//! Replica listing handler.

use super::*;
use crate::replica_manager::replica_from_row;
use coder_core::api::ReplicaResponse;
use std::time::Duration;
use time::OffsetDateTime;

/// Staleness-cutoff multiplier.  Matches the `3 × UpdateInterval`
/// pruning policy in `coder/enterprise/replicasync/replicasync.go`.
const STALE_MULTIPLIER: u32 = 3;

/// GET /api/v2/replicas — list active Coder replicas.
///
/// Ports `coder/enterprise/coderd/replicas.go:22`
/// (`(*API).replicas`).  In the Go code the set of replicas is provided
/// by the in-memory `replicasync.Manager`; here we query the database
/// view that the manager populates, which is equivalent for `AllPrimary`.
///
/// The staleness cut-off is derived from
/// `ServerConfig::worker.replica_update_interval_secs` so this handler
/// and the replica manager stay in sync: the manager refreshes every
/// `replica_update_interval_secs` and prunes rows older than
/// `3 × replica_update_interval_secs`; the handler applies the same
/// cut-off when filtering query results.
pub(crate) async fn get_replicas(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: ActionRead on ResourceReplicas.
    // Per the Go implementation, return 404 (not 403) on deny.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::Replicas),
        )
        .is_err()
    {
        return Ok(resource_not_found_response());
    }

    let update_interval = Duration::from_secs(state.config.worker.replica_update_interval_secs);
    let scaled = update_interval.saturating_mul(STALE_MULTIPLIER);
    let staleness = time::Duration::try_from(scaled).unwrap_or(time::Duration::MAX);
    let threshold = OffsetDateTime::now_utc() - staleness;
    let rows = state.store.list_coderd_replicas(threshold).await?;
    let replicas: Vec<ReplicaResponse> = rows.iter().map(replica_from_row).collect();

    Ok((StatusCode::OK, Json(replicas)).into_response())
}
