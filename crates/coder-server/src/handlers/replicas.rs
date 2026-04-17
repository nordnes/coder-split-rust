//! Replica listing handler.

use super::*;
use crate::replica_manager::{replica_from_row, stale_cutoff};
use coder_core::api::ReplicaResponse;
use std::time::Duration;
use time::OffsetDateTime;

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
    // Share the same staleness formula as the replica manager so the
    // handler's filter and the manager's prune policy cannot drift.
    let threshold = OffsetDateTime::now_utc() - stale_cutoff(update_interval);
    let rows = state.store.list_coderd_replicas(threshold).await?;
    let replicas: Vec<ReplicaResponse> = rows.iter().map(replica_from_row).collect();

    Ok((StatusCode::OK, Json(replicas)).into_response())
}
