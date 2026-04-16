//! Replica listing handler.

use super::*;
use crate::replica_manager::replica_from_row;
use coder_core::api::Replica;
use std::time::Duration;
use time::OffsetDateTime;

/// Default staleness cutoff when the replica manager is disabled.
/// Mirrors `3 × DEFAULT_UPDATE_INTERVAL` from the Go implementation
/// (`coder/enterprise/replicasync/replicasync.go` — `DefaultUpdateInterval`).
const DEFAULT_REPLICA_STALENESS_SECS: u64 = 45;

/// GET /api/v2/replicas — list active Coder replicas.
///
/// Ports `coder/enterprise/coderd/replicas.go:22`
/// (`(*API).replicas`).  In the Go code the set of replicas is provided
/// by the in-memory `replicasync.Manager`; here we query the database
/// view that the manager populates, which is equivalent for `AllPrimary`.
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

    let staleness = time::Duration::try_from(Duration::from_secs(DEFAULT_REPLICA_STALENESS_SECS))
        .unwrap_or(time::Duration::seconds(45));
    let threshold = OffsetDateTime::now_utc() - staleness;
    let rows = state.store.list_coderd_replicas(threshold).await?;
    let replicas: Vec<Replica> = rows.iter().map(replica_from_row).collect();

    Ok((StatusCode::OK, Json(replicas)).into_response())
}
