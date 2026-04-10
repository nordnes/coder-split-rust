//! Replica listing handler.

use super::*;
use coder_core::api::Replica;

/// GET /api/v2/replicas — list active Coder replicas.
///
/// In a high-availability deployment this would return all primary replicas
/// from the replica manager.  Since the replica manager service is not yet
/// implemented, we return an empty array.
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

    // TODO: Once a replicaManager service exists, query it for all primary
    // replicas and convert them to `Replica` responses.  For now, return an
    // empty array matching the Go single-replica / no-HA behaviour.
    let replicas: Vec<Replica> = Vec::new();

    Ok((StatusCode::OK, Json(replicas)).into_response())
}
