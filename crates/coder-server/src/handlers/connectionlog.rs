//! Connection log listing handler.

use super::users::clamp_pagination_limit;
use super::*;
use coder_core::ConnectionLogResponse;
use coder_core::ports::ConnectionLogListFilter;

#[derive(Debug, Default, Deserialize)]
pub(crate) struct ConnectionLogQuery {
    #[serde(default)]
    q: String,
    limit: Option<u32>,
    offset: Option<u32>,
}

/// GET /api/v2/connectionlog — list connection log entries with optional filtering.
pub(crate) async fn list_connection_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ConnectionLogQuery>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: connection logs have their own resource type in the Rust RBAC model.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::ConnectionLog),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to view connection logs.",
        ));
    }

    let response: ConnectionLogResponse = state
        .store
        .list_connection_logs(ConnectionLogListFilter {
            search: query.q,
            limit: clamp_pagination_limit(query.limit.unwrap_or(100)),
            offset: query.offset.unwrap_or_default(),
        })
        .await?;

    Ok((StatusCode::OK, Json(response)).into_response())
}
