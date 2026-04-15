//! Application-related HTTP handlers (enterprise — workspace proxy features).

use super::*;
use crate::handlers::workspace_apps::{AccessMethod, AppRequest, create_signed_app_token};

/// `POST /api/v2/applications/reconnecting-pty-signed-token`
///
/// Issues a signed app token that workspace proxies can verify to authorize
/// reconnecting PTY connections.  Matches the Go handler in
/// `coder/enterprise/coderd/workspaceproxy.go → reconnectingPTYSignedToken`.
pub(crate) async fn post_reconnecting_pty_signed_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<coder_core::api::IssueReconnectingPTYSignedTokenRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Json(request) = match body {
        Ok(r) => r,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    // Parse and validate the URL.
    let parsed = match url::Url::parse(&request.url) {
        Ok(u) => u,
        Err(e) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    message: "Invalid URL.".to_owned(),
                    detail: Some(e.to_string()),
                    validations: Vec::new(),
                }),
            )
                .into_response());
        }
    };

    // Only ws:// and wss:// schemes are accepted.
    if parsed.scheme() != "ws" && parsed.scheme() != "wss" {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                message: "Invalid URL.".to_owned(),
                detail: Some(format!(
                    "invalid URL scheme {:?}, expected 'ws' or 'wss'",
                    parsed.scheme()
                )),
                validations: Vec::new(),
            }),
        )
            .into_response());
    }

    // Assert the URL is a valid reconnecting-pty path.
    let expected_path = format!("/api/v2/workspaceagents/{}/pty", request.agent_id);
    if parsed.path() != expected_path {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                message: "Invalid URL path.".to_owned(),
                detail: Some(
                    "The provided URL is not a valid reconnecting PTY endpoint URL.".to_owned(),
                ),
                validations: Vec::new(),
            }),
        )
            .into_response());
    }

    // NOTE: The Go handler additionally validates the hostname via
    // `ValidWorkspaceAppHostname` (lines 906-927 in workspaceproxy.go).
    // That check requires the full workspace-proxy infrastructure which is
    // not yet ported; it will be added when workspace-proxy support lands.

    // Build an AppRequest scoped to the terminal access method, matching the
    // Go handler's call to WorkspaceAppsProvider.Issue.
    let app_request = AppRequest {
        access_method: AccessMethod::Terminal,
        base_path: parsed.path().to_owned(),
        prefix: String::new(),
        username_or_id: String::new(),
        workspace_and_agent: String::new(),
        workspace_name_or_id: String::new(),
        agent_name_or_id: request.agent_id.to_string(),
        app_slug_or_port: String::new(),
    };

    // Derive a signing key from the deployment identifier.  A dedicated
    // signing-key field will be added to AppState when the full workspace-proxy
    // infrastructure is ported.
    let signing_key = format!("coder-signing-{}", state.deployment_id);
    let token = create_signed_app_token(signing_key.as_bytes(), &app_request, context.user.id)
        .map_err(|e| AppError::InternalError {
            message: "Failed to sign reconnecting PTY token.".to_owned(),
            detail: e.to_string(),
        })?;

    Ok((
        StatusCode::OK,
        Json(coder_core::api::IssueReconnectingPTYSignedTokenResponse {
            signed_token: token,
        }),
    )
        .into_response())
}
