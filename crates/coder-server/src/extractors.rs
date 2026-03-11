//! Axum extractors for authentication, eliminating per-handler boilerplate.
//!
//! Provides three extractors:
//!
//! * [`Auth`] — requires a valid session token (returns 401 otherwise)
//! * [`OptionalAuth`] — authenticates if a token is present, passes through if not
//! * [`AgentAuth`] — requires a valid workspace-agent auth token

use std::str::FromStr;

use axum::{
    Json,
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
use coder_auth::{AuthenticatedRequest, cookie_from_headers};
use coder_core::{ApiResponse, WorkspaceAgentRow};
use uuid::Uuid;

use crate::app::AppState;
use crate::error::AppError;

// ---------------------------------------------------------------------------
// Auth – mandatory session-token authentication
// ---------------------------------------------------------------------------

/// Extractor that requires a valid session token.
///
/// Replaces the repeated `authenticate_request` + `None`-check boilerplate in
/// every handler that needs an authenticated user.
pub(crate) struct Auth(pub AuthenticatedRequest);

impl FromRequestParts<AppState> for Auth {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        match state.auth.authenticate(&parts.headers).await {
            Ok(Some(ctx)) => Ok(Auth(ctx)),
            Ok(None) => Err(unauthorized_response("Missing or invalid session token.")),
            Err(e) => Err(AppError::from(e).into_response()),
        }
    }
}

// ---------------------------------------------------------------------------
// OptionalAuth – session-token authentication that may be absent
// ---------------------------------------------------------------------------

/// Extractor that optionally authenticates via session token.
///
/// Use this for routes that support both authenticated and unauthenticated
/// access (e.g. public endpoints that personalise output for logged-in users).
pub(crate) struct OptionalAuth(pub Option<AuthenticatedRequest>);

impl FromRequestParts<AppState> for OptionalAuth {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        match state.auth.authenticate(&parts.headers).await {
            Ok(ctx) => Ok(OptionalAuth(ctx)),
            Err(e) => Err(AppError::from(e).into_response()),
        }
    }
}

// ---------------------------------------------------------------------------
// AgentAuth – workspace-agent token authentication
// ---------------------------------------------------------------------------

/// Extractor that requires a valid workspace-agent auth token.
///
/// Agents authenticate using the same `Coder-Session-Token` header, but their
/// token is a UUID stored in `workspace_agents.auth_token`.
pub(crate) struct AgentAuth(pub WorkspaceAgentRow);

impl FromRequestParts<AppState> for AgentAuth {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        match authenticate_agent_from_parts(parts, state).await {
            Ok(Some(agent)) => Ok(AgentAuth(agent)),
            Ok(None) => Err(unauthorized_response("Missing or invalid agent token.")),
            Err(e) => Err(e.into_response()),
        }
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Reproduce the agent-authentication logic from the original
/// `authenticate_agent_request` helper so it can be used inside extractors.
async fn authenticate_agent_from_parts(
    parts: &Parts,
    state: &AppState,
) -> Result<Option<WorkspaceAgentRow>, AppError> {
    let raw_token: Option<String> = parts
        .headers
        .get("coder-session-token")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .or_else(|| cookie_from_headers(&parts.headers, "coder_session_token"));

    let token_str = match raw_token {
        Some(ref s) if !s.is_empty() => s.clone(),
        _ => return Ok(None),
    };

    let token = match Uuid::from_str(&token_str) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(None),
    };

    state
        .store
        .find_workspace_agent_by_auth_token(token)
        .await
        .map_err(AppError::from)
}

fn unauthorized_response(message: impl Into<String>) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(ApiResponse::ok(message.into())),
    )
        .into_response()
}
