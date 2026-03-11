//! Shared helper functions for HTTP handlers.

use std::{collections::HashMap, str::FromStr, sync::Arc};

use axum::{
    Json,
    extract::State,
    http::{
        HeaderMap, HeaderName, HeaderValue, StatusCode,
        header::{CONTENT_TYPE, LOCATION},
    },
    response::{IntoResponse, Response},
};
use coder_audit::{AuditAction, AuditEvent, AuditSink};
use coder_auth::{
    AuthService, AuthServiceError, AuthenticatedRequest, ExternalAuthService,
    ExternalAuthServiceError, cookie_from_headers,
};
use coder_connectivity::{HealthService, generate_git_ssh_key};
use coder_core::{
    ApiResponse, AppStore, AuthenticatedUser, HealthSettings, OrganizationRecord, ServerConfig,
    UserRecord, ValidationError,
};
use coder_identity::{IdentityService, IdentityServiceError};
use coder_rbac::{Action, Actor, Authorizer, Object, ROLE_AUDITOR, ResourceType};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::app::AppState;
use crate::error::AppError;

use axum::extract::rejection::JsonRejection;
use axum::extract::ws::{CloseFrame, Message, WebSocket};
use coder_core::HealthcheckReport;
use coder_rbac::ResourceKind;

pub(crate) async fn authenticate_request(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<AuthenticatedRequest>, AppError> {
    state
        .auth
        .authenticate(headers)
        .await
        .map_err(AppError::from)
}

/// Authenticate an agent request by looking up the agent via its auth token.
///
/// Agents authenticate using the same `Coder-Session-Token` header, but their
/// token is a UUID stored in `workspace_agents.auth_token` (not a hashed
/// session token in the auth_sessions table).
pub(crate) async fn authenticate_agent_request(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<coder_core::WorkspaceAgentRow>, AppError> {
    // Extract token from header first, then fall back to cookie.
    let raw_token: Option<String> = headers
        .get("coder-session-token")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .or_else(|| cookie_from_headers(headers, "coder_session_token"));

    let token_str = match raw_token {
        Some(ref s) if !s.is_empty() => s.as_str(),
        _ => return Ok(None),
    };

    let token = match Uuid::from_str(token_str) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(None),
    };

    state
        .store
        .find_workspace_agent_by_auth_token(token)
        .await
        .map_err(AppError::from)
}

pub(crate) async fn resolve_user(
    state: &AppState,
    requested_user: &str,
    authenticated_user: &AuthenticatedUser,
) -> Result<Option<UserRecord>, AppError> {
    if requested_user == "me" {
        return state
            .store
            .find_user_by_id(authenticated_user.id)
            .await
            .map_err(AppError::from);
    }

    if let Ok(user_id) = Uuid::parse_str(requested_user) {
        return state
            .store
            .find_user_by_id(user_id)
            .await
            .map_err(AppError::from);
    }

    state
        .store
        .find_user_by_username(requested_user)
        .await
        .map_err(AppError::from)
}

pub(crate) fn can_view_operational_data(actor: &Actor) -> bool {
    actor.is_owner() || actor.has_site_role(ROLE_AUDITOR)
}

pub(crate) fn find_external_auth_provider<'a>(
    state: &'a AppState,
    provider_id: &str,
) -> Option<&'a coder_core::ExternalAuthLinkProvider> {
    state
        .config
        .external_auth_providers
        .iter()
        .find(|provider| provider.id == provider_id)
}

pub(crate) fn apply_dismissed_health_settings(
    mut report: HealthcheckReport,
    settings: &HealthSettings,
) -> HealthcheckReport {
    for section in &settings.dismissed_healthchecks {
        match section.as_str() {
            "AccessURL" => report.access_url.base.dismissed = true,
            "DERP" => report.derp.base.dismissed = true,
            "Database" => report.database.base.dismissed = true,
            "Websocket" => report.websocket.base.dismissed = true,
            "WorkspaceProxy" => report.workspace_proxy.base.dismissed = true,
            "ProvisionerDaemons" => report.provisioner_daemons.base.dismissed = true,
            _ => {}
        }
    }
    report
}

pub(crate) fn sanitize_redirect_uri(input: &str) -> String {
    if let Ok(url) = url::Url::parse(input) {
        let path = url.path();
        let query = url
            .query()
            .map(|value| format!("?{value}"))
            .unwrap_or_default();
        return if path.is_empty() {
            "/".to_owned()
        } else {
            format!("{path}{query}")
        };
    }

    if let Ok(uri) = http::Uri::from_str(input) {
        if let Some(path_and_query) = uri.path_and_query() {
            return path_and_query.as_str().to_owned();
        }
        if !uri.path().is_empty() {
            return uri.path().to_owned();
        }
    }

    "/".to_owned()
}

pub(crate) fn redirect_to_login_response(uri: &http::Uri, message: &str) -> Response {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("message", message);
    serializer.append_pair("redirect", &sanitize_redirect_uri(&uri.to_string()));
    let location = format!("/login?{}", serializer.finish());

    let mut response = StatusCode::SEE_OTHER.into_response();
    response.headers_mut().insert(
        LOCATION,
        HeaderValue::from_str(&location).unwrap_or_else(|_| HeaderValue::from_static("/login")),
    );
    response
}

pub(crate) fn external_auth_device_flow_unsupported_response() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ApiResponse::ok(
            "Git auth provider does not support device flow.",
        )),
    )
        .into_response()
}

pub(crate) async fn store_new_git_ssh_key(
    state: &AppState,
    user: &UserRecord,
) -> Result<coder_core::GitSshKeyRecord, String> {
    let comment = if !user.email.trim().is_empty() {
        user.email.clone()
    } else {
        user.username.clone()
    };
    let generated = generate_git_ssh_key(&comment).map_err(|error| error.to_string())?;
    state
        .store
        .upsert_git_ssh_key(user.id, &generated.public_key, &generated.private_key)
        .await
        .map_err(|error| error.to_string())
}

pub(crate) async fn record_audit(
    state: &AppState,
    action: AuditAction,
    resource: ResourceKind,
    actor: Option<&AuthenticatedUser>,
    target_id: Option<String>,
    summary: impl Into<String>,
) {
    state
        .audit
        .record(AuditEvent {
            action,
            resource,
            actor_user_id: actor.map(|user| user.id),
            target_id,
            summary: summary.into(),
        })
        .await;
}

pub(crate) fn handle_auth_error(error: AuthServiceError) -> Result<Response, AppError> {
    match error {
        AuthServiceError::Storage(error) => Err(AppError::from(error)),
        AuthServiceError::Unauthorized { message } => Ok(unauthorized_response(message)),
        AuthServiceError::Forbidden { message } => Ok(forbidden_response(message)),
        AuthServiceError::NotFound { message } => Ok(not_found_response(message)),
        AuthServiceError::BadRequest { message, detail } => Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                message,
                detail,
                validations: Vec::new(),
            }),
        )
            .into_response()),
        AuthServiceError::Validation {
            message,
            validations,
        } => Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                message,
                detail: None,
                validations,
            }),
        )
            .into_response()),
        AuthServiceError::Conflict {
            message,
            detail,
            validations,
        } => Ok((
            StatusCode::CONFLICT,
            Json(ApiResponse {
                message,
                detail,
                validations,
            }),
        )
            .into_response()),
    }
}

pub(crate) fn handle_external_auth_error(
    message: &'static str,
    error: ExternalAuthServiceError,
) -> Result<Response, AppError> {
    match error {
        ExternalAuthServiceError::BadRequest(detail) => Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(message, detail)),
        )
            .into_response()),
        ExternalAuthServiceError::Storage(error) => Err(AppError::from(error)),
        ExternalAuthServiceError::Internal(detail) => {
            Ok(internal_server_error_detail_response(message, detail))
        }
    }
}

pub(crate) fn handle_identity_error(error: IdentityServiceError) -> Result<Response, AppError> {
    match error {
        IdentityServiceError::Storage(error) => Err(AppError::from(error)),
        IdentityServiceError::NotFound { message } => Ok(not_found_response(message)),
        IdentityServiceError::Forbidden { message } => Ok(forbidden_response(message)),
        IdentityServiceError::BadRequest { message, detail } => Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                message,
                detail,
                validations: Vec::new(),
            }),
        )
            .into_response()),
        IdentityServiceError::Validation {
            message,
            validations,
        } => Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                message,
                detail: None,
                validations,
            }),
        )
            .into_response()),
        IdentityServiceError::Conflict {
            message,
            detail,
            validations,
        } => Ok((
            StatusCode::CONFLICT,
            Json(ApiResponse {
                message,
                detail,
                validations,
            }),
        )
            .into_response()),
    }
}

pub(crate) fn build_version_headers(version: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Ok(value) = HeaderValue::from_str(version) {
        headers.insert(HeaderName::from_static(BUILD_VERSION_HEADER), value);
    }
    headers
}

pub(crate) fn invalid_json_response(error: JsonRejection) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ApiResponse::error(
            "Request body must be valid JSON.",
            error.body_text(),
        )),
    )
        .into_response()
}

pub(crate) fn validation_response(validations: Vec<ValidationError>) -> Response {
    validation_message_response("Request body has invalid fields.", validations)
}

pub(crate) fn validation_message_response(
    message: &str,
    validations: Vec<ValidationError>,
) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ApiResponse {
            message: message.to_owned(),
            detail: None,
            validations,
        }),
    )
        .into_response()
}

pub(crate) fn unauthorized_response(message: impl Into<String>) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(ApiResponse::ok(message.into())),
    )
        .into_response()
}

pub(crate) fn forbidden_response(message: impl Into<String>) -> Response {
    (StatusCode::FORBIDDEN, Json(ApiResponse::ok(message.into()))).into_response()
}

pub(crate) fn not_implemented_response(message: impl Into<String>) -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(ApiResponse::ok(message.into())),
    )
        .into_response()
}

pub(crate) fn not_implemented_detail_response(
    message: impl Into<String>,
    detail: impl Into<String>,
) -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(ApiResponse::error(message.into(), detail.into())),
    )
        .into_response()
}

/// Accept a WebSocket upgrade then immediately close with a "not implemented" reason.
/// Used for endpoints that require tailnet/pubsub integration not yet available.
pub(crate) async fn ws_close_not_implemented(mut socket: WebSocket, reason: &str) {
    // Send the reason as a text message, then close gracefully.
    let _ = socket.send(Message::Text(reason.into())).await;
    let _ = socket
        .send(Message::Close(Some(CloseFrame {
            // 4001 = application-level "not implemented" close code (in the 4000-4999 private range).
            code: 4001,
            reason: reason.into(),
        })))
        .await;
}

pub(crate) fn not_found_response(message: impl Into<String>) -> Response {
    (StatusCode::NOT_FOUND, Json(ApiResponse::ok(message.into()))).into_response()
}

pub(crate) fn not_found_detail_response(
    message: impl Into<String>,
    detail: impl Into<String>,
) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ApiResponse::error(message.into(), detail.into())),
    )
        .into_response()
}

pub(crate) fn internal_server_error_response(message: impl Into<String>) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ApiResponse::error(message.into(), "")),
    )
        .into_response()
}

pub(crate) fn internal_server_error_detail_response(
    message: impl Into<String>,
    detail: impl Into<String>,
) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ApiResponse::error(message.into(), detail.into())),
    )
        .into_response()
}

pub(crate) fn resource_not_found_response() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ApiResponse::ok(
            "Resource not found or you do not have access to this resource",
        )),
    )
        .into_response()
}

/// Resolve an organization path segment by UUID or name.
pub(crate) async fn resolve_organization(
    state: &AppState,
    org_ref: &str,
) -> Result<Option<OrganizationRecord>, AppError> {
    if let Ok(org_id) = Uuid::parse_str(org_ref) {
        return Ok(state.store.find_organization_by_id(org_id).await?);
    }
    Ok(state.store.find_organization_by_name(org_ref).await?)
}

// Constants moved from app.rs
pub(crate) const TIMING_ALLOW_ORIGIN: &str = "timing-allow-origin";

pub(crate) const BUILD_VERSION_HEADER: &str = "x-coder-build-version";

pub(crate) const SLIM_BUILD_MESSAGE: &str =
    "Slim build of Coder, does not contain the frontend static files.";

pub(crate) const PUBLIC_API_KEY_SCOPES: &[&str] = &[
    "audit_log:*",
    "audit_log:create",
    "audit_log:read",
    "api_key:*",
    "api_key:create",
    "api_key:delete",
    "api_key:read",
    "api_key:update",
    "coder:all",
    "coder:apikeys.manage_self",
    "coder:application_connect",
    "deployment_stats:*",
    "deployment_stats:read",
    "coder:templates.author",
    "coder:templates.build",
    "coder:workspaces.access",
    "coder:workspaces.create",
    "coder:workspaces.delete",
    "coder:workspaces.operate",
    "file:*",
    "file:create",
    "file:read",
    "organization:*",
    "organization:delete",
    "organization:read",
    "organization:update",
    "task:*",
    "task:create",
    "task:delete",
    "task:read",
    "task:update",
    "template:*",
    "template:create",
    "template:delete",
    "template:read",
    "template:update",
    "template:use",
    "user:read_personal",
    "user:update_personal",
    "user_secret:*",
    "user_secret:create",
    "user_secret:delete",
    "user_secret:read",
    "user_secret:update",
    "workspace:*",
    "workspace:application_connect",
    "workspace:create",
    "workspace:delete",
    "workspace:read",
    "workspace:ssh",
    "workspace:start",
    "workspace:stop",
    "workspace:update",
];

pub(crate) const VALID_HEALTH_SECTIONS: &[&str] = &[
    "DERP",
    "AccessURL",
    "Websocket",
    "Database",
    "WorkspaceProxy",
    "ProvisionerDaemons",
];
