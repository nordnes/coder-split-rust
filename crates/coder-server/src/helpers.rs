//! Shared helper functions used across handler modules.
//!
//! This module provides:
//!
//! * **Authentication helpers** — [`authenticate_request`], [`authenticate_agent_request`]
//! * **User resolution** — [`resolve_user`] (by `"me"`, UUID, or username)
//! * **Error mappers** — [`handle_auth_error`], [`handle_external_auth_error`],
//!   [`handle_identity_error`] convert domain errors into HTTP responses
//! * **Response builders** — convenience functions for common HTTP status codes
//!   (`unauthorized_response`, `forbidden_response`, `not_found_response`, …)
//! * **Audit recording** — [`record_audit`] dispatches events to the audit sink

use crate::app::{AppState, BUILD_VERSION_HEADER};
use crate::error::AppError;

use axum::{
    Json,
    extract::rejection::JsonRejection,
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header::LOCATION},
    response::{IntoResponse, Response},
};
use coder_audit::{AuditAction, AuditEvent};
use coder_auth::{
    AuthServiceError, AuthenticatedRequest, ExternalAuthServiceError, cookie_from_headers,
};
use coder_connectivity::generate_git_ssh_key;
use coder_core::{
    ApiResponse, AuthenticatedUser, HealthSettings, HealthcheckReport, UserRecord, ValidationError,
};
use coder_identity::IdentityServiceError;
use coder_rbac::{Actor, ROLE_AUDITOR, ResourceKind};
use std::str::FromStr;
use uuid::Uuid;

/// Authenticates an HTTP request using the session token in the headers.
///
/// Returns `Ok(Some(…))` for a valid session, `Ok(None)` when no token is
/// present, or an error on storage failures.
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

/// Resolves a user identifier from a URL path segment.
///
/// Accepts the literal `"me"` (returns the authenticated user), a UUID, or a
/// username.  Returns `Ok(None)` when no matching user is found.
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

/// Returns `true` if the actor has permission to view operational data
/// (owners and auditors).
pub(crate) fn can_view_operational_data(actor: &Actor) -> bool {
    actor.is_owner() || actor.has_site_role(ROLE_AUDITOR)
}

/// Looks up an external auth provider by its identifier from the server
/// configuration.
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

/// Marks dismissed health-check sections in the report so the UI can hide
/// them.
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

/// Extracts the path (and optional query) from a redirect URI, stripping
/// the scheme and authority to prevent open-redirect attacks.
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

/// Builds a `303 See Other` redirect to `/login` with the given message
/// and the original URI preserved as a `redirect` query parameter.
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

/// Returns a `400 Bad Request` response indicating that the provider does
/// not support the device-code flow.
pub(crate) fn external_auth_device_flow_unsupported_response() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ApiResponse::ok(
            "Git auth provider does not support device flow.",
        )),
    )
        .into_response()
}

/// Generates a new SSH keypair for the user and upserts it in the store.
///
/// The key comment is set to the user's email or, if empty, their username.
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

/// Records an audit event via the batched audit sink.
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

/// Converts an [`AuthServiceError`] into an HTTP response, mapping each
/// variant to the appropriate status code.
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

/// Converts an [`ExternalAuthServiceError`] into an HTTP response,
/// wrapping the service-level detail with a caller-supplied message.
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

/// Converts an [`IdentityServiceError`] into an HTTP response, mapping
/// each variant to the appropriate status code.
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

/// Returns a [`HeaderMap`] containing the `X-Coder-Build-Version` header.
pub(crate) fn build_version_headers(version: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Ok(value) = HeaderValue::from_str(version) {
        headers.insert(HeaderName::from_static(BUILD_VERSION_HEADER), value);
    }
    headers
}

/// Returns a `400 Bad Request` response for malformed JSON request bodies.
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

/// Returns a `400 Bad Request` response listing field-level validation
/// errors.
pub(crate) fn validation_response(validations: Vec<ValidationError>) -> Response {
    validation_message_response("Request body has invalid fields.", validations)
}

/// Returns a `400 Bad Request` response with a custom message and
/// field-level validation errors.
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

/// Returns a `401 Unauthorized` JSON response.
pub(crate) fn unauthorized_response(message: impl Into<String>) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(ApiResponse::ok(message.into())),
    )
        .into_response()
}

/// Returns a `403 Forbidden` JSON response.
pub(crate) fn forbidden_response(message: impl Into<String>) -> Response {
    (StatusCode::FORBIDDEN, Json(ApiResponse::ok(message.into()))).into_response()
}

/// Returns a `404 Not Found` JSON response.
pub(crate) fn not_found_response(message: impl Into<String>) -> Response {
    (StatusCode::NOT_FOUND, Json(ApiResponse::ok(message.into()))).into_response()
}

/// Returns a `404 Not Found` JSON response with an additional detail
/// string.
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

/// Returns a `500 Internal Server Error` JSON response.
pub(crate) fn internal_server_error_response(message: impl Into<String>) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ApiResponse::error(message.into(), "")),
    )
        .into_response()
}

/// Returns a `500 Internal Server Error` JSON response with an additional
/// detail string.
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

/// Returns a generic `404 Not Found` response suitable for routes that
/// must not reveal whether the resource exists.
pub(crate) fn resource_not_found_response() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ApiResponse::ok(
            "Resource not found or you do not have access to this resource",
        )),
    )
        .into_response()
}
