//! Shared helper functions for HTTP handlers.

//! Router construction and HTTP handlers.

use std::{collections::HashMap, str::FromStr, sync::Arc};

use async_trait::async_trait;
use axum::{
    Form, Json, Router,
    body::Bytes,
    extract::{
        DefaultBodyLimit, OriginalUri, Path, Query, State,
        rejection::JsonRejection,
        ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
    },
    http::{
        HeaderMap, HeaderName, HeaderValue, StatusCode,
        header::{
            ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS,
            ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_TYPE, LOCATION,
        },
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post, put},
};
use coder_audit::{AuditAction, AuditEvent, AuditSink};
use coder_auth::{
    AuthService, AuthServiceError, AuthenticatedRequest, ExternalAuthService,
    ExternalAuthServiceError, OAUTH2_REDIRECT_COOKIE, OAUTH2_STATE_COOKIE, OAuth2ProviderError,
    OAuth2ProviderService, cookie_from_headers, supported_auth_methods,
};
use coder_connectivity::{
    HealthService,
    agents::{AgentConnection, AgentError, AgentProvider},
    generate_git_ssh_key,
    tailnet::{DerpTrafficTracker, TailnetCoordinator},
};
use coder_core::StorageError;
use coder_core::api::{
    ArchiveTemplateVersionsRequest, ArchiveTemplateVersionsResponse, CreateTemplateRequest,
    CreateTemplateVersionDryRunRequest, CreateTemplateVersionRequest, DAUEntry, DAUsResponse,
    DynamicParametersRequest, DynamicParametersResponse, MatchedProvisioners, MinimalUser,
    PatchTemplateVersionRequest, ProvisionerJobLog, ProvisionerJobResponse, ProvisionerJobStatus,
    TemplateExample, TemplateFilter, TemplateResponse, TemplateVersionExternalAuth,
    TemplateVersionParameter, TemplateVersionPreset, TemplateVersionPresetParameter,
    TemplateVersionResponse, TemplateVersionVariable, UpdateActiveTemplateVersionRequest,
    UpdateTemplateMeta, WorkspaceBuildParameter, WorkspaceResource, WorkspaceResourceMetadata,
    WorkspaceResourceResponse,
};
use coder_core::api::{InsightsReportInterval, TemplateInsightsSection};
use coder_core::api::{
    UpdateWorkspaceACLRequest, WorkspaceACLGroup, WorkspaceACLResponse, WorkspaceACLUser,
};
use coder_core::ports::UpdateWorkspaceACLInput;
use coder_core::pubsub::PubSub;
use coder_core::template::{
    CreateProvisionerJobInput, CreateTemplateInput, CreateTemplateStoreError,
    CreateTemplateVersionInput, ProvisionerJobRecord as TemplateProvisionerJobRecord,
    TemplateListFilter, TemplateRecord, TemplateVersionListFilter, TemplateVersionRecord,
    UpdateTemplateMetaInput,
};
use coder_core::{
    AWSInstanceIdentityToken, ApiResponse, AppHostResponse, AppStore, AuditLogListFilter,
    AuthMethods, AuthenticatedUser, AuthorizationRequest, AvailableExperiments,
    AzureInstanceIdentityToken, BuildMetadata, ChangePasswordWithOneTimePasscodeRequest,
    ChatMessagePart, ChatMessageRecord, ChatMessageResponse, ChatMessageUsage,
    ChatMessageVisibility, ChatQueuedMessageRecord, ChatQueuedMessageResponse, ChatRecord,
    ChatResponse, ChatWithMessagesResponse, ConvertLoginRequest, CreateChatMessageApiResponse,
    CreateChatMessageRequest, CreateChatRequest, CreateFirstUserRequest, CreateFirstUserResponse,
    CreateLogSourceRequest, CreateTaskRequest, CreateTestAuditLogRequest, CreateTokenRequest,
    CreateUserRequestWithOrgs, CreateWorkspaceBuildInput, CreateWorkspaceInput, DERPMap,
    DERPMapRegion, DERPNode, DeploymentConfigResponse, ExternalApiKeyScopes,
    ExternalAuthDeviceExchangeRequest, GCPInstanceIdentityToken, GetUsersResponse, HealthSettings,
    HealthcheckReport, InsertChatInput, InsertChatMessageInput, InsertFileInput, InsertTaskInput,
    LoginType, LoginWithPasswordRequest, OAuth2AuthorizeRequest, OAuth2ProviderAppEndpoints,
    OAuth2ProviderAppResponse, OAuth2ProviderAppSecretFullResponse,
    OAuth2ProviderAppSecretResponse, OAuth2TokenRequest, OAuth2TokenResponse, OrganizationMember,
    OrganizationMemberWithUserData, OrganizationRecord, OrganizationResponse,
    PaginatedMembersResponse, PatchAgentLogsRequest, PatchAppStatusRequest, PersistAuditLogInput,
    PostOAuth2ProviderAppRequest, PutOAuth2ProviderAppRequest, RequestOneTimePasscodeRequest,
    ServerConfig, SshConfigResponse, TaskListFilter, TaskLogSnapshotEnvelope, TaskLogsResponse,
    TaskRecord, TaskResponse, TaskSendRequest, TasksListResponse, UpdateCheckResponse,
    UpdateInboxNotificationReadStatusRequest, UpdateNotificationTemplateMethod, UpdateRolesRequest,
    UpdateUserAppearanceSettingsRequest, UpdateUserNotificationPreferences,
    UpdateUserPasswordRequest, UpdateUserPreferenceSettingsRequest, UpdateUserProfileRequest,
    UploadFileResponse, UpsertPortShareInput, UserAppearanceSettings, UserListFilter,
    UserParameter, UserPreferenceSettings, UserRecord, UserResponse, UserRolesResponse, UserStatus,
    ValidateUserPasswordRequest, ValidationError, WebpushSubscription,
    WorkspaceAgentAuthenticateResponse, WorkspaceAgentConnectionInfo,
    WorkspaceAgentListContainersResponse, WorkspaceAgentListeningPortsResponse,
    WorkspaceListFilter,
};
use coder_identity::{IdentityService, IdentityServiceError};
use coder_provisioner::{InitScriptError, render_init_script};
use coder_rbac::{Action, Actor, Authorizer, Object, ROLE_AUDITOR, ResourceKind, ResourceType};
use coder_workspaces::DeploymentStatsService;
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use time::OffsetDateTime;
use tower_http::{
    normalize_path::NormalizePathLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer},
};
use tracing::debug;
use uuid::Uuid;

use crate::error::AppError;

const TIMING_ALLOW_ORIGIN: &str = "timing-allow-origin";
const BUILD_VERSION_HEADER: &str = "x-coder-build-version";
const SLIM_BUILD_MESSAGE: &str = "Slim build of Coder, does not contain the frontend static files.";
const PUBLIC_API_KEY_SCOPES: &[&str] = &[
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
const VALID_HEALTH_SECTIONS: &[&str] = &[
    "DERP",
    "AccessURL",
    "Websocket",
    "Database",
    "WorkspaceProxy",
    "ProvisionerDaemons",
];

const MAX_CHAT_FILE_SIZE: usize = 10 << 20;

use crate::app::AppState;

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

/// Deprecated: all call-sites now use `Authorizer::new().authorize()` with
/// the appropriate `ResourceType` and `Action` instead of this coarse check.
/// Retained temporarily for reference; safe to remove once confirmed unused.
#[allow(dead_code)]
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
