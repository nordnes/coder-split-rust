//! Oauth2 handlers.

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
use crate::helpers::*;

pub(crate) async fn list_oauth2_provider_apps(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can read OAuth2 provider apps.
    // The member site role grants Oauth2App::Read, so all authenticated users
    // with the default member role retain access (backward compatible).
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::Oauth2App),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to list OAuth2 provider apps.",
        ));
    }

    let apps = match state.oauth2_provider.list_apps().await {
        Ok(apps) => apps,
        Err(error) => return handle_oauth2_provider_error(error),
    };
    let response: Vec<OAuth2ProviderAppResponse> =
        apps.into_iter().map(oauth2_app_response).collect();
    Ok((StatusCode::OK, Json(response)).into_response())
}

pub(crate) async fn post_oauth2_provider_app(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<PostOAuth2ProviderAppRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can create OAuth2 provider apps.
    // This intentionally replaces the prior is_owner() gate to support future
    // custom roles that may grant OAuth2 app management without full ownership.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Create,
            &Object::new(ResourceType::Oauth2App),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to create OAuth2 provider apps.",
        ));
    }

    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    let app = match state
        .oauth2_provider
        .create_app(
            &request.name,
            &request.icon,
            &request.callback_url,
            context.user.id,
        )
        .await
    {
        Ok(app) => app,
        Err(error) => return handle_oauth2_provider_error(error),
    };

    record_audit(
        &state,
        AuditAction::Create,
        ResourceKind::Oauth2ProviderApp,
        Some(&context.user),
        Some(app.id.to_string()),
        "created oauth2 provider app",
    )
    .await;

    Ok((StatusCode::CREATED, Json(oauth2_app_response(app))).into_response())
}

pub(crate) async fn get_oauth2_provider_app(
    State(state): State<AppState>,
    Path(app_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can read OAuth2 provider apps.
    // The member site role grants Oauth2App::Read, so all authenticated users
    // with the default member role retain access (backward compatible).
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::Oauth2App),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to read OAuth2 provider apps.",
        ));
    }

    let app_uuid = match Uuid::parse_str(&app_id) {
        Ok(id) => id,
        Err(_) => {
            return Ok(not_found_response("OAuth2 provider app not found."));
        }
    };
    let app = match state.oauth2_provider.get_app(app_uuid).await {
        Ok(app) => app,
        Err(error) => return handle_oauth2_provider_error(error),
    };
    Ok((StatusCode::OK, Json(oauth2_app_response(app))).into_response())
}

pub(crate) async fn put_oauth2_provider_app(
    State(state): State<AppState>,
    Path(app_id): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<PutOAuth2ProviderAppRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can update OAuth2 provider apps.
    // This intentionally replaces the prior is_owner() gate to support future
    // custom roles that may grant OAuth2 app management without full ownership.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::Oauth2App),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update OAuth2 provider apps.",
        ));
    }

    let app_uuid = match Uuid::parse_str(&app_id) {
        Ok(id) => id,
        Err(_) => {
            return Ok(not_found_response("OAuth2 provider app not found."));
        }
    };
    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    let app = match state
        .oauth2_provider
        .update_app(
            app_uuid,
            &request.name,
            &request.icon,
            &request.callback_url,
        )
        .await
    {
        Ok(app) => app,
        Err(error) => return handle_oauth2_provider_error(error),
    };

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::Oauth2ProviderApp,
        Some(&context.user),
        Some(app.id.to_string()),
        "updated oauth2 provider app",
    )
    .await;

    Ok((StatusCode::OK, Json(oauth2_app_response(app))).into_response())
}

pub(crate) async fn delete_oauth2_provider_app(
    State(state): State<AppState>,
    Path(app_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can delete OAuth2 provider apps.
    // This intentionally replaces the prior is_owner() gate to support future
    // custom roles that may grant OAuth2 app management without full ownership.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Delete,
            &Object::new(ResourceType::Oauth2App),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to delete OAuth2 provider apps.",
        ));
    }

    let app_uuid = match Uuid::parse_str(&app_id) {
        Ok(id) => id,
        Err(_) => {
            return Ok(not_found_response("OAuth2 provider app not found."));
        }
    };
    if let Err(error) = state.oauth2_provider.delete_app(app_uuid).await {
        return handle_oauth2_provider_error(error);
    }

    record_audit(
        &state,
        AuditAction::Delete,
        ResourceKind::Oauth2ProviderApp,
        Some(&context.user),
        Some(app_id),
        "deleted oauth2 provider app",
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

pub(crate) async fn list_oauth2_provider_app_secrets(
    State(state): State<AppState>,
    Path(app_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can read OAuth2 provider app secrets.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::Oauth2AppSecret),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to list OAuth2 provider app secrets.",
        ));
    }

    let app_uuid = match Uuid::parse_str(&app_id) {
        Ok(id) => id,
        Err(_) => {
            return Ok(not_found_response("OAuth2 provider app not found."));
        }
    };
    let secrets = match state.oauth2_provider.list_app_secrets(app_uuid).await {
        Ok(secrets) => secrets,
        Err(error) => return handle_oauth2_provider_error(error),
    };
    let response: Vec<OAuth2ProviderAppSecretResponse> =
        secrets.into_iter().map(oauth2_secret_response).collect();
    Ok((StatusCode::OK, Json(response)).into_response())
}

pub(crate) async fn post_oauth2_provider_app_secret(
    State(state): State<AppState>,
    Path(app_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can create OAuth2 provider app secrets.
    // This intentionally replaces the prior is_owner() gate to support future
    // custom roles that may grant OAuth2 app management without full ownership.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Create,
            &Object::new(ResourceType::Oauth2AppSecret),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to create OAuth2 provider app secrets.",
        ));
    }

    let app_uuid = match Uuid::parse_str(&app_id) {
        Ok(id) => id,
        Err(_) => {
            return Ok(not_found_response("OAuth2 provider app not found."));
        }
    };
    let (raw_secret, record) = match state.oauth2_provider.create_app_secret(app_uuid).await {
        Ok(result) => result,
        Err(error) => return handle_oauth2_provider_error(error),
    };

    record_audit(
        &state,
        AuditAction::Create,
        ResourceKind::Oauth2ProviderAppSecret,
        Some(&context.user),
        Some(record.id.to_string()),
        "created oauth2 provider app secret",
    )
    .await;

    let response = OAuth2ProviderAppSecretFullResponse {
        id: record.id.to_string(),
        client_secret_full: raw_secret,
        client_secret_truncated: record.display_secret,
    };
    Ok((StatusCode::CREATED, Json(response)).into_response())
}

pub(crate) async fn delete_oauth2_provider_app_secret(
    State(state): State<AppState>,
    Path((app_id, secret_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can delete OAuth2 provider app secrets.
    // This intentionally replaces the prior is_owner() gate to support future
    // custom roles that may grant OAuth2 app management without full ownership.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Delete,
            &Object::new(ResourceType::Oauth2AppSecret),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to delete OAuth2 provider app secrets.",
        ));
    }

    let app_uuid = match Uuid::parse_str(&app_id) {
        Ok(id) => id,
        Err(_) => {
            return Ok(not_found_response("OAuth2 provider app not found."));
        }
    };
    let secret_uuid = match Uuid::parse_str(&secret_id) {
        Ok(id) => id,
        Err(_) => {
            return Ok(not_found_response("OAuth2 provider app secret not found."));
        }
    };
    if let Err(error) = state
        .oauth2_provider
        .delete_app_secret(app_uuid, secret_uuid)
        .await
    {
        return handle_oauth2_provider_error(error);
    }

    record_audit(
        &state,
        AuditAction::Delete,
        ResourceKind::Oauth2ProviderAppSecret,
        Some(&context.user),
        Some(secret_id),
        "deleted oauth2 provider app secret",
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

pub(crate) async fn delete_oauth2_provider_app_tokens(
    State(state): State<AppState>,
    Path(app_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // No RBAC check here: this is a self-service endpoint where any
    // authenticated user can revoke their own OAuth2 app authorizations.
    // The downstream revoke_tokens() call is scoped to context.user.id,
    // so users can only revoke their own tokens.

    let app_uuid = match Uuid::parse_str(&app_id) {
        Ok(id) => id,
        Err(_) => {
            return Ok(not_found_response("OAuth2 provider app not found."));
        }
    };
    if let Err(error) = state
        .oauth2_provider
        .revoke_tokens(app_uuid, context.user.id)
        .await
    {
        return handle_oauth2_provider_error(error);
    }

    record_audit(
        &state,
        AuditAction::Delete,
        ResourceKind::Oauth2ProviderApp,
        Some(&context.user),
        Some(app_id),
        "revoked oauth2 provider app tokens",
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

pub(crate) async fn get_oauth2_authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<OAuth2AuthorizeRequest>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if params.response_type != "code" {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "response_type must be \"code\".",
                "Only the authorization code flow is supported.",
            )),
        )
            .into_response());
    }
    let client_id = match Uuid::parse_str(&params.client_id) {
        Ok(id) => id,
        Err(_) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error(
                    "Invalid client_id.",
                    "The client_id must be a valid UUID.",
                )),
            )
                .into_response());
        }
    };

    // Validate the app and its callback URL BEFORE creating the authorization
    // code.  This prevents orphaned codes when the callback URL is invalid.
    let app = match state.oauth2_provider.get_app(client_id).await {
        Ok(app) => app,
        Err(error) => return handle_oauth2_provider_error(error),
    };
    let mut redirect_url = match url::Url::parse(&app.callback_url) {
        Ok(url) => url,
        Err(_) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error(
                    "App has invalid callback URL.",
                    "The registered callback URL could not be parsed.",
                )),
            )
                .into_response());
        }
    };

    let raw_code = match state
        .oauth2_provider
        .create_authorization_code(
            client_id,
            context.user.id,
            &params.resource,
            &params.code_challenge,
            &params.code_challenge_method,
        )
        .await
    {
        Ok(code) => code,
        Err(error) => return handle_oauth2_provider_error(error),
    };

    // Build the redirect URL with the code and state.
    redirect_url
        .query_pairs_mut()
        .append_pair("code", &raw_code)
        .append_pair("state", &params.state);

    Ok((
        StatusCode::TEMPORARY_REDIRECT,
        [("location", redirect_url.as_str())],
    )
        .into_response())
}

pub(crate) async fn post_oauth2_authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<OAuth2AuthorizeRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(params) = match payload {
        Ok(p) => p,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    if params.response_type != "code" {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "response_type must be \"code\".",
                "Only the authorization code flow is supported.",
            )),
        )
            .into_response());
    }
    let client_id = match Uuid::parse_str(&params.client_id) {
        Ok(id) => id,
        Err(_) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error(
                    "Invalid client_id.",
                    "The client_id must be a valid UUID.",
                )),
            )
                .into_response());
        }
    };

    // Validate the app and its callback URL BEFORE creating the authorization
    // code.  This prevents orphaned codes when the callback URL is invalid.
    let app = match state.oauth2_provider.get_app(client_id).await {
        Ok(app) => app,
        Err(error) => return handle_oauth2_provider_error(error),
    };
    let mut redirect_url = match url::Url::parse(&app.callback_url) {
        Ok(url) => url,
        Err(_) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error(
                    "App has invalid callback URL.",
                    "The registered callback URL could not be parsed.",
                )),
            )
                .into_response());
        }
    };

    let raw_code = match state
        .oauth2_provider
        .create_authorization_code(
            client_id,
            context.user.id,
            &params.resource,
            &params.code_challenge,
            &params.code_challenge_method,
        )
        .await
    {
        Ok(code) => code,
        Err(error) => return handle_oauth2_provider_error(error),
    };

    // Build the redirect URL with the code and state.
    redirect_url
        .query_pairs_mut()
        .append_pair("code", &raw_code)
        .append_pair("state", &params.state);

    // Use 303 See Other (not 307) so the browser follows the redirect with
    // GET.  A 307 would re-issue the POST to the callback URL, which only
    // handles GET per RFC 6749 §4.1.2.
    Ok((StatusCode::SEE_OTHER, [("location", redirect_url.as_str())]).into_response())
}

pub(crate) async fn post_oauth2_token(
    State(state): State<AppState>,
    Form(request): Form<OAuth2TokenRequest>,
) -> Result<Response, AppError> {
    match request.grant_type.as_str() {
        "authorization_code" => {
            let client_id = match Uuid::parse_str(&request.client_id) {
                Ok(id) => id,
                Err(_) => {
                    return Ok((
                        StatusCode::BAD_REQUEST,
                        Json(ApiResponse::error(
                            "Invalid client_id.",
                            "The client_id must be a valid UUID.",
                        )),
                    )
                        .into_response());
                }
            };
            let result = match state
                .oauth2_provider
                .exchange_code(
                    &request.code,
                    client_id,
                    &request.client_secret,
                    &request.code_verifier,
                )
                .await
            {
                Ok(result) => result,
                Err(error) => return handle_oauth2_provider_error(error),
            };
            let response = OAuth2TokenResponse {
                access_token: result.access_token,
                token_type: result.token_type,
                expires_in: result.expires_in,
                refresh_token: result.refresh_token,
            };
            Ok((StatusCode::OK, Json(response)).into_response())
        }
        "refresh_token" => {
            let client_id = match Uuid::parse_str(&request.client_id) {
                Ok(id) => id,
                Err(_) => {
                    return Ok((
                        StatusCode::BAD_REQUEST,
                        Json(ApiResponse::error(
                            "Invalid client_id.",
                            "The client_id must be a valid UUID.",
                        )),
                    )
                        .into_response());
                }
            };
            let result = match state
                .oauth2_provider
                .refresh_token(&request.refresh_token, client_id, &request.client_secret)
                .await
            {
                Ok(result) => result,
                Err(error) => return handle_oauth2_provider_error(error),
            };
            let response = OAuth2TokenResponse {
                access_token: result.access_token,
                token_type: result.token_type,
                expires_in: result.expires_in,
                refresh_token: result.refresh_token,
            };
            Ok((StatusCode::OK, Json(response)).into_response())
        }
        _ => Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "Unsupported grant_type.",
                "Supported grant types are: authorization_code, refresh_token.",
            )),
        )
            .into_response()),
    }
}

pub(crate) fn handle_oauth2_provider_error(
    error: OAuth2ProviderError,
) -> Result<Response, AppError> {
    match error {
        OAuth2ProviderError::Storage(error) => Err(AppError::from(error)),
        OAuth2ProviderError::BadRequest { message } => Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(message, "")),
        )
            .into_response()),
        OAuth2ProviderError::NotFound { message } => Ok(not_found_response(message)),
        OAuth2ProviderError::Unauthorized { message } => Ok(unauthorized_response(message)),
    }
}

pub(crate) fn oauth2_app_response(
    app: coder_core::identity::OAuth2ProviderAppRecord,
) -> OAuth2ProviderAppResponse {
    OAuth2ProviderAppResponse {
        id: app.id.to_string(),
        name: app.name,
        icon: app.icon,
        callback_url: app.callback_url,
        redirect_uris: app.redirect_uris,
        endpoints: OAuth2ProviderAppEndpoints {
            authorization: "/oauth2/authorize".to_owned(),
            token: "/oauth2/tokens".to_owned(),
            device_authorization: String::new(),
        },
    }
}

pub(crate) fn oauth2_secret_response(
    secret: coder_core::identity::OAuth2ProviderAppSecretRecord,
) -> OAuth2ProviderAppSecretResponse {
    OAuth2ProviderAppSecretResponse {
        id: secret.id.to_string(),
        last_used_at: None,
        client_secret_truncated: secret.display_secret,
    }
}
