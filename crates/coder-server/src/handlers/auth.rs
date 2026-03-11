//! Auth handlers.

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

pub(crate) async fn list_api_key_scopes() -> Json<ExternalApiKeyScopes> {
    Json(ExternalApiKeyScopes {
        external: PUBLIC_API_KEY_SCOPES
            .iter()
            .map(|scope| (*scope).to_owned())
            .collect(),
    })
}

pub(crate) async fn auth_methods() -> Json<AuthMethods> {
    Json(supported_auth_methods())
}

pub(crate) async fn get_first_user(State(state): State<AppState>) -> Result<Response, AppError> {
    let exists = state.auth.first_user_exists().await?;
    let body = if exists {
        ApiResponse::ok("The initial user has already been created!")
    } else {
        ApiResponse::ok("The initial user has not been created!")
    };
    let status = if exists {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    };

    Ok((
        status,
        build_version_headers(&state.build_metadata.version),
        Json(body),
    )
        .into_response())
}

pub(crate) async fn post_first_user(
    State(state): State<AppState>,
    payload: Result<Json<CreateFirstUserRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    match state.auth.create_first_user(&request).await {
        Ok(created) => {
            record_audit(
                &state,
                AuditAction::Create,
                ResourceKind::User,
                None,
                Some(created.user_id.to_string()),
                "bootstrapped first user",
            )
            .await;

            Ok((
                StatusCode::CREATED,
                Json(CreateFirstUserResponse {
                    user_id: created.user_id,
                    organization_id: created.organization_id,
                }),
            )
                .into_response())
        }
        Err(error) => handle_auth_error(error),
    }
}

pub(crate) async fn login_with_password(
    State(state): State<AppState>,
    payload: Result<Json<LoginWithPasswordRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let outcome = match state.auth.login_with_password(&request).await {
        Ok(outcome) => outcome,
        Err(error) => return handle_auth_error(error),
    };
    record_audit(
        &state,
        AuditAction::Login,
        ResourceKind::Authentication,
        Some(&outcome.user),
        Some(outcome.user.id.to_string()),
        "authenticated with password",
    )
    .await;

    Ok((StatusCode::CREATED, Json(outcome.response)).into_response())
}

pub(crate) async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    state.auth.logout(&context.session_token).await?;
    record_audit(
        &state,
        AuditAction::Logout,
        ResourceKind::Authentication,
        Some(&context.user),
        Some(context.user.id.to_string()),
        "logged out",
    )
    .await;

    Ok((StatusCode::OK, Json(ApiResponse::ok("Logged out!"))).into_response())
}

pub(crate) async fn post_validate_user_password(
    State(state): State<AppState>,
    payload: Result<Json<ValidateUserPasswordRequest>, JsonRejection>,
) -> Response {
    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return invalid_json_response(error),
    };

    (
        StatusCode::OK,
        Json(state.auth.validate_user_password(&request)),
    )
        .into_response()
}

pub(crate) async fn post_request_one_time_passcode(
    State(state): State<AppState>,
    payload: Result<Json<RequestOneTimePasscodeRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    if let Err(error) = state.auth.request_one_time_passcode(&request).await {
        return handle_auth_error(error);
    }

    Ok(StatusCode::NO_CONTENT.into_response())
}

pub(crate) async fn post_change_password_with_one_time_passcode(
    State(state): State<AppState>,
    payload: Result<Json<ChangePasswordWithOneTimePasscodeRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let user_id = match state
        .auth
        .change_password_with_one_time_passcode(&request)
        .await
    {
        Ok(user_id) => user_id,
        Err(error) => return handle_auth_error(error),
    };

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::User,
        None,
        Some(user_id.to_string()),
        "changed password with one-time passcode",
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

pub(crate) async fn get_github_oauth_device_disabled() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ApiResponse::error(
            "GitHub OAuth2 is not enabled.",
            "This deployment does not have GitHub OAuth2 configured.",
        )),
    )
        .into_response()
}

pub(crate) async fn get_github_oauth_callback_disabled() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ApiResponse::error(
            "GitHub OAuth2 is not enabled.",
            "This deployment does not have GitHub OAuth2 configured.",
        )),
    )
        .into_response()
}

pub(crate) async fn get_oidc_callback_disabled() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ApiResponse::error(
            "OIDC is not enabled.",
            "This deployment does not have OIDC configured.",
        )),
    )
        .into_response()
}

pub(crate) async fn get_user_debug_link(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(requested_user): Path<String>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Some(target_user) = resolve_user(&state, &requested_user, &context.user).await? else {
        return Ok(not_found_response("User not found."));
    };
    if context.user.username != target_user.username && !context.actor.is_owner() {
        return Ok(forbidden_response(
            "You are not authorized to inspect this user.",
        ));
    }
    if target_user.login_type != LoginType::Oidc {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "User is not an OIDC user.",
                "Debug links are only available for OIDC-authenticated users.",
            )),
        )
            .into_response());
    }

    let links = state.store.list_user_links(target_user.id).await?;
    let claims = links
        .into_iter()
        .find(|l| l.login_type == LoginType::Oidc)
        .map(|l| l.claims)
        .unwrap_or_default();

    Ok((StatusCode::OK, Json(claims)).into_response())
}

pub(crate) async fn post_convert_login(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<ConvertLoginRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // NOTE: RBAC is enforced inside AuthService::convert_login.
    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    let message = match state
        .auth
        .convert_login(&context.user, &user, &request)
        .await
    {
        Ok(message) => message,
        Err(error) => return handle_auth_error(error),
    };
    Ok((StatusCode::BAD_REQUEST, Json(ApiResponse::ok(message))).into_response())
}

pub(crate) async fn create_session_api_key(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can create API keys for this user.
    let Some(target_user) = resolve_user(&state, &user, &context.user).await? else {
        return Ok(not_found_response("User not found."));
    };
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Create,
            &Object::new(ResourceType::ApiKey).with_owner(target_user.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to create API keys for this user.",
        ));
    }

    let result = match state
        .auth
        .create_session_api_key(&context.actor, &context.user, &user)
        .await
    {
        Ok(result) => result,
        Err(error) => return handle_auth_error(error),
    };

    record_audit(
        &state,
        AuditAction::Create,
        ResourceKind::ApiKey,
        Some(&context.user),
        Some(result.key_id),
        "created session API key",
    )
    .await;

    Ok((StatusCode::CREATED, Json(result.response)).into_response())
}

pub(crate) async fn create_token_api_key(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<CreateTokenRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can create token API keys for this user.
    let Some(target_user) = resolve_user(&state, &user, &context.user).await? else {
        return Ok(not_found_response("User not found."));
    };
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Create,
            &Object::new(ResourceType::ApiKey).with_owner(target_user.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to create token API keys for this user.",
        ));
    }

    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    let result = match state
        .auth
        .create_token_api_key(&context.actor, &context.user, &user, request)
        .await
    {
        Ok(result) => result,
        Err(error) => return handle_auth_error(error),
    };

    record_audit(
        &state,
        AuditAction::Create,
        ResourceKind::ApiKey,
        Some(&context.user),
        Some(result.key_id),
        "created token API key",
    )
    .await;

    Ok((StatusCode::CREATED, Json(result.response)).into_response())
}

pub(crate) async fn list_token_api_keys(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
    Query(query): Query<TokenListQuery>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let keys = match state
        .auth
        .list_token_api_keys(
            &context.actor,
            &context.user,
            &user,
            query.include_all,
            query.include_expired,
        )
        .await
    {
        Ok(keys) => keys,
        Err(error) => return handle_auth_error(error),
    };

    Ok((StatusCode::OK, Json(keys)).into_response())
}

pub(crate) async fn get_api_key(
    State(state): State<AppState>,
    Path((user, keyid)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let key = match state
        .auth
        .get_api_key(&context.actor, &context.user, &user, &keyid)
        .await
    {
        Ok(key) => key,
        Err(error) => return handle_auth_error(error),
    };

    Ok((StatusCode::OK, Json(key)).into_response())
}

pub(crate) async fn get_api_key_by_name(
    State(state): State<AppState>,
    Path((user, keyname)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let key = match state
        .auth
        .get_api_key_by_name(&context.actor, &context.user, &user, &keyname)
        .await
    {
        Ok(key) => key,
        Err(error) => return handle_auth_error(error),
    };

    Ok((StatusCode::OK, Json(key)).into_response())
}

pub(crate) async fn delete_api_key(
    State(state): State<AppState>,
    Path((user, keyid)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can delete API keys for this user.
    let Some(target_user) = resolve_user(&state, &user, &context.user).await? else {
        return Ok(not_found_response("User not found."));
    };
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Delete,
            &Object::new(ResourceType::ApiKey).with_owner(target_user.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to delete API keys for this user.",
        ));
    }

    let key_id = match state
        .auth
        .delete_api_key(&context.actor, &context.user, &user, &keyid)
        .await
    {
        Ok(key_id) => key_id,
        Err(error) => return handle_auth_error(error),
    };

    record_audit(
        &state,
        AuditAction::Delete,
        ResourceKind::ApiKey,
        Some(&context.user),
        Some(key_id),
        "deleted API key",
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

pub(crate) async fn expire_api_key(
    State(state): State<AppState>,
    Path((user, keyid)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can expire API keys for this user.
    let Some(target_user) = resolve_user(&state, &user, &context.user).await? else {
        return Ok(not_found_response("User not found."));
    };
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::ApiKey).with_owner(target_user.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to expire API keys for this user.",
        ));
    }

    let key_id = match state
        .auth
        .expire_api_key(&context.actor, &context.user, &user, &keyid)
        .await
    {
        Ok(key_id) => key_id,
        Err(error) => return handle_auth_error(error),
    };

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::ApiKey,
        Some(&context.user),
        Some(key_id),
        "expired API key",
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

pub(crate) async fn get_token_config(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let config = match state
        .auth
        .get_token_config(&context.actor, &context.user, &user)
        .await
    {
        Ok(config) => config,
        Err(error) => return handle_auth_error(error),
    };
    Ok((StatusCode::OK, Json(config)).into_response())
}

// ---------------------------------------------------------------------------
// End of Template & Template Version Handlers
// ---------------------------------------------------------------------------

pub(crate) async fn post_authcheck(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<AuthorizationRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    // Limit the number of resource_id lookups to prevent abuse.
    let max_id_fetch = 10;
    let id_fetch_count = request
        .checks
        .values()
        .filter(|c| !c.object.resource_id.is_empty())
        .count();
    if id_fetch_count > max_id_fetch {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                format!(
                    "Endpoint only supports using \"resource_id\" field {max_id_fetch} times, found {id_fetch_count} usages. Remove {} objects with this field set.",
                    id_fetch_count - max_id_fetch,
                ),
                "Too many resource_id lookups.",
            )),
        )
            .into_response());
    }

    let authorizer = Authorizer::new();
    let mut response = HashMap::new();

    for (key, check) in &request.checks {
        if check.object.resource_type.is_empty() {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error(
                    format!("Object's \"resource_type\" field must be defined for key \"{key}\"."),
                    "Missing resource_type.",
                )),
            )
                .into_response());
        }

        let resource_type = match ResourceType::from_str_opt(&check.object.resource_type) {
            Some(rt) => rt,
            None => {
                response.insert(key.clone(), false);
                continue;
            }
        };

        let action = match serde_json::from_value::<Action>(Value::String(check.action.clone())) {
            Ok(a) => a,
            Err(_) => {
                response.insert(key.clone(), false);
                continue;
            }
        };

        let mut obj = Object::new(resource_type);

        // Parse owner_id.
        if !check.object.owner_id.is_empty() {
            let owner_str = if check.object.owner_id == "me" {
                context.actor.user_id.to_string()
            } else {
                check.object.owner_id.clone()
            };
            if let Ok(owner_id) = Uuid::parse_str(&owner_str) {
                obj = obj.with_owner(owner_id);
            }
        }

        // Parse organization_id.
        if !check.object.organization_id.is_empty() {
            if let Ok(org_id) = Uuid::parse_str(&check.object.organization_id) {
                obj = obj.in_org(org_id);
            }
        } else if check.object.any_org {
            obj = obj.any_organization();
        }

        // Parse resource_id.
        if !check.object.resource_id.is_empty() {
            if let Ok(res_id) = Uuid::parse_str(&check.object.resource_id) {
                obj = obj.with_id(res_id);
            } else {
                return Ok((
                    StatusCode::BAD_REQUEST,
                    Json(ApiResponse::error(
                        format!("Object \"{key}\" resource_id is not a valid uuid.",),
                        "Invalid resource_id.",
                    )),
                )
                    .into_response());
            }
        }

        let result = authorizer.authorize(&context.actor, action, &obj).is_ok();
        response.insert(key.clone(), result);
    }

    Ok((StatusCode::OK, Json(response)).into_response())
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct TokenListQuery {
    #[serde(default)]
    include_all: bool,
    #[serde(default)]
    include_expired: bool,
}
