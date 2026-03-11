//! Users handlers.

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

pub(crate) async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<UsersQuery>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    // RBAC: only owners can enumerate all users (preserves can_list_users() semantics).
    if !context.actor.is_owner() {
        return Ok(forbidden_response("You are not authorized to list users."));
    }

    let status = match query.status.as_deref() {
        Some(value) => match UserStatus::from_str(value) {
            Ok(status) => Some(status),
            Err(error) => {
                return Ok(validation_response(vec![ValidationError {
                    field: "status".to_owned(),
                    detail: error.to_string(),
                }]));
            }
        },
        None => None,
    };

    let (users, count) = match state
        .identity
        .list_users(
            &context.actor,
            UserListFilter {
                search: query.q,
                status,
                limit: query.limit.unwrap_or_default(),
                offset: query.offset.unwrap_or_default(),
            },
        )
        .await
    {
        Ok(result) => result,
        Err(error) => return handle_identity_error(error),
    };

    Ok((
        StatusCode::OK,
        Json(GetUsersResponse {
            users: users.into_iter().map(UserResponse::from).collect(),
            count,
        }),
    )
        .into_response())
}

pub(crate) async fn post_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<CreateUserRequestWithOrgs>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can create users.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Create,
            &Object::new(ResourceType::User),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to create users.",
        ));
    }

    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    let user = match state.identity.create_user(&context.actor, &request).await {
        Ok(user) => user,
        Err(error) => return handle_identity_error(error),
    };

    record_audit(
        &state,
        AuditAction::Create,
        ResourceKind::User,
        Some(&context.user),
        Some(user.id.to_string()),
        "created user",
    )
    .await;

    Ok((StatusCode::CREATED, Json(UserResponse::from(user))).into_response())
}

pub(crate) async fn get_user_login_type(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let response = match state
        .auth
        .get_user_login_type(&context.actor, &context.user, &user)
        .await
    {
        Ok(response) => response,
        Err(error) => return handle_auth_error(error),
    };

    Ok((StatusCode::OK, Json(response)).into_response())
}

pub(crate) async fn get_user_git_ssh_key(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Some(target_user) = resolve_user(&state, &user, &context.user).await? else {
        return Ok(not_found_response("User not found."));
    };
    if !context.actor.can_access_user(target_user.id) {
        return Ok(not_found_response("User not found."));
    }

    let key = match state.store.find_git_ssh_key(target_user.id).await? {
        Some(key) => key,
        None => match store_new_git_ssh_key(&state, &target_user).await {
            Ok(key) => key,
            Err(error) => {
                return Ok(internal_server_error_detail_response(
                    "Internal error generating a new SSH keypair.",
                    error,
                ));
            }
        },
    };

    Ok((
        StatusCode::OK,
        Json(coder_core::GitSshKeyResponse {
            user_id: key.user_id,
            created_at: key.created_at,
            updated_at: key.updated_at,
            public_key: key.public_key,
        }),
    )
        .into_response())
}

pub(crate) async fn put_user_git_ssh_key(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Some(target_user) = resolve_user(&state, &user, &context.user).await? else {
        return Ok(not_found_response("User not found."));
    };
    // RBAC: verify the actor can update this user's SSH key.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::UpdatePersonal,
            &Object::new(ResourceType::User)
                .with_id(target_user.id)
                .with_owner(target_user.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update this user's SSH key.",
        ));
    }

    let key = match store_new_git_ssh_key(&state, &target_user).await {
        Ok(key) => key,
        Err(error) => {
            return Ok(internal_server_error_detail_response(
                "Internal error generating a new SSH keypair.",
                error,
            ));
        }
    };

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::GitSshKey,
        Some(&context.user),
        Some(target_user.id.to_string()),
        "regenerated git ssh key",
    )
    .await;

    Ok((
        StatusCode::OK,
        Json(coder_core::GitSshKeyResponse {
            user_id: key.user_id,
            created_at: key.created_at,
            updated_at: key.updated_at,
            public_key: key.public_key,
        }),
    )
        .into_response())
}

pub(crate) async fn get_user_autofill_parameters(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Some(target_user) = resolve_user(&state, &user, &context.user).await? else {
        return Ok(not_found_response("User not found."));
    };
    if context.user.username != target_user.username && !context.actor.is_owner() {
        return Ok(forbidden_response(
            "You are not authorized to inspect this user.",
        ));
    }

    let mut validations = Vec::new();
    match query.get("template_id") {
        Some(template_id) if !template_id.is_empty() => {
            if let Err(error) = Uuid::parse_str(template_id) {
                validations.push(ValidationError {
                    field: "template_id".to_owned(),
                    detail: error.to_string(),
                });
            }
        }
        _ => validations.push(ValidationError {
            field: "template_id".to_owned(),
            detail: "Missing value, this cannot be empty".to_owned(),
        }),
    }

    for key in query.keys() {
        if key != "template_id" {
            validations.push(ValidationError {
                field: key.clone(),
                detail: "unknown query parameter".to_owned(),
            });
        }
    }

    if !validations.is_empty() {
        return Ok(validation_message_response(
            "Invalid query parameters.",
            validations,
        ));
    }

    Ok(Json(Vec::<UserParameter>::new()).into_response())
}

pub(crate) async fn put_user_profile(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<UpdateUserProfileRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    // NOTE: RBAC is enforced inside IdentityService::update_user_profile.
    let updated_user = match state
        .identity
        .update_user_profile(&context.actor, &context.user, &user, &request)
        .await
    {
        Ok(user) => user,
        Err(error) => return handle_identity_error(error),
    };

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::User,
        Some(&context.user),
        Some(updated_user.id.to_string()),
        "updated user profile",
    )
    .await;

    Ok((StatusCode::OK, Json(UserResponse::from(updated_user))).into_response())
}

pub(crate) async fn put_suspend_user_account(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    put_user_status(state, user, headers, UserStatus::Suspended).await
}

pub(crate) async fn put_activate_user_account(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    put_user_status(state, user, headers, UserStatus::Active).await
}

pub(crate) async fn put_user_status(
    state: AppState,
    user: String,
    headers: HeaderMap,
    status: UserStatus,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can update user status.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::User),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update user status.",
        ));
    }

    let updated_user = match state
        .identity
        .update_user_status(&context.actor, &context.user, &user, status)
        .await
    {
        Ok(user) => user,
        Err(error) => return handle_identity_error(error),
    };

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::User,
        Some(&context.user),
        Some(updated_user.id.to_string()),
        "updated user status",
    )
    .await;

    Ok((StatusCode::OK, Json(UserResponse::from(updated_user))).into_response())
}

pub(crate) async fn get_user_appearance(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let settings = match state
        .identity
        .get_user_appearance(&context.actor, &context.user, &user)
        .await
    {
        Ok(settings) => settings,
        Err(error) => return handle_identity_error(error),
    };
    Ok((
        StatusCode::OK,
        Json(UserAppearanceSettings {
            theme_preference: settings.theme_preference,
            terminal_font: settings.terminal_font,
        }),
    )
        .into_response())
}

pub(crate) async fn put_user_appearance(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<UpdateUserAppearanceSettingsRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    // NOTE: RBAC is enforced inside IdentityService::update_user_appearance.
    let (target_user_id, settings) = match state
        .identity
        .update_user_appearance(&context.actor, &context.user, &user, &request)
        .await
    {
        Ok(settings) => settings,
        Err(error) => return handle_identity_error(error),
    };

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::User,
        Some(&context.user),
        Some(target_user_id.to_string()),
        "updated user appearance settings",
    )
    .await;

    Ok((
        StatusCode::OK,
        Json(UserAppearanceSettings {
            theme_preference: settings.theme_preference,
            terminal_font: settings.terminal_font,
        }),
    )
        .into_response())
}

pub(crate) async fn get_user_preferences(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let settings = match state
        .identity
        .get_user_preferences(&context.actor, &context.user, &user)
        .await
    {
        Ok(settings) => settings,
        Err(error) => return handle_identity_error(error),
    };
    Ok((
        StatusCode::OK,
        Json(UserPreferenceSettings {
            task_notification_alert_dismissed: settings.task_notification_alert_dismissed,
        }),
    )
        .into_response())
}

pub(crate) async fn put_user_preferences(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<UpdateUserPreferenceSettingsRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    // NOTE: RBAC is enforced inside IdentityService::update_user_preferences.
    let (target_user_id, settings) = match state
        .identity
        .update_user_preferences(&context.actor, &context.user, &user, &request)
        .await
    {
        Ok(settings) => settings,
        Err(error) => return handle_identity_error(error),
    };

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::User,
        Some(&context.user),
        Some(target_user_id.to_string()),
        "updated user preference settings",
    )
    .await;

    Ok((
        StatusCode::OK,
        Json(UserPreferenceSettings {
            task_notification_alert_dismissed: settings.task_notification_alert_dismissed,
        }),
    )
        .into_response())
}

pub(crate) async fn put_user_password(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<UpdateUserPasswordRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    // NOTE: RBAC is enforced inside AuthService::update_user_password.
    let target_user_id = match state
        .auth
        .update_user_password(&context.actor, &context.user, &user, &request)
        .await
    {
        Ok(target_user_id) => target_user_id,
        Err(error) => return handle_auth_error(error),
    };

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::User,
        Some(&context.user),
        Some(target_user_id.to_string()),
        "updated user password",
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

pub(crate) async fn get_user(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let target_user = match state
        .identity
        .get_user(&context.actor, &context.user, &user)
        .await
    {
        Ok(user) => user,
        Err(error) => return handle_identity_error(error),
    };

    Ok((StatusCode::OK, Json(UserResponse::from(target_user))).into_response())
}

pub(crate) async fn list_site_roles(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let roles = match state.identity.list_site_roles(&context.actor) {
        Ok(roles) => roles,
        Err(error) => return handle_identity_error(error),
    };

    Ok((StatusCode::OK, Json(roles)).into_response())
}

pub(crate) async fn get_user_roles(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let (target_user, organization_roles) = match state
        .identity
        .get_user_roles(&context.actor, &context.user, &user)
        .await
    {
        Ok(result) => result,
        Err(error) => return handle_identity_error(error),
    };

    Ok((
        StatusCode::OK,
        Json(UserRolesResponse {
            roles: target_user
                .roles
                .into_iter()
                .map(|role| role.name)
                .collect(),
            organization_roles,
        }),
    )
        .into_response())
}

pub(crate) async fn put_user_roles(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<UpdateRolesRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can assign user roles (admin-only).
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Assign,
            &Object::new(ResourceType::AssignRole),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to assign user roles.",
        ));
    }

    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    let updated_user = match state
        .identity
        .update_user_roles(&context.actor, &context.user, &user, &request)
        .await
    {
        Ok(user) => user,
        Err(error) => return handle_identity_error(error),
    };

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::User,
        Some(&context.user),
        Some(updated_user.id.to_string()),
        "updated user roles",
    )
    .await;

    Ok((StatusCode::OK, Json(UserResponse::from(updated_user))).into_response())
}

pub(crate) async fn list_user_organizations(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let organizations = match state
        .identity
        .list_user_organizations(&context.actor, &context.user, &user)
        .await
    {
        Ok(organizations) => organizations,
        Err(error) => return handle_identity_error(error),
    };

    Ok((
        StatusCode::OK,
        Json(
            organizations
                .into_iter()
                .map(OrganizationResponse::from)
                .collect::<Vec<_>>(),
        ),
    )
        .into_response())
}

pub(crate) async fn get_user_organization_by_name(
    State(state): State<AppState>,
    Path((user, organizationname)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let target_organization = match state
        .identity
        .get_user_organization_by_name(&context.actor, &context.user, &user, &organizationname)
        .await
    {
        Ok(organization) => organization,
        Err(error) => return handle_identity_error(error),
    };

    Ok((
        StatusCode::OK,
        Json(OrganizationResponse::from(target_organization)),
    )
        .into_response())
}

pub(crate) async fn delete_user(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can delete users.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Delete,
            &Object::new(ResourceType::User),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to delete users.",
        ));
    }

    let target_user = match state
        .identity
        .delete_user(&context.actor, &context.user, &user)
        .await
    {
        Ok(user) => user,
        Err(error) => return handle_identity_error(error),
    };

    record_audit(
        &state,
        AuditAction::Delete,
        ResourceKind::User,
        Some(&context.user),
        Some(target_user.id.to_string()),
        "deleted user",
    )
    .await;

    Ok((
        StatusCode::OK,
        Json(ApiResponse::ok("User has been deleted!")),
    )
        .into_response())
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct UsersQuery {
    #[serde(default)]
    q: String,
    status: Option<String>,
    limit: Option<u32>,
    offset: Option<u32>,
}
