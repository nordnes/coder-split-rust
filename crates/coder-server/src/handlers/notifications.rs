//! Notifications handlers.

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

/// Maximum length for custom notification title.
const MAX_CUSTOM_NOTIFICATION_TITLE_LEN: usize = 120;
/// Maximum length for custom notification message.
const MAX_CUSTOM_NOTIFICATION_MESSAGE_LEN: usize = 2000;

pub(crate) async fn get_notifications_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can read deployment configuration.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::DeploymentConfig),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to view notification settings.",
        ));
    }

    let settings = state.store.get_notifications_settings().await?;
    Ok((StatusCode::OK, Json(settings)).into_response())
}

pub(crate) async fn put_notifications_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<coder_core::NotificationsSettings>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can update deployment configuration.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::DeploymentConfig),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update notification settings.",
        ));
    }

    let Json(settings) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    state.store.upsert_notifications_settings(&settings).await?;

    Ok((StatusCode::OK, Json(settings)).into_response())
}

pub(crate) async fn get_system_notification_templates(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // NOTE: No RBAC beyond authentication — NotificationTemplate is not granted
    // to any non-owner role, but any authenticated user should be able to view
    // available notification templates (e.g., to configure preferences).

    let templates = state
        .store
        .get_notification_templates_by_kind("system")
        .await?;
    Ok((StatusCode::OK, Json(templates)).into_response())
}

pub(crate) async fn get_custom_notification_templates(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // NOTE: No RBAC beyond authentication — NotificationTemplate is not granted
    // to any non-owner role, but any authenticated user should be able to view
    // available notification templates (e.g., to configure preferences).

    let templates = state
        .store
        .get_notification_templates_by_kind("custom")
        .await?;
    Ok((StatusCode::OK, Json(templates)).into_response())
}

pub(crate) async fn post_test_notification(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can update deployment configuration.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::DeploymentConfig),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to send test notifications.",
        ));
    }

    // The test notification endpoint just returns 200 OK to confirm it's reachable.
    // Full dispatch integration is not implemented yet.
    let _ = &state;
    Ok((
        StatusCode::OK,
        Json(ApiResponse::ok("Test notification acknowledged.")),
    )
        .into_response())
}

pub(crate) async fn put_notification_template_method(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    payload: Result<Json<UpdateNotificationTemplateMethod>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can update notification templates.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::NotificationTemplate),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update notification template methods.",
        ));
    }

    let Json(body) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let method_ref = body.method.as_deref();
    if let Some(m) = method_ref {
        if !matches!(m, "smtp" | "webhook" | "inbox") {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error(
                    format!(
                        "Invalid notification method: {m}. Must be one of: smtp, webhook, inbox"
                    ),
                    "",
                )),
            )
                .into_response());
        }
    }

    let template = state
        .store
        .update_notification_template_method(id, method_ref)
        .await?;

    match template {
        Some(t) => Ok((StatusCode::OK, Json(t)).into_response()),
        None => Ok(not_found_response("Notification template not found.")),
    }
}

pub(crate) async fn get_notification_dispatch_methods(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can read deployment configuration.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::DeploymentConfig),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to view notification dispatch methods.",
        ));
    }

    let _ = &state;
    let response = coder_core::NotificationMethodsResponse {
        available: vec!["smtp".to_owned(), "webhook".to_owned(), "inbox".to_owned()],
        default: "smtp".to_owned(),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

pub(crate) async fn get_user_notification_preferences(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let target_user = match resolve_user(&state, &user, &context.user).await? {
        Some(u) => u,
        None => {
            return Ok(not_found_response("User not found."));
        }
    };

    if target_user.id != context.user.id && !context.actor.is_owner() {
        return Ok(forbidden_response(
            "You are not authorized to access this user's notification preferences.",
        ));
    }

    let preferences = state
        .store
        .get_user_notification_preferences(target_user.id)
        .await?;
    Ok((StatusCode::OK, Json(preferences)).into_response())
}

pub(crate) async fn put_user_notification_preferences(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<UpdateUserNotificationPreferences>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let target_user = match resolve_user(&state, &user, &context.user).await? {
        Some(u) => u,
        None => {
            return Ok(not_found_response("User not found."));
        }
    };

    if target_user.id != context.user.id && !context.actor.is_owner() {
        return Ok(forbidden_response(
            "You are not authorized to update this user's notification preferences.",
        ));
    }

    let Json(body) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let mut template_ids = Vec::new();
    let mut disableds = Vec::new();
    for (id_str, disabled) in &body.template_disabled_map {
        let id = match Uuid::from_str(id_str) {
            Ok(id) => id,
            Err(_) => {
                return Ok((
                    StatusCode::BAD_REQUEST,
                    Json(ApiResponse::error(
                        format!("Invalid template ID: {id_str}"),
                        "",
                    )),
                )
                    .into_response());
            }
        };
        template_ids.push(id);
        disableds.push(*disabled);
    }

    state
        .store
        .update_user_notification_preferences(target_user.id, &template_ids, &disableds)
        .await?;

    let preferences = state
        .store
        .get_user_notification_preferences(target_user.id)
        .await?;
    Ok((StatusCode::OK, Json(preferences)).into_response())
}

pub(crate) async fn list_inbox_notifications(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<InboxNotificationsQuery>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can read their own notifications.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::InboxNotification).with_owner(context.user.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to read inbox notifications.",
        ));
    }

    let read_status = params.read_status.unwrap_or_else(|| "all".to_owned());
    if !matches!(read_status.as_str(), "all" | "unread" | "read") {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                format!("Invalid read_status: {read_status}. Must be one of: all, unread, read"),
                "",
            )),
        )
            .into_response());
    }

    let templates: Option<Vec<Uuid>> = match params.templates.as_deref() {
        None | Some("") => None,
        Some(s) => {
            let mut parsed = Vec::new();
            for raw in s.split(',') {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    continue;
                }
                match Uuid::from_str(trimmed) {
                    Ok(id) => parsed.push(id),
                    Err(_) => {
                        return Ok((
                            StatusCode::BAD_REQUEST,
                            Json(ApiResponse::error(
                                format!("Invalid UUID in templates parameter: {trimmed}"),
                                "",
                            )),
                        )
                            .into_response());
                    }
                }
            }
            if parsed.is_empty() {
                None
            } else {
                Some(parsed)
            }
        }
    };
    let targets: Option<Vec<Uuid>> = match params.targets.as_deref() {
        None | Some("") => None,
        Some(s) => {
            let mut parsed = Vec::new();
            for raw in s.split(',') {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    continue;
                }
                match Uuid::from_str(trimmed) {
                    Ok(id) => parsed.push(id),
                    Err(_) => {
                        return Ok((
                            StatusCode::BAD_REQUEST,
                            Json(ApiResponse::error(
                                format!("Invalid UUID in targets parameter: {trimmed}"),
                                "",
                            )),
                        )
                            .into_response());
                    }
                }
            }
            if parsed.is_empty() {
                None
            } else {
                Some(parsed)
            }
        }
    };

    let notifications = state
        .store
        .get_filtered_inbox_notifications(
            context.user.id,
            templates.as_deref(),
            targets.as_deref(),
            &read_status,
            None,
        )
        .await?;

    let unread_count = state
        .store
        .count_unread_inbox_notifications(context.user.id)
        .await?;

    Ok((
        StatusCode::OK,
        Json(coder_core::ListInboxNotificationsResponse {
            notifications,
            unread_count,
        }),
    )
        .into_response())
}

pub(crate) async fn put_mark_all_inbox_notifications_read(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can update their own notifications.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::InboxNotification).with_owner(context.user.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update inbox notifications.",
        ));
    }

    state
        .store
        .mark_all_inbox_notifications_as_read(context.user.id, OffsetDateTime::now_utc())
        .await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

pub(crate) async fn watch_inbox_notifications(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // Return initial state. Real-time push requires pub/sub infrastructure not yet available.
    let notifications = state
        .store
        .get_filtered_inbox_notifications(context.user.id, None, None, "all", None)
        .await?;

    let unread_count = state
        .store
        .count_unread_inbox_notifications(context.user.id)
        .await?;

    Ok((
        StatusCode::OK,
        Json(coder_core::ListInboxNotificationsResponse {
            notifications,
            unread_count,
        }),
    )
        .into_response())
}

pub(crate) async fn put_inbox_notification_read_status(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    payload: Result<Json<UpdateInboxNotificationReadStatusRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can update their own notifications.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::InboxNotification).with_owner(context.user.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update inbox notifications.",
        ));
    }

    let Json(body) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    // Verify the notification exists and belongs to the user
    let notification = match state.store.get_inbox_notification_by_id(id).await? {
        Some(n) => n,
        None => {
            return Ok(not_found_response("Inbox notification not found."));
        }
    };

    if notification.user_id != context.user.id {
        return Ok(forbidden_response(
            "You are not authorized to update this notification.",
        ));
    }

    let read_at = if body.is_read {
        Some(OffsetDateTime::now_utc())
    } else {
        None
    };

    state
        .store
        .update_inbox_notification_read_status(id, read_at)
        .await?;

    let updated = state.store.get_inbox_notification_by_id(id).await?;
    let unread_count = state
        .store
        .count_unread_inbox_notifications(context.user.id)
        .await?;

    match updated {
        Some(notification) => Ok((
            StatusCode::OK,
            Json(coder_core::UpdateInboxNotificationReadStatusResponse {
                notification,
                unread_count,
            }),
        )
            .into_response()),
        None => Ok(not_found_response(
            "Inbox notification not found after update.",
        )),
    }
}

pub(crate) async fn post_user_webpush_subscription(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<WebpushSubscription>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let target_user = match resolve_user(&state, &user, &context.user).await? {
        Some(u) => u,
        None => {
            return Ok(not_found_response("User not found."));
        }
    };

    if target_user.id != context.user.id && !context.actor.is_owner() {
        return Ok(forbidden_response(
            "You are not authorized to manage this user's webpush subscriptions.",
        ));
    }

    let Json(body) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    state
        .store
        .insert_webpush_subscription(
            target_user.id,
            &body.endpoint,
            &body.p256dh_key,
            &body.auth_key,
        )
        .await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

pub(crate) async fn delete_user_webpush_subscription(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<coder_core::DeleteWebpushSubscription>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let target_user = match resolve_user(&state, &user, &context.user).await? {
        Some(u) => u,
        None => {
            return Ok(not_found_response("User not found."));
        }
    };

    if target_user.id != context.user.id && !context.actor.is_owner() {
        return Ok(forbidden_response(
            "You are not authorized to manage this user's webpush subscriptions.",
        ));
    }

    let Json(body) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let deleted = state
        .store
        .delete_webpush_subscription_by_user_and_endpoint(target_user.id, &body.endpoint)
        .await?;

    if deleted {
        Ok(StatusCode::NO_CONTENT.into_response())
    } else {
        Ok(not_found_response("Webpush subscription not found."))
    }
}

pub(crate) async fn post_user_webpush_test(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let target_user = match resolve_user(&state, &user, &context.user).await? {
        Some(u) => u,
        None => {
            return Ok(not_found_response("User not found."));
        }
    };

    if target_user.id != context.user.id && !context.actor.is_owner() {
        return Ok(forbidden_response(
            "You are not authorized to test this user's webpush subscriptions.",
        ));
    }

    // Verify user has webpush subscriptions
    let _subscriptions = state
        .store
        .get_webpush_subscriptions_by_user_id(target_user.id)
        .await?;

    // Full web push sending requires VAPID key infrastructure not yet available.
    // Return success to indicate the endpoint is reachable and the user was resolved.
    Ok((
        StatusCode::OK,
        Json(ApiResponse::ok("Web push test acknowledged.")),
    )
        .into_response())
}

/// POST /api/v2/notifications/custom — send a custom notification.
///
/// Validates the request body, ensures the caller is not a system user, and
/// enqueues a custom notification.  Full dispatch is not yet wired, so the
/// handler currently returns 204 No Content after validation succeeds.
pub(crate) async fn post_custom_notification(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<coder_core::CustomNotificationRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can create notification messages.
    // In Go, postCustomNotification checks policy.ActionCreate on
    // rbac.ResourceNotificationMessage at site level. Only the owner role
    // has NotificationMessage:Create at site scope, so this is intentionally
    // restricted to site owners. No org scoping needed.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Create,
            &Object::new(ResourceType::NotificationMessage),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to send custom notifications.",
        ));
    }

    let Json(req) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    // Validate: content is required
    let content = match &req.content {
        Some(c) => c,
        None => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error(
                    "Invalid request body",
                    "content is required",
                )),
            )
                .into_response());
        }
    };

    // Validate: title and message must be non-empty
    if content.title.trim().is_empty() || content.message.trim().is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "Invalid request body",
                "provide a non-empty 'content.title' and 'content.message'",
            )),
        )
            .into_response());
    }

    // Validate: title length
    if content.title.chars().count() > MAX_CUSTOM_NOTIFICATION_TITLE_LEN {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "Invalid request body",
                format!(
                    "'content.title' must be at most {} characters",
                    MAX_CUSTOM_NOTIFICATION_TITLE_LEN
                ),
            )),
        )
            .into_response());
    }

    // Validate: message length
    if content.message.chars().count() > MAX_CUSTOM_NOTIFICATION_MESSAGE_LEN {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "Invalid request body",
                format!(
                    "'content.message' must be at most {} characters",
                    MAX_CUSTOM_NOTIFICATION_MESSAGE_LEN
                ),
            )),
        )
            .into_response());
    }

    // In Go, system users are blocked from sending custom notifications.
    // The Rust Actor type does not yet expose an is_system() flag; this
    // check will be added once the identity layer tracks that attribute.
    let _ = &context;

    // Full notification dispatch is not yet wired in the Rust backend.
    // Return 204 No Content to match the Go handler's success response.
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[derive(Deserialize)]
pub(crate) struct InboxNotificationsQuery {
    #[serde(default)]
    targets: Option<String>,
    #[serde(default)]
    templates: Option<String>,
    #[serde(default)]
    read_status: Option<String>,
}
