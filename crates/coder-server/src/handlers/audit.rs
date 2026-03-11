//! Audit handlers.

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

//     - create_task (Create, Task)
//     - create_workspace, patch_workspace (Create/Update, Workspace)
//     - post_org_template (Create, Template)
//     - create_org_member, delete_org_member (Create/Delete, OrganizationMember)
//     - put_org_member_roles (Assign, OrganizationMember)
//     - post_oauth2_app, put_oauth2_app, delete_oauth2_app (CRUD, OAuth2ProviderApp)
//     - post_file (Create, File)
//     - put_health_settings (Update, DeploymentConfig)
//     - put_notifications_settings (Update, DeploymentConfig)
//     - put_notification_template_method (Update, NotificationTemplate)
//     - put_user_notification_preferences (Update, NotificationPreference)
//     - post_webpush_subscription, delete_webpush_subscription (Create/Delete, NotificationPreference)
//     - post_test_audit_log (Create, AuditLog)
//
//   Sensitive reads:
//     - list_audit_logs (Read, AuditLog)
//     - list_users (owner-only check, preserves can_list_users() semantics) [NEW]
//     - deployment_stats (Read, DeploymentStats) [NEW - replaced can_view_operational_data()]
//     - debug_health (Read, DeploymentConfig) [NEW]
//     - get_health_settings (Read, DeploymentConfig) [NEW]
//     - get_notifications_settings (Read, DeploymentConfig) [NEW]
//     - get_notification_dispatch_methods (Read, DeploymentConfig) [NEW]
//     - get_system_notification_templates (auth-only, no RBAC — see note in handler)
//     - get_custom_notification_templates (auth-only, no RBAC — see note in handler)
//     - insights_daus, insights_templates, insights_user_activity,
//       insights_user_latency, insights_user_status_counts (Read, DeploymentStats) [NEW]
//     - debug_coordinator, debug_tailnet, debug_derp_traffic,
//       debug_expvar, debug_pprof, debug_websocket,
//       debug_metrics (Read, DebugInfo; also allows auditor role) [NEW]
//     - get_deployment_config (Read, DeploymentConfig)
//     - list_templates (Read, Template - filter-based)
//
//   Service-layer delegation (RBAC checked inside service):
//     - get_user, get_user_roles (via IdentityService)
//     - get_organization, list_organization_members (via IdentityService)
//     - list_token_api_keys, get_api_key (via AuthService)
//
// **Public / unauthenticated endpoints (no RBAC needed):**
//     - healthz, latency_check, build_info, deployment_ssh
//     - auth_methods, get_first_user (existence check)
//     - login_with_password (pre-auth), OAuth disabled stubs
//     - DERP map, SSH config (public deployment info)
//
// **resolve_organization / resolve_user patterns:**
//   All instances correctly use `let Some(...) = resolve_*(...) else { return Ok(not_found) }`
//   or `match ... { Some => ..., None => return Ok(not_found) }`, ensuring the handler
//   stops processing when the target cannot be resolved. No RBAC bypass bugs detected.
//
// ---------------------------------------------------------------------------

pub(crate) async fn list_audit_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    // RBAC: verify the actor can read audit logs.
    // This replaces the previous can_view_operational_data() check, which was
    // redundant — role_auditor() and role_owner() both grant AuditLog::Read at
    // site level, and the RBAC check is strictly more correct and extensible.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::AuditLog),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to view audit logs.",
        ));
    }

    let response = state
        .store
        .list_audit_logs(AuditLogListFilter {
            search: query.q,
            limit: query.limit.unwrap_or(50),
            offset: query.offset.unwrap_or_default(),
        })
        .await?;

    Ok((StatusCode::OK, Json(response)).into_response())
}

pub(crate) async fn post_generate_test_audit_log(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<CreateTestAuditLogRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can create audit log entries.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Create,
            &Object::new(ResourceType::AuditLog),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to generate audit logs.",
        ));
    }

    let Json(mut request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    if request.time.is_none() {
        request.time = Some(OffsetDateTime::now_utc());
    }

    let mut additional_fields = match request.additional_fields {
        Value::Null => json!({}),
        value => value,
    };
    if let Some(build_reason) = request.build_reason {
        if !additional_fields.is_object() {
            additional_fields = json!({});
        }
        if let Some(fields) = additional_fields.as_object_mut() {
            fields.insert("build_reason".to_owned(), Value::String(build_reason));
        }
    }

    state
        .store
        .insert_audit_log(PersistAuditLogInput {
            id: Uuid::new_v4(),
            request_id: request.request_id.or_else(|| Some(Uuid::new_v4())),
            time: request.time.unwrap_or_else(OffsetDateTime::now_utc),
            ip: String::new(),
            user_agent: String::new(),
            resource_type: request.resource_type.as_str().to_owned(),
            resource_id: request.resource_id.or_else(|| Some(Uuid::new_v4())),
            resource_target: context.user.username.clone(),
            resource_icon: String::new(),
            action: request.action.as_str().to_owned(),
            diff: json!({
                "foo": {
                    "old": "bar",
                    "new": "baz",
                    "secret": false
                }
            }),
            status_code: i32::from(StatusCode::OK.as_u16()),
            additional_fields,
            description: "generated test audit log".to_owned(),
            resource_link: String::new(),
            is_deleted: false,
            organization_id: request.organization_id,
            user_id: Some(context.user.id),
        })
        .await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct AuditQuery {
    #[serde(default)]
    q: String,
    limit: Option<u32>,
    offset: Option<u32>,
}
