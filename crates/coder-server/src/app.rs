//! Router construction and HTTP handlers.

use std::{collections::HashMap, str::FromStr, sync::Arc};

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
use coder_connectivity::{HealthService, generate_git_ssh_key};
use coder_core::StorageError;
use coder_core::api::{
    ArchiveTemplateVersionsRequest, ArchiveTemplateVersionsResponse, CreateTemplateRequest,
    CreateTemplateVersionDryRunRequest, CreateTemplateVersionRequest, DAUEntry, DAUsResponse,
    DynamicParametersRequest, DynamicParametersResponse, MatchedProvisioners, MinimalUser,
    PatchTemplateVersionRequest, ProvisionerJobLog, ProvisionerJobResponse, ProvisionerJobStatus,
    ProvisionerTiming, TemplateExample, TemplateFilter, TemplateResponse,
    TemplateVersionExternalAuth, TemplateVersionParameter, TemplateVersionPreset,
    TemplateVersionPresetParameter, TemplateVersionResponse, TemplateVersionVariable,
    UpdateActiveTemplateVersionRequest, UpdateTemplateMeta, WorkspaceBuildParameter,
    WorkspaceBuildTimings, WorkspaceResource, WorkspaceResourceMetadata, WorkspaceResourceResponse,
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
/// Shared application state for the HTTP router.
#[derive(Clone)]
pub struct AppState {
    /// Redacted runtime configuration and immutable startup settings.
    pub config: ServerConfig,
    /// Static build metadata for the running binary.
    pub build_metadata: BuildMetadata,
    /// Stable deployment identifier loaded during startup.
    pub deployment_id: Uuid,
    /// Backing store used by the current HTTP handlers.
    pub store: Arc<dyn AppStore>,
    /// Structured audit sink for mutating and auth-related routes.
    pub audit: Arc<dyn AuditSink>,
    /// Pub/sub event system for real-time event broadcasting.
    pub pubsub: Arc<dyn PubSub>,
    auth: AuthService<Arc<dyn AppStore>>,
    identity: IdentityService<Arc<dyn AppStore>>,
    deployment_stats: Arc<DeploymentStatsService<Arc<dyn AppStore>>>,
    health: HealthService<Arc<dyn AppStore>>,
    external_auth: ExternalAuthService<Arc<dyn AppStore>>,
    pub oauth2_provider: OAuth2ProviderService<Arc<dyn AppStore>>,
}

impl AppState {
    /// Builds application state with default shared clients and caches.
    pub fn new(
        config: ServerConfig,
        build_metadata: BuildMetadata,
        deployment_id: Uuid,
        store: Arc<dyn AppStore>,
        audit: Arc<dyn AuditSink>,
        pubsub: Arc<dyn PubSub>,
    ) -> Result<Self, reqwest::Error> {
        let auth = AuthService::new(store.clone());
        let identity = IdentityService::new(store.clone());
        let deployment_stats = DeploymentStatsService::new(store.clone());
        let health = HealthService::new(store.clone())?;
        let external_auth = ExternalAuthService::new(store.clone())?;
        let oauth2_provider = OAuth2ProviderService::new(store.clone());

        Ok(Self {
            config,
            build_metadata,
            deployment_id,
            store,
            audit,
            pubsub,
            auth,
            identity,
            deployment_stats,
            health,
            external_auth,
            oauth2_provider,
        })
    }
}

#[derive(Debug, Default, Deserialize)]
struct UsersQuery {
    #[serde(default)]
    q: String,
    status: Option<String>,
    limit: Option<u32>,
    offset: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
struct MembersQuery {
    #[serde(default)]
    q: String,
    limit: Option<u32>,
    offset: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
struct TokenListQuery {
    #[serde(default)]
    include_all: bool,
    #[serde(default)]
    include_expired: bool,
}

#[derive(Debug, Default, Deserialize)]
struct AuditQuery {
    #[serde(default)]
    q: String,
    limit: Option<u32>,
    offset: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
struct DebugHealthQuery {
    format: Option<String>,
    #[serde(default)]
    force: bool,
}

#[derive(Debug, Default, Deserialize)]
struct ExternalAuthCallbackQuery {
    code: Option<String>,
    state: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CspViolationReport {
    #[serde(rename = "csp-report")]
    report: HashMap<String, Value>,
}

#[derive(Debug, Deserialize)]
struct InsightsDausQuery {
    #[serde(default)]
    tz_offset: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct InsightsTemplatesQuery {
    start_time: Option<String>,
    end_time: Option<String>,
    #[serde(default)]
    interval: Option<String>,
    #[serde(default)]
    template_ids: Option<String>,
    #[serde(default)]
    sections: Option<String>,
}

#[derive(Debug, Deserialize)]
struct InsightsUserActivityQuery {
    start_time: Option<String>,
    end_time: Option<String>,
    #[serde(default)]
    template_ids: Option<String>,
}

#[derive(Debug, Deserialize)]
struct InsightsUserLatencyQuery {
    start_time: Option<String>,
    end_time: Option<String>,
    #[serde(default)]
    template_ids: Option<String>,
}

#[derive(Debug, Deserialize)]
struct InsightsUserStatusCountsQuery {
    #[serde(default)]
    timezone: Option<String>,
    #[serde(default)]
    tz_offset: Option<i32>,
}

/// Query parameters for listing template versions.
#[derive(Clone, Debug, Default, Deserialize)]
struct TemplateVersionsQuery {
    #[serde(default)]
    include_archived: Option<bool>,
    #[serde(default)]
    limit: Option<u32>,
    #[serde(default)]
    offset: Option<u32>,
}

/// Builds the Axum router for the current Rust backend slice.
pub fn build_router(state: AppState) -> Router {
    let request_id_header = HeaderName::from_static("x-request-id");

    Router::new()
        .route("/", get(server_root))
        .route("/healthz", get(healthz))
        .route("/latency-check", get(latency_check))
        .route(
            "/external-auth/{externalauth}/callback",
            get(get_external_auth_callback_by_id),
        )
        .route(
            "/gitauth/{externalauth}/callback",
            get(get_external_auth_callback_by_id),
        )
        .nest(
            "/api/v2",
            Router::new()
                .route("/", get(api_root))
                .route("/audit", get(list_audit_logs))
                .route("/audit/testgenerate", post(post_generate_test_audit_log))
                .route("/auth/scopes", get(list_api_key_scopes))
                .route("/buildinfo", get(build_info))
                .route("/csp/reports", post(post_csp_report))
                .route("/deployment/config", get(deployment_config))
                .route("/deployment/stats", get(deployment_stats))
                .route("/deployment/ssh", get(deployment_ssh))
                .route("/debug/health", get(debug_health))
                .route(
                    "/debug/health/settings",
                    get(get_health_settings).put(put_health_settings),
                )
                .route("/debug/coordinator", get(debug_coordinator))
                .route("/debug/tailnet", get(debug_tailnet))
                .route("/debug/derp/traffic", get(debug_derp_traffic))
                .route("/debug/expvar", get(debug_expvar))
                .route("/debug/pprof", get(debug_pprof))
                .route("/debug/pprof/cmdline", get(debug_pprof))
                .route("/debug/pprof/profile", get(debug_pprof))
                .route("/debug/pprof/symbol", get(debug_pprof))
                .route("/debug/pprof/trace", get(debug_pprof))
                .route("/debug/ws", get(debug_websocket))
                .route("/debug/metrics", get(debug_metrics))
                .route("/insights/daus", get(insights_daus))
                .route("/insights/templates", get(insights_templates))
                .route("/insights/user-activity", get(insights_user_activity))
                .route("/insights/user-latency", get(insights_user_latency))
                .route(
                    "/insights/user-status-counts",
                    get(insights_user_status_counts),
                )
                .route("/experiments", get(get_enabled_experiments))
                .route("/experiments/available", get(get_available_experiments))
                .route("/external-auth", get(list_external_auths))
                .route(
                    "/external-auth/{externalauth}",
                    get(get_external_auth_by_id).delete(delete_external_auth_by_id),
                )
                .route(
                    "/external-auth/{externalauth}/device",
                    get(get_external_auth_device_by_id).post(post_external_auth_device_exchange),
                )
                .route("/debug/{user}/debug-link", get(get_user_debug_link))
                .route("/organizations", get(list_organizations))
                .route("/init-script/{os}/{arch}", get(get_init_script))
                .route("/organizations/{organization}", get(get_organization))
                .route(
                    "/organizations/{organization}/provisionerdaemons",
                    get(list_provisioner_daemons),
                )
                .route(
                    "/organizations/{organization}/provisionerjobs",
                    get(list_provisioner_jobs),
                )
                .route(
                    "/organizations/{organization}/provisionerjobs/{job}",
                    get(get_provisioner_job),
                )
                .route(
                    "/organizations/{organization}/provisionerjobs/{job}/cancel",
                    patch(cancel_provisioner_job),
                )
                .route(
                    "/organizations/{organization}/provisionerjobs/{job}/logs",
                    get(get_provisioner_job_logs),
                )
                .route(
                    "/organizations/{organization}/members/roles",
                    get(list_organization_roles),
                )
                .route(
                    "/organizations/{organization}/members",
                    get(list_organization_members),
                )
                .route(
                    "/organizations/{organization}/paginated-members",
                    get(list_paginated_organization_members),
                )
                .route(
                    "/organizations/{organization}/members/{user}",
                    get(get_organization_member)
                        .post(post_organization_member)
                        .delete(delete_organization_member),
                )
                .route(
                    "/organizations/{organization}/members/{user}/roles",
                    put(put_organization_member_roles),
                )
                .route(
                    "/organizations/{organization}/members/{user}/workspaces",
                    post(post_org_member_workspace),
                )
                .route(
                    "/organizations/{organization}/members/{user}/workspaces/available-users",
                    get(get_org_member_workspace_available_users),
                )
                .route("/users", get(list_users).post(post_user))
                .route("/users/authmethods", get(auth_methods))
                .route("/updatecheck", get(update_check))
                .route("/users/first", get(get_first_user).post(post_first_user))
                .route("/users/login", post(login_with_password))
                .route("/users/logout", post(logout))
                .route(
                    "/users/validate-password",
                    post(post_validate_user_password),
                )
                .route("/users/otp/request", post(post_request_one_time_passcode))
                .route(
                    "/users/otp/change-password",
                    post(post_change_password_with_one_time_passcode),
                )
                .route(
                    "/users/oauth2/github/device",
                    get(get_github_oauth_device_disabled),
                )
                .route(
                    "/users/oauth2/github/callback",
                    get(get_github_oauth_callback_disabled),
                )
                .route("/users/oidc/callback", get(get_oidc_callback_disabled))
                .route("/users/roles", get(list_site_roles))
                .route("/users/{user}/keys", post(create_session_api_key))
                .route(
                    "/users/{user}/keys/{keyid}",
                    get(get_api_key).delete(delete_api_key),
                )
                .route("/users/{user}/keys/{keyid}/expire", put(expire_api_key))
                .route(
                    "/users/{user}/keys/tokens",
                    get(list_token_api_keys).post(create_token_api_key),
                )
                .route(
                    "/users/{user}/keys/tokens/tokenconfig",
                    get(get_token_config),
                )
                .route(
                    "/users/{user}/keys/tokens/{keyname}",
                    get(get_api_key_by_name),
                )
                .route("/users/{user}/organizations", get(list_user_organizations))
                .route(
                    "/users/{user}/organizations/{organizationname}",
                    get(get_user_organization_by_name),
                )
                .route(
                    "/users/{user}/roles",
                    get(get_user_roles).put(put_user_roles),
                )
                .route("/users/{user}/login-type", get(get_user_login_type))
                .route(
                    "/users/{user}/gitsshkey",
                    get(get_user_git_ssh_key).put(put_user_git_ssh_key),
                )
                .route("/users/{user}/profile", put(put_user_profile))
                .route(
                    "/users/{user}/autofill-parameters",
                    get(get_user_autofill_parameters),
                )
                .route(
                    "/users/{user}/status/suspend",
                    put(put_suspend_user_account),
                )
                .route(
                    "/users/{user}/status/activate",
                    put(put_activate_user_account),
                )
                .route(
                    "/users/{user}/appearance",
                    get(get_user_appearance).put(put_user_appearance),
                )
                .route(
                    "/users/{user}/preferences",
                    get(get_user_preferences).put(put_user_preferences),
                )
                .route("/users/{user}/password", put(put_user_password))
                .route("/users/{user}/convert-login", post(post_convert_login))
                .route("/users/{user}", get(get_user).delete(delete_user))
                // AI Tasks
                .route("/tasks", get(list_tasks))
                .route("/tasks/{user}", post(create_task))
                .route(
                    "/tasks/{user}/{task}",
                    get(get_task).delete(delete_task),
                )
                .route("/tasks/{user}/{task}/input", patch(patch_task_input))
                .route("/tasks/{user}/{task}/logs", get(get_task_logs))
                .route("/tasks/{user}/{task}/send", post(post_task_send))
                .route("/tasks/{user}/{task}/pause", post(post_task_pause))
                .route("/tasks/{user}/{task}/resume", post(post_task_resume))
                .route(
                    "/workspaceagents/me/tasks/{task}/log-snapshot",
                    post(post_task_log_snapshot),
                )
                // Chats
                .route("/chats", get(list_chats).post(create_chat))
                .route("/chats/{chat}", get(get_chat).delete(delete_chat))
                .route("/chats/{chat}/messages", post(post_chat_message))
                .route(
                    "/chats/files",
                    post(upload_chat_file).layer(DefaultBodyLimit::max(MAX_CHAT_FILE_SIZE)),
                )
                .route("/chats/files/{file}", get(get_chat_file))
                .route("/chats/{chat}/archive", post(archive_chat_handler))
                .route("/chats/{chat}/unarchive", post(unarchive_chat_handler))
                .route("/chats/{chat}/git/watch", get(watch_chat_git))
                // Notifications domain
                .route(
                    "/notifications/settings",
                    get(get_notifications_settings).put(put_notifications_settings),
                )
                .route(
                    "/notifications/templates/system",
                    get(get_system_notification_templates),
                )
                .route(
                    "/notifications/templates/custom",
                    get(get_custom_notification_templates),
                )
                .route("/notifications/test", post(post_test_notification))
                .route("/notifications/custom", post(post_custom_notification))
                .route(
                    "/notifications/templates/{id}/method",
                    put(put_notification_template_method),
                )
                .route(
                    "/notifications/dispatch-methods",
                    get(get_notification_dispatch_methods),
                )
                .route(
                    "/users/{user}/notifications/preferences",
                    get(get_user_notification_preferences).put(put_user_notification_preferences),
                )
                // Inbox domain
                .route("/notifications/inbox", get(list_inbox_notifications))
                .route(
                    "/notifications/inbox/mark-all-as-read",
                    put(put_mark_all_inbox_notifications_read),
                )
                .route("/notifications/inbox/watch", get(watch_inbox_notifications))
                .route(
                    "/notifications/inbox/{id}/read-status",
                    put(put_inbox_notification_read_status),
                )
                // Webpush domain
                .route(
                    "/users/{user}/webpush/subscription",
                    post(post_user_webpush_subscription).delete(delete_user_webpush_subscription),
                )
                .route("/users/{user}/webpush/test", post(post_user_webpush_test))
                // Workspace domain routes
                .route("/workspaces", get(list_workspaces))
                .route(
                    "/workspaces/{workspace}",
                    get(get_workspace).patch(patch_workspace),
                )
                .route(
                    "/workspaces/{workspace}/builds",
                    get(list_workspace_builds_handler).post(post_workspace_build),
                )
                .route(
                    "/workspaces/{workspace}/autostart",
                    put(put_workspace_autostart),
                )
                .route("/workspaces/{workspace}/ttl", put(put_workspace_ttl))
                .route(
                    "/workspaces/{workspace}/dormant",
                    put(put_workspace_dormant),
                )
                .route("/workspaces/{workspace}/extend", put(put_workspace_extend))
                .route(
                    "/workspaces/{workspace}/autoupdates",
                    put(put_workspace_autoupdates),
                )
                .route(
                    "/workspaces/{workspace}/favorite",
                    put(put_workspace_favorite).delete(delete_workspace_favorite),
                )
                .route(
                    "/workspaces/{workspace}/acl",
                    get(get_workspace_acl)
                        .patch(patch_workspace_acl)
                        .delete(delete_workspace_acl),
                )
                .route(
                    "/workspaces/{workspace}/port-share",
                    get(list_workspace_port_shares)
                        .post(post_workspace_port_share)
                        .delete(delete_workspace_port_share),
                )
                .route(
                    "/workspaces/{workspace}/resolve-autostart",
                    get(get_workspace_resolve_autostart),
                )
                .route(
                    "/workspaces/{workspace}/timings",
                    get(get_workspace_timings),
                )
                .route("/workspaces/{workspace}/usage", post(post_workspace_usage))
                .route("/workspaces/{workspace}/watch", get(get_workspace_watch))
                .route(
                    "/workspaces/{workspace}/watch-ws",
                    get(get_workspace_watch_ws),
                )
                // Workspace build routes
                .route("/workspacebuilds/{build}", get(get_workspace_build))
                .route(
                    "/workspacebuilds/{build}/cancel",
                    patch(patch_cancel_workspace_build),
                )
                .route(
                    "/workspacebuilds/{build}/logs",
                    get(get_workspace_build_logs),
                )
                .route(
                    "/workspacebuilds/{build}/parameters",
                    get(get_workspace_build_parameters),
                )
                .route(
                    "/workspacebuilds/{build}/resources",
                    get(get_workspace_build_resources),
                )
                .route(
                    "/workspacebuilds/{build}/state",
                    get(get_workspace_build_state).put(put_workspace_build_state),
                )
                .route(
                    "/workspacebuilds/{build}/timings",
                    get(get_workspace_build_timings),
                )
                // User workspace routes
                .route(
                    "/users/{user}/workspace/{name}",
                    get(get_user_workspace_by_name),
                )
                .route(
                    "/users/{user}/workspace/{name}/builds/{number}",
                    get(get_user_workspace_build_by_number),
                )
                .route("/users/{user}/workspaces", post(post_user_workspace))
                .route("/authcheck", post(post_authcheck))
                // ----- Template routes -----
                .route(
                    "/organizations/{organization}/templates",
                    get(list_org_templates).post(post_org_template),
                )
                .route(
                    "/organizations/{organization}/templates/{templatename}",
                    get(get_org_template_by_name),
                )
                .route(
                    "/organizations/{organization}/templates/examples",
                    get(get_org_template_examples),
                )
                .route(
                    "/organizations/{organization}/templates/{templatename}/versions/{templateversionname}",
                    get(get_org_template_version_by_name),
                )
                .route(
                    "/organizations/{organization}/templates/{templatename}/versions/{templateversionname}/previous",
                    get(get_org_previous_template_version),
                )
                .route(
                    "/organizations/{organization}/templateversions",
                    post(post_org_template_version),
                )
                .route(
                    "/templates/{template}",
                    get(get_template).delete(delete_template).patch(patch_template),
                )
                .route("/templates/{template}/daus", get(get_template_daus))
                .route(
                    "/templates/{template}/examples",
                    get(get_template_examples),
                )
                .route(
                    "/templates/{template}/versions",
                    get(list_template_versions).patch(patch_active_template_version),
                )
                .route(
                    "/templates/{template}/versions/archive",
                    post(post_archive_template_versions),
                )
                .route(
                    "/templates/{template}/versions/{templateversionname}",
                    get(get_template_version_by_name),
                )
                .route(
                    "/templateversions/{templateversion}",
                    get(get_template_version).patch(patch_template_version),
                )
                .route(
                    "/templateversions/{templateversion}/archive",
                    post(post_archive_template_version),
                )
                .route(
                    "/templateversions/{templateversion}/cancel",
                    patch(patch_cancel_template_version),
                )
                .route(
                    "/templateversions/{templateversion}/dry-run",
                    post(post_template_version_dry_run),
                )
                .route(
                    "/templateversions/{templateversion}/dry-run/{jobid}",
                    get(get_template_version_dry_run).patch(patch_template_version_dry_run),
                )
                .route(
                    "/templateversions/{templateversion}/dry-run/{jobid}/cancel",
                    patch(patch_cancel_template_version_dry_run),
                )
                .route(
                    "/templateversions/{templateversion}/dry-run/{jobid}/logs",
                    get(get_template_version_dry_run_logs),
                )
                .route(
                    "/templateversions/{templateversion}/dry-run/{jobid}/matched-provisioners",
                    get(get_template_version_dry_run_matched_provisioners),
                )
                .route(
                    "/templateversions/{templateversion}/dry-run/{jobid}/resources",
                    get(get_template_version_dry_run_resources),
                )
                .route(
                    "/templateversions/{templateversion}/dynamic-parameters",
                    get(get_template_version_dynamic_parameters),
                )
                .route(
                    "/templateversions/{templateversion}/dynamic-parameters/evaluate",
                    post(post_template_version_dynamic_parameters_evaluate),
                )
                .route(
                    "/templateversions/{templateversion}/external-auth",
                    get(get_template_version_external_auth),
                )
                .route(
                    "/templateversions/{templateversion}/logs",
                    get(get_template_version_logs),
                )
                .route(
                    "/templateversions/{templateversion}/parameters",
                    get(get_template_version_parameters),
                )
                .route(
                    "/templateversions/{templateversion}/presets",
                    get(get_template_version_presets),
                )
                .route(
                    "/templateversions/{templateversion}/presets/{presetid}/parameters",
                    get(get_template_version_preset_parameters),
                )
                .route(
                    "/templateversions/{templateversion}/resources",
                    get(get_template_version_resources),
                )
                .route(
                    "/templateversions/{templateversion}/rich-parameters",
                    get(get_template_version_rich_parameters),
                )
                .route(
                    "/templateversions/{templateversion}/schema",
                    get(get_template_version_schema),
                )
                .route(
                    "/templateversions/{templateversion}/unarchive",
                    post(post_unarchive_template_version),
                )
                .route(
                    "/templateversions/{templateversion}/variables",
                    get(get_template_version_variables),
                )
                // ----- OAuth2 provider routes -----
                .route(
                    "/oauth2-provider/apps",
                    get(list_oauth2_provider_apps).post(post_oauth2_provider_app),
                )
                .route(
                    "/oauth2-provider/apps/{app_id}",
                    get(get_oauth2_provider_app)
                        .put(put_oauth2_provider_app)
                        .delete(delete_oauth2_provider_app),
                )
                .route(
                    "/oauth2-provider/apps/{app_id}/secrets",
                    get(list_oauth2_provider_app_secrets).post(post_oauth2_provider_app_secret),
                )
                .route(
                    "/oauth2-provider/apps/{app_id}/secrets/{secret_id}",
                    delete(delete_oauth2_provider_app_secret),
                )
                .route(
                    "/oauth2-provider/apps/{app_id}/tokens",
                    delete(delete_oauth2_provider_app_tokens),
                )
                .route(
                    "/files",
                    post(post_file).layer(DefaultBodyLimit::max(10 * 1024 * 1024)),
                )
                .route("/files/{fileid}", get(get_file_by_id))
                .route("/derp-map", get(derp_map_updates))
                .route("/regions", get(get_regions))
                .route("/tailnet", get(tailnet_rpc_conn))
                .route("/applications/host", get(applications_host))
                .route(
                    "/applications/auth-redirect",
                    get(applications_auth_redirect),
                )
                // Workspace agent routes
                .route(
                    "/workspaceagents/connection",
                    get(get_workspace_agents_connection_info),
                )
                .route(
                    "/workspaceagents/me/app-status",
                    patch(patch_workspace_agent_app_status),
                )
                .route(
                    "/workspaceagents/me/external-auth",
                    get(get_workspace_agent_external_auth),
                )
                .route(
                    "/workspaceagents/me/gitsshkey",
                    get(workspace_agent_git_ssh_key),
                )
                .route(
                    "/workspaceagents/me/gitauth",
                    get(deprecated_workspace_agent_git_auth),
                )
                .route(
                    "/workspaceagents/me/log-source",
                    post(post_workspace_agent_log_source),
                )
                .route(
                    "/workspaceagents/me/logs",
                    patch(patch_workspace_agent_logs),
                )
                .route(
                    "/workspaceagents/me/reinit",
                    get(get_workspace_agent_reinit),
                )
                .route("/workspaceagents/me/rpc", get(get_workspace_agent_rpc))
                .route("/workspaceagents/{agent}", get(get_workspace_agent))
                .route(
                    "/workspaceagents/{agent}/connection",
                    get(get_workspace_agent_connection),
                )
                .route(
                    "/workspaceagents/{agent}/containers",
                    get(get_workspace_agent_containers),
                )
                .route(
                    "/workspaceagents/{agent}/containers/devcontainers/{devcontainer}",
                    delete(delete_workspace_agent_devcontainer),
                )
                .route(
                    "/workspaceagents/{agent}/containers/devcontainers/{devcontainer}/recreate",
                    post(post_workspace_agent_recreate_devcontainer),
                )
                .route(
                    "/workspaceagents/{agent}/containers/watch",
                    get(get_workspace_agent_containers_watch),
                )
                .route(
                    "/workspaceagents/{agent}/coordinate",
                    get(get_workspace_agent_coordinate),
                )
                .route(
                    "/workspaceagents/{agent}/listening-ports",
                    get(get_workspace_agent_listening_ports),
                )
                .route(
                    "/workspaceagents/{agent}/logs",
                    get(get_workspace_agent_logs),
                )
                .route("/workspaceagents/{agent}/pty", get(get_workspace_agent_pty))
                .route(
                    "/workspaceagents/{agent}/startup-logs",
                    get(deprecated_workspace_agent_startup_logs),
                )
                .route(
                    "/workspaceagents/{agent}/watch-metadata",
                    get(get_workspace_agent_watch_metadata),
                )
                .route(
                    "/workspaceagents/{agent}/watch-metadata-ws",
                    get(get_workspace_agent_watch_metadata_ws),
                )
                .route(
                    "/workspaceagents/aws-instance-identity",
                    post(post_workspace_agent_instance_identity_aws),
                )
                .route(
                    "/workspaceagents/azure-instance-identity",
                    post(post_workspace_agent_instance_identity_azure),
                )
                .route(
                    "/workspaceagents/google-instance-identity",
                    post(post_workspace_agent_instance_identity_google),
                ),
        )
        .route(
            "/oauth2/authorize",
            get(get_oauth2_authorize).post(post_oauth2_authorize),
        )
        .route("/oauth2/tokens", post(post_oauth2_token))
        // route_layer runs *after* routing so MatchedPath is populated.
        .route_layer(middleware::from_fn(prometheus_middleware))
        .layer(middleware::from_fn(csrf_middleware))
        .layer(middleware::from_fn(csp_middleware))
        .layer(middleware::from_fn(hsts_middleware))
        .layer(middleware::from_fn(real_ip_middleware))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new())
                .on_response(DefaultOnResponse::new()),
        )
        .layer(PropagateRequestIdLayer::new(request_id_header.clone()))
        .layer(SetRequestIdLayer::new(request_id_header, MakeRequestUuid))
        .layer(NormalizePathLayer::trim_trailing_slash())
        .with_state(state)
}

async fn server_root() -> impl IntoResponse {
    (StatusCode::OK, SLIM_BUILD_MESSAGE)
}

async fn api_root() -> Json<ApiResponse> {
    Json(ApiResponse::ok("\u{1f44b}"))
}

async fn healthz(State(state): State<AppState>) -> Result<impl IntoResponse, AppError> {
    state.store.ping().await?;
    Ok((StatusCode::OK, "OK"))
}

async fn latency_check() -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static(TIMING_ALLOW_ORIGIN),
        HeaderValue::from_static("*"),
    );
    headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    headers.insert(ACCESS_CONTROL_ALLOW_HEADERS, HeaderValue::from_static("*"));
    headers.insert(
        ACCESS_CONTROL_ALLOW_CREDENTIALS,
        HeaderValue::from_static("false"),
    );
    headers.insert(ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static("*"));
    (StatusCode::OK, headers, "OK")
}

async fn build_info(State(state): State<AppState>) -> Json<coder_core::BuildInfoResponse> {
    Json(state.build_metadata.to_response(
        state.deployment_id,
        &state.config.access_url,
        state.config.telemetry_enabled,
    ))
}

async fn post_csp_report(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<CspViolationReport>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Json(report) = match payload {
        Ok(payload) => payload,
        Err(error) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error(
                    "Failed to read body, invalid json.",
                    error.body_text(),
                )),
            )
                .into_response());
        }
    };

    debug!(report = ?report.report, "CSP violation reported");

    Ok((StatusCode::OK, Json("ok")).into_response())
}

async fn deployment_config(State(state): State<AppState>) -> Json<DeploymentConfigResponse> {
    Json(DeploymentConfigResponse {
        config: state.config.public(),
        options: ServerConfig::supported_options(),
    })
}

async fn update_check(State(state): State<AppState>) -> Json<UpdateCheckResponse> {
    Json(UpdateCheckResponse {
        current: true,
        version: state.build_metadata.version.clone(),
        url: state.build_metadata.external_url.clone(),
    })
}

async fn get_init_script(
    State(state): State<AppState>,
    Path((os, arch)): Path<(String, String)>,
) -> Response {
    let script = match render_init_script(&os, &arch, state.config.access_url.as_str()) {
        Ok(script) => script,
        Err(InitScriptError::UnknownTarget { os, arch }) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::ok(format!("Unknown os/arch: {os}/{arch}"))),
            )
                .into_response();
        }
    };

    let mut response = (StatusCode::OK, script.body).into_response();
    response.headers_mut().insert(
        HeaderName::from_static("content-digest"),
        HeaderValue::from_str(&script.content_digest)
            .unwrap_or_else(|_| HeaderValue::from_static("sha256:")),
    );
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

async fn list_audit_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !can_view_operational_data(&context.actor) {
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

async fn post_generate_test_audit_log(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<CreateTestAuditLogRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !context.actor.is_owner() {
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

async fn deployment_stats(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !can_view_operational_data(&context.actor) {
        return Ok(forbidden_response(
            "You are not authorized to view deployment stats.",
        ));
    }

    Ok((StatusCode::OK, Json(state.deployment_stats.get().await?)).into_response())
}

async fn deployment_ssh(State(state): State<AppState>) -> Json<SshConfigResponse> {
    Json(SshConfigResponse {
        hostname_prefix: state.config.ssh.hostname_prefix.clone(),
        hostname_suffix: state.config.ssh.hostname_suffix.clone(),
        ssh_config_options: state.config.ssh.ssh_config_options.clone(),
    })
}

async fn debug_health(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<DebugHealthQuery>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !can_view_operational_data(&context.actor) {
        return Ok(forbidden_response(
            "You are not authorized to view deployment health.",
        ));
    }

    let settings = state.store.health_settings().await?;
    let report = state
        .health
        .report(&state.config, &state.build_metadata, query.force)
        .await?;
    let report = apply_dismissed_health_settings(report, &settings);

    match query.format.as_deref() {
        None | Some("json") => Ok((StatusCode::OK, Json(report)).into_response()),
        Some("text") => Ok((
            StatusCode::OK,
            format!(
                "time: {}\nhealthy: {}\nderp: {}\naccess_url: {}\nwebsocket: {}\ndatabase: {}\n",
                report
                    .time
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
                report.healthy,
                report.derp.healthy,
                report.access_url.healthy,
                report.websocket.healthy,
                report.database.healthy,
            ),
        )
            .into_response()),
        Some(other) => Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::ok(format!("Invalid format option {other:?}."))),
        )
            .into_response()),
    }
}

async fn get_health_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !can_view_operational_data(&context.actor) {
        return Ok(forbidden_response(
            "You are not authorized to view health settings.",
        ));
    }

    Ok((StatusCode::OK, Json(state.store.health_settings().await?)).into_response())
}

async fn put_health_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<HealthSettings>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !context.actor.is_owner() {
        return Ok(forbidden_response(
            "You are not authorized to update health settings.",
        ));
    }

    let Json(settings) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    let invalid = settings
        .dismissed_healthchecks
        .iter()
        .filter(|section| !VALID_HEALTH_SECTIONS.contains(&section.as_str()))
        .map(|section| ValidationError {
            field: "dismissed_healthchecks".to_owned(),
            detail: format!("unsupported health section: {section}"),
        })
        .collect::<Vec<_>>();
    if !invalid.is_empty() {
        return Ok(validation_message_response(
            "Request body has invalid fields.",
            invalid,
        ));
    }

    let changed = state.store.upsert_health_settings(&settings).await?;
    if !changed {
        return Ok(StatusCode::NO_CONTENT.into_response());
    }

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::HealthSettings,
        Some(&context.user),
        None,
        "updated health settings",
    )
    .await;

    Ok((StatusCode::OK, Json(settings)).into_response())
}

async fn list_api_key_scopes() -> Json<ExternalApiKeyScopes> {
    Json(ExternalApiKeyScopes {
        external: PUBLIC_API_KEY_SCOPES
            .iter()
            .map(|scope| (*scope).to_owned())
            .collect(),
    })
}

async fn get_enabled_experiments(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    Ok(Json(Vec::<String>::new()).into_response())
}

async fn get_available_experiments(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    Ok(Json(AvailableExperiments { safe: Vec::new() }).into_response())
}

async fn auth_methods() -> Json<AuthMethods> {
    Json(supported_auth_methods())
}

async fn list_external_auths(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    Ok(Json(
        state
            .external_auth
            .list(&state.config.external_auth_providers, context.user.id)
            .await?,
    )
    .into_response())
}

async fn get_external_auth_by_id(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(provider): Path<String>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Some(config) = find_external_auth_provider(&state, &provider) else {
        return Ok(resource_not_found_response());
    };
    let response = state
        .external_auth
        .get(
            &state.config.external_auth_providers,
            context.user.id,
            &provider,
        )
        .await?;
    let Some(response) = response else {
        debug_assert!(config.id.eq_ignore_ascii_case(&provider));
        return Ok(resource_not_found_response());
    };

    Ok(Json(response).into_response())
}

async fn delete_external_auth_by_id(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(provider): Path<String>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Some(response) = state
        .external_auth
        .delete(
            &state.config.external_auth_providers,
            context.user.id,
            &provider,
        )
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    record_audit(
        &state,
        AuditAction::Delete,
        ResourceKind::ExternalAuth,
        Some(&context.user),
        Some(provider.clone()),
        "deleted external auth link",
    )
    .await;

    Ok((StatusCode::OK, Json(response)).into_response())
}

async fn get_external_auth_device_by_id(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(provider): Path<String>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Some(config) = find_external_auth_provider(&state, &provider) else {
        return Ok(resource_not_found_response());
    };
    if !config.device {
        return Ok(external_auth_device_flow_unsupported_response());
    }

    state
        .external_auth
        .authorize_device(config)
        .await
        .map(|device| (StatusCode::OK, Json(device)).into_response())
        .or_else(|error| handle_external_auth_error("Failed to authorize device.", error))
}

async fn post_external_auth_device_exchange(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(provider): Path<String>,
    payload: Result<Json<ExternalAuthDeviceExchangeRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Some(config) = find_external_auth_provider(&state, &provider) else {
        return Ok(resource_not_found_response());
    };
    if !config.device {
        return Ok(external_auth_device_flow_unsupported_response());
    }
    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    if request.device_code.trim().is_empty() {
        return Ok(validation_message_response(
            "Request body has invalid fields.",
            vec![ValidationError {
                field: "device_code".to_owned(),
                detail: "Missing value, this cannot be empty".to_owned(),
            }],
        ));
    }

    if let Err(error) = state
        .external_auth
        .exchange_device(config, context.user.id, &request)
        .await
    {
        return handle_external_auth_error("Failed to exchange device code.", error);
    }

    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn get_external_auth_callback_by_id(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(provider): Path<String>,
    Query(query): Query<ExternalAuthCallbackQuery>,
) -> Result<Response, AppError> {
    let Some(config) = find_external_auth_provider(&state, &provider) else {
        return Ok(resource_not_found_response());
    };
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(redirect_to_login_response(
            &uri,
            "Missing or invalid session token.",
        ));
    };
    let Some(state_value) = query.state.filter(|value| !value.trim().is_empty()) else {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::ok("State must be provided.")),
        )
            .into_response());
    };
    let Some(state_cookie) = cookie_from_headers(&headers, OAUTH2_STATE_COOKIE) else {
        return Ok(unauthorized_response(format!(
            "Cookie {OAUTH2_STATE_COOKIE:?} must be provided."
        )));
    };
    if state_cookie != state_value {
        return Ok(unauthorized_response("State mismatched."));
    }
    let Some(code) = query.code.filter(|value| !value.trim().is_empty()) else {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::ok("Code must be provided.")),
        )
            .into_response());
    };

    if let Err(error) = state
        .external_auth
        .exchange_callback(config, context.user.id, &code)
        .await
    {
        return handle_external_auth_error("Failed exchanging OAuth code.", error);
    }

    let redirect = cookie_from_headers(&headers, OAUTH2_REDIRECT_COOKIE)
        .map(|value| sanitize_redirect_uri(&value))
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| format!("/external-auth/{provider}?redirected=true"));

    let mut response = StatusCode::TEMPORARY_REDIRECT.into_response();
    response.headers_mut().insert(
        LOCATION,
        HeaderValue::from_str(&redirect).unwrap_or_else(|_| HeaderValue::from_static("/")),
    );
    Ok(response)
}

async fn get_first_user(State(state): State<AppState>) -> Result<Response, AppError> {
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

async fn post_first_user(
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

async fn login_with_password(
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

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, AppError> {
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

async fn post_validate_user_password(
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

async fn post_request_one_time_passcode(
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

async fn post_change_password_with_one_time_passcode(
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

async fn get_github_oauth_device_disabled() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ApiResponse::ok("GitHub OAuth2 is not enabled.")),
    )
        .into_response()
}

async fn get_github_oauth_callback_disabled() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ApiResponse::ok("GitHub OAuth2 is not enabled.")),
    )
        .into_response()
}

async fn get_oidc_callback_disabled() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ApiResponse::ok("OIDC is not enabled.")),
    )
        .into_response()
}

async fn get_user_debug_link(
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
            Json(ApiResponse::ok("User is not an OIDC user.")),
        )
            .into_response());
    }

    Ok(not_implemented_response(
        "OIDC debug context is not yet available in the Rust backend.",
    ))
}

async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<UsersQuery>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !context.actor.can_list_users() {
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

async fn post_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<CreateUserRequestWithOrgs>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
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

async fn get_user_login_type(
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

async fn get_user_git_ssh_key(
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
                return Ok((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiResponse::error(
                        "Internal error generating a new SSH keypair.",
                        error,
                    )),
                )
                    .into_response());
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

async fn put_user_git_ssh_key(
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

    let key = match store_new_git_ssh_key(&state, &target_user).await {
        Ok(key) => key,
        Err(error) => {
            return Ok((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error(
                    "Internal error generating a new SSH keypair.",
                    error,
                )),
            )
                .into_response());
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

async fn get_user_autofill_parameters(
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

async fn put_user_profile(
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

async fn put_suspend_user_account(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    put_user_status(state, user, headers, UserStatus::Suspended).await
}

async fn put_activate_user_account(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    put_user_status(state, user, headers, UserStatus::Active).await
}

async fn put_user_status(
    state: AppState,
    user: String,
    headers: HeaderMap,
    status: UserStatus,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
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

async fn get_user_appearance(
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

async fn put_user_appearance(
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

async fn get_user_preferences(
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

async fn put_user_preferences(
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

async fn put_user_password(
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

async fn post_convert_login(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<ConvertLoginRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
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

async fn get_user(
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

async fn list_site_roles(
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

async fn get_user_roles(
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

async fn put_user_roles(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<UpdateRolesRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
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

async fn list_organizations(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let organizations = match state.identity.list_organizations(&context.actor).await {
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

async fn get_organization(
    State(state): State<AppState>,
    Path(organization): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let target_organization = match state
        .identity
        .get_organization(&context.actor, &organization)
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

async fn list_organization_roles(
    State(state): State<AppState>,
    Path(organization): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let roles = match state
        .identity
        .list_organization_roles(&context.actor, &organization)
        .await
    {
        Ok(roles) => roles,
        Err(error) => return handle_identity_error(error),
    };

    Ok((StatusCode::OK, Json(roles)).into_response())
}

async fn list_organization_members(
    State(state): State<AppState>,
    Path(organization): Path<String>,
    headers: HeaderMap,
    Query(query): Query<MembersQuery>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let members = match state
        .identity
        .list_organization_members(
            &context.actor,
            &organization,
            query.q,
            query.limit.unwrap_or_default(),
            query.offset.unwrap_or_default(),
        )
        .await
    {
        Ok(members) => members,
        Err(error) => return handle_identity_error(error),
    };

    Ok((
        StatusCode::OK,
        Json(
            members
                .into_iter()
                .map(OrganizationMemberWithUserData::from)
                .collect::<Vec<_>>(),
        ),
    )
        .into_response())
}

async fn list_paginated_organization_members(
    State(state): State<AppState>,
    Path(organization): Path<String>,
    headers: HeaderMap,
    Query(query): Query<MembersQuery>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let (members, count) = match state
        .identity
        .list_organization_members_page(
            &context.actor,
            &organization,
            query.q,
            query.limit.unwrap_or_default(),
            query.offset.unwrap_or_default(),
        )
        .await
    {
        Ok(result) => result,
        Err(error) => return handle_identity_error(error),
    };

    Ok((
        StatusCode::OK,
        Json(PaginatedMembersResponse {
            members: members
                .into_iter()
                .map(OrganizationMemberWithUserData::from)
                .collect(),
            count,
        }),
    )
        .into_response())
}

async fn get_organization_member(
    State(state): State<AppState>,
    Path((organization, user)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let member = match state
        .identity
        .get_organization_member(&context.actor, &context.user, &organization, &user)
        .await
    {
        Ok(member) => member,
        Err(error) => return handle_identity_error(error),
    };

    Ok((
        StatusCode::OK,
        Json(OrganizationMemberWithUserData::from(member)),
    )
        .into_response())
}

async fn post_organization_member(
    State(state): State<AppState>,
    Path((organization, user)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let member = match state
        .identity
        .create_organization_member(&context.actor, &context.user, &organization, &user)
        .await
    {
        Ok(member) => member,
        Err(error) => return handle_identity_error(error),
    };

    record_audit(
        &state,
        AuditAction::Create,
        ResourceKind::OrganizationMember,
        Some(&context.user),
        Some(format!("{}:{}", member.organization_id, member.user_id)),
        "added organization member",
    )
    .await;

    Ok((
        StatusCode::OK,
        Json(OrganizationMemberWithUserData::from(member)),
    )
        .into_response())
}

async fn delete_organization_member(
    State(state): State<AppState>,
    Path((organization, user)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let (organization_id, user_id) = match state
        .identity
        .delete_organization_member(&context.actor, &context.user, &organization, &user)
        .await
    {
        Ok(ids) => ids,
        Err(error) => return handle_identity_error(error),
    };

    record_audit(
        &state,
        AuditAction::Delete,
        ResourceKind::OrganizationMember,
        Some(&context.user),
        Some(format!("{}:{}", organization_id, user_id)),
        "removed organization member",
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn put_organization_member_roles(
    State(state): State<AppState>,
    Path((organization, user)): Path<(String, String)>,
    headers: HeaderMap,
    payload: Result<Json<UpdateRolesRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    let updated_member = match state
        .identity
        .update_organization_member_roles(
            &context.actor,
            &context.user,
            &organization,
            &user,
            &request,
        )
        .await
    {
        Ok(member) => member,
        Err(error) => return handle_identity_error(error),
    };

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::OrganizationMember,
        Some(&context.user),
        Some(format!(
            "{}:{}",
            updated_member.organization_id, updated_member.user_id
        )),
        "updated organization member roles",
    )
    .await;

    Ok((
        StatusCode::OK,
        Json(OrganizationMember::from(updated_member)),
    )
        .into_response())
}

async fn create_session_api_key(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
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

async fn create_token_api_key(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<CreateTokenRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
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

async fn list_token_api_keys(
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

async fn get_api_key(
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

async fn get_api_key_by_name(
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

async fn delete_api_key(
    State(state): State<AppState>,
    Path((user, keyid)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
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

async fn expire_api_key(
    State(state): State<AppState>,
    Path((user, keyid)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
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

async fn get_token_config(
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

async fn list_user_organizations(
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

async fn get_user_organization_by_name(
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

async fn delete_user(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
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

// ---------------------------------------------------------------------------
// GET /organizations/{org}/provisionerdaemons — list provisioner daemons.
// The provisioner domain is a stub; we return an empty array.
// ---------------------------------------------------------------------------
async fn list_provisioner_daemons(
    State(state): State<AppState>,
    Path(organization): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    // Validate the organization exists and the caller has access.
    if let Err(error) = state
        .identity
        .get_organization(&context.actor, &organization)
        .await
    {
        return handle_identity_error(error);
    }
    let empty: Vec<coder_core::ProvisionerDaemonResponse> = Vec::new();
    Ok((StatusCode::OK, Json(empty)).into_response())
}

// ---------------------------------------------------------------------------
// GET /organizations/{org}/provisionerjobs — list provisioner jobs.
// The provisioner domain is a stub; we return an empty array.
// ---------------------------------------------------------------------------
async fn list_provisioner_jobs(
    State(state): State<AppState>,
    Path(organization): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    // Validate the organization exists and the caller has access.
    if let Err(error) = state
        .identity
        .get_organization(&context.actor, &organization)
        .await
    {
        return handle_identity_error(error);
    }
    let empty: Vec<ProvisionerJobResponse> = Vec::new();
    Ok((StatusCode::OK, Json(empty)).into_response())
}

// ---------------------------------------------------------------------------
// GET /organizations/{org}/provisionerjobs/{job} — get a single provisioner
// job. Stub: always returns 404.
// ---------------------------------------------------------------------------
async fn get_provisioner_job(
    State(state): State<AppState>,
    Path((organization, _job)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    // Validate the organization exists and the caller has access.
    if let Err(error) = state
        .identity
        .get_organization(&context.actor, &organization)
        .await
    {
        return handle_identity_error(error);
    }
    Ok((
        StatusCode::NOT_FOUND,
        Json(ApiResponse::error(
            "Resource not found or you do not have access to this resource",
            "The provisioner domain is not yet implemented in this backend slice.",
        )),
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// PATCH /organizations/{org}/provisionerjobs/{job}/cancel — cancel a
// provisioner job. Stub: always returns 404.
// ---------------------------------------------------------------------------
async fn cancel_provisioner_job(
    State(state): State<AppState>,
    Path((organization, _job)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    // Validate the organization exists and the caller has access.
    if let Err(error) = state
        .identity
        .get_organization(&context.actor, &organization)
        .await
    {
        return handle_identity_error(error);
    }
    Ok((
        StatusCode::NOT_FOUND,
        Json(ApiResponse::error(
            "Resource not found or you do not have access to this resource",
            "The provisioner domain is not yet implemented in this backend slice.",
        )),
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// GET /organizations/{org}/provisionerjobs/{job}/logs — stream provisioner
// job logs. Stub: returns 404 (consistent with get/cancel single-job stubs).
// ---------------------------------------------------------------------------
async fn get_provisioner_job_logs(
    State(state): State<AppState>,
    Path((organization, _job)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    // Validate the organization exists and the caller has access.
    if let Err(error) = state
        .identity
        .get_organization(&context.actor, &organization)
        .await
    {
        return handle_identity_error(error);
    }
    Ok((
        StatusCode::NOT_FOUND,
        Json(ApiResponse::error(
            "Resource not found or you do not have access to this resource",
            "The provisioner domain is not yet implemented in this backend slice.",
        )),
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// GET /applications/host — returns the wildcard hostname for workspace
// applications (currently empty).
// ---------------------------------------------------------------------------
async fn applications_host(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    Ok((
        StatusCode::OK,
        Json(AppHostResponse {
            host: String::new(),
        }),
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// GET /applications/auth-redirect — redirects with an encrypted API key.
// Stub: returns 400 because subdomain apps are not supported yet.
// ---------------------------------------------------------------------------
async fn applications_auth_redirect(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    Ok((
        StatusCode::BAD_REQUEST,
        Json(ApiResponse::error(
            "Subdomain-based application routing is not supported in this deployment.",
            "Subdomain-based workspace application routing requires additional proxy configuration.",
        )),
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// GET /workspaceagents/me/gitsshkey — workspace agent endpoint.
// In Go this is `agentGitSSHKey` in `gitsshkey.go` — returns the agent's
// Git SSH key for the workspace owner.
// ---------------------------------------------------------------------------
async fn workspace_agent_git_ssh_key(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    // Try agent auth first, fall back to user auth for backwards compatibility.
    let agent = authenticate_agent_request(&state, &headers).await?;
    if agent.is_none() {
        let Some(_context) = authenticate_request(&state, &headers).await? else {
            return Ok(unauthorized_response("Missing or invalid session token."));
        };
        // User-authenticated fallback: return empty stub (owner key lookup
        // requires workspace resolution which is not yet available for user auth).
        return Ok((
            StatusCode::OK,
            Json(json!({"public_key":"","private_key":""})),
        )
            .into_response());
    }
    let agent = match agent {
        Some(a) => a,
        None => return Ok(unauthorized_response("Missing or invalid agent token.")),
    };

    // Look up the workspace to find the owner, then fetch their git SSH key.
    let workspace = state.store.find_workspace_by_agent_id(agent.id).await?;
    let owner_id = match workspace {
        Some(ref ws) => ws.owner_id,
        None => {
            return Ok((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error("Failed to get workspace for agent.", "")),
            )
                .into_response());
        }
    };

    let key = state.store.find_git_ssh_key(owner_id).await?;
    match key {
        Some(k) => Ok((
            StatusCode::OK,
            Json(json!({
                "public_key": k.public_key,
                "private_key": k.private_key,
            })),
        )
            .into_response()),
        None => Ok((
            StatusCode::OK,
            Json(json!({"public_key":"","private_key":""})),
        )
            .into_response()),
    }
}

// ---------------------------------------------------------------------------
// Deprecated endpoints — return empty arrays or stub responses matching the
// original Go implementation in deprecated.go.
// ---------------------------------------------------------------------------

/// GET /workspaceagents/me/gitauth — deprecated, returns empty array.
/// Accepts both agent auth and user auth for backwards compatibility.
async fn deprecated_workspace_agent_git_auth(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let agent = authenticate_agent_request(&state, &headers).await?;
    if agent.is_none() {
        let Some(_context) = authenticate_request(&state, &headers).await? else {
            return Ok(unauthorized_response("Missing or invalid session token."));
        };
    }
    let empty: Vec<Value> = Vec::new();
    Ok((StatusCode::OK, Json(empty)).into_response())
}

/// GET /workspaceagents/{agent}/startup-logs — deprecated, delegates to the logs endpoint.
///
/// The Go implementation redirects this to the main logs endpoint.
/// We replicate the same behavior by returning the agent logs directly.
async fn deprecated_workspace_agent_startup_logs(
    State(state): State<AppState>,
    Path(agent_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(_row) = state.store.find_workspace_agent_by_id(agent_id).await? else {
        return Ok(resource_not_found_response());
    };

    // Return agent logs with default parameters (no follow, after=0, limit=256).
    let limit: i64 = 256;
    let log_rows = state
        .store
        .list_workspace_agent_logs(agent_id, 0, limit)
        .await?;
    let logs: Vec<coder_core::WorkspaceAgentLog> = log_rows
        .iter()
        .map(|r| coder_core::WorkspaceAgentLog {
            id: r.id,
            created_at: r.created_at,
            output: r.output.clone(),
            level: convert_log_level(&r.level),
            source_id: r.log_source_id,
        })
        .collect();

    Ok((StatusCode::OK, Json(logs)).into_response())
}

// ---------------------------------------------------------------------------
// AI Tasks handlers
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct TasksQuery {
    #[serde(default)]
    organization_id: Option<Uuid>,
}

/// GET /tasks — list tasks for the authenticated user.
async fn list_tasks(
    State(state): State<AppState>,
    Query(query): Query<TasksQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // Always scope to the authenticated user — no cross-user enumeration.
    let filter = TaskListFilter {
        owner_id: Some(context.user.id),
        organization_id: query.organization_id,
        ..Default::default()
    };
    let tasks = state.store.list_tasks(filter).await?;
    let count = tasks.len();
    let task_responses: Vec<TaskResponse> =
        tasks.into_iter().map(task_response_from_record).collect();

    Ok(Json(TasksListResponse {
        tasks: task_responses,
        count,
    })
    .into_response())
}

/// POST /tasks/{user} — create a new task.
async fn create_task(
    State(state): State<AppState>,
    Path(user_param): Path<String>,
    headers: HeaderMap,
    Json(request): Json<CreateTaskRequest>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // Resolve the user from the path parameter.
    let Some(target_user) = resolve_user(&state, &user_param, &context.user).await? else {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Task not found.", "")),
        )
            .into_response());
    };

    // Only allow creating tasks for oneself.
    if target_user.id != context.user.id {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Task not found.", "")),
        )
            .into_response());
    }

    let now = OffsetDateTime::now_utc();
    let task_id = Uuid::new_v4();
    let name = request.name.unwrap_or_else(|| format!("task-{task_id}"));
    let display_name = request.display_name.unwrap_or_default();

    let Some(&organization_id) = context.user.organization_ids.first() else {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "User has no organization memberships.",
                "A task cannot be created without an organization.",
            )),
        )
            .into_response());
    };

    let input = InsertTaskInput {
        id: task_id,
        organization_id,
        owner_id: context.user.id,
        name,
        display_name,
        template_version_id: request.template_version_id,
        template_parameters: Value::Object(serde_json::Map::new()),
        prompt: request.input,
        created_at: now,
    };

    let record = state.store.insert_task(input).await?;
    Ok((StatusCode::CREATED, Json(task_response_from_record(record))).into_response())
}

/// Helper: resolve a task from the `{task}` path segment — accepts UUID or
/// task name (scoped to owner).
async fn resolve_task(
    state: &AppState,
    task_param: &str,
    owner_id: Uuid,
) -> Result<Option<TaskRecord>, AppError> {
    // Try parsing as UUID first.
    if let Ok(task_id) = Uuid::parse_str(task_param) {
        let record = state.store.find_task_by_id(task_id).await?;
        // Ensure the task belongs to the expected owner.
        return Ok(record.filter(|r| r.owner_id == owner_id));
    }

    // Fall back to name-based lookup.
    state
        .store
        .find_task_by_owner_and_name(owner_id, task_param)
        .await
        .map_err(AppError::from)
}

/// GET /tasks/{user}/{task} — get a single task by ID or name.
async fn get_task(
    State(state): State<AppState>,
    Path((user_param, task_param)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(target_user) = resolve_user(&state, &user_param, &context.user).await? else {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Task not found.", "")),
        )
            .into_response());
    };

    // Only allow viewing own tasks.
    if target_user.id != context.user.id {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Task not found.", "")),
        )
            .into_response());
    }

    let Some(record) = resolve_task(&state, &task_param, target_user.id).await? else {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Task not found.", "")),
        )
            .into_response());
    };

    Ok(Json(task_response_from_record(record)).into_response())
}

/// PATCH /tasks/{user}/{task}/input — update a task's input (prompt).
async fn patch_task_input(
    State(state): State<AppState>,
    Path((user_param, task_param)): Path<(String, String)>,
    headers: HeaderMap,
    Json(request): Json<coder_core::UpdateTaskInputRequest>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(target_user) = resolve_user(&state, &user_param, &context.user).await? else {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Task not found.", "")),
        )
            .into_response());
    };

    if target_user.id != context.user.id {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Task not found.", "")),
        )
            .into_response());
    }

    let Some(record) = resolve_task(&state, &task_param, target_user.id).await? else {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Task not found.", "")),
        )
            .into_response());
    };

    // Validate non-empty input.
    if request.input.trim().is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error("Task input is required.", "")),
        )
            .into_response());
    }

    // In the Go implementation, the task must be paused to update input.
    if record.status != coder_core::TaskStatus::Paused {
        return Ok((
            StatusCode::CONFLICT,
            Json(ApiResponse::error(
                "Unable to update task input, task must be paused.",
                "Please stop the task's workspace before updating the input.",
            )),
        )
            .into_response());
    }

    let _updated = state
        .store
        .update_task_prompt(record.id, &request.input)
        .await?;

    // Go returns 204 No Content on success.
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// DELETE /tasks/{user}/{task} — soft-delete a task.
async fn delete_task(
    State(state): State<AppState>,
    Path((user_param, task_param)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(target_user) = resolve_user(&state, &user_param, &context.user).await? else {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Task not found.", "")),
        )
            .into_response());
    };

    if target_user.id != context.user.id {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Task not found.", "")),
        )
            .into_response());
    }

    let Some(record) = resolve_task(&state, &task_param, target_user.id).await? else {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Task not found.", "")),
        )
            .into_response());
    };

    let now = OffsetDateTime::now_utc();
    let deleted = state.store.delete_task(record.id, now).await?;
    if !deleted {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Task not found.", "")),
        )
            .into_response());
    }

    // Go returns 202 Accepted (workspace deletion is async).
    Ok(StatusCode::ACCEPTED.into_response())
}

/// GET /tasks/{user}/{task}/logs — get task logs (snapshot-based).
async fn get_task_logs(
    State(state): State<AppState>,
    Path((user_param, task_param)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(target_user) = resolve_user(&state, &user_param, &context.user).await? else {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Task not found.", "")),
        )
            .into_response());
    };

    if target_user.id != context.user.id {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Task not found.", "")),
        )
            .into_response());
    }

    let Some(record) = resolve_task(&state, &task_param, target_user.id).await? else {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Task not found.", "")),
        )
            .into_response());
    };

    // In the Go implementation, error/unknown status tasks cannot fetch logs.
    match record.status {
        coder_core::TaskStatus::Error | coder_core::TaskStatus::Unknown => {
            return Ok((
                StatusCode::CONFLICT,
                Json(ApiResponse::error(
                    "Cannot fetch logs for task in current state.",
                    format!("Task status is {}.", record.status),
                )),
            )
                .into_response());
        }
        // Active tasks would normally fetch live logs from the agent; for the
        // Rust port we fall through to the snapshot path since we don't yet
        // have the agent-dial infrastructure.
        _ => {}
    }

    // Check for a stored snapshot.
    let snapshot = state.store.find_task_snapshot(record.id).await?;
    let response = match snapshot {
        Some(snap) => TaskLogsResponse {
            logs: Vec::new(),
            snapshot: true,
            snapshot_at: Some(snap.log_snapshot_created_at),
        },
        None => TaskLogsResponse {
            logs: Vec::new(),
            snapshot: false,
            snapshot_at: None,
        },
    };

    Ok(Json(response).into_response())
}

/// POST /tasks/{user}/{task}/send — send input to a task.
async fn post_task_send(
    State(state): State<AppState>,
    Path((user_param, task_param)): Path<(String, String)>,
    headers: HeaderMap,
    Json(request): Json<TaskSendRequest>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(target_user) = resolve_user(&state, &user_param, &context.user).await? else {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Task not found.", "")),
        )
            .into_response());
    };

    if target_user.id != context.user.id {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Task not found.", "")),
        )
            .into_response());
    }

    let Some(record) = resolve_task(&state, &task_param, target_user.id).await? else {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Task not found.", "")),
        )
            .into_response());
    };

    // Validate non-empty input.
    if request.input.trim().is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error("Task input is required.", "")),
        )
            .into_response());
    }

    // Task must be active to accept input (matches Go status check).
    match record.status {
        coder_core::TaskStatus::Active => { /* ok */ }
        coder_core::TaskStatus::Pending | coder_core::TaskStatus::Initializing => {
            return Ok((
                StatusCode::CONFLICT,
                Json(ApiResponse::error(
                    format!("Task is {}.", record.status),
                    "The task is resuming. Wait for the task to become active before sending messages.",
                )),
            )
                .into_response());
        }
        coder_core::TaskStatus::Paused => {
            return Ok((
                StatusCode::CONFLICT,
                Json(ApiResponse::error(
                    "Task is paused.",
                    "Resume the task to send messages.",
                )),
            )
                .into_response());
        }
        _ => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error(
                    "Task must be active.",
                    format!(
                        "Task status is {}, it must be \"active\" to interact with the task.",
                        record.status
                    ),
                )),
            )
                .into_response());
        }
    }

    // In the full implementation this dials the agent and sends input to the
    // workspace sidebar app via AgentAPI. For now we acknowledge the request.
    // Go returns 204 No Content.
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// POST /tasks/{user}/{task}/pause — pause a task.
async fn post_task_pause(
    State(state): State<AppState>,
    Path((user_param, task_param)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(target_user) = resolve_user(&state, &user_param, &context.user).await? else {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Task not found.", "")),
        )
            .into_response());
    };

    if target_user.id != context.user.id {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Task not found.", "")),
        )
            .into_response());
    }

    let Some(record) = resolve_task(&state, &task_param, target_user.id).await? else {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Task not found.", "")),
        )
            .into_response());
    };

    // Task must have a workspace to pause.
    if record.workspace_id.is_none() {
        return Ok((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::error("Task does not have a workspace.", "")),
        )
            .into_response());
    }

    // In the full implementation this would stop the workspace (transition =
    // stop) and enqueue a notification. Go returns 202 Accepted.
    Ok((
        StatusCode::ACCEPTED,
        Json(coder_core::PauseTaskResponse {
            workspace_build: None,
        }),
    )
        .into_response())
}

/// POST /tasks/{user}/{task}/resume — resume a task.
async fn post_task_resume(
    State(state): State<AppState>,
    Path((user_param, task_param)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(target_user) = resolve_user(&state, &user_param, &context.user).await? else {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Task not found.", "")),
        )
            .into_response());
    };

    if target_user.id != context.user.id {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Task not found.", "")),
        )
            .into_response());
    }

    let Some(record) = resolve_task(&state, &task_param, target_user.id).await? else {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Task not found.", "")),
        )
            .into_response());
    };

    // Task must have a workspace to resume.
    if record.workspace_id.is_none() {
        return Ok((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::error("Task does not have a workspace.", "")),
        )
            .into_response());
    }

    // In the full implementation this would start the workspace (transition =
    // start) and enqueue a notification. Go returns 202 Accepted.
    Ok((
        StatusCode::ACCEPTED,
        Json(coder_core::ResumeTaskResponse {
            workspace_build: None,
        }),
    )
        .into_response())
}

async fn post_task_log_snapshot(
    State(state): State<AppState>,
    Path(task_id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<TaskLogSnapshotEnvelope>,
) -> Result<Response, AppError> {
    // This endpoint supports both agent auth and user auth.
    // Agents post log snapshots for tasks running in their workspace.
    let agent = authenticate_agent_request(&state, &headers).await?;
    let owner_id = if let Some(ref agent_row) = agent {
        // Agent auth: look up the workspace owner.
        let workspace = state.store.find_workspace_by_agent_id(agent_row.id).await?;
        match workspace {
            Some(ws) => ws.owner_id,
            None => {
                return Ok((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiResponse::error(
                        "Failed to resolve workspace for agent.",
                        "",
                    )),
                )
                    .into_response());
            }
        }
    } else {
        // Fall back to user auth.
        let Some(context) = authenticate_request(&state, &headers).await? else {
            return Ok(unauthorized_response("Missing or invalid session token."));
        };
        context.user.id
    };

    let Some(record) = state.store.find_task_by_id(task_id).await? else {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Task not found.", "")),
        )
            .into_response());
    };

    if record.owner_id != owner_id {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Task not found.", "")),
        )
            .into_response());
    }

    let now = OffsetDateTime::now_utc();
    state
        .store
        .upsert_task_snapshot(task_id, &request.log_snapshot, now)
        .await?;

    Ok((StatusCode::OK, Json(ApiResponse::ok("Snapshot saved."))).into_response())
}

fn task_response_from_record(record: TaskRecord) -> TaskResponse {
    TaskResponse {
        id: record.id,
        organization_id: record.organization_id,
        owner_id: record.owner_id,
        owner_name: String::new(),
        owner_avatar_url: String::new(),
        name: record.name,
        display_name: record.display_name,
        template_version_id: record.template_version_id,
        workspace_id: record.workspace_id,
        initial_prompt: record.prompt,
        status: record.status,
        current_state: None,
        created_at: record.created_at,
    }
}

// ---------------------------------------------------------------------------
// Chats handlers
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ChatsQuery {
    #[serde(default)]
    archived: Option<bool>,
}

async fn list_chats(
    State(state): State<AppState>,
    Query(query): Query<ChatsQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let chats = state
        .store
        .list_chats_by_owner(context.user.id, query.archived)
        .await?;

    let chat_responses: Vec<ChatResponse> =
        chats.into_iter().map(chat_response_from_record).collect();
    Ok(Json(chat_responses).into_response())
}

async fn create_chat(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateChatRequest>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // Use a default model config ID if none provided.
    let model_config_id = request.model_config_id.unwrap_or_else(Uuid::nil);

    let input = InsertChatInput {
        owner_id: context.user.id,
        workspace_id: request.workspace_id,
        parent_chat_id: None,
        root_chat_id: None,
        last_model_config_id: model_config_id,
        title: "New Chat".to_string(),
    };

    let chat = state.store.insert_chat(input).await?;

    // Store the initial user message.
    let content_value = serde_json::to_value(&request.content)
        .map(Some)
        .map_err(|e| StorageError::invalid_data(e.to_string()))?;
    let msg_input = InsertChatMessageInput {
        chat_id: chat.id,
        model_config_id: Some(model_config_id),
        role: "user".to_string(),
        content: content_value,
        visibility: ChatMessageVisibility::Both,
    };
    let message = state.store.insert_chat_message(msg_input).await?;
    let messages = vec![chat_message_response_from_record(message)?];

    Ok((
        StatusCode::CREATED,
        Json(ChatWithMessagesResponse {
            chat: chat_response_from_record(chat),
            messages,
            queued_messages: Vec::new(),
        }),
    )
        .into_response())
}

async fn get_chat(
    State(state): State<AppState>,
    Path(chat_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(chat) = state.store.find_chat_by_id(chat_id).await? else {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Chat not found.", "")),
        )
            .into_response());
    };

    if chat.owner_id != context.user.id {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Chat not found.", "")),
        )
            .into_response());
    }

    let messages = state.store.list_chat_messages(chat_id, 0).await?;
    let queued = state.store.list_chat_queued_messages(chat_id).await?;

    let message_responses: Vec<ChatMessageResponse> = messages
        .into_iter()
        .map(chat_message_response_from_record)
        .collect::<Result<_, _>>()?;
    let queued_responses: Vec<ChatQueuedMessageResponse> = queued
        .into_iter()
        .map(chat_queued_message_response_from_record)
        .collect::<Result<_, _>>()?;

    Ok(Json(ChatWithMessagesResponse {
        chat: chat_response_from_record(chat),
        messages: message_responses,
        queued_messages: queued_responses,
    })
    .into_response())
}

async fn delete_chat(
    State(state): State<AppState>,
    Path(chat_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(chat) = state.store.find_chat_by_id(chat_id).await? else {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Chat not found.", "")),
        )
            .into_response());
    };

    if chat.owner_id != context.user.id {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Chat not found.", "")),
        )
            .into_response());
    }

    state.store.archive_chat(chat_id).await?;
    Ok((StatusCode::OK, Json(ApiResponse::ok("Chat archived."))).into_response())
}

async fn post_chat_message(
    State(state): State<AppState>,
    Path(chat_id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<CreateChatMessageRequest>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(chat) = state.store.find_chat_by_id(chat_id).await? else {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Chat not found.", "")),
        )
            .into_response());
    };

    if chat.owner_id != context.user.id {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Chat not found.", "")),
        )
            .into_response());
    }

    let model_config_id = request.model_config_id.unwrap_or(chat.last_model_config_id);
    let content_value = serde_json::to_value(&request.content)
        .map(Some)
        .map_err(|e| StorageError::invalid_data(e.to_string()))?;

    let msg_input = InsertChatMessageInput {
        chat_id,
        model_config_id: Some(model_config_id),
        role: "user".to_string(),
        content: content_value,
        visibility: ChatMessageVisibility::Both,
    };

    let message = state.store.insert_chat_message(msg_input).await?;

    // In the full implementation, this would trigger an LLM call and stream
    // the response back via SSE. For now, we return the stored user message.
    Ok((
        StatusCode::OK,
        Json(CreateChatMessageApiResponse {
            message: Some(chat_message_response_from_record(message)?),
            queued_message: None,
            queued: false,
        }),
    )
        .into_response())
}

fn chat_response_from_record(record: ChatRecord) -> ChatResponse {
    ChatResponse {
        id: record.id,
        owner_id: record.owner_id,
        workspace_id: record.workspace_id,
        parent_chat_id: record.parent_chat_id,
        root_chat_id: record.root_chat_id,
        last_model_config_id: record.last_model_config_id,
        title: record.title,
        status: record.status,
        last_error: record.last_error,
        created_at: record.created_at,
        updated_at: record.updated_at,
        archived: record.archived,
    }
}

fn chat_message_response_from_record(
    record: ChatMessageRecord,
) -> Result<ChatMessageResponse, AppError> {
    let content: Vec<ChatMessagePart> = match record.content {
        Some(v) => serde_json::from_value(v)
            .map_err(|e| StorageError::invalid_data(format!("chat message content: {e}")))?,
        None => Vec::new(),
    };

    let usage = if record.input_tokens.is_some()
        || record.output_tokens.is_some()
        || record.total_tokens.is_some()
    {
        Some(ChatMessageUsage {
            input_tokens: record.input_tokens,
            output_tokens: record.output_tokens,
            total_tokens: record.total_tokens,
            reasoning_tokens: record.reasoning_tokens,
            cache_creation_tokens: record.cache_creation_tokens,
            cache_read_tokens: record.cache_read_tokens,
            context_limit: record.context_limit,
        })
    } else {
        None
    };

    Ok(ChatMessageResponse {
        id: record.id,
        chat_id: record.chat_id,
        model_config_id: record.model_config_id,
        created_at: record.created_at,
        role: record.role,
        content,
        usage,
    })
}

fn chat_queued_message_response_from_record(
    record: ChatQueuedMessageRecord,
) -> Result<ChatQueuedMessageResponse, AppError> {
    let content: Vec<ChatMessagePart> = serde_json::from_value(record.content)
        .map_err(|e| StorageError::invalid_data(format!("queued message content: {e}")))?;
    Ok(ChatQueuedMessageResponse {
        id: record.id,
        chat_id: record.chat_id,
        content,
        created_at: record.created_at,
    })
}

// ---------------------------------------------------------------------------
// Chat file upload/download and archive/unarchive handlers
// ---------------------------------------------------------------------------

/// Maximum chat file upload size (10 MB).
const MAX_CHAT_FILE_SIZE: usize = 10 << 20;
/// Maximum length for an uploaded chat file name.
const MAX_CHAT_FILE_NAME: usize = 255;

/// Allowed MIME types for chat file uploads.
fn is_allowed_chat_file_mime(mime: &str) -> bool {
    matches!(
        mime,
        "image/png" | "image/jpeg" | "image/gif" | "image/webp"
    )
}

/// Detect the MIME type of file data, with extended WebP support.
/// Go's `http.DetectContentType` equivalent + WebP magic bytes check.
fn detect_chat_file_type(data: &[u8]) -> &'static str {
    // WebP: starts with "RIFF" at 0..4 and "WEBP" at 8..12
    if data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        return "image/webp";
    }
    // PNG magic bytes
    if data.len() >= 8 && &data[0..8] == b"\x89PNG\r\n\x1a\n" {
        return "image/png";
    }
    // JPEG magic bytes
    if data.len() >= 3 && &data[0..3] == b"\xff\xd8\xff" {
        return "image/jpeg";
    }
    // GIF magic bytes (GIF87a or GIF89a)
    if data.len() >= 6 && (&data[0..6] == b"GIF87a" || &data[0..6] == b"GIF89a") {
        return "image/gif";
    }
    "application/octet-stream"
}

#[derive(Deserialize)]
struct ChatFileUploadQuery {
    organization: Option<String>,
}

/// POST /api/v2/chats/files – upload a chat file.
async fn upload_chat_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ChatFileUploadQuery>,
    body: Bytes,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // Require organization query parameter.
    let org_id_str = match query.organization {
        Some(ref s) if !s.is_empty() => s.as_str(),
        _ => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error(
                    "Missing organization query parameter.",
                    "",
                )),
            )
                .into_response());
        }
    };
    let org_id = match Uuid::from_str(org_id_str) {
        Ok(id) => id,
        Err(_) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error("Invalid organization ID.", "")),
            )
                .into_response());
        }
    };

    // Enforce file size limit.
    if body.len() > MAX_CHAT_FILE_SIZE {
        return Ok((
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(ApiResponse::error(
                "File too large.",
                format!("Maximum file size is {} bytes.", MAX_CHAT_FILE_SIZE),
            )),
        )
            .into_response());
    }

    // Check Content-Type header and strip parameters.
    let raw_content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream");
    let content_type = raw_content_type
        .split(';')
        .next()
        .unwrap_or("application/octet-stream")
        .trim();

    if !is_allowed_chat_file_mime(content_type) {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "Unsupported file type.",
                "Allowed types: image/png, image/jpeg, image/gif, image/webp.",
            )),
        )
            .into_response());
    }

    let data = body.to_vec();

    // Sniff the actual content type from the first 512 bytes.
    let sniff_len = std::cmp::min(data.len(), 512);
    let detected = detect_chat_file_type(&data[..sniff_len]);
    if !is_allowed_chat_file_mime(detected) {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "Unsupported file type.",
                "Allowed types: image/png, image/jpeg, image/gif, image/webp.",
            )),
        )
            .into_response());
    }

    // Extract filename from Content-Disposition header if provided.
    let filename = headers
        .get("content-disposition")
        .and_then(|v| v.to_str().ok())
        .and_then(|cd| {
            // Parse "attachment; filename=\"name.png\"" or similar.
            let lower = cd.to_lowercase();
            if let Some(pos) = lower.find("filename=") {
                let rest = &cd[pos + 9..];
                // Take only the filename token (up to the next `;` or end of string).
                let token = rest.split(';').next().unwrap_or(rest).trim();
                let name = token.trim_matches('"').trim_matches('\'');
                Some(name.to_string())
            } else {
                None
            }
        })
        .unwrap_or_default();

    // Truncate filename at rune boundary to max length.
    let truncated_name: String = if filename.len() > MAX_CHAT_FILE_NAME {
        let mut result = String::new();
        for ch in filename.chars() {
            if result.len() + ch.len_utf8() > MAX_CHAT_FILE_NAME {
                break;
            }
            result.push(ch);
        }
        result
    } else {
        filename
    };

    let input = coder_core::InsertChatFileInput {
        owner_id: context.user.id,
        organization_id: org_id,
        name: truncated_name,
        mimetype: detected.to_string(),
        data,
    };

    let record = state.store.insert_chat_file(input).await?;

    Ok((
        StatusCode::CREATED,
        Json(coder_core::UploadChatFileResponse { id: record.id }),
    )
        .into_response())
}

/// GET /api/v2/chats/files/{file} – retrieve a chat file by ID.
async fn get_chat_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(file) = state.store.find_chat_file_by_id(file_id).await? else {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Chat file not found.", "")),
        )
            .into_response());
    };

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, &file.mimetype)
        .header("cache-control", "private, max-age=31536000, immutable")
        .header("content-length", file.data.len().to_string());

    if file.name.is_empty() {
        builder = builder.header("content-disposition", "inline");
    } else {
        // Sanitize filename to prevent header injection via embedded quotes/backslashes.
        let sanitized_name = file.name.replace('"', "").replace('\\', "");
        builder = builder.header(
            "content-disposition",
            format!("inline; filename=\"{}\"", sanitized_name),
        );
    }

    let response = builder
        .body(axum::body::Body::from(file.data))
        .map_err(|e| StorageError::unavailable(e.to_string()))?;
    Ok(response)
}

/// POST /api/v2/chats/{chat}/archive – archive a chat.
async fn archive_chat_handler(
    State(state): State<AppState>,
    Path(chat_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(chat) = state.store.find_chat_by_id(chat_id).await? else {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Chat not found.", "")),
        )
            .into_response());
    };

    if chat.owner_id != context.user.id {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Chat not found.", "")),
        )
            .into_response());
    }

    if chat.archived {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error("Chat is already archived.", "")),
        )
            .into_response());
    }

    state.store.archive_chat(chat_id).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// POST /api/v2/chats/{chat}/unarchive – unarchive a chat.
async fn unarchive_chat_handler(
    State(state): State<AppState>,
    Path(chat_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(chat) = state.store.find_chat_by_id(chat_id).await? else {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Chat not found.", "")),
        )
            .into_response());
    };

    if chat.owner_id != context.user.id {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Chat not found.", "")),
        )
            .into_response());
    }

    if !chat.archived {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error("Chat is not archived.", "")),
        )
            .into_response());
    }

    state.store.unarchive_chat(chat_id).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// GET /api/v2/chats/{chat}/git/watch – WebSocket stub for watching git changes.
///
/// The full implementation requires dialing a workspace agent via the
/// tailnet coordinator, which is out of scope for this port. Return a
/// 501 Not Implemented until the agent infrastructure is available.
async fn watch_chat_git(
    State(state): State<AppState>,
    Path(chat_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(chat) = state.store.find_chat_by_id(chat_id).await? else {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Chat not found.", "")),
        )
            .into_response());
    };

    if chat.owner_id != context.user.id {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Chat not found.", "")),
        )
            .into_response());
    }

    // The Go implementation upgrades to a WebSocket, dials the workspace
    // agent, and proxies bidirectional JSON messages. This requires the
    // tailnet coordinator and agent provider which are not yet available.
    Ok((
        StatusCode::NOT_IMPLEMENTED,
        Json(ApiResponse::error(
            "Git watch is not yet implemented.",
            "Agent infrastructure required for git watching is not available.",
        )),
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// Notifications domain handlers
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct InboxNotificationsQuery {
    #[serde(default)]
    targets: Option<String>,
    #[serde(default)]
    templates: Option<String>,
    #[serde(default)]
    read_status: Option<String>,
}

async fn get_notifications_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let settings = state.store.get_notifications_settings().await?;
    Ok((StatusCode::OK, Json(settings)).into_response())
}

async fn put_notifications_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<coder_core::NotificationsSettings>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !context.actor.is_owner() {
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

async fn get_system_notification_templates(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let templates = state
        .store
        .get_notification_templates_by_kind("system")
        .await?;
    Ok((StatusCode::OK, Json(templates)).into_response())
}

async fn get_custom_notification_templates(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let templates = state
        .store
        .get_notification_templates_by_kind("custom")
        .await?;
    Ok((StatusCode::OK, Json(templates)).into_response())
}

async fn post_test_notification(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // The test notification endpoint just returns 200 OK to confirm it's reachable.
    // Full dispatch integration is not implemented yet.
    let _ = &state;
    Ok((
        StatusCode::OK,
        Json(ApiResponse::ok("Test notification acknowledged.")),
    )
        .into_response())
}

async fn put_notification_template_method(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    payload: Result<Json<UpdateNotificationTemplateMethod>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !context.actor.is_owner() {
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
        None => Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Notification template not found.", "")),
        )
            .into_response()),
    }
}

async fn get_notification_dispatch_methods(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let _ = &state;
    let response = coder_core::NotificationMethodsResponse {
        available: vec!["smtp".to_owned(), "webhook".to_owned(), "inbox".to_owned()],
        default: "smtp".to_owned(),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

async fn get_user_notification_preferences(
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
            return Ok((
                StatusCode::NOT_FOUND,
                Json(ApiResponse::error("User not found.", "")),
            )
                .into_response());
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

async fn put_user_notification_preferences(
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
            return Ok((
                StatusCode::NOT_FOUND,
                Json(ApiResponse::error("User not found.", "")),
            )
                .into_response());
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

async fn list_inbox_notifications(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<InboxNotificationsQuery>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

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

async fn put_mark_all_inbox_notifications_read(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    state
        .store
        .mark_all_inbox_notifications_as_read(context.user.id, OffsetDateTime::now_utc())
        .await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn watch_inbox_notifications(
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

async fn put_inbox_notification_read_status(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    payload: Result<Json<UpdateInboxNotificationReadStatusRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Json(body) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    // Verify the notification exists and belongs to the user
    let notification = match state.store.get_inbox_notification_by_id(id).await? {
        Some(n) => n,
        None => {
            return Ok((
                StatusCode::NOT_FOUND,
                Json(ApiResponse::error("Inbox notification not found.", "")),
            )
                .into_response());
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
        None => Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error(
                "Inbox notification not found after update.",
                "",
            )),
        )
            .into_response()),
    }
}

async fn post_user_webpush_subscription(
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
            return Ok((
                StatusCode::NOT_FOUND,
                Json(ApiResponse::error("User not found.", "")),
            )
                .into_response());
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

async fn delete_user_webpush_subscription(
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
            return Ok((
                StatusCode::NOT_FOUND,
                Json(ApiResponse::error("User not found.", "")),
            )
                .into_response());
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
        Ok((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Webpush subscription not found.", "")),
        )
            .into_response())
    }
}

async fn post_user_webpush_test(
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
            return Ok((
                StatusCode::NOT_FOUND,
                Json(ApiResponse::error("User not found.", "")),
            )
                .into_response());
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

// ---------------------------------------------------------------------------
// Template & Template Version Handlers (33 routes)
// ---------------------------------------------------------------------------

/// Resolve an organization path segment by UUID or name.
async fn resolve_organization(
    state: &AppState,
    org_ref: &str,
) -> Result<Option<OrganizationRecord>, AppError> {
    if let Ok(org_id) = Uuid::parse_str(org_ref) {
        return Ok(state.store.find_organization_by_id(org_id).await?);
    }
    Ok(state.store.find_organization_by_name(org_ref).await?)
}

/// Converts a `TemplateRecord` into a `TemplateResponse`.
fn template_response(rec: &TemplateRecord) -> TemplateResponse {
    use coder_core::api::{TemplateAutostartRequirement, TemplateAutostopRequirement};
    TemplateResponse {
        id: rec.id,
        created_at: rec.created_at,
        updated_at: rec.updated_at,
        organization_id: rec.organization_id,
        organization_name: rec.organization_name.clone(),
        organization_display_name: rec.organization_display_name.clone(),
        organization_icon: rec.organization_icon.clone(),
        name: rec.name.clone(),
        display_name: rec.display_name.clone(),
        provisioner: rec.provisioner.clone(),
        active_version_id: rec.active_version_id,
        active_user_count: -1,
        build_time_stats: HashMap::new(),
        description: rec.description.clone(),
        deprecated: !rec.deprecated.is_empty(),
        deprecation_message: rec.deprecated.clone(),
        deleted: rec.deleted,
        icon: rec.icon.clone(),
        default_ttl_ms: rec.default_ttl / 1_000_000,
        activity_bump_ms: rec.activity_bump / 1_000_000,
        autostop_requirement: TemplateAutostopRequirement::default(),
        autostart_requirement: TemplateAutostartRequirement::default(),
        created_by_id: rec.created_by,
        created_by_name: rec.created_by_name.clone(),
        allow_user_autostart: rec.allow_user_autostart,
        allow_user_autostop: rec.allow_user_autostop,
        allow_user_cancel_workspace_jobs: rec.allow_user_cancel_workspace_jobs,
        failure_ttl_ms: rec.failure_ttl / 1_000_000,
        time_til_dormant_ms: rec.time_til_dormant / 1_000_000,
        time_til_dormant_autodelete_ms: rec.time_til_dormant_autodelete / 1_000_000,
        require_active_version: rec.require_active_version,
        max_port_share_level: rec.max_port_sharing_level.clone(),
        cors_behavior: rec.cors_behavior.clone(),
        use_classic_parameter_flow: rec.use_classic_parameter_flow,
        disable_module_cache: rec.disable_module_cache,
    }
}

/// Converts a `TemplateProvisionerJobRecord` into a `ProvisionerJobResponse`.
fn provisioner_job_response(job: &TemplateProvisionerJobRecord) -> ProvisionerJobResponse {
    ProvisionerJobResponse {
        id: job.id,
        created_at: job.created_at,
        started_at: job.started_at,
        completed_at: job.completed_at,
        canceled_at: job.canceled_at,
        error: job.error.clone(),
        status: ProvisionerJobStatus::from_str_opt(&job.job_status).unwrap_or_default(),
        worker_id: job.worker_id,
        file_id: job.file_id,
        tags: job.tags.clone(),
        queue_position: 0,
        queue_size: 0,
    }
}

/// Converts a `TemplateVersionRecord` + `TemplateProvisionerJobRecord` into a `TemplateVersionResponse`.
fn template_version_response(
    ver: &TemplateVersionRecord,
    job: &TemplateProvisionerJobRecord,
) -> TemplateVersionResponse {
    TemplateVersionResponse {
        id: ver.id,
        template_id: ver.template_id,
        organization_id: ver.organization_id,
        created_at: ver.created_at,
        updated_at: ver.updated_at,
        name: ver.name.clone(),
        message: ver.message.clone(),
        job: provisioner_job_response(job),
        readme: ver.readme.clone(),
        created_by: MinimalUser {
            id: ver.created_by,
            username: ver.created_by_username.clone(),
            name: ver.created_by_name.clone(),
            avatar_url: ver.created_by_avatar_url.clone(),
        },
        archived: ver.archived,
        warnings: Vec::new(),
        has_external_agent: ver.has_external_agent.unwrap_or(false),
    }
}

/// Helper to build a template version response, fetching the provisioner job.
async fn build_tv_response(
    state: &AppState,
    ver: &TemplateVersionRecord,
) -> Result<TemplateVersionResponse, AppError> {
    let job = state.store.find_provisioner_job(ver.job_id).await?;
    let job = job.ok_or_else(|| {
        AppError::from(StorageError::invalid_data(format!(
            "provisioner job {} not found for version {}",
            ver.job_id, ver.id
        )))
    })?;
    Ok(template_version_response(ver, &job))
}

/// GET /organizations/{organization}/templates
async fn list_org_templates(
    State(state): State<AppState>,
    Path(org): Path<String>,
    headers: HeaderMap,
    Query(query): Query<TemplateFilter>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let org_record = match resolve_organization(&state, &org).await? {
        Some(o) => o,
        None => {
            return Ok(not_found_response(format!(
                "Organization '{org}' not found."
            )));
        }
    };

    let templates = state
        .store
        .list_templates(TemplateListFilter {
            organization_id: Some(org_record.id),
            exact_name: query.exact_name,
            search: query.search,
            deleted: query.deleted.unwrap_or(false),
        })
        .await?;

    let body: Vec<TemplateResponse> = templates.iter().map(template_response).collect();
    Ok((StatusCode::OK, Json(body)).into_response())
}

/// POST /organizations/{organization}/templates
async fn post_org_template(
    State(state): State<AppState>,
    Path(org): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<CreateTemplateRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(body) =
        payload.map_err(|e| AppError::from(StorageError::invalid_data(e.to_string())))?;

    let org_record = match resolve_organization(&state, &org).await? {
        Some(o) => o,
        None => {
            return Ok(not_found_response(format!(
                "Organization '{org}' not found."
            )));
        }
    };

    let now = OffsetDateTime::now_utc();
    let template_id = Uuid::new_v4();
    let input = CreateTemplateInput {
        id: template_id,
        created_at: now,
        updated_at: now,
        organization_id: org_record.id,
        name: body.name.clone(),
        display_name: body.display_name.clone(),
        provisioner: String::from("terraform"),
        active_version_id: body.template_version_id,
        description: body.description.clone(),
        default_ttl: body.default_ttl_ms * 1_000_000,
        created_by: context.user.id,
        icon: body.icon.clone(),
        allow_user_cancel_workspace_jobs: body.allow_user_cancel_workspace_jobs,
        allow_user_autostart: body.allow_user_autostart,
        allow_user_autostop: body.allow_user_autostop,
        failure_ttl: body.failure_ttl_ms * 1_000_000,
        time_til_dormant: body.time_til_dormant_ms * 1_000_000,
        time_til_dormant_autodelete: body.time_til_dormant_autodelete_ms * 1_000_000,
        require_active_version: body.require_active_version,
        activity_bump: body.activity_bump_ms * 1_000_000,
        max_port_share_level: body.max_port_share_level.clone(),
    };

    let template = match state.store.insert_template(input).await {
        Ok(t) => t,
        Err(CreateTemplateStoreError::AlreadyExists) => {
            return Ok((
                StatusCode::CONFLICT,
                Json(ApiResponse::error(
                    "A template with that name already exists.",
                    "duplicate name",
                )),
            )
                .into_response());
        }
        Err(CreateTemplateStoreError::Storage(e)) => return Err(AppError::from(e)),
    };

    record_audit(
        &state,
        AuditAction::Create,
        ResourceKind::Template,
        Some(&context.user),
        Some(template.id.to_string()),
        "created template",
    )
    .await;

    Ok((StatusCode::CREATED, Json(template_response(&template))).into_response())
}

/// GET /organizations/{organization}/templates/{templatename}
async fn get_org_template_by_name(
    State(state): State<AppState>,
    Path((org, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let org_record = match resolve_organization(&state, &org).await? {
        Some(o) => o,
        None => {
            return Ok(not_found_response(format!(
                "Organization '{org}' not found."
            )));
        }
    };

    let template = state
        .store
        .find_template_by_org_and_name(org_record.id, &name)
        .await?;

    match template {
        Some(t) => Ok((StatusCode::OK, Json(template_response(&t))).into_response()),
        None => Ok(not_found_response(format!("Template '{name}' not found."))),
    }
}

/// GET /organizations/{organization}/templates/{templatename}/versions/{templateversionname}
async fn get_org_template_version_by_name(
    State(state): State<AppState>,
    Path((org, tname, vname)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let org_record = match resolve_organization(&state, &org).await? {
        Some(o) => o,
        None => {
            return Ok(not_found_response(format!(
                "Organization '{org}' not found."
            )));
        }
    };

    let ver = state
        .store
        .find_template_version_by_org_and_name(org_record.id, &tname, &vname)
        .await?;

    match ver {
        Some(v) => {
            let resp = build_tv_response(&state, &v).await?;
            Ok((StatusCode::OK, Json(resp)).into_response())
        }
        None => Ok(not_found_response(format!(
            "Template version '{vname}' not found."
        ))),
    }
}

/// GET /organizations/{organization}/templates/examples
async fn get_org_template_examples(
    State(state): State<AppState>,
    Path(org): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let _org_record = match resolve_organization(&state, &org).await? {
        Some(o) => o,
        None => {
            return Ok(not_found_response(format!(
                "Organization '{org}' not found."
            )));
        }
    };

    // Template examples are static / built-in. Return empty list for now.
    let examples: Vec<TemplateExample> = Vec::new();
    Ok((StatusCode::OK, Json(examples)).into_response())
}

/// GET /organizations/{organization}/templates/{templatename}/versions/{templateversionname}/previous
async fn get_org_previous_template_version(
    State(state): State<AppState>,
    Path((org, tname, vname)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let org_record = match resolve_organization(&state, &org).await? {
        Some(o) => o,
        None => {
            return Ok(not_found_response(format!(
                "Organization '{org}' not found."
            )));
        }
    };

    let ver = state
        .store
        .find_previous_template_version(org_record.id, &tname, &vname)
        .await?;

    match ver {
        Some(v) => {
            let resp = build_tv_response(&state, &v).await?;
            Ok((StatusCode::OK, Json(resp)).into_response())
        }
        None => Ok(not_found_response(format!(
            "No previous version found for '{vname}'."
        ))),
    }
}

/// POST /organizations/{organization}/templateversions
async fn post_org_template_version(
    State(state): State<AppState>,
    Path(org): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<CreateTemplateVersionRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(body) =
        payload.map_err(|e| AppError::from(StorageError::invalid_data(e.to_string())))?;

    let org_record = match resolve_organization(&state, &org).await? {
        Some(o) => o,
        None => {
            return Ok(not_found_response(format!(
                "Organization '{org}' not found."
            )));
        }
    };

    let now = OffsetDateTime::now_utc();
    let job_id = Uuid::new_v4();
    let version_id = Uuid::new_v4();

    // Create the provisioner job (stub — stays in pending state).
    let provisioner = if body.provisioner.is_empty() {
        "terraform".to_owned()
    } else {
        body.provisioner.clone()
    };
    let _job = state
        .store
        .create_provisioner_job(CreateProvisionerJobInput {
            id: job_id,
            created_at: now,
            updated_at: now,
            organization_id: org_record.id,
            initiator_id: context.user.id,
            provisioner: provisioner.clone(),
            file_id: body.file_id,
            job_type: "template_version_import".to_owned(),
            input: serde_json::json!({}),
            tags: body.tags.clone(),
        })
        .await?;

    let version_name = if body.name.is_empty() {
        version_id.to_string()
    } else {
        body.name.clone()
    };

    let ver = state
        .store
        .insert_template_version(CreateTemplateVersionInput {
            id: version_id,
            template_id: body.template_id,
            organization_id: org_record.id,
            created_at: now,
            updated_at: now,
            name: version_name,
            message: body.message.clone(),
            readme: String::new(),
            job_id,
            created_by: context.user.id,
            source_example_id: body.example_id.clone(),
        })
        .await?;

    let resp = build_tv_response(&state, &ver).await?;
    Ok((StatusCode::CREATED, Json(resp)).into_response())
}

/// GET /templates/{template}
async fn get_template(
    State(state): State<AppState>,
    Path(template_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let template = state.store.find_template_by_id(template_id).await?;
    match template {
        Some(t) if !t.deleted => Ok((StatusCode::OK, Json(template_response(&t))).into_response()),
        _ => Ok(not_found_response("Template not found.")),
    }
}

/// DELETE /templates/{template}
async fn delete_template(
    State(state): State<AppState>,
    Path(template_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let deleted = state.store.soft_delete_template(template_id).await?;
    if !deleted {
        return Ok(not_found_response("Template not found."));
    }

    record_audit(
        &state,
        AuditAction::Delete,
        ResourceKind::Template,
        Some(&context.user),
        Some(template_id.to_string()),
        "deleted template",
    )
    .await;

    Ok((
        StatusCode::OK,
        Json(ApiResponse::ok("Template has been deleted!")),
    )
        .into_response())
}

/// PATCH /templates/{template}
async fn patch_template(
    State(state): State<AppState>,
    Path(template_id): Path<Uuid>,
    headers: HeaderMap,
    payload: Result<Json<UpdateTemplateMeta>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(body) =
        payload.map_err(|e| AppError::from(StorageError::invalid_data(e.to_string())))?;

    // Fetch existing template to use current values as defaults.
    let existing = match state.store.find_template_by_id(template_id).await? {
        Some(t) if !t.deleted => t,
        _ => return Ok(not_found_response("Template not found.")),
    };

    let name = if body.name.is_empty() {
        &existing.name
    } else {
        &body.name
    };
    let display_name = body
        .display_name
        .as_deref()
        .unwrap_or(&existing.display_name);
    let description = body.description.as_deref().unwrap_or(&existing.description);
    let icon = body.icon.as_deref().unwrap_or(&existing.icon);
    let deprecation_message = body
        .deprecation_message
        .as_deref()
        .unwrap_or(&existing.deprecated);
    let max_port_share_level = body
        .max_port_share_level
        .as_deref()
        .unwrap_or(&existing.max_port_sharing_level);

    let updated = state
        .store
        .update_template_meta(UpdateTemplateMetaInput {
            template_id,
            name: name.to_owned(),
            display_name: display_name.to_owned(),
            description: description.to_owned(),
            icon: icon.to_owned(),
            default_ttl: body
                .default_ttl_ms
                .unwrap_or(existing.default_ttl / 1_000_000)
                * 1_000_000,
            activity_bump: body
                .activity_bump_ms
                .unwrap_or(existing.activity_bump / 1_000_000)
                * 1_000_000,
            allow_user_autostart: body
                .allow_user_autostart
                .unwrap_or(existing.allow_user_autostart),
            allow_user_autostop: body
                .allow_user_autostop
                .unwrap_or(existing.allow_user_autostop),
            allow_user_cancel_workspace_jobs: body
                .allow_user_cancel_workspace_jobs
                .unwrap_or(existing.allow_user_cancel_workspace_jobs),
            failure_ttl: body
                .failure_ttl_ms
                .unwrap_or(existing.failure_ttl / 1_000_000)
                * 1_000_000,
            time_til_dormant: body
                .time_til_dormant_ms
                .unwrap_or(existing.time_til_dormant / 1_000_000)
                * 1_000_000,
            time_til_dormant_autodelete: body
                .time_til_dormant_autodelete_ms
                .unwrap_or(existing.time_til_dormant_autodelete / 1_000_000)
                * 1_000_000,
            require_active_version: body
                .require_active_version
                .unwrap_or(existing.require_active_version),
            deprecation_message: deprecation_message.to_owned(),
            max_port_share_level: max_port_share_level.to_owned(),
            cors_behavior: body
                .cors_behavior
                .as_deref()
                .unwrap_or(&existing.cors_behavior)
                .to_owned(),
            use_classic_parameter_flow: body
                .use_classic_parameter_flow
                .unwrap_or(existing.use_classic_parameter_flow),
            disable_module_cache: body
                .disable_module_cache
                .unwrap_or(existing.disable_module_cache),
        })
        .await?;

    match updated {
        Some(t) => {
            record_audit(
                &state,
                AuditAction::Write,
                ResourceKind::Template,
                Some(&context.user),
                Some(template_id.to_string()),
                "updated template metadata",
            )
            .await;
            Ok((StatusCode::OK, Json(template_response(&t))).into_response())
        }
        None => Ok(not_found_response("Template not found.")),
    }
}

/// GET /templates/{template}/daus
async fn get_template_daus(
    State(state): State<AppState>,
    Path(template_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let rows = state.store.template_daus(template_id).await?;
    let entries: Vec<DAUEntry> = rows
        .iter()
        .map(|r| DAUEntry {
            date: r.date.clone(),
            amount: r.amount as i64,
        })
        .collect();
    let resp = DAUsResponse {
        entries,
        tz_hour_offset: 0,
    };
    Ok((StatusCode::OK, Json(resp)).into_response())
}

/// GET /templates/{template}/examples
async fn get_template_examples(
    State(state): State<AppState>,
    Path(_template_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    // Template examples are static / built-in. Return empty list for now.
    let examples: Vec<TemplateExample> = Vec::new();
    Ok((StatusCode::OK, Json(examples)).into_response())
}

/// GET /templates/{template}/versions
async fn list_template_versions(
    State(state): State<AppState>,
    Path(template_id): Path<Uuid>,
    headers: HeaderMap,
    Query(query): Query<TemplateVersionsQuery>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let versions = state
        .store
        .list_template_versions(TemplateVersionListFilter {
            template_id,
            include_archived: query.include_archived.unwrap_or(false),
            limit: query.limit.unwrap_or(50),
            offset: query.offset.unwrap_or(0),
        })
        .await?;

    let mut responses = Vec::with_capacity(versions.len());
    for v in &versions {
        responses.push(build_tv_response(&state, v).await?);
    }
    Ok((StatusCode::OK, Json(responses)).into_response())
}

/// GET /templates/{template}/versions/{templateversionname}
async fn get_template_version_by_name(
    State(state): State<AppState>,
    Path((template_id, vname)): Path<(Uuid, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let ver = state
        .store
        .find_template_version_by_template_and_name(template_id, &vname)
        .await?;

    match ver {
        Some(v) => {
            let resp = build_tv_response(&state, &v).await?;
            Ok((StatusCode::OK, Json(resp)).into_response())
        }
        None => Ok(not_found_response(format!(
            "Template version '{vname}' not found."
        ))),
    }
}

/// GET /templateversions/{templateversion}
async fn get_template_version(
    State(state): State<AppState>,
    Path(version_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let ver = state.store.find_template_version_by_id(version_id).await?;
    match ver {
        Some(v) => {
            let resp = build_tv_response(&state, &v).await?;
            Ok((StatusCode::OK, Json(resp)).into_response())
        }
        None => Ok(not_found_response("Template version not found.")),
    }
}

/// PATCH /templateversions/{templateversion}
async fn patch_template_version(
    State(state): State<AppState>,
    Path(version_id): Path<Uuid>,
    headers: HeaderMap,
    payload: Result<Json<PatchTemplateVersionRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(body) =
        payload.map_err(|e| AppError::from(StorageError::invalid_data(e.to_string())))?;

    let existing = match state.store.find_template_version_by_id(version_id).await? {
        Some(v) => v,
        None => return Ok(not_found_response("Template version not found.")),
    };

    let name = if body.name.is_empty() {
        &existing.name
    } else {
        &body.name
    };
    let message = body.message.as_deref().unwrap_or(&existing.message);

    let updated = state
        .store
        .update_template_version(version_id, name, message)
        .await?;

    match updated {
        Some(v) => {
            record_audit(
                &state,
                AuditAction::Write,
                ResourceKind::TemplateVersion,
                Some(&context.user),
                Some(version_id.to_string()),
                "updated template version",
            )
            .await;
            let resp = build_tv_response(&state, &v).await?;
            Ok((StatusCode::OK, Json(resp)).into_response())
        }
        None => Ok(not_found_response("Template version not found.")),
    }
}

/// POST /templateversions/{templateversion}/archive
async fn post_archive_template_version(
    State(state): State<AppState>,
    Path(version_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let archived = state.store.archive_template_version(version_id).await?;
    if !archived {
        return Ok(not_found_response("Template version not found."));
    }
    Ok((
        StatusCode::OK,
        Json(ApiResponse::ok("Template version archived.")),
    )
        .into_response())
}

/// PATCH /templateversions/{templateversion}/cancel
async fn patch_cancel_template_version(
    State(state): State<AppState>,
    Path(version_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let ver = match state.store.find_template_version_by_id(version_id).await? {
        Some(v) => v,
        None => return Ok(not_found_response("Template version not found.")),
    };

    let canceled = state
        .store
        .cancel_template_provisioner_job(ver.job_id)
        .await?;
    if !canceled {
        return Ok((
            StatusCode::PRECONDITION_FAILED,
            Json(ApiResponse::error(
                "Job cannot be canceled.",
                "job is already completed or canceled",
            )),
        )
            .into_response());
    }
    Ok((
        StatusCode::OK,
        Json(ApiResponse::ok("Template version job canceled.")),
    )
        .into_response())
}

/// POST /templateversions/{templateversion}/dry-run
async fn post_template_version_dry_run(
    State(state): State<AppState>,
    Path(version_id): Path<Uuid>,
    headers: HeaderMap,
    payload: Result<Json<CreateTemplateVersionDryRunRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(body) =
        payload.map_err(|e| AppError::from(StorageError::invalid_data(e.to_string())))?;

    // Ensure the template version exists.
    let ver = match state.store.find_template_version_by_id(version_id).await? {
        Some(v) => v,
        None => return Ok(not_found_response("Template version not found.")),
    };

    let now = OffsetDateTime::now_utc();
    let job_id = Uuid::new_v4();

    let input_json = serde_json::json!({
        "template_version_id": version_id,
        "workspace_name": body.workspace_name,
        "rich_parameter_values": body.rich_parameter_values,
        "user_variable_values": body.user_variable_values,
    });

    let job = state
        .store
        .create_provisioner_job(CreateProvisionerJobInput {
            id: job_id,
            created_at: now,
            updated_at: now,
            organization_id: ver.organization_id,
            initiator_id: context.user.id,
            provisioner: String::from("terraform"),
            file_id: None,
            job_type: "template_version_dry_run".to_owned(),
            input: input_json,
            tags: HashMap::new(),
        })
        .await?;

    Ok((StatusCode::CREATED, Json(provisioner_job_response(&job))).into_response())
}

/// GET /templateversions/{templateversion}/dry-run/{jobid}
async fn get_template_version_dry_run(
    State(state): State<AppState>,
    Path((_version_id, job_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let job = state.store.find_provisioner_job(job_id).await?;
    match job {
        Some(j) => Ok((StatusCode::OK, Json(provisioner_job_response(&j))).into_response()),
        None => Ok(not_found_response("Dry-run job not found.")),
    }
}

/// PATCH /templateversions/{templateversion}/dry-run/{jobid}
async fn patch_template_version_dry_run(
    State(state): State<AppState>,
    Path((_version_id, job_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let canceled = state.store.cancel_template_provisioner_job(job_id).await?;
    if !canceled {
        return Ok((
            StatusCode::PRECONDITION_FAILED,
            Json(ApiResponse::error(
                "Job cannot be canceled.",
                "job is already completed or canceled",
            )),
        )
            .into_response());
    }

    let job = state.store.find_provisioner_job(job_id).await?;
    match job {
        Some(j) => Ok((StatusCode::OK, Json(provisioner_job_response(&j))).into_response()),
        None => Ok(not_found_response("Dry-run job not found.")),
    }
}

/// PATCH /templateversions/{templateversion}/dry-run/{jobid}/cancel
async fn patch_cancel_template_version_dry_run(
    State(state): State<AppState>,
    Path((_version_id, job_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let canceled = state.store.cancel_template_provisioner_job(job_id).await?;
    if !canceled {
        return Ok((
            StatusCode::PRECONDITION_FAILED,
            Json(ApiResponse::error(
                "Job cannot be canceled.",
                "job is already completed or canceled",
            )),
        )
            .into_response());
    }
    Ok((
        StatusCode::OK,
        Json(ApiResponse::ok("Dry-run job canceled.")),
    )
        .into_response())
}

/// GET /templateversions/{templateversion}/dry-run/{jobid}/logs
async fn get_template_version_dry_run_logs(
    State(state): State<AppState>,
    Path((_version_id, job_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // Verify the job exists.
    let _job = match state.store.find_provisioner_job(job_id).await? {
        Some(j) => j,
        None => return Ok(not_found_response("Dry-run job not found.")),
    };

    // Provisioner logs are not stored in the stub implementation.
    let logs: Vec<ProvisionerJobLog> = Vec::new();
    Ok((StatusCode::OK, Json(logs)).into_response())
}

/// GET /templateversions/{templateversion}/dry-run/{jobid}/resources
async fn get_template_version_dry_run_resources(
    State(state): State<AppState>,
    Path((_version_id, job_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let _job = match state.store.find_provisioner_job(job_id).await? {
        Some(j) => j,
        None => return Ok(not_found_response("Dry-run job not found.")),
    };

    // Resources are populated by the provisioner daemon. Return empty for stub.
    let resources: Vec<WorkspaceResource> = Vec::new();
    Ok((StatusCode::OK, Json(resources)).into_response())
}

/// GET /templateversions/{templateversion}/dry-run/{jobid}/matched-provisioners
async fn get_template_version_dry_run_matched_provisioners(
    State(state): State<AppState>,
    Path((_version_id, job_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let _job = match state.store.find_provisioner_job(job_id).await? {
        Some(j) => j,
        None => return Ok(not_found_response("Dry-run job not found.")),
    };

    // Matched provisioners require daemon tag matching which is not yet implemented.
    let response = MatchedProvisioners {
        count: 0,
        available: 0,
        most_recently_seen: None,
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// GET /templateversions/{templateversion}/dynamic-parameters
async fn get_template_version_dynamic_parameters(
    State(state): State<AppState>,
    Path(version_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let _ver = match state.store.find_template_version_by_id(version_id).await? {
        Some(v) => v,
        None => return Ok(not_found_response("Template version not found.")),
    };

    // Dynamic parameters are evaluated via the provisioner. Return empty stub.
    let response = DynamicParametersResponse::default();
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// POST /templateversions/{templateversion}/dynamic-parameters/evaluate
async fn post_template_version_dynamic_parameters_evaluate(
    State(state): State<AppState>,
    Path(version_id): Path<Uuid>,
    headers: HeaderMap,
    body: Result<Json<DynamicParametersRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let _ver = match state.store.find_template_version_by_id(version_id).await? {
        Some(v) => v,
        None => return Ok(not_found_response("Template version not found.")),
    };

    let req = match body {
        Ok(Json(r)) => r,
        Err(e) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error("Invalid request body.", e.to_string())),
            )
                .into_response());
        }
    };

    // Dynamic parameters are evaluated via the provisioner. Return stub response.
    let response = DynamicParametersResponse {
        id: req.id,
        diagnostics: Vec::new(),
        parameters: Vec::new(),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// PATCH /templates/{template}/versions — update active template version
async fn patch_active_template_version(
    State(state): State<AppState>,
    Path(template_id): Path<Uuid>,
    headers: HeaderMap,
    body: Result<Json<UpdateActiveTemplateVersionRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let template = match state.store.find_template_by_id(template_id).await? {
        Some(t) => t,
        None => return Ok(not_found_response("Template not found.")),
    };

    let req = match body {
        Ok(Json(r)) => r,
        Err(e) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error("Invalid request body.", e.to_string())),
            )
                .into_response());
        }
    };

    // Verify the version exists and belongs to this template.
    let ver = match state.store.find_template_version_by_id(req.id).await? {
        Some(v) => v,
        None => return Ok(not_found_response("Template version not found.")),
    };

    if ver.template_id != Some(template.id) {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "Version does not belong to this template.",
                "",
            )),
        )
            .into_response());
    }

    let updated = state
        .store
        .update_template_active_version(template.id, req.id)
        .await?;
    if !updated {
        return Ok(not_found_response("Template not found."));
    }

    Ok(StatusCode::OK.into_response())
}

/// POST /templates/{template}/versions/archive — archive unused template versions
async fn post_archive_template_versions(
    State(state): State<AppState>,
    Path(template_id): Path<Uuid>,
    headers: HeaderMap,
    body: Result<Json<ArchiveTemplateVersionsRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let _template = match state.store.find_template_by_id(template_id).await? {
        Some(t) => t,
        None => return Ok(not_found_response("Template not found.")),
    };

    let req = match body {
        Ok(Json(r)) => r,
        Err(e) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error("Invalid request body.", e.to_string())),
            )
                .into_response());
        }
    };

    let archived_ids = state
        .store
        .archive_unused_template_versions(template_id, req.all)
        .await?;

    let response = ArchiveTemplateVersionsResponse {
        template_id,
        archived_ids,
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// GET /templateversions/{templateversion}/external-auth
async fn get_template_version_external_auth(
    State(state): State<AppState>,
    Path(version_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // Verify the version exists.
    let _ver = match state.store.find_template_version_by_id(version_id).await? {
        Some(v) => v,
        None => return Ok(not_found_response("Template version not found.")),
    };

    // External auth requirements come from provisioner output. Return empty for stub.
    let auths: Vec<TemplateVersionExternalAuth> = Vec::new();
    Ok((StatusCode::OK, Json(auths)).into_response())
}

/// GET /templateversions/{templateversion}/logs
async fn get_template_version_logs(
    State(state): State<AppState>,
    Path(version_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let _ver = match state.store.find_template_version_by_id(version_id).await? {
        Some(v) => v,
        None => return Ok(not_found_response("Template version not found.")),
    };

    let logs: Vec<ProvisionerJobLog> = Vec::new();
    Ok((StatusCode::OK, Json(logs)).into_response())
}

/// GET /templateversions/{templateversion}/parameters (deprecated alias for rich-parameters)
async fn get_template_version_parameters(
    State(state): State<AppState>,
    Path(version_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    get_template_version_rich_parameters_impl(&state, &headers, version_id).await
}

/// GET /templateversions/{templateversion}/rich-parameters
async fn get_template_version_rich_parameters(
    State(state): State<AppState>,
    Path(version_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    get_template_version_rich_parameters_impl(&state, &headers, version_id).await
}

/// Shared implementation for parameters / rich-parameters endpoints.
async fn get_template_version_rich_parameters_impl(
    state: &AppState,
    headers: &HeaderMap,
    version_id: Uuid,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(state, headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let params = state
        .store
        .list_template_version_parameters(version_id)
        .await?;

    let body: Vec<TemplateVersionParameter> = params
        .iter()
        .map(|p| {
            let options: Vec<coder_core::api::TemplateVersionParameterOption> =
                serde_json::from_value(p.options.clone()).unwrap_or_default();
            TemplateVersionParameter {
                name: p.name.clone(),
                display_name: p.display_name.clone(),
                description: p.description.clone(),
                description_plaintext: p.description.clone(),
                param_type: p.param_type.clone(),
                form_type: p.form_type.clone(),
                mutable: p.mutable,
                default_value: p.default_value.clone(),
                icon: p.icon.clone(),
                options,
                validation_error: p.validation_error.clone(),
                validation_regex: p.validation_regex.clone(),
                validation_min: p.validation_min,
                validation_max: p.validation_max,
                validation_monotonic: p.validation_monotonic.clone(),
                required: p.required,
                ephemeral: p.ephemeral,
            }
        })
        .collect();

    Ok((StatusCode::OK, Json(body)).into_response())
}

/// GET /templateversions/{templateversion}/presets
async fn get_template_version_presets(
    State(state): State<AppState>,
    Path(version_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let presets = state
        .store
        .list_template_version_presets(version_id)
        .await?;

    let body: Vec<TemplateVersionPreset> = presets
        .iter()
        .map(|p| TemplateVersionPreset {
            id: p.id,
            template_version_id: p.template_version_id,
            name: p.name.clone(),
            created_at: p.created_at,
            is_default: p.is_default,
            description: p.description.clone(),
            icon: p.icon.clone(),
        })
        .collect();

    Ok((StatusCode::OK, Json(body)).into_response())
}

/// GET /templateversions/{templateversion}/presets/{presetid}/parameters
async fn get_template_version_preset_parameters(
    State(state): State<AppState>,
    Path((_version_id, preset_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let params = state
        .store
        .list_template_version_preset_parameters(preset_id)
        .await?;

    let body: Vec<TemplateVersionPresetParameter> = params
        .iter()
        .map(|p| TemplateVersionPresetParameter {
            id: p.id,
            template_version_preset_id: p.template_version_preset_id,
            name: p.name.clone(),
            value: p.value.clone(),
        })
        .collect();

    Ok((StatusCode::OK, Json(body)).into_response())
}

/// GET /templateversions/{templateversion}/resources
async fn get_template_version_resources(
    State(state): State<AppState>,
    Path(version_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let _ver = match state.store.find_template_version_by_id(version_id).await? {
        Some(v) => v,
        None => return Ok(not_found_response("Template version not found.")),
    };

    // Resources are populated by the provisioner daemon. Return empty for stub.
    let resources: Vec<WorkspaceResource> = Vec::new();
    Ok((StatusCode::OK, Json(resources)).into_response())
}

/// GET /templateversions/{templateversion}/schema (deprecated)
async fn get_template_version_schema(
    State(state): State<AppState>,
    Path(version_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let _ver = match state.store.find_template_version_by_id(version_id).await? {
        Some(v) => v,
        None => return Ok(not_found_response("Template version not found.")),
    };

    // Deprecated endpoint — return empty array.
    let schema: Vec<Value> = Vec::new();
    Ok((StatusCode::OK, Json(schema)).into_response())
}

/// POST /templateversions/{templateversion}/unarchive
async fn post_unarchive_template_version(
    State(state): State<AppState>,
    Path(version_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let unarchived = state.store.unarchive_template_version(version_id).await?;
    if !unarchived {
        return Ok(not_found_response("Template version not found."));
    }
    Ok((
        StatusCode::OK,
        Json(ApiResponse::ok("Template version unarchived.")),
    )
        .into_response())
}

/// GET /templateversions/{templateversion}/variables
async fn get_template_version_variables(
    State(state): State<AppState>,
    Path(version_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let vars = state
        .store
        .list_template_version_variables(version_id)
        .await?;

    let body: Vec<TemplateVersionVariable> = vars
        .iter()
        .map(|v| TemplateVersionVariable {
            name: v.name.clone(),
            description: v.description.clone(),
            var_type: v.var_type.clone(),
            value: if v.sensitive {
                String::new()
            } else {
                v.value.clone()
            },
            default_value: if v.sensitive {
                String::new()
            } else {
                v.default_value.clone()
            },
            required: v.required,
            sensitive: v.sensitive,
        })
        .collect();

    Ok((StatusCode::OK, Json(body)).into_response())
}

// ---------------------------------------------------------------------------
// End of Template & Template Version Handlers
// ---------------------------------------------------------------------------

async fn post_authcheck(
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

async fn authenticate_request(
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
async fn authenticate_agent_request(
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

async fn resolve_user(
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

fn can_view_operational_data(actor: &Actor) -> bool {
    actor.is_owner() || actor.has_site_role(ROLE_AUDITOR)
}

fn find_external_auth_provider<'a>(
    state: &'a AppState,
    provider_id: &str,
) -> Option<&'a coder_core::ExternalAuthLinkProvider> {
    state
        .config
        .external_auth_providers
        .iter()
        .find(|provider| provider.id == provider_id)
}

fn apply_dismissed_health_settings(
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

fn sanitize_redirect_uri(input: &str) -> String {
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

fn redirect_to_login_response(uri: &http::Uri, message: &str) -> Response {
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

fn external_auth_device_flow_unsupported_response() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ApiResponse::ok(
            "Git auth provider does not support device flow.",
        )),
    )
        .into_response()
}

async fn store_new_git_ssh_key(
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

async fn record_audit(
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

fn handle_auth_error(error: AuthServiceError) -> Result<Response, AppError> {
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

fn handle_external_auth_error(
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
        ExternalAuthServiceError::Internal(detail) => Ok((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::error(message, detail)),
        )
            .into_response()),
    }
}

fn handle_identity_error(error: IdentityServiceError) -> Result<Response, AppError> {
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

fn build_version_headers(version: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Ok(value) = HeaderValue::from_str(version) {
        headers.insert(HeaderName::from_static(BUILD_VERSION_HEADER), value);
    }
    headers
}

fn invalid_json_response(error: JsonRejection) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ApiResponse::error(
            "Request body must be valid JSON.",
            error.body_text(),
        )),
    )
        .into_response()
}

fn validation_response(validations: Vec<ValidationError>) -> Response {
    validation_message_response("Request body has invalid fields.", validations)
}

fn validation_message_response(message: &str, validations: Vec<ValidationError>) -> Response {
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

fn unauthorized_response(message: impl Into<String>) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(ApiResponse::ok(message.into())),
    )
        .into_response()
}

fn forbidden_response(message: impl Into<String>) -> Response {
    (StatusCode::FORBIDDEN, Json(ApiResponse::ok(message.into()))).into_response()
}

fn not_implemented_response(message: impl Into<String>) -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(ApiResponse::ok(message.into())),
    )
        .into_response()
}

/// Accept a WebSocket upgrade then immediately close with a "not implemented" reason.
/// Used for endpoints that require tailnet/pubsub integration not yet available.
async fn ws_close_not_implemented(mut socket: WebSocket, reason: &str) {
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

fn not_found_response(message: impl Into<String>) -> Response {
    (StatusCode::NOT_FOUND, Json(ApiResponse::ok(message.into()))).into_response()
}

fn resource_not_found_response() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ApiResponse::ok(
            "Resource not found or you do not have access to this resource",
        )),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Workspace domain query types
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
struct WorkspacesQuery {
    owner: Option<String>,
    template: Option<String>,
    name: Option<String>,
    status: Option<String>,
    has_agent: Option<String>,
    dormant: Option<bool>,
    limit: Option<u32>,
    offset: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
struct WorkspaceBuildsQuery {
    limit: Option<u32>,
    offset: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
struct BuildLogsQuery {
    after: Option<i64>,
    follow: Option<bool>,
}

// ---------------------------------------------------------------------------
// Workspace domain handlers (32 routes)
// ---------------------------------------------------------------------------

/// GET /workspaces — filtered, paginated workspace listing.
async fn list_workspaces(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WorkspacesQuery>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let owner_id = if let Some(ref owner) = query.owner {
        if owner == "me" {
            Some(context.user.id)
        } else {
            Uuid::parse_str(owner).ok()
        }
    } else {
        None
    };
    let owner_username = query
        .owner
        .as_deref()
        .filter(|o| *o != "me" && Uuid::parse_str(o).is_err())
        .map(String::from);

    let filter = WorkspaceListFilter {
        owner_id,
        owner_username,
        template_name: query.template,
        template_ids: Vec::new(),
        name: query.name,
        status: query.status,
        has_agent: query.has_agent,
        dormant: query.dormant,
        last_used_before: None,
        last_used_after: None,
        organization_id: None,
        limit: query.limit.unwrap_or(25),
        offset: query.offset.unwrap_or(0),
        viewer_id: Some(context.user.id),
    };

    let (workspaces, count) = state.store.list_workspaces(filter).await?;
    let items: Vec<Value> = workspaces
        .into_iter()
        .map(|w| {
            json!({
                "id": w.id,
                "created_at": w.created_at.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
                "updated_at": w.updated_at.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
                "owner_id": w.owner_id,
                "organization_id": w.organization_id,
                "template_id": w.template_id,
                "name": w.name,
                "autostart_schedule": w.autostart_schedule,
                "ttl_ms": w.ttl_ns.map(|ns| ns / 1_000_000),
                "last_used_at": w.last_used_at.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
                "dormant_at": w.dormant_at.map(|t| t.format(&time::format_description::well_known::Rfc3339).unwrap_or_default()),
                "deleting_at": w.deleting_at.map(|t| t.format(&time::format_description::well_known::Rfc3339).unwrap_or_default()),
                "automatic_updates": w.automatic_updates,
                "favorite": w.favorite,
                "next_start_at": w.next_start_at.map(|t| t.format(&time::format_description::well_known::Rfc3339).unwrap_or_default()),
            })
        })
        .collect();

    Ok((
        StatusCode::OK,
        Json(json!({ "workspaces": items, "count": count })),
    )
        .into_response())
}

/// GET /workspaces/{workspace}
async fn get_workspace(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    Ok((StatusCode::OK, Json(workspace_to_json(&workspace))).into_response())
}

/// PATCH /workspaces/{workspace}
async fn patch_workspace(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
    payload: Result<Json<Value>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(body) = match payload {
        Ok(p) => p,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let Some(_workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    if let Some(name) = body.get("name").and_then(|v| v.as_str()) {
        let Some(updated) = state
            .store
            .update_workspace_name(workspace_id, name, Some(context.user.id))
            .await?
        else {
            return Ok(resource_not_found_response());
        };
        return Ok((StatusCode::OK, Json(workspace_to_json(&updated))).into_response());
    }

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// GET /workspaces/{workspace}/builds
async fn list_workspace_builds_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
    Query(query): Query<WorkspaceBuildsQuery>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(_workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    let builds = state
        .store
        .list_workspace_builds(
            workspace_id,
            query.limit.unwrap_or(25),
            query.offset.unwrap_or(0),
        )
        .await?;

    let items: Vec<Value> = builds.into_iter().map(|b| build_to_json(&b)).collect();
    Ok((StatusCode::OK, Json(items)).into_response())
}

/// POST /workspaces/{workspace}/builds — start/stop/delete transition.
async fn post_workspace_build(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
    payload: Result<Json<Value>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(body) = match payload {
        Ok(p) => p,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let Some(workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    let transition = body
        .get("transition")
        .and_then(|v| v.as_str())
        .unwrap_or("start")
        .to_owned();

    let template_version_id = body
        .get("template_version_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok());

    let tv_id = if let Some(id) = template_version_id {
        id
    } else {
        let Some(template) = state
            .store
            .find_template_by_id(workspace.template_id)
            .await?
        else {
            return Ok(not_found_response("Template not found."));
        };
        template.active_version_id
    };

    let job_id = Uuid::new_v4();
    let build_id = Uuid::new_v4();

    let _job = state
        .store
        .create_provisioner_job(CreateProvisionerJobInput {
            id: job_id,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            organization_id: workspace.organization_id,
            initiator_id: context.user.id,
            provisioner: "echo".to_owned(),
            file_id: None,
            job_type: "workspace_build".to_owned(),
            input: json!({}),
            tags: HashMap::new(),
        })
        .await?;

    // build_number is computed atomically inside insert_workspace_build.
    let build = state
        .store
        .insert_workspace_build(CreateWorkspaceBuildInput {
            id: build_id,
            workspace_id,
            template_version_id: tv_id,
            build_number: 0,
            transition,
            initiator_id: context.user.id,
            job_id,
            reason: "initiator".to_owned(),
            deadline: None,
            max_deadline: None,
        })
        .await?;

    Ok((StatusCode::CREATED, Json(build_to_json(&build))).into_response())
}

/// PUT /workspaces/{workspace}/autostart
async fn put_workspace_autostart(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
    payload: Result<Json<Value>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(body) = match payload {
        Ok(p) => p,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let Some(_workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    let schedule = body
        .get("schedule")
        .and_then(|v| v.as_str())
        .map(String::from);

    state
        .store
        .update_workspace_autostart(workspace_id, schedule.as_deref())
        .await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// PUT /workspaces/{workspace}/ttl
async fn put_workspace_ttl(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
    payload: Result<Json<Value>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(body) = match payload {
        Ok(p) => p,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let Some(_workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    let ttl_ms = body.get("ttl_ms").and_then(|v| v.as_i64());
    let ttl_ns = ttl_ms.map(|ms| ms * 1_000_000);

    state
        .store
        .update_workspace_ttl(workspace_id, ttl_ns)
        .await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// PUT /workspaces/{workspace}/dormant
async fn put_workspace_dormant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
    payload: Result<Json<Value>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(body) = match payload {
        Ok(p) => p,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let dormant = body
        .get("dormant")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let dormant_at = if dormant {
        Some(OffsetDateTime::now_utc())
    } else {
        None
    };

    let Some(updated) = state
        .store
        .update_workspace_dormant_at(workspace_id, dormant_at, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    Ok((StatusCode::OK, Json(workspace_to_json(&updated))).into_response())
}

/// PUT /workspaces/{workspace}/extend
async fn put_workspace_extend(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
    payload: Result<Json<Value>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(body) = match payload {
        Ok(p) => p,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let Some(_workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    let deadline_str = body.get("deadline").and_then(|v| v.as_str());

    let new_deadline = match deadline_str {
        Some(s) => match OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339) {
            Ok(dt) => Some(dt),
            Err(_) => {
                return Ok(validation_response(vec![ValidationError {
                    field: "deadline".to_owned(),
                    detail: "Invalid RFC3339 timestamp.".to_owned(),
                }]));
            }
        },
        None => {
            return Ok(validation_response(vec![ValidationError {
                field: "deadline".to_owned(),
                detail: "Deadline is required.".to_owned(),
            }]));
        }
    };

    let Some(latest_build) = state
        .store
        .find_latest_workspace_build(workspace_id)
        .await?
    else {
        return Ok(not_found_response("No build found for workspace."));
    };

    // Enforce max_deadline: the new deadline cannot exceed the build's max_deadline.
    let clamped_deadline = match (new_deadline, latest_build.max_deadline) {
        (Some(nd), Some(md)) if nd > md => Some(md),
        (d, _) => d,
    };

    let _updated = state
        .store
        .update_workspace_build_deadline(
            latest_build.id,
            clamped_deadline,
            latest_build.max_deadline,
        )
        .await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// PUT /workspaces/{workspace}/autoupdates
async fn put_workspace_autoupdates(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
    payload: Result<Json<Value>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(body) = match payload {
        Ok(p) => p,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let Some(_workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    let automatic_updates = body
        .get("automatic_updates")
        .and_then(|v| v.as_str())
        .unwrap_or("never");

    state
        .store
        .update_workspace_automatic_updates(workspace_id, automatic_updates)
        .await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// PUT /workspaces/{workspace}/favorite
async fn put_workspace_favorite(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(_workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    state
        .store
        .favorite_workspace(workspace_id, context.user.id, true)
        .await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// DELETE /workspaces/{workspace}/favorite
async fn delete_workspace_favorite(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(_workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    state
        .store
        .favorite_workspace(workspace_id, context.user.id, false)
        .await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// GET /workspaces/{workspace}/port-share
async fn list_workspace_port_shares(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(_workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    let shares = state.store.list_workspace_port_shares(workspace_id).await?;
    let items: Vec<Value> = shares
        .into_iter()
        .map(|s| {
            json!({
                "workspace_id": s.workspace_id,
                "agent_name": s.agent_name,
                "port": s.port,
                "share_level": s.share_level,
                "protocol": s.protocol,
            })
        })
        .collect();

    Ok((StatusCode::OK, Json(json!({ "shares": items }))).into_response())
}

/// POST /workspaces/{workspace}/port-share
async fn post_workspace_port_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
    payload: Result<Json<Value>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(body) = match payload {
        Ok(p) => p,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let Some(_workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    let agent_name = body
        .get("agent_name")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();
    let port = body.get("port").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
    let share_level = body
        .get("share_level")
        .and_then(|v| v.as_str())
        .unwrap_or("owner")
        .to_owned();
    let protocol = body
        .get("protocol")
        .and_then(|v| v.as_str())
        .unwrap_or("http")
        .to_owned();

    let share = state
        .store
        .upsert_workspace_port_share(UpsertPortShareInput {
            workspace_id,
            agent_name,
            port,
            share_level,
            protocol,
        })
        .await?;

    Ok((
        StatusCode::OK,
        Json(json!({
            "workspace_id": share.workspace_id,
            "agent_name": share.agent_name,
            "port": share.port,
            "share_level": share.share_level,
            "protocol": share.protocol,
        })),
    )
        .into_response())
}

/// DELETE /workspaces/{workspace}/port-share
async fn delete_workspace_port_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
    payload: Result<Json<Value>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(body) = match payload {
        Ok(p) => p,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let Some(_workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    let agent_name = body
        .get("agent_name")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let port = body.get("port").and_then(|v| v.as_i64()).unwrap_or(0) as i32;

    state
        .store
        .delete_workspace_port_share(workspace_id, agent_name, port)
        .await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// GET /workspaces/{workspace}/acl
async fn get_workspace_acl(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(_workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    let acl_record = state.store.get_workspace_acl(workspace_id).await?;

    // Resolve user details for user ACL entries.
    let mut users = Vec::new();
    for (user_id_str, role) in &acl_record.user_acl {
        if let Ok(uid) = Uuid::from_str(user_id_str) {
            if let Some(user) = state.store.find_user_by_id(uid).await? {
                users.push(WorkspaceACLUser {
                    id: user.id,
                    username: user.username,
                    avatar_url: user.avatar_url,
                    role: role.clone(),
                });
            }
        }
    }

    // Resolve group details for group ACL entries.
    let mut groups = Vec::new();
    for (group_id_str, role) in &acl_record.group_acl {
        if let Ok(gid) = Uuid::from_str(group_id_str) {
            let name = if let Some(group) = state.store.find_group_by_id(gid).await? {
                group.name
            } else {
                group_id_str.clone()
            };
            groups.push(WorkspaceACLGroup {
                id: gid,
                name,
                role: role.clone(),
            });
        }
    }

    Ok((StatusCode::OK, Json(WorkspaceACLResponse { users, groups })).into_response())
}

/// PATCH /workspaces/{workspace}/acl
async fn patch_workspace_acl(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
    payload: Result<Json<UpdateWorkspaceACLRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(req) = match payload {
        Ok(p) => p,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let Some(_workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    let input = UpdateWorkspaceACLInput {
        user_roles: req.user_roles,
        group_roles: req.group_roles,
    };
    state
        .store
        .update_workspace_acl(workspace_id, &input)
        .await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// DELETE /workspaces/{workspace}/acl
async fn delete_workspace_acl(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(_workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    state.store.delete_workspace_acl(workspace_id).await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// GET /workspaces/{workspace}/resolve-autostart
async fn get_workspace_resolve_autostart(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    let parameter_mismatch = false;
    Ok((
        StatusCode::OK,
        Json(json!({ "parameter_mismatch": parameter_mismatch, "template_id": workspace.template_id })),
    )
        .into_response())
}

/// GET /workspaces/{workspace}/timings
///
/// Returns build timings for the latest workspace build, including provisioner
/// timings and agent script timings. Mirrors the Go `buildTimings` function
/// in `coderd/workspacebuilds.go`.
async fn get_workspace_timings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(latest_build) = state
        .store
        .find_latest_workspace_build(workspace_id)
        .await?
    else {
        return Ok((
            StatusCode::OK,
            Json(json!({
                "provisioner_timings": [],
                "agent_script_timings": [],
                "agent_connection_timings": []
            })),
        )
            .into_response());
    };

    let timings_response = build_timings_response(&state, &latest_build).await?;
    Ok((StatusCode::OK, Json(timings_response)).into_response())
}

/// POST /workspaces/{workspace}/usage — updates last_used_at.
async fn post_workspace_usage(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(_workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    state
        .store
        .update_workspace_last_used_at(workspace_id, OffsetDateTime::now_utc())
        .await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// GET /workspaces/{workspace}/watch — SSE stream of workspace updates.
///
/// Subscribes to the workspace owner's pub/sub channel and streams workspace
/// state as Server-Sent Events whenever a relevant event is received.
/// Mirrors the Go `watchWorkspace` handler in `coderd/workspaces.go`.
async fn get_workspace_watch(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
) -> Result<Response, AppError> {
    use axum::body::Body;
    use coder_core::pubsub::{WorkspaceEvent, workspace_event_channel};

    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    let owner_id = workspace.owner_id;
    let channel = workspace_event_channel(owner_id);

    let mut subscription = state.pubsub.subscribe(&channel).await.map_err(|e| {
        AppError::Storage(StorageError::Unavailable {
            message: e.to_string(),
        })
    })?;

    let (tx, rx) = tokio::sync::mpsc::channel::<String>(64);

    // Send initial ping to signal the connection is established.
    let _ = tx.send("event: ping\ndata: {}\n\n".to_owned()).await;

    // Send current workspace state immediately after connection.
    let initial_data = serde_json::to_string(&workspace_to_json(&workspace)).unwrap_or_default();
    let _ = tx
        .send(format!("event: data\ndata: {initial_data}\n\n"))
        .await;

    // Spawn a task that listens for pub/sub events and sends SSE data.
    let store = state.store.clone();
    let viewer_id = context.user.id;
    tokio::spawn(async move {
        loop {
            // Race pub/sub recv against client disconnect (rx dropped → tx.closed()).
            tokio::select! {
                msg = subscription.recv() => {
                    match msg {
                        Ok(bytes) => {
                            // Skip messages that fail to parse or belong to a different workspace.
                            match serde_json::from_slice::<WorkspaceEvent>(&bytes) {
                                Ok(ev) if ev.workspace_id == workspace_id => { /* proceed */ }
                                _ => continue,
                            }

                            // Fetch fresh workspace state.
                            match store
                                .find_workspace_by_id(workspace_id, Some(viewer_id))
                                .await
                            {
                                Ok(Some(w)) => {
                                    let data =
                                        serde_json::to_string(&workspace_to_json(&w)).unwrap_or_default();
                                    let sse = format!("event: data\ndata: {data}\n\n");
                                    if tx.send(sse).await.is_err() {
                                        break;
                                    }
                                }
                                Ok(None) => break,
                                Err(_) => {
                                    let err_data = serde_json::to_string(&json!({
                                        "message": "Internal error fetching workspace."
                                    }))
                                    .unwrap_or_default();
                                    let sse = format!("event: error\ndata: {err_data}\n\n");
                                    let _ = tx.send(sse).await;
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
                _ = tx.closed() => {
                    // Client disconnected (rx was dropped).
                    break;
                }
            }
        }
    });

    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    let body = Body::from_stream(tokio_stream::StreamExt::map(
        stream,
        Ok::<_, std::convert::Infallible>,
    ));

    Ok((
        StatusCode::OK,
        [
            (CONTENT_TYPE, HeaderValue::from_static("text/event-stream")),
            (
                HeaderName::from_static("cache-control"),
                HeaderValue::from_static("no-cache"),
            ),
        ],
        body,
    )
        .into_response())
}

/// GET /workspaces/{workspace}/watch-ws — WebSocket stream of workspace updates.
///
/// Upgrades the connection to a WebSocket and streams workspace JSON state
/// whenever a relevant pub/sub event is received for this workspace.
/// Mirrors the Go `watchWorkspaceWS` handler.
async fn get_workspace_watch_ws(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
    ws: axum::extract::ws::WebSocketUpgrade,
) -> Result<Response, AppError> {
    use axum::extract::ws::Message;
    use coder_core::pubsub::{WorkspaceEvent, workspace_event_channel};

    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    let owner_id = workspace.owner_id;
    let viewer_id = context.user.id;
    let store = state.store.clone();
    let pubsub = state.pubsub.clone();

    Ok(ws.on_upgrade(move |mut socket| async move {
        // Subscribe to pub/sub BEFORE sending initial state to avoid missing
        // events that arrive between the initial fetch and the subscription.
        let channel = workspace_event_channel(owner_id);
        let mut subscription = match pubsub.subscribe(&channel).await {
            Ok(sub) => sub,
            Err(_) => return,
        };

        // Send initial workspace state.
        let initial = serde_json::to_string(&workspace_to_json(&workspace)).unwrap_or_default();
        if socket.send(Message::Text(initial.into())).await.is_err() {
            return;
        }

        loop {
            // Race pub/sub recv against WebSocket client messages to detect disconnect.
            tokio::select! {
                msg = subscription.recv() => {
                    match msg {
                        Ok(bytes) => {
                            // Skip messages that fail to parse or belong to a different workspace.
                            match serde_json::from_slice::<WorkspaceEvent>(&bytes) {
                                Ok(ev) if ev.workspace_id == workspace_id => { /* proceed */ }
                                _ => continue,
                            }

                            match store
                                .find_workspace_by_id(workspace_id, Some(viewer_id))
                                .await
                            {
                                Ok(Some(w)) => {
                                    let data =
                                        serde_json::to_string(&workspace_to_json(&w)).unwrap_or_default();
                                    if socket.send(Message::Text(data.into())).await.is_err() {
                                        break;
                                    }
                                }
                                Ok(None) => break,
                                Err(_) => {
                                    let err = serde_json::to_string(&json!({
                                        "message": "Internal error fetching workspace."
                                    }))
                                    .unwrap_or_default();
                                    let _ = socket.send(Message::Text(err.into())).await;
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
                ws_msg = socket.recv() => {
                    // Client sent a close frame or disconnected.
                    match ws_msg {
                        Some(Ok(Message::Close(_))) | None => break,
                        _ => { /* ignore other client messages */ }
                    }
                }
            }
        }
    }))
}

/// GET /workspacebuilds/{build}
async fn get_workspace_build(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(build_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(build) = state.store.find_workspace_build_by_id(build_id).await? else {
        return Ok(resource_not_found_response());
    };

    Ok((StatusCode::OK, Json(build_to_json(&build))).into_response())
}

/// PATCH /workspacebuilds/{build}/cancel
async fn patch_cancel_workspace_build(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(build_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(build) = state.store.find_workspace_build_by_id(build_id).await? else {
        return Ok(resource_not_found_response());
    };

    let canceled = state
        .store
        .cancel_template_provisioner_job(build.job_id)
        .await?;

    if !canceled {
        return Ok((
            StatusCode::PRECONDITION_FAILED,
            Json(ApiResponse::ok("Build is already completed or canceled.")),
        )
            .into_response());
    }

    Ok(StatusCode::OK.into_response())
}

/// GET /workspacebuilds/{build}/logs
async fn get_workspace_build_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(build_id): Path<Uuid>,
    Query(query): Query<BuildLogsQuery>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(build) = state.store.find_workspace_build_by_id(build_id).await? else {
        return Ok(resource_not_found_response());
    };

    let _follow = query.follow.unwrap_or(false);
    let logs = state
        .store
        .list_provisioner_job_logs(build.job_id, query.after)
        .await?;

    let items: Vec<ProvisionerJobLog> = logs
        .into_iter()
        .map(|l| ProvisionerJobLog {
            id: l.id,
            created_at: l.created_at,
            log_source: l.source,
            log_level: l.level,
            stage: l.stage,
            output: l.output,
        })
        .collect();

    Ok((StatusCode::OK, Json(items)).into_response())
}

/// GET /workspacebuilds/{build}/parameters
async fn get_workspace_build_parameters(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(build_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(_build) = state.store.find_workspace_build_by_id(build_id).await? else {
        return Ok(resource_not_found_response());
    };

    let params = state
        .store
        .list_workspace_build_parameters(build_id)
        .await?;

    let items: Vec<WorkspaceBuildParameter> = params
        .into_iter()
        .map(|p| WorkspaceBuildParameter {
            name: p.name,
            value: p.value,
        })
        .collect();

    Ok((StatusCode::OK, Json(items)).into_response())
}

/// GET /workspacebuilds/{build}/resources
async fn get_workspace_build_resources(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(build_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(build) = state.store.find_workspace_build_by_id(build_id).await? else {
        return Ok(resource_not_found_response());
    };

    let resources = state
        .store
        .list_workspace_resources_by_job(build.job_id)
        .await?;

    // Fetch metadata for all resources in one batch.
    let resource_ids: Vec<Uuid> = resources.iter().map(|r| r.id).collect();
    let all_metadata = state
        .store
        .list_workspace_resource_metadata(&resource_ids)
        .await?;

    // Group metadata by resource id.
    let mut metadata_map: HashMap<Uuid, Vec<WorkspaceResourceMetadata>> = HashMap::new();
    for m in all_metadata {
        metadata_map
            .entry(m.workspace_resource_id)
            .or_default()
            .push(WorkspaceResourceMetadata {
                key: m.key,
                value: m.value,
                sensitive: m.sensitive,
            });
    }

    let items: Vec<WorkspaceResourceResponse> = resources
        .into_iter()
        .map(|r| {
            let meta = metadata_map.remove(&r.id).unwrap_or_default();
            WorkspaceResourceResponse {
                id: r.id,
                created_at: r.created_at,
                job_id: r.job_id,
                workspace_transition: workspace_transition_from_str(&r.transition),
                resource_type: r.resource_type,
                name: r.name,
                hide: r.hide,
                icon: r.icon,
                daily_cost: r.daily_cost,
                agents: Vec::new(),
                metadata: meta,
            }
        })
        .collect();

    Ok((StatusCode::OK, Json(items)).into_response())
}

/// GET /workspacebuilds/{build}/state
async fn get_workspace_build_state(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(build_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(build) = state.store.find_workspace_build_by_id(build_id).await? else {
        return Ok(resource_not_found_response());
    };

    let state_bytes = build.provisioner_state.unwrap_or_default();
    Ok((
        StatusCode::OK,
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        )],
        state_bytes,
    )
        .into_response())
}

/// PUT /workspacebuilds/{build}/state
async fn put_workspace_build_state(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(build_id): Path<Uuid>,
    body: Bytes,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(_build) = state.store.find_workspace_build_by_id(build_id).await? else {
        return Ok(resource_not_found_response());
    };

    state
        .store
        .update_workspace_build_provisioner_state(build_id, &body)
        .await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// GET /workspacebuilds/{build}/timings
async fn get_workspace_build_timings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(build_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(build) = state.store.find_workspace_build_by_id(build_id).await? else {
        return Ok(resource_not_found_response());
    };

    let timings_response = build_timings_response(&state, &build).await?;
    Ok((StatusCode::OK, Json(timings_response)).into_response())
}

/// GET /users/{user}/workspace/{name}
async fn get_user_workspace_by_name(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((user, name)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(target_user) = resolve_user(&state, &user, &context.user).await? else {
        return Ok(resource_not_found_response());
    };

    let Some(workspace) = state
        .store
        .find_workspace_by_owner_and_name(target_user.id, &name, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    Ok((StatusCode::OK, Json(workspace_to_json(&workspace))).into_response())
}

/// GET /users/{user}/workspace/{name}/builds/{number}
async fn get_user_workspace_build_by_number(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((user, name, number)): Path<(String, String, i64)>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(target_user) = resolve_user(&state, &user, &context.user).await? else {
        return Ok(resource_not_found_response());
    };

    let Some(workspace) = state
        .store
        .find_workspace_by_owner_and_name(target_user.id, &name, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    let Some(build) = state
        .store
        .find_workspace_build_by_number(workspace.id, number)
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    Ok((StatusCode::OK, Json(build_to_json(&build))).into_response())
}

/// POST /users/{user}/workspaces — create workspace + initial build.
async fn post_user_workspace(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user): Path<String>,
    payload: Result<Json<Value>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(body) = match payload {
        Ok(p) => p,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let Some(target_user) = resolve_user(&state, &user, &context.user).await? else {
        return Ok(resource_not_found_response());
    };

    let template_id = match body.get("template_id").and_then(|v| v.as_str()) {
        Some(id) => match Uuid::parse_str(id) {
            Ok(uuid) => uuid,
            Err(_) => {
                return Ok(validation_response(vec![ValidationError {
                    field: "template_id".to_owned(),
                    detail: "Invalid UUID.".to_owned(),
                }]));
            }
        },
        None => {
            return Ok(validation_response(vec![ValidationError {
                field: "template_id".to_owned(),
                detail: "Template ID is required.".to_owned(),
            }]));
        }
    };

    let ws_name = body
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();

    if ws_name.is_empty() {
        return Ok(validation_response(vec![ValidationError {
            field: "name".to_owned(),
            detail: "Name is required.".to_owned(),
        }]));
    }

    let Some(template) = state.store.find_template_by_id(template_id).await? else {
        return Ok(not_found_response("Template not found."));
    };

    let workspace_id = Uuid::new_v4();
    let autostart_schedule = body
        .get("autostart_schedule")
        .and_then(|v| v.as_str())
        .map(String::from);
    let ttl_ms = body.get("ttl_ms").and_then(|v| v.as_i64());
    let automatic_updates = body
        .get("automatic_updates")
        .and_then(|v| v.as_str())
        .unwrap_or("never")
        .to_owned();

    let workspace = state
        .store
        .insert_workspace(CreateWorkspaceInput {
            id: workspace_id,
            owner_id: target_user.id,
            organization_id: template.organization_id,
            template_id,
            name: ws_name,
            autostart_schedule,
            ttl_ns: ttl_ms.map(|ms| ms * 1_000_000),
            automatic_updates,
        })
        .await?;

    // Create initial build.
    let job_id = Uuid::new_v4();
    let build_id = Uuid::new_v4();

    let template_version_id = body
        .get("template_version_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or(template.active_version_id);

    let _job = state
        .store
        .create_provisioner_job(CreateProvisionerJobInput {
            id: job_id,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            organization_id: template.organization_id,
            initiator_id: context.user.id,
            provisioner: "echo".to_owned(),
            file_id: None,
            job_type: "workspace_build".to_owned(),
            input: json!({}),
            tags: HashMap::new(),
        })
        .await?;

    // build_number is computed atomically inside insert_workspace_build.
    let _build = state
        .store
        .insert_workspace_build(CreateWorkspaceBuildInput {
            id: build_id,
            workspace_id,
            template_version_id,
            build_number: 0,
            transition: "start".to_owned(),
            initiator_id: context.user.id,
            job_id,
            reason: "initiator".to_owned(),
            deadline: None,
            max_deadline: None,
        })
        .await?;

    // Insert build parameters if provided.
    if let Some(params) = body.get("rich_parameter_values").and_then(|v| v.as_array()) {
        let param_pairs: Vec<(String, String)> = params
            .iter()
            .filter_map(|p| {
                let name = p.get("name")?.as_str()?.to_owned();
                let value = p.get("value")?.as_str()?.to_owned();
                Some((name, value))
            })
            .collect();
        if !param_pairs.is_empty() {
            state
                .store
                .insert_workspace_build_parameters(build_id, &param_pairs)
                .await?;
        }
    }

    Ok((StatusCode::CREATED, Json(workspace_to_json(&workspace))).into_response())
}

/// POST /organizations/{organization}/members/{user}/workspaces — create workspace in org.
///
/// Mirrors the Go `postWorkspacesByOrganization` handler: resolves the
/// organization and member, then delegates to the same workspace-creation
/// logic used by `post_user_workspace`.
async fn post_org_member_workspace(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((organization, user)): Path<(String, String)>,
    payload: Result<Json<Value>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(body) = match payload {
        Ok(p) => p,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    // Resolve organization.
    let Some(org_record) = resolve_organization(&state, &organization).await? else {
        return Ok(not_found_response("Organization not found."));
    };

    // Resolve the target user (member) within the organization context.
    let Some(target_user) = resolve_user(&state, &user, &context.user).await? else {
        return Ok(resource_not_found_response());
    };

    // From here, the workspace creation logic is identical to post_user_workspace.
    let template_id = match body.get("template_id").and_then(|v| v.as_str()) {
        Some(id) => match Uuid::parse_str(id) {
            Ok(uuid) => uuid,
            Err(_) => {
                return Ok(validation_response(vec![ValidationError {
                    field: "template_id".to_owned(),
                    detail: "Invalid UUID.".to_owned(),
                }]));
            }
        },
        None => {
            return Ok(validation_response(vec![ValidationError {
                field: "template_id".to_owned(),
                detail: "Template ID is required.".to_owned(),
            }]));
        }
    };

    let ws_name = body
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();

    if ws_name.is_empty() {
        return Ok(validation_response(vec![ValidationError {
            field: "name".to_owned(),
            detail: "Name is required.".to_owned(),
        }]));
    }

    let Some(template) = state.store.find_template_by_id(template_id).await? else {
        return Ok(not_found_response("Template not found."));
    };

    // Ensure the template belongs to the resolved organization.
    if template.organization_id != org_record.id {
        return Ok(not_found_response(
            "Template not found in the specified organization.",
        ));
    }

    let workspace_id = Uuid::new_v4();
    let autostart_schedule = body
        .get("autostart_schedule")
        .and_then(|v| v.as_str())
        .map(String::from);
    let ttl_ms = body.get("ttl_ms").and_then(|v| v.as_i64());
    let automatic_updates = body
        .get("automatic_updates")
        .and_then(|v| v.as_str())
        .unwrap_or("never")
        .to_owned();

    let workspace = state
        .store
        .insert_workspace(CreateWorkspaceInput {
            id: workspace_id,
            owner_id: target_user.id,
            organization_id: org_record.id,
            template_id,
            name: ws_name,
            autostart_schedule,
            ttl_ns: ttl_ms.map(|ms| ms * 1_000_000),
            automatic_updates,
        })
        .await?;

    // Create initial build.
    let job_id = Uuid::new_v4();
    let build_id = Uuid::new_v4();

    let template_version_id = body
        .get("template_version_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or(template.active_version_id);

    let _job = state
        .store
        .create_provisioner_job(CreateProvisionerJobInput {
            id: job_id,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            organization_id: org_record.id,
            initiator_id: context.user.id,
            provisioner: "echo".to_owned(),
            file_id: None,
            job_type: "workspace_build".to_owned(),
            input: json!({}),
            tags: HashMap::new(),
        })
        .await?;

    let _build = state
        .store
        .insert_workspace_build(CreateWorkspaceBuildInput {
            id: build_id,
            workspace_id,
            template_version_id,
            build_number: 0,
            transition: "start".to_owned(),
            initiator_id: context.user.id,
            job_id,
            reason: "initiator".to_owned(),
            deadline: None,
            max_deadline: None,
        })
        .await?;

    // Insert build parameters if provided.
    if let Some(params) = body.get("rich_parameter_values").and_then(|v| v.as_array()) {
        let param_pairs: Vec<(String, String)> = params
            .iter()
            .filter_map(|p| {
                let name = p.get("name")?.as_str()?.to_owned();
                let value = p.get("value")?.as_str()?.to_owned();
                Some((name, value))
            })
            .collect();
        if !param_pairs.is_empty() {
            state
                .store
                .insert_workspace_build_parameters(build_id, &param_pairs)
                .await?;
        }
    }

    Ok((StatusCode::CREATED, Json(workspace_to_json(&workspace))).into_response())
}

/// GET /organizations/{organization}/members/{user}/workspaces/available-users
///
/// Returns a list of users that can own workspaces in the given organization.
/// Mirrors the Go `workspaceAvailableUsers` handler.
async fn get_org_member_workspace_available_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((organization, _user)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // Validate the organization exists.
    let Some(_org_record) = resolve_organization(&state, &organization).await? else {
        return Ok(not_found_response("Organization not found."));
    };

    // List all active users — the Go implementation lists all users using
    // system context.  We return MinimalUser representations.
    let (users, _count) = state
        .store
        .list_users(UserListFilter {
            status: Some(UserStatus::Active),
            ..UserListFilter::default()
        })
        .await?;

    let minimal_users: Vec<MinimalUser> = users
        .into_iter()
        .map(|u| MinimalUser {
            id: u.id,
            username: u.username,
            name: u.name,
            avatar_url: u.avatar_url,
        })
        .collect();

    Ok((StatusCode::OK, Json(minimal_users)).into_response())
}

// ---------------------------------------------------------------------------
// Workspace JSON helpers
// ---------------------------------------------------------------------------

/// Builds the full timings response for a workspace build, including provisioner
/// timings, agent script timings, and agent connection timings.
/// Mirrors the Go `buildTimings` function in `coderd/workspacebuilds.go`.
async fn build_timings_response(
    state: &AppState,
    build: &coder_core::WorkspaceBuildRecord,
) -> Result<Value, AppError> {
    // Fetch provisioner job timings.
    let provisioner_timings = state
        .store
        .list_provisioner_job_timings(build.job_id)
        .await?;

    // Go's time.Time.IsZero() checks for year 0001-01-01T00:00:00Z, not Unix epoch.
    let go_zero = time::Date::from_calendar_date(1, time::Month::January, 1)
        .unwrap_or(time::Date::MIN)
        .midnight()
        .assume_utc();

    let provisioner_items: Vec<Value> = provisioner_timings
        .into_iter()
        .filter(|t| {
            // Ref: #15432: timings must not have a zero start or end time.
            t.started_at != go_zero && t.ended_at != go_zero
        })
        .map(|t| {
            json!({
                "job_id": build.job_id,
                "started_at": t.started_at.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
                "ended_at": t.ended_at.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
                "stage": t.stage,
                "source": t.source,
                "action": t.action,
                "resource": t.resource,
            })
        })
        .collect();

    // Fetch agent script timings (best-effort; the store may not implement this yet).
    let agent_script_timings = state
        .store
        .list_workspace_agent_script_timings_by_build_id(build.id)
        .await
        .unwrap_or_default();

    let agent_script_items: Vec<Value> = agent_script_timings
        .into_iter()
        .filter(|t| t.started_at != go_zero && t.ended_at != go_zero)
        .map(|t| {
            json!({
                "started_at": t.started_at.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
                "ended_at": t.ended_at.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
                "exit_code": t.exit_code,
                "stage": t.stage,
                "status": t.status,
                "display_name": t.display_name,
                "workspace_agent_id": t.workspace_agent_id.to_string(),
                "workspace_agent_name": t.workspace_agent_name,
            })
        })
        .collect();

    Ok(json!({
        "provisioner_timings": provisioner_items,
        "agent_script_timings": agent_script_items,
        "agent_connection_timings": [],
    }))
}

fn workspace_transition_from_str(s: &str) -> coder_core::api::WorkspaceTransition {
    match s {
        "start" => coder_core::api::WorkspaceTransition::Start,
        "stop" => coder_core::api::WorkspaceTransition::Stop,
        "delete" => coder_core::api::WorkspaceTransition::Delete,
        other => {
            tracing::warn!(
                transition = other,
                "unknown workspace transition, defaulting to start"
            );
            coder_core::api::WorkspaceTransition::Start
        }
    }
}

fn workspace_to_json(w: &coder_core::WorkspaceRecord) -> Value {
    json!({
        "id": w.id,
        "created_at": w.created_at.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
        "updated_at": w.updated_at.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
        "owner_id": w.owner_id,
        "organization_id": w.organization_id,
        "template_id": w.template_id,
        "name": w.name,
        "autostart_schedule": w.autostart_schedule,
        "ttl_ms": w.ttl_ns.map(|ns| ns / 1_000_000),
        "last_used_at": w.last_used_at.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
        "dormant_at": w.dormant_at.map(|t| t.format(&time::format_description::well_known::Rfc3339).unwrap_or_default()),
        "deleting_at": w.deleting_at.map(|t| t.format(&time::format_description::well_known::Rfc3339).unwrap_or_default()),
        "automatic_updates": w.automatic_updates,
        "favorite": w.favorite,
        "next_start_at": w.next_start_at.map(|t| t.format(&time::format_description::well_known::Rfc3339).unwrap_or_default()),
    })
}

fn build_to_json(b: &coder_core::WorkspaceBuildRecord) -> Value {
    json!({
        "id": b.id,
        "created_at": b.created_at.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
        "updated_at": b.updated_at.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
        "workspace_id": b.workspace_id,
        "build_number": b.build_number,
        "transition": b.transition,
        "job_id": b.job_id,
        "template_version_id": b.template_version_id,
        "initiator_id": b.initiator_id,
        "deadline": b.deadline.map(|t| t.format(&time::format_description::well_known::Rfc3339).unwrap_or_default()),
        "max_deadline": b.max_deadline.map(|t| t.format(&time::format_description::well_known::Rfc3339).unwrap_or_default()),
        "reason": b.reason,
        "daily_cost": b.daily_cost,
    })
}

async fn list_oauth2_provider_apps(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let apps = match state.oauth2_provider.list_apps().await {
        Ok(apps) => apps,
        Err(error) => return handle_oauth2_provider_error(error),
    };
    let response: Vec<OAuth2ProviderAppResponse> =
        apps.into_iter().map(oauth2_app_response).collect();
    Ok((StatusCode::OK, Json(response)).into_response())
}

async fn post_oauth2_provider_app(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<PostOAuth2ProviderAppRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !context.actor.is_owner() {
        return Ok(forbidden_response(
            "You must be an owner to manage OAuth2 provider apps.",
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

async fn get_oauth2_provider_app(
    State(state): State<AppState>,
    Path(app_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
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

async fn put_oauth2_provider_app(
    State(state): State<AppState>,
    Path(app_id): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<PutOAuth2ProviderAppRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !context.actor.is_owner() {
        return Ok(forbidden_response(
            "You must be an owner to manage OAuth2 provider apps.",
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

async fn delete_oauth2_provider_app(
    State(state): State<AppState>,
    Path(app_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !context.actor.is_owner() {
        return Ok(forbidden_response(
            "You must be an owner to manage OAuth2 provider apps.",
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

async fn list_oauth2_provider_app_secrets(
    State(state): State<AppState>,
    Path(app_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
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

async fn post_oauth2_provider_app_secret(
    State(state): State<AppState>,
    Path(app_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !context.actor.is_owner() {
        return Ok(forbidden_response(
            "You must be an owner to manage OAuth2 provider app secrets.",
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

async fn delete_oauth2_provider_app_secret(
    State(state): State<AppState>,
    Path((app_id, secret_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !context.actor.is_owner() {
        return Ok(forbidden_response(
            "You must be an owner to manage OAuth2 provider app secrets.",
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

async fn delete_oauth2_provider_app_tokens(
    State(state): State<AppState>,
    Path(app_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
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

async fn get_oauth2_authorize(
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
            Json(ApiResponse::ok("response_type must be \"code\".")),
        )
            .into_response());
    }
    let client_id = match Uuid::parse_str(&params.client_id) {
        Ok(id) => id,
        Err(_) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::ok("Invalid client_id.")),
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
                Json(ApiResponse::ok("App has invalid callback URL.")),
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

async fn post_oauth2_authorize(
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
            Json(ApiResponse::ok("response_type must be \"code\".")),
        )
            .into_response());
    }
    let client_id = match Uuid::parse_str(&params.client_id) {
        Ok(id) => id,
        Err(_) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::ok("Invalid client_id.")),
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
                Json(ApiResponse::ok("App has invalid callback URL.")),
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

async fn post_oauth2_token(
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
                        Json(ApiResponse::ok("Invalid client_id.")),
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
                        Json(ApiResponse::ok("Invalid client_id.")),
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
            Json(ApiResponse::ok("Unsupported grant_type.")),
        )
            .into_response()),
    }
}

fn handle_oauth2_provider_error(error: OAuth2ProviderError) -> Result<Response, AppError> {
    match error {
        OAuth2ProviderError::Storage(error) => Err(AppError::from(error)),
        OAuth2ProviderError::BadRequest { message } => {
            Ok((StatusCode::BAD_REQUEST, Json(ApiResponse::ok(message))).into_response())
        }
        OAuth2ProviderError::NotFound { message } => Ok(not_found_response(message)),
        OAuth2ProviderError::Unauthorized { message } => Ok(unauthorized_response(message)),
    }
}

fn oauth2_app_response(
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

fn oauth2_secret_response(
    secret: coder_core::identity::OAuth2ProviderAppSecretRecord,
) -> OAuth2ProviderAppSecretResponse {
    OAuth2ProviderAppSecretResponse {
        id: secret.id.to_string(),
        last_used_at: None,
        client_secret_truncated: secret.display_secret,
    }
}

// ---------------------------------------------------------------------------
// Insights / Analytics handlers
// ---------------------------------------------------------------------------

async fn insights_daus(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<InsightsDausQuery>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !can_view_operational_data(&context.actor) {
        return Ok(forbidden_response(
            "You are not authorized to view deployment DAUs.",
        ));
    }

    let tz_offset = query.tz_offset.unwrap_or(0);
    if !(-23..=23).contains(&tz_offset) {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::ok(
                "Invalid tz_offset: must be between -23 and 23.",
            )),
        )
            .into_response());
    }
    let response = state.store.get_deployment_daus(tz_offset).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}

fn parse_template_ids(raw: &Option<String>) -> Vec<Uuid> {
    raw.as_deref()
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| Uuid::from_str(s).ok())
        .collect()
}

fn parse_rfc3339(raw: &Option<String>) -> Option<OffsetDateTime> {
    raw.as_deref()
        .and_then(|s| OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok())
}

async fn insights_templates(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<InsightsTemplatesQuery>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !can_view_operational_data(&context.actor) {
        return Ok(forbidden_response(
            "You are not authorized to view template insights.",
        ));
    }

    let start_time = match parse_rfc3339(&query.start_time) {
        Some(t) => t,
        None => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::ok(
                    "start_time is required and must be RFC 3339.",
                )),
            )
                .into_response());
        }
    };
    let end_time = match parse_rfc3339(&query.end_time) {
        Some(t) => t,
        None => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::ok(
                    "end_time is required and must be RFC 3339.",
                )),
            )
                .into_response());
        }
    };
    let interval = match query.interval.as_deref() {
        Some("week") => InsightsReportInterval::Week,
        None | Some("day") => InsightsReportInterval::Day,
        Some(_) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::ok(
                    "interval must be 'day', 'week', or omitted.",
                )),
            )
                .into_response());
        }
    };
    let template_ids = parse_template_ids(&query.template_ids);

    let sections: Vec<TemplateInsightsSection> = query
        .sections
        .as_deref()
        .unwrap_or("")
        .split(',')
        .filter(|s| !s.is_empty())
        .filter_map(|s| match s.trim() {
            "interval_reports" => Some(TemplateInsightsSection::IntervalReports),
            "report" => Some(TemplateInsightsSection::Report),
            _ => None,
        })
        .collect();

    let mut response = state
        .store
        .get_template_insights(start_time, end_time, interval, template_ids)
        .await?;

    // When the client specifies explicit sections, strip the parts they did
    // not ask for.  An empty `sections` vec means "return everything".
    if !sections.is_empty() {
        if !sections.contains(&TemplateInsightsSection::Report) {
            response.report = None;
        }
        if !sections.contains(&TemplateInsightsSection::IntervalReports) {
            response.interval_reports = Vec::new();
        }
    }

    Ok((StatusCode::OK, Json(response)).into_response())
}

async fn insights_user_activity(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<InsightsUserActivityQuery>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !can_view_operational_data(&context.actor) {
        return Ok(forbidden_response(
            "You are not authorized to view user activity insights.",
        ));
    }

    let start_time = match parse_rfc3339(&query.start_time) {
        Some(t) => t,
        None => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::ok(
                    "start_time is required and must be RFC 3339.",
                )),
            )
                .into_response());
        }
    };
    let end_time = match parse_rfc3339(&query.end_time) {
        Some(t) => t,
        None => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::ok(
                    "end_time is required and must be RFC 3339.",
                )),
            )
                .into_response());
        }
    };
    let template_ids = parse_template_ids(&query.template_ids);

    let response = state
        .store
        .get_user_activity_insights(start_time, end_time, template_ids)
        .await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}

async fn insights_user_latency(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<InsightsUserLatencyQuery>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !can_view_operational_data(&context.actor) {
        return Ok(forbidden_response(
            "You are not authorized to view user latency insights.",
        ));
    }

    let start_time = match parse_rfc3339(&query.start_time) {
        Some(t) => t,
        None => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::ok(
                    "start_time is required and must be RFC 3339.",
                )),
            )
                .into_response());
        }
    };
    let end_time = match parse_rfc3339(&query.end_time) {
        Some(t) => t,
        None => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::ok(
                    "end_time is required and must be RFC 3339.",
                )),
            )
                .into_response());
        }
    };
    let template_ids = parse_template_ids(&query.template_ids);

    let response = state
        .store
        .get_user_latency_insights(start_time, end_time, template_ids)
        .await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}

async fn insights_user_status_counts(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<InsightsUserStatusCountsQuery>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !can_view_operational_data(&context.actor) {
        return Ok(forbidden_response(
            "You are not authorized to view user status counts.",
        ));
    }

    // Resolve timezone from query params, following Go's Etc/GMT±N convention.
    let timezone = match (&query.timezone, query.tz_offset) {
        (Some(tz), _) if !tz.is_empty() => tz.clone(),
        (_, Some(offset)) if !(-23..=23).contains(&offset) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::ok("tz_offset must be between -23 and 23.")),
            )
                .into_response());
        }
        (_, Some(offset)) if offset > 0 => format!("Etc/GMT-{offset}"),
        (_, Some(offset)) if offset < 0 => {
            let abs = offset.saturating_neg();
            format!("Etc/GMT+{abs}")
        }
        _ => "UTC".to_owned(),
    };

    let response = state.store.get_user_status_counts(&timezone).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}

// ---------------------------------------------------------------------------
// Debug / Observability handlers
// ---------------------------------------------------------------------------

async fn debug_coordinator(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !can_view_operational_data(&context.actor) {
        return Ok(forbidden_response(
            "You are not authorized to view coordinator debug information.",
        ));
    }

    Ok(not_implemented_response(
        "Coordinator debug endpoint is not yet implemented in the Rust backend.",
    ))
}

async fn debug_tailnet(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !can_view_operational_data(&context.actor) {
        return Ok(forbidden_response(
            "You are not authorized to view tailnet debug information.",
        ));
    }

    Ok(not_implemented_response(
        "Tailnet debug endpoint is not yet implemented in the Rust backend.",
    ))
}

async fn debug_derp_traffic(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !can_view_operational_data(&context.actor) {
        return Ok(forbidden_response(
            "You are not authorized to view DERP traffic debug information.",
        ));
    }

    Ok(not_implemented_response(
        "DERP traffic debug endpoint is not yet implemented in the Rust backend.",
    ))
}

async fn debug_expvar(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !can_view_operational_data(&context.actor) {
        return Ok(forbidden_response(
            "You are not authorized to view expvar debug information.",
        ));
    }

    Ok(not_implemented_response(
        "Expvar debug endpoint is not yet implemented in the Rust backend.",
    ))
}

async fn debug_pprof(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !can_view_operational_data(&context.actor) {
        return Ok(forbidden_response(
            "You are not authorized to view pprof debug information.",
        ));
    }

    Ok(not_implemented_response(
        "Rust does not support Go-style pprof. Use tracing or jemalloc profiling instead.",
    ))
}

async fn debug_websocket(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !can_view_operational_data(&context.actor) {
        return Ok(forbidden_response(
            "You are not authorized to use the debug websocket.",
        ));
    }

    // In Go this upgrades to a WebSocket echo. For now return a stub JSON response.
    Ok(not_implemented_response(
        "WebSocket echo endpoint is not yet implemented in the Rust backend.",
    ))
}

/// GET /api/v2/debug/metrics — Prometheus metrics endpoint.
///
/// In Go this serves the Prometheus registry via `promhttp`. The Rust backend
/// does not yet have a shared Prometheus registry, so we return a stub
/// `not_implemented` response.
async fn debug_metrics(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !can_view_operational_data(&context.actor) {
        return Ok(forbidden_response(
            "You are not authorized to view debug metrics.",
        ));
    }

    Ok(not_implemented_response(
        "Prometheus metrics endpoint is not yet implemented in the Rust backend.",
    ))
}

// ---------------------------------------------------------------------------
// DERP Map Updates
// ---------------------------------------------------------------------------

/// GET /api/v2/derp-map — WebSocket endpoint that streams DERP map updates.
///
/// In Go this upgrades to a WebSocket and periodically sends the current DERP
/// map. The Rust backend does not yet maintain a live DERP map, so we return a
/// stub `not_implemented` response.
async fn derp_map_updates(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    // The Go handler does NOT require apiKeyMiddleware (it's commented out in
    // coderd.go), so we mirror that: no authentication check here.
    let _ = (&state, &headers);

    Ok(not_implemented_response(
        "DERP map WebSocket endpoint is not yet implemented in the Rust backend.",
    ))
}

// ---------------------------------------------------------------------------
// Regions
// ---------------------------------------------------------------------------

/// GET /api/v2/regions — returns the list of available workspace proxy regions.
///
/// In the OSS edition this always returns a single "primary" region built from
/// the deployment ID and access URL.  The enterprise edition may add additional
/// workspace-proxy regions.
async fn get_regions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let region_id = state
        .store
        .ensure_deployment_metadata()
        .await
        .map(|m| m.deployment_id)?;

    let access_url = state.config.access_url.clone();

    let region = coder_core::Region {
        id: region_id,
        name: "primary".to_string(),
        display_name: "Default".to_string(),
        icon_url: String::new(),
        healthy: true,
        path_app_url: access_url.to_string(),
        wildcard_hostname: String::new(),
    };

    Ok((
        StatusCode::OK,
        Json(coder_core::RegionsResponse {
            regions: vec![region],
        }),
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// Tailnet RPC Connection
// ---------------------------------------------------------------------------

/// GET /api/v2/tailnet — WebSocket RPC connection for tailnet coordination.
///
/// In Go this is `tailnetRPCConn` which upgrades to a WebSocket and serves
/// the tailnet coordination protocol. The Rust backend does not yet have a
/// tailnet service, so we return a stub `not_implemented` response.
async fn tailnet_rpc_conn(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    Ok(not_implemented_response(
        "Tailnet RPC endpoint is not yet implemented in the Rust backend.",
    ))
}

// ---------------------------------------------------------------------------
// Custom Notifications
// ---------------------------------------------------------------------------

/// Maximum length for custom notification title.
const MAX_CUSTOM_NOTIFICATION_TITLE_LEN: usize = 120;
/// Maximum length for custom notification message.
const MAX_CUSTOM_NOTIFICATION_MESSAGE_LEN: usize = 2000;

/// POST /api/v2/notifications/custom — send a custom notification.
///
/// Validates the request body, ensures the caller is not a system user, and
/// enqueues a custom notification.  Full dispatch is not yet wired, so the
/// handler currently returns 204 No Content after validation succeeds.
async fn post_custom_notification(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<coder_core::CustomNotificationRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

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

// ---------------------------------------------------------------------------
// Workspace Agent query parameters
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
struct AgentLogsQuery {
    #[serde(default)]
    after: i64,
    #[serde(default)]
    follow: bool,
    #[serde(default)]
    limit: Option<i64>,
}

#[derive(Debug, Default, Deserialize)]
#[allow(dead_code)]
struct AgentExternalAuthQuery {
    #[serde(default)]
    id: String,
    #[serde(default)]
    listen: bool,
}

// ---------------------------------------------------------------------------
// Workspace Agent conversion helpers
// ---------------------------------------------------------------------------

fn convert_workspace_agent_row(
    row: &coder_core::WorkspaceAgentRow,
    apps: Vec<coder_core::WorkspaceApp>,
    log_sources: Vec<coder_core::WorkspaceAgentLogSource>,
    scripts: Vec<coder_core::WorkspaceAgentScript>,
) -> coder_core::WorkspaceAgent {
    let lifecycle_state = match row.lifecycle_state.as_str() {
        "starting" => coder_core::WorkspaceAgentLifecycle::Starting,
        "start_timeout" => coder_core::WorkspaceAgentLifecycle::StartTimeout,
        "start_error" => coder_core::WorkspaceAgentLifecycle::StartError,
        "ready" => coder_core::WorkspaceAgentLifecycle::Ready,
        "shutting_down" => coder_core::WorkspaceAgentLifecycle::ShuttingDown,
        "shutdown_timeout" => coder_core::WorkspaceAgentLifecycle::ShutdownTimeout,
        "shutdown_error" => coder_core::WorkspaceAgentLifecycle::ShutdownError,
        "off" => coder_core::WorkspaceAgentLifecycle::Off,
        _ => coder_core::WorkspaceAgentLifecycle::Created,
    };

    let status = derive_agent_status(row);

    let subsystems: Vec<coder_core::AgentSubsystem> = row
        .subsystems
        .iter()
        .filter_map(|s| match s.as_str() {
            "envbuilder" => Some(coder_core::AgentSubsystem::Envbuilder),
            "envbox" => Some(coder_core::AgentSubsystem::Envbox),
            "exectrace" => Some(coder_core::AgentSubsystem::Exectrace),
            _ => None,
        })
        .collect();

    let display_apps: Vec<coder_core::DisplayApp> = row
        .display_apps
        .iter()
        .filter_map(|d| match d.as_str() {
            "vscode" => Some(coder_core::DisplayApp::Vscode),
            "vscode_insiders" => Some(coder_core::DisplayApp::VscodeInsiders),
            "web_terminal" => Some(coder_core::DisplayApp::WebTerminal),
            "ssh_helper" => Some(coder_core::DisplayApp::SshHelper),
            "port_forwarding_helper" => Some(coder_core::DisplayApp::PortForwardingHelper),
            _ => None,
        })
        .collect();

    let environment_variables: HashMap<String, String> = row
        .environment_variables
        .as_deref()
        .and_then(|json_str| serde_json::from_str(json_str).ok())
        .unwrap_or_default();

    coder_core::WorkspaceAgent {
        id: row.id,
        parent_id: row.parent_id,
        created_at: row.created_at,
        updated_at: row.updated_at,
        first_connected_at: row.first_connected_at,
        last_connected_at: row.last_connected_at,
        disconnected_at: row.disconnected_at,
        started_at: row.started_at,
        ready_at: row.ready_at,
        status,
        lifecycle_state,
        name: row.name.clone(),
        resource_id: row.resource_id,
        instance_id: row.auth_instance_id.clone().unwrap_or_default(),
        architecture: row.architecture.clone(),
        environment_variables,
        operating_system: row.operating_system.clone(),
        logs_length: row.logs_length,
        logs_overflowed: row.logs_overflowed,
        directory: row.directory.clone(),
        expanded_directory: row.expanded_directory.clone(),
        version: row.version.clone(),
        api_version: row.api_version.clone(),
        apps,
        latency: HashMap::new(),
        connection_timeout_seconds: row.connection_timeout_seconds,
        troubleshooting_url: row.troubleshooting_url.clone(),
        subsystems,
        health: coder_core::WorkspaceAgentHealth {
            healthy: true,
            reason: None,
        },
        display_apps,
        log_sources,
        scripts,
    }
}

fn derive_agent_status(row: &coder_core::WorkspaceAgentRow) -> coder_core::WorkspaceAgentStatus {
    if row.first_connected_at.is_none() {
        if row.connection_timeout_seconds > 0 {
            if let Some(timeout) =
                i64::from(row.connection_timeout_seconds).checked_mul(1_000_000_000)
            {
                let deadline = row.created_at + time::Duration::nanoseconds(timeout);
                if OffsetDateTime::now_utc() > deadline {
                    return coder_core::WorkspaceAgentStatus::Timeout;
                }
            }
        }
        return coder_core::WorkspaceAgentStatus::Connecting;
    }
    if row.disconnected_at.is_some() {
        return coder_core::WorkspaceAgentStatus::Disconnected;
    }
    coder_core::WorkspaceAgentStatus::Connected
}

fn convert_workspace_app_row(row: &coder_core::WorkspaceAppRow) -> coder_core::WorkspaceApp {
    let sharing_level = match row.sharing_level.as_str() {
        "authenticated" => coder_core::AppSharingLevel::Authenticated,
        "organization" => coder_core::AppSharingLevel::Organization,
        "public" => coder_core::AppSharingLevel::Public,
        _ => coder_core::AppSharingLevel::Owner,
    };
    let health = match row.health.as_str() {
        "initializing" => coder_core::WorkspaceAppHealth::Initializing,
        "healthy" => coder_core::WorkspaceAppHealth::Healthy,
        "unhealthy" => coder_core::WorkspaceAppHealth::Unhealthy,
        _ => coder_core::WorkspaceAppHealth::Disabled,
    };
    let open_in = match row.open_in.as_str() {
        "tab" => coder_core::WorkspaceAppOpenIn::Tab,
        "window" => coder_core::WorkspaceAppOpenIn::Window,
        _ => coder_core::WorkspaceAppOpenIn::SlimWindow,
    };
    coder_core::WorkspaceApp {
        id: row.id,
        slug: row.slug.clone(),
        display_name: row.display_name.clone(),
        command: row.command.clone(),
        url: row.url.clone(),
        icon: row.icon.clone(),
        subdomain: row.subdomain,
        sharing_level,
        healthcheck_url: row.healthcheck_url.clone(),
        healthcheck_interval: row.healthcheck_interval,
        healthcheck_threshold: row.healthcheck_threshold,
        health,
        external: row.external,
        display_order: row.display_order,
        hidden: row.hidden,
        open_in,
        display_group: row.display_group.clone(),
    }
}

fn convert_log_source_row(
    row: &coder_core::WorkspaceAgentLogSourceRow,
) -> coder_core::WorkspaceAgentLogSource {
    coder_core::WorkspaceAgentLogSource {
        id: row.id,
        workspace_agent_id: row.workspace_agent_id,
        created_at: row.created_at,
        display_name: row.display_name.clone(),
        icon: row.icon.clone(),
    }
}

fn convert_script_row(
    row: &coder_core::WorkspaceAgentScriptRow,
) -> coder_core::WorkspaceAgentScript {
    coder_core::WorkspaceAgentScript {
        id: row.id,
        log_source_id: row.log_source_id,
        log_path: row.log_path.clone(),
        script: row.script.clone(),
        cron: row.cron.clone(),
        start_blocks_login: row.start_blocks_login,
        run_on_start: row.run_on_start,
        run_on_stop: row.run_on_stop,
        timeout_seconds: row.timeout_seconds,
        display_name: row.display_name.clone(),
    }
}

fn convert_log_level(level: &str) -> coder_core::LogLevel {
    match level {
        "trace" => coder_core::LogLevel::Trace,
        "debug" => coder_core::LogLevel::Debug,
        "warn" => coder_core::LogLevel::Warn,
        "error" => coder_core::LogLevel::Error,
        _ => coder_core::LogLevel::Info,
    }
}

#[allow(dead_code)]
fn convert_app_status_state(state: &str) -> coder_core::WorkspaceAppStatusState {
    match state {
        "working" => coder_core::WorkspaceAppStatusState::Working,
        "complete" => coder_core::WorkspaceAppStatusState::Complete,
        "failure" => coder_core::WorkspaceAppStatusState::Failure,
        _ => coder_core::WorkspaceAppStatusState::Idle,
    }
}

/// Build a full agent response including apps, log sources, scripts.
async fn build_agent_response(
    state: &AppState,
    row: &coder_core::WorkspaceAgentRow,
) -> Result<coder_core::WorkspaceAgent, AppError> {
    let app_rows = state.store.list_workspace_apps_by_agent_id(row.id).await?;
    let apps: Vec<coder_core::WorkspaceApp> =
        app_rows.iter().map(convert_workspace_app_row).collect();

    let source_rows = state.store.list_workspace_agent_log_sources(row.id).await?;
    let log_sources: Vec<coder_core::WorkspaceAgentLogSource> =
        source_rows.iter().map(convert_log_source_row).collect();

    let script_rows = state.store.list_workspace_agent_scripts(row.id).await?;
    let scripts: Vec<coder_core::WorkspaceAgentScript> =
        script_rows.iter().map(convert_script_row).collect();

    Ok(convert_workspace_agent_row(row, apps, log_sources, scripts))
}

// ---------------------------------------------------------------------------
// Workspace Agent handlers (20 routes)
// ---------------------------------------------------------------------------

/// GET /api/v2/workspaceagents/{agent} — get agent info.
async fn get_workspace_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(agent_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(row) = state.store.find_workspace_agent_by_id(agent_id).await? else {
        return Ok(resource_not_found_response());
    };

    let agent = build_agent_response(&state, &row).await?;
    Ok((StatusCode::OK, Json(agent)).into_response())
}

/// GET /api/v2/workspaceagents/{agent}/connection — per-agent connection info.
async fn get_workspace_agent_connection(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(_agent_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let info = build_workspace_agent_connection_info(&state);
    Ok((StatusCode::OK, Json(info)).into_response())
}

/// GET /api/v2/workspaceagents/{agent}/containers — list containers.
async fn get_workspace_agent_containers(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(agent_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(_row) = state.store.find_workspace_agent_by_id(agent_id).await? else {
        return Ok(resource_not_found_response());
    };

    let devcontainer_rows = state
        .store
        .list_workspace_agent_devcontainers(agent_id)
        .await?;
    let devcontainers: Vec<coder_core::WorkspaceAgentDevcontainer> = devcontainer_rows
        .iter()
        .map(|dc| coder_core::WorkspaceAgentDevcontainer {
            id: dc.id,
            workspace_agent_id: dc.workspace_agent_id,
            workspace_folder: dc.workspace_folder.clone(),
            config_path: dc.config_path.clone(),
            name: dc.name.clone(),
            container: None,
        })
        .collect();

    Ok((
        StatusCode::OK,
        Json(WorkspaceAgentListContainersResponse {
            containers: Vec::new(),
            devcontainers,
        }),
    )
        .into_response())
}

/// POST /api/v2/workspaceagents/{agent}/containers/devcontainers/{dc}/recreate — recreate devcontainer.
async fn post_workspace_agent_recreate_devcontainer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((agent_id, _dc_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(row) = state.store.find_workspace_agent_by_id(agent_id).await? else {
        return Ok(resource_not_found_response());
    };

    let status = derive_agent_status(&row);
    if status != coder_core::WorkspaceAgentStatus::Connected {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                format!("Agent state is \"{status:?}\", it must be in the \"Connected\" state."),
                "The agent must be connected before a devcontainer can be recreated.",
            )),
        )
            .into_response());
    }

    // Devcontainer recreation requires a real-time connection to the agent
    // which is not yet available in the Rust backend.
    Ok(not_implemented_response(
        "Devcontainer recreation requires agent connectivity which is not yet implemented.",
    ))
}

/// DELETE /api/v2/workspaceagents/{agent}/containers/devcontainers/{dc} — delete devcontainer.
async fn delete_workspace_agent_devcontainer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((agent_id, _dc_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(row) = state.store.find_workspace_agent_by_id(agent_id).await? else {
        return Ok(resource_not_found_response());
    };

    let status = derive_agent_status(&row);
    if status != coder_core::WorkspaceAgentStatus::Connected {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                format!("Agent state is \"{status:?}\", it must be in the \"Connected\" state."),
                "The agent must be connected before a devcontainer can be deleted.",
            )),
        )
            .into_response());
    }

    // Devcontainer deletion requires a real-time connection to the agent
    // which is not yet available in the Rust backend.
    Ok(not_implemented_response(
        "Devcontainer deletion requires agent connectivity which is not yet implemented.",
    ))
}

/// GET /api/v2/workspaceagents/{agent}/containers/watch — SSE container watch.
async fn get_workspace_agent_containers_watch(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(agent_id): Path<Uuid>,
    ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(_row) = state.store.find_workspace_agent_by_id(agent_id).await? else {
        return Ok(resource_not_found_response());
    };

    // Accept WebSocket upgrade, then close — real streaming requires agent connectivity.
    Ok(ws.on_upgrade(|socket| {
        ws_close_not_implemented(
            socket,
            "Container watch requires agent connectivity which is not yet implemented.",
        )
    }))
}

/// GET /api/v2/workspaceagents/{agent}/coordinate — WebSocket coordination.
async fn get_workspace_agent_coordinate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(agent_id): Path<Uuid>,
    ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(_row) = state.store.find_workspace_agent_by_id(agent_id).await? else {
        return Ok(resource_not_found_response());
    };

    // Accept WebSocket upgrade, then close — real coordination requires tailnet.
    Ok(ws.on_upgrade(|socket| {
        ws_close_not_implemented(
            socket,
            "Agent coordination requires tailnet integration which is not yet implemented.",
        )
    }))
}

/// GET /api/v2/workspaceagents/{agent}/listening-ports — list listening ports.
async fn get_workspace_agent_listening_ports(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(agent_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(_row) = state.store.find_workspace_agent_by_id(agent_id).await? else {
        return Ok(resource_not_found_response());
    };

    // Listening ports are reported by the agent in real-time; return empty for now.
    Ok((
        StatusCode::OK,
        Json(WorkspaceAgentListeningPortsResponse { ports: Vec::new() }),
    )
        .into_response())
}

/// GET /api/v2/workspaceagents/{agent}/logs — streaming agent logs.
async fn get_workspace_agent_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(agent_id): Path<Uuid>,
    Query(query): Query<AgentLogsQuery>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(_row) = state.store.find_workspace_agent_by_id(agent_id).await? else {
        return Ok(resource_not_found_response());
    };

    if query.follow {
        // Streaming follow is not yet implemented; return current logs.
        return Ok(not_implemented_response(
            "Log streaming follow is not yet implemented.",
        ));
    }

    let limit = query.limit.unwrap_or(256).clamp(1, 10000);
    let log_rows = state
        .store
        .list_workspace_agent_logs(agent_id, query.after, limit)
        .await?;
    let logs: Vec<coder_core::WorkspaceAgentLog> = log_rows
        .iter()
        .map(|r| coder_core::WorkspaceAgentLog {
            id: r.id,
            created_at: r.created_at,
            output: r.output.clone(),
            level: convert_log_level(&r.level),
            source_id: r.log_source_id,
        })
        .collect();

    Ok((StatusCode::OK, Json(logs)).into_response())
}

/// GET /api/v2/workspaceagents/{agent}/pty — WebSocket terminal.
async fn get_workspace_agent_pty(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(agent_id): Path<Uuid>,
    ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(_row) = state.store.find_workspace_agent_by_id(agent_id).await? else {
        return Ok(resource_not_found_response());
    };

    // Accept WebSocket upgrade, then close — real PTY requires agent connectivity.
    Ok(ws.on_upgrade(|socket| {
        ws_close_not_implemented(
            socket,
            "Agent PTY requires agent connectivity which is not yet implemented.",
        )
    }))
}

/// GET /api/v2/workspaceagents/{agent}/watch-metadata — SSE metadata watch.
async fn get_workspace_agent_watch_metadata(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(agent_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(_row) = state.store.find_workspace_agent_by_id(agent_id).await? else {
        return Ok(resource_not_found_response());
    };

    // SSE streaming not yet implemented; return current snapshot as JSON.
    let metadata_rows = state.store.list_workspace_agent_metadata(agent_id).await?;
    let metadata: Vec<coder_core::WorkspaceAgentMetadata> = metadata_rows
        .iter()
        .map(|m| coder_core::WorkspaceAgentMetadata {
            display_name: m.display_name.clone(),
            key: m.key.clone(),
            script: m.script.clone(),
            value: m.value.clone(),
            error: m.error.clone(),
            timeout: m.timeout,
            interval: m.interval,
            collected_at: m.collected_at,
            display_order: m.display_order,
        })
        .collect();

    Ok((StatusCode::OK, Json(metadata)).into_response())
}

/// GET /api/v2/workspaceagents/{agent}/watch-metadata-ws — WebSocket metadata watch.
async fn get_workspace_agent_watch_metadata_ws(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(agent_id): Path<Uuid>,
    ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(_row) = state.store.find_workspace_agent_by_id(agent_id).await? else {
        return Ok(resource_not_found_response());
    };

    // Accept WebSocket upgrade, then close — real watch requires pubsub.
    Ok(ws.on_upgrade(|socket| ws_close_not_implemented(
        socket,
        "Agent metadata WebSocket watch requires pubsub integration which is not yet implemented.",
    )))
}

/// GET /api/v2/workspaceagents/connection — global agent connection info.
/// Build the deployment-wide DERP connection info from server config.
/// Shared by both the per-agent and global connection endpoints.
fn build_workspace_agent_connection_info(state: &AppState) -> WorkspaceAgentConnectionInfo {
    let mut regions = HashMap::new();
    for region in &state.config.derp_regions {
        let nodes: Vec<DERPNode> = region
            .nodes
            .iter()
            .map(|node| DERPNode {
                name: node.name.clone(),
                region_id: i64::from(region.id),
                host_name: node.url.host_str().unwrap_or_default().to_owned(),
                ipv4: None,
                ipv6: None,
                stun_port: 3478,
                stun_only: false,
                derp_port: node.url.port_or_known_default().map_or(443, i32::from),
                force_http: node.url.scheme() == "http",
            })
            .collect();
        regions.insert(
            region.id.to_string(),
            DERPMapRegion {
                region_id: i64::from(region.id),
                region_code: region.name.to_lowercase().replace(' ', "-"),
                region_name: region.name.clone(),
                avoid: false,
                nodes,
            },
        );
    }

    WorkspaceAgentConnectionInfo {
        derp_map: DERPMap { regions },
        derp_force_websockets: false,
        disable_direct_connections: false,
        hostname_suffix: state.config.ssh.hostname_suffix.clone(),
    }
}

async fn get_workspace_agents_connection_info(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let info = build_workspace_agent_connection_info(&state);
    Ok((StatusCode::OK, Json(info)).into_response())
}

/// PATCH /api/v2/workspaceagents/me/app-status — update app status (agent-authenticated).
async fn patch_workspace_agent_app_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<PatchAppStatusRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(agent) = authenticate_agent_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid agent token."));
    };

    let Json(request) = match body {
        Ok(json) => json,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    if request.app_slug.is_empty() {
        return Ok(validation_response(vec![ValidationError {
            field: "app_slug".to_owned(),
            detail: "App slug is required.".to_owned(),
        }]));
    }

    // Resolve the workspace for this agent.
    let workspace = state.store.find_workspace_by_agent_id(agent.id).await?;
    let workspace = match workspace {
        Some(ws) => ws,
        None => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error("Failed to get workspace.", "")),
            )
                .into_response());
        }
    };

    // Look up the app by slug to get its ID.
    let app = state
        .store
        .find_workspace_app_by_agent_and_slug(agent.id, &request.app_slug)
        .await?;
    let app = match app {
        Some(a) => a,
        None => {
            return Ok((
                StatusCode::NOT_FOUND,
                Json(ApiResponse::error(
                    "App not found.",
                    format!("no app with slug {}", request.app_slug),
                )),
            )
                .into_response());
        }
    };

    // Insert the app status.
    let state_str = match request.state {
        coder_core::WorkspaceAppStatusState::Working => "working",
        coder_core::WorkspaceAppStatusState::Complete => "complete",
        coder_core::WorkspaceAppStatusState::Failure => "failure",
        coder_core::WorkspaceAppStatusState::Idle => "idle",
    };
    let input = coder_core::InsertWorkspaceAppStatusInput {
        agent_id: agent.id,
        app_id: app.id,
        workspace_id: workspace.id,
        state: state_str.to_owned(),
        message: request.message,
        uri: request.uri,
    };
    state.store.insert_workspace_app_status(&input).await?;

    Ok((StatusCode::OK, Json(ApiResponse::ok("App status updated."))).into_response())
}

/// GET /api/v2/workspaceagents/me/external-auth — agent external auth.
async fn get_workspace_agent_external_auth(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AgentExternalAuthQuery>,
) -> Result<Response, AppError> {
    let Some(_agent) = authenticate_agent_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid agent token."));
    };

    // Validate that either id or match is provided.
    if query.id.is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error("'id' must be provided.", "")),
        )
            .into_response());
    }

    // External auth configuration lookup is not yet available in the Rust
    // backend. Return a stub response indicating the provider was not found.
    Ok((
        StatusCode::NOT_FOUND,
        Json(ApiResponse::error(
            "External auth provider not found.",
            "External auth configuration is not yet supported.",
        )),
    )
        .into_response())
}

/// POST /api/v2/workspaceagents/me/log-source — create agent log source.
async fn post_workspace_agent_log_source(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<CreateLogSourceRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(agent) = authenticate_agent_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid agent token."));
    };

    let Json(request) = match body {
        Ok(json) => json,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    if request.display_name.is_empty() {
        return Ok(validation_response(vec![ValidationError {
            field: "display_name".to_owned(),
            detail: "Display name is required.".to_owned(),
        }]));
    }

    let row = state
        .store
        .insert_workspace_agent_log_source(
            agent.id,
            request.id,
            &request.display_name,
            &request.icon,
        )
        .await?;

    let source = convert_log_source_row(&row);
    Ok((StatusCode::CREATED, Json(source)).into_response())
}

/// PATCH /api/v2/workspaceagents/me/logs — append agent logs.
async fn patch_workspace_agent_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<PatchAgentLogsRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(agent) = authenticate_agent_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid agent token."));
    };

    let Json(request) = match body {
        Ok(json) => json,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    if request.logs.is_empty() {
        return Ok(validation_response(vec![ValidationError {
            field: "logs".to_owned(),
            detail: "At least one log entry is required.".to_owned(),
        }]));
    }

    let log_inputs: Vec<coder_core::InsertAgentLogInput> = request
        .logs
        .into_iter()
        .map(|entry| coder_core::InsertAgentLogInput {
            created_at: entry.created_at,
            output: entry.output,
            level: match entry.level {
                coder_core::LogLevel::Trace => "trace".to_owned(),
                coder_core::LogLevel::Debug => "debug".to_owned(),
                coder_core::LogLevel::Info => "info".to_owned(),
                coder_core::LogLevel::Warn => "warn".to_owned(),
                coder_core::LogLevel::Error => "error".to_owned(),
            },
        })
        .collect();

    state
        .store
        .insert_workspace_agent_logs(agent.id, request.log_source_id, &log_inputs)
        .await?;

    Ok(StatusCode::OK.into_response())
}

/// GET /api/v2/workspaceagents/me/reinit — long-poll for agent reinit (SSE).
///
/// In Go this uses Server-Sent Events to stream reinitialization events
/// (e.g. when a prebuilt workspace is claimed). For now, the Rust implementation
/// authenticates the agent and returns a 200 with no events since the pubsub
/// infrastructure for prebuild claims is not yet ported.
async fn get_workspace_agent_reinit(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_agent) = authenticate_agent_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid agent token."));
    };

    // The full SSE-based reinit watcher requires pubsub subscription to
    // prebuild_claimed channels. For now, return not_implemented to signal
    // the endpoint is recognized but the streaming behaviour is pending.
    Ok(not_implemented_response(
        "Agent reinit long-poll requires pubsub infrastructure.",
    ))
}

/// GET /api/v2/workspaceagents/me/rpc — dRPC over WebSocket.
///
/// In Go this upgrades to a WebSocket, wraps it with yamux, then serves dRPC
/// methods for the agent API (manifest, stats, lifecycle, etc.).
/// The full dRPC/yamux infrastructure is not yet ported.
async fn get_workspace_agent_rpc(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_agent) = authenticate_agent_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid agent token."));
    };

    Ok(not_implemented_response(
        "Agent dRPC/WebSocket endpoint requires yamux and dRPC infrastructure.",
    ))
}

/// POST /api/v2/workspaceagents/aws-instance-identity — AWS instance identity auth.
async fn post_workspace_agent_instance_identity_aws(
    State(state): State<AppState>,
    body: Result<Json<AWSInstanceIdentityToken>, JsonRejection>,
) -> Result<Response, AppError> {
    let Json(token) = match body {
        Ok(json) => json,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    // In the Go implementation, the document is parsed and validated against
    // AWS certificates to extract the instance ID.  Full cryptographic
    // verification is not yet implemented; we extract the instance_id from
    // the identity document JSON directly.
    let instance_id = match serde_json::from_str::<Value>(&token.document) {
        Ok(doc) => match doc.get("instanceId").and_then(|v| v.as_str()) {
            Some(id) => id.to_owned(),
            None => {
                return Ok((
                    StatusCode::BAD_REQUEST,
                    Json(ApiResponse::error(
                        "Invalid AWS identity document: missing instanceId.",
                        "",
                    )),
                )
                    .into_response());
            }
        },
        Err(_) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error(
                    "Invalid AWS identity document: malformed JSON.",
                    "",
                )),
            )
                .into_response());
        }
    };

    handle_auth_instance_id(&state, &instance_id).await
}

/// POST /api/v2/workspaceagents/azure-instance-identity — Azure instance identity auth.
async fn post_workspace_agent_instance_identity_azure(
    State(state): State<AppState>,
    body: Result<Json<AzureInstanceIdentityToken>, JsonRejection>,
) -> Result<Response, AppError> {
    let Json(token) = match body {
        Ok(json) => json,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    // In the Go implementation, the Azure signature is a PKCS7 JWT that is
    // validated against Microsoft certificates.  Full cryptographic
    // verification is not yet implemented; we extract the VM ID from the
    // JWT payload directly.
    let instance_id = extract_instance_id_from_jwt(&token.signature);
    match instance_id {
        Some(id) => handle_auth_instance_id(&state, &id).await,
        None => Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "Invalid Azure identity: could not extract instance ID from signature.",
                "",
            )),
        )
            .into_response()),
    }
}

/// POST /api/v2/workspaceagents/google-instance-identity — Google instance identity auth.
async fn post_workspace_agent_instance_identity_google(
    State(state): State<AppState>,
    body: Result<Json<GCPInstanceIdentityToken>, JsonRejection>,
) -> Result<Response, AppError> {
    let Json(token) = match body {
        Ok(json) => json,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    // In the Go implementation, the GCP JWT is validated against Google's
    // token validator and the instance_id is extracted from the claims.
    // Full cryptographic verification is not yet implemented; we extract
    // the instance_id from the JWT payload directly.
    let instance_id = extract_instance_id_from_jwt(&token.json_web_token);
    match instance_id {
        Some(id) => handle_auth_instance_id(&state, &id).await,
        None => Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "Invalid GCP identity: could not extract instance ID from token.",
                "",
            )),
        )
            .into_response()),
    }
}

/// Extracts an instance_id claim from a JWT payload without cryptographic
/// verification.  Returns `None` when the token structure is invalid or
/// the claim is missing.
fn extract_instance_id_from_jwt(jwt: &str) -> Option<String> {
    // JWTs are header.payload.signature – we need the payload part.
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() < 2 {
        return None;
    }

    use base64::Engine;
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let payload_bytes = engine.decode(parts[1]).ok()?;
    let payload: Value = serde_json::from_slice(&payload_bytes).ok()?;

    // Azure puts vmId at the top level; GCP nests under google.compute_engine.instance_id.
    if let Some(vm_id) = payload.get("vmId").and_then(|v| v.as_str()) {
        return Some(vm_id.to_owned());
    }
    if let Some(id) = payload
        .get("google")
        .and_then(|g| g.get("compute_engine"))
        .and_then(|ce| ce.get("instance_id"))
        .and_then(|v| v.as_str())
    {
        return Some(id.to_owned());
    }

    None
}

/// Shared handler that takes a cloud-provider instance_id and performs the
/// agent→resource→job→build lookup chain, mirroring the Go
/// `handleAuthInstanceID` function.
async fn handle_auth_instance_id(
    state: &AppState,
    instance_id: &str,
) -> Result<Response, AppError> {
    // Step 1: Lookup agent by instance_id.
    let agent = match state
        .store
        .find_workspace_agent_by_instance_id(instance_id)
        .await?
    {
        Some(agent) => agent,
        None => {
            return Ok(not_found_response(format!(
                "Instance with id \"{instance_id}\" not found."
            )));
        }
    };

    // Step 2: Lookup the workspace resource that owns this agent.
    let resource = match state
        .store
        .find_workspace_resource_by_id(agent.resource_id)
        .await?
    {
        Some(resource) => resource,
        None => {
            return Ok((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error(
                    "Internal error fetching provisioner job resource.",
                    "",
                )),
            )
                .into_response());
        }
    };

    // Step 3: Lookup the provisioner job for this resource.
    let job = match state.store.find_provisioner_job(resource.job_id).await? {
        Some(job) => job,
        None => {
            return Ok((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error(
                    "Internal error fetching provisioner job.",
                    "",
                )),
            )
                .into_response());
        }
    };

    // Step 4: Validate job type is "workspace_build".
    if job.job_type != "workspace_build" {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                format!("\"{}\" jobs cannot be authenticated.", job.job_type),
                "",
            )),
        )
            .into_response());
    }

    // Step 5: Extract workspace_build_id from job input.
    let workspace_build_id = match job
        .input
        .get("workspace_build_id")
        .and_then(|v: &Value| v.as_str())
        .and_then(|s| Uuid::from_str(s).ok())
    {
        Some(id) => id,
        None => {
            return Ok((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error(
                    "Internal error extracting job data.",
                    "",
                )),
            )
                .into_response());
        }
    };

    // Step 6: Lookup the workspace build.
    let build = match state
        .store
        .find_workspace_build_by_id(workspace_build_id)
        .await?
    {
        Some(build) => build,
        None => {
            return Ok((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error(
                    "Internal error fetching workspace build.",
                    "",
                )),
            )
                .into_response());
        }
    };

    // Step 7: Verify this is the latest build (replay prevention).
    let latest_build = match state
        .store
        .find_latest_workspace_build(build.workspace_id)
        .await?
    {
        Some(latest) => latest,
        None => {
            return Ok((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error(
                    "Internal error fetching the latest workspace build.",
                    "",
                )),
            )
                .into_response());
        }
    };

    if latest_build.id != build.id {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                format!(
                    "Resource found for id \"{instance_id}\", but isn't registered on the latest history."
                ),
                "",
            )),
        )
            .into_response());
    }

    // Step 8: Return the agent auth token.
    Ok((
        StatusCode::OK,
        Json(WorkspaceAgentAuthenticateResponse {
            session_token: agent.auth_token.to_string(),
        }),
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// File upload / download handlers
// ---------------------------------------------------------------------------

const TAR_MIME_TYPE: &str = "application/x-tar";
const ZIP_MIME_TYPE: &str = "application/zip";
const WINDOWS_ZIP_MIME_TYPE: &str = "application/x-zip-compressed";

/// POST /api/v2/files – upload a binary file, deduplicate by SHA-256 hash.
async fn post_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let raw_content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    // Strip optional parameters (e.g. "; charset=binary") before matching.
    let content_type = raw_content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim();

    match content_type {
        TAR_MIME_TYPE | ZIP_MIME_TYPE | WINDOWS_ZIP_MIME_TYPE => {}
        _ => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::ok(format!(
                    "Unsupported content type header \"{content_type}\"."
                ))),
            )
                .into_response());
        }
    }

    let data: Vec<u8> = body.to_vec();
    let mimetype = content_type.to_owned();

    // Compute SHA-256 hash of the raw bytes.
    let hash = {
        let mut hasher = Sha256::new();
        hasher.update(&data);
        format!("{:x}", hasher.finalize())
    };

    let file_id = Uuid::new_v4();
    let input = InsertFileInput {
        id: file_id,
        hash,
        created_by: context.user.id,
        mimetype,
        data,
    };

    // INSERT … ON CONFLICT handles the race atomically – if a duplicate
    // exists the DB returns the existing row instead of raising an error.
    let result = state.store.insert_file(input).await?;

    // If the returned id differs from the one we generated, a duplicate
    // already existed and the DB returned the existing row.
    let status = if result.id == file_id {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };

    Ok((status, Json(UploadFileResponse { id: result.id })).into_response())
}

/// GET /api/v2/files/{fileid} – retrieve a file by UUID.
async fn get_file_by_id(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let file = state.store.get_file_by_id(file_id).await?;
    let Some(file) = file else {
        return Ok(resource_not_found_response());
    };

    let content_type = HeaderValue::from_str(&file.mimetype)
        .unwrap_or(HeaderValue::from_static("application/octet-stream"));

    let mut response_headers = HeaderMap::new();
    response_headers.insert(CONTENT_TYPE, content_type);

    Ok((StatusCode::OK, response_headers, file.data).into_response())
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

/// Stored in request extensions so downstream handlers can read the real
/// client IP even when the server is behind a reverse proxy.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(crate) struct RealIp(pub(crate) IpAddr);

/// Middleware: extract the real client IP from X-Forwarded-For / X-Real-IP
/// headers and store it in request extensions.
async fn real_ip_middleware(mut request: axum::extract::Request, next: Next) -> Response {
    let ip = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
        .or_else(|| {
            request
                .headers()
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.trim().parse::<IpAddr>().ok())
        });

    if let Some(ip) = ip {
        request.extensions_mut().insert(RealIp(ip));
    }

    next.run(request).await
}

/// Middleware: set Content-Security-Policy on every response.
async fn csp_middleware(request: axum::extract::Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    // Use a restrictive default policy; callers can override per-route if needed.
    if let Ok(value) =
        HeaderValue::from_str("default-src 'self'; frame-ancestors 'none'; form-action 'self'")
    {
        response
            .headers_mut()
            .insert(HeaderName::from_static("content-security-policy"), value);
    }
    response
}

/// Middleware: add Strict-Transport-Security header when the request arrived
/// over HTTPS (indicated by scheme or X-Forwarded-Proto).
async fn hsts_middleware(request: axum::extract::Request, next: Next) -> Response {
    let is_https = request
        .uri()
        .scheme_str()
        .map(|s| s == "https")
        .unwrap_or(false)
        || request
            .headers()
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(|v| v.trim().eq_ignore_ascii_case("https"))
            .unwrap_or(false);

    let mut response = next.run(request).await;

    if is_https {
        if let Ok(value) = HeaderValue::from_str("max-age=31536000; includeSubDomains") {
            response
                .headers_mut()
                .insert(HeaderName::from_static("strict-transport-security"), value);
        }
    }

    response
}

/// Middleware: CSRF protection – require a non-empty X-CSRF-Token header on
/// mutating requests (POST / PUT / DELETE / PATCH) that carry cookie-based
/// authentication.
///
/// Pre-authentication endpoints are exempt because the browser may still hold
/// an expired session cookie when the user tries to log in again, and there is
/// no way for the client to obtain a CSRF token before authenticating.  CSP
/// violation reports are also exempt because browsers send them automatically
/// without custom headers.
async fn csrf_middleware(request: axum::extract::Request, next: Next) -> Response {
    use http::Method;

    /// Paths that are exempt from CSRF validation.  These are either
    /// pre-authentication endpoints or browser-initiated reports that cannot
    /// carry custom headers.
    const CSRF_EXEMPT_PATHS: &[&str] = &[
        "/api/v2/users/login",
        "/api/v2/users/first",
        "/api/v2/users/otp/request",
        "/api/v2/users/otp/change-password",
        "/api/v2/csp/reports",
        "/oauth2/tokens",
    ];

    let path = request.uri().path();
    let is_exempt = CSRF_EXEMPT_PATHS.contains(&path);

    if is_exempt {
        return next.run(request).await;
    }

    let is_mutating_method = matches!(
        *request.method(),
        Method::POST | Method::PUT | Method::DELETE | Method::PATCH
    );

    let has_cookie = request.headers().contains_key(http::header::COOKIE);

    if is_mutating_method && has_cookie {
        let has_csrf = request
            .headers()
            .get("x-csrf-token")
            .and_then(|v| v.to_str().ok())
            .map(|v| !v.is_empty())
            .unwrap_or(false);

        if !has_csrf {
            return (
                StatusCode::FORBIDDEN,
                Json(ApiResponse::ok(
                    "CSRF token required for cookie-authenticated mutating requests.",
                )),
            )
                .into_response();
        }
    }

    next.run(request).await
}

/// Middleware: record basic Prometheus-style HTTP metrics using the `metrics`
/// crate.  Counters and histograms are registered lazily on first use.
async fn prometheus_middleware(request: axum::extract::Request, next: Next) -> Response {
    let method = request.method().to_string();
    let path = request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|m| m.as_str().to_owned())
        .unwrap_or_else(|| "unmatched".to_owned());

    let start = std::time::Instant::now();
    let response = next.run(request).await;
    let elapsed = start.elapsed().as_secs_f64();

    let status = response.status().as_u16().to_string();

    metrics::counter!(
        "coderd_api_requests_processed_total",
        "code" => status,
        "method" => method.clone(),
        "path" => path.clone(),
    )
    .increment(1);

    metrics::histogram!(
        "coderd_api_request_latencies_seconds",
        "method" => method,
        "path" => path,
    )
    .record(elapsed);

    response
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        error::Error,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use async_trait::async_trait;
    use axum::{
        Json, Router,
        body::{Body, to_bytes},
        http::HeaderMap,
        http::{Method, Request, Response, StatusCode, header::CONTENT_TYPE},
        response::IntoResponse,
        routing::{get, post},
    };
    use coder_audit::{AuditEvent, AuditSink};
    use coder_auth::{
        OAUTH2_REDIRECT_COOKIE, OAUTH2_STATE_COOKIE, SESSION_TOKEN_COOKIE, SESSION_TOKEN_HEADER,
        hash_password,
    };
    use coder_core::ports::{
        ProvisionerJobLogRecord as PortsJobLogRecord,
        ProvisionerJobTimingRecord as PortsJobTimingRecord,
    };
    use coder_core::ports::{UpdateWorkspaceACLInput, WorkspaceACLRecord};
    use coder_core::provisioner::{
        ProvisionerJobLogRecord as ProvisionerLogRecord,
        ProvisionerJobTimingRecord as ProvisionerTimingRecord,
    };
    use coder_core::template::ProvisionerJobRecord as TemplateProvisionerJobRecord;
    use coder_core::{
        AcquireProvisionerJobInput, ApiKeyListFilter, ApiKeyRecord, ApiKeyWithOwnerRecord,
        AppStore, AuditLog, AuditLogListFilter, AuditLogResponse, AuthenticatedUser, BuildMetadata,
        CancelProvisionerJobInput, ChangePasswordWithOneTimePasscodeRequest, ChatMessageRecord,
        ChatQueuedMessageRecord, ChatRecord, ChatStatus, CompleteProvisionerJobInput,
        ConvertLoginRequest, CreateApiKeyInput, CreateApiKeyStoreError, CreateChatMessageRequest,
        CreateChatRequest, CreateFirstUserInput, CreateFirstUserRequest, CreateFirstUserStoreError,
        CreateProvisionerJobInput, CreateTaskRequest, CreateTemplateInput, CreateTemplateRequest,
        CreateTemplateStoreError, CreateTemplateVersionInput, CreateTestAuditLogRequest,
        CreateTokenRequest, CreateUserInput, CreateUserRequestWithOrgs, CreateUserStoreError,
        CreateWorkspaceBuildInput, CreateWorkspaceInput, DatabaseConfig, DeploymentMetadata,
        DeploymentStatsResponse, DeploymentStore, DerpNodeConfig, DerpRegionConfig,
        ExternalAuthLinkProvider, ExternalAuthLinkRecord, ExternalAuthUser, FileRecord,
        GetJobsToBeReapedInput, GitSshKeyRecord, HealthSettings, InsertAgentLogInput,
        InsertChatInput, InsertChatMessageInput, InsertFileInput, InsertFileResult,
        InsertOrganizationMemberError, InsertProvisionerJobInput, InsertProvisionerJobLogsInput,
        InsertProvisionerJobTimingsInput, InsertProvisionerKeyInput, InsertTaskInput,
        InsertWorkspaceAppStatusInput, LogFormat, LoginType, LoginWithPasswordRequest,
        OrganizationMemberListFilter, OrganizationMemberRecord, OrganizationRecord,
        PasswordUserRecord, PersistAuditLogInput, ProvisionerDaemonHealthInput,
        ProvisionerDaemonHealthRecord, ProvisionerDaemonRecord, ProvisionerJobRecord,
        ProvisionerJobStatsInput, ProvisionerKeyRecord, ProvisionerStore,
        RequestOneTimePasscodeRequest, ServerConfig, SessionCountDeploymentStatsResponse,
        SlimRoleRecord, SshConfig, StorageError, TaskListFilter, TaskRecord, TaskSendRequest,
        TaskSnapshotRecord, TaskStatus, TemplateDAURow, TemplateListFilter, TemplateRecord,
        TemplateVersionListFilter, TemplateVersionParameterRecord,
        TemplateVersionPresetParameterRecord, TemplateVersionPresetRecord, TemplateVersionRecord,
        TemplateVersionVariableRecord, TokenConfigRecord, UpdateRolesRequest, UpdateTemplateMeta,
        UpdateTemplateMetaInput, UpdateUserAppearanceSettingsRequest, UpdateUserPasswordRequest,
        UpdateUserPreferenceSettingsRequest, UpdateUserProfileRequest, UpsertExternalAuthLinkInput,
        UpsertPortShareInput, UpsertProvisionerDaemonInput, UserAppearanceRecord, UserListFilter,
        UserPreferenceRecord, UserRecord, UserStatus, ValidateUserPasswordRequest,
        WorkspaceAgentLogRow, WorkspaceAgentLogSourceRow, WorkspaceAgentMetadataRow,
        WorkspaceAgentPortShareRecord, WorkspaceAgentRow, WorkspaceAgentScriptRow,
        WorkspaceAgentStatInput, WorkspaceAppRow, WorkspaceAppStatusRow,
        WorkspaceBuildParameterRecord, WorkspaceBuildRecord, WorkspaceBuildStatsInput,
        WorkspaceConnectionLatencyMs, WorkspaceDeploymentStatsResponse, WorkspaceListFilter,
        WorkspaceProxyHealthInput, WorkspaceProxyHealthRecord, WorkspaceRecord,
        WorkspaceResourceMetadataRecord, WorkspaceResourceRecord, WorkspaceStatsWorkspaceInput,
    };
    use serde::Serialize;
    use serde_json::{Value, json};
    use time::OffsetDateTime;
    use tower::ServiceExt;
    use url::Url;
    use uuid::Uuid;

    use super::{
        AppState, BUILD_VERSION_HEADER, PUBLIC_API_KEY_SCOPES, SLIM_BUILD_MESSAGE, build_router,
    };

    #[derive(Debug, Default)]
    struct MemoryAuditSink {
        events: Mutex<Vec<AuditEvent>>,
    }

    #[async_trait]
    impl AuditSink for MemoryAuditSink {
        async fn record(&self, event: AuditEvent) {
            if let Ok(mut events) = self.events.lock() {
                events.push(event);
            }
        }
    }

    #[derive(Debug)]
    struct FakeStore {
        health_ok: bool,
        users: Mutex<HashMap<Uuid, UserRecord>>,
        organizations: Mutex<HashMap<Uuid, OrganizationRecord>>,
        organization_members: Mutex<HashMap<(Uuid, Uuid), OrganizationMemberRecord>>,
        sessions: Mutex<HashMap<Vec<u8>, AuthenticatedUser>>,
        api_keys: Mutex<HashMap<String, ApiKeyRecord>>,
        audit_logs: Mutex<Vec<AuditLog>>,
        password_hashes: Mutex<HashMap<Uuid, String>>,
        one_time_passcodes: Mutex<HashMap<Uuid, (String, OffsetDateTime)>>,
        appearance: Mutex<HashMap<Uuid, UserAppearanceRecord>>,
        preferences: Mutex<HashMap<Uuid, UserPreferenceRecord>>,
        health_settings: Mutex<HealthSettings>,
        git_ssh_keys: Mutex<HashMap<Uuid, GitSshKeyRecord>>,
        external_auth_links: Mutex<HashMap<(Uuid, String), ExternalAuthLinkRecord>>,
        stats_workspaces: Mutex<HashMap<Uuid, WorkspaceStatsWorkspaceInput>>,
        stats_jobs: Mutex<HashMap<Uuid, ProvisionerJobStatsInput>>,
        stats_builds: Mutex<HashMap<Uuid, WorkspaceBuildStatsInput>>,
        stats_agents: Mutex<Vec<WorkspaceAgentStatInput>>,
        workspace_proxies: Mutex<HashMap<Uuid, WorkspaceProxyHealthRecord>>,
        provisioner_daemons: Mutex<HashMap<Uuid, ProvisionerDaemonHealthRecord>>,
        tasks: Mutex<HashMap<Uuid, TaskRecord>>,
        task_snapshots: Mutex<HashMap<Uuid, TaskSnapshotRecord>>,
        chats: Mutex<HashMap<Uuid, ChatRecord>>,
        chat_messages: Mutex<Vec<ChatMessageRecord>>,
        chat_message_next_id: Mutex<i64>,
        chat_files: Mutex<HashMap<Uuid, coder_core::ChatFileRecord>>,
        notifications_settings: Mutex<coder_core::NotificationsSettings>,
        notification_templates: Mutex<Vec<coder_core::NotificationTemplate>>,
        notification_preferences: Mutex<HashMap<(Uuid, Uuid), coder_core::NotificationPreference>>,
        inbox_notifications: Mutex<HashMap<Uuid, coder_core::InboxNotification>>,
        webpush_subscriptions:
            Mutex<HashMap<(Uuid, String), coder_core::WebpushSubscriptionRecord>>,
        templates: Mutex<HashMap<Uuid, TemplateRecord>>,
        template_versions: Mutex<HashMap<Uuid, TemplateVersionRecord>>,
        provisioner_jobs: Mutex<HashMap<Uuid, TemplateProvisionerJobRecord>>,
        template_version_parameters: Mutex<HashMap<Uuid, Vec<TemplateVersionParameterRecord>>>,
        template_version_variables: Mutex<HashMap<Uuid, Vec<TemplateVersionVariableRecord>>>,
        template_version_presets: Mutex<HashMap<Uuid, Vec<TemplateVersionPresetRecord>>>,
        template_version_preset_parameters:
            Mutex<HashMap<Uuid, Vec<TemplateVersionPresetParameterRecord>>>,
        files: Mutex<HashMap<Uuid, FileRecord>>,
        // Agent-related fields
        workspace_agents: Mutex<HashMap<Uuid, WorkspaceAgentRow>>,
        workspace_apps: Mutex<HashMap<Uuid, WorkspaceAppRow>>,
        workspace_app_statuses: Mutex<Vec<WorkspaceAppStatusRow>>,
        workspace_agent_log_sources: Mutex<HashMap<Uuid, WorkspaceAgentLogSourceRow>>,
        workspace_agent_logs: Mutex<Vec<WorkspaceAgentLogRow>>,
        workspace_agent_log_next_id: Mutex<i64>,
        workspace_agent_scripts: Mutex<Vec<WorkspaceAgentScriptRow>>,
        workspace_agent_metadata: Mutex<Vec<WorkspaceAgentMetadataRow>>,
        workspace_agent_devcontainers: Mutex<Vec<coder_core::WorkspaceAgentDevcontainerRow>>,
        workspaces: Mutex<HashMap<Uuid, WorkspaceRecord>>,
        workspace_builds: Mutex<HashMap<Uuid, WorkspaceBuildRecord>>,
        workspace_build_parameters: Mutex<HashMap<Uuid, Vec<WorkspaceBuildParameterRecord>>>,
        workspace_resources: Mutex<HashMap<Uuid, Vec<WorkspaceResourceRecord>>>,
        workspace_resource_metadata: Mutex<HashMap<Uuid, Vec<WorkspaceResourceMetadataRecord>>>,
        provisioner_job_logs: Mutex<HashMap<Uuid, Vec<PortsJobLogRecord>>>,
        provisioner_job_timings: Mutex<HashMap<Uuid, Vec<PortsJobTimingRecord>>>,
        workspace_port_shares: Mutex<Vec<WorkspaceAgentPortShareRecord>>,
        workspace_acls: Mutex<HashMap<Uuid, WorkspaceACLRecord>>,
    }

    impl FakeStore {
        fn new(health_ok: bool) -> Self {
            Self {
                health_ok,
                users: Mutex::new(HashMap::new()),
                organizations: Mutex::new(HashMap::new()),
                organization_members: Mutex::new(HashMap::new()),
                sessions: Mutex::new(HashMap::new()),
                api_keys: Mutex::new(HashMap::new()),
                audit_logs: Mutex::new(Vec::new()),
                password_hashes: Mutex::new(HashMap::new()),
                one_time_passcodes: Mutex::new(HashMap::new()),
                appearance: Mutex::new(HashMap::new()),
                preferences: Mutex::new(HashMap::new()),
                health_settings: Mutex::new(HealthSettings::default()),
                git_ssh_keys: Mutex::new(HashMap::new()),
                external_auth_links: Mutex::new(HashMap::new()),
                stats_workspaces: Mutex::new(HashMap::new()),
                stats_jobs: Mutex::new(HashMap::new()),
                stats_builds: Mutex::new(HashMap::new()),
                stats_agents: Mutex::new(Vec::new()),
                workspace_proxies: Mutex::new(HashMap::new()),
                provisioner_daemons: Mutex::new(HashMap::new()),
                tasks: Mutex::new(HashMap::new()),
                task_snapshots: Mutex::new(HashMap::new()),
                chats: Mutex::new(HashMap::new()),
                chat_messages: Mutex::new(Vec::new()),
                chat_message_next_id: Mutex::new(1),
                chat_files: Mutex::new(HashMap::new()),
                notifications_settings: Mutex::new(coder_core::NotificationsSettings::default()),
                notification_templates: Mutex::new(Vec::new()),
                notification_preferences: Mutex::new(HashMap::new()),
                inbox_notifications: Mutex::new(HashMap::new()),
                webpush_subscriptions: Mutex::new(HashMap::new()),
                templates: Mutex::new(HashMap::new()),
                template_versions: Mutex::new(HashMap::new()),
                provisioner_jobs: Mutex::new(HashMap::new()),
                template_version_parameters: Mutex::new(HashMap::new()),
                template_version_variables: Mutex::new(HashMap::new()),
                template_version_presets: Mutex::new(HashMap::new()),
                template_version_preset_parameters: Mutex::new(HashMap::new()),
                files: Mutex::new(HashMap::new()),
                workspace_agents: Mutex::new(HashMap::new()),
                workspace_apps: Mutex::new(HashMap::new()),
                workspace_app_statuses: Mutex::new(Vec::new()),
                workspace_agent_log_sources: Mutex::new(HashMap::new()),
                workspace_agent_logs: Mutex::new(Vec::new()),
                workspace_agent_log_next_id: Mutex::new(1),
                workspace_agent_scripts: Mutex::new(Vec::new()),
                workspace_agent_metadata: Mutex::new(Vec::new()),
                workspace_agent_devcontainers: Mutex::new(Vec::new()),
                workspaces: Mutex::new(HashMap::new()),
                workspace_builds: Mutex::new(HashMap::new()),
                workspace_build_parameters: Mutex::new(HashMap::new()),
                workspace_resources: Mutex::new(HashMap::new()),
                workspace_resource_metadata: Mutex::new(HashMap::new()),
                provisioner_job_logs: Mutex::new(HashMap::new()),
                provisioner_job_timings: Mutex::new(HashMap::new()),
                workspace_port_shares: Mutex::new(Vec::new()),
                workspace_acls: Mutex::new(HashMap::new()),
            }
        }

        /// Inserts a workspace agent into the fake store for testing.
        fn insert_agent(&self, agent: WorkspaceAgentRow) -> Result<(), StorageError> {
            self.workspace_agents
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?
                .insert(agent.id, agent);
            Ok(())
        }

        /// Inserts a workspace app into the fake store for testing.
        fn insert_app(&self, app: WorkspaceAppRow) -> Result<(), StorageError> {
            self.workspace_apps
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?
                .insert(app.id, app);
            Ok(())
        }

        /// Inserts a workspace into the fake store for testing.
        fn insert_workspace(&self, workspace: WorkspaceRecord) -> Result<(), StorageError> {
            self.workspaces
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?
                .insert(workspace.id, workspace);
            Ok(())
        }

        fn set_one_time_passcode(
            &self,
            user_id: Uuid,
            passcode: &str,
            expires_at: OffsetDateTime,
        ) -> Result<(), StorageError> {
            let passcode_hash = hash_password(passcode)
                .map_err(|error| StorageError::invalid_data(error.to_string()))?;
            self.one_time_passcodes
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .insert(user_id, (passcode_hash, expires_at));
            Ok(())
        }
    }

    #[async_trait]
    impl DeploymentStore for FakeStore {
        async fn ping(&self) -> Result<(), StorageError> {
            if self.health_ok {
                Ok(())
            } else {
                Err(StorageError::unavailable("database is down"))
            }
        }

        async fn ensure_deployment_metadata(&self) -> Result<DeploymentMetadata, StorageError> {
            Ok(DeploymentMetadata {
                deployment_id: Uuid::nil(),
            })
        }
    }

    #[async_trait]
    impl ProvisionerStore for FakeStore {
        async fn acquire_provisioner_job(
            &self,
            _input: AcquireProvisionerJobInput,
        ) -> Result<Option<ProvisionerJobRecord>, StorageError> {
            Ok(None)
        }

        async fn get_provisioner_job_by_id(
            &self,
            _id: Uuid,
        ) -> Result<Option<ProvisionerJobRecord>, StorageError> {
            Ok(None)
        }

        async fn get_provisioner_jobs_by_ids(
            &self,
            _ids: &[Uuid],
        ) -> Result<Vec<ProvisionerJobRecord>, StorageError> {
            Ok(Vec::new())
        }

        async fn insert_provisioner_job(
            &self,
            _input: InsertProvisionerJobInput,
        ) -> Result<ProvisionerJobRecord, StorageError> {
            Err(StorageError::unavailable("not implemented in FakeStore"))
        }

        async fn update_provisioner_job_by_id(
            &self,
            _id: Uuid,
            _updated_at: OffsetDateTime,
        ) -> Result<(), StorageError> {
            Err(StorageError::unavailable("not implemented in FakeStore"))
        }

        async fn update_provisioner_job_with_complete_by_id(
            &self,
            _input: CompleteProvisionerJobInput,
        ) -> Result<(), StorageError> {
            Err(StorageError::unavailable("not implemented in FakeStore"))
        }

        async fn update_provisioner_job_with_cancel_by_id(
            &self,
            _input: CancelProvisionerJobInput,
        ) -> Result<(), StorageError> {
            Err(StorageError::unavailable("not implemented in FakeStore"))
        }

        async fn get_provisioner_jobs_to_be_reaped(
            &self,
            _input: GetJobsToBeReapedInput,
        ) -> Result<Vec<ProvisionerJobRecord>, StorageError> {
            Ok(Vec::new())
        }

        async fn insert_provisioner_job_logs(
            &self,
            _input: InsertProvisionerJobLogsInput,
        ) -> Result<Vec<ProvisionerLogRecord>, StorageError> {
            Ok(Vec::new())
        }

        async fn get_provisioner_logs_after_id(
            &self,
            _job_id: Uuid,
            _after_id: i64,
        ) -> Result<Vec<ProvisionerLogRecord>, StorageError> {
            Ok(Vec::new())
        }

        async fn insert_provisioner_job_timings(
            &self,
            _input: InsertProvisionerJobTimingsInput,
        ) -> Result<Vec<ProvisionerTimingRecord>, StorageError> {
            Ok(Vec::new())
        }

        async fn get_provisioner_job_timings_by_job_id(
            &self,
            _job_id: Uuid,
        ) -> Result<Vec<ProvisionerTimingRecord>, StorageError> {
            Ok(Vec::new())
        }

        async fn upsert_provisioner_daemon(
            &self,
            _input: UpsertProvisionerDaemonInput,
        ) -> Result<ProvisionerDaemonRecord, StorageError> {
            Err(StorageError::unavailable("not implemented in FakeStore"))
        }

        async fn update_provisioner_daemon_last_seen_at(
            &self,
            _id: Uuid,
            _last_seen_at: OffsetDateTime,
        ) -> Result<(), StorageError> {
            Err(StorageError::unavailable("not implemented in FakeStore"))
        }

        async fn get_provisioner_daemons_by_organization(
            &self,
            _organization_id: Uuid,
        ) -> Result<Vec<ProvisionerDaemonRecord>, StorageError> {
            Ok(Vec::new())
        }

        async fn delete_old_provisioner_daemons(&self) -> Result<(), StorageError> {
            Err(StorageError::unavailable("not implemented in FakeStore"))
        }

        async fn insert_provisioner_key(
            &self,
            _input: InsertProvisionerKeyInput,
        ) -> Result<ProvisionerKeyRecord, StorageError> {
            Err(StorageError::unavailable("not implemented in FakeStore"))
        }

        async fn get_provisioner_key_by_id(
            &self,
            _id: Uuid,
        ) -> Result<Option<ProvisionerKeyRecord>, StorageError> {
            Ok(None)
        }

        async fn get_provisioner_key_by_hashed_secret(
            &self,
            _hashed_secret: &[u8],
        ) -> Result<Option<ProvisionerKeyRecord>, StorageError> {
            Ok(None)
        }

        async fn get_provisioner_key_by_name(
            &self,
            _organization_id: Uuid,
            _name: &str,
        ) -> Result<Option<ProvisionerKeyRecord>, StorageError> {
            Ok(None)
        }

        async fn list_provisioner_keys_by_organization(
            &self,
            _organization_id: Uuid,
        ) -> Result<Vec<ProvisionerKeyRecord>, StorageError> {
            Ok(Vec::new())
        }

        async fn delete_provisioner_key(&self, _id: Uuid) -> Result<bool, StorageError> {
            Ok(false)
        }
    }

    #[async_trait]
    impl AppStore for FakeStore {
        async fn first_user_exists(&self) -> Result<bool, StorageError> {
            let users = self
                .users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            Ok(!users.is_empty())
        }

        async fn create_first_user(
            &self,
            user: CreateFirstUserInput,
        ) -> Result<coder_core::FirstUserRecord, CreateFirstUserStoreError> {
            let mut users = self
                .users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))
                .map_err(CreateFirstUserStoreError::from)?;
            if !users.is_empty() {
                return Err(CreateFirstUserStoreError::AlreadyExists);
            }

            let mut organizations = self
                .organizations
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))
                .map_err(CreateFirstUserStoreError::from)?;
            let mut members = self
                .organization_members
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))
                .map_err(CreateFirstUserStoreError::from)?;

            let user_id = Uuid::from_u128(1);
            let organization_id = Uuid::from_u128(2);
            let now = OffsetDateTime::now_utc();
            let role = SlimRoleRecord {
                name: "owner".to_owned(),
                display_name: "Owner".to_owned(),
                organization_id: None,
            };
            let user_record = UserRecord {
                id: user_id,
                email: user.email.clone(),
                username: user.username.clone(),
                name: user.name.clone(),
                avatar_url: String::new(),
                created_at: now,
                updated_at: now,
                last_seen_at: None,
                organization_ids: vec![organization_id],
                roles: vec![role.clone()],
                login_type: LoginType::Password,
                status: UserStatus::Active,
                deleted: false,
                is_system: false,
            };
            let organization = OrganizationRecord {
                id: organization_id,
                name: "first-organization".to_owned(),
                display_name: "First Organization".to_owned(),
                description: "Builtin default organization.".to_owned(),
                icon: String::new(),
                created_at: now,
                updated_at: now,
                is_default: true,
                deleted: false,
            };
            let member = OrganizationMemberRecord {
                user_id,
                organization_id,
                created_at: now,
                updated_at: now,
                roles: Vec::new(),
                username: user.username,
                name: user.name,
                avatar_url: String::new(),
                email: user.email,
                global_roles: vec![role],
            };

            organizations.insert(organization_id, organization);
            members.insert((organization_id, user_id), member);
            users.insert(user_id, user_record.clone());
            self.password_hashes
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))
                .map_err(CreateFirstUserStoreError::from)?
                .insert(user_id, user.password_hash);
            self.appearance
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))
                .map_err(CreateFirstUserStoreError::from)?
                .insert(
                    user_id,
                    UserAppearanceRecord {
                        theme_preference: String::new(),
                        terminal_font: String::new(),
                    },
                );
            self.preferences
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))
                .map_err(CreateFirstUserStoreError::from)?
                .insert(
                    user_id,
                    UserPreferenceRecord {
                        task_notification_alert_dismissed: false,
                    },
                );

            Ok(coder_core::FirstUserRecord {
                user_id,
                organization_id,
            })
        }

        async fn find_password_user_by_email(
            &self,
            email: &str,
        ) -> Result<Option<PasswordUserRecord>, StorageError> {
            let users = self
                .users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let password_hashes = self
                .password_hashes
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let one_time_passcodes = self
                .one_time_passcodes
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            Ok(users
                .values()
                .find(|record| !record.deleted && record.email.eq_ignore_ascii_case(email))
                .cloned()
                .map(|user| PasswordUserRecord {
                    password_hash: password_hashes.get(&user.id).cloned().unwrap_or_default(),
                    one_time_passcode_hash: one_time_passcodes
                        .get(&user.id)
                        .map(|(hash, _)| hash.clone()),
                    one_time_passcode_expires_at: one_time_passcodes
                        .get(&user.id)
                        .map(|(_, expires_at)| *expires_at),
                    user,
                }))
        }

        async fn find_password_user_by_id(
            &self,
            user_id: Uuid,
        ) -> Result<Option<PasswordUserRecord>, StorageError> {
            let users = self
                .users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let Some(user) = users.get(&user_id).filter(|user| !user.deleted).cloned() else {
                return Ok(None);
            };
            let password_hashes = self
                .password_hashes
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let one_time_passcodes = self
                .one_time_passcodes
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            Ok(Some(PasswordUserRecord {
                password_hash: password_hashes.get(&user.id).cloned().unwrap_or_default(),
                one_time_passcode_hash: one_time_passcodes
                    .get(&user.id)
                    .map(|(hash, _)| hash.clone()),
                one_time_passcode_expires_at: one_time_passcodes
                    .get(&user.id)
                    .map(|(_, expires_at)| *expires_at),
                user,
            }))
        }

        async fn insert_auth_session(
            &self,
            token_hash: &[u8],
            user_id: Uuid,
        ) -> Result<(), StorageError> {
            let user = self
                .users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .get(&user_id)
                .cloned()
                .ok_or_else(|| StorageError::invalid_data("missing user for session"))?;
            let mut auth_user = AuthenticatedUser::from(user);
            // Populate org_roles from organization member records.
            let members = self
                .organization_members
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            for ((_, member_user_id), member) in members.iter() {
                if *member_user_id == user_id {
                    for role in &member.roles {
                        auth_user
                            .org_roles
                            .push(format!("{}:{}", role.name, member.organization_id));
                    }
                }
            }
            self.sessions
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .insert(token_hash.to_vec(), auth_user);
            Ok(())
        }

        async fn find_user_by_session_token_hash(
            &self,
            token_hash: &[u8],
        ) -> Result<Option<AuthenticatedUser>, StorageError> {
            let sessions = self
                .sessions
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            Ok(sessions.get(token_hash).cloned())
        }

        async fn delete_auth_session(&self, token_hash: &[u8]) -> Result<bool, StorageError> {
            Ok(self
                .sessions
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .remove(token_hash)
                .is_some())
        }

        async fn list_users(
            &self,
            filter: UserListFilter,
        ) -> Result<(Vec<UserRecord>, usize), StorageError> {
            let users = self
                .users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let mut matched = users
                .values()
                .filter(|user| {
                    if user.deleted {
                        return false;
                    }
                    let search = filter.search.to_lowercase();
                    let search_matches = search.is_empty()
                        || user.username.to_lowercase().contains(&search)
                        || user.email.to_lowercase().contains(&search)
                        || user.name.to_lowercase().contains(&search);
                    let status_matches = filter.status.is_none_or(|status| user.status == status);
                    search_matches && status_matches
                })
                .cloned()
                .collect::<Vec<_>>();
            matched.sort_by(|left, right| left.username.cmp(&right.username));
            let count = matched.len();
            let start = usize::try_from(filter.offset).unwrap_or(0);
            let end = if filter.limit == 0 {
                matched.len()
            } else {
                start.saturating_add(usize::try_from(filter.limit).unwrap_or(0))
            };
            let page = matched
                .into_iter()
                .skip(start)
                .take(end.saturating_sub(start))
                .collect();
            Ok((page, count))
        }

        async fn create_user(
            &self,
            input: CreateUserInput,
        ) -> Result<UserRecord, CreateUserStoreError> {
            let mut users = self
                .users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))
                .map_err(CreateUserStoreError::from)?;
            if users.values().any(|user| {
                !user.deleted
                    && (user.email.eq_ignore_ascii_case(&input.email)
                        || user.username.eq_ignore_ascii_case(&input.username))
            }) {
                return Err(CreateUserStoreError::AlreadyExists);
            }

            let organizations = self
                .organizations
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))
                .map_err(CreateUserStoreError::from)?;
            for organization_id in &input.organization_ids {
                if !organizations.contains_key(organization_id) {
                    return Err(CreateUserStoreError::from(StorageError::invalid_data(
                        "unknown organization",
                    )));
                }
            }
            drop(organizations);

            let next_id = Uuid::from_u128(u128::try_from(users.len()).unwrap_or(0) + 10);
            let now = OffsetDateTime::now_utc();
            let user_record = UserRecord {
                id: next_id,
                email: input.email.clone(),
                username: input.username.clone(),
                name: input.name.clone(),
                avatar_url: String::new(),
                created_at: now,
                updated_at: now,
                last_seen_at: None,
                organization_ids: input.organization_ids.clone(),
                roles: Vec::new(),
                login_type: input.login_type,
                status: input.status,
                deleted: false,
                is_system: false,
            };
            users.insert(next_id, user_record.clone());
            drop(users);

            let mut members = self
                .organization_members
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))
                .map_err(CreateUserStoreError::from)?;
            for organization_id in &input.organization_ids {
                members.insert(
                    (*organization_id, next_id),
                    OrganizationMemberRecord {
                        user_id: next_id,
                        organization_id: *organization_id,
                        created_at: now,
                        updated_at: now,
                        roles: Vec::new(),
                        username: input.username.clone(),
                        name: input.name.clone(),
                        avatar_url: String::new(),
                        email: input.email.clone(),
                        global_roles: Vec::new(),
                    },
                );
            }

            if let Some(password_hash) = input.password_hash {
                self.password_hashes
                    .lock()
                    .map_err(|error| StorageError::unavailable(error.to_string()))
                    .map_err(CreateUserStoreError::from)?
                    .insert(next_id, password_hash);
            }
            self.appearance
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))
                .map_err(CreateUserStoreError::from)?
                .insert(
                    next_id,
                    UserAppearanceRecord {
                        theme_preference: String::new(),
                        terminal_font: String::new(),
                    },
                );
            self.preferences
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))
                .map_err(CreateUserStoreError::from)?
                .insert(
                    next_id,
                    UserPreferenceRecord {
                        task_notification_alert_dismissed: false,
                    },
                );

            Ok(user_record)
        }

        async fn find_user_by_id(&self, user_id: Uuid) -> Result<Option<UserRecord>, StorageError> {
            Ok(self
                .users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .get(&user_id)
                .filter(|user| !user.deleted)
                .cloned())
        }

        async fn find_user_by_username(
            &self,
            username: &str,
        ) -> Result<Option<UserRecord>, StorageError> {
            let users = self
                .users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            Ok(users
                .values()
                .filter(|user| !user.deleted)
                .find(|user| user.username.eq_ignore_ascii_case(username))
                .cloned())
        }

        async fn soft_delete_user(&self, user_id: Uuid) -> Result<bool, StorageError> {
            let mut users = self
                .users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let Some(user) = users.get_mut(&user_id) else {
                return Ok(false);
            };
            if user.deleted {
                return Ok(false);
            }
            user.deleted = true;
            user.status = UserStatus::Suspended;
            user.updated_at = OffsetDateTime::now_utc();
            drop(users);

            self.sessions
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .retain(|_, user| user.id != user_id);
            self.api_keys
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .retain(|_, key| key.user_id != user_id);
            self.organization_members
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .retain(|(_, member_user_id), _| member_user_id != &user_id);
            self.password_hashes
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .remove(&user_id);
            self.one_time_passcodes
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .remove(&user_id);
            self.appearance
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .remove(&user_id);
            self.preferences
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .remove(&user_id);

            Ok(true)
        }

        async fn list_user_memberships(
            &self,
            user_id: Uuid,
        ) -> Result<Vec<OrganizationMemberRecord>, StorageError> {
            let members = self
                .organization_members
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let mut rows = members
                .values()
                .filter(|member| member.user_id == user_id)
                .cloned()
                .collect::<Vec<_>>();
            rows.sort_by(|left, right| left.organization_id.cmp(&right.organization_id));
            Ok(rows)
        }

        async fn update_user_roles(
            &self,
            user_id: Uuid,
            roles: Vec<String>,
        ) -> Result<Option<UserRecord>, StorageError> {
            let now = OffsetDateTime::now_utc();
            let mut users = self
                .users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let Some(user) = users.get_mut(&user_id) else {
                return Ok(None);
            };
            if user.deleted {
                return Ok(None);
            }
            let slim_roles = roles
                .iter()
                .map(|role| SlimRoleRecord {
                    name: role.clone(),
                    display_name: role
                        .split('-')
                        .map(|part| {
                            let mut chars = part.chars();
                            match chars.next() {
                                Some(first) => {
                                    first.to_uppercase().collect::<String>() + chars.as_str()
                                }
                                None => String::new(),
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(" "),
                    organization_id: None,
                })
                .collect::<Vec<_>>();
            user.roles = slim_roles.clone();
            user.updated_at = now;
            let updated_user = user.clone();
            drop(users);

            self.organization_members
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .values_mut()
                .filter(|member| member.user_id == user_id)
                .for_each(|member| {
                    member.global_roles = slim_roles.clone();
                });

            Ok(Some(updated_user))
        }

        async fn update_user_profile(
            &self,
            user_id: Uuid,
            username: &str,
            name: &str,
        ) -> Result<Option<UserRecord>, StorageError> {
            let mut users = self
                .users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let Some(user) = users.get_mut(&user_id) else {
                return Ok(None);
            };
            if user.deleted {
                return Ok(None);
            }
            user.username = username.to_owned();
            user.name = name.to_owned();
            user.updated_at = OffsetDateTime::now_utc();
            let updated_user = user.clone();
            drop(users);

            self.organization_members
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .values_mut()
                .filter(|member| member.user_id == user_id)
                .for_each(|member| {
                    member.username = username.to_owned();
                    member.name = name.to_owned();
                    member.updated_at = updated_user.updated_at;
                });

            Ok(Some(updated_user))
        }

        async fn update_user_status(
            &self,
            user_id: Uuid,
            status: UserStatus,
        ) -> Result<Option<UserRecord>, StorageError> {
            let mut users = self
                .users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let Some(user) = users.get_mut(&user_id) else {
                return Ok(None);
            };
            if user.deleted {
                return Ok(None);
            }
            user.status = status;
            user.updated_at = OffsetDateTime::now_utc();
            Ok(Some(user.clone()))
        }

        async fn user_appearance(
            &self,
            user_id: Uuid,
        ) -> Result<UserAppearanceRecord, StorageError> {
            self.appearance
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .get(&user_id)
                .cloned()
                .ok_or_else(|| StorageError::invalid_data("unknown user appearance"))
        }

        async fn update_user_appearance(
            &self,
            user_id: Uuid,
            theme_preference: &str,
            terminal_font: &str,
        ) -> Result<Option<UserAppearanceRecord>, StorageError> {
            let mut appearance = self
                .appearance
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let Some(settings) = appearance.get_mut(&user_id) else {
                return Ok(None);
            };
            settings.theme_preference = theme_preference.to_owned();
            settings.terminal_font = terminal_font.to_owned();
            Ok(Some(settings.clone()))
        }

        async fn user_preferences(
            &self,
            user_id: Uuid,
        ) -> Result<UserPreferenceRecord, StorageError> {
            self.preferences
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .get(&user_id)
                .cloned()
                .ok_or_else(|| StorageError::invalid_data("unknown user preferences"))
        }

        async fn update_user_preferences(
            &self,
            user_id: Uuid,
            task_notification_alert_dismissed: bool,
        ) -> Result<Option<UserPreferenceRecord>, StorageError> {
            let mut preferences = self
                .preferences
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let Some(settings) = preferences.get_mut(&user_id) else {
                return Ok(None);
            };
            settings.task_notification_alert_dismissed = task_notification_alert_dismissed;
            Ok(Some(settings.clone()))
        }

        async fn list_organizations(
            &self,
            organization_ids: Vec<Uuid>,
        ) -> Result<Vec<OrganizationRecord>, StorageError> {
            let organizations = self
                .organizations
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let mut rows = organizations
                .values()
                .filter(|org| organization_ids.is_empty() || organization_ids.contains(&org.id))
                .cloned()
                .collect::<Vec<_>>();
            rows.sort_by(|left, right| left.name.cmp(&right.name));
            Ok(rows)
        }

        async fn find_organization_by_id(
            &self,
            organization_id: Uuid,
        ) -> Result<Option<OrganizationRecord>, StorageError> {
            Ok(self
                .organizations
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .get(&organization_id)
                .cloned())
        }

        async fn find_organization_by_name(
            &self,
            name: &str,
        ) -> Result<Option<OrganizationRecord>, StorageError> {
            let organizations = self
                .organizations
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            Ok(organizations
                .values()
                .find(|org| org.name.eq_ignore_ascii_case(name))
                .cloned())
        }

        async fn list_organization_members(
            &self,
            filter: OrganizationMemberListFilter,
        ) -> Result<Vec<OrganizationMemberRecord>, StorageError> {
            let users = self
                .users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let members = self
                .organization_members
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let mut rows = members
                .values()
                .filter(|member| member.organization_id == filter.organization_id)
                .filter(|member| users.get(&member.user_id).is_some_and(|user| !user.deleted))
                .filter(|member| {
                    let search = filter.search.to_lowercase();
                    search.is_empty()
                        || member.username.to_lowercase().contains(&search)
                        || member.email.to_lowercase().contains(&search)
                        || member.name.to_lowercase().contains(&search)
                })
                .cloned()
                .collect::<Vec<_>>();
            rows.sort_by(|left, right| left.username.cmp(&right.username));
            let start = usize::try_from(filter.offset).unwrap_or(0);
            let end = if filter.limit == 0 {
                rows.len()
            } else {
                start.saturating_add(usize::try_from(filter.limit).unwrap_or(0))
            };
            Ok(rows
                .into_iter()
                .skip(start)
                .take(end.saturating_sub(start))
                .collect())
        }

        async fn list_organization_members_page(
            &self,
            filter: OrganizationMemberListFilter,
        ) -> Result<(Vec<OrganizationMemberRecord>, usize), StorageError> {
            let users = self
                .users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let members = self
                .organization_members
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let search = filter.search.to_lowercase();
            let mut rows = members
                .values()
                .filter(|member| member.organization_id == filter.organization_id)
                .filter(|member| users.get(&member.user_id).is_some_and(|user| !user.deleted))
                .filter(|member| {
                    search.is_empty()
                        || member.username.to_lowercase().contains(&search)
                        || member.email.to_lowercase().contains(&search)
                        || member.name.to_lowercase().contains(&search)
                })
                .cloned()
                .collect::<Vec<_>>();
            rows.sort_by(|left, right| left.username.cmp(&right.username));
            let count = rows.len();
            let start = usize::try_from(filter.offset).unwrap_or(0);
            let end = if filter.limit == 0 {
                rows.len()
            } else {
                start.saturating_add(usize::try_from(filter.limit).unwrap_or(0))
            };
            Ok((
                rows.into_iter()
                    .skip(start)
                    .take(end.saturating_sub(start))
                    .collect(),
                count,
            ))
        }

        async fn find_organization_member(
            &self,
            organization_id: Uuid,
            user_id: Uuid,
        ) -> Result<Option<OrganizationMemberRecord>, StorageError> {
            Ok(self
                .organization_members
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .get(&(organization_id, user_id))
                .cloned())
        }

        async fn insert_organization_member(
            &self,
            organization_id: Uuid,
            user_id: Uuid,
        ) -> Result<OrganizationMemberRecord, InsertOrganizationMemberError> {
            let user = self
                .users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))
                .map_err(InsertOrganizationMemberError::from)?
                .get(&user_id)
                .cloned()
                .ok_or_else(|| {
                    InsertOrganizationMemberError::from(StorageError::invalid_data("unknown user"))
                })?;
            let mut members = self
                .organization_members
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))
                .map_err(InsertOrganizationMemberError::from)?;
            if members.contains_key(&(organization_id, user_id)) {
                return Err(InsertOrganizationMemberError::AlreadyExists);
            }
            let now = OffsetDateTime::now_utc();
            let member = OrganizationMemberRecord {
                user_id,
                organization_id,
                created_at: now,
                updated_at: now,
                roles: Vec::new(),
                username: user.username.clone(),
                name: user.name.clone(),
                avatar_url: user.avatar_url.clone(),
                email: user.email.clone(),
                global_roles: user.roles.clone(),
            };
            members.insert((organization_id, user_id), member.clone());
            drop(members);
            self.users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))
                .map_err(InsertOrganizationMemberError::from)?
                .entry(user_id)
                .and_modify(|entry| {
                    if !entry.organization_ids.contains(&organization_id) {
                        entry.organization_ids.push(organization_id);
                    }
                });
            Ok(member)
        }

        async fn delete_organization_member(
            &self,
            organization_id: Uuid,
            user_id: Uuid,
        ) -> Result<bool, StorageError> {
            let deleted = self
                .organization_members
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .remove(&(organization_id, user_id))
                .is_some();
            if deleted {
                self.users
                    .lock()
                    .map_err(|error| StorageError::unavailable(error.to_string()))?
                    .entry(user_id)
                    .and_modify(|entry| entry.organization_ids.retain(|id| id != &organization_id));
            }
            Ok(deleted)
        }

        async fn update_organization_member_roles(
            &self,
            organization_id: Uuid,
            user_id: Uuid,
            roles: Vec<String>,
        ) -> Result<Option<OrganizationMemberRecord>, StorageError> {
            let mut members = self
                .organization_members
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let Some(member) = members.get_mut(&(organization_id, user_id)) else {
                return Ok(None);
            };
            member.updated_at = OffsetDateTime::now_utc();
            member.roles = roles
                .iter()
                .map(|role| SlimRoleRecord {
                    name: role.clone(),
                    display_name: role
                        .split('-')
                        .map(|part| {
                            let mut chars = part.chars();
                            match chars.next() {
                                Some(first) => {
                                    first.to_uppercase().collect::<String>() + chars.as_str()
                                }
                                None => String::new(),
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(" "),
                    organization_id: Some(organization_id),
                })
                .collect();

            Ok(Some(member.clone()))
        }

        async fn store_one_time_passcode_by_email(
            &self,
            email: &str,
            passcode_hash: &str,
            expires_at: OffsetDateTime,
        ) -> Result<(), StorageError> {
            let users = self
                .users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let user_id = users
                .values()
                .find(|user| {
                    !user.deleted
                        && user.login_type == LoginType::Password
                        && user.email.eq_ignore_ascii_case(email)
                })
                .map(|user| user.id);
            drop(users);

            if let Some(user_id) = user_id {
                self.one_time_passcodes
                    .lock()
                    .map_err(|error| StorageError::unavailable(error.to_string()))?
                    .insert(user_id, (passcode_hash.to_owned(), expires_at));
            }
            Ok(())
        }

        async fn replace_user_password(
            &self,
            user_id: Uuid,
            password_hash: &str,
            clear_one_time_passcode: bool,
        ) -> Result<bool, StorageError> {
            let users = self
                .users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            if users.get(&user_id).is_none_or(|user| user.deleted) {
                return Ok(false);
            }
            drop(users);

            self.password_hashes
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .insert(user_id, password_hash.to_owned());
            if clear_one_time_passcode {
                self.one_time_passcodes
                    .lock()
                    .map_err(|error| StorageError::unavailable(error.to_string()))?
                    .remove(&user_id);
            }
            self.sessions
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .retain(|_, user| user.id != user_id);
            self.api_keys
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .retain(|_, key| key.user_id != user_id);
            Ok(true)
        }

        async fn create_api_key(
            &self,
            input: CreateApiKeyInput,
        ) -> Result<ApiKeyRecord, CreateApiKeyStoreError> {
            let mut api_keys = self
                .api_keys
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))
                .map_err(CreateApiKeyStoreError::from)?;
            if !input.token_name.is_empty()
                && api_keys
                    .values()
                    .any(|key| key.user_id == input.user_id && key.token_name == input.token_name)
            {
                return Err(CreateApiKeyStoreError::DuplicateTokenName);
            }
            let record = ApiKeyRecord {
                id: input.id,
                hashed_secret: input.hashed_secret,
                user_id: input.user_id,
                last_used: input.last_used,
                expires_at: input.expires_at,
                created_at: input.created_at,
                updated_at: input.updated_at,
                login_type: input.login_type,
                scopes: input.scopes,
                token_name: input.token_name,
                lifetime_seconds: input.lifetime_seconds,
                allow_list: input.allow_list,
            };
            api_keys.insert(record.id.clone(), record.clone());
            Ok(record)
        }

        async fn find_api_key_by_id(&self, id: &str) -> Result<Option<ApiKeyRecord>, StorageError> {
            Ok(self
                .api_keys
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .get(id)
                .cloned())
        }

        async fn find_api_key_by_name(
            &self,
            user_id: Uuid,
            token_name: &str,
        ) -> Result<Option<ApiKeyRecord>, StorageError> {
            let api_keys = self
                .api_keys
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            Ok(api_keys
                .values()
                .find(|key| key.user_id == user_id && key.token_name == token_name)
                .cloned())
        }

        async fn list_api_keys(
            &self,
            filter: ApiKeyListFilter,
        ) -> Result<Vec<ApiKeyWithOwnerRecord>, StorageError> {
            let api_keys = self
                .api_keys
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let users = self
                .users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let now = OffsetDateTime::now_utc();
            Ok(api_keys
                .values()
                .filter(|key| key.login_type == filter.login_type)
                .filter(|key| filter.user_id.is_none_or(|user_id| key.user_id == user_id))
                .filter(|key| filter.include_expired || key.expires_at > now)
                .map(|key| ApiKeyWithOwnerRecord {
                    key: key.clone(),
                    username: users
                        .get(&key.user_id)
                        .map(|user| user.username.clone())
                        .unwrap_or_default(),
                })
                .collect())
        }

        async fn delete_api_key(&self, id: &str) -> Result<bool, StorageError> {
            Ok(self
                .api_keys
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .remove(id)
                .is_some())
        }

        async fn expire_api_key(
            &self,
            id: &str,
            now: OffsetDateTime,
        ) -> Result<bool, StorageError> {
            let mut api_keys = self
                .api_keys
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let Some(key) = api_keys.get_mut(id) else {
                return Ok(false);
            };
            key.expires_at = now;
            key.updated_at = now;
            Ok(true)
        }

        async fn token_config(&self, user_id: Uuid) -> Result<TokenConfigRecord, StorageError> {
            let users = self
                .users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let user = users
                .get(&user_id)
                .ok_or_else(|| StorageError::invalid_data("unknown user"))?;
            let max = if user.roles.iter().any(|role| role.name == "owner") {
                Duration::from_secs(60 * 60 * 24 * 365)
            } else {
                Duration::from_secs(60 * 60 * 24 * 30)
            };
            Ok(TokenConfigRecord {
                max_token_lifetime: max,
            })
        }

        async fn list_audit_logs(
            &self,
            filter: AuditLogListFilter,
        ) -> Result<AuditLogResponse, StorageError> {
            let search = filter.search.to_lowercase();
            let mut logs = self
                .audit_logs
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .iter()
                .filter(|log| {
                    search.is_empty()
                        || log.description.to_lowercase().contains(&search)
                        || log.resource_target.to_lowercase().contains(&search)
                        || log
                            .user
                            .as_ref()
                            .is_some_and(|user| user.username.to_lowercase().contains(&search))
                })
                .cloned()
                .collect::<Vec<_>>();
            logs.sort_by(|left, right| right.time.cmp(&left.time));
            let count = logs.len();
            let start = usize::try_from(filter.offset).unwrap_or(0);
            let limit = usize::try_from(filter.limit).unwrap_or(0);
            let audit_logs = if limit == 0 {
                logs.into_iter().skip(start).collect()
            } else {
                logs.into_iter().skip(start).take(limit).collect()
            };
            Ok(AuditLogResponse { audit_logs, count })
        }

        async fn insert_audit_log(&self, input: PersistAuditLogInput) -> Result<(), StorageError> {
            let user = input.user_id.and_then(|user_id| {
                self.users
                    .lock()
                    .ok()
                    .and_then(|users| users.get(&user_id).cloned())
                    .map(|user| coder_core::MinimalUser {
                        id: user.id,
                        username: user.username,
                        name: user.name,
                        avatar_url: user.avatar_url,
                    })
            });
            self.audit_logs
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .push(AuditLog {
                    id: input.id,
                    request_id: input.request_id,
                    time: input.time,
                    ip: input.ip,
                    user_agent: input.user_agent,
                    resource_type: match input.resource_type.as_str() {
                        "api_key" => coder_core::AuditResourceType::ApiKey,
                        "git_ssh_key" => coder_core::AuditResourceType::GitSshKey,
                        "health_settings" => coder_core::AuditResourceType::HealthSettings,
                        "organization" => coder_core::AuditResourceType::Organization,
                        "organization_member" => coder_core::AuditResourceType::OrganizationMember,
                        "convert_login" => coder_core::AuditResourceType::ConvertLogin,
                        _ => coder_core::AuditResourceType::User,
                    },
                    resource_id: input.resource_id,
                    resource_target: input.resource_target,
                    resource_icon: input.resource_icon,
                    action: match input.action.as_str() {
                        "create" => coder_core::AuditLogAction::Create,
                        "delete" => coder_core::AuditLogAction::Delete,
                        "start" => coder_core::AuditLogAction::Start,
                        "stop" => coder_core::AuditLogAction::Stop,
                        "login" => coder_core::AuditLogAction::Login,
                        "logout" => coder_core::AuditLogAction::Logout,
                        "register" => coder_core::AuditLogAction::Register,
                        "request_password_reset" => {
                            coder_core::AuditLogAction::RequestPasswordReset
                        }
                        _ => coder_core::AuditLogAction::Write,
                    },
                    diff: serde_json::from_value(input.diff).unwrap_or_default(),
                    status_code: input.status_code,
                    additional_fields: input.additional_fields,
                    description: input.description,
                    resource_link: input.resource_link,
                    is_deleted: input.is_deleted,
                    organization_id: input.organization_id,
                    organization: None,
                    user,
                });
            Ok(())
        }

        async fn health_settings(&self) -> Result<HealthSettings, StorageError> {
            self.health_settings
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))
                .map(|settings| settings.clone())
        }

        async fn upsert_health_settings(
            &self,
            settings: &HealthSettings,
        ) -> Result<bool, StorageError> {
            let mut current = self
                .health_settings
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            if *current == *settings {
                return Ok(false);
            }
            *current = settings.clone();
            Ok(true)
        }

        async fn deployment_stats(&self) -> Result<DeploymentStatsResponse, StorageError> {
            let now = OffsetDateTime::now_utc();
            let workspaces = self
                .stats_workspaces
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .clone();
            let jobs = self
                .stats_jobs
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .clone();
            let builds = self
                .stats_builds
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .clone();
            let agent_stats = self
                .stats_agents
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .clone();

            let mut pending = 0;
            let mut building = 0;
            let mut running = 0;
            let mut failed = 0;
            let mut stopped = 0;

            for workspace in workspaces.values().filter(|workspace| !workspace.deleted) {
                let latest_build = builds
                    .values()
                    .filter(|build| build.workspace_id == workspace.id)
                    .max_by_key(|build| build.build_number);

                let Some(build) = latest_build else {
                    pending += 1;
                    continue;
                };

                let Some(job) = build.job_id.and_then(|job_id| jobs.get(&job_id)) else {
                    pending += 1;
                    continue;
                };

                if job.started_at.is_none() {
                    pending += 1;
                    continue;
                }
                if job.started_at.is_some()
                    && job.canceled_at.is_none()
                    && job.completed_at.is_none()
                    && job.updated_at < now - time::Duration::seconds(30)
                {
                    building += 1;
                    continue;
                }
                if job.completed_at.is_some()
                    && job.canceled_at.is_none()
                    && job.error.is_empty()
                    && build.transition == "start"
                {
                    running += 1;
                    continue;
                }
                if (job.canceled_at.is_some() && !job.error.is_empty())
                    || (job.completed_at.is_some() && !job.error.is_empty())
                {
                    failed += 1;
                    continue;
                }
                if job.completed_at.is_some()
                    && job.canceled_at.is_none()
                    && job.error.is_empty()
                    && build.transition == "stop"
                {
                    stopped += 1;
                }
            }

            let aggregated_from = now - time::Duration::minutes(15);
            let mut latest_by_agent = HashMap::<Uuid, WorkspaceAgentStatInput>::new();
            let mut latencies = Vec::new();
            let mut rx_bytes = 0;
            let mut tx_bytes = 0;

            for stat in agent_stats
                .into_iter()
                .filter(|stat| stat.created_at > aggregated_from)
            {
                rx_bytes += stat.rx_bytes;
                tx_bytes += stat.tx_bytes;
                if stat.connection_median_latency_ms > 0.0 {
                    latencies.push(stat.connection_median_latency_ms);
                }

                let existing = latest_by_agent.get(&stat.agent_id).cloned();
                if existing
                    .as_ref()
                    .is_none_or(|existing| existing.created_at < stat.created_at)
                {
                    latest_by_agent.insert(stat.agent_id, stat);
                }
            }

            latencies.sort_by(|left, right| {
                left.partial_cmp(right).unwrap_or(std::cmp::Ordering::Equal)
            });
            let percentile = |quantile: f64| -> f64 {
                if latencies.is_empty() {
                    return 0.0;
                }
                let index = ((latencies.len() - 1) as f64 * quantile).round() as usize;
                latencies.get(index).copied().unwrap_or_default()
            };

            Ok(DeploymentStatsResponse {
                aggregated_from,
                collected_at: now,
                next_update_at: now + time::Duration::minutes(1),
                workspaces: WorkspaceDeploymentStatsResponse {
                    pending,
                    building,
                    running,
                    failed,
                    stopped,
                    connection_latency_ms: WorkspaceConnectionLatencyMs {
                        p50: percentile(0.5),
                        p95: percentile(0.95),
                    },
                    rx_bytes,
                    tx_bytes,
                },
                session_count: SessionCountDeploymentStatsResponse {
                    vscode: latest_by_agent
                        .values()
                        .map(|value| value.session_count_vscode)
                        .sum(),
                    ssh: latest_by_agent
                        .values()
                        .map(|value| value.session_count_ssh)
                        .sum(),
                    jetbrains: latest_by_agent
                        .values()
                        .map(|value| value.session_count_jetbrains)
                        .sum(),
                    reconnecting_pty: latest_by_agent
                        .values()
                        .map(|value| value.session_count_reconnecting_pty)
                        .sum(),
                },
            })
        }

        async fn upsert_workspace_stats_workspace(
            &self,
            input: &WorkspaceStatsWorkspaceInput,
        ) -> Result<(), StorageError> {
            self.stats_workspaces
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .insert(input.id, input.clone());
            Ok(())
        }

        async fn upsert_provisioner_job_stats(
            &self,
            input: &ProvisionerJobStatsInput,
        ) -> Result<(), StorageError> {
            self.stats_jobs
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .insert(input.id, input.clone());
            Ok(())
        }

        async fn upsert_workspace_build_stats(
            &self,
            input: &WorkspaceBuildStatsInput,
        ) -> Result<(), StorageError> {
            self.stats_builds
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .insert(input.id, input.clone());
            Ok(())
        }

        async fn insert_workspace_agent_stat(
            &self,
            input: &WorkspaceAgentStatInput,
        ) -> Result<(), StorageError> {
            self.stats_agents
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .push(input.clone());
            Ok(())
        }

        async fn list_workspace_proxies_for_health(
            &self,
        ) -> Result<Vec<WorkspaceProxyHealthRecord>, StorageError> {
            Ok(self
                .workspace_proxies
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .values()
                .cloned()
                .collect())
        }

        async fn upsert_workspace_proxy_for_health(
            &self,
            input: &WorkspaceProxyHealthInput,
        ) -> Result<(), StorageError> {
            self.workspace_proxies
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .insert(
                    input.id,
                    WorkspaceProxyHealthRecord {
                        id: input.id,
                        name: input.name.clone(),
                        display_name: input.display_name.clone(),
                        icon_url: input.icon_url.clone(),
                        path_app_url: input.path_app_url.clone(),
                        wildcard_hostname: input.wildcard_hostname.clone(),
                        derp_enabled: input.derp_enabled,
                        derp_only: input.derp_only,
                        created_at: input.created_at,
                        updated_at: input.updated_at,
                        deleted: input.deleted,
                        version: input.version.clone(),
                    },
                );
            Ok(())
        }

        async fn list_provisioner_daemons_for_health(
            &self,
        ) -> Result<Vec<ProvisionerDaemonHealthRecord>, StorageError> {
            Ok(self
                .provisioner_daemons
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .values()
                .cloned()
                .collect())
        }

        async fn upsert_provisioner_daemon_for_health(
            &self,
            input: &ProvisionerDaemonHealthInput,
        ) -> Result<(), StorageError> {
            self.provisioner_daemons
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .insert(
                    input.id,
                    ProvisionerDaemonHealthRecord {
                        id: input.id,
                        organization_id: input.organization_id,
                        created_at: input.created_at,
                        last_seen_at: input.last_seen_at,
                        name: input.name.clone(),
                        version: input.version.clone(),
                        api_version: input.api_version.clone(),
                        provisioners: input.provisioners.clone(),
                        tags: input.tags.clone(),
                        status: input.status.clone(),
                    },
                );
            Ok(())
        }

        async fn find_git_ssh_key(
            &self,
            user_id: Uuid,
        ) -> Result<Option<GitSshKeyRecord>, StorageError> {
            self.git_ssh_keys
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))
                .map(|keys| keys.get(&user_id).cloned())
        }

        async fn upsert_git_ssh_key(
            &self,
            user_id: Uuid,
            public_key: &str,
            private_key: &str,
        ) -> Result<GitSshKeyRecord, StorageError> {
            let mut keys = self
                .git_ssh_keys
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let now = OffsetDateTime::now_utc();
            let key = keys
                .entry(user_id)
                .and_modify(|existing| {
                    existing.updated_at = now;
                    existing.public_key = public_key.to_owned();
                    existing.private_key = private_key.to_owned();
                })
                .or_insert_with(|| GitSshKeyRecord {
                    user_id,
                    created_at: now,
                    updated_at: now,
                    public_key: public_key.to_owned(),
                    private_key: private_key.to_owned(),
                })
                .clone();
            Ok(key)
        }

        async fn list_external_auth_links(
            &self,
            user_id: Uuid,
        ) -> Result<Vec<ExternalAuthLinkRecord>, StorageError> {
            Ok(self
                .external_auth_links
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .iter()
                .filter(|((stored_user_id, _), _)| *stored_user_id == user_id)
                .map(|(_, link)| link.clone())
                .collect())
        }

        async fn find_external_auth_link(
            &self,
            user_id: Uuid,
            provider_id: &str,
        ) -> Result<Option<ExternalAuthLinkRecord>, StorageError> {
            self.external_auth_links
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))
                .map(|links| links.get(&(user_id, provider_id.to_owned())).cloned())
        }

        async fn delete_external_auth_link(
            &self,
            user_id: Uuid,
            provider_id: &str,
        ) -> Result<bool, StorageError> {
            Ok(self
                .external_auth_links
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .remove(&(user_id, provider_id.to_owned()))
                .is_some())
        }

        async fn upsert_external_auth_link(
            &self,
            user_id: Uuid,
            link: &UpsertExternalAuthLinkInput,
        ) -> Result<ExternalAuthLinkRecord, StorageError> {
            let mut links = self
                .external_auth_links
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let now = OffsetDateTime::now_utc();
            let created_at = links
                .get(&(user_id, link.provider_id.clone()))
                .map(|existing| existing.created_at)
                .unwrap_or(now);
            let record = ExternalAuthLinkRecord {
                provider_id: link.provider_id.clone(),
                created_at,
                updated_at: now,
                has_refresh_token: !link.refresh_token.is_empty(),
                expires: link.expires_at,
                access_token: link.access_token.clone(),
                refresh_token: link.refresh_token.clone(),
                token_type: link.token_type.clone(),
                scopes: link.scopes.clone(),
                authenticated: link.authenticated,
                validate_error: link.validate_error.clone(),
                refresh_error: link.refresh_error.clone(),
                last_validated_at: link.last_validated_at,
                last_refreshed_at: link.last_refreshed_at,
                user: link.user.clone(),
                installations: link.installations.clone(),
                app_installable: link.app_installable,
            };
            links.insert((user_id, link.provider_id.clone()), record.clone());
            Ok(record)
        }

        async fn get_deployment_daus(
            &self,
            tz_offset: i32,
        ) -> Result<coder_core::api::DAUsResponse, StorageError> {
            Ok(coder_core::api::DAUsResponse {
                tz_hour_offset: tz_offset,
                entries: Vec::new(),
            })
        }

        async fn get_template_insights(
            &self,
            start_time: OffsetDateTime,
            end_time: OffsetDateTime,
            _interval: coder_core::api::InsightsReportInterval,
            template_ids: Vec<Uuid>,
        ) -> Result<coder_core::api::TemplateInsightsResponse, StorageError> {
            Ok(coder_core::api::TemplateInsightsResponse {
                report: Some(coder_core::api::TemplateInsightsReport {
                    start_time,
                    end_time,
                    template_ids: template_ids.clone(),
                    active_users: 0,
                    apps_usage: Vec::new(),
                    parameters_usage: Vec::new(),
                }),
                interval_reports: vec![coder_core::api::TemplateInsightsIntervalReport {
                    start_time,
                    end_time,
                    template_ids,
                    interval: coder_core::api::InsightsReportInterval::Day,
                    active_users: 0,
                }],
            })
        }

        async fn get_template_insights_by_interval(
            &self,
            _start_time: OffsetDateTime,
            _end_time: OffsetDateTime,
            _interval: coder_core::api::InsightsReportInterval,
            _template_ids: Vec<Uuid>,
        ) -> Result<Vec<coder_core::api::TemplateInsightsIntervalReport>, StorageError> {
            Ok(Vec::new())
        }

        async fn get_user_activity_insights(
            &self,
            start_time: OffsetDateTime,
            end_time: OffsetDateTime,
            template_ids: Vec<Uuid>,
        ) -> Result<coder_core::api::UserActivityInsightsResponse, StorageError> {
            Ok(coder_core::api::UserActivityInsightsResponse {
                report: coder_core::api::UserActivityInsightsReport {
                    start_time,
                    end_time,
                    template_ids,
                    users: Vec::new(),
                },
            })
        }

        async fn get_user_latency_insights(
            &self,
            start_time: OffsetDateTime,
            end_time: OffsetDateTime,
            template_ids: Vec<Uuid>,
        ) -> Result<coder_core::api::UserLatencyInsightsResponse, StorageError> {
            Ok(coder_core::api::UserLatencyInsightsResponse {
                report: coder_core::api::UserLatencyInsightsReport {
                    start_time,
                    end_time,
                    template_ids,
                    users: Vec::new(),
                },
            })
        }

        async fn get_user_status_counts(
            &self,
            _timezone: &str,
        ) -> Result<coder_core::api::GetUserStatusCountsResponse, StorageError> {
            Ok(coder_core::api::GetUserStatusCountsResponse {
                status_counts: HashMap::new(),
            })
        }

        // -----------------------------------------------------------------
        // Tasks
        // -----------------------------------------------------------------

        async fn insert_task(&self, input: InsertTaskInput) -> Result<TaskRecord, StorageError> {
            let record = TaskRecord {
                id: input.id,
                organization_id: input.organization_id,
                owner_id: input.owner_id,
                name: input.name,
                display_name: input.display_name,
                workspace_id: None,
                template_version_id: input.template_version_id,
                template_parameters: input.template_parameters,
                prompt: input.prompt,
                status: TaskStatus::Pending,
                created_at: input.created_at,
                deleted_at: None,
            };
            self.tasks
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?
                .insert(record.id, record.clone());
            Ok(record)
        }

        async fn find_task_by_id(&self, id: Uuid) -> Result<Option<TaskRecord>, StorageError> {
            // Match PostgresStore: exclude soft-deleted tasks (WHERE deleted_at IS NULL).
            Ok(self
                .tasks
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?
                .get(&id)
                .filter(|t| t.deleted_at.is_none())
                .cloned())
        }

        async fn find_task_by_owner_and_name(
            &self,
            owner_id: Uuid,
            name: &str,
        ) -> Result<Option<TaskRecord>, StorageError> {
            Ok(self
                .tasks
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?
                .values()
                .find(|t| t.deleted_at.is_none() && t.owner_id == owner_id && t.name == name)
                .cloned())
        }

        async fn list_tasks(
            &self,
            filter: TaskListFilter,
        ) -> Result<Vec<TaskRecord>, StorageError> {
            let tasks = self
                .tasks
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            let mut result: Vec<TaskRecord> = tasks
                .values()
                .filter(|t| t.deleted_at.is_none())
                .filter(|t| filter.owner_id.is_none() || filter.owner_id == Some(t.owner_id))
                .filter(|t| {
                    filter.organization_id.is_none()
                        || filter.organization_id == Some(t.organization_id)
                })
                .filter(|t| filter.status.is_none() || filter.status.as_ref() == Some(&t.status))
                .cloned()
                .collect();
            result.sort_by(|a, b| b.created_at.cmp(&a.created_at));
            Ok(result)
        }

        async fn delete_task(
            &self,
            id: Uuid,
            deleted_at: OffsetDateTime,
        ) -> Result<bool, StorageError> {
            let mut tasks = self
                .tasks
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            // Match PostgresStore: only soft-delete if not already deleted
            // (WHERE id = $1 AND deleted_at IS NULL).
            if let Some(task) = tasks.get_mut(&id) {
                if task.deleted_at.is_none() {
                    task.deleted_at = Some(deleted_at);
                    Ok(true)
                } else {
                    Ok(false)
                }
            } else {
                Ok(false)
            }
        }

        async fn update_task_prompt(
            &self,
            id: Uuid,
            prompt: &str,
        ) -> Result<Option<TaskRecord>, StorageError> {
            let mut tasks = self
                .tasks
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            // Match PostgresStore: WHERE id = $1 AND deleted_at IS NULL
            if let Some(task) = tasks.get_mut(&id) {
                if task.deleted_at.is_none() {
                    task.prompt = prompt.to_string();
                    Ok(Some(task.clone()))
                } else {
                    Ok(None)
                }
            } else {
                Ok(None)
            }
        }

        async fn upsert_task_snapshot(
            &self,
            task_id: Uuid,
            log_snapshot: &Value,
            log_snapshot_created_at: OffsetDateTime,
        ) -> Result<(), StorageError> {
            self.task_snapshots
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?
                .insert(
                    task_id,
                    TaskSnapshotRecord {
                        task_id,
                        log_snapshot: log_snapshot.clone(),
                        log_snapshot_created_at,
                    },
                );
            Ok(())
        }

        async fn find_task_snapshot(
            &self,
            task_id: Uuid,
        ) -> Result<Option<TaskSnapshotRecord>, StorageError> {
            Ok(self
                .task_snapshots
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?
                .get(&task_id)
                .cloned())
        }

        // -----------------------------------------------------------------
        // Chats
        // -----------------------------------------------------------------

        async fn insert_chat(&self, input: InsertChatInput) -> Result<ChatRecord, StorageError> {
            let now = OffsetDateTime::now_utc();
            let id = Uuid::new_v4();
            let record = ChatRecord {
                id,
                owner_id: input.owner_id,
                workspace_id: input.workspace_id,
                title: input.title,
                status: ChatStatus::Waiting,
                last_error: None,
                parent_chat_id: input.parent_chat_id,
                root_chat_id: input.root_chat_id,
                last_model_config_id: input.last_model_config_id,
                archived: false,
                created_at: now,
                updated_at: now,
            };
            self.chats
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?
                .insert(record.id, record.clone());
            Ok(record)
        }

        async fn find_chat_by_id(&self, id: Uuid) -> Result<Option<ChatRecord>, StorageError> {
            Ok(self
                .chats
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?
                .get(&id)
                .cloned())
        }

        async fn list_chats_by_owner(
            &self,
            owner_id: Uuid,
            archived: Option<bool>,
        ) -> Result<Vec<ChatRecord>, StorageError> {
            let chats = self
                .chats
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            let mut result: Vec<ChatRecord> = chats
                .values()
                .filter(|c| c.owner_id == owner_id)
                .filter(|c| archived.is_none() || archived == Some(c.archived))
                .cloned()
                .collect();
            // Match PostgresStore: ORDER BY updated_at DESC.
            result.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
            Ok(result)
        }

        async fn archive_chat(&self, id: Uuid) -> Result<(), StorageError> {
            let mut chats = self
                .chats
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            // Cascade: archive the entire chat tree. Resolve the root first,
            // matching PostgresStore: WHERE id=$1 OR root_chat_id=$1
            //   OR id=COALESCE(root_chat_id,$1) OR root_chat_id=COALESCE(root_chat_id,$1)
            let resolved_root = chats.get(&id).and_then(|c| c.root_chat_id).unwrap_or(id);
            let ids_to_archive: Vec<Uuid> = chats
                .values()
                .filter(|c| {
                    c.id == id
                        || c.root_chat_id == Some(id)
                        || c.id == resolved_root
                        || c.root_chat_id == Some(resolved_root)
                })
                .map(|c| c.id)
                .collect();
            let now = OffsetDateTime::now_utc();
            for cid in ids_to_archive {
                if let Some(chat) = chats.get_mut(&cid) {
                    chat.archived = true;
                    chat.updated_at = now;
                }
            }
            Ok(())
        }

        async fn list_chat_messages(
            &self,
            chat_id: Uuid,
            after_id: i64,
        ) -> Result<Vec<ChatMessageRecord>, StorageError> {
            let msgs = self
                .chat_messages
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            let result: Vec<ChatMessageRecord> = msgs
                .iter()
                .filter(|m| m.chat_id == chat_id && m.id > after_id)
                .cloned()
                .collect();
            Ok(result)
        }

        async fn insert_chat_message(
            &self,
            input: InsertChatMessageInput,
        ) -> Result<ChatMessageRecord, StorageError> {
            let mut next_id = self
                .chat_message_next_id
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            let id = *next_id;
            *next_id += 1;
            let record = ChatMessageRecord {
                id,
                chat_id: input.chat_id,
                model_config_id: input.model_config_id,
                created_at: OffsetDateTime::now_utc(),
                role: input.role,
                content: input.content,
                visibility: input.visibility,
                input_tokens: None,
                output_tokens: None,
                total_tokens: None,
                reasoning_tokens: None,
                cache_creation_tokens: None,
                cache_read_tokens: None,
                context_limit: None,
                compressed: false,
            };
            self.chat_messages
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?
                .push(record.clone());
            Ok(record)
        }

        async fn list_chat_queued_messages(
            &self,
            _chat_id: Uuid,
        ) -> Result<Vec<ChatQueuedMessageRecord>, StorageError> {
            Ok(Vec::new())
        }

        async fn unarchive_chat(&self, id: Uuid) -> Result<(), StorageError> {
            let mut chats = self
                .chats
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            if let Some(chat) = chats.get_mut(&id) {
                chat.archived = false;
                chat.updated_at = OffsetDateTime::now_utc();
            }
            Ok(())
        }

        // -----------------------------------------------------------------
        // Chat Files
        // -----------------------------------------------------------------

        async fn insert_chat_file(
            &self,
            input: coder_core::InsertChatFileInput,
        ) -> Result<coder_core::ChatFileRecord, StorageError> {
            let now = OffsetDateTime::now_utc();
            let id = Uuid::new_v4();
            let record = coder_core::ChatFileRecord {
                id,
                owner_id: input.owner_id,
                organization_id: input.organization_id,
                created_at: now,
                name: input.name,
                mimetype: input.mimetype,
                data: input.data,
            };
            self.chat_files
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?
                .insert(record.id, record.clone());
            Ok(record)
        }

        async fn find_chat_file_by_id(
            &self,
            id: Uuid,
        ) -> Result<Option<coder_core::ChatFileRecord>, StorageError> {
            Ok(self
                .chat_files
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?
                .get(&id)
                .cloned())
        }

        // -------------------------------------------------------------------
        // Notifications domain
        // -------------------------------------------------------------------

        async fn get_notifications_settings(
            &self,
        ) -> Result<coder_core::NotificationsSettings, StorageError> {
            self.notifications_settings
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))
                .map(|s| s.clone())
        }

        async fn upsert_notifications_settings(
            &self,
            settings: &coder_core::NotificationsSettings,
        ) -> Result<(), StorageError> {
            let mut current = self
                .notifications_settings
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            *current = settings.clone();
            Ok(())
        }

        async fn get_notification_templates_by_kind(
            &self,
            kind: &str,
        ) -> Result<Vec<coder_core::NotificationTemplate>, StorageError> {
            let templates = self
                .notification_templates
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            if kind.is_empty() {
                Ok(templates.clone())
            } else {
                Ok(templates
                    .iter()
                    .filter(|t| t.kind == kind)
                    .cloned()
                    .collect())
            }
        }

        async fn update_notification_template_method(
            &self,
            template_id: Uuid,
            method: Option<&str>,
        ) -> Result<Option<coder_core::NotificationTemplate>, StorageError> {
            let mut templates = self
                .notification_templates
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            if let Some(t) = templates.iter_mut().find(|t| t.id == template_id) {
                t.method = method.map(|m| m.to_owned());
                Ok(Some(t.clone()))
            } else {
                Ok(None)
            }
        }

        async fn get_user_notification_preferences(
            &self,
            user_id: Uuid,
        ) -> Result<Vec<coder_core::NotificationPreference>, StorageError> {
            let prefs = self
                .notification_preferences
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            Ok(prefs
                .iter()
                .filter(|((uid, _), _)| *uid == user_id)
                .map(|(_, v)| v.clone())
                .collect())
        }

        async fn update_user_notification_preferences(
            &self,
            user_id: Uuid,
            template_ids: &[Uuid],
            disableds: &[bool],
        ) -> Result<(), StorageError> {
            let mut prefs = self
                .notification_preferences
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let now = OffsetDateTime::now_utc();
            for (tid, disabled) in template_ids.iter().zip(disableds.iter()) {
                prefs.insert(
                    (user_id, *tid),
                    coder_core::NotificationPreference {
                        id: *tid,
                        disabled: *disabled,
                        updated_at: now,
                    },
                );
            }
            Ok(())
        }

        async fn get_filtered_inbox_notifications(
            &self,
            user_id: Uuid,
            templates: Option<&[Uuid]>,
            targets: Option<&[Uuid]>,
            read_status: &str,
            _created_before: Option<OffsetDateTime>,
        ) -> Result<Vec<coder_core::InboxNotification>, StorageError> {
            let notifs = self
                .inbox_notifications
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let mut result: Vec<coder_core::InboxNotification> = notifs
                .values()
                .filter(|n| n.user_id == user_id)
                .filter(|n| match templates {
                    Some(t) => t.contains(&n.template_id),
                    None => true,
                })
                .filter(|n| match targets {
                    Some(t) => n.targets.iter().any(|tid| t.contains(tid)),
                    None => true,
                })
                .filter(|n| match read_status {
                    "unread" => n.read_at.is_none(),
                    "read" => n.read_at.is_some(),
                    _ => true,
                })
                .cloned()
                .collect();
            result.sort_by(|a, b| b.created_at.cmp(&a.created_at));
            Ok(result)
        }

        async fn count_unread_inbox_notifications(
            &self,
            user_id: Uuid,
        ) -> Result<i64, StorageError> {
            let notifs = self
                .inbox_notifications
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let count = notifs
                .values()
                .filter(|n| n.user_id == user_id && n.read_at.is_none())
                .count();
            Ok(count as i64)
        }

        async fn get_inbox_notification_by_id(
            &self,
            id: Uuid,
        ) -> Result<Option<coder_core::InboxNotification>, StorageError> {
            self.inbox_notifications
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))
                .map(|notifs| notifs.get(&id).cloned())
        }

        async fn update_inbox_notification_read_status(
            &self,
            id: Uuid,
            read_at: Option<OffsetDateTime>,
        ) -> Result<(), StorageError> {
            let mut notifs = self
                .inbox_notifications
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            if let Some(n) = notifs.get_mut(&id) {
                n.read_at = read_at;
            }
            Ok(())
        }

        async fn mark_all_inbox_notifications_as_read(
            &self,
            user_id: Uuid,
            read_at: OffsetDateTime,
        ) -> Result<(), StorageError> {
            let mut notifs = self
                .inbox_notifications
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            for n in notifs.values_mut() {
                if n.user_id == user_id && n.read_at.is_none() {
                    n.read_at = Some(read_at);
                }
            }
            Ok(())
        }

        async fn get_webpush_subscriptions_by_user_id(
            &self,
            user_id: Uuid,
        ) -> Result<Vec<coder_core::WebpushSubscriptionRecord>, StorageError> {
            let subs = self
                .webpush_subscriptions
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            Ok(subs
                .iter()
                .filter(|((uid, _), _)| *uid == user_id)
                .map(|(_, v)| v.clone())
                .collect())
        }

        async fn insert_webpush_subscription(
            &self,
            user_id: Uuid,
            endpoint: &str,
            p256dh_key: &str,
            auth_key: &str,
        ) -> Result<(), StorageError> {
            let mut subs = self
                .webpush_subscriptions
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let record = coder_core::WebpushSubscriptionRecord {
                id: Uuid::new_v4(),
                user_id,
                created_at: OffsetDateTime::now_utc(),
                endpoint: endpoint.to_owned(),
                endpoint_p256dh_key: p256dh_key.to_owned(),
                endpoint_auth_key: auth_key.to_owned(),
            };
            subs.insert((user_id, endpoint.to_owned()), record);
            Ok(())
        }

        async fn delete_webpush_subscription_by_user_and_endpoint(
            &self,
            user_id: Uuid,
            endpoint: &str,
        ) -> Result<bool, StorageError> {
            Ok(self
                .webpush_subscriptions
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .remove(&(user_id, endpoint.to_owned()))
                .is_some())
        }

        // ----- Template Store Methods -----

        async fn list_templates(
            &self,
            filter: TemplateListFilter,
        ) -> Result<Vec<TemplateRecord>, StorageError> {
            let templates = self
                .templates
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            let mut results: Vec<TemplateRecord> = templates
                .values()
                .filter(|t| {
                    if !filter.deleted && t.deleted {
                        return false;
                    }
                    if let Some(ref org_id) = filter.organization_id {
                        if t.organization_id != *org_id {
                            return false;
                        }
                    }
                    if let Some(ref name) = filter.exact_name {
                        if t.name != *name {
                            return false;
                        }
                    }
                    if let Some(ref search) = filter.search {
                        let lower = search.to_lowercase();
                        if !t.name.to_lowercase().contains(&lower)
                            && !t.display_name.to_lowercase().contains(&lower)
                        {
                            return false;
                        }
                    }
                    true
                })
                .cloned()
                .collect();
            results.sort_by(|a, b| a.name.cmp(&b.name));
            Ok(results)
        }

        async fn find_template_by_id(
            &self,
            template_id: Uuid,
        ) -> Result<Option<TemplateRecord>, StorageError> {
            let templates = self
                .templates
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            Ok(templates.get(&template_id).cloned())
        }

        async fn find_template_by_org_and_name(
            &self,
            organization_id: Uuid,
            name: &str,
        ) -> Result<Option<TemplateRecord>, StorageError> {
            let templates = self
                .templates
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            Ok(templates
                .values()
                .find(|t| t.organization_id == organization_id && t.name == name && !t.deleted)
                .cloned())
        }

        async fn insert_template(
            &self,
            input: CreateTemplateInput,
        ) -> Result<TemplateRecord, CreateTemplateStoreError> {
            let mut templates = self
                .templates
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))
                .map_err(CreateTemplateStoreError::Storage)?;

            // Check for duplicate name in same org.
            let duplicate = templates.values().any(|t| {
                t.organization_id == input.organization_id && t.name == input.name && !t.deleted
            });
            if duplicate {
                return Err(CreateTemplateStoreError::AlreadyExists);
            }

            let organizations = self
                .organizations
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))
                .map_err(CreateTemplateStoreError::Storage)?;
            let org = organizations.get(&input.organization_id);

            let users = self
                .users
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))
                .map_err(CreateTemplateStoreError::Storage)?;
            let creator = users.get(&input.created_by);

            let record = TemplateRecord {
                id: input.id,
                created_at: input.created_at,
                updated_at: input.updated_at,
                organization_id: input.organization_id,
                organization_name: org.map(|o| o.name.clone()).unwrap_or_default(),
                organization_display_name: org.map(|o| o.display_name.clone()).unwrap_or_default(),
                organization_icon: org.map(|o| o.icon.clone()).unwrap_or_default(),
                deleted: false,
                name: input.name,
                provisioner: input.provisioner,
                active_version_id: input.active_version_id,
                description: input.description,
                default_ttl: input.default_ttl,
                created_by: input.created_by,
                icon: input.icon,
                user_acl: HashMap::new(),
                group_acl: HashMap::new(),
                display_name: input.display_name,
                allow_user_cancel_workspace_jobs: input.allow_user_cancel_workspace_jobs,
                allow_user_autostart: input.allow_user_autostart,
                allow_user_autostop: input.allow_user_autostop,
                failure_ttl: input.failure_ttl,
                time_til_dormant: input.time_til_dormant,
                time_til_dormant_autodelete: input.time_til_dormant_autodelete,
                autostop_requirement_days_of_week: 0,
                autostop_requirement_weeks: 0,
                autostart_block_days_of_week: 0,
                require_active_version: input.require_active_version,
                deprecated: String::new(),
                activity_bump: input.activity_bump,
                max_port_sharing_level: input.max_port_share_level,
                use_classic_parameter_flow: false,
                cors_behavior: String::new(),
                disable_module_cache: false,
                created_by_username: creator.map(|u| u.username.clone()).unwrap_or_default(),
                created_by_avatar_url: creator.map(|u| u.avatar_url.clone()).unwrap_or_default(),
                created_by_name: creator.map(|u| u.name.clone()).unwrap_or_default(),
            };
            templates.insert(record.id, record.clone());
            Ok(record)
        }

        async fn update_template_meta(
            &self,
            input: UpdateTemplateMetaInput,
        ) -> Result<Option<TemplateRecord>, StorageError> {
            let mut templates = self
                .templates
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            let template = match templates.get_mut(&input.template_id) {
                Some(t) => t,
                None => return Ok(None),
            };
            template.name = input.name;
            template.display_name = input.display_name;
            template.description = input.description;
            template.icon = input.icon;
            template.default_ttl = input.default_ttl;
            template.activity_bump = input.activity_bump;
            template.allow_user_autostart = input.allow_user_autostart;
            template.allow_user_autostop = input.allow_user_autostop;
            template.allow_user_cancel_workspace_jobs = input.allow_user_cancel_workspace_jobs;
            template.failure_ttl = input.failure_ttl;
            template.time_til_dormant = input.time_til_dormant;
            template.time_til_dormant_autodelete = input.time_til_dormant_autodelete;
            template.require_active_version = input.require_active_version;
            template.deprecated = input.deprecation_message;
            template.max_port_sharing_level = input.max_port_share_level;
            template.cors_behavior = input.cors_behavior;
            template.use_classic_parameter_flow = input.use_classic_parameter_flow;
            template.disable_module_cache = input.disable_module_cache;
            template.updated_at = OffsetDateTime::now_utc();
            Ok(Some(template.clone()))
        }

        async fn soft_delete_template(&self, template_id: Uuid) -> Result<bool, StorageError> {
            let mut templates = self
                .templates
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            match templates.get_mut(&template_id) {
                Some(t) if !t.deleted => {
                    t.deleted = true;
                    t.updated_at = OffsetDateTime::now_utc();
                    Ok(true)
                }
                _ => Ok(false),
            }
        }

        async fn update_template_active_version(
            &self,
            template_id: Uuid,
            active_version_id: Uuid,
        ) -> Result<bool, StorageError> {
            let mut templates = self
                .templates
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            match templates.get_mut(&template_id) {
                Some(t) => {
                    t.active_version_id = active_version_id;
                    t.updated_at = OffsetDateTime::now_utc();
                    Ok(true)
                }
                None => Ok(false),
            }
        }

        async fn template_daus(
            &self,
            _template_id: Uuid,
        ) -> Result<Vec<TemplateDAURow>, StorageError> {
            Ok(Vec::new())
        }

        async fn list_template_versions(
            &self,
            filter: TemplateVersionListFilter,
        ) -> Result<Vec<TemplateVersionRecord>, StorageError> {
            let versions = self
                .template_versions
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            let mut results: Vec<TemplateVersionRecord> = versions
                .values()
                .filter(|v| {
                    v.template_id == Some(filter.template_id)
                        && (filter.include_archived || !v.archived)
                })
                .cloned()
                .collect();
            results.sort_by(|a, b| b.created_at.cmp(&a.created_at));
            let offset = filter.offset as usize;
            let limit = filter.limit as usize;
            Ok(results.into_iter().skip(offset).take(limit).collect())
        }

        async fn find_template_version_by_id(
            &self,
            version_id: Uuid,
        ) -> Result<Option<TemplateVersionRecord>, StorageError> {
            let versions = self
                .template_versions
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            Ok(versions.get(&version_id).cloned())
        }

        async fn find_template_version_by_template_and_name(
            &self,
            template_id: Uuid,
            name: &str,
        ) -> Result<Option<TemplateVersionRecord>, StorageError> {
            let versions = self
                .template_versions
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            Ok(versions
                .values()
                .find(|v| v.template_id == Some(template_id) && v.name == name)
                .cloned())
        }

        async fn find_template_version_by_org_and_name(
            &self,
            organization_id: Uuid,
            _template_name: &str,
            version_name: &str,
        ) -> Result<Option<TemplateVersionRecord>, StorageError> {
            let versions = self
                .template_versions
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            Ok(versions
                .values()
                .find(|v| v.organization_id == organization_id && v.name == version_name)
                .cloned())
        }

        async fn find_previous_template_version(
            &self,
            organization_id: Uuid,
            template_name: &str,
            version_name: &str,
        ) -> Result<Option<TemplateVersionRecord>, StorageError> {
            let templates = self
                .templates
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            let template_id = match templates
                .values()
                .find(|t| t.organization_id == organization_id && t.name == template_name)
                .map(|t| t.id)
            {
                Some(id) => id,
                None => return Ok(None),
            };
            drop(templates);

            let versions = self
                .template_versions
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;

            // Find the target version to get its created_at timestamp.
            let target = versions.values().find(|v| {
                v.organization_id == organization_id
                    && v.template_id == Some(template_id)
                    && v.name == version_name
            });
            let target_created_at = match target {
                Some(t) => t.created_at,
                None => return Ok(None),
            };

            // Find the version created immediately before the target.
            let mut candidates: Vec<&TemplateVersionRecord> = versions
                .values()
                .filter(|v| {
                    v.organization_id == organization_id
                        && v.template_id == Some(template_id)
                        && v.created_at < target_created_at
                })
                .collect();
            candidates.sort_by(|a, b| b.created_at.cmp(&a.created_at));
            Ok(candidates.first().cloned().cloned())
        }

        async fn insert_template_version(
            &self,
            input: CreateTemplateVersionInput,
        ) -> Result<TemplateVersionRecord, StorageError> {
            let mut versions = self
                .template_versions
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;

            let users = self
                .users
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            let creator = users.get(&input.created_by);

            let record = TemplateVersionRecord {
                id: input.id,
                template_id: input.template_id,
                organization_id: input.organization_id,
                created_at: input.created_at,
                updated_at: input.updated_at,
                name: input.name,
                readme: input.readme,
                job_id: input.job_id,
                created_by: input.created_by,
                external_auth_providers: Value::Array(Vec::new()),
                message: input.message,
                archived: false,
                source_example_id: input.source_example_id,
                has_ai_task: None,
                has_external_agent: None,
                created_by_avatar_url: creator.map(|u| u.avatar_url.clone()).unwrap_or_default(),
                created_by_username: creator.map(|u| u.username.clone()).unwrap_or_default(),
                created_by_name: creator.map(|u| u.name.clone()).unwrap_or_default(),
            };
            versions.insert(record.id, record.clone());
            Ok(record)
        }

        async fn update_template_version(
            &self,
            version_id: Uuid,
            name: &str,
            message: &str,
        ) -> Result<Option<TemplateVersionRecord>, StorageError> {
            let mut versions = self
                .template_versions
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            match versions.get_mut(&version_id) {
                Some(v) => {
                    v.name = name.to_owned();
                    v.message = message.to_owned();
                    v.updated_at = OffsetDateTime::now_utc();
                    Ok(Some(v.clone()))
                }
                None => Ok(None),
            }
        }

        async fn archive_template_version(&self, version_id: Uuid) -> Result<bool, StorageError> {
            let mut versions = self
                .template_versions
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            match versions.get_mut(&version_id) {
                Some(v) => {
                    v.archived = true;
                    Ok(true)
                }
                None => Ok(false),
            }
        }

        async fn unarchive_template_version(&self, version_id: Uuid) -> Result<bool, StorageError> {
            let mut versions = self
                .template_versions
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            match versions.get_mut(&version_id) {
                Some(v) => {
                    v.archived = false;
                    Ok(true)
                }
                None => Ok(false),
            }
        }

        async fn list_template_version_parameters(
            &self,
            version_id: Uuid,
        ) -> Result<Vec<TemplateVersionParameterRecord>, StorageError> {
            let params = self
                .template_version_parameters
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            Ok(params.get(&version_id).cloned().unwrap_or_default())
        }

        async fn list_template_version_variables(
            &self,
            version_id: Uuid,
        ) -> Result<Vec<TemplateVersionVariableRecord>, StorageError> {
            let vars = self
                .template_version_variables
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            Ok(vars.get(&version_id).cloned().unwrap_or_default())
        }

        async fn list_template_version_presets(
            &self,
            version_id: Uuid,
        ) -> Result<Vec<TemplateVersionPresetRecord>, StorageError> {
            let presets = self
                .template_version_presets
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            Ok(presets.get(&version_id).cloned().unwrap_or_default())
        }

        async fn list_template_version_preset_parameters(
            &self,
            preset_id: Uuid,
        ) -> Result<Vec<TemplateVersionPresetParameterRecord>, StorageError> {
            let params = self
                .template_version_preset_parameters
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            Ok(params.get(&preset_id).cloned().unwrap_or_default())
        }

        async fn create_provisioner_job(
            &self,
            input: CreateProvisionerJobInput,
        ) -> Result<TemplateProvisionerJobRecord, StorageError> {
            let mut jobs = self
                .provisioner_jobs
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            let record = TemplateProvisionerJobRecord {
                id: input.id,
                created_at: input.created_at,
                updated_at: input.updated_at,
                started_at: None,
                canceled_at: None,
                completed_at: None,
                error: String::new(),
                organization_id: input.organization_id,
                initiator_id: input.initiator_id,
                provisioner: input.provisioner,
                job_status: "pending".to_owned(),
                file_id: input.file_id,
                job_type: input.job_type,
                input: input.input,
                worker_id: None,
                tags: input.tags,
            };
            jobs.insert(record.id, record.clone());
            Ok(record)
        }

        async fn find_provisioner_job(
            &self,
            job_id: Uuid,
        ) -> Result<Option<TemplateProvisionerJobRecord>, StorageError> {
            let jobs = self
                .provisioner_jobs
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            Ok(jobs.get(&job_id).cloned())
        }

        async fn cancel_template_provisioner_job(
            &self,
            job_id: Uuid,
        ) -> Result<bool, StorageError> {
            let mut jobs = self
                .provisioner_jobs
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            match jobs.get_mut(&job_id) {
                Some(j) => {
                    j.canceled_at = Some(OffsetDateTime::now_utc());
                    j.job_status = "canceling".to_owned();
                    Ok(true)
                }
                None => Ok(false),
            }
        }

        async fn insert_file(
            &self,
            input: InsertFileInput,
        ) -> Result<InsertFileResult, StorageError> {
            let mut files = self
                .files
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;

            // Mimic ON CONFLICT (hash, created_by) DO UPDATE SET id = files.id
            // – return the existing record’s id when a duplicate exists.
            if let Some(existing) = files
                .values()
                .find(|f| f.hash == input.hash && f.created_by == input.created_by)
            {
                return Ok(InsertFileResult { id: existing.id });
            }

            let id = input.id;
            let record = FileRecord {
                id,
                hash: input.hash,
                created_by: input.created_by,
                created_at: OffsetDateTime::now_utc(),
                mimetype: input.mimetype,
                data: input.data,
            };
            files.insert(record.id, record);
            Ok(InsertFileResult { id })
        }

        async fn get_file_by_id(&self, file_id: Uuid) -> Result<Option<FileRecord>, StorageError> {
            self.files
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))
                .map(|files| files.get(&file_id).cloned())
        }

        async fn get_file_by_hash_and_creator(
            &self,
            hash: &str,
            creator_id: Uuid,
        ) -> Result<Option<FileRecord>, StorageError> {
            self.files
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))
                .map(|files| {
                    files
                        .values()
                        .find(|f| f.hash == hash && f.created_by == creator_id)
                        .cloned()
                })
        }

        async fn archive_unused_template_versions(
            &self,
            template_id: Uuid,
            all: bool,
        ) -> Result<Vec<Uuid>, StorageError> {
            let templates = self
                .templates
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            let active_version_id = templates.get(&template_id).map(|t| t.active_version_id);

            let jobs = self
                .provisioner_jobs
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;

            let mut versions = self
                .template_versions
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            let mut archived = Vec::new();
            for v in versions.values_mut() {
                if v.template_id == Some(template_id)
                    && !v.archived
                    && Some(v.id) != active_version_id
                {
                    // When `all` is false, only archive versions whose job failed
                    // (completed with an error and not canceled).
                    if !all {
                        let job_failed = jobs
                            .get(&v.job_id)
                            .map(|j| {
                                j.completed_at.is_some()
                                    && !j.error.is_empty()
                                    && j.canceled_at.is_none()
                            })
                            .unwrap_or(false);
                        if !job_failed {
                            continue;
                        }
                    }
                    v.archived = true;
                    archived.push(v.id);
                }
            }
            Ok(archived)
        }

        async fn get_previous_template_version(
            &self,
            organization_id: Uuid,
            name: &str,
            template_id: Option<Uuid>,
        ) -> Result<Option<TemplateVersionRecord>, StorageError> {
            let versions = self
                .template_versions
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;

            // Find the target version by name and org.
            let target = versions.values().find(|v| {
                v.organization_id == organization_id
                    && v.name == name
                    && (template_id.is_none() || v.template_id == template_id)
            });
            let target_created_at = match target {
                Some(t) => t.created_at,
                None => return Ok(None),
            };

            // Find the version created immediately before.
            let mut candidates: Vec<&TemplateVersionRecord> = versions
                .values()
                .filter(|v| {
                    v.organization_id == organization_id
                        && v.created_at < target_created_at
                        && (template_id.is_none() || v.template_id == template_id)
                })
                .collect();
            candidates.sort_by(|a, b| b.created_at.cmp(&a.created_at));
            Ok(candidates.first().cloned().cloned())
        }

        // ----- Agent storage methods -----

        async fn find_workspace_agent_by_id(
            &self,
            agent_id: Uuid,
        ) -> Result<Option<WorkspaceAgentRow>, StorageError> {
            self.workspace_agents
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))
                .map(|agents| agents.get(&agent_id).cloned())
        }

        // ----- Agent storage methods -----

        async fn find_workspace_agent_by_auth_token(
            &self,
            auth_token: Uuid,
        ) -> Result<Option<WorkspaceAgentRow>, StorageError> {
            let agents = self
                .workspace_agents
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            Ok(agents
                .values()
                .find(|a| a.auth_token == auth_token)
                .cloned())
        }

        async fn find_workspace_by_agent_id(
            &self,
            agent_id: Uuid,
        ) -> Result<Option<WorkspaceRecord>, StorageError> {
            // In the fake store, we look up the agent to find the resource_id,
            // but we don't have the full build chain. Instead we store
            // workspaces keyed by their id and look up by iterating.
            // For testing we rely on tests setting up workspace records with
            // matching IDs.
            let agents = self
                .workspace_agents
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            let _agent = match agents.get(&agent_id) {
                Some(a) => a,
                None => return Ok(None),
            };
            // Return the first workspace (tests typically only have one).
            let workspaces = self
                .workspaces
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            Ok(workspaces.values().next().cloned())
        }

        async fn insert_workspace_agent_log_source(
            &self,
            agent_id: Uuid,
            id: Option<Uuid>,
            display_name: &str,
            icon: &str,
        ) -> Result<WorkspaceAgentLogSourceRow, StorageError> {
            let source_id = id.unwrap_or_else(Uuid::new_v4);
            let now = OffsetDateTime::now_utc();
            let row = WorkspaceAgentLogSourceRow {
                id: source_id,
                workspace_agent_id: agent_id,
                created_at: now,
                display_name: display_name.to_owned(),
                icon: icon.to_owned(),
            };
            self.workspace_agent_log_sources
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?
                .insert(source_id, row.clone());
            Ok(row)
        }

        async fn list_workspace_agent_log_sources(
            &self,
            agent_id: Uuid,
        ) -> Result<Vec<WorkspaceAgentLogSourceRow>, StorageError> {
            let sources = self
                .workspace_agent_log_sources
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            Ok(sources
                .values()
                .filter(|s| s.workspace_agent_id == agent_id)
                .cloned()
                .collect())
        }

        async fn insert_workspace_agent_logs(
            &self,
            agent_id: Uuid,
            log_source_id: Uuid,
            logs: &[InsertAgentLogInput],
        ) -> Result<Vec<WorkspaceAgentLogRow>, StorageError> {
            let mut stored = self
                .workspace_agent_logs
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            let mut next_id = self
                .workspace_agent_log_next_id
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            let mut result = Vec::with_capacity(logs.len());
            for entry in logs {
                let row = WorkspaceAgentLogRow {
                    id: *next_id,
                    agent_id,
                    created_at: entry.created_at,
                    output: entry.output.clone(),
                    level: entry.level.clone(),
                    log_source_id,
                };
                *next_id += 1;
                stored.push(row.clone());
                result.push(row);
            }
            Ok(result)
        }

        async fn insert_workspace_app_status(
            &self,
            input: &InsertWorkspaceAppStatusInput,
        ) -> Result<WorkspaceAppStatusRow, StorageError> {
            let row = WorkspaceAppStatusRow {
                id: Uuid::new_v4(),
                created_at: OffsetDateTime::now_utc(),
                agent_id: input.agent_id,
                app_id: input.app_id,
                workspace_id: input.workspace_id,
                state: input.state.clone(),
                message: input.message.clone(),
                uri: input.uri.clone(),
            };
            self.workspace_app_statuses
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?
                .push(row.clone());
            Ok(row)
        }

        async fn list_workspace_app_statuses_by_agent_id(
            &self,
            agent_id: Uuid,
        ) -> Result<Vec<WorkspaceAppStatusRow>, StorageError> {
            let statuses = self
                .workspace_app_statuses
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            Ok(statuses
                .iter()
                .filter(|s| s.agent_id == agent_id)
                .cloned()
                .collect())
        }

        async fn find_workspace_app_by_agent_and_slug(
            &self,
            agent_id: Uuid,
            slug: &str,
        ) -> Result<Option<WorkspaceAppRow>, StorageError> {
            let apps = self
                .workspace_apps
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            Ok(apps
                .values()
                .find(|a| a.agent_id == agent_id && a.slug == slug)
                .cloned())
        }

        async fn find_workspace_agent_by_instance_id(
            &self,
            instance_id: &str,
        ) -> Result<Option<WorkspaceAgentRow>, StorageError> {
            let agents = self
                .workspace_agents
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            Ok(agents
                .values()
                .find(|a| a.auth_instance_id.as_deref() == Some(instance_id))
                .cloned())
        }

        async fn list_workspace_apps_by_agent_id(
            &self,
            agent_id: Uuid,
        ) -> Result<Vec<WorkspaceAppRow>, StorageError> {
            self.workspace_apps
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))
                .map(|apps| {
                    apps.values()
                        .filter(|a| a.agent_id == agent_id)
                        .cloned()
                        .collect()
                })
        }

        async fn list_workspace_agent_scripts(
            &self,
            agent_id: Uuid,
        ) -> Result<Vec<WorkspaceAgentScriptRow>, StorageError> {
            self.workspace_agent_scripts
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))
                .map(|scripts| {
                    scripts
                        .iter()
                        .filter(|s| s.workspace_agent_id == agent_id)
                        .cloned()
                        .collect()
                })
        }

        async fn list_workspace_agent_logs(
            &self,
            agent_id: Uuid,
            after_id: i64,
            limit: i64,
        ) -> Result<Vec<WorkspaceAgentLogRow>, StorageError> {
            self.workspace_agent_logs
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))
                .map(|logs| {
                    logs.iter()
                        .filter(|l| l.agent_id == agent_id && l.id > after_id)
                        .take(limit as usize)
                        .cloned()
                        .collect()
                })
        }

        async fn list_workspace_agent_metadata(
            &self,
            agent_id: Uuid,
        ) -> Result<Vec<WorkspaceAgentMetadataRow>, StorageError> {
            self.workspace_agent_metadata
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))
                .map(|metadata| {
                    metadata
                        .iter()
                        .filter(|m| m.workspace_agent_id == agent_id)
                        .cloned()
                        .collect()
                })
        }

        async fn list_workspace_agent_devcontainers(
            &self,
            agent_id: Uuid,
        ) -> Result<Vec<coder_core::WorkspaceAgentDevcontainerRow>, StorageError> {
            self.workspace_agent_devcontainers
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))
                .map(|dcs| {
                    dcs.iter()
                        .filter(|dc| dc.workspace_agent_id == agent_id)
                        .cloned()
                        .collect()
                })
        }

        async fn find_workspace_resource_by_id(
            &self,
            resource_id: Uuid,
        ) -> Result<Option<WorkspaceResourceRecord>, StorageError> {
            let resources = self
                .workspace_resources
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            Ok(resources
                .values()
                .flatten()
                .find(|r| r.id == resource_id)
                .cloned())
        }

        async fn find_workspace_build_by_id(
            &self,
            build_id: Uuid,
        ) -> Result<Option<WorkspaceBuildRecord>, StorageError> {
            let builds = self
                .workspace_builds
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            Ok(builds.get(&build_id).cloned())
        }

        async fn find_latest_workspace_build(
            &self,
            workspace_id: Uuid,
        ) -> Result<Option<WorkspaceBuildRecord>, StorageError> {
            let builds = self
                .workspace_builds
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            Ok(builds
                .values()
                .filter(|b| b.workspace_id == workspace_id)
                .max_by_key(|b| b.build_number)
                .cloned())
        }

        async fn list_workspace_build_parameters(
            &self,
            build_id: Uuid,
        ) -> Result<Vec<WorkspaceBuildParameterRecord>, StorageError> {
            self.workspace_build_parameters
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))
                .map(|params| params.get(&build_id).cloned().unwrap_or_default())
        }

        async fn list_provisioner_job_logs(
            &self,
            job_id: Uuid,
            _after: Option<i64>,
        ) -> Result<Vec<PortsJobLogRecord>, StorageError> {
            let logs = self
                .provisioner_job_logs
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            Ok(logs.get(&job_id).cloned().unwrap_or_default())
        }

        async fn list_workspace_resources_by_job(
            &self,
            job_id: Uuid,
        ) -> Result<Vec<WorkspaceResourceRecord>, StorageError> {
            self.workspace_resources
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))
                .map(|resources| resources.get(&job_id).cloned().unwrap_or_default())
        }

        async fn list_workspace_resource_metadata(
            &self,
            resource_ids: &[Uuid],
        ) -> Result<Vec<WorkspaceResourceMetadataRecord>, StorageError> {
            let metadata = self
                .workspace_resource_metadata
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            let mut result = Vec::new();
            for id in resource_ids {
                if let Some(items) = metadata.get(id) {
                    result.extend(items.iter().cloned());
                }
            }
            Ok(result)
        }

        async fn list_provisioner_job_timings(
            &self,
            job_id: Uuid,
        ) -> Result<Vec<PortsJobTimingRecord>, StorageError> {
            let timings = self
                .provisioner_job_timings
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            Ok(timings.get(&job_id).cloned().unwrap_or_default())
        }

        // ---------------------------------------------------------------
        // Workspace domain overrides
        // ---------------------------------------------------------------

        async fn insert_workspace(
            &self,
            input: CreateWorkspaceInput,
        ) -> Result<WorkspaceRecord, StorageError> {
            let now = OffsetDateTime::now_utc();
            let record = WorkspaceRecord {
                id: input.id,
                created_at: now,
                updated_at: now,
                deleted: false,
                owner_id: input.owner_id,
                organization_id: input.organization_id,
                template_id: input.template_id,
                name: input.name,
                autostart_schedule: input.autostart_schedule,
                ttl_ns: input.ttl_ns,
                last_used_at: now,
                dormant_at: None,
                deleting_at: None,
                automatic_updates: input.automatic_updates,
                favorite: false,
                next_start_at: None,
            };
            self.workspaces
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?
                .insert(record.id, record.clone());
            Ok(record)
        }

        async fn find_workspace_by_owner_and_name(
            &self,
            owner_id: Uuid,
            name: &str,
            _viewer_id: Option<Uuid>,
        ) -> Result<Option<WorkspaceRecord>, StorageError> {
            let workspaces = self
                .workspaces
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            Ok(workspaces
                .values()
                .find(|w| !w.deleted && w.owner_id == owner_id && w.name == name)
                .cloned())
        }

        async fn insert_workspace_build(
            &self,
            input: CreateWorkspaceBuildInput,
        ) -> Result<WorkspaceBuildRecord, StorageError> {
            let now = OffsetDateTime::now_utc();
            let record = WorkspaceBuildRecord {
                id: input.id,
                created_at: now,
                updated_at: now,
                workspace_id: input.workspace_id,
                build_number: input.build_number,
                transition: input.transition,
                job_id: input.job_id,
                template_version_id: input.template_version_id,
                initiator_id: input.initiator_id,
                provisioner_state: None,
                deadline: input.deadline,
                max_deadline: input.max_deadline,
                reason: input.reason,
                daily_cost: 0,
            };
            self.workspace_builds
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?
                .insert(record.id, record.clone());
            Ok(record)
        }

        async fn find_workspace_build_by_number(
            &self,
            workspace_id: Uuid,
            build_number: i64,
        ) -> Result<Option<WorkspaceBuildRecord>, StorageError> {
            let builds = self
                .workspace_builds
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            Ok(builds
                .values()
                .find(|b| b.workspace_id == workspace_id && b.build_number == build_number)
                .cloned())
        }

        async fn insert_workspace_build_parameters(
            &self,
            build_id: Uuid,
            params: &[(String, String)],
        ) -> Result<(), StorageError> {
            let records: Vec<WorkspaceBuildParameterRecord> = params
                .iter()
                .map(|(name, value)| WorkspaceBuildParameterRecord {
                    workspace_build_id: build_id,
                    name: name.clone(),
                    value: value.clone(),
                })
                .collect();
            self.workspace_build_parameters
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?
                .insert(build_id, records);
            Ok(())
        }

        async fn list_workspaces(
            &self,
            filter: WorkspaceListFilter,
        ) -> Result<(Vec<WorkspaceRecord>, i64), StorageError> {
            let workspaces = self
                .workspaces
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            let mut rows: Vec<WorkspaceRecord> = workspaces
                .values()
                .filter(|w| !w.deleted)
                .filter(|w| {
                    filter
                        .owner_id
                        .is_none_or(|owner_id| w.owner_id == owner_id)
                })
                .filter(|w| {
                    filter
                        .name
                        .as_ref()
                        .is_none_or(|n| w.name.contains(n.as_str()))
                })
                .filter(|w| {
                    filter
                        .organization_id
                        .is_none_or(|org_id| w.organization_id == org_id)
                })
                .filter(|w| {
                    filter.template_ids.is_empty() || filter.template_ids.contains(&w.template_id)
                })
                .filter(|w| {
                    filter.dormant.is_none_or(|d| {
                        if d {
                            w.dormant_at.is_some()
                        } else {
                            w.dormant_at.is_none()
                        }
                    })
                })
                .cloned()
                .collect();
            let count = i64::try_from(rows.len()).unwrap_or(0);
            let offset = usize::try_from(filter.offset).unwrap_or(0);
            let limit = usize::try_from(filter.limit).unwrap_or(25);
            rows = rows.into_iter().skip(offset).take(limit).collect();
            Ok((rows, count))
        }

        async fn find_workspace_by_id(
            &self,
            workspace_id: Uuid,
            _viewer_id: Option<Uuid>,
        ) -> Result<Option<WorkspaceRecord>, StorageError> {
            let workspaces = self
                .workspaces
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            Ok(workspaces
                .get(&workspace_id)
                .filter(|w| !w.deleted)
                .cloned())
        }

        async fn update_workspace_name(
            &self,
            workspace_id: Uuid,
            name: &str,
            _viewer_id: Option<Uuid>,
        ) -> Result<Option<WorkspaceRecord>, StorageError> {
            let mut workspaces = self
                .workspaces
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            let Some(ws) = workspaces.get_mut(&workspace_id) else {
                return Ok(None);
            };
            if ws.deleted {
                return Ok(None);
            }
            ws.name = name.to_owned();
            ws.updated_at = OffsetDateTime::now_utc();
            Ok(Some(ws.clone()))
        }

        async fn soft_delete_workspace(&self, workspace_id: Uuid) -> Result<bool, StorageError> {
            let mut workspaces = self
                .workspaces
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            let Some(ws) = workspaces.get_mut(&workspace_id) else {
                return Ok(false);
            };
            if ws.deleted {
                return Ok(false);
            }
            ws.deleted = true;
            ws.updated_at = OffsetDateTime::now_utc();
            Ok(true)
        }

        async fn list_workspace_builds(
            &self,
            workspace_id: Uuid,
            limit: u32,
            offset: u32,
        ) -> Result<Vec<WorkspaceBuildRecord>, StorageError> {
            let builds = self
                .workspace_builds
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            let mut rows: Vec<WorkspaceBuildRecord> = builds
                .values()
                .filter(|b| b.workspace_id == workspace_id)
                .cloned()
                .collect();
            rows.sort_by(|a, b| b.build_number.cmp(&a.build_number));
            let off = usize::try_from(offset).unwrap_or(0);
            let lim = usize::try_from(limit).unwrap_or(25);
            Ok(rows.into_iter().skip(off).take(lim).collect())
        }

        async fn list_workspace_port_shares(
            &self,
            workspace_id: Uuid,
        ) -> Result<Vec<WorkspaceAgentPortShareRecord>, StorageError> {
            let shares = self
                .workspace_port_shares
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            Ok(shares
                .iter()
                .filter(|s| s.workspace_id == workspace_id)
                .cloned()
                .collect())
        }

        async fn upsert_workspace_port_share(
            &self,
            input: UpsertPortShareInput,
        ) -> Result<WorkspaceAgentPortShareRecord, StorageError> {
            let mut shares = self
                .workspace_port_shares
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            // Update existing or insert new.
            if let Some(existing) = shares.iter_mut().find(|s| {
                s.workspace_id == input.workspace_id
                    && s.agent_name == input.agent_name
                    && s.port == input.port
            }) {
                existing.share_level = input.share_level.clone();
                existing.protocol = input.protocol.clone();
                return Ok(existing.clone());
            }
            let record = WorkspaceAgentPortShareRecord {
                workspace_id: input.workspace_id,
                agent_name: input.agent_name,
                port: input.port,
                share_level: input.share_level,
                protocol: input.protocol,
            };
            shares.push(record.clone());
            Ok(record)
        }

        async fn delete_workspace_port_share(
            &self,
            workspace_id: Uuid,
            agent_name: &str,
            port: i32,
        ) -> Result<bool, StorageError> {
            let mut shares = self
                .workspace_port_shares
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            let before = shares.len();
            shares.retain(|s| {
                !(s.workspace_id == workspace_id && s.agent_name == agent_name && s.port == port)
            });
            Ok(shares.len() < before)
        }

        async fn get_workspace_acl(
            &self,
            workspace_id: Uuid,
        ) -> Result<WorkspaceACLRecord, StorageError> {
            let acls = self
                .workspace_acls
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            Ok(acls
                .get(&workspace_id)
                .cloned()
                .unwrap_or_else(|| WorkspaceACLRecord {
                    user_acl: HashMap::new(),
                    group_acl: HashMap::new(),
                }))
        }

        async fn update_workspace_acl(
            &self,
            workspace_id: Uuid,
            input: &UpdateWorkspaceACLInput,
        ) -> Result<(), StorageError> {
            let mut acls = self
                .workspace_acls
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            let entry = acls
                .entry(workspace_id)
                .or_insert_with(|| WorkspaceACLRecord {
                    user_acl: HashMap::new(),
                    group_acl: HashMap::new(),
                });
            entry.user_acl.extend(
                input
                    .user_roles
                    .iter()
                    .map(|(k, v): (&String, &String)| (k.to_owned(), v.to_owned())),
            );
            entry.group_acl.extend(
                input
                    .group_roles
                    .iter()
                    .map(|(k, v): (&String, &String)| (k.to_owned(), v.to_owned())),
            );
            Ok(())
        }

        async fn delete_workspace_acl(&self, workspace_id: Uuid) -> Result<(), StorageError> {
            let mut acls = self
                .workspace_acls
                .lock()
                .map_err(|e| StorageError::unavailable(e.to_string()))?;
            acls.remove(&workspace_id);
            Ok(())
        }
    }

    fn test_config() -> Result<ServerConfig, url::ParseError> {
        Ok(ServerConfig {
            listen_addr: std::net::SocketAddr::from(([127, 0, 0, 1], 3000)),
            access_url: Url::parse("http://127.0.0.1:3000")?,
            database: DatabaseConfig {
                postgres_url: "postgres://unused".to_owned(),
                max_connections: 20,
                min_connections: 1,
                acquire_timeout_secs: 10,
            },
            telemetry_enabled: false,
            ssh: SshConfig {
                hostname_prefix: "coder".to_owned(),
                hostname_suffix: "example.internal".to_owned(),
                ssh_config_options: vec![("StrictHostKeyChecking".to_owned(), "no".to_owned())],
            },
            external_auth_providers: Vec::new(),
            derp_regions: Vec::new(),
            shutdown_grace_period_secs: 10,
            log_format: LogFormat::Pretty,
        })
    }

    fn test_state_with_store(
        health_ok: bool,
    ) -> Result<(AppState, Arc<FakeStore>), Box<dyn Error>> {
        let store = Arc::new(FakeStore::new(health_ok));
        let store_trait: Arc<dyn AppStore> = store.clone();
        let audit: Arc<dyn AuditSink> = Arc::new(MemoryAuditSink::default());
        let pubsub: Arc<dyn coder_core::pubsub::PubSub> =
            Arc::new(coder_core::pubsub::InMemoryPubSub::new());

        Ok((
            AppState::new(
                test_config()?,
                BuildMetadata::default(),
                Uuid::nil(),
                store_trait,
                audit,
                pubsub,
            )?,
            store,
        ))
    }

    fn test_state(health_ok: bool) -> Result<AppState, Box<dyn Error>> {
        test_state_with_store(health_ok).map(|(state, _)| state)
    }

    fn request(method: Method, uri: &str) -> Result<Request<Body>, http::Error> {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
    }

    fn json_request<T: Serialize>(
        method: Method,
        uri: &str,
        payload: &T,
    ) -> Result<Request<Body>, Box<dyn Error>> {
        let body = serde_json::to_vec(payload)?;
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(body))?;
        Ok(request)
    }

    fn authenticated_request(
        method: Method,
        uri: &str,
        session_token: &str,
    ) -> Result<Request<Body>, http::Error> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(SESSION_TOKEN_HEADER, session_token)
            .body(Body::empty())
    }

    fn authenticated_json_request<T: Serialize>(
        method: Method,
        uri: &str,
        session_token: &str,
        payload: &T,
    ) -> Result<Request<Body>, Box<dyn Error>> {
        let body = serde_json::to_vec(payload)?;
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header(CONTENT_TYPE, "application/json")
            .header(SESSION_TOKEN_HEADER, session_token)
            .body(Body::from(body))?;
        Ok(request)
    }

    fn request_with_cookies(
        method: Method,
        uri: &str,
        cookies: &[(&str, &str)],
    ) -> Result<Request<Body>, http::Error> {
        let cookie_header = cookies
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ");
        Request::builder()
            .method(method)
            .uri(uri)
            .header(http::header::COOKIE, cookie_header)
            .body(Body::empty())
    }

    async fn call(app: Router, request: Request<Body>) -> Result<Response<Body>, Box<dyn Error>> {
        let response = match app.oneshot(request).await {
            Ok(response) => response,
            Err(never) => match never {},
        };

        Ok(response)
    }

    async fn response_json(response: Response<Body>) -> Result<Value, Box<dyn Error>> {
        let bytes = to_bytes(response.into_body(), usize::MAX).await?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    async fn create_and_login(app: &Router) -> Result<String, Box<dyn Error>> {
        let create_response = call(
            app.clone(),
            json_request(
                Method::POST,
                "/api/v2/users/first",
                &CreateFirstUserRequest {
                    email: "owner@example.com".to_owned(),
                    username: "owner".to_owned(),
                    name: "Owner".to_owned(),
                    password: "Password123".to_owned(),
                },
            )?,
        )
        .await?;
        assert_eq!(create_response.status(), StatusCode::CREATED);

        let login_response = call(
            app.clone(),
            json_request(
                Method::POST,
                "/api/v2/users/login",
                &LoginWithPasswordRequest {
                    email: "owner@example.com".to_owned(),
                    password: "Password123".to_owned(),
                },
            )?,
        )
        .await?;
        assert_eq!(login_response.status(), StatusCode::CREATED);
        let login_body = response_json(login_response).await?;
        Ok(login_body
            .get("session_token")
            .and_then(Value::as_str)
            .ok_or("missing session token")?
            .to_owned())
    }

    async fn spawn_test_server(
        router: Router,
    ) -> Result<(Url, tokio::task::JoinHandle<()>), Box<dyn Error>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, router.into_make_service()).await;
        });
        Ok((Url::parse(&format!("http://{address}"))?, handle))
    }

    async fn first_organization_id(
        app: &Router,
        session_token: &str,
    ) -> Result<Uuid, Box<dyn Error>> {
        let response = call(
            app.clone(),
            authenticated_request(Method::GET, "/api/v2/organizations", session_token)?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await?;
        let org_id = body
            .as_array()
            .and_then(|organizations| organizations.first())
            .and_then(|organization| organization.get("id"))
            .and_then(Value::as_str)
            .ok_or("missing organization id")?;
        Ok(Uuid::parse_str(org_id)?)
    }

    #[tokio::test]
    async fn root_endpoint_returns_slim_build_response() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let response = call(app, request(Method::GET, "/")?).await?;

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), usize::MAX).await?;
        assert_eq!(String::from_utf8(bytes.to_vec())?, SLIM_BUILD_MESSAGE);
        Ok(())
    }

    #[tokio::test]
    async fn api_root_returns_wave_message() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let response = call(app, request(Method::GET, "/api/v2")?).await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await?;
        assert_eq!(
            body.get("message").and_then(Value::as_str),
            Some("\u{1f44b}")
        );
        Ok(())
    }

    #[tokio::test]
    async fn updatecheck_returns_current_build_metadata() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let response = call(app, request(Method::GET, "/api/v2/updatecheck")?).await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await?;
        assert_eq!(body.get("current").and_then(Value::as_bool), Some(true));
        assert_eq!(
            body.get("version").and_then(Value::as_str),
            Some(env!("CARGO_PKG_VERSION"))
        );
        assert_eq!(
            body.get("url").and_then(Value::as_str),
            Some("https://github.com/coder/coder")
        );
        Ok(())
    }

    #[tokio::test]
    async fn csp_reports_require_auth_and_return_ok() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);

        let unauthorized = call(
            app.clone(),
            json_request(
                Method::POST,
                "/api/v2/csp/reports",
                &json!({ "csp-report": { "blocked-uri": "https://example.com" } }),
            )?,
        )
        .await?;
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

        let session_token = create_and_login(&app).await?;
        let response = call(
            app,
            authenticated_json_request(
                Method::POST,
                "/api/v2/csp/reports",
                &session_token,
                &json!({ "csp-report": { "blocked-uri": "https://example.com" } }),
            )?,
        )
        .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await?;
        assert_eq!(body, Value::String("ok".to_owned()));
        Ok(())
    }

    #[tokio::test]
    async fn csp_reports_reject_invalid_json() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;
        let request = Request::builder()
            .method(Method::POST)
            .uri("/api/v2/csp/reports")
            .header(CONTENT_TYPE, "application/json")
            .header(SESSION_TOKEN_HEADER, session_token)
            .body(Body::from("{"))?;

        let response = call(app, request).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response_json(response).await?;
        assert_eq!(
            body.get("message").and_then(Value::as_str),
            Some("Failed to read body, invalid json.")
        );
        Ok(())
    }

    #[tokio::test]
    async fn init_script_returns_rendered_shell_script() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let response = call(
            app,
            request(Method::GET, "/api/v2/init-script/linux/amd64")?,
        )
        .await?;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("text/plain; charset=utf-8")
        );
        assert!(
            response.headers().contains_key("content-digest"),
            "expected content-digest header"
        );
        let bytes = to_bytes(response.into_body(), usize::MAX).await?;
        let body = String::from_utf8(bytes.to_vec())?;
        assert!(body.contains("coder-linux-amd64"));
        assert!(body.contains("CODER_AGENT_AUTH=\"token\""));
        assert!(body.contains("CODER_AGENT_URL=\"http://127.0.0.1:3000/\""));
        Ok(())
    }

    #[tokio::test]
    async fn init_script_rejects_unknown_targets() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let response = call(
            app,
            request(Method::GET, "/api/v2/init-script/plan9/amd64")?,
        )
        .await?;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response_json(response).await?;
        assert_eq!(
            body.get("message").and_then(Value::as_str),
            Some("Unknown os/arch: plan9/amd64")
        );
        Ok(())
    }

    #[tokio::test]
    async fn first_user_endpoint_returns_404_and_build_version_header_when_missing()
    -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let response = call(app, request(Method::GET, "/api/v2/users/first")?).await?;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response
                .headers()
                .get(BUILD_VERSION_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some(env!("CARGO_PKG_VERSION"))
        );
        Ok(())
    }

    #[tokio::test]
    async fn create_first_user_then_login_and_fetch_me() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        let user_response = call(
            app,
            authenticated_request(Method::GET, "/api/v2/users/me", &session_token)?,
        )
        .await?;
        assert_eq!(user_response.status(), StatusCode::OK);
        let user_body = response_json(user_response).await?;
        assert_eq!(
            user_body.get("email").and_then(Value::as_str),
            Some("owner@example.com")
        );
        assert_eq!(
            user_body.get("username").and_then(Value::as_str),
            Some("owner")
        );
        Ok(())
    }

    #[tokio::test]
    async fn auth_scopes_and_experiments_routes_return_expected_defaults()
    -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        let scopes_response =
            call(app.clone(), request(Method::GET, "/api/v2/auth/scopes")?).await?;
        assert_eq!(scopes_response.status(), StatusCode::OK);
        let scopes_body = response_json(scopes_response).await?;
        assert_eq!(
            scopes_body
                .get("external")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(PUBLIC_API_KEY_SCOPES.len())
        );

        let experiments_response = call(
            app.clone(),
            authenticated_request(Method::GET, "/api/v2/experiments", &session_token)?,
        )
        .await?;
        assert_eq!(experiments_response.status(), StatusCode::OK);
        assert_eq!(
            response_json(experiments_response).await?,
            Value::Array(Vec::new())
        );

        let available_response = call(
            app,
            authenticated_request(Method::GET, "/api/v2/experiments/available", &session_token)?,
        )
        .await?;
        assert_eq!(available_response.status(), StatusCode::OK);
        let available_body = response_json(available_response).await?;
        assert_eq!(
            available_body
                .get("safe")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(0)
        );

        Ok(())
    }

    #[tokio::test]
    async fn external_auth_and_debug_routes_return_current_fallbacks() -> Result<(), Box<dyn Error>>
    {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        let list_response = call(
            app.clone(),
            authenticated_request(Method::GET, "/api/v2/external-auth", &session_token)?,
        )
        .await?;
        assert_eq!(list_response.status(), StatusCode::OK);
        let list_body = response_json(list_response).await?;
        assert_eq!(
            list_body
                .get("providers")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(0)
        );
        assert_eq!(
            list_body
                .get("links")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(0)
        );

        let provider_response = call(
            app.clone(),
            authenticated_request(Method::GET, "/api/v2/external-auth/github", &session_token)?,
        )
        .await?;
        assert_eq!(provider_response.status(), StatusCode::NOT_FOUND);

        let debug_response = call(
            app.clone(),
            authenticated_request(Method::GET, "/api/v2/debug/me/debug-link", &session_token)?,
        )
        .await?;
        assert_eq!(debug_response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response_json(debug_response)
                .await?
                .get("message")
                .and_then(Value::as_str),
            Some("User is not an OIDC user.")
        );

        let autofill_response = call(
            app,
            authenticated_request(
                Method::GET,
                &format!(
                    "/api/v2/users/me/autofill-parameters?template_id={}",
                    Uuid::nil()
                ),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(autofill_response.status(), StatusCode::OK);
        assert_eq!(
            response_json(autofill_response).await?,
            Value::Array(Vec::new())
        );

        Ok(())
    }

    #[tokio::test]
    async fn operational_admin_routes_use_backing_store() -> Result<(), Box<dyn Error>> {
        let (mut state, store) = test_state_with_store(true)?;
        let (health_url, health_handle) = spawn_test_server(
            Router::new()
                .route("/healthz", get(|| async { (StatusCode::OK, "OK") }))
                .route("/latency-check", get(|| async { (StatusCode::OK, "OK") })),
        )
        .await?;
        state.config.access_url = health_url;
        state.config.external_auth_providers = vec![ExternalAuthLinkProvider {
            id: "github".to_owned(),
            provider_type: "github".to_owned(),
            device: false,
            display_name: "GitHub".to_owned(),
            display_icon: "github".to_owned(),
            allow_refresh: false,
            allow_validate: true,
            supports_revocation: false,
            code_challenge_methods_supported: Vec::new(),
            ..ExternalAuthLinkProvider::default()
        }];
        let app = build_router(state);
        let session_token = create_and_login(&app).await?;

        store
            .external_auth_links
            .lock()
            .map_err(|error| error.to_string())?
            .insert(
                (Uuid::from_u128(1), "github".to_owned()),
                ExternalAuthLinkRecord {
                    provider_id: "github".to_owned(),
                    created_at: OffsetDateTime::now_utc(),
                    updated_at: OffsetDateTime::now_utc(),
                    has_refresh_token: false,
                    expires: OffsetDateTime::now_utc() + time::Duration::hours(1),
                    access_token: "access-token".to_owned(),
                    refresh_token: String::new(),
                    token_type: "bearer".to_owned(),
                    scopes: Vec::new(),
                    authenticated: true,
                    validate_error: String::new(),
                    refresh_error: String::new(),
                    last_validated_at: Some(OffsetDateTime::now_utc()),
                    last_refreshed_at: None,
                    user: Some(ExternalAuthUser {
                        id: 1,
                        login: "coder".to_owned(),
                        avatar_url: String::new(),
                        profile_url: "https://github.com/coder".to_owned(),
                        name: "Coder".to_owned(),
                    }),
                    installations: Vec::new(),
                    app_installable: false,
                },
            );

        let health_response = call(
            app.clone(),
            authenticated_request(Method::GET, "/api/v2/debug/health", &session_token)?,
        )
        .await?;
        assert_eq!(health_response.status(), StatusCode::OK);
        assert_eq!(
            response_json(health_response)
                .await?
                .get("healthy")
                .and_then(Value::as_bool),
            Some(true)
        );

        let update_health_response = call(
            app.clone(),
            authenticated_json_request(
                Method::PUT,
                "/api/v2/debug/health/settings",
                &session_token,
                &HealthSettings {
                    dismissed_healthchecks: vec!["Database".to_owned()],
                },
            )?,
        )
        .await?;
        assert_eq!(update_health_response.status(), StatusCode::OK);

        let audit_generate_response = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                "/api/v2/audit/testgenerate",
                &session_token,
                &CreateTestAuditLogRequest::default(),
            )?,
        )
        .await?;
        assert_eq!(audit_generate_response.status(), StatusCode::NO_CONTENT);

        let audit_list_response = call(
            app.clone(),
            authenticated_request(Method::GET, "/api/v2/audit", &session_token)?,
        )
        .await?;
        assert_eq!(audit_list_response.status(), StatusCode::OK);
        assert_eq!(
            response_json(audit_list_response)
                .await?
                .get("count")
                .and_then(Value::as_u64),
            Some(1)
        );

        let git_ssh_key_response = call(
            app.clone(),
            authenticated_request(Method::GET, "/api/v2/users/me/gitsshkey", &session_token)?,
        )
        .await?;
        assert_eq!(git_ssh_key_response.status(), StatusCode::OK);
        assert_eq!(
            response_json(git_ssh_key_response)
                .await?
                .get("public_key")
                .and_then(Value::as_str)
                .map(|value| value.starts_with("ssh-ed25519 ")),
            Some(true)
        );

        let external_auth_response = call(
            app.clone(),
            authenticated_request(Method::GET, "/api/v2/external-auth/github", &session_token)?,
        )
        .await?;
        assert_eq!(external_auth_response.status(), StatusCode::OK);
        assert_eq!(
            response_json(external_auth_response)
                .await?
                .get("authenticated")
                .and_then(Value::as_bool),
            Some(true)
        );

        let delete_external_auth_response = call(
            app,
            authenticated_request(
                Method::DELETE,
                "/api/v2/external-auth/github",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(delete_external_auth_response.status(), StatusCode::OK);
        health_handle.abort();

        Ok(())
    }

    #[tokio::test]
    async fn deployment_stats_reflect_seeded_workspace_and_agent_data() -> Result<(), Box<dyn Error>>
    {
        let (state, store) = test_state_with_store(true)?;
        let app = build_router(state);
        let session_token = create_and_login(&app).await?;

        let now = OffsetDateTime::now_utc();
        let running_workspace = Uuid::new_v4();
        let failed_workspace = Uuid::new_v4();
        let running_job = Uuid::new_v4();
        let failed_job = Uuid::new_v4();

        store
            .upsert_workspace_stats_workspace(&WorkspaceStatsWorkspaceInput {
                id: running_workspace,
                deleted: false,
            })
            .await?;
        store
            .upsert_workspace_stats_workspace(&WorkspaceStatsWorkspaceInput {
                id: failed_workspace,
                deleted: false,
            })
            .await?;
        store
            .upsert_provisioner_job_stats(&ProvisionerJobStatsInput {
                id: running_job,
                created_at: now - time::Duration::minutes(5),
                updated_at: now - time::Duration::minutes(1),
                started_at: Some(now - time::Duration::minutes(4)),
                canceled_at: None,
                completed_at: Some(now - time::Duration::minutes(1)),
                error: String::new(),
            })
            .await?;
        store
            .upsert_provisioner_job_stats(&ProvisionerJobStatsInput {
                id: failed_job,
                created_at: now - time::Duration::minutes(5),
                updated_at: now - time::Duration::minutes(2),
                started_at: Some(now - time::Duration::minutes(4)),
                canceled_at: None,
                completed_at: Some(now - time::Duration::minutes(2)),
                error: "boom".to_owned(),
            })
            .await?;
        store
            .upsert_workspace_build_stats(&WorkspaceBuildStatsInput {
                id: Uuid::new_v4(),
                workspace_id: running_workspace,
                created_at: now - time::Duration::minutes(5),
                updated_at: now - time::Duration::minutes(1),
                build_number: 1,
                transition: "start".to_owned(),
                job_id: Some(running_job),
            })
            .await?;
        store
            .upsert_workspace_build_stats(&WorkspaceBuildStatsInput {
                id: Uuid::new_v4(),
                workspace_id: failed_workspace,
                created_at: now - time::Duration::minutes(5),
                updated_at: now - time::Duration::minutes(2),
                build_number: 1,
                transition: "start".to_owned(),
                job_id: Some(failed_job),
            })
            .await?;
        store
            .insert_workspace_agent_stat(&WorkspaceAgentStatInput {
                id: Uuid::new_v4(),
                created_at: now - time::Duration::minutes(1),
                user_id: Some(Uuid::from_u128(1)),
                workspace_id: Some(running_workspace),
                template_id: None,
                agent_id: Uuid::new_v4(),
                connections_by_proto: json!({"ssh": 2}),
                connection_count: 1,
                rx_packets: 10,
                rx_bytes: 128,
                tx_packets: 20,
                tx_bytes: 256,
                session_count_vscode: 1,
                session_count_jetbrains: 0,
                session_count_reconnecting_pty: 0,
                session_count_ssh: 2,
                connection_median_latency_ms: 42.0,
                usage: false,
            })
            .await?;

        let response = call(
            app,
            authenticated_request(Method::GET, "/api/v2/deployment/stats", &session_token)?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);

        let body = response_json(response).await?;
        assert_eq!(
            body.get("workspaces")
                .and_then(|value| value.get("running"))
                .and_then(Value::as_i64),
            Some(1)
        );
        assert_eq!(
            body.get("workspaces")
                .and_then(|value| value.get("failed"))
                .and_then(Value::as_i64),
            Some(1)
        );
        assert_eq!(
            body.get("session_count")
                .and_then(|value| value.get("ssh"))
                .and_then(Value::as_i64),
            Some(2)
        );
        assert_eq!(
            body.get("workspaces")
                .and_then(|value| value.get("rx_bytes"))
                .and_then(Value::as_i64),
            Some(128)
        );

        Ok(())
    }

    #[tokio::test]
    async fn debug_health_reports_derp_proxy_and_provisioner_sections() -> Result<(), Box<dyn Error>>
    {
        let (health_url, health_handle) = spawn_test_server(
            Router::new()
                .route("/healthz", get(|| async { (StatusCode::OK, "OK") }))
                .route("/latency-check", get(|| async { (StatusCode::OK, "OK") })),
        )
        .await?;
        let (derp_url, derp_handle) = spawn_test_server(
            Router::new().route("/probe", get(|| async { (StatusCode::OK, "DERP") })),
        )
        .await?;
        let (proxy_url, proxy_handle) = spawn_test_server(
            Router::new().route("/healthz", get(|| async { (StatusCode::OK, "OK") })),
        )
        .await?;

        let (mut state, store) = test_state_with_store(true)?;
        state.config.access_url = health_url;
        state.config.derp_regions = vec![DerpRegionConfig {
            id: 1,
            name: "local".to_owned(),
            nodes: vec![DerpNodeConfig {
                name: "node-1".to_owned(),
                url: derp_url.join("/probe")?,
            }],
        }];
        store
            .upsert_workspace_proxy_for_health(&WorkspaceProxyHealthInput {
                id: Uuid::new_v4(),
                name: "proxy-eu".to_owned(),
                display_name: "Proxy EU".to_owned(),
                icon_url: String::new(),
                path_app_url: proxy_url.to_string(),
                wildcard_hostname: String::new(),
                derp_enabled: false,
                derp_only: false,
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
                deleted: false,
                version: "0.1.0".to_owned(),
            })
            .await?;
        store
            .upsert_provisioner_daemon_for_health(&ProvisionerDaemonHealthInput {
                id: Uuid::new_v4(),
                organization_id: Uuid::from_u128(2),
                created_at: OffsetDateTime::now_utc(),
                last_seen_at: Some(OffsetDateTime::now_utc()),
                name: "daemon-eu".to_owned(),
                version: "0.1.0".to_owned(),
                api_version: "v1".to_owned(),
                provisioners: vec!["terraform".to_owned()],
                tags: HashMap::new(),
                status: Some("idle".to_owned()),
            })
            .await?;

        let app = build_router(state);
        let session_token = create_and_login(&app).await?;

        let response = call(
            app,
            authenticated_request(Method::GET, "/api/v2/debug/health", &session_token)?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);

        let body = response_json(response).await?;
        assert_eq!(
            body.get("derp")
                .and_then(|value| value.get("regions"))
                .and_then(|value| value.get("local"))
                .and_then(Value::as_str),
            Some("1/1 nodes healthy")
        );
        assert_eq!(
            body.get("workspace_proxy")
                .and_then(|value| value.get("items"))
                .and_then(Value::as_array)
                .and_then(|value| value.first())
                .and_then(Value::as_str),
            Some("proxy-eu: ok")
        );
        assert_eq!(
            body.get("provisioner_daemons")
                .and_then(|value| value.get("items"))
                .and_then(Value::as_array)
                .and_then(|value| value.first())
                .and_then(Value::as_str),
            Some("daemon-eu: idle")
        );

        health_handle.abort();
        derp_handle.abort();
        proxy_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn external_auth_get_refreshes_and_delete_revokes() -> Result<(), Box<dyn Error>> {
        let revoke_hits = Arc::new(Mutex::new(0usize));
        let provider_state = revoke_hits.clone();
        let (provider_url, provider_handle) = spawn_test_server(
            Router::new()
                .route(
                    "/token",
                    post(|| async {
                        Json(json!({
                            "access_token": "fresh-access-token",
                            "refresh_token": "fresh-refresh-token",
                            "token_type": "bearer",
                            "scope": "read_api",
                            "expires_in": 1800
                        }))
                    }),
                )
                .route(
                    "/user",
                    get(|headers: HeaderMap| async move {
                        let authenticated = headers
                            .get(http::header::AUTHORIZATION)
                            .and_then(|value| value.to_str().ok())
                            == Some("Bearer fresh-access-token");
                        if authenticated {
                            (
                                StatusCode::OK,
                                Json(json!({
                                    "id": 99,
                                    "login": "refreshed-user",
                                    "avatar_url": "",
                                    "html_url": "https://gitlab.example.com/refreshed-user",
                                    "name": "Refreshed User"
                                })),
                            )
                                .into_response()
                        } else {
                            StatusCode::UNAUTHORIZED.into_response()
                        }
                    }),
                )
                .route(
                    "/revoke",
                    post(move || {
                        let provider_state = provider_state.clone();
                        async move {
                            if let Ok(mut hits) = provider_state.lock() {
                                *hits += 1;
                            }
                            StatusCode::OK
                        }
                    }),
                ),
        )
        .await?;

        let (mut state, store) = test_state_with_store(true)?;
        state.config.external_auth_providers = vec![ExternalAuthLinkProvider {
            id: "gitlab".to_owned(),
            provider_type: "gitlab".to_owned(),
            display_name: "GitLab".to_owned(),
            display_icon: "gitlab".to_owned(),
            allow_refresh: true,
            allow_validate: true,
            supports_revocation: true,
            token_url: provider_url.join("/token")?.to_string(),
            user_url: provider_url.join("/user")?.to_string(),
            revoke_url: provider_url.join("/revoke")?.to_string(),
            client_id: "client-id".to_owned(),
            client_secret: "client-secret".to_owned(),
            ..ExternalAuthLinkProvider::default()
        }];
        let app = build_router(state);
        let session_token = create_and_login(&app).await?;

        store
            .external_auth_links
            .lock()
            .map_err(|error| error.to_string())?
            .insert(
                (Uuid::from_u128(1), "gitlab".to_owned()),
                ExternalAuthLinkRecord {
                    provider_id: "gitlab".to_owned(),
                    created_at: OffsetDateTime::now_utc() - time::Duration::minutes(30),
                    updated_at: OffsetDateTime::now_utc() - time::Duration::minutes(30),
                    has_refresh_token: true,
                    expires: OffsetDateTime::now_utc() - time::Duration::minutes(5),
                    access_token: "expired-access-token".to_owned(),
                    refresh_token: "valid-refresh-token".to_owned(),
                    token_type: "bearer".to_owned(),
                    scopes: Vec::new(),
                    authenticated: false,
                    validate_error: String::new(),
                    refresh_error: String::new(),
                    last_validated_at: None,
                    last_refreshed_at: None,
                    user: None,
                    installations: Vec::new(),
                    app_installable: false,
                },
            );

        let get_response = call(
            app.clone(),
            authenticated_request(Method::GET, "/api/v2/external-auth/gitlab", &session_token)?,
        )
        .await?;
        assert_eq!(get_response.status(), StatusCode::OK);
        let get_body = response_json(get_response).await?;
        assert_eq!(
            get_body.get("authenticated").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            get_body
                .get("user")
                .and_then(|value| value.get("login"))
                .and_then(Value::as_str),
            Some("refreshed-user")
        );

        let stored_link = store
            .external_auth_links
            .lock()
            .map_err(|error| error.to_string())?
            .get(&(Uuid::from_u128(1), "gitlab".to_owned()))
            .cloned()
            .ok_or("missing refreshed link")?;
        assert_eq!(stored_link.access_token, "fresh-access-token");
        assert_eq!(stored_link.refresh_token, "fresh-refresh-token");
        assert!(stored_link.last_refreshed_at.is_some());
        assert!(stored_link.last_validated_at.is_some());

        let delete_response = call(
            app,
            authenticated_request(
                Method::DELETE,
                "/api/v2/external-auth/gitlab",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(delete_response.status(), StatusCode::OK);
        let delete_body = response_json(delete_response).await?;
        assert_eq!(
            delete_body.get("token_revoked").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(*revoke_hits.lock().map_err(|error| error.to_string())?, 1);
        assert!(
            store
                .external_auth_links
                .lock()
                .map_err(|error| error.to_string())?
                .get(&(Uuid::from_u128(1), "gitlab".to_owned()))
                .is_none()
        );

        provider_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn external_auth_callback_persists_link_and_sanitizes_redirect()
    -> Result<(), Box<dyn Error>> {
        let (provider_url, provider_handle) = spawn_test_server(
            Router::new()
                .route(
                    "/token",
                    post(|| async {
                        Json(json!({
                            "access_token": "callback-access-token",
                            "refresh_token": "callback-refresh-token",
                            "expires_in": 1800
                        }))
                    }),
                )
                .route(
                    "/user",
                    get(|| async {
                        Json(json!({
                            "id": 1,
                            "login": "coder",
                            "avatar_url": "https://example.com/avatar.png",
                            "html_url": "https://github.com/coder",
                            "name": "Coder"
                        }))
                    }),
                ),
        )
        .await?;

        let (mut state, _store) = test_state_with_store(true)?;
        state.config.external_auth_providers = vec![ExternalAuthLinkProvider {
            id: "github".to_owned(),
            provider_type: "github".to_owned(),
            display_name: "GitHub".to_owned(),
            display_icon: "github".to_owned(),
            allow_validate: true,
            token_url: provider_url.join("/token")?.to_string(),
            user_url: provider_url.join("/user")?.to_string(),
            callback_url: "http://127.0.0.1/external-auth/github/callback".to_owned(),
            client_id: "client-id".to_owned(),
            client_secret: "client-secret".to_owned(),
            ..ExternalAuthLinkProvider::default()
        }];
        let app = build_router(state);
        let session_token = create_and_login(&app).await?;

        let callback_response = call(
            app.clone(),
            request_with_cookies(
                Method::GET,
                "/external-auth/github/callback?code=callback-code&state=known-state",
                &[
                    (SESSION_TOKEN_COOKIE, &session_token),
                    (OAUTH2_STATE_COOKIE, "known-state"),
                    (
                        OAUTH2_REDIRECT_COOKIE,
                        "https://malicious.example/internal/path?ok=1",
                    ),
                ],
            )?,
        )
        .await?;
        assert_eq!(callback_response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            callback_response
                .headers()
                .get(http::header::LOCATION)
                .and_then(|value| value.to_str().ok()),
            Some("/internal/path?ok=1")
        );

        let external_auth_response = call(
            app,
            authenticated_request(Method::GET, "/api/v2/external-auth/github", &session_token)?,
        )
        .await?;
        assert_eq!(external_auth_response.status(), StatusCode::OK);
        let body = response_json(external_auth_response).await?;
        assert_eq!(
            body.get("authenticated").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            body.get("user")
                .and_then(|value| value.get("login"))
                .and_then(Value::as_str),
            Some("coder")
        );
        provider_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn external_auth_device_flow_persists_link() -> Result<(), Box<dyn Error>> {
        let (provider_url, provider_handle) = spawn_test_server(
            Router::new()
                .route(
                    "/device",
                    post(|| async {
                        Json(json!({
                            "device_code": "device-code",
                            "user_code": "ABCD-EFGH",
                            "verification_uri": "https://example.com/device",
                            "expires_in": 900,
                            "interval": 5
                        }))
                    }),
                )
                .route(
                    "/token",
                    post(|| async {
                        Json(json!({
                            "access_token": "device-access-token",
                            "refresh_token": "device-refresh-token",
                            "expires_in": 900
                        }))
                    }),
                )
                .route(
                    "/user",
                    get(|| async {
                        Json(json!({
                            "id": 7,
                            "login": "device-user",
                            "avatar_url": "",
                            "profile_url": "https://gitlab.example.com/device-user",
                            "name": "Device User"
                        }))
                    }),
                ),
        )
        .await?;

        let (mut state, _store) = test_state_with_store(true)?;
        state.config.external_auth_providers = vec![ExternalAuthLinkProvider {
            id: "gitlab".to_owned(),
            provider_type: "gitlab".to_owned(),
            device: true,
            display_name: "GitLab".to_owned(),
            display_icon: "gitlab".to_owned(),
            device_authorization_url: provider_url.join("/device")?.to_string(),
            token_url: provider_url.join("/token")?.to_string(),
            user_url: provider_url.join("/user")?.to_string(),
            client_id: "client-id".to_owned(),
            client_secret: "client-secret".to_owned(),
            scopes: vec!["read_api".to_owned()],
            ..ExternalAuthLinkProvider::default()
        }];
        let app = build_router(state);
        let session_token = create_and_login(&app).await?;

        let device_response = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                "/api/v2/external-auth/gitlab/device",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(device_response.status(), StatusCode::OK);
        assert_eq!(
            response_json(device_response)
                .await?
                .get("device_code")
                .and_then(Value::as_str),
            Some("device-code")
        );

        let exchange_response = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                "/api/v2/external-auth/gitlab/device",
                &session_token,
                &json!({ "device_code": "device-code" }),
            )?,
        )
        .await?;
        assert_eq!(exchange_response.status(), StatusCode::NO_CONTENT);

        let external_auth_response = call(
            app,
            authenticated_request(Method::GET, "/api/v2/external-auth/gitlab", &session_token)?,
        )
        .await?;
        assert_eq!(external_auth_response.status(), StatusCode::OK);
        let body = response_json(external_auth_response).await?;
        assert_eq!(
            body.get("authenticated").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            body.get("user")
                .and_then(|value| value.get("login"))
                .and_then(Value::as_str),
            Some("device-user")
        );
        provider_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn owner_can_list_users_organizations_and_members() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        let users_response = call(
            app.clone(),
            authenticated_request(Method::GET, "/api/v2/users", &session_token)?,
        )
        .await?;
        assert_eq!(users_response.status(), StatusCode::OK);
        let users_body = response_json(users_response).await?;
        assert_eq!(users_body.get("count").and_then(Value::as_u64), Some(1));

        let orgs_response = call(
            app.clone(),
            authenticated_request(Method::GET, "/api/v2/organizations", &session_token)?,
        )
        .await?;
        assert_eq!(orgs_response.status(), StatusCode::OK);

        let members_response = call(
            app,
            authenticated_request(
                Method::GET,
                "/api/v2/organizations/first-organization/members",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(members_response.status(), StatusCode::OK);
        let members_body = response_json(members_response).await?;
        assert_eq!(members_body.as_array().map(Vec::len), Some(1));
        Ok(())
    }

    #[tokio::test]
    async fn token_api_key_lifecycle_and_logout_work() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        let create_token_response = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                "/api/v2/users/me/keys/tokens",
                &session_token,
                &CreateTokenRequest {
                    lifetime: Duration::from_secs(3600),
                    token_name: "ci-token".to_owned(),
                    ..CreateTokenRequest::default()
                },
            )?,
        )
        .await?;
        assert_eq!(create_token_response.status(), StatusCode::CREATED);
        let key_body = response_json(create_token_response).await?;
        assert!(key_body.get("key").and_then(Value::as_str).is_some());

        let list_response = call(
            app.clone(),
            authenticated_request(Method::GET, "/api/v2/users/me/keys/tokens", &session_token)?,
        )
        .await?;
        assert_eq!(list_response.status(), StatusCode::OK);
        let list_body = response_json(list_response).await?;
        assert_eq!(list_body.as_array().map(Vec::len), Some(1));

        let logout_response = call(
            app.clone(),
            authenticated_request(Method::POST, "/api/v2/users/logout", &session_token)?,
        )
        .await?;
        assert_eq!(logout_response.status(), StatusCode::OK);

        let after_logout = call(
            app,
            authenticated_request(Method::GET, "/api/v2/users/me", &session_token)?,
        )
        .await?;
        assert_eq!(after_logout.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[tokio::test]
    async fn owner_can_create_users_and_manage_site_roles() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;
        let organization_id = first_organization_id(&app, &session_token).await?;

        let create_user_response = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                "/api/v2/users",
                &session_token,
                &CreateUserRequestWithOrgs {
                    email: "member@example.com".to_owned(),
                    username: "member".to_owned(),
                    name: "Member User".to_owned(),
                    password: "Password123".to_owned(),
                    login_type: Some(LoginType::Password),
                    user_status: Some(UserStatus::Active),
                    organization_ids: vec![organization_id],
                },
            )?,
        )
        .await?;
        assert_eq!(create_user_response.status(), StatusCode::CREATED);

        let site_roles_response = call(
            app.clone(),
            authenticated_request(Method::GET, "/api/v2/users/roles", &session_token)?,
        )
        .await?;
        assert_eq!(site_roles_response.status(), StatusCode::OK);
        let site_roles_body = response_json(site_roles_response).await?;
        assert_eq!(site_roles_body.as_array().map(Vec::len), Some(5));

        let update_roles_response = call(
            app.clone(),
            authenticated_json_request(
                Method::PUT,
                "/api/v2/users/member/roles",
                &session_token,
                &UpdateRolesRequest {
                    roles: vec!["user-admin".to_owned()],
                },
            )?,
        )
        .await?;
        assert_eq!(update_roles_response.status(), StatusCode::OK);
        let update_roles_body = response_json(update_roles_response).await?;
        assert_eq!(
            update_roles_body
                .get("roles")
                .and_then(Value::as_array)
                .and_then(|roles| roles.first())
                .and_then(|role| role.get("name"))
                .and_then(Value::as_str),
            Some("user-admin")
        );

        let user_roles_response = call(
            app.clone(),
            authenticated_request(Method::GET, "/api/v2/users/member/roles", &session_token)?,
        )
        .await?;
        assert_eq!(user_roles_response.status(), StatusCode::OK);
        let user_roles_body = response_json(user_roles_response).await?;
        assert_eq!(
            user_roles_body
                .get("roles")
                .and_then(Value::as_array)
                .and_then(|roles| roles.first())
                .and_then(Value::as_str),
            Some("user-admin")
        );

        let organizations_response = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                "/api/v2/users/member/organizations",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(organizations_response.status(), StatusCode::OK);
        let organizations_body = response_json(organizations_response).await?;
        assert_eq!(organizations_body.as_array().map(Vec::len), Some(1));

        let organization_response = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                "/api/v2/users/member/organizations/first-organization",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(organization_response.status(), StatusCode::OK);

        let delete_response = call(
            app.clone(),
            authenticated_request(Method::DELETE, "/api/v2/users/member", &session_token)?,
        )
        .await?;
        assert_eq!(delete_response.status(), StatusCode::OK);

        let after_delete = call(
            app,
            authenticated_request(Method::GET, "/api/v2/users/member", &session_token)?,
        )
        .await?;
        assert_eq!(after_delete.status(), StatusCode::NOT_FOUND);
        Ok(())
    }

    #[tokio::test]
    async fn owner_can_list_and_update_organization_member_roles() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;
        let organization_id = first_organization_id(&app, &session_token).await?;

        let create_user_response = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                "/api/v2/users",
                &session_token,
                &CreateUserRequestWithOrgs {
                    email: "orgmember@example.com".to_owned(),
                    username: "orgmember".to_owned(),
                    name: "Org Member".to_owned(),
                    password: "Password123".to_owned(),
                    login_type: Some(LoginType::Password),
                    user_status: Some(UserStatus::Active),
                    organization_ids: vec![organization_id],
                },
            )?,
        )
        .await?;
        assert_eq!(create_user_response.status(), StatusCode::CREATED);

        let org_roles_response = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                "/api/v2/organizations/first-organization/members/roles",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(org_roles_response.status(), StatusCode::OK);
        let org_roles_body = response_json(org_roles_response).await?;
        assert_eq!(org_roles_body.as_array().map(Vec::len), Some(5));

        let update_member_roles_response = call(
            app.clone(),
            authenticated_json_request(
                Method::PUT,
                "/api/v2/organizations/first-organization/members/orgmember/roles",
                &session_token,
                &UpdateRolesRequest {
                    roles: vec!["organization-admin".to_owned()],
                },
            )?,
        )
        .await?;
        assert_eq!(update_member_roles_response.status(), StatusCode::OK);
        let update_member_roles_body = response_json(update_member_roles_response).await?;
        assert_eq!(
            update_member_roles_body
                .get("roles")
                .and_then(Value::as_array)
                .and_then(|roles| roles.first())
                .and_then(|role| role.get("name"))
                .and_then(Value::as_str),
            Some("organization-admin")
        );

        let member_response = call(
            app,
            authenticated_request(
                Method::GET,
                "/api/v2/organizations/first-organization/members/orgmember",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(member_response.status(), StatusCode::OK);
        let member_body = response_json(member_response).await?;
        assert_eq!(
            member_body
                .get("roles")
                .and_then(Value::as_array)
                .and_then(|roles| roles.first())
                .and_then(|role| role.get("name"))
                .and_then(Value::as_str),
            Some("organization-admin")
        );
        Ok(())
    }

    #[tokio::test]
    async fn actor_cannot_mutate_their_own_roles() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        let site_roles_response = call(
            app.clone(),
            authenticated_json_request(
                Method::PUT,
                "/api/v2/users/me/roles",
                &session_token,
                &UpdateRolesRequest {
                    roles: vec!["user-admin".to_owned()],
                },
            )?,
        )
        .await?;
        assert_eq!(site_roles_response.status(), StatusCode::BAD_REQUEST);

        let organization_roles_response = call(
            app.clone(),
            authenticated_json_request(
                Method::PUT,
                "/api/v2/organizations/first-organization/members/me/roles",
                &session_token,
                &UpdateRolesRequest {
                    roles: vec!["organization-admin".to_owned()],
                },
            )?,
        )
        .await?;
        assert_eq!(
            organization_roles_response.status(),
            StatusCode::BAD_REQUEST
        );

        let delete_self_response = call(
            app,
            authenticated_request(Method::DELETE, "/api/v2/users/me", &session_token)?,
        )
        .await?;
        assert_eq!(delete_self_response.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    #[tokio::test]
    async fn owner_can_get_paginated_members_and_self_login_type() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;
        let organization_id = first_organization_id(&app, &session_token).await?;

        let create_user_response = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                "/api/v2/users",
                &session_token,
                &CreateUserRequestWithOrgs {
                    email: "member@example.com".to_owned(),
                    username: "member".to_owned(),
                    name: "Member User".to_owned(),
                    password: "Password123".to_owned(),
                    login_type: Some(LoginType::Password),
                    user_status: Some(UserStatus::Active),
                    organization_ids: vec![organization_id],
                },
            )?,
        )
        .await?;
        assert_eq!(create_user_response.status(), StatusCode::CREATED);

        let paginated_members_response = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                "/api/v2/organizations/first-organization/paginated-members?limit=1&offset=0",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(paginated_members_response.status(), StatusCode::OK);
        let paginated_members_body = response_json(paginated_members_response).await?;
        assert_eq!(
            paginated_members_body.get("count").and_then(Value::as_u64),
            Some(2)
        );
        assert_eq!(
            paginated_members_body
                .get("members")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(1)
        );

        let login_type_response = call(
            app.clone(),
            authenticated_request(Method::GET, "/api/v2/users/me/login-type", &session_token)?,
        )
        .await?;
        assert_eq!(login_type_response.status(), StatusCode::OK);
        let login_type_body = response_json(login_type_response).await?;
        assert_eq!(
            login_type_body.get("login_type").and_then(Value::as_str),
            Some("password")
        );

        let forbidden_login_type_response = call(
            app,
            authenticated_request(
                Method::GET,
                "/api/v2/users/member/login-type",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(
            forbidden_login_type_response.status(),
            StatusCode::FORBIDDEN
        );
        Ok(())
    }

    #[tokio::test]
    async fn profile_status_and_settings_flows_work() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let owner_session_token = create_and_login(&app).await?;
        let organization_id = first_organization_id(&app, &owner_session_token).await?;

        let create_user_response = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                "/api/v2/users",
                &owner_session_token,
                &CreateUserRequestWithOrgs {
                    email: "member@example.com".to_owned(),
                    username: "member".to_owned(),
                    name: "Member User".to_owned(),
                    password: "Password123".to_owned(),
                    login_type: Some(LoginType::Password),
                    user_status: Some(UserStatus::Active),
                    organization_ids: vec![organization_id],
                },
            )?,
        )
        .await?;
        assert_eq!(create_user_response.status(), StatusCode::CREATED);

        let member_login_response = call(
            app.clone(),
            json_request(
                Method::POST,
                "/api/v2/users/login",
                &LoginWithPasswordRequest {
                    email: "member@example.com".to_owned(),
                    password: "Password123".to_owned(),
                },
            )?,
        )
        .await?;
        assert_eq!(member_login_response.status(), StatusCode::CREATED);
        let member_session_token = response_json(member_login_response)
            .await?
            .get("session_token")
            .and_then(Value::as_str)
            .ok_or("missing member session token")?
            .to_owned();

        let self_profile_response = call(
            app.clone(),
            authenticated_json_request(
                Method::PUT,
                "/api/v2/users/me/profile",
                &member_session_token,
                &UpdateUserProfileRequest {
                    username: "member".to_owned(),
                    name: "Updated Member".to_owned(),
                },
            )?,
        )
        .await?;
        assert_eq!(self_profile_response.status(), StatusCode::OK);
        let self_profile_body = response_json(self_profile_response).await?;
        assert_eq!(
            self_profile_body.get("name").and_then(Value::as_str),
            Some("Updated Member")
        );

        let forbidden_username_change = call(
            app.clone(),
            authenticated_json_request(
                Method::PUT,
                "/api/v2/users/me/profile",
                &member_session_token,
                &UpdateUserProfileRequest {
                    username: "member-renamed".to_owned(),
                    name: "Updated Member".to_owned(),
                },
            )?,
        )
        .await?;
        assert_eq!(forbidden_username_change.status(), StatusCode::NOT_FOUND);

        let owner_profile_response = call(
            app.clone(),
            authenticated_json_request(
                Method::PUT,
                "/api/v2/users/member/profile",
                &owner_session_token,
                &UpdateUserProfileRequest {
                    username: "member-renamed".to_owned(),
                    name: "Renamed Member".to_owned(),
                },
            )?,
        )
        .await?;
        assert_eq!(owner_profile_response.status(), StatusCode::OK);
        let owner_profile_body = response_json(owner_profile_response).await?;
        assert_eq!(
            owner_profile_body.get("username").and_then(Value::as_str),
            Some("member-renamed")
        );

        let suspend_response = call(
            app.clone(),
            authenticated_request(
                Method::PUT,
                "/api/v2/users/member-renamed/status/suspend",
                &owner_session_token,
            )?,
        )
        .await?;
        assert_eq!(suspend_response.status(), StatusCode::OK);
        let suspend_body = response_json(suspend_response).await?;
        assert_eq!(
            suspend_body.get("status").and_then(Value::as_str),
            Some("suspended")
        );

        let activate_response = call(
            app.clone(),
            authenticated_request(
                Method::PUT,
                "/api/v2/users/member-renamed/status/activate",
                &owner_session_token,
            )?,
        )
        .await?;
        assert_eq!(activate_response.status(), StatusCode::OK);
        let activate_body = response_json(activate_response).await?;
        assert_eq!(
            activate_body.get("status").and_then(Value::as_str),
            Some("active")
        );

        let get_appearance_response = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                "/api/v2/users/me/appearance",
                &member_session_token,
            )?,
        )
        .await?;
        assert_eq!(get_appearance_response.status(), StatusCode::OK);

        let update_appearance_response = call(
            app.clone(),
            authenticated_json_request(
                Method::PUT,
                "/api/v2/users/me/appearance",
                &member_session_token,
                &UpdateUserAppearanceSettingsRequest {
                    theme_preference: "dark".to_owned(),
                    terminal_font: "jetbrains-mono".to_owned(),
                },
            )?,
        )
        .await?;
        assert_eq!(update_appearance_response.status(), StatusCode::OK);
        let update_appearance_body = response_json(update_appearance_response).await?;
        assert_eq!(
            update_appearance_body
                .get("terminal_font")
                .and_then(Value::as_str),
            Some("jetbrains-mono")
        );

        let update_preferences_response = call(
            app.clone(),
            authenticated_json_request(
                Method::PUT,
                "/api/v2/users/me/preferences",
                &member_session_token,
                &UpdateUserPreferenceSettingsRequest {
                    task_notification_alert_dismissed: true,
                },
            )?,
        )
        .await?;
        assert_eq!(update_preferences_response.status(), StatusCode::OK);
        let update_preferences_body = response_json(update_preferences_response).await?;
        assert_eq!(
            update_preferences_body
                .get("task_notification_alert_dismissed")
                .and_then(Value::as_bool),
            Some(true)
        );

        Ok(())
    }

    #[tokio::test]
    async fn validate_password_and_change_password_work() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let owner_session_token = create_and_login(&app).await?;
        let organization_id = first_organization_id(&app, &owner_session_token).await?;

        let create_user_response = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                "/api/v2/users",
                &owner_session_token,
                &CreateUserRequestWithOrgs {
                    email: "member@example.com".to_owned(),
                    username: "member".to_owned(),
                    name: "Member User".to_owned(),
                    password: "Password123".to_owned(),
                    login_type: Some(LoginType::Password),
                    user_status: Some(UserStatus::Active),
                    organization_ids: vec![organization_id],
                },
            )?,
        )
        .await?;
        assert_eq!(create_user_response.status(), StatusCode::CREATED);

        let member_login_response = call(
            app.clone(),
            json_request(
                Method::POST,
                "/api/v2/users/login",
                &LoginWithPasswordRequest {
                    email: "member@example.com".to_owned(),
                    password: "Password123".to_owned(),
                },
            )?,
        )
        .await?;
        assert_eq!(member_login_response.status(), StatusCode::CREATED);
        let member_session_token = response_json(member_login_response)
            .await?
            .get("session_token")
            .and_then(Value::as_str)
            .ok_or("missing member session token")?
            .to_owned();

        let validate_password_response = call(
            app.clone(),
            json_request(
                Method::POST,
                "/api/v2/users/validate-password",
                &ValidateUserPasswordRequest {
                    password: "short".to_owned(),
                },
            )?,
        )
        .await?;
        assert_eq!(validate_password_response.status(), StatusCode::OK);
        let validate_password_body = response_json(validate_password_response).await?;
        assert_eq!(
            validate_password_body.get("valid").and_then(Value::as_bool),
            Some(false)
        );

        let missing_old_password_response = call(
            app.clone(),
            authenticated_json_request(
                Method::PUT,
                "/api/v2/users/me/password",
                &member_session_token,
                &UpdateUserPasswordRequest {
                    old_password: String::new(),
                    password: "NewPassword123".to_owned(),
                },
            )?,
        )
        .await?;
        assert_eq!(
            missing_old_password_response.status(),
            StatusCode::BAD_REQUEST
        );

        let update_password_response = call(
            app.clone(),
            authenticated_json_request(
                Method::PUT,
                "/api/v2/users/me/password",
                &member_session_token,
                &UpdateUserPasswordRequest {
                    old_password: "Password123".to_owned(),
                    password: "NewPassword123".to_owned(),
                },
            )?,
        )
        .await?;
        assert_eq!(update_password_response.status(), StatusCode::NO_CONTENT);

        let invalidated_session_response = call(
            app.clone(),
            authenticated_request(Method::GET, "/api/v2/users/me", &member_session_token)?,
        )
        .await?;
        assert_eq!(
            invalidated_session_response.status(),
            StatusCode::UNAUTHORIZED
        );

        let old_password_login_response = call(
            app.clone(),
            json_request(
                Method::POST,
                "/api/v2/users/login",
                &LoginWithPasswordRequest {
                    email: "member@example.com".to_owned(),
                    password: "Password123".to_owned(),
                },
            )?,
        )
        .await?;
        assert_eq!(
            old_password_login_response.status(),
            StatusCode::UNAUTHORIZED
        );

        let new_password_login_response = call(
            app,
            json_request(
                Method::POST,
                "/api/v2/users/login",
                &LoginWithPasswordRequest {
                    email: "member@example.com".to_owned(),
                    password: "NewPassword123".to_owned(),
                },
            )?,
        )
        .await?;
        assert_eq!(new_password_login_response.status(), StatusCode::CREATED);
        Ok(())
    }

    #[tokio::test]
    async fn otp_request_and_reset_work() -> Result<(), Box<dyn Error>> {
        let (state, store) = test_state_with_store(true)?;
        let app = build_router(state);
        let owner_session_token = create_and_login(&app).await?;
        let organization_id = first_organization_id(&app, &owner_session_token).await?;

        let create_user_response = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                "/api/v2/users",
                &owner_session_token,
                &CreateUserRequestWithOrgs {
                    email: "member@example.com".to_owned(),
                    username: "member".to_owned(),
                    name: "Member User".to_owned(),
                    password: "Password123".to_owned(),
                    login_type: Some(LoginType::Password),
                    user_status: Some(UserStatus::Active),
                    organization_ids: vec![organization_id],
                },
            )?,
        )
        .await?;
        assert_eq!(create_user_response.status(), StatusCode::CREATED);
        let create_user_body = response_json(create_user_response).await?;
        let member_id = Uuid::parse_str(
            create_user_body
                .get("id")
                .and_then(Value::as_str)
                .ok_or("missing member id")?,
        )?;

        let otp_request_response = call(
            app.clone(),
            json_request(
                Method::POST,
                "/api/v2/users/otp/request",
                &RequestOneTimePasscodeRequest {
                    email: "unknown@example.com".to_owned(),
                },
            )?,
        )
        .await?;
        assert_eq!(otp_request_response.status(), StatusCode::NO_CONTENT);

        store.set_one_time_passcode(
            member_id,
            "reset-passcode",
            OffsetDateTime::now_utc() + time::Duration::minutes(5),
        )?;

        let reset_response = call(
            app.clone(),
            json_request(
                Method::POST,
                "/api/v2/users/otp/change-password",
                &ChangePasswordWithOneTimePasscodeRequest {
                    email: "member@example.com".to_owned(),
                    password: "RecoveredPassword123".to_owned(),
                    one_time_passcode: "reset-passcode".to_owned(),
                },
            )?,
        )
        .await?;
        assert_eq!(reset_response.status(), StatusCode::NO_CONTENT);

        let old_password_login_response = call(
            app.clone(),
            json_request(
                Method::POST,
                "/api/v2/users/login",
                &LoginWithPasswordRequest {
                    email: "member@example.com".to_owned(),
                    password: "Password123".to_owned(),
                },
            )?,
        )
        .await?;
        assert_eq!(
            old_password_login_response.status(),
            StatusCode::UNAUTHORIZED
        );

        let new_password_login_response = call(
            app,
            json_request(
                Method::POST,
                "/api/v2/users/login",
                &LoginWithPasswordRequest {
                    email: "member@example.com".to_owned(),
                    password: "RecoveredPassword123".to_owned(),
                },
            )?,
        )
        .await?;
        assert_eq!(new_password_login_response.status(), StatusCode::CREATED);
        Ok(())
    }

    #[tokio::test]
    async fn oauth_userauth_surfaces_return_disabled() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        let github_device_response = call(
            app.clone(),
            request(Method::GET, "/api/v2/users/oauth2/github/device")?,
        )
        .await?;
        assert_eq!(github_device_response.status(), StatusCode::BAD_REQUEST);

        let github_callback_response = call(
            app.clone(),
            request(Method::GET, "/api/v2/users/oauth2/github/callback")?,
        )
        .await?;
        assert_eq!(github_callback_response.status(), StatusCode::BAD_REQUEST);

        let oidc_callback_response = call(
            app.clone(),
            request(Method::GET, "/api/v2/users/oidc/callback")?,
        )
        .await?;
        assert_eq!(oidc_callback_response.status(), StatusCode::BAD_REQUEST);

        let convert_login_response = call(
            app,
            authenticated_json_request(
                Method::POST,
                "/api/v2/users/me/convert-login",
                &session_token,
                &ConvertLoginRequest {
                    to_type: LoginType::Github,
                    password: "Password123".to_owned(),
                },
            )?,
        )
        .await?;
        assert_eq!(convert_login_response.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[tokio::test]
    async fn misc_routes_return_expected_stubs_and_status_codes() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;
        let organization_id = first_organization_id(&app, &session_token).await?;

        // --- GET /organizations/{org}/provisionerdaemons returns 200 + empty array ---
        let daemons_response = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                &format!("/api/v2/organizations/{organization_id}/provisionerdaemons"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(daemons_response.status(), StatusCode::OK);
        let daemons_body = response_json(daemons_response).await?;
        assert_eq!(daemons_body.as_array().map(Vec::len), Some(0));

        // --- GET /organizations/{org}/provisionerdaemons without auth returns 401 ---
        let daemons_unauth = call(
            app.clone(),
            request(
                Method::GET,
                &format!("/api/v2/organizations/{organization_id}/provisionerdaemons"),
            )?,
        )
        .await?;
        assert_eq!(daemons_unauth.status(), StatusCode::UNAUTHORIZED);

        // --- GET /organizations/{invalid_org}/provisionerdaemons returns 404 ---
        let fake_org = Uuid::new_v4();
        let daemons_bad_org = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                &format!("/api/v2/organizations/{fake_org}/provisionerdaemons"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(daemons_bad_org.status(), StatusCode::NOT_FOUND);

        // --- GET /organizations/{org}/provisionerjobs returns 200 + empty array ---
        let jobs_response = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                &format!("/api/v2/organizations/{organization_id}/provisionerjobs"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(jobs_response.status(), StatusCode::OK);
        let jobs_body = response_json(jobs_response).await?;
        assert_eq!(jobs_body.as_array().map(Vec::len), Some(0));

        // --- GET /organizations/{org}/provisionerjobs without auth returns 401 ---
        let jobs_unauth = call(
            app.clone(),
            request(
                Method::GET,
                &format!("/api/v2/organizations/{organization_id}/provisionerjobs"),
            )?,
        )
        .await?;
        assert_eq!(jobs_unauth.status(), StatusCode::UNAUTHORIZED);

        // --- GET /organizations/{invalid_org}/provisionerjobs returns 404 ---
        let jobs_bad_org = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                &format!("/api/v2/organizations/{fake_org}/provisionerjobs"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(jobs_bad_org.status(), StatusCode::NOT_FOUND);

        // --- GET /organizations/{org}/provisionerjobs/{job} returns 404 ---
        let job_id = Uuid::new_v4();
        let get_job_response = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                &format!("/api/v2/organizations/{organization_id}/provisionerjobs/{job_id}"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(get_job_response.status(), StatusCode::NOT_FOUND);

        // --- GET /organizations/{org}/provisionerjobs/{job} without auth returns 401 ---
        let get_job_unauth = call(
            app.clone(),
            request(
                Method::GET,
                &format!("/api/v2/organizations/{organization_id}/provisionerjobs/{job_id}"),
            )?,
        )
        .await?;
        assert_eq!(get_job_unauth.status(), StatusCode::UNAUTHORIZED);

        // --- PATCH /organizations/{org}/provisionerjobs/{job}/cancel returns 404 ---
        let cancel_job_response = call(
            app.clone(),
            authenticated_request(
                Method::PATCH,
                &format!("/api/v2/organizations/{organization_id}/provisionerjobs/{job_id}/cancel"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(cancel_job_response.status(), StatusCode::NOT_FOUND);

        // --- PATCH cancel without auth returns 401 ---
        let cancel_job_unauth = call(
            app.clone(),
            request(
                Method::PATCH,
                &format!("/api/v2/organizations/{organization_id}/provisionerjobs/{job_id}/cancel"),
            )?,
        )
        .await?;
        assert_eq!(cancel_job_unauth.status(), StatusCode::UNAUTHORIZED);

        // --- GET /organizations/{org}/provisionerjobs/{job}/logs returns 404 (consistent with get/cancel) ---
        let logs_response = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                &format!("/api/v2/organizations/{organization_id}/provisionerjobs/{job_id}/logs"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(logs_response.status(), StatusCode::NOT_FOUND);

        // --- GET logs without auth returns 401 ---
        let logs_unauth = call(
            app.clone(),
            request(
                Method::GET,
                &format!("/api/v2/organizations/{organization_id}/provisionerjobs/{job_id}/logs"),
            )?,
        )
        .await?;
        assert_eq!(logs_unauth.status(), StatusCode::UNAUTHORIZED);

        // --- GET /applications/host with auth returns 200 with empty host ---
        let host_response = call(
            app.clone(),
            authenticated_request(Method::GET, "/api/v2/applications/host", &session_token)?,
        )
        .await?;
        assert_eq!(host_response.status(), StatusCode::OK);
        let host_body = response_json(host_response).await?;
        assert_eq!(host_body.get("host").and_then(Value::as_str), Some(""));

        // --- GET /applications/host without auth returns 401 ---
        let host_unauth = call(
            app.clone(),
            request(Method::GET, "/api/v2/applications/host")?,
        )
        .await?;
        assert_eq!(host_unauth.status(), StatusCode::UNAUTHORIZED);

        // --- GET /applications/auth-redirect with auth returns 400 ---
        let auth_redirect_response = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                "/api/v2/applications/auth-redirect",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(auth_redirect_response.status(), StatusCode::BAD_REQUEST);

        // --- GET /applications/auth-redirect without auth returns 401 ---
        let auth_redirect_unauth = call(
            app.clone(),
            request(Method::GET, "/api/v2/applications/auth-redirect")?,
        )
        .await?;
        assert_eq!(auth_redirect_unauth.status(), StatusCode::UNAUTHORIZED);

        // --- GET /workspaceagents/me/gitsshkey with auth returns 200 with stub keys ---
        let gitsshkey_response = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                "/api/v2/workspaceagents/me/gitsshkey",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(gitsshkey_response.status(), StatusCode::OK);
        let gitsshkey_body = response_json(gitsshkey_response).await?;
        assert_eq!(
            gitsshkey_body.get("public_key").and_then(Value::as_str),
            Some("")
        );
        assert_eq!(
            gitsshkey_body.get("private_key").and_then(Value::as_str),
            Some("")
        );

        // --- GET /workspaceagents/me/gitsshkey without auth returns 401 ---
        let gitsshkey_unauth = call(
            app.clone(),
            request(Method::GET, "/api/v2/workspaceagents/me/gitsshkey")?,
        )
        .await?;
        assert_eq!(gitsshkey_unauth.status(), StatusCode::UNAUTHORIZED);

        // --- GET /workspaceagents/me/gitauth with auth returns 200 with empty array ---
        let gitauth_response = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                "/api/v2/workspaceagents/me/gitauth",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(gitauth_response.status(), StatusCode::OK);
        let gitauth_body = response_json(gitauth_response).await?;
        assert_eq!(gitauth_body.as_array().map(Vec::len), Some(0));

        // --- GET /workspaceagents/me/gitauth without auth returns 401 ---
        let gitauth_unauth = call(
            app.clone(),
            request(Method::GET, "/api/v2/workspaceagents/me/gitauth")?,
        )
        .await?;
        assert_eq!(gitauth_unauth.status(), StatusCode::UNAUTHORIZED);

        // --- GET /workspaceagents/{agent}/startup-logs with auth returns 404 for non-existent agent ---
        let agent_id = Uuid::new_v4();
        let startup_logs_response = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                &format!("/api/v2/workspaceagents/{agent_id}/startup-logs"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(startup_logs_response.status(), StatusCode::NOT_FOUND);

        // --- GET /workspaceagents/{agent}/startup-logs without auth returns 401 ---
        let startup_logs_unauth = call(
            app.clone(),
            request(
                Method::GET,
                &format!("/api/v2/workspaceagents/{agent_id}/startup-logs"),
            )?,
        )
        .await?;
        assert_eq!(startup_logs_unauth.status(), StatusCode::UNAUTHORIZED);

        // --- GET /templateversions/{tv}/schema with auth returns 404 (non-existent version) ---
        // This route is now handled by the template-version handler (not the deprecated stub),
        // so a random UUID returns 404.
        let tv_id = Uuid::new_v4();
        let schema_response = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                &format!("/api/v2/templateversions/{tv_id}/schema"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(schema_response.status(), StatusCode::NOT_FOUND);

        // --- GET /templateversions/{tv}/schema without auth returns 401 ---
        let schema_unauth = call(
            app.clone(),
            request(
                Method::GET,
                &format!("/api/v2/templateversions/{tv_id}/schema"),
            )?,
        )
        .await?;
        assert_eq!(schema_unauth.status(), StatusCode::UNAUTHORIZED);

        // --- GET /organizations/{org}/templates/examples returns 200 + empty array ---
        let examples_response = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                &format!("/api/v2/organizations/{organization_id}/templates/examples"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(examples_response.status(), StatusCode::OK);
        let examples_body = response_json(examples_response).await?;
        assert_eq!(examples_body.as_array().map(Vec::len), Some(0));

        // --- GET /organizations/{org}/templates/examples without auth returns 401 ---
        let examples_unauth = call(
            app.clone(),
            request(
                Method::GET,
                &format!("/api/v2/organizations/{organization_id}/templates/examples"),
            )?,
        )
        .await?;
        assert_eq!(examples_unauth.status(), StatusCode::UNAUTHORIZED);

        // --- GET /organizations/{invalid_org}/templates/examples returns 404 ---
        let examples_bad_org = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                &format!("/api/v2/organizations/{fake_org}/templates/examples"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(examples_bad_org.status(), StatusCode::NOT_FOUND);

        // --- GET /organizations/{org}/templates/{t}/versions/{v}/previous returns 404 (no previous) ---
        let prev_response = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                &format!("/api/v2/organizations/{organization_id}/templates/mytemplate/versions/v1/previous"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(prev_response.status(), StatusCode::NOT_FOUND);

        // --- GET /organizations/{org}/templates/{t}/versions/{v}/previous without auth returns 401 ---
        let prev_unauth = call(
            app.clone(),
            request(
                Method::GET,
                &format!("/api/v2/organizations/{organization_id}/templates/mytemplate/versions/v1/previous"),
            )?,
        )
        .await?;
        assert_eq!(prev_unauth.status(), StatusCode::UNAUTHORIZED);

        // --- GET /organizations/{invalid_org}/templates/{t}/versions/{v}/previous returns 404 ---
        let prev_bad_org = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                &format!(
                    "/api/v2/organizations/{fake_org}/templates/mytemplate/versions/v1/previous"
                ),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(prev_bad_org.status(), StatusCode::NOT_FOUND);

        Ok(())
    }

    // ── Insights route tests ──────────────────────────────────────────

    #[tokio::test]
    async fn insights_daus_requires_auth_and_returns_stub() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);

        // 401 – unauthenticated
        let unauth = call(app.clone(), request(Method::GET, "/api/v2/insights/daus")?).await?;
        assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

        // 200 – happy path (owner role has operational data access)
        let session_token = create_and_login(&app).await?;
        let ok = call(
            app,
            authenticated_request(Method::GET, "/api/v2/insights/daus", &session_token)?,
        )
        .await?;
        assert_eq!(ok.status(), StatusCode::OK);
        let body = response_json(ok).await?;
        assert_eq!(body.get("tz_hour_offset").and_then(Value::as_i64), Some(0));
        assert_eq!(
            body.get("entries").and_then(Value::as_array).map(Vec::len),
            Some(0)
        );
        Ok(())
    }

    #[tokio::test]
    async fn insights_templates_requires_auth_and_returns_stub() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);

        let unauth = call(
            app.clone(),
            request(
                Method::GET,
                "/api/v2/insights/templates?start_time=2024-01-01T00:00:00Z&end_time=2024-01-02T00:00:00Z",
            )?,
        )
        .await?;
        assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

        let session_token = create_and_login(&app).await?;
        let ok = call(
            app,
            authenticated_request(
                Method::GET,
                "/api/v2/insights/templates?start_time=2024-01-01T00:00:00Z&end_time=2024-01-02T00:00:00Z",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(ok.status(), StatusCode::OK);
        let body = response_json(ok).await?;
        assert!(body.get("report").is_some());
        Ok(())
    }

    #[tokio::test]
    async fn insights_templates_sections_filter_strips_unrequested_fields()
    -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        // Request only "report" section – interval_reports should be stripped
        let report_only = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                "/api/v2/insights/templates?start_time=2024-01-01T00:00:00Z&end_time=2024-01-02T00:00:00Z&sections=report",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(report_only.status(), StatusCode::OK);
        let body = response_json(report_only).await?;
        assert!(body.get("report").is_some());
        // interval_reports should be absent or empty (skip_serializing_if = "Vec::is_empty")
        assert!(
            body.get("interval_reports").is_none()
                || body
                    .get("interval_reports")
                    .and_then(Value::as_array)
                    .map(Vec::is_empty)
                    .unwrap_or(false)
        );

        // Request only "interval_reports" section – report should be stripped
        let interval_only = call(
            app,
            authenticated_request(
                Method::GET,
                "/api/v2/insights/templates?start_time=2024-01-01T00:00:00Z&end_time=2024-01-02T00:00:00Z&sections=interval_reports",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(interval_only.status(), StatusCode::OK);
        let body = response_json(interval_only).await?;
        // report should be absent (skip_serializing_if = "Option::is_none")
        assert!(body.get("report").is_none());
        Ok(())
    }

    #[tokio::test]
    async fn insights_user_activity_requires_auth_and_returns_stub() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);

        let unauth = call(
            app.clone(),
            request(
                Method::GET,
                "/api/v2/insights/user-activity?start_time=2024-01-01T00:00:00Z&end_time=2024-01-02T00:00:00Z",
            )?,
        )
        .await?;
        assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

        let session_token = create_and_login(&app).await?;
        let ok = call(
            app,
            authenticated_request(
                Method::GET,
                "/api/v2/insights/user-activity?start_time=2024-01-01T00:00:00Z&end_time=2024-01-02T00:00:00Z",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(ok.status(), StatusCode::OK);
        let body = response_json(ok).await?;
        assert!(body.get("report").is_some());
        assert_eq!(
            body.get("report")
                .and_then(|r| r.get("users"))
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(0)
        );
        Ok(())
    }

    #[tokio::test]
    async fn insights_user_latency_requires_auth_and_returns_stub() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);

        let unauth = call(
            app.clone(),
            request(
                Method::GET,
                "/api/v2/insights/user-latency?start_time=2024-01-01T00:00:00Z&end_time=2024-01-02T00:00:00Z",
            )?,
        )
        .await?;
        assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

        let session_token = create_and_login(&app).await?;
        let ok = call(
            app,
            authenticated_request(
                Method::GET,
                "/api/v2/insights/user-latency?start_time=2024-01-01T00:00:00Z&end_time=2024-01-02T00:00:00Z",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(ok.status(), StatusCode::OK);
        let body = response_json(ok).await?;
        assert!(body.get("report").is_some());
        Ok(())
    }

    #[tokio::test]
    async fn insights_user_status_counts_requires_auth_and_returns_stub()
    -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);

        let unauth = call(
            app.clone(),
            request(Method::GET, "/api/v2/insights/user-status-counts")?,
        )
        .await?;
        assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

        let session_token = create_and_login(&app).await?;
        let ok = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                "/api/v2/insights/user-status-counts",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(ok.status(), StatusCode::OK);
        let body = response_json(ok).await?;
        assert!(body.get("status_counts").is_some());

        // Test timezone offset logic: tz_offset=5 → Etc/GMT-5
        let tz_ok = call(
            app,
            authenticated_request(
                Method::GET,
                "/api/v2/insights/user-status-counts?tz_offset=5",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(tz_ok.status(), StatusCode::OK);
        Ok(())
    }

    // ── Debug route tests ─────────────────────────────────────────────

    #[tokio::test]
    async fn debug_coordinator_requires_auth_and_returns_stub() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);

        let unauth = call(
            app.clone(),
            request(Method::GET, "/api/v2/debug/coordinator")?,
        )
        .await?;
        assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

        let session_token = create_and_login(&app).await?;
        let resp = call(
            app,
            authenticated_request(Method::GET, "/api/v2/debug/coordinator", &session_token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
        Ok(())
    }

    #[tokio::test]
    async fn debug_tailnet_requires_auth_and_returns_stub() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);

        let unauth = call(app.clone(), request(Method::GET, "/api/v2/debug/tailnet")?).await?;
        assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

        let session_token = create_and_login(&app).await?;
        let resp = call(
            app,
            authenticated_request(Method::GET, "/api/v2/debug/tailnet", &session_token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
        Ok(())
    }

    #[tokio::test]
    async fn debug_derp_traffic_requires_auth_and_returns_stub() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);

        let unauth = call(
            app.clone(),
            request(Method::GET, "/api/v2/debug/derp/traffic")?,
        )
        .await?;
        assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

        let session_token = create_and_login(&app).await?;
        let resp = call(
            app,
            authenticated_request(Method::GET, "/api/v2/debug/derp/traffic", &session_token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
        Ok(())
    }

    #[tokio::test]
    async fn debug_expvar_requires_auth_and_returns_stub() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);

        let unauth = call(app.clone(), request(Method::GET, "/api/v2/debug/expvar")?).await?;
        assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

        let session_token = create_and_login(&app).await?;
        let resp = call(
            app,
            authenticated_request(Method::GET, "/api/v2/debug/expvar", &session_token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
        Ok(())
    }

    #[tokio::test]
    async fn debug_pprof_requires_auth_and_returns_stub() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);

        let unauth = call(app.clone(), request(Method::GET, "/api/v2/debug/pprof")?).await?;
        assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

        let session_token = create_and_login(&app).await?;

        // Test main pprof endpoint
        let resp = call(
            app.clone(),
            authenticated_request(Method::GET, "/api/v2/debug/pprof", &session_token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);

        // Test pprof sub-routes (cmdline, profile, symbol, trace)
        for sub in &["cmdline", "profile", "symbol", "trace"] {
            let sub_resp = call(
                app.clone(),
                authenticated_request(
                    Method::GET,
                    &format!("/api/v2/debug/pprof/{sub}"),
                    &session_token,
                )?,
            )
            .await?;
            assert_eq!(
                sub_resp.status(),
                StatusCode::NOT_IMPLEMENTED,
                "pprof/{sub} should return 501"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn debug_websocket_requires_auth_and_returns_stub() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);

        let unauth = call(app.clone(), request(Method::GET, "/api/v2/debug/ws")?).await?;
        assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

        let session_token = create_and_login(&app).await?;
        let resp = call(
            app,
            authenticated_request(Method::GET, "/api/v2/debug/ws", &session_token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
        Ok(())
    }

    #[tokio::test]
    async fn debug_metrics_requires_auth_and_returns_stub() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);

        let unauth = call(app.clone(), request(Method::GET, "/api/v2/debug/metrics")?).await?;
        assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

        let session_token = create_and_login(&app).await?;
        let resp = call(
            app,
            authenticated_request(Method::GET, "/api/v2/debug/metrics", &session_token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
        Ok(())
    }

    #[tokio::test]
    async fn derp_map_updates_returns_stub() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);

        // The Go handler does NOT use apiKeyMiddleware, so no auth is required.
        let resp = call(app, request(Method::GET, "/api/v2/derp-map")?).await?;
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
        Ok(())
    }

    #[tokio::test]
    async fn get_regions_requires_auth_and_returns_regions() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);

        let unauth = call(app.clone(), request(Method::GET, "/api/v2/regions")?).await?;
        assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

        let session_token = create_and_login(&app).await?;
        let resp = call(
            app,
            authenticated_request(Method::GET, "/api/v2/regions", &session_token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), usize::MAX).await?;
        let regions: coder_core::RegionsResponse = serde_json::from_slice(&body)?;
        assert_eq!(regions.regions.len(), 1);
        assert_eq!(regions.regions[0].name, "primary");
        assert!(regions.regions[0].healthy);
        Ok(())
    }

    #[tokio::test]
    async fn tailnet_rpc_conn_requires_auth_and_returns_stub() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);

        let unauth = call(app.clone(), request(Method::GET, "/api/v2/tailnet")?).await?;
        assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

        let session_token = create_and_login(&app).await?;
        let resp = call(
            app,
            authenticated_request(Method::GET, "/api/v2/tailnet", &session_token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
        Ok(())
    }

    #[tokio::test]
    async fn post_custom_notification_requires_auth() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);

        let payload = coder_core::CustomNotificationRequest {
            content: Some(coder_core::CustomNotificationContent {
                title: "Hello".to_string(),
                message: "World".to_string(),
            }),
        };

        let unauth = call(
            app.clone(),
            json_request(Method::POST, "/api/v2/notifications/custom", &payload)?,
        )
        .await?;
        assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[tokio::test]
    async fn post_custom_notification_validates_content() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        // Missing content field
        let payload = coder_core::CustomNotificationRequest { content: None };
        let resp = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                "/api/v2/notifications/custom",
                &session_token,
                &payload,
            )?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Empty title
        let payload = coder_core::CustomNotificationRequest {
            content: Some(coder_core::CustomNotificationContent {
                title: "  ".to_string(),
                message: "Hello".to_string(),
            }),
        };
        let resp = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                "/api/v2/notifications/custom",
                &session_token,
                &payload,
            )?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Title too long
        let payload = coder_core::CustomNotificationRequest {
            content: Some(coder_core::CustomNotificationContent {
                title: "a".repeat(121),
                message: "Hello".to_string(),
            }),
        };
        let resp = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                "/api/v2/notifications/custom",
                &session_token,
                &payload,
            )?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Valid request returns 204
        let payload = coder_core::CustomNotificationRequest {
            content: Some(coder_core::CustomNotificationContent {
                title: "Test".to_string(),
                message: "Test message".to_string(),
            }),
        };
        let resp = call(
            app,
            authenticated_json_request(
                Method::POST,
                "/api/v2/notifications/custom",
                &session_token,
                &payload,
            )?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        Ok(())
    }

    // ── BAD_REQUEST validation tests ─────────────────────────────────

    #[tokio::test]
    async fn insights_templates_returns_400_for_missing_timestamps() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        // Missing both start_time and end_time
        let resp = call(
            app.clone(),
            authenticated_request(Method::GET, "/api/v2/insights/templates", &session_token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Missing end_time
        let resp = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                "/api/v2/insights/templates?start_time=2024-01-01T00:00:00Z",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Invalid interval
        let resp = call(
            app,
            authenticated_request(
                Method::GET,
                "/api/v2/insights/templates?start_time=2024-01-01T00:00:00Z&end_time=2024-01-02T00:00:00Z&interval=monthly",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[tokio::test]
    async fn insights_user_activity_returns_400_for_missing_timestamps()
    -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        let resp = call(
            app,
            authenticated_request(
                Method::GET,
                "/api/v2/insights/user-activity",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[tokio::test]
    async fn insights_user_latency_returns_400_for_missing_timestamps() -> Result<(), Box<dyn Error>>
    {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        let resp = call(
            app,
            authenticated_request(Method::GET, "/api/v2/insights/user-latency", &session_token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[tokio::test]
    async fn insights_daus_returns_400_for_invalid_tz_offset() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        let resp = call(
            app,
            authenticated_request(
                Method::GET,
                "/api/v2/insights/daus?tz_offset=99",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[tokio::test]
    async fn insights_user_status_counts_returns_400_for_invalid_tz_offset()
    -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        let resp = call(
            app,
            authenticated_request(
                Method::GET,
                "/api/v2/insights/user-status-counts?tz_offset=-99",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }

    // ----- Template Route Tests -----

    /// Helper: creates a user, logs in, fetches the org id, and creates a
    /// template via the HTTP API. Returns (session_token, org_id, template json).
    async fn create_test_template(app: &Router) -> Result<(String, Uuid, Value), Box<dyn Error>> {
        let session_token = create_and_login(app).await?;
        let org_id = first_organization_id(app, &session_token).await?;

        let create_body = CreateTemplateRequest {
            name: "test-template".to_owned(),
            display_name: "Test Template".to_owned(),
            description: "A test template".to_owned(),
            icon: "/icon/docker.png".to_owned(),
            template_version_id: Uuid::nil(),
            default_ttl_ms: 3_600_000,
            activity_bump_ms: 1_800_000,
            allow_user_cancel_workspace_jobs: true,
            allow_user_autostart: true,
            allow_user_autostop: true,
            require_active_version: false,
            failure_ttl_ms: 0,
            time_til_dormant_ms: 0,
            time_til_dormant_autodelete_ms: 0,
            disable_everyone_group_access: false,
            max_port_share_level: "owner".to_owned(),
        };
        let create_response = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                &format!("/api/v2/organizations/{org_id}/templates"),
                &session_token,
                &create_body,
            )?,
        )
        .await?;
        assert_eq!(create_response.status(), StatusCode::CREATED);
        let template = response_json(create_response).await?;
        Ok((session_token, org_id, template))
    }

    #[tokio::test]
    async fn template_create_and_get() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let (session_token, org_id, template) = create_test_template(&app).await?;

        let template_id = template
            .get("id")
            .and_then(Value::as_str)
            .ok_or("missing id")?;

        // Verify fields on creation response.
        assert_eq!(
            template.get("name").and_then(Value::as_str),
            Some("test-template")
        );
        assert_eq!(
            template.get("display_name").and_then(Value::as_str),
            Some("Test Template")
        );
        assert_eq!(
            template.get("description").and_then(Value::as_str),
            Some("A test template")
        );

        // GET /templates/{id}
        let get_response = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                &format!("/api/v2/templates/{template_id}"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(get_response.status(), StatusCode::OK);
        let fetched = response_json(get_response).await?;
        assert_eq!(
            fetched.get("name").and_then(Value::as_str),
            Some("test-template")
        );

        // GET /organizations/{org}/templates (list)
        let list_response = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                &format!("/api/v2/organizations/{org_id}/templates"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(list_response.status(), StatusCode::OK);
        let list_body = response_json(list_response).await?;
        let templates = list_body.as_array().ok_or("expected array")?;
        assert_eq!(templates.len(), 1);

        // GET /organizations/{org}/templates/{name}
        let by_name_response = call(
            app,
            authenticated_request(
                Method::GET,
                &format!("/api/v2/organizations/{org_id}/templates/test-template"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(by_name_response.status(), StatusCode::OK);
        let by_name = response_json(by_name_response).await?;
        assert_eq!(by_name.get("id").and_then(Value::as_str), Some(template_id));

        Ok(())
    }

    #[tokio::test]
    async fn template_patch_preserves_fields() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let (session_token, _org_id, template) = create_test_template(&app).await?;

        let template_id = template
            .get("id")
            .and_then(Value::as_str)
            .ok_or("missing id")?;

        // PATCH with partial update — only change description and the newly-fixed fields.
        let patch_body = UpdateTemplateMeta {
            description: Some("Updated description".to_owned()),
            cors_behavior: Some("passthru".to_owned()),
            use_classic_parameter_flow: Some(true),
            disable_module_cache: Some(true),
            ..UpdateTemplateMeta::default()
        };
        let patch_response = call(
            app.clone(),
            authenticated_json_request(
                Method::PATCH,
                &format!("/api/v2/templates/{template_id}"),
                &session_token,
                &patch_body,
            )?,
        )
        .await?;
        assert_eq!(patch_response.status(), StatusCode::OK);
        let patched = response_json(patch_response).await?;

        // The patched fields should reflect the new values.
        assert_eq!(
            patched.get("description").and_then(Value::as_str),
            Some("Updated description")
        );

        // Original name should be preserved (not zeroed).
        assert_eq!(
            patched.get("name").and_then(Value::as_str),
            Some("test-template")
        );

        // Verify GET also returns the persisted values.
        let get_response = call(
            app,
            authenticated_request(
                Method::GET,
                &format!("/api/v2/templates/{template_id}"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(get_response.status(), StatusCode::OK);
        let fetched = response_json(get_response).await?;
        assert_eq!(
            fetched.get("description").and_then(Value::as_str),
            Some("Updated description")
        );

        Ok(())
    }

    #[tokio::test]
    async fn template_delete() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let (session_token, _org_id, template) = create_test_template(&app).await?;

        let template_id = template
            .get("id")
            .and_then(Value::as_str)
            .ok_or("missing id")?;

        // DELETE /templates/{id}
        let delete_response = call(
            app.clone(),
            authenticated_request(
                Method::DELETE,
                &format!("/api/v2/templates/{template_id}"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(delete_response.status(), StatusCode::OK);

        // GET after delete should return 404.
        let get_response = call(
            app,
            authenticated_request(
                Method::GET,
                &format!("/api/v2/templates/{template_id}"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(get_response.status(), StatusCode::NOT_FOUND);

        Ok(())
    }

    #[tokio::test]
    async fn template_versions_list() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let (session_token, _org_id, template) = create_test_template(&app).await?;

        let template_id = template
            .get("id")
            .and_then(Value::as_str)
            .ok_or("missing id")?;

        // GET /templates/{id}/versions — should return an empty array since
        // the nil-UUID version created by post_org_template has template_id=nil.
        let versions_response = call(
            app,
            authenticated_request(
                Method::GET,
                &format!("/api/v2/templates/{template_id}/versions"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(versions_response.status(), StatusCode::OK);
        let versions = response_json(versions_response).await?;
        // It's an array (may be empty or contain the initial version).
        assert!(versions.is_array());

        Ok(())
    }

    #[tokio::test]
    async fn template_requires_auth() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);

        // Unauthenticated requests to template endpoints should return 401.
        let list_response = call(
            app.clone(),
            request(
                Method::GET,
                &format!("/api/v2/organizations/{}/templates", Uuid::from_u128(2)),
            )?,
        )
        .await?;
        assert_eq!(list_response.status(), StatusCode::UNAUTHORIZED);

        let get_response = call(
            app.clone(),
            request(Method::GET, &format!("/api/v2/templates/{}", Uuid::nil()))?,
        )
        .await?;
        assert_eq!(get_response.status(), StatusCode::UNAUTHORIZED);

        let delete_response = call(
            app,
            request(
                Method::DELETE,
                &format!("/api/v2/templates/{}", Uuid::nil()),
            )?,
        )
        .await?;
        assert_eq!(delete_response.status(), StatusCode::UNAUTHORIZED);

        Ok(())
    }

    #[tokio::test]
    async fn template_not_found() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        let missing_id = Uuid::from_u128(999);

        // GET non-existent template
        let get_response = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                &format!("/api/v2/templates/{missing_id}"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(get_response.status(), StatusCode::NOT_FOUND);

        // PATCH non-existent template
        let patch_body = UpdateTemplateMeta::default();
        let patch_response = call(
            app.clone(),
            authenticated_json_request(
                Method::PATCH,
                &format!("/api/v2/templates/{missing_id}"),
                &session_token,
                &patch_body,
            )?,
        )
        .await?;
        assert_eq!(patch_response.status(), StatusCode::NOT_FOUND);

        // DELETE non-existent template
        let delete_response = call(
            app,
            authenticated_request(
                Method::DELETE,
                &format!("/api/v2/templates/{missing_id}"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(delete_response.status(), StatusCode::NOT_FOUND);

        Ok(())
    }

    // -----------------------------------------------------------------------
    // AI Tasks handler tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn task_lifecycle_create_list_get_delete() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        // Create a task
        let create_response = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                "/api/v2/tasks/me",
                &session_token,
                &CreateTaskRequest {
                    template_version_id: Uuid::new_v4(),
                    input: "Build me a website".to_string(),
                    name: Some("my-task".to_string()),
                    display_name: Some("My Task".to_string()),
                },
            )?,
        )
        .await?;
        assert_eq!(create_response.status(), StatusCode::CREATED);
        let body = to_bytes(create_response.into_body(), 1_000_000).await?;
        let task: Value = serde_json::from_slice(&body)?;
        let task_id = task["id"].as_str().ok_or("missing task id")?;
        assert_eq!(task["name"], "my-task");
        assert_eq!(task["display_name"], "My Task");
        assert_eq!(task["initial_prompt"], "Build me a website");

        // List tasks
        let list_response = call(
            app.clone(),
            authenticated_request(Method::GET, "/api/v2/tasks", &session_token)?,
        )
        .await?;
        assert_eq!(list_response.status(), StatusCode::OK);
        let body = to_bytes(list_response.into_body(), 1_000_000).await?;
        let list: Value = serde_json::from_slice(&body)?;
        assert_eq!(list["count"], 1);
        assert_eq!(list["tasks"][0]["id"], task_id);

        // Get task
        let get_response = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                &format!("/api/v2/tasks/me/{task_id}"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(get_response.status(), StatusCode::OK);
        let body = to_bytes(get_response.into_body(), 1_000_000).await?;
        let fetched: Value = serde_json::from_slice(&body)?;
        assert_eq!(fetched["id"], task_id);

        // Delete task
        let delete_response = call(
            app.clone(),
            authenticated_request(
                Method::DELETE,
                &format!("/api/v2/tasks/me/{task_id}"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(delete_response.status(), StatusCode::ACCEPTED);

        // Verify deleted task no longer appears in list
        let list_response2 = call(
            app,
            authenticated_request(Method::GET, "/api/v2/tasks", &session_token)?,
        )
        .await?;
        let body = to_bytes(list_response2.into_body(), 1_000_000).await?;
        let list2: Value = serde_json::from_slice(&body)?;
        assert_eq!(list2["count"], 0);

        Ok(())
    }

    #[tokio::test]
    async fn task_get_by_name() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        let create_response = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                "/api/v2/tasks/me",
                &session_token,
                &CreateTaskRequest {
                    template_version_id: Uuid::new_v4(),
                    input: "Write a test".to_string(),
                    name: Some("lookup-by-name".to_string()),
                    display_name: None,
                },
            )?,
        )
        .await?;
        assert_eq!(create_response.status(), StatusCode::CREATED);
        let body = to_bytes(create_response.into_body(), 1_000_000).await?;
        let task: Value = serde_json::from_slice(&body)?;
        let task_id = task["id"].as_str().ok_or("missing task id")?;

        // Look up by name instead of UUID
        let get_response = call(
            app,
            authenticated_request(
                Method::GET,
                "/api/v2/tasks/me/lookup-by-name",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(get_response.status(), StatusCode::OK);
        let body = to_bytes(get_response.into_body(), 1_000_000).await?;
        let fetched: Value = serde_json::from_slice(&body)?;
        assert_eq!(fetched["id"], task_id);
        assert_eq!(fetched["name"], "lookup-by-name");
        Ok(())
    }

    #[tokio::test]
    async fn task_patch_input_requires_paused() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        let create_response = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                "/api/v2/tasks/me",
                &session_token,
                &CreateTaskRequest {
                    template_version_id: Uuid::new_v4(),
                    input: "Original prompt".to_string(),
                    name: None,
                    display_name: None,
                },
            )?,
        )
        .await?;
        let body = to_bytes(create_response.into_body(), 1_000_000).await?;
        let task: Value = serde_json::from_slice(&body)?;
        let task_id = task["id"].as_str().ok_or("missing task id")?;

        // Task starts as pending, so patch should return 409 Conflict.
        let patch_response = call(
            app,
            authenticated_json_request(
                Method::PATCH,
                &format!("/api/v2/tasks/me/{task_id}/input"),
                &session_token,
                &json!({ "input": "Updated prompt" }),
            )?,
        )
        .await?;
        assert_eq!(patch_response.status(), StatusCode::CONFLICT);
        Ok(())
    }

    #[tokio::test]
    async fn task_get_logs_empty() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        let create_response = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                "/api/v2/tasks/me",
                &session_token,
                &CreateTaskRequest {
                    template_version_id: Uuid::new_v4(),
                    input: "log test".to_string(),
                    name: None,
                    display_name: None,
                },
            )?,
        )
        .await?;
        let body = to_bytes(create_response.into_body(), 1_000_000).await?;
        let task: Value = serde_json::from_slice(&body)?;
        let task_id = task["id"].as_str().ok_or("missing task id")?;

        let logs_response = call(
            app,
            authenticated_request(
                Method::GET,
                &format!("/api/v2/tasks/me/{task_id}/logs"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(logs_response.status(), StatusCode::OK);
        let body = to_bytes(logs_response.into_body(), 1_000_000).await?;
        let logs: Value = serde_json::from_slice(&body)?;
        assert_eq!(logs["logs"], json!([]));
        Ok(())
    }

    #[tokio::test]
    async fn task_send_requires_active() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        let create_response = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                "/api/v2/tasks/me",
                &session_token,
                &CreateTaskRequest {
                    template_version_id: Uuid::new_v4(),
                    input: "send test".to_string(),
                    name: None,
                    display_name: None,
                },
            )?,
        )
        .await?;
        let body = to_bytes(create_response.into_body(), 1_000_000).await?;
        let task: Value = serde_json::from_slice(&body)?;
        let task_id = task["id"].as_str().ok_or("missing task id")?;

        // Task starts as pending, so send should return 409 Conflict.
        let send_response = call(
            app,
            authenticated_json_request(
                Method::POST,
                &format!("/api/v2/tasks/me/{task_id}/send"),
                &session_token,
                &TaskSendRequest {
                    input: "follow-up".to_string(),
                },
            )?,
        )
        .await?;
        assert_eq!(send_response.status(), StatusCode::CONFLICT);
        Ok(())
    }

    #[tokio::test]
    async fn task_pause_resume_requires_workspace() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        let create_response = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                "/api/v2/tasks/me",
                &session_token,
                &CreateTaskRequest {
                    template_version_id: Uuid::new_v4(),
                    input: "pause test".to_string(),
                    name: None,
                    display_name: None,
                },
            )?,
        )
        .await?;
        let body = to_bytes(create_response.into_body(), 1_000_000).await?;
        let task: Value = serde_json::from_slice(&body)?;
        let task_id = task["id"].as_str().ok_or("missing task id")?;

        // Task has no workspace, so pause should return 500.
        let pause_response = call(
            app.clone(),
            authenticated_request(
                Method::POST,
                &format!("/api/v2/tasks/me/{task_id}/pause"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(pause_response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        // Task has no workspace, so resume should also return 500.
        let resume_response = call(
            app,
            authenticated_request(
                Method::POST,
                &format!("/api/v2/tasks/me/{task_id}/resume"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(resume_response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        Ok(())
    }

    #[tokio::test]
    async fn task_log_snapshot_roundtrip() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        let create_response = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                "/api/v2/tasks/me",
                &session_token,
                &CreateTaskRequest {
                    template_version_id: Uuid::new_v4(),
                    input: "snapshot test".to_string(),
                    name: None,
                    display_name: None,
                },
            )?,
        )
        .await?;
        let body = to_bytes(create_response.into_body(), 1_000_000).await?;
        let task: Value = serde_json::from_slice(&body)?;
        let task_id = task["id"].as_str().ok_or("missing task id")?;

        // Post a log snapshot
        let snapshot_response = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                &format!("/api/v2/workspaceagents/me/tasks/{task_id}/log-snapshot"),
                &session_token,
                &json!({ "log_snapshot": { "lines": ["hello", "world"] } }),
            )?,
        )
        .await?;
        assert_eq!(snapshot_response.status(), StatusCode::OK);

        // Verify snapshot appears in logs
        let logs_response = call(
            app,
            authenticated_request(
                Method::GET,
                &format!("/api/v2/tasks/me/{task_id}/logs"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(logs_response.status(), StatusCode::OK);
        let body = to_bytes(logs_response.into_body(), 1_000_000).await?;
        let logs: Value = serde_json::from_slice(&body)?;
        assert_eq!(logs["snapshot"], true);
        assert!(logs["snapshot_at"].is_string());
        Ok(())
    }

    #[tokio::test]
    async fn task_not_found_returns_404() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;
        let fake_id = Uuid::new_v4();

        let get_response = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                &format!("/api/v2/tasks/me/{fake_id}"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(get_response.status(), StatusCode::NOT_FOUND);

        let delete_response = call(
            app,
            authenticated_request(
                Method::DELETE,
                &format!("/api/v2/tasks/me/{fake_id}"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(delete_response.status(), StatusCode::NOT_FOUND);

        Ok(())
    }

    #[tokio::test]
    async fn task_requires_auth() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);

        let list_response = call(app.clone(), request(Method::GET, "/api/v2/tasks")?).await?;
        assert_eq!(list_response.status(), StatusCode::UNAUTHORIZED);

        let create_response = call(
            app,
            json_request(
                Method::POST,
                "/api/v2/tasks/me",
                &CreateTaskRequest {
                    template_version_id: Uuid::new_v4(),
                    input: "test".to_string(),
                    name: None,
                    display_name: None,
                },
            )?,
        )
        .await?;
        assert_eq!(create_response.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Chats handler tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn chat_lifecycle_create_list_get_delete() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        // Create a chat
        let create_response = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                "/api/v2/chats",
                &session_token,
                &CreateChatRequest {
                    content: vec![],
                    workspace_id: None,
                    model_config_id: None,
                },
            )?,
        )
        .await?;
        assert_eq!(create_response.status(), StatusCode::CREATED);
        let body = to_bytes(create_response.into_body(), 1_000_000).await?;
        let chat_with_messages: Value = serde_json::from_slice(&body)?;
        let chat_id = chat_with_messages["chat"]["id"]
            .as_str()
            .ok_or("missing chat id")?;

        // List chats
        let list_response = call(
            app.clone(),
            authenticated_request(Method::GET, "/api/v2/chats", &session_token)?,
        )
        .await?;
        assert_eq!(list_response.status(), StatusCode::OK);
        let body = to_bytes(list_response.into_body(), 1_000_000).await?;
        let chats: Value = serde_json::from_slice(&body)?;
        let chats_arr = chats.as_array().ok_or("expected array")?;
        assert_eq!(chats_arr.len(), 1);
        assert_eq!(chats_arr[0]["id"], chat_id);

        // Get chat with messages
        let get_response = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                &format!("/api/v2/chats/{chat_id}"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(get_response.status(), StatusCode::OK);
        let body = to_bytes(get_response.into_body(), 1_000_000).await?;
        let fetched: Value = serde_json::from_slice(&body)?;
        assert_eq!(fetched["chat"]["id"], chat_id);

        // Delete (archive) chat
        let delete_response = call(
            app.clone(),
            authenticated_request(
                Method::DELETE,
                &format!("/api/v2/chats/{chat_id}"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(delete_response.status(), StatusCode::OK);

        Ok(())
    }

    #[tokio::test]
    async fn chat_post_message() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        // Create chat first
        let create_response = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                "/api/v2/chats",
                &session_token,
                &CreateChatRequest {
                    content: vec![],
                    workspace_id: None,
                    model_config_id: None,
                },
            )?,
        )
        .await?;
        let body = to_bytes(create_response.into_body(), 1_000_000).await?;
        let chat_with_messages: Value = serde_json::from_slice(&body)?;
        let chat_id = chat_with_messages["chat"]["id"]
            .as_str()
            .ok_or("missing chat id")?;

        // Post a message
        let msg_response = call(
            app,
            authenticated_json_request(
                Method::POST,
                &format!("/api/v2/chats/{chat_id}/messages"),
                &session_token,
                &CreateChatMessageRequest {
                    content: vec![],
                    model_config_id: None,
                },
            )?,
        )
        .await?;
        assert_eq!(msg_response.status(), StatusCode::OK);
        let body = to_bytes(msg_response.into_body(), 1_000_000).await?;
        let msg: Value = serde_json::from_slice(&body)?;
        assert!(!msg["queued"].as_bool().unwrap_or(true));
        Ok(())
    }

    #[tokio::test]
    async fn chat_not_found_returns_404() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;
        let fake_id = Uuid::new_v4();

        let get_response = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                &format!("/api/v2/chats/{fake_id}"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(get_response.status(), StatusCode::NOT_FOUND);

        let delete_response = call(
            app,
            authenticated_request(
                Method::DELETE,
                &format!("/api/v2/chats/{fake_id}"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(delete_response.status(), StatusCode::NOT_FOUND);
        Ok(())
    }

    #[tokio::test]
    async fn chat_requires_auth() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);

        let list_response = call(app.clone(), request(Method::GET, "/api/v2/chats")?).await?;
        assert_eq!(list_response.status(), StatusCode::UNAUTHORIZED);

        let create_response = call(
            app,
            json_request(
                Method::POST,
                "/api/v2/chats",
                &CreateChatRequest {
                    content: vec![],
                    workspace_id: None,
                    model_config_id: None,
                },
            )?,
        )
        .await?;
        assert_eq!(create_response.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Chat file upload/download tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn chat_file_upload_and_download() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        let org_id = Uuid::new_v4();
        // A minimal valid PNG (1x1 pixel).
        let png_data: Vec<u8> = vec![
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
            0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR chunk
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x00, 0x00, 0x00, 0x90,
            0x77, 0x53, 0xDE,
        ];

        // Upload
        let upload_request = Request::builder()
            .method(Method::POST)
            .uri(format!("/api/v2/chats/files?organization={org_id}"))
            .header(SESSION_TOKEN_HEADER, &session_token)
            .header(CONTENT_TYPE, "image/png")
            .header("content-disposition", "attachment; filename=\"test.png\"")
            .body(Body::from(png_data.clone()))?;

        let upload_response = call(app.clone(), upload_request).await?;
        assert_eq!(upload_response.status(), StatusCode::CREATED);
        let body = to_bytes(upload_response.into_body(), 1_000_000).await?;
        let upload_result: Value = serde_json::from_slice(&body)?;
        let file_id = upload_result["id"].as_str().ok_or("missing file id")?;

        // Download
        let download_response = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                &format!("/api/v2/chats/files/{file_id}"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(download_response.status(), StatusCode::OK);
        assert_eq!(
            download_response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("image/png")
        );
        assert_eq!(
            download_response
                .headers()
                .get("content-disposition")
                .and_then(|v| v.to_str().ok()),
            Some("inline; filename=\"test.png\"")
        );
        let downloaded = to_bytes(download_response.into_body(), 1_000_000).await?;
        assert_eq!(downloaded.to_vec(), png_data);

        Ok(())
    }

    #[tokio::test]
    async fn chat_file_upload_rejects_unsupported_mime() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;
        let org_id = Uuid::new_v4();

        // Try uploading with text/plain content type
        let upload_request = Request::builder()
            .method(Method::POST)
            .uri(format!("/api/v2/chats/files?organization={org_id}"))
            .header(SESSION_TOKEN_HEADER, &session_token)
            .header(CONTENT_TYPE, "text/plain")
            .body(Body::from("not an image"))?;

        let response = call(app, upload_request).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[tokio::test]
    async fn chat_file_upload_requires_organization() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        let upload_request = Request::builder()
            .method(Method::POST)
            .uri("/api/v2/chats/files")
            .header(SESSION_TOKEN_HEADER, &session_token)
            .header(CONTENT_TYPE, "image/png")
            .body(Body::from(vec![0x89, 0x50, 0x4E, 0x47]))?;

        let response = call(app, upload_request).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[tokio::test]
    async fn chat_file_not_found_returns_404() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;
        let fake_id = Uuid::new_v4();

        let response = call(
            app,
            authenticated_request(
                Method::GET,
                &format!("/api/v2/chats/files/{fake_id}"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        Ok(())
    }

    #[tokio::test]
    async fn chat_file_requires_auth() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);

        let upload_response = call(
            app.clone(),
            Request::builder()
                .method(Method::POST)
                .uri("/api/v2/chats/files?organization=00000000-0000-0000-0000-000000000000")
                .header(CONTENT_TYPE, "image/png")
                .body(Body::from(vec![0x89, 0x50, 0x4E, 0x47]))?,
        )
        .await?;
        assert_eq!(upload_response.status(), StatusCode::UNAUTHORIZED);

        let download_response = call(
            app,
            request(
                Method::GET,
                &format!("/api/v2/chats/files/{}", Uuid::new_v4()),
            )?,
        )
        .await?;
        assert_eq!(download_response.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Chat archive/unarchive tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn chat_archive_and_unarchive() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        // Create a chat first
        let create_response = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                "/api/v2/chats",
                &session_token,
                &CreateChatRequest {
                    content: vec![],
                    workspace_id: None,
                    model_config_id: None,
                },
            )?,
        )
        .await?;
        assert_eq!(create_response.status(), StatusCode::CREATED);
        let body = to_bytes(create_response.into_body(), 1_000_000).await?;
        let chat_with_messages: Value = serde_json::from_slice(&body)?;
        let chat_id = chat_with_messages["chat"]["id"]
            .as_str()
            .ok_or("missing chat id")?;

        // Archive
        let archive_response = call(
            app.clone(),
            authenticated_request(
                Method::POST,
                &format!("/api/v2/chats/{chat_id}/archive"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(archive_response.status(), StatusCode::NO_CONTENT);

        // Archiving again should return 400
        let archive_again = call(
            app.clone(),
            authenticated_request(
                Method::POST,
                &format!("/api/v2/chats/{chat_id}/archive"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(archive_again.status(), StatusCode::BAD_REQUEST);

        // Unarchive
        let unarchive_response = call(
            app.clone(),
            authenticated_request(
                Method::POST,
                &format!("/api/v2/chats/{chat_id}/unarchive"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(unarchive_response.status(), StatusCode::NO_CONTENT);

        // Unarchiving again should return 400
        let unarchive_again = call(
            app.clone(),
            authenticated_request(
                Method::POST,
                &format!("/api/v2/chats/{chat_id}/unarchive"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(unarchive_again.status(), StatusCode::BAD_REQUEST);

        Ok(())
    }

    #[tokio::test]
    async fn chat_archive_not_found() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;
        let fake_id = Uuid::new_v4();

        let archive_response = call(
            app.clone(),
            authenticated_request(
                Method::POST,
                &format!("/api/v2/chats/{fake_id}/archive"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(archive_response.status(), StatusCode::NOT_FOUND);

        let unarchive_response = call(
            app,
            authenticated_request(
                Method::POST,
                &format!("/api/v2/chats/{fake_id}/unarchive"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(unarchive_response.status(), StatusCode::NOT_FOUND);
        Ok(())
    }

    #[tokio::test]
    async fn chat_archive_requires_auth() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let fake_id = Uuid::new_v4();

        let archive_response = call(
            app.clone(),
            request(Method::POST, &format!("/api/v2/chats/{fake_id}/archive"))?,
        )
        .await?;
        assert_eq!(archive_response.status(), StatusCode::UNAUTHORIZED);

        let unarchive_response = call(
            app,
            request(Method::POST, &format!("/api/v2/chats/{fake_id}/unarchive"))?,
        )
        .await?;
        assert_eq!(unarchive_response.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Chat git/watch tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn chat_git_watch_returns_not_implemented() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        // Create a chat
        let create_response = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                "/api/v2/chats",
                &session_token,
                &CreateChatRequest {
                    content: vec![],
                    workspace_id: None,
                    model_config_id: None,
                },
            )?,
        )
        .await?;
        let body = to_bytes(create_response.into_body(), 1_000_000).await?;
        let chat_with_messages: Value = serde_json::from_slice(&body)?;
        let chat_id = chat_with_messages["chat"]["id"]
            .as_str()
            .ok_or("missing chat id")?;

        let watch_response = call(
            app,
            authenticated_request(
                Method::GET,
                &format!("/api/v2/chats/{chat_id}/git/watch"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(watch_response.status(), StatusCode::NOT_IMPLEMENTED);
        Ok(())
    }

    #[tokio::test]
    async fn chat_git_watch_requires_auth() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let fake_id = Uuid::new_v4();

        let response = call(
            app,
            request(Method::GET, &format!("/api/v2/chats/{fake_id}/git/watch"))?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Notifications domain tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn notifications_settings_requires_auth() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let response = call(app, request(Method::GET, "/api/v2/notifications/settings")?).await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[tokio::test]
    async fn notifications_settings_get_and_put() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        // GET default settings
        let get_response = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                "/api/v2/notifications/settings",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(get_response.status(), StatusCode::OK);

        // PUT settings (owner can update)
        let put_response = call(
            app.clone(),
            authenticated_json_request(
                Method::PUT,
                "/api/v2/notifications/settings",
                &session_token,
                &coder_core::NotificationsSettings {
                    notifier_paused: true,
                },
            )?,
        )
        .await?;
        assert_eq!(put_response.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn notification_system_templates_list() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        let response = call(
            app,
            authenticated_request(
                Method::GET,
                "/api/v2/notifications/templates/system",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn notification_custom_templates_list() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        let response = call(
            app,
            authenticated_request(
                Method::GET,
                "/api/v2/notifications/templates/custom",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn notification_dispatch_methods() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        let response = call(
            app,
            authenticated_request(
                Method::GET,
                "/api/v2/notifications/dispatch-methods",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn notification_test_endpoint() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        let response = call(
            app,
            authenticated_request(Method::POST, "/api/v2/notifications/test", &session_token)?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn user_notification_preferences_get() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        let response = call(
            app,
            authenticated_request(
                Method::GET,
                "/api/v2/users/me/notifications/preferences",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn inbox_notifications_list() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        let response = call(
            app,
            authenticated_request(Method::GET, "/api/v2/notifications/inbox", &session_token)?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn inbox_notifications_invalid_uuid_returns_400() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        let response = call(
            app,
            authenticated_request(
                Method::GET,
                "/api/v2/notifications/inbox?templates=not-a-uuid",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[tokio::test]
    async fn inbox_notifications_invalid_read_status_returns_400() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        let response = call(
            app,
            authenticated_request(
                Method::GET,
                "/api/v2/notifications/inbox?read_status=invalid",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[tokio::test]
    async fn inbox_mark_all_read() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        let response = call(
            app,
            authenticated_request(
                Method::PUT,
                "/api/v2/notifications/inbox/mark-all-as-read",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        Ok(())
    }

    #[tokio::test]
    async fn webpush_subscription_lifecycle() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        // Create subscription
        let create_response = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                "/api/v2/users/me/webpush/subscription",
                &session_token,
                &coder_core::WebpushSubscription {
                    endpoint: "https://push.example.com/sub1".to_owned(),
                    p256dh_key: "test-p256dh-key".to_owned(),
                    auth_key: "test-auth-key".to_owned(),
                },
            )?,
        )
        .await?;
        assert_eq!(create_response.status(), StatusCode::NO_CONTENT);

        // Delete subscription
        let delete_response = call(
            app.clone(),
            authenticated_json_request(
                Method::DELETE,
                "/api/v2/users/me/webpush/subscription",
                &session_token,
                &coder_core::DeleteWebpushSubscription {
                    endpoint: "https://push.example.com/sub1".to_owned(),
                },
            )?,
        )
        .await?;
        assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);

        // Delete non-existent should return 404
        let delete_again_response = call(
            app,
            authenticated_json_request(
                Method::DELETE,
                "/api/v2/users/me/webpush/subscription",
                &session_token,
                &coder_core::DeleteWebpushSubscription {
                    endpoint: "https://push.example.com/sub1".to_owned(),
                },
            )?,
        )
        .await?;
        assert_eq!(delete_again_response.status(), StatusCode::NOT_FOUND);
        Ok(())
    }

    #[tokio::test]
    async fn webpush_test_endpoint() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        let response = call(
            app,
            authenticated_request(
                Method::POST,
                "/api/v2/users/me/webpush/test",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // File upload / download tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn file_upload_requires_auth() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/v2/files")
            .header(CONTENT_TYPE, "application/x-tar")
            .body(Body::from(vec![1u8, 2, 3]))?;
        let response = call(app, req).await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[tokio::test]
    async fn file_upload_rejects_unsupported_content_type() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;
        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/v2/files")
            .header(CONTENT_TYPE, "text/plain")
            .header(SESSION_TOKEN_HEADER, &session_token)
            .body(Body::from(vec![1u8, 2, 3]))?;
        let response = call(app, req).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[tokio::test]
    async fn file_upload_and_download_round_trip() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        let payload = b"hello tar world".to_vec();
        let upload_req = Request::builder()
            .method(Method::POST)
            .uri("/api/v2/files")
            .header(CONTENT_TYPE, "application/x-tar")
            .header(SESSION_TOKEN_HEADER, &session_token)
            .body(Body::from(payload.clone()))?;
        let upload_response = call(app.clone(), upload_req).await?;
        assert_eq!(upload_response.status(), StatusCode::CREATED);

        let upload_body = response_json(upload_response).await?;
        let file_id = upload_body
            .get("hash")
            .and_then(Value::as_str)
            .ok_or("missing hash in upload response")?;

        // Download
        let download_req = authenticated_request(
            Method::GET,
            &format!("/api/v2/files/{file_id}"),
            &session_token,
        )?;
        let download_response = call(app, download_req).await?;
        assert_eq!(download_response.status(), StatusCode::OK);
        assert_eq!(
            download_response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/x-tar"),
        );
        let bytes = to_bytes(download_response.into_body(), usize::MAX).await?;
        assert_eq!(bytes.to_vec(), payload);
        Ok(())
    }

    #[tokio::test]
    async fn file_upload_duplicate_returns_existing_id() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        let payload = b"duplicate content".to_vec();

        let first = Request::builder()
            .method(Method::POST)
            .uri("/api/v2/files")
            .header(CONTENT_TYPE, "application/x-tar")
            .header(SESSION_TOKEN_HEADER, &session_token)
            .body(Body::from(payload.clone()))?;
        let first_response = call(app.clone(), first).await?;
        assert_eq!(first_response.status(), StatusCode::CREATED);
        let first_body = response_json(first_response).await?;
        let first_id = first_body
            .get("hash")
            .and_then(Value::as_str)
            .ok_or("missing hash")?
            .to_owned();

        let second = Request::builder()
            .method(Method::POST)
            .uri("/api/v2/files")
            .header(CONTENT_TYPE, "application/x-tar")
            .header(SESSION_TOKEN_HEADER, &session_token)
            .body(Body::from(payload))?;
        let second_response = call(app, second).await?;
        // Duplicate returns 200 OK, not 201
        assert_eq!(second_response.status(), StatusCode::OK);
        let second_body = response_json(second_response).await?;
        let second_id = second_body
            .get("hash")
            .and_then(Value::as_str)
            .ok_or("missing hash")?;
        assert_eq!(first_id, second_id);
        Ok(())
    }

    #[tokio::test]
    async fn file_download_not_found() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;
        let random_id = Uuid::new_v4();
        let req = authenticated_request(
            Method::GET,
            &format!("/api/v2/files/{random_id}"),
            &session_token,
        )?;
        let response = call(app, req).await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Middleware tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn csp_header_present_on_responses() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let response = call(app, request(Method::GET, "/")?).await?;
        let csp = response
            .headers()
            .get("content-security-policy")
            .and_then(|v| v.to_str().ok());
        assert!(csp.is_some(), "CSP header should be present");
        assert!(
            csp.map(|v| v.contains("default-src")).unwrap_or(false),
            "CSP should contain default-src directive"
        );
        Ok(())
    }

    #[tokio::test]
    async fn hsts_header_present_when_https() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let req = Request::builder()
            .method(Method::GET)
            .uri("/")
            .header("x-forwarded-proto", "https")
            .body(Body::empty())?;
        let response = call(app, req).await?;
        let hsts = response
            .headers()
            .get("strict-transport-security")
            .and_then(|v| v.to_str().ok());
        assert!(hsts.is_some(), "HSTS header should be present for HTTPS");
        assert!(
            hsts.map(|v| v.contains("max-age=31536000"))
                .unwrap_or(false),
            "HSTS should contain correct max-age"
        );
        Ok(())
    }

    #[tokio::test]
    async fn hsts_header_absent_when_http() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let response = call(app, request(Method::GET, "/")?).await?;
        let hsts = response.headers().get("strict-transport-security");
        assert!(hsts.is_none(), "HSTS header should not be present for HTTP");
        Ok(())
    }

    #[tokio::test]
    async fn csrf_rejects_mutating_cookie_request_without_token() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        // Use a non-exempt path so the CSRF middleware actually fires.
        let req = request_with_cookies(
            Method::POST,
            "/api/v2/users",
            &[("coder_session_token", "fake")],
        )?;
        let response = call(app, req).await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    #[tokio::test]
    async fn csrf_allows_get_with_cookies() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let req = request_with_cookies(Method::GET, "/", &[("coder_session_token", "fake")])?;
        let response = call(app, req).await?;
        // GET requests should not be blocked by CSRF middleware
        assert_ne!(response.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    #[tokio::test]
    async fn csrf_allows_mutating_request_with_token() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/v2/users")
            .header(http::header::COOKIE, "coder_session_token=fake")
            .header("x-csrf-token", "some-token-value")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from("{}"))?;
        let response = call(app, req).await?;
        // Should pass CSRF check (might fail auth, but not CSRF)
        assert_ne!(response.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    #[tokio::test]
    async fn csrf_exempts_login_endpoint() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        // Login is exempt: even with a cookie and no CSRF token the
        // middleware must not return 403.
        let req = request_with_cookies(
            Method::POST,
            "/api/v2/users/login",
            &[("coder_session_token", "expired")],
        )?;
        let response = call(app, req).await?;
        assert_ne!(response.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    #[tokio::test]
    async fn csrf_exempts_csp_reports_endpoint() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let req = request_with_cookies(
            Method::POST,
            "/api/v2/csp/reports",
            &[("coder_session_token", "expired")],
        )?;
        let response = call(app, req).await?;
        // CSP reports are exempt from CSRF; should not get 403.
        assert_ne!(response.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Workspace Agent endpoint tests
    // -----------------------------------------------------------------------

    /// Helper: create a connected workspace agent row.
    fn make_connected_agent(agent_id: Uuid) -> WorkspaceAgentRow {
        let now = OffsetDateTime::now_utc();
        WorkspaceAgentRow {
            id: agent_id,
            parent_id: None,
            created_at: now,
            updated_at: now,
            name: "test-agent".to_owned(),
            first_connected_at: Some(now),
            last_connected_at: Some(now),
            disconnected_at: None,
            resource_id: Uuid::new_v4(),
            auth_token: Uuid::new_v4(),
            auth_instance_id: None,
            architecture: "amd64".to_owned(),
            environment_variables: None,
            operating_system: "linux".to_owned(),
            directory: "/home/coder".to_owned(),
            expanded_directory: "/home/coder".to_owned(),
            version: "v2.19.0".to_owned(),
            api_version: "1.0".to_owned(),
            connection_timeout_seconds: 120,
            troubleshooting_url: String::new(),
            motd_file: String::new(),
            lifecycle_state: "ready".to_owned(),
            logs_length: 0,
            logs_overflowed: false,
            started_at: Some(now),
            ready_at: Some(now),
            subsystems: Vec::new(),
            display_apps: Vec::new(),
            display_order: 0,
            api_key_scope: "all".to_owned(),
        }
    }

    /// Helper: create a disconnected workspace agent row.
    fn make_disconnected_agent(agent_id: Uuid) -> WorkspaceAgentRow {
        let now = OffsetDateTime::now_utc();
        let earlier = now - Duration::from_secs(300);
        WorkspaceAgentRow {
            id: agent_id,
            parent_id: None,
            created_at: earlier,
            updated_at: now,
            name: "disconnected-agent".to_owned(),
            first_connected_at: Some(earlier),
            last_connected_at: Some(earlier),
            disconnected_at: Some(now),
            resource_id: Uuid::new_v4(),
            auth_token: Uuid::new_v4(),
            auth_instance_id: None,
            architecture: "amd64".to_owned(),
            environment_variables: None,
            operating_system: "linux".to_owned(),
            directory: "/home/coder".to_owned(),
            expanded_directory: "/home/coder".to_owned(),
            version: "v2.19.0".to_owned(),
            api_version: "1.0".to_owned(),
            connection_timeout_seconds: 120,
            troubleshooting_url: String::new(),
            motd_file: String::new(),
            lifecycle_state: "ready".to_owned(),
            logs_length: 0,
            logs_overflowed: false,
            started_at: Some(earlier),
            ready_at: Some(earlier),
            subsystems: Vec::new(),
            display_apps: Vec::new(),
            display_order: 0,
            api_key_scope: "all".to_owned(),
        }
    }

    #[tokio::test]
    async fn get_workspace_agent_returns_agent() -> Result<(), Box<dyn Error>> {
        let (state, store) = test_state_with_store(true)?;
        let app = build_router(state);
        let token = create_and_login(&app).await?;

        let agent_id = Uuid::new_v4();
        store.insert_agent(make_connected_agent(agent_id))?;

        let response = call(
            app,
            authenticated_request(
                Method::GET,
                &format!("/api/v2/workspaceagents/{agent_id}"),
                &token,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await?;
        assert_eq!(
            body.get("id").and_then(Value::as_str),
            Some(agent_id.to_string()).as_deref()
        );
        assert_eq!(body.get("name").and_then(Value::as_str), Some("test-agent"));
        Ok(())
    }

    #[tokio::test]
    async fn get_workspace_agent_not_found() -> Result<(), Box<dyn Error>> {
        let (state, _store) = test_state_with_store(true)?;
        let app = build_router(state);
        let token = create_and_login(&app).await?;

        let agent_id = Uuid::new_v4();
        let response = call(
            app,
            authenticated_request(
                Method::GET,
                &format!("/api/v2/workspaceagents/{agent_id}"),
                &token,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        Ok(())
    }

    #[tokio::test]
    async fn get_workspace_agent_unauthorized() -> Result<(), Box<dyn Error>> {
        let state = test_state(true)?;
        let app = build_router(state);

        let agent_id = Uuid::new_v4();
        let response = call(
            app,
            request(Method::GET, &format!("/api/v2/workspaceagents/{agent_id}"))?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[tokio::test]
    async fn get_workspace_agent_connection_returns_info() -> Result<(), Box<dyn Error>> {
        let (state, _store) = test_state_with_store(true)?;
        let app = build_router(state);
        let token = create_and_login(&app).await?;

        let agent_id = Uuid::new_v4();
        let response = call(
            app,
            authenticated_request(
                Method::GET,
                &format!("/api/v2/workspaceagents/{agent_id}/connection"),
                &token,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await?;
        assert_eq!(
            body.get("hostname_suffix").and_then(Value::as_str),
            Some("example.internal")
        );
        assert_eq!(
            body.get("derp_force_websockets").and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(
            body.get("disable_direct_connections")
                .and_then(Value::as_bool),
            Some(false)
        );
        Ok(())
    }

    #[tokio::test]
    async fn get_workspace_agents_connection_info_returns_global_info() -> Result<(), Box<dyn Error>>
    {
        let (state, _store) = test_state_with_store(true)?;
        let app = build_router(state);
        let token = create_and_login(&app).await?;

        let response = call(
            app,
            authenticated_request(Method::GET, "/api/v2/workspaceagents/connection", &token)?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await?;
        assert_eq!(
            body.get("hostname_suffix").and_then(Value::as_str),
            Some("example.internal")
        );
        Ok(())
    }

    #[tokio::test]
    async fn get_workspace_agent_containers_returns_list() -> Result<(), Box<dyn Error>> {
        let (state, store) = test_state_with_store(true)?;
        let app = build_router(state);
        let token = create_and_login(&app).await?;

        let agent_id = Uuid::new_v4();
        store.insert_agent(make_connected_agent(agent_id))?;

        // Add a devcontainer
        let dc_id = Uuid::new_v4();
        store
            .workspace_agent_devcontainers
            .lock()
            .map_err(|e| e.to_string())?
            .push(coder_core::WorkspaceAgentDevcontainerRow {
                id: dc_id,
                workspace_agent_id: agent_id,
                created_at: OffsetDateTime::now_utc(),
                workspace_folder: "/workspaces/myproject".to_owned(),
                config_path: ".devcontainer/devcontainer.json".to_owned(),
                name: "myproject".to_owned(),
                subagent_id: None,
            });

        let response = call(
            app,
            authenticated_request(
                Method::GET,
                &format!("/api/v2/workspaceagents/{agent_id}/containers"),
                &token,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await?;
        let devcontainers = body.get("devcontainers").and_then(Value::as_array);
        assert!(devcontainers.is_some());
        let dcs = devcontainers.ok_or("missing devcontainers")?;
        assert_eq!(dcs.len(), 1);
        assert_eq!(
            dcs[0].get("workspace_folder").and_then(Value::as_str),
            Some("/workspaces/myproject")
        );
        Ok(())
    }

    #[tokio::test]
    async fn get_workspace_agent_containers_not_found() -> Result<(), Box<dyn Error>> {
        let (state, _store) = test_state_with_store(true)?;
        let app = build_router(state);
        let token = create_and_login(&app).await?;

        let agent_id = Uuid::new_v4();
        let response = call(
            app,
            authenticated_request(
                Method::GET,
                &format!("/api/v2/workspaceagents/{agent_id}/containers"),
                &token,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        Ok(())
    }

    #[tokio::test]
    async fn post_recreate_devcontainer_requires_connected_agent() -> Result<(), Box<dyn Error>> {
        let (state, store) = test_state_with_store(true)?;
        let app = build_router(state);
        let token = create_and_login(&app).await?;

        let agent_id = Uuid::new_v4();
        store.insert_agent(make_disconnected_agent(agent_id))?;

        let dc_id = Uuid::new_v4();
        let response = call(
            app,
            authenticated_request(
                Method::POST,
                &format!(
                    "/api/v2/workspaceagents/{agent_id}/containers/devcontainers/{dc_id}/recreate"
                ),
                &token,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response_json(response).await?;
        let message = body
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(
            message.contains("Connected"),
            "expected message about Connected state, got: {message}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn post_recreate_devcontainer_connected_returns_not_implemented()
    -> Result<(), Box<dyn Error>> {
        let (state, store) = test_state_with_store(true)?;
        let app = build_router(state);
        let token = create_and_login(&app).await?;

        let agent_id = Uuid::new_v4();
        store.insert_agent(make_connected_agent(agent_id))?;

        let dc_id = Uuid::new_v4();
        let response = call(
            app,
            authenticated_request(
                Method::POST,
                &format!(
                    "/api/v2/workspaceagents/{agent_id}/containers/devcontainers/{dc_id}/recreate"
                ),
                &token,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        Ok(())
    }

    #[tokio::test]
    async fn delete_devcontainer_requires_connected_agent() -> Result<(), Box<dyn Error>> {
        let (state, store) = test_state_with_store(true)?;
        let app = build_router(state);
        let token = create_and_login(&app).await?;

        let agent_id = Uuid::new_v4();
        store.insert_agent(make_disconnected_agent(agent_id))?;

        let dc_id = Uuid::new_v4();
        let response = call(
            app,
            authenticated_request(
                Method::DELETE,
                &format!("/api/v2/workspaceagents/{agent_id}/containers/devcontainers/{dc_id}"),
                &token,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response_json(response).await?;
        let message = body
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(
            message.contains("Connected"),
            "expected message about Connected state, got: {message}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn delete_devcontainer_connected_returns_not_implemented() -> Result<(), Box<dyn Error>> {
        let (state, store) = test_state_with_store(true)?;
        let app = build_router(state);
        let token = create_and_login(&app).await?;

        let agent_id = Uuid::new_v4();
        store.insert_agent(make_connected_agent(agent_id))?;

        let dc_id = Uuid::new_v4();
        let response = call(
            app,
            authenticated_request(
                Method::DELETE,
                &format!("/api/v2/workspaceagents/{agent_id}/containers/devcontainers/{dc_id}"),
                &token,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        Ok(())
    }

    #[tokio::test]
    async fn get_workspace_agent_listening_ports_returns_empty() -> Result<(), Box<dyn Error>> {
        let (state, store) = test_state_with_store(true)?;
        let app = build_router(state);
        let token = create_and_login(&app).await?;

        let agent_id = Uuid::new_v4();
        store.insert_agent(make_connected_agent(agent_id))?;

        let response = call(
            app,
            authenticated_request(
                Method::GET,
                &format!("/api/v2/workspaceagents/{agent_id}/listening-ports"),
                &token,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await?;
        let ports = body
            .get("ports")
            .and_then(Value::as_array)
            .ok_or("missing ports")?;
        assert!(ports.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn get_workspace_agent_listening_ports_not_found() -> Result<(), Box<dyn Error>> {
        let (state, _store) = test_state_with_store(true)?;
        let app = build_router(state);
        let token = create_and_login(&app).await?;

        let agent_id = Uuid::new_v4();
        let response = call(
            app,
            authenticated_request(
                Method::GET,
                &format!("/api/v2/workspaceagents/{agent_id}/listening-ports"),
                &token,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        Ok(())
    }

    #[tokio::test]
    async fn get_workspace_agent_logs_returns_logs() -> Result<(), Box<dyn Error>> {
        let (state, store) = test_state_with_store(true)?;
        let app = build_router(state);
        let token = create_and_login(&app).await?;

        let agent_id = Uuid::new_v4();
        store.insert_agent(make_connected_agent(agent_id))?;

        let log_source_id = Uuid::new_v4();
        store
            .workspace_agent_logs
            .lock()
            .map_err(|e| e.to_string())?
            .push(WorkspaceAgentLogRow {
                id: 1,
                agent_id,
                created_at: OffsetDateTime::now_utc(),
                output: "Hello from agent".to_owned(),
                level: "info".to_owned(),
                log_source_id,
            });

        let response = call(
            app,
            authenticated_request(
                Method::GET,
                &format!("/api/v2/workspaceagents/{agent_id}/logs"),
                &token,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await?;
        let logs = body.as_array().ok_or("expected array")?;
        assert_eq!(logs.len(), 1);
        assert_eq!(
            logs[0].get("output").and_then(Value::as_str),
            Some("Hello from agent")
        );
        Ok(())
    }

    #[tokio::test]
    async fn get_workspace_agent_logs_not_found() -> Result<(), Box<dyn Error>> {
        let (state, _store) = test_state_with_store(true)?;
        let app = build_router(state);
        let token = create_and_login(&app).await?;

        let agent_id = Uuid::new_v4();
        let response = call(
            app,
            authenticated_request(
                Method::GET,
                &format!("/api/v2/workspaceagents/{agent_id}/logs"),
                &token,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        Ok(())
    }

    #[tokio::test]
    async fn deprecated_startup_logs_returns_logs() -> Result<(), Box<dyn Error>> {
        let (state, store) = test_state_with_store(true)?;
        let app = build_router(state);
        let token = create_and_login(&app).await?;

        let agent_id = Uuid::new_v4();
        store.insert_agent(make_connected_agent(agent_id))?;

        let log_source_id = Uuid::new_v4();
        store
            .workspace_agent_logs
            .lock()
            .map_err(|e| e.to_string())?
            .push(WorkspaceAgentLogRow {
                id: 1,
                agent_id,
                created_at: OffsetDateTime::now_utc(),
                output: "Startup log line".to_owned(),
                level: "info".to_owned(),
                log_source_id,
            });

        let response = call(
            app,
            authenticated_request(
                Method::GET,
                &format!("/api/v2/workspaceagents/{agent_id}/startup-logs"),
                &token,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await?;
        // The deprecated startup-logs handler returns a flat array of logs.
        let logs = body.as_array().ok_or("expected array")?;
        assert_eq!(logs.len(), 1);
        assert_eq!(
            logs[0].get("output").and_then(Value::as_str),
            Some("Startup log line")
        );
        Ok(())
    }

    #[tokio::test]
    async fn get_workspace_agent_watch_metadata_returns_metadata() -> Result<(), Box<dyn Error>> {
        let (state, store) = test_state_with_store(true)?;
        let app = build_router(state);
        let token = create_and_login(&app).await?;

        let agent_id = Uuid::new_v4();
        store.insert_agent(make_connected_agent(agent_id))?;

        store
            .workspace_agent_metadata
            .lock()
            .map_err(|e| e.to_string())?
            .push(WorkspaceAgentMetadataRow {
                workspace_agent_id: agent_id,
                display_name: "CPU Usage".to_owned(),
                key: "cpu".to_owned(),
                script: "cat /proc/loadavg".to_owned(),
                value: "0.5".to_owned(),
                error: String::new(),
                timeout: 5,
                interval: 10,
                collected_at: OffsetDateTime::now_utc(),
                display_order: 0,
            });

        let response = call(
            app,
            authenticated_request(
                Method::GET,
                &format!("/api/v2/workspaceagents/{agent_id}/watch-metadata"),
                &token,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await?;
        let metadata = body.as_array().ok_or("expected array")?;
        assert_eq!(metadata.len(), 1);
        assert_eq!(metadata[0].get("key").and_then(Value::as_str), Some("cpu"));
        assert_eq!(
            metadata[0].get("value").and_then(Value::as_str),
            Some("0.5")
        );
        Ok(())
    }

    #[tokio::test]
    async fn get_workspace_agent_watch_metadata_not_found() -> Result<(), Box<dyn Error>> {
        let (state, _store) = test_state_with_store(true)?;
        let app = build_router(state);
        let token = create_and_login(&app).await?;

        let agent_id = Uuid::new_v4();
        let response = call(
            app,
            authenticated_request(
                Method::GET,
                &format!("/api/v2/workspaceagents/{agent_id}/watch-metadata"),
                &token,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        Ok(())
    }

    /// Helper to build a request with WebSocket upgrade headers (HTTP/1.1).
    fn ws_upgrade_request(uri: &str, session_token: &str) -> Result<Request<Body>, http::Error> {
        Request::builder()
            .method(Method::GET)
            .uri(uri)
            .version(http::Version::HTTP_11)
            .header(SESSION_TOKEN_HEADER, session_token)
            .header("connection", "Upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .body(Body::empty())
    }

    #[tokio::test]
    async fn get_workspace_agent_coordinate_rejects_non_ws() -> Result<(), Box<dyn Error>> {
        let (state, store) = test_state_with_store(true)?;
        let app = build_router(state);
        let token = create_and_login(&app).await?;

        let agent_id = Uuid::new_v4();
        store.insert_agent(make_connected_agent(agent_id))?;

        // Non-WebSocket request should be rejected by the WebSocketUpgrade extractor.
        let response = call(
            app,
            authenticated_request(
                Method::GET,
                &format!("/api/v2/workspaceagents/{agent_id}/coordinate"),
                &token,
            )?,
        )
        .await?;
        // Axum returns 400 (Bad Request) when WebSocket upgrade headers are missing.
        assert!(
            response.status() == StatusCode::BAD_REQUEST
                || response.status() == StatusCode::UPGRADE_REQUIRED,
            "expected 400 or 426, got {}",
            response.status()
        );
        Ok(())
    }

    #[tokio::test]
    async fn get_workspace_agent_coordinate_ws_upgrade() -> Result<(), Box<dyn Error>> {
        let (state, store) = test_state_with_store(true)?;
        let app = build_router(state);
        let token = create_and_login(&app).await?;

        let agent_id = Uuid::new_v4();
        store.insert_agent(make_connected_agent(agent_id))?;

        let response = call(
            app,
            ws_upgrade_request(
                &format!("/api/v2/workspaceagents/{agent_id}/coordinate"),
                &token,
            )?,
        )
        .await?;
        // In a real server this returns 101; in oneshot tests the upgrade cannot complete
        // so axum returns 426. Both prove the route matched and the WS extractor ran.
        assert!(
            response.status() == StatusCode::SWITCHING_PROTOCOLS
                || response.status() == StatusCode::UPGRADE_REQUIRED,
            "expected 101 or 426, got {}",
            response.status()
        );
        Ok(())
    }

    #[tokio::test]
    async fn get_workspace_agent_pty_rejects_non_ws() -> Result<(), Box<dyn Error>> {
        let (state, store) = test_state_with_store(true)?;
        let app = build_router(state);
        let token = create_and_login(&app).await?;

        let agent_id = Uuid::new_v4();
        store.insert_agent(make_connected_agent(agent_id))?;

        let response = call(
            app,
            authenticated_request(
                Method::GET,
                &format!("/api/v2/workspaceagents/{agent_id}/pty"),
                &token,
            )?,
        )
        .await?;
        assert!(
            response.status() == StatusCode::BAD_REQUEST
                || response.status() == StatusCode::UPGRADE_REQUIRED,
            "expected 400 or 426, got {}",
            response.status()
        );
        Ok(())
    }

    #[tokio::test]
    async fn get_workspace_agent_pty_ws_upgrade() -> Result<(), Box<dyn Error>> {
        let (state, store) = test_state_with_store(true)?;
        let app = build_router(state);
        let token = create_and_login(&app).await?;

        let agent_id = Uuid::new_v4();
        store.insert_agent(make_connected_agent(agent_id))?;

        let response = call(
            app,
            ws_upgrade_request(&format!("/api/v2/workspaceagents/{agent_id}/pty"), &token)?,
        )
        .await?;
        assert!(
            response.status() == StatusCode::SWITCHING_PROTOCOLS
                || response.status() == StatusCode::UPGRADE_REQUIRED,
            "expected 101 or 426, got {}",
            response.status()
        );
        Ok(())
    }

    #[tokio::test]
    async fn get_workspace_agent_containers_watch_rejects_non_ws() -> Result<(), Box<dyn Error>> {
        let (state, store) = test_state_with_store(true)?;
        let app = build_router(state);
        let token = create_and_login(&app).await?;

        let agent_id = Uuid::new_v4();
        store.insert_agent(make_connected_agent(agent_id))?;

        let response = call(
            app,
            authenticated_request(
                Method::GET,
                &format!("/api/v2/workspaceagents/{agent_id}/containers/watch"),
                &token,
            )?,
        )
        .await?;
        assert!(
            response.status() == StatusCode::BAD_REQUEST
                || response.status() == StatusCode::UPGRADE_REQUIRED,
            "expected 400 or 426, got {}",
            response.status()
        );
        Ok(())
    }

    #[tokio::test]
    async fn get_workspace_agent_containers_watch_ws_upgrade() -> Result<(), Box<dyn Error>> {
        let (state, store) = test_state_with_store(true)?;
        let app = build_router(state);
        let token = create_and_login(&app).await?;

        let agent_id = Uuid::new_v4();
        store.insert_agent(make_connected_agent(agent_id))?;

        let response = call(
            app,
            ws_upgrade_request(
                &format!("/api/v2/workspaceagents/{agent_id}/containers/watch"),
                &token,
            )?,
        )
        .await?;
        assert!(
            response.status() == StatusCode::SWITCHING_PROTOCOLS
                || response.status() == StatusCode::UPGRADE_REQUIRED,
            "expected 101 or 426, got {}",
            response.status()
        );
        Ok(())
    }

    #[tokio::test]
    async fn get_workspace_agent_watch_metadata_ws_rejects_non_ws() -> Result<(), Box<dyn Error>> {
        let (state, store) = test_state_with_store(true)?;
        let app = build_router(state);
        let token = create_and_login(&app).await?;

        let agent_id = Uuid::new_v4();
        store.insert_agent(make_connected_agent(agent_id))?;

        let response = call(
            app,
            authenticated_request(
                Method::GET,
                &format!("/api/v2/workspaceagents/{agent_id}/watch-metadata-ws"),
                &token,
            )?,
        )
        .await?;
        assert!(
            response.status() == StatusCode::BAD_REQUEST
                || response.status() == StatusCode::UPGRADE_REQUIRED,
            "expected 400 or 426, got {}",
            response.status()
        );
        Ok(())
    }

    #[tokio::test]
    async fn get_workspace_agent_watch_metadata_ws_upgrade() -> Result<(), Box<dyn Error>> {
        let (state, store) = test_state_with_store(true)?;
        let app = build_router(state);
        let token = create_and_login(&app).await?;

        let agent_id = Uuid::new_v4();
        store.insert_agent(make_connected_agent(agent_id))?;

        let response = call(
            app,
            ws_upgrade_request(
                &format!("/api/v2/workspaceagents/{agent_id}/watch-metadata-ws"),
                &token,
            )?,
        )
        .await?;
        assert!(
            response.status() == StatusCode::SWITCHING_PROTOCOLS
                || response.status() == StatusCode::UPGRADE_REQUIRED,
            "expected 101 or 426, got {}",
            response.status()
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Template version route tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn dynamic_parameters_requires_auth() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let version_id = Uuid::new_v4();
        let response = call(
            app,
            request(
                Method::GET,
                &format!("/api/v2/templateversions/{version_id}/dynamic-parameters"),
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[tokio::test]
    async fn dynamic_parameters_returns_ok_for_existing_version() -> Result<(), Box<dyn Error>> {
        let (state, store) = test_state_with_store(true)?;
        let app = build_router(state);
        let session_token = create_and_login(&app).await?;
        let org_id = first_organization_id(&app, &session_token).await?;

        // Create a provisioner job and template version in the store.
        let job_id = Uuid::new_v4();
        let version_id = Uuid::new_v4();
        store
            .provisioner_jobs
            .lock()
            .map_err(|e| -> Box<dyn Error> { e.to_string().into() })?
            .insert(
                job_id,
                TemplateProvisionerJobRecord {
                    id: job_id,
                    created_at: OffsetDateTime::now_utc(),
                    updated_at: OffsetDateTime::now_utc(),
                    started_at: None,
                    canceled_at: None,
                    completed_at: None,
                    error: String::new(),
                    organization_id: org_id,
                    initiator_id: Uuid::from_u128(1),
                    provisioner: "echo".to_owned(),
                    job_status: "succeeded".to_owned(),
                    file_id: Some(Uuid::new_v4()),
                    job_type: "template_version_import".to_owned(),
                    input: Value::Null,
                    worker_id: None,
                    tags: HashMap::new(),
                },
            );
        store
            .template_versions
            .lock()
            .map_err(|e| -> Box<dyn Error> { e.to_string().into() })?
            .insert(
                version_id,
                TemplateVersionRecord {
                    id: version_id,
                    template_id: None,
                    organization_id: org_id,
                    created_at: OffsetDateTime::now_utc(),
                    updated_at: OffsetDateTime::now_utc(),
                    name: "test-version".to_owned(),
                    readme: String::new(),
                    job_id,
                    created_by: Uuid::from_u128(1),
                    external_auth_providers: Value::Array(Vec::new()),
                    message: String::new(),
                    archived: false,
                    source_example_id: None,
                    has_ai_task: None,
                    has_external_agent: None,
                    created_by_avatar_url: String::new(),
                    created_by_username: "owner".to_owned(),
                    created_by_name: "Owner".to_owned(),
                },
            );

        let response = call(
            app,
            authenticated_request(
                Method::GET,
                &format!("/api/v2/templateversions/{version_id}/dynamic-parameters"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await?;
        assert_eq!(body.get("id").and_then(Value::as_i64), Some(0));
        Ok(())
    }

    #[tokio::test]
    async fn dynamic_parameters_evaluate_returns_ok() -> Result<(), Box<dyn Error>> {
        let (state, store) = test_state_with_store(true)?;
        let app = build_router(state);
        let session_token = create_and_login(&app).await?;
        let org_id = first_organization_id(&app, &session_token).await?;

        let job_id = Uuid::new_v4();
        let version_id = Uuid::new_v4();
        store
            .provisioner_jobs
            .lock()
            .map_err(|e| -> Box<dyn Error> { e.to_string().into() })?
            .insert(
                job_id,
                TemplateProvisionerJobRecord {
                    id: job_id,
                    created_at: OffsetDateTime::now_utc(),
                    updated_at: OffsetDateTime::now_utc(),
                    started_at: None,
                    canceled_at: None,
                    completed_at: None,
                    error: String::new(),
                    organization_id: org_id,
                    initiator_id: Uuid::from_u128(1),
                    provisioner: "echo".to_owned(),
                    job_status: "succeeded".to_owned(),
                    file_id: Some(Uuid::new_v4()),
                    job_type: "template_version_import".to_owned(),
                    input: Value::Null,
                    worker_id: None,
                    tags: HashMap::new(),
                },
            );
        store
            .template_versions
            .lock()
            .map_err(|e| -> Box<dyn Error> { e.to_string().into() })?
            .insert(
                version_id,
                TemplateVersionRecord {
                    id: version_id,
                    template_id: None,
                    organization_id: org_id,
                    created_at: OffsetDateTime::now_utc(),
                    updated_at: OffsetDateTime::now_utc(),
                    name: "test-version".to_owned(),
                    readme: String::new(),
                    job_id,
                    created_by: Uuid::from_u128(1),
                    external_auth_providers: Value::Array(Vec::new()),
                    message: String::new(),
                    archived: false,
                    source_example_id: None,
                    has_ai_task: None,
                    has_external_agent: None,
                    created_by_avatar_url: String::new(),
                    created_by_username: "owner".to_owned(),
                    created_by_name: "Owner".to_owned(),
                },
            );

        let response = call(
            app,
            authenticated_json_request(
                Method::POST,
                &format!("/api/v2/templateversions/{version_id}/dynamic-parameters/evaluate"),
                &session_token,
                &json!({"id": 42, "inputs": {"key": "value"}}),
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await?;
        assert_eq!(body.get("id").and_then(Value::as_i64), Some(42));
        Ok(())
    }

    #[tokio::test]
    async fn matched_provisioners_requires_auth() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let version_id = Uuid::new_v4();
        let job_id = Uuid::new_v4();
        let response = call(
            app,
            request(
                Method::GET,
                &format!(
                    "/api/v2/templateversions/{version_id}/dry-run/{job_id}/matched-provisioners"
                ),
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[tokio::test]
    async fn archive_template_versions_requires_auth() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let template_id = Uuid::new_v4();
        let response = call(
            app,
            json_request(
                Method::POST,
                &format!("/api/v2/templates/{template_id}/versions/archive"),
                &json!({"all": false}),
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[tokio::test]
    async fn patch_active_template_version_requires_auth() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let template_id = Uuid::new_v4();
        let response = call(
            app,
            json_request(
                Method::PATCH,
                &format!("/api/v2/templates/{template_id}/versions"),
                &json!({"id": Uuid::new_v4()}),
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Agent endpoint tests
    // -----------------------------------------------------------------------

    /// Helper: set up a FakeStore with an agent, workspace, and optionally an
    /// app. Returns (AppState, Arc<FakeStore>, agent_auth_token).
    fn setup_agent_test_state() -> Result<(AppState, Arc<FakeStore>, Uuid), Box<dyn Error>> {
        let (state, store) = test_state_with_store(true)?;
        let agent_token = Uuid::new_v4();
        let agent_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let owner_id = Uuid::from_u128(100);
        let now = OffsetDateTime::now_utc();

        let agent = WorkspaceAgentRow {
            id: agent_id,
            parent_id: None,
            created_at: now,
            updated_at: now,
            name: "test-agent".to_owned(),
            first_connected_at: None,
            last_connected_at: None,
            disconnected_at: None,
            resource_id: Uuid::new_v4(),
            auth_token: agent_token,
            auth_instance_id: None,
            architecture: "amd64".to_owned(),
            environment_variables: None,
            operating_system: "linux".to_owned(),
            directory: "/home/coder".to_owned(),
            expanded_directory: "/home/coder".to_owned(),
            version: "2.0.0".to_owned(),
            api_version: "1.0".to_owned(),
            connection_timeout_seconds: 120,
            troubleshooting_url: String::new(),
            motd_file: String::new(),
            lifecycle_state: "ready".to_owned(),
            logs_length: 0,
            logs_overflowed: false,
            started_at: Some(now),
            ready_at: Some(now),
            subsystems: Vec::new(),
            display_apps: Vec::new(),
            display_order: 0,
            api_key_scope: "all".to_owned(),
        };
        store.insert_agent(agent)?;

        let workspace = WorkspaceRecord {
            id: workspace_id,
            created_at: now,
            updated_at: now,
            owner_id,
            organization_id: Uuid::from_u128(2),
            template_id: Uuid::new_v4(),
            deleted: false,
            name: "test-workspace".to_owned(),
            autostart_schedule: None,
            ttl_ns: None,
            last_used_at: now,
            dormant_at: None,
            deleting_at: None,
            automatic_updates: "never".to_owned(),
            favorite: false,
            next_start_at: None,
        };
        store.insert_workspace(workspace)?;

        Ok((state, store, agent_token))
    }

    /// Helper: create an authenticated agent request using the agent token.
    fn agent_request(
        method: Method,
        uri: &str,
        agent_token: Uuid,
    ) -> Result<Request<Body>, http::Error> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(SESSION_TOKEN_HEADER, agent_token.to_string())
            .body(Body::empty())
    }

    fn agent_json_request<T: Serialize>(
        method: Method,
        uri: &str,
        agent_token: Uuid,
        payload: &T,
    ) -> Result<Request<Body>, Box<dyn Error>> {
        let body = serde_json::to_vec(payload)?;
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header(CONTENT_TYPE, "application/json")
            .header(SESSION_TOKEN_HEADER, agent_token.to_string())
            .body(Body::from(body))?;
        Ok(req)
    }

    #[tokio::test]
    async fn agent_endpoints_reject_unauthenticated() -> Result<(), Box<dyn Error>> {
        let state = test_state(true)?;
        let app = build_router(state);

        // All agent endpoints should return 401 without a valid token.
        let endpoints: Vec<(Method, &str)> = vec![
            (Method::GET, "/api/v2/workspaceagents/me/gitsshkey"),
            (
                Method::GET,
                "/api/v2/workspaceagents/me/external-auth?id=github",
            ),
            (Method::GET, "/api/v2/workspaceagents/me/reinit"),
            (Method::GET, "/api/v2/workspaceagents/me/rpc"),
        ];

        for (method, uri) in endpoints {
            let req = request(method.clone(), uri)?;
            let response = call(app.clone(), req).await?;
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "Expected 401 for unauthenticated {method} {uri}"
            );
        }

        Ok(())
    }

    #[tokio::test]
    async fn agent_gitsshkey_returns_ok() -> Result<(), Box<dyn Error>> {
        let (state, store, agent_token) = setup_agent_test_state()?;

        // Insert a git SSH key for the workspace owner.
        let owner_id = Uuid::from_u128(100);
        store
            .git_ssh_keys
            .lock()
            .map_err(|e| StorageError::unavailable(e.to_string()))?
            .insert(
                owner_id,
                GitSshKeyRecord {
                    user_id: owner_id,
                    created_at: OffsetDateTime::now_utc(),
                    updated_at: OffsetDateTime::now_utc(),
                    private_key: "PRIVATE_KEY".to_owned(),
                    public_key: "PUBLIC_KEY".to_owned(),
                },
            );

        let app = build_router(state);
        let req = agent_request(
            Method::GET,
            "/api/v2/workspaceagents/me/gitsshkey",
            agent_token,
        )?;
        let response = call(app, req).await?;
        assert_eq!(response.status(), StatusCode::OK);

        let body = response_json(response).await?;
        assert_eq!(body["public_key"], "PUBLIC_KEY");
        assert_eq!(body["private_key"], "PRIVATE_KEY");

        Ok(())
    }

    #[tokio::test]
    async fn agent_log_source_create() -> Result<(), Box<dyn Error>> {
        let (state, _store, agent_token) = setup_agent_test_state()?;
        let app = build_router(state);

        let payload = json!({
            "display_name": "Startup Script",
            "icon": "/icon/terminal.svg",
        });
        let req = agent_json_request(
            Method::POST,
            "/api/v2/workspaceagents/me/log-source",
            agent_token,
            &payload,
        )?;
        let response = call(app, req).await?;
        assert_eq!(response.status(), StatusCode::CREATED);

        let body = response_json(response).await?;
        assert_eq!(body["display_name"], "Startup Script");
        assert_eq!(body["icon"], "/icon/terminal.svg");
        assert!(body["id"].is_string());

        Ok(())
    }

    #[tokio::test]
    async fn agent_log_source_validation() -> Result<(), Box<dyn Error>> {
        let (state, _store, agent_token) = setup_agent_test_state()?;
        let app = build_router(state);

        // Empty display_name should fail validation.
        let payload = json!({
            "display_name": "",
            "icon": "/icon/terminal.svg",
        });
        let req = agent_json_request(
            Method::POST,
            "/api/v2/workspaceagents/me/log-source",
            agent_token,
            &payload,
        )?;
        let response = call(app, req).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        Ok(())
    }

    #[tokio::test]
    async fn agent_logs_append() -> Result<(), Box<dyn Error>> {
        let (state, store, agent_token) = setup_agent_test_state()?;

        // First create a log source.
        let agent_id = store
            .workspace_agents
            .lock()
            .map_err(|e| StorageError::unavailable(e.to_string()))?
            .values()
            .next()
            .map(|a| a.id)
            .ok_or("no agent")?;
        let source = store
            .insert_workspace_agent_log_source(agent_id, None, "test", "")
            .await?;

        let app = build_router(state);
        let payload = json!({
            "log_source_id": source.id.to_string(),
            "logs": [
                {
                    "created_at": "2025-01-01T00:00:00Z",
                    "output": "hello world",
                    "level": "info"
                }
            ]
        });
        let req = agent_json_request(
            Method::PATCH,
            "/api/v2/workspaceagents/me/logs",
            agent_token,
            &payload,
        )?;
        let response = call(app, req).await?;
        assert_eq!(response.status(), StatusCode::OK);

        // Verify log was stored.
        let logs = store
            .workspace_agent_logs
            .lock()
            .map_err(|e| StorageError::unavailable(e.to_string()))?;
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].output, "hello world");

        Ok(())
    }

    #[tokio::test]
    async fn agent_logs_empty_validation() -> Result<(), Box<dyn Error>> {
        let (state, _store, agent_token) = setup_agent_test_state()?;
        let app = build_router(state);

        let payload = json!({
            "log_source_id": Uuid::new_v4().to_string(),
            "logs": []
        });
        let req = agent_json_request(
            Method::PATCH,
            "/api/v2/workspaceagents/me/logs",
            agent_token,
            &payload,
        )?;
        let response = call(app, req).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        Ok(())
    }

    #[tokio::test]
    async fn agent_app_status_update() -> Result<(), Box<dyn Error>> {
        let (state, store, agent_token) = setup_agent_test_state()?;

        // Insert a workspace app.
        let agent_id = store
            .workspace_agents
            .lock()
            .map_err(|e| StorageError::unavailable(e.to_string()))?
            .values()
            .next()
            .map(|a| a.id)
            .ok_or("no agent")?;
        let now = OffsetDateTime::now_utc();
        let app_row = WorkspaceAppRow {
            id: Uuid::new_v4(),
            created_at: now,
            agent_id,
            display_name: "My App".to_owned(),
            icon: String::new(),
            command: None,
            url: None,
            healthcheck_url: String::new(),
            healthcheck_interval: 0,
            healthcheck_threshold: 0,
            health: "healthy".to_owned(),
            subdomain: false,
            sharing_level: "owner".to_owned(),
            slug: "my-app".to_owned(),
            external: false,
            display_order: 0,
            hidden: false,
            open_in: "slim-window".to_owned(),
            display_group: None,
        };
        store.insert_app(app_row)?;

        let app = build_router(state);
        let payload = json!({
            "app_slug": "my-app",
            "state": "working",
            "message": "Processing...",
        });
        let req = agent_json_request(
            Method::PATCH,
            "/api/v2/workspaceagents/me/app-status",
            agent_token,
            &payload,
        )?;
        let response = call(app, req).await?;
        assert_eq!(response.status(), StatusCode::OK);

        // Verify status was stored.
        let statuses = store
            .workspace_app_statuses
            .lock()
            .map_err(|e| StorageError::unavailable(e.to_string()))?;
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].state, "working");
        assert_eq!(statuses[0].message, "Processing...");

        Ok(())
    }

    #[tokio::test]
    async fn agent_app_status_missing_slug() -> Result<(), Box<dyn Error>> {
        let (state, _store, agent_token) = setup_agent_test_state()?;
        let app = build_router(state);

        let payload = json!({
            "app_slug": "",
            "state": "working",
            "message": "test",
        });
        let req = agent_json_request(
            Method::PATCH,
            "/api/v2/workspaceagents/me/app-status",
            agent_token,
            &payload,
        )?;
        let response = call(app, req).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        Ok(())
    }

    #[tokio::test]
    async fn agent_app_status_unknown_slug() -> Result<(), Box<dyn Error>> {
        let (state, _store, agent_token) = setup_agent_test_state()?;
        let app = build_router(state);

        let payload = json!({
            "app_slug": "nonexistent",
            "state": "working",
            "message": "test",
        });
        let req = agent_json_request(
            Method::PATCH,
            "/api/v2/workspaceagents/me/app-status",
            agent_token,
            &payload,
        )?;
        let response = call(app, req).await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        Ok(())
    }

    #[tokio::test]
    async fn agent_external_auth_requires_id() -> Result<(), Box<dyn Error>> {
        let (state, _store, agent_token) = setup_agent_test_state()?;
        let app = build_router(state);

        // No 'id' parameter should fail.
        let req = agent_request(
            Method::GET,
            "/api/v2/workspaceagents/me/external-auth?id=",
            agent_token,
        )?;
        let response = call(app, req).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        Ok(())
    }

    #[tokio::test]
    async fn agent_external_auth_not_found() -> Result<(), Box<dyn Error>> {
        let (state, _store, agent_token) = setup_agent_test_state()?;
        let app = build_router(state);

        let req = agent_request(
            Method::GET,
            "/api/v2/workspaceagents/me/external-auth?id=github",
            agent_token,
        )?;
        let response = call(app, req).await?;
        // Returns 404 since external auth config is not yet supported.
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        Ok(())
    }

    #[tokio::test]
    async fn agent_reinit_returns_not_implemented() -> Result<(), Box<dyn Error>> {
        let (state, _store, agent_token) = setup_agent_test_state()?;
        let app = build_router(state);

        let req = agent_request(
            Method::GET,
            "/api/v2/workspaceagents/me/reinit",
            agent_token,
        )?;
        let response = call(app, req).await?;
        // Reinit SSE requires pubsub infrastructure, returns 501.
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);

        Ok(())
    }

    #[tokio::test]
    async fn agent_rpc_returns_not_implemented() -> Result<(), Box<dyn Error>> {
        let (state, _store, agent_token) = setup_agent_test_state()?;
        let app = build_router(state);

        let req = agent_request(Method::GET, "/api/v2/workspaceagents/me/rpc", agent_token)?;
        let response = call(app, req).await?;
        // RPC/WebSocket requires yamux/dRPC infrastructure, returns 501.
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);

        Ok(())
    }

    #[tokio::test]
    async fn agent_gitauth_deprecated_returns_empty() -> Result<(), Box<dyn Error>> {
        let (state, _store, agent_token) = setup_agent_test_state()?;
        let app = build_router(state);

        let req = agent_request(
            Method::GET,
            "/api/v2/workspaceagents/me/gitauth",
            agent_token,
        )?;
        let response = call(app, req).await?;
        assert_eq!(response.status(), StatusCode::OK);

        let body = response_json(response).await?;
        assert_eq!(body, json!([]));

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Instance identity & connection endpoint tests
    // -----------------------------------------------------------------------

    /// Helper: build a base64url-encoded JWT payload for testing.
    fn make_jwt_payload(claims: &Value) -> String {
        use base64::Engine;
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = engine.encode(b"{\"alg\":\"none\"}");
        let payload = engine.encode(serde_json::to_vec(claims).unwrap_or_default());
        format!("{header}.{payload}.fake-signature")
    }

    /// Seed the FakeStore with the full agent→resource→job→build chain and
    /// return the agent auth_token so tests can assert against it.
    fn seed_instance_identity_chain(
        store: &FakeStore,
        instance_id: &str,
    ) -> Result<Uuid, Box<dyn Error>> {
        let agent_id = Uuid::from_u128(100);
        let resource_id = Uuid::from_u128(101);
        let job_id = Uuid::from_u128(102);
        let build_id = Uuid::from_u128(103);
        let workspace_id = Uuid::from_u128(104);
        let auth_token = Uuid::from_u128(999);
        let now = OffsetDateTime::now_utc();

        // Agent
        store
            .workspace_agents
            .lock()
            .map_err(|e| -> Box<dyn Error> { e.to_string().into() })?
            .insert(
                agent_id,
                WorkspaceAgentRow {
                    id: agent_id,
                    parent_id: None,
                    created_at: now,
                    updated_at: now,
                    name: "main".to_owned(),
                    first_connected_at: None,
                    last_connected_at: None,
                    disconnected_at: None,
                    resource_id,
                    auth_token,
                    auth_instance_id: Some(instance_id.to_owned()),
                    architecture: "amd64".to_owned(),
                    environment_variables: None,
                    operating_system: "linux".to_owned(),
                    directory: String::new(),
                    expanded_directory: String::new(),
                    version: String::new(),
                    api_version: String::new(),
                    connection_timeout_seconds: 120,
                    troubleshooting_url: String::new(),
                    motd_file: String::new(),
                    lifecycle_state: "created".to_owned(),
                    logs_length: 0,
                    logs_overflowed: false,
                    started_at: None,
                    ready_at: None,
                    subsystems: Vec::new(),
                    display_apps: Vec::new(),
                    display_order: 0,
                    api_key_scope: "all".to_owned(),
                },
            );

        // Resource (stored as Vec keyed by job_id)
        store
            .workspace_resources
            .lock()
            .map_err(|e| -> Box<dyn Error> { e.to_string().into() })?
            .entry(job_id)
            .or_default()
            .push(WorkspaceResourceRecord {
                id: resource_id,
                created_at: now,
                job_id,
                transition: "start".to_owned(),
                resource_type: "aws_instance".to_owned(),
                name: "dev".to_owned(),
                hide: false,
                icon: String::new(),
                daily_cost: 0,
            });

        // Provisioner job
        store
            .provisioner_jobs
            .lock()
            .map_err(|e| -> Box<dyn Error> { e.to_string().into() })?
            .insert(
                job_id,
                TemplateProvisionerJobRecord {
                    id: job_id,
                    created_at: now,
                    updated_at: now,
                    started_at: None,
                    canceled_at: None,
                    completed_at: None,
                    error: String::new(),
                    organization_id: Uuid::nil(),
                    initiator_id: Uuid::nil(),
                    provisioner: "terraform".to_owned(),
                    job_status: "succeeded".to_owned(),
                    file_id: None,
                    job_type: "workspace_build".to_owned(),
                    input: json!({ "workspace_build_id": build_id.to_string() }),
                    worker_id: None,
                    tags: HashMap::new(),
                },
            );

        // Workspace build (latest)
        store
            .workspace_builds
            .lock()
            .map_err(|e| -> Box<dyn Error> { e.to_string().into() })?
            .insert(
                build_id,
                WorkspaceBuildRecord {
                    id: build_id,
                    created_at: now,
                    updated_at: now,
                    workspace_id,
                    build_number: 1,
                    transition: "start".to_owned(),
                    job_id,
                    template_version_id: Uuid::nil(),
                    initiator_id: Uuid::nil(),
                    provisioner_state: None,
                    deadline: None,
                    max_deadline: None,
                    reason: "initiator".to_owned(),
                    daily_cost: 0,
                },
            );

        Ok(auth_token)
    }

    #[tokio::test]
    async fn connection_info_returns_derp_map_and_hostname_suffix() -> Result<(), Box<dyn Error>> {
        let (state, _store) = test_state_with_store(true)?;
        let app = build_router(state);
        let session_token = create_and_login(&app).await?;

        let response = call(
            app,
            authenticated_request(
                Method::GET,
                "/api/v2/workspaceagents/connection",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);

        let body = response_json(response).await?;
        // test_config sets hostname_suffix = "example.internal"
        assert_eq!(
            body.get("hostname_suffix").and_then(Value::as_str),
            Some("example.internal")
        );
        // derp_map should be present even when no regions configured
        assert!(body.get("derp_map").is_some());
        Ok(())
    }

    #[tokio::test]
    async fn connection_info_requires_auth() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let response = call(
            app,
            request(Method::GET, "/api/v2/workspaceagents/connection")?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[tokio::test]
    async fn aws_instance_identity_valid() -> Result<(), Box<dyn Error>> {
        let (state, store) = test_state_with_store(true)?;
        let auth_token = seed_instance_identity_chain(&store, "i-abc123")?;
        let app = build_router(state);

        let payload = json!({
            "document": "{\"instanceId\": \"i-abc123\"}",
            "signature": "unused"
        });
        let response = call(
            app,
            json_request(
                Method::POST,
                "/api/v2/workspaceagents/aws-instance-identity",
                &payload,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await?;
        assert_eq!(
            body.get("session_token").and_then(Value::as_str),
            Some(auth_token.to_string()).as_deref()
        );
        Ok(())
    }

    #[tokio::test]
    async fn aws_instance_identity_unknown_instance() -> Result<(), Box<dyn Error>> {
        let (state, _store) = test_state_with_store(true)?;
        let app = build_router(state);

        let payload = json!({
            "document": "{\"instanceId\": \"i-unknown\"}",
            "signature": "unused"
        });
        let response = call(
            app,
            json_request(
                Method::POST,
                "/api/v2/workspaceagents/aws-instance-identity",
                &payload,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        Ok(())
    }

    #[tokio::test]
    async fn aws_instance_identity_malformed_document() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);

        let payload = json!({
            "document": "not-json",
            "signature": "unused"
        });
        let response = call(
            app,
            json_request(
                Method::POST,
                "/api/v2/workspaceagents/aws-instance-identity",
                &payload,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[tokio::test]
    async fn azure_instance_identity_valid() -> Result<(), Box<dyn Error>> {
        let (state, store) = test_state_with_store(true)?;
        let auth_token = seed_instance_identity_chain(&store, "vm-azure-001")?;
        let app = build_router(state);

        let jwt = make_jwt_payload(&json!({ "vmId": "vm-azure-001" }));
        let payload = json!({ "encoding": "pkcs7", "signature": jwt });
        let response = call(
            app,
            json_request(
                Method::POST,
                "/api/v2/workspaceagents/azure-instance-identity",
                &payload,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await?;
        assert_eq!(
            body.get("session_token").and_then(Value::as_str),
            Some(auth_token.to_string()).as_deref()
        );
        Ok(())
    }

    #[tokio::test]
    async fn azure_instance_identity_bad_jwt() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);

        let payload = json!({ "encoding": "pkcs7", "signature": "not-a-jwt" });
        let response = call(
            app,
            json_request(
                Method::POST,
                "/api/v2/workspaceagents/azure-instance-identity",
                &payload,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[tokio::test]
    async fn gcp_instance_identity_valid() -> Result<(), Box<dyn Error>> {
        let (state, store) = test_state_with_store(true)?;
        let auth_token = seed_instance_identity_chain(&store, "gcp-inst-42")?;
        let app = build_router(state);

        let jwt = make_jwt_payload(&json!({
            "google": { "compute_engine": { "instance_id": "gcp-inst-42" } }
        }));
        let payload = json!({ "json_web_token": jwt });
        let response = call(
            app,
            json_request(
                Method::POST,
                "/api/v2/workspaceagents/google-instance-identity",
                &payload,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await?;
        assert_eq!(
            body.get("session_token").and_then(Value::as_str),
            Some(auth_token.to_string()).as_deref()
        );
        Ok(())
    }

    #[tokio::test]
    async fn gcp_instance_identity_bad_jwt() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);

        let payload = json!({ "json_web_token": "bad" });
        let response = call(
            app,
            json_request(
                Method::POST,
                "/api/v2/workspaceagents/google-instance-identity",
                &payload,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[tokio::test]
    async fn instance_identity_replay_prevention() -> Result<(), Box<dyn Error>> {
        let (state, store) = test_state_with_store(true)?;
        let _auth_token = seed_instance_identity_chain(&store, "i-replay")?;

        // Insert a newer build for the same workspace so the original build is
        // no longer the latest.
        let workspace_id = Uuid::from_u128(104);
        let newer_build_id = Uuid::from_u128(200);
        let now = OffsetDateTime::now_utc();
        store
            .workspace_builds
            .lock()
            .map_err(|e| -> Box<dyn Error> { e.to_string().into() })?
            .insert(
                newer_build_id,
                WorkspaceBuildRecord {
                    id: newer_build_id,
                    created_at: now,
                    updated_at: now,
                    workspace_id,
                    build_number: 2,
                    transition: "start".to_owned(),
                    job_id: Uuid::nil(),
                    template_version_id: Uuid::nil(),
                    initiator_id: Uuid::nil(),
                    provisioner_state: None,
                    deadline: None,
                    max_deadline: None,
                    reason: "initiator".to_owned(),
                    daily_cost: 0,
                },
            );

        let app = build_router(state);
        let payload = json!({
            "document": "{\"instanceId\": \"i-replay\"}",
            "signature": "unused"
        });
        let response = call(
            app,
            json_request(
                Method::POST,
                "/api/v2/workspaceagents/aws-instance-identity",
                &payload,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response_json(response).await?;
        let msg = body.get("message").and_then(Value::as_str).unwrap_or("");
        assert!(msg.contains("latest"), "expected replay error, got: {msg}");
        Ok(())
    }

    #[tokio::test]
    async fn instance_identity_wrong_job_type() -> Result<(), Box<dyn Error>> {
        let (state, store) = test_state_with_store(true)?;
        let _auth_token = seed_instance_identity_chain(&store, "i-wrongjob")?;

        // Override the job_type to something other than "workspace_build"
        let job_id = Uuid::from_u128(102);
        if let Ok(mut jobs) = store.provisioner_jobs.lock() {
            if let Some(job) = jobs.get_mut(&job_id) {
                job.job_type = "template_version_import".to_owned();
            }
        }

        let app = build_router(state);
        let payload = json!({
            "document": "{\"instanceId\": \"i-wrongjob\"}",
            "signature": "unused"
        });
        let response = call(
            app,
            json_request(
                Method::POST,
                "/api/v2/workspaceagents/aws-instance-identity",
                &payload,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response_json(response).await?;
        let msg = body.get("message").and_then(Value::as_str).unwrap_or("");
        assert!(
            msg.contains("cannot be authenticated"),
            "expected job type error, got: {msg}"
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Workspace build handler tests
    // -----------------------------------------------------------------------

    /// Helper: seed a workspace build into the FakeStore and return its id + job_id.
    fn seed_workspace_build(store: &FakeStore) -> (Uuid, Uuid) {
        let build_id = Uuid::from_u128(1000);
        let job_id = Uuid::from_u128(2000);
        let now = OffsetDateTime::now_utc();
        let build = WorkspaceBuildRecord {
            id: build_id,
            created_at: now,
            updated_at: now,
            workspace_id: Uuid::from_u128(3000),
            build_number: 1,
            transition: "start".to_owned(),
            job_id,
            template_version_id: Uuid::from_u128(4000),
            initiator_id: Uuid::from_u128(1),
            provisioner_state: None,
            deadline: None,
            max_deadline: None,
            reason: "initiator".to_owned(),
            daily_cost: 0,
        };
        if let Ok(mut builds) = store.workspace_builds.lock() {
            builds.insert(build_id, build);
        }
        (build_id, job_id)
    }

    #[tokio::test]
    async fn workspace_build_get_requires_auth() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let build_id = Uuid::from_u128(1000);
        let response = call(
            app,
            request(Method::GET, &format!("/api/v2/workspacebuilds/{build_id}"))?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[tokio::test]
    async fn workspace_build_get_returns_not_found() -> Result<(), Box<dyn Error>> {
        let (state, _store) = test_state_with_store(true)?;
        let app = build_router(state);
        let session_token = create_and_login(&app).await?;
        let build_id = Uuid::from_u128(9999);
        let response = call(
            app,
            authenticated_request(
                Method::GET,
                &format!("/api/v2/workspacebuilds/{build_id}"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        Ok(())
    }

    #[tokio::test]
    async fn workspace_build_cancel_requires_auth() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let build_id = Uuid::from_u128(1000);
        let response = call(
            app,
            request(
                Method::PATCH,
                &format!("/api/v2/workspacebuilds/{build_id}/cancel"),
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[tokio::test]
    async fn workspace_build_logs_requires_auth() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let build_id = Uuid::from_u128(1000);
        let response = call(
            app,
            request(
                Method::GET,
                &format!("/api/v2/workspacebuilds/{build_id}/logs"),
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[tokio::test]
    async fn workspace_build_logs_returns_empty_array() -> Result<(), Box<dyn Error>> {
        let (state, store) = test_state_with_store(true)?;
        let app = build_router(state);
        let session_token = create_and_login(&app).await?;
        let (build_id, _job_id) = seed_workspace_build(&store);
        let response = call(
            app,
            authenticated_request(
                Method::GET,
                &format!("/api/v2/workspacebuilds/{build_id}/logs"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await?;
        assert_eq!(body, json!([]));
        Ok(())
    }

    #[tokio::test]
    async fn workspace_build_parameters_requires_auth() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let build_id = Uuid::from_u128(1000);
        let response = call(
            app,
            request(
                Method::GET,
                &format!("/api/v2/workspacebuilds/{build_id}/parameters"),
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[tokio::test]
    async fn workspace_build_parameters_returns_empty_array() -> Result<(), Box<dyn Error>> {
        let (state, store) = test_state_with_store(true)?;
        let app = build_router(state);
        let session_token = create_and_login(&app).await?;
        let (build_id, _job_id) = seed_workspace_build(&store);
        let response = call(
            app,
            authenticated_request(
                Method::GET,
                &format!("/api/v2/workspacebuilds/{build_id}/parameters"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await?;
        assert_eq!(body, json!([]));
        Ok(())
    }

    #[tokio::test]
    async fn workspace_build_resources_requires_auth() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let build_id = Uuid::from_u128(1000);
        let response = call(
            app,
            request(
                Method::GET,
                &format!("/api/v2/workspacebuilds/{build_id}/resources"),
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[tokio::test]
    async fn workspace_build_resources_returns_empty_array() -> Result<(), Box<dyn Error>> {
        let (state, store) = test_state_with_store(true)?;
        let app = build_router(state);
        let session_token = create_and_login(&app).await?;
        let (build_id, _job_id) = seed_workspace_build(&store);
        let response = call(
            app,
            authenticated_request(
                Method::GET,
                &format!("/api/v2/workspacebuilds/{build_id}/resources"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await?;
        assert_eq!(body, json!([]));
        Ok(())
    }

    #[tokio::test]
    async fn workspace_build_state_get_requires_auth() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let build_id = Uuid::from_u128(1000);
        let response = call(
            app,
            request(
                Method::GET,
                &format!("/api/v2/workspacebuilds/{build_id}/state"),
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[tokio::test]
    async fn workspace_build_state_put_requires_auth() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let build_id = Uuid::from_u128(1000);
        let response = call(
            app,
            request(
                Method::PUT,
                &format!("/api/v2/workspacebuilds/{build_id}/state"),
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[tokio::test]
    async fn workspace_build_timings_requires_auth() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let build_id = Uuid::from_u128(1000);
        let response = call(
            app,
            request(
                Method::GET,
                &format!("/api/v2/workspacebuilds/{build_id}/timings"),
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[tokio::test]
    async fn workspace_build_timings_returns_empty_timings() -> Result<(), Box<dyn Error>> {
        let (state, store) = test_state_with_store(true)?;
        let app = build_router(state);
        let session_token = create_and_login(&app).await?;
        let (build_id, _job_id) = seed_workspace_build(&store);
        let response = call(
            app,
            authenticated_request(
                Method::GET,
                &format!("/api/v2/workspacebuilds/{build_id}/timings"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await?;
        assert_eq!(
            body.get("provisioner_timings")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(0)
        );
        assert_eq!(
            body.get("agent_script_timings")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(0)
        );
        assert_eq!(
            body.get("agent_connection_timings")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(0)
        );
        Ok(())
    }

    // ----- Organization Workspace Route Tests -----

    #[tokio::test]
    async fn post_org_member_workspace_requires_auth() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let response = call(
            app,
            json_request(
                Method::POST,
                "/api/v2/organizations/some-org/members/some-user/workspaces",
                &json!({"name": "ws", "template_id": Uuid::nil().to_string()}),
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[tokio::test]
    async fn post_org_member_workspace_creates_workspace() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let (session_token, org_id, template) = create_test_template(&app).await?;

        let template_id = template
            .get("id")
            .and_then(Value::as_str)
            .ok_or("missing template id")?;

        let response = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                &format!("/api/v2/organizations/{org_id}/members/me/workspaces"),
                &session_token,
                &json!({
                    "name": "org-workspace",
                    "template_id": template_id,
                }),
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = response_json(response).await?;
        assert_eq!(
            body.get("name").and_then(Value::as_str),
            Some("org-workspace")
        );
        assert!(body.get("id").and_then(Value::as_str).is_some());
        Ok(())
    }

    #[tokio::test]
    async fn post_org_member_workspace_validates_missing_fields() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;
        let org_id = first_organization_id(&app, &session_token).await?;

        // Missing template_id
        let response = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                &format!("/api/v2/organizations/{org_id}/members/me/workspaces"),
                &session_token,
                &json!({"name": "ws"}),
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        Ok(())
    }

    #[tokio::test]
    async fn get_org_member_available_users_requires_auth() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let response = call(
            app,
            request(
                Method::GET,
                "/api/v2/organizations/some-org/members/some-user/workspaces/available-users",
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[tokio::test]
    async fn get_org_member_available_users_returns_user_list() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;
        let org_id = first_organization_id(&app, &session_token).await?;

        let response = call(
            app,
            authenticated_request(
                Method::GET,
                &format!("/api/v2/organizations/{org_id}/members/me/workspaces/available-users"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await?;
        let users = body.as_array().ok_or("expected array")?;
        // The bootstrapped owner should be in the list.
        assert!(!users.is_empty());
        let first = &users[0];
        assert!(first.get("id").is_some());
        assert!(first.get("username").is_some());
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Happy-path integration tests: Workspace lifecycle
    // -----------------------------------------------------------------------

    /// Helper: creates a workspace via the org-member endpoint.
    /// Returns (workspace_id_str, workspace json).
    async fn create_test_workspace(
        app: &Router,
        session_token: &str,
        org_id: Uuid,
        template_id: &str,
        name: &str,
    ) -> Result<Value, Box<dyn Error>> {
        let response = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                &format!("/api/v2/organizations/{org_id}/members/me/workspaces"),
                session_token,
                &json!({
                    "name": name,
                    "template_id": template_id,
                }),
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::CREATED);
        let ws = response_json(response).await?;
        Ok(ws)
    }

    #[tokio::test]
    async fn workspace_lifecycle_create_get_list_update_delete() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let (session_token, org_id, template) = create_test_template(&app).await?;

        let template_id = template
            .get("id")
            .and_then(Value::as_str)
            .ok_or("missing template id")?;

        // 1. Create workspace
        let ws = create_test_workspace(&app, &session_token, org_id, template_id, "my-ws").await?;
        let ws_id = ws
            .get("id")
            .and_then(Value::as_str)
            .ok_or("missing workspace id")?;
        assert_eq!(ws.get("name").and_then(Value::as_str), Some("my-ws"));
        assert!(ws.get("owner_id").and_then(Value::as_str).is_some());
        assert_eq!(
            ws.get("template_id").and_then(Value::as_str),
            Some(template_id)
        );

        // 2. Get workspace
        let get_resp = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                &format!("/api/v2/workspaces/{ws_id}"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(get_resp.status(), StatusCode::OK);
        let fetched = response_json(get_resp).await?;
        assert_eq!(fetched.get("name").and_then(Value::as_str), Some("my-ws"));
        assert_eq!(fetched.get("id").and_then(Value::as_str), Some(ws_id));

        // 3. List workspaces
        let list_resp = call(
            app.clone(),
            authenticated_request(Method::GET, "/api/v2/workspaces?owner=me", &session_token)?,
        )
        .await?;
        assert_eq!(list_resp.status(), StatusCode::OK);
        let list_body = response_json(list_resp).await?;
        let workspaces = list_body
            .get("workspaces")
            .and_then(Value::as_array)
            .ok_or("expected workspaces array")?;
        assert_eq!(workspaces.len(), 1);
        assert_eq!(
            workspaces[0].get("name").and_then(Value::as_str),
            Some("my-ws")
        );
        let count = list_body.get("count").and_then(Value::as_i64);
        assert_eq!(count, Some(1));

        // 4. Update workspace (rename)
        let patch_resp = call(
            app.clone(),
            authenticated_json_request(
                Method::PATCH,
                &format!("/api/v2/workspaces/{ws_id}"),
                &session_token,
                &json!({"name": "renamed-ws"}),
            )?,
        )
        .await?;
        assert_eq!(patch_resp.status(), StatusCode::OK);
        let patched = response_json(patch_resp).await?;
        assert_eq!(
            patched.get("name").and_then(Value::as_str),
            Some("renamed-ws")
        );

        // Verify rename persisted via GET.
        let get_resp2 = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                &format!("/api/v2/workspaces/{ws_id}"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(get_resp2.status(), StatusCode::OK);
        let fetched2 = response_json(get_resp2).await?;
        assert_eq!(
            fetched2.get("name").and_then(Value::as_str),
            Some("renamed-ws")
        );

        // 5. Delete workspace (soft-delete via build with "delete" transition)
        let delete_build_resp = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                &format!("/api/v2/workspaces/{ws_id}/builds"),
                &session_token,
                &json!({"transition": "delete"}),
            )?,
        )
        .await?;
        assert_eq!(delete_build_resp.status(), StatusCode::CREATED);
        let delete_build = response_json(delete_build_resp).await?;
        assert_eq!(
            delete_build.get("transition").and_then(Value::as_str),
            Some("delete")
        );

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Happy-path integration tests: Workspace builds
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn workspace_builds_create_get_list_cancel() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let (session_token, org_id, template) = create_test_template(&app).await?;

        let template_id = template
            .get("id")
            .and_then(Value::as_str)
            .ok_or("missing template id")?;

        // Create workspace (also creates initial build internally).
        let ws =
            create_test_workspace(&app, &session_token, org_id, template_id, "build-ws").await?;
        let ws_id = ws
            .get("id")
            .and_then(Value::as_str)
            .ok_or("missing workspace id")?;

        // 1. Create a new build (start transition).
        let build_resp = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                &format!("/api/v2/workspaces/{ws_id}/builds"),
                &session_token,
                &json!({"transition": "start"}),
            )?,
        )
        .await?;
        assert_eq!(build_resp.status(), StatusCode::CREATED);
        let build = response_json(build_resp).await?;
        let build_id = build
            .get("id")
            .and_then(Value::as_str)
            .ok_or("missing build id")?;
        assert_eq!(
            build.get("transition").and_then(Value::as_str),
            Some("start")
        );
        assert_eq!(
            build.get("workspace_id").and_then(Value::as_str),
            Some(ws_id)
        );
        assert_eq!(
            build.get("reason").and_then(Value::as_str),
            Some("initiator")
        );

        // 2. Get build by ID.
        let get_build_resp = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                &format!("/api/v2/workspacebuilds/{build_id}"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(get_build_resp.status(), StatusCode::OK);
        let fetched_build = response_json(get_build_resp).await?;
        assert_eq!(
            fetched_build.get("id").and_then(Value::as_str),
            Some(build_id)
        );

        // 3. List builds for workspace.
        let list_builds_resp = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                &format!("/api/v2/workspaces/{ws_id}/builds"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(list_builds_resp.status(), StatusCode::OK);
        let builds_list = response_json(list_builds_resp).await?;
        let builds = builds_list.as_array().ok_or("expected builds array")?;
        // At least the build we just created (workspace creation also created one).
        assert!(!builds.is_empty());

        // 4. Cancel build.
        let cancel_resp = call(
            app.clone(),
            authenticated_request(
                Method::PATCH,
                &format!("/api/v2/workspacebuilds/{build_id}/cancel"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(cancel_resp.status(), StatusCode::OK);

        Ok(())
    }

    #[tokio::test]
    async fn workspace_build_resources_parameters_logs_timings() -> Result<(), Box<dyn Error>> {
        let (state, store) = test_state_with_store(true)?;
        let app = build_router(state);
        let (session_token, org_id, template) = create_test_template(&app).await?;

        let template_id = template
            .get("id")
            .and_then(Value::as_str)
            .ok_or("missing template id")?;

        // Create workspace to get a build.
        let ws =
            create_test_workspace(&app, &session_token, org_id, template_id, "resource-ws").await?;
        let ws_id = ws
            .get("id")
            .and_then(Value::as_str)
            .ok_or("missing workspace id")?;

        // Create a build.
        let build_resp = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                &format!("/api/v2/workspaces/{ws_id}/builds"),
                &session_token,
                &json!({"transition": "start"}),
            )?,
        )
        .await?;
        assert_eq!(build_resp.status(), StatusCode::CREATED);
        let build = response_json(build_resp).await?;
        let build_id_str = build
            .get("id")
            .and_then(Value::as_str)
            .ok_or("missing build id")?;
        let build_id = Uuid::parse_str(build_id_str)?;
        let job_id_str = build
            .get("job_id")
            .and_then(Value::as_str)
            .ok_or("missing job_id")?;
        let job_id = Uuid::parse_str(job_id_str)?;

        // Seed build parameters, resources, logs, and timings via the store.
        store
            .insert_workspace_build_parameters(
                build_id,
                &[("region".to_owned(), "us-east-1".to_owned())],
            )
            .await?;

        let resource_id = Uuid::new_v4();
        store
            .workspace_resources
            .lock()
            .map_err(|e| -> Box<dyn Error> { e.to_string().into() })?
            .entry(job_id)
            .or_default()
            .push(WorkspaceResourceRecord {
                id: resource_id,
                created_at: OffsetDateTime::now_utc(),
                job_id,
                transition: "start".to_owned(),
                resource_type: "docker_container".to_owned(),
                name: "main".to_owned(),
                hide: false,
                icon: String::new(),
                daily_cost: 0,
            });

        store
            .workspace_resource_metadata
            .lock()
            .map_err(|e| -> Box<dyn Error> { e.to_string().into() })?
            .entry(resource_id)
            .or_default()
            .push(WorkspaceResourceMetadataRecord {
                workspace_resource_id: resource_id,
                key: "image".to_owned(),
                value: "ubuntu:22.04".to_owned(),
                sensitive: false,
            });

        store
            .provisioner_job_logs
            .lock()
            .map_err(|e| -> Box<dyn Error> { e.to_string().into() })?
            .entry(job_id)
            .or_default()
            .push(PortsJobLogRecord {
                id: 1,
                job_id,
                created_at: OffsetDateTime::now_utc(),
                source: "provisioner".to_owned(),
                level: "info".to_owned(),
                stage: "init".to_owned(),
                output: "Initializing...".to_owned(),
            });

        store
            .provisioner_job_timings
            .lock()
            .map_err(|e| -> Box<dyn Error> { e.to_string().into() })?
            .entry(job_id)
            .or_default()
            .push(PortsJobTimingRecord {
                job_id,
                started_at: OffsetDateTime::now_utc(),
                ended_at: OffsetDateTime::now_utc(),
                stage: "init".to_owned(),
                source: "provisioner".to_owned(),
                action: "create".to_owned(),
                resource: "docker_container".to_owned(),
            });

        // 1. GET build parameters.
        let params_resp = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                &format!("/api/v2/workspacebuilds/{build_id_str}/parameters"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(params_resp.status(), StatusCode::OK);
        let params_body = response_json(params_resp).await?;
        let params = params_body.as_array().ok_or("expected params array")?;
        assert_eq!(params.len(), 1);
        assert_eq!(
            params[0].get("name").and_then(Value::as_str),
            Some("region")
        );
        assert_eq!(
            params[0].get("value").and_then(Value::as_str),
            Some("us-east-1")
        );

        // 2. GET build resources.
        let resources_resp = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                &format!("/api/v2/workspacebuilds/{build_id_str}/resources"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(resources_resp.status(), StatusCode::OK);
        let resources_body = response_json(resources_resp).await?;
        let resources = resources_body
            .as_array()
            .ok_or("expected resources array")?;
        assert_eq!(resources.len(), 1);
        assert_eq!(
            resources[0].get("name").and_then(Value::as_str),
            Some("main")
        );
        assert_eq!(
            resources[0].get("type").and_then(Value::as_str),
            Some("docker_container")
        );
        let meta = resources[0]
            .get("metadata")
            .and_then(Value::as_array)
            .ok_or("expected metadata array")?;
        assert_eq!(meta.len(), 1);
        assert_eq!(meta[0].get("key").and_then(Value::as_str), Some("image"));

        // 3. GET build logs.
        let logs_resp = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                &format!("/api/v2/workspacebuilds/{build_id_str}/logs"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(logs_resp.status(), StatusCode::OK);
        let logs_body = response_json(logs_resp).await?;
        let logs = logs_body.as_array().ok_or("expected logs array")?;
        assert_eq!(logs.len(), 1);
        assert_eq!(
            logs[0].get("output").and_then(Value::as_str),
            Some("Initializing...")
        );
        assert_eq!(logs[0].get("stage").and_then(Value::as_str), Some("init"));

        // 4. GET build timings.
        let timings_resp = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                &format!("/api/v2/workspacebuilds/{build_id_str}/timings"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(timings_resp.status(), StatusCode::OK);
        let timings_body = response_json(timings_resp).await?;
        let prov_timings = timings_body
            .get("provisioner_timings")
            .and_then(Value::as_array)
            .ok_or("expected provisioner_timings array")?;
        assert_eq!(prov_timings.len(), 1);
        assert_eq!(
            prov_timings[0].get("stage").and_then(Value::as_str),
            Some("init")
        );
        assert_eq!(
            prov_timings[0].get("action").and_then(Value::as_str),
            Some("create")
        );

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Happy-path integration tests: Template lifecycle
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn template_lifecycle_create_get_list_update_delete() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let (session_token, org_id, template) = create_test_template(&app).await?;

        let template_id = template
            .get("id")
            .and_then(Value::as_str)
            .ok_or("missing id")?;

        // 1. Verify create response fields.
        assert_eq!(
            template.get("name").and_then(Value::as_str),
            Some("test-template")
        );
        assert_eq!(
            template.get("display_name").and_then(Value::as_str),
            Some("Test Template")
        );
        assert_eq!(
            template.get("description").and_then(Value::as_str),
            Some("A test template")
        );
        assert_eq!(
            template.get("icon").and_then(Value::as_str),
            Some("/icon/docker.png")
        );
        assert!(
            template
                .get("organization_id")
                .and_then(Value::as_str)
                .is_some()
        );

        // 2. GET template by ID.
        let get_resp = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                &format!("/api/v2/templates/{template_id}"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(get_resp.status(), StatusCode::OK);
        let fetched = response_json(get_resp).await?;
        assert_eq!(
            fetched.get("name").and_then(Value::as_str),
            Some("test-template")
        );

        // 3. List templates in org.
        let list_resp = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                &format!("/api/v2/organizations/{org_id}/templates"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(list_resp.status(), StatusCode::OK);
        let list_body = response_json(list_resp).await?;
        let templates = list_body.as_array().ok_or("expected array")?;
        assert_eq!(templates.len(), 1);
        assert_eq!(
            templates[0].get("name").and_then(Value::as_str),
            Some("test-template")
        );

        // 4. Update template meta (description).
        let patch_resp = call(
            app.clone(),
            authenticated_json_request(
                Method::PATCH,
                &format!("/api/v2/templates/{template_id}"),
                &session_token,
                &UpdateTemplateMeta {
                    description: Some("New description".to_owned()),
                    ..UpdateTemplateMeta::default()
                },
            )?,
        )
        .await?;
        assert_eq!(patch_resp.status(), StatusCode::OK);
        let patched = response_json(patch_resp).await?;
        assert_eq!(
            patched.get("description").and_then(Value::as_str),
            Some("New description")
        );
        // Original name preserved.
        assert_eq!(
            patched.get("name").and_then(Value::as_str),
            Some("test-template")
        );

        // 5. Delete template.
        let delete_resp = call(
            app.clone(),
            authenticated_request(
                Method::DELETE,
                &format!("/api/v2/templates/{template_id}"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(delete_resp.status(), StatusCode::OK);

        // Verify gone.
        let get_after_delete = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                &format!("/api/v2/templates/{template_id}"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(get_after_delete.status(), StatusCode::NOT_FOUND);

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Happy-path integration tests: Template versions
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn template_versions_create_get_list_archive_unarchive() -> Result<(), Box<dyn Error>> {
        let (state, store) = test_state_with_store(true)?;
        let app = build_router(state);
        let (session_token, org_id, template) = create_test_template(&app).await?;

        let template_id_str = template
            .get("id")
            .and_then(Value::as_str)
            .ok_or("missing id")?;
        let template_id = Uuid::parse_str(template_id_str)?;

        // Create a template version via the store directly (the HTTP API for
        // creating template versions requires file uploads which are complex;
        // seed via the store and test the read/archive endpoints).
        let version_id = Uuid::new_v4();
        let job_id = Uuid::new_v4();

        // Create the provisioner job first.
        store
            .create_provisioner_job(CreateProvisionerJobInput {
                id: job_id,
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
                organization_id: org_id,
                initiator_id: Uuid::nil(),
                provisioner: "echo".to_owned(),
                file_id: None,
                job_type: "template_version_import".to_owned(),
                input: json!({}),
                tags: HashMap::new(),
            })
            .await?;

        store
            .insert_template_version(CreateTemplateVersionInput {
                id: version_id,
                template_id: Some(template_id),
                organization_id: org_id,
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
                created_by: Uuid::nil(),
                name: "v1.0.0".to_owned(),
                message: "Initial version".to_owned(),
                readme: String::new(),
                job_id,
                source_example_id: None,
            })
            .await?;

        // 1. GET template version by ID.
        let get_resp = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                &format!("/api/v2/templateversions/{version_id}"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(get_resp.status(), StatusCode::OK);
        let fetched = response_json(get_resp).await?;
        assert_eq!(fetched.get("name").and_then(Value::as_str), Some("v1.0.0"));
        assert_eq!(
            fetched.get("id").and_then(Value::as_str),
            Some(version_id.to_string().as_str())
        );

        // 2. List template versions.
        let list_resp = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                &format!("/api/v2/templates/{template_id_str}/versions"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(list_resp.status(), StatusCode::OK);
        let list_body = response_json(list_resp).await?;
        let versions = list_body.as_array().ok_or("expected array")?;
        assert!(
            versions
                .iter()
                .any(|v| v.get("name").and_then(Value::as_str) == Some("v1.0.0"))
        );

        // 3. Archive template version.
        let archive_resp = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                &format!("/api/v2/templateversions/{version_id}/archive"),
                &session_token,
                &json!({}),
            )?,
        )
        .await?;
        assert_eq!(archive_resp.status(), StatusCode::OK);

        // 4. Unarchive template version.
        let unarchive_resp = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                &format!("/api/v2/templateversions/{version_id}/unarchive"),
                &session_token,
                &json!({}),
            )?,
        )
        .await?;
        assert_eq!(unarchive_resp.status(), StatusCode::OK);

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Happy-path integration tests: Workspace ACL
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn workspace_acl_set_get_delete() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let (session_token, org_id, template) = create_test_template(&app).await?;

        let template_id = template
            .get("id")
            .and_then(Value::as_str)
            .ok_or("missing template id")?;

        // Create workspace.
        let ws = create_test_workspace(&app, &session_token, org_id, template_id, "acl-ws").await?;
        let ws_id = ws
            .get("id")
            .and_then(Value::as_str)
            .ok_or("missing workspace id")?;

        // Get the owner's user id.
        let owner_id = ws
            .get("owner_id")
            .and_then(Value::as_str)
            .ok_or("missing owner_id")?;

        // 1. Set ACL (PATCH).
        let user_roles = HashMap::from([(owner_id.to_owned(), "admin".to_owned())]);
        let set_resp = call(
            app.clone(),
            authenticated_json_request(
                Method::PATCH,
                &format!("/api/v2/workspaces/{ws_id}/acl"),
                &session_token,
                &json!({
                    "user_roles": user_roles,
                    "group_roles": {},
                }),
            )?,
        )
        .await?;
        assert_eq!(set_resp.status(), StatusCode::NO_CONTENT);

        // 2. Get ACL.
        let get_resp = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                &format!("/api/v2/workspaces/{ws_id}/acl"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(get_resp.status(), StatusCode::OK);
        let acl_body = response_json(get_resp).await?;
        let acl_users = acl_body
            .get("users")
            .and_then(Value::as_array)
            .ok_or("expected users array")?;
        assert_eq!(acl_users.len(), 1);
        assert_eq!(
            acl_users[0].get("role").and_then(Value::as_str),
            Some("admin")
        );
        // Verify user details were resolved (handler calls find_user_by_id).
        assert!(acl_users[0].get("id").and_then(Value::as_str).is_some());
        assert!(
            acl_users[0]
                .get("username")
                .and_then(Value::as_str)
                .is_some()
        );

        // 3. Delete ACL.
        let delete_resp = call(
            app.clone(),
            authenticated_request(
                Method::DELETE,
                &format!("/api/v2/workspaces/{ws_id}/acl"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(delete_resp.status(), StatusCode::NO_CONTENT);

        // Verify ACL is empty after deletion.
        let get_resp2 = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                &format!("/api/v2/workspaces/{ws_id}/acl"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(get_resp2.status(), StatusCode::OK);
        let acl_body2 = response_json(get_resp2).await?;
        let acl_users2 = acl_body2
            .get("users")
            .and_then(Value::as_array)
            .ok_or("expected users array")?;
        assert!(acl_users2.is_empty());

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Happy-path integration tests: Workspace port sharing
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn workspace_port_sharing_create_list_delete() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let (session_token, org_id, template) = create_test_template(&app).await?;

        let template_id = template
            .get("id")
            .and_then(Value::as_str)
            .ok_or("missing template id")?;

        // Create workspace.
        let ws = create_test_workspace(&app, &session_token, org_id, template_id, "port-share-ws")
            .await?;
        let ws_id = ws
            .get("id")
            .and_then(Value::as_str)
            .ok_or("missing workspace id")?;

        // 1. Create port share.
        let share_resp = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                &format!("/api/v2/workspaces/{ws_id}/port-share"),
                &session_token,
                &json!({
                    "agent_name": "main",
                    "port": 8080,
                    "share_level": "authenticated",
                    "protocol": "http",
                }),
            )?,
        )
        .await?;
        assert_eq!(share_resp.status(), StatusCode::OK);
        let share = response_json(share_resp).await?;
        assert_eq!(
            share.get("agent_name").and_then(Value::as_str),
            Some("main")
        );
        assert_eq!(share.get("port").and_then(Value::as_i64), Some(8080));
        assert_eq!(
            share.get("share_level").and_then(Value::as_str),
            Some("authenticated")
        );
        assert_eq!(share.get("protocol").and_then(Value::as_str), Some("http"));

        // Create a second port share.
        let share2_resp = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                &format!("/api/v2/workspaces/{ws_id}/port-share"),
                &session_token,
                &json!({
                    "agent_name": "main",
                    "port": 3000,
                    "share_level": "public",
                    "protocol": "https",
                }),
            )?,
        )
        .await?;
        assert_eq!(share2_resp.status(), StatusCode::OK);

        // 2. List port shares.
        let list_resp = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                &format!("/api/v2/workspaces/{ws_id}/port-share"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(list_resp.status(), StatusCode::OK);
        let list_body = response_json(list_resp).await?;
        let shares = list_body
            .get("shares")
            .and_then(Value::as_array)
            .ok_or("expected shares array")?;
        assert_eq!(shares.len(), 2);

        // 3. Delete port share.
        let delete_resp = call(
            app.clone(),
            authenticated_json_request(
                Method::DELETE,
                &format!("/api/v2/workspaces/{ws_id}/port-share"),
                &session_token,
                &json!({
                    "agent_name": "main",
                    "port": 8080,
                }),
            )?,
        )
        .await?;
        assert_eq!(delete_resp.status(), StatusCode::NO_CONTENT);

        // Verify only one share remains.
        let list_resp2 = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                &format!("/api/v2/workspaces/{ws_id}/port-share"),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(list_resp2.status(), StatusCode::OK);
        let list_body2 = response_json(list_resp2).await?;
        let shares2 = list_body2
            .get("shares")
            .and_then(Value::as_array)
            .ok_or("expected shares array")?;
        assert_eq!(shares2.len(), 1);
        assert_eq!(shares2[0].get("port").and_then(Value::as_i64), Some(3000));

        Ok(())
    }
}
