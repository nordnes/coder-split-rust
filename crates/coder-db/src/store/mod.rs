//! Postgres-backed application store.

use std::{str::FromStr, time::Duration};

use async_trait::async_trait;
use std::collections::HashMap;

use coder_core::api::{
    ConnectionLatency, DAUEntry, DAUsResponse, GetUserStatusCountsResponse, InsightsReportInterval,
    TemplateAppUsage, TemplateAppsType, TemplateInsightsIntervalReport, TemplateInsightsReport,
    TemplateInsightsResponse, TemplateParameterUsage, TemplateParameterValue, UserActivity,
    UserActivityInsightsReport, UserActivityInsightsResponse, UserLatency,
    UserLatencyInsightsReport, UserLatencyInsightsResponse, UserStatusChangeCount, VapidKeyPair,
};
use coder_core::ports::{UpdateWorkspaceACLInput, WorkspaceACLRecord, WorkspaceTransitionRow};
use coder_core::provisioner::{
    LogLevel, LogSource, ProvisionerJobLogRecord as ProvisionerLogRecord,
    ProvisionerJobTimingRecord as ProvisionerTimingRecord,
};
use coder_core::template::{
    CreateProvisionerJobInput, CreateTemplateInput, CreateTemplateStoreError,
    CreateTemplateVersionInput, ProvisionerJobRecord as TemplateProvisionerJobRecord,
    TemplateDAURow, TemplateListFilter, TemplateRecord, TemplateVersionListFilter,
    TemplateVersionParameterRecord, TemplateVersionPresetParameterRecord,
    TemplateVersionPresetRecord, TemplateVersionRecord, TemplateVersionVariableRecord,
    UpdateTemplateMetaInput,
};
use coder_core::{
    AcquireProvisionerJobInput, ApiAllowListTarget, ApiKeyListFilter, ApiKeyRecord,
    ApiKeyWithOwnerRecord, AppStore, AuditDiff, AuditLog, AuditLogAction, AuditLogListFilter,
    AuditLogResponse, AuditResourceType, AuthenticatedUser, CancelProvisionerJobInput,
    ChatFileRecord, ChatMessageRecord, ChatMessageVisibility, ChatModelConfigRecord,
    ChatProviderRecord, ChatQueuedMessageRecord, ChatRecord, ChatStatus,
    CompleteProvisionerJobInput, ConnectionLogListFilter, ConnectionLogResponse, CreateApiKeyInput,
    CreateApiKeyStoreError, CreateFirstUserInput, CreateFirstUserStoreError, CreateGroupInput,
    CreateOAuth2ProviderAppInput, CreateOAuth2ProviderAppTokenInput, CreateOrganizationInput,
    CreateOrganizationStoreError, CreateUserInput, CreateUserStoreError, CreateWorkspaceBuildInput,
    CreateWorkspaceInput, CustomRoleRecord, DatabaseConfig, DeploymentMetadata,
    DeploymentStatsResponse, DeploymentStore, ExternalAuthAppInstallation, ExternalAuthLinkRecord,
    ExternalAuthUser, FileRecord, FirstUserRecord, GetJobsToBeReapedInput, GitSshKeyRecord,
    GroupMemberRecord, GroupRecord, HealthSettings, InsertAgentLogInput, InsertChatFileInput,
    InsertChatInput, InsertChatMessageInput, InsertChatModelConfigInput, InsertChatProviderInput,
    InsertFileInput, InsertFileResult, InsertOrganizationMemberError, InsertProvisionerJobInput,
    InsertProvisionerJobLogsInput, InsertProvisionerJobTimingsInput, InsertProvisionerKeyInput,
    InsertTaskInput, InsertWorkspaceAppStatusInput, LicenseRecord, LoginType, MinimalOrganization,
    MinimalUser, NotificationMessageRecord, NotificationMessageStatus, NotificationMethod,
    OAuth2ProviderAppCodeRecord, OAuth2ProviderAppRecord, OAuth2ProviderAppSecretRecord,
    OAuth2ProviderAppTokenRecord, OrgResourceCounts, OrganizationMemberListFilter,
    OrganizationMemberRecord, OrganizationRecord, PasswordUserRecord, PersistAuditLogInput,
    ProvisionerDaemonHealthInput, ProvisionerDaemonHealthRecord, ProvisionerDaemonRecord,
    ProvisionerJobLogRecord, ProvisionerJobRecord, ProvisionerJobStatsInput, ProvisionerJobStatus,
    ProvisionerJobTimingRecord, ProvisionerJobTimingStage, ProvisionerJobType,
    ProvisionerKeyRecord, ProvisionerStorageMethod, ProvisionerStore, ProvisionerType,
    SessionCountDeploymentStatsResponse, SlimRoleRecord, StorageError, TaskListFilter, TaskRecord,
    TaskSnapshotRecord, TaskStatus, TokenConfigRecord, UpdateChatMessageContentInput,
    UpdateChatModelConfigInput, UpdateChatProviderInput, UpdateOAuth2ProviderAppInput,
    UpdateOrganizationInput, UpdateOrganizationStoreError, UpsertCustomRoleInput,
    UpsertExternalAuthLinkInput, UpsertPortShareInput, UpsertProvisionerDaemonInput,
    UpsertUserLinkInput, UserAppearanceRecord, UserConfigRecord, UserDeletedRecord, UserLinkRecord,
    UserListFilter, UserPreferenceRecord, UserRecord, UserStatus, UserStatusChangeRecord,
    WebpushSubscriptionRecord, WorkspaceAgentDevcontainerRow, WorkspaceAgentLogRow,
    WorkspaceAgentLogSourceRow, WorkspaceAgentMetadataRow, WorkspaceAgentPortShareRecord,
    WorkspaceAgentRow, WorkspaceAgentScriptRow, WorkspaceAgentScriptTimingRow,
    WorkspaceAgentStatInput, WorkspaceAppRow, WorkspaceAppStatusRow, WorkspaceBuildParameterRecord,
    WorkspaceBuildRecord, WorkspaceBuildStatsInput, WorkspaceConnectionLatencyMs,
    WorkspaceDeploymentStatsResponse, WorkspaceListFilter, WorkspaceProxyHealthInput,
    WorkspaceProxyHealthRecord, WorkspaceRecord, WorkspaceResourceMetadataRecord,
    WorkspaceResourceRecord, WorkspaceStatsWorkspaceInput,
};
use coder_core::{
    InboxNotification, InboxNotificationAction, NotificationPreference, NotificationTemplate,
    NotificationsSettings,
};
use serde_json::{Value, from_str};
use sqlx::{FromRow, PgPool, Postgres, Transaction, postgres::PgPoolOptions};
use thiserror::Error;
use time::OffsetDateTime;

// Domain module declarations
mod app_store;
mod deployment;
mod provisioner;

use tracing::instrument;
use uuid::Uuid;

use crate::migrations;

const REGULAR_MAX_TOKEN_LIFETIME_SECS: u64 = 60 * 60 * 24 * 30;
const OWNER_MAX_TOKEN_LIFETIME_SECS: u64 = 60 * 60 * 24 * 365;

/// Records a database query metric with operation name, duration, and success/failure.
///
/// Emits two metrics:
/// - `db_query_duration_ms` (histogram): query latency in milliseconds, labelled by
///   `operation` and `success`.
/// - `db_queries_total` (counter): total number of queries, labelled by `operation` and
///   `success`.
fn record_db_query(operation: &str, duration_ms: f64, success: bool) {
    let success_str = if success { "true" } else { "false" };
    metrics::histogram!("db_query_duration_ms", "operation" => operation.to_owned(), "success" => success_str)
        .record(duration_ms);
    metrics::counter!("db_queries_total", "operation" => operation.to_owned(), "success" => success_str)
        .increment(1);
}

/// Database initialization failures.
#[derive(Debug, Error)]
pub enum DatabaseInitError {
    /// Pool creation failed.
    #[error("connect to postgres: {source}")]
    Connect {
        /// Wrapped SQLx error.
        #[source]
        source: sqlx::Error,
    },
    /// Migration execution failed.
    #[error(transparent)]
    Migrate {
        /// Wrapped migration error.
        #[from]
        source: migrations::MigrationError,
    },
}

/// Postgres-backed implementation of the application store.
#[derive(Debug)]
pub struct PostgresStore {
    pool: PgPool,
}

#[derive(Debug, FromRow)]
struct StoredUserRow {
    id: Uuid,
    email: String,
    username: String,
    name: String,
    avatar_url: String,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    last_seen_at: Option<OffsetDateTime>,
    login_type: String,
    status: String,
    deleted: bool,
    is_system: bool,
    organization_ids: Vec<Uuid>,
    global_roles: Vec<String>,
}

#[derive(Debug, FromRow)]
struct StoredPasswordUserRow {
    id: Uuid,
    email: String,
    username: String,
    name: String,
    avatar_url: String,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    last_seen_at: Option<OffsetDateTime>,
    hashed_password: Vec<u8>,
    hashed_one_time_passcode: Vec<u8>,
    one_time_passcode_expires_at: Option<OffsetDateTime>,
    login_type: String,
    status: String,
    deleted: bool,
    is_system: bool,
    organization_ids: Vec<Uuid>,
    global_roles: Vec<String>,
}

#[derive(Debug, FromRow)]
struct StoredOrganizationRow {
    id: Uuid,
    name: String,
    display_name: String,
    description: String,
    icon: String,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    is_default: bool,
    deleted: bool,
}

#[derive(Debug, FromRow)]
struct StoredOrganizationMemberRow {
    user_id: Uuid,
    organization_id: Uuid,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    roles: Vec<String>,
    username: String,
    avatar_url: String,
    name: String,
    email: String,
    global_roles: Vec<String>,
}

#[derive(Debug, FromRow)]
struct StoredApiKeyRow {
    id: String,
    hashed_secret: Vec<u8>,
    user_id: Uuid,
    last_used: OffsetDateTime,
    expires_at: OffsetDateTime,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    login_type: String,
    scopes: Vec<String>,
    token_name: String,
    lifetime_seconds: i64,
    allow_list_json: String,
    username: Option<String>,
}

#[derive(Debug, FromRow)]
struct StoredAppearanceRow {
    theme_preference: String,
    terminal_font: String,
}

#[derive(Debug, FromRow)]
struct StoredPreferenceRow {
    task_notification_alert_dismissed: bool,
}

#[derive(Debug, FromRow)]
struct StoredAuditLogRow {
    id: Uuid,
    request_id: Option<Uuid>,
    time: OffsetDateTime,
    ip: String,
    user_agent: String,
    resource_type: String,
    resource_id: Option<Uuid>,
    resource_target: String,
    resource_icon: String,
    action: String,
    diff_json: String,
    status_code: i32,
    additional_fields_json: String,
    description: String,
    resource_link: String,
    is_deleted: bool,
    organization_id: Option<Uuid>,
    organization_name: Option<String>,
    organization_display_name: Option<String>,
    organization_icon: Option<String>,
    user_id: Option<Uuid>,
    username: Option<String>,
    name: Option<String>,
    avatar_url: Option<String>,
}

#[derive(Debug, FromRow)]
struct StoredGitSshKeyRow {
    user_id: Uuid,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    public_key: String,
    private_key: String,
}

#[derive(Debug, FromRow)]
struct StoredExternalAuthLinkRow {
    provider_id: String,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    access_token: String,
    refresh_token: String,
    token_type: String,
    scopes: Vec<String>,
    expires_at: OffsetDateTime,
    authenticated: bool,
    validate_error: String,
    refresh_error: String,
    last_validated_at: Option<OffsetDateTime>,
    last_refreshed_at: Option<OffsetDateTime>,
    external_user_json: String,
    installations_json: String,
    app_installable: bool,
}

#[derive(Debug, FromRow)]
struct StoredDeploymentWorkspaceStatsRow {
    pending_workspaces: i64,
    building_workspaces: i64,
    running_workspaces: i64,
    failed_workspaces: i64,
    stopped_workspaces: i64,
}

#[derive(Debug, FromRow)]
struct StoredDeploymentAgentStatsRow {
    workspace_rx_bytes: i64,
    workspace_tx_bytes: i64,
    workspace_connection_latency_50: f64,
    workspace_connection_latency_95: f64,
    session_count_vscode: i64,
    session_count_ssh: i64,
    session_count_jetbrains: i64,
    session_count_reconnecting_pty: i64,
}

#[derive(Debug, FromRow)]
struct StoredWorkspaceProxyRow {
    id: Uuid,
    name: String,
    display_name: String,
    icon_url: String,
    path_app_url: String,
    wildcard_hostname: String,
    derp_enabled: bool,
    derp_only: bool,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    deleted: bool,
    version: String,
}

#[derive(Debug, FromRow)]
struct StoredProvisionerDaemonRow {
    id: Uuid,
    organization_id: Uuid,
    created_at: OffsetDateTime,
    last_seen_at: Option<OffsetDateTime>,
    name: String,
    version: String,
    api_version: String,
    provisioners: Vec<String>,
    tags_json: String,
    status: Option<String>,
}

// ---------------------------------------------------------------------------
// Notification domain row types
// ---------------------------------------------------------------------------

#[derive(FromRow)]
struct StoredNotificationTemplateRow {
    id: Uuid,
    name: String,
    title_template: String,
    body_template: String,
    actions: Option<String>,
    #[sqlx(rename = "group")]
    group: Option<String>,
    method: Option<String>,
    kind: String,
    enabled_by_default: bool,
}

#[derive(FromRow)]
struct StoredNotificationPreferenceRow {
    id: Uuid,
    disabled: bool,
    updated_at: OffsetDateTime,
}

#[derive(FromRow)]
struct StoredInboxNotificationRow {
    id: Uuid,
    user_id: Uuid,
    template_id: Uuid,
    targets: Vec<Uuid>,
    title: String,
    content: String,
    icon: String,
    actions: String,
    read_at: Option<OffsetDateTime>,
    created_at: OffsetDateTime,
}

#[derive(FromRow)]
struct StoredWebpushSubscriptionRow {
    id: Uuid,
    user_id: Uuid,
    created_at: OffsetDateTime,
    endpoint: String,
    endpoint_p256dh_key: String,
    endpoint_auth_key: String,
}

#[derive(FromRow)]
struct StoredNotificationMessageRow {
    id: Uuid,
    user_id: Uuid,
    notification_template_id: Uuid,
    method: String,
    status: String,
    attempt_count: Option<i32>,
    payload: String,
    targets_json: String,
    created_at: OffsetDateTime,
    updated_at: Option<OffsetDateTime>,
}

#[derive(FromRow)]
struct StoredCustomRoleRow {
    name: String,
    display_name: String,
    organization_id: Option<Uuid>,
    site_permissions: String,
    org_permissions: String,
    user_permissions: String,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

#[derive(Debug, FromRow)]
struct StoredTaskRow {
    id: Uuid,
    organization_id: Uuid,
    owner_id: Uuid,
    name: String,
    display_name: String,
    workspace_id: Option<Uuid>,
    template_version_id: Uuid,
    template_parameters: Value,
    prompt: String,
    created_at: OffsetDateTime,
    deleted_at: Option<OffsetDateTime>,
}

#[derive(Debug, FromRow)]
struct StoredTaskSnapshotRow {
    task_id: Uuid,
    log_snapshot: Value,
    log_snapshot_created_at: OffsetDateTime,
}

#[derive(Debug, FromRow)]
struct StoredChatRow {
    id: Uuid,
    owner_id: Uuid,
    workspace_id: Option<Uuid>,
    title: String,
    status: String,
    last_error: Option<String>,
    parent_chat_id: Option<Uuid>,
    root_chat_id: Option<Uuid>,
    last_model_config_id: Uuid,
    archived: bool,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

#[derive(Debug, FromRow)]
struct StoredChatMessageRow {
    id: i64,
    chat_id: Uuid,
    model_config_id: Option<Uuid>,
    created_at: OffsetDateTime,
    role: String,
    content: Option<Value>,
    visibility: String,
    input_tokens: Option<i64>,
    output_tokens: Option<i64>,
    total_tokens: Option<i64>,
    reasoning_tokens: Option<i64>,
    cache_creation_tokens: Option<i64>,
    cache_read_tokens: Option<i64>,
    context_limit: Option<i64>,
    compressed: bool,
}

#[derive(Debug, FromRow)]
struct StoredChatQueuedMessageRow {
    id: i64,
    chat_id: Uuid,
    content: Value,
    created_at: OffsetDateTime,
}

#[derive(Debug, FromRow)]
struct StoredChatDiffStatusRow {
    chat_id: Uuid,
    url: Option<String>,
    pull_request_state: Option<String>,
    changes_requested: bool,
    additions: i32,
    deletions: i32,
    changed_files: i32,
    refreshed_at: Option<OffsetDateTime>,
    stale_at: Option<OffsetDateTime>,
    git_branch: String,
    git_remote_origin: String,
}

#[derive(Debug, FromRow)]
struct StoredChatFileRow {
    id: Uuid,
    owner_id: Uuid,
    organization_id: Uuid,
    created_at: OffsetDateTime,
    name: String,
    mimetype: String,
    data: Vec<u8>,
}

#[derive(FromRow)]
struct StoredChatProviderRow {
    id: Uuid,
    provider: String,
    display_name: String,
    api_key: String,
    base_url: String,
    enabled: bool,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl std::fmt::Debug for StoredChatProviderRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredChatProviderRow")
            .field("id", &self.id)
            .field("provider", &self.provider)
            .field("display_name", &self.display_name)
            .field("api_key", &"[REDACTED]")
            .field("base_url", &self.base_url)
            .field("enabled", &self.enabled)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

#[derive(Debug, FromRow)]
struct StoredChatModelConfigRow {
    id: Uuid,
    provider: String,
    model: String,
    display_name: String,
    enabled: bool,
    is_default: bool,
    context_limit: i64,
    compression_threshold: i32,
    options: Value,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

#[derive(Debug, FromRow)]
struct StoredWorkspaceAgentRow {
    id: Uuid,
    parent_id: Option<Uuid>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    name: String,
    first_connected_at: Option<OffsetDateTime>,
    last_connected_at: Option<OffsetDateTime>,
    disconnected_at: Option<OffsetDateTime>,
    resource_id: Uuid,
    auth_token: Uuid,
    auth_instance_id: Option<String>,
    architecture: String,
    environment_variables: Option<String>,
    operating_system: String,
    directory: String,
    expanded_directory: String,
    version: String,
    api_version: String,
    connection_timeout_seconds: i32,
    troubleshooting_url: String,
    motd_file: String,
    lifecycle_state: String,
    logs_length: i32,
    logs_overflowed: bool,
    started_at: Option<OffsetDateTime>,
    ready_at: Option<OffsetDateTime>,
    subsystems: Vec<String>,
    display_apps: Vec<String>,
    display_order: i32,
    api_key_scope: String,
}

#[derive(Debug, FromRow)]
struct StoredWorkspaceAppRow {
    id: Uuid,
    created_at: OffsetDateTime,
    agent_id: Uuid,
    display_name: String,
    icon: String,
    command: Option<String>,
    url: Option<String>,
    healthcheck_url: String,
    healthcheck_interval: i32,
    healthcheck_threshold: i32,
    health: String,
    subdomain: bool,
    sharing_level: String,
    slug: String,
    external: bool,
    display_order: i32,
    hidden: bool,
    open_in: String,
    display_group: Option<String>,
}

#[derive(Debug, FromRow)]
struct StoredWorkspaceAgentScriptRow {
    id: Uuid,
    workspace_agent_id: Uuid,
    log_source_id: Uuid,
    log_path: String,
    created_at: OffsetDateTime,
    script: String,
    cron: String,
    start_blocks_login: bool,
    run_on_start: bool,
    run_on_stop: bool,
    timeout_seconds: i32,
    display_name: String,
}

#[derive(Debug, FromRow)]
struct StoredWorkspaceAgentLogSourceRow {
    id: Uuid,
    workspace_agent_id: Uuid,
    created_at: OffsetDateTime,
    display_name: String,
    icon: String,
}

#[derive(Debug, FromRow)]
struct StoredWorkspaceAgentLogRow {
    id: i64,
    agent_id: Uuid,
    created_at: OffsetDateTime,
    output: String,
    level: String,
    log_source_id: Uuid,
}

#[derive(Debug, FromRow)]
struct StoredWorkspaceAgentMetadataRow {
    workspace_agent_id: Uuid,
    display_name: String,
    key: String,
    script: String,
    value: String,
    error: String,
    timeout: i64,
    interval: i64,
    collected_at: OffsetDateTime,
    display_order: i32,
}

#[derive(Debug, FromRow)]
struct StoredWorkspaceAgentDevcontainerRow {
    id: Uuid,
    workspace_agent_id: Uuid,
    created_at: OffsetDateTime,
    workspace_folder: String,
    config_path: String,
    name: String,
    subagent_id: Option<Uuid>,
}

#[derive(Debug, FromRow)]
struct StoredWorkspaceAppStatusRow {
    id: Uuid,
    created_at: OffsetDateTime,
    agent_id: Uuid,
    app_id: Uuid,
    workspace_id: Uuid,
    state: String,
    message: String,
    uri: Option<String>,
}

#[derive(Debug, FromRow)]
struct StoredProvisionerJobRow {
    id: Uuid,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    started_at: Option<OffsetDateTime>,
    canceled_at: Option<OffsetDateTime>,
    completed_at: Option<OffsetDateTime>,
    error: String,
    error_code: String,
    organization_id: Option<Uuid>,
    initiator_id: Option<Uuid>,
    provisioner: String,
    storage_method: String,
    file_id: Option<Uuid>,
    job_type: String,
    input: Value,
    tags: Value,
    trace_metadata: Value,
    worker_id: Option<Uuid>,
    job_status: String,
    logs_overflowed: bool,
    logs_length: i32,
}

#[derive(Debug, FromRow)]
struct StoredProvisionerJobLogRow {
    id: i64,
    job_id: Uuid,
    created_at: OffsetDateTime,
    source: String,
    level: String,
    stage: String,
    output: String,
}

#[derive(Debug, FromRow)]
struct StoredProvisionerJobTimingRow {
    job_id: Uuid,
    started_at: OffsetDateTime,
    ended_at: OffsetDateTime,
    stage: String,
    source: String,
    action: String,
    resource: String,
}

#[derive(Debug, FromRow)]
struct StoredProvisionerKeyRow {
    id: Uuid,
    created_at: OffsetDateTime,
    organization_id: Uuid,
    name: String,
    hashed_secret: Vec<u8>,
    tags: Value,
}

#[derive(Debug, FromRow)]
struct StoredFullProvisionerDaemonRow {
    id: Uuid,
    organization_id: Uuid,
    created_at: OffsetDateTime,
    last_seen_at: Option<OffsetDateTime>,
    name: String,
    version: String,
    api_version: String,
    provisioners: Vec<String>,
    tags_json: String,
    key_id: Option<Uuid>,
}

#[derive(Debug, FromRow)]
struct StoredWorkspaceResourceMetadataRow {
    workspace_resource_id: Uuid,
    key: String,
    value: String,
    sensitive: bool,
}

#[derive(Debug, FromRow)]
struct StoredUserLinkRow {
    user_id: Uuid,
    login_type: String,
    linked_id: String,
    oauth_access_token: String,
    oauth_refresh_token: String,
    oauth_expiry: OffsetDateTime,
    claims: Value,
}

#[derive(Debug, FromRow)]
struct StoredUserStatusChangeRow {
    id: Uuid,
    user_id: Uuid,
    new_status: String,
    old_status: String,
    changed_at: OffsetDateTime,
    changed_by: Option<Uuid>,
    reason: String,
}

#[derive(Debug, FromRow)]
struct StoredUserConfigRow {
    user_id: Uuid,
    key: String,
    value: String,
}

#[derive(Debug, FromRow)]
struct StoredUserDeletedRow {
    id: Uuid,
    user_id: Uuid,
    deleted_at: OffsetDateTime,
    deleted_by: Option<Uuid>,
    reason: String,
}

#[derive(Debug, FromRow)]
struct StoredFileRow {
    id: Uuid,
    hash: String,
    created_by: Uuid,
    created_at: OffsetDateTime,
    mimetype: String,
    data: Vec<u8>,
}

// ---------------------------------------------------------------------------
// License domain row types
// ---------------------------------------------------------------------------

#[derive(Debug, FromRow)]
struct StoredLicenseRow {
    id: i32,
    uuid: Uuid,
    uploaded_at: OffsetDateTime,
    jwt: String,
    #[allow(dead_code)]
    exp: OffsetDateTime,
}

// ---------------------------------------------------------------------------
// OAuth2 provider domain row types
// ---------------------------------------------------------------------------

#[derive(Debug, FromRow)]
struct StoredOAuth2ProviderAppRow {
    id: Uuid,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    name: String,
    icon: String,
    callback_url: String,
    redirect_uris: Vec<String>,
    created_by: Option<Uuid>,
}

#[derive(Debug, FromRow)]
struct StoredOAuth2ProviderAppSecretRow {
    id: Uuid,
    created_at: OffsetDateTime,
    last_used_at: Option<OffsetDateTime>,
    secret_prefix: Vec<u8>,
    hashed_secret: Vec<u8>,
    display_secret: String,
    app_id: Uuid,
}

#[derive(Debug, FromRow)]
struct StoredOAuth2ProviderAppCodeRow {
    id: Uuid,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    secret_prefix: Vec<u8>,
    hashed_secret: Vec<u8>,
    app_id: Uuid,
    user_id: Uuid,
    resource_uri: String,
    code_challenge: String,
    code_challenge_method: String,
    state_hash: Option<String>,
    redirect_uri: Option<String>,
}

#[derive(Debug, FromRow)]
struct StoredOAuth2ProviderAppTokenRow {
    id: Uuid,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    hash_prefix: Vec<u8>,
    refresh_hash: Vec<u8>,
    app_secret_id: Uuid,
    api_key_id: String,
    audience: String,
    user_id: Uuid,
}

impl PostgresStore {
    /// Connects to Postgres using the supplied configuration.
    pub async fn connect(config: &DatabaseConfig) -> Result<Self, DatabaseInitError> {
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .min_connections(config.min_connections)
            .acquire_timeout(Duration::from_secs(config.acquire_timeout_secs))
            .connect(&config.postgres_url)
            .await
            .map_err(|source| DatabaseInitError::Connect { source })?;

        Ok(Self { pool })
    }

    /// Returns a clone of the underlying connection pool.
    pub fn pool(&self) -> PgPool {
        self.pool.clone()
    }

    /// Applies the Rust rewrite migrations.
    pub async fn migrate(&self) -> Result<(), DatabaseInitError> {
        migrations::run_migrations(&self.pool).await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Template & Template Version StoredRow types
// ---------------------------------------------------------------------------

#[derive(Debug, FromRow)]
struct StoredTemplateRow {
    id: Uuid,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    organization_id: Uuid,
    deleted: bool,
    name: String,
    provisioner: String,
    active_version_id: Uuid,
    description: String,
    default_ttl: i64,
    created_by: Uuid,
    icon: String,
    user_acl: Value,
    group_acl: Value,
    display_name: String,
    allow_user_cancel_workspace_jobs: bool,
    allow_user_autostart: bool,
    allow_user_autostop: bool,
    failure_ttl: i64,
    time_til_dormant: i64,
    time_til_dormant_autodelete: i64,
    autostop_requirement_days_of_week: i16,
    autostop_requirement_weeks: i64,
    autostart_block_days_of_week: i16,
    require_active_version: bool,
    deprecated: String,
    activity_bump: i64,
    max_port_sharing_level: String,
    use_classic_parameter_flow: bool,
    cors_behavior: String,
    disable_module_cache: bool,
    organization_name: String,
    organization_display_name: String,
    organization_icon: String,
    created_by_username: String,
    created_by_avatar_url: String,
    created_by_name: String,
}

#[derive(Debug, FromRow)]
struct StoredTemplateProvisionerJobRow {
    id: Uuid,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    started_at: Option<OffsetDateTime>,
    canceled_at: Option<OffsetDateTime>,
    completed_at: Option<OffsetDateTime>,
    error: String,
    organization_id: Uuid,
    initiator_id: Uuid,
    provisioner: String,
    job_status: String,
    file_id: Option<Uuid>,
    #[sqlx(rename = "type")]
    job_type: String,
    input: Value,
    worker_id: Option<Uuid>,
    tags: Value,
}

#[derive(Debug, FromRow)]
struct StoredTemplateVersionRow {
    id: Uuid,
    template_id: Option<Uuid>,
    organization_id: Uuid,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    name: String,
    readme: String,
    job_id: Uuid,
    created_by: Uuid,
    external_auth_providers: Value,
    message: String,
    archived: bool,
    source_example_id: Option<String>,
    has_ai_task: Option<bool>,
    has_external_agent: Option<bool>,
    created_by_avatar_url: String,
    created_by_username: String,
    created_by_name: String,
}

#[derive(Debug, FromRow)]
struct StoredTemplateVersionParameterRow {
    template_version_id: Uuid,
    name: String,
    description: String,
    #[sqlx(rename = "type")]
    param_type: String,
    mutable: bool,
    default_value: String,
    icon: String,
    options: Value,
    validation_regex: String,
    validation_min: Option<i32>,
    validation_max: Option<i32>,
    validation_error: String,
    validation_monotonic: String,
    required: bool,
    display_name: String,
    display_order: i32,
    ephemeral: bool,
    form_type: String,
}

#[derive(Debug, FromRow)]
struct StoredTemplateVersionVariableRow {
    template_version_id: Uuid,
    name: String,
    description: String,
    #[sqlx(rename = "type")]
    var_type: String,
    value: String,
    default_value: String,
    required: bool,
    sensitive: bool,
}

#[derive(Debug, FromRow)]
struct StoredTemplateVersionPresetRow {
    id: Uuid,
    template_version_id: Uuid,
    name: String,
    created_at: OffsetDateTime,
    is_default: bool,
    description: String,
    icon: String,
}

#[derive(Debug, FromRow)]
struct StoredTemplateVersionPresetParameterRow {
    id: Uuid,
    template_version_preset_id: Uuid,
    name: String,
    value: String,
}

#[derive(Debug, FromRow)]
struct StoredDAURow {
    date: String,
    amount: i32,
}

fn template_record_from_row(row: StoredTemplateRow) -> TemplateRecord {
    let user_acl: HashMap<String, Value> = serde_json::from_value(row.user_acl).unwrap_or_default();
    let group_acl: HashMap<String, Value> =
        serde_json::from_value(row.group_acl).unwrap_or_default();
    TemplateRecord {
        id: row.id,
        created_at: row.created_at,
        updated_at: row.updated_at,
        organization_id: row.organization_id,
        organization_name: row.organization_name,
        organization_display_name: row.organization_display_name,
        organization_icon: row.organization_icon,
        deleted: row.deleted,
        name: row.name,
        provisioner: row.provisioner,
        active_version_id: row.active_version_id,
        description: row.description,
        default_ttl: row.default_ttl,
        created_by: row.created_by,
        icon: row.icon,
        user_acl,
        group_acl,
        display_name: row.display_name,
        allow_user_cancel_workspace_jobs: row.allow_user_cancel_workspace_jobs,
        allow_user_autostart: row.allow_user_autostart,
        allow_user_autostop: row.allow_user_autostop,
        failure_ttl: row.failure_ttl,
        time_til_dormant: row.time_til_dormant,
        time_til_dormant_autodelete: row.time_til_dormant_autodelete,
        autostop_requirement_days_of_week: row.autostop_requirement_days_of_week,
        autostop_requirement_weeks: row.autostop_requirement_weeks,
        autostart_block_days_of_week: row.autostart_block_days_of_week,
        require_active_version: row.require_active_version,
        deprecated: row.deprecated,
        activity_bump: row.activity_bump,
        max_port_sharing_level: row.max_port_sharing_level,
        use_classic_parameter_flow: row.use_classic_parameter_flow,
        cors_behavior: row.cors_behavior,
        disable_module_cache: row.disable_module_cache,
        created_by_username: row.created_by_username,
        created_by_avatar_url: row.created_by_avatar_url,
        created_by_name: row.created_by_name,
    }
}

fn template_provisioner_job_record_from_row(
    row: StoredTemplateProvisionerJobRow,
) -> TemplateProvisionerJobRecord {
    let tags: HashMap<String, String> = serde_json::from_value(row.tags).unwrap_or_default();
    TemplateProvisionerJobRecord {
        id: row.id,
        created_at: row.created_at,
        updated_at: row.updated_at,
        started_at: row.started_at,
        canceled_at: row.canceled_at,
        completed_at: row.completed_at,
        error: row.error,
        organization_id: row.organization_id,
        initiator_id: row.initiator_id,
        provisioner: row.provisioner,
        job_status: row.job_status,
        file_id: row.file_id,
        job_type: row.job_type,
        input: row.input,
        worker_id: row.worker_id,
        tags,
    }
}

fn template_version_record_from_row(row: StoredTemplateVersionRow) -> TemplateVersionRecord {
    TemplateVersionRecord {
        id: row.id,
        template_id: row.template_id,
        organization_id: row.organization_id,
        created_at: row.created_at,
        updated_at: row.updated_at,
        name: row.name,
        readme: row.readme,
        job_id: row.job_id,
        created_by: row.created_by,
        external_auth_providers: row.external_auth_providers,
        message: row.message,
        archived: row.archived,
        source_example_id: row.source_example_id,
        has_ai_task: row.has_ai_task,
        has_external_agent: row.has_external_agent,
        created_by_avatar_url: row.created_by_avatar_url,
        created_by_username: row.created_by_username,
        created_by_name: row.created_by_name,
    }
}

fn template_version_parameter_from_row(
    row: StoredTemplateVersionParameterRow,
) -> TemplateVersionParameterRecord {
    TemplateVersionParameterRecord {
        template_version_id: row.template_version_id,
        name: row.name,
        description: row.description,
        param_type: row.param_type,
        mutable: row.mutable,
        default_value: row.default_value,
        icon: row.icon,
        options: row.options,
        validation_regex: row.validation_regex,
        validation_min: row.validation_min,
        validation_max: row.validation_max,
        validation_error: row.validation_error,
        validation_monotonic: row.validation_monotonic,
        required: row.required,
        display_name: row.display_name,
        display_order: row.display_order,
        ephemeral: row.ephemeral,
        form_type: row.form_type,
    }
}

fn template_version_variable_from_row(
    row: StoredTemplateVersionVariableRow,
) -> TemplateVersionVariableRecord {
    TemplateVersionVariableRecord {
        template_version_id: row.template_version_id,
        name: row.name,
        description: row.description,
        var_type: row.var_type,
        value: row.value,
        default_value: row.default_value,
        required: row.required,
        sensitive: row.sensitive,
    }
}

async fn ensure_default_organization(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<Uuid, StorageError> {
    let organization_id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO organizations (
            id,
            name,
            display_name,
            description,
            icon,
            created_at,
            updated_at,
            is_default,
            deleted,
            workspace_sharing_disabled
        )
        SELECT
            $1,
            'first-organization',
            'First Organization',
            'Builtin default organization.',
            '',
            NOW(),
            NOW(),
            true,
            false,
            false
        WHERE NOT EXISTS (
            SELECT 1
            FROM organizations
            WHERE is_default = true
        )",
    )
    .bind(organization_id)
    .execute(&mut **transaction)
    .await
    .map_err(storage_error)?;

    sqlx::query_scalar(
        "SELECT id
         FROM organizations
         WHERE is_default = true
         LIMIT 1",
    )
    .fetch_one(&mut **transaction)
    .await
    .map_err(storage_error)
}

fn user_record_from_row(row: StoredUserRow) -> Result<UserRecord, StorageError> {
    let login_type = LoginType::from_str(&row.login_type)
        .map_err(|error| StorageError::invalid_data(error.to_string()))?;
    let status = UserStatus::from_str(&row.status)
        .map_err(|error| StorageError::invalid_data(error.to_string()))?;

    Ok(UserRecord {
        id: row.id,
        email: row.email,
        username: row.username,
        name: row.name,
        avatar_url: row.avatar_url,
        created_at: row.created_at,
        updated_at: row.updated_at,
        last_seen_at: row.last_seen_at,
        organization_ids: row.organization_ids,
        roles: slim_roles_from_names(&row.global_roles, None),
        login_type,
        status,
        deleted: row.deleted,
        is_system: row.is_system,
    })
}

fn password_record_from_row(
    row: StoredPasswordUserRow,
) -> Result<PasswordUserRecord, StorageError> {
    let password_hash = String::from_utf8(row.hashed_password.clone()).map_err(|error| {
        StorageError::invalid_data(format!(
            "users.hashed_password must be valid UTF-8: {error}"
        ))
    })?;
    let one_time_passcode_hash = if row.hashed_one_time_passcode.is_empty() {
        None
    } else {
        Some(
            String::from_utf8(row.hashed_one_time_passcode.clone()).map_err(|error| {
                StorageError::invalid_data(format!(
                    "users.hashed_one_time_passcode must be valid UTF-8: {error}"
                ))
            })?,
        )
    };

    Ok(PasswordUserRecord {
        user: user_record_from_password_row(&row)?,
        password_hash,
        one_time_passcode_hash,
        one_time_passcode_expires_at: row.one_time_passcode_expires_at,
    })
}

fn user_record_from_password_row(row: &StoredPasswordUserRow) -> Result<UserRecord, StorageError> {
    let login_type = LoginType::from_str(&row.login_type)
        .map_err(|error| StorageError::invalid_data(error.to_string()))?;
    let status = UserStatus::from_str(&row.status)
        .map_err(|error| StorageError::invalid_data(error.to_string()))?;

    Ok(UserRecord {
        id: row.id,
        email: row.email.clone(),
        username: row.username.clone(),
        name: row.name.clone(),
        avatar_url: row.avatar_url.clone(),
        created_at: row.created_at,
        updated_at: row.updated_at,
        last_seen_at: row.last_seen_at,
        organization_ids: row.organization_ids.clone(),
        roles: slim_roles_from_names(&row.global_roles, None),
        login_type,
        status,
        deleted: row.deleted,
        is_system: row.is_system,
    })
}

fn organization_record_from_row(
    row: StoredOrganizationRow,
) -> Result<OrganizationRecord, StorageError> {
    if row.name.trim().is_empty() {
        return Err(StorageError::invalid_data(
            "organizations.name must not be empty",
        ));
    }

    Ok(OrganizationRecord {
        id: row.id,
        name: row.name,
        display_name: row.display_name,
        description: row.description,
        icon: row.icon,
        created_at: row.created_at,
        updated_at: row.updated_at,
        is_default: row.is_default,
        deleted: row.deleted,
    })
}

fn organization_member_record_from_row(
    row: StoredOrganizationMemberRow,
) -> Result<OrganizationMemberRecord, StorageError> {
    Ok(OrganizationMemberRecord {
        user_id: row.user_id,
        organization_id: row.organization_id,
        created_at: row.created_at,
        updated_at: row.updated_at,
        roles: slim_roles_from_names(&row.roles, Some(row.organization_id)),
        username: row.username,
        name: row.name,
        avatar_url: row.avatar_url,
        email: row.email,
        global_roles: slim_roles_from_names(&row.global_roles, None),
    })
}

fn api_key_record_from_row(row: StoredApiKeyRow) -> Result<ApiKeyRecord, StorageError> {
    let login_type = LoginType::from_str(&row.login_type)
        .map_err(|error| StorageError::invalid_data(error.to_string()))?;
    let allow_list = from_str::<Vec<ApiAllowListTarget>>(&row.allow_list_json)
        .map_err(|error| StorageError::invalid_data(error.to_string()))?;

    Ok(ApiKeyRecord {
        id: row.id,
        hashed_secret: row.hashed_secret,
        user_id: row.user_id,
        last_used: row.last_used,
        expires_at: row.expires_at,
        created_at: row.created_at,
        updated_at: row.updated_at,
        login_type,
        scopes: row.scopes,
        token_name: row.token_name,
        lifetime_seconds: row.lifetime_seconds,
        allow_list,
    })
}

fn audit_log_from_row(row: StoredAuditLogRow) -> Result<AuditLog, StorageError> {
    let resource_type = match row.resource_type.as_str() {
        "user" => AuditResourceType::User,
        "api_key" => AuditResourceType::ApiKey,
        "git_ssh_key" => AuditResourceType::GitSshKey,
        "health_settings" => AuditResourceType::HealthSettings,
        "organization" => AuditResourceType::Organization,
        "organization_member" => AuditResourceType::OrganizationMember,
        "convert_login" => AuditResourceType::ConvertLogin,
        other => {
            return Err(StorageError::invalid_data(format!(
                "unsupported audit resource type: {other}"
            )));
        }
    };
    let action = match row.action.as_str() {
        "create" => AuditLogAction::Create,
        "write" => AuditLogAction::Write,
        "delete" => AuditLogAction::Delete,
        "start" => AuditLogAction::Start,
        "stop" => AuditLogAction::Stop,
        "login" => AuditLogAction::Login,
        "logout" => AuditLogAction::Logout,
        "register" => AuditLogAction::Register,
        "request_password_reset" => AuditLogAction::RequestPasswordReset,
        other => {
            return Err(StorageError::invalid_data(format!(
                "unsupported audit action: {other}"
            )));
        }
    };
    let diff = from_str::<AuditDiff>(&row.diff_json)
        .map_err(|error| StorageError::invalid_data(error.to_string()))?;
    let additional_fields = from_str::<Value>(&row.additional_fields_json)
        .map_err(|error| StorageError::invalid_data(error.to_string()))?;

    Ok(AuditLog {
        id: row.id,
        request_id: row.request_id,
        time: row.time,
        ip: row.ip,
        user_agent: row.user_agent,
        resource_type,
        resource_id: row.resource_id,
        resource_target: row.resource_target,
        resource_icon: row.resource_icon,
        action,
        diff,
        status_code: row.status_code,
        additional_fields,
        description: row.description,
        resource_link: row.resource_link,
        is_deleted: row.is_deleted,
        organization_id: row.organization_id,
        organization: row.organization_id.map(|id| MinimalOrganization {
            id,
            name: row.organization_name.unwrap_or_default(),
            display_name: row.organization_display_name.unwrap_or_default(),
            icon: row.organization_icon.unwrap_or_default(),
        }),
        user: row.user_id.map(|id| MinimalUser {
            id,
            username: row.username.unwrap_or_default(),
            name: row.name.unwrap_or_default(),
            avatar_url: row.avatar_url.unwrap_or_default(),
        }),
    })
}

fn git_ssh_key_record_from_row(row: StoredGitSshKeyRow) -> Result<GitSshKeyRecord, StorageError> {
    if row.public_key.trim().is_empty() || row.private_key.trim().is_empty() {
        return Err(StorageError::invalid_data(
            "git ssh keys must contain both public and private material",
        ));
    }

    Ok(GitSshKeyRecord {
        user_id: row.user_id,
        created_at: row.created_at,
        updated_at: row.updated_at,
        public_key: row.public_key,
        private_key: row.private_key,
    })
}

fn external_auth_link_record_from_row(
    row: StoredExternalAuthLinkRow,
) -> Result<ExternalAuthLinkRecord, StorageError> {
    let user = match row.external_user_json.as_str() {
        "" | "null" => None,
        encoded => Some(
            from_str::<ExternalAuthUser>(encoded)
                .map_err(|error| StorageError::invalid_data(error.to_string()))?,
        ),
    };
    let installations = from_str::<Vec<ExternalAuthAppInstallation>>(&row.installations_json)
        .map_err(|error| StorageError::invalid_data(error.to_string()))?;

    Ok(ExternalAuthLinkRecord {
        provider_id: row.provider_id,
        created_at: row.created_at,
        updated_at: row.updated_at,
        has_refresh_token: !row.refresh_token.is_empty(),
        access_token: row.access_token,
        refresh_token: row.refresh_token,
        token_type: row.token_type,
        scopes: row.scopes,
        expires: row.expires_at,
        authenticated: row.authenticated,
        validate_error: row.validate_error,
        refresh_error: row.refresh_error,
        last_validated_at: row.last_validated_at,
        last_refreshed_at: row.last_refreshed_at,
        user,
        installations,
        app_installable: row.app_installable,
    })
}

fn workspace_proxy_record_from_row(row: StoredWorkspaceProxyRow) -> WorkspaceProxyHealthRecord {
    WorkspaceProxyHealthRecord {
        id: row.id,
        name: row.name,
        display_name: row.display_name,
        icon_url: row.icon_url,
        path_app_url: row.path_app_url,
        wildcard_hostname: row.wildcard_hostname,
        derp_enabled: row.derp_enabled,
        derp_only: row.derp_only,
        created_at: row.created_at,
        updated_at: row.updated_at,
        deleted: row.deleted,
        version: row.version,
    }
}

fn provisioner_daemon_record_from_row(
    row: StoredProvisionerDaemonRow,
) -> Result<ProvisionerDaemonHealthRecord, StorageError> {
    let tags =
        from_str(&row.tags_json).map_err(|error| StorageError::invalid_data(error.to_string()))?;

    Ok(ProvisionerDaemonHealthRecord {
        id: row.id,
        organization_id: row.organization_id,
        created_at: row.created_at,
        last_seen_at: row.last_seen_at,
        name: row.name,
        version: row.version,
        api_version: row.api_version,
        provisioners: row.provisioners,
        tags,
        status: row.status,
    })
}

fn provisioner_job_from_row(
    row: StoredProvisionerJobRow,
) -> Result<ProvisionerJobRecord, StorageError> {
    let provisioner = match row.provisioner.as_str() {
        "terraform" => ProvisionerType::Terraform,
        "echo" => ProvisionerType::Echo,
        other => {
            return Err(StorageError::invalid_data(format!(
                "unknown provisioner type: {other}"
            )));
        }
    };
    let storage_method = match row.storage_method.as_str() {
        "file" => ProvisionerStorageMethod::File,
        other => {
            return Err(StorageError::invalid_data(format!(
                "unknown storage method: {other}"
            )));
        }
    };
    let job_type = match row.job_type.as_str() {
        "template_version_import" => ProvisionerJobType::TemplateVersionImport,
        "template_version_dry_run" => ProvisionerJobType::TemplateVersionDryRun,
        "workspace_build" => ProvisionerJobType::WorkspaceBuild,
        other => {
            return Err(StorageError::invalid_data(format!(
                "unknown job type: {other}"
            )));
        }
    };
    let job_status = match row.job_status.as_str() {
        "pending" => ProvisionerJobStatus::Pending,
        "running" => ProvisionerJobStatus::Running,
        "succeeded" => ProvisionerJobStatus::Succeeded,
        "failed" => ProvisionerJobStatus::Failed,
        "canceling" => ProvisionerJobStatus::Canceling,
        "canceled" => ProvisionerJobStatus::Canceled,
        _ => ProvisionerJobStatus::Unknown,
    };

    Ok(ProvisionerJobRecord {
        id: row.id,
        created_at: row.created_at,
        updated_at: row.updated_at,
        started_at: row.started_at,
        canceled_at: row.canceled_at,
        completed_at: row.completed_at,
        error: row.error,
        error_code: row.error_code,
        organization_id: row.organization_id,
        initiator_id: row.initiator_id,
        provisioner,
        storage_method,
        file_id: row.file_id,
        job_type,
        input: row.input,
        tags: row.tags,
        trace_metadata: row.trace_metadata,
        worker_id: row.worker_id,
        job_status,
        logs_overflowed: row.logs_overflowed,
        logs_length: row.logs_length,
    })
}

fn provisioner_job_log_from_row(
    row: StoredProvisionerJobLogRow,
) -> Result<ProvisionerLogRecord, StorageError> {
    let source = match row.source.as_str() {
        "provisioner_daemon" => LogSource::ProvisionerDaemon,
        "provisioner" => LogSource::Provisioner,
        other => {
            return Err(StorageError::invalid_data(format!(
                "unknown log source: {other}"
            )));
        }
    };
    let level = match row.level.as_str() {
        "trace" => LogLevel::Trace,
        "debug" => LogLevel::Debug,
        "info" => LogLevel::Info,
        "warn" => LogLevel::Warn,
        "error" => LogLevel::Error,
        other => {
            return Err(StorageError::invalid_data(format!(
                "unknown log level: {other}"
            )));
        }
    };

    Ok(ProvisionerLogRecord {
        id: row.id,
        job_id: row.job_id,
        created_at: row.created_at,
        source,
        level,
        stage: row.stage,
        output: row.output,
    })
}

fn provisioner_job_timing_from_row(
    row: StoredProvisionerJobTimingRow,
) -> Result<ProvisionerTimingRecord, StorageError> {
    let stage = match row.stage.as_str() {
        "init" => ProvisionerJobTimingStage::Init,
        "plan" => ProvisionerJobTimingStage::Plan,
        "graph" => ProvisionerJobTimingStage::Graph,
        "apply" => ProvisionerJobTimingStage::Apply,
        other => {
            return Err(StorageError::invalid_data(format!(
                "unknown timing stage: {other}"
            )));
        }
    };

    Ok(ProvisionerTimingRecord {
        job_id: row.job_id,
        started_at: row.started_at,
        ended_at: row.ended_at,
        stage,
        source: row.source,
        action: row.action,
        resource: row.resource,
    })
}

fn provisioner_key_from_row(row: StoredProvisionerKeyRow) -> ProvisionerKeyRecord {
    ProvisionerKeyRecord {
        id: row.id,
        created_at: row.created_at,
        organization_id: row.organization_id,
        name: row.name,
        hashed_secret: row.hashed_secret,
        tags: row.tags,
    }
}

fn full_provisioner_daemon_from_row(
    row: StoredFullProvisionerDaemonRow,
) -> Result<ProvisionerDaemonRecord, StorageError> {
    let tags: HashMap<String, String> =
        from_str(&row.tags_json).map_err(|e| StorageError::invalid_data(e.to_string()))?;

    Ok(ProvisionerDaemonRecord {
        id: row.id,
        organization_id: row.organization_id,
        created_at: row.created_at,
        last_seen_at: row.last_seen_at,
        name: row.name,
        version: row.version,
        api_version: row.api_version,
        provisioners: row.provisioners,
        tags,
        key_id: row.key_id,
    })
}

fn file_record_from_row(row: StoredFileRow) -> FileRecord {
    FileRecord {
        id: row.id,
        hash: row.hash,
        created_by: row.created_by,
        created_at: row.created_at,
        mimetype: row.mimetype,
        data: row.data,
    }
}

fn slim_roles_from_names(
    role_names: &[String],
    organization_id: Option<Uuid>,
) -> Vec<SlimRoleRecord> {
    role_names
        .iter()
        .map(|role| SlimRoleRecord {
            name: role.clone(),
            display_name: role
                .split(['-', '_'])
                .filter(|part| !part.is_empty())
                .map(title_case)
                .collect::<Vec<_>>()
                .join(" "),
            organization_id,
        })
        .collect()
}

fn title_case(value: &str) -> String {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

fn task_record_from_row(row: StoredTaskRow) -> TaskRecord {
    // The tasks table doesn't store status directly; it's derived from workspace state.
    // For now we default to "pending" since we don't have workspace provisioning yet.
    TaskRecord {
        id: row.id,
        organization_id: row.organization_id,
        owner_id: row.owner_id,
        name: row.name,
        display_name: row.display_name,
        workspace_id: row.workspace_id,
        template_version_id: row.template_version_id,
        template_parameters: row.template_parameters,
        prompt: row.prompt,
        status: TaskStatus::Pending,
        created_at: row.created_at,
        deleted_at: row.deleted_at,
    }
}

fn chat_record_from_row(row: StoredChatRow) -> Result<ChatRecord, StorageError> {
    let status = match row.status.as_str() {
        "waiting" => ChatStatus::Waiting,
        "pending" => ChatStatus::Pending,
        "running" => ChatStatus::Running,
        "paused" => ChatStatus::Paused,
        "completed" => ChatStatus::Completed,
        "error" => ChatStatus::Error,
        other => {
            return Err(StorageError::invalid_data(format!(
                "unknown chat status: {other}"
            )));
        }
    };
    Ok(ChatRecord {
        id: row.id,
        owner_id: row.owner_id,
        workspace_id: row.workspace_id,
        title: row.title,
        status,
        last_error: row.last_error,
        parent_chat_id: row.parent_chat_id,
        root_chat_id: row.root_chat_id,
        last_model_config_id: row.last_model_config_id,
        archived: row.archived,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

fn chat_message_record_from_row(
    row: StoredChatMessageRow,
) -> Result<ChatMessageRecord, StorageError> {
    let visibility = match row.visibility.as_str() {
        "user" => ChatMessageVisibility::User,
        "model" => ChatMessageVisibility::Model,
        "both" => ChatMessageVisibility::Both,
        other => {
            return Err(StorageError::invalid_data(format!(
                "unknown chat message visibility: {other}"
            )));
        }
    };
    Ok(ChatMessageRecord {
        id: row.id,
        chat_id: row.chat_id,
        model_config_id: row.model_config_id,
        created_at: row.created_at,
        role: row.role,
        content: row.content,
        visibility,
        input_tokens: row.input_tokens,
        output_tokens: row.output_tokens,
        total_tokens: row.total_tokens,
        reasoning_tokens: row.reasoning_tokens,
        cache_creation_tokens: row.cache_creation_tokens,
        cache_read_tokens: row.cache_read_tokens,
        context_limit: row.context_limit,
        compressed: row.compressed,
    })
}

fn chat_provider_record_from_row(row: StoredChatProviderRow) -> ChatProviderRecord {
    ChatProviderRecord {
        id: row.id,
        provider: row.provider,
        display_name: row.display_name,
        api_key: row.api_key,
        base_url: row.base_url,
        enabled: row.enabled,
        created_at: row.created_at,
        updated_at: row.updated_at,
    }
}

fn chat_model_config_record_from_row(row: StoredChatModelConfigRow) -> ChatModelConfigRecord {
    ChatModelConfigRecord {
        id: row.id,
        provider: row.provider,
        model: row.model,
        display_name: row.display_name,
        enabled: row.enabled,
        is_default: row.is_default,
        context_limit: row.context_limit,
        compression_threshold: row.compression_threshold,
        options: row.options,
        created_at: row.created_at,
        updated_at: row.updated_at,
    }
}

fn inbox_notification_from_row(
    row: StoredInboxNotificationRow,
) -> Result<InboxNotification, StorageError> {
    let actions: Vec<InboxNotificationAction> =
        from_str(&row.actions).map_err(|error| StorageError::invalid_data(error.to_string()))?;

    Ok(InboxNotification {
        id: row.id,
        user_id: row.user_id,
        template_id: row.template_id,
        targets: row.targets,
        title: row.title,
        content: row.content,
        icon: row.icon,
        actions,
        read_at: row.read_at,
        created_at: row.created_at,
    })
}

fn notification_message_from_row(
    row: StoredNotificationMessageRow,
) -> Result<NotificationMessageRecord, StorageError> {
    let method = match row.method.as_str() {
        "smtp" => NotificationMethod::Email,
        "webhook" => NotificationMethod::Webhook,
        "inbox" => NotificationMethod::Inbox,
        other => {
            return Err(StorageError::invalid_data(format!(
                "unknown notification method: {other}"
            )));
        }
    };
    let status = match row.status.as_str() {
        "pending" => NotificationMessageStatus::Pending,
        "leased" => NotificationMessageStatus::Leased,
        "sent" => NotificationMessageStatus::Sent,
        "temporary_failure" => NotificationMessageStatus::TemporaryFailure,
        "permanent_failure" => NotificationMessageStatus::PermanentFailure,
        "unknown" => NotificationMessageStatus::Unknown,
        "inhibited" => NotificationMessageStatus::Inhibited,
        other => {
            return Err(StorageError::invalid_data(format!(
                "unknown notification message status: {other}"
            )));
        }
    };
    Ok(NotificationMessageRecord {
        id: row.id,
        user_id: row.user_id,
        notification_template_id: row.notification_template_id,
        method,
        status,
        attempt_count: row.attempt_count.unwrap_or(0),
        input_json: row.payload,
        targets_json: row.targets_json,
        created_at: row.created_at,
        updated_at: row.updated_at.unwrap_or(row.created_at),
    })
}

// ---------------------------------------------------------------------------
// Workspace domain StoredRow types
// ---------------------------------------------------------------------------

#[derive(Debug, FromRow)]
struct StoredWorkspaceRow {
    id: Uuid,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    deleted: bool,
    owner_id: Uuid,
    organization_id: Uuid,
    template_id: Uuid,
    name: String,
    autostart_schedule: Option<String>,
    ttl: Option<i64>,
    last_used_at: OffsetDateTime,
    dormant_at: Option<OffsetDateTime>,
    deleting_at: Option<OffsetDateTime>,
    automatic_updates: String,
    favorite: bool,
    next_start_at: Option<OffsetDateTime>,
}

#[derive(Debug, FromRow)]
struct StoredWorkspaceBuildRow {
    id: Uuid,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    workspace_id: Uuid,
    build_number: i64,
    transition: String,
    job_id: Uuid,
    template_version_id: Uuid,
    initiator_id: Uuid,
    provisioner_state: Option<Vec<u8>>,
    deadline: Option<OffsetDateTime>,
    max_deadline: Option<OffsetDateTime>,
    reason: String,
    daily_cost: i32,
}

#[derive(Debug, FromRow)]
struct StoredWorkspaceResourceRow {
    id: Uuid,
    created_at: OffsetDateTime,
    job_id: Uuid,
    transition: String,
    resource_type: String,
    name: String,
    hide: bool,
    icon: String,
    daily_cost: i32,
}

#[derive(Debug, FromRow)]
struct StoredWorkspaceBuildParameterRow {
    workspace_build_id: Uuid,
    name: String,
    value: String,
}

#[derive(Debug, FromRow)]
struct StoredPortShareRow {
    workspace_id: Uuid,
    agent_name: String,
    port: i32,
    share_level: String,
    protocol: String,
}

#[derive(Debug, FromRow)]
struct StoredWorkspaceTransitionRow {
    id: Uuid,
    name: String,
    owner_id: Uuid,
    template_id: Uuid,
    autostart_schedule: Option<String>,
    ttl: Option<i64>,
    last_used_at: OffsetDateTime,
    dormant_at: Option<OffsetDateTime>,
    deleting_at: Option<OffsetDateTime>,
    deleted: bool,
    build_transition: String,
    build_deadline: Option<OffsetDateTime>,
    job_status: String,
    job_completed_at: Option<OffsetDateTime>,
    template_allow_user_autostart: bool,
    template_default_ttl: i64,
    template_failure_ttl: i64,
    template_time_til_dormant: i64,
    template_time_til_dormant_autodelete: i64,
    owner_status: String,
    build_id: Uuid,
    max_deadline: Option<OffsetDateTime>,
    activity_bump_ns: i64,
}

fn workspace_transition_row_from_stored(
    row: StoredWorkspaceTransitionRow,
) -> WorkspaceTransitionRow {
    WorkspaceTransitionRow {
        id: row.id,
        name: row.name,
        owner_id: row.owner_id,
        template_id: row.template_id,
        autostart_schedule: row.autostart_schedule,
        ttl_ns: row.ttl,
        last_used_at: row.last_used_at,
        dormant_at: row.dormant_at,
        deleting_at: row.deleting_at,
        deleted: row.deleted,
        build_transition: row.build_transition,
        build_deadline: row.build_deadline,
        job_status: row.job_status,
        job_completed_at: row.job_completed_at,
        template_allow_user_autostart: row.template_allow_user_autostart,
        template_default_ttl: row.template_default_ttl,
        template_failure_ttl: row.template_failure_ttl,
        template_time_til_dormant: row.template_time_til_dormant,
        template_time_til_dormant_autodelete: row.template_time_til_dormant_autodelete,
        owner_status: row.owner_status,
        build_id: row.build_id,
        max_deadline: row.max_deadline,
        activity_bump_ns: row.activity_bump_ns,
    }
}

// ---------------------------------------------------------------------------
// Workspace domain conversion helpers
// ---------------------------------------------------------------------------

fn workspace_record_from_row(row: StoredWorkspaceRow) -> WorkspaceRecord {
    WorkspaceRecord {
        id: row.id,
        created_at: row.created_at,
        updated_at: row.updated_at,
        deleted: row.deleted,
        owner_id: row.owner_id,
        organization_id: row.organization_id,
        template_id: row.template_id,
        name: row.name,
        autostart_schedule: row.autostart_schedule,
        ttl_ns: row.ttl,
        last_used_at: row.last_used_at,
        dormant_at: row.dormant_at,
        deleting_at: row.deleting_at,
        automatic_updates: row.automatic_updates,
        favorite: row.favorite,
        next_start_at: row.next_start_at,
    }
}

fn workspace_build_record_from_row(row: StoredWorkspaceBuildRow) -> WorkspaceBuildRecord {
    WorkspaceBuildRecord {
        id: row.id,
        created_at: row.created_at,
        updated_at: row.updated_at,
        workspace_id: row.workspace_id,
        build_number: row.build_number,
        transition: row.transition,
        job_id: row.job_id,
        template_version_id: row.template_version_id,
        initiator_id: row.initiator_id,
        provisioner_state: row.provisioner_state,
        deadline: row.deadline,
        max_deadline: row.max_deadline,
        reason: row.reason,
        daily_cost: row.daily_cost,
    }
}

fn workspace_resource_record_from_row(row: StoredWorkspaceResourceRow) -> WorkspaceResourceRecord {
    WorkspaceResourceRecord {
        id: row.id,
        created_at: row.created_at,
        job_id: row.job_id,
        transition: row.transition,
        resource_type: row.resource_type,
        name: row.name,
        hide: row.hide,
        icon: row.icon,
        daily_cost: row.daily_cost,
    }
}

fn port_share_record_from_row(row: StoredPortShareRow) -> WorkspaceAgentPortShareRecord {
    WorkspaceAgentPortShareRecord {
        workspace_id: row.workspace_id,
        agent_name: row.agent_name,
        port: row.port,
        share_level: row.share_level,
        protocol: row.protocol,
    }
}

fn provisioner_job_log_record_from_row(row: StoredProvisionerJobLogRow) -> ProvisionerJobLogRecord {
    ProvisionerJobLogRecord {
        id: row.id,
        job_id: row.job_id,
        created_at: row.created_at,
        source: row.source,
        level: row.level,
        stage: row.stage,
        output: row.output,
    }
}

fn provisioner_job_timing_record_from_row(
    row: StoredProvisionerJobTimingRow,
) -> ProvisionerJobTimingRecord {
    ProvisionerJobTimingRecord {
        job_id: row.job_id,
        started_at: row.started_at,
        ended_at: row.ended_at,
        stage: row.stage,
        source: row.source,
        action: row.action,
        resource: row.resource,
    }
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    matches!(
        error,
        sqlx::Error::Database(database_error) if database_error.is_unique_violation()
    )
}

/// Escapes SQL LIKE metacharacters (`%`, `_`, `\`) so that user-supplied
/// search strings are matched literally.
fn escape_like(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '\\' | '%' | '_' => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    out
}

fn storage_error(error: sqlx::Error) -> StorageError {
    StorageError::unavailable(error.to_string())
}

/// Decodes JWT claims from the payload (middle) segment of a JWT string.
/// Returns an empty JSON object if decoding fails.
fn decode_jwt_claims(jwt: &str) -> Value {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() < 2 {
        return Value::Object(serde_json::Map::new());
    }
    let payload = parts[1];
    // JWT uses base64url encoding without padding (RFC 7515), but some
    // libraries emit trailing '=' padding. Strip it before decoding.
    use base64::Engine;
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let trimmed = payload.trim_end_matches('=');
    match engine.decode(trimmed) {
        Ok(bytes) => {
            serde_json::from_slice(&bytes).unwrap_or_else(|_| Value::Object(serde_json::Map::new()))
        }
        Err(_) => Value::Object(serde_json::Map::new()),
    }
}

/// Like [`storage_error`] but maps [`sqlx::Error::RowNotFound`] to
/// [`StorageError::NotFound`] instead of [`StorageError::Unavailable`].
/// Use this only for queries where a missing row is an expected
/// "not found" condition (e.g. UPDATE ... RETURNING on a specific row).
fn storage_error_or_not_found(error: sqlx::Error) -> StorageError {
    if matches!(error, sqlx::Error::RowNotFound) {
        return StorageError::not_found(error.to_string());
    }
    StorageError::unavailable(error.to_string())
}

// ---------------------------------------------------------------------------
// OAuth2 provider row-to-record conversions
// ---------------------------------------------------------------------------

fn oauth2_provider_app_from_row(row: StoredOAuth2ProviderAppRow) -> OAuth2ProviderAppRecord {
    OAuth2ProviderAppRecord {
        id: row.id,
        created_at: row.created_at,
        updated_at: row.updated_at,
        name: row.name,
        icon: row.icon,
        callback_url: row.callback_url,
        redirect_uris: row.redirect_uris,
        created_by: row.created_by,
    }
}

fn oauth2_provider_app_secret_from_row(
    row: StoredOAuth2ProviderAppSecretRow,
) -> OAuth2ProviderAppSecretRecord {
    OAuth2ProviderAppSecretRecord {
        id: row.id,
        created_at: row.created_at,
        last_used_at: row.last_used_at,
        secret_prefix: row.secret_prefix,
        hashed_secret: row.hashed_secret,
        display_secret: row.display_secret,
        app_id: row.app_id,
    }
}

fn oauth2_provider_app_code_from_row(
    row: StoredOAuth2ProviderAppCodeRow,
) -> OAuth2ProviderAppCodeRecord {
    OAuth2ProviderAppCodeRecord {
        id: row.id,
        created_at: row.created_at,
        expires_at: row.expires_at,
        secret_prefix: row.secret_prefix,
        hashed_secret: row.hashed_secret,
        app_id: row.app_id,
        user_id: row.user_id,
        resource_uri: row.resource_uri,
        code_challenge: row.code_challenge,
        code_challenge_method: row.code_challenge_method,
        state_hash: row.state_hash,
        redirect_uri: row.redirect_uri,
    }
}

fn oauth2_provider_app_token_from_row(
    row: StoredOAuth2ProviderAppTokenRow,
) -> OAuth2ProviderAppTokenRecord {
    OAuth2ProviderAppTokenRecord {
        id: row.id,
        created_at: row.created_at,
        expires_at: row.expires_at,
        hash_prefix: row.hash_prefix,
        refresh_hash: row.refresh_hash,
        app_secret_id: row.app_secret_id,
        api_key_id: row.api_key_id,
        audience: row.audience,
        user_id: row.user_id,
    }
}

fn workspace_agent_row_from_stored(row: StoredWorkspaceAgentRow) -> WorkspaceAgentRow {
    WorkspaceAgentRow {
        id: row.id,
        parent_id: row.parent_id,
        created_at: row.created_at,
        updated_at: row.updated_at,
        name: row.name,
        first_connected_at: row.first_connected_at,
        last_connected_at: row.last_connected_at,
        disconnected_at: row.disconnected_at,
        resource_id: row.resource_id,
        auth_token: row.auth_token,
        auth_instance_id: row.auth_instance_id,
        architecture: row.architecture,
        environment_variables: row.environment_variables,
        operating_system: row.operating_system,
        directory: row.directory,
        expanded_directory: row.expanded_directory,
        version: row.version,
        api_version: row.api_version,
        connection_timeout_seconds: row.connection_timeout_seconds,
        troubleshooting_url: row.troubleshooting_url,
        motd_file: row.motd_file,
        lifecycle_state: row.lifecycle_state,
        logs_length: row.logs_length,
        logs_overflowed: row.logs_overflowed,
        started_at: row.started_at,
        ready_at: row.ready_at,
        subsystems: row.subsystems,
        display_apps: row.display_apps,
        display_order: row.display_order,
        api_key_scope: row.api_key_scope,
    }
}

fn workspace_app_row_from_stored(row: StoredWorkspaceAppRow) -> WorkspaceAppRow {
    WorkspaceAppRow {
        id: row.id,
        created_at: row.created_at,
        agent_id: row.agent_id,
        display_name: row.display_name,
        icon: row.icon,
        command: row.command,
        url: row.url,
        healthcheck_url: row.healthcheck_url,
        healthcheck_interval: row.healthcheck_interval,
        healthcheck_threshold: row.healthcheck_threshold,
        health: row.health,
        subdomain: row.subdomain,
        sharing_level: row.sharing_level,
        slug: row.slug,
        external: row.external,
        display_order: row.display_order,
        hidden: row.hidden,
        open_in: row.open_in,
        display_group: row.display_group,
    }
}

fn workspace_agent_script_row_from_stored(
    row: StoredWorkspaceAgentScriptRow,
) -> WorkspaceAgentScriptRow {
    WorkspaceAgentScriptRow {
        id: row.id,
        workspace_agent_id: row.workspace_agent_id,
        log_source_id: row.log_source_id,
        log_path: row.log_path,
        created_at: row.created_at,
        script: row.script,
        cron: row.cron,
        start_blocks_login: row.start_blocks_login,
        run_on_start: row.run_on_start,
        run_on_stop: row.run_on_stop,
        timeout_seconds: row.timeout_seconds,
        display_name: row.display_name,
    }
}

fn workspace_agent_log_source_row_from_stored(
    row: StoredWorkspaceAgentLogSourceRow,
) -> WorkspaceAgentLogSourceRow {
    WorkspaceAgentLogSourceRow {
        id: row.id,
        workspace_agent_id: row.workspace_agent_id,
        created_at: row.created_at,
        display_name: row.display_name,
        icon: row.icon,
    }
}

fn workspace_agent_log_row_from_stored(row: StoredWorkspaceAgentLogRow) -> WorkspaceAgentLogRow {
    WorkspaceAgentLogRow {
        id: row.id,
        agent_id: row.agent_id,
        created_at: row.created_at,
        output: row.output,
        level: row.level,
        log_source_id: row.log_source_id,
    }
}

fn workspace_agent_metadata_row_from_stored(
    row: StoredWorkspaceAgentMetadataRow,
) -> WorkspaceAgentMetadataRow {
    WorkspaceAgentMetadataRow {
        workspace_agent_id: row.workspace_agent_id,
        display_name: row.display_name,
        key: row.key,
        script: row.script,
        value: row.value,
        error: row.error,
        timeout: row.timeout,
        interval: row.interval,
        collected_at: row.collected_at,
        display_order: row.display_order,
    }
}

fn workspace_agent_devcontainer_row_from_stored(
    row: StoredWorkspaceAgentDevcontainerRow,
) -> WorkspaceAgentDevcontainerRow {
    WorkspaceAgentDevcontainerRow {
        id: row.id,
        workspace_agent_id: row.workspace_agent_id,
        created_at: row.created_at,
        workspace_folder: row.workspace_folder,
        config_path: row.config_path,
        name: row.name,
        subagent_id: row.subagent_id,
    }
}

fn workspace_app_status_row_from_stored(row: StoredWorkspaceAppStatusRow) -> WorkspaceAppStatusRow {
    WorkspaceAppStatusRow {
        id: row.id,
        created_at: row.created_at,
        agent_id: row.agent_id,
        app_id: row.app_id,
        workspace_id: row.workspace_id,
        state: row.state,
        message: row.message,
        uri: row.uri,
    }
}

fn user_link_record_from_row(row: StoredUserLinkRow) -> Result<UserLinkRecord, StorageError> {
    let login_type = row
        .login_type
        .parse::<LoginType>()
        .map_err(|e| StorageError::invalid_data(e.to_string()))?;
    let claims = serde_json::from_value(row.claims).unwrap_or_default();
    Ok(UserLinkRecord {
        user_id: row.user_id,
        login_type,
        linked_id: row.linked_id,
        oauth_access_token: row.oauth_access_token,
        oauth_refresh_token: row.oauth_refresh_token,
        oauth_expiry: row.oauth_expiry,
        claims,
    })
}

fn user_status_change_record_from_row(
    row: StoredUserStatusChangeRow,
) -> Result<UserStatusChangeRecord, StorageError> {
    let new_status = row
        .new_status
        .parse::<UserStatus>()
        .map_err(|e| StorageError::invalid_data(e.to_string()))?;
    let old_status = row
        .old_status
        .parse::<UserStatus>()
        .map_err(|e| StorageError::invalid_data(e.to_string()))?;
    Ok(UserStatusChangeRecord {
        id: row.id,
        user_id: row.user_id,
        new_status,
        old_status,
        changed_at: row.changed_at,
        changed_by: row.changed_by,
        reason: row.reason,
    })
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    //! Integration tests for `PostgresStore` SQL paths.
    //!
    //! These tests run against a real Postgres database and verify SQL correctness,
    //! parameterization, JOINs, and row-to-record conversions that are not exercised
    //! by `FakeStore`-based unit tests.
    //!
    //! # Running
    //!
    //! Set `DATABASE_URL` to a Postgres connection string and run:
    //!
    //! ```sh
    //! DATABASE_URL="postgres://user:pass@localhost/coder_test" cargo test -p coder-db -- --ignored
    //! ```
    //!
    //! Without `DATABASE_URL` these tests are skipped (`#[ignore]`).

    use std::error::Error;

    use coder_core::template::{
        CreateTemplateInput, CreateTemplateVersionInput, TemplateVersionListFilter,
    };
    use coder_core::{
        AcquireProvisionerJobInput, AppStore, CreateGroupInput, CreateOAuth2ProviderAppInput,
        CreateOAuth2ProviderAppTokenInput, CreateUserInput, CreateWorkspaceBuildInput,
        CreateWorkspaceInput, DatabaseConfig, GetJobsToBeReapedInput, LoginType, ProvisionerStore,
        ProvisionerType, UserListFilter, UserStatus, WorkspaceListFilter,
    };
    use sqlx::PgPool;
    use time::OffsetDateTime;
    use uuid::Uuid;

    use super::PostgresStore;
    use coder_core::api::InsightsReportInterval;
    use serde_json::json;
    use time::macros::datetime;

    type TestResult = Result<(), Box<dyn Error>>;

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    /// Connect to a test database using `DATABASE_URL`. Returns `None` when the
    /// env var is missing so callers can bail out early (the `#[ignore]` attribute
    /// already gates these tests, but this is a safety net).
    async fn setup_store() -> Result<Option<PostgresStore>, Box<dyn Error>> {
        let url = match std::env::var("DATABASE_URL") {
            Ok(u) => u,
            Err(_) => return Ok(None),
        };

        let config = DatabaseConfig {
            postgres_url: url,
            max_connections: 5,
            min_connections: 1,
            acquire_timeout_secs: 10,
        };

        let store = PostgresStore::connect(&config).await?;
        store.migrate().await?;
        Ok(Some(store))
    }

    /// Create a test organization and return its id.
    async fn ensure_default_org(pool: &PgPool) -> Result<Uuid, Box<dyn Error>> {
        let org_id = Uuid::new_v4();
        let org_name = format!("test-org-{}", &org_id.to_string()[..8]);
        sqlx::query(
            "INSERT INTO organizations (id, name, display_name, description, icon, created_at, updated_at, is_default)
             VALUES ($1, $2, $3, '', '', NOW(), NOW(), false)
             ON CONFLICT DO NOTHING",
        )
        .bind(org_id)
        .bind(&org_name)
        .bind("Test Org")
        .execute(pool)
        .await?;
        Ok(org_id)
    }

    /// Create a test user and return its id.
    async fn create_test_user(
        store: &PostgresStore,
        org_id: Uuid,
        suffix: &str,
    ) -> Result<Uuid, Box<dyn Error>> {
        let input = CreateUserInput {
            email: format!("test-{suffix}@example.com"),
            username: format!("testuser-{suffix}"),
            name: format!("Test User {suffix}"),
            password_hash: Some("hashed".to_string()),
            login_type: LoginType::Password,
            status: UserStatus::Active,
            organization_ids: vec![org_id],
        };
        let user = store.create_user(input).await?;
        Ok(user.id)
    }

    /// Create a minimal provisioner job via raw SQL and return its id.
    /// We use raw SQL to avoid needing all the provisioner enum dependencies;
    /// the job only serves as a FK target for template versions and workspace builds.
    async fn create_provisioner_job(
        pool: &PgPool,
        org_id: Uuid,
        user_id: Uuid,
    ) -> Result<Uuid, Box<dyn Error>> {
        let job_id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO provisioner_jobs (
                id, created_at, updated_at, organization_id, initiator_id,
                provisioner, file_id, "type", input, tags
             ) VALUES (
                $1, NOW(), NOW(), $2, $3,
                'echo'::provisioner_type, NULL,
                'template_version_import'::provisioner_job_type,
                '{}'::jsonb, '{}'::jsonb
             )"#,
        )
        .bind(job_id)
        .bind(org_id)
        .bind(user_id)
        .execute(pool)
        .await?;
        Ok(job_id)
    }

    /// Create a template with an initial version and return the template id.
    async fn create_test_template(
        store: &PostgresStore,
        pool: &PgPool,
        org_id: Uuid,
        user_id: Uuid,
        name: &str,
    ) -> Result<Uuid, Box<dyn Error>> {
        let template_id = Uuid::new_v4();
        let version_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();
        let job_id = create_provisioner_job(pool, org_id, user_id).await?;

        let input = CreateTemplateInput {
            id: template_id,
            created_at: now,
            updated_at: now,
            organization_id: org_id,
            name: name.to_string(),
            display_name: name.to_string(),
            provisioner: "echo".to_string(),
            active_version_id: version_id,
            description: "test template".to_string(),
            default_ttl: 0,
            created_by: user_id,
            icon: "".to_string(),
            allow_user_cancel_workspace_jobs: true,
            allow_user_autostart: true,
            allow_user_autostop: true,
            failure_ttl: 0,
            time_til_dormant: 0,
            time_til_dormant_autodelete: 0,
            require_active_version: false,
            activity_bump: 0,
            max_port_share_level: "owner".to_string(),
        };

        store.insert_template(input).await?;

        let tv_input = CreateTemplateVersionInput {
            id: version_id,
            template_id: Some(template_id),
            organization_id: org_id,
            created_at: now,
            updated_at: now,
            name: format!("{name}-v1"),
            message: "initial".to_string(),
            readme: "".to_string(),
            job_id,
            created_by: user_id,
            source_example_id: None,
        };
        store.insert_template_version(tv_input).await?;

        Ok(template_id)
    }

    /// Unique suffix for test isolation.
    fn uniq() -> String {
        Uuid::new_v4().to_string()[..8].to_string()
    }

    // =========================================================================
    // 1. OAuth2 Provider App Lifecycle
    // =========================================================================

    #[tokio::test]
    #[ignore]
    async fn test_oauth2_secret_lifecycle() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;

        // Create app
        let app = store
            .create_oauth2_provider_app(&CreateOAuth2ProviderAppInput {
                name: format!("test-app-{}", uniq()),
                icon: "https://example.com/icon.png".to_string(),
                callback_url: "https://example.com/callback".to_string(),
                created_by: Some(user_id),
            })
            .await?;

        // Create secret
        let prefix = b"prefix1234";
        let hashed = b"hashedsecretbytes";
        let secret = store
            .create_oauth2_provider_app_secret(app.id, prefix, hashed, "disp****")
            .await?;
        assert_eq!(secret.app_id, app.id);
        assert!(secret.last_used_at.is_none());

        // Find by prefix
        let found = store
            .find_oauth2_provider_app_secret_by_prefix(prefix)
            .await?;
        assert!(found.is_some());
        assert_eq!(found.as_ref().map(|s| s.id), Some(secret.id));

        // Update last_used
        let updated = store
            .update_oauth2_provider_app_secret_last_used(secret.id)
            .await?;
        assert!(updated.is_some());
        assert!(updated.as_ref().and_then(|s| s.last_used_at).is_some());

        // Delete secret
        let deleted = store.delete_oauth2_provider_app_secret(secret.id).await?;
        assert!(deleted);

        // Verify gone
        let gone = store
            .find_oauth2_provider_app_secret_by_prefix(prefix)
            .await?;
        assert!(gone.is_none());
        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_oauth2_code_lifecycle() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;

        let app = store
            .create_oauth2_provider_app(&CreateOAuth2ProviderAppInput {
                name: format!("code-app-{}", uniq()),
                icon: "".to_string(),
                callback_url: "https://example.com/cb".to_string(),
                created_by: Some(user_id),
            })
            .await?;

        let code_prefix = b"codeprefix";
        let code_hash = b"codehashval";
        let expires = OffsetDateTime::now_utc() + time::Duration::hours(1);

        let code = store
            .create_oauth2_provider_app_code(
                app.id,
                user_id,
                code_prefix,
                code_hash,
                expires,
                "urn:example:resource",
                "S256challenge",
                "S256",
                None,
                None,
            )
            .await?;
        assert_eq!(code.app_id, app.id);
        assert_eq!(code.user_id, user_id);

        // Find by prefix
        let found = store
            .find_oauth2_provider_app_code_by_prefix(code_prefix)
            .await?;
        assert!(found.is_some());
        assert_eq!(found.as_ref().map(|c| c.id), Some(code.id));

        // Delete code
        let deleted = store.delete_oauth2_provider_app_code(code.id).await?;
        assert!(deleted);

        let gone = store
            .find_oauth2_provider_app_code_by_prefix(code_prefix)
            .await?;
        assert!(gone.is_none());
        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_oauth2_token_lifecycle() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;

        let app = store
            .create_oauth2_provider_app(&CreateOAuth2ProviderAppInput {
                name: format!("token-app-{}", uniq()),
                icon: "".to_string(),
                callback_url: "https://example.com/cb".to_string(),
                created_by: Some(user_id),
            })
            .await?;

        let secret = store
            .create_oauth2_provider_app_secret(app.id, b"tkprefix", b"tkhashed", "tk****")
            .await?;

        // Insert a minimal api_keys row so the FK is satisfied
        let api_key_id = format!("ak-{}", &uniq());
        sqlx::query(
            "INSERT INTO api_keys (id, hashed_secret, user_id, last_used, expires_at, created_at,
             updated_at, login_type, lifetime_seconds, scopes, token_name)
             VALUES ($1, $2, $3, NOW(), NOW() + INTERVAL '1 hour', NOW(), NOW(),
             'password'::login_type, 3600, ARRAY['all']::text[], '')",
        )
        .bind(&api_key_id)
        .bind(b"fakehashedsecret".to_vec())
        .bind(user_id)
        .execute(&pool)
        .await?;

        let token_prefix = b"tokenprefix";
        let refresh_hash = b"refreshhash1";
        let token = store
            .create_oauth2_provider_app_token(&CreateOAuth2ProviderAppTokenInput {
                expires_at: OffsetDateTime::now_utc() + time::Duration::hours(1),
                hash_prefix: token_prefix.to_vec(),
                refresh_hash: refresh_hash.to_vec(),
                app_secret_id: secret.id,
                api_key_id: api_key_id.clone(),
                audience: "https://example.com".to_string(),
                user_id,
            })
            .await?;

        // Find by prefix
        let by_prefix = store
            .find_oauth2_provider_app_token_by_prefix(token_prefix)
            .await?;
        assert!(by_prefix.is_some());
        assert_eq!(by_prefix.as_ref().map(|t| t.id), Some(token.id));

        // Find by API key id
        let by_api = store
            .find_oauth2_provider_app_token_by_api_key_id(&api_key_id)
            .await?;
        assert!(by_api.is_some());
        assert_eq!(by_api.as_ref().map(|t| t.id), Some(token.id));

        // Find by refresh hash
        let by_refresh = store
            .find_oauth2_provider_app_token_by_refresh_hash(refresh_hash)
            .await?;
        assert!(by_refresh.is_some());
        assert_eq!(by_refresh.as_ref().map(|t| t.id), Some(token.id));

        // Delete token
        let deleted = store.delete_oauth2_provider_app_token(token.id).await?;
        assert!(deleted);
        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_oauth2_delete_app_cascades() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;

        let app = store
            .create_oauth2_provider_app(&CreateOAuth2ProviderAppInput {
                name: format!("cascade-app-{}", uniq()),
                icon: "".to_string(),
                callback_url: "https://example.com/cb".to_string(),
                created_by: Some(user_id),
            })
            .await?;

        // Create a secret
        let secret_prefix = b"cascpfx1";
        let _secret = store
            .create_oauth2_provider_app_secret(app.id, secret_prefix, b"caschashe", "cs****")
            .await?;

        // Create a code
        let code_prefix = b"casccpfx";
        let _code = store
            .create_oauth2_provider_app_code(
                app.id,
                user_id,
                code_prefix,
                b"casccodehs",
                OffsetDateTime::now_utc() + time::Duration::hours(1),
                "",
                "",
                "plain",
                None,
                None,
            )
            .await?;

        // Delete the app -- should cascade
        let deleted = store.delete_oauth2_provider_app(app.id).await?;
        assert!(deleted);

        // Verify secret is gone
        let secret_gone = store
            .find_oauth2_provider_app_secret_by_prefix(secret_prefix)
            .await?;
        assert!(secret_gone.is_none(), "secret should be cascade deleted");

        // Verify code is gone
        let code_gone = store
            .find_oauth2_provider_app_code_by_prefix(code_prefix)
            .await?;
        assert!(code_gone.is_none(), "code should be cascade deleted");

        // Verify app is gone
        let app_gone = store.find_oauth2_provider_app_by_id(app.id).await?;
        assert!(app_gone.is_none(), "app should be deleted");
        Ok(())
    }

    // =========================================================================
    // 2. Group Membership
    // =========================================================================

    #[tokio::test]
    #[ignore]
    async fn test_group_create_insert_list_members() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;

        let group = store
            .create_group(&CreateGroupInput {
                name: format!("grp-{}", uniq()),
                display_name: "Test Group".to_string(),
                organization_id: org_id,
                avatar_url: "".to_string(),
                quota_allowance: 0,
            })
            .await?;

        // Insert member
        store.insert_group_member(group.id, user_id).await?;

        // List members -- should contain our user
        let members = store.list_group_members(group.id).await?;
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].user_id, user_id);
        assert_eq!(members[0].group_id, group.id);
        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_group_delete_member() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;

        let group = store
            .create_group(&CreateGroupInput {
                name: format!("grp-del-{}", uniq()),
                display_name: "Delete Group".to_string(),
                organization_id: org_id,
                avatar_url: "".to_string(),
                quota_allowance: 0,
            })
            .await?;

        store.insert_group_member(group.id, user_id).await?;

        // Delete member
        let removed = store.delete_group_member(group.id, user_id).await?;
        assert!(removed);

        // Verify gone
        let members = store.list_group_members(group.id).await?;
        assert!(members.is_empty());
        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_group_soft_deleted_user_excluded() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;

        let group = store
            .create_group(&CreateGroupInput {
                name: format!("grp-soft-{}", uniq()),
                display_name: "Soft Delete Group".to_string(),
                organization_id: org_id,
                avatar_url: "".to_string(),
                quota_allowance: 0,
            })
            .await?;

        store.insert_group_member(group.id, user_id).await?;

        // Verify member is there
        let members = store.list_group_members(group.id).await?;
        assert_eq!(members.len(), 1);

        // Soft-delete the user
        store.soft_delete_user(user_id).await?;

        // List members again -- deleted user should be excluded
        let members_after = store.list_group_members(group.id).await?;
        assert!(
            members_after.is_empty(),
            "soft-deleted user should be excluded from group members"
        );
        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_group_delete_cleans_up_members() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;

        let group = store
            .create_group(&CreateGroupInput {
                name: format!("grp-cleanup-{}", uniq()),
                display_name: "Cleanup Group".to_string(),
                organization_id: org_id,
                avatar_url: "".to_string(),
                quota_allowance: 0,
            })
            .await?;

        store.insert_group_member(group.id, user_id).await?;

        // Delete the group
        let deleted = store.delete_group(group.id).await?;
        assert!(deleted);

        // The group is gone
        let found = store.find_group_by_id(group.id).await?;
        assert!(found.is_none(), "group should be deleted");

        // Members should be cleaned up (FK cascade).
        // Verify by attempting to delete the member -- should return false.
        let was_member = store.delete_group_member(group.id, user_id).await?;
        assert!(
            !was_member,
            "member should have been cascade-deleted with group"
        );
        Ok(())
    }

    // =========================================================================
    // 3. Workspace Listings with Filters
    // =========================================================================

    fn default_ws_filter() -> WorkspaceListFilter {
        WorkspaceListFilter {
            owner_id: None,
            owner_username: None,
            template_name: None,
            template_ids: vec![],
            name: None,
            status: None,
            has_agent: None,
            dormant: None,
            last_used_before: None,
            last_used_after: None,
            organization_id: None,
            limit: 100,
            offset: 0,
            viewer_id: None,
        }
    }

    #[tokio::test]
    #[ignore]
    async fn test_workspace_list_filters() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let owner1 = create_test_user(&store, org_id, &uniq()).await?;
        let owner2 = create_test_user(&store, org_id, &uniq()).await?;

        let tmpl1 =
            create_test_template(&store, &pool, org_id, owner1, &format!("tmpl-a-{}", uniq()))
                .await?;
        let tmpl2 =
            create_test_template(&store, &pool, org_id, owner1, &format!("tmpl-b-{}", uniq()))
                .await?;

        // Insert workspaces
        let ws1_id = Uuid::new_v4();
        store
            .insert_workspace(CreateWorkspaceInput {
                id: ws1_id,
                owner_id: owner1,
                organization_id: org_id,
                template_id: tmpl1,
                name: format!("ws-alpha-{}", uniq()),
                autostart_schedule: None,
                ttl_ns: None,
                automatic_updates: "never".to_string(),
            })
            .await?;

        let ws2_id = Uuid::new_v4();
        store
            .insert_workspace(CreateWorkspaceInput {
                id: ws2_id,
                owner_id: owner2,
                organization_id: org_id,
                template_id: tmpl2,
                name: format!("ws-beta-{}", uniq()),
                autostart_schedule: None,
                ttl_ns: None,
                automatic_updates: "never".to_string(),
            })
            .await?;

        // Filter by owner
        let (by_owner, count) = store
            .list_workspaces(WorkspaceListFilter {
                owner_id: Some(owner1),
                ..default_ws_filter()
            })
            .await?;
        assert_eq!(count, 1);
        assert_eq!(by_owner.len(), 1);
        assert_eq!(by_owner[0].owner_id, owner1);

        // Filter by template_ids
        let (by_tmpl, count) = store
            .list_workspaces(WorkspaceListFilter {
                template_ids: vec![tmpl2],
                ..default_ws_filter()
            })
            .await?;
        assert_eq!(count, 1);
        assert_eq!(by_tmpl.len(), 1);
        assert_eq!(by_tmpl[0].template_id, tmpl2);

        // Filter by organization_id -- should get both
        let (by_org, count) = store
            .list_workspaces(WorkspaceListFilter {
                organization_id: Some(org_id),
                ..default_ws_filter()
            })
            .await?;
        assert_eq!(count, 2);
        assert_eq!(by_org.len(), 2);
        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_workspace_soft_deleted_excluded() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;
        let tmpl = create_test_template(
            &store,
            &pool,
            org_id,
            user_id,
            &format!("tmpl-del-{}", uniq()),
        )
        .await?;

        let ws_id = Uuid::new_v4();
        store
            .insert_workspace(CreateWorkspaceInput {
                id: ws_id,
                owner_id: user_id,
                organization_id: org_id,
                template_id: tmpl,
                name: format!("ws-del-{}", uniq()),
                autostart_schedule: None,
                ttl_ns: None,
                automatic_updates: "never".to_string(),
            })
            .await?;

        // Verify it shows up
        let found = store.find_workspace_by_id(ws_id, None).await?;
        assert!(found.is_some());

        // Soft-delete
        store.soft_delete_workspace(ws_id).await?;

        // Should not be found
        let gone = store.find_workspace_by_id(ws_id, None).await?;
        assert!(gone.is_none(), "soft-deleted workspace should not be found");
        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_workspace_dormant_filter() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;
        let tmpl = create_test_template(
            &store,
            &pool,
            org_id,
            user_id,
            &format!("tmpl-dorm-{}", uniq()),
        )
        .await?;

        let ws_id = Uuid::new_v4();
        store
            .insert_workspace(CreateWorkspaceInput {
                id: ws_id,
                owner_id: user_id,
                organization_id: org_id,
                template_id: tmpl,
                name: format!("ws-dormant-{}", uniq()),
                autostart_schedule: None,
                ttl_ns: None,
                automatic_updates: "never".to_string(),
            })
            .await?;

        // Mark workspace as dormant via raw SQL
        sqlx::query("UPDATE workspaces SET dormant_at = NOW() WHERE id = $1")
            .bind(ws_id)
            .execute(&pool)
            .await?;

        // Filter dormant=true -- should include it
        let (dormant_list, dormant_count) = store
            .list_workspaces(WorkspaceListFilter {
                owner_id: Some(user_id),
                dormant: Some(true),
                ..default_ws_filter()
            })
            .await?;
        assert_eq!(dormant_count, 1);
        assert_eq!(dormant_list.len(), 1);

        // Filter dormant=false -- should exclude it
        let (active_list, active_count) = store
            .list_workspaces(WorkspaceListFilter {
                owner_id: Some(user_id),
                dormant: Some(false),
                ..default_ws_filter()
            })
            .await?;
        assert_eq!(active_count, 0);
        assert!(active_list.is_empty());
        Ok(())
    }

    // =========================================================================
    // 4. Notification Inbox Filters
    // =========================================================================

    #[tokio::test]
    #[ignore]
    async fn test_notification_inbox_count_and_filter() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;

        // Seed a notification template
        let template_id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO notification_templates (id, name, title_template, body_template, "group", actions, kind)
               VALUES ($1, $2, 'Title', 'Body', NULL, '[]', 'system')
               ON CONFLICT (id) DO NOTHING"#,
        )
        .bind(template_id)
        .bind(format!("test-notif-{}", uniq()))
        .execute(&pool)
        .await?;

        // Insert inbox notifications directly (no store method for insertion)
        let notif1_id = Uuid::new_v4();
        let notif2_id = Uuid::new_v4();
        for (id, read) in [(notif1_id, false), (notif2_id, true)] {
            let read_at: Option<OffsetDateTime> = if read {
                Some(OffsetDateTime::now_utc())
            } else {
                None
            };
            sqlx::query(
                "INSERT INTO inbox_notifications (id, user_id, template_id, targets, title, content, icon, actions, read_at, created_at)
                 VALUES ($1, $2, $3, ARRAY[]::uuid[], 'Test Title', 'Test Content', '', '[]', $4, NOW())",
            )
            .bind(id)
            .bind(user_id)
            .bind(template_id)
            .bind(read_at)
            .execute(&pool)
            .await?;
        }

        // Count unread -- fresh user with exactly 1 unread notification
        let unread_count = store.count_unread_inbox_notifications(user_id).await?;
        assert_eq!(unread_count, 1, "expected exactly 1 unread notification");

        // Filter: unread only
        let unread = store
            .get_filtered_inbox_notifications(user_id, None, None, "unread", None)
            .await?;
        assert_eq!(unread.len(), 1, "expected exactly 1 unread notification");
        assert!(
            unread.iter().all(|n| n.read_at.is_none()),
            "all returned notifications should be unread"
        );

        // Filter: read only
        let read_notifs = store
            .get_filtered_inbox_notifications(user_id, None, None, "read", None)
            .await?;
        assert_eq!(read_notifs.len(), 1, "expected exactly 1 read notification");
        assert!(
            read_notifs.iter().all(|n| n.read_at.is_some()),
            "all returned notifications should be read"
        );

        // Filter: all
        let all = store
            .get_filtered_inbox_notifications(user_id, None, None, "all", None)
            .await?;
        assert_eq!(all.len(), 2, "expected exactly 2 total notifications");
        Ok(())
    }

    // NOTE: test_notification_message_fetch_pending_respects_max_attempts was removed
    // because fetch_pending_notification_messages is no longer part of the public trait.

    // =========================================================================
    // 5. Template Version Archiving
    // =========================================================================

    #[tokio::test]
    #[ignore]
    async fn test_template_version_archive_unused() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;
        let template_name = format!("tmpl-archive-{}", uniq());

        // Create a template with an initial version (the active one)
        let template_id =
            create_test_template(&store, &pool, org_id, user_id, &template_name).await?;

        // Get the active version id from the template
        let tmpl = store
            .find_template_by_id(template_id)
            .await?
            .ok_or("template not found")?;
        let active_version_id = tmpl.active_version_id;

        // Create a second (unused) version
        let job_id2 = create_provisioner_job(&pool, org_id, user_id).await?;
        let v2_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();
        store
            .insert_template_version(CreateTemplateVersionInput {
                id: v2_id,
                template_id: Some(template_id),
                organization_id: org_id,
                created_at: now,
                updated_at: now,
                name: format!("{template_name}-v2"),
                message: "unused version".to_string(),
                readme: "".to_string(),
                job_id: job_id2,
                created_by: user_id,
                source_example_id: None,
            })
            .await?;

        // Create a third (unused) version
        let job_id3 = create_provisioner_job(&pool, org_id, user_id).await?;
        let v3_id = Uuid::new_v4();
        store
            .insert_template_version(CreateTemplateVersionInput {
                id: v3_id,
                template_id: Some(template_id),
                organization_id: org_id,
                created_at: now + time::Duration::seconds(1),
                updated_at: now + time::Duration::seconds(1),
                name: format!("{template_name}-v3"),
                message: "another unused".to_string(),
                readme: "".to_string(),
                job_id: job_id3,
                created_by: user_id,
                source_example_id: None,
            })
            .await?;

        // Archive unused (all=true)
        let archived = store
            .archive_unused_template_versions(template_id, true)
            .await?;

        // The active version should NOT be archived
        assert!(
            !archived.contains(&active_version_id),
            "active version should not be archived"
        );

        // v2 and v3 should be archived
        assert!(archived.contains(&v2_id), "v2 should be archived");
        assert!(archived.contains(&v3_id), "v3 should be archived");

        // Verify via list with include_archived=false
        let versions = store
            .list_template_versions(TemplateVersionListFilter {
                template_id,
                include_archived: false,
                limit: 100,
                offset: 0,
            })
            .await?;

        let version_ids: Vec<_> = versions.iter().map(|v| v.id).collect();
        assert!(
            version_ids.contains(&active_version_id),
            "active version should still be listed"
        );
        assert!(
            !version_ids.contains(&v2_id),
            "v2 should not appear when archived excluded"
        );
        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_template_version_unarchive() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;
        let template_name = format!("tmpl-unarch-{}", uniq());

        let template_id =
            create_test_template(&store, &pool, org_id, user_id, &template_name).await?;

        // Create an unused version
        let job_id = create_provisioner_job(&pool, org_id, user_id).await?;
        let v2_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();
        store
            .insert_template_version(CreateTemplateVersionInput {
                id: v2_id,
                template_id: Some(template_id),
                organization_id: org_id,
                created_at: now,
                updated_at: now,
                name: format!("{template_name}-v2"),
                message: "to archive".to_string(),
                readme: "".to_string(),
                job_id,
                created_by: user_id,
                source_example_id: None,
            })
            .await?;

        // Archive it
        let archived = store.archive_template_version(v2_id).await?;
        assert!(archived);

        // Verify it's archived (not in non-archived list)
        let versions = store
            .list_template_versions(TemplateVersionListFilter {
                template_id,
                include_archived: false,
                limit: 100,
                offset: 0,
            })
            .await?;
        assert!(
            !versions.iter().any(|v| v.id == v2_id),
            "archived version should not appear"
        );

        // Unarchive it
        let unarchived = store.unarchive_template_version(v2_id).await?;
        assert!(unarchived);

        // Verify it's back
        let versions_after = store
            .list_template_versions(TemplateVersionListFilter {
                template_id,
                include_archived: false,
                limit: 100,
                offset: 0,
            })
            .await?;
        assert!(
            versions_after.iter().any(|v| v.id == v2_id),
            "unarchived version should appear again"
        );
        Ok(())
    }

    // =========================================================================
    // 6. Workspace Build Number Sequencing
    // =========================================================================

    #[tokio::test]
    #[ignore]
    async fn test_workspace_build_number_sequencing() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;
        let tmpl_name = format!("tmpl-build-{}", uniq());
        let template_id = create_test_template(&store, &pool, org_id, user_id, &tmpl_name).await?;

        // Get the template version id for build references
        let tmpl = store
            .find_template_by_id(template_id)
            .await?
            .ok_or("template not found")?;
        let tv_id = tmpl.active_version_id;

        // Create a workspace
        let ws_id = Uuid::new_v4();
        store
            .insert_workspace(CreateWorkspaceInput {
                id: ws_id,
                owner_id: user_id,
                organization_id: org_id,
                template_id,
                name: format!("ws-build-{}", uniq()),
                autostart_schedule: None,
                ttl_ns: None,
                automatic_updates: "never".to_string(),
            })
            .await?;

        // next_workspace_build_number on empty workspace should be 1
        let next = store.next_workspace_build_number(ws_id).await?;
        assert_eq!(next, 1, "first build number should be 1");

        // Insert first build -- should get build_number = 1
        let job1 = create_provisioner_job(&pool, org_id, user_id).await?;
        let build1 = store
            .insert_workspace_build(CreateWorkspaceBuildInput {
                id: Uuid::new_v4(),
                workspace_id: ws_id,
                template_version_id: tv_id,
                build_number: 0, // ignored -- computed by inline subquery
                transition: "start".to_string(),
                initiator_id: user_id,
                job_id: job1,
                reason: "initiator".to_string(),
                deadline: None,
                max_deadline: None,
            })
            .await?;
        assert_eq!(build1.build_number, 1, "first build should be number 1");

        // Insert second build -- should get build_number = 2
        let job2 = create_provisioner_job(&pool, org_id, user_id).await?;
        let build2 = store
            .insert_workspace_build(CreateWorkspaceBuildInput {
                id: Uuid::new_v4(),
                workspace_id: ws_id,
                template_version_id: tv_id,
                build_number: 0,
                transition: "stop".to_string(),
                initiator_id: user_id,
                job_id: job2,
                reason: "initiator".to_string(),
                deadline: None,
                max_deadline: None,
            })
            .await?;
        assert_eq!(build2.build_number, 2, "second build should be number 2");

        // Insert third build
        let job3 = create_provisioner_job(&pool, org_id, user_id).await?;
        let build3 = store
            .insert_workspace_build(CreateWorkspaceBuildInput {
                id: Uuid::new_v4(),
                workspace_id: ws_id,
                template_version_id: tv_id,
                build_number: 0,
                transition: "start".to_string(),
                initiator_id: user_id,
                job_id: job3,
                reason: "initiator".to_string(),
                deadline: None,
                max_deadline: None,
            })
            .await?;
        assert_eq!(build3.build_number, 3, "third build should be number 3");

        // next_workspace_build_number should now be 4
        let next_after = store.next_workspace_build_number(ws_id).await?;
        assert_eq!(
            next_after, 4,
            "next build number after 3 builds should be 4"
        );

        // Verify find_workspace_build_by_number works
        let found = store.find_workspace_build_by_number(ws_id, 2).await?;
        assert!(found.is_some());
        assert_eq!(found.as_ref().map(|b| b.id), Some(build2.id));
        Ok(())
    }

    // =========================================================================
    // 7. Insights Queries (merged from main)
    // =========================================================================

    /// Insert a user row into the `users` table (minimal fields for joining).
    async fn seed_user(pool: &PgPool, user_id: Uuid, username: &str) {
        sqlx::query(
            r#"
            INSERT INTO users (id, email, username, hashed_password, created_at, updated_at, status, rbac_roles, login_type, avatar_url, deleted, last_seen_at, quiet_hours_schedule, name, github_com_user_id, hashed_one_time_passcode, one_time_passcode_expires_at, is_system)
            VALUES ($1, $2, $3, '', now(), now(), 'active', '{}', 'password', '', false, now(), '', '', NULL, NULL, NULL, false)
            ON CONFLICT (id) DO NOTHING
            "#,
        )
        .bind(user_id)
        .bind(format!("{username}@test.com"))
        .bind(username)
        .execute(pool)
        .await
        .ok();
    }

    /// Insert a row into template_usage_stats.
    #[allow(clippy::too_many_arguments)]
    async fn seed_usage_stats(
        pool: &PgPool,
        start: OffsetDateTime,
        end: OffsetDateTime,
        template_id: Uuid,
        user_id: Uuid,
        median_latency_ms: Option<f32>,
        usage_mins: i16,
        ssh_mins: i16,
        sftp_mins: i16,
        reconnecting_pty_mins: i16,
        vscode_mins: i16,
        jetbrains_mins: i16,
        app_usage_mins: Option<serde_json::Value>,
    ) {
        sqlx::query(
            r#"
            INSERT INTO template_usage_stats
                (start_time, end_time, template_id, user_id, median_latency_ms,
                 usage_mins, ssh_mins, sftp_mins, reconnecting_pty_mins,
                 vscode_mins, jetbrains_mins, app_usage_mins)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            ON CONFLICT (start_time, template_id, user_id) DO NOTHING
            "#,
        )
        .bind(start)
        .bind(end)
        .bind(template_id)
        .bind(user_id)
        .bind(median_latency_ms)
        .bind(usage_mins)
        .bind(ssh_mins)
        .bind(sftp_mins)
        .bind(reconnecting_pty_mins)
        .bind(vscode_mins)
        .bind(jetbrains_mins)
        .bind(app_usage_mins)
        .execute(pool)
        .await
        .ok();
    }

    /// Clean up test data after each test run.
    async fn cleanup(pool: &PgPool, user_ids: &[Uuid]) {
        for uid in user_ids {
            let _ = sqlx::query("DELETE FROM template_usage_stats WHERE user_id = $1")
                .bind(uid)
                .execute(pool)
                .await;
            let _ = sqlx::query("DELETE FROM users WHERE id = $1")
                .bind(uid)
                .execute(pool)
                .await;
        }
    }

    // ── get_user_latency_insights ────────────────────────────────────

    #[tokio::test]
    #[ignore]
    async fn test_get_user_latency_insights_basic() {
        let store = match setup_store().await {
            Ok(Some(s)) => s,
            Ok(None) => return,
            Err(e) => panic!("setup_store() failed: {e}"), // skip if no DATABASE_URL
        };
        let pool = store.pool();

        let user1 = Uuid::new_v4();
        let user2 = Uuid::new_v4();
        let tmpl = Uuid::new_v4();
        let start = datetime!(2026-01-01 00:00 UTC);
        let end = datetime!(2026-01-01 00:30 UTC);

        seed_user(&pool, user1, "latuser1").await;
        seed_user(&pool, user2, "latuser2").await;

        // user1: latency 10ms, user2: latency 50ms
        seed_usage_stats(
            &pool,
            start,
            end,
            tmpl,
            user1,
            Some(10.0),
            5,
            0,
            0,
            0,
            0,
            0,
            None,
        )
        .await;
        seed_usage_stats(
            &pool,
            start,
            end,
            tmpl,
            user2,
            Some(50.0),
            5,
            0,
            0,
            0,
            0,
            0,
            None,
        )
        .await;

        let query_start = datetime!(2025-12-31 00:00 UTC);
        let query_end = datetime!(2026-01-02 00:00 UTC);

        let resp = store
            .get_user_latency_insights(query_start, query_end, vec![])
            .await;
        assert!(resp.is_ok(), "query should succeed: {:?}", resp.err());

        let resp = resp.unwrap_or_else(|e| panic!("unexpected error: {e:?}"));
        // Should contain at least our 2 test users
        let our_users: Vec<_> = resp
            .report
            .users
            .iter()
            .filter(|u| u.user_id == user1 || u.user_id == user2)
            .collect();
        assert!(
            our_users.len() >= 2,
            "should find both test users, got {}",
            our_users.len()
        );

        // Test with template_ids filter
        let resp_filtered = store
            .get_user_latency_insights(query_start, query_end, vec![tmpl])
            .await;
        assert!(resp_filtered.is_ok());

        // Test with non-matching template_ids
        let resp_empty = store
            .get_user_latency_insights(query_start, query_end, vec![Uuid::new_v4()])
            .await;
        assert!(resp_empty.is_ok());
        let resp_empty = resp_empty.unwrap_or_else(|e| panic!("unexpected error: {e:?}"));
        let empty_users: Vec<_> = resp_empty
            .report
            .users
            .iter()
            .filter(|u| u.user_id == user1 || u.user_id == user2)
            .collect();
        assert_eq!(
            empty_users.len(),
            0,
            "non-matching filter should exclude test users"
        );

        cleanup(&pool, &[user1, user2]).await;
    }

    // ── get_user_activity_insights ───────────────────────────────────

    #[tokio::test]
    #[ignore]
    async fn test_get_user_activity_insights_cap_per_slot() {
        let store = match setup_store().await {
            Ok(Some(s)) => s,
            Ok(None) => return,
            Err(e) => panic!("setup_store() failed: {e}"),
        };
        let pool = store.pool();

        let user1 = Uuid::new_v4();
        let tmpl1 = Uuid::new_v4();
        let tmpl2 = Uuid::new_v4();
        let start = datetime!(2026-02-01 00:00 UTC);
        let end = datetime!(2026-02-01 00:30 UTC);

        seed_user(&pool, user1, "actuser1").await;

        // Two rows for the same (start_time, user_id) but different templates.
        // usage_mins=20 each → capped at 30 per slot → 30 minutes = 1800 seconds.
        seed_usage_stats(
            &pool, start, end, tmpl1, user1, None, 20, 0, 0, 0, 0, 0, None,
        )
        .await;
        seed_usage_stats(
            &pool, start, end, tmpl2, user1, None, 20, 0, 0, 0, 0, 0, None,
        )
        .await;

        let query_start = datetime!(2026-01-31 00:00 UTC);
        let query_end = datetime!(2026-02-02 00:00 UTC);

        let resp = store
            .get_user_activity_insights(query_start, query_end, vec![])
            .await;
        assert!(resp.is_ok(), "query should succeed: {:?}", resp.err());

        let resp = resp.unwrap_or_else(|e| panic!("unexpected error: {e:?}"));
        let user_entry = resp.report.users.iter().find(|u| u.user_id == user1);
        assert!(user_entry.is_some(), "should find test user");

        let entry = user_entry.unwrap_or_else(|| panic!("user not found"));
        // Cap is LEAST(SUM(usage_mins), 30) = LEAST(40, 30) = 30 → 30*60 = 1800 seconds
        assert_eq!(
            entry.seconds, 1800,
            "usage should be capped at 30 minutes (1800s)"
        );

        // Verify template_ids includes both templates
        assert!(
            entry.template_ids.contains(&tmpl1) && entry.template_ids.contains(&tmpl2),
            "should include both template_ids"
        );

        cleanup(&pool, &[user1]).await;
    }

    // ── get_template_insights_by_interval ────────────────────────────

    #[tokio::test]
    #[ignore]
    async fn test_get_template_insights_by_interval_day() {
        let store = match setup_store().await {
            Ok(Some(s)) => s,
            Ok(None) => return,
            Err(e) => panic!("setup_store() failed: {e}"),
        };
        let pool = store.pool();

        let user1 = Uuid::new_v4();
        let tmpl = Uuid::new_v4();

        seed_user(&pool, user1, "intuser1").await;

        // Seed data across 2 days
        let day1_start = datetime!(2026-03-01 00:00 UTC);
        let day1_end = datetime!(2026-03-01 00:30 UTC);
        let day2_start = datetime!(2026-03-02 12:00 UTC);
        let day2_end = datetime!(2026-03-02 12:30 UTC);

        seed_usage_stats(
            &pool, day1_start, day1_end, tmpl, user1, None, 10, 0, 0, 0, 0, 0, None,
        )
        .await;
        seed_usage_stats(
            &pool, day2_start, day2_end, tmpl, user1, None, 5, 0, 0, 0, 0, 0, None,
        )
        .await;

        let query_start = datetime!(2026-03-01 00:00 UTC);
        let query_end = datetime!(2026-03-04 00:00 UTC);

        let reports = store
            .get_template_insights_by_interval(
                query_start,
                query_end,
                InsightsReportInterval::Day,
                vec![],
            )
            .await;
        assert!(reports.is_ok(), "query should succeed: {:?}", reports.err());

        let reports = reports.unwrap_or_else(|e| panic!("unexpected error: {e:?}"));
        // Should have 3 day buckets (Mar 1, Mar 2, Mar 3)
        assert_eq!(reports.len(), 3, "should have 3 day buckets");

        // Verify ordering (ORDER BY ts.from_ ASC)
        for i in 1..reports.len() {
            assert!(
                reports[i].start_time >= reports[i - 1].start_time,
                "reports should be ordered by start_time"
            );
        }

        // Day 1 bucket should have 1 active user
        let day1_report = reports.iter().find(|r| r.start_time == query_start);
        assert!(day1_report.is_some(), "should have day 1 bucket");
        assert!(
            day1_report
                .unwrap_or_else(|| panic!("day1 not found"))
                .active_users
                >= 1,
            "day 1 should have at least 1 active user"
        );

        // Day 3 bucket should have 0 active users (empty bucket)
        let day3_start = datetime!(2026-03-03 00:00 UTC);
        let day3_report = reports.iter().find(|r| r.start_time == day3_start);
        assert!(day3_report.is_some(), "should have day 3 bucket");
        assert_eq!(
            day3_report
                .unwrap_or_else(|| panic!("day3 not found"))
                .active_users,
            0,
            "empty bucket should have 0 active users"
        );

        cleanup(&pool, &[user1]).await;
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_template_insights_by_interval_week() {
        let store = match setup_store().await {
            Ok(Some(s)) => s,
            Ok(None) => return,
            Err(e) => panic!("setup_store() failed: {e}"),
        };
        let pool = store.pool();

        let user1 = Uuid::new_v4();
        let tmpl = Uuid::new_v4();

        seed_user(&pool, user1, "weekuser1").await;

        let start = datetime!(2026-03-01 00:00 UTC);
        let end = datetime!(2026-03-01 00:30 UTC);
        seed_usage_stats(
            &pool, start, end, tmpl, user1, None, 10, 0, 0, 0, 0, 0, None,
        )
        .await;

        let query_start = datetime!(2026-03-01 00:00 UTC);
        let query_end = datetime!(2026-03-15 00:00 UTC);

        let reports = store
            .get_template_insights_by_interval(
                query_start,
                query_end,
                InsightsReportInterval::Week,
                vec![],
            )
            .await;
        assert!(reports.is_ok(), "query should succeed: {:?}", reports.err());

        let reports = reports.unwrap_or_else(|e| panic!("unexpected error: {e:?}"));
        // 14 days / 7 = 2 week buckets
        assert_eq!(reports.len(), 2, "should have 2 week buckets");

        cleanup(&pool, &[user1]).await;
    }

    // ── get_template_insights ────────────────────────────────────────

    #[tokio::test]
    #[ignore]
    async fn test_get_template_insights_empty_data() {
        let store = match setup_store().await {
            Ok(Some(s)) => s,
            Ok(None) => return,
            Err(e) => panic!("setup_store() failed: {e}"),
        };

        // Query a time range with no data — COALESCE wrappers should ensure
        // fetch_one succeeds and returns zero-valued fields.
        let query_start = datetime!(2099-01-01 00:00 UTC);
        let query_end = datetime!(2099-01-02 00:00 UTC);

        let resp = store
            .get_template_insights(query_start, query_end, InsightsReportInterval::Day, vec![])
            .await;
        assert!(
            resp.is_ok(),
            "should succeed even with zero data: {:?}",
            resp.err()
        );

        let resp = resp.unwrap_or_else(|e| panic!("unexpected error: {e:?}"));
        assert!(resp.report.is_some(), "report should be present");

        let report = resp.report.unwrap_or_else(|| panic!("report missing"));
        assert_eq!(report.active_users, 0, "active_users should be 0");
        assert!(
            report.template_ids.is_empty(),
            "template_ids should be empty"
        );
        assert!(
            report.apps_usage.is_empty(),
            "apps_usage should be empty with no data"
        );
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_template_insights_builtin_apps() {
        let store = match setup_store().await {
            Ok(Some(s)) => s,
            Ok(None) => return,
            Err(e) => panic!("setup_store() failed: {e}"),
        };
        let pool = store.pool();

        let user1 = Uuid::new_v4();
        let tmpl = Uuid::new_v4();

        seed_user(&pool, user1, "insightuser1").await;

        let start = datetime!(2026-04-01 00:00 UTC);
        let end = datetime!(2026-04-01 00:30 UTC);
        // Set ssh_mins=5 and vscode_mins=10, others=0
        seed_usage_stats(
            &pool,
            start,
            end,
            tmpl,
            user1,
            Some(15.0),
            15,
            5,
            0,
            0,
            10,
            0,
            None,
        )
        .await;

        let query_start = datetime!(2026-03-31 00:00 UTC);
        let query_end = datetime!(2026-04-02 00:00 UTC);

        let resp = store
            .get_template_insights(query_start, query_end, InsightsReportInterval::Day, vec![])
            .await;
        assert!(resp.is_ok(), "query should succeed: {:?}", resp.err());

        let resp = resp.unwrap_or_else(|e| panic!("unexpected error: {e:?}"));
        assert!(resp.report.is_some());

        let report = resp.report.unwrap_or_else(|| panic!("report missing"));

        // Should include SSH and VSCode built-in apps but NOT SFTP, JetBrains, or Terminal
        let slugs: Vec<&str> = report.apps_usage.iter().map(|a| a.slug.as_str()).collect();
        assert!(slugs.contains(&"ssh"), "should include SSH built-in app");
        assert!(
            slugs.contains(&"vscode"),
            "should include VSCode built-in app"
        );
        assert!(
            !slugs.contains(&"sftp"),
            "should NOT include SFTP (0 usage)"
        );
        assert!(
            !slugs.contains(&"jetbrains"),
            "should NOT include JetBrains (0 usage)"
        );
        assert!(
            !slugs.contains(&"reconnecting-pty"),
            "should NOT include Terminal (0 usage)"
        );

        // Verify interval_reports are present
        assert!(
            !resp.interval_reports.is_empty(),
            "should have interval reports"
        );

        cleanup(&pool, &[user1]).await;
    }

    // =========================================================================
    // Edge-Case & Complex Filter Integration Tests
    // =========================================================================

    // ---- Workspace listing complex filters ----

    #[tokio::test]
    #[ignore]
    async fn test_workspace_list_by_owner_and_status() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user1 = create_test_user(&store, org_id, &uniq()).await?;
        let user2 = create_test_user(&store, org_id, &uniq()).await?;
        let tmpl = create_test_template(
            &store,
            &pool,
            org_id,
            user1,
            &format!("tmpl-own-{}", uniq()),
        )
        .await?;

        // Create workspace for user1
        store
            .insert_workspace(CreateWorkspaceInput {
                id: Uuid::new_v4(),
                owner_id: user1,
                organization_id: org_id,
                template_id: tmpl,
                name: format!("ws-u1-{}", uniq()),
                autostart_schedule: None,
                ttl_ns: None,
                automatic_updates: "never".to_string(),
            })
            .await?;

        // Create workspace for user2
        store
            .insert_workspace(CreateWorkspaceInput {
                id: Uuid::new_v4(),
                owner_id: user2,
                organization_id: org_id,
                template_id: tmpl,
                name: format!("ws-u2-{}", uniq()),
                autostart_schedule: None,
                ttl_ns: None,
                automatic_updates: "never".to_string(),
            })
            .await?;

        // Filter by owner_id = user1
        let (by_owner, count) = store
            .list_workspaces(WorkspaceListFilter {
                owner_id: Some(user1),
                ..default_ws_filter()
            })
            .await?;
        assert_eq!(count, 1, "user1 owns exactly 1 workspace");
        assert_eq!(by_owner.len(), 1);
        assert_eq!(by_owner[0].owner_id, user1);

        // Also filter by dormant (an actually-wired SQL filter path)
        let (with_dormant, _) = store
            .list_workspaces(WorkspaceListFilter {
                owner_id: Some(user1),
                dormant: Some(false),
                ..default_ws_filter()
            })
            .await?;
        // Non-dormant filter should still return user1's workspace
        assert_eq!(
            with_dormant.len(),
            1,
            "non-dormant filter should return 1 workspace for user1"
        );

        cleanup(&pool, &[user1, user2]).await;
        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_workspace_list_with_search() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;
        let tmpl = create_test_template(
            &store,
            &pool,
            org_id,
            user_id,
            &format!("tmpl-srch-{}", uniq()),
        )
        .await?;

        let needle = format!("findme-{}", uniq());
        let noise_name = format!("noise-{}", uniq());

        // Create workspace with searchable name
        store
            .insert_workspace(CreateWorkspaceInput {
                id: Uuid::new_v4(),
                owner_id: user_id,
                organization_id: org_id,
                template_id: tmpl,
                name: needle.clone(),
                autostart_schedule: None,
                ttl_ns: None,
                automatic_updates: "never".to_string(),
            })
            .await?;

        // Create a noise workspace
        store
            .insert_workspace(CreateWorkspaceInput {
                id: Uuid::new_v4(),
                owner_id: user_id,
                organization_id: org_id,
                template_id: tmpl,
                name: noise_name,
                autostart_schedule: None,
                ttl_ns: None,
                automatic_updates: "never".to_string(),
            })
            .await?;

        // Search by name substring
        let (results, count) = store
            .list_workspaces(WorkspaceListFilter {
                owner_id: Some(user_id),
                name: Some(needle.clone()),
                ..default_ws_filter()
            })
            .await?;
        assert_eq!(count, 1, "search should match exactly 1 workspace");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, needle);

        cleanup(&pool, &[user_id]).await;
        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_workspace_list_pagination() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;
        let tmpl = create_test_template(
            &store,
            &pool,
            org_id,
            user_id,
            &format!("tmpl-page-{}", uniq()),
        )
        .await?;

        // Create 5 workspaces with distinct last_used_at for stable ordering
        let mut ws_ids = Vec::new();
        for i in 0..5 {
            let ws_id = Uuid::new_v4();
            store
                .insert_workspace(CreateWorkspaceInput {
                    id: ws_id,
                    owner_id: user_id,
                    organization_id: org_id,
                    template_id: tmpl,
                    name: format!("ws-page-{}-{}", i, uniq()),
                    autostart_schedule: None,
                    ttl_ns: None,
                    automatic_updates: "never".to_string(),
                })
                .await?;
            ws_ids.push(ws_id);
        }

        // Set distinct last_used_at so ORDER BY last_used_at DESC is deterministic
        for (idx, ws_id) in ws_ids.iter().enumerate() {
            sqlx::query(
                "UPDATE workspaces SET last_used_at = NOW() + ($1 || ' seconds')::interval WHERE id = $2",
            )
            .bind(format!("{}", idx * 10))
            .bind(ws_id)
            .execute(&pool)
            .await?;
        }

        // Page 1: limit=2, offset=0
        let (page1, total) = store
            .list_workspaces(WorkspaceListFilter {
                owner_id: Some(user_id),
                limit: 2,
                offset: 0,
                ..default_ws_filter()
            })
            .await?;
        assert_eq!(total, 5, "total count should be 5");
        assert_eq!(page1.len(), 2, "page 1 should have 2 items");

        // Page 2: limit=2, offset=2
        let (page2, total2) = store
            .list_workspaces(WorkspaceListFilter {
                owner_id: Some(user_id),
                limit: 2,
                offset: 2,
                ..default_ws_filter()
            })
            .await?;
        assert_eq!(total2, 5, "total count should still be 5");
        assert_eq!(page2.len(), 2, "page 2 should have 2 items");

        // Pages should not overlap
        let page1_ids: Vec<_> = page1.iter().map(|w| w.id).collect();
        let page2_ids: Vec<_> = page2.iter().map(|w| w.id).collect();
        for id in &page2_ids {
            assert!(
                !page1_ids.contains(id),
                "page 2 should not overlap with page 1"
            );
        }

        // Page 3: limit=2, offset=4
        let (page3, _) = store
            .list_workspaces(WorkspaceListFilter {
                owner_id: Some(user_id),
                limit: 2,
                offset: 4,
                ..default_ws_filter()
            })
            .await?;
        assert_eq!(page3.len(), 1, "page 3 should have 1 remaining item");

        cleanup(&pool, &[user_id]).await;
        Ok(())
    }

    // ---- Template operations ----

    #[tokio::test]
    #[ignore]
    async fn test_template_version_promote_and_archive() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;
        let template_name = format!("tmpl-promote-{}", uniq());

        let template_id =
            create_test_template(&store, &pool, org_id, user_id, &template_name).await?;

        // Get the initial active version (v1)
        let tmpl = store
            .find_template_by_id(template_id)
            .await?
            .ok_or("template not found")?;
        let v1_id = tmpl.active_version_id;

        // Create v2
        let job_id2 = create_provisioner_job(&pool, org_id, user_id).await?;
        let v2_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();
        store
            .insert_template_version(CreateTemplateVersionInput {
                id: v2_id,
                template_id: Some(template_id),
                organization_id: org_id,
                created_at: now + time::Duration::seconds(1),
                updated_at: now + time::Duration::seconds(1),
                name: format!("{template_name}-v2"),
                message: "promoted version".to_string(),
                readme: "".to_string(),
                job_id: job_id2,
                created_by: user_id,
                source_example_id: None,
            })
            .await?;

        // Promote v2 to active via store API
        store
            .update_template_active_version(template_id, v2_id)
            .await?;

        // Archive old v1
        let archived = store.archive_template_version(v1_id).await?;
        assert!(archived, "v1 should be archived");

        // List non-archived versions
        let versions = store
            .list_template_versions(TemplateVersionListFilter {
                template_id,
                include_archived: false,
                limit: 100,
                offset: 0,
            })
            .await?;
        let version_ids: Vec<_> = versions.iter().map(|v| v.id).collect();
        assert!(version_ids.contains(&v2_id), "promoted v2 should be listed");
        assert!(
            !version_ids.contains(&v1_id),
            "archived v1 should not be listed"
        );

        // Verify the template's active_version_id was updated
        let tmpl_after = store
            .find_template_by_id(template_id)
            .await?
            .ok_or("template not found after promote")?;
        assert_eq!(tmpl_after.active_version_id, v2_id);

        cleanup(&pool, &[user_id]).await;
        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_template_with_multiple_versions() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;
        let template_name = format!("tmpl-multi-{}", uniq());

        let template_id =
            create_test_template(&store, &pool, org_id, user_id, &template_name).await?;

        // Template already has v1. Add v2 and v3.
        let now = OffsetDateTime::now_utc();

        let job_id2 = create_provisioner_job(&pool, org_id, user_id).await?;
        store
            .insert_template_version(CreateTemplateVersionInput {
                id: Uuid::new_v4(),
                template_id: Some(template_id),
                organization_id: org_id,
                created_at: now + time::Duration::seconds(1),
                updated_at: now + time::Duration::seconds(1),
                name: format!("{template_name}-v2"),
                message: "version 2".to_string(),
                readme: "".to_string(),
                job_id: job_id2,
                created_by: user_id,
                source_example_id: None,
            })
            .await?;

        let job_id3 = create_provisioner_job(&pool, org_id, user_id).await?;
        store
            .insert_template_version(CreateTemplateVersionInput {
                id: Uuid::new_v4(),
                template_id: Some(template_id),
                organization_id: org_id,
                created_at: now + time::Duration::seconds(2),
                updated_at: now + time::Duration::seconds(2),
                name: format!("{template_name}-v3"),
                message: "version 3".to_string(),
                readme: "".to_string(),
                job_id: job_id3,
                created_by: user_id,
                source_example_id: None,
            })
            .await?;

        // List all versions (including archived, though none are archived)
        let versions = store
            .list_template_versions(TemplateVersionListFilter {
                template_id,
                include_archived: true,
                limit: 100,
                offset: 0,
            })
            .await?;

        assert_eq!(versions.len(), 3, "should have 3 versions");

        // Verify ordering: list_template_versions orders by created_at DESC
        for pair in versions.windows(2) {
            assert!(
                pair[0].created_at >= pair[1].created_at,
                "versions should be ordered by created_at DESC"
            );
        }

        cleanup(&pool, &[user_id]).await;
        Ok(())
    }

    // ---- Provisioner job lifecycle ----

    #[tokio::test]
    #[ignore]
    async fn test_provisioner_job_acquire_returns_oldest_pending() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;

        // Each test run creates a unique org_id via ensure_default_org, so
        // acquire_provisioner_job is scoped to only jobs created in this test.
        let mut job_ids = Vec::new();
        for i in 0..3i32 {
            let job_id = Uuid::new_v4();
            sqlx::query(
                r#"INSERT INTO provisioner_jobs (
                    id, created_at, updated_at, organization_id, initiator_id,
                    provisioner, file_id, "type", input, tags
                 ) VALUES (
                    $1, NOW() - ($2 || ' seconds')::interval, NOW(), $3, $4,
                    'echo'::provisioner_type, NULL,
                    'template_version_import'::provisioner_job_type,
                    '{}'::jsonb, '{}'::jsonb
                 )"#,
            )
            .bind(job_id)
            .bind(format!("{}", (3 - i) * 10)) // oldest first: 30s ago, 20s ago, 10s ago
            .bind(org_id)
            .bind(user_id)
            .execute(&pool)
            .await?;
            job_ids.push(job_id);
        }

        // Acquire -- should return the oldest job (job_ids[0], created 30s ago)
        let acquired = store
            .acquire_provisioner_job(AcquireProvisionerJobInput {
                worker_id: Uuid::new_v4(),
                started_at: OffsetDateTime::now_utc(),
                organization_id: org_id,
                types: vec![ProvisionerType::Echo],
                provisioner_tags: json!({}),
            })
            .await?;

        let acquired = acquired.ok_or("expected a job to be acquired")?;
        assert_eq!(
            acquired.id, job_ids[0],
            "should acquire oldest pending job first (FIFO)"
        );

        // Clean up provisioner jobs created by this test
        for jid in &job_ids {
            let _ = sqlx::query("DELETE FROM provisioner_jobs WHERE id = $1")
                .bind(jid)
                .execute(&pool)
                .await;
        }
        cleanup(&pool, &[user_id]).await;
        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_provisioner_job_reap_stale_jobs() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;

        // NOTE: This test assumes the Rust process clock and Postgres clock are
        // roughly synchronized (same host). The 30-minute margin provides ample
        // buffer against minor clock skew.
        let stale_id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO provisioner_jobs (
                id, created_at, updated_at, organization_id, initiator_id,
                provisioner, file_id, "type", input, tags
             ) VALUES (
                $1, NOW() - INTERVAL '1 hour', NOW() - INTERVAL '1 hour', $2, $3,
                'echo'::provisioner_type, NULL,
                'template_version_import'::provisioner_job_type,
                '{}'::jsonb, '{}'::jsonb
             )"#,
        )
        .bind(stale_id)
        .bind(org_id)
        .bind(user_id)
        .execute(&pool)
        .await?;

        // Create a fresh pending job (just now)
        let fresh_id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO provisioner_jobs (
                id, created_at, updated_at, organization_id, initiator_id,
                provisioner, file_id, "type", input, tags
             ) VALUES (
                $1, NOW(), NOW(), $2, $3,
                'echo'::provisioner_type, NULL,
                'template_version_import'::provisioner_job_type,
                '{}'::jsonb, '{}'::jsonb
             )"#,
        )
        .bind(fresh_id)
        .bind(org_id)
        .bind(user_id)
        .execute(&pool)
        .await?;

        // Reap jobs pending for > 30 minutes
        let reaped = store
            .get_provisioner_jobs_to_be_reaped(GetJobsToBeReapedInput {
                pending_since: OffsetDateTime::now_utc() - time::Duration::minutes(30),
                hung_since: OffsetDateTime::now_utc() - time::Duration::minutes(30),
                max_jobs: 10_000,
            })
            .await?;

        let reaped_ids: Vec<_> = reaped.iter().map(|j| j.id).collect();
        assert!(reaped_ids.contains(&stale_id), "stale job should be reaped");
        assert!(
            !reaped_ids.contains(&fresh_id),
            "fresh job should not be reaped"
        );

        // Clean up provisioner jobs created by this test
        for jid in &[stale_id, fresh_id] {
            let _ = sqlx::query("DELETE FROM provisioner_jobs WHERE id = $1")
                .bind(jid)
                .execute(&pool)
                .await;
        }
        cleanup(&pool, &[user_id]).await;
        Ok(())
    }

    // ---- Notification filtering ----

    #[tokio::test]
    #[ignore]
    async fn test_notification_inbox_read_unread_filter() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;

        // Seed notification template
        let template_id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO notification_templates (id, name, title_template, body_template, "group", actions, kind)
               VALUES ($1, $2, 'Title', 'Body', NULL, '[]', 'system')
               ON CONFLICT (id) DO NOTHING"#,
        )
        .bind(template_id)
        .bind(format!("test-rw-{}", uniq()))
        .execute(&pool)
        .await?;

        // Insert 3 unread notifications
        let mut notif_ids = Vec::new();
        for _ in 0..3 {
            let nid = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO inbox_notifications (id, user_id, template_id, targets, title, content, icon, actions, read_at, created_at)
                 VALUES ($1, $2, $3, ARRAY[]::uuid[], 'Test', 'Content', '', '[]', NULL, NOW())",
            )
            .bind(nid)
            .bind(user_id)
            .bind(template_id)
            .execute(&pool)
            .await?;
            notif_ids.push(nid);
        }

        // All should be unread initially
        let unread = store
            .get_filtered_inbox_notifications(user_id, None, None, "unread", None)
            .await?;
        assert!(
            unread.len() >= 3,
            "should have at least 3 unread notifications"
        );

        // Mark first 2 as read
        for nid in &notif_ids[..2] {
            sqlx::query("UPDATE inbox_notifications SET read_at = NOW() WHERE id = $1")
                .bind(nid)
                .execute(&pool)
                .await?;
        }

        // Filter unread -- the third notification should still be unread
        let unread_after = store
            .get_filtered_inbox_notifications(user_id, None, None, "unread", None)
            .await?;
        assert!(
            unread_after.iter().any(|n| n.id == notif_ids[2]),
            "third notification should still be unread"
        );

        // Filter read -- should include the 2 we marked
        let read_after = store
            .get_filtered_inbox_notifications(user_id, None, None, "read", None)
            .await?;
        assert!(
            read_after.iter().any(|n| n.id == notif_ids[0]),
            "first notification should be read"
        );
        assert!(
            read_after.iter().any(|n| n.id == notif_ids[1]),
            "second notification should be read"
        );

        // Clean up inbox notifications and notification template
        for nid in &notif_ids {
            let _ = sqlx::query("DELETE FROM inbox_notifications WHERE id = $1")
                .bind(nid)
                .execute(&pool)
                .await;
        }
        let _ = sqlx::query("DELETE FROM notification_templates WHERE id = $1")
            .bind(template_id)
            .execute(&pool)
            .await;
        cleanup(&pool, &[user_id]).await;
        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_notification_message_lease_expiry() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;

        // Seed notification template
        let template_id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO notification_templates (id, name, title_template, body_template, "group", actions, kind)
               VALUES ($1, $2, 'Title', 'Body', NULL, '[]', 'system')
               ON CONFLICT (id) DO NOTHING"#,
        )
        .bind(template_id)
        .bind(format!("test-lease-{}", uniq()))
        .execute(&pool)
        .await?;

        // Insert a pending notification message with old created_at so it sorts first
        // (acquire_pending_notification_messages orders by created_at ASC with a LIMIT)
        let msg_id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO notification_messages
               (id, notification_template_id, user_id, method, status, payload, created_at, updated_at)
               VALUES ($1, $2, $3, 'smtp'::notification_method, 'pending'::notification_message_status,
                       '{}'::jsonb, NOW() - INTERVAL '1 year', NOW())"#,
        )
        .bind(msg_id)
        .bind(template_id)
        .bind(user_id)
        .execute(&pool)
        .await?;

        // acquire_pending_notification_messages is global (not user-scoped),
        // so we check our message is among the acquired batch, not that it's the only one.
        let acquired = store.acquire_pending_notification_messages(10, 5).await?;
        assert!(
            acquired.iter().any(|m| m.id == msg_id),
            "our message should be acquired"
        );

        // Now the message is leased. Force-expire the lease via raw SQL.
        sqlx::query(
            "UPDATE notification_messages SET leased_until = NOW() - INTERVAL '1 minute' WHERE id = $1",
        )
        .bind(msg_id)
        .execute(&pool)
        .await?;

        // Re-acquire -- the expired lease should make it available again
        let reacquired = store.acquire_pending_notification_messages(10, 5).await?;
        assert!(
            reacquired.iter().any(|m| m.id == msg_id),
            "message with expired lease should be re-acquired"
        );

        // Clean up notification message and template
        let _ = sqlx::query("DELETE FROM notification_messages WHERE id = $1")
            .bind(msg_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM notification_templates WHERE id = $1")
            .bind(template_id)
            .execute(&pool)
            .await;
        cleanup(&pool, &[user_id]).await;
        Ok(())
    }

    // ---- OAuth2 complex flows ----

    #[tokio::test]
    #[ignore]
    async fn test_oauth2_token_refresh_flow() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;

        // Create app + secret
        let app = store
            .create_oauth2_provider_app(&CreateOAuth2ProviderAppInput {
                name: format!("refresh-app-{}", uniq()),
                icon: "".to_string(),
                callback_url: "https://example.com/cb".to_string(),
                created_by: Some(user_id),
            })
            .await?;

        let secret = store
            .create_oauth2_provider_app_secret(app.id, b"rfshpfx1", b"rfshhash1", "rf****")
            .await?;

        // Insert a minimal api_keys row (FK requirement)
        let api_key_id = format!("ak-{}", &uniq());
        sqlx::query(
            "INSERT INTO api_keys (id, hashed_secret, user_id, last_used, expires_at, created_at,
             updated_at, login_type, lifetime_seconds, scopes, token_name)
             VALUES ($1, $2, $3, NOW(), NOW() + INTERVAL '1 hour', NOW(), NOW(),
             'password'::login_type, 3600, ARRAY['all']::text[], '')",
        )
        .bind(&api_key_id)
        .bind(b"fakehashedsecret".to_vec())
        .bind(user_id)
        .execute(&pool)
        .await?;

        // Create initial token
        let refresh_hash_v1 = b"refreshhashv1xxx";
        let token = store
            .create_oauth2_provider_app_token(&CreateOAuth2ProviderAppTokenInput {
                expires_at: OffsetDateTime::now_utc() + time::Duration::hours(1),
                hash_prefix: b"tokpfx001".to_vec(),
                refresh_hash: refresh_hash_v1.to_vec(),
                app_secret_id: secret.id,
                api_key_id: api_key_id.clone(),
                audience: "https://example.com".to_string(),
                user_id,
            })
            .await?;

        // Simulate refresh: find token by refresh hash
        let found = store
            .find_oauth2_provider_app_token_by_refresh_hash(refresh_hash_v1)
            .await?;
        assert!(found.is_some(), "should find token by refresh hash");
        assert_eq!(found.as_ref().map(|t| t.id), Some(token.id));

        // Delete old token (token rotation)
        let deleted = store.delete_oauth2_provider_app_token(token.id).await?;
        assert!(deleted, "old token should be deleted");

        // Create a new api_keys row for the new token
        let api_key_id2 = format!("ak-{}", &uniq());
        sqlx::query(
            "INSERT INTO api_keys (id, hashed_secret, user_id, last_used, expires_at, created_at,
             updated_at, login_type, lifetime_seconds, scopes, token_name)
             VALUES ($1, $2, $3, NOW(), NOW() + INTERVAL '1 hour', NOW(), NOW(),
             'password'::login_type, 3600, ARRAY['all']::text[], '')",
        )
        .bind(&api_key_id2)
        .bind(b"fakehashedsecret2".to_vec())
        .bind(user_id)
        .execute(&pool)
        .await?;

        // Issue new token with new refresh hash
        let refresh_hash_v2 = b"refreshhashv2xxx";
        let new_token = store
            .create_oauth2_provider_app_token(&CreateOAuth2ProviderAppTokenInput {
                expires_at: OffsetDateTime::now_utc() + time::Duration::hours(1),
                hash_prefix: b"tokpfx002".to_vec(),
                refresh_hash: refresh_hash_v2.to_vec(),
                app_secret_id: secret.id,
                api_key_id: api_key_id2.clone(),
                audience: "https://example.com".to_string(),
                user_id,
            })
            .await?;

        // Old refresh hash should no longer find anything
        let old_gone = store
            .find_oauth2_provider_app_token_by_refresh_hash(refresh_hash_v1)
            .await?;
        assert!(
            old_gone.is_none(),
            "old refresh hash should not find a token"
        );

        // New refresh hash should find the new token
        let new_found = store
            .find_oauth2_provider_app_token_by_refresh_hash(refresh_hash_v2)
            .await?;
        assert!(new_found.is_some(), "new refresh hash should find token");
        assert_eq!(new_found.as_ref().map(|t| t.id), Some(new_token.id));

        // Clean up: delete app (cascades to secrets/tokens), api_keys, then user
        let _ = store.delete_oauth2_provider_app(app.id).await;
        let _ = sqlx::query("DELETE FROM api_keys WHERE id = $1")
            .bind(&api_key_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM api_keys WHERE id = $1")
            .bind(&api_key_id2)
            .execute(&pool)
            .await;
        cleanup(&pool, &[user_id]).await;
        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_oauth2_cascading_delete() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;

        let app = store
            .create_oauth2_provider_app(&CreateOAuth2ProviderAppInput {
                name: format!("casc-full-{}", uniq()),
                icon: "".to_string(),
                callback_url: "https://example.com/cb".to_string(),
                created_by: Some(user_id),
            })
            .await?;

        // Create secret
        let secret_prefix = b"cascfpfx1";
        let secret = store
            .create_oauth2_provider_app_secret(app.id, secret_prefix, b"casfhash1", "cf****")
            .await?;

        // Create code
        let code_prefix = b"cascfcpfx";
        let _code = store
            .create_oauth2_provider_app_code(
                app.id,
                user_id,
                code_prefix,
                b"cascfcodehs",
                OffsetDateTime::now_utc() + time::Duration::hours(1),
                "",
                "",
                "plain",
                None,
                None,
            )
            .await?;

        // Create token (requires api_key FK)
        let api_key_id = format!("ak-{}", &uniq());
        sqlx::query(
            "INSERT INTO api_keys (id, hashed_secret, user_id, last_used, expires_at, created_at,
             updated_at, login_type, lifetime_seconds, scopes, token_name)
             VALUES ($1, $2, $3, NOW(), NOW() + INTERVAL '1 hour', NOW(), NOW(),
             'password'::login_type, 3600, ARRAY['all']::text[], '')",
        )
        .bind(&api_key_id)
        .bind(b"fakehashed".to_vec())
        .bind(user_id)
        .execute(&pool)
        .await?;

        let token_prefix = b"cascftpfx";
        let refresh_hash = b"cascfrefrs";
        let _token = store
            .create_oauth2_provider_app_token(&CreateOAuth2ProviderAppTokenInput {
                expires_at: OffsetDateTime::now_utc() + time::Duration::hours(1),
                hash_prefix: token_prefix.to_vec(),
                refresh_hash: refresh_hash.to_vec(),
                app_secret_id: secret.id,
                api_key_id: api_key_id.clone(),
                audience: "https://example.com".to_string(),
                user_id,
            })
            .await?;

        // Delete the app -- everything should cascade
        let deleted = store.delete_oauth2_provider_app(app.id).await?;
        assert!(deleted, "app should be deleted");

        // Verify secret is gone
        let secret_gone = store
            .find_oauth2_provider_app_secret_by_prefix(secret_prefix)
            .await?;
        assert!(secret_gone.is_none(), "secret should be cascade deleted");

        // Verify code is gone
        let code_gone = store
            .find_oauth2_provider_app_code_by_prefix(code_prefix)
            .await?;
        assert!(code_gone.is_none(), "code should be cascade deleted");

        // Verify token is gone
        let token_gone = store
            .find_oauth2_provider_app_token_by_prefix(token_prefix)
            .await?;
        assert!(token_gone.is_none(), "token should be cascade deleted");

        // Verify app is gone
        let app_gone = store.find_oauth2_provider_app_by_id(app.id).await?;
        assert!(app_gone.is_none(), "app should be deleted");

        // Clean up api_keys and user (app already deleted by the test)
        let _ = sqlx::query("DELETE FROM api_keys WHERE id = $1")
            .bind(&api_key_id)
            .execute(&pool)
            .await;
        cleanup(&pool, &[user_id]).await;
        Ok(())
    }

    // ---- User edge cases ----

    #[tokio::test]
    #[ignore]
    async fn test_user_soft_delete_excluded_from_list() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let u_active = uniq();
        let u_deleted = uniq();
        let active_id = create_test_user(&store, org_id, &u_active).await?;
        let deleted_id = create_test_user(&store, org_id, &u_deleted).await?;

        // Soft-delete one user
        store.soft_delete_user(deleted_id).await?;

        // list_users with NO status filter should still exclude the soft-deleted user
        // (this exercises the deleted=true exclusion, not just status filtering)
        let (users, _) = store
            .list_users(UserListFilter {
                search: String::new(),
                status: None,
                limit: 1000,
                offset: 0,
            })
            .await?;
        let user_ids: Vec<_> = users.iter().map(|u| u.id).collect();
        assert!(
            user_ids.contains(&active_id),
            "active user should appear in list"
        );
        assert!(
            !user_ids.contains(&deleted_id),
            "soft-deleted user should NOT appear even without status filter"
        );

        cleanup(&pool, &[active_id, deleted_id]).await;
        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_user_memberships_multiple_orgs() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org1 = ensure_default_org(&pool).await?;
        let org2 = ensure_default_org(&pool).await?;

        // Create user in both orgs
        let suffix = uniq();
        let input = CreateUserInput {
            email: format!("test-{suffix}@example.com"),
            username: format!("testuser-{suffix}"),
            name: format!("Test User {suffix}"),
            password_hash: Some("hashed".to_string()),
            login_type: LoginType::Password,
            status: UserStatus::Active,
            organization_ids: vec![org1, org2],
        };
        let user = store.create_user(input).await?;

        let memberships = store.list_user_memberships(user.id).await?;
        let org_ids: Vec<_> = memberships.iter().map(|m| m.organization_id).collect();
        assert!(org_ids.contains(&org1), "user should be member of org1");
        assert!(org_ids.contains(&org2), "user should be member of org2");
        assert!(
            memberships.len() >= 2,
            "user should have at least 2 memberships"
        );

        cleanup(&pool, &[user.id]).await;
        Ok(())
    }

    // =========================================================================
    // 8. User CRUD
    // =========================================================================

    #[tokio::test]
    #[ignore]
    async fn test_user_create_find_update_delete() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let suffix = uniq();

        // Create
        let user = store
            .create_user(CreateUserInput {
                email: format!("crud-{suffix}@example.com"),
                username: format!("cruduser-{suffix}"),
                name: format!("CRUD User {suffix}"),
                password_hash: Some("hashed".to_string()),
                login_type: LoginType::Password,
                status: UserStatus::Active,
                organization_ids: vec![org_id],
            })
            .await?;
        assert_eq!(user.status, UserStatus::Active);
        assert!(!user.deleted, "new user should not be deleted");

        // Find by ID
        let by_id = store.find_user_by_id(user.id).await?;
        assert!(by_id.is_some(), "should find user by ID");
        assert_eq!(by_id.as_ref().map(|u| &u.email), Some(&user.email));

        // Find by username
        let by_name = store.find_user_by_username(&user.username).await?;
        assert!(by_name.is_some(), "should find user by username");
        assert_eq!(by_name.as_ref().map(|u| u.id), Some(user.id));

        // Find by email (via password user)
        let by_email = store.find_password_user_by_email(&user.email).await?;
        assert!(by_email.is_some(), "should find user by email");
        assert_eq!(by_email.as_ref().map(|u| u.user.id), Some(user.id));

        // Update profile
        let new_username = format!("updated-{suffix}");
        let updated = store
            .update_user_profile(user.id, &new_username, "Updated Name")
            .await?;
        assert!(
            updated.is_some(),
            "update_user_profile should return updated user"
        );
        assert_eq!(
            updated.as_ref().map(|u| u.username.as_str()),
            Some(new_username.as_str())
        );
        assert_eq!(
            updated.as_ref().map(|u| u.name.as_str()),
            Some("Updated Name")
        );

        // Update status
        let suspended = store
            .update_user_status(user.id, UserStatus::Suspended)
            .await?;
        assert!(
            suspended.is_some(),
            "update_user_status should return updated user"
        );
        assert_eq!(
            suspended.as_ref().map(|u| u.status),
            Some(UserStatus::Suspended)
        );

        // Soft-delete
        let deleted = store.soft_delete_user(user.id).await?;
        assert!(deleted);

        // Verify soft-deleted user is gone from find_user_by_id
        let gone = store.find_user_by_id(user.id).await?;
        assert!(gone.is_none(), "soft-deleted user should not be found");

        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_user_list_with_filters() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;

        let tag = uniq();
        // Create 3 users: 2 active, 1 suspended
        let u1 = store
            .create_user(CreateUserInput {
                email: format!("list-a-{tag}@example.com"),
                username: format!("lista-{tag}"),
                name: format!("List A {tag}"),
                password_hash: Some("h".to_string()),
                login_type: LoginType::Password,
                status: UserStatus::Active,
                organization_ids: vec![org_id],
            })
            .await?;
        let u2 = store
            .create_user(CreateUserInput {
                email: format!("list-b-{tag}@example.com"),
                username: format!("listb-{tag}"),
                name: format!("List B {tag}"),
                password_hash: Some("h".to_string()),
                login_type: LoginType::Password,
                status: UserStatus::Active,
                organization_ids: vec![org_id],
            })
            .await?;
        let u3 = store
            .create_user(CreateUserInput {
                email: format!("list-c-{tag}@example.com"),
                username: format!("listc-{tag}"),
                name: format!("List C {tag}"),
                password_hash: Some("h".to_string()),
                login_type: LoginType::Password,
                status: UserStatus::Suspended,
                organization_ids: vec![org_id],
            })
            .await?;

        // Filter by search
        let (users, total) = store
            .list_users(UserListFilter {
                search: tag.clone(),
                status: None,
                limit: 50,
                offset: 0,
            })
            .await?;
        assert!(total >= 3, "should find at least 3 users with tag");
        assert!(users.len() >= 3);
        // Verify the created users are present in the result set.
        let returned_ids: Vec<_> = users.iter().map(|u| u.id).collect();
        assert!(returned_ids.contains(&u1.id), "u1 should be in results");
        assert!(returned_ids.contains(&u2.id), "u2 should be in results");
        assert!(returned_ids.contains(&u3.id), "u3 should be in results");
        // Verify the search filter actually matched: every returned user
        // must contain the unique tag in username, email, or name.
        assert!(
            users.iter().all(|u| {
                u.username.contains(&tag) || u.email.contains(&tag) || u.name.contains(&tag)
            }),
            "all returned users should match the search tag"
        );

        // Filter by status=suspended
        let (suspended, _) = store
            .list_users(UserListFilter {
                search: tag.clone(),
                status: Some(UserStatus::Suspended),
                limit: 50,
                offset: 0,
            })
            .await?;
        assert!(
            suspended.iter().all(|u| u.status == UserStatus::Suspended),
            "all results should be suspended"
        );
        assert!(
            !suspended.is_empty(),
            "should find at least 1 suspended user"
        );

        // Pagination: limit 1, offset 0
        let (page, _) = store
            .list_users(UserListFilter {
                search: tag.clone(),
                status: None,
                limit: 1,
                offset: 0,
            })
            .await?;
        assert_eq!(page.len(), 1, "limit=1 should return exactly 1 user");

        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_user_appearance_and_preferences() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;

        // Get default appearance
        let appearance = store.user_appearance(user_id).await?;
        // Should return defaults (empty strings)
        assert!(
            appearance.theme_preference.is_empty(),
            "default theme_preference should be empty"
        );

        // Update appearance
        let updated = store
            .update_user_appearance(user_id, "dark", "JetBrains Mono")
            .await?;
        assert!(
            updated.is_some(),
            "update_user_appearance should return result"
        );
        let upd = updated.as_ref().unwrap_or_else(|| panic!("no appearance"));
        assert_eq!(upd.theme_preference, "dark");
        assert_eq!(upd.terminal_font, "JetBrains Mono");

        // Verify round-trip
        let fetched = store.user_appearance(user_id).await?;
        assert_eq!(fetched.theme_preference, "dark");
        assert_eq!(fetched.terminal_font, "JetBrains Mono");

        // Get default preferences
        let prefs = store.user_preferences(user_id).await?;
        assert!(!prefs.task_notification_alert_dismissed);

        // Update preferences
        let updated_prefs = store.update_user_preferences(user_id, true).await?;
        let updated_prefs =
            updated_prefs.unwrap_or_else(|| panic!("update_user_preferences should return result"));
        assert!(
            updated_prefs.task_notification_alert_dismissed,
            "preference should be dismissed after update"
        );

        // Verify round-trip
        let fetched_prefs = store.user_preferences(user_id).await?;
        assert!(fetched_prefs.task_notification_alert_dismissed);

        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_user_roles_update() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;

        // Verify initial roles are empty
        let user = store.find_user_by_id(user_id).await?;
        let user = user.unwrap_or_else(|| panic!("user should exist"));
        assert!(user.roles.is_empty(), "initial roles should be empty");

        // Update roles
        let updated = store
            .update_user_roles(user_id, vec!["owner".to_string()])
            .await?;
        let updated =
            updated.unwrap_or_else(|| panic!("update_user_roles should return updated user"));
        assert_eq!(updated.roles.len(), 1);
        assert_eq!(updated.roles[0].name, "owner");

        // Update roles to multiple
        let updated2 = store
            .update_user_roles(user_id, vec!["owner".to_string(), "auditor".to_string()])
            .await?;
        let updated2 = updated2.unwrap_or_else(|| panic!("second role update should succeed"));
        assert_eq!(updated2.roles.len(), 2);

        // Clear roles
        let cleared = store.update_user_roles(user_id, vec![]).await?;
        let cleared = cleared.unwrap_or_else(|| panic!("clearing roles should succeed"));
        assert!(
            cleared.roles.is_empty(),
            "roles should be empty after clear"
        );

        Ok(())
    }

    // =========================================================================
    // 9. API Keys
    // =========================================================================

    #[tokio::test]
    #[ignore]
    async fn test_api_key_create_find_delete() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;

        let key_id = format!("ak-{}", uniq());
        let now = OffsetDateTime::now_utc();

        // Create
        let key = store
            .create_api_key(coder_core::CreateApiKeyInput {
                id: key_id.clone(),
                hashed_secret: b"secret_hash".to_vec(),
                user_id,
                last_used: now,
                expires_at: now + time::Duration::hours(24),
                created_at: now,
                updated_at: now,
                login_type: LoginType::Password,
                scopes: vec!["all".to_string()],
                token_name: format!("test-token-{}", uniq()),
                lifetime_seconds: 86400,
                allow_list: vec![],
            })
            .await?;
        assert_eq!(key.id, key_id);
        assert_eq!(key.user_id, user_id);

        // Find by ID
        let found = store.find_api_key_by_id(&key_id).await?;
        assert!(found.is_some(), "should find API key by ID");
        assert_eq!(found.as_ref().map(|k| k.user_id), Some(user_id));

        // Delete
        let deleted = store.delete_api_key(&key_id).await?;
        assert!(deleted, "delete_api_key should return true");

        // Verify gone
        let gone = store.find_api_key_by_id(&key_id).await?;
        assert!(gone.is_none(), "deleted key should not be found");

        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_api_key_expiry() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;

        let key_id = format!("ak-{}", uniq());
        let now = OffsetDateTime::now_utc();

        let _key = store
            .create_api_key(coder_core::CreateApiKeyInput {
                id: key_id.clone(),
                hashed_secret: b"secret2".to_vec(),
                user_id,
                last_used: now,
                expires_at: now + time::Duration::hours(24),
                created_at: now,
                updated_at: now,
                login_type: LoginType::Password,
                scopes: vec!["all".to_string()],
                token_name: format!("expire-token-{}", uniq()),
                lifetime_seconds: 86400,
                allow_list: vec![],
            })
            .await?;

        // Expire the key
        let expire_time = OffsetDateTime::now_utc();
        let expired = store.expire_api_key(&key_id, expire_time).await?;
        assert!(expired, "expire_api_key should return true");

        // Verify it's expired (expires_at <= now)
        let found = store.find_api_key_by_id(&key_id).await?;
        let found = found.unwrap_or_else(|| panic!("expired key should still be findable"));
        assert!(
            found.expires_at <= expire_time,
            "key should be expired: expires_at={:?}, expire_time={:?}",
            found.expires_at,
            expire_time
        );

        Ok(())
    }

    // =========================================================================
    // 10. Tasks
    // =========================================================================

    #[tokio::test]
    #[ignore]
    async fn test_task_create_find_update_delete() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;
        let now = OffsetDateTime::now_utc();

        // We need a template version for the FK. Create one via helper.
        let tmpl_name = format!("tmpl-task-{}", uniq());
        let _template_id = create_test_template(&store, &pool, org_id, user_id, &tmpl_name).await?;

        // Use the template version created by the helper. We need to look it up.
        let tmpl = store
            .find_template_by_org_and_name(org_id, &tmpl_name)
            .await?
            .ok_or("template not found")?;
        let tv_id = tmpl.active_version_id;

        let task_id = Uuid::new_v4();
        let task_name = format!("task-{}", uniq());

        // Create
        let task = store
            .insert_task(coder_core::InsertTaskInput {
                id: task_id,
                organization_id: org_id,
                owner_id: user_id,
                name: task_name.clone(),
                display_name: "Test Task".to_string(),
                template_version_id: tv_id,
                template_parameters: serde_json::json!({}),
                prompt: "do something".to_string(),
                created_at: now,
            })
            .await?;
        assert_eq!(task.id, task_id);
        assert_eq!(task.name, task_name);
        assert!(task.deleted_at.is_none());

        // Find by ID
        let found = store.find_task_by_id(task_id).await?;
        assert!(found.is_some(), "should find task by ID");
        assert_eq!(found.as_ref().map(|t| &t.name), Some(&task_name));

        // Update prompt
        let updated = store.update_task_prompt(task_id, "updated prompt").await?;
        assert!(
            updated.is_some(),
            "update_task_prompt should return updated task"
        );
        assert_eq!(
            updated.as_ref().map(|t| t.prompt.as_str()),
            Some("updated prompt")
        );

        // Soft-delete
        let delete_time = OffsetDateTime::now_utc();
        let deleted = store.delete_task(task_id, delete_time).await?;
        assert!(deleted, "delete_task should return true");

        // find_task_by_id uses `WHERE deleted_at IS NULL`, so a soft-deleted
        // task should no longer be found — matching the user soft-delete pattern.
        let after_delete = store.find_task_by_id(task_id).await?;
        assert!(
            after_delete.is_none(),
            "soft-deleted task should not be found via find_task_by_id"
        );

        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_task_list_with_filters() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;
        let now = OffsetDateTime::now_utc();

        let tmpl_name = format!("tmpl-tasklist-{}", uniq());
        let _template_id = create_test_template(&store, &pool, org_id, user_id, &tmpl_name).await?;
        let tmpl = store
            .find_template_by_org_and_name(org_id, &tmpl_name)
            .await?
            .ok_or("template not found")?;
        let tv_id = tmpl.active_version_id;

        // Create 2 tasks for this user/org
        for i in 0..2 {
            store
                .insert_task(coder_core::InsertTaskInput {
                    id: Uuid::new_v4(),
                    organization_id: org_id,
                    owner_id: user_id,
                    name: format!("listask-{}-{}", i, uniq()),
                    display_name: format!("Task {i}"),
                    template_version_id: tv_id,
                    template_parameters: serde_json::json!({}),
                    prompt: format!("prompt {i}"),
                    created_at: now + time::Duration::seconds(i as i64),
                })
                .await?;
        }

        // List by owner_id
        let tasks = store
            .list_tasks(coder_core::TaskListFilter {
                owner_id: Some(user_id),
                organization_id: None,
                status: None,
            })
            .await?;
        assert!(tasks.len() >= 2, "should find at least 2 tasks for user");
        assert!(
            tasks.iter().all(|t| t.owner_id == user_id),
            "all tasks should belong to user"
        );

        // List by organization_id
        let by_org = store
            .list_tasks(coder_core::TaskListFilter {
                owner_id: None,
                organization_id: Some(org_id),
                status: None,
            })
            .await?;
        assert!(
            by_org.len() >= 2,
            "should find at least 2 tasks for organization"
        );
        assert!(
            by_org.iter().all(|t| t.organization_id == org_id),
            "all tasks should belong to the queried organization"
        );

        Ok(())
    }

    // =========================================================================
    // 11. Chats
    // =========================================================================

    #[tokio::test]
    #[ignore]
    async fn test_chat_create_list_archive_unarchive() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;

        // last_model_config_id has no FK constraint in the schema, so a random UUID is fine.
        let model_config_id = Uuid::new_v4();

        // Create chat
        let chat = store
            .insert_chat(coder_core::InsertChatInput {
                owner_id: user_id,
                workspace_id: None,
                parent_chat_id: None,
                root_chat_id: None,
                last_model_config_id: model_config_id,
                title: "Test Chat".to_string(),
            })
            .await?;
        assert_eq!(chat.owner_id, user_id);
        assert!(!chat.archived);

        // List chats (non-archived)
        let chats = store.list_chats_by_owner(user_id, Some(false)).await?;
        assert!(
            chats.iter().any(|c| c.id == chat.id),
            "newly created chat should appear"
        );

        // Archive
        store.archive_chat(chat.id).await?;

        // Verify archived
        let after_archive = store.find_chat_by_id(chat.id).await?;
        let after_archive =
            after_archive.unwrap_or_else(|| panic!("chat should exist after archive"));
        assert!(after_archive.archived, "chat should be archived");

        // Should not appear in non-archived list
        let non_archived = store.list_chats_by_owner(user_id, Some(false)).await?;
        assert!(
            !non_archived.iter().any(|c| c.id == chat.id),
            "archived chat should not appear in non-archived list"
        );

        // Unarchive
        store.unarchive_chat(chat.id).await?;

        // Verify unarchived
        let after_unarchive = store.find_chat_by_id(chat.id).await?;
        let after_unarchive =
            after_unarchive.unwrap_or_else(|| panic!("chat should exist after unarchive"));
        assert!(!after_unarchive.archived, "chat should be unarchived");

        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_chat_messages_append_and_list() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;

        // last_model_config_id has no FK constraint in the schema, so a random UUID is fine.
        let model_config_id = Uuid::new_v4();

        let chat = store
            .insert_chat(coder_core::InsertChatInput {
                owner_id: user_id,
                workspace_id: None,
                parent_chat_id: None,
                root_chat_id: None,
                last_model_config_id: model_config_id,
                title: "Messages Chat".to_string(),
            })
            .await?;

        // Insert messages
        let msg1 = store
            .insert_chat_message(coder_core::InsertChatMessageInput {
                chat_id: chat.id,
                model_config_id: Some(model_config_id),
                role: "user".to_string(),
                content: Some(serde_json::json!("Hello")),
                visibility: coder_core::api::ChatMessageVisibility::User,
            })
            .await?;

        let msg2 = store
            .insert_chat_message(coder_core::InsertChatMessageInput {
                chat_id: chat.id,
                model_config_id: Some(model_config_id),
                role: "assistant".to_string(),
                content: Some(serde_json::json!("Hi there")),
                visibility: coder_core::api::ChatMessageVisibility::Both,
            })
            .await?;

        // List messages (after_id = 0 means all)
        let messages = store.list_chat_messages(chat.id, 0).await?;
        assert!(messages.len() >= 2, "should have at least 2 messages");

        // Verify ordering (IDs are auto-incrementing)
        assert!(msg1.id < msg2.id, "message IDs should be sequential");

        // Verify content
        let first = messages
            .iter()
            .find(|m| m.id == msg1.id)
            .unwrap_or_else(|| panic!("msg1 not found"));
        assert_eq!(first.role, "user");

        let second = messages
            .iter()
            .find(|m| m.id == msg2.id)
            .unwrap_or_else(|| panic!("msg2 not found"));
        assert_eq!(second.role, "assistant");

        // List after first message
        let after_first = store.list_chat_messages(chat.id, msg1.id).await?;
        assert!(
            after_first.iter().all(|m| m.id > msg1.id),
            "all messages should be after msg1"
        );
        assert!(
            after_first.iter().any(|m| m.id == msg2.id),
            "msg2 should appear after msg1"
        );

        Ok(())
    }

    // =========================================================================
    // 11b. Chat Providers
    // =========================================================================

    #[tokio::test]
    #[ignore]
    async fn test_chat_provider_crud() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };

        // Insert a provider (provider must be from the DB CHECK allowlist)
        let provider = store
            .insert_chat_provider(coder_core::InsertChatProviderInput {
                provider: "openai".to_string(),
                display_name: format!("OpenAI Test {}", uniq()),
                api_key: "test-fake-api-key-1234".to_string(),
                base_url: "https://api.openai.com/v1".to_string(),
                enabled: true,
                created_by: None,
            })
            .await?;
        assert!(provider.display_name.starts_with("OpenAI Test"));
        assert!(provider.enabled);

        // List providers — should contain the one we just created
        let providers = store.list_chat_providers().await?;
        assert!(
            providers.iter().any(|p| p.id == provider.id),
            "newly created provider should appear in list"
        );

        // Update the provider
        let updated = store
            .update_chat_provider(coder_core::UpdateChatProviderInput {
                id: provider.id,
                display_name: "OpenAI Updated".to_string(),
                api_key: "test-fake-updated-key".to_string(),
                base_url: "https://api.openai.com/v2".to_string(),
                enabled: false,
            })
            .await?;
        assert_eq!(updated.id, provider.id);
        assert_eq!(updated.display_name, "OpenAI Updated");
        assert_eq!(updated.base_url, "https://api.openai.com/v2");
        assert!(!updated.enabled);

        // Delete the provider
        store.delete_chat_provider(provider.id).await?;

        // Verify it's gone
        let after_delete = store.list_chat_providers().await?;
        assert!(
            !after_delete.iter().any(|p| p.id == provider.id),
            "deleted provider should not appear in list"
        );

        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_chat_provider_update_not_found() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };

        // Updating a non-existent provider should return an error
        let result = store
            .update_chat_provider(coder_core::UpdateChatProviderInput {
                id: Uuid::new_v4(),
                display_name: "Ghost".to_string(),
                api_key: "test-fake-key".to_string(),
                base_url: "https://example.com".to_string(),
                enabled: true,
            })
            .await;
        assert!(result.is_err(), "updating a missing provider should fail");

        Ok(())
    }

    // =========================================================================
    // 11c. Chat Model Configs
    // =========================================================================

    #[tokio::test]
    #[ignore]
    async fn test_chat_model_config_crud() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };

        // Insert a model config (compression_threshold must be 0..=100 per DB CHECK)
        let config = store
            .insert_chat_model_config(coder_core::InsertChatModelConfigInput {
                provider: "openai".to_string(),
                model: format!("gpt-4-{}", uniq()),
                display_name: "GPT-4 Test".to_string(),
                enabled: true,
                is_default: false,
                context_limit: 128000,
                compression_threshold: 80,
                options: json!({"temperature": 0.7}),
                created_by: None,
            })
            .await?;
        assert!(config.model.starts_with("gpt-4-"));
        assert_eq!(config.display_name, "GPT-4 Test");
        assert!(config.enabled);
        assert!(!config.is_default);
        assert_eq!(config.context_limit, 128000);

        // List configs (all)
        let configs = store.list_chat_model_configs(false).await?;
        assert!(
            configs.iter().any(|c| c.id == config.id),
            "newly created config should appear in list"
        );

        // List configs (enabled only)
        let enabled = store.list_chat_model_configs(true).await?;
        assert!(
            enabled.iter().any(|c| c.id == config.id),
            "enabled config should appear in enabled-only list"
        );

        // Update the config
        let updated = store
            .update_chat_model_config(coder_core::UpdateChatModelConfigInput {
                id: config.id,
                provider: config.provider.clone(),
                model: "gpt-4-turbo".to_string(),
                display_name: "GPT-4 Turbo".to_string(),
                enabled: false,
                is_default: false,
                context_limit: 256000,
                compression_threshold: 50,
                options: json!({"temperature": 0.5}),
                updated_by: None,
            })
            .await?;
        assert_eq!(updated.id, config.id);
        assert_eq!(updated.model, "gpt-4-turbo");
        assert_eq!(updated.display_name, "GPT-4 Turbo");
        assert!(!updated.enabled);
        assert_eq!(updated.context_limit, 256000);

        // Disabled config should NOT appear in enabled-only list
        let enabled_after = store.list_chat_model_configs(true).await?;
        assert!(
            !enabled_after.iter().any(|c| c.id == config.id),
            "disabled config should not appear in enabled-only list"
        );

        // Soft-delete the config
        store.delete_chat_model_config(config.id).await?;

        // Verify it's gone from all lists (soft-deleted)
        let after_delete = store.list_chat_model_configs(false).await?;
        assert!(
            !after_delete.iter().any(|c| c.id == config.id),
            "soft-deleted config should not appear in list"
        );

        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_chat_model_config_ensure_default() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();

        // Soft-delete ALL existing configs and clear defaults so this test
        // is fully isolated — ensure_default picks the earliest enabled row
        // from the entire table.
        sqlx::query("UPDATE chat_model_configs SET deleted_at = NOW() WHERE deleted_at IS NULL")
            .execute(&pool)
            .await?;
        store.unset_default_chat_model_configs().await?;

        let model_a = format!("model-a-{}", uniq());
        let model_b = format!("model-b-{}", uniq());

        // Insert two enabled configs, neither is default
        let c1 = store
            .insert_chat_model_config(coder_core::InsertChatModelConfigInput {
                provider: "openai".to_string(),
                model: model_a,
                display_name: "Model A".to_string(),
                enabled: true,
                is_default: false,
                context_limit: 4096,
                compression_threshold: 50,
                options: json!({}),
                created_by: None,
            })
            .await?;

        let _c2 = store
            .insert_chat_model_config(coder_core::InsertChatModelConfigInput {
                provider: "openai".to_string(),
                model: model_b,
                display_name: "Model B".to_string(),
                enabled: true,
                is_default: false,
                context_limit: 8192,
                compression_threshold: 60,
                options: json!({}),
                created_by: None,
            })
            .await?;

        // Neither is default yet
        let before = store.list_chat_model_configs(false).await?;
        assert!(
            !before.iter().any(|c| c.is_default),
            "no config should be default after unset"
        );

        // ensure_default should promote the earliest created enabled config
        store.ensure_default_chat_model_config().await?;

        let after = store.list_chat_model_configs(false).await?;

        // c1 (the earliest created enabled config) should now be default
        let c1_after = after
            .iter()
            .find(|c| c.id == c1.id)
            .unwrap_or_else(|| panic!("c1 should still exist after ensure_default"));
        assert!(
            c1_after.is_default,
            "c1 (the earliest created enabled config) should be promoted to default"
        );

        // No other config should be default
        assert!(
            !after.iter().any(|c| c.id != c1.id && c.is_default),
            "only the earliest created enabled config should be default"
        );

        // Cleanup: unset defaults so we don't pollute other tests
        store.unset_default_chat_model_configs().await?;

        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_chat_model_config_update_not_found() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };

        // Updating a non-existent model config should return an error
        let result = store
            .update_chat_model_config(coder_core::UpdateChatModelConfigInput {
                id: Uuid::new_v4(),
                provider: "openai".to_string(),
                model: "ghost-model".to_string(),
                display_name: "Ghost".to_string(),
                enabled: true,
                is_default: false,
                context_limit: 1000,
                compression_threshold: 50,
                options: json!({}),
                updated_by: None,
            })
            .await;
        assert!(
            result.is_err(),
            "updating a missing model config should fail"
        );

        Ok(())
    }

    // =========================================================================
    // 12. Provisioner Jobs
    // =========================================================================

    #[tokio::test]
    #[ignore]
    async fn test_provisioner_job_create_acquire_complete() -> TestResult {
        use coder_core::{
            AcquireProvisionerJobInput, CompleteProvisionerJobInput, InsertProvisionerJobInput,
            ProvisionerJobStatus, ProvisionerJobType, ProvisionerStorageMethod, ProvisionerType,
        };

        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;

        let job_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();

        // Create a file row for the FK (provisioner_jobs.file_id can be NULL
        // in the raw SQL helper, but the typed input requires it).
        let file_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO files (id, hash, created_by, created_at, mimetype, data)
             VALUES ($1, $2, $3, NOW(), 'application/tar', $4)
             ON CONFLICT DO NOTHING",
        )
        .bind(file_id)
        .bind(format!("fakehash-{}", uniq()))
        .bind(user_id)
        .bind(b"fakedata".to_vec())
        .execute(&pool)
        .await?;

        // Insert job
        let job = store
            .insert_provisioner_job(InsertProvisionerJobInput {
                id: job_id,
                created_at: now,
                organization_id: org_id,
                initiator_id: user_id,
                provisioner: ProvisionerType::Echo,
                storage_method: ProvisionerStorageMethod::File,
                file_id,
                job_type: ProvisionerJobType::TemplateVersionImport,
                input: serde_json::json!({}),
                tags: serde_json::json!({}),
                trace_metadata: serde_json::json!({}),
            })
            .await?;
        assert_eq!(job.id, job_id);
        assert_eq!(job.job_status, ProvisionerJobStatus::Pending);

        // Get by ID
        let found = store.get_provisioner_job_by_id(job_id).await?;
        assert!(found.is_some(), "should find provisioner job by ID");
        assert_eq!(
            found.as_ref().map(|j| j.job_status),
            Some(ProvisionerJobStatus::Pending)
        );

        // Acquire
        let worker_id = Uuid::new_v4();
        let acquired = store
            .acquire_provisioner_job(AcquireProvisionerJobInput {
                worker_id,
                started_at: OffsetDateTime::now_utc(),
                organization_id: org_id,
                types: vec![ProvisionerType::Echo],
                provisioner_tags: serde_json::json!({}),
            })
            .await?;
        // Within our unique org, the only pending Echo job is the one we just
        // created, so acquire must return that specific job.
        let acquired = acquired.unwrap_or_else(|| panic!("should acquire the pending job"));
        assert_eq!(
            acquired.id, job_id,
            "acquired job should be the one we created"
        );

        // Complete the job
        let complete_time = OffsetDateTime::now_utc();
        store
            .update_provisioner_job_with_complete_by_id(CompleteProvisionerJobInput {
                id: job_id,
                updated_at: complete_time,
                completed_at: complete_time,
                error: String::new(),
                error_code: String::new(),
            })
            .await?;

        // Verify completed
        let completed = store.get_provisioner_job_by_id(job_id).await?;
        let completed = completed.unwrap_or_else(|| panic!("completed job should still be found"));
        assert_eq!(completed.job_status, ProvisionerJobStatus::Succeeded);
        assert!(completed.completed_at.is_some());

        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_provisioner_job_logs_insert_and_list() -> TestResult {
        use coder_core::provisioner::{LogLevel, LogSource};
        use coder_core::{
            InsertProvisionerJobInput, InsertProvisionerJobLogsInput, ProvisionerJobType,
            ProvisionerStorageMethod, ProvisionerType,
        };

        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;
        let now = OffsetDateTime::now_utc();

        // Create file for FK
        let file_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO files (id, hash, created_by, created_at, mimetype, data)
             VALUES ($1, $2, $3, NOW(), 'application/tar', $4)
             ON CONFLICT DO NOTHING",
        )
        .bind(file_id)
        .bind(format!("loghash-{}", uniq()))
        .bind(user_id)
        .bind(b"logdata".to_vec())
        .execute(&pool)
        .await?;

        let job_id = Uuid::new_v4();
        store
            .insert_provisioner_job(InsertProvisionerJobInput {
                id: job_id,
                created_at: now,
                organization_id: org_id,
                initiator_id: user_id,
                provisioner: ProvisionerType::Echo,
                storage_method: ProvisionerStorageMethod::File,
                file_id,
                job_type: ProvisionerJobType::TemplateVersionImport,
                input: serde_json::json!({}),
                tags: serde_json::json!({}),
                trace_metadata: serde_json::json!({}),
            })
            .await?;

        // Insert logs
        let logs = store
            .insert_provisioner_job_logs(InsertProvisionerJobLogsInput {
                job_id,
                created_at: vec![now, now + time::Duration::seconds(1)],
                source: vec![LogSource::Provisioner, LogSource::ProvisionerDaemon],
                level: vec![LogLevel::Info, LogLevel::Warn],
                stage: vec!["init".to_string(), "plan".to_string()],
                output: vec!["starting up".to_string(), "warning occurred".to_string()],
            })
            .await?;
        assert_eq!(logs.len(), 2, "should insert 2 log entries");

        // List logs (after_id = 0 means all)
        let listed = store.get_provisioner_logs_after_id(job_id, 0).await?;
        assert!(listed.len() >= 2, "should list at least 2 logs");
        assert!(
            listed.iter().all(|l| l.job_id == job_id),
            "all logs should belong to our job"
        );

        // List after first log
        let first_id = listed[0].id;
        let after_first = store
            .get_provisioner_logs_after_id(job_id, first_id)
            .await?;
        assert!(
            after_first.iter().all(|l| l.id > first_id),
            "all logs should be after first"
        );

        Ok(())
    }

    // =========================================================================
    // 13. Audit
    // =========================================================================

    #[tokio::test]
    #[ignore]
    async fn test_audit_log_insert_and_list() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;

        let audit_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();
        let target = format!("audit-target-{}", uniq());

        // Insert audit log
        store
            .insert_audit_log(coder_core::PersistAuditLogInput {
                id: audit_id,
                request_id: Some(Uuid::new_v4()),
                time: now,
                ip: "127.0.0.1".to_string(),
                user_agent: "test-agent".to_string(),
                resource_type: "user".to_string(),
                resource_id: Some(user_id),
                resource_target: target.clone(),
                resource_icon: "".to_string(),
                action: "create".to_string(),
                diff: serde_json::json!({}),
                status_code: 200,
                additional_fields: serde_json::json!({}),
                description: format!("test audit {target}"),
                resource_link: "".to_string(),
                is_deleted: false,
                organization_id: Some(org_id),
                user_id: Some(user_id),
            })
            .await?;

        // List audit logs with search
        let response = store
            .list_audit_logs(coder_core::AuditLogListFilter {
                search: target.clone(),
                limit: 10,
                offset: 0,
            })
            .await?;
        assert!(response.count >= 1, "should find at least 1 audit log");
        assert!(
            response
                .audit_logs
                .iter()
                .any(|l| l.resource_target == target),
            "should find our specific audit entry"
        );
        // Verify the search filter actually works: every returned log must
        // match the search term in resource_target or description.
        assert!(
            response.audit_logs.iter().all(|l| {
                l.resource_target.contains(&target) || l.description.contains(&target)
            }),
            "all returned audit logs should match the search term"
        );

        Ok(())
    }

    // =========================================================================
    // 14. External Auth
    // =========================================================================

    #[tokio::test]
    #[ignore]
    async fn test_external_auth_link_upsert_and_find() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;

        let provider_id = format!("github-{}", uniq());
        let now = OffsetDateTime::now_utc();

        // Upsert
        let link = store
            .upsert_external_auth_link(
                user_id,
                &coder_core::UpsertExternalAuthLinkInput {
                    provider_id: provider_id.clone(),
                    access_token: "access-token-123".to_string(),
                    refresh_token: "refresh-token-456".to_string(),
                    token_type: "Bearer".to_string(),
                    scopes: vec!["repo".to_string(), "user".to_string()],
                    expires_at: now + time::Duration::hours(1),
                    authenticated: true,
                    validate_error: String::new(),
                    refresh_error: String::new(),
                    last_validated_at: Some(now),
                    last_refreshed_at: None,
                    user: None,
                    installations: vec![],
                    app_installable: false,
                },
            )
            .await?;
        assert_eq!(link.provider_id, provider_id);
        assert!(link.authenticated, "link should be authenticated");
        assert_eq!(link.access_token, "access-token-123");

        // Find
        let found = store.find_external_auth_link(user_id, &provider_id).await?;
        let found = found.unwrap_or_else(|| panic!("should find external auth link"));
        assert_eq!(found.provider_id, provider_id);
        assert_eq!(found.access_token, "access-token-123");

        // Update via upsert
        let updated = store
            .upsert_external_auth_link(
                user_id,
                &coder_core::UpsertExternalAuthLinkInput {
                    provider_id: provider_id.clone(),
                    access_token: "new-access-token".to_string(),
                    refresh_token: "new-refresh-token".to_string(),
                    token_type: "Bearer".to_string(),
                    scopes: vec!["repo".to_string()],
                    expires_at: now + time::Duration::hours(2),
                    authenticated: true,
                    validate_error: String::new(),
                    refresh_error: String::new(),
                    last_validated_at: Some(now),
                    last_refreshed_at: Some(now),
                    user: None,
                    installations: vec![],
                    app_installable: false,
                },
            )
            .await?;
        assert_eq!(updated.access_token, "new-access-token");

        // List all links for user
        let links = store.list_external_auth_links(user_id).await?;
        assert!(
            links.iter().any(|l| l.provider_id == provider_id),
            "should find our provider in the list"
        );

        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_external_auth_link_delete() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;

        let provider_id = format!("gitlab-{}", uniq());
        let now = OffsetDateTime::now_utc();

        // Create
        store
            .upsert_external_auth_link(
                user_id,
                &coder_core::UpsertExternalAuthLinkInput {
                    provider_id: provider_id.clone(),
                    access_token: "token".to_string(),
                    refresh_token: "refresh".to_string(),
                    token_type: "Bearer".to_string(),
                    scopes: vec![],
                    expires_at: now + time::Duration::hours(1),
                    authenticated: true,
                    validate_error: String::new(),
                    refresh_error: String::new(),
                    last_validated_at: None,
                    last_refreshed_at: None,
                    user: None,
                    installations: vec![],
                    app_installable: false,
                },
            )
            .await?;

        // Delete
        let deleted = store
            .delete_external_auth_link(user_id, &provider_id)
            .await?;
        assert!(deleted, "delete should return true");

        // Verify gone
        let gone = store.find_external_auth_link(user_id, &provider_id).await?;
        assert!(gone.is_none(), "deleted link should not be found");

        // Delete again should return false
        let deleted_again = store
            .delete_external_auth_link(user_id, &provider_id)
            .await?;
        assert!(!deleted_again, "second delete should return false");

        Ok(())
    }

    // =========================================================================
    // 15. Custom Roles
    // =========================================================================

    #[tokio::test]
    #[ignore]
    async fn test_custom_role_upsert_list_delete() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;

        let role_name = format!("custom-role-{}", uniq());

        // Upsert (create)
        let role = store
            .upsert_custom_role(&coder_core::UpsertCustomRoleInput {
                name: role_name.clone(),
                display_name: "Test Custom Role".to_string(),
                organization_id: Some(org_id),
                site_permissions: "[]".to_string(),
                org_permissions: r#"[{"resource_type": "workspace", "action": "read"}]"#
                    .to_string(),
                user_permissions: "[]".to_string(),
            })
            .await?;
        assert_eq!(role.name, role_name);
        assert_eq!(role.display_name, "Test Custom Role");
        assert_eq!(role.organization_id, Some(org_id));

        // List by organization
        let roles = store.list_custom_roles(Some(org_id)).await?;
        assert!(
            roles.iter().any(|r| r.name == role_name),
            "should find our role in the org list"
        );

        // Upsert (update display name)
        let updated = store
            .upsert_custom_role(&coder_core::UpsertCustomRoleInput {
                name: role_name.clone(),
                display_name: "Updated Role Name".to_string(),
                organization_id: Some(org_id),
                site_permissions: "[]".to_string(),
                org_permissions: "[]".to_string(),
                user_permissions: "[]".to_string(),
            })
            .await?;
        assert_eq!(updated.display_name, "Updated Role Name");

        // Delete
        let deleted = store.delete_custom_role(&role_name, Some(org_id)).await?;
        assert!(deleted, "delete_custom_role should return true");

        // Verify gone
        let after_delete = store.list_custom_roles(Some(org_id)).await?;
        assert!(
            !after_delete.iter().any(|r| r.name == role_name),
            "deleted role should not appear"
        );

        Ok(())
    }

    // =========================================================================
    // 16. Files
    // =========================================================================

    #[tokio::test]
    #[ignore]
    async fn test_file_insert_and_find_by_hash() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;

        let file_id = Uuid::new_v4();
        let file_hash = format!("sha256-{}", uniq());
        let file_data = b"hello world file content".to_vec();

        // Insert
        let result = store
            .insert_file(coder_core::InsertFileInput {
                id: file_id,
                hash: file_hash.clone(),
                created_by: user_id,
                mimetype: "text/plain".to_string(),
                data: file_data.clone(),
            })
            .await?;
        assert_eq!(result.id, file_id);

        // Find by ID
        let found = store.get_file_by_id(file_id).await?;
        let found = found.unwrap_or_else(|| panic!("should find file by ID"));
        assert_eq!(found.hash, file_hash);
        assert_eq!(found.data, file_data);
        assert_eq!(found.mimetype, "text/plain");
        assert_eq!(found.created_by, user_id);

        // Find by hash and creator
        let by_hash = store
            .get_file_by_hash_and_creator(&file_hash, user_id)
            .await?;
        assert!(by_hash.is_some());
        assert_eq!(by_hash.as_ref().map(|f| f.id), Some(file_id));

        // Find by non-existent hash
        let missing = store
            .get_file_by_hash_and_creator("nonexistent-hash", user_id)
            .await?;
        assert!(missing.is_none());

        Ok(())
    }

    // =========================================================================
    // find_provisioner_job / cancel_template_provisioner_job
    // =========================================================================

    #[tokio::test]
    #[ignore]
    async fn test_find_provisioner_job_returns_some() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;
        let job_id = create_provisioner_job(&pool, org_id, user_id).await?;

        let found = store.find_provisioner_job(job_id).await?;
        assert!(found.is_some(), "should find the provisioner job");
        let job = found.unwrap_or_else(|| panic!("just asserted Some"));
        assert_eq!(job.id, job_id);
        assert_eq!(job.organization_id, org_id);
        assert_eq!(job.initiator_id, user_id);
        assert!(job.canceled_at.is_none());
        assert!(job.completed_at.is_none());
        assert_eq!(job.job_status, "pending");

        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_find_provisioner_job_returns_none_for_missing() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };

        let missing_id = Uuid::new_v4();
        let found = store.find_provisioner_job(missing_id).await?;
        assert!(found.is_none(), "should return None for non-existent job");

        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_cancel_template_provisioner_job_happy_path() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;
        let job_id = create_provisioner_job(&pool, org_id, user_id).await?;

        // Cancel should succeed
        let canceled = store.cancel_template_provisioner_job(job_id).await?;
        assert!(canceled, "cancel should return true for a pending job");

        // Pending job (no worker) should have both canceled_at and completed_at set
        let job = store
            .find_provisioner_job(job_id)
            .await?
            .unwrap_or_else(|| panic!("job should still exist"));
        assert!(job.canceled_at.is_some(), "canceled_at should be set");
        assert!(
            job.completed_at.is_some(),
            "completed_at should be set for pending (no worker) job"
        );
        assert_eq!(job.job_status, "canceled");

        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_cancel_template_provisioner_job_running() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;
        let job_id = create_provisioner_job(&pool, org_id, user_id).await?;

        // Simulate a worker picking up the job (set worker_id and started_at)
        let worker_id = Uuid::new_v4();
        sqlx::query(
            "UPDATE provisioner_jobs SET worker_id = $1, started_at = NOW(), updated_at = NOW() WHERE id = $2",
        )
        .bind(worker_id)
        .bind(job_id)
        .execute(&pool)
        .await?;

        // Cancel should succeed
        let canceled = store.cancel_template_provisioner_job(job_id).await?;
        assert!(canceled, "cancel should return true for a running job");

        // Running job should have canceled_at set but NOT completed_at (enters "canceling" state)
        let job = store
            .find_provisioner_job(job_id)
            .await?
            .unwrap_or_else(|| panic!("job should still exist"));
        assert!(job.canceled_at.is_some(), "canceled_at should be set");
        assert!(
            job.completed_at.is_none(),
            "completed_at should NOT be set for running job (enters canceling state)"
        );
        assert_eq!(job.job_status, "canceling");

        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_cancel_template_provisioner_job_already_canceled() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;
        let job_id = create_provisioner_job(&pool, org_id, user_id).await?;

        // Cancel once
        let first = store.cancel_template_provisioner_job(job_id).await?;
        assert!(first, "first cancel should succeed");

        // Cancel again — should return false (idempotent)
        let second = store.cancel_template_provisioner_job(job_id).await?;
        assert!(!second, "second cancel should return false");

        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_cancel_template_provisioner_job_nonexistent() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };

        let missing_id = Uuid::new_v4();
        let canceled = store.cancel_template_provisioner_job(missing_id).await?;
        assert!(!canceled, "cancel should return false for non-existent job");

        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_cancel_template_provisioner_job_already_completed() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;
        let job_id = create_provisioner_job(&pool, org_id, user_id).await?;

        // Manually mark the job as completed (simulating a successful finish)
        sqlx::query(
            "UPDATE provisioner_jobs SET completed_at = NOW(), updated_at = NOW() WHERE id = $1",
        )
        .bind(job_id)
        .execute(&pool)
        .await?;

        // Cancel should fail because completed_at is already set
        let canceled = store.cancel_template_provisioner_job(job_id).await?;
        assert!(
            !canceled,
            "cancel should return false for an already-completed job"
        );

        Ok(())
    }

    // =========================================================================
    // NEW: Constraint Violations
    // =========================================================================

    /// Verify that creating a user with a duplicate email/username returns
    /// `CreateUserStoreError::AlreadyExists` instead of panicking.
    #[tokio::test]
    #[ignore]
    async fn test_create_user_duplicate_returns_error() -> TestResult {
        use coder_core::CreateUserStoreError;

        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let suffix = uniq();

        // First creation succeeds
        let _user_id = create_test_user(&store, org_id, &suffix).await?;

        // Second creation with the same username/email should fail gracefully
        let input = CreateUserInput {
            email: format!("test-{suffix}@example.com"),
            username: format!("testuser-{suffix}"),
            name: format!("Test User {suffix}"),
            password_hash: Some("hashed".to_string()),
            login_type: LoginType::Password,
            status: UserStatus::Active,
            organization_ids: vec![org_id],
        };

        let result = store.create_user(input).await;
        assert!(result.is_err(), "duplicate user should return an error");
        match result {
            Err(CreateUserStoreError::AlreadyExists) => {} // expected
            Err(other) => {
                return Err(format!("expected AlreadyExists, got: {other:?}").into());
            }
            Ok(_) => return Err("expected error but got Ok".into()),
        }

        Ok(())
    }

    /// Inserting a workspace with an invalid template_id (non-existent FK)
    /// should return a storage error, not panic.
    #[tokio::test]
    #[ignore]
    async fn test_insert_workspace_invalid_template_fk() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;

        let bogus_template_id = Uuid::new_v4(); // does not exist
        let result = store
            .insert_workspace(CreateWorkspaceInput {
                id: Uuid::new_v4(),
                owner_id: user_id,
                organization_id: org_id,
                template_id: bogus_template_id,
                name: format!("ws-fk-{}", uniq()),
                autostart_schedule: None,
                ttl_ns: None,
                automatic_updates: "never".to_string(),
            })
            .await;

        assert!(
            result.is_err(),
            "workspace with bogus template FK should fail"
        );
        Ok(())
    }

    /// Creating a group with a duplicate name in the same organization should
    /// return an error rather than panicking.
    #[tokio::test]
    #[ignore]
    async fn test_create_group_duplicate_name_returns_error() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;

        let group_name = format!("dup-group-{}", uniq());
        let input = CreateGroupInput {
            name: group_name.clone(),
            display_name: "Dup Group".to_string(),
            organization_id: org_id,
            avatar_url: String::new(),
            quota_allowance: 0,
        };

        // First creation succeeds
        let _g1 = store.create_group(&input).await?;

        // Second creation with the same name should fail
        let result = store.create_group(&input).await;
        assert!(
            result.is_err(),
            "duplicate group name in same org should fail"
        );

        Ok(())
    }

    // =========================================================================
    // NEW: Complex Query – find_workspace_by_owner_and_name (JOIN + LOWER)
    // =========================================================================

    /// `find_workspace_by_owner_and_name` uses LOWER() for case-insensitive
    /// matching and a LEFT JOIN on workspace_favorites. Verify both the happy
    /// path and the case-insensitive lookup.
    #[tokio::test]
    #[ignore]
    async fn test_find_workspace_by_owner_and_name_case_insensitive() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;
        let tmpl = create_test_template(
            &store,
            &pool,
            org_id,
            user_id,
            &format!("tmpl-ci-{}", uniq()),
        )
        .await?;

        let ws_name = format!("MyWorkspace-{}", uniq());
        let ws_id = Uuid::new_v4();
        store
            .insert_workspace(CreateWorkspaceInput {
                id: ws_id,
                owner_id: user_id,
                organization_id: org_id,
                template_id: tmpl,
                name: ws_name.clone(),
                autostart_schedule: None,
                ttl_ns: None,
                automatic_updates: "never".to_string(),
            })
            .await?;

        // Exact name match
        let found = store
            .find_workspace_by_owner_and_name(user_id, &ws_name, None)
            .await?;
        assert!(found.is_some(), "exact name should match");
        assert_eq!(found.as_ref().map(|w| w.id), Some(ws_id));

        // Case-insensitive match (all lower)
        let lower = store
            .find_workspace_by_owner_and_name(user_id, &ws_name.to_lowercase(), None)
            .await?;
        assert!(lower.is_some(), "lower-case name should still match");

        // Non-existent name should return None
        let missing = store
            .find_workspace_by_owner_and_name(user_id, "no-such-ws", None)
            .await?;
        assert!(missing.is_none());

        Ok(())
    }

    // =========================================================================
    // NEW: Workspace list – empty result set
    // =========================================================================

    /// Listing workspaces with a filter that matches nothing should return an
    /// empty vec with a total count of 0.
    #[tokio::test]
    #[ignore]
    async fn test_workspace_list_empty_result() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };

        let non_existent_owner = Uuid::new_v4();
        let (list, total) = store
            .list_workspaces(WorkspaceListFilter {
                owner_id: Some(non_existent_owner),
                ..default_ws_filter()
            })
            .await?;
        assert!(list.is_empty(), "no workspaces should match bogus owner");
        assert_eq!(total, 0);
        Ok(())
    }

    // =========================================================================
    // NEW: Workspace list – pagination boundary
    // =========================================================================

    /// Test that offset beyond total rows returns an empty page while the total
    /// count remains correct.
    #[tokio::test]
    #[ignore]
    async fn test_workspace_list_pagination_beyond_end() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;
        let tmpl = create_test_template(
            &store,
            &pool,
            org_id,
            user_id,
            &format!("tmpl-pag-{}", uniq()),
        )
        .await?;

        // Create 3 workspaces
        for i in 0..3 {
            store
                .insert_workspace(CreateWorkspaceInput {
                    id: Uuid::new_v4(),
                    owner_id: user_id,
                    organization_id: org_id,
                    template_id: tmpl,
                    name: format!("ws-pag-{}-{}", i, uniq()),
                    autostart_schedule: None,
                    ttl_ns: None,
                    automatic_updates: "never".to_string(),
                })
                .await?;
        }

        // Page with offset past the end
        let (page, total) = store
            .list_workspaces(WorkspaceListFilter {
                owner_id: Some(user_id),
                offset: 100,
                limit: 10,
                ..default_ws_filter()
            })
            .await?;
        assert!(page.is_empty(), "offset past end should return empty page");
        assert_eq!(total, 3, "total should still reflect all matching rows");

        // Page with limit 1, offset 0 – should get exactly 1
        let (first_page, total2) = store
            .list_workspaces(WorkspaceListFilter {
                owner_id: Some(user_id),
                offset: 0,
                limit: 1,
                ..default_ws_filter()
            })
            .await?;
        assert_eq!(first_page.len(), 1, "limit=1 should return exactly 1 row");
        assert_eq!(total2, 3);

        Ok(())
    }

    // =========================================================================
    // NEW: Workspace list – combined template_ids + owner filter
    // =========================================================================

    /// Verify that combining `owner_id` and `template_ids` filters narrows
    /// results correctly (AND semantics).
    #[tokio::test]
    #[ignore]
    async fn test_workspace_list_combined_owner_and_template_filter() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let owner_a = create_test_user(&store, org_id, &uniq()).await?;
        let owner_b = create_test_user(&store, org_id, &uniq()).await?;
        let tmpl_x =
            create_test_template(&store, &pool, org_id, owner_a, &format!("tx-{}", uniq())).await?;
        let tmpl_y =
            create_test_template(&store, &pool, org_id, owner_a, &format!("ty-{}", uniq())).await?;

        // owner_a has 2 workspaces: one on tmpl_x, one on tmpl_y
        store
            .insert_workspace(CreateWorkspaceInput {
                id: Uuid::new_v4(),
                owner_id: owner_a,
                organization_id: org_id,
                template_id: tmpl_x,
                name: format!("ws-ax-{}", uniq()),
                autostart_schedule: None,
                ttl_ns: None,
                automatic_updates: "never".to_string(),
            })
            .await?;
        store
            .insert_workspace(CreateWorkspaceInput {
                id: Uuid::new_v4(),
                owner_id: owner_a,
                organization_id: org_id,
                template_id: tmpl_y,
                name: format!("ws-ay-{}", uniq()),
                autostart_schedule: None,
                ttl_ns: None,
                automatic_updates: "never".to_string(),
            })
            .await?;

        // owner_b has 1 workspace on tmpl_x
        store
            .insert_workspace(CreateWorkspaceInput {
                id: Uuid::new_v4(),
                owner_id: owner_b,
                organization_id: org_id,
                template_id: tmpl_x,
                name: format!("ws-bx-{}", uniq()),
                autostart_schedule: None,
                ttl_ns: None,
                automatic_updates: "never".to_string(),
            })
            .await?;

        // Filter: owner_a AND tmpl_x → should be exactly 1
        let (rows, total) = store
            .list_workspaces(WorkspaceListFilter {
                owner_id: Some(owner_a),
                template_ids: vec![tmpl_x],
                ..default_ws_filter()
            })
            .await?;
        assert_eq!(total, 1, "only 1 workspace belongs to owner_a on tmpl_x");
        assert_eq!(rows.len(), 1);

        // Filter: owner_a with no template filter → should be 2
        let (rows2, total2) = store
            .list_workspaces(WorkspaceListFilter {
                owner_id: Some(owner_a),
                ..default_ws_filter()
            })
            .await?;
        assert_eq!(total2, 2);
        assert_eq!(rows2.len(), 2);

        Ok(())
    }

    // =========================================================================
    // NEW: Soft-delete cascade – template soft-delete hides from find
    // =========================================================================

    /// After soft-deleting a template, `find_template_by_id` should return
    /// `None` (the SQL filters `deleted = false`).
    #[tokio::test]
    #[ignore]
    async fn test_soft_delete_template_hides_from_find() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;
        let tmpl_id = create_test_template(
            &store,
            &pool,
            org_id,
            user_id,
            &format!("tmpl-sdel-{}", uniq()),
        )
        .await?;

        // Should be findable before deletion
        let before = store.find_template_by_id(tmpl_id).await?;
        assert!(before.is_some(), "template should exist before soft-delete");

        // Soft-delete
        let deleted = store.soft_delete_template(tmpl_id).await?;
        assert!(deleted, "soft_delete_template should return true");

        // Should NOT be findable after deletion
        let after = store.find_template_by_id(tmpl_id).await?;
        assert!(
            after.is_none(),
            "template should not be found after soft-delete"
        );

        // Deleting again should return false (already soft-deleted)
        let second = store.soft_delete_template(tmpl_id).await?;
        assert!(
            !second,
            "second soft_delete_template should return false (idempotent)"
        );

        Ok(())
    }

    // =========================================================================
    // NEW: Soft-delete cascade – workspace soft-delete excludes from list
    // =========================================================================

    /// After soft-deleting a workspace it should be excluded from list_workspaces
    /// AND the total count should drop.
    #[tokio::test]
    #[ignore]
    async fn test_soft_delete_workspace_excludes_from_list_and_count() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;
        let tmpl = create_test_template(
            &store,
            &pool,
            org_id,
            user_id,
            &format!("tmpl-wsdel-{}", uniq()),
        )
        .await?;

        let ws_id = Uuid::new_v4();
        store
            .insert_workspace(CreateWorkspaceInput {
                id: ws_id,
                owner_id: user_id,
                organization_id: org_id,
                template_id: tmpl,
                name: format!("ws-sdel-{}", uniq()),
                autostart_schedule: None,
                ttl_ns: None,
                automatic_updates: "never".to_string(),
            })
            .await?;

        // Count before delete
        let (_, before_total) = store
            .list_workspaces(WorkspaceListFilter {
                owner_id: Some(user_id),
                ..default_ws_filter()
            })
            .await?;
        assert!(before_total >= 1);

        // Soft-delete the workspace
        store.soft_delete_workspace(ws_id).await?;

        // The workspace should no longer appear in list or find
        let after_find = store.find_workspace_by_id(ws_id, None).await?;
        assert!(
            after_find.is_none(),
            "soft-deleted workspace should not be found"
        );

        let (after_list, after_total) = store
            .list_workspaces(WorkspaceListFilter {
                owner_id: Some(user_id),
                ..default_ws_filter()
            })
            .await?;
        assert_eq!(
            after_total,
            before_total - 1,
            "total should drop by 1 after soft-delete"
        );
        assert!(
            !after_list.iter().any(|w| w.id == ws_id),
            "deleted workspace should not appear in list"
        );

        Ok(())
    }

    // =========================================================================
    // NEW: Transaction method – acquire_pending_notification_messages
    // =========================================================================

    /// `acquire_pending_notification_messages` uses FOR UPDATE SKIP LOCKED in a
    /// subquery. Verify that:
    ///   - pending messages are leased and returned with status "leased"
    ///   - messages that already exceeded max_attempt_count are skipped
    #[tokio::test]
    #[ignore]
    async fn test_acquire_pending_notification_messages_basic() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;

        // Seed a notification template
        let notif_tmpl_id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO notification_templates (id, name, title_template, body_template, "group", actions, kind)
               VALUES ($1, $2, 'Title', 'Body', NULL, '[]', 'system')
               ON CONFLICT (id) DO NOTHING"#,
        )
        .bind(notif_tmpl_id)
        .bind(format!("test-acq-{}", uniq()))
        .execute(&pool)
        .await?;

        // Insert 2 pending messages; one with attempt_count already at the max
        let msg1 = Uuid::new_v4();
        let msg2 = Uuid::new_v4();
        for (id, attempts) in [(msg1, 0i32), (msg2, 99)] {
            sqlx::query(
                r#"INSERT INTO notification_messages
                   (id, user_id, notification_template_id, method, status, payload,
                    created_at, updated_at, attempt_count)
                   VALUES ($1, $2, $3, 'smtp'::notification_method,
                           'pending'::notification_message_status,
                           '{}'::jsonb, NOW(), NOW(), $4)"#,
            )
            .bind(id)
            .bind(user_id)
            .bind(notif_tmpl_id)
            .bind(attempts)
            .execute(&pool)
            .await?;
        }

        // Acquire with max_attempt_count = 5: only msg1 should be acquired
        let acquired = store.acquire_pending_notification_messages(10, 5).await?;

        let acquired_ids: Vec<Uuid> = acquired.iter().map(|m| m.id).collect();
        assert!(
            acquired_ids.contains(&msg1),
            "pending message with 0 attempts should be acquired"
        );
        assert!(
            !acquired_ids.contains(&msg2),
            "message with 99 attempts should NOT be acquired (exceeds max)"
        );

        // The acquired message should have status Leased
        for msg in &acquired {
            if msg.id == msg1 {
                assert_eq!(
                    msg.status,
                    coder_core::NotificationMessageStatus::Leased,
                    "acquired message should be leased"
                );
            }
        }

        // Clean up
        for id in [msg1, msg2] {
            let _ = sqlx::query("DELETE FROM notification_messages WHERE id = $1")
                .bind(id)
                .execute(&pool)
                .await;
        }
        let _ = sqlx::query("DELETE FROM notification_templates WHERE id = $1")
            .bind(notif_tmpl_id)
            .execute(&pool)
            .await;

        Ok(())
    }

    // =========================================================================
    // NEW: update_workspace_name – CTE-based UPDATE with JOIN
    // =========================================================================

    /// `update_workspace_name` uses a CTE (WITH updated AS ...) and a LEFT JOIN
    /// on workspace_favorites. Verify it updates correctly and returns None for
    /// a non-existent workspace.
    #[tokio::test]
    #[ignore]
    async fn test_update_workspace_name_cte_path() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;
        let tmpl = create_test_template(
            &store,
            &pool,
            org_id,
            user_id,
            &format!("tmpl-ren-{}", uniq()),
        )
        .await?;

        let ws_id = Uuid::new_v4();
        let orig_name = format!("ws-orig-{}", uniq());
        store
            .insert_workspace(CreateWorkspaceInput {
                id: ws_id,
                owner_id: user_id,
                organization_id: org_id,
                template_id: tmpl,
                name: orig_name.clone(),
                autostart_schedule: None,
                ttl_ns: None,
                automatic_updates: "never".to_string(),
            })
            .await?;

        // Rename the workspace
        let new_name = format!("ws-renamed-{}", uniq());
        let updated = store
            .update_workspace_name(ws_id, &new_name, Some(user_id))
            .await?;
        assert!(updated.is_some(), "update should return the record");
        assert_eq!(
            updated.as_ref().map(|w| w.name.as_str()),
            Some(new_name.as_str())
        );

        // Verify via find
        let found = store.find_workspace_by_id(ws_id, None).await?;
        assert_eq!(
            found.as_ref().map(|w| w.name.as_str()),
            Some(new_name.as_str())
        );

        // Update a non-existent workspace should return None (not error)
        let missing = store
            .update_workspace_name(Uuid::new_v4(), "nope", None)
            .await?;
        assert!(
            missing.is_none(),
            "updating non-existent workspace should return None"
        );

        Ok(())
    }

    // =========================================================================
    // NEW: User status change tracking (insert + list)
    // =========================================================================

    /// `insert_user_status_change` and `list_user_status_changes` exercise the
    /// user_status_changes table. Verify insertion and ordering (ASC by
    /// changed_at).
    #[tokio::test]
    #[ignore]
    async fn test_user_status_changes_insert_and_list() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;

        // Insert two status changes
        let sc1 = store
            .insert_user_status_change(
                user_id,
                UserStatus::Active,
                UserStatus::Suspended,
                None,
                "test suspension",
            )
            .await?;
        assert_eq!(sc1.user_id, user_id);

        let sc2 = store
            .insert_user_status_change(
                user_id,
                UserStatus::Suspended,
                UserStatus::Active,
                None,
                "reactivated",
            )
            .await?;

        // List should return them ordered by changed_at ASC
        let changes = store.list_user_status_changes(user_id).await?;
        assert!(
            changes.len() >= 2,
            "should have at least the 2 changes we inserted"
        );

        // The second change should come after the first in the list
        let pos1 = changes
            .iter()
            .position(|c| c.id == sc1.id)
            .ok_or("sc1 not found in changes list")?;
        let pos2 = changes
            .iter()
            .position(|c| c.id == sc2.id)
            .ok_or("sc2 not found in changes list")?;
        assert!(pos1 < pos2, "changes should be ordered by changed_at ASC");

        Ok(())
    }

    // =========================================================================
    // NEW: Template version list – sort order verification
    // =========================================================================

    /// `list_template_versions` orders by `created_at DESC`. Verify that the
    /// most recently created version appears first.
    #[tokio::test]
    #[ignore]
    async fn test_template_version_list_sort_order() -> TestResult {
        use coder_core::template::CreateTemplateVersionInput;

        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;
        let tmpl_name = format!("tmpl-sort-{}", uniq());
        let tmpl_id = create_test_template(&store, &pool, org_id, user_id, &tmpl_name).await?;

        // Add two more versions (the template helper already created v1)
        for i in 2..=3 {
            let v_id = Uuid::new_v4();
            let job_id = create_provisioner_job(&pool, org_id, user_id).await?;
            let now = OffsetDateTime::now_utc();
            store
                .insert_template_version(CreateTemplateVersionInput {
                    id: v_id,
                    template_id: Some(tmpl_id),
                    organization_id: org_id,
                    created_at: now,
                    updated_at: now,
                    name: format!("{tmpl_name}-v{i}"),
                    message: format!("version {i}"),
                    readme: String::new(),
                    job_id,
                    created_by: user_id,
                    source_example_id: None,
                })
                .await?;
        }

        let versions = store
            .list_template_versions(TemplateVersionListFilter {
                template_id: tmpl_id,
                include_archived: true,
                offset: 0,
                limit: 100,
            })
            .await?;

        assert!(versions.len() >= 3, "should have at least 3 versions");

        // Verify DESC ordering: first version in the list has the latest created_at
        for window in versions.windows(2) {
            assert!(
                window[0].created_at >= window[1].created_at,
                "versions should be ordered by created_at DESC"
            );
        }

        Ok(())
    }

    // =========================================================================
    // NEW: User list – sort order verification (LOWER(username) ASC)
    // =========================================================================

    /// `list_users` orders by `LOWER(username) ASC`. Verify alphabetical
    /// ordering among newly created users.
    #[tokio::test]
    #[ignore]
    async fn test_user_list_sort_order_by_username() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;

        // Create users with carefully chosen prefixes so we can verify ordering
        let tag = uniq();
        let mut names = vec![
            format!("charlie-{tag}"),
            format!("alpha-{tag}"),
            format!("bravo-{tag}"),
        ];
        for name in &names {
            create_test_user(&store, org_id, name).await?;
        }

        let (users, total) = store
            .list_users(UserListFilter {
                search: tag.clone(),
                status: None,
                offset: 0,
                limit: 100,
            })
            .await?;

        assert_eq!(total, 3, "should find the 3 test users");

        // Extract usernames
        let returned_usernames: Vec<String> = users.iter().map(|u| u.username.clone()).collect();

        names.sort();
        let expected: Vec<String> = names.iter().map(|n| format!("testuser-{n}")).collect();

        assert_eq!(
            returned_usernames, expected,
            "users should be ordered by LOWER(username) ASC"
        );

        Ok(())
    }

    // =========================================================================
    // Deployment Store
    // =========================================================================

    #[tokio::test]
    #[ignore]
    async fn test_deployment_ping() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };

        use coder_core::DeploymentStore;
        store.ping().await?;
        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_deployment_metadata_idempotent() -> TestResult {
        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };

        use coder_core::DeploymentStore;

        // First call creates the deployment_id.
        let meta1 = store.ensure_deployment_metadata().await?;
        // Second call must return the same UUID (idempotent).
        let meta2 = store.ensure_deployment_metadata().await?;
        assert_eq!(
            meta1.deployment_id, meta2.deployment_id,
            "ensure_deployment_metadata must be idempotent"
        );
        Ok(())
    }

    // =========================================================================
    // Provisioner Store — Job Lifecycle
    // =========================================================================

    #[tokio::test]
    #[ignore]
    async fn test_provisioner_job_insert_acquire_complete() -> TestResult {
        use coder_core::{
            CompleteProvisionerJobInput, InsertProvisionerJobInput, ProvisionerJobStatus,
            ProvisionerJobType, ProvisionerStorageMethod,
        };

        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;
        let file_id = Uuid::new_v4();

        // Insert a file stub so the FK is satisfied (provisioner_jobs.file_id is nullable, skip).
        let job_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();

        let job = store
            .insert_provisioner_job(InsertProvisionerJobInput {
                id: job_id,
                created_at: now,
                organization_id: org_id,
                initiator_id: user_id,
                provisioner: ProvisionerType::Echo,
                storage_method: ProvisionerStorageMethod::File,
                file_id,
                job_type: ProvisionerJobType::TemplateVersionImport,
                input: json!({}),
                tags: json!({}),
                trace_metadata: json!({}),
            })
            .await?;

        assert_eq!(job.id, job_id);
        assert_eq!(job.job_status, ProvisionerJobStatus::Pending);
        assert!(job.started_at.is_none());

        // Fetch by id
        let fetched = store.get_provisioner_job_by_id(job_id).await?;
        assert!(fetched.is_some());
        assert_eq!(fetched.as_ref().map(|j| j.id), Some(job_id));

        // Acquire the job
        let worker_id = Uuid::new_v4();
        let acquired = store
            .acquire_provisioner_job(AcquireProvisionerJobInput {
                worker_id,
                started_at: OffsetDateTime::now_utc(),
                organization_id: org_id,
                types: vec![ProvisionerType::Echo],
                provisioner_tags: json!({}),
            })
            .await?;
        assert!(acquired.is_some());
        let acquired = acquired.as_ref();
        assert_eq!(acquired.map(|j| j.id), Some(job_id));
        assert!(acquired.and_then(|j| j.started_at).is_some());

        // Complete the job
        let complete_time = OffsetDateTime::now_utc();
        store
            .update_provisioner_job_with_complete_by_id(CompleteProvisionerJobInput {
                id: job_id,
                updated_at: complete_time,
                completed_at: complete_time,
                error: String::new(),
                error_code: String::new(),
            })
            .await?;

        let completed = store.get_provisioner_job_by_id(job_id).await?;
        assert!(completed.is_some());
        let completed = completed.as_ref();
        assert!(completed.and_then(|j| j.completed_at).is_some());
        assert_eq!(completed.map(|j| &j.error).map(String::as_str), Some(""));

        Ok(())
    }

    // =========================================================================
    // Provisioner Store — Log Insertion with Transaction
    // =========================================================================

    #[tokio::test]
    #[ignore]
    async fn test_provisioner_job_logs_insert() -> TestResult {
        use coder_core::provisioner::{LogLevel, LogSource};
        use coder_core::{
            InsertProvisionerJobInput, InsertProvisionerJobLogsInput, ProvisionerJobType,
            ProvisionerStorageMethod,
        };

        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;

        let job_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();

        store
            .insert_provisioner_job(InsertProvisionerJobInput {
                id: job_id,
                created_at: now,
                organization_id: org_id,
                initiator_id: user_id,
                provisioner: ProvisionerType::Echo,
                storage_method: ProvisionerStorageMethod::File,
                file_id: Uuid::new_v4(),
                job_type: ProvisionerJobType::TemplateVersionImport,
                input: json!({}),
                tags: json!({}),
                trace_metadata: json!({}),
            })
            .await?;

        // Insert 2 log entries
        let logs = store
            .insert_provisioner_job_logs(InsertProvisionerJobLogsInput {
                job_id,
                created_at: vec![now, now],
                source: vec![LogSource::ProvisionerDaemon, LogSource::Provisioner],
                level: vec![LogLevel::Info, LogLevel::Warn],
                stage: vec!["init".to_string(), "plan".to_string()],
                output: vec!["hello".to_string(), "world".to_string()],
            })
            .await?;

        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0].source, LogSource::ProvisionerDaemon);
        assert_eq!(logs[1].level, LogLevel::Warn);

        // Verify logs_length was updated on the job
        let job = store.get_provisioner_job_by_id(job_id).await?;
        assert!(job.is_some());
        let job = job.as_ref();
        assert!(
            job.map(|j| j.logs_length).unwrap_or(0) > 0,
            "logs_length should be incremented"
        );

        // Get logs after id=0
        let fetched = store.get_provisioner_logs_after_id(job_id, 0).await?;
        assert_eq!(fetched.len(), 2);

        Ok(())
    }

    // =========================================================================
    // Provisioner Store — Daemon Upsert
    // =========================================================================

    #[tokio::test]
    #[ignore]
    async fn test_provisioner_daemon_upsert() -> TestResult {
        use coder_core::UpsertProvisionerDaemonInput;
        use std::collections::HashMap;

        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;

        let daemon_name = format!("test-daemon-{}", uniq());
        let mut tags = HashMap::new();
        tags.insert("scope".to_string(), "organization".to_string());

        let daemon = store
            .upsert_provisioner_daemon(UpsertProvisionerDaemonInput {
                name: daemon_name.clone(),
                provisioners: vec!["echo".to_string()],
                tags: tags.clone(),
                last_seen_at: OffsetDateTime::now_utc(),
                version: "1.0.0".to_string(),
                organization_id: org_id,
                api_version: "1.0".to_string(),
                key_id: None,
            })
            .await?;

        assert_eq!(daemon.name, daemon_name);
        assert_eq!(daemon.organization_id, org_id);

        // Upsert again — should update, not create a second row.
        let daemon2 = store
            .upsert_provisioner_daemon(UpsertProvisionerDaemonInput {
                name: daemon_name.clone(),
                provisioners: vec!["echo".to_string(), "terraform".to_string()],
                tags,
                last_seen_at: OffsetDateTime::now_utc(),
                version: "2.0.0".to_string(),
                organization_id: org_id,
                api_version: "1.1".to_string(),
                key_id: None,
            })
            .await?;

        assert_eq!(daemon2.id, daemon.id, "upsert should return same id");
        assert_eq!(daemon2.version, "2.0.0");

        // List daemons by org
        let daemons = store
            .get_provisioner_daemons_by_organization(org_id)
            .await?;
        let found = daemons.iter().any(|d| d.id == daemon.id);
        assert!(found, "daemon should appear in org listing");

        Ok(())
    }

    // =========================================================================
    // Provisioner Store — Key CRUD
    // =========================================================================

    #[tokio::test]
    #[ignore]
    async fn test_provisioner_key_crud() -> TestResult {
        use coder_core::InsertProvisionerKeyInput;

        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;

        let key_id = Uuid::new_v4();
        let key_name = format!("test-key-{}", uniq());
        let hashed = b"sha256hashbytes1234".to_vec();

        let key = store
            .insert_provisioner_key(InsertProvisionerKeyInput {
                id: key_id,
                created_at: OffsetDateTime::now_utc(),
                organization_id: org_id,
                name: key_name.clone(),
                hashed_secret: hashed.clone(),
                tags: json!({"env": "test"}),
            })
            .await?;
        assert_eq!(key.id, key_id);
        assert_eq!(key.name, key_name);

        // Get by id
        let by_id = store.get_provisioner_key_by_id(key_id).await?;
        assert!(by_id.is_some());
        assert_eq!(by_id.as_ref().map(|k| &k.name), Some(&key_name));

        // Get by hashed secret
        let by_hash = store.get_provisioner_key_by_hashed_secret(&hashed).await?;
        assert!(by_hash.is_some());
        assert_eq!(by_hash.as_ref().map(|k| k.id), Some(key_id));

        // Get by name
        let by_name = store.get_provisioner_key_by_name(org_id, &key_name).await?;
        assert!(by_name.is_some());

        // List by org
        let keys = store.list_provisioner_keys_by_organization(org_id).await?;
        let found = keys.iter().any(|k| k.id == key_id);
        assert!(found);

        // Delete
        let deleted = store.delete_provisioner_key(key_id).await?;
        assert!(deleted);

        // Verify gone
        let gone = store.get_provisioner_key_by_id(key_id).await?;
        assert!(gone.is_none());

        Ok(())
    }

    // =========================================================================
    // Provisioner Store — Job Timings
    // =========================================================================

    #[tokio::test]
    #[ignore]
    async fn test_provisioner_job_timings() -> TestResult {
        use coder_core::{
            InsertProvisionerJobInput, InsertProvisionerJobTimingsInput, ProvisionerJobTimingStage,
            ProvisionerJobType, ProvisionerStorageMethod,
        };

        let store = match setup_store().await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let pool = store.pool();
        let org_id = ensure_default_org(&pool).await?;
        let user_id = create_test_user(&store, org_id, &uniq()).await?;

        let job_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();

        store
            .insert_provisioner_job(InsertProvisionerJobInput {
                id: job_id,
                created_at: now,
                organization_id: org_id,
                initiator_id: user_id,
                provisioner: ProvisionerType::Echo,
                storage_method: ProvisionerStorageMethod::File,
                file_id: Uuid::new_v4(),
                job_type: ProvisionerJobType::TemplateVersionImport,
                input: json!({}),
                tags: json!({}),
                trace_metadata: json!({}),
            })
            .await?;

        let later = now + time::Duration::seconds(5);
        let timings = store
            .insert_provisioner_job_timings(InsertProvisionerJobTimingsInput {
                job_id,
                started_at: vec![now],
                ended_at: vec![later],
                stage: vec![ProvisionerJobTimingStage::Init],
                source: vec!["terraform".to_string()],
                action: vec!["create".to_string()],
                resource: vec!["null_resource.test".to_string()],
            })
            .await?;

        assert_eq!(timings.len(), 1);
        assert_eq!(timings[0].stage, ProvisionerJobTimingStage::Init);

        // Fetch by job_id
        let fetched = store.get_provisioner_job_timings_by_job_id(job_id).await?;
        assert_eq!(fetched.len(), 1);

        Ok(())
    }
}
