//! Postgres-backed application store.

use std::{str::FromStr, time::Duration};

use async_trait::async_trait;
use std::collections::HashMap;

use coder_core::api::{
    ConnectionLatency, DAUEntry, DAUsResponse, GetUserStatusCountsResponse, InsightsReportInterval,
    TemplateAppUsage, TemplateAppsType, TemplateInsightsIntervalReport, TemplateInsightsReport,
    TemplateInsightsResponse, TemplateParameterUsage, TemplateParameterValue, UserActivity,
    UserActivityInsightsReport, UserActivityInsightsResponse, UserLatency,
    UserLatencyInsightsReport, UserLatencyInsightsResponse, UserStatusChangeCount,
};
use coder_core::ports::{UpdateWorkspaceACLInput, WorkspaceACLRecord};
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
    ChatFileRecord, ChatMessageRecord, ChatMessageVisibility, ChatQueuedMessageRecord, ChatRecord,
    ChatStatus, CompleteProvisionerJobInput, CreateApiKeyInput, CreateApiKeyStoreError,
    CreateFirstUserInput, CreateFirstUserStoreError, CreateGroupInput,
    CreateOAuth2ProviderAppInput, CreateOAuth2ProviderAppTokenInput, CreateUserInput,
    CreateUserStoreError, CreateWorkspaceBuildInput, CreateWorkspaceInput, CustomRoleRecord,
    DatabaseConfig, DeploymentMetadata, DeploymentStatsResponse, DeploymentStore,
    ExternalAuthAppInstallation, ExternalAuthLinkRecord, ExternalAuthUser, FileRecord,
    FirstUserRecord, GetJobsToBeReapedInput, GitSshKeyRecord, GroupMemberRecord, GroupRecord,
    HealthSettings, InsertAgentLogInput, InsertChatFileInput, InsertChatInput,
    InsertChatMessageInput, InsertFileInput, InsertFileResult, InsertOrganizationMemberError,
    InsertProvisionerJobInput, InsertProvisionerJobLogsInput, InsertProvisionerJobTimingsInput,
    InsertProvisionerKeyInput, InsertTaskInput, InsertWorkspaceAppStatusInput, LoginType,
    MinimalOrganization, MinimalUser, NotificationMessageRecord, NotificationMessageStatus,
    NotificationMethod, OAuth2ProviderAppCodeRecord, OAuth2ProviderAppRecord,
    OAuth2ProviderAppSecretRecord, OAuth2ProviderAppTokenRecord, OrganizationMemberListFilter,
    OrganizationMemberRecord, OrganizationRecord, PasswordUserRecord, PersistAuditLogInput,
    ProvisionerDaemonHealthInput, ProvisionerDaemonHealthRecord, ProvisionerDaemonRecord,
    ProvisionerJobLogRecord, ProvisionerJobRecord, ProvisionerJobStatsInput, ProvisionerJobStatus,
    ProvisionerJobTimingRecord, ProvisionerJobTimingStage, ProvisionerJobType,
    ProvisionerKeyRecord, ProvisionerStorageMethod, ProvisionerStore, ProvisionerType,
    SessionCountDeploymentStatsResponse, SlimRoleRecord, StorageError, TaskListFilter, TaskRecord,
    TaskSnapshotRecord, TaskStatus, TokenConfigRecord, UpdateOAuth2ProviderAppInput,
    UpsertCustomRoleInput, UpsertExternalAuthLinkInput, UpsertPortShareInput,
    UpsertProvisionerDaemonInput, UpsertUserLinkInput, UserAppearanceRecord, UserConfigRecord,
    UserDeletedRecord, UserLinkRecord, UserListFilter, UserPreferenceRecord, UserRecord,
    UserStatus, UserStatusChangeRecord, WebpushSubscriptionRecord, WorkspaceAgentDevcontainerRow,
    WorkspaceAgentLogRow, WorkspaceAgentLogSourceRow, WorkspaceAgentMetadataRow,
    WorkspaceAgentPortShareRecord, WorkspaceAgentRow, WorkspaceAgentScriptRow,
    WorkspaceAgentScriptTimingRow, WorkspaceAgentStatInput, WorkspaceAppRow, WorkspaceAppStatusRow,
    WorkspaceBuildParameterRecord, WorkspaceBuildRecord, WorkspaceBuildStatsInput,
    WorkspaceConnectionLatencyMs, WorkspaceDeploymentStatsResponse, WorkspaceListFilter,
    WorkspaceProxyHealthInput, WorkspaceProxyHealthRecord, WorkspaceRecord,
    WorkspaceResourceMetadataRecord, WorkspaceResourceRecord, WorkspaceStatsWorkspaceInput,
};
use coder_core::{
    InboxNotification, InboxNotificationAction, NotificationPreference, NotificationTemplate,
    NotificationsSettings,
};
use serde_json::{Value, from_str};
use sqlx::{FromRow, PgPool, Postgres, Transaction, postgres::PgPoolOptions};
use thiserror::Error;
use time::OffsetDateTime;
use tracing::instrument;
use uuid::Uuid;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

const REGULAR_MAX_TOKEN_LIFETIME_SECS: u64 = 60 * 60 * 24 * 30;
const OWNER_MAX_TOKEN_LIFETIME_SECS: u64 = 60 * 60 * 24 * 365;

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
    #[error("run database migrations: {source}")]
    Migrate {
        /// Wrapped migration error.
        #[source]
        source: sqlx::migrate::MigrateError,
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
struct StoredChatFileRow {
    id: Uuid,
    owner_id: Uuid,
    organization_id: Uuid,
    created_at: OffsetDateTime,
    name: String,
    mimetype: String,
    data: Vec<u8>,
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
    created_by: Uuid,
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
        MIGRATOR
            .run(&self.pool)
            .await
            .map_err(|source| DatabaseInitError::Migrate { source })
    }
}

#[async_trait]
impl DeploymentStore for PostgresStore {
    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn ping(&self) -> Result<(), StorageError> {
        sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .map(|_| ())
            .map_err(storage_error)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn ensure_deployment_metadata(&self) -> Result<DeploymentMetadata, StorageError> {
        let candidate = Uuid::new_v4();

        sqlx::query(
            "INSERT INTO site_configs (key, value)
             VALUES ('deployment_id', $1)
             ON CONFLICT (key) DO NOTHING",
        )
        .bind(candidate.to_string())
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        let stored: String =
            sqlx::query_scalar("SELECT value FROM site_configs WHERE key = 'deployment_id'")
                .fetch_one(&self.pool)
                .await
                .map_err(storage_error)?;

        let deployment_id = Uuid::parse_str(&stored).map_err(|error| {
            StorageError::invalid_data(format!(
                "site_configs.deployment_id must be a UUID: {error}"
            ))
        })?;

        Ok(DeploymentMetadata { deployment_id })
    }
}

#[async_trait]
impl AppStore for PostgresStore {
    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn first_user_exists(&self) -> Result<bool, StorageError> {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(
                SELECT 1
                FROM users
                WHERE deleted = false AND is_system = false
            )",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)
    }

    #[instrument(skip(self, user), err(level = tracing::Level::WARN))]
    async fn create_first_user(
        &self,
        user: CreateFirstUserInput,
    ) -> Result<FirstUserRecord, CreateFirstUserStoreError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(storage_error)
            .map_err(CreateFirstUserStoreError::from)?;

        let existing_user_id: Option<Uuid> = sqlx::query_scalar(
            "SELECT id
             FROM users
             WHERE deleted = false AND is_system = false
             LIMIT 1",
        )
        .fetch_optional(&mut *transaction)
        .await
        .map_err(storage_error)
        .map_err(CreateFirstUserStoreError::from)?;

        if existing_user_id.is_some() {
            return Err(CreateFirstUserStoreError::AlreadyExists);
        }

        let organization_id = ensure_default_organization(&mut transaction)
            .await
            .map_err(CreateFirstUserStoreError::from)?;
        let user_id = Uuid::new_v4();

        sqlx::query(
            "INSERT INTO users (
                id,
                email,
                username,
                name,
                hashed_password,
                created_at,
                updated_at,
                rbac_roles,
                login_type,
                status
            )
            VALUES (
                $1,
                $2,
                $3,
                $4,
                $5,
                NOW(),
                NOW(),
                ARRAY['owner']::text[],
                'password'::login_type,
                'active'::user_status
            )",
        )
        .bind(user_id)
        .bind(&user.email)
        .bind(&user.username)
        .bind(&user.name)
        .bind(user.password_hash.as_bytes())
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)
        .map_err(CreateFirstUserStoreError::from)?;

        sqlx::query(
            "INSERT INTO organization_members (
                organization_id,
                user_id,
                created_at,
                updated_at,
                roles
            )
            VALUES ($1, $2, NOW(), NOW(), ARRAY[]::text[])",
        )
        .bind(organization_id)
        .bind(user_id)
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)
        .map_err(CreateFirstUserStoreError::from)?;

        transaction
            .commit()
            .await
            .map_err(storage_error)
            .map_err(CreateFirstUserStoreError::from)?;

        Ok(FirstUserRecord {
            user_id,
            organization_id,
        })
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_password_user_by_email(
        &self,
        email: &str,
    ) -> Result<Option<PasswordUserRecord>, StorageError> {
        sqlx::query_as::<_, StoredPasswordUserRow>(
            "SELECT
                u.id,
                u.email,
                u.username,
                u.name,
                u.avatar_url,
                u.created_at,
                u.updated_at,
                u.last_seen_at,
                u.hashed_password,
                u.hashed_one_time_passcode,
                u.one_time_passcode_expires_at,
                u.login_type::text AS login_type,
                u.status::text AS status,
                u.deleted,
                u.is_system,
                COALESCE(
                    array_agg(DISTINCT om.organization_id) FILTER (WHERE om.organization_id IS NOT NULL),
                    ARRAY[]::uuid[]
                ) AS organization_ids,
                COALESCE(u.rbac_roles, ARRAY[]::text[]) AS global_roles
             FROM users u
             LEFT JOIN organization_members om ON om.user_id = u.id
             WHERE LOWER(u.email) = LOWER($1)
               AND u.deleted = false
             GROUP BY u.id",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?
        .map(password_record_from_row)
        .transpose()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_password_user_by_id(
        &self,
        user_id: Uuid,
    ) -> Result<Option<PasswordUserRecord>, StorageError> {
        sqlx::query_as::<_, StoredPasswordUserRow>(
            "SELECT
                u.id,
                u.email,
                u.username,
                u.name,
                u.avatar_url,
                u.created_at,
                u.updated_at,
                u.last_seen_at,
                u.hashed_password,
                u.hashed_one_time_passcode,
                u.one_time_passcode_expires_at,
                u.login_type::text AS login_type,
                u.status::text AS status,
                u.deleted,
                u.is_system,
                COALESCE(
                    array_agg(DISTINCT om.organization_id) FILTER (WHERE om.organization_id IS NOT NULL),
                    ARRAY[]::uuid[]
                ) AS organization_ids,
                COALESCE(u.rbac_roles, ARRAY[]::text[]) AS global_roles
             FROM users u
             LEFT JOIN organization_members om ON om.user_id = u.id
             WHERE u.id = $1
               AND u.deleted = false
             GROUP BY u.id",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?
        .map(password_record_from_row)
        .transpose()
    }

    #[instrument(skip(self, token_hash), err(level = tracing::Level::WARN))]
    async fn insert_auth_session(
        &self,
        token_hash: &[u8],
        user_id: Uuid,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO auth_sessions (token_hash, user_id, created_at, last_used_at)
             VALUES ($1, $2, NOW(), NOW())",
        )
        .bind(token_hash)
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(storage_error)
    }

    #[instrument(skip(self, token_hash), err(level = tracing::Level::WARN))]
    async fn find_user_by_session_token_hash(
        &self,
        token_hash: &[u8],
    ) -> Result<Option<AuthenticatedUser>, StorageError> {
        let row = sqlx::query_as::<_, StoredUserRow>(
            "SELECT
                u.id,
                u.email,
                u.username,
                u.name,
                u.avatar_url,
                u.created_at,
                u.updated_at,
                u.last_seen_at,
                u.login_type::text AS login_type,
                u.status::text AS status,
                u.deleted,
                u.is_system,
                COALESCE(
                    array_agg(DISTINCT om.organization_id) FILTER (WHERE om.organization_id IS NOT NULL),
                    ARRAY[]::uuid[]
                ) AS organization_ids,
                COALESCE(u.rbac_roles, ARRAY[]::text[]) AS global_roles
             FROM auth_sessions s
             INNER JOIN users u ON u.id = s.user_id
             LEFT JOIN organization_members om ON om.user_id = u.id
             WHERE s.token_hash = $1
               AND u.deleted = false
             GROUP BY u.id",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        let Some(row) = row else {
            return Ok(None);
        };

        let user_id = row.id;
        let user_record = user_record_from_row(row)?;
        let mut auth_user = AuthenticatedUser::from(user_record);

        // Fetch organization-scoped roles in "role_name:org_id" format.
        let org_roles: Vec<String> = sqlx::query_scalar(
            "SELECT role_name || ':' || sub_om.organization_id::text
             FROM organization_members sub_om
             CROSS JOIN LATERAL unnest(sub_om.roles) AS role_name
             WHERE sub_om.user_id = $1",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        auth_user.org_roles = org_roles;
        Ok(Some(auth_user))
    }

    #[instrument(skip(self, token_hash), err(level = tracing::Level::WARN))]
    async fn delete_auth_session(&self, token_hash: &[u8]) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM auth_sessions WHERE token_hash = $1")
            .bind(token_hash)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;

        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_users(
        &self,
        filter: UserListFilter,
    ) -> Result<(Vec<UserRecord>, usize), StorageError> {
        let search = (!filter.search.trim().is_empty())
            .then(|| format!("%{}%", filter.search.trim().replace('%', "\\%")));
        let status = filter.status.map(|value| value.as_str().to_owned());

        let total = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*)
             FROM users u
             WHERE u.deleted = false
               AND (
                    $1::text IS NULL
                    OR u.username ILIKE $1
                    OR u.email ILIKE $1
                    OR u.name ILIKE $1
               )
               AND ($2::text IS NULL OR u.status::text = $2)",
        )
        .bind(search.clone())
        .bind(status.clone())
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        let rows = sqlx::query_as::<_, StoredUserRow>(
            "SELECT
                u.id,
                u.email,
                u.username,
                u.name,
                u.avatar_url,
                u.created_at,
                u.updated_at,
                u.last_seen_at,
                u.login_type::text AS login_type,
                u.status::text AS status,
                u.deleted,
                u.is_system,
                COALESCE(
                    array_agg(DISTINCT om.organization_id) FILTER (WHERE om.organization_id IS NOT NULL),
                    ARRAY[]::uuid[]
                ) AS organization_ids,
                COALESCE(u.rbac_roles, ARRAY[]::text[]) AS global_roles
             FROM users u
             LEFT JOIN organization_members om ON om.user_id = u.id
             WHERE u.deleted = false
               AND (
                    $1::text IS NULL
                    OR u.username ILIKE $1
                    OR u.email ILIKE $1
                    OR u.name ILIKE $1
               )
               AND ($2::text IS NULL OR u.status::text = $2)
             GROUP BY u.id
             ORDER BY LOWER(u.username) ASC
             OFFSET $3
             LIMIT NULLIF($4::int, 0)",
        )
        .bind(search)
        .bind(status)
        .bind(i64::from(filter.offset))
        .bind(i64::from(filter.limit))
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        let users = rows
            .into_iter()
            .map(user_record_from_row)
            .collect::<Result<Vec<_>, _>>()?;

        Ok((
            users,
            usize::try_from(total)
                .map_err(|error| StorageError::invalid_data(error.to_string()))?,
        ))
    }

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn create_user(
        &self,
        input: CreateUserInput,
    ) -> Result<UserRecord, CreateUserStoreError> {
        let CreateUserInput {
            email,
            username,
            name,
            password_hash,
            login_type,
            status,
            organization_ids,
        } = input;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(storage_error)
            .map_err(CreateUserStoreError::from)?;
        let user_id = Uuid::new_v4();

        let result = sqlx::query(
            "INSERT INTO users (
                id,
                email,
                username,
                name,
                hashed_password,
                created_at,
                updated_at,
                rbac_roles,
                login_type,
                status
             ) VALUES (
                $1,
                $2,
                $3,
                $4,
                $5,
                NOW(),
                NOW(),
                ARRAY[]::text[],
                $6::login_type,
                $7::user_status
             )",
        )
        .bind(user_id)
        .bind(&email)
        .bind(&username)
        .bind(&name)
        .bind(password_hash.unwrap_or_default().into_bytes())
        .bind(login_type.as_str())
        .bind(status.as_str())
        .execute(&mut *transaction)
        .await;

        match result {
            Ok(_) => {}
            Err(error) if is_unique_violation(&error) => {
                return Err(CreateUserStoreError::AlreadyExists);
            }
            Err(error) => return Err(CreateUserStoreError::from(storage_error(error))),
        }

        for organization_id in &organization_ids {
            sqlx::query(
                "INSERT INTO organization_members (
                    organization_id,
                    user_id,
                    created_at,
                    updated_at,
                    roles
                 ) VALUES ($1, $2, NOW(), NOW(), ARRAY[]::text[])",
            )
            .bind(*organization_id)
            .bind(user_id)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)
            .map_err(CreateUserStoreError::from)?;
        }

        transaction
            .commit()
            .await
            .map_err(storage_error)
            .map_err(CreateUserStoreError::from)?;

        self.find_user_by_id(user_id)
            .await
            .map_err(CreateUserStoreError::from)?
            .ok_or_else(|| {
                CreateUserStoreError::from(StorageError::invalid_data(
                    "inserted user could not be reloaded",
                ))
            })
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_user_by_id(&self, user_id: Uuid) -> Result<Option<UserRecord>, StorageError> {
        sqlx::query_as::<_, StoredUserRow>(
            "SELECT
                u.id,
                u.email,
                u.username,
                u.name,
                u.avatar_url,
                u.created_at,
                u.updated_at,
                u.last_seen_at,
                u.login_type::text AS login_type,
                u.status::text AS status,
                u.deleted,
                u.is_system,
                COALESCE(
                    array_agg(DISTINCT om.organization_id) FILTER (WHERE om.organization_id IS NOT NULL),
                    ARRAY[]::uuid[]
                ) AS organization_ids,
                COALESCE(u.rbac_roles, ARRAY[]::text[]) AS global_roles
             FROM users u
             LEFT JOIN organization_members om ON om.user_id = u.id
             WHERE u.id = $1 AND u.deleted = false
             GROUP BY u.id",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?
        .map(user_record_from_row)
        .transpose()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_user_by_username(
        &self,
        username: &str,
    ) -> Result<Option<UserRecord>, StorageError> {
        sqlx::query_as::<_, StoredUserRow>(
            "SELECT
                u.id,
                u.email,
                u.username,
                u.name,
                u.avatar_url,
                u.created_at,
                u.updated_at,
                u.last_seen_at,
                u.login_type::text AS login_type,
                u.status::text AS status,
                u.deleted,
                u.is_system,
                COALESCE(
                    array_agg(DISTINCT om.organization_id) FILTER (WHERE om.organization_id IS NOT NULL),
                    ARRAY[]::uuid[]
                ) AS organization_ids,
                COALESCE(u.rbac_roles, ARRAY[]::text[]) AS global_roles
             FROM users u
             LEFT JOIN organization_members om ON om.user_id = u.id
             WHERE LOWER(u.username) = LOWER($1) AND u.deleted = false
             GROUP BY u.id",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?
        .map(user_record_from_row)
        .transpose()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn soft_delete_user(&self, user_id: Uuid) -> Result<bool, StorageError> {
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        let result = sqlx::query(
            "UPDATE users
             SET deleted = true, status = 'suspended'::user_status, updated_at = NOW()
             WHERE id = $1 AND deleted = false",
        )
        .bind(user_id)
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;

        if result.rows_affected() == 0 {
            transaction.rollback().await.map_err(storage_error)?;
            return Ok(false);
        }

        sqlx::query("DELETE FROM auth_sessions WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;

        sqlx::query("DELETE FROM api_keys WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;

        transaction.commit().await.map_err(storage_error)?;
        Ok(true)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_user_memberships(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<OrganizationMemberRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredOrganizationMemberRow>(
            "SELECT
                om.user_id,
                om.organization_id,
                om.created_at,
                om.updated_at,
                om.roles,
                u.username,
                u.avatar_url,
                u.name,
                u.email,
                COALESCE(u.rbac_roles, ARRAY[]::text[]) AS global_roles
             FROM organization_members om
             INNER JOIN users u ON u.id = om.user_id
             WHERE om.user_id = $1
               AND u.deleted = false
             ORDER BY om.created_at ASC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        rows.into_iter()
            .map(organization_member_record_from_row)
            .collect()
    }

    #[instrument(skip(self, roles), err(level = tracing::Level::WARN))]
    async fn update_user_roles(
        &self,
        user_id: Uuid,
        roles: Vec<String>,
    ) -> Result<Option<UserRecord>, StorageError> {
        let result = sqlx::query(
            "UPDATE users
             SET rbac_roles = $2, updated_at = NOW()
             WHERE id = $1 AND deleted = false",
        )
        .bind(user_id)
        .bind(roles)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        if result.rows_affected() == 0 {
            return Ok(None);
        }

        self.find_user_by_id(user_id).await
    }

    #[instrument(skip(self, username, name), err(level = tracing::Level::WARN))]
    async fn update_user_profile(
        &self,
        user_id: Uuid,
        username: &str,
        name: &str,
    ) -> Result<Option<UserRecord>, StorageError> {
        let result = sqlx::query(
            "UPDATE users
             SET username = $2, name = $3, updated_at = NOW()
             WHERE id = $1 AND deleted = false",
        )
        .bind(user_id)
        .bind(username)
        .bind(name)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        if result.rows_affected() == 0 {
            return Ok(None);
        }

        self.find_user_by_id(user_id).await
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_user_status(
        &self,
        user_id: Uuid,
        status: UserStatus,
    ) -> Result<Option<UserRecord>, StorageError> {
        let result = sqlx::query(
            "UPDATE users
             SET status = $2::user_status, updated_at = NOW()
             WHERE id = $1 AND deleted = false",
        )
        .bind(user_id)
        .bind(status.as_str())
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        if result.rows_affected() == 0 {
            return Ok(None);
        }

        self.find_user_by_id(user_id).await
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn user_appearance(&self, user_id: Uuid) -> Result<UserAppearanceRecord, StorageError> {
        let row = sqlx::query_as::<_, StoredAppearanceRow>(
            "SELECT theme_preference, terminal_font
             FROM users
             WHERE id = $1 AND deleted = false",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?
        .ok_or_else(|| StorageError::invalid_data("user appearance target is missing"))?;

        Ok(UserAppearanceRecord {
            theme_preference: row.theme_preference,
            terminal_font: row.terminal_font,
        })
    }

    #[instrument(skip(self, theme_preference, terminal_font), err(level = tracing::Level::WARN))]
    async fn update_user_appearance(
        &self,
        user_id: Uuid,
        theme_preference: &str,
        terminal_font: &str,
    ) -> Result<Option<UserAppearanceRecord>, StorageError> {
        let row = sqlx::query_as::<_, StoredAppearanceRow>(
            "UPDATE users
             SET theme_preference = $2,
                 terminal_font = $3,
                 updated_at = NOW()
             WHERE id = $1
               AND deleted = false
             RETURNING theme_preference, terminal_font",
        )
        .bind(user_id)
        .bind(theme_preference)
        .bind(terminal_font)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(row.map(|row| UserAppearanceRecord {
            theme_preference: row.theme_preference,
            terminal_font: row.terminal_font,
        }))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn user_preferences(&self, user_id: Uuid) -> Result<UserPreferenceRecord, StorageError> {
        let row = sqlx::query_as::<_, StoredPreferenceRow>(
            "SELECT task_notification_alert_dismissed
             FROM users
             WHERE id = $1 AND deleted = false",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?
        .ok_or_else(|| StorageError::invalid_data("user preference target is missing"))?;

        Ok(UserPreferenceRecord {
            task_notification_alert_dismissed: row.task_notification_alert_dismissed,
        })
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_user_preferences(
        &self,
        user_id: Uuid,
        task_notification_alert_dismissed: bool,
    ) -> Result<Option<UserPreferenceRecord>, StorageError> {
        let row = sqlx::query_as::<_, StoredPreferenceRow>(
            "UPDATE users
             SET task_notification_alert_dismissed = $2,
                 updated_at = NOW()
             WHERE id = $1
               AND deleted = false
             RETURNING task_notification_alert_dismissed",
        )
        .bind(user_id)
        .bind(task_notification_alert_dismissed)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(row.map(|row| UserPreferenceRecord {
            task_notification_alert_dismissed: row.task_notification_alert_dismissed,
        }))
    }

    // ----- User identity supplements -----

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn upsert_user_link(
        &self,
        user_id: Uuid,
        input: &UpsertUserLinkInput,
    ) -> Result<UserLinkRecord, StorageError> {
        let row = sqlx::query_as::<_, StoredUserLinkRow>(
            "INSERT INTO user_links (
                user_id, login_type, linked_id,
                oauth_access_token, oauth_refresh_token, oauth_expiry, claims
             ) VALUES ($1, $2::login_type, $3, $4, $5, $6, $7)
             ON CONFLICT (user_id, login_type) DO UPDATE SET
                linked_id = EXCLUDED.linked_id,
                oauth_access_token = EXCLUDED.oauth_access_token,
                oauth_refresh_token = EXCLUDED.oauth_refresh_token,
                oauth_expiry = EXCLUDED.oauth_expiry,
                claims = EXCLUDED.claims
             RETURNING
                user_id,
                login_type::text AS login_type,
                linked_id,
                oauth_access_token,
                oauth_refresh_token,
                oauth_expiry,
                claims",
        )
        .bind(user_id)
        .bind(input.login_type.as_str())
        .bind(&input.linked_id)
        .bind(&input.oauth_access_token)
        .bind(&input.oauth_refresh_token)
        .bind(input.oauth_expiry)
        .bind(serde_json::to_value(&input.claims).unwrap_or_default())
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        user_link_record_from_row(row)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_user_link(
        &self,
        user_id: Uuid,
        login_type: LoginType,
    ) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "DELETE FROM user_links WHERE user_id = $1 AND login_type = $2::login_type",
        )
        .bind(user_id)
        .bind(login_type.as_str())
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_user_config(
        &self,
        user_id: Uuid,
        key: &str,
    ) -> Result<Option<UserConfigRecord>, StorageError> {
        let row = sqlx::query_as::<_, StoredUserConfigRow>(
            "SELECT user_id, key, value FROM user_configs WHERE user_id = $1 AND key = $2",
        )
        .bind(user_id)
        .bind(key)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(row.map(|r| UserConfigRecord {
            user_id: r.user_id,
            key: r.key,
            value: r.value,
        }))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn upsert_user_config(
        &self,
        user_id: Uuid,
        key: &str,
        value: &str,
    ) -> Result<UserConfigRecord, StorageError> {
        let row = sqlx::query_as::<_, StoredUserConfigRow>(
            "INSERT INTO user_configs (user_id, key, value)
             VALUES ($1, $2, $3)
             ON CONFLICT (user_id, key) DO UPDATE SET value = EXCLUDED.value
             RETURNING user_id, key, value",
        )
        .bind(user_id)
        .bind(key)
        .bind(value)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(UserConfigRecord {
            user_id: row.user_id,
            key: row.key,
            value: row.value,
        })
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_user_config(&self, user_id: Uuid, key: &str) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM user_configs WHERE user_id = $1 AND key = $2")
            .bind(user_id)
            .bind(key)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;

        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn insert_user_deleted(
        &self,
        user_id: Uuid,
        deleted_by: Option<Uuid>,
        reason: &str,
    ) -> Result<UserDeletedRecord, StorageError> {
        let row = sqlx::query_as::<_, StoredUserDeletedRow>(
            "INSERT INTO user_deleted (user_id, deleted_by, reason)
             VALUES ($1, $2, $3)
             RETURNING id, user_id, deleted_at, deleted_by, reason",
        )
        .bind(user_id)
        .bind(deleted_by)
        .bind(reason)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(UserDeletedRecord {
            id: row.id,
            user_id: row.user_id,
            deleted_at: row.deleted_at,
            deleted_by: row.deleted_by,
            reason: row.reason,
        })
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn insert_user_status_change(
        &self,
        user_id: Uuid,
        old_status: UserStatus,
        new_status: UserStatus,
        changed_by: Option<Uuid>,
        reason: &str,
    ) -> Result<UserStatusChangeRecord, StorageError> {
        let row = sqlx::query_as::<_, StoredUserStatusChangeRow>(
            "INSERT INTO user_status_changes (user_id, old_status, new_status, changed_by, reason)
             VALUES ($1, $2::user_status, $3::user_status, $4, $5)
             RETURNING id, user_id, new_status::text AS new_status, old_status::text AS old_status, changed_at, changed_by, reason",
        )
        .bind(user_id)
        .bind(old_status.as_str())
        .bind(new_status.as_str())
        .bind(changed_by)
        .bind(reason)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        user_status_change_record_from_row(row)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_custom_role(
        &self,
        name: &str,
        organization_id: Option<Uuid>,
    ) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "DELETE FROM custom_roles WHERE name = lower($1) AND organization_id IS NOT DISTINCT FROM $2",
        )
        .bind(name)
        .bind(organization_id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_user_links(&self, user_id: Uuid) -> Result<Vec<UserLinkRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredUserLinkRow>(
            "SELECT
                user_id,
                login_type::text AS login_type,
                linked_id,
                oauth_access_token,
                oauth_refresh_token,
                oauth_expiry,
                claims
             FROM user_links
             WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        rows.into_iter().map(user_link_record_from_row).collect()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_user_status_changes(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<UserStatusChangeRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredUserStatusChangeRow>(
            "SELECT
                id,
                user_id,
                new_status::text AS new_status,
                old_status::text AS old_status,
                changed_at,
                changed_by,
                reason
             FROM user_status_changes
             WHERE user_id = $1
             ORDER BY changed_at ASC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        rows.into_iter()
            .map(user_status_change_record_from_row)
            .collect()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_organizations(
        &self,
        organization_ids: Vec<Uuid>,
    ) -> Result<Vec<OrganizationRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredOrganizationRow>(
            "SELECT
                id,
                name,
                display_name,
                description,
                icon,
                created_at,
                updated_at,
                is_default,
                deleted
             FROM organizations
             WHERE deleted = false
               AND (
                    COALESCE(array_length($1::uuid[], 1), 0) = 0
                    OR id = ANY($1)
               )
             ORDER BY LOWER(name) ASC",
        )
        .bind(organization_ids)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        rows.into_iter()
            .map(organization_record_from_row)
            .collect::<Result<Vec<_>, _>>()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_organization_by_id(
        &self,
        organization_id: Uuid,
    ) -> Result<Option<OrganizationRecord>, StorageError> {
        sqlx::query_as::<_, StoredOrganizationRow>(
            "SELECT
                id,
                name,
                display_name,
                description,
                icon,
                created_at,
                updated_at,
                is_default,
                deleted
             FROM organizations
             WHERE id = $1 AND deleted = false",
        )
        .bind(organization_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?
        .map(organization_record_from_row)
        .transpose()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_organization_by_name(
        &self,
        name: &str,
    ) -> Result<Option<OrganizationRecord>, StorageError> {
        sqlx::query_as::<_, StoredOrganizationRow>(
            "SELECT
                id,
                name,
                display_name,
                description,
                icon,
                created_at,
                updated_at,
                is_default,
                deleted
             FROM organizations
             WHERE LOWER(name) = LOWER($1) AND deleted = false",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?
        .map(organization_record_from_row)
        .transpose()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_organization_members(
        &self,
        filter: OrganizationMemberListFilter,
    ) -> Result<Vec<OrganizationMemberRecord>, StorageError> {
        let search = (!filter.search.trim().is_empty())
            .then(|| format!("%{}%", filter.search.trim().replace('%', "\\%")));

        let rows = sqlx::query_as::<_, StoredOrganizationMemberRow>(
            "SELECT
                om.user_id,
                om.organization_id,
                om.created_at,
                om.updated_at,
                om.roles,
                u.username,
                u.avatar_url,
                u.name,
                u.email,
                COALESCE(u.rbac_roles, ARRAY[]::text[]) AS global_roles
             FROM organization_members om
             INNER JOIN users u ON u.id = om.user_id
             WHERE om.organization_id = $1
               AND u.deleted = false
               AND (
                    $2::text IS NULL
                    OR u.username ILIKE $2
                    OR u.email ILIKE $2
                    OR u.name ILIKE $2
               )
             ORDER BY LOWER(u.username) ASC
             OFFSET $3
             LIMIT NULLIF($4::int, 0)",
        )
        .bind(filter.organization_id)
        .bind(search)
        .bind(i64::from(filter.offset))
        .bind(i64::from(filter.limit))
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        rows.into_iter()
            .map(organization_member_record_from_row)
            .collect()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_organization_members_page(
        &self,
        filter: OrganizationMemberListFilter,
    ) -> Result<(Vec<OrganizationMemberRecord>, usize), StorageError> {
        let search = (!filter.search.trim().is_empty())
            .then(|| format!("%{}%", filter.search.trim().replace('%', "\\%")));

        let total = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*)
             FROM organization_members om
             INNER JOIN users u ON u.id = om.user_id
             WHERE om.organization_id = $1
               AND u.deleted = false
               AND (
                    $2::text IS NULL
                    OR u.username ILIKE $2
                    OR u.email ILIKE $2
                    OR u.name ILIKE $2
               )",
        )
        .bind(filter.organization_id)
        .bind(search)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        let members = self.list_organization_members(filter).await?;
        let total = usize::try_from(total)
            .map_err(|error| StorageError::invalid_data(error.to_string()))?;

        Ok((members, total))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_organization_member(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<OrganizationMemberRecord>, StorageError> {
        sqlx::query_as::<_, StoredOrganizationMemberRow>(
            "SELECT
                om.user_id,
                om.organization_id,
                om.created_at,
                om.updated_at,
                om.roles,
                u.username,
                u.avatar_url,
                u.name,
                u.email,
                COALESCE(u.rbac_roles, ARRAY[]::text[]) AS global_roles
             FROM organization_members om
             INNER JOIN users u ON u.id = om.user_id
             WHERE om.organization_id = $1
               AND om.user_id = $2
               AND u.deleted = false",
        )
        .bind(organization_id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?
        .map(organization_member_record_from_row)
        .transpose()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn insert_organization_member(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> Result<OrganizationMemberRecord, InsertOrganizationMemberError> {
        let result = sqlx::query(
            "INSERT INTO organization_members (
                organization_id,
                user_id,
                created_at,
                updated_at,
                roles
             ) VALUES ($1, $2, NOW(), NOW(), ARRAY[]::text[])",
        )
        .bind(organization_id)
        .bind(user_id)
        .execute(&self.pool)
        .await;

        match result {
            Ok(_) => self
                .find_organization_member(organization_id, user_id)
                .await
                .map_err(InsertOrganizationMemberError::from)?
                .ok_or_else(|| {
                    InsertOrganizationMemberError::from(StorageError::invalid_data(
                        "inserted organization member could not be reloaded",
                    ))
                }),
            Err(error) if is_unique_violation(&error) => {
                Err(InsertOrganizationMemberError::AlreadyExists)
            }
            Err(error) => Err(InsertOrganizationMemberError::from(storage_error(error))),
        }
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_organization_member(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "DELETE FROM organization_members
             WHERE organization_id = $1 AND user_id = $2",
        )
        .bind(organization_id)
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self, roles), err(level = tracing::Level::WARN))]
    async fn update_organization_member_roles(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
        roles: Vec<String>,
    ) -> Result<Option<OrganizationMemberRecord>, StorageError> {
        let result = sqlx::query(
            "UPDATE organization_members
             SET roles = $3, updated_at = NOW()
             WHERE organization_id = $1 AND user_id = $2",
        )
        .bind(organization_id)
        .bind(user_id)
        .bind(roles)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        if result.rows_affected() == 0 {
            return Ok(None);
        }

        self.find_organization_member(organization_id, user_id)
            .await
    }

    #[instrument(skip(self, passcode_hash), err(level = tracing::Level::WARN))]
    async fn store_one_time_passcode_by_email(
        &self,
        email: &str,
        passcode_hash: &str,
        expires_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "UPDATE users
             SET hashed_one_time_passcode = $2,
                 one_time_passcode_expires_at = $3,
                 updated_at = NOW()
             WHERE LOWER(email) = LOWER($1)
               AND deleted = false
               AND login_type = 'password'::login_type",
        )
        .bind(email)
        .bind(passcode_hash.as_bytes())
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(storage_error)
    }

    #[instrument(skip(self, password_hash), err(level = tracing::Level::WARN))]
    async fn replace_user_password(
        &self,
        user_id: Uuid,
        password_hash: &str,
        clear_one_time_passcode: bool,
    ) -> Result<bool, StorageError> {
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        let result = sqlx::query(
            "UPDATE users
             SET hashed_password = $2,
                 hashed_one_time_passcode = CASE
                     WHEN $3 THEN ''::bytea
                     ELSE hashed_one_time_passcode
                 END,
                 one_time_passcode_expires_at = CASE
                     WHEN $3 THEN NULL
                     ELSE one_time_passcode_expires_at
                 END,
                 updated_at = NOW()
             WHERE id = $1
               AND deleted = false",
        )
        .bind(user_id)
        .bind(password_hash.as_bytes())
        .bind(clear_one_time_passcode)
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;

        if result.rows_affected() == 0 {
            transaction.rollback().await.map_err(storage_error)?;
            return Ok(false);
        }

        sqlx::query("DELETE FROM auth_sessions WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;

        sqlx::query("DELETE FROM api_keys WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;

        transaction.commit().await.map_err(storage_error)?;
        Ok(true)
    }

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn create_api_key(
        &self,
        input: CreateApiKeyInput,
    ) -> Result<ApiKeyRecord, CreateApiKeyStoreError> {
        let result = sqlx::query(
            "INSERT INTO api_keys (
                id,
                hashed_secret,
                user_id,
                last_used,
                expires_at,
                created_at,
                updated_at,
                login_type,
                scopes,
                token_name,
                lifetime_seconds,
                allow_list_json
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::login_type, $9, $10, $11, $12)",
        )
        .bind(&input.id)
        .bind(&input.hashed_secret)
        .bind(input.user_id)
        .bind(input.last_used)
        .bind(input.expires_at)
        .bind(input.created_at)
        .bind(input.updated_at)
        .bind(input.login_type.as_str())
        .bind(&input.scopes)
        .bind(&input.token_name)
        .bind(input.lifetime_seconds)
        .bind(serde_json::to_string(&input.allow_list).map_err(|error| {
            CreateApiKeyStoreError::from(StorageError::invalid_data(error.to_string()))
        })?)
        .execute(&self.pool)
        .await;

        match result {
            Ok(_) => self
                .find_api_key_by_id(&input.id)
                .await
                .map_err(CreateApiKeyStoreError::from)?
                .ok_or_else(|| {
                    CreateApiKeyStoreError::from(StorageError::invalid_data(
                        "inserted API key could not be reloaded",
                    ))
                }),
            Err(error) if is_unique_violation(&error) => {
                Err(CreateApiKeyStoreError::DuplicateTokenName)
            }
            Err(error) => Err(CreateApiKeyStoreError::from(storage_error(error))),
        }
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_api_key_by_id(&self, id: &str) -> Result<Option<ApiKeyRecord>, StorageError> {
        sqlx::query_as::<_, StoredApiKeyRow>(
            "SELECT
                id,
                hashed_secret,
                user_id,
                last_used,
                expires_at,
                created_at,
                updated_at,
                login_type::text AS login_type,
                scopes,
                token_name,
                lifetime_seconds,
                allow_list_json,
                NULL::text AS username
             FROM api_keys
             WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?
        .map(api_key_record_from_row)
        .transpose()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_api_key_by_name(
        &self,
        user_id: Uuid,
        token_name: &str,
    ) -> Result<Option<ApiKeyRecord>, StorageError> {
        sqlx::query_as::<_, StoredApiKeyRow>(
            "SELECT
                id,
                hashed_secret,
                user_id,
                last_used,
                expires_at,
                created_at,
                updated_at,
                login_type::text AS login_type,
                scopes,
                token_name,
                lifetime_seconds,
                allow_list_json,
                NULL::text AS username
             FROM api_keys
             WHERE user_id = $1
               AND token_name = $2
               AND token_name <> ''",
        )
        .bind(user_id)
        .bind(token_name)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?
        .map(api_key_record_from_row)
        .transpose()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_api_keys(
        &self,
        filter: ApiKeyListFilter,
    ) -> Result<Vec<ApiKeyWithOwnerRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredApiKeyRow>(
            "SELECT
                k.id,
                k.hashed_secret,
                k.user_id,
                k.last_used,
                k.expires_at,
                k.created_at,
                k.updated_at,
                k.login_type::text AS login_type,
                k.scopes,
                k.token_name,
                k.lifetime_seconds,
                k.allow_list_json,
                u.username
             FROM api_keys k
             INNER JOIN users u ON u.id = k.user_id
             WHERE k.login_type::text = $1
               AND ($2::uuid IS NULL OR k.user_id = $2)
               AND ($3::bool OR k.expires_at > NOW())
             ORDER BY LOWER(u.username) ASC, k.created_at DESC",
        )
        .bind(filter.login_type.as_str())
        .bind(filter.user_id)
        .bind(filter.include_expired)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        rows.into_iter()
            .map(|row| {
                let username = row.username.clone().unwrap_or_default();
                Ok(ApiKeyWithOwnerRecord {
                    key: api_key_record_from_row(row)?,
                    username,
                })
            })
            .collect()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_api_key(&self, id: &str) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM api_keys WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;

        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn expire_api_key(&self, id: &str, now: OffsetDateTime) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "UPDATE api_keys
             SET expires_at = $2, updated_at = $2
             WHERE id = $1",
        )
        .bind(id)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn token_config(&self, user_id: Uuid) -> Result<TokenConfigRecord, StorageError> {
        let is_owner = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(
                SELECT 1
                FROM users
                WHERE id = $1
                  AND 'owner' = ANY(rbac_roles)
                  AND deleted = false
            )",
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        let max_token_lifetime = if is_owner {
            Duration::from_secs(OWNER_MAX_TOKEN_LIFETIME_SECS)
        } else {
            Duration::from_secs(REGULAR_MAX_TOKEN_LIFETIME_SECS)
        };

        Ok(TokenConfigRecord { max_token_lifetime })
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_audit_logs(
        &self,
        filter: AuditLogListFilter,
    ) -> Result<AuditLogResponse, StorageError> {
        let search = filter.search.trim().to_owned();
        let search_pattern = format!("%{search}%");
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*)
             FROM audit_logs al
             LEFT JOIN users u ON u.id = al.user_id
             WHERE $1 = ''
                OR al.description ILIKE $2
                OR al.resource_target ILIKE $2
                OR COALESCE(u.username, '') ILIKE $2",
        )
        .bind(&search)
        .bind(&search_pattern)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        let rows = sqlx::query_as::<_, StoredAuditLogRow>(
            "SELECT
                al.id,
                al.request_id,
                al.time,
                al.ip,
                al.user_agent,
                al.resource_type,
                al.resource_id,
                al.resource_target,
                al.resource_icon,
                al.action,
                al.diff_json,
                al.status_code,
                al.additional_fields_json,
                al.description,
                al.resource_link,
                al.is_deleted,
                al.organization_id,
                o.name AS organization_name,
                o.display_name AS organization_display_name,
                o.icon AS organization_icon,
                al.user_id,
                u.username,
                u.name,
                u.avatar_url
             FROM audit_logs al
             LEFT JOIN organizations o ON o.id = al.organization_id
             LEFT JOIN users u ON u.id = al.user_id
             WHERE $1 = ''
                OR al.description ILIKE $2
                OR al.resource_target ILIKE $2
                OR COALESCE(u.username, '') ILIKE $2
             ORDER BY al.time DESC
             LIMIT $3
             OFFSET $4",
        )
        .bind(&search)
        .bind(&search_pattern)
        .bind(i64::from(filter.limit))
        .bind(i64::from(filter.offset))
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(AuditLogResponse {
            audit_logs: rows
                .into_iter()
                .map(audit_log_from_row)
                .collect::<Result<Vec<_>, _>>()?,
            count: usize::try_from(count)
                .map_err(|error| StorageError::invalid_data(error.to_string()))?,
        })
    }

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn insert_audit_log(&self, input: PersistAuditLogInput) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO audit_logs (
                id,
                request_id,
                time,
                ip,
                user_agent,
                resource_type,
                resource_id,
                resource_target,
                resource_icon,
                action,
                diff_json,
                status_code,
                additional_fields_json,
                description,
                resource_link,
                is_deleted,
                organization_id,
                user_id
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18
            )",
        )
        .bind(input.id)
        .bind(input.request_id)
        .bind(input.time)
        .bind(input.ip)
        .bind(input.user_agent)
        .bind(input.resource_type)
        .bind(input.resource_id)
        .bind(input.resource_target)
        .bind(input.resource_icon)
        .bind(input.action)
        .bind(input.diff.to_string())
        .bind(input.status_code)
        .bind(input.additional_fields.to_string())
        .bind(input.description)
        .bind(input.resource_link)
        .bind(input.is_deleted)
        .bind(input.organization_id)
        .bind(input.user_id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn health_settings(&self) -> Result<HealthSettings, StorageError> {
        let encoded: Option<String> = sqlx::query_scalar(
            "SELECT value
             FROM site_configs
             WHERE key = 'health_settings'",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        match encoded {
            Some(encoded) => {
                from_str(&encoded).map_err(|error| StorageError::invalid_data(error.to_string()))
            }
            None => Ok(HealthSettings::default()),
        }
    }

    #[instrument(skip(self, settings), err(level = tracing::Level::WARN))]
    async fn upsert_health_settings(
        &self,
        settings: &HealthSettings,
    ) -> Result<bool, StorageError> {
        let encoded = serde_json::to_string(settings)
            .map_err(|error| StorageError::invalid_data(error.to_string()))?;
        let current: Option<String> = sqlx::query_scalar(
            "SELECT value
             FROM site_configs
             WHERE key = 'health_settings'",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        if current.as_deref() == Some(encoded.as_str()) {
            return Ok(false);
        }

        sqlx::query(
            "INSERT INTO site_configs (key, value)
             VALUES ('health_settings', $1)
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(encoded)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(true)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn deployment_stats(&self) -> Result<DeploymentStatsResponse, StorageError> {
        let collected_at: OffsetDateTime = sqlx::query_scalar("SELECT NOW()")
            .fetch_one(&self.pool)
            .await
            .map_err(storage_error)?;
        let aggregated_from = collected_at - time::Duration::minutes(15);
        let next_update_at = collected_at + time::Duration::minutes(1);
        let workspace_stats = sqlx::query_as::<_, StoredDeploymentWorkspaceStatsRow>(
            "WITH workspaces_with_jobs AS (
                SELECT latest_build.*
                FROM workspaces
                LEFT JOIN LATERAL (
                    SELECT
                        workspace_builds.transition,
                        provisioner_jobs.id AS provisioner_job_id,
                        provisioner_jobs.started_at,
                        provisioner_jobs.updated_at,
                        provisioner_jobs.canceled_at,
                        provisioner_jobs.completed_at,
                        provisioner_jobs.error
                    FROM workspace_builds
                    LEFT JOIN provisioner_jobs
                        ON provisioner_jobs.id = workspace_builds.job_id
                    WHERE workspace_builds.workspace_id = workspaces.id
                    ORDER BY build_number DESC
                    LIMIT 1
                ) latest_build ON TRUE
                WHERE workspaces.deleted = FALSE
            ),
            pending_workspaces AS (
                SELECT COUNT(*)::bigint AS count
                FROM workspaces_with_jobs
                WHERE started_at IS NULL
            ),
            building_workspaces AS (
                SELECT COUNT(*)::bigint AS count
                FROM workspaces_with_jobs
                WHERE started_at IS NOT NULL
                    AND canceled_at IS NULL
                    AND completed_at IS NULL
                    AND updated_at - INTERVAL '30 seconds' < NOW()
            ),
            running_workspaces AS (
                SELECT COUNT(*)::bigint AS count
                FROM workspaces_with_jobs
                WHERE completed_at IS NOT NULL
                    AND canceled_at IS NULL
                    AND error = ''
                    AND transition = 'start'
            ),
            failed_workspaces AS (
                SELECT COUNT(*)::bigint AS count
                FROM workspaces_with_jobs
                WHERE (canceled_at IS NOT NULL AND error <> '')
                    OR (completed_at IS NOT NULL AND error <> '')
            ),
            stopped_workspaces AS (
                SELECT COUNT(*)::bigint AS count
                FROM workspaces_with_jobs
                WHERE completed_at IS NOT NULL
                    AND canceled_at IS NULL
                    AND error = ''
                    AND transition = 'stop'
            )
            SELECT
                pending_workspaces.count AS pending_workspaces,
                building_workspaces.count AS building_workspaces,
                running_workspaces.count AS running_workspaces,
                failed_workspaces.count AS failed_workspaces,
                stopped_workspaces.count AS stopped_workspaces
            FROM pending_workspaces,
                 building_workspaces,
                 running_workspaces,
                 failed_workspaces,
                 stopped_workspaces",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;
        let agent_stats = sqlx::query_as::<_, StoredDeploymentAgentStatsRow>(
            "WITH stats AS (
                SELECT
                    agent_id,
                    created_at,
                    rx_bytes,
                    tx_bytes,
                    connection_median_latency_ms,
                    session_count_vscode,
                    session_count_ssh,
                    session_count_jetbrains,
                    session_count_reconnecting_pty,
                    ROW_NUMBER() OVER (PARTITION BY agent_id ORDER BY created_at DESC) AS rn
                FROM workspace_agent_stats
                WHERE created_at > $1
            )
            SELECT
                COALESCE(SUM(rx_bytes), 0)::bigint AS workspace_rx_bytes,
                COALESCE(SUM(tx_bytes), 0)::bigint AS workspace_tx_bytes,
                COALESCE(
                    (
                        PERCENTILE_CONT(0.5) WITHIN GROUP (
                            ORDER BY connection_median_latency_ms
                        ) FILTER (WHERE connection_median_latency_ms > 0)
                    ),
                    -1
                )::float8 AS workspace_connection_latency_50,
                COALESCE(
                    (
                        PERCENTILE_CONT(0.95) WITHIN GROUP (
                            ORDER BY connection_median_latency_ms
                        ) FILTER (WHERE connection_median_latency_ms > 0)
                    ),
                    -1
                )::float8 AS workspace_connection_latency_95,
                COALESCE(SUM(session_count_vscode) FILTER (WHERE rn = 1), 0)::bigint
                    AS session_count_vscode,
                COALESCE(SUM(session_count_ssh) FILTER (WHERE rn = 1), 0)::bigint
                    AS session_count_ssh,
                COALESCE(SUM(session_count_jetbrains) FILTER (WHERE rn = 1), 0)::bigint
                    AS session_count_jetbrains,
                COALESCE(
                    SUM(session_count_reconnecting_pty) FILTER (WHERE rn = 1),
                    0
                )::bigint AS session_count_reconnecting_pty
            FROM stats",
        )
        .bind(aggregated_from)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(DeploymentStatsResponse {
            aggregated_from,
            collected_at,
            next_update_at,
            workspaces: WorkspaceDeploymentStatsResponse {
                pending: workspace_stats.pending_workspaces,
                building: workspace_stats.building_workspaces,
                running: workspace_stats.running_workspaces,
                failed: workspace_stats.failed_workspaces,
                stopped: workspace_stats.stopped_workspaces,
                connection_latency_ms: WorkspaceConnectionLatencyMs {
                    p50: agent_stats.workspace_connection_latency_50,
                    p95: agent_stats.workspace_connection_latency_95,
                },
                rx_bytes: agent_stats.workspace_rx_bytes,
                tx_bytes: agent_stats.workspace_tx_bytes,
            },
            session_count: SessionCountDeploymentStatsResponse {
                vscode: agent_stats.session_count_vscode,
                ssh: agent_stats.session_count_ssh,
                jetbrains: agent_stats.session_count_jetbrains,
                reconnecting_pty: agent_stats.session_count_reconnecting_pty,
            },
        })
    }

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn upsert_workspace_stats_workspace(
        &self,
        input: &WorkspaceStatsWorkspaceInput,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO workspaces (id, updated_at, deleted)
             VALUES ($1, NOW(), $2)
             ON CONFLICT (id) DO UPDATE SET
                updated_at = NOW(),
                deleted = EXCLUDED.deleted",
        )
        .bind(input.id)
        .bind(input.deleted)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn upsert_provisioner_job_stats(
        &self,
        input: &ProvisionerJobStatsInput,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO provisioner_jobs (
                id, created_at, updated_at, started_at, canceled_at, completed_at, error
             )
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (id) DO UPDATE SET
                updated_at = EXCLUDED.updated_at,
                started_at = EXCLUDED.started_at,
                canceled_at = EXCLUDED.canceled_at,
                completed_at = EXCLUDED.completed_at,
                error = EXCLUDED.error",
        )
        .bind(input.id)
        .bind(input.created_at)
        .bind(input.updated_at)
        .bind(input.started_at)
        .bind(input.canceled_at)
        .bind(input.completed_at)
        .bind(&input.error)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn upsert_workspace_build_stats(
        &self,
        input: &WorkspaceBuildStatsInput,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO workspace_builds (
                id, created_at, updated_at, workspace_id, build_number, transition, job_id
             )
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (id) DO UPDATE SET
                updated_at = EXCLUDED.updated_at,
                workspace_id = EXCLUDED.workspace_id,
                build_number = EXCLUDED.build_number,
                transition = EXCLUDED.transition,
                job_id = EXCLUDED.job_id",
        )
        .bind(input.id)
        .bind(input.created_at)
        .bind(input.updated_at)
        .bind(input.workspace_id)
        .bind(input.build_number)
        .bind(&input.transition)
        .bind(input.job_id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn insert_workspace_agent_stat(
        &self,
        input: &WorkspaceAgentStatInput,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO workspace_agent_stats (
                id,
                created_at,
                user_id,
                workspace_id,
                template_id,
                agent_id,
                connections_by_proto,
                connection_count,
                rx_packets,
                rx_bytes,
                tx_packets,
                tx_bytes,
                session_count_vscode,
                session_count_jetbrains,
                session_count_reconnecting_pty,
                session_count_ssh,
                connection_median_latency_ms,
                usage
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18
            )",
        )
        .bind(input.id)
        .bind(input.created_at)
        .bind(input.user_id)
        .bind(input.workspace_id)
        .bind(input.template_id)
        .bind(input.agent_id)
        .bind(&input.connections_by_proto)
        .bind(input.connection_count)
        .bind(input.rx_packets)
        .bind(input.rx_bytes)
        .bind(input.tx_packets)
        .bind(input.tx_bytes)
        .bind(input.session_count_vscode)
        .bind(input.session_count_jetbrains)
        .bind(input.session_count_reconnecting_pty)
        .bind(input.session_count_ssh)
        .bind(input.connection_median_latency_ms)
        .bind(input.usage)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_deployment_daus(&self, tz_offset: i32) -> Result<DAUsResponse, StorageError> {
        #[derive(sqlx::FromRow)]
        struct DauRow {
            date: time::Date,
            amount: i64,
        }

        // Build a proper Etc/GMT timezone string from the integer offset.
        // Etc/GMT sign convention is inverted: positive tz_offset → Etc/GMT-N.
        let tz_name = if tz_offset == 0 {
            "UTC".to_string()
        } else if tz_offset > 0 {
            format!("Etc/GMT-{tz_offset}")
        } else {
            format!("Etc/GMT+{}", tz_offset.abs())
        };

        let rows = sqlx::query_as::<_, DauRow>(
            "SELECT
                (created_at AT TIME ZONE $1)::date AS date,
                COUNT(DISTINCT user_id) AS amount
             FROM workspace_agent_stats
             WHERE connection_count > 0
               AND user_id IS NOT NULL
             GROUP BY date
             ORDER BY date ASC",
        )
        .bind(&tz_name)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        let entries = rows
            .into_iter()
            .map(|row| DAUEntry {
                date: row.date.to_string(),
                amount: row.amount,
            })
            .collect();

        Ok(DAUsResponse {
            tz_hour_offset: tz_offset,
            entries,
        })
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_user_status_counts(
        &self,
        timezone: &str,
        start_time: OffsetDateTime,
        end_time: OffsetDateTime,
    ) -> Result<GetUserStatusCountsResponse, StorageError> {
        #[derive(sqlx::FromRow)]
        struct StatusCountRow {
            date: OffsetDateTime,
            status: String,
            count: i64,
        }

        let rows = sqlx::query_as::<_, StatusCountRow>(
            r#"
            WITH
            system_users AS (
                SELECT id FROM users WHERE is_system = TRUE
            ),
            dates_of_interest AS (
                SELECT timezone($1::text, gs_local) AS date
                FROM generate_series(
                    timezone($1::text, $2::timestamptz),
                    timezone($1::text, $3::timestamptz),
                    interval '1 day'
                ) AS gs_local
            ),
            latest_status_before_range AS (
                SELECT
                    DISTINCT ON (usc.user_id)
                    usc.user_id,
                    usc.new_status,
                    usc.changed_at
                FROM user_status_changes usc
                LEFT JOIN LATERAL (
                    SELECT COUNT(*) > 0 AS deleted
                    FROM user_deleted ud
                    WHERE ud.user_id = usc.user_id
                      AND (ud.deleted_at < usc.changed_at OR ud.deleted_at < $2::timestamptz)
                ) AS ud ON true
                WHERE usc.user_id NOT IN (SELECT id FROM system_users)
                    AND NOT ud.deleted
                    AND usc.changed_at < $2::timestamptz
                ORDER BY usc.user_id, usc.changed_at DESC
            ),
            status_changes_during_range AS (
                SELECT
                    usc.user_id,
                    usc.new_status,
                    usc.changed_at
                FROM user_status_changes usc
                LEFT JOIN LATERAL (
                    SELECT COUNT(*) > 0 AS deleted
                    FROM user_deleted ud
                    WHERE ud.user_id = usc.user_id AND ud.deleted_at < usc.changed_at
                ) AS ud ON true
                WHERE usc.user_id NOT IN (SELECT id FROM system_users)
                    AND NOT ud.deleted
                    AND usc.changed_at >= $2::timestamptz
                    AND usc.changed_at <= $3::timestamptz
            ),
            relevant_status_changes AS (
                SELECT user_id, new_status, changed_at
                FROM latest_status_before_range
                UNION ALL
                SELECT user_id, new_status, changed_at
                FROM status_changes_during_range
            ),
            statuses AS (
                SELECT DISTINCT new_status FROM relevant_status_changes
            ),
            ranked_status_change_per_user_per_date AS (
                SELECT
                    d.date,
                    rsc1.user_id,
                    ROW_NUMBER() OVER (
                        PARTITION BY d.date, rsc1.user_id
                        ORDER BY rsc1.changed_at DESC
                    ) AS rn,
                    rsc1.new_status
                FROM dates_of_interest d
                LEFT JOIN relevant_status_changes rsc1 ON rsc1.changed_at <= d.date
            )
            SELECT
                rscpupd.date::timestamptz AS date,
                statuses.new_status::text AS status,
                COUNT(rscpupd.user_id) FILTER (
                    WHERE rscpupd.rn = 1
                    AND (
                        rscpupd.new_status = statuses.new_status
                        AND (
                            NOT EXISTS (SELECT 1 FROM user_deleted WHERE user_id = rscpupd.user_id)
                            OR
                            rscpupd.date < (SELECT MIN(deleted_at) FROM user_deleted WHERE user_id = rscpupd.user_id)
                        )
                    )
                ) AS count
            FROM ranked_status_change_per_user_per_date rscpupd
            CROSS JOIN statuses
            GROUP BY rscpupd.date, statuses.new_status
            ORDER BY rscpupd.date
            "#,
        )
        .bind(timezone)
        .bind(start_time)
        .bind(end_time)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        let mut status_counts: HashMap<String, Vec<UserStatusChangeCount>> = HashMap::new();
        for row in rows {
            status_counts
                .entry(row.status)
                .or_default()
                .push(UserStatusChangeCount {
                    date: row.date,
                    count: row.count,
                });
        }

        Ok(GetUserStatusCountsResponse { status_counts })
    }

    // ── Insights methods ──────────────────────────────────────────

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_user_latency_insights(
        &self,
        start_time: OffsetDateTime,
        end_time: OffsetDateTime,
        template_ids: Vec<Uuid>,
    ) -> Result<UserLatencyInsightsResponse, StorageError> {
        #[derive(sqlx::FromRow)]
        struct LatencyRow {
            user_id: Uuid,
            username: String,
            avatar_url: String,
            template_ids: Vec<Uuid>,
            workspace_connection_latency_50: f64,
            workspace_connection_latency_95: f64,
        }

        let rows = sqlx::query_as::<_, LatencyRow>(
            r#"
            SELECT
                tus.user_id,
                u.username,
                u.avatar_url,
                array_agg(DISTINCT tus.template_id)::uuid[] AS template_ids,
                COALESCE((PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY tus.median_latency_ms)), -1)::float8 AS workspace_connection_latency_50,
                COALESCE((PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY tus.median_latency_ms)), -1)::float8 AS workspace_connection_latency_95
            FROM template_usage_stats tus
            JOIN users u ON u.id = tus.user_id
            WHERE
                tus.start_time >= $1::timestamptz
                AND tus.end_time <= $2::timestamptz
                AND CASE WHEN COALESCE(array_length($3::uuid[], 1), 0) > 0 THEN tus.template_id = ANY($3::uuid[]) ELSE TRUE END
            GROUP BY tus.user_id, u.username, u.avatar_url
            ORDER BY tus.user_id ASC
            "#,
        )
        .bind(start_time)
        .bind(end_time)
        .bind(&template_ids)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        let mut all_template_ids: Vec<Uuid> = rows
            .iter()
            .flat_map(|r| r.template_ids.iter().copied())
            .collect();
        all_template_ids.sort();
        all_template_ids.dedup();

        let users = rows
            .into_iter()
            .map(|row| UserLatency {
                template_ids: row.template_ids,
                user_id: row.user_id,
                username: row.username,
                avatar_url: row.avatar_url,
                latency_ms: ConnectionLatency {
                    p50: row.workspace_connection_latency_50,
                    p95: row.workspace_connection_latency_95,
                },
            })
            .collect();

        Ok(UserLatencyInsightsResponse {
            report: UserLatencyInsightsReport {
                start_time,
                end_time,
                template_ids: all_template_ids,
                users,
            },
        })
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_user_activity_insights(
        &self,
        start_time: OffsetDateTime,
        end_time: OffsetDateTime,
        template_ids: Vec<Uuid>,
    ) -> Result<UserActivityInsightsResponse, StorageError> {
        #[derive(sqlx::FromRow)]
        struct ActivityRow {
            user_id: Uuid,
            username: String,
            avatar_url: String,
            template_ids: Vec<Uuid>,
            usage_seconds: i64,
        }

        let rows = sqlx::query_as::<_, ActivityRow>(
            r#"
            WITH deployment_stats AS (
                SELECT
                    start_time,
                    user_id,
                    array_agg(template_id) AS template_ids,
                    LEAST(SUM(usage_mins), 30) AS usage_mins
                FROM template_usage_stats
                WHERE
                    start_time >= $1::timestamptz
                    AND end_time <= $2::timestamptz
                    AND CASE WHEN COALESCE(array_length($3::uuid[], 1), 0) > 0 THEN template_id = ANY($3::uuid[]) ELSE TRUE END
                GROUP BY start_time, user_id
            ),
            template_ids AS (
                SELECT
                    user_id,
                    array_agg(DISTINCT template_id) AS ids
                FROM deployment_stats, unnest(template_ids) template_id
                GROUP BY user_id
            )
            SELECT
                ds.user_id,
                u.username,
                u.avatar_url,
                t.ids::uuid[] AS template_ids,
                (SUM(ds.usage_mins) * 60)::bigint AS usage_seconds
            FROM deployment_stats ds
            JOIN users u ON u.id = ds.user_id
            JOIN template_ids t ON ds.user_id = t.user_id
            GROUP BY ds.user_id, u.username, u.avatar_url, t.ids
            ORDER BY ds.user_id ASC
            "#,
        )
        .bind(start_time)
        .bind(end_time)
        .bind(&template_ids)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        let mut all_template_ids: Vec<Uuid> = rows
            .iter()
            .flat_map(|r| r.template_ids.iter().copied())
            .collect();
        all_template_ids.sort();
        all_template_ids.dedup();

        let users = rows
            .into_iter()
            .map(|row| UserActivity {
                template_ids: row.template_ids,
                user_id: row.user_id,
                username: row.username,
                avatar_url: row.avatar_url,
                seconds: row.usage_seconds,
            })
            .collect();

        Ok(UserActivityInsightsResponse {
            report: UserActivityInsightsReport {
                start_time,
                end_time,
                template_ids: all_template_ids,
                users,
            },
        })
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_template_insights_by_interval(
        &self,
        start_time: OffsetDateTime,
        end_time: OffsetDateTime,
        interval: InsightsReportInterval,
        template_ids: Vec<Uuid>,
    ) -> Result<Vec<TemplateInsightsIntervalReport>, StorageError> {
        #[derive(sqlx::FromRow)]
        struct IntervalRow {
            start_time: OffsetDateTime,
            end_time: OffsetDateTime,
            template_ids: Vec<Uuid>,
            active_users: i64,
        }

        let interval_days = interval.days();

        let rows = sqlx::query_as::<_, IntervalRow>(
            r#"
            WITH ts AS (
                SELECT
                    d::timestamptz AS from_,
                    LEAST(
                        (d::timestamptz + make_interval(days => $4))::timestamptz,
                        $2::timestamptz
                    )::timestamptz AS to_
                FROM generate_series(
                    $1::timestamptz,
                    ($2::timestamptz) - '1 microsecond'::interval,
                    make_interval(days => $4)
                ) AS d
            )
            SELECT
                ts.from_ AS start_time,
                ts.to_ AS end_time,
                array_remove(array_agg(DISTINCT tus.template_id), NULL)::uuid[] AS template_ids,
                COUNT(DISTINCT tus.user_id) AS active_users
            FROM ts
            LEFT JOIN template_usage_stats AS tus
            ON
                tus.start_time >= ts.from_
                AND tus.start_time < ts.to_
                AND tus.end_time <= ts.to_
                AND CASE WHEN COALESCE(array_length($3::uuid[], 1), 0) > 0 THEN tus.template_id = ANY($3::uuid[]) ELSE TRUE END
            GROUP BY ts.from_, ts.to_
            ORDER BY ts.from_ ASC
            "#,
        )
        .bind(start_time)
        .bind(end_time)
        .bind(&template_ids)
        .bind(interval_days)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(|row| TemplateInsightsIntervalReport {
                start_time: row.start_time,
                end_time: row.end_time,
                template_ids: row.template_ids,
                interval: interval.clone(),
                active_users: row.active_users,
            })
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_template_insights(
        &self,
        start_time: OffsetDateTime,
        end_time: OffsetDateTime,
        interval: InsightsReportInterval,
        template_ids: Vec<Uuid>,
    ) -> Result<TemplateInsightsResponse, StorageError> {
        #[derive(sqlx::FromRow)]
        struct InsightsRow {
            template_ids: Vec<Uuid>,
            ssh_template_ids: Vec<Uuid>,
            sftp_template_ids: Vec<Uuid>,
            reconnecting_pty_template_ids: Vec<Uuid>,
            vscode_template_ids: Vec<Uuid>,
            jetbrains_template_ids: Vec<Uuid>,
            active_users: i64,
            #[allow(dead_code)]
            usage_total_seconds: i64,
            usage_ssh_seconds: i64,
            usage_sftp_seconds: i64,
            usage_reconnecting_pty_seconds: i64,
            usage_vscode_seconds: i64,
            usage_jetbrains_seconds: i64,
        }

        #[derive(sqlx::FromRow)]
        struct AppInsightRow {
            template_ids: Vec<Uuid>,
            #[allow(dead_code)]
            active_users: i64,
            slug: String,
            display_name: String,
            icon: String,
            usage_seconds: i64,
            times_used: i64,
        }

        #[derive(sqlx::FromRow)]
        struct ParamRow {
            num: i64,
            template_ids: Vec<Uuid>,
            name: String,
            #[sqlx(rename = "type")]
            param_type: String,
            display_name: String,
            description: String,
            options: Value,
            value: String,
            count: i64,
        }

        // Clone template_ids for the interval query since it will be moved.
        let tids_for_interval = template_ids.clone();

        // Run all 4 queries concurrently — they share no mutable state.
        let (main_row, app_rows, param_rows, interval_reports) = tokio::try_join!(
            // ── 1. Main aggregation (matches Go GetTemplateInsights) ──────
            async {
                sqlx::query_as::<_, InsightsRow>(
                    r#"
                    WITH insights AS (
                        SELECT
                            user_id,
                            LEAST(SUM(usage_mins), 30) AS usage_mins,
                            LEAST(SUM(ssh_mins), 30) AS ssh_mins,
                            LEAST(SUM(sftp_mins), 30) AS sftp_mins,
                            LEAST(SUM(reconnecting_pty_mins), 30) AS reconnecting_pty_mins,
                            LEAST(SUM(vscode_mins), 30) AS vscode_mins,
                            LEAST(SUM(jetbrains_mins), 30) AS jetbrains_mins
                        FROM template_usage_stats
                        WHERE
                            start_time >= $1::timestamptz
                            AND end_time <= $2::timestamptz
                            AND CASE WHEN COALESCE(array_length($3::uuid[], 1), 0) > 0 THEN template_id = ANY($3::uuid[]) ELSE TRUE END
                        GROUP BY start_time, user_id
                    ),
                    templates AS (
                        SELECT
                            array_agg(DISTINCT template_id) AS template_ids,
                            array_agg(DISTINCT template_id) FILTER (WHERE ssh_mins > 0) AS ssh_template_ids,
                            array_agg(DISTINCT template_id) FILTER (WHERE sftp_mins > 0) AS sftp_template_ids,
                            array_agg(DISTINCT template_id) FILTER (WHERE reconnecting_pty_mins > 0) AS reconnecting_pty_template_ids,
                            array_agg(DISTINCT template_id) FILTER (WHERE vscode_mins > 0) AS vscode_template_ids,
                            array_agg(DISTINCT template_id) FILTER (WHERE jetbrains_mins > 0) AS jetbrains_template_ids
                        FROM template_usage_stats
                        WHERE
                            start_time >= $1::timestamptz
                            AND end_time <= $2::timestamptz
                            AND CASE WHEN COALESCE(array_length($3::uuid[], 1), 0) > 0 THEN template_id = ANY($3::uuid[]) ELSE TRUE END
                    )
                    SELECT
                        COALESCE((SELECT template_ids FROM templates), '{}')::uuid[] AS template_ids,
                        COALESCE((SELECT ssh_template_ids FROM templates), '{}')::uuid[] AS ssh_template_ids,
                        COALESCE((SELECT sftp_template_ids FROM templates), '{}')::uuid[] AS sftp_template_ids,
                        COALESCE((SELECT reconnecting_pty_template_ids FROM templates), '{}')::uuid[] AS reconnecting_pty_template_ids,
                        COALESCE((SELECT vscode_template_ids FROM templates), '{}')::uuid[] AS vscode_template_ids,
                        COALESCE((SELECT jetbrains_template_ids FROM templates), '{}')::uuid[] AS jetbrains_template_ids,
                        COALESCE(COUNT(DISTINCT user_id), 0)::bigint AS active_users,
                        COALESCE(SUM(usage_mins) * 60, 0)::bigint AS usage_total_seconds,
                        COALESCE(SUM(ssh_mins) * 60, 0)::bigint AS usage_ssh_seconds,
                        COALESCE(SUM(sftp_mins) * 60, 0)::bigint AS usage_sftp_seconds,
                        COALESCE(SUM(reconnecting_pty_mins) * 60, 0)::bigint AS usage_reconnecting_pty_seconds,
                        COALESCE(SUM(vscode_mins) * 60, 0)::bigint AS usage_vscode_seconds,
                        COALESCE(SUM(jetbrains_mins) * 60, 0)::bigint AS usage_jetbrains_seconds
                    FROM insights
                    "#,
                )
                .bind(start_time)
                .bind(end_time)
                .bind(&template_ids)
                .fetch_one(&self.pool)
                .await
                .map_err(storage_error)
            },
            // ── 2. App insights (matches Go GetTemplateAppInsights) ──────
            async {
                sqlx::query_as::<_, AppInsightRow>(
                    r#"
                    WITH apps AS (
                        SELECT DISTINCT ON (ws.template_id, app.slug)
                            ws.template_id,
                            app.slug,
                            app.display_name,
                            app.icon
                        FROM workspaces ws
                        JOIN workspace_builds AS build ON build.workspace_id = ws.id
                        JOIN workspace_resources AS resource ON resource.job_id = build.job_id
                        JOIN workspace_agents AS agent ON agent.resource_id = resource.id
                        JOIN workspace_apps AS app ON app.agent_id = agent.id
                        WHERE
                                ws.deleted = FALSE
                            AND agent.deleted = FALSE
                        AND CASE WHEN COALESCE(array_length($3::uuid[], 1), 0) > 0 THEN ws.template_id = ANY($3::uuid[]) ELSE TRUE END
                            ORDER BY ws.template_id, app.slug, app.created_at DESC
                    ),
                    template_usage_stats_with_apps AS (
                        SELECT
                            tus.start_time,
                            tus.template_id,
                            tus.user_id,
                            apps.slug,
                            apps.display_name,
                            apps.icon,
                            (tus.app_usage_mins -> apps.slug)::smallint AS usage_mins
                        FROM apps
                        JOIN template_usage_stats AS tus
                        ON
                            tus.start_time >= $1::timestamptz
                            AND tus.end_time <= $2::timestamptz
                            AND CASE WHEN COALESCE(array_length($3::uuid[], 1), 0) > 0 THEN tus.template_id = ANY($3::uuid[]) ELSE TRUE END
                            AND tus.template_id = apps.template_id
                            AND tus.app_usage_mins ? apps.slug
                    ),
                    app_insights AS (
                        SELECT
                            user_id,
                            slug,
                            display_name,
                            icon,
                            LEAST(SUM(usage_mins), 30) AS usage_mins
                        FROM template_usage_stats_with_apps
                        GROUP BY start_time, user_id, slug, display_name, icon
                    ),
                    times_used AS (
                        SELECT DISTINCT ON (user_id, slug, display_name, icon, uniq)
                            slug,
                            display_name,
                            icon,
                            start_time - (
                                dense_rank() OVER (
                                    PARTITION BY user_id, slug, display_name, icon
                                    ORDER BY start_time
                                ) * '30 minutes'::interval
                            ) AS uniq
                        FROM template_usage_stats_with_apps
                    ),
                    templates AS (
                        SELECT
                            slug,
                            display_name,
                            icon,
                            array_agg(DISTINCT template_id)::uuid[] AS template_ids
                        FROM template_usage_stats_with_apps
                        GROUP BY slug, display_name, icon
                    )
                    SELECT
                        t.template_ids,
                        COUNT(DISTINCT ai.user_id)::bigint AS active_users,
                        ai.slug,
                        ai.display_name,
                        ai.icon,
                        (SUM(ai.usage_mins) * 60)::bigint AS usage_seconds,
                        COALESCE((
                            SELECT COUNT(*)
                            FROM times_used
                            WHERE times_used.slug = ai.slug
                                AND times_used.display_name = ai.display_name
                                AND times_used.icon = ai.icon
                        ), 0)::bigint AS times_used
                    FROM app_insights AS ai
                    JOIN templates AS t
                    ON t.slug = ai.slug
                        AND t.display_name = ai.display_name
                        AND t.icon = ai.icon
                    GROUP BY t.template_ids, ai.slug, ai.display_name, ai.icon
                    "#,
                )
                .bind(start_time)
                .bind(end_time)
                .bind(&template_ids)
                .fetch_all(&self.pool)
                .await
                .map_err(storage_error)
            },
            // ── 3. Parameter insights (matches Go GetTemplateParameterInsights) ──
            async {
                sqlx::query_as::<_, ParamRow>(
                    r#"
                    WITH latest_workspace_builds AS (
                        SELECT
                            wb.id,
                            wbmax.template_id,
                            wb.template_version_id
                        FROM (
                            SELECT
                                tv.template_id,
                                wbmax.workspace_id,
                                MAX(wbmax.build_number) AS max_build_number
                            FROM workspace_builds wbmax
                            JOIN template_versions tv ON tv.id = wbmax.template_version_id
                            WHERE
                                wbmax.created_at >= $1::timestamptz
                                AND wbmax.created_at < $2::timestamptz
                                AND CASE WHEN COALESCE(array_length($3::uuid[], 1), 0) > 0 THEN tv.template_id = ANY($3::uuid[]) ELSE TRUE END
                            GROUP BY tv.template_id, wbmax.workspace_id
                        ) wbmax
                        JOIN workspace_builds wb ON (
                            wb.workspace_id = wbmax.workspace_id
                            AND wb.build_number = wbmax.max_build_number
                        )
                    ),
                    unique_template_params AS (
                        SELECT
                            ROW_NUMBER() OVER (
                        ORDER BY tvp.name, tvp.type, tvp.display_name, tvp.description, tvp.options
                    ) AS num,
                            array_agg(DISTINCT wb.template_id)::uuid[] AS template_ids,
                            array_agg(wb.id)::uuid[] AS workspace_build_ids,
                            tvp.name,
                            tvp.type,
                            tvp.display_name,
                            tvp.description,
                            tvp.options
                        FROM latest_workspace_builds wb
                        JOIN template_version_parameters tvp ON tvp.template_version_id = wb.template_version_id
                        GROUP BY tvp.name, tvp.type, tvp.display_name, tvp.description, tvp.options
                    )
                    SELECT
                        utp.num,
                        utp.template_ids,
                        utp.name,
                        utp.type,
                        utp.display_name,
                        utp.description,
                        utp.options,
                        wbp.value,
                        COUNT(wbp.value) AS count
                    FROM unique_template_params utp
                    JOIN workspace_build_parameters wbp
                        ON utp.workspace_build_ids @> ARRAY[wbp.workspace_build_id]
                        AND utp.name = wbp.name
                    GROUP BY utp.num, utp.template_ids, utp.name, utp.type, utp.display_name, utp.description, utp.options, wbp.value
                    "#,
                )
                .bind(start_time)
                .bind(end_time)
                .bind(&template_ids)
                .fetch_all(&self.pool)
                .await
                .map_err(storage_error)
            },
            // ── 4. Interval reports ───────────────────────────────────────
            self.get_template_insights_by_interval(
                start_time,
                end_time,
                interval,
                tids_for_interval,
            ),
        )?;

        // Group parameter rows by num into TemplateParameterUsage entries.
        let mut param_map: HashMap<i64, TemplateParameterUsage> = HashMap::new();
        for row in param_rows {
            let entry = param_map.entry(row.num).or_insert_with(|| {
                let options = match row.options.clone() {
                    Value::Array(arr) => arr,
                    _ => Vec::new(),
                };
                TemplateParameterUsage {
                    template_ids: row.template_ids.clone(),
                    display_name: row.display_name.clone(),
                    name: row.name.clone(),
                    param_type: row.param_type.clone(),
                    description: row.description.clone(),
                    options,
                    values: Vec::new(),
                }
            });
            entry.values.push(TemplateParameterValue {
                value: row.value,
                count: row.count,
            });
        }
        let parameters_usage: Vec<TemplateParameterUsage> = {
            let mut entries: Vec<(i64, TemplateParameterUsage)> = param_map.into_iter().collect();
            entries.sort_by_key(|(k, _)| *k);
            entries.into_iter().map(|(_, v)| v).collect()
        };

        // ── 5. Build apps_usage from built-in apps + custom apps ─────
        let mut apps_usage: Vec<TemplateAppUsage> = Vec::new();

        // Built-in apps follow Go handler convention.
        if main_row.usage_vscode_seconds > 0 {
            apps_usage.push(TemplateAppUsage {
                template_ids: main_row.vscode_template_ids,
                app_type: TemplateAppsType::Builtin,
                display_name: "Visual Studio Code".to_string(),
                slug: "vscode".to_string(),
                icon: String::new(),
                seconds: main_row.usage_vscode_seconds,
                times_used: 0,
            });
        }
        if main_row.usage_jetbrains_seconds > 0 {
            apps_usage.push(TemplateAppUsage {
                template_ids: main_row.jetbrains_template_ids,
                app_type: TemplateAppsType::Builtin,
                display_name: "JetBrains".to_string(),
                slug: "jetbrains".to_string(),
                icon: String::new(),
                seconds: main_row.usage_jetbrains_seconds,
                times_used: 0,
            });
        }
        if main_row.usage_reconnecting_pty_seconds > 0 {
            apps_usage.push(TemplateAppUsage {
                template_ids: main_row.reconnecting_pty_template_ids,
                app_type: TemplateAppsType::Builtin,
                display_name: "Web Terminal".to_string(),
                slug: "reconnecting-pty".to_string(),
                icon: String::new(),
                seconds: main_row.usage_reconnecting_pty_seconds,
                times_used: 0,
            });
        }
        if main_row.usage_ssh_seconds > 0 {
            apps_usage.push(TemplateAppUsage {
                template_ids: main_row.ssh_template_ids,
                app_type: TemplateAppsType::Builtin,
                display_name: "SSH".to_string(),
                slug: "ssh".to_string(),
                icon: String::new(),
                seconds: main_row.usage_ssh_seconds,
                times_used: 0,
            });
        }
        if main_row.usage_sftp_seconds > 0 {
            apps_usage.push(TemplateAppUsage {
                template_ids: main_row.sftp_template_ids,
                app_type: TemplateAppsType::Builtin,
                display_name: "SFTP".to_string(),
                slug: "sftp".to_string(),
                icon: String::new(),
                seconds: main_row.usage_sftp_seconds,
                times_used: 0,
            });
        }

        // Custom apps from GetTemplateAppInsights.
        for row in app_rows {
            apps_usage.push(TemplateAppUsage {
                template_ids: row.template_ids,
                app_type: TemplateAppsType::App,
                display_name: row.display_name,
                slug: row.slug,
                icon: row.icon,
                seconds: row.usage_seconds,
                times_used: row.times_used,
            });
        }

        // ── 6. Assemble response ─────────────────────────────────────
        let report = TemplateInsightsReport {
            start_time,
            end_time,
            template_ids: main_row.template_ids,
            active_users: main_row.active_users,
            apps_usage,
            parameters_usage,
        };

        Ok(TemplateInsightsResponse {
            report: Some(report),
            interval_reports,
        })
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_workspace_proxies_for_health(
        &self,
    ) -> Result<Vec<WorkspaceProxyHealthRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredWorkspaceProxyRow>(
            "SELECT
                id,
                name,
                display_name,
                icon_url,
                path_app_url,
                wildcard_hostname,
                derp_enabled,
                derp_only,
                created_at,
                updated_at,
                deleted,
                version
             FROM workspace_proxies
             ORDER BY name ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(workspace_proxy_record_from_row)
            .collect())
    }

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn upsert_workspace_proxy_for_health(
        &self,
        input: &WorkspaceProxyHealthInput,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO workspace_proxies (
                id,
                name,
                display_name,
                icon_url,
                path_app_url,
                wildcard_hostname,
                derp_enabled,
                derp_only,
                created_at,
                updated_at,
                deleted,
                version
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            ON CONFLICT (id) DO UPDATE SET
                name = EXCLUDED.name,
                display_name = EXCLUDED.display_name,
                icon_url = EXCLUDED.icon_url,
                path_app_url = EXCLUDED.path_app_url,
                wildcard_hostname = EXCLUDED.wildcard_hostname,
                derp_enabled = EXCLUDED.derp_enabled,
                derp_only = EXCLUDED.derp_only,
                updated_at = EXCLUDED.updated_at,
                deleted = EXCLUDED.deleted,
                version = EXCLUDED.version",
        )
        .bind(input.id)
        .bind(&input.name)
        .bind(&input.display_name)
        .bind(&input.icon_url)
        .bind(&input.path_app_url)
        .bind(&input.wildcard_hostname)
        .bind(input.derp_enabled)
        .bind(input.derp_only)
        .bind(input.created_at)
        .bind(input.updated_at)
        .bind(input.deleted)
        .bind(&input.version)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_provisioner_daemons_for_health(
        &self,
    ) -> Result<Vec<ProvisionerDaemonHealthRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredProvisionerDaemonRow>(
            "SELECT
                id,
                organization_id,
                created_at,
                last_seen_at,
                name,
                version,
                api_version,
                provisioners,
                tags_json,
                status
             FROM provisioner_daemons
             ORDER BY name ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        rows.into_iter()
            .map(provisioner_daemon_record_from_row)
            .collect()
    }

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn upsert_provisioner_daemon_for_health(
        &self,
        input: &ProvisionerDaemonHealthInput,
    ) -> Result<(), StorageError> {
        let tags_json = serde_json::to_string(&input.tags)
            .map_err(|error| StorageError::invalid_data(error.to_string()))?;
        sqlx::query(
            "INSERT INTO provisioner_daemons (
                id,
                organization_id,
                created_at,
                last_seen_at,
                name,
                version,
                api_version,
                provisioners,
                tags_json,
                status
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT (id) DO UPDATE SET
                organization_id = EXCLUDED.organization_id,
                last_seen_at = EXCLUDED.last_seen_at,
                name = EXCLUDED.name,
                version = EXCLUDED.version,
                api_version = EXCLUDED.api_version,
                provisioners = EXCLUDED.provisioners,
                tags_json = EXCLUDED.tags_json,
                status = EXCLUDED.status",
        )
        .bind(input.id)
        .bind(input.organization_id)
        .bind(input.created_at)
        .bind(input.last_seen_at)
        .bind(&input.name)
        .bind(&input.version)
        .bind(&input.api_version)
        .bind(&input.provisioners)
        .bind(tags_json)
        .bind(&input.status)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_git_ssh_key(
        &self,
        user_id: Uuid,
    ) -> Result<Option<GitSshKeyRecord>, StorageError> {
        sqlx::query_as::<_, StoredGitSshKeyRow>(
            "SELECT user_id, created_at, updated_at, public_key, private_key
             FROM git_ssh_keys
             WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?
        .map(git_ssh_key_record_from_row)
        .transpose()
    }

    #[instrument(skip(self, public_key, private_key), err(level = tracing::Level::WARN))]
    async fn upsert_git_ssh_key(
        &self,
        user_id: Uuid,
        public_key: &str,
        private_key: &str,
    ) -> Result<GitSshKeyRecord, StorageError> {
        let row = sqlx::query_as::<_, StoredGitSshKeyRow>(
            "INSERT INTO git_ssh_keys (user_id, created_at, updated_at, public_key, private_key)
             VALUES ($1, NOW(), NOW(), $2, $3)
             ON CONFLICT (user_id)
             DO UPDATE SET
                updated_at = NOW(),
                public_key = EXCLUDED.public_key,
                private_key = EXCLUDED.private_key
             RETURNING user_id, created_at, updated_at, public_key, private_key",
        )
        .bind(user_id)
        .bind(public_key)
        .bind(private_key)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        git_ssh_key_record_from_row(row)
    }

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn insert_file(&self, input: InsertFileInput) -> Result<InsertFileResult, StorageError> {
        // Only RETURNING id — avoids shipping the (potentially large) data
        // blob back from Postgres on every insert/duplicate.
        let (id,): (Uuid,) = sqlx::query_as(
            "INSERT INTO files (id, hash, created_by, created_at, mimetype, data)
             VALUES ($1, $2, $3, NOW(), $4, $5)
             ON CONFLICT (hash, created_by) DO UPDATE SET id = files.id
             RETURNING id",
        )
        .bind(input.id)
        .bind(&input.hash)
        .bind(input.created_by)
        .bind(&input.mimetype)
        .bind(&input.data)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(InsertFileResult { id })
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_file_by_id(&self, file_id: Uuid) -> Result<Option<FileRecord>, StorageError> {
        Ok(sqlx::query_as::<_, StoredFileRow>(
            "SELECT id, hash, created_by, created_at, mimetype, data
             FROM files
             WHERE id = $1",
        )
        .bind(file_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?
        .map(file_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_file_by_hash_and_creator(
        &self,
        hash: &str,
        creator_id: Uuid,
    ) -> Result<Option<FileRecord>, StorageError> {
        Ok(sqlx::query_as::<_, StoredFileRow>(
            "SELECT id, hash, created_by, created_at, mimetype, data
             FROM files
             WHERE hash = $1 AND created_by = $2",
        )
        .bind(hash)
        .bind(creator_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?
        .map(file_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_external_auth_links(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<ExternalAuthLinkRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredExternalAuthLinkRow>(
            "SELECT
                provider_id,
                created_at,
                updated_at,
                access_token,
                refresh_token,
                token_type,
                scopes,
                expires_at,
                authenticated,
                validate_error,
                refresh_error,
                last_validated_at,
                last_refreshed_at,
                external_user_json,
                installations_json,
                app_installable
             FROM external_auth_links
             WHERE user_id = $1
             ORDER BY provider_id ASC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        rows.into_iter()
            .map(external_auth_link_record_from_row)
            .collect()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_external_auth_link(
        &self,
        user_id: Uuid,
        provider_id: &str,
    ) -> Result<Option<ExternalAuthLinkRecord>, StorageError> {
        sqlx::query_as::<_, StoredExternalAuthLinkRow>(
            "SELECT
                provider_id,
                created_at,
                updated_at,
                access_token,
                refresh_token,
                token_type,
                scopes,
                expires_at,
                authenticated,
                validate_error,
                refresh_error,
                last_validated_at,
                last_refreshed_at,
                external_user_json,
                installations_json,
                app_installable
             FROM external_auth_links
             WHERE user_id = $1 AND provider_id = $2",
        )
        .bind(user_id)
        .bind(provider_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?
        .map(external_auth_link_record_from_row)
        .transpose()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_external_auth_link(
        &self,
        user_id: Uuid,
        provider_id: &str,
    ) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "DELETE FROM external_auth_links
             WHERE user_id = $1 AND provider_id = $2",
        )
        .bind(user_id)
        .bind(provider_id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self, link), err(level = tracing::Level::WARN))]
    async fn upsert_external_auth_link(
        &self,
        user_id: Uuid,
        link: &UpsertExternalAuthLinkInput,
    ) -> Result<ExternalAuthLinkRecord, StorageError> {
        let external_user_json = match &link.user {
            Some(user) => serde_json::to_string(user)
                .map_err(|error| StorageError::invalid_data(error.to_string()))?,
            None => "null".to_owned(),
        };
        let installations_json = serde_json::to_string(&link.installations)
            .map_err(|error| StorageError::invalid_data(error.to_string()))?;

        sqlx::query_as::<_, StoredExternalAuthLinkRow>(
            "INSERT INTO external_auth_links (
                provider_id,
                user_id,
                created_at,
                updated_at,
                access_token,
                refresh_token,
                token_type,
                scopes,
                expires_at,
                authenticated,
                validate_error,
                refresh_error,
                last_validated_at,
                last_refreshed_at,
                external_user_json,
                installations_json,
                app_installable
            )
            VALUES (
                $1, $2, NOW(), NOW(), $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
            )
            ON CONFLICT (provider_id, user_id) DO UPDATE SET
                updated_at = NOW(),
                access_token = EXCLUDED.access_token,
                refresh_token = EXCLUDED.refresh_token,
                token_type = EXCLUDED.token_type,
                scopes = EXCLUDED.scopes,
                expires_at = EXCLUDED.expires_at,
                authenticated = EXCLUDED.authenticated,
                validate_error = EXCLUDED.validate_error,
                refresh_error = EXCLUDED.refresh_error,
                last_validated_at = EXCLUDED.last_validated_at,
                last_refreshed_at = EXCLUDED.last_refreshed_at,
                external_user_json = EXCLUDED.external_user_json,
                installations_json = EXCLUDED.installations_json,
                app_installable = EXCLUDED.app_installable
            RETURNING
                provider_id,
                created_at,
                updated_at,
                access_token,
                refresh_token,
                token_type,
                scopes,
                expires_at,
                authenticated,
                validate_error,
                refresh_error,
                last_validated_at,
                last_refreshed_at,
                external_user_json,
                installations_json,
                app_installable",
        )
        .bind(&link.provider_id)
        .bind(user_id)
        .bind(&link.access_token)
        .bind(&link.refresh_token)
        .bind(&link.token_type)
        .bind(&link.scopes)
        .bind(link.expires_at)
        .bind(link.authenticated)
        .bind(&link.validate_error)
        .bind(&link.refresh_error)
        .bind(link.last_validated_at)
        .bind(link.last_refreshed_at)
        .bind(external_user_json)
        .bind(installations_json)
        .bind(link.app_installable)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)
        .and_then(external_auth_link_record_from_row)
    }

    // -----------------------------------------------------------------------
    // Tasks
    // -----------------------------------------------------------------------

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn insert_task(&self, input: InsertTaskInput) -> Result<TaskRecord, StorageError> {
        let row: StoredTaskRow = sqlx::query_as(
            "INSERT INTO tasks (id, organization_id, owner_id, name, display_name, template_version_id, template_parameters, prompt, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             RETURNING id, organization_id, owner_id, name, display_name, workspace_id, template_version_id, template_parameters, prompt, created_at, deleted_at",
        )
        .bind(input.id)
        .bind(input.organization_id)
        .bind(input.owner_id)
        .bind(&input.name)
        .bind(&input.display_name)
        .bind(input.template_version_id)
        .bind(&input.template_parameters)
        .bind(&input.prompt)
        .bind(input.created_at)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(task_record_from_row(row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_task_by_id(&self, id: Uuid) -> Result<Option<TaskRecord>, StorageError> {
        let row: Option<StoredTaskRow> = sqlx::query_as(
            "SELECT id, organization_id, owner_id, name, display_name, workspace_id, template_version_id, template_parameters, prompt, created_at, deleted_at
             FROM tasks WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(row.map(task_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_task_by_owner_and_name(
        &self,
        owner_id: Uuid,
        name: &str,
    ) -> Result<Option<TaskRecord>, StorageError> {
        let row: Option<StoredTaskRow> = sqlx::query_as(
            "SELECT id, organization_id, owner_id, name, display_name, workspace_id, template_version_id, template_parameters, prompt, created_at, deleted_at
             FROM tasks WHERE owner_id = $1 AND name = $2 AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 1",
        )
        .bind(owner_id)
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(row.map(task_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_tasks(&self, filter: TaskListFilter) -> Result<Vec<TaskRecord>, StorageError> {
        let rows: Vec<StoredTaskRow> = sqlx::query_as(
            "SELECT id, organization_id, owner_id, name, display_name, workspace_id, template_version_id, template_parameters, prompt, created_at, deleted_at
             FROM tasks
             WHERE deleted_at IS NULL
               AND ($1::uuid IS NULL OR owner_id = $1)
               AND ($2::uuid IS NULL OR organization_id = $2)
             ORDER BY created_at DESC",
        )
        .bind(filter.owner_id)
        .bind(filter.organization_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows.into_iter().map(task_record_from_row).collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_task(
        &self,
        id: Uuid,
        deleted_at: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let result =
            sqlx::query("UPDATE tasks SET deleted_at = $2 WHERE id = $1 AND deleted_at IS NULL")
                .bind(id)
                .bind(deleted_at)
                .execute(&self.pool)
                .await
                .map_err(storage_error)?;

        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_task_prompt(
        &self,
        id: Uuid,
        prompt: &str,
    ) -> Result<Option<TaskRecord>, StorageError> {
        let row: Option<StoredTaskRow> = sqlx::query_as(
            "UPDATE tasks SET prompt = $2
             WHERE id = $1 AND deleted_at IS NULL
             RETURNING id, organization_id, owner_id, name, display_name, workspace_id, template_version_id, template_parameters, prompt, created_at, deleted_at",
        )
        .bind(id)
        .bind(prompt)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(row.map(task_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn upsert_task_snapshot(
        &self,
        task_id: Uuid,
        log_snapshot: &Value,
        log_snapshot_created_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO task_snapshots (task_id, log_snapshot, log_snapshot_created_at)
             VALUES ($1, $2, $3)
             ON CONFLICT (task_id)
             DO UPDATE SET log_snapshot = EXCLUDED.log_snapshot,
                           log_snapshot_created_at = EXCLUDED.log_snapshot_created_at",
        )
        .bind(task_id)
        .bind(log_snapshot)
        .bind(log_snapshot_created_at)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_task_snapshot(
        &self,
        task_id: Uuid,
    ) -> Result<Option<TaskSnapshotRecord>, StorageError> {
        let row: Option<StoredTaskSnapshotRow> = sqlx::query_as(
            "SELECT task_id, log_snapshot, log_snapshot_created_at
             FROM task_snapshots WHERE task_id = $1",
        )
        .bind(task_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(row.map(|r| TaskSnapshotRecord {
            task_id: r.task_id,
            log_snapshot: r.log_snapshot,
            log_snapshot_created_at: r.log_snapshot_created_at,
        }))
    }

    // -----------------------------------------------------------------------
    // Chats
    // -----------------------------------------------------------------------

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn insert_chat(&self, input: InsertChatInput) -> Result<ChatRecord, StorageError> {
        let row: StoredChatRow = sqlx::query_as(
            "INSERT INTO chats (owner_id, workspace_id, parent_chat_id, root_chat_id, last_model_config_id, title)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING id, owner_id, workspace_id, title, status::text, last_error, parent_chat_id, root_chat_id, last_model_config_id, archived, created_at, updated_at",
        )
        .bind(input.owner_id)
        .bind(input.workspace_id)
        .bind(input.parent_chat_id)
        .bind(input.root_chat_id)
        .bind(input.last_model_config_id)
        .bind(&input.title)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        chat_record_from_row(row)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_chat_by_id(&self, id: Uuid) -> Result<Option<ChatRecord>, StorageError> {
        let row: Option<StoredChatRow> = sqlx::query_as(
            "SELECT id, owner_id, workspace_id, title, status::text, last_error, parent_chat_id, root_chat_id, last_model_config_id, archived, created_at, updated_at
             FROM chats WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        row.map(chat_record_from_row).transpose()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_chats_by_owner(
        &self,
        owner_id: Uuid,
        archived: Option<bool>,
    ) -> Result<Vec<ChatRecord>, StorageError> {
        let rows: Vec<StoredChatRow> = sqlx::query_as(
            "SELECT id, owner_id, workspace_id, title, status::text, last_error, parent_chat_id, root_chat_id, last_model_config_id, archived, created_at, updated_at
             FROM chats
             WHERE owner_id = $1
               AND ($2::boolean IS NULL OR archived = $2)
             ORDER BY updated_at DESC",
        )
        .bind(owner_id)
        .bind(archived)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        rows.into_iter().map(chat_record_from_row).collect()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn archive_chat(&self, id: Uuid) -> Result<(), StorageError> {
        sqlx::query(
            "UPDATE chats SET archived = true, updated_at = now()
             WHERE id = $1
                OR root_chat_id = $1
                OR id = (SELECT COALESCE(root_chat_id, id) FROM chats WHERE id = $1)
                OR root_chat_id = (SELECT COALESCE(root_chat_id, id) FROM chats WHERE id = $1)",
        )
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_chat_messages(
        &self,
        chat_id: Uuid,
        after_id: i64,
    ) -> Result<Vec<ChatMessageRecord>, StorageError> {
        let rows: Vec<StoredChatMessageRow> = sqlx::query_as(
            "SELECT id, chat_id, model_config_id, created_at, role, content, visibility::text, input_tokens, output_tokens, total_tokens, reasoning_tokens, cache_creation_tokens, cache_read_tokens, context_limit, compressed
             FROM chat_messages
             WHERE chat_id = $1 AND id > $2
             ORDER BY id ASC",
        )
        .bind(chat_id)
        .bind(after_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        rows.into_iter().map(chat_message_record_from_row).collect()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn insert_chat_message(
        &self,
        input: InsertChatMessageInput,
    ) -> Result<ChatMessageRecord, StorageError> {
        let visibility_str = match input.visibility {
            ChatMessageVisibility::User => "user",
            ChatMessageVisibility::Model => "model",
            ChatMessageVisibility::Both => "both",
        };
        let row: StoredChatMessageRow = sqlx::query_as(
            "INSERT INTO chat_messages (chat_id, model_config_id, role, content, visibility)
             VALUES ($1, $2, $3, $4, $5::chat_message_visibility)
             RETURNING id, chat_id, model_config_id, created_at, role, content, visibility::text, input_tokens, output_tokens, total_tokens, reasoning_tokens, cache_creation_tokens, cache_read_tokens, context_limit, compressed",
        )
        .bind(input.chat_id)
        .bind(input.model_config_id)
        .bind(&input.role)
        .bind(&input.content)
        .bind(visibility_str)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        chat_message_record_from_row(row)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_chat_queued_messages(
        &self,
        chat_id: Uuid,
    ) -> Result<Vec<ChatQueuedMessageRecord>, StorageError> {
        let rows: Vec<StoredChatQueuedMessageRow> = sqlx::query_as(
            "SELECT id, chat_id, content, created_at
             FROM chat_queued_messages
             WHERE chat_id = $1
             ORDER BY id ASC",
        )
        .bind(chat_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(|r| ChatQueuedMessageRecord {
                id: r.id,
                chat_id: r.chat_id,
                content: r.content,
                created_at: r.created_at,
            })
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn unarchive_chat(&self, id: Uuid) -> Result<(), StorageError> {
        sqlx::query(
            "UPDATE chats SET archived = false, updated_at = now()
             WHERE id = $1",
        )
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Chat Files
    // -----------------------------------------------------------------------

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn insert_chat_file(
        &self,
        input: InsertChatFileInput,
    ) -> Result<ChatFileRecord, StorageError> {
        let row: StoredChatFileRow = sqlx::query_as(
            "INSERT INTO chat_files (owner_id, organization_id, name, mimetype, data)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING id, owner_id, organization_id, created_at, name, mimetype, data",
        )
        .bind(input.owner_id)
        .bind(input.organization_id)
        .bind(&input.name)
        .bind(&input.mimetype)
        .bind(&input.data)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(ChatFileRecord {
            id: row.id,
            owner_id: row.owner_id,
            organization_id: row.organization_id,
            created_at: row.created_at,
            name: row.name,
            mimetype: row.mimetype,
            data: row.data,
        })
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_chat_file_by_id(&self, id: Uuid) -> Result<Option<ChatFileRecord>, StorageError> {
        let row: Option<StoredChatFileRow> = sqlx::query_as(
            "SELECT id, owner_id, organization_id, created_at, name, mimetype, data
             FROM chat_files WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(row.map(|r| ChatFileRecord {
            id: r.id,
            owner_id: r.owner_id,
            organization_id: r.organization_id,
            created_at: r.created_at,
            name: r.name,
            mimetype: r.mimetype,
            data: r.data,
        }))
    }

    // -----------------------------------------------------------------------
    // Notifications domain
    // -----------------------------------------------------------------------

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_notifications_settings(&self) -> Result<NotificationsSettings, StorageError> {
        let encoded: Option<String> = sqlx::query_scalar(
            "SELECT value FROM site_configs WHERE key = 'notifications_settings' LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        match encoded {
            Some(encoded) => {
                from_str(&encoded).map_err(|error| StorageError::invalid_data(error.to_string()))
            }
            None => Ok(NotificationsSettings::default()),
        }
    }

    #[instrument(skip(self, settings), err(level = tracing::Level::WARN))]
    async fn upsert_notifications_settings(
        &self,
        settings: &NotificationsSettings,
    ) -> Result<(), StorageError> {
        let json = serde_json::to_string(settings)
            .map_err(|e| StorageError::invalid_data(e.to_string()))?;

        sqlx::query(
            "INSERT INTO site_configs (key, value)
             VALUES ('notifications_settings', $1)
             ON CONFLICT (key) DO UPDATE SET value = $1",
        )
        .bind(&json)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_notification_templates_by_kind(
        &self,
        kind: &str,
    ) -> Result<Vec<NotificationTemplate>, StorageError> {
        let rows = sqlx::query_as::<_, StoredNotificationTemplateRow>(
            r#"SELECT id, name, title_template, body_template, actions::text, "group", method::text,
                      kind::text, enabled_by_default
               FROM notification_templates
               WHERE ($1 = '' OR kind::text = $1)
               ORDER BY name ASC"#,
        )
        .bind(kind)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        let mut templates = Vec::with_capacity(rows.len());
        for r in rows {
            templates.push(NotificationTemplate {
                id: r.id,
                name: r.name,
                title_template: r.title_template,
                body_template: r.body_template,
                actions: r
                    .actions
                    .map(|s| from_str(&s))
                    .transpose()
                    .map_err(|e| StorageError::invalid_data(e.to_string()))?,
                group: r.group,
                method: r.method,
                kind: r.kind,
                enabled_by_default: r.enabled_by_default,
            });
        }
        Ok(templates)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_notification_template_method(
        &self,
        template_id: Uuid,
        method: Option<&str>,
    ) -> Result<Option<NotificationTemplate>, StorageError> {
        let row = sqlx::query_as::<_, StoredNotificationTemplateRow>(
            r#"UPDATE notification_templates
               SET method = $2::notification_method
               WHERE id = $1
               RETURNING id, name, title_template, body_template, actions::text, "group", method::text,
                         kind::text, enabled_by_default"#,
        )
        .bind(template_id)
        .bind(method)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        match row {
            Some(r) => Ok(Some(NotificationTemplate {
                id: r.id,
                name: r.name,
                title_template: r.title_template,
                body_template: r.body_template,
                actions: r
                    .actions
                    .map(|s| from_str(&s))
                    .transpose()
                    .map_err(|e| StorageError::invalid_data(e.to_string()))?,
                group: r.group,
                method: r.method,
                kind: r.kind,
                enabled_by_default: r.enabled_by_default,
            })),
            None => Ok(None),
        }
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_user_notification_preferences(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<NotificationPreference>, StorageError> {
        let rows = sqlx::query_as::<_, StoredNotificationPreferenceRow>(
            "SELECT notification_template_id AS id, disabled, updated_at
             FROM notification_preferences
             WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(|r| NotificationPreference {
                id: r.id,
                disabled: r.disabled,
                updated_at: r.updated_at,
            })
            .collect())
    }

    #[instrument(skip(self, template_ids, disableds), err(level = tracing::Level::WARN))]
    async fn update_user_notification_preferences(
        &self,
        user_id: Uuid,
        template_ids: &[Uuid],
        disableds: &[bool],
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO notification_preferences (user_id, notification_template_id, disabled)
             SELECT $1, UNNEST($2::uuid[]), UNNEST($3::bool[])
             ON CONFLICT (user_id, notification_template_id) DO UPDATE SET
                disabled = EXCLUDED.disabled,
                updated_at = NOW()",
        )
        .bind(user_id)
        .bind(template_ids)
        .bind(disableds)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_filtered_inbox_notifications(
        &self,
        user_id: Uuid,
        templates: Option<&[Uuid]>,
        targets: Option<&[Uuid]>,
        read_status: &str,
        created_before: Option<OffsetDateTime>,
    ) -> Result<Vec<InboxNotification>, StorageError> {
        let rows = sqlx::query_as::<_, StoredInboxNotificationRow>(
            r#"SELECT id, user_id, template_id, targets, title, content, icon, actions::text,
                      read_at, created_at
               FROM inbox_notifications
               WHERE user_id = $1
                 AND ($2::uuid[] IS NULL OR template_id = ANY($2))
                 AND ($3::uuid[] IS NULL OR targets && $3::uuid[])
                 AND (
                    $4 = 'all'
                    OR ($4 = 'unread' AND read_at IS NULL)
                    OR ($4 = 'read' AND read_at IS NOT NULL)
                 )
                 AND ($5::timestamptz IS NULL OR created_at < $5)
               ORDER BY created_at DESC
               LIMIT 25"#,
        )
        .bind(user_id)
        .bind(templates)
        .bind(targets)
        .bind(read_status)
        .bind(created_before)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        rows.into_iter().map(inbox_notification_from_row).collect()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn count_unread_inbox_notifications(&self, user_id: Uuid) -> Result<i64, StorageError> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM inbox_notifications WHERE user_id = $1 AND read_at IS NULL",
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(row.0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_inbox_notification_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<InboxNotification>, StorageError> {
        let row = sqlx::query_as::<_, StoredInboxNotificationRow>(
            "SELECT id, user_id, template_id, targets, title, content, icon, actions::text,
                    read_at, created_at
             FROM inbox_notifications WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        row.map(inbox_notification_from_row).transpose()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_inbox_notification_read_status(
        &self,
        id: Uuid,
        read_at: Option<OffsetDateTime>,
    ) -> Result<(), StorageError> {
        sqlx::query("UPDATE inbox_notifications SET read_at = $2 WHERE id = $1")
            .bind(id)
            .bind(read_at)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn mark_all_inbox_notifications_as_read(
        &self,
        user_id: Uuid,
        read_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "UPDATE inbox_notifications SET read_at = $2 WHERE user_id = $1 AND read_at IS NULL",
        )
        .bind(user_id)
        .bind(read_at)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_webpush_subscriptions_by_user_id(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<WebpushSubscriptionRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredWebpushSubscriptionRow>(
            "SELECT id, user_id, created_at, endpoint, endpoint_p256dh_key, endpoint_auth_key
             FROM webpush_subscriptions WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(|r| WebpushSubscriptionRecord {
                id: r.id,
                user_id: r.user_id,
                created_at: r.created_at,
                endpoint: r.endpoint,
                endpoint_p256dh_key: r.endpoint_p256dh_key,
                endpoint_auth_key: r.endpoint_auth_key,
            })
            .collect())
    }

    #[instrument(skip(self, endpoint, p256dh_key, auth_key), err(level = tracing::Level::WARN))]
    async fn insert_webpush_subscription(
        &self,
        user_id: Uuid,
        endpoint: &str,
        p256dh_key: &str,
        auth_key: &str,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO webpush_subscriptions (id, user_id, created_at, endpoint, endpoint_p256dh_key, endpoint_auth_key)
             VALUES (gen_random_uuid(), $1, NOW(), $2, $3, $4)
             ON CONFLICT (user_id, endpoint) DO UPDATE
             SET endpoint_p256dh_key = $3, endpoint_auth_key = $4",
        )
        .bind(user_id)
        .bind(endpoint)
        .bind(p256dh_key)
        .bind(auth_key)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self, endpoint), err(level = tracing::Level::WARN))]
    async fn delete_webpush_subscription_by_user_and_endpoint(
        &self,
        user_id: Uuid,
        endpoint: &str,
    ) -> Result<bool, StorageError> {
        let result =
            sqlx::query("DELETE FROM webpush_subscriptions WHERE user_id = $1 AND endpoint = $2")
                .bind(user_id)
                .bind(endpoint)
                .execute(&self.pool)
                .await
                .map_err(storage_error)?;

        Ok(result.rows_affected() > 0)
    }

    // -----------------------------------------------------------------------
    // Notification message dispatch
    // -----------------------------------------------------------------------

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn acquire_pending_notification_messages(
        &self,
        limit: u32,
        max_attempt_count: u32,
    ) -> Result<Vec<NotificationMessageRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredNotificationMessageRow>(
            r#"UPDATE notification_messages
               SET status = 'leased'::notification_message_status,
                   leased_until = NOW() + INTERVAL '30 seconds',
                   updated_at = NOW()
               WHERE id IN (
                   SELECT id
                   FROM notification_messages
                   WHERE (status IN ('pending', 'temporary_failure')
                          OR (status = 'leased' AND leased_until < NOW()))
                     AND (next_retry_after IS NULL OR next_retry_after < NOW())
                     AND (attempt_count IS NULL OR attempt_count < $2)
                   ORDER BY created_at ASC
                   LIMIT $1
                   FOR UPDATE SKIP LOCKED
               )
               RETURNING id, user_id, notification_template_id,
                         method::text AS method,
                         status::text AS status,
                         attempt_count,
                         payload::text AS payload,
                         COALESCE(to_json(COALESCE(targets, ARRAY[]::uuid[])), '[]'::json)::text AS targets_json,
                         created_at,
                         updated_at"#,
        )
        .bind(limit as i64)
        .bind(max_attempt_count as i32)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        rows.into_iter()
            .map(notification_message_from_row)
            .collect()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_notification_message_status(
        &self,
        message_id: Uuid,
        status: NotificationMessageStatus,
    ) -> Result<bool, StorageError> {
        let status_str = match status {
            NotificationMessageStatus::Pending => "pending",
            NotificationMessageStatus::Leased => "leased",
            NotificationMessageStatus::Sent => "sent",
            NotificationMessageStatus::TemporaryFailure => "temporary_failure",
            NotificationMessageStatus::Failed => "permanent_failure",
        };

        let result = sqlx::query(
            r#"UPDATE notification_messages
               SET status = $2::notification_message_status,
                   updated_at = NOW()
               WHERE id = $1"#,
        )
        .bind(message_id)
        .bind(status_str)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn increment_notification_message_attempt_count(
        &self,
        message_id: Uuid,
    ) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "UPDATE notification_messages
             SET attempt_count = COALESCE(attempt_count, 0) + 1,
                 updated_at = NOW()
             WHERE id = $1",
        )
        .bind(message_id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(result.rows_affected() > 0)
    }

    // -----------------------------------------------------------------------
    // Custom roles
    // -----------------------------------------------------------------------

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_custom_roles(
        &self,
        organization_id: Option<Uuid>,
    ) -> Result<Vec<CustomRoleRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredCustomRoleRow>(
            r#"SELECT name, display_name, organization_id,
                      site_permissions::text AS site_permissions,
                      org_permissions::text AS org_permissions,
                      user_permissions::text AS user_permissions,
                      created_at, updated_at
               FROM custom_roles
               WHERE ($1::uuid IS NULL OR organization_id = $1)
               ORDER BY name ASC"#,
        )
        .bind(organization_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(|r| CustomRoleRecord {
                name: r.name,
                display_name: r.display_name,
                organization_id: r.organization_id,
                site_permissions: r.site_permissions,
                org_permissions: r.org_permissions,
                user_permissions: r.user_permissions,
                created_at: r.created_at,
                updated_at: r.updated_at,
            })
            .collect())
    }

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn upsert_custom_role(
        &self,
        input: &UpsertCustomRoleInput,
    ) -> Result<CustomRoleRecord, StorageError> {
        let row = sqlx::query_as::<_, StoredCustomRoleRow>(
            r#"INSERT INTO custom_roles (name, display_name, organization_id,
                                         site_permissions, org_permissions, user_permissions,
                                         created_at, updated_at)
               VALUES (LOWER($1), $2, $3, $4::jsonb, $5::jsonb, $6::jsonb, NOW(), NOW())
               ON CONFLICT (name, organization_id) DO UPDATE
               SET display_name = EXCLUDED.display_name,
                   site_permissions = EXCLUDED.site_permissions,
                   org_permissions = EXCLUDED.org_permissions,
                   user_permissions = EXCLUDED.user_permissions,
                   updated_at = NOW()
               RETURNING name, display_name, organization_id,
                         site_permissions::text AS site_permissions,
                         org_permissions::text AS org_permissions,
                         user_permissions::text AS user_permissions,
                         created_at, updated_at"#,
        )
        .bind(&input.name)
        .bind(&input.display_name)
        .bind(input.organization_id)
        .bind(&input.site_permissions)
        .bind(&input.org_permissions)
        .bind(&input.user_permissions)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(CustomRoleRecord {
            name: row.name,
            display_name: row.display_name,
            organization_id: row.organization_id,
            site_permissions: row.site_permissions,
            org_permissions: row.org_permissions,
            user_permissions: row.user_permissions,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    // -----------------------------------------------------------------------
    // Workspace Agent storage methods
    // -----------------------------------------------------------------------

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_workspace_agent_by_id(
        &self,
        agent_id: Uuid,
    ) -> Result<Option<WorkspaceAgentRow>, StorageError> {
        sqlx::query_as::<_, StoredWorkspaceAgentRow>(
            "SELECT
                id, parent_id, created_at, updated_at, name,
                first_connected_at, last_connected_at, disconnected_at,
                resource_id, auth_token, auth_instance_id,
                architecture, environment_variables::text AS environment_variables, operating_system,
                directory, expanded_directory, version, api_version,
                connection_timeout_seconds, troubleshooting_url, motd_file,
                lifecycle_state::text AS lifecycle_state, logs_length, logs_overflowed,
                started_at, ready_at,
                subsystems::text[] AS subsystems,
                display_apps::text[] AS display_apps,
                display_order, api_key_scope::text AS api_key_scope
             FROM workspace_agents
             WHERE id = $1 AND deleted = false",
        )
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(workspace_agent_row_from_stored))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_workspace_agent_by_auth_token(
        &self,
        auth_token: Uuid,
    ) -> Result<Option<WorkspaceAgentRow>, StorageError> {
        sqlx::query_as::<_, StoredWorkspaceAgentRow>(
            "SELECT
                id, parent_id, created_at, updated_at, name,
                first_connected_at, last_connected_at, disconnected_at,
                resource_id, auth_token, auth_instance_id,
                architecture, environment_variables::text AS environment_variables, operating_system,
                directory, expanded_directory, version, api_version,
                connection_timeout_seconds, troubleshooting_url, motd_file,
                lifecycle_state::text AS lifecycle_state, logs_length, logs_overflowed,
                started_at, ready_at,
                subsystems::text[] AS subsystems,
                display_apps::text[] AS display_apps,
                display_order, api_key_scope::text AS api_key_scope
             FROM workspace_agents
             WHERE auth_token = $1 AND deleted = false",
        )
        .bind(auth_token)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(workspace_agent_row_from_stored))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_workspace_agent_by_instance_id(
        &self,
        instance_id: &str,
    ) -> Result<Option<WorkspaceAgentRow>, StorageError> {
        sqlx::query_as::<_, StoredWorkspaceAgentRow>(
            "SELECT
                id, parent_id, created_at, updated_at, name,
                first_connected_at, last_connected_at, disconnected_at,
                resource_id, auth_token, auth_instance_id,
                architecture, environment_variables::text AS environment_variables, operating_system,
                directory, expanded_directory, version, api_version,
                connection_timeout_seconds, troubleshooting_url, motd_file,
                lifecycle_state::text AS lifecycle_state, logs_length, logs_overflowed,
                started_at, ready_at,
                subsystems::text[] AS subsystems,
                display_apps::text[] AS display_apps,
                display_order, api_key_scope::text AS api_key_scope
             FROM workspace_agents
             WHERE auth_instance_id = $1 AND deleted = false
             ORDER BY created_at DESC
             LIMIT 1",
        )
        .bind(instance_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(workspace_agent_row_from_stored))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_workspace_by_agent_id(
        &self,
        agent_id: Uuid,
    ) -> Result<Option<WorkspaceRecord>, StorageError> {
        sqlx::query_as::<_, StoredWorkspaceRow>(
            "SELECT
                w.id, w.created_at, w.updated_at, w.deleted,
                w.owner_id, w.organization_id, w.template_id,
                w.name, w.autostart_schedule, w.ttl,
                w.last_used_at, w.dormant_at, w.deleting_at,
                w.automatic_updates::text AS automatic_updates,
                w.favorite, w.next_start_at
             FROM workspaces w
             JOIN workspace_builds wb ON wb.workspace_id = w.id
             JOIN workspace_resources wr ON wr.job_id = wb.job_id
             JOIN workspace_agents wa ON wa.resource_id = wr.id
             WHERE wa.id = $1 AND wa.deleted = false AND w.deleted = false
             ORDER BY wb.build_number DESC
             LIMIT 1",
        )
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(workspace_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_workspace_agents_by_resource_ids(
        &self,
        resource_ids: &[Uuid],
    ) -> Result<Vec<WorkspaceAgentRow>, StorageError> {
        let rows = sqlx::query_as::<_, StoredWorkspaceAgentRow>(
            "SELECT
                id, parent_id, created_at, updated_at, name,
                first_connected_at, last_connected_at, disconnected_at,
                resource_id, auth_token, auth_instance_id,
                architecture, environment_variables::text AS environment_variables, operating_system,
                directory, expanded_directory, version, api_version,
                connection_timeout_seconds, troubleshooting_url, motd_file,
                lifecycle_state::text AS lifecycle_state, logs_length, logs_overflowed,
                started_at, ready_at,
                subsystems::text[] AS subsystems,
                display_apps::text[] AS display_apps,
                display_order, api_key_scope::text AS api_key_scope
             FROM workspace_agents
             WHERE resource_id = ANY($1) AND deleted = false
             ORDER BY created_at ASC",
        )
        .bind(resource_ids)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(workspace_agent_row_from_stored)
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_workspace_apps_by_agent_id(
        &self,
        agent_id: Uuid,
    ) -> Result<Vec<WorkspaceAppRow>, StorageError> {
        let rows = sqlx::query_as::<_, StoredWorkspaceAppRow>(
            "SELECT
                id, created_at, agent_id, display_name, icon,
                command, url, healthcheck_url, healthcheck_interval,
                healthcheck_threshold, health::text AS health, subdomain,
                sharing_level::text AS sharing_level, slug, external,
                display_order, hidden, open_in::text AS open_in,
                display_group
             FROM workspace_apps
             WHERE agent_id = $1
             ORDER BY display_order ASC, slug ASC",
        )
        .bind(agent_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(workspace_app_row_from_stored)
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_workspace_agent_scripts(
        &self,
        agent_id: Uuid,
    ) -> Result<Vec<WorkspaceAgentScriptRow>, StorageError> {
        let rows = sqlx::query_as::<_, StoredWorkspaceAgentScriptRow>(
            "SELECT
                id, workspace_agent_id, log_source_id, log_path,
                created_at, script, cron, start_blocks_login,
                run_on_start, run_on_stop, timeout_seconds, display_name
             FROM workspace_agent_scripts
             WHERE workspace_agent_id = $1
             ORDER BY display_name ASC",
        )
        .bind(agent_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(workspace_agent_script_row_from_stored)
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_workspace_agent_log_sources(
        &self,
        agent_id: Uuid,
    ) -> Result<Vec<WorkspaceAgentLogSourceRow>, StorageError> {
        let rows = sqlx::query_as::<_, StoredWorkspaceAgentLogSourceRow>(
            "SELECT id, workspace_agent_id, created_at, display_name, icon
             FROM workspace_agent_log_sources
             WHERE workspace_agent_id = $1
             ORDER BY created_at ASC",
        )
        .bind(agent_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(workspace_agent_log_source_row_from_stored)
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_workspace_agent_logs(
        &self,
        agent_id: Uuid,
        after_id: i64,
        limit: i64,
    ) -> Result<Vec<WorkspaceAgentLogRow>, StorageError> {
        let rows = sqlx::query_as::<_, StoredWorkspaceAgentLogRow>(
            "SELECT id, agent_id, created_at, output, level::text AS level, log_source_id
             FROM workspace_agent_logs
             WHERE agent_id = $1 AND id > $2
             ORDER BY id ASC
             LIMIT $3",
        )
        .bind(agent_id)
        .bind(after_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(workspace_agent_log_row_from_stored)
            .collect())
    }

    #[instrument(skip(self, logs), err(level = tracing::Level::WARN))]
    async fn insert_workspace_agent_logs(
        &self,
        agent_id: Uuid,
        log_source_id: Uuid,
        logs: &[InsertAgentLogInput],
    ) -> Result<Vec<WorkspaceAgentLogRow>, StorageError> {
        let log_count = i32::try_from(logs.len())
            .map_err(|_| StorageError::invalid_data("too many log entries"))?;

        let mut created_ats = Vec::with_capacity(logs.len());
        let mut outputs = Vec::with_capacity(logs.len());
        let mut levels = Vec::with_capacity(logs.len());

        for log in logs {
            created_ats.push(log.created_at);
            outputs.push(log.output.as_str());
            levels.push(log.level.as_str());
        }

        let mut tx = self.pool.begin().await.map_err(storage_error)?;

        // Update logs_length and logs_overflowed on the workspace_agents row.
        // The CHECK constraint max_logs_length ensures logs_length <= 1048576.
        sqlx::query(
            "UPDATE workspace_agents
             SET logs_length = LEAST(logs_length + $2, 1048576),
                 logs_overflowed = logs_overflowed OR (logs_length + $2 > 1048576)
             WHERE id = $1",
        )
        .bind(agent_id)
        .bind(log_count)
        .execute(&mut *tx)
        .await
        .map_err(storage_error)?;

        let rows = sqlx::query_as::<_, StoredWorkspaceAgentLogRow>(
            "INSERT INTO workspace_agent_logs (agent_id, created_at, output, level, log_source_id)
             SELECT $1, unnest($2::timestamptz[]), unnest($3::text[]),
                    unnest($4::log_level[]), $5
             RETURNING id, agent_id, created_at, output, level::text AS level, log_source_id",
        )
        .bind(agent_id)
        .bind(&created_ats)
        .bind(&outputs)
        .bind(&levels)
        .bind(log_source_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(storage_error)?;

        tx.commit().await.map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(workspace_agent_log_row_from_stored)
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_workspace_agent_metadata(
        &self,
        agent_id: Uuid,
    ) -> Result<Vec<WorkspaceAgentMetadataRow>, StorageError> {
        let rows = sqlx::query_as::<_, StoredWorkspaceAgentMetadataRow>(
            "SELECT workspace_agent_id, display_name, key, script,
                    value, error, timeout, interval, collected_at, display_order
             FROM workspace_agent_metadata
             WHERE workspace_agent_id = $1
             ORDER BY display_order ASC, key ASC",
        )
        .bind(agent_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(workspace_agent_metadata_row_from_stored)
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_workspace_agent_devcontainers(
        &self,
        agent_id: Uuid,
    ) -> Result<Vec<WorkspaceAgentDevcontainerRow>, StorageError> {
        let rows = sqlx::query_as::<_, StoredWorkspaceAgentDevcontainerRow>(
            "SELECT id, workspace_agent_id, created_at, workspace_folder,
                    config_path, name, subagent_id
             FROM workspace_agent_devcontainers
             WHERE workspace_agent_id = $1
             ORDER BY name ASC",
        )
        .bind(agent_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(workspace_agent_devcontainer_row_from_stored)
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn insert_workspace_agent_log_source(
        &self,
        agent_id: Uuid,
        id: Option<Uuid>,
        display_name: &str,
        icon: &str,
    ) -> Result<WorkspaceAgentLogSourceRow, StorageError> {
        let source_id = id.unwrap_or_else(Uuid::new_v4);
        let row = sqlx::query_as::<_, StoredWorkspaceAgentLogSourceRow>(
            "INSERT INTO workspace_agent_log_sources (id, workspace_agent_id, created_at, display_name, icon)
             VALUES ($1, $2, NOW(), $3, $4)
             RETURNING id, workspace_agent_id, created_at, display_name, icon",
        )
        .bind(source_id)
        .bind(agent_id)
        .bind(display_name)
        .bind(icon)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(workspace_agent_log_source_row_from_stored(row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_workspace_app_statuses_by_agent_id(
        &self,
        agent_id: Uuid,
    ) -> Result<Vec<WorkspaceAppStatusRow>, StorageError> {
        let rows = sqlx::query_as::<_, StoredWorkspaceAppStatusRow>(
            "SELECT id, created_at, agent_id, app_id, workspace_id,
                    state::text AS state, message, uri
             FROM workspace_app_statuses
             WHERE agent_id = $1
             ORDER BY created_at DESC",
        )
        .bind(agent_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(workspace_app_status_row_from_stored)
            .collect())
    }

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn insert_workspace_app_status(
        &self,
        input: &InsertWorkspaceAppStatusInput,
    ) -> Result<WorkspaceAppStatusRow, StorageError> {
        let row = sqlx::query_as::<_, StoredWorkspaceAppStatusRow>(
            "INSERT INTO workspace_app_statuses (id, created_at, agent_id, app_id, workspace_id, state, message, uri)
             VALUES ($1, NOW(), $2, $3, $4, $5::workspace_app_status_state, $6, $7)
             RETURNING id, created_at, agent_id, app_id, workspace_id, state::text AS state, message, uri",
        )
        .bind(Uuid::new_v4())
        .bind(input.agent_id)
        .bind(input.app_id)
        .bind(input.workspace_id)
        .bind(&input.state)
        .bind(&input.message)
        .bind(&input.uri)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(workspace_app_status_row_from_stored(row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_workspace_app_by_agent_and_slug(
        &self,
        agent_id: Uuid,
        slug: &str,
    ) -> Result<Option<WorkspaceAppRow>, StorageError> {
        sqlx::query_as::<_, StoredWorkspaceAppRow>(
            "SELECT
                id, created_at, agent_id, display_name, icon,
                command, url, healthcheck_url, healthcheck_interval,
                healthcheck_threshold, health::text AS health, subdomain,
                sharing_level::text AS sharing_level, slug, external,
                display_order, hidden, open_in::text AS open_in,
                display_group
             FROM workspace_apps
             WHERE agent_id = $1 AND slug = $2",
        )
        .bind(agent_id)
        .bind(slug)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(workspace_app_row_from_stored))
    }

    // -------------------------------------------------------------------
    // Workspace domain
    // -------------------------------------------------------------------

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_workspaces(
        &self,
        filter: WorkspaceListFilter,
    ) -> Result<(Vec<WorkspaceRecord>, i64), StorageError> {
        let search = filter
            .name
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .map(|s| format!("%{}%", s.trim().replace('%', "\\%").replace('_', "\\_")));
        let owner_username = filter.owner_username.clone();
        let template_name = filter.template_name.clone();
        let _status = filter.status.clone();
        let _has_agent = filter.has_agent.clone();
        let dormant = filter.dormant;
        let template_ids: Vec<Uuid> = filter.template_ids.clone();

        let total = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*)
             FROM workspaces w
             LEFT JOIN users u ON u.id = w.owner_id
             LEFT JOIN templates t ON t.id = w.template_id
             WHERE w.deleted = false
               AND ($1::uuid IS NULL OR w.owner_id = $1)
               AND ($2::text IS NULL OR u.username = $2)
               AND ($3::text IS NULL OR w.name ILIKE $3)
               AND ($4::text IS NULL OR t.name = $4)
               AND ($5::uuid IS NULL OR w.organization_id = $5)
               AND ($6::bool IS NULL OR ($6 = true AND w.dormant_at IS NOT NULL) OR ($6 = false AND w.dormant_at IS NULL))
               AND (cardinality($7::uuid[]) = 0 OR w.template_id = ANY($7))",
        )
        .bind(filter.owner_id)
        .bind(owner_username.as_deref())
        .bind(search.as_deref())
        .bind(template_name.as_deref())
        .bind(filter.organization_id)
        .bind(dormant)
        .bind(&template_ids)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        let viewer_id = filter.viewer_id;
        let rows = sqlx::query_as::<_, StoredWorkspaceRow>(
            "SELECT
                w.id,
                w.created_at,
                w.updated_at,
                w.deleted,
                w.owner_id,
                w.organization_id,
                w.template_id,
                w.name,
                w.autostart_schedule,
                w.ttl,
                w.last_used_at,
                w.dormant_at,
                w.deleting_at,
                w.automatic_updates,
                COALESCE((wf.workspace_id IS NOT NULL), false) AS favorite,
                w.next_start_at
             FROM workspaces w
             LEFT JOIN users u ON u.id = w.owner_id
             LEFT JOIN templates t ON t.id = w.template_id
             LEFT JOIN workspace_favorites wf ON wf.workspace_id = w.id AND wf.user_id = $10
             WHERE w.deleted = false
               AND ($1::uuid IS NULL OR w.owner_id = $1)
               AND ($2::text IS NULL OR u.username = $2)
               AND ($3::text IS NULL OR w.name ILIKE $3)
               AND ($4::text IS NULL OR t.name = $4)
               AND ($5::uuid IS NULL OR w.organization_id = $5)
               AND ($6::bool IS NULL OR ($6 = true AND w.dormant_at IS NOT NULL) OR ($6 = false AND w.dormant_at IS NULL))
               AND (cardinality($7::uuid[]) = 0 OR w.template_id = ANY($7))
             ORDER BY w.last_used_at DESC
             LIMIT $8 OFFSET $9",
        )
        .bind(filter.owner_id)
        .bind(owner_username.as_deref())
        .bind(search.as_deref())
        .bind(template_name.as_deref())
        .bind(filter.organization_id)
        .bind(dormant)
        .bind(&template_ids)
        .bind(i64::from(filter.limit.min(1000)))
        .bind(i64::from(filter.offset))
        .bind(viewer_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        let workspaces: Vec<WorkspaceRecord> =
            rows.into_iter().map(workspace_record_from_row).collect();
        Ok((workspaces, total))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_workspace_by_id(
        &self,
        workspace_id: Uuid,
        viewer_id: Option<Uuid>,
    ) -> Result<Option<WorkspaceRecord>, StorageError> {
        sqlx::query_as::<_, StoredWorkspaceRow>(
            "SELECT w.id, w.created_at, w.updated_at, w.deleted, w.owner_id, w.organization_id,
                    w.template_id, w.name, w.autostart_schedule, w.ttl, w.last_used_at,
                    w.dormant_at, w.deleting_at, w.automatic_updates,
                    COALESCE((wf.workspace_id IS NOT NULL), false) AS favorite,
                    w.next_start_at
             FROM workspaces w
             LEFT JOIN workspace_favorites wf ON wf.workspace_id = w.id AND wf.user_id = $2
             WHERE w.id = $1 AND w.deleted = false",
        )
        .bind(workspace_id)
        .bind(viewer_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(workspace_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_workspace_by_owner_and_name(
        &self,
        owner_id: Uuid,
        name: &str,
        viewer_id: Option<Uuid>,
    ) -> Result<Option<WorkspaceRecord>, StorageError> {
        sqlx::query_as::<_, StoredWorkspaceRow>(
            "SELECT w.id, w.created_at, w.updated_at, w.deleted, w.owner_id, w.organization_id,
                    w.template_id, w.name, w.autostart_schedule, w.ttl, w.last_used_at,
                    w.dormant_at, w.deleting_at, w.automatic_updates,
                    COALESCE((wf.workspace_id IS NOT NULL), false) AS favorite,
                    w.next_start_at
             FROM workspaces w
             LEFT JOIN workspace_favorites wf ON wf.workspace_id = w.id AND wf.user_id = $3
             WHERE w.owner_id = $1 AND LOWER(w.name) = LOWER($2) AND w.deleted = false",
        )
        .bind(owner_id)
        .bind(name)
        .bind(viewer_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(workspace_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn insert_workspace(
        &self,
        input: CreateWorkspaceInput,
    ) -> Result<WorkspaceRecord, StorageError> {
        sqlx::query_as::<_, StoredWorkspaceRow>(
            "INSERT INTO workspaces (
                id, owner_id, organization_id, template_id, name,
                autostart_schedule, ttl, automatic_updates,
                created_at, updated_at, last_used_at
             )
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW(), NOW())
             RETURNING id, created_at, updated_at, deleted, owner_id, organization_id,
                       template_id, name, autostart_schedule, ttl, last_used_at,
                       dormant_at, deleting_at, automatic_updates,
                       false AS favorite, next_start_at",
        )
        .bind(input.id)
        .bind(input.owner_id)
        .bind(input.organization_id)
        .bind(input.template_id)
        .bind(&input.name)
        .bind(input.autostart_schedule.as_deref())
        .bind(input.ttl_ns)
        .bind(&input.automatic_updates)
        .fetch_one(&self.pool)
        .await
        .map(workspace_record_from_row)
        .map_err(storage_error)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_workspace_name(
        &self,
        workspace_id: Uuid,
        name: &str,
        viewer_id: Option<Uuid>,
    ) -> Result<Option<WorkspaceRecord>, StorageError> {
        sqlx::query_as::<_, StoredWorkspaceRow>(
            "WITH updated AS (
                UPDATE workspaces
                SET name = $2, updated_at = NOW()
                WHERE id = $1 AND deleted = false
                RETURNING *
             )
             SELECT u.id, u.created_at, u.updated_at, u.deleted, u.owner_id,
                    u.organization_id, u.template_id, u.name, u.autostart_schedule,
                    u.ttl, u.last_used_at, u.dormant_at, u.deleting_at,
                    u.automatic_updates,
                    COALESCE((wf.user_id IS NOT NULL), false) AS favorite,
                    u.next_start_at
             FROM updated u
             LEFT JOIN workspace_favorites wf
               ON wf.workspace_id = u.id AND wf.user_id = $3",
        )
        .bind(workspace_id)
        .bind(name)
        .bind(viewer_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(workspace_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_workspace_autostart(
        &self,
        workspace_id: Uuid,
        schedule: Option<&str>,
    ) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "UPDATE workspaces SET autostart_schedule = $2, updated_at = NOW()
             WHERE id = $1 AND deleted = false",
        )
        .bind(workspace_id)
        .bind(schedule)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_workspace_ttl(
        &self,
        workspace_id: Uuid,
        ttl_ns: Option<i64>,
    ) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "UPDATE workspaces SET ttl = $2, updated_at = NOW()
             WHERE id = $1 AND deleted = false",
        )
        .bind(workspace_id)
        .bind(ttl_ns)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_workspace_dormant_at(
        &self,
        workspace_id: Uuid,
        dormant_at: Option<OffsetDateTime>,
        viewer_id: Option<Uuid>,
    ) -> Result<Option<WorkspaceRecord>, StorageError> {
        sqlx::query_as::<_, StoredWorkspaceRow>(
            "WITH updated AS (
                UPDATE workspaces
                SET dormant_at = $2, updated_at = NOW()
                WHERE id = $1 AND deleted = false
                RETURNING *
             )
             SELECT u.id, u.created_at, u.updated_at, u.deleted, u.owner_id,
                    u.organization_id, u.template_id, u.name, u.autostart_schedule,
                    u.ttl, u.last_used_at, u.dormant_at, u.deleting_at,
                    u.automatic_updates,
                    COALESCE((wf.user_id IS NOT NULL), false) AS favorite,
                    u.next_start_at
             FROM updated u
             LEFT JOIN workspace_favorites wf
               ON wf.workspace_id = u.id AND wf.user_id = $3",
        )
        .bind(workspace_id)
        .bind(dormant_at)
        .bind(viewer_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(workspace_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_workspace_automatic_updates(
        &self,
        workspace_id: Uuid,
        automatic_updates: &str,
    ) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "UPDATE workspaces SET automatic_updates = $2, updated_at = NOW()
             WHERE id = $1 AND deleted = false",
        )
        .bind(workspace_id)
        .bind(automatic_updates)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_workspace_last_used_at(
        &self,
        workspace_id: Uuid,
        last_used_at: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "UPDATE workspaces SET last_used_at = $2, updated_at = NOW()
             WHERE id = $1 AND deleted = false",
        )
        .bind(workspace_id)
        .bind(last_used_at)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn favorite_workspace(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
        favorite: bool,
    ) -> Result<bool, StorageError> {
        if favorite {
            // Insert into junction table (ignore conflict if already favorited).
            sqlx::query(
                "INSERT INTO workspace_favorites (workspace_id, user_id)
                 VALUES ($1, $2)
                 ON CONFLICT (workspace_id, user_id) DO NOTHING",
            )
            .bind(workspace_id)
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;
        } else {
            // Remove from junction table.
            sqlx::query(
                "DELETE FROM workspace_favorites
                 WHERE workspace_id = $1 AND user_id = $2",
            )
            .bind(workspace_id)
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;
        }
        Ok(true)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn soft_delete_workspace(&self, workspace_id: Uuid) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "UPDATE workspaces SET deleted = true, updated_at = NOW()
             WHERE id = $1 AND deleted = false",
        )
        .bind(workspace_id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn create_group(&self, input: &CreateGroupInput) -> Result<GroupRecord, StorageError> {
        let row: (
            Uuid,
            String,
            String,
            Uuid,
            String,
            i32,
            String,
            OffsetDateTime,
        ) = sqlx::query_as(
            "INSERT INTO groups (name, display_name, organization_id, avatar_url, quota_allowance)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING id, name, display_name, organization_id, avatar_url,
                       quota_allowance, source, created_at",
        )
        .bind(&input.name)
        .bind(&input.display_name)
        .bind(input.organization_id)
        .bind(&input.avatar_url)
        .bind(input.quota_allowance)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                StorageError::invalid_data(
                    "group with this name already exists in the organization",
                )
            } else {
                storage_error(e)
            }
        })?;

        let (
            id,
            name,
            display_name,
            organization_id,
            avatar_url,
            quota_allowance,
            source,
            created_at,
        ) = row;
        Ok(GroupRecord {
            id,
            name,
            display_name,
            organization_id,
            avatar_url,
            quota_allowance,
            source,
            created_at,
        })
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_group(&self, group_id: Uuid) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM groups WHERE id = $1")
            .bind(group_id)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;
        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_groups(&self, organization_id: Uuid) -> Result<Vec<GroupRecord>, StorageError> {
        let rows: Vec<(
            Uuid,
            String,
            String,
            Uuid,
            String,
            i32,
            String,
            OffsetDateTime,
        )> = sqlx::query_as(
            "SELECT id, name, display_name, organization_id, avatar_url,
                    quota_allowance, source, created_at
             FROM groups
             WHERE organization_id = $1
             ORDER BY LOWER(name) ASC",
        )
        .bind(organization_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(
                |(
                    id,
                    name,
                    display_name,
                    organization_id,
                    avatar_url,
                    quota_allowance,
                    source,
                    created_at,
                )| {
                    GroupRecord {
                        id,
                        name,
                        display_name,
                        organization_id,
                        avatar_url,
                        quota_allowance,
                        source,
                        created_at,
                    }
                },
            )
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn insert_group_member(&self, group_id: Uuid, user_id: Uuid) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO group_members (group_id, user_id)
             VALUES ($1, $2)",
        )
        .bind(group_id)
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                StorageError::invalid_data("user is already a member of this group")
            } else {
                storage_error(e)
            }
        })?;
        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_group_members(
        &self,
        group_id: Uuid,
    ) -> Result<Vec<GroupMemberRecord>, StorageError> {
        let rows: Vec<(Uuid, Uuid)> = sqlx::query_as(
            "SELECT gm.group_id, gm.user_id
             FROM group_members gm
             JOIN users u ON u.id = gm.user_id
             WHERE gm.group_id = $1
               AND u.deleted = false
             ORDER BY LOWER(u.username) ASC",
        )
        .bind(group_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(|(group_id, user_id)| GroupMemberRecord { group_id, user_id })
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_group_member(
        &self,
        group_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM group_members WHERE group_id = $1 AND user_id = $2")
            .bind(group_id)
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;
        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_group_by_id(&self, group_id: Uuid) -> Result<Option<GroupRecord>, StorageError> {
        let row: Option<(
            Uuid,
            String,
            String,
            Uuid,
            String,
            i32,
            String,
            OffsetDateTime,
        )> = sqlx::query_as(
            "SELECT id, name, display_name, organization_id, avatar_url,
                        quota_allowance, source, created_at
                 FROM groups WHERE id = $1",
        )
        .bind(group_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(row.map(
            |(
                id,
                name,
                display_name,
                organization_id,
                avatar_url,
                quota_allowance,
                source,
                created_at,
            )| {
                GroupRecord {
                    id,
                    name,
                    display_name,
                    organization_id,
                    avatar_url,
                    quota_allowance,
                    source,
                    created_at,
                }
            },
        ))
    }

    // ----- OAuth2 Provider Apps -----

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_oauth2_provider_apps(
        &self,
    ) -> Result<Vec<OAuth2ProviderAppRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredOAuth2ProviderAppRow>(
            "SELECT id, created_at, updated_at, name, icon, callback_url, redirect_uris, created_by
             FROM oauth2_provider_apps
             ORDER BY (name, id) ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows.into_iter().map(oauth2_provider_app_from_row).collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn create_oauth2_provider_app(
        &self,
        input: &CreateOAuth2ProviderAppInput,
    ) -> Result<OAuth2ProviderAppRecord, StorageError> {
        let row = sqlx::query_as::<_, StoredOAuth2ProviderAppRow>(
            "INSERT INTO oauth2_provider_apps (name, icon, callback_url, created_by)
             VALUES ($1, $2, $3, $4)
             RETURNING id, created_at, updated_at, name, icon, callback_url, redirect_uris, created_by",
        )
        .bind(&input.name)
        .bind(&input.icon)
        .bind(&input.callback_url)
        .bind(input.created_by)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(oauth2_provider_app_from_row(row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_oauth2_provider_app_by_id(
        &self,
        app_id: Uuid,
    ) -> Result<Option<OAuth2ProviderAppRecord>, StorageError> {
        sqlx::query_as::<_, StoredOAuth2ProviderAppRow>(
            "SELECT id, created_at, updated_at, name, icon, callback_url, redirect_uris, created_by
             FROM oauth2_provider_apps WHERE id = $1",
        )
        .bind(app_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(oauth2_provider_app_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_oauth2_provider_app(
        &self,
        input: &UpdateOAuth2ProviderAppInput,
    ) -> Result<Option<OAuth2ProviderAppRecord>, StorageError> {
        sqlx::query_as::<_, StoredOAuth2ProviderAppRow>(
            "UPDATE oauth2_provider_apps SET
                updated_at = NOW(),
                name = $2,
                icon = $3,
                callback_url = $4,
                redirect_uris = $5
             WHERE id = $1
             RETURNING id, created_at, updated_at, name, icon, callback_url, redirect_uris, created_by",
        )
        .bind(input.id)
        .bind(&input.name)
        .bind(&input.icon)
        .bind(&input.callback_url)
        .bind(&input.redirect_uris)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(oauth2_provider_app_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_oauth2_provider_app(&self, app_id: Uuid) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM oauth2_provider_apps WHERE id = $1")
            .bind(app_id)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;
        Ok(result.rows_affected() > 0)
    }

    // ----- OAuth2 Provider App Secrets -----

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_oauth2_provider_app_secrets(
        &self,
        app_id: Uuid,
    ) -> Result<Vec<OAuth2ProviderAppSecretRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredOAuth2ProviderAppSecretRow>(
            "SELECT id, created_at, last_used_at, secret_prefix, hashed_secret, display_secret, app_id
             FROM oauth2_provider_app_secrets
             WHERE app_id = $1
             ORDER BY (created_at, id) ASC",
        )
        .bind(app_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(oauth2_provider_app_secret_from_row)
            .collect())
    }

    #[instrument(skip(self, secret_prefix, hashed_secret), err(level = tracing::Level::WARN))]
    async fn create_oauth2_provider_app_secret(
        &self,
        app_id: Uuid,
        secret_prefix: &[u8],
        hashed_secret: &[u8],
        display_secret: &str,
    ) -> Result<OAuth2ProviderAppSecretRecord, StorageError> {
        let row = sqlx::query_as::<_, StoredOAuth2ProviderAppSecretRow>(
            "INSERT INTO oauth2_provider_app_secrets (secret_prefix, hashed_secret, display_secret, app_id)
             VALUES ($1, $2, $3, $4)
             RETURNING id, created_at, last_used_at, secret_prefix, hashed_secret, display_secret, app_id",
        )
        .bind(secret_prefix)
        .bind(hashed_secret)
        .bind(display_secret)
        .bind(app_id)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(oauth2_provider_app_secret_from_row(row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_oauth2_provider_app_secret_by_id(
        &self,
        secret_id: Uuid,
    ) -> Result<Option<OAuth2ProviderAppSecretRecord>, StorageError> {
        sqlx::query_as::<_, StoredOAuth2ProviderAppSecretRow>(
            "SELECT id, created_at, last_used_at, secret_prefix, hashed_secret, display_secret, app_id
             FROM oauth2_provider_app_secrets WHERE id = $1",
        )
        .bind(secret_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(oauth2_provider_app_secret_from_row))
    }

    #[instrument(skip(self, secret_prefix), err(level = tracing::Level::WARN))]
    async fn find_oauth2_provider_app_secret_by_prefix(
        &self,
        secret_prefix: &[u8],
    ) -> Result<Option<OAuth2ProviderAppSecretRecord>, StorageError> {
        sqlx::query_as::<_, StoredOAuth2ProviderAppSecretRow>(
            "SELECT id, created_at, last_used_at, secret_prefix, hashed_secret, display_secret, app_id
             FROM oauth2_provider_app_secrets WHERE secret_prefix = $1",
        )
        .bind(secret_prefix)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(oauth2_provider_app_secret_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_oauth2_provider_app_secret_last_used(
        &self,
        secret_id: Uuid,
    ) -> Result<Option<OAuth2ProviderAppSecretRecord>, StorageError> {
        sqlx::query_as::<_, StoredOAuth2ProviderAppSecretRow>(
            "UPDATE oauth2_provider_app_secrets SET last_used_at = NOW()
             WHERE id = $1
             RETURNING id, created_at, last_used_at, secret_prefix, hashed_secret, display_secret, app_id",
        )
        .bind(secret_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(oauth2_provider_app_secret_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_oauth2_provider_app_secret(
        &self,
        secret_id: Uuid,
    ) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM oauth2_provider_app_secrets WHERE id = $1")
            .bind(secret_id)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;
        Ok(result.rows_affected() > 0)
    }

    // ----- OAuth2 Provider App Codes -----

    #[instrument(skip(self, secret_prefix, hashed_secret), err(level = tracing::Level::WARN))]
    async fn create_oauth2_provider_app_code(
        &self,
        app_id: Uuid,
        user_id: Uuid,
        secret_prefix: &[u8],
        hashed_secret: &[u8],
        expires_at: OffsetDateTime,
        resource_uri: &str,
        code_challenge: &str,
        code_challenge_method: &str,
        state_hash: Option<&str>,
        redirect_uri: Option<&str>,
    ) -> Result<OAuth2ProviderAppCodeRecord, StorageError> {
        let row = sqlx::query_as::<_, StoredOAuth2ProviderAppCodeRow>(
            "INSERT INTO oauth2_provider_app_codes
                (expires_at, secret_prefix, hashed_secret, app_id, user_id,
                 resource_uri, code_challenge, code_challenge_method, state_hash, redirect_uri)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             RETURNING id, created_at, expires_at, secret_prefix, hashed_secret,
                       app_id, user_id, resource_uri, code_challenge, code_challenge_method,
                       state_hash, redirect_uri",
        )
        .bind(expires_at)
        .bind(secret_prefix)
        .bind(hashed_secret)
        .bind(app_id)
        .bind(user_id)
        .bind(resource_uri)
        .bind(code_challenge)
        .bind(code_challenge_method)
        .bind(state_hash)
        .bind(redirect_uri)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(oauth2_provider_app_code_from_row(row))
    }

    #[instrument(skip(self, secret_prefix), err(level = tracing::Level::WARN))]
    async fn find_oauth2_provider_app_code_by_prefix(
        &self,
        secret_prefix: &[u8],
    ) -> Result<Option<OAuth2ProviderAppCodeRecord>, StorageError> {
        sqlx::query_as::<_, StoredOAuth2ProviderAppCodeRow>(
            "SELECT id, created_at, expires_at, secret_prefix, hashed_secret,
                    app_id, user_id, resource_uri, code_challenge, code_challenge_method,
                    state_hash, redirect_uri
             FROM oauth2_provider_app_codes WHERE secret_prefix = $1",
        )
        .bind(secret_prefix)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(oauth2_provider_app_code_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_oauth2_provider_app_code_by_id(
        &self,
        code_id: Uuid,
    ) -> Result<Option<OAuth2ProviderAppCodeRecord>, StorageError> {
        sqlx::query_as::<_, StoredOAuth2ProviderAppCodeRow>(
            "SELECT id, created_at, expires_at, secret_prefix, hashed_secret,
                    app_id, user_id, resource_uri, code_challenge, code_challenge_method,
                    state_hash, redirect_uri
             FROM oauth2_provider_app_codes WHERE id = $1",
        )
        .bind(code_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(oauth2_provider_app_code_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_oauth2_provider_app_code(&self, code_id: Uuid) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM oauth2_provider_app_codes WHERE id = $1")
            .bind(code_id)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;
        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_oauth2_provider_app_codes_by_app_and_user(
        &self,
        app_id: Uuid,
        user_id: Uuid,
    ) -> Result<u64, StorageError> {
        let result =
            sqlx::query("DELETE FROM oauth2_provider_app_codes WHERE app_id = $1 AND user_id = $2")
                .bind(app_id)
                .bind(user_id)
                .execute(&self.pool)
                .await
                .map_err(storage_error)?;
        Ok(result.rows_affected())
    }

    // ----- OAuth2 Provider App Tokens -----

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn create_oauth2_provider_app_token(
        &self,
        input: &CreateOAuth2ProviderAppTokenInput,
    ) -> Result<OAuth2ProviderAppTokenRecord, StorageError> {
        let row = sqlx::query_as::<_, StoredOAuth2ProviderAppTokenRow>(
            "INSERT INTO oauth2_provider_app_tokens
                (expires_at, hash_prefix, refresh_hash, app_secret_id, api_key_id, user_id, audience)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             RETURNING id, created_at, expires_at, hash_prefix, refresh_hash,
                       app_secret_id, api_key_id, audience, user_id",
        )
        .bind(input.expires_at)
        .bind(&input.hash_prefix)
        .bind(&input.refresh_hash)
        .bind(input.app_secret_id)
        .bind(&input.api_key_id)
        .bind(input.user_id)
        .bind(&input.audience)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(oauth2_provider_app_token_from_row(row))
    }

    #[instrument(skip(self, hash_prefix), err(level = tracing::Level::WARN))]
    async fn find_oauth2_provider_app_token_by_prefix(
        &self,
        hash_prefix: &[u8],
    ) -> Result<Option<OAuth2ProviderAppTokenRecord>, StorageError> {
        sqlx::query_as::<_, StoredOAuth2ProviderAppTokenRow>(
            "SELECT id, created_at, expires_at, hash_prefix, refresh_hash,
                    app_secret_id, api_key_id, audience, user_id
             FROM oauth2_provider_app_tokens WHERE hash_prefix = $1",
        )
        .bind(hash_prefix)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(oauth2_provider_app_token_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_oauth2_provider_app_token_by_api_key_id(
        &self,
        api_key_id: &str,
    ) -> Result<Option<OAuth2ProviderAppTokenRecord>, StorageError> {
        sqlx::query_as::<_, StoredOAuth2ProviderAppTokenRow>(
            "SELECT id, created_at, expires_at, hash_prefix, refresh_hash,
                    app_secret_id, api_key_id, audience, user_id
             FROM oauth2_provider_app_tokens WHERE api_key_id = $1",
        )
        .bind(api_key_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(oauth2_provider_app_token_from_row))
    }

    #[instrument(skip(self, refresh_hash), err(level = tracing::Level::WARN))]
    async fn find_oauth2_provider_app_token_by_refresh_hash(
        &self,
        refresh_hash: &[u8],
    ) -> Result<Option<OAuth2ProviderAppTokenRecord>, StorageError> {
        sqlx::query_as::<_, StoredOAuth2ProviderAppTokenRow>(
            "SELECT id, created_at, expires_at, hash_prefix, refresh_hash,
                    app_secret_id, api_key_id, audience, user_id
             FROM oauth2_provider_app_tokens WHERE refresh_hash = $1",
        )
        .bind(refresh_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(oauth2_provider_app_token_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_oauth2_provider_app_token(&self, token_id: Uuid) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM oauth2_provider_app_tokens WHERE id = $1")
            .bind(token_id)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;
        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_oauth2_provider_app_tokens_by_app_and_user(
        &self,
        app_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<OAuth2ProviderAppTokenRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredOAuth2ProviderAppTokenRow>(
            "SELECT t.id, t.created_at, t.expires_at, t.hash_prefix, t.refresh_hash,
                    t.app_secret_id, t.api_key_id, t.audience, t.user_id
             FROM oauth2_provider_app_tokens t
             INNER JOIN oauth2_provider_app_secrets s ON s.id = t.app_secret_id
             WHERE s.app_id = $1 AND t.user_id = $2",
        )
        .bind(app_id)
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(oauth2_provider_app_token_from_row)
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_oauth2_provider_app_tokens_by_app_and_user(
        &self,
        app_id: Uuid,
        user_id: Uuid,
    ) -> Result<u64, StorageError> {
        let result = sqlx::query(
            "DELETE FROM oauth2_provider_app_tokens
             USING oauth2_provider_app_secrets
             WHERE oauth2_provider_app_secrets.id = oauth2_provider_app_tokens.app_secret_id
               AND oauth2_provider_app_secrets.app_id = $1
               AND oauth2_provider_app_tokens.user_id = $2",
        )
        .bind(app_id)
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(result.rows_affected())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_workspace_acl(
        &self,
        workspace_id: Uuid,
    ) -> Result<WorkspaceACLRecord, StorageError> {
        let row: Option<(Value, Value)> =
            sqlx::query_as("SELECT group_acl, user_acl FROM workspaces WHERE id = $1")
                .bind(workspace_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_error)?;

        match row {
            Some((group_acl_val, user_acl_val)) => {
                let group_acl: HashMap<String, String> =
                    serde_json::from_value(group_acl_val).unwrap_or_default();
                let user_acl: HashMap<String, String> =
                    serde_json::from_value(user_acl_val).unwrap_or_default();
                Ok(WorkspaceACLRecord {
                    group_acl,
                    user_acl,
                })
            }
            None => Ok(WorkspaceACLRecord::default()),
        }
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_workspace_acl(
        &self,
        workspace_id: Uuid,
        input: &UpdateWorkspaceACLInput,
    ) -> Result<(), StorageError> {
        let user_acl_json =
            serde_json::to_value(&input.user_roles).map_err(|e| StorageError::InvalidData {
                message: format!("failed to serialize user_roles: {e}"),
            })?;
        let group_acl_json =
            serde_json::to_value(&input.group_roles).map_err(|e| StorageError::InvalidData {
                message: format!("failed to serialize group_roles: {e}"),
            })?;
        sqlx::query(
            "UPDATE workspaces SET user_acl = user_acl || $2, group_acl = group_acl || $3
             WHERE id = $1",
        )
        .bind(workspace_id)
        .bind(user_acl_json)
        .bind(group_acl_json)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_workspace_acl(&self, workspace_id: Uuid) -> Result<(), StorageError> {
        sqlx::query(
            "UPDATE workspaces SET group_acl = '{}'::jsonb, user_acl = '{}'::jsonb
             WHERE id = $1",
        )
        .bind(workspace_id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_workspace_builds(
        &self,
        workspace_id: Uuid,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<WorkspaceBuildRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredWorkspaceBuildRow>(
            "SELECT id, created_at, updated_at, workspace_id, build_number, transition,
                    job_id, template_version_id, initiator_id, provisioner_state,
                    deadline, max_deadline, reason, daily_cost
             FROM workspace_builds
             WHERE workspace_id = $1
             ORDER BY build_number DESC
             LIMIT $2 OFFSET $3",
        )
        .bind(workspace_id)
        .bind(i64::from(limit.min(1000)))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(rows
            .into_iter()
            .map(workspace_build_record_from_row)
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_latest_workspace_build(
        &self,
        workspace_id: Uuid,
    ) -> Result<Option<WorkspaceBuildRecord>, StorageError> {
        sqlx::query_as::<_, StoredWorkspaceBuildRow>(
            "SELECT id, created_at, updated_at, workspace_id, build_number, transition,
                    job_id, template_version_id, initiator_id, provisioner_state,
                    deadline, max_deadline, reason, daily_cost
             FROM workspace_builds
             WHERE workspace_id = $1
             ORDER BY build_number DESC
             LIMIT 1",
        )
        .bind(workspace_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(workspace_build_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_workspace_build_by_id(
        &self,
        build_id: Uuid,
    ) -> Result<Option<WorkspaceBuildRecord>, StorageError> {
        sqlx::query_as::<_, StoredWorkspaceBuildRow>(
            "SELECT id, created_at, updated_at, workspace_id, build_number, transition,
                    job_id, template_version_id, initiator_id, provisioner_state,
                    deadline, max_deadline, reason, daily_cost
             FROM workspace_builds
             WHERE id = $1",
        )
        .bind(build_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(workspace_build_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_workspace_build_by_number(
        &self,
        workspace_id: Uuid,
        build_number: i64,
    ) -> Result<Option<WorkspaceBuildRecord>, StorageError> {
        sqlx::query_as::<_, StoredWorkspaceBuildRow>(
            "SELECT id, created_at, updated_at, workspace_id, build_number, transition,
                    job_id, template_version_id, initiator_id, provisioner_state,
                    deadline, max_deadline, reason, daily_cost
             FROM workspace_builds
             WHERE workspace_id = $1 AND build_number = $2",
        )
        .bind(workspace_id)
        .bind(build_number)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(workspace_build_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn insert_workspace_build(
        &self,
        input: CreateWorkspaceBuildInput,
    ) -> Result<WorkspaceBuildRecord, StorageError> {
        sqlx::query_as::<_, StoredWorkspaceBuildRow>(
            "INSERT INTO workspace_builds (
                id, workspace_id, template_version_id, build_number, transition,
                initiator_id, job_id, reason, deadline, max_deadline,
                created_at, updated_at
             )
             VALUES ($1, $2, $3,
                     (SELECT COALESCE(MAX(build_number), 0) + 1 FROM workspace_builds WHERE workspace_id = $2),
                     $4, $5, $6, $7, $8, $9, NOW(), NOW())
             RETURNING id, created_at, updated_at, workspace_id, build_number, transition,
                       job_id, template_version_id, initiator_id, provisioner_state,
                       deadline, max_deadline, reason, daily_cost",
        )
        .bind(input.id)
        .bind(input.workspace_id)
        .bind(input.template_version_id)
        .bind(&input.transition)
        .bind(input.initiator_id)
        .bind(input.job_id)
        .bind(&input.reason)
        .bind(input.deadline)
        .bind(input.max_deadline)
        .fetch_one(&self.pool)
        .await
        .map(workspace_build_record_from_row)
        .map_err(storage_error)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_workspace_build_deadline(
        &self,
        build_id: Uuid,
        deadline: Option<OffsetDateTime>,
        max_deadline: Option<OffsetDateTime>,
    ) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "UPDATE workspace_builds
             SET deadline = $2, max_deadline = $3, updated_at = NOW()
             WHERE id = $1",
        )
        .bind(build_id)
        .bind(deadline)
        .bind(max_deadline)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self, state), err(level = tracing::Level::WARN))]
    async fn update_workspace_build_provisioner_state(
        &self,
        build_id: Uuid,
        state: &[u8],
    ) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "UPDATE workspace_builds
             SET provisioner_state = $2, updated_at = NOW()
             WHERE id = $1",
        )
        .bind(build_id)
        .bind(state)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn next_workspace_build_number(&self, workspace_id: Uuid) -> Result<i64, StorageError> {
        let max: Option<i64> = sqlx::query_scalar(
            "SELECT MAX(build_number) FROM workspace_builds WHERE workspace_id = $1",
        )
        .bind(workspace_id)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(max.unwrap_or(0) + 1) // sqlx query_scalar returns Option for MAX
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_workspace_build_parameters(
        &self,
        build_id: Uuid,
    ) -> Result<Vec<WorkspaceBuildParameterRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredWorkspaceBuildParameterRow>(
            "SELECT workspace_build_id, name, value
             FROM workspace_build_parameters
             WHERE workspace_build_id = $1
             ORDER BY name",
        )
        .bind(build_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(rows
            .into_iter()
            .map(|row| WorkspaceBuildParameterRecord {
                workspace_build_id: row.workspace_build_id,
                name: row.name,
                value: row.value,
            })
            .collect())
    }

    #[instrument(skip(self, params), err(level = tracing::Level::WARN))]
    async fn insert_workspace_build_parameters(
        &self,
        build_id: Uuid,
        params: &[(String, String)],
    ) -> Result<(), StorageError> {
        let mut tx = self.pool.begin().await.map_err(storage_error)?;
        for (name, value) in params {
            sqlx::query(
                "INSERT INTO workspace_build_parameters (workspace_build_id, name, value)
                 VALUES ($1, $2, $3)",
            )
            .bind(build_id)
            .bind(name)
            .bind(value)
            .execute(&mut *tx)
            .await
            .map_err(storage_error)?;
        }
        tx.commit().await.map_err(storage_error)?;
        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_provisioner_job_logs(
        &self,
        job_id: Uuid,
        after: Option<i64>,
    ) -> Result<Vec<ProvisionerJobLogRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredProvisionerJobLogRow>(
            "SELECT id, job_id, created_at, source, level, stage, output
             FROM provisioner_job_logs
             WHERE job_id = $1 AND ($2::bigint IS NULL OR id > $2)
             ORDER BY id ASC",
        )
        .bind(job_id)
        .bind(after)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(rows
            .into_iter()
            .map(provisioner_job_log_record_from_row)
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_provisioner_job_timings(
        &self,
        job_id: Uuid,
    ) -> Result<Vec<ProvisionerJobTimingRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredProvisionerJobTimingRow>(
            "SELECT job_id, started_at, ended_at, stage, source, action, resource
             FROM provisioner_job_timings
             WHERE job_id = $1
             ORDER BY started_at ASC",
        )
        .bind(job_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(rows
            .into_iter()
            .map(provisioner_job_timing_record_from_row)
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_workspace_agent_script_timings_by_build_id(
        &self,
        build_id: Uuid,
    ) -> Result<Vec<WorkspaceAgentScriptTimingRow>, StorageError> {
        #[derive(sqlx::FromRow)]
        struct Row {
            script_id: Uuid,
            started_at: OffsetDateTime,
            ended_at: OffsetDateTime,
            exit_code: i32,
            stage: String,
            status: String,
            display_name: String,
            workspace_agent_id: Uuid,
            workspace_agent_name: String,
        }

        let rows = sqlx::query_as::<_, Row>(
            "SELECT
                DISTINCT ON (wast.script_id) wast.script_id,
                wast.started_at,
                wast.ended_at,
                wast.exit_code,
                wast.stage::text AS stage,
                wast.status::text AS status,
                was2.display_name,
                wa.id AS workspace_agent_id,
                wa.name AS workspace_agent_name
             FROM workspace_agent_script_timings wast
             INNER JOIN workspace_agent_scripts was2 ON was2.id = wast.script_id
             INNER JOIN workspace_agents wa ON wa.id = was2.workspace_agent_id
             INNER JOIN workspace_resources wr ON wr.id = wa.resource_id
             INNER JOIN workspace_builds wb ON wb.job_id = wr.job_id
             WHERE wb.id = $1
             ORDER BY wast.script_id, wast.started_at",
        )
        .bind(build_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(|r| WorkspaceAgentScriptTimingRow {
                script_id: r.script_id,
                started_at: r.started_at,
                ended_at: r.ended_at,
                exit_code: r.exit_code,
                stage: r.stage,
                status: r.status,
                display_name: r.display_name,
                workspace_agent_id: r.workspace_agent_id,
                workspace_agent_name: r.workspace_agent_name,
            })
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_workspace_resource_by_id(
        &self,
        resource_id: Uuid,
    ) -> Result<Option<WorkspaceResourceRecord>, StorageError> {
        let row = sqlx::query_as::<_, StoredWorkspaceResourceRow>(
            "SELECT id, created_at, job_id, transition, type AS resource_type,
                    name, hide, icon, daily_cost
             FROM workspace_resources
             WHERE id = $1",
        )
        .bind(resource_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(row.map(workspace_resource_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_workspace_resources_by_job(
        &self,
        job_id: Uuid,
    ) -> Result<Vec<WorkspaceResourceRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredWorkspaceResourceRow>(
            "SELECT id, created_at, job_id, transition, type AS resource_type,
                    name, hide, icon, daily_cost
             FROM workspace_resources
             WHERE job_id = $1
             ORDER BY name ASC",
        )
        .bind(job_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(rows
            .into_iter()
            .map(workspace_resource_record_from_row)
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_workspace_resource_metadata(
        &self,
        resource_ids: &[Uuid],
    ) -> Result<Vec<WorkspaceResourceMetadataRecord>, StorageError> {
        if resource_ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows = sqlx::query_as::<_, StoredWorkspaceResourceMetadataRow>(
            "SELECT workspace_resource_id, key, value, sensitive
             FROM workspace_resource_metadata
             WHERE workspace_resource_id = ANY($1)
             ORDER BY workspace_resource_id, key",
        )
        .bind(resource_ids)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(rows
            .into_iter()
            .map(|row| WorkspaceResourceMetadataRecord {
                workspace_resource_id: row.workspace_resource_id,
                key: row.key,
                value: row.value,
                sensitive: row.sensitive,
            })
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_workspace_port_shares(
        &self,
        workspace_id: Uuid,
    ) -> Result<Vec<WorkspaceAgentPortShareRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredPortShareRow>(
            "SELECT workspace_id, agent_name, port, share_level, protocol
             FROM workspace_agent_port_shares
             WHERE workspace_id = $1
             ORDER BY agent_name, port",
        )
        .bind(workspace_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(rows.into_iter().map(port_share_record_from_row).collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn upsert_workspace_port_share(
        &self,
        input: UpsertPortShareInput,
    ) -> Result<WorkspaceAgentPortShareRecord, StorageError> {
        sqlx::query_as::<_, StoredPortShareRow>(
            "INSERT INTO workspace_agent_port_shares (
                workspace_id, agent_name, port, share_level, protocol
             )
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (workspace_id, agent_name, port) DO UPDATE
             SET share_level = EXCLUDED.share_level,
                 protocol = EXCLUDED.protocol
             RETURNING workspace_id, agent_name, port, share_level, protocol",
        )
        .bind(input.workspace_id)
        .bind(&input.agent_name)
        .bind(input.port)
        .bind(&input.share_level)
        .bind(&input.protocol)
        .fetch_one(&self.pool)
        .await
        .map(port_share_record_from_row)
        .map_err(storage_error)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_workspace_port_share(
        &self,
        workspace_id: Uuid,
        agent_name: &str,
        port: i32,
    ) -> Result<Option<WorkspaceAgentPortShareRecord>, StorageError> {
        sqlx::query_as::<_, StoredPortShareRow>(
            "SELECT workspace_id, agent_name, port, share_level, protocol
             FROM workspace_agent_port_shares
             WHERE workspace_id = $1 AND agent_name = $2 AND port = $3",
        )
        .bind(workspace_id)
        .bind(agent_name)
        .bind(port)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(port_share_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_workspace_port_share(
        &self,
        workspace_id: Uuid,
        agent_name: &str,
        port: i32,
    ) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "DELETE FROM workspace_agent_port_shares
             WHERE workspace_id = $1 AND agent_name = $2 AND port = $3",
        )
        .bind(workspace_id)
        .bind(agent_name)
        .bind(port)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(result.rows_affected() > 0)
    }

    // ----- Template Store Methods -----

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_templates(
        &self,
        filter: TemplateListFilter,
    ) -> Result<Vec<TemplateRecord>, StorageError> {
        // Escape LIKE metacharacters so user input is treated literally.
        let escaped_search = filter.search.as_deref().map(escape_like);
        let rows = sqlx::query_as::<_, StoredTemplateRow>(
            r#"
            SELECT t.id, t.created_at, t.updated_at, t.organization_id, t.deleted,
                   t.name, t.provisioner::text AS provisioner, t.active_version_id,
                   t.description, t.default_ttl, t.created_by, t.icon, t.user_acl,
                   t.group_acl, t.display_name, t.allow_user_cancel_workspace_jobs,
                   t.allow_user_autostart, t.allow_user_autostop, t.failure_ttl,
                   t.time_til_dormant, t.time_til_dormant_autodelete,
                   t.autostop_requirement_days_of_week, t.autostop_requirement_weeks,
                   t.autostart_block_days_of_week, t.require_active_version,
                   t.deprecated, t.activity_bump,
                   t.max_port_sharing_level::text AS max_port_sharing_level,
                   t.use_classic_parameter_flow,
                   t.cors_behavior::text AS cors_behavior,
                   t.disable_module_cache,
                   COALESCE(o.name, '') AS organization_name,
                   COALESCE(o.display_name, '') AS organization_display_name,
                   COALESCE(o.icon, '') AS organization_icon,
                   COALESCE(u.username, '') AS created_by_username,
                   COALESCE(u.avatar_url, '') AS created_by_avatar_url,
                   COALESCE(u.name, '') AS created_by_name
            FROM templates t
            LEFT JOIN organizations o ON o.id = t.organization_id
            LEFT JOIN users u ON u.id = t.created_by
            WHERE ($1::uuid IS NULL OR t.organization_id = $1)
              AND ($2::text IS NULL OR t.name = $2)
              AND ($3::bool OR t.deleted = false)
              AND ($4::text IS NULL OR t.name ILIKE '%' || $4 || '%' OR t.display_name ILIKE '%' || $4 || '%')
            ORDER BY t.name ASC
            "#,
        )
        .bind(filter.organization_id)
        .bind(filter.exact_name.as_deref())
        .bind(filter.deleted)
        .bind(escaped_search.as_deref())
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(rows.into_iter().map(template_record_from_row).collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_template_by_id(
        &self,
        template_id: Uuid,
    ) -> Result<Option<TemplateRecord>, StorageError> {
        let row = sqlx::query_as::<_, StoredTemplateRow>(
            r#"
            SELECT t.id, t.created_at, t.updated_at, t.organization_id, t.deleted,
                   t.name, t.provisioner::text AS provisioner, t.active_version_id,
                   t.description, t.default_ttl, t.created_by, t.icon, t.user_acl,
                   t.group_acl, t.display_name, t.allow_user_cancel_workspace_jobs,
                   t.allow_user_autostart, t.allow_user_autostop, t.failure_ttl,
                   t.time_til_dormant, t.time_til_dormant_autodelete,
                   t.autostop_requirement_days_of_week, t.autostop_requirement_weeks,
                   t.autostart_block_days_of_week, t.require_active_version,
                   t.deprecated, t.activity_bump,
                   t.max_port_sharing_level::text AS max_port_sharing_level,
                   t.use_classic_parameter_flow,
                   t.cors_behavior::text AS cors_behavior,
                   t.disable_module_cache,
                   COALESCE(o.name, '') AS organization_name,
                   COALESCE(o.display_name, '') AS organization_display_name,
                   COALESCE(o.icon, '') AS organization_icon,
                   COALESCE(u.username, '') AS created_by_username,
                   COALESCE(u.avatar_url, '') AS created_by_avatar_url,
                   COALESCE(u.name, '') AS created_by_name
            FROM templates t
            LEFT JOIN organizations o ON o.id = t.organization_id
            LEFT JOIN users u ON u.id = t.created_by
            WHERE t.id = $1
            "#,
        )
        .bind(template_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(row.map(template_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_template_by_org_and_name(
        &self,
        organization_id: Uuid,
        name: &str,
    ) -> Result<Option<TemplateRecord>, StorageError> {
        let row = sqlx::query_as::<_, StoredTemplateRow>(
            r#"
            SELECT t.id, t.created_at, t.updated_at, t.organization_id, t.deleted,
                   t.name, t.provisioner::text AS provisioner, t.active_version_id,
                   t.description, t.default_ttl, t.created_by, t.icon, t.user_acl,
                   t.group_acl, t.display_name, t.allow_user_cancel_workspace_jobs,
                   t.allow_user_autostart, t.allow_user_autostop, t.failure_ttl,
                   t.time_til_dormant, t.time_til_dormant_autodelete,
                   t.autostop_requirement_days_of_week, t.autostop_requirement_weeks,
                   t.autostart_block_days_of_week, t.require_active_version,
                   t.deprecated, t.activity_bump,
                   t.max_port_sharing_level::text AS max_port_sharing_level,
                   t.use_classic_parameter_flow,
                   t.cors_behavior::text AS cors_behavior,
                   t.disable_module_cache,
                   COALESCE(o.name, '') AS organization_name,
                   COALESCE(o.display_name, '') AS organization_display_name,
                   COALESCE(o.icon, '') AS organization_icon,
                   COALESCE(u.username, '') AS created_by_username,
                   COALESCE(u.avatar_url, '') AS created_by_avatar_url,
                   COALESCE(u.name, '') AS created_by_name
            FROM templates t
            LEFT JOIN organizations o ON o.id = t.organization_id
            LEFT JOIN users u ON u.id = t.created_by
            WHERE t.organization_id = $1 AND t.name = $2 AND t.deleted = false
            "#,
        )
        .bind(organization_id)
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(row.map(template_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn insert_template(
        &self,
        input: CreateTemplateInput,
    ) -> Result<TemplateRecord, CreateTemplateStoreError> {
        let result = sqlx::query(
            r#"
            INSERT INTO templates (
                id, created_at, updated_at, organization_id, name, display_name,
                provisioner, active_version_id, description, default_ttl,
                created_by, icon, allow_user_cancel_workspace_jobs,
                allow_user_autostart, allow_user_autostop,
                failure_ttl, time_til_dormant, time_til_dormant_autodelete,
                require_active_version, activity_bump, max_port_sharing_level
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7::provisioner_type, $8, $9, $10, $11, $12, $13, $14, $15,
                $16, $17, $18, $19, $20, $21::app_sharing_level
            )
            "#,
        )
        .bind(input.id)
        .bind(input.created_at)
        .bind(input.updated_at)
        .bind(input.organization_id)
        .bind(&input.name)
        .bind(&input.display_name)
        .bind(&input.provisioner)
        .bind(input.active_version_id)
        .bind(&input.description)
        .bind(input.default_ttl)
        .bind(input.created_by)
        .bind(&input.icon)
        .bind(input.allow_user_cancel_workspace_jobs)
        .bind(input.allow_user_autostart)
        .bind(input.allow_user_autostop)
        .bind(input.failure_ttl)
        .bind(input.time_til_dormant)
        .bind(input.time_til_dormant_autodelete)
        .bind(input.require_active_version)
        .bind(input.activity_bump)
        .bind(&input.max_port_share_level)
        .execute(&self.pool)
        .await;

        match result {
            Ok(_) => {}
            Err(e) if is_unique_violation(&e) => {
                return Err(CreateTemplateStoreError::AlreadyExists);
            }
            Err(e) => return Err(CreateTemplateStoreError::Storage(storage_error(e))),
        }

        self.find_template_by_id(input.id)
            .await
            .map_err(CreateTemplateStoreError::Storage)?
            .ok_or_else(|| {
                CreateTemplateStoreError::Storage(StorageError::unavailable(
                    "template not found after insert",
                ))
            })
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_template_meta(
        &self,
        input: UpdateTemplateMetaInput,
    ) -> Result<Option<TemplateRecord>, StorageError> {
        let result = sqlx::query(
            r#"
            UPDATE templates SET
                name = $2,
                display_name = $3,
                description = $4,
                icon = $5,
                default_ttl = $6,
                activity_bump = $7,
                allow_user_autostart = $8,
                allow_user_autostop = $9,
                allow_user_cancel_workspace_jobs = $10,
                failure_ttl = $11,
                time_til_dormant = $12,
                time_til_dormant_autodelete = $13,
                require_active_version = $14,
                deprecated = $15,
                max_port_sharing_level = $16::app_sharing_level,
                cors_behavior = $17::cors_behavior,
                use_classic_parameter_flow = $18,
                disable_module_cache = $19,
                updated_at = NOW()
            WHERE id = $1 AND deleted = false
            "#,
        )
        .bind(input.template_id)
        .bind(&input.name)
        .bind(&input.display_name)
        .bind(&input.description)
        .bind(&input.icon)
        .bind(input.default_ttl)
        .bind(input.activity_bump)
        .bind(input.allow_user_autostart)
        .bind(input.allow_user_autostop)
        .bind(input.allow_user_cancel_workspace_jobs)
        .bind(input.failure_ttl)
        .bind(input.time_til_dormant)
        .bind(input.time_til_dormant_autodelete)
        .bind(input.require_active_version)
        .bind(&input.deprecation_message)
        .bind(&input.max_port_share_level)
        .bind(&input.cors_behavior)
        .bind(input.use_classic_parameter_flow)
        .bind(input.disable_module_cache)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        if result.rows_affected() == 0 {
            return Ok(None);
        }
        self.find_template_by_id(input.template_id).await
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn soft_delete_template(&self, template_id: Uuid) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "UPDATE templates SET deleted = true, updated_at = NOW() WHERE id = $1 AND deleted = false",
        )
        .bind(template_id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_template_active_version(
        &self,
        template_id: Uuid,
        active_version_id: Uuid,
    ) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "UPDATE templates SET active_version_id = $2, updated_at = NOW() WHERE id = $1",
        )
        .bind(template_id)
        .bind(active_version_id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn template_daus(&self, template_id: Uuid) -> Result<Vec<TemplateDAURow>, StorageError> {
        let rows = sqlx::query_as::<_, StoredDAURow>(
            r#"
            SELECT TO_CHAR(start_time::date, 'YYYY-MM-DD') AS date,
                   CAST(COUNT(DISTINCT user_id) AS INT) AS amount
            FROM template_usage_stats
            WHERE template_id = $1
            GROUP BY start_time::date
            ORDER BY start_time::date ASC
            "#,
        )
        .bind(template_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(rows
            .into_iter()
            .map(|r| TemplateDAURow {
                date: r.date,
                amount: r.amount,
            })
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_template_versions(
        &self,
        filter: TemplateVersionListFilter,
    ) -> Result<Vec<TemplateVersionRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredTemplateVersionRow>(
            r#"
            SELECT tv.*,
                   COALESCE(u.avatar_url, '') AS created_by_avatar_url,
                   COALESCE(u.username, '') AS created_by_username,
                   COALESCE(u.name, '') AS created_by_name
            FROM template_versions tv
            LEFT JOIN users u ON u.id = tv.created_by
            WHERE tv.template_id = $1
              AND ($2::bool OR tv.archived = false)
            ORDER BY tv.created_at DESC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(filter.template_id)
        .bind(filter.include_archived)
        .bind(if filter.limit == 0 {
            i64::MAX
        } else {
            i64::from(filter.limit)
        })
        .bind(i64::from(filter.offset))
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(rows
            .into_iter()
            .map(template_version_record_from_row)
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_template_version_by_id(
        &self,
        version_id: Uuid,
    ) -> Result<Option<TemplateVersionRecord>, StorageError> {
        let row = sqlx::query_as::<_, StoredTemplateVersionRow>(
            r#"
            SELECT tv.*,
                   COALESCE(u.avatar_url, '') AS created_by_avatar_url,
                   COALESCE(u.username, '') AS created_by_username,
                   COALESCE(u.name, '') AS created_by_name
            FROM template_versions tv
            LEFT JOIN users u ON u.id = tv.created_by
            WHERE tv.id = $1
            "#,
        )
        .bind(version_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(row.map(template_version_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_template_version_by_template_and_name(
        &self,
        template_id: Uuid,
        name: &str,
    ) -> Result<Option<TemplateVersionRecord>, StorageError> {
        let row = sqlx::query_as::<_, StoredTemplateVersionRow>(
            r#"
            SELECT tv.*,
                   COALESCE(u.avatar_url, '') AS created_by_avatar_url,
                   COALESCE(u.username, '') AS created_by_username,
                   COALESCE(u.name, '') AS created_by_name
            FROM template_versions tv
            LEFT JOIN users u ON u.id = tv.created_by
            WHERE tv.template_id = $1 AND tv.name = $2
            "#,
        )
        .bind(template_id)
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(row.map(template_version_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_template_version_by_org_and_name(
        &self,
        organization_id: Uuid,
        template_name: &str,
        version_name: &str,
    ) -> Result<Option<TemplateVersionRecord>, StorageError> {
        let row = sqlx::query_as::<_, StoredTemplateVersionRow>(
            r#"
            SELECT tv.*,
                   COALESCE(u.avatar_url, '') AS created_by_avatar_url,
                   COALESCE(u.username, '') AS created_by_username,
                   COALESCE(u.name, '') AS created_by_name
            FROM template_versions tv
            LEFT JOIN users u ON u.id = tv.created_by
            JOIN templates t ON t.id = tv.template_id
            WHERE t.organization_id = $1 AND t.name = $2 AND tv.name = $3
            "#,
        )
        .bind(organization_id)
        .bind(template_name)
        .bind(version_name)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(row.map(template_version_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_previous_template_version(
        &self,
        organization_id: Uuid,
        template_name: &str,
        version_name: &str,
    ) -> Result<Option<TemplateVersionRecord>, StorageError> {
        let row = sqlx::query_as::<_, StoredTemplateVersionRow>(
            r#"
            SELECT tv.*,
                   COALESCE(u.avatar_url, '') AS created_by_avatar_url,
                   COALESCE(u.username, '') AS created_by_username,
                   COALESCE(u.name, '') AS created_by_name
            FROM template_versions tv
            LEFT JOIN users u ON u.id = tv.created_by
            JOIN templates t ON t.id = tv.template_id
            WHERE t.organization_id = $1 AND t.name = $2
              AND tv.created_at < (
                  SELECT tv2.created_at
                  FROM template_versions tv2
                  JOIN templates t2 ON t2.id = tv2.template_id
                  WHERE t2.organization_id = $1 AND t2.name = $2 AND tv2.name = $3
                  LIMIT 1
              )
            ORDER BY tv.created_at DESC
            LIMIT 1
            "#,
        )
        .bind(organization_id)
        .bind(template_name)
        .bind(version_name)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(row.map(template_version_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn insert_template_version(
        &self,
        input: CreateTemplateVersionInput,
    ) -> Result<TemplateVersionRecord, StorageError> {
        sqlx::query(
            r#"
            INSERT INTO template_versions (
                id, template_id, organization_id, created_at, updated_at,
                name, message, readme, job_id, created_by, source_example_id
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
        )
        .bind(input.id)
        .bind(input.template_id)
        .bind(input.organization_id)
        .bind(input.created_at)
        .bind(input.updated_at)
        .bind(&input.name)
        .bind(&input.message)
        .bind(&input.readme)
        .bind(input.job_id)
        .bind(input.created_by)
        .bind(input.source_example_id.as_deref())
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        self.find_template_version_by_id(input.id)
            .await?
            .ok_or_else(|| StorageError::unavailable("template version not found after insert"))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_template_version(
        &self,
        version_id: Uuid,
        name: &str,
        message: &str,
    ) -> Result<Option<TemplateVersionRecord>, StorageError> {
        let result = sqlx::query(
            "UPDATE template_versions SET name = $2, message = $3, updated_at = NOW() WHERE id = $1",
        )
        .bind(version_id)
        .bind(name)
        .bind(message)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        if result.rows_affected() == 0 {
            return Ok(None);
        }
        self.find_template_version_by_id(version_id).await
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn archive_template_version(&self, version_id: Uuid) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "UPDATE template_versions SET archived = true, updated_at = NOW() WHERE id = $1 AND archived = false",
        )
        .bind(version_id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn unarchive_template_version(&self, version_id: Uuid) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "UPDATE template_versions SET archived = false, updated_at = NOW() WHERE id = $1 AND archived = true",
        )
        .bind(version_id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_template_version_parameters(
        &self,
        version_id: Uuid,
    ) -> Result<Vec<TemplateVersionParameterRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredTemplateVersionParameterRow>(
            "SELECT template_version_id, name, description, type, mutable, default_value, icon, options, validation_regex, validation_min, validation_max, validation_error, validation_monotonic, required, display_name, display_order, ephemeral, form_type::text AS form_type FROM template_version_parameters WHERE template_version_id = $1 ORDER BY display_order ASC",
        )
        .bind(version_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(rows
            .into_iter()
            .map(template_version_parameter_from_row)
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_template_version_variables(
        &self,
        version_id: Uuid,
    ) -> Result<Vec<TemplateVersionVariableRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredTemplateVersionVariableRow>(
            "SELECT * FROM template_version_variables WHERE template_version_id = $1 ORDER BY name ASC",
        )
        .bind(version_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(rows
            .into_iter()
            .map(template_version_variable_from_row)
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_template_version_presets(
        &self,
        version_id: Uuid,
    ) -> Result<Vec<TemplateVersionPresetRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredTemplateVersionPresetRow>(
            "SELECT * FROM template_version_presets WHERE template_version_id = $1 ORDER BY name ASC",
        )
        .bind(version_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(rows
            .into_iter()
            .map(|r| TemplateVersionPresetRecord {
                id: r.id,
                template_version_id: r.template_version_id,
                name: r.name,
                created_at: r.created_at,
                is_default: r.is_default,
                description: r.description,
                icon: r.icon,
            })
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_template_version_preset_parameters(
        &self,
        preset_id: Uuid,
    ) -> Result<Vec<TemplateVersionPresetParameterRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredTemplateVersionPresetParameterRow>(
            "SELECT * FROM template_version_preset_parameters WHERE template_version_preset_id = $1 ORDER BY name ASC",
        )
        .bind(preset_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(rows
            .into_iter()
            .map(|r| TemplateVersionPresetParameterRecord {
                id: r.id,
                template_version_preset_id: r.template_version_preset_id,
                name: r.name,
                value: r.value,
            })
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn create_provisioner_job(
        &self,
        input: CreateProvisionerJobInput,
    ) -> Result<TemplateProvisionerJobRecord, StorageError> {
        let tags_json = serde_json::to_value(&input.tags)
            .map_err(|e| StorageError::unavailable(format!("serialize tags: {e}")))?;
        sqlx::query(
            r#"
            INSERT INTO provisioner_jobs (
                id, created_at, updated_at, organization_id, initiator_id,
                provisioner, file_id, type, input, tags
            ) VALUES ($1, $2, $3, $4, $5, $6::provisioner_type, $7, $8, $9, $10)
            "#,
        )
        .bind(input.id)
        .bind(input.created_at)
        .bind(input.updated_at)
        .bind(input.organization_id)
        .bind(input.initiator_id)
        .bind(&input.provisioner)
        .bind(input.file_id)
        .bind(&input.job_type)
        .bind(&input.input)
        .bind(&tags_json)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        self.find_provisioner_job(input.id)
            .await?
            .ok_or_else(|| StorageError::unavailable("provisioner job not found after insert"))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_provisioner_job(
        &self,
        job_id: Uuid,
    ) -> Result<Option<TemplateProvisionerJobRecord>, StorageError> {
        let row = sqlx::query_as::<_, StoredTemplateProvisionerJobRow>(
            r#"
            SELECT id, created_at, updated_at, started_at, canceled_at, completed_at,
                   error, organization_id, initiator_id, provisioner::text AS provisioner,
                   CASE
                       WHEN completed_at IS NOT NULL AND canceled_at IS NOT NULL THEN 'canceled'
                       WHEN completed_at IS NOT NULL AND error != '' THEN 'failed'
                       WHEN completed_at IS NOT NULL THEN 'succeeded'
                       WHEN canceled_at IS NOT NULL THEN 'canceling'
                       WHEN started_at IS NOT NULL THEN 'running'
                       ELSE 'pending'
                   END AS job_status,
                   file_id, type, input, worker_id, tags
            FROM provisioner_jobs
            WHERE id = $1
            "#,
        )
        .bind(job_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(row.map(template_provisioner_job_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn cancel_template_provisioner_job(&self, job_id: Uuid) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "UPDATE provisioner_jobs SET canceled_at = NOW(), completed_at = CASE WHEN worker_id IS NULL THEN NOW() ELSE completed_at END, updated_at = NOW() WHERE id = $1 AND canceled_at IS NULL AND completed_at IS NULL",
        )
        .bind(job_id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn archive_unused_template_versions(
        &self,
        template_id: Uuid,
        all: bool,
    ) -> Result<Vec<Uuid>, StorageError> {
        // Archive template versions that are not actively used.
        // If `all` is false, only archive versions whose provisioner job failed.
        let rows: Vec<(Uuid,)> = if all {
            sqlx::query_as(
                r#"
                UPDATE template_versions
                SET archived = true, updated_at = NOW()
                WHERE template_id = $1
                  AND archived = false
                  AND id != (SELECT active_version_id FROM templates WHERE id = $1)
                RETURNING id
                "#,
            )
            .bind(template_id)
            .fetch_all(&self.pool)
            .await
            .map_err(storage_error)?
        } else {
            sqlx::query_as(
                r#"
                UPDATE template_versions
                SET archived = true, updated_at = NOW()
                WHERE template_id = $1
                  AND archived = false
                  AND id != (SELECT active_version_id FROM templates WHERE id = $1)
                  AND id IN (
                      SELECT tv.id FROM template_versions tv
                      JOIN provisioner_jobs pj ON pj.id = tv.job_id
                      WHERE tv.template_id = $1
                        AND pj.completed_at IS NOT NULL
                        AND pj.error <> ''
                        AND pj.canceled_at IS NULL
                  )
                RETURNING id
                "#,
            )
            .bind(template_id)
            .fetch_all(&self.pool)
            .await
            .map_err(storage_error)?
        };
        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_previous_template_version(
        &self,
        organization_id: Uuid,
        name: &str,
        template_id: Option<Uuid>,
    ) -> Result<Option<TemplateVersionRecord>, StorageError> {
        // Find the template version with matching name, then get the one
        // created immediately before it (by created_at).
        let row = if let Some(tid) = template_id {
            sqlx::query_as::<_, StoredTemplateVersionRow>(
                r#"
                SELECT tv.*,
                       COALESCE(u.avatar_url, '') AS created_by_avatar_url,
                       COALESCE(u.username, '') AS created_by_username,
                       COALESCE(u.name, '') AS created_by_name
                FROM template_versions tv
                LEFT JOIN users u ON u.id = tv.created_by
                WHERE tv.organization_id = $1
                  AND tv.template_id = $3
                  AND tv.created_at < (
                      SELECT created_at FROM template_versions
                      WHERE organization_id = $1 AND name = $2 AND template_id = $3
                      ORDER BY created_at DESC
                      LIMIT 1
                  )
                ORDER BY tv.created_at DESC
                LIMIT 1
                "#,
            )
            .bind(organization_id)
            .bind(name)
            .bind(tid)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_error)?
        } else {
            sqlx::query_as::<_, StoredTemplateVersionRow>(
                r#"
                SELECT tv.*,
                       COALESCE(u.avatar_url, '') AS created_by_avatar_url,
                       COALESCE(u.username, '') AS created_by_username,
                       COALESCE(u.name, '') AS created_by_name
                FROM template_versions tv
                LEFT JOIN users u ON u.id = tv.created_by
                WHERE tv.organization_id = $1
                  AND tv.created_at < (
                      SELECT created_at FROM template_versions
                      WHERE organization_id = $1 AND name = $2
                      ORDER BY created_at DESC
                      LIMIT 1
                  )
                ORDER BY tv.created_at DESC
                LIMIT 1
                "#,
            )
            .bind(organization_id)
            .bind(name)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_error)?
        };
        Ok(row.map(template_version_record_from_row))
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

#[async_trait]
impl ProvisionerStore for PostgresStore {
    // ── Jobs ──────────────────────────────────────────────────

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn acquire_provisioner_job(
        &self,
        input: AcquireProvisionerJobInput,
    ) -> Result<Option<ProvisionerJobRecord>, StorageError> {
        let provisioner_types: Vec<String> = input.types.iter().map(|t| t.to_string()).collect();

        // Atomically find and lock one pending job using FOR UPDATE SKIP LOCKED.
        // Tag matching: the job's tags must be a subset of the daemon's tags.
        let row = sqlx::query_as::<_, StoredProvisionerJobRow>(
            "UPDATE provisioner_jobs
             SET started_at = $1,
                 updated_at = $1,
                 worker_id = $2
             WHERE id = (
                 SELECT id
                 FROM provisioner_jobs
                 WHERE started_at IS NULL
                   AND completed_at IS NULL
                   AND canceled_at IS NULL
                   AND organization_id = $3
                   AND provisioner::TEXT = ANY($4)
                   AND tags <@ $5::JSONB
                 ORDER BY created_at ASC
                 LIMIT 1
                 FOR UPDATE SKIP LOCKED
             )
             RETURNING id, created_at, updated_at, started_at, canceled_at,
                       completed_at, error, error_code, organization_id,
                       initiator_id, provisioner::TEXT, storage_method::TEXT,
                       file_id, \"type\"::TEXT AS job_type, input, tags,
                       trace_metadata, worker_id, job_status::TEXT,
                       logs_overflowed, logs_length",
        )
        .bind(input.started_at)
        .bind(input.worker_id)
        .bind(input.organization_id)
        .bind(&provisioner_types)
        .bind(&input.provisioner_tags)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        row.map(provisioner_job_from_row).transpose()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_provisioner_job_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<ProvisionerJobRecord>, StorageError> {
        let row = sqlx::query_as::<_, StoredProvisionerJobRow>(
            "SELECT id, created_at, updated_at, started_at, canceled_at,
                    completed_at, error, error_code, organization_id,
                    initiator_id, provisioner::TEXT, storage_method::TEXT,
                    file_id, \"type\"::TEXT AS job_type, input, tags,
                    trace_metadata, worker_id, job_status::TEXT,
                    logs_overflowed, logs_length
             FROM provisioner_jobs
             WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        row.map(provisioner_job_from_row).transpose()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_provisioner_jobs_by_ids(
        &self,
        ids: &[Uuid],
    ) -> Result<Vec<ProvisionerJobRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredProvisionerJobRow>(
            "SELECT id, created_at, updated_at, started_at, canceled_at,
                    completed_at, error, error_code, organization_id,
                    initiator_id, provisioner::TEXT, storage_method::TEXT,
                    file_id, \"type\"::TEXT AS job_type, input, tags,
                    trace_metadata, worker_id, job_status::TEXT,
                    logs_overflowed, logs_length
             FROM provisioner_jobs
             WHERE id = ANY($1)
             ORDER BY created_at ASC",
        )
        .bind(ids)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        rows.into_iter()
            .map(provisioner_job_from_row)
            .collect::<Result<Vec<_>, _>>()
    }

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn insert_provisioner_job(
        &self,
        input: InsertProvisionerJobInput,
    ) -> Result<ProvisionerJobRecord, StorageError> {
        let row = sqlx::query_as::<_, StoredProvisionerJobRow>(
            "INSERT INTO provisioner_jobs (
                 id, created_at, updated_at, organization_id, initiator_id,
                 provisioner, storage_method, file_id, \"type\", input,
                 tags, trace_metadata
             ) VALUES (
                 $1, $2, $2, $3, $4,
                 $5::provisioner_type, $6::provisioner_storage_method,
                 $7, $8::provisioner_job_type, $9, $10, $11
             )
             RETURNING id, created_at, updated_at, started_at, canceled_at,
                       completed_at, error, error_code, organization_id,
                       initiator_id, provisioner::TEXT, storage_method::TEXT,
                       file_id, \"type\"::TEXT AS job_type, input, tags,
                       trace_metadata, worker_id, job_status::TEXT,
                       logs_overflowed, logs_length",
        )
        .bind(input.id)
        .bind(input.created_at)
        .bind(input.organization_id)
        .bind(input.initiator_id)
        .bind(input.provisioner.as_str())
        .bind(input.storage_method.as_str())
        .bind(input.file_id)
        .bind(input.job_type.as_str())
        .bind(&input.input)
        .bind(&input.tags)
        .bind(&input.trace_metadata)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        provisioner_job_from_row(row)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_provisioner_job_by_id(
        &self,
        id: Uuid,
        updated_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        sqlx::query("UPDATE provisioner_jobs SET updated_at = $1 WHERE id = $2")
            .bind(updated_at)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn update_provisioner_job_with_complete_by_id(
        &self,
        input: CompleteProvisionerJobInput,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "UPDATE provisioner_jobs
             SET updated_at = $1,
                 completed_at = $2,
                 error = $3,
                 error_code = $4
             WHERE id = $5",
        )
        .bind(input.updated_at)
        .bind(input.completed_at)
        .bind(&input.error)
        .bind(&input.error_code)
        .bind(input.id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn update_provisioner_job_with_cancel_by_id(
        &self,
        input: CancelProvisionerJobInput,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "UPDATE provisioner_jobs
             SET canceled_at = $1,
                 completed_at = COALESCE($2, completed_at),
                 updated_at = $1
             WHERE id = $3",
        )
        .bind(input.canceled_at)
        .bind(input.completed_at)
        .bind(input.id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn get_provisioner_jobs_to_be_reaped(
        &self,
        input: GetJobsToBeReapedInput,
    ) -> Result<Vec<ProvisionerJobRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredProvisionerJobRow>(
            "SELECT id, created_at, updated_at, started_at, canceled_at,
                    completed_at, error, error_code, organization_id,
                    initiator_id, provisioner::TEXT, storage_method::TEXT,
                    file_id, \"type\"::TEXT AS job_type, input, tags,
                    trace_metadata, worker_id, job_status::TEXT,
                    logs_overflowed, logs_length
             FROM provisioner_jobs
             WHERE (
                 -- Pending too long
                 (started_at IS NULL AND completed_at IS NULL AND created_at < $1)
                 OR
                 -- Running but no heartbeat (hung)
                 (started_at IS NOT NULL AND completed_at IS NULL AND updated_at < $2)
             )
             ORDER BY created_at ASC
             LIMIT $3",
        )
        .bind(input.pending_since)
        .bind(input.hung_since)
        .bind(input.max_jobs)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        rows.into_iter()
            .map(provisioner_job_from_row)
            .collect::<Result<Vec<_>, _>>()
    }

    // ── Logs ─────────────────────────────────────────────────

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn insert_provisioner_job_logs(
        &self,
        input: InsertProvisionerJobLogsInput,
    ) -> Result<Vec<ProvisionerLogRecord>, StorageError> {
        let n = input.created_at.len();
        if input.source.len() != n
            || input.level.len() != n
            || input.stage.len() != n
            || input.output.len() != n
        {
            return Err(StorageError::invalid_data(
                "all log input vectors must have the same length".to_string(),
            ));
        }
        let job_ids: Vec<Uuid> = vec![input.job_id; n];
        let sources: Vec<String> = input.source.iter().map(|s| s.to_string()).collect();
        let levels: Vec<String> = input.level.iter().map(|l| l.to_string()).collect();

        let mut transaction = self.pool.begin().await.map_err(storage_error)?;

        let rows = sqlx::query_as::<_, StoredProvisionerJobLogRow>(
            "INSERT INTO provisioner_job_logs (job_id, created_at, source, level, stage, output)
             SELECT * FROM UNNEST($1::UUID[], $2::TIMESTAMPTZ[], $3::log_source[], $4::log_level[], $5::VARCHAR[], $6::VARCHAR[])
             RETURNING id, job_id, created_at, source::TEXT, level::TEXT, stage, output",
        )
        .bind(&job_ids)
        .bind(&input.created_at)
        .bind(&sources)
        .bind(&levels)
        .bind(&input.stage)
        .bind(&input.output)
        .fetch_all(&mut *transaction)
        .await
        .map_err(storage_error)?;

        // Update logs_length on the parent job (tracks total bytes, not entry count).
        let total_bytes: usize = input.output.iter().map(|o| o.len()).sum();
        let log_bytes = i32::try_from(total_bytes).unwrap_or(i32::MAX);
        sqlx::query(
            "UPDATE provisioner_jobs
             SET logs_length = logs_length + $1
             WHERE id = $2",
        )
        .bind(log_bytes)
        .bind(input.job_id)
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;

        transaction.commit().await.map_err(storage_error)?;

        rows.into_iter()
            .map(provisioner_job_log_from_row)
            .collect::<Result<Vec<_>, _>>()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_provisioner_logs_after_id(
        &self,
        job_id: Uuid,
        after_id: i64,
    ) -> Result<Vec<ProvisionerLogRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredProvisionerJobLogRow>(
            "SELECT id, job_id, created_at, source::TEXT, level::TEXT, stage, output
             FROM provisioner_job_logs
             WHERE job_id = $1 AND id > $2
             ORDER BY id ASC",
        )
        .bind(job_id)
        .bind(after_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        rows.into_iter()
            .map(provisioner_job_log_from_row)
            .collect::<Result<Vec<_>, _>>()
    }

    // ── Timings ──────────────────────────────────────────────

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn insert_provisioner_job_timings(
        &self,
        input: InsertProvisionerJobTimingsInput,
    ) -> Result<Vec<ProvisionerTimingRecord>, StorageError> {
        let n = input.started_at.len();
        if input.ended_at.len() != n
            || input.stage.len() != n
            || input.source.len() != n
            || input.action.len() != n
            || input.resource.len() != n
        {
            return Err(StorageError::invalid_data(
                "all timing input vectors must have the same length".to_string(),
            ));
        }
        let job_ids: Vec<Uuid> = vec![input.job_id; n];
        let stages: Vec<String> = input.stage.iter().map(|s| s.to_string()).collect();

        let rows = sqlx::query_as::<_, StoredProvisionerJobTimingRow>(
            "INSERT INTO provisioner_job_timings (job_id, started_at, ended_at, stage, source, action, resource)
             SELECT * FROM UNNEST($1::UUID[], $2::TIMESTAMPTZ[], $3::TIMESTAMPTZ[], $4::provisioner_job_timing_stage[], $5::TEXT[], $6::TEXT[], $7::TEXT[])
             RETURNING job_id, started_at, ended_at, stage::TEXT, source, action, resource",
        )
        .bind(&job_ids)
        .bind(&input.started_at)
        .bind(&input.ended_at)
        .bind(&stages)
        .bind(&input.source)
        .bind(&input.action)
        .bind(&input.resource)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        rows.into_iter()
            .map(provisioner_job_timing_from_row)
            .collect::<Result<Vec<_>, _>>()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_provisioner_job_timings_by_job_id(
        &self,
        job_id: Uuid,
    ) -> Result<Vec<ProvisionerTimingRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredProvisionerJobTimingRow>(
            "SELECT job_id, started_at, ended_at, stage::TEXT, source, action, resource
             FROM provisioner_job_timings
             WHERE job_id = $1
             ORDER BY started_at ASC",
        )
        .bind(job_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        rows.into_iter()
            .map(provisioner_job_timing_from_row)
            .collect::<Result<Vec<_>, _>>()
    }

    // ── Daemons ──────────────────────────────────────────────

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn upsert_provisioner_daemon(
        &self,
        input: UpsertProvisionerDaemonInput,
    ) -> Result<ProvisionerDaemonRecord, StorageError> {
        let tags_json = serde_json::to_string(&input.tags)
            .map_err(|e| StorageError::invalid_data(e.to_string()))?;

        let row = sqlx::query_as::<_, StoredFullProvisionerDaemonRow>(
            "INSERT INTO provisioner_daemons (
                 name, provisioners, tags_json, last_seen_at, version,
                 organization_id, api_version, key_id
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (organization_id, name) DO UPDATE SET
                 provisioners = EXCLUDED.provisioners,
                 tags_json = EXCLUDED.tags_json,
                 last_seen_at = EXCLUDED.last_seen_at,
                 version = EXCLUDED.version,
                 api_version = EXCLUDED.api_version,
                 key_id = EXCLUDED.key_id
             RETURNING id, organization_id, created_at, last_seen_at,
                       name, version, api_version, provisioners,
                       tags_json, key_id",
        )
        .bind(&input.name)
        .bind(&input.provisioners)
        .bind(&tags_json)
        .bind(input.last_seen_at)
        .bind(&input.version)
        .bind(input.organization_id)
        .bind(&input.api_version)
        .bind(input.key_id)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        full_provisioner_daemon_from_row(row)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_provisioner_daemon_last_seen_at(
        &self,
        id: Uuid,
        last_seen_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        sqlx::query("UPDATE provisioner_daemons SET last_seen_at = $1 WHERE id = $2")
            .bind(last_seen_at)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_provisioner_daemons_by_organization(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<ProvisionerDaemonRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredFullProvisionerDaemonRow>(
            "SELECT id, organization_id, created_at, last_seen_at,
                    name, version, api_version, provisioners,
                    tags_json, key_id
             FROM provisioner_daemons
             WHERE organization_id = $1
             ORDER BY created_at ASC",
        )
        .bind(organization_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        rows.into_iter()
            .map(full_provisioner_daemon_from_row)
            .collect::<Result<Vec<_>, _>>()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_old_provisioner_daemons(&self) -> Result<(), StorageError> {
        sqlx::query(
            "DELETE FROM provisioner_daemons
             WHERE last_seen_at IS NOT NULL AND last_seen_at < NOW() - INTERVAL '7 days'",
        )
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    // ── Keys ─────────────────────────────────────────────────

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn insert_provisioner_key(
        &self,
        input: InsertProvisionerKeyInput,
    ) -> Result<ProvisionerKeyRecord, StorageError> {
        let row = sqlx::query_as::<_, StoredProvisionerKeyRow>(
            "INSERT INTO provisioner_keys (id, created_at, organization_id, name, hashed_secret, tags)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING id, created_at, organization_id, name, hashed_secret, tags",
        )
        .bind(input.id)
        .bind(input.created_at)
        .bind(input.organization_id)
        .bind(&input.name)
        .bind(&input.hashed_secret)
        .bind(&input.tags)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(provisioner_key_from_row(row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_provisioner_key_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<ProvisionerKeyRecord>, StorageError> {
        let row = sqlx::query_as::<_, StoredProvisionerKeyRow>(
            "SELECT id, created_at, organization_id, name, hashed_secret, tags
             FROM provisioner_keys
             WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(row.map(provisioner_key_from_row))
    }

    #[instrument(skip(self, hashed_secret), err(level = tracing::Level::WARN))]
    async fn get_provisioner_key_by_hashed_secret(
        &self,
        hashed_secret: &[u8],
    ) -> Result<Option<ProvisionerKeyRecord>, StorageError> {
        let row = sqlx::query_as::<_, StoredProvisionerKeyRow>(
            "SELECT id, created_at, organization_id, name, hashed_secret, tags
             FROM provisioner_keys
             WHERE hashed_secret = $1",
        )
        .bind(hashed_secret)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(row.map(provisioner_key_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_provisioner_key_by_name(
        &self,
        organization_id: Uuid,
        name: &str,
    ) -> Result<Option<ProvisionerKeyRecord>, StorageError> {
        let row = sqlx::query_as::<_, StoredProvisionerKeyRow>(
            "SELECT id, created_at, organization_id, name, hashed_secret, tags
             FROM provisioner_keys
             WHERE organization_id = $1 AND name = $2",
        )
        .bind(organization_id)
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(row.map(provisioner_key_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_provisioner_keys_by_organization(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<ProvisionerKeyRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredProvisionerKeyRow>(
            "SELECT id, created_at, organization_id, name, hashed_secret, tags
             FROM provisioner_keys
             WHERE organization_id = $1
             ORDER BY name ASC",
        )
        .bind(organization_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows.into_iter().map(provisioner_key_from_row).collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_provisioner_key(&self, id: Uuid) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM provisioner_keys WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;

        Ok(result.rows_affected() > 0)
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
        "permanent_failure" => NotificationMessageStatus::Failed,
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
                created_by: user_id,
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
                created_by: user_id,
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
                created_by: user_id,
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
                created_by: user_id,
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
                created_by: user_id,
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
                created_by: user_id,
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
}
