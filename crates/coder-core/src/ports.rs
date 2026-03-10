//! Storage contracts for the Rust backend slice.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::api::{
    AuditLogResponse, ChatMessageVisibility, ChatStatus, DAUsResponse, ExternalAuthAppInstallation,
    ExternalAuthUser, GetUserStatusCountsResponse, HealthSettings, InboxNotification,
    InsightsReportInterval, NotificationPreference, NotificationTemplate, NotificationsSettings,
    TaskStatus, TemplateInsightsIntervalReport, TemplateInsightsResponse,
    UserActivityInsightsResponse, UserLatencyInsightsResponse,
};
use crate::identity::{
    ApiKeyListFilter, ApiKeyRecord, ApiKeyWithOwnerRecord, AuthenticatedUser, CreateApiKeyInput,
    CreateApiKeyStoreError, CreateFirstUserInput, CreateFirstUserStoreError, CreateGroupInput,
    CreateOAuth2ProviderAppInput, CreateOAuth2ProviderAppTokenInput, CreateUserInput,
    CreateUserStoreError, CustomRoleRecord, FirstUserRecord, GroupMemberRecord, GroupRecord,
    InsertOrganizationMemberError, NotificationMessageRecord, OAuth2ProviderAppCodeRecord,
    OAuth2ProviderAppRecord, OAuth2ProviderAppSecretRecord, OAuth2ProviderAppTokenRecord,
    OrganizationMemberListFilter, OrganizationMemberRecord, OrganizationRecord, PasswordUserRecord,
    TokenConfigRecord, UpdateOAuth2ProviderAppInput, UpsertCustomRoleInput, UpsertUserLinkInput,
    UserAppearanceRecord, UserConfigRecord, UserDeletedRecord, UserLinkRecord, UserListFilter,
    UserPreferenceRecord, UserRecord, UserStatus, UserStatusChangeRecord,
};
use crate::provisioner::{
    AcquireProvisionerJobInput, CancelProvisionerJobInput, CompleteProvisionerJobInput,
    GetJobsToBeReapedInput, InsertProvisionerJobInput, InsertProvisionerJobLogsInput,
    InsertProvisionerJobTimingsInput, InsertProvisionerKeyInput, ProvisionerDaemonRecord,
    ProvisionerJobLogRecord as ProvisionerLogRecord, ProvisionerJobRecord,
    ProvisionerJobTimingRecord as ProvisionerTimingRecord, ProvisionerKeyRecord,
    UpsertProvisionerDaemonInput,
};
use crate::template::{
    CreateProvisionerJobInput, CreateTemplateInput, CreateTemplateStoreError,
    CreateTemplateVersionInput, ProvisionerJobRecord as TemplateProvisionerJobRecord,
    TemplateDAURow, TemplateListFilter, TemplateRecord, TemplateVersionListFilter,
    TemplateVersionParameterRecord, TemplateVersionPresetParameterRecord,
    TemplateVersionPresetRecord, TemplateVersionRecord, TemplateVersionVariableRecord,
    UpdateTemplateMetaInput,
};

// ---------------------------------------------------------------------------
// Task & Chat domain records
// ---------------------------------------------------------------------------

/// A task record as stored in the database.
#[derive(Clone, Debug)]
pub struct TaskRecord {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub owner_id: Uuid,
    pub name: String,
    pub display_name: String,
    pub workspace_id: Option<Uuid>,
    pub template_version_id: Uuid,
    pub template_parameters: Value,
    pub prompt: String,
    pub status: TaskStatus,
    pub created_at: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,
}

/// Input for creating a new task.
#[derive(Clone, Debug)]
pub struct InsertTaskInput {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub owner_id: Uuid,
    pub name: String,
    pub display_name: String,
    pub template_version_id: Uuid,
    pub template_parameters: Value,
    pub prompt: String,
    pub created_at: OffsetDateTime,
}

/// Filter for listing tasks.
#[derive(Clone, Debug, Default)]
pub struct TaskListFilter {
    pub owner_id: Option<Uuid>,
    pub organization_id: Option<Uuid>,
    pub status: Option<TaskStatus>,
}

/// A task log snapshot record.
#[derive(Clone, Debug)]
pub struct TaskSnapshotRecord {
    pub task_id: Uuid,
    pub log_snapshot: Value,
    pub log_snapshot_created_at: OffsetDateTime,
}

/// A chat record as stored in the database.
#[derive(Clone, Debug)]
pub struct ChatRecord {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub workspace_id: Option<Uuid>,
    pub title: String,
    pub status: ChatStatus,
    pub last_error: Option<String>,
    pub parent_chat_id: Option<Uuid>,
    pub root_chat_id: Option<Uuid>,
    pub last_model_config_id: Uuid,
    pub archived: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// Input for creating a new chat.
#[derive(Clone, Debug)]
pub struct InsertChatInput {
    pub owner_id: Uuid,
    pub workspace_id: Option<Uuid>,
    pub parent_chat_id: Option<Uuid>,
    pub root_chat_id: Option<Uuid>,
    pub last_model_config_id: Uuid,
    pub title: String,
}

/// A chat message record as stored in the database.
#[derive(Clone, Debug)]
pub struct ChatMessageRecord {
    pub id: i64,
    pub chat_id: Uuid,
    pub model_config_id: Option<Uuid>,
    pub created_at: OffsetDateTime,
    pub role: String,
    pub content: Option<Value>,
    pub visibility: ChatMessageVisibility,
    pub input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
    pub total_tokens: Option<i64>,
    pub reasoning_tokens: Option<i64>,
    pub cache_creation_tokens: Option<i64>,
    pub cache_read_tokens: Option<i64>,
    pub context_limit: Option<i64>,
    pub compressed: bool,
}

/// Input for inserting a chat message.
#[derive(Clone, Debug)]
pub struct InsertChatMessageInput {
    pub chat_id: Uuid,
    pub model_config_id: Option<Uuid>,
    pub role: String,
    pub content: Option<Value>,
    pub visibility: ChatMessageVisibility,
}

/// A chat queued message record.
#[derive(Clone, Debug)]
pub struct ChatQueuedMessageRecord {
    pub id: i64,
    pub chat_id: Uuid,
    pub content: Value,
    pub created_at: OffsetDateTime,
}

/// A chat file record as stored in the database.
#[derive(Clone, Debug)]
pub struct ChatFileRecord {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub organization_id: Uuid,
    pub created_at: OffsetDateTime,
    pub name: String,
    pub mimetype: String,
    pub data: Vec<u8>,
}

/// Input for inserting a new chat file.
#[derive(Clone, Debug)]
pub struct InsertChatFileInput {
    pub owner_id: Uuid,
    pub organization_id: Uuid,
    pub name: String,
    pub mimetype: String,
    pub data: Vec<u8>,
}

/// Deployment metadata required by the HTTP layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeploymentMetadata {
    /// Stable deployment identifier.
    pub deployment_id: Uuid,
}

/// Pagination and search filter for `GET /api/v2/audit`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuditLogListFilter {
    /// Search query applied to descriptions, targets, and actor usernames.
    pub search: String,
    /// Page limit.
    pub limit: u32,
    /// Page offset.
    pub offset: u32,
}

/// Persisted audit event inserted either by handlers or the audit sink.
#[derive(Clone, Debug, PartialEq)]
pub struct PersistAuditLogInput {
    /// Stable audit event identifier.
    pub id: Uuid,
    /// Request identifier when one exists.
    pub request_id: Option<Uuid>,
    /// Event timestamp.
    pub time: OffsetDateTime,
    /// Client IP address when known.
    pub ip: String,
    /// Client user agent when known.
    pub user_agent: String,
    /// Audited resource type.
    pub resource_type: String,
    /// Audited resource identifier.
    pub resource_id: Option<Uuid>,
    /// Human-readable resource target.
    pub resource_target: String,
    /// Optional resource icon.
    pub resource_icon: String,
    /// Audited action.
    pub action: String,
    /// Structured diff payload.
    pub diff: Value,
    /// HTTP status code associated with the action.
    pub status_code: i32,
    /// Extra structured fields.
    pub additional_fields: Value,
    /// Human-readable description.
    pub description: String,
    /// Optional deep link to the resource.
    pub resource_link: String,
    /// Whether the target resource was deleted.
    pub is_deleted: bool,
    /// Organization scope when one exists.
    pub organization_id: Option<Uuid>,
    /// Actor user ID when one exists.
    pub user_id: Option<Uuid>,
}

/// Stored git SSH keypair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitSshKeyRecord {
    /// Owning user identifier.
    pub user_id: Uuid,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Update time.
    pub updated_at: OffsetDateTime,
    /// Public key in OpenSSH format.
    pub public_key: String,
    /// Private key in OpenSSH format.
    pub private_key: String,
}

/// Stored external-auth link for one user and provider.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalAuthLinkRecord {
    /// Provider identifier.
    pub provider_id: String,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Update time.
    pub updated_at: OffsetDateTime,
    /// Whether the link includes a refresh token.
    pub has_refresh_token: bool,
    /// Access token expiry time.
    pub expires: OffsetDateTime,
    /// OAuth2 access token.
    pub access_token: String,
    /// OAuth2 refresh token.
    pub refresh_token: String,
    /// OAuth2 token type.
    pub token_type: String,
    /// Granted OAuth2 scopes.
    pub scopes: Vec<String>,
    /// Whether the link currently validates.
    pub authenticated: bool,
    /// Validation error text.
    pub validate_error: String,
    /// Cached refresh failure reason when a refresh token becomes invalid.
    pub refresh_error: String,
    /// Last time the provider-side state was validated.
    pub last_validated_at: Option<OffsetDateTime>,
    /// Last time the token was refreshed successfully.
    pub last_refreshed_at: Option<OffsetDateTime>,
    /// Linked provider user when known.
    pub user: Option<ExternalAuthUser>,
    /// App-installation metadata when known.
    pub installations: Vec<ExternalAuthAppInstallation>,
    /// Whether the user can install the provider app.
    pub app_installable: bool,
}

/// External-auth link data persisted after callback or device exchange.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpsertExternalAuthLinkInput {
    /// Provider identifier.
    pub provider_id: String,
    /// OAuth2 access token.
    pub access_token: String,
    /// OAuth2 refresh token.
    pub refresh_token: String,
    /// OAuth2 token type.
    pub token_type: String,
    /// Granted OAuth2 scopes.
    pub scopes: Vec<String>,
    /// Expiry time for the access token.
    pub expires_at: OffsetDateTime,
    /// Whether the link currently validates against the provider.
    pub authenticated: bool,
    /// Validation error text when authentication could not be verified.
    pub validate_error: String,
    /// Cached refresh failure reason when refresh failed permanently.
    pub refresh_error: String,
    /// Last time the provider-side state was validated.
    pub last_validated_at: Option<OffsetDateTime>,
    /// Last time the token was refreshed successfully.
    pub last_refreshed_at: Option<OffsetDateTime>,
    /// Linked provider user when known.
    pub user: Option<ExternalAuthUser>,
    /// Provider app-installation metadata when known.
    pub installations: Vec<ExternalAuthAppInstallation>,
    /// Whether the provider app can be installed for the account.
    pub app_installable: bool,
}

/// Upsert payload for one workspace used by deployment stats aggregation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceStatsWorkspaceInput {
    /// Workspace identifier.
    pub id: Uuid,
    /// Whether the workspace has been deleted.
    pub deleted: bool,
}

/// Upsert payload for one provisioner job used by deployment stats aggregation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvisionerJobStatsInput {
    /// Job identifier.
    pub id: Uuid,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Update time.
    pub updated_at: OffsetDateTime,
    /// Job start time.
    pub started_at: Option<OffsetDateTime>,
    /// Job cancellation time.
    pub canceled_at: Option<OffsetDateTime>,
    /// Job completion time.
    pub completed_at: Option<OffsetDateTime>,
    /// Error payload.
    pub error: String,
}

/// Upsert payload for one workspace build used by deployment stats aggregation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceBuildStatsInput {
    /// Build identifier.
    pub id: Uuid,
    /// Workspace identifier.
    pub workspace_id: Uuid,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Update time.
    pub updated_at: OffsetDateTime,
    /// Build sequence number.
    pub build_number: i64,
    /// Transition string such as `start` or `stop`.
    pub transition: String,
    /// Backing job identifier when one exists.
    pub job_id: Option<Uuid>,
}

/// One raw agent-stat sample used by deployment stats aggregation.
#[derive(Clone, Debug, PartialEq)]
pub struct WorkspaceAgentStatInput {
    /// Sample identifier.
    pub id: Uuid,
    /// Sample creation time.
    pub created_at: OffsetDateTime,
    /// Owning user when known.
    pub user_id: Option<Uuid>,
    /// Workspace when known.
    pub workspace_id: Option<Uuid>,
    /// Template when known.
    pub template_id: Option<Uuid>,
    /// Agent identifier.
    pub agent_id: Uuid,
    /// Per-protocol connection counts.
    pub connections_by_proto: Value,
    /// Total connection count.
    pub connection_count: i64,
    /// Received packets.
    pub rx_packets: i64,
    /// Received bytes.
    pub rx_bytes: i64,
    /// Transmitted packets.
    pub tx_packets: i64,
    /// Transmitted bytes.
    pub tx_bytes: i64,
    /// Active VS Code sessions.
    pub session_count_vscode: i64,
    /// Active JetBrains sessions.
    pub session_count_jetbrains: i64,
    /// Active reconnecting PTY sessions.
    pub session_count_reconnecting_pty: i64,
    /// Active SSH sessions.
    pub session_count_ssh: i64,
    /// Median connection latency.
    pub connection_median_latency_ms: f64,
    /// Whether usage-based aggregation should use this sample.
    pub usage: bool,
}

/// Upsert payload for one workspace proxy health record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceProxyHealthInput {
    /// Proxy identifier.
    pub id: Uuid,
    /// Region name.
    pub name: String,
    /// Human-readable display name.
    pub display_name: String,
    /// Icon URL.
    pub icon_url: String,
    /// Path-app URL used for health probes.
    pub path_app_url: String,
    /// Wildcard hostname when one exists.
    pub wildcard_hostname: String,
    /// Whether the proxy exposes DERP.
    pub derp_enabled: bool,
    /// Whether the proxy is DERP-only.
    pub derp_only: bool,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Update time.
    pub updated_at: OffsetDateTime,
    /// Deletion marker.
    pub deleted: bool,
    /// Running version.
    pub version: String,
}

/// Stored workspace proxy health record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceProxyHealthRecord {
    /// Proxy identifier.
    pub id: Uuid,
    /// Region name.
    pub name: String,
    /// Human-readable display name.
    pub display_name: String,
    /// Icon URL.
    pub icon_url: String,
    /// Path-app URL used for health probes.
    pub path_app_url: String,
    /// Wildcard hostname when one exists.
    pub wildcard_hostname: String,
    /// Whether the proxy exposes DERP.
    pub derp_enabled: bool,
    /// Whether the proxy is DERP-only.
    pub derp_only: bool,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Update time.
    pub updated_at: OffsetDateTime,
    /// Deletion marker.
    pub deleted: bool,
    /// Running version.
    pub version: String,
}

/// Upsert payload for one provisioner daemon health record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvisionerDaemonHealthInput {
    /// Daemon identifier.
    pub id: Uuid,
    /// Organization identifier.
    pub organization_id: Uuid,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Last heartbeat time.
    pub last_seen_at: Option<OffsetDateTime>,
    /// Daemon name.
    pub name: String,
    /// Running version.
    pub version: String,
    /// Provisioner API version.
    pub api_version: String,
    /// Supported provisioner types.
    pub provisioners: Vec<String>,
    /// Free-form daemon tags.
    pub tags: HashMap<String, String>,
    /// Current daemon status.
    pub status: Option<String>,
}

/// Stored provisioner daemon health record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvisionerDaemonHealthRecord {
    /// Daemon identifier.
    pub id: Uuid,
    /// Organization identifier.
    pub organization_id: Uuid,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Last heartbeat time.
    pub last_seen_at: Option<OffsetDateTime>,
    /// Daemon name.
    pub name: String,
    /// Running version.
    pub version: String,
    /// Provisioner API version.
    pub api_version: String,
    /// Supported provisioner types.
    pub provisioners: Vec<String>,
    /// Free-form daemon tags.
    pub tags: HashMap<String, String>,
    /// Current daemon status.
    pub status: Option<String>,
}

// ---------------------------------------------------------------------------
// Workspace domain records
// ---------------------------------------------------------------------------

/// Stored workspace ACL record.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WorkspaceACLRecord {
    /// User ACL: maps user UUID string to role string.
    pub user_acl: HashMap<String, String>,
    /// Group ACL: maps group UUID string to role string.
    pub group_acl: HashMap<String, String>,
}

/// Input for updating workspace ACL.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UpdateWorkspaceACLInput {
    /// User role mapping (UUID string -> role).
    pub user_roles: HashMap<String, String>,
    /// Group role mapping (UUID string -> role).
    pub group_roles: HashMap<String, String>,
}

/// Stored workspace record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceRecord {
    /// Workspace identifier.
    pub id: Uuid,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Update time.
    pub updated_at: OffsetDateTime,
    /// Soft-delete flag.
    pub deleted: bool,
    /// Owner identifier.
    pub owner_id: Uuid,
    /// Organization identifier.
    pub organization_id: Uuid,
    /// Template identifier.
    pub template_id: Uuid,
    /// Workspace name.
    pub name: String,
    /// Autostart cron schedule.
    pub autostart_schedule: Option<String>,
    /// TTL in nanoseconds.
    pub ttl_ns: Option<i64>,
    /// Last used time.
    pub last_used_at: OffsetDateTime,
    /// Dormant timestamp.
    pub dormant_at: Option<OffsetDateTime>,
    /// Scheduled deletion time.
    pub deleting_at: Option<OffsetDateTime>,
    /// Automatic updates setting.
    pub automatic_updates: String,
    /// Favorite flag.
    pub favorite: bool,
    /// Next start time.
    pub next_start_at: Option<OffsetDateTime>,
}

/// Stored workspace build record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceBuildRecord {
    /// Build identifier.
    pub id: Uuid,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Update time.
    pub updated_at: OffsetDateTime,
    /// Parent workspace identifier.
    pub workspace_id: Uuid,
    /// Build sequence number.
    pub build_number: i64,
    /// Transition: start, stop, delete.
    pub transition: String,
    /// Provisioner job identifier.
    pub job_id: Uuid,
    /// Template version identifier.
    pub template_version_id: Uuid,
    /// User who initiated the build.
    pub initiator_id: Uuid,
    /// Provisioner state blob.
    pub provisioner_state: Option<Vec<u8>>,
    /// Build deadline.
    pub deadline: Option<OffsetDateTime>,
    /// Maximum deadline.
    pub max_deadline: Option<OffsetDateTime>,
    /// Build reason.
    pub reason: String,
    /// Daily cost in credits.
    pub daily_cost: i32,
}

/// Stored workspace resource record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceResourceRecord {
    /// Resource identifier.
    pub id: Uuid,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Job identifier.
    pub job_id: Uuid,
    /// Workspace transition.
    pub transition: String,
    /// Resource type.
    pub resource_type: String,
    /// Resource name.
    pub name: String,
    /// Whether to hide.
    pub hide: bool,
    /// Resource icon.
    pub icon: String,
    /// Daily cost.
    pub daily_cost: i32,
}

/// Stored workspace build parameter record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceBuildParameterRecord {
    /// Build identifier.
    pub workspace_build_id: Uuid,
    /// Parameter name.
    pub name: String,
    /// Parameter value.
    pub value: String,
}

/// Stored workspace resource metadata record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceResourceMetadataRecord {
    /// Resource identifier.
    pub workspace_resource_id: Uuid,
    /// Metadata key.
    pub key: String,
    /// Metadata value.
    pub value: String,
    /// Whether the value is sensitive.
    pub sensitive: bool,
}

/// Stored workspace agent port share record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceAgentPortShareRecord {
    /// Workspace identifier.
    pub workspace_id: Uuid,
    /// Agent name.
    pub agent_name: String,
    /// Port number.
    pub port: i32,
    /// Share level.
    pub share_level: String,
    /// Protocol.
    pub protocol: String,
}

/// Stored provisioner job log record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvisionerJobLogRecord {
    /// Log identifier.
    pub id: i64,
    /// Job identifier.
    pub job_id: Uuid,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Source.
    pub source: String,
    /// Level.
    pub level: String,
    /// Stage.
    pub stage: String,
    /// Output.
    pub output: String,
}

/// Stored provisioner job timing record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvisionerJobTimingRecord {
    /// Job identifier.
    pub job_id: Uuid,
    /// Start time.
    pub started_at: OffsetDateTime,
    /// End time.
    pub ended_at: OffsetDateTime,
    /// Stage.
    pub stage: String,
    /// Source.
    pub source: String,
    /// Action.
    pub action: String,
    /// Resource.
    pub resource: String,
}

/// Stored workspace agent script timing row (joined from script timings + agents).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceAgentScriptTimingRow {
    /// Script identifier.
    pub script_id: Uuid,
    /// Start time.
    pub started_at: OffsetDateTime,
    /// End time.
    pub ended_at: OffsetDateTime,
    /// Exit code.
    pub exit_code: i32,
    /// Timing stage.
    pub stage: String,
    /// Timing status.
    pub status: String,
    /// Display name.
    pub display_name: String,
    /// Workspace agent identifier.
    pub workspace_agent_id: Uuid,
    /// Workspace agent name.
    pub workspace_agent_name: String,
}

/// Filter for listing workspaces.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WorkspaceListFilter {
    /// Owner identifier (empty = all).
    pub owner_id: Option<Uuid>,
    /// Owner username (empty = all).
    pub owner_username: Option<String>,
    /// Template name filter.
    pub template_name: Option<String>,
    /// Template IDs filter.
    pub template_ids: Vec<Uuid>,
    /// Name search (partial match).
    pub name: Option<String>,
    /// Status filter.
    pub status: Option<String>,
    /// Has agent filter.
    pub has_agent: Option<String>,
    /// Dormant filter.
    pub dormant: Option<bool>,
    /// Last used before.
    pub last_used_before: Option<OffsetDateTime>,
    /// Last used after.
    pub last_used_after: Option<OffsetDateTime>,
    /// Organization ID.
    pub organization_id: Option<Uuid>,
    /// Page limit.
    pub limit: u32,
    /// Page offset.
    pub offset: u32,
    /// Viewer user ID for computing per-user fields (e.g. favorite).
    pub viewer_id: Option<Uuid>,
}

/// Input for creating a workspace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateWorkspaceInput {
    /// Workspace identifier.
    pub id: Uuid,
    /// Owner identifier.
    pub owner_id: Uuid,
    /// Organization identifier.
    pub organization_id: Uuid,
    /// Template identifier.
    pub template_id: Uuid,
    /// Workspace name.
    pub name: String,
    /// Autostart schedule.
    pub autostart_schedule: Option<String>,
    /// TTL in nanoseconds.
    pub ttl_ns: Option<i64>,
    /// Automatic updates.
    pub automatic_updates: String,
}

/// Input for creating a workspace build.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateWorkspaceBuildInput {
    /// Build identifier.
    pub id: Uuid,
    /// Workspace identifier.
    pub workspace_id: Uuid,
    /// Template version identifier.
    pub template_version_id: Uuid,
    /// Build number (auto-increment based on workspace).
    pub build_number: i64,
    /// Transition: start, stop, delete.
    pub transition: String,
    /// Initiator identifier.
    pub initiator_id: Uuid,
    /// Job identifier.
    pub job_id: Uuid,
    /// Build reason.
    pub reason: String,
    /// Deadline.
    pub deadline: Option<OffsetDateTime>,
    /// Max deadline.
    pub max_deadline: Option<OffsetDateTime>,
}

/// Input for upserting a port share.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpsertPortShareInput {
    /// Workspace identifier.
    pub workspace_id: Uuid,
    /// Agent name.
    pub agent_name: String,
    /// Port number.
    pub port: i32,
    /// Share level.
    pub share_level: String,
    /// Protocol.
    pub protocol: String,
}

/// Stored file record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileRecord {
    /// Stable file identifier.
    pub id: Uuid,
    /// SHA-256 hex-encoded hash of the file data.
    pub hash: String,
    /// User who uploaded the file.
    pub created_by: Uuid,
    /// Upload time.
    pub created_at: OffsetDateTime,
    /// MIME type of the file.
    pub mimetype: String,
    /// Raw file bytes.
    pub data: Vec<u8>,
}

/// Input for inserting a new file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InsertFileInput {
    /// Stable file identifier.
    pub id: Uuid,
    /// SHA-256 hex-encoded hash of the file data.
    pub hash: String,
    /// User who uploaded the file.
    pub created_by: Uuid,
    /// MIME type of the file.
    pub mimetype: String,
    /// Raw file bytes.
    pub data: Vec<u8>,
}

/// Lightweight result from [`OperationalStore::insert_file`].
///
/// Only the fields needed by the caller are returned so the DB does not have
/// to ship the (potentially large) `data` blob back over the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InsertFileResult {
    /// Stable file identifier (either the newly-created id or the existing
    /// duplicate's id).
    pub id: Uuid,
}

/// Errors surfaced by storage backends.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum StorageError {
    /// The backing store is unavailable.
    #[error("storage unavailable: {message}")]
    Unavailable { message: String },
    /// Stored data exists but is invalid.
    #[error("stored data is invalid: {message}")]
    InvalidData { message: String },
}

impl StorageError {
    /// Creates an availability error.
    #[must_use]
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::Unavailable {
            message: message.into(),
        }
    }

    /// Creates a data-integrity error.
    #[must_use]
    pub fn invalid_data(message: impl Into<String>) -> Self {
        Self::InvalidData {
            message: message.into(),
        }
    }
}

/// Minimal store contract for the deployment and health surfaces.
#[async_trait]
pub trait DeploymentStore: Send + Sync {
    /// Verifies that the backing store is reachable.
    async fn ping(&self) -> Result<(), StorageError>;

    /// Ensures that a stable deployment identifier exists and returns it.
    async fn ensure_deployment_metadata(&self) -> Result<DeploymentMetadata, StorageError>;
}

/// Narrow store contract for auth, sessions, passwords, API keys, and external-auth links.
#[async_trait]
pub trait AuthStore: Send + Sync {
    /// Returns whether a non-system first user exists.
    async fn first_user_exists(&self) -> Result<bool, StorageError>;

    /// Attempts to create the first user for the deployment.
    async fn create_first_user(
        &self,
        user: CreateFirstUserInput,
    ) -> Result<FirstUserRecord, CreateFirstUserStoreError>;

    /// Looks up a password-backed login user by email.
    async fn find_password_user_by_email(
        &self,
        email: &str,
    ) -> Result<Option<PasswordUserRecord>, StorageError>;

    /// Looks up a password-backed login user by identifier.
    async fn find_password_user_by_id(
        &self,
        user_id: Uuid,
    ) -> Result<Option<PasswordUserRecord>, StorageError>;

    /// Persists a hashed session token for later authentication.
    async fn insert_auth_session(
        &self,
        token_hash: &[u8],
        user_id: Uuid,
    ) -> Result<(), StorageError>;

    /// Looks up a user by hashed session token.
    async fn find_user_by_session_token_hash(
        &self,
        token_hash: &[u8],
    ) -> Result<Option<AuthenticatedUser>, StorageError>;

    /// Deletes a hashed session token.
    async fn delete_auth_session(&self, token_hash: &[u8]) -> Result<bool, StorageError>;

    /// Looks up a user by stable identifier.
    async fn find_user_by_id(&self, user_id: Uuid) -> Result<Option<UserRecord>, StorageError>;

    /// Looks up a user by username.
    async fn find_user_by_username(
        &self,
        username: &str,
    ) -> Result<Option<UserRecord>, StorageError>;

    /// Stores a one-time passcode hash for the user identified by email.
    async fn store_one_time_passcode_by_email(
        &self,
        email: &str,
        passcode_hash: &str,
        expires_at: OffsetDateTime,
    ) -> Result<(), StorageError>;

    /// Replaces a user's password hash and revokes active sessions and API keys.
    async fn replace_user_password(
        &self,
        user_id: Uuid,
        password_hash: &str,
        clear_one_time_passcode: bool,
    ) -> Result<bool, StorageError>;

    /// Inserts a new API key record.
    async fn create_api_key(
        &self,
        input: CreateApiKeyInput,
    ) -> Result<ApiKeyRecord, CreateApiKeyStoreError>;

    /// Looks up an API key by stable identifier.
    async fn find_api_key_by_id(&self, id: &str) -> Result<Option<ApiKeyRecord>, StorageError>;

    /// Looks up an API key by user and token name.
    async fn find_api_key_by_name(
        &self,
        user_id: Uuid,
        token_name: &str,
    ) -> Result<Option<ApiKeyRecord>, StorageError>;

    /// Lists API keys using the supplied filter.
    async fn list_api_keys(
        &self,
        filter: ApiKeyListFilter,
    ) -> Result<Vec<ApiKeyWithOwnerRecord>, StorageError>;

    /// Deletes an API key.
    async fn delete_api_key(&self, id: &str) -> Result<bool, StorageError>;

    /// Expires an API key in-place.
    async fn expire_api_key(&self, id: &str, now: OffsetDateTime) -> Result<bool, StorageError>;

    /// Returns token-lifetime settings for the given user.
    async fn token_config(&self, user_id: Uuid) -> Result<TokenConfigRecord, StorageError>;

    /// Lists configured external-auth links for one user.
    async fn list_external_auth_links(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<ExternalAuthLinkRecord>, StorageError>;

    /// Looks up one external-auth link for a user.
    async fn find_external_auth_link(
        &self,
        user_id: Uuid,
        provider_id: &str,
    ) -> Result<Option<ExternalAuthLinkRecord>, StorageError>;

    /// Deletes one external-auth link for a user.
    async fn delete_external_auth_link(
        &self,
        user_id: Uuid,
        provider_id: &str,
    ) -> Result<bool, StorageError>;

    /// Inserts or updates one external-auth link for a user.
    async fn upsert_external_auth_link(
        &self,
        user_id: Uuid,
        link: &UpsertExternalAuthLinkInput,
    ) -> Result<ExternalAuthLinkRecord, StorageError>;
}

/// Narrow storage contract for identity-owned domain logic.
#[allow(clippy::too_many_arguments)]
#[async_trait]
pub trait IdentityStore: Send + Sync {
    /// Lists users matching the supplied filter.
    async fn list_users(
        &self,
        filter: UserListFilter,
    ) -> Result<(Vec<UserRecord>, usize), StorageError>;

    /// Creates a new user and inserts the requested organization memberships.
    async fn create_user(&self, input: CreateUserInput)
    -> Result<UserRecord, CreateUserStoreError>;

    /// Looks up a user by stable identifier.
    async fn find_user_by_id(&self, user_id: Uuid) -> Result<Option<UserRecord>, StorageError>;

    /// Looks up a user by username.
    async fn find_user_by_username(
        &self,
        username: &str,
    ) -> Result<Option<UserRecord>, StorageError>;

    /// Soft-deletes a user and revokes its sessions and API keys.
    async fn soft_delete_user(&self, user_id: Uuid) -> Result<bool, StorageError>;

    /// Lists organization memberships for a specific user.
    async fn list_user_memberships(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<OrganizationMemberRecord>, StorageError>;

    /// Replaces the site-wide roles for a user.
    async fn update_user_roles(
        &self,
        user_id: Uuid,
        roles: Vec<String>,
    ) -> Result<Option<UserRecord>, StorageError>;

    /// Updates a user's basic profile fields.
    async fn update_user_profile(
        &self,
        user_id: Uuid,
        username: &str,
        name: &str,
    ) -> Result<Option<UserRecord>, StorageError>;

    /// Updates a user's status.
    async fn update_user_status(
        &self,
        user_id: Uuid,
        status: UserStatus,
    ) -> Result<Option<UserRecord>, StorageError>;

    /// Returns appearance settings for a user.
    async fn user_appearance(&self, user_id: Uuid) -> Result<UserAppearanceRecord, StorageError>;

    /// Updates appearance settings for a user.
    async fn update_user_appearance(
        &self,
        user_id: Uuid,
        theme_preference: &str,
        terminal_font: &str,
    ) -> Result<Option<UserAppearanceRecord>, StorageError>;

    /// Returns preference settings for a user.
    async fn user_preferences(&self, user_id: Uuid) -> Result<UserPreferenceRecord, StorageError>;

    /// Updates preference settings for a user.
    async fn update_user_preferences(
        &self,
        user_id: Uuid,
        task_notification_alert_dismissed: bool,
    ) -> Result<Option<UserPreferenceRecord>, StorageError>;

    /// Lists organizations, optionally filtering by identifiers.
    async fn list_organizations(
        &self,
        organization_ids: Vec<Uuid>,
    ) -> Result<Vec<OrganizationRecord>, StorageError>;

    /// Looks up an organization by stable identifier.
    async fn find_organization_by_id(
        &self,
        organization_id: Uuid,
    ) -> Result<Option<OrganizationRecord>, StorageError>;

    /// Looks up an organization by name.
    async fn find_organization_by_name(
        &self,
        name: &str,
    ) -> Result<Option<OrganizationRecord>, StorageError>;

    /// Lists members for an organization.
    async fn list_organization_members(
        &self,
        filter: OrganizationMemberListFilter,
    ) -> Result<Vec<OrganizationMemberRecord>, StorageError>;

    /// Lists members for an organization together with the total count.
    async fn list_organization_members_page(
        &self,
        filter: OrganizationMemberListFilter,
    ) -> Result<(Vec<OrganizationMemberRecord>, usize), StorageError>;

    /// Looks up a specific organization member.
    async fn find_organization_member(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<OrganizationMemberRecord>, StorageError>;

    /// Inserts a new organization membership.
    async fn insert_organization_member(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> Result<OrganizationMemberRecord, InsertOrganizationMemberError>;

    /// Deletes an organization membership.
    async fn delete_organization_member(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, StorageError>;

    /// Replaces the organization-scoped roles for a member.
    async fn update_organization_member_roles(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
        roles: Vec<String>,
    ) -> Result<Option<OrganizationMemberRecord>, StorageError>;

    // ----- User identity supplements -----

    /// Lists user links for a user.
    async fn list_user_links(&self, user_id: Uuid) -> Result<Vec<UserLinkRecord>, StorageError> {
        let _ = user_id;
        Err(StorageError::unavailable("user links are not implemented"))
    }

    /// Upserts a user link.
    async fn upsert_user_link(
        &self,
        user_id: Uuid,
        input: &UpsertUserLinkInput,
    ) -> Result<UserLinkRecord, StorageError> {
        let _ = (user_id, input);
        Err(StorageError::unavailable("user links are not implemented"))
    }

    /// Deletes a user link.
    async fn delete_user_link(
        &self,
        user_id: Uuid,
        login_type: crate::identity::LoginType,
    ) -> Result<bool, StorageError> {
        let _ = (user_id, login_type);
        Err(StorageError::unavailable("user links are not implemented"))
    }

    /// Returns a user configuration value.
    async fn get_user_config(
        &self,
        user_id: Uuid,
        key: &str,
    ) -> Result<Option<UserConfigRecord>, StorageError> {
        let _ = (user_id, key);
        Err(StorageError::unavailable(
            "user configs are not implemented",
        ))
    }

    /// Sets a user configuration value.
    async fn upsert_user_config(
        &self,
        user_id: Uuid,
        key: &str,
        value: &str,
    ) -> Result<UserConfigRecord, StorageError> {
        let _ = (user_id, key, value);
        Err(StorageError::unavailable(
            "user configs are not implemented",
        ))
    }

    /// Deletes a user configuration value.
    async fn delete_user_config(&self, user_id: Uuid, key: &str) -> Result<bool, StorageError> {
        let _ = (user_id, key);
        Err(StorageError::unavailable(
            "user configs are not implemented",
        ))
    }

    /// Records a soft-delete tracking entry.
    async fn insert_user_deleted(
        &self,
        user_id: Uuid,
        deleted_by: Option<Uuid>,
        reason: &str,
    ) -> Result<UserDeletedRecord, StorageError> {
        let _ = (user_id, deleted_by, reason);
        Err(StorageError::unavailable(
            "user deletion tracking is not implemented",
        ))
    }

    /// Records a user status change.
    async fn insert_user_status_change(
        &self,
        user_id: Uuid,
        old_status: UserStatus,
        new_status: UserStatus,
        changed_by: Option<Uuid>,
        reason: &str,
    ) -> Result<UserStatusChangeRecord, StorageError> {
        let _ = (user_id, old_status, new_status, changed_by, reason);
        Err(StorageError::unavailable(
            "user status changes are not implemented",
        ))
    }

    /// Lists status changes for a user.
    async fn list_user_status_changes(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<UserStatusChangeRecord>, StorageError> {
        let _ = user_id;
        Err(StorageError::unavailable(
            "user status changes are not implemented",
        ))
    }

    // ----- Custom roles -----

    /// Lists custom roles, optionally filtered by organization.
    async fn list_custom_roles(
        &self,
        organization_id: Option<Uuid>,
    ) -> Result<Vec<CustomRoleRecord>, StorageError> {
        let _ = organization_id;
        Err(StorageError::unavailable(
            "custom roles are not implemented",
        ))
    }

    /// Upserts a custom role.
    async fn upsert_custom_role(
        &self,
        input: &UpsertCustomRoleInput,
    ) -> Result<CustomRoleRecord, StorageError> {
        let _ = input;
        Err(StorageError::unavailable(
            "custom roles are not implemented",
        ))
    }

    /// Deletes a custom role.
    async fn delete_custom_role(
        &self,
        name: &str,
        organization_id: Option<Uuid>,
    ) -> Result<bool, StorageError> {
        let _ = (name, organization_id);
        Err(StorageError::unavailable(
            "custom roles are not implemented",
        ))
    }

    // ----- Groups -----

    /// Lists groups for an organization.
    async fn list_groups(&self, organization_id: Uuid) -> Result<Vec<GroupRecord>, StorageError> {
        let _ = organization_id;
        Err(StorageError::unavailable("groups are not implemented"))
    }

    /// Creates a new group.
    async fn create_group(&self, input: &CreateGroupInput) -> Result<GroupRecord, StorageError> {
        let _ = input;
        Err(StorageError::unavailable("groups are not implemented"))
    }

    /// Looks up a group by identifier.
    async fn find_group_by_id(&self, group_id: Uuid) -> Result<Option<GroupRecord>, StorageError> {
        let _ = group_id;
        Err(StorageError::unavailable("groups are not implemented"))
    }

    /// Deletes a group.
    async fn delete_group(&self, group_id: Uuid) -> Result<bool, StorageError> {
        let _ = group_id;
        Err(StorageError::unavailable("groups are not implemented"))
    }

    /// Lists members of a group.
    async fn list_group_members(
        &self,
        group_id: Uuid,
    ) -> Result<Vec<GroupMemberRecord>, StorageError> {
        let _ = group_id;
        Err(StorageError::unavailable(
            "group members are not implemented",
        ))
    }

    /// Adds a user to a group.
    async fn insert_group_member(&self, group_id: Uuid, user_id: Uuid) -> Result<(), StorageError> {
        let _ = (group_id, user_id);
        Err(StorageError::unavailable(
            "group members are not implemented",
        ))
    }

    /// Removes a user from a group.
    async fn delete_group_member(
        &self,
        group_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, StorageError> {
        let _ = (group_id, user_id);
        Err(StorageError::unavailable(
            "group members are not implemented",
        ))
    }

    // ----- OAuth2 Provider -----

    /// Lists registered OAuth2 provider apps.
    async fn list_oauth2_provider_apps(
        &self,
    ) -> Result<Vec<OAuth2ProviderAppRecord>, StorageError> {
        Err(StorageError::unavailable(
            "oauth2 provider apps are not implemented",
        ))
    }

    /// Creates an OAuth2 provider app.
    async fn create_oauth2_provider_app(
        &self,
        input: &CreateOAuth2ProviderAppInput,
    ) -> Result<OAuth2ProviderAppRecord, StorageError> {
        let _ = input;
        Err(StorageError::unavailable(
            "oauth2 provider apps are not implemented",
        ))
    }

    /// Looks up an OAuth2 provider app by identifier.
    async fn find_oauth2_provider_app_by_id(
        &self,
        app_id: Uuid,
    ) -> Result<Option<OAuth2ProviderAppRecord>, StorageError> {
        let _ = app_id;
        Err(StorageError::unavailable(
            "oauth2 provider apps are not implemented",
        ))
    }

    /// Updates an OAuth2 provider app.
    async fn update_oauth2_provider_app(
        &self,
        input: &UpdateOAuth2ProviderAppInput,
    ) -> Result<Option<OAuth2ProviderAppRecord>, StorageError> {
        let _ = input;
        Err(StorageError::unavailable(
            "oauth2 provider apps are not implemented",
        ))
    }

    /// Deletes an OAuth2 provider app.
    async fn delete_oauth2_provider_app(&self, app_id: Uuid) -> Result<bool, StorageError> {
        let _ = app_id;
        Err(StorageError::unavailable(
            "oauth2 provider apps are not implemented",
        ))
    }

    /// Lists secrets for an OAuth2 provider app.
    async fn list_oauth2_provider_app_secrets(
        &self,
        app_id: Uuid,
    ) -> Result<Vec<OAuth2ProviderAppSecretRecord>, StorageError> {
        let _ = app_id;
        Err(StorageError::unavailable(
            "oauth2 provider app secrets are not implemented",
        ))
    }

    /// Creates a secret for an OAuth2 provider app.
    async fn create_oauth2_provider_app_secret(
        &self,
        app_id: Uuid,
        hashed_secret: &[u8],
        display_secret: &str,
    ) -> Result<OAuth2ProviderAppSecretRecord, StorageError> {
        let _ = (app_id, hashed_secret, display_secret);
        Err(StorageError::unavailable(
            "oauth2 provider app secrets are not implemented",
        ))
    }

    /// Deletes a secret for an OAuth2 provider app.
    async fn delete_oauth2_provider_app_secret(
        &self,
        secret_id: Uuid,
    ) -> Result<bool, StorageError> {
        let _ = secret_id;
        Err(StorageError::unavailable(
            "oauth2 provider app secrets are not implemented",
        ))
    }

    /// Finds an OAuth2 provider app secret by identifier.
    async fn find_oauth2_provider_app_secret_by_id(
        &self,
        secret_id: Uuid,
    ) -> Result<Option<OAuth2ProviderAppSecretRecord>, StorageError> {
        let _ = secret_id;
        Err(StorageError::unavailable(
            "oauth2 provider app secrets are not implemented",
        ))
    }

    /// Creates an authorization code for the OAuth2 flow.
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
    ) -> Result<OAuth2ProviderAppCodeRecord, StorageError> {
        let _ = (
            app_id,
            user_id,
            secret_prefix,
            hashed_secret,
            expires_at,
            resource_uri,
            code_challenge,
            code_challenge_method,
        );
        Err(StorageError::unavailable(
            "oauth2 provider app codes are not implemented",
        ))
    }

    /// Finds an authorization code by secret prefix.
    async fn find_oauth2_provider_app_code_by_prefix(
        &self,
        secret_prefix: &[u8],
    ) -> Result<Option<OAuth2ProviderAppCodeRecord>, StorageError> {
        let _ = secret_prefix;
        Err(StorageError::unavailable(
            "oauth2 provider app codes are not implemented",
        ))
    }

    /// Deletes an authorization code.
    async fn delete_oauth2_provider_app_code(&self, code_id: Uuid) -> Result<bool, StorageError> {
        let _ = code_id;
        Err(StorageError::unavailable(
            "oauth2 provider app codes are not implemented",
        ))
    }

    /// Creates an OAuth2 provider app token.
    async fn create_oauth2_provider_app_token(
        &self,
        input: &CreateOAuth2ProviderAppTokenInput,
    ) -> Result<OAuth2ProviderAppTokenRecord, StorageError> {
        let _ = input;
        Err(StorageError::unavailable(
            "oauth2 provider app tokens are not implemented",
        ))
    }

    /// Finds an OAuth2 token by hash prefix.
    async fn find_oauth2_provider_app_token_by_prefix(
        &self,
        hash_prefix: &[u8],
    ) -> Result<Option<OAuth2ProviderAppTokenRecord>, StorageError> {
        let _ = hash_prefix;
        Err(StorageError::unavailable(
            "oauth2 provider app tokens are not implemented",
        ))
    }

    /// Finds an OAuth2 token by refresh hash.
    async fn find_oauth2_provider_app_token_by_refresh_hash(
        &self,
        refresh_hash: &[u8],
    ) -> Result<Option<OAuth2ProviderAppTokenRecord>, StorageError> {
        let _ = refresh_hash;
        Err(StorageError::unavailable(
            "oauth2 provider app tokens are not implemented",
        ))
    }

    /// Deletes an OAuth2 provider app token.
    async fn delete_oauth2_provider_app_token(&self, token_id: Uuid) -> Result<bool, StorageError> {
        let _ = token_id;
        Err(StorageError::unavailable(
            "oauth2 provider app tokens are not implemented",
        ))
    }

    /// Lists all OAuth2 tokens for a given user and app.
    async fn list_oauth2_provider_app_tokens_by_app_and_user(
        &self,
        app_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<OAuth2ProviderAppTokenRecord>, StorageError> {
        let _ = (app_id, user_id);
        Err(StorageError::unavailable(
            "oauth2 provider app tokens are not implemented",
        ))
    }

    /// Deletes all OAuth2 tokens for a given user and app.
    async fn delete_oauth2_provider_app_tokens_by_app_and_user(
        &self,
        app_id: Uuid,
        user_id: Uuid,
    ) -> Result<u64, StorageError> {
        let _ = (app_id, user_id);
        Err(StorageError::unavailable(
            "oauth2 provider app tokens are not implemented",
        ))
    }

    // ----- Notifications -----

    /// Fetches pending notification messages for dispatch.
    ///
    /// Messages with `attempt_count >= max_attempt_count` are excluded so they
    /// can be purged separately rather than retried indefinitely.
    async fn fetch_pending_notification_messages(
        &self,
        limit: u32,
        max_attempt_count: u32,
    ) -> Result<Vec<NotificationMessageRecord>, StorageError> {
        let _ = (limit, max_attempt_count);
        Err(StorageError::unavailable(
            "notification messages are not implemented",
        ))
    }

    /// Updates the status of a notification message after dispatch.
    async fn update_notification_message_status(
        &self,
        message_id: Uuid,
        status: crate::identity::NotificationMessageStatus,
    ) -> Result<bool, StorageError> {
        let _ = (message_id, status);
        Err(StorageError::unavailable(
            "notification messages are not implemented",
        ))
    }

    /// Increments the attempt count for a notification message.
    async fn increment_notification_message_attempt_count(
        &self,
        message_id: Uuid,
    ) -> Result<bool, StorageError> {
        let _ = message_id;
        Err(StorageError::unavailable(
            "notification messages are not implemented",
        ))
    }
}

/// Narrow storage contract for operational and deployment-owned state.
#[async_trait]
pub trait OperationalStore: Send + Sync {
    /// Lists audit logs using the supplied filter.
    async fn list_audit_logs(
        &self,
        filter: AuditLogListFilter,
    ) -> Result<AuditLogResponse, StorageError> {
        let _ = filter;
        Err(StorageError::unavailable("audit logs are not implemented"))
    }

    /// Persists one audit log entry.
    async fn insert_audit_log(&self, input: PersistAuditLogInput) -> Result<(), StorageError> {
        let _ = input;
        Err(StorageError::unavailable(
            "audit log inserts are not implemented",
        ))
    }

    /// Returns deployment health settings.
    async fn health_settings(&self) -> Result<HealthSettings, StorageError> {
        Err(StorageError::unavailable(
            "deployment health settings are not implemented",
        ))
    }

    /// Replaces deployment health settings, returning whether the value changed.
    async fn upsert_health_settings(
        &self,
        settings: &HealthSettings,
    ) -> Result<bool, StorageError> {
        let _ = settings;
        Err(StorageError::unavailable(
            "deployment health settings are not implemented",
        ))
    }

    /// Returns deployment statistics for the current backend slice.
    async fn deployment_stats(&self) -> Result<crate::api::DeploymentStatsResponse, StorageError> {
        Err(StorageError::unavailable(
            "deployment stats are not implemented",
        ))
    }

    /// Upserts one workspace into the deployment-stats foundation tables.
    async fn upsert_workspace_stats_workspace(
        &self,
        input: &WorkspaceStatsWorkspaceInput,
    ) -> Result<(), StorageError> {
        let _ = input;
        Err(StorageError::unavailable(
            "workspace stats writers are not implemented",
        ))
    }

    /// Upserts one provisioner job into the deployment-stats foundation tables.
    async fn upsert_provisioner_job_stats(
        &self,
        input: &ProvisionerJobStatsInput,
    ) -> Result<(), StorageError> {
        let _ = input;
        Err(StorageError::unavailable(
            "provisioner stats writers are not implemented",
        ))
    }

    /// Upserts one workspace build into the deployment-stats foundation tables.
    async fn upsert_workspace_build_stats(
        &self,
        input: &WorkspaceBuildStatsInput,
    ) -> Result<(), StorageError> {
        let _ = input;
        Err(StorageError::unavailable(
            "workspace build stats writers are not implemented",
        ))
    }

    /// Inserts one raw agent-stat sample into the deployment-stats foundation tables.
    async fn insert_workspace_agent_stat(
        &self,
        input: &WorkspaceAgentStatInput,
    ) -> Result<(), StorageError> {
        let _ = input;
        Err(StorageError::unavailable(
            "workspace agent stats writers are not implemented",
        ))
    }

    /// Lists persisted workspace proxies for deployment health checks.
    async fn list_workspace_proxies_for_health(
        &self,
    ) -> Result<Vec<WorkspaceProxyHealthRecord>, StorageError> {
        Err(StorageError::unavailable(
            "workspace proxy health is not implemented",
        ))
    }

    /// Upserts one workspace proxy for deployment health checks.
    async fn upsert_workspace_proxy_for_health(
        &self,
        input: &WorkspaceProxyHealthInput,
    ) -> Result<(), StorageError> {
        let _ = input;
        Err(StorageError::unavailable(
            "workspace proxy health is not implemented",
        ))
    }

    /// Lists persisted provisioner daemons for deployment health checks.
    async fn list_provisioner_daemons_for_health(
        &self,
    ) -> Result<Vec<ProvisionerDaemonHealthRecord>, StorageError> {
        Err(StorageError::unavailable(
            "provisioner daemon health is not implemented",
        ))
    }

    /// Upserts one provisioner daemon for deployment health checks.
    async fn upsert_provisioner_daemon_for_health(
        &self,
        input: &ProvisionerDaemonHealthInput,
    ) -> Result<(), StorageError> {
        let _ = input;
        Err(StorageError::unavailable(
            "provisioner daemon health is not implemented",
        ))
    }

    /// Returns the stored git SSH keypair when one exists.
    async fn find_git_ssh_key(
        &self,
        user_id: Uuid,
    ) -> Result<Option<GitSshKeyRecord>, StorageError> {
        let _ = user_id;
        Err(StorageError::unavailable(
            "git ssh keys are not implemented",
        ))
    }

    /// Inserts or updates the git SSH keypair for a user.
    async fn upsert_git_ssh_key(
        &self,
        user_id: Uuid,
        public_key: &str,
        private_key: &str,
    ) -> Result<GitSshKeyRecord, StorageError> {
        let _ = (user_id, public_key, private_key);
        Err(StorageError::unavailable(
            "git ssh keys are not implemented",
        ))
    }

    /// Inserts a new file record.
    async fn insert_file(&self, input: InsertFileInput) -> Result<InsertFileResult, StorageError> {
        let _ = input;
        Err(StorageError::unavailable("file storage is not implemented"))
    }

    /// Looks up a file by stable identifier.
    async fn get_file_by_id(&self, file_id: Uuid) -> Result<Option<FileRecord>, StorageError> {
        let _ = file_id;
        Err(StorageError::unavailable("file storage is not implemented"))
    }

    /// Looks up a file by hash and creator.
    async fn get_file_by_hash_and_creator(
        &self,
        hash: &str,
        creator_id: Uuid,
    ) -> Result<Option<FileRecord>, StorageError> {
        let _ = (hash, creator_id);
        Err(StorageError::unavailable("file storage is not implemented"))
    }
}

/// Narrow storage contract for insights and analytics queries.
#[async_trait]
pub trait InsightsStore: Send + Sync {
    /// Returns DAU (daily active user) entries for the deployment.
    async fn get_deployment_daus(&self, tz_offset: i32) -> Result<DAUsResponse, StorageError> {
        let _ = tz_offset;
        Err(StorageError::unavailable(
            "deployment DAUs are not implemented",
        ))
    }

    /// Returns template-level insights for a time range.
    async fn get_template_insights(
        &self,
        start_time: OffsetDateTime,
        end_time: OffsetDateTime,
        interval: InsightsReportInterval,
        template_ids: Vec<Uuid>,
    ) -> Result<TemplateInsightsResponse, StorageError> {
        let _ = (start_time, end_time, interval, template_ids);
        Err(StorageError::unavailable(
            "template insights are not implemented",
        ))
    }

    /// Returns template insights broken down by interval.
    async fn get_template_insights_by_interval(
        &self,
        start_time: OffsetDateTime,
        end_time: OffsetDateTime,
        interval: InsightsReportInterval,
        template_ids: Vec<Uuid>,
    ) -> Result<Vec<TemplateInsightsIntervalReport>, StorageError> {
        let _ = (start_time, end_time, interval, template_ids);
        Err(StorageError::unavailable(
            "template insights by interval are not implemented",
        ))
    }

    /// Returns per-user activity insights for a time range.
    async fn get_user_activity_insights(
        &self,
        start_time: OffsetDateTime,
        end_time: OffsetDateTime,
        template_ids: Vec<Uuid>,
    ) -> Result<UserActivityInsightsResponse, StorageError> {
        let _ = (start_time, end_time, template_ids);
        Err(StorageError::unavailable(
            "user activity insights are not implemented",
        ))
    }

    /// Returns per-user latency insights for a time range.
    async fn get_user_latency_insights(
        &self,
        start_time: OffsetDateTime,
        end_time: OffsetDateTime,
        template_ids: Vec<Uuid>,
    ) -> Result<UserLatencyInsightsResponse, StorageError> {
        let _ = (start_time, end_time, template_ids);
        Err(StorageError::unavailable(
            "user latency insights are not implemented",
        ))
    }

    /// Returns user status counts over time for the deployment.
    async fn get_user_status_counts(
        &self,
        timezone: &str,
        start_time: OffsetDateTime,
        end_time: OffsetDateTime,
    ) -> Result<GetUserStatusCountsResponse, StorageError> {
        let _ = (timezone, start_time, end_time);
        Err(StorageError::unavailable(
            "user status counts are not implemented",
        ))
    }
}

/// Storage contract for provisioner job lifecycle, daemons, keys, logs, and timings.
#[async_trait]
pub trait ProvisionerStore: Send + Sync {
    // ── Jobs ──────────────────────────────────────────────────

    /// Atomically acquires a pending job matching the daemon's capabilities.
    /// Uses `FOR UPDATE SKIP LOCKED` to prevent double-assignment.
    async fn acquire_provisioner_job(
        &self,
        input: AcquireProvisionerJobInput,
    ) -> Result<Option<ProvisionerJobRecord>, StorageError>;

    /// Looks up a single provisioner job by identifier.
    async fn get_provisioner_job_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<ProvisionerJobRecord>, StorageError>;

    /// Looks up multiple provisioner jobs by identifiers.
    async fn get_provisioner_jobs_by_ids(
        &self,
        ids: &[Uuid],
    ) -> Result<Vec<ProvisionerJobRecord>, StorageError>;

    /// Inserts a new provisioner job.
    async fn insert_provisioner_job(
        &self,
        input: InsertProvisionerJobInput,
    ) -> Result<ProvisionerJobRecord, StorageError>;

    /// Updates the heartbeat timestamp for a running job.
    async fn update_provisioner_job_by_id(
        &self,
        id: Uuid,
        updated_at: OffsetDateTime,
    ) -> Result<(), StorageError>;

    /// Marks a job as completed (successfully or with error).
    async fn update_provisioner_job_with_complete_by_id(
        &self,
        input: CompleteProvisionerJobInput,
    ) -> Result<(), StorageError>;

    /// Marks a job as canceled.
    async fn update_provisioner_job_with_cancel_by_id(
        &self,
        input: CancelProvisionerJobInput,
    ) -> Result<(), StorageError>;

    /// Returns stale jobs that should be reaped (pending too long or hung).
    async fn get_provisioner_jobs_to_be_reaped(
        &self,
        input: GetJobsToBeReapedInput,
    ) -> Result<Vec<ProvisionerJobRecord>, StorageError>;

    // ── Logs ─────────────────────────────────────────────────

    /// Inserts a batch of log entries for a job.
    async fn insert_provisioner_job_logs(
        &self,
        input: InsertProvisionerJobLogsInput,
    ) -> Result<Vec<ProvisionerLogRecord>, StorageError>;

    /// Returns log entries for a job after the given log-line identifier.
    async fn get_provisioner_logs_after_id(
        &self,
        job_id: Uuid,
        after_id: i64,
    ) -> Result<Vec<ProvisionerLogRecord>, StorageError>;

    // ── Timings ──────────────────────────────────────────────

    /// Inserts a batch of timing entries for a job.
    async fn insert_provisioner_job_timings(
        &self,
        input: InsertProvisionerJobTimingsInput,
    ) -> Result<Vec<ProvisionerTimingRecord>, StorageError>;

    /// Returns all timing entries for a job.
    async fn get_provisioner_job_timings_by_job_id(
        &self,
        job_id: Uuid,
    ) -> Result<Vec<ProvisionerTimingRecord>, StorageError>;

    // ── Daemons ──────────────────────────────────────────────

    /// Registers or updates a provisioner daemon.
    async fn upsert_provisioner_daemon(
        &self,
        input: UpsertProvisionerDaemonInput,
    ) -> Result<ProvisionerDaemonRecord, StorageError>;

    /// Updates the last-seen heartbeat time for a daemon.
    async fn update_provisioner_daemon_last_seen_at(
        &self,
        id: Uuid,
        last_seen_at: OffsetDateTime,
    ) -> Result<(), StorageError>;

    /// Lists daemons for an organization.
    async fn get_provisioner_daemons_by_organization(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<ProvisionerDaemonRecord>, StorageError>;

    /// Deletes provisioner daemons that have not been seen in over 7 days.
    async fn delete_old_provisioner_daemons(&self) -> Result<(), StorageError>;

    // ── Keys ─────────────────────────────────────────────────

    /// Inserts a new provisioner key.
    async fn insert_provisioner_key(
        &self,
        input: InsertProvisionerKeyInput,
    ) -> Result<ProvisionerKeyRecord, StorageError>;

    /// Looks up a provisioner key by identifier.
    async fn get_provisioner_key_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<ProvisionerKeyRecord>, StorageError>;

    /// Looks up a provisioner key by hashed secret.
    async fn get_provisioner_key_by_hashed_secret(
        &self,
        hashed_secret: &[u8],
    ) -> Result<Option<ProvisionerKeyRecord>, StorageError>;

    /// Looks up a provisioner key by organization and name.
    async fn get_provisioner_key_by_name(
        &self,
        organization_id: Uuid,
        name: &str,
    ) -> Result<Option<ProvisionerKeyRecord>, StorageError>;

    /// Lists provisioner keys for an organization.
    async fn list_provisioner_keys_by_organization(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<ProvisionerKeyRecord>, StorageError>;

    /// Deletes a provisioner key by identifier.
    async fn delete_provisioner_key(&self, id: Uuid) -> Result<bool, StorageError>;
}

/// Narrow storage contract for template and template-version domain logic.
#[async_trait]
pub trait TemplateStore: Send + Sync {
    /// Lists templates matching the supplied filter.
    async fn list_templates(
        &self,
        filter: TemplateListFilter,
    ) -> Result<Vec<TemplateRecord>, StorageError>;

    /// Finds a template by identifier.
    async fn find_template_by_id(
        &self,
        template_id: Uuid,
    ) -> Result<Option<TemplateRecord>, StorageError>;

    /// Finds a template by organization and name.
    async fn find_template_by_org_and_name(
        &self,
        organization_id: Uuid,
        name: &str,
    ) -> Result<Option<TemplateRecord>, StorageError>;

    /// Creates a new template.
    async fn insert_template(
        &self,
        input: CreateTemplateInput,
    ) -> Result<TemplateRecord, CreateTemplateStoreError>;

    /// Updates a template's metadata.
    async fn update_template_meta(
        &self,
        input: UpdateTemplateMetaInput,
    ) -> Result<Option<TemplateRecord>, StorageError>;

    /// Soft-deletes a template.
    async fn soft_delete_template(&self, template_id: Uuid) -> Result<bool, StorageError>;

    /// Updates the active version on a template.
    async fn update_template_active_version(
        &self,
        template_id: Uuid,
        active_version_id: Uuid,
    ) -> Result<bool, StorageError>;

    /// Returns DAU rows for a template.
    async fn template_daus(&self, template_id: Uuid) -> Result<Vec<TemplateDAURow>, StorageError>;

    /// Lists template versions matching the supplied filter.
    async fn list_template_versions(
        &self,
        filter: TemplateVersionListFilter,
    ) -> Result<Vec<TemplateVersionRecord>, StorageError>;

    /// Finds a template version by identifier.
    async fn find_template_version_by_id(
        &self,
        version_id: Uuid,
    ) -> Result<Option<TemplateVersionRecord>, StorageError>;

    /// Finds a template version by template ID and name.
    async fn find_template_version_by_template_and_name(
        &self,
        template_id: Uuid,
        name: &str,
    ) -> Result<Option<TemplateVersionRecord>, StorageError>;

    /// Finds a template version by organization and name.
    async fn find_template_version_by_org_and_name(
        &self,
        organization_id: Uuid,
        template_name: &str,
        version_name: &str,
    ) -> Result<Option<TemplateVersionRecord>, StorageError>;

    /// Creates a new template version.
    async fn insert_template_version(
        &self,
        input: CreateTemplateVersionInput,
    ) -> Result<TemplateVersionRecord, StorageError>;

    /// Updates a template version's name and message.
    async fn update_template_version(
        &self,
        version_id: Uuid,
        name: &str,
        message: &str,
    ) -> Result<Option<TemplateVersionRecord>, StorageError>;

    /// Finds the template version created immediately before the named version.
    async fn find_previous_template_version(
        &self,
        organization_id: Uuid,
        template_name: &str,
        version_name: &str,
    ) -> Result<Option<TemplateVersionRecord>, StorageError>;

    /// Archives a template version.
    async fn archive_template_version(&self, version_id: Uuid) -> Result<bool, StorageError>;

    /// Unarchives a template version.
    async fn unarchive_template_version(&self, version_id: Uuid) -> Result<bool, StorageError>;

    /// Lists parameters for a template version.
    async fn list_template_version_parameters(
        &self,
        version_id: Uuid,
    ) -> Result<Vec<TemplateVersionParameterRecord>, StorageError>;

    /// Lists variables for a template version.
    async fn list_template_version_variables(
        &self,
        version_id: Uuid,
    ) -> Result<Vec<TemplateVersionVariableRecord>, StorageError>;

    /// Lists presets for a template version.
    async fn list_template_version_presets(
        &self,
        version_id: Uuid,
    ) -> Result<Vec<TemplateVersionPresetRecord>, StorageError>;

    /// Lists preset parameters for a specific preset.
    async fn list_template_version_preset_parameters(
        &self,
        preset_id: Uuid,
    ) -> Result<Vec<TemplateVersionPresetParameterRecord>, StorageError>;

    /// Creates a provisioner job (template workflow).
    async fn create_provisioner_job(
        &self,
        input: CreateProvisionerJobInput,
    ) -> Result<TemplateProvisionerJobRecord, StorageError>;

    /// Finds a provisioner job by identifier (template workflow).
    async fn find_provisioner_job(
        &self,
        job_id: Uuid,
    ) -> Result<Option<TemplateProvisionerJobRecord>, StorageError>;

    /// Cancels a provisioner job (template workflow).
    async fn cancel_template_provisioner_job(&self, job_id: Uuid) -> Result<bool, StorageError>;

    /// Archives unused template versions for a template.
    /// If `all` is true, archives all unused versions. Otherwise only failed ones.
    /// Returns the list of archived version IDs.
    async fn archive_unused_template_versions(
        &self,
        template_id: Uuid,
        all: bool,
    ) -> Result<Vec<Uuid>, StorageError>;

    /// Returns the template version created immediately before the given one.
    async fn get_previous_template_version(
        &self,
        organization_id: Uuid,
        name: &str,
        template_id: Option<Uuid>,
    ) -> Result<Option<TemplateVersionRecord>, StorageError>;
}

/// Aggregate store contract used by the current Rust backend slice.
#[allow(clippy::too_many_arguments)]
#[async_trait]
pub trait AppStore: DeploymentStore + ProvisionerStore + Send + Sync {
    /// Returns whether a non-system first user exists.
    async fn first_user_exists(&self) -> Result<bool, StorageError>;

    /// Attempts to create the first user for the deployment.
    async fn create_first_user(
        &self,
        user: CreateFirstUserInput,
    ) -> Result<FirstUserRecord, CreateFirstUserStoreError>;

    /// Looks up a password-backed login user by email.
    async fn find_password_user_by_email(
        &self,
        email: &str,
    ) -> Result<Option<PasswordUserRecord>, StorageError>;

    /// Looks up a password-backed login user by identifier.
    async fn find_password_user_by_id(
        &self,
        user_id: Uuid,
    ) -> Result<Option<PasswordUserRecord>, StorageError>;

    /// Persists a hashed session token for later authentication.
    async fn insert_auth_session(
        &self,
        token_hash: &[u8],
        user_id: Uuid,
    ) -> Result<(), StorageError>;

    /// Looks up a user by hashed session token.
    async fn find_user_by_session_token_hash(
        &self,
        token_hash: &[u8],
    ) -> Result<Option<AuthenticatedUser>, StorageError>;

    /// Deletes a hashed session token.
    async fn delete_auth_session(&self, token_hash: &[u8]) -> Result<bool, StorageError>;

    /// Lists users matching the supplied filter.
    async fn list_users(
        &self,
        filter: UserListFilter,
    ) -> Result<(Vec<UserRecord>, usize), StorageError>;

    /// Creates a new user and inserts the requested organization memberships.
    async fn create_user(&self, input: CreateUserInput)
    -> Result<UserRecord, CreateUserStoreError>;

    /// Looks up a user by stable identifier.
    async fn find_user_by_id(&self, user_id: Uuid) -> Result<Option<UserRecord>, StorageError>;

    /// Looks up a user by username.
    async fn find_user_by_username(
        &self,
        username: &str,
    ) -> Result<Option<UserRecord>, StorageError>;

    /// Soft-deletes a user and revokes its sessions and API keys.
    async fn soft_delete_user(&self, user_id: Uuid) -> Result<bool, StorageError>;

    /// Lists organization memberships for a specific user.
    async fn list_user_memberships(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<OrganizationMemberRecord>, StorageError>;

    /// Replaces the site-wide roles for a user.
    async fn update_user_roles(
        &self,
        user_id: Uuid,
        roles: Vec<String>,
    ) -> Result<Option<UserRecord>, StorageError>;

    /// Updates a user's basic profile fields.
    async fn update_user_profile(
        &self,
        user_id: Uuid,
        username: &str,
        name: &str,
    ) -> Result<Option<UserRecord>, StorageError>;

    /// Updates a user's status.
    async fn update_user_status(
        &self,
        user_id: Uuid,
        status: UserStatus,
    ) -> Result<Option<UserRecord>, StorageError>;

    /// Returns appearance settings for a user.
    async fn user_appearance(&self, user_id: Uuid) -> Result<UserAppearanceRecord, StorageError>;

    /// Updates appearance settings for a user.
    async fn update_user_appearance(
        &self,
        user_id: Uuid,
        theme_preference: &str,
        terminal_font: &str,
    ) -> Result<Option<UserAppearanceRecord>, StorageError>;

    /// Returns preference settings for a user.
    async fn user_preferences(&self, user_id: Uuid) -> Result<UserPreferenceRecord, StorageError>;

    /// Updates preference settings for a user.
    async fn update_user_preferences(
        &self,
        user_id: Uuid,
        task_notification_alert_dismissed: bool,
    ) -> Result<Option<UserPreferenceRecord>, StorageError>;

    /// Lists organizations, optionally filtering by identifiers.
    async fn list_organizations(
        &self,
        organization_ids: Vec<Uuid>,
    ) -> Result<Vec<OrganizationRecord>, StorageError>;

    /// Looks up an organization by stable identifier.
    async fn find_organization_by_id(
        &self,
        organization_id: Uuid,
    ) -> Result<Option<OrganizationRecord>, StorageError>;

    /// Looks up an organization by name.
    async fn find_organization_by_name(
        &self,
        name: &str,
    ) -> Result<Option<OrganizationRecord>, StorageError>;

    /// Lists members for an organization.
    async fn list_organization_members(
        &self,
        filter: OrganizationMemberListFilter,
    ) -> Result<Vec<OrganizationMemberRecord>, StorageError>;

    /// Lists members for an organization together with the total count.
    async fn list_organization_members_page(
        &self,
        filter: OrganizationMemberListFilter,
    ) -> Result<(Vec<OrganizationMemberRecord>, usize), StorageError>;

    /// Looks up a specific organization member.
    async fn find_organization_member(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<OrganizationMemberRecord>, StorageError>;

    /// Inserts a new organization membership.
    async fn insert_organization_member(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> Result<OrganizationMemberRecord, InsertOrganizationMemberError>;

    /// Deletes an organization membership.
    async fn delete_organization_member(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, StorageError>;

    /// Replaces the organization-scoped roles for a member.
    async fn update_organization_member_roles(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
        roles: Vec<String>,
    ) -> Result<Option<OrganizationMemberRecord>, StorageError>;

    /// Stores a one-time passcode hash for the user identified by email.
    async fn store_one_time_passcode_by_email(
        &self,
        email: &str,
        passcode_hash: &str,
        expires_at: OffsetDateTime,
    ) -> Result<(), StorageError>;

    /// Replaces a user's password hash and revokes active sessions and API keys.
    async fn replace_user_password(
        &self,
        user_id: Uuid,
        password_hash: &str,
        clear_one_time_passcode: bool,
    ) -> Result<bool, StorageError>;

    /// Inserts a new API key record.
    async fn create_api_key(
        &self,
        input: CreateApiKeyInput,
    ) -> Result<ApiKeyRecord, CreateApiKeyStoreError>;

    /// Looks up an API key by stable identifier.
    async fn find_api_key_by_id(&self, id: &str) -> Result<Option<ApiKeyRecord>, StorageError>;

    /// Looks up an API key by user and token name.
    async fn find_api_key_by_name(
        &self,
        user_id: Uuid,
        token_name: &str,
    ) -> Result<Option<ApiKeyRecord>, StorageError>;

    /// Lists API keys using the supplied filter.
    async fn list_api_keys(
        &self,
        filter: ApiKeyListFilter,
    ) -> Result<Vec<ApiKeyWithOwnerRecord>, StorageError>;

    /// Deletes an API key.
    async fn delete_api_key(&self, id: &str) -> Result<bool, StorageError>;

    /// Expires an API key in-place.
    async fn expire_api_key(&self, id: &str, now: OffsetDateTime) -> Result<bool, StorageError>;

    /// Returns token-lifetime settings for the given user.
    async fn token_config(&self, user_id: Uuid) -> Result<TokenConfigRecord, StorageError>;

    /// Lists audit logs using the supplied filter.
    async fn list_audit_logs(
        &self,
        filter: AuditLogListFilter,
    ) -> Result<AuditLogResponse, StorageError> {
        let _ = filter;
        Err(StorageError::unavailable("audit logs are not implemented"))
    }

    /// Persists one audit log entry.
    async fn insert_audit_log(&self, input: PersistAuditLogInput) -> Result<(), StorageError> {
        let _ = input;
        Err(StorageError::unavailable(
            "audit log inserts are not implemented",
        ))
    }

    /// Returns deployment health settings.
    async fn health_settings(&self) -> Result<HealthSettings, StorageError> {
        Err(StorageError::unavailable(
            "deployment health settings are not implemented",
        ))
    }

    /// Replaces deployment health settings, returning whether the value changed.
    async fn upsert_health_settings(
        &self,
        settings: &HealthSettings,
    ) -> Result<bool, StorageError> {
        let _ = settings;
        Err(StorageError::unavailable(
            "deployment health settings are not implemented",
        ))
    }

    /// Returns deployment statistics for the current backend slice.
    async fn deployment_stats(&self) -> Result<crate::api::DeploymentStatsResponse, StorageError> {
        Err(StorageError::unavailable(
            "deployment stats are not implemented",
        ))
    }

    /// Upserts one workspace into the deployment-stats foundation tables.
    async fn upsert_workspace_stats_workspace(
        &self,
        input: &WorkspaceStatsWorkspaceInput,
    ) -> Result<(), StorageError> {
        let _ = input;
        Err(StorageError::unavailable(
            "workspace stats writers are not implemented",
        ))
    }

    /// Upserts one provisioner job into the deployment-stats foundation tables.
    async fn upsert_provisioner_job_stats(
        &self,
        input: &ProvisionerJobStatsInput,
    ) -> Result<(), StorageError> {
        let _ = input;
        Err(StorageError::unavailable(
            "provisioner stats writers are not implemented",
        ))
    }

    /// Upserts one workspace build into the deployment-stats foundation tables.
    async fn upsert_workspace_build_stats(
        &self,
        input: &WorkspaceBuildStatsInput,
    ) -> Result<(), StorageError> {
        let _ = input;
        Err(StorageError::unavailable(
            "workspace build stats writers are not implemented",
        ))
    }

    /// Inserts one raw agent-stat sample into the deployment-stats foundation tables.
    async fn insert_workspace_agent_stat(
        &self,
        input: &WorkspaceAgentStatInput,
    ) -> Result<(), StorageError> {
        let _ = input;
        Err(StorageError::unavailable(
            "workspace agent stats writers are not implemented",
        ))
    }

    /// Lists persisted workspace proxies for deployment health checks.
    async fn list_workspace_proxies_for_health(
        &self,
    ) -> Result<Vec<WorkspaceProxyHealthRecord>, StorageError> {
        Err(StorageError::unavailable(
            "workspace proxy health is not implemented",
        ))
    }

    /// Upserts one workspace proxy for deployment health checks.
    async fn upsert_workspace_proxy_for_health(
        &self,
        input: &WorkspaceProxyHealthInput,
    ) -> Result<(), StorageError> {
        let _ = input;
        Err(StorageError::unavailable(
            "workspace proxy health is not implemented",
        ))
    }

    /// Lists persisted provisioner daemons for deployment health checks.
    async fn list_provisioner_daemons_for_health(
        &self,
    ) -> Result<Vec<ProvisionerDaemonHealthRecord>, StorageError> {
        Err(StorageError::unavailable(
            "provisioner daemon health is not implemented",
        ))
    }

    /// Upserts one provisioner daemon for deployment health checks.
    async fn upsert_provisioner_daemon_for_health(
        &self,
        input: &ProvisionerDaemonHealthInput,
    ) -> Result<(), StorageError> {
        let _ = input;
        Err(StorageError::unavailable(
            "provisioner daemon health is not implemented",
        ))
    }

    /// Returns the stored git SSH keypair when one exists.
    async fn find_git_ssh_key(
        &self,
        user_id: Uuid,
    ) -> Result<Option<GitSshKeyRecord>, StorageError> {
        let _ = user_id;
        Err(StorageError::unavailable(
            "git ssh keys are not implemented",
        ))
    }

    /// Inserts or updates the git SSH keypair for a user.
    async fn upsert_git_ssh_key(
        &self,
        user_id: Uuid,
        public_key: &str,
        private_key: &str,
    ) -> Result<GitSshKeyRecord, StorageError> {
        let _ = (user_id, public_key, private_key);
        Err(StorageError::unavailable(
            "git ssh keys are not implemented",
        ))
    }

    /// Inserts a new file record.
    async fn insert_file(&self, input: InsertFileInput) -> Result<InsertFileResult, StorageError> {
        let _ = input;
        Err(StorageError::unavailable("file storage is not implemented"))
    }

    /// Looks up a file by stable identifier.
    async fn get_file_by_id(&self, file_id: Uuid) -> Result<Option<FileRecord>, StorageError> {
        let _ = file_id;
        Err(StorageError::unavailable("file storage is not implemented"))
    }

    /// Looks up a file by hash and creator.
    async fn get_file_by_hash_and_creator(
        &self,
        hash: &str,
        creator_id: Uuid,
    ) -> Result<Option<FileRecord>, StorageError> {
        let _ = (hash, creator_id);
        Err(StorageError::unavailable("file storage is not implemented"))
    }

    /// Lists configured external-auth links for one user.
    async fn list_external_auth_links(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<ExternalAuthLinkRecord>, StorageError> {
        let _ = user_id;
        Err(StorageError::unavailable(
            "external auth links are not implemented",
        ))
    }

    /// Looks up one external-auth link for a user.
    async fn find_external_auth_link(
        &self,
        user_id: Uuid,
        provider_id: &str,
    ) -> Result<Option<ExternalAuthLinkRecord>, StorageError> {
        let _ = (user_id, provider_id);
        Err(StorageError::unavailable(
            "external auth links are not implemented",
        ))
    }

    /// Deletes one external-auth link for a user.
    async fn delete_external_auth_link(
        &self,
        user_id: Uuid,
        provider_id: &str,
    ) -> Result<bool, StorageError> {
        let _ = (user_id, provider_id);
        Err(StorageError::unavailable(
            "external auth links are not implemented",
        ))
    }

    /// Inserts or updates one external-auth link for a user.
    async fn upsert_external_auth_link(
        &self,
        user_id: Uuid,
        link: &UpsertExternalAuthLinkInput,
    ) -> Result<ExternalAuthLinkRecord, StorageError> {
        let _ = (user_id, link);
        Err(StorageError::unavailable(
            "external auth links are not implemented",
        ))
    }

    // ── InsightsStore delegate methods ──────────────────────────────

    /// Returns DAU entries for the deployment.
    async fn get_deployment_daus(&self, tz_offset: i32) -> Result<DAUsResponse, StorageError> {
        let _ = tz_offset;
        Err(StorageError::unavailable(
            "deployment DAUs are not implemented",
        ))
    }

    /// Returns template-level insights for a time range.
    async fn get_template_insights(
        &self,
        start_time: OffsetDateTime,
        end_time: OffsetDateTime,
        interval: InsightsReportInterval,
        template_ids: Vec<Uuid>,
    ) -> Result<TemplateInsightsResponse, StorageError> {
        let _ = (start_time, end_time, interval, template_ids);
        Err(StorageError::unavailable(
            "template insights are not implemented",
        ))
    }

    /// Returns template insights broken down by interval.
    async fn get_template_insights_by_interval(
        &self,
        start_time: OffsetDateTime,
        end_time: OffsetDateTime,
        interval: InsightsReportInterval,
        template_ids: Vec<Uuid>,
    ) -> Result<Vec<TemplateInsightsIntervalReport>, StorageError> {
        let _ = (start_time, end_time, interval, template_ids);
        Err(StorageError::unavailable(
            "template insights by interval are not implemented",
        ))
    }

    /// Returns per-user activity insights for a time range.
    async fn get_user_activity_insights(
        &self,
        start_time: OffsetDateTime,
        end_time: OffsetDateTime,
        template_ids: Vec<Uuid>,
    ) -> Result<UserActivityInsightsResponse, StorageError> {
        let _ = (start_time, end_time, template_ids);
        Err(StorageError::unavailable(
            "user activity insights are not implemented",
        ))
    }

    /// Returns per-user latency insights for a time range.
    async fn get_user_latency_insights(
        &self,
        start_time: OffsetDateTime,
        end_time: OffsetDateTime,
        template_ids: Vec<Uuid>,
    ) -> Result<UserLatencyInsightsResponse, StorageError> {
        let _ = (start_time, end_time, template_ids);
        Err(StorageError::unavailable(
            "user latency insights are not implemented",
        ))
    }

    /// Returns user status counts over time.
    async fn get_user_status_counts(
        &self,
        timezone: &str,
        start_time: OffsetDateTime,
        end_time: OffsetDateTime,
    ) -> Result<GetUserStatusCountsResponse, StorageError> {
        let _ = (timezone, start_time, end_time);
        Err(StorageError::unavailable(
            "user status counts are not implemented",
        ))
    }

    // -----------------------------------------------------------------------
    // Tasks
    // -----------------------------------------------------------------------

    /// Inserts a new task.
    async fn insert_task(&self, input: InsertTaskInput) -> Result<TaskRecord, StorageError> {
        let _ = input;
        Err(StorageError::unavailable("tasks are not implemented"))
    }

    /// Fetches a task by ID.
    async fn find_task_by_id(&self, id: Uuid) -> Result<Option<TaskRecord>, StorageError> {
        let _ = id;
        Err(StorageError::unavailable("tasks are not implemented"))
    }

    /// Fetches a task by owner ID and name.
    async fn find_task_by_owner_and_name(
        &self,
        owner_id: Uuid,
        name: &str,
    ) -> Result<Option<TaskRecord>, StorageError> {
        let _ = (owner_id, name);
        Err(StorageError::unavailable("tasks are not implemented"))
    }

    /// Lists tasks matching the supplied filter.
    async fn list_tasks(&self, filter: TaskListFilter) -> Result<Vec<TaskRecord>, StorageError> {
        let _ = filter;
        Err(StorageError::unavailable("tasks are not implemented"))
    }

    /// Soft-deletes a task by ID.
    async fn delete_task(
        &self,
        id: Uuid,
        deleted_at: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let _ = (id, deleted_at);
        Err(StorageError::unavailable("tasks are not implemented"))
    }

    /// Updates a task's prompt.
    async fn update_task_prompt(
        &self,
        id: Uuid,
        prompt: &str,
    ) -> Result<Option<TaskRecord>, StorageError> {
        let _ = (id, prompt);
        Err(StorageError::unavailable("tasks are not implemented"))
    }

    /// Upserts a task log snapshot.
    async fn upsert_task_snapshot(
        &self,
        task_id: Uuid,
        log_snapshot: &Value,
        log_snapshot_created_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        let _ = (task_id, log_snapshot, log_snapshot_created_at);
        Err(StorageError::unavailable("tasks are not implemented"))
    }

    /// Fetches the task log snapshot.
    async fn find_task_snapshot(
        &self,
        task_id: Uuid,
    ) -> Result<Option<TaskSnapshotRecord>, StorageError> {
        let _ = task_id;
        Err(StorageError::unavailable("tasks are not implemented"))
    }

    // -----------------------------------------------------------------------
    // Chats
    // -----------------------------------------------------------------------

    /// Inserts a new chat.
    async fn insert_chat(&self, input: InsertChatInput) -> Result<ChatRecord, StorageError> {
        let _ = input;
        Err(StorageError::unavailable("chats are not implemented"))
    }

    /// Fetches a chat by ID.
    async fn find_chat_by_id(&self, id: Uuid) -> Result<Option<ChatRecord>, StorageError> {
        let _ = id;
        Err(StorageError::unavailable("chats are not implemented"))
    }

    /// Lists chats by owner ID.
    async fn list_chats_by_owner(
        &self,
        owner_id: Uuid,
        archived: Option<bool>,
    ) -> Result<Vec<ChatRecord>, StorageError> {
        let _ = (owner_id, archived);
        Err(StorageError::unavailable("chats are not implemented"))
    }

    /// Archives a chat by ID (sets archived = true for the chat and all chats
    /// sharing the same root).
    async fn archive_chat(&self, id: Uuid) -> Result<(), StorageError> {
        let _ = id;
        Err(StorageError::unavailable("chats are not implemented"))
    }

    /// Fetches chat messages by chat ID.
    async fn list_chat_messages(
        &self,
        chat_id: Uuid,
        after_id: i64,
    ) -> Result<Vec<ChatMessageRecord>, StorageError> {
        let _ = (chat_id, after_id);
        Err(StorageError::unavailable("chats are not implemented"))
    }

    /// Inserts a chat message.
    async fn insert_chat_message(
        &self,
        input: InsertChatMessageInput,
    ) -> Result<ChatMessageRecord, StorageError> {
        let _ = input;
        Err(StorageError::unavailable("chats are not implemented"))
    }

    /// Lists queued messages for a chat.
    async fn list_chat_queued_messages(
        &self,
        chat_id: Uuid,
    ) -> Result<Vec<ChatQueuedMessageRecord>, StorageError> {
        let _ = chat_id;
        Err(StorageError::unavailable("chats are not implemented"))
    }

    /// Unarchives a chat by ID (sets archived = false for the single chat).
    async fn unarchive_chat(&self, id: Uuid) -> Result<(), StorageError> {
        let _ = id;
        Err(StorageError::unavailable("chats are not implemented"))
    }

    // -----------------------------------------------------------------------
    // Chat Files
    // -----------------------------------------------------------------------

    /// Inserts a new chat file.
    async fn insert_chat_file(
        &self,
        input: InsertChatFileInput,
    ) -> Result<ChatFileRecord, StorageError> {
        let _ = input;
        Err(StorageError::unavailable("chat files are not implemented"))
    }

    /// Fetches a chat file by ID.
    async fn find_chat_file_by_id(&self, id: Uuid) -> Result<Option<ChatFileRecord>, StorageError> {
        let _ = id;
        Err(StorageError::unavailable("chat files are not implemented"))
    }

    // -----------------------------------------------------------------------
    // Workspace Agent storage methods
    // -----------------------------------------------------------------------

    /// Looks up a workspace agent by stable identifier.
    async fn find_workspace_agent_by_id(
        &self,
        agent_id: Uuid,
    ) -> Result<Option<WorkspaceAgentRow>, StorageError> {
        let _ = agent_id;
        Err(StorageError::unavailable(
            "workspace agents are not implemented",
        ))
    }

    /// Looks up a workspace agent by auth token.
    async fn find_workspace_agent_by_auth_token(
        &self,
        auth_token: Uuid,
    ) -> Result<Option<WorkspaceAgentRow>, StorageError> {
        let _ = auth_token;
        Err(StorageError::unavailable(
            "workspace agents are not implemented",
        ))
    }

    /// Looks up a workspace agent by instance identity.
    async fn find_workspace_agent_by_instance_id(
        &self,
        instance_id: &str,
    ) -> Result<Option<WorkspaceAgentRow>, StorageError> {
        let _ = instance_id;
        Err(StorageError::unavailable(
            "workspace agents are not implemented",
        ))
    }

    /// Lists workspace agents for a given resource.
    async fn list_workspace_agents_by_resource_ids(
        &self,
        resource_ids: &[Uuid],
    ) -> Result<Vec<WorkspaceAgentRow>, StorageError> {
        let _ = resource_ids;
        Err(StorageError::unavailable(
            "workspace agents are not implemented",
        ))
    }

    /// Lists workspace apps for a given agent.
    async fn list_workspace_apps_by_agent_id(
        &self,
        agent_id: Uuid,
    ) -> Result<Vec<WorkspaceAppRow>, StorageError> {
        let _ = agent_id;
        Err(StorageError::unavailable(
            "workspace apps are not implemented",
        ))
    }

    /// Lists workspace agent scripts for a given agent.
    async fn list_workspace_agent_scripts(
        &self,
        agent_id: Uuid,
    ) -> Result<Vec<WorkspaceAgentScriptRow>, StorageError> {
        let _ = agent_id;
        Err(StorageError::unavailable(
            "workspace agent scripts are not implemented",
        ))
    }

    /// Lists workspace agent log sources for a given agent.
    async fn list_workspace_agent_log_sources(
        &self,
        agent_id: Uuid,
    ) -> Result<Vec<WorkspaceAgentLogSourceRow>, StorageError> {
        let _ = agent_id;
        Err(StorageError::unavailable(
            "workspace agent log sources are not implemented",
        ))
    }

    /// Lists workspace agent logs for a given agent.
    async fn list_workspace_agent_logs(
        &self,
        agent_id: Uuid,
        after_id: i64,
        limit: i64,
    ) -> Result<Vec<WorkspaceAgentLogRow>, StorageError> {
        let _ = (agent_id, after_id, limit);
        Err(StorageError::unavailable(
            "workspace agent logs are not implemented",
        ))
    }

    /// Inserts workspace agent logs.
    async fn insert_workspace_agent_logs(
        &self,
        agent_id: Uuid,
        log_source_id: Uuid,
        logs: &[InsertAgentLogInput],
    ) -> Result<Vec<WorkspaceAgentLogRow>, StorageError> {
        let _ = (agent_id, log_source_id, logs);
        Err(StorageError::unavailable(
            "workspace agent logs are not implemented",
        ))
    }

    /// Lists workspace agent metadata for a given agent.
    async fn list_workspace_agent_metadata(
        &self,
        agent_id: Uuid,
    ) -> Result<Vec<WorkspaceAgentMetadataRow>, StorageError> {
        let _ = agent_id;
        Err(StorageError::unavailable(
            "workspace agent metadata are not implemented",
        ))
    }

    /// Lists devcontainers for a given agent.
    async fn list_workspace_agent_devcontainers(
        &self,
        agent_id: Uuid,
    ) -> Result<Vec<WorkspaceAgentDevcontainerRow>, StorageError> {
        let _ = agent_id;
        Err(StorageError::unavailable(
            "workspace agent devcontainers are not implemented",
        ))
    }

    /// Creates a workspace agent log source.
    async fn insert_workspace_agent_log_source(
        &self,
        agent_id: Uuid,
        id: Option<Uuid>,
        display_name: &str,
        icon: &str,
    ) -> Result<WorkspaceAgentLogSourceRow, StorageError> {
        let _ = (agent_id, id, display_name, icon);
        Err(StorageError::unavailable(
            "workspace agent log sources are not implemented",
        ))
    }

    /// Finds a workspace by agent ID (looks up resource → build → workspace).
    async fn find_workspace_by_agent_id(
        &self,
        agent_id: Uuid,
    ) -> Result<Option<WorkspaceRecord>, StorageError> {
        let _ = agent_id;
        Err(StorageError::unavailable("workspaces are not implemented"))
    }

    /// Lists workspace app statuses for a given agent.
    async fn list_workspace_app_statuses_by_agent_id(
        &self,
        agent_id: Uuid,
    ) -> Result<Vec<WorkspaceAppStatusRow>, StorageError> {
        let _ = agent_id;
        Err(StorageError::unavailable(
            "workspace app statuses are not implemented",
        ))
    }

    /// Inserts a workspace app status.
    async fn insert_workspace_app_status(
        &self,
        input: &InsertWorkspaceAppStatusInput,
    ) -> Result<WorkspaceAppStatusRow, StorageError> {
        let _ = input;
        Err(StorageError::unavailable(
            "workspace app statuses are not implemented",
        ))
    }

    /// Finds a workspace app by agent ID and slug.
    async fn find_workspace_app_by_agent_and_slug(
        &self,
        agent_id: Uuid,
        slug: &str,
    ) -> Result<Option<WorkspaceAppRow>, StorageError> {
        let _ = (agent_id, slug);
        Err(StorageError::unavailable(
            "workspace apps are not implemented",
        ))
    }

    // -----------------------------------------------------------------------
    // Workspace domain methods
    // -----------------------------------------------------------------------

    /// Lists workspaces matching the supplied filter.
    async fn list_workspaces(
        &self,
        filter: WorkspaceListFilter,
    ) -> Result<(Vec<WorkspaceRecord>, i64), StorageError> {
        let _ = filter;
        Err(StorageError::unavailable("workspaces are not implemented"))
    }

    /// Looks up a workspace by stable identifier.
    async fn find_workspace_by_id(
        &self,
        workspace_id: Uuid,
        viewer_id: Option<Uuid>,
    ) -> Result<Option<WorkspaceRecord>, StorageError> {
        let _ = (workspace_id, viewer_id);
        Err(StorageError::unavailable("workspaces are not implemented"))
    }

    /// Looks up a workspace by owner and name.
    async fn find_workspace_by_owner_and_name(
        &self,
        owner_id: Uuid,
        name: &str,
        viewer_id: Option<Uuid>,
    ) -> Result<Option<WorkspaceRecord>, StorageError> {
        let _ = (owner_id, name, viewer_id);
        Err(StorageError::unavailable("workspaces are not implemented"))
    }

    /// Creates a new workspace.
    async fn insert_workspace(
        &self,
        input: CreateWorkspaceInput,
    ) -> Result<WorkspaceRecord, StorageError> {
        let _ = input;
        Err(StorageError::unavailable("workspaces are not implemented"))
    }

    /// Updates a workspace name.
    async fn update_workspace_name(
        &self,
        workspace_id: Uuid,
        name: &str,
        viewer_id: Option<Uuid>,
    ) -> Result<Option<WorkspaceRecord>, StorageError> {
        let _ = (workspace_id, name, viewer_id);
        Err(StorageError::unavailable("workspaces are not implemented"))
    }

    /// Updates a workspace autostart schedule.
    async fn update_workspace_autostart(
        &self,
        workspace_id: Uuid,
        schedule: Option<&str>,
    ) -> Result<bool, StorageError> {
        let _ = (workspace_id, schedule);
        Err(StorageError::unavailable("workspaces are not implemented"))
    }

    /// Updates a workspace TTL.
    async fn update_workspace_ttl(
        &self,
        workspace_id: Uuid,
        ttl_ns: Option<i64>,
    ) -> Result<bool, StorageError> {
        let _ = (workspace_id, ttl_ns);
        Err(StorageError::unavailable("workspaces are not implemented"))
    }

    /// Updates workspace dormancy.
    async fn update_workspace_dormant_at(
        &self,
        workspace_id: Uuid,
        dormant_at: Option<OffsetDateTime>,
        viewer_id: Option<Uuid>,
    ) -> Result<Option<WorkspaceRecord>, StorageError> {
        let _ = (workspace_id, dormant_at, viewer_id);
        Err(StorageError::unavailable("workspaces are not implemented"))
    }

    /// Updates workspace automatic updates.
    async fn update_workspace_automatic_updates(
        &self,
        workspace_id: Uuid,
        automatic_updates: &str,
    ) -> Result<bool, StorageError> {
        let _ = (workspace_id, automatic_updates);
        Err(StorageError::unavailable("workspaces are not implemented"))
    }

    /// Updates workspace last used time.
    async fn update_workspace_last_used_at(
        &self,
        workspace_id: Uuid,
        last_used_at: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let _ = (workspace_id, last_used_at);
        Err(StorageError::unavailable("workspaces are not implemented"))
    }

    /// Sets workspace favorite status.
    async fn favorite_workspace(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
        favorite: bool,
    ) -> Result<bool, StorageError> {
        let _ = (workspace_id, user_id, favorite);
        Err(StorageError::unavailable("workspaces are not implemented"))
    }

    /// Soft-deletes a workspace.
    async fn soft_delete_workspace(&self, workspace_id: Uuid) -> Result<bool, StorageError> {
        let _ = workspace_id;
        Err(StorageError::unavailable("workspaces are not implemented"))
    }

    /// Creates a new group.
    async fn create_group(&self, input: &CreateGroupInput) -> Result<GroupRecord, StorageError> {
        let _ = input;
        Err(StorageError::unavailable("groups are not implemented"))
    }

    /// Deletes a group.
    async fn delete_group(&self, group_id: Uuid) -> Result<bool, StorageError> {
        let _ = group_id;
        Err(StorageError::unavailable("groups are not implemented"))
    }

    /// Lists groups for an organization.
    async fn list_groups(&self, organization_id: Uuid) -> Result<Vec<GroupRecord>, StorageError> {
        let _ = organization_id;
        Err(StorageError::unavailable("groups are not implemented"))
    }

    /// Adds a user to a group.
    async fn insert_group_member(&self, group_id: Uuid, user_id: Uuid) -> Result<(), StorageError> {
        let _ = (group_id, user_id);
        Err(StorageError::unavailable(
            "group members are not implemented",
        ))
    }

    /// Lists members of a group.
    async fn list_group_members(
        &self,
        group_id: Uuid,
    ) -> Result<Vec<GroupMemberRecord>, StorageError> {
        let _ = group_id;
        Err(StorageError::unavailable(
            "group members are not implemented",
        ))
    }

    /// Removes a user from a group.
    async fn delete_group_member(
        &self,
        group_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, StorageError> {
        let _ = (group_id, user_id);
        Err(StorageError::unavailable(
            "group members are not implemented",
        ))
    }

    /// Looks up a group by identifier.
    async fn find_group_by_id(&self, group_id: Uuid) -> Result<Option<GroupRecord>, StorageError> {
        let _ = group_id;
        Err(StorageError::unavailable("groups are not implemented"))
    }

    /// Returns the ACL for a workspace.
    async fn get_workspace_acl(
        &self,
        workspace_id: Uuid,
    ) -> Result<WorkspaceACLRecord, StorageError> {
        let _ = workspace_id;
        Err(StorageError::unavailable(
            "workspace ACL is not implemented",
        ))
    }

    /// Updates workspace ACL entries.
    async fn update_workspace_acl(
        &self,
        workspace_id: Uuid,
        input: &UpdateWorkspaceACLInput,
    ) -> Result<(), StorageError> {
        let _ = (workspace_id, input);
        Err(StorageError::unavailable(
            "workspace ACL is not implemented",
        ))
    }

    /// Clears all workspace ACL entries.
    async fn delete_workspace_acl(&self, workspace_id: Uuid) -> Result<(), StorageError> {
        let _ = workspace_id;
        Err(StorageError::unavailable(
            "workspace ACL is not implemented",
        ))
    }

    /// Lists workspace builds for a workspace.
    async fn list_workspace_builds(
        &self,
        workspace_id: Uuid,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<WorkspaceBuildRecord>, StorageError> {
        let _ = (workspace_id, limit, offset);
        Err(StorageError::unavailable(
            "workspace builds are not implemented",
        ))
    }

    /// Returns the latest build for a workspace.
    async fn find_latest_workspace_build(
        &self,
        workspace_id: Uuid,
    ) -> Result<Option<WorkspaceBuildRecord>, StorageError> {
        let _ = workspace_id;
        Err(StorageError::unavailable(
            "workspace builds are not implemented",
        ))
    }

    /// Looks up a workspace build by stable identifier.
    async fn find_workspace_build_by_id(
        &self,
        build_id: Uuid,
    ) -> Result<Option<WorkspaceBuildRecord>, StorageError> {
        let _ = build_id;
        Err(StorageError::unavailable(
            "workspace builds are not implemented",
        ))
    }

    /// Looks up a workspace build by workspace and build number.
    async fn find_workspace_build_by_number(
        &self,
        workspace_id: Uuid,
        build_number: i64,
    ) -> Result<Option<WorkspaceBuildRecord>, StorageError> {
        let _ = (workspace_id, build_number);
        Err(StorageError::unavailable(
            "workspace builds are not implemented",
        ))
    }

    /// Creates a new workspace build.
    async fn insert_workspace_build(
        &self,
        input: CreateWorkspaceBuildInput,
    ) -> Result<WorkspaceBuildRecord, StorageError> {
        let _ = input;
        Err(StorageError::unavailable(
            "workspace builds are not implemented",
        ))
    }

    /// Updates the build deadline.
    async fn update_workspace_build_deadline(
        &self,
        build_id: Uuid,
        deadline: Option<OffsetDateTime>,
        max_deadline: Option<OffsetDateTime>,
    ) -> Result<bool, StorageError> {
        let _ = (build_id, deadline, max_deadline);
        Err(StorageError::unavailable(
            "workspace builds are not implemented",
        ))
    }

    /// Updates the provisioner state blob for a build.
    async fn update_workspace_build_provisioner_state(
        &self,
        build_id: Uuid,
        state: &[u8],
    ) -> Result<bool, StorageError> {
        let _ = (build_id, state);
        Err(StorageError::unavailable(
            "workspace builds are not implemented",
        ))
    }

    /// Returns the next build number for a workspace.
    async fn next_workspace_build_number(&self, workspace_id: Uuid) -> Result<i64, StorageError> {
        let _ = workspace_id;
        Err(StorageError::unavailable(
            "workspace builds are not implemented",
        ))
    }

    /// Lists build parameters for a workspace build.
    async fn list_workspace_build_parameters(
        &self,
        build_id: Uuid,
    ) -> Result<Vec<WorkspaceBuildParameterRecord>, StorageError> {
        let _ = build_id;
        Err(StorageError::unavailable(
            "workspace build parameters are not implemented",
        ))
    }

    /// Inserts build parameters.
    async fn insert_workspace_build_parameters(
        &self,
        build_id: Uuid,
        params: &[(String, String)],
    ) -> Result<(), StorageError> {
        let _ = (build_id, params);
        Err(StorageError::unavailable(
            "workspace build parameters are not implemented",
        ))
    }

    /// Lists provisioner job logs.
    async fn list_provisioner_job_logs(
        &self,
        job_id: Uuid,
        after: Option<i64>,
    ) -> Result<Vec<ProvisionerJobLogRecord>, StorageError> {
        let _ = (job_id, after);
        Err(StorageError::unavailable(
            "provisioner job logs are not implemented",
        ))
    }

    /// Lists provisioner job timings.
    async fn list_provisioner_job_timings(
        &self,
        job_id: Uuid,
    ) -> Result<Vec<ProvisionerJobTimingRecord>, StorageError> {
        let _ = job_id;
        Err(StorageError::unavailable(
            "provisioner job timings are not implemented",
        ))
    }

    /// Looks up a workspace resource by stable identifier.
    async fn find_workspace_resource_by_id(
        &self,
        resource_id: Uuid,
    ) -> Result<Option<WorkspaceResourceRecord>, StorageError> {
        let _ = resource_id;
        Err(StorageError::unavailable(
            "workspace resources are not implemented",
        ))
    }

    /// Lists workspace agent script timings for a build.
    async fn list_workspace_agent_script_timings_by_build_id(
        &self,
        build_id: Uuid,
    ) -> Result<Vec<WorkspaceAgentScriptTimingRow>, StorageError> {
        let _ = build_id;
        Err(StorageError::unavailable(
            "workspace agent script timings are not implemented",
        ))
    }

    /// Lists workspace resources for a job.
    async fn list_workspace_resources_by_job(
        &self,
        job_id: Uuid,
    ) -> Result<Vec<WorkspaceResourceRecord>, StorageError> {
        let _ = job_id;
        Err(StorageError::unavailable(
            "workspace resources are not implemented",
        ))
    }

    /// Lists metadata for a set of workspace resources.
    async fn list_workspace_resource_metadata(
        &self,
        resource_ids: &[Uuid],
    ) -> Result<Vec<WorkspaceResourceMetadataRecord>, StorageError> {
        let _ = resource_ids;
        Err(StorageError::unavailable(
            "workspace resource metadata is not implemented",
        ))
    }

    /// Lists port shares for a workspace.
    async fn list_workspace_port_shares(
        &self,
        workspace_id: Uuid,
    ) -> Result<Vec<WorkspaceAgentPortShareRecord>, StorageError> {
        let _ = workspace_id;
        Err(StorageError::unavailable("port shares are not implemented"))
    }

    /// Upserts a port share.
    async fn upsert_workspace_port_share(
        &self,
        input: UpsertPortShareInput,
    ) -> Result<WorkspaceAgentPortShareRecord, StorageError> {
        let _ = input;
        Err(StorageError::unavailable("port shares are not implemented"))
    }

    /// Finds a port share.
    async fn find_workspace_port_share(
        &self,
        workspace_id: Uuid,
        agent_name: &str,
        port: i32,
    ) -> Result<Option<WorkspaceAgentPortShareRecord>, StorageError> {
        let _ = (workspace_id, agent_name, port);
        Err(StorageError::unavailable("port shares are not implemented"))
    }

    /// Deletes a port share.
    async fn delete_workspace_port_share(
        &self,
        workspace_id: Uuid,
        agent_name: &str,
        port: i32,
    ) -> Result<bool, StorageError> {
        let _ = (workspace_id, agent_name, port);
        Err(StorageError::unavailable("port shares are not implemented"))
    }

    // ----- Template Store Methods -----

    /// Lists templates matching the supplied filter.
    async fn list_templates(
        &self,
        filter: TemplateListFilter,
    ) -> Result<Vec<TemplateRecord>, StorageError> {
        let _ = filter;
        Err(StorageError::unavailable("templates are not implemented"))
    }

    /// Finds a template by identifier.
    async fn find_template_by_id(
        &self,
        template_id: Uuid,
    ) -> Result<Option<TemplateRecord>, StorageError> {
        let _ = template_id;
        Err(StorageError::unavailable("templates are not implemented"))
    }

    /// Finds a template by organization and name.
    async fn find_template_by_org_and_name(
        &self,
        organization_id: Uuid,
        name: &str,
    ) -> Result<Option<TemplateRecord>, StorageError> {
        let _ = (organization_id, name);
        Err(StorageError::unavailable("templates are not implemented"))
    }

    /// Creates a new template.
    async fn insert_template(
        &self,
        input: CreateTemplateInput,
    ) -> Result<TemplateRecord, CreateTemplateStoreError> {
        let _ = input;
        Err(CreateTemplateStoreError::Storage(
            StorageError::unavailable("templates are not implemented"),
        ))
    }

    /// Updates a template's metadata.
    async fn update_template_meta(
        &self,
        input: UpdateTemplateMetaInput,
    ) -> Result<Option<TemplateRecord>, StorageError> {
        let _ = input;
        Err(StorageError::unavailable("templates are not implemented"))
    }

    /// Soft-deletes a template.
    async fn soft_delete_template(&self, template_id: Uuid) -> Result<bool, StorageError> {
        let _ = template_id;
        Err(StorageError::unavailable("templates are not implemented"))
    }

    /// Updates the active version on a template.
    async fn update_template_active_version(
        &self,
        template_id: Uuid,
        active_version_id: Uuid,
    ) -> Result<bool, StorageError> {
        let _ = (template_id, active_version_id);
        Err(StorageError::unavailable("templates are not implemented"))
    }

    /// Returns DAU rows for a template.
    async fn template_daus(&self, template_id: Uuid) -> Result<Vec<TemplateDAURow>, StorageError> {
        let _ = template_id;
        Err(StorageError::unavailable("templates are not implemented"))
    }

    /// Lists template versions matching the supplied filter.
    async fn list_template_versions(
        &self,
        filter: TemplateVersionListFilter,
    ) -> Result<Vec<TemplateVersionRecord>, StorageError> {
        let _ = filter;
        Err(StorageError::unavailable(
            "template versions are not implemented",
        ))
    }

    /// Finds a template version by identifier.
    async fn find_template_version_by_id(
        &self,
        version_id: Uuid,
    ) -> Result<Option<TemplateVersionRecord>, StorageError> {
        let _ = version_id;
        Err(StorageError::unavailable(
            "template versions are not implemented",
        ))
    }

    /// Finds a template version by template ID and name.
    async fn find_template_version_by_template_and_name(
        &self,
        template_id: Uuid,
        name: &str,
    ) -> Result<Option<TemplateVersionRecord>, StorageError> {
        let _ = (template_id, name);
        Err(StorageError::unavailable(
            "template versions are not implemented",
        ))
    }

    /// Finds a template version by organization and name.
    async fn find_template_version_by_org_and_name(
        &self,
        organization_id: Uuid,
        template_name: &str,
        version_name: &str,
    ) -> Result<Option<TemplateVersionRecord>, StorageError> {
        let _ = (organization_id, template_name, version_name);
        Err(StorageError::unavailable(
            "template versions are not implemented",
        ))
    }

    /// Creates a new template version.
    async fn insert_template_version(
        &self,
        input: CreateTemplateVersionInput,
    ) -> Result<TemplateVersionRecord, StorageError> {
        let _ = input;
        Err(StorageError::unavailable(
            "template versions are not implemented",
        ))
    }

    /// Updates a template version's name and message.
    async fn update_template_version(
        &self,
        version_id: Uuid,
        name: &str,
        message: &str,
    ) -> Result<Option<TemplateVersionRecord>, StorageError> {
        let _ = (version_id, name, message);
        Err(StorageError::unavailable(
            "template versions are not implemented",
        ))
    }

    /// Finds the template version created immediately before the named version.
    async fn find_previous_template_version(
        &self,
        organization_id: Uuid,
        template_name: &str,
        version_name: &str,
    ) -> Result<Option<TemplateVersionRecord>, StorageError> {
        let _ = (organization_id, template_name, version_name);
        Err(StorageError::unavailable(
            "template versions are not implemented",
        ))
    }

    /// Archives a template version.
    async fn archive_template_version(&self, version_id: Uuid) -> Result<bool, StorageError> {
        let _ = version_id;
        Err(StorageError::unavailable(
            "template versions are not implemented",
        ))
    }

    /// Unarchives a template version.
    async fn unarchive_template_version(&self, version_id: Uuid) -> Result<bool, StorageError> {
        let _ = version_id;
        Err(StorageError::unavailable(
            "template versions are not implemented",
        ))
    }

    /// Lists parameters for a template version.
    async fn list_template_version_parameters(
        &self,
        version_id: Uuid,
    ) -> Result<Vec<TemplateVersionParameterRecord>, StorageError> {
        let _ = version_id;
        Err(StorageError::unavailable(
            "template version parameters are not implemented",
        ))
    }

    /// Lists variables for a template version.
    async fn list_template_version_variables(
        &self,
        version_id: Uuid,
    ) -> Result<Vec<TemplateVersionVariableRecord>, StorageError> {
        let _ = version_id;
        Err(StorageError::unavailable(
            "template version variables are not implemented",
        ))
    }

    /// Lists presets for a template version.
    async fn list_template_version_presets(
        &self,
        version_id: Uuid,
    ) -> Result<Vec<TemplateVersionPresetRecord>, StorageError> {
        let _ = version_id;
        Err(StorageError::unavailable(
            "template version presets are not implemented",
        ))
    }

    /// Lists preset parameters for a specific preset.
    async fn list_template_version_preset_parameters(
        &self,
        preset_id: Uuid,
    ) -> Result<Vec<TemplateVersionPresetParameterRecord>, StorageError> {
        let _ = preset_id;
        Err(StorageError::unavailable(
            "template version preset parameters are not implemented",
        ))
    }

    /// Creates a provisioner job (template workflow).
    async fn create_provisioner_job(
        &self,
        input: CreateProvisionerJobInput,
    ) -> Result<TemplateProvisionerJobRecord, StorageError> {
        let _ = input;
        Err(StorageError::unavailable(
            "provisioner jobs are not implemented",
        ))
    }

    /// Finds a provisioner job by identifier (template workflow).
    async fn find_provisioner_job(
        &self,
        job_id: Uuid,
    ) -> Result<Option<TemplateProvisionerJobRecord>, StorageError> {
        let _ = job_id;
        Err(StorageError::unavailable(
            "provisioner jobs are not implemented",
        ))
    }

    /// Cancels a provisioner job (template workflow).
    async fn cancel_template_provisioner_job(&self, job_id: Uuid) -> Result<bool, StorageError> {
        let _ = job_id;
        Err(StorageError::unavailable(
            "provisioner jobs are not implemented",
        ))
    }

    /// Archives unused template versions for a template.
    async fn archive_unused_template_versions(
        &self,
        template_id: Uuid,
        all: bool,
    ) -> Result<Vec<Uuid>, StorageError> {
        let _ = (template_id, all);
        Err(StorageError::unavailable(
            "archive unused template versions is not implemented",
        ))
    }

    /// Returns the template version created immediately before the given one.
    async fn get_previous_template_version(
        &self,
        organization_id: Uuid,
        name: &str,
        template_id: Option<Uuid>,
    ) -> Result<Option<TemplateVersionRecord>, StorageError> {
        let _ = (organization_id, name, template_id);
        Err(StorageError::unavailable(
            "get previous template version is not implemented",
        ))
    }

    // -----------------------------------------------------------------------
    // Notifications domain
    // -----------------------------------------------------------------------

    /// Returns the current global notification settings JSON.
    async fn get_notifications_settings(&self) -> Result<NotificationsSettings, StorageError> {
        Err(StorageError::unavailable(
            "notifications settings are not implemented",
        ))
    }

    /// Replaces the global notification settings.
    async fn upsert_notifications_settings(
        &self,
        settings: &NotificationsSettings,
    ) -> Result<(), StorageError> {
        let _ = settings;
        Err(StorageError::unavailable(
            "notifications settings are not implemented",
        ))
    }

    /// Returns notification templates filtered by kind.
    async fn get_notification_templates_by_kind(
        &self,
        kind: &str,
    ) -> Result<Vec<NotificationTemplate>, StorageError> {
        let _ = kind;
        Err(StorageError::unavailable(
            "notification templates are not implemented",
        ))
    }

    /// Updates the delivery method for a notification template.
    async fn update_notification_template_method(
        &self,
        template_id: Uuid,
        method: Option<&str>,
    ) -> Result<Option<NotificationTemplate>, StorageError> {
        let _ = (template_id, method);
        Err(StorageError::unavailable(
            "notification templates are not implemented",
        ))
    }

    /// Returns notification preferences for a user.
    async fn get_user_notification_preferences(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<NotificationPreference>, StorageError> {
        let _ = user_id;
        Err(StorageError::unavailable(
            "notification preferences are not implemented",
        ))
    }

    /// Updates notification preferences for a user.
    async fn update_user_notification_preferences(
        &self,
        user_id: Uuid,
        template_ids: &[Uuid],
        disableds: &[bool],
    ) -> Result<(), StorageError> {
        let _ = (user_id, template_ids, disableds);
        Err(StorageError::unavailable(
            "notification preferences are not implemented",
        ))
    }

    /// Lists inbox notifications for a user with optional filtering.
    async fn get_filtered_inbox_notifications(
        &self,
        user_id: Uuid,
        templates: Option<&[Uuid]>,
        targets: Option<&[Uuid]>,
        read_status: &str,
        created_before: Option<OffsetDateTime>,
    ) -> Result<Vec<InboxNotification>, StorageError> {
        let _ = (user_id, templates, targets, read_status, created_before);
        Err(StorageError::unavailable(
            "inbox notifications are not implemented",
        ))
    }

    /// Counts unread inbox notifications for a user.
    async fn count_unread_inbox_notifications(&self, user_id: Uuid) -> Result<i64, StorageError> {
        let _ = user_id;
        Err(StorageError::unavailable(
            "inbox notifications are not implemented",
        ))
    }

    /// Finds an inbox notification by ID.
    async fn get_inbox_notification_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<InboxNotification>, StorageError> {
        let _ = id;
        Err(StorageError::unavailable(
            "inbox notifications are not implemented",
        ))
    }

    /// Updates the read status of an inbox notification.
    async fn update_inbox_notification_read_status(
        &self,
        id: Uuid,
        read_at: Option<OffsetDateTime>,
    ) -> Result<(), StorageError> {
        let _ = (id, read_at);
        Err(StorageError::unavailable(
            "inbox notifications are not implemented",
        ))
    }

    /// Marks all unread inbox notifications as read for a user.
    async fn mark_all_inbox_notifications_as_read(
        &self,
        user_id: Uuid,
        read_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        let _ = (user_id, read_at);
        Err(StorageError::unavailable(
            "inbox notifications are not implemented",
        ))
    }

    /// Lists webpush subscriptions for a user.
    async fn get_webpush_subscriptions_by_user_id(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<WebpushSubscriptionRecord>, StorageError> {
        let _ = user_id;
        Err(StorageError::unavailable(
            "webpush subscriptions are not implemented",
        ))
    }

    /// Inserts a webpush subscription.
    async fn insert_webpush_subscription(
        &self,
        user_id: Uuid,
        endpoint: &str,
        p256dh_key: &str,
        auth_key: &str,
    ) -> Result<(), StorageError> {
        let _ = (user_id, endpoint, p256dh_key, auth_key);
        Err(StorageError::unavailable(
            "webpush subscriptions are not implemented",
        ))
    }

    /// Deletes a webpush subscription by user ID and endpoint.
    async fn delete_webpush_subscription_by_user_and_endpoint(
        &self,
        user_id: Uuid,
        endpoint: &str,
    ) -> Result<bool, StorageError> {
        let _ = (user_id, endpoint);
        Err(StorageError::unavailable(
            "webpush subscriptions are not implemented",
        ))
    }

    // ----- Notification message dispatch -----

    /// Fetches pending notification messages for dispatch.
    ///
    /// Messages with `attempt_count >= max_attempt_count` are excluded so they
    /// can be purged separately rather than retried indefinitely.
    async fn fetch_pending_notification_messages(
        &self,
        limit: u32,
        max_attempt_count: u32,
    ) -> Result<Vec<NotificationMessageRecord>, StorageError> {
        let _ = (limit, max_attempt_count);
        Err(StorageError::unavailable(
            "notification messages are not implemented",
        ))
    }

    /// Updates the status of a notification message after dispatch.
    async fn update_notification_message_status(
        &self,
        message_id: Uuid,
        status: crate::identity::NotificationMessageStatus,
    ) -> Result<bool, StorageError> {
        let _ = (message_id, status);
        Err(StorageError::unavailable(
            "notification messages are not implemented",
        ))
    }

    /// Increments the attempt count for a notification message.
    async fn increment_notification_message_attempt_count(
        &self,
        message_id: Uuid,
    ) -> Result<bool, StorageError> {
        let _ = message_id;
        Err(StorageError::unavailable(
            "notification messages are not implemented",
        ))
    }

    // ----- Custom roles -----

    /// Lists custom roles, optionally filtered by organization.
    async fn list_custom_roles(
        &self,
        organization_id: Option<Uuid>,
    ) -> Result<Vec<CustomRoleRecord>, StorageError> {
        let _ = organization_id;
        Err(StorageError::unavailable(
            "custom roles are not implemented",
        ))
    }

    /// Upserts a custom role.
    async fn upsert_custom_role(
        &self,
        input: &UpsertCustomRoleInput,
    ) -> Result<CustomRoleRecord, StorageError> {
        let _ = input;
        Err(StorageError::unavailable(
            "custom roles are not implemented",
        ))
    }
}

/// Stored webpush subscription record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebpushSubscriptionRecord {
    pub id: Uuid,
    pub user_id: Uuid,
    pub created_at: OffsetDateTime,
    pub endpoint: String,
    pub endpoint_p256dh_key: String,
    pub endpoint_auth_key: String,
}

/// Stored workspace agent row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceAgentRow {
    /// Stable identifier.
    pub id: Uuid,
    /// Parent agent identifier for sub-agents.
    pub parent_id: Option<Uuid>,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Update time.
    pub updated_at: OffsetDateTime,
    /// Agent name.
    pub name: String,
    /// First connection time.
    pub first_connected_at: Option<OffsetDateTime>,
    /// Last connection time.
    pub last_connected_at: Option<OffsetDateTime>,
    /// Disconnection time.
    pub disconnected_at: Option<OffsetDateTime>,
    /// Owning resource identifier.
    pub resource_id: Uuid,
    /// Auth token.
    pub auth_token: Uuid,
    /// Instance identity string.
    pub auth_instance_id: Option<String>,
    /// Architecture.
    pub architecture: String,
    /// Environment variables as JSON.
    pub environment_variables: Option<String>,
    /// Operating system.
    pub operating_system: String,
    /// Working directory.
    pub directory: String,
    /// Expanded working directory.
    pub expanded_directory: String,
    /// Agent version.
    pub version: String,
    /// Agent API version.
    pub api_version: String,
    /// Connection timeout in seconds.
    pub connection_timeout_seconds: i32,
    /// Troubleshooting URL.
    pub troubleshooting_url: String,
    /// MOTD file path.
    pub motd_file: String,
    /// Lifecycle state.
    pub lifecycle_state: String,
    /// Total log length.
    pub logs_length: i32,
    /// Whether logs have overflowed.
    pub logs_overflowed: bool,
    /// Agent start time.
    pub started_at: Option<OffsetDateTime>,
    /// Agent ready time.
    pub ready_at: Option<OffsetDateTime>,
    /// Subsystems as string array.
    pub subsystems: Vec<String>,
    /// Display apps as string array.
    pub display_apps: Vec<String>,
    /// Display order.
    pub display_order: i32,
    /// API key scope.
    pub api_key_scope: String,
}

/// Stored workspace app row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceAppRow {
    /// Stable identifier.
    pub id: Uuid,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Owning agent identifier.
    pub agent_id: Uuid,
    /// Display name.
    pub display_name: String,
    /// Icon URL.
    pub icon: String,
    /// Command to execute.
    pub command: Option<String>,
    /// URL.
    pub url: Option<String>,
    /// Health check URL.
    pub healthcheck_url: String,
    /// Health check interval.
    pub healthcheck_interval: i32,
    /// Health check threshold.
    pub healthcheck_threshold: i32,
    /// Health status.
    pub health: String,
    /// Whether the app uses a subdomain.
    pub subdomain: bool,
    /// Sharing level.
    pub sharing_level: String,
    /// URL-safe slug.
    pub slug: String,
    /// Whether external.
    pub external: bool,
    /// Display order.
    pub display_order: i32,
    /// Whether hidden.
    pub hidden: bool,
    /// Where the app opens.
    pub open_in: String,
    /// Display group.
    pub display_group: Option<String>,
}

/// Stored workspace agent script row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceAgentScriptRow {
    /// Stable identifier.
    pub id: Uuid,
    /// Owning agent identifier.
    pub workspace_agent_id: Uuid,
    /// Log source identifier.
    pub log_source_id: Uuid,
    /// Log path.
    pub log_path: String,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Script content.
    pub script: String,
    /// Cron expression.
    pub cron: String,
    /// Whether start blocks login.
    pub start_blocks_login: bool,
    /// Whether runs on start.
    pub run_on_start: bool,
    /// Whether runs on stop.
    pub run_on_stop: bool,
    /// Timeout seconds.
    pub timeout_seconds: i32,
    /// Display name.
    pub display_name: String,
}

/// Stored workspace agent log source row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceAgentLogSourceRow {
    /// Stable identifier.
    pub id: Uuid,
    /// Owning agent identifier.
    pub workspace_agent_id: Uuid,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Display name.
    pub display_name: String,
    /// Icon.
    pub icon: String,
}

/// Stored workspace agent log row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceAgentLogRow {
    /// Stable identifier.
    pub id: i64,
    /// Agent identifier.
    pub agent_id: Uuid,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Log output.
    pub output: String,
    /// Log level.
    pub level: String,
    /// Source identifier.
    pub log_source_id: Uuid,
}

/// Stored workspace agent metadata row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceAgentMetadataRow {
    /// Agent identifier.
    pub workspace_agent_id: Uuid,
    /// Display name.
    pub display_name: String,
    /// Key.
    pub key: String,
    /// Script.
    pub script: String,
    /// Value.
    pub value: String,
    /// Error.
    pub error: String,
    /// Timeout.
    pub timeout: i64,
    /// Interval.
    pub interval: i64,
    /// Collected at.
    pub collected_at: OffsetDateTime,
    /// Display order.
    pub display_order: i32,
}

/// Stored workspace agent devcontainer row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceAgentDevcontainerRow {
    /// Stable identifier.
    pub id: Uuid,
    /// Owning agent identifier.
    pub workspace_agent_id: Uuid,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Workspace folder path.
    pub workspace_folder: String,
    /// Config path.
    pub config_path: String,
    /// Name.
    pub name: String,
    /// Sub-agent identifier.
    pub subagent_id: Option<Uuid>,
}

/// Stored workspace app status row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceAppStatusRow {
    /// Stable identifier.
    pub id: Uuid,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Agent identifier.
    pub agent_id: Uuid,
    /// App identifier.
    pub app_id: Uuid,
    /// Workspace identifier.
    pub workspace_id: Uuid,
    /// State.
    pub state: String,
    /// Message.
    pub message: String,
    /// URI.
    pub uri: Option<String>,
}

/// Input for inserting agent logs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InsertAgentLogInput {
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Log output.
    pub output: String,
    /// Log level.
    pub level: String,
}

/// Input for inserting a workspace app status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InsertWorkspaceAppStatusInput {
    /// Agent identifier.
    pub agent_id: Uuid,
    /// App identifier.
    pub app_id: Uuid,
    /// Workspace identifier.
    pub workspace_id: Uuid,
    /// State.
    pub state: String,
    /// Message.
    pub message: String,
    /// URI.
    pub uri: Option<String>,
}

/// Workspace-domain storage contract.
#[async_trait]
pub trait WorkspaceStore: Send + Sync {
    /// Lists workspaces matching the supplied filter.
    async fn list_workspaces(
        &self,
        filter: WorkspaceListFilter,
    ) -> Result<(Vec<WorkspaceRecord>, i64), StorageError>;

    /// Looks up a workspace by stable identifier.
    async fn find_workspace_by_id(
        &self,
        workspace_id: Uuid,
        viewer_id: Option<Uuid>,
    ) -> Result<Option<WorkspaceRecord>, StorageError>;

    /// Looks up a workspace by owner and name.
    async fn find_workspace_by_owner_and_name(
        &self,
        owner_id: Uuid,
        name: &str,
        viewer_id: Option<Uuid>,
    ) -> Result<Option<WorkspaceRecord>, StorageError>;

    /// Creates a new workspace.
    async fn insert_workspace(
        &self,
        input: CreateWorkspaceInput,
    ) -> Result<WorkspaceRecord, StorageError>;

    /// Updates a workspace name.
    async fn update_workspace_name(
        &self,
        workspace_id: Uuid,
        name: &str,
        viewer_id: Option<Uuid>,
    ) -> Result<Option<WorkspaceRecord>, StorageError>;

    /// Updates a workspace autostart schedule.
    async fn update_workspace_autostart(
        &self,
        workspace_id: Uuid,
        schedule: Option<&str>,
    ) -> Result<bool, StorageError>;

    /// Updates a workspace TTL.
    async fn update_workspace_ttl(
        &self,
        workspace_id: Uuid,
        ttl_ns: Option<i64>,
    ) -> Result<bool, StorageError>;

    /// Updates workspace dormancy.
    async fn update_workspace_dormant_at(
        &self,
        workspace_id: Uuid,
        dormant_at: Option<OffsetDateTime>,
        viewer_id: Option<Uuid>,
    ) -> Result<Option<WorkspaceRecord>, StorageError>;

    /// Updates workspace automatic updates.
    async fn update_workspace_automatic_updates(
        &self,
        workspace_id: Uuid,
        automatic_updates: &str,
    ) -> Result<bool, StorageError>;

    /// Updates workspace last used time.
    async fn update_workspace_last_used_at(
        &self,
        workspace_id: Uuid,
        last_used_at: OffsetDateTime,
    ) -> Result<bool, StorageError>;

    /// Sets workspace favorite status.
    async fn favorite_workspace(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
        favorite: bool,
    ) -> Result<bool, StorageError>;

    /// Soft-deletes a workspace.
    async fn soft_delete_workspace(&self, workspace_id: Uuid) -> Result<bool, StorageError>;

    /// Creates a new group.
    async fn create_group(&self, input: &CreateGroupInput) -> Result<GroupRecord, StorageError>;

    /// Deletes a group.
    async fn delete_group(&self, group_id: Uuid) -> Result<bool, StorageError>;

    /// Lists groups for an organization.
    async fn list_groups(&self, organization_id: Uuid) -> Result<Vec<GroupRecord>, StorageError>;

    /// Adds a user to a group.
    async fn insert_group_member(&self, group_id: Uuid, user_id: Uuid) -> Result<(), StorageError>;

    /// Lists members of a group.
    async fn list_group_members(
        &self,
        group_id: Uuid,
    ) -> Result<Vec<GroupMemberRecord>, StorageError>;

    /// Removes a user from a group.
    async fn delete_group_member(
        &self,
        group_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, StorageError>;

    /// Looks up a group by identifier.
    async fn find_group_by_id(&self, group_id: Uuid) -> Result<Option<GroupRecord>, StorageError>;

    /// Returns the ACL for a workspace.
    async fn get_workspace_acl(
        &self,
        workspace_id: Uuid,
    ) -> Result<WorkspaceACLRecord, StorageError>;

    /// Updates workspace ACL entries.
    async fn update_workspace_acl(
        &self,
        workspace_id: Uuid,
        input: &UpdateWorkspaceACLInput,
    ) -> Result<(), StorageError>;

    /// Clears all workspace ACL entries.
    async fn delete_workspace_acl(&self, workspace_id: Uuid) -> Result<(), StorageError>;

    /// Looks up a template by stable identifier.
    async fn find_template_by_id(
        &self,
        template_id: Uuid,
    ) -> Result<Option<TemplateRecord>, StorageError>;

    /// Looks up a template version by stable identifier.
    async fn find_template_version_by_id(
        &self,
        template_version_id: Uuid,
    ) -> Result<Option<TemplateVersionRecord>, StorageError>;

    /// Lists workspace builds for a workspace.
    async fn list_workspace_builds(
        &self,
        workspace_id: Uuid,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<WorkspaceBuildRecord>, StorageError>;

    /// Returns the latest build for a workspace.
    async fn find_latest_workspace_build(
        &self,
        workspace_id: Uuid,
    ) -> Result<Option<WorkspaceBuildRecord>, StorageError>;

    /// Looks up a workspace build by stable identifier.
    async fn find_workspace_build_by_id(
        &self,
        build_id: Uuid,
    ) -> Result<Option<WorkspaceBuildRecord>, StorageError>;

    /// Looks up a workspace build by workspace and build number.
    async fn find_workspace_build_by_number(
        &self,
        workspace_id: Uuid,
        build_number: i64,
    ) -> Result<Option<WorkspaceBuildRecord>, StorageError>;

    /// Creates a new workspace build.
    async fn insert_workspace_build(
        &self,
        input: CreateWorkspaceBuildInput,
    ) -> Result<WorkspaceBuildRecord, StorageError>;

    /// Updates the build deadline.
    async fn update_workspace_build_deadline(
        &self,
        build_id: Uuid,
        deadline: Option<OffsetDateTime>,
        max_deadline: Option<OffsetDateTime>,
    ) -> Result<bool, StorageError>;

    /// Updates the provisioner state blob for a build.
    async fn update_workspace_build_provisioner_state(
        &self,
        build_id: Uuid,
        state: &[u8],
    ) -> Result<bool, StorageError>;

    /// Returns the next build number for a workspace.
    async fn next_workspace_build_number(&self, workspace_id: Uuid) -> Result<i64, StorageError>;

    /// Lists build parameters for a workspace build.
    async fn list_workspace_build_parameters(
        &self,
        build_id: Uuid,
    ) -> Result<Vec<WorkspaceBuildParameterRecord>, StorageError>;

    /// Inserts build parameters.
    async fn insert_workspace_build_parameters(
        &self,
        build_id: Uuid,
        params: &[(String, String)],
    ) -> Result<(), StorageError>;

    /// Looks up a provisioner job by stable identifier.
    async fn find_provisioner_job_by_id(
        &self,
        job_id: Uuid,
    ) -> Result<Option<TemplateProvisionerJobRecord>, StorageError>;

    /// Creates a new provisioner job.
    async fn insert_provisioner_job(
        &self,
        input: CreateProvisionerJobInput,
    ) -> Result<TemplateProvisionerJobRecord, StorageError>;

    /// Cancels a provisioner job.
    async fn cancel_provisioner_job(&self, job_id: Uuid) -> Result<bool, StorageError>;

    /// Lists provisioner job logs.
    async fn list_provisioner_job_logs(
        &self,
        job_id: Uuid,
        after: Option<i64>,
    ) -> Result<Vec<ProvisionerJobLogRecord>, StorageError>;

    /// Lists provisioner job timings.
    async fn list_provisioner_job_timings(
        &self,
        job_id: Uuid,
    ) -> Result<Vec<ProvisionerJobTimingRecord>, StorageError>;

    /// Looks up a workspace resource by stable identifier.
    async fn find_workspace_resource_by_id(
        &self,
        resource_id: Uuid,
    ) -> Result<Option<WorkspaceResourceRecord>, StorageError>;

    /// Lists workspace agent script timings for a build.
    async fn list_workspace_agent_script_timings_by_build_id(
        &self,
        build_id: Uuid,
    ) -> Result<Vec<WorkspaceAgentScriptTimingRow>, StorageError>;

    /// Lists workspace resources for a job.
    async fn list_workspace_resources_by_job(
        &self,
        job_id: Uuid,
    ) -> Result<Vec<WorkspaceResourceRecord>, StorageError>;

    /// Lists metadata for a set of workspace resources.
    async fn list_workspace_resource_metadata(
        &self,
        resource_ids: &[Uuid],
    ) -> Result<Vec<WorkspaceResourceMetadataRecord>, StorageError>;

    /// Lists port shares for a workspace.
    async fn list_workspace_port_shares(
        &self,
        workspace_id: Uuid,
    ) -> Result<Vec<WorkspaceAgentPortShareRecord>, StorageError>;

    /// Upserts a port share.
    async fn upsert_workspace_port_share(
        &self,
        input: UpsertPortShareInput,
    ) -> Result<WorkspaceAgentPortShareRecord, StorageError>;

    /// Finds a port share.
    async fn find_workspace_port_share(
        &self,
        workspace_id: Uuid,
        agent_name: &str,
        port: i32,
    ) -> Result<Option<WorkspaceAgentPortShareRecord>, StorageError>;

    /// Deletes a port share.
    async fn delete_workspace_port_share(
        &self,
        workspace_id: Uuid,
        agent_name: &str,
        port: i32,
    ) -> Result<bool, StorageError>;
}

#[async_trait]
impl<T> AuthStore for T
where
    T: AppStore + ?Sized,
{
    async fn first_user_exists(&self) -> Result<bool, StorageError> {
        AppStore::first_user_exists(self).await
    }

    async fn create_first_user(
        &self,
        user: CreateFirstUserInput,
    ) -> Result<FirstUserRecord, CreateFirstUserStoreError> {
        AppStore::create_first_user(self, user).await
    }

    async fn find_password_user_by_email(
        &self,
        email: &str,
    ) -> Result<Option<PasswordUserRecord>, StorageError> {
        AppStore::find_password_user_by_email(self, email).await
    }

    async fn find_password_user_by_id(
        &self,
        user_id: Uuid,
    ) -> Result<Option<PasswordUserRecord>, StorageError> {
        AppStore::find_password_user_by_id(self, user_id).await
    }

    async fn insert_auth_session(
        &self,
        token_hash: &[u8],
        user_id: Uuid,
    ) -> Result<(), StorageError> {
        AppStore::insert_auth_session(self, token_hash, user_id).await
    }

    async fn find_user_by_session_token_hash(
        &self,
        token_hash: &[u8],
    ) -> Result<Option<AuthenticatedUser>, StorageError> {
        AppStore::find_user_by_session_token_hash(self, token_hash).await
    }

    async fn delete_auth_session(&self, token_hash: &[u8]) -> Result<bool, StorageError> {
        AppStore::delete_auth_session(self, token_hash).await
    }

    async fn find_user_by_id(&self, user_id: Uuid) -> Result<Option<UserRecord>, StorageError> {
        AppStore::find_user_by_id(self, user_id).await
    }

    async fn find_user_by_username(
        &self,
        username: &str,
    ) -> Result<Option<UserRecord>, StorageError> {
        AppStore::find_user_by_username(self, username).await
    }

    async fn store_one_time_passcode_by_email(
        &self,
        email: &str,
        passcode_hash: &str,
        expires_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        AppStore::store_one_time_passcode_by_email(self, email, passcode_hash, expires_at).await
    }

    async fn replace_user_password(
        &self,
        user_id: Uuid,
        password_hash: &str,
        clear_one_time_passcode: bool,
    ) -> Result<bool, StorageError> {
        AppStore::replace_user_password(self, user_id, password_hash, clear_one_time_passcode).await
    }

    async fn create_api_key(
        &self,
        input: CreateApiKeyInput,
    ) -> Result<ApiKeyRecord, CreateApiKeyStoreError> {
        AppStore::create_api_key(self, input).await
    }

    async fn find_api_key_by_id(&self, id: &str) -> Result<Option<ApiKeyRecord>, StorageError> {
        AppStore::find_api_key_by_id(self, id).await
    }

    async fn find_api_key_by_name(
        &self,
        user_id: Uuid,
        token_name: &str,
    ) -> Result<Option<ApiKeyRecord>, StorageError> {
        AppStore::find_api_key_by_name(self, user_id, token_name).await
    }

    async fn list_api_keys(
        &self,
        filter: ApiKeyListFilter,
    ) -> Result<Vec<ApiKeyWithOwnerRecord>, StorageError> {
        AppStore::list_api_keys(self, filter).await
    }

    async fn delete_api_key(&self, id: &str) -> Result<bool, StorageError> {
        AppStore::delete_api_key(self, id).await
    }

    async fn expire_api_key(&self, id: &str, now: OffsetDateTime) -> Result<bool, StorageError> {
        AppStore::expire_api_key(self, id, now).await
    }

    async fn token_config(&self, user_id: Uuid) -> Result<TokenConfigRecord, StorageError> {
        AppStore::token_config(self, user_id).await
    }

    async fn list_external_auth_links(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<ExternalAuthLinkRecord>, StorageError> {
        AppStore::list_external_auth_links(self, user_id).await
    }

    async fn find_external_auth_link(
        &self,
        user_id: Uuid,
        provider_id: &str,
    ) -> Result<Option<ExternalAuthLinkRecord>, StorageError> {
        AppStore::find_external_auth_link(self, user_id, provider_id).await
    }

    async fn delete_external_auth_link(
        &self,
        user_id: Uuid,
        provider_id: &str,
    ) -> Result<bool, StorageError> {
        AppStore::delete_external_auth_link(self, user_id, provider_id).await
    }

    async fn upsert_external_auth_link(
        &self,
        user_id: Uuid,
        link: &UpsertExternalAuthLinkInput,
    ) -> Result<ExternalAuthLinkRecord, StorageError> {
        AppStore::upsert_external_auth_link(self, user_id, link).await
    }
}

#[async_trait]
impl<T> AuthStore for Arc<T>
where
    T: AuthStore + ?Sized,
{
    async fn first_user_exists(&self) -> Result<bool, StorageError> {
        (**self).first_user_exists().await
    }

    async fn create_first_user(
        &self,
        user: CreateFirstUserInput,
    ) -> Result<FirstUserRecord, CreateFirstUserStoreError> {
        (**self).create_first_user(user).await
    }

    async fn find_password_user_by_email(
        &self,
        email: &str,
    ) -> Result<Option<PasswordUserRecord>, StorageError> {
        (**self).find_password_user_by_email(email).await
    }

    async fn find_password_user_by_id(
        &self,
        user_id: Uuid,
    ) -> Result<Option<PasswordUserRecord>, StorageError> {
        (**self).find_password_user_by_id(user_id).await
    }

    async fn insert_auth_session(
        &self,
        token_hash: &[u8],
        user_id: Uuid,
    ) -> Result<(), StorageError> {
        (**self).insert_auth_session(token_hash, user_id).await
    }

    async fn find_user_by_session_token_hash(
        &self,
        token_hash: &[u8],
    ) -> Result<Option<AuthenticatedUser>, StorageError> {
        (**self).find_user_by_session_token_hash(token_hash).await
    }

    async fn delete_auth_session(&self, token_hash: &[u8]) -> Result<bool, StorageError> {
        (**self).delete_auth_session(token_hash).await
    }

    async fn find_user_by_id(&self, user_id: Uuid) -> Result<Option<UserRecord>, StorageError> {
        (**self).find_user_by_id(user_id).await
    }

    async fn find_user_by_username(
        &self,
        username: &str,
    ) -> Result<Option<UserRecord>, StorageError> {
        (**self).find_user_by_username(username).await
    }

    async fn store_one_time_passcode_by_email(
        &self,
        email: &str,
        passcode_hash: &str,
        expires_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        (**self)
            .store_one_time_passcode_by_email(email, passcode_hash, expires_at)
            .await
    }

    async fn replace_user_password(
        &self,
        user_id: Uuid,
        password_hash: &str,
        clear_one_time_passcode: bool,
    ) -> Result<bool, StorageError> {
        (**self)
            .replace_user_password(user_id, password_hash, clear_one_time_passcode)
            .await
    }

    async fn create_api_key(
        &self,
        input: CreateApiKeyInput,
    ) -> Result<ApiKeyRecord, CreateApiKeyStoreError> {
        (**self).create_api_key(input).await
    }

    async fn find_api_key_by_id(&self, id: &str) -> Result<Option<ApiKeyRecord>, StorageError> {
        (**self).find_api_key_by_id(id).await
    }

    async fn find_api_key_by_name(
        &self,
        user_id: Uuid,
        token_name: &str,
    ) -> Result<Option<ApiKeyRecord>, StorageError> {
        (**self).find_api_key_by_name(user_id, token_name).await
    }

    async fn list_api_keys(
        &self,
        filter: ApiKeyListFilter,
    ) -> Result<Vec<ApiKeyWithOwnerRecord>, StorageError> {
        (**self).list_api_keys(filter).await
    }

    async fn delete_api_key(&self, id: &str) -> Result<bool, StorageError> {
        (**self).delete_api_key(id).await
    }

    async fn expire_api_key(&self, id: &str, now: OffsetDateTime) -> Result<bool, StorageError> {
        (**self).expire_api_key(id, now).await
    }

    async fn token_config(&self, user_id: Uuid) -> Result<TokenConfigRecord, StorageError> {
        (**self).token_config(user_id).await
    }

    async fn list_external_auth_links(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<ExternalAuthLinkRecord>, StorageError> {
        (**self).list_external_auth_links(user_id).await
    }

    async fn find_external_auth_link(
        &self,
        user_id: Uuid,
        provider_id: &str,
    ) -> Result<Option<ExternalAuthLinkRecord>, StorageError> {
        (**self).find_external_auth_link(user_id, provider_id).await
    }

    async fn delete_external_auth_link(
        &self,
        user_id: Uuid,
        provider_id: &str,
    ) -> Result<bool, StorageError> {
        (**self)
            .delete_external_auth_link(user_id, provider_id)
            .await
    }

    async fn upsert_external_auth_link(
        &self,
        user_id: Uuid,
        link: &UpsertExternalAuthLinkInput,
    ) -> Result<ExternalAuthLinkRecord, StorageError> {
        (**self).upsert_external_auth_link(user_id, link).await
    }
}

#[async_trait]
impl<T> DeploymentStore for Arc<T>
where
    T: DeploymentStore + ?Sized,
{
    async fn ping(&self) -> Result<(), StorageError> {
        (**self).ping().await
    }

    async fn ensure_deployment_metadata(&self) -> Result<DeploymentMetadata, StorageError> {
        (**self).ensure_deployment_metadata().await
    }
}

#[async_trait]
impl<T> IdentityStore for T
where
    T: AppStore + ?Sized,
{
    async fn list_users(
        &self,
        filter: UserListFilter,
    ) -> Result<(Vec<UserRecord>, usize), StorageError> {
        AppStore::list_users(self, filter).await
    }

    async fn create_user(
        &self,
        input: CreateUserInput,
    ) -> Result<UserRecord, CreateUserStoreError> {
        AppStore::create_user(self, input).await
    }

    async fn find_user_by_id(&self, user_id: Uuid) -> Result<Option<UserRecord>, StorageError> {
        AppStore::find_user_by_id(self, user_id).await
    }

    async fn find_user_by_username(
        &self,
        username: &str,
    ) -> Result<Option<UserRecord>, StorageError> {
        AppStore::find_user_by_username(self, username).await
    }

    async fn soft_delete_user(&self, user_id: Uuid) -> Result<bool, StorageError> {
        AppStore::soft_delete_user(self, user_id).await
    }

    async fn list_user_memberships(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<OrganizationMemberRecord>, StorageError> {
        AppStore::list_user_memberships(self, user_id).await
    }

    async fn update_user_roles(
        &self,
        user_id: Uuid,
        roles: Vec<String>,
    ) -> Result<Option<UserRecord>, StorageError> {
        AppStore::update_user_roles(self, user_id, roles).await
    }

    async fn update_user_profile(
        &self,
        user_id: Uuid,
        username: &str,
        name: &str,
    ) -> Result<Option<UserRecord>, StorageError> {
        AppStore::update_user_profile(self, user_id, username, name).await
    }

    async fn update_user_status(
        &self,
        user_id: Uuid,
        status: UserStatus,
    ) -> Result<Option<UserRecord>, StorageError> {
        AppStore::update_user_status(self, user_id, status).await
    }

    async fn user_appearance(&self, user_id: Uuid) -> Result<UserAppearanceRecord, StorageError> {
        AppStore::user_appearance(self, user_id).await
    }

    async fn update_user_appearance(
        &self,
        user_id: Uuid,
        theme_preference: &str,
        terminal_font: &str,
    ) -> Result<Option<UserAppearanceRecord>, StorageError> {
        AppStore::update_user_appearance(self, user_id, theme_preference, terminal_font).await
    }

    async fn user_preferences(&self, user_id: Uuid) -> Result<UserPreferenceRecord, StorageError> {
        AppStore::user_preferences(self, user_id).await
    }

    async fn update_user_preferences(
        &self,
        user_id: Uuid,
        task_notification_alert_dismissed: bool,
    ) -> Result<Option<UserPreferenceRecord>, StorageError> {
        AppStore::update_user_preferences(self, user_id, task_notification_alert_dismissed).await
    }

    async fn list_organizations(
        &self,
        organization_ids: Vec<Uuid>,
    ) -> Result<Vec<OrganizationRecord>, StorageError> {
        AppStore::list_organizations(self, organization_ids).await
    }

    async fn find_organization_by_id(
        &self,
        organization_id: Uuid,
    ) -> Result<Option<OrganizationRecord>, StorageError> {
        AppStore::find_organization_by_id(self, organization_id).await
    }

    async fn find_organization_by_name(
        &self,
        name: &str,
    ) -> Result<Option<OrganizationRecord>, StorageError> {
        AppStore::find_organization_by_name(self, name).await
    }

    async fn list_organization_members(
        &self,
        filter: OrganizationMemberListFilter,
    ) -> Result<Vec<OrganizationMemberRecord>, StorageError> {
        AppStore::list_organization_members(self, filter).await
    }

    async fn list_organization_members_page(
        &self,
        filter: OrganizationMemberListFilter,
    ) -> Result<(Vec<OrganizationMemberRecord>, usize), StorageError> {
        AppStore::list_organization_members_page(self, filter).await
    }

    async fn find_organization_member(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<OrganizationMemberRecord>, StorageError> {
        AppStore::find_organization_member(self, organization_id, user_id).await
    }

    async fn insert_organization_member(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> Result<OrganizationMemberRecord, InsertOrganizationMemberError> {
        AppStore::insert_organization_member(self, organization_id, user_id).await
    }

    async fn delete_organization_member(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, StorageError> {
        AppStore::delete_organization_member(self, organization_id, user_id).await
    }

    async fn update_organization_member_roles(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
        roles: Vec<String>,
    ) -> Result<Option<OrganizationMemberRecord>, StorageError> {
        AppStore::update_organization_member_roles(self, organization_id, user_id, roles).await
    }

    async fn list_groups(&self, organization_id: Uuid) -> Result<Vec<GroupRecord>, StorageError> {
        AppStore::list_groups(self, organization_id).await
    }

    async fn create_group(&self, input: &CreateGroupInput) -> Result<GroupRecord, StorageError> {
        AppStore::create_group(self, input).await
    }

    async fn find_group_by_id(&self, group_id: Uuid) -> Result<Option<GroupRecord>, StorageError> {
        AppStore::find_group_by_id(self, group_id).await
    }

    async fn delete_group(&self, group_id: Uuid) -> Result<bool, StorageError> {
        AppStore::delete_group(self, group_id).await
    }

    async fn list_group_members(
        &self,
        group_id: Uuid,
    ) -> Result<Vec<GroupMemberRecord>, StorageError> {
        AppStore::list_group_members(self, group_id).await
    }

    async fn insert_group_member(&self, group_id: Uuid, user_id: Uuid) -> Result<(), StorageError> {
        AppStore::insert_group_member(self, group_id, user_id).await
    }

    async fn delete_group_member(
        &self,
        group_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, StorageError> {
        AppStore::delete_group_member(self, group_id, user_id).await
    }
}

#[async_trait]
impl<T> IdentityStore for Arc<T>
where
    T: IdentityStore + ?Sized,
{
    async fn list_users(
        &self,
        filter: UserListFilter,
    ) -> Result<(Vec<UserRecord>, usize), StorageError> {
        (**self).list_users(filter).await
    }

    async fn create_user(
        &self,
        input: CreateUserInput,
    ) -> Result<UserRecord, CreateUserStoreError> {
        (**self).create_user(input).await
    }

    async fn find_user_by_id(&self, user_id: Uuid) -> Result<Option<UserRecord>, StorageError> {
        (**self).find_user_by_id(user_id).await
    }

    async fn find_user_by_username(
        &self,
        username: &str,
    ) -> Result<Option<UserRecord>, StorageError> {
        (**self).find_user_by_username(username).await
    }

    async fn soft_delete_user(&self, user_id: Uuid) -> Result<bool, StorageError> {
        (**self).soft_delete_user(user_id).await
    }

    async fn list_user_memberships(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<OrganizationMemberRecord>, StorageError> {
        (**self).list_user_memberships(user_id).await
    }

    async fn update_user_roles(
        &self,
        user_id: Uuid,
        roles: Vec<String>,
    ) -> Result<Option<UserRecord>, StorageError> {
        (**self).update_user_roles(user_id, roles).await
    }

    async fn update_user_profile(
        &self,
        user_id: Uuid,
        username: &str,
        name: &str,
    ) -> Result<Option<UserRecord>, StorageError> {
        (**self).update_user_profile(user_id, username, name).await
    }

    async fn update_user_status(
        &self,
        user_id: Uuid,
        status: UserStatus,
    ) -> Result<Option<UserRecord>, StorageError> {
        (**self).update_user_status(user_id, status).await
    }

    async fn user_appearance(&self, user_id: Uuid) -> Result<UserAppearanceRecord, StorageError> {
        (**self).user_appearance(user_id).await
    }

    async fn update_user_appearance(
        &self,
        user_id: Uuid,
        theme_preference: &str,
        terminal_font: &str,
    ) -> Result<Option<UserAppearanceRecord>, StorageError> {
        (**self)
            .update_user_appearance(user_id, theme_preference, terminal_font)
            .await
    }

    async fn user_preferences(&self, user_id: Uuid) -> Result<UserPreferenceRecord, StorageError> {
        (**self).user_preferences(user_id).await
    }

    async fn update_user_preferences(
        &self,
        user_id: Uuid,
        task_notification_alert_dismissed: bool,
    ) -> Result<Option<UserPreferenceRecord>, StorageError> {
        (**self)
            .update_user_preferences(user_id, task_notification_alert_dismissed)
            .await
    }

    async fn list_organizations(
        &self,
        organization_ids: Vec<Uuid>,
    ) -> Result<Vec<OrganizationRecord>, StorageError> {
        (**self).list_organizations(organization_ids).await
    }

    async fn find_organization_by_id(
        &self,
        organization_id: Uuid,
    ) -> Result<Option<OrganizationRecord>, StorageError> {
        (**self).find_organization_by_id(organization_id).await
    }

    async fn find_organization_by_name(
        &self,
        name: &str,
    ) -> Result<Option<OrganizationRecord>, StorageError> {
        (**self).find_organization_by_name(name).await
    }

    async fn list_organization_members(
        &self,
        filter: OrganizationMemberListFilter,
    ) -> Result<Vec<OrganizationMemberRecord>, StorageError> {
        (**self).list_organization_members(filter).await
    }

    async fn list_organization_members_page(
        &self,
        filter: OrganizationMemberListFilter,
    ) -> Result<(Vec<OrganizationMemberRecord>, usize), StorageError> {
        (**self).list_organization_members_page(filter).await
    }

    async fn find_organization_member(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<OrganizationMemberRecord>, StorageError> {
        (**self)
            .find_organization_member(organization_id, user_id)
            .await
    }

    async fn insert_organization_member(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> Result<OrganizationMemberRecord, InsertOrganizationMemberError> {
        (**self)
            .insert_organization_member(organization_id, user_id)
            .await
    }

    async fn delete_organization_member(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, StorageError> {
        (**self)
            .delete_organization_member(organization_id, user_id)
            .await
    }

    async fn update_organization_member_roles(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
        roles: Vec<String>,
    ) -> Result<Option<OrganizationMemberRecord>, StorageError> {
        (**self)
            .update_organization_member_roles(organization_id, user_id, roles)
            .await
    }

    async fn list_groups(&self, organization_id: Uuid) -> Result<Vec<GroupRecord>, StorageError> {
        (**self).list_groups(organization_id).await
    }

    async fn create_group(&self, input: &CreateGroupInput) -> Result<GroupRecord, StorageError> {
        (**self).create_group(input).await
    }

    async fn find_group_by_id(&self, group_id: Uuid) -> Result<Option<GroupRecord>, StorageError> {
        (**self).find_group_by_id(group_id).await
    }

    async fn delete_group(&self, group_id: Uuid) -> Result<bool, StorageError> {
        (**self).delete_group(group_id).await
    }

    async fn list_group_members(
        &self,
        group_id: Uuid,
    ) -> Result<Vec<GroupMemberRecord>, StorageError> {
        (**self).list_group_members(group_id).await
    }

    async fn insert_group_member(&self, group_id: Uuid, user_id: Uuid) -> Result<(), StorageError> {
        (**self).insert_group_member(group_id, user_id).await
    }

    async fn delete_group_member(
        &self,
        group_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, StorageError> {
        (**self).delete_group_member(group_id, user_id).await
    }
}

#[async_trait]
impl<T> OperationalStore for T
where
    T: AppStore + ?Sized,
{
    async fn list_audit_logs(
        &self,
        filter: AuditLogListFilter,
    ) -> Result<AuditLogResponse, StorageError> {
        AppStore::list_audit_logs(self, filter).await
    }

    async fn insert_audit_log(&self, input: PersistAuditLogInput) -> Result<(), StorageError> {
        AppStore::insert_audit_log(self, input).await
    }

    async fn health_settings(&self) -> Result<HealthSettings, StorageError> {
        AppStore::health_settings(self).await
    }

    async fn upsert_health_settings(
        &self,
        settings: &HealthSettings,
    ) -> Result<bool, StorageError> {
        AppStore::upsert_health_settings(self, settings).await
    }

    async fn deployment_stats(&self) -> Result<crate::api::DeploymentStatsResponse, StorageError> {
        AppStore::deployment_stats(self).await
    }

    async fn upsert_workspace_stats_workspace(
        &self,
        input: &WorkspaceStatsWorkspaceInput,
    ) -> Result<(), StorageError> {
        AppStore::upsert_workspace_stats_workspace(self, input).await
    }

    async fn upsert_provisioner_job_stats(
        &self,
        input: &ProvisionerJobStatsInput,
    ) -> Result<(), StorageError> {
        AppStore::upsert_provisioner_job_stats(self, input).await
    }

    async fn upsert_workspace_build_stats(
        &self,
        input: &WorkspaceBuildStatsInput,
    ) -> Result<(), StorageError> {
        AppStore::upsert_workspace_build_stats(self, input).await
    }

    async fn insert_workspace_agent_stat(
        &self,
        input: &WorkspaceAgentStatInput,
    ) -> Result<(), StorageError> {
        AppStore::insert_workspace_agent_stat(self, input).await
    }

    async fn list_workspace_proxies_for_health(
        &self,
    ) -> Result<Vec<WorkspaceProxyHealthRecord>, StorageError> {
        AppStore::list_workspace_proxies_for_health(self).await
    }

    async fn upsert_workspace_proxy_for_health(
        &self,
        input: &WorkspaceProxyHealthInput,
    ) -> Result<(), StorageError> {
        AppStore::upsert_workspace_proxy_for_health(self, input).await
    }

    async fn list_provisioner_daemons_for_health(
        &self,
    ) -> Result<Vec<ProvisionerDaemonHealthRecord>, StorageError> {
        AppStore::list_provisioner_daemons_for_health(self).await
    }

    async fn upsert_provisioner_daemon_for_health(
        &self,
        input: &ProvisionerDaemonHealthInput,
    ) -> Result<(), StorageError> {
        AppStore::upsert_provisioner_daemon_for_health(self, input).await
    }

    async fn find_git_ssh_key(
        &self,
        user_id: Uuid,
    ) -> Result<Option<GitSshKeyRecord>, StorageError> {
        AppStore::find_git_ssh_key(self, user_id).await
    }

    async fn upsert_git_ssh_key(
        &self,
        user_id: Uuid,
        public_key: &str,
        private_key: &str,
    ) -> Result<GitSshKeyRecord, StorageError> {
        AppStore::upsert_git_ssh_key(self, user_id, public_key, private_key).await
    }

    async fn insert_file(&self, input: InsertFileInput) -> Result<InsertFileResult, StorageError> {
        AppStore::insert_file(self, input).await
    }

    async fn get_file_by_id(&self, file_id: Uuid) -> Result<Option<FileRecord>, StorageError> {
        AppStore::get_file_by_id(self, file_id).await
    }

    async fn get_file_by_hash_and_creator(
        &self,
        hash: &str,
        creator_id: Uuid,
    ) -> Result<Option<FileRecord>, StorageError> {
        AppStore::get_file_by_hash_and_creator(self, hash, creator_id).await
    }
}

#[async_trait]
impl<T> OperationalStore for Arc<T>
where
    T: OperationalStore + ?Sized,
{
    async fn list_audit_logs(
        &self,
        filter: AuditLogListFilter,
    ) -> Result<AuditLogResponse, StorageError> {
        (**self).list_audit_logs(filter).await
    }

    async fn insert_audit_log(&self, input: PersistAuditLogInput) -> Result<(), StorageError> {
        (**self).insert_audit_log(input).await
    }

    async fn health_settings(&self) -> Result<HealthSettings, StorageError> {
        (**self).health_settings().await
    }

    async fn upsert_health_settings(
        &self,
        settings: &HealthSettings,
    ) -> Result<bool, StorageError> {
        (**self).upsert_health_settings(settings).await
    }

    async fn deployment_stats(&self) -> Result<crate::api::DeploymentStatsResponse, StorageError> {
        (**self).deployment_stats().await
    }

    async fn upsert_workspace_stats_workspace(
        &self,
        input: &WorkspaceStatsWorkspaceInput,
    ) -> Result<(), StorageError> {
        (**self).upsert_workspace_stats_workspace(input).await
    }

    async fn upsert_provisioner_job_stats(
        &self,
        input: &ProvisionerJobStatsInput,
    ) -> Result<(), StorageError> {
        (**self).upsert_provisioner_job_stats(input).await
    }

    async fn upsert_workspace_build_stats(
        &self,
        input: &WorkspaceBuildStatsInput,
    ) -> Result<(), StorageError> {
        (**self).upsert_workspace_build_stats(input).await
    }

    async fn insert_workspace_agent_stat(
        &self,
        input: &WorkspaceAgentStatInput,
    ) -> Result<(), StorageError> {
        (**self).insert_workspace_agent_stat(input).await
    }

    async fn list_workspace_proxies_for_health(
        &self,
    ) -> Result<Vec<WorkspaceProxyHealthRecord>, StorageError> {
        (**self).list_workspace_proxies_for_health().await
    }

    async fn upsert_workspace_proxy_for_health(
        &self,
        input: &WorkspaceProxyHealthInput,
    ) -> Result<(), StorageError> {
        (**self).upsert_workspace_proxy_for_health(input).await
    }

    async fn list_provisioner_daemons_for_health(
        &self,
    ) -> Result<Vec<ProvisionerDaemonHealthRecord>, StorageError> {
        (**self).list_provisioner_daemons_for_health().await
    }

    async fn upsert_provisioner_daemon_for_health(
        &self,
        input: &ProvisionerDaemonHealthInput,
    ) -> Result<(), StorageError> {
        (**self).upsert_provisioner_daemon_for_health(input).await
    }

    async fn find_git_ssh_key(
        &self,
        user_id: Uuid,
    ) -> Result<Option<GitSshKeyRecord>, StorageError> {
        (**self).find_git_ssh_key(user_id).await
    }

    async fn upsert_git_ssh_key(
        &self,
        user_id: Uuid,
        public_key: &str,
        private_key: &str,
    ) -> Result<GitSshKeyRecord, StorageError> {
        (**self)
            .upsert_git_ssh_key(user_id, public_key, private_key)
            .await
    }

    async fn insert_file(&self, input: InsertFileInput) -> Result<InsertFileResult, StorageError> {
        (**self).insert_file(input).await
    }

    async fn get_file_by_id(&self, file_id: Uuid) -> Result<Option<FileRecord>, StorageError> {
        (**self).get_file_by_id(file_id).await
    }

    async fn get_file_by_hash_and_creator(
        &self,
        hash: &str,
        creator_id: Uuid,
    ) -> Result<Option<FileRecord>, StorageError> {
        (**self)
            .get_file_by_hash_and_creator(hash, creator_id)
            .await
    }
}

// ---------------------------------------------------------------------------
// WorkspaceStore blanket impls
// ---------------------------------------------------------------------------

#[async_trait]
impl<T> WorkspaceStore for T
where
    T: AppStore + ?Sized,
{
    async fn list_workspaces(
        &self,
        filter: WorkspaceListFilter,
    ) -> Result<(Vec<WorkspaceRecord>, i64), StorageError> {
        AppStore::list_workspaces(self, filter).await
    }

    async fn find_workspace_by_id(
        &self,
        workspace_id: Uuid,
        viewer_id: Option<Uuid>,
    ) -> Result<Option<WorkspaceRecord>, StorageError> {
        AppStore::find_workspace_by_id(self, workspace_id, viewer_id).await
    }

    async fn find_workspace_by_owner_and_name(
        &self,
        owner_id: Uuid,
        name: &str,
        viewer_id: Option<Uuid>,
    ) -> Result<Option<WorkspaceRecord>, StorageError> {
        AppStore::find_workspace_by_owner_and_name(self, owner_id, name, viewer_id).await
    }

    async fn insert_workspace(
        &self,
        input: CreateWorkspaceInput,
    ) -> Result<WorkspaceRecord, StorageError> {
        AppStore::insert_workspace(self, input).await
    }

    async fn update_workspace_name(
        &self,
        workspace_id: Uuid,
        name: &str,
        viewer_id: Option<Uuid>,
    ) -> Result<Option<WorkspaceRecord>, StorageError> {
        AppStore::update_workspace_name(self, workspace_id, name, viewer_id).await
    }

    async fn update_workspace_autostart(
        &self,
        workspace_id: Uuid,
        schedule: Option<&str>,
    ) -> Result<bool, StorageError> {
        AppStore::update_workspace_autostart(self, workspace_id, schedule).await
    }

    async fn update_workspace_ttl(
        &self,
        workspace_id: Uuid,
        ttl_ns: Option<i64>,
    ) -> Result<bool, StorageError> {
        AppStore::update_workspace_ttl(self, workspace_id, ttl_ns).await
    }

    async fn update_workspace_dormant_at(
        &self,
        workspace_id: Uuid,
        dormant_at: Option<OffsetDateTime>,
        viewer_id: Option<Uuid>,
    ) -> Result<Option<WorkspaceRecord>, StorageError> {
        AppStore::update_workspace_dormant_at(self, workspace_id, dormant_at, viewer_id).await
    }

    async fn update_workspace_automatic_updates(
        &self,
        workspace_id: Uuid,
        automatic_updates: &str,
    ) -> Result<bool, StorageError> {
        AppStore::update_workspace_automatic_updates(self, workspace_id, automatic_updates).await
    }

    async fn update_workspace_last_used_at(
        &self,
        workspace_id: Uuid,
        last_used_at: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        AppStore::update_workspace_last_used_at(self, workspace_id, last_used_at).await
    }

    async fn favorite_workspace(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
        favorite: bool,
    ) -> Result<bool, StorageError> {
        AppStore::favorite_workspace(self, workspace_id, user_id, favorite).await
    }

    async fn soft_delete_workspace(&self, workspace_id: Uuid) -> Result<bool, StorageError> {
        AppStore::soft_delete_workspace(self, workspace_id).await
    }

    async fn create_group(&self, input: &CreateGroupInput) -> Result<GroupRecord, StorageError> {
        AppStore::create_group(self, input).await
    }

    async fn delete_group(&self, group_id: Uuid) -> Result<bool, StorageError> {
        AppStore::delete_group(self, group_id).await
    }

    async fn list_groups(&self, organization_id: Uuid) -> Result<Vec<GroupRecord>, StorageError> {
        AppStore::list_groups(self, organization_id).await
    }

    async fn insert_group_member(&self, group_id: Uuid, user_id: Uuid) -> Result<(), StorageError> {
        AppStore::insert_group_member(self, group_id, user_id).await
    }

    async fn list_group_members(
        &self,
        group_id: Uuid,
    ) -> Result<Vec<GroupMemberRecord>, StorageError> {
        AppStore::list_group_members(self, group_id).await
    }

    async fn delete_group_member(
        &self,
        group_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, StorageError> {
        AppStore::delete_group_member(self, group_id, user_id).await
    }

    async fn find_group_by_id(&self, group_id: Uuid) -> Result<Option<GroupRecord>, StorageError> {
        AppStore::find_group_by_id(self, group_id).await
    }

    async fn get_workspace_acl(
        &self,
        workspace_id: Uuid,
    ) -> Result<WorkspaceACLRecord, StorageError> {
        AppStore::get_workspace_acl(self, workspace_id).await
    }

    async fn update_workspace_acl(
        &self,
        workspace_id: Uuid,
        input: &UpdateWorkspaceACLInput,
    ) -> Result<(), StorageError> {
        AppStore::update_workspace_acl(self, workspace_id, input).await
    }

    async fn delete_workspace_acl(&self, workspace_id: Uuid) -> Result<(), StorageError> {
        AppStore::delete_workspace_acl(self, workspace_id).await
    }

    async fn find_template_by_id(
        &self,
        template_id: Uuid,
    ) -> Result<Option<TemplateRecord>, StorageError> {
        AppStore::find_template_by_id(self, template_id).await
    }

    async fn find_template_version_by_id(
        &self,
        template_version_id: Uuid,
    ) -> Result<Option<TemplateVersionRecord>, StorageError> {
        AppStore::find_template_version_by_id(self, template_version_id).await
    }

    async fn list_workspace_builds(
        &self,
        workspace_id: Uuid,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<WorkspaceBuildRecord>, StorageError> {
        AppStore::list_workspace_builds(self, workspace_id, limit, offset).await
    }

    async fn find_latest_workspace_build(
        &self,
        workspace_id: Uuid,
    ) -> Result<Option<WorkspaceBuildRecord>, StorageError> {
        AppStore::find_latest_workspace_build(self, workspace_id).await
    }

    async fn find_workspace_build_by_id(
        &self,
        build_id: Uuid,
    ) -> Result<Option<WorkspaceBuildRecord>, StorageError> {
        AppStore::find_workspace_build_by_id(self, build_id).await
    }

    async fn find_workspace_build_by_number(
        &self,
        workspace_id: Uuid,
        build_number: i64,
    ) -> Result<Option<WorkspaceBuildRecord>, StorageError> {
        AppStore::find_workspace_build_by_number(self, workspace_id, build_number).await
    }

    async fn insert_workspace_build(
        &self,
        input: CreateWorkspaceBuildInput,
    ) -> Result<WorkspaceBuildRecord, StorageError> {
        AppStore::insert_workspace_build(self, input).await
    }

    async fn update_workspace_build_deadline(
        &self,
        build_id: Uuid,
        deadline: Option<OffsetDateTime>,
        max_deadline: Option<OffsetDateTime>,
    ) -> Result<bool, StorageError> {
        AppStore::update_workspace_build_deadline(self, build_id, deadline, max_deadline).await
    }

    async fn update_workspace_build_provisioner_state(
        &self,
        build_id: Uuid,
        state: &[u8],
    ) -> Result<bool, StorageError> {
        AppStore::update_workspace_build_provisioner_state(self, build_id, state).await
    }

    async fn next_workspace_build_number(&self, workspace_id: Uuid) -> Result<i64, StorageError> {
        AppStore::next_workspace_build_number(self, workspace_id).await
    }

    async fn list_workspace_build_parameters(
        &self,
        build_id: Uuid,
    ) -> Result<Vec<WorkspaceBuildParameterRecord>, StorageError> {
        AppStore::list_workspace_build_parameters(self, build_id).await
    }

    async fn insert_workspace_build_parameters(
        &self,
        build_id: Uuid,
        params: &[(String, String)],
    ) -> Result<(), StorageError> {
        AppStore::insert_workspace_build_parameters(self, build_id, params).await
    }

    async fn find_provisioner_job_by_id(
        &self,
        job_id: Uuid,
    ) -> Result<Option<TemplateProvisionerJobRecord>, StorageError> {
        AppStore::find_provisioner_job(self, job_id).await
    }

    async fn insert_provisioner_job(
        &self,
        input: CreateProvisionerJobInput,
    ) -> Result<TemplateProvisionerJobRecord, StorageError> {
        AppStore::create_provisioner_job(self, input).await
    }

    async fn cancel_provisioner_job(&self, job_id: Uuid) -> Result<bool, StorageError> {
        AppStore::cancel_template_provisioner_job(self, job_id).await
    }

    async fn list_provisioner_job_logs(
        &self,
        job_id: Uuid,
        after: Option<i64>,
    ) -> Result<Vec<ProvisionerJobLogRecord>, StorageError> {
        AppStore::list_provisioner_job_logs(self, job_id, after).await
    }

    async fn list_provisioner_job_timings(
        &self,
        job_id: Uuid,
    ) -> Result<Vec<ProvisionerJobTimingRecord>, StorageError> {
        AppStore::list_provisioner_job_timings(self, job_id).await
    }

    async fn find_workspace_resource_by_id(
        &self,
        resource_id: Uuid,
    ) -> Result<Option<WorkspaceResourceRecord>, StorageError> {
        AppStore::find_workspace_resource_by_id(self, resource_id).await
    }

    async fn list_workspace_agent_script_timings_by_build_id(
        &self,
        build_id: Uuid,
    ) -> Result<Vec<WorkspaceAgentScriptTimingRow>, StorageError> {
        AppStore::list_workspace_agent_script_timings_by_build_id(self, build_id).await
    }

    async fn list_workspace_resources_by_job(
        &self,
        job_id: Uuid,
    ) -> Result<Vec<WorkspaceResourceRecord>, StorageError> {
        AppStore::list_workspace_resources_by_job(self, job_id).await
    }

    async fn list_workspace_resource_metadata(
        &self,
        resource_ids: &[Uuid],
    ) -> Result<Vec<WorkspaceResourceMetadataRecord>, StorageError> {
        AppStore::list_workspace_resource_metadata(self, resource_ids).await
    }

    async fn list_workspace_port_shares(
        &self,
        workspace_id: Uuid,
    ) -> Result<Vec<WorkspaceAgentPortShareRecord>, StorageError> {
        AppStore::list_workspace_port_shares(self, workspace_id).await
    }

    async fn upsert_workspace_port_share(
        &self,
        input: UpsertPortShareInput,
    ) -> Result<WorkspaceAgentPortShareRecord, StorageError> {
        AppStore::upsert_workspace_port_share(self, input).await
    }

    async fn find_workspace_port_share(
        &self,
        workspace_id: Uuid,
        agent_name: &str,
        port: i32,
    ) -> Result<Option<WorkspaceAgentPortShareRecord>, StorageError> {
        AppStore::find_workspace_port_share(self, workspace_id, agent_name, port).await
    }

    async fn delete_workspace_port_share(
        &self,
        workspace_id: Uuid,
        agent_name: &str,
        port: i32,
    ) -> Result<bool, StorageError> {
        AppStore::delete_workspace_port_share(self, workspace_id, agent_name, port).await
    }
}

#[async_trait]
impl<T> WorkspaceStore for Arc<T>
where
    T: WorkspaceStore + ?Sized,
{
    async fn list_workspaces(
        &self,
        filter: WorkspaceListFilter,
    ) -> Result<(Vec<WorkspaceRecord>, i64), StorageError> {
        (**self).list_workspaces(filter).await
    }

    async fn find_workspace_by_id(
        &self,
        workspace_id: Uuid,
        viewer_id: Option<Uuid>,
    ) -> Result<Option<WorkspaceRecord>, StorageError> {
        (**self).find_workspace_by_id(workspace_id, viewer_id).await
    }

    async fn find_workspace_by_owner_and_name(
        &self,
        owner_id: Uuid,
        name: &str,
        viewer_id: Option<Uuid>,
    ) -> Result<Option<WorkspaceRecord>, StorageError> {
        (**self)
            .find_workspace_by_owner_and_name(owner_id, name, viewer_id)
            .await
    }

    async fn insert_workspace(
        &self,
        input: CreateWorkspaceInput,
    ) -> Result<WorkspaceRecord, StorageError> {
        (**self).insert_workspace(input).await
    }

    async fn update_workspace_name(
        &self,
        workspace_id: Uuid,
        name: &str,
        viewer_id: Option<Uuid>,
    ) -> Result<Option<WorkspaceRecord>, StorageError> {
        (**self)
            .update_workspace_name(workspace_id, name, viewer_id)
            .await
    }

    async fn update_workspace_autostart(
        &self,
        workspace_id: Uuid,
        schedule: Option<&str>,
    ) -> Result<bool, StorageError> {
        (**self)
            .update_workspace_autostart(workspace_id, schedule)
            .await
    }

    async fn update_workspace_ttl(
        &self,
        workspace_id: Uuid,
        ttl_ns: Option<i64>,
    ) -> Result<bool, StorageError> {
        (**self).update_workspace_ttl(workspace_id, ttl_ns).await
    }

    async fn update_workspace_dormant_at(
        &self,
        workspace_id: Uuid,
        dormant_at: Option<OffsetDateTime>,
        viewer_id: Option<Uuid>,
    ) -> Result<Option<WorkspaceRecord>, StorageError> {
        (**self)
            .update_workspace_dormant_at(workspace_id, dormant_at, viewer_id)
            .await
    }

    async fn update_workspace_automatic_updates(
        &self,
        workspace_id: Uuid,
        automatic_updates: &str,
    ) -> Result<bool, StorageError> {
        (**self)
            .update_workspace_automatic_updates(workspace_id, automatic_updates)
            .await
    }

    async fn update_workspace_last_used_at(
        &self,
        workspace_id: Uuid,
        last_used_at: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        (**self)
            .update_workspace_last_used_at(workspace_id, last_used_at)
            .await
    }

    async fn favorite_workspace(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
        favorite: bool,
    ) -> Result<bool, StorageError> {
        (**self)
            .favorite_workspace(workspace_id, user_id, favorite)
            .await
    }

    async fn soft_delete_workspace(&self, workspace_id: Uuid) -> Result<bool, StorageError> {
        (**self).soft_delete_workspace(workspace_id).await
    }

    async fn create_group(&self, input: &CreateGroupInput) -> Result<GroupRecord, StorageError> {
        (**self).create_group(input).await
    }

    async fn delete_group(&self, group_id: Uuid) -> Result<bool, StorageError> {
        (**self).delete_group(group_id).await
    }

    async fn list_groups(&self, organization_id: Uuid) -> Result<Vec<GroupRecord>, StorageError> {
        (**self).list_groups(organization_id).await
    }

    async fn insert_group_member(&self, group_id: Uuid, user_id: Uuid) -> Result<(), StorageError> {
        (**self).insert_group_member(group_id, user_id).await
    }

    async fn list_group_members(
        &self,
        group_id: Uuid,
    ) -> Result<Vec<GroupMemberRecord>, StorageError> {
        (**self).list_group_members(group_id).await
    }

    async fn delete_group_member(
        &self,
        group_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, StorageError> {
        (**self).delete_group_member(group_id, user_id).await
    }

    async fn find_group_by_id(&self, group_id: Uuid) -> Result<Option<GroupRecord>, StorageError> {
        (**self).find_group_by_id(group_id).await
    }

    async fn get_workspace_acl(
        &self,
        workspace_id: Uuid,
    ) -> Result<WorkspaceACLRecord, StorageError> {
        (**self).get_workspace_acl(workspace_id).await
    }

    async fn update_workspace_acl(
        &self,
        workspace_id: Uuid,
        input: &UpdateWorkspaceACLInput,
    ) -> Result<(), StorageError> {
        (**self).update_workspace_acl(workspace_id, input).await
    }

    async fn delete_workspace_acl(&self, workspace_id: Uuid) -> Result<(), StorageError> {
        (**self).delete_workspace_acl(workspace_id).await
    }

    async fn find_template_by_id(
        &self,
        template_id: Uuid,
    ) -> Result<Option<TemplateRecord>, StorageError> {
        (**self).find_template_by_id(template_id).await
    }

    async fn find_template_version_by_id(
        &self,
        template_version_id: Uuid,
    ) -> Result<Option<TemplateVersionRecord>, StorageError> {
        (**self)
            .find_template_version_by_id(template_version_id)
            .await
    }

    async fn list_workspace_builds(
        &self,
        workspace_id: Uuid,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<WorkspaceBuildRecord>, StorageError> {
        (**self)
            .list_workspace_builds(workspace_id, limit, offset)
            .await
    }

    async fn find_latest_workspace_build(
        &self,
        workspace_id: Uuid,
    ) -> Result<Option<WorkspaceBuildRecord>, StorageError> {
        (**self).find_latest_workspace_build(workspace_id).await
    }

    async fn find_workspace_build_by_id(
        &self,
        build_id: Uuid,
    ) -> Result<Option<WorkspaceBuildRecord>, StorageError> {
        (**self).find_workspace_build_by_id(build_id).await
    }

    async fn find_workspace_build_by_number(
        &self,
        workspace_id: Uuid,
        build_number: i64,
    ) -> Result<Option<WorkspaceBuildRecord>, StorageError> {
        (**self)
            .find_workspace_build_by_number(workspace_id, build_number)
            .await
    }

    async fn insert_workspace_build(
        &self,
        input: CreateWorkspaceBuildInput,
    ) -> Result<WorkspaceBuildRecord, StorageError> {
        (**self).insert_workspace_build(input).await
    }

    async fn update_workspace_build_deadline(
        &self,
        build_id: Uuid,
        deadline: Option<OffsetDateTime>,
        max_deadline: Option<OffsetDateTime>,
    ) -> Result<bool, StorageError> {
        (**self)
            .update_workspace_build_deadline(build_id, deadline, max_deadline)
            .await
    }

    async fn update_workspace_build_provisioner_state(
        &self,
        build_id: Uuid,
        state: &[u8],
    ) -> Result<bool, StorageError> {
        (**self)
            .update_workspace_build_provisioner_state(build_id, state)
            .await
    }

    async fn next_workspace_build_number(&self, workspace_id: Uuid) -> Result<i64, StorageError> {
        (**self).next_workspace_build_number(workspace_id).await
    }

    async fn list_workspace_build_parameters(
        &self,
        build_id: Uuid,
    ) -> Result<Vec<WorkspaceBuildParameterRecord>, StorageError> {
        (**self).list_workspace_build_parameters(build_id).await
    }

    async fn insert_workspace_build_parameters(
        &self,
        build_id: Uuid,
        params: &[(String, String)],
    ) -> Result<(), StorageError> {
        (**self)
            .insert_workspace_build_parameters(build_id, params)
            .await
    }

    async fn find_provisioner_job_by_id(
        &self,
        job_id: Uuid,
    ) -> Result<Option<TemplateProvisionerJobRecord>, StorageError> {
        (**self).find_provisioner_job_by_id(job_id).await
    }

    async fn insert_provisioner_job(
        &self,
        input: CreateProvisionerJobInput,
    ) -> Result<TemplateProvisionerJobRecord, StorageError> {
        (**self).insert_provisioner_job(input).await
    }

    async fn cancel_provisioner_job(&self, job_id: Uuid) -> Result<bool, StorageError> {
        (**self).cancel_provisioner_job(job_id).await
    }

    async fn list_provisioner_job_logs(
        &self,
        job_id: Uuid,
        after: Option<i64>,
    ) -> Result<Vec<ProvisionerJobLogRecord>, StorageError> {
        (**self).list_provisioner_job_logs(job_id, after).await
    }

    async fn list_provisioner_job_timings(
        &self,
        job_id: Uuid,
    ) -> Result<Vec<ProvisionerJobTimingRecord>, StorageError> {
        (**self).list_provisioner_job_timings(job_id).await
    }

    async fn find_workspace_resource_by_id(
        &self,
        resource_id: Uuid,
    ) -> Result<Option<WorkspaceResourceRecord>, StorageError> {
        (**self).find_workspace_resource_by_id(resource_id).await
    }

    async fn list_workspace_agent_script_timings_by_build_id(
        &self,
        build_id: Uuid,
    ) -> Result<Vec<WorkspaceAgentScriptTimingRow>, StorageError> {
        (**self)
            .list_workspace_agent_script_timings_by_build_id(build_id)
            .await
    }

    async fn list_workspace_resources_by_job(
        &self,
        job_id: Uuid,
    ) -> Result<Vec<WorkspaceResourceRecord>, StorageError> {
        (**self).list_workspace_resources_by_job(job_id).await
    }

    async fn list_workspace_resource_metadata(
        &self,
        resource_ids: &[Uuid],
    ) -> Result<Vec<WorkspaceResourceMetadataRecord>, StorageError> {
        (**self)
            .list_workspace_resource_metadata(resource_ids)
            .await
    }

    async fn list_workspace_port_shares(
        &self,
        workspace_id: Uuid,
    ) -> Result<Vec<WorkspaceAgentPortShareRecord>, StorageError> {
        (**self).list_workspace_port_shares(workspace_id).await
    }

    async fn upsert_workspace_port_share(
        &self,
        input: UpsertPortShareInput,
    ) -> Result<WorkspaceAgentPortShareRecord, StorageError> {
        (**self).upsert_workspace_port_share(input).await
    }

    async fn find_workspace_port_share(
        &self,
        workspace_id: Uuid,
        agent_name: &str,
        port: i32,
    ) -> Result<Option<WorkspaceAgentPortShareRecord>, StorageError> {
        (**self)
            .find_workspace_port_share(workspace_id, agent_name, port)
            .await
    }

    async fn delete_workspace_port_share(
        &self,
        workspace_id: Uuid,
        agent_name: &str,
        port: i32,
    ) -> Result<bool, StorageError> {
        (**self)
            .delete_workspace_port_share(workspace_id, agent_name, port)
            .await
    }
}

#[async_trait]
impl<T> InsightsStore for T
where
    T: AppStore + ?Sized,
{
    async fn get_deployment_daus(&self, tz_offset: i32) -> Result<DAUsResponse, StorageError> {
        AppStore::get_deployment_daus(self, tz_offset).await
    }

    async fn get_template_insights(
        &self,
        start_time: OffsetDateTime,
        end_time: OffsetDateTime,
        interval: InsightsReportInterval,
        template_ids: Vec<Uuid>,
    ) -> Result<TemplateInsightsResponse, StorageError> {
        AppStore::get_template_insights(self, start_time, end_time, interval, template_ids).await
    }

    async fn get_template_insights_by_interval(
        &self,
        start_time: OffsetDateTime,
        end_time: OffsetDateTime,
        interval: InsightsReportInterval,
        template_ids: Vec<Uuid>,
    ) -> Result<Vec<TemplateInsightsIntervalReport>, StorageError> {
        AppStore::get_template_insights_by_interval(
            self,
            start_time,
            end_time,
            interval,
            template_ids,
        )
        .await
    }

    async fn get_user_activity_insights(
        &self,
        start_time: OffsetDateTime,
        end_time: OffsetDateTime,
        template_ids: Vec<Uuid>,
    ) -> Result<UserActivityInsightsResponse, StorageError> {
        AppStore::get_user_activity_insights(self, start_time, end_time, template_ids).await
    }

    async fn get_user_latency_insights(
        &self,
        start_time: OffsetDateTime,
        end_time: OffsetDateTime,
        template_ids: Vec<Uuid>,
    ) -> Result<UserLatencyInsightsResponse, StorageError> {
        AppStore::get_user_latency_insights(self, start_time, end_time, template_ids).await
    }

    async fn get_user_status_counts(
        &self,
        timezone: &str,
        start_time: OffsetDateTime,
        end_time: OffsetDateTime,
    ) -> Result<GetUserStatusCountsResponse, StorageError> {
        AppStore::get_user_status_counts(self, timezone, start_time, end_time).await
    }
}

#[async_trait]
impl<T> InsightsStore for Arc<T>
where
    T: InsightsStore + ?Sized,
{
    async fn get_deployment_daus(&self, tz_offset: i32) -> Result<DAUsResponse, StorageError> {
        (**self).get_deployment_daus(tz_offset).await
    }

    async fn get_template_insights(
        &self,
        start_time: OffsetDateTime,
        end_time: OffsetDateTime,
        interval: InsightsReportInterval,
        template_ids: Vec<Uuid>,
    ) -> Result<TemplateInsightsResponse, StorageError> {
        (**self)
            .get_template_insights(start_time, end_time, interval, template_ids)
            .await
    }

    async fn get_template_insights_by_interval(
        &self,
        start_time: OffsetDateTime,
        end_time: OffsetDateTime,
        interval: InsightsReportInterval,
        template_ids: Vec<Uuid>,
    ) -> Result<Vec<TemplateInsightsIntervalReport>, StorageError> {
        (**self)
            .get_template_insights_by_interval(start_time, end_time, interval, template_ids)
            .await
    }

    async fn get_user_activity_insights(
        &self,
        start_time: OffsetDateTime,
        end_time: OffsetDateTime,
        template_ids: Vec<Uuid>,
    ) -> Result<UserActivityInsightsResponse, StorageError> {
        (**self)
            .get_user_activity_insights(start_time, end_time, template_ids)
            .await
    }

    async fn get_user_latency_insights(
        &self,
        start_time: OffsetDateTime,
        end_time: OffsetDateTime,
        template_ids: Vec<Uuid>,
    ) -> Result<UserLatencyInsightsResponse, StorageError> {
        (**self)
            .get_user_latency_insights(start_time, end_time, template_ids)
            .await
    }

    async fn get_user_status_counts(
        &self,
        timezone: &str,
        start_time: OffsetDateTime,
        end_time: OffsetDateTime,
    ) -> Result<GetUserStatusCountsResponse, StorageError> {
        (**self)
            .get_user_status_counts(timezone, start_time, end_time)
            .await
    }
}

#[async_trait]
impl<T> ProvisionerStore for Arc<T>
where
    T: ProvisionerStore + ?Sized,
{
    async fn acquire_provisioner_job(
        &self,
        input: AcquireProvisionerJobInput,
    ) -> Result<Option<ProvisionerJobRecord>, StorageError> {
        (**self).acquire_provisioner_job(input).await
    }

    async fn get_provisioner_job_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<ProvisionerJobRecord>, StorageError> {
        (**self).get_provisioner_job_by_id(id).await
    }

    async fn get_provisioner_jobs_by_ids(
        &self,
        ids: &[Uuid],
    ) -> Result<Vec<ProvisionerJobRecord>, StorageError> {
        (**self).get_provisioner_jobs_by_ids(ids).await
    }

    async fn insert_provisioner_job(
        &self,
        input: InsertProvisionerJobInput,
    ) -> Result<ProvisionerJobRecord, StorageError> {
        (**self).insert_provisioner_job(input).await
    }

    async fn update_provisioner_job_by_id(
        &self,
        id: Uuid,
        updated_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        (**self).update_provisioner_job_by_id(id, updated_at).await
    }

    async fn update_provisioner_job_with_complete_by_id(
        &self,
        input: CompleteProvisionerJobInput,
    ) -> Result<(), StorageError> {
        (**self)
            .update_provisioner_job_with_complete_by_id(input)
            .await
    }

    async fn update_provisioner_job_with_cancel_by_id(
        &self,
        input: CancelProvisionerJobInput,
    ) -> Result<(), StorageError> {
        (**self)
            .update_provisioner_job_with_cancel_by_id(input)
            .await
    }

    async fn get_provisioner_jobs_to_be_reaped(
        &self,
        input: GetJobsToBeReapedInput,
    ) -> Result<Vec<ProvisionerJobRecord>, StorageError> {
        (**self).get_provisioner_jobs_to_be_reaped(input).await
    }

    async fn insert_provisioner_job_logs(
        &self,
        input: InsertProvisionerJobLogsInput,
    ) -> Result<Vec<ProvisionerLogRecord>, StorageError> {
        (**self).insert_provisioner_job_logs(input).await
    }

    async fn get_provisioner_logs_after_id(
        &self,
        job_id: Uuid,
        after_id: i64,
    ) -> Result<Vec<ProvisionerLogRecord>, StorageError> {
        (**self)
            .get_provisioner_logs_after_id(job_id, after_id)
            .await
    }

    async fn insert_provisioner_job_timings(
        &self,
        input: InsertProvisionerJobTimingsInput,
    ) -> Result<Vec<ProvisionerTimingRecord>, StorageError> {
        (**self).insert_provisioner_job_timings(input).await
    }

    async fn get_provisioner_job_timings_by_job_id(
        &self,
        job_id: Uuid,
    ) -> Result<Vec<ProvisionerTimingRecord>, StorageError> {
        (**self).get_provisioner_job_timings_by_job_id(job_id).await
    }

    async fn upsert_provisioner_daemon(
        &self,
        input: UpsertProvisionerDaemonInput,
    ) -> Result<ProvisionerDaemonRecord, StorageError> {
        (**self).upsert_provisioner_daemon(input).await
    }

    async fn update_provisioner_daemon_last_seen_at(
        &self,
        id: Uuid,
        last_seen_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        (**self)
            .update_provisioner_daemon_last_seen_at(id, last_seen_at)
            .await
    }

    async fn get_provisioner_daemons_by_organization(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<ProvisionerDaemonRecord>, StorageError> {
        (**self)
            .get_provisioner_daemons_by_organization(organization_id)
            .await
    }

    async fn delete_old_provisioner_daemons(&self) -> Result<(), StorageError> {
        (**self).delete_old_provisioner_daemons().await
    }

    async fn insert_provisioner_key(
        &self,
        input: InsertProvisionerKeyInput,
    ) -> Result<ProvisionerKeyRecord, StorageError> {
        (**self).insert_provisioner_key(input).await
    }

    async fn get_provisioner_key_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<ProvisionerKeyRecord>, StorageError> {
        (**self).get_provisioner_key_by_id(id).await
    }

    async fn get_provisioner_key_by_hashed_secret(
        &self,
        hashed_secret: &[u8],
    ) -> Result<Option<ProvisionerKeyRecord>, StorageError> {
        (**self)
            .get_provisioner_key_by_hashed_secret(hashed_secret)
            .await
    }

    async fn get_provisioner_key_by_name(
        &self,
        organization_id: Uuid,
        name: &str,
    ) -> Result<Option<ProvisionerKeyRecord>, StorageError> {
        (**self)
            .get_provisioner_key_by_name(organization_id, name)
            .await
    }

    async fn list_provisioner_keys_by_organization(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<ProvisionerKeyRecord>, StorageError> {
        (**self)
            .list_provisioner_keys_by_organization(organization_id)
            .await
    }

    async fn delete_provisioner_key(&self, id: Uuid) -> Result<bool, StorageError> {
        (**self).delete_provisioner_key(id).await
    }
}

#[async_trait]
impl<T> TemplateStore for T
where
    T: AppStore + ?Sized,
{
    async fn list_templates(
        &self,
        filter: TemplateListFilter,
    ) -> Result<Vec<TemplateRecord>, StorageError> {
        AppStore::list_templates(self, filter).await
    }

    async fn find_template_by_id(
        &self,
        template_id: Uuid,
    ) -> Result<Option<TemplateRecord>, StorageError> {
        AppStore::find_template_by_id(self, template_id).await
    }

    async fn find_template_by_org_and_name(
        &self,
        organization_id: Uuid,
        name: &str,
    ) -> Result<Option<TemplateRecord>, StorageError> {
        AppStore::find_template_by_org_and_name(self, organization_id, name).await
    }

    async fn insert_template(
        &self,
        input: CreateTemplateInput,
    ) -> Result<TemplateRecord, CreateTemplateStoreError> {
        AppStore::insert_template(self, input).await
    }

    async fn update_template_meta(
        &self,
        input: UpdateTemplateMetaInput,
    ) -> Result<Option<TemplateRecord>, StorageError> {
        AppStore::update_template_meta(self, input).await
    }

    async fn soft_delete_template(&self, template_id: Uuid) -> Result<bool, StorageError> {
        AppStore::soft_delete_template(self, template_id).await
    }

    async fn update_template_active_version(
        &self,
        template_id: Uuid,
        active_version_id: Uuid,
    ) -> Result<bool, StorageError> {
        AppStore::update_template_active_version(self, template_id, active_version_id).await
    }

    async fn template_daus(&self, template_id: Uuid) -> Result<Vec<TemplateDAURow>, StorageError> {
        AppStore::template_daus(self, template_id).await
    }

    async fn list_template_versions(
        &self,
        filter: TemplateVersionListFilter,
    ) -> Result<Vec<TemplateVersionRecord>, StorageError> {
        AppStore::list_template_versions(self, filter).await
    }

    async fn find_template_version_by_id(
        &self,
        version_id: Uuid,
    ) -> Result<Option<TemplateVersionRecord>, StorageError> {
        AppStore::find_template_version_by_id(self, version_id).await
    }

    async fn find_template_version_by_template_and_name(
        &self,
        template_id: Uuid,
        name: &str,
    ) -> Result<Option<TemplateVersionRecord>, StorageError> {
        AppStore::find_template_version_by_template_and_name(self, template_id, name).await
    }

    async fn find_template_version_by_org_and_name(
        &self,
        organization_id: Uuid,
        template_name: &str,
        version_name: &str,
    ) -> Result<Option<TemplateVersionRecord>, StorageError> {
        AppStore::find_template_version_by_org_and_name(
            self,
            organization_id,
            template_name,
            version_name,
        )
        .await
    }

    async fn insert_template_version(
        &self,
        input: CreateTemplateVersionInput,
    ) -> Result<TemplateVersionRecord, StorageError> {
        AppStore::insert_template_version(self, input).await
    }

    async fn update_template_version(
        &self,
        version_id: Uuid,
        name: &str,
        message: &str,
    ) -> Result<Option<TemplateVersionRecord>, StorageError> {
        AppStore::update_template_version(self, version_id, name, message).await
    }

    async fn find_previous_template_version(
        &self,
        organization_id: Uuid,
        template_name: &str,
        version_name: &str,
    ) -> Result<Option<TemplateVersionRecord>, StorageError> {
        AppStore::find_previous_template_version(self, organization_id, template_name, version_name)
            .await
    }

    async fn archive_template_version(&self, version_id: Uuid) -> Result<bool, StorageError> {
        AppStore::archive_template_version(self, version_id).await
    }

    async fn unarchive_template_version(&self, version_id: Uuid) -> Result<bool, StorageError> {
        AppStore::unarchive_template_version(self, version_id).await
    }

    async fn list_template_version_parameters(
        &self,
        version_id: Uuid,
    ) -> Result<Vec<TemplateVersionParameterRecord>, StorageError> {
        AppStore::list_template_version_parameters(self, version_id).await
    }

    async fn list_template_version_variables(
        &self,
        version_id: Uuid,
    ) -> Result<Vec<TemplateVersionVariableRecord>, StorageError> {
        AppStore::list_template_version_variables(self, version_id).await
    }

    async fn list_template_version_presets(
        &self,
        version_id: Uuid,
    ) -> Result<Vec<TemplateVersionPresetRecord>, StorageError> {
        AppStore::list_template_version_presets(self, version_id).await
    }

    async fn list_template_version_preset_parameters(
        &self,
        preset_id: Uuid,
    ) -> Result<Vec<TemplateVersionPresetParameterRecord>, StorageError> {
        AppStore::list_template_version_preset_parameters(self, preset_id).await
    }

    async fn create_provisioner_job(
        &self,
        input: CreateProvisionerJobInput,
    ) -> Result<TemplateProvisionerJobRecord, StorageError> {
        AppStore::create_provisioner_job(self, input).await
    }

    async fn find_provisioner_job(
        &self,
        job_id: Uuid,
    ) -> Result<Option<TemplateProvisionerJobRecord>, StorageError> {
        AppStore::find_provisioner_job(self, job_id).await
    }

    async fn cancel_template_provisioner_job(&self, job_id: Uuid) -> Result<bool, StorageError> {
        AppStore::cancel_template_provisioner_job(self, job_id).await
    }

    async fn archive_unused_template_versions(
        &self,
        template_id: Uuid,
        all: bool,
    ) -> Result<Vec<Uuid>, StorageError> {
        AppStore::archive_unused_template_versions(self, template_id, all).await
    }

    async fn get_previous_template_version(
        &self,
        organization_id: Uuid,
        name: &str,
        template_id: Option<Uuid>,
    ) -> Result<Option<TemplateVersionRecord>, StorageError> {
        AppStore::get_previous_template_version(self, organization_id, name, template_id).await
    }
}

// Note: TemplateStore for Arc<T> is not needed — the blanket
// `impl<T: AppStore> TemplateStore for T` already covers `Arc<T>` when
// `Arc<T>: AppStore`, which is provided by the `AppStore for Arc<T>` impl.
