//! PostgreSQL enum types shared across the Rust backend rewrite.
//!
//! Each enum here corresponds to a `CREATE TYPE ... AS ENUM` in the PostgreSQL
//! schema. The `sqlx::Type` derive ensures seamless encoding/decoding between
//! Rust and the database layer.

// ---------------------------------------------------------------------------
// Agent
// ---------------------------------------------------------------------------

/// Lifecycle state of a workspace agent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(
    type_name = "workspace_agent_lifecycle_state",
    rename_all = "snake_case"
)]
pub enum WorkspaceAgentLifecycleState {
    Created,
    Starting,
    StartTimeout,
    StartError,
    Ready,
    ShuttingDown,
    ShutdownTimeout,
    ShutdownError,
    Off,
}

/// Monitor state of a workspace agent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[sqlx(type_name = "workspace_agent_monitor_state")]
pub enum WorkspaceAgentMonitorState {
    /// Database value: `OK`
    #[serde(rename = "OK")]
    #[sqlx(rename = "OK")]
    Ok,
    /// Database value: `NOK`
    #[serde(rename = "NOK")]
    #[sqlx(rename = "NOK")]
    Nok,
}

/// Stage at which a workspace agent script timing was recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(
    type_name = "workspace_agent_script_timing_stage",
    rename_all = "snake_case"
)]
pub enum WorkspaceAgentScriptTimingStage {
    Start,
    Stop,
    Cron,
}

/// Exit status of a workspace agent script.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(
    type_name = "workspace_agent_script_timing_status",
    rename_all = "snake_case"
)]
pub enum WorkspaceAgentScriptTimingStatus {
    Ok,
    ExitFailure,
    TimedOut,
    PipesLeftOpen,
}

/// Subsystem a workspace agent belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "workspace_agent_subsystem", rename_all = "snake_case")]
pub enum WorkspaceAgentSubsystem {
    Envbuilder,
    Envbox,
    None,
    Exectrace,
}

// ---------------------------------------------------------------------------
// Workspace
// ---------------------------------------------------------------------------

/// Transition direction for a workspace build.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "workspace_transition", rename_all = "snake_case")]
pub enum WorkspaceTransition {
    Start,
    Stop,
    Delete,
}

/// Health status of a workspace application.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "workspace_app_health", rename_all = "snake_case")]
pub enum WorkspaceAppHealth {
    Disabled,
    Initializing,
    Healthy,
    Unhealthy,
}

/// Where a workspace application opens.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[sqlx(type_name = "workspace_app_open_in")]
pub enum WorkspaceAppOpenIn {
    #[serde(rename = "tab")]
    #[sqlx(rename = "tab")]
    Tab,
    #[serde(rename = "window")]
    #[sqlx(rename = "window")]
    Window,
    #[serde(rename = "slim-window")]
    #[sqlx(rename = "slim-window")]
    SlimWindow,
}

/// Status state of a workspace application.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "workspace_app_status_state", rename_all = "snake_case")]
pub enum WorkspaceAppStatusState {
    Working,
    Complete,
    Failure,
    Idle,
}

/// Automatic update policy for a workspace.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "automatic_updates", rename_all = "snake_case")]
pub enum AutomaticUpdates {
    Always,
    Never,
}

/// Application sharing level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "app_sharing_level", rename_all = "snake_case")]
pub enum AppSharingLevel {
    Owner,
    Authenticated,
    Organization,
    Public,
}

// ---------------------------------------------------------------------------
// Provisioner
// ---------------------------------------------------------------------------

/// Provisioner implementation type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "provisioner_type", rename_all = "snake_case")]
pub enum ProvisionerType {
    Echo,
    Terraform,
}

/// Storage method used by a provisioner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "provisioner_storage_method", rename_all = "snake_case")]
pub enum ProvisionerStorageMethod {
    File,
}

/// Type of a provisioner job.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "provisioner_job_type", rename_all = "snake_case")]
pub enum ProvisionerJobType {
    TemplateVersionImport,
    WorkspaceBuild,
    TemplateVersionDryRun,
}

/// Computed status of a provisioner job.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "provisioner_job_status", rename_all = "snake_case")]
pub enum ProvisionerJobStatus {
    Pending,
    Running,
    Succeeded,
    Canceling,
    Canceled,
    Failed,
    Unknown,
}

/// Stage within a provisioner job timing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "provisioner_job_timing_stage", rename_all = "snake_case")]
pub enum ProvisionerJobTimingStage {
    Init,
    Plan,
    Graph,
    Apply,
}

/// Status of a provisioner daemon.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "provisioner_daemon_status", rename_all = "snake_case")]
pub enum ProvisionerDaemonStatus {
    Offline,
    Idle,
    Busy,
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

/// Reason for a workspace build.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "build_reason", rename_all = "snake_case")]
pub enum BuildReason {
    Initiator,
    Autostart,
    Autostop,
    Dormancy,
    Failedstop,
    Autodelete,
    Dashboard,
    Cli,
    SshConnection,
    VscodeConnection,
    JetbrainsConnection,
    TaskAutoPause,
    TaskManualPause,
    TaskResume,
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

/// Scope of an agent key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "agent_key_scope_enum", rename_all = "snake_case")]
pub enum AgentKeyScopeEnum {
    All,
    NoUserData,
}

// Note: api_key_scope has many variants with special characters (colons, dots,
// asterisks). We store the PostgreSQL type but map through explicit renames
// because the wire values are not valid Rust identifiers. A simpler approach is
// to keep the raw string representation and convert at the boundary, but we
// define the full enum here for schema completeness. Given the large number of
// variants (~200) in the Go schema, and the fact that the existing codebase
// already stores scopes as `Vec<String>`, we intentionally skip defining a Rust
// enum for `api_key_scope` here. The PostgreSQL type is created in the
// migration and the Rust side continues to use `Vec<String>` for scopes until
// route handlers need strongly-typed scope checks.

// ---------------------------------------------------------------------------
// Notifications
// ---------------------------------------------------------------------------

/// Status of a notification message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "notification_message_status", rename_all = "snake_case")]
pub enum NotificationMessageStatus {
    Pending,
    Leased,
    Sent,
    PermanentFailure,
    TemporaryFailure,
    Unknown,
    Inhibited,
}

/// Delivery method for a notification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "notification_method", rename_all = "snake_case")]
pub enum NotificationMethod {
    Smtp,
    Webhook,
    Inbox,
}

/// Kind of a notification template.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "notification_template_kind", rename_all = "snake_case")]
pub enum NotificationTemplateKind {
    System,
    Custom,
}

/// Read status filter for inbox notifications.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(
    type_name = "inbox_notification_read_status",
    rename_all = "snake_case"
)]
pub enum InboxNotificationReadStatus {
    All,
    Unread,
    Read,
}

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------

/// Destination scheme for a parameter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "parameter_destination_scheme", rename_all = "snake_case")]
pub enum ParameterDestinationScheme {
    None,
    EnvironmentVariable,
    ProvisionerVariable,
}

/// Form type for a template parameter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[sqlx(type_name = "parameter_form_type")]
pub enum ParameterFormType {
    /// Empty string default.
    #[serde(rename = "")]
    #[sqlx(rename = "")]
    Default,
    #[serde(rename = "error")]
    #[sqlx(rename = "error")]
    Error,
    #[serde(rename = "radio")]
    #[sqlx(rename = "radio")]
    Radio,
    #[serde(rename = "dropdown")]
    #[sqlx(rename = "dropdown")]
    Dropdown,
    #[serde(rename = "input")]
    #[sqlx(rename = "input")]
    Input,
    #[serde(rename = "textarea")]
    #[sqlx(rename = "textarea")]
    Textarea,
    #[serde(rename = "slider")]
    #[sqlx(rename = "slider")]
    Slider,
    #[serde(rename = "checkbox")]
    #[sqlx(rename = "checkbox")]
    Checkbox,
    #[serde(rename = "switch")]
    #[sqlx(rename = "switch")]
    Switch,
    #[serde(rename = "tag-select")]
    #[sqlx(rename = "tag-select")]
    TagSelect,
    #[serde(rename = "multi-select")]
    #[sqlx(rename = "multi-select")]
    MultiSelect,
}

/// Scope of a parameter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "parameter_scope", rename_all = "snake_case")]
pub enum ParameterScope {
    Template,
    ImportJob,
    Workspace,
}

/// Source scheme for a parameter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "parameter_source_scheme", rename_all = "snake_case")]
pub enum ParameterSourceScheme {
    None,
    Data,
}

/// Type system for a parameter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "parameter_type_system", rename_all = "snake_case")]
pub enum ParameterTypeSystem {
    None,
    Hcl,
}

// ---------------------------------------------------------------------------
// Chat / AI
// ---------------------------------------------------------------------------

/// Visibility of a chat message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "chat_message_visibility", rename_all = "snake_case")]
pub enum ChatMessageVisibility {
    User,
    Model,
    Both,
}

/// Status of a chat session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "chat_status", rename_all = "snake_case")]
pub enum ChatStatus {
    Waiting,
    Pending,
    Running,
    Paused,
    Completed,
    Error,
}

/// Status of an AI task.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "task_status", rename_all = "snake_case")]
pub enum TaskStatus {
    Pending,
    Initializing,
    Active,
    Paused,
    Unknown,
    Error,
}

// ---------------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------------

/// Display application type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "display_app", rename_all = "snake_case")]
pub enum DisplayApp {
    Vscode,
    VscodeInsiders,
    WebTerminal,
    SshHelper,
    PortForwardingHelper,
}

/// Log severity level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "log_level", rename_all = "snake_case")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

/// Source of a provisioner log line.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "log_source", rename_all = "snake_case")]
pub enum LogSource {
    ProvisionerDaemon,
    Provisioner,
}

/// Startup script behavior.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[sqlx(type_name = "startup_script_behavior")]
pub enum StartupScriptBehavior {
    #[serde(rename = "blocking")]
    #[sqlx(rename = "blocking")]
    Blocking,
    #[serde(rename = "non-blocking")]
    #[sqlx(rename = "non-blocking")]
    NonBlocking,
}

// ---------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------

/// Connection status of an agent or proxy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "connection_status", rename_all = "snake_case")]
pub enum ConnectionStatus {
    Connected,
    Disconnected,
}

/// Type of workspace connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "connection_type", rename_all = "snake_case")]
pub enum ConnectionType {
    Ssh,
    Vscode,
    Jetbrains,
    ReconnectingPty,
    WorkspaceApp,
    PortForwarding,
}

/// CORS behavior for a workspace application.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "cors_behavior", rename_all = "snake_case")]
pub enum CorsBehavior {
    Simple,
    Passthru,
}

/// Tailnet connection status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "tailnet_status", rename_all = "snake_case")]
pub enum TailnetStatus {
    Ok,
    Lost,
}

/// Protocol for a shared port.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "port_share_protocol", rename_all = "snake_case")]
pub enum PortShareProtocol {
    Http,
    Https,
}

// ---------------------------------------------------------------------------
// RBAC
// ---------------------------------------------------------------------------

/// Source of a group membership.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "group_source", rename_all = "snake_case")]
pub enum GroupSource {
    User,
    Oidc,
}

/// Status of a prebuild.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "prebuild_status", rename_all = "snake_case")]
pub enum PrebuildStatus {
    Healthy,
    HardLimited,
    ValidationFailed,
}

// ---------------------------------------------------------------------------
// Audit (database-mapped)
// ---------------------------------------------------------------------------

/// Audit action matching the PostgreSQL `audit_action` enum.
///
/// This is the database-mapped version. See also `coder_audit::AuditAction`
/// which is used by the Rust audit layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "audit_action", rename_all = "snake_case")]
pub enum AuditAction {
    Create,
    Write,
    Delete,
    Start,
    Stop,
    Login,
    Logout,
    Register,
    RequestPasswordReset,
    Connect,
    Disconnect,
    Open,
    Close,
}

/// Resource type matching the PostgreSQL `resource_type` enum.
///
/// This is the database-mapped version. See also `coder_rbac::ResourceKind`
/// which includes additional Rust-only variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "resource_type", rename_all = "snake_case")]
pub enum ResourceType {
    Organization,
    Template,
    TemplateVersion,
    User,
    Workspace,
    GitSshKey,
    ApiKey,
    Group,
    WorkspaceBuild,
    License,
    WorkspaceProxy,
    ConvertLogin,
    HealthSettings,
    Oauth2ProviderApp,
    Oauth2ProviderAppSecret,
    CustomRole,
    OrganizationMember,
    NotificationsSettings,
    NotificationTemplate,
    IdpSyncSettingsOrganization,
    IdpSyncSettingsGroup,
    IdpSyncSettingsRole,
    WorkspaceAgent,
    WorkspaceApp,
    PrebuildsSettings,
    Task,
}

// ---------------------------------------------------------------------------
// Crypto
// ---------------------------------------------------------------------------

/// Feature a crypto key is used for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "crypto_key_feature", rename_all = "snake_case")]
pub enum CryptoKeyFeature {
    WorkspaceAppsToken,
    WorkspaceAppsApiKey,
    OidcConvert,
    TailnetResume,
}
