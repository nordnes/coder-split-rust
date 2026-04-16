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
    /// Created.
    Created,
    /// Starting.
    Starting,
    /// StartTimeout.
    StartTimeout,
    /// StartError.
    StartError,
    /// Ready.
    Ready,
    /// ShuttingDown.
    ShuttingDown,
    /// ShutdownTimeout.
    ShutdownTimeout,
    /// ShutdownError.
    ShutdownError,
    /// Off.
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
    /// Start.
    Start,
    /// Stop.
    Stop,
    /// Cron.
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
    /// Ok.
    Ok,
    /// ExitFailure.
    ExitFailure,
    /// TimedOut.
    TimedOut,
    /// PipesLeftOpen.
    PipesLeftOpen,
}

/// Subsystem a workspace agent belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "workspace_agent_subsystem", rename_all = "snake_case")]
pub enum WorkspaceAgentSubsystem {
    /// Envbuilder.
    Envbuilder,
    /// Envbox.
    Envbox,
    /// None.
    None,
    /// Exectrace.
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
    /// Start.
    Start,
    /// Stop.
    Stop,
    /// Delete.
    Delete,
}

/// Health status of a workspace application.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "workspace_app_health", rename_all = "snake_case")]
pub enum WorkspaceAppHealth {
    /// Disabled.
    Disabled,
    /// Initializing.
    Initializing,
    /// Healthy.
    Healthy,
    /// Unhealthy.
    Unhealthy,
}

/// Where a workspace application opens.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[sqlx(type_name = "workspace_app_open_in")]
pub enum WorkspaceAppOpenIn {
    /// Tab.
    #[serde(rename = "tab")]
    #[sqlx(rename = "tab")]
    Tab,
    /// Window.
    #[serde(rename = "window")]
    #[sqlx(rename = "window")]
    Window,
    /// SlimWindow.
    #[serde(rename = "slim-window")]
    #[sqlx(rename = "slim-window")]
    SlimWindow,
}

/// Status state of a workspace application.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "workspace_app_status_state", rename_all = "snake_case")]
pub enum WorkspaceAppStatusState {
    /// Working.
    Working,
    /// Complete.
    Complete,
    /// Failure.
    Failure,
    /// Idle.
    Idle,
}

/// Automatic update policy for a workspace.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "automatic_updates", rename_all = "snake_case")]
pub enum AutomaticUpdates {
    /// Always.
    Always,
    /// Never.
    Never,
}

/// Application sharing level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "app_sharing_level", rename_all = "snake_case")]
pub enum AppSharingLevel {
    /// Owner.
    Owner,
    /// Authenticated.
    Authenticated,
    /// Organization.
    Organization,
    /// Public.
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
    /// Echo.
    Echo,
    /// Terraform.
    Terraform,
}

/// Storage method used by a provisioner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "provisioner_storage_method", rename_all = "snake_case")]
pub enum ProvisionerStorageMethod {
    /// File.
    File,
}

/// Type of a provisioner job.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "provisioner_job_type", rename_all = "snake_case")]
pub enum ProvisionerJobType {
    /// TemplateVersionImport.
    TemplateVersionImport,
    /// WorkspaceBuild.
    WorkspaceBuild,
    /// TemplateVersionDryRun.
    TemplateVersionDryRun,
}

/// Computed status of a provisioner job.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "provisioner_job_status", rename_all = "snake_case")]
pub enum ProvisionerJobStatus {
    /// Pending.
    Pending,
    /// Running.
    Running,
    /// Succeeded.
    Succeeded,
    /// Canceling.
    Canceling,
    /// Canceled.
    Canceled,
    /// Failed.
    Failed,
    /// Unknown.
    Unknown,
}

/// Stage within a provisioner job timing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "provisioner_job_timing_stage", rename_all = "snake_case")]
pub enum ProvisionerJobTimingStage {
    /// Init.
    Init,
    /// Plan.
    Plan,
    /// Graph.
    Graph,
    /// Apply.
    Apply,
}

/// Status of a provisioner daemon.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "provisioner_daemon_status", rename_all = "snake_case")]
pub enum ProvisionerDaemonStatus {
    /// Offline.
    Offline,
    /// Idle.
    Idle,
    /// Busy.
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
    /// Initiator.
    Initiator,
    /// Autostart.
    Autostart,
    /// Autostop.
    Autostop,
    /// Dormancy.
    Dormancy,
    /// Failedstop.
    Failedstop,
    /// Autodelete.
    Autodelete,
    /// Dashboard.
    Dashboard,
    /// Cli.
    Cli,
    /// SshConnection.
    SshConnection,
    /// VscodeConnection.
    VscodeConnection,
    /// JetbrainsConnection.
    JetbrainsConnection,
    /// TaskAutoPause.
    TaskAutoPause,
    /// TaskManualPause.
    TaskManualPause,
    /// TaskResume.
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
    /// All.
    All,
    /// NoUserData.
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
    /// Pending.
    Pending,
    /// Leased.
    Leased,
    /// Sent.
    Sent,
    /// PermanentFailure.
    PermanentFailure,
    /// TemporaryFailure.
    TemporaryFailure,
    /// Unknown.
    Unknown,
    /// Inhibited.
    Inhibited,
}

/// Delivery method for a notification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "notification_method", rename_all = "snake_case")]
pub enum NotificationMethod {
    /// Smtp.
    Smtp,
    /// Webhook.
    Webhook,
    /// Inbox.
    Inbox,
}

/// Kind of a notification template.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "notification_template_kind", rename_all = "snake_case")]
pub enum NotificationTemplateKind {
    /// System.
    System,
    /// Custom.
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
    /// All.
    All,
    /// Unread.
    Unread,
    /// Read.
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
    /// None.
    None,
    /// EnvironmentVariable.
    EnvironmentVariable,
    /// ProvisionerVariable.
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
    /// Error.
    #[serde(rename = "error")]
    #[sqlx(rename = "error")]
    Error,
    /// Radio.
    #[serde(rename = "radio")]
    #[sqlx(rename = "radio")]
    Radio,
    /// Dropdown.
    #[serde(rename = "dropdown")]
    #[sqlx(rename = "dropdown")]
    Dropdown,
    /// Input.
    #[serde(rename = "input")]
    #[sqlx(rename = "input")]
    Input,
    /// Textarea.
    #[serde(rename = "textarea")]
    #[sqlx(rename = "textarea")]
    Textarea,
    /// Slider.
    #[serde(rename = "slider")]
    #[sqlx(rename = "slider")]
    Slider,
    /// Checkbox.
    #[serde(rename = "checkbox")]
    #[sqlx(rename = "checkbox")]
    Checkbox,
    /// Switch.
    #[serde(rename = "switch")]
    #[sqlx(rename = "switch")]
    Switch,
    /// TagSelect.
    #[serde(rename = "tag-select")]
    #[sqlx(rename = "tag-select")]
    TagSelect,
    /// MultiSelect.
    #[serde(rename = "multi-select")]
    #[sqlx(rename = "multi-select")]
    MultiSelect,
}

/// Scope of a parameter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "parameter_scope", rename_all = "snake_case")]
pub enum ParameterScope {
    /// Template.
    Template,
    /// ImportJob.
    ImportJob,
    /// Workspace.
    Workspace,
}

/// Source scheme for a parameter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "parameter_source_scheme", rename_all = "snake_case")]
pub enum ParameterSourceScheme {
    /// None.
    None,
    /// Data.
    Data,
}

/// Type system for a parameter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "parameter_type_system", rename_all = "snake_case")]
pub enum ParameterTypeSystem {
    /// None.
    None,
    /// Hcl.
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
    /// User.
    User,
    /// Model.
    Model,
    /// Both.
    Both,
}

/// Status of a chat session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "chat_status", rename_all = "snake_case")]
pub enum ChatStatus {
    /// Waiting.
    Waiting,
    /// Pending.
    Pending,
    /// Running.
    Running,
    /// Paused.
    Paused,
    /// Completed.
    Completed,
    /// Error.
    Error,
}

/// Status of an AI task.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "task_status", rename_all = "snake_case")]
pub enum TaskStatus {
    /// Pending.
    Pending,
    /// Initializing.
    Initializing,
    /// Active.
    Active,
    /// Paused.
    Paused,
    /// Unknown.
    Unknown,
    /// Error.
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
    /// Vscode.
    Vscode,
    /// VscodeInsiders.
    VscodeInsiders,
    /// WebTerminal.
    WebTerminal,
    /// SshHelper.
    SshHelper,
    /// PortForwardingHelper.
    PortForwardingHelper,
}

/// Log severity level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "log_level", rename_all = "snake_case")]
pub enum LogLevel {
    /// Trace.
    Trace,
    /// Debug.
    Debug,
    /// Info.
    Info,
    /// Warn.
    Warn,
    /// Error.
    Error,
}

/// Source of a provisioner log line.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "log_source", rename_all = "snake_case")]
pub enum LogSource {
    /// ProvisionerDaemon.
    ProvisionerDaemon,
    /// Provisioner.
    Provisioner,
}

/// Startup script behavior.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[sqlx(type_name = "startup_script_behavior")]
pub enum StartupScriptBehavior {
    /// Blocking.
    #[serde(rename = "blocking")]
    #[sqlx(rename = "blocking")]
    Blocking,
    /// NonBlocking.
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
    /// Connected.
    Connected,
    /// Disconnected.
    Disconnected,
}

/// Type of workspace connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "connection_type", rename_all = "snake_case")]
pub enum ConnectionType {
    /// Ssh.
    Ssh,
    /// Vscode.
    Vscode,
    /// Jetbrains.
    Jetbrains,
    /// ReconnectingPty.
    ReconnectingPty,
    /// WorkspaceApp.
    WorkspaceApp,
    /// PortForwarding.
    PortForwarding,
}

/// CORS behavior for a workspace application.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "cors_behavior", rename_all = "snake_case")]
pub enum CorsBehavior {
    /// Simple.
    Simple,
    /// Passthru.
    Passthru,
}

/// Tailnet connection status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "tailnet_status", rename_all = "snake_case")]
pub enum TailnetStatus {
    /// Ok.
    Ok,
    /// Lost.
    Lost,
}

/// Protocol for a shared port.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "port_share_protocol", rename_all = "snake_case")]
pub enum PortShareProtocol {
    /// Http.
    Http,
    /// Https.
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
    /// User.
    User,
    /// Oidc.
    Oidc,
}

/// Status of a prebuild.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "prebuild_status", rename_all = "snake_case")]
pub enum PrebuildStatus {
    /// Healthy.
    Healthy,
    /// HardLimited.
    HardLimited,
    /// ValidationFailed.
    ValidationFailed,
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

// The canonical `AuditAction` enum with `sqlx::Type` lives in
// `coder_audit::AuditAction`.  It is the single source of truth for the
// PostgreSQL `audit_action` type and is used by `AuditEvent` and
// `PersistingAuditSink`.  Do **not** duplicate it here.

/// Resource type matching the PostgreSQL `resource_type` enum.
///
/// This is the **database-mapped** version that corresponds 1-to-1 with the
/// `resource_type` PostgreSQL enum.  Use this type when reading/writing
/// `resource_type` columns via `sqlx`.
///
/// See also `coder_rbac::ResourceKind`, which extends this set with
/// Rust-only variants (`Authentication`, `ExternalAuth`) used in the
/// authorization layer.  `ResourceKind` intentionally does **not** derive
/// `sqlx::Type` because those extra variants have no database counterpart.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "resource_type", rename_all = "snake_case")]
pub enum ResourceType {
    /// Organization.
    Organization,
    /// Template.
    Template,
    /// TemplateVersion.
    TemplateVersion,
    /// User.
    User,
    /// Workspace.
    Workspace,
    /// GitSshKey.
    GitSshKey,
    /// ApiKey.
    ApiKey,
    /// Group.
    Group,
    /// WorkspaceBuild.
    WorkspaceBuild,
    /// License.
    License,
    /// WorkspaceProxy.
    WorkspaceProxy,
    /// ConvertLogin.
    ConvertLogin,
    /// HealthSettings.
    HealthSettings,
    /// Oauth2ProviderApp.
    Oauth2ProviderApp,
    /// Oauth2ProviderAppSecret.
    Oauth2ProviderAppSecret,
    /// CustomRole.
    CustomRole,
    /// OrganizationMember.
    OrganizationMember,
    /// NotificationsSettings.
    NotificationsSettings,
    /// NotificationTemplate.
    NotificationTemplate,
    /// IdpSyncSettingsOrganization.
    IdpSyncSettingsOrganization,
    /// IdpSyncSettingsGroup.
    IdpSyncSettingsGroup,
    /// IdpSyncSettingsRole.
    IdpSyncSettingsRole,
    /// WorkspaceAgent.
    WorkspaceAgent,
    /// WorkspaceApp.
    WorkspaceApp,
    /// PrebuildsSettings.
    PrebuildsSettings,
    /// Task.
    Task,
}

// ---------------------------------------------------------------------------
// Crypto
// ---------------------------------------------------------------------------

/// Feature a crypto key is used for.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Deserialize, serde::Serialize, sqlx::Type,
)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "crypto_key_feature", rename_all = "snake_case")]
pub enum CryptoKeyFeature {
    /// WorkspaceAppsToken.
    WorkspaceAppsToken,
    /// WorkspaceAppsApiKey.
    WorkspaceAppsApiKey,
    /// OidcConvert.
    OidcConvert,
    /// TailnetResume.
    TailnetResume,
}

impl CryptoKeyFeature {
    /// Returns the snake_case string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::WorkspaceAppsToken => "workspace_apps_token",
            Self::WorkspaceAppsApiKey => "workspace_apps_api_key",
            Self::OidcConvert => "oidc_convert",
            Self::TailnetResume => "tailnet_resume",
        }
    }
}

impl std::str::FromStr for CryptoKeyFeature {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "workspace_apps_token" => Ok(Self::WorkspaceAppsToken),
            "workspace_apps_api_key" => Ok(Self::WorkspaceAppsApiKey),
            "oidc_convert" => Ok(Self::OidcConvert),
            "tailnet_resume" => Ok(Self::TailnetResume),
            _ => Err(format!("unknown crypto key feature: {s}")),
        }
    }
}
