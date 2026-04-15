//! HTTP-facing models shared across the Rust service crates.

use std::{collections::HashMap, fmt, time::Duration};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::circuit_breaker::CircuitBreakerStatus;
use crate::config::PublicDeploymentConfig;
use crate::identity::{
    ApiKeyRecord, AuthenticatedUser, LoginType, OrganizationMemberRecord, OrganizationRecord,
    SlimRoleRecord, UserRecord, UserStatus,
};

/// A generic API response body.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct ApiResponse {
    /// A user-facing summary of the outcome.
    pub message: String,
    /// Optional detail for debugging and operational diagnostics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Field-scoped validation failures.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub validations: Vec<ValidationError>,
}

impl ApiResponse {
    /// Builds a successful response with no extra detail.
    #[must_use]
    pub fn ok(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            detail: None,
            validations: Vec::new(),
        }
    }

    /// Builds an error response with an explicit detail message.
    #[must_use]
    pub fn error(message: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            detail: Some(detail.into()),
            validations: Vec::new(),
        }
    }
}

/// A field-scoped validation error.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ValidationError {
    /// The field that failed validation.
    pub field: String,
    /// The validation message for the field.
    pub detail: String,
}

/// Build metadata surfaced through `/api/v2/buildinfo`.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct BuildInfoResponse {
    /// Canonical link for the running build.
    pub external_url: String,
    /// Semantic version for the running build.
    pub version: String,
    /// Dashboard URL for this deployment.
    pub dashboard_url: String,
    /// Whether telemetry is enabled.
    pub telemetry: bool,
    /// Whether this process is acting as a workspace proxy.
    pub workspace_proxy: bool,
    /// Current agent API version exposed by this deployment.
    pub agent_api_version: String,
    /// Current provisioner API version exposed by this deployment.
    pub provisioner_api_version: String,
    /// Upgrade guidance for mismatched clients.
    pub upgrade_message: String,
    /// Stable deployment identifier.
    pub deployment_id: String,
    /// Web Push public key (VAPID), omitted when not configured.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub webpush_public_key: String,
}

/// Update-check information surfaced through `/api/v2/updatecheck`.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct UpdateCheckResponse {
    /// Whether the running version is current.
    pub current: bool,
    /// Latest available semantic version.
    pub version: String,
    /// URL for the latest release.
    pub url: String,
}

/// SSH deployment settings surfaced through `/api/v2/deployment/ssh`.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct SshConfigResponse {
    /// Deprecated hostname prefix kept for compatibility with the original API.
    pub hostname_prefix: String,
    /// Hostname suffix used for workspace SSH hostnames.
    pub hostname_suffix: String,
    /// Extra SSH config directives the client should write.
    ///
    /// Serialized as a JSON object to match Go's `map[string]string`.
    pub ssh_config_options: HashMap<String, String>,
}

/// Deployment configuration surfaced through `/api/v2/deployment/config`.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct DeploymentConfigResponse {
    /// Redacted runtime configuration.
    pub config: PublicDeploymentConfig,
    /// Supported flags and environment variables for this Rust slice.
    pub options: Vec<ConfigOption>,
}

/// A single supported configuration option.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ConfigOption {
    /// Canonical flag name.
    pub name: &'static str,
    /// Matching environment variable.
    pub env: &'static str,
    /// Default value, if one exists.
    pub default: Option<&'static str>,
    /// Human-readable description.
    pub description: &'static str,
}

/// Available low-level API key scopes.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct ExternalApiKeyScopes {
    /// Requestable external scopes.
    pub external: Vec<String>,
}

/// Safe experiments exposed by the deployment.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct AvailableExperiments {
    /// Safe experiments suitable for general use.
    pub safe: Vec<String>,
}

/// Workspace connection latency percentiles.
#[derive(Clone, Debug, Default, Serialize, PartialEq)]
pub struct WorkspaceConnectionLatencyMs {
    /// p50 latency in milliseconds.
    pub p50: f64,
    /// p95 latency in milliseconds.
    pub p95: f64,
}

/// Workspace-related deployment counters.
#[derive(Clone, Debug, Default, Serialize, PartialEq)]
pub struct WorkspaceDeploymentStatsResponse {
    /// Pending workspaces.
    pub pending: i64,
    /// Building workspaces.
    pub building: i64,
    /// Running workspaces.
    pub running: i64,
    /// Failed workspaces.
    pub failed: i64,
    /// Stopped workspaces.
    pub stopped: i64,
    /// Connection latency metrics.
    pub connection_latency_ms: WorkspaceConnectionLatencyMs,
    /// Received bytes.
    pub rx_bytes: i64,
    /// Transmitted bytes.
    pub tx_bytes: i64,
}

/// Session counters grouped by client type.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct SessionCountDeploymentStatsResponse {
    /// Active VS Code sessions.
    pub vscode: i64,
    /// Active SSH sessions.
    pub ssh: i64,
    /// Active JetBrains sessions.
    pub jetbrains: i64,
    /// Active reconnecting PTY sessions.
    pub reconnecting_pty: i64,
}

/// Deployment statistics payload.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct DeploymentStatsResponse {
    /// Start of the aggregation window.
    #[serde(with = "time::serde::rfc3339")]
    pub aggregated_from: OffsetDateTime,
    /// Time at which the metrics were collected.
    #[serde(with = "time::serde::rfc3339")]
    pub collected_at: OffsetDateTime,
    /// Scheduled time for the next update.
    #[serde(with = "time::serde::rfc3339")]
    pub next_update_at: OffsetDateTime,
    /// Workspace counters.
    pub workspaces: WorkspaceDeploymentStatsResponse,
    /// Session counters.
    pub session_count: SessionCountDeploymentStatsResponse,
}

/// A recent user build parameter.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct UserParameter {
    /// Parameter name.
    pub name: String,
    /// Parameter value.
    pub value: String,
}

/// Static external auth provider metadata.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ExternalAuthLinkProvider {
    /// Provider identifier.
    pub id: String,
    /// Provider type.
    #[serde(rename = "type")]
    pub provider_type: String,
    /// Whether device auth is supported.
    pub device: bool,
    /// Human-readable provider name.
    pub display_name: String,
    /// Icon URL or identifier.
    pub display_icon: String,
    /// Whether refresh is allowed.
    pub allow_refresh: bool,
    /// Whether refresh is disabled even when a refresh token exists.
    #[serde(default, skip_serializing)]
    pub no_refresh: bool,
    /// Whether validation is allowed.
    pub allow_validate: bool,
    /// Whether token revocation is supported.
    pub supports_revocation: bool,
    /// Supported PKCE challenge methods.
    pub code_challenge_methods_supported: Vec<String>,
    /// Provider authorization endpoint used by runtime callback flows.
    #[serde(default, skip_serializing)]
    pub authorize_url: String,
    /// Provider token endpoint used by runtime callback and device flows.
    #[serde(default, skip_serializing)]
    pub token_url: String,
    /// Provider device-authorization endpoint used by device flows.
    #[serde(default, skip_serializing)]
    pub device_authorization_url: String,
    /// Provider token validation endpoint.
    #[serde(default, skip_serializing)]
    pub validate_url: String,
    /// Provider token revocation endpoint.
    #[serde(default, skip_serializing)]
    pub revoke_url: String,
    /// Provider user-info endpoint.
    #[serde(default, skip_serializing)]
    pub user_url: String,
    /// Provider app-installations endpoint.
    #[serde(default, skip_serializing)]
    pub app_installations_url: String,
    /// Provider-side installation URL.
    #[serde(default, skip_serializing)]
    pub app_install_url: String,
    /// OAuth2 client identifier.
    #[serde(default, skip_serializing)]
    pub client_id: String,
    /// OAuth2 client secret.
    #[serde(default, skip_serializing)]
    pub client_secret: String,
    /// Callback URL registered with the provider.
    #[serde(default, skip_serializing)]
    pub callback_url: String,
    /// OAuth2 scopes requested during callback and device exchanges.
    #[serde(default, skip_serializing)]
    pub scopes: Vec<String>,
}

/// Stored external auth link summary.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ExternalAuthLink {
    /// Provider identifier.
    pub provider_id: String,
    /// Link creation time.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Link update time.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    /// Whether the link includes a refresh token.
    pub has_refresh_token: bool,
    /// Access token expiry time.
    #[serde(with = "time::serde::rfc3339")]
    pub expires: OffsetDateTime,
    /// Whether the provider currently validates the token.
    pub authenticated: bool,
    /// Validation error text.
    pub validate_error: String,
}

/// External auth account identity.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ExternalAuthUser {
    /// Stable provider-side account identifier.
    pub id: i64,
    /// Account login name.
    pub login: String,
    /// Avatar URL.
    pub avatar_url: String,
    /// Profile URL.
    pub profile_url: String,
    /// Display name.
    pub name: String,
}

/// Application installation visible through external auth.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ExternalAuthAppInstallation {
    /// Stable installation identifier.
    pub id: i32,
    /// Owning account.
    pub account: ExternalAuthUser,
    /// Provider-side configure URL.
    pub configure_url: String,
}

/// External auth provider state for the current user.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ExternalAuthResponse {
    /// Whether the user is currently authenticated with the provider.
    pub authenticated: bool,
    /// Whether device flow is supported.
    pub device: bool,
    /// Human-readable provider name.
    pub display_name: String,
    /// Whether token revocation is supported.
    pub supports_revocation: bool,
    /// Authenticated account details when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<ExternalAuthUser>,
    /// Whether the provider supports app installations.
    pub app_installable: bool,
    /// Visible installations for the account.
    pub installations: Vec<ExternalAuthAppInstallation>,
    /// Provider-side installation URL.
    pub app_install_url: String,
}

/// Device-flow authorization payload.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ExternalAuthDevice {
    /// Device code issued by the provider.
    pub device_code: String,
    /// User code shown to the user.
    pub user_code: String,
    /// Verification URL.
    pub verification_uri: String,
    /// Expiry in seconds.
    pub expires_in: i32,
    /// Poll interval in seconds.
    pub interval: i32,
}

/// Request payload for `POST /api/v2/external-auth/{externalauth}/device`.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ExternalAuthDeviceExchangeRequest {
    /// Device code previously returned by the provider.
    pub device_code: String,
}

/// External auth list response.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ListUserExternalAuthResponse {
    /// Configured providers.
    pub providers: Vec<ExternalAuthLinkProvider>,
    /// Existing authenticated links for the current user.
    pub links: Vec<ExternalAuthLink>,
}

/// External auth unlink response.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct DeleteExternalAuthByIdResponse {
    /// Whether provider-side token revocation succeeded.
    pub token_revoked: bool,
    /// Optional revocation error details.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub token_revocation_error: String,
}

/// Public git SSH key payload.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct GitSshKeyResponse {
    /// Owning user identifier.
    pub user_id: Uuid,
    /// Key creation time.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Key update time.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    /// Public key in OpenSSH format.
    pub public_key: String,
}

/// Audit resource types returned by the operational audit API.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditResourceType {
    /// A user record.
    #[default]
    User,
    /// An API key or session token.
    ApiKey,
    /// A Git SSH keypair.
    GitSshKey,
    /// Deployment health settings.
    HealthSettings,
    /// An organization.
    Organization,
    /// An organization member.
    OrganizationMember,
    /// A login conversion operation.
    ConvertLogin,
}

impl AuditResourceType {
    /// Returns the canonical wire-format string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::ApiKey => "api_key",
            Self::GitSshKey => "git_ssh_key",
            Self::HealthSettings => "health_settings",
            Self::Organization => "organization",
            Self::OrganizationMember => "organization_member",
            Self::ConvertLogin => "convert_login",
        }
    }
}

/// Audit actions returned by the operational audit API.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditLogAction {
    /// A resource was created.
    Create,
    /// A resource was updated.
    #[default]
    Write,
    /// A resource was deleted.
    Delete,
    /// A process started.
    Start,
    /// A process stopped.
    Stop,
    /// A user authenticated.
    Login,
    /// A user logged out.
    Logout,
    /// A user registered.
    Register,
    /// A password-reset flow was requested.
    RequestPasswordReset,
}

impl AuditLogAction {
    /// Returns the canonical wire-format string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Write => "write",
            Self::Delete => "delete",
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Login => "login",
            Self::Logout => "logout",
            Self::Register => "register",
            Self::RequestPasswordReset => "request_password_reset",
        }
    }
}

/// One changed field in an audit diff.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct AuditDiffField {
    /// Previous value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old: Option<Value>,
    /// New value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new: Option<Value>,
    /// Whether the field contains secret material.
    #[serde(default)]
    pub secret: bool,
}

/// Structured audit diff keyed by field name.
pub type AuditDiff = HashMap<String, AuditDiffField>;

/// Minimal organization reference embedded in audit events.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct MinimalOrganization {
    /// Stable organization identifier.
    pub id: Uuid,
    /// Canonical organization name.
    pub name: String,
    /// Human-readable display name.
    pub display_name: String,
    /// Icon URL or path.
    pub icon: String,
}

/// One audit event returned by `GET /api/v2/audit`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct AuditLog {
    /// Stable audit event identifier.
    pub id: Uuid,
    /// Request identifier when one exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<Uuid>,
    /// Event timestamp.
    #[serde(with = "time::serde::rfc3339")]
    pub time: OffsetDateTime,
    /// Client IP address when known.
    pub ip: String,
    /// Client user agent when known.
    pub user_agent: String,
    /// Audited resource type.
    pub resource_type: AuditResourceType,
    /// Audited resource identifier when one exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<Uuid>,
    /// Human-readable target name or slug.
    pub resource_target: String,
    /// Optional resource icon.
    pub resource_icon: String,
    /// Audit action.
    pub action: AuditLogAction,
    /// Structured diff when the resource changed.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub diff: AuditDiff,
    /// HTTP status code associated with the action.
    pub status_code: i32,
    /// Extra structured fields.
    #[serde(default, skip_serializing_if = "value_is_null_or_empty_object")]
    pub additional_fields: Value,
    /// Human-readable summary of the action.
    pub description: String,
    /// Optional resource deep link.
    pub resource_link: String,
    /// Whether the target resource was deleted.
    pub is_deleted: bool,
    /// Deprecated organization identifier retained for compatibility.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<Uuid>,
    /// Expanded organization metadata when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<MinimalOrganization>,
    /// User responsible for the action when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<MinimalUser>,
}

/// Audit log listing response.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct AuditLogResponse {
    /// Returned audit events.
    pub audit_logs: Vec<AuditLog>,
    /// Total number of matching events.
    pub count: usize,
}

// ── Connection log types ─────────────────────────────────────────────────

/// The type of connection that an agent is receiving.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum ConnectionType {
    /// SSH connection.
    #[serde(rename = "ssh")]
    Ssh,
    /// VS Code connection.
    #[serde(rename = "vscode")]
    VsCode,
    /// JetBrains IDE connection.
    #[serde(rename = "jetbrains")]
    JetBrains,
    /// Reconnecting PTY session.
    #[serde(rename = "reconnecting_pty")]
    ReconnectingPty,
    /// Workspace application connection.
    #[serde(rename = "workspace_app")]
    WorkspaceApp,
    /// Port forwarding connection.
    #[serde(rename = "port_forwarding")]
    PortForwarding,
}

impl ConnectionType {
    /// Returns the canonical wire-format string for this connection type.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ssh => "ssh",
            Self::VsCode => "vscode",
            Self::JetBrains => "jetbrains",
            Self::ReconnectingPty => "reconnecting_pty",
            Self::WorkspaceApp => "workspace_app",
            Self::PortForwarding => "port_forwarding",
        }
    }
}

impl fmt::Display for ConnectionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Web-specific metadata for workspace_app and port_forwarding connections.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct ConnectionLogWebInfo {
    /// The user agent string of the HTTP request.
    pub user_agent: String,
    /// The user who initiated the connection, if authenticated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<MinimalUser>,
    /// The app slug or port number.
    pub slug_or_port: String,
    /// HTTP status code of the request.
    pub status_code: i32,
}

/// SSH-specific metadata for ssh, vscode, jetbrains, and reconnecting_pty connections.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct ConnectionLogSSHInfo {
    /// Unique connection identifier linking connect/disconnect events.
    pub connection_id: Uuid,
    /// When the connection was closed, if known.
    #[serde(
        with = "time::serde::rfc3339::option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub disconnect_time: Option<OffsetDateTime>,
    /// Reason for disconnection, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disconnect_reason: Option<String>,
    /// Exit code of the SSH session, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
}

/// One connection log entry returned by `GET /api/v2/connectionlog`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct ConnectionLog {
    /// Stable connection log identifier.
    pub id: Uuid,
    /// When the connection was established.
    #[serde(with = "time::serde::rfc3339")]
    pub connect_time: OffsetDateTime,
    /// Organization the workspace belongs to.
    pub organization: MinimalOrganization,
    /// Owner of the workspace.
    pub workspace_owner_id: Uuid,
    /// Username of the workspace owner.
    pub workspace_owner_username: String,
    /// Workspace identifier.
    pub workspace_id: Uuid,
    /// Workspace name.
    pub workspace_name: String,
    /// Agent name inside the workspace.
    pub agent_name: String,
    /// Client IP address, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// Type of connection.
    #[serde(rename = "type")]
    pub connection_type: ConnectionType,
    /// Web-specific info (workspace_app / port_forwarding only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub web_info: Option<ConnectionLogWebInfo>,
    /// SSH-specific info (ssh / vscode / jetbrains / reconnecting_pty only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_info: Option<ConnectionLogSSHInfo>,
}

/// Response for `GET /api/v2/connectionlog`.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct ConnectionLogResponse {
    /// Returned connection log entries.
    pub connection_logs: Vec<ConnectionLog>,
    /// Total number of matching entries.
    pub count: i64,
}

/// Request payload for `POST /api/v2/audit/testgenerate`.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct CreateTestAuditLogRequest {
    /// Requested audit action.
    #[serde(default)]
    pub action: AuditLogAction,
    /// Requested audit resource type.
    #[serde(default)]
    pub resource_type: AuditResourceType,
    /// Optional audited resource identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<Uuid>,
    /// Optional extra structured fields.
    #[serde(default, skip_serializing_if = "value_is_null_or_empty_object")]
    pub additional_fields: Value,
    /// Event time override.
    #[serde(
        with = "time::serde::rfc3339::option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub time: Option<OffsetDateTime>,
    /// Optional build reason, retained inside `additional_fields`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_reason: Option<String>,
    /// Optional organization scope for the event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<Uuid>,
    /// Optional request identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<Uuid>,
}

/// Deployment health severity.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HealthSeverity {
    /// Fully healthy.
    #[default]
    Ok,
    /// Healthy enough to operate but requires attention.
    Warning,
    /// Broken or unavailable.
    Error,
}

/// Reusable base fields for health report sections.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct BaseHealthReport {
    /// Error summary when the section is unhealthy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Current section severity.
    pub severity: HealthSeverity,
    /// Human-readable warnings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// Whether the section is dismissed in the UI.
    #[serde(default)]
    pub dismissed: bool,
}

/// Access URL health section.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct AccessUrlHealthReport {
    /// Shared health metadata.
    #[serde(flatten)]
    pub base: BaseHealthReport,
    /// Deprecated compatibility flag.
    pub healthy: bool,
    /// Advertised access URL.
    pub access_url: String,
    /// Whether the service is reachable.
    pub reachable: bool,
    /// HTTP status returned by `/healthz`.
    pub status_code: i32,
    /// Response body from `/healthz`.
    pub healthz_response: String,
}

/// Database health section.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct DatabaseHealthReport {
    /// Shared health metadata.
    #[serde(flatten)]
    pub base: BaseHealthReport,
    /// Deprecated compatibility flag.
    pub healthy: bool,
    /// Whether the database is reachable.
    pub reachable: bool,
    /// Human-readable latency string.
    pub latency: String,
    /// Measured latency in milliseconds.
    pub latency_ms: i64,
    /// Threshold used for warnings.
    pub threshold_ms: i64,
}

/// Websocket health section.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct WebsocketHealthReport {
    /// Deprecated compatibility flag.
    pub healthy: bool,
    /// Shared health metadata.
    #[serde(flatten)]
    pub base: BaseHealthReport,
    /// Response body from the test endpoint.
    pub body: String,
    /// Response code from the test endpoint.
    pub code: i32,
}

/// DERP health section.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct DerpHealthReport {
    /// Shared health metadata.
    #[serde(flatten)]
    pub base: BaseHealthReport,
    /// Deprecated compatibility flag.
    pub healthy: bool,
    /// Region summaries. Empty in the current Rust slice.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub regions: HashMap<String, String>,
    /// Netcheck logs captured during the health run.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub netcheck_logs: Vec<String>,
}

/// Workspace proxy health section.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct WorkspaceProxyHealthReport {
    /// Shared health metadata.
    #[serde(flatten)]
    pub base: BaseHealthReport,
    /// Deprecated compatibility flag.
    pub healthy: bool,
    /// Proxy items. Empty in the current Rust slice.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub items: Vec<String>,
}

/// Provisioner daemon health section.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ProvisionerDaemonsHealthReport {
    /// Shared health metadata.
    #[serde(flatten)]
    pub base: BaseHealthReport,
    /// Connected daemon summaries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub items: Vec<String>,
}

/// Complete deployment health report.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct HealthcheckReport {
    /// Time at which the report was generated.
    #[serde(with = "time::serde::rfc3339")]
    pub time: OffsetDateTime,
    /// Deprecated compatibility flag.
    pub healthy: bool,
    /// Top-level deployment severity.
    pub severity: HealthSeverity,
    /// DERP health details.
    pub derp: DerpHealthReport,
    /// Access URL health details.
    pub access_url: AccessUrlHealthReport,
    /// Websocket health details.
    pub websocket: WebsocketHealthReport,
    /// Database health details.
    pub database: DatabaseHealthReport,
    /// Workspace proxy health details.
    pub workspace_proxy: WorkspaceProxyHealthReport,
    /// Provisioner daemon health details.
    pub provisioner_daemons: ProvisionerDaemonsHealthReport,
    /// Version string for the running backend.
    pub coder_version: String,
    /// Per-dependency circuit breaker statuses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub circuit_breakers: Vec<CircuitBreakerStatus>,
}

/// Persisted deployment health UI settings.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct HealthSettings {
    /// Dismissed healthcheck sections.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dismissed_healthchecks: Vec<String>,
}

/// Request payload for `POST /api/v2/users/first`.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CreateFirstUserRequest {
    /// Login email for the first user.
    pub email: String,
    /// Username for the first user.
    pub username: String,
    /// Display name for the first user.
    #[serde(default)]
    pub name: String,
    /// Plain-text password for the first user.
    pub password: String,
}

/// Response payload for `POST /api/v2/users/first`.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct CreateFirstUserResponse {
    /// Identifier of the newly created user.
    pub user_id: Uuid,
    /// Identifier of the organization the new user joined.
    pub organization_id: Uuid,
}

/// Request payload for `POST /api/v2/users/login`.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct LoginWithPasswordRequest {
    /// Login email.
    pub email: String,
    /// Plain-text password.
    pub password: String,
}

/// Response payload for `POST /api/v2/users/login`.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct LoginWithPasswordResponse {
    /// Opaque session token to send in `Coder-Session-Token`.
    pub session_token: String,
}

/// User authentication capabilities advertised by the deployment.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct AuthMethods {
    /// Terms of service URL when configured.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub terms_of_service_url: String,
    /// Password authentication settings.
    pub password: AuthMethod,
    /// GitHub authentication settings.
    pub github: GithubAuthMethod,
    /// OIDC authentication settings.
    pub oidc: OidcAuthMethod,
}

/// Basic enabled/disabled auth method.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct AuthMethod {
    /// Whether the auth method is enabled.
    pub enabled: bool,
}

/// GitHub auth settings.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct GithubAuthMethod {
    /// Whether GitHub auth is enabled.
    pub enabled: bool,
    /// Whether the default provider is configured.
    pub default_provider_configured: bool,
}

/// OIDC auth settings.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct OidcAuthMethod {
    /// Shared enabled flag.
    #[serde(flatten)]
    pub auth_method: AuthMethod,
    /// Custom sign-in button text.
    #[serde(rename = "signInText", default)]
    pub sign_in_text: String,
    /// Custom icon URL.
    #[serde(rename = "iconUrl", default)]
    pub icon_url: String,
}

/// Minimal user identity data.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct MinimalUser {
    /// Stable user identifier.
    pub id: Uuid,
    /// Login username.
    pub username: String,
    /// Human-readable display name.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    /// Avatar URL when configured.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub avatar_url: String,
}

/// Minimal role shape used by the current user and member APIs.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct SlimRole {
    /// Stable role name.
    pub name: String,
    /// Human-readable display name.
    pub display_name: String,
    /// Organization-scoped role identifier when applicable.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub organization_id: String,
}

/// Shared reduced user representation.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ReducedUser {
    /// Minimal identity fields.
    #[serde(flatten)]
    pub minimal: MinimalUser,
    /// Login email.
    pub email: String,
    /// User creation time.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// User update time.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    /// Most recent activity time when known.
    #[serde(
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub last_seen_at: Option<OffsetDateTime>,
    /// Current user status.
    pub status: UserStatus,
    /// Login type for the account.
    #[serde(serialize_with = "serialize_login_type")]
    pub login_type: &'static str,
    /// Deprecated theme preference placeholder.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub theme_preference: String,
}

/// Full user representation used by the current Rust slice.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct UserResponse {
    /// Reduced user fields.
    #[serde(flatten)]
    pub reduced: ReducedUser,
    /// Organization memberships for the user.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub organization_ids: Vec<Uuid>,
    /// Site-wide roles for the user.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<SlimRole>,
}

impl From<AuthenticatedUser> for UserResponse {
    fn from(value: AuthenticatedUser) -> Self {
        Self {
            reduced: ReducedUser {
                minimal: MinimalUser {
                    id: value.id,
                    username: value.username,
                    name: value.name,
                    avatar_url: value.avatar_url,
                },
                email: value.email,
                created_at: value.created_at,
                updated_at: value.updated_at,
                last_seen_at: value.last_seen_at,
                status: value.status,
                login_type: value.login_type.as_str(),
                theme_preference: String::new(),
            },
            organization_ids: value.organization_ids,
            roles: value.roles.into_iter().map(SlimRole::from).collect(),
        }
    }
}

impl From<UserRecord> for UserResponse {
    fn from(value: UserRecord) -> Self {
        Self {
            reduced: ReducedUser {
                minimal: MinimalUser {
                    id: value.id,
                    username: value.username,
                    name: value.name,
                    avatar_url: value.avatar_url,
                },
                email: value.email,
                created_at: value.created_at,
                updated_at: value.updated_at,
                last_seen_at: value.last_seen_at,
                status: value.status,
                login_type: value.login_type.as_str(),
                theme_preference: String::new(),
            },
            organization_ids: value.organization_ids,
            roles: value.roles.into_iter().map(SlimRole::from).collect(),
        }
    }
}

/// Paginated user listing response.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct GetUsersResponse {
    /// Returned user page.
    pub users: Vec<UserResponse>,
    /// Total number of matching users.
    pub count: usize,
}

/// Request payload for `POST /api/v2/users`.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CreateUserRequestWithOrgs {
    /// Login email.
    pub email: String,
    /// Login username.
    pub username: String,
    /// Display name.
    #[serde(default)]
    pub name: String,
    /// Optional password for password-backed accounts.
    #[serde(default)]
    pub password: String,
    /// Login type for the new account.
    #[serde(default)]
    pub login_type: Option<LoginType>,
    /// Initial user status.
    #[serde(default)]
    pub user_status: Option<UserStatus>,
    /// Organizations to join on creation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub organization_ids: Vec<Uuid>,
}

/// Organization shape returned by the current Rust slice.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct OrganizationResponse {
    /// Stable organization identifier.
    pub id: Uuid,
    /// Canonical organization name.
    pub name: String,
    /// Human-readable organization display name.
    pub display_name: String,
    /// Organization description.
    pub description: String,
    /// Icon URL or path.
    pub icon: String,
    /// Organization creation time.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Organization update time.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    /// Whether this is the deployment default organization.
    pub is_default: bool,
}

impl From<OrganizationRecord> for OrganizationResponse {
    fn from(value: OrganizationRecord) -> Self {
        Self {
            id: value.id,
            name: value.name,
            display_name: value.display_name,
            description: value.description,
            icon: value.icon,
            created_at: value.created_at,
            updated_at: value.updated_at,
            is_default: value.is_default,
        }
    }
}

/// Request payload for `POST /api/v2/organizations`.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CreateOrganizationRequest {
    /// Canonical organization name.
    pub name: String,
    /// Human-readable display name.
    #[serde(default)]
    pub display_name: String,
    /// Description.
    #[serde(default)]
    pub description: String,
    /// Icon URL or relative path.
    #[serde(default)]
    pub icon: String,
}

/// Request payload for `PATCH /api/v2/organizations/{organization}`.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct UpdateOrganizationRequest {
    /// Updated organization name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Updated display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Updated description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Updated icon URL or relative path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
}

/// Request payload for creating or updating a custom role.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct CustomRoleRequest {
    /// Unique role name (slug).
    pub name: String,
    /// Human-readable display name.
    pub display_name: String,
    /// Site-wide permissions granted by this role.
    #[serde(default)]
    pub site_permissions: Vec<Permission>,
    /// Organization-scoped permissions granted by this role.
    #[serde(default)]
    pub organization_permissions: Vec<Permission>,
    /// User-scoped permissions granted by this role.
    #[serde(default)]
    pub user_permissions: Vec<Permission>,
}

/// A single permission entry in a custom role.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Permission {
    /// The resource type this permission applies to.
    pub resource_type: String,
    /// The action this permission grants or denies.
    pub action: String,
    /// Whether this permission is negated.
    #[serde(default)]
    pub negate: bool,
}

/// Organization membership without embedded user data.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct OrganizationMember {
    /// Member user identifier.
    pub user_id: Uuid,
    /// Organization identifier.
    pub organization_id: Uuid,
    /// Membership creation time.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Membership update time.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    /// Organization-scoped roles.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<SlimRole>,
}

impl From<OrganizationMemberRecord> for OrganizationMember {
    fn from(value: OrganizationMemberRecord) -> Self {
        Self {
            user_id: value.user_id,
            organization_id: value.organization_id,
            created_at: value.created_at,
            updated_at: value.updated_at,
            roles: value.roles.into_iter().map(SlimRole::from).collect(),
        }
    }
}

/// Organization membership with embedded user data.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct OrganizationMemberWithUserData {
    /// Member username.
    pub username: String,
    /// Member display name.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    /// Member avatar URL.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub avatar_url: String,
    /// Member email.
    pub email: String,
    /// Member site-wide roles.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub global_roles: Vec<SlimRole>,
    /// Membership fields.
    #[serde(flatten)]
    pub membership: OrganizationMember,
}

impl From<OrganizationMemberRecord> for OrganizationMemberWithUserData {
    fn from(value: OrganizationMemberRecord) -> Self {
        Self {
            username: value.username,
            name: value.name,
            avatar_url: value.avatar_url,
            email: value.email,
            global_roles: value.global_roles.into_iter().map(SlimRole::from).collect(),
            membership: OrganizationMember {
                user_id: value.user_id,
                organization_id: value.organization_id,
                created_at: value.created_at,
                updated_at: value.updated_at,
                roles: value.roles.into_iter().map(SlimRole::from).collect(),
            },
        }
    }
}

/// Paginated organization member listing response.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct PaginatedMembersResponse {
    /// Returned member page.
    pub members: Vec<OrganizationMemberWithUserData>,
    /// Total number of matching members.
    pub count: usize,
}

/// Request payload used by site and organization role update routes.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct UpdateRolesRequest {
    /// Target role identifiers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
}

/// Site plus organization role assignments for a user.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct UserRolesResponse {
    /// Site-wide role identifiers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    /// Organization-scoped role identifiers keyed by organization ID.
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub organization_roles: HashMap<Uuid, Vec<String>>,
}

/// Request payload for `PUT /api/v2/users/{user}/profile`.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct UpdateUserProfileRequest {
    /// Updated username.
    pub username: String,
    /// Updated display name.
    #[serde(default)]
    pub name: String,
}

/// Request payload for `POST /api/v2/users/validate-password`.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ValidateUserPasswordRequest {
    /// Password to validate.
    pub password: String,
}

/// Password validation response.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct ValidateUserPasswordResponse {
    /// Whether the password is valid.
    pub valid: bool,
    /// Validation details when invalid.
    #[serde(default)]
    pub details: String,
}

/// User appearance settings payload.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct UserAppearanceSettings {
    /// Selected theme preference.
    #[serde(default)]
    pub theme_preference: String,
    /// Selected terminal font.
    #[serde(default)]
    pub terminal_font: String,
}

/// Request payload for `PUT /api/v2/users/{user}/appearance`.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct UpdateUserAppearanceSettingsRequest {
    /// Updated theme preference.
    #[serde(default)]
    pub theme_preference: String,
    /// Updated terminal font.
    #[serde(default)]
    pub terminal_font: String,
}

/// User preference settings payload.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct UserPreferenceSettings {
    /// Whether the task notification alert has been dismissed.
    pub task_notification_alert_dismissed: bool,
}

/// Request payload for `PUT /api/v2/users/{user}/preferences`.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct UpdateUserPreferenceSettingsRequest {
    /// Updated dismissal flag.
    pub task_notification_alert_dismissed: bool,
}

/// Request payload for `PUT /api/v2/users/{user}/password`.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct UpdateUserPasswordRequest {
    /// Current password when a user is changing their own password.
    #[serde(default)]
    pub old_password: String,
    /// Replacement password.
    pub password: String,
}

/// Request payload for `POST /api/v2/users/otp/request`.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct RequestOneTimePasscodeRequest {
    /// Email tied to the account.
    pub email: String,
}

/// Request payload for `POST /api/v2/users/otp/change-password`.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ChangePasswordWithOneTimePasscodeRequest {
    /// Email tied to the account.
    pub email: String,
    /// Replacement password.
    pub password: String,
    /// One-time passcode sent to the user.
    pub one_time_passcode: String,
}

/// Request payload for `POST /api/v2/users/{user}/convert-login`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ConvertLoginRequest {
    /// Requested target login type.
    pub to_type: LoginType,
    /// Current password used to authorize the conversion.
    pub password: String,
}

/// OAuth conversion handoff response.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct OAuthConversionResponse {
    /// Provider state string for the browser redirect flow.
    pub state_string: String,
    /// Expiry for the state string.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// Requested target login type.
    pub to_type: LoginType,
    /// Target user identifier.
    pub user_id: Uuid,
}

/// Response payload for `GET /api/v2/users/{user}/login-type`.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub struct UserLoginType {
    /// Login type for the account.
    pub login_type: LoginType,
}

/// Role details surfaced by assignable-role routes.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct RoleResponse {
    /// Canonical role identifier.
    pub name: String,
    /// Organization scope for organization roles.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub organization_id: String,
    /// Human-readable role label.
    pub display_name: String,
    /// Site permission entries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub site_permissions: Vec<PermissionResponse>,
    /// User permission entries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub user_permissions: Vec<PermissionResponse>,
    /// Organization permission entries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub organization_permissions: Vec<PermissionResponse>,
    /// Organization-member permission entries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub organization_member_permissions: Vec<PermissionResponse>,
}

/// Permission placeholder used by the current role responses.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct PermissionResponse {
    /// Whether this permission is negated.
    pub negate: bool,
    /// Resource type name.
    pub resource_type: String,
    /// Action identifier.
    pub action: String,
}

/// Assignable role response shape.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct AssignableRoleResponse {
    /// Flattened role details.
    #[serde(flatten)]
    pub role: RoleResponse,
    /// Whether the authenticated actor may assign the role.
    pub assignable: bool,
    /// Whether the role is built in.
    pub built_in: bool,
}

/// Request payload for `POST /api/v2/users/{user}/keys/tokens`.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CreateTokenRequest {
    /// Requested token lifetime encoded as Go-compatible duration nanoseconds.
    #[serde(
        default,
        deserialize_with = "deserialize_duration_nanos",
        serialize_with = "serialize_duration_nanos"
    )]
    pub lifetime: Duration,
    /// Legacy single-scope field.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub scope: String,
    /// Multi-scope field.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    /// Human-readable token name.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub token_name: String,
    /// Optional allow-list restrictions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_list: Vec<ApiAllowListTarget>,
}

/// Response payload containing a newly minted API key secret.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct GenerateApiKeyResponse {
    /// Raw API key secret.
    pub key: String,
}

/// API allow-list target encoded as `<type>:<id>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiAllowListTarget {
    /// Resource kind.
    pub type_name: String,
    /// Resource identifier or `*`.
    pub id: String,
}

impl Serialize for ApiAllowListTarget {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{}:{}", self.type_name, self.id))
    }
}

impl<'de> Deserialize<'de> for ApiAllowListTarget {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let (type_name, id) = encoded
            .split_once(':')
            .ok_or_else(|| D::Error::custom("allow-list entries must be encoded as <type>:<id>"))?;

        if type_name.is_empty() || id.is_empty() {
            return Err(D::Error::custom(
                "allow-list entries must be encoded as <type>:<id>",
            ));
        }

        Ok(Self {
            type_name: type_name.to_owned(),
            id: id.to_owned(),
        })
    }
}

/// Public API key representation.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ApiKeyResponse {
    /// Stable API key identifier.
    pub id: String,
    /// Owning user identifier.
    pub user_id: Uuid,
    /// Last observed use.
    #[serde(with = "time::serde::rfc3339")]
    pub last_used: OffsetDateTime,
    /// Expiry time.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// Creation time.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Update time.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    /// Login type tied to the key.
    #[serde(serialize_with = "serialize_login_type")]
    pub login_type: &'static str,
    /// Deprecated single-scope field.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub scope: String,
    /// Full scope list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    /// Human-readable token name.
    pub token_name: String,
    /// Lifetime in seconds.
    pub lifetime_seconds: i64,
    /// Allow-list restrictions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_list: Vec<ApiAllowListTarget>,
}

impl From<ApiKeyRecord> for ApiKeyResponse {
    fn from(value: ApiKeyRecord) -> Self {
        let scope = value.scopes.first().cloned().unwrap_or_default();
        Self {
            id: value.id,
            user_id: value.user_id,
            last_used: value.last_used,
            expires_at: value.expires_at,
            created_at: value.created_at,
            updated_at: value.updated_at,
            login_type: value.login_type.as_str(),
            scope,
            scopes: value.scopes,
            token_name: value.token_name,
            lifetime_seconds: value.lifetime_seconds,
            allow_list: value.allow_list,
        }
    }
}

/// Token listing representation with owner username included.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ApiKeyWithOwnerResponse {
    /// API key payload.
    #[serde(flatten)]
    pub api_key: ApiKeyResponse,
    /// Owner username.
    pub username: String,
}

/// Token configuration limits.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct TokenConfig {
    /// Maximum allowed token lifetime, encoded in Go-compatible duration nanoseconds.
    #[serde(serialize_with = "serialize_duration_nanos")]
    pub max_token_lifetime: Duration,
}

impl From<SlimRoleRecord> for SlimRole {
    fn from(value: SlimRoleRecord) -> Self {
        Self {
            name: value.name,
            display_name: value.display_name,
            organization_id: value
                .organization_id
                .map(|value| value.to_string())
                .unwrap_or_default(),
        }
    }
}

/// Response returned by `POST /api/v2/files` after uploading a file.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct UploadFileResponse {
    /// The file identifier (returned as "hash" for Go SDK compatibility).
    #[serde(rename = "hash")]
    pub id: Uuid,
}

// ---------------------------------------------------------------------------
// License & Entitlements API types
// ---------------------------------------------------------------------------

/// Request body for `POST /api/v2/licenses`.
#[derive(Clone, Debug, Deserialize)]
pub struct AddLicenseRequest {
    /// Raw JWT license string.
    pub license: String,
}

/// Response for a single license record.
#[derive(Clone, Debug, Serialize)]
pub struct LicenseResponse {
    /// Numeric license identifier.
    pub id: i32,
    /// Unique license UUID.
    pub uuid: Uuid,
    /// When the license was uploaded (RFC 3339).
    #[serde(with = "time::serde::rfc3339")]
    pub uploaded_at: OffsetDateTime,
    /// Parsed claims as a JSON value.
    pub claims: Value,
}

// ---------------------------------------------------------------------------
// OAuth2 Provider API types
// ---------------------------------------------------------------------------

/// Response for a registered OAuth2 provider application.
#[derive(Clone, Debug, Serialize)]
pub struct OAuth2ProviderAppResponse {
    /// Application identifier.
    pub id: String,
    /// Application name.
    pub name: String,
    /// Application icon URL.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub icon: String,
    /// Primary callback URL.
    pub callback_url: String,
    /// Redirect URIs.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub redirect_uris: Vec<String>,
    /// Endpoints for the OAuth2 flow.
    pub endpoints: OAuth2ProviderAppEndpoints,
}

/// Endpoints for an OAuth2 provider application.
#[derive(Clone, Debug, Serialize)]
pub struct OAuth2ProviderAppEndpoints {
    /// Authorization endpoint.
    pub authorization: String,
    /// Token endpoint.
    pub token: String,
    /// Device authorization endpoint.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub device_authorization: String,
}

/// Request to create or update an OAuth2 provider application.
#[derive(Clone, Debug, Deserialize)]
pub struct PostOAuth2ProviderAppRequest {
    /// Application name.
    pub name: String,
    /// Application icon URL.
    #[serde(default)]
    pub icon: String,
    /// Primary callback URL.
    pub callback_url: String,
}

/// Request to update an existing OAuth2 provider application.
#[derive(Clone, Debug, Deserialize)]
pub struct PutOAuth2ProviderAppRequest {
    /// Updated application name.
    pub name: String,
    /// Updated icon URL.
    #[serde(default)]
    pub icon: String,
    /// Updated callback URL.
    pub callback_url: String,
}

/// Response for an OAuth2 provider app secret.
#[derive(Clone, Debug, Serialize)]
pub struct OAuth2ProviderAppSecretResponse {
    /// Secret identifier.
    pub id: String,
    /// Last few characters of the secret for display.
    pub last_used_at: Option<String>,
    /// Truncated secret for display.
    pub client_secret_truncated: String,
}

/// Full secret response returned only on creation.
#[derive(Clone, Debug, Serialize)]
pub struct OAuth2ProviderAppSecretFullResponse {
    /// Secret identifier.
    pub id: String,
    /// Full client secret (only shown once).
    pub client_secret_full: String,
    /// Truncated secret for display.
    pub client_secret_truncated: String,
}

/// OAuth2 authorization request parameters.
#[derive(Clone, Debug, Deserialize)]
pub struct OAuth2AuthorizeRequest {
    /// Response type (must be "code").
    pub response_type: String,
    /// Client (app) identifier.
    pub client_id: String,
    /// Redirect URI.
    #[serde(default)]
    pub redirect_uri: String,
    /// State parameter for CSRF protection.
    #[serde(default)]
    pub state: String,
    /// Requested scopes.
    #[serde(default)]
    pub scope: String,
    /// PKCE code challenge.
    #[serde(default)]
    pub code_challenge: String,
    /// PKCE code challenge method.
    #[serde(default)]
    pub code_challenge_method: String,
    /// Resource URI.
    #[serde(default)]
    pub resource: String,
}

/// OAuth2 token request parameters.
#[derive(Clone, Debug, Deserialize)]
pub struct OAuth2TokenRequest {
    /// Grant type (authorization_code or refresh_token).
    pub grant_type: String,
    /// Authorization code (for authorization_code grant).
    #[serde(default)]
    pub code: String,
    /// Redirect URI (must match the authorize request).
    #[serde(default)]
    pub redirect_uri: String,
    /// Client identifier.
    #[serde(default)]
    pub client_id: String,
    /// Client secret.
    #[serde(default)]
    pub client_secret: String,
    /// PKCE code verifier.
    #[serde(default)]
    pub code_verifier: String,
    /// Refresh token (for refresh_token grant).
    #[serde(default)]
    pub refresh_token: String,
    /// Resource URI.
    #[serde(default)]
    pub resource: String,
}

/// OAuth2 token response.
#[derive(Clone, Debug, Serialize)]
pub struct OAuth2TokenResponse {
    /// Access token.
    pub access_token: String,
    /// Token type (always "Bearer").
    pub token_type: String,
    /// Token lifetime in seconds.
    pub expires_in: i64,
    /// Refresh token.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub refresh_token: String,
}

// ---------------------------------------------------------------------------
// OAuth2 RFC Compliance API types
// ---------------------------------------------------------------------------

/// RFC 8414 OAuth 2.0 Authorization Server Metadata.
#[derive(Clone, Debug, Serialize)]
pub struct OAuth2AuthorizationServerMetadata {
    /// Authorization server issuer identifier.
    pub issuer: String,
    /// URL of the authorization endpoint.
    pub authorization_endpoint: String,
    /// URL of the token endpoint.
    pub token_endpoint: String,
    /// URL of the dynamic client registration endpoint (RFC 7591).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub registration_endpoint: String,
    /// URL of the token revocation endpoint (RFC 7009).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub revocation_endpoint: String,
    /// Supported response types.
    pub response_types_supported: Vec<String>,
    /// Supported grant types.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub grant_types_supported: Vec<String>,
    /// Supported PKCE code challenge methods.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub code_challenge_methods_supported: Vec<String>,
    /// Supported scopes.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub scopes_supported: Vec<String>,
    /// Supported token endpoint auth methods.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub token_endpoint_auth_methods_supported: Vec<String>,
}

/// RFC 9728 OAuth 2.0 Protected Resource Metadata.
#[derive(Clone, Debug, Serialize)]
pub struct OAuth2ProtectedResourceMetadata {
    /// Protected resource identifier.
    pub resource: String,
    /// Authorization servers that protect this resource.
    pub authorization_servers: Vec<String>,
    /// Supported scopes.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub scopes_supported: Vec<String>,
    /// Supported bearer methods.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub bearer_methods_supported: Vec<String>,
}

/// RFC 7591 Dynamic Client Registration Request.
#[derive(Clone, Debug, Deserialize, Default)]
pub struct OAuth2ClientRegistrationRequest {
    /// Redirect URIs.
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    /// Human-readable client name.
    #[serde(default)]
    pub client_name: String,
    /// Client home page URI.
    #[serde(default)]
    pub client_uri: String,
    /// Client logo URI.
    #[serde(default)]
    pub logo_uri: String,
    /// Terms of service URI.
    #[serde(default)]
    pub tos_uri: String,
    /// Privacy policy URI.
    #[serde(default)]
    pub policy_uri: String,
    /// JWKS URI for client authentication.
    #[serde(default)]
    pub jwks_uri: String,
    /// JWKS inline for client authentication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks: Option<Value>,
    /// Software identifier.
    #[serde(default)]
    pub software_id: String,
    /// Software version.
    #[serde(default)]
    pub software_version: String,
    /// Requested grant types.
    #[serde(default)]
    pub grant_types: Vec<String>,
    /// Requested response types.
    #[serde(default)]
    pub response_types: Vec<String>,
    /// Token endpoint auth method.
    #[serde(default)]
    pub token_endpoint_auth_method: String,
    /// Requested scope (space-delimited).
    #[serde(default)]
    pub scope: String,
    /// Contact emails.
    #[serde(default)]
    pub contacts: Vec<String>,
}

impl OAuth2ClientRegistrationRequest {
    /// Apply RFC 7591 defaults for missing fields.
    ///
    /// **Ordering note:** This method sets `client_name` to a default when
    /// empty, which means a subsequent call to `generate_client_name()` will
    /// see a non-empty name and skip the URI-derived fallback logic. This
    /// matches Go's `ApplyDefaults()` → `GenerateClientName()` ordering, where
    /// the same behavior occurs intentionally.
    pub fn apply_defaults(mut self) -> Self {
        if self.grant_types.is_empty() {
            self.grant_types = vec!["authorization_code".to_owned(), "refresh_token".to_owned()];
        }
        if self.response_types.is_empty() {
            self.response_types = vec!["code".to_owned()];
        }
        if self.token_endpoint_auth_method.is_empty() {
            self.token_endpoint_auth_method = "client_secret_basic".to_owned();
        }
        if self.client_name.is_empty() {
            self.client_name = "Dynamically Registered Client".to_owned();
        }
        self
    }

    /// Validate the registration request.
    pub fn validate(&self) -> Result<(), String> {
        if self.redirect_uris.is_empty() {
            return Err("redirect_uris is required".to_owned());
        }
        for uri in &self.redirect_uris {
            if url::Url::parse(uri).is_err() {
                return Err(format!("invalid redirect_uri: {uri}"));
            }
        }
        Ok(())
    }

    /// Generate a client name, falling back to URI-derived names.
    pub fn generate_client_name(&self) -> String {
        use sha2::Digest as _;
        if !self.client_name.is_empty() {
            if self.client_name.len() > 64 {
                let hash = format!("{:x}", sha2::Sha256::digest(self.client_name.as_bytes()));
                let hash_prefix = &hash[..8];
                let max_prefix = 64 - 1 - hash_prefix.len();
                let prefix: String = self
                    .client_name
                    .char_indices()
                    .take_while(|&(i, c)| i + c.len_utf8() <= max_prefix)
                    .map(|(_, c)| c)
                    .collect();
                return format!("{prefix}-{hash_prefix}");
            }
            return self.client_name.clone();
        }
        if !self.client_uri.is_empty() {
            if let Ok(uri) = url::Url::parse(&self.client_uri) {
                if let Some(host) = uri.host_str() {
                    return truncate_name_to_64(&format!("Client ({host})"));
                }
            }
        }
        if let Some(first_uri) = self.redirect_uris.first() {
            if let Ok(uri) = url::Url::parse(first_uri) {
                if let Some(host) = uri.host_str() {
                    return truncate_name_to_64(&format!("Client ({host})"));
                }
            }
        }
        "Dynamically Registered Client".to_owned()
    }
}

/// Truncate a name to at most 64 characters, respecting UTF-8 char boundaries.
fn truncate_name_to_64(name: &str) -> String {
    if name.len() <= 64 {
        return name.to_owned();
    }
    name.char_indices()
        .take_while(|&(i, c)| i + c.len_utf8() <= 64)
        .map(|(_, c)| c)
        .collect()
}

/// RFC 7591 Dynamic Client Registration Response.
#[derive(Clone, Debug, Serialize)]
pub struct OAuth2ClientRegistrationResponse {
    /// Unique client identifier.
    pub client_id: String,
    /// Client secret (only returned on creation).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub client_secret: String,
    /// Timestamp when client_id was issued (Unix seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id_issued_at: Option<i64>,
    /// Timestamp when client_secret expires (0 = no expiration).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret_expires_at: Option<i64>,
    /// Registered redirect URIs.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub redirect_uris: Vec<String>,
    /// Client name.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub client_name: String,
    /// Client URI.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub client_uri: String,
    /// Logo URI.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub logo_uri: String,
    /// Terms of service URI.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub tos_uri: String,
    /// Policy URI.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub policy_uri: String,
    /// Grant types.
    pub grant_types: Vec<String>,
    /// Response types.
    pub response_types: Vec<String>,
    /// Token endpoint auth method.
    pub token_endpoint_auth_method: String,
    /// Scope.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub scope: String,
    /// Contacts.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub contacts: Vec<String>,
    /// Registration access token for RFC 7592 management.
    pub registration_access_token: String,
    /// Registration client URI for RFC 7592 management.
    pub registration_client_uri: String,
}

/// RFC 7592 Client Configuration (read response).
#[derive(Clone, Debug, Serialize)]
pub struct OAuth2ClientConfiguration {
    /// Client identifier.
    pub client_id: String,
    /// Timestamp when client_id was issued (Unix seconds).
    pub client_id_issued_at: i64,
    /// Timestamp when client_secret expires (0 = no expiration).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret_expires_at: Option<i64>,
    /// Registered redirect URIs.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub redirect_uris: Vec<String>,
    /// Client name.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub client_name: String,
    /// Client URI.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub client_uri: String,
    /// Logo URI.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub logo_uri: String,
    /// Terms of service URI.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub tos_uri: String,
    /// Policy URI.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub policy_uri: String,
    /// Grant types.
    pub grant_types: Vec<String>,
    /// Response types.
    pub response_types: Vec<String>,
    /// Token endpoint auth method.
    pub token_endpoint_auth_method: String,
    /// Scope.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub scope: String,
    /// Contacts.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub contacts: Vec<String>,
    /// Registration access token (empty in GET responses for security).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub registration_access_token: String,
    /// Registration client URI.
    pub registration_client_uri: String,
}

/// OAuth2 error response per RFC 6749.
#[derive(Clone, Debug, Serialize)]
pub struct OAuth2ErrorResponse {
    /// Error code.
    pub error: String,
    /// Human-readable error description.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error_description: String,
}

/// OAuth2 token revocation request per RFC 7009.
#[derive(Clone, Debug, Deserialize)]
pub struct OAuth2TokenRevocationRequest {
    /// The token to revoke.
    #[serde(default)]
    pub token: String,
    /// Hint about the token type.
    #[serde(default)]
    pub token_type_hint: String,
    /// Client identifier.
    #[serde(default)]
    pub client_id: String,
    /// Client secret.
    #[serde(default)]
    pub client_secret: String,
}

// ---------------------------------------------------------------------------
// User Identity Supplement API types
// ---------------------------------------------------------------------------

/// Response for a user link.
#[derive(Clone, Debug, Serialize)]
pub struct UserLinkResponse {
    /// Owning user identifier.
    pub user_id: String,
    /// Login type of the linked provider.
    pub login_type: String,
    /// Whether the link has a valid token.
    pub has_valid_token: bool,
}

/// Response for a user configuration entry.
#[derive(Clone, Debug, Serialize)]
pub struct UserConfigResponse {
    /// Configuration key.
    pub key: String,
    /// Configuration value.
    pub value: String,
}

/// Request to set a user configuration entry.
#[derive(Clone, Debug, Deserialize)]
pub struct PutUserConfigRequest {
    /// Configuration value.
    pub value: String,
}

// ---------------------------------------------------------------------------
// Quiet Hours
// ---------------------------------------------------------------------------

/// Response for a user's quiet hours schedule.
#[derive(Clone, Debug, Serialize)]
pub struct UserQuietHoursScheduleResponse {
    /// Raw cron schedule string, e.g. `CRON_TZ=America/Chicago 0 0 * * *`.
    pub raw_schedule: String,
    /// Whether the user explicitly set this schedule.
    pub user_set: bool,
    /// Whether the deployment allows users to set their own schedule.
    pub user_can_set: bool,
    /// Human-readable time string, e.g. `"00:00"`.
    pub time: String,
    /// IANA timezone name, e.g. `"America/Chicago"`.
    pub timezone: String,
    /// Next quiet hours window start time (UTC).
    #[serde(with = "time::serde::rfc3339")]
    pub next: OffsetDateTime,
}

/// Request to update a user's quiet hours schedule.
#[derive(Clone, Debug, Deserialize)]
pub struct UpdateUserQuietHoursScheduleRequest {
    /// Cron schedule string with timezone, e.g. `CRON_TZ=America/Chicago 0 0 * * *`.
    pub schedule: String,
}

// ---------------------------------------------------------------------------
// Replicas
// ---------------------------------------------------------------------------

/// A running Coder replica instance.
#[derive(Clone, Debug, Serialize)]
pub struct Replica {
    /// Unique identifier of this replica.
    pub id: Uuid,
    /// Hostname of the replica.
    pub hostname: String,
    /// When the replica was registered.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Relay address used for DERP traffic.
    pub relay_address: String,
    /// DERP region identifier for this replica.
    pub region_id: i32,
    /// Error message if the replica is unhealthy (empty string if healthy).
    pub error: String,
    /// Database latency in nanoseconds.
    pub database_latency: i64,
}

// ---------------------------------------------------------------------------
// Workspace Quota
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Workspace Sharing Settings
// ---------------------------------------------------------------------------

/// Organization-level workspace sharing settings.
#[derive(Clone, Debug, Serialize)]
pub struct WorkspaceSharingSettings {
    /// Whether workspace sharing is globally disabled at the deployment level.
    pub sharing_globally_disabled: bool,
    /// Whether workspace sharing is disabled for this organization.
    pub sharing_disabled: bool,
    /// Who can share workspaces: `"none"`, `"everyone"`, or `"service_accounts"`.
    pub shareable_workspace_owners: String,
}

/// Request to update workspace sharing settings for an organization.
#[derive(Clone, Debug, Deserialize)]
pub struct UpdateWorkspaceSharingSettingsRequest {
    /// Whether workspace sharing should be disabled.
    pub sharing_disabled: Option<bool>,
    /// Who can share workspaces: `"none"`, `"everyone"`, or `"service_accounts"`.
    pub shareable_workspace_owners: Option<String>,
}

/// Response for a group.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct GroupResponse {
    /// Group identifier.
    pub id: String,
    /// Group name.
    pub name: String,
    /// Group display name.
    pub display_name: String,
    /// Owning organization identifier.
    pub organization_id: String,
    /// Avatar URL.
    pub avatar_url: String,
    /// Quota allowance.
    pub quota_allowance: i32,
    /// Source of creation.
    pub source: String,
    /// Member list (may be empty if caller lacks read-member permission).
    pub members: Vec<ReducedUser>,
    /// Total member count (may differ from `members.len()` due to permissions).
    pub total_member_count: i32,
    /// Organization name.
    pub organization_name: String,
    /// Organization display name.
    pub organization_display_name: String,
}

/// Request to create a group.
#[derive(Clone, Debug, Deserialize)]
pub struct CreateGroupRequest {
    /// Group name.
    pub name: String,
    /// Group display name.
    #[serde(default)]
    pub display_name: String,
    /// Avatar URL.
    #[serde(default)]
    pub avatar_url: String,
    /// Quota allowance.
    #[serde(default)]
    pub quota_allowance: i32,
}

/// Request to update a group.
#[derive(Clone, Debug, Deserialize)]
pub struct PatchGroupRequest {
    /// Updated name.
    #[serde(default)]
    pub name: Option<String>,
    /// Updated display name.
    #[serde(default)]
    pub display_name: Option<String>,
    /// Updated avatar URL.
    #[serde(default)]
    pub avatar_url: Option<String>,
    /// Updated quota allowance.
    #[serde(default)]
    pub quota_allowance: Option<i32>,
    /// User IDs to add to the group.
    #[serde(default)]
    pub add_users: Vec<String>,
    /// User IDs to remove from the group.
    #[serde(default)]
    pub remove_users: Vec<String>,
}

/// Response for a custom role.
#[derive(Clone, Debug, Serialize)]
pub struct CustomRoleResponse {
    /// Role name.
    pub name: String,
    /// Display name.
    pub display_name: String,
    /// Organization identifier (if org-scoped).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
}

fn serialize_login_type<S>(value: &&'static str, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(value)
}

fn serialize_duration_nanos<S>(value: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let nanos = i64::try_from(value.as_nanos()).map_err(serde::ser::Error::custom)?;
    serializer.serialize_i64(nanos)
}

fn deserialize_duration_nanos<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    let nanos = i64::deserialize(deserializer)?;
    if nanos < 0 {
        return Err(D::Error::custom("duration must be non-negative"));
    }

    let nanos = u64::try_from(nanos).map_err(D::Error::custom)?;
    Ok(Duration::from_nanos(nanos))
}

/// Response for `GET /api/v2/applications/host`.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct AppHostResponse {
    /// Wildcard hostname for workspace applications.
    pub host: String,
}

/// Provisioner daemon response matching `codersdk.ProvisionerDaemon`.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ProvisionerDaemonResponse {
    /// Stable daemon identifier.
    pub id: Uuid,
    /// Organization that owns the daemon.
    pub organization_id: Uuid,
    /// When the daemon was created.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When the daemon was last seen.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub last_seen_at: Option<OffsetDateTime>,
    /// Daemon name.
    pub name: String,
    /// Daemon version.
    pub version: String,
    /// API version supported.
    pub api_version: String,
    /// Provisioner types supported.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provisioners: Vec<String>,
    /// Tags associated with the daemon.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub tags: HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// Provisioner keys domain
// ---------------------------------------------------------------------------

/// Reserved provisioner key UUID for the built-in key.
pub const PROVISIONER_KEY_ID_BUILT_IN: &str = "00000000-0000-0000-0000-000000000001";
/// Reserved provisioner key UUID for user-auth key.
pub const PROVISIONER_KEY_ID_USER_AUTH: &str = "00000000-0000-0000-0000-000000000002";
/// Reserved provisioner key UUID for PSK key.
pub const PROVISIONER_KEY_ID_PSK: &str = "00000000-0000-0000-0000-000000000003";

/// Reserved provisioner key names that cannot be created or deleted.
pub const RESERVED_PROVISIONER_KEY_NAMES: &[&str] = &["built-in", "user-auth", "psk"];

/// Request body for creating a provisioner key.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct CreateProvisionerKeyRequest {
    /// Human-readable name for the key.
    pub name: String,
    /// Free-form tags associated with this key.
    #[serde(default)]
    pub tags: HashMap<String, String>,
}

/// Response returned after creating a provisioner key (contains the raw token).
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct CreateProvisionerKeyResponse {
    /// The raw provisioner key token. Only returned on creation.
    pub key: String,
}

/// API response representing a provisioner key (never includes the secret).
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ProvisionerKeyResponse {
    /// Key identifier.
    pub id: Uuid,
    /// Creation time.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Organization that owns this key.
    #[serde(rename = "organization")]
    pub organization_id: Uuid,
    /// Human-readable name.
    pub name: String,
    /// Free-form tags.
    pub tags: HashMap<String, String>,
}

/// A provisioner key with its associated daemons.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ProvisionerKeyDaemonsResponse {
    /// The provisioner key.
    pub key: ProvisionerKeyResponse,
    /// Daemons authenticated with this key.
    pub daemons: Vec<ProvisionerDaemonResponse>,
}

// ---------------------------------------------------------------------------
// Notifications domain
// ---------------------------------------------------------------------------

/// Global notification dispatch settings.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NotificationsSettings {
    /// Notifier paused.
    #[serde(default)]
    pub notifier_paused: bool,
}

/// A single notification template row.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotificationTemplate {
    /// Id.
    pub id: Uuid,
    /// Name.
    pub name: String,
    /// Title template.
    pub title_template: String,
    /// Body template.
    pub body_template: String,
    /// Actions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actions: Option<Value>,
    /// Group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Method.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// Kind.
    pub kind: String,
    /// Enabled by default.
    pub enabled_by_default: bool,
}

/// Response listing available and default dispatch methods.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotificationMethodsResponse {
    /// Available.
    pub available: Vec<String>,
    /// Default.
    pub default: String,
}

/// A single per-user notification preference.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotificationPreference {
    /// Id.
    pub id: Uuid,
    /// Disabled.
    pub disabled: bool,
    /// Updated at.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// Request body for PUT notification template method.
#[derive(Clone, Debug, Deserialize)]
pub struct UpdateNotificationTemplateMethod {
    /// Method.
    #[serde(default)]
    pub method: Option<String>,
}

/// Request body for PUT user notification preferences.
#[derive(Clone, Debug, Deserialize)]
pub struct UpdateUserNotificationPreferences {
    /// Template disabled map.
    pub template_disabled_map: HashMap<String, bool>,
}

/// A web push subscription registration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebpushSubscription {
    /// Endpoint.
    pub endpoint: String,
    /// Auth key.
    pub auth_key: String,
    /// P256dh key.
    pub p256dh_key: String,
}

/// Request body for DELETE web push subscription.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeleteWebpushSubscription {
    /// Endpoint.
    pub endpoint: String,
}

/// An action button inside a web push notification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebpushMessageAction {
    /// Display label for the action button.
    pub label: String,
    /// URL to navigate to when the action is activated.
    pub url: String,
}

/// Payload for a web push notification sent to the browser.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebpushMessage {
    /// Icon URL for the notification.
    #[serde(default)]
    pub icon: String,
    /// Title text of the notification.
    #[serde(default)]
    pub title: String,
    /// Body text of the notification.
    #[serde(default)]
    pub body: String,
    /// Notification tag for grouping or replacing.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tag: String,
    /// Action buttons shown with the notification.
    #[serde(default)]
    pub actions: Vec<WebpushMessageAction>,
    /// Arbitrary key-value data attached to the notification.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub data: HashMap<String, String>,
}

/// Stored VAPID key pair for web push.
#[derive(Clone, Debug)]
pub struct VapidKeyPair {
    /// Base64url-encoded public key.
    pub public_key: String,
    /// PEM-encoded EC private key (SEC1 format).
    pub private_key: String,
}

/// An action inside an inbox notification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InboxNotificationAction {
    /// Label.
    pub label: String,
    /// Url.
    pub url: String,
}

/// A single inbox notification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InboxNotification {
    /// Id.
    pub id: Uuid,
    /// User id.
    pub user_id: Uuid,
    /// Template id.
    pub template_id: Uuid,
    /// Targets.
    pub targets: Vec<Uuid>,
    /// Title.
    pub title: String,
    /// Content.
    pub content: String,
    /// Icon.
    pub icon: String,
    /// Actions.
    pub actions: Vec<InboxNotificationAction>,
    /// Read at.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub read_at: Option<OffsetDateTime>,
    /// Created at.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// Response for listing inbox notifications.
#[derive(Clone, Debug, Serialize)]
pub struct ListInboxNotificationsResponse {
    /// Notifications.
    pub notifications: Vec<InboxNotification>,
    /// Unread count.
    pub unread_count: i64,
}

/// Request body for updating inbox notification read status.
#[derive(Clone, Debug, Deserialize)]
pub struct UpdateInboxNotificationReadStatusRequest {
    /// Is read.
    pub is_read: bool,
}

/// Response for updating inbox notification read status.
#[derive(Clone, Debug, Serialize)]
pub struct UpdateInboxNotificationReadStatusResponse {
    /// Notification.
    pub notification: InboxNotification,
    /// Unread count.
    pub unread_count: i64,
}

/// Response for the watch endpoint (single notification + unread count).
#[derive(Clone, Debug, Serialize)]
pub struct GetInboxNotificationResponse {
    /// Notification.
    pub notification: InboxNotification,
    /// Unread count.
    pub unread_count: i64,
}

fn value_is_null_or_empty_object(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Object(object) => object.is_empty(),
        _ => false,
    }
}

impl fmt::Display for ApiAllowListTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.type_name, self.id)
    }
}

// ---------------------------------------------------------------------------
// Insights / Analytics
// ---------------------------------------------------------------------------

/// The interval of time over which to generate a smaller insights report.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum InsightsReportInterval {
    /// Day.
    #[serde(rename = "day")]
    Day,
    /// Week.
    #[serde(rename = "week")]
    Week,
}

impl InsightsReportInterval {
    /// Returns the number of days in this interval.
    #[must_use]
    pub fn days(&self) -> i32 {
        match self {
            Self::Day => 1,
            Self::Week => 7,
        }
    }
}

/// Section to include in the template insights response.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TemplateInsightsSection {
    /// IntervalReports.
    #[serde(rename = "interval_reports")]
    IntervalReports,
    /// Report.
    #[serde(rename = "report")]
    Report,
}

/// Type of app reported in template insights.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TemplateAppsType {
    /// Builtin.
    #[serde(rename = "builtin")]
    Builtin,
    /// App.
    #[serde(rename = "app")]
    App,
}

/// Connection latency percentiles.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ConnectionLatency {
    /// P50.
    pub p50: f64,
    /// P95.
    pub p95: f64,
}

/// A single DAU entry.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DAUEntry {
    /// Date.
    pub date: String,
    /// Amount.
    pub amount: i64,
}

/// Response from the DAU endpoint.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DAUsResponse {
    /// Tz hour offset.
    pub tz_hour_offset: i32,
    /// Entries.
    pub entries: Vec<DAUEntry>,
}

/// Per-user latency data.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct UserLatency {
    /// Template ids.
    pub template_ids: Vec<Uuid>,
    /// User id.
    pub user_id: Uuid,
    /// Username.
    pub username: String,
    /// Avatar url.
    pub avatar_url: String,
    /// Latency ms.
    pub latency_ms: ConnectionLatency,
}

/// Report for user latency insights.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct UserLatencyInsightsReport {
    /// Start time.
    #[serde(with = "time::serde::rfc3339")]
    pub start_time: OffsetDateTime,
    /// End time.
    #[serde(with = "time::serde::rfc3339")]
    pub end_time: OffsetDateTime,
    /// Template ids.
    pub template_ids: Vec<Uuid>,
    /// Users.
    pub users: Vec<UserLatency>,
}

/// Response for user latency insights.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct UserLatencyInsightsResponse {
    /// Report.
    pub report: UserLatencyInsightsReport,
}

/// Per-user activity data.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserActivity {
    /// Template ids.
    pub template_ids: Vec<Uuid>,
    /// User id.
    pub user_id: Uuid,
    /// Username.
    pub username: String,
    /// Avatar url.
    pub avatar_url: String,
    /// Seconds.
    pub seconds: i64,
}

/// Report for user activity insights.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserActivityInsightsReport {
    /// Start time.
    #[serde(with = "time::serde::rfc3339")]
    pub start_time: OffsetDateTime,
    /// End time.
    #[serde(with = "time::serde::rfc3339")]
    pub end_time: OffsetDateTime,
    /// Template ids.
    pub template_ids: Vec<Uuid>,
    /// Users.
    pub users: Vec<UserActivity>,
}

/// Response for user activity insights.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserActivityInsightsResponse {
    /// Report.
    pub report: UserActivityInsightsReport,
}

/// App usage entry for template insights.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TemplateAppUsage {
    /// Template ids.
    pub template_ids: Vec<Uuid>,
    /// App type.
    #[serde(rename = "type")]
    pub app_type: TemplateAppsType,
    /// Display name.
    pub display_name: String,
    /// Slug.
    pub slug: String,
    /// Icon.
    pub icon: String,
    /// Seconds.
    pub seconds: i64,
    /// Times used.
    #[serde(default)]
    pub times_used: i64,
}

/// Parameter value usage entry.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TemplateParameterValue {
    /// Value.
    pub value: String,
    /// Count.
    pub count: i64,
}

/// Parameter usage entry for template insights.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TemplateParameterUsage {
    /// Template ids.
    pub template_ids: Vec<Uuid>,
    /// Display name.
    pub display_name: String,
    /// Name.
    pub name: String,
    /// Param type.
    #[serde(rename = "type")]
    pub param_type: String,
    /// Description.
    pub description: String,
    /// Options.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<Value>,
    /// Values.
    pub values: Vec<TemplateParameterValue>,
}

/// Full report for template insights.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TemplateInsightsReport {
    /// Start time.
    #[serde(with = "time::serde::rfc3339")]
    pub start_time: OffsetDateTime,
    /// End time.
    #[serde(with = "time::serde::rfc3339")]
    pub end_time: OffsetDateTime,
    /// Template ids.
    pub template_ids: Vec<Uuid>,
    /// Active users.
    pub active_users: i64,
    /// Apps usage.
    pub apps_usage: Vec<TemplateAppUsage>,
    /// Parameters usage.
    pub parameters_usage: Vec<TemplateParameterUsage>,
}

/// Per-interval report for template insights.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TemplateInsightsIntervalReport {
    /// Start time.
    #[serde(with = "time::serde::rfc3339")]
    pub start_time: OffsetDateTime,
    /// End time.
    #[serde(with = "time::serde::rfc3339")]
    pub end_time: OffsetDateTime,
    /// Template ids.
    pub template_ids: Vec<Uuid>,
    /// Interval.
    pub interval: InsightsReportInterval,
    /// Active users.
    pub active_users: i64,
}

/// Response for template insights.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TemplateInsightsResponse {
    /// Report.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<TemplateInsightsReport>,
    /// Interval reports.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interval_reports: Vec<TemplateInsightsIntervalReport>,
}

/// Count of users in a given status at a specific date.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserStatusChangeCount {
    /// Date.
    #[serde(with = "time::serde::rfc3339")]
    pub date: OffsetDateTime,
    /// Count.
    pub count: i64,
}

/// Response for user status counts over time.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GetUserStatusCountsResponse {
    /// Status counts.
    pub status_counts: HashMap<String, Vec<UserStatusChangeCount>>,
}

// ---------------------------------------------------------------------------
// Debug / Observability
// ---------------------------------------------------------------------------

/// Response from the debug coordinator endpoint.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugCoordinatorResponse {
    /// Message.
    pub message: String,
}

/// Response from the debug tailnet endpoint.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugTailnetResponse {
    /// Message.
    pub message: String,
}

/// Response from the debug DERP traffic endpoint.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugDerpTrafficResponse {
    /// Message.
    pub message: String,
}

/// Response from the debug expvar endpoint.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugExpvarResponse {
    /// Vars.
    pub vars: HashMap<String, Value>,
}

/// Response from the debug websocket test endpoint.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugWebsocketResponse {
    /// Message.
    pub message: String,
}

/// Response from the debug pprof endpoint.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugPprofResponse {
    /// Message.
    pub message: String,
}

// ---------------------------------------------------------------------------
// AI Tasks
// ---------------------------------------------------------------------------

/// TaskStatus represents the status of a task.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
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

impl TaskStatus {
    /// Returns the string representation of this task status.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Initializing => "initializing",
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Unknown => "unknown",
            Self::Error => "error",
        }
    }
}

impl fmt::Display for TaskStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// TaskState represents the high-level lifecycle of a task.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TaskState {
    /// Working.
    Working,
    /// Idle.
    Idle,
    /// Complete.
    Complete,
    /// Failed.
    Failed,
}

/// TaskStateEntry represents a single entry in the task's state history.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskStateEntry {
    /// Timestamp.
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    /// State.
    pub state: TaskState,
    /// Message.
    pub message: String,
    /// Uri.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub uri: String,
}

/// Task represents a task.
#[derive(Clone, Debug, Serialize)]
pub struct TaskResponse {
    /// Id.
    pub id: Uuid,
    /// Organization id.
    pub organization_id: Uuid,
    /// Owner id.
    pub owner_id: Uuid,
    /// Owner name.
    pub owner_name: String,
    /// Owner avatar url.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub owner_avatar_url: String,
    /// Name.
    pub name: String,
    /// Display name.
    pub display_name: String,
    /// Template version id.
    pub template_version_id: Uuid,
    /// Workspace id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<Uuid>,
    /// Initial prompt.
    pub initial_prompt: String,
    /// Status.
    pub status: TaskStatus,
    /// Current state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_state: Option<TaskStateEntry>,
    /// Created at.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// TasksListResponse is the response for the task list endpoint.
#[derive(Clone, Debug, Serialize)]
pub struct TasksListResponse {
    /// Tasks.
    pub tasks: Vec<TaskResponse>,
    /// Count.
    pub count: usize,
}

/// CreateTaskRequest is the request to create a new task.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateTaskRequest {
    /// Template version id.
    pub template_version_id: Uuid,
    /// Input.
    pub input: String,
    /// Name.
    #[serde(default)]
    pub name: Option<String>,
    /// Display name.
    #[serde(default)]
    pub display_name: Option<String>,
}

/// UpdateTaskInputRequest is used to update a task's input.
#[derive(Clone, Debug, Deserialize)]
pub struct UpdateTaskInputRequest {
    /// Input.
    pub input: String,
}

/// TaskSendRequest is used to send task input to the tasks sidebar app.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskSendRequest {
    /// Input.
    pub input: String,
}

/// TaskLogType indicates the source of a task log entry.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TaskLogType {
    /// Input.
    Input,
    /// Output.
    Output,
}

/// TaskLogEntry represents a single log entry for a task.
#[derive(Clone, Debug, Serialize)]
pub struct TaskLogEntry {
    /// Id.
    pub id: i32,
    /// Content.
    pub content: String,
    /// Log type.
    #[serde(rename = "type")]
    pub log_type: TaskLogType,
    /// Time.
    #[serde(with = "time::serde::rfc3339")]
    pub time: OffsetDateTime,
}

/// TaskLogsResponse contains task logs and metadata.
#[derive(Clone, Debug, Serialize)]
pub struct TaskLogsResponse {
    /// Logs.
    pub logs: Vec<TaskLogEntry>,
    /// Snapshot.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub snapshot: bool,
    /// Snapshot at.
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub snapshot_at: Option<OffsetDateTime>,
}

/// TaskLogSnapshotEnvelope wraps a task log snapshot posted by an agent.
#[derive(Clone, Debug, Deserialize)]
pub struct TaskLogSnapshotEnvelope {
    /// Log snapshot.
    pub log_snapshot: Value,
}

/// PauseTaskResponse represents the response from pausing a task.
#[derive(Clone, Debug, Serialize)]
pub struct PauseTaskResponse {
    /// Placeholder for the workspace build that was created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_build: Option<Value>,
}

/// ResumeTaskResponse represents the response from resuming a task.
#[derive(Clone, Debug, Serialize)]
pub struct ResumeTaskResponse {
    /// Placeholder for the workspace build that was created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_build: Option<Value>,
}

// ---------------------------------------------------------------------------
// Chats
// ---------------------------------------------------------------------------

/// ChatStatus represents the status of a chat.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
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

impl ChatStatus {
    /// Returns the string representation of this chat status.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Waiting => "waiting",
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Paused => "paused",
            Self::Completed => "completed",
            Self::Error => "error",
        }
    }
}

impl fmt::Display for ChatStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// ChatMessageVisibility controls who sees a chat message.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatMessageVisibility {
    /// User.
    User,
    /// Model.
    Model,
    /// Both.
    Both,
}

/// ChatMessagePartType represents a structured message part type.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChatMessagePartType {
    /// Text.
    #[serde(rename = "text")]
    Text,
    /// Reasoning.
    #[serde(rename = "reasoning")]
    Reasoning,
    /// ToolCall.
    #[serde(rename = "tool-call")]
    ToolCall,
    /// ToolResult.
    #[serde(rename = "tool-result")]
    ToolResult,
    /// Source.
    #[serde(rename = "source")]
    Source,
    /// File.
    #[serde(rename = "file")]
    File,
    /// FileReference.
    #[serde(rename = "file-reference")]
    FileReference,
}

/// ChatMessagePart is a structured chunk of a chat message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChatMessagePart {
    /// Part type.
    #[serde(rename = "type")]
    pub part_type: ChatMessagePartType,
    /// Text.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub text: String,
    /// Signature.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature: String,
    /// Tool call id.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tool_call_id: String,
    /// Tool name.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tool_name: String,
    /// Args.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<Value>,
    /// Args delta.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub args_delta: String,
    /// Result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Result delta.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub result_delta: String,
    /// Is error.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_error: bool,
    /// Source id.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_id: String,
    /// Url.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub url: String,
    /// Title.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub title: String,
    /// Media type.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub media_type: String,
    /// File id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_id: Option<Uuid>,
    /// File name.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub file_name: String,
    /// Start line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_line: Option<i32>,
    /// End line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_line: Option<i32>,
    /// Content.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub content: String,
}

/// ChatMessageUsage contains token usage information for a chat message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChatMessageUsage {
    /// Input tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<i64>,
    /// Output tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<i64>,
    /// Total tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_tokens: Option<i64>,
    /// Reasoning tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_tokens: Option<i64>,
    /// Cache creation tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_creation_tokens: Option<i64>,
    /// Cache read tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_read_tokens: Option<i64>,
    /// Context limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_limit: Option<i64>,
}

/// ChatMessage represents a single message in a chat.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChatMessageResponse {
    /// Id.
    pub id: i64,
    /// Chat id.
    pub chat_id: Uuid,
    /// Model config id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_config_id: Option<Uuid>,
    /// Created at.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Role.
    pub role: String,
    /// Content.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub content: Vec<ChatMessagePart>,
    /// Usage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<ChatMessageUsage>,
}

/// Chat represents a chat session.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChatResponse {
    /// Id.
    pub id: Uuid,
    /// Owner id.
    pub owner_id: Uuid,
    /// Workspace id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<Uuid>,
    /// Parent chat id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_chat_id: Option<Uuid>,
    /// Root chat id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_chat_id: Option<Uuid>,
    /// Last model config id.
    pub last_model_config_id: Uuid,
    /// Title.
    pub title: String,
    /// Status.
    pub status: ChatStatus,
    /// Last error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// Created at.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Updated at.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    /// Archived.
    pub archived: bool,
}

/// ChatQueuedMessage represents a queued message waiting to be processed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChatQueuedMessageResponse {
    /// Id.
    pub id: i64,
    /// Chat id.
    pub chat_id: Uuid,
    /// Content.
    pub content: Vec<ChatMessagePart>,
    /// Created at.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// ChatWithMessages is a chat along with its messages.
#[derive(Clone, Debug, Serialize)]
pub struct ChatWithMessagesResponse {
    /// Chat.
    pub chat: ChatResponse,
    /// Messages.
    pub messages: Vec<ChatMessageResponse>,
    /// Queued messages.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub queued_messages: Vec<ChatQueuedMessageResponse>,
}

/// ChatInputPartType represents an input part type for user chat input.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChatInputPartType {
    /// Text.
    #[serde(rename = "text")]
    Text,
    /// File.
    #[serde(rename = "file")]
    File,
    /// FileReference.
    #[serde(rename = "file-reference")]
    FileReference,
}

/// ChatInputPart is a single user input part for creating a chat.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChatInputPart {
    /// Part type.
    #[serde(rename = "type")]
    pub part_type: ChatInputPartType,
    /// Text.
    #[serde(default)]
    pub text: String,
    /// File id.
    #[serde(default)]
    pub file_id: Option<Uuid>,
    /// File name.
    #[serde(default)]
    pub file_name: String,
    /// Start line.
    #[serde(default)]
    pub start_line: Option<i32>,
    /// End line.
    #[serde(default)]
    pub end_line: Option<i32>,
    /// Content.
    #[serde(default)]
    pub content: String,
}

/// CreateChatRequest is the request to create a new chat.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateChatRequest {
    /// Content.
    pub content: Vec<ChatInputPart>,
    /// Workspace id.
    #[serde(default)]
    pub workspace_id: Option<Uuid>,
    /// Model config id.
    #[serde(default)]
    pub model_config_id: Option<Uuid>,
}

/// CreateChatMessageRequest is the request to add a message to a chat.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateChatMessageRequest {
    /// Content.
    pub content: Vec<ChatInputPart>,
    /// Model config id.
    #[serde(default)]
    pub model_config_id: Option<Uuid>,
}

/// CreateChatMessageResponse is the response from adding a message.
#[derive(Clone, Debug, Serialize)]
pub struct CreateChatMessageApiResponse {
    /// Message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<ChatMessageResponse>,
    /// Queued message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queued_message: Option<ChatQueuedMessageResponse>,
    /// Queued.
    pub queued: bool,
}

/// UploadChatFileResponse is the response from uploading a chat file.
#[derive(Clone, Debug, Serialize)]
pub struct UploadChatFileResponse {
    /// Id.
    pub id: Uuid,
}

/// EditChatMessageRequest is the request to edit a user message in a chat.
#[derive(Clone, Debug, Deserialize)]
pub struct EditChatMessageRequest {
    /// Content.
    pub content: Vec<ChatInputPart>,
}

/// ChatProviderConfigSource describes how a provider entry is sourced.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatProviderConfigSource {
    /// Database.
    Database,
    /// EnvPreset.
    EnvPreset,
    /// Supported.
    Supported,
}

/// ChatProviderConfigResponse is an admin-managed provider configuration.
#[derive(Clone, Debug, Serialize)]
pub struct ChatProviderConfigResponse {
    /// Id.
    pub id: Uuid,
    /// Provider.
    pub provider: String,
    /// Display name.
    pub display_name: String,
    /// Enabled.
    pub enabled: bool,
    /// Has api key.
    pub has_api_key: bool,
    /// Base url.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub base_url: String,
    /// Source.
    pub source: ChatProviderConfigSource,
    /// Created at.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Updated at.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// CreateChatProviderConfigRequest creates a chat provider config.
#[derive(Clone, Deserialize)]
pub struct CreateChatProviderConfigRequest {
    /// Provider.
    pub provider: String,
    /// Display name.
    #[serde(default)]
    pub display_name: String,
    /// Api key.
    #[serde(default)]
    pub api_key: String,
    /// Base url.
    #[serde(default)]
    pub base_url: String,
    /// Enabled.
    #[serde(default)]
    pub enabled: Option<bool>,
}

impl fmt::Debug for CreateChatProviderConfigRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateChatProviderConfigRequest")
            .field("provider", &self.provider)
            .field("display_name", &self.display_name)
            .field("api_key", &"[REDACTED]")
            .field("base_url", &self.base_url)
            .field("enabled", &self.enabled)
            .finish()
    }
}

/// UpdateChatProviderConfigRequest updates a chat provider config.
#[derive(Clone, Deserialize)]
pub struct UpdateChatProviderConfigRequest {
    /// Display name.
    #[serde(default)]
    pub display_name: String,
    /// Api key.
    #[serde(default)]
    pub api_key: Option<String>,
    /// Base url.
    #[serde(default)]
    pub base_url: Option<String>,
    /// Enabled.
    #[serde(default)]
    pub enabled: Option<bool>,
}

impl fmt::Debug for UpdateChatProviderConfigRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpdateChatProviderConfigRequest")
            .field("display_name", &self.display_name)
            .field("api_key", &"[REDACTED]")
            .field("base_url", &self.base_url)
            .field("enabled", &self.enabled)
            .finish()
    }
}

/// ChatModelCallConfig configures per-call model behavior defaults.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChatModelCallConfig {
    /// Max output tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<i64>,
    /// Temperature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    /// Top p.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f64>,
    /// Top k.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_k: Option<i64>,
    /// Presence penalty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presence_penalty: Option<f64>,
    /// Frequency penalty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frequency_penalty: Option<f64>,
    /// Provider options.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_options: Option<Value>,
}

/// ChatModelConfigResponse is an admin-managed model configuration.
#[derive(Clone, Debug, Serialize)]
pub struct ChatModelConfigResponse {
    /// Id.
    pub id: Uuid,
    /// Provider.
    pub provider: String,
    /// Model.
    pub model: String,
    /// Display name.
    pub display_name: String,
    /// Enabled.
    pub enabled: bool,
    /// Is default.
    pub is_default: bool,
    /// Context limit.
    pub context_limit: i64,
    /// Compression threshold.
    pub compression_threshold: i32,
    /// Model config.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_config: Option<ChatModelCallConfig>,
    /// Created at.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Updated at.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// CreateChatModelConfigRequest creates a chat model config.
#[derive(Clone, Debug, Deserialize)]
pub struct CreateChatModelConfigRequest {
    /// Provider.
    pub provider: String,
    /// Model.
    pub model: String,
    /// Display name.
    #[serde(default)]
    pub display_name: String,
    /// Enabled.
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Is default.
    #[serde(default)]
    pub is_default: Option<bool>,
    /// Context limit.
    #[serde(default)]
    pub context_limit: Option<i64>,
    /// Compression threshold.
    #[serde(default)]
    pub compression_threshold: Option<i32>,
    /// Model config.
    #[serde(default)]
    pub model_config: Option<ChatModelCallConfig>,
}

/// UpdateChatModelConfigRequest updates a chat model config.
#[derive(Clone, Debug, Deserialize)]
pub struct UpdateChatModelConfigRequest {
    /// Provider.
    #[serde(default)]
    pub provider: String,
    /// Model.
    #[serde(default)]
    pub model: String,
    /// Display name.
    #[serde(default)]
    pub display_name: String,
    /// Enabled.
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Is default.
    #[serde(default)]
    pub is_default: Option<bool>,
    /// Context limit.
    #[serde(default)]
    pub context_limit: Option<i64>,
    /// Compression threshold.
    #[serde(default)]
    pub compression_threshold: Option<i32>,
    /// Model config.
    #[serde(default)]
    pub model_config: Option<ChatModelCallConfig>,
}

// ---------------------------------------------------------------------------
// Chat Models & Diff types
// ---------------------------------------------------------------------------

/// ChatModel represents a model in the chat model catalog.
#[derive(Clone, Debug, Serialize)]
pub struct ChatModel {
    /// Id.
    pub id: String,
    /// Provider.
    pub provider: String,
    /// Model.
    pub model: String,
    /// Display name.
    pub display_name: String,
}

/// ChatModelProviderUnavailableReason explains why a provider cannot be used.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChatModelProviderUnavailableReason {
    /// MissingApiKey.
    MissingApiKey,
    /// FetchFailed.
    FetchFailed,
}

/// ChatModelProvider represents provider availability and model results.
#[derive(Clone, Debug, Serialize)]
pub struct ChatModelProvider {
    /// Provider.
    pub provider: String,
    /// Available.
    pub available: bool,
    /// Unavailable reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<ChatModelProviderUnavailableReason>,
    /// Models.
    pub models: Vec<ChatModel>,
}

/// ChatModelsResponse is the catalog returned from chat model discovery.
#[derive(Clone, Debug, Serialize)]
pub struct ChatModelsResponse {
    /// Providers.
    pub providers: Vec<ChatModelProvider>,
}

/// ChatDiffStatusResponse represents cached diff status for a chat.
#[derive(Clone, Debug, Serialize)]
pub struct ChatDiffStatusResponse {
    /// Chat id.
    pub chat_id: Uuid,
    /// Url.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Pull request state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pull_request_state: Option<String>,
    /// Changes requested.
    pub changes_requested: bool,
    /// Additions.
    pub additions: i32,
    /// Deletions.
    pub deletions: i32,
    /// Changed files.
    pub changed_files: i32,
    /// Refreshed at.
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_rfc3339"
    )]
    pub refreshed_at: Option<OffsetDateTime>,
    /// Stale at.
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_rfc3339"
    )]
    pub stale_at: Option<OffsetDateTime>,
}

/// ChatDiffContentsResponse represents the resolved diff text for a chat.
#[derive(Clone, Debug, Serialize)]
pub struct ChatDiffContentsResponse {
    /// Chat id.
    pub chat_id: Uuid,
    /// Provider.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Remote origin.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_origin: Option<String>,
    /// Branch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    /// Pull request url.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pull_request_url: Option<String>,
    /// Diff.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub diff: String,
}

// ---------------------------------------------------------------------------
// Chat Stream types
// ---------------------------------------------------------------------------

/// ChatStreamEventType represents the kind of chat stream update.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatStreamEventType {
    /// MessagePart.
    MessagePart,
    /// Message.
    Message,
    /// Status.
    Status,
    /// Error.
    Error,
    /// QueueUpdate.
    QueueUpdate,
    /// Retry.
    Retry,
}

/// ChatStreamMessagePart is a streamed message part update.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChatStreamMessagePart {
    /// Role.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub role: String,
    /// Part.
    pub part: ChatMessagePart,
}

/// ChatStreamStatus represents an updated chat status.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChatStreamStatus {
    /// Status.
    pub status: ChatStatus,
}

/// ChatStreamError represents an error event in the stream.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChatStreamError {
    /// Message.
    pub message: String,
}

/// ChatStreamRetry represents an auto-retry status event in the stream.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChatStreamRetry {
    /// Attempt.
    pub attempt: i32,
    /// Delay ms.
    pub delay_ms: i64,
    /// Error.
    pub error: String,
    /// Retrying at.
    #[serde(with = "time::serde::rfc3339")]
    pub retrying_at: OffsetDateTime,
}

/// ChatStreamEvent represents a real-time update for chat streaming.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChatStreamEvent {
    /// Event type.
    #[serde(rename = "type")]
    pub event_type: ChatStreamEventType,
    /// Chat id.
    pub chat_id: Uuid,
    /// Message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<ChatMessageResponse>,
    /// Message part.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_part: Option<ChatStreamMessagePart>,
    /// Status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<ChatStreamStatus>,
    /// Error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ChatStreamError>,
    /// Retry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry: Option<ChatStreamRetry>,
    /// Queued messages.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub queued_messages: Vec<ChatQueuedMessageResponse>,
}

// ---------------------------------------------------------------------------
// Chat PubSub event types
// ---------------------------------------------------------------------------

/// ChatEventKind represents the kind of chat event broadcast over pub/sub.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatEventKind {
    /// StatusChange.
    StatusChange,
    /// TitleChange.
    TitleChange,
    /// Created.
    Created,
    /// Deleted.
    Deleted,
    /// DiffStatusChange.
    DiffStatusChange,
}

/// ChatEvent is a pub/sub event payload for chat updates.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChatEvent {
    /// Kind.
    pub kind: ChatEventKind,
    /// Chat.
    pub chat: ChatResponse,
}

/// ServerSentEventType represents SSE event types.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServerSentEventType {
    /// Ping.
    Ping,
    /// Data.
    Data,
    /// Error.
    Error,
}

/// ServerSentEvent is a generic server-sent event envelope.
#[derive(Clone, Debug, Serialize)]
pub struct ServerSentEvent<T: Serialize> {
    /// Event type.
    #[serde(rename = "type")]
    pub event_type: ServerSentEventType,
    /// Data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
}

/// Returns the pub/sub channel name for chat events owned by the given user.
///
/// Mirrors the Go `pubsub.ChatEventChannel(ownerID)` function.
#[must_use]
pub fn chat_event_channel(owner_id: Uuid) -> String {
    format!("chat:owner:{owner_id}")
}

/// Returns the pub/sub channel name for streaming events on a specific chat.
///
/// Used by `stream_chat` to receive live message parts, status updates, and
/// errors for an individual chat session.
#[must_use]
pub fn chat_stream_channel(chat_id: Uuid) -> String {
    format!("chat:stream:{chat_id}")
}

/// Helper to serialize an optional OffsetDateTime in RFC 3339.
fn serialize_optional_rfc3339<S>(
    value: &Option<OffsetDateTime>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match value {
        Some(dt) => time::serde::rfc3339::serialize(dt, serializer),
        None => serializer.serialize_none(),
    }
}

// ---------------------------------------------------------------------------
// Workspace Agent types
// ---------------------------------------------------------------------------

/// Status of a workspace agent's connection.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceAgentStatus {
    /// Agent has not yet connected.
    #[default]
    Connecting,
    /// Agent is connected.
    Connected,
    /// Agent has disconnected.
    Disconnected,
    /// Agent connection has timed out.
    Timeout,
}

/// Lifecycle state of a workspace agent.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceAgentLifecycle {
    /// Agent has been created.
    #[default]
    Created,
    /// Agent is starting.
    Starting,
    /// Agent start has timed out.
    StartTimeout,
    /// Agent start encountered an error.
    StartError,
    /// Agent is ready.
    Ready,
    /// Agent is shutting down.
    ShuttingDown,
    /// Agent shutdown has timed out.
    ShutdownTimeout,
    /// Agent shutdown encountered an error.
    ShutdownError,
    /// Agent is off.
    Off,
}

/// Agent subsystem markers.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentSubsystem {
    /// Envbuilder subsystem.
    Envbuilder,
    /// Envbox subsystem.
    Envbox,
    /// Exectrace subsystem.
    Exectrace,
}

/// Display app types available on an agent.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DisplayApp {
    /// VS Code desktop.
    Vscode,
    /// VS Code Insiders.
    VscodeInsiders,
    /// Web terminal.
    WebTerminal,
    /// SSH helper.
    SshHelper,
    /// Port forwarding helper.
    PortForwardingHelper,
}

/// Health status for a workspace agent.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceAgentHealth {
    /// Whether the agent is healthy.
    pub healthy: bool,
    /// Reason for unhealthy status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A workspace agent log source.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceAgentLogSource {
    /// Stable identifier.
    pub id: Uuid,
    /// Owning workspace agent identifier.
    pub workspace_agent_id: Uuid,
    /// Creation time.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Human-readable display name.
    pub display_name: String,
    /// Icon URL or identifier.
    pub icon: String,
}

/// A workspace agent startup/shutdown script.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceAgentScript {
    /// Stable identifier.
    pub id: Uuid,
    /// Log source identifier for this script.
    pub log_source_id: Uuid,
    /// Path where log output is written.
    pub log_path: String,
    /// Script content.
    pub script: String,
    /// Cron expression for scheduled runs.
    pub cron: String,
    /// Whether this script blocks login during start.
    pub start_blocks_login: bool,
    /// Whether this script runs on agent start.
    pub run_on_start: bool,
    /// Whether this script runs on agent stop.
    pub run_on_stop: bool,
    /// Timeout in seconds.
    pub timeout_seconds: i32,
    /// Human-readable display name.
    pub display_name: String,
}

/// App sharing level.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AppSharingLevel {
    /// Only the workspace owner.
    #[default]
    Owner,
    /// Any authenticated user.
    Authenticated,
    /// Any organization member.
    Organization,
    /// Public access.
    Public,
}

/// Where a workspace app opens.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum WorkspaceAppOpenIn {
    /// New browser tab.
    #[serde(rename = "tab")]
    Tab,
    /// New browser window.
    #[serde(rename = "window")]
    Window,
    /// Slim window.
    #[default]
    #[serde(rename = "slim-window")]
    SlimWindow,
}

/// Health state of a workspace app.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceAppHealth {
    /// Health checks are disabled.
    #[default]
    Disabled,
    /// Health check is initializing.
    Initializing,
    /// App is healthy.
    Healthy,
    /// App is unhealthy.
    Unhealthy,
}

/// A workspace app configured on an agent.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceApp {
    /// Stable identifier.
    pub id: Uuid,
    /// URL-safe slug.
    pub slug: String,
    /// Human-readable display name.
    pub display_name: String,
    /// Command to execute when using the app.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// URL for the app.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Icon URL or identifier.
    pub icon: String,
    /// Whether this app uses a subdomain.
    pub subdomain: bool,
    /// Sharing level.
    pub sharing_level: AppSharingLevel,
    /// Health check URL.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub healthcheck_url: String,
    /// Health check interval in seconds.
    pub healthcheck_interval: i32,
    /// Health check failure threshold.
    pub healthcheck_threshold: i32,
    /// Current health status.
    pub health: WorkspaceAppHealth,
    /// Whether this is an external app.
    pub external: bool,
    /// Display order.
    pub display_order: i32,
    /// Whether the app is hidden.
    pub hidden: bool,
    /// Where the app opens.
    pub open_in: WorkspaceAppOpenIn,
    /// Display group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_group: Option<String>,
}

/// Full workspace agent representation.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct WorkspaceAgent {
    /// Stable identifier.
    pub id: Uuid,
    /// Parent agent identifier for sub-agents.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<Uuid>,
    /// Creation time.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Update time.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    /// First connection time.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub first_connected_at: Option<OffsetDateTime>,
    /// Last connection time.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub last_connected_at: Option<OffsetDateTime>,
    /// Disconnection time.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub disconnected_at: Option<OffsetDateTime>,
    /// Agent start time.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub started_at: Option<OffsetDateTime>,
    /// Agent ready time.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub ready_at: Option<OffsetDateTime>,
    /// Connection status.
    pub status: WorkspaceAgentStatus,
    /// Lifecycle state.
    pub lifecycle_state: WorkspaceAgentLifecycle,
    /// Agent name.
    pub name: String,
    /// Owning resource identifier.
    pub resource_id: Uuid,
    /// Instance identifier for cloud providers.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub instance_id: String,
    /// Agent architecture.
    pub architecture: String,
    /// Agent environment variables.
    pub environment_variables: HashMap<String, String>,
    /// Agent operating system.
    pub operating_system: String,
    /// Total log length.
    pub logs_length: i32,
    /// Whether logs have overflowed.
    pub logs_overflowed: bool,
    /// Working directory.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub directory: String,
    /// Expanded working directory.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub expanded_directory: String,
    /// Agent version.
    pub version: String,
    /// Agent API version.
    pub api_version: String,
    /// Installed apps.
    pub apps: Vec<WorkspaceApp>,
    /// DERP latency measurements.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub latency: HashMap<String, DERPRegion>,
    /// Connection timeout in seconds.
    pub connection_timeout_seconds: i32,
    /// Troubleshooting URL.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub troubleshooting_url: String,
    /// Active subsystems.
    pub subsystems: Vec<AgentSubsystem>,
    /// Agent health status.
    pub health: WorkspaceAgentHealth,
    /// Display apps.
    pub display_apps: Vec<DisplayApp>,
    /// Log sources.
    pub log_sources: Vec<WorkspaceAgentLogSource>,
    /// Scripts.
    pub scripts: Vec<WorkspaceAgentScript>,
}

/// DERP region latency measurement.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct DERPRegion {
    /// Whether this is the preferred region.
    pub preferred: bool,
    /// Latency in milliseconds.
    #[serde(rename = "latency_ms")]
    pub latency_milliseconds: f64,
}

/// A DERP map node.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DERPNode {
    /// Node name.
    pub name: String,
    /// Region identifier.
    pub region_id: i64,
    /// Host address.
    pub host_name: String,
    /// IPv4 address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv4: Option<String>,
    /// IPv6 address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<String>,
    /// STUN port.
    pub stun_port: i32,
    /// Whether STUN is supported.
    pub stun_only: bool,
    /// DERP port.
    pub derp_port: i32,
    /// Whether to force HTTP.
    pub force_http: bool,
}

/// A DERP map region.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DERPMapRegion {
    /// Region identifier.
    pub region_id: i64,
    /// Region code.
    pub region_code: String,
    /// Region name.
    pub region_name: String,
    /// Whether to avoid this region.
    pub avoid: bool,
    /// Nodes in this region.
    pub nodes: Vec<DERPNode>,
}

/// DERP map containing all regions.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DERPMap {
    /// Regions keyed by region identifier.
    pub regions: HashMap<String, DERPMapRegion>,
}

/// Workspace agent connection info response.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct WorkspaceAgentConnectionInfo {
    /// DERP map for the deployment.
    pub derp_map: DERPMap,
    /// Whether DERP force WebSocket is enabled.
    pub derp_force_websockets: bool,
    /// Whether direct connections are disabled.
    pub disable_direct_connections: bool,
    /// Hostname suffix used for workspace SSH hostnames.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hostname_suffix: String,
}

/// Log level for workspace agent logs.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    /// Trace level.
    Trace,
    /// Debug level.
    Debug,
    /// Info level.
    #[default]
    Info,
    /// Warn level.
    Warn,
    /// Error level.
    Error,
}

/// A workspace agent log entry.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceAgentLog {
    /// Stable identifier.
    pub id: i64,
    /// Creation time.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Log output.
    pub output: String,
    /// Log level.
    pub level: LogLevel,
    /// Source identifier.
    pub source_id: Uuid,
}

/// A listening port on a workspace agent.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceAgentListeningPort {
    /// Process name listening on this port.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub process_name: String,
    /// Network type (tcp, udp).
    pub network: String,
    /// Port number.
    pub port: u16,
}

/// Listening ports response.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceAgentListeningPortsResponse {
    /// List of listening ports.
    pub ports: Vec<WorkspaceAgentListeningPort>,
}

/// Port share protocol.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PortShareProtocol {
    /// HTTP protocol.
    #[default]
    Http,
    /// HTTPS protocol.
    Https,
}

/// A container port mapping.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceAgentContainerPort {
    /// Network type (tcp, udp).
    pub network: String,
    /// Port number.
    pub port: u16,
    /// Host port number.
    pub host_port: u16,
    /// Host IP address.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host_ip: String,
}

/// A container running on a workspace agent.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceAgentContainer {
    /// Creation time.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Container identifier.
    pub id: String,
    /// Friendly name.
    #[serde(rename = "name")]
    pub friendly_name: String,
    /// Container image.
    pub image: String,
    /// Labels.
    pub labels: HashMap<String, String>,
    /// Whether the container is running.
    pub running: bool,
    /// Port mappings.
    pub ports: Vec<WorkspaceAgentContainerPort>,
    /// Container status.
    pub status: String,
    /// Volume mounts.
    pub volumes: HashMap<String, String>,
}

/// A devcontainer on a workspace agent.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceAgentDevcontainer {
    /// Stable identifier.
    pub id: Uuid,
    /// Agent identifier.
    pub workspace_agent_id: Uuid,
    /// Workspace folder path.
    pub workspace_folder: String,
    /// Config file path.
    pub config_path: String,
    /// Devcontainer name.
    pub name: String,
    /// Container associated with this devcontainer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<WorkspaceAgentContainer>,
}

/// Response for container listing.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceAgentListContainersResponse {
    /// Running containers.
    pub containers: Vec<WorkspaceAgentContainer>,
    /// Configured devcontainers.
    pub devcontainers: Vec<WorkspaceAgentDevcontainer>,
}

/// Workspace agent metadata entry.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceAgentMetadata {
    /// Display name.
    pub display_name: String,
    /// Key.
    pub key: String,
    /// Script to execute.
    pub script: String,
    /// Collected value.
    pub value: String,
    /// Error message.
    pub error: String,
    /// Timeout in seconds.
    pub timeout: i64,
    /// Collection interval in seconds.
    pub interval: i64,
    /// Last collection time.
    #[serde(with = "time::serde::rfc3339")]
    pub collected_at: OffsetDateTime,
    /// Display order.
    pub display_order: i32,
}

/// Status state for a workspace app.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceAppStatusState {
    /// App is working.
    Working,
    /// App has completed.
    Complete,
    /// App has failed.
    Failure,
    /// App is idle.
    #[default]
    Idle,
}

/// Status of a workspace app.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceAppStatus {
    /// Stable identifier.
    pub id: Uuid,
    /// Creation time.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Agent identifier.
    pub agent_id: Uuid,
    /// App identifier.
    pub app_id: Uuid,
    /// Workspace identifier.
    pub workspace_id: Uuid,
    /// State.
    pub state: WorkspaceAppStatusState,
    /// Status message.
    pub message: String,
    /// URI for the status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
}

/// Request to update an app status.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct PatchAppStatusRequest {
    /// App slug.
    pub app_slug: String,
    /// Status message.
    pub message: String,
    /// URI for the status.
    #[serde(default)]
    pub uri: Option<String>,
    /// State.
    pub state: WorkspaceAppStatusState,
    /// Icon (deprecated, unused).
    #[serde(default)]
    pub icon: Option<String>,
    /// Needs user attention (deprecated, unused).
    #[serde(default)]
    pub needs_user_attention: Option<bool>,
}

/// Request to create an agent log source.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct CreateLogSourceRequest {
    /// Unique identifier for the log source (scoped to an agent).
    #[serde(default)]
    pub id: Option<Uuid>,
    /// Display name.
    pub display_name: String,
    /// Icon URL or identifier.
    pub icon: String,
}

/// Request to patch agent logs.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct PatchAgentLogsRequest {
    /// Log source identifier.
    pub log_source_id: Uuid,
    /// Log entries.
    pub logs: Vec<AgentLogEntry>,
}

/// A single agent log entry in a patch request.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct AgentLogEntry {
    /// Creation time.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Log output.
    pub output: String,
    /// Log level.
    pub level: LogLevel,
}

/// Instance identity token for AWS.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct AWSInstanceIdentityToken {
    /// PKCS7 signature.
    pub signature: String,
    /// Instance identity document.
    pub document: String,
}

/// Instance identity token for Azure.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct AzureInstanceIdentityToken {
    /// Encoded JWT token.
    pub signature: String,
}

/// Instance identity token for GCP.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct GCPInstanceIdentityToken {
    /// Encoded JWT token.
    pub json_web_token: String,
}

/// Agent auth token response from instance identity.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct WorkspaceAgentAuthenticateResponse {
    /// Session token.
    pub session_token: String,
}

/// External auth response for agents.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceAgentExternalAuthResponse {
    /// Access token.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub access_token: String,
    /// Token URL.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub url: String,
    /// Auth type.
    #[serde(rename = "type", default, skip_serializing_if = "String::is_empty")]
    pub auth_type: String,
    /// Whether the token is valid.
    pub authenticated: bool,
    /// Username if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Password if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

// ---------------------------------------------------------------------------
// Workspace domain types
// ---------------------------------------------------------------------------

/// Workspace transition type.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceTransition {
    /// Start the workspace.
    #[default]
    Start,
    /// Stop the workspace.
    Stop,
    /// Delete the workspace.
    Delete,
}

impl WorkspaceTransition {
    /// Returns the canonical wire-format string.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Delete => "delete",
        }
    }
}

/// Workspace status derived from the latest build.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceStatus {
    /// Workspace is pending.
    #[default]
    Pending,
    /// Workspace is starting.
    Starting,
    /// Workspace is running.
    Running,
    /// Workspace is stopping.
    Stopping,
    /// Workspace is stopped.
    Stopped,
    /// Workspace build failed.
    Failed,
    /// Workspace build is being canceled.
    Canceling,
    /// Workspace build was canceled.
    Canceled,
    /// Workspace is being deleted.
    Deleting,
    /// Workspace has been deleted.
    Deleted,
}

impl WorkspaceStatus {
    /// Returns the canonical wire-format string.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Stopping => "stopping",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
            Self::Canceling => "canceling",
            Self::Canceled => "canceled",
            Self::Deleting => "deleting",
            Self::Deleted => "deleted",
        }
    }
}

/// Build reason.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BuildReason {
    /// Triggered by a user.
    #[default]
    Initiator,
    /// Triggered by autostart.
    Autostart,
    /// Triggered by autostop.
    Autostop,
    /// Triggered by dormancy.
    Dormancy,
}

impl BuildReason {
    /// Returns the canonical wire-format string.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Initiator => "initiator",
            Self::Autostart => "autostart",
            Self::Autostop => "autostop",
            Self::Dormancy => "dormancy",
        }
    }
}

/// Automatic updates mode.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AutomaticUpdates {
    /// Always auto-update.
    Always,
    /// Never auto-update.
    #[default]
    Never,
}

/// Workspace health status.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct WorkspaceHealth {
    /// Whether the workspace is healthy.
    pub healthy: bool,
    /// IDs of failing agents, if any.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failing_agents: Vec<Uuid>,
}

/// Provisioner job representation.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ProvisionerJob {
    /// Job identifier.
    pub id: Uuid,
    /// Job creation time.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Job start time.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub started_at: Option<OffsetDateTime>,
    /// Job completion time.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub completed_at: Option<OffsetDateTime>,
    /// Job cancellation time.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub canceled_at: Option<OffsetDateTime>,
    /// Error from the provisioner.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
    /// Current job status.
    pub status: ProvisionerJobStatus,
    /// Worker ID when assigned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_id: Option<Uuid>,
}

/// Workspace build representation.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct WorkspaceBuildResponse {
    /// Build identifier.
    pub id: Uuid,
    /// Build creation time.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Build update time.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    /// Workspace identifier.
    pub workspace_id: Uuid,
    /// Workspace name.
    pub workspace_name: String,
    /// Workspace owner identifier.
    pub workspace_owner_id: Uuid,
    /// Workspace owner username.
    pub workspace_owner_name: String,
    /// Template version identifier.
    pub template_version_id: Uuid,
    /// Template version name.
    pub template_version_name: String,
    /// Build sequence number.
    pub build_number: i64,
    /// Transition type.
    pub transition: WorkspaceTransition,
    /// Initiator identifier.
    pub initiator_id: Uuid,
    /// Initiator username.
    pub initiator_name: String,
    /// Provisioner job state.
    pub job: ProvisionerJob,
    /// Build reason.
    pub reason: BuildReason,
    /// Build resources.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<WorkspaceResourceResponse>,
    /// Build deadline.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub deadline: Option<OffsetDateTime>,
    /// Maximum deadline.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub max_deadline: Option<OffsetDateTime>,
    /// Derived workspace status.
    pub status: WorkspaceStatus,
    /// Daily cost of the build.
    pub daily_cost: i32,
}

/// Workspace resource description.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct WorkspaceResourceResponse {
    /// Resource identifier.
    pub id: Uuid,
    /// Resource creation time.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Provisioner job identifier.
    pub job_id: Uuid,
    /// Workspace transition that produced this resource.
    pub workspace_transition: WorkspaceTransition,
    /// Resource type from the provisioner.
    #[serde(rename = "type")]
    pub resource_type: String,
    /// Resource name.
    pub name: String,
    /// Whether to hide the resource in the UI.
    #[serde(default)]
    pub hide: bool,
    /// Resource icon.
    #[serde(default)]
    pub icon: String,
    /// Daily cost.
    #[serde(default)]
    pub daily_cost: i32,
    /// Agents running on this resource.
    #[serde(default)]
    pub agents: Vec<Value>,
    /// Resource metadata annotations.
    #[serde(default)]
    pub metadata: Vec<WorkspaceResourceMetadata>,
}

/// Workspace resource metadata annotation.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct WorkspaceResourceMetadata {
    /// Metadata key.
    pub key: String,
    /// Metadata value.
    pub value: String,
    /// Whether the value is sensitive.
    #[serde(default)]
    pub sensitive: bool,
}

/// A full workspace response.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct WorkspaceResponse {
    /// Workspace identifier.
    pub id: Uuid,
    /// Workspace creation time.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Workspace update time.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    /// Workspace owner identifier.
    pub owner_id: Uuid,
    /// Workspace owner username.
    pub owner_name: String,
    /// Workspace owner avatar URL.
    #[serde(default)]
    pub owner_avatar_url: String,
    /// Organization identifier.
    pub organization_id: Uuid,
    /// Organization name.
    #[serde(default)]
    pub organization_name: String,
    /// Template identifier.
    pub template_id: Uuid,
    /// Template name.
    pub template_name: String,
    /// Template display name.
    #[serde(default)]
    pub template_display_name: String,
    /// Template icon.
    #[serde(default)]
    pub template_icon: String,
    /// Whether the template allows user cancel.
    #[serde(default)]
    pub template_allow_user_cancel_workspace_jobs: bool,
    /// Active template version identifier.
    pub template_active_version_id: Uuid,
    /// Whether the template requires the active version.
    #[serde(default)]
    pub template_require_active_version: bool,
    /// Latest build.
    pub latest_build: WorkspaceBuildResponse,
    /// Whether the workspace is outdated.
    #[serde(default)]
    pub outdated: bool,
    /// Workspace name.
    pub name: String,
    /// Autostart schedule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub autostart_schedule: Option<String>,
    /// Autostop TTL in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_ms: Option<i64>,
    /// Last used timestamp.
    #[serde(with = "time::serde::rfc3339")]
    pub last_used_at: OffsetDateTime,
    /// Scheduled deletion time.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub deleting_at: Option<OffsetDateTime>,
    /// Dormancy timestamp.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub dormant_at: Option<OffsetDateTime>,
    /// Health status.
    pub health: WorkspaceHealth,
    /// Automatic updates setting.
    pub automatic_updates: AutomaticUpdates,
    /// Whether renames are allowed.
    #[serde(default)]
    pub allow_renames: bool,
    /// Whether this workspace is a favorite.
    #[serde(default)]
    pub favorite: bool,
    /// Next scheduled start time.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub next_start_at: Option<OffsetDateTime>,
}

/// Paginated workspaces response.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct WorkspacesResponse {
    /// Matching workspaces.
    pub workspaces: Vec<WorkspaceResponse>,
    /// Total count of matching workspaces.
    pub count: i64,
}

/// Request to create a workspace.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CreateWorkspaceRequest {
    /// Template identifier.
    #[serde(default)]
    pub template_id: Uuid,
    /// Workspace name.
    pub name: String,
    /// Autostart schedule.
    #[serde(default)]
    pub autostart_schedule: Option<String>,
    /// TTL in milliseconds.
    #[serde(default)]
    pub ttl_ms: Option<i64>,
    /// Automatic updates setting.
    #[serde(default)]
    pub automatic_updates: Option<AutomaticUpdates>,
    /// Rich parameter values.
    #[serde(default)]
    pub rich_parameter_values: Vec<WorkspaceBuildParameter>,
    /// Template version identifier override.
    #[serde(default)]
    pub template_version_id: Option<Uuid>,
}

/// Request to update a workspace.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct UpdateWorkspaceRequest {
    /// New workspace name.
    #[serde(default)]
    pub name: Option<String>,
}

/// Request to update autostart schedule.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct UpdateWorkspaceAutostartRequest {
    /// Cron schedule.
    #[serde(default)]
    pub schedule: Option<String>,
}

/// Request to update workspace TTL.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct UpdateWorkspaceTTLRequest {
    /// TTL in milliseconds.
    #[serde(default)]
    pub ttl_ms: Option<i64>,
}

/// Request to extend workspace deadline.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PutExtendWorkspaceRequest {
    /// New deadline.
    #[serde(with = "time::serde::rfc3339")]
    pub deadline: OffsetDateTime,
}

/// Request to update workspace dormancy.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct UpdateWorkspaceDormancy {
    /// Whether to make dormant (true) or activate (false).
    pub dormant: bool,
}

/// Request to update automatic updates.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct UpdateWorkspaceAutomaticUpdatesRequest {
    /// New automatic updates setting.
    pub automatic_updates: AutomaticUpdates,
}

/// Request to post workspace usage.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct PostWorkspaceUsageRequest {
    /// Agent identifier.
    #[serde(default)]
    pub agent_id: Uuid,
    /// App name.
    #[serde(default)]
    pub app_name: String,
}

/// Request to create a workspace build.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CreateWorkspaceBuildRequest {
    /// Template version override.
    #[serde(default)]
    pub template_version_id: Option<Uuid>,
    /// Transition to perform.
    pub transition: WorkspaceTransition,
    /// Whether this is a dry run.
    #[serde(default)]
    pub dry_run: bool,
    /// Provisioner state override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<Vec<u8>>,
    /// Orphan on destroy.
    #[serde(default)]
    pub orphan: bool,
    /// Rich parameter values.
    #[serde(default)]
    pub rich_parameter_values: Vec<WorkspaceBuildParameter>,
    /// Log level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_level: Option<String>,
}

/// Request to update the provisioner state of a workspace build.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct UpdateWorkspaceBuildStateRequest {
    /// Raw provisioner state bytes (base64 encoded in JSON, matching Go []byte).
    pub state: Vec<u8>,
}

/// Workspace quota information.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct WorkspaceQuota {
    /// Credits consumed.
    pub credits_consumed: i32,
    /// Budget available.
    pub budget: i32,
}

/// Resolve autostart response.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ResolveAutostartResponse {
    /// Whether there is a parameter mismatch.
    pub parameter_mismatch: bool,
}

/// Provisioner timing entry.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ProvisionerTiming {
    /// Job identifier.
    pub job_id: Uuid,
    /// Start time.
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    /// End time.
    #[serde(with = "time::serde::rfc3339")]
    pub ended_at: OffsetDateTime,
    /// Timing stage.
    pub stage: String,
    /// Timing source.
    pub source: String,
    /// Timing action.
    pub action: String,
    /// Timing resource.
    pub resource: String,
}

/// Agent script timing entry.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct AgentScriptTiming {
    /// Start time.
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    /// End time.
    #[serde(with = "time::serde::rfc3339")]
    pub ended_at: OffsetDateTime,
    /// Exit code.
    pub exit_code: i32,
    /// Timing stage.
    pub stage: String,
    /// Status.
    pub status: String,
    /// Display name.
    pub display_name: String,
    /// Agent identifier.
    pub workspace_agent_id: String,
    /// Agent name.
    pub workspace_agent_name: String,
}

/// Agent connection timing entry.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct AgentConnectionTiming {
    /// Start time.
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    /// End time.
    #[serde(with = "time::serde::rfc3339")]
    pub ended_at: OffsetDateTime,
    /// Timing stage.
    pub stage: String,
    /// Agent identifier.
    pub workspace_agent_id: String,
    /// Agent name.
    pub workspace_agent_name: String,
}

/// Workspace build timings.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct WorkspaceBuildTimings {
    /// Provisioner timings.
    #[serde(default)]
    pub provisioner_timings: Vec<ProvisionerTiming>,
    /// Agent script timings.
    #[serde(default)]
    pub agent_script_timings: Vec<AgentScriptTiming>,
    /// Agent connection timings.
    #[serde(default)]
    pub agent_connection_timings: Vec<AgentConnectionTiming>,
}

/// Workspace ACL response.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct WorkspaceACLResponse {
    /// Users with access.
    #[serde(default)]
    pub users: Vec<WorkspaceACLUser>,
    /// Groups with access.
    #[serde(default)]
    pub groups: Vec<WorkspaceACLGroup>,
}

/// Workspace ACL user entry.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct WorkspaceACLUser {
    /// User identifier.
    pub id: Uuid,
    /// Username.
    pub username: String,
    /// Avatar URL.
    #[serde(default)]
    pub avatar_url: String,
    /// Workspace role.
    pub role: String,
}

/// Workspace ACL group entry.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct WorkspaceACLGroup {
    /// Group identifier.
    pub id: Uuid,
    /// Group name.
    pub name: String,
    /// Workspace role.
    pub role: String,
}

/// Request to update workspace ACL.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct UpdateWorkspaceACLRequest {
    /// User role mapping (UUID -> role).
    #[serde(default)]
    pub user_roles: HashMap<String, String>,
    /// Group role mapping (UUID -> role).
    #[serde(default)]
    pub group_roles: HashMap<String, String>,
}

/// Port share level.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceAgentPortShareLevel {
    /// Owner only.
    #[default]
    Owner,
    /// Authenticated users.
    Authenticated,
    /// Public access.
    Public,
}

/// Port share protocol.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceAgentPortShareProtocol {
    /// HTTP protocol.
    #[default]
    Http,
    /// HTTPS protocol.
    Https,
}

/// A single port share.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct WorkspaceAgentPortShare {
    /// Workspace identifier.
    pub workspace_id: Uuid,
    /// Agent name.
    pub agent_name: String,
    /// Shared port number.
    pub port: i32,
    /// Share level.
    pub share_level: WorkspaceAgentPortShareLevel,
    /// Protocol.
    pub protocol: WorkspaceAgentPortShareProtocol,
}

/// Multiple port shares response.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct WorkspaceAgentPortShares {
    /// Port shares list.
    pub shares: Vec<WorkspaceAgentPortShare>,
}

/// Request to upsert a port share.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct UpsertWorkspaceAgentPortShareRequest {
    /// Agent name.
    pub agent_name: String,
    /// Port number.
    pub port: i32,
    /// Share level.
    pub share_level: WorkspaceAgentPortShareLevel,
    /// Protocol.
    #[serde(default)]
    pub protocol: WorkspaceAgentPortShareProtocol,
}

/// Request to delete a port share.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct DeleteWorkspaceAgentPortShareRequest {
    /// Agent name.
    pub agent_name: String,
    /// Port number.
    pub port: i32,
}

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Template & Template Version API types
// ---------------------------------------------------------------------------

/// Transition stats for build time aggregation.
#[derive(Clone, Debug, Default, Serialize, PartialEq)]
pub struct TransitionStats {
    /// p50 build time in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p50: Option<i64>,
    /// p95 build time in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p95: Option<i64>,
}

/// Build time stats keyed by workspace transition (start/stop/delete).
pub type TemplateBuildTimeStats = HashMap<String, TransitionStats>;

/// Autostop requirement for a template (enterprise feature).
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct TemplateAutostopRequirement {
    /// Days of the week on which restarts are required.
    #[serde(default)]
    pub days_of_week: Vec<String>,
    /// Number of weeks between required restarts.
    #[serde(default)]
    pub weeks: i64,
}

/// Autostart requirement for a template (enterprise feature).
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct TemplateAutostartRequirement {
    /// Days of the week on which autostart is allowed.
    #[serde(default)]
    pub days_of_week: Vec<String>,
}

/// A Coder template response.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct TemplateResponse {
    /// Stable template identifier.
    pub id: Uuid,
    /// Template creation time.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Last update time.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    /// Owning organization identifier.
    pub organization_id: Uuid,
    /// Organization name.
    pub organization_name: String,
    /// Organization display name.
    pub organization_display_name: String,
    /// Organization icon.
    pub organization_icon: String,
    /// Template slug name.
    pub name: String,
    /// Human-friendly display name.
    pub display_name: String,
    /// Provisioner type.
    pub provisioner: String,
    /// Active template version identifier.
    pub active_version_id: Uuid,
    /// Count of active users (-1 when loading).
    pub active_user_count: i32,
    /// Build time statistics.
    pub build_time_stats: TemplateBuildTimeStats,
    /// Template description.
    pub description: String,
    /// Whether the template is deprecated.
    pub deprecated: bool,
    /// Deprecation message when deprecated.
    pub deprecation_message: String,
    /// Deletion marker.
    pub deleted: bool,
    /// Icon URL or path.
    pub icon: String,
    /// Default TTL in milliseconds.
    pub default_ttl_ms: i64,
    /// Activity bump duration in milliseconds.
    pub activity_bump_ms: i64,
    /// Autostop requirement (enterprise).
    pub autostop_requirement: TemplateAutostopRequirement,
    /// Autostart requirement (enterprise).
    pub autostart_requirement: TemplateAutostartRequirement,
    /// Creator user identifier.
    pub created_by_id: Uuid,
    /// Creator username.
    pub created_by_name: String,
    /// Whether users can autostart.
    pub allow_user_autostart: bool,
    /// Whether users can autostop.
    pub allow_user_autostop: bool,
    /// Whether users can cancel workspace jobs.
    pub allow_user_cancel_workspace_jobs: bool,
    /// Failure TTL in milliseconds.
    pub failure_ttl_ms: i64,
    /// Time til dormant in milliseconds.
    pub time_til_dormant_ms: i64,
    /// Time til dormant auto-delete in milliseconds.
    pub time_til_dormant_autodelete_ms: i64,
    /// Whether active version is required for workspace builds.
    pub require_active_version: bool,
    /// Max port share level.
    pub max_port_share_level: String,
    /// CORS behavior.
    pub cors_behavior: String,
    /// Whether to use the classic parameter flow.
    pub use_classic_parameter_flow: bool,
    /// Whether the module cache is disabled.
    pub disable_module_cache: bool,
}

/// Request to create a new template.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct CreateTemplateRequest {
    /// Template name (slug).
    pub name: String,
    /// Human-friendly display name.
    #[serde(default)]
    pub display_name: String,
    /// Template description.
    #[serde(default)]
    pub description: String,
    /// Icon URL or path.
    #[serde(default)]
    pub icon: String,
    /// ID of the template version to promote.
    pub template_version_id: Uuid,
    /// Default TTL in milliseconds.
    #[serde(default)]
    pub default_ttl_ms: i64,
    /// Activity bump in milliseconds.
    #[serde(default)]
    pub activity_bump_ms: i64,
    /// Whether users can cancel workspace jobs.
    #[serde(default = "default_true")]
    pub allow_user_cancel_workspace_jobs: bool,
    /// Whether users can autostart.
    #[serde(default = "default_true")]
    pub allow_user_autostart: bool,
    /// Whether users can autostop.
    #[serde(default = "default_true")]
    pub allow_user_autostop: bool,
    /// Whether active version is required.
    #[serde(default)]
    pub require_active_version: bool,
    /// Failure TTL in milliseconds.
    #[serde(default)]
    pub failure_ttl_ms: i64,
    /// Time til dormant in milliseconds.
    #[serde(default)]
    pub time_til_dormant_ms: i64,
    /// Time til dormant auto-delete in milliseconds.
    #[serde(default)]
    pub time_til_dormant_autodelete_ms: i64,
    /// Disable everyone group access.
    #[serde(default)]
    pub disable_everyone_group_access: bool,
    /// Max port share level.
    #[serde(default)]
    pub max_port_share_level: String,
}

fn default_true() -> bool {
    true
}

/// Request to update template metadata.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct UpdateTemplateMeta {
    /// New template name.
    #[serde(default)]
    pub name: String,
    /// New display name.
    #[serde(default)]
    pub display_name: Option<String>,
    /// New description.
    #[serde(default)]
    pub description: Option<String>,
    /// New icon.
    #[serde(default)]
    pub icon: Option<String>,
    /// New default TTL in milliseconds.
    #[serde(default)]
    pub default_ttl_ms: Option<i64>,
    /// New activity bump in milliseconds.
    #[serde(default)]
    pub activity_bump_ms: Option<i64>,
    /// Allow user autostart.
    #[serde(default)]
    pub allow_user_autostart: Option<bool>,
    /// Allow user autostop.
    #[serde(default)]
    pub allow_user_autostop: Option<bool>,
    /// Allow user cancel workspace jobs.
    #[serde(default)]
    pub allow_user_cancel_workspace_jobs: Option<bool>,
    /// Failure TTL in milliseconds.
    #[serde(default)]
    pub failure_ttl_ms: Option<i64>,
    /// Time til dormant in milliseconds.
    #[serde(default)]
    pub time_til_dormant_ms: Option<i64>,
    /// Time til dormant auto-delete in milliseconds.
    #[serde(default)]
    pub time_til_dormant_autodelete_ms: Option<i64>,
    /// Require active version.
    #[serde(default)]
    pub require_active_version: Option<bool>,
    /// Deprecation message.
    #[serde(default)]
    pub deprecation_message: Option<String>,
    /// Max port share level.
    #[serde(default)]
    pub max_port_share_level: Option<String>,
    /// CORS behavior.
    #[serde(default)]
    pub cors_behavior: Option<String>,
    /// Use classic parameter flow.
    #[serde(default)]
    pub use_classic_parameter_flow: Option<bool>,
    /// Disable module cache.
    #[serde(default)]
    pub disable_module_cache: Option<bool>,
}

/// A starter/example template.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct TemplateExample {
    /// Example identifier.
    pub id: String,
    /// URL for the example.
    pub url: String,
    /// Human-readable name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Icon URL.
    pub icon: String,
    /// Tags for the example.
    pub tags: Vec<String>,
    /// Markdown README.
    pub markdown: String,
}

/// Provisioner job status.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProvisionerJobStatus {
    /// Job is pending.
    #[default]
    Pending,
    /// Job is running.
    Running,
    /// Job succeeded.
    Succeeded,
    /// Job is being canceled.
    Canceling,
    /// Job was canceled.
    Canceled,
    /// Job failed.
    Failed,
}

impl ProvisionerJobStatus {
    /// Returns the canonical wire-format string.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Canceling => "canceling",
            Self::Canceled => "canceled",
            Self::Failed => "failed",
        }
    }

    /// Parses a status string into the enum variant.
    #[must_use]
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "running" => Some(Self::Running),
            "succeeded" => Some(Self::Succeeded),
            "canceling" => Some(Self::Canceling),
            "canceled" => Some(Self::Canceled),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

/// A provisioner job response.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct ProvisionerJobResponse {
    /// Job identifier.
    pub id: Uuid,
    /// Job creation time.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Job start time.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub started_at: Option<OffsetDateTime>,
    /// Job completion time.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub completed_at: Option<OffsetDateTime>,
    /// Job cancellation time.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub canceled_at: Option<OffsetDateTime>,
    /// Error text when the job failed.
    #[serde(default)]
    pub error: String,
    /// Current job status.
    pub status: ProvisionerJobStatus,
    /// Worker identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worker_id: Option<Uuid>,
    /// File identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_id: Option<Uuid>,
    /// Tags associated with the job.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub tags: HashMap<String, String>,
    /// Queue position (0 when not queued).
    #[serde(default)]
    pub queue_position: i32,
    /// Queue size.
    #[serde(default)]
    pub queue_size: i32,
}

/// A template version response.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct TemplateVersionResponse {
    /// Version identifier.
    pub id: Uuid,
    /// Owning template identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_id: Option<Uuid>,
    /// Organization identifier.
    pub organization_id: Uuid,
    /// Version creation time.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Version update time.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    /// Version name (slug).
    pub name: String,
    /// Commit-style message.
    pub message: String,
    /// Provisioner job information.
    pub job: ProvisionerJobResponse,
    /// README content.
    pub readme: String,
    /// User who created the version.
    pub created_by: MinimalUser,
    /// Whether the version is archived.
    pub archived: bool,
    /// Warnings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// Whether the version has an external agent.
    #[serde(default)]
    pub has_external_agent: bool,
}

/// Request to create a new template version.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct CreateTemplateVersionRequest {
    /// Template name.
    #[serde(default)]
    pub name: String,
    /// Commit-style message.
    #[serde(default)]
    pub message: String,
    /// Template ID to associate (optional for standalone versions).
    #[serde(default)]
    pub template_id: Option<Uuid>,
    /// File reference ID.
    #[serde(default)]
    pub file_id: Option<Uuid>,
    /// Source example ID.
    #[serde(default)]
    pub example_id: Option<String>,
    /// Provisioner type.
    #[serde(default)]
    pub provisioner: String,
    /// Workspace tags.
    #[serde(default)]
    pub tags: HashMap<String, String>,
    /// User-specified variable values.
    #[serde(default)]
    pub user_variable_values: Vec<VariableValue>,
}

/// A user-specified variable value for template version creation.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct VariableValue {
    /// Variable name.
    pub name: String,
    /// Variable value.
    pub value: String,
}

/// Request to update a template version.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct PatchTemplateVersionRequest {
    /// New name.
    #[serde(default)]
    pub name: String,
    /// New message.
    #[serde(default)]
    pub message: Option<String>,
}

/// A template version parameter option.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct TemplateVersionParameterOption {
    /// Option name.
    pub name: String,
    /// Option description.
    pub description: String,
    /// Option value.
    pub value: String,
    /// Option icon.
    pub icon: String,
}

/// A template version parameter.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct TemplateVersionParameter {
    /// Parameter name.
    pub name: String,
    /// Display name.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub display_name: String,
    /// Description.
    pub description: String,
    /// Plaintext description.
    pub description_plaintext: String,
    /// Parameter type.
    #[serde(rename = "type")]
    pub param_type: String,
    /// Form type.
    pub form_type: String,
    /// Whether the parameter is mutable.
    pub mutable: bool,
    /// Default value.
    pub default_value: String,
    /// Icon.
    pub icon: String,
    /// Selectable options.
    pub options: Vec<TemplateVersionParameterOption>,
    /// Validation error.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub validation_error: String,
    /// Validation regex.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub validation_regex: String,
    /// Minimum validation value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_min: Option<i32>,
    /// Maximum validation value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_max: Option<i32>,
    /// Monotonic order validation.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub validation_monotonic: String,
    /// Whether the parameter is required.
    pub required: bool,
    /// Whether the parameter is ephemeral.
    pub ephemeral: bool,
}

/// A template version variable.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct TemplateVersionVariable {
    /// Variable name.
    pub name: String,
    /// Variable description.
    pub description: String,
    /// Variable type.
    #[serde(rename = "type")]
    pub var_type: String,
    /// Variable value.
    pub value: String,
    /// Default value.
    pub default_value: String,
    /// Whether the variable is required.
    pub required: bool,
    /// Whether the variable is sensitive.
    pub sensitive: bool,
}

/// A template version preset.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct TemplateVersionPreset {
    /// Preset identifier.
    pub id: Uuid,
    /// Template version identifier.
    pub template_version_id: Uuid,
    /// Preset name.
    pub name: String,
    /// Creation time.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Whether this is the default preset.
    pub is_default: bool,
    /// Description.
    pub description: String,
    /// Icon.
    pub icon: String,
}

/// A template version preset parameter.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct TemplateVersionPresetParameter {
    /// Preset parameter identifier.
    pub id: Uuid,
    /// Owning preset identifier.
    pub template_version_preset_id: Uuid,
    /// Parameter name.
    pub name: String,
    /// Parameter value.
    pub value: String,
}

/// External auth requirement for a template version.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct TemplateVersionExternalAuth {
    /// Provider identifier.
    pub id: String,
    /// Provider type.
    #[serde(rename = "type")]
    pub provider_type: String,
    /// Display name.
    pub display_name: String,
    /// Display icon.
    pub display_icon: String,
    /// Authenticate URL.
    pub authenticate_url: String,
    /// Whether the user is authenticated.
    pub authenticated: bool,
    /// Whether the provider is optional.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub optional: bool,
}

/// Dry-run request for a template version.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct CreateTemplateVersionDryRunRequest {
    /// Workspace name.
    #[serde(default)]
    pub workspace_name: String,
    /// Parameter values.
    #[serde(default)]
    pub rich_parameter_values: Vec<WorkspaceBuildParameter>,
    /// User variable values.
    #[serde(default)]
    pub user_variable_values: Vec<VariableValue>,
}

/// A workspace build parameter value.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct WorkspaceBuildParameter {
    /// Parameter name.
    pub name: String,
    /// Parameter value.
    pub value: String,
}

/// Provisioner job log entry.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ProvisionerJobLog {
    /// Log identifier.
    pub id: i64,
    /// Log creation time.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Log source.
    pub log_source: String,
    /// Log level.
    pub log_level: String,
    /// Stage of provisioning.
    pub stage: String,
    /// Log output.
    pub output: String,
}

/// Workspace resource returned by template version resources.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct WorkspaceResource {
    /// Resource identifier.
    pub id: Uuid,
    /// Resource creation time.
    pub created_at: String,
    /// Job identifier.
    pub job_id: Uuid,
    /// Workspace transition.
    pub transition: String,
    /// Resource type.
    #[serde(rename = "type")]
    pub resource_type: String,
    /// Resource name.
    pub name: String,
    /// Whether the resource should be hidden.
    pub hide: bool,
    /// Icon.
    pub icon: String,
    /// Daily cost.
    pub daily_cost: i32,
}

/// Filter for listing templates.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct TemplateFilter {
    /// Organization identifier filter.
    #[serde(default)]
    pub organization_id: Option<Uuid>,
    /// Exact name filter.
    #[serde(default)]
    pub exact_name: Option<String>,
    /// Fuzzy name filter.
    #[serde(default, rename = "q")]
    pub search: Option<String>,
    /// Whether to include deleted templates.
    #[serde(default)]
    pub deleted: Option<bool>,
}

/// Matched provisioners information for a provisioner job.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct MatchedProvisioners {
    /// Number of provisioner daemons that matched the requested tags.
    pub count: i32,
    /// Number of matched provisioners available to take jobs.
    pub available: i32,
    /// Most recently seen time of matched provisioners.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub most_recently_seen: Option<OffsetDateTime>,
}

/// Request to update the active template version.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct UpdateActiveTemplateVersionRequest {
    /// The template version ID to promote.
    pub id: Uuid,
}

/// Request to archive unused template versions.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct ArchiveTemplateVersionsRequest {
    /// If true, archive all unused versions regardless of job status.
    #[serde(default)]
    pub all: bool,
}

/// Response from archiving unused template versions.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct ArchiveTemplateVersionsResponse {
    /// Template identifier.
    pub template_id: Uuid,
    /// IDs of archived versions.
    pub archived_ids: Vec<Uuid>,
}

/// Request to evaluate dynamic parameters for a template version.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct DynamicParametersRequest {
    /// Request identifier for matching responses.
    #[serde(default)]
    pub id: i32,
    /// Input parameter values.
    #[serde(default)]
    pub inputs: HashMap<String, String>,
    /// Owner user ID.
    #[serde(default)]
    pub owner_id: Option<Uuid>,
}

/// Response from evaluating dynamic parameters.
#[derive(Clone, Debug, Default, Serialize, PartialEq)]
pub struct DynamicParametersResponse {
    /// Matching request identifier.
    pub id: i32,
    /// Diagnostics from evaluation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<FriendlyDiagnostic>,
    /// Evaluated parameters.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parameters: Vec<Value>,
}

/// A diagnostic message from dynamic parameter evaluation.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct FriendlyDiagnostic {
    /// Severity of the diagnostic.
    pub severity: String,
    /// Summary message.
    pub summary: String,
    /// Detailed message.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

// ---------------------------------------------------------------------------
// Authorization check (POST /api/v2/authcheck)
// ---------------------------------------------------------------------------

/// Bulk authorization request body.
#[derive(Clone, Debug, Deserialize)]
pub struct AuthorizationRequest {
    /// Map of caller-chosen keys to individual permission checks.
    pub checks: HashMap<String, AuthorizationCheck>,
}

/// A single permission check within an authorization request.
#[derive(Clone, Debug, Deserialize)]
pub struct AuthorizationCheck {
    /// The object (or set of objects) to check against.
    pub object: AuthorizationObject,
    /// The RBAC action to test.
    pub action: String,
}

/// Describes the target object (or set of objects) for a permission check.
#[derive(Clone, Debug, Deserialize)]
pub struct AuthorizationObject {
    /// The RBAC resource type name.
    pub resource_type: String,
    /// Optional owner user ID (use `"me"` for the authenticated user).
    #[serde(default)]
    pub owner_id: String,
    /// Optional organization ID.
    #[serde(default)]
    pub organization_id: String,
    /// Optional specific resource ID (UUID).
    #[serde(default)]
    pub resource_id: String,
    /// If true, disregard the organization owner constraint.
    #[serde(default)]
    pub any_org: bool,
}

/// Bulk authorization response: maps each request key to a boolean result.
pub type AuthorizationResponse = HashMap<String, bool>;

// ---------------------------------------------------------------------------
// Regions
// ---------------------------------------------------------------------------

/// A workspace proxy region.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Region {
    /// Region identifier.
    pub id: Uuid,
    /// Short machine-friendly name.
    pub name: String,
    /// Human-readable display name.
    pub display_name: String,
    /// Icon URL.
    pub icon_url: String,
    /// Whether this region is healthy.
    pub healthy: bool,
    /// Base URL for path-based apps.
    pub path_app_url: String,
    /// Wildcard hostname for subdomain apps.
    pub wildcard_hostname: String,
}

/// Response containing a list of regions.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegionsResponse {
    /// Regions.
    pub regions: Vec<Region>,
}

// ---------------------------------------------------------------------------
// Custom Notifications
// ---------------------------------------------------------------------------

/// Content payload for a custom notification.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CustomNotificationContent {
    /// Title.
    pub title: String,
    /// Message.
    pub message: String,
}

/// Request to send a custom notification.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CustomNotificationRequest {
    /// Content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<CustomNotificationContent>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------
    // generate_client_name() unit tests
    // ---------------------------------------------------------------

    #[test]
    fn generate_client_name_empty_with_redirect_uri() {
        let req = OAuth2ClientRegistrationRequest {
            redirect_uris: vec!["https://myapp.example.com/callback".to_owned()],
            ..Default::default()
        };
        let name = req.generate_client_name();
        assert_eq!(name, "Client (myapp.example.com)");
    }

    #[test]
    fn generate_client_name_explicit_name() {
        let req = OAuth2ClientRegistrationRequest {
            redirect_uris: vec!["https://example.com/callback".to_owned()],
            client_name: "My App".to_owned(),
            ..Default::default()
        };
        let name = req.generate_client_name();
        assert_eq!(name, "My App");
    }

    #[test]
    fn generate_client_name_long_name_truncated_with_hash() {
        let long_name = "A".repeat(100);
        let req = OAuth2ClientRegistrationRequest {
            redirect_uris: vec!["https://example.com/callback".to_owned()],
            client_name: long_name.clone(),
            ..Default::default()
        };
        let name = req.generate_client_name();
        assert!(
            name.len() <= 64,
            "name should be at most 64 bytes, got {}",
            name.len()
        );
        assert!(name.contains('-'), "truncated name should have hash suffix");
    }

    #[test]
    fn generate_client_name_long_multibyte_name() {
        // Each emoji is 4 bytes, so 20 emojis = 80 bytes > 64
        let emoji_name = "🎉".repeat(20);
        let req = OAuth2ClientRegistrationRequest {
            redirect_uris: vec!["https://example.com/callback".to_owned()],
            client_name: emoji_name,
            ..Default::default()
        };
        let name = req.generate_client_name();
        assert!(
            name.len() <= 64,
            "name should be at most 64 bytes, got {}",
            name.len()
        );
    }

    #[test]
    fn generate_client_name_fallback_to_client_uri() {
        let req = OAuth2ClientRegistrationRequest {
            redirect_uris: vec!["https://other.example.com/callback".to_owned()],
            client_uri: "https://myapp.dev".to_owned(),
            ..Default::default()
        };
        let name = req.generate_client_name();
        assert_eq!(name, "Client (myapp.dev)");
    }

    #[test]
    fn generate_client_name_fallback_to_redirect_uri_host() {
        let req = OAuth2ClientRegistrationRequest {
            redirect_uris: vec!["https://redirect.example.org/cb".to_owned()],
            ..Default::default()
        };
        let name = req.generate_client_name();
        assert_eq!(name, "Client (redirect.example.org)");
    }

    #[test]
    fn generate_client_name_ultimate_fallback() {
        // Empty redirect_uris won't reach this in practice (validation rejects it),
        // but the function itself falls back to a default.
        let req = OAuth2ClientRegistrationRequest {
            redirect_uris: vec![],
            ..Default::default()
        };
        let name = req.generate_client_name();
        assert_eq!(name, "Dynamically Registered Client");
    }

    // ---------------------------------------------------------------
    // truncate_name_to_64() unit tests
    // ---------------------------------------------------------------

    #[test]
    fn truncate_name_short_ascii() {
        let name = "Hello World";
        let result = truncate_name_to_64(name);
        assert_eq!(result, "Hello World");
    }

    #[test]
    fn truncate_name_exactly_64_bytes() {
        let name = "A".repeat(64);
        let result = truncate_name_to_64(&name);
        assert_eq!(result.len(), 64);
        assert_eq!(result, name);
    }

    #[test]
    fn truncate_name_over_64_ascii() {
        let name = "B".repeat(100);
        let result = truncate_name_to_64(&name);
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn truncate_name_multibyte_utf8_over_64() {
        // Each '€' is 3 bytes. 22 * 3 = 66 bytes > 64
        let name = "€".repeat(22);
        let result = truncate_name_to_64(&name);
        assert!(
            result.len() <= 64,
            "result length {} exceeds 64",
            result.len()
        );
        // Should truncate to 21 * 3 = 63 bytes (can't fit 22nd char within 64)
        assert_eq!(result.len(), 63);
    }

    #[test]
    fn truncate_name_4byte_chars() {
        // Each '🎉' is 4 bytes. 17 * 4 = 68 > 64
        let name = "🎉".repeat(17);
        let result = truncate_name_to_64(&name);
        assert!(
            result.len() <= 64,
            "result length {} exceeds 64",
            result.len()
        );
        // Should truncate to 16 * 4 = 64 bytes
        assert_eq!(result.len(), 64);
    }
}

// ---------------------------------------------------------------------------
// SCIM (System for Cross-domain Identity Management) types
// ---------------------------------------------------------------------------

/// SCIM user resource used by the `/scim/v2/Users` endpoints.
///
/// Mirrors the Go `SCIMUser` struct from `enterprise/coderd/scim.go`.
/// Only the fields needed for Okta-style provisioning are included.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScimUser {
    /// SCIM schema URNs.
    #[serde(default)]
    pub schemas: Vec<String>,
    /// Stable user identifier (UUID string).
    #[serde(default)]
    pub id: String,
    /// Login username.
    #[serde(default, rename = "userName")]
    pub user_name: String,
    /// Structured name component.
    #[serde(default)]
    pub name: ScimUserName,
    /// Email addresses attached to the user.
    #[serde(default)]
    pub emails: Vec<ScimUserEmail>,
    /// Whether the user is active. Pointer semantics (Option) to distinguish
    /// absent from `false`.
    pub active: Option<bool>,
    /// Group memberships (currently unused).
    #[serde(default)]
    pub groups: Vec<Value>,
    /// SCIM resource metadata.
    #[serde(default)]
    pub meta: ScimUserMeta,
}

/// Structured name inside a SCIM user resource.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ScimUserName {
    /// Given (first) name.
    #[serde(default, rename = "givenName")]
    pub given_name: String,
    /// Family (last) name.
    #[serde(default, rename = "familyName")]
    pub family_name: String,
}

/// One email entry inside a SCIM user resource.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ScimUserEmail {
    /// Whether this is the primary email.
    #[serde(default)]
    pub primary: bool,
    /// Email address value.
    #[serde(default)]
    pub value: String,
    /// Email type label (e.g. "work").
    #[serde(default, rename = "type")]
    pub email_type: String,
    /// Display string.
    #[serde(default)]
    pub display: String,
}

/// Resource metadata inside a SCIM user resource.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ScimUserMeta {
    /// SCIM resource type.
    #[serde(default, rename = "resourceType")]
    pub resource_type: String,
}

/// SCIM list response wrapper (RFC 7644 §3.4.2).
#[derive(Clone, Debug, Serialize)]
pub struct ScimListResponse<T: Serialize> {
    /// Schema URNs for the list response.
    pub schemas: Vec<String>,
    /// Total number of results.
    #[serde(rename = "totalResults")]
    pub total_results: usize,
    /// 1-based start index.
    #[serde(rename = "startIndex")]
    pub start_index: usize,
    /// Number of items in this page.
    #[serde(rename = "itemsPerPage")]
    pub items_per_page: usize,
    /// Resource items.
    #[serde(rename = "Resources")]
    pub resources: Vec<T>,
}

/// SCIM error response (RFC 7644 §3.12).
#[derive(Clone, Debug, Serialize)]
pub struct ScimErrorResponse {
    /// Schema URNs for the error response.
    pub schemas: Vec<String>,
    /// SCIM error type.
    #[serde(rename = "scimType")]
    pub scim_type: String,
    /// Human-readable error detail.
    pub detail: String,
    /// HTTP status code.
    pub status: u16,
}

impl ScimErrorResponse {
    /// Builds a SCIM-compliant error response.
    #[must_use]
    pub fn new(status: u16, scim_type: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            schemas: vec!["urn:ietf:params:scim:api:messages:2.0:Error".to_owned()],
            scim_type: scim_type.into(),
            detail: detail.into(),
            status,
        }
    }
}

// ── Appearance configuration ────────────────────────────────────────────

/// Deployment-wide appearance configuration (enterprise feature).
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct AppearanceConfig {
    /// Custom application name shown in the UI.
    #[serde(default)]
    pub application_name: String,
    /// URL for a custom logo image.
    #[serde(default)]
    pub logo_url: String,
    /// Service banner displayed to all users.
    #[serde(default)]
    pub service_banner: ServiceBannerConfig,
    /// Announcement banners displayed to all users.
    #[serde(default)]
    pub announcement_banners: Vec<AnnouncementBannerConfig>,
}

/// Configuration for the service banner.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct ServiceBannerConfig {
    /// Whether the banner is currently displayed.
    #[serde(default)]
    pub enabled: bool,
    /// Banner message content (must be non-empty when enabled).
    #[serde(default)]
    pub message: String,
    /// CSS background colour for the banner.
    #[serde(default)]
    pub background_color: String,
}

/// Configuration for an announcement banner.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct AnnouncementBannerConfig {
    /// Whether the banner is currently displayed.
    #[serde(default)]
    pub enabled: bool,
    /// Banner message content.
    #[serde(default)]
    pub message: String,
    /// CSS background colour for the banner.
    #[serde(default)]
    pub background_color: String,
}

// ── Prebuilds settings ──────────────────────────────────────────────────

/// Workspace prebuilds reconciliation settings.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct PrebuildsSettings {
    /// When `true`, the prebuilds reconciliation loop is paused.
    #[serde(default)]
    pub reconciliation_paused: bool,
}

// ── Template ACL types ──────────────────────────────────────────────────

/// Role assigned to a user or group on a template ACL.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum TemplateRole {
    /// Full admin access to the template.
    #[serde(rename = "admin")]
    Admin,
    /// Use-only access to the template.
    #[serde(rename = "use")]
    Use,
    /// Deleted / no role (serialised as empty string).
    #[default]
    #[serde(rename = "")]
    Deleted,
}

/// Template ACL response containing users and groups with access.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct TemplateACLResponse {
    /// Users with access to the template.
    #[serde(default)]
    pub users: Vec<TemplateACLUser>,
    /// Groups with access to the template.
    #[serde(default, rename = "group")]
    pub groups: Vec<TemplateACLGroup>,
}

/// A user entry in a template ACL.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct TemplateACLUser {
    /// Full user details.
    #[serde(flatten)]
    pub user: UserResponse,
    /// Template role for this user.
    pub role: TemplateRole,
}

/// A group entry in a template ACL.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct TemplateACLGroup {
    /// Group details.
    #[serde(flatten)]
    pub group: GroupResponse,
    /// Template role for this group.
    pub role: TemplateRole,
}

/// Request to update template ACL.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct UpdateTemplateACLRequest {
    /// User permissions: mapping from user UUID string to template role.
    /// Use empty string role to remove a user.
    #[serde(default)]
    pub user_perms: HashMap<String, TemplateRole>,
    /// Group permissions: mapping from group UUID string to template role.
    /// Use empty string role to remove a group.
    #[serde(default)]
    pub group_perms: HashMap<String, TemplateRole>,
}

/// Available users and groups that can be added to a template ACL.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct ACLAvailableResponse {
    /// Users available for ACL assignment.
    #[serde(default)]
    pub users: Vec<ReducedUser>,
    /// Groups available for ACL assignment.
    #[serde(default)]
    pub groups: Vec<GroupResponse>,
}

/// Response for invalidating template presets.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct InvalidatePresetsResponse {
    /// List of presets that were invalidated.
    pub invalidated: Vec<InvalidatedPreset>,
}

/// A single invalidated preset entry.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct InvalidatedPreset {
    /// Template name.
    pub template_name: String,
    /// Template version name.
    pub template_version_name: String,
    /// Preset name.
    pub preset_name: String,
}

// ── IDP Sync settings ───────────────────────────────────────────────────

/// Group sync settings for an organization's IDP integration.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct GroupSyncSettings {
    /// Claim field name that specifies group membership.
    #[serde(default)]
    pub field: String,
    /// Map from OIDC claim values to Coder group IDs.
    #[serde(default)]
    pub mapping: HashMap<String, Vec<Uuid>>,
    /// Regex filter applied to groups returned by the OIDC provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regex_filter: Option<String>,
    /// Whether to auto-create missing groups.
    #[serde(default, rename = "auto_create_missing_groups")]
    pub auto_create_missing_groups: bool,
    /// Deprecated legacy name mapping.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_group_name_mapping: Option<HashMap<String, String>>,
}

/// Role sync settings for an organization's IDP integration.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct RoleSyncSettings {
    /// Claim field name that specifies role assignments.
    #[serde(default)]
    pub field: String,
    /// Map from OIDC claim values to Coder organization role names.
    #[serde(default)]
    pub mapping: HashMap<String, Vec<String>>,
}

/// Request to partially update group sync config (field, regex, auto-create)
/// without touching the mapping.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct PatchGroupIDPSyncConfigRequest {
    /// Claim field name.
    #[serde(default)]
    pub field: String,
    /// Regex filter.
    #[serde(default)]
    pub regex_filter: Option<String>,
    /// Whether to auto-create missing groups.
    #[serde(default, rename = "auto_create_missing_groups")]
    pub auto_create_missing_groups: bool,
}

/// A single IDP sync mapping entry mapping a claim value to a group UUID.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct IDPSyncMappingGroup {
    /// The IDP claim value the user has.
    #[serde(rename = "Given")]
    pub given: String,
    /// The Coder group ID to assign.
    #[serde(rename = "Gets")]
    pub gets: Uuid,
}

/// Request to add/remove entries in the group sync mapping.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct PatchGroupIDPSyncMappingRequest {
    /// Mappings to add.
    #[serde(rename = "Add", default)]
    pub add: Vec<IDPSyncMappingGroup>,
    /// Mappings to remove.
    #[serde(rename = "Remove", default)]
    pub remove: Vec<IDPSyncMappingGroup>,
}

/// Request to partially update role sync config (field only)
/// without touching the mapping.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct PatchRoleIDPSyncConfigRequest {
    /// Claim field name.
    #[serde(default)]
    pub field: String,
}

/// A single IDP sync mapping entry mapping a claim value to a role name.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct IDPSyncMappingRole {
    /// The IDP claim value the user has.
    #[serde(rename = "Given")]
    pub given: String,
    /// The Coder role name to assign.
    #[serde(rename = "Gets")]
    pub gets: String,
}

/// Request to add/remove entries in the role sync mapping.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct PatchRoleIDPSyncMappingRequest {
    /// Mappings to add.
    #[serde(rename = "Add", default)]
    pub add: Vec<IDPSyncMappingRole>,
    /// Mappings to remove.
    #[serde(rename = "Remove", default)]
    pub remove: Vec<IDPSyncMappingRole>,
}

// ---------------------------------------------------------------------------
// IDP Sync — Organization sync settings (deployment-level)
// ---------------------------------------------------------------------------

/// Deployment-level organization IDP sync settings.
///
/// Maps Go `codersdk.OrganizationSyncSettings`.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct OrganizationSyncSettings {
    /// The OIDC claim field used to determine organization membership.
    /// Empty string means no organization sync from the IdP.
    #[serde(default)]
    pub field: String,
    /// Mapping from OIDC claim value to Coder organization UUIDs.
    #[serde(default)]
    pub mapping: HashMap<String, Vec<Uuid>>,
    /// When true, all authenticated users are placed into the default org.
    #[serde(default, rename = "organization_assign_default")]
    pub assign_default: bool,
}

/// Request body for `PATCH /settings/idpsync/organization/config`.
///
/// Partially updates the organization sync settings (field + assign_default)
/// while preserving the existing mapping.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct PatchOrganizationIDPSyncConfigRequest {
    /// The OIDC claim field.
    #[serde(default)]
    pub field: String,
    /// Whether to assign users to the default organization.
    #[serde(default)]
    pub assign_default: bool,
}

/// A single IDP sync mapping entry (claim value → resource ID).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct IDPSyncMappingUUID {
    /// The IdP claim value the user has.
    #[serde(default, rename = "Given")]
    pub given: String,
    /// The UUID of the Coder resource the user should be added to.
    #[serde(default, rename = "Gets")]
    pub gets: Uuid,
}

/// Request body for `PATCH /settings/idpsync/organization/mapping`.
///
/// Adds and/or removes individual mapping entries.
/// If the same mapping appears in both `add` and `remove`, removal wins.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct PatchOrganizationIDPSyncMappingRequest {
    /// Mappings to add.
    #[serde(default, rename = "Add")]
    pub add: Vec<IDPSyncMappingUUID>,
    /// Mappings to remove.
    #[serde(default, rename = "Remove")]
    pub remove: Vec<IDPSyncMappingUUID>,
}
