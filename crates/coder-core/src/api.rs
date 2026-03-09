//! HTTP-facing models shared across the Rust service crates.

use std::{collections::HashMap, fmt, time::Duration};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

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
    pub ssh_config_options: Vec<(String, String)>,
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

/// Provisioner job status.
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
    pub status: WorkspaceStatus,
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
    pub build_number: i32,
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

/// Build parameter.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct WorkspaceBuildParameter {
    /// Parameter name.
    pub name: String,
    /// Parameter value.
    pub value: String,
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
    /// TTL in nanoseconds.
    #[serde(default)]
    pub ttl_ns: Option<i64>,
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
    #[serde(default, rename = "group")]
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

/// Provisioner job log entry.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ProvisionerJobLog {
    /// Log identifier.
    pub id: i64,
    /// Job identifier.
    pub job_id: Uuid,
    /// Creation time.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Log source.
    pub source: String,
    /// Log level.
    pub level: String,
    /// Log stage.
    pub stage: String,
    /// Log output.
    pub output: String,
}
