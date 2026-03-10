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

/// Response returned by `POST /api/v2/files` after uploading a file.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct UploadFileResponse {
    /// The file identifier (returned as "hash" for Go SDK compatibility).
    #[serde(rename = "hash")]
    pub id: Uuid,
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

/// Response for a group.
#[derive(Clone, Debug, Serialize)]
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
    #[serde(skip_serializing_if = "String::is_empty")]
    pub avatar_url: String,
    /// Quota allowance.
    pub quota_allowance: i32,
    /// Source of creation.
    pub source: String,
    /// Member user identifiers.
    pub members: Vec<ReducedUser>,
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
// AI Tasks
// ---------------------------------------------------------------------------

/// TaskStatus represents the status of a task.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Pending,
    Initializing,
    Active,
    Paused,
    Unknown,
    Error,
}

impl TaskStatus {
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
    Working,
    Idle,
    Complete,
    Failed,
}

/// TaskStateEntry represents a single entry in the task's state history.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskStateEntry {
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    pub state: TaskState,
    pub message: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub uri: String,
}

/// Task represents a task.
#[derive(Clone, Debug, Serialize)]
pub struct TaskResponse {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub owner_id: Uuid,
    pub owner_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub owner_avatar_url: String,
    pub name: String,
    pub display_name: String,
    pub template_version_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<Uuid>,
    pub initial_prompt: String,
    pub status: TaskStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_state: Option<TaskStateEntry>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// TasksListResponse is the response for the task list endpoint.
#[derive(Clone, Debug, Serialize)]
pub struct TasksListResponse {
    pub tasks: Vec<TaskResponse>,
    pub count: usize,
}

/// CreateTaskRequest is the request to create a new task.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateTaskRequest {
    pub template_version_id: Uuid,
    pub input: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
}

/// UpdateTaskInputRequest is used to update a task's input.
#[derive(Clone, Debug, Deserialize)]
pub struct UpdateTaskInputRequest {
    pub input: String,
}

/// TaskSendRequest is used to send task input to the tasks sidebar app.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskSendRequest {
    pub input: String,
}

/// TaskLogType indicates the source of a task log entry.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TaskLogType {
    Input,
    Output,
}

/// TaskLogEntry represents a single log entry for a task.
#[derive(Clone, Debug, Serialize)]
pub struct TaskLogEntry {
    pub id: i32,
    pub content: String,
    #[serde(rename = "type")]
    pub log_type: TaskLogType,
    #[serde(with = "time::serde::rfc3339")]
    pub time: OffsetDateTime,
}

/// TaskLogsResponse contains task logs and metadata.
#[derive(Clone, Debug, Serialize)]
pub struct TaskLogsResponse {
    pub logs: Vec<TaskLogEntry>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub snapshot: bool,
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub snapshot_at: Option<OffsetDateTime>,
}

/// TaskLogSnapshotEnvelope wraps a task log snapshot posted by an agent.
#[derive(Clone, Debug, Deserialize)]
pub struct TaskLogSnapshotEnvelope {
    pub log_snapshot: Value,
}

// ---------------------------------------------------------------------------
// Chats
// ---------------------------------------------------------------------------

/// ChatStatus represents the status of a chat.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatStatus {
    Waiting,
    Pending,
    Running,
    Paused,
    Completed,
    Error,
}

impl ChatStatus {
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
    User,
    Model,
    Both,
}

/// ChatMessagePartType represents a structured message part type.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChatMessagePartType {
    #[serde(rename = "text")]
    Text,
    #[serde(rename = "reasoning")]
    Reasoning,
    #[serde(rename = "tool-call")]
    ToolCall,
    #[serde(rename = "tool-result")]
    ToolResult,
    #[serde(rename = "source")]
    Source,
    #[serde(rename = "file")]
    File,
    #[serde(rename = "file-reference")]
    FileReference,
}

/// ChatMessagePart is a structured chunk of a chat message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChatMessagePart {
    #[serde(rename = "type")]
    pub part_type: ChatMessagePartType,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub text: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tool_call_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tool_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<Value>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub args_delta: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub result_delta: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_error: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub title: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub media_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub file_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_line: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_line: Option<i32>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub content: String,
}

/// ChatMessageUsage contains token usage information for a chat message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChatMessageUsage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_tokens: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_tokens: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_creation_tokens: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_read_tokens: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_limit: Option<i64>,
}

/// ChatMessage represents a single message in a chat.
#[derive(Clone, Debug, Serialize)]
pub struct ChatMessageResponse {
    pub id: i64,
    pub chat_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_config_id: Option<Uuid>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    pub role: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub content: Vec<ChatMessagePart>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<ChatMessageUsage>,
}

/// Chat represents a chat session.
#[derive(Clone, Debug, Serialize)]
pub struct ChatResponse {
    pub id: Uuid,
    pub owner_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_chat_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_chat_id: Option<Uuid>,
    pub last_model_config_id: Uuid,
    pub title: String,
    pub status: ChatStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    pub archived: bool,
}

/// ChatQueuedMessage represents a queued message waiting to be processed.
#[derive(Clone, Debug, Serialize)]
pub struct ChatQueuedMessageResponse {
    pub id: i64,
    pub chat_id: Uuid,
    pub content: Vec<ChatMessagePart>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// ChatWithMessages is a chat along with its messages.
#[derive(Clone, Debug, Serialize)]
pub struct ChatWithMessagesResponse {
    pub chat: ChatResponse,
    pub messages: Vec<ChatMessageResponse>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub queued_messages: Vec<ChatQueuedMessageResponse>,
}

/// ChatInputPartType represents an input part type for user chat input.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChatInputPartType {
    #[serde(rename = "text")]
    Text,
    #[serde(rename = "file")]
    File,
    #[serde(rename = "file-reference")]
    FileReference,
}

/// ChatInputPart is a single user input part for creating a chat.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChatInputPart {
    #[serde(rename = "type")]
    pub part_type: ChatInputPartType,
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub file_id: Option<Uuid>,
    #[serde(default)]
    pub file_name: String,
    #[serde(default)]
    pub start_line: Option<i32>,
    #[serde(default)]
    pub end_line: Option<i32>,
    #[serde(default)]
    pub content: String,
}

/// CreateChatRequest is the request to create a new chat.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateChatRequest {
    pub content: Vec<ChatInputPart>,
    #[serde(default)]
    pub workspace_id: Option<Uuid>,
    #[serde(default)]
    pub model_config_id: Option<Uuid>,
}

/// CreateChatMessageRequest is the request to add a message to a chat.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateChatMessageRequest {
    pub content: Vec<ChatInputPart>,
    #[serde(default)]
    pub model_config_id: Option<Uuid>,
}

/// CreateChatMessageResponse is the response from adding a message.
#[derive(Clone, Debug, Serialize)]
pub struct CreateChatMessageApiResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<ChatMessageResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queued_message: Option<ChatQueuedMessageResponse>,
    pub queued: bool,
}

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

/// DAU (Daily Active Users) response for a template.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct DAUsResponse {
    /// Daily entries.
    pub entries: Vec<DAUEntry>,
    /// Timezone offset used for aggregation.
    pub tz_hour_offset: i32,
}

/// A single day's active user count.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct DAUEntry {
    /// Date in YYYY-MM-DD format.
    pub date: String,
    /// Number of active users.
    pub amount: i32,
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
