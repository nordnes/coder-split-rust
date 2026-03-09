//! Storage contracts for the Rust backend slice.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::api::{AuditLogResponse, ExternalAuthAppInstallation, ExternalAuthUser, HealthSettings};
use crate::identity::{
    ApiKeyListFilter, ApiKeyRecord, ApiKeyWithOwnerRecord, AuthenticatedUser, CreateApiKeyInput,
    CreateApiKeyStoreError, CreateFirstUserInput, CreateFirstUserStoreError, CreateUserInput,
    CreateUserStoreError, FirstUserRecord, InsertOrganizationMemberError,
    OrganizationMemberListFilter, OrganizationMemberRecord, OrganizationRecord, PasswordUserRecord,
    TokenConfigRecord, UserAppearanceRecord, UserListFilter, UserPreferenceRecord, UserRecord,
    UserStatus,
};

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
    pub tags: std::collections::HashMap<String, String>,
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
    pub tags: std::collections::HashMap<String, String>,
    /// Current daemon status.
    pub status: Option<String>,
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
}

/// Aggregate store contract used by the current Rust backend slice.
#[async_trait]
pub trait AppStore: DeploymentStore + Send + Sync {
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
        display_name: &str,
        icon: &str,
    ) -> Result<WorkspaceAgentLogSourceRow, StorageError> {
        let _ = (agent_id, display_name, icon);
        Err(StorageError::unavailable(
            "workspace agent log sources are not implemented",
        ))
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
}
