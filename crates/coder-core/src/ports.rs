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
use crate::template::{
    CreateProvisionerJobInput, CreateTemplateInput, CreateTemplateStoreError,
    CreateTemplateVersionInput, ProvisionerJobRecord, TemplateDAURow, TemplateListFilter,
    TemplateRecord, TemplateVersionListFilter, TemplateVersionParameterRecord,
    TemplateVersionPresetParameterRecord, TemplateVersionPresetRecord, TemplateVersionRecord,
    TemplateVersionVariableRecord, UpdateTemplateMetaInput,
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
    async fn fetch_pending_notification_messages(
        &self,
        limit: u32,
    ) -> Result<Vec<NotificationMessageRecord>, StorageError> {
        let _ = limit;
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

    /// Creates a provisioner job.
    async fn insert_provisioner_job(
        &self,
        input: CreateProvisionerJobInput,
    ) -> Result<ProvisionerJobRecord, StorageError>;

    /// Finds a provisioner job by identifier.
    async fn find_provisioner_job_by_id(
        &self,
        job_id: Uuid,
    ) -> Result<Option<ProvisionerJobRecord>, StorageError>;

    /// Cancels a provisioner job.
    async fn cancel_provisioner_job(&self, job_id: Uuid) -> Result<bool, StorageError>;
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

    /// Creates a provisioner job.
    async fn insert_provisioner_job(
        &self,
        input: CreateProvisionerJobInput,
    ) -> Result<ProvisionerJobRecord, StorageError> {
        let _ = input;
        Err(StorageError::unavailable(
            "provisioner jobs are not implemented",
        ))
    }

    /// Finds a provisioner job by identifier.
    async fn find_provisioner_job_by_id(
        &self,
        job_id: Uuid,
    ) -> Result<Option<ProvisionerJobRecord>, StorageError> {
        let _ = job_id;
        Err(StorageError::unavailable(
            "provisioner jobs are not implemented",
        ))
    }

    /// Cancels a provisioner job.
    async fn cancel_provisioner_job(&self, job_id: Uuid) -> Result<bool, StorageError> {
        let _ = job_id;
        Err(StorageError::unavailable(
            "provisioner jobs are not implemented",
        ))
    }

    // ----- User identity supplements (forwarded from IdentityStore) -----

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
    async fn fetch_pending_notification_messages(
        &self,
        limit: u32,
    ) -> Result<Vec<NotificationMessageRecord>, StorageError> {
        let _ = limit;
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

    // ----- Forwarded user identity supplements -----

    async fn list_user_links(&self, user_id: Uuid) -> Result<Vec<UserLinkRecord>, StorageError> {
        AppStore::list_user_links(self, user_id).await
    }

    async fn upsert_user_link(
        &self,
        user_id: Uuid,
        input: &UpsertUserLinkInput,
    ) -> Result<UserLinkRecord, StorageError> {
        AppStore::upsert_user_link(self, user_id, input).await
    }

    async fn delete_user_link(
        &self,
        user_id: Uuid,
        login_type: crate::identity::LoginType,
    ) -> Result<bool, StorageError> {
        AppStore::delete_user_link(self, user_id, login_type).await
    }

    async fn get_user_config(
        &self,
        user_id: Uuid,
        key: &str,
    ) -> Result<Option<UserConfigRecord>, StorageError> {
        AppStore::get_user_config(self, user_id, key).await
    }

    async fn upsert_user_config(
        &self,
        user_id: Uuid,
        key: &str,
        value: &str,
    ) -> Result<UserConfigRecord, StorageError> {
        AppStore::upsert_user_config(self, user_id, key, value).await
    }

    async fn delete_user_config(&self, user_id: Uuid, key: &str) -> Result<bool, StorageError> {
        AppStore::delete_user_config(self, user_id, key).await
    }

    async fn insert_user_deleted(
        &self,
        user_id: Uuid,
        deleted_by: Option<Uuid>,
        reason: &str,
    ) -> Result<UserDeletedRecord, StorageError> {
        AppStore::insert_user_deleted(self, user_id, deleted_by, reason).await
    }

    async fn insert_user_status_change(
        &self,
        user_id: Uuid,
        old_status: UserStatus,
        new_status: UserStatus,
        changed_by: Option<Uuid>,
        reason: &str,
    ) -> Result<UserStatusChangeRecord, StorageError> {
        AppStore::insert_user_status_change(
            self, user_id, old_status, new_status, changed_by, reason,
        )
        .await
    }

    async fn list_user_status_changes(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<UserStatusChangeRecord>, StorageError> {
        AppStore::list_user_status_changes(self, user_id).await
    }

    async fn list_custom_roles(
        &self,
        organization_id: Option<Uuid>,
    ) -> Result<Vec<CustomRoleRecord>, StorageError> {
        AppStore::list_custom_roles(self, organization_id).await
    }

    async fn upsert_custom_role(
        &self,
        input: &UpsertCustomRoleInput,
    ) -> Result<CustomRoleRecord, StorageError> {
        AppStore::upsert_custom_role(self, input).await
    }

    async fn delete_custom_role(
        &self,
        name: &str,
        organization_id: Option<Uuid>,
    ) -> Result<bool, StorageError> {
        AppStore::delete_custom_role(self, name, organization_id).await
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

    async fn list_oauth2_provider_apps(
        &self,
    ) -> Result<Vec<OAuth2ProviderAppRecord>, StorageError> {
        AppStore::list_oauth2_provider_apps(self).await
    }

    async fn create_oauth2_provider_app(
        &self,
        input: &CreateOAuth2ProviderAppInput,
    ) -> Result<OAuth2ProviderAppRecord, StorageError> {
        AppStore::create_oauth2_provider_app(self, input).await
    }

    async fn find_oauth2_provider_app_by_id(
        &self,
        app_id: Uuid,
    ) -> Result<Option<OAuth2ProviderAppRecord>, StorageError> {
        AppStore::find_oauth2_provider_app_by_id(self, app_id).await
    }

    async fn update_oauth2_provider_app(
        &self,
        input: &UpdateOAuth2ProviderAppInput,
    ) -> Result<Option<OAuth2ProviderAppRecord>, StorageError> {
        AppStore::update_oauth2_provider_app(self, input).await
    }

    async fn delete_oauth2_provider_app(&self, app_id: Uuid) -> Result<bool, StorageError> {
        AppStore::delete_oauth2_provider_app(self, app_id).await
    }

    async fn list_oauth2_provider_app_secrets(
        &self,
        app_id: Uuid,
    ) -> Result<Vec<OAuth2ProviderAppSecretRecord>, StorageError> {
        AppStore::list_oauth2_provider_app_secrets(self, app_id).await
    }

    async fn create_oauth2_provider_app_secret(
        &self,
        app_id: Uuid,
        hashed_secret: &[u8],
        display_secret: &str,
    ) -> Result<OAuth2ProviderAppSecretRecord, StorageError> {
        AppStore::create_oauth2_provider_app_secret(self, app_id, hashed_secret, display_secret)
            .await
    }

    async fn delete_oauth2_provider_app_secret(
        &self,
        secret_id: Uuid,
    ) -> Result<bool, StorageError> {
        AppStore::delete_oauth2_provider_app_secret(self, secret_id).await
    }

    async fn find_oauth2_provider_app_secret_by_id(
        &self,
        secret_id: Uuid,
    ) -> Result<Option<OAuth2ProviderAppSecretRecord>, StorageError> {
        AppStore::find_oauth2_provider_app_secret_by_id(self, secret_id).await
    }

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
        AppStore::create_oauth2_provider_app_code(
            self,
            app_id,
            user_id,
            secret_prefix,
            hashed_secret,
            expires_at,
            resource_uri,
            code_challenge,
            code_challenge_method,
        )
        .await
    }

    async fn find_oauth2_provider_app_code_by_prefix(
        &self,
        secret_prefix: &[u8],
    ) -> Result<Option<OAuth2ProviderAppCodeRecord>, StorageError> {
        AppStore::find_oauth2_provider_app_code_by_prefix(self, secret_prefix).await
    }

    async fn delete_oauth2_provider_app_code(&self, code_id: Uuid) -> Result<bool, StorageError> {
        AppStore::delete_oauth2_provider_app_code(self, code_id).await
    }

    async fn create_oauth2_provider_app_token(
        &self,
        input: &CreateOAuth2ProviderAppTokenInput,
    ) -> Result<OAuth2ProviderAppTokenRecord, StorageError> {
        AppStore::create_oauth2_provider_app_token(self, input).await
    }

    async fn find_oauth2_provider_app_token_by_prefix(
        &self,
        hash_prefix: &[u8],
    ) -> Result<Option<OAuth2ProviderAppTokenRecord>, StorageError> {
        AppStore::find_oauth2_provider_app_token_by_prefix(self, hash_prefix).await
    }

    async fn find_oauth2_provider_app_token_by_refresh_hash(
        &self,
        refresh_hash: &[u8],
    ) -> Result<Option<OAuth2ProviderAppTokenRecord>, StorageError> {
        AppStore::find_oauth2_provider_app_token_by_refresh_hash(self, refresh_hash).await
    }

    async fn delete_oauth2_provider_app_token(&self, token_id: Uuid) -> Result<bool, StorageError> {
        AppStore::delete_oauth2_provider_app_token(self, token_id).await
    }

    async fn list_oauth2_provider_app_tokens_by_app_and_user(
        &self,
        app_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<OAuth2ProviderAppTokenRecord>, StorageError> {
        AppStore::list_oauth2_provider_app_tokens_by_app_and_user(self, app_id, user_id).await
    }

    async fn delete_oauth2_provider_app_tokens_by_app_and_user(
        &self,
        app_id: Uuid,
        user_id: Uuid,
    ) -> Result<u64, StorageError> {
        AppStore::delete_oauth2_provider_app_tokens_by_app_and_user(self, app_id, user_id).await
    }

    async fn fetch_pending_notification_messages(
        &self,
        limit: u32,
    ) -> Result<Vec<NotificationMessageRecord>, StorageError> {
        AppStore::fetch_pending_notification_messages(self, limit).await
    }

    async fn update_notification_message_status(
        &self,
        message_id: Uuid,
        status: crate::identity::NotificationMessageStatus,
    ) -> Result<bool, StorageError> {
        AppStore::update_notification_message_status(self, message_id, status).await
    }

    async fn increment_notification_message_attempt_count(
        &self,
        message_id: Uuid,
    ) -> Result<bool, StorageError> {
        AppStore::increment_notification_message_attempt_count(self, message_id).await
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

    // ----- Forwarded user identity supplements -----

    async fn list_user_links(&self, user_id: Uuid) -> Result<Vec<UserLinkRecord>, StorageError> {
        (**self).list_user_links(user_id).await
    }

    async fn upsert_user_link(
        &self,
        user_id: Uuid,
        input: &UpsertUserLinkInput,
    ) -> Result<UserLinkRecord, StorageError> {
        (**self).upsert_user_link(user_id, input).await
    }

    async fn delete_user_link(
        &self,
        user_id: Uuid,
        login_type: crate::identity::LoginType,
    ) -> Result<bool, StorageError> {
        (**self).delete_user_link(user_id, login_type).await
    }

    async fn get_user_config(
        &self,
        user_id: Uuid,
        key: &str,
    ) -> Result<Option<UserConfigRecord>, StorageError> {
        (**self).get_user_config(user_id, key).await
    }

    async fn upsert_user_config(
        &self,
        user_id: Uuid,
        key: &str,
        value: &str,
    ) -> Result<UserConfigRecord, StorageError> {
        (**self).upsert_user_config(user_id, key, value).await
    }

    async fn delete_user_config(&self, user_id: Uuid, key: &str) -> Result<bool, StorageError> {
        (**self).delete_user_config(user_id, key).await
    }

    async fn insert_user_deleted(
        &self,
        user_id: Uuid,
        deleted_by: Option<Uuid>,
        reason: &str,
    ) -> Result<UserDeletedRecord, StorageError> {
        (**self)
            .insert_user_deleted(user_id, deleted_by, reason)
            .await
    }

    async fn insert_user_status_change(
        &self,
        user_id: Uuid,
        old_status: UserStatus,
        new_status: UserStatus,
        changed_by: Option<Uuid>,
        reason: &str,
    ) -> Result<UserStatusChangeRecord, StorageError> {
        (**self)
            .insert_user_status_change(user_id, old_status, new_status, changed_by, reason)
            .await
    }

    async fn list_user_status_changes(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<UserStatusChangeRecord>, StorageError> {
        (**self).list_user_status_changes(user_id).await
    }

    async fn list_custom_roles(
        &self,
        organization_id: Option<Uuid>,
    ) -> Result<Vec<CustomRoleRecord>, StorageError> {
        (**self).list_custom_roles(organization_id).await
    }

    async fn upsert_custom_role(
        &self,
        input: &UpsertCustomRoleInput,
    ) -> Result<CustomRoleRecord, StorageError> {
        (**self).upsert_custom_role(input).await
    }

    async fn delete_custom_role(
        &self,
        name: &str,
        organization_id: Option<Uuid>,
    ) -> Result<bool, StorageError> {
        (**self).delete_custom_role(name, organization_id).await
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

    async fn list_oauth2_provider_apps(
        &self,
    ) -> Result<Vec<OAuth2ProviderAppRecord>, StorageError> {
        (**self).list_oauth2_provider_apps().await
    }

    async fn create_oauth2_provider_app(
        &self,
        input: &CreateOAuth2ProviderAppInput,
    ) -> Result<OAuth2ProviderAppRecord, StorageError> {
        (**self).create_oauth2_provider_app(input).await
    }

    async fn find_oauth2_provider_app_by_id(
        &self,
        app_id: Uuid,
    ) -> Result<Option<OAuth2ProviderAppRecord>, StorageError> {
        (**self).find_oauth2_provider_app_by_id(app_id).await
    }

    async fn update_oauth2_provider_app(
        &self,
        input: &UpdateOAuth2ProviderAppInput,
    ) -> Result<Option<OAuth2ProviderAppRecord>, StorageError> {
        (**self).update_oauth2_provider_app(input).await
    }

    async fn delete_oauth2_provider_app(&self, app_id: Uuid) -> Result<bool, StorageError> {
        (**self).delete_oauth2_provider_app(app_id).await
    }

    async fn list_oauth2_provider_app_secrets(
        &self,
        app_id: Uuid,
    ) -> Result<Vec<OAuth2ProviderAppSecretRecord>, StorageError> {
        (**self).list_oauth2_provider_app_secrets(app_id).await
    }

    async fn create_oauth2_provider_app_secret(
        &self,
        app_id: Uuid,
        hashed_secret: &[u8],
        display_secret: &str,
    ) -> Result<OAuth2ProviderAppSecretRecord, StorageError> {
        (**self)
            .create_oauth2_provider_app_secret(app_id, hashed_secret, display_secret)
            .await
    }

    async fn delete_oauth2_provider_app_secret(
        &self,
        secret_id: Uuid,
    ) -> Result<bool, StorageError> {
        (**self).delete_oauth2_provider_app_secret(secret_id).await
    }

    async fn find_oauth2_provider_app_secret_by_id(
        &self,
        secret_id: Uuid,
    ) -> Result<Option<OAuth2ProviderAppSecretRecord>, StorageError> {
        (**self)
            .find_oauth2_provider_app_secret_by_id(secret_id)
            .await
    }

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
        (**self)
            .create_oauth2_provider_app_code(
                app_id,
                user_id,
                secret_prefix,
                hashed_secret,
                expires_at,
                resource_uri,
                code_challenge,
                code_challenge_method,
            )
            .await
    }

    async fn find_oauth2_provider_app_code_by_prefix(
        &self,
        secret_prefix: &[u8],
    ) -> Result<Option<OAuth2ProviderAppCodeRecord>, StorageError> {
        (**self)
            .find_oauth2_provider_app_code_by_prefix(secret_prefix)
            .await
    }

    async fn delete_oauth2_provider_app_code(&self, code_id: Uuid) -> Result<bool, StorageError> {
        (**self).delete_oauth2_provider_app_code(code_id).await
    }

    async fn create_oauth2_provider_app_token(
        &self,
        input: &CreateOAuth2ProviderAppTokenInput,
    ) -> Result<OAuth2ProviderAppTokenRecord, StorageError> {
        (**self).create_oauth2_provider_app_token(input).await
    }

    async fn find_oauth2_provider_app_token_by_prefix(
        &self,
        hash_prefix: &[u8],
    ) -> Result<Option<OAuth2ProviderAppTokenRecord>, StorageError> {
        (**self)
            .find_oauth2_provider_app_token_by_prefix(hash_prefix)
            .await
    }

    async fn find_oauth2_provider_app_token_by_refresh_hash(
        &self,
        refresh_hash: &[u8],
    ) -> Result<Option<OAuth2ProviderAppTokenRecord>, StorageError> {
        (**self)
            .find_oauth2_provider_app_token_by_refresh_hash(refresh_hash)
            .await
    }

    async fn delete_oauth2_provider_app_token(&self, token_id: Uuid) -> Result<bool, StorageError> {
        (**self).delete_oauth2_provider_app_token(token_id).await
    }

    async fn list_oauth2_provider_app_tokens_by_app_and_user(
        &self,
        app_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<OAuth2ProviderAppTokenRecord>, StorageError> {
        (**self)
            .list_oauth2_provider_app_tokens_by_app_and_user(app_id, user_id)
            .await
    }

    async fn delete_oauth2_provider_app_tokens_by_app_and_user(
        &self,
        app_id: Uuid,
        user_id: Uuid,
    ) -> Result<u64, StorageError> {
        (**self)
            .delete_oauth2_provider_app_tokens_by_app_and_user(app_id, user_id)
            .await
    }

    async fn fetch_pending_notification_messages(
        &self,
        limit: u32,
    ) -> Result<Vec<NotificationMessageRecord>, StorageError> {
        (**self).fetch_pending_notification_messages(limit).await
    }

    async fn update_notification_message_status(
        &self,
        message_id: Uuid,
        status: crate::identity::NotificationMessageStatus,
    ) -> Result<bool, StorageError> {
        (**self)
            .update_notification_message_status(message_id, status)
            .await
    }

    async fn increment_notification_message_attempt_count(
        &self,
        message_id: Uuid,
    ) -> Result<bool, StorageError> {
        (**self)
            .increment_notification_message_attempt_count(message_id)
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

    async fn insert_provisioner_job(
        &self,
        input: CreateProvisionerJobInput,
    ) -> Result<ProvisionerJobRecord, StorageError> {
        AppStore::insert_provisioner_job(self, input).await
    }

    async fn find_provisioner_job_by_id(
        &self,
        job_id: Uuid,
    ) -> Result<Option<ProvisionerJobRecord>, StorageError> {
        AppStore::find_provisioner_job_by_id(self, job_id).await
    }

    async fn cancel_provisioner_job(&self, job_id: Uuid) -> Result<bool, StorageError> {
        AppStore::cancel_provisioner_job(self, job_id).await
    }
}

#[async_trait]
impl<T> TemplateStore for Arc<T>
where
    T: TemplateStore + ?Sized,
{
    async fn list_templates(
        &self,
        filter: TemplateListFilter,
    ) -> Result<Vec<TemplateRecord>, StorageError> {
        (**self).list_templates(filter).await
    }

    async fn find_template_by_id(
        &self,
        template_id: Uuid,
    ) -> Result<Option<TemplateRecord>, StorageError> {
        (**self).find_template_by_id(template_id).await
    }

    async fn find_template_by_org_and_name(
        &self,
        organization_id: Uuid,
        name: &str,
    ) -> Result<Option<TemplateRecord>, StorageError> {
        (**self)
            .find_template_by_org_and_name(organization_id, name)
            .await
    }

    async fn insert_template(
        &self,
        input: CreateTemplateInput,
    ) -> Result<TemplateRecord, CreateTemplateStoreError> {
        (**self).insert_template(input).await
    }

    async fn update_template_meta(
        &self,
        input: UpdateTemplateMetaInput,
    ) -> Result<Option<TemplateRecord>, StorageError> {
        (**self).update_template_meta(input).await
    }

    async fn soft_delete_template(&self, template_id: Uuid) -> Result<bool, StorageError> {
        (**self).soft_delete_template(template_id).await
    }

    async fn update_template_active_version(
        &self,
        template_id: Uuid,
        active_version_id: Uuid,
    ) -> Result<bool, StorageError> {
        (**self)
            .update_template_active_version(template_id, active_version_id)
            .await
    }

    async fn template_daus(&self, template_id: Uuid) -> Result<Vec<TemplateDAURow>, StorageError> {
        (**self).template_daus(template_id).await
    }

    async fn list_template_versions(
        &self,
        filter: TemplateVersionListFilter,
    ) -> Result<Vec<TemplateVersionRecord>, StorageError> {
        (**self).list_template_versions(filter).await
    }

    async fn find_template_version_by_id(
        &self,
        version_id: Uuid,
    ) -> Result<Option<TemplateVersionRecord>, StorageError> {
        (**self).find_template_version_by_id(version_id).await
    }

    async fn find_template_version_by_template_and_name(
        &self,
        template_id: Uuid,
        name: &str,
    ) -> Result<Option<TemplateVersionRecord>, StorageError> {
        (**self)
            .find_template_version_by_template_and_name(template_id, name)
            .await
    }

    async fn find_template_version_by_org_and_name(
        &self,
        organization_id: Uuid,
        template_name: &str,
        version_name: &str,
    ) -> Result<Option<TemplateVersionRecord>, StorageError> {
        (**self)
            .find_template_version_by_org_and_name(organization_id, template_name, version_name)
            .await
    }

    async fn insert_template_version(
        &self,
        input: CreateTemplateVersionInput,
    ) -> Result<TemplateVersionRecord, StorageError> {
        (**self).insert_template_version(input).await
    }

    async fn update_template_version(
        &self,
        version_id: Uuid,
        name: &str,
        message: &str,
    ) -> Result<Option<TemplateVersionRecord>, StorageError> {
        (**self)
            .update_template_version(version_id, name, message)
            .await
    }

    async fn archive_template_version(&self, version_id: Uuid) -> Result<bool, StorageError> {
        (**self).archive_template_version(version_id).await
    }

    async fn unarchive_template_version(&self, version_id: Uuid) -> Result<bool, StorageError> {
        (**self).unarchive_template_version(version_id).await
    }

    async fn list_template_version_parameters(
        &self,
        version_id: Uuid,
    ) -> Result<Vec<TemplateVersionParameterRecord>, StorageError> {
        (**self).list_template_version_parameters(version_id).await
    }

    async fn list_template_version_variables(
        &self,
        version_id: Uuid,
    ) -> Result<Vec<TemplateVersionVariableRecord>, StorageError> {
        (**self).list_template_version_variables(version_id).await
    }

    async fn list_template_version_presets(
        &self,
        version_id: Uuid,
    ) -> Result<Vec<TemplateVersionPresetRecord>, StorageError> {
        (**self).list_template_version_presets(version_id).await
    }

    async fn list_template_version_preset_parameters(
        &self,
        preset_id: Uuid,
    ) -> Result<Vec<TemplateVersionPresetParameterRecord>, StorageError> {
        (**self)
            .list_template_version_preset_parameters(preset_id)
            .await
    }

    async fn insert_provisioner_job(
        &self,
        input: CreateProvisionerJobInput,
    ) -> Result<ProvisionerJobRecord, StorageError> {
        (**self).insert_provisioner_job(input).await
    }

    async fn find_provisioner_job_by_id(
        &self,
        job_id: Uuid,
    ) -> Result<Option<ProvisionerJobRecord>, StorageError> {
        (**self).find_provisioner_job_by_id(job_id).await
    }

    async fn cancel_provisioner_job(&self, job_id: Uuid) -> Result<bool, StorageError> {
        (**self).cancel_provisioner_job(job_id).await
    }
}
