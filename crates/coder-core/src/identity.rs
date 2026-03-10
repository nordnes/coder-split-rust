//! Identity domain types used by the bootstrap, auth, and admin slices.

use std::{str::FromStr, time::Duration};

use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{api::ApiAllowListTarget, ports::StorageError};

/// Supported login types for the Rust identity slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "login_type", rename_all = "snake_case")]
pub enum LoginType {
    /// Password-backed local account.
    Password,
    /// GitHub-backed account.
    Github,
    /// OIDC-backed account.
    Oidc,
    /// API-token-backed pseudo user.
    Token,
    /// Disabled login.
    None,
    /// OAuth2 provider app user.
    Oauth2ProviderApp,
}

impl LoginType {
    /// Returns the wire-format string value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Github => "github",
            Self::Oidc => "oidc",
            Self::Token => "token",
            Self::None => "none",
            Self::Oauth2ProviderApp => "oauth2_provider_app",
        }
    }
}

impl FromStr for LoginType {
    type Err = IdentityParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "password" => Ok(Self::Password),
            "github" => Ok(Self::Github),
            "oidc" => Ok(Self::Oidc),
            "token" => Ok(Self::Token),
            "none" => Ok(Self::None),
            "oauth2_provider_app" => Ok(Self::Oauth2ProviderApp),
            _ => Err(IdentityParseError::UnknownLoginType(value.to_owned())),
        }
    }
}

/// Supported user states for the Rust identity slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "user_status", rename_all = "snake_case")]
pub enum UserStatus {
    /// Active user that may log in.
    Active,
    /// Suspended user that may not log in.
    Suspended,
    /// Dormant user awaiting activation.
    Dormant,
}

impl UserStatus {
    /// Returns the wire-format string value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Dormant => "dormant",
        }
    }
}

impl FromStr for UserStatus {
    type Err = IdentityParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "active" => Ok(Self::Active),
            "suspended" => Ok(Self::Suspended),
            "dormant" => Ok(Self::Dormant),
            _ => Err(IdentityParseError::UnknownUserStatus(value.to_owned())),
        }
    }
}

/// Minimal role data kept in domain records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlimRoleRecord {
    /// Stable role name.
    pub name: String,
    /// Human-readable display name.
    pub display_name: String,
    /// Organization-scoped role identifier when applicable.
    pub organization_id: Option<Uuid>,
}

/// Full persisted user data used by list and lookup routes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserRecord {
    /// Stable user identifier.
    pub id: Uuid,
    /// Login email.
    pub email: String,
    /// Login username.
    pub username: String,
    /// Display name.
    pub name: String,
    /// Avatar URL.
    pub avatar_url: String,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Update time.
    pub updated_at: OffsetDateTime,
    /// Most recent use time when known.
    pub last_seen_at: Option<OffsetDateTime>,
    /// Organization memberships.
    pub organization_ids: Vec<Uuid>,
    /// Site-wide roles.
    pub roles: Vec<SlimRoleRecord>,
    /// Login type for the account.
    pub login_type: LoginType,
    /// Current user status.
    pub status: UserStatus,
    /// Whether the user is soft-deleted.
    pub deleted: bool,
    /// Whether the user is a system account.
    pub is_system: bool,
}

/// Persisted user identity data used by authenticated routes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedUser {
    /// Stable user identifier.
    pub id: Uuid,
    /// Login email.
    pub email: String,
    /// Login username.
    pub username: String,
    /// Display name.
    pub name: String,
    /// Avatar URL.
    pub avatar_url: String,
    /// User creation time.
    pub created_at: OffsetDateTime,
    /// User update time.
    pub updated_at: OffsetDateTime,
    /// Last seen time when known.
    pub last_seen_at: Option<OffsetDateTime>,
    /// Organization memberships.
    pub organization_ids: Vec<Uuid>,
    /// Site-wide RBAC roles.
    pub roles: Vec<SlimRoleRecord>,
    /// Organization-scoped RBAC roles in `"role_name:org_id"` format.
    pub org_roles: Vec<String>,
    /// Login type for the account.
    pub login_type: LoginType,
    /// Current user status.
    pub status: UserStatus,
}

impl From<UserRecord> for AuthenticatedUser {
    fn from(value: UserRecord) -> Self {
        Self {
            id: value.id,
            email: value.email,
            username: value.username,
            name: value.name,
            avatar_url: value.avatar_url,
            created_at: value.created_at,
            updated_at: value.updated_at,
            last_seen_at: value.last_seen_at,
            organization_ids: value.organization_ids,
            roles: value.roles,
            org_roles: vec![],
            login_type: value.login_type,
            status: value.status,
        }
    }
}

/// Persisted password-login data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasswordUserRecord {
    /// Public user summary.
    pub user: UserRecord,
    /// Encoded password hash.
    pub password_hash: String,
    /// Encoded one-time passcode hash when a reset is pending.
    pub one_time_passcode_hash: Option<String>,
    /// One-time passcode expiry when a reset is pending.
    pub one_time_passcode_expires_at: Option<OffsetDateTime>,
}

/// Persisted user appearance settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserAppearanceRecord {
    /// Selected theme preference.
    pub theme_preference: String,
    /// Selected terminal font name.
    pub terminal_font: String,
}

/// Persisted user preference settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserPreferenceRecord {
    /// Whether the task notification alert has been dismissed.
    pub task_notification_alert_dismissed: bool,
}

/// Organization row used by organization routes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrganizationRecord {
    /// Stable organization identifier.
    pub id: Uuid,
    /// Canonical organization name.
    pub name: String,
    /// Human-readable organization display name.
    pub display_name: String,
    /// Organization description.
    pub description: String,
    /// Icon URL or relative path.
    pub icon: String,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Update time.
    pub updated_at: OffsetDateTime,
    /// Whether this is the default organization.
    pub is_default: bool,
    /// Whether the organization is soft-deleted.
    pub deleted: bool,
}

/// Organization membership joined with user data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrganizationMemberRecord {
    /// Member user identifier.
    pub user_id: Uuid,
    /// Organization identifier.
    pub organization_id: Uuid,
    /// Membership creation time.
    pub created_at: OffsetDateTime,
    /// Membership update time.
    pub updated_at: OffsetDateTime,
    /// Organization-scoped roles.
    pub roles: Vec<SlimRoleRecord>,
    /// Member username.
    pub username: String,
    /// Member display name.
    pub name: String,
    /// Member avatar URL.
    pub avatar_url: String,
    /// Member email.
    pub email: String,
    /// Site-wide roles attached to the user.
    pub global_roles: Vec<SlimRoleRecord>,
}

/// API key record exposed through user token routes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiKeyRecord {
    /// Stable API key identifier.
    pub id: String,
    /// Opaque hashed secret.
    pub hashed_secret: Vec<u8>,
    /// Owning user identifier.
    pub user_id: Uuid,
    /// Last observed use time.
    pub last_used: OffsetDateTime,
    /// Expiry time.
    pub expires_at: OffsetDateTime,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Update time.
    pub updated_at: OffsetDateTime,
    /// Login type tied to the key.
    pub login_type: LoginType,
    /// Scope list.
    pub scopes: Vec<String>,
    /// Human-readable token name.
    pub token_name: String,
    /// Lifetime in seconds.
    pub lifetime_seconds: i64,
    /// Allow-list restrictions.
    pub allow_list: Vec<ApiAllowListTarget>,
}

/// API key plus owner username used by token listings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiKeyWithOwnerRecord {
    /// API key payload.
    pub key: ApiKeyRecord,
    /// Owner username.
    pub username: String,
}

/// Validated input for the first-user bootstrap flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateFirstUserInput {
    /// Login email.
    pub email: String,
    /// Login username.
    pub username: String,
    /// Display name.
    pub name: String,
    /// Encoded password hash.
    pub password_hash: String,
}

/// Success payload from the first-user bootstrap flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirstUserRecord {
    /// Identifier of the newly created user.
    pub user_id: Uuid,
    /// Organization receiving the new user.
    pub organization_id: Uuid,
}

/// Filters used by the current user listing route.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UserListFilter {
    /// Raw search query.
    pub search: String,
    /// Optional status filter.
    pub status: Option<UserStatus>,
    /// Page limit, where 0 means no limit.
    pub limit: u32,
    /// Page offset.
    pub offset: u32,
}

/// Organization member listing filters.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OrganizationMemberListFilter {
    /// Organization to list members from.
    pub organization_id: Uuid,
    /// Raw search query.
    pub search: String,
    /// Page limit, where 0 means no limit.
    pub limit: u32,
    /// Page offset.
    pub offset: u32,
}

/// API key listing filters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiKeyListFilter {
    /// Optional owning user filter.
    pub user_id: Option<Uuid>,
    /// Login type to filter by.
    pub login_type: LoginType,
    /// Whether expired keys should be included.
    pub include_expired: bool,
}

/// Input for creating an API key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateApiKeyInput {
    /// Stable API key identifier.
    pub id: String,
    /// Opaque hashed secret.
    pub hashed_secret: Vec<u8>,
    /// Owning user identifier.
    pub user_id: Uuid,
    /// Initial last-used timestamp.
    pub last_used: OffsetDateTime,
    /// Expiry timestamp.
    pub expires_at: OffsetDateTime,
    /// Creation timestamp.
    pub created_at: OffsetDateTime,
    /// Update timestamp.
    pub updated_at: OffsetDateTime,
    /// Login type tied to the key.
    pub login_type: LoginType,
    /// Scope list.
    pub scopes: Vec<String>,
    /// Human-readable token name.
    pub token_name: String,
    /// Lifetime in seconds.
    pub lifetime_seconds: i64,
    /// Allow-list restrictions.
    pub allow_list: Vec<ApiAllowListTarget>,
}

/// Input for creating a user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateUserInput {
    /// Login email.
    pub email: String,
    /// Login username.
    pub username: String,
    /// Display name.
    pub name: String,
    /// Optional encoded password hash.
    pub password_hash: Option<String>,
    /// Login type for the new account.
    pub login_type: LoginType,
    /// Initial user status.
    pub status: UserStatus,
    /// Organizations to join on creation.
    pub organization_ids: Vec<Uuid>,
}

/// Input for creating an organization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateOrganizationInput {
    /// Canonical organization name.
    pub name: String,
    /// Human-readable organization display name.
    pub display_name: String,
    /// Organization description.
    pub description: String,
    /// Icon path or URL.
    pub icon: String,
    /// Authenticated actor to add as an initial member.
    pub actor_user_id: Uuid,
}

/// Input for updating an organization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateOrganizationInput {
    /// Stable organization identifier.
    pub id: Uuid,
    /// Updated canonical name.
    pub name: String,
    /// Updated display name.
    pub display_name: String,
    /// Updated description.
    pub description: String,
    /// Updated icon path or URL.
    pub icon: String,
}

/// Token lifetime settings derived from policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenConfigRecord {
    /// Maximum allowed token lifetime.
    pub max_token_lifetime: Duration,
}

/// User creation failures surfaced by the store layer.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CreateUserStoreError {
    /// A user with the same email or username already exists.
    #[error("user already exists")]
    AlreadyExists,
    /// A storage failure occurred.
    #[error("{0}")]
    Storage(#[from] StorageError),
}

/// Organization creation failures surfaced by the store layer.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CreateOrganizationStoreError {
    /// An organization with the same name already exists.
    #[error("organization already exists")]
    AlreadyExists,
    /// A storage failure occurred.
    #[error("{0}")]
    Storage(#[from] StorageError),
}

/// Organization update failures surfaced by the store layer.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum UpdateOrganizationStoreError {
    /// An organization with the requested name already exists.
    #[error("organization already exists")]
    AlreadyExists,
    /// A storage failure occurred.
    #[error("{0}")]
    Storage(#[from] StorageError),
}

/// Errors that arise when parsing persisted identity data.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum IdentityParseError {
    /// An unknown login type was loaded from storage.
    #[error("unknown login type: {0}")]
    UnknownLoginType(String),
    /// An unknown user status was loaded from storage.
    #[error("unknown user status: {0}")]
    UnknownUserStatus(String),
}

/// First-user creation failures surfaced by the store layer.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CreateFirstUserStoreError {
    /// The deployment already has a first user.
    #[error("the initial user has already been created")]
    AlreadyExists,
    /// A storage failure occurred.
    #[error("{0}")]
    Storage(#[from] StorageError),
}

/// Organization member creation failures.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum InsertOrganizationMemberError {
    /// The membership already exists.
    #[error("the user is already a member of the organization")]
    AlreadyExists,
    /// A storage failure occurred.
    #[error("{0}")]
    Storage(#[from] StorageError),
}

/// API key creation failures.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CreateApiKeyStoreError {
    /// The token name already exists for the user.
    #[error("a token with the requested name already exists")]
    DuplicateTokenName,
    /// A storage failure occurred.
    #[error("{0}")]
    Storage(#[from] StorageError),
}

// ---------------------------------------------------------------------------
// User Identity Supplements
// ---------------------------------------------------------------------------

/// An OAuth/OIDC identity provider link for a user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserLinkRecord {
    /// Owning user identifier.
    pub user_id: Uuid,
    /// Login type of the linked provider.
    pub login_type: LoginType,
    /// Provider-side identifier for the user.
    pub linked_id: String,
    /// OAuth access token (encrypted at rest).
    pub oauth_access_token: String,
    /// OAuth refresh token (encrypted at rest).
    pub oauth_refresh_token: String,
    /// OAuth token expiry time.
    pub oauth_expiry: OffsetDateTime,
}

/// Input for upserting a user link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpsertUserLinkInput {
    /// Login type of the linked provider.
    pub login_type: LoginType,
    /// Provider-side identifier for the user.
    pub linked_id: String,
    /// OAuth access token.
    pub oauth_access_token: String,
    /// OAuth refresh token.
    pub oauth_refresh_token: String,
    /// OAuth token expiry time.
    pub oauth_expiry: OffsetDateTime,
}

/// Per-user key-value configuration entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserConfigRecord {
    /// Owning user identifier.
    pub user_id: Uuid,
    /// Configuration key.
    pub key: String,
    /// Configuration value.
    pub value: String,
}

/// Soft-delete tracking record for a deleted user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserDeletedRecord {
    /// Record identifier.
    pub id: Uuid,
    /// Deleted user identifier.
    pub user_id: Uuid,
    /// When the user was deleted.
    pub deleted_at: OffsetDateTime,
    /// Who deleted the user (if known).
    pub deleted_by: Option<Uuid>,
    /// Reason for deletion.
    pub reason: String,
}

/// A user status change audit entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserStatusChangeRecord {
    /// Record identifier.
    pub id: Uuid,
    /// User whose status changed.
    pub user_id: Uuid,
    /// The new status.
    pub new_status: UserStatus,
    /// The previous status.
    pub old_status: UserStatus,
    /// When the change occurred.
    pub changed_at: OffsetDateTime,
    /// Who initiated the change (if known).
    pub changed_by: Option<Uuid>,
    /// Reason for the change.
    pub reason: String,
}

/// A custom RBAC role defined by an administrator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomRoleRecord {
    /// Stable role name.
    pub name: String,
    /// Human-readable display name.
    pub display_name: String,
    /// Organization scope (if org-scoped).
    pub organization_id: Option<Uuid>,
    /// Site-level permissions (JSON).
    pub site_permissions: String,
    /// Organization-level permissions (JSON).
    pub org_permissions: String,
    /// User-level permissions (JSON).
    pub user_permissions: String,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Update time.
    pub updated_at: OffsetDateTime,
}

/// Input for upserting a custom role.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpsertCustomRoleInput {
    /// Stable role name.
    pub name: String,
    /// Human-readable display name.
    pub display_name: String,
    /// Organization scope (if org-scoped).
    pub organization_id: Option<Uuid>,
    /// Site-level permissions (JSON).
    pub site_permissions: String,
    /// Organization-level permissions (JSON).
    pub org_permissions: String,
    /// User-level permissions (JSON).
    pub user_permissions: String,
}

/// A user group for template ACLs and RBAC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupRecord {
    /// Stable group identifier.
    pub id: Uuid,
    /// Canonical group name.
    pub name: String,
    /// Human-readable display name.
    pub display_name: String,
    /// Owning organization.
    pub organization_id: Uuid,
    /// Avatar URL.
    pub avatar_url: String,
    /// Resource quota allowance.
    pub quota_allowance: i32,
    /// Source of group creation (e.g. "user", "oidc").
    pub source: String,
    /// Creation time.
    pub created_at: OffsetDateTime,
}

/// Input for creating a group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateGroupInput {
    /// Canonical group name.
    pub name: String,
    /// Human-readable display name.
    pub display_name: String,
    /// Owning organization.
    pub organization_id: Uuid,
    /// Avatar URL.
    pub avatar_url: String,
    /// Resource quota allowance.
    pub quota_allowance: i32,
}

/// A group membership entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupMemberRecord {
    /// Group identifier.
    pub group_id: Uuid,
    /// Member user identifier.
    pub user_id: Uuid,
}

// ---------------------------------------------------------------------------
// OAuth2 Provider
// ---------------------------------------------------------------------------

/// A registered OAuth2 provider application.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OAuth2ProviderAppRecord {
    /// Stable application identifier.
    pub id: Uuid,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Update time.
    pub updated_at: OffsetDateTime,
    /// Application name.
    pub name: String,
    /// Application icon URL.
    pub icon: String,
    /// Primary callback URL.
    pub callback_url: String,
    /// Additional redirect URIs.
    pub redirect_uris: Vec<String>,
    /// User who created the application.
    pub created_by: Uuid,
}

/// Input for creating an OAuth2 provider app.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateOAuth2ProviderAppInput {
    /// Application name.
    pub name: String,
    /// Application icon URL.
    pub icon: String,
    /// Primary callback URL.
    pub callback_url: String,
    /// User who created the application.
    pub created_by: Uuid,
}

/// Input for updating an OAuth2 provider app.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateOAuth2ProviderAppInput {
    /// Application identifier.
    pub id: Uuid,
    /// Updated name.
    pub name: String,
    /// Updated icon URL.
    pub icon: String,
    /// Updated callback URL.
    pub callback_url: String,
    /// Updated redirect URIs.
    pub redirect_uris: Vec<String>,
}

/// A secret for an OAuth2 provider application.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OAuth2ProviderAppSecretRecord {
    /// Secret identifier.
    pub id: Uuid,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Last time this secret was used.
    pub last_used_at: Option<OffsetDateTime>,
    /// Prefix for fast lookup.
    pub secret_prefix: Vec<u8>,
    /// Hashed secret.
    pub hashed_secret: Vec<u8>,
    /// Truncated display string for the UI.
    pub display_secret: String,
    /// Owning application identifier.
    pub app_id: Uuid,
}

/// An authorization code issued during the OAuth2 flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OAuth2ProviderAppCodeRecord {
    /// Code identifier.
    pub id: Uuid,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Expiry time.
    pub expires_at: OffsetDateTime,
    /// Prefix for fast lookup.
    pub secret_prefix: Vec<u8>,
    /// Hashed authorization code secret.
    pub hashed_secret: Vec<u8>,
    /// Owning application identifier.
    pub app_id: Uuid,
    /// Authorizing user identifier.
    pub user_id: Uuid,
    /// Optional resource URI.
    pub resource_uri: String,
    /// PKCE code challenge.
    pub code_challenge: String,
    /// PKCE code challenge method.
    pub code_challenge_method: String,
    /// SHA-256 hash of the OAuth2 state parameter.
    pub state_hash: Option<String>,
    /// The redirect_uri provided during authorization.
    pub redirect_uri: Option<String>,
}

/// An access token issued by the OAuth2 provider.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OAuth2ProviderAppTokenRecord {
    /// Token identifier.
    pub id: Uuid,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Expiry time.
    pub expires_at: OffsetDateTime,
    /// Hash prefix for fast lookup.
    pub hash_prefix: Vec<u8>,
    /// Hashed refresh token.
    pub refresh_hash: Vec<u8>,
    /// Owning secret identifier.
    pub app_secret_id: Uuid,
    /// Associated API key identifier.
    pub api_key_id: String,
    /// Token audience.
    pub audience: String,
    /// Owning user identifier.
    pub user_id: Uuid,
}

/// Input for creating an OAuth2 provider app token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateOAuth2ProviderAppTokenInput {
    /// Expiry time.
    pub expires_at: OffsetDateTime,
    /// Hash prefix for fast lookup.
    pub hash_prefix: Vec<u8>,
    /// Hashed refresh token.
    pub refresh_hash: Vec<u8>,
    /// Owning secret identifier.
    pub app_secret_id: Uuid,
    /// Associated API key identifier.
    pub api_key_id: String,
    /// Token audience.
    pub audience: String,
    /// Owning user identifier.
    pub user_id: Uuid,
}

// ---------------------------------------------------------------------------
// Notification dispatch
// ---------------------------------------------------------------------------

/// Notification dispatch method.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationMethod {
    /// SMTP email dispatch.
    #[serde(rename = "smtp")]
    Email,
    /// HTTP webhook dispatch.
    Webhook,
    /// In-app inbox delivery.
    Inbox,
}

/// Status of a queued notification message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationMessageStatus {
    /// Waiting to be dispatched.
    Pending,
    /// Leased by a dispatch worker (being sent).
    Leased,
    /// Successfully dispatched.
    Sent,
    /// Dispatch temporarily failed (eligible for retry).
    #[serde(rename = "temporary_failure")]
    TemporaryFailure,
    /// Dispatch permanently failed.
    #[serde(rename = "permanent_failure")]
    Failed,
}

/// A queued notification message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotificationMessageRecord {
    /// Unique message identifier.
    pub id: Uuid,
    /// Recipient user identifier.
    pub user_id: Uuid,
    /// Notification template identifier.
    pub notification_template_id: Uuid,
    /// Dispatch method.
    pub method: NotificationMethod,
    /// Current dispatch status.
    pub status: NotificationMessageStatus,
    /// Number of delivery attempts so far.
    pub attempt_count: i32,
    /// Serialized template input values (JSON).
    pub input_json: String,
    /// Targets for the notification (JSON).
    pub targets_json: String,
    /// When the message was enqueued.
    pub created_at: OffsetDateTime,
    /// When the message was last updated.
    pub updated_at: OffsetDateTime,
}
