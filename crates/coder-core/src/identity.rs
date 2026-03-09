//! Identity domain types used by the bootstrap, auth, and admin slices.

use std::{str::FromStr, time::Duration};

use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{api::ApiAllowListTarget, ports::StorageError};

/// Supported login types for the Rust identity slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
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
