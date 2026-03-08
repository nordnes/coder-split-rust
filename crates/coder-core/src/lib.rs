//! Shared domain types, API models, and storage contracts for the Rust
//! backend rewrite.
#![forbid(unsafe_code)]

pub mod api;
pub mod build_info;
pub mod config;
pub mod identity;
pub mod password;
pub mod ports;

pub use api::{
    AccessUrlHealthReport, ApiAllowListTarget, ApiKeyResponse, ApiKeyWithOwnerResponse,
    ApiResponse, AssignableRoleResponse, AuditDiff, AuditDiffField, AuditLog, AuditLogAction,
    AuditLogResponse, AuditResourceType, AuthMethod, AuthMethods, AvailableExperiments,
    BaseHealthReport, BuildInfoResponse, ChangePasswordWithOneTimePasscodeRequest, ConfigOption,
    ConvertLoginRequest, CreateFirstUserRequest, CreateFirstUserResponse,
    CreateOrganizationRequest, CreateTestAuditLogRequest, CreateTokenRequest,
    CreateUserRequestWithOrgs, DatabaseHealthReport, DeleteExternalAuthByIdResponse,
    DeploymentConfigResponse, DeploymentStatsResponse, DerpHealthReport, ExternalApiKeyScopes,
    ExternalAuthAppInstallation, ExternalAuthDevice, ExternalAuthDeviceExchangeRequest,
    ExternalAuthLink, ExternalAuthLinkProvider, ExternalAuthResponse, ExternalAuthUser,
    GenerateApiKeyResponse, GetUsersResponse, GitSshKeyResponse, GithubAuthMethod, HealthSettings,
    HealthSeverity, HealthcheckReport, ListUserExternalAuthResponse, LoginWithPasswordRequest,
    LoginWithPasswordResponse, MinimalOrganization, MinimalUser, OAuthConversionResponse,
    OidcAuthMethod, OrganizationMember, OrganizationMemberWithUserData, OrganizationResponse,
    PaginatedMembersResponse, PermissionResponse, ProvisionerDaemonsHealthReport, ReducedUser,
    RequestOneTimePasscodeRequest, RoleResponse, SessionCountDeploymentStatsResponse, SlimRole,
    SshConfigResponse, TokenConfig, UpdateCheckResponse, UpdateOrganizationRequest,
    UpdateRolesRequest, UpdateUserAppearanceSettingsRequest, UpdateUserPasswordRequest,
    UpdateUserPreferenceSettingsRequest, UpdateUserProfileRequest, UserAppearanceSettings,
    UserLoginType, UserParameter, UserPreferenceSettings, UserResponse, UserRolesResponse,
    ValidateUserPasswordRequest, ValidateUserPasswordResponse, ValidationError,
    WebsocketHealthReport, WorkspaceConnectionLatencyMs, WorkspaceDeploymentStatsResponse,
    WorkspaceProxyHealthReport,
};
pub use build_info::BuildMetadata;
pub use config::{
    DatabaseConfig, DerpNodeConfig, DerpRegionConfig, LogFormat, PublicDatabaseConfig,
    PublicDeploymentConfig, ServerConfig, SshConfig,
};
pub use identity::{
    ApiKeyListFilter, ApiKeyRecord, ApiKeyWithOwnerRecord, AuthenticatedUser, CreateApiKeyInput,
    CreateApiKeyStoreError, CreateFirstUserInput, CreateFirstUserStoreError,
    CreateOrganizationInput, CreateOrganizationStoreError, CreateUserInput, CreateUserStoreError,
    FirstUserRecord, InsertOrganizationMemberError, LoginType, OrganizationMemberListFilter,
    OrganizationMemberRecord, OrganizationRecord, PasswordUserRecord, SlimRoleRecord,
    TokenConfigRecord, UpdateOrganizationInput, UpdateOrganizationStoreError, UserAppearanceRecord,
    UserListFilter, UserPreferenceRecord, UserRecord, UserStatus,
};
pub use password::{
    PasswordError, hash_password, hash_session_token, new_session_token, normalize_real_name,
    validate_email, validate_password, validate_real_name, validate_username, verify_password,
};
pub use ports::{
    AppStore, AuditLogListFilter, AuthStore, DeploymentMetadata, DeploymentStore,
    ExternalAuthLinkRecord, GitSshKeyRecord, IdentityStore, OperationalStore, PersistAuditLogInput,
    ProvisionerDaemonHealthInput, ProvisionerDaemonHealthRecord, ProvisionerJobStatsInput,
    StorageError, UpsertExternalAuthLinkInput, WorkspaceAgentStatInput, WorkspaceBuildStatsInput,
    WorkspaceProxyHealthInput, WorkspaceProxyHealthRecord, WorkspaceStatsWorkspaceInput,
};
