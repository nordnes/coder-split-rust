//! Shared domain types, API models, and storage contracts for the Rust
//! backend rewrite.
#![forbid(unsafe_code)]

pub mod api;
pub mod build_info;
pub mod config;
pub mod enums;
pub mod identity;
pub mod password;
pub mod ports;
pub mod provisioner;
pub mod pubsub;
pub mod template;

pub use api::{
    AWSInstanceIdentityToken, AccessUrlHealthReport, AgentLogEntry, AgentSubsystem,
    ApiAllowListTarget, ApiKeyResponse, ApiKeyWithOwnerResponse, ApiResponse, AppHostResponse,
    AppSharingLevel, AssignableRoleResponse, AuditDiff, AuditDiffField, AuditLog, AuditLogAction,
    AuditLogResponse, AuditResourceType, AuthMethod, AuthMethods, AuthorizationCheck,
    AuthorizationObject, AuthorizationRequest, AuthorizationResponse, AvailableExperiments,
    AzureInstanceIdentityToken, BaseHealthReport, BuildInfoResponse,
    ChangePasswordWithOneTimePasscodeRequest, ConfigOption, ConvertLoginRequest,
    CreateFirstUserRequest, CreateFirstUserResponse, CreateLogSourceRequest,
    CreateOrganizationRequest, CreateTemplateRequest, CreateTestAuditLogRequest,
    CreateTokenRequest, CreateUserRequestWithOrgs, DERPMap, DERPMapRegion, DERPNode, DERPRegion,
    DatabaseHealthReport, DeleteExternalAuthByIdResponse, DeploymentConfigResponse,
    DeploymentStatsResponse, DerpHealthReport, DisplayApp, ExternalApiKeyScopes,
    ExternalAuthAppInstallation, ExternalAuthDevice, ExternalAuthDeviceExchangeRequest,
    ExternalAuthLink, ExternalAuthLinkProvider, ExternalAuthResponse, ExternalAuthUser,
    GCPInstanceIdentityToken, GenerateApiKeyResponse, GetUsersResponse, GitSshKeyResponse,
    GithubAuthMethod, HealthSettings, HealthSeverity, HealthcheckReport,
    ListUserExternalAuthResponse, LogLevel, LoginWithPasswordRequest, LoginWithPasswordResponse,
    MinimalOrganization, MinimalUser, OAuth2AuthorizeRequest, OAuth2ProviderAppEndpoints,
    OAuth2ProviderAppResponse, OAuth2ProviderAppSecretFullResponse,
    OAuth2ProviderAppSecretResponse, OAuth2TokenRequest, OAuth2TokenResponse,
    OAuthConversionResponse, OidcAuthMethod, OrganizationMember, OrganizationMemberWithUserData,
    OrganizationResponse, PaginatedMembersResponse, PatchAgentLogsRequest, PatchAppStatusRequest,
    PermissionResponse, PortShareProtocol, PostOAuth2ProviderAppRequest, ProvisionerDaemonResponse,
    ProvisionerDaemonsHealthReport, ProvisionerJobLogResponse, ProvisionerJobResponse,
    PutOAuth2ProviderAppRequest, ReducedUser, RequestOneTimePasscodeRequest, RoleResponse,
    SessionCountDeploymentStatsResponse, SlimRole, SshConfigResponse, TokenConfig,
    UpdateCheckResponse, UpdateOrganizationRequest, UpdateRolesRequest, UpdateTemplateMeta,
    UpdateUserAppearanceSettingsRequest, UpdateUserPasswordRequest,
    UpdateUserPreferenceSettingsRequest, UpdateUserProfileRequest, UploadFileResponse,
    UserAppearanceSettings, UserLoginType, UserParameter, UserPreferenceSettings, UserResponse,
    UserRolesResponse, ValidateUserPasswordRequest, ValidateUserPasswordResponse, ValidationError,
    WebsocketHealthReport, WorkspaceAgent, WorkspaceAgentAuthenticateResponse,
    WorkspaceAgentConnectionInfo, WorkspaceAgentContainer, WorkspaceAgentContainerPort,
    WorkspaceAgentDevcontainer, WorkspaceAgentExternalAuthResponse, WorkspaceAgentHealth,
    WorkspaceAgentLifecycle, WorkspaceAgentListContainersResponse, WorkspaceAgentListeningPort,
    WorkspaceAgentListeningPortsResponse, WorkspaceAgentLog, WorkspaceAgentLogSource,
    WorkspaceAgentMetadata, WorkspaceAgentScript, WorkspaceAgentStatus, WorkspaceApp,
    WorkspaceAppHealth, WorkspaceAppOpenIn, WorkspaceAppStatus, WorkspaceAppStatusState,
    WorkspaceConnectionLatencyMs, WorkspaceDeploymentStatsResponse, WorkspaceProxyHealthReport,
};
pub use build_info::BuildMetadata;
pub use config::{
    DatabaseConfig, DerpNodeConfig, DerpRegionConfig, LogFormat, PublicDatabaseConfig,
    PublicDeploymentConfig, ServerConfig, SshConfig,
};
pub use identity::{
    ApiKeyListFilter, ApiKeyRecord, ApiKeyWithOwnerRecord, AuthenticatedUser, CreateApiKeyInput,
    CreateApiKeyStoreError, CreateFirstUserInput, CreateFirstUserStoreError, CreateGroupInput,
    CreateOrganizationInput, CreateOrganizationStoreError, CreateUserInput, CreateUserStoreError,
    CustomRoleRecord, FirstUserRecord, GroupMemberRecord, GroupRecord,
    InsertOrganizationMemberError, LoginType, OrganizationMemberListFilter,
    OrganizationMemberRecord, OrganizationRecord, PasswordUserRecord, SlimRoleRecord,
    TokenConfigRecord, UpdateOrganizationInput, UpdateOrganizationStoreError,
    UpsertCustomRoleInput, UpsertUserLinkInput, UserAppearanceRecord, UserConfigRecord,
    UserDeletedRecord, UserLinkRecord, UserListFilter, UserPreferenceRecord, UserRecord,
    UserStatus, UserStatusChangeRecord,
};
pub use password::{
    PasswordError, hash_password, hash_session_token, new_session_token, normalize_real_name,
    validate_email, validate_password, validate_real_name, validate_username, verify_password,
};
pub use ports::{
    AppStore, AuditLogListFilter, AuthStore, CreateWorkspaceBuildInput, CreateWorkspaceInput,
    DeploymentMetadata, DeploymentStore, ExternalAuthLinkRecord, FileRecord, GitSshKeyRecord,
    IdentityStore, InsertAgentLogInput, InsertFileInput, InsertFileResult,
    InsertWorkspaceAppStatusInput, OperationalStore, PersistAuditLogInput,
    ProvisionerDaemonHealthInput, ProvisionerDaemonHealthRecord, ProvisionerJobLogRecord,
    ProvisionerJobStatsInput, ProvisionerJobTimingRecord, ProvisionerStore, StorageError,
    TemplateStore, UpsertExternalAuthLinkInput, UpsertPortShareInput,
    WorkspaceAgentDevcontainerRow, WorkspaceAgentLogRow, WorkspaceAgentLogSourceRow,
    WorkspaceAgentMetadataRow, WorkspaceAgentPortShareRecord, WorkspaceAgentRow,
    WorkspaceAgentScriptRow, WorkspaceAgentStatInput, WorkspaceAppRow, WorkspaceAppStatusRow,
    WorkspaceBuildParameterRecord, WorkspaceBuildRecord, WorkspaceBuildStatsInput,
    WorkspaceListFilter, WorkspaceProxyHealthInput, WorkspaceProxyHealthRecord, WorkspaceRecord,
    WorkspaceResourceRecord, WorkspaceStatsWorkspaceInput, WorkspaceStore,
};
pub use provisioner::{
    AcquireProvisionerJobInput, CancelProvisionerJobInput, CompleteProvisionerJobInput,
    GetJobsToBeReapedInput, InsertProvisionerJobInput, InsertProvisionerJobLogsInput,
    InsertProvisionerJobTimingsInput, InsertProvisionerKeyInput, ProvisionerDaemonRecord,
    ProvisionerJobRecord, ProvisionerJobStatus, ProvisionerJobTimingStage, ProvisionerJobType,
    ProvisionerKeyRecord, ProvisionerStorageMethod, ProvisionerType, UpsertProvisionerDaemonInput,
};
pub use template::{
    CreateProvisionerJobInput, CreateTemplateInput, CreateTemplateStoreError,
    CreateTemplateVersionInput, TemplateDAURow, TemplateListFilter, TemplateRecord,
    TemplateVersionListFilter, TemplateVersionParameterRecord,
    TemplateVersionPresetParameterRecord, TemplateVersionPresetRecord, TemplateVersionRecord,
    TemplateVersionVariableRecord, UpdateTemplateMetaInput,
};
