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
    ChangePasswordWithOneTimePasscodeRequest, ChatInputPart, ChatInputPartType, ChatMessagePart,
    ChatMessagePartType, ChatMessageResponse, ChatMessageUsage, ChatMessageVisibility,
    ChatQueuedMessageResponse, ChatResponse, ChatStatus, ChatWithMessagesResponse, ConfigOption,
    ConvertLoginRequest, CreateChatMessageApiResponse, CreateChatMessageRequest, CreateChatRequest,
    CreateFirstUserRequest, CreateFirstUserResponse, CreateLogSourceRequest,
    CreateOrganizationRequest, CreateTaskRequest, CreateTemplateRequest, CreateTestAuditLogRequest,
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
    PauseTaskResponse, PermissionResponse, PortShareProtocol, PostOAuth2ProviderAppRequest,
    ProvisionerDaemonResponse, ProvisionerDaemonsHealthReport, ProvisionerJobResponse,
    PutOAuth2ProviderAppRequest, ReducedUser, RequestOneTimePasscodeRequest, ResumeTaskResponse,
    RoleResponse, SessionCountDeploymentStatsResponse, SlimRole, SshConfigResponse, TaskLogEntry,
    TaskLogSnapshotEnvelope, TaskLogType, TaskLogsResponse, TaskResponse, TaskSendRequest,
    TaskState, TaskStateEntry, TaskStatus, TasksListResponse, TokenConfig, UpdateCheckResponse,
    UpdateOrganizationRequest, UpdateRolesRequest, UpdateTaskInputRequest, UpdateTemplateMeta,
    UpdateUserAppearanceSettingsRequest, UpdateUserPasswordRequest,
    UpdateUserPreferenceSettingsRequest, UpdateUserProfileRequest, UploadChatFileResponse,
    UploadFileResponse, UserAppearanceSettings, UserLoginType, UserParameter,
    UserPreferenceSettings, UserResponse, UserRolesResponse, ValidateUserPasswordRequest,
    ValidateUserPasswordResponse, ValidationError, WebsocketHealthReport, WorkspaceAgent,
    WorkspaceAgentAuthenticateResponse, WorkspaceAgentConnectionInfo, WorkspaceAgentContainer,
    WorkspaceAgentContainerPort, WorkspaceAgentDevcontainer, WorkspaceAgentExternalAuthResponse,
    WorkspaceAgentHealth, WorkspaceAgentLifecycle, WorkspaceAgentListContainersResponse,
    WorkspaceAgentListeningPort, WorkspaceAgentListeningPortsResponse, WorkspaceAgentLog,
    WorkspaceAgentLogSource, WorkspaceAgentMetadata, WorkspaceAgentScript, WorkspaceAgentStatus,
    WorkspaceApp, WorkspaceAppHealth, WorkspaceAppOpenIn, WorkspaceAppStatus,
    WorkspaceAppStatusState, WorkspaceConnectionLatencyMs, WorkspaceDeploymentStatsResponse,
    WorkspaceProxyHealthReport,
};
// Insights / Analytics & Debug types are accessed via `coder_core::api::*` in
// downstream crates that need them (e.g. coder-server).
pub use api::{
    CustomNotificationContent, CustomNotificationRequest, DeleteWebpushSubscription,
    GetInboxNotificationResponse, InboxNotification, InboxNotificationAction,
    ListInboxNotificationsResponse, NotificationMethodsResponse, NotificationPreference,
    NotificationTemplate, NotificationsSettings, Region, RegionsResponse,
    UpdateInboxNotificationReadStatusRequest, UpdateInboxNotificationReadStatusResponse,
    UpdateNotificationTemplateMethod, UpdateUserNotificationPreferences, WebpushSubscription,
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
    AppStore, AuditLogListFilter, AuthStore, ChatFileRecord, ChatMessageRecord,
    ChatQueuedMessageRecord, ChatRecord, CreateWorkspaceBuildInput, CreateWorkspaceInput,
    DeploymentMetadata, DeploymentStore, ExternalAuthLinkRecord, FileRecord, GitSshKeyRecord,
    IdentityStore, InsertAgentLogInput, InsertChatFileInput, InsertChatInput,
    InsertChatMessageInput, InsertFileInput, InsertFileResult, InsertTaskInput,
    InsertWorkspaceAppStatusInput, InsightsStore, OperationalStore, PersistAuditLogInput,
    ProvisionerDaemonHealthInput, ProvisionerDaemonHealthRecord, ProvisionerJobLogRecord,
    ProvisionerJobStatsInput, ProvisionerJobTimingRecord, ProvisionerStore, StorageError,
    TaskListFilter, TaskRecord, TaskSnapshotRecord, TemplateStore, UpsertExternalAuthLinkInput,
    UpsertPortShareInput, WebpushSubscriptionRecord, WorkspaceAgentDevcontainerRow,
    WorkspaceAgentLogRow, WorkspaceAgentLogSourceRow, WorkspaceAgentMetadataRow,
    WorkspaceAgentPortShareRecord, WorkspaceAgentRow, WorkspaceAgentScriptRow,
    WorkspaceAgentScriptTimingRow, WorkspaceAgentStatInput, WorkspaceAppRow, WorkspaceAppStatusRow,
    WorkspaceBuildParameterRecord, WorkspaceBuildRecord, WorkspaceBuildStatsInput,
    WorkspaceListFilter, WorkspaceProxyHealthInput, WorkspaceProxyHealthRecord, WorkspaceRecord,
    WorkspaceResourceMetadataRecord, WorkspaceResourceRecord, WorkspaceStatsWorkspaceInput,
    WorkspaceStore,
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
