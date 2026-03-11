//! Shared domain types, API models, and storage contracts for the Rust
//! backend rewrite.
//!
//! `coder-core` is the foundation crate of the Rust Coder backend.  It defines
//! every type that crosses crate boundaries but contains **no** business logic
//! or I/O of its own.  Higher-level crates (`coder-auth`, `coder-identity`,
//! `coder-db`, `coder-server`, …) depend on `coder-core` for their shared
//! vocabulary.
//!
//! # Modules
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`api`] | HTTP request / response models serialised to JSON |
//! | [`build_info`] | Compile-time metadata (version, git commit) |
//! | [`config`] | Runtime configuration structs (`ServerConfig`, `DatabaseConfig`, …) |
//! | [`enums`] | PostgreSQL `CREATE TYPE … AS ENUM` mirrors with `sqlx::Type` derives |
//! | [`identity`] | Domain records for users, organisations, API keys, and OAuth2 apps |
//! | [`password`] | PBKDF2-SHA256 password hashing and session-token helpers |
//! | [`ports`] | Storage trait hierarchy (`AppStore` and its sub-traits) |
//! | [`provisioner`] | Provisioner job, daemon, and key domain records |
//! | [`pubsub`] | Lightweight pub/sub trait for real-time event fan-out |
//! | [`retry`] | Configurable retry loop with exponential back-off |
//! | [`template`] | Template and template-version domain records |
//!
//! # Design Principles
//!
//! * **No unsafe code** — enforced by `#![forbid(unsafe_code)]`.
//! * **No business logic** — pure data definitions and trait contracts.
//! * **Serde-first** — API types derive `Serialize` / `Deserialize` for
//!   zero-copy JSON round-tripping.
//! * **Go parity** — types mirror the original Go SDK (`codersdk/`) so that
//!   HTTP responses are byte-for-byte compatible.
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
pub mod retry;
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
    ChatModelCallConfig, ChatModelConfigResponse, ChatProviderConfigResponse,
    ChatProviderConfigSource, ChatQueuedMessageResponse, ChatResponse, ChatStatus,
    ChatWithMessagesResponse, ConfigOption, ConvertLoginRequest, CreateChatMessageApiResponse,
    CreateChatMessageRequest, CreateChatModelConfigRequest, CreateChatProviderConfigRequest,
    CreateChatRequest, CreateFirstUserRequest, CreateFirstUserResponse, CreateLogSourceRequest,
    CreateOrganizationRequest, CreateTaskRequest, CreateTemplateRequest, CreateTestAuditLogRequest,
    CreateTokenRequest, CreateUserRequestWithOrgs, DERPMap, DERPMapRegion, DERPNode, DERPRegion,
    DatabaseHealthReport, DeleteExternalAuthByIdResponse, DeploymentConfigResponse,
    DeploymentStatsResponse, DerpHealthReport, DisplayApp, EditChatMessageRequest,
    ExternalApiKeyScopes, ExternalAuthAppInstallation, ExternalAuthDevice,
    ExternalAuthDeviceExchangeRequest, ExternalAuthLink, ExternalAuthLinkProvider,
    ExternalAuthResponse, ExternalAuthUser, GCPInstanceIdentityToken, GenerateApiKeyResponse,
    GetUsersResponse, GitSshKeyResponse, GithubAuthMethod, HealthSettings, HealthSeverity,
    HealthcheckReport, ListUserExternalAuthResponse, LogLevel, LoginWithPasswordRequest,
    LoginWithPasswordResponse, MinimalOrganization, MinimalUser, OAuth2AuthorizationServerMetadata,
    OAuth2AuthorizeRequest, OAuth2ClientConfiguration, OAuth2ClientRegistrationRequest,
    OAuth2ClientRegistrationResponse, OAuth2ErrorResponse, OAuth2ProtectedResourceMetadata,
    OAuth2ProviderAppEndpoints, OAuth2ProviderAppResponse, OAuth2ProviderAppSecretFullResponse,
    OAuth2ProviderAppSecretResponse, OAuth2TokenRequest, OAuth2TokenResponse,
    OAuth2TokenRevocationRequest, OAuthConversionResponse, OidcAuthMethod, OrganizationMember,
    OrganizationMemberWithUserData, OrganizationResponse, PaginatedMembersResponse,
    PatchAgentLogsRequest, PatchAppStatusRequest, PauseTaskResponse, PermissionResponse,
    PortShareProtocol, PostOAuth2ProviderAppRequest, ProvisionerDaemonResponse,
    ProvisionerDaemonsHealthReport, ProvisionerJobResponse, PutOAuth2ProviderAppRequest,
    ReducedUser, RequestOneTimePasscodeRequest, ResumeTaskResponse, RoleResponse,
    SessionCountDeploymentStatsResponse, SlimRole, SshConfigResponse, TaskLogEntry,
    TaskLogSnapshotEnvelope, TaskLogType, TaskLogsResponse, TaskResponse, TaskSendRequest,
    TaskState, TaskStateEntry, TaskStatus, TasksListResponse, TokenConfig,
    UpdateChatModelConfigRequest, UpdateChatProviderConfigRequest, UpdateCheckResponse,
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
    CorsConfig, DatabaseConfig, DerpNodeConfig, DerpRegionConfig, LogFormat, OtelConfig,
    PublicDatabaseConfig, PublicDeploymentConfig, ServerConfig, SshConfig,
};
pub use identity::{
    ApiKeyListFilter, ApiKeyRecord, ApiKeyScope, ApiKeyWithOwnerRecord, AuthenticatedUser,
    CreateApiKeyInput, CreateApiKeyStoreError, CreateFirstUserInput, CreateFirstUserStoreError,
    CreateGroupInput, CreateOAuth2ProviderAppInput, CreateOAuth2ProviderAppTokenInput,
    CreateOrganizationInput, CreateOrganizationStoreError, CreateUserInput, CreateUserStoreError,
    CustomRoleRecord, FirstUserRecord, GroupMemberRecord, GroupRecord,
    InsertOrganizationMemberError, LoginType, NotificationMessageRecord, NotificationMessageStatus,
    NotificationMethod, OAuth2ProviderAppCodeRecord, OAuth2ProviderAppRecord,
    OAuth2ProviderAppSecretRecord, OAuth2ProviderAppTokenRecord, OrganizationMemberListFilter,
    OrganizationMemberRecord, OrganizationRecord, PasswordUserRecord, SlimRoleRecord,
    TokenConfigRecord, UpdateOAuth2ProviderAppInput, UpdateOrganizationInput,
    UpdateOrganizationStoreError, UpsertCustomRoleInput, UpsertUserLinkInput, UserAppearanceRecord,
    UserConfigRecord, UserDeletedRecord, UserLinkClaims, UserLinkRecord, UserListFilter,
    UserPreferenceRecord, UserRecord, UserStatus, UserStatusChangeRecord,
};
pub use password::{
    PasswordError, hash_password, hash_session_token, new_session_token, normalize_real_name,
    validate_email, validate_password, validate_real_name, validate_username, verify_password,
};
pub use ports::{
    AppStore, AuditLogListFilter, AuthStore, ChatFileRecord, ChatMessageRecord,
    ChatModelConfigRecord, ChatProviderRecord, ChatQueuedMessageRecord, ChatRecord,
    CreateWorkspaceBuildInput, CreateWorkspaceInput, DeploymentMetadata, DeploymentStore,
    ExternalAuthLinkRecord, FileRecord, GitSshKeyRecord, IdentityStore, InsertAgentLogInput,
    InsertChatFileInput, InsertChatInput, InsertChatMessageInput, InsertChatModelConfigInput,
    InsertChatProviderInput, InsertFileInput, InsertFileResult, InsertTaskInput,
    InsertWorkspaceAppStatusInput, InsightsStore, OperationalStore, PersistAuditLogInput,
    ProvisionerDaemonHealthInput, ProvisionerDaemonHealthRecord, ProvisionerJobLogRecord,
    ProvisionerJobStatsInput, ProvisionerJobTimingRecord, ProvisionerStore, StorageError,
    TaskListFilter, TaskRecord, TaskSnapshotRecord, TemplateStore, UpdateChatMessageContentInput,
    UpdateChatModelConfigInput, UpdateChatProviderInput, UpsertExternalAuthLinkInput,
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
