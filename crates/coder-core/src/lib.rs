//! Shared domain types, API models, and storage contracts for the Rust
//! backend rewrite.
//!
//! `coder-core` is the foundation crate of the Rust Coder backend.  It defines
//! every type that crosses crate boundaries and provides lightweight domain
//! utilities (password hashing, retry helpers) but performs **no** external I/O.
//! Higher-level crates (`coder-auth`, `coder-identity`, `coder-db`,
//! `coder-server`, …) depend on `coder-core` for their shared vocabulary.
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
//! * **Minimal domain utilities** — data definitions, trait contracts, and
//!   lightweight helpers (password hashing, retry loops) with no external I/O.
//! * **Serde-first** — API types derive `Serialize` / `Deserialize` for
//!   zero-copy JSON round-tripping.
//! * **Go parity** — types mirror the original Go SDK (`codersdk/`) so that
//!   HTTP responses are byte-for-byte compatible.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod api;
pub mod build_info;
pub mod circuit_breaker;
pub mod config;
pub mod constants;
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
    ApiAllowListTarget, ApiKeyResponse, ApiKeyScopeMetadata, ApiKeyWithOwnerResponse, ApiResponse,
    AppHostResponse, AppSharingLevel, AssignableRoleResponse, AuditDiff, AuditDiffField, AuditLog,
    AuditLogAction, AuditLogResponse, AuditResourceType, AuthMethod, AuthMethods,
    AuthorizationCheck, AuthorizationObject, AuthorizationRequest, AuthorizationResponse,
    AvailableExperiments, AzureInstanceIdentityToken, BaseHealthReport, BuildInfoResponse,
    ChangePasswordWithOneTimePasscodeRequest, ChatInputPart, ChatInputPartType, ChatMessagePart,
    ChatMessagePartType, ChatMessageResponse, ChatMessageUsage, ChatMessageVisibility,
    ChatModelCallConfig, ChatModelConfigResponse, ChatProviderConfigResponse,
    ChatProviderConfigSource, ChatQueuedMessageResponse, ChatResponse, ChatStatus,
    ChatWithMessagesResponse, ConfigOption, ConnectionLog, ConnectionLogResponse,
    ConnectionLogSSHInfo, ConnectionLogWebInfo, ConnectionType, ConvertLoginRequest,
    CreateChatMessageApiResponse, CreateChatMessageRequest, CreateChatModelConfigRequest,
    CreateChatProviderConfigRequest, CreateChatRequest, CreateFirstUserRequest,
    CreateFirstUserResponse, CreateFirstUserTrialInfo, CreateLogSourceRequest,
    CreateOrganizationRequest, CreateTaskRequest, CreateTemplateRequest, CreateTestAuditLogRequest,
    CreateTokenRequest, CreateUserRequestWithOrgs, CustomRoleRequest, DERPMap, DERPMapRegion,
    DERPNode, DERPRegion, DatabaseHealthReport, DeleteExternalAuthByIdResponse,
    DeploymentConfigResponse, DeploymentStatsResponse, DerpHealthReport, DisplayApp,
    EditChatMessageRequest, ExternalApiKeyScopes, ExternalAuthAppInstallation, ExternalAuthDevice,
    ExternalAuthDeviceExchangeRequest, ExternalAuthLink, ExternalAuthLinkProvider,
    ExternalAuthResponse, ExternalAuthUser, GCPInstanceIdentityToken, GenerateApiKeyResponse,
    GetUsersResponse, GitSshKeyResponse, GithubAuthMethod, HealthSettings, HealthSeverity,
    HealthcheckReport, LicensorTrialRequest, ListUserExternalAuthResponse, LogLevel,
    LoginWithPasswordRequest, LoginWithPasswordResponse, MinimalOrganization, MinimalUser,
    OAuth2AuthorizationServerMetadata, OAuth2AuthorizeRequest, OAuth2ClientConfiguration,
    OAuth2ClientRegistrationRequest, OAuth2ClientRegistrationResponse, OAuth2ErrorResponse,
    OAuth2ProtectedResourceMetadata, OAuth2ProviderAppEndpoints, OAuth2ProviderAppResponse,
    OAuth2ProviderAppSecretFullResponse, OAuth2ProviderAppSecretResponse, OAuth2TokenRequest,
    OAuth2TokenResponse, OAuth2TokenRevocationRequest, OAuthConversionResponse, OidcAuthMethod,
    OrganizationMember, OrganizationMemberWithUserData, OrganizationResponse,
    PaginatedMembersResponse, PatchAgentLogsRequest, PatchAppStatusRequest, PauseTaskResponse,
    Permission, PermissionResponse, PortShareProtocol, PostOAuth2ProviderAppRequest,
    ProvisionerDaemonResponse, ProvisionerDaemonsHealthReport, ProvisionerJobResponse,
    PutOAuth2ProviderAppRequest, ReducedUser, RequestOneTimePasscodeRequest, ResumeTaskResponse,
    RoleResponse, SessionCountDeploymentStatsResponse, SlimRole, SshConfigResponse, TaskLogEntry,
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
    CreateWorkspaceProxyRequest, CryptoKeyResponse, CryptoKeysResponse, CustomNotificationContent,
    CustomNotificationRequest, DeleteWebpushSubscription, DeregisterWorkspaceProxyRequest,
    GetInboxNotificationResponse, InboxNotification, InboxNotificationAction,
    IssueSignedAppTokenRequest, IssueSignedAppTokenResponse, ListInboxNotificationsResponse,
    NotificationMethodsResponse, NotificationPreference, NotificationTemplate,
    NotificationsSettings, PatchWorkspaceProxyRequest, ProxyHealthReport, ProxyHealthStatus,
    Region, RegionsResponse, RegisterWorkspaceProxyRequest, RegisterWorkspaceProxyResponse,
    ReplicaResponse, ReportAppStatsRequest, UpdateInboxNotificationReadStatusRequest,
    UpdateInboxNotificationReadStatusResponse, UpdateNotificationTemplateMethod,
    UpdateUserNotificationPreferences, UpdateWorkspaceProxyResponse, WebpushSubscription,
    WorkspaceProxyResponse, WorkspaceProxyStatus,
};
pub use build_info::BuildMetadata;
pub use circuit_breaker::{
    CircuitBreaker, CircuitBreakerCallError, CircuitBreakerConfig, CircuitBreakerOpen,
    CircuitBreakerRegistry, CircuitBreakerState, CircuitBreakerStatus,
};
pub use config::{
    CorsConfig, DatabaseConfig, DerpNodeConfig, DerpRegionConfig, LogFormat, OtelConfig,
    PublicDatabaseConfig, PublicDeploymentConfig, PublicProvisionerConfig, PublicTelemetryConfig,
    PublicTlsConfig, ServerConfig, SshConfig,
};
pub use constants::{
    PREBUILDS_SYSTEM_USER_ID, TEMPLATE_CUSTOM_NOTIFICATION,
    TEMPLATE_PREBUILD_FAILURE_LIMIT_REACHED, TEMPLATE_TASK_COMPLETED, TEMPLATE_TASK_FAILED,
    TEMPLATE_TASK_IDLE, TEMPLATE_TASK_PAUSED, TEMPLATE_TASK_RESUMED, TEMPLATE_TASK_WORKING,
    TEMPLATE_TEMPLATE_DELETED, TEMPLATE_TEMPLATE_DEPRECATED, TEMPLATE_TEST_NOTIFICATION,
    TEMPLATE_USER_ACCOUNT_ACTIVATED, TEMPLATE_USER_ACCOUNT_CREATED, TEMPLATE_USER_ACCOUNT_DELETED,
    TEMPLATE_USER_ACCOUNT_SUSPENDED, TEMPLATE_USER_REQUESTED_ONE_TIME_PASSCODE,
    TEMPLATE_WORKSPACE_AUTO_UPDATED, TEMPLATE_WORKSPACE_AUTOBUILD_FAILED,
    TEMPLATE_WORKSPACE_BUILDS_FAILED_REPORT, TEMPLATE_WORKSPACE_CREATED,
    TEMPLATE_WORKSPACE_DELETED, TEMPLATE_WORKSPACE_DORMANT, TEMPLATE_WORKSPACE_MANUAL_BUILD_FAILED,
    TEMPLATE_WORKSPACE_MANUALLY_UPDATED, TEMPLATE_WORKSPACE_MARKED_FOR_DELETION,
    TEMPLATE_WORKSPACE_OUT_OF_DISK, TEMPLATE_WORKSPACE_OUT_OF_MEMORY,
    TEMPLATE_WORKSPACE_RESOURCE_REPLACED, TEMPLATE_YOUR_ACCOUNT_ACTIVATED,
    TEMPLATE_YOUR_ACCOUNT_SUSPENDED,
};
pub use identity::{
    ApiKeyListFilter, ApiKeyRecord, ApiKeyScope, ApiKeyWithOwnerRecord, AuthenticatedUser,
    CreateApiKeyInput, CreateApiKeyStoreError, CreateFirstUserInput, CreateFirstUserStoreError,
    CreateGroupInput, CreateOAuth2ProviderAppInput, CreateOAuth2ProviderAppTokenInput,
    CreateOrganizationInput, CreateOrganizationStoreError, CreateUserInput, CreateUserStoreError,
    CustomRoleRecord, FirstUserRecord, GroupMemberRecord, GroupRecord,
    InsertOrganizationMemberError, LoginType, NotificationMessageRecord, NotificationMessageStatus,
    NotificationMethod, OAuth2ProviderAppCodeRecord, OAuth2ProviderAppRecord,
    OAuth2ProviderAppSecretRecord, OAuth2ProviderAppTokenRecord, OrgResourceCounts,
    OrganizationMemberListFilter, OrganizationMemberRecord, OrganizationRecord, PasswordUserRecord,
    SlimRoleRecord, TokenConfigRecord, UpdateGroupInput, UpdateOAuth2ProviderAppInput,
    UpdateOrganizationInput, UpdateOrganizationStoreError, UpsertCustomRoleInput,
    UpsertUserLinkInput, UserAppearanceRecord, UserConfigRecord, UserDeletedRecord, UserLinkClaims,
    UserLinkRecord, UserListFilter, UserPreferenceRecord, UserRecord, UserStatus,
    UserStatusChangeRecord, WorkspaceSharingMode,
};
pub use password::{
    PasswordError, hash_password, hash_session_token, new_session_token, normalize_real_name,
    validate_email, validate_password, validate_real_name, validate_username, verify_password,
};
pub use ports::{
    AdvisoryLock, AppStore, AuditLogListFilter, AuthStore, ChatFileRecord, ChatMessageRecord,
    ChatModelConfigRecord, ChatProviderRecord, ChatQueuedMessageRecord, ChatRecord,
    CoderdReplicaRow, ConnectionLogListFilter, CreateWorkspaceBuildInput, CreateWorkspaceInput,
    CreateWorkspaceProxyInput, CryptoKeyRow, DeploymentMetadata, DeploymentStore,
    ExternalAuthLinkRecord, FileRecord, GitSshKeyRecord, IdentityStore, InsertAgentLogInput,
    InsertChatFileInput, InsertChatInput, InsertChatMessageInput, InsertChatModelConfigInput,
    InsertChatProviderInput, InsertCoderdReplicaInput, InsertFileInput, InsertFileResult,
    InsertTaskInput, InsertWorkspaceAppStatusInput, InsightsStore, LicenseRecord, OperationalStore,
    PersistAuditLogInput, ProvisionerDaemonHealthInput, ProvisionerDaemonHealthRecord,
    ProvisionerJobLogRecord, ProvisionerJobStatsInput, ProvisionerJobTimingRecord,
    ProvisionerStore, ReplicaRow, StorageError, TaskListFilter, TaskRecord, TaskSnapshotRecord,
    TemplateStore, UpdateChatMessageContentInput, UpdateChatModelConfigInput,
    UpdateChatProviderInput, UpdateWorkspaceProxyInput, UpdateWorkspaceProxyRegistrationInput,
    UpsertAgentMetadataEntry, UpsertExternalAuthLinkInput, UpsertPortShareInput,
    UpsertReplicaInput, WebpushSubscriptionRecord, WorkspaceAgentDevcontainerRow,
    WorkspaceAgentLogRow, WorkspaceAgentLogSourceRow, WorkspaceAgentMetadataRow,
    WorkspaceAgentPortShareRecord, WorkspaceAgentRow, WorkspaceAgentScriptRow,
    WorkspaceAgentScriptTimingRow, WorkspaceAgentStatInput, WorkspaceAppHealthcheckTarget,
    WorkspaceAppRow, WorkspaceAppStatusRow, WorkspaceBuildParameterRecord, WorkspaceBuildRecord,
    WorkspaceBuildStatsInput, WorkspaceListFilter, WorkspaceProxyHealthInput,
    WorkspaceProxyHealthRecord, WorkspaceProxyRow, WorkspaceRecord,
    WorkspaceResourceMetadataRecord, WorkspaceResourceRecord, WorkspaceStatsWorkspaceInput,
    WorkspaceStore,
};
pub use provisioner::{
    AcquireProvisionerJobInput, CancelProvisionerJobInput, CompleteProvisionerJobInput,
    GetJobsToBeReapedInput, InsertProvisionerJobInput, InsertProvisionerJobLogsInput,
    InsertProvisionerJobTimingsInput, InsertProvisionerKeyInput, ProvisionerDaemonRecord,
    ProvisionerJobRecord, ProvisionerJobStatus, ProvisionerJobTimingStage, ProvisionerJobType,
    ProvisionerKeyRecord, ProvisionerStorageMethod, ProvisionerType, SCOPE_ORGANIZATION,
    SCOPE_USER, TAG_OWNER, TAG_SCOPE, UpsertProvisionerDaemonInput, mutate_tags,
    provisioner_tagset_matches, tags_from_json,
};
pub use template::{
    CreateProvisionerJobInput, CreateTemplateInput, CreateTemplateStoreError,
    CreateTemplateVersionInput, TemplateDAURow, TemplateListFilter, TemplateRecord,
    TemplateVersionListFilter, TemplateVersionParameterRecord,
    TemplateVersionPresetParameterRecord, TemplateVersionPresetRecord, TemplateVersionRecord,
    TemplateVersionVariableRecord, UpdateTemplateMetaInput,
};
