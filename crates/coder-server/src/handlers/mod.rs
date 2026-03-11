//! Domain-specific handler modules.

pub(crate) use crate::app::*;
pub(crate) use crate::error::AppError;
pub(crate) use crate::helpers::*;

use std::{collections::HashMap, str::FromStr, sync::Arc};

use axum::{
    Form, Json,
    body::Bytes,
    extract::{
        OriginalUri, Path, Query, State,
        rejection::JsonRejection,
        ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
    },
    http::{
        HeaderMap, HeaderName, HeaderValue, StatusCode,
        header::{CONTENT_TYPE, LOCATION},
    },
    response::{IntoResponse, Response},
};
use coder_audit::AuditAction;
use coder_auth::{
    OAUTH2_REDIRECT_COOKIE, OAUTH2_STATE_COOKIE, OAuth2ProviderError, cookie_from_headers,
    supported_auth_methods,
};
use coder_connectivity::agents::{AgentConnection, AgentError, AgentProvider};
use coder_core::StorageError;
use coder_core::api::{
    ArchiveTemplateVersionsRequest, ArchiveTemplateVersionsResponse, CreateTemplateRequest,
    CreateTemplateVersionDryRunRequest, CreateTemplateVersionRequest, DAUEntry, DAUsResponse,
    DynamicParametersRequest, DynamicParametersResponse, MatchedProvisioners, MinimalUser,
    PatchTemplateVersionRequest, ProvisionerJobLog, ProvisionerJobResponse, ProvisionerJobStatus,
    TemplateExample, TemplateFilter, TemplateResponse, TemplateVersionExternalAuth,
    TemplateVersionParameter, TemplateVersionPreset, TemplateVersionPresetParameter,
    TemplateVersionResponse, TemplateVersionVariable, UpdateActiveTemplateVersionRequest,
    UpdateTemplateMeta, WorkspaceBuildParameter, WorkspaceResource, WorkspaceResourceMetadata,
    WorkspaceResourceResponse,
};
use coder_core::api::{InsightsReportInterval, TemplateInsightsSection};
use coder_core::api::{
    UpdateWorkspaceACLRequest, WorkspaceACLGroup, WorkspaceACLResponse, WorkspaceACLUser,
};
use coder_core::ports::UpdateWorkspaceACLInput;
use coder_core::template::{
    CreateProvisionerJobInput, CreateTemplateInput, CreateTemplateStoreError,
    CreateTemplateVersionInput, ProvisionerJobRecord as TemplateProvisionerJobRecord,
    TemplateListFilter, TemplateRecord, TemplateVersionListFilter, TemplateVersionRecord,
    UpdateTemplateMetaInput,
};
use coder_core::{
    AWSInstanceIdentityToken, ApiResponse, AppHostResponse, AppStore, AuditLogListFilter,
    AuthMethods, AuthorizationRequest, AvailableExperiments, AzureInstanceIdentityToken,
    ChangePasswordWithOneTimePasscodeRequest, ChatMessagePart, ChatMessageRecord,
    ChatMessageResponse, ChatMessageUsage, ChatMessageVisibility, ChatQueuedMessageRecord,
    ChatQueuedMessageResponse, ChatRecord, ChatResponse, ChatWithMessagesResponse,
    ConvertLoginRequest, CreateChatMessageApiResponse, CreateChatMessageRequest, CreateChatRequest,
    CreateFirstUserRequest, CreateFirstUserResponse, CreateLogSourceRequest, CreateTaskRequest,
    CreateTestAuditLogRequest, CreateTokenRequest, CreateUserRequestWithOrgs,
    CreateWorkspaceBuildInput, CreateWorkspaceInput, DERPMap, DERPMapRegion, DERPNode,
    DeploymentConfigResponse, ExternalApiKeyScopes, ExternalAuthDeviceExchangeRequest,
    GCPInstanceIdentityToken, GetUsersResponse, HealthSettings, InsertChatInput,
    InsertChatMessageInput, InsertFileInput, InsertTaskInput, LoginType, LoginWithPasswordRequest,
    OAuth2AuthorizationServerMetadata, OAuth2AuthorizeRequest, OAuth2ClientConfiguration,
    OAuth2ClientRegistrationRequest, OAuth2ClientRegistrationResponse, OAuth2ErrorResponse,
    OAuth2ProtectedResourceMetadata, OAuth2ProviderAppEndpoints, OAuth2ProviderAppResponse,
    OAuth2ProviderAppSecretFullResponse, OAuth2ProviderAppSecretResponse, OAuth2TokenRequest,
    OAuth2TokenResponse, OAuth2TokenRevocationRequest, OrganizationMember,
    OrganizationMemberWithUserData, OrganizationRecord, OrganizationResponse,
    PaginatedMembersResponse, PatchAgentLogsRequest, PatchAppStatusRequest, PersistAuditLogInput,
    PostOAuth2ProviderAppRequest, PutOAuth2ProviderAppRequest, RequestOneTimePasscodeRequest,
    ServerConfig, SshConfigResponse, TaskListFilter, TaskLogSnapshotEnvelope, TaskLogsResponse,
    TaskRecord, TaskResponse, TaskSendRequest, TasksListResponse, UpdateCheckResponse,
    UpdateInboxNotificationReadStatusRequest, UpdateNotificationTemplateMethod, UpdateRolesRequest,
    UpdateUserAppearanceSettingsRequest, UpdateUserNotificationPreferences,
    UpdateUserPasswordRequest, UpdateUserPreferenceSettingsRequest, UpdateUserProfileRequest,
    UploadFileResponse, UpsertPortShareInput, UserAppearanceSettings, UserListFilter,
    UserParameter, UserPreferenceSettings, UserResponse, UserRolesResponse, UserStatus,
    ValidateUserPasswordRequest, ValidationError, WebpushSubscription,
    WorkspaceAgentAuthenticateResponse, WorkspaceAgentConnectionInfo,
    WorkspaceAgentListContainersResponse, WorkspaceAgentListeningPortsResponse,
    WorkspaceListFilter,
};
use coder_provisioner::{InitScriptError, render_init_script};
use coder_rbac::{Action, Authorizer, Object, ResourceKind, ResourceType};
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::Sha256;
use time::OffsetDateTime;
use tracing::debug;
use uuid::Uuid;

pub(crate) mod agents;
pub(crate) mod audit;
pub(crate) mod auth;
pub(crate) mod chats;
pub(crate) mod deployment;
pub(crate) mod external_auth;
pub(crate) mod files;
pub(crate) mod health;
pub(crate) mod insights;
pub(crate) mod notifications;
pub(crate) mod oauth2;
pub(crate) mod organizations;
pub(crate) mod tasks;
pub(crate) mod templates;
pub(crate) mod users;
pub(crate) mod workspaces;
