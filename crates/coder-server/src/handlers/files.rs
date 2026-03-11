//! Files handlers.

//! Router construction and HTTP handlers.

use std::{collections::HashMap, str::FromStr, sync::Arc};

use async_trait::async_trait;
use axum::{
    Form, Json, Router,
    body::Bytes,
    extract::{
        DefaultBodyLimit, OriginalUri, Path, Query, State,
        rejection::JsonRejection,
        ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
    },
    http::{
        HeaderMap, HeaderName, HeaderValue, StatusCode,
        header::{
            ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS,
            ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_TYPE, LOCATION,
        },
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post, put},
};
use coder_audit::{AuditAction, AuditEvent, AuditSink};
use coder_auth::{
    AuthService, AuthServiceError, AuthenticatedRequest, ExternalAuthService,
    ExternalAuthServiceError, OAUTH2_REDIRECT_COOKIE, OAUTH2_STATE_COOKIE, OAuth2ProviderError,
    OAuth2ProviderService, cookie_from_headers, supported_auth_methods,
};
use coder_connectivity::{
    HealthService,
    agents::{AgentConnection, AgentError, AgentProvider},
    generate_git_ssh_key,
    tailnet::{DerpTrafficTracker, TailnetCoordinator},
};
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
use coder_core::pubsub::PubSub;
use coder_core::template::{
    CreateProvisionerJobInput, CreateTemplateInput, CreateTemplateStoreError,
    CreateTemplateVersionInput, ProvisionerJobRecord as TemplateProvisionerJobRecord,
    TemplateListFilter, TemplateRecord, TemplateVersionListFilter, TemplateVersionRecord,
    UpdateTemplateMetaInput,
};
use coder_core::{
    AWSInstanceIdentityToken, ApiResponse, AppHostResponse, AppStore, AuditLogListFilter,
    AuthMethods, AuthenticatedUser, AuthorizationRequest, AvailableExperiments,
    AzureInstanceIdentityToken, BuildMetadata, ChangePasswordWithOneTimePasscodeRequest,
    ChatMessagePart, ChatMessageRecord, ChatMessageResponse, ChatMessageUsage,
    ChatMessageVisibility, ChatQueuedMessageRecord, ChatQueuedMessageResponse, ChatRecord,
    ChatResponse, ChatWithMessagesResponse, ConvertLoginRequest, CreateChatMessageApiResponse,
    CreateChatMessageRequest, CreateChatRequest, CreateFirstUserRequest, CreateFirstUserResponse,
    CreateLogSourceRequest, CreateTaskRequest, CreateTestAuditLogRequest, CreateTokenRequest,
    CreateUserRequestWithOrgs, CreateWorkspaceBuildInput, CreateWorkspaceInput, DERPMap,
    DERPMapRegion, DERPNode, DeploymentConfigResponse, ExternalApiKeyScopes,
    ExternalAuthDeviceExchangeRequest, GCPInstanceIdentityToken, GetUsersResponse, HealthSettings,
    HealthcheckReport, InsertChatInput, InsertChatMessageInput, InsertFileInput, InsertTaskInput,
    LoginType, LoginWithPasswordRequest, OAuth2AuthorizeRequest, OAuth2ProviderAppEndpoints,
    OAuth2ProviderAppResponse, OAuth2ProviderAppSecretFullResponse,
    OAuth2ProviderAppSecretResponse, OAuth2TokenRequest, OAuth2TokenResponse, OrganizationMember,
    OrganizationMemberWithUserData, OrganizationRecord, OrganizationResponse,
    PaginatedMembersResponse, PatchAgentLogsRequest, PatchAppStatusRequest, PersistAuditLogInput,
    PostOAuth2ProviderAppRequest, PutOAuth2ProviderAppRequest, RequestOneTimePasscodeRequest,
    ServerConfig, SshConfigResponse, TaskListFilter, TaskLogSnapshotEnvelope, TaskLogsResponse,
    TaskRecord, TaskResponse, TaskSendRequest, TasksListResponse, UpdateCheckResponse,
    UpdateInboxNotificationReadStatusRequest, UpdateNotificationTemplateMethod, UpdateRolesRequest,
    UpdateUserAppearanceSettingsRequest, UpdateUserNotificationPreferences,
    UpdateUserPasswordRequest, UpdateUserPreferenceSettingsRequest, UpdateUserProfileRequest,
    UploadFileResponse, UpsertPortShareInput, UserAppearanceSettings, UserListFilter,
    UserParameter, UserPreferenceSettings, UserRecord, UserResponse, UserRolesResponse, UserStatus,
    ValidateUserPasswordRequest, ValidationError, WebpushSubscription,
    WorkspaceAgentAuthenticateResponse, WorkspaceAgentConnectionInfo,
    WorkspaceAgentListContainersResponse, WorkspaceAgentListeningPortsResponse,
    WorkspaceListFilter,
};
use coder_identity::{IdentityService, IdentityServiceError};
use coder_provisioner::{InitScriptError, render_init_script};
use coder_rbac::{Action, Actor, Authorizer, Object, ROLE_AUDITOR, ResourceKind, ResourceType};
use coder_workspaces::DeploymentStatsService;
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use time::OffsetDateTime;
use tower_http::{
    normalize_path::NormalizePathLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer},
};
use tracing::debug;
use uuid::Uuid;

use crate::error::AppError;

const TIMING_ALLOW_ORIGIN: &str = "timing-allow-origin";
const BUILD_VERSION_HEADER: &str = "x-coder-build-version";
const SLIM_BUILD_MESSAGE: &str = "Slim build of Coder, does not contain the frontend static files.";
const PUBLIC_API_KEY_SCOPES: &[&str] = &[
    "audit_log:*",
    "audit_log:create",
    "audit_log:read",
    "api_key:*",
    "api_key:create",
    "api_key:delete",
    "api_key:read",
    "api_key:update",
    "coder:all",
    "coder:apikeys.manage_self",
    "coder:application_connect",
    "deployment_stats:*",
    "deployment_stats:read",
    "coder:templates.author",
    "coder:templates.build",
    "coder:workspaces.access",
    "coder:workspaces.create",
    "coder:workspaces.delete",
    "coder:workspaces.operate",
    "file:*",
    "file:create",
    "file:read",
    "organization:*",
    "organization:delete",
    "organization:read",
    "organization:update",
    "task:*",
    "task:create",
    "task:delete",
    "task:read",
    "task:update",
    "template:*",
    "template:create",
    "template:delete",
    "template:read",
    "template:update",
    "template:use",
    "user:read_personal",
    "user:update_personal",
    "user_secret:*",
    "user_secret:create",
    "user_secret:delete",
    "user_secret:read",
    "user_secret:update",
    "workspace:*",
    "workspace:application_connect",
    "workspace:create",
    "workspace:delete",
    "workspace:read",
    "workspace:ssh",
    "workspace:start",
    "workspace:stop",
    "workspace:update",
];
const VALID_HEALTH_SECTIONS: &[&str] = &[
    "DERP",
    "AccessURL",
    "Websocket",
    "Database",
    "WorkspaceProxy",
    "ProvisionerDaemons",
];

const MAX_CHAT_FILE_SIZE: usize = 10 << 20;

use crate::app::AppState;
use crate::helpers::*;

const TAR_MIME_TYPE: &str = "application/x-tar";
const ZIP_MIME_TYPE: &str = "application/zip";
const WINDOWS_ZIP_MIME_TYPE: &str = "application/x-zip-compressed";

/// POST /api/v2/files – upload a binary file, deduplicate by SHA-256 hash.
pub(crate) async fn post_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can upload files.
    // In Go, postFile checks rbac.ActionCreate on rbac.ResourceFile at the
    // site level (no org/owner scoping). This intentionally differs from
    // upload_chat_file which uses .with_owner().in_org() because chat file
    // uploads are organization-scoped, while general file uploads (used for
    // template archives) are a site-level operation.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Create,
            &Object::new(ResourceType::File),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to upload files.",
        ));
    }

    let raw_content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    // Strip optional parameters (e.g. "; charset=binary") before matching.
    let content_type = raw_content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim();

    match content_type {
        TAR_MIME_TYPE | ZIP_MIME_TYPE | WINDOWS_ZIP_MIME_TYPE => {}
        _ => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error(
                    format!("Unsupported content type header \"{content_type}\"."),
                    "Allowed content types are: application/x-tar, application/zip, application/x-zip-compressed.",
                )),
            )
                .into_response());
        }
    }

    let data: Vec<u8> = body.to_vec();
    let mimetype = content_type.to_owned();

    // Compute SHA-256 hash of the raw bytes.
    let hash = {
        let mut hasher = Sha256::new();
        hasher.update(&data);
        format!("{:x}", hasher.finalize())
    };

    let file_id = Uuid::new_v4();
    let input = InsertFileInput {
        id: file_id,
        hash,
        created_by: context.user.id,
        mimetype,
        data,
    };

    // INSERT … ON CONFLICT handles the race atomically – if a duplicate
    // exists the DB returns the existing row instead of raising an error.
    let result = state.store.insert_file(input).await?;

    // If the returned id differs from the one we generated, a duplicate
    // already existed and the DB returned the existing row.
    let status = if result.id == file_id {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };

    Ok((status, Json(UploadFileResponse { id: result.id })).into_response())
}

/// GET /api/v2/files/{fileid} – retrieve a file by UUID.
pub(crate) async fn get_file_by_id(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let file = state.store.get_file_by_id(file_id).await?;
    let Some(file) = file else {
        return Ok(resource_not_found_response());
    };

    let content_type = HeaderValue::from_str(&file.mimetype)
        .unwrap_or(HeaderValue::from_static("application/octet-stream"));

    let mut response_headers = HeaderMap::new();
    response_headers.insert(CONTENT_TYPE, content_type);

    Ok((StatusCode::OK, response_headers, file.data).into_response())
}
