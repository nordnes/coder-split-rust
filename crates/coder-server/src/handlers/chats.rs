//! Chats handlers.

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
use tracing::debug;
use uuid::Uuid;

use crate::app::AppState;
use crate::error::AppError;
use crate::helpers::*;

pub(crate) async fn list_chats(
    State(state): State<AppState>,
    Query(query): Query<ChatsQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let chats = state
        .store
        .list_chats_by_owner(context.user.id, query.archived)
        .await?;

    let chat_responses: Vec<ChatResponse> =
        chats.into_iter().map(chat_response_from_record).collect();
    Ok(Json(chat_responses).into_response())
}

pub(crate) async fn create_chat(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateChatRequest>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can create a chat.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Create,
            &Object::new(ResourceType::Chat).with_owner(context.user.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to create chats.",
        ));
    }

    // Use a default model config ID if none provided.
    let model_config_id = request.model_config_id.unwrap_or_else(Uuid::nil);

    let input = InsertChatInput {
        owner_id: context.user.id,
        workspace_id: request.workspace_id,
        parent_chat_id: None,
        root_chat_id: None,
        last_model_config_id: model_config_id,
        title: "New Chat".to_string(),
    };

    let chat = state.store.insert_chat(input).await?;

    // Store the initial user message.
    let content_value = serde_json::to_value(&request.content)
        .map(Some)
        .map_err(|e| StorageError::invalid_data(e.to_string()))?;
    let msg_input = InsertChatMessageInput {
        chat_id: chat.id,
        model_config_id: Some(model_config_id),
        role: "user".to_string(),
        content: content_value,
        visibility: ChatMessageVisibility::Both,
    };
    let message = state.store.insert_chat_message(msg_input).await?;
    let messages = vec![chat_message_response_from_record(message)?];

    Ok((
        StatusCode::CREATED,
        Json(ChatWithMessagesResponse {
            chat: chat_response_from_record(chat),
            messages,
            queued_messages: Vec::new(),
        }),
    )
        .into_response())
}

pub(crate) async fn get_chat(
    State(state): State<AppState>,
    Path(chat_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(chat) = state.store.find_chat_by_id(chat_id).await? else {
        return Ok(not_found_response("Chat not found."));
    };

    if chat.owner_id != context.user.id {
        return Ok(not_found_response("Chat not found."));
    }

    let messages = state.store.list_chat_messages(chat_id, 0).await?;
    let queued = state.store.list_chat_queued_messages(chat_id).await?;

    let message_responses: Vec<ChatMessageResponse> = messages
        .into_iter()
        .map(chat_message_response_from_record)
        .collect::<Result<_, _>>()?;
    let queued_responses: Vec<ChatQueuedMessageResponse> = queued
        .into_iter()
        .map(chat_queued_message_response_from_record)
        .collect::<Result<_, _>>()?;

    Ok(Json(ChatWithMessagesResponse {
        chat: chat_response_from_record(chat),
        messages: message_responses,
        queued_messages: queued_responses,
    })
    .into_response())
}

pub(crate) async fn delete_chat(
    State(state): State<AppState>,
    Path(chat_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(chat) = state.store.find_chat_by_id(chat_id).await? else {
        return Ok(not_found_response("Chat not found."));
    };

    if chat.owner_id != context.user.id {
        return Ok(not_found_response("Chat not found."));
    }

    // RBAC: verify the actor can delete this chat.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Delete,
            &Object::new(ResourceType::Chat)
                .with_id(chat_id)
                .with_owner(context.user.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to delete this chat.",
        ));
    }

    state.store.archive_chat(chat_id).await?;
    Ok((StatusCode::OK, Json(ApiResponse::ok("Chat archived."))).into_response())
}

pub(crate) async fn post_chat_message(
    State(state): State<AppState>,
    Path(chat_id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<CreateChatMessageRequest>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(chat) = state.store.find_chat_by_id(chat_id).await? else {
        return Ok(not_found_response("Chat not found."));
    };

    if chat.owner_id != context.user.id {
        return Ok(not_found_response("Chat not found."));
    }

    // RBAC: verify the actor can create messages in this chat.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Create,
            &Object::new(ResourceType::Chat)
                .with_id(chat_id)
                .with_owner(context.user.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to post messages to this chat.",
        ));
    }

    let model_config_id = request.model_config_id.unwrap_or(chat.last_model_config_id);
    let content_value = serde_json::to_value(&request.content)
        .map(Some)
        .map_err(|e| StorageError::invalid_data(e.to_string()))?;

    let msg_input = InsertChatMessageInput {
        chat_id,
        model_config_id: Some(model_config_id),
        role: "user".to_string(),
        content: content_value,
        visibility: ChatMessageVisibility::Both,
    };

    let message = state.store.insert_chat_message(msg_input).await?;

    // In the full implementation, this would trigger an LLM call and stream
    // the response back via SSE. For now, we return the stored user message.
    Ok((
        StatusCode::OK,
        Json(CreateChatMessageApiResponse {
            message: Some(chat_message_response_from_record(message)?),
            queued_message: None,
            queued: false,
        }),
    )
        .into_response())
}

pub(crate) fn chat_response_from_record(record: ChatRecord) -> ChatResponse {
    ChatResponse {
        id: record.id,
        owner_id: record.owner_id,
        workspace_id: record.workspace_id,
        parent_chat_id: record.parent_chat_id,
        root_chat_id: record.root_chat_id,
        last_model_config_id: record.last_model_config_id,
        title: record.title,
        status: record.status,
        last_error: record.last_error,
        created_at: record.created_at,
        updated_at: record.updated_at,
        archived: record.archived,
    }
}

pub(crate) fn chat_message_response_from_record(
    record: ChatMessageRecord,
) -> Result<ChatMessageResponse, AppError> {
    let content: Vec<ChatMessagePart> = match record.content {
        Some(v) => serde_json::from_value(v)
            .map_err(|e| StorageError::invalid_data(format!("chat message content: {e}")))?,
        None => Vec::new(),
    };

    let usage = if record.input_tokens.is_some()
        || record.output_tokens.is_some()
        || record.total_tokens.is_some()
    {
        Some(ChatMessageUsage {
            input_tokens: record.input_tokens,
            output_tokens: record.output_tokens,
            total_tokens: record.total_tokens,
            reasoning_tokens: record.reasoning_tokens,
            cache_creation_tokens: record.cache_creation_tokens,
            cache_read_tokens: record.cache_read_tokens,
            context_limit: record.context_limit,
        })
    } else {
        None
    };

    Ok(ChatMessageResponse {
        id: record.id,
        chat_id: record.chat_id,
        model_config_id: record.model_config_id,
        created_at: record.created_at,
        role: record.role,
        content,
        usage,
    })
}

pub(crate) fn chat_queued_message_response_from_record(
    record: ChatQueuedMessageRecord,
) -> Result<ChatQueuedMessageResponse, AppError> {
    let content: Vec<ChatMessagePart> = serde_json::from_value(record.content)
        .map_err(|e| StorageError::invalid_data(format!("queued message content: {e}")))?;
    Ok(ChatQueuedMessageResponse {
        id: record.id,
        chat_id: record.chat_id,
        content,
        created_at: record.created_at,
    })
}

// ---------------------------------------------------------------------------
// Chat file upload/download and archive/unarchive handlers
// ---------------------------------------------------------------------------

/// Maximum chat file upload size (10 MB).
const MAX_CHAT_FILE_SIZE: usize = 10 << 20;
/// Maximum length for an uploaded chat file name.
const MAX_CHAT_FILE_NAME: usize = 255;

/// Allowed MIME types for chat file uploads.
pub(crate) fn is_allowed_chat_file_mime(mime: &str) -> bool {
    matches!(
        mime,
        "image/png" | "image/jpeg" | "image/gif" | "image/webp"
    )
}

/// Detect the MIME type of file data, with extended WebP support.
/// Go's `http.DetectContentType` equivalent + WebP magic bytes check.
pub(crate) fn detect_chat_file_type(data: &[u8]) -> &'static str {
    // WebP: starts with "RIFF" at 0..4 and "WEBP" at 8..12
    if data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        return "image/webp";
    }
    // PNG magic bytes
    if data.len() >= 8 && &data[0..8] == b"\x89PNG\r\n\x1a\n" {
        return "image/png";
    }
    // JPEG magic bytes
    if data.len() >= 3 && &data[0..3] == b"\xff\xd8\xff" {
        return "image/jpeg";
    }
    // GIF magic bytes (GIF87a or GIF89a)
    if data.len() >= 6 && (&data[0..6] == b"GIF87a" || &data[0..6] == b"GIF89a") {
        return "image/gif";
    }
    "application/octet-stream"
}

/// POST /api/v2/chats/files – upload a chat file.
pub(crate) async fn upload_chat_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ChatFileUploadQuery>,
    body: Bytes,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // Require organization query parameter.
    let org_id_str = match query.organization {
        Some(ref s) if !s.is_empty() => s.as_str(),
        _ => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error(
                    "Missing organization query parameter.",
                    "",
                )),
            )
                .into_response());
        }
    };
    let org_id = match Uuid::from_str(org_id_str) {
        Ok(id) => id,
        Err(_) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error("Invalid organization ID.", "")),
            )
                .into_response());
        }
    };

    // RBAC: verify the actor can create chat resources.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Create,
            &Object::new(ResourceType::File)
                .with_owner(context.user.id)
                .in_org(org_id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to upload chat files.",
        ));
    }

    // Enforce file size limit.
    if body.len() > MAX_CHAT_FILE_SIZE {
        return Ok((
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(ApiResponse::error(
                "File too large.",
                format!("Maximum file size is {} bytes.", MAX_CHAT_FILE_SIZE),
            )),
        )
            .into_response());
    }

    // Check Content-Type header and strip parameters.
    let raw_content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream");
    let content_type = raw_content_type
        .split(';')
        .next()
        .unwrap_or("application/octet-stream")
        .trim();

    if !is_allowed_chat_file_mime(content_type) {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "Unsupported file type.",
                "Allowed types: image/png, image/jpeg, image/gif, image/webp.",
            )),
        )
            .into_response());
    }

    let data = body.to_vec();

    // Sniff the actual content type from the first 512 bytes.
    let sniff_len = std::cmp::min(data.len(), 512);
    let detected = detect_chat_file_type(&data[..sniff_len]);
    if !is_allowed_chat_file_mime(detected) {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "Unsupported file type.",
                "Allowed types: image/png, image/jpeg, image/gif, image/webp.",
            )),
        )
            .into_response());
    }

    // Extract filename from Content-Disposition header if provided.
    let filename = headers
        .get("content-disposition")
        .and_then(|v| v.to_str().ok())
        .and_then(|cd| {
            // Parse "attachment; filename=\"name.png\"" or similar.
            let lower = cd.to_lowercase();
            if let Some(pos) = lower.find("filename=") {
                let rest = &cd[pos + 9..];
                // Take only the filename token (up to the next `;` or end of string).
                let token = rest.split(';').next().unwrap_or(rest).trim();
                let name = token.trim_matches('"').trim_matches('\'');
                Some(name.to_string())
            } else {
                None
            }
        })
        .unwrap_or_default();

    // Truncate filename at rune boundary to max length.
    let truncated_name: String = if filename.len() > MAX_CHAT_FILE_NAME {
        let mut result = String::new();
        for ch in filename.chars() {
            if result.len() + ch.len_utf8() > MAX_CHAT_FILE_NAME {
                break;
            }
            result.push(ch);
        }
        result
    } else {
        filename
    };

    let input = coder_core::InsertChatFileInput {
        owner_id: context.user.id,
        organization_id: org_id,
        name: truncated_name,
        mimetype: detected.to_string(),
        data,
    };

    let record = state.store.insert_chat_file(input).await?;

    Ok((
        StatusCode::CREATED,
        Json(coder_core::UploadChatFileResponse { id: record.id }),
    )
        .into_response())
}

/// GET /api/v2/chats/files/{file} – retrieve a chat file by ID.
pub(crate) async fn get_chat_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(file) = state.store.find_chat_file_by_id(file_id).await? else {
        return Ok(not_found_response("Chat file not found."));
    };

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, &file.mimetype)
        .header("cache-control", "private, max-age=31536000, immutable")
        .header("content-length", file.data.len().to_string());

    if file.name.is_empty() {
        builder = builder.header("content-disposition", "inline");
    } else {
        // Sanitize filename to prevent header injection via embedded quotes/backslashes.
        let sanitized_name = file.name.replace(['"', '\\'], "");
        builder = builder.header(
            "content-disposition",
            format!("inline; filename=\"{}\"", sanitized_name),
        );
    }

    let response = builder
        .body(axum::body::Body::from(file.data))
        .map_err(|e| StorageError::unavailable(e.to_string()))?;
    Ok(response)
}

/// POST /api/v2/chats/{chat}/archive – archive a chat.
pub(crate) async fn archive_chat_handler(
    State(state): State<AppState>,
    Path(chat_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(chat) = state.store.find_chat_by_id(chat_id).await? else {
        return Ok(not_found_response("Chat not found."));
    };

    if chat.owner_id != context.user.id {
        return Ok(not_found_response("Chat not found."));
    }

    // RBAC: verify the actor can update (archive) this chat.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::Chat)
                .with_id(chat_id)
                .with_owner(context.user.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to archive this chat.",
        ));
    }

    if chat.archived {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error("Chat is already archived.", "")),
        )
            .into_response());
    }

    state.store.archive_chat(chat_id).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// POST /api/v2/chats/{chat}/unarchive – unarchive a chat.
pub(crate) async fn unarchive_chat_handler(
    State(state): State<AppState>,
    Path(chat_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(chat) = state.store.find_chat_by_id(chat_id).await? else {
        return Ok(not_found_response("Chat not found."));
    };

    if chat.owner_id != context.user.id {
        return Ok(not_found_response("Chat not found."));
    }

    // RBAC: verify the actor can update (unarchive) this chat.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::Chat)
                .with_id(chat_id)
                .with_owner(context.user.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to unarchive this chat.",
        ));
    }

    if !chat.archived {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error("Chat is not archived.", "")),
        )
            .into_response());
    }

    state.store.unarchive_chat(chat_id).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// GET /api/v2/chats/{chat}/git/watch – WebSocket for watching git changes.
///
/// Validates that the chat exists and belongs to the authenticated user,
/// then upgrades to a WebSocket.  The Go reference dials the workspace
/// agent over the tailnet and proxies bidirectional JSON messages between
/// the client WebSocket and the agent's git-watcher stream.
///
/// Because the Rust agent connectivity layer does not yet expose a
/// `WatchGit` RPC, the handler upgrades to a WebSocket and then
/// streams an error message to the client indicating that the agent
/// connection could not be established, before closing the socket.
/// All pre-upgrade validation (auth, chat ownership, workspace
/// presence) is fully implemented.
pub(crate) async fn watch_chat_git(
    State(state): State<AppState>,
    Path(chat_id): Path<Uuid>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(chat) = state.store.find_chat_by_id(chat_id).await? else {
        return Ok(not_found_response("Chat not found."));
    };

    if chat.owner_id != context.user.id {
        return Ok(not_found_response("Chat not found."));
    }

    // The Go handler requires the chat to be associated with a workspace.
    let Some(workspace_id) = chat.workspace_id else {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error("Chat has no workspace to watch.", "")),
        )
            .into_response());
    };

    let agent_provider = state.agent_provider.clone();

    // Upgrade to WebSocket.  All pre-upgrade validation has passed.
    Ok(ws.on_upgrade(move |mut socket| async move {
        // Attempt to locate a connected agent for this workspace.
        //
        // The Go reference calls
        //   `GetWorkspaceAgentsInLatestBuildByWorkspaceID`
        // and then dials the first agent via the tailnet coordinator
        // (`agentProvider.AgentConn`).  The Rust store does not yet
        // implement that query, and `AgentProvider` does not expose a
        // `WatchGit` RPC.  As a best-effort step we check whether
        // *any* agent is registered in the provider.
        //
        // TODO(agent-rpc): Once the store exposes
        //   `find_workspace_agents_by_workspace_id` and `AgentConnection`
        //   gains a `watch_git` method, replace this stub with a real
        //   bidirectional proxy identical to `tailnet_rpc_conn`.

        // For now we cannot resolve workspace_id -> agent_id because the
        // store query is unimplemented.  Fall through to the error path.
        let _workspace_id = workspace_id;

        let connected = agent_provider.debug_info().await;
        if connected.is_empty() {
            // No agents connected at all -- inform the client.
            let err_msg = serde_json::json!({
                "type": "error",
                "message": "No workspace agents are currently connected. Git watching requires a running agent."
            });
            let _ = socket
                .send(Message::Text(
                    serde_json::to_string(&err_msg).unwrap_or_default().into(),
                ))
                .await;
            let _ = socket
                .send(Message::Close(Some(CloseFrame {
                    code: 4002,
                    reason: "no connected agents".into(),
                })))
                .await;
            return;
        }

        // Agent(s) exist but we cannot dial them for git watching yet.
        let err_msg = serde_json::json!({
            "type": "error",
            "message": "Agent git watch RPC is not yet implemented. The workspace has connected agents but the server cannot proxy git changes yet."
        });
        let _ = socket
            .send(Message::Text(
                serde_json::to_string(&err_msg).unwrap_or_default().into(),
            ))
            .await;
        let _ = socket
            .send(Message::Close(Some(CloseFrame {
                code: 4001,
                reason: "agent git watch not implemented".into(),
            })))
            .await;
    }))
}

#[derive(Deserialize)]
pub(crate) struct ChatsQuery {
    #[serde(default)]
    archived: Option<bool>,
}

#[derive(Deserialize)]
pub(crate) struct ChatFileUploadQuery {
    organization: Option<String>,
}
