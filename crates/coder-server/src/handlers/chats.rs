//! Chat and message handlers.

use super::*;

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
    payload: Result<Json<CreateChatRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };
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
    payload: Result<Json<CreateChatMessageRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };
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

/// Maximum chat file upload size (10 MB).
pub(crate) const MAX_CHAT_FILE_SIZE: usize = 10 << 20;

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

/// GET /api/v2/chats/watch – SSE stream for chat list updates.
///
/// Subscribes to the pub/sub channel for the authenticated user's chat events
/// and streams them as server-sent events. Sends an initial ping to signal
/// the connection is ready.
pub(crate) async fn watch_chats(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    use axum::response::sse::{Event, KeepAlive, Sse};
    use std::convert::Infallible;

    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let channel = coder_core::api::chat_event_channel(context.user.id);
    let subscription = state
        .pubsub
        .subscribe(&channel)
        .await
        .map_err(|e| StorageError::unavailable(e.to_string()))?;

    let stream = async_stream::stream! {
        // Send initial ping to signal the connection is ready.
        let ping = coder_core::api::ServerSentEvent::<()> {
            event_type: coder_core::api::ServerSentEventType::Ping,
            data: None,
        };
        match serde_json::to_string(&ping) {
            Ok(json) => {
                yield Ok::<_, Infallible>(Event::default().data(json));
            }
            Err(e) => {
                tracing::debug!(error = %e, "failed to serialize watch_chats ping event");
            }
        }

        // Stream chat events from pub/sub.
        let mut sub = subscription;
        while let Ok(message) = sub.recv().await {
            // Parse the message as a ChatEvent.
            match serde_json::from_slice::<coder_core::api::ChatEvent>(&message) {
                Ok(chat_event) => {
                    let sse = coder_core::api::ServerSentEvent {
                        event_type: coder_core::api::ServerSentEventType::Data,
                        data: Some(chat_event),
                    };
                    match serde_json::to_string(&sse) {
                        Ok(json) => {
                            yield Ok::<_, Infallible>(Event::default().data(json));
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "failed to serialize watch_chats SSE event");
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!(error = %e, "failed to deserialize watch_chats pub/sub message");
                    continue;
                }
            }
        }
    };

    Ok(Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response())
}

/// GET /api/v2/chats/models – List available AI chat models.
///
/// Returns the list of configured AI model providers and their models.
/// The Go reference queries the database for enabled providers and models,
/// then merges with deployment-level API keys. This implementation returns
/// the providers from the store.
///
/// Authentication is required but no RBAC check is performed — any
/// authenticated user can list available models, matching the Go reference.
pub(crate) async fn list_chat_models(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    // Auth only — no RBAC needed for read-only model catalog.
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let providers = state.store.get_enabled_chat_providers().await?;

    Ok(Json(coder_core::api::ChatModelsResponse { providers }).into_response())
}

/// GET /api/v2/chats/{chat}/stream – SSE stream for chat messages.
///
/// Streams real-time chat messages as server-sent events. Sends message parts,
/// status updates, and errors. The Go reference subscribes to a chat daemon
/// for live events and sends an initial snapshot. This implementation
/// subscribes to the chat's pub/sub channel and streams events.
pub(crate) async fn stream_chat(
    State(state): State<AppState>,
    Path(chat_id): Path<Uuid>,
    Query(query): Query<StreamChatQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    use axum::response::sse::{Event, KeepAlive, Sse};
    use std::convert::Infallible;

    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(chat) = state.store.find_chat_by_id(chat_id).await? else {
        return Ok(not_found_response("Chat not found."));
    };

    if chat.owner_id != context.user.id {
        return Ok(not_found_response("Chat not found."));
    }

    // Subscribe to pub/sub BEFORE fetching the snapshot to avoid missing
    // events that arrive between the initial fetch and the subscription.
    // This matches the established pattern in agents.rs and workspaces.rs.
    let channel = coder_core::api::chat_stream_channel(chat_id);
    let subscription = state
        .pubsub
        .subscribe(&channel)
        .await
        .map_err(|e| StorageError::unavailable(e.to_string()))?;

    // Load initial message snapshot (optionally filtered by after_id).
    let after_id = query.after_id.unwrap_or(0);
    let messages = state.store.list_chat_messages(chat_id, after_id).await?;
    let queued = state.store.list_chat_queued_messages(chat_id).await?;

    // Convert to ChatStreamEvent snapshot.
    let mut snapshot: Vec<coder_core::api::ChatStreamEvent> = Vec::new();
    for msg in messages {
        let msg_resp = chat_message_response_from_record(msg)?;
        snapshot.push(coder_core::api::ChatStreamEvent {
            event_type: coder_core::api::ChatStreamEventType::Message,
            chat_id,
            message: Some(msg_resp),
            message_part: None,
            status: None,
            error: None,
            retry: None,
            queued_messages: Vec::new(),
        });
    }

    // Add status event.
    snapshot.push(coder_core::api::ChatStreamEvent {
        event_type: coder_core::api::ChatStreamEventType::Status,
        chat_id,
        message: None,
        message_part: None,
        status: Some(coder_core::api::ChatStreamStatus {
            status: chat.status.clone(),
        }),
        error: None,
        retry: None,
        queued_messages: Vec::new(),
    });

    // Add queued messages if any.
    if !queued.is_empty() {
        let queued_responses: Vec<ChatQueuedMessageResponse> = queued
            .into_iter()
            .map(chat_queued_message_response_from_record)
            .collect::<Result<_, _>>()?;
        snapshot.push(coder_core::api::ChatStreamEvent {
            event_type: coder_core::api::ChatStreamEventType::QueueUpdate,
            chat_id,
            message: None,
            message_part: None,
            status: None,
            error: None,
            retry: None,
            queued_messages: queued_responses,
        });
    }

    let stream = async_stream::stream! {
        // Send snapshot in batches (up to 256 events per SSE message).
        // The batch size of 256 matches the Go reference `chatStreamBatchSize`.
        const BATCH_SIZE: usize = 256;
        for chunk in snapshot.chunks(BATCH_SIZE) {
            let sse = coder_core::api::ServerSentEvent {
                event_type: coder_core::api::ServerSentEventType::Data,
                data: Some(chunk),
            };
            match serde_json::to_string(&sse) {
                Ok(json) => {
                    yield Ok::<_, Infallible>(Event::default().data(json));
                }
                Err(e) => {
                    tracing::debug!(error = %e, "failed to serialize stream_chat snapshot batch");
                }
            }
        }

        // Stream live events from pub/sub subscription.
        let mut sub = subscription;
        while let Ok(message) = sub.recv().await {
            match serde_json::from_slice::<Vec<coder_core::api::ChatStreamEvent>>(&message) {
                Ok(events) => {
                    let sse = coder_core::api::ServerSentEvent {
                        event_type: coder_core::api::ServerSentEventType::Data,
                        data: Some(events),
                    };
                    match serde_json::to_string(&sse) {
                        Ok(json) => {
                            yield Ok::<_, Infallible>(Event::default().data(json));
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "failed to serialize stream_chat SSE event");
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!(error = %e, "failed to deserialize stream_chat pub/sub message");
                    continue;
                }
            }
        }
    };

    Ok(Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response())
}

/// POST /api/v2/chats/{chat}/interrupt – Interrupt active chat.
///
/// Cancels an ongoing AI response generation by updating the chat status
/// to "waiting". Returns the updated chat.
///
/// Note: No chat-status guard is applied intentionally — the Go reference
/// (`interruptChat` in `coder/coderd/chats.go`) unconditionally sets the
/// status to `Waiting` regardless of the chat’s current state.
pub(crate) async fn interrupt_chat(
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

    // RBAC: verify the actor can update (interrupt) this chat.
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
            "You are not authorized to interrupt this chat.",
        ));
    }

    // Unconditionally set status to Waiting — no current-state guard,
    // matching the Go reference which also sets Waiting regardless of
    // whether the chat is Running, Pending, or already Waiting.
    let updated = state
        .store
        .update_chat_status(chat_id, coder_core::api::ChatStatus::Waiting)
        .await?;

    Ok(Json(chat_response_from_record(updated)).into_response())
}

/// GET /api/v2/chats/{chat}/diff-status – Get chat diff status.
///
/// Returns the cached diff status for a chat's code changes. This includes
/// pull request state, additions/deletions, and refresh timestamps.
pub(crate) async fn get_chat_diff_status(
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

    // Fetch the diff status from the store; return a default if none exists.
    let status = state.store.get_chat_diff_status(chat_id).await?;
    let response = status.unwrap_or(coder_core::api::ChatDiffStatusResponse {
        chat_id,
        url: None,
        pull_request_state: None,
        changes_requested: false,
        additions: 0,
        deletions: 0,
        changed_files: 0,
        refreshed_at: None,
        stale_at: None,
    });

    Ok(Json(response).into_response())
}

/// GET /api/v2/chats/{chat}/diff – Get chat diff contents.
///
/// Returns the resolved diff text for a chat. Includes provider information,
/// remote origin, branch, and the actual diff content.
pub(crate) async fn get_chat_diff_contents(
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

    let diff = state.store.get_chat_diff_contents(chat_id).await?;
    Ok(Json(diff).into_response())
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
    let store = state.store.clone();

    // Upgrade to WebSocket.  All pre-upgrade validation has passed.
    Ok(ws.on_upgrade(move |mut socket| async move {
        // The Go reference calls `GetWorkspaceAgentsInLatestBuildByWorkspaceID`
        // to find agents, then dials the first one via the tailnet coordinator
        // (`agentProvider.AgentConn`) and proxies the `WatchGit` RPC
        // bidirectionally over the WebSocket.
        //
        // We check the connected agents via `AgentProvider::debug_info()` and
        // cross-reference each one against the store's `find_workspace_by_agent_id`
        // to confirm the agent belongs to the target workspace.
        let connected = agent_provider.debug_info().await;
        if connected.is_empty() {
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

        // Find a connected agent that belongs to the target workspace by
        // checking each connected agent against the store.  This prevents
        // accidentally routing to an agent from an unrelated workspace.
        let mut matched_agent_id = None;
        for info in &connected {
            match store.find_workspace_by_agent_id(info.agent_id).await {
                Ok(Some(ws)) if ws.id == workspace_id => {
                    matched_agent_id = Some(info.agent_id);
                    break;
                }
                _ => continue,
            }
        }

        let Some(agent_id) = matched_agent_id else {
            let err_msg = serde_json::json!({
                "type": "error",
                "message": "No connected agent found for this workspace."
            });
            let _ = socket
                .send(Message::Text(
                    serde_json::to_string(&err_msg).unwrap_or_default().into(),
                ))
                .await;
            let _ = socket
                .send(Message::Close(Some(CloseFrame {
                    code: 4002,
                    reason: "no matching agent for workspace".into(),
                })))
                .await;
            return;
        };

        match agent_provider.get_agent_connection(agent_id).await {
            Some(_agent_conn) => {
                // `AgentConnection` does not yet expose a `watch_git` RPC.
                // Close the socket with a descriptive code so clients know
                // the feature is partially implemented.
                let err_msg = serde_json::json!({
                    "type": "error",
                    "message": "Agent git watch RPC is not yet available on this connection."
                });
                let _ = socket
                    .send(Message::Text(
                        serde_json::to_string(&err_msg).unwrap_or_default().into(),
                    ))
                    .await;
                let _ = socket
                    .send(Message::Close(Some(CloseFrame {
                        code: 4001,
                        reason: "watch_git RPC not available".into(),
                    })))
                    .await;
            }
            None => {
                tracing::warn!(
                    agent_id = %agent_id,
                    workspace_id = %workspace_id,
                    "watch_git: agent listed in debug_info but connection not found"
                );
                let err_msg = serde_json::json!({
                    "type": "error",
                    "message": "Workspace agent connection is no longer available."
                });
                let _ = socket
                    .send(Message::Text(
                        serde_json::to_string(&err_msg).unwrap_or_default().into(),
                    ))
                    .await;
                let _ = socket
                    .send(Message::Close(Some(CloseFrame {
                        code: 4002,
                        reason: "agent connection lost".into(),
                    })))
                    .await;
            }
        }
    }))
}

// ---------------------------------------------------------------------------
// PATCH /api/v2/chats/{chat}/messages/{message}
// ---------------------------------------------------------------------------

pub(crate) async fn patch_chat_message(
    State(state): State<AppState>,
    Path((chat_id, message_id)): Path<(Uuid, i64)>,
    headers: HeaderMap,
    payload: Result<Json<EditChatMessageRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Json(request) = match payload {
        Ok(r) => r,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(chat) = state.store.find_chat_by_id(chat_id).await? else {
        return Ok(not_found_response("Chat not found."));
    };

    if chat.owner_id != context.user.id {
        return Ok(not_found_response("Chat not found."));
    }

    if message_id <= 0 {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "Invalid chat message ID.",
                "Message ID must be a positive integer.",
            )),
        )
            .into_response());
    }

    let content_value = serde_json::to_value(&request.content)
        .map(Some)
        .map_err(|e| StorageError::invalid_data(e.to_string()))?;

    let input = UpdateChatMessageContentInput {
        message_id,
        chat_id,
        content: content_value,
    };

    let message = match state.store.update_chat_message_content(input).await {
        Ok(m) => m,
        Err(StorageError::NotFound { .. }) => {
            return Ok(not_found_response(
                "Chat message not found or not editable.",
            ));
        }
        Err(e) => return Err(e.into()),
    };
    Ok(Json(chat_message_response_from_record(message)?).into_response())
}

// ---------------------------------------------------------------------------
// DELETE /api/v2/chats/{chat}/queue/{queuedMessage}
// ---------------------------------------------------------------------------

pub(crate) async fn delete_chat_queued_message(
    State(state): State<AppState>,
    Path((chat_id, queued_message_id)): Path<(Uuid, i64)>,
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

    if queued_message_id <= 0 {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "Invalid queued message ID.",
                "Queued message ID must be a positive integer.",
            )),
        )
            .into_response());
    }

    state
        .store
        .delete_chat_queued_message(chat_id, queued_message_id)
        .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

// ---------------------------------------------------------------------------
// POST /api/v2/chats/{chat}/queue/{queuedMessage}/promote
// ---------------------------------------------------------------------------

pub(crate) async fn promote_chat_queued_message(
    State(state): State<AppState>,
    Path((chat_id, queued_message_id)): Path<(Uuid, i64)>,
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

    if queued_message_id <= 0 {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "Invalid queued message ID.",
                "Queued message ID must be a positive integer.",
            )),
        )
            .into_response());
    }

    let promoted = match state
        .store
        .promote_chat_queued_message(chat_id, queued_message_id)
        .await
    {
        Ok(record) => record,
        Err(StorageError::NotFound { .. }) => {
            return Ok(not_found_response("Queued message not found."));
        }
        Err(e) => return Err(e.into()),
    };
    Ok(Json(chat_queued_message_response_from_record(promoted)?).into_response())
}

// ---------------------------------------------------------------------------
// Conversion helpers for provider and model config responses
// ---------------------------------------------------------------------------

fn chat_provider_config_response_from_record(
    record: ChatProviderRecord,
) -> ChatProviderConfigResponse {
    let has_api_key = !record.api_key.trim().is_empty();
    let display_name = if record.display_name.trim().is_empty() {
        record.provider.clone()
    } else {
        record.display_name.trim().to_string()
    };
    ChatProviderConfigResponse {
        id: record.id,
        provider: record.provider,
        display_name,
        enabled: record.enabled,
        has_api_key,
        base_url: record.base_url.trim().to_string(),
        source: ChatProviderConfigSource::Database,
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}

fn chat_model_config_response_from_record(
    record: ChatModelConfigRecord,
) -> ChatModelConfigResponse {
    let model_config: Option<ChatModelCallConfig> =
        match serde_json::from_value::<ChatModelCallConfig>(record.options.clone()) {
            Ok(cfg) => Some(cfg),
            Err(e) => {
                tracing::warn!(
                    config_id = %record.id,
                    error = %e,
                    "failed to deserialize chat model config options"
                );
                None
            }
        }
        .and_then(|cfg: ChatModelCallConfig| {
            if cfg.max_output_tokens.is_none()
                && cfg.temperature.is_none()
                && cfg.top_p.is_none()
                && cfg.top_k.is_none()
                && cfg.presence_penalty.is_none()
                && cfg.frequency_penalty.is_none()
                && cfg.provider_options.is_none()
            {
                None
            } else {
                Some(cfg)
            }
        });
    ChatModelConfigResponse {
        id: record.id,
        provider: record.provider,
        model: record.model,
        display_name: record.display_name,
        enabled: record.enabled,
        is_default: record.is_default,
        context_limit: record.context_limit,
        compression_threshold: record.compression_threshold,
        model_config,
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}

// ---------------------------------------------------------------------------
// GET /api/v2/chats/providers
// ---------------------------------------------------------------------------

pub(crate) async fn list_chat_providers(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::DeploymentConfig),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to view chat providers.",
        ));
    }

    let providers = state.store.list_chat_providers().await?;
    let response: Vec<ChatProviderConfigResponse> = providers
        .into_iter()
        .map(chat_provider_config_response_from_record)
        .collect();
    Ok(Json(response).into_response())
}

// ---------------------------------------------------------------------------
// POST /api/v2/chats/providers
// ---------------------------------------------------------------------------

pub(crate) async fn create_chat_provider(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<CreateChatProviderConfigRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Json(request) = match payload {
        Ok(r) => r,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::DeploymentConfig),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to create chat providers.",
        ));
    }

    let provider = request.provider.trim().to_string();
    if provider.is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "Invalid provider.",
                "Provider must not be empty.",
            )),
        )
            .into_response());
    }

    // Validate provider against the allowed set (matches DB CHECK constraint).
    const ALLOWED_PROVIDERS: &[&str] = &[
        "anthropic",
        "azure",
        "bedrock",
        "google",
        "openai",
        "openai-compat",
        "openrouter",
        "vercel",
    ];
    if !ALLOWED_PROVIDERS.contains(&provider.as_str()) {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "Invalid provider.",
                format!("Provider must be one of: {}.", ALLOWED_PROVIDERS.join(", ")),
            )),
        )
            .into_response());
    }

    let enabled = request.enabled.unwrap_or(true);

    let input = InsertChatProviderInput {
        provider,
        display_name: request.display_name.trim().to_string(),
        api_key: request.api_key.trim().to_string(),
        base_url: request.base_url.trim().to_string(),
        enabled,
        created_by: Some(context.user.id),
    };

    let record = state.store.insert_chat_provider(input).await?;
    Ok((
        StatusCode::CREATED,
        Json(chat_provider_config_response_from_record(record)),
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// PATCH /api/v2/chats/providers/{provider}
// ---------------------------------------------------------------------------

pub(crate) async fn update_chat_provider(
    State(state): State<AppState>,
    Path(provider_id): Path<Uuid>,
    headers: HeaderMap,
    payload: Result<Json<UpdateChatProviderConfigRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Json(request) = match payload {
        Ok(r) => r,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::DeploymentConfig),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update chat providers.",
        ));
    }

    // Fetch existing provider to merge optional fields.
    let providers = state.store.list_chat_providers().await?;
    let Some(existing) = providers.into_iter().find(|p| p.id == provider_id) else {
        return Ok(not_found_response("Chat provider not found."));
    };

    let display_name = {
        let trimmed = request.display_name.trim();
        if trimmed.is_empty() {
            existing.display_name
        } else {
            trimmed.to_string()
        }
    };
    let enabled = request.enabled.unwrap_or(existing.enabled);
    let api_key = match &request.api_key {
        Some(k) => k.trim().to_string(),
        None => existing.api_key,
    };
    let base_url = match &request.base_url {
        Some(u) => u.trim().to_string(),
        None => existing.base_url,
    };

    let input = UpdateChatProviderInput {
        id: provider_id,
        display_name,
        api_key,
        base_url,
        enabled,
    };

    let record = state.store.update_chat_provider(input).await?;
    Ok(Json(chat_provider_config_response_from_record(record)).into_response())
}

// ---------------------------------------------------------------------------
// DELETE /api/v2/chats/providers/{provider}
// ---------------------------------------------------------------------------

pub(crate) async fn delete_chat_provider(
    State(state): State<AppState>,
    Path(provider_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::DeploymentConfig),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to delete chat providers.",
        ));
    }

    // Verify the provider exists.
    let providers = state.store.list_chat_providers().await?;
    if !providers.iter().any(|p| p.id == provider_id) {
        return Ok(not_found_response("Chat provider not found."));
    }

    state.store.delete_chat_provider(provider_id).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

// ---------------------------------------------------------------------------
// GET /api/v2/chats/model-configs
// ---------------------------------------------------------------------------

pub(crate) async fn list_chat_model_configs(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // Admin users see all configs; non-admin users see only enabled ones.
    let authorizer = Authorizer::new();
    let is_admin = authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::DeploymentConfig),
        )
        .is_ok();

    let enabled_only = !is_admin;
    let configs = state.store.list_chat_model_configs(enabled_only).await?;
    let response: Vec<ChatModelConfigResponse> = configs
        .into_iter()
        .map(chat_model_config_response_from_record)
        .collect();
    Ok(Json(response).into_response())
}

// ---------------------------------------------------------------------------
// POST /api/v2/chats/model-configs
// ---------------------------------------------------------------------------

pub(crate) async fn create_chat_model_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<CreateChatModelConfigRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Json(request) = match payload {
        Ok(r) => r,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::DeploymentConfig),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to create chat model configs.",
        ));
    }

    let provider = request.provider.trim().to_string();
    if provider.is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "Invalid provider.",
                "Provider must not be empty.",
            )),
        )
            .into_response());
    }

    let model = request.model.trim().to_string();
    if model.is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error("Model is required.", "")),
        )
            .into_response());
    }

    let enabled = request.enabled.unwrap_or(true);
    let is_default = request.is_default.unwrap_or(false);

    let context_limit = match request.context_limit {
        Some(limit) if limit > 0 => limit,
        _ => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error(
                    "Context limit is required.",
                    "context_limit must be greater than zero.",
                )),
            )
                .into_response());
        }
    };

    let compression_threshold = request.compression_threshold.unwrap_or(80);
    if !(0..=100).contains(&compression_threshold) {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "Invalid compression threshold.",
                "compression_threshold must be between 0 and 100.",
            )),
        )
            .into_response());
    }

    let options = match &request.model_config {
        Some(cfg) => {
            serde_json::to_value(cfg).map_err(|e| StorageError::invalid_data(e.to_string()))?
        }
        None => serde_json::json!({}),
    };

    // Disabled configs cannot be the default.
    let mut set_as_default = if enabled { is_default } else { false };
    // If no enabled default currently exists, make this one the default (if enabled).
    if !set_as_default && enabled {
        let existing = state.store.list_chat_model_configs(false).await?;
        if !existing.iter().any(|c| c.is_default && c.enabled) {
            set_as_default = true;
        }
    }

    if set_as_default {
        state.store.unset_default_chat_model_configs().await?;
    }

    let input = InsertChatModelConfigInput {
        provider,
        model,
        display_name: request.display_name.trim().to_string(),
        enabled,
        is_default: set_as_default,
        context_limit,
        compression_threshold,
        options,
        created_by: Some(context.user.id),
    };

    let record = match state.store.insert_chat_model_config(input).await {
        Ok(r) => r,
        Err(e) => {
            // Recover: re-establish a default since we may have already unset them.
            let _recovery = state.store.ensure_default_chat_model_config().await;
            return Err(e.into());
        }
    };
    state.store.ensure_default_chat_model_config().await?;

    // NOTE: The `record` returned by insert may have a stale `is_default`
    // value if `ensure_default_chat_model_config` promoted this record to
    // the default after insert. This matches the Go reference behaviour
    // which also returns the record from the INSERT without re-fetching.
    Ok((
        StatusCode::CREATED,
        Json(chat_model_config_response_from_record(record)),
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// PATCH /api/v2/chats/model-configs/{config}
// ---------------------------------------------------------------------------

pub(crate) async fn update_chat_model_config(
    State(state): State<AppState>,
    Path(config_id): Path<Uuid>,
    headers: HeaderMap,
    payload: Result<Json<UpdateChatModelConfigRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Json(request) = match payload {
        Ok(r) => r,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::DeploymentConfig),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update chat model configs.",
        ));
    }

    // Fetch existing config to merge optional fields.
    let configs = state.store.list_chat_model_configs(false).await?;
    let Some(existing) = configs.into_iter().find(|c| c.id == config_id) else {
        return Ok(not_found_response("Chat model config not found."));
    };

    let provider = {
        let trimmed = request.provider.trim();
        if trimmed.is_empty() {
            existing.provider
        } else {
            trimmed.to_string()
        }
    };
    let model = {
        let trimmed = request.model.trim();
        if trimmed.is_empty() {
            existing.model
        } else {
            trimmed.to_string()
        }
    };
    let display_name = {
        let trimmed = request.display_name.trim();
        if trimmed.is_empty() {
            existing.display_name
        } else {
            trimmed.to_string()
        }
    };
    let enabled = request.enabled.unwrap_or(existing.enabled);
    // Disabled configs cannot be the default.
    let is_default = if enabled {
        request.is_default.unwrap_or(existing.is_default)
    } else {
        false
    };

    let context_limit = match request.context_limit {
        Some(limit) => {
            if limit <= 0 {
                return Ok((
                    StatusCode::BAD_REQUEST,
                    Json(ApiResponse::error(
                        "Context limit must be greater than zero.",
                        "",
                    )),
                )
                    .into_response());
            }
            limit
        }
        None => existing.context_limit,
    };

    let compression_threshold = request
        .compression_threshold
        .unwrap_or(existing.compression_threshold);
    if !(0..=100).contains(&compression_threshold) {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "Invalid compression threshold.",
                "compression_threshold must be between 0 and 100.",
            )),
        )
            .into_response());
    }

    let options = match &request.model_config {
        Some(cfg) => {
            serde_json::to_value(cfg).map_err(|e| StorageError::invalid_data(e.to_string()))?
        }
        None => existing.options,
    };

    // Handle default logic: if setting as new default, unset others first.
    if is_default && !existing.is_default {
        state.store.unset_default_chat_model_configs().await?;
    }

    let input = UpdateChatModelConfigInput {
        id: config_id,
        provider,
        model,
        display_name,
        enabled,
        is_default,
        context_limit,
        compression_threshold,
        options,
        updated_by: Some(context.user.id),
    };

    let record = match state.store.update_chat_model_config(input).await {
        Ok(r) => r,
        Err(e) => {
            // Recover: re-establish a default since we may have already unset them.
            let _recovery = state.store.ensure_default_chat_model_config().await;
            return Err(e.into());
        }
    };
    state.store.ensure_default_chat_model_config().await?;

    Ok(Json(chat_model_config_response_from_record(record)).into_response())
}

// ---------------------------------------------------------------------------
// DELETE /api/v2/chats/model-configs/{config}
// ---------------------------------------------------------------------------

pub(crate) async fn delete_chat_model_config(
    State(state): State<AppState>,
    Path(config_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::DeploymentConfig),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to delete chat model configs.",
        ));
    }

    // Verify the config exists.
    let configs = state.store.list_chat_model_configs(false).await?;
    if !configs.iter().any(|c| c.id == config_id) {
        return Ok(not_found_response("Chat model config not found."));
    }

    state.store.delete_chat_model_config(config_id).await?;
    state.store.ensure_default_chat_model_config().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
