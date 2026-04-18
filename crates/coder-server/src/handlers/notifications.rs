//! Notification and inbox handlers.

use super::*;

pub(crate) async fn get_notifications_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: reading deployment-wide notification settings is an admin action.
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
            "You are not authorized to read notification settings.",
        ));
    }

    let settings = state.store.get_notifications_settings().await?;
    Ok((StatusCode::OK, Json(settings)).into_response())
}

pub(crate) async fn put_notifications_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<coder_core::NotificationsSettings>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can update deployment configuration.
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
            "You are not authorized to update notification settings.",
        ));
    }

    let Json(settings) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    state.store.upsert_notifications_settings(&settings).await?;

    Ok((StatusCode::OK, Json(settings)).into_response())
}

pub(crate) async fn get_system_notification_templates(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: listing system notification templates requires template-level read access.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::NotificationTemplate),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to read system notification templates.",
        ));
    }

    let templates = state
        .store
        .get_notification_templates_by_kind("system")
        .await?;
    Ok((StatusCode::OK, Json(templates)).into_response())
}

pub(crate) async fn get_custom_notification_templates(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: listing custom notification templates requires template-level read access.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::NotificationTemplate),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to read custom notification templates.",
        ));
    }

    let templates = state
        .store
        .get_notification_templates_by_kind("custom")
        .await?;
    Ok((StatusCode::OK, Json(templates)).into_response())
}

pub(crate) async fn post_test_notification(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can update deployment configuration.
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
            "You are not authorized to send test notifications.",
        ));
    }

    // The template ID for test notifications is a compile-time constant.
    // When the notification enqueue path is wired, it will use this constant
    // as the `notification_template_id` column value.
    let _template_id = coder_core::TEMPLATE_TEST_NOTIFICATION;

    // The test notification endpoint just returns 200 OK to confirm it's reachable.
    // Full dispatch integration is not implemented yet.
    let _ = &state;
    Ok((
        StatusCode::OK,
        Json(ApiResponse::ok("Test notification acknowledged.")),
    )
        .into_response())
}

pub(crate) async fn put_notification_template_method(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    payload: Result<Json<UpdateNotificationTemplateMethod>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can update notification templates.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::NotificationTemplate),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update notification template methods.",
        ));
    }

    let Json(body) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let method_ref = body.method.as_deref();
    if let Some(m) = method_ref {
        if !matches!(m, "smtp" | "webhook" | "inbox") {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error(
                    format!(
                        "Invalid notification method: {m}. Must be one of: smtp, webhook, inbox"
                    ),
                    "",
                )),
            )
                .into_response());
        }
    }

    let template = state
        .store
        .update_notification_template_method(id, method_ref)
        .await?;

    match template {
        Some(t) => Ok((StatusCode::OK, Json(t)).into_response()),
        None => Ok(not_found_response("Notification template not found.")),
    }
}

pub(crate) async fn get_notification_dispatch_methods(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: dispatch methods are admin-level notification configuration.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::NotificationTemplate),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to read notification dispatch methods.",
        ));
    }

    let _ = &state;
    let response = coder_core::NotificationMethodsResponse {
        available: vec!["smtp".to_owned(), "webhook".to_owned(), "inbox".to_owned()],
        default: "smtp".to_owned(),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

pub(crate) async fn get_user_notification_preferences(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let target_user = match resolve_user(&state, &user, &context.user).await? {
        Some(u) => u,
        None => {
            return Ok(not_found_response("User not found."));
        }
    };

    if target_user.id != context.user.id && !context.actor.is_owner() {
        return Ok(forbidden_response(
            "You are not authorized to access this user's notification preferences.",
        ));
    }

    let preferences = state
        .store
        .get_user_notification_preferences(target_user.id)
        .await?;
    Ok((StatusCode::OK, Json(preferences)).into_response())
}

pub(crate) async fn put_user_notification_preferences(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<UpdateUserNotificationPreferences>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let target_user = match resolve_user(&state, &user, &context.user).await? {
        Some(u) => u,
        None => {
            return Ok(not_found_response("User not found."));
        }
    };

    if target_user.id != context.user.id && !context.actor.is_owner() {
        return Ok(forbidden_response(
            "You are not authorized to update this user's notification preferences.",
        ));
    }

    let Json(body) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let mut template_ids = Vec::new();
    let mut disableds = Vec::new();
    for (id_str, disabled) in &body.template_disabled_map {
        let id = match Uuid::from_str(id_str) {
            Ok(id) => id,
            Err(_) => {
                return Ok((
                    StatusCode::BAD_REQUEST,
                    Json(ApiResponse::error(
                        format!("Invalid template ID: {id_str}"),
                        "",
                    )),
                )
                    .into_response());
            }
        };
        template_ids.push(id);
        disableds.push(*disabled);
    }

    state
        .store
        .update_user_notification_preferences(target_user.id, &template_ids, &disableds)
        .await?;

    let preferences = state
        .store
        .get_user_notification_preferences(target_user.id)
        .await?;
    Ok((StatusCode::OK, Json(preferences)).into_response())
}

pub(crate) async fn list_inbox_notifications(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<InboxNotificationsQuery>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can read their own notifications.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::InboxNotification).with_owner(context.user.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to read inbox notifications.",
        ));
    }

    let read_status = params.read_status.unwrap_or_else(|| "all".to_owned());
    if !matches!(read_status.as_str(), "all" | "unread" | "read") {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                format!("Invalid read_status: {read_status}. Must be one of: all, unread, read"),
                "",
            )),
        )
            .into_response());
    }

    let templates: Option<Vec<Uuid>> = match params.templates.as_deref() {
        None | Some("") => None,
        Some(s) => {
            let mut parsed = Vec::new();
            for raw in s.split(',') {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    continue;
                }
                match Uuid::from_str(trimmed) {
                    Ok(id) => parsed.push(id),
                    Err(_) => {
                        return Ok((
                            StatusCode::BAD_REQUEST,
                            Json(ApiResponse::error(
                                format!("Invalid UUID in templates parameter: {trimmed}"),
                                "",
                            )),
                        )
                            .into_response());
                    }
                }
            }
            if parsed.is_empty() {
                None
            } else {
                Some(parsed)
            }
        }
    };
    let targets: Option<Vec<Uuid>> = match params.targets.as_deref() {
        None | Some("") => None,
        Some(s) => {
            let mut parsed = Vec::new();
            for raw in s.split(',') {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    continue;
                }
                match Uuid::from_str(trimmed) {
                    Ok(id) => parsed.push(id),
                    Err(_) => {
                        return Ok((
                            StatusCode::BAD_REQUEST,
                            Json(ApiResponse::error(
                                format!("Invalid UUID in targets parameter: {trimmed}"),
                                "",
                            )),
                        )
                            .into_response());
                    }
                }
            }
            if parsed.is_empty() {
                None
            } else {
                Some(parsed)
            }
        }
    };

    let notifications = state
        .store
        .get_filtered_inbox_notifications(
            context.user.id,
            templates.as_deref(),
            targets.as_deref(),
            &read_status,
            None,
        )
        .await?;

    let unread_count = state
        .store
        .count_unread_inbox_notifications(context.user.id)
        .await?;

    Ok((
        StatusCode::OK,
        Json(coder_core::ListInboxNotificationsResponse {
            notifications,
            unread_count,
        }),
    )
        .into_response())
}

pub(crate) async fn put_mark_all_inbox_notifications_read(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can update their own notifications.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::InboxNotification).with_owner(context.user.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update inbox notifications.",
        ));
    }

    state
        .store
        .mark_all_inbox_notifications_as_read(context.user.id, OffsetDateTime::now_utc())
        .await?;

    // Notify SSE subscribers that the inbox changed.
    let channel = coder_core::pubsub::inbox_notification_channel(context.user.id);
    let _ = state.pubsub.publish(&channel, b"read_all").await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

pub(crate) async fn watch_inbox_notifications(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    use axum::response::sse::{Event, KeepAlive, Sse};
    use std::convert::Infallible;

    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can read their own notifications.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::InboxNotification).with_owner(context.user.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to read inbox notifications.",
        ));
    }

    let channel = coder_core::pubsub::inbox_notification_channel(context.user.id);
    let subscription = state
        .pubsub
        .subscribe(&channel)
        .await
        .map_err(|e| StorageError::unavailable(e.to_string()))?;

    let user_id = context.user.id;
    let store = state.store.clone();

    let stream = async_stream::stream! {
        // Send the initial inbox snapshot as the first SSE event.
        let initial = fetch_inbox_snapshot(&*store, user_id).await;
        match initial {
            Ok(response) => {
                let sse = coder_core::api::ServerSentEvent {
                    event_type: coder_core::api::ServerSentEventType::Data,
                    data: Some(response),
                };
                match serde_json::to_string(&sse) {
                    Ok(json) => {
                        // Include `retry:` hint in the first event so clients
                        // know how long to wait before reconnecting.
                        yield Ok::<_, Infallible>(Event::default().data(json).retry(SSE_RETRY_DURATION));
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "failed to serialize initial inbox SSE event");
                    }
                }
            }
            Err(e) => {
                tracing::debug!(error = %e, "failed to fetch initial inbox snapshot");
                let err_sse = coder_core::api::ServerSentEvent::<coder_core::ListInboxNotificationsResponse> {
                    event_type: coder_core::api::ServerSentEventType::Error,
                    data: None,
                };
                if let Ok(json) = serde_json::to_string(&err_sse) {
                    yield Ok::<_, Infallible>(Event::default().data(json).retry(SSE_RETRY_DURATION));
                }
            }
        }

        // Stream inbox updates from pub/sub.
        let mut sub = subscription;
        while let Ok(_message) = sub.recv().await {
            // On each pub/sub event, re-query the current inbox state.
            match fetch_inbox_snapshot(&*store, user_id).await {
                Ok(response) => {
                    let sse = coder_core::api::ServerSentEvent {
                        event_type: coder_core::api::ServerSentEventType::Data,
                        data: Some(response),
                    };
                    match serde_json::to_string(&sse) {
                        Ok(json) => {
                            yield Ok::<_, Infallible>(Event::default().data(json));
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "failed to serialize inbox SSE event");
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!(error = %e, "failed to fetch inbox snapshot on pub/sub event");
                    continue;
                }
            }
        }
    };

    Ok(Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(SSE_KEEPALIVE_INTERVAL)
                .text("ping"),
        )
        .into_response())
}

/// Fetches the current inbox snapshot for the given user.
async fn fetch_inbox_snapshot(
    store: &dyn AppStore,
    user_id: Uuid,
) -> Result<coder_core::ListInboxNotificationsResponse, AppError> {
    let notifications = store
        .get_filtered_inbox_notifications(user_id, None, None, "all", None)
        .await?;
    let unread_count = store.count_unread_inbox_notifications(user_id).await?;
    Ok(coder_core::ListInboxNotificationsResponse {
        notifications,
        unread_count,
    })
}

pub(crate) async fn put_inbox_notification_read_status(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    payload: Result<Json<UpdateInboxNotificationReadStatusRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can update their own notifications.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::InboxNotification).with_owner(context.user.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update inbox notifications.",
        ));
    }

    let Json(body) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    // Verify the notification exists and belongs to the user
    let notification = match state.store.get_inbox_notification_by_id(id).await? {
        Some(n) => n,
        None => {
            return Ok(not_found_response("Inbox notification not found."));
        }
    };

    if notification.user_id != context.user.id {
        return Ok(forbidden_response(
            "You are not authorized to update this notification.",
        ));
    }

    let read_at = if body.is_read {
        Some(OffsetDateTime::now_utc())
    } else {
        None
    };

    state
        .store
        .update_inbox_notification_read_status(id, read_at)
        .await?;

    // Notify SSE subscribers that the inbox changed.
    let channel = coder_core::pubsub::inbox_notification_channel(context.user.id);
    let _ = state.pubsub.publish(&channel, b"read_status").await;

    let updated = state.store.get_inbox_notification_by_id(id).await?;
    let unread_count = state
        .store
        .count_unread_inbox_notifications(context.user.id)
        .await?;

    match updated {
        Some(notification) => Ok((
            StatusCode::OK,
            Json(coder_core::UpdateInboxNotificationReadStatusResponse {
                notification,
                unread_count,
            }),
        )
            .into_response()),
        None => Ok(not_found_response(
            "Inbox notification not found after update.",
        )),
    }
}

pub(crate) async fn post_user_webpush_subscription(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<WebpushSubscription>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let target_user = match resolve_user(&state, &user, &context.user).await? {
        Some(u) => u,
        None => {
            return Ok(not_found_response("User not found."));
        }
    };

    if target_user.id != context.user.id && !context.actor.is_owner() {
        return Ok(forbidden_response(
            "You are not authorized to manage this user's webpush subscriptions.",
        ));
    }

    let Json(body) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    state
        .store
        .insert_webpush_subscription(
            target_user.id,
            &body.endpoint,
            &body.p256dh_key,
            &body.auth_key,
        )
        .await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

pub(crate) async fn delete_user_webpush_subscription(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<coder_core::DeleteWebpushSubscription>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let target_user = match resolve_user(&state, &user, &context.user).await? {
        Some(u) => u,
        None => {
            return Ok(not_found_response("User not found."));
        }
    };

    if target_user.id != context.user.id && !context.actor.is_owner() {
        return Ok(forbidden_response(
            "You are not authorized to manage this user's webpush subscriptions.",
        ));
    }

    let Json(body) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let deleted = state
        .store
        .delete_webpush_subscription_by_user_and_endpoint(target_user.id, &body.endpoint)
        .await?;

    if deleted {
        Ok(StatusCode::NO_CONTENT.into_response())
    } else {
        Ok(not_found_response("Webpush subscription not found."))
    }
}

pub(crate) async fn post_user_webpush_test(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let target_user = match resolve_user(&state, &user, &context.user).await? {
        Some(u) => u,
        None => {
            return Ok(not_found_response("User not found."));
        }
    };

    if target_user.id != context.user.id && !context.actor.is_owner() {
        return Ok(forbidden_response(
            "You are not authorized to test this user's webpush subscriptions.",
        ));
    }

    // Verify user has webpush subscriptions
    let _subscriptions = state
        .store
        .get_webpush_subscriptions_by_user_id(target_user.id)
        .await?;

    // Full web push sending requires VAPID key infrastructure not yet available.
    // Return success to indicate the endpoint is reachable and the user was resolved.
    Ok((
        StatusCode::OK,
        Json(ApiResponse::ok("Web push test acknowledged.")),
    )
        .into_response())
}

/// Maximum length for custom notification title.
pub(crate) const MAX_CUSTOM_NOTIFICATION_TITLE_LEN: usize = 120;
/// Maximum length for custom notification message.
pub(crate) const MAX_CUSTOM_NOTIFICATION_MESSAGE_LEN: usize = 2000;

/// POST /api/v2/notifications/custom — send a custom notification.
///
/// Validates the request body, ensures the caller is not a system user, and
/// dispatches a custom notification to the caller's inbox (matching Go's
/// `postCustomNotification`, which targets the caller themselves). After
/// persisting the inbox row the handler publishes an
/// [`InboxNotificationEvent`] on the caller's inbox pub/sub channel so that
/// SSE subscribers (`/notifications/inbox/watch`) see the update in real
/// time. Returns 204 No Content on success.
///
/// The template UUID used for custom notifications is
/// [`coder_core::TEMPLATE_CUSTOM_NOTIFICATION`], a compile-time constant
/// matching Go's `notifications.TemplateCustomNotification`.
pub(crate) async fn post_custom_notification(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<coder_core::CustomNotificationRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can create notification messages.
    // In Go, postCustomNotification checks policy.ActionCreate on
    // rbac.ResourceNotificationMessage at site level. Only the owner role
    // has NotificationMessage:Create at site scope, so this is intentionally
    // restricted to site owners. No org scoping needed.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Create,
            &Object::new(ResourceType::NotificationMessage),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to send custom notifications.",
        ));
    }

    let Json(req) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    // Validate: content is required
    let content = match &req.content {
        Some(c) => c,
        None => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error(
                    "Invalid request body",
                    "content is required",
                )),
            )
                .into_response());
        }
    };

    // Validate: title must be non-empty
    if content.title.trim().is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "Invalid request body",
                "provide a non-empty 'content.title'",
            )),
        )
            .into_response());
    }

    // Validate: message must be non-empty
    if content.message.trim().is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "Invalid request body",
                "provide a non-empty 'content.message'",
            )),
        )
            .into_response());
    }

    // Validate: title length
    if content.title.chars().count() > MAX_CUSTOM_NOTIFICATION_TITLE_LEN {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "Invalid request body",
                format!(
                    "'content.title' must be at most {} characters",
                    MAX_CUSTOM_NOTIFICATION_TITLE_LEN
                ),
            )),
        )
            .into_response());
    }

    // Validate: message length
    if content.message.chars().count() > MAX_CUSTOM_NOTIFICATION_MESSAGE_LEN {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "Invalid request body",
                format!(
                    "'content.message' must be at most {} characters",
                    MAX_CUSTOM_NOTIFICATION_MESSAGE_LEN
                ),
            )),
        )
            .into_response());
    }

    // In Go, system users are blocked from sending custom notifications via
    // `user.IsSystem` on the resolved DB record. Mirror that by loading the
    // caller's user record and refusing if it is a system user.
    let caller = match state.store.find_user_by_id(context.user.id).await? {
        Some(user) => user,
        None => {
            return Ok((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error(
                    "Failed to send custom notification",
                    "caller user record not found",
                )),
            )
                .into_response());
        }
    };
    if caller.is_system {
        return Ok((
            StatusCode::FORBIDDEN,
            Json(ApiResponse::error(
                "Forbidden",
                "System users cannot send custom notifications.",
            )),
        )
            .into_response());
    }

    // Go's `postCustomNotification` targets the caller themselves: the
    // `EnqueueWithData` call at `coder/coderd/notifications.go:399-407`
    // passes `user.ID` as the recipient, and the SDK request body
    // `codersdk.CustomNotificationRequest` at
    // `coder/codersdk/notifications.go:292-296` carries only `content` —
    // there is no `user_ids`/`recipient_id`/roles field. A TODO on that
    // struct (coder/coder#19768) tracks future multi-user/role targeting.
    // Mirror that behaviour here and deliver an inbox row to the caller.
    let notification = coder_core::InboxNotification {
        id: Uuid::new_v4(),
        user_id: caller.id,
        template_id: coder_core::TEMPLATE_CUSTOM_NOTIFICATION,
        targets: vec![caller.id],
        title: content.title.clone(),
        content: content.message.clone(),
        icon: String::new(),
        actions: Vec::new(),
        read_at: None,
        created_at: OffsetDateTime::now_utc(),
    };

    state.store.insert_inbox_notification(&notification).await?;

    // Publish an inbox notification event so SSE subscribers on the
    // caller's inbox channel see the new notification in real time. Match
    // Go's `pubsub.InboxNotificationEvent` payload shape.
    let event = coder_core::pubsub::InboxNotificationEvent {
        kind: coder_core::pubsub::InboxNotificationEventKind::New,
        inbox_notification: notification,
    };
    match serde_json::to_vec(&event) {
        Ok(payload) => {
            let channel = coder_core::pubsub::inbox_notification_channel(caller.id);
            let _ = state.pubsub.publish(&channel, &payload).await;
        }
        Err(error) => {
            debug!(
                error = %error,
                "failed to serialize inbox notification event; skipping pubsub publish"
            );
        }
    }

    // Return 204 No Content to match the Go handler's success response.
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::tests::{create_and_login, test_state_with_store};
    use crate::build_router;
    use axum::Router;
    use serde_json::Value;
    use std::error::Error;
    use std::time::Duration;

    type TestResult = Result<(), Box<dyn Error>>;

    /// Spin up a test HTTP server on a random port and return its base URL.
    async fn spawn_test_server(
        router: Router,
    ) -> Result<(url::Url, tokio::task::JoinHandle<()>), Box<dyn Error>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, router.into_make_service()).await;
        });
        Ok((url::Url::parse(&format!("http://{address}"))?, handle))
    }

    /// Read SSE chunks from the response until a complete frame (double newline) is received
    /// or the deadline expires.
    async fn read_sse_frame(
        resp: &mut reqwest::Response,
        timeout_secs: u64,
    ) -> Result<String, Box<dyn Error>> {
        let mut buffer: Vec<u8> = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, resp.chunk()).await {
                Ok(Ok(Some(bytes))) => {
                    buffer.extend_from_slice(&bytes);
                    if buffer.windows(2).any(|w| w == b"\n\n") {
                        break;
                    }
                }
                _ => break,
            }
        }
        Ok(String::from_utf8_lossy(&buffer).into_owned())
    }

    #[tokio::test]
    async fn watch_inbox_notifications_returns_sse_content_type() -> TestResult {
        let (state, _store) = test_state_with_store(true)?;
        let app = build_router(state, None);
        let (base_url, _handle) = spawn_test_server(app.clone()).await?;

        let session_token = create_and_login(&app).await?;
        let url = format!("{base_url}api/v2/notifications/inbox/watch");
        let client = reqwest::Client::new();
        let resp = client
            .get(&url)
            .header("Coder-Session-Token", &session_token)
            .send()
            .await?;

        assert_eq!(resp.status(), StatusCode::OK);
        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            content_type.contains("text/event-stream"),
            "expected text/event-stream, got: {content_type}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn watch_inbox_notifications_sends_initial_snapshot() -> TestResult {
        let (state, _store) = test_state_with_store(true)?;
        let app = build_router(state, None);
        let (base_url, _handle) = spawn_test_server(app.clone()).await?;

        let session_token = create_and_login(&app).await?;
        let url = format!("{base_url}api/v2/notifications/inbox/watch");
        let client = reqwest::Client::new();
        let mut resp = client
            .get(&url)
            .header("Coder-Session-Token", &session_token)
            .send()
            .await?;

        let text = read_sse_frame(&mut resp, 2).await?;
        assert!(
            text.contains("\"type\":\"data\""),
            "expected initial SSE data event, got: {text}"
        );
        assert!(
            text.contains("\"notifications\""),
            "expected notifications field in SSE data, got: {text}"
        );
        assert!(
            text.contains("\"unread_count\""),
            "expected unread_count field in SSE data, got: {text}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn watch_inbox_notifications_streams_pubsub_updates() -> TestResult {
        let (state, _store) = test_state_with_store(true)?;
        let pubsub = state.pubsub.clone();
        let app = build_router(state, None);
        let (base_url, _handle) = spawn_test_server(app.clone()).await?;

        let session_token = create_and_login(&app).await?;
        let url = format!("{base_url}api/v2/notifications/inbox/watch");
        let client = reqwest::Client::new();
        let mut resp = client
            .get(&url)
            .header("Coder-Session-Token", &session_token)
            .send()
            .await?;

        // Consume the initial snapshot event.
        let _ = read_sse_frame(&mut resp, 2).await?;

        // Look up the authenticated user's ID to publish on the right channel.
        let me_resp = client
            .get(format!("{base_url}api/v2/users/me"))
            .header("Coder-Session-Token", &session_token)
            .send()
            .await?;
        let me_body: Value = me_resp.json().await?;
        let user_id_str = me_body
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or("missing user id")?;
        let user_id = Uuid::from_str(user_id_str)?;

        // Publish a notification event via pub/sub.
        let channel = coder_core::pubsub::inbox_notification_channel(user_id);
        pubsub.publish(&channel, b"new_notification").await?;

        // Read the next SSE event triggered by the pub/sub message.
        let text = read_sse_frame(&mut resp, 2).await?;
        assert!(
            !text.is_empty(),
            "expected SSE event after pub/sub publish, got empty"
        );
        assert!(
            text.contains("\"type\":\"data\""),
            "expected SSE data event after pub/sub publish, got: {text}"
        );
        assert!(
            text.contains("\"notifications\""),
            "expected notifications in SSE update, got: {text}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn watch_inbox_notifications_rejects_unauthenticated() -> TestResult {
        let state = crate::app::tests::test_state(true)?;
        let app = build_router(state, None);
        let (base_url, _handle) = spawn_test_server(app).await?;

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("{base_url}api/v2/notifications/inbox/watch"))
            .send()
            .await?;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[tokio::test]
    async fn watch_inbox_notifications_initial_event_contains_retry() -> TestResult {
        let (state, _store) = test_state_with_store(true)?;
        let app = build_router(state, None);
        let (base_url, _handle) = spawn_test_server(app.clone()).await?;

        let session_token = create_and_login(&app).await?;
        let url = format!("{base_url}api/v2/notifications/inbox/watch");
        let client = reqwest::Client::new();
        let mut resp = client
            .get(&url)
            .header("Coder-Session-Token", &session_token)
            .send()
            .await?;

        let text = read_sse_frame(&mut resp, 2).await?;
        assert!(
            text.contains("retry:"),
            "expected retry: field in initial SSE event, got: {text}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn watch_inbox_notifications_mark_all_read_triggers_update() -> TestResult {
        let (state, _store) = test_state_with_store(true)?;
        let app = build_router(state, None);
        let (base_url, _handle) = spawn_test_server(app.clone()).await?;

        let session_token = create_and_login(&app).await?;
        let url = format!("{base_url}api/v2/notifications/inbox/watch");
        let client = reqwest::Client::new();
        let mut resp = client
            .get(&url)
            .header("Coder-Session-Token", &session_token)
            .send()
            .await?;

        // Consume the initial snapshot event.
        let _ = read_sse_frame(&mut resp, 2).await?;

        // Call mark-all-read, which should publish to the inbox channel.
        let mark_resp = client
            .put(format!(
                "{base_url}api/v2/notifications/inbox/mark-all-as-read"
            ))
            .header("Coder-Session-Token", &session_token)
            .send()
            .await?;
        assert_eq!(mark_resp.status(), StatusCode::NO_CONTENT);

        // The SSE stream should receive an update triggered by the write path.
        let text = read_sse_frame(&mut resp, 2).await?;
        assert!(
            text.contains("\"type\":\"data\""),
            "expected SSE data event after mark-all-read, got: {text}"
        );
        assert!(
            text.contains("\"notifications\""),
            "expected notifications in SSE update after mark-all-read, got: {text}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn watch_inbox_notifications_stream_terminates_on_pubsub_close() -> TestResult {
        let (state, _store) = test_state_with_store(true)?;
        let pubsub = state.pubsub.clone();
        let app = build_router(state, None);
        let (base_url, _handle) = spawn_test_server(app.clone()).await?;

        let session_token = create_and_login(&app).await?;
        let url = format!("{base_url}api/v2/notifications/inbox/watch");
        let client = reqwest::Client::new();
        let mut resp = client
            .get(&url)
            .header("Coder-Session-Token", &session_token)
            .send()
            .await?;

        // Consume the initial snapshot event.
        let _ = read_sse_frame(&mut resp, 2).await?;

        // Close the pubsub system — this simulates server shutdown.
        pubsub.close().await?;

        // The stream should terminate: reading should return empty/no more data.
        let text = read_sse_frame(&mut resp, 2).await?;
        // After pubsub closes the stream loop exits and the SSE response ends.
        // We might get empty data or a partial keepalive; the key assertion is
        // that we don't hang — the read_sse_frame call returns within the timeout.
        // The stream should NOT produce another data event.
        let has_data_event =
            text.contains("\"type\":\"data\"") && text.contains("\"notifications\"");
        assert!(
            !has_data_event,
            "stream should not produce data events after pubsub close, got: {text}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn watch_inbox_notifications_sends_keepalive() -> TestResult {
        let (state, _store) = test_state_with_store(true)?;
        let app = build_router(state, None);
        let (base_url, _handle) = spawn_test_server(app.clone()).await?;

        let session_token = create_and_login(&app).await?;
        let url = format!("{base_url}api/v2/notifications/inbox/watch");
        let client = reqwest::Client::new();
        let mut resp = client
            .get(&url)
            .header("Coder-Session-Token", &session_token)
            .send()
            .await?;

        // Consume the initial snapshot event.
        let _ = read_sse_frame(&mut resp, 2).await?;

        // Wait long enough for the keepalive interval (15s) to fire, plus margin.
        // Read raw bytes from the response to detect the `: ping` keepalive comment.
        let mut buffer: Vec<u8> = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, resp.chunk()).await {
                Ok(Ok(Some(bytes))) => {
                    buffer.extend_from_slice(&bytes);
                    let text = String::from_utf8_lossy(&buffer);
                    if text.contains(": ping") {
                        break;
                    }
                }
                _ => break,
            }
        }
        let text = String::from_utf8_lossy(&buffer).into_owned();
        assert!(
            text.contains(": ping"),
            "expected keepalive `: ping` comment within 20s, got: {text}"
        );
        Ok(())
    }

    // -------------------------------------------------------------------
    // post_custom_notification tests
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn custom_notification_valid_inputs_returns_204() -> TestResult {
        let (state, _store) = test_state_with_store(true)?;
        let app = build_router(state, None);
        let (base_url, _handle) = spawn_test_server(app.clone()).await?;

        let session_token = create_and_login(&app).await?;
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{base_url}api/v2/notifications/custom"))
            .header("Coder-Session-Token", &session_token)
            .json(&serde_json::json!({
                "content": {
                    "title": "Test Title",
                    "message": "Test message body"
                }
            }))
            .send()
            .await?;

        assert_eq!(
            resp.status(),
            StatusCode::NO_CONTENT,
            "expected 204 for valid custom notification"
        );
        Ok(())
    }

    #[tokio::test]
    async fn custom_notification_missing_content_returns_400() -> TestResult {
        let (state, _store) = test_state_with_store(true)?;
        let app = build_router(state, None);
        let (base_url, _handle) = spawn_test_server(app.clone()).await?;

        let session_token = create_and_login(&app).await?;
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{base_url}api/v2/notifications/custom"))
            .header("Coder-Session-Token", &session_token)
            .json(&serde_json::json!({}))
            .send()
            .await?;

        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "expected 400 when content is missing"
        );
        let body: Value = resp.json().await?;
        assert_eq!(body["detail"], "content is required");
        Ok(())
    }

    #[tokio::test]
    async fn custom_notification_empty_title_returns_400() -> TestResult {
        let (state, _store) = test_state_with_store(true)?;
        let app = build_router(state, None);
        let (base_url, _handle) = spawn_test_server(app.clone()).await?;

        let session_token = create_and_login(&app).await?;
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{base_url}api/v2/notifications/custom"))
            .header("Coder-Session-Token", &session_token)
            .json(&serde_json::json!({
                "content": {
                    "title": "",
                    "message": "Non-empty message"
                }
            }))
            .send()
            .await?;

        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "expected 400 when title is empty"
        );
        let body: Value = resp.json().await?;
        assert_eq!(body["detail"], "provide a non-empty 'content.title'");
        Ok(())
    }

    #[tokio::test]
    async fn custom_notification_empty_message_returns_400() -> TestResult {
        let (state, _store) = test_state_with_store(true)?;
        let app = build_router(state, None);
        let (base_url, _handle) = spawn_test_server(app.clone()).await?;

        let session_token = create_and_login(&app).await?;
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{base_url}api/v2/notifications/custom"))
            .header("Coder-Session-Token", &session_token)
            .json(&serde_json::json!({
                "content": {
                    "title": "Valid Title",
                    "message": "   "
                }
            }))
            .send()
            .await?;

        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "expected 400 when message is whitespace-only"
        );
        let body: Value = resp.json().await?;
        assert_eq!(body["detail"], "provide a non-empty 'content.message'");
        Ok(())
    }

    #[tokio::test]
    async fn custom_notification_rejects_unauthenticated() -> TestResult {
        let state = crate::app::tests::test_state(true)?;
        let app = build_router(state, None);
        let (base_url, _handle) = spawn_test_server(app).await?;

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{base_url}api/v2/notifications/custom"))
            .json(&serde_json::json!({
                "content": {
                    "title": "Test",
                    "message": "Test"
                }
            }))
            .send()
            .await?;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    // -------------------------------------------------------------------
    // Compile-time constant UUID tests
    // -------------------------------------------------------------------

    #[test]
    fn custom_notification_template_id_matches_expected_value() {
        assert_eq!(
            coder_core::TEMPLATE_CUSTOM_NOTIFICATION.to_string(),
            "39b1e189-c857-4b0c-877a-511144c18516",
            "TEMPLATE_CUSTOM_NOTIFICATION must match the Go reference value"
        );
    }

    #[test]
    fn test_notification_template_id_matches_expected_value() {
        assert_eq!(
            coder_core::TEMPLATE_TEST_NOTIFICATION.to_string(),
            "c425f63e-716a-4bf4-ae24-78348f706c3f",
            "TEMPLATE_TEST_NOTIFICATION must match the Go reference value"
        );
    }

    #[test]
    fn prebuilds_system_user_id_matches_expected_value() {
        assert_eq!(
            coder_core::PREBUILDS_SYSTEM_USER_ID.to_string(),
            "c42fdf75-3097-471c-8c33-fb52454d81c0",
            "PREBUILDS_SYSTEM_USER_ID must match the Go reference value"
        );
    }

    #[test]
    fn compile_time_uuid_constants_are_not_nil() {
        assert!(!coder_core::TEMPLATE_CUSTOM_NOTIFICATION.is_nil());
        assert!(!coder_core::TEMPLATE_TEST_NOTIFICATION.is_nil());
        assert!(!coder_core::PREBUILDS_SYSTEM_USER_ID.is_nil());
    }

    /// After a successful `POST /api/v2/notifications/custom` the handler
    /// should persist an inbox notification for the caller, targeted at
    /// themselves and carrying the request's title/message as title/content.
    #[tokio::test]
    async fn post_custom_notification_inserts_inbox_row_for_caller() -> TestResult {
        use crate::app::tests::{authenticated_json_request, call};
        use axum::http::Method;
        use serde_json::json;

        let (state, store) = test_state_with_store(true)?;
        let app = build_router(state, None);
        let session_token = create_and_login(&app).await?;

        // Resolve the authenticated caller's id.
        let me_resp = call(
            app.clone(),
            crate::app::tests::authenticated_request(
                Method::GET,
                "/api/v2/users/me",
                &session_token,
            )?,
        )
        .await?;
        let me_body = crate::app::tests::response_json(me_resp).await?;
        let user_id = Uuid::from_str(
            me_body
                .get("id")
                .and_then(Value::as_str)
                .ok_or("missing user id")?,
        )?;

        let response = call(
            app,
            authenticated_json_request(
                Method::POST,
                "/api/v2/notifications/custom",
                &session_token,
                &json!({
                    "content": {
                        "title": "Hello",
                        "message": "World"
                    }
                }),
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let stored = store
            .get_filtered_inbox_notifications(user_id, None, None, "all", None)
            .await?;
        assert_eq!(
            stored.len(),
            1,
            "expected exactly one inbox notification for caller"
        );
        let row = &stored[0];
        assert_eq!(row.user_id, user_id);
        assert_eq!(row.template_id, coder_core::TEMPLATE_CUSTOM_NOTIFICATION);
        assert_eq!(row.targets, vec![user_id]);
        assert_eq!(row.title, "Hello");
        assert_eq!(row.content, "World");
        assert!(row.read_at.is_none());
        Ok(())
    }

    /// On successful dispatch the handler should publish an
    /// `InboxNotificationEvent` on the caller's inbox pub/sub channel so
    /// that SSE subscribers on `/notifications/inbox/watch` receive an
    /// update in real time.
    #[tokio::test]
    async fn post_custom_notification_publishes_inbox_pubsub_event() -> TestResult {
        use crate::app::tests::{authenticated_json_request, call};
        use axum::http::Method;
        use serde_json::json;

        let (state, _store) = test_state_with_store(true)?;
        let pubsub = state.pubsub.clone();
        let app = build_router(state, None);
        let session_token = create_and_login(&app).await?;

        let me_resp = call(
            app.clone(),
            crate::app::tests::authenticated_request(
                Method::GET,
                "/api/v2/users/me",
                &session_token,
            )?,
        )
        .await?;
        let me_body = crate::app::tests::response_json(me_resp).await?;
        let user_id = Uuid::from_str(
            me_body
                .get("id")
                .and_then(Value::as_str)
                .ok_or("missing user id")?,
        )?;

        // Subscribe before invoking the handler so we don't race the publish.
        let mut subscription = pubsub
            .subscribe(&coder_core::pubsub::inbox_notification_channel(user_id))
            .await?;

        let response = call(
            app,
            authenticated_json_request(
                Method::POST,
                "/api/v2/notifications/custom",
                &session_token,
                &json!({
                    "content": {
                        "title": "Ping",
                        "message": "From test"
                    }
                }),
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let payload = tokio::time::timeout(Duration::from_secs(2), subscription.recv()).await??;

        let event: coder_core::pubsub::InboxNotificationEvent = serde_json::from_slice(&payload)?;
        assert_eq!(
            event.kind,
            coder_core::pubsub::InboxNotificationEventKind::New
        );
        assert_eq!(event.inbox_notification.user_id, user_id);
        assert_eq!(event.inbox_notification.title, "Ping");
        assert_eq!(event.inbox_notification.content, "From test");
        Ok(())
    }

    /// Go's `postCustomNotification` refuses requests from system users
    /// (`user.IsSystem`). Verify the Rust handler does the same.
    #[tokio::test]
    async fn post_custom_notification_blocks_system_user() -> TestResult {
        use crate::app::tests::{authenticated_json_request, call};
        use axum::http::Method;
        use serde_json::json;

        let (state, store) = test_state_with_store(true)?;
        let app = build_router(state, None);
        let session_token = create_and_login(&app).await?;

        let me_resp = call(
            app.clone(),
            crate::app::tests::authenticated_request(
                Method::GET,
                "/api/v2/users/me",
                &session_token,
            )?,
        )
        .await?;
        let me_body = crate::app::tests::response_json(me_resp).await?;
        let user_id = Uuid::from_str(
            me_body
                .get("id")
                .and_then(Value::as_str)
                .ok_or("missing user id")?,
        )?;

        store.set_user_is_system(user_id, true)?;

        let response = call(
            app,
            authenticated_json_request(
                Method::POST,
                "/api/v2/notifications/custom",
                &session_token,
                &json!({
                    "content": {
                        "title": "Should not dispatch",
                        "message": "System users are blocked"
                    }
                }),
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let stored = store
            .get_filtered_inbox_notifications(user_id, None, None, "all", None)
            .await?;
        assert!(
            stored.is_empty(),
            "system user should not produce inbox rows, got {stored:?}"
        );
        Ok(())
    }
}
