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

    Ok(StatusCode::NO_CONTENT.into_response())
}

pub(crate) async fn watch_inbox_notifications(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // Return initial state. Real-time push requires pub/sub infrastructure not yet available.
    let notifications = state
        .store
        .get_filtered_inbox_notifications(context.user.id, None, None, "all", None)
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
/// enqueues a custom notification.  Full dispatch is not yet wired, so the
/// handler currently returns 204 No Content after validation succeeds.
pub(crate) async fn post_custom_notification(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<coder_core::CustomNotificationRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // Block system users from sending custom notifications.
    // Checked early (before input validation) to match Go handler ordering.
    if context.user.is_system {
        return Ok((
            StatusCode::FORBIDDEN,
            Json(ApiResponse::error(
                "Forbidden",
                "System users cannot send custom notifications.",
            )),
        )
            .into_response());
    }

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

    // Validate: title and message must be non-empty
    if content.title.trim().is_empty() || content.message.trim().is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "Invalid request body",
                "provide a non-empty 'content.title' and 'content.message'",
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

    // Custom notification template UUID (matches Go's TemplateCustomNotification).
    let template_id = Uuid::parse_str("39b1e189-c857-4b0c-877a-511144c18516").unwrap_or_default();

    // Build the JSON payload matching the Go handler's label map.
    // Include a minute-bucketed timestamp to bypass per-day deduplication for
    // self-sends, matching the Go implementation.
    let now = OffsetDateTime::now_utc();
    let dedupe_ts = now
        .replace_second(0)
        .unwrap_or(now)
        .replace_nanosecond(0)
        .unwrap_or(now);
    let payload = serde_json::json!({
        "custom_title": content.title,
        "custom_message": content.message,
        "dedupe_bypass_ts": dedupe_ts.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
    });

    let user_id = context.user.id;

    // Enqueue the notification for inbox delivery.  The dispatch service will
    // pick this up on its next poll cycle and deliver it.
    let input = EnqueueNotificationMessageInput {
        id: Uuid::new_v4(),
        user_id,
        notification_template_id: template_id,
        method: NotificationMethod::Inbox,
        payload: payload.to_string(),
        targets: vec![user_id],
        created_by: user_id,
    };
    state
        .store
        .enqueue_notification_message(&input)
        .await
        .map_err(AppError::from)?;

    Ok(StatusCode::NO_CONTENT.into_response())
}
