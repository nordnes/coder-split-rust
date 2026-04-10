//! User CRUD, profile, preferences, appearance, role, and quiet hours handlers.

use super::*;
use chrono_tz::Tz;
use coder_core::api::{UpdateUserQuietHoursScheduleRequest, UserQuietHoursScheduleResponse};

/// Maximum number of rows a single paginated request may return.
///
/// This prevents clients from requesting unbounded result sets that could
/// exhaust server memory or cause excessive database load.
const MAX_PAGE_LIMIT: u32 = 1_000;

/// Clamps a caller-supplied pagination limit to `[0, MAX_PAGE_LIMIT]`.
///
/// A value of `0` is left as-is so the downstream layer can apply its own
/// default.  Values above `MAX_PAGE_LIMIT` are silently reduced.
pub(crate) fn clamp_pagination_limit(raw: u32) -> u32 {
    raw.min(MAX_PAGE_LIMIT)
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct UsersQuery {
    #[serde(default)]
    q: String,
    status: Option<String>,
    limit: Option<u32>,
    offset: Option<u32>,
}

/// GET /api/v2/users — list users with optional filtering and pagination.
pub(crate) async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<UsersQuery>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !context.actor.can_list_users() {
        return Ok(forbidden_response("You are not authorized to list users."));
    }

    let status = match query.status.as_deref() {
        Some(value) => match UserStatus::from_str(value) {
            Ok(status) => Some(status),
            Err(error) => {
                return Ok(validation_response(vec![ValidationError {
                    field: "status".to_owned(),
                    detail: error.to_string(),
                }]));
            }
        },
        None => None,
    };

    let (users, count) = match state
        .identity
        .list_users(
            &context.actor,
            UserListFilter {
                search: query.q,
                status,
                limit: clamp_pagination_limit(query.limit.unwrap_or_default()),
                offset: query.offset.unwrap_or_default(),
            },
        )
        .await
    {
        Ok(result) => result,
        Err(error) => return handle_identity_error(error),
    };

    Ok((
        StatusCode::OK,
        Json(GetUsersResponse {
            users: users.into_iter().map(UserResponse::from).collect(),
            count,
        }),
    )
        .into_response())
}

/// POST /api/v2/users — create a new user account.
pub(crate) async fn post_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<CreateUserRequestWithOrgs>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can create users.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Create,
            &Object::new(ResourceType::User),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to create users.",
        ));
    }

    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    let user = match state.identity.create_user(&context.actor, &request).await {
        Ok(user) => user,
        Err(error) => return handle_identity_error(error),
    };

    record_audit(
        &state,
        AuditAction::Create,
        ResourceKind::User,
        Some(&context.user),
        Some(user.id.to_string()),
        "created user",
    )
    .await;

    Ok((StatusCode::CREATED, Json(UserResponse::from(user))).into_response())
}

/// GET /api/v2/users/:user/login-type — return the user's authentication method.
pub(crate) async fn get_user_login_type(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let response = match state
        .auth
        .get_user_login_type(&context.actor, &context.user, &user)
        .await
    {
        Ok(response) => response,
        Err(error) => return handle_auth_error(error),
    };

    Ok((StatusCode::OK, Json(response)).into_response())
}

/// GET /api/v2/users/:user/gitsshkey — return the user's Git SSH public key.
pub(crate) async fn get_user_git_ssh_key(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Some(target_user) = resolve_user(&state, &user, &context.user).await? else {
        return Ok(not_found_response("User not found."));
    };
    if !context.actor.can_access_user(target_user.id) {
        return Ok(not_found_response("User not found."));
    }

    let key = match state.store.find_git_ssh_key(target_user.id).await? {
        Some(key) => key,
        None => match store_new_git_ssh_key(&state, &target_user).await {
            Ok(key) => key,
            Err(error) => {
                return Ok(internal_server_error_detail_response(
                    "Internal error generating a new SSH keypair.",
                    error,
                ));
            }
        },
    };

    Ok((
        StatusCode::OK,
        Json(coder_core::GitSshKeyResponse {
            user_id: key.user_id,
            created_at: key.created_at,
            updated_at: key.updated_at,
            public_key: key.public_key,
        }),
    )
        .into_response())
}

/// PUT /api/v2/users/:user/gitsshkey — regenerate and return a new Git SSH key.
pub(crate) async fn put_user_git_ssh_key(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Some(target_user) = resolve_user(&state, &user, &context.user).await? else {
        return Ok(not_found_response("User not found."));
    };
    // RBAC: verify the actor can update this user's SSH key.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::UpdatePersonal,
            &Object::new(ResourceType::User)
                .with_id(target_user.id)
                .with_owner(target_user.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update this user's SSH key.",
        ));
    }

    let key = match store_new_git_ssh_key(&state, &target_user).await {
        Ok(key) => key,
        Err(error) => {
            return Ok(internal_server_error_detail_response(
                "Internal error generating a new SSH keypair.",
                error,
            ));
        }
    };

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::GitSshKey,
        Some(&context.user),
        Some(target_user.id.to_string()),
        "regenerated git ssh key",
    )
    .await;

    Ok((
        StatusCode::OK,
        Json(coder_core::GitSshKeyResponse {
            user_id: key.user_id,
            created_at: key.created_at,
            updated_at: key.updated_at,
            public_key: key.public_key,
        }),
    )
        .into_response())
}

pub(crate) async fn get_user_autofill_parameters(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Some(target_user) = resolve_user(&state, &user, &context.user).await? else {
        return Ok(not_found_response("User not found."));
    };
    if context.user.username != target_user.username && !context.actor.is_owner() {
        return Ok(forbidden_response(
            "You are not authorized to inspect this user.",
        ));
    }

    let mut validations = Vec::new();
    match query.get("template_id") {
        Some(template_id) if !template_id.is_empty() => {
            if let Err(error) = Uuid::parse_str(template_id) {
                validations.push(ValidationError {
                    field: "template_id".to_owned(),
                    detail: error.to_string(),
                });
            }
        }
        _ => validations.push(ValidationError {
            field: "template_id".to_owned(),
            detail: "Missing value, this cannot be empty".to_owned(),
        }),
    }

    for key in query.keys() {
        if key != "template_id" {
            validations.push(ValidationError {
                field: key.clone(),
                detail: "unknown query parameter".to_owned(),
            });
        }
    }

    if !validations.is_empty() {
        return Ok(validation_message_response(
            "Invalid query parameters.",
            validations,
        ));
    }

    Ok(Json(Vec::<UserParameter>::new()).into_response())
}

/// PUT /api/v2/users/:user/profile — update a user's display name and username.
pub(crate) async fn put_user_profile(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<UpdateUserProfileRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    let updated_user = match state
        .identity
        .update_user_profile(&context.actor, &context.user, &user, &request)
        .await
    {
        Ok(user) => user,
        Err(error) => return handle_identity_error(error),
    };

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::User,
        Some(&context.user),
        Some(updated_user.id.to_string()),
        "updated user profile",
    )
    .await;

    Ok((StatusCode::OK, Json(UserResponse::from(updated_user))).into_response())
}

pub(crate) async fn put_suspend_user_account(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    put_user_status(state, user, headers, UserStatus::Suspended).await
}

pub(crate) async fn put_activate_user_account(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    put_user_status(state, user, headers, UserStatus::Active).await
}

pub(crate) async fn put_user_status(
    state: AppState,
    user: String,
    headers: HeaderMap,
    status: UserStatus,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can update user status.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::User),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update user status.",
        ));
    }

    let updated_user = match state
        .identity
        .update_user_status(&context.actor, &context.user, &user, status)
        .await
    {
        Ok(user) => user,
        Err(error) => return handle_identity_error(error),
    };

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::User,
        Some(&context.user),
        Some(updated_user.id.to_string()),
        "updated user status",
    )
    .await;

    Ok((StatusCode::OK, Json(UserResponse::from(updated_user))).into_response())
}

/// GET /api/v2/users/:user/appearance — return the user's UI appearance settings.
pub(crate) async fn get_user_appearance(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let settings = match state
        .identity
        .get_user_appearance(&context.actor, &context.user, &user)
        .await
    {
        Ok(settings) => settings,
        Err(error) => return handle_identity_error(error),
    };
    Ok((
        StatusCode::OK,
        Json(UserAppearanceSettings {
            theme_preference: settings.theme_preference,
            terminal_font: settings.terminal_font,
        }),
    )
        .into_response())
}

/// PUT /api/v2/users/:user/appearance — update the user's UI appearance settings.
pub(crate) async fn put_user_appearance(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<UpdateUserAppearanceSettingsRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    let (target_user_id, settings) = match state
        .identity
        .update_user_appearance(&context.actor, &context.user, &user, &request)
        .await
    {
        Ok(settings) => settings,
        Err(error) => return handle_identity_error(error),
    };

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::User,
        Some(&context.user),
        Some(target_user_id.to_string()),
        "updated user appearance settings",
    )
    .await;

    Ok((
        StatusCode::OK,
        Json(UserAppearanceSettings {
            theme_preference: settings.theme_preference,
            terminal_font: settings.terminal_font,
        }),
    )
        .into_response())
}

/// GET /api/v2/users/:user/preferences — return the user's notification preferences.
pub(crate) async fn get_user_preferences(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let settings = match state
        .identity
        .get_user_preferences(&context.actor, &context.user, &user)
        .await
    {
        Ok(settings) => settings,
        Err(error) => return handle_identity_error(error),
    };
    Ok((
        StatusCode::OK,
        Json(UserPreferenceSettings {
            task_notification_alert_dismissed: settings.task_notification_alert_dismissed,
        }),
    )
        .into_response())
}

/// PUT /api/v2/users/:user/preferences — update the user's notification preferences.
pub(crate) async fn put_user_preferences(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<UpdateUserPreferenceSettingsRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    let (target_user_id, settings) = match state
        .identity
        .update_user_preferences(&context.actor, &context.user, &user, &request)
        .await
    {
        Ok(settings) => settings,
        Err(error) => return handle_identity_error(error),
    };

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::User,
        Some(&context.user),
        Some(target_user_id.to_string()),
        "updated user preference settings",
    )
    .await;

    Ok((
        StatusCode::OK,
        Json(UserPreferenceSettings {
            task_notification_alert_dismissed: settings.task_notification_alert_dismissed,
        }),
    )
        .into_response())
}

/// PUT /api/v2/users/:user/password — change the user's password.
pub(crate) async fn put_user_password(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<UpdateUserPasswordRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    let target_user_id = match state
        .auth
        .update_user_password(&context.actor, &context.user, &user, &request)
        .await
    {
        Ok(target_user_id) => target_user_id,
        Err(error) => return handle_auth_error(error),
    };

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::User,
        Some(&context.user),
        Some(target_user_id.to_string()),
        "updated user password",
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// GET /api/v2/users/:user — return a single user by ID or username.
pub(crate) async fn get_user(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let target_user = match state
        .identity
        .get_user(&context.actor, &context.user, &user)
        .await
    {
        Ok(user) => user,
        Err(error) => return handle_identity_error(error),
    };

    Ok((StatusCode::OK, Json(UserResponse::from(target_user))).into_response())
}

pub(crate) async fn list_site_roles(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let roles = match state.identity.list_site_roles(&context.actor) {
        Ok(roles) => roles,
        Err(error) => return handle_identity_error(error),
    };

    Ok((StatusCode::OK, Json(roles)).into_response())
}

pub(crate) async fn get_user_roles(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let (target_user, organization_roles) = match state
        .identity
        .get_user_roles(&context.actor, &context.user, &user)
        .await
    {
        Ok(result) => result,
        Err(error) => return handle_identity_error(error),
    };

    Ok((
        StatusCode::OK,
        Json(UserRolesResponse {
            roles: target_user
                .roles
                .into_iter()
                .map(|role| role.name)
                .collect(),
            organization_roles,
        }),
    )
        .into_response())
}

pub(crate) async fn put_user_roles(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<UpdateRolesRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can assign user roles (admin-only).
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Assign,
            &Object::new(ResourceType::AssignRole),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to assign user roles.",
        ));
    }

    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    let updated_user = match state
        .identity
        .update_user_roles(&context.actor, &context.user, &user, &request)
        .await
    {
        Ok(user) => user,
        Err(error) => return handle_identity_error(error),
    };

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::User,
        Some(&context.user),
        Some(updated_user.id.to_string()),
        "updated user roles",
    )
    .await;

    Ok((StatusCode::OK, Json(UserResponse::from(updated_user))).into_response())
}

/// GET /api/v2/users/:user/organizations — list organizations the user belongs to.
pub(crate) async fn list_user_organizations(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let organizations = match state
        .identity
        .list_user_organizations(&context.actor, &context.user, &user)
        .await
    {
        Ok(organizations) => organizations,
        Err(error) => return handle_identity_error(error),
    };

    Ok((
        StatusCode::OK,
        Json(
            organizations
                .into_iter()
                .map(OrganizationResponse::from)
                .collect::<Vec<_>>(),
        ),
    )
        .into_response())
}

pub(crate) async fn get_user_organization_by_name(
    State(state): State<AppState>,
    Path((user, organizationname)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let target_organization = match state
        .identity
        .get_user_organization_by_name(&context.actor, &context.user, &user, &organizationname)
        .await
    {
        Ok(organization) => organization,
        Err(error) => return handle_identity_error(error),
    };

    Ok((
        StatusCode::OK,
        Json(OrganizationResponse::from(target_organization)),
    )
        .into_response())
}

/// DELETE /api/v2/users/:user — permanently delete a user account.
pub(crate) async fn delete_user(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can delete users.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Delete,
            &Object::new(ResourceType::User),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to delete users.",
        ));
    }

    let target_user = match state
        .identity
        .delete_user(&context.actor, &context.user, &user)
        .await
    {
        Ok(user) => user,
        Err(error) => return handle_identity_error(error),
    };

    record_audit(
        &state,
        AuditAction::Delete,
        ResourceKind::User,
        Some(&context.user),
        Some(target_user.id.to_string()),
        "deleted user",
    )
    .await;

    Ok((
        StatusCode::OK,
        Json(ApiResponse::ok("User has been deleted!")),
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// Quiet Hours
// ---------------------------------------------------------------------------

/// Key used to store the quiet hours schedule in the `user_configs` table.
const QUIET_HOURS_SCHEDULE_KEY: &str = "quiet_hours_schedule";

/// Parsed components of a quiet-hours cron schedule.
struct ParsedQuietHours<'a> {
    tz_name: &'a str,
    hour: u32,
    minute: u32,
}

/// Extracts timezone, hour, and minute from a quiet-hours cron schedule.
///
/// Expected format: `CRON_TZ=America/Chicago 0 0 * * *`
/// Falls back to `UTC` / `0` for missing or unparseable parts.
fn parse_cron_fields(schedule: &str) -> ParsedQuietHours<'_> {
    let schedule = schedule.trim();
    let (tz_name, cron_part) = if let Some(rest) = schedule.strip_prefix("CRON_TZ=") {
        match rest.split_once(' ') {
            Some((tz, cron)) => (tz, cron),
            None => ("UTC", rest),
        }
    } else {
        ("UTC", schedule)
    };

    let fields: Vec<&str> = cron_part.split_whitespace().collect();
    let minute: u32 = fields.first().and_then(|f| f.parse().ok()).unwrap_or(0);
    let hour: u32 = fields.get(1).and_then(|f| f.parse().ok()).unwrap_or(0);

    ParsedQuietHours {
        tz_name,
        hour,
        minute,
    }
}

/// Returns `(timezone_name, "HH:MM")` for a quiet-hours cron schedule.
fn parse_quiet_hours_cron(schedule: &str) -> (String, String) {
    let parsed = parse_cron_fields(schedule);
    let time_str = format!("{:02}:{:02}", parsed.hour, parsed.minute);
    (parsed.tz_name.to_owned(), time_str)
}

/// Computes the next quiet hours window start time in UTC given a cron schedule.
///
/// Parses the `CRON_TZ=` prefix to obtain the IANA timezone, converts the
/// local hour/minute to UTC using `chrono-tz`, and returns the next occurrence.
/// If the timezone is invalid or missing, falls back to UTC.
fn next_quiet_hours(schedule: &str) -> OffsetDateTime {
    let parsed = parse_cron_fields(schedule);

    // Parse the timezone; fall back to UTC on failure.
    let tz: Tz = parsed.tz_name.parse().unwrap_or(chrono_tz::UTC);

    use chrono::{NaiveTime, TimeZone, Utc};
    let now_utc = Utc::now();
    let now_local = now_utc.with_timezone(&tz);

    let target_time = NaiveTime::from_hms_opt(parsed.hour, parsed.minute, 0).unwrap_or_default();

    // Build today's candidate in the local timezone.
    let today_naive = now_local.date_naive().and_time(target_time);
    let today_local = tz.from_local_datetime(&today_naive).earliest();

    let next_utc = match today_local {
        Some(dt) if dt > now_local => dt.with_timezone(&Utc),
        _ => {
            // Already passed today or ambiguous — try tomorrow.
            let tomorrow_naive =
                (now_local.date_naive() + chrono::Duration::days(1)).and_time(target_time);
            tz.from_local_datetime(&tomorrow_naive)
                .earliest()
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or(now_utc)
        }
    };

    // Convert chrono::DateTime<Utc> → time::OffsetDateTime.
    OffsetDateTime::from_unix_timestamp(next_utc.timestamp()).unwrap_or(OffsetDateTime::now_utc())
}

/// Validates a quiet hours cron schedule string.
///
/// Returns `Ok(())` if the schedule is valid, or an error message if not.
fn validate_quiet_hours_schedule(schedule: &str) -> Result<(), String> {
    let schedule = schedule.trim();
    if schedule.is_empty() {
        return Err("Schedule must not be empty.".to_owned());
    }

    let parsed = parse_cron_fields(schedule);

    // Validate timezone against the IANA database via chrono-tz.
    if parsed.tz_name != "UTC" && parsed.tz_name.parse::<Tz>().is_err() {
        return Err(format!("Invalid timezone: {}", parsed.tz_name));
    }

    // Ensure the schedule has a CRON_TZ prefix *and* cron fields following it,
    // or is a bare 5-field cron expression.
    let cron_part = if let Some(rest) = schedule.strip_prefix("CRON_TZ=") {
        match rest.split_once(' ') {
            Some((_, cron)) => cron,
            None => return Err("Missing cron fields after CRON_TZ.".to_owned()),
        }
    } else {
        schedule
    };

    let fields: Vec<&str> = cron_part.split_whitespace().collect();
    if fields.len() < 5 {
        return Err("Cron schedule must have at least 5 fields.".to_owned());
    }

    // Validate minute and hour fields are numeric and in range.
    // Note: we cannot rely on `parsed.hour` / `parsed.minute` here because
    // `parse_cron_fields` silently defaults non-numeric values to 0.
    let minute: u32 = match fields[0].parse() {
        Ok(v) => v,
        Err(_) => return Err(format!("Invalid minute field: {}", fields[0])),
    };
    let hour: u32 = match fields[1].parse() {
        Ok(v) => v,
        Err(_) => return Err(format!("Invalid hour field: {}", fields[1])),
    };
    if hour >= 24 {
        return Err(format!("Invalid hour field: {}", fields[1]));
    }
    if minute >= 60 {
        return Err(format!("Invalid minute field: {}", fields[0]));
    }

    Ok(())
}

/// GET /api/v2/users/{user}/quiet-hours — get a user's quiet hours schedule.
pub(crate) async fn get_user_quiet_hours(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // Feature gate: AdvancedTemplateScheduling must be entitled.
    // Since no persistent EntitlementSet is wired into AppState yet, we check
    // the feature gate via the license helpers. For now, we allow access (the
    // entitlement check will be enforced once the license service is integrated).
    // TODO: enforce FeatureName::AdvancedTemplateScheduling entitlement check.

    let Some(target_user) = resolve_user(&state, &user, &context.user).await? else {
        return Ok(resource_not_found_response());
    };

    // RBAC: verify the actor can read this user's personal data.
    if !context.actor.can_access_user(target_user.id) {
        return Ok(resource_not_found_response());
    }

    // Read the user's quiet hours schedule from user_configs.
    let config_record = state
        .store
        .get_user_config(target_user.id, QUIET_HOURS_SCHEDULE_KEY)
        .await?;

    let default_schedule = &state.config.workspace.default_quiet_hours_schedule;
    let (raw_schedule, user_set) = match config_record {
        Some(ref record) if !record.value.is_empty() => (record.value.clone(), true),
        _ => (default_schedule.clone(), false),
    };

    let (timezone, time_str) = parse_quiet_hours_cron(&raw_schedule);
    let next = next_quiet_hours(&raw_schedule);

    // user_can_set: deployment allows users to set their own schedule.
    // For now, we default to true. This should be read from deployment config
    // once the allow_custom_quiet_hours flag is implemented.
    let user_can_set = true;

    Ok((
        StatusCode::OK,
        Json(UserQuietHoursScheduleResponse {
            raw_schedule,
            user_set,
            user_can_set,
            time: time_str,
            timezone,
            next,
        }),
    )
        .into_response())
}

/// PUT /api/v2/users/{user}/quiet-hours — update a user's quiet hours schedule.
pub(crate) async fn put_user_quiet_hours(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<UpdateUserQuietHoursScheduleRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // TODO: enforce FeatureName::AdvancedTemplateScheduling entitlement check.

    let Some(target_user) = resolve_user(&state, &user, &context.user).await? else {
        return Ok(resource_not_found_response());
    };

    // RBAC: verify the actor can update this user's personal data.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::UpdatePersonal,
            &Object::new(ResourceType::User)
                .with_id(target_user.id)
                .with_owner(target_user.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update this user's quiet hours schedule.",
        ));
    }

    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    // Validate the cron schedule.
    if let Err(msg) = validate_quiet_hours_schedule(&request.schedule) {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error("Invalid quiet hours schedule.", msg)),
        )
            .into_response());
    }

    // Save the schedule.
    state
        .store
        .upsert_user_config(target_user.id, QUIET_HOURS_SCHEDULE_KEY, &request.schedule)
        .await?;

    // Audit log.
    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::User,
        Some(&context.user),
        Some(target_user.id.to_string()),
        "updated quiet hours schedule",
    )
    .await;

    // Return the updated schedule.
    let (timezone, time_str) = parse_quiet_hours_cron(&request.schedule);
    let next = next_quiet_hours(&request.schedule);

    Ok((
        StatusCode::OK,
        Json(UserQuietHoursScheduleResponse {
            raw_schedule: request.schedule,
            user_set: true,
            user_can_set: true,
            time: time_str,
            timezone,
            next,
        }),
    )
        .into_response())
}
