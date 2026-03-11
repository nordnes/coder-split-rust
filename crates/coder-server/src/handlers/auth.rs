//! Authentication, session management, and API key handlers.

use super::*;

#[derive(Debug, Default, Deserialize)]
pub(crate) struct TokenListQuery {
    #[serde(default)]
    include_all: bool,
    #[serde(default)]
    include_expired: bool,
}

pub(crate) async fn list_api_key_scopes() -> Json<ExternalApiKeyScopes> {
    Json(ExternalApiKeyScopes {
        external: PUBLIC_API_KEY_SCOPES
            .iter()
            .map(|scope| (*scope).to_owned())
            .collect(),
    })
}

pub(crate) async fn auth_methods() -> Json<AuthMethods> {
    Json(supported_auth_methods())
}

pub(crate) async fn get_first_user(State(state): State<AppState>) -> Result<Response, AppError> {
    let exists = state.auth.first_user_exists().await?;
    let body = if exists {
        ApiResponse::ok("The initial user has already been created!")
    } else {
        ApiResponse::ok("The initial user has not been created!")
    };
    let status = if exists {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    };

    Ok((
        status,
        build_version_headers(&state.build_metadata.version),
        Json(body),
    )
        .into_response())
}

pub(crate) async fn post_first_user(
    State(state): State<AppState>,
    payload: Result<Json<CreateFirstUserRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    match state.auth.create_first_user(&request).await {
        Ok(created) => {
            record_audit(
                &state,
                AuditAction::Create,
                ResourceKind::User,
                None,
                Some(created.user_id.to_string()),
                "bootstrapped first user",
            )
            .await;

            Ok((
                StatusCode::CREATED,
                Json(CreateFirstUserResponse {
                    user_id: created.user_id,
                    organization_id: created.organization_id,
                }),
            )
                .into_response())
        }
        Err(error) => handle_auth_error(error),
    }
}

pub(crate) async fn login_with_password(
    State(state): State<AppState>,
    payload: Result<Json<LoginWithPasswordRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let outcome = match state.auth.login_with_password(&request).await {
        Ok(outcome) => outcome,
        Err(error) => return handle_auth_error(error),
    };
    record_audit(
        &state,
        AuditAction::Login,
        ResourceKind::Authentication,
        Some(&outcome.user),
        Some(outcome.user.id.to_string()),
        "authenticated with password",
    )
    .await;

    Ok((StatusCode::CREATED, Json(outcome.response)).into_response())
}

pub(crate) async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    state.auth.logout(&context.session_token).await?;
    record_audit(
        &state,
        AuditAction::Logout,
        ResourceKind::Authentication,
        Some(&context.user),
        Some(context.user.id.to_string()),
        "logged out",
    )
    .await;

    Ok((StatusCode::OK, Json(ApiResponse::ok("Logged out!"))).into_response())
}

pub(crate) async fn post_validate_user_password(
    State(state): State<AppState>,
    payload: Result<Json<ValidateUserPasswordRequest>, JsonRejection>,
) -> Response {
    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return invalid_json_response(error),
    };

    (
        StatusCode::OK,
        Json(state.auth.validate_user_password(&request)),
    )
        .into_response()
}

pub(crate) async fn post_request_one_time_passcode(
    State(state): State<AppState>,
    payload: Result<Json<RequestOneTimePasscodeRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    if let Err(error) = state.auth.request_one_time_passcode(&request).await {
        return handle_auth_error(error);
    }

    Ok(StatusCode::NO_CONTENT.into_response())
}

pub(crate) async fn post_change_password_with_one_time_passcode(
    State(state): State<AppState>,
    payload: Result<Json<ChangePasswordWithOneTimePasscodeRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let user_id = match state
        .auth
        .change_password_with_one_time_passcode(&request)
        .await
    {
        Ok(user_id) => user_id,
        Err(error) => return handle_auth_error(error),
    };

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::User,
        None,
        Some(user_id.to_string()),
        "changed password with one-time passcode",
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

pub(crate) async fn get_github_oauth_device_disabled() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ApiResponse::ok("GitHub OAuth2 is not enabled.")),
    )
        .into_response()
}

pub(crate) async fn get_github_oauth_callback_disabled() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ApiResponse::ok("GitHub OAuth2 is not enabled.")),
    )
        .into_response()
}

pub(crate) async fn get_oidc_callback_disabled() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ApiResponse::ok("OIDC is not enabled.")),
    )
        .into_response()
}

pub(crate) async fn get_user_debug_link(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(requested_user): Path<String>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Some(target_user) = resolve_user(&state, &requested_user, &context.user).await? else {
        return Ok(not_found_response("User not found."));
    };
    if context.user.username != target_user.username && !context.actor.is_owner() {
        return Ok(forbidden_response(
            "You are not authorized to inspect this user.",
        ));
    }
    if target_user.login_type != LoginType::Oidc {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::ok("User is not an OIDC user.")),
        )
            .into_response());
    }

    let links = state.store.list_user_links(target_user.id).await?;
    let claims = links
        .into_iter()
        .find(|l| l.login_type == LoginType::Oidc)
        .map(|l| l.claims)
        .unwrap_or_default();

    Ok((StatusCode::OK, Json(claims)).into_response())
}

pub(crate) async fn post_convert_login(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<ConvertLoginRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    let message = match state
        .auth
        .convert_login(&context.user, &user, &request)
        .await
    {
        Ok(message) => message,
        Err(error) => return handle_auth_error(error),
    };
    Ok((StatusCode::BAD_REQUEST, Json(ApiResponse::ok(message))).into_response())
}

pub(crate) async fn create_session_api_key(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can create API keys for this user.
    let Some(target_user) = resolve_user(&state, &user, &context.user).await? else {
        return Ok(not_found_response("User not found."));
    };
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Create,
            &Object::new(ResourceType::ApiKey).with_owner(target_user.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to create API keys for this user.",
        ));
    }

    let result = match state
        .auth
        .create_session_api_key(&context.actor, &context.user, &user)
        .await
    {
        Ok(result) => result,
        Err(error) => return handle_auth_error(error),
    };

    record_audit(
        &state,
        AuditAction::Create,
        ResourceKind::ApiKey,
        Some(&context.user),
        Some(result.key_id),
        "created session API key",
    )
    .await;

    Ok((StatusCode::CREATED, Json(result.response)).into_response())
}

pub(crate) async fn create_token_api_key(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<CreateTokenRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can create token API keys for this user.
    let Some(target_user) = resolve_user(&state, &user, &context.user).await? else {
        return Ok(not_found_response("User not found."));
    };
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Create,
            &Object::new(ResourceType::ApiKey).with_owner(target_user.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to create token API keys for this user.",
        ));
    }

    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    let result = match state
        .auth
        .create_token_api_key(&context.actor, &context.user, &user, request)
        .await
    {
        Ok(result) => result,
        Err(error) => return handle_auth_error(error),
    };

    record_audit(
        &state,
        AuditAction::Create,
        ResourceKind::ApiKey,
        Some(&context.user),
        Some(result.key_id),
        "created token API key",
    )
    .await;

    Ok((StatusCode::CREATED, Json(result.response)).into_response())
}

pub(crate) async fn list_token_api_keys(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
    Query(query): Query<TokenListQuery>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let keys = match state
        .auth
        .list_token_api_keys(
            &context.actor,
            &context.user,
            &user,
            query.include_all,
            query.include_expired,
        )
        .await
    {
        Ok(keys) => keys,
        Err(error) => return handle_auth_error(error),
    };

    Ok((StatusCode::OK, Json(keys)).into_response())
}

pub(crate) async fn get_api_key(
    State(state): State<AppState>,
    Path((user, keyid)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let key = match state
        .auth
        .get_api_key(&context.actor, &context.user, &user, &keyid)
        .await
    {
        Ok(key) => key,
        Err(error) => return handle_auth_error(error),
    };

    Ok((StatusCode::OK, Json(key)).into_response())
}

pub(crate) async fn get_api_key_by_name(
    State(state): State<AppState>,
    Path((user, keyname)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let key = match state
        .auth
        .get_api_key_by_name(&context.actor, &context.user, &user, &keyname)
        .await
    {
        Ok(key) => key,
        Err(error) => return handle_auth_error(error),
    };

    Ok((StatusCode::OK, Json(key)).into_response())
}

pub(crate) async fn delete_api_key(
    State(state): State<AppState>,
    Path((user, keyid)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can delete API keys for this user.
    let Some(target_user) = resolve_user(&state, &user, &context.user).await? else {
        return Ok(not_found_response("User not found."));
    };
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Delete,
            &Object::new(ResourceType::ApiKey).with_owner(target_user.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to delete API keys for this user.",
        ));
    }

    let key_id = match state
        .auth
        .delete_api_key(&context.actor, &context.user, &user, &keyid)
        .await
    {
        Ok(key_id) => key_id,
        Err(error) => return handle_auth_error(error),
    };

    record_audit(
        &state,
        AuditAction::Delete,
        ResourceKind::ApiKey,
        Some(&context.user),
        Some(key_id),
        "deleted API key",
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

pub(crate) async fn expire_api_key(
    State(state): State<AppState>,
    Path((user, keyid)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can expire API keys for this user.
    let Some(target_user) = resolve_user(&state, &user, &context.user).await? else {
        return Ok(not_found_response("User not found."));
    };
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::ApiKey).with_owner(target_user.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to expire API keys for this user.",
        ));
    }

    let key_id = match state
        .auth
        .expire_api_key(&context.actor, &context.user, &user, &keyid)
        .await
    {
        Ok(key_id) => key_id,
        Err(error) => return handle_auth_error(error),
    };

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::ApiKey,
        Some(&context.user),
        Some(key_id),
        "expired API key",
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

pub(crate) async fn get_token_config(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let config = match state
        .auth
        .get_token_config(&context.actor, &context.user, &user)
        .await
    {
        Ok(config) => config,
        Err(error) => return handle_auth_error(error),
    };
    Ok((StatusCode::OK, Json(config)).into_response())
}

pub(crate) async fn post_authcheck(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<AuthorizationRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    // Limit the number of resource_id lookups to prevent abuse.
    let max_id_fetch = 10;
    let id_fetch_count = request
        .checks
        .values()
        .filter(|c| !c.object.resource_id.is_empty())
        .count();
    if id_fetch_count > max_id_fetch {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                format!(
                    "Endpoint only supports using \"resource_id\" field {max_id_fetch} times, found {id_fetch_count} usages. Remove {} objects with this field set.",
                    id_fetch_count - max_id_fetch,
                ),
                "Too many resource_id lookups.",
            )),
        )
            .into_response());
    }

    let authorizer = Authorizer::new();
    let mut response = HashMap::new();

    for (key, check) in &request.checks {
        if check.object.resource_type.is_empty() {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error(
                    format!("Object's \"resource_type\" field must be defined for key \"{key}\"."),
                    "Missing resource_type.",
                )),
            )
                .into_response());
        }

        let resource_type = match ResourceType::from_str_opt(&check.object.resource_type) {
            Some(rt) => rt,
            None => {
                response.insert(key.clone(), false);
                continue;
            }
        };

        let action = match serde_json::from_value::<Action>(Value::String(check.action.clone())) {
            Ok(a) => a,
            Err(_) => {
                response.insert(key.clone(), false);
                continue;
            }
        };

        let mut obj = Object::new(resource_type);

        // Parse owner_id.
        if !check.object.owner_id.is_empty() {
            let owner_str = if check.object.owner_id == "me" {
                context.actor.user_id.to_string()
            } else {
                check.object.owner_id.clone()
            };
            if let Ok(owner_id) = Uuid::parse_str(&owner_str) {
                obj = obj.with_owner(owner_id);
            }
        }

        // Parse organization_id.
        if !check.object.organization_id.is_empty() {
            if let Ok(org_id) = Uuid::parse_str(&check.object.organization_id) {
                obj = obj.in_org(org_id);
            }
        } else if check.object.any_org {
            obj = obj.any_organization();
        }

        // Parse resource_id.
        if !check.object.resource_id.is_empty() {
            if let Ok(res_id) = Uuid::parse_str(&check.object.resource_id) {
                obj = obj.with_id(res_id);
            } else {
                return Ok((
                    StatusCode::BAD_REQUEST,
                    Json(ApiResponse::error(
                        format!("Object \"{key}\" resource_id is not a valid uuid.",),
                        "Invalid resource_id.",
                    )),
                )
                    .into_response());
            }
        }

        let result = authorizer.authorize(&context.actor, action, &obj).is_ok();
        response.insert(key.clone(), result);
    }

    Ok((StatusCode::OK, Json(response)).into_response())
}
