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
        Json(ApiResponse::error(
            "GitHub OAuth2 is not enabled.",
            "This deployment does not have GitHub OAuth2 configured.",
        )),
    )
        .into_response()
}

pub(crate) async fn get_github_oauth_callback_disabled() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ApiResponse::error(
            "GitHub OAuth2 is not enabled.",
            "This deployment does not have GitHub OAuth2 configured.",
        )),
    )
        .into_response()
}

pub(crate) async fn get_oidc_callback_disabled() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ApiResponse::error(
            "OIDC is not enabled.",
            "This deployment does not have OIDC configured.",
        )),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Real OAuth2/OIDC handler implementations
// ---------------------------------------------------------------------------

/// `POST /api/v2/users/oauth2/github/device`
///
/// Initiates the GitHub OAuth2 device authorization flow for CLI clients.
/// Returns a device code and verification URL that the user can use to
/// authorize the application in their browser.
#[tracing::instrument(skip_all)]
pub(crate) async fn post_github_oauth_device(
    State(state): State<AppState>,
) -> Result<Response, AppError> {
    let Some(ref github_config) = state.config.github_oauth else {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "GitHub OAuth2 is not enabled.",
                "This deployment does not have GitHub OAuth2 configured.",
            )),
        )
            .into_response());
    };

    let client = reqwest::Client::new();
    let device_response =
        coder_auth::oauth_login::github_request_device_code(&client, github_config)
            .await
            .map_err(|e| {
                tracing::error!("GitHub device code request failed: {e}");
                AppError::from(StorageError::unavailable(e.to_string()))
            })?;

    Ok((StatusCode::OK, Json(device_response)).into_response())
}

/// `GET /api/v2/users/oauth2/github/callback`
///
/// Handles the OAuth2 authorization code callback from GitHub.
/// Exchanges the code for an access token, fetches the user profile and
/// verified emails, finds or creates the user, creates a session, and
/// redirects to the application.
#[tracing::instrument(skip_all)]
pub(crate) async fn get_github_oauth_callback(
    State(state): State<AppState>,
    Query(query): Query<coder_auth::oauth_login::OAuthCallbackQuery>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
) -> Result<Response, AppError> {
    let Some(ref github_config) = state.config.github_oauth else {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "GitHub OAuth2 is not enabled.",
                "This deployment does not have GitHub OAuth2 configured.",
            )),
        )
            .into_response());
    };

    // Check for upstream errors from the provider.
    if let Some(ref err_msg) = query.error {
        let detail = query
            .error_description
            .as_deref()
            .unwrap_or("Unknown error from GitHub");
        tracing::warn!("GitHub OAuth error: {err_msg} — {detail}");
        return Ok(redirect_to_login_response(
            &uri,
            &format!("GitHub OAuth error: {detail}"),
        ));
    }

    // Validate the state parameter against the stored cookie.
    let stored_state = cookie_from_headers(&headers, OAUTH2_STATE_COOKIE);
    match stored_state {
        Some(ref s) if s == &query.state => {}
        _ => {
            tracing::warn!("OAuth state mismatch");
            return Ok(redirect_to_login_response(
                &uri,
                "OAuth state mismatch. Please try again.",
            ));
        }
    }

    let redirect_uri =
        cookie_from_headers(&headers, OAUTH2_REDIRECT_COOKIE).unwrap_or_else(|| "/".to_owned());

    // Exchange the authorization code for an access token.
    let client = reqwest::Client::new();
    let token_response =
        coder_auth::oauth_login::github_exchange_code(&client, github_config, &query.code)
            .await
            .map_err(|e| {
                tracing::error!("GitHub code exchange failed: {e}");
                AppError::from(StorageError::unavailable(e.to_string()))
            })?;

    let access_token = &token_response.access_token;

    // Fetch user profile and emails concurrently.
    let (gh_user, gh_emails) = tokio::try_join!(
        coder_auth::oauth_login::github_fetch_user(&client, &github_config.api_url, access_token),
        coder_auth::oauth_login::github_fetch_emails(&client, &github_config.api_url, access_token),
    )
    .map_err(|e| {
        tracing::error!("GitHub API fetch failed: {e}");
        AppError::from(StorageError::unavailable(e.to_string()))
    })?;

    // Check organization/team membership if restrictions are configured.
    if !github_config.allow_everyone
        && (!github_config.allowed_orgs.is_empty() || !github_config.allowed_teams.is_empty())
    {
        let (orgs, teams) = tokio::try_join!(
            coder_auth::oauth_login::github_fetch_orgs(
                &client,
                &github_config.api_url,
                access_token
            ),
            coder_auth::oauth_login::github_fetch_teams(
                &client,
                &github_config.api_url,
                access_token
            ),
        )
        .map_err(|e| {
            tracing::error!("GitHub org/team fetch failed: {e}");
            AppError::from(StorageError::unavailable(e.to_string()))
        })?;

        if !coder_auth::oauth_login::github_check_org_membership(github_config, &orgs) {
            return Ok(redirect_to_login_response(
                &uri,
                "Your GitHub account is not a member of an allowed organization.",
            ));
        }
        if !coder_auth::oauth_login::github_check_team_membership(github_config, &teams) {
            return Ok(redirect_to_login_response(
                &uri,
                "Your GitHub account is not a member of an allowed team.",
            ));
        }
    }

    // Find the primary verified email.
    let primary_email =
        coder_auth::oauth_login::github_primary_email(&gh_emails).ok_or_else(|| {
            tracing::warn!("No verified email found for GitHub user {}", gh_user.login);
            AppError::from(StorageError::unavailable(
                "No verified email found on your GitHub account.",
            ))
        })?;

    let linked_id = coder_auth::oauth_login::github_linked_id(gh_user.id);

    // Look up user by GitHub linked ID or by email.
    let existing_user = find_user_by_linked_id_or_email(
        &state,
        LoginType::Github,
        &linked_id,
        &primary_email.email,
    )
    .await?;

    let user = match existing_user {
        Some(user) => {
            // Existing user found — update the user link.
            let link_input = coder_core::UpsertUserLinkInput {
                login_type: LoginType::Github,
                linked_id: linked_id.clone(),
                oauth_access_token: access_token.clone(),
                oauth_refresh_token: String::new(),
                oauth_expiry: OffsetDateTime::now_utc(),
                claims: coder_core::UserLinkClaims::default(),
            };
            state
                .store
                .upsert_user_link(user.id, &link_input)
                .await
                .map_err(AppError::from)?;
            user
        }
        None => {
            // No user found — create new if signups are allowed.
            if !github_config.allow_signups {
                return Ok(redirect_to_login_response(
                    &uri,
                    "Signups are disabled for GitHub OAuth.",
                ));
            }
            create_oauth_user_and_link(
                &state,
                &primary_email.email,
                &gh_user.login,
                &gh_user.name.clone().unwrap_or_default(),
                &gh_user.avatar_url,
                LoginType::Github,
                &linked_id,
                access_token,
            )
            .await?
        }
    };

    // Create session and redirect.
    let session_token = state
        .auth
        .create_oauth_session(&user)
        .await
        .map_err(|e| AppError::from(StorageError::unavailable(e.to_string())))?;

    record_audit(
        &state,
        AuditAction::Login,
        ResourceKind::Authentication,
        None,
        Some(user.id.to_string()),
        "authenticated via GitHub OAuth",
    )
    .await;

    Ok(build_oauth_redirect_response(
        &session_token,
        &sanitize_redirect_uri(&redirect_uri),
    ))
}

/// `GET /api/v2/users/oidc/callback`
///
/// Handles the OIDC authorization code callback. Exchanges the code for
/// tokens, validates the ID token, extracts user claims, finds or creates
/// the user, creates a session, and redirects to the application.
#[tracing::instrument(skip_all)]
pub(crate) async fn get_oidc_callback(
    State(state): State<AppState>,
    Query(query): Query<coder_auth::oauth_login::OAuthCallbackQuery>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
) -> Result<Response, AppError> {
    let Some(ref oidc_config) = state.config.oidc else {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "OIDC is not enabled.",
                "This deployment does not have OIDC configured.",
            )),
        )
            .into_response());
    };

    // Check for upstream errors from the provider.
    if let Some(ref err_msg) = query.error {
        let detail = query
            .error_description
            .as_deref()
            .unwrap_or("Unknown error from OIDC provider");
        tracing::warn!("OIDC error: {err_msg} — {detail}");
        return Ok(redirect_to_login_response(
            &uri,
            &format!("OIDC error: {detail}"),
        ));
    }

    // Validate the state parameter.
    let stored_state = cookie_from_headers(&headers, OAUTH2_STATE_COOKIE);
    match stored_state {
        Some(ref s) if s == &query.state => {}
        _ => {
            tracing::warn!("OIDC state mismatch");
            return Ok(redirect_to_login_response(
                &uri,
                "OAuth state mismatch. Please try again.",
            ));
        }
    }

    let redirect_uri =
        cookie_from_headers(&headers, OAUTH2_REDIRECT_COOKIE).unwrap_or_else(|| "/".to_owned());

    // Discover the OIDC endpoints.
    let client = reqwest::Client::new();
    let discovery = coder_auth::oauth_login::oidc_discover(&client, &oidc_config.issuer_url)
        .await
        .map_err(|e| {
            tracing::error!("OIDC discovery failed: {e}");
            AppError::from(StorageError::unavailable(e.to_string()))
        })?;

    // Build the callback redirect URI for the token exchange.
    let callback_redirect = format!(
        "{}/api/v2/users/oidc/callback",
        state.config.access_url.as_str().trim_end_matches('/')
    );

    // Exchange the authorization code for tokens.
    let token_response = coder_auth::oauth_login::oidc_exchange_code(
        &client,
        oidc_config,
        &discovery.token_endpoint,
        &query.code,
        &callback_redirect,
    )
    .await
    .map_err(|e| {
        tracing::error!("OIDC code exchange failed: {e}");
        AppError::from(StorageError::unavailable(e.to_string()))
    })?;

    // Decode and validate the ID token claims.
    let claims = coder_auth::oauth_login::decode_id_token_claims(&token_response.id_token)
        .map_err(|e| {
            tracing::error!("OIDC ID token decode failed: {e}");
            AppError::from(StorageError::unavailable(e.to_string()))
        })?;

    coder_auth::oauth_login::validate_oidc_claims(&claims, oidc_config).map_err(|e| {
        tracing::error!("OIDC claims validation failed: {e}");
        AppError::from(StorageError::unavailable(e.to_string()))
    })?;

    // Extract the email from the claims.
    let email = coder_auth::oauth_login::extract_claim(&claims, &oidc_config.email_field)
        .ok_or_else(|| {
            tracing::warn!("No email claim found in OIDC token");
            AppError::from(StorageError::unavailable("No email found in OIDC claims."))
        })?;

    // Check email verification if required.
    if !oidc_config.ignore_email_verified {
        if let Some(false) = claims.email_verified {
            return Ok(redirect_to_login_response(
                &uri,
                "Your email address has not been verified by the OIDC provider.",
            ));
        }
    }

    // Check email domain restrictions.
    if !coder_auth::oauth_login::oidc_check_email_domain(oidc_config, &email) {
        return Ok(redirect_to_login_response(
            &uri,
            "Your email domain is not allowed.",
        ));
    }

    let linked_id = coder_auth::oauth_login::oidc_linked_id(&claims.sub);
    let username = coder_auth::oauth_login::oidc_derive_username(&claims, oidc_config);
    let name = coder_auth::oauth_login::extract_claim(&claims, &oidc_config.name_field)
        .unwrap_or_default();

    // Look up user by OIDC linked ID or by email.
    let existing_user =
        find_user_by_linked_id_or_email(&state, LoginType::Oidc, &linked_id, &email).await?;

    let user_link_claims = coder_auth::oauth_login::build_user_link_claims(&claims);

    let user = match existing_user {
        Some(user) => {
            // Update the user link with fresh claims.
            let link_input = coder_core::UpsertUserLinkInput {
                login_type: LoginType::Oidc,
                linked_id: linked_id.clone(),
                oauth_access_token: token_response.access_token.clone(),
                oauth_refresh_token: token_response.refresh_token.clone().unwrap_or_default(),
                oauth_expiry: token_response
                    .expires_in
                    .map(|secs| {
                        time::OffsetDateTime::now_utc()
                            + time::Duration::seconds(i64::try_from(secs).unwrap_or(3600))
                    })
                    .unwrap_or_else(time::OffsetDateTime::now_utc),
                claims: user_link_claims,
            };
            state
                .store
                .upsert_user_link(user.id, &link_input)
                .await
                .map_err(AppError::from)?;
            user
        }
        None => {
            // No user found — create if signups allowed.
            if !oidc_config.allow_signups {
                return Ok(redirect_to_login_response(
                    &uri,
                    "Signups are disabled for OIDC.",
                ));
            }
            create_oauth_user_and_link(
                &state,
                &email,
                &username,
                &name,
                "",
                LoginType::Oidc,
                &linked_id,
                &token_response.access_token,
            )
            .await?
        }
    };

    // Create session and redirect.
    let session_token = state
        .auth
        .create_oauth_session(&user)
        .await
        .map_err(|e| AppError::from(StorageError::unavailable(e.to_string())))?;

    record_audit(
        &state,
        AuditAction::Login,
        ResourceKind::Authentication,
        None,
        Some(user.id.to_string()),
        "authenticated via OIDC",
    )
    .await;

    Ok(build_oauth_redirect_response(
        &session_token,
        &sanitize_redirect_uri(&redirect_uri),
    ))
}

// ---------------------------------------------------------------------------
// Shared OAuth helper functions
// ---------------------------------------------------------------------------

/// Finds an existing user by external linked ID or by email.
async fn find_user_by_linked_id_or_email(
    state: &AppState,
    login_type: LoginType,
    linked_id: &str,
    email: &str,
) -> Result<Option<coder_core::UserRecord>, AppError> {
    // First, try to find via user links across all users.
    // We list all users and check their links. For scalability, a direct
    // query method would be better, but we use the existing store API.
    let (users, _count) = state
        .store
        .list_users(coder_core::UserListFilter::default())
        .await
        .map_err(AppError::from)?;

    for user in &users {
        if user.deleted || user.is_system || user.status != UserStatus::Active {
            continue;
        }
        let links = state
            .store
            .list_user_links(user.id)
            .await
            .map_err(AppError::from)?;
        for link in &links {
            if link.login_type == login_type && link.linked_id == *linked_id {
                return Ok(Some(user.clone()));
            }
        }
    }

    // Fall back to email lookup.
    for user in &users {
        if user.email.eq_ignore_ascii_case(email)
            && !user.deleted
            && !user.is_system
            && user.status == UserStatus::Active
        {
            return Ok(Some(user.clone()));
        }
    }

    Ok(None)
}

/// Creates a new user account and links it to the OAuth/OIDC provider.
#[allow(clippy::too_many_arguments)]
async fn create_oauth_user_and_link(
    state: &AppState,
    email: &str,
    username: &str,
    name: &str,
    avatar_url: &str,
    login_type: LoginType,
    linked_id: &str,
    access_token: &str,
) -> Result<coder_core::UserRecord, AppError> {
    // Get the default organization to assign the user to.
    let orgs = state
        .store
        .list_organizations(Vec::new())
        .await
        .map_err(AppError::from)?;
    let org_ids: Vec<Uuid> = orgs.iter().take(1).map(|o| o.id).collect();

    let create_input = coder_core::CreateUserInput {
        email: email.to_owned(),
        username: username.to_owned(),
        name: name.to_owned(),
        password_hash: None,
        login_type,
        status: UserStatus::Active,
        organization_ids: org_ids,
    };

    let user = state
        .store
        .create_user(create_input)
        .await
        .map_err(|e| match e {
            coder_core::CreateUserStoreError::AlreadyExists => AppError::from(
                StorageError::unavailable("A user with this email or username already exists."),
            ),
            coder_core::CreateUserStoreError::Storage(se) => AppError::from(se),
        })?;

    // Generate and store a Git SSH key for the user.
    if let Err(e) = store_new_git_ssh_key(state, &user).await {
        tracing::warn!("Failed to create Git SSH key for new OAuth user: {e}");
    }

    // Create the user link.
    let link_input = coder_core::UpsertUserLinkInput {
        login_type,
        linked_id: linked_id.to_owned(),
        oauth_access_token: access_token.to_owned(),
        oauth_refresh_token: String::new(),
        oauth_expiry: OffsetDateTime::now_utc(),
        claims: coder_core::UserLinkClaims::default(),
    };
    state
        .store
        .upsert_user_link(user.id, &link_input)
        .await
        .map_err(AppError::from)?;

    record_audit(
        state,
        AuditAction::Create,
        ResourceKind::User,
        None,
        Some(user.id.to_string()),
        "created user via OAuth",
    )
    .await;

    Ok(user)
}

/// Builds an HTTP 303 redirect response with the session token cookie set.
fn build_oauth_redirect_response(session_token: &str, redirect_path: &str) -> Response {
    let cookie_value = format!(
        "{}={session_token}; Path=/; HttpOnly; SameSite=Lax",
        coder_auth::SESSION_TOKEN_COOKIE
    );
    // Clear the OAuth state and redirect cookies.
    let clear_state = format!("{}=; Path=/; Max-Age=0", OAUTH2_STATE_COOKIE);
    let clear_redirect = format!("{}=; Path=/; Max-Age=0", OAUTH2_REDIRECT_COOKIE);

    let mut response = StatusCode::SEE_OTHER.into_response();
    if let Ok(loc) = HeaderValue::from_str(redirect_path) {
        response.headers_mut().insert(LOCATION, loc);
    }
    if let Ok(v) = HeaderValue::from_str(&cookie_value) {
        response
            .headers_mut()
            .append(HeaderName::from_static("set-cookie"), v);
    }
    if let Ok(v) = HeaderValue::from_str(&clear_state) {
        response
            .headers_mut()
            .append(HeaderName::from_static("set-cookie"), v);
    }
    if let Ok(v) = HeaderValue::from_str(&clear_redirect) {
        response
            .headers_mut()
            .append(HeaderName::from_static("set-cookie"), v);
    }
    response
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
