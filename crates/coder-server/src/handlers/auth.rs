//! Authentication, session management, and API key handlers.

use super::*;

#[derive(Debug, Default, Deserialize)]
pub(crate) struct TokenListQuery {
    #[serde(default)]
    include_all: bool,
    #[serde(default)]
    include_expired: bool,
}

/// GET /api/v2/auth/scopes — list available API key scopes, each with its
/// human-readable description and the set of resources it unlocks.
///
/// The response is driven by `PUBLIC_API_KEY_SCOPE_METADATA`, which is the
/// single source of truth for both the catalog's ordering and the per-scope
/// metadata.
pub(crate) async fn list_api_key_scopes() -> Json<ExternalApiKeyScopes> {
    let external = PUBLIC_API_KEY_SCOPE_METADATA
        .iter()
        .map(|(name, description, resources)| ApiKeyScopeMetadata {
            name: (*name).to_owned(),
            description: (*description).to_owned(),
            resources: resources
                .iter()
                .map(|resource| (*resource).to_owned())
                .collect(),
        })
        .collect();
    Json(ExternalApiKeyScopes { external })
}

/// GET /api/v2/users/authmethods — return the supported authentication methods.
pub(crate) async fn auth_methods() -> Json<AuthMethods> {
    Json(supported_auth_methods())
}

/// GET /api/v2/users/first — check whether the initial admin user has been created.
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

/// POST /api/v2/users/first — create the initial admin user and organization.
///
/// When the request has `trial = true` and the deployment has a trial
/// signup URL configured (`CODER_TRIAL_SIGNUP_URL`), the trial payload is
/// POSTed to that endpoint before user creation. Mirrors Go's
/// `postFirstUser` → `TrialGenerator` behavior.
pub(crate) async fn post_first_user(
    State(state): State<AppState>,
    payload: Result<Json<CreateFirstUserRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    // Trial-signup redirector: forward to the configured endpoint *before*
    // creating the user, so a failed signup surfaces as a 500 with the
    // remote's error message (matching Go's ordering).  When the trial URL
    // is empty, the field is silently ignored.
    if request.trial && !state.config.trial_signup_url.is_empty() {
        if let Err(response) = forward_trial_signup(&state, &request).await {
            return Ok(response);
        }
    }

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

/// POSTs a [`LicensorTrialRequest`] to the configured trial-signup URL.
/// Returns `Err(Response)` with a 500 body on any failure (network, non-2xx
/// response, or body read/parse error) so the caller can short-circuit.
async fn forward_trial_signup(
    state: &AppState,
    request: &CreateFirstUserRequest,
) -> Result<(), Response> {
    let deployment_id = state.deployment_id.to_string();
    let payload = coder_core::LicensorTrialRequest {
        deployment_id,
        email: request.email.clone(),
        source: "first_user".to_owned(),
        first_name: request.trial_info.first_name.clone(),
        last_name: request.trial_info.last_name.clone(),
        phone_number: request.trial_info.phone_number.clone(),
        job_title: request.trial_info.job_title.clone(),
        company_name: request.trial_info.company_name.clone(),
        country: request.trial_info.country.clone(),
        developers: request.trial_info.developers.clone(),
    };

    let resp = match state
        .http_client
        .post(&state.config.trial_signup_url)
        .json(&payload)
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(error) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error(
                    "Failed to generate trial",
                    error.to_string(),
                )),
            )
                .into_response());
        }
    };

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        // The trial licensor typically returns `{"error":"message"}`.
        let detail = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(String::from))
            .unwrap_or(body);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::error("Failed to generate trial", detail)),
        )
            .into_response());
    }
    Ok(())
}

/// POST /api/v2/users/login — authenticate with email and password.
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

/// POST /api/v2/users/logout — invalidate the current session.
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

/// POST /api/v2/users/validate-password — check password strength without creating a user.
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

/// POST /api/v2/users/otp/request — send a one-time passcode for password reset.
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

/// POST /api/v2/users/otp/change-password — reset password using a one-time passcode.
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

/// GET /api/v2/externalauth/github/device — error response when GitHub OAuth is not configured.
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

// NOTE: get_github_oauth_callback_disabled and get_oidc_callback_disabled were
// removed — the router now uses the real handlers which return appropriate
// errors when OAuth/OIDC is not configured.

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

    let device_response =
        coder_auth::oauth_login::github_request_device_code(&state.http_client, github_config)
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
    let token_response = coder_auth::oauth_login::github_exchange_code(
        &state.http_client,
        github_config,
        &query.code,
    )
    .await
    .map_err(|e| {
        tracing::error!("GitHub code exchange failed: {e}");
        AppError::from(StorageError::unavailable(e.to_string()))
    })?;

    let access_token = &token_response.access_token;

    // Fetch user profile and emails concurrently.
    let (gh_user, gh_emails) = tokio::try_join!(
        coder_auth::oauth_login::github_fetch_user(
            &state.http_client,
            &github_config.api_url,
            access_token
        ),
        coder_auth::oauth_login::github_fetch_emails(
            &state.http_client,
            &github_config.api_url,
            access_token
        ),
    )
    .map_err(|e| {
        tracing::error!("GitHub API fetch failed: {e}");
        AppError::from(StorageError::unavailable(e.to_string()))
    })?;

    // Check organization/team membership if restrictions are configured.
    // NOTE: The Go reference (coder/coderd/userauth.go) enforces org AND team
    // checks sequentially — the user must pass the org check first, and then
    // the team check only runs within matched orgs. We replicate that AND
    // behavior here.
    if !github_config.allow_everyone
        && (!github_config.allowed_orgs.is_empty() || !github_config.allowed_teams.is_empty())
    {
        let (orgs, teams) = tokio::try_join!(
            coder_auth::oauth_login::github_fetch_orgs(
                &state.http_client,
                &github_config.api_url,
                access_token
            ),
            coder_auth::oauth_login::github_fetch_teams(
                &state.http_client,
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
    let primary_email = match coder_auth::oauth_login::github_primary_email(&gh_emails) {
        Some(email) => email,
        None => {
            tracing::warn!("No verified email found for GitHub user {}", gh_user.login);
            return Ok(redirect_to_login_response(
                &uri,
                "Your primary email must be verified on GitHub.",
            ));
        }
    };

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

    let is_https = state.config.access_url.scheme() == "https";
    Ok(build_oauth_redirect_response(
        &session_token,
        &sanitize_redirect_uri(&redirect_uri),
        is_https,
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

    // Discover the OIDC endpoints.  Uses a process-wide cache with a 5-minute
    // TTL so we avoid fetching the rarely-changing discovery document on every
    // single login callback.  The cache is keyed on the issuer URL so that a
    // config change does not serve a stale document from a different provider.
    //
    // The mutex is NOT held across the HTTP fetch to avoid serializing all
    // concurrent logins behind a single outbound request.  Instead we use a
    // check-release-fetch-recheck pattern.
    let discovery = {
        use std::sync::OnceLock;
        use tokio::sync::Mutex;

        static CACHE: OnceLock<Mutex<Option<OidcDiscoveryCacheEntry>>> = OnceLock::new();
        const TTL: std::time::Duration = std::time::Duration::from_secs(300);

        let issuer_key = oidc_config.issuer_url.as_str().to_owned();
        let cache = CACHE.get_or_init(|| Mutex::new(None));

        // First check: read the cache while holding the lock briefly.
        let cached_hit = {
            let guard = cache.lock().await;
            if let Some(ref cached) = *guard {
                let now = std::time::Instant::now();
                if cached.issuer_url == issuer_key && now.duration_since(cached.fetched_at) < TTL {
                    Some(cached.doc.clone())
                } else {
                    None
                }
            } else {
                None
            }
        }; // lock released here

        if let Some(doc) = cached_hit {
            doc
        } else {
            // Fetch without holding the lock so concurrent requests are not blocked.
            let doc =
                coder_auth::oauth_login::oidc_discover(&state.http_client, &oidc_config.issuer_url)
                    .await
                    .map_err(|e| {
                        tracing::error!("OIDC discovery failed: {e}");
                        AppError::from(StorageError::unavailable(e.to_string()))
                    })?;

            // Re-acquire the lock and store the fresh document.
            let mut guard = cache.lock().await;
            *guard = Some(OidcDiscoveryCacheEntry {
                doc: doc.clone(),
                fetched_at: std::time::Instant::now(),
                issuer_url: issuer_key,
            });
            doc
        }
    };

    // Build the callback redirect URI for the token exchange.
    let callback_redirect = format!(
        "{}/api/v2/users/oidc/callback",
        state.config.access_url.as_str().trim_end_matches('/')
    );

    // Exchange the authorization code for tokens.
    let token_response = coder_auth::oauth_login::oidc_exchange_code(
        &state.http_client,
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

    // Fetch the JWKS for cryptographic verification of the ID token.
    let jwks = coder_auth::oauth_login::fetch_jwks(&state.http_client, &discovery.jwks_uri)
        .await
        .map_err(|e| {
            tracing::error!("JWKS fetch failed: {e}");
            AppError::from(StorageError::unavailable(e.to_string()))
        })?;

    // Decode AND cryptographically verify the ID token claims using the
    // provider's JWKS.  This replaces the previous insecure base64-only
    // decode and also validates issuer, audience, and expiry.
    let claims = coder_auth::oauth_login::decode_id_token_claims(
        &token_response.id_token,
        &jwks,
        oidc_config,
    )
    .map_err(|e| {
        tracing::error!("OIDC ID token verification failed: {e}");
        AppError::from(StorageError::unavailable(e.to_string()))
    })?;

    // Extract the email from the claims.
    let email = coder_auth::oauth_login::extract_claim(&claims, &oidc_config.email_field)
        .ok_or_else(|| {
            tracing::warn!("No email claim found in OIDC token");
            AppError::from(StorageError::unavailable("No email found in OIDC claims."))
        })?;

    // Check email verification if required.
    // When ignore_email_verified is false, only Some(true) passes.
    // None (missing claim) and Some(false) are both treated as unverified.
    if !oidc_config.ignore_email_verified {
        match claims.email_verified {
            Some(true) => {} // verified, OK
            _ => {
                return Ok(redirect_to_login_response(
                    &uri,
                    "Your email address has not been verified by the OIDC provider.",
                ));
            }
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
                        OffsetDateTime::now_utc()
                            + time::Duration::seconds(i64::try_from(secs).unwrap_or(3600))
                    })
                    .unwrap_or_else(OffsetDateTime::now_utc),
                claims: user_link_claims.clone(),
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

    // IDP sync (best-effort). Runs between the user upsert and the
    // session issue so the freshly-logged-in user already sees the
    // right memberships/roles on the first request. Errors are logged
    // and swallowed — login must succeed even when sync breaks.
    //
    // Ports Go's `AGPLIDPSync.{SyncOrganizations,SyncRoles,SyncGroups}`
    // invocations from `coderd/userauth.go`. See §B.12.1 / Wave 0 S5.
    //
    // Order matters: organization membership must exist before role /
    // group sync, because both scope their work to the orgs the user
    // is a member of.
    let merged_claims = serde_json::Value::Object(user_link_claims.merged_claims.clone());

    // 1. Organization sync.
    match state.store.get_organization_idp_sync_settings().await {
        Ok(org_settings) => {
            let raw_orgs =
                coder_auth::idpsync::claims::parse_org_claims(&org_settings.field, &merged_claims);
            if let Err(err) = coder_auth::idpsync::organization::sync_organizations(
                &state.store,
                user.id,
                &raw_orgs,
                &org_settings,
                None,
            )
            .await
            {
                tracing::warn!(
                    user_id = %user.id,
                    error = %err,
                    "IDP organization sync failed",
                );
            }
        }
        Err(err) => {
            tracing::warn!(
                user_id = %user.id,
                error = %err,
                "failed to load IDP organization sync settings",
            );
        }
    }

    // 2. Role sync. Site-role sync is AGPL-disabled in Go
    //    (`SiteRoleSyncEnabled` returns false); we mirror that by
    //    passing `sync_site_wide = false` and an empty claim set until
    //    enterprise role sync lands. Per-org role sync is driven by
    //    each org's own `RoleSyncSettings`.
    if let Err(err) =
        coder_auth::idpsync::role::sync_roles(&state.store, user.id, &merged_claims, &[], false)
            .await
    {
        tracing::warn!(
            user_id = %user.id,
            error = %err,
            "IDP role sync failed",
        );
    }

    // 3. Group sync.
    let raw_groups = coder_auth::idpsync::claims::parse_group_claims(oidc_config, &merged_claims);
    if !raw_groups.is_empty() || !oidc_config.groups_field.is_empty() {
        match state.store.list_user_memberships(user.id).await {
            Ok(memberships) => {
                for membership in memberships {
                    let settings = match state
                        .store
                        .group_sync_settings(membership.organization_id)
                        .await
                    {
                        Ok(s) => s,
                        Err(err) => {
                            tracing::warn!(
                                user_id = %user.id,
                                organization_id = %membership.organization_id,
                                error = %err,
                                "failed to load IDP group sync settings",
                            );
                            continue;
                        }
                    };
                    if let Err(err) = coder_auth::idpsync::group_sync::sync_groups(
                        &state.store,
                        user.id,
                        membership.organization_id,
                        &raw_groups,
                        &settings,
                    )
                    .await
                    {
                        tracing::warn!(
                            user_id = %user.id,
                            organization_id = %membership.organization_id,
                            error = %err,
                            "IDP group sync failed",
                        );
                    }
                }
            }
            Err(err) => {
                tracing::warn!(
                    user_id = %user.id,
                    error = %err,
                    "failed to enumerate user memberships for IDP group sync",
                );
            }
        }
    }

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

    let is_https = state.config.access_url.scheme() == "https";
    Ok(build_oauth_redirect_response(
        &session_token,
        &sanitize_redirect_uri(&redirect_uri),
        is_https,
    ))
}

/// Cache entry for the OIDC discovery document, keyed on issuer URL.
struct OidcDiscoveryCacheEntry {
    doc: coder_auth::oauth_login::OidcDiscovery,
    fetched_at: std::time::Instant,
    issuer_url: String,
}

// ---------------------------------------------------------------------------
// Shared OAuth helper functions
// ---------------------------------------------------------------------------

/// Finds an existing user by external linked ID or by email.
///
/// Uses targeted store queries instead of scanning all users (O(1) vs O(n×m)).
async fn find_user_by_linked_id_or_email(
    state: &AppState,
    login_type: LoginType,
    linked_id: &str,
    email: &str,
) -> Result<Option<coder_core::UserRecord>, AppError> {
    // First, try to find via the linked ID (most specific match).
    if let Some(user) = state
        .store
        .find_user_by_linked_id(login_type, linked_id)
        .await
        .map_err(AppError::from)?
    {
        if !user.deleted && !user.is_system && user.status == UserStatus::Active {
            return Ok(Some(user));
        }
        // If the user was deleted/inactive, fall through to email lookup.
    }

    // Fall back to email lookup — only match users with the SAME login_type
    // to prevent account takeover (e.g. OAuth user matching a password user
    // by email).
    if let Some(user) = state
        .store
        .find_active_user_by_email_and_login_type(email, login_type)
        .await
        .map_err(AppError::from)?
    {
        return Ok(Some(user));
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
    _avatar_url: &str,
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
    // Prefer the default organization; fall back to the first one if no default is set.
    let org_ids: Vec<Uuid> = orgs
        .iter()
        .find(|o| o.is_default)
        .or_else(|| orgs.first())
        .into_iter()
        .map(|o| o.id)
        .collect();

    let create_input = coder_core::CreateUserInput {
        email: email.to_owned(),
        username: username.to_owned(),
        name: name.to_owned(),
        password_hash: None,
        login_type,
        status: UserStatus::Active,
        organization_ids: org_ids,
    };

    let user = match state.store.create_user(create_input).await {
        Ok(user) => user,
        Err(coder_core::CreateUserStoreError::AlreadyExists) => {
            // Race condition: another concurrent OAuth callback created the same
            // user between our lookup and this create call. Retry the lookup
            // instead of returning a 503.
            tracing::info!(
                "User already exists (likely concurrent OAuth callback), retrying lookup"
            );
            match find_user_by_linked_id_or_email(state, login_type, linked_id, email).await? {
                Some(user) => return Ok(user),
                None => {
                    return Err(AppError::from(StorageError::unavailable(
                        "A user with this email or username already exists.",
                    )));
                }
            }
        }
        Err(coder_core::CreateUserStoreError::Storage(se)) => {
            return Err(AppError::from(se));
        }
    };

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

/// Build an HTTP 303 redirect response that sets the session cookie after OAuth login.
fn build_oauth_redirect_response(
    session_token: &str,
    redirect_path: &str,
    is_https: bool,
) -> Response {
    let secure_flag = if is_https { "; Secure" } else { "" };
    let cookie_value = format!(
        "{}={session_token}; Path=/; HttpOnly; SameSite=Lax{secure_flag}",
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

/// GET /api/v2/debug/{user}/debug-link — return the external auth link for a user (debug only).
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

/// POST /api/v2/users/me/convert-login — convert a user's login method (e.g. password to OIDC).
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

/// Create a session-scoped API key for the authenticated user.
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

/// POST /api/v2/users/:user/keys/tokens — create a long-lived token API key.
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

/// GET /api/v2/users/:user/keys/tokens — list token API keys for a user.
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

/// GET /api/v2/users/:user/keys/:key — return a single API key by ID.
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

/// GET /api/v2/users/:user/keys/tokens/:name — return a token API key by name.
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

/// DELETE /api/v2/users/:user/keys/:key — permanently delete an API key.
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

/// PUT /api/v2/users/:user/keys/:key/expire — mark an API key as expired.
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

/// GET /api/v2/users/:user/keys/tokens/tokenconfig — return token creation configuration.
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

/// POST /api/v2/authcheck — verify whether the caller is authorized for a given RBAC action.
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::collections::BTreeSet;

    #[tokio::test]
    async fn list_api_key_scopes_enriches_every_public_scope() {
        let Json(body) = list_api_key_scopes().await;

        assert_eq!(
            body.external.len(),
            PUBLIC_API_KEY_SCOPE_METADATA.len(),
            "every catalog entry must appear in the response",
        );

        for (index, (name, _, _)) in PUBLIC_API_KEY_SCOPE_METADATA.iter().enumerate() {
            let entry = &body.external[index];
            assert_eq!(
                entry.name, *name,
                "order must match PUBLIC_API_KEY_SCOPE_METADATA",
            );
            assert!(
                !entry.description.trim().is_empty(),
                "scope {name} must have a non-empty description",
            );
            assert!(
                !entry.resources.is_empty(),
                "scope {name} must unlock at least one resource",
            );
            for resource in &entry.resources {
                assert!(
                    !resource.trim().is_empty(),
                    "scope {name} has an empty resource entry",
                );
            }
        }
    }

    #[tokio::test]
    async fn list_api_key_scopes_uses_snake_case_json_field_names() {
        let Json(body) = list_api_key_scopes().await;
        let value = serde_json::to_value(&body).expect("serialize response");

        let external = value
            .get("external")
            .and_then(Value::as_array)
            .expect("response must have an `external` array");

        let Some(first) = external.first() else {
            panic!("response must contain at least one scope");
        };

        let first_obj = first.as_object().expect("scope entries are JSON objects");
        assert!(
            first_obj.contains_key("name"),
            "scope entries must have a snake_case `name` field",
        );
        assert!(
            first_obj.contains_key("description"),
            "scope entries must have a snake_case `description` field",
        );
        assert!(
            first_obj.contains_key("resources"),
            "scope entries must have a snake_case `resources` field",
        );
        // Guard against camelCase regressions.
        assert!(!first_obj.contains_key("resourceList"));
        assert!(!first_obj.contains_key("resourcesList"));
    }

    #[test]
    fn public_api_key_scope_metadata_entries_are_well_formed() {
        // `PUBLIC_API_KEY_SCOPE_METADATA` is the sole catalog of public API
        // key scopes. Every entry must carry a non-empty description and at
        // least one non-empty resource name, and scope names must be unique.
        assert!(
            !PUBLIC_API_KEY_SCOPE_METADATA.is_empty(),
            "the public scope catalog must not be empty",
        );
        let mut seen = BTreeSet::new();
        for (name, description, resources) in PUBLIC_API_KEY_SCOPE_METADATA {
            assert!(!name.trim().is_empty(), "scope names must be non-empty",);
            assert!(
                seen.insert(*name),
                "scope {name} appears more than once in the catalog",
            );
            assert!(
                !description.trim().is_empty(),
                "scope {name} has an empty description in the catalog",
            );
            assert!(
                !resources.is_empty(),
                "scope {name} has no resources in the catalog",
            );
            for resource in *resources {
                assert!(
                    !resource.trim().is_empty(),
                    "scope {name} has an empty resource entry in the catalog",
                );
            }
        }
    }
}
