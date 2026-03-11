//! OAuth2 provider app CRUD, authorize, and token handlers.

use super::*;

pub(crate) async fn list_oauth2_provider_apps(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can read OAuth2 provider apps.
    // The member site role grants Oauth2App::Read, so all authenticated users
    // with the default member role retain access (backward compatible).
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::Oauth2App),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to list OAuth2 provider apps.",
        ));
    }

    let apps = match state.oauth2_provider.list_apps().await {
        Ok(apps) => apps,
        Err(error) => return handle_oauth2_provider_error(error),
    };
    let response: Vec<OAuth2ProviderAppResponse> =
        apps.into_iter().map(oauth2_app_response).collect();
    Ok((StatusCode::OK, Json(response)).into_response())
}

pub(crate) async fn post_oauth2_provider_app(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<PostOAuth2ProviderAppRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can create OAuth2 provider apps.
    // This intentionally replaces the prior is_owner() gate to support future
    // custom roles that may grant OAuth2 app management without full ownership.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Create,
            &Object::new(ResourceType::Oauth2App),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to create OAuth2 provider apps.",
        ));
    }

    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    let app = match state
        .oauth2_provider
        .create_app(
            &request.name,
            &request.icon,
            &request.callback_url,
            Some(context.user.id),
        )
        .await
    {
        Ok(app) => app,
        Err(error) => return handle_oauth2_provider_error(error),
    };

    record_audit(
        &state,
        AuditAction::Create,
        ResourceKind::Oauth2ProviderApp,
        Some(&context.user),
        Some(app.id.to_string()),
        "created oauth2 provider app",
    )
    .await;

    Ok((StatusCode::CREATED, Json(oauth2_app_response(app))).into_response())
}

pub(crate) async fn get_oauth2_provider_app(
    State(state): State<AppState>,
    Path(app_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can read OAuth2 provider apps.
    // The member site role grants Oauth2App::Read, so all authenticated users
    // with the default member role retain access (backward compatible).
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::Oauth2App),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to read OAuth2 provider apps.",
        ));
    }

    let app_uuid = match Uuid::parse_str(&app_id) {
        Ok(id) => id,
        Err(_) => {
            return Ok(not_found_response("OAuth2 provider app not found."));
        }
    };
    let app = match state.oauth2_provider.get_app(app_uuid).await {
        Ok(app) => app,
        Err(error) => return handle_oauth2_provider_error(error),
    };
    Ok((StatusCode::OK, Json(oauth2_app_response(app))).into_response())
}

pub(crate) async fn put_oauth2_provider_app(
    State(state): State<AppState>,
    Path(app_id): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<PutOAuth2ProviderAppRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can update OAuth2 provider apps.
    // This intentionally replaces the prior is_owner() gate to support future
    // custom roles that may grant OAuth2 app management without full ownership.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::Oauth2App),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update OAuth2 provider apps.",
        ));
    }

    let app_uuid = match Uuid::parse_str(&app_id) {
        Ok(id) => id,
        Err(_) => {
            return Ok(not_found_response("OAuth2 provider app not found."));
        }
    };
    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    let app = match state
        .oauth2_provider
        .update_app(
            app_uuid,
            &request.name,
            &request.icon,
            &request.callback_url,
        )
        .await
    {
        Ok(app) => app,
        Err(error) => return handle_oauth2_provider_error(error),
    };

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::Oauth2ProviderApp,
        Some(&context.user),
        Some(app.id.to_string()),
        "updated oauth2 provider app",
    )
    .await;

    Ok((StatusCode::OK, Json(oauth2_app_response(app))).into_response())
}

pub(crate) async fn delete_oauth2_provider_app(
    State(state): State<AppState>,
    Path(app_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can delete OAuth2 provider apps.
    // This intentionally replaces the prior is_owner() gate to support future
    // custom roles that may grant OAuth2 app management without full ownership.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Delete,
            &Object::new(ResourceType::Oauth2App),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to delete OAuth2 provider apps.",
        ));
    }

    let app_uuid = match Uuid::parse_str(&app_id) {
        Ok(id) => id,
        Err(_) => {
            return Ok(not_found_response("OAuth2 provider app not found."));
        }
    };
    if let Err(error) = state.oauth2_provider.delete_app(app_uuid).await {
        return handle_oauth2_provider_error(error);
    }

    record_audit(
        &state,
        AuditAction::Delete,
        ResourceKind::Oauth2ProviderApp,
        Some(&context.user),
        Some(app_id),
        "deleted oauth2 provider app",
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

pub(crate) async fn list_oauth2_provider_app_secrets(
    State(state): State<AppState>,
    Path(app_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can read OAuth2 provider app secrets.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::Oauth2AppSecret),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to list OAuth2 provider app secrets.",
        ));
    }

    let app_uuid = match Uuid::parse_str(&app_id) {
        Ok(id) => id,
        Err(_) => {
            return Ok(not_found_response("OAuth2 provider app not found."));
        }
    };
    let secrets = match state.oauth2_provider.list_app_secrets(app_uuid).await {
        Ok(secrets) => secrets,
        Err(error) => return handle_oauth2_provider_error(error),
    };
    let response: Vec<OAuth2ProviderAppSecretResponse> =
        secrets.into_iter().map(oauth2_secret_response).collect();
    Ok((StatusCode::OK, Json(response)).into_response())
}

pub(crate) async fn post_oauth2_provider_app_secret(
    State(state): State<AppState>,
    Path(app_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can create OAuth2 provider app secrets.
    // This intentionally replaces the prior is_owner() gate to support future
    // custom roles that may grant OAuth2 app management without full ownership.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Create,
            &Object::new(ResourceType::Oauth2AppSecret),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to create OAuth2 provider app secrets.",
        ));
    }

    let app_uuid = match Uuid::parse_str(&app_id) {
        Ok(id) => id,
        Err(_) => {
            return Ok(not_found_response("OAuth2 provider app not found."));
        }
    };
    let (raw_secret, record) = match state.oauth2_provider.create_app_secret(app_uuid).await {
        Ok(result) => result,
        Err(error) => return handle_oauth2_provider_error(error),
    };

    record_audit(
        &state,
        AuditAction::Create,
        ResourceKind::Oauth2ProviderAppSecret,
        Some(&context.user),
        Some(record.id.to_string()),
        "created oauth2 provider app secret",
    )
    .await;

    let response = OAuth2ProviderAppSecretFullResponse {
        id: record.id.to_string(),
        client_secret_full: raw_secret,
        client_secret_truncated: record.display_secret,
    };
    Ok((StatusCode::CREATED, Json(response)).into_response())
}

pub(crate) async fn delete_oauth2_provider_app_secret(
    State(state): State<AppState>,
    Path((app_id, secret_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can delete OAuth2 provider app secrets.
    // This intentionally replaces the prior is_owner() gate to support future
    // custom roles that may grant OAuth2 app management without full ownership.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Delete,
            &Object::new(ResourceType::Oauth2AppSecret),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to delete OAuth2 provider app secrets.",
        ));
    }

    let app_uuid = match Uuid::parse_str(&app_id) {
        Ok(id) => id,
        Err(_) => {
            return Ok(not_found_response("OAuth2 provider app not found."));
        }
    };
    let secret_uuid = match Uuid::parse_str(&secret_id) {
        Ok(id) => id,
        Err(_) => {
            return Ok(not_found_response("OAuth2 provider app secret not found."));
        }
    };
    if let Err(error) = state
        .oauth2_provider
        .delete_app_secret(app_uuid, secret_uuid)
        .await
    {
        return handle_oauth2_provider_error(error);
    }

    record_audit(
        &state,
        AuditAction::Delete,
        ResourceKind::Oauth2ProviderAppSecret,
        Some(&context.user),
        Some(secret_id),
        "deleted oauth2 provider app secret",
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

pub(crate) async fn delete_oauth2_provider_app_tokens(
    State(state): State<AppState>,
    Path(app_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // No RBAC check here: this is a self-service endpoint where any
    // authenticated user can revoke their own OAuth2 app authorizations.
    // The downstream revoke_tokens() call is scoped to context.user.id,
    // so users can only revoke their own tokens.

    let app_uuid = match Uuid::parse_str(&app_id) {
        Ok(id) => id,
        Err(_) => {
            return Ok(not_found_response("OAuth2 provider app not found."));
        }
    };
    if let Err(error) = state
        .oauth2_provider
        .revoke_tokens(app_uuid, context.user.id)
        .await
    {
        return handle_oauth2_provider_error(error);
    }

    record_audit(
        &state,
        AuditAction::Delete,
        ResourceKind::Oauth2ProviderApp,
        Some(&context.user),
        Some(app_id),
        "revoked oauth2 provider app tokens",
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

pub(crate) async fn get_oauth2_authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<OAuth2AuthorizeRequest>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if params.response_type != "code" {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "response_type must be \"code\".",
                "Only the authorization code flow is supported.",
            )),
        )
            .into_response());
    }
    let client_id = match Uuid::parse_str(&params.client_id) {
        Ok(id) => id,
        Err(_) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error(
                    "Invalid client_id.",
                    "The client_id must be a valid UUID.",
                )),
            )
                .into_response());
        }
    };

    // Validate the app and its callback URL BEFORE creating the authorization
    // code.  This prevents orphaned codes when the callback URL is invalid.
    let app = match state.oauth2_provider.get_app(client_id).await {
        Ok(app) => app,
        Err(error) => return handle_oauth2_provider_error(error),
    };
    let mut redirect_url = match url::Url::parse(&app.callback_url) {
        Ok(url) => url,
        Err(_) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error(
                    "App has invalid callback URL.",
                    "The callback URL configured for this app is not a valid URL.",
                )),
            )
                .into_response());
        }
    };

    let raw_code = match state
        .oauth2_provider
        .create_authorization_code(
            client_id,
            context.user.id,
            &params.resource,
            &params.code_challenge,
            &params.code_challenge_method,
        )
        .await
    {
        Ok(code) => code,
        Err(error) => return handle_oauth2_provider_error(error),
    };

    // Build the redirect URL with the code and state.
    redirect_url
        .query_pairs_mut()
        .append_pair("code", &raw_code)
        .append_pair("state", &params.state);

    Ok((
        StatusCode::TEMPORARY_REDIRECT,
        [("location", redirect_url.as_str())],
    )
        .into_response())
}

pub(crate) async fn post_oauth2_authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<OAuth2AuthorizeRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(params) = match payload {
        Ok(p) => p,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    if params.response_type != "code" {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "response_type must be \"code\".",
                "Only the authorization code flow is supported.",
            )),
        )
            .into_response());
    }
    let client_id = match Uuid::parse_str(&params.client_id) {
        Ok(id) => id,
        Err(_) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error(
                    "Invalid client_id.",
                    "The client_id must be a valid UUID.",
                )),
            )
                .into_response());
        }
    };

    // Validate the app and its callback URL BEFORE creating the authorization
    // code.  This prevents orphaned codes when the callback URL is invalid.
    let app = match state.oauth2_provider.get_app(client_id).await {
        Ok(app) => app,
        Err(error) => return handle_oauth2_provider_error(error),
    };
    let mut redirect_url = match url::Url::parse(&app.callback_url) {
        Ok(url) => url,
        Err(_) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error(
                    "App has invalid callback URL.",
                    "The callback URL configured for this app is not a valid URL.",
                )),
            )
                .into_response());
        }
    };

    let raw_code = match state
        .oauth2_provider
        .create_authorization_code(
            client_id,
            context.user.id,
            &params.resource,
            &params.code_challenge,
            &params.code_challenge_method,
        )
        .await
    {
        Ok(code) => code,
        Err(error) => return handle_oauth2_provider_error(error),
    };

    // Build the redirect URL with the code and state.
    redirect_url
        .query_pairs_mut()
        .append_pair("code", &raw_code)
        .append_pair("state", &params.state);

    // Use 303 See Other (not 307) so the browser follows the redirect with
    // GET.  A 307 would re-issue the POST to the callback URL, which only
    // handles GET per RFC 6749 §4.1.2.
    Ok((StatusCode::SEE_OTHER, [("location", redirect_url.as_str())]).into_response())
}

pub(crate) async fn post_oauth2_token(
    State(state): State<AppState>,
    Form(request): Form<OAuth2TokenRequest>,
) -> Result<Response, AppError> {
    match request.grant_type.as_str() {
        "authorization_code" => {
            let client_id = match Uuid::parse_str(&request.client_id) {
                Ok(id) => id,
                Err(_) => {
                    return Ok((
                        StatusCode::BAD_REQUEST,
                        Json(ApiResponse::error(
                            "Invalid client_id.",
                            "The client_id must be a valid UUID.",
                        )),
                    )
                        .into_response());
                }
            };
            let result = match state
                .oauth2_provider
                .exchange_code(
                    &request.code,
                    client_id,
                    &request.client_secret,
                    &request.code_verifier,
                )
                .await
            {
                Ok(result) => result,
                Err(error) => return handle_oauth2_provider_error(error),
            };
            let response = OAuth2TokenResponse {
                access_token: result.access_token,
                token_type: result.token_type,
                expires_in: result.expires_in,
                refresh_token: result.refresh_token,
            };
            Ok((StatusCode::OK, Json(response)).into_response())
        }
        "refresh_token" => {
            let client_id = match Uuid::parse_str(&request.client_id) {
                Ok(id) => id,
                Err(_) => {
                    return Ok((
                        StatusCode::BAD_REQUEST,
                        Json(ApiResponse::error(
                            "Invalid client_id.",
                            "The client_id must be a valid UUID.",
                        )),
                    )
                        .into_response());
                }
            };
            let result = match state
                .oauth2_provider
                .refresh_token(&request.refresh_token, client_id, &request.client_secret)
                .await
            {
                Ok(result) => result,
                Err(error) => return handle_oauth2_provider_error(error),
            };
            let response = OAuth2TokenResponse {
                access_token: result.access_token,
                token_type: result.token_type,
                expires_in: result.expires_in,
                refresh_token: result.refresh_token,
            };
            Ok((StatusCode::OK, Json(response)).into_response())
        }
        _ => Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "Unsupported grant_type.",
                "Supported grant types are: authorization_code, refresh_token.",
            )),
        )
            .into_response()),
    }
}

// ---------------------------------------------------------------------------
// RFC 8414 — Authorization Server Metadata
// ---------------------------------------------------------------------------

/// GET /.well-known/oauth-authorization-server
pub(crate) async fn get_oauth2_authorization_server_metadata(
    State(state): State<AppState>,
) -> Json<OAuth2AuthorizationServerMetadata> {
    let access_url = state.config.access_url.to_string();
    let access_url = access_url.trim_end_matches('/');
    Json(OAuth2AuthorizationServerMetadata {
        issuer: access_url.to_owned(),
        authorization_endpoint: format!("{access_url}/oauth2/authorize"),
        token_endpoint: format!("{access_url}/oauth2/tokens"),
        registration_endpoint: format!("{access_url}/oauth2/register"),
        // NOTE: Token revocation is not yet implemented — the handler returns
        // an error instead of silently succeeding. We still advertise the
        // endpoint to match Go's metadata response (which also includes it),
        // so clients can discover it for future use.
        revocation_endpoint: format!("{access_url}/oauth2/revoke"),
        response_types_supported: vec!["code".to_owned()],
        grant_types_supported: vec!["authorization_code".to_owned(), "refresh_token".to_owned()],
        code_challenge_methods_supported: vec!["S256".to_owned()],
        scopes_supported: external_scope_names(),
        token_endpoint_auth_methods_supported: vec![
            "client_secret_basic".to_owned(),
            "client_secret_post".to_owned(),
        ],
    })
}

// ---------------------------------------------------------------------------
// RFC 9728 — Protected Resource Metadata
// ---------------------------------------------------------------------------

/// GET /.well-known/oauth-protected-resource
pub(crate) async fn get_oauth2_protected_resource_metadata(
    State(state): State<AppState>,
) -> Json<OAuth2ProtectedResourceMetadata> {
    let access_url = state.config.access_url.to_string();
    let access_url = access_url.trim_end_matches('/');
    Json(OAuth2ProtectedResourceMetadata {
        resource: access_url.to_owned(),
        authorization_servers: vec![access_url.to_owned()],
        scopes_supported: external_scope_names(),
        bearer_methods_supported: vec!["header".to_owned(), "query".to_owned()],
    })
}

// ---------------------------------------------------------------------------
// RFC 7591 — Dynamic Client Registration
// ---------------------------------------------------------------------------

/// POST /oauth2/register
pub(crate) async fn post_oauth2_register(
    State(state): State<AppState>,
    payload: Result<Json<OAuth2ClientRegistrationRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Json(req) = match payload {
        Ok(r) => r,
        Err(_) => {
            return Ok(oauth2_registration_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                "Invalid JSON body",
            ));
        }
    };

    // Validate
    if let Err(msg) = req.validate() {
        return Ok(oauth2_registration_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            &msg,
        ));
    }

    // Apply defaults
    let req = req.apply_defaults();
    let client_name = req.generate_client_name();

    // Create the app via the existing OAuth2 provider service.
    // Dynamic registration uses a system-level context (no user auth required),
    // matching Go's use of `dbauthz.AsSystemRestricted(ctx)` with `InsertOAuth2ProviderApp`.
    //
    // NOTE: The existing store only supports a single callback_url.
    // The response echoes back all redirect_uris from the request, but only
    // the first one is persisted as the app's callback_url. This matches
    // Go behavior where only the primary redirect_uri is stored.
    let callback_url = req.redirect_uris.first().cloned().unwrap_or_default();

    let app = match state
        .oauth2_provider
        .create_app(&client_name, &req.logo_uri, &callback_url, None)
        .await
    {
        Ok(app) => app,
        Err(_) => {
            return Ok(oauth2_registration_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Failed to store client registration",
            ));
        }
    };

    // Create a client secret for the app.
    let (client_secret, _secret_record) =
        match state.oauth2_provider.create_app_secret(app.id).await {
            Ok(result) => result,
            Err(_) => {
                return Ok(oauth2_registration_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "Failed to generate client secret",
                ));
            }
        };

    let access_url = state.config.access_url.to_string();
    let access_url = access_url.trim_end_matches('/');

    // Generate a random registration access token for RFC 7592 client management.
    // NOTE: This token is NOT persisted or verified — the RFC 7592 endpoints
    // (GET/PUT/DELETE /oauth2/clients/{client_id}) currently reject all requests
    // because the DB lacks a registration_access_token_hash column.
    // A future migration will add token storage and hash verification.
    let registration_access_token = generate_registration_token();
    let registration_client_uri = format!("{access_url}/oauth2/clients/{}", app.id);

    let now = OffsetDateTime::now_utc().unix_timestamp();

    let response = OAuth2ClientRegistrationResponse {
        client_id: app.id.to_string(),
        client_secret,
        client_id_issued_at: Some(now),
        client_secret_expires_at: Some(0),
        redirect_uris: req.redirect_uris,
        client_name,
        client_uri: req.client_uri,
        logo_uri: req.logo_uri,
        tos_uri: req.tos_uri,
        policy_uri: req.policy_uri,
        grant_types: req.grant_types,
        response_types: req.response_types,
        token_endpoint_auth_method: req.token_endpoint_auth_method,
        scope: req.scope,
        contacts: req.contacts,
        registration_access_token,
        registration_client_uri,
    };

    record_audit(
        &state,
        AuditAction::Create,
        ResourceKind::Oauth2ProviderApp,
        None,
        Some(app.id.to_string()),
        "dynamic client registration (RFC 7591)",
    )
    .await;

    Ok((StatusCode::CREATED, Json(response)).into_response())
}

// ---------------------------------------------------------------------------
// RFC 7592 — Client Configuration (GET / PUT / DELETE)
// ---------------------------------------------------------------------------

/// GET /oauth2/clients/{client_id}
pub(crate) async fn get_oauth2_client_configuration(
    State(state): State<AppState>,
    Path(client_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    // Validate registration access token
    if let Some(err_response) = validate_registration_token(&headers) {
        return Ok(err_response);
    }

    let client_uuid = match Uuid::parse_str(&client_id) {
        Ok(id) => id,
        Err(_) => {
            return Ok(oauth2_registration_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                "Invalid client ID format",
            ));
        }
    };

    let app = match state.oauth2_provider.get_app(client_uuid).await {
        Ok(app) => app,
        Err(OAuth2ProviderError::NotFound { .. }) => {
            return Ok(oauth2_registration_error(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "Client not found",
            ));
        }
        Err(_) => {
            return Ok(oauth2_registration_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Failed to retrieve client",
            ));
        }
    };

    let access_url = state.config.access_url.to_string();
    let access_url = access_url.trim_end_matches('/');

    let response = OAuth2ClientConfiguration {
        client_id: app.id.to_string(),
        client_id_issued_at: app.created_at.unix_timestamp(),
        client_secret_expires_at: Some(0),
        redirect_uris: app.redirect_uris,
        client_name: app.name,
        client_uri: String::new(),
        logo_uri: app.icon,
        tos_uri: String::new(),
        policy_uri: String::new(),
        grant_types: vec!["authorization_code".to_owned(), "refresh_token".to_owned()],
        response_types: vec!["code".to_owned()],
        token_endpoint_auth_method: "client_secret_basic".to_owned(),
        scope: String::new(),
        contacts: Vec::new(),
        registration_access_token: String::new(), // RFC 7592: Not returned in GET for security
        registration_client_uri: format!("{access_url}/oauth2/clients/{}", app.id),
    };

    Ok((StatusCode::OK, Json(response)).into_response())
}

/// PUT /oauth2/clients/{client_id}
pub(crate) async fn put_oauth2_client_configuration(
    State(state): State<AppState>,
    Path(client_id): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<OAuth2ClientRegistrationRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    // Validate registration access token
    if let Some(err_response) = validate_registration_token(&headers) {
        return Ok(err_response);
    }

    let client_uuid = match Uuid::parse_str(&client_id) {
        Ok(id) => id,
        Err(_) => {
            return Ok(oauth2_registration_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                "Invalid client ID format",
            ));
        }
    };

    let Json(req) = match payload {
        Ok(r) => r,
        Err(_) => {
            return Ok(oauth2_registration_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                "Invalid JSON body",
            ));
        }
    };

    // Validate
    if let Err(msg) = req.validate() {
        return Ok(oauth2_registration_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            &msg,
        ));
    }

    let req = req.apply_defaults();
    let client_name = req.generate_client_name();
    let callback_url = req.redirect_uris.first().cloned().unwrap_or_default();

    let app = match state
        .oauth2_provider
        .update_app(client_uuid, &client_name, &req.logo_uri, &callback_url)
        .await
    {
        Ok(app) => app,
        Err(OAuth2ProviderError::NotFound { .. }) => {
            return Ok(oauth2_registration_error(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "Client not found",
            ));
        }
        Err(_) => {
            return Ok(oauth2_registration_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Failed to update client",
            ));
        }
    };

    let access_url = state.config.access_url.to_string();
    let access_url = access_url.trim_end_matches('/');

    let response = OAuth2ClientConfiguration {
        client_id: app.id.to_string(),
        client_id_issued_at: app.created_at.unix_timestamp(),
        client_secret_expires_at: Some(0),
        redirect_uris: app.redirect_uris,
        client_name: app.name,
        client_uri: req.client_uri,
        logo_uri: app.icon,
        tos_uri: req.tos_uri,
        policy_uri: req.policy_uri,
        grant_types: req.grant_types,
        response_types: req.response_types,
        token_endpoint_auth_method: req.token_endpoint_auth_method,
        scope: req.scope,
        contacts: req.contacts,
        registration_access_token: String::new(), // RFC 7592: Not returned for security
        registration_client_uri: format!("{access_url}/oauth2/clients/{}", app.id),
    };

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::Oauth2ProviderApp,
        None,
        Some(app.id.to_string()),
        "updated client configuration (RFC 7592)",
    )
    .await;

    Ok((StatusCode::OK, Json(response)).into_response())
}

/// DELETE /oauth2/clients/{client_id}
pub(crate) async fn delete_oauth2_client_configuration(
    State(state): State<AppState>,
    Path(client_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    // Validate registration access token
    if let Some(err_response) = validate_registration_token(&headers) {
        return Ok(err_response);
    }

    let client_uuid = match Uuid::parse_str(&client_id) {
        Ok(id) => id,
        Err(_) => {
            return Ok(oauth2_registration_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                "Invalid client ID format",
            ));
        }
    };

    // Verify app exists before deleting
    match state.oauth2_provider.get_app(client_uuid).await {
        Ok(_) => {}
        Err(OAuth2ProviderError::NotFound { .. }) => {
            return Ok(oauth2_registration_error(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "Client not found",
            ));
        }
        Err(_) => {
            return Ok(oauth2_registration_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Failed to retrieve client",
            ));
        }
    }

    if state.oauth2_provider.delete_app(client_uuid).await.is_err() {
        return Ok(oauth2_registration_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "Failed to delete client",
        ));
    }

    record_audit(
        &state,
        AuditAction::Delete,
        ResourceKind::Oauth2ProviderApp,
        None,
        Some(client_id),
        "deleted client registration (RFC 7592)",
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

// ---------------------------------------------------------------------------
// RFC 7009 — Token Revocation
// ---------------------------------------------------------------------------

/// POST /oauth2/revoke
pub(crate) async fn post_oauth2_revoke(
    State(state): State<AppState>,
    Form(req): Form<OAuth2TokenRevocationRequest>,
) -> Result<Response, AppError> {
    // RFC 7009 requires the 'token' parameter.
    if req.token.is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(OAuth2ErrorResponse {
                error: "invalid_request".to_owned(),
                error_description: "Missing token parameter".to_owned(),
            }),
        )
            .into_response());
    }

    // Parse client_id to find the app.
    let client_id = match Uuid::parse_str(&req.client_id) {
        Ok(id) => id,
        Err(_) => {
            // RFC 7009: return 200 even for invalid requests to not reveal info.
            return Ok(StatusCode::OK.into_response());
        }
    };

    // Verify the app exists.
    match state.oauth2_provider.get_app(client_id).await {
        Ok(_) => {}
        Err(_) => {
            // RFC 7009: return 200 regardless.
            return Ok(StatusCode::OK.into_response());
        }
    }

    // Token revocation is not yet fully implemented. The Go reference
    // implementation looks up tokens by hash and revokes the associated
    // API key + refresh token, but the Rust store lacks the necessary
    // token-to-user lookup.  Return `unsupported_token_type` so callers
    // know the token was NOT revoked, instead of silently returning 200
    // which would mislead clients into believing revocation succeeded.
    Ok((
        StatusCode::BAD_REQUEST,
        Json(OAuth2ErrorResponse {
            error: "unsupported_token_type".to_owned(),
            error_description: "Token revocation is not yet implemented".to_owned(),
        }),
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// Helper functions for RFC compliance endpoints
// ---------------------------------------------------------------------------

/// Returns the sorted list of external scope names (matching Go's rbac.ExternalScopeNames).
///
/// Uses `LazyLock` so the list is sorted and allocated only once.
fn external_scope_names() -> Vec<String> {
    use std::sync::LazyLock;

    static SCOPE_NAMES: LazyLock<Vec<String>> = LazyLock::new(|| {
        let mut names = vec![
            "all".to_owned(),
            "application_connect".to_owned(),
            // Low-level workspace scopes
            "workspace:read".to_owned(),
            "workspace:create".to_owned(),
            "workspace:update".to_owned(),
            "workspace:delete".to_owned(),
            "workspace:ssh".to_owned(),
            "workspace:start".to_owned(),
            "workspace:stop".to_owned(),
            "workspace:application_connect".to_owned(),
            "workspace:*".to_owned(),
            // Template scopes
            "template:read".to_owned(),
            "template:create".to_owned(),
            "template:update".to_owned(),
            "template:delete".to_owned(),
            "template:use".to_owned(),
            "template:*".to_owned(),
            // API key scopes
            "api_key:read".to_owned(),
            "api_key:create".to_owned(),
            "api_key:update".to_owned(),
            "api_key:delete".to_owned(),
            "api_key:*".to_owned(),
            // File scopes
            "file:read".to_owned(),
            "file:create".to_owned(),
            "file:*".to_owned(),
            // User scopes
            "user:read_personal".to_owned(),
            "user:update_personal".to_owned(),
            "user.*".to_owned(),
            // User secret scopes
            "user_secret:read".to_owned(),
            "user_secret:create".to_owned(),
            "user_secret:update".to_owned(),
            "user_secret:delete".to_owned(),
            "user_secret:*".to_owned(),
            // Task scopes
            "task:create".to_owned(),
            "task:read".to_owned(),
            "task:update".to_owned(),
            "task:delete".to_owned(),
            "task:*".to_owned(),
            // Organization scopes
            "organization:read".to_owned(),
            "organization:update".to_owned(),
            "organization:delete".to_owned(),
            "organization:*".to_owned(),
            // Composite scopes
            "coder:workspaces.create".to_owned(),
            "coder:workspaces.operate".to_owned(),
            "coder:workspaces.delete".to_owned(),
            "coder:workspaces.access".to_owned(),
            "coder:templates.build".to_owned(),
            "coder:templates.author".to_owned(),
            "coder:apikeys.manage_self".to_owned(),
        ];
        names.sort();
        names
    });

    SCOPE_NAMES.clone()
}

/// Generate a random registration access token for RFC 7592.
fn generate_registration_token() -> String {
    use base64::Engine as _;
    // Use two UUIDs concatenated to get 32 bytes of randomness without needing `rand`.
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    let mut raw_bytes = [0u8; 32];
    raw_bytes[..16].copy_from_slice(a.as_bytes());
    raw_bytes[16..].copy_from_slice(b.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw_bytes)
}

/// Write an RFC 7591 / 7592 compliant error response.
fn oauth2_registration_error(status: StatusCode, error_code: &str, description: &str) -> Response {
    (
        status,
        Json(OAuth2ErrorResponse {
            error: error_code.to_owned(),
            error_description: description.to_owned(),
        }),
    )
        .into_response()
}

/// Validate the Authorization: Bearer <token> header for RFC 7592 endpoints.
///
/// Currently **always rejects** because registration access tokens are not
/// persisted (the DB has no `registration_access_token_hash` column yet).
/// Once token storage is added, this should verify the token's SHA-256 hash
/// against the stored value, matching Go's `apikey.ValidateHash()` approach.
fn validate_registration_token(headers: &HeaderMap) -> Option<Response> {
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());

    let Some(auth_header) = auth_header else {
        return Some(oauth2_registration_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "Missing Authorization header",
        ));
    };

    if !auth_header.starts_with("Bearer ") {
        return Some(oauth2_registration_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "Authorization header must use Bearer scheme",
        ));
    }

    let token = &auth_header["Bearer ".len()..];
    if token.is_empty() {
        return Some(oauth2_registration_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "Missing registration access token",
        ));
    }

    // Registration access token verification is not yet implemented.
    // The token generated during POST /oauth2/register is not persisted,
    // so we cannot verify it. Reject all requests until a DB migration
    // adds the `registration_access_token_hash` column and the store
    // gains verification support.
    let _ = token;
    Some(oauth2_registration_error(
        StatusCode::UNAUTHORIZED,
        "invalid_token",
        "Registration access token verification is not yet implemented",
    ))
}

pub(crate) fn handle_oauth2_provider_error(
    error: OAuth2ProviderError,
) -> Result<Response, AppError> {
    match error {
        OAuth2ProviderError::Storage(error) => Err(AppError::from(error)),
        OAuth2ProviderError::BadRequest { message } => Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(message, "")),
        )
            .into_response()),
        OAuth2ProviderError::NotFound { message } => Ok(not_found_response(message)),
        OAuth2ProviderError::Unauthorized { message } => Ok(unauthorized_response(message)),
    }
}

pub(crate) fn oauth2_app_response(
    app: coder_core::identity::OAuth2ProviderAppRecord,
) -> OAuth2ProviderAppResponse {
    OAuth2ProviderAppResponse {
        id: app.id.to_string(),
        name: app.name,
        icon: app.icon,
        callback_url: app.callback_url,
        redirect_uris: app.redirect_uris,
        endpoints: OAuth2ProviderAppEndpoints {
            authorization: "/oauth2/authorize".to_owned(),
            token: "/oauth2/tokens".to_owned(),
            device_authorization: String::new(),
        },
    }
}

pub(crate) fn oauth2_secret_response(
    secret: coder_core::identity::OAuth2ProviderAppSecretRecord,
) -> OAuth2ProviderAppSecretResponse {
    OAuth2ProviderAppSecretResponse {
        id: secret.id.to_string(),
        last_used_at: None,
        client_secret_truncated: secret.display_secret,
    }
}
