//! OAuth2 provider app CRUD, authorize, and token handlers.

use super::*;

// ---------------------------------------------------------------------------
// RFC 6749 error envelope — typed wrapper + `IntoResponse` mapping
// ---------------------------------------------------------------------------

/// RFC 6749 §5.2 error codes recognised by the token, authorize, and revoke
/// endpoints. Constructing any other error code would put us outside the RFC,
/// so this enum is the only source of error identifiers for those handlers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OAuth2ErrorCode {
    /// The request is missing a required parameter, includes an unsupported
    /// parameter value, or is otherwise malformed.
    InvalidRequest,
    /// Client authentication failed (unknown client, no credentials, or
    /// unsupported auth method).
    InvalidClient,
    /// The provided authorization grant or refresh token is invalid,
    /// expired, revoked, or was issued to another client.
    InvalidGrant,
    /// The authenticated client is not authorized to use this grant type.
    #[allow(dead_code)]
    UnauthorizedClient,
    /// The authorization grant type is not supported by the server.
    UnsupportedGrantType,
    /// The requested scope is invalid, unknown, malformed, or exceeds the
    /// scope granted by the resource owner.
    InvalidScope,
    /// The resource owner or authorization server denied the request.
    #[allow(dead_code)]
    AccessDenied,
    /// The authorization server encountered an unexpected condition.
    ServerError,
    /// The authorization server is currently unable to handle the request.
    #[allow(dead_code)]
    TemporarilyUnavailable,
    /// RFC 8707: the requested `resource` indicator is invalid or not
    /// permitted for this client.
    InvalidTarget,
}

impl OAuth2ErrorCode {
    fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::InvalidScope => "invalid_scope",
            Self::AccessDenied => "access_denied",
            Self::ServerError => "server_error",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::InvalidTarget => "invalid_target",
        }
    }
}

/// An RFC 6749 §5.2 compliant error returned from the OAuth2 token,
/// authorize, and revoke endpoints.
///
/// Implements `IntoResponse` so handlers can return `Err(OAuth2Error{…})`
/// without duplicating the status-code/JSON-body construction.
#[derive(Clone, Debug)]
pub(crate) struct OAuth2Error {
    pub(crate) status: StatusCode,
    pub(crate) code: OAuth2ErrorCode,
    pub(crate) description: String,
}

impl OAuth2Error {
    pub(crate) fn new(
        status: StatusCode,
        code: OAuth2ErrorCode,
        description: impl Into<String>,
    ) -> Self {
        Self {
            status,
            code,
            description: description.into(),
        }
    }

    /// RFC 6749 §5.2 prescribes `400 Bad Request` for most token-endpoint
    /// errors (`invalid_request`, `invalid_grant`, `unsupported_grant_type`,
    /// `invalid_scope`, `invalid_target`).
    pub(crate) fn bad_request(code: OAuth2ErrorCode, description: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, description)
    }

    /// RFC 6749 §5.2 requires `401 Unauthorized` for `invalid_client` when
    /// client authentication is attempted but fails.
    pub(crate) fn invalid_client(description: impl Into<String>) -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            OAuth2ErrorCode::InvalidClient,
            description,
        )
    }

    /// Unexpected server-side failures — the body is still RFC 6749 compliant.
    pub(crate) fn server_error(description: impl Into<String>) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            OAuth2ErrorCode::ServerError,
            description,
        )
    }

    fn into_response_impl(self) -> Response {
        (
            self.status,
            Json(OAuth2ErrorResponse {
                error: self.code.as_str().to_owned(),
                error_description: self.description,
                error_uri: String::new(),
            }),
        )
            .into_response()
    }
}

impl IntoResponse for OAuth2Error {
    fn into_response(self) -> Response {
        self.into_response_impl()
    }
}

/// Translates an [`OAuth2ProviderError`] (from the provider service) into the
/// appropriate [`OAuth2Error`] so handlers on the token/authorize endpoints
/// can use RFC 6749 error bodies consistently.
///
/// The provider error semantics map:
/// * `Storage` → `500 server_error` (DB failure).
/// * `BadRequest` → `400`; the message is scanned for known tags so RFC
///   8707 `invalid_target` and scope errors surface with the correct code.
/// * `NotFound` → `400 invalid_request` (missing client, missing secret).
/// * `Unauthorized` → `401 invalid_grant` (bad code/token/client secret).
fn oauth2_provider_error_to_oauth2_error(error: OAuth2ProviderError) -> OAuth2Error {
    match error {
        OAuth2ProviderError::Storage(e) => OAuth2Error::server_error(format!("{e}")),
        OAuth2ProviderError::BadRequest { message } => {
            // The provider uses these message substrings for the two
            // resource-indicator branches that map to RFC 8707
            // `invalid_target`; everything else maps to `invalid_request`.
            let lower = message.to_ascii_lowercase();
            let code = if lower.contains("resource parameter") {
                OAuth2ErrorCode::InvalidTarget
            } else {
                OAuth2ErrorCode::InvalidRequest
            };
            OAuth2Error::bad_request(code, message)
        }
        OAuth2ProviderError::NotFound { message } => {
            OAuth2Error::bad_request(OAuth2ErrorCode::InvalidRequest, message)
        }
        OAuth2ProviderError::Unauthorized { message } => {
            // Treat every unauthorized as `invalid_grant` for the token
            // endpoint — bad code, bad refresh, bad secret. The
            // `invalid_client` branch is only exercised from HTTP-Basic
            // handling, which does not go through this function.
            OAuth2Error::new(
                StatusCode::UNAUTHORIZED,
                OAuth2ErrorCode::InvalidGrant,
                message,
            )
        }
    }
}

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
        return Ok(OAuth2Error::bad_request(
            OAuth2ErrorCode::InvalidRequest,
            "response_type must be \"code\".",
        )
        .into_response());
    }
    let client_id = match Uuid::parse_str(&params.client_id) {
        Ok(id) => id,
        Err(_) => {
            return Ok(OAuth2Error::bad_request(
                OAuth2ErrorCode::InvalidRequest,
                "Invalid client_id: must be a valid UUID.",
            )
            .into_response());
        }
    };

    // Validate the app and its callback URL BEFORE creating the authorization
    // code.  This prevents orphaned codes when the callback URL is invalid.
    let app = match state.oauth2_provider.get_app(client_id).await {
        Ok(app) => app,
        Err(error) => return Ok(oauth2_provider_error_to_oauth2_error(error).into_response()),
    };
    let mut redirect_url = match url::Url::parse(&app.callback_url) {
        Ok(url) => url,
        Err(_) => {
            return Ok(
                OAuth2Error::server_error("App has invalid callback URL configured.")
                    .into_response(),
            );
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
        Err(error) => return Ok(oauth2_provider_error_to_oauth2_error(error).into_response()),
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
        Err(error) => {
            return Ok(OAuth2Error::bad_request(
                OAuth2ErrorCode::InvalidRequest,
                format!("Invalid JSON body: {error}"),
            )
            .into_response());
        }
    };
    if params.response_type != "code" {
        return Ok(OAuth2Error::bad_request(
            OAuth2ErrorCode::InvalidRequest,
            "response_type must be \"code\".",
        )
        .into_response());
    }
    let client_id = match Uuid::parse_str(&params.client_id) {
        Ok(id) => id,
        Err(_) => {
            return Ok(OAuth2Error::bad_request(
                OAuth2ErrorCode::InvalidRequest,
                "Invalid client_id: must be a valid UUID.",
            )
            .into_response());
        }
    };

    // Validate the app and its callback URL BEFORE creating the authorization
    // code.  This prevents orphaned codes when the callback URL is invalid.
    let app = match state.oauth2_provider.get_app(client_id).await {
        Ok(app) => app,
        Err(error) => return Ok(oauth2_provider_error_to_oauth2_error(error).into_response()),
    };
    let mut redirect_url = match url::Url::parse(&app.callback_url) {
        Ok(url) => url,
        Err(_) => {
            return Ok(
                OAuth2Error::server_error("App has invalid callback URL configured.")
                    .into_response(),
            );
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
        Err(error) => return Ok(oauth2_provider_error_to_oauth2_error(error).into_response()),
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

/// Parse HTTP Basic authentication from an `Authorization` header.
///
/// Returns `(client_id, client_secret)` if the header starts with `Basic `
/// and the base64-encoded payload decodes to a `user:pass` string. Matches
/// RFC 7617 / RFC 6749 §2.3.1 semantics — OAuth2 confidential clients may
/// authenticate via HTTP Basic (percent-decoded), with `user` → `client_id`
/// and `pass` → `client_secret`.
///
/// Returns `None` on any parse failure so the caller can fall back to form
/// credentials without tearing the whole request down.
fn parse_oauth2_basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    use base64::Engine as _;

    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok())?;
    // The scheme prefix is case-insensitive per RFC 7235.
    let rest = auth_header
        .strip_prefix("Basic ")
        .or_else(|| auth_header.strip_prefix("basic "))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(rest.trim())
        .ok()?;
    let decoded = std::str::from_utf8(&decoded).ok()?;
    let (id, secret) = decoded.split_once(':')?;
    // RFC 6749 §2.3.1 requires percent-encoding of the form-urlencoded id
    // and secret before base64 wrapping. We pass the raw values through —
    // both our client_ids (UUIDs) and client_secrets (URL-safe bytes) are
    // always percent-encoding-safe, so this shortcut is correct for every
    // secret the Rust provider mints. Clients that choose to embed
    // reserved characters would need to use body credentials instead.
    Some((id.to_owned(), secret.to_owned()))
}

pub(crate) async fn post_oauth2_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(mut request): Form<OAuth2TokenRequest>,
) -> Result<Response, AppError> {
    // RFC 6749 §2.3.1: confidential clients authenticate via HTTP Basic
    // credentials OR body parameters, but MUST NOT use both in one request.
    // If the client sends Basic auth without also sending body creds, we
    // lift the Basic values into `request` before proceeding.
    if let Some((basic_id, basic_secret)) = parse_oauth2_basic_auth(&headers) {
        let body_has_id = !request.client_id.is_empty();
        let body_has_secret = !request.client_secret.is_empty();
        if body_has_id || body_has_secret {
            return Ok(OAuth2Error::bad_request(
                OAuth2ErrorCode::InvalidRequest,
                "Use either HTTP Basic authentication or body credentials, not both.",
            )
            .into_response());
        }
        request.client_id = basic_id;
        request.client_secret = basic_secret;
    }

    match request.grant_type.as_str() {
        "authorization_code" => {
            let client_id = match Uuid::parse_str(&request.client_id) {
                Ok(id) => id,
                Err(_) => {
                    return Ok(OAuth2Error::invalid_client(
                        "Invalid client_id: must be a valid UUID.",
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
                    &request.resource,
                )
                .await
            {
                Ok(result) => result,
                Err(error) => {
                    return Ok(oauth2_provider_error_to_oauth2_error(error).into_response());
                }
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
                    return Ok(OAuth2Error::invalid_client(
                        "Invalid client_id: must be a valid UUID.",
                    )
                    .into_response());
                }
            };

            // RFC 6749 §6: if the client supplies a `scope` parameter, the
            // requested scope MUST NOT exceed the scope originally granted
            // by the resource owner. The current backend issues tokens with
            // the advertised "external" scope set as the effective grant,
            // so any requested scope that is not in that advertised set is
            // rejected with `invalid_scope`. An empty `scope` preserves the
            // original grant (no narrowing), matching the RFC default.
            if !request.scope.trim().is_empty()
                && let Err(err) = validate_refresh_scope(&request.scope)
            {
                return Ok(err.into_response());
            }

            let result = match state
                .oauth2_provider
                .refresh_token(
                    &request.refresh_token,
                    client_id,
                    &request.client_secret,
                    &request.resource,
                )
                .await
            {
                Ok(result) => result,
                Err(error) => {
                    return Ok(oauth2_provider_error_to_oauth2_error(error).into_response());
                }
            };
            let response = OAuth2TokenResponse {
                access_token: result.access_token,
                token_type: result.token_type,
                expires_in: result.expires_in,
                refresh_token: result.refresh_token,
            };
            Ok((StatusCode::OK, Json(response)).into_response())
        }
        _ => Ok(OAuth2Error::bad_request(
            OAuth2ErrorCode::UnsupportedGrantType,
            "Supported grant types are: authorization_code, refresh_token.",
        )
        .into_response()),
    }
}

/// Validates that every space-separated scope in `requested` is within the
/// advertised external scope set (which represents the "original grant" for
/// tokens minted by this provider).
///
/// Returns `Err(OAuth2Error)` with `invalid_scope` on the first unknown
/// scope. An empty `requested` string should be filtered out by the caller
/// so `preserve original scope` remains the default.
fn validate_refresh_scope(requested: &str) -> Result<(), OAuth2Error> {
    let allowed = external_scope_names();
    for scope in requested.split_whitespace() {
        // Case-sensitive match per RFC 6749 §3.3 scope-token ABNF.
        if !allowed.iter().any(|s| s == scope) {
            return Err(OAuth2Error::bad_request(
                OAuth2ErrorCode::InvalidScope,
                format!("Requested scope \"{scope}\" is not within the scope originally granted."),
            ));
        }
    }
    Ok(())
}

/// `DELETE /oauth2/tokens` — revokes all tokens for the OAuth2 app identified
/// by the `client_id` query parameter, scoped to the current user.
///
/// Mirrors Go `deleteOAuth2ProviderAppTokens()` (the query-param variant).
pub(crate) async fn delete_oauth2_tokens(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<DeleteOAuth2TokensQuery>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

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

    if let Err(error) = state
        .oauth2_provider
        .revoke_tokens(client_id, context.user.id)
        .await
    {
        return handle_oauth2_provider_error(error);
    }

    record_audit(
        &state,
        AuditAction::Delete,
        ResourceKind::Oauth2ProviderApp,
        Some(&context.user),
        Some(client_id.to_string()),
        "revoked oauth2 provider app tokens via /oauth2/tokens",
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

#[derive(Debug, Deserialize)]
pub(crate) struct DeleteOAuth2TokensQuery {
    pub client_id: String,
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
        // Token revocation endpoint — see `post_oauth2_revoke`.
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

    // Generate a registration access token for RFC 7592 client management
    // and persist its SHA-256 hash so the token can be verified later.
    // This is a hard error: returning a token that can never be validated
    // violates RFC 7591 §3.2 (the returned token must be usable).
    let registration_access_token = generate_registration_token();
    {
        use sha2::Digest;
        let token_hash = sha2::Sha256::digest(registration_access_token.as_bytes()).to_vec();
        if let Err(e) = state
            .store
            .update_oauth2_provider_app_registration_token(app.id, &token_hash)
            .await
        {
            tracing::error!(app_id = %app.id, error = %e, "failed to persist registration access token hash");
            return Ok(oauth2_registration_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Failed to persist registration access token",
            ));
        }
    }
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

    // Validate registration access token against stored hash.
    if let Some(err_response) =
        validate_registration_token(&headers, &*state.store, client_uuid).await
    {
        return Ok(err_response);
    }

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

    // Validate registration access token against stored hash.
    if let Some(err_response) =
        validate_registration_token(&headers, &*state.store, client_uuid).await
    {
        return Ok(err_response);
    }

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

    // Validate registration access token against stored hash.
    if let Some(err_response) =
        validate_registration_token(&headers, &*state.store, client_uuid).await
    {
        return Ok(err_response);
    }

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
        return Ok(OAuth2Error::bad_request(
            OAuth2ErrorCode::InvalidRequest,
            "Missing token parameter.",
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

    // Try to revoke the token. We attempt both access-token and
    // refresh-token lookups since the two formats are not easily
    // distinguishable in the Rust backend (both are opaque base64).
    //
    // `revoked` carries the (token_record, hint) pair for the token that
    // was actually deleted — used to emit exactly one audit event below.
    let mut revoked: Option<(
        coder_core::identity::OAuth2ProviderAppTokenRecord,
        &'static str,
    )> = None;

    // --- Access token path ---
    // The hash_prefix stored in the token record is the first 8 bytes
    // of the raw access token string (not hashed).
    let access_prefix = if req.token.len() >= 8 {
        &req.token.as_bytes()[..8]
    } else {
        req.token.as_bytes()
    };

    let mut access_path_verified = false;
    if let Ok(Some(token_record)) = state
        .store
        .find_oauth2_provider_app_token_by_prefix(access_prefix)
        .await
    {
        // Verify the full token matches the API key's hashed secret
        // (the access token IS the API key secret — see generate_token_pair).
        use sha2::Digest;
        use subtle::ConstantTimeEq;

        let mut verified = false;
        if let Ok(Some(api_key)) = state
            .store
            .find_api_key_by_id(&token_record.api_key_id)
            .await
        {
            let token_hash = sha2::Sha256::digest(req.token.as_bytes());
            if bool::from(
                api_key
                    .hashed_secret
                    .as_slice()
                    .ct_eq(token_hash.as_slice()),
            ) {
                verified = true;
            }
        }

        if verified {
            access_path_verified = true;
            // Verify ownership: the token's app must match the requesting client.
            if let Ok(Some(secret)) = state
                .store
                .find_oauth2_provider_app_secret_by_id(token_record.app_secret_id)
                .await
                && secret.app_id == client_id
            {
                // Cascade: deleting the API key cascades to the
                // oauth2_provider_app_tokens row via FK in PostgreSQL; the
                // explicit token delete keeps the FakeStore in sync and
                // guards against any stale rows.
                let _ = state.store.delete_api_key(&token_record.api_key_id).await;
                let _ = state
                    .store
                    .delete_oauth2_provider_app_token(token_record.id)
                    .await;
                revoked = Some((token_record, "access_token"));
            }
        }
        // If verification failed (prefix collision), fall through to the
        // refresh-token path below.
    }

    // --- Refresh token path ---
    // The refresh_hash stored in the token record is SHA-256(refresh_token).
    // Skip the refresh lookup when the access-token path already verified
    // this token; the two formats must not both match a single token value.
    if !access_path_verified {
        use sha2::Digest;

        let refresh_hash = sha2::Sha256::digest(req.token.as_bytes()).to_vec();
        if let Ok(Some(token_record)) = state
            .store
            .find_oauth2_provider_app_token_by_refresh_hash(&refresh_hash)
            .await
            && let Ok(Some(secret)) = state
                .store
                .find_oauth2_provider_app_secret_by_id(token_record.app_secret_id)
                .await
            && secret.app_id == client_id
        {
            let _ = state.store.delete_api_key(&token_record.api_key_id).await;
            let _ = state
                .store
                .delete_oauth2_provider_app_token(token_record.id)
                .await;
            revoked = Some((token_record, "refresh_token"));
        }
    }

    // Emit audit event only on successful revocation — unknown tokens,
    // prefix collisions, and wrong-owner attempts are silent per RFC 7009
    // to avoid leaking token existence.
    if let Some((token, hint)) = revoked {
        let prefix_hex = encode_token_prefix_hex(&token.hash_prefix);
        state
            .audit
            .record(AuditEvent {
                action: AuditAction::Delete,
                resource: ResourceKind::Oauth2ProviderAppToken,
                actor_user_id: Some(token.user_id),
                target_id: Some(token.id.to_string()),
                summary: format!(
                    "revoked oauth2 provider app token ({hint}, prefix={prefix_hex}, client_id={client_id})"
                ),
                diff: None,
            })
            .await;
    }

    // RFC 7009: always return 200 OK regardless of whether the token
    // was found, invalid, or belonged to another client.
    Ok(StatusCode::OK.into_response())
}

/// Returns a lowercase hex-encoded representation of the token's stored
/// `hash_prefix` — safe to include in audit summaries because the prefix
/// is not the secret (the verified secret is the API-key hashed_secret or
/// the `refresh_hash`).
fn encode_token_prefix_hex(prefix: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(prefix.len() * 2);
    for byte in prefix {
        // Writing to a `String` via `fmt::Write` is infallible.
        let _ = write!(&mut s, "{byte:02x}");
    }
    s
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
            error_uri: String::new(),
        }),
    )
        .into_response()
}

/// Validate the Authorization: Bearer <token> header for RFC 7592 endpoints.
///
/// Extracts the Bearer token, hashes it with SHA-256, looks up the app
/// by `app_id`, and compares the hash against the stored
/// `registration_access_token` using constant-time comparison.
///
/// Returns `None` on success, or `Some(error_response)` on failure.
async fn validate_registration_token(
    headers: &HeaderMap,
    store: &dyn AppStore,
    app_id: Uuid,
) -> Option<Response> {
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

    // Look up the app to get the stored registration access token hash.
    let app = match store.find_oauth2_provider_app_by_id(app_id).await {
        Ok(Some(app)) => app,
        Ok(None) => {
            return Some(oauth2_registration_error(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "Client not found",
            ));
        }
        Err(_) => {
            return Some(oauth2_registration_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Failed to retrieve client",
            ));
        }
    };

    let Some(stored_hash) = app.registration_access_token else {
        // Apps created before the migration or via the admin API have no
        // stored hash.  Per RFC 6750 §3.1, return 401 — this is an auth
        // failure, not a server error.
        return Some(oauth2_registration_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "Invalid registration access token",
        ));
    };

    // Compare the provided token's SHA-256 hash against the stored hash.
    use sha2::Digest;
    use subtle::ConstantTimeEq;

    let provided_hash = sha2::Sha256::digest(token.as_bytes());
    if !bool::from(stored_hash.as_slice().ct_eq(provided_hash.as_slice())) {
        return Some(oauth2_registration_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "Invalid registration access token",
        ));
    }

    None
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

#[cfg(test)]
mod tests {
    use super::parse_oauth2_basic_auth;
    use base64::Engine as _;
    use http::HeaderMap;

    fn headers_with_auth(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Ok(v) = http::HeaderValue::from_str(value) {
            headers.insert("authorization", v);
        }
        headers
    }

    #[test]
    fn basic_auth_parses_standard_credentials() {
        let creds = base64::engine::general_purpose::STANDARD
            .encode(b"00000000-0000-0000-0000-000000000000:some-secret");
        let headers = headers_with_auth(&format!("Basic {creds}"));
        let parsed = parse_oauth2_basic_auth(&headers);
        assert!(parsed.is_some(), "Basic credentials must parse");
        let (id, secret) = parsed.unwrap_or_default();
        assert_eq!(id, "00000000-0000-0000-0000-000000000000");
        assert_eq!(secret, "some-secret");
    }

    #[test]
    fn basic_auth_scheme_is_case_insensitive() {
        // RFC 7235 allows mixed-case scheme tokens; confirm the lowercase
        // variant some proxy stacks normalize to still parses.
        let creds = base64::engine::general_purpose::STANDARD.encode(b"abc:xyz");
        let headers = headers_with_auth(&format!("basic {creds}"));
        assert!(
            parse_oauth2_basic_auth(&headers).is_some(),
            "lowercase 'basic' scheme must be accepted"
        );
    }

    #[test]
    fn basic_auth_returns_none_without_header() {
        assert!(parse_oauth2_basic_auth(&HeaderMap::new()).is_none());
    }

    #[test]
    fn basic_auth_returns_none_for_bearer_scheme() {
        // Bearer tokens must not be treated as Basic credentials — they feed
        // a different auth path (the RFC 7592 registration endpoints).
        let headers = headers_with_auth("Bearer some-token");
        assert!(parse_oauth2_basic_auth(&headers).is_none());
    }

    #[test]
    fn basic_auth_returns_none_for_non_base64_payload() {
        let headers = headers_with_auth("Basic !!!not-base64!!!");
        assert!(parse_oauth2_basic_auth(&headers).is_none());
    }

    #[test]
    fn basic_auth_returns_none_when_payload_missing_colon() {
        // "noColon" base64-decodes cleanly but has no `user:pass` split.
        let creds = base64::engine::general_purpose::STANDARD.encode(b"noColon");
        let headers = headers_with_auth(&format!("Basic {creds}"));
        assert!(parse_oauth2_basic_auth(&headers).is_none());
    }

    #[test]
    fn basic_auth_accepts_empty_secret() {
        // "client:" (empty password) is legal HTTP Basic and sometimes used
        // by public OAuth2 clients that only authenticate the id half.
        let creds = base64::engine::general_purpose::STANDARD.encode(b"client-id:");
        let headers = headers_with_auth(&format!("Basic {creds}"));
        let parsed = parse_oauth2_basic_auth(&headers);
        assert!(parsed.is_some());
        let (id, secret) = parsed.unwrap_or_default();
        assert_eq!(id, "client-id");
        assert_eq!(secret, "");
    }
}
