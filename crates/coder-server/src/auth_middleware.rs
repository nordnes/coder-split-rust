//! Unified API-key / session-token extraction middleware.
//!
//! Equivalent to Go's `ExtractAPIKeyMW` in `coder/coderd/httpmw/apikey.go`.
//!
//! The middleware:
//! 1. Extracts a token from the `Coder-Session-Token` header,
//!    `coder_session_token` cookie, or `Authorization: Bearer` header.
//! 2. Determines whether the token is an API key (format `{10}-{22}`) or a
//!    session token and validates accordingly.
//! 3. Activates dormant users on successful authentication.
//! 4. Tracks API key `last_used` with a 1-hour debounce window.
//! 5. Stores the [`AuthenticatedContext`] in request extensions for downstream
//!    handlers / extractors.

use axum::{
    Json,
    extract::{FromRequestParts, State},
    http::{HeaderMap, StatusCode, request::Parts},
    middleware::Next,
    response::{IntoResponse, Response},
};
use coder_auth::{SESSION_TOKEN_HEADER, cookie_from_headers};
use coder_core::{ApiKeyRecord, ApiKeyScope, ApiResponse, AuthenticatedUser, UserStatus};
use coder_rbac::Actor;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use tracing::warn;

use crate::app::AppState;

// ---------------------------------------------------------------------------
// Public types stored in request extensions
// ---------------------------------------------------------------------------

/// Authentication context produced by the auth middleware and stored in
/// request extensions.  Downstream handlers retrieve it via the [`ApiKeyAuth`]
/// extractor.
#[derive(Clone, Debug)]
pub(crate) struct AuthenticatedContext {
    /// The authenticated user.
    pub user: AuthenticatedUser,
    /// Derived RBAC actor.
    #[allow(dead_code)] // Used by scope enforcement and RBAC checks (wired incrementally).
    pub actor: Actor,
    /// The API key record when authentication was via an API key (as opposed
    /// to a session token).
    pub api_key: Option<ApiKeyRecord>,
    /// Parsed scopes from the API key (or `[All]` for session tokens).
    #[allow(dead_code)] // Used by scope enforcement helpers (wired incrementally).
    pub scopes: Vec<ApiKeyScope>,
}

// ---------------------------------------------------------------------------
// Token helpers
// ---------------------------------------------------------------------------

/// Length of the API key ID portion.
const API_KEY_ID_LEN: usize = 10;
/// Length of the API key secret portion.
const API_KEY_SECRET_LEN: usize = 22;

/// 1 hour in seconds -- the debounce window for `last_used` updates
/// (matches Go's `time.Hour`).
const LAST_USED_DEBOUNCE_SECS: i64 = 3600;

/// Attempts to split a token into API key ID + secret.
///
/// Returns `Some((id, secret))` if the token matches the `{10}-{22}` format,
/// `None` otherwise (treat as session token).
fn split_api_token(token: &str) -> Option<(&str, &str)> {
    let (id, rest) = token.split_once('-')?;
    // Ensure there is exactly one '-' separator.
    if rest.contains('-') {
        return None;
    }
    if id.len() == API_KEY_ID_LEN && rest.len() == API_KEY_SECRET_LEN {
        Some((id, rest))
    } else {
        None
    }
}

/// Extracts the raw token string from request headers.
///
/// Priority order (matching the existing Rust codebase patterns in
/// `helpers.rs`, `extractors.rs`, and `coder-auth/lib.rs`):
/// 1. `Coder-Session-Token` header
/// 2. `coder_session_token` cookie
/// 3. `Authorization: Bearer <token>` header (case-insensitive per RFC 6750)
fn extract_token_from_headers(headers: &HeaderMap) -> Option<String> {
    // Custom header first (matches helpers.rs, extractors.rs, coder-auth/lib.rs).
    if let Some(header_val) = headers
        .get("coder-session-token")
        .and_then(|v| v.to_str().ok())
    {
        if !header_val.is_empty() {
            return Some(header_val.to_owned());
        }
    }

    // Cookie second.
    if let Some(cookie_val) = cookie_from_headers(headers, "coder_session_token") {
        if !cookie_val.is_empty() {
            return Some(cookie_val);
        }
    }

    // RFC 6750 Bearer token (case-insensitive scheme per RFC 7235).
    if let Some(auth_header) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        let mut parts = auth_header.splitn(2, char::is_whitespace);
        if let (Some(scheme), Some(rest)) = (parts.next(), parts.next()) {
            if scheme.eq_ignore_ascii_case("bearer") {
                let token = rest.trim();
                if !token.is_empty() {
                    return Some(token.to_owned());
                }
            }
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Middleware function
// ---------------------------------------------------------------------------

/// Axum middleware that extracts and validates API keys / session tokens.
///
/// On success the [`AuthenticatedContext`] is inserted into request extensions
/// so downstream extractors (e.g. [`ApiKeyAuth`]) can access it.
///
/// If no token is present the request passes through *without* an
/// `AuthenticatedContext` — public routes work normally while protected
/// routes rely on the [`ApiKeyAuth`] extractor to return 401.
///
/// If a token *is* present but invalid, the middleware short-circuits with
/// an appropriate HTTP error so that bad credentials are rejected early.
pub(crate) async fn api_key_auth_middleware(
    State(state): State<AppState>,
    mut request: axum::extract::Request,
    next: Next,
) -> Response {
    // --- Extract token --------------------------------------------------
    // Borrow headers immutably for token extraction; no clone needed.
    let token = match extract_token_from_headers(request.headers()) {
        Some(t) => t,
        None => {
            // No token at all — pass through for public routes.
            // Protected routes will reject via the ApiKeyAuth extractor.
            return next.run(request).await;
        }
    };

    // --- Determine token type and validate ------------------------------
    let ctx = if let Some((key_id, key_secret)) = split_api_token(&token) {
        match validate_api_key(&state, key_id, key_secret).await {
            Ok(ctx) => ctx,
            Err(resp) => return resp,
        }
    } else {
        // Session token path -- delegate to the existing AuthService.
        // The token may have been extracted from the Authorization: Bearer
        // header which `AuthService::authenticate` doesn't check, so we
        // build a synthetic header map with the token in the canonical
        // `Coder-Session-Token` header to ensure it is found.
        let mut auth_headers = HeaderMap::new();
        if let Ok(val) = http::HeaderValue::from_str(&token) {
            auth_headers.insert(SESSION_TOKEN_HEADER, val);
        }
        match state.auth.authenticate(&auth_headers).await {
            Ok(Some(auth_req)) => {
                let scopes = vec![ApiKeyScope::All];
                let actor = coder_auth::actor_from_user(&auth_req.user);
                AuthenticatedContext {
                    user: auth_req.user,
                    actor,
                    api_key: None,
                    scopes,
                }
            }
            Ok(None) => {
                return unauthorized_json("Missing or invalid session token.");
            }
            Err(e) => {
                warn!(error = %e, "session authentication failed");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiResponse::error(
                        "Internal authentication error.",
                        e.to_string(),
                    )),
                )
                    .into_response();
            }
        }
    };

    // --- Dormant user activation ----------------------------------------
    let ctx = match maybe_activate_dormant(&state, ctx).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    // --- Reject non-active users ----------------------------------------
    if ctx.user.status != UserStatus::Active {
        return unauthorized_json(&format!(
            "User is not active (status = {}). Contact an admin to reactivate your account.",
            ctx.user.status.as_str(),
        ));
    }

    // --- Normalise token into the canonical header ----------------------
    // Downstream handlers still call `authenticate_request()` which reads the
    // `Coder-Session-Token` header directly.  By injecting the extracted token
    // here we ensure that session tokens arriving via `Authorization: Bearer`
    // (or cookie) are visible to those handlers without any further changes.
    //
    // For API-key-authenticated requests the token is *not* a session token,
    // so we skip header injection — the `AuthenticatedContext` in extensions
    // is the authoritative source for those requests.
    if ctx.api_key.is_none() {
        if let Ok(val) = http::HeaderValue::from_str(&token) {
            request.headers_mut().insert(SESSION_TOKEN_HEADER, val);
        }
    }

    // --- Store context in extensions ------------------------------------
    request.extensions_mut().insert(ctx);

    next.run(request).await
}

// ---------------------------------------------------------------------------
// API key validation
// ---------------------------------------------------------------------------

/// Validates an API key token against the store.
///
/// Performs:
/// - DB lookup by key ID
/// - Constant-time secret hash comparison
/// - Expiry check
/// - Last-used / expiry refresh (1-hour debounce)
/// - User lookup + RBAC actor construction
async fn validate_api_key(
    state: &AppState,
    key_id: &str,
    key_secret: &str,
) -> Result<AuthenticatedContext, Response> {
    // Look up key.
    let key = state
        .store
        .find_api_key_by_id(key_id)
        .await
        .map_err(|e| {
            warn!(error = %e, "store error looking up API key");
            internal_error_json("A database error occurred.", &e.to_string())
        })?
        .ok_or_else(|| unauthorized_json("API key is invalid."))?;

    // Constant-time secret comparison (SHA-256 of secret vs stored hash).
    //
    // All API key validation failures intentionally return the same generic
    // message to prevent key-ID enumeration.
    let mut hasher = Sha256::new();
    hasher.update(key_secret.as_bytes());
    let secret_hash = hasher.finalize();
    if secret_hash.ct_eq(&key.hashed_secret).unwrap_u8() != 1 {
        return Err(unauthorized_json("API key is invalid."));
    }

    // Expiry check.
    let now = OffsetDateTime::now_utc();
    if key.expires_at < now {
        return Err(unauthorized_json("API key is invalid."));
    }

    // Parse scopes.
    //
    // Go's `expandRBACScope` returns an error when no scopes are provided
    // (modelmethods.go) rather than defaulting to ScopeAll.  We reject
    // keys with no recognised scopes to avoid silently granting full
    // access when an unrecognised scope string is stored in the DB.
    let scopes: Vec<ApiKeyScope> = key
        .scopes
        .iter()
        .filter_map(|s| ApiKeyScope::from_scope_string(s))
        .collect();
    if scopes.is_empty() {
        return Err(unauthorized_json("API key has no recognised scopes."));
    }

    // --- Last-used debounce & expiry refresh ----------------------------
    let mut updated_key = key.clone();
    let mut changed = false;

    let elapsed = now - key.last_used;
    if elapsed.whole_seconds() > LAST_USED_DEBOUNCE_SECS {
        updated_key.last_used = now;
        changed = true;
    }

    // Refresh session expiry.  Go's `ValidateAPIKey` refreshes the expiry
    // for ALL key types (not just Password) when
    // `DisableSessionExpiryRefresh` is false (apikey.go lines 430-436).
    // We replicate that behaviour here.
    {
        let lifetime = time::Duration::seconds(key.lifetime_seconds);
        let remaining = updated_key.expires_at - now;
        if remaining <= lifetime - time::Duration::hours(1) {
            updated_key.expires_at = now + lifetime;
            changed = true;
        }
    }

    if changed {
        // Fire-and-forget updates (non-critical).  Log but don't fail the
        // request if the update itself fails.
        if let Err(e) = state
            .store
            .update_api_key_last_used(
                &updated_key.id,
                updated_key.last_used,
                updated_key.expires_at,
            )
            .await
        {
            warn!(error = %e, key_id = %updated_key.id, "failed to update API key last_used");
        }
        if let Err(e) = state.store.update_user_last_seen_at(key.user_id, now).await {
            warn!(error = %e, user_id = %key.user_id, "failed to update user last_seen_at");
        }
    }

    // Look up user for RBAC.
    let user = state
        .store
        .find_user_by_id(key.user_id)
        .await
        .map_err(|e| {
            warn!(error = %e, "store error looking up user for API key");
            internal_error_json("A database error occurred.", &e.to_string())
        })?
        .ok_or_else(|| unauthorized_json("API key is invalid."))?;

    // Populate org_roles from organization memberships, matching the
    // session-auth path behaviour.
    let mut auth_user = AuthenticatedUser::from(user);
    let memberships = state
        .store
        .list_user_memberships(auth_user.id)
        .await
        .map_err(|e| {
            warn!(error = %e, "store error listing user memberships for API key");
            internal_error_json("A database error occurred.", &e.to_string())
        })?;
    for member in &memberships {
        for role in &member.roles {
            auth_user
                .org_roles
                .push(format!("{}:{}", role.name, member.organization_id));
        }
    }
    let actor = coder_auth::actor_from_user(&auth_user);

    Ok(AuthenticatedContext {
        user: auth_user,
        actor,
        api_key: Some(updated_key),
        scopes,
    })
}

// ---------------------------------------------------------------------------
// Dormant user activation
// ---------------------------------------------------------------------------

/// If the authenticated user is dormant, activate them.
async fn maybe_activate_dormant(
    state: &AppState,
    mut ctx: AuthenticatedContext,
) -> Result<AuthenticatedContext, Response> {
    if ctx.user.status != UserStatus::Dormant {
        return Ok(ctx);
    }

    match state
        .store
        .update_user_status(ctx.user.id, UserStatus::Active)
        .await
    {
        Ok(Some(_updated)) => {
            ctx.user.status = UserStatus::Active;
            Ok(ctx)
        }
        Ok(None) => {
            // User vanished between auth and activation -- treat as
            // unauthorized.
            Err(unauthorized_json("User not found."))
        }
        Err(e) => {
            warn!(error = %e, user_id = %ctx.user.id, "failed to activate dormant user");
            Err(internal_error_json(
                "Failed to activate dormant user.",
                &e.to_string(),
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Extractors
// ---------------------------------------------------------------------------

/// Axum extractor that requires the [`AuthenticatedContext`] produced by
/// [`api_key_auth_middleware`].
///
/// Usage in handlers:
/// ```ignore
/// async fn my_handler(ApiKeyAuth(ctx): ApiKeyAuth) -> impl IntoResponse { .. }
/// ```
#[allow(dead_code)] // Scaffolded extractor for handler migration to extension-based auth.
pub(crate) struct ApiKeyAuth(pub AuthenticatedContext);

impl FromRequestParts<AppState> for ApiKeyAuth {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthenticatedContext>()
            .cloned()
            .map(ApiKeyAuth)
            .ok_or_else(|| unauthorized_json("Authentication required."))
    }
}

/// Extractor that optionally reads the [`AuthenticatedContext`] from request
/// extensions.  Returns `None` when the middleware did not run or the user is
/// not authenticated.
#[allow(dead_code)] // Scaffolded extractor for handlers with optional auth.
pub(crate) struct OptionalApiKeyAuth(pub Option<AuthenticatedContext>);

impl FromRequestParts<AppState> for OptionalApiKeyAuth {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        Ok(OptionalApiKeyAuth(
            parts.extensions.get::<AuthenticatedContext>().cloned(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Scope enforcement helpers
// ---------------------------------------------------------------------------

/// Returns `true` if the authenticated context has the given scope.
#[allow(dead_code)] // Scaffolded for scope-gated route handlers.
pub(crate) fn has_scope(ctx: &AuthenticatedContext, required: ApiKeyScope) -> bool {
    ctx.scopes
        .iter()
        .any(|s| *s == ApiKeyScope::All || *s == required)
}

/// Middleware-style helper that checks scope and returns an error response
/// if the scope requirement is not met.
#[allow(clippy::result_large_err, dead_code)] // Scaffolded for scope-gated route handlers.
pub(crate) fn require_scope(
    ctx: &AuthenticatedContext,
    required: ApiKeyScope,
) -> Result<(), Response> {
    if has_scope(ctx, required) {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(ApiResponse::error(
                format!(
                    "API key does not have the required scope: {}.",
                    required.as_str()
                ),
                String::new(),
            )),
        )
            .into_response())
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn unauthorized_json(message: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(ApiResponse::error(message.to_owned(), String::new())),
    )
        .into_response()
}

fn internal_error_json(message: &str, detail: &str) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ApiResponse::error(message.to_owned(), detail.to_owned())),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_api_token_valid() {
        let token = "abcdefghij-abcdefghijklmnopqrstuv";
        let result = split_api_token(token);
        assert!(result.is_some());
        let (id, secret) = result.unwrap_or_default();
        assert_eq!(id, "abcdefghij");
        assert_eq!(secret, "abcdefghijklmnopqrstuv");
    }

    #[test]
    fn test_split_api_token_invalid_no_dash() {
        assert!(split_api_token("noseparator").is_none());
    }

    #[test]
    fn test_split_api_token_invalid_wrong_id_len() {
        assert!(split_api_token("abcdefghi-abcdefghijklmnopqrstuv").is_none());
    }

    #[test]
    fn test_split_api_token_invalid_wrong_secret_len() {
        assert!(split_api_token("abcdefghij-abcdefghijklmnopqrstu").is_none());
    }

    #[test]
    fn test_split_api_token_multiple_dashes() {
        assert!(split_api_token("abcdefghij-abcdefghijklmnopqr-stuv").is_none());
    }

    #[test]
    fn test_extract_token_from_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            http::HeaderValue::from_static("coder_session_token=my-session-token"),
        );
        let token = extract_token_from_headers(&headers);
        assert_eq!(token.as_deref(), Some("my-session-token"));
    }

    #[test]
    fn test_extract_token_from_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "coder-session-token",
            http::HeaderValue::from_static("header-token"),
        );
        let token = extract_token_from_headers(&headers);
        assert_eq!(token.as_deref(), Some("header-token"));
    }

    #[test]
    fn test_extract_token_from_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            http::HeaderValue::from_static("Bearer my-bearer-token"),
        );
        let token = extract_token_from_headers(&headers);
        assert_eq!(token.as_deref(), Some("my-bearer-token"));
    }

    #[test]
    fn test_extract_token_header_takes_priority_over_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            http::HeaderValue::from_static("coder_session_token=cookie-token"),
        );
        headers.insert(
            "coder-session-token",
            http::HeaderValue::from_static("header-token"),
        );
        let token = extract_token_from_headers(&headers);
        assert_eq!(token.as_deref(), Some("header-token"));
    }

    #[test]
    fn test_extract_token_bearer_case_insensitive() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            http::HeaderValue::from_static("BEARER my-bearer-token"),
        );
        let token = extract_token_from_headers(&headers);
        assert_eq!(token.as_deref(), Some("my-bearer-token"));
    }

    #[test]
    fn test_extract_token_none_when_empty() {
        let headers = HeaderMap::new();
        assert!(extract_token_from_headers(&headers).is_none());
    }

    #[test]
    fn test_api_key_scope_roundtrip() {
        assert_eq!(
            ApiKeyScope::from_scope_string("all"),
            Some(ApiKeyScope::All)
        );
        assert_eq!(
            ApiKeyScope::from_scope_string("application_connect"),
            Some(ApiKeyScope::ApplicationConnect)
        );
        assert_eq!(ApiKeyScope::from_scope_string("unknown"), None);
        assert_eq!(ApiKeyScope::All.as_str(), "all");
        assert_eq!(
            ApiKeyScope::ApplicationConnect.as_str(),
            "application_connect"
        );
    }

    #[test]
    fn test_has_scope_all_grants_everything() {
        let ctx = AuthenticatedContext {
            user: test_user(),
            actor: test_actor(),
            api_key: None,
            scopes: vec![ApiKeyScope::All],
        };
        assert!(has_scope(&ctx, ApiKeyScope::All));
        assert!(has_scope(&ctx, ApiKeyScope::ApplicationConnect));
    }

    #[test]
    fn test_has_scope_specific_does_not_grant_all() {
        let ctx = AuthenticatedContext {
            user: test_user(),
            actor: test_actor(),
            api_key: None,
            scopes: vec![ApiKeyScope::ApplicationConnect],
        };
        assert!(has_scope(&ctx, ApiKeyScope::ApplicationConnect));
        // ApplicationConnect should NOT grant All
        assert!(!has_scope(&ctx, ApiKeyScope::All));
    }

    #[test]
    fn test_require_scope_ok() {
        let ctx = AuthenticatedContext {
            user: test_user(),
            actor: test_actor(),
            api_key: None,
            scopes: vec![ApiKeyScope::All],
        };
        assert!(require_scope(&ctx, ApiKeyScope::ApplicationConnect).is_ok());
    }

    #[test]
    fn test_require_scope_forbidden() {
        let ctx = AuthenticatedContext {
            user: test_user(),
            actor: test_actor(),
            api_key: None,
            scopes: vec![ApiKeyScope::ApplicationConnect],
        };
        assert!(require_scope(&ctx, ApiKeyScope::All).is_err());
    }

    // ---- helpers -------------------------------------------------------

    fn test_user() -> AuthenticatedUser {
        AuthenticatedUser {
            id: uuid::Uuid::from_u128(1),
            email: "test@example.com".to_owned(),
            username: "testuser".to_owned(),
            name: "Test User".to_owned(),
            avatar_url: String::new(),
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            last_seen_at: None,
            organization_ids: vec![],
            roles: vec![],
            org_roles: vec![],
            login_type: coder_core::LoginType::Password,
            status: UserStatus::Active,
        }
    }

    fn test_actor() -> Actor {
        Actor {
            user_id: uuid::Uuid::from_u128(1),
            username: "testuser".to_owned(),
            organization_ids: vec![],
            site_roles: vec![],
            org_roles: vec![],
            groups: vec![],
            scope: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Integration tests — exercise the middleware through the full router
// ---------------------------------------------------------------------------

#[cfg(test)]
mod integration_tests {
    use std::error::Error;

    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use serde_json::Value;
    use tower::ServiceExt;

    use crate::app::build_router;

    /// Helper: build a test router with FakeStore state.
    fn test_app() -> Result<axum::Router, Box<dyn Error>> {
        let state = crate::app::tests::test_state(true)?;
        Ok(build_router(state, None))
    }

    /// Helper: perform a one-shot request against the router.
    async fn call(
        app: axum::Router,
        request: Request<Body>,
    ) -> Result<axum::response::Response<Body>, Box<dyn Error>> {
        let response = match app.oneshot(request).await {
            Ok(r) => r,
            Err(never) => match never {},
        };
        Ok(response)
    }

    /// Helper: parse response body as JSON.
    async fn response_json(
        response: axum::response::Response<Body>,
    ) -> Result<Value, Box<dyn Error>> {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Helper: create first user + login, return session token.
    async fn create_and_login(app: &axum::Router) -> Result<String, Box<dyn Error>> {
        crate::app::tests::create_and_login(app).await
    }

    // -- Public routes work without auth ----------------------------------

    #[tokio::test]
    async fn public_route_buildinfo_returns_ok_without_auth() -> Result<(), Box<dyn Error>> {
        let app = test_app()?;
        let request = Request::builder()
            .method(Method::GET)
            .uri("/api/v2/buildinfo")
            .body(Body::empty())?;
        let response = call(app, request).await?;
        assert_eq!(response.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn public_route_api_root_returns_ok_without_auth() -> Result<(), Box<dyn Error>> {
        let app = test_app()?;
        let request = Request::builder()
            .method(Method::GET)
            .uri("/api/v2")
            .body(Body::empty())?;
        let response = call(app, request).await?;
        assert_eq!(response.status(), StatusCode::OK);
        Ok(())
    }

    // -- Session token authentication through middleware -------------------

    #[tokio::test]
    async fn session_token_auth_via_header() -> Result<(), Box<dyn Error>> {
        let app = test_app()?;
        let session_token = create_and_login(&app).await?;

        // Use the session token via Coder-Session-Token header.
        let request = Request::builder()
            .method(Method::GET)
            .uri("/api/v2/users/me")
            .header("Coder-Session-Token", &session_token)
            .body(Body::empty())?;
        let response = call(app, request).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await?;
        assert_eq!(body.get("username").and_then(Value::as_str), Some("owner"));
        Ok(())
    }

    #[tokio::test]
    async fn session_token_auth_via_cookie() -> Result<(), Box<dyn Error>> {
        let app = test_app()?;
        let session_token = create_and_login(&app).await?;

        // Use the session token via coder_session_token cookie.
        let request = Request::builder()
            .method(Method::GET)
            .uri("/api/v2/users/me")
            .header(
                http::header::COOKIE,
                format!("coder_session_token={session_token}"),
            )
            .body(Body::empty())?;
        let response = call(app, request).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await?;
        assert_eq!(body.get("username").and_then(Value::as_str), Some("owner"));
        Ok(())
    }

    // -- Bearer token authentication through middleware --------------------

    #[tokio::test]
    async fn bearer_token_auth() -> Result<(), Box<dyn Error>> {
        let app = test_app()?;
        let session_token = create_and_login(&app).await?;

        // Use the session token via Authorization: Bearer header.
        let request = Request::builder()
            .method(Method::GET)
            .uri("/api/v2/users/me")
            .header("Authorization", format!("Bearer {session_token}"))
            .body(Body::empty())?;
        let response = call(app, request).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await?;
        assert_eq!(body.get("username").and_then(Value::as_str), Some("owner"));
        Ok(())
    }

    // -- Invalid / missing token rejects ----------------------------------

    #[tokio::test]
    async fn invalid_session_token_returns_unauthorized() -> Result<(), Box<dyn Error>> {
        let app = test_app()?;
        // Ensure first user exists so the route is active.
        let _token = create_and_login(&app).await?;

        let request = Request::builder()
            .method(Method::GET)
            .uri("/api/v2/users/me")
            .header("Coder-Session-Token", "bad-token-value")
            .body(Body::empty())?;
        let response = call(app, request).await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    // -- API key authentication -------------------------------------------

    /// Verify that the middleware correctly validates a well-formed API key
    /// token (`{10-char-id}-{22-char-secret}`) and stores the
    /// `AuthenticatedContext` in request extensions.
    ///
    /// NOTE: The current Rust `create_session_api_key` endpoint returns only
    /// the raw secret (not the `{id}-{secret}` format used in Go), so we
    /// seed the `FakeStore` directly with a properly formatted key to
    /// exercise the middleware's API-key validation path.
    #[tokio::test]
    async fn api_key_auth_with_direct_store_seed() -> Result<(), Box<dyn Error>> {
        use coder_core::{ApiKeyRecord, LoginType};
        use sha2::{Digest, Sha256};
        use time::OffsetDateTime;

        let state = crate::app::tests::test_state(true)?;

        // Step 1: Create first user + login so there is a user in the store.
        let app = build_router(state.clone(), None);
        let _session_token = create_and_login(&app).await?;

        // Resolve the "owner" user id.
        let user = state
            .store
            .find_user_by_username("owner")
            .await
            .map_err(|e| format!("store error: {e}"))?
            .ok_or("owner user not found")?;

        // Step 2: Seed a properly formatted API key (10-char ID, 22-char secret).
        let key_id = "abcdefghij"; // 10 chars
        let key_secret = "0123456789abcdefghijkl"; // 22 chars

        let mut hasher = Sha256::new();
        hasher.update(key_secret.as_bytes());
        let hashed_secret: Vec<u8> = hasher.finalize().to_vec();

        let now = OffsetDateTime::now_utc();
        let expires_at = now + time::Duration::hours(24);
        let record = ApiKeyRecord {
            id: key_id.to_owned(),
            hashed_secret,
            user_id: user.id,
            last_used: now,
            expires_at,
            created_at: now,
            updated_at: now,
            login_type: LoginType::Password,
            scopes: vec!["all".to_owned()],
            token_name: String::new(),
            lifetime_seconds: 86400,
            allow_list: Vec::new(),
        };

        // Insert directly into the FakeStore.
        state
            .store
            .create_api_key(coder_core::CreateApiKeyInput {
                id: record.id.clone(),
                hashed_secret: record.hashed_secret.clone(),
                user_id: record.user_id,
                last_used: record.last_used,
                expires_at: record.expires_at,
                created_at: record.created_at,
                updated_at: record.updated_at,
                login_type: record.login_type,
                scopes: record.scopes.clone(),
                token_name: record.token_name.clone(),
                lifetime_seconds: record.lifetime_seconds,
                allow_list: record.allow_list.clone(),
            })
            .await
            .map_err(|e| format!("create_api_key error: {e}"))?;

        // Step 3: Build a request with the `{id}-{secret}` token.
        let token = format!("{key_id}-{key_secret}");
        let request = Request::builder()
            .method(Method::GET)
            .uri("/api/v2/buildinfo")
            .header("Coder-Session-Token", &token)
            .body(Body::empty())?;
        let response = call(app.clone(), request).await?;

        // buildinfo is a public route so always 200, but the middleware
        // should have run and set the AuthenticatedContext extension.
        assert_eq!(response.status(), StatusCode::OK);

        // Step 4: Verify the API key can also reach a protected endpoint.
        // The protected endpoint still calls authenticate_request() which
        // checks sessions only, so we verify via buildinfo above that the
        // middleware itself accepted the API key.  Full end-to-end protected
        // route support requires handlers to read from extensions (tracked
        // as future migration work).
        Ok(())
    }

    /// Verify that the API key auth path populates `org_roles` on the
    /// `AuthenticatedContext`, matching the session-auth behaviour.
    ///
    /// The test seeds an API key and an organization membership with a role,
    /// then calls `validate_api_key` directly and asserts that the returned
    /// `AuthenticatedContext.user.org_roles` contains the expected entries.
    #[tokio::test]
    async fn api_key_auth_populates_org_roles() -> Result<(), Box<dyn Error>> {
        use coder_core::LoginType;
        use sha2::{Digest, Sha256};
        use time::OffsetDateTime;

        let state = crate::app::tests::test_state(true)?;

        // Create first user + login so there is a user with org membership.
        let app = build_router(state.clone(), None);
        let _session_token = create_and_login(&app).await?;

        // Resolve the "owner" user.
        let user = state
            .store
            .find_user_by_username("owner")
            .await
            .map_err(|e| format!("store error: {e}"))?
            .ok_or("owner user not found")?;

        // Add an org-scoped role to the member so org_roles is non-empty.
        let org_id = user
            .organization_ids
            .first()
            .copied()
            .ok_or("user has no organization_ids")?;
        state
            .store
            .update_organization_member_roles(
                org_id,
                user.id,
                vec!["organization-admin".to_owned()],
            )
            .await
            .map_err(|e| format!("update_organization_member_roles error: {e}"))?;

        // Seed an API key.
        let key_id = "orgroltest"; // 10 chars
        let key_secret = "abcdefghijklmnopqrstuv"; // 22 chars

        let mut hasher = Sha256::new();
        hasher.update(key_secret.as_bytes());
        let hashed_secret: Vec<u8> = hasher.finalize().to_vec();

        let now = OffsetDateTime::now_utc();
        let expires_at = now + time::Duration::hours(24);

        state
            .store
            .create_api_key(coder_core::CreateApiKeyInput {
                id: key_id.to_owned(),
                hashed_secret,
                user_id: user.id,
                last_used: now,
                expires_at,
                created_at: now,
                updated_at: now,
                login_type: LoginType::Password,
                scopes: vec!["all".to_owned()],
                token_name: String::new(),
                lifetime_seconds: 86400,
                allow_list: Vec::new(),
            })
            .await
            .map_err(|e| format!("create_api_key error: {e}"))?;

        // Call validate_api_key directly and inspect the result.
        let ctx = super::validate_api_key(&state, key_id, key_secret)
            .await
            .map_err(|_| "validate_api_key returned an error response")?;

        // org_roles should contain the "organization-admin" role we assigned.
        assert!(
            !ctx.user.org_roles.is_empty(),
            "expected org_roles to be populated for API key auth, got: {:?}",
            ctx.user.org_roles
        );

        // Verify the format is "role_name:org_id".
        for entry in &ctx.user.org_roles {
            assert!(
                entry.contains(':'),
                "org_role entry should be in 'role_name:org_id' format, got: {entry}"
            );
        }

        // Verify org_roles match what session auth would produce via
        // list_user_memberships.
        let memberships = state
            .store
            .list_user_memberships(user.id)
            .await
            .map_err(|e| format!("list_user_memberships error: {e}"))?;
        let mut expected_roles: Vec<String> = Vec::new();
        for member in &memberships {
            for role in &member.roles {
                expected_roles.push(format!("{}:{}", role.name, member.organization_id));
            }
        }
        assert_eq!(
            ctx.user.org_roles, expected_roles,
            "API key org_roles should match session auth org_roles"
        );

        Ok(())
    }
}
