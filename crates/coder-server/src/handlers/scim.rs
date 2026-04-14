//! SCIM 2.0 user provisioning handlers.
//!
//! Implements the subset of the SCIM specification needed for IdP-driven user
//! provisioning (tested with Okta).  Mirrors the Go reference at
//! `coder/enterprise/coderd/scim.go`.

use super::*;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// SCIM core user schema URN.
const SCIM_USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";

/// SCIM list response schema URN.
const SCIM_LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";

// ---------------------------------------------------------------------------
// Auth helper
// ---------------------------------------------------------------------------

/// Validates the SCIM bearer token from the `Authorization` header.
///
/// The comparison is intentionally constant-time to prevent timing attacks.
fn scim_verify_auth(headers: &HeaderMap, scim_api_key: &str) -> bool {
    use subtle::ConstantTimeEq;

    if scim_api_key.is_empty() {
        return false;
    }

    let Some(auth_value) = headers.get("Authorization") else {
        return false;
    };
    let Ok(auth_str) = auth_value.to_str() else {
        return false;
    };

    let auth_bytes = auth_str.as_bytes();
    let bearer_prefix = b"bearer ";

    // Strip case-insensitive "bearer " prefix if present.
    let token_bytes = if auth_bytes.len() >= bearer_prefix.len()
        && auth_bytes[..bearer_prefix.len()]
            .to_ascii_lowercase()
            .ct_eq(bearer_prefix)
            .into()
    {
        &auth_bytes[bearer_prefix.len()..]
    } else {
        auth_bytes
    };

    token_bytes.ct_eq(scim_api_key.as_bytes()).into()
}

/// Builds a SCIM-compliant 401 JSON response.
fn scim_unauthorized_response() -> Response {
    let body = coder_core::api::ScimErrorResponse::new(
        401,
        "invalidAuthorization",
        "invalid authorization",
    );
    (StatusCode::UNAUTHORIZED, Json(body)).into_response()
}

/// Builds a SCIM-compliant error JSON response for the given status code.
fn scim_error_response(status: StatusCode, scim_type: &str, detail: impl Into<String>) -> Response {
    let body = coder_core::api::ScimErrorResponse::new(status.as_u16(), scim_type, detail);
    (status, Json(body)).into_response()
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /scim/v2/ServiceProviderConfig` — returns a static SCIM 2.0
/// ServiceProviderConfig document describing server capabilities.
///
/// Mirrors Go `scimServiceProviderConfig()`.
pub(crate) async fn scim_service_provider_config(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    if !scim_verify_auth(&headers, &state.config.scim_api_key) {
        return scim_unauthorized_response();
    }

    let body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "patch": { "supported": true },
        "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
        "filter": { "supported": false, "maxResults": 0 },
        "changePassword": { "supported": false },
        "sort": { "supported": false },
        "etag": { "supported": false },
        "authenticationSchemes": [{
            "type": "httpbasic",
            "name": "HTTP Basic",
            "description": "Authentication via HTTP Basic"
        }]
    });
    (StatusCode::OK, Json(body)).into_response()
}

/// `GET /scim/v2/Users` — intentionally returns an empty list.
///
/// This forces the IdP (e.g. Okta) to create each user individually via POST,
/// avoiding the need to implement full user listing twice.
pub(crate) async fn scim_get_users(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !scim_verify_auth(&headers, &state.config.scim_api_key) {
        return scim_unauthorized_response();
    }

    let body = coder_core::api::ScimListResponse::<coder_core::api::ScimUser> {
        schemas: vec![SCIM_LIST_SCHEMA.to_owned()],
        total_results: 0,
        start_index: 1,
        items_per_page: 0,
        resources: vec![],
    };
    (StatusCode::OK, Json(body)).into_response()
}

/// `GET /scim/v2/Users/{id}` — intentionally returns 404.
///
/// This forces the IdP to create users via POST rather than updating existing
/// ones, keeping the implementation simple.
pub(crate) async fn scim_get_user(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !scim_verify_auth(&headers, &state.config.scim_api_key) {
        return scim_unauthorized_response();
    }

    scim_error_response(
        StatusCode::NOT_FOUND,
        "notFound",
        "endpoint will always return 404",
    )
}

/// `POST /scim/v2/Users` — creates a new user, or returns the existing user
/// if one is found by email or username.
pub(crate) async fn scim_post_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<coder_core::api::ScimUser>, JsonRejection>,
) -> Result<Response, AppError> {
    if !scim_verify_auth(&headers, &state.config.scim_api_key) {
        return Ok(scim_unauthorized_response());
    }

    let Json(mut scim_user) = match payload {
        Ok(r) => r,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    // Validate required fields.
    if scim_user.active.is_none() {
        return Ok(scim_error_response(
            StatusCode::BAD_REQUEST,
            "invalidRequest",
            "active field is required",
        ));
    }

    // Extract primary email.
    let email = scim_user
        .emails
        .iter()
        .find(|e| e.primary)
        .map(|e| e.value.clone())
        .unwrap_or_default();

    if email.is_empty() {
        return Ok(scim_error_response(
            StatusCode::BAD_REQUEST,
            "invalidEmail",
            "no primary email provided",
        ));
    }

    // Try to find an existing user by username first, then by email.
    let existing_user = find_existing_user(&state, &scim_user.user_name, &email).await?;

    if let Some(db_user) = existing_user {
        // User already exists — return it.
        scim_user.id = db_user.id.to_string();
        scim_user.user_name.clone_from(&db_user.username);

        let active = scim_user.active.unwrap_or(false);
        let new_status = compute_scim_user_status(&db_user, active);

        if db_user.status != new_status {
            let updated = state
                .store
                .update_user_status(db_user.id, new_status)
                .await?;

            if let Some(ref new_user) = updated {
                record_audit(
                    &state,
                    AuditAction::Write,
                    ResourceKind::User,
                    None,
                    Some(new_user.id.to_string()),
                    format!(
                        "SCIM: updated existing user {} status to {:?}",
                        new_user.username, new_status,
                    ),
                )
                .await;
            }
        }

        ensure_scim_schemas(&mut scim_user);
        return Ok((StatusCode::OK, Json(&scim_user)).into_response());
    }

    // ----- Create new user -----

    // Sanitise username — fall back to email prefix if invalid.
    let username = sanitize_scim_username(&scim_user.user_name, &email);

    // Build display name from SCIM name fields.
    let display_name = build_display_name(&scim_user.name);

    // Determine which organizations to assign.
    let organization_ids = default_org_ids(&state).await;

    let new_user = state
        .store
        .create_user(coder_core::CreateUserInput {
            email: email.clone(),
            username: username.clone(),
            name: display_name,
            password_hash: None,
            login_type: LoginType::Oidc,
            status: UserStatus::Dormant,
            organization_ids,
        })
        .await
        .map_err(|err| AppError::InternalError {
            message: "failed to create SCIM user".to_owned(),
            detail: err.to_string(),
        })?;

    record_audit(
        &state,
        AuditAction::Create,
        ResourceKind::User,
        None,
        Some(new_user.id.to_string()),
        format!("SCIM: created user {}", new_user.username),
    )
    .await;

    scim_user.id = new_user.id.to_string();
    scim_user.user_name = new_user.username;
    ensure_scim_schemas(&mut scim_user);

    Ok((StatusCode::CREATED, Json(&scim_user)).into_response())
}

/// `PATCH /scim/v2/Users/{id}` — updates user status (activate/deactivate).
pub(crate) async fn scim_patch_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    payload: Result<Json<coder_core::api::ScimUser>, JsonRejection>,
) -> Result<Response, AppError> {
    if !scim_verify_auth(&headers, &state.config.scim_api_key) {
        return Ok(scim_unauthorized_response());
    }

    let Json(mut scim_user) = match payload {
        Ok(r) => r,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let uid = match Uuid::from_str(&id) {
        Ok(u) => u,
        Err(_) => {
            return Ok(scim_error_response(
                StatusCode::BAD_REQUEST,
                "invalidId",
                format!("id must be a uuid: {id}"),
            ));
        }
    };
    scim_user.id = id;

    let db_user = state
        .store
        .find_user_by_id(uid)
        .await?
        .ok_or_else(|| AppError::NotFound {
            message: format!("user {uid} not found"),
        })?;

    if scim_user.active.is_none() {
        return Ok(scim_error_response(
            StatusCode::BAD_REQUEST,
            "invalidRequest",
            "active field is required",
        ));
    }

    let active = scim_user.active.unwrap_or(false);
    let new_status = compute_scim_user_status(&db_user, active);

    if db_user.status != new_status {
        let updated = state
            .store
            .update_user_status(db_user.id, new_status)
            .await?;

        if let Some(ref new_user) = updated {
            record_audit(
                &state,
                AuditAction::Write,
                ResourceKind::User,
                None,
                Some(new_user.id.to_string()),
                format!(
                    "SCIM: updated user {} status to {:?}",
                    new_user.username, new_status,
                ),
            )
            .await;
        }
    }

    ensure_scim_schemas(&mut scim_user);
    Ok((StatusCode::OK, Json(&scim_user)).into_response())
}

/// `PUT /scim/v2/Users/{id}` — replaces a user resource.
///
/// Currently only supports changing the `active` field.  Other field mutations
/// are rejected as immutability violations per the SCIM specification.
pub(crate) async fn scim_put_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    payload: Result<Json<coder_core::api::ScimUser>, JsonRejection>,
) -> Result<Response, AppError> {
    if !scim_verify_auth(&headers, &state.config.scim_api_key) {
        return Ok(scim_unauthorized_response());
    }

    let Json(mut scim_user) = match payload {
        Ok(r) => r,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let uid = match Uuid::from_str(&id) {
        Ok(u) => u,
        Err(_) => {
            return Ok(scim_error_response(
                StatusCode::BAD_REQUEST,
                "invalidId",
                format!("id must be a uuid: {id}"),
            ));
        }
    };
    scim_user.id = id;

    if scim_user.active.is_none() {
        return Ok(scim_error_response(
            StatusCode::BAD_REQUEST,
            "invalidRequest",
            "active field is required",
        ));
    }

    let db_user = state
        .store
        .find_user_by_id(uid)
        .await?
        .ok_or_else(|| AppError::NotFound {
            message: format!("user {uid} not found"),
        })?;

    // Enforce immutability on username.
    if immutability_violation(&db_user.username, &scim_user.user_name) {
        return Ok(scim_error_response(
            StatusCode::BAD_REQUEST,
            "mutability",
            format!(
                "username is currently an immutable field, and cannot be changed. Current: {}, New: {}",
                db_user.username, scim_user.user_name,
            ),
        ));
    }

    let active = scim_user.active.unwrap_or(false);
    let new_status = compute_scim_user_status(&db_user, active);

    if db_user.status != new_status {
        let updated = state
            .store
            .update_user_status(db_user.id, new_status)
            .await?;

        if let Some(ref new_user) = updated {
            record_audit(
                &state,
                AuditAction::Write,
                ResourceKind::User,
                None,
                Some(new_user.id.to_string()),
                format!(
                    "SCIM: replaced user {} status to {:?}",
                    new_user.username, new_status,
                ),
            )
            .await;
        }
    }

    ensure_scim_schemas(&mut scim_user);
    Ok((StatusCode::OK, Json(&scim_user)).into_response())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Tries to find an existing user by username first, then by email via search.
async fn find_existing_user(
    state: &AppState,
    username: &str,
    email: &str,
) -> Result<Option<coder_core::UserRecord>, AppError> {
    // Try username first (exact match).
    if !username.is_empty() {
        if let Some(user) = state.store.find_user_by_username(username).await? {
            return Ok(Some(user));
        }
    }

    // Fall back to email search.
    if !email.is_empty() {
        let (users, _) = state
            .store
            .list_users(UserListFilter {
                search: email.to_owned(),
                status: None,
                limit: 100,
                offset: 0,
            })
            .await?;

        // Verify exact email match (list_users does substring matching).
        if let Some(user) = users
            .into_iter()
            .find(|u| u.email.eq_ignore_ascii_case(email))
        {
            return Ok(Some(user));
        }
    }

    Ok(None)
}

/// Determines the new `UserStatus` when a SCIM active flag is set.
///
/// Mirrors Go `scimUserStatus()`.
fn compute_scim_user_status(user: &coder_core::UserRecord, active: bool) -> UserStatus {
    if !active {
        return UserStatus::Suspended;
    }

    match user.status {
        UserStatus::Active => UserStatus::Active,
        // Dormant and Suspended both transition to Dormant when activated.
        // The user will become Active after their next login.
        UserStatus::Dormant | UserStatus::Suspended => UserStatus::Dormant,
    }
}

/// Returns `true` if the new value is non-empty and differs from the old one.
///
/// Mirrors Go `immutabilityViolation()`.
fn immutability_violation(old: &str, new: &str) -> bool {
    if new.is_empty() {
        return false;
    }
    old != new
}

/// Sanitises a SCIM-provided username into a valid Coder username.
///
/// If the provided username is empty or would not pass basic validation,
/// falls back to the local part of the email address, then strips invalid
/// characters and truncates to 32 characters.
fn sanitize_scim_username(raw: &str, email: &str) -> String {
    let base = if raw.is_empty() { email } else { raw };

    // Take the local part if it looks like an email.
    let local = base.split('@').next().unwrap_or(base);

    // Replace invalid characters with hyphens and lowercase.
    let sanitized: String = local
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();

    // Trim leading/trailing hyphens, collapse consecutive hyphens, and truncate.
    let trimmed = sanitized.trim_matches('-');
    // Collapse consecutive hyphens.
    let mut collapsed = String::with_capacity(trimmed.len());
    let mut prev_hyphen = false;
    for c in trimmed.chars() {
        if c == '-' {
            if prev_hyphen {
                continue;
            }
            prev_hyphen = true;
        } else {
            prev_hyphen = false;
        }
        collapsed.push(c);
    }
    let truncated = if collapsed.len() > 32 {
        &collapsed[..32]
    } else {
        &collapsed
    };
    // Re-trim in case truncation left a trailing hyphen.
    let truncated = truncated.trim_end_matches('-');

    // If nothing remains, generate a fallback.
    if truncated.is_empty() {
        "scim-user".to_owned()
    } else {
        truncated.to_owned()
    }
}

/// Builds a display name from SCIM name components.
fn build_display_name(name: &coder_core::api::ScimUserName) -> String {
    let full = format!("{} {}", name.given_name, name.family_name);
    let trimmed = full.trim();
    if trimmed.is_empty() {
        String::new()
    } else {
        trimmed.to_owned()
    }
}

/// Returns the default organization ID list for new SCIM users.
///
/// The Go implementation checks OrganizationSyncSettings.AssignDefault.
/// For simplicity, we always assign the default organization if one exists.
async fn default_org_ids(state: &AppState) -> Vec<Uuid> {
    let orgs = state.store.list_organizations(vec![]).await;
    match orgs {
        Ok(list) => list
            .into_iter()
            .filter(|org| org.is_default)
            .map(|org| org.id)
            .collect(),
        Err(_) => vec![],
    }
}

/// Ensures the SCIM user response contains the required schema URN.
fn ensure_scim_schemas(user: &mut coder_core::api::ScimUser) {
    if user.schemas.is_empty() {
        user.schemas = vec![SCIM_USER_SCHEMA.to_owned()];
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::{Method, Request, Response};
    use coder_core::api::{ScimUser, ScimUserEmail, ScimUserMeta, ScimUserName};
    use time::OffsetDateTime;
    use tower::ServiceExt;

    // ----- Test helpers (self-contained, no dependency on app::tests) -----

    fn scim_test_state() -> Result<AppState, Box<dyn std::error::Error>> {
        let (mut state, _store) = crate::app::tests::test_state_with_store(true)?;
        // Override the SCIM API key for testing.
        state.config.scim_api_key = "test-scim-key".to_owned();
        Ok(state)
    }

    async fn call(
        app: axum::Router,
        request: Request<Body>,
    ) -> Result<Response<Body>, Box<dyn std::error::Error>> {
        let response = match app.oneshot(request).await {
            Ok(response) => response,
            Err(never) => match never {},
        };
        Ok(response)
    }

    fn scim_router(state: AppState) -> axum::Router {
        axum::Router::new()
            .route(
                "/scim/v2/Users",
                axum::routing::get(scim_get_users).post(scim_post_user),
            )
            .route(
                "/scim/v2/Users/{id}",
                axum::routing::get(scim_get_user)
                    .patch(scim_patch_user)
                    .put(scim_put_user),
            )
            .with_state(state)
    }

    fn bearer_request(
        method: Method,
        uri: &str,
        token: &str,
    ) -> Result<Request<Body>, http::Error> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
    }

    fn bearer_json_request<T: Serialize>(
        method: Method,
        uri: &str,
        token: &str,
        payload: &T,
    ) -> Result<Request<Body>, Box<dyn std::error::Error>> {
        let body = serde_json::to_vec(payload)?;
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(body))?;
        Ok(request)
    }

    fn test_scim_user(active: bool) -> ScimUser {
        ScimUser {
            schemas: vec![SCIM_USER_SCHEMA.to_owned()],
            id: String::new(),
            user_name: "testuser".to_owned(),
            name: ScimUserName {
                given_name: "Test".to_owned(),
                family_name: "User".to_owned(),
            },
            emails: vec![ScimUserEmail {
                primary: true,
                value: "test@example.com".to_owned(),
                email_type: "work".to_owned(),
                display: "test@example.com".to_owned(),
            }],
            active: Some(active),
            groups: vec![],
            meta: ScimUserMeta {
                resource_type: "User".to_owned(),
            },
        }
    }

    fn test_user_record(status: UserStatus) -> coder_core::UserRecord {
        coder_core::UserRecord {
            id: Uuid::new_v4(),
            email: "a@b.com".to_owned(),
            username: "test".to_owned(),
            name: "Test".to_owned(),
            avatar_url: String::new(),
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            last_seen_at: None,
            organization_ids: vec![],
            roles: vec![],
            login_type: LoginType::Oidc,
            status,
            deleted: false,
            is_system: false,
        }
    }

    async fn response_json(resp: Response<Body>) -> Result<Value, Box<dyn std::error::Error>> {
        let bytes = to_bytes(resp.into_body(), usize::MAX).await?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    async fn response_typed<T: serde::de::DeserializeOwned>(
        resp: Response<Body>,
    ) -> Result<T, Box<dyn std::error::Error>> {
        let bytes = to_bytes(resp.into_body(), usize::MAX).await?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    // ----- Auth tests -----

    #[tokio::test]
    async fn test_scim_auth_missing_header() -> Result<(), Box<dyn std::error::Error>> {
        let state = scim_test_state()?;
        let app = scim_router(state);
        let req = Request::builder()
            .method(Method::GET)
            .uri("/scim/v2/Users")
            .body(Body::empty())?;
        let resp = call(app, req).await?;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[tokio::test]
    async fn test_scim_auth_invalid_token() -> Result<(), Box<dyn std::error::Error>> {
        let state = scim_test_state()?;
        let app = scim_router(state);
        let req = bearer_request(Method::GET, "/scim/v2/Users", "wrong-key")?;
        let resp = call(app, req).await?;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[tokio::test]
    async fn test_scim_auth_valid_token() -> Result<(), Box<dyn std::error::Error>> {
        let state = scim_test_state()?;
        let app = scim_router(state);
        let req = bearer_request(Method::GET, "/scim/v2/Users", "test-scim-key")?;
        let resp = call(app, req).await?;
        assert_eq!(resp.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn test_scim_auth_case_insensitive_bearer() -> Result<(), Box<dyn std::error::Error>> {
        let state = scim_test_state()?;
        let app = scim_router(state);
        let req = Request::builder()
            .method(Method::GET)
            .uri("/scim/v2/Users")
            .header("Authorization", "BEARER test-scim-key")
            .body(Body::empty())?;
        let resp = call(app, req).await?;
        assert_eq!(resp.status(), StatusCode::OK);
        Ok(())
    }

    // ----- GET /scim/v2/Users -----

    #[tokio::test]
    async fn test_scim_get_users_returns_empty() -> Result<(), Box<dyn std::error::Error>> {
        let state = scim_test_state()?;
        let app = scim_router(state);
        let req = bearer_request(Method::GET, "/scim/v2/Users", "test-scim-key")?;
        let resp = call(app, req).await?;
        assert_eq!(resp.status(), StatusCode::OK);

        let body = response_json(resp).await?;
        assert_eq!(body["totalResults"], 0);
        assert_eq!(body["itemsPerPage"], 0);
        Ok(())
    }

    // ----- GET /scim/v2/Users/{id} -----

    #[tokio::test]
    async fn test_scim_get_user_returns_404() -> Result<(), Box<dyn std::error::Error>> {
        let state = scim_test_state()?;
        let app = scim_router(state);
        let uid = Uuid::new_v4();
        let req = bearer_request(
            Method::GET,
            &format!("/scim/v2/Users/{uid}"),
            "test-scim-key",
        )?;
        let resp = call(app, req).await?;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        Ok(())
    }

    // ----- POST /scim/v2/Users -----

    #[tokio::test]
    async fn test_scim_post_user_creates_new_user() -> Result<(), Box<dyn std::error::Error>> {
        let state = scim_test_state()?;
        let app = scim_router(state);
        let scim_user = test_scim_user(true);
        let req = bearer_json_request(Method::POST, "/scim/v2/Users", "test-scim-key", &scim_user)?;
        let resp = call(app, req).await?;
        assert_eq!(resp.status(), StatusCode::CREATED);

        let created: ScimUser = response_typed(resp).await?;
        assert!(!created.id.is_empty());
        assert_eq!(created.user_name, "testuser");
        Ok(())
    }

    #[tokio::test]
    async fn test_scim_post_user_missing_active() -> Result<(), Box<dyn std::error::Error>> {
        let state = scim_test_state()?;
        let app = scim_router(state);
        let mut scim_user = test_scim_user(true);
        scim_user.active = None;
        let req = bearer_json_request(Method::POST, "/scim/v2/Users", "test-scim-key", &scim_user)?;
        let resp = call(app, req).await?;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[tokio::test]
    async fn test_scim_post_user_missing_email() -> Result<(), Box<dyn std::error::Error>> {
        let state = scim_test_state()?;
        let app = scim_router(state);
        let mut scim_user = test_scim_user(true);
        scim_user.emails.clear();
        let req = bearer_json_request(Method::POST, "/scim/v2/Users", "test-scim-key", &scim_user)?;
        let resp = call(app, req).await?;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[tokio::test]
    async fn test_scim_post_user_returns_existing() -> Result<(), Box<dyn std::error::Error>> {
        let state = scim_test_state()?;
        let app = scim_router(state);

        // Create user first.
        let scim_user = test_scim_user(true);
        let req1 =
            bearer_json_request(Method::POST, "/scim/v2/Users", "test-scim-key", &scim_user)?;
        let resp1 = call(app.clone(), req1).await?;
        assert_eq!(resp1.status(), StatusCode::CREATED);
        let body1: ScimUser = response_typed(resp1).await?;

        // POST again with same username — should return existing user.
        let req2 =
            bearer_json_request(Method::POST, "/scim/v2/Users", "test-scim-key", &scim_user)?;
        let resp2 = call(app, req2).await?;
        assert_eq!(resp2.status(), StatusCode::OK);
        let body2: ScimUser = response_typed(resp2).await?;
        assert_eq!(body1.id, body2.id);
        Ok(())
    }

    // ----- PATCH /scim/v2/Users/{id} -----

    #[tokio::test]
    async fn test_scim_patch_deactivate_user() -> Result<(), Box<dyn std::error::Error>> {
        let state = scim_test_state()?;
        let app = scim_router(state);

        // Create a user first.
        let scim_user = test_scim_user(true);
        let req = bearer_json_request(Method::POST, "/scim/v2/Users", "test-scim-key", &scim_user)?;
        let resp = call(app.clone(), req).await?;
        let created: ScimUser = response_typed(resp).await?;

        // Deactivate via PATCH.
        let mut patch_user = test_scim_user(false);
        patch_user.id = created.id.clone();
        let patch_req = bearer_json_request(
            Method::PATCH,
            &format!("/scim/v2/Users/{}", created.id),
            "test-scim-key",
            &patch_user,
        )?;
        let patch_resp = call(app, patch_req).await?;
        assert_eq!(patch_resp.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn test_scim_patch_invalid_uuid() -> Result<(), Box<dyn std::error::Error>> {
        let state = scim_test_state()?;
        let app = scim_router(state);
        let patch_user = test_scim_user(false);
        let req = bearer_json_request(
            Method::PATCH,
            "/scim/v2/Users/not-a-uuid",
            "test-scim-key",
            &patch_user,
        )?;
        let resp = call(app, req).await?;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }

    // ----- PUT /scim/v2/Users/{id} -----

    #[tokio::test]
    async fn test_scim_put_user_immutability_violation() -> Result<(), Box<dyn std::error::Error>> {
        let state = scim_test_state()?;
        let app = scim_router(state);

        // Create a user.
        let scim_user = test_scim_user(true);
        let req = bearer_json_request(Method::POST, "/scim/v2/Users", "test-scim-key", &scim_user)?;
        let resp = call(app.clone(), req).await?;
        let created: ScimUser = response_typed(resp).await?;

        // Try to change username via PUT — should fail.
        let mut put_user = test_scim_user(true);
        put_user.user_name = "different-name".to_owned();
        let put_req = bearer_json_request(
            Method::PUT,
            &format!("/scim/v2/Users/{}", created.id),
            "test-scim-key",
            &put_user,
        )?;
        let put_resp = call(app, put_req).await?;
        assert_eq!(put_resp.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }

    // ----- Helper unit tests -----

    #[test]
    fn test_compute_scim_user_status_deactivate() {
        let user = test_user_record(UserStatus::Active);
        assert_eq!(
            compute_scim_user_status(&user, false),
            UserStatus::Suspended,
        );
    }

    #[test]
    fn test_compute_scim_user_status_keep_active() {
        let user = test_user_record(UserStatus::Active);
        assert_eq!(compute_scim_user_status(&user, true), UserStatus::Active,);
    }

    #[test]
    fn test_compute_scim_user_status_dormant_to_dormant() {
        let user = test_user_record(UserStatus::Dormant);
        assert_eq!(compute_scim_user_status(&user, true), UserStatus::Dormant,);
    }

    #[test]
    fn test_compute_scim_user_status_suspended_to_dormant() {
        let user = test_user_record(UserStatus::Suspended);
        assert_eq!(compute_scim_user_status(&user, true), UserStatus::Dormant,);
    }

    #[test]
    fn test_immutability_violation_empty_new() {
        assert!(!immutability_violation("old", ""));
    }

    #[test]
    fn test_immutability_violation_same() {
        assert!(!immutability_violation("same", "same"));
    }

    #[test]
    fn test_immutability_violation_different() {
        assert!(immutability_violation("old", "new"));
    }

    #[test]
    fn test_sanitize_username_valid() {
        assert_eq!(
            sanitize_scim_username("valid-name", "x@y.com"),
            "valid-name"
        );
    }

    #[test]
    fn test_sanitize_username_empty_uses_email() {
        assert_eq!(sanitize_scim_username("", "user@example.com"), "user");
    }

    #[test]
    fn test_sanitize_username_special_chars() {
        assert_eq!(
            sanitize_scim_username("Hello World!", "x@y.com"),
            "hello-world"
        );
    }

    #[test]
    fn test_sanitize_username_consecutive_special_chars() {
        assert_eq!(sanitize_scim_username("a__b", "x@y.com"), "a-b");
    }

    #[test]
    fn test_build_display_name() {
        let name = ScimUserName {
            given_name: "John".to_owned(),
            family_name: "Doe".to_owned(),
        };
        assert_eq!(build_display_name(&name), "John Doe");
    }

    #[test]
    fn test_build_display_name_empty() {
        let name = ScimUserName::default();
        assert_eq!(build_display_name(&name), "");
    }

    // ----- Auth helper unit tests -----

    #[test]
    fn test_scim_verify_auth_empty_key() {
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", HeaderValue::from_static("Bearer some-key"));
        assert!(!scim_verify_auth(&headers, ""));
    }

    #[test]
    fn test_scim_verify_auth_no_header() {
        let headers = HeaderMap::new();
        assert!(!scim_verify_auth(&headers, "test-key"));
    }

    #[test]
    fn test_scim_verify_auth_valid() {
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", HeaderValue::from_static("Bearer test-key"));
        assert!(scim_verify_auth(&headers, "test-key"));
    }

    #[test]
    fn test_scim_verify_auth_wrong_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            HeaderValue::from_static("Bearer wrong-key"),
        );
        assert!(!scim_verify_auth(&headers, "test-key"));
    }

    #[test]
    fn test_scim_verify_auth_case_insensitive_prefix() {
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", HeaderValue::from_static("BEARER test-key"));
        assert!(scim_verify_auth(&headers, "test-key"));
    }

    #[test]
    fn test_scim_verify_auth_no_prefix() {
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", HeaderValue::from_static("test-key"));
        assert!(scim_verify_auth(&headers, "test-key"));
    }
}
