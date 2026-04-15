//! Workspace proxy CRUD and internal handlers (enterprise — gated on
//! `WorkspaceProxy`).

use super::*;
use coder_core::api::{
    CreateWorkspaceProxyRequest, CryptoKeysResponse, DeregisterWorkspaceProxyRequest,
    IssueSignedAppTokenRequest, IssueSignedAppTokenResponse, PatchWorkspaceProxyRequest,
    ProxyHealthReport, RegisterWorkspaceProxyRequest, RegisterWorkspaceProxyResponse,
    ReportAppStatsRequest, UpdateWorkspaceProxyResponse, WorkspaceProxyResponse,
    WorkspaceProxyStatus,
};
use coder_core::ports::{CreateWorkspaceProxyInput, UpdateWorkspaceProxyInput, WorkspaceProxyRow};
use coder_license::FeatureName;
use sha2::{Digest, Sha256};

use crate::handlers::licenses::{is_feature_entitled, require_enterprise_feature};

/// Length of the random secret portion of a workspace proxy token.
const PROXY_TOKEN_SECRET_LENGTH: usize = 64;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generates a random ASCII secret of the given length.
fn generate_proxy_secret(length: usize) -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// Hashes a secret with SHA-256 (matches Go's `apikey.HashSecret`).
fn hash_proxy_secret(secret: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hasher.finalize().to_vec()
}

/// Generates a full proxy token (`<id>:<secret>`) and returns the token string
/// plus the hashed secret for storage.
fn generate_workspace_proxy_token(id: Uuid) -> (String, Vec<u8>) {
    let secret = generate_proxy_secret(PROXY_TOKEN_SECRET_LENGTH);
    let hashed = hash_proxy_secret(&secret);
    let full_token = format!("{id}:{secret}");
    (full_token, hashed)
}

/// Converts a [`WorkspaceProxyRow`] into a [`WorkspaceProxyResponse`] with a
/// default/unknown health status.
fn proxy_row_to_response(row: &WorkspaceProxyRow) -> WorkspaceProxyResponse {
    WorkspaceProxyResponse {
        region: coder_core::Region {
            id: row.id,
            name: row.name.clone(),
            display_name: row.display_name.clone(),
            icon_url: row.icon.clone(),
            healthy: false,
            path_app_url: row.url.clone(),
            wildcard_hostname: row.wildcard_hostname.clone(),
        },
        derp_enabled: row.derp_enabled,
        derp_only: row.derp_only,
        status: Some(WorkspaceProxyStatus {
            status: "unknown".to_owned(),
            report: Some(ProxyHealthReport {
                errors: Vec::new(),
                warnings: Vec::new(),
            }),
            checked_at: None,
        }),
        created_at: row.created_at,
        updated_at: row.updated_at,
        deleted: row.deleted,
        version: row.version.clone(),
    }
}

/// Resolves a workspace proxy by its path parameter, which can be a UUID or
/// a name slug.
async fn resolve_workspace_proxy(
    state: &AppState,
    id_or_name: &str,
) -> Result<Option<WorkspaceProxyRow>, AppError> {
    // Try UUID first.
    if let Ok(id) = Uuid::parse_str(id_or_name) {
        return Ok(state.store.find_workspace_proxy_by_id(id).await?);
    }
    Ok(state.store.find_workspace_proxy_by_name(id_or_name).await?)
}

// ---------------------------------------------------------------------------
// CRUD Handlers
// ---------------------------------------------------------------------------

/// `GET /api/v2/workspaceproxies` — list all workspace proxies.
pub(crate) async fn list_workspace_proxies(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // Enterprise gate
    let entitlements = state.entitlements.clone();
    if !is_feature_entitled(&entitlements, FeatureName::WorkspaceProxy) {
        return Ok(require_enterprise_feature(&FeatureName::WorkspaceProxy));
    }

    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::WorkspaceProxy),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to list workspace proxies.",
        ));
    }

    let proxies = state.store.list_workspace_proxies().await?;
    let responses: Vec<WorkspaceProxyResponse> =
        proxies.iter().map(proxy_row_to_response).collect();

    // The Go reference wraps proxy responses in `{"regions": [...]}`.
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({ "regions": responses })),
    )
        .into_response())
}

/// `POST /api/v2/workspaceproxies` — create a new workspace proxy.
pub(crate) async fn create_workspace_proxy(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<CreateWorkspaceProxyRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // Enterprise gate
    let entitlements = state.entitlements.clone();
    if !is_feature_entitled(&entitlements, FeatureName::WorkspaceProxy) {
        return Ok(require_enterprise_feature(&FeatureName::WorkspaceProxy));
    }

    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Create,
            &Object::new(ResourceType::WorkspaceProxy),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to create workspace proxies.",
        ));
    }

    let Json(request) = match payload {
        Ok(r) => r,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    // Validate name
    if request.name.is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "Name is required.".to_string(),
                "Workspace proxy name cannot be empty.",
            )),
        )
            .into_response());
    }

    // The name "primary" is reserved for the built-in primary proxy.
    if request.name.eq_ignore_ascii_case("primary") {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "Name \"primary\" is reserved.".to_string(),
                "Cannot create a workspace proxy with the name \"primary\".",
            )),
        )
            .into_response());
    }

    let proxy_id = Uuid::new_v4();
    let (full_token, hashed_token) = generate_workspace_proxy_token(proxy_id);
    let now = OffsetDateTime::now_utc();

    let row = state
        .store
        .create_workspace_proxy(CreateWorkspaceProxyInput {
            id: proxy_id,
            name: request.name,
            display_name: request.display_name,
            icon: request.icon,
            token_hashed: hashed_token,
            created_at: now,
            updated_at: now,
        })
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(UpdateWorkspaceProxyResponse {
            proxy: proxy_row_to_response(&row),
            proxy_token: full_token,
        }),
    )
        .into_response())
}

/// `GET /api/v2/workspaceproxies/{workspaceproxy}` — get a single proxy.
pub(crate) async fn get_workspace_proxy(
    State(state): State<AppState>,
    Path(proxy_id_or_name): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // Enterprise gate
    let entitlements = state.entitlements.clone();
    if !is_feature_entitled(&entitlements, FeatureName::WorkspaceProxy) {
        return Ok(require_enterprise_feature(&FeatureName::WorkspaceProxy));
    }

    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::WorkspaceProxy),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to read workspace proxies.",
        ));
    }

    let Some(row) = resolve_workspace_proxy(&state, &proxy_id_or_name).await? else {
        return Ok(not_found_response("Workspace proxy not found."));
    };

    Ok((StatusCode::OK, Json(proxy_row_to_response(&row))).into_response())
}

/// `PATCH /api/v2/workspaceproxies/{workspaceproxy}` — update a proxy.
pub(crate) async fn patch_workspace_proxy(
    State(state): State<AppState>,
    Path(proxy_id_or_name): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<PatchWorkspaceProxyRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // Enterprise gate
    let entitlements = state.entitlements.clone();
    if !is_feature_entitled(&entitlements, FeatureName::WorkspaceProxy) {
        return Ok(require_enterprise_feature(&FeatureName::WorkspaceProxy));
    }

    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::WorkspaceProxy),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update workspace proxies.",
        ));
    }

    let Some(existing) = resolve_workspace_proxy(&state, &proxy_id_or_name).await? else {
        return Ok(not_found_response("Workspace proxy not found."));
    };

    let Json(request) = match payload {
        Ok(r) => r,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    // Optionally regenerate the token.
    let (full_token, hashed_token) = if request.regenerate_token {
        let (tok, hashed) = generate_workspace_proxy_token(existing.id);
        (tok, Some(hashed))
    } else {
        (String::new(), None)
    };

    let name = if request.name.is_empty() {
        existing.name.clone()
    } else {
        request.name
    };
    let display_name = if request.display_name.is_empty() {
        existing.display_name.clone()
    } else {
        request.display_name
    };
    let icon = if request.icon.is_empty() {
        existing.icon.clone()
    } else {
        request.icon
    };

    let row = state
        .store
        .update_workspace_proxy(UpdateWorkspaceProxyInput {
            id: existing.id,
            name,
            display_name,
            icon,
            token_hashed: hashed_token,
            updated_at: OffsetDateTime::now_utc(),
        })
        .await?;

    Ok((
        StatusCode::OK,
        Json(UpdateWorkspaceProxyResponse {
            proxy: proxy_row_to_response(&row),
            proxy_token: full_token,
        }),
    )
        .into_response())
}

/// `DELETE /api/v2/workspaceproxies/{workspaceproxy}` — soft-delete a proxy.
pub(crate) async fn delete_workspace_proxy(
    State(state): State<AppState>,
    Path(proxy_id_or_name): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // Enterprise gate
    let entitlements = state.entitlements.clone();
    if !is_feature_entitled(&entitlements, FeatureName::WorkspaceProxy) {
        return Ok(require_enterprise_feature(&FeatureName::WorkspaceProxy));
    }

    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Delete,
            &Object::new(ResourceType::WorkspaceProxy),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to delete workspace proxies.",
        ));
    }

    let Some(existing) = resolve_workspace_proxy(&state, &proxy_id_or_name).await? else {
        return Ok(not_found_response("Workspace proxy not found."));
    };

    state.store.soft_delete_workspace_proxy(existing.id).await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

// ---------------------------------------------------------------------------
// Internal / Proxy-Auth Handlers
// ---------------------------------------------------------------------------

/// `POST /api/v2/workspaceproxies/me/register` — register or refresh a proxy.
///
/// In the Go reference this performs complex replica management and DERP mesh
/// setup. The Rust port provides a stub that validates the request and returns
/// a minimal response so the route exists and proxies can call it.
pub(crate) async fn workspace_proxy_register(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<RegisterWorkspaceProxyRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    // Enterprise gate
    let entitlements = state.entitlements.clone();
    if !is_feature_entitled(&entitlements, FeatureName::WorkspaceProxy) {
        return Ok(require_enterprise_feature(&FeatureName::WorkspaceProxy));
    }

    // Proxy auth: validate that a proxy token header is present.
    // Full proxy-token authentication is not yet wired; for now we just
    // check the header exists so the route shape is correct.
    let _proxy_token = match headers
        .get("Coder-Session-Token")
        .or_else(|| headers.get("coder-session-token"))
    {
        Some(v) => v.clone(),
        None => return Ok(unauthorized_response("Missing proxy authentication token.")),
    };

    let Json(request) = match payload {
        Ok(r) => r,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    // Validate required fields.
    if request.access_url.is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "URL is invalid.".to_string(),
                "access_url is required.",
            )),
        )
            .into_response());
    }

    if request.replica_id == Uuid::nil() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error("Replica ID is invalid.".to_string(), "")),
        )
            .into_response());
    }

    if request.derp_only && !request.derp_enabled {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "DerpOnly cannot be true when DerpEnabled is false.".to_string(),
                "",
            )),
        )
            .into_response());
    }

    // Return a minimal registration response (stub).
    Ok((
        StatusCode::CREATED,
        Json(RegisterWorkspaceProxyResponse {
            derp_mesh_key: String::new(),
            derp_region_id: 0,
            derp_force_websockets: false,
            sibling_replicas: Vec::new(),
        }),
    )
        .into_response())
}

/// `POST /api/v2/workspaceproxies/me/deregister` — deregister a proxy replica.
pub(crate) async fn workspace_proxy_deregister(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<DeregisterWorkspaceProxyRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    // Enterprise gate
    let entitlements = state.entitlements.clone();
    if !is_feature_entitled(&entitlements, FeatureName::WorkspaceProxy) {
        return Ok(require_enterprise_feature(&FeatureName::WorkspaceProxy));
    }

    let _proxy_token = match headers
        .get("Coder-Session-Token")
        .or_else(|| headers.get("coder-session-token"))
    {
        Some(v) => v.clone(),
        None => return Ok(unauthorized_response("Missing proxy authentication token.")),
    };

    let Json(request) = match payload {
        Ok(r) => r,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    if request.replica_id == Uuid::nil() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error("Replica ID is invalid.".to_string(), "")),
        )
            .into_response());
    }

    // Stub: in production this would update the replica table and publish
    // replicasync events. For now just acknowledge.
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `GET /api/v2/workspaceproxies/me/coordinate` — WebSocket endpoint for
/// proxy-to-coderd coordination (tailnet multi-agent).
///
/// This is a WebSocket upgrade endpoint. The full tailnet coordination
/// protocol is not yet implemented; the handler accepts the upgrade and
/// immediately closes the connection with a message.
pub(crate) async fn workspace_proxy_coordinate(
    State(state): State<AppState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
    // Enterprise gate
    let entitlements = state.entitlements.clone();
    if !is_feature_entitled(&entitlements, FeatureName::WorkspaceProxy) {
        return Ok(require_enterprise_feature(&FeatureName::WorkspaceProxy));
    }

    let _proxy_token = match headers
        .get("Coder-Session-Token")
        .or_else(|| headers.get("coder-session-token"))
    {
        Some(v) => v.clone(),
        None => return Ok(unauthorized_response("Missing proxy authentication token.")),
    };

    Ok(ws.on_upgrade(|mut socket| async move {
        // Stub: close immediately. Full tailnet coordination will be
        // implemented when the connectivity crate is complete.
        let close = CloseFrame {
            code: axum::extract::ws::close_code::NORMAL,
            reason: "coordinate stub — not yet implemented".into(),
        };
        let _ = socket.send(Message::Close(Some(close))).await;
    }))
}

/// `GET /api/v2/workspaceproxies/me/crypto-keys` — fetch signing keys.
pub(crate) async fn workspace_proxy_crypto_keys(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, AppError> {
    // Enterprise gate
    let entitlements = state.entitlements.clone();
    if !is_feature_entitled(&entitlements, FeatureName::WorkspaceProxy) {
        return Ok(require_enterprise_feature(&FeatureName::WorkspaceProxy));
    }

    let _proxy_token = match headers
        .get("Coder-Session-Token")
        .or_else(|| headers.get("coder-session-token"))
    {
        Some(v) => v.clone(),
        None => return Ok(unauthorized_response("Missing proxy authentication token.")),
    };

    let feature = params.get("feature").cloned().unwrap_or_default();
    if feature.is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "Missing feature query parameter.".to_string(),
                "",
            )),
        )
            .into_response());
    }

    // Allowed features (matches Go whitelistedCryptoKeyFeatures).
    let allowed = ["signing_key", "oidc_convert"];
    if !allowed.contains(&feature.as_str()) {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                format!("Invalid feature: \"{feature}\""),
                "",
            )),
        )
            .into_response());
    }

    // Stub: return an empty key set. Real implementation will query the
    // crypto_keys table once it is ported.
    Ok((
        StatusCode::OK,
        Json(CryptoKeysResponse {
            crypto_keys: Vec::new(),
        }),
    )
        .into_response())
}

/// `POST /api/v2/workspaceproxies/me/issue-signed-app-token` — issue a
/// signed app token on behalf of a user via the proxy.
pub(crate) async fn workspace_proxy_issue_signed_app_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<IssueSignedAppTokenRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    // Enterprise gate
    let entitlements = state.entitlements.clone();
    if !is_feature_entitled(&entitlements, FeatureName::WorkspaceProxy) {
        return Ok(require_enterprise_feature(&FeatureName::WorkspaceProxy));
    }

    let _proxy_token = match headers
        .get("Coder-Session-Token")
        .or_else(|| headers.get("coder-session-token"))
    {
        Some(v) => v.clone(),
        None => return Ok(unauthorized_response("Missing proxy authentication token.")),
    };

    let Json(_request) = match payload {
        Ok(r) => r,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    // Stub: the full token issuance flow requires the WorkspaceAppsProvider
    // which is not yet ported. Return a placeholder.
    Ok((
        StatusCode::CREATED,
        Json(IssueSignedAppTokenResponse {
            signed_token_str: String::new(),
        }),
    )
        .into_response())
}

/// `POST /api/v2/workspaceproxies/me/app-stats` — report app usage stats
/// from a workspace proxy.
pub(crate) async fn workspace_proxy_report_app_stats(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<ReportAppStatsRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    // Enterprise gate
    let entitlements = state.entitlements.clone();
    if !is_feature_entitled(&entitlements, FeatureName::WorkspaceProxy) {
        return Ok(require_enterprise_feature(&FeatureName::WorkspaceProxy));
    }

    let _proxy_token = match headers
        .get("Coder-Session-Token")
        .or_else(|| headers.get("coder-session-token"))
    {
        Some(v) => v.clone(),
        None => return Ok(unauthorized_response("Missing proxy authentication token.")),
    };

    let Json(_request) = match payload {
        Ok(r) => r,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    // Stub: in production this would forward stats to the stats reporter.
    Ok(StatusCode::NO_CONTENT.into_response())
}
