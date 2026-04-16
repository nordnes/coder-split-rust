//! Workspace proxy CRUD and internal handlers (enterprise — gated on
//! `WorkspaceProxy`).

use super::*;
use coder_core::api::{
    CreateWorkspaceProxyRequest, CryptoKeyResponse, CryptoKeysResponse,
    DeregisterWorkspaceProxyRequest, IssueSignedAppTokenRequest, IssueSignedAppTokenResponse,
    PatchWorkspaceProxyRequest, ProxyHealthReport, RegisterWorkspaceProxyRequest,
    RegisterWorkspaceProxyResponse, ReplicaResponse, ReportAppStatsRequest,
    UpdateWorkspaceProxyResponse, WorkspaceProxyResponse, WorkspaceProxyStatus,
};
use coder_core::ports::{
    CreateWorkspaceProxyInput, UpdateWorkspaceProxyInput, UpdateWorkspaceProxyRegistrationInput,
    UpsertReplicaInput, WorkspaceProxyRow,
};
use coder_license::FeatureName;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::handlers::licenses::{is_feature_entitled, require_enterprise_feature};
use crate::handlers::workspace_apps::{AppRequest, create_signed_app_token};

/// Hex-encodes a byte slice (lowercase).
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

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

/// Authenticates a proxy request by parsing the `Coder-Session-Token` header
/// as `<proxy_id>:<secret>`, looking up the proxy, and comparing the hashed
/// secret using constant-time comparison.
///
/// Returns the [`WorkspaceProxyRow`] on success, or an unauthorized response
/// on failure.
async fn authenticate_proxy_request(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Result<WorkspaceProxyRow, Response>, AppError> {
    let raw_token = headers
        .get("Coder-Session-Token")
        .or_else(|| headers.get("coder-session-token"))
        .and_then(|v| v.to_str().ok());

    let token_str = match raw_token {
        Some(s) if !s.is_empty() => s,
        _ => {
            return Ok(Err(unauthorized_response(
                "Missing proxy authentication token.",
            )));
        }
    };

    // Parse as "<proxy_id>:<secret>"
    let (id_str, secret) = match token_str.split_once(':') {
        Some(parts) => parts,
        None => {
            return Ok(Err(unauthorized_response(
                "Invalid proxy authentication token format.",
            )));
        }
    };

    let proxy_id = match Uuid::parse_str(id_str) {
        Ok(id) => id,
        Err(_) => {
            return Ok(Err(unauthorized_response(
                "Invalid proxy authentication token.",
            )));
        }
    };

    let proxy = match state.store.find_workspace_proxy_by_id(proxy_id).await? {
        Some(p) if !p.deleted => p,
        _ => {
            return Ok(Err(unauthorized_response(
                "Workspace proxy not found or deleted.",
            )));
        }
    };

    // Hash the provided secret and compare with the stored hash.
    let provided_hash = hash_proxy_secret(secret);
    if provided_hash.ct_eq(&proxy.token_hashed).into() {
        Ok(Ok(proxy))
    } else {
        Ok(Err(unauthorized_response(
            "Invalid proxy authentication token.",
        )))
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
        // The name "primary" is reserved — same guard as create.
        if request.name.eq_ignore_ascii_case("primary") {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error(
                    "Name \"primary\" is reserved.".to_string(),
                    "Cannot rename a workspace proxy to \"primary\".",
                )),
            )
                .into_response());
        }
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
/// Go reference: `coder/enterprise/coderd/workspaceproxy.go` →
/// `workspaceProxyRegister()`.
///
/// Called periodically (every ~30s) by each proxy replica to update its
/// registration and refresh the replica entry.
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

    // Authenticate proxy token.
    let proxy = match authenticate_proxy_request(&state, &headers).await? {
        Ok(p) => p,
        Err(resp) => return Ok(resp),
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

    let now = OffsetDateTime::now_utc();

    // 1. Update the proxy's registration fields.
    state
        .store
        .update_workspace_proxy_registration(UpdateWorkspaceProxyRegistrationInput {
            id: proxy.id,
            url: request.access_url,
            wildcard_hostname: request.wildcard_hostname,
            derp_enabled: request.derp_enabled,
            derp_only: request.derp_only,
            version: request.version.clone(),
            updated_at: now,
        })
        .await?;

    // Compute the effective region_id for this proxy's replicas.
    let region_id = proxy.region_id;

    // 2. Upsert the replica record.
    state
        .store
        .upsert_replica(UpsertReplicaInput {
            id: request.replica_id,
            proxy_id: proxy.id,
            hostname: request.hostname,
            relay_address: request.replica_relay_address,
            region_id,
            version: request.version,
            error: request.replica_error,
            database_latency: 0,
            started_at: now,
            updated_at: now,
        })
        .await?;

    // 3. Query sibling replicas (same proxy, excluding current).
    let siblings = state
        .store
        .list_replicas_by_proxy_excluding(proxy.id, request.replica_id)
        .await?;

    let sibling_responses: Vec<ReplicaResponse> = siblings
        .iter()
        .map(|r| ReplicaResponse {
            id: r.id,
            hostname: r.hostname.clone(),
            created_at: r.created_at,
            relay_address: r.relay_address.clone(),
            region_id: r.region_id,
            error: r.error.clone(),
            database_latency: r.database_latency,
        })
        .collect();

    // 4. Build the DERP mesh key. In Go this comes from the DB
    // (`GetDERPMeshKey`). For now, use the hex-encoded app_signing_key.
    let derp_mesh_key = if request.derp_enabled {
        hex_encode(&state.app_signing_key)
    } else {
        String::new()
    };

    Ok((
        StatusCode::CREATED,
        Json(RegisterWorkspaceProxyResponse {
            derp_mesh_key,
            derp_region_id: region_id,
            derp_force_websockets: false,
            sibling_replicas: sibling_responses,
        }),
    )
        .into_response())
}

/// `POST /api/v2/workspaceproxies/me/deregister` — deregister a proxy replica.
///
/// Go reference: `coder/enterprise/coderd/workspaceproxy.go` →
/// `workspaceProxyDeregister()`.
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

    // Authenticate proxy token.
    let _proxy = match authenticate_proxy_request(&state, &headers).await? {
        Ok(p) => p,
        Err(resp) => return Ok(resp),
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

    // Delete the replica record.
    state.store.delete_replica(request.replica_id).await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `GET /api/v2/workspaceproxies/me/coordinate` — WebSocket endpoint for
/// proxy-to-coderd coordination (tailnet multi-agent).
///
/// Go reference: `coder/enterprise/coderd/workspaceproxycoordinate.go` →
/// `workspaceProxyCoordinate()`.
///
/// Keeps the WebSocket alive with ping/pong and logs received messages.
/// Full tailnet coordination will be implemented when the connectivity
/// crate supports multi-agent proxy coordination.
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

    // Authenticate proxy token.
    let _proxy = match authenticate_proxy_request(&state, &headers).await? {
        Ok(p) => p,
        Err(resp) => return Ok(resp),
    };

    Ok(ws.on_upgrade(|mut socket| async move {
        // Minimal coordinate loop: keep alive with ping/pong, log messages.
        loop {
            match socket.recv().await {
                Some(Ok(Message::Ping(data))) => {
                    if socket.send(Message::Pong(data)).await.is_err() {
                        break;
                    }
                }
                Some(Ok(Message::Close(_))) | None => {
                    break;
                }
                Some(Ok(msg)) => {
                    tracing::debug!("proxy coordinate received: {msg:?}");
                }
                Some(Err(_)) => {
                    break;
                }
            }
        }
        let close = CloseFrame {
            code: axum::extract::ws::close_code::NORMAL,
            reason: "coordinate session ended".into(),
        };
        let _ = socket.send(Message::Close(Some(close))).await;
    }))
}

/// `GET /api/v2/workspaceproxies/me/crypto-keys` — fetch signing keys.
///
/// Go reference: `coder/enterprise/coderd/workspaceproxy.go` →
/// `workspaceProxyCryptoKeys()`.
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

    // Authenticate proxy token.
    let _proxy = match authenticate_proxy_request(&state, &headers).await? {
        Ok(p) => p,
        Err(resp) => return Ok(resp),
    };

    let feature_str = params.get("feature").cloned().unwrap_or_default();
    if feature_str.is_empty() {
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
    let allowed = ["workspace_apps_token", "workspace_apps_api_key"];
    if !allowed.contains(&feature_str.as_str()) {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                format!("Invalid feature: \"{feature_str}\""),
                "",
            )),
        )
            .into_response());
    }

    let feature = match coder_core::enums::CryptoKeyFeature::from_str(&feature_str) {
        Ok(f) => f,
        Err(_) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error(
                    format!("Invalid feature: \"{feature_str}\""),
                    "",
                )),
            )
                .into_response());
        }
    };

    // Query active keys for the feature.
    let mut keys = state.store.list_crypto_keys_by_feature(feature).await?;

    // If no keys exist, auto-generate one (lazy creation, matches Go behavior).
    if keys.is_empty() {
        let mut secret = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret);
        let new_key = coder_core::CryptoKeyRow {
            feature,
            sequence: 1,
            secret,
            starts_at: OffsetDateTime::now_utc(),
            deletes_at: None,
        };
        let inserted = state.store.insert_crypto_key(new_key).await?;
        keys.push(inserted);
    }

    let crypto_keys: Vec<CryptoKeyResponse> = keys
        .iter()
        .map(|k| CryptoKeyResponse {
            feature: k.feature.as_str().to_owned(),
            secret: hex_encode(&k.secret),
            sequence: k.sequence,
            starts_at: k.starts_at,
            deletes_at: k.deletes_at,
        })
        .collect();

    Ok((StatusCode::OK, Json(CryptoKeysResponse { crypto_keys })).into_response())
}

/// `POST /api/v2/workspaceproxies/me/issue-signed-app-token` — issue a
/// signed app token on behalf of a user via the proxy.
///
/// Go reference: `coder/enterprise/coderd/workspaceproxy.go` →
/// `issueSignedAppTokenFromProxy()`.
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

    // Authenticate proxy token.
    let _proxy = match authenticate_proxy_request(&state, &headers).await? {
        Ok(p) => p,
        Err(resp) => return Ok(resp),
    };

    let Json(request) = match payload {
        Ok(r) => r,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    // Validate the session token from the request body: look up the user.
    if request.session_token.is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error("Missing session_token.".to_string(), "")),
        )
            .into_response());
    }

    // Build a temporary HeaderMap with the user's session token so we can
    // authenticate them via the existing helper.
    let mut user_headers = HeaderMap::new();
    if let Ok(hv) = HeaderValue::from_str(&request.session_token) {
        user_headers.insert("Coder-Session-Token", hv);
    } else {
        return Ok(unauthorized_response("Invalid session token."));
    }

    let Some(user_context) = authenticate_request(&state, &user_headers).await? else {
        return Ok(unauthorized_response("Invalid or expired session token."));
    };

    // Parse the app request from the JSON value.
    let app_request: AppRequest = match serde_json::from_value(request.app_request) {
        Ok(r) => r,
        Err(e) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error(format!("Invalid app_request: {e}"), "")),
            )
                .into_response());
        }
    };

    // Create the signed app token.
    let signed_token = match create_signed_app_token(
        &state.app_signing_key,
        &app_request,
        user_context.actor.user_id,
    ) {
        Ok(token) => token,
        Err(e) => {
            return Ok((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error(
                    format!("Failed to create signed app token: {e}"),
                    "",
                )),
            )
                .into_response());
        }
    };

    Ok((
        StatusCode::CREATED,
        Json(IssueSignedAppTokenResponse {
            signed_token_str: signed_token,
        }),
    )
        .into_response())
}

/// `POST /api/v2/workspaceproxies/me/app-stats` — report app usage stats
/// from a workspace proxy.
///
/// Go reference: `coder/enterprise/coderd/workspaceproxy.go` →
/// `workspaceProxyReportAppStats()`.
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

    // Authenticate proxy token.
    let _proxy = match authenticate_proxy_request(&state, &headers).await? {
        Ok(p) => p,
        Err(resp) => return Ok(resp),
    };

    let Json(request) = match payload {
        Ok(r) => r,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    // Insert stats into the database.
    if !request.stats.is_empty() {
        state
            .store
            .insert_workspace_app_stats(&request.stats)
            .await?;
    }

    Ok(StatusCode::NO_CONTENT.into_response())
}
