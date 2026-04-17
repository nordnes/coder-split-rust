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

    // 4. Build the DERP mesh key. Mirrors Go's `GetDERPMeshKey` lookup in
    // `coder/enterprise/coderd/workspaceproxy.go` (~L612). The mesh key lives
    // in `site_configs` under the `derp_mesh_key` row and is lazily
    // provisioned the first time a proxy with DERP enabled registers, so
    // existing deployments migrate seamlessly.
    let derp_mesh_key = if request.derp_enabled {
        let existing = state.store.get_derp_mesh_key().await?;
        match existing {
            Some(v) if !v.is_empty() => v,
            _ => {
                let mut buf = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut buf);
                let encoded = hex_encode(&buf);
                // Best-effort insert; if a concurrent registration won the
                // race, re-read the stored value instead of returning ours.
                state.store.insert_derp_mesh_key(&encoded).await?;
                state.store.get_derp_mesh_key().await?.unwrap_or(encoded)
            }
        }
    } else {
        String::new()
    };

    Ok((
        StatusCode::CREATED,
        Json(RegisterWorkspaceProxyResponse {
            derp_mesh_key,
            derp_region_id: region_id,
            derp_force_websockets: state.config.derp_force_websockets,
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

    // Publish a replica-sync event so every other replica (and this one)
    // refreshes its replicas list. Mirrors Go's
    // `api.Pubsub.Publish(replicasync.PubsubEvent, []byte(uuid.Nil.String()))`
    // in `coder/enterprise/coderd/workspaceproxy.go` (~L847). We log but do
    // not fail the request if the publish fails — the replica row is already
    // gone and siblings will reconcile on their next register tick.
    let payload = Uuid::nil().to_string().into_bytes();
    if let Err(error) = state
        .pubsub
        .publish(coder_core::pubsub::REPLICA_EVENTS_CHANNEL, &payload)
        .await
    {
        tracing::warn!(
            %error,
            replica_id = %request.replica_id,
            "failed to publish replica-sync event"
        );
    }

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `GET /api/v2/workspaceproxies/me/coordinate` — WebSocket endpoint for
/// proxy-to-coderd coordination (tailnet multi-agent).
///
/// Go reference: `coder/enterprise/coderd/workspaceproxycoordinate.go` →
/// `workspaceProxyCoordinate()`.
///
/// Registers the proxy as a `Client`-kind peer in the in-memory
/// [`TailnetCoordinator`](coder_connectivity::tailnet::TailnetCoordinator)
/// and multiplexes the JSON coordinate protocol over the WebSocket:
///
/// - The initial frame is a `{ "derp_map": ... }` envelope so the proxy has
///   relay information immediately (mirrors the agent coordinate handler and
///   what the Go `tailnetService` does on attach).
/// - Inbound JSON frames are parsed as
///   [`CoordinateRequest`](coder_connectivity::tailnet::CoordinateRequest)
///   and fed to the coordinator, which fans out peer updates to tunnel
///   targets.
/// - Outbound coordinator responses are serialised as JSON and written back
///   to the socket.
/// - DERP map changes (published via the coordinator's `watch::Receiver`)
///   are forwarded as `{ "derp_map": ... }` envelopes so the proxy stays in
///   sync when relay topology changes.
///
/// The handler honours the `?version=` query parameter used by the Go
/// reference to distinguish the JSON-over-WebSocket protocol (`1.x`) from
/// the binary dRPC protocol (`2.x+`). Because the Rust tailnet coordinator
/// does not yet speak dRPC/protobuf, any major version ≥ 2 is rejected with
/// 400 before the upgrade. Missing/empty defaults to `1.0`.
///
/// # Remaining gaps vs. Go
///
/// * **Multi-agent fan-out.** In Go, `ServeMultiAgentClient` gives the proxy
///   a single RPC channel that multiplexes many end-user client sessions.
///   Each `CoordinateRequest` carries a per-client peer ID. The Rust JSON
///   protocol treats the proxy as a single peer; per-client multiplexing
///   will come in with the DRPC port (gap §6).
/// * **DRPC / protobuf wire compatibility.** Real Go proxies will dial
///   `?version=2.x` and speak binary DRPC; this handler rejects those
///   connections until the connectivity crate grows DRPC support.
pub(crate) async fn workspace_proxy_coordinate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
    ws: WebSocketUpgrade,
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

    // Validate the requested API version. The Go reference parses
    // `?version=` (default "1.0") against `proto.CurrentVersion` and upgrades
    // to binary dRPC framing for major >= 2. We only speak JSON (v1.x); any
    // other major is rejected before the upgrade so the proxy fails fast and
    // can fall back to v1 negotiation.
    let version = params
        .get("version")
        .map(String::as_str)
        .filter(|v| !v.is_empty())
        .unwrap_or("1.0");
    let (major, minor) = match parse_api_version(version) {
        Ok(v) => v,
        Err(detail) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    message: "Unknown or unsupported API version".to_string(),
                    detail: None,
                    validations: vec![ValidationError {
                        field: "version".to_string(),
                        detail,
                    }],
                }),
            )
                .into_response());
        }
    };
    if major != 1 {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                message: "Unknown or unsupported API version".to_string(),
                detail: None,
                validations: vec![ValidationError {
                    field: "version".to_string(),
                    detail: format!(
                        "version {major}.{minor} is not supported by this \
                         coderd build; only major version 1 (JSON over \
                         WebSocket) is implemented"
                    ),
                }],
            }),
        )
            .into_response());
    }

    let coordinator = state.coordinator.clone();
    let proxy_name = proxy.name.clone();
    let session_id = Uuid::new_v4();

    Ok(ws.on_upgrade(move |socket| async move {
        run_workspace_proxy_coordinate(socket, coordinator, session_id, proxy_name).await;
    }))
}

/// Parses a `major.minor` version string, matching the semantics of the Go
/// `apiversion.Parse` helper. Returns a human-readable error message on
/// failure.
fn parse_api_version(version: &str) -> Result<(u32, u32), String> {
    let (maj, min) = version
        .split_once('.')
        .ok_or_else(|| format!("invalid version string: {version:?}; expected \"major.minor\""))?;
    let major: u32 = maj
        .parse()
        .map_err(|_| format!("invalid major version: {maj:?}"))?;
    let minor: u32 = min
        .parse()
        .map_err(|_| format!("invalid minor version: {min:?}"))?;
    Ok((major, minor))
}

/// Drives a single proxy coordinate WebSocket session.
///
/// Factored out of [`workspace_proxy_coordinate`] so it can be unit-tested
/// directly without spinning up an HTTP server.
async fn run_workspace_proxy_coordinate(
    mut socket: WebSocket,
    coordinator: Arc<dyn coder_connectivity::tailnet::TailnetCoordinator>,
    session_id: Uuid,
    proxy_name: String,
) {
    use coder_connectivity::tailnet::{CoordinateRequest, CoordinateResponse, PeerKind};

    // Watch DERP map updates so changes propagate to the proxy without it
    // having to poll `/derp-map`.
    let mut derp_rx = coordinator.subscribe_derp_map();
    let initial_derp = derp_rx.borrow_and_update().clone();
    let derp_envelope = serde_json::json!({ "derp_map": initial_derp });
    if let Ok(payload) = serde_json::to_string(&derp_envelope) {
        if socket.send(Message::Text(payload.into())).await.is_err() {
            return;
        }
    }

    // Register the proxy as a Client peer. The Go multi-agent model would
    // assign each end-user client its own peer ID, but the Rust JSON path
    // treats the proxy as a single peer until DRPC lands.
    let mut handle = coordinator.coordinate(session_id, proxy_name.clone(), PeerKind::Client);

    loop {
        tokio::select! {
            // --- Inbound WebSocket frame ---
            ws_msg = socket.recv() => {
                match ws_msg {
                    Some(Ok(Message::Text(text))) => {
                        match serde_json::from_str::<CoordinateRequest>(&text) {
                            Ok(request) => {
                                if let Err(error) =
                                    coordinator.process_request(session_id, request)
                                {
                                    tracing::warn!(
                                        %error,
                                        session_id = %session_id,
                                        proxy = %proxy_name,
                                        "workspace proxy coordinate request error",
                                    );
                                }
                            }
                            Err(error) => {
                                tracing::debug!(
                                    %error,
                                    session_id = %session_id,
                                    proxy = %proxy_name,
                                    "invalid workspace proxy coordinate JSON",
                                );
                                let err_resp = CoordinateResponse {
                                    peer_updates: Vec::new(),
                                    error: Some(format!("invalid request: {error}")),
                                };
                                if let Ok(payload) = serde_json::to_string(&err_resp) {
                                    if socket
                                        .send(Message::Text(payload.into()))
                                        .await
                                        .is_err()
                                    {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    Some(Ok(Message::Binary(bin))) => {
                        match serde_json::from_slice::<CoordinateRequest>(&bin) {
                            Ok(request) => {
                                if let Err(error) =
                                    coordinator.process_request(session_id, request)
                                {
                                    tracing::warn!(
                                        %error,
                                        session_id = %session_id,
                                        proxy = %proxy_name,
                                        "workspace proxy coordinate request error (binary)",
                                    );
                                }
                            }
                            Err(error) => {
                                tracing::debug!(
                                    %error,
                                    session_id = %session_id,
                                    proxy = %proxy_name,
                                    "invalid workspace proxy coordinate binary JSON",
                                );
                                let err_resp = CoordinateResponse {
                                    peer_updates: Vec::new(),
                                    error: Some(format!("invalid request: {error}")),
                                };
                                if let Ok(payload) = serde_json::to_string(&err_resp) {
                                    if socket
                                        .send(Message::Text(payload.into()))
                                        .await
                                        .is_err()
                                    {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    Some(Ok(Message::Ping(data))) => {
                        if socket.send(Message::Pong(data)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(_)) => break,
                }
            }
            // --- Outbound coordination response ---
            resp = handle.response_rx.recv() => {
                match resp {
                    Some(coord_response) => {
                        if let Ok(payload) = serde_json::to_string(&coord_response) {
                            if socket.send(Message::Text(payload.into())).await.is_err() {
                                break;
                            }
                        }
                    }
                    None => break,
                }
            }
            // --- DERP map change ---
            derp_changed = derp_rx.changed() => {
                if derp_changed.is_err() {
                    // Coordinator shut down — close the session.
                    break;
                }
                let updated = derp_rx.borrow_and_update().clone();
                let envelope = serde_json::json!({ "derp_map": updated });
                if let Ok(payload) = serde_json::to_string(&envelope) {
                    if socket.send(Message::Text(payload.into())).await.is_err() {
                        break;
                    }
                }
            }
        }
    }

    coordinator.close_coordination(session_id, handle.session_id);

    let close = CloseFrame {
        code: axum::extract::ws::close_code::NORMAL,
        reason: "coordinate session ended".into(),
    };
    let _ = socket.send(Message::Close(Some(close))).await;
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
    // Use the rotator's per-feature secret length so the lazy and the
    // background-rotated paths produce identically-sized keys — otherwise a
    // deployment that hits `/crypto-keys` before the rotator's initial sweep
    // lands would serve a 32-byte `WorkspaceAppsToken` / `OidcConvert` /
    // `TailnetResume` secret where Go's `generateNewSecret` emits 64 bytes.
    if keys.is_empty() {
        let mut secret = vec![0u8; crate::crypto_key_rotator::secret_byte_length(feature)];
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod coordinate_tests {
    //! Tests for [`workspace_proxy_coordinate`].
    //!
    //! These exercise the bridge between the proxy WebSocket and the
    //! [`coder_connectivity::tailnet::TailnetCoordinator`]: version
    //! negotiation, initial DERP map delivery, peer-update forwarding, and
    //! disconnect cleanup.

    use super::*;
    use crate::app::build_router;
    use crate::app::tests::{
        FakeStore, authenticated_json_request, call, create_and_login, response_json,
        test_state_with_store,
    };
    use axum::Router;
    use axum::http::Method;
    use coder_connectivity::tailnet::{CoordinateRequest, NodeInfo, PeerKind};
    use coder_license::FeatureName;
    use futures_util::{SinkExt, StreamExt};
    use serde_json::Value;
    use std::error::Error;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio_tungstenite::tungstenite;

    type TestResult = Result<(), Box<dyn Error>>;

    async fn spawn_test_server(
        router: Router,
    ) -> Result<(url::Url, tokio::task::JoinHandle<()>), Box<dyn Error>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, router.into_make_service()).await;
        });
        Ok((url::Url::parse(&format!("http://{address}"))?, handle))
    }

    fn ws_url(base: &url::Url, path: &str) -> String {
        let mut url = base.clone();
        let _ = url.set_scheme("ws");
        format!("{url}{path}")
    }

    fn ws_request(url: &str, proxy_token: &str) -> Result<http::Request<()>, Box<dyn Error>> {
        let parsed = url::Url::parse(url)?;
        let host = match parsed.port() {
            Some(port) => format!("{}:{}", parsed.host_str().unwrap_or("127.0.0.1"), port),
            None => parsed.host_str().unwrap_or("127.0.0.1").to_owned(),
        };
        let request = http::Request::builder()
            .uri(url)
            .header("Host", &host)
            .header("Coder-Session-Token", proxy_token)
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header(
                "Sec-WebSocket-Key",
                tungstenite::handshake::client::generate_key(),
            )
            .body(())?;
        Ok(request)
    }

    /// Builds a state with the WorkspaceProxy entitlement applied so the
    /// coordinate endpoint is enabled.
    fn entitled_state() -> Result<(AppState, Arc<FakeStore>), Box<dyn Error>> {
        let (state, store) = test_state_with_store(true)?;
        let mut ent = coder_license::Entitlements::new_unlicensed();
        ent.features.insert(
            FeatureName::WorkspaceProxy.as_str().to_owned(),
            coder_license::Feature {
                entitlement: coder_license::Entitlement::Entitled,
                enabled: true,
                limit: None,
                actual: None,
            },
        );
        state.entitlements.update(ent);
        Ok((state, store))
    }

    /// Creates an admin session + a workspace proxy and returns the proxy
    /// token so the test can authenticate as the proxy on
    /// `/workspaceproxies/me/coordinate`.
    async fn create_proxy(app: &Router, name: &str) -> Result<String, Box<dyn Error>> {
        let session_token = create_and_login(app).await?;
        let create_resp = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                "/api/v2/workspaceproxies",
                &session_token,
                &serde_json::json!({
                    "name": name,
                    "display_name": name,
                    "icon": "",
                }),
            )?,
        )
        .await?;
        assert_eq!(create_resp.status(), StatusCode::CREATED);
        let body = response_json(create_resp).await?;
        let proxy_token = body
            .get("proxy_token")
            .and_then(Value::as_str)
            .ok_or("missing proxy_token in create response")?
            .to_owned();
        Ok(proxy_token)
    }

    /// Unauthenticated clients cannot upgrade to the coordinate WebSocket.
    #[tokio::test]
    async fn coordinate_rejects_missing_proxy_token() -> TestResult {
        let (state, _store) = entitled_state()?;
        let app = build_router(state, None);
        let (base_url, _handle) = spawn_test_server(app).await?;

        // No Coder-Session-Token header: the server should reject the
        // upgrade with a 4xx before any WebSocket frames are exchanged.
        let url = ws_url(&base_url, "api/v2/workspaceproxies/me/coordinate");
        let request = http::Request::builder()
            .uri(&url)
            .header("Host", base_url.host_str().unwrap_or("127.0.0.1"))
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header(
                "Sec-WebSocket-Key",
                tungstenite::handshake::client::generate_key(),
            )
            .body(())?;
        let result = tokio_tungstenite::connect_async(request).await;
        assert!(result.is_err(), "should reject unauthenticated coordinate");
        Ok(())
    }

    /// An authenticated proxy receives the initial DERP-map envelope on
    /// connect, before any other frames.
    #[tokio::test]
    async fn coordinate_sends_initial_derp_map() -> TestResult {
        let (state, _store) = entitled_state()?;
        let app = build_router(state, None);
        let (base_url, _handle) = spawn_test_server(app.clone()).await?;

        let proxy_token = create_proxy(&app, "proxy-derp").await?;
        let url = ws_url(&base_url, "api/v2/workspaceproxies/me/coordinate");
        let request = ws_request(&url, &proxy_token)?;
        let (mut ws, _resp) = tokio_tungstenite::connect_async(request).await?;

        let msg = tokio::time::timeout(Duration::from_secs(2), ws.next()).await?;
        let Some(Ok(tungstenite::Message::Text(text))) = msg else {
            return Err(format!("expected text DERP map frame, got: {msg:?}").into());
        };
        let parsed: Value = serde_json::from_str(&text)?;
        assert!(
            parsed.get("derp_map").is_some(),
            "initial frame must carry derp_map, got: {parsed}"
        );

        ws.close(None).await?;
        Ok(())
    }

    /// Helper: perform a full WebSocket upgrade against a spawned server and
    /// return the HTTP response body + status for the failure path. Returns
    /// `Err` if the handshake actually succeeds.
    async fn ws_connect_expecting_failure(
        url: &str,
        proxy_token: &str,
    ) -> Result<(StatusCode, Value), Box<dyn Error>> {
        let request = ws_request(url, proxy_token)?;
        match tokio_tungstenite::connect_async(request).await {
            Ok(_) => Err("expected handshake to fail but it succeeded".into()),
            Err(tungstenite::Error::Http(resp)) => {
                let status = resp.status();
                let body = resp.body().as_deref().unwrap_or(&[]);
                let parsed: Value = if body.is_empty() {
                    Value::Null
                } else {
                    serde_json::from_slice(body).unwrap_or(Value::Null)
                };
                Ok((status, parsed))
            }
            Err(other) => Err(format!("unexpected ws error: {other:?}").into()),
        }
    }

    /// Version 2+ is the binary dRPC protocol which Rust does not yet speak;
    /// the server must reject it with HTTP 400 and a `version` validation
    /// error before the WebSocket upgrade.
    #[tokio::test]
    async fn coordinate_rejects_unsupported_api_version() -> TestResult {
        let (state, _store) = entitled_state()?;
        let app = build_router(state, None);
        let (base_url, _handle) = spawn_test_server(app.clone()).await?;

        let proxy_token = create_proxy(&app, "proxy-v2").await?;
        let url = ws_url(
            &base_url,
            "api/v2/workspaceproxies/me/coordinate?version=2.0",
        );
        let (status, body) = ws_connect_expecting_failure(&url, &proxy_token).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let validations = body
            .get("validations")
            .and_then(Value::as_array)
            .ok_or("expected validations array in 400 response")?;
        assert!(
            validations
                .iter()
                .any(|v| v.get("field").and_then(Value::as_str) == Some("version")),
            "validations must include a version field error: {body}"
        );
        Ok(())
    }

    /// A malformed `?version=abc` string is rejected with the same 400 +
    /// validations shape.
    #[tokio::test]
    async fn coordinate_rejects_malformed_version() -> TestResult {
        let (state, _store) = entitled_state()?;
        let app = build_router(state, None);
        let (base_url, _handle) = spawn_test_server(app.clone()).await?;

        let proxy_token = create_proxy(&app, "proxy-bad-ver").await?;
        let url = ws_url(
            &base_url,
            "api/v2/workspaceproxies/me/coordinate?version=abc",
        );
        let (status, _body) = ws_connect_expecting_failure(&url, &proxy_token).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        Ok(())
    }

    /// Peer node updates pushed by a second peer (e.g. an agent) connected
    /// to the same coordinator must be forwarded down the proxy WebSocket.
    #[tokio::test]
    async fn coordinate_forwards_peer_updates() -> TestResult {
        let (state, _store) = entitled_state()?;
        let coordinator = state.coordinator.clone();
        let app = build_router(state, None);
        let (base_url, _handle) = spawn_test_server(app.clone()).await?;

        let proxy_token = create_proxy(&app, "proxy-peers").await?;
        let url = ws_url(&base_url, "api/v2/workspaceproxies/me/coordinate");
        let request = ws_request(&url, &proxy_token)?;
        let (mut ws, _resp) = tokio_tungstenite::connect_async(request).await?;

        // Skip the initial DERP-map envelope.
        let _ = tokio::time::timeout(Duration::from_secs(2), ws.next()).await?;

        // The proxy opens a tunnel to a remote agent, then the agent
        // publishes a node update; the coordinator should push a
        // peer_updates response down the proxy socket.
        let agent_id = Uuid::new_v4();
        let agent_handle =
            coordinator.coordinate(agent_id, "target-agent".to_owned(), PeerKind::Agent);

        // Find the proxy's session_id by asking the first peer update;
        // first we need the proxy to subscribe via `add_tunnel` → this
        // requires knowing the session_id assigned to the proxy. The
        // handler generates it internally, so instead we drive this from
        // the agent side: the agent opens a tunnel to the proxy session.
        // But again, the proxy session id isn't exposed.
        //
        // Approach: update node on the agent and have the proxy add a
        // tunnel to the agent; the coordinator will then notify the proxy
        // of the agent's node info.
        let add_tunnel = CoordinateRequest {
            add_tunnel: Some(agent_id),
            ..Default::default()
        };
        let text = serde_json::to_string(&add_tunnel)?;
        ws.send(tungstenite::Message::Text(text.into())).await?;

        // Now publish an agent node update.
        let node_update = CoordinateRequest {
            update_self: Some(NodeInfo {
                id: 42,
                preferred_derp: 1,
                ..Default::default()
            }),
            ..Default::default()
        };
        coordinator.process_request(agent_id, node_update)?;

        // Expect a coordinate response with non-empty peer_updates within
        // a short timeout.
        let mut saw_node = false;
        for _ in 0..5 {
            let msg = tokio::time::timeout(Duration::from_secs(2), ws.next()).await?;
            let Some(Ok(tungstenite::Message::Text(text))) = msg else {
                continue;
            };
            let parsed: Value = serde_json::from_str(&text)?;
            if let Some(updates) = parsed.get("peer_updates").and_then(Value::as_array) {
                if updates
                    .iter()
                    .any(|u| u.get("kind").and_then(Value::as_str) == Some("node"))
                {
                    saw_node = true;
                    break;
                }
            }
        }
        assert!(
            saw_node,
            "expected a Node peer update to be forwarded to the proxy"
        );

        drop(agent_handle);
        ws.close(None).await?;
        Ok(())
    }

    /// Closing the WebSocket must release the coordinator session so the
    /// mesh doesn't leak state.
    #[tokio::test]
    async fn coordinate_cleans_up_on_disconnect() -> TestResult {
        let (state, _store) = entitled_state()?;
        let coordinator = state.coordinator.clone();
        let app = build_router(state, None);
        let (base_url, _handle) = spawn_test_server(app.clone()).await?;

        let before = coordinator
            .debug_json()
            .get("total_peers")
            .and_then(Value::as_u64)
            .unwrap_or(0);

        let proxy_token = create_proxy(&app, "proxy-cleanup").await?;
        let url = ws_url(&base_url, "api/v2/workspaceproxies/me/coordinate");
        let request = ws_request(&url, &proxy_token)?;
        let (mut ws, _resp) = tokio_tungstenite::connect_async(request).await?;

        // Consume the DERP-map envelope so we know the session is live.
        let _ = tokio::time::timeout(Duration::from_secs(2), ws.next()).await;

        let during = coordinator
            .debug_json()
            .get("total_peers")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        assert!(
            during > before,
            "coordinator must register the proxy while connected \
             (before={before}, during={during})"
        );

        ws.close(None).await?;

        // Give the server a beat to run the cleanup branch.
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let now = coordinator
                .debug_json()
                .get("total_peers")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            if now <= before {
                return Ok(());
            }
        }
        let final_count = coordinator
            .debug_json()
            .get("total_peers")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        Err(format!(
            "coordinator did not release the proxy session on disconnect \
             (before={before}, final={final_count})"
        )
        .into())
    }

    /// `parse_api_version` mirrors Go's `apiversion.Parse`.
    #[test]
    fn parse_api_version_accepts_major_minor() {
        assert_eq!(parse_api_version("1.0"), Ok((1, 0)));
        assert_eq!(parse_api_version("1.3"), Ok((1, 3)));
        assert_eq!(parse_api_version("2.8"), Ok((2, 8)));
    }

    #[test]
    fn parse_api_version_rejects_garbage() {
        assert!(parse_api_version("").is_err());
        assert!(parse_api_version("1").is_err());
        assert!(parse_api_version("x.y").is_err());
        assert!(parse_api_version("1.x").is_err());
        assert!(parse_api_version("1.0.0").is_err());
    }
}
