//! Build info, deployment config, stats, SSH config, experiments, debug, and region handlers.

use super::*;

pub(crate) async fn build_info(
    State(state): State<AppState>,
) -> Json<coder_core::BuildInfoResponse> {
    Json(state.build_metadata.to_response(
        state.deployment_id,
        &state.config.access_url,
        &state.config.telemetry,
    ))
}

pub(crate) async fn deployment_config(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can read deployment configuration (matches Go's
    // `api.Authorize(r, policy.ActionRead, rbac.ResourceDeploymentConfig)`).
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::DeploymentConfig),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to view deployment configuration.",
        ));
    }

    Ok((
        StatusCode::OK,
        Json(DeploymentConfigResponse {
            config: state.config.public(),
            options: ServerConfig::supported_options(),
        }),
    )
        .into_response())
}

pub(crate) async fn update_check(State(state): State<AppState>) -> Json<UpdateCheckResponse> {
    Json(UpdateCheckResponse {
        current: true,
        version: state.build_metadata.version.clone(),
        url: state.build_metadata.external_url.clone(),
    })
}

pub(crate) async fn get_init_script(
    State(state): State<AppState>,
    Path((os, arch)): Path<(String, String)>,
) -> Response {
    let script = match render_init_script(&os, &arch, state.config.access_url.as_str()) {
        Ok(script) => script,
        Err(InitScriptError::UnknownTarget { os, arch }) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error(
                    format!("Unknown os/arch: {os}/{arch}"),
                    "The requested os/arch combination is not supported.",
                )),
            )
                .into_response();
        }
    };

    let mut response = (StatusCode::OK, script.body).into_response();
    response.headers_mut().insert(
        HeaderName::from_static("content-digest"),
        HeaderValue::from_str(&script.content_digest)
            .unwrap_or_else(|_| HeaderValue::from_static("sha256:")),
    );
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

pub(crate) async fn deployment_stats(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !can_view_operational_data(&context.actor) {
        return Ok(forbidden_response(
            "You are not authorized to view deployment stats.",
        ));
    }

    Ok((StatusCode::OK, Json(state.deployment_stats.get().await?)).into_response())
}

pub(crate) async fn deployment_ssh(State(state): State<AppState>) -> Json<SshConfigResponse> {
    Json(SshConfigResponse {
        hostname_prefix: state.config.ssh.hostname_prefix.clone(),
        hostname_suffix: state.config.ssh.hostname_suffix.clone(),
        ssh_config_options: state.config.ssh.ssh_config_options.clone(),
    })
}

pub(crate) async fn get_enabled_experiments(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    Ok(Json(Vec::<String>::new()).into_response())
}

pub(crate) async fn get_available_experiments(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    Ok(Json(AvailableExperiments { safe: Vec::new() }).into_response())
}

pub(crate) async fn list_provisioner_daemons(
    State(state): State<AppState>,
    Path(organization): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    // Validate the organization exists and the caller has access.
    let org = match state
        .identity
        .get_organization(&context.actor, &organization)
        .await
    {
        Ok(o) => o,
        Err(error) => return handle_identity_error(error),
    };

    // RBAC: verify the actor can read provisioner daemons in this org.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::ProvisionerDaemon).in_org(org.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to view provisioner daemons.",
        ));
    }

    let empty: Vec<coder_core::ProvisionerDaemonResponse> = Vec::new();
    Ok((StatusCode::OK, Json(empty)).into_response())
}

pub(crate) async fn list_provisioner_jobs(
    State(state): State<AppState>,
    Path(organization): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    // Validate the organization exists and the caller has access.
    let org = match state
        .identity
        .get_organization(&context.actor, &organization)
        .await
    {
        Ok(o) => o,
        Err(error) => return handle_identity_error(error),
    };

    // RBAC: verify the actor can read provisioner jobs in this org.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::ProvisionerJobs).in_org(org.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to view provisioner jobs.",
        ));
    }

    let empty: Vec<ProvisionerJobResponse> = Vec::new();
    Ok((StatusCode::OK, Json(empty)).into_response())
}

pub(crate) async fn get_provisioner_job(
    State(state): State<AppState>,
    Path((organization, _job)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    // Validate the organization exists and the caller has access.
    let org = match state
        .identity
        .get_organization(&context.actor, &organization)
        .await
    {
        Ok(o) => o,
        Err(error) => return handle_identity_error(error),
    };

    // RBAC: verify the actor can read provisioner jobs in this org.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::ProvisionerJobs).in_org(org.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to view provisioner jobs.",
        ));
    }
    Ok(not_found_detail_response(
        "Resource not found or you do not have access to this resource",
        "The provisioner domain is not yet implemented in this backend slice.",
    ))
}

pub(crate) async fn cancel_provisioner_job(
    State(state): State<AppState>,
    Path((organization, job)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    // Validate the organization exists and the caller has access.
    let org = match state
        .identity
        .get_organization(&context.actor, &organization)
        .await
    {
        Ok(o) => o,
        Err(error) => {
            return handle_identity_error(error);
        }
    };

    // RBAC: verify the actor can update provisioner jobs in this org.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::ProvisionerJobs).in_org(org.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to cancel provisioner jobs.",
        ));
    }

    // Parse job UUID.
    let job_id = match Uuid::from_str(&job) {
        Ok(id) => id,
        Err(_) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error(
                    "Invalid provisioner job ID",
                    "The job path parameter must be a valid UUID.",
                )),
            )
                .into_response());
        }
    };

    // Look up the provisioner job.
    let Some(pj) = state.store.find_provisioner_job(job_id).await? else {
        return Ok(resource_not_found_response());
    };

    // Verify the job belongs to the requested organization.
    if pj.organization_id != org.id {
        return Ok(resource_not_found_response());
    }

    // Check the job is not already completed or cancelled.
    if pj.completed_at.is_some() || pj.canceled_at.is_some() {
        return Ok((
            StatusCode::PRECONDITION_FAILED,
            Json(ApiResponse::error(
                "Job cannot be canceled",
                "The provisioner job has already completed or been canceled.",
            )),
        )
            .into_response());
    }

    // Cancel the job.
    let updated = state.store.cancel_template_provisioner_job(job_id).await?;
    if !updated {
        // Race: someone else completed/cancelled it between our check and update.
        return Ok((
            StatusCode::PRECONDITION_FAILED,
            Json(ApiResponse::error(
                "Job cannot be canceled",
                "The provisioner job has already completed or been canceled.",
            )),
        )
            .into_response());
    }

    Ok(StatusCode::OK.into_response())
}

pub(crate) async fn get_provisioner_job_logs(
    State(state): State<AppState>,
    Path((organization, job)): Path<(String, String)>,
    Query(query): Query<ProvisionerJobLogsQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    // Validate the organization exists and the caller has access.
    let org = match state
        .identity
        .get_organization(&context.actor, &organization)
        .await
    {
        Ok(o) => o,
        Err(error) => {
            return handle_identity_error(error);
        }
    };

    // RBAC: verify the actor can read provisioner jobs in this org.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::ProvisionerJobs).in_org(org.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to view provisioner job logs.",
        ));
    }

    // Parse job UUID.
    let job_id = match Uuid::from_str(&job) {
        Ok(id) => id,
        Err(_) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error(
                    "Invalid provisioner job ID",
                    "The job path parameter must be a valid UUID.",
                )),
            )
                .into_response());
        }
    };

    // Look up the provisioner job to verify it exists.
    let Some(pj) = state.store.find_provisioner_job(job_id).await? else {
        return Ok(resource_not_found_response());
    };

    // Verify the job belongs to the requested organization.
    if pj.organization_id != org.id {
        return Ok(resource_not_found_response());
    }

    let _follow = query.follow.unwrap_or(false);

    // Fetch the logs.
    let logs = state
        .store
        .list_provisioner_job_logs(job_id, query.after)
        .await?;

    let items: Vec<ProvisionerJobLog> = logs
        .into_iter()
        .map(|l| ProvisionerJobLog {
            id: l.id,
            created_at: l.created_at,
            log_source: l.source,
            log_level: l.level,
            stage: l.stage,
            output: l.output,
        })
        .collect();

    Ok((StatusCode::OK, Json(items)).into_response())
}

pub(crate) async fn applications_host(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    Ok((
        StatusCode::OK,
        Json(AppHostResponse {
            host: String::new(),
        }),
    )
        .into_response())
}

pub(crate) async fn applications_auth_redirect(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    Ok((
        StatusCode::BAD_REQUEST,
        Json(ApiResponse::error(
            "Subdomain-based application routing is not supported in this deployment.",
            "Subdomain-based workspace application routing requires additional proxy configuration.",
        )),
    )
        .into_response())
}

/// GET /api/v2/debug/coordinator — return coordinator state/debug info.
///
/// Dependency: requires a `TailnetCoordinator` implementation that tracks
/// connected agents and clients.  In Go this calls
/// `(*api.TailnetCoordinator.Load()).ServeHTTPDebug(rw, r)`.  The Rust
/// backend does not yet have a tailnet coordination layer, so we return 501.
pub(crate) async fn debug_coordinator(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !can_view_operational_data(&context.actor) {
        return Ok(forbidden_response(
            "You are not authorized to view coordinator debug information.",
        ));
    }

    let html = state.coordinator.debug_html();
    Ok((
        StatusCode::OK,
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        )],
        html,
    )
        .into_response())
}

/// GET /api/v2/debug/tailnet — return tailnet debug info.
///
/// Dependency: requires an `agentProvider` that manages workspace-agent
/// connections over the tailnet mesh.  In Go this calls
/// `api.agentProvider.ServeHTTPDebug(rw, r)`.  The Rust backend does not yet
/// have a workspace-agent provider, so we return 501.
pub(crate) async fn debug_tailnet(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !can_view_operational_data(&context.actor) {
        return Ok(forbidden_response(
            "You are not authorized to view tailnet debug information.",
        ));
    }

    let debug = state.coordinator.debug_json();
    Ok((StatusCode::OK, Json(debug)).into_response())
}

/// GET /api/v2/debug/derp/traffic — return DERP relay traffic statistics.
///
/// Dependency: requires a running DERP relay server (`DERPServer`) that
/// tracks per-client send/receive byte counters.  In Go this calls
/// `options.DERPServer.ServeDebugTraffic`.  The Rust backend does not yet
/// include a DERP relay, so we return 501.
pub(crate) async fn debug_derp_traffic(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !can_view_operational_data(&context.actor) {
        return Ok(forbidden_response(
            "You are not authorized to view DERP traffic debug information.",
        ));
    }

    let debug = state.derp_tracker.debug_json().await;
    Ok((StatusCode::OK, Json(debug)).into_response())
}

/// GET /api/v2/debug/expvar — return expvar-style debug variables.
///
/// In Go this serves `expvar.Handler()` which returns JSON with memstats,
/// cmdline, and (when available) DERP metrics.  The Rust equivalent reads
/// process stats from `/proc/self` (Linux) or returns basic runtime info
/// on other platforms.
pub(crate) async fn debug_expvar(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !can_view_operational_data(&context.actor) {
        return Ok(forbidden_response(
            "You are not authorized to view expvar debug information.",
        ));
    }

    let mut vars: serde_json::Map<String, Value> = serde_json::Map::new();

    // cmdline — mirrors Go's `os.Args` expvar.
    let cmdline = std::env::args().collect::<Vec<String>>();
    vars.insert("cmdline".to_string(), json!(cmdline));

    // memstats — read RSS and VmSize from /proc/self/status on Linux.
    let memstats = read_proc_memstats();
    let mut memstats_map = serde_json::Map::new();
    if let Some(rss) = memstats.rss_bytes {
        memstats_map.insert("rss_bytes".to_string(), json!(rss));
    }
    if let Some(vm) = memstats.vm_size_bytes {
        memstats_map.insert("vm_size_bytes".to_string(), json!(vm));
    }
    vars.insert("memstats".to_string(), Value::Object(memstats_map));

    Ok(Json(Value::Object(vars)).into_response())
}

/// Basic memory statistics read from `/proc/self/status`.
pub(crate) struct ProcMemstats {
    rss_bytes: Option<u64>,
    vm_size_bytes: Option<u64>,
}

/// Read basic memory statistics from `/proc/self/status`.
/// On non-Linux platforms (or read failure) both fields are `None`.
pub(crate) fn read_proc_memstats() -> ProcMemstats {
    let mut stats = ProcMemstats {
        rss_bytes: None,
        vm_size_bytes: None,
    };
    if let Ok(contents) = std::fs::read_to_string("/proc/self/status") {
        for line in contents.lines() {
            if let Some(val) = line.strip_prefix("VmRSS:") {
                stats.rss_bytes = parse_proc_kb(val).map(|kb| kb * 1024);
            } else if let Some(val) = line.strip_prefix("VmSize:") {
                stats.vm_size_bytes = parse_proc_kb(val).map(|kb| kb * 1024);
            }
        }
    }
    stats
}

/// Parse a `/proc/self/status` value like `"   12345 kB"` into kilobytes.
pub(crate) fn parse_proc_kb(val: &str) -> Option<u64> {
    val.split_whitespace()
        .next()
        .and_then(|s| s.parse::<u64>().ok())
}

/// GET /api/v2/debug/pprof (and sub-routes cmdline, profile, symbol, trace)
///
/// Go exposes `net/http/pprof` handlers that produce CPU/memory/goroutine
/// profiles in the pprof protobuf format.  There is no direct Rust
/// equivalent.  For CPU profiling consider `perf`, `flamegraph`, or the
/// `pprof-rs` crate.  For heap profiling use jemalloc with
/// `MALLOC_CONF="prof:true"`.  For async-task dumps use `tokio-console`.
/// Each sub-route returns informational JSON about Rust alternatives.
pub(crate) async fn debug_pprof(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !can_view_operational_data(&context.actor) {
        return Ok(forbidden_response(
            "You are not authorized to view pprof debug information.",
        ));
    }

    let uri_path = uri.path();
    let response = match uri_path {
        "/api/v2/debug/pprof/cmdline" => {
            let cmdline = std::env::args().collect::<Vec<String>>().join(" ");
            json!({
                "cmdline": cmdline,
            })
        }
        "/api/v2/debug/pprof/profile" => {
            json!({
                "message": "Go-style CPU profiling is not available in Rust.",
                "alternatives": [
                    "cargo flamegraph -- produces an SVG flamegraph",
                    "perf record -g -- followed by perf report for CPU profiling",
                    "pprof-rs crate for programmatic CPU profiling"
                ]
            })
        }
        "/api/v2/debug/pprof/symbol" => {
            json!({
                "message": "Symbol lookup is not supported in the Rust backend.",
                "detail": "Use addr2line or rustfilt for symbol resolution."
            })
        }
        "/api/v2/debug/pprof/trace" => {
            json!({
                "message": "Go-style execution tracing is not available in Rust.",
                "alternatives": [
                    "tokio-console -- real-time async task inspector",
                    "tracing crate with tracing-subscriber for structured logging",
                    "perf sched -- for OS-level scheduling analysis"
                ]
            })
        }
        _ => {
            // /api/v2/debug/pprof — summary index page
            json!({
                "message": "Rust profiling debug index",
                "note": "Go pprof is not available in Rust. The following endpoints provide guidance on Rust alternatives.",
                "endpoints": {
                    "/api/v2/debug/pprof/cmdline": "Returns the process command line arguments.",
                    "/api/v2/debug/pprof/profile": "Guidance on CPU profiling alternatives (cargo flamegraph, perf).",
                    "/api/v2/debug/pprof/symbol": "Symbol lookup is not supported; use addr2line.",
                    "/api/v2/debug/pprof/trace": "Guidance on tracing alternatives (tokio-console, tracing crate)."
                }
            })
        }
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// GET /api/v2/debug/ws — WebSocket echo server used as a health check.
///
/// In Go this is `WebsocketEchoServer.ServeHTTP` which accepts a WebSocket
/// connection and echoes every received message back to the client.  The
/// health checker (`healthcheck/websocket.go`) connects here and sends
/// three numbered text messages, verifying each is echoed correctly.
pub(crate) async fn debug_websocket(
    State(state): State<AppState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !can_view_operational_data(&context.actor) {
        return Ok(forbidden_response(
            "You are not authorized to use the debug websocket.",
        ));
    }

    Ok(ws.on_upgrade(websocket_echo))
}

/// Run the WebSocket echo loop: read a message, send it back, repeat.
///
/// Each echo operation has a 10-second timeout, matching Go's
/// `WebsocketEchoServer` which uses `context.WithTimeout(ctx, 10s)`.
pub(crate) async fn websocket_echo(mut socket: WebSocket) {
    use std::time::Duration;
    const ECHO_TIMEOUT: Duration = Duration::from_secs(10);

    loop {
        let msg = match tokio::time::timeout(ECHO_TIMEOUT, socket.next()).await {
            Ok(Some(Ok(msg))) => msg,
            // Timeout, receive error, or stream ended — close.
            _ => return,
        };
        let reply = match msg {
            Message::Text(text) => Message::Text(text),
            Message::Binary(data) => Message::Binary(data),
            Message::Close(_) => return,
            // Ping/Pong are handled automatically by axum.
            _ => continue,
        };
        let send_result = tokio::time::timeout(ECHO_TIMEOUT, socket.send(reply)).await;
        match send_result {
            Ok(Ok(())) => {}
            // Timeout or send error — close.
            _ => return,
        }
    }
}

/// GET /api/v2/debug/metrics — Prometheus metrics endpoint.
///
/// In Go this serves the full Prometheus registry via `promhttp`.
/// The Rust backend does not yet have a shared `prometheus::Registry`,
/// so we emit a small set of process-level gauges in Prometheus exposition
/// format.  Once a registry is wired into `AppState`, this handler should
/// delegate to it.
pub(crate) async fn debug_metrics(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !can_view_operational_data(&context.actor) {
        return Ok(forbidden_response(
            "You are not authorized to view debug metrics.",
        ));
    }

    let mut out = String::new();

    // process_resident_memory_bytes and process_virtual_memory_bytes
    // Reuse read_proc_memstats() to stay consistent with the expvar endpoint.
    let memstats = read_proc_memstats();
    if let Some(rss) = memstats.rss_bytes {
        out.push_str("# HELP process_resident_memory_bytes Resident memory size in bytes.\n");
        out.push_str("# TYPE process_resident_memory_bytes gauge\n");
        out.push_str(&format!("process_resident_memory_bytes {rss}\n"));
    }
    if let Some(vm) = memstats.vm_size_bytes {
        out.push_str("# HELP process_virtual_memory_bytes Virtual memory size in bytes.\n");
        out.push_str("# TYPE process_virtual_memory_bytes gauge\n");
        out.push_str(&format!("process_virtual_memory_bytes {vm}\n"));
    }

    // process_open_fds
    // Note: `read_dir` itself opens an fd for the directory iterator,
    // so the count is inflated by 1.  This matches the behavior of Go's
    // `prometheus/procfs` collector.
    if let Ok(entries) = std::fs::read_dir("/proc/self/fd") {
        let count = entries.count();
        out.push_str("# HELP process_open_fds Number of open file descriptors.\n");
        out.push_str("# TYPE process_open_fds gauge\n");
        out.push_str(&format!("process_open_fds {count}\n"));
    }

    // process_start_time_seconds (approximate via /proc/self/stat field 22)
    if let Ok(stat) = std::fs::read_to_string("/proc/self/stat") {
        // Field 22 (1-indexed) is starttime in clock ticks since boot.
        // We combine it with /proc/uptime to get a UNIX timestamp.
        // The comm field (field 2) is in parentheses and may contain spaces,
        // so we find the last ')' and parse fields after it.
        let after_comm = match stat.rfind(')') {
            Some(pos) => &stat[pos + 1..],
            None => &stat,
        };
        let fields: Vec<&str> = after_comm.split_whitespace().collect();
        // After comm, field 3 is state (index 0), so starttime (field 22) is index 19.
        if fields.len() > 19 {
            if let (Ok(start_ticks), Ok(uptime_content)) = (
                fields[19].parse::<u64>(),
                std::fs::read_to_string("/proc/uptime"),
            ) {
                if let Some(uptime_secs_str) = uptime_content.split_whitespace().next() {
                    if let Ok(uptime_secs) = uptime_secs_str.parse::<f64>() {
                        // 100 is the standard `USER_HZ` on Linux x86/x86_64/ARM.
                        // Using `libc::sysconf(_SC_CLK_TCK)` would be more correct
                        // but requires `unsafe`, which this crate forbids.
                        let clock_ticks_per_sec: u64 = 100;
                        let boot_time_approx =
                            OffsetDateTime::now_utc().unix_timestamp() as f64 - uptime_secs;
                        let process_start =
                            boot_time_approx + (start_ticks as f64 / clock_ticks_per_sec as f64);
                        out.push_str("# HELP process_start_time_seconds Start time of the process since unix epoch in seconds.\n");
                        out.push_str("# TYPE process_start_time_seconds gauge\n");
                        out.push_str(&format!("process_start_time_seconds {process_start:.2}\n"));
                    }
                }
            }
        }
    }

    if out.is_empty() {
        out.push_str("# No process metrics available on this platform.\n");
    }

    Ok((
        StatusCode::OK,
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
        )],
        out,
    )
        .into_response())
}

/// GET /api/v2/derp-map — WebSocket endpoint that streams DERP map updates.
///
/// Upgrades to a WebSocket, sends the initial DERP map, then pushes updates
/// whenever the map changes.  The Go handler does NOT require
/// apiKeyMiddleware (it's commented out in coderd.go), so we mirror that.
pub(crate) async fn derp_map_updates(
    State(state): State<AppState>,
    ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
    let mut rx = state.coordinator.subscribe_derp_map();
    Ok(ws.on_upgrade(move |mut socket| async move {
        // Send the initial DERP map.
        let initial = rx.borrow_and_update().clone();
        if let Ok(payload) = serde_json::to_string(&initial) {
            if socket.send(Message::Text(payload.into())).await.is_err() {
                return;
            }
        }

        // Stream updates until the connection closes or the coordinator drops.
        loop {
            if rx.changed().await.is_err() {
                // Sender dropped — coordinator shut down.
                break;
            }
            let updated = rx.borrow_and_update().clone();
            if let Ok(payload) = serde_json::to_string(&updated) {
                if socket.send(Message::Text(payload.into())).await.is_err() {
                    break;
                }
            }
        }
        let _ = socket
            .send(Message::Close(Some(CloseFrame {
                code: 1000,
                reason: "coordinator shutdown".into(),
            })))
            .await;
    }))
}

/// GET /api/v2/regions — returns the list of available workspace proxy regions.
///
/// In the OSS edition this always returns a single "primary" region built from
/// the deployment ID and access URL.  The enterprise edition may add additional
/// workspace-proxy regions.
pub(crate) async fn get_regions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let region_id = state
        .store
        .ensure_deployment_metadata()
        .await
        .map(|m| m.deployment_id)?;

    let access_url = state.config.access_url.clone();

    let region = coder_core::Region {
        id: region_id,
        name: "primary".to_string(),
        display_name: "Default".to_string(),
        icon_url: String::new(),
        healthy: true,
        path_app_url: access_url.to_string(),
        wildcard_hostname: String::new(),
    };

    Ok((
        StatusCode::OK,
        Json(coder_core::RegionsResponse {
            regions: vec![region],
        }),
    )
        .into_response())
}

/// GET /api/v2/tailnet — WebSocket RPC connection for tailnet coordination.
///
/// Accepts a WebSocket connection for tailnet coordination protocol.  This is
/// the main coordination channel where agents and clients exchange node
/// information to establish peer-to-peer connections.
pub(crate) async fn tailnet_rpc_conn(
    State(state): State<AppState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
    use coder_connectivity::tailnet::PeerKind;

    // First try agent authentication — agents present their auth_token via
    // the same Coder-Session-Token header but it resolves to a workspace
    // agent row instead of a user session.
    let (peer_id, peer_name, peer_kind) =
        if let Some(agent) = authenticate_agent_request(&state, &headers).await? {
            (agent.id, agent.name.clone(), PeerKind::Agent)
        } else if let Some(context) = authenticate_request(&state, &headers).await? {
            // Fall back to session-token authentication for regular clients.
            (
                context.actor.user_id,
                context.actor.username.clone(),
                PeerKind::Client,
            )
        } else {
            return Ok(unauthorized_response("Missing or invalid session token."));
        };

    let coordinator = state.coordinator.clone();

    Ok(ws.on_upgrade(move |mut socket| async move {
        use coder_connectivity::tailnet::{CoordinateRequest, CoordinateResponse};

        // Start a coordination session — this returns a handle with a
        // channel that receives responses pushed by the coordinator when
        // tunnel peers update their node info.  The peer kind is determined
        // from the authentication context: agents authenticate via
        // workspace agent auth tokens, clients via session tokens.
        let mut handle =
            coordinator.coordinate(peer_id, peer_name, peer_kind);

        // Multiplex: read from WebSocket AND from the coordinator response
        // channel simultaneously.  When the client sends a coordination
        // request we process it; when the coordinator pushes a response we
        // forward it over the WebSocket.
        loop {
            tokio::select! {
                // --- Incoming WebSocket message from the client ---
                ws_msg = socket.next() => {
                    match ws_msg {
                        Some(Ok(Message::Text(text))) => {
                            // Parse the JSON coordination request.
                            match serde_json::from_str::<CoordinateRequest>(&text) {
                                Ok(request) => {
                                    if let Err(e) = coordinator.process_request(peer_id, request) {
                                        tracing::warn!(
                                            peer_id = %peer_id,
                                            error = %e,
                                            "coordination request error",
                                        );
                                    }
                                }
                                Err(e) => {
                                    tracing::debug!(
                                        peer_id = %peer_id,
                                        error = %e,
                                        "invalid coordination request JSON",
                                    );
                                    // Send a proper CoordinateResponse error back to the peer.
                                    let err_resp = CoordinateResponse {
                                        peer_updates: Vec::new(),
                                        error: Some(format!("invalid request: {e}")),
                                    };
                                    if let Ok(payload) = serde_json::to_string(&err_resp) {
                                        if socket.send(Message::Text(payload.into())).await.is_err() {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        Some(Ok(Message::Binary(bin))) => {
                            // Try to parse binary as JSON coordination request.
                            match serde_json::from_slice::<CoordinateRequest>(&bin) {
                                Ok(request) => {
                                    if let Err(e) = coordinator.process_request(peer_id, request) {
                                        tracing::warn!(
                                            peer_id = %peer_id,
                                            error = %e,
                                            "coordination request error (binary)",
                                        );
                                    }
                                }
                                Err(e) => {
                                    tracing::debug!(
                                        peer_id = %peer_id,
                                        error = %e,
                                        "invalid coordination request (binary)",
                                    );
                                    // Send a proper CoordinateResponse error back to the peer.
                                    let err_resp = CoordinateResponse {
                                        peer_updates: Vec::new(),
                                        error: Some(format!("invalid request: {e}")),
                                    };
                                    if let Ok(payload) = serde_json::to_string(&err_resp) {
                                        if socket.send(Message::Text(payload.into())).await.is_err() {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        Some(Ok(Message::Close(_))) | None => break,
                        Some(Err(_)) => break,
                        _ => continue,
                    }
                }
                // --- Outgoing coordination response from the coordinator ---
                resp = handle.response_rx.recv() => {
                    match resp {
                        Some(coord_response) => {
                            if let Ok(payload) = serde_json::to_string(&coord_response) {
                                if socket.send(Message::Text(payload.into())).await.is_err() {
                                    break;
                                }
                            }
                        }
                        // Channel closed — coordinator shut down our session.
                        None => break,
                    }
                }
            }
        }

        coordinator.close_coordination(peer_id, handle.session_id);
    }))
}
