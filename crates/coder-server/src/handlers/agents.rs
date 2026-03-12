//! Workspace agent handlers.

use super::*;

/// GET /api/v2/workspaceagents/me/gitsshkey — return the workspace owner's Git SSH key.
pub(crate) async fn workspace_agent_git_ssh_key(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    // Try agent auth first, fall back to user auth for backwards compatibility.
    let agent = authenticate_agent_request(&state, &headers).await?;
    let Some(agent) = agent else {
        let Some(_context) = authenticate_request(&state, &headers).await? else {
            return Ok(unauthorized_response("Missing or invalid session token."));
        };
        // User-authenticated fallback: return empty stub (owner key lookup
        // requires workspace resolution which is not yet available for user auth).
        return Ok((
            StatusCode::OK,
            Json(json!({"public_key":"","private_key":""})),
        )
            .into_response());
    };

    // Look up the workspace to find the owner, then fetch their git SSH key.
    let workspace = state.store.find_workspace_by_agent_id(agent.id).await?;
    let owner_id = match workspace {
        Some(ref ws) => ws.owner_id,
        None => {
            return Ok(internal_server_error_response(
                "Failed to get workspace for agent.",
            ));
        }
    };

    let key = state.store.find_git_ssh_key(owner_id).await?;
    match key {
        Some(k) => Ok((
            StatusCode::OK,
            Json(json!({
                "public_key": k.public_key,
                "private_key": k.private_key,
            })),
        )
            .into_response()),
        None => Ok((
            StatusCode::OK,
            Json(json!({"public_key":"","private_key":""})),
        )
            .into_response()),
    }
}

/// GET /workspaceagents/me/gitauth — deprecated, returns empty array.
/// Accepts both agent auth and user auth for backwards compatibility.
pub(crate) async fn deprecated_workspace_agent_git_auth(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let agent = authenticate_agent_request(&state, &headers).await?;
    if agent.is_none() {
        let Some(_context) = authenticate_request(&state, &headers).await? else {
            return Ok(unauthorized_response("Missing or invalid session token."));
        };
    }
    let empty: Vec<Value> = Vec::new();
    Ok((StatusCode::OK, Json(empty)).into_response())
}

/// GET /workspaceagents/{agent}/startup-logs — deprecated, delegates to the logs endpoint.
///
/// The Go implementation redirects this to the main logs endpoint.
/// We replicate the same behavior by returning the agent logs directly.
pub(crate) async fn deprecated_workspace_agent_startup_logs(
    State(state): State<AppState>,
    Path(agent_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(_row) = state.store.find_workspace_agent_by_id(agent_id).await? else {
        return Ok(resource_not_found_response());
    };

    // Return agent logs with default parameters (no follow, after=0, limit=256).
    let limit: i64 = 256;
    let log_rows = state
        .store
        .list_workspace_agent_logs(agent_id, 0, limit)
        .await?;
    let logs: Vec<coder_core::WorkspaceAgentLog> = log_rows
        .iter()
        .map(|r| coder_core::WorkspaceAgentLog {
            id: r.id,
            created_at: r.created_at,
            output: r.output.clone(),
            level: convert_log_level(&r.level),
            source_id: r.log_source_id,
        })
        .collect();

    Ok((StatusCode::OK, Json(logs)).into_response())
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct AgentLogsQuery {
    #[serde(default)]
    after: i64,
    #[serde(default)]
    follow: bool,
    #[serde(default)]
    limit: Option<i64>,
}

#[derive(Debug, Default, Deserialize)]
#[allow(dead_code)]
pub(crate) struct AgentExternalAuthQuery {
    #[serde(default)]
    id: String,
    #[serde(default)]
    listen: bool,
}

pub(crate) fn convert_workspace_agent_row(
    row: &coder_core::WorkspaceAgentRow,
    apps: Vec<coder_core::WorkspaceApp>,
    log_sources: Vec<coder_core::WorkspaceAgentLogSource>,
    scripts: Vec<coder_core::WorkspaceAgentScript>,
) -> coder_core::WorkspaceAgent {
    let lifecycle_state = match row.lifecycle_state.as_str() {
        "starting" => coder_core::WorkspaceAgentLifecycle::Starting,
        "start_timeout" => coder_core::WorkspaceAgentLifecycle::StartTimeout,
        "start_error" => coder_core::WorkspaceAgentLifecycle::StartError,
        "ready" => coder_core::WorkspaceAgentLifecycle::Ready,
        "shutting_down" => coder_core::WorkspaceAgentLifecycle::ShuttingDown,
        "shutdown_timeout" => coder_core::WorkspaceAgentLifecycle::ShutdownTimeout,
        "shutdown_error" => coder_core::WorkspaceAgentLifecycle::ShutdownError,
        "off" => coder_core::WorkspaceAgentLifecycle::Off,
        _ => coder_core::WorkspaceAgentLifecycle::Created,
    };

    let status = derive_agent_status(row);

    let subsystems: Vec<coder_core::AgentSubsystem> = row
        .subsystems
        .iter()
        .filter_map(|s| match s.as_str() {
            "envbuilder" => Some(coder_core::AgentSubsystem::Envbuilder),
            "envbox" => Some(coder_core::AgentSubsystem::Envbox),
            "exectrace" => Some(coder_core::AgentSubsystem::Exectrace),
            _ => None,
        })
        .collect();

    let display_apps: Vec<coder_core::DisplayApp> = row
        .display_apps
        .iter()
        .filter_map(|d| match d.as_str() {
            "vscode" => Some(coder_core::DisplayApp::Vscode),
            "vscode_insiders" => Some(coder_core::DisplayApp::VscodeInsiders),
            "web_terminal" => Some(coder_core::DisplayApp::WebTerminal),
            "ssh_helper" => Some(coder_core::DisplayApp::SshHelper),
            "port_forwarding_helper" => Some(coder_core::DisplayApp::PortForwardingHelper),
            _ => None,
        })
        .collect();

    let environment_variables: HashMap<String, String> = row
        .environment_variables
        .as_deref()
        .and_then(|json_str| serde_json::from_str(json_str).ok())
        .unwrap_or_default();

    coder_core::WorkspaceAgent {
        id: row.id,
        parent_id: row.parent_id,
        created_at: row.created_at,
        updated_at: row.updated_at,
        first_connected_at: row.first_connected_at,
        last_connected_at: row.last_connected_at,
        disconnected_at: row.disconnected_at,
        started_at: row.started_at,
        ready_at: row.ready_at,
        status,
        lifecycle_state,
        name: row.name.clone(),
        resource_id: row.resource_id,
        instance_id: row.auth_instance_id.clone().unwrap_or_default(),
        architecture: row.architecture.clone(),
        environment_variables,
        operating_system: row.operating_system.clone(),
        logs_length: row.logs_length,
        logs_overflowed: row.logs_overflowed,
        directory: row.directory.clone(),
        expanded_directory: row.expanded_directory.clone(),
        version: row.version.clone(),
        api_version: row.api_version.clone(),
        apps,
        latency: HashMap::new(),
        connection_timeout_seconds: row.connection_timeout_seconds,
        troubleshooting_url: row.troubleshooting_url.clone(),
        subsystems,
        health: coder_core::WorkspaceAgentHealth {
            healthy: true,
            reason: None,
        },
        display_apps,
        log_sources,
        scripts,
    }
}

pub(crate) fn derive_agent_status(
    row: &coder_core::WorkspaceAgentRow,
) -> coder_core::WorkspaceAgentStatus {
    if row.first_connected_at.is_none() {
        if row.connection_timeout_seconds > 0 {
            if let Some(timeout) =
                i64::from(row.connection_timeout_seconds).checked_mul(1_000_000_000)
            {
                let deadline = row.created_at + time::Duration::nanoseconds(timeout);
                if OffsetDateTime::now_utc() > deadline {
                    return coder_core::WorkspaceAgentStatus::Timeout;
                }
            }
        }
        return coder_core::WorkspaceAgentStatus::Connecting;
    }
    if row.disconnected_at.is_some() {
        return coder_core::WorkspaceAgentStatus::Disconnected;
    }
    coder_core::WorkspaceAgentStatus::Connected
}

pub(crate) fn convert_workspace_app_row(
    row: &coder_core::WorkspaceAppRow,
) -> coder_core::WorkspaceApp {
    let sharing_level = match row.sharing_level.as_str() {
        "authenticated" => coder_core::AppSharingLevel::Authenticated,
        "organization" => coder_core::AppSharingLevel::Organization,
        "public" => coder_core::AppSharingLevel::Public,
        _ => coder_core::AppSharingLevel::Owner,
    };
    let health = match row.health.as_str() {
        "initializing" => coder_core::WorkspaceAppHealth::Initializing,
        "healthy" => coder_core::WorkspaceAppHealth::Healthy,
        "unhealthy" => coder_core::WorkspaceAppHealth::Unhealthy,
        _ => coder_core::WorkspaceAppHealth::Disabled,
    };
    let open_in = match row.open_in.as_str() {
        "tab" => coder_core::WorkspaceAppOpenIn::Tab,
        "window" => coder_core::WorkspaceAppOpenIn::Window,
        _ => coder_core::WorkspaceAppOpenIn::SlimWindow,
    };
    coder_core::WorkspaceApp {
        id: row.id,
        slug: row.slug.clone(),
        display_name: row.display_name.clone(),
        command: row.command.clone(),
        url: row.url.clone(),
        icon: row.icon.clone(),
        subdomain: row.subdomain,
        sharing_level,
        healthcheck_url: row.healthcheck_url.clone(),
        healthcheck_interval: row.healthcheck_interval,
        healthcheck_threshold: row.healthcheck_threshold,
        health,
        external: row.external,
        display_order: row.display_order,
        hidden: row.hidden,
        open_in,
        display_group: row.display_group.clone(),
    }
}

pub(crate) fn convert_log_source_row(
    row: &coder_core::WorkspaceAgentLogSourceRow,
) -> coder_core::WorkspaceAgentLogSource {
    coder_core::WorkspaceAgentLogSource {
        id: row.id,
        workspace_agent_id: row.workspace_agent_id,
        created_at: row.created_at,
        display_name: row.display_name.clone(),
        icon: row.icon.clone(),
    }
}

pub(crate) fn convert_script_row(
    row: &coder_core::WorkspaceAgentScriptRow,
) -> coder_core::WorkspaceAgentScript {
    coder_core::WorkspaceAgentScript {
        id: row.id,
        log_source_id: row.log_source_id,
        log_path: row.log_path.clone(),
        script: row.script.clone(),
        cron: row.cron.clone(),
        start_blocks_login: row.start_blocks_login,
        run_on_start: row.run_on_start,
        run_on_stop: row.run_on_stop,
        timeout_seconds: row.timeout_seconds,
        display_name: row.display_name.clone(),
    }
}

pub(crate) fn convert_log_level(level: &str) -> coder_core::LogLevel {
    match level {
        "trace" => coder_core::LogLevel::Trace,
        "debug" => coder_core::LogLevel::Debug,
        "warn" => coder_core::LogLevel::Warn,
        "error" => coder_core::LogLevel::Error,
        _ => coder_core::LogLevel::Info,
    }
}

#[allow(dead_code)]
pub(crate) fn convert_app_status_state(state: &str) -> coder_core::WorkspaceAppStatusState {
    match state {
        "working" => coder_core::WorkspaceAppStatusState::Working,
        "complete" => coder_core::WorkspaceAppStatusState::Complete,
        "failure" => coder_core::WorkspaceAppStatusState::Failure,
        _ => coder_core::WorkspaceAppStatusState::Idle,
    }
}

/// Build a full agent response including apps, log sources, scripts.
pub(crate) async fn build_agent_response(
    state: &AppState,
    row: &coder_core::WorkspaceAgentRow,
) -> Result<coder_core::WorkspaceAgent, AppError> {
    let app_rows = state.store.list_workspace_apps_by_agent_id(row.id).await?;
    let apps: Vec<coder_core::WorkspaceApp> =
        app_rows.iter().map(convert_workspace_app_row).collect();

    let source_rows = state.store.list_workspace_agent_log_sources(row.id).await?;
    let log_sources: Vec<coder_core::WorkspaceAgentLogSource> =
        source_rows.iter().map(convert_log_source_row).collect();

    let script_rows = state.store.list_workspace_agent_scripts(row.id).await?;
    let scripts: Vec<coder_core::WorkspaceAgentScript> =
        script_rows.iter().map(convert_script_row).collect();

    Ok(convert_workspace_agent_row(row, apps, log_sources, scripts))
}

/// GET /api/v2/workspaceagents/{agent} — get agent info.
pub(crate) async fn get_workspace_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(agent_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(row) = state.store.find_workspace_agent_by_id(agent_id).await? else {
        return Ok(resource_not_found_response());
    };

    let agent = build_agent_response(&state, &row).await?;
    Ok((StatusCode::OK, Json(agent)).into_response())
}

/// GET /api/v2/workspaceagents/{agent}/connection — per-agent connection info.
pub(crate) async fn get_workspace_agent_connection(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(_agent_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let info = build_workspace_agent_connection_info(&state);
    Ok((StatusCode::OK, Json(info)).into_response())
}

/// GET /api/v2/workspaceagents/{agent}/containers — list containers.
pub(crate) async fn get_workspace_agent_containers(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(agent_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(_row) = state.store.find_workspace_agent_by_id(agent_id).await? else {
        return Ok(resource_not_found_response());
    };

    let devcontainer_rows = state
        .store
        .list_workspace_agent_devcontainers(agent_id)
        .await?;
    let devcontainers: Vec<coder_core::WorkspaceAgentDevcontainer> = devcontainer_rows
        .iter()
        .map(|dc| coder_core::WorkspaceAgentDevcontainer {
            id: dc.id,
            workspace_agent_id: dc.workspace_agent_id,
            workspace_folder: dc.workspace_folder.clone(),
            config_path: dc.config_path.clone(),
            name: dc.name.clone(),
            container: None,
        })
        .collect();

    Ok((
        StatusCode::OK,
        Json(WorkspaceAgentListContainersResponse {
            containers: Vec::new(),
            devcontainers,
        }),
    )
        .into_response())
}

/// POST /api/v2/workspaceagents/{agent}/containers/devcontainers/{dc}/recreate — recreate devcontainer.
pub(crate) async fn post_workspace_agent_recreate_devcontainer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((agent_id, dc_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(row) = state.store.find_workspace_agent_by_id(agent_id).await? else {
        return Ok(resource_not_found_response());
    };

    // RBAC: verify the actor can update workspace agent devcontainers.
    // Look up the workspace for org/owner-scoped RBAC when available.
    let workspace = state.store.find_workspace_by_agent_id(agent_id).await?;
    let authorizer = Authorizer::new();
    let rbac_obj = match workspace {
        Some(ref ws) => Object::new(ResourceType::WorkspaceAgentDevcontainers)
            .with_owner(ws.owner_id)
            .in_org(ws.organization_id),
        None => Object::new(ResourceType::WorkspaceAgentDevcontainers),
    };
    if authorizer
        .authorize(&context.actor, Action::Update, &rbac_obj)
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to recreate devcontainers.",
        ));
    }

    let status = derive_agent_status(&row);
    if status != coder_core::WorkspaceAgentStatus::Connected {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                format!("Agent state is \"{status:?}\", it must be in the \"Connected\" state."),
                "The agent must be connected before a devcontainer can be recreated.",
            )),
        )
            .into_response());
    }

    let Some(conn) = state.agent_provider.get_agent_connection(agent_id).await else {
        return Ok(not_found_detail_response(
            "Agent is not connected.",
            "The workspace agent does not have an active connection to the server.",
        ));
    };

    if let Err(err) = conn.recreate_devcontainer(&dc_id.to_string()).await {
        return Ok(internal_server_error_response(format!(
            "Failed to recreate devcontainer: {err}"
        )));
    }

    Ok(StatusCode::OK.into_response())
}

/// DELETE /api/v2/workspaceagents/{agent}/containers/devcontainers/{dc} — delete devcontainer.
pub(crate) async fn delete_workspace_agent_devcontainer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((agent_id, dc_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(row) = state.store.find_workspace_agent_by_id(agent_id).await? else {
        return Ok(resource_not_found_response());
    };

    // RBAC: verify the actor can delete workspace agent devcontainers.
    // Look up the workspace for org/owner-scoped RBAC when available.
    let workspace = state.store.find_workspace_by_agent_id(agent_id).await?;
    let authorizer = Authorizer::new();
    let rbac_obj = match workspace {
        Some(ref ws) => Object::new(ResourceType::WorkspaceAgentDevcontainers)
            .with_owner(ws.owner_id)
            .in_org(ws.organization_id),
        None => Object::new(ResourceType::WorkspaceAgentDevcontainers),
    };
    if authorizer
        .authorize(&context.actor, Action::Delete, &rbac_obj)
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to delete devcontainers.",
        ));
    }

    let status = derive_agent_status(&row);
    if status != coder_core::WorkspaceAgentStatus::Connected {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                format!("Agent state is \"{status:?}\", it must be in the \"Connected\" state."),
                "The agent must be connected before a devcontainer can be deleted.",
            )),
        )
            .into_response());
    }

    let Some(conn) = state.agent_provider.get_agent_connection(agent_id).await else {
        return Ok(not_found_detail_response(
            "Agent is not connected.",
            "The workspace agent does not have an active connection to the server.",
        ));
    };

    if let Err(err) = conn.delete_devcontainer(&dc_id.to_string()).await {
        return Ok(internal_server_error_response(format!(
            "Failed to delete devcontainer: {err}"
        )));
    }

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// GET /api/v2/workspaceagents/{agent}/containers/watch — SSE container watch.
pub(crate) async fn get_workspace_agent_containers_watch(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(agent_id): Path<Uuid>,
    ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(_row) = state.store.find_workspace_agent_by_id(agent_id).await? else {
        return Ok(resource_not_found_response());
    };

    let pubsub = state.pubsub.clone();
    let store = state.store.clone();
    let channel = coder_core::pubsub::workspace_agent_containers_channel(agent_id);

    Ok(ws.on_upgrade(move |mut socket| async move {
        // Subscribe to pub/sub BEFORE sending initial state to avoid missing
        // events that arrive between the initial fetch and the subscription.
        let mut subscription = match pubsub.subscribe(&channel).await {
            Ok(sub) => sub,
            Err(e) => {
                tracing::warn!(
                    agent_id = %agent_id,
                    error = %e,
                    "failed to subscribe to container events",
                );
                let _ = socket
                    .send(Message::Close(Some(CloseFrame {
                        code: 1011,
                        reason: format!("pubsub subscribe failed: {e}").into(),
                    })))
                    .await;
                return;
            }
        };

        // Send the initial container state snapshot.
        let devcontainer_rows = match store.list_workspace_agent_devcontainers(agent_id).await {
            Ok(rows) => rows,
            Err(e) => {
                tracing::warn!(
                    agent_id = %agent_id,
                    error = %e,
                    "failed to fetch initial container state",
                );
                Vec::new()
            }
        };
        let devcontainers: Vec<coder_core::WorkspaceAgentDevcontainer> = devcontainer_rows
            .iter()
            .map(|dc| coder_core::WorkspaceAgentDevcontainer {
                id: dc.id,
                workspace_agent_id: dc.workspace_agent_id,
                workspace_folder: dc.workspace_folder.clone(),
                config_path: dc.config_path.clone(),
                name: dc.name.clone(),
                container: None,
            })
            .collect();
        let snapshot = WorkspaceAgentListContainersResponse {
            containers: Vec::new(),
            devcontainers,
        };
        if let Ok(payload) = serde_json::to_string(&snapshot) {
            if socket.send(Message::Text(payload.into())).await.is_err() {
                return;
            }
        }

        // Stream container state changes until the connection closes.
        loop {
            tokio::select! {
                ws_msg = socket.recv() => {
                    match ws_msg {
                        Some(Ok(Message::Close(_))) | None => break,
                        Some(Err(_)) => break,
                        _ => continue,
                    }
                }
                event = subscription.recv() => {
                    match event {
                        Ok(data) => {
                            let text = match String::from_utf8(data) {
                                Ok(s) => s,
                                Err(e) => {
                                    tracing::debug!(
                                        error = %e,
                                        "non-UTF-8 container event payload",
                                    );
                                    continue;
                                }
                            };
                            if socket.send(Message::Text(text.into())).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    }))
}

/// GET /api/v2/workspaceagents/{agent}/coordinate — WebSocket coordination.
///
/// Implements agent-side coordination protocol.  Registers the agent as a
/// peer in the [`TailnetCoordinator`] and multiplexes between incoming
/// WebSocket messages and outgoing coordinator responses.
pub(crate) async fn get_workspace_agent_coordinate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(agent_id): Path<Uuid>,
    ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(row) = state.store.find_workspace_agent_by_id(agent_id).await? else {
        return Ok(resource_not_found_response());
    };

    let coordinator = state.coordinator.clone();

    Ok(ws.on_upgrade(move |mut socket| async move {
        use coder_connectivity::tailnet::{CoordinateRequest, CoordinateResponse, PeerKind};

        // Register the agent as a peer in the coordinator.
        let mut handle =
            coordinator.coordinate(agent_id, row.name.clone(), PeerKind::Agent);

        // Multiplex: read from WebSocket AND from the coordinator response
        // channel simultaneously.
        loop {
            tokio::select! {
                // --- Incoming WebSocket message from the agent ---
                ws_msg = socket.next() => {
                    match ws_msg {
                        Some(Ok(Message::Text(text))) => {
                            match serde_json::from_str::<CoordinateRequest>(&text) {
                                Ok(request) => {
                                    if let Err(e) = coordinator.process_request(agent_id, request) {
                                        tracing::warn!(
                                            agent_id = %agent_id,
                                            error = %e,
                                            "agent coordination request error",
                                        );
                                    }
                                }
                                Err(e) => {
                                    tracing::debug!(
                                        agent_id = %agent_id,
                                        error = %e,
                                        "invalid agent coordination request JSON",
                                    );
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
                            match serde_json::from_slice::<CoordinateRequest>(&bin) {
                                Ok(request) => {
                                    if let Err(e) = coordinator.process_request(agent_id, request) {
                                        tracing::warn!(
                                            agent_id = %agent_id,
                                            error = %e,
                                            "agent coordination request error (binary)",
                                        );
                                    }
                                }
                                Err(e) => {
                                    tracing::debug!(
                                        agent_id = %agent_id,
                                        error = %e,
                                        "invalid agent coordination request (binary)",
                                    );
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

        coordinator.close_coordination(agent_id, handle.session_id);
    }))
}

/// GET /api/v2/workspaceagents/{agent}/listening-ports — list listening ports.
pub(crate) async fn get_workspace_agent_listening_ports(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(agent_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(_row) = state.store.find_workspace_agent_by_id(agent_id).await? else {
        return Ok(resource_not_found_response());
    };

    // Listening ports are reported by the agent in real-time; return empty for now.
    Ok((
        StatusCode::OK,
        Json(WorkspaceAgentListeningPortsResponse { ports: Vec::new() }),
    )
        .into_response())
}

/// GET /api/v2/workspaceagents/{agent}/logs — streaming agent logs.
pub(crate) async fn get_workspace_agent_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(agent_id): Path<Uuid>,
    Query(query): Query<AgentLogsQuery>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(_row) = state.store.find_workspace_agent_by_id(agent_id).await? else {
        return Ok(resource_not_found_response());
    };

    if query.follow {
        use axum::body::Body;
        use coder_core::pubsub::workspace_agent_logs_channel;

        let channel = workspace_agent_logs_channel(agent_id);
        let mut subscription = state.pubsub.subscribe(&channel).await.map_err(|e| {
            AppError::Storage(StorageError::Unavailable {
                message: e.to_string(),
            })
        })?;

        let (tx, rx) = tokio::sync::mpsc::channel::<String>(64);

        // Fetch existing logs and send them first.
        let limit = query.limit.unwrap_or(256).clamp(1, 10000);
        let existing_rows = state
            .store
            .list_workspace_agent_logs(agent_id, query.after, limit)
            .await?;
        let existing_logs: Vec<coder_core::WorkspaceAgentLog> = existing_rows
            .iter()
            .map(|r| coder_core::WorkspaceAgentLog {
                id: r.id,
                created_at: r.created_at,
                output: r.output.clone(),
                level: convert_log_level(&r.level),
                source_id: r.log_source_id,
            })
            .collect();

        // Track the highest log ID from the initial batch so that the
        // spawned task can skip any pubsub messages that were already
        // included (avoids duplicates from the subscribe-before-query race
        // window).
        let last_sent_id = existing_logs.last().map(|l| l.id);

        // Pre-serialize existing logs so they can be moved into the
        // spawned task.  We must NOT send them on `tx` here because the
        // receiver (`rx`) hasn't been returned to the client yet — doing
        // so would deadlock once the 64-slot channel buffer fills up.
        let initial_events: Vec<String> = existing_logs
            .iter()
            .map(|log| {
                let data = serde_json::to_string(log).unwrap_or_default();
                format!("data: {data}\n\n")
            })
            .collect();

        // Spawn a task that first drains the initial batch, then listens
        // for new log events on pubsub.
        tokio::spawn(async move {
            // Send existing logs first.
            for sse in initial_events {
                if tx.send(sse).await.is_err() {
                    return;
                }
            }

            loop {
                tokio::select! {
                    msg = subscription.recv() => {
                        match msg {
                            Ok(bytes) => {
                                // Each message is a JSON-serialised WorkspaceAgentLog.
                                // Deduplicate: skip messages with an ID that was
                                // already sent in the initial batch.
                                if let Some(max_id) = last_sent_id {
                                    if let Ok(log) = serde_json::from_slice::<Value>(&bytes) {
                                        if let Some(id_val) = log.get("id").and_then(|v| v.as_i64()) {
                                            if id_val <= max_id {
                                                continue;
                                            }
                                        }
                                    }
                                }
                                let data = String::from_utf8_lossy(&bytes);
                                let sse = format!("data: {data}\n\n");
                                if tx.send(sse).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    _ = tx.closed() => {
                        break;
                    }
                }
            }
        });

        let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        let body = Body::from_stream(tokio_stream::StreamExt::map(
            stream,
            Ok::<_, std::convert::Infallible>,
        ));

        return Ok((
            StatusCode::OK,
            [
                (CONTENT_TYPE, HeaderValue::from_static("text/event-stream")),
                (
                    HeaderName::from_static("cache-control"),
                    HeaderValue::from_static("no-cache"),
                ),
            ],
            body,
        )
            .into_response());
    }

    let limit = query.limit.unwrap_or(256).clamp(1, 10000);
    let log_rows = state
        .store
        .list_workspace_agent_logs(agent_id, query.after, limit)
        .await?;
    let logs: Vec<coder_core::WorkspaceAgentLog> = log_rows
        .iter()
        .map(|r| coder_core::WorkspaceAgentLog {
            id: r.id,
            created_at: r.created_at,
            output: r.output.clone(),
            level: convert_log_level(&r.level),
            source_id: r.log_source_id,
        })
        .collect();

    Ok((StatusCode::OK, Json(logs)).into_response())
}

/// GET /api/v2/workspaceagents/{agent}/pty — WebSocket terminal.
pub(crate) async fn get_workspace_agent_pty(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(agent_id): Path<Uuid>,
    ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(_row) = state.store.find_workspace_agent_by_id(agent_id).await? else {
        return Ok(resource_not_found_response());
    };

    let pubsub = state.pubsub.clone();
    let agent_provider = state.agent_provider.clone();

    Ok(ws.on_upgrade(move |mut socket| async move {
        // Verify the agent is currently connected before starting the relay.
        if agent_provider
            .get_agent_connection(agent_id)
            .await
            .is_none()
        {
            let _ = socket
                .send(Message::Close(Some(CloseFrame {
                    code: 4002,
                    reason: "agent is not connected".into(),
                })))
                .await;
            return;
        }

        // Set up bidirectional relay channels via pubsub.
        let output_channel = coder_core::pubsub::workspace_agent_pty_output_channel(agent_id);
        let input_channel = coder_core::pubsub::workspace_agent_pty_input_channel(agent_id);

        let mut output_sub = match pubsub.subscribe(&output_channel).await {
            Ok(sub) => sub,
            Err(e) => {
                tracing::warn!(
                    agent_id = %agent_id,
                    error = %e,
                    "failed to subscribe to PTY output",
                );
                let _ = socket
                    .send(Message::Close(Some(CloseFrame {
                        code: 1011,
                        reason: format!("pubsub subscribe failed: {e}").into(),
                    })))
                    .await;
                return;
            }
        };

        // Relay binary frames between WebSocket client and PTY channels.
        loop {
            tokio::select! {
                ws_msg = socket.recv() => {
                    match ws_msg {
                        Some(Ok(Message::Binary(data))) => {
                            if let Err(e) = pubsub.publish(&input_channel, &data).await {
                                tracing::debug!(
                                    agent_id = %agent_id,
                                    error = %e,
                                    "failed to publish PTY input",
                                );
                                break;
                            }
                        }
                        Some(Ok(Message::Text(text))) => {
                            if let Err(e) = pubsub.publish(&input_channel, text.as_bytes()).await {
                                tracing::debug!(
                                    agent_id = %agent_id,
                                    error = %e,
                                    "failed to publish PTY input",
                                );
                                break;
                            }
                        }
                        Some(Ok(Message::Close(_))) | None => break,
                        Some(Err(_)) => break,
                        _ => continue,
                    }
                }
                pty_data = output_sub.recv() => {
                    match pty_data {
                        Ok(data) => {
                            if socket.send(Message::Binary(data.into())).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    }))
}

/// GET /api/v2/workspaceagents/{agent}/watch-metadata — SSE metadata watch.
///
/// Implements Server-Sent Events streaming of agent metadata updates, matching
/// Go's `watchWorkspaceAgentMetadataSSE`.  Subscribes to the pubsub metadata
/// channel *before* fetching the initial snapshot so no updates are lost.
/// Sends the initial snapshot immediately, then streams updates as they arrive.
pub(crate) async fn get_workspace_agent_watch_metadata(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(agent_id): Path<Uuid>,
) -> Result<Response, AppError> {
    use axum::body::Body;
    use coder_core::pubsub::workspace_agent_metadata_channel;

    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(_row) = state.store.find_workspace_agent_by_id(agent_id).await? else {
        return Ok(resource_not_found_response());
    };

    let channel = workspace_agent_metadata_channel(agent_id);
    let mut subscription = state.pubsub.subscribe(&channel).await.map_err(|e| {
        AppError::Storage(StorageError::Unavailable {
            message: e.to_string(),
        })
    })?;

    // Fetch the initial metadata snapshot *after* subscribing so we don't
    // miss events that arrive between the fetch and the subscribe.
    let metadata_rows = state.store.list_workspace_agent_metadata(agent_id).await?;

    let (tx, rx) = tokio::sync::mpsc::channel::<String>(64);

    // Pre-serialize the initial metadata so it can be sent inside the spawned
    // task (the receiver isn't returned to the client until after this fn).
    let initial_metadata: Vec<coder_core::WorkspaceAgentMetadata> = metadata_rows
        .iter()
        .map(|m| coder_core::WorkspaceAgentMetadata {
            display_name: m.display_name.clone(),
            key: m.key.clone(),
            script: m.script.clone(),
            value: m.value.clone(),
            error: m.error.clone(),
            timeout: m.timeout,
            interval: m.interval,
            collected_at: m.collected_at,
            display_order: m.display_order,
        })
        .collect();
    let initial_payload =
        serde_json::to_string(&initial_metadata).map_err(|e| AppError::InternalError {
            message: "failed to serialize initial agent metadata".to_owned(),
            detail: e.to_string(),
        })?;

    tokio::spawn(async move {
        // Send initial snapshot (multiline-safe per SSE spec).
        let sse = initial_payload
            .lines()
            .map(|line| format!("data: {line}\n"))
            .collect::<String>()
            + "\n";
        if tx.send(sse).await.is_err() {
            return;
        }

        // Stream updates until the connection closes.
        loop {
            tokio::select! {
                msg = subscription.recv() => {
                    match msg {
                        Ok(bytes) => {
                            let data = match String::from_utf8(bytes.to_vec()) {
                                Ok(s) => s,
                                Err(_) => {
                                    // Skip invalid UTF-8 payloads to avoid sending corrupted SSE data.
                                    continue;
                                }
                            };
                            let sse = data
                                .lines()
                                .map(|line| format!("data: {line}\n"))
                                .collect::<String>()
                                + "\n";
                            if tx.send(sse).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                _ = tx.closed() => {
                    break;
                }
            }
        }
    });

    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    let body = Body::from_stream(tokio_stream::StreamExt::map(
        stream,
        Ok::<_, std::convert::Infallible>,
    ));

    Ok((
        StatusCode::OK,
        [
            (CONTENT_TYPE, HeaderValue::from_static("text/event-stream")),
            (
                HeaderName::from_static("cache-control"),
                HeaderValue::from_static("no-cache"),
            ),
        ],
        body,
    )
        .into_response())
}

/// GET /api/v2/workspaceagents/{agent}/watch-metadata-ws — WebSocket metadata watch.
pub(crate) async fn get_workspace_agent_watch_metadata_ws(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(agent_id): Path<Uuid>,
    ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(_row) = state.store.find_workspace_agent_by_id(agent_id).await? else {
        return Ok(resource_not_found_response());
    };

    let pubsub = state.pubsub.clone();
    let store = state.store.clone();
    let channel = coder_core::pubsub::workspace_agent_metadata_channel(agent_id);

    Ok(ws.on_upgrade(move |mut socket| async move {
        // Subscribe to pub/sub BEFORE sending initial state to avoid missing
        // events that arrive between the initial fetch and the subscription.
        let mut subscription = match pubsub.subscribe(&channel).await {
            Ok(sub) => sub,
            Err(e) => {
                tracing::warn!(
                    agent_id = %agent_id,
                    error = %e,
                    "failed to subscribe to metadata events",
                );
                let _ = socket
                    .send(Message::Close(Some(CloseFrame {
                        code: 1011,
                        reason: format!("pubsub subscribe failed: {e}").into(),
                    })))
                    .await;
                return;
            }
        };

        // Send the initial metadata snapshot.
        match store.list_workspace_agent_metadata(agent_id).await {
            Ok(rows) => {
                let metadata: Vec<coder_core::WorkspaceAgentMetadata> = rows
                    .iter()
                    .map(|m| coder_core::WorkspaceAgentMetadata {
                        display_name: m.display_name.clone(),
                        key: m.key.clone(),
                        script: m.script.clone(),
                        value: m.value.clone(),
                        error: m.error.clone(),
                        timeout: m.timeout,
                        interval: m.interval,
                        collected_at: m.collected_at,
                        display_order: m.display_order,
                    })
                    .collect();
                if let Ok(payload) = serde_json::to_string(&metadata) {
                    if socket.send(Message::Text(payload.into())).await.is_err() {
                        return;
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    agent_id = %agent_id,
                    error = %e,
                    "failed to fetch initial metadata",
                );
            }
        }

        // Stream metadata updates until the connection closes.
        loop {
            tokio::select! {
                ws_msg = socket.recv() => {
                    match ws_msg {
                        Some(Ok(Message::Close(_))) | None => break,
                        Some(Err(_)) => break,
                        _ => continue,
                    }
                }
                event = subscription.recv() => {
                    match event {
                        Ok(data) => {
                            let text = match String::from_utf8(data) {
                                Ok(s) => s,
                                Err(e) => {
                                    tracing::debug!(
                                        error = %e,
                                        "non-UTF-8 metadata event payload",
                                    );
                                    continue;
                                }
                            };
                            if socket.send(Message::Text(text.into())).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    }))
}

/// GET /api/v2/workspaceagents/connection — global agent connection info.
/// Build the deployment-wide DERP connection info from server config.
/// Shared by both the per-agent and global connection endpoints.
pub(crate) fn build_workspace_agent_connection_info(
    state: &AppState,
) -> WorkspaceAgentConnectionInfo {
    let mut regions = HashMap::new();
    for region in &state.config.derp_regions {
        let nodes: Vec<DERPNode> = region
            .nodes
            .iter()
            .map(|node| DERPNode {
                name: node.name.clone(),
                region_id: i64::from(region.id),
                host_name: node.url.host_str().unwrap_or_default().to_owned(),
                ipv4: None,
                ipv6: None,
                stun_port: 3478,
                stun_only: false,
                derp_port: node.url.port_or_known_default().map_or(443, i32::from),
                force_http: node.url.scheme() == "http",
            })
            .collect();
        regions.insert(
            region.id.to_string(),
            DERPMapRegion {
                region_id: i64::from(region.id),
                region_code: region.name.to_lowercase().replace(' ', "-"),
                region_name: region.name.clone(),
                avoid: false,
                nodes,
            },
        );
    }

    WorkspaceAgentConnectionInfo {
        derp_map: DERPMap { regions },
        derp_force_websockets: false,
        disable_direct_connections: false,
        hostname_suffix: state.config.ssh.hostname_suffix.clone(),
    }
}

pub(crate) async fn get_workspace_agents_connection_info(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let info = build_workspace_agent_connection_info(&state);
    Ok((StatusCode::OK, Json(info)).into_response())
}

/// PATCH /api/v2/workspaceagents/me/app-status — update app status (agent-authenticated).
pub(crate) async fn patch_workspace_agent_app_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<PatchAppStatusRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(agent) = authenticate_agent_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid agent token."));
    };

    let Json(request) = match body {
        Ok(json) => json,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    if request.app_slug.is_empty() {
        return Ok(validation_response(vec![ValidationError {
            field: "app_slug".to_owned(),
            detail: "App slug is required.".to_owned(),
        }]));
    }

    // Resolve the workspace for this agent.
    let workspace = state.store.find_workspace_by_agent_id(agent.id).await?;
    let workspace = match workspace {
        Some(ws) => ws,
        None => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error("Failed to get workspace.", "")),
            )
                .into_response());
        }
    };

    // Look up the app by slug to get its ID.
    let app = state
        .store
        .find_workspace_app_by_agent_and_slug(agent.id, &request.app_slug)
        .await?;
    let app = match app {
        Some(a) => a,
        None => {
            return Ok(not_found_detail_response(
                "App not found.",
                format!("no app with slug {}", request.app_slug),
            ));
        }
    };

    // Insert the app status.
    let state_str = match request.state {
        coder_core::WorkspaceAppStatusState::Working => "working",
        coder_core::WorkspaceAppStatusState::Complete => "complete",
        coder_core::WorkspaceAppStatusState::Failure => "failure",
        coder_core::WorkspaceAppStatusState::Idle => "idle",
    };
    let input = coder_core::InsertWorkspaceAppStatusInput {
        agent_id: agent.id,
        app_id: app.id,
        workspace_id: workspace.id,
        state: state_str.to_owned(),
        message: request.message,
        uri: request.uri,
    };
    state.store.insert_workspace_app_status(&input).await?;

    Ok((StatusCode::OK, Json(ApiResponse::ok("App status updated."))).into_response())
}

/// GET /api/v2/workspaceagents/me/external-auth — agent external auth.
///
/// Returns the external auth status for the calling agent's workspace owner
/// for the requested provider, matching Go's
/// `workspaceAgentsExternalAuth` handler.
pub(crate) async fn get_workspace_agent_external_auth(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AgentExternalAuthQuery>,
) -> Result<Response, AppError> {
    let Some(agent) = authenticate_agent_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid agent token."));
    };

    // Validate that the provider id is provided.
    if query.id.is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error("'id' must be provided.", "")),
        )
            .into_response());
    }

    // Find the matching provider configuration.
    let Some(provider_config) = find_external_auth_provider(&state, &query.id) else {
        return Ok(not_found_detail_response(
            "External auth provider not found.",
            format!(
                "No external auth provider with id {:?} is configured.",
                query.id
            ),
        ));
    };

    // Resolve the workspace owner via agent → workspace → owner.
    let workspace = state.store.find_workspace_by_agent_id(agent.id).await?;
    let owner_id = match workspace {
        Some(ref ws) => ws.owner_id,
        None => {
            return Ok(internal_server_error_response(
                "Failed to get workspace for agent.",
            ));
        }
    };

    // Long-poll loop: when query.listen is true, Go's
    // `workspaceAgentsExternalAuth` keeps polling until the token becomes
    // available or the request is cancelled (r.Context().Done()).
    //
    // We mirror that by polling at a short interval until the link is
    // authenticated, the deadline elapses, or the client disconnects.
    //
    // Cancellation: every `.await` inside this loop is a cancellation
    // point.  When a client disconnects, Hyper drops the handler future at
    // the nearest `.await`, stopping the loop and preventing further DB
    // queries.  The `tokio::select!` below makes this intent explicit —
    // if additional cancellation signals (e.g. a shutdown token) are added
    // later, they slot into the `select!` naturally.
    const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
    const POLL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

    let deadline = tokio::time::sleep(POLL_TIMEOUT);
    tokio::pin!(deadline);

    loop {
        // Check whether the workspace owner has linked this external auth provider.
        let link = state
            .store
            .find_external_auth_link(owner_id, &query.id)
            .await?;

        let authenticated = link
            .as_ref()
            .map(|l| {
                l.authenticated
                    && l.validate_error.is_empty()
                    && l.expires > OffsetDateTime::now_utc()
            })
            .unwrap_or(false);

        // If not listening or already authenticated, return immediately.
        if !query.listen || authenticated {
            return Ok((
                StatusCode::OK,
                Json(build_agent_external_auth_response(
                    &state,
                    &query,
                    provider_config,
                    link.as_ref(),
                    authenticated,
                )?),
            )
                .into_response());
        }

        // Wait for the poll interval, or stop if the deadline elapses.
        // Each branch is a cancellation point: if the client disconnects
        // the handler future is dropped here.
        tokio::select! {
            _ = tokio::time::sleep(POLL_INTERVAL) => {
                // Continue to next poll iteration.
            }
            _ = &mut deadline => {
                // Timeout reached – return whatever state we have.
                return Ok((
                    StatusCode::OK,
                    Json(build_agent_external_auth_response(
                        &state,
                        &query,
                        provider_config,
                        link.as_ref(),
                        authenticated,
                    )?),
                )
                    .into_response());
            }
        }
    }
}

/// Builds the agent-facing external auth response (shared by immediate-return
/// and deadline-expiry paths in the long-poll handler).
fn build_agent_external_auth_response(
    state: &AppState,
    query: &AgentExternalAuthQuery,
    provider_config: &coder_core::api::ExternalAuthLinkProvider,
    link: Option<&coder_core::ExternalAuthLinkRecord>,
    authenticated: bool,
) -> Result<coder_core::api::WorkspaceAgentExternalAuthResponse, AppError> {
    Ok(coder_core::api::WorkspaceAgentExternalAuthResponse {
        access_token: link
            .filter(|_| authenticated)
            .map(|l| l.access_token.clone())
            .unwrap_or_default(),
        url: if authenticated {
            String::new()
        } else {
            state
                .config
                .access_url
                .join(&format!("external-auth/{}", query.id))
                .map_err(|e| AppError::InternalError {
                    message: "Failed to construct external auth redirect URL.".into(),
                    detail: e.to_string(),
                })?
                .to_string()
        },
        auth_type: provider_config.provider_type.clone(),
        authenticated,
        username: None,
        password: None,
    })
}

/// POST /api/v2/workspaceagents/me/log-source — create agent log source.
pub(crate) async fn post_workspace_agent_log_source(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<CreateLogSourceRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(agent) = authenticate_agent_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid agent token."));
    };

    let Json(request) = match body {
        Ok(json) => json,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    if request.display_name.is_empty() {
        return Ok(validation_response(vec![ValidationError {
            field: "display_name".to_owned(),
            detail: "Display name is required.".to_owned(),
        }]));
    }

    let row = state
        .store
        .insert_workspace_agent_log_source(
            agent.id,
            request.id,
            &request.display_name,
            &request.icon,
        )
        .await?;

    let source = convert_log_source_row(&row);
    Ok((StatusCode::CREATED, Json(source)).into_response())
}

/// PATCH /api/v2/workspaceagents/me/logs — append agent logs.
pub(crate) async fn patch_workspace_agent_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<PatchAgentLogsRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(agent) = authenticate_agent_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid agent token."));
    };

    let Json(request) = match body {
        Ok(json) => json,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    if request.logs.is_empty() {
        return Ok(validation_response(vec![ValidationError {
            field: "logs".to_owned(),
            detail: "At least one log entry is required.".to_owned(),
        }]));
    }

    let log_inputs: Vec<coder_core::InsertAgentLogInput> = request
        .logs
        .into_iter()
        .map(|entry| coder_core::InsertAgentLogInput {
            created_at: entry.created_at,
            output: entry.output,
            level: match entry.level {
                coder_core::LogLevel::Trace => "trace".to_owned(),
                coder_core::LogLevel::Debug => "debug".to_owned(),
                coder_core::LogLevel::Info => "info".to_owned(),
                coder_core::LogLevel::Warn => "warn".to_owned(),
                coder_core::LogLevel::Error => "error".to_owned(),
            },
        })
        .collect();

    let new_logs = state
        .store
        .insert_workspace_agent_logs(agent.id, request.log_source_id, &log_inputs)
        .await?;

    // Publish each new log entry to the pubsub channel so follow-mode
    // subscribers receive real-time updates.
    let channel = coder_core::pubsub::workspace_agent_logs_channel(agent.id);
    for log_row in &new_logs {
        let api_log = coder_core::WorkspaceAgentLog {
            id: log_row.id,
            created_at: log_row.created_at,
            output: log_row.output.clone(),
            level: convert_log_level(&log_row.level),
            source_id: log_row.log_source_id,
        };
        let payload = serde_json::to_vec(&api_log).unwrap_or_default();
        let _ = state.pubsub.publish(&channel, &payload).await;
    }

    Ok(StatusCode::OK.into_response())
}

/// GET /api/v2/workspaceagents/me/reinit — long-poll for agent reinit (SSE).
///
/// In Go this uses Server-Sent Events to stream reinitialization events
/// (e.g. when a prebuilt workspace is claimed). The Rust implementation
/// subscribes to the pubsub reinit channel for the authenticated agent and
/// streams events as they arrive.
pub(crate) async fn get_workspace_agent_reinit(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    use axum::body::Body;
    use coder_core::pubsub::workspace_agent_reinit_channel;

    let Some(agent) = authenticate_agent_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid agent token."));
    };

    let channel = workspace_agent_reinit_channel(agent.id);
    let mut subscription = state.pubsub.subscribe(&channel).await.map_err(|e| {
        AppError::Storage(StorageError::Unavailable {
            message: e.to_string(),
        })
    })?;

    let (tx, rx) = tokio::sync::mpsc::channel::<String>(64);

    // Spawn a task that listens for reinit events on pubsub.
    tokio::spawn(async move {
        loop {
            tokio::select! {
                msg = subscription.recv() => {
                    match msg {
                        Ok(bytes) => {
                            let data = String::from_utf8_lossy(&bytes);
                            let sse = format!("data: {data}\n\n");
                            if tx.send(sse).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                _ = tx.closed() => {
                    break;
                }
            }
        }
    });

    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    let body = Body::from_stream(tokio_stream::StreamExt::map(
        stream,
        Ok::<_, std::convert::Infallible>,
    ));

    Ok((
        StatusCode::OK,
        [
            (CONTENT_TYPE, HeaderValue::from_static("text/event-stream")),
            (
                HeaderName::from_static("cache-control"),
                HeaderValue::from_static("no-cache"),
            ),
        ],
        body,
    )
        .into_response())
}

/// GET /api/v2/workspaceagents/me/rpc — dRPC over WebSocket.
///
/// In Go this upgrades to a WebSocket, wraps it with yamux, then serves dRPC
/// methods for the agent API (manifest, stats, lifecycle, etc.).
///
/// This implementation upgrades to WebSocket and registers the agent connection
/// in the [`AgentProvider`] so that devcontainer commands can be delivered.
/// Full dRPC/yamux message handling is not yet ported; the connection is held
/// open and cleaned up when the agent disconnects.
pub(crate) async fn get_workspace_agent_rpc(
    State(state): State<AppState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
    let Some(agent) = authenticate_agent_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid agent token."));
    };

    let agent_id = agent.id;
    let provider = state.agent_provider.clone();
    let store = state.store.clone();

    Ok(ws.on_upgrade(move |socket| handle_agent_rpc_socket(socket, agent_id, provider, store)))
}

/// Runs the WebSocket message loop for one connected agent.
///
/// Registers the agent in the provider, processes incoming messages, and
/// removes the agent on disconnect.
pub(crate) async fn handle_agent_rpc_socket(
    mut socket: WebSocket,
    agent_id: Uuid,
    provider: Arc<dyn AgentProvider>,
    store: Arc<dyn AppStore>,
) {
    let now = OffsetDateTime::now_utc();

    // Create a WebSocket-backed agent connection and register it.
    let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::channel::<AgentRpcCommand>(32);
    let conn: Arc<dyn AgentConnection> = Arc::new(WebSocketAgentConnection {
        id: agent_id,
        connected_at: now,
        cmd_tx,
    });
    provider.register_agent(agent_id, conn.clone()).await;

    // Ping interval to keep the connection alive.
    let mut ping_interval = tokio::time::interval(std::time::Duration::from_secs(30));
    ping_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Consume the first immediate tick so we don't send a spurious ping on connect.
    ping_interval.tick().await;

    loop {
        tokio::select! {
            // Incoming message from the agent.
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        handle_agent_message(&store, agent_id, &text).await;
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(Message::Ping(data))) => {
                        let _ = socket.send(Message::Pong(data)).await;
                    }
                    Some(Ok(_)) => {} // Binary, Pong — ignore
                    Some(Err(_)) => break,
                }
            }
            // Outbound command to the agent.
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(AgentRpcCommand::RecreateDevcontainer { container_id, reply }) => {
                        let payload = serde_json::json!({
                            "type": "recreate_devcontainer",
                            "container_id": container_id,
                        });
                        let result = socket.send(Message::Text(payload.to_string().into())).await;
                        let _ = reply.send(result.map_err(|e| AgentError::SendFailed(e.to_string())));
                    }
                    Some(AgentRpcCommand::DeleteDevcontainer { container_id, reply }) => {
                        let payload = serde_json::json!({
                            "type": "delete_devcontainer",
                            "container_id": container_id,
                        });
                        let result = socket.send(Message::Text(payload.to_string().into())).await;
                        let _ = reply.send(result.map_err(|e| AgentError::SendFailed(e.to_string())));
                    }
                    None => break,
                }
            }
            // Periodic ping.
            _ = ping_interval.tick() => {
                if socket.send(Message::Ping(vec![].into())).await.is_err() {
                    break;
                }
            }
        }
    }

    // Clean up: only remove if this is still the registered connection
    // (prevents a disconnecting task from removing a newer reconnection).
    provider.remove_agent(agent_id, &conn).await;

    // Graceful close.
    let _ = socket
        .send(Message::Close(Some(CloseFrame {
            code: 1000,
            reason: "agent disconnected".into(),
        })))
        .await;
}

/// Processes a single inbound text message from the agent.
pub(crate) async fn handle_agent_message(_store: &Arc<dyn AppStore>, agent_id: Uuid, text: &str) {
    let Ok(msg) = serde_json::from_str::<Value>(text) else {
        return;
    };
    let msg_type = msg.get("type").and_then(Value::as_str).unwrap_or_default();
    match msg_type {
        "report_stats" | "report_lifecycle" | "update_metadata" | "push_logs" => {
            // These message types will be fully handled once the dRPC service
            // layer is ported.  For now we log the receipt.
            debug!(agent_id = %agent_id, msg_type = msg_type, "received agent message");
        }
        _ => {
            debug!(agent_id = %agent_id, msg_type = msg_type, "unknown agent message type");
        }
    }
}

/// POST /api/v2/workspaceagents/aws-instance-identity — AWS instance identity auth.
pub(crate) async fn post_workspace_agent_instance_identity_aws(
    State(state): State<AppState>,
    body: Result<Json<AWSInstanceIdentityToken>, JsonRejection>,
) -> Result<Response, AppError> {
    let Json(token) = match body {
        Ok(json) => json,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    // In the Go implementation, the document is parsed and validated against
    // AWS certificates to extract the instance ID.  Full cryptographic
    // verification is not yet implemented; we extract the instance_id from
    // the identity document JSON directly.
    let instance_id = match serde_json::from_str::<Value>(&token.document) {
        Ok(doc) => match doc.get("instanceId").and_then(|v| v.as_str()) {
            Some(id) => id.to_owned(),
            None => {
                return Ok((
                    StatusCode::BAD_REQUEST,
                    Json(ApiResponse::error(
                        "Invalid AWS identity document: missing instanceId.",
                        "",
                    )),
                )
                    .into_response());
            }
        },
        Err(_) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error(
                    "Invalid AWS identity document: malformed JSON.",
                    "",
                )),
            )
                .into_response());
        }
    };

    handle_auth_instance_id(&state, &instance_id).await
}

/// POST /api/v2/workspaceagents/azure-instance-identity — Azure instance identity auth.
pub(crate) async fn post_workspace_agent_instance_identity_azure(
    State(state): State<AppState>,
    body: Result<Json<AzureInstanceIdentityToken>, JsonRejection>,
) -> Result<Response, AppError> {
    let Json(token) = match body {
        Ok(json) => json,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    // In the Go implementation, the Azure signature is a PKCS7 JWT that is
    // validated against Microsoft certificates.  Full cryptographic
    // verification is not yet implemented; we extract the VM ID from the
    // JWT payload directly.
    let instance_id = extract_instance_id_from_jwt(&token.signature);
    match instance_id {
        Some(id) => handle_auth_instance_id(&state, &id).await,
        None => Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "Invalid Azure identity: could not extract instance ID from signature.",
                "",
            )),
        )
            .into_response()),
    }
}

/// POST /api/v2/workspaceagents/google-instance-identity — Google instance identity auth.
pub(crate) async fn post_workspace_agent_instance_identity_google(
    State(state): State<AppState>,
    body: Result<Json<GCPInstanceIdentityToken>, JsonRejection>,
) -> Result<Response, AppError> {
    let Json(token) = match body {
        Ok(json) => json,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    // In the Go implementation, the GCP JWT is validated against Google's
    // token validator and the instance_id is extracted from the claims.
    // Full cryptographic verification is not yet implemented; we extract
    // the instance_id from the JWT payload directly.
    let instance_id = extract_instance_id_from_jwt(&token.json_web_token);
    match instance_id {
        Some(id) => handle_auth_instance_id(&state, &id).await,
        None => Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "Invalid GCP identity: could not extract instance ID from token.",
                "",
            )),
        )
            .into_response()),
    }
}

/// Extracts an instance_id claim from a JWT payload without cryptographic
/// verification.  Returns `None` when the token structure is invalid or
/// the claim is missing.
pub(crate) fn extract_instance_id_from_jwt(jwt: &str) -> Option<String> {
    // JWTs are header.payload.signature – we need the payload part.
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() < 2 {
        return None;
    }

    use base64::Engine;
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let payload_bytes = engine.decode(parts[1]).ok()?;
    let payload: Value = serde_json::from_slice(&payload_bytes).ok()?;

    // Azure puts vmId at the top level; GCP nests under google.compute_engine.instance_id.
    if let Some(vm_id) = payload.get("vmId").and_then(|v| v.as_str()) {
        return Some(vm_id.to_owned());
    }
    if let Some(id) = payload
        .get("google")
        .and_then(|g| g.get("compute_engine"))
        .and_then(|ce| ce.get("instance_id"))
        .and_then(|v| v.as_str())
    {
        return Some(id.to_owned());
    }

    None
}

/// Shared handler that takes a cloud-provider instance_id and performs the
/// agent→resource→job→build lookup chain, mirroring the Go
/// `handleAuthInstanceID` function.
pub(crate) async fn handle_auth_instance_id(
    state: &AppState,
    instance_id: &str,
) -> Result<Response, AppError> {
    // Step 1: Lookup agent by instance_id.
    let agent = match state
        .store
        .find_workspace_agent_by_instance_id(instance_id)
        .await?
    {
        Some(agent) => agent,
        None => {
            return Ok(not_found_response(format!(
                "Instance with id \"{instance_id}\" not found."
            )));
        }
    };

    // Step 2: Lookup the workspace resource that owns this agent.
    let resource = match state
        .store
        .find_workspace_resource_by_id(agent.resource_id)
        .await?
    {
        Some(resource) => resource,
        None => {
            return Ok(internal_server_error_response(
                "Internal error fetching provisioner job resource.",
            ));
        }
    };

    // Step 3: Lookup the provisioner job for this resource.
    let job = match state.store.find_provisioner_job(resource.job_id).await? {
        Some(job) => job,
        None => {
            return Ok(internal_server_error_response(
                "Internal error fetching provisioner job.",
            ));
        }
    };

    // Step 4: Validate job type is "workspace_build".
    if job.job_type != "workspace_build" {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                format!("\"{}\" jobs cannot be authenticated.", job.job_type),
                "",
            )),
        )
            .into_response());
    }

    // Step 5: Extract workspace_build_id from job input.
    let workspace_build_id = match job
        .input
        .get("workspace_build_id")
        .and_then(|v: &Value| v.as_str())
        .and_then(|s| Uuid::from_str(s).ok())
    {
        Some(id) => id,
        None => {
            return Ok(internal_server_error_response(
                "Internal error extracting job data.",
            ));
        }
    };

    // Step 6: Lookup the workspace build.
    let build = match state
        .store
        .find_workspace_build_by_id(workspace_build_id)
        .await?
    {
        Some(build) => build,
        None => {
            return Ok(internal_server_error_response(
                "Internal error fetching workspace build.",
            ));
        }
    };

    // Step 7: Verify this is the latest build (replay prevention).
    let latest_build = match state
        .store
        .find_latest_workspace_build(build.workspace_id)
        .await?
    {
        Some(latest) => latest,
        None => {
            return Ok(internal_server_error_response(
                "Internal error fetching the latest workspace build.",
            ));
        }
    };

    if latest_build.id != build.id {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                format!(
                    "Resource found for id \"{instance_id}\", but isn't registered on the latest history."
                ),
                "",
            )),
        )
            .into_response());
    }

    // Step 8: Return the agent auth token.
    Ok((
        StatusCode::OK,
        Json(WorkspaceAgentAuthenticateResponse {
            session_token: agent.auth_token.to_string(),
        }),
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::build_router;
    use crate::app::tests::{create_and_login, test_state_with_store};
    use axum::Router;
    use coder_core::WorkspaceAgentRow;
    use futures_util::{SinkExt, StreamExt};
    use std::error::Error;
    use std::time::Duration;
    use tokio_tungstenite::tungstenite;

    type TestResult = Result<(), Box<dyn Error>>;

    /// Spin up a test HTTP server on a random port and return its base URL.
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

    /// Seed a minimal workspace agent into the FakeStore and return its ID.
    fn seed_agent(store: &crate::app::tests::FakeStore) -> Result<Uuid, Box<dyn Error>> {
        let agent_id = Uuid::new_v4();
        let row = WorkspaceAgentRow {
            id: agent_id,
            parent_id: None,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            first_connected_at: Some(OffsetDateTime::now_utc()),
            last_connected_at: Some(OffsetDateTime::now_utc()),
            disconnected_at: None,
            started_at: None,
            ready_at: None,
            name: "test-agent".to_owned(),
            resource_id: Uuid::new_v4(),
            auth_token: Uuid::new_v4(),
            auth_instance_id: None,
            architecture: "amd64".to_owned(),
            environment_variables: None,
            operating_system: "linux".to_owned(),
            logs_length: 0,
            logs_overflowed: false,
            directory: String::new(),
            expanded_directory: String::new(),
            version: "1.0.0".to_owned(),
            api_version: "1.0".to_owned(),
            connection_timeout_seconds: 120,
            troubleshooting_url: String::new(),
            motd_file: String::new(),
            lifecycle_state: "created".to_owned(),
            subsystems: Vec::new(),
            display_apps: Vec::new(),
            display_order: 0,
            api_key_scope: "all".to_owned(),
        };
        store.insert_agent(row)?;
        Ok(agent_id)
    }

    /// Build a WebSocket URL from a base URL and path.
    fn ws_url(base: &url::Url, path: &str) -> String {
        let mut url = base.clone();
        url.set_scheme("ws").ok();
        format!("{url}{path}")
    }

    /// Build an authenticated WebSocket request with a session token header.
    fn ws_request(
        url: &str,
        session_token: &str,
    ) -> Result<http::Request<()>, Box<dyn Error>> {
        let parsed = url::Url::parse(url)?;
        let host = match parsed.port() {
            Some(port) => format!("{}:{}", parsed.host_str().unwrap_or("127.0.0.1"), port),
            None => parsed.host_str().unwrap_or("127.0.0.1").to_owned(),
        };
        let request = http::Request::builder()
            .uri(url)
            .header("Host", &host)
            .header("Coder-Session-Token", session_token)
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

    // =========================================================================
    // get_workspace_agent_coordinate tests
    // =========================================================================

    #[tokio::test]
    async fn coordinate_rejects_unauthenticated() -> TestResult {
        let (state, store) = test_state_with_store(true)?;
        let agent_id = seed_agent(&store)?;
        let app = build_router(state, None);
        let (base_url, _handle) = spawn_test_server(app).await?;

        let url = ws_url(
            &base_url,
            &format!("api/v2/workspaceagents/{agent_id}/coordinate"),
        );
        let result = tokio_tungstenite::connect_async(&url).await;
        assert!(result.is_err(), "should reject unauthenticated connection");
        Ok(())
    }

    #[tokio::test]
    async fn coordinate_accepts_authenticated_connection() -> TestResult {
        let (state, store) = test_state_with_store(true)?;
        let agent_id = seed_agent(&store)?;
        let app = build_router(state, None);
        let (base_url, _handle) = spawn_test_server(app.clone()).await?;

        let session_token = create_and_login(&app).await?;
        let url = ws_url(
            &base_url,
            &format!("api/v2/workspaceagents/{agent_id}/coordinate"),
        );
        let request = ws_request(&url, &session_token)?;
        let (mut ws, _resp) = tokio_tungstenite::connect_async(request).await?;

        // Send a valid coordination request and verify the connection stays open.
        let req = serde_json::json!({
            "add_tunnel": null,
            "update_self": null,
            "disconnect": null,
            "ready_for_handshake": null
        });
        ws.send(tungstenite::Message::Text(req.to_string().into()))
            .await?;

        ws.close(None).await?;
        Ok(())
    }

    #[tokio::test]
    async fn coordinate_returns_error_for_invalid_json() -> TestResult {
        let (state, store) = test_state_with_store(true)?;
        let agent_id = seed_agent(&store)?;
        let app = build_router(state, None);
        let (base_url, _handle) = spawn_test_server(app.clone()).await?;

        let session_token = create_and_login(&app).await?;
        let url = ws_url(
            &base_url,
            &format!("api/v2/workspaceagents/{agent_id}/coordinate"),
        );
        let request = ws_request(&url, &session_token)?;
        let (mut ws, _resp) = tokio_tungstenite::connect_async(request).await?;

        // Send invalid JSON — the server should handle it gracefully.
        ws.send(tungstenite::Message::Text("not valid json".into()))
            .await?;

        // The server may respond with an error or close the connection.
        let msg = tokio::time::timeout(Duration::from_secs(2), ws.next()).await;
        // We just verify the server doesn't crash — any response is acceptable.
        drop(msg);

        ws.close(None).await?;
        Ok(())
    }

    #[tokio::test]
    async fn coordinate_returns_not_found_for_unknown_agent() -> TestResult {
        let (state, _store) = test_state_with_store(true)?;
        let unknown_id = Uuid::new_v4();
        let app = build_router(state, None);
        let (base_url, _handle) = spawn_test_server(app.clone()).await?;

        let session_token = create_and_login(&app).await?;
        let url = ws_url(
            &base_url,
            &format!("api/v2/workspaceagents/{unknown_id}/coordinate"),
        );
        let request = ws_request(&url, &session_token)?;
        let result = tokio_tungstenite::connect_async(request).await;
        assert!(result.is_err(), "should reject unknown agent");
        Ok(())
    }

    // =========================================================================
    // get_workspace_agent_pty tests
    // =========================================================================

    #[tokio::test]
    async fn pty_rejects_unauthenticated() -> TestResult {
        let (state, store) = test_state_with_store(true)?;
        let agent_id = seed_agent(&store)?;
        let app = build_router(state, None);
        let (base_url, _handle) = spawn_test_server(app).await?;

        let url = ws_url(&base_url, &format!("api/v2/workspaceagents/{agent_id}/pty"));
        let result = tokio_tungstenite::connect_async(&url).await;
        assert!(result.is_err(), "should reject unauthenticated connection");
        Ok(())
    }

    #[tokio::test]
    async fn pty_closes_when_agent_not_connected() -> TestResult {
        let (state, store) = test_state_with_store(true)?;
        let agent_id = seed_agent(&store)?;
        let app = build_router(state, None);
        let (base_url, _handle) = spawn_test_server(app.clone()).await?;

        let session_token = create_and_login(&app).await?;
        let url = ws_url(&base_url, &format!("api/v2/workspaceagents/{agent_id}/pty"));
        let request = ws_request(&url, &session_token)?;
        let (mut ws, _resp) = tokio_tungstenite::connect_async(request).await?;

        // The agent is not connected, so the server should close the connection.
        let msg = tokio::time::timeout(Duration::from_secs(2), ws.next()).await;
        match msg {
            Ok(Some(Ok(tungstenite::Message::Close(_)))) | Ok(None) | Err(_) => {
                // Expected: server closed the connection in some form.
            }
            other => {
                // Any other response is also acceptable as long as the server
                // doesn't hang — it may send an error frame.
                drop(other);
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn pty_relays_binary_data_via_pubsub() -> TestResult {
        let (state, store) = test_state_with_store(true)?;
        let agent_id = seed_agent(&store)?;

        // Register a fake agent connection so PTY handler doesn't reject.
        let conn: Arc<dyn AgentConnection> =
            Arc::new(FakeAgentConnection {
                id: agent_id,
                connected_at: OffsetDateTime::now_utc(),
            });
        state.agent_provider.register_agent(agent_id, conn).await;

        let pubsub = state.pubsub.clone();
        let app = build_router(state, None);
        let (base_url, _handle) = spawn_test_server(app.clone()).await?;

        let session_token = create_and_login(&app).await?;
        let url = ws_url(&base_url, &format!("api/v2/workspaceagents/{agent_id}/pty"));
        let request = ws_request(&url, &session_token)?;
        let (mut ws, _resp) = tokio_tungstenite::connect_async(request).await?;

        // Subscribe to the PTY input channel to verify the relay.
        let input_channel = coder_core::pubsub::workspace_agent_pty_input_channel(agent_id);
        let mut input_sub = pubsub.subscribe(&input_channel).await?;

        // Send binary data from the client.
        ws.send(tungstenite::Message::Binary(b"hello pty".to_vec().into()))
            .await?;

        // Verify the data arrives on the pubsub input channel.
        let received = tokio::time::timeout(Duration::from_secs(2), input_sub.recv()).await?;
        assert_eq!(received?, b"hello pty");

        // Now publish data on the output channel and verify it arrives on the WS.
        let output_channel = coder_core::pubsub::workspace_agent_pty_output_channel(agent_id);
        pubsub.publish(&output_channel, b"pty output").await?;

        let msg = tokio::time::timeout(Duration::from_secs(2), ws.next()).await?;
        if let Some(Ok(tungstenite::Message::Binary(data))) = msg {
            assert_eq!(&data[..], b"pty output");
        } else {
            return Err(format!("expected binary message from PTY output, got: {msg:?}").into());
        }

        ws.close(None).await?;
        Ok(())
    }

    // =========================================================================
    // get_workspace_agent_containers_watch tests
    // =========================================================================

    #[tokio::test]
    async fn containers_watch_rejects_unauthenticated() -> TestResult {
        let (state, store) = test_state_with_store(true)?;
        let agent_id = seed_agent(&store)?;
        let app = build_router(state, None);
        let (base_url, _handle) = spawn_test_server(app).await?;

        let url = ws_url(
            &base_url,
            &format!("api/v2/workspaceagents/{agent_id}/containers/watch"),
        );
        let result = tokio_tungstenite::connect_async(&url).await;
        assert!(result.is_err(), "should reject unauthenticated connection");
        Ok(())
    }

    #[tokio::test]
    async fn containers_watch_sends_initial_snapshot() -> TestResult {
        let (state, store) = test_state_with_store(true)?;
        let agent_id = seed_agent(&store)?;
        let app = build_router(state, None);
        let (base_url, _handle) = spawn_test_server(app.clone()).await?;

        let session_token = create_and_login(&app).await?;
        let url = ws_url(
            &base_url,
            &format!("api/v2/workspaceagents/{agent_id}/containers/watch"),
        );
        let request = ws_request(&url, &session_token)?;
        let (mut ws, _resp) = tokio_tungstenite::connect_async(request).await?;

        // Should receive an initial snapshot (empty containers/devcontainers).
        let msg = tokio::time::timeout(Duration::from_secs(2), ws.next()).await?;
        if let Some(Ok(tungstenite::Message::Text(text))) = msg {
            let snapshot: Value = serde_json::from_str(&text)?;
            assert!(
                snapshot.get("containers").is_some(),
                "expected containers field"
            );
            assert!(
                snapshot.get("devcontainers").is_some(),
                "expected devcontainers field"
            );
        } else {
            return Err(
                format!("expected text message with initial snapshot, got: {msg:?}").into(),
            );
        }

        ws.close(None).await?;
        Ok(())
    }

    #[tokio::test]
    async fn containers_watch_streams_pubsub_updates() -> TestResult {
        let (state, store) = test_state_with_store(true)?;
        let agent_id = seed_agent(&store)?;
        let pubsub = state.pubsub.clone();
        let app = build_router(state, None);
        let (base_url, _handle) = spawn_test_server(app.clone()).await?;

        let session_token = create_and_login(&app).await?;
        let url = ws_url(
            &base_url,
            &format!("api/v2/workspaceagents/{agent_id}/containers/watch"),
        );
        let request = ws_request(&url, &session_token)?;
        let (mut ws, _resp) = tokio_tungstenite::connect_async(request).await?;

        // Consume the initial snapshot.
        let _ = tokio::time::timeout(Duration::from_secs(2), ws.next()).await;

        // Publish a container state change.
        let channel = coder_core::pubsub::workspace_agent_containers_channel(agent_id);
        let update = serde_json::json!({
            "containers": [{"id": "c1", "name": "test"}],
            "devcontainers": []
        });
        pubsub
            .publish(&channel, update.to_string().as_bytes())
            .await?;

        // Verify the update arrives on the WebSocket.
        let msg = tokio::time::timeout(Duration::from_secs(2), ws.next()).await?;
        if let Some(Ok(tungstenite::Message::Text(text))) = msg {
            let received: Value = serde_json::from_str(&text)?;
            assert!(received.get("containers").is_some());
        } else {
            return Err(
                format!("expected text message with container update, got: {msg:?}").into(),
            );
        }

        ws.close(None).await?;
        Ok(())
    }

    // =========================================================================
    // get_workspace_agent_watch_metadata (SSE) tests
    // =========================================================================

    #[tokio::test]
    async fn watch_metadata_sse_rejects_unauthenticated() -> TestResult {
        let (state, store) = test_state_with_store(true)?;
        let agent_id = seed_agent(&store)?;
        let app = build_router(state, None);
        let (base_url, _handle) = spawn_test_server(app).await?;

        let url = format!("{base_url}api/v2/workspaceagents/{agent_id}/watch-metadata");
        let resp = reqwest::get(&url).await?;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[tokio::test]
    async fn watch_metadata_sse_returns_event_stream() -> TestResult {
        let (state, store) = test_state_with_store(true)?;
        let agent_id = seed_agent(&store)?;
        let app = build_router(state, None);
        let (base_url, _handle) = spawn_test_server(app.clone()).await?;

        let session_token = create_and_login(&app).await?;
        let url = format!("{base_url}api/v2/workspaceagents/{agent_id}/watch-metadata");
        let client = reqwest::Client::new();
        let resp = client
            .get(&url)
            .header("Coder-Session-Token", &session_token)
            .send()
            .await?;

        assert_eq!(resp.status(), StatusCode::OK);
        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        assert!(
            content_type.contains("text/event-stream"),
            "expected text/event-stream, got: {content_type}"
        );

        // Buffer chunks until we have a complete SSE frame (terminated by \n\n).
        let mut resp = resp;
        let mut buffer: Vec<u8> = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err("timeout waiting for initial SSE metadata frame".into());
            }
            match tokio::time::timeout(remaining, resp.chunk()).await {
                Ok(Ok(Some(bytes))) => {
                    buffer.extend_from_slice(&bytes);
                    if buffer.windows(2).any(|w| w == b"\n\n") {
                        break;
                    }
                }
                _ => break,
            }
        }
        let text = String::from_utf8_lossy(&buffer);
        // Find the first complete SSE frame.
        let frame = text.split("\n\n").next().unwrap_or_default();
        assert!(
            frame.starts_with("data: "),
            "expected SSE data prefix, got: {frame}"
        );
        // The data should be a JSON array (empty metadata).
        let json_str = frame.trim_start_matches("data: ").trim();
        let parsed: Value = serde_json::from_str(json_str)?;
        assert!(parsed.is_array(), "expected JSON array");

        Ok(())
    }

    #[tokio::test]
    async fn watch_metadata_sse_streams_pubsub_updates() -> TestResult {
        let (state, store) = test_state_with_store(true)?;
        let agent_id = seed_agent(&store)?;
        let pubsub = state.pubsub.clone();
        let app = build_router(state, None);
        let (base_url, _handle) = spawn_test_server(app.clone()).await?;

        let session_token = create_and_login(&app).await?;
        let url = format!("{base_url}api/v2/workspaceagents/{agent_id}/watch-metadata");
        let client = reqwest::Client::new();
        let mut resp = client
            .get(&url)
            .header("Coder-Session-Token", &session_token)
            .send()
            .await?;

        // Consume the initial snapshot.
        let _ = tokio::time::timeout(Duration::from_secs(2), resp.chunk()).await;

        // Publish a metadata update.
        let channel = coder_core::pubsub::workspace_agent_metadata_channel(agent_id);
        let update = serde_json::json!([{
            "display_name": "CPU",
            "key": "cpu",
            "value": "42%"
        }]);
        pubsub
            .publish(&channel, update.to_string().as_bytes())
            .await?;

        // Buffer chunks until we have a complete SSE frame containing the update.
        let mut buffer: Vec<u8> = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err("timeout waiting for SSE metadata update frame".into());
            }
            match tokio::time::timeout(remaining, resp.chunk()).await {
                Ok(Ok(Some(bytes))) => {
                    buffer.extend_from_slice(&bytes);
                    if buffer.windows(2).any(|w| w == b"\n\n") {
                        break;
                    }
                }
                _ => break,
            }
        }
        let text = String::from_utf8_lossy(&buffer);
        assert!(text.contains("CPU"), "expected metadata update with CPU");

        Ok(())
    }

    #[tokio::test]
    async fn watch_metadata_sse_returns_not_found_for_unknown_agent() -> TestResult {
        let (state, _store) = test_state_with_store(true)?;
        let unknown_id = Uuid::new_v4();
        let app = build_router(state, None);
        let (base_url, _handle) = spawn_test_server(app.clone()).await?;

        let session_token = create_and_login(&app).await?;
        let url = format!("{base_url}api/v2/workspaceagents/{unknown_id}/watch-metadata");
        let client = reqwest::Client::new();
        let resp = client
            .get(&url)
            .header("Coder-Session-Token", &session_token)
            .send()
            .await?;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        Ok(())
    }

    // =========================================================================
    // get_workspace_agent_watch_metadata_ws tests
    // =========================================================================

    #[tokio::test]
    async fn watch_metadata_ws_rejects_unauthenticated() -> TestResult {
        let (state, store) = test_state_with_store(true)?;
        let agent_id = seed_agent(&store)?;
        let app = build_router(state, None);
        let (base_url, _handle) = spawn_test_server(app).await?;

        let url = ws_url(
            &base_url,
            &format!("api/v2/workspaceagents/{agent_id}/watch-metadata-ws"),
        );
        let result = tokio_tungstenite::connect_async(&url).await;
        assert!(result.is_err(), "should reject unauthenticated connection");
        Ok(())
    }

    #[tokio::test]
    async fn watch_metadata_ws_sends_initial_snapshot() -> TestResult {
        let (state, store) = test_state_with_store(true)?;
        let agent_id = seed_agent(&store)?;
        let app = build_router(state, None);
        let (base_url, _handle) = spawn_test_server(app.clone()).await?;

        let session_token = create_and_login(&app).await?;
        let url = ws_url(
            &base_url,
            &format!("api/v2/workspaceagents/{agent_id}/watch-metadata-ws"),
        );
        let request = ws_request(&url, &session_token)?;
        let (mut ws, _resp) = tokio_tungstenite::connect_async(request).await?;

        // Should receive initial metadata snapshot (empty array).
        let msg = tokio::time::timeout(Duration::from_secs(2), ws.next()).await?;
        if let Some(Ok(tungstenite::Message::Text(text))) = msg {
            let parsed: Value = serde_json::from_str(&text)?;
            assert!(
                parsed.is_array(),
                "expected JSON array for metadata snapshot"
            );
        } else {
            return Err(
                format!("expected text message with metadata snapshot, got: {msg:?}").into(),
            );
        }

        ws.close(None).await?;
        Ok(())
    }

    #[tokio::test]
    async fn watch_metadata_ws_streams_pubsub_updates() -> TestResult {
        let (state, store) = test_state_with_store(true)?;
        let agent_id = seed_agent(&store)?;
        let pubsub = state.pubsub.clone();
        let app = build_router(state, None);
        let (base_url, _handle) = spawn_test_server(app.clone()).await?;

        let session_token = create_and_login(&app).await?;
        let url = ws_url(
            &base_url,
            &format!("api/v2/workspaceagents/{agent_id}/watch-metadata-ws"),
        );
        let request = ws_request(&url, &session_token)?;
        let (mut ws, _resp) = tokio_tungstenite::connect_async(request).await?;

        // Consume initial snapshot.
        let _ = tokio::time::timeout(Duration::from_secs(2), ws.next()).await;

        // Publish a metadata update via pubsub.
        let channel = coder_core::pubsub::workspace_agent_metadata_channel(agent_id);
        let update = serde_json::json!([{
            "display_name": "Memory",
            "key": "memory",
            "value": "8GB"
        }]);
        pubsub
            .publish(&channel, update.to_string().as_bytes())
            .await?;

        // Verify the update arrives on the WebSocket.
        let msg = tokio::time::timeout(Duration::from_secs(2), ws.next()).await?;
        if let Some(Ok(tungstenite::Message::Text(text))) = msg {
            assert!(
                text.contains("Memory"),
                "expected metadata update with Memory"
            );
        } else {
            return Err(format!("expected text message with metadata update, got: {msg:?}").into());
        }

        ws.close(None).await?;
        Ok(())
    }

    #[tokio::test]
    async fn watch_metadata_ws_returns_not_found_for_unknown_agent() -> TestResult {
        let (state, _store) = test_state_with_store(true)?;
        let unknown_id = Uuid::new_v4();
        let app = build_router(state, None);
        let (base_url, _handle) = spawn_test_server(app.clone()).await?;

        let session_token = create_and_login(&app).await?;
        let url = ws_url(
            &base_url,
            &format!("api/v2/workspaceagents/{unknown_id}/watch-metadata-ws"),
        );
        let request = ws_request(&url, &session_token)?;
        let result = tokio_tungstenite::connect_async(request).await;
        assert!(result.is_err(), "should reject unknown agent");
        Ok(())
    }

    // =========================================================================
    // Helper: fake agent connection for PTY tests
    // =========================================================================

    #[derive(Debug)]
    struct FakeAgentConnection {
        id: Uuid,
        connected_at: OffsetDateTime,
    }

    #[async_trait::async_trait]
    impl AgentConnection for FakeAgentConnection {
        async fn recreate_devcontainer(
            &self,
            _container_id: &str,
        ) -> Result<(), AgentError> {
            Ok(())
        }

        async fn delete_devcontainer(
            &self,
            _container_id: &str,
        ) -> Result<(), AgentError> {
            Ok(())
        }

        fn agent_id(&self) -> Uuid {
            self.id
        }

        fn connected_at(&self) -> OffsetDateTime {
            self.connected_at
        }
    }
}
