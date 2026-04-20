//! Live implementation of the agent DRPC service.
//!
//! The [`LiveAgentHandler`] implements [`AgentRpcHandler`] against the live
//! [`AppStore`], replacing the `StubHandler` used during Phase 1. The Go
//! reference lives in `coder/coderd/agentapi/` — each method below documents
//! the specific file/function it mirrors.
//!
//! The handler is intentionally thin: it reads from / writes to the store
//! and converts between domain rows and the `coder.agent.v2` protobuf
//! messages. Any behaviour that needs external services (notifications,
//! workspace pubsub, build metrics) is deferred — Phase 2 only requires
//! the four methods called out in the Go server's manifest/banner/startup/
//! app-health paths to return correct data.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use coder_agent_rpc::AgentRpcHandler;
use coder_agent_rpc::handlers::RpcError;
use coder_agent_rpc::proto::agent_v2 as agent;
use coder_agent_rpc::proto::tailnet_v2 as tailnet;
use coder_core::AppStore;
use coder_core::config::DerpRegionConfig;
use coder_core::pubsub::PubSub;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

/// Default agent stats reporting interval. Mirrors
/// `coder/cli/server.go` → `--agent-stats-refresh-interval` default of 30s.
const DEFAULT_AGENT_STATS_REFRESH_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(30);

/// Metadata key size caps from `coder/coderd/agentapi/metadata.go`.
/// Values here must mirror the Go constants so that clients see the same
/// truncation / rejection behaviour.
const MAX_ALL_METADATA_KEYS_LEN: usize = 6144;
const MAX_METADATA_VALUE_LEN: usize = 2048;
const MAX_METADATA_ERROR_LEN: usize = MAX_METADATA_VALUE_LEN;

/// Deployment-level configuration forwarded to the `GetManifest` reply.
///
/// Ports the trailing fields of `coder/coderd/agentapi/manifest.go::ManifestAPI`
/// (`AccessURL`, `AppHostname`, `ExternalAuthConfigs`, `DerpForceWebSockets`,
/// `DerpMapFn`). These values are deployment-wide and do not change across
/// agent connections, so the router-facing constructor in
/// `handlers/agents.rs` captures them from [`crate::app::AppState`] once and
/// hands the snapshot to the handler.
#[derive(Clone, Debug)]
pub(crate) struct ManifestDeploymentConfig {
    /// External access URL for the deployment (e.g. `https://coder.example.com`).
    /// Used to build the `vs_code_port_proxy_uri` scheme/host.
    pub(crate) access_url: Url,
    /// Wildcard app hostname (e.g. `*.apps.example.com`). Empty when
    /// subdomain app routing is disabled; in that case the Go server emits
    /// an empty `vs_code_port_proxy_uri`.
    pub(crate) app_hostname: String,
    /// Number of Git-capable external-auth providers configured for the
    /// deployment. Mirrors the Go `Git()` filter applied over
    /// `ExternalAuthConfigs` in `manifest.go`.
    pub(crate) git_auth_config_count: u32,
    /// `DeploymentValues.DERP.Config.ForceWebSockets` — whether agents must
    /// fall back to WebSocket relays instead of native `Upgrade: derp`.
    pub(crate) derp_force_websockets: bool,
    /// DERP regions advertised to agents. Converted to
    /// `coder.tailnet.v2.DERPMap` at manifest-time.
    pub(crate) derp_regions: Vec<DerpRegionConfig>,
}

/// A concrete [`AgentRpcHandler`] that serves the agent DRPC protocol
/// against a live [`AppStore`]. Scoped to a single agent connection — the
/// agent id is taken from the WebSocket authentication, not from each
/// request (mirroring the Go `AgentFn` closure set up in
/// `coder/coderd/workspaceagentsrpc.go`).
pub(crate) struct LiveAgentHandler {
    pub(crate) agent_id: Uuid,
    pub(crate) store: Arc<dyn AppStore>,
    pub(crate) api_version: String,
    pub(crate) deployment: ManifestDeploymentConfig,
    /// Pubsub handle for publishing workspace/agent events from mutating
    /// RPCs (lifecycle, metadata, logs). Optional — unit tests and older
    /// call sites may omit it.
    pub(crate) pubsub: Option<Arc<dyn PubSub>>,
}

impl LiveAgentHandler {
    pub(crate) fn new(
        agent_id: Uuid,
        store: Arc<dyn AppStore>,
        api_version: String,
        deployment: ManifestDeploymentConfig,
    ) -> Self {
        Self {
            agent_id,
            store,
            api_version,
            deployment,
            pubsub: None,
        }
    }

    /// Attaches a pubsub handle so mutating RPCs can publish change events.
    pub(crate) fn with_pubsub(mut self, pubsub: Arc<dyn PubSub>) -> Self {
        self.pubsub = Some(pubsub);
        self
    }
}

/// Mirrors `coder/coderd/workspaceapps/appurl::SubdomainAppHost`. Returns
/// the app hostname with a port appended when the access URL specifies one
/// and the app host itself does not. An empty `app_hostname` yields `""`.
fn subdomain_app_host(app_hostname: &str, access_url: &Url) -> String {
    if app_hostname.is_empty() {
        return String::new();
    }
    let access_port = access_url.port();
    if let Some(port) = access_port {
        // Parse `https://{host}` to determine if the app host already has a
        // port. If parsing fails we conservatively append the access URL's
        // port, matching the Go fallback on `url.Parse` error.
        let parse_attempt = Url::parse(&format!("https://{app_hostname}"));
        let app_has_port = parse_attempt.as_ref().is_ok_and(|u| u.port().is_some());
        if !app_has_port {
            return format!("{app_hostname}:{port}");
        }
    }
    app_hostname.to_owned()
}

/// Builds the VS Code port-proxy URI advertised to agents, matching
/// `coder/coderd/agentapi/manifest.go::vscodeProxyURI`.
///
/// Returns an empty string when `app_hostname` is empty (subdomain apps
/// disabled). The produced string replaces every `*` in the wildcard app
/// host with the template `{{port}}--{agent}--{workspace}--{owner}`; the
/// literal `{{port}}` placeholder is later substituted by the VS Code
/// extension at connect time.
fn build_vscode_port_proxy_uri(
    access_url: &Url,
    app_hostname: &str,
    agent_name: &str,
    workspace_name: &str,
    owner_username: &str,
) -> String {
    if app_hostname.is_empty() {
        return String::new();
    }
    let host = subdomain_app_host(app_hostname, access_url);
    let app_str = format!("{{{{port}}}}--{agent_name}--{workspace_name}--{owner_username}");
    let replaced = host.replace('*', &app_str);
    format!("{}://{replaced}", access_url.scheme())
}

/// Converts the Rust [`DerpRegionConfig`] slice into the protobuf
/// `coder.tailnet.v2.DERPMap` expected by the agent manifest.
///
/// Mirrors `coder/tailnet.DERPMapToProto` over the deployment's configured
/// regions/nodes, matching the Rust-side translation in
/// `handlers/agents.rs::build_workspace_agent_connection_info` so direct
/// and proxied clients see the same topology.
fn build_derp_map_proto(regions: &[DerpRegionConfig]) -> tailnet::DerpMap {
    let mut proto_regions = HashMap::with_capacity(regions.len());
    for region in regions {
        let nodes: Vec<tailnet::derp_map::region::Node> = region
            .nodes
            .iter()
            .map(|node| tailnet::derp_map::region::Node {
                name: node.name.clone(),
                region_id: i64::from(region.id),
                host_name: node.url.host_str().unwrap_or_default().to_owned(),
                cert_name: String::new(),
                ipv4: String::new(),
                ipv6: String::new(),
                stun_port: 3478,
                stun_only: false,
                derp_port: node.url.port_or_known_default().map_or(443, i32::from),
                insecure_for_tests: false,
                force_http: node.url.scheme() == "http",
                stun_test_ip: String::new(),
                can_port_80: false,
            })
            .collect();
        proto_regions.insert(
            i64::from(region.id),
            tailnet::derp_map::Region {
                region_id: i64::from(region.id),
                embedded_relay: false,
                region_code: region.name.to_lowercase().replace(' ', "-"),
                region_name: region.name.clone(),
                avoid: false,
                nodes,
            },
        );
    }
    tailnet::DerpMap {
        home_params: None,
        regions: proto_regions,
    }
}

/// Mirrors `codersdk::EnhancedExternalAuthProvider::Git`. Returns `true`
/// for the set of providers the Go SDK tags as Git-capable.
pub(crate) fn is_git_external_auth_provider(provider_type: &str) -> bool {
    matches!(
        provider_type,
        "github"
            | "gitlab"
            | "bitbucket-cloud"
            | "bitbucket-server"
            | "azure-devops"
            | "azure-devops-entra"
            | "gitea"
    )
}

/// Snapshot the deployment-level manifest inputs from the shared
/// [`crate::app::AppState`]. Called once per WebSocket upgrade so the
/// per-connection [`LiveAgentHandler`] does not need to clone the whole
/// state on every `GetManifest` call.
pub(crate) fn build_manifest_deployment_config(
    state: &crate::app::AppState,
) -> ManifestDeploymentConfig {
    let git_auth_config_count = u32::try_from(
        state
            .config
            .external_auth_providers
            .iter()
            .filter(|p| is_git_external_auth_provider(&p.provider_type))
            .count(),
    )
    .unwrap_or(u32::MAX);

    ManifestDeploymentConfig {
        access_url: state.config.access_url.clone(),
        app_hostname: state.config.wildcard_access_url.clone(),
        git_auth_config_count,
        derp_force_websockets: state.config.derp_force_websockets,
        derp_regions: state.config.derp_regions.clone(),
    }
}

/// Maps the on-the-wire `AppHealth` enum to the database enum string used by
/// `UPDATE workspace_apps SET health = $2`.
///
/// Ports `coder/coderd/agentapi/apps.go` lines 79–91 (`BatchUpdateAppHealths`
/// switch on `update.Health`).
fn app_health_proto_to_db(value: i32) -> Option<&'static str> {
    match agent::AppHealth::try_from(value).ok()? {
        agent::AppHealth::Disabled => Some("disabled"),
        agent::AppHealth::Initializing => Some("initializing"),
        agent::AppHealth::Healthy => Some("healthy"),
        agent::AppHealth::Unhealthy => Some("unhealthy"),
        agent::AppHealth::Unspecified => None,
    }
}

/// Maps the database `workspace_app_health` enum string to the on-the-wire
/// enum used by `Manifest.apps[].health`.
fn app_health_db_to_proto(value: &str) -> i32 {
    let h = match value {
        "disabled" => agent::AppHealth::Disabled,
        "initializing" => agent::AppHealth::Initializing,
        "healthy" => agent::AppHealth::Healthy,
        "unhealthy" => agent::AppHealth::Unhealthy,
        _ => agent::AppHealth::Unspecified,
    };
    h as i32
}

/// Maps the database `workspace_app_sharing_level` enum string to the
/// on-the-wire `WorkspaceApp.SharingLevel` enum.
fn sharing_level_db_to_proto(value: &str) -> i32 {
    let l = match value {
        "owner" => agent::workspace_app::SharingLevel::Owner,
        "authenticated" => agent::workspace_app::SharingLevel::Authenticated,
        "public" => agent::workspace_app::SharingLevel::Public,
        "organization" => agent::workspace_app::SharingLevel::Organization,
        _ => agent::workspace_app::SharingLevel::Unspecified,
    };
    l as i32
}

/// Maps a `Startup.Subsystem` enum value to its database string form.
///
/// Mirrors `coder/coderd/agentapi/lifecycle.go` L168-L179 which rejects
/// unknown subsystems — we return `None` to trigger `InvalidArgument`.
fn subsystem_proto_to_db(value: i32) -> Option<&'static str> {
    match agent::startup::Subsystem::try_from(value).ok()? {
        agent::startup::Subsystem::Envbox => Some("envbox"),
        agent::startup::Subsystem::Envbuilder => Some("envbuilder"),
        agent::startup::Subsystem::Exectrace => Some("exectrace"),
        agent::startup::Subsystem::Unspecified => None,
    }
}

#[async_trait]
impl AgentRpcHandler for LiveAgentHandler {
    /// Ports `coder/coderd/agentapi/manifest.go::GetManifest`.
    async fn get_manifest(
        &self,
        _req: agent::GetManifestRequest,
    ) -> Result<agent::Manifest, RpcError> {
        let agent_row = self
            .store
            .find_workspace_agent_by_id(self.agent_id)
            .await
            .map_err(|e| RpcError::Internal(format!("find agent: {e}")))?
            .ok_or_else(|| RpcError::Internal("workspace agent not found".into()))?;

        let workspace = self
            .store
            .find_workspace_by_agent_id(self.agent_id)
            .await
            .map_err(|e| RpcError::Internal(format!("find workspace: {e}")))?
            .ok_or_else(|| RpcError::Internal("workspace not found for agent".into()))?;

        let owner_username = self
            .store
            .find_user_by_id(workspace.owner_id)
            .await
            .map_err(|e| RpcError::Internal(format!("find owner: {e}")))?
            .map(|u| u.username)
            .unwrap_or_default();

        let apps = self
            .store
            .list_workspace_apps_by_agent_id(self.agent_id)
            .await
            .map_err(|e| RpcError::Internal(format!("list apps: {e}")))?;

        let scripts = self
            .store
            .list_workspace_agent_scripts(self.agent_id)
            .await
            .map_err(|e| RpcError::Internal(format!("list scripts: {e}")))?;

        let metadata = self
            .store
            .list_workspace_agent_metadata(self.agent_id)
            .await
            .map_err(|e| RpcError::Internal(format!("list metadata: {e}")))?;

        let devcontainers = self
            .store
            .list_workspace_agent_devcontainers(self.agent_id)
            .await
            .map_err(|e| RpcError::Internal(format!("list devcontainers: {e}")))?;

        // Environment variables — stored as JSON in the DB. If parsing fails
        // we return empty rather than a hard error; this matches the Go
        // helper `db2sdk.WorkspaceAgentEnvironment` which silently defaults
        // on an empty column.
        let environment_variables: HashMap<String, String> = agent_row
            .environment_variables
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_default();

        let apps_proto: Vec<agent::WorkspaceApp> = apps
            .into_iter()
            .map(|a| agent::WorkspaceApp {
                id: a.id.as_bytes().to_vec(),
                url: a.url.unwrap_or_default(),
                external: a.external,
                slug: a.slug,
                display_name: a.display_name,
                command: a.command.unwrap_or_default(),
                icon: a.icon,
                subdomain: a.subdomain,
                subdomain_name: String::new(),
                sharing_level: sharing_level_db_to_proto(&a.sharing_level),
                healthcheck: Some(agent::workspace_app::Healthcheck {
                    url: a.healthcheck_url,
                    interval: Some(prost_types::Duration {
                        seconds: i64::from(a.healthcheck_interval),
                        nanos: 0,
                    }),
                    threshold: a.healthcheck_threshold,
                }),
                health: app_health_db_to_proto(&a.health),
                hidden: a.hidden,
            })
            .collect();

        let scripts_proto: Vec<agent::WorkspaceAgentScript> = scripts
            .into_iter()
            .map(|s| agent::WorkspaceAgentScript {
                id: s.id.as_bytes().to_vec(),
                log_source_id: s.log_source_id.as_bytes().to_vec(),
                log_path: s.log_path,
                script: s.script,
                cron: s.cron,
                run_on_start: s.run_on_start,
                run_on_stop: s.run_on_stop,
                start_blocks_login: s.start_blocks_login,
                timeout: Some(prost_types::Duration {
                    seconds: i64::from(s.timeout_seconds),
                    nanos: 0,
                }),
                display_name: s.display_name,
            })
            .collect();

        let metadata_proto: Vec<agent::workspace_agent_metadata::Description> = metadata
            .into_iter()
            .map(|m| agent::workspace_agent_metadata::Description {
                display_name: m.display_name,
                key: m.key,
                script: m.script,
                interval: Some(prost_types::Duration {
                    seconds: m.interval,
                    nanos: 0,
                }),
                timeout: Some(prost_types::Duration {
                    seconds: m.timeout,
                    nanos: 0,
                }),
            })
            .collect();

        let devcontainers_proto: Vec<agent::WorkspaceAgentDevcontainer> = devcontainers
            .into_iter()
            .map(|d| agent::WorkspaceAgentDevcontainer {
                id: d.id.as_bytes().to_vec(),
                workspace_folder: d.workspace_folder,
                config_path: d.config_path,
                name: d.name,
                subagent_id: d.subagent_id.map(|id| id.as_bytes().to_vec()),
            })
            .collect();

        // Build the VS Code port-proxy URI. When `app_hostname` is empty
        // (subdomain apps disabled) this returns "" — matching Go.
        let vscode_proxy_uri = build_vscode_port_proxy_uri(
            &self.deployment.access_url,
            &self.deployment.app_hostname,
            &agent_row.name,
            &workspace.name,
            &owner_username,
        );

        let derp_map = build_derp_map_proto(&self.deployment.derp_regions);

        Ok(agent::Manifest {
            agent_id: agent_row.id.as_bytes().to_vec(),
            agent_name: agent_row.name,
            owner_username,
            workspace_id: workspace.id.as_bytes().to_vec(),
            workspace_name: workspace.name,
            git_auth_configs: self.deployment.git_auth_config_count,
            environment_variables,
            directory: agent_row.directory,
            vs_code_port_proxy_uri: vscode_proxy_uri,
            motd_path: agent_row.motd_file,
            disable_direct_connections: false,
            derp_force_websockets: self.deployment.derp_force_websockets,
            parent_id: agent_row.parent_id.map(|id| id.as_bytes().to_vec()),
            derp_map: Some(derp_map),
            scripts: scripts_proto,
            apps: apps_proto,
            metadata: metadata_proto,
            devcontainers: devcontainers_proto,
        })
    }

    /// Ports `coder/coderd/agentapi/announcement_banners.go::GetAnnouncementBanners`.
    async fn get_announcement_banners(
        &self,
        _req: agent::GetAnnouncementBannersRequest,
    ) -> Result<agent::GetAnnouncementBannersResponse, RpcError> {
        let cfg = self
            .store
            .appearance_config()
            .await
            .map_err(|e| RpcError::Internal(format!("fetch appearance: {e}")))?;

        let announcement_banners: Vec<agent::BannerConfig> = cfg
            .announcement_banners
            .into_iter()
            .map(|b| agent::BannerConfig {
                enabled: b.enabled,
                message: b.message,
                background_color: b.background_color,
            })
            .collect();

        Ok(agent::GetAnnouncementBannersResponse {
            announcement_banners,
        })
    }

    /// Ports `coder/coderd/agentapi/lifecycle.go::UpdateStartup`.
    async fn update_startup(
        &self,
        req: agent::UpdateStartupRequest,
    ) -> Result<agent::Startup, RpcError> {
        let startup = req
            .startup
            .ok_or_else(|| RpcError::InvalidArgument("startup is required".into()))?;

        // Validate subsystems + dedupe while preserving the Go server's
        // "reject unknown" semantics.
        let mut seen: std::collections::BTreeSet<&'static str> = std::collections::BTreeSet::new();
        for s in &startup.subsystems {
            let Some(db) = subsystem_proto_to_db(*s) else {
                return Err(RpcError::InvalidArgument(format!(
                    "invalid agent subsystem {s}"
                )));
            };
            seen.insert(db);
        }
        let subsystems: Vec<&str> = seen.iter().copied().collect();

        self.store
            .update_workspace_agent_startup(
                self.agent_id,
                &startup.version,
                &startup.expanded_directory,
                &subsystems,
                &self.api_version,
            )
            .await
            .map_err(|e| RpcError::Internal(format!("update startup: {e}")))?;

        Ok(startup)
    }

    /// Ports `coder/coderd/agentapi/apps.go::BatchUpdateAppHealths`.
    async fn batch_update_app_health(
        &self,
        req: agent::BatchUpdateAppHealthRequest,
    ) -> Result<agent::BatchUpdateAppHealthResponse, RpcError> {
        if req.updates.is_empty() {
            return Ok(agent::BatchUpdateAppHealthResponse::default());
        }

        let apps = self
            .store
            .list_workspace_apps_by_agent_id(self.agent_id)
            .await
            .map_err(|e| RpcError::Internal(format!("list apps: {e}")))?;

        for update in req.updates {
            let id = Uuid::from_slice(&update.id)
                .map_err(|e| RpcError::InvalidArgument(format!("parse workspace app ID: {e}")))?;

            let Some(old) = apps.iter().find(|a| a.id == id) else {
                return Err(RpcError::InvalidArgument(format!(
                    "workspace app ID {id} not found"
                )));
            };

            if old.healthcheck_url.is_empty() {
                return Err(RpcError::InvalidArgument(format!(
                    "workspace app {} ({}) does not have healthchecks enabled",
                    id, old.slug
                )));
            }

            let Some(new_health) = app_health_proto_to_db(update.health) else {
                return Err(RpcError::InvalidArgument(format!(
                    "unknown health status for app {} ({})",
                    id, old.slug
                )));
            };

            if old.health == new_health {
                continue;
            }

            self.store
                .update_workspace_app_health(id, new_health)
                .await
                .map_err(|e| {
                    RpcError::Internal(format!("update workspace app health for {id}: {e}"))
                })?;
        }

        Ok(agent::BatchUpdateAppHealthResponse::default())
    }

    /// Ports `coder/coderd/agentapi/stats.go::UpdateStats`.
    ///
    /// Stats are persisted to `workspace_agent_stats` via
    /// [`AppStore::insert_workspace_agent_stat`]. An empty request body (no
    /// `stats` payload) simply returns the refresh interval, matching the
    /// "report interval poll" behaviour of the Go handler.
    async fn update_stats(
        &self,
        req: agent::UpdateStatsRequest,
    ) -> Result<agent::UpdateStatsResponse, RpcError> {
        let response = agent::UpdateStatsResponse {
            report_interval: Some(prost_types::Duration {
                seconds: DEFAULT_AGENT_STATS_REFRESH_INTERVAL.as_secs() as i64,
                nanos: 0,
            }),
        };

        let Some(stats) = req.stats else {
            // Empty body — agent is just asking for the reporting interval.
            return Ok(response);
        };

        // Resolve owning workspace so we can populate user/workspace/template.
        let workspace = self
            .store
            .find_workspace_by_agent_id(self.agent_id)
            .await
            .map_err(|e| RpcError::Internal(format!("find workspace: {e}")))?;
        let (user_id, workspace_id, template_id) = match workspace.as_ref() {
            Some(w) => (Some(w.owner_id), Some(w.id), Some(w.template_id)),
            None => (None, None, None),
        };

        let connections_by_proto = serde_json::to_value(&stats.connections_by_proto)
            .unwrap_or_else(|_| serde_json::Value::Object(serde_json::Map::new()));

        let input = coder_core::WorkspaceAgentStatInput {
            id: Uuid::new_v4(),
            created_at: OffsetDateTime::now_utc(),
            user_id,
            workspace_id,
            template_id,
            agent_id: self.agent_id,
            connections_by_proto,
            connection_count: stats.connection_count,
            rx_packets: stats.rx_packets,
            rx_bytes: stats.rx_bytes,
            tx_packets: stats.tx_packets,
            tx_bytes: stats.tx_bytes,
            session_count_vscode: stats.session_count_vscode,
            session_count_jetbrains: stats.session_count_jetbrains,
            session_count_reconnecting_pty: stats.session_count_reconnecting_pty,
            session_count_ssh: stats.session_count_ssh,
            connection_median_latency_ms: stats.connection_median_latency_ms,
            usage: false,
        };

        self.store
            .insert_workspace_agent_stat(&input)
            .await
            .map_err(|e| RpcError::Internal(format!("insert agent stats: {e}")))?;

        Ok(response)
    }

    /// Ports `coder/coderd/agentapi/lifecycle.go::UpdateLifecycle`.
    ///
    /// Persists the agent's lifecycle state, deriving `started_at`/`ready_at`
    /// from the reported transition, then publishes an
    /// `AgentLifecycleUpdate` pubsub event when a handle is attached.
    async fn update_lifecycle(
        &self,
        req: agent::UpdateLifecycleRequest,
    ) -> Result<agent::Lifecycle, RpcError> {
        let lifecycle = req
            .lifecycle
            .ok_or_else(|| RpcError::InvalidArgument("lifecycle is required".into()))?;

        let state_str = match agent::lifecycle::State::try_from(lifecycle.state) {
            Ok(agent::lifecycle::State::Created) => "created",
            Ok(agent::lifecycle::State::Starting) => "starting",
            Ok(agent::lifecycle::State::StartTimeout) => "start_timeout",
            Ok(agent::lifecycle::State::StartError) => "start_error",
            Ok(agent::lifecycle::State::Ready) => "ready",
            Ok(agent::lifecycle::State::ShuttingDown) => "shutting_down",
            Ok(agent::lifecycle::State::ShutdownTimeout) => "shutdown_timeout",
            Ok(agent::lifecycle::State::ShutdownError) => "shutdown_error",
            Ok(agent::lifecycle::State::Off) => "off",
            Ok(agent::lifecycle::State::Unspecified) | Err(_) => {
                return Err(RpcError::InvalidArgument(format!(
                    "unknown lifecycle state {}",
                    lifecycle.state
                )));
            }
        };

        // Derive started_at / ready_at transitions, mirroring the Go handler
        // at coder/coderd/agentapi/lifecycle.go L95-L108.
        let now = OffsetDateTime::now_utc();
        let changed_at = lifecycle
            .changed_at
            .as_ref()
            .and_then(proto_timestamp_to_time)
            .unwrap_or(now);

        let (started_at, ready_at) = match state_str {
            "starting" => (Some(changed_at), None),
            "ready" | "start_timeout" | "start_error" => (Some(changed_at), Some(changed_at)),
            _ => (None, None),
        };

        self.store
            .update_workspace_agent_lifecycle_state(self.agent_id, state_str, started_at, ready_at)
            .await
            .map_err(|e| RpcError::Internal(format!("update lifecycle: {e}")))?;

        if let Some(pubsub) = self.pubsub.as_ref() {
            let channel = coder_core::pubsub::workspace_agent_channel(self.agent_id);
            let _ = pubsub.publish(&channel, b"lifecycle_update").await;
        }

        Ok(agent::Lifecycle {
            state: lifecycle.state,
            changed_at: Some(prost_types::Timestamp {
                seconds: changed_at.unix_timestamp(),
                nanos: changed_at.nanosecond() as i32,
            }),
        })
    }

    /// Ports `coder/coderd/agentapi/logs.go::BatchCreateLogs`.
    ///
    /// The handler reuses the same `insert_workspace_agent_logs` store call
    /// as the HTTP `PATCH /workspaceagents/me/logs` endpoint and publishes
    /// new log entries onto the per-agent log channel.
    async fn batch_create_logs(
        &self,
        req: agent::BatchCreateLogsRequest,
    ) -> Result<agent::BatchCreateLogsResponse, RpcError> {
        if req.logs.is_empty() {
            return Ok(agent::BatchCreateLogsResponse::default());
        }

        let agent_row = self
            .store
            .find_workspace_agent_by_id(self.agent_id)
            .await
            .map_err(|e| RpcError::Internal(format!("find agent: {e}")))?
            .ok_or_else(|| RpcError::Internal("workspace agent not found".into()))?;
        if agent_row.logs_overflowed {
            return Ok(agent::BatchCreateLogsResponse {
                log_limit_exceeded: true,
            });
        }

        let log_source_id = Uuid::from_slice(&req.log_source_id)
            .map_err(|e| RpcError::InvalidArgument(format!("parse log source id: {e}")))?;

        let now = OffsetDateTime::now_utc();
        let entries: Vec<coder_core::InsertAgentLogInput> = req
            .logs
            .into_iter()
            .map(|entry| coder_core::InsertAgentLogInput {
                created_at: entry
                    .created_at
                    .as_ref()
                    .and_then(proto_timestamp_to_time)
                    .unwrap_or(now),
                output: entry.output,
                // Default unknown levels to "info" to match the Go handler's
                // tolerant behaviour for older clients.
                level: match agent::log::Level::try_from(entry.level) {
                    Ok(agent::log::Level::Trace) => "trace".to_owned(),
                    Ok(agent::log::Level::Debug) => "debug".to_owned(),
                    Ok(agent::log::Level::Warn) => "warn".to_owned(),
                    Ok(agent::log::Level::Error) => "error".to_owned(),
                    _ => "info".to_owned(),
                },
            })
            .collect();

        let inserted = self
            .store
            .insert_workspace_agent_logs(self.agent_id, log_source_id, &entries)
            .await
            .map_err(|e| RpcError::Internal(format!("insert agent logs: {e}")))?;

        if let Some(pubsub) = self.pubsub.as_ref() {
            let channel = coder_core::pubsub::workspace_agent_logs_channel(self.agent_id);
            for row in &inserted {
                let api_log = coder_core::api::WorkspaceAgentLog {
                    id: row.id,
                    created_at: row.created_at,
                    output: row.output.clone(),
                    level: db_log_level_to_api(&row.level),
                    source_id: row.log_source_id,
                };
                let payload = serde_json::to_vec(&api_log).unwrap_or_default();
                let _ = pubsub.publish(&channel, &payload).await;
            }
        }

        Ok(agent::BatchCreateLogsResponse {
            log_limit_exceeded: false,
        })
    }

    /// Ports `coder/coderd/agentapi/metadata.go::BatchUpdateMetadata`.
    ///
    /// Performs the same key-length cap and value/error truncation as the
    /// Go handler, then upserts via
    /// [`AppStore::upsert_workspace_agent_metadata`] and publishes a
    /// metadata-change event.
    async fn batch_update_metadata(
        &self,
        req: agent::BatchUpdateMetadataRequest,
    ) -> Result<agent::BatchUpdateMetadataResponse, RpcError> {
        let collected_at = OffsetDateTime::now_utc();
        let mut all_keys_len = 0usize;
        let mut entries: Vec<coder_core::UpsertAgentMetadataEntry> =
            Vec::with_capacity(req.metadata.len());
        let mut overflow = false;
        for md in req.metadata {
            all_keys_len = all_keys_len.saturating_add(md.key.len());
            if all_keys_len > MAX_ALL_METADATA_KEYS_LEN {
                overflow = true;
                break;
            }
            let (value, mut error) = match md.result {
                Some(r) => (r.value, r.error),
                None => (String::new(), String::new()),
            };

            // Overwrite `error` if the value or error payload is oversized,
            // mirroring the Go handler.
            let value = if value.len() > MAX_METADATA_VALUE_LEN {
                error = format!(
                    "value of {} bytes exceeded {} bytes",
                    value.len(),
                    MAX_METADATA_VALUE_LEN
                );
                value.chars().take(MAX_METADATA_VALUE_LEN).collect()
            } else {
                value
            };
            let error = if error.len() > MAX_METADATA_ERROR_LEN {
                format!(
                    "error of {} bytes exceeded {} bytes",
                    error.len(),
                    MAX_METADATA_ERROR_LEN
                )
            } else {
                error
            };

            entries.push(coder_core::UpsertAgentMetadataEntry {
                key: md.key,
                value,
                error,
                // Ignore the agent-provided collected_at to avoid clock skew,
                // per the Go handler.
                collected_at,
            });
        }

        if !entries.is_empty() {
            self.store
                .upsert_workspace_agent_metadata(self.agent_id, &entries)
                .await
                .map_err(|e| RpcError::Internal(format!("upsert metadata: {e}")))?;

            if let Some(pubsub) = self.pubsub.as_ref() {
                let channel = coder_core::pubsub::workspace_agent_metadata_channel(self.agent_id);
                let _ = pubsub.publish(&channel, b"metadata_update").await;
            }
        }

        if overflow {
            return Err(RpcError::InvalidArgument(format!(
                "metadata keys of {} bytes exceeded {} bytes",
                all_keys_len, MAX_ALL_METADATA_KEYS_LEN
            )));
        }

        Ok(agent::BatchUpdateMetadataResponse::default())
    }

    /// Ports `coder/coderd/agentapi/scripts.go::ScriptCompleted`.
    async fn script_completed(
        &self,
        req: agent::WorkspaceAgentScriptCompletedRequest,
    ) -> Result<agent::WorkspaceAgentScriptCompletedResponse, RpcError> {
        let timing = req
            .timing
            .ok_or_else(|| RpcError::InvalidArgument("script timing is required".into()))?;

        let script_id = Uuid::from_slice(&timing.script_id)
            .map_err(|e| RpcError::InvalidArgument(format!("script id from bytes: {e}")))?;

        let start = timing
            .start
            .as_ref()
            .and_then(proto_timestamp_to_time)
            .ok_or_else(|| {
                RpcError::InvalidArgument("script start time is required and cannot be zero".into())
            })?;
        let end = timing
            .end
            .as_ref()
            .and_then(proto_timestamp_to_time)
            .ok_or_else(|| {
                RpcError::InvalidArgument("script end time is required and cannot be zero".into())
            })?;
        if start > end {
            return Err(RpcError::InvalidArgument(
                "script start time cannot be after end time".into(),
            ));
        }

        let stage = match agent::timing::Stage::try_from(timing.stage) {
            Ok(agent::timing::Stage::Start) => "start",
            Ok(agent::timing::Stage::Stop) => "stop",
            Ok(agent::timing::Stage::Cron) => "cron",
            Err(_) => {
                return Err(RpcError::InvalidArgument(format!(
                    "unknown timing stage {}",
                    timing.stage
                )));
            }
        };
        let status = match agent::timing::Status::try_from(timing.status) {
            Ok(agent::timing::Status::Ok) => "ok",
            Ok(agent::timing::Status::ExitFailure) => "exit_failure",
            Ok(agent::timing::Status::TimedOut) => "timed_out",
            Ok(agent::timing::Status::PipesLeftOpen) => "pipes_left_open",
            Err(_) => {
                return Err(RpcError::InvalidArgument(format!(
                    "unknown timing status {}",
                    timing.status
                )));
            }
        };

        self.store
            .insert_workspace_agent_script_timing(&coder_core::InsertAgentScriptTimingInput {
                script_id,
                started_at: start,
                ended_at: end,
                exit_code: timing.exit_code,
                stage: stage.to_owned(),
                status: status.to_owned(),
            })
            .await
            .map_err(|e| RpcError::Internal(format!("insert script timing: {e}")))?;

        Ok(agent::WorkspaceAgentScriptCompletedResponse::default())
    }

    /// Ports the deprecated `coder/coderd/agentapi/announcement_banners.go::
    /// GetServiceBanner` legacy RPC. Reads from the same appearance config as
    /// [`get_announcement_banners`](#method.get_announcement_banners) and
    /// returns the `ServiceBanner` from the appearance config — falling back
    /// to the first announcement banner when the dedicated service banner
    /// is empty, which matches the Go helper `agentsdk.ProtoFromServiceBanner`.
    async fn get_service_banner(
        &self,
        _req: agent::GetServiceBannerRequest,
    ) -> Result<agent::ServiceBanner, RpcError> {
        let cfg = self
            .store
            .appearance_config()
            .await
            .map_err(|e| RpcError::Internal(format!("fetch appearance: {e}")))?;

        if cfg.service_banner.enabled
            || !cfg.service_banner.message.is_empty()
            || !cfg.service_banner.background_color.is_empty()
        {
            return Ok(agent::ServiceBanner {
                enabled: cfg.service_banner.enabled,
                message: cfg.service_banner.message,
                background_color: cfg.service_banner.background_color,
            });
        }
        if let Some(first) = cfg.announcement_banners.first() {
            return Ok(agent::ServiceBanner {
                enabled: first.enabled,
                message: first.message.clone(),
                background_color: first.background_color.clone(),
            });
        }
        Ok(agent::ServiceBanner::default())
    }

    /// Ports `coder/coderd/agentapi/connectionlog.go::ReportConnection`.
    ///
    /// Decodes the `Connection` payload, resolves the workspace / agent
    /// metadata required for the denormalized `connection_logs` columns,
    /// and upserts via [`AppStore::insert_connection_log`]. Nil /
    /// unparseable connection IDs are rejected per the Go handler. The
    /// structured-enum logging kept from PR #260 remains — it is useful
    /// even after persistence lands because the log is emitted at `info`
    /// regardless of database success.
    async fn report_connection(&self, req: agent::ReportConnectionRequest) -> Result<(), RpcError> {
        let connection = req
            .connection
            .ok_or_else(|| RpcError::InvalidArgument("connection is required".into()))?;
        let connection_id = Uuid::from_slice(&connection.id)
            .map_err(|e| RpcError::InvalidArgument(format!("connection id from bytes: {e}")))?;
        if connection_id.is_nil() {
            return Err(RpcError::InvalidArgument(
                "connection ID cannot be nil".into(),
            ));
        }

        // The enums live on the nested `Connection` message. `as_str_name()`
        // (prost-generated) gives us stable PROTO field names to log
        // instead of raw i32 values.
        let action_proto =
            agent::connection::Action::try_from(connection.action).map_err(|_| {
                RpcError::InvalidArgument(format!(
                    "unknown connection action: {}",
                    connection.action
                ))
            })?;
        let status = match action_proto {
            agent::connection::Action::Connect => "connected",
            agent::connection::Action::Disconnect => "disconnected",
            agent::connection::Action::Unspecified => {
                return Err(RpcError::InvalidArgument(
                    "connection action unspecified".into(),
                ));
            }
        };

        let type_proto = agent::connection::Type::try_from(connection.r#type).map_err(|_| {
            RpcError::InvalidArgument(format!("unknown connection type: {}", connection.r#type))
        })?;
        let connection_type = match type_proto {
            agent::connection::Type::Ssh => "ssh",
            agent::connection::Type::Vscode => "vscode",
            agent::connection::Type::Jetbrains => "jetbrains",
            agent::connection::Type::ReconnectingPty => "reconnecting_pty",
            agent::connection::Type::Unspecified => {
                return Err(RpcError::InvalidArgument(
                    "connection type unspecified".into(),
                ));
            }
        };

        // Resolve the agent + workspace so we can denormalize name /
        // organization / owner into the connection_logs row. Matches the
        // Go handler's `a.AgentFn(ctx)` + `GetWorkspaceByAgentID` path.
        let agent_row = self
            .store
            .find_workspace_agent_by_id(self.agent_id)
            .await
            .map_err(|e| RpcError::Internal(format!("find agent: {e}")))?
            .ok_or_else(|| RpcError::Internal("workspace agent not found".into()))?;
        let workspace = self
            .store
            .find_workspace_by_agent_id(self.agent_id)
            .await
            .map_err(|e| RpcError::Internal(format!("find workspace: {e}")))?
            .ok_or_else(|| RpcError::Internal("workspace not found for agent".into()))?;

        // Some older clients incorrectly report "localhost". Mirrors
        // `connectionlog.go` L85-L88 (github.com/coder/coder#20194).
        let log_ip = if connection.ip == "localhost" {
            "127.0.0.1".to_owned()
        } else {
            connection.ip.clone()
        };

        let reason = connection.reason.clone().unwrap_or_default();
        let time = connection
            .timestamp
            .and_then(|ts| {
                OffsetDateTime::from_unix_timestamp(ts.seconds)
                    .ok()
                    .map(|t| t + time::Duration::nanoseconds(i64::from(ts.nanos)))
            })
            .unwrap_or_else(OffsetDateTime::now_utc);

        let code = if matches!(action_proto, agent::connection::Action::Disconnect) {
            Some(connection.status_code)
        } else {
            None
        };

        tracing::info!(
            agent_id = %self.agent_id,
            connection_id = %connection_id,
            action = action_proto.as_str_name(),
            r#type = type_proto.as_str_name(),
            ip = %connection.ip,
            status_code = connection.status_code,
            "agent report_connection",
        );

        self.store
            .insert_connection_log(coder_core::InsertConnectionLogInput {
                id: Uuid::new_v4(),
                time,
                connection_status: status.to_owned(),
                organization_id: workspace.organization_id,
                workspace_owner_id: workspace.owner_id,
                workspace_id: workspace.id,
                workspace_name: workspace.name,
                agent_name: agent_row.name,
                connection_type: connection_type.to_owned(),
                ip: log_ip,
                code,
                // Agent RPC reports SSH-like connections only — user_agent
                // / user_id / slug_or_port are the preserve of the web
                // workspace-app handlers, not this path.
                user_agent: None,
                user_id: None,
                slug_or_port: None,
                connection_id: Some(connection_id),
                disconnect_reason: if reason.is_empty() {
                    None
                } else {
                    Some(reason)
                },
            })
            .await
            .map_err(|e| RpcError::Internal(format!("insert connection log: {e}")))?;

        Ok(())
    }

    /// Ports `coder/coderd/agentapi/resources_monitoring.go::
    /// GetResourcesMonitoringConfiguration`.
    ///
    /// The persisted `workspace_agent_*_resource_monitors` tables are not
    /// yet ported, so we return Go's static defaults:
    /// - `num_datapoints = 20`, `collection_interval_seconds = 10`
    /// - `memory = None`, `volumes = []` (monitors unconfigured).
    async fn get_resources_monitoring_configuration(
        &self,
        _req: agent::GetResourcesMonitoringConfigurationRequest,
    ) -> Result<agent::GetResourcesMonitoringConfigurationResponse, RpcError> {
        Ok(agent::GetResourcesMonitoringConfigurationResponse {
            config: Some(
                agent::get_resources_monitoring_configuration_response::Config {
                    num_datapoints: 20,
                    collection_interval_seconds: 10,
                },
            ),
            memory: None,
            volumes: Vec::new(),
        })
    }

    /// Ports `coder/coderd/agentapi/resources_monitoring.go::
    /// PushResourcesMonitoringUsage`.
    ///
    /// The `workspace_agent_*_resource_monitors` tables aren't ported, so we
    /// just log the batch size and return OK. Matches the Go handler when
    /// no monitors are configured (it performs a no-op through
    /// `monitorMemory` / `monitorVolumes`).
    async fn push_resources_monitoring_usage(
        &self,
        req: agent::PushResourcesMonitoringUsageRequest,
    ) -> Result<agent::PushResourcesMonitoringUsageResponse, RpcError> {
        tracing::info!(
            agent_id = %self.agent_id,
            datapoints = req.datapoints.len(),
            "agent push_resources_monitoring_usage (persistence deferred)",
        );
        Ok(agent::PushResourcesMonitoringUsageResponse::default())
    }

    /// Ports `coder/coderd/agentapi/subagent.go::CreateSubAgent`.
    ///
    /// TODO-sub-agent-create: the `insert_workspace_agent` AppStore method
    /// is not yet present, so we return `Unimplemented` rather than silently
    /// succeeding. The router still advertises the RPC so clients can tell
    /// the difference between "not yet supported" and "unknown endpoint".
    async fn create_sub_agent(
        &self,
        _req: agent::CreateSubAgentRequest,
    ) -> Result<agent::CreateSubAgentResponse, RpcError> {
        Err(RpcError::Unimplemented(
            "CreateSubAgent (sub-agent persistence not yet ported)".into(),
        ))
    }

    /// Ports `coder/coderd/agentapi/subagent.go::DeleteSubAgent`.
    ///
    /// Looks up the sub-agent and rejects with `InvalidArgument` if its
    /// `parent_id` does not match `self.agent_id`. This safeguard (flagged
    /// in the Devin AI review of closed PR #251) prevents an agent from
    /// deleting a sub-agent that belongs to a different parent within the
    /// same workspace.
    async fn delete_sub_agent(
        &self,
        req: agent::DeleteSubAgentRequest,
    ) -> Result<agent::DeleteSubAgentResponse, RpcError> {
        let sub_agent_id = Uuid::from_slice(&req.id)
            .map_err(|e| RpcError::InvalidArgument(format!("sub agent id from bytes: {e}")))?;
        if sub_agent_id.is_nil() {
            return Err(RpcError::InvalidArgument(
                "sub agent ID cannot be nil".into(),
            ));
        }

        // Parent-ownership check: look up the candidate sub-agent and
        // confirm its parent_id equals this handler's agent_id. If the row
        // is absent, fall through to `delete_workspace_sub_agent` (the
        // current store implementation is a safe no-op).
        if let Some(row) = self
            .store
            .find_workspace_agent_by_id(sub_agent_id)
            .await
            .map_err(|e| RpcError::Internal(format!("find sub agent: {e}")))?
        {
            match row.parent_id {
                Some(p) if p == self.agent_id => {}
                _ => {
                    return Err(RpcError::InvalidArgument(
                        "subagent does not belong to this parent agent".into(),
                    ));
                }
            }
        }

        self.store
            .delete_workspace_sub_agent(sub_agent_id)
            .await
            .map_err(|e| RpcError::Internal(format!("delete sub agent: {e}")))?;
        Ok(agent::DeleteSubAgentResponse::default())
    }

    /// Ports `coder/coderd/agentapi/subagent.go::ListSubAgents`.
    ///
    /// Calls `list_workspace_agents_by_parent_id` — the default in-memory
    /// implementation returns an empty list until the sub-agent projection
    /// lands.
    async fn list_sub_agents(
        &self,
        _req: agent::ListSubAgentsRequest,
    ) -> Result<agent::ListSubAgentsResponse, RpcError> {
        let rows = self
            .store
            .list_workspace_agents_by_parent_id(self.agent_id)
            .await
            .map_err(|e| RpcError::Internal(format!("list sub agents: {e}")))?;
        let agents = rows
            .into_iter()
            .map(|r| agent::SubAgent {
                name: r.name,
                id: r.id.as_bytes().to_vec(),
                auth_token: r.auth_token.as_bytes().to_vec(),
            })
            .collect();
        Ok(agent::ListSubAgentsResponse { agents })
    }

    /// Ports `coder/coderd/agentapi/boundary_logs.go::ReportBoundaryLogs`.
    ///
    /// The `boundary_logs` / boundary usage tracking tables are not yet
    /// ported — log the batch size and return OK.
    async fn report_boundary_logs(
        &self,
        req: agent::ReportBoundaryLogsRequest,
    ) -> Result<agent::ReportBoundaryLogsResponse, RpcError> {
        tracing::info!(
            agent_id = %self.agent_id,
            logs = req.logs.len(),
            "agent report_boundary_logs (persistence deferred)",
        );
        Ok(agent::ReportBoundaryLogsResponse::default())
    }

    /// Ports `coder/coderd/agentapi/apps.go::UpdateAppStatus`.
    ///
    /// Enforces the Go handler's 160-character message cap (Devin AI review
    /// on closed PR #251 flagged that the error wording had to match the
    /// inequality the code enforces — the check is `> 160`, so the message
    /// must read "must be at most 160 characters"), validates the state
    /// enum, resolves the target app by `(agent_id, slug)`, and persists
    /// via [`AppStore::insert_workspace_app_status`]. AI-task notifications
    /// + activity bump are deferred.
    async fn update_app_status(
        &self,
        req: agent::UpdateAppStatusRequest,
    ) -> Result<agent::UpdateAppStatusResponse, RpcError> {
        if req.message.chars().count() > 160 {
            return Err(RpcError::InvalidArgument(
                "Message must be at most 160 characters.".into(),
            ));
        }

        let state_str = match agent::update_app_status_request::AppStatusState::try_from(req.state)
        {
            Ok(agent::update_app_status_request::AppStatusState::Working) => "working",
            Ok(agent::update_app_status_request::AppStatusState::Idle) => "idle",
            Ok(agent::update_app_status_request::AppStatusState::Complete) => "complete",
            Ok(agent::update_app_status_request::AppStatusState::Failure) => "failure",
            Err(_) => {
                return Err(RpcError::InvalidArgument(format!(
                    "invalid state: {}",
                    req.state
                )));
            }
        };

        let app = self
            .store
            .find_workspace_app_by_agent_and_slug(self.agent_id, &req.slug)
            .await
            .map_err(|e| RpcError::Internal(format!("find workspace app: {e}")))?
            .ok_or_else(|| {
                RpcError::InvalidArgument(format!("no app found with slug {:?}", req.slug))
            })?;

        let workspace = self
            .store
            .find_workspace_by_agent_id(self.agent_id)
            .await
            .map_err(|e| RpcError::Internal(format!("find workspace: {e}")))?
            .ok_or_else(|| RpcError::Internal("workspace not found for agent".into()))?;

        let uri = if req.uri.is_empty() {
            None
        } else {
            Some(req.uri)
        };

        self.store
            .insert_workspace_app_status(&coder_core::InsertWorkspaceAppStatusInput {
                agent_id: self.agent_id,
                app_id: app.id,
                workspace_id: workspace.id,
                state: state_str.to_owned(),
                message: req.message,
                uri,
            })
            .await
            .map_err(|e| RpcError::Internal(format!("insert workspace app status: {e}")))?;

        Ok(agent::UpdateAppStatusResponse::default())
    }
}

/// Converts a `google.protobuf.Timestamp` to an `OffsetDateTime`. Returns
/// `None` when the proto value is zero (Go treats this as "unset") or when
/// the value cannot be represented.
fn proto_timestamp_to_time(ts: &prost_types::Timestamp) -> Option<OffsetDateTime> {
    if ts.seconds == 0 && ts.nanos == 0 {
        return None;
    }
    let nanos_total = i128::from(ts.seconds) * 1_000_000_000 + i128::from(ts.nanos);
    OffsetDateTime::from_unix_timestamp_nanos(nanos_total).ok()
}

/// Maps a DB `log_level` enum string to the API `LogLevel`. Mirrors the
/// small enum translator already used by the HTTP logs handler.
fn db_log_level_to_api(level: &str) -> coder_core::api::LogLevel {
    match level {
        "trace" => coder_core::api::LogLevel::Trace,
        "debug" => coder_core::api::LogLevel::Debug,
        "warn" => coder_core::api::LogLevel::Warn,
        "error" => coder_core::api::LogLevel::Error,
        _ => coder_core::api::LogLevel::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use coder_core::config::DerpNodeConfig;

    #[test]
    fn git_provider_filter_matches_go_list() {
        assert!(is_git_external_auth_provider("github"));
        assert!(is_git_external_auth_provider("gitlab"));
        assert!(is_git_external_auth_provider("bitbucket-cloud"));
        assert!(is_git_external_auth_provider("bitbucket-server"));
        assert!(is_git_external_auth_provider("azure-devops"));
        assert!(is_git_external_auth_provider("azure-devops-entra"));
        assert!(is_git_external_auth_provider("gitea"));
        assert!(!is_git_external_auth_provider("slack"));
        assert!(!is_git_external_auth_provider("jfrog"));
        assert!(!is_git_external_auth_provider(""));
    }

    #[test]
    fn subdomain_app_host_appends_access_port_when_missing() -> Result<(), url::ParseError> {
        let access = Url::parse("https://coder.example.com:3000")?;
        assert_eq!(
            subdomain_app_host("*.apps.example.com", &access),
            "*.apps.example.com:3000"
        );
        Ok(())
    }

    #[test]
    fn subdomain_app_host_preserves_explicit_port() -> Result<(), url::ParseError> {
        let access = Url::parse("https://coder.example.com:3000")?;
        assert_eq!(
            subdomain_app_host("*.apps.example.com:8443", &access),
            "*.apps.example.com:8443"
        );
        Ok(())
    }

    #[test]
    fn subdomain_app_host_empty_when_disabled() -> Result<(), url::ParseError> {
        let access = Url::parse("https://coder.example.com")?;
        assert_eq!(subdomain_app_host("", &access), "");
        Ok(())
    }

    #[test]
    fn build_vscode_port_proxy_uri_matches_go_template() -> Result<(), url::ParseError> {
        // Access URL without port should not alter the app host.
        let access = Url::parse("https://coder.example.com")?;
        let uri = build_vscode_port_proxy_uri(
            &access,
            "*.apps.example.com",
            "my-agent",
            "my-ws",
            "alice",
        );
        assert_eq!(
            uri,
            "https://{{port}}--my-agent--my-ws--alice.apps.example.com"
        );
        Ok(())
    }

    #[test]
    fn build_vscode_port_proxy_uri_empty_when_apphost_missing() -> Result<(), url::ParseError> {
        let access = Url::parse("https://coder.example.com")?;
        let uri = build_vscode_port_proxy_uri(&access, "", "a", "w", "u");
        assert_eq!(uri, "");
        Ok(())
    }

    #[test]
    fn build_derp_map_proto_preserves_regions_and_nodes() -> Result<(), url::ParseError> {
        let region = DerpRegionConfig {
            id: 10,
            name: "Test Region".to_owned(),
            nodes: vec![DerpNodeConfig {
                name: "node-a".to_owned(),
                url: Url::parse("https://derp.example.com:4443")?,
            }],
        };
        let map = build_derp_map_proto(&[region]);
        assert_eq!(map.regions.len(), 1);
        let region_proto = map.regions.get(&10).ok_or(url::ParseError::EmptyHost)?;
        assert_eq!(region_proto.region_id, 10);
        assert_eq!(region_proto.region_name, "Test Region");
        assert_eq!(region_proto.region_code, "test-region");
        assert_eq!(region_proto.nodes.len(), 1);
        let node = &region_proto.nodes[0];
        assert_eq!(node.name, "node-a");
        assert_eq!(node.host_name, "derp.example.com");
        assert_eq!(node.derp_port, 4443);
        assert!(!node.force_http);
        Ok(())
    }

    #[test]
    fn build_derp_map_proto_force_http_for_http_scheme() -> Result<(), url::ParseError> {
        let region = DerpRegionConfig {
            id: 1,
            name: "local".to_owned(),
            nodes: vec![DerpNodeConfig {
                name: "n".to_owned(),
                url: Url::parse("http://localhost:8080")?,
            }],
        };
        let map = build_derp_map_proto(&[region]);
        let region_proto = map.regions.get(&1).ok_or(url::ParseError::EmptyHost)?;
        let node = region_proto
            .nodes
            .first()
            .ok_or(url::ParseError::EmptyHost)?;
        assert!(node.force_http);
        assert_eq!(node.derp_port, 8080);
        Ok(())
    }
}
