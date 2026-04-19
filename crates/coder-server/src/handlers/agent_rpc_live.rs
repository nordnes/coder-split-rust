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
use url::Url;
use uuid::Uuid;

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
        }
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
