//! Connectivity, agent, health, and SSH helpers.
#![forbid(unsafe_code)]

pub mod agents;
pub mod tailnet;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use coder_core::{
    AccessUrlHealthReport, BaseHealthReport, BuildMetadata, DatabaseHealthReport, DeploymentStore,
    DerpHealthReport, HealthSeverity, HealthcheckReport, OperationalStore,
    ProvisionerDaemonsHealthReport, ServerConfig, WebsocketHealthReport,
    WorkspaceProxyHealthReport,
};
use ssh_key::{Algorithm, LineEnding, PrivateKey, rand_core::OsRng};
use thiserror::Error;
use time::OffsetDateTime;
use tokio::sync::Mutex;

const HEALTHCHECK_CACHE_TTL_SECS: u64 = 15;
const HTTP_TIMEOUT_SECS: u64 = 10;
const PROVISIONER_OFFLINE_SECS: i64 = 60 * 5;

/// Generated Git SSH keypair in OpenSSH-compatible formats.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneratedGitSshKey {
    /// Public key in OpenSSH authorized-keys format with a trailing newline.
    pub public_key: String,
    /// Private key in OpenSSH private-key format.
    pub private_key: String,
}

/// Key-generation failures surfaced by the connectivity crate.
#[derive(Debug, Error)]
pub enum GitSshKeyError {
    /// Failed to generate the keypair.
    #[error("generate ssh keypair: {0}")]
    Generate(#[from] ssh_key::Error),
}

#[derive(Clone, Debug)]
struct CachedHealthReport {
    generated_at: Instant,
    report: HealthcheckReport,
}

/// Cached deployment-health service with live subsystem probes.
#[derive(Clone)]
pub struct HealthService<S> {
    store: S,
    http_client: reqwest::Client,
    cache: Arc<Mutex<Option<CachedHealthReport>>>,
    refresh_lock: Arc<Mutex<()>>,
}

impl<S> HealthService<S>
where
    S: DeploymentStore + OperationalStore + Clone + Send + Sync + 'static,
{
    /// Creates the health service with one shared HTTP client.
    pub fn new(store: S) -> Result<Self, reqwest::Error> {
        Ok(Self {
            store,
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
                .build()?,
            cache: Arc::new(Mutex::new(None)),
            refresh_lock: Arc::new(Mutex::new(())),
        })
    }

    /// Returns the cached report unless a forced refresh is requested.
    pub async fn report(
        &self,
        config: &ServerConfig,
        build_metadata: &BuildMetadata,
        force: bool,
    ) -> Result<HealthcheckReport, coder_core::StorageError> {
        if !force {
            if let Some(cached) = self.cache.lock().await.clone() {
                if cached.generated_at.elapsed() < Duration::from_secs(HEALTHCHECK_CACHE_TTL_SECS) {
                    return Ok(cached.report);
                }
            }
        }

        let _refresh_guard = self.refresh_lock.lock().await;
        if !force {
            if let Some(cached) = self.cache.lock().await.clone() {
                if cached.generated_at.elapsed() < Duration::from_secs(HEALTHCHECK_CACHE_TTL_SECS) {
                    return Ok(cached.report);
                }
            }
        }

        let report = self.build_report(config, build_metadata).await?;
        *self.cache.lock().await = Some(CachedHealthReport {
            generated_at: Instant::now(),
            report: report.clone(),
        });
        Ok(report)
    }

    async fn build_report(
        &self,
        config: &ServerConfig,
        build_metadata: &BuildMetadata,
    ) -> Result<HealthcheckReport, coder_core::StorageError> {
        let database_future = self.probe_database();
        let access_url_future = self.probe_access_url(config);
        let websocket_future = self.probe_websocket(config);
        let derp_future = self.probe_derp(config);
        let workspace_proxy_future = self.probe_workspace_proxies();
        let provisioner_future = self.probe_provisioner_daemons();

        let (
            database_report,
            access_url_report,
            websocket_report,
            derp_report,
            workspace_proxy_report,
            provisioner_report,
        ) = tokio::join!(
            database_future,
            access_url_future,
            websocket_future,
            derp_future,
            workspace_proxy_future,
            provisioner_future
        );

        let database_report = database_report?;
        let workspace_proxy_report = workspace_proxy_report?;
        let provisioner_report = provisioner_report?;

        let severity = [
            database_report.base.severity,
            access_url_report.base.severity,
            websocket_report.base.severity,
            derp_report.base.severity,
            workspace_proxy_report.base.severity,
            provisioner_report.base.severity,
        ]
        .into_iter()
        .fold(HealthSeverity::Ok, max_severity);

        Ok(HealthcheckReport {
            time: OffsetDateTime::now_utc(),
            healthy: !matches!(severity, HealthSeverity::Error),
            severity,
            derp: derp_report,
            access_url: access_url_report,
            websocket: websocket_report,
            database: database_report,
            workspace_proxy: workspace_proxy_report,
            provisioner_daemons: provisioner_report,
            coder_version: build_metadata.version.clone(),
        })
    }

    async fn probe_database(&self) -> Result<DatabaseHealthReport, coder_core::StorageError> {
        let start = Instant::now();
        let ping_result = self.store.ping().await;
        let latency_ms = i64::try_from(start.elapsed().as_millis()).unwrap_or_default();

        Ok(DatabaseHealthReport {
            base: BaseHealthReport {
                error: ping_result.as_ref().err().map(ToString::to_string),
                severity: if ping_result.is_ok() {
                    HealthSeverity::Ok
                } else {
                    HealthSeverity::Error
                },
                warnings: Vec::new(),
                dismissed: false,
            },
            healthy: ping_result.is_ok(),
            reachable: ping_result.is_ok(),
            latency: format!("{latency_ms}ms"),
            latency_ms,
            threshold_ms: 10_000,
        })
    }

    async fn probe_access_url(&self, config: &ServerConfig) -> AccessUrlHealthReport {
        let access_url = config.access_url.to_string();
        let Ok(url) = config.access_url.join("/healthz") else {
            return AccessUrlHealthReport {
                base: BaseHealthReport {
                    error: Some("Configured access URL cannot be resolved to /healthz.".to_owned()),
                    severity: HealthSeverity::Error,
                    warnings: Vec::new(),
                    dismissed: false,
                },
                healthy: false,
                access_url,
                reachable: false,
                status_code: 0,
                healthz_response: String::new(),
            };
        };

        match self.http_client.get(url).send().await {
            Ok(response) => {
                let status_code = i32::from(response.status().as_u16());
                let healthy = response.status().is_success();
                let body = response.text().await.unwrap_or_default();

                AccessUrlHealthReport {
                    base: BaseHealthReport {
                        error: if healthy {
                            None
                        } else {
                            Some(format!("healthz returned HTTP {status_code}"))
                        },
                        severity: if healthy {
                            HealthSeverity::Ok
                        } else {
                            HealthSeverity::Error
                        },
                        warnings: Vec::new(),
                        dismissed: false,
                    },
                    healthy,
                    access_url,
                    reachable: healthy,
                    status_code,
                    healthz_response: body,
                }
            }
            Err(error) => AccessUrlHealthReport {
                base: BaseHealthReport {
                    error: Some(error.to_string()),
                    severity: HealthSeverity::Error,
                    warnings: Vec::new(),
                    dismissed: false,
                },
                healthy: false,
                access_url,
                reachable: false,
                status_code: 0,
                healthz_response: String::new(),
            },
        }
    }

    async fn probe_websocket(&self, config: &ServerConfig) -> WebsocketHealthReport {
        let Ok(url) = config.access_url.join("/latency-check") else {
            return WebsocketHealthReport {
                healthy: false,
                base: BaseHealthReport {
                    error: Some(
                        "Configured access URL cannot be resolved to /latency-check.".to_owned(),
                    ),
                    severity: HealthSeverity::Error,
                    warnings: Vec::new(),
                    dismissed: false,
                },
                body: String::new(),
                code: 0,
            };
        };

        match self.http_client.get(url).send().await {
            Ok(response) => {
                let code = i32::from(response.status().as_u16());
                let healthy = response.status().is_success();
                let body = response.text().await.unwrap_or_default();

                WebsocketHealthReport {
                    healthy,
                    base: BaseHealthReport {
                        error: if healthy {
                            None
                        } else {
                            Some(format!("latency-check returned HTTP {code}"))
                        },
                        severity: if healthy {
                            HealthSeverity::Ok
                        } else {
                            HealthSeverity::Error
                        },
                        warnings: Vec::new(),
                        dismissed: false,
                    },
                    body,
                    code,
                }
            }
            Err(error) => WebsocketHealthReport {
                healthy: false,
                base: BaseHealthReport {
                    error: Some(error.to_string()),
                    severity: HealthSeverity::Error,
                    warnings: Vec::new(),
                    dismissed: false,
                },
                body: String::new(),
                code: 0,
            },
        }
    }

    async fn probe_derp(&self, config: &ServerConfig) -> DerpHealthReport {
        let mut regions = HashMap::new();
        let mut logs = Vec::new();
        let mut severity = HealthSeverity::Ok;
        let mut warnings = Vec::new();
        let mut error = None;

        for region in &config.derp_regions {
            let mut healthy_nodes = 0usize;
            let mut total_nodes = 0usize;

            for node in &region.nodes {
                total_nodes = total_nodes.saturating_add(1);
                match self.http_client.get(node.url.clone()).send().await {
                    Ok(response) if response.status().is_success() => {
                        healthy_nodes = healthy_nodes.saturating_add(1);
                        logs.push(format!(
                            "region={} node={} status=ok code={}",
                            region.name,
                            node.name,
                            response.status().as_u16()
                        ));
                    }
                    Ok(response) => {
                        severity = HealthSeverity::Error;
                        let message = format!(
                            "region={} node={} status=error code={}",
                            region.name,
                            node.name,
                            response.status().as_u16()
                        );
                        error = Some(message.clone());
                        logs.push(message);
                    }
                    Err(probe_error) => {
                        severity = HealthSeverity::Error;
                        let message = format!(
                            "region={} node={} status=unreachable error={probe_error}",
                            region.name, node.name
                        );
                        error = Some(message.clone());
                        logs.push(message);
                    }
                }
            }

            if total_nodes == 0 {
                warnings.push(format!(
                    "DERP region {} has no configured nodes.",
                    region.name
                ));
                severity = max_severity(severity, HealthSeverity::Warning);
                regions.insert(region.name.clone(), "no configured nodes".to_owned());
                continue;
            }

            let summary = format!("{healthy_nodes}/{total_nodes} nodes healthy");
            if healthy_nodes != total_nodes {
                severity = HealthSeverity::Error;
            }
            regions.insert(region.name.clone(), summary);
        }

        DerpHealthReport {
            base: BaseHealthReport {
                error,
                severity,
                warnings,
                dismissed: false,
            },
            healthy: !matches!(severity, HealthSeverity::Error),
            regions,
            netcheck_logs: logs,
        }
    }

    async fn probe_workspace_proxies(
        &self,
    ) -> Result<WorkspaceProxyHealthReport, coder_core::StorageError> {
        let mut warnings = Vec::new();
        let mut items = Vec::new();
        let mut severity = HealthSeverity::Ok;
        let mut error = None;

        for proxy in self.store.list_workspace_proxies_for_health().await? {
            if proxy.deleted {
                continue;
            }
            if proxy.path_app_url.trim().is_empty() {
                items.push(format!("{}: unregistered", proxy.name));
                warnings.push(format!(
                    "workspace proxy {} has no registered path app URL",
                    proxy.name
                ));
                severity = max_severity(severity, HealthSeverity::Warning);
                continue;
            }

            let outcome = reqwest::Url::parse(&proxy.path_app_url)
                .and_then(|url| url.join("/healthz"))
                .ok()
                .map(|url| async {
                    match self.http_client.get(url).send().await {
                        Ok(response) if response.status().is_success() => {
                            Ok::<String, String>(format!("{}: ok", proxy.name))
                        }
                        Ok(response) => Err(format!(
                            "{}: unhealthy ({})",
                            proxy.name,
                            response.status().as_u16()
                        )),
                        Err(probe_error) => {
                            Err(format!("{}: unreachable ({probe_error})", proxy.name))
                        }
                    }
                });

            match outcome {
                Some(future) => match future.await {
                    Ok(item) => items.push(item),
                    Err(item_error) => {
                        items.push(item_error.clone());
                        error = Some(item_error);
                        severity = HealthSeverity::Error;
                    }
                },
                None => {
                    let item_error = format!("{}: invalid proxy access URL", proxy.name);
                    items.push(item_error.clone());
                    error = Some(item_error);
                    severity = HealthSeverity::Error;
                }
            }
        }

        Ok(WorkspaceProxyHealthReport {
            base: BaseHealthReport {
                error,
                severity,
                warnings,
                dismissed: false,
            },
            healthy: !matches!(severity, HealthSeverity::Error),
            items,
        })
    }

    async fn probe_provisioner_daemons(
        &self,
    ) -> Result<ProvisionerDaemonsHealthReport, coder_core::StorageError> {
        let mut warnings = Vec::new();
        let mut items = Vec::new();
        let mut severity = HealthSeverity::Ok;

        for daemon in self.store.list_provisioner_daemons_for_health().await? {
            let status = daemon.status.clone().unwrap_or_else(|| {
                if daemon.last_seen_at.is_some_and(|last_seen| {
                    (OffsetDateTime::now_utc() - last_seen).whole_seconds()
                        <= PROVISIONER_OFFLINE_SECS
                }) {
                    "idle".to_owned()
                } else {
                    "offline".to_owned()
                }
            });

            if status == "offline" {
                warnings.push(format!("provisioner daemon {} is offline", daemon.name));
                severity = max_severity(severity, HealthSeverity::Warning);
            }

            items.push(format!("{}: {}", daemon.name, status));
        }

        Ok(ProvisionerDaemonsHealthReport {
            base: BaseHealthReport {
                error: None,
                severity,
                warnings,
                dismissed: false,
            },
            items,
        })
    }
}

fn max_severity(left: HealthSeverity, right: HealthSeverity) -> HealthSeverity {
    match (left, right) {
        (HealthSeverity::Error, _) | (_, HealthSeverity::Error) => HealthSeverity::Error,
        (HealthSeverity::Warning, _) | (_, HealthSeverity::Warning) => HealthSeverity::Warning,
        _ => HealthSeverity::Ok,
    }
}

// ---------------------------------------------------------------------------
// Telemetry
// ---------------------------------------------------------------------------

/// Anonymous deployment telemetry snapshot sent daily.
#[derive(Clone, Debug, serde::Serialize)]
pub struct TelemetrySnapshot {
    /// Unique deployment identifier.
    pub deployment_id: String,
    /// Number of active sessions (sum of VS Code, SSH, and JetBrains sessions).
    pub active_sessions: u64,
    /// Number of workspaces.
    pub workspaces: u64,
    /// Number of templates.
    pub templates: u64,
    /// Coder version.
    pub version: String,
    /// Snapshot timestamp (RFC 3339).
    pub timestamp: String,
}

/// Periodic telemetry collection service.
pub struct TelemetryService<S> {
    store: S,
    deployment_id: String,
    version: String,
}

impl<S> TelemetryService<S>
where
    S: DeploymentStore + OperationalStore + Clone + Send + Sync + 'static,
{
    /// Creates the telemetry service and starts the daily collection loop.
    #[must_use]
    pub fn new(store: S, deployment_id: String, version: String) -> Arc<Self> {
        let service = Arc::new(Self {
            store,
            deployment_id,
            version,
        });
        Self::spawn_collection_loop(&service);
        service
    }

    /// Collects a telemetry snapshot.
    pub async fn collect_snapshot(&self) -> Result<TelemetrySnapshot, coder_core::StorageError> {
        let stats = self.store.deployment_stats().await?;
        let sessions = u64::try_from(stats.session_count.vscode)
            .unwrap_or_default()
            .saturating_add(u64::try_from(stats.session_count.ssh).unwrap_or_default())
            .saturating_add(u64::try_from(stats.session_count.jetbrains).unwrap_or_default())
            .saturating_add(
                u64::try_from(stats.session_count.reconnecting_pty).unwrap_or_default(),
            );
        let workspaces = u64::try_from(stats.workspaces.pending)
            .unwrap_or_default()
            .saturating_add(u64::try_from(stats.workspaces.building).unwrap_or_default())
            .saturating_add(u64::try_from(stats.workspaces.running).unwrap_or_default())
            .saturating_add(u64::try_from(stats.workspaces.stopped).unwrap_or_default())
            .saturating_add(u64::try_from(stats.workspaces.failed).unwrap_or_default());

        Ok(TelemetrySnapshot {
            deployment_id: self.deployment_id.clone(),
            active_sessions: sessions,
            workspaces,
            templates: 0,
            version: self.version.clone(),
            timestamp: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        })
    }

    fn spawn_collection_loop(service: &Arc<Self>) {
        let weak = Arc::downgrade(service);
        tokio::spawn(async move {
            run_telemetry_loop(weak).await;
        });
    }
}

const TELEMETRY_INTERVAL_SECS: u64 = 86400; // 24 hours

async fn run_telemetry_loop<S>(service: std::sync::Weak<TelemetryService<S>>)
where
    S: DeploymentStore + OperationalStore + Clone + Send + Sync + 'static,
{
    let mut interval = tokio::time::interval(Duration::from_secs(TELEMETRY_INTERVAL_SECS));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        interval.tick().await;
        let Some(service) = service.upgrade() else {
            return;
        };
        match service.collect_snapshot().await {
            Ok(snapshot) => {
                tracing::info!(
                    deployment_id = %snapshot.deployment_id,
                    active_sessions = snapshot.active_sessions,
                    workspaces = snapshot.workspaces,
                    "telemetry snapshot collected"
                );
            }
            Err(error) => {
                tracing::warn!(error = %error, "telemetry snapshot collection failed");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Update Checker
// ---------------------------------------------------------------------------

/// Cached result of a version update check.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct UpdateCheckResult {
    /// Current version of the deployment.
    pub current_version: String,
    /// Latest available version from upstream.
    pub latest_version: String,
    /// URL to the release page.
    pub url: String,
    /// Whether an update is available.
    pub update_available: bool,
}

/// Background update checker that polls upstream releases.
pub struct UpdateCheckService {
    current_version: String,
    http_client: reqwest::Client,
    cache: Arc<Mutex<Option<UpdateCheckResult>>>,
}

const UPDATE_CHECK_INTERVAL_SECS: u64 = 3600; // 1 hour
const GITHUB_RELEASES_API: &str = "https://api.github.com/repos/coder/coder/releases/latest";

impl UpdateCheckService {
    /// Creates the update check service and starts the periodic polling loop.
    pub fn new(current_version: String) -> Result<Arc<Self>, reqwest::Error> {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
            .user_agent("coder-update-checker")
            .build()?;

        let service = Arc::new(Self {
            current_version,
            http_client,
            cache: Arc::new(Mutex::new(None)),
        });
        Self::spawn_check_loop(&service);
        Ok(service)
    }

    /// Returns the cached update check result when available.
    pub async fn latest(&self) -> Option<UpdateCheckResult> {
        self.cache.lock().await.clone()
    }

    async fn check_once(&self) -> Result<UpdateCheckResult, UpdateCheckError> {
        let response = self
            .http_client
            .get(GITHUB_RELEASES_API)
            .send()
            .await
            .map_err(|e| UpdateCheckError::Http(e.to_string()))?;

        if !response.status().is_success() {
            return Err(UpdateCheckError::Http(format!(
                "GitHub API returned HTTP {}",
                response.status().as_u16()
            )));
        }

        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| UpdateCheckError::Parse(e.to_string()))?;

        let tag_name = body
            .get("tag_name")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .trim_start_matches('v')
            .to_owned();

        let html_url = body
            .get("html_url")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned();

        let update_available =
            !tag_name.is_empty() && tag_name != self.current_version.trim_start_matches('v');

        let result = UpdateCheckResult {
            current_version: self.current_version.clone(),
            latest_version: tag_name,
            url: html_url,
            update_available,
        };

        *self.cache.lock().await = Some(result.clone());
        Ok(result)
    }

    fn spawn_check_loop(service: &Arc<Self>) {
        let weak = Arc::downgrade(service);
        tokio::spawn(async move {
            run_update_check_loop(weak).await;
        });
    }
}

/// Errors from the update checker.
#[derive(Debug, Error)]
pub enum UpdateCheckError {
    /// HTTP transport error.
    #[error("http error: {0}")]
    Http(String),
    /// Response parsing error.
    #[error("parse error: {0}")]
    Parse(String),
}

async fn run_update_check_loop(service: std::sync::Weak<UpdateCheckService>) {
    let mut interval = tokio::time::interval(Duration::from_secs(UPDATE_CHECK_INTERVAL_SECS));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        interval.tick().await;
        let Some(service) = service.upgrade() else {
            return;
        };
        match service.check_once().await {
            Ok(result) => {
                if result.update_available {
                    tracing::info!(
                        current = %result.current_version,
                        latest = %result.latest_version,
                        url = %result.url,
                        "coder update available"
                    );
                }
            }
            Err(error) => {
                tracing::warn!(error = %error, "update check failed");
            }
        }
    }
}

/// Generates a new Ed25519 Git SSH keypair for one user.
pub fn generate_git_ssh_key(comment: &str) -> Result<GeneratedGitSshKey, GitSshKeyError> {
    let mut private_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)?;
    private_key.set_comment(comment.to_owned());

    let mut public_key = private_key.public_key().to_openssh()?;
    if !comment.trim().is_empty() {
        public_key.push(' ');
        public_key.push_str(comment.trim());
    }
    public_key.push('\n');

    Ok(GeneratedGitSshKey {
        public_key,
        private_key: private_key.to_openssh(LineEnding::LF)?.to_string(),
    })
}
