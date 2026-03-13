//! Connectivity, agent, health, and SSH helpers.
//!
//! `coder-connectivity` groups operational services that probe the health
//! of subsystems and manage infrastructure-level resources:
//!
//! * [`HealthService`] — cached deployment health checks (database, access URL,
//!   WebSocket, DERP, workspace proxies, provisioner daemons) with a 15-second
//!   TTL
//! * [`TelemetryService`] — periodic anonymous deployment telemetry snapshots
//! * [`UpdateCheckService`] — polls GitHub releases for available updates
//! * [`generate_git_ssh_key`] — Ed25519 keypair generation for Git-over-SSH
//! * [`agents`] — in-memory agent connection provider
//! * [`tailnet`] — DERP map construction and in-memory coordinator
#![forbid(unsafe_code)]

pub mod agents;
pub mod derp;
pub mod proxy_routing;
pub mod tailnet;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use coder_core::{
    AccessUrlHealthReport, BaseHealthReport, BuildMetadata, CircuitBreakerRegistry,
    CircuitBreakerState, DatabaseHealthReport, DeploymentStore, DerpHealthReport, HealthSeverity,
    HealthcheckReport, OperationalStore, ProvisionerDaemonsHealthReport, ServerConfig,
    WebsocketHealthReport, WorkspaceProxyHealthReport,
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
    circuit_breakers: CircuitBreakerRegistry,
}

impl<S> HealthService<S>
where
    S: DeploymentStore + OperationalStore + Clone + Send + Sync + 'static,
{
    /// Creates the health service with one shared HTTP client and default
    /// circuit breakers for all external dependencies.
    pub fn new(store: S) -> Result<Self, reqwest::Error> {
        Self::with_circuit_breakers(store, CircuitBreakerRegistry::with_defaults())
    }

    /// Creates the health service with the given circuit breaker registry.
    pub fn with_circuit_breakers(
        store: S,
        circuit_breakers: CircuitBreakerRegistry,
    ) -> Result<Self, reqwest::Error> {
        Ok(Self {
            store,
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
                .build()?,
            cache: Arc::new(Mutex::new(None)),
            refresh_lock: Arc::new(Mutex::new(())),
            circuit_breakers,
        })
    }

    /// Returns a reference to the circuit breaker registry.
    #[must_use]
    pub fn circuit_breakers(&self) -> &CircuitBreakerRegistry {
        &self.circuit_breakers
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

        let cb_statuses = self.circuit_breakers.all_statuses().await;

        // Factor circuit breaker states into overall severity: any open
        // breaker raises severity to at least Warning.
        let cb_severity = if cb_statuses
            .iter()
            .any(|s| s.state == CircuitBreakerState::Open)
        {
            HealthSeverity::Warning
        } else {
            HealthSeverity::Ok
        };
        let severity = max_severity(severity, cb_severity);

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
            circuit_breakers: cb_statuses,
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

        match health_probe_get(&self.http_client, url).await {
            Ok(result) => {
                let status_code = i32::from(result.status_code);
                let healthy = (200..300).contains(&result.status_code);

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
                    healthz_response: result.body,
                }
            }
            Err(error) => {
                let code = i32::from(error.status_code);
                AccessUrlHealthReport {
                    base: BaseHealthReport {
                        error: Some(error.message),
                        severity: HealthSeverity::Error,
                        warnings: Vec::new(),
                        dismissed: false,
                    },
                    healthy: false,
                    access_url,
                    reachable: error.status_code != 0,
                    status_code: code,
                    healthz_response: String::new(),
                }
            }
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

        match health_probe_get(&self.http_client, url).await {
            Ok(result) => {
                let code = i32::from(result.status_code);
                let healthy = (200..300).contains(&result.status_code);

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
                    body: result.body,
                    code,
                }
            }
            Err(error) => WebsocketHealthReport {
                healthy: false,
                base: BaseHealthReport {
                    error: Some(error.message),
                    severity: HealthSeverity::Error,
                    warnings: Vec::new(),
                    dismissed: false,
                },
                body: String::new(),
                code: i32::from(error.status_code),
            },
        }
    }

    async fn probe_derp(&self, config: &ServerConfig) -> DerpHealthReport {
        let mut regions = HashMap::new();
        let mut logs = Vec::new();
        let mut severity = HealthSeverity::Ok;
        let mut warnings = Vec::new();
        let mut error = None;

        let derp_breaker = self.circuit_breakers.get("derp_mesh");

        for region in &config.derp_regions {
            let mut healthy_nodes = 0usize;
            let mut total_nodes = 0usize;

            for node in &region.nodes {
                total_nodes = total_nodes.saturating_add(1);

                // Wrap the HTTP probe through the DERP circuit breaker.
                let probe_result = if let Some(breaker) = derp_breaker {
                    let client = &self.http_client;
                    let url = node.url.clone();
                    match breaker
                        .call(|| async { health_probe_get(client, url).await })
                        .await
                    {
                        Ok(r) => Ok(r),
                        Err(coder_core::CircuitBreakerCallError::BreakerOpen(open)) => {
                            Err(HealthProbeError {
                                message: format!("circuit breaker open: {open}"),
                                status_code: 503,
                                is_client_error: false,
                            })
                        }
                        Err(coder_core::CircuitBreakerCallError::Inner(probe_err)) => {
                            Err(probe_err)
                        }
                    }
                } else {
                    health_probe_get(&self.http_client, node.url.clone()).await
                };

                match probe_result {
                    Ok(result) if (200..300).contains(&result.status_code) => {
                        healthy_nodes = healthy_nodes.saturating_add(1);
                        logs.push(format!(
                            "region={} node={} status=ok code={}",
                            region.name, node.name, result.status_code
                        ));
                    }
                    Ok(result) => {
                        severity = HealthSeverity::Error;
                        let message = format!(
                            "region={} node={} status=error code={}",
                            region.name, node.name, result.status_code
                        );
                        error = Some(message.clone());
                        logs.push(message);
                    }
                    Err(probe_error) => {
                        severity = HealthSeverity::Error;
                        let status_label = if probe_error.status_code != 0 {
                            "error"
                        } else {
                            "unreachable"
                        };
                        let message = format!(
                            "region={} node={} status={status_label} code={} error={}",
                            region.name, node.name, probe_error.status_code, probe_error.message
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

        // Check if the workspace-proxy circuit breaker is open — if so, skip
        // all HTTP probes and report a degraded status immediately.
        let proxy_breaker = self.circuit_breakers.get("workspace_proxies");
        let mut proxy_breaker_open = if let Some(breaker) = proxy_breaker {
            breaker.state().await == CircuitBreakerState::Open
        } else {
            false
        };

        if proxy_breaker_open {
            warnings.push("workspace proxy circuit breaker is open; skipping probes".to_owned());
            severity = max_severity(severity, HealthSeverity::Warning);
        }

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

            // Skip HTTP probes when the circuit breaker is open.
            if proxy_breaker_open {
                items.push(format!("{}: skipped (circuit breaker open)", proxy.name));
                continue;
            }

            let healthz_url = reqwest::Url::parse(&proxy.path_app_url)
                .and_then(|url| url.join("/healthz"))
                .ok();

            match healthz_url {
                Some(url) => match health_probe_get(&self.http_client, url).await {
                    Ok(result) if (200..300).contains(&result.status_code) => {
                        // Record success through breaker.
                        if let Some(breaker) = proxy_breaker {
                            breaker.report_success().await;
                        }
                        items.push(format!("{}: ok", proxy.name));
                    }
                    Ok(result) => {
                        // Record failure through breaker.
                        if let Some(breaker) = proxy_breaker {
                            breaker.report_failure().await;
                        }
                        let item_error =
                            format!("{}: unhealthy ({})", proxy.name, result.status_code);
                        items.push(item_error.clone());
                        error = Some(item_error);
                        severity = HealthSeverity::Error;
                    }
                    Err(probe_error) => {
                        // Record failure through breaker.
                        if let Some(breaker) = proxy_breaker {
                            breaker.report_failure().await;
                        }
                        let item_error =
                            format!("{}: unreachable ({})", proxy.name, probe_error.message);
                        items.push(item_error.clone());
                        error = Some(item_error);
                        severity = HealthSeverity::Error;
                        // Re-check breaker state; if it just tripped Open,
                        // skip remaining proxy probes.
                        if let Some(breaker) = proxy_breaker {
                            if breaker.state().await == CircuitBreakerState::Open {
                                proxy_breaker_open = true;
                            }
                        }
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

        let mut any_offline = false;

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
                any_offline = true;
            }

            items.push(format!("{}: {}", daemon.name, status));
        }

        // Record provisioner health through the circuit breaker.
        if let Some(breaker) = self.circuit_breakers.get("provisioner_daemons") {
            if any_offline {
                breaker.report_failure().await;
            } else {
                breaker.report_success().await;
            }
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

/// Result of a single health probe HTTP GET request.
struct HealthProbeResult {
    status_code: u16,
    body: String,
}

/// Error from a health probe HTTP GET request.
#[derive(Debug)]
struct HealthProbeError {
    message: String,
    /// The HTTP status code that triggered the error, or `0` for connection-
    /// level failures where no response was received.
    status_code: u16,
    /// True when the error is a client-side 4xx that should not be retried.
    is_client_error: bool,
}

impl std::fmt::Display for HealthProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// Executes a GET request with health-probe retry semantics.
///
/// Uses `Fixed { delay: 2s, max_attempts: 2 }`.  4xx responses are NOT
/// retried because they indicate genuine failures.
async fn health_probe_get(
    client: &reqwest::Client,
    url: reqwest::Url,
) -> Result<HealthProbeResult, HealthProbeError> {
    let url_clone = url.clone();
    let client_clone = client.clone();

    coder_core::retry::retry_with_strategy(
        coder_core::retry::RetryStrategy::Fixed {
            delay: Duration::from_secs(2),
            max_attempts: 2,
        },
        |err: &HealthProbeError| !err.is_client_error,
        || {
            let u = url_clone.clone();
            let c = client_clone.clone();
            async move {
                match c.get(u).send().await {
                    Ok(response) => {
                        let status_code = response.status().as_u16();
                        let body = response.text().await.unwrap_or_default();
                        if (400..500).contains(&status_code) {
                            Err(HealthProbeError {
                                message: format!("HTTP {status_code}: {body}"),
                                status_code,
                                is_client_error: true,
                            })
                        } else if status_code >= 500 {
                            Err(HealthProbeError {
                                message: format!("HTTP {status_code}: {body}"),
                                status_code,
                                is_client_error: false,
                            })
                        } else {
                            Ok(HealthProbeResult { status_code, body })
                        }
                    }
                    Err(error) => Err(HealthProbeError {
                        message: error.to_string(),
                        status_code: 0,
                        is_client_error: false,
                    }),
                }
            }
        },
    )
    .await
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

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use coder_core::identity::UserRecord;
    use coder_core::{
        DeploymentMetadata, DeploymentStore, HealthSeverity, OperationalStore,
        ProvisionerDaemonHealthRecord, StorageError, WorkspaceProxyHealthRecord,
    };
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    // ── Mock store ───────────────────────────────────────────

    /// Configurable mock for `DeploymentStore + OperationalStore`.
    #[derive(Clone)]
    struct MockStore {
        ping_ok: Arc<AtomicBool>,
        proxies: Arc<Mutex<Vec<WorkspaceProxyHealthRecord>>>,
        daemons: Arc<Mutex<Vec<ProvisionerDaemonHealthRecord>>>,
        ping_call_count: Arc<AtomicU32>,
    }

    impl MockStore {
        fn healthy() -> Self {
            Self {
                ping_ok: Arc::new(AtomicBool::new(true)),
                proxies: Arc::new(Mutex::new(Vec::new())),
                daemons: Arc::new(Mutex::new(Vec::new())),
                ping_call_count: Arc::new(AtomicU32::new(0)),
            }
        }

        fn with_ping_failing(self) -> Self {
            self.ping_ok.store(false, Ordering::SeqCst);
            self
        }

        fn with_daemons(daemons: Vec<ProvisionerDaemonHealthRecord>) -> Self {
            Self {
                ping_ok: Arc::new(AtomicBool::new(true)),
                proxies: Arc::new(Mutex::new(Vec::new())),
                daemons: Arc::new(Mutex::new(daemons)),
                ping_call_count: Arc::new(AtomicU32::new(0)),
            }
        }
    }

    #[async_trait]
    impl DeploymentStore for MockStore {
        async fn ping(&self) -> Result<(), StorageError> {
            self.ping_call_count.fetch_add(1, Ordering::SeqCst);
            if self.ping_ok.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err(StorageError::unavailable("mock database unreachable"))
            }
        }

        async fn ensure_deployment_metadata(&self) -> Result<DeploymentMetadata, StorageError> {
            Ok(DeploymentMetadata {
                deployment_id: uuid::Uuid::nil(),
            })
        }
    }

    #[async_trait]
    impl OperationalStore for MockStore {
        async fn list_audit_logs(
            &self,
            _filter: coder_core::ports::AuditLogListFilter,
        ) -> Result<coder_core::api::AuditLogResponse, StorageError> {
            Ok(coder_core::api::AuditLogResponse {
                audit_logs: Vec::new(),
                count: 0,
            })
        }

        async fn insert_audit_log(
            &self,
            _input: coder_core::ports::PersistAuditLogInput,
        ) -> Result<(), StorageError> {
            Ok(())
        }

        async fn batch_insert_audit_logs(
            &self,
            _logs: Vec<coder_core::ports::PersistAuditLogInput>,
        ) -> Result<(), StorageError> {
            Ok(())
        }

        async fn batch_insert_workspace_build_parameters(
            &self,
            _params: Vec<coder_core::ports::WorkspaceBuildParameterRecord>,
        ) -> Result<(), StorageError> {
            Ok(())
        }

        async fn batch_update_workspace_last_used_at(
            &self,
            _ids: &[uuid::Uuid],
            _last_used_at: time::OffsetDateTime,
        ) -> Result<u64, StorageError> {
            Ok(0)
        }

        async fn upsert_workspace_stats_workspace(
            &self,
            _input: &coder_core::ports::WorkspaceStatsWorkspaceInput,
        ) -> Result<(), StorageError> {
            Ok(())
        }

        async fn upsert_workspace_build_stats(
            &self,
            _input: &coder_core::ports::WorkspaceBuildStatsInput,
        ) -> Result<(), StorageError> {
            Ok(())
        }

        async fn insert_workspace_agent_stat(
            &self,
            _input: &coder_core::ports::WorkspaceAgentStatInput,
        ) -> Result<(), StorageError> {
            Ok(())
        }

        async fn upsert_workspace_proxy_for_health(
            &self,
            _input: &coder_core::ports::WorkspaceProxyHealthInput,
        ) -> Result<(), StorageError> {
            Ok(())
        }

        async fn get_file_by_hash_and_creator(
            &self,
            _hash: &str,
            _creator_id: uuid::Uuid,
        ) -> Result<Option<coder_core::ports::FileRecord>, StorageError> {
            Ok(None)
        }

        async fn health_settings(&self) -> Result<coder_core::api::HealthSettings, StorageError> {
            Ok(coder_core::api::HealthSettings {
                dismissed_healthchecks: Vec::new(),
            })
        }

        async fn upsert_health_settings(
            &self,
            _settings: &coder_core::api::HealthSettings,
        ) -> Result<bool, StorageError> {
            Ok(false)
        }

        async fn find_git_ssh_key(
            &self,
            _user_id: uuid::Uuid,
        ) -> Result<Option<coder_core::ports::GitSshKeyRecord>, StorageError> {
            Ok(None)
        }

        async fn insert_file(
            &self,
            _input: coder_core::ports::InsertFileInput,
        ) -> Result<coder_core::ports::InsertFileResult, StorageError> {
            Err(StorageError::unavailable("not implemented in mock"))
        }

        async fn get_file_by_id(
            &self,
            _file_id: uuid::Uuid,
        ) -> Result<Option<coder_core::ports::FileRecord>, StorageError> {
            Ok(None)
        }

        async fn delete_file(&self, _file_id: uuid::Uuid) -> Result<bool, StorageError> {
            Ok(false)
        }

        async fn list_workspace_proxies_for_health(
            &self,
        ) -> Result<Vec<WorkspaceProxyHealthRecord>, StorageError> {
            Ok(self.proxies.lock().await.clone())
        }

        async fn list_provisioner_daemons_for_health(
            &self,
        ) -> Result<Vec<ProvisionerDaemonHealthRecord>, StorageError> {
            Ok(self.daemons.lock().await.clone())
        }

        async fn deployment_stats(
            &self,
        ) -> Result<coder_core::api::DeploymentStatsResponse, StorageError> {
            Ok(coder_core::api::DeploymentStatsResponse {
                aggregated_from: OffsetDateTime::now_utc(),
                collected_at: OffsetDateTime::now_utc(),
                next_update_at: OffsetDateTime::now_utc(),
                workspaces: Default::default(),
                session_count: Default::default(),
            })
        }

        async fn find_users_by_ids(
            &self,
            _ids: &[uuid::Uuid],
        ) -> Result<Vec<UserRecord>, StorageError> {
            Ok(Vec::new())
        }

        async fn upsert_provisioner_job_stats(
            &self,
            _input: &coder_core::ports::ProvisionerJobStatsInput,
        ) -> Result<(), StorageError> {
            Err(StorageError::unavailable("not implemented in mock"))
        }

        async fn upsert_provisioner_daemon_for_health(
            &self,
            _input: &coder_core::ports::ProvisionerDaemonHealthInput,
        ) -> Result<(), StorageError> {
            Err(StorageError::unavailable("not implemented in mock"))
        }

        async fn upsert_git_ssh_key(
            &self,
            _user_id: uuid::Uuid,
            _public_key: &str,
            _private_key: &str,
        ) -> Result<coder_core::ports::GitSshKeyRecord, StorageError> {
            Err(StorageError::unavailable("not implemented in mock"))
        }
    }

    fn test_config() -> ServerConfig {
        ServerConfig {
            listen_addr: "127.0.0.1:0"
                .parse()
                .unwrap_or_else(|_| std::net::SocketAddr::from(([127, 0, 0, 1], 0))),
            access_url: reqwest::Url::parse("http://127.0.0.1:0").unwrap_or_else(|_| {
                reqwest::Url::parse("http://localhost").unwrap_or_else(|_| unreachable!())
            }),
            wildcard_access_url: String::new(),
            database: coder_core::DatabaseConfig {
                postgres_url: String::new(),
                max_connections: 1,
                min_connections: 1,
                acquire_timeout_secs: 5,
            },
            tls: coder_core::config::TlsConfig::default(),
            networking: coder_core::config::NetworkingConfig::default(),
            http_cookies: coder_core::config::HttpCookieConfig::default(),
            telemetry: coder_core::config::TelemetryConfig::default(),
            ssh: coder_core::SshConfig {
                hostname_prefix: String::new(),
                hostname_suffix: String::new(),
                ssh_config_options: std::collections::HashMap::new(),
            },
            external_auth_providers: Vec::new(),
            derp_regions: Vec::new(),
            shutdown_grace_period_secs: 5,
            log_format: coder_core::LogFormat::Pretty,
            logging: coder_core::config::LoggingConfig::default(),
            session_cache_ttl_secs: 30,
            audit_batch_flush_interval_ms: 500,
            audit_batch_max_size: 50,
            max_concurrent_requests: 1024,
            max_concurrent_db_queries: 40,
            rate_limit: coder_core::config::RateLimitConfig::default(),
            github_oauth: None,
            oidc: None,
            otel: coder_core::config::OtelConfig::default(),
            cors: coder_core::config::CorsConfig::default(),
            security_headers: coder_core::config::SecurityHeadersConfig::default(),
            provisioner: coder_core::config::ProvisionerConfig::default(),
            session_lifetime: coder_core::config::SessionLifetimeConfig::default(),
            dangerous: coder_core::config::DangerousConfig::default(),
            healthcheck: coder_core::config::HealthcheckConfig::default(),
            workspace: coder_core::config::WorkspaceConfig::default(),
            swagger_enabled: true,
            update_check: false,
            ssh_keygen_algorithm: "ed25519".to_owned(),
            cache_dir: String::new(),
            browser_only: false,
            disable_password_auth: false,
            disable_path_apps: false,
            disable_owner_workspace_exec: false,
            strict_transport_security: 0,
            strict_transport_security_options: Vec::new(),
            experiments: Vec::new(),
            agent_fallback_troubleshooting_url: String::new(),
            terms_of_service_url: String::new(),
            web_terminal_renderer: String::new(),
            allow_workspace_renames: false,
            additional_csp_policy: Vec::new(),
            disable_workspace_sharing: false,
            docs_url: String::new(),
            scim_api_key: String::new(),
            cli_upgrade_message: String::new(),
            worker: coder_core::config::WorkerConfig::default(),
        }
    }

    fn test_build_metadata() -> BuildMetadata {
        BuildMetadata {
            version: "0.0.0-test".to_owned(),
            git_commit: "test".to_owned(),
            external_url: String::new(),
            agent_api_version: String::new(),
            provisioner_api_version: String::new(),
            upgrade_message: String::new(),
            workspace_proxy: false,
        }
    }

    // ── Git SSH key tests ────────────────────────────────────

    #[test]
    fn generate_git_ssh_key_returns_valid_keypair() {
        let result = generate_git_ssh_key("test@coder.com");
        assert!(result.is_ok());
        let key = result.unwrap_or_else(|_| unreachable!());
        assert!(
            key.public_key.starts_with("ssh-ed25519"),
            "public key should start with ssh-ed25519"
        );
        assert!(
            key.private_key.contains("BEGIN OPENSSH PRIVATE KEY"),
            "private key should contain PEM header"
        );
    }

    #[test]
    fn generate_git_ssh_key_includes_comment_in_public_key() {
        let result = generate_git_ssh_key("alice@example.com");
        assert!(result.is_ok());
        let key = result.unwrap_or_else(|_| unreachable!());
        assert!(
            key.public_key.contains("alice@example.com"),
            "public key should contain the comment"
        );
        assert!(
            key.public_key.ends_with('\n'),
            "public key should end with a newline"
        );
    }

    #[test]
    fn generate_git_ssh_key_empty_comment() {
        let result = generate_git_ssh_key("");
        assert!(result.is_ok());
        let key = result.unwrap_or_else(|_| unreachable!());
        assert!(key.public_key.starts_with("ssh-ed25519"));
    }

    #[test]
    fn generate_git_ssh_key_produces_unique_keys() {
        let key1 = generate_git_ssh_key("a").unwrap_or_else(|_| unreachable!());
        let key2 = generate_git_ssh_key("a").unwrap_or_else(|_| unreachable!());
        assert_ne!(
            key1.private_key, key2.private_key,
            "two generated keys should differ"
        );
    }

    // ── Health service tests ─────────────────────────────────

    #[tokio::test]
    async fn health_report_with_healthy_store() {
        let store = MockStore::healthy();
        let svc = HealthService::new(store).unwrap_or_else(|_| unreachable!());
        let config = test_config();
        let meta = test_build_metadata();

        let report = svc.report(&config, &meta, true).await;
        assert!(report.is_ok());
        let report = report.unwrap_or_else(|_| unreachable!());

        assert_eq!(report.database.base.severity, HealthSeverity::Ok);
        assert!(report.database.healthy);
        assert!(report.database.reachable);
    }

    #[tokio::test]
    async fn health_report_with_unhealthy_database() {
        let store = MockStore::healthy().with_ping_failing();
        let svc = HealthService::new(store).unwrap_or_else(|_| unreachable!());
        let config = test_config();
        let meta = test_build_metadata();

        let report = svc.report(&config, &meta, true).await;
        assert!(report.is_ok());
        let report = report.unwrap_or_else(|_| unreachable!());

        assert_eq!(report.database.base.severity, HealthSeverity::Error);
        assert!(!report.database.healthy);
        assert!(!report.database.reachable);
        assert!(report.database.base.error.is_some());
    }

    #[tokio::test]
    async fn health_report_cache_returns_same_result() {
        let store = MockStore::healthy();
        let call_count = store.ping_call_count.clone();
        let svc = HealthService::new(store).unwrap_or_else(|_| unreachable!());
        let config = test_config();
        let meta = test_build_metadata();

        // First call: populates the cache
        let report1 = svc.report(&config, &meta, false).await;
        assert!(report1.is_ok());
        let count_after_first = call_count.load(Ordering::SeqCst);

        // Second call: should use cache (no additional ping)
        let report2 = svc.report(&config, &meta, false).await;
        assert!(report2.is_ok());
        let count_after_second = call_count.load(Ordering::SeqCst);

        assert_eq!(
            count_after_first, count_after_second,
            "second call should use cache without pinging again"
        );

        let r1 = report1.unwrap_or_else(|_| unreachable!());
        let r2 = report2.unwrap_or_else(|_| unreachable!());
        assert_eq!(r1.time, r2.time, "cached report should have same timestamp");
    }

    #[tokio::test]
    async fn health_report_force_bypasses_cache() {
        let store = MockStore::healthy();
        let call_count = store.ping_call_count.clone();
        let svc = HealthService::new(store).unwrap_or_else(|_| unreachable!());
        let config = test_config();
        let meta = test_build_metadata();

        let _r1 = svc.report(&config, &meta, true).await;
        let count1 = call_count.load(Ordering::SeqCst);

        let _r2 = svc.report(&config, &meta, true).await;
        let count2 = call_count.load(Ordering::SeqCst);

        assert!(
            count2 > count1,
            "force=true should bypass cache and ping again"
        );
    }

    #[tokio::test]
    async fn provisioner_daemon_offline_detection() {
        let old_daemon = ProvisionerDaemonHealthRecord {
            id: uuid::Uuid::new_v4(),
            organization_id: uuid::Uuid::new_v4(),
            created_at: OffsetDateTime::now_utc() - time::Duration::hours(1),
            last_seen_at: Some(OffsetDateTime::now_utc() - time::Duration::minutes(10)),
            name: "stale-daemon".to_owned(),
            version: "1.0.0".to_owned(),
            api_version: "1.0".to_owned(),
            provisioners: vec!["terraform".to_owned()],
            tags: HashMap::new(),
            status: None,
        };

        let store = MockStore::with_daemons(vec![old_daemon]);
        let svc = HealthService::new(store).unwrap_or_else(|_| unreachable!());
        let config = test_config();
        let meta = test_build_metadata();

        let report = svc.report(&config, &meta, true).await;
        assert!(report.is_ok());
        let report = report.unwrap_or_else(|_| unreachable!());

        assert_eq!(
            report.provisioner_daemons.base.severity,
            HealthSeverity::Warning
        );
        assert!(
            report
                .provisioner_daemons
                .base
                .warnings
                .iter()
                .any(|w| w.contains("offline")),
            "should have an offline warning"
        );
        assert!(
            report
                .provisioner_daemons
                .items
                .iter()
                .any(|i| i.contains("offline")),
            "daemon item should show offline status"
        );
    }

    #[tokio::test]
    async fn provisioner_daemon_idle_when_recently_seen() {
        let recent_daemon = ProvisionerDaemonHealthRecord {
            id: uuid::Uuid::new_v4(),
            organization_id: uuid::Uuid::new_v4(),
            created_at: OffsetDateTime::now_utc(),
            last_seen_at: Some(OffsetDateTime::now_utc() - time::Duration::seconds(30)),
            name: "active-daemon".to_owned(),
            version: "1.0.0".to_owned(),
            api_version: "1.0".to_owned(),
            provisioners: vec!["terraform".to_owned()],
            tags: HashMap::new(),
            status: None,
        };

        let store = MockStore::with_daemons(vec![recent_daemon]);
        let svc = HealthService::new(store).unwrap_or_else(|_| unreachable!());
        let config = test_config();
        let meta = test_build_metadata();

        let report = svc.report(&config, &meta, true).await;
        assert!(report.is_ok());
        let report = report.unwrap_or_else(|_| unreachable!());

        assert_eq!(report.provisioner_daemons.base.severity, HealthSeverity::Ok);
        assert!(
            report
                .provisioner_daemons
                .items
                .iter()
                .any(|i| i.contains("idle")),
            "recently-seen daemon should show idle status"
        );
    }

    #[tokio::test]
    async fn provisioner_daemon_with_explicit_status() {
        let daemon = ProvisionerDaemonHealthRecord {
            id: uuid::Uuid::new_v4(),
            organization_id: uuid::Uuid::new_v4(),
            created_at: OffsetDateTime::now_utc(),
            last_seen_at: Some(OffsetDateTime::now_utc()),
            name: "busy-daemon".to_owned(),
            version: "1.0.0".to_owned(),
            api_version: "1.0".to_owned(),
            provisioners: vec!["terraform".to_owned()],
            tags: HashMap::new(),
            status: Some("busy".to_owned()),
        };

        let store = MockStore::with_daemons(vec![daemon]);
        let svc = HealthService::new(store).unwrap_or_else(|_| unreachable!());
        let config = test_config();
        let meta = test_build_metadata();

        let report = svc.report(&config, &meta, true).await;
        assert!(report.is_ok());
        let report = report.unwrap_or_else(|_| unreachable!());

        assert!(
            report
                .provisioner_daemons
                .items
                .iter()
                .any(|i| i.contains("busy")),
            "daemon with explicit status should use that status"
        );
    }

    // ── max_severity tests ───────────────────────────────────

    #[test]
    fn max_severity_error_dominates() {
        assert_eq!(
            max_severity(HealthSeverity::Error, HealthSeverity::Ok),
            HealthSeverity::Error
        );
        assert_eq!(
            max_severity(HealthSeverity::Ok, HealthSeverity::Error),
            HealthSeverity::Error
        );
    }

    #[test]
    fn max_severity_warning_over_ok() {
        assert_eq!(
            max_severity(HealthSeverity::Warning, HealthSeverity::Ok),
            HealthSeverity::Warning
        );
    }

    #[test]
    fn max_severity_ok_when_both_ok() {
        assert_eq!(
            max_severity(HealthSeverity::Ok, HealthSeverity::Ok),
            HealthSeverity::Ok
        );
    }

    // ── Circuit breaker health aggregation tests ──────────────

    #[tokio::test]
    async fn health_report_includes_circuit_breaker_statuses() {
        let store = MockStore::healthy();
        let svc = HealthService::new(store).unwrap_or_else(|_| unreachable!());
        let config = test_config();
        let meta = test_build_metadata();

        let report = svc.report(&config, &meta, true).await;
        assert!(report.is_ok());
        let report = report.unwrap_or_else(|_| unreachable!());

        // Default registry has 5 breakers, all should be Closed.
        assert_eq!(report.circuit_breakers.len(), 5);
        for cb in &report.circuit_breakers {
            assert_eq!(cb.state, CircuitBreakerState::Closed);
            assert_eq!(cb.consecutive_failures, 0);
        }
    }

    #[tokio::test]
    async fn health_report_severity_elevated_when_breaker_open() {
        use coder_core::{CircuitBreaker, CircuitBreakerConfig, CircuitBreakerRegistry};

        let fast = CircuitBreakerConfig {
            failure_threshold: 1,
            reset_timeout: Duration::from_secs(300),
            half_open_max_probes: 1,
        };
        let breaker = CircuitBreaker::new("test_dep", fast);

        // Trip the breaker.
        let _: Result<(), _> = breaker.call(|| async { Err::<(), &str>("boom") }).await;
        assert_eq!(breaker.state().await, CircuitBreakerState::Open);

        let registry = CircuitBreakerRegistry::new(vec![breaker]);
        let store = MockStore::healthy();
        let svc = HealthService::with_circuit_breakers(store, registry)
            .unwrap_or_else(|_| unreachable!());
        let config = test_config();
        let meta = test_build_metadata();

        let report = svc.report(&config, &meta, true).await;
        assert!(report.is_ok());
        let report = report.unwrap_or_else(|_| unreachable!());

        // An open breaker should raise severity to at least Warning.
        assert!(
            report.severity == HealthSeverity::Warning || report.severity == HealthSeverity::Error,
            "severity should be at least Warning when a breaker is open, got {:?}",
            report.severity
        );
        assert_eq!(report.circuit_breakers.len(), 1);
        assert_eq!(report.circuit_breakers[0].state, CircuitBreakerState::Open);
    }

    #[tokio::test]
    async fn health_report_with_custom_registry_no_defaults() {
        let registry = CircuitBreakerRegistry::new(vec![]);
        let store = MockStore::healthy();
        let svc = HealthService::with_circuit_breakers(store, registry)
            .unwrap_or_else(|_| unreachable!());
        let config = test_config();
        let meta = test_build_metadata();

        let report = svc.report(&config, &meta, true).await;
        assert!(report.is_ok());
        let report = report.unwrap_or_else(|_| unreachable!());

        // Empty registry → no circuit breaker statuses in report.
        assert!(report.circuit_breakers.is_empty());
    }

    #[tokio::test]
    async fn provisioner_offline_records_breaker_failure() {
        let old_daemon = ProvisionerDaemonHealthRecord {
            id: uuid::Uuid::new_v4(),
            organization_id: uuid::Uuid::new_v4(),
            created_at: OffsetDateTime::now_utc() - time::Duration::hours(1),
            last_seen_at: Some(OffsetDateTime::now_utc() - time::Duration::minutes(10)),
            name: "stale-daemon".to_owned(),
            version: "1.0.0".to_owned(),
            api_version: "1.0".to_owned(),
            provisioners: vec!["terraform".to_owned()],
            tags: HashMap::new(),
            status: None,
        };

        let store = MockStore::with_daemons(vec![old_daemon]);
        let svc = HealthService::new(store).unwrap_or_else(|_| unreachable!());
        let config = test_config();
        let meta = test_build_metadata();

        let report = svc.report(&config, &meta, true).await;
        assert!(report.is_ok());
        let report = report.unwrap_or_else(|_| unreachable!());

        // The provisioner_daemons breaker should have recorded at least
        // one failure.
        let prov_cb = report
            .circuit_breakers
            .iter()
            .find(|s| s.name == "provisioner_daemons");
        assert!(prov_cb.is_some(), "provisioner breaker should be in report");
        let prov_cb = prov_cb.unwrap_or_else(|| unreachable!());
        assert!(
            prov_cb.consecutive_failures >= 1,
            "provisioner breaker should have recorded at least one failure, got {}",
            prov_cb.consecutive_failures
        );
    }

    // ── Telemetry snapshot test ──────────────────────────────

    #[tokio::test]
    async fn telemetry_snapshot_collects_stats() {
        let store = MockStore::healthy();
        // Create service without background loop by constructing directly
        let service = Arc::new(TelemetryService {
            store,
            deployment_id: "test-deploy-id".to_owned(),
            version: "0.0.1-test".to_owned(),
        });

        let snapshot = service.collect_snapshot().await;
        assert!(snapshot.is_ok());
        let snapshot = snapshot.unwrap_or_else(|_| unreachable!());
        assert_eq!(snapshot.deployment_id, "test-deploy-id");
        assert_eq!(snapshot.version, "0.0.1-test");
        assert!(
            !snapshot.timestamp.is_empty(),
            "timestamp should be non-empty"
        );
        assert_eq!(snapshot.active_sessions, 0);
        assert_eq!(snapshot.workspaces, 0);
    }
}
