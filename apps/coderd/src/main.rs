#![forbid(unsafe_code)]

mod shutdown;

use std::time::Duration;
use std::{net::SocketAddr, process::ExitCode, sync::Arc};

use async_trait::async_trait;
use clap::{Args, Parser, Subcommand, ValueEnum};
use coder_audit::{AuditEvent, AuditSink};
use coder_connectivity::agents::InMemoryAgentProvider;
use coder_connectivity::tailnet::{
    DerpTrafficTracker, InMemoryCoordinator, build_derp_map_from_config,
};
use coder_core::pubsub::PubSub;
use coder_core::{
    AppStore, BuildMetadata, DatabaseConfig, DeploymentStore, DerpRegionConfig,
    ExternalAuthLinkProvider, LogFormat, PersistAuditLogInput, ServerConfig, SshConfig,
    StorageError, config::RateLimitConfig,
};
use coder_db::{DatabaseInitError, MigrationError, PostgresPubSub, PostgresStore, run_migrations};
use coder_server::{AppState, build_router};
use metrics_exporter_prometheus::PrometheusBuilder;
use shutdown::ShutdownCoordinator;
use thiserror::Error;
use time::OffsetDateTime;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use url::Url;
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(author, version, about = "Rust backend service for the Coder rewrite")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start the Rust coderd service.
    Server(ServerArgs),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum LogFormatArg {
    Pretty,
    Json,
}

#[derive(Debug, Args)]
struct ServerArgs {
    /// Bind address for the HTTP listener.
    #[arg(long, env = "CODER_LISTEN_ADDR", default_value = "127.0.0.1:3000")]
    listen_addr: SocketAddr,

    /// External access URL advertised by the deployment.
    #[arg(
        long,
        env = "CODER_ACCESS_URL",
        default_value = "http://127.0.0.1:3000"
    )]
    access_url: Url,

    /// Postgres connection string.
    #[arg(long, env = "CODER_POSTGRES_URL")]
    postgres_url: String,

    /// Maximum number of pooled Postgres connections.
    #[arg(long, env = "CODER_DB_MAX_CONNECTIONS", default_value_t = 20)]
    db_max_connections: u32,

    /// Minimum number of pooled Postgres connections.
    #[arg(long, env = "CODER_DB_MIN_CONNECTIONS", default_value_t = 1)]
    db_min_connections: u32,

    /// Seconds to wait when acquiring a pooled connection.
    #[arg(long, env = "CODER_DB_ACQUIRE_TIMEOUT_SECS", default_value_t = 10)]
    db_acquire_timeout_secs: u64,

    /// Enable deployment telemetry.
    #[arg(long, env = "CODER_TELEMETRY_ENABLED", default_value_t = false)]
    telemetry_enabled: bool,

    /// Deprecated SSH hostname prefix kept for compatibility.
    #[arg(long, env = "CODER_SSH_HOSTNAME_PREFIX", default_value = "coder")]
    ssh_hostname_prefix: String,

    /// SSH hostname suffix appended to workspace hostnames.
    #[arg(long, env = "CODER_SSH_HOSTNAME_SUFFIX", default_value = "")]
    ssh_hostname_suffix: String,

    /// JSON array of configured external auth providers.
    #[arg(long, env = "CODER_EXTERNAL_AUTH_PROVIDERS_JSON", default_value = "[]")]
    external_auth_providers_json: String,

    /// JSON array of DERP regions used by the Rust health service.
    #[arg(long, env = "CODER_DERP_REGIONS_JSON", default_value = "[]")]
    derp_regions_json: String,

    /// Grace period for shutdown.
    #[arg(long, env = "CODER_SHUTDOWN_GRACE_PERIOD_SECS", default_value_t = 10)]
    shutdown_grace_period_secs: u64,

    /// Output format for logs.
    #[arg(long, env = "CODER_LOG_FORMAT", value_enum, default_value_t = LogFormatArg::Pretty)]
    log_format: LogFormatArg,

    /// Session cache TTL in seconds.
    #[arg(long, env = "CODER_SESSION_CACHE_TTL_SECS", default_value_t = 30)]
    session_cache_ttl_secs: u64,

    /// Audit batch flush interval in milliseconds.
    #[arg(
        long,
        env = "CODER_AUDIT_BATCH_FLUSH_INTERVAL_MS",
        default_value_t = 500
    )]
    audit_batch_flush_interval_ms: u64,

    /// Maximum number of audit events per batch.
    #[arg(long, env = "CODER_AUDIT_BATCH_MAX_SIZE", default_value_t = 50)]
    audit_batch_max_size: usize,

    /// Maximum number of concurrent HTTP requests before returning 503.
    #[arg(long, env = "CODER_MAX_CONCURRENT_REQUESTS", default_value_t = 1024)]
    max_concurrent_requests: usize,

    /// Maximum number of concurrent database queries.
    #[arg(long, env = "CODER_MAX_CONCURRENT_DB_QUERIES", default_value_t = 0)]
    max_concurrent_db_queries: usize,

    /// Enable HTTP rate limiting.
    #[arg(long, env = "CODER_RATE_LIMIT_ENABLED", default_value_t = true)]
    rate_limit_enabled: bool,

    /// Maximum general API requests per minute for authenticated users.
    #[arg(long, env = "CODER_RATE_LIMIT_API_PER_MINUTE", default_value_t = 600)]
    rate_limit_api_per_minute: u32,

    /// Maximum login attempts per minute per IP address.
    #[arg(long, env = "CODER_RATE_LIMIT_LOGIN_PER_MINUTE", default_value_t = 5)]
    rate_limit_login_per_minute: u32,

    /// Maximum API requests per minute for unauthenticated IPs.
    #[arg(
        long,
        env = "CODER_RATE_LIMIT_UNAUTHENTICATED_PER_MINUTE",
        default_value_t = 60
    )]
    rate_limit_unauthenticated_per_minute: u32,

    /// Run database migrations and exit without starting the server.
    #[arg(long, env = "CODER_MIGRATE_ONLY", default_value_t = false)]
    migrate_only: bool,
}

#[derive(Debug, Error)]
enum MainError {
    #[error("invalid configuration: {0}")]
    Config(String),
    #[error(transparent)]
    DatabaseInit(#[from] DatabaseInitError),
    #[error(transparent)]
    Migration(#[from] MigrationError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error("listen on {listen_addr}: {source}")]
    Listen {
        listen_addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("serve HTTP: {0}")]
    Serve(#[source] std::io::Error),
}

struct PersistingAuditSink {
    store: Arc<dyn AppStore>,
}

#[async_trait]
impl AuditSink for PersistingAuditSink {
    async fn record(&self, event: AuditEvent) {
        info!(
            action = event.action.as_str(),
            resource = ?event.resource,
            actor_user_id = event.actor_user_id.map(|value| value.to_string()),
            target_id = event.target_id,
            summary = event.summary,
            "audit event"
        );

        if let Err(error) = self
            .store
            .insert_audit_log(Self::event_to_input(&event))
            .await
        {
            warn!(error = %error, "failed to persist audit event");
        }
    }

    /// Persists a batch of audit events using a single multi-row INSERT
    /// via [`AppStore::batch_insert_audit_logs`].  Falls back to
    /// individual inserts if the batch call fails.
    async fn record_batch(&self, events: Vec<AuditEvent>) {
        if events.is_empty() {
            return;
        }

        for event in &events {
            info!(
                action = event.action.as_str(),
                resource = ?event.resource,
                actor_user_id = event.actor_user_id.as_ref().map(Uuid::to_string),
                target_id = event.target_id,
                summary = event.summary,
                "audit event"
            );
        }

        let inputs: Vec<PersistAuditLogInput> = events.iter().map(Self::event_to_input).collect();

        if let Err(batch_error) = self.store.batch_insert_audit_logs(inputs).await {
            warn!(
                error = %batch_error,
                count = events.len(),
                "batch audit insert failed, falling back to individual inserts"
            );
            for event in &events {
                if let Err(error) = self
                    .store
                    .insert_audit_log(Self::event_to_input(event))
                    .await
                {
                    warn!(error = %error, "failed to persist audit event (individual fallback)");
                }
            }
        }
    }
}

impl PersistingAuditSink {
    fn new(store: Arc<dyn AppStore>) -> Self {
        Self { store }
    }

    fn event_to_input(event: &AuditEvent) -> PersistAuditLogInput {
        PersistAuditLogInput {
            id: Uuid::new_v4(),
            request_id: None,
            time: OffsetDateTime::now_utc(),
            ip: String::new(),
            user_agent: String::new(),
            resource_type: resource_kind_name(event.resource).to_owned(),
            resource_id: event
                .target_id
                .as_deref()
                .and_then(|target_id| Uuid::parse_str(target_id).ok()),
            resource_target: event.target_id.clone().unwrap_or_default(),
            resource_icon: String::new(),
            action: event.action.as_str().to_owned(),
            diff: serde_json::json!({}),
            status_code: 0,
            additional_fields: serde_json::json!({}),
            description: event.summary.clone(),
            resource_link: String::new(),
            is_deleted: matches!(event.action, coder_audit::AuditAction::Delete),
            organization_id: None,
            user_id: event.actor_user_id,
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), MainError> {
    let cli = Cli::parse();
    let Command::Server(args) = cli.command;

    init_tracing(args.log_format);
    init_panic_hook();

    let migrate_only = args.migrate_only;
    let config = build_config(args)?;

    let store = PostgresStore::connect(&config.database).await?;
    let pool = store.pool();
    run_migrations(&pool).await?;

    if migrate_only {
        info!("--migrate-only requested, exiting after migrations");
        return Ok(());
    }

    let deployment_metadata = store.ensure_deployment_metadata().await?;
    let store_pool = store.pool();
    let store: Arc<dyn AppStore> = Arc::new(store);

    let pubsub: Arc<dyn PubSub> = Arc::new(
        PostgresPubSub::new(store_pool.clone())
            .await
            .map_err(|error| MainError::Config(format!("create pubsub: {error}")))?,
    );

    let agent_provider = Arc::new(InMemoryAgentProvider::new());
    let derp_map = build_derp_map_from_config(&config.derp_regions);
    let coordinator = InMemoryCoordinator::new(derp_map);
    let derp_tracker = DerpTrafficTracker::new();
    let prometheus_handle = PrometheusBuilder::new()
        .install_recorder()
        .map_err(|error| MainError::Config(format!("install prometheus recorder: {error}")))?;

    let state = AppState::new(
        config.clone(),
        BuildMetadata::default(),
        deployment_metadata.deployment_id,
        store.clone(),
        Arc::new(PersistingAuditSink::new(store)),
        pubsub.clone(),
        agent_provider,
        coordinator,
        derp_tracker,
        Some(prometheus_handle),
    )
    .map_err(|error| MainError::Config(format!("build shared HTTP services: {error}")))?;

    let listener = tokio::net::TcpListener::bind(config.listen_addr)
        .await
        .map_err(|source| MainError::Listen {
            listen_addr: config.listen_addr,
            source,
        })?;

    let rate_limit_state = coder_server::RateLimitState::new(&config.rate_limit).map(Arc::new);
    let application = build_router(state.clone(), rate_limit_state);
    info!(
        listen_addr = %config.listen_addr,
        access_url = %config.access_url,
        "starting Rust coderd"
    );

    let serve_result = axum::serve(listener, application.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(MainError::Serve);

    // --- Graceful shutdown sequence ---
    let grace_period = Duration::from_secs(config.shutdown_grace_period_secs);
    info!(
        grace_period_secs = config.shutdown_grace_period_secs,
        "graceful shutdown initiated"
    );

    let mut coordinator = ShutdownCoordinator::new();

    // 1. Flush the batched audit sink so buffered events are persisted
    //    before the database pool is closed.
    let audit_sink = state.audit.clone();
    coordinator.register("audit", async move {
        audit_sink.close().await;
    });

    // 2. Close pub/sub background listener and release its PgListener connection.
    coordinator.register("pubsub", async move {
        if let Err(e) = pubsub.close().await {
            warn!(error = %e, "pubsub close failed");
        }
    });

    // 3. Cancel the deployment-stats background refresh loop.
    coordinator.register("deployment_stats", async move {
        state.close_deployment_stats();
    });

    // 4. Close the database connection pool last so preceding tasks can still
    //    issue final queries during their own shutdown.
    coordinator.register("database", async move {
        store_pool.close().await;
    });

    coordinator.run(grace_period).await;
    info!("shutdown complete");

    serve_result
}

fn build_config(args: ServerArgs) -> Result<ServerConfig, MainError> {
    if args.db_min_connections > args.db_max_connections {
        return Err(MainError::Config(
            "db-min-connections cannot exceed db-max-connections".to_owned(),
        ));
    }

    Ok(ServerConfig {
        listen_addr: args.listen_addr,
        access_url: args.access_url,
        database: DatabaseConfig {
            postgres_url: args.postgres_url,
            max_connections: args.db_max_connections,
            min_connections: args.db_min_connections,
            acquire_timeout_secs: args.db_acquire_timeout_secs,
        },
        telemetry_enabled: args.telemetry_enabled,
        ssh: SshConfig {
            hostname_prefix: args.ssh_hostname_prefix,
            hostname_suffix: args.ssh_hostname_suffix,
            ssh_config_options: vec![("StrictHostKeyChecking".to_owned(), "no".to_owned())],
        },
        external_auth_providers: serde_json::from_str::<Vec<ExternalAuthLinkProvider>>(
            &args.external_auth_providers_json,
        )
        .map_err(|error| {
            MainError::Config(format!("invalid external auth providers JSON: {error}"))
        })?,
        derp_regions: serde_json::from_str::<Vec<DerpRegionConfig>>(&args.derp_regions_json)
            .map_err(|error| MainError::Config(format!("invalid DERP regions JSON: {error}")))?,
        shutdown_grace_period_secs: args.shutdown_grace_period_secs,
        log_format: match args.log_format {
            LogFormatArg::Pretty => LogFormat::Pretty,
            LogFormatArg::Json => LogFormat::Json,
        },
        session_cache_ttl_secs: args.session_cache_ttl_secs,
        audit_batch_flush_interval_ms: args.audit_batch_flush_interval_ms,
        audit_batch_max_size: args.audit_batch_max_size,
        max_concurrent_requests: args.max_concurrent_requests,
        max_concurrent_db_queries: if args.max_concurrent_db_queries > 0 {
            args.max_concurrent_db_queries
        } else {
            args.db_max_connections as usize * 2
        },
        rate_limit: RateLimitConfig {
            enabled: args.rate_limit_enabled,
            login_per_minute: args.rate_limit_login_per_minute,
            api_per_minute: args.rate_limit_api_per_minute,
            unauthenticated_per_minute: args.rate_limit_unauthenticated_per_minute,
            audit_per_minute: 30,
        },
    })
}

fn init_panic_hook() {
    std::panic::set_hook(Box::new(move |panic_info| {
        let backtrace = std::backtrace::Backtrace::force_capture();
        let location = panic_info
            .location()
            .map(|loc| format!("{}:{}", loc.file(), loc.line()));
        tracing::error!(panic = true, %panic_info, ?location, %backtrace, "Server Panic");
    }));
}

fn init_tracing(log_format: LogFormatArg) {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    match log_format {
        LogFormatArg::Pretty => {
            tracing_subscriber::fmt()
                .with_env_filter(env_filter)
                .with_target(false)
                .compact()
                .init();
        }
        LogFormatArg::Json => {
            tracing_subscriber::fmt()
                .with_env_filter(env_filter)
                .with_target(false)
                .json()
                .init();
        }
    }
}

async fn shutdown_signal() {
    if let Err(signal_error) = wait_for_shutdown_signal().await {
        error!(
            error = %signal_error,
            "failed to install graceful shutdown handlers"
        );
        std::future::pending::<()>().await;
    }
}

async fn wait_for_shutdown_signal() -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut terminate = signal(SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result?,
            _ = terminate.recv() => {}
        }
        Ok(())
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
        Ok(())
    }
}

fn resource_kind_name(resource: coder_rbac::ResourceKind) -> &'static str {
    match resource {
        coder_rbac::ResourceKind::Authentication => "user",
        coder_rbac::ResourceKind::ExternalAuth => "user",
        coder_rbac::ResourceKind::Organization => "organization",
        coder_rbac::ResourceKind::Template => "template",
        coder_rbac::ResourceKind::TemplateVersion => "template_version",
        coder_rbac::ResourceKind::User => "user",
        coder_rbac::ResourceKind::Workspace => "workspace",
        coder_rbac::ResourceKind::GitSshKey => "git_ssh_key",
        coder_rbac::ResourceKind::ApiKey => "api_key",
        coder_rbac::ResourceKind::Group => "group",
        coder_rbac::ResourceKind::WorkspaceBuild => "workspace_build",
        coder_rbac::ResourceKind::License => "license",
        coder_rbac::ResourceKind::WorkspaceProxy => "workspace_proxy",
        coder_rbac::ResourceKind::ConvertLogin => "convert_login",
        coder_rbac::ResourceKind::HealthSettings => "health_settings",
        coder_rbac::ResourceKind::Oauth2ProviderApp => "oauth2_provider_app",
        coder_rbac::ResourceKind::Oauth2ProviderAppSecret => "oauth2_provider_app_secret",
        coder_rbac::ResourceKind::CustomRole => "custom_role",
        coder_rbac::ResourceKind::OrganizationMember => "organization_member",
        coder_rbac::ResourceKind::NotificationsSettings => "notifications_settings",
        coder_rbac::ResourceKind::NotificationTemplate => "notification_template",
        coder_rbac::ResourceKind::IdpSyncSettingsOrganization => "idp_sync_settings_organization",
        coder_rbac::ResourceKind::IdpSyncSettingsGroup => "idp_sync_settings_group",
        coder_rbac::ResourceKind::IdpSyncSettingsRole => "idp_sync_settings_role",
        coder_rbac::ResourceKind::WorkspaceAgent => "workspace_agent",
        coder_rbac::ResourceKind::WorkspaceApp => "workspace_app",
        coder_rbac::ResourceKind::PrebuildsSettings => "prebuilds_settings",
        coder_rbac::ResourceKind::Task => "task",
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[test]
    fn cli_parse_server_defaults() {
        let cli = Cli::parse_from([
            "coderd",
            "server",
            "--postgres-url",
            "postgres://localhost/test",
        ]);
        let Command::Server(args) = cli.command;
        assert!(!args.migrate_only);
        assert_eq!(args.listen_addr.to_string(), "127.0.0.1:3000");
    }

    #[test]
    fn cli_parse_migrate_only_flag() {
        let cli = Cli::parse_from([
            "coderd",
            "server",
            "--postgres-url",
            "postgres://localhost/test",
            "--migrate-only",
        ]);
        let Command::Server(args) = cli.command;
        assert!(args.migrate_only);
    }

    #[test]
    fn cli_parse_without_migrate_only() {
        // When --migrate-only is not passed, it defaults to false.
        let cli = Cli::parse_from([
            "coderd",
            "server",
            "--postgres-url",
            "postgres://localhost/test",
        ]);
        let Command::Server(args) = cli.command;
        assert!(!args.migrate_only);
        assert_eq!(args.db_max_connections, 20);
    }
}
