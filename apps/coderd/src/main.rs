//! Rust `coderd` binary — the main entry point for the Coder backend.
//!
//! Parses CLI arguments via [`clap`], initialises the database pool and
//! migrations, constructs the [`coder_server::AppState`], and starts the
//! Axum HTTP server with graceful shutdown.
//!
//! # Subcommands
//!
//! * `server` — start the HTTP service (the only subcommand today)
//!
//! # Environment
//!
//! Every flag has a corresponding `CODER_*` environment variable so that
//! the binary can be configured purely via env in container deployments.
#![forbid(unsafe_code)]

mod shutdown;

use std::collections::HashMap;
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
    AppStore, BuildMetadata, CorsConfig, DatabaseConfig, DeploymentStore, DerpRegionConfig,
    ExternalAuthLinkProvider, LogFormat, OtelConfig, PersistAuditLogInput, ServerConfig, SshConfig,
    StorageError,
    config::{
        DangerousConfig, GithubOAuthConfig, HealthcheckConfig, HttpCookieConfig, LoggingConfig,
        NetworkingConfig, OidcConfig, ProvisionerConfig, RateLimitConfig, SecurityHeadersConfig,
        SessionLifetimeConfig, TelemetryConfig, TlsConfig, WorkerConfig, WorkspaceConfig,
    },
};
use coder_db::{DatabaseInitError, MigrationError, PostgresPubSub, PostgresStore, run_migrations};
use coder_notifications::{NotificationConfig, NotificationDispatchService, SmtpTlsMode};
use coder_server::{AppState, build_router};
use coder_workspaces::{
    ActivityBumpWorker, AutobuildExecutor, DormancyCheckerWorker, LifecycleScheduler,
    parse_quiet_hours_schedule,
};
use metrics_exporter_prometheus::PrometheusBuilder;
use opentelemetry::trace::TracerProvider;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::trace::SdkTracerProvider;
use shutdown::ShutdownCoordinator;
use thiserror::Error;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
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

    /// Wildcard hostname for workspace application routing.
    #[arg(long, env = "CODER_WILDCARD_ACCESS_URL", default_value = "")]
    wildcard_access_url: String,

    // ----- TLS -----
    /// Enable TLS termination.
    #[arg(long, env = "CODER_TLS_ENABLE", default_value_t = false)]
    tls_enable: bool,

    /// Bind address for the HTTPS listener.
    #[arg(long, env = "CODER_TLS_ADDRESS", default_value = "127.0.0.1:3443")]
    tls_address: String,

    /// Redirect HTTP requests to HTTPS when TLS is enabled.
    #[arg(long, env = "CODER_TLS_REDIRECT_HTTP_TO_HTTPS", default_value_t = true)]
    tls_redirect_http: bool,

    /// Comma-separated paths to TLS certificate files.
    #[arg(long, env = "CODER_TLS_CERT_FILE", default_value = "")]
    tls_cert_files: String,

    /// Comma-separated paths to TLS private key files.
    #[arg(long, env = "CODER_TLS_KEY_FILE", default_value = "")]
    tls_key_files: String,

    /// Minimum TLS version accepted (tls10, tls11, tls12, tls13).
    #[arg(long, env = "CODER_TLS_MIN_VERSION", default_value = "tls12")]
    tls_min_version: String,

    // ----- Networking -----
    /// Redirect requests that do not match the access URL host.
    #[arg(long, env = "CODER_REDIRECT_TO_ACCESS_URL", default_value_t = false)]
    redirect_to_access_url: bool,

    /// Comma-separated HTTP headers to trust from a reverse proxy.
    #[arg(long, env = "CODER_PROXY_TRUSTED_HEADERS", default_value = "")]
    proxy_trusted_headers: String,

    /// Comma-separated trusted proxy origin addresses (CIDR or IP).
    #[arg(long, env = "CODER_PROXY_TRUSTED_ORIGINS", default_value = "")]
    proxy_trusted_origins: String,

    // ----- HTTP Cookies -----
    /// Set the Secure flag on session cookies.
    #[arg(long, env = "CODER_SECURE_AUTH_COOKIE", default_value_t = false)]
    secure_auth_cookie: bool,

    /// SameSite attribute for session cookies (lax, strict, none).
    #[arg(long, env = "CODER_SAMESITE_AUTH_COOKIE", default_value = "lax")]
    same_site_auth_cookie: String,

    // ----- Telemetry -----
    /// Enable deployment telemetry.
    #[arg(
        long = "telemetry",
        env = "CODER_TELEMETRY_ENABLE",
        default_value_t = false
    )]
    telemetry_enabled: bool,

    /// Enable trace-level telemetry data collection.
    #[arg(long, env = "CODER_TRACE_ENABLE", default_value_t = false)]
    telemetry_trace: bool,

    /// URL of the telemetry collection endpoint.
    #[arg(
        long,
        env = "CODER_TELEMETRY_URL",
        default_value = "https://telemetry.coder.com"
    )]
    telemetry_url: String,

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

    /// Enable OpenTelemetry distributed tracing.
    #[arg(long, env = "CODER_OTEL_ENABLED", default_value_t = false)]
    otel_enabled: bool,

    /// OTLP gRPC endpoint for trace export.
    #[arg(
        long,
        env = "CODER_OTEL_ENDPOINT",
        default_value = "http://localhost:4317"
    )]
    otel_endpoint: String,

    /// Trace sampling ratio (0.0 – 1.0).
    #[arg(long, env = "CODER_OTEL_SAMPLE_RATIO", default_value_t = 1.0)]
    otel_sample_ratio: f64,

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

    // ----- GitHub OAuth2 -----
    /// GitHub OAuth2 client ID.
    #[arg(long, env = "CODER_GITHUB_CLIENT_ID", default_value = "")]
    github_client_id: String,

    /// GitHub OAuth2 client secret.
    #[arg(long, env = "CODER_GITHUB_CLIENT_SECRET", default_value = "")]
    github_client_secret: String,

    /// Allow new user signups via GitHub OAuth.
    #[arg(long, env = "CODER_GITHUB_ALLOW_SIGNUPS", default_value_t = false)]
    github_allow_signups: bool,

    /// Allow all GitHub users (skip org/team checks).
    #[arg(long, env = "CODER_GITHUB_ALLOW_EVERYONE", default_value_t = false)]
    github_allow_everyone: bool,

    /// Comma-separated list of allowed GitHub organization logins.
    #[arg(long, env = "CODER_GITHUB_ALLOWED_ORGS", default_value = "")]
    github_allowed_orgs: String,

    /// Comma-separated list of allowed GitHub team slugs (org/team format).
    #[arg(long, env = "CODER_GITHUB_ALLOWED_TEAMS", default_value = "")]
    github_allowed_teams: String,

    /// GitHub API base URL.
    #[arg(
        long,
        env = "CODER_GITHUB_API_URL",
        default_value = "https://api.github.com"
    )]
    github_api_url: Url,

    // ----- OIDC -----
    /// OIDC issuer URL.
    #[arg(long, env = "CODER_OIDC_ISSUER_URL", default_value = "")]
    oidc_issuer_url: String,

    /// OIDC client ID.
    #[arg(long, env = "CODER_OIDC_CLIENT_ID", default_value = "")]
    oidc_client_id: String,

    /// OIDC client secret.
    #[arg(long, env = "CODER_OIDC_CLIENT_SECRET", default_value = "")]
    oidc_client_secret: String,

    /// Comma-separated OIDC scopes to request.
    #[arg(
        long,
        env = "CODER_OIDC_SCOPES",
        default_value = "openid,profile,email"
    )]
    oidc_scopes: String,

    /// Allow new user signups via OIDC.
    #[arg(long, env = "CODER_OIDC_ALLOW_SIGNUPS", default_value_t = true)]
    oidc_allow_signups: bool,

    /// Comma-separated list of allowed email domains for OIDC.
    #[arg(long, env = "CODER_OIDC_EMAIL_DOMAIN", default_value = "")]
    oidc_email_domain: String,

    /// OIDC claim field to use as username.
    #[arg(
        long,
        env = "CODER_OIDC_USERNAME_FIELD",
        default_value = "preferred_username"
    )]
    oidc_username_field: String,

    /// OIDC claim field to use as email.
    #[arg(long, env = "CODER_OIDC_EMAIL_FIELD", default_value = "email")]
    oidc_email_field: String,

    /// OIDC claim field to use as display name.
    #[arg(long, env = "CODER_OIDC_NAME_FIELD", default_value = "name")]
    oidc_name_field: String,

    /// Ignore the email_verified claim from the OIDC provider.
    #[arg(
        long,
        env = "CODER_OIDC_IGNORE_EMAIL_VERIFIED",
        default_value_t = false
    )]
    oidc_ignore_email_verified: bool,

    /// Run database migrations and exit without starting the server.
    #[arg(long, env = "CODER_MIGRATE_ONLY", default_value_t = false)]
    migrate_only: bool,

    // ----- Logging -----
    /// Enable verbose (debug-level) logging.
    #[arg(long, env = "CODER_VERBOSE", default_value_t = false)]
    verbose: bool,

    /// Output path for human-readable logs. Empty disables.
    #[arg(long, env = "CODER_LOGGING_HUMAN", default_value = "/dev/stderr")]
    log_human: String,

    /// Output path for JSON-formatted logs. Empty disables.
    #[arg(long, env = "CODER_LOGGING_JSON", default_value = "")]
    log_json: String,

    /// Output path for Stackdriver-formatted logs. Empty disables.
    #[arg(long, env = "CODER_LOGGING_STACKDRIVER", default_value = "")]
    log_stackdriver: String,

    /// Comma-separated log filter directives.
    #[arg(long, env = "CODER_LOG_FILTER", default_value = "")]
    log_filter: String,

    // ----- Provisioner -----
    /// Number of built-in provisioner daemons to run.
    #[arg(long, env = "CODER_PROVISIONER_DAEMONS", default_value_t = 3)]
    provisioner_daemon_count: u32,

    /// Polling interval in milliseconds for provisioner job acquisition.
    #[arg(
        long,
        env = "CODER_PROVISIONER_DAEMON_POLL_INTERVAL",
        default_value_t = 1000
    )]
    provisioner_poll_interval_ms: u64,

    /// Random jitter in milliseconds added to provisioner polling interval.
    #[arg(
        long,
        env = "CODER_PROVISIONER_DAEMON_POLL_JITTER",
        default_value_t = 100
    )]
    provisioner_poll_jitter_ms: u64,

    /// Interval in milliseconds after which a provisioner job is force-cancelled.
    #[arg(
        long,
        env = "CODER_PROVISIONER_FORCE_CANCEL_INTERVAL",
        default_value_t = 600_000
    )]
    provisioner_force_cancel_interval_ms: u64,

    /// Pre-shared key for external provisioner daemon authentication.
    #[arg(long, env = "CODER_PROVISIONER_DAEMON_PSK", default_value = "")]
    provisioner_daemon_psk: String,

    // ----- Session Lifetime -----
    /// Default session duration in hours.
    #[arg(long, env = "CODER_SESSION_DURATION", default_value_t = 24)]
    session_duration_hours: u64,

    /// Disable automatic session expiry refresh on activity.
    #[arg(
        long,
        env = "CODER_DISABLE_SESSION_EXPIRY_REFRESH",
        default_value_t = false
    )]
    disable_session_expiry_refresh: bool,

    /// Maximum lifetime in hours for API tokens (default 90 days).
    #[arg(long, env = "CODER_MAX_TOKEN_LIFETIME", default_value_t = 2160)]
    max_token_lifetime_hours: u64,

    // ----- Dangerous -----
    /// DANGEROUS: Allow all CORS origins.
    #[arg(
        long,
        env = "CODER_DANGEROUS_ALLOW_CORS_REQUESTS",
        default_value_t = false
    )]
    dangerous_allow_all_cors: bool,

    /// DANGEROUS: Allow sharing path-based workspace applications.
    #[arg(
        long,
        env = "CODER_DANGEROUS_ALLOW_PATH_APP_SHARING",
        default_value_t = false
    )]
    dangerous_allow_path_app_sharing: bool,

    /// DANGEROUS: Allow site owners to access path-based workspace apps.
    #[arg(
        long,
        env = "CODER_DANGEROUS_ALLOW_PATH_APP_SITE_OWNER_ACCESS",
        default_value_t = false
    )]
    dangerous_allow_path_app_site_owner_access: bool,

    // ----- Healthcheck -----
    /// Interval in seconds between automatic health check refreshes.
    #[arg(long, env = "CODER_HEALTH_CHECK_REFRESH", default_value_t = 600)]
    healthcheck_refresh_secs: u64,

    /// Database health check latency threshold in milliseconds.
    #[arg(
        long,
        env = "CODER_HEALTH_CHECK_THRESHOLD_DATABASE",
        default_value_t = 15
    )]
    healthcheck_threshold_database_ms: u64,

    // ----- Workspace -----
    /// Default quiet hours cron schedule for workspaces.
    #[arg(
        long,
        env = "CODER_QUIET_HOURS_DEFAULT_SCHEDULE",
        default_value = "CRON_TZ=UTC 0 0 * * *"
    )]
    default_quiet_hours_schedule: String,

    /// Whether workspace renames are allowed.
    #[arg(long, env = "CODER_ALLOW_WORKSPACE_RENAMES", default_value_t = false)]
    allow_workspace_renames: bool,

    // ----- Security -----
    /// Only allow browser-based connections to workspaces.
    #[arg(long, env = "CODER_BROWSER_ONLY", default_value_t = false)]
    browser_only: bool,

    /// Disable password-based authentication.
    #[arg(long, env = "CODER_DISABLE_PASSWORD_AUTH", default_value_t = false)]
    disable_password_auth: bool,

    /// Disable path-based workspace application routing.
    #[arg(long, env = "CODER_DISABLE_PATH_APPS", default_value_t = false)]
    disable_path_apps: bool,

    /// Disable workspace exec for site owners.
    #[arg(
        long,
        env = "CODER_DISABLE_OWNER_WORKSPACE_ACCESS",
        default_value_t = false
    )]
    disable_owner_workspace_exec: bool,

    /// Disable workspace sharing.
    #[arg(long, env = "CODER_DISABLE_WORKSPACE_SHARING", default_value_t = false)]
    disable_workspace_sharing: bool,

    /// HSTS max-age in seconds. Zero disables HSTS.
    #[arg(long, env = "CODER_STRICT_TRANSPORT_SECURITY", default_value_t = 0)]
    strict_transport_security: u64,

    /// Comma-separated additional HSTS options.
    #[arg(
        long,
        env = "CODER_STRICT_TRANSPORT_SECURITY_OPTIONS",
        default_value = ""
    )]
    strict_transport_security_options: String,

    // ----- Swagger / Update / Misc -----
    /// Whether the /swagger endpoint is accessible.
    #[arg(long, env = "CODER_SWAGGER_ENABLE", default_value_t = true)]
    swagger_enabled: bool,

    /// Periodically check for new Coder releases.
    #[arg(long, env = "CODER_UPDATE_CHECK", default_value_t = false)]
    update_check: bool,

    /// Algorithm used for SSH key generation.
    #[arg(long, env = "CODER_SSH_KEYGEN_ALGORITHM", default_value = "ed25519")]
    ssh_keygen_algorithm: String,

    /// Directory for caching temporary files.
    #[arg(long, env = "CODER_CACHE_DIRECTORY", default_value = "~/.cache/coder")]
    cache_dir: String,

    /// Comma-separated list of enabled experiment feature flags.
    #[arg(long, env = "CODER_EXPERIMENTS", default_value = "")]
    experiments: String,

    /// Fallback troubleshooting URL shown when agent connections fail.
    #[arg(
        long,
        env = "CODER_AGENT_FALLBACK_TROUBLESHOOTING_URL",
        default_value = ""
    )]
    agent_fallback_troubleshooting_url: String,

    /// URL to terms of service displayed to users.
    #[arg(long, env = "CODER_TERMS_OF_SERVICE_URL", default_value = "")]
    terms_of_service_url: String,

    /// Renderer for web terminals (canvas, dom, webgl).
    #[arg(long, env = "CODER_WEB_TERMINAL_RENDERER", default_value = "")]
    web_terminal_renderer: String,

    /// Custom documentation URL override.
    #[arg(
        long,
        env = "CODER_DOCS_URL",
        default_value = "https://coder.com/docs/coder-oss"
    )]
    docs_url: String,

    /// SCIM API key for user provisioning. Empty disables SCIM.
    #[arg(long, env = "CODER_SCIM_AUTH_HEADER", default_value = "")]
    scim_api_key: String,

    /// Message displayed to users suggesting they upgrade the CLI.
    #[arg(long, env = "CODER_CLI_UPGRADE_MESSAGE", default_value = "")]
    cli_upgrade_message: String,

    /// Comma-separated additional Content-Security-Policy directives.
    #[arg(long, env = "CODER_ADDITIONAL_CSP_POLICY", default_value = "")]
    additional_csp_policy: String,

    // ----- Security Headers -----
    /// Value for the X-Content-Type-Options response header.
    #[arg(long, env = "CODER_X_CONTENT_TYPE_OPTIONS", default_value = "nosniff")]
    x_content_type_options: String,

    /// Value for the X-Frame-Options response header.
    #[arg(long, env = "CODER_X_FRAME_OPTIONS", default_value = "DENY")]
    x_frame_options: String,

    /// Value for the Referrer-Policy response header.
    #[arg(long, env = "CODER_REFERRER_POLICY", default_value = "no-referrer")]
    referrer_policy: String,

    // ----- Worker Intervals -----
    // ----- SMTP / Notifications -----
    /// SMTP relay host for email notifications (empty = email disabled).
    #[arg(long, env = "CODER_NOTIFICATIONS_SMTP_HOST", default_value = "")]
    smtp_host: String,

    /// SMTP relay port (587 for STARTTLS, 465 for implicit TLS, 25 for plain).
    #[arg(long, env = "CODER_NOTIFICATIONS_SMTP_PORT", default_value_t = 587)]
    smtp_port: u16,

    /// Sender email address for outgoing notifications.
    #[arg(long, env = "CODER_NOTIFICATIONS_SMTP_FROM", default_value = "")]
    smtp_from: String,

    /// SMTP authentication username (empty = no auth).
    #[arg(long, env = "CODER_NOTIFICATIONS_SMTP_USERNAME", default_value = "")]
    smtp_username: String,

    /// SMTP authentication password.
    #[arg(long, env = "CODER_NOTIFICATIONS_SMTP_PASSWORD", default_value = "")]
    smtp_password: String,

    /// TLS mode for the SMTP connection (none, tls, start_tls).
    #[arg(
        long,
        env = "CODER_NOTIFICATIONS_SMTP_TLS_MODE",
        default_value = "start_tls"
    )]
    smtp_tls_mode: String,

    /// Timeout in seconds for outgoing webhook notifications.
    #[arg(
        long,
        env = "CODER_NOTIFICATIONS_WEBHOOK_TIMEOUT",
        default_value_t = 30
    )]
    webhook_timeout_secs: u64,

    /// Poll interval in seconds for the notification dispatch worker.
    #[arg(
        long,
        env = "CODER_NOTIFICATION_DISPATCH_INTERVAL",
        default_value_t = 10,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    notification_dispatch_interval_secs: u64,

    /// Poll interval in seconds for the activity bump worker.
    #[arg(
        long,
        env = "CODER_ACTIVITY_BUMP_INTERVAL",
        default_value_t = 10,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    activity_bump_interval_secs: u64,

    /// Poll interval in seconds for the dormancy checker worker.
    #[arg(
        long,
        env = "CODER_DORMANCY_CHECK_INTERVAL",
        default_value_t = 60,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    dormancy_check_interval_secs: u64,

    /// Flush interval in seconds for the telemetry batching worker.
    #[arg(
        long,
        env = "CODER_TELEMETRY_FLUSH_INTERVAL",
        default_value_t = 1800,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    telemetry_flush_interval_secs: u64,

    /// Poll interval in seconds for the lifecycle scheduler (autostart/autostop).
    #[arg(
        long,
        env = "CODER_LIFECYCLE_CHECK_INTERVAL",
        default_value_t = 30,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    lifecycle_check_interval_secs: u64,

    /// Comma-separated list of allowed CORS origins.  When empty every origin
    /// is permitted (wildcard).
    #[arg(
        long,
        env = "CODER_CORS_ALLOWED_ORIGINS",
        default_value = "",
        value_delimiter = ','
    )]
    cors_allowed_origins: Vec<String>,

    /// Whether cross-origin requests may include credentials.
    ///
    /// Note: Credentials are only allowed when one or more explicit origins are
    /// configured via `--cors-allowed-origins` / `CODER_CORS_ALLOWED_ORIGINS`.
    /// In wildcard mode (no explicit origins), `Access-Control-Allow-Credentials`
    /// is not sent, even if this flag is true.
    #[arg(long, env = "CODER_CORS_ALLOW_CREDENTIALS", default_value_t = false)]
    cors_allow_credentials: bool,
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

    let log_format = args.log_format;
    let migrate_only = args.migrate_only;
    let notification_config = NotificationConfig {
        smtp_host: args.smtp_host.clone(),
        smtp_port: args.smtp_port,
        smtp_from: args.smtp_from.clone(),
        smtp_username: args.smtp_username.clone(),
        smtp_password: args.smtp_password.clone(),
        smtp_tls_mode: parse_smtp_tls_mode(&args.smtp_tls_mode),
        webhook_timeout_secs: args.webhook_timeout_secs,
    };
    let config = build_config(args)?;
    let tracer_provider = init_tracing(log_format, &config.otel);
    init_panic_hook();

    let store = PostgresStore::connect(&config.database).await?;
    let pool = store.pool();
    let report = run_migrations(&pool).await?;

    if report.applied_count > 0 {
        info!(
            applied = report.applied_count,
            total = report.total_count,
            "applied new database migrations"
        );
    } else {
        info!(total = report.total_count, "database schema is up to date");
    }

    if migrate_only {
        info!("--migrate-only requested, exiting after migrations");
        pool.close().await;
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
    // Start the telemetry background worker.
    let telemetry_config = coder_telemetry::TelemetryConfig {
        enabled: config.telemetry.enabled,
        deployment_id: deployment_metadata.deployment_id,
        version: BuildMetadata::default().version.clone(),
        flush_interval: Duration::from_secs(config.worker.telemetry_flush_interval_secs),
        ..coder_telemetry::TelemetryConfig::default()
    };
    let (mut telemetry_worker, telemetry_reporter) =
        coder_telemetry::TelemetryWorker::start(telemetry_config);

    let prometheus_handle = PrometheusBuilder::new()
        .install_recorder()
        .map_err(|error| MainError::Config(format!("install prometheus recorder: {error}")))?;

    // Start the notification dispatch background worker.
    //
    // NOTE: The `Webpusher` is NOT wired into `AppState` yet because the
    // `AppStore` trait methods it depends on (`get_webpush_vapid_keys`,
    // `upsert_webpush_vapid_keys`, `get_webpush_subscriptions_by_user_id`,
    // `delete_webpush_subscription_by_user_and_endpoint`,
    // `delete_webpush_subscriptions`, `delete_all_webpush_subscriptions`)
    // currently return `StorageError::unavailable` — the `PostgresStore`
    // implementations have not been added.  Once those DB methods exist,
    // instantiate a `Webpusher<Arc<dyn AppStore>>` here and add it as a
    // field on `AppState` so HTTP handlers can send push notifications.
    let notification_cancel = CancellationToken::new();
    let (notification_service, notification_handle) = NotificationDispatchService::new(
        store.clone(),
        notification_config,
        config.worker.notification_dispatch_interval_secs,
        notification_cancel.clone(),
    )
    .map_err(|error| MainError::Config(format!("create notification service: {error}")))?;

    // Start the activity bump background worker.
    let activity_bump_cancel = CancellationToken::new();
    let activity_bump_worker = ActivityBumpWorker::start(
        store.clone(),
        config.worker.activity_bump_interval_secs,
        activity_bump_cancel.clone(),
    );

    // Start the dormancy checker background worker.
    let dormancy_cancel = CancellationToken::new();
    let dormancy_worker = DormancyCheckerWorker::start(
        store.clone(),
        config.worker.dormancy_check_interval_secs,
        dormancy_cancel.clone(),
    );

    // Start the autobuild lifecycle executor (workspace auto-start/stop).
    let autobuild_cancel = CancellationToken::new();
    let (_autobuild_executor, autobuild_handle) =
        AutobuildExecutor::start(store.clone(), autobuild_cancel.clone());

    // Start the lifecycle scheduler (autostart/autostop/failed-stop retry).
    let quiet_hours = parse_quiet_hours_schedule(&config.workspace.default_quiet_hours_schedule);
    let lifecycle_scheduler = LifecycleScheduler::start(
        store.clone(),
        config.worker.lifecycle_check_interval_secs,
        quiet_hours,
        CancellationToken::new(),
    );

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
        coder_connectivity::derp::DerpServer::new(coder_connectivity::derp::NodeKey::new(
            [0u8; 32],
        )),
        Some(prometheus_handle),
        telemetry_reporter,
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

    // 1b. Flush and shut down the telemetry background worker so buffered
    //     events are submitted before the process exits.
    coordinator.register("telemetry", async move {
        telemetry_worker.shutdown().await;
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

    // 4. Cancel the notification dispatch loop and wait for in-flight
    //    dispatch cycles to finish their DB writes before the pool is
    //    closed in a later step.  Mirrors the autobuild executor pattern.
    coordinator.register("notifications", async move {
        notification_cancel.cancel();
        drop(notification_service);
        if let Err(e) = notification_handle.await {
            warn!(error = %e, "notification dispatch task panicked during shutdown");
        }
    });

    // 4b. Cancel the activity bump background worker and await completion
    //     so in-flight DB queries finish before the pool is closed.
    coordinator.register("activity_bump", async move {
        activity_bump_worker.join().await;
    });

    // 4c. Cancel the dormancy checker background worker and await completion
    //     so in-flight DB queries finish before the pool is closed.
    coordinator.register("dormancy_checker", async move {
        dormancy_worker.join().await;
    });

    // 4d. Cancel the lifecycle scheduler and await completion so in-flight
    //     DB queries finish before the pool is closed.
    coordinator.register("lifecycle_scheduler", async move {
        lifecycle_scheduler.join().await;
    });

    // 5. Cancel the autobuild lifecycle executor and wait for in-flight
    //    evaluations to finish so database writes complete before the pool
    //    is closed later.
    coordinator.register("autobuild", async move {
        autobuild_cancel.cancel();
        if let Err(e) = autobuild_handle.await {
            warn!(error = %e, "autobuild executor task panicked during shutdown");
        }
    });

    // 6. Flush and shut down the OpenTelemetry tracer provider so buffered
    //    spans are exported before the process exits.  The OTLP exporter
    //    sends to a remote collector (gRPC), not to the database, so this
    //    is safe to run before closing the DB pool.
    coordinator.register("opentelemetry", async move {
        if let Some(provider) = tracer_provider {
            if let Err(e) = provider.shutdown() {
                warn!(error = %e, "opentelemetry tracer shutdown failed");
            }
        }
    });

    // 7. Close the database connection pool last so preceding tasks can
    //    still issue final queries during their own shutdown.
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

    if args.otel_sample_ratio.is_nan()
        || args.otel_sample_ratio.is_infinite()
        || args.otel_sample_ratio < 0.0
        || args.otel_sample_ratio > 1.0
    {
        return Err(MainError::Config(
            "otel-sample-ratio must be between 0.0 and 1.0 (inclusive)".to_owned(),
        ));
    }

    Ok(ServerConfig {
        listen_addr: args.listen_addr,
        access_url: args.access_url,
        wildcard_access_url: args.wildcard_access_url,
        database: DatabaseConfig {
            postgres_url: args.postgres_url,
            max_connections: args.db_max_connections,
            min_connections: args.db_min_connections,
            acquire_timeout_secs: args.db_acquire_timeout_secs,
        },
        tls: TlsConfig {
            enabled: args.tls_enable,
            address: args.tls_address,
            redirect_http: args.tls_redirect_http,
            cert_files: split_csv(&args.tls_cert_files),
            key_files: split_csv(&args.tls_key_files),
            min_version: args.tls_min_version,
        },
        networking: NetworkingConfig {
            redirect_to_access_url: args.redirect_to_access_url,
            proxy_trusted_headers: split_csv(&args.proxy_trusted_headers),
            proxy_trusted_origins: split_csv(&args.proxy_trusted_origins),
        },
        http_cookies: HttpCookieConfig {
            secure_auth_cookie: args.secure_auth_cookie,
            same_site: args.same_site_auth_cookie,
        },
        telemetry: TelemetryConfig {
            enabled: args.telemetry_enabled,
            trace: args.telemetry_trace,
            url: args.telemetry_url,
        },
        ssh: SshConfig {
            hostname_prefix: args.ssh_hostname_prefix,
            hostname_suffix: args.ssh_hostname_suffix,
            ssh_config_options: HashMap::from([(
                "StrictHostKeyChecking".to_owned(),
                "no".to_owned(),
            )]),
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
        logging: LoggingConfig {
            verbose: args.verbose,
            human_path: args.log_human,
            json_path: args.log_json,
            stackdriver_path: args.log_stackdriver,
            log_filter: split_csv(&args.log_filter),
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
        github_oauth: if args.github_client_id.is_empty() {
            None
        } else {
            Some(GithubOAuthConfig {
                client_id: args.github_client_id,
                client_secret: args.github_client_secret,
                allow_signups: args.github_allow_signups,
                allow_everyone: args.github_allow_everyone,
                allowed_orgs: split_csv(&args.github_allowed_orgs),
                allowed_teams: split_csv(&args.github_allowed_teams),
                api_url: args.github_api_url,
            })
        },
        oidc: if args.oidc_issuer_url.is_empty() {
            None
        } else {
            let issuer_url = Url::parse(&args.oidc_issuer_url)
                .map_err(|error| MainError::Config(format!("invalid OIDC issuer URL: {error}")))?;
            Some(OidcConfig {
                issuer_url,
                client_id: args.oidc_client_id,
                client_secret: args.oidc_client_secret,
                scopes: split_csv(&args.oidc_scopes),
                allow_signups: args.oidc_allow_signups,
                email_domain: split_csv(&args.oidc_email_domain),
                username_field: args.oidc_username_field,
                email_field: args.oidc_email_field,
                name_field: args.oidc_name_field,
                ignore_email_verified: args.oidc_ignore_email_verified,
            })
        },
        otel: OtelConfig {
            enabled: args.otel_enabled,
            endpoint: args.otel_endpoint,
            service_name: "coderd".to_owned(),
            sample_ratio: args.otel_sample_ratio,
        },
        cors: CorsConfig {
            allowed_origins: args
                .cors_allowed_origins
                .into_iter()
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
                .collect(),
            allow_credentials: args.cors_allow_credentials,
            max_age_secs: 3600,
        },
        provisioner: ProvisionerConfig {
            daemon_count: args.provisioner_daemon_count,
            poll_interval_ms: args.provisioner_poll_interval_ms,
            poll_jitter_ms: args.provisioner_poll_jitter_ms,
            force_cancel_interval_ms: args.provisioner_force_cancel_interval_ms,
            daemon_psk: args.provisioner_daemon_psk,
        },
        session_lifetime: SessionLifetimeConfig {
            default_duration_hours: args.session_duration_hours,
            disable_expiry_refresh: args.disable_session_expiry_refresh,
            max_token_lifetime_hours: args.max_token_lifetime_hours,
        },
        dangerous: DangerousConfig {
            allow_all_cors: args.dangerous_allow_all_cors,
            allow_path_app_sharing: args.dangerous_allow_path_app_sharing,
            allow_path_app_site_owner_access: args.dangerous_allow_path_app_site_owner_access,
        },
        healthcheck: HealthcheckConfig {
            refresh_secs: args.healthcheck_refresh_secs,
            threshold_database_ms: args.healthcheck_threshold_database_ms,
        },
        workspace: WorkspaceConfig {
            default_quiet_hours_schedule: args.default_quiet_hours_schedule,
        },
        worker: WorkerConfig {
            notification_dispatch_interval_secs: args.notification_dispatch_interval_secs,
            activity_bump_interval_secs: args.activity_bump_interval_secs,
            dormancy_check_interval_secs: args.dormancy_check_interval_secs,
            telemetry_flush_interval_secs: args.telemetry_flush_interval_secs,
            lifecycle_check_interval_secs: args.lifecycle_check_interval_secs,
        },
        swagger_enabled: args.swagger_enabled,
        update_check: args.update_check,
        ssh_keygen_algorithm: args.ssh_keygen_algorithm,
        cache_dir: args.cache_dir,
        browser_only: args.browser_only,
        disable_password_auth: args.disable_password_auth,
        disable_path_apps: args.disable_path_apps,
        disable_owner_workspace_exec: args.disable_owner_workspace_exec,
        strict_transport_security: args.strict_transport_security,
        strict_transport_security_options: split_csv(&args.strict_transport_security_options),
        experiments: split_csv(&args.experiments),
        agent_fallback_troubleshooting_url: args.agent_fallback_troubleshooting_url,
        terms_of_service_url: args.terms_of_service_url,
        web_terminal_renderer: args.web_terminal_renderer,
        allow_workspace_renames: args.allow_workspace_renames,
        additional_csp_policy: split_csv(&args.additional_csp_policy),
        security_headers: SecurityHeadersConfig {
            x_content_type_options: args.x_content_type_options,
            x_frame_options: args.x_frame_options,
            referrer_policy: args.referrer_policy,
        },
        disable_workspace_sharing: args.disable_workspace_sharing,
        docs_url: args.docs_url,
        scim_api_key: args.scim_api_key,
        cli_upgrade_message: args.cli_upgrade_message,
    })
}

/// Parses a CLI/env string into a [`SmtpTlsMode`].
///
/// Accepted values (case-insensitive): `none`, `tls`, `start_tls` / `starttls`.
/// Falls back to [`SmtpTlsMode::StartTls`] for unrecognised input.
fn parse_smtp_tls_mode(value: &str) -> SmtpTlsMode {
    match value.to_ascii_lowercase().as_str() {
        "none" => SmtpTlsMode::None,
        "tls" => SmtpTlsMode::Tls,
        "start_tls" | "starttls" => SmtpTlsMode::StartTls,
        _ => SmtpTlsMode::StartTls,
    }
}

/// Splits a comma-separated string into a `Vec<String>`, trimming whitespace
/// and discarding empty entries.
fn split_csv(input: &str) -> Vec<String> {
    input
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
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

/// Initialises the global tracing subscriber.
///
/// When OpenTelemetry is enabled via `otel_config`, a [`SdkTracerProvider`] is
/// constructed with an OTLP gRPC exporter and wired into the subscriber as an
/// additional layer.  The returned provider **must** be shut down during the
/// graceful-shutdown sequence so that buffered spans are flushed.
fn init_tracing(log_format: LogFormatArg, otel_config: &OtelConfig) -> Option<SdkTracerProvider> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    // Build the optional tracer provider.
    let tracer_provider = if otel_config.enabled {
        match build_otel_provider(otel_config) {
            Ok(provider) => Some(provider),
            Err(e) => {
                eprintln!("WARNING: failed to initialise OpenTelemetry: {e}");
                None
            }
        }
    } else {
        None
    };

    // The OTel layer must be constructed inside each match arm because the
    // `OpenTelemetryLayer<S, T>` type parameter `S` depends on the concrete
    // fmt layer variant (compact vs json).
    match log_format {
        LogFormatArg::Pretty => {
            let fmt_layer = tracing_subscriber::fmt::layer()
                .with_target(false)
                .compact();
            let otel_layer = tracer_provider
                .as_ref()
                .map(|p| tracing_opentelemetry::layer().with_tracer(p.tracer("coderd")));
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt_layer)
                .with(otel_layer)
                .init();
        }
        LogFormatArg::Json => {
            let fmt_layer = tracing_subscriber::fmt::layer().with_target(false).json();
            let otel_layer = tracer_provider
                .as_ref()
                .map(|p| tracing_opentelemetry::layer().with_tracer(p.tracer("coderd")));
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt_layer)
                .with(otel_layer)
                .init();
        }
    }

    tracer_provider
}

/// Builds an [`SdkTracerProvider`] configured with an OTLP gRPC exporter.
fn build_otel_provider(
    config: &OtelConfig,
) -> Result<SdkTracerProvider, Box<dyn std::error::Error + Send + Sync>> {
    use opentelemetry_sdk::trace::Sampler;

    // Set the global text-map propagator so that incoming W3C TraceContext
    // headers (traceparent / tracestate) are understood by the SDK.
    opentelemetry::global::set_text_map_propagator(
        opentelemetry_sdk::propagation::TraceContextPropagator::new(),
    );

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(&config.endpoint)
        .build()?;

    let sampler = if (config.sample_ratio - 1.0_f64).abs() < f64::EPSILON {
        Sampler::AlwaysOn
    } else if config.sample_ratio <= 0.0 {
        Sampler::AlwaysOff
    } else {
        Sampler::TraceIdRatioBased(config.sample_ratio)
    };

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_sampler(sampler)
        .with_resource(
            opentelemetry_sdk::Resource::builder()
                .with_service_name(config.service_name.clone())
                .build(),
        )
        .build();

    Ok(provider)
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
