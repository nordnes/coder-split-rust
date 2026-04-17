//! Runtime configuration models for the Rust backend slice.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::api::{ConfigOption, ExternalAuthLinkProvider};

/// Server configuration used by the Rust `coderd` binary.
///
/// # Examples
///
/// ```
/// use coder_core::ServerConfig;
///
/// // List all supported configuration options and their environment variables.
/// let options = ServerConfig::supported_options();
/// assert!(!options.is_empty());
///
/// // Each option exposes its env-var name for 12-factor config.
/// let first = &options[0];
/// assert!(!first.env.is_empty());
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerConfig {
    /// Bind address for the HTTP server.
    pub listen_addr: std::net::SocketAddr,
    /// External access URL for the deployment.
    pub access_url: Url,
    /// Wildcard hostname for workspace application routing.
    pub wildcard_access_url: String,
    /// Database settings for Postgres.
    pub database: DatabaseConfig,
    /// TLS configuration for HTTPS termination.
    pub tls: TlsConfig,
    /// Networking settings (proxy headers, redirect).
    pub networking: NetworkingConfig,
    /// HTTP cookie security settings.
    pub http_cookies: HttpCookieConfig,
    /// Telemetry reporting settings.
    pub telemetry: TelemetryConfig,
    /// SSH hostname configuration.
    pub ssh: SshConfig,
    /// Configured external authentication providers.
    pub external_auth_providers: Vec<ExternalAuthLinkProvider>,
    /// Configured DERP regions used by deployment health probes.
    pub derp_regions: Vec<DerpRegionConfig>,
    /// Grace period for HTTP shutdown.
    pub shutdown_grace_period_secs: u64,
    /// Log format used by the binary.
    pub log_format: LogFormat,
    /// Extended logging configuration.
    pub logging: LoggingConfig,
    /// TTL in seconds for the in-memory session authentication cache.
    pub session_cache_ttl_secs: u64,
    /// Flush interval in milliseconds for the batched audit sink.
    pub audit_batch_flush_interval_ms: u64,
    /// Maximum batch size before the batched audit sink forces a flush.
    pub audit_batch_max_size: usize,
    /// Maximum number of concurrent HTTP requests before returning 503.
    pub max_concurrent_requests: usize,
    /// Maximum number of concurrent database queries (semaphore permits).
    pub max_concurrent_db_queries: usize,
    /// Rate-limiting configuration for the HTTP layer.
    pub rate_limit: RateLimitConfig,
    /// GitHub OAuth2 configuration. `None` means GitHub OAuth is disabled.
    pub github_oauth: Option<GithubOAuthConfig>,
    /// OIDC authentication configuration. `None` means OIDC is disabled.
    pub oidc: Option<OidcConfig>,
    /// OpenTelemetry distributed tracing configuration.
    pub otel: OtelConfig,
    /// CORS (Cross-Origin Resource Sharing) configuration.
    pub cors: CorsConfig,
    /// Security headers configuration.
    pub security_headers: SecurityHeadersConfig,
    /// Provisioner daemon settings.
    pub provisioner: ProvisionerConfig,
    /// Session and token lifetime settings.
    pub session_lifetime: SessionLifetimeConfig,
    /// Dangerous settings that should not be enabled in production.
    pub dangerous: DangerousConfig,
    /// Health check configuration.
    pub healthcheck: HealthcheckConfig,
    /// Workspace default settings.
    pub workspace: WorkspaceConfig,
    /// Background worker interval settings.
    pub worker: WorkerConfig,
    /// Whether the Swagger API docs endpoint is enabled.
    pub swagger_enabled: bool,
    /// Whether to periodically check for Coder updates.
    pub update_check: bool,
    /// Interval between GitHub release polls, in seconds (default 24h).
    pub update_check_interval_secs: u64,
    /// URL used to fetch the latest Coder release from GitHub.
    pub update_check_url: String,
    /// Algorithm used for SSH key generation (e.g. "ed25519").
    pub ssh_keygen_algorithm: String,
    /// Directory used for caching temporary files.
    pub cache_dir: String,
    /// Only allow browser-based connections (disables CLI/SSH).
    pub browser_only: bool,
    /// Disable password-based authentication.
    pub disable_password_auth: bool,
    /// Disable path-based workspace application routing.
    pub disable_path_apps: bool,
    /// Disable workspace exec for site owners.
    pub disable_owner_workspace_exec: bool,
    /// HSTS max-age in seconds. Zero disables HSTS.
    pub strict_transport_security: u64,
    /// Additional options for the Strict-Transport-Security header.
    pub strict_transport_security_options: Vec<String>,
    /// Enabled experiment feature flags.
    pub experiments: Vec<String>,
    /// Fallback troubleshooting URL for workspace agents.
    pub agent_fallback_troubleshooting_url: String,
    /// Terms of service URL displayed to users.
    pub terms_of_service_url: String,
    /// Web terminal renderer setting (e.g. "canvas", "dom", "webgl").
    pub web_terminal_renderer: String,
    /// Whether workspace renames are allowed.
    pub allow_workspace_renames: bool,
    /// Additional Content-Security-Policy directives.
    pub additional_csp_policy: Vec<String>,
    /// Whether workspace sharing is disabled.
    pub disable_workspace_sharing: bool,
    /// Custom documentation URL override.
    pub docs_url: String,
    /// SCIM API key for user provisioning. Empty disables SCIM.
    pub scim_api_key: String,
    /// Message displayed to users suggesting they upgrade the CLI.
    pub cli_upgrade_message: String,
}

impl ServerConfig {
    /// Returns a redacted view of the runtime configuration.
    #[must_use]
    pub fn public(&self) -> PublicDeploymentConfig {
        PublicDeploymentConfig {
            listen_addr: self.listen_addr.to_string(),
            access_url: self.access_url.clone(),
            wildcard_access_url: self.wildcard_access_url.clone(),
            database: PublicDatabaseConfig {
                max_connections: self.database.max_connections,
                min_connections: self.database.min_connections,
                acquire_timeout_secs: self.database.acquire_timeout_secs,
            },
            tls: PublicTlsConfig {
                enabled: self.tls.enabled,
                address: self.tls.address.clone(),
                redirect_http: self.tls.redirect_http,
                min_version: self.tls.min_version.clone(),
            },
            networking: self.networking.clone(),
            http_cookies: self.http_cookies.clone(),
            telemetry: PublicTelemetryConfig {
                enabled: self.telemetry.enabled,
            },
            ssh: self.ssh.clone(),
            shutdown_grace_period_secs: self.shutdown_grace_period_secs,
            log_format: self.log_format,
            logging: self.logging.clone(),
            provisioner: PublicProvisionerConfig {
                daemon_count: self.provisioner.daemon_count,
                poll_interval_ms: self.provisioner.poll_interval_ms,
                force_cancel_interval_ms: self.provisioner.force_cancel_interval_ms,
            },
            session_lifetime: self.session_lifetime.clone(),
            dangerous: self.dangerous.clone(),
            healthcheck: self.healthcheck.clone(),
            swagger_enabled: self.swagger_enabled,
            update_check: self.update_check,
            update_check_interval_secs: self.update_check_interval_secs,
            update_check_url: self.update_check_url.clone(),
            browser_only: self.browser_only,
            disable_password_auth: self.disable_password_auth,
            disable_path_apps: self.disable_path_apps,
            disable_owner_workspace_exec: self.disable_owner_workspace_exec,
            strict_transport_security: self.strict_transport_security,
            strict_transport_security_options: self.strict_transport_security_options.clone(),
            experiments: self.experiments.clone(),
            agent_fallback_troubleshooting_url: self.agent_fallback_troubleshooting_url.clone(),
            terms_of_service_url: self.terms_of_service_url.clone(),
            web_terminal_renderer: self.web_terminal_renderer.clone(),
            allow_workspace_renames: self.allow_workspace_renames,
            additional_csp_policy: self.additional_csp_policy.clone(),
            security_headers: self.security_headers.clone(),
            disable_workspace_sharing: self.disable_workspace_sharing,
            ssh_keygen_algorithm: self.ssh_keygen_algorithm.clone(),
            cache_dir: self.cache_dir.clone(),
            cli_upgrade_message: self.cli_upgrade_message.clone(),
            workspace: self.workspace.clone(),
            docs_url: self.docs_url.clone(),
        }
    }

    /// Enumerates the supported configuration surface for the current Rust
    /// backend slice.
    #[must_use]
    pub fn supported_options() -> Vec<ConfigOption> {
        vec![
            // -- Core --
            ConfigOption {
                name: "listen-addr",
                env: "CODER_LISTEN_ADDR",
                default: Some("127.0.0.1:3000"),
                description: "Bind address for the Rust coderd HTTP listener.",
            },
            ConfigOption {
                name: "access-url",
                env: "CODER_ACCESS_URL",
                default: Some("http://127.0.0.1:3000"),
                description: "External access URL advertised by the service.",
            },
            ConfigOption {
                name: "wildcard-access-url",
                env: "CODER_WILDCARD_ACCESS_URL",
                default: Some(""),
                description: "Wildcard hostname for workspace application routing.",
            },
            // -- Database --
            ConfigOption {
                name: "postgres-url",
                env: "CODER_POSTGRES_URL",
                default: None,
                description: "Postgres connection string for the Rust backend.",
            },
            ConfigOption {
                name: "db-max-connections",
                env: "CODER_DB_MAX_CONNECTIONS",
                default: Some("20"),
                description: "Maximum Postgres connections for the SQL pool.",
            },
            ConfigOption {
                name: "db-min-connections",
                env: "CODER_DB_MIN_CONNECTIONS",
                default: Some("1"),
                description: "Minimum Postgres connections kept warm in the pool.",
            },
            ConfigOption {
                name: "db-acquire-timeout-secs",
                env: "CODER_DB_ACQUIRE_TIMEOUT_SECS",
                default: Some("10"),
                description: "Maximum time to wait for a pooled Postgres connection.",
            },
            // -- TLS --
            ConfigOption {
                name: "tls-enable",
                env: "CODER_TLS_ENABLE",
                default: Some("false"),
                description: "Whether TLS termination is enabled.",
            },
            ConfigOption {
                name: "tls-address",
                env: "CODER_TLS_ADDRESS",
                default: Some("127.0.0.1:3443"),
                description: "Bind address for the HTTPS listener.",
            },
            ConfigOption {
                name: "tls-redirect-http",
                env: "CODER_TLS_REDIRECT_HTTP_TO_HTTPS",
                default: Some("true"),
                description: "Whether to redirect HTTP requests to HTTPS when TLS is enabled.",
            },
            ConfigOption {
                name: "tls-cert-file",
                env: "CODER_TLS_CERT_FILE",
                default: Some(""),
                description: "Comma-separated paths to TLS certificate files.",
            },
            ConfigOption {
                name: "tls-key-file",
                env: "CODER_TLS_KEY_FILE",
                default: Some(""),
                description: "Comma-separated paths to TLS private key files.",
            },
            ConfigOption {
                name: "tls-min-version",
                env: "CODER_TLS_MIN_VERSION",
                default: Some("tls12"),
                description: "Minimum TLS version accepted (tls10, tls11, tls12, tls13).",
            },
            // -- Networking --
            ConfigOption {
                name: "redirect-to-access-url",
                env: "CODER_REDIRECT_TO_ACCESS_URL",
                default: Some("false"),
                description: "Redirect requests that do not match the access URL host.",
            },
            ConfigOption {
                name: "proxy-trusted-headers",
                env: "CODER_PROXY_TRUSTED_HEADERS",
                default: Some(""),
                description: "Comma-separated HTTP headers to trust from a reverse proxy.",
            },
            ConfigOption {
                name: "proxy-trusted-origins",
                env: "CODER_PROXY_TRUSTED_ORIGINS",
                default: Some(""),
                description: "Comma-separated trusted proxy origin addresses (CIDR or IP).",
            },
            // -- HTTP Cookies --
            ConfigOption {
                name: "secure-auth-cookie",
                env: "CODER_SECURE_AUTH_COOKIE",
                default: Some("false"),
                description: "Set the Secure flag on session cookies.",
            },
            ConfigOption {
                name: "samesite-auth-cookie",
                env: "CODER_SAMESITE_AUTH_COOKIE",
                default: Some("lax"),
                description: "SameSite attribute for session cookies (lax, strict, none).",
            },
            // -- Telemetry --
            ConfigOption {
                name: "telemetry",
                env: "CODER_TELEMETRY_ENABLE",
                default: Some("false"),
                description: "Enables deployment telemetry reporting.",
            },
            ConfigOption {
                name: "trace-enable",
                env: "CODER_TRACE_ENABLE",
                default: Some("false"),
                description: "Enables trace-level telemetry data collection.",
            },
            ConfigOption {
                name: "telemetry-url",
                env: "CODER_TELEMETRY_URL",
                default: Some("https://telemetry.coder.com"),
                description: "URL of the telemetry collection endpoint.",
            },
            // -- SSH --
            ConfigOption {
                name: "ssh-hostname-prefix",
                env: "CODER_SSH_HOSTNAME_PREFIX",
                default: Some("coder"),
                description: "Deprecated SSH hostname prefix kept for compatibility.",
            },
            ConfigOption {
                name: "ssh-hostname-suffix",
                env: "CODER_SSH_HOSTNAME_SUFFIX",
                default: Some(""),
                description: "SSH hostname suffix appended to workspace hostnames.",
            },
            ConfigOption {
                name: "ssh-keygen-algorithm",
                env: "CODER_SSH_KEYGEN_ALGORITHM",
                default: Some("ed25519"),
                description: "Algorithm used for SSH key generation.",
            },
            // -- External Auth --
            ConfigOption {
                name: "external-auth-providers-json",
                env: "CODER_EXTERNAL_AUTH_PROVIDERS_JSON",
                default: Some("[]"),
                description: "JSON array of external auth provider metadata exposed by the Rust backend.",
            },
            // -- DERP --
            ConfigOption {
                name: "derp-regions-json",
                env: "CODER_DERP_REGIONS_JSON",
                default: Some("[]"),
                description: "JSON array of DERP region probe metadata used by deployment health checks.",
            },
            // -- Server Lifecycle --
            ConfigOption {
                name: "shutdown-grace-period-secs",
                env: "CODER_SHUTDOWN_GRACE_PERIOD_SECS",
                default: Some("10"),
                description: "Grace period allowed for in-flight HTTP requests on shutdown.",
            },
            // -- Logging --
            ConfigOption {
                name: "log-format",
                env: "CODER_LOG_FORMAT",
                default: Some("pretty"),
                description: "Structured log output format.",
            },
            ConfigOption {
                name: "verbose",
                env: "CODER_VERBOSE",
                default: Some("false"),
                description: "Enable verbose (debug-level) logging.",
            },
            ConfigOption {
                name: "log-human",
                env: "CODER_LOGGING_HUMAN",
                default: Some("/dev/stderr"),
                description: "Output path for human-readable logs. Empty disables.",
            },
            ConfigOption {
                name: "log-json",
                env: "CODER_LOGGING_JSON",
                default: Some(""),
                description: "Output path for JSON-formatted logs. Empty disables.",
            },
            ConfigOption {
                name: "log-stackdriver",
                env: "CODER_LOGGING_STACKDRIVER",
                default: Some(""),
                description: "Output path for Stackdriver-formatted logs. Empty disables.",
            },
            ConfigOption {
                name: "log-filter",
                env: "CODER_LOG_FILTER",
                default: Some(""),
                description: "Comma-separated list of log filter directives.",
            },
            // -- Session / Caching --
            ConfigOption {
                name: "session-cache-ttl-secs",
                env: "CODER_SESSION_CACHE_TTL_SECS",
                default: Some("30"),
                description: "TTL in seconds for the in-memory session authentication cache.",
            },
            // -- Audit --
            ConfigOption {
                name: "audit-batch-flush-interval-ms",
                env: "CODER_AUDIT_BATCH_FLUSH_INTERVAL_MS",
                default: Some("500"),
                description: "Flush interval in milliseconds for the batched audit log sink.",
            },
            ConfigOption {
                name: "audit-batch-max-size",
                env: "CODER_AUDIT_BATCH_MAX_SIZE",
                default: Some("50"),
                description: "Maximum batch size before the audit sink forces a flush.",
            },
            // -- Concurrency --
            ConfigOption {
                name: "max-concurrent-requests",
                env: "CODER_MAX_CONCURRENT_REQUESTS",
                default: Some("1024"),
                description: "Maximum number of concurrent HTTP requests before returning 503.",
            },
            ConfigOption {
                name: "max-concurrent-db-queries",
                env: "CODER_MAX_CONCURRENT_DB_QUERIES",
                default: Some("40"),
                description: "Maximum number of concurrent database queries.",
            },
            // -- OpenTelemetry --
            ConfigOption {
                name: "otel-enabled",
                env: "CODER_OTEL_ENABLED",
                default: Some("false"),
                description: "Enable OpenTelemetry distributed tracing with OTLP export.",
            },
            ConfigOption {
                name: "otel-endpoint",
                env: "CODER_OTEL_ENDPOINT",
                default: Some("http://localhost:4317"),
                description: "OTLP gRPC collector endpoint for trace export.",
            },
            ConfigOption {
                name: "otel-sample-ratio",
                env: "CODER_OTEL_SAMPLE_RATIO",
                default: Some("1.0"),
                description: "Trace sampling ratio (0.0 to 1.0). 1.0 samples every request.",
            },
            // -- Rate Limiting --
            ConfigOption {
                name: "rate-limit-enabled",
                env: "CODER_RATE_LIMIT_ENABLED",
                default: Some("true"),
                description: "Whether HTTP rate limiting is active.",
            },
            ConfigOption {
                name: "rate-limit-api-per-minute",
                env: "CODER_RATE_LIMIT_API_PER_MINUTE",
                default: Some("600"),
                description: "Maximum general API requests per minute for authenticated users.",
            },
            // -- CORS --
            ConfigOption {
                name: "cors-allowed-origins",
                env: "CODER_CORS_ALLOWED_ORIGINS",
                default: Some(""),
                description: "Comma-separated list of allowed CORS origins.",
            },
            ConfigOption {
                name: "cors-allow-credentials",
                env: "CODER_CORS_ALLOW_CREDENTIALS",
                default: Some("false"),
                description: "Whether cross-origin requests may include credentials.",
            },
            // -- Provisioner --
            ConfigOption {
                name: "provisioner-daemon-count",
                env: "CODER_PROVISIONER_DAEMONS",
                default: Some("3"),
                description: "Number of built-in provisioner daemons to run.",
            },
            ConfigOption {
                name: "provisioner-poll-interval-ms",
                env: "CODER_PROVISIONER_DAEMON_POLL_INTERVAL",
                default: Some("1000"),
                description: "Polling interval in milliseconds for provisioner job acquisition.",
            },
            ConfigOption {
                name: "provisioner-poll-jitter-ms",
                env: "CODER_PROVISIONER_DAEMON_POLL_JITTER",
                default: Some("100"),
                description: "Random jitter in milliseconds added to provisioner polling interval.",
            },
            ConfigOption {
                name: "provisioner-force-cancel-interval-ms",
                env: "CODER_PROVISIONER_FORCE_CANCEL_INTERVAL",
                default: Some("600000"),
                description: "Interval in milliseconds after which a provisioner job is force-cancelled.",
            },
            ConfigOption {
                name: "provisioner-daemon-psk",
                env: "CODER_PROVISIONER_DAEMON_PSK",
                default: Some(""),
                description: "Pre-shared key for external provisioner daemon authentication.",
            },
            // -- Session Lifetime --
            ConfigOption {
                name: "session-duration-hours",
                env: "CODER_SESSION_DURATION",
                default: Some("24"),
                description: "Default session duration in hours.",
            },
            ConfigOption {
                name: "disable-session-expiry-refresh",
                env: "CODER_DISABLE_SESSION_EXPIRY_REFRESH",
                default: Some("false"),
                description: "Disable automatic session expiry refresh on activity.",
            },
            ConfigOption {
                name: "max-token-lifetime-hours",
                env: "CODER_MAX_TOKEN_LIFETIME",
                default: Some("2160"),
                description: "Maximum lifetime in hours for API tokens (default 90 days).",
            },
            // -- Dangerous --
            ConfigOption {
                name: "dangerous-allow-cors-requests",
                env: "CODER_DANGEROUS_ALLOW_CORS_REQUESTS",
                default: Some("false"),
                description: "DANGEROUS: Allow all CORS origins. Not recommended for production.",
            },
            ConfigOption {
                name: "dangerous-allow-path-app-sharing",
                env: "CODER_DANGEROUS_ALLOW_PATH_APP_SHARING",
                default: Some("false"),
                description: "DANGEROUS: Allow sharing path-based workspace applications.",
            },
            ConfigOption {
                name: "dangerous-allow-path-app-site-owner-access",
                env: "CODER_DANGEROUS_ALLOW_PATH_APP_SITE_OWNER_ACCESS",
                default: Some("false"),
                description: "DANGEROUS: Allow site owners to access path-based workspace apps.",
            },
            // -- Healthcheck --
            ConfigOption {
                name: "health-check-refresh",
                env: "CODER_HEALTH_CHECK_REFRESH",
                default: Some("600"),
                description: "Interval in seconds between automatic health check refreshes.",
            },
            ConfigOption {
                name: "health-check-threshold-database",
                env: "CODER_HEALTH_CHECK_THRESHOLD_DATABASE",
                default: Some("15"),
                description: "Database health check latency threshold in milliseconds.",
            },
            // -- Workspace Defaults --
            ConfigOption {
                name: "default-quiet-hours-schedule",
                env: "CODER_QUIET_HOURS_DEFAULT_SCHEDULE",
                default: Some("CRON_TZ=UTC 0 0 * * *"),
                description: "Default quiet hours cron schedule for workspaces.",
            },
            ConfigOption {
                name: "allow-workspace-renames",
                env: "CODER_ALLOW_WORKSPACE_RENAMES",
                default: Some("false"),
                description: "Whether workspace renames are allowed.",
            },
            // -- Worker Intervals --
            ConfigOption {
                name: "notification-dispatch-interval",
                env: "CODER_NOTIFICATION_DISPATCH_INTERVAL",
                default: Some("10"),
                description: "Poll interval in seconds for the notification dispatch worker.",
            },
            ConfigOption {
                name: "activity-bump-interval",
                env: "CODER_ACTIVITY_BUMP_INTERVAL",
                default: Some("10"),
                description: "Poll interval in seconds for the activity bump worker.",
            },
            ConfigOption {
                name: "dormancy-check-interval",
                env: "CODER_DORMANCY_CHECK_INTERVAL",
                default: Some("60"),
                description: "Poll interval in seconds for the dormancy checker worker.",
            },
            ConfigOption {
                name: "telemetry-flush-interval",
                env: "CODER_TELEMETRY_FLUSH_INTERVAL",
                default: Some("1800"),
                description: "Flush interval in seconds for the telemetry batching worker.",
            },
            // -- Security --
            ConfigOption {
                name: "browser-only",
                env: "CODER_BROWSER_ONLY",
                default: Some("false"),
                description: "Only allow browser-based connections to workspaces.",
            },
            ConfigOption {
                name: "disable-password-auth",
                env: "CODER_DISABLE_PASSWORD_AUTH",
                default: Some("false"),
                description: "Disable password-based authentication.",
            },
            ConfigOption {
                name: "disable-path-apps",
                env: "CODER_DISABLE_PATH_APPS",
                default: Some("false"),
                description: "Disable path-based workspace application routing.",
            },
            ConfigOption {
                name: "disable-owner-workspace-access",
                env: "CODER_DISABLE_OWNER_WORKSPACE_ACCESS",
                default: Some("false"),
                description: "Disable workspace exec for site owners.",
            },
            ConfigOption {
                name: "disable-workspace-sharing",
                env: "CODER_DISABLE_WORKSPACE_SHARING",
                default: Some("false"),
                description: "Disable workspace sharing via ACLs.",
            },
            ConfigOption {
                name: "strict-transport-security",
                env: "CODER_STRICT_TRANSPORT_SECURITY",
                default: Some("0"),
                description: "HSTS max-age in seconds. Zero disables HSTS.",
            },
            ConfigOption {
                name: "strict-transport-security-options",
                env: "CODER_STRICT_TRANSPORT_SECURITY_OPTIONS",
                default: Some(""),
                description: "Comma-separated additional HSTS options (e.g. includeSubDomains).",
            },
            // -- Swagger --
            ConfigOption {
                name: "swagger-enable",
                env: "CODER_SWAGGER_ENABLE",
                default: Some("true"),
                description: "Whether the /swagger endpoint is accessible.",
            },
            // -- Update Check --
            ConfigOption {
                name: "update-check",
                env: "CODER_UPDATE_CHECK",
                default: Some("false"),
                description: "Periodically check for new Coder releases.",
            },
            ConfigOption {
                name: "update-check-interval-secs",
                env: "CODER_UPDATE_CHECK_INTERVAL_SECS",
                default: Some("86400"),
                description: "Interval in seconds between GitHub release polls for update checks.",
            },
            ConfigOption {
                name: "update-check-url",
                env: "CODER_UPDATE_CHECK_URL",
                default: Some("https://api.github.com/repos/coder/coder/releases/latest"),
                description: "URL used to fetch the latest Coder release.",
            },
            // -- Miscellaneous --
            ConfigOption {
                name: "experiments",
                env: "CODER_EXPERIMENTS",
                default: Some(""),
                description: "Comma-separated list of enabled experiment feature flags.",
            },
            ConfigOption {
                name: "cache-dir",
                env: "CODER_CACHE_DIRECTORY",
                default: Some("~/.cache/coder"),
                description: "Directory for caching temporary files.",
            },
            ConfigOption {
                name: "agent-fallback-troubleshooting-url",
                env: "CODER_AGENT_FALLBACK_TROUBLESHOOTING_URL",
                default: Some(""),
                description: "Fallback troubleshooting URL shown when agent connections fail.",
            },
            ConfigOption {
                name: "terms-of-service-url",
                env: "CODER_TERMS_OF_SERVICE_URL",
                default: Some(""),
                description: "URL to terms of service displayed to users.",
            },
            ConfigOption {
                name: "web-terminal-renderer",
                env: "CODER_WEB_TERMINAL_RENDERER",
                default: Some(""),
                description: "Renderer for web terminals (canvas, dom, webgl).",
            },
            ConfigOption {
                name: "docs-url",
                env: "CODER_DOCS_URL",
                default: Some("https://coder.com/docs/coder-oss"),
                description: "Custom documentation URL override.",
            },
            ConfigOption {
                name: "cli-upgrade-message",
                env: "CODER_CLI_UPGRADE_MESSAGE",
                default: Some(""),
                description: "Message displayed to users suggesting they upgrade the CLI.",
            },
            ConfigOption {
                name: "scim-auth-header",
                env: "CODER_SCIM_AUTH_HEADER",
                default: Some(""),
                description: "SCIM API key for user provisioning. Empty disables SCIM.",
            },
            ConfigOption {
                name: "additional-csp-policy",
                env: "CODER_ADDITIONAL_CSP_POLICY",
                default: Some(""),
                description: "Comma-separated additional Content-Security-Policy directives.",
            },
            // -- Security Headers --
            ConfigOption {
                name: "x-content-type-options",
                env: "CODER_X_CONTENT_TYPE_OPTIONS",
                default: Some("nosniff"),
                description: "Value for the X-Content-Type-Options response header.",
            },
            ConfigOption {
                name: "x-frame-options",
                env: "CODER_X_FRAME_OPTIONS",
                default: Some("DENY"),
                description: "Value for the X-Frame-Options response header.",
            },
            ConfigOption {
                name: "referrer-policy",
                env: "CODER_REFERRER_POLICY",
                default: Some("no-referrer"),
                description: "Value for the Referrer-Policy response header.",
            },
            // -- GitHub OAuth2 --
            ConfigOption {
                name: "github-client-id",
                env: "CODER_GITHUB_CLIENT_ID",
                default: Some(""),
                description: "GitHub OAuth2 client ID.",
            },
            ConfigOption {
                name: "github-client-secret",
                env: "CODER_GITHUB_CLIENT_SECRET",
                default: Some(""),
                description: "GitHub OAuth2 client secret.",
            },
            ConfigOption {
                name: "github-allow-signups",
                env: "CODER_GITHUB_ALLOW_SIGNUPS",
                default: Some("false"),
                description: "Allow new user signups via GitHub OAuth.",
            },
            ConfigOption {
                name: "github-allow-everyone",
                env: "CODER_GITHUB_ALLOW_EVERYONE",
                default: Some("false"),
                description: "Allow all GitHub users (skip org/team checks).",
            },
            ConfigOption {
                name: "github-allowed-orgs",
                env: "CODER_GITHUB_ALLOWED_ORGS",
                default: Some(""),
                description: "Comma-separated list of allowed GitHub organization logins.",
            },
            ConfigOption {
                name: "github-allowed-teams",
                env: "CODER_GITHUB_ALLOWED_TEAMS",
                default: Some(""),
                description: "Comma-separated list of allowed GitHub team slugs (org/team format).",
            },
            ConfigOption {
                name: "github-api-url",
                env: "CODER_GITHUB_API_URL",
                default: Some("https://api.github.com"),
                description: "GitHub API base URL.",
            },
            // -- OIDC --
            ConfigOption {
                name: "oidc-issuer-url",
                env: "CODER_OIDC_ISSUER_URL",
                default: Some(""),
                description: "OIDC issuer URL (used for discovery).",
            },
            ConfigOption {
                name: "oidc-client-id",
                env: "CODER_OIDC_CLIENT_ID",
                default: Some(""),
                description: "OIDC client ID.",
            },
            ConfigOption {
                name: "oidc-client-secret",
                env: "CODER_OIDC_CLIENT_SECRET",
                default: Some(""),
                description: "OIDC client secret.",
            },
            ConfigOption {
                name: "oidc-scopes",
                env: "CODER_OIDC_SCOPES",
                default: Some("openid,profile,email"),
                description: "Comma-separated OIDC scopes to request.",
            },
            ConfigOption {
                name: "oidc-allow-signups",
                env: "CODER_OIDC_ALLOW_SIGNUPS",
                default: Some("true"),
                description: "Allow new user signups via OIDC.",
            },
            ConfigOption {
                name: "oidc-email-domain",
                env: "CODER_OIDC_EMAIL_DOMAIN",
                default: Some(""),
                description: "Comma-separated list of allowed email domains for OIDC.",
            },
            ConfigOption {
                name: "oidc-username-field",
                env: "CODER_OIDC_USERNAME_FIELD",
                default: Some("preferred_username"),
                description: "OIDC claim field to use as username.",
            },
            ConfigOption {
                name: "oidc-email-field",
                env: "CODER_OIDC_EMAIL_FIELD",
                default: Some("email"),
                description: "OIDC claim field to use as email.",
            },
            ConfigOption {
                name: "oidc-name-field",
                env: "CODER_OIDC_NAME_FIELD",
                default: Some("name"),
                description: "OIDC claim field to use as display name.",
            },
            ConfigOption {
                name: "oidc-ignore-email-verified",
                env: "CODER_OIDC_IGNORE_EMAIL_VERIFIED",
                default: Some("false"),
                description: "Ignore the email_verified claim from the OIDC provider.",
            },
            // -- Rate Limiting (additional) --
            ConfigOption {
                name: "rate-limit-login-per-minute",
                env: "CODER_RATE_LIMIT_LOGIN_PER_MINUTE",
                default: Some("5"),
                description: "Maximum login attempts per minute per IP address.",
            },
            ConfigOption {
                name: "rate-limit-unauthenticated-per-minute",
                env: "CODER_RATE_LIMIT_UNAUTHENTICATED_PER_MINUTE",
                default: Some("60"),
                description: "Maximum API requests per minute for unauthenticated IPs.",
            },
            // -- Worker Intervals (additional) --
            ConfigOption {
                name: "lifecycle-check-interval",
                env: "CODER_LIFECYCLE_CHECK_INTERVAL",
                default: Some("30"),
                description: "Poll interval in seconds for the lifecycle scheduler (autostart/autostop).",
            },
            ConfigOption {
                name: "replica-update-interval",
                env: "CODER_REPLICA_UPDATE_INTERVAL",
                default: Some("15"),
                description: "Heartbeat interval in seconds for the HA replica manager. Stale rows are pruned at 3× this value.",
            },
        ]
    }
}

/// GitHub OAuth2 configuration for login.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GithubOAuthConfig {
    /// GitHub OAuth2 client ID.
    pub client_id: String,
    /// GitHub OAuth2 client secret.
    pub client_secret: String,
    /// Whether to allow new user signups via GitHub.
    pub allow_signups: bool,
    /// Whether all GitHub users are allowed (skip org/team checks).
    pub allow_everyone: bool,
    /// Allowed GitHub organization logins. Empty means no org restriction.
    pub allowed_orgs: Vec<String>,
    /// Allowed GitHub team slugs in `org/team` format. Empty means no team restriction.
    pub allowed_teams: Vec<String>,
    /// GitHub API base URL (defaults to `https://api.github.com`).
    pub api_url: Url,
}

/// OIDC authentication configuration for login.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OidcConfig {
    /// OIDC issuer URL (used for discovery).
    pub issuer_url: Url,
    /// OIDC client ID.
    pub client_id: String,
    /// OIDC client secret.
    pub client_secret: String,
    /// OAuth2 scopes to request.
    pub scopes: Vec<String>,
    /// Whether to allow new user signups via OIDC.
    pub allow_signups: bool,
    /// Allowed email domains. Empty means allow all.
    pub email_domain: Vec<String>,
    /// Claim field to use as the username.
    pub username_field: String,
    /// Claim field to use as the email.
    pub email_field: String,
    /// Claim field to use as the display name.
    pub name_field: String,
    /// Whether to ignore the email_verified claim.
    pub ignore_email_verified: bool,
}

/// OpenTelemetry distributed tracing configuration.
#[derive(Clone, Debug, PartialEq)]
pub struct OtelConfig {
    // NOTE: `Eq` is implemented manually below because `f64` does not derive
    // `Eq`.  The `sample_ratio` field is bounded to [0.0, 1.0] so NaN is never
    // expected, making the `Eq` contract safe to uphold.
    /// Whether OpenTelemetry tracing is enabled.
    pub enabled: bool,
    /// OTLP collector endpoint (gRPC).
    pub endpoint: String,
    /// Logical service name reported in traces.
    pub service_name: String,
    /// Sampling ratio (0.0 to 1.0).  1.0 samples every request.
    pub sample_ratio: f64,
}

impl Eq for OtelConfig {}

impl Default for OtelConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: "http://localhost:4317".to_owned(),
            service_name: "coderd".to_owned(),
            sample_ratio: 1.0,
        }
    }
}

/// Security headers configuration for the HTTP layer.
///
/// Controls `X-Content-Type-Options`, `X-Frame-Options`, and
/// `Referrer-Policy` headers on all responses.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SecurityHeadersConfig {
    /// Value for the `X-Content-Type-Options` header.
    /// Default: `"nosniff"`.
    pub x_content_type_options: String,
    /// Value for the `X-Frame-Options` header.
    /// Default: `"DENY"`. Set to an empty string to omit.
    pub x_frame_options: String,
    /// Value for the `Referrer-Policy` header.
    /// Default: `"no-referrer"`. Set to an empty string to omit.
    pub referrer_policy: String,
}

impl Default for SecurityHeadersConfig {
    fn default() -> Self {
        Self {
            x_content_type_options: "nosniff".to_owned(),
            x_frame_options: "DENY".to_owned(),
            referrer_policy: "no-referrer".to_owned(),
        }
    }
}

/// Cross-origin resource sharing (CORS) configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorsConfig {
    /// Allowed origins for cross-origin requests.
    ///
    /// When empty, every origin is permitted (wildcard) and the
    /// `Access-Control-Allow-Credentials` header is **not** sent, regardless
    /// of the value of [`Self::allow_credentials`].
    pub allowed_origins: Vec<String>,
    /// Whether the `Access-Control-Allow-Credentials` header is sent for
    /// requests from explicitly allowed origins.
    ///
    /// This setting is ignored when [`Self::allowed_origins`] is empty
    /// (wildcard mode), because the CORS specification forbids combining
    /// `Access-Control-Allow-Origin: *` with credentials.
    pub allow_credentials: bool,
    /// How long browsers may cache preflight responses, in seconds.
    pub max_age_secs: u64,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: Vec::new(),
            allow_credentials: false,
            max_age_secs: 3600,
        }
    }
}

/// Rate-limiting configuration for the HTTP layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RateLimitConfig {
    /// Whether rate limiting is active.
    pub enabled: bool,
    /// Maximum login attempts per minute per IP address.
    pub login_per_minute: u32,
    /// Maximum API requests per minute for authenticated users.
    pub api_per_minute: u32,
    /// Maximum API requests per minute for unauthenticated IPs.
    pub unauthenticated_per_minute: u32,
    /// Maximum audit endpoint requests per minute per user.
    pub audit_per_minute: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            login_per_minute: 5,
            api_per_minute: 600,
            unauthenticated_per_minute: 60,
            audit_per_minute: 30,
        }
    }
}

/// Database settings used by the Postgres store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatabaseConfig {
    /// Postgres connection string.
    pub postgres_url: String,
    /// Maximum number of pooled connections.
    pub max_connections: u32,
    /// Minimum number of pooled connections.
    pub min_connections: u32,
    /// Seconds to wait for a connection before failing.
    pub acquire_timeout_secs: u64,
}

/// SSH hostname configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SshConfig {
    /// Deprecated prefix kept for compatibility.
    pub hostname_prefix: String,
    /// Suffix appended to workspace hostnames.
    pub hostname_suffix: String,
    /// Additional SSH config directives.
    ///
    /// Serialized as a JSON object to match Go's `map[string]string`.
    pub ssh_config_options: HashMap<String, String>,
}

/// One DERP region exposed to the Rust health service.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct DerpRegionConfig {
    /// Stable numeric region identifier.
    pub id: i32,
    /// Human-readable region name.
    pub name: String,
    /// One or more nodes to probe for the region.
    #[serde(default)]
    pub nodes: Vec<DerpNodeConfig>,
}

/// One DERP node exposed to the Rust health service.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct DerpNodeConfig {
    /// Human-readable node name.
    pub name: String,
    /// Probe URL for the node.
    pub url: Url,
}

/// Log format exposed by the binary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    /// Human-readable compact logs.
    Pretty,
    /// Structured JSON logs.
    Json,
}

// -- New configuration domain structs --

/// TLS configuration for HTTPS termination.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsConfig {
    /// Whether TLS is enabled.
    pub enabled: bool,
    /// Bind address for the HTTPS listener.
    pub address: String,
    /// Whether to redirect HTTP requests to HTTPS.
    pub redirect_http: bool,
    /// Paths to PEM-encoded TLS certificate files.
    pub cert_files: Vec<String>,
    /// Paths to PEM-encoded TLS private key files.
    pub key_files: Vec<String>,
    /// Minimum TLS version accepted (e.g. "tls12", "tls13").
    pub min_version: String,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            address: "127.0.0.1:3443".to_owned(),
            redirect_http: true,
            cert_files: Vec::new(),
            key_files: Vec::new(),
            min_version: "tls12".to_owned(),
        }
    }
}

/// Networking settings for proxy and redirect behaviour.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct NetworkingConfig {
    /// Whether to redirect requests to the access URL when the host does not match.
    pub redirect_to_access_url: bool,
    /// HTTP headers to trust from a reverse proxy (e.g. X-Forwarded-For).
    pub proxy_trusted_headers: Vec<String>,
    /// Trusted proxy origin addresses (CIDR or IP).
    pub proxy_trusted_origins: Vec<String>,
}

/// HTTP cookie security settings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HttpCookieConfig {
    /// Set the `Secure` flag on session cookies.
    pub secure_auth_cookie: bool,
    /// SameSite attribute for session cookies ("lax", "strict", "none").
    pub same_site: String,
}

impl Default for HttpCookieConfig {
    fn default() -> Self {
        Self {
            secure_auth_cookie: false,
            same_site: "lax".to_owned(),
        }
    }
}

/// Telemetry reporting configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TelemetryConfig {
    /// Whether telemetry is enabled.
    pub enabled: bool,
    /// Whether trace-level telemetry data is collected.
    pub trace: bool,
    /// URL of the telemetry collection endpoint.
    pub url: String,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            trace: false,
            url: "https://telemetry.coder.com".to_owned(),
        }
    }
}

/// Provisioner daemon configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvisionerConfig {
    /// Number of built-in provisioner daemons to run.
    pub daemon_count: u32,
    /// Polling interval in milliseconds for provisioner job acquisition.
    pub poll_interval_ms: u64,
    /// Random jitter in milliseconds added to the polling interval.
    pub poll_jitter_ms: u64,
    /// Interval in milliseconds after which a provisioner job is force-cancelled.
    pub force_cancel_interval_ms: u64,
    /// Pre-shared key for external provisioner daemon authentication.
    pub daemon_psk: String,
}

impl Default for ProvisionerConfig {
    fn default() -> Self {
        Self {
            daemon_count: 3,
            poll_interval_ms: 1000,
            poll_jitter_ms: 100,
            force_cancel_interval_ms: 600_000,
            daemon_psk: String::new(),
        }
    }
}

/// Extended logging configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LoggingConfig {
    /// Enable verbose (debug-level) logging.
    pub verbose: bool,
    /// Output path for human-readable logs. Empty disables.
    pub human_path: String,
    /// Output path for JSON-formatted logs. Empty disables.
    pub json_path: String,
    /// Output path for Stackdriver-formatted logs. Empty disables.
    pub stackdriver_path: String,
    /// Log filter directives (e.g. module-level overrides).
    pub log_filter: Vec<String>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            verbose: false,
            human_path: "/dev/stderr".to_owned(),
            json_path: String::new(),
            stackdriver_path: String::new(),
            log_filter: Vec::new(),
        }
    }
}

/// Session and token lifetime settings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SessionLifetimeConfig {
    /// Default session duration in hours.
    pub default_duration_hours: u64,
    /// Whether automatic session expiry refresh on activity is disabled.
    pub disable_expiry_refresh: bool,
    /// Maximum lifetime in hours for API tokens (default 90 days = 2160 hours).
    pub max_token_lifetime_hours: u64,
}

impl Default for SessionLifetimeConfig {
    fn default() -> Self {
        Self {
            default_duration_hours: 24,
            disable_expiry_refresh: false,
            max_token_lifetime_hours: 2160,
        }
    }
}

/// Dangerous settings that should not be enabled in production.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct DangerousConfig {
    /// Allow all CORS origins (overrides CORS configuration).
    pub allow_all_cors: bool,
    /// Allow sharing path-based workspace applications.
    pub allow_path_app_sharing: bool,
    /// Allow site owners to access path-based workspace apps.
    pub allow_path_app_site_owner_access: bool,
}

/// Health check configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HealthcheckConfig {
    /// Interval in seconds between automatic health check refreshes.
    pub refresh_secs: u64,
    /// Database health check latency threshold in milliseconds.
    pub threshold_database_ms: u64,
}

impl Default for HealthcheckConfig {
    fn default() -> Self {
        Self {
            refresh_secs: 600,
            threshold_database_ms: 15,
        }
    }
}

/// Workspace default settings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WorkspaceConfig {
    /// Default quiet hours cron schedule for workspaces.
    pub default_quiet_hours_schedule: String,
}

impl Default for WorkspaceConfig {
    fn default() -> Self {
        Self {
            default_quiet_hours_schedule: "CRON_TZ=UTC 0 0 * * *".to_owned(),
        }
    }
}

/// Background worker interval configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WorkerConfig {
    /// Poll interval in seconds for the notification dispatch worker.
    pub notification_dispatch_interval_secs: u64,
    /// Poll interval in seconds for the activity bump worker.
    pub activity_bump_interval_secs: u64,
    /// Poll interval in seconds for the dormancy checker worker.
    pub dormancy_check_interval_secs: u64,
    /// Flush interval in seconds for the telemetry batching worker.
    pub telemetry_flush_interval_secs: u64,
    /// Poll interval in seconds for the lifecycle scheduler (autostart/autostop).
    pub lifecycle_check_interval_secs: u64,
    /// Heartbeat interval in seconds for the HA replica manager. The
    /// `/replicas` handler uses `3 ×` this value as the staleness
    /// cut-off when filtering rows, matching the manager's prune logic.
    pub replica_update_interval_secs: u64,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            notification_dispatch_interval_secs: 10,
            activity_bump_interval_secs: 10,
            dormancy_check_interval_secs: 60,
            telemetry_flush_interval_secs: 1800,
            lifecycle_check_interval_secs: 30,
            replica_update_interval_secs: 15,
        }
    }
}

// -- Public (redacted) configuration types --

/// Redacted deployment configuration exposed over HTTP.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PublicDeploymentConfig {
    /// Bind address for the HTTP server.
    pub listen_addr: String,
    /// External access URL for the deployment.
    pub access_url: Url,
    /// Wildcard access URL for workspace apps.
    pub wildcard_access_url: String,
    /// Non-secret database pool settings.
    pub database: PublicDatabaseConfig,
    /// TLS status (no secrets).
    pub tls: PublicTlsConfig,
    /// Networking settings.
    pub networking: NetworkingConfig,
    /// HTTP cookie settings.
    pub http_cookies: HttpCookieConfig,
    /// Whether telemetry is enabled.
    pub telemetry: PublicTelemetryConfig,
    /// SSH hostname settings.
    pub ssh: SshConfig,
    /// Grace period allowed for shutdown.
    pub shutdown_grace_period_secs: u64,
    /// Log format configured for the process.
    pub log_format: LogFormat,
    /// Logging configuration.
    pub logging: LoggingConfig,
    /// Provisioner settings (no secrets).
    pub provisioner: PublicProvisionerConfig,
    /// Session lifetime settings.
    pub session_lifetime: SessionLifetimeConfig,
    /// Dangerous settings.
    pub dangerous: DangerousConfig,
    /// Health check settings.
    pub healthcheck: HealthcheckConfig,
    /// Whether Swagger endpoint is enabled.
    pub swagger_enabled: bool,
    /// Whether update check is enabled.
    pub update_check: bool,
    /// Interval between update checks, in seconds.
    pub update_check_interval_secs: u64,
    /// URL used to fetch the latest Coder release.
    pub update_check_url: String,
    /// Whether browser-only mode is active.
    pub browser_only: bool,
    /// Whether password auth is disabled.
    pub disable_password_auth: bool,
    /// Whether path-based apps are disabled.
    pub disable_path_apps: bool,
    /// Disable workspace exec for site owners.
    pub disable_owner_workspace_exec: bool,
    /// HSTS max-age in seconds.
    pub strict_transport_security: u64,
    /// Additional Strict-Transport-Security header options.
    pub strict_transport_security_options: Vec<String>,
    /// Enabled experiments.
    pub experiments: Vec<String>,
    /// Fallback troubleshooting URL for workspace agents.
    pub agent_fallback_troubleshooting_url: String,
    /// Terms of service URL displayed to users.
    pub terms_of_service_url: String,
    /// Web terminal renderer setting.
    pub web_terminal_renderer: String,
    /// Whether workspace renames are allowed.
    pub allow_workspace_renames: bool,
    /// Additional Content-Security-Policy directives.
    pub additional_csp_policy: Vec<String>,
    /// Security headers configuration.
    pub security_headers: SecurityHeadersConfig,
    /// Whether workspace sharing is disabled.
    pub disable_workspace_sharing: bool,
    /// SSH key generation algorithm.
    pub ssh_keygen_algorithm: String,
    /// Cache directory.
    pub cache_dir: String,
    /// CLI upgrade message.
    pub cli_upgrade_message: String,
    /// Workspace default settings.
    pub workspace: WorkspaceConfig,
    /// Custom docs URL.
    pub docs_url: String,
}

/// Redacted database configuration exposed over HTTP.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PublicDatabaseConfig {
    /// Maximum number of pooled connections.
    pub max_connections: u32,
    /// Minimum number of pooled connections.
    pub min_connections: u32,
    /// Seconds to wait when acquiring a connection.
    pub acquire_timeout_secs: u64,
}

/// Redacted TLS configuration exposed over HTTP.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PublicTlsConfig {
    /// Whether TLS is enabled.
    pub enabled: bool,
    /// TLS bind address.
    pub address: String,
    /// Whether HTTP-to-HTTPS redirect is active.
    pub redirect_http: bool,
    /// Minimum TLS version.
    pub min_version: String,
}

/// Redacted telemetry configuration exposed over HTTP.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PublicTelemetryConfig {
    /// Whether telemetry is enabled.
    pub enabled: bool,
}

/// Redacted provisioner configuration exposed over HTTP.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PublicProvisionerConfig {
    /// Number of provisioner daemons.
    pub daemon_count: u32,
    /// Poll interval in milliseconds.
    pub poll_interval_ms: u64,
    /// Force cancel interval in milliseconds.
    pub force_cancel_interval_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to build a minimal `ServerConfig` for testing.
    pub(crate) fn test_server_config() -> ServerConfig {
        ServerConfig {
            listen_addr: std::net::SocketAddr::from(([127, 0, 0, 1], 3000)),
            access_url: Url::parse("http://127.0.0.1:3000").unwrap_or_else(|_| unreachable!()),
            wildcard_access_url: String::new(),
            database: DatabaseConfig {
                postgres_url: "postgres://unused".to_owned(),
                max_connections: 20,
                min_connections: 1,
                acquire_timeout_secs: 10,
            },
            tls: TlsConfig::default(),
            networking: NetworkingConfig::default(),
            http_cookies: HttpCookieConfig::default(),
            telemetry: TelemetryConfig::default(),
            ssh: SshConfig {
                hostname_prefix: String::new(),
                hostname_suffix: String::new(),
                ssh_config_options: HashMap::new(),
            },
            external_auth_providers: Vec::new(),
            derp_regions: Vec::new(),
            shutdown_grace_period_secs: 10,
            log_format: LogFormat::Pretty,
            logging: LoggingConfig::default(),
            session_cache_ttl_secs: 30,
            audit_batch_flush_interval_ms: 500,
            audit_batch_max_size: 50,
            max_concurrent_requests: 1024,
            max_concurrent_db_queries: 40,
            rate_limit: RateLimitConfig::default(),
            github_oauth: None,
            oidc: None,
            otel: OtelConfig::default(),
            cors: CorsConfig::default(),
            security_headers: SecurityHeadersConfig::default(),
            provisioner: ProvisionerConfig::default(),
            session_lifetime: SessionLifetimeConfig::default(),
            dangerous: DangerousConfig::default(),
            healthcheck: HealthcheckConfig::default(),
            workspace: WorkspaceConfig::default(),
            worker: WorkerConfig::default(),
            swagger_enabled: true,
            update_check: false,
            update_check_interval_secs: 24 * 60 * 60,
            update_check_url: "https://api.github.com/repos/coder/coder/releases/latest".to_owned(),
            ssh_keygen_algorithm: "ed25519".to_owned(),
            cache_dir: "~/.cache/coder".to_owned(),
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
            docs_url: "https://coder.com/docs/coder-oss".to_owned(),
            scim_api_key: String::new(),
            cli_upgrade_message: String::new(),
        }
    }

    #[test]
    fn otel_config_default_is_disabled() {
        let config = OtelConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.endpoint, "http://localhost:4317");
        assert_eq!(config.service_name, "coderd");
        assert!((config.sample_ratio - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn otel_config_clone_preserves_fields() {
        let config = OtelConfig {
            enabled: true,
            endpoint: "http://collector:4317".to_owned(),
            service_name: "my-service".to_owned(),
            sample_ratio: 0.5,
        };
        let cloned = config.clone();
        assert_eq!(config, cloned);
    }

    #[test]
    fn otel_config_equality() {
        let a = OtelConfig::default();
        let b = OtelConfig::default();
        assert_eq!(a, b);

        let c = OtelConfig {
            enabled: true,
            ..OtelConfig::default()
        };
        assert_ne!(a, c);
    }

    #[test]
    fn otel_config_debug_format() {
        let config = OtelConfig::default();
        let debug = format!("{config:?}");
        assert!(debug.contains("OtelConfig"));
        assert!(debug.contains("enabled: false"));
    }

    #[test]
    fn server_config_includes_otel() {
        let config = test_server_config();
        assert!(!config.otel.enabled);
        assert_eq!(config.otel.endpoint, "http://localhost:4317");
    }

    #[test]
    fn telemetry_config_defaults() {
        let config = TelemetryConfig::default();
        assert!(!config.enabled);
        assert!(!config.trace);
        assert_eq!(config.url, "https://telemetry.coder.com");
    }

    #[test]
    fn provisioner_config_defaults() {
        let config = ProvisionerConfig::default();
        assert_eq!(config.daemon_count, 3);
        assert_eq!(config.poll_interval_ms, 1000);
        assert_eq!(config.poll_jitter_ms, 100);
        assert_eq!(config.force_cancel_interval_ms, 600_000);
        assert!(config.daemon_psk.is_empty());
    }

    #[test]
    fn session_lifetime_config_defaults() {
        let config = SessionLifetimeConfig::default();
        assert_eq!(config.default_duration_hours, 24);
        assert!(!config.disable_expiry_refresh);
        assert_eq!(config.max_token_lifetime_hours, 2160);
    }

    #[test]
    fn dangerous_config_defaults_all_false() {
        let config = DangerousConfig::default();
        assert!(!config.allow_all_cors);
        assert!(!config.allow_path_app_sharing);
        assert!(!config.allow_path_app_site_owner_access);
    }

    #[test]
    fn healthcheck_config_defaults() {
        let config = HealthcheckConfig::default();
        assert_eq!(config.refresh_secs, 600);
        assert_eq!(config.threshold_database_ms, 15);
    }

    #[test]
    fn logging_config_defaults() {
        let config = LoggingConfig::default();
        assert!(!config.verbose);
        assert_eq!(config.human_path, "/dev/stderr");
        assert!(config.json_path.is_empty());
        assert!(config.stackdriver_path.is_empty());
        assert!(config.log_filter.is_empty());
    }

    #[test]
    fn tls_config_defaults_disabled() {
        let config = TlsConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.address, "127.0.0.1:3443");
        assert!(config.redirect_http);
        assert_eq!(config.min_version, "tls12");
        assert!(config.cert_files.is_empty());
        assert!(config.key_files.is_empty());
    }

    #[test]
    fn http_cookie_config_defaults() {
        let config = HttpCookieConfig::default();
        assert!(!config.secure_auth_cookie);
        assert_eq!(config.same_site, "lax");
    }

    #[test]
    fn workspace_config_defaults() {
        let config = WorkspaceConfig::default();
        assert_eq!(config.default_quiet_hours_schedule, "CRON_TZ=UTC 0 0 * * *");
    }

    #[test]
    fn networking_config_defaults() {
        let config = NetworkingConfig::default();
        assert!(!config.redirect_to_access_url);
        assert!(config.proxy_trusted_headers.is_empty());
        assert!(config.proxy_trusted_origins.is_empty());
    }

    #[test]
    fn public_config_redacts_secrets() {
        let mut config = test_server_config();
        config.database.postgres_url = "postgres://secret:password@host/db".to_owned();
        config.scim_api_key = "super-secret-key".to_owned();
        config.provisioner.daemon_psk = "psk-secret".to_owned();

        let public = config.public();
        // PublicDeploymentConfig should not contain database URL or SCIM key
        let json = serde_json::to_string(&public).unwrap_or_else(|_| String::new());
        assert!(!json.contains("secret:password"));
        assert!(!json.contains("super-secret-key"));
        assert!(!json.contains("psk-secret"));
    }

    #[test]
    fn public_config_includes_new_fields() {
        let mut config = test_server_config();
        config.swagger_enabled = false;
        config.update_check = true;
        config.browser_only = true;
        config.experiments = vec!["exp1".to_owned()];

        let public = config.public();
        assert!(!public.swagger_enabled);
        assert!(public.update_check);
        assert!(public.browser_only);
        assert_eq!(public.experiments, vec!["exp1"]);
    }

    #[test]
    fn supported_options_includes_new_entries() {
        let options = ServerConfig::supported_options();
        let names: Vec<&str> = options.iter().map(|o| o.name).collect();

        // Spot-check a selection of new config options
        assert!(names.contains(&"tls-enable"));
        assert!(names.contains(&"secure-auth-cookie"));
        assert!(names.contains(&"provisioner-daemon-count"));
        assert!(names.contains(&"telemetry-url"));
        assert!(names.contains(&"verbose"));
        assert!(names.contains(&"session-duration-hours"));
        assert!(names.contains(&"dangerous-allow-cors-requests"));
        assert!(names.contains(&"health-check-refresh"));
        assert!(names.contains(&"swagger-enable"));
        assert!(names.contains(&"update-check"));
        assert!(names.contains(&"browser-only"));
        assert!(names.contains(&"experiments"));
        assert!(names.contains(&"cache-dir"));
        assert!(names.contains(&"default-quiet-hours-schedule"));

        // Security headers
        assert!(names.contains(&"x-content-type-options"));
        assert!(names.contains(&"x-frame-options"));
        assert!(names.contains(&"referrer-policy"));

        // GitHub OAuth
        assert!(names.contains(&"github-client-id"));
        assert!(names.contains(&"github-client-secret"));
        assert!(names.contains(&"github-allow-signups"));
        assert!(names.contains(&"github-api-url"));

        // OIDC
        assert!(names.contains(&"oidc-issuer-url"));
        assert!(names.contains(&"oidc-client-id"));
        assert!(names.contains(&"oidc-scopes"));
        assert!(names.contains(&"oidc-ignore-email-verified"));

        // Rate limiting (additional)
        assert!(names.contains(&"rate-limit-login-per-minute"));
        assert!(names.contains(&"rate-limit-unauthenticated-per-minute"));

        // Worker intervals (additional)
        assert!(names.contains(&"lifecycle-check-interval"));
    }
}
