//! Runtime configuration models for the Rust backend slice.

use serde::{Deserialize, Serialize};
use url::Url;

use crate::api::{ConfigOption, ExternalAuthLinkProvider};

/// Server configuration used by the Rust `coderd` binary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerConfig {
    /// Bind address for the HTTP server.
    pub listen_addr: std::net::SocketAddr,
    /// External access URL for the deployment.
    pub access_url: Url,
    /// Database settings for Postgres.
    pub database: DatabaseConfig,
    /// Whether telemetry is enabled.
    pub telemetry_enabled: bool,
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
}

impl ServerConfig {
    /// Returns a redacted view of the runtime configuration.
    #[must_use]
    pub fn public(&self) -> PublicDeploymentConfig {
        PublicDeploymentConfig {
            listen_addr: self.listen_addr.to_string(),
            access_url: self.access_url.clone(),
            database: PublicDatabaseConfig {
                max_connections: self.database.max_connections,
                min_connections: self.database.min_connections,
                acquire_timeout_secs: self.database.acquire_timeout_secs,
            },
            telemetry_enabled: self.telemetry_enabled,
            ssh: self.ssh.clone(),
            shutdown_grace_period_secs: self.shutdown_grace_period_secs,
            log_format: self.log_format,
        }
    }

    /// Enumerates the supported configuration surface for the current Rust
    /// backend slice.
    #[must_use]
    pub fn supported_options() -> Vec<ConfigOption> {
        vec![
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
            ConfigOption {
                name: "telemetry-enabled",
                env: "CODER_TELEMETRY_ENABLED",
                default: Some("false"),
                description: "Enables deployment telemetry reporting.",
            },
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
                name: "external-auth-providers-json",
                env: "CODER_EXTERNAL_AUTH_PROVIDERS_JSON",
                default: Some("[]"),
                description: "JSON array of external auth provider metadata exposed by the Rust backend.",
            },
            ConfigOption {
                name: "derp-regions-json",
                env: "CODER_DERP_REGIONS_JSON",
                default: Some("[]"),
                description: "JSON array of DERP region probe metadata used by deployment health checks.",
            },
            ConfigOption {
                name: "shutdown-grace-period-secs",
                env: "CODER_SHUTDOWN_GRACE_PERIOD_SECS",
                default: Some("10"),
                description: "Grace period allowed for in-flight HTTP requests on shutdown.",
            },
            ConfigOption {
                name: "log-format",
                env: "CODER_LOG_FORMAT",
                default: Some("pretty"),
                description: "Structured log output format.",
            },
            ConfigOption {
                name: "session-cache-ttl-secs",
                env: "CODER_SESSION_CACHE_TTL_SECS",
                default: Some("30"),
                description: "TTL in seconds for the in-memory session authentication cache.",
            },
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
    pub ssh_config_options: Vec<(String, String)>,
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

/// Redacted deployment configuration exposed over HTTP.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PublicDeploymentConfig {
    /// Bind address for the HTTP server.
    pub listen_addr: String,
    /// External access URL for the deployment.
    pub access_url: Url,
    /// Non-secret database pool settings.
    pub database: PublicDatabaseConfig,
    /// Whether telemetry is enabled.
    pub telemetry_enabled: bool,
    /// SSH hostname settings.
    pub ssh: SshConfig,
    /// Grace period allowed for shutdown.
    pub shutdown_grace_period_secs: u64,
    /// Log format configured for the process.
    pub log_format: LogFormat,
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
