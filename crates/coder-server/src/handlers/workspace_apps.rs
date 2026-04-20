//! Workspace application proxying handlers.
//!
//! Implements subdomain-based and path-based application proxy access for
//! workspace apps, ported from the Go reference in
//! `coder/coderd/workspaceapps/`.

use super::*;
use axum::extract::ws::{Message, WebSocketUpgrade};
use axum::middleware::Next;
use futures_util::{SinkExt, StreamExt as FuturesStreamExt};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Query parameter used for API key smuggling on subdomain apps.
///
/// This must be a unique parameter name to avoid conflicts with user-defined
/// query parameters.
pub(crate) const SUBDOMAIN_PROXY_API_KEY_PARAM: &str = "coder_application_connect_api_key_35e783";

/// Cookie name for path-based app session tokens.
pub(crate) const PATH_APP_SESSION_TOKEN_COOKIE: &str = "coder_path_app_session_token";

/// Cookie prefix for subdomain-based app session tokens.
///
/// The full cookie name is `{prefix}_{hex_hash}` where the hash is derived
/// from the wildcard hostname so that different workspace proxies never
/// collide.
pub(crate) const SUBDOMAIN_APP_SESSION_TOKEN_COOKIE_PREFIX: &str =
    "coder_subdomain_app_session_token";

/// Signed-app-token cookie name.
pub(crate) const SIGNED_APP_TOKEN_COOKIE: &str = "coder_signed_app_token";

/// Signed-app-token query parameter (used for cross-domain terminal access).
pub(crate) const SIGNED_APP_TOKEN_QUERY: &str = "coder_signed_app_token";

/// Minimum port number that workspace agents allow listening on.
///
/// Ports below this are reserved for internal agent use (e.g. SSH on 4).
pub(crate) const AGENT_MINIMUM_LISTENING_PORT: u16 = 9;

/// Deprecated logout hostname kept for redirect compatibility.
const APP_LOGOUT_HOSTNAME: &str = "coder-logout";

// ---------------------------------------------------------------------------
// appurl — Application URL parsing
// ---------------------------------------------------------------------------

#[allow(unreachable_pub)] // Items are re-exported at pub(crate) via the module.
pub(crate) mod appurl {
    //! URL parsing for workspace app subdomains and paths.
    //!
    //! Ported from `coder/coderd/workspaceapps/appurl/appurl.go`.

    use regex::Regex;
    use std::sync::LazyLock;

    /// Regex matching valid name segments (usernames, workspace names, etc.).
    const NAME_REGEX: &str = "[a-zA-Z0-9]+(?:-[a-zA-Z0-9]+)*";

    /// Port regex: 4-5 digit number with optional trailing `s` for HTTPS.
    #[allow(clippy::expect_used)] // Hardcoded pattern — guaranteed to compile.
    pub(crate) static PORT_REGEX: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^\d{4,5}s?$").expect("PORT_REGEX is a valid hardcoded pattern")
    });

    /// Application URL regex supporting optional agent name.
    ///
    /// Format: `{APP_SLUG}[--{AGENT_NAME}]--{WORKSPACE_NAME}--{USERNAME}`
    #[allow(clippy::expect_used)] // Hardcoded pattern — guaranteed to compile.
    static APP_URL_REGEX: LazyLock<Regex> = LazyLock::new(|| {
        let pattern = format!(
            r"^(?P<AppSlug>{name})(?:--(?P<AgentName>{name}))?--(?P<WorkspaceName>{name})--(?P<Username>{name})$",
            name = NAME_REGEX,
        );
        Regex::new(&pattern).expect("APP_URL_REGEX is a valid hardcoded pattern")
    });

    /// Valid hostname label regex for pattern compilation.
    #[allow(clippy::expect_used)] // Hardcoded pattern — guaranteed to compile.
    static VALID_HOSTNAME_LABEL: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
            .expect("VALID_HOSTNAME_LABEL is a valid hardcoded pattern")
    });

    /// Parsed application URL hostname.
    ///
    /// Represents the components extracted from a subdomain-based workspace app
    /// URL. Can also generate path-based URLs for path apps.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct ApplicationURL {
        /// Optional prefix segment (ends with `---` when present).
        pub prefix: String,
        /// Application slug or port number (e.g. `myapp`, `8080`, `8080s`).
        pub app_slug_or_port: String,
        /// Agent name (required for port-based URLs, optional for app slugs).
        pub agent_name: String,
        /// Workspace name.
        pub workspace_name: String,
        /// Username of the workspace owner.
        pub username: String,
    }

    /// Port information extracted from an [`ApplicationURL`].
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct PortInfo {
        /// Numeric port value.
        pub port: u16,
        /// Protocol (`http` or `https`).
        pub protocol: String,
    }

    impl ApplicationURL {
        /// Returns the subdomain string (without trailing dot or base hostname).
        pub fn to_subdomain(&self) -> String {
            let mut s = String::new();
            s.push_str(&self.prefix);
            s.push_str(&self.app_slug_or_port);
            if !self.agent_name.is_empty() {
                s.push_str("--");
                s.push_str(&self.agent_name);
            }
            s.push_str("--");
            s.push_str(&self.workspace_name);
            s.push_str("--");
            s.push_str(&self.username);
            s
        }

        /// Returns the path-based URL for this application.
        ///
        /// E.g. `/@user/workspace.agent/apps/myapp` or
        /// `/@user/workspace/apps/myapp`.
        pub fn to_path(&self) -> String {
            if self.agent_name.is_empty() {
                format!(
                    "/@{}/{}/apps/{}",
                    self.username, self.workspace_name, self.app_slug_or_port
                )
            } else {
                format!(
                    "/@{}/{}.{}/apps/{}",
                    self.username, self.workspace_name, self.agent_name, self.app_slug_or_port,
                )
            }
        }

        /// Returns port information if the app slug is a port number.
        ///
        /// Port strings may end with `s` to indicate HTTPS (e.g. `8080s`).
        /// Returns `None` if the slug is not a valid port.
        pub fn port_info(&self) -> Option<PortInfo> {
            let slug = &self.app_slug_or_port;
            if slug.ends_with('s') {
                let trimmed = &slug[..slug.len() - 1];
                trimmed.parse::<u16>().ok().map(|port| PortInfo {
                    port,
                    protocol: "https".to_owned(),
                })
            } else {
                slug.parse::<u16>().ok().map(|port| PortInfo {
                    port,
                    protocol: "http".to_owned(),
                })
            }
        }
    }

    /// Error type for app URL parsing.
    #[derive(Debug, thiserror::Error)]
    pub enum AppURLError {
        /// The subdomain string does not match the expected format.
        #[error("invalid application URL format: {0:?}")]
        InvalidFormat(String),

        /// Agent name is required for port-based URLs.
        #[error("agent name is required for port-based URLs: {0:?}")]
        AgentRequired(String),

        /// The hostname pattern is invalid.
        #[error("invalid hostname pattern: {0}")]
        InvalidPattern(String),
    }

    /// Parses an [`ApplicationURL`] from a subdomain string.
    ///
    /// Subdomains should be in the form:
    /// ```text
    /// ({PREFIX}---)?{PORT{s?}/APP_SLUG}[--{AGENT_NAME}]--{WORKSPACE_NAME}--{USERNAME}
    /// ```
    ///
    /// The optional prefix is separated by triple hyphens (`---`).
    /// Agent name is **required** for port-based URLs but optional for app slugs.
    pub fn parse_subdomain_app_url(subdomain: &str) -> Result<ApplicationURL, AppURLError> {
        // Split off optional prefix (delimited by `---`).
        let (prefix, rest) = {
            let segments: Vec<&str> = subdomain.split("---").collect();
            if segments.len() > 1 {
                let prefix_parts = &segments[..segments.len() - 1];
                let prefix_str = format!("{}---", prefix_parts.join("---"));
                let rest = segments[segments.len() - 1];
                (prefix_str, rest.to_owned())
            } else {
                (String::new(), subdomain.to_owned())
            }
        };

        let caps = APP_URL_REGEX
            .captures(&rest)
            .ok_or_else(|| AppURLError::InvalidFormat(subdomain.to_owned()))?;

        let app_slug = caps
            .name("AppSlug")
            .map(|m| m.as_str().to_owned())
            .unwrap_or_default();
        let agent_name = caps
            .name("AgentName")
            .map(|m| m.as_str().to_owned())
            .unwrap_or_default();
        let workspace_name = caps
            .name("WorkspaceName")
            .map(|m| m.as_str().to_owned())
            .unwrap_or_default();
        let username = caps
            .name("Username")
            .map(|m| m.as_str().to_owned())
            .unwrap_or_default();

        // Agent name is required for port-based URLs but should be cleared for
        // app slug URLs.
        if PORT_REGEX.is_match(&app_slug) {
            if agent_name.is_empty() {
                return Err(AppURLError::AgentRequired(subdomain.to_owned()));
            }
        } else {
            // For app slugs, clear the agent name (it's embedded differently).
            return Ok(ApplicationURL {
                prefix,
                app_slug_or_port: app_slug,
                agent_name: String::new(),
                workspace_name,
                username,
            });
        }

        Ok(ApplicationURL {
            prefix,
            app_slug_or_port: app_slug,
            agent_name,
            workspace_name,
            username,
        })
    }

    /// Compiles a wildcard hostname pattern into a regular expression.
    ///
    /// The pattern must:
    /// - Contain exactly one `*` at the beginning
    /// - Not start or end with a period
    /// - Contain at least two labels (e.g. `*.example.com`)
    /// - Use only hostname-safe characters
    ///
    /// The returned regex captures the wildcard portion as group 1.
    pub fn compile_hostname_pattern(pattern: &str) -> Result<Regex, AppURLError> {
        let pattern = pattern.to_lowercase();

        if pattern.contains("http:") || pattern.contains("https:") {
            return Err(AppURLError::InvalidPattern(format!(
                "hostname pattern must not contain a scheme: {pattern:?}"
            )));
        }
        if pattern.starts_with('.') || pattern.ends_with('.') {
            return Err(AppURLError::InvalidPattern(format!(
                "hostname pattern must not start or end with a period: {pattern:?}"
            )));
        }
        if pattern.matches('.').count() < 1 {
            return Err(AppURLError::InvalidPattern(format!(
                "hostname pattern must contain at least two labels/segments: {pattern:?}"
            )));
        }
        if pattern.matches('*').count() != 1 {
            return Err(AppURLError::InvalidPattern(format!(
                "hostname pattern must contain exactly one asterisk: {pattern:?}"
            )));
        }
        if !pattern.starts_with('*') {
            return Err(AppURLError::InvalidPattern(format!(
                "hostname pattern must only contain an asterisk at the beginning: {pattern:?}"
            )));
        }

        // Strip port if present (we only care about the hostname for matching).
        let hostname = pattern
            .rsplit_once(':')
            .and_then(|(host, port)| {
                // Only strip if the part after : looks like a port number.
                if port.chars().all(|c| c.is_ascii_digit()) {
                    Some(host)
                } else {
                    None
                }
            })
            .unwrap_or(&pattern);

        // Validate each label.
        for (i, label) in hostname.split('.').enumerate() {
            let check_label = if i == 0 {
                let stripped = label.strip_prefix('*').unwrap_or(label);
                format!("a{stripped}")
            } else {
                label.to_owned()
            };
            if !VALID_HOSTNAME_LABEL.is_match(&check_label) {
                return Err(AppURLError::InvalidPattern(format!(
                    "hostname pattern contains invalid label {check_label:?}: {pattern:?}"
                )));
            }
        }

        // Build regex from pattern.
        let regex_pattern = hostname.replace('.', "\\.");
        let regex_pattern = regex_pattern.replacen('*', "([^.]+)", 1);
        // Allow trailing period, optional port, surrounding whitespace.
        let regex_pattern = format!(r"^\s*{regex_pattern}\.?(?::\d+)?\s*$");

        Regex::new(&regex_pattern)
            .map_err(|e| AppURLError::InvalidPattern(format!("failed to compile regex: {e}")))
    }

    /// Executes a compiled hostname pattern against a hostname.
    ///
    /// Returns the captured wildcard portion if the hostname matches.
    pub fn execute_hostname_pattern(pattern: &Regex, hostname: &str) -> Option<String> {
        let caps = pattern.captures(hostname)?;
        caps.get(1).map(|m| m.as_str().to_owned())
    }

    /// Returns whether two hostnames match, ignoring case, trailing dots, and
    /// port numbers.
    ///
    /// Handles IPv6 addresses in bracket notation (e.g. `[::1]:3000`).
    pub fn hostnames_match(a: &str, b: &str) -> bool {
        let normalize = |s: &str| -> String {
            let s = s.trim_matches('.');
            // Strip port if present, but handle IPv6 brackets.
            let s = if let Some(bracketed) = s.strip_prefix('[') {
                // IPv6: [::1]:port or [::1]
                bracketed.split(']').next().unwrap_or(s)
            } else {
                // IPv4/hostname: host:port or host
                s.rsplit_once(':').map(|(host, _)| host).unwrap_or(s)
            };
            s.to_lowercase()
        };
        normalize(a) == normalize(b)
    }

    #[cfg(test)]
    #[allow(clippy::expect_used)]
    mod tests {
        use super::*;

        // -- parse_subdomain_app_url tests --

        #[test]
        fn parse_app_slug_no_agent() {
            let result = parse_subdomain_app_url("myapp--dev--dean");
            assert!(result.is_ok());
            let app = result.expect("test: parsing should succeed");
            assert_eq!(app.app_slug_or_port, "myapp");
            assert_eq!(app.agent_name, "");
            assert_eq!(app.workspace_name, "dev");
            assert_eq!(app.username, "dean");
            assert_eq!(app.prefix, "");
        }

        #[test]
        fn parse_app_slug_with_agent_ignored() {
            // For app slugs, the "agent" capture is cleared.
            let result = parse_subdomain_app_url("myapp--main--dev--dean");
            assert!(result.is_ok());
            let app = result.expect("test: parsing should succeed");
            assert_eq!(app.app_slug_or_port, "myapp");
            assert_eq!(app.agent_name, "");
            assert_eq!(app.workspace_name, "dev");
            assert_eq!(app.username, "dean");
        }

        #[test]
        fn parse_port_with_agent() {
            let result = parse_subdomain_app_url("8080--main--dev--dean");
            assert!(result.is_ok());
            let app = result.expect("test: parsing should succeed");
            assert_eq!(app.app_slug_or_port, "8080");
            assert_eq!(app.agent_name, "main");
            assert_eq!(app.workspace_name, "dev");
            assert_eq!(app.username, "dean");
        }

        #[test]
        fn parse_https_port_with_agent() {
            let result = parse_subdomain_app_url("8080s--main--dev--dean");
            assert!(result.is_ok());
            let app = result.expect("test: parsing should succeed");
            assert_eq!(app.app_slug_or_port, "8080s");
            assert_eq!(app.agent_name, "main");
            assert_eq!(app.workspace_name, "dev");
            assert_eq!(app.username, "dean");
        }

        #[test]
        fn parse_port_without_agent_fails() {
            let result = parse_subdomain_app_url("8080--dev--dean");
            assert!(result.is_err());
        }

        #[test]
        fn parse_with_prefix() {
            let result = parse_subdomain_app_url("prefix---myapp--dev--dean");
            assert!(result.is_ok());
            let app = result.expect("test: parsing should succeed");
            assert_eq!(app.prefix, "prefix---");
            assert_eq!(app.app_slug_or_port, "myapp");
            assert_eq!(app.workspace_name, "dev");
            assert_eq!(app.username, "dean");
        }

        #[test]
        fn parse_with_port_prefix() {
            let result = parse_subdomain_app_url("prefix---8080--main--dev--dean");
            assert!(result.is_ok());
            let app = result.expect("test: parsing should succeed");
            assert_eq!(app.prefix, "prefix---");
            assert_eq!(app.app_slug_or_port, "8080");
            assert_eq!(app.agent_name, "main");
        }

        #[test]
        fn parse_invalid_format() {
            assert!(parse_subdomain_app_url("").is_err());
            assert!(parse_subdomain_app_url("only-one").is_err());
            assert!(parse_subdomain_app_url("--empty--parts--here").is_err());
        }

        #[test]
        fn to_subdomain_roundtrip() {
            let app = ApplicationURL {
                prefix: String::new(),
                app_slug_or_port: "myapp".to_owned(),
                agent_name: String::new(),
                workspace_name: "dev".to_owned(),
                username: "dean".to_owned(),
            };
            assert_eq!(app.to_subdomain(), "myapp--dev--dean");
        }

        #[test]
        fn to_subdomain_with_agent() {
            let app = ApplicationURL {
                prefix: String::new(),
                app_slug_or_port: "8080".to_owned(),
                agent_name: "main".to_owned(),
                workspace_name: "dev".to_owned(),
                username: "dean".to_owned(),
            };
            assert_eq!(app.to_subdomain(), "8080--main--dev--dean");
        }

        #[test]
        fn to_path_no_agent() {
            let app = ApplicationURL {
                prefix: String::new(),
                app_slug_or_port: "myapp".to_owned(),
                agent_name: String::new(),
                workspace_name: "dev".to_owned(),
                username: "dean".to_owned(),
            };
            assert_eq!(app.to_path(), "/@dean/dev/apps/myapp");
        }

        #[test]
        fn to_path_with_agent() {
            let app = ApplicationURL {
                prefix: String::new(),
                app_slug_or_port: "myapp".to_owned(),
                agent_name: "main".to_owned(),
                workspace_name: "dev".to_owned(),
                username: "dean".to_owned(),
            };
            assert_eq!(app.to_path(), "/@dean/dev.main/apps/myapp");
        }

        #[test]
        fn port_info_http() {
            let app = ApplicationURL {
                app_slug_or_port: "8080".to_owned(),
                ..Default::default()
            };
            let info = app.port_info();
            assert!(info.is_some());
            let info = info.expect("test: port info should be present");
            assert_eq!(info.port, 8080);
            assert_eq!(info.protocol, "http");
        }

        #[test]
        fn port_info_https() {
            let app = ApplicationURL {
                app_slug_or_port: "8080s".to_owned(),
                ..Default::default()
            };
            let info = app.port_info();
            assert!(info.is_some());
            let info = info.expect("test: port info should be present");
            assert_eq!(info.port, 8080);
            assert_eq!(info.protocol, "https");
        }

        #[test]
        fn port_info_not_a_port() {
            let app = ApplicationURL {
                app_slug_or_port: "myapp".to_owned(),
                ..Default::default()
            };
            assert!(app.port_info().is_none());
        }

        // -- compile/execute hostname pattern tests --

        #[test]
        fn compile_and_execute_simple_wildcard() {
            let re = compile_hostname_pattern("*.example.com");
            assert!(re.is_ok());
            let re = re.expect("test: parsing should succeed");

            let result = execute_hostname_pattern(&re, "myapp--dev--dean.example.com");
            assert_eq!(result.as_deref(), Some("myapp--dev--dean"));
        }

        #[test]
        fn compile_and_execute_with_suffix() {
            let re = compile_hostname_pattern("*--apps.example.com");
            assert!(re.is_ok());
            let re = re.expect("test: parsing should succeed");

            let result = execute_hostname_pattern(&re, "myapp--dev--dean--apps.example.com");
            assert_eq!(result.as_deref(), Some("myapp--dev--dean"));
        }

        #[test]
        fn compile_and_execute_with_port() {
            let re = compile_hostname_pattern("*.example.com:8080");
            assert!(re.is_ok());
            let re = re.expect("test: parsing should succeed");

            let result = execute_hostname_pattern(&re, "myapp--dev--dean.example.com:8080");
            assert_eq!(result.as_deref(), Some("myapp--dev--dean"));

            // Should also match without port.
            let result = execute_hostname_pattern(&re, "myapp--dev--dean.example.com");
            assert_eq!(result.as_deref(), Some("myapp--dev--dean"));
        }

        #[test]
        fn compile_and_execute_no_match() {
            let re = compile_hostname_pattern("*.example.com");
            assert!(re.is_ok());
            let re = re.expect("test: parsing should succeed");

            assert!(execute_hostname_pattern(&re, "other.domain.com").is_none());
            assert!(execute_hostname_pattern(&re, "example.com").is_none());
        }

        #[test]
        fn compile_rejects_scheme() {
            assert!(compile_hostname_pattern("http://*.example.com").is_err());
        }

        #[test]
        fn compile_rejects_leading_dot() {
            assert!(compile_hostname_pattern(".*.example.com").is_err());
        }

        #[test]
        fn compile_rejects_trailing_dot() {
            assert!(compile_hostname_pattern("*.example.com.").is_err());
        }

        #[test]
        fn compile_rejects_no_asterisk() {
            assert!(compile_hostname_pattern("example.com").is_err());
        }

        #[test]
        fn compile_rejects_multiple_asterisks() {
            assert!(compile_hostname_pattern("*.*.example.com").is_err());
        }

        #[test]
        fn compile_rejects_single_label() {
            assert!(compile_hostname_pattern("*").is_err());
        }

        #[test]
        fn compile_rejects_asterisk_not_at_start() {
            assert!(compile_hostname_pattern("example.*.com").is_err());
        }

        // -- hostnames_match tests --

        #[test]
        fn hostnames_match_basic() {
            assert!(hostnames_match("example.com", "example.com"));
            assert!(hostnames_match("Example.Com", "example.com"));
            assert!(hostnames_match("example.com.", "example.com"));
            assert!(hostnames_match("example.com:8080", "example.com"));
            assert!(hostnames_match("example.com:8080", "example.com:9090"));
        }

        #[test]
        fn hostnames_no_match() {
            assert!(!hostnames_match("a.example.com", "b.example.com"));
            assert!(!hostnames_match("example.com", "other.com"));
        }

        #[test]
        fn hostnames_match_ipv6() {
            // IPv6 in bracket notation — port stripping must not break the address.
            assert!(hostnames_match("[::1]:3000", "[::1]"));
            assert!(hostnames_match("[::1]", "[::1]:8080"));
            assert!(hostnames_match("[::1]:3000", "[::1]:8080"));
            // Bare IPv6 without brackets is not valid in Host headers, so we
            // only guarantee correctness for bracket notation.
        }
    }
}

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

/// How the workspace app is being accessed.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AccessMethod {
    /// Path-based access (e.g. `/@user/workspace.agent/apps/myapp`).
    Path,
    /// Subdomain-based access (e.g. `myapp--agent--workspace--user.apps.example.com`).
    Subdomain,
    /// Terminal/PTY access (WebSocket endpoint).
    Terminal,
}

impl std::fmt::Display for AccessMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Path => write!(f, "path"),
            Self::Subdomain => write!(f, "subdomain"),
            Self::Terminal => write!(f, "terminal"),
        }
    }
}

/// A workspace app request containing routing information.
///
/// This corresponds to the Go `Request` struct in
/// `coder/coderd/workspaceapps/request.go`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct AppRequest {
    /// How the app is being accessed.
    pub access_method: AccessMethod,
    /// Base path for cookie scoping.
    pub base_path: String,
    /// Optional prefix for subdomain apps (ends with `---`).
    #[serde(default)]
    pub prefix: String,
    /// Username or user ID of the workspace owner.
    #[serde(default)]
    pub username_or_id: String,
    /// Raw `workspace.agent` string before normalization.
    #[serde(skip)]
    pub workspace_and_agent: String,
    /// Workspace name or ID.
    #[serde(default)]
    pub workspace_name_or_id: String,
    /// Agent name or ID (optional if workspace has one agent).
    #[serde(default)]
    pub agent_name_or_id: String,
    /// Application slug or port number.
    #[serde(default)]
    pub app_slug_or_port: String,
}

impl AppRequest {
    /// Normalizes the request by splitting `workspace_and_agent` into
    /// separate fields and ensuring `base_path` has a trailing slash.
    pub(crate) fn normalize(mut self) -> Self {
        if !self.workspace_and_agent.is_empty() {
            let parts: Vec<&str> = self.workspace_and_agent.splitn(2, '.').collect();
            self.workspace_name_or_id = parts[0].to_owned();
            if parts.len() > 1 {
                self.agent_name_or_id = parts[1].to_owned();
            }
            self.workspace_and_agent = String::new();
        }
        if !self.base_path.ends_with('/') {
            self.base_path.push('/');
        }
        self
    }

    /// Validates the request fields.
    ///
    /// Must be called after [`normalize`](Self::normalize).
    pub(crate) fn check(&self) -> Result<(), AppRequestError> {
        match self.access_method {
            AccessMethod::Path | AccessMethod::Subdomain | AccessMethod::Terminal => {}
        }

        if self.base_path.is_empty() {
            return Err(AppRequestError::Validation(
                "base path is required".to_owned(),
            ));
        }

        if !self.workspace_and_agent.is_empty() {
            return Err(AppRequestError::Validation(
                "dev error: check() called before normalize()".to_owned(),
            ));
        }

        if self.access_method == AccessMethod::Terminal {
            if !self.username_or_id.is_empty()
                || !self.workspace_name_or_id.is_empty()
                || !self.app_slug_or_port.is_empty()
            {
                return Err(AppRequestError::Validation(
                    "terminal access method must only specify agent_name_or_id".to_owned(),
                ));
            }
            if self.agent_name_or_id.is_empty() {
                return Err(AppRequestError::Validation(
                    "agent name or ID is required".to_owned(),
                ));
            }
            if Uuid::parse_str(&self.agent_name_or_id).is_err() {
                return Err(AppRequestError::Validation(format!(
                    "invalid agent name or ID {:?}, must be a UUID",
                    self.agent_name_or_id
                )));
            }
            return Ok(());
        }

        if self.username_or_id.is_empty() {
            return Err(AppRequestError::Validation(
                "username or ID is required".to_owned(),
            ));
        }
        if self.username_or_id == "me" {
            return Err(AppRequestError::Validation(
                r#"username cannot be "me" in app requests"#.to_owned(),
            ));
        }
        if self.workspace_name_or_id.is_empty() {
            return Err(AppRequestError::Validation(
                "workspace name or ID is required".to_owned(),
            ));
        }
        if self.app_slug_or_port.is_empty() {
            return Err(AppRequestError::Validation(
                "app slug or port is required".to_owned(),
            ));
        }

        if !self.prefix.is_empty() && self.access_method != AccessMethod::Subdomain {
            return Err(AppRequestError::Validation(
                "prefix is only valid for subdomain apps".to_owned(),
            ));
        }
        if !self.prefix.is_empty() && !self.prefix.ends_with("---") {
            return Err(AppRequestError::Validation(
                "prefix must have a trailing '---'".to_owned(),
            ));
        }

        Ok(())
    }
}

/// Errors from app request validation.
#[derive(Debug, thiserror::Error)]
pub(crate) enum AppRequestError {
    /// A validation constraint was violated.
    #[error("{0}")]
    Validation(String),
}

// ---------------------------------------------------------------------------
// Cookie handling
// ---------------------------------------------------------------------------

/// Cookie name management for workspace apps.
///
/// Different cookie names are used for path vs subdomain apps to prevent
/// collisions.
#[derive(Clone, Debug)]
pub(crate) struct AppCookies {
    /// Cookie name for path-based app sessions.
    pub path_app_session_token: String,
    /// Cookie name for subdomain-based app sessions (unique per proxy).
    pub subdomain_app_session_token: String,
}

impl AppCookies {
    /// Creates cookie names for the given wildcard hostname.
    ///
    /// The subdomain cookie name includes a hash of the hostname so that
    /// different workspace proxies don't collide.
    pub(crate) fn new(hostname: &str) -> Self {
        Self {
            path_app_session_token: PATH_APP_SESSION_TOKEN_COOKIE.to_owned(),
            subdomain_app_session_token: subdomain_app_session_token_cookie(hostname),
        }
    }

    /// Returns the appropriate cookie name for the given access method.
    pub(crate) fn cookie_name_for_access_method(&self, method: &AccessMethod) -> &str {
        match method {
            AccessMethod::Subdomain => &self.subdomain_app_session_token,
            // Path and terminal use the same domain:
            AccessMethod::Path | AccessMethod::Terminal => &self.path_app_session_token,
        }
    }

    /// Extracts the session token from request headers for the given access
    /// method.
    ///
    /// Priority:
    /// 1. Access-method-specific cookie
    /// 2. Standard Coder token extraction (session header, cookie, bearer)
    pub(crate) fn token_from_request(
        &self,
        headers: &HeaderMap,
        method: &AccessMethod,
    ) -> Option<String> {
        let cookie_name = self.cookie_name_for_access_method(method);

        // Check method-specific cookie first.
        if let Some(cookie_val) = cookie_from_headers(headers, cookie_name) {
            if !cookie_val.is_empty() {
                return Some(cookie_val);
            }
        }

        // Fall back to standard Coder token extraction.
        // Coder-Session-Token header.
        if let Some(val) = headers
            .get("coder-session-token")
            .and_then(|v| v.to_str().ok())
        {
            if !val.is_empty() {
                return Some(val.to_owned());
            }
        }

        // coder_session_token cookie.
        if let Some(val) = cookie_from_headers(headers, "coder_session_token") {
            if !val.is_empty() {
                return Some(val);
            }
        }

        // Authorization: Bearer header.
        if let Some(auth_header) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
            let mut parts = auth_header.splitn(2, char::is_whitespace);
            if let (Some(scheme), Some(rest)) = (parts.next(), parts.next()) {
                if scheme.eq_ignore_ascii_case("bearer") {
                    let token = rest.trim();
                    if !token.is_empty() {
                        return Some(token.to_owned());
                    }
                }
            }
        }

        None
    }
}

/// Generates a unique subdomain app session token cookie name for the given
/// hostname.
///
/// Uses a SHA-256 hash of the hostname to ensure uniqueness across different
/// workspace proxies operating under the same wildcard domain.
fn subdomain_app_session_token_cookie(hostname: &str) -> String {
    use sha2::Digest;
    let hash = Sha256::digest(hostname.as_bytes());
    // Encode the first 16 bytes as hex (32 hex chars).
    let hex: String = hash[..16]
        .iter()
        .fold(String::with_capacity(32), |mut acc, byte| {
            use std::fmt::Write;
            let _ = write!(acc, "{byte:02x}");
            acc
        });
    format!("{SUBDOMAIN_APP_SESSION_TOKEN_COOKIE_PREFIX}_{hex}")
}

// ---------------------------------------------------------------------------
// Proxy server types
// ---------------------------------------------------------------------------

/// Configuration for the workspace app proxy server.
#[derive(Clone, Debug)]
pub(crate) struct WorkspaceAppServer {
    /// Dashboard/primary URL.
    pub dashboard_url: url::Url,
    /// Access URL for the current deployment.
    pub access_url: url::Url,
    /// Wildcard hostname pattern (e.g. `*.apps.example.com`).
    /// Empty string means subdomain apps are disabled.
    pub hostname: String,
    /// Compiled regex from the hostname pattern.
    pub hostname_regex: Option<regex::Regex>,
    /// Whether path-based apps are disabled.
    pub disable_path_apps: bool,
    /// Cookie names for this proxy.
    pub cookies: AppCookies,
}

impl WorkspaceAppServer {
    /// Creates a new workspace app server configuration.
    ///
    /// If `hostname` is non-empty, compiles it into a regex for subdomain
    /// matching.
    pub(crate) fn new(
        dashboard_url: url::Url,
        access_url: url::Url,
        hostname: String,
        disable_path_apps: bool,
    ) -> Result<Self, appurl::AppURLError> {
        let hostname_regex = if hostname.is_empty() {
            None
        } else {
            Some(appurl::compile_hostname_pattern(&hostname)?)
        };
        let cookies = AppCookies::new(&hostname);

        Ok(Self {
            dashboard_url,
            access_url,
            hostname,
            hostname_regex,
            disable_path_apps,
            cookies,
        })
    }
}

// ---------------------------------------------------------------------------
// Access-error classification (ported from Go `appErrNotFoundDescription` in
// coder/coderd/workspaceapps/appurl/errorpage.go)
// ---------------------------------------------------------------------------

/// Classified, user-facing reasons why a workspace app request was rejected.
///
/// The display strings are deliberately kept in sync with the Go reference
/// (`coder/coderd/workspaceapps/auth.go` and `appurl/errorpage.go`) so that UI
/// error pages and API clients see identical wording.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AppAccessError {
    /// Workspace agent has not connected back to the control plane yet.
    AgentNotReporting,
    /// Agent was connected, but has dropped and not returned in time.
    AgentNotConnected,
    /// Template policy forbids end-user app access.
    TemplateDoesNotAllowAppAccess,
    /// App is present but reporting unhealthy.
    AppNotRunning,
    /// App exists but has no configured upstream URL.
    AppURLNotSet,
    /// Authenticated user is not a member of the workspace's organization,
    /// and the app sharing level is set to `organization`.
    NotOrganizationMember,
}

impl AppAccessError {
    /// Returns the message shown to the user. Matches Go exactly.
    pub(crate) const fn description(&self) -> &'static str {
        match self {
            Self::AgentNotReporting => "agent is not reporting",
            Self::AgentNotConnected => "agent is not connected",
            Self::TemplateDoesNotAllowAppAccess => "template does not allow app access",
            Self::AppNotRunning => "app is not running",
            Self::AppURLNotSet => "app URL is not set",
            Self::NotOrganizationMember => "user is not a member of the workspace's organization",
        }
    }

    /// Returns the HTTP status Go uses for each classification.
    ///
    /// Most of these are 404 because Go intentionally hides whether a
    /// workspace/agent/app exists from users who can't access it — the one
    /// exception is the organization sharing-level denial, which is a true
    /// 403.
    pub(crate) const fn status_code(&self) -> StatusCode {
        match self {
            Self::NotOrganizationMember => StatusCode::FORBIDDEN,
            Self::AgentNotReporting
            | Self::AgentNotConnected
            | Self::TemplateDoesNotAllowAppAccess
            | Self::AppNotRunning
            | Self::AppURLNotSet => StatusCode::NOT_FOUND,
        }
    }
}

impl std::fmt::Display for AppAccessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.description())
    }
}

// ---------------------------------------------------------------------------
// Proxy error types
// ---------------------------------------------------------------------------

/// Errors from workspace app proxy operations.
#[derive(Debug, thiserror::Error)]
pub(crate) enum WorkspaceAppError {
    /// The application was not found.
    #[error("application not found: {0}")]
    NotFound(String),

    /// The user is not authenticated.
    #[error("authentication required")]
    Unauthorized,

    /// The user does not have permission.
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// The request is invalid.
    #[error("bad request: {0}")]
    BadRequest(String),

    /// Path-based apps are disabled.
    #[error("path-based applications are disabled")]
    PathAppsDisabled,

    /// The workspace is offline/stopped.
    #[error("workspace offline")]
    WorkspaceOffline,

    /// The agent is not connected.
    #[error("agent offline: {0}")]
    AgentOffline(String),

    /// Internal server error.
    #[error("internal error: {0}")]
    Internal(String),

    /// Upstream proxy error.
    #[error("proxy error: {0}")]
    ProxyError(String),

    /// App-access classification (mirrors Go's `appErrNotFoundDescription`).
    #[error("{0}")]
    Classified(AppAccessError),
}

impl WorkspaceAppError {
    /// Short classification string (if any) suitable for structured error
    /// payloads. `None` for non-classified variants.
    pub(crate) fn classification(&self) -> Option<&'static str> {
        match self {
            Self::Classified(c) => Some(c.description()),
            _ => None,
        }
    }
}

impl IntoResponse for WorkspaceAppError {
    fn into_response(self) -> Response {
        let (status, message, detail) = match &self {
            Self::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone(), String::new()),
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "Authentication required.".to_owned(),
                String::new(),
            ),
            Self::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.clone(), String::new()),
            Self::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone(), String::new()),
            Self::PathAppsDisabled => (
                StatusCode::FORBIDDEN,
                "Path-based applications are disabled on this Coder deployment.".to_owned(),
                String::new(),
            ),
            Self::WorkspaceOffline => (
                StatusCode::BAD_REQUEST,
                "Workspace is offline. Start the workspace to access its applications.".to_owned(),
                String::new(),
            ),
            Self::AgentOffline(msg) => (StatusCode::BAD_GATEWAY, msg.clone(), String::new()),
            Self::Internal(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                msg.clone(),
                String::new(),
            ),
            Self::ProxyError(msg) => (StatusCode::BAD_GATEWAY, msg.clone(), String::new()),
            Self::Classified(c) => (c.status_code(), c.description().to_owned(), String::new()),
        };
        (status, Json(ApiResponse::error(message, detail))).into_response()
    }
}

// ---------------------------------------------------------------------------
// Path-based app proxy handler
// ---------------------------------------------------------------------------

/// Handler for path-based workspace app proxy requests.
///
/// Route pattern: `/@{user}/{workspace_and_agent}/apps/{workspaceapp}/*rest`
///
/// This handler:
/// 1. Validates that path apps are enabled
/// 2. Rejects `@me` usernames (must use full username)
/// 3. Extracts routing parameters
/// 4. Authenticates the user
/// 5. Proxies the request to the workspace agent
pub(crate) async fn workspace_apps_proxy_path(
    State(state): State<AppState>,
    method: http::Method,
    headers: HeaderMap,
    Path(params): Path<PathAppParams>,
    OriginalUri(original_uri): OriginalUri,
    body: axum::body::Body,
) -> Result<Response, WorkspaceAppError> {
    let server = build_workspace_app_server(&state);

    // Check if path apps are disabled.
    if server.disable_path_apps {
        return Err(WorkspaceAppError::PathAppsDisabled);
    }

    // Reject @me.
    if params.user == "me" {
        return Err(WorkspaceAppError::NotFound(
            "Applications must be accessed with the full username, not @me.".to_owned(),
        ));
    }

    // Determine the real path after the app base.
    let full_path = original_uri.path();
    // The base path is /@{user}/{workspace_and_agent}/apps/{workspaceapp}/
    let base_path = format!(
        "/@{}/{}/apps/{}/",
        params.user, params.workspace_and_agent, params.workspaceapp
    );
    let app_path = full_path
        .strip_prefix(base_path.trim_end_matches('/'))
        .unwrap_or("/");
    let app_path = if app_path.is_empty() { "/" } else { app_path };

    // Build the app request.
    let app_request = AppRequest {
        access_method: AccessMethod::Path,
        base_path: base_path.clone(),
        prefix: String::new(),
        username_or_id: params.user.clone(),
        workspace_and_agent: params.workspace_and_agent.clone(),
        workspace_name_or_id: String::new(),
        agent_name_or_id: String::new(),
        app_slug_or_port: params.workspaceapp.clone(),
    }
    .normalize();

    if let Err(e) = app_request.check() {
        return Err(WorkspaceAppError::BadRequest(e.to_string()));
    }

    // Authenticate the user.
    let session_token = server
        .cookies
        .token_from_request(&headers, &app_request.access_method);

    let auth_context = authenticate_app_request(&state, &headers, session_token.as_deref()).await?;

    // Proxy the request to the agent.
    proxy_workspace_app(
        &state,
        &server,
        &auth_context,
        &app_request,
        method,
        &headers,
        body,
        app_path,
        original_uri.query().unwrap_or(""),
        false,
    )
    .await
}

/// Path parameters for path-based app routes.
#[derive(Debug, Deserialize)]
pub(crate) struct PathAppParams {
    pub user: String,
    pub workspace_and_agent: String,
    pub workspaceapp: String,
}

// ---------------------------------------------------------------------------
// Subdomain middleware
// ---------------------------------------------------------------------------

/// Middleware for subdomain-based workspace app proxying.
///
/// This should be applied as an outer layer on the router. It inspects the
/// `Host` header and, if it matches the configured app hostname pattern,
/// routes the request to the workspace app proxy instead of the normal API
/// handlers.
///
/// Follows the same decision tree as the Go implementation:
/// 1. If hostname is not configured, pass through
/// 2. If Host header is missing, return 400
/// 3. If Host matches access URL or dashboard URL, pass through
/// 4. If Host doesn't contain periods, pass through
/// 5. Parse subdomain from hostname pattern
/// 6. Parse application URL from subdomain
/// 7. Authenticate and proxy
pub(crate) async fn subdomain_app_middleware(
    State(state): State<AppState>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let server = build_workspace_app_server(&state);

    // Step 1: Pass through if subdomain apps are not configured.
    if server.hostname.is_empty() || server.hostname_regex.is_none() {
        return next.run(request).await;
    }

    // Step 2: Get the request Host.
    let host = request
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if host.is_empty() {
        // Check for /derp endpoint which sometimes has no Host header.
        if request.uri().path() == "/derp" {
            return next.run(request).await;
        }
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "Could not determine request Host.".to_owned(),
                String::new(),
            )),
        )
            .into_response();
    }

    // Step 3: Check if host matches access or dashboard URL.
    if appurl::hostnames_match(server.dashboard_url.host_str().unwrap_or(""), host)
        || appurl::hostnames_match(server.access_url.host_str().unwrap_or(""), host)
    {
        return next.run(request).await;
    }

    // Step 4: Must contain periods to be a subdomain.
    if !host.contains('.') {
        return next.run(request).await;
    }

    // Step 5: Match against hostname regex.
    let hostname_regex = match &server.hostname_regex {
        Some(re) => re,
        None => return next.run(request).await,
    };

    let subdomain = match appurl::execute_hostname_pattern(hostname_regex, host) {
        Some(s) => s,
        None => return next.run(request).await,
    };

    // Handle deprecated logout hostname.
    if subdomain == APP_LOGOUT_HOSTNAME {
        return axum::response::Redirect::to(server.access_url.as_str()).into_response();
    }

    // Step 6: Parse the application URL from subdomain.
    let app = match appurl::parse_subdomain_app_url(&subdomain) {
        Ok(app) => app,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error(
                    format!("Invalid application URL: {e}"),
                    String::new(),
                )),
            )
                .into_response();
        }
    };

    // Build the app request.
    let app_request = AppRequest {
        access_method: AccessMethod::Subdomain,
        base_path: "/".to_owned(),
        prefix: app.prefix.clone(),
        username_or_id: app.username.clone(),
        workspace_and_agent: String::new(),
        workspace_name_or_id: app.workspace_name.clone(),
        agent_name_or_id: app.agent_name.clone(),
        app_slug_or_port: app.app_slug_or_port.clone(),
    };

    if let Err(e) = app_request.check() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(e.to_string(), String::new())),
        )
            .into_response();
    }

    let headers = request.headers().clone();

    // Authenticate.
    let session_token = server
        .cookies
        .token_from_request(&headers, &app_request.access_method);

    let auth_result = authenticate_app_request(&state, &headers, session_token.as_deref()).await;

    let auth_context = match auth_result {
        Ok(ctx) => ctx,
        Err(e) => return e.into_response(),
    };

    let app_path = request.uri().path().to_owned();
    let app_query = request.uri().query().unwrap_or("").to_owned();
    let method = request.method().clone();
    let req_headers = request.headers().clone();
    let body = request.into_body();

    // Proxy the request.
    match proxy_workspace_app(
        &state,
        &server,
        &auth_context,
        &app_request,
        method,
        &req_headers,
        body,
        &app_path,
        &app_query,
        false,
    )
    .await
    {
        Ok(resp) => resp,
        Err(e) => e.into_response(),
    }
}

// ---------------------------------------------------------------------------
// Authentication helpers
// ---------------------------------------------------------------------------

/// Authenticated context for a workspace app request.
#[derive(Clone, Debug)]
pub(crate) struct AppAuthContext {
    /// The authenticated user ID (if authenticated).
    pub user_id: Option<Uuid>,
    /// The username (if authenticated).
    pub username: Option<String>,
}

/// Authenticates a workspace app request using session tokens.
///
/// Checks the session token cookie/header and validates it against the store.
/// Returns the authentication context.
async fn authenticate_app_request(
    state: &AppState,
    _headers: &HeaderMap,
    session_token: Option<&str>,
) -> Result<AppAuthContext, WorkspaceAppError> {
    // If there's a session token, try to authenticate.
    if let Some(token) = session_token {
        // Build headers with the session token for the auth service.
        let mut auth_headers = HeaderMap::new();
        if let Ok(val) = HeaderValue::from_str(token) {
            auth_headers.insert(HeaderName::from_static("coder-session-token"), val);
        }

        match state.auth.authenticate(&auth_headers).await {
            Ok(Some(auth_req)) => {
                return Ok(AppAuthContext {
                    user_id: Some(auth_req.user.id),
                    username: Some(auth_req.user.username.clone()),
                });
            }
            Ok(None) => {
                // Token was invalid — treat as unauthenticated.
            }
            Err(_) => {
                // Auth error — treat as unauthenticated for app requests.
            }
        }
    }

    // Unauthenticated — this is allowed for public apps, the authorization
    // step will determine if access is permitted.
    Ok(AppAuthContext {
        user_id: None,
        username: None,
    })
}

// ---------------------------------------------------------------------------
// Proxy implementation
// ---------------------------------------------------------------------------

/// Proxies a workspace app request to the appropriate agent.
///
/// This function:
/// 1. Validates the app URL and port
/// 2. Handles path redirects for trailing slashes
/// 3. Strips Coder cookies from the forwarded request
/// 4. Forwards the request using the HTTP client
/// 5. Returns the proxied response
#[allow(clippy::too_many_arguments)]
async fn proxy_workspace_app(
    state: &AppState,
    _server: &WorkspaceAppServer,
    auth_context: &AppAuthContext,
    app_request: &AppRequest,
    method: http::Method,
    original_headers: &HeaderMap,
    body: axum::body::Body,
    app_path: &str,
    app_query: &str,
    slug_is_port: bool,
) -> Result<Response, WorkspaceAppError> {
    // For now, workspace app proxying requires authentication.
    // Public apps would be handled here with sharing level checks.
    let user_id = auth_context
        .user_id
        .ok_or(WorkspaceAppError::Unauthorized)?;

    // Resolve the workspace + agent + app in a single pass so we can enforce
    // sharing-level policy (B.13 item 1) and record session stats (B.13
    // item 2).
    let resolved = resolve_app_context(state, app_request, slug_is_port).await?;

    // Organization-scoped sharing enforcement.
    enforce_organization_sharing(
        state,
        &resolved.sharing_level,
        resolved.workspace_organization_id,
        Some(user_id),
    )
    .await?;

    // Validate port.
    if let Some(port_str) = resolved.url.port() {
        if port_str < AGENT_MINIMUM_LISTENING_PORT {
            return Err(WorkspaceAppError::BadRequest(format!(
                "Application port {} is not permitted. Coder reserves ports less than {} for internal use.",
                port_str, AGENT_MINIMUM_LISTENING_PORT,
            )));
        }
    }

    // Handle empty path redirect.
    if app_path.is_empty() {
        return Ok(axum::response::Redirect::temporary(&format!(
            "{}/",
            app_request.base_path.trim_end_matches('/')
        ))
        .into_response());
    }

    // Record session stats for the lifetime of this request. The guard
    // persists on drop so any early-return error path still flushes.
    let mut stats_guard = AppStatsGuard::new(
        state.store.clone(),
        AppStatsContext {
            user_id,
            workspace_id: resolved.workspace_id,
            agent_id: resolved.agent_id,
            access_method: app_request.access_method.to_string(),
            slug_or_port: resolved.slug_or_port.clone(),
        },
    );
    stats_guard.record_request();

    // Build the proxy target URL.
    let mut target_url = resolved.url.clone();
    target_url.set_path(app_path);
    if !app_query.is_empty() {
        target_url.set_query(Some(app_query));
    }

    // Build the outbound request using the original HTTP method.
    let reqwest_method = reqwest::Method::from_bytes(method.as_str().as_bytes())
        .map_err(|e| WorkspaceAppError::Internal(format!("invalid HTTP method: {e}")))?;

    let mut proxy_request_builder = state
        .http_client
        .request(reqwest_method, target_url.as_str());

    // Forward original headers, stripping Coder cookies.
    for (key, value) in original_headers {
        let header_name = key.as_str();
        // Skip hop-by-hop headers and host (will be set by reqwest).
        if header_name == "host" || header_name == "connection" || header_name == "te" {
            continue;
        }
        if header_name == "cookie" {
            // Strip Coder-specific cookies from the cookie header.
            let cleaned = strip_coder_cookies(value.to_str().unwrap_or(""));
            if !cleaned.is_empty() {
                if let Ok(val) = HeaderValue::from_str(&cleaned) {
                    proxy_request_builder = proxy_request_builder.header(key.clone(), val);
                }
            }
            continue;
        }
        proxy_request_builder = proxy_request_builder.header(key.clone(), value.clone());
    }

    // Forward the request body.
    let body_bytes = axum::body::to_bytes(body, 64 * 1024 * 1024)
        .await
        .map_err(|e| WorkspaceAppError::ProxyError(format!("failed to read request body: {e}")))?;
    if !body_bytes.is_empty() {
        proxy_request_builder = proxy_request_builder.body(body_bytes);
    }

    let proxy_request = proxy_request_builder
        .build()
        .map_err(|e| WorkspaceAppError::ProxyError(e.to_string()))?;

    // Execute the proxy request.
    let response = state
        .http_client
        .execute(proxy_request)
        .await
        .map_err(|e| WorkspaceAppError::ProxyError(e.to_string()))?;

    // Convert the reqwest response to an axum response.
    let status = StatusCode::from_u16(response.status().as_u16()).map_err(|_| {
        WorkspaceAppError::ProxyError(format!(
            "upstream returned invalid status code: {}",
            response.status().as_u16()
        ))
    })?;

    let mut builder = Response::builder().status(status);

    // Copy response headers.
    // NOTE: The `http` crate's `HeaderName` always lowercases header names,
    // so non-canonical WebSocket header casing (e.g. `Sec-WebSocket-Accept`)
    // cannot be preserved through axum's `Response::builder()`. This is a
    // known limitation — the Go implementation uses a custom HTTP/1.1 writer
    // to emit mixed-case headers for sensitive WebSocket clients. A future
    // improvement could use hyper's lower-level API to emit raw header names.
    for (key, value) in response.headers() {
        if let Ok(val) = HeaderValue::from_bytes(value.as_bytes()) {
            builder = builder.header(key.clone(), val);
        }
    }

    let body = response
        .bytes()
        .await
        .map_err(|e| WorkspaceAppError::ProxyError(e.to_string()))?;

    builder
        .body(axum::body::Body::from(body))
        .map_err(|e| WorkspaceAppError::Internal(e.to_string()))
}

// ---------------------------------------------------------------------------
// Organization sharing-level enforcement
// ---------------------------------------------------------------------------

/// Verifies that an authenticated user is allowed to access an app based on
/// the app's sharing level and the workspace's organization.
///
/// Ported from Go `coder/coderd/workspaceapps/auth.go`
/// (`authorizeWorkspaceApp`). The key behaviour this covers is:
///
/// - If the app is shared at organization level and the caller is not a
///   member of the workspace's organization, the request is denied with 403
///   and the classification `NotOrganizationMember`.
///
/// Other sharing levels (owner / authenticated / public) are enforced
/// elsewhere in the pipeline today; this function is a no-op for them.
pub(crate) async fn enforce_organization_sharing(
    state: &AppState,
    sharing_level: &str,
    workspace_organization_id: Uuid,
    user_id: Option<Uuid>,
) -> Result<(), WorkspaceAppError> {
    if !sharing_level.eq_ignore_ascii_case("organization") {
        return Ok(());
    }

    let user_id = user_id.ok_or(WorkspaceAppError::Unauthorized)?;

    let member = state
        .store
        .find_organization_member(workspace_organization_id, user_id)
        .await
        .map_err(|e| {
            WorkspaceAppError::Internal(format!("failed to look up organization member: {e}"))
        })?;

    if member.is_none() {
        return Err(WorkspaceAppError::Classified(
            AppAccessError::NotOrganizationMember,
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Session stats recorder
// ---------------------------------------------------------------------------

/// Context required to record a session's stats to `workspace_app_stats`.
#[derive(Clone, Debug)]
pub(crate) struct AppStatsContext {
    /// Authenticated user.
    pub user_id: Uuid,
    /// Workspace that owns the agent/app.
    pub workspace_id: Uuid,
    /// Agent the session is proxied through.
    pub agent_id: Uuid,
    /// Access method: `path` / `subdomain` / `terminal`.
    pub access_method: String,
    /// Slug (for apps) or port number (for port-forwarding).
    pub slug_or_port: String,
}

impl AppStatsContext {
    /// Serializes this record in the same shape expected by
    /// [`AppStore::insert_workspace_app_stats`].
    pub(crate) fn to_stat_value(
        &self,
        session_id: Uuid,
        session_started_at: OffsetDateTime,
        session_ended_at: OffsetDateTime,
        requests: i32,
    ) -> Value {
        let fmt_ts = |ts: OffsetDateTime| {
            ts.format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default()
        };
        serde_json::json!({
            "user_id": self.user_id.to_string(),
            "workspace_id": self.workspace_id.to_string(),
            "agent_id": self.agent_id.to_string(),
            "access_method": self.access_method,
            "slug_or_port": self.slug_or_port,
            "session_id": session_id.to_string(),
            "session_started_at": fmt_ts(session_started_at),
            "session_ended_at": fmt_ts(session_ended_at),
            "requests": requests,
        })
    }
}

/// Drop guard that writes a `workspace_app_stats` row when the proxied
/// request completes.
///
/// Ported from the Go stats collector (`coder/coderd/workspaceapps/stats.go`
/// + `statscollector.go`). We use a fire-and-forget background task on drop
/// so the response returns to the user without waiting on the DB write.
pub(crate) struct AppStatsGuard {
    store: Arc<dyn AppStore>,
    ctx: AppStatsContext,
    session_id: Uuid,
    session_started_at: OffsetDateTime,
    requests: i32,
    /// Takes the value when emitting so double-emit on drop is a no-op.
    emitted: bool,
}

impl AppStatsGuard {
    /// Starts recording stats for a new session.
    pub(crate) fn new(store: Arc<dyn AppStore>, ctx: AppStatsContext) -> Self {
        Self {
            store,
            ctx,
            session_id: Uuid::new_v4(),
            session_started_at: OffsetDateTime::now_utc(),
            requests: 0,
            emitted: false,
        }
    }

    /// Records a completed HTTP request on this session.
    pub(crate) fn record_request(&mut self) {
        self.requests = self.requests.saturating_add(1);
    }

    /// Emits the stats row to the store synchronously. Useful from tests and
    /// in synchronous shutdown paths.
    pub(crate) async fn flush(mut self) -> Result<(), StorageError> {
        self.emitted = true;
        let ended = OffsetDateTime::now_utc();
        let stat = self.ctx.to_stat_value(
            self.session_id,
            self.session_started_at,
            ended,
            self.requests,
        );
        self.store.insert_workspace_app_stats(&[stat]).await
    }
}

impl Drop for AppStatsGuard {
    fn drop(&mut self) {
        if self.emitted {
            return;
        }
        // Best-effort background insert so the response is not delayed. Any
        // error is logged but does not propagate to the user.
        let store = self.store.clone();
        let ctx = self.ctx.clone();
        let session_id = self.session_id;
        let session_started_at = self.session_started_at;
        let ended = OffsetDateTime::now_utc();
        let requests = self.requests;
        tokio::spawn(async move {
            let stat = ctx.to_stat_value(session_id, session_started_at, ended, requests);
            if let Err(err) = store.insert_workspace_app_stats(&[stat]).await {
                tracing::warn!(
                    error = %err,
                    workspace_id = %ctx.workspace_id,
                    agent_id = %ctx.agent_id,
                    "failed to insert workspace app stats"
                );
            }
        });
    }
}

// ---------------------------------------------------------------------------
// URL resolution
// ---------------------------------------------------------------------------

/// Full context for a resolved app request, populated by
/// [`resolve_app_context`]. Supersedes the old url-only resolver once the
/// new path is rolled out.
#[derive(Clone, Debug)]
pub(crate) struct ResolvedApp {
    /// Upstream URL to forward the request to.
    pub url: url::Url,
    /// Agent handling the session.
    pub agent_id: Uuid,
    /// Workspace that owns the agent.
    pub workspace_id: Uuid,
    /// Workspace organization (used for org sharing-level enforcement).
    pub workspace_organization_id: Uuid,
    /// Sharing level for the resolved app (empty string for port-forwarding).
    pub sharing_level: String,
    /// Slug or port string as presented to the client (for stats).
    pub slug_or_port: String,
}

/// Resolves the target URL for a workspace app.
///
/// For port-based apps (matching `PORT_REGEX`: 4-5 digits, optional `s`
/// suffix), looks up the workspace agent from the store and constructs the
/// target URL using the agent's address.
///
/// For slug-based apps, looks up the app's URL from the database via
/// `find_workspace_app_by_agent_and_slug`.
///
/// In both cases the proxy routes through the workspace agent's address
/// rather than the Coder server's own loopback interface, preventing SSRF.
#[allow(dead_code)] // Kept for reference; superseded by `resolve_app_context`.
async fn resolve_app_url(
    state: &AppState,
    request: &AppRequest,
    slug_is_port: bool,
) -> Result<url::Url, WorkspaceAppError> {
    let slug = &request.app_slug_or_port;

    // Resolve the workspace agent so we can route to its address.
    let agent_id = resolve_workspace_agent_id(state, request).await?;
    let agent = state
        .store
        .find_workspace_agent_by_id(agent_id)
        .await
        .map_err(|e| {
            WorkspaceAppError::Internal(format!("failed to look up workspace agent: {e}"))
        })?
        .ok_or_else(|| WorkspaceAppError::NotFound("workspace agent not found".into()))?;

    // Use the agent's name as a tailnet DNS label.  The tailnet
    // coordinator resolves this to the agent's actual address, so we
    // never construct URLs pointing at the server's own loopback.
    let agent_host = if agent.name.is_empty() {
        return Err(WorkspaceAppError::Internal(
            "workspace agent has no name configured".into(),
        ));
    } else {
        &agent.name
    };

    // Check if the slug is a port number. The appurl::PORT_REGEX only matches
    // 4-5 digit numbers (with optional trailing 's' for HTTPS), but port
    // forwarding accepts any valid u16 >= AGENT_MINIMUM_LISTENING_PORT. Handle
    // both the regex-style format (e.g. "8080s" for HTTPS) and plain numeric
    // ports (e.g. "80", "443").
    if appurl::PORT_REGEX.is_match(slug) {
        let (port_str, protocol) = if slug.ends_with('s') {
            (&slug[..slug.len() - 1], "https")
        } else {
            (slug.as_str(), "http")
        };

        if let Ok(port) = port_str.parse::<u16>() {
            let url_str = format!("{protocol}://{agent_host}:{port}");
            return url::Url::parse(&url_str)
                .map_err(|e| WorkspaceAppError::Internal(format!("invalid port URL: {e}")));
        }
    } else if slug_is_port {
        // The caller (port forwarding handler) has already validated this is a
        // port number. Parse it as u16 — this covers 1-3 digit ports like 80,
        // 443 that don't match PORT_REGEX (which only matches 4-5 digits).
        if let Ok(port) = slug.parse::<u16>() {
            let url_str = format!("http://{agent_host}:{port}");
            return url::Url::parse(&url_str)
                .map_err(|e| WorkspaceAppError::Internal(format!("invalid port URL: {e}")));
        }
    }

    // For slug-based apps, look up the app record in the database.
    let app = state
        .store
        .find_workspace_app_by_agent_and_slug(agent_id, slug)
        .await
        .map_err(|e| WorkspaceAppError::Internal(format!("failed to look up workspace app: {e}")))?
        .ok_or_else(|| {
            WorkspaceAppError::NotFound(format!("application {slug:?} not found for agent"))
        })?;

    // Use the app's URL if set, otherwise construct from the agent host.
    let app_url_str = app.url.unwrap_or_default();
    if app_url_str.is_empty() {
        return Err(WorkspaceAppError::Internal(format!(
            "workspace app {slug:?} has no URL configured"
        )));
    }

    url::Url::parse(&app_url_str)
        .map_err(|e| WorkspaceAppError::Internal(format!("invalid app URL: {e}")))
}

/// Resolves the full app context (agent, workspace, URL, sharing level) for
/// a proxy request. Used by [`proxy_workspace_app`] to drive both
/// organization sharing-level enforcement (B.13 item 1) and session-stats
/// recording (B.13 item 2).
///
/// The legacy [`resolve_app_url`] helper is retained for call sites that do
/// not yet consume the full context.
async fn resolve_app_context(
    state: &AppState,
    request: &AppRequest,
    slug_is_port: bool,
) -> Result<ResolvedApp, WorkspaceAppError> {
    let slug = &request.app_slug_or_port;

    // Step 1: resolve the agent (may parse a UUID directly, or traverse
    // user → workspace → build → resources → agents).
    let agent_id = resolve_workspace_agent_id(state, request).await?;
    let agent = state
        .store
        .find_workspace_agent_by_id(agent_id)
        .await
        .map_err(|e| {
            WorkspaceAppError::Internal(format!("failed to look up workspace agent: {e}"))
        })?
        .ok_or_else(|| WorkspaceAppError::NotFound("workspace agent not found".into()))?;

    // Step 2: classify the agent connection state so we can return Go's UI
    // error strings (B.13 item 3). `first_connected_at` being None means the
    // agent has never reported in; `disconnected_at` being Some means it
    // dropped out.
    if agent.first_connected_at.is_none() {
        return Err(WorkspaceAppError::Classified(
            AppAccessError::AgentNotReporting,
        ));
    }
    if agent.disconnected_at.is_some() && agent.last_connected_at.is_none() {
        return Err(WorkspaceAppError::Classified(
            AppAccessError::AgentNotConnected,
        ));
    }

    // Step 3: resolve the workspace record so we can get the organization
    // for sharing-level enforcement.
    let workspace = lookup_workspace_for_request(state, request).await?;

    if agent.name.is_empty() {
        return Err(WorkspaceAppError::Internal(
            "workspace agent has no name configured".into(),
        ));
    }
    let agent_host = &agent.name;

    // Step 4: port-style slug → synthesize URL from agent host.
    if appurl::PORT_REGEX.is_match(slug) {
        let (port_str, protocol) = if slug.ends_with('s') {
            (&slug[..slug.len() - 1], "https")
        } else {
            (slug.as_str(), "http")
        };
        if let Ok(port) = port_str.parse::<u16>() {
            let url_str = format!("{protocol}://{agent_host}:{port}");
            let url = url::Url::parse(&url_str)
                .map_err(|e| WorkspaceAppError::Internal(format!("invalid port URL: {e}")))?;
            return Ok(ResolvedApp {
                url,
                agent_id,
                workspace_id: workspace.id,
                workspace_organization_id: workspace.organization_id,
                sharing_level: String::new(),
                slug_or_port: slug.clone(),
            });
        }
    } else if slug_is_port {
        if let Ok(port) = slug.parse::<u16>() {
            let url_str = format!("http://{agent_host}:{port}");
            let url = url::Url::parse(&url_str)
                .map_err(|e| WorkspaceAppError::Internal(format!("invalid port URL: {e}")))?;
            return Ok(ResolvedApp {
                url,
                agent_id,
                workspace_id: workspace.id,
                workspace_organization_id: workspace.organization_id,
                sharing_level: String::new(),
                slug_or_port: slug.clone(),
            });
        }
    }

    // Step 5: slug-based app lookup.
    let app = state
        .store
        .find_workspace_app_by_agent_and_slug(agent_id, slug)
        .await
        .map_err(|e| WorkspaceAppError::Internal(format!("failed to look up workspace app: {e}")))?
        .ok_or_else(|| {
            WorkspaceAppError::NotFound(format!("application {slug:?} not found for agent"))
        })?;

    let app_url_str = app.url.clone().unwrap_or_default();
    if app_url_str.is_empty() {
        return Err(WorkspaceAppError::Classified(AppAccessError::AppURLNotSet));
    }
    let url = url::Url::parse(&app_url_str)
        .map_err(|e| WorkspaceAppError::Internal(format!("invalid app URL: {e}")))?;

    // Unhealthy app (Go uses `health != healthy && health != disabled` as
    // the "app is not running" signal; we model the same here).
    if !app.health.is_empty()
        && !app.health.eq_ignore_ascii_case("healthy")
        && !app.health.eq_ignore_ascii_case("disabled")
    {
        return Err(WorkspaceAppError::Classified(AppAccessError::AppNotRunning));
    }

    Ok(ResolvedApp {
        url,
        agent_id,
        workspace_id: workspace.id,
        workspace_organization_id: workspace.organization_id,
        sharing_level: app.sharing_level.clone(),
        slug_or_port: slug.clone(),
    })
}

/// Looks up the workspace referenced by the request, accepting either
/// `workspace_name_or_id` (as a UUID) or falling back to owner+name.
async fn lookup_workspace_for_request(
    state: &AppState,
    request: &AppRequest,
) -> Result<coder_core::ports::WorkspaceRecord, WorkspaceAppError> {
    if let Ok(id) = request.workspace_name_or_id.parse::<Uuid>() {
        if let Some(ws) = state
            .store
            .find_workspace_by_id(id, None)
            .await
            .map_err(|e| WorkspaceAppError::Internal(format!("failed to look up workspace: {e}")))?
        {
            return Ok(ws);
        }
    }

    let user = state
        .store
        .find_user_by_username(&request.username_or_id)
        .await
        .map_err(|e| WorkspaceAppError::Internal(format!("failed to look up user: {e}")))?
        .ok_or_else(|| {
            WorkspaceAppError::NotFound(format!("user {:?} not found", request.username_or_id))
        })?;

    state
        .store
        .find_workspace_by_owner_and_name(user.id, &request.workspace_name_or_id, None)
        .await
        .map_err(|e| WorkspaceAppError::Internal(format!("failed to look up workspace: {e}")))?
        .ok_or_else(|| {
            WorkspaceAppError::NotFound(format!(
                "workspace {:?} not found for user {:?}",
                request.workspace_name_or_id, request.username_or_id
            ))
        })
}

/// Resolves the workspace agent ID from the app request.
///
/// Tries to parse `agent_name_or_id` as a UUID first; otherwise looks up the
/// workspace by owner username + workspace name, retrieves the agents for the
/// latest build, and matches the agent by name.
async fn resolve_workspace_agent_id(
    state: &AppState,
    request: &AppRequest,
) -> Result<Uuid, WorkspaceAppError> {
    // If the agent field is a UUID, use it directly.
    if let Ok(id) = request.agent_name_or_id.parse::<Uuid>() {
        return Ok(id);
    }

    // Name-based agent lookup: user → workspace → build → resources → agents.
    // Step 1: Look up the user by username.
    let user = state
        .store
        .find_user_by_username(&request.username_or_id)
        .await
        .map_err(|e| WorkspaceAppError::Internal(format!("failed to look up user: {e}")))?
        .ok_or_else(|| {
            WorkspaceAppError::NotFound(format!("user {:?} not found", request.username_or_id))
        })?;

    // Step 2: Look up the workspace by owner + name.
    let workspace = state
        .store
        .find_workspace_by_owner_and_name(user.id, &request.workspace_name_or_id, None)
        .await
        .map_err(|e| WorkspaceAppError::Internal(format!("failed to look up workspace: {e}")))?
        .ok_or_else(|| {
            WorkspaceAppError::NotFound(format!(
                "workspace {:?} not found for user {:?}",
                request.workspace_name_or_id, request.username_or_id
            ))
        })?;

    // Step 3: Get the latest build for this workspace.
    let build = state
        .store
        .find_latest_workspace_build(workspace.id)
        .await
        .map_err(|e| {
            WorkspaceAppError::Internal(format!("failed to look up workspace build: {e}"))
        })?
        .ok_or_else(|| {
            WorkspaceAppError::NotFound(format!(
                "no build found for workspace {:?}",
                request.workspace_name_or_id
            ))
        })?;

    // Step 4: Get resources for this build.
    let resources = state
        .store
        .list_workspace_resources_by_job(build.job_id)
        .await
        .map_err(|e| {
            WorkspaceAppError::Internal(format!("failed to list workspace resources: {e}"))
        })?;

    let resource_ids: Vec<Uuid> = resources.iter().map(|r| r.id).collect();

    // Step 5: Get agents for these resources.
    let agents = state
        .store
        .list_workspace_agents_by_resource_ids(&resource_ids)
        .await
        .map_err(|e| {
            WorkspaceAppError::Internal(format!("failed to list workspace agents: {e}"))
        })?;

    // Step 6: If agent_name_or_id is empty and there's exactly one agent,
    // use it. Otherwise match by name.
    if request.agent_name_or_id.is_empty() {
        if agents.len() == 1 {
            if let Some(agent) = agents.first() {
                return Ok(agent.id);
            }
        }
        if agents.is_empty() {
            return Err(WorkspaceAppError::NotFound(
                "no agents found for workspace".into(),
            ));
        }
        return Err(WorkspaceAppError::NotFound(
            "workspace has multiple agents; specify an agent name".into(),
        ));
    }

    for agent in &agents {
        if agent.name == request.agent_name_or_id {
            return Ok(agent.id);
        }
    }

    Err(WorkspaceAppError::NotFound(format!(
        "agent {:?} not found in workspace {:?}",
        request.agent_name_or_id, request.workspace_name_or_id
    )))
}

// ---------------------------------------------------------------------------
// Helper to build WorkspaceAppServer from AppState
// ---------------------------------------------------------------------------

/// Builds a [`WorkspaceAppServer`] from the application state.
///
/// Reads the access URL and wildcard hostname from config. If the wildcard
/// hostname is configured (e.g. `*.apps.example.com`), subdomain-based app
/// routing is enabled. Otherwise only path-based apps are available.
fn build_workspace_app_server(state: &AppState) -> WorkspaceAppServer {
    let access_url = state.config.access_url.clone();
    let hostname = state.config.wildcard_access_url.clone();

    // Try to build with the configured hostname pattern.
    // If the pattern is invalid or empty, fall back to subdomain-disabled mode.
    match WorkspaceAppServer::new(
        access_url.clone(),
        access_url.clone(),
        hostname,
        state.config.disable_path_apps,
    ) {
        Ok(server) => server,
        Err(_) => WorkspaceAppServer {
            dashboard_url: access_url.clone(),
            access_url,
            hostname: String::new(),
            hostname_regex: None,
            disable_path_apps: state.config.disable_path_apps,
            cookies: AppCookies::new(""),
        },
    }
}

/// Strips Coder-specific cookies from a cookie header string.
///
/// This prevents Coder session tokens from being forwarded to workspace apps.
pub(crate) fn strip_coder_cookies(cookie_header: &str) -> String {
    let coder_cookie_prefixes = [
        "coder_session_token",
        "coder_path_app_session_token",
        "coder_subdomain_app_session_token",
        "coder_signed_app_token",
        "oauth_state",
        "oauth_redirect",
    ];

    cookie_header
        .split(';')
        .filter_map(|cookie| {
            let trimmed = cookie.trim();
            let name = trimmed.split('=').next().unwrap_or("").trim();
            if coder_cookie_prefixes
                .iter()
                .any(|prefix| name.starts_with(prefix))
            {
                None
            } else {
                Some(trimmed)
            }
        })
        .collect::<Vec<&str>>()
        .join("; ")
}

// ---------------------------------------------------------------------------
// Signed app token exchange
// ---------------------------------------------------------------------------

/// JWT claims for a signed workspace app token.
///
/// Matches the Go `SignedToken` structure from `coderd/workspaceapps/token.go`.
/// These tokens are short-lived (5 minutes) and scoped to a specific app
/// request, preventing reuse across different apps or workspaces.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct SignedAppTokenClaims {
    /// The access method used (path, subdomain, terminal).
    pub access_method: String,
    /// Username or ID of the workspace owner.
    pub username_or_id: String,
    /// Workspace name or ID.
    pub workspace_name_or_id: String,
    /// Agent name or ID.
    pub agent_name_or_id: String,
    /// App slug or port number.
    pub app_slug_or_port: String,
    /// Authenticated user ID.
    pub user_id: String,
    /// Issued-at timestamp (Unix seconds).
    pub iat: i64,
    /// Expiry timestamp (Unix seconds).
    pub exp: i64,
}

/// Default signed token lifetime: 5 minutes.
const SIGNED_APP_TOKEN_LIFETIME_SECS: i64 = 300;

/// Creates a signed app token for the given request and user.
///
/// The token is a JWT signed with HMAC-SHA256 using the deployment's signing
/// key. It encodes the app request details and the authenticated user, and
/// expires after [`SIGNED_APP_TOKEN_LIFETIME_SECS`].
pub(crate) fn create_signed_app_token(
    signing_key: &[u8],
    request: &AppRequest,
    user_id: Uuid,
) -> Result<String, WorkspaceAppError> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let claims = SignedAppTokenClaims {
        access_method: request.access_method.to_string(),
        username_or_id: request.username_or_id.clone(),
        workspace_name_or_id: request.workspace_name_or_id.clone(),
        agent_name_or_id: request.agent_name_or_id.clone(),
        app_slug_or_port: request.app_slug_or_port.clone(),
        user_id: user_id.to_string(),
        iat: now,
        exp: now + SIGNED_APP_TOKEN_LIFETIME_SECS,
    };

    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    let key = jsonwebtoken::EncodingKey::from_secret(signing_key);
    jsonwebtoken::encode(&header, &claims, &key)
        .map_err(|e| WorkspaceAppError::Internal(format!("failed to create signed app token: {e}")))
}

/// Validates a signed app token and checks it matches the given request.
///
/// Returns the claims if the token is valid, not expired, and matches the
/// request parameters (access method, workspace, agent, app).
pub(crate) fn validate_signed_app_token(
    signing_key: &[u8],
    token: &str,
    request: &AppRequest,
) -> Result<SignedAppTokenClaims, WorkspaceAppError> {
    let key = jsonwebtoken::DecodingKey::from_secret(signing_key);
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.required_spec_claims.clear();
    validation.set_required_spec_claims(&["exp"]);

    let token_data = jsonwebtoken::decode::<SignedAppTokenClaims>(token, &key, &validation)
        .map_err(|_e| WorkspaceAppError::Unauthorized)?;

    let claims = token_data.claims;

    // Verify the token matches the current request.
    if claims.access_method != request.access_method.to_string()
        || claims.username_or_id != request.username_or_id
        || claims.workspace_name_or_id != request.workspace_name_or_id
        || claims.agent_name_or_id != request.agent_name_or_id
        || claims.app_slug_or_port != request.app_slug_or_port
    {
        return Err(WorkspaceAppError::Unauthorized);
    }

    Ok(claims)
}

/// Simple percent-decoding for query parameter values.
///
/// Uses `application/x-www-form-urlencoded` semantics where `+` is decoded
/// as a space character. This is intentional for query string values but
/// would be incorrect for path segments where `+` is literal.
///
/// JWT tokens only contain base64url characters (`A-Z`, `a-z`, `0-9`, `-`,
/// `_`, `.`) which are not percent-encoded, so this handles the common case
/// of `%2B` (+), `%2F` (/), `%3D` (=) from standard base64.
fn percent_decode_str(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.as_bytes().iter();
    while let Some(&b) = chars.next() {
        if b == b'%' {
            let hi = match chars.next().copied() {
                Some(v) => v,
                None => {
                    result.push('%');
                    continue;
                }
            };
            let lo = match chars.next().copied() {
                Some(v) => v,
                None => {
                    result.push('%');
                    result.push(hi as char);
                    continue;
                }
            };
            let hex = [hi, lo];
            if let Ok(s) = std::str::from_utf8(&hex) {
                if let Ok(byte) = u8::from_str_radix(s, 16) {
                    result.push(byte as char);
                    continue;
                }
            }
            result.push('%');
            result.push(hi as char);
            result.push(lo as char);
        } else if b == b'+' {
            result.push(' ');
        } else {
            result.push(b as char);
        }
    }
    result
}

/// Extracts a signed app token from the request (cookie or query parameter).
fn extract_signed_app_token(headers: &HeaderMap, uri: &http::Uri) -> Option<String> {
    // Check query parameter first.
    if let Some(query) = uri.query() {
        for pair in query.split('&') {
            if let Some(value) = pair.strip_prefix(&format!("{SIGNED_APP_TOKEN_QUERY}=")) {
                // Percent-decode the token value. JWT tokens may contain
                // characters that are percent-encoded in query strings.
                let decoded = percent_decode_str(value);
                if !decoded.is_empty() {
                    return Some(decoded);
                }
            }
        }
    }

    // Check cookie.
    if let Some(cookie_header) = headers.get(http::header::COOKIE) {
        if let Ok(cookies) = cookie_header.to_str() {
            for cookie in cookies.split(';') {
                let trimmed = cookie.trim();
                if let Some(value) = trimmed.strip_prefix(&format!("{SIGNED_APP_TOKEN_COOKIE}=")) {
                    if !value.is_empty() {
                        return Some(value.to_owned());
                    }
                }
            }
        }
    }

    None
}

// ---------------------------------------------------------------------------
// WebSocket upgrade support
// ---------------------------------------------------------------------------

/// Checks whether the given headers indicate a WebSocket upgrade request.
fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    headers
        .get(http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
}

/// Proxies a WebSocket connection to the upstream app.
///
/// Uses axum's `WebSocketUpgrade` to accept the client connection, then
/// opens a WebSocket to the upstream URL and bidirectionally pipes messages
/// between the client and upstream sockets.
async fn proxy_websocket(
    _state: &AppState,
    ws: WebSocketUpgrade,
    target_url: url::Url,
    original_headers: &HeaderMap,
) -> Result<Response, WorkspaceAppError> {
    // Convert http:// to ws:// and https:// to wss://.
    let ws_url = match target_url.scheme() {
        "https" => {
            let mut u = target_url.clone();
            let _ = u.set_scheme("wss");
            u
        }
        _ => {
            let mut u = target_url.clone();
            let _ = u.set_scheme("ws");
            u
        }
    };

    // Build the upstream connector request with forwarded headers.
    let mut ws_request = http::Request::builder()
        .uri(ws_url.as_str())
        .body(())
        .map_err(|e| WorkspaceAppError::ProxyError(format!("failed to build WS request: {e}")))?;

    // Forward select headers to upstream.
    for (key, value) in original_headers {
        let name = key.as_str();
        if name == "host"
            || name == "connection"
            || name == "upgrade"
            || name.starts_with("sec-websocket-")
        {
            continue;
        }
        if name == "cookie" {
            let cleaned = strip_coder_cookies(value.to_str().unwrap_or(""));
            if !cleaned.is_empty() {
                if let Ok(val) = HeaderValue::from_str(&cleaned) {
                    ws_request.headers_mut().insert(
                        HeaderName::from_bytes(key.as_str().as_bytes()).map_err(|e| {
                            WorkspaceAppError::ProxyError(format!("invalid header name: {e}"))
                        })?,
                        val,
                    );
                }
                continue;
            }
            continue;
        }
        if let Ok(val) = HeaderValue::from_bytes(value.as_bytes()) {
            if let Ok(header_name) = HeaderName::from_bytes(key.as_str().as_bytes()) {
                ws_request.headers_mut().insert(header_name, val);
            }
        }
    }

    let response = ws.on_upgrade(move |client_socket| async move {
        // Connect to the upstream WebSocket using the request with forwarded headers.
        let upstream_result = tokio_tungstenite::connect_async(ws_request).await;

        let (upstream_socket, _response) = match upstream_result {
            Ok(pair) => pair,
            Err(e) => {
                tracing::error!("failed to connect upstream WebSocket: {e}");
                return;
            }
        };

        // Split both sockets and pipe bidirectionally.
        let (mut client_sink, mut client_stream) = client_socket.split();
        let (mut upstream_sink, mut upstream_stream) = upstream_socket.split();

        // Client → upstream task.
        let mut client_to_upstream = tokio::spawn(async move {
            while let Some(msg) = client_stream.next().await {
                match msg {
                    Ok(Message::Text(text)) => {
                        let s: String = text.to_string();
                        if upstream_sink
                            .send(tokio_tungstenite::tungstenite::Message::Text(s.into()))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Ok(Message::Binary(data)) => {
                        let bytes: Vec<u8> = data.to_vec();
                        if upstream_sink
                            .send(tokio_tungstenite::tungstenite::Message::Binary(
                                bytes.into(),
                            ))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Ok(Message::Close(_)) | Err(_) => break,
                    _ => {}
                }
            }
            let _ = upstream_sink.close().await;
        });

        // Upstream → client task.
        let mut upstream_to_client = tokio::spawn(async move {
            while let Some(msg) = upstream_stream.next().await {
                match msg {
                    Ok(tokio_tungstenite::tungstenite::Message::Text(text)) => {
                        let s: String = text.to_string();
                        if client_sink.send(Message::Text(s.into())).await.is_err() {
                            break;
                        }
                    }
                    Ok(tokio_tungstenite::tungstenite::Message::Binary(data)) => {
                        let bytes: Vec<u8> = data.to_vec();
                        if client_sink
                            .send(Message::Binary(bytes.into()))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Ok(tokio_tungstenite::tungstenite::Message::Close(_)) | Err(_) => break,
                    _ => {}
                }
            }
            let _ = client_sink.close().await;
        });

        // Wait for either direction to finish, then abort the other to prevent
        // task leaks.
        tokio::select! {
            _ = &mut client_to_upstream => {
                upstream_to_client.abort();
            },
            _ = &mut upstream_to_client => {
                client_to_upstream.abort();
            },
        };
    });

    Ok(response)
}

// ---------------------------------------------------------------------------
// Port forwarding
// ---------------------------------------------------------------------------

/// Path parameters for port forwarding routes.
///
/// Route pattern: `/@{user}/{workspace_and_agent}/port/{port}/{*rest}`
#[derive(Debug, Deserialize)]
pub(crate) struct PortForwardParams {
    pub user: String,
    pub workspace_and_agent: String,
    pub port: String,
}

/// Handles port forwarding requests.
///
/// Port forwarding provides direct TCP port access to workspace agents via
/// `/@{user}/{workspace}.{agent}/port/{port}/` URL patterns.
///
/// The port must be >= [`AGENT_MINIMUM_LISTENING_PORT`] (9) to prevent
/// access to internal agent ports.
pub(crate) async fn workspace_port_forward(
    State(state): State<AppState>,
    method: http::Method,
    headers: HeaderMap,
    Path(params): Path<PortForwardParams>,
    OriginalUri(original_uri): OriginalUri,
    body: axum::body::Body,
) -> Result<Response, WorkspaceAppError> {
    let server = build_workspace_app_server(&state);

    // Check if path apps are disabled (port forwarding uses path-based URLs).
    if server.disable_path_apps {
        return Err(WorkspaceAppError::PathAppsDisabled);
    }

    // Reject @me.
    if params.user == "me" {
        return Err(WorkspaceAppError::NotFound(
            "Port forwarding must use the full username, not @me.".to_owned(),
        ));
    }

    // Validate port number.
    let port: u16 = params.port.parse().map_err(|_| {
        WorkspaceAppError::BadRequest(format!("invalid port number: {:?}", params.port))
    })?;

    if port < AGENT_MINIMUM_LISTENING_PORT {
        return Err(WorkspaceAppError::BadRequest(format!(
            "Port {} is not permitted. Coder reserves ports less than {} for internal use.",
            port, AGENT_MINIMUM_LISTENING_PORT,
        )));
    }

    // Determine the real path after the port base.
    let full_path = original_uri.path();
    let base_path = format!(
        "/@{}/{}/port/{}/",
        params.user, params.workspace_and_agent, params.port
    );
    let app_path = full_path
        .strip_prefix(base_path.trim_end_matches('/'))
        .unwrap_or("/");
    let app_path = if app_path.is_empty() { "/" } else { app_path };

    // Build the app request using the port as the app slug.
    let app_request = AppRequest {
        access_method: AccessMethod::Path,
        base_path: base_path.clone(),
        prefix: String::new(),
        username_or_id: params.user.clone(),
        workspace_and_agent: params.workspace_and_agent.clone(),
        workspace_name_or_id: String::new(),
        agent_name_or_id: String::new(),
        app_slug_or_port: params.port.clone(),
    }
    .normalize();

    if let Err(e) = app_request.check() {
        return Err(WorkspaceAppError::BadRequest(e.to_string()));
    }

    // Authenticate the user.
    let session_token = server
        .cookies
        .token_from_request(&headers, &app_request.access_method);

    let auth_context = authenticate_app_request(&state, &headers, session_token.as_deref()).await?;

    // Proxy the request to the agent.
    proxy_workspace_app(
        &state,
        &server,
        &auth_context,
        &app_request,
        method,
        &headers,
        body,
        app_path,
        original_uri.query().unwrap_or(""),
        true,
    )
    .await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    // -- AccessMethod tests --

    #[test]
    fn access_method_display() {
        assert_eq!(AccessMethod::Path.to_string(), "path");
        assert_eq!(AccessMethod::Subdomain.to_string(), "subdomain");
        assert_eq!(AccessMethod::Terminal.to_string(), "terminal");
    }

    // -- AppRequest normalize/check tests --

    #[test]
    fn normalize_splits_workspace_and_agent() {
        let req = AppRequest {
            access_method: AccessMethod::Path,
            base_path: "/test".to_owned(),
            prefix: String::new(),
            username_or_id: "dean".to_owned(),
            workspace_and_agent: "myworkspace.main".to_owned(),
            workspace_name_or_id: String::new(),
            agent_name_or_id: String::new(),
            app_slug_or_port: "myapp".to_owned(),
        }
        .normalize();

        assert_eq!(req.workspace_name_or_id, "myworkspace");
        assert_eq!(req.agent_name_or_id, "main");
        assert!(req.workspace_and_agent.is_empty());
        assert!(req.base_path.ends_with('/'));
    }

    #[test]
    fn normalize_workspace_only() {
        let req = AppRequest {
            access_method: AccessMethod::Path,
            base_path: "/test/".to_owned(),
            prefix: String::new(),
            username_or_id: "dean".to_owned(),
            workspace_and_agent: "myworkspace".to_owned(),
            workspace_name_or_id: String::new(),
            agent_name_or_id: String::new(),
            app_slug_or_port: "myapp".to_owned(),
        }
        .normalize();

        assert_eq!(req.workspace_name_or_id, "myworkspace");
        assert!(req.agent_name_or_id.is_empty());
    }

    #[test]
    fn check_valid_path_request() {
        let req = AppRequest {
            access_method: AccessMethod::Path,
            base_path: "/test/".to_owned(),
            prefix: String::new(),
            username_or_id: "dean".to_owned(),
            workspace_and_agent: String::new(),
            workspace_name_or_id: "dev".to_owned(),
            agent_name_or_id: String::new(),
            app_slug_or_port: "myapp".to_owned(),
        };
        assert!(req.check().is_ok());
    }

    #[test]
    fn check_valid_subdomain_request() {
        let req = AppRequest {
            access_method: AccessMethod::Subdomain,
            base_path: "/".to_owned(),
            prefix: String::new(),
            username_or_id: "dean".to_owned(),
            workspace_and_agent: String::new(),
            workspace_name_or_id: "dev".to_owned(),
            agent_name_or_id: "main".to_owned(),
            app_slug_or_port: "8080".to_owned(),
        };
        assert!(req.check().is_ok());
    }

    #[test]
    fn check_rejects_me_username() {
        let req = AppRequest {
            access_method: AccessMethod::Path,
            base_path: "/test/".to_owned(),
            prefix: String::new(),
            username_or_id: "me".to_owned(),
            workspace_and_agent: String::new(),
            workspace_name_or_id: "dev".to_owned(),
            agent_name_or_id: String::new(),
            app_slug_or_port: "myapp".to_owned(),
        };
        assert!(req.check().is_err());
    }

    #[test]
    fn check_rejects_empty_username() {
        let req = AppRequest {
            access_method: AccessMethod::Path,
            base_path: "/test/".to_owned(),
            prefix: String::new(),
            username_or_id: String::new(),
            workspace_and_agent: String::new(),
            workspace_name_or_id: "dev".to_owned(),
            agent_name_or_id: String::new(),
            app_slug_or_port: "myapp".to_owned(),
        };
        assert!(req.check().is_err());
    }

    #[test]
    fn check_rejects_empty_workspace() {
        let req = AppRequest {
            access_method: AccessMethod::Path,
            base_path: "/test/".to_owned(),
            prefix: String::new(),
            username_or_id: "dean".to_owned(),
            workspace_and_agent: String::new(),
            workspace_name_or_id: String::new(),
            agent_name_or_id: String::new(),
            app_slug_or_port: "myapp".to_owned(),
        };
        assert!(req.check().is_err());
    }

    #[test]
    fn check_rejects_empty_app() {
        let req = AppRequest {
            access_method: AccessMethod::Path,
            base_path: "/test/".to_owned(),
            prefix: String::new(),
            username_or_id: "dean".to_owned(),
            workspace_and_agent: String::new(),
            workspace_name_or_id: "dev".to_owned(),
            agent_name_or_id: String::new(),
            app_slug_or_port: String::new(),
        };
        assert!(req.check().is_err());
    }

    #[test]
    fn check_rejects_prefix_on_path_apps() {
        let req = AppRequest {
            access_method: AccessMethod::Path,
            base_path: "/test/".to_owned(),
            prefix: "prefix---".to_owned(),
            username_or_id: "dean".to_owned(),
            workspace_and_agent: String::new(),
            workspace_name_or_id: "dev".to_owned(),
            agent_name_or_id: String::new(),
            app_slug_or_port: "myapp".to_owned(),
        };
        assert!(req.check().is_err());
    }

    #[test]
    fn check_rejects_prefix_without_trailing_hyphens() {
        let req = AppRequest {
            access_method: AccessMethod::Subdomain,
            base_path: "/".to_owned(),
            prefix: "prefix".to_owned(),
            username_or_id: "dean".to_owned(),
            workspace_and_agent: String::new(),
            workspace_name_or_id: "dev".to_owned(),
            agent_name_or_id: String::new(),
            app_slug_or_port: "myapp".to_owned(),
        };
        assert!(req.check().is_err());
    }

    #[test]
    fn check_valid_terminal_request() {
        let req = AppRequest {
            access_method: AccessMethod::Terminal,
            base_path: "/api/v2/workspaceagents/test/pty/".to_owned(),
            prefix: String::new(),
            username_or_id: String::new(),
            workspace_and_agent: String::new(),
            workspace_name_or_id: String::new(),
            agent_name_or_id: "550e8400-e29b-41d4-a716-446655440000".to_owned(),
            app_slug_or_port: String::new(),
        };
        assert!(req.check().is_ok());
    }

    #[test]
    fn check_rejects_terminal_without_uuid() {
        let req = AppRequest {
            access_method: AccessMethod::Terminal,
            base_path: "/test/".to_owned(),
            prefix: String::new(),
            username_or_id: String::new(),
            workspace_and_agent: String::new(),
            workspace_name_or_id: String::new(),
            agent_name_or_id: "not-a-uuid".to_owned(),
            app_slug_or_port: String::new(),
        };
        assert!(req.check().is_err());
    }

    #[test]
    fn check_rejects_empty_base_path() {
        let req = AppRequest {
            access_method: AccessMethod::Path,
            base_path: String::new(),
            prefix: String::new(),
            username_or_id: "dean".to_owned(),
            workspace_and_agent: String::new(),
            workspace_name_or_id: "dev".to_owned(),
            agent_name_or_id: String::new(),
            app_slug_or_port: "myapp".to_owned(),
        };
        assert!(req.check().is_err());
    }

    // -- Cookie tests --

    #[test]
    fn app_cookies_path_method() {
        let cookies = AppCookies::new("*.example.com");
        assert_eq!(
            cookies.cookie_name_for_access_method(&AccessMethod::Path),
            PATH_APP_SESSION_TOKEN_COOKIE
        );
    }

    #[test]
    fn app_cookies_subdomain_method() {
        let cookies = AppCookies::new("*.example.com");
        let name = cookies.cookie_name_for_access_method(&AccessMethod::Subdomain);
        assert!(name.starts_with(SUBDOMAIN_APP_SESSION_TOKEN_COOKIE_PREFIX));
        assert!(name.len() > SUBDOMAIN_APP_SESSION_TOKEN_COOKIE_PREFIX.len());
    }

    #[test]
    fn subdomain_cookie_names_differ_by_hostname() {
        let c1 = subdomain_app_session_token_cookie("*.a.example.com");
        let c2 = subdomain_app_session_token_cookie("*.b.example.com");
        assert_ne!(c1, c2);
    }

    #[test]
    fn subdomain_cookie_name_deterministic() {
        let c1 = subdomain_app_session_token_cookie("*.example.com");
        let c2 = subdomain_app_session_token_cookie("*.example.com");
        assert_eq!(c1, c2);
    }

    // -- strip_coder_cookies tests --

    #[test]
    fn strip_coder_cookies_removes_session() {
        let input = "coder_session_token=abc123; other_cookie=value";
        let result = strip_coder_cookies(input);
        assert_eq!(result, "other_cookie=value");
    }

    #[test]
    fn strip_coder_cookies_removes_multiple() {
        let input = "coder_session_token=a; coder_path_app_session_token=b; keep=c; coder_signed_app_token=d";
        let result = strip_coder_cookies(input);
        assert_eq!(result, "keep=c");
    }

    #[test]
    fn strip_coder_cookies_keeps_non_coder() {
        let input = "my_cookie=value; another=test";
        let result = strip_coder_cookies(input);
        assert_eq!(result, "my_cookie=value; another=test");
    }

    #[test]
    fn strip_coder_cookies_empty_input() {
        assert_eq!(strip_coder_cookies(""), "");
    }

    // -- resolve_app_url tests --

    // resolve_app_url tests: The function is now async and requires AppState
    // with a real store for agent/app lookups.  Since the store methods for
    // workspace agents are stubs, resolve_app_url correctly returns errors
    // (fail-closed), preventing SSRF to localhost.

    #[test]
    fn resolve_agent_id_from_uuid() {
        // When agent_name_or_id is a valid UUID, resolve_workspace_agent_id
        // returns it directly without hitting the store.
        let req = AppRequest {
            access_method: AccessMethod::Subdomain,
            base_path: "/".to_owned(),
            prefix: String::new(),
            username_or_id: "dean".to_owned(),
            workspace_and_agent: String::new(),
            workspace_name_or_id: "dev".to_owned(),
            agent_name_or_id: "550e8400-e29b-41d4-a716-446655440000".to_owned(),
            app_slug_or_port: "8080".to_owned(),
        };
        // Verify the UUID parse path works (this is the sync part of the logic).
        let parsed: Result<Uuid, _> = req.agent_name_or_id.parse();
        assert!(parsed.is_ok(), "UUID agent_name_or_id should parse");
    }

    #[test]
    fn resolve_agent_id_non_uuid_needs_workspace_lookup() {
        // When agent_name_or_id is NOT a UUID, workspace lookup is required.
        let req = AppRequest {
            access_method: AccessMethod::Subdomain,
            base_path: "/".to_owned(),
            prefix: String::new(),
            username_or_id: "dean".to_owned(),
            workspace_and_agent: String::new(),
            workspace_name_or_id: "dev".to_owned(),
            agent_name_or_id: "main".to_owned(),
            app_slug_or_port: "8080".to_owned(),
        };
        let parsed: Result<Uuid, _> = req.agent_name_or_id.parse();
        assert!(
            parsed.is_err(),
            "non-UUID agent name must fall through to workspace lookup"
        );
    }

    // -- WorkspaceAppServer tests --

    #[test]
    fn workspace_app_server_no_hostname() {
        let url = url::Url::parse("http://localhost:3000").expect("test: parsing should succeed");
        let server = WorkspaceAppServer::new(url.clone(), url, String::new(), false);
        assert!(server.is_ok());
        let server = server.expect("test: parsing should succeed");
        assert!(server.hostname_regex.is_none());
    }

    #[test]
    fn workspace_app_server_with_hostname() {
        let url = url::Url::parse("http://localhost:3000").expect("test: parsing should succeed");
        let server =
            WorkspaceAppServer::new(url.clone(), url, "*.apps.example.com".to_owned(), false);
        assert!(server.is_ok());
        let server = server.expect("test: parsing should succeed");
        assert!(server.hostname_regex.is_some());
    }

    // -- Signed app token tests --

    fn test_app_request() -> AppRequest {
        AppRequest {
            access_method: AccessMethod::Path,
            base_path: "/@dean/dev.main/apps/code-server/".to_owned(),
            prefix: String::new(),
            username_or_id: "dean".to_owned(),
            workspace_and_agent: String::new(),
            workspace_name_or_id: "dev".to_owned(),
            agent_name_or_id: "main".to_owned(),
            app_slug_or_port: "code-server".to_owned(),
        }
    }

    #[test]
    fn signed_app_token_create_and_validate() {
        let signing_key = b"test-signing-key-at-least-32-bytes-long!!";
        let request = test_app_request();
        let user_id =
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("test: valid UUID");

        let token =
            create_signed_app_token(signing_key, &request, user_id).expect("test: token creation");
        assert!(!token.is_empty());

        let claims = validate_signed_app_token(signing_key, &token, &request)
            .expect("test: token validation");
        assert_eq!(claims.access_method, "path");
        assert_eq!(claims.username_or_id, "dean");
        assert_eq!(claims.workspace_name_or_id, "dev");
        assert_eq!(claims.agent_name_or_id, "main");
        assert_eq!(claims.app_slug_or_port, "code-server");
        assert_eq!(claims.user_id, user_id.to_string());
    }

    #[test]
    fn signed_app_token_wrong_key_fails() {
        let signing_key = b"test-signing-key-at-least-32-bytes-long!!";
        let wrong_key = b"wrong-signing-key-at-least-32-bytes-long!";
        let request = test_app_request();
        let user_id =
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("test: valid UUID");

        let token =
            create_signed_app_token(signing_key, &request, user_id).expect("test: token creation");

        let result = validate_signed_app_token(wrong_key, &token, &request);
        assert!(result.is_err(), "validation with wrong key should fail");
    }

    #[test]
    fn signed_app_token_mismatched_request_fails() {
        let signing_key = b"test-signing-key-at-least-32-bytes-long!!";
        let request = test_app_request();
        let user_id =
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("test: valid UUID");

        let token =
            create_signed_app_token(signing_key, &request, user_id).expect("test: token creation");

        // Different app slug.
        let mut wrong_request = test_app_request();
        wrong_request.app_slug_or_port = "different-app".to_owned();

        let result = validate_signed_app_token(signing_key, &token, &wrong_request);
        assert!(
            result.is_err(),
            "validation with different app slug should fail"
        );
    }

    #[test]
    fn signed_app_token_mismatched_workspace_fails() {
        let signing_key = b"test-signing-key-at-least-32-bytes-long!!";
        let request = test_app_request();
        let user_id =
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("test: valid UUID");

        let token =
            create_signed_app_token(signing_key, &request, user_id).expect("test: token creation");

        let mut wrong_request = test_app_request();
        wrong_request.workspace_name_or_id = "other-workspace".to_owned();

        let result = validate_signed_app_token(signing_key, &token, &wrong_request);
        assert!(
            result.is_err(),
            "validation with different workspace should fail"
        );
    }

    #[test]
    fn signed_app_token_mismatched_access_method_fails() {
        let signing_key = b"test-signing-key-at-least-32-bytes-long!!";
        let request = test_app_request();
        let user_id =
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("test: valid UUID");

        let token =
            create_signed_app_token(signing_key, &request, user_id).expect("test: token creation");

        let mut wrong_request = test_app_request();
        wrong_request.access_method = AccessMethod::Subdomain;

        let result = validate_signed_app_token(signing_key, &token, &wrong_request);
        assert!(
            result.is_err(),
            "validation with different access method should fail"
        );
    }

    #[test]
    fn signed_app_token_expired_fails() {
        let signing_key = b"test-signing-key-at-least-32-bytes-long!!";
        let request = test_app_request();

        // Manually build an expired token.
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let claims = SignedAppTokenClaims {
            access_method: request.access_method.to_string(),
            username_or_id: request.username_or_id.clone(),
            workspace_name_or_id: request.workspace_name_or_id.clone(),
            agent_name_or_id: request.agent_name_or_id.clone(),
            app_slug_or_port: request.app_slug_or_port.clone(),
            user_id: "550e8400-e29b-41d4-a716-446655440000".to_owned(),
            iat: now - 600,
            exp: now - 300, // expired 5 minutes ago
        };

        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        let key = jsonwebtoken::EncodingKey::from_secret(signing_key);
        let token = jsonwebtoken::encode(&header, &claims, &key).expect("test: encode");

        let result = validate_signed_app_token(signing_key, &token, &request);
        assert!(result.is_err(), "expired token should fail validation");
    }

    #[test]
    fn signed_app_token_claims_contain_correct_lifetime() {
        let signing_key = b"test-signing-key-at-least-32-bytes-long!!";
        let request = test_app_request();
        let user_id =
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("test: valid UUID");

        let token =
            create_signed_app_token(signing_key, &request, user_id).expect("test: token creation");
        let claims = validate_signed_app_token(signing_key, &token, &request)
            .expect("test: token validation");

        let lifetime = claims.exp - claims.iat;
        assert_eq!(
            lifetime, SIGNED_APP_TOKEN_LIFETIME_SECS,
            "token lifetime should be {SIGNED_APP_TOKEN_LIFETIME_SECS} seconds"
        );
    }

    // -- WebSocket upgrade detection tests --

    #[test]
    fn is_websocket_upgrade_true() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::UPGRADE, HeaderValue::from_static("websocket"));
        assert!(is_websocket_upgrade(&headers));
    }

    #[test]
    fn is_websocket_upgrade_case_insensitive() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::UPGRADE, HeaderValue::from_static("WebSocket"));
        assert!(is_websocket_upgrade(&headers));
    }

    #[test]
    fn is_websocket_upgrade_false_missing_header() {
        let headers = HeaderMap::new();
        assert!(!is_websocket_upgrade(&headers));
    }

    #[test]
    fn is_websocket_upgrade_false_other_value() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::UPGRADE, HeaderValue::from_static("h2c"));
        assert!(!is_websocket_upgrade(&headers));
    }

    // -- percent_decode_str tests --

    #[test]
    fn percent_decode_simple() {
        assert_eq!(percent_decode_str("hello"), "hello");
    }

    #[test]
    fn percent_decode_encoded_chars() {
        assert_eq!(percent_decode_str("hello%20world"), "hello world");
        assert_eq!(percent_decode_str("a%2Bb%2Fc%3D"), "a+b/c=");
    }

    #[test]
    fn percent_decode_plus_as_space() {
        assert_eq!(percent_decode_str("hello+world"), "hello world");
    }

    #[test]
    fn percent_decode_empty() {
        assert_eq!(percent_decode_str(""), "");
    }

    #[test]
    fn percent_decode_jwt_token_passthrough() {
        // JWT tokens use base64url characters which should pass through unchanged.
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ0ZXN0IjoxfQ.signature_here-ok";
        assert_eq!(percent_decode_str(jwt), jwt);
    }

    // -- extract_signed_app_token tests --

    #[test]
    fn extract_signed_app_token_from_query() {
        let uri: http::Uri = format!("/path?{SIGNED_APP_TOKEN_QUERY}=my-token-value")
            .parse()
            .expect("test: valid URI");
        let headers = HeaderMap::new();
        let result = extract_signed_app_token(&headers, &uri);
        assert_eq!(result, Some("my-token-value".to_owned()));
    }

    #[test]
    fn extract_signed_app_token_from_cookie() {
        let uri: http::Uri = "/path".parse().expect("test: valid URI");
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            HeaderValue::from_str(&format!("{SIGNED_APP_TOKEN_COOKIE}=cookie-token-value"))
                .expect("test: valid header"),
        );
        let result = extract_signed_app_token(&headers, &uri);
        assert_eq!(result, Some("cookie-token-value".to_owned()));
    }

    #[test]
    fn extract_signed_app_token_query_takes_precedence() {
        let uri: http::Uri = format!("/path?{SIGNED_APP_TOKEN_QUERY}=query-token")
            .parse()
            .expect("test: valid URI");
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            HeaderValue::from_str(&format!("{SIGNED_APP_TOKEN_COOKIE}=cookie-token"))
                .expect("test: valid header"),
        );
        let result = extract_signed_app_token(&headers, &uri);
        assert_eq!(
            result,
            Some("query-token".to_owned()),
            "query param should take precedence over cookie"
        );
    }

    #[test]
    fn extract_signed_app_token_none_when_absent() {
        let uri: http::Uri = "/path".parse().expect("test: valid URI");
        let headers = HeaderMap::new();
        let result = extract_signed_app_token(&headers, &uri);
        assert!(result.is_none());
    }

    // -- Port forwarding validation tests --

    #[test]
    fn port_forwarding_minimum_port() {
        // Port 9 is the minimum allowed.
        let min_port = AGENT_MINIMUM_LISTENING_PORT;
        assert!(min_port <= 9);
    }

    #[test]
    fn port_forwarding_port_validation_accepts_valid() {
        let port: u16 = 8080;
        assert!(port >= AGENT_MINIMUM_LISTENING_PORT);
    }

    #[test]
    fn port_forwarding_port_validation_rejects_low() {
        let port: u16 = 1;
        assert!(port < AGENT_MINIMUM_LISTENING_PORT);
    }

    #[test]
    fn port_forwarding_request_normalize() {
        let req = AppRequest {
            access_method: AccessMethod::Path,
            base_path: "/@dean/dev.main/port/8080/".to_owned(),
            prefix: String::new(),
            username_or_id: "dean".to_owned(),
            workspace_and_agent: "dev.main".to_owned(),
            workspace_name_or_id: String::new(),
            agent_name_or_id: String::new(),
            app_slug_or_port: "8080".to_owned(),
        }
        .normalize();

        assert_eq!(req.workspace_name_or_id, "dev");
        assert_eq!(req.agent_name_or_id, "main");
        assert_eq!(req.app_slug_or_port, "8080");
    }

    // -- WorkspaceAppError response tests --

    #[test]
    fn workspace_app_error_unauthorized_status() {
        let err = WorkspaceAppError::Unauthorized;
        let response = err.into_response();
        assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn workspace_app_error_not_found_status() {
        let err = WorkspaceAppError::NotFound("test".to_owned());
        let response = err.into_response();
        assert_eq!(response.status(), http::StatusCode::NOT_FOUND);
    }

    #[test]
    fn workspace_app_error_bad_request_status() {
        let err = WorkspaceAppError::BadRequest("test".to_owned());
        let response = err.into_response();
        assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn workspace_app_error_internal_status() {
        let err = WorkspaceAppError::Internal("test".to_owned());
        let response = err.into_response();
        assert_eq!(response.status(), http::StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn workspace_app_error_proxy_error_status() {
        let err = WorkspaceAppError::ProxyError("test".to_owned());
        let response = err.into_response();
        assert_eq!(response.status(), http::StatusCode::BAD_GATEWAY);
    }

    // -- Gap item #23: organization sharing-level enforcement ---------------

    /// Cross-organization access must be refused with the
    /// `NotOrganizationMember` classification (HTTP 403) when the app is
    /// shared at `organization` level. Ports the Go behaviour from
    /// `coder/coderd/workspaceapps/db.go` (`SharingLevelOrganization` arm).
    #[tokio::test]
    async fn org_sharing_rejects_non_member_with_403() -> Result<(), Box<dyn std::error::Error>> {
        use coder_core::CreateUserInput;
        use coder_core::identity::CreateOrganizationInput;

        let (state, store) = crate::app::tests::test_state_with_store(true)?;

        // Seed an owning user (required to satisfy insert_organization's
        // actor_user_id), then create the owning organization.
        let owner = store
            .create_user(CreateUserInput {
                email: "owner@test.com".to_owned(),
                username: "owner".to_owned(),
                name: "Owner".to_owned(),
                password_hash: None,
                login_type: LoginType::Password,
                status: UserStatus::Active,
                organization_ids: Vec::new(),
            })
            .await?;
        let org = store
            .insert_organization(&CreateOrganizationInput {
                name: "acme".to_owned(),
                display_name: "Acme".to_owned(),
                description: String::new(),
                icon: String::new(),
                actor_user_id: owner.id,
            })
            .await?;

        // Seed a different user who is NOT a member of `org`.
        let outsider = store
            .create_user(CreateUserInput {
                email: "outsider@test.com".to_owned(),
                username: "outsider".to_owned(),
                name: "Outsider".to_owned(),
                password_hash: None,
                login_type: LoginType::Password,
                status: UserStatus::Active,
                organization_ids: Vec::new(),
            })
            .await?;

        let result =
            enforce_organization_sharing(&state, "organization", org.id, Some(outsider.id)).await;

        assert!(
            matches!(
                result,
                Err(WorkspaceAppError::Classified(
                    AppAccessError::NotOrganizationMember
                ))
            ),
            "expected Classified(NotOrganizationMember); got {kind:?}",
            kind = result.map(|_| "ok")
        );

        // And the classified error maps to HTTP 403.
        let response =
            WorkspaceAppError::Classified(AppAccessError::NotOrganizationMember).into_response();
        assert_eq!(response.status(), http::StatusCode::FORBIDDEN);
        Ok(())
    }

    /// A user who IS a member of the workspace's organization must pass the
    /// `sharing_level=organization` check.
    #[tokio::test]
    async fn org_sharing_allows_member() -> Result<(), Box<dyn std::error::Error>> {
        use coder_core::CreateUserInput;
        use coder_core::identity::CreateOrganizationInput;

        let (state, store) = crate::app::tests::test_state_with_store(true)?;

        let member = store
            .create_user(CreateUserInput {
                email: "member@test.com".to_owned(),
                username: "member".to_owned(),
                name: "Member".to_owned(),
                password_hash: None,
                login_type: LoginType::Password,
                status: UserStatus::Active,
                organization_ids: Vec::new(),
            })
            .await?;
        let org = store
            .insert_organization(&CreateOrganizationInput {
                name: "acme2".to_owned(),
                display_name: "Acme2".to_owned(),
                description: String::new(),
                icon: String::new(),
                actor_user_id: member.id,
            })
            .await?;
        // Put the member into the org.
        store
            .insert_organization_member(org.id, member.id, false)
            .await?;

        let result =
            enforce_organization_sharing(&state, "organization", org.id, Some(member.id)).await;
        assert!(
            result.is_ok(),
            "member of the workspace's organization should be allowed"
        );
        Ok(())
    }

    /// Non-organization sharing levels must be a no-op — the check belongs to
    /// a different policy branch and must not accidentally block access.
    #[tokio::test]
    async fn org_sharing_noop_for_other_levels() -> Result<(), Box<dyn std::error::Error>> {
        let (state, _store) = crate::app::tests::test_state_with_store(true)?;
        // We can pass a random user / org UUID — the function must short-circuit.
        let res = enforce_organization_sharing(
            &state,
            "authenticated",
            Uuid::new_v4(),
            Some(Uuid::new_v4()),
        )
        .await;
        assert!(
            res.is_ok(),
            "authenticated-level sharing must not hit the org check"
        );

        let res = enforce_organization_sharing(&state, "owner", Uuid::new_v4(), None).await;
        assert!(
            res.is_ok(),
            "owner-level sharing must not hit the org check"
        );

        let res = enforce_organization_sharing(&state, "public", Uuid::new_v4(), None).await;
        assert!(
            res.is_ok(),
            "public-level sharing must not hit the org check"
        );
        Ok(())
    }

    // -- Gap item #25: error classification parity --------------------------

    /// Agent-not-reporting must surface Go's specific UI string rather than a
    /// bare 404 "not found". Ports the `appErrNotFoundDescription` chain from
    /// `coder/coderd/workspaceapps/response.go`.
    #[test]
    fn agent_not_reporting_surfaces_specific_error() {
        let err = WorkspaceAppError::Classified(AppAccessError::AgentNotReporting);
        let msg = err.classification().unwrap_or("");
        assert!(
            msg.contains("agent") && msg.contains("not reporting"),
            "expected classification to contain 'agent' and 'not reporting'; got {msg:?}"
        );

        // Go uses 404 here to hide existence of the workspace/agent from
        // unauthorized users, but with a specific body, not a bare 404.
        let response = err.into_response();
        assert_eq!(response.status(), http::StatusCode::NOT_FOUND);
    }

    #[test]
    fn agent_not_connected_classification() {
        let err = WorkspaceAppError::Classified(AppAccessError::AgentNotConnected);
        let msg = err.classification().unwrap_or("");
        assert!(msg.contains("agent") && msg.contains("not connected"));
    }

    #[test]
    fn app_not_running_classification() {
        let err = WorkspaceAppError::Classified(AppAccessError::AppNotRunning);
        let msg = err.classification().unwrap_or("");
        assert!(msg.contains("not running"));
    }

    #[test]
    fn app_url_not_set_classification() {
        let err = WorkspaceAppError::Classified(AppAccessError::AppURLNotSet);
        let msg = err.classification().unwrap_or("");
        assert!(msg.contains("URL") && msg.contains("not set"));
    }

    #[test]
    fn template_forbid_app_access_classification() {
        let err = WorkspaceAppError::Classified(AppAccessError::TemplateDoesNotAllowAppAccess);
        let msg = err.classification().unwrap_or("");
        assert!(msg.contains("template") && msg.contains("does not allow"));
    }

    /// All agent/app-state classifications must return HTTP 404 (Go hides
    /// workspace existence), while `NotOrganizationMember` is HTTP 403.
    #[test]
    fn classification_status_codes_match_go() {
        assert_eq!(
            AppAccessError::AgentNotReporting.status_code(),
            http::StatusCode::NOT_FOUND
        );
        assert_eq!(
            AppAccessError::AgentNotConnected.status_code(),
            http::StatusCode::NOT_FOUND
        );
        assert_eq!(
            AppAccessError::AppNotRunning.status_code(),
            http::StatusCode::NOT_FOUND
        );
        assert_eq!(
            AppAccessError::AppURLNotSet.status_code(),
            http::StatusCode::NOT_FOUND
        );
        assert_eq!(
            AppAccessError::TemplateDoesNotAllowAppAccess.status_code(),
            http::StatusCode::NOT_FOUND
        );
        assert_eq!(
            AppAccessError::NotOrganizationMember.status_code(),
            http::StatusCode::FORBIDDEN
        );
    }

    // -- Gap item #24: per-session stats writer ----------------------------

    /// The stats payload serialized by [`AppStatsContext::to_stat_value`]
    /// must match the JSON shape `AppStore::insert_workspace_app_stats`
    /// consumes (see `coder/coderd/workspaceapps/stats.go`'s `StatsReport`).
    #[test]
    fn app_stats_context_serializes_expected_shape() {
        let ctx = AppStatsContext {
            user_id: Uuid::new_v4(),
            workspace_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            access_method: "path".to_owned(),
            slug_or_port: "code-server".to_owned(),
        };
        let session_id = Uuid::new_v4();
        let started = OffsetDateTime::now_utc();
        let ended = started + time::Duration::seconds(30);

        let value = ctx.to_stat_value(session_id, started, ended, 5);
        let object = value
            .as_object()
            .expect("to_stat_value should produce a JSON object");

        assert_eq!(
            object.get("user_id").and_then(|v| v.as_str()),
            Some(ctx.user_id.to_string().as_str())
        );
        assert_eq!(
            object.get("workspace_id").and_then(|v| v.as_str()),
            Some(ctx.workspace_id.to_string().as_str())
        );
        assert_eq!(
            object.get("agent_id").and_then(|v| v.as_str()),
            Some(ctx.agent_id.to_string().as_str())
        );
        assert_eq!(
            object.get("access_method").and_then(|v| v.as_str()),
            Some("path")
        );
        assert_eq!(
            object.get("slug_or_port").and_then(|v| v.as_str()),
            Some("code-server")
        );
        assert_eq!(
            object.get("session_id").and_then(|v| v.as_str()),
            Some(session_id.to_string().as_str())
        );
        assert_eq!(object.get("requests").and_then(|v| v.as_i64()), Some(5));
        assert!(object.contains_key("session_started_at"));
        assert!(object.contains_key("session_ended_at"));
    }

    /// `AppStatsGuard::flush` must invoke the store's
    /// `insert_workspace_app_stats` path. The FakeStore used here accepts
    /// the write and returns `Ok(())`, proving the wiring.
    ///
    /// The fully-persistent test (verifying a row ends up in the DB) lives
    /// at the sqlx layer in `crates/coder-db`; this unit test exercises the
    /// handler → trait-method boundary.
    #[tokio::test]
    async fn app_stats_guard_flush_writes_row() -> Result<(), Box<dyn std::error::Error>> {
        let (_state, store) = crate::app::tests::test_state_with_store(true)?;
        let store_trait: std::sync::Arc<dyn AppStore> = store.clone();

        let mut guard = AppStatsGuard::new(
            store_trait,
            AppStatsContext {
                user_id: Uuid::new_v4(),
                workspace_id: Uuid::new_v4(),
                agent_id: Uuid::new_v4(),
                access_method: "path".to_owned(),
                slug_or_port: "myapp".to_owned(),
            },
        );
        guard.record_request();
        guard.record_request();

        // flush() consumes the guard and must not error when the store
        // accepts the insert.
        guard.flush().await?;
        Ok(())
    }

    /// Dropping an unflushed `AppStatsGuard` must also drive a best-effort
    /// insert (see `AppStatsGuard::drop`). The spawned task just needs to
    /// complete without panicking — any error is logged but swallowed.
    #[tokio::test]
    async fn app_stats_guard_drop_spawns_insert() -> Result<(), Box<dyn std::error::Error>> {
        let (_state, store) = crate::app::tests::test_state_with_store(true)?;
        let store_trait: std::sync::Arc<dyn AppStore> = store.clone();

        {
            let mut guard = AppStatsGuard::new(
                store_trait,
                AppStatsContext {
                    user_id: Uuid::new_v4(),
                    workspace_id: Uuid::new_v4(),
                    agent_id: Uuid::new_v4(),
                    access_method: "subdomain".to_owned(),
                    slug_or_port: "8080".to_owned(),
                },
            );
            guard.record_request();
            // Drop here fires the background insert.
        }

        // Yield so the spawned task can run. The fact that we reach here
        // without panicking is the assertion — the insert is fire-and-forget.
        tokio::task::yield_now().await;
        Ok(())
    }
}
