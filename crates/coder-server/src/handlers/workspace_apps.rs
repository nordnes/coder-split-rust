//! Workspace application proxying handlers.
//!
//! Implements subdomain-based and path-based application proxy access for
//! workspace apps, ported from the Go reference in
//! `coder/coderd/workspaceapps/`.

use super::*;
use axum::middleware::Next;

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
    pub fn normalize(mut self) -> Self {
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
    pub fn check(&self) -> Result<(), AppRequestError> {
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
    pub fn new(hostname: &str) -> Self {
        Self {
            path_app_session_token: PATH_APP_SESSION_TOKEN_COOKIE.to_owned(),
            subdomain_app_session_token: subdomain_app_session_token_cookie(hostname),
        }
    }

    /// Returns the appropriate cookie name for the given access method.
    pub fn cookie_name_for_access_method(&self, method: &AccessMethod) -> &str {
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
    pub fn token_from_request(&self, headers: &HeaderMap, method: &AccessMethod) -> Option<String> {
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
    pub fn new(
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
}

impl IntoResponse for WorkspaceAppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Self::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "Authentication required.".to_owned(),
            ),
            Self::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.clone()),
            Self::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            Self::PathAppsDisabled => (
                StatusCode::FORBIDDEN,
                "Path-based applications are disabled on this Coder deployment.".to_owned(),
            ),
            Self::WorkspaceOffline => (
                StatusCode::BAD_REQUEST,
                "Workspace is offline. Start the workspace to access its applications.".to_owned(),
            ),
            Self::AgentOffline(msg) => (StatusCode::BAD_GATEWAY, msg.clone()),
            Self::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
            Self::ProxyError(msg) => (StatusCode::BAD_GATEWAY, msg.clone()),
        };
        (status, Json(ApiResponse::error(message, String::new()))).into_response()
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
) -> Result<Response, WorkspaceAppError> {
    // For now, workspace app proxying requires authentication.
    // Public apps would be handled here with sharing level checks.
    let _user_id = auth_context
        .user_id
        .ok_or(WorkspaceAppError::Unauthorized)?;

    // Resolve the target URL for the app.
    // In a full implementation, this would look up the workspace, agent, and
    // app in the database. For now, we build a reasonable proxy target.
    let app_url = resolve_app_url(app_request)?;

    // Validate port.
    if let Some(port_str) = app_url.port() {
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

    // Build the proxy target URL.
    let mut target_url = app_url.clone();
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

/// Resolves the target URL for a workspace app.
///
/// For port-based apps (matching `PORT_REGEX`: 4-5 digits, optional `s`
/// suffix), constructs `http(s)://127.0.0.1:{port}`.
///
/// **IMPORTANT / TODO**: The `127.0.0.1` target is a placeholder. In a full
/// implementation, the proxy must route through the workspace agent connection
/// (`AgentProvider`) so that requests reach the *workspace*, not the Coder
/// server's own loopback interface. Without this, an authenticated user could
/// reach arbitrary ports on the server itself (SSRF).
///
/// For slug-based apps, this would look up the app URL from the database
/// in a full implementation.
fn resolve_app_url(request: &AppRequest) -> Result<url::Url, WorkspaceAppError> {
    // Check if it's a port-based app using the same PORT_REGEX that
    // parse_subdomain_app_url enforces (4-5 digits, optional trailing 's').
    // This ensures consistent access-control between subdomain and path access.
    let slug = &request.app_slug_or_port;

    if appurl::PORT_REGEX.is_match(slug) {
        let (port_str, protocol) = if slug.ends_with('s') {
            (&slug[..slug.len() - 1], "https")
        } else {
            (slug.as_str(), "http")
        };

        if let Ok(port) = port_str.parse::<u16>() {
            // NOTE: This currently resolves to 127.0.0.1 which is a placeholder.
            // In a full implementation, the proxy should connect through the
            // workspace agent connection (via AgentProvider) rather than
            // directly to the server's localhost. See SSRF note in the doc
            // comment.
            let url_str = format!("{protocol}://127.0.0.1:{port}");
            return url::Url::parse(&url_str)
                .map_err(|e| WorkspaceAppError::Internal(format!("invalid port URL: {e}")));
        }
    }

    // For slug-based apps, we'd look up the app in the database.
    // For now, return a placeholder that indicates this needs database lookup.
    Err(WorkspaceAppError::NotFound(format!(
        "application {slug:?} not found (database lookup not yet implemented for slug-based apps)"
    )))
}

// ---------------------------------------------------------------------------
// Helper to build WorkspaceAppServer from AppState
// ---------------------------------------------------------------------------

/// Builds a [`WorkspaceAppServer`] from the application state.
///
/// Reads the access URL from config and uses it as both the dashboard and
/// access URL. The wildcard hostname is currently not configured (subdomain
/// apps disabled by default).
fn build_workspace_app_server(state: &AppState) -> WorkspaceAppServer {
    let access_url = state.config.access_url.clone();
    WorkspaceAppServer {
        dashboard_url: access_url.clone(),
        access_url,
        hostname: String::new(), // Subdomain apps disabled unless configured
        hostname_regex: None,
        disable_path_apps: false,
        cookies: AppCookies::new(""),
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

    #[test]
    fn resolve_port_http() {
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
        let result = resolve_app_url(&req);
        assert!(result.is_ok());
        let url = result.expect("test: parsing should succeed");
        assert_eq!(url.scheme(), "http");
        assert_eq!(url.port(), Some(8080));
    }

    #[test]
    fn resolve_port_https() {
        let req = AppRequest {
            access_method: AccessMethod::Subdomain,
            base_path: "/".to_owned(),
            prefix: String::new(),
            username_or_id: "dean".to_owned(),
            workspace_and_agent: String::new(),
            workspace_name_or_id: "dev".to_owned(),
            agent_name_or_id: "main".to_owned(),
            app_slug_or_port: "8080s".to_owned(),
        };
        let result = resolve_app_url(&req);
        assert!(result.is_ok());
        let url = result.expect("test: parsing should succeed");
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.port(), Some(8080));
    }

    #[test]
    fn resolve_slug_returns_not_found() {
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
        let result = resolve_app_url(&req);
        assert!(result.is_err());
    }

    #[test]
    fn resolve_short_numeric_slug_rejected() {
        // A 3-digit number does NOT match PORT_REGEX (requires 4-5 digits),
        // so it falls through to slug-based resolution → NotFound.
        let req = AppRequest {
            access_method: AccessMethod::Path,
            base_path: "/".to_owned(),
            prefix: String::new(),
            username_or_id: "dean".to_owned(),
            workspace_and_agent: String::new(),
            workspace_name_or_id: "dev".to_owned(),
            agent_name_or_id: "main".to_owned(),
            app_slug_or_port: "80".to_owned(),
        };
        let result = resolve_app_url(&req);
        assert!(
            result.is_err(),
            "2-digit number must not be treated as port"
        );

        let req2 = AppRequest {
            app_slug_or_port: "123".to_owned(),
            ..req
        };
        let result2 = resolve_app_url(&req2);
        assert!(
            result2.is_err(),
            "3-digit number must not be treated as port"
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
}
