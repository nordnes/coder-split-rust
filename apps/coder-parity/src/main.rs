//! Route parity comparison tool between the Go and Rust Coder backends.
//!
//! Provides `inventory` and `compare` subcommands for tracking and validating
//! API route porting progress.

#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use clap::{Args, Parser, Subcommand, ValueEnum};
use regex::Regex;
use reqwest::{Client, Method, redirect::Policy};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Parser)]
#[command(author, version, about = "Parity tooling for the Rust coderd rewrite")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Scan the Go and Rust trees and emit a parity matrix.
    Inventory(InventoryArgs),
    /// Compare live Go and Rust HTTP responses from a corpus of requests.
    Compare(CompareArgs),
    /// Scan the Rust tree and emit a per-route implementation-depth matrix.
    Depth(DepthArgs),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum InventoryScopeArg {
    Oss,
    Enterprise,
    All,
}

#[derive(Debug, Args)]
struct InventoryArgs {
    /// Path to the original Go repository root.
    #[arg(long, default_value = "coder")]
    go_root: PathBuf,

    /// Path to the Rust rewrite root.
    #[arg(long, default_value = ".")]
    rust_root: PathBuf,

    /// Which route scope to inventory.
    #[arg(long, value_enum, default_value_t = InventoryScopeArg::Oss)]
    scope: InventoryScopeArg,

    /// Additional Go source directories to scan (relative to go-root).
    /// Defaults to ["coderd"]. For enterprise, include "enterprise/coderd".
    #[arg(long, value_delimiter = ',')]
    go_dirs: Option<Vec<String>>,

    /// Additional Go SDK directories to scan (relative to go-root).
    /// Defaults to ["codersdk"].
    #[arg(long, value_delimiter = ',')]
    sdk_dirs: Option<Vec<String>>,

    /// Optional output file. Writes markdown when set.
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct DepthArgs {
    /// Path to the Rust rewrite root.
    #[arg(long, default_value = ".")]
    rust_root: PathBuf,

    /// Optional output file. Writes markdown when set.
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct CompareArgs {
    /// JSON corpus file describing black-box requests to run.
    #[arg(long)]
    corpus: PathBuf,

    /// Base URL for the Go coderd instance.
    #[arg(long)]
    go_base_url: String,

    /// Base URL for the Rust coderd instance.
    #[arg(long)]
    rust_base_url: String,
}

#[derive(Clone, Debug)]
struct GoRoute {
    method: String,
    path: String,
    live_path: String,
    mount: String,
    normalized_path: String,
    source: String,
    scope: RouteScope,
}

#[derive(Clone, Debug, Serialize)]
struct RustRoute {
    path: String,
    live_path: String,
    mount: String,
    normalized_path: String,
    methods: BTreeSet<String>,
    source: String,
}

#[derive(Clone, Debug, Serialize)]
struct ClientMethod {
    name: String,
    method: String,
    path: String,
    normalized_path: String,
    source: String,
}

#[derive(Clone, Debug, Serialize)]
struct ParityMatrixRow {
    method: String,
    path: String,
    live_path: String,
    mount: String,
    scope: RouteScope,
    source: String,
    sdk_methods: Vec<String>,
    rust_sources: Vec<String>,
    status: RouteStatus,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum RouteStatus {
    Ported,
    Missing,
}

#[derive(Clone, Copy, Debug, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum RouteScope {
    Oss,
    Enterprise,
}

#[derive(Clone, Debug, Serialize)]
struct InventorySummary {
    go_route_pairs: usize,
    rust_route_pairs: usize,
    sdk_client_methods: usize,
    ported_route_pairs: usize,
    missing_route_pairs: usize,
}

#[derive(Clone, Debug, Serialize)]
struct ParityInventory {
    scope: InventoryScope,
    summary: InventorySummary,
    rows: Vec<ParityMatrixRow>,
    unmatched_sdk_methods: Vec<ClientMethod>,
}

#[derive(Clone, Copy, Debug, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum InventoryScope {
    Oss,
    Enterprise,
    All,
}

#[derive(Debug, Deserialize)]
struct CompareCorpus {
    cases: Vec<CompareCase>,
}

#[derive(Debug, Deserialize)]
struct CompareCase {
    name: String,
    #[serde(default)]
    transport: Transport,
    request: HttpRequestSpec,
    #[serde(default)]
    comparison: ComparisonSpec,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Transport {
    #[default]
    Http,
    Sse,
    Websocket,
}

#[derive(Debug, Deserialize)]
struct HttpRequestSpec {
    method: String,
    path: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    body: Option<RequestBody>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RequestBody {
    Json(Value),
    Text(String),
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, ValueEnum)]
#[serde(rename_all = "snake_case")]
enum BodyMode {
    #[default]
    Json,
    Text,
    Empty,
    Ignore,
}

#[derive(Debug, Default, Deserialize)]
struct ComparisonSpec {
    #[serde(default)]
    body_mode: BodyMode,
    #[serde(default)]
    ignore_headers: Vec<String>,
    #[serde(default)]
    check_headers: bool,
    #[serde(default)]
    check_cookies: bool,
}

#[derive(Debug)]
struct ObservedResponse {
    status: u16,
    headers: BTreeMap<String, Vec<String>>,
    cookies: BTreeMap<String, String>,
    body: Vec<u8>,
}

#[derive(Debug, Error)]
enum ParityError {
    #[error("I/O error for {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("HTTP client error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("regex compilation failed: {0}")]
    Regex(String),
    #[error("unsupported transport in case {case_name}: {transport:?}")]
    UnsupportedTransport {
        case_name: String,
        transport: Transport,
    },
    #[error("comparison failed for {case_name}: {detail}")]
    ComparisonFailed { case_name: String, detail: String },
}

#[tokio::main]
async fn main() -> Result<(), ParityError> {
    let cli = Cli::parse();

    match cli.command {
        Command::Inventory(args) => run_inventory(args),
        Command::Compare(args) => run_compare(args).await,
        Command::Depth(args) => run_depth(args),
    }
}

fn run_inventory(args: InventoryArgs) -> Result<(), ParityError> {
    let scope = match args.scope {
        InventoryScopeArg::Oss => InventoryScope::Oss,
        InventoryScopeArg::Enterprise => InventoryScope::Enterprise,
        InventoryScopeArg::All => InventoryScope::All,
    };

    let default_go_dirs = match scope {
        InventoryScope::Oss => vec!["coderd".to_owned()],
        InventoryScope::Enterprise | InventoryScope::All => {
            vec!["coderd".to_owned(), "enterprise/coderd".to_owned()]
        }
    };
    let go_dirs = args.go_dirs.unwrap_or(default_go_dirs);

    let default_sdk_dirs = match scope {
        InventoryScope::Oss => vec!["codersdk".to_owned()],
        InventoryScope::Enterprise | InventoryScope::All => {
            let mut dirs = vec!["codersdk".to_owned()];
            if args.go_root.join("enterprise/codersdk").is_dir() {
                dirs.push("enterprise/codersdk".to_owned());
            }
            dirs
        }
    };
    let sdk_dirs = args.sdk_dirs.unwrap_or(default_sdk_dirs);

    let inventory = build_inventory(&args.go_root, &args.rust_root, scope, &go_dirs, &sdk_dirs)?;
    let markdown = render_inventory_markdown(&inventory, &go_dirs);

    if let Some(output) = args.output {
        write_file(&output, &markdown)?;
    } else {
        print!("{markdown}");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Depth command — scans the Rust tree and classifies each registered route by
// implementation depth (`complete`, `stub-partial`, `stub-501`).  The output is
// a markdown matrix used to maintain `crates/coder-server/PARITY_MATRIX.md`.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum DepthStatus {
    Complete,
    StubPartial,
    Stub501,
}

impl DepthStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::StubPartial => "stub-partial",
            Self::Stub501 => "stub-501",
        }
    }
}

#[derive(Clone, Debug)]
struct DepthRoute {
    live_path: String,
    method: String,
    handler: String,
    status: DepthStatus,
    notes: Option<String>,
    section: &'static str,
}

/// Authoritative list of handlers that are registered but still return
/// simplified / placeholder responses.  Sourced from §3 of
/// `docs/remaining-behavioral-gaps.md` and kept in-sync with that document.
/// Each entry maps a handler function name to a short note describing the
/// remaining behavioral gap.
const STUB_PARTIAL_HANDLERS: &[(&str, &str)] = &[
    (
        "list_api_key_scopes",
        "Returns the fixed `PUBLIC_API_KEY_SCOPES` list; full scope expansion not modelled yet.",
    ),
    (
        "update_check",
        "Always reports `current: true`; no remote version probe.",
    ),
    (
        "post_template_version_dynamic_parameters_evaluate",
        "Evaluates seeded parameters only; no Terraform module execution.",
    ),
    (
        "post_workspace_agent_instance_identity_aws",
        "Parses instance_id from the identity document without AWS certificate verification.",
    ),
    (
        "post_workspace_agent_instance_identity_azure",
        "Extracts VM id from the JWT payload without Microsoft signature verification.",
    ),
    (
        "post_workspace_agent_instance_identity_google",
        "Extracts instance id from the GCP JWT payload without Google token validation.",
    ),
    (
        "get_workspace_quota_deprecated",
        "Returns unlimited budget; quota allowance/consumed queries not wired.",
    ),
    (
        "get_workspace_quota",
        "Returns unlimited budget; quota allowance/consumed queries not wired.",
    ),
    (
        "patch_workspace_sharing_settings",
        "Validates payload but stores nothing; returns 501 until the store is wired.",
    ),
    (
        "get_replicas",
        "Returns an empty array; no replica manager service implemented.",
    ),
];

fn run_depth(args: DepthArgs) -> Result<(), ParityError> {
    let (routes, summary) = build_depth_matrix(&args.rust_root)?;
    let markdown = render_depth_markdown(&routes, &summary);

    if let Some(output) = args.output {
        write_file(&output, &markdown)?;
    } else {
        print!("{markdown}");
    }

    Ok(())
}

#[derive(Clone, Debug)]
struct DepthSummary {
    total: usize,
    complete: usize,
    stub_partial: usize,
    stub_501: usize,
}

fn build_depth_matrix(rust_root: &Path) -> Result<(Vec<DepthRoute>, DepthSummary), ParityError> {
    let app_rs = rust_root.join("crates/coder-server/src/app.rs");
    let app_content = read_to_string(&app_rs)?;
    let router_body = extract_build_router_body(&app_content).ok_or_else(|| {
        ParityError::Regex("could not locate build_router(...) body in app.rs".to_owned())
    })?;

    let mut handler_routes = Vec::new();
    collect_rust_handler_routes_from_content(&router_body, "", &mut handler_routes)?;

    let handler_bodies = collect_handler_bodies(rust_root)?;

    let mut rows = Vec::with_capacity(handler_routes.len());
    for entry in &handler_routes {
        let body = handler_bodies
            .get(entry.handler.as_str())
            .map(String::as_str);
        let (status, notes) = classify_depth(&entry.handler, body);
        rows.push(DepthRoute {
            live_path: entry.live_path.clone(),
            method: entry.method.clone(),
            handler: entry.handler.clone(),
            status,
            notes,
            section: classify_section(&entry.live_path),
        });
    }

    rows.sort_by(|left, right| {
        left.section
            .cmp(right.section)
            .then(left.live_path.cmp(&right.live_path))
            .then(left.method.cmp(&right.method))
    });

    // Within each section/path, dedupe exact duplicates that can arise from
    // aliased routes (e.g. `/gitauth/{id}/callback` == `/external-auth/{id}/callback`).
    rows.dedup_by(|a, b| {
        a.section == b.section
            && a.live_path == b.live_path
            && a.method == b.method
            && a.handler == b.handler
    });

    let total = rows.len();
    let complete = rows
        .iter()
        .filter(|row| matches!(row.status, DepthStatus::Complete))
        .count();
    let stub_partial = rows
        .iter()
        .filter(|row| matches!(row.status, DepthStatus::StubPartial))
        .count();
    let stub_501 = rows
        .iter()
        .filter(|row| matches!(row.status, DepthStatus::Stub501))
        .count();

    let summary = DepthSummary {
        total,
        complete,
        stub_partial,
        stub_501,
    };
    Ok((rows, summary))
}

#[derive(Clone, Debug)]
struct HandlerRoute {
    live_path: String,
    method: String,
    handler: String,
}

fn extract_build_router_body(content: &str) -> Option<String> {
    let start = content.find("pub fn build_router(")?;
    let rest = &content[start..];
    // Find the opening `{` of the function body.
    let open = rest.find('{')?;
    let bytes = rest.as_bytes();
    let mut depth: i32 = 0;
    let mut index = open;
    while index < bytes.len() {
        match bytes[index] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(rest[open..=index].to_owned());
                }
            }
            _ => {}
        }
        index += 1;
    }
    None
}

fn collect_rust_handler_routes_from_content(
    content: &str,
    prefix: &str,
    routes: &mut Vec<HandlerRoute>,
) -> Result<(), ParityError> {
    let path_re = compile_regex(r#"(?s)\.route\(\s*"(?P<path>/[^"]*)","#)?;
    let nest_re = compile_regex(r#"(?s)\.nest\(\s*"(?P<path>/[^"]+)""#)?;
    let lines = content.lines().collect::<Vec<_>>();
    let mut index = 0usize;

    while index < lines.len() {
        let line = lines[index].trim();

        if line.contains(".nest(") {
            let (block, next_index) = collect_block(&lines, index);
            if let Some(captures) = nest_re.captures(&block) {
                if let Some(router_start) = block.find("Router::new()") {
                    let nested_prefix = join_path(prefix, &captures["path"]);
                    let nested = &block[router_start + "Router::new()".len()..];
                    collect_rust_handler_routes_from_content(
                        nested,
                        &nested_prefix,
                        routes,
                    )?;
                }
            }
            index = next_index;
            continue;
        }

        if line.contains(".merge(") {
            let (block, next_index) = collect_block(&lines, index);
            if let Some(router_start) = block.find("Router::new()") {
                let nested = &block[router_start + "Router::new()".len()..];
                collect_rust_handler_routes_from_content(nested, prefix, routes)?;
            }
            index = next_index;
            continue;
        }

        if line.contains(".route(") {
            let (block, next_index) = collect_block(&lines, index);
            if let Some(captures) = path_re.captures(&block) {
                let path_value = captures["path"].to_owned();
                let live_path = join_path(prefix, &path_value);
                for (method, handler) in extract_method_handlers(&block) {
                    routes.push(HandlerRoute {
                        live_path: live_path.clone(),
                        method,
                        handler,
                    });
                }
            }
            index = next_index;
            continue;
        }

        index += 1;
    }

    Ok(())
}

fn extract_method_handlers(block: &str) -> Vec<(String, String)> {
    // Matches `get(fn_name)`, `post(fn_name)`, ... where `fn_name` is a bare
    // identifier.  Inline closures or trailing punctuation (e.g.
    // `get(|| async { ... })`) are skipped.
    let Ok(regex) = compile_regex(
        r"(?P<method>get|post|put|patch|delete|any)\(\s*(?P<handler>[A-Za-z_][A-Za-z0-9_]*)\s*\)",
    ) else {
        return Vec::new();
    };
    let mut handlers = Vec::new();
    for captures in regex.captures_iter(block) {
        let method = captures["method"].to_ascii_uppercase();
        let handler = captures["handler"].to_owned();
        // Skip false positives where the identifier is obviously not a handler
        // function (e.g. `State`, `Router`).
        if handler.chars().next().is_some_and(|c| c.is_uppercase()) {
            continue;
        }
        handlers.push((method, handler));
    }
    handlers
}

fn collect_handler_bodies(rust_root: &Path) -> Result<BTreeMap<String, String>, ParityError> {
    let handlers_dir = rust_root.join("crates/coder-server/src/handlers");
    let mut bodies = BTreeMap::new();

    let mut rust_files = Vec::new();
    if handlers_dir.is_dir() {
        for path in collect_files(&handlers_dir, "rs")? {
            rust_files.push(path);
        }
    }
    let app_rs = rust_root.join("crates/coder-server/src/app.rs");
    if app_rs.is_file() {
        rust_files.push(app_rs);
    }

    let fn_re = compile_regex(
        r"(?m)^\s*(?:pub(?:\([^)]+\))?\s+)?(?:async\s+)?fn\s+(?P<name>[a-z_][a-zA-Z0-9_]*)\s*\(",
    )?;

    for path in rust_files {
        let content = read_to_string(&path)?;
        let matches: Vec<(usize, String)> = fn_re
            .captures_iter(&content)
            .filter_map(|captures| {
                let full = captures.get(0)?;
                let name = captures.name("name")?.as_str().to_owned();
                Some((full.start(), name))
            })
            .collect();

        for (match_start, name) in &matches {
            // Only capture the first definition of a given name.  If the name
            // is already registered, keep the earlier (likely-canonical) body.
            if bodies.contains_key(name) {
                continue;
            }
            if let Some(body) = extract_fn_body(&content, *match_start) {
                bodies.insert(name.clone(), body);
            }
        }
    }

    Ok(bodies)
}

fn extract_fn_body(content: &str, match_start: usize) -> Option<String> {
    // Advance from match_start to the first `{` at brace-depth 0 (ignoring
    // generic / parameter parens) — i.e. the start of the function body.
    let bytes = content.as_bytes();
    let mut index = match_start;
    let mut paren: i32 = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'(' => paren += 1,
            b')' => paren -= 1,
            b'{' if paren == 0 => break,
            b';' if paren == 0 => return None,
            _ => {}
        }
        index += 1;
    }
    if index >= bytes.len() {
        return None;
    }
    let body_start = index;
    let mut depth: i32 = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(content[body_start..=index].to_owned());
                }
            }
            _ => {}
        }
        index += 1;
    }
    None
}

fn classify_depth(handler_name: &str, body: Option<&str>) -> (DepthStatus, Option<String>) {
    if let Some((_, note)) = STUB_PARTIAL_HANDLERS
        .iter()
        .find(|(name, _)| *name == handler_name)
    {
        return (DepthStatus::StubPartial, Some((*note).to_owned()));
    }
    if let Some(body) = body {
        if body_returns_not_implemented(body) {
            return (DepthStatus::Stub501, None);
        }
    }
    (DepthStatus::Complete, None)
}

fn body_returns_not_implemented(body: &str) -> bool {
    // Heuristic: consider any function that constructs a `StatusCode::NOT_IMPLEMENTED`
    // response as a 501 stub.  Line-comments containing the literal are stripped
    // before the search so that comment-only mentions do not produce false
    // positives.  This does not understand `/* ... */` block comments, but
    // none of the handlers in this codebase use them around status literals.
    for line in body.lines() {
        let code = match line.find("//") {
            Some(index) => &line[..index],
            None => line,
        };
        if code.contains("StatusCode::NOT_IMPLEMENTED") {
            return true;
        }
    }
    false
}

fn classify_section(live_path: &str) -> &'static str {
    if live_path.starts_with("/scim/") || live_path == "/scim/v2" {
        return "SCIM";
    }
    if live_path.starts_with("/external-auth/") || live_path.starts_with("/gitauth/") {
        return "External Auth (OAuth/OIDC)";
    }
    if live_path.starts_with("/@") {
        return "Workspace Apps";
    }
    let stripped = live_path.strip_prefix("/api/v2").unwrap_or(live_path);
    let first = stripped
        .trim_start_matches('/')
        .split('/')
        .next()
        .unwrap_or("");
    match first {
        "" | "healthz" | "latency-check" | "derp" | "metrics" | "mcp" | "derp-map" => {
            "Root / Health"
        }
        "audit" => "Audit",
        "auth" | "authcheck" => "Auth",
        "buildinfo" | "csp" | "deployment" | "experiments" | "init-script" | "updatecheck"
        | "telemetry" => "Deployment & Config",
        "debug" => "Debug",
        "regions" | "tailnet" | "workspaceagents-server" | "workspaceagents-client" => {
            "Connectivity (DERP / Tailnet / Regions)"
        }
        "external-auth" | "gitauth" => "External Auth (OAuth/OIDC)",
        "files" => "Files",
        "insights" => "Insights & Analytics",
        "notifications" | "inbox" => "Notifications & Inbox",
        "oauth2" | ".well-known" => "OAuth2 Provider",
        "organizations" => "Organizations",
        "applications" => "Applications",
        "tasks" => "AI Tasks",
        "chats" => "Chats",
        "templates" | "templateversions" => "Templates & Template Versions",
        "users" => "Users & Identity",
        "workspaces" | "workspacebuilds" => "Workspaces & Builds",
        "workspaceagents" | "workspaceresources" => "Workspace Agents",
        "appearance" => "Appearance",
        "licenses" | "entitlements" => "Licenses & Entitlements",
        "scim" => "SCIM",
        "groups" => "Groups",
        "workspace-quota" => "Workspace Quotas",
        "provisionerkeys" | "provisionerdaemons" | "organizations-provisioner" => "Provisioner",
        "aibridge" => "AI Bridge",
        "connectionlog" => "Connection Log",
        "workspaceproxies" => "Workspace Proxies",
        "replicas" => "Replicas",
        "prebuilds" => "Prebuilds",
        "oauth2-provider" => "OAuth2 Provider",
        "settings" => "Deployment Settings & IDP Sync",
        "external-agent-credentials" | "externalagentcredentials" => "External Agent Credentials",
        _ => "Other",
    }
}

fn render_depth_markdown(rows: &[DepthRoute], summary: &DepthSummary) -> String {
    let mut out = String::new();
    out.push_str("# `coder-server` Route Implementation Depth\n\n");
    out.push_str(
        "For the authoritative analysis of behavioral gaps, see `docs/remaining-behavioral-gaps.md`.\n\n",
    );
    out.push_str(
        "Generated by `cargo run -p coder-parity -- depth --rust-root . --output \
         crates/coder-server/PARITY_MATRIX.md`.  Re-run this command after adding or \
         modifying a route handler; the classifier inspects `build_router` in \
         `crates/coder-server/src/app.rs` and each handler body under \
         `crates/coder-server/src/handlers/`.\n\n",
    );
    out.push_str("## Summary\n\n");
    out.push_str(&format!(
        "- Total registered routes: **{}**\n",
        summary.total
    ));
    out.push_str(&format!("- `complete`: **{}**\n", summary.complete));
    out.push_str(&format!(
        "- `stub-partial`: **{}** (see §3 of the gap doc)\n",
        summary.stub_partial
    ));
    out.push_str(&format!("- `stub-501`: **{}**\n\n", summary.stub_501));

    out.push_str("### Status Legend\n\n");
    out.push_str("| Status | Meaning |\n");
    out.push_str("| --- | --- |\n");
    out.push_str(
        "| `complete` | Full behavioral parity with the Go handler — reads/writes the store, emits audit/notification events, enforces RBAC. |\n",
    );
    out.push_str(
        "| `stub-partial` | Registered route that returns a simplified response (hard-coded value, empty list, or partial validation) while the full integration is pending.  Enumerated in §3 of `docs/remaining-behavioral-gaps.md`. |\n",
    );
    out.push_str(
        "| `stub-501` | Registered route that returns `501 Not Implemented`.  The route exists to match the Go surface area but has no semantics yet. |\n\n",
    );

    // Group by section in sort order.
    let mut current_section: Option<&str> = None;
    for row in rows {
        if current_section != Some(row.section) {
            if current_section.is_some() {
                out.push('\n');
            }
            current_section = Some(row.section);
            out.push_str(&format!("## {}\n\n", row.section));
            out.push_str("| Method | Route | Handler | Status | Notes |\n");
            out.push_str("| --- | --- | --- | --- | --- |\n");
        }
        let notes = row.notes.as_deref().unwrap_or("");
        out.push_str(&format!(
            "| {} | `{}` | `{}` | `{}` | {} |\n",
            row.method,
            row.live_path,
            row.handler,
            row.status.as_str(),
            notes,
        ));
    }

    if rows
        .iter()
        .any(|row| matches!(row.status, DepthStatus::Stub501))
    {
        out.push_str(
            "\nRoutes classified `stub-501` above currently return `501 Not Implemented` verbatim.  \
             Promote them to `stub-partial` or `complete` as handler behavior evolves.\n",
        );
    }

    out
}

async fn run_compare(args: CompareArgs) -> Result<(), ParityError> {
    let corpus = read_json::<CompareCorpus>(&args.corpus)?;
    let client = Client::builder().redirect(Policy::none()).build()?;
    let go_base = args.go_base_url.trim_end_matches('/');
    let rust_base = args.rust_base_url.trim_end_matches('/');

    for case in corpus.cases {
        if case.transport != Transport::Http {
            return Err(ParityError::UnsupportedTransport {
                case_name: case.name,
                transport: case.transport,
            });
        }

        let go_response = execute_http_case(&client, go_base, &case.request).await?;
        let rust_response = execute_http_case(&client, rust_base, &case.request).await?;
        compare_http_case(&case.name, &case.comparison, &go_response, &rust_response)?;
    }

    Ok(())
}

fn build_inventory(
    go_root: &Path,
    rust_root: &Path,
    scope: InventoryScope,
    go_dirs: &[String],
    sdk_dirs: &[String],
) -> Result<ParityInventory, ParityError> {
    let mut go_routes = Vec::new();
    for dir in go_dirs {
        let dir_path = go_root.join(dir);
        if dir_path.is_dir() {
            go_routes.extend(collect_go_routes(&dir_path, scope)?);
        }
    }
    go_routes.sort_by(|left, right| {
        left.normalized_path
            .cmp(&right.normalized_path)
            .then(left.method.cmp(&right.method))
            .then(left.source.cmp(&right.source))
    });
    go_routes.dedup_by(|a, b| a.method == b.method && a.normalized_path == b.normalized_path);

    let mut client_methods = Vec::new();
    for dir in sdk_dirs {
        let dir_path = go_root.join(dir);
        if dir_path.is_dir() {
            client_methods.extend(collect_client_methods(&dir_path)?);
        }
    }
    client_methods.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.method.cmp(&right.method))
            .then(left.name.cmp(&right.name))
    });
    let rust_routes = collect_rust_routes(&rust_root.join("crates"))?;

    let mut sdk_by_route: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
    for client_method in &client_methods {
        sdk_by_route
            .entry((
                client_method.method.clone(),
                client_method.normalized_path.clone(),
            ))
            .or_default()
            .push(client_method.name.clone());
    }

    let mut rust_by_route: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
    for rust_route in &rust_routes {
        for method in &rust_route.methods {
            rust_by_route
                .entry((method.clone(), rust_route.normalized_path.clone()))
                .or_default()
                .push(rust_route.source.clone());
        }
    }

    let mut rows = Vec::with_capacity(go_routes.len());
    let mut ported_route_pairs = 0_usize;
    for route in &go_routes {
        let sdk_methods = sdk_by_route
            .get(&(route.method.clone(), route.normalized_path.clone()))
            .cloned()
            .unwrap_or_default();
        let rust_sources = rust_by_route
            .get(&(route.method.clone(), route.normalized_path.clone()))
            .cloned()
            .unwrap_or_default();
        let status = if rust_sources.is_empty() {
            RouteStatus::Missing
        } else {
            ported_route_pairs += 1;
            RouteStatus::Ported
        };

        rows.push(ParityMatrixRow {
            method: route.method.clone(),
            path: route.path.clone(),
            live_path: route.live_path.clone(),
            mount: route.mount.clone(),
            scope: route.scope,
            source: route.source.clone(),
            sdk_methods,
            rust_sources,
            status,
        });
    }

    let go_route_keys: BTreeSet<(String, String)> = go_routes
        .iter()
        .map(|route| (route.method.clone(), route.normalized_path.clone()))
        .collect();
    let unmatched_sdk_methods = client_methods
        .into_iter()
        .filter(|client_method| {
            !go_route_keys.contains(&(
                client_method.method.clone(),
                client_method.normalized_path.clone(),
            ))
        })
        .collect::<Vec<_>>();

    let rust_route_pairs = rust_routes.iter().map(|route| route.methods.len()).sum();
    let missing_route_pairs = go_routes.len().saturating_sub(ported_route_pairs);

    Ok(ParityInventory {
        scope,
        summary: InventorySummary {
            go_route_pairs: go_routes.len(),
            rust_route_pairs,
            sdk_client_methods: sdk_by_route.values().map(Vec::len).sum(),
            ported_route_pairs,
            missing_route_pairs,
        },
        rows,
        unmatched_sdk_methods,
    })
}

fn collect_go_routes(root: &Path, scope: InventoryScope) -> Result<Vec<GoRoute>, ParityError> {
    let mut routes = Vec::new();

    for path in collect_files(root, "go")? {
        let content = read_to_string(&path)?;
        let display = relative_display(&path);
        routes.extend(
            parse_go_routes(&content, &display)?
                .into_iter()
                .filter(|route| matches_scope(route.scope, scope)),
        );
    }

    Ok(routes)
}

fn parse_go_routes(content: &str, source: &str) -> Result<Vec<GoRoute>, ParityError> {
    let route_re = compile_regex(r"// @Router (?P<path>/\S*) \[(?P<method>[^\]]+)\]")?;
    let mut routes = Vec::new();
    let mut tags = Vec::<String>::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(tag_line) = trimmed.strip_prefix("// @Tags ") {
            tags = tag_line
                .split_whitespace()
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>();
            continue;
        }

        if let Some(captures) = route_re.captures(trimmed) {
            let path = captures["path"].to_owned();
            let live_path = go_live_path(&path);
            routes.push(GoRoute {
                method: captures["method"].to_ascii_uppercase(),
                path,
                live_path: live_path.clone(),
                mount: route_mount(&live_path),
                normalized_path: normalize_path(&live_path),
                source: source.to_owned(),
                scope: if tags.iter().any(|tag| tag == "Enterprise") {
                    RouteScope::Enterprise
                } else {
                    RouteScope::Oss
                },
            });
            tags.clear();
            continue;
        }

        if !trimmed.starts_with("// @") && !trimmed.starts_with("//") {
            tags.clear();
        }
    }

    Ok(routes)
}

fn collect_client_methods(root: &Path) -> Result<Vec<ClientMethod>, ParityError> {
    let function_re = compile_regex(r"(?m)^func \(c \*Client\) (?P<name>[A-Za-z0-9_]+)\(")?;
    let method_re = compile_regex(r"http\.Method(?P<method>[A-Za-z]+)")?;
    let path_re = compile_regex(r#"(?:fmt\.Sprintf\()?"(?P<path>/[^"]*)""#)?;
    let mut methods = Vec::new();

    for path in collect_files(root, "go")? {
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with("_test.go"))
        {
            continue;
        }

        let content = read_to_string(&path)?;
        let function_starts = function_re
            .captures_iter(&content)
            .filter_map(|captures| {
                captures.get(0).map(|matched| {
                    (
                        matched.start(),
                        captures["name"].to_owned(),
                        matched.as_str().to_owned(),
                    )
                })
            })
            .collect::<Vec<_>>();

        for (index, (start, name, _signature)) in function_starts.iter().enumerate() {
            let end = function_starts
                .get(index + 1)
                .map_or(content.len(), |(next_start, _, _)| *next_start);
            let body = &content[*start..end];
            let Some(method_captures) = method_re.captures(body) else {
                continue;
            };
            let Some(path_captures) = path_re.captures(body) else {
                continue;
            };

            let method = method_captures["method"].to_ascii_uppercase();
            let path_value = path_captures["path"].to_owned();
            methods.push(ClientMethod {
                name: name.clone(),
                normalized_path: normalize_path(&path_value),
                method,
                path: path_value,
                source: relative_display(&path),
            });
        }
    }

    methods.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.method.cmp(&right.method))
            .then(left.name.cmp(&right.name))
    });
    Ok(methods)
}

fn collect_rust_routes(root: &Path) -> Result<Vec<RustRoute>, ParityError> {
    let mut routes = Vec::new();

    for path in collect_files(root, "rs")? {
        let content = read_to_string(&path)?;
        collect_rust_routes_from_content(&content, "", &relative_display(&path), &mut routes)?;
    }

    routes.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.source.cmp(&right.source))
    });
    Ok(routes)
}

fn collect_rust_routes_from_content(
    content: &str,
    prefix: &str,
    source: &str,
    routes: &mut Vec<RustRoute>,
) -> Result<(), ParityError> {
    let path_re = compile_regex(r#"(?s)\.route\(\s*"(?P<path>/[^"]*)","#)?;
    let nest_re = compile_regex(r#"(?s)\.nest\(\s*"(?P<path>/[^"]+)""#)?;
    let lines = content.lines().collect::<Vec<_>>();
    let mut index = 0usize;

    while index < lines.len() {
        let line = lines[index].trim();

        if line.contains(".nest(") {
            let (block, next_index) = collect_block(&lines, index);
            if let Some(captures) = nest_re.captures(&block) {
                if let Some(router_start) = block.find("Router::new()") {
                    let nested_prefix = join_path(prefix, &captures["path"]);
                    let nested = &block[router_start + "Router::new()".len()..];
                    collect_rust_routes_from_content(nested, &nested_prefix, source, routes)?;
                }
            }
            index = next_index;
            continue;
        }

        if line.contains(".merge(") {
            let (block, next_index) = collect_block(&lines, index);
            if let Some(router_start) = block.find("Router::new()") {
                let nested = &block[router_start + "Router::new()".len()..];
                collect_rust_routes_from_content(nested, prefix, source, routes)?;
            } else {
                eprintln!(
                    "warning: .merge() block without Router::new() in {source} — routes may be missed"
                );
            }
            index = next_index;
            continue;
        }

        if line.contains(".route(") {
            let (block, next_index) = collect_block(&lines, index);
            if let Some(captures) = path_re.captures(&block) {
                let path_value = captures["path"].to_owned();
                let methods = extract_rust_methods(&block);
                if !methods.is_empty() {
                    let live_path = join_path(prefix, &path_value);
                    routes.push(RustRoute {
                        normalized_path: normalize_path(&live_path),
                        methods,
                        path: path_value,
                        live_path: live_path.clone(),
                        mount: route_mount(&live_path),
                        source: source.to_owned(),
                    });
                }
            }
            index = next_index;
            continue;
        }

        index += 1;
    }

    Ok(())
}

fn collect_block(lines: &[&str], start: usize) -> (String, usize) {
    let mut block = String::new();
    let mut paren_balance: isize = 0;
    let mut index = start;

    while index < lines.len() {
        let line = lines[index].trim();
        if !block.is_empty() {
            block.push('\n');
        }
        block.push_str(line);
        paren_balance += line.chars().filter(|character| *character == '(').count() as isize;
        paren_balance -= line.chars().filter(|character| *character == ')').count() as isize;
        index += 1;

        if paren_balance <= 0 {
            break;
        }
    }

    (block, index)
}

fn extract_rust_methods(block: &str) -> BTreeSet<String> {
    let mut methods = BTreeSet::new();
    for (needle, method) in [
        ("get(", "GET"),
        ("post(", "POST"),
        ("put(", "PUT"),
        ("patch(", "PATCH"),
        ("delete(", "DELETE"),
    ] {
        if block.contains(needle) {
            methods.insert(method.to_owned());
        }
    }
    methods
}

fn render_inventory_markdown(inventory: &ParityInventory, go_dirs: &[String]) -> String {
    let mut markdown = String::new();
    markdown.push_str(&format!(
        "# {} Parity Matrix\n\n",
        inventory.scope.display_name()
    ));

    let default_dirs = ["coderd".to_owned()];
    let dirs_flag = if go_dirs != default_dirs.as_slice() {
        format!(" --go-dirs {}", go_dirs.join(","))
    } else {
        String::new()
    };
    markdown.push_str(&format!(
        "Generated by `cargo run -p coder-parity -- inventory --go-root coder --rust-root . --scope {}{}`.\n\n",
        inventory.scope.flag_value(),
        dirs_flag
    ));
    markdown.push_str("## Summary\n\n");
    markdown.push_str(&format!(
        "- Go route/method pairs in scope: {}\n",
        inventory.summary.go_route_pairs
    ));
    markdown.push_str(&format!(
        "- Rust route/method pairs: {}\n",
        inventory.summary.rust_route_pairs
    ));
    markdown.push_str(&format!(
        "- `codersdk.Client` methods with direct HTTP mapping: {}\n",
        inventory.summary.sdk_client_methods
    ));
    markdown.push_str(&format!(
        "- Ported route/method pairs: {}\n",
        inventory.summary.ported_route_pairs
    ));
    markdown.push_str(&format!(
        "- Missing route/method pairs: {}\n\n",
        inventory.summary.missing_route_pairs
    ));
    markdown.push_str("## Route Matrix\n\n");
    markdown.push_str(
        "| Method | Route Path | Live Path | Mount | Scope | Go Source | SDK Methods | Rust Status |\n",
    );
    markdown.push_str("| --- | --- | --- | --- | --- | --- | --- | --- |\n");
    for row in &inventory.rows {
        let sdk_methods = if row.sdk_methods.is_empty() {
            "-".to_owned()
        } else {
            row.sdk_methods.join(", ")
        };
        let rust_status = match row.status {
            RouteStatus::Ported => format!("ported (`{}`)", row.rust_sources.join(", ")),
            RouteStatus::Missing => "missing".to_owned(),
        };

        markdown.push_str(&format!(
            "| {} | `{}` | `{}` | `{}` | `{}` | `{}` | {} | {} |\n",
            row.method,
            row.path,
            row.live_path,
            row.mount,
            row.scope.as_str(),
            row.source,
            sdk_methods,
            rust_status
        ));
    }

    if !inventory.unmatched_sdk_methods.is_empty() {
        markdown.push_str("\n## SDK Methods Without Direct Route Match\n\n");
        markdown.push_str("| Client Method | Method | Path | Source |\n");
        markdown.push_str("| --- | --- | --- | --- |\n");
        for client_method in &inventory.unmatched_sdk_methods {
            markdown.push_str(&format!(
                "| `{}` | {} | `{}` | `{}` |\n",
                client_method.name, client_method.method, client_method.path, client_method.source
            ));
        }
    }

    markdown
}

async fn execute_http_case(
    client: &Client,
    base_url: &str,
    request: &HttpRequestSpec,
) -> Result<ObservedResponse, ParityError> {
    let method = Method::from_bytes(request.method.as_bytes()).map_err(|_| {
        ParityError::ComparisonFailed {
            case_name: request.path.clone(),
            detail: format!("unsupported method {}", request.method),
        }
    })?;
    let url = format!("{base_url}{}", request.path);
    let mut builder = client.request(method, url);
    for (name, value) in &request.headers {
        builder = builder.header(name, value);
    }

    if let Some(body) = &request.body {
        builder = match body {
            RequestBody::Json(value) => builder.json(value),
            RequestBody::Text(value) => builder.body(value.clone()),
        };
    }

    let response = builder.send().await?;
    let status = response.status().as_u16();
    let mut headers = BTreeMap::new();
    for (name, value) in response.headers() {
        headers
            .entry(name.as_str().to_ascii_lowercase())
            .or_insert_with(Vec::new)
            .push(value.to_str().unwrap_or_default().to_owned());
    }
    for values in headers.values_mut() {
        values.sort();
    }

    let cookies = headers
        .get("set-cookie")
        .into_iter()
        .flatten()
        .filter_map(|cookie| cookie.split_once('='))
        .map(|(name, rest)| {
            let value = rest.split(';').next().unwrap_or_default().to_owned();
            (name.to_owned(), value)
        })
        .collect::<BTreeMap<_, _>>();

    let body = response.bytes().await?.to_vec();
    Ok(ObservedResponse {
        status,
        headers,
        cookies,
        body,
    })
}

fn compare_http_case(
    case_name: &str,
    comparison: &ComparisonSpec,
    go_response: &ObservedResponse,
    rust_response: &ObservedResponse,
) -> Result<(), ParityError> {
    if go_response.status != rust_response.status {
        return Err(ParityError::ComparisonFailed {
            case_name: case_name.to_owned(),
            detail: format!(
                "status mismatch: go={} rust={}",
                go_response.status, rust_response.status
            ),
        });
    }

    if comparison.check_headers {
        let ignore_headers = comparison
            .ignore_headers
            .iter()
            .map(|header| header.to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        let go_headers = filtered_headers(go_response, &ignore_headers, comparison.check_cookies);
        let rust_headers =
            filtered_headers(rust_response, &ignore_headers, comparison.check_cookies);
        if go_headers != rust_headers {
            return Err(ParityError::ComparisonFailed {
                case_name: case_name.to_owned(),
                detail: format!("header mismatch: go={go_headers:?} rust={rust_headers:?}"),
            });
        }
    }

    if comparison.check_cookies && go_response.cookies != rust_response.cookies {
        return Err(ParityError::ComparisonFailed {
            case_name: case_name.to_owned(),
            detail: format!(
                "cookie mismatch: go={:?} rust={:?}",
                go_response.cookies, rust_response.cookies
            ),
        });
    }

    match comparison.body_mode {
        BodyMode::Ignore => {}
        BodyMode::Empty => {
            let go_body = String::from_utf8_lossy(&go_response.body);
            let rust_body = String::from_utf8_lossy(&rust_response.body);
            if !go_body.trim().is_empty() || !rust_body.trim().is_empty() {
                return Err(ParityError::ComparisonFailed {
                    case_name: case_name.to_owned(),
                    detail: format!("expected empty bodies: go={go_body:?} rust={rust_body:?}"),
                });
            }
        }
        BodyMode::Text => {
            let go_body = String::from_utf8_lossy(&go_response.body);
            let rust_body = String::from_utf8_lossy(&rust_response.body);
            if go_body != rust_body {
                return Err(ParityError::ComparisonFailed {
                    case_name: case_name.to_owned(),
                    detail: format!("text mismatch: go={go_body:?} rust={rust_body:?}"),
                });
            }
        }
        BodyMode::Json => {
            let go_body = serde_json::from_slice::<Value>(&go_response.body)?;
            let rust_body = serde_json::from_slice::<Value>(&rust_response.body)?;
            if go_body != rust_body {
                return Err(ParityError::ComparisonFailed {
                    case_name: case_name.to_owned(),
                    detail: format!("json mismatch: go={go_body} rust={rust_body}"),
                });
            }
        }
    }

    Ok(())
}

fn filtered_headers(
    response: &ObservedResponse,
    ignore_headers: &BTreeSet<String>,
    ignore_set_cookie: bool,
) -> BTreeMap<String, Vec<String>> {
    response
        .headers
        .iter()
        .filter(|(name, _)| !ignore_headers.contains(name.as_str()))
        .filter(|(name, _)| !(ignore_set_cookie && name.as_str() == "set-cookie"))
        .map(|(name, values)| (name.clone(), values.clone()))
        .collect()
}

fn normalize_path(path: &str) -> String {
    let stripped = path
        .strip_prefix("/api/v2")
        .or_else(|| path.strip_prefix("/api/experimental"))
        .unwrap_or(path);
    let mut normalized = String::with_capacity(stripped.len());
    let mut characters = stripped.chars().peekable();

    while let Some(character) = characters.next() {
        match character {
            '%' => {
                for next in characters.by_ref() {
                    if next.is_ascii_alphabetic() {
                        break;
                    }
                }
                normalized.push('{');
                normalized.push('}');
            }
            '{' => {
                for next in characters.by_ref() {
                    if next == '}' {
                        break;
                    }
                }
                normalized.push('{');
                normalized.push('}');
            }
            _ => normalized.push(character),
        }
    }

    normalized
}

fn matches_scope(route_scope: RouteScope, selected_scope: InventoryScope) -> bool {
    match selected_scope {
        InventoryScope::Oss => route_scope == RouteScope::Oss,
        InventoryScope::Enterprise => route_scope == RouteScope::Enterprise,
        InventoryScope::All => true,
    }
}

fn go_live_path(path: &str) -> String {
    if path.starts_with("/.well-known/") || path.starts_with("/oauth2") {
        path.to_owned()
    } else {
        join_path("/api/v2", path)
    }
}

fn route_mount(live_path: &str) -> String {
    if live_path == "/api/v2" || live_path.starts_with("/api/v2/") {
        "/api/v2".to_owned()
    } else {
        String::new()
    }
}

fn join_path(prefix: &str, path: &str) -> String {
    if prefix.is_empty() {
        return path.to_owned();
    }
    if path == "/" {
        return prefix.to_owned();
    }
    format!("{prefix}{path}")
}

fn collect_files(root: &Path, extension: &str) -> Result<Vec<PathBuf>, ParityError> {
    let mut files = Vec::new();
    collect_files_inner(root, extension, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_files_inner(
    root: &Path,
    extension: &str,
    files: &mut Vec<PathBuf>,
) -> Result<(), ParityError> {
    for entry in read_dir(root)? {
        let entry = entry.map_err(|source| ParityError::Io {
            path: root.display().to_string(),
            source,
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|source| ParityError::Io {
            path: path.display().to_string(),
            source,
        })?;
        if file_type.is_dir() {
            collect_files_inner(&path, extension, files)?;
        } else if path
            .extension()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value == extension)
        {
            files.push(path);
        }
    }

    Ok(())
}

fn read_dir(root: &Path) -> Result<fs::ReadDir, ParityError> {
    fs::read_dir(root).map_err(|source| ParityError::Io {
        path: root.display().to_string(),
        source,
    })
}

fn read_to_string(path: &Path) -> Result<String, ParityError> {
    fs::read_to_string(path).map_err(|source| ParityError::Io {
        path: path.display().to_string(),
        source,
    })
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, ParityError> {
    let bytes = fs::read(path).map_err(|source| ParityError::Io {
        path: path.display().to_string(),
        source,
    })?;
    serde_json::from_slice(&bytes).map_err(ParityError::from)
}

fn write_file(path: &Path, content: &str) -> Result<(), ParityError> {
    fs::write(path, content).map_err(|source| ParityError::Io {
        path: path.display().to_string(),
        source,
    })
}

fn relative_display(path: &Path) -> String {
    path.strip_prefix(".").unwrap_or(path).display().to_string()
}

fn compile_regex(pattern: &str) -> Result<Regex, ParityError> {
    Regex::new(pattern).map_err(|error| ParityError::Regex(format!("{pattern}: {error}")))
}

impl RouteScope {
    fn as_str(self) -> &'static str {
        match self {
            Self::Oss => "oss",
            Self::Enterprise => "enterprise",
        }
    }
}

impl InventoryScope {
    fn display_name(self) -> &'static str {
        match self {
            Self::Oss => "OSS",
            Self::Enterprise => "Enterprise",
            Self::All => "Full",
        }
    }

    fn flag_value(self) -> &'static str {
        match self {
            Self::Oss => "oss",
            Self::Enterprise => "enterprise",
            Self::All => "all",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::{
        DepthStatus, GoRoute, InventoryScope, RouteScope, body_returns_not_implemented,
        classify_depth, classify_section, collect_rust_handler_routes_from_content,
        collect_rust_routes_from_content, extract_build_router_body, extract_fn_body,
        extract_method_handlers, extract_rust_methods, go_live_path, join_path, matches_scope,
        normalize_path, parse_go_routes,
    };

    #[test]
    fn normalize_path_strips_api_prefix_and_placeholders() {
        assert_eq!(
            normalize_path("/api/v2/users/{user}/workspace/%s/builds/%d"),
            "/users/{}/workspace/{}/builds/{}"
        );
    }

    #[test]
    fn normalize_path_preserves_non_api_paths() {
        assert_eq!(normalize_path("/derp-map"), "/derp-map");
    }

    #[test]
    fn rust_method_extraction_handles_multiple_methods() {
        let methods = extract_rust_methods(".route(\"/users/first\", get(first).post(create))");
        assert!(methods.contains("GET"));
        assert!(methods.contains("POST"));
        assert_eq!(methods.len(), 2);
    }

    #[test]
    fn rust_method_extraction_handles_multiline_route_blocks() {
        let methods = extract_rust_methods(
            ".route( \"/users/{user}/roles\", get(get_roles).put(put_roles), )",
        );
        assert!(methods.contains("GET"));
        assert!(methods.contains("PUT"));
        assert_eq!(methods.len(), 2);
    }

    #[test]
    fn go_route_parser_marks_enterprise_scope_and_live_path() -> Result<(), Box<dyn Error>> {
        let routes = parse_go_routes(
            "// @Tags Enterprise\n// @Router /oauth2/tokens [post]\n",
            "coder/coderd/oauth2.go",
        )?;
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].scope, RouteScope::Enterprise);
        assert_eq!(routes[0].live_path, "/oauth2/tokens");
        Ok(())
    }

    #[test]
    fn go_route_parser_mounts_api_root_routes_under_api_v2() -> Result<(), Box<dyn Error>> {
        let routes = parse_go_routes(
            "// @Tags General\n// @Router / [get]\n",
            "coder/coderd/apiroot.go",
        )?;
        assert_eq!(routes[0].live_path, "/api/v2");
        assert_eq!(go_live_path("/buildinfo"), "/api/v2/buildinfo");
        Ok(())
    }

    #[test]
    fn scope_filter_excludes_enterprise_from_oss_inventory() {
        assert!(matches_scope(RouteScope::Oss, InventoryScope::Oss));
        assert!(!matches_scope(RouteScope::Enterprise, InventoryScope::Oss));
        assert!(matches_scope(RouteScope::Enterprise, InventoryScope::All));
    }

    #[test]
    fn join_path_preserves_api_root_mount() {
        assert_eq!(join_path("/api/v2", "/"), "/api/v2");
        assert_eq!(join_path("/api/v2", "/users"), "/api/v2/users");
    }

    #[test]
    fn enterprise_routes_parsed_from_enterprise_coderd_files() -> Result<(), Box<dyn Error>> {
        let content = "// @Tags Enterprise\n// @Router /appearance [get]\n\
                        // @Tags Enterprise\n// @Router /appearance [put]\n";
        let routes = parse_go_routes(content, "coder/enterprise/coderd/appearance.go")?;
        assert_eq!(routes.len(), 2);
        assert!(routes.iter().all(|r| r.scope == RouteScope::Enterprise));
        assert_eq!(routes[0].method, "GET");
        assert_eq!(routes[1].method, "PUT");
        Ok(())
    }

    #[test]
    fn scope_filter_enterprise_only_returns_enterprise_routes() {
        assert!(!matches_scope(RouteScope::Oss, InventoryScope::Enterprise));
        assert!(matches_scope(
            RouteScope::Enterprise,
            InventoryScope::Enterprise
        ));
    }

    #[test]
    fn scope_filter_all_includes_both_oss_and_enterprise() {
        assert!(matches_scope(RouteScope::Oss, InventoryScope::All));
        assert!(matches_scope(RouteScope::Enterprise, InventoryScope::All));
    }

    #[test]
    fn merged_routes_are_deduplicated_by_method_and_normalized_path() {
        let mut routes = vec![
            GoRoute {
                method: "GET".to_owned(),
                path: "/users/{user}".to_owned(),
                live_path: "/api/v2/users/{user}".to_owned(),
                mount: "/api/v2".to_owned(),
                normalized_path: "/users/{}".to_owned(),
                source: "coder/coderd/users.go".to_owned(),
                scope: RouteScope::Oss,
            },
            GoRoute {
                method: "GET".to_owned(),
                path: "/users/{id}".to_owned(),
                live_path: "/api/v2/users/{id}".to_owned(),
                mount: "/api/v2".to_owned(),
                normalized_path: "/users/{}".to_owned(),
                source: "coder/enterprise/coderd/users.go".to_owned(),
                scope: RouteScope::Enterprise,
            },
        ];
        // Sort by normalized_path (matching dedup key) to ensure correct dedup
        routes.sort_by(|left, right| {
            left.normalized_path
                .cmp(&right.normalized_path)
                .then(left.method.cmp(&right.method))
                .then(left.source.cmp(&right.source))
        });
        routes.dedup_by(|a, b| a.method == b.method && a.normalized_path == b.normalized_path);
        assert_eq!(routes.len(), 1);
    }

    #[test]
    fn render_includes_go_dirs_flag_when_non_default() {
        let inventory = super::ParityInventory {
            scope: InventoryScope::All,
            summary: super::InventorySummary {
                go_route_pairs: 0,
                rust_route_pairs: 0,
                sdk_client_methods: 0,
                ported_route_pairs: 0,
                missing_route_pairs: 0,
            },
            rows: vec![],
            unmatched_sdk_methods: vec![],
        };
        let dirs = vec!["coderd".to_owned(), "enterprise/coderd".to_owned()];
        let md = super::render_inventory_markdown(&inventory, &dirs);
        assert!(md.contains("--go-dirs coderd,enterprise/coderd"));
    }

    #[test]
    fn render_omits_go_dirs_flag_when_default() {
        let inventory = super::ParityInventory {
            scope: InventoryScope::Oss,
            summary: super::InventorySummary {
                go_route_pairs: 0,
                rust_route_pairs: 0,
                sdk_client_methods: 0,
                ported_route_pairs: 0,
                missing_route_pairs: 0,
            },
            rows: vec![],
            unmatched_sdk_methods: vec![],
        };
        let dirs = vec!["coderd".to_owned()];
        let md = super::render_inventory_markdown(&inventory, &dirs);
        assert!(!md.contains("--go-dirs"));
    }

    #[test]
    fn merge_blocks_detect_routes_at_current_prefix() -> Result<(), Box<dyn Error>> {
        let content = r#"
            .route("/audit", get(list_audit_logs))
            .merge(axum::Router::new()
                .route("/connectionlog", get(list_connection_logs))
                .route_layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    crate::middleware::require_feature_connection_log,
                ))
            )
            .route("/telemetry", get(get_telemetry_status))
        "#;
        let mut routes = Vec::new();
        collect_rust_routes_from_content(content, "/api/v2", "app.rs", &mut routes)?;
        let paths: Vec<&str> = routes.iter().map(|r| r.live_path.as_str()).collect();
        assert!(
            paths.contains(&"/api/v2/connectionlog"),
            "expected /api/v2/connectionlog in {paths:?}"
        );
        assert!(paths.contains(&"/api/v2/audit"));
        assert!(paths.contains(&"/api/v2/telemetry"));
        assert_eq!(routes.len(), 3);
        Ok(())
    }

    #[test]
    fn merge_blocks_detect_multiple_routes() -> Result<(), Box<dyn Error>> {
        let content = r#"
            .merge(axum::Router::new()
                .route("/groups", get(list_all_groups))
                .route("/groups/{group}", get(get_group).patch(patch_group).delete(delete_group))
                .route_layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    crate::middleware::require_feature_template_rbac,
                ))
            )
        "#;
        let mut routes = Vec::new();
        collect_rust_routes_from_content(content, "/api/v2", "app.rs", &mut routes)?;
        assert_eq!(routes.len(), 2);
        assert!(routes.iter().any(|r| r.live_path == "/api/v2/groups"));
        let group_route = routes
            .iter()
            .find(|r| r.live_path == "/api/v2/groups/{group}")
            .ok_or("missing /api/v2/groups/{group}")?;
        assert!(group_route.methods.contains("GET"));
        assert!(group_route.methods.contains("PATCH"));
        assert!(group_route.methods.contains("DELETE"));
        Ok(())
    }

    #[test]
    fn merge_inside_nest_inherits_nested_prefix() -> Result<(), Box<dyn Error>> {
        let content = r#"
            .nest("/api/v2", Router::new()
                .route("/audit", get(list_audit_logs))
                .merge(axum::Router::new()
                    .route("/connectionlog", get(list_connection_logs))
                    .route_layer(axum::middleware::from_fn_with_state(
                        state.clone(),
                        crate::middleware::require_feature_connection_log,
                    ))
                )
            )
        "#;
        let mut routes = Vec::new();
        collect_rust_routes_from_content(content, "", "app.rs", &mut routes)?;
        let paths: Vec<&str> = routes.iter().map(|r| r.live_path.as_str()).collect();
        assert!(
            paths.contains(&"/api/v2/connectionlog"),
            "merge inside nest should inherit /api/v2 prefix, got {paths:?}"
        );
        assert!(paths.contains(&"/api/v2/audit"));
        assert_eq!(routes.len(), 2);
        Ok(())
    }

    #[test]
    fn merge_without_router_new_produces_no_routes() -> Result<(), Box<dyn Error>> {
        let content = r#"
            .route("/before", get(before_handler))
            .merge(enterprise_routes(state.clone()))
            .route("/after", get(after_handler))
        "#;
        let mut routes = Vec::new();
        collect_rust_routes_from_content(content, "/api/v2", "app.rs", &mut routes)?;
        let paths: Vec<&str> = routes.iter().map(|r| r.live_path.as_str()).collect();
        assert!(
            !paths.iter().any(|p| p.contains("enterprise")),
            "merge without Router::new() should not produce routes"
        );
        assert!(paths.contains(&"/api/v2/before"));
        assert!(paths.contains(&"/api/v2/after"));
        assert_eq!(routes.len(), 2);
        Ok(())
    }

    #[test]
    fn single_line_merge_block_detected() -> Result<(), Box<dyn Error>> {
        let content = r#".merge(Router::new().route("/connectionlog", get(list_connection_logs)))"#;
        let mut routes = Vec::new();
        collect_rust_routes_from_content(content, "/api/v2", "app.rs", &mut routes)?;
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].live_path, "/api/v2/connectionlog");
        assert!(routes[0].methods.contains("GET"));
        Ok(())
    }

    #[test]
    fn no_duplicate_routes_from_merge_blocks() -> Result<(), Box<dyn Error>> {
        // Ensure routes inside .merge() are only counted once (via recursive
        // processing), not also by the outer .route() scan.
        let content = r#"
            .route("/before", get(handler_a))
            .merge(axum::Router::new()
                .route("/connectionlog", get(list_connection_logs))
                .route_layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    crate::middleware::require_feature_connection_log,
                ))
            )
            .route("/after", get(handler_b))
        "#;
        let mut routes = Vec::new();
        collect_rust_routes_from_content(content, "/api/v2", "app.rs", &mut routes)?;
        let connectionlog_count = routes
            .iter()
            .filter(|r| r.live_path == "/api/v2/connectionlog")
            .count();
        assert_eq!(
            connectionlog_count, 1,
            "connectionlog should appear exactly once, not duplicated"
        );
        assert_eq!(routes.len(), 3);
        Ok(())
    }

    #[test]
    fn merge_containing_nest_works_recursively() -> Result<(), Box<dyn Error>> {
        let content = r#"
            .merge(Router::new()
                .nest("/orgs", Router::new()
                    .route("/groups", get(list_groups))
                )
            )
        "#;
        let mut routes = Vec::new();
        collect_rust_routes_from_content(content, "/api/v2", "app.rs", &mut routes)?;
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].live_path, "/api/v2/orgs/groups");
        Ok(())
    }

    #[test]
    fn depth_classifier_returns_complete_for_non_stub_body() {
        let body = "{ let data = state.store.query().await?; Ok(Json(data).into_response()) }";
        let (status, notes) = classify_depth("some_handler", Some(body));
        assert_eq!(status, DepthStatus::Complete);
        assert!(notes.is_none());
    }

    #[test]
    fn depth_classifier_detects_501_body() {
        let body = "{ Ok((StatusCode::NOT_IMPLEMENTED, Json(err)).into_response()) }";
        let (status, _notes) = classify_depth("some_handler", Some(body));
        assert_eq!(status, DepthStatus::Stub501);
    }

    #[test]
    fn depth_classifier_ignores_comments_in_body() {
        // A `// StatusCode::NOT_IMPLEMENTED` in a comment should NOT trigger the
        // 501 classification — only real occurrences in code do.
        let body = "{ // TODO: return StatusCode::NOT_IMPLEMENTED once wired\n Ok(Json(x).into_response()) }";
        let (status, _notes) = classify_depth("some_handler", Some(body));
        assert_eq!(status, DepthStatus::Complete);
    }

    #[test]
    fn depth_classifier_flags_known_partial_handler() {
        let body = "{ Ok(Json(quota).into_response()) }";
        let (status, notes) = classify_depth("get_workspace_quota", Some(body));
        assert_eq!(status, DepthStatus::StubPartial);
        assert!(notes.is_some());
    }

    #[test]
    fn depth_partial_list_is_stable() {
        // Guard against accidental duplication / ordering regressions.
        let (status, notes) = classify_depth("get_replicas", None);
        assert_eq!(status, DepthStatus::StubPartial);
        assert!(notes.is_some());
    }

    #[test]
    fn body_returns_not_implemented_matches_token() {
        assert!(body_returns_not_implemented(
            "Ok((StatusCode::NOT_IMPLEMENTED, body).into_response())"
        ));
    }

    #[test]
    fn body_returns_not_implemented_skips_comment_only_occurrence() {
        let body = "// could eventually return StatusCode::NOT_IMPLEMENTED\nreturn something;";
        assert!(!body_returns_not_implemented(body));
    }

    #[test]
    fn extract_build_router_body_captures_matching_braces() {
        let content = r#"
            fn noise() { let _ = 1; }

            pub fn build_router(state: AppState) -> Router {
                Router::new()
                    .route("/x", get(x))
            }

            fn trailer() {}
        "#;
        let body = extract_build_router_body(content).unwrap_or_default();
        assert!(!body.is_empty(), "expected non-empty body");
        assert!(body.contains("Router::new()"));
        assert!(body.contains(".route(\"/x\", get(x))"));
        // Make sure we didn't leak into `fn trailer`.
        assert!(!body.contains("fn trailer"));
    }

    #[test]
    fn extract_method_handlers_parses_basic_route() {
        let handlers = extract_method_handlers(".route(\"/a\", get(list_a).post(create_a))");
        assert!(handlers.contains(&("GET".to_owned(), "list_a".to_owned())));
        assert!(handlers.contains(&("POST".to_owned(), "create_a".to_owned())));
    }

    #[test]
    fn extract_method_handlers_skips_inline_closures() {
        // Bare identifiers only — closures and non-identifier args are ignored.
        let handlers = extract_method_handlers(".route(\"/a\", get(|| async { \"ok\" }))");
        assert!(handlers.is_empty());
    }

    #[test]
    fn extract_fn_body_handles_nested_braces() {
        let content = "fn hello(x: i32) -> i32 { { x + 1 } }";
        let body = extract_fn_body(content, 0).unwrap_or_default();
        assert!(!body.is_empty(), "expected non-empty body");
        assert_eq!(body, "{ { x + 1 } }");
    }

    #[test]
    fn collect_rust_handler_routes_finds_nested_routes() -> Result<(), Box<dyn Error>> {
        let content = r#"
            Router::new()
                .route("/top", get(top))
                .nest("/api/v2", Router::new()
                    .route("/users", get(list_users).post(create_user))
                )
        "#;
        let mut routes = Vec::new();
        collect_rust_handler_routes_from_content(content, "", &mut routes)?;
        let paths: Vec<&str> = routes.iter().map(|r| r.live_path.as_str()).collect();
        assert!(paths.contains(&"/top"));
        assert!(paths.contains(&"/api/v2/users"));
        // Two methods on `/api/v2/users` should produce two rows.
        assert_eq!(
            routes
                .iter()
                .filter(|r| r.live_path == "/api/v2/users")
                .count(),
            2
        );
        Ok(())
    }

    #[test]
    fn classify_section_buckets_common_prefixes() {
        assert_eq!(classify_section("/api/v2/users"), "Users & Identity");
        assert_eq!(
            classify_section("/api/v2/oauth2-provider/apps"),
            "OAuth2 Provider",
        );
        assert_eq!(
            classify_section("/api/v2/settings/idpsync/organization"),
            "Deployment Settings & IDP Sync",
        );
        assert_eq!(classify_section("/healthz"), "Root / Health");
        assert_eq!(classify_section("/scim/v2/Users"), "SCIM");
    }
}
