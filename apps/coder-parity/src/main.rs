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
    }
}

fn run_inventory(args: InventoryArgs) -> Result<(), ParityError> {
    let inventory = build_inventory(
        &args.go_root,
        &args.rust_root,
        match args.scope {
            InventoryScopeArg::Oss => InventoryScope::Oss,
            InventoryScopeArg::Enterprise => InventoryScope::Enterprise,
            InventoryScopeArg::All => InventoryScope::All,
        },
    )?;
    let markdown = render_inventory_markdown(&inventory);

    if let Some(output) = args.output {
        write_file(&output, &markdown)?;
    } else {
        print!("{markdown}");
    }

    Ok(())
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
) -> Result<ParityInventory, ParityError> {
    let go_routes = collect_go_routes(&go_root.join("coderd"), scope)?;
    let client_methods = collect_client_methods(&go_root.join("codersdk"))?;
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

    routes.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.method.cmp(&right.method))
            .then(left.source.cmp(&right.source))
    });
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
    let mut paren_balance = 0i32;
    let mut index = start;

    while index < lines.len() {
        let line = lines[index].trim();
        if !block.is_empty() {
            block.push('\n');
        }
        block.push_str(line);
        #[allow(clippy::cast_possible_truncation)]
        {
            paren_balance += line.chars().filter(|character| *character == '(').count() as i32;
            paren_balance -= line.chars().filter(|character| *character == ')').count() as i32;
        }
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

fn render_inventory_markdown(inventory: &ParityInventory) -> String {
    let mut markdown = String::new();
    markdown.push_str(&format!(
        "# {} Parity Matrix\n\n",
        inventory.scope.display_name()
    ));
    markdown.push_str(&format!(
        "Generated by `cargo run -p coder-parity -- inventory --go-root coder --rust-root . --scope {}`.\n\n",
        inventory.scope.flag_value()
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
        InventoryScope, RouteScope, extract_rust_methods, go_live_path, join_path, matches_scope,
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
}
