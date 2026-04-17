//! Criterion benchmarks for Axum route matching.
//!
//! These benchmarks build the full production router (256+ registered routes)
//! and measure request dispatch latency for common endpoint patterns.
//! Request construction is separated from the timed dispatch via `iter_batched`
//! so that only `app.clone().oneshot(req)` is measured.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use criterion::{BatchSize, Criterion, black_box, criterion_group, criterion_main};
use http::Request;
use tower::ServiceExt;
use uuid::Uuid;

use coder_benchmarks::BenchStore;
use coder_connectivity::tailnet::{DerpTrafficTracker, InMemoryCoordinator};
use coder_core::config::{DatabaseConfig, LogFormat, SshConfig};
use coder_core::ports::AppStore;
use coder_core::pubsub::InMemoryPubSub;
use coder_core::{BuildMetadata, ServerConfig};
use coder_server::{AppState, build_router};

/// Constructs a minimal `AppState` backed by `BenchStore` for router benchmarks.
fn bench_app_state() -> AppState {
    let store: Arc<dyn AppStore> = Arc::new(BenchStore::new());
    let audit: Arc<dyn coder_audit::AuditSink> = Arc::new(coder_audit::TracingAuditSink);
    let pubsub: Arc<dyn coder_core::pubsub::PubSub> = Arc::new(InMemoryPubSub::new());
    let agent_provider: Arc<dyn coder_connectivity::agents::AgentProvider> =
        Arc::new(coder_connectivity::agents::InMemoryAgentProvider::new());
    let coordinator = InMemoryCoordinator::new(Default::default());
    let derp_tracker = DerpTrafficTracker::new();
    let derp_server = coder_connectivity::derp::DerpServer::new(
        coder_connectivity::derp::NodeKey::new([0u8; 32]),
    );

    let config = ServerConfig {
        listen_addr: std::net::SocketAddr::from(([127, 0, 0, 1], 3000)),
        access_url: url::Url::parse("http://127.0.0.1:3000")
            .unwrap_or_else(|_| std::process::abort()),
        wildcard_access_url: String::new(),
        database: DatabaseConfig {
            postgres_url: "postgres://unused".to_owned(),
            max_connections: 20,
            min_connections: 1,
            acquire_timeout_secs: 10,
        },
        tls: coder_core::config::TlsConfig::default(),
        networking: coder_core::config::NetworkingConfig::default(),
        http_cookies: coder_core::config::HttpCookieConfig::default(),
        telemetry: coder_core::config::TelemetryConfig::default(),
        ssh: SshConfig {
            hostname_prefix: "coder".to_owned(),
            hostname_suffix: "example.internal".to_owned(),
            ssh_config_options: HashMap::from([(
                "StrictHostKeyChecking".to_owned(),
                "no".to_owned(),
            )]),
        },
        external_auth_providers: Vec::new(),
        derp_regions: Vec::new(),
        shutdown_grace_period_secs: 10,
        log_format: LogFormat::Pretty,
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
        worker: coder_core::config::WorkerConfig::default(),
        swagger_enabled: false,
        update_check: false,
        update_check_interval_secs: 24 * 60 * 60,
        update_check_url: "https://api.github.com/repos/coder/coder/releases/latest".to_owned(),
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
        verify_instance_identity: false,
        aws_instance_identity_certs_dir: None,
    };

    AppState::new(
        config,
        BuildMetadata::default(),
        Uuid::nil(),
        store,
        audit,
        pubsub,
        agent_provider,
        coordinator,
        derp_tracker,
        derp_server,
        None,
        coder_telemetry::TelemetryReporter::disabled(Uuid::nil()),
        std::sync::Arc::new(coder_license::EntitlementSet::new()),
    )
    .unwrap_or_else(|_| std::process::abort())
}

/// Helper to build a GET request for the given URI.
/// Aborts on failure to satisfy workspace `unwrap_used`/`expect_used` deny lints.
fn build_get_request(uri: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .unwrap_or_else(|_| std::process::abort())
}

fn bench_router_build(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|_| std::process::abort());

    let state = rt.block_on(async { bench_app_state() });

    c.bench_function("routing/build_router", |b| {
        b.iter(|| {
            let _ = build_router(black_box(state.clone()), None);
        });
    });
}

fn bench_route_match_buildinfo(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|_| std::process::abort());

    let state = rt.block_on(async { bench_app_state() });
    let app = build_router(state, None);

    c.bench_function("routing/match_api_v2_buildinfo", |b| {
        b.iter_batched(
            || build_get_request("/api/v2/buildinfo"),
            |req| {
                rt.block_on(async {
                    let app = app.clone();
                    let _ = app.oneshot(black_box(req)).await;
                });
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_route_match_users_me(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|_| std::process::abort());

    let state = rt.block_on(async { bench_app_state() });
    let app = build_router(state, None);

    c.bench_function("routing/match_api_v2_users_me", |b| {
        b.iter_batched(
            || build_get_request("/api/v2/users/me"),
            |req| {
                rt.block_on(async {
                    let app = app.clone();
                    let _ = app.oneshot(black_box(req)).await;
                });
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_route_match_template_versions(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|_| std::process::abort());

    let state = rt.block_on(async { bench_app_state() });
    let app = build_router(state, None);
    let tv_id = Uuid::new_v4();
    let uri = format!("/api/v2/templateversions/{tv_id}/parameters");

    c.bench_function("routing/match_templateversions_params", |b| {
        b.iter_batched(
            || build_get_request(&uri),
            |req| {
                rt.block_on(async {
                    let app = app.clone();
                    let _ = app.oneshot(black_box(req)).await;
                });
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_route_match_workspace_builds(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|_| std::process::abort());

    let state = rt.block_on(async { bench_app_state() });
    let app = build_router(state, None);
    let ws_id = Uuid::new_v4();
    let uri = format!("/api/v2/workspaces/{ws_id}/builds");

    c.bench_function("routing/match_workspace_builds", |b| {
        b.iter_batched(
            || build_get_request(&uri),
            |req| {
                rt.block_on(async {
                    let app = app.clone();
                    let _ = app.oneshot(black_box(req)).await;
                });
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_route_match_healthz(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|_| std::process::abort());

    let state = rt.block_on(async { bench_app_state() });
    let app = build_router(state, None);

    c.bench_function("routing/match_healthz", |b| {
        b.iter_batched(
            || build_get_request("/healthz"),
            |req| {
                rt.block_on(async {
                    let app = app.clone();
                    let _ = app.oneshot(black_box(req)).await;
                });
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_route_match_org_templates(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|_| std::process::abort());

    let state = rt.block_on(async { bench_app_state() });
    let app = build_router(state, None);
    let org_id = Uuid::new_v4();
    let uri = format!("/api/v2/organizations/{org_id}/templates");

    c.bench_function("routing/match_org_templates", |b| {
        b.iter_batched(
            || build_get_request(&uri),
            |req| {
                rt.block_on(async {
                    let app = app.clone();
                    let _ = app.oneshot(black_box(req)).await;
                });
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_route_no_match(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|_| std::process::abort());

    let state = rt.block_on(async { bench_app_state() });
    let app = build_router(state, None);

    c.bench_function("routing/no_match_404", |b| {
        b.iter_batched(
            || build_get_request("/api/v2/nonexistent/route/that/does/not/exist"),
            |req| {
                rt.block_on(async {
                    let app = app.clone();
                    let _ = app.oneshot(black_box(req)).await;
                });
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(
    routing_benches,
    bench_router_build,
    bench_route_match_buildinfo,
    bench_route_match_users_me,
    bench_route_match_template_versions,
    bench_route_match_workspace_builds,
    bench_route_match_healthz,
    bench_route_match_org_templates,
    bench_route_no_match,
);

criterion_main!(routing_benches);
