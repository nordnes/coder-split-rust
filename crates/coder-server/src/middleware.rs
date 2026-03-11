//! HTTP middleware functions.

use crate::helpers::forbidden_response;
use axum::{
    http::{HeaderName, HeaderValue},
    middleware::Next,
    response::Response,
};
use coder_core::config::CorsConfig;
use http::Method;
use http::header::HeaderMap;
use std::net::IpAddr;
use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer, ExposeHeaders};
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// Builds a [`CorsLayer`] from the given [`CorsConfig`].
///
/// When `allowed_origins` is empty the layer allows every origin (wildcard).
/// Otherwise only the listed origins are permitted.
///
/// If `allowed_origins` is non-empty but **all** entries fail
/// [`HeaderValue::from_str`] validation, the layer falls back to an empty
/// allow-list that blocks every cross-origin request rather than silently
/// opening up to all origins.  A warning is logged for each rejected origin.
pub(crate) fn build_cors_layer(config: &CorsConfig) -> CorsLayer {
    // Filter origins up-front so that invalid values (non-visible-ASCII, etc.)
    // are dropped before we decide between wildcard and explicit-list mode.
    let valid_origins: Vec<HeaderValue> = config
        .allowed_origins
        .iter()
        .filter_map(|o| match HeaderValue::from_str(o) {
            Ok(v) => Some(v),
            Err(err) => {
                tracing::warn!(
                    origin = %o,
                    error = %err,
                    "ignoring invalid CORS origin (not a valid HTTP header value)"
                );
                None
            }
        })
        .collect();

    // Decide between wildcard, explicit-list, or restrictive fallback.
    let explicitly_configured = !config.allowed_origins.is_empty();
    let allow_origin = if !explicitly_configured {
        // Operator did not restrict origins → wildcard.
        AllowOrigin::any()
    } else if valid_origins.is_empty() {
        // Operator intended to restrict origins but every entry was invalid.
        // Falling back to wildcard would silently weaken security, so we use
        // an empty list that blocks all cross-origin requests.
        tracing::warn!(
            "all configured CORS origins were invalid; \
             cross-origin requests will be blocked"
        );
        AllowOrigin::list(Vec::<HeaderValue>::new())
    } else {
        AllowOrigin::list(valid_origins.clone())
    };

    let allow_methods = AllowMethods::list([
        Method::GET,
        Method::POST,
        Method::PUT,
        Method::PATCH,
        Method::DELETE,
        Method::HEAD,
        Method::OPTIONS,
    ]);

    let allow_headers = AllowHeaders::list([
        HeaderName::from_static("content-type"),
        HeaderName::from_static("authorization"),
        HeaderName::from_static("coder-session-token"),
        HeaderName::from_static("accept"),
        HeaderName::from_static("x-csrf-token"),
    ]);

    let expose_headers = ExposeHeaders::list([
        HeaderName::from_static("content-range"),
        HeaderName::from_static("x-content-type-options"),
    ]);

    let mut layer = CorsLayer::new()
        .allow_origin(allow_origin)
        .allow_methods(allow_methods)
        .allow_headers(allow_headers)
        .expose_headers(expose_headers)
        .max_age(std::time::Duration::from_secs(config.max_age_secs));

    if config.allow_credentials && !valid_origins.is_empty() {
        layer = layer.allow_credentials(true);
    }

    layer
}

/// Stored in request extensions so downstream handlers can read the real
/// client IP even when the server is behind a reverse proxy.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(crate) struct RealIp(pub(crate) IpAddr);

/// Middleware: extract the real client IP from X-Forwarded-For / X-Real-IP
/// headers and store it in request extensions.
pub(crate) async fn real_ip_middleware(
    mut request: axum::extract::Request,
    next: Next,
) -> Response {
    let ip = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
        .or_else(|| {
            request
                .headers()
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.trim().parse::<IpAddr>().ok())
        });

    if let Some(ip) = ip {
        request.extensions_mut().insert(RealIp(ip));
    }

    next.run(request).await
}

/// Middleware: set Content-Security-Policy on every response.
pub(crate) async fn csp_middleware(request: axum::extract::Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    // Use a restrictive default policy; callers can override per-route if needed.
    if let Ok(value) =
        HeaderValue::from_str("default-src 'self'; frame-ancestors 'none'; form-action 'self'")
    {
        response
            .headers_mut()
            .insert(HeaderName::from_static("content-security-policy"), value);
    }
    response
}

/// Middleware: add Strict-Transport-Security header when the request arrived
/// over HTTPS (indicated by scheme or X-Forwarded-Proto).
pub(crate) async fn hsts_middleware(request: axum::extract::Request, next: Next) -> Response {
    let is_https = request
        .uri()
        .scheme_str()
        .map(|s| s == "https")
        .unwrap_or(false)
        || request
            .headers()
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(|v| v.trim().eq_ignore_ascii_case("https"))
            .unwrap_or(false);

    let mut response = next.run(request).await;

    if is_https {
        if let Ok(value) = HeaderValue::from_str("max-age=31536000; includeSubDomains") {
            response
                .headers_mut()
                .insert(HeaderName::from_static("strict-transport-security"), value);
        }
    }

    response
}

/// Middleware: CSRF protection – require a non-empty X-CSRF-Token header on
/// mutating requests (POST / PUT / DELETE / PATCH) that carry cookie-based
/// authentication.
///
/// Pre-authentication endpoints are exempt because the browser may still hold
/// an expired session cookie when the user tries to log in again, and there is
/// no way for the client to obtain a CSRF token before authenticating.  CSP
/// violation reports are also exempt because browsers send them automatically
/// without custom headers.
pub(crate) async fn csrf_middleware(request: axum::extract::Request, next: Next) -> Response {
    use http::Method;

    /// Paths that are exempt from CSRF validation.  These are either
    /// pre-authentication endpoints or browser-initiated reports that cannot
    /// carry custom headers.
    const CSRF_EXEMPT_PATHS: &[&str] = &[
        "/api/v2/users/login",
        "/api/v2/users/first",
        "/api/v2/users/otp/request",
        "/api/v2/users/otp/change-password",
        "/api/v2/csp/reports",
        "/oauth2/tokens",
    ];

    let path = request.uri().path();
    let is_exempt = CSRF_EXEMPT_PATHS.contains(&path);

    if is_exempt {
        return next.run(request).await;
    }

    let is_mutating_method = matches!(
        *request.method(),
        Method::POST | Method::PUT | Method::DELETE | Method::PATCH
    );

    let has_cookie = request.headers().contains_key(http::header::COOKIE);

    if is_mutating_method && has_cookie {
        let has_csrf = request
            .headers()
            .get("x-csrf-token")
            .and_then(|v| v.to_str().ok())
            .map(|v| !v.is_empty())
            .unwrap_or(false);

        if !has_csrf {
            return forbidden_response(
                "CSRF token required for cookie-authenticated mutating requests.",
            );
        }
    }

    next.run(request).await
}

// ---------------------------------------------------------------------------
// Zero-copy OTel propagation helpers
// ---------------------------------------------------------------------------

/// Zero-copy [`opentelemetry::propagation::Extractor`] backed by an Axum
/// [`HeaderMap`].  Avoids cloning all request headers into a `HashMap` on
/// every request.
struct HeaderExtractor<'a>(&'a HeaderMap);

impl opentelemetry::propagation::Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|k| k.as_str()).collect()
    }
}

/// Zero-copy [`opentelemetry::propagation::Injector`] that writes directly
/// into an Axum [`HeaderMap`].
struct HeaderInjector<'a>(&'a mut HeaderMap);

impl opentelemetry::propagation::Injector for HeaderInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        if let (Ok(name), Ok(val)) = (HeaderName::try_from(key), HeaderValue::from_str(&value)) {
            self.0.insert(name, val);
        }
    }
}

/// Middleware: propagate W3C TraceContext from incoming request headers into
/// the current `tracing` span and echo `traceparent` / `tracestate` back on
/// the response so downstream services can continue the trace.
///
/// This middleware should only be added to the router when OTel is enabled
/// (see [`crate::build_router`]).  It uses zero-copy [`HeaderExtractor`] and
/// [`HeaderInjector`] wrappers to avoid per-request `HashMap` allocations.
pub(crate) async fn otel_trace_context_middleware(
    request: axum::extract::Request,
    next: Next,
) -> Response {
    // Extract incoming propagation headers directly from the HeaderMap.
    let parent_cx = opentelemetry::global::get_text_map_propagator(|propagator| {
        propagator.extract(&HeaderExtractor(request.headers()))
    });

    // Attach the extracted context to the current tracing span so that the
    // OTel layer records it as the parent.
    //
    // `set_parent` returns `Err(SetParentError::LayerNotFound)` when the
    // `tracing-opentelemetry` layer is not present in the subscriber, or
    // `AlreadyStarted` / `SpanDisabled` in other edge cases.  Because this
    // middleware is only wired when OTel is enabled, `LayerNotFound` should
    // not occur in practice, but we still discard the result defensively.
    let _ = tracing::Span::current().set_parent(parent_cx);

    let mut response = next.run(request).await;

    // Inject the current span context into the response headers so callers
    // (and browser devtools) can see the trace.
    let cx = tracing::Span::current().context();
    opentelemetry::global::get_text_map_propagator(|propagator| {
        propagator.inject_context(&cx, &mut HeaderInjector(response.headers_mut()));
    });

    response
}

/// Middleware: record Prometheus-compatible HTTP metrics using the `metrics`
/// crate.  Counters and histograms are registered lazily on first use.
/// Tracks per-request latency, status codes, and active connection count.
pub(crate) async fn prometheus_middleware(request: axum::extract::Request, next: Next) -> Response {
    let method = request.method().to_string();
    let path = request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|m| m.as_str().to_owned())
        .unwrap_or_else(|| "unmatched".to_owned());

    metrics::gauge!("active_connections").increment(1.0);

    let start = std::time::Instant::now();
    let response = next.run(request).await;
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;

    metrics::gauge!("active_connections").decrement(1.0);

    let status = response.status().as_u16();
    crate::metrics::record_request(&method, &path, status, elapsed_ms);

    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, middleware, routing::get};
    use http::{Request, StatusCode};
    use tower::ServiceExt;

    /// Tiny handler that returns 200 OK for every request.
    async fn ok_handler() -> StatusCode {
        StatusCode::OK
    }

    #[tokio::test]
    async fn otel_middleware_returns_200_without_trace_headers() {
        let app = Router::new()
            .route("/ping", get(ok_handler))
            .layer(middleware::from_fn(otel_trace_context_middleware));

        let request = Request::builder()
            .uri("/ping")
            .body(Body::empty())
            .unwrap_or_else(|_| unreachable!());

        let response = app
            .oneshot(request)
            .await
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn otel_middleware_passes_through_request_with_traceparent() {
        let app = Router::new()
            .route("/ping", get(ok_handler))
            .layer(middleware::from_fn(otel_trace_context_middleware));

        let request = Request::builder()
            .uri("/ping")
            .header(
                "traceparent",
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            )
            .body(Body::empty())
            .unwrap_or_else(|_| unreachable!());

        let response = app
            .oneshot(request)
            .await
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// Verify that when a W3C `TraceContextPropagator` is installed globally
    /// and the tracing subscriber includes an OTel layer, the middleware
    /// echoes `traceparent` back on the response and preserves the trace-id
    /// from the incoming header.
    ///
    /// NOTE: This test installs a global propagator and a process-wide
    /// default subscriber.  In practice the other tests in this module use
    /// the default no-op propagator and are unaffected.
    #[tokio::test]
    async fn otel_middleware_echoes_traceparent_when_propagator_set() {
        use opentelemetry::trace::TracerProvider;
        use opentelemetry_sdk::trace::SdkTracerProvider;
        use tracing_subscriber::layer::SubscriberExt;

        // Install the W3C propagator for this test.
        opentelemetry::global::set_text_map_propagator(
            opentelemetry_sdk::propagation::TraceContextPropagator::new(),
        );

        // Build a minimal tracer provider (no exporter needed — we only care
        // about context propagation, not span export).
        let provider = SdkTracerProvider::builder().build();
        let otel_layer = tracing_opentelemetry::layer().with_tracer(provider.tracer("test"));

        // Install a subscriber that includes the OTel layer so that
        // `set_parent` / `context()` actually propagate trace context.
        let subscriber = tracing_subscriber::registry().with(otel_layer);

        // Use `set_default` to scope the dispatcher to this test without
        // needing `block_on` (which panics inside a tokio runtime).
        let dispatch = tracing::dispatcher::Dispatch::new(subscriber);
        let _guard = tracing::dispatcher::set_default(&dispatch);

        let traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

        // Wrap in a tracing span so that `Span::current()` inside the
        // middleware has a real span to attach the parent context to.
        let test_span = tracing::info_span!("test_request");
        let _enter = test_span.enter();

        let app = Router::new()
            .route("/ping", get(ok_handler))
            .layer(middleware::from_fn(otel_trace_context_middleware));

        let request = Request::builder()
            .uri("/ping")
            .header("traceparent", traceparent)
            .body(Body::empty())
            .unwrap_or_else(|_| unreachable!());

        let response = app
            .oneshot(request)
            .await
            .unwrap_or_else(|_| unreachable!());

        assert_eq!(response.status(), StatusCode::OK);

        // The response must contain a traceparent header.
        let resp_traceparent = response
            .headers()
            .get("traceparent")
            .map(|v| v.to_str().unwrap_or_else(|_| unreachable!()));

        assert!(
            resp_traceparent.is_some(),
            "response should include a traceparent header when propagator is set"
        );

        // Verify the response traceparent is well-formed W3C TraceContext:
        // version-traceid-spanid-traceflags (4 hyphen-separated fields).
        let parts: Vec<&str> = resp_traceparent
            .unwrap_or_else(|| unreachable!())
            .split('-')
            .collect();

        assert_eq!(
            parts.len(),
            4,
            "traceparent should have 4 fields (version-traceid-spanid-flags)"
        );
        assert_eq!(parts[0], "00", "version should be 00");
        assert_eq!(parts[1].len(), 32, "trace-id should be 32 hex chars");
        assert_eq!(parts[2].len(), 16, "span-id should be 16 hex chars");
    }
}
