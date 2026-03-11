//! HTTP middleware functions.

use crate::helpers::forbidden_response;
use axum::{
    Json,
    http::{HeaderName, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use coder_core::ApiResponse;
use std::net::IpAddr;

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

/// Middleware: record basic Prometheus-style HTTP metrics using the `metrics`
/// crate.  Counters and histograms are registered lazily on first use.
pub(crate) async fn prometheus_middleware(request: axum::extract::Request, next: Next) -> Response {
    let method = request.method().to_string();
    let path = request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|m| m.as_str().to_owned())
        .unwrap_or_else(|| "unmatched".to_owned());

    let start = std::time::Instant::now();
    let response = next.run(request).await;
    let elapsed = start.elapsed().as_secs_f64();

    let status = response.status().as_u16().to_string();

    metrics::counter!(
        "coderd_api_requests_processed_total",
        "code" => status,
        "method" => method.clone(),
        "path" => path.clone(),
    )
    .increment(1);

    metrics::histogram!(
        "coderd_api_request_latencies_seconds",
        "method" => method,
        "path" => path,
    )
    .record(elapsed);

    response
}
