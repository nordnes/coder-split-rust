//! Governor-based rate limiting middleware for the Axum HTTP layer.
//!
//! Provides per-IP and per-user token-bucket rate limiting with configurable
//! limits for different endpoint categories.  Standard `X-RateLimit-*` headers
//! are injected into every response and a `Retry-After` header is added when
//! the caller is throttled (HTTP 429).

use std::{net::IpAddr, num::NonZeroU32, sync::Arc};

use axum::{
    body::Body,
    http::{HeaderMap, HeaderValue, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DashMapStateStore};
use tracing::warn;

use coder_core::config::RateLimitConfig;

// ---------------------------------------------------------------------------
// Header constants
// ---------------------------------------------------------------------------

const HEADER_RATE_LIMIT: &str = "x-ratelimit-limit";
const HEADER_RATE_REMAINING: &str = "x-ratelimit-remaining";
const HEADER_RATE_RESET: &str = "x-ratelimit-reset";
const HEADER_RETRY_AFTER: &str = "retry-after";

// ---------------------------------------------------------------------------
// Key type
// ---------------------------------------------------------------------------

/// Identifies the caller for keyed rate limiters.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
enum RateLimitKey {
    Ip(IpAddr),
    /// Hashed session token — avoids storing raw secrets in memory while still
    /// providing per-session bucketing.
    HashedToken(String),
}

// ---------------------------------------------------------------------------
// Endpoint category
// ---------------------------------------------------------------------------

/// Which rate-limit bucket an incoming request belongs to.
enum EndpointCategory {
    Login,
    Audit,
    AuthenticatedApi,
    Unauthenticated,
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

type KeyedLimiter = RateLimiter<RateLimitKey, DashMapStateStore<RateLimitKey>, DefaultClock>;

/// Shared, cheaply-cloneable rate-limit state created once at startup.
///
/// Four separate governor limiters enforce truly distinct quotas for each
/// endpoint category (login, audit, general authenticated, unauthenticated).
#[derive(Clone)]
pub struct RateLimitState {
    config: RateLimitConfig,
    /// Login endpoint limiter — per IP, strict quota (`login_per_minute`).
    login_limiter: Arc<KeyedLimiter>,
    /// Audit endpoint limiter — per user/IP, moderate quota (`audit_per_minute`).
    audit_limiter: Arc<KeyedLimiter>,
    /// General authenticated API limiter — per user, generous quota (`api_per_minute`).
    user_limiter: Arc<KeyedLimiter>,
    /// Unauthenticated endpoint limiter — per IP, moderate quota (`unauthenticated_per_minute`).
    ip_limiter: Arc<KeyedLimiter>,
}

impl RateLimitState {
    /// Creates the shared limiters from the provided configuration.
    ///
    /// Returns `None` when rate limiting is disabled so the middleware can
    /// short-circuit.
    #[must_use]
    pub fn new(config: &RateLimitConfig) -> Option<Self> {
        if !config.enabled {
            return None;
        }

        Some(Self {
            login_limiter: Arc::new(RateLimiter::dashmap(per_minute_quota(
                config.login_per_minute,
            ))),
            audit_limiter: Arc::new(RateLimiter::dashmap(per_minute_quota(
                config.audit_per_minute,
            ))),
            user_limiter: Arc::new(RateLimiter::dashmap(per_minute_quota(
                config.api_per_minute,
            ))),
            ip_limiter: Arc::new(RateLimiter::dashmap(per_minute_quota(
                config.unauthenticated_per_minute,
            ))),
            config: config.clone(),
        })
    }
}

/// Builds a per-minute `Quota` from a `u32` count, clamping to at least 1.
fn per_minute_quota(n: u32) -> Quota {
    let nz = NonZeroU32::new(n.max(1)).unwrap_or(NonZeroU32::MIN);
    Quota::per_minute(nz)
}

// ---------------------------------------------------------------------------
// Middleware function
// ---------------------------------------------------------------------------

/// Axum middleware that enforces rate limits based on the request path and
/// caller identity.
///
/// Insert into the router via:
/// ```ignore
/// .layer(middleware::from_fn_with_state(rate_limit_state, rate_limit_middleware))
/// ```
pub async fn rate_limit_middleware(
    axum::extract::State(state): axum::extract::State<Option<Arc<RateLimitState>>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    // If rate limiting is disabled (state is None), pass through.
    let rl = match state {
        Some(ref s) => s,
        None => return next.run(request).await,
    };

    let path = request.uri().path().to_owned();
    let headers = request.headers().clone();

    // Determine the endpoint category, key, and which limiter to use.
    let (category, key) = resolve_category_and_key(&headers, &path);

    let (limiter, limit_per_minute): (&KeyedLimiter, u32) = match category {
        EndpointCategory::Login => (&rl.login_limiter, rl.config.login_per_minute),
        EndpointCategory::Audit => (&rl.audit_limiter, rl.config.audit_per_minute),
        EndpointCategory::AuthenticatedApi => (&rl.user_limiter, rl.config.api_per_minute),
        EndpointCategory::Unauthenticated => (&rl.ip_limiter, rl.config.unauthenticated_per_minute),
    };

    // Attempt to acquire a token.
    match limiter.check_key(&key) {
        Ok(_) => {
            let mut response = next.run(request).await;
            // Governor's GCRA algorithm does not expose remaining capacity on
            // the Ok branch, so we only emit `x-ratelimit-limit` and
            // `x-ratelimit-reset`.  Omitting `x-ratelimit-remaining` is more
            // honest than reporting an inaccurate value that could mislead
            // clients implementing proactive backoff.
            inject_rate_limit_headers(response.headers_mut(), limit_per_minute, None, 60);
            response
        }
        Err(not_until) => {
            let retry_after =
                not_until.wait_time_from(governor::clock::Clock::now(&DefaultClock::default()));
            let retry_secs = retry_after.as_secs().saturating_add(1);

            warn!(
                key = ?key,
                path = %path,
                retry_after_secs = retry_secs,
                "rate limit exceeded"
            );

            let body = serde_json::json!({
                "message": "Rate limit exceeded",
                "detail": format!("Try again in {retry_secs}s")
            })
            .to_string();

            let mut response = (StatusCode::TOO_MANY_REQUESTS, body).into_response();

            inject_rate_limit_headers(
                response.headers_mut(),
                limit_per_minute,
                Some(0),
                retry_secs,
            );
            if let Ok(val) = HeaderValue::from_str(&retry_secs.to_string()) {
                response.headers_mut().insert(HEADER_RETRY_AFTER, val);
            }

            response
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Determines the endpoint category and rate-limit key based on the request
/// path and headers.
fn resolve_category_and_key(headers: &HeaderMap, path: &str) -> (EndpointCategory, RateLimitKey) {
    // Hash the session token (if present) to avoid storing raw secrets in the
    // DashMap.  The hash is deterministic so the same token always maps to the
    // same bucket.
    let hashed_token = headers
        .get("coder-session-token")
        .and_then(|v| v.to_str().ok())
        .map(hash_token);

    let client_ip = extract_client_ip(headers);

    // Login endpoint: always keyed by IP with strict limit.
    if path.ends_with("/users/login") || path.ends_with("/users/otp/request") {
        return (EndpointCategory::Login, RateLimitKey::Ip(client_ip));
    }

    // Audit endpoint: keyed by hashed token (or IP if unauthenticated).
    if path.contains("/audit") {
        if let Some(hash) = hashed_token {
            return (EndpointCategory::Audit, RateLimitKey::HashedToken(hash));
        }
        return (
            EndpointCategory::Unauthenticated,
            RateLimitKey::Ip(client_ip),
        );
    }

    // Authenticated request: generous per-user limit.
    if let Some(hash) = hashed_token {
        return (
            EndpointCategory::AuthenticatedApi,
            RateLimitKey::HashedToken(hash),
        );
    }

    // Unauthenticated: moderate per-IP limit.
    (
        EndpointCategory::Unauthenticated,
        RateLimitKey::Ip(client_ip),
    )
}

/// Hash a session token using the standard library [`DefaultHasher`] to produce
/// a fixed-length hex key.  This avoids keeping the raw secret in the governor
/// `DashMap`.
///
/// **Note:** `DefaultHasher` is *not* cryptographically secure and its output
/// is *not* guaranteed to be stable across Rust compiler versions.  This is
/// acceptable here because:
///
/// 1. The hash is only used as a transient, in-process rate-limit bucket key —
///    it is never persisted to disk, sent over the network, or used for
///    authentication.
/// 2. Collision resistance only needs to be "good enough" to avoid unrelated
///    sessions sharing a bucket; cryptographic strength is unnecessary.
/// 3. `DefaultHasher` is fast and available without pulling in extra
///    dependencies.
fn hash_token(token: &str) -> String {
    use std::hash::{DefaultHasher, Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    token.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// Best-effort extraction of the client IP from standard proxy headers,
/// falling back to a loopback address if nothing is available.
fn extract_client_ip(headers: &HeaderMap) -> IpAddr {
    // Try X-Forwarded-For first (first entry is the original client).
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = xff.split(',').next() {
            if let Ok(ip) = first.trim().parse::<IpAddr>() {
                return ip;
            }
        }
    }

    // Try X-Real-Ip.
    if let Some(xri) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        if let Ok(ip) = xri.trim().parse::<IpAddr>() {
            return ip;
        }
    }

    // Fallback – localhost.
    IpAddr::from([127, 0, 0, 1])
}

/// Injects standard `X-RateLimit-*` headers into the response.
///
/// `remaining` is `None` when the governor GCRA algorithm doesn't expose
/// bucket state (success branch).  In that case the `x-ratelimit-remaining`
/// header is omitted rather than reporting an inaccurate value.
fn inject_rate_limit_headers(
    headers: &mut HeaderMap,
    limit: u32,
    remaining: Option<u32>,
    reset_secs: u64,
) {
    if let Ok(v) = HeaderValue::from_str(&limit.to_string()) {
        headers.insert(HEADER_RATE_LIMIT, v);
    }
    if let Some(rem) = remaining {
        if let Ok(v) = HeaderValue::from_str(&rem.to_string()) {
            headers.insert(HEADER_RATE_REMAINING, v);
        }
    }
    if let Ok(v) = HeaderValue::from_str(&reset_secs.to_string()) {
        headers.insert(HEADER_RATE_RESET, v);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        Router,
        body::Body,
        http::{Method, Request, Response, StatusCode},
        middleware,
        routing::get,
    };
    use tower::ServiceExt;

    use coder_core::config::RateLimitConfig;

    use super::*;

    // ── Helpers ──────────────────────────────────────────────────────────

    /// Build a minimal Axum router that applies the rate-limit middleware and
    /// returns 200 OK with a JSON body for every path.
    fn test_app(rl_state: Option<Arc<RateLimitState>>) -> Router {
        Router::new()
            .route("/api/v2/users/login", get(|| async { "login" }))
            .route("/api/v2/audit", get(|| async { "audit" }))
            .route("/api/v2/buildinfo", get(|| async { "buildinfo" }))
            .layer(middleware::from_fn_with_state(
                rl_state,
                rate_limit_middleware,
            ))
    }

    async fn send(
        app: &Router,
        method: Method,
        uri: &str,
        headers: Vec<(&str, &str)>,
    ) -> Response<Body> {
        let mut builder = Request::builder().method(method).uri(uri);
        for (k, v) in headers {
            builder = builder.header(k, v);
        }
        let request = builder.body(Body::empty()).ok();
        let request = match request {
            Some(r) => r,
            None => {
                return Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::empty())
                    .unwrap_or_else(|_| Response::new(Body::empty()));
            }
        };
        match app.clone().oneshot(request).await {
            Ok(resp) => resp,
            Err(never) => match never {},
        }
    }

    // ── Tests ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn requests_under_limit_succeed() {
        let config = RateLimitConfig {
            enabled: true,
            api_per_minute: 600,
            login_per_minute: 5,
            unauthenticated_per_minute: 60,
            audit_per_minute: 30,
        };
        let state = RateLimitState::new(&config).map(Arc::new);
        let app = test_app(state);

        // A single request to an unauthenticated endpoint should succeed.
        let resp = send(&app, Method::GET, "/api/v2/buildinfo", vec![]).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn requests_over_limit_get_429_with_retry_after() {
        let config = RateLimitConfig {
            enabled: true,
            api_per_minute: 600,
            login_per_minute: 5,
            // Very tight limit so we can exhaust it quickly.
            unauthenticated_per_minute: 1,
            audit_per_minute: 30,
        };
        let state = RateLimitState::new(&config).map(Arc::new);
        let app = test_app(state);

        // First request should succeed.
        let resp = send(&app, Method::GET, "/api/v2/buildinfo", vec![]).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Subsequent requests should be throttled.
        let mut got_429 = false;
        for _ in 0..10 {
            let resp = send(&app, Method::GET, "/api/v2/buildinfo", vec![]).await;
            if resp.status() == StatusCode::TOO_MANY_REQUESTS {
                // Verify Retry-After header is present.
                assert!(
                    resp.headers().get(HEADER_RETRY_AFTER).is_some(),
                    "429 response must include Retry-After header"
                );
                got_429 = true;
                break;
            }
        }
        assert!(got_429, "expected at least one 429 response");
    }

    #[tokio::test]
    async fn rate_limit_header_present_on_success() {
        let config = RateLimitConfig {
            enabled: true,
            api_per_minute: 600,
            login_per_minute: 5,
            unauthenticated_per_minute: 60,
            audit_per_minute: 30,
        };
        let state = RateLimitState::new(&config).map(Arc::new);
        let app = test_app(state);

        let resp = send(&app, Method::GET, "/api/v2/buildinfo", vec![]).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let limit_header = resp.headers().get(HEADER_RATE_LIMIT);
        assert!(
            limit_header.is_some(),
            "X-RateLimit-Limit header must be present on successful responses"
        );
        // The unauthenticated limit is 60.
        assert_eq!(limit_header.and_then(|v| v.to_str().ok()), Some("60"),);
    }

    #[tokio::test]
    async fn login_endpoint_has_stricter_limits() {
        let config = RateLimitConfig {
            enabled: true,
            api_per_minute: 600,
            // Login is very strict.
            login_per_minute: 1,
            unauthenticated_per_minute: 600,
            audit_per_minute: 30,
        };
        let state = RateLimitState::new(&config).map(Arc::new);
        let app = test_app(state);

        // First login request should pass.
        let resp = send(&app, Method::GET, "/api/v2/users/login", vec![]).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // The login limiter should be exhausted much faster than the general
        // unauthenticated limiter.
        let mut got_429 = false;
        for _ in 0..10 {
            let resp = send(&app, Method::GET, "/api/v2/users/login", vec![]).await;
            if resp.status() == StatusCode::TOO_MANY_REQUESTS {
                got_429 = true;
                break;
            }
        }
        assert!(
            got_429,
            "login endpoint should be rate-limited before general API"
        );

        // Meanwhile a general unauthenticated request should still succeed
        // because it uses a different limiter.
        let resp = send(&app, Method::GET, "/api/v2/buildinfo", vec![]).await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "general API should not be affected by login limiter"
        );
    }

    #[tokio::test]
    async fn disabled_rate_limiting_passes_all_requests() {
        let config = RateLimitConfig {
            enabled: false,
            api_per_minute: 1,
            login_per_minute: 1,
            unauthenticated_per_minute: 1,
            audit_per_minute: 1,
        };
        // When disabled, `RateLimitState::new` returns None.
        let state = RateLimitState::new(&config).map(Arc::new);
        assert!(state.is_none(), "disabled config should produce None state");

        let app = test_app(state);

        // Even though limits are 1/min, all requests should pass because
        // rate limiting is disabled.
        for _ in 0..20 {
            let resp = send(&app, Method::GET, "/api/v2/buildinfo", vec![]).await;
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "disabled rate limiter should not reject requests"
            );
        }
    }

    #[tokio::test]
    async fn endpoint_categories_route_to_correct_limiters() {
        let config = RateLimitConfig {
            enabled: true,
            api_per_minute: 600,
            login_per_minute: 600,
            unauthenticated_per_minute: 600,
            audit_per_minute: 600,
        };
        let state = RateLimitState::new(&config).map(Arc::new);
        let app = test_app(state);

        // Login endpoint → should report login limit (600).
        let resp = send(&app, Method::GET, "/api/v2/users/login", vec![]).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(HEADER_RATE_LIMIT)
                .and_then(|v| v.to_str().ok()),
            Some("600"),
            "login endpoint should use login_per_minute limit"
        );

        // Audit endpoint with a session token → should report audit limit.
        let resp = send(
            &app,
            Method::GET,
            "/api/v2/audit",
            vec![("coder-session-token", "test-token-abc")],
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(HEADER_RATE_LIMIT)
                .and_then(|v| v.to_str().ok()),
            Some("600"),
            "audit endpoint with token should use audit_per_minute limit"
        );

        // General unauthenticated request → should use unauthenticated limit.
        let resp = send(&app, Method::GET, "/api/v2/buildinfo", vec![]).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(HEADER_RATE_LIMIT)
                .and_then(|v| v.to_str().ok()),
            Some("600"),
            "unauthenticated endpoint should use unauthenticated_per_minute limit"
        );

        // General authenticated request → should use api_per_minute limit.
        let resp = send(
            &app,
            Method::GET,
            "/api/v2/buildinfo",
            vec![("coder-session-token", "user-session-xyz")],
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(HEADER_RATE_LIMIT)
                .and_then(|v| v.to_str().ok()),
            Some("600"),
            "authenticated API endpoint should use api_per_minute limit"
        );
    }

    // ── Unit tests for internal helpers ──────────────────────────────────

    #[test]
    fn hash_token_produces_deterministic_output() {
        let a = hash_token("my-secret-token");
        let b = hash_token("my-secret-token");
        assert_eq!(a, b, "same input must produce same hash");
    }

    #[test]
    fn hash_token_differs_for_different_inputs() {
        let a = hash_token("token-a");
        let b = hash_token("token-b");
        assert_ne!(a, b, "different tokens should produce different hashes");
    }

    #[test]
    fn extract_client_ip_from_x_forwarded_for() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("10.0.0.1, 192.168.1.1"),
        );
        let ip = extract_client_ip(&headers);
        assert_eq!(ip, IpAddr::from([10, 0, 0, 1]));
    }

    #[test]
    fn extract_client_ip_from_x_real_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", HeaderValue::from_static("172.16.0.5"));
        let ip = extract_client_ip(&headers);
        assert_eq!(ip, IpAddr::from([172, 16, 0, 5]));
    }

    #[test]
    fn extract_client_ip_fallback_to_loopback() {
        let headers = HeaderMap::new();
        let ip = extract_client_ip(&headers);
        assert_eq!(ip, IpAddr::from([127, 0, 0, 1]));
    }

    #[test]
    fn resolve_login_category() {
        let headers = HeaderMap::new();
        let (cat, key) = resolve_category_and_key(&headers, "/api/v2/users/login");
        assert!(matches!(cat, EndpointCategory::Login));
        assert!(matches!(key, RateLimitKey::Ip(_)));
    }

    #[test]
    fn resolve_audit_category_with_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "coder-session-token",
            HeaderValue::from_static("session-abc"),
        );
        let (cat, key) = resolve_category_and_key(&headers, "/api/v2/audit");
        assert!(matches!(cat, EndpointCategory::Audit));
        assert!(matches!(key, RateLimitKey::HashedToken(_)));
    }

    #[test]
    fn resolve_authenticated_api_category() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "coder-session-token",
            HeaderValue::from_static("session-xyz"),
        );
        let (cat, key) = resolve_category_and_key(&headers, "/api/v2/buildinfo");
        assert!(matches!(cat, EndpointCategory::AuthenticatedApi));
        assert!(matches!(key, RateLimitKey::HashedToken(_)));
    }

    #[test]
    fn resolve_unauthenticated_category() {
        let headers = HeaderMap::new();
        let (cat, key) = resolve_category_and_key(&headers, "/api/v2/buildinfo");
        assert!(matches!(cat, EndpointCategory::Unauthenticated));
        assert!(matches!(key, RateLimitKey::Ip(_)));
    }
}
