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
    User(String),
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

type KeyedLimiter = RateLimiter<RateLimitKey, DashMapStateStore<RateLimitKey>, DefaultClock>;

/// Shared, cheaply-cloneable rate-limit state created once at startup.
#[derive(Clone)]
pub struct RateLimitState {
    config: RateLimitConfig,
    /// Per-IP limiter used for login and unauthenticated requests.
    ip_limiter: Arc<KeyedLimiter>,
    /// Per-user limiter used for general authenticated requests.
    user_limiter: Arc<KeyedLimiter>,
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

        let ip_quota = per_minute_quota(config.unauthenticated_per_minute);
        let user_quota = per_minute_quota(config.api_per_minute);

        Some(Self {
            config: config.clone(),
            ip_limiter: Arc::new(RateLimiter::dashmap(ip_quota)),
            user_limiter: Arc::new(RateLimiter::dashmap(user_quota)),
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

    // Determine the key and which limiter to use.
    let (key, limit_per_minute) = resolve_key_and_limit(&headers, &path, &rl.config);

    let limiter: &KeyedLimiter = match &key {
        RateLimitKey::User(_) => &rl.user_limiter,
        RateLimitKey::Ip(_) => &rl.ip_limiter,
    };

    // Attempt to acquire a token.
    match limiter.check_key(&key) {
        Ok(_) => {
            let mut response = next.run(request).await;
            // Governor's Ok branch with the default NoOpMiddleware does not
            // expose remaining capacity.  We report the configured limit and
            // a fixed 60s reset window (buckets are per-minute).
            inject_rate_limit_headers(
                response.headers_mut(),
                limit_per_minute,
                limit_per_minute,
                60,
            );
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

            inject_rate_limit_headers(response.headers_mut(), limit_per_minute, 0, retry_secs);
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

/// Determines the rate-limit key (IP or user) and the applicable per-minute
/// limit based on the request path and headers.
fn resolve_key_and_limit(
    headers: &HeaderMap,
    path: &str,
    config: &RateLimitConfig,
) -> (RateLimitKey, u32) {
    // Check for an authenticated user (session token header).
    let user_id = headers
        .get("coder-session-token")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned());

    // Extract client IP from X-Forwarded-For or X-Real-Ip.
    let client_ip = extract_client_ip(headers);

    // Login endpoint: always keyed by IP with strict limit.
    if path.ends_with("/users/login") || path.ends_with("/users/otp/request") {
        let key = RateLimitKey::Ip(client_ip);
        return (key, config.login_per_minute);
    }

    // Audit endpoint: keyed by user with moderate limit.
    if path.contains("/audit") {
        if let Some(uid) = user_id {
            return (RateLimitKey::User(uid), config.audit_per_minute);
        }
        return (
            RateLimitKey::Ip(client_ip),
            config.unauthenticated_per_minute,
        );
    }

    // Authenticated request: generous per-user limit.
    if let Some(uid) = user_id {
        return (RateLimitKey::User(uid), config.api_per_minute);
    }

    // Unauthenticated: moderate per-IP limit.
    (
        RateLimitKey::Ip(client_ip),
        config.unauthenticated_per_minute,
    )
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
fn inject_rate_limit_headers(headers: &mut HeaderMap, limit: u32, remaining: u32, reset_secs: u64) {
    if let Ok(v) = HeaderValue::from_str(&limit.to_string()) {
        headers.insert(HEADER_RATE_LIMIT, v);
    }
    if let Ok(v) = HeaderValue::from_str(&remaining.to_string()) {
        headers.insert(HEADER_RATE_REMAINING, v);
    }
    if let Ok(v) = HeaderValue::from_str(&reset_secs.to_string()) {
        headers.insert(HEADER_RATE_RESET, v);
    }
}
