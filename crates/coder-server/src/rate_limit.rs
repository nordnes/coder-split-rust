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

/// Hash a session token using the standard library `DefaultHasher` to produce
/// a fixed-length hex key.  This avoids keeping the raw secret in the governor
/// `DashMap`.
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
