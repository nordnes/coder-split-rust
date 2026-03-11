//! Prometheus-compatible metric helpers for the Rust backend.
//!
//! This module centralises metric recording so that metric names, label keys,
//! and units are defined in one place.  Consumers that live *outside*
//! `coder-server` (e.g. `coder-db`, `coder-auth`) cannot depend on this crate
//! without creating a circular dependency, so they record metrics inline via
//! the `metrics` crate macros directly.
//!
//! ## Metrics emitted
//!
//! | Name | Type | Labels | Description |
//! |------|------|--------|-------------|
//! | `http_requests_total` | counter | `method`, `path`, `status` | Total HTTP requests processed |
//! | `http_request_duration_ms` | histogram | `method`, `path`, `status` | Request latency in milliseconds |
//! | `active_connections` | gauge | *(none)* | Number of in-flight HTTP requests (incremented/decremented in middleware) |
//! | `db_query_duration_ms` | histogram | `operation`, `success` | Database query latency in milliseconds (emitted by `coder-db`) |
//! | `db_queries_total` | counter | `operation`, `success` | Total database queries (emitted by `coder-db`) |
//! | `auth_events_total` | counter | `type` | Authentication events such as `login_success`, `login_failure`, `logout`, `session_expired` (emitted by `coder-auth`) |

/// Records an HTTP request with method, path, status, and duration.
///
/// Emits two metrics:
/// - `http_requests_total` (counter): incremented once per request, labelled
///   with `method`, `path`, and `status`.
/// - `http_request_duration_ms` (histogram): records the request latency in
///   milliseconds, labelled with `method`, `path`, and `status`.
pub fn record_request(method: &str, path: &str, status: u16, duration_ms: f64) {
    let labels = [
        ("method", method.to_owned()),
        ("path", path.to_owned()),
        ("status", status.to_string()),
    ];
    metrics::counter!("http_requests_total", &labels).increment(1);
    metrics::histogram!("http_request_duration_ms", &labels).record(duration_ms);
}
