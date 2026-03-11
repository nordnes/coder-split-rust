//! Prometheus-compatible metric helpers for the Rust backend.

/// Records an HTTP request with method, path, status, and duration.
pub fn record_request(method: &str, path: &str, status: u16, duration_ms: f64) {
    let labels = [
        ("method", method.to_owned()),
        ("path", path.to_owned()),
        ("status", status.to_string()),
    ];
    metrics::counter!("http_requests_total", &labels).increment(1);
    metrics::histogram!("http_request_duration_ms", &labels).record(duration_ms);
}

/// Records a database query with operation name, duration, and success status.
pub fn record_db_query(operation: &str, duration_ms: f64, success: bool) {
    let labels = [
        ("operation", operation.to_owned()),
        ("success", success.to_string()),
    ];
    metrics::histogram!("db_query_duration_ms", &labels).record(duration_ms);
    metrics::counter!("db_queries_total", &labels).increment(1);
}

/// Sets the current active HTTP connection count gauge.
pub fn set_active_connections(count: usize) {
    metrics::gauge!("active_connections").set(count as f64);
}

/// Records an authentication event (login_success, login_failure, logout, session_expired).
pub fn record_auth_event(event_type: &str) {
    metrics::counter!("auth_events_total", "type" => event_type.to_owned()).increment(1);
}
