//! Concurrency control middleware inspired by Zed's `ConnectionGuard`.
//!
//! Tracks concurrent in-flight HTTP requests using an `AtomicUsize`
//! counter and returns `503 Service Unavailable` when the configured
//! threshold is exceeded.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use metrics::gauge;
use tracing::warn;

/// Shared state for the connection guard, holding the concurrent-request
/// counter and the configured maximum.
#[derive(Clone)]
pub struct ConnectionGuardState {
    counter: Arc<AtomicUsize>,
    max_concurrent: usize,
}

impl ConnectionGuardState {
    /// Creates a new connection guard with the specified concurrency limit.
    #[must_use]
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            counter: Arc::new(AtomicUsize::new(0)),
            max_concurrent,
        }
    }

    /// Returns the current number of concurrent in-flight requests.
    #[must_use]
    pub fn current(&self) -> usize {
        self.counter.load(Ordering::Relaxed)
    }
}

/// RAII guard that decrements the concurrent-request counter on drop.
struct RequestGuard {
    counter: Arc<AtomicUsize>,
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        let prev = self.counter.fetch_sub(1, Ordering::Relaxed);
        gauge!("http_concurrent_requests").set((prev - 1) as f64);
    }
}

/// Axum middleware that enforces a maximum number of concurrent requests.
///
/// Returns `503 Service Unavailable` when the threshold is exceeded,
/// providing backpressure to load balancers and clients.
pub async fn connection_guard_middleware(
    request: Request,
    next: Next,
    state: ConnectionGuardState,
) -> Response {
    let current = state.counter.fetch_add(1, Ordering::Relaxed);
    gauge!("http_concurrent_requests").set((current + 1) as f64);

    if current >= state.max_concurrent {
        // We already incremented, so decrement before returning.
        state.counter.fetch_sub(1, Ordering::Relaxed);
        gauge!("http_concurrent_requests").set(current as f64);
        warn!(
            current,
            max_concurrent = state.max_concurrent,
            "rejecting request: max concurrent requests exceeded"
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "server is overloaded, please try again later",
        )
            .into_response();
    }

    // The guard ensures the counter is decremented even if the handler panics.
    let _guard = RequestGuard {
        counter: Arc::clone(&state.counter),
    };
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_decrements_on_drop() {
        let counter = Arc::new(AtomicUsize::new(5));
        {
            let _guard = RequestGuard {
                counter: Arc::clone(&counter),
            };
        }
        assert_eq!(counter.load(Ordering::Relaxed), 4);
    }

    #[test]
    fn state_reports_current_count() {
        let state = ConnectionGuardState::new(100);
        assert_eq!(state.current(), 0);
        state.counter.fetch_add(3, Ordering::Relaxed);
        assert_eq!(state.current(), 3);
    }
}
