//! Async-friendly circuit breaker for external dependency calls.
//!
//! The circuit breaker tracks consecutive failures and transitions through
//! three states:
//!
//! * **Closed** — requests flow normally; failures are counted.
//! * **Open** — requests are rejected immediately; a reset timeout governs
//!   when the breaker transitions to half-open.
//! * **Half-Open** — a limited number of probe requests are allowed through;
//!   if enough succeed the breaker closes, otherwise it re-opens.
//!
//! All operations are non-blocking and compatible with Tokio.

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configurable parameters for a [`CircuitBreaker`].
#[derive(Clone, Debug)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures before the breaker opens.
    pub failure_threshold: u32,
    /// How long the breaker stays open before transitioning to half-open.
    pub reset_timeout: Duration,
    /// Number of successful probes required in half-open state to close.
    pub half_open_max_probes: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            reset_timeout: Duration::from_secs(30),
            half_open_max_probes: 3,
        }
    }
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Observable circuit breaker state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitBreakerState {
    /// Healthy — requests pass through normally.
    Closed,
    /// Tripped — requests are rejected immediately.
    Open,
    /// Probing — a limited number of requests are allowed through.
    HalfOpen,
}

impl std::fmt::Display for CircuitBreakerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => f.write_str("closed"),
            Self::Open => f.write_str("open"),
            Self::HalfOpen => f.write_str("half_open"),
        }
    }
}

/// Snapshot of a circuit breaker's status for health reporting.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CircuitBreakerStatus {
    /// Name of the dependency this breaker protects.
    pub name: String,
    /// Current state.
    pub state: CircuitBreakerState,
    /// Consecutive failure count.
    pub consecutive_failures: u32,
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Error returned when the circuit breaker rejects a request.
#[derive(Debug, Clone)]
pub struct CircuitBreakerOpen {
    /// Name of the dependency whose breaker is open.
    pub dependency: String,
}

impl std::fmt::Display for CircuitBreakerOpen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "circuit breaker open for dependency: {}",
            self.dependency
        )
    }
}

impl std::error::Error for CircuitBreakerOpen {}

// ---------------------------------------------------------------------------
// Internal mutable state
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct Inner {
    state: CircuitBreakerState,
    consecutive_failures: u32,
    half_open_successes: u32,
    last_failure_time: Option<Instant>,
}

// ---------------------------------------------------------------------------
// Circuit Breaker
// ---------------------------------------------------------------------------

/// A tokio-compatible circuit breaker.
///
/// Wrap calls to external dependencies with [`CircuitBreaker::call`] to
/// automatically track failures and trip the breaker when the failure
/// threshold is exceeded.
#[derive(Clone, Debug)]
pub struct CircuitBreaker {
    name: String,
    config: CircuitBreakerConfig,
    inner: Arc<Mutex<Inner>>,
}

impl CircuitBreaker {
    /// Creates a new circuit breaker in the **Closed** state.
    #[must_use]
    pub fn new(name: impl Into<String>, config: CircuitBreakerConfig) -> Self {
        Self {
            name: name.into(),
            config,
            inner: Arc::new(Mutex::new(Inner {
                state: CircuitBreakerState::Closed,
                consecutive_failures: 0,
                half_open_successes: 0,
                last_failure_time: None,
            })),
        }
    }

    /// Returns the dependency name this breaker protects.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns a snapshot of the current status (for health reporting).
    pub async fn status(&self) -> CircuitBreakerStatus {
        let mut inner = self.inner.lock().await;
        // Check for automatic open -> half-open transition.
        maybe_transition_to_half_open(&self.config, &mut inner);

        CircuitBreakerStatus {
            name: self.name.clone(),
            state: inner.state,
            consecutive_failures: inner.consecutive_failures,
        }
    }

    /// Returns the current state.
    pub async fn state(&self) -> CircuitBreakerState {
        let mut inner = self.inner.lock().await;
        maybe_transition_to_half_open(&self.config, &mut inner);
        inner.state
    }

    /// Executes `operation` through the circuit breaker.
    ///
    /// * If the breaker is **Open** the call is rejected immediately with
    ///   [`CircuitBreakerOpen`].
    /// * If the breaker is **Closed** or **Half-Open** the operation runs
    ///   normally and the result is used to update internal counters.
    pub async fn call<F, Fut, T, E>(&self, operation: F) -> Result<T, CircuitBreakerCallError<E>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>>,
    {
        // --- pre-flight check ---
        {
            let mut inner = self.inner.lock().await;
            maybe_transition_to_half_open(&self.config, &mut inner);

            match inner.state {
                CircuitBreakerState::Open => {
                    return Err(CircuitBreakerCallError::BreakerOpen(CircuitBreakerOpen {
                        dependency: self.name.clone(),
                    }));
                }
                CircuitBreakerState::Closed | CircuitBreakerState::HalfOpen => {}
            }
        }
        // Lock is released before running the potentially slow operation.

        // --- execute ---
        let result = operation().await;

        // --- post-flight bookkeeping ---
        let mut inner = self.inner.lock().await;
        match &result {
            Ok(_) => self.record_success(&mut inner),
            Err(_) => self.record_failure(&mut inner),
        }

        result.map_err(CircuitBreakerCallError::Inner)
    }

    /// Records a successful outcome for bookkeeping purposes.
    ///
    /// Use this instead of [`call`] when the operation has already been
    /// executed outside the circuit breaker and you only want to update
    /// the breaker's internal counters.
    ///
    /// **Note:** These methods bypass the half-open probe limit enforced by
    /// [`call`].  In the `HalfOpen` state every reported success counts
    /// toward closing the breaker, regardless of `half_open_max_probes`.
    /// This is acceptable for batch-style probes (e.g. workspace proxies,
    /// provisioner daemons) where the caller already gates on breaker state
    /// before running the operation.
    pub async fn report_success(&self) {
        let mut inner = self.inner.lock().await;
        self.record_success(&mut inner);
    }

    /// Records a failed outcome for bookkeeping purposes.
    ///
    /// Use this instead of [`call`] when the operation has already been
    /// executed outside the circuit breaker and you only want to update
    /// the breaker's internal counters.
    ///
    /// **Note:** These methods bypass the half-open probe limit enforced by
    /// [`call`].  See [`report_success`](Self::report_success) for details.
    pub async fn report_failure(&self) {
        let mut inner = self.inner.lock().await;
        self.record_failure(&mut inner);
    }

    /// Records a successful call.
    fn record_success(&self, inner: &mut Inner) {
        match inner.state {
            CircuitBreakerState::Closed => {
                inner.consecutive_failures = 0;
            }
            CircuitBreakerState::HalfOpen => {
                inner.half_open_successes = inner.half_open_successes.saturating_add(1);
                if inner.half_open_successes >= self.config.half_open_max_probes {
                    // Enough probes succeeded — close the breaker.
                    inner.state = CircuitBreakerState::Closed;
                    inner.consecutive_failures = 0;
                    inner.half_open_successes = 0;
                    inner.last_failure_time = None;
                }
            }
            CircuitBreakerState::Open => {
                // Reachable via `report_success()` when the dependency
                // recovers while the breaker is still open.  Transition
                // to HalfOpen so the normal probe-then-close path runs,
                // cutting recovery latency without skipping validation.
                inner.state = CircuitBreakerState::HalfOpen;
                inner.half_open_successes = 1;
            }
        }
    }

    /// Records a failed call.
    fn record_failure(&self, inner: &mut Inner) {
        match inner.state {
            CircuitBreakerState::Closed => {
                inner.consecutive_failures = inner.consecutive_failures.saturating_add(1);
                inner.last_failure_time = Some(Instant::now());
                if inner.consecutive_failures >= self.config.failure_threshold {
                    inner.state = CircuitBreakerState::Open;
                }
            }
            CircuitBreakerState::HalfOpen => {
                // Any failure in half-open immediately re-opens the breaker.
                inner.consecutive_failures = inner.consecutive_failures.saturating_add(1);
                inner.last_failure_time = Some(Instant::now());
                inner.state = CircuitBreakerState::Open;
                inner.half_open_successes = 0;
            }
            CircuitBreakerState::Open => {
                // Already open — do NOT update last_failure_time to avoid
                // indefinitely extending the reset timeout (e.g. when
                // report_failure() is called every health-check cycle).
            }
        }
    }
}

/// Checks whether an **Open** breaker should transition to **Half-Open**
/// based on the reset timeout.
fn maybe_transition_to_half_open(config: &CircuitBreakerConfig, inner: &mut Inner) {
    if inner.state == CircuitBreakerState::Open {
        if let Some(last_failure) = inner.last_failure_time {
            if last_failure.elapsed() >= config.reset_timeout {
                inner.state = CircuitBreakerState::HalfOpen;
                inner.half_open_successes = 0;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Composite error type
// ---------------------------------------------------------------------------

/// Error type returned by [`CircuitBreaker::call`].
#[derive(Debug)]
pub enum CircuitBreakerCallError<E> {
    /// The circuit breaker was open and the call was rejected.
    BreakerOpen(CircuitBreakerOpen),
    /// The wrapped operation returned an error.
    Inner(E),
}

impl<E: std::fmt::Display> std::fmt::Display for CircuitBreakerCallError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BreakerOpen(err) => err.fmt(f),
            Self::Inner(err) => err.fmt(f),
        }
    }
}

impl<E: std::fmt::Display + std::fmt::Debug> std::error::Error for CircuitBreakerCallError<E> {}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// A registry holding named circuit breakers for all external dependencies.
///
/// The registry is cheap to clone (all breakers are behind `Arc`).
#[derive(Clone, Debug)]
pub struct CircuitBreakerRegistry {
    breakers: Arc<Vec<CircuitBreaker>>,
}

impl CircuitBreakerRegistry {
    /// Creates a registry from a list of pre-built circuit breakers.
    #[must_use]
    pub fn new(breakers: Vec<CircuitBreaker>) -> Self {
        Self {
            breakers: Arc::new(breakers),
        }
    }

    /// Creates a registry with default-configured breakers for all standard
    /// external dependencies.
    #[must_use]
    pub fn with_defaults() -> Self {
        let config = CircuitBreakerConfig::default();
        Self::new(vec![
            CircuitBreaker::new("oauth_oidc", config.clone()),
            CircuitBreaker::new("telemetry", config.clone()),
            CircuitBreaker::new("derp_mesh", config.clone()),
            CircuitBreaker::new("provisioner_daemons", config.clone()),
            CircuitBreaker::new("workspace_proxies", config),
        ])
    }

    /// Looks up a breaker by dependency name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&CircuitBreaker> {
        self.breakers.iter().find(|b| b.name() == name)
    }

    /// Returns a snapshot of all breaker statuses.
    pub async fn all_statuses(&self) -> Vec<CircuitBreakerStatus> {
        let mut out = Vec::with_capacity(self.breakers.len());
        for breaker in self.breakers.iter() {
            out.push(breaker.status().await);
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_config() -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            failure_threshold: 3,
            reset_timeout: Duration::from_millis(50),
            half_open_max_probes: 2,
        }
    }

    #[tokio::test]
    async fn starts_in_closed_state() {
        let cb = CircuitBreaker::new("test", fast_config());
        assert_eq!(cb.state().await, CircuitBreakerState::Closed);
    }

    #[tokio::test]
    async fn success_resets_failure_count() {
        let cb = CircuitBreaker::new("test", fast_config());
        // Two failures (below threshold of 3).
        let _: Result<(), _> = cb.call(|| async { Err::<(), &str>("fail") }).await;
        let _: Result<(), _> = cb.call(|| async { Err::<(), &str>("fail") }).await;
        assert_eq!(cb.state().await, CircuitBreakerState::Closed);

        // One success resets the counter.
        let result: Result<&str, _> = cb.call(|| async { Ok::<&str, &str>("ok") }).await;
        assert!(result.is_ok());

        // Two more failures should not trip it (counter was reset).
        let _: Result<(), _> = cb.call(|| async { Err::<(), &str>("fail") }).await;
        let _: Result<(), _> = cb.call(|| async { Err::<(), &str>("fail") }).await;
        assert_eq!(cb.state().await, CircuitBreakerState::Closed);
    }

    #[tokio::test]
    async fn opens_after_threshold_failures() {
        let cb = CircuitBreaker::new("test", fast_config());
        for _ in 0..3 {
            let _: Result<(), _> = cb.call(|| async { Err::<(), &str>("fail") }).await;
        }
        assert_eq!(cb.state().await, CircuitBreakerState::Open);
    }

    #[tokio::test]
    async fn open_breaker_rejects_calls() {
        let cb = CircuitBreaker::new("test", fast_config());
        for _ in 0..3 {
            let _: Result<(), _> = cb.call(|| async { Err::<(), &str>("fail") }).await;
        }

        let result: Result<&str, CircuitBreakerCallError<&str>> =
            cb.call(|| async { Ok("should not run") }).await;
        assert!(matches!(
            result,
            Err(CircuitBreakerCallError::BreakerOpen(_))
        ));
    }

    #[tokio::test]
    async fn transitions_to_half_open_after_timeout() {
        let cb = CircuitBreaker::new("test", fast_config());
        for _ in 0..3 {
            let _: Result<(), _> = cb.call(|| async { Err::<(), &str>("fail") }).await;
        }
        assert_eq!(cb.state().await, CircuitBreakerState::Open);

        // Wait for the reset timeout.
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(cb.state().await, CircuitBreakerState::HalfOpen);
    }

    #[tokio::test]
    async fn half_open_closes_after_enough_successes() {
        let cb = CircuitBreaker::new("test", fast_config());
        // Trip the breaker.
        for _ in 0..3 {
            let _: Result<(), _> = cb.call(|| async { Err::<(), &str>("fail") }).await;
        }
        // Wait for half-open.
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(cb.state().await, CircuitBreakerState::HalfOpen);

        // Two successful probes (half_open_max_probes = 2) should close it.
        let _: Result<&str, _> = cb.call(|| async { Ok::<&str, &str>("ok") }).await;
        let _: Result<&str, _> = cb.call(|| async { Ok::<&str, &str>("ok") }).await;
        assert_eq!(cb.state().await, CircuitBreakerState::Closed);
    }

    #[tokio::test]
    async fn half_open_reopens_on_failure() {
        let cb = CircuitBreaker::new("test", fast_config());
        for _ in 0..3 {
            let _: Result<(), _> = cb.call(|| async { Err::<(), &str>("fail") }).await;
        }
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(cb.state().await, CircuitBreakerState::HalfOpen);

        // One failure in half-open immediately re-opens.
        let _: Result<(), _> = cb.call(|| async { Err::<(), &str>("fail again") }).await;
        assert_eq!(cb.state().await, CircuitBreakerState::Open);
    }

    #[tokio::test]
    async fn status_reports_correct_values() {
        let cb = CircuitBreaker::new("my_dep", fast_config());
        let status = cb.status().await;
        assert_eq!(status.name, "my_dep");
        assert_eq!(status.state, CircuitBreakerState::Closed);
        assert_eq!(status.consecutive_failures, 0);

        // After two failures:
        let _: Result<(), _> = cb.call(|| async { Err::<(), &str>("fail") }).await;
        let _: Result<(), _> = cb.call(|| async { Err::<(), &str>("fail") }).await;
        let status = cb.status().await;
        assert_eq!(status.consecutive_failures, 2);
        assert_eq!(status.state, CircuitBreakerState::Closed);
    }

    #[tokio::test]
    async fn registry_with_defaults_has_all_dependencies() {
        let registry = CircuitBreakerRegistry::with_defaults();
        assert!(registry.get("oauth_oidc").is_some());
        assert!(registry.get("telemetry").is_some());
        assert!(registry.get("derp_mesh").is_some());
        assert!(registry.get("provisioner_daemons").is_some());
        assert!(registry.get("workspace_proxies").is_some());
        assert!(registry.get("nonexistent").is_none());
    }

    #[tokio::test]
    async fn registry_all_statuses() {
        let registry = CircuitBreakerRegistry::with_defaults();
        let statuses = registry.all_statuses().await;
        assert_eq!(statuses.len(), 5);
        for status in &statuses {
            assert_eq!(status.state, CircuitBreakerState::Closed);
            assert_eq!(status.consecutive_failures, 0);
        }
    }

    #[tokio::test]
    async fn report_failure_while_open_does_not_reset_timeout() {
        let cb = CircuitBreaker::new("test", fast_config());
        // Trip the breaker.
        for _ in 0..3 {
            let _: Result<(), _> = cb.call(|| async { Err::<(), &str>("fail") }).await;
        }
        assert_eq!(cb.state().await, CircuitBreakerState::Open);

        // Wait 30ms (more than half the 50ms reset_timeout).
        tokio::time::sleep(Duration::from_millis(30)).await;

        // report_failure while Open must NOT reset last_failure_time.
        cb.report_failure().await;

        // Wait another 25ms — total 55ms since the breaker originally
        // opened, which exceeds the 50ms reset_timeout.  If
        // last_failure_time was incorrectly reset by report_failure(),
        // only 25ms would have elapsed and the breaker would still be Open.
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert_eq!(
            cb.state().await,
            CircuitBreakerState::HalfOpen,
            "breaker should transition to HalfOpen based on original failure time"
        );
    }

    #[tokio::test]
    async fn report_success_while_open_transitions_to_half_open() {
        let cb = CircuitBreaker::new("test", fast_config());
        // Trip the breaker.
        for _ in 0..3 {
            let _: Result<(), _> = cb.call(|| async { Err::<(), &str>("fail") }).await;
        }
        assert_eq!(cb.state().await, CircuitBreakerState::Open);

        // report_success while Open should transition to HalfOpen
        // (counting that success as the first half-open probe).
        cb.report_success().await;
        assert_eq!(cb.state().await, CircuitBreakerState::HalfOpen);

        // One more success should close it (half_open_max_probes = 2,
        // and we already counted 1 from the Open→HalfOpen transition).
        cb.report_success().await;
        assert_eq!(cb.state().await, CircuitBreakerState::Closed);
    }

    #[tokio::test]
    async fn call_error_display() {
        let err: CircuitBreakerCallError<String> =
            CircuitBreakerCallError::BreakerOpen(CircuitBreakerOpen {
                dependency: "test_dep".to_owned(),
            });
        assert_eq!(
            err.to_string(),
            "circuit breaker open for dependency: test_dep"
        );

        let err: CircuitBreakerCallError<String> =
            CircuitBreakerCallError::Inner("inner error".to_owned());
        assert_eq!(err.to_string(), "inner error");
    }
}
