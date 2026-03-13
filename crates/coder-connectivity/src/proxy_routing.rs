//! Health-aware workspace proxy routing.
//!
//! Provides a [`ProxyRouter`] that filters and selects healthy workspace
//! proxies for request routing.  Unhealthy proxies (those that fail health
//! probes or whose circuit breaker is open) are skipped automatically.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use coder_core::{
    CircuitBreaker, CircuitBreakerConfig, CircuitBreakerState, WorkspaceProxyHealthRecord,
};
use tokio::sync::Mutex;

/// A single proxy entry with cached health status.
#[derive(Clone, Debug)]
pub struct ProxyEntry {
    /// The underlying proxy record.
    pub record: WorkspaceProxyHealthRecord,
    /// Per-proxy circuit breaker tracking probe failures.
    pub circuit_breaker: CircuitBreaker,
}

/// Health-aware workspace proxy router.
///
/// Maintains a cached list of proxies with per-proxy circuit breakers.
/// Callers use [`ProxyRouter::select_healthy_proxies`] to get only the
/// proxies whose breakers are not open.
#[derive(Clone)]
pub struct ProxyRouter {
    entries: Arc<Mutex<Vec<ProxyEntry>>>,
    breaker_config: CircuitBreakerConfig,
    last_refresh: Arc<Mutex<Option<Instant>>>,
    refresh_interval: Duration,
}

impl ProxyRouter {
    /// Creates a new proxy router with the given circuit breaker config.
    #[must_use]
    pub fn new(breaker_config: CircuitBreakerConfig) -> Self {
        Self {
            entries: Arc::new(Mutex::new(Vec::new())),
            breaker_config,
            last_refresh: Arc::new(Mutex::new(None)),
            refresh_interval: Duration::from_secs(30),
        }
    }

    /// Creates a router with default circuit breaker settings.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(CircuitBreakerConfig {
            failure_threshold: 3,
            reset_timeout: Duration::from_secs(30),
            half_open_max_probes: 2,
        })
    }

    /// Updates the proxy list from the store.  Existing circuit breakers are
    /// preserved for proxies that still exist (matched by id); new proxies
    /// get fresh breakers.
    pub async fn refresh(&self, proxies: Vec<WorkspaceProxyHealthRecord>) {
        let new_entries = {
            let mut entries = self.entries.lock().await;
            // Index old breakers by proxy id for O(n) lookup.
            let old_breakers: HashMap<uuid::Uuid, CircuitBreaker> = entries
                .drain(..)
                .map(|e| (e.record.id, e.circuit_breaker))
                .collect();

            let mut new = Vec::with_capacity(proxies.len());
            for proxy in proxies {
                if proxy.deleted {
                    continue;
                }
                let breaker = old_breakers.get(&proxy.id).cloned().unwrap_or_else(|| {
                    CircuitBreaker::new(
                        format!("proxy_{}", proxy.name),
                        self.breaker_config.clone(),
                    )
                });

                new.push(ProxyEntry {
                    record: proxy,
                    circuit_breaker: breaker,
                });
            }
            *entries = new.clone();
            new
        };
        // entries lock is dropped here before acquiring last_refresh.
        let _ = new_entries; // ensure we moved out of the lock scope
        *self.last_refresh.lock().await = Some(Instant::now());
    }

    /// Returns whether the cached proxy list needs refreshing.
    pub async fn needs_refresh(&self) -> bool {
        let last = self.last_refresh.lock().await;
        match *last {
            None => true,
            Some(t) => t.elapsed() >= self.refresh_interval,
        }
    }

    /// Returns all proxy entries (including unhealthy ones).
    pub async fn all_proxies(&self) -> Vec<ProxyEntry> {
        self.entries.lock().await.clone()
    }

    /// Returns only healthy proxies — those whose circuit breaker is not
    /// in the **Open** state.
    pub async fn select_healthy_proxies(&self) -> Vec<ProxyEntry> {
        // Clone entries under the lock, then drop the guard before
        // awaiting breaker state checks to avoid holding entries across
        // .await points.
        let snapshot: Vec<ProxyEntry> = self.entries.lock().await.clone();
        let mut healthy = Vec::with_capacity(snapshot.len());
        for entry in &snapshot {
            let state = entry.circuit_breaker.state().await;
            if state != CircuitBreakerState::Open {
                healthy.push(entry.clone());
            }
        }
        healthy
    }

    /// Records a successful request to the given proxy (by id).
    pub async fn record_success(&self, proxy_id: uuid::Uuid) {
        // Clone the breaker under the lock, then drop the guard before
        // awaiting the breaker update.
        let breaker = {
            let entries = self.entries.lock().await;
            entries
                .iter()
                .find(|e| e.record.id == proxy_id)
                .map(|e| e.circuit_breaker.clone())
        };
        if let Some(b) = breaker {
            b.report_success().await;
        }
    }

    /// Records a failed request to the given proxy (by id).
    pub async fn record_failure(&self, proxy_id: uuid::Uuid) {
        let breaker = {
            let entries = self.entries.lock().await;
            entries
                .iter()
                .find(|e| e.record.id == proxy_id)
                .map(|e| e.circuit_breaker.clone())
        };
        if let Some(b) = breaker {
            b.report_failure().await;
        }
    }
}

/// Error surfaced when no healthy proxy is available.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyRouteError {
    /// All proxies have their circuit breakers open.
    AllProxiesUnhealthy,
}

impl std::fmt::Display for ProxyRouteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AllProxiesUnhealthy => f.write_str("all workspace proxies are unhealthy"),
        }
    }
}

impl std::error::Error for ProxyRouteError {}

#[cfg(test)]
mod tests {
    use super::*;
    use coder_core::CircuitBreakerConfig;
    use time::OffsetDateTime;

    fn make_proxy(name: &str) -> WorkspaceProxyHealthRecord {
        WorkspaceProxyHealthRecord {
            id: uuid::Uuid::new_v4(),
            name: name.to_owned(),
            display_name: name.to_owned(),
            icon_url: String::new(),
            path_app_url: format!("http://{name}.example.com"),
            wildcard_hostname: String::new(),
            derp_enabled: false,
            derp_only: false,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            deleted: false,
            version: "1.0.0".to_owned(),
        }
    }

    fn fast_config() -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            failure_threshold: 2,
            reset_timeout: Duration::from_millis(50),
            half_open_max_probes: 1,
        }
    }

    #[tokio::test]
    async fn all_proxies_returned_when_healthy() {
        let router = ProxyRouter::new(fast_config());
        router
            .refresh(vec![make_proxy("us-east"), make_proxy("eu-west")])
            .await;

        let healthy = router.select_healthy_proxies().await;
        assert_eq!(healthy.len(), 2);
    }

    #[tokio::test]
    async fn deleted_proxies_are_excluded() {
        let router = ProxyRouter::new(fast_config());
        let mut proxy = make_proxy("deleted-proxy");
        proxy.deleted = true;
        router.refresh(vec![make_proxy("alive"), proxy]).await;

        let all = router.all_proxies().await;
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].record.name, "alive");
    }

    #[tokio::test]
    async fn unhealthy_proxy_is_skipped() {
        let router = ProxyRouter::new(fast_config());
        let proxy_a = make_proxy("healthy-proxy");
        let proxy_b = make_proxy("failing-proxy");
        let proxy_b_id = proxy_b.id;
        router.refresh(vec![proxy_a, proxy_b]).await;

        // Trip the circuit breaker for proxy_b.
        router.record_failure(proxy_b_id).await;
        router.record_failure(proxy_b_id).await;

        let healthy = router.select_healthy_proxies().await;
        assert_eq!(healthy.len(), 1);
        assert_eq!(healthy[0].record.name, "healthy-proxy");
    }

    #[tokio::test]
    async fn proxy_recovers_after_timeout() {
        let router = ProxyRouter::new(fast_config());
        let proxy = make_proxy("recovering");
        let proxy_id = proxy.id;
        router.refresh(vec![proxy]).await;

        // Trip the breaker.
        router.record_failure(proxy_id).await;
        router.record_failure(proxy_id).await;
        assert_eq!(router.select_healthy_proxies().await.len(), 0);

        // Wait for reset timeout.
        tokio::time::sleep(Duration::from_millis(60)).await;

        // Should be in half-open now, which counts as available.
        let healthy = router.select_healthy_proxies().await;
        assert_eq!(healthy.len(), 1);
    }

    #[tokio::test]
    async fn refresh_preserves_circuit_breaker_state() {
        let router = ProxyRouter::new(fast_config());
        let proxy = make_proxy("persistent");
        let proxy_id = proxy.id;
        router.refresh(vec![proxy.clone()]).await;

        // Record one failure.
        router.record_failure(proxy_id).await;

        // Refresh with the same proxy — breaker state should be preserved.
        router.refresh(vec![proxy]).await;

        let entries = router.all_proxies().await;
        assert_eq!(entries.len(), 1);
        let status = entries[0].circuit_breaker.status().await;
        assert_eq!(status.consecutive_failures, 1);
    }

    #[tokio::test]
    async fn needs_refresh_initially_true() {
        let router = ProxyRouter::new(fast_config());
        assert!(router.needs_refresh().await);
    }

    #[tokio::test]
    async fn needs_refresh_false_after_refresh() {
        let router = ProxyRouter::new(fast_config());
        router.refresh(vec![]).await;
        assert!(!router.needs_refresh().await);
    }
}
