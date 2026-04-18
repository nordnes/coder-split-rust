//! Server-side workspace-app healthcheck prober.
//!
//! Ports the periodic prober behind `workspace_apps.health` from
//! `coder/coderd/workspaceapps/`. Each app with a non-empty
//! `healthcheck_url` is probed on its configured interval. On a state
//! transition we update `workspace_apps.health` in the DB.
//!
//! State machine per app (mirrors Go):
//! - `initializing` — the starting state for a freshly-created app.
//! - `healthy` — last probe was 2xx.
//! - `unhealthy` — `healthcheck_threshold` consecutive probes failed. One
//!   success immediately flips back to `healthy`.
//! - `disabled` — app has no `healthcheck_url` (these are not probed).
//!
//! The prober coexists with the agent-reported path (DRPC
//! `BatchUpdateAppHealths`); last-writer-wins on the DB column matches Go.

use std::{collections::HashMap, sync::Arc, time::Duration};

use coder_core::{AppStore, WorkspaceAppHealthcheckTarget};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};
use uuid::Uuid;

/// Default interval between prober ticks. Individual apps are only probed
/// when their configured `healthcheck_interval` has elapsed since the last
/// check, so a shorter tick merely means the loop wakes up more often.
pub const DEFAULT_PROBER_TICK: Duration = Duration::from_secs(15);

/// HTTP timeout applied to each probe.
pub const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

const HEALTH_HEALTHY: &str = "healthy";
const HEALTH_UNHEALTHY: &str = "unhealthy";
const HEALTH_INITIALIZING: &str = "initializing";

/// Options for the prober background loop.
#[derive(Clone, Debug)]
pub struct AppHealthcheckProberOptions {
    /// Interval between wake-ups of the outer loop. Individual apps honour
    /// their own `healthcheck_interval`.
    pub tick: Duration,
    /// Per-request timeout for the HTTP probe.
    pub probe_timeout: Duration,
}

impl Default for AppHealthcheckProberOptions {
    fn default() -> Self {
        Self {
            tick: DEFAULT_PROBER_TICK,
            probe_timeout: DEFAULT_PROBE_TIMEOUT,
        }
    }
}

/// Per-app state tracked across probes.
#[derive(Clone, Copy, Debug, Default)]
struct AppState {
    /// Unix-epoch seconds of the last probe attempt. `None` if never probed
    /// in this prober lifetime.
    last_probed_unix: Option<i64>,
    /// Count of consecutive failures observed. Reset to zero on success.
    consecutive_failures: u32,
}

/// Background worker that probes workspace-app health URLs and updates
/// `workspace_apps.health` on transition.
pub struct AppHealthcheckProber {
    store: Arc<dyn AppStore>,
    client: reqwest::Client,
    options: AppHealthcheckProberOptions,
    cancel: CancellationToken,
    state: Mutex<HashMap<Uuid, AppState>>,
}

/// Handle returned by [`AppHealthcheckProber::spawn`] — used by the
/// graceful-shutdown coordinator.
pub struct AppHealthcheckProberHandle {
    cancel: CancellationToken,
    join: tokio::task::JoinHandle<()>,
}

impl AppHealthcheckProberHandle {
    /// Cancels the loop and awaits the background task.
    pub async fn shutdown(self) {
        self.cancel.cancel();
        if let Err(error) = self.join.await {
            warn!(error = %error, "app healthcheck prober task panicked during shutdown");
        }
    }
}

impl AppHealthcheckProber {
    /// Builds a new prober. Use [`Self::spawn`] to start the loop.
    #[must_use]
    pub fn new(
        store: Arc<dyn AppStore>,
        client: reqwest::Client,
        options: AppHealthcheckProberOptions,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            store,
            client,
            options,
            cancel,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Spawns the background loop and returns a shutdown handle.
    #[must_use]
    pub fn spawn(self: Arc<Self>) -> AppHealthcheckProberHandle {
        let cancel = self.cancel.clone();
        let this = Arc::clone(&self);
        let join = tokio::spawn(async move {
            this.run().await;
        });
        AppHealthcheckProberHandle { cancel, join }
    }

    /// Runs a single tick — exposed for tests.
    pub async fn tick_now(&self) {
        if let Err(error) = self.tick().await {
            warn!(error = %error, "app healthcheck prober tick failed");
        }
    }

    async fn run(&self) {
        debug!("app healthcheck prober started");
        let mut interval = tokio::time::interval(self.options.tick);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => {
                    debug!("app healthcheck prober cancelled");
                    return;
                }
                _ = interval.tick() => {
                    if let Err(error) = self.tick().await {
                        warn!(error = %error, "app healthcheck prober tick failed");
                    }
                }
            }
        }
    }

    async fn tick(&self) -> Result<(), ProberError> {
        let targets = self
            .store
            .list_workspace_apps_with_healthchecks()
            .await
            .map_err(|e| ProberError::Store(e.to_string()))?;

        if targets.is_empty() {
            return Ok(());
        }

        let now_unix = offset_now_unix();
        for target in targets {
            if !self.is_due(&target, now_unix).await {
                continue;
            }
            self.probe_one(target, now_unix).await;
        }
        Ok(())
    }

    async fn is_due(&self, target: &WorkspaceAppHealthcheckTarget, now_unix: i64) -> bool {
        let interval = i64::from(target.app.healthcheck_interval.max(1));
        let state = self.state.lock().await;
        match state.get(&target.app.id).and_then(|s| s.last_probed_unix) {
            Some(last) => now_unix.saturating_sub(last) >= interval,
            None => true,
        }
    }

    async fn probe_one(&self, target: WorkspaceAppHealthcheckTarget, now_unix: i64) {
        let url = target.app.healthcheck_url.clone();
        let app_id = target.app.id;
        let threshold = u32::try_from(target.app.healthcheck_threshold.max(1)).unwrap_or(1);
        let success = self.probe_http(&url).await;

        let (consecutive_failures, old_status) = {
            let mut state = self.state.lock().await;
            let entry = state.entry(app_id).or_default();
            entry.last_probed_unix = Some(now_unix);
            let old_consecutive = entry.consecutive_failures;
            if success {
                entry.consecutive_failures = 0;
            } else {
                entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
            }
            (entry.consecutive_failures, old_consecutive)
        };

        let new_status =
            compute_new_status(success, consecutive_failures, threshold, &target.app.health);

        if new_status == target.app.health {
            return;
        }

        if let Err(error) = self
            .store
            .update_workspace_app_health(app_id, new_status)
            .await
        {
            warn!(
                app_id = %app_id,
                error = %error,
                "failed to persist workspace-app health transition"
            );
            return;
        }

        debug!(
            app_id = %app_id,
            from = %target.app.health,
            to = new_status,
            consecutive_failures,
            old_consecutive = old_status,
            "workspace-app health transitioned"
        );
    }

    async fn probe_http(&self, url: &str) -> bool {
        match self
            .client
            .get(url)
            .timeout(self.options.probe_timeout)
            .send()
            .await
        {
            Ok(resp) => resp.status().is_success(),
            Err(err) => {
                debug!(url, error = %err, "healthcheck probe failed");
                false
            }
        }
    }
}

fn compute_new_status(
    success: bool,
    consecutive_failures: u32,
    threshold: u32,
    current: &str,
) -> &'static str {
    if success {
        return HEALTH_HEALTHY;
    }
    if consecutive_failures >= threshold {
        return HEALTH_UNHEALTHY;
    }
    // Below the threshold we do not flip to unhealthy; preserve the
    // current status, promoting `initializing` to itself.
    match current {
        HEALTH_HEALTHY => HEALTH_HEALTHY,
        HEALTH_UNHEALTHY => HEALTH_UNHEALTHY,
        _ => HEALTH_INITIALIZING,
    }
}

fn offset_now_unix() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

#[derive(Debug, thiserror::Error)]
enum ProberError {
    #[error("store error: {0}")]
    Store(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_new_status_success_is_healthy() {
        assert_eq!(
            compute_new_status(true, 0, 3, HEALTH_INITIALIZING),
            HEALTH_HEALTHY
        );
        assert_eq!(
            compute_new_status(true, 2, 3, HEALTH_UNHEALTHY),
            HEALTH_HEALTHY
        );
    }

    #[test]
    fn compute_new_status_below_threshold_keeps_current() {
        assert_eq!(
            compute_new_status(false, 1, 3, HEALTH_HEALTHY),
            HEALTH_HEALTHY
        );
        assert_eq!(
            compute_new_status(false, 2, 3, HEALTH_INITIALIZING),
            HEALTH_INITIALIZING
        );
    }

    #[test]
    fn compute_new_status_at_threshold_is_unhealthy() {
        assert_eq!(
            compute_new_status(false, 3, 3, HEALTH_HEALTHY),
            HEALTH_UNHEALTHY
        );
        assert_eq!(
            compute_new_status(false, 5, 3, HEALTH_INITIALIZING),
            HEALTH_UNHEALTHY
        );
    }
}
