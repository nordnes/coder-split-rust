//! Periodic aggregation worker for insights rollup tables.
//!
//! Mirrors Go's `coder/coderd/database/dbrollup/dbrollup.go`: every tick,
//! aggregate `workspace_agent_stats` and `workspace_app_stats` into the
//! `template_usage_stats` half-hour buckets so the insights endpoints can
//! read pre-computed aggregates rather than raw event rows.
//!
//! # Current status
//!
//! This worker wires the ticker into the server process with the correct
//! cadence (5 minutes by default, matching Go's `DefaultInterval`) and the
//! shared `advisory_lock_ids::DB_ROLLUP` advisory lock so concurrent
//! replicas do not duplicate work. **The rollup SQL itself is not yet
//! ported**: Go's `UpsertTemplateUsageStats` in
//! `coder/coderd/database/queries/insights.sql` is a ~100-line CTE that
//! flattens agent/app stats into half-hour buckets per template.
//! Porting it is tracked as a follow-up; the ticker here is intentionally
//! a no-op (returns `0` rows affected) today so the wiring lands
//! independently of the SQL port.
//!
//! The `template_usage_stats` target table already exists in
//! `crates/coder-db/migrations/20260308000001_templates_and_versions.sql`,
//! so the follow-up only needs to land the upsert query.

use std::sync::Arc;
use std::time::Duration;

use coder_core::AppStore;
use coder_core::ports::advisory_lock_ids;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Default interval between rollup sweeps. Mirrors Go's
/// `dbrollup.DefaultInterval = 5 * time.Minute`.
pub const DEFAULT_ROLLUP_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// Configuration for [`DbRollupWorker`].
#[derive(Clone, Debug)]
pub struct DbRollupOptions {
    /// How often the rollup runs.
    pub interval: Duration,
}

impl Default for DbRollupOptions {
    fn default() -> Self {
        Self {
            interval: DEFAULT_ROLLUP_INTERVAL,
        }
    }
}

/// Background worker that rolls `workspace_agent_stats` /
/// `workspace_app_stats` into `template_usage_stats` buckets at a fixed
/// cadence.
pub struct DbRollupWorker {
    handle: JoinHandle<()>,
}

impl DbRollupWorker {
    /// Spawns the rollup loop on the current Tokio runtime. The loop
    /// exits cleanly when `cancel` is triggered.
    #[must_use]
    pub fn start(
        store: Arc<dyn AppStore>,
        options: DbRollupOptions,
        cancel: CancellationToken,
    ) -> Self {
        let handle = tokio::spawn(async move {
            run_loop(store, options, cancel).await;
        });
        Self { handle }
    }

    /// Awaits the background task to completion. Call after cancelling
    /// the worker's token to guarantee in-flight DB queries land before
    /// the pool is closed.
    pub async fn join(self) {
        let _result = self.handle.await;
    }
}

async fn run_loop(store: Arc<dyn AppStore>, options: DbRollupOptions, cancel: CancellationToken) {
    let mut interval = tokio::time::interval(options.interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => {
                debug!(target: "coder_server::db_rollup", "shutting down");
                return;
            }
            _ = interval.tick() => {
                rollup_once(store.as_ref()).await;
            }
        }
    }
}

async fn rollup_once(store: &dyn AppStore) {
    // Advisory-lock guard: skip the tick if a peer replica is already
    // rolling up, so we do not do duplicate work. Mirrors Go's
    // `InTx { TryAcquireLock(LockIDDBRollup); UpsertTemplateUsageStats }`.
    let guard = match store
        .try_acquire_advisory_lock(advisory_lock_ids::DB_ROLLUP)
        .await
    {
        Ok(Some(g)) => g,
        Ok(None) => {
            debug!(
                target: "coder_server::db_rollup",
                "another replica holds the rollup lock; skipping sweep"
            );
            return;
        }
        Err(error) => {
            warn!(
                target: "coder_server::db_rollup",
                %error,
                "failed to acquire rollup advisory lock"
            );
            return;
        }
    };

    // TODO(dbrollup): Port Go's `UpsertTemplateUsageStats` CTE from
    // `coder/coderd/database/queries/insights.sql` into the Rust store.
    // Until then this sweep is a no-op; the ticker is wired so wiring
    // regressions surface independently of the SQL port, and switching
    // to a real upsert is a one-line change here plus the DB method.
    info!(
        target: "coder_server::db_rollup",
        "rollup sweep skipped (SQL port pending — Go UpsertTemplateUsageStats not yet ported)"
    );

    if let Err(error) = guard.release().await {
        warn!(
            target: "coder_server::db_rollup",
            %error,
            "failed to release rollup advisory lock"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_interval_matches_go() {
        assert_eq!(DbRollupOptions::default().interval, DEFAULT_ROLLUP_INTERVAL);
    }
}
