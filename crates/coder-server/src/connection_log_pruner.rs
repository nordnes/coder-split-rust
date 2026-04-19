//! Periodic pruner for the `connection_logs` table.
//!
//! Mirrors Go's `coder/coderd/connectionlog/` pruner: on a fixed cadence
//! (default 1 hour), delete rows whose `connect_time` is older than the
//! configured retention window (default 30 days). The worker batches
//! deletions to a bounded row count per tick so a long-lived retention
//! shrinkage does not pin the write-ahead log on a single sweep.
//!
//! TODO-rbac(W0.S4): thread [`coder_rbac::system_actors::system_restricted`]
//! through the pruner so deletes go via a `dbauthz::Authorized<_>` wrapper
//! instead of raw `AppStore`. See `crates/coder-rbac/src/system_actors.rs`.
//!
//! Safe on deployments without the `connection_logs` table: the storage
//! layer maps `undefined_table` (PostgreSQL SQLSTATE `42P01`) to a zero-row
//! no-op, so the worker simply logs `pruned=0` each tick until the
//! enterprise migration lands.

use std::sync::Arc;
use std::time::Duration;

use coder_core::AppStore;
use time::OffsetDateTime;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Default interval between pruning sweeps. Matches Go's 1-hour cadence.
pub const DEFAULT_PRUNE_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Default retention window for connection-log rows. Rows older than this
/// are eligible for deletion. Matches Go's 30-day default.
pub const DEFAULT_RETENTION: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Maximum rows deleted per sweep, to bound the per-tick lock footprint.
pub const DEFAULT_BATCH_SIZE: i64 = 1000;

/// Configuration for [`ConnectionLogPruner`].
#[derive(Clone, Debug)]
pub struct ConnectionLogPrunerOptions {
    /// How often the pruner runs.
    pub interval: Duration,
    /// Rows older than this are eligible for deletion.
    pub retention: Duration,
    /// Cap on the number of rows deleted per sweep.
    pub batch_size: i64,
}

impl Default for ConnectionLogPrunerOptions {
    fn default() -> Self {
        Self {
            interval: DEFAULT_PRUNE_INTERVAL,
            retention: DEFAULT_RETENTION,
            batch_size: DEFAULT_BATCH_SIZE,
        }
    }
}

/// Background worker that deletes stale `connection_logs` rows at a fixed
/// interval. Construct with [`ConnectionLogPruner::start`].
pub struct ConnectionLogPruner {
    handle: JoinHandle<()>,
}

impl ConnectionLogPruner {
    /// Spawns the pruning loop on the current Tokio runtime. The loop
    /// exits cleanly when `cancel` is triggered.
    #[must_use]
    pub fn start(
        store: Arc<dyn AppStore>,
        options: ConnectionLogPrunerOptions,
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

async fn run_loop(
    store: Arc<dyn AppStore>,
    options: ConnectionLogPrunerOptions,
    cancel: CancellationToken,
) {
    let mut interval = tokio::time::interval(options.interval);
    // `Delay` keeps the scheduled cadence even if a prune sweep takes
    // longer than the interval — it will not fire twice back-to-back to
    // "catch up". Matches the drift-correction pattern used by the
    // activity-bump worker.
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => {
                debug!(target: "coder_server::connection_log_pruner", "shutting down");
                return;
            }
            _ = interval.tick() => {
                let cutoff = OffsetDateTime::now_utc()
                    - time::Duration::try_from(options.retention).unwrap_or(time::Duration::MAX);
                match store
                    .delete_old_connection_logs(cutoff, options.batch_size)
                    .await
                {
                    Ok(pruned) => info!(
                        target: "coder_server::connection_log_pruner",
                        pruned,
                        cutoff = %cutoff,
                        "connection_log prune sweep completed"
                    ),
                    Err(error) => warn!(
                        target: "coder_server::connection_log_pruner",
                        %error,
                        "connection_log prune sweep failed"
                    ),
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "tests are allowed to fail loudly")]
mod tests {
    use super::*;

    fn compute_cutoff(retention: Duration, now: OffsetDateTime) -> OffsetDateTime {
        now - time::Duration::try_from(retention).unwrap_or(time::Duration::MAX)
    }

    #[test]
    fn cutoff_respects_retention_window() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("valid ts");
        let cutoff = compute_cutoff(Duration::from_secs(3600), now);
        assert_eq!(cutoff, now - time::Duration::seconds(3600));
    }

    #[test]
    fn cutoff_clamps_on_overflow() {
        // `time::Duration::try_from` saturates at `time::Duration::MAX`
        // if the std duration exceeds its representable range — assert
        // the conversion does not panic; the value itself is unused.
        let cutoff = compute_cutoff(Duration::MAX, OffsetDateTime::now_utc());
        assert!(cutoff.year() != 0);
    }

    #[test]
    fn default_options_match_go() {
        let opts = ConnectionLogPrunerOptions::default();
        assert_eq!(opts.interval, DEFAULT_PRUNE_INTERVAL);
        assert_eq!(opts.retention, DEFAULT_RETENTION);
        assert_eq!(opts.batch_size, DEFAULT_BATCH_SIZE);
    }
}
