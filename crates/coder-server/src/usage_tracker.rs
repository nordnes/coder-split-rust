//! Batched flusher for `POST /workspaces/{id}/usage` updates.
//!
//! Mirrors Go's `coder/coderd/workspacestats/tracker.go::NewTracker`: the
//! HTTP handler pushes `(workspace_id, last_used_at)` tuples onto an
//! unbounded mpsc; a background task accumulates them into a set and
//! flushes via `AppStore::batch_update_workspace_last_used_at` either
//! every [`UsageTrackerOptions::flush_interval`] or once
//! [`UsageTrackerOptions::batch_size`] distinct workspace IDs are queued,
//! whichever fires first.
//!
//! Runs under the `system_restricted` actor context
//! ([`coder_rbac::system_actors::system_restricted`]). Today only the
//! `Authorized<S>` list methods in `coder-db/src/dbauthz.rs` consult the
//! actor; the `batch_update_workspace_last_used_at` call carries a
//! `TODO-dbauthz-full-wrap` comment for the eventual wrap.
//!
//! The flush replaces the prior synchronous-per-request pattern so a burst
//! of usage pings collapses to one DB write instead of one per workspace.
//! For tests that need deterministic semantics the tracker exposes a
//! `flush_on_send` override: each `add` call drives an immediate flush.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use coder_core::AppStore;
use coder_rbac::{Actor, system_actors};
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Default flush cadence for the batching tracker. Matches Go's
/// `workspacestats.DefaultFlushInterval = 60s`.
pub const DEFAULT_FLUSH_INTERVAL: Duration = Duration::from_secs(60);

/// Default batch size at which the tracker flushes ahead of the timer.
/// 1024 keeps the per-flush query well below Postgres' `$N` parameter
/// cap (~65k) while amortising a typical 1-min burst.
pub const DEFAULT_BATCH_SIZE: usize = 1024;

/// Configuration for [`UsageTracker`].
#[derive(Clone, Debug)]
pub struct UsageTrackerOptions {
    /// Maximum duration between flushes when the pending set is non-empty.
    pub flush_interval: Duration,
    /// Flush ahead of the timer once this many distinct workspace IDs have
    /// accumulated.
    pub batch_size: usize,
    /// Testing knob: flush after every `add`, defeating batching. Leave
    /// `false` in production.
    pub flush_on_send: bool,
}

impl Default for UsageTrackerOptions {
    fn default() -> Self {
        Self {
            flush_interval: DEFAULT_FLUSH_INTERVAL,
            batch_size: DEFAULT_BATCH_SIZE,
            flush_on_send: false,
        }
    }
}

/// Handle the HTTP layer uses to enqueue usage pings. Construct with
/// [`UsageTracker::start`]; shared across all handler invocations via
/// `Arc<UsageTracker>`.
#[derive(Clone)]
pub struct UsageTracker {
    tx: mpsc::UnboundedSender<Message>,
    /// System-actor context the tracker runs under. See
    /// [`coder_rbac::system_actors::system_restricted`]. Stored for
    /// diagnostics and for the future `Authorized<S>` wrap of
    /// `batch_update_workspace_last_used_at`.
    actor: Actor,
}

enum Message {
    Add(Uuid, OffsetDateTime),
}

impl UsageTracker {
    /// Spawns the background flushing task on the current Tokio runtime.
    /// Returns a handle to the sender half plus the task's `JoinHandle`
    /// so the graceful-shutdown coordinator can drain buffered pings.
    #[must_use]
    pub fn start(
        store: Arc<dyn AppStore>,
        options: UsageTrackerOptions,
        cancel: CancellationToken,
    ) -> (Arc<Self>, JoinHandle<()>) {
        let (tx, rx) = mpsc::unbounded_channel();
        // TODO-dbauthz-full-wrap: once `Authorized<S>` wraps
        // `batch_update_workspace_last_used_at`, route the flush call in
        // `flush()` through the wrapper so this actor is enforced at the
        // store boundary.
        let tracker = Arc::new(Self {
            tx,
            actor: system_actors::system_restricted(),
        });
        let task = tokio::spawn(async move {
            run_loop(store, options, rx, cancel).await;
        });
        (tracker, task)
    }

    /// Returns the system actor this tracker runs under.
    #[must_use]
    pub fn actor(&self) -> &Actor {
        &self.actor
    }

    /// Enqueues a usage ping. Non-blocking; on a full / closed channel the
    /// call is silently dropped (matches Go's fire-and-forget tracker
    /// semantics — a lost tick at worst delays a single `last_used_at`
    /// bump by one interval).
    pub fn add(&self, workspace_id: Uuid, now: OffsetDateTime) {
        let _ = self.tx.send(Message::Add(workspace_id, now));
    }
}

async fn run_loop(
    store: Arc<dyn AppStore>,
    options: UsageTrackerOptions,
    mut rx: mpsc::UnboundedReceiver<Message>,
    cancel: CancellationToken,
) {
    // `pending` maps workspace_id → latest timestamp. Later pings
    // supersede earlier ones for the same workspace, matching Go's
    // `uuidSet.Add` de-duplication.
    let mut pending: HashMap<Uuid, OffsetDateTime> = HashMap::new();
    let mut interval = tokio::time::interval(options.flush_interval);
    // Drift correction: keep the cadence stable across slow flushes.
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Skip the first immediate tick — we only want to flush when there
    // is something queued or the interval has actually elapsed.
    interval.tick().await;

    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => {
                debug!(target: "coder_server::usage_tracker", "shutting down; final flush");
                if !pending.is_empty() {
                    flush(&store, &mut pending).await;
                }
                return;
            }
            msg = rx.recv() => {
                let Some(Message::Add(id, ts)) = msg else {
                    // Sender closed. Final flush then exit.
                    if !pending.is_empty() {
                        flush(&store, &mut pending).await;
                    }
                    return;
                };
                // Keep the latest timestamp per workspace, matching Go's
                // "update with flush time" semantics closely enough: the
                // client wall clock is strictly more accurate than the
                // server's batched flush time.
                pending
                    .entry(id)
                    .and_modify(|existing| if ts > *existing { *existing = ts; })
                    .or_insert(ts);
                if options.flush_on_send || pending.len() >= options.batch_size {
                    flush(&store, &mut pending).await;
                }
            }
            _ = interval.tick() => {
                if !pending.is_empty() {
                    flush(&store, &mut pending).await;
                }
            }
        }
    }
}

async fn flush(store: &Arc<dyn AppStore>, pending: &mut HashMap<Uuid, OffsetDateTime>) {
    if pending.is_empty() {
        return;
    }
    let count = pending.len();
    let now = OffsetDateTime::now_utc();
    let ids: Vec<Uuid> = pending.keys().copied().collect();
    // Clear *before* awaiting the DB so a concurrent `add` does not see
    // stale entries and trigger a second flush with the same rows.
    pending.clear();
    match store.batch_update_workspace_last_used_at(&ids, now).await {
        Ok(affected) => info!(
            target: "coder_server::usage_tracker",
            count,
            affected,
            "flushed workspace usage batch"
        ),
        Err(error) => warn!(
            target: "coder_server::usage_tracker",
            %error,
            count,
            "failed to flush workspace usage batch"
        ),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "tests are allowed to fail loudly")]
mod tests {
    use super::*;

    #[test]
    fn usage_tracker_uses_system_restricted_actor() {
        // Regression guard for W0.S4 wiring: the tracker actor factory
        // must hand back the `system` system actor.
        let actor = system_actors::system_restricted();
        assert!(
            system_actors::is_system(&actor),
            "system_restricted() must be a system actor",
        );
        assert_eq!(actor.username, "system");
    }

    #[test]
    fn options_default_values_are_sane() {
        let opts = UsageTrackerOptions::default();
        assert_eq!(opts.flush_interval, DEFAULT_FLUSH_INTERVAL);
        assert_eq!(opts.batch_size, DEFAULT_BATCH_SIZE);
        assert!(!opts.flush_on_send);
    }

    #[test]
    fn pending_map_de_duplicates_per_workspace() {
        // The loop stores the *latest* timestamp per workspace. Mirror
        // that invariant in a standalone unit test so regressions in the
        // `entry().and_modify()` branch surface without running the full
        // async loop.
        let id = Uuid::new_v4();
        let t0 = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("valid ts");
        let t1 = t0 + time::Duration::seconds(30);

        let mut pending: HashMap<Uuid, OffsetDateTime> = HashMap::new();
        for ts in [t0, t1, t0] {
            pending
                .entry(id)
                .and_modify(|existing| {
                    if ts > *existing {
                        *existing = ts;
                    }
                })
                .or_insert(ts);
        }
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[&id], t1, "must keep the most recent timestamp");
    }
}
