//! Replica registration and heartbeat service.
//!
//! Ports the behaviour of `coder/enterprise/replicasync/replicasync.go` at
//! a minimal fidelity: each running `coderd` process registers itself in
//! the `replicas` table on startup, refreshes `updated_at` periodically,
//! prunes rows whose heartbeats have stopped, and deletes its own row
//! during graceful shutdown.
//!
//! The Go implementation additionally orchestrates DERP meshing and
//! sibling pubsub; those are intentionally out of scope here.  The
//! enterprise `/replicas` handler only needs the database view of the
//! current fleet.
//!
//! # Lifecycle
//!
//! ```ignore
//! let manager = ReplicaManager::start(
//!     store.clone(),
//!     ReplicaManagerOptions::default(),
//! )
//! .await?;
//! // … serve traffic …
//! manager.shutdown().await;
//! ```
//!
//! On drop, the background task is cancelled.  Prefer calling
//! [`ReplicaManager::shutdown`] explicitly during graceful shutdown so
//! the replica row is removed synchronously before the DB pool closes.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use coder_core::ports::DeploymentStore;
use coder_core::{AppStore, CoderdReplicaRow, InsertCoderdReplicaInput, StorageError};
use thiserror::Error;
use time::OffsetDateTime;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use uuid::Uuid;

/// Minimum allowed update interval — prevents pathologically fast polling.
const MIN_UPDATE_INTERVAL: Duration = Duration::from_millis(10);

/// Factor applied to the update interval to determine when rows are
/// considered stale.  Mirrors the Go `updateInterval` helper which uses
/// `now - 3 * updateInterval` as the liveness threshold.
///
/// Shared with the `/replicas` handler so the manager's prune policy
/// and the handler's staleness filter cannot drift out of sync.
pub(crate) const STALE_MULTIPLIER: u32 = 3;

/// Narrow storage trait the manager depends on.  Separating this from the
/// full `AppStore` keeps unit tests cheap: tests only need to implement
/// four small async methods on an in-memory fake.
#[async_trait]
pub trait ReplicaManagerStore: Send + Sync + 'static {
    /// Ping the backing database so the manager can record an initial
    /// database-latency reading.
    async fn ping(&self) -> Result<(), StorageError>;

    /// Insert the replica row for this process.
    async fn insert_coderd_replica(
        &self,
        input: InsertCoderdReplicaInput,
    ) -> Result<CoderdReplicaRow, StorageError>;

    /// Refresh `updated_at` for the replica row with the given id.
    async fn refresh_coderd_replica(
        &self,
        id: Uuid,
        updated_at: OffsetDateTime,
    ) -> Result<bool, StorageError>;

    /// Delete the replica row for this process.
    async fn delete_coderd_replica(&self, id: Uuid) -> Result<bool, StorageError>;

    /// Prune coderd replica rows whose `updated_at` is older than the
    /// supplied threshold.
    async fn prune_stale_coderd_replicas(
        &self,
        older_than: OffsetDateTime,
    ) -> Result<u64, StorageError>;
}

/// Adapter that exposes an [`AppStore`] trait object as a
/// [`ReplicaManagerStore`].  Callers that already hold an
/// `Arc<dyn AppStore>` (e.g. the server main) can wrap it once in this
/// newtype and pass the resulting `Arc<dyn ReplicaManagerStore>` to
/// [`ReplicaManager::start`] without introducing an extra `Arc` layer.
pub struct AppStoreReplicaAdapter(Arc<dyn AppStore>);

impl AppStoreReplicaAdapter {
    /// Wrap an existing `Arc<dyn AppStore>` so it can be used as a
    /// replica-manager store.
    #[must_use]
    pub fn new(store: Arc<dyn AppStore>) -> Self {
        Self(store)
    }
}

#[async_trait]
impl ReplicaManagerStore for AppStoreReplicaAdapter {
    async fn ping(&self) -> Result<(), StorageError> {
        DeploymentStore::ping(self.0.as_ref()).await
    }

    async fn insert_coderd_replica(
        &self,
        input: InsertCoderdReplicaInput,
    ) -> Result<CoderdReplicaRow, StorageError> {
        AppStore::insert_coderd_replica(self.0.as_ref(), input).await
    }

    async fn refresh_coderd_replica(
        &self,
        id: Uuid,
        updated_at: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        AppStore::refresh_coderd_replica(self.0.as_ref(), id, updated_at).await
    }

    async fn delete_coderd_replica(&self, id: Uuid) -> Result<bool, StorageError> {
        AppStore::delete_coderd_replica(self.0.as_ref(), id).await
    }

    async fn prune_stale_coderd_replicas(
        &self,
        older_than: OffsetDateTime,
    ) -> Result<u64, StorageError> {
        AppStore::prune_stale_coderd_replicas(self.0.as_ref(), older_than).await
    }
}

/// Tunable options for [`ReplicaManager`].
#[derive(Clone, Debug)]
pub struct ReplicaManagerOptions {
    /// Stable replica identifier for this process.  Defaults to a fresh
    /// `Uuid::new_v4()` each time the manager starts — matching the Go
    /// ephemeral-replica model.
    pub id: Uuid,
    /// Hostname to record in the replica row.
    pub hostname: String,
    /// Relay address used by this replica.  May be empty for
    /// non-HA deployments.
    pub relay_address: String,
    /// DERP region identifier.
    pub region_id: i32,
    /// Running coder version.
    pub version: String,
    /// How often to refresh `updated_at` and prune stale rows.
    pub update_interval: Duration,
}

impl Default for ReplicaManagerOptions {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            hostname: default_hostname(),
            relay_address: String::new(),
            region_id: 0,
            version: env!("CARGO_PKG_VERSION").to_string(),
            update_interval: Duration::from_secs(15),
        }
    }
}

/// Errors produced when constructing or running a [`ReplicaManager`].
#[derive(Debug, Error)]
pub enum ReplicaManagerError {
    /// Underlying storage error (insert, update, or delete failed).
    #[error("replica storage error: {0}")]
    Storage(#[from] StorageError),
}

/// Registered replica handle.  Drop or call [`Self::shutdown`] to stop
/// the heartbeat loop and delete the replica row.
pub struct ReplicaManager {
    id: Uuid,
    store: Arc<dyn ReplicaManagerStore>,
    cancel: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl ReplicaManager {
    /// Registers a new replica row and spawns the heartbeat loop.
    ///
    /// Accepts an already-shared `Arc<dyn ReplicaManagerStore>` so
    /// callers holding a trait-object store (e.g. `Arc<dyn AppStore>`
    /// wrapped via [`AppStoreReplicaAdapter`]) don't pay for a second
    /// `Arc` allocation.  Returns once the initial `INSERT` has
    /// completed so that the row is immediately visible to `/replicas`
    /// callers on other replicas.
    pub async fn start(
        store: Arc<dyn ReplicaManagerStore>,
        options: ReplicaManagerOptions,
    ) -> Result<Self, ReplicaManagerError> {
        let update_interval = options.update_interval.max(MIN_UPDATE_INTERVAL);
        let now = OffsetDateTime::now_utc();
        let database_latency = measure_latency_micros(store.as_ref()).await;

        let _inserted = store
            .insert_coderd_replica(InsertCoderdReplicaInput {
                id: options.id,
                hostname: options.hostname.clone(),
                relay_address: options.relay_address.clone(),
                region_id: options.region_id,
                version: options.version.clone(),
                database_latency,
                created_at: now,
                started_at: now,
                updated_at: now,
            })
            .await?;

        info!(
            replica_id = %options.id,
            hostname = %options.hostname,
            update_interval_secs = update_interval.as_secs(),
            "replica registered"
        );

        let cancel = CancellationToken::new();
        let task = {
            let store = store.clone();
            let cancel = cancel.clone();
            let id = options.id;
            tokio::spawn(async move {
                run_heartbeat_loop(store, id, update_interval, cancel).await;
            })
        };

        Ok(Self {
            id: options.id,
            store,
            cancel,
            task: Some(task),
        })
    }

    /// Returns the registered replica identifier.
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// Cancels the heartbeat loop, waits for in-flight work to complete,
    /// and deletes the replica row.  Safe to call multiple times.
    pub async fn shutdown(&mut self) {
        self.cancel.cancel();
        if let Some(handle) = self.task.take()
            && let Err(error) = handle.await
            && !error.is_cancelled()
        {
            warn!(error = %error, "replica heartbeat task failed to join");
        }
        match self.store.delete_coderd_replica(self.id).await {
            Ok(true) => info!(replica_id = %self.id, "replica row deleted"),
            Ok(false) => warn!(replica_id = %self.id, "replica row already absent on shutdown"),
            Err(error) => {
                warn!(replica_id = %self.id, error = %error, "failed to delete replica row");
            }
        }
    }
}

impl Drop for ReplicaManager {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// Periodically refresh `updated_at` and prune stale replica rows.
async fn run_heartbeat_loop(
    store: Arc<dyn ReplicaManagerStore>,
    id: Uuid,
    update_interval: Duration,
    cancel: CancellationToken,
) {
    let mut interval = tokio::time::interval(update_interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Consume the immediate first tick so the first heartbeat waits for
    // one interval — the insert in `start` already counts as t=0.
    interval.tick().await;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!(replica_id = %id, "replica heartbeat cancelled");
                return;
            }
            _ = interval.tick() => {}
        }

        if let Err(error) = refresh_and_prune(store.as_ref(), id, update_interval).await {
            warn!(replica_id = %id, error = %error, "replica heartbeat cycle failed");
        }
    }
}

/// Perform one heartbeat tick: refresh this replica's row and delete
/// rows whose `updated_at` is older than `3 * update_interval`.
async fn refresh_and_prune(
    store: &dyn ReplicaManagerStore,
    id: Uuid,
    update_interval: Duration,
) -> Result<(), StorageError> {
    let now = OffsetDateTime::now_utc();
    let updated = store.refresh_coderd_replica(id, now).await?;
    if !updated {
        warn!(replica_id = %id, "heartbeat found no replica row to refresh");
    }
    let threshold = now - stale_cutoff(update_interval);
    let _pruned = store.prune_stale_coderd_replicas(threshold).await?;
    Ok(())
}

/// Returns the `time::Duration` used as the staleness threshold for
/// pruning.  Go uses `3 * UpdateInterval`; we preserve the full
/// sub-second precision of the configured interval so small test
/// intervals don't truncate to zero.
fn stale_cutoff(update_interval: Duration) -> time::Duration {
    let scaled = update_interval.saturating_mul(STALE_MULTIPLIER);
    // `time::Duration::try_from` preserves nanosecond precision and
    // only errors when the std `Duration` exceeds `i64::MAX` seconds,
    // which is not physically achievable here but we guard against it
    // anyway.
    time::Duration::try_from(scaled).unwrap_or(time::Duration::MAX)
}

async fn measure_latency_micros(store: &dyn ReplicaManagerStore) -> i32 {
    let start = std::time::Instant::now();
    if let Err(error) = store.ping().await {
        warn!(error = %error, "replica manager ping failed");
        return 0;
    }
    i32::try_from(start.elapsed().as_micros()).unwrap_or(i32::MAX)
}

fn default_hostname() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string())
}

/// Build a [`ReplicaResponse`][coder_core::api::ReplicaResponse] from a
/// stored row.  This is the same shape used by the workspace-proxy
/// register endpoint and matches Go's `codersdk.Replica` JSON layout.
///
/// Shared by the `/replicas` handler and by tests.
pub(crate) fn replica_from_row(row: &CoderdReplicaRow) -> coder_core::api::ReplicaResponse {
    coder_core::api::ReplicaResponse {
        id: row.id,
        hostname: row.hostname.clone(),
        created_at: row.created_at,
        relay_address: row.relay_address.clone(),
        region_id: row.region_id,
        error: row.error.clone(),
        database_latency: row.database_latency,
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    #[derive(Default)]
    struct FakeReplicaStore {
        rows: StdMutex<Vec<CoderdReplicaRow>>,
    }

    impl FakeReplicaStore {
        fn rows(&self) -> Vec<CoderdReplicaRow> {
            self.rows.lock().unwrap_or_else(|p| p.into_inner()).clone()
        }

        fn insert_raw(&self, row: CoderdReplicaRow) {
            self.rows
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(row);
        }
    }

    #[async_trait]
    impl ReplicaManagerStore for FakeReplicaStore {
        async fn ping(&self) -> Result<(), StorageError> {
            Ok(())
        }

        async fn insert_coderd_replica(
            &self,
            input: InsertCoderdReplicaInput,
        ) -> Result<CoderdReplicaRow, StorageError> {
            let row = CoderdReplicaRow {
                id: input.id,
                hostname: input.hostname,
                relay_address: input.relay_address,
                region_id: input.region_id,
                version: input.version,
                error: String::new(),
                database_latency: input.database_latency,
                created_at: input.created_at,
                started_at: input.started_at,
                stopped_at: None,
                updated_at: input.updated_at,
            };
            self.rows
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(row.clone());
            Ok(row)
        }

        async fn refresh_coderd_replica(
            &self,
            id: Uuid,
            updated_at: OffsetDateTime,
        ) -> Result<bool, StorageError> {
            let mut rows = self.rows.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(row) = rows
                .iter_mut()
                .find(|r| r.id == id && r.stopped_at.is_none())
            {
                row.updated_at = updated_at;
                return Ok(true);
            }
            Ok(false)
        }

        async fn delete_coderd_replica(&self, id: Uuid) -> Result<bool, StorageError> {
            let mut rows = self.rows.lock().unwrap_or_else(|p| p.into_inner());
            let before = rows.len();
            rows.retain(|r| r.id != id);
            Ok(rows.len() != before)
        }

        async fn prune_stale_coderd_replicas(
            &self,
            older_than: OffsetDateTime,
        ) -> Result<u64, StorageError> {
            let mut rows = self.rows.lock().unwrap_or_else(|p| p.into_inner());
            let before = rows.len();
            rows.retain(|r| r.updated_at >= older_than);
            Ok((before - rows.len()) as u64)
        }
    }

    fn options(update_ms: u64) -> ReplicaManagerOptions {
        ReplicaManagerOptions {
            update_interval: Duration::from_millis(update_ms),
            ..ReplicaManagerOptions::default()
        }
    }

    fn as_replica_store(store: &Arc<FakeReplicaStore>) -> Arc<dyn ReplicaManagerStore> {
        store.clone()
    }

    #[tokio::test]
    async fn start_inserts_and_shutdown_deletes_row() {
        let store = Arc::new(FakeReplicaStore::default());
        let mut manager = ReplicaManager::start(as_replica_store(&store), options(50))
            .await
            .expect("start");
        assert_eq!(store.rows().len(), 1);

        manager.shutdown().await;
        assert!(store.rows().is_empty());
    }

    #[tokio::test]
    async fn heartbeat_refreshes_updated_at() {
        let store = Arc::new(FakeReplicaStore::default());
        let mut manager = ReplicaManager::start(as_replica_store(&store), options(20))
            .await
            .expect("start");
        let initial = store.rows()[0].updated_at;

        tokio::time::sleep(Duration::from_millis(120)).await;
        let rows = store.rows();
        assert_eq!(rows.len(), 1);
        assert!(
            rows[0].updated_at > initial,
            "expected heartbeat to refresh updated_at"
        );

        manager.shutdown().await;
    }

    #[tokio::test]
    async fn heartbeat_prunes_stale_rows() {
        let store = Arc::new(FakeReplicaStore::default());
        let stale_id = Uuid::new_v4();
        store.insert_raw(CoderdReplicaRow {
            id: stale_id,
            hostname: "stale-host".into(),
            relay_address: String::new(),
            region_id: 0,
            version: "0.0.0".into(),
            error: String::new(),
            database_latency: 0,
            created_at: OffsetDateTime::now_utc() - time::Duration::hours(1),
            started_at: OffsetDateTime::now_utc() - time::Duration::hours(1),
            stopped_at: None,
            updated_at: OffsetDateTime::now_utc() - time::Duration::hours(1),
        });

        let mut manager = ReplicaManager::start(as_replica_store(&store), options(20))
            .await
            .expect("start");

        // Wait for at least one heartbeat tick + prune.  With a 20 ms
        // update interval the stale cutoff is 60 ms, so the hour-old
        // row is well past that threshold and gets deleted on the first
        // prune pass.
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            if !store.rows().iter().any(|r| r.id == stale_id) {
                break;
            }
        }

        assert!(
            store.rows().iter().all(|r| r.id != stale_id),
            "stale row should have been pruned"
        );

        manager.shutdown().await;
    }

    #[tokio::test]
    async fn stale_cutoff_preserves_sub_second_precision() {
        // A 100ms update interval should produce a 300ms stale cutoff,
        // not truncate to 0.  Previously the implementation used
        // `.as_secs()` which silently rounded this down to zero and
        // caused all peer replicas to be pruned on every tick.
        let cutoff = stale_cutoff(Duration::from_millis(100));
        assert!(
            cutoff > time::Duration::milliseconds(299)
                && cutoff < time::Duration::milliseconds(301),
            "expected ~300ms cutoff, got {cutoff}"
        );

        let fresh_id = Uuid::new_v4();
        let store = Arc::new(FakeReplicaStore::default());
        store.insert_raw(CoderdReplicaRow {
            id: fresh_id,
            hostname: "peer".into(),
            relay_address: String::new(),
            region_id: 0,
            version: "0.0.0".into(),
            error: String::new(),
            database_latency: 0,
            created_at: OffsetDateTime::now_utc(),
            started_at: OffsetDateTime::now_utc(),
            stopped_at: None,
            // 50ms-old row: fresher than the 300ms cutoff, must NOT be pruned.
            updated_at: OffsetDateTime::now_utc() - time::Duration::milliseconds(50),
        });

        let mut manager = ReplicaManager::start(as_replica_store(&store), options(100))
            .await
            .expect("start");
        // Give the heartbeat loop at least one tick.
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(
            store.rows().iter().any(|r| r.id == fresh_id),
            "peer replica within the 3×interval window must not be pruned"
        );
        manager.shutdown().await;
    }

    #[tokio::test]
    async fn drop_cancels_background_task() {
        let store = Arc::new(FakeReplicaStore::default());
        let manager = ReplicaManager::start(as_replica_store(&store), options(20))
            .await
            .expect("start");
        let abort = manager.task.as_ref().map(|h| h.abort_handle());
        drop(manager);

        for _ in 0..50 {
            if let Some(h) = &abort
                && h.is_finished()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("background task did not stop after drop");
    }

    #[tokio::test]
    async fn replica_from_row_preserves_latency_microseconds() {
        let row = CoderdReplicaRow {
            id: Uuid::new_v4(),
            hostname: "h".into(),
            relay_address: "r".into(),
            region_id: 7,
            version: "1".into(),
            error: "oops".into(),
            database_latency: 123,
            created_at: OffsetDateTime::now_utc(),
            started_at: OffsetDateTime::now_utc(),
            stopped_at: None,
            updated_at: OffsetDateTime::now_utc(),
        };
        let replica = replica_from_row(&row);
        assert_eq!(replica.database_latency, 123);
        assert_eq!(replica.region_id, 7);
        assert_eq!(replica.error, "oops");
    }
}
