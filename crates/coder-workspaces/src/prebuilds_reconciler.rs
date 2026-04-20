//! Enterprise prebuild reconciliation loop.
//!
//! Minimum-shippable slice of Go's
//! `coder/enterprise/coderd/prebuilds/reconcile.go`. A ticker drives a
//! [`PrebuildReconciler::tick`] that snapshots presets with configured
//! prebuilds, computes the desired-vs-actual delta per preset, and emits
//! metrics. Create/delete of prebuilt workspaces is intentionally stubbed
//! (see `TODO-prebuild-build-action`) pending the build-creation wiring;
//! that stub is safe because the HTTP `/prebuilds/settings` routes and
//! metrics are meaningful without the actual spawn logic.
//!
//! When the build-creation helper chain is plumbed through we flip the
//! stub inside [`PrebuildReconciler::tick`] to call into the
//! workspace-build builder (the Go equivalent is
//! `wsbuilder.New(...).Build(...)`). Until then we log the intent and
//! bump metrics so operators can still observe the reconciler's
//! decisions.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use coder_core::StorageError;

use crate::builder::{PrebuildActions, PrebuildStartInput};

/// Go's `FailureHardLimitDefault` — the maximum number of consecutive
/// prebuild failures per preset before reconciliation stops creating new
/// prebuilds for it (deletions remain allowed). Mirrors
/// `codersdk.PrebuildsConfig.FailureHardLimit` default.
pub const PREBUILD_FAILURE_HARD_LIMIT: i32 = 3;

/// Default cadence of the reconciler tick. Go defaults to one minute in
/// `codersdk.PrebuildsConfig.ReconciliationInterval`.
pub const DEFAULT_RECONCILE_INTERVAL: Duration = Duration::from_secs(60);

/// Counter: prebuilt workspaces the reconciler has created (or intended
/// to create, while the build helper is stubbed).
pub const METRIC_PREBUILDS_CREATED_TOTAL: &str = "prebuilds_created_total";
/// Counter: prebuilt workspaces the reconciler has marked for deletion.
pub const METRIC_PREBUILDS_DELETED_TOTAL: &str = "prebuilds_deleted_total";
/// Gauge: current total number of running/pending prebuilt workspaces
/// across all presets.
pub const METRIC_PREBUILDS_CURRENT: &str = "prebuilds_current";
/// Gauge: sum of desired prebuild instances across all presets.
pub const METRIC_PREBUILDS_DESIRED: &str = "prebuilds_desired";
/// Counter: ticks that failed with a storage or internal error.
pub const METRIC_PREBUILDS_RECONCILE_ERRORS_TOTAL: &str = "prebuilds_reconcile_errors_total";
/// Histogram: reconcile tick duration in seconds.
pub const METRIC_PREBUILDS_TICK_DURATION_SECONDS: &str = "prebuilds_tick_duration_seconds";

/// Runtime configuration for [`PrebuildReconciler`].
#[derive(Clone, Debug)]
pub struct PrebuildReconcilerOptions {
    /// Cadence of the reconciler tick.
    pub tick_interval: Duration,
    /// Global hard-limit on the total number of prebuilt workspaces. When
    /// reaching this limit, new prebuild creates are suppressed. `None`
    /// disables the cap. Mirrors Go's `FailureHardLimit` in spirit but
    /// applied at the global level to keep the minimum slice simple.
    pub hard_limit: Option<usize>,
}

impl Default for PrebuildReconcilerOptions {
    fn default() -> Self {
        Self {
            tick_interval: DEFAULT_RECONCILE_INTERVAL,
            hard_limit: None,
        }
    }
}

/// Errors returned by the reconciler.
#[derive(Debug, thiserror::Error)]
pub enum ReconcileError {
    /// Storage failure while reading presets or counts.
    #[error("storage: {0}")]
    Storage(#[from] StorageError),
}

/// One preset's prebuild configuration as seen by the reconciler.
///
/// Mirrors the subset of Go's
/// `database.GetTemplatePresetsWithPrebuildsRow` that the reconciler
/// needs to decide actions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresetPrebuildInfo {
    /// Owning template id.
    pub template_id: Uuid,
    /// Active template version id (presets always belong to a version).
    pub template_version_id: Uuid,
    /// Organization the template belongs to. Needed by the
    /// [`crate::builder::PrebuildBuilder`] when spawning prebuilt
    /// workspaces.
    pub organization_id: Uuid,
    /// Preset id.
    pub preset_id: Uuid,
    /// Preset name (for logs/metrics).
    pub preset_name: String,
    /// Desired number of running prebuilt workspaces for this preset.
    pub desired_instances: u32,
    /// Whether the preset's template version is the template's active
    /// version. Inactive versions do not get new prebuilds created but
    /// may still have stale prebuilds deleted.
    pub using_active_version: bool,
    /// Whether the preset is currently hard-limited (too many consecutive
    /// failures). Hard-limited presets skip creates but can delete.
    pub is_hard_limited: bool,
}

/// A running (or pending) prebuilt workspace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrebuiltWorkspace {
    /// Workspace id.
    pub id: Uuid,
    /// Preset id the workspace was created for.
    pub preset_id: Uuid,
    /// Workspace creation timestamp — used to order deletion candidates
    /// (oldest first).
    pub created_at: OffsetDateTime,
}

/// Delta computed for a single preset during a reconciler tick.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PresetDelta {
    /// Preset id.
    pub preset_id: Uuid,
    /// Number of prebuilds the reconciler should create.
    pub to_create: u32,
    /// Workspace ids the reconciler should delete (oldest first).
    pub to_delete: Vec<Uuid>,
}

/// Stats returned from a single [`PrebuildReconciler::tick`] call.
///
/// Useful for tests and log observation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReconcileStats {
    /// Number of presets evaluated this tick.
    pub presets_evaluated: usize,
    /// Sum of `desired_instances` across all presets.
    pub total_desired: u64,
    /// Total running/pending prebuilt workspaces at the start of the tick.
    pub total_actual: u64,
    /// Number of prebuilds the reconciler intended to create.
    pub creates_requested: u64,
    /// Number of prebuilds actually created (stub returns 0 until wired).
    pub creates_executed: u64,
    /// Number of prebuilds the reconciler intended to delete.
    pub deletes_requested: u64,
    /// Number of prebuilds actually deleted (stub returns 0 until wired).
    pub deletes_executed: u64,
    /// Number of create actions suppressed by the global `hard_limit`.
    pub creates_suppressed_by_hard_limit: u64,
}

/// Narrow storage trait for the reconciler. Matches the subset of
/// `AppStore` calls the reconciler needs; a fake implementation is used
/// in unit tests.
#[async_trait]
pub trait PrebuildReconcilerStore: Send + Sync + 'static {
    /// Returns every preset with `desired_instances > 0` across all
    /// templates. Mirrors Go's `GetTemplatePresetsWithPrebuilds`.
    async fn list_presets_with_prebuilds(&self) -> Result<Vec<PresetPrebuildInfo>, StorageError>;

    /// Returns running/pending prebuilt workspaces owned by
    /// `PREBUILDS_SYSTEM_USER_ID`. Mirrors Go's
    /// `GetRunningPrebuiltWorkspaces`.
    async fn list_prebuilt_workspaces(&self) -> Result<Vec<PrebuiltWorkspace>, StorageError>;
}

/// Enterprise prebuild reconciler.
pub struct PrebuildReconciler<S>
where
    S: PrebuildReconcilerStore,
{
    store: Arc<S>,
    options: PrebuildReconcilerOptions,
    cancel: CancellationToken,
    last_stats: Mutex<Option<ReconcileStats>>,
    /// Build-action executor. When `None`, the reconciler logs + bumps
    /// metrics but performs no database writes; useful for tests and
    /// early-startup situations where the AppStore is not yet wired.
    actions: Option<Arc<dyn PrebuildActions>>,
}

impl<S> PrebuildReconciler<S>
where
    S: PrebuildReconcilerStore,
{
    /// Constructs a new reconciler without a build executor. Actions
    /// will be logged + metered but not persisted. Prefer
    /// [`Self::with_actions`] in production where the reconciler must
    /// actually spawn and delete workspaces.
    pub fn new(
        store: Arc<S>,
        options: PrebuildReconcilerOptions,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            store,
            options,
            cancel,
            last_stats: Mutex::new(None),
            actions: None,
        }
    }

    /// Constructs a reconciler wired to a [`PrebuildActions`] executor
    /// so the tick loop can actually create and delete prebuilt
    /// workspaces via `AppStore`.
    pub fn with_actions(
        store: Arc<S>,
        options: PrebuildReconcilerOptions,
        cancel: CancellationToken,
        actions: Arc<dyn PrebuildActions>,
    ) -> Self {
        Self {
            store,
            options,
            cancel,
            last_stats: Mutex::new(None),
            actions: Some(actions),
        }
    }

    /// Spawns the reconciler's background ticker loop. Returns a handle
    /// whose `join` awaits a clean shutdown.
    pub fn spawn(self: Arc<Self>) -> PrebuildReconcilerHandle {
        let cancel = self.cancel.clone();
        let interval = self.options.tick_interval;
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // First tick fires immediately; skip it so startup doesn't
            // double-trigger with the server bootstrap.
            ticker.tick().await;
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        debug!("prebuilds: reconciler loop cancelled, exiting");
                        break;
                    }
                    _ = ticker.tick() => {
                        if let Err(error) = self.tick().await {
                            metrics::counter!(METRIC_PREBUILDS_RECONCILE_ERRORS_TOTAL).increment(1);
                            warn!(error = %error, "prebuilds: tick failed");
                        }
                    }
                }
            }
        });
        PrebuildReconcilerHandle { join: handle }
    }

    /// Runs a single reconciliation pass.
    ///
    /// Pipeline:
    /// 1. Load the global snapshot (presets + current prebuilt workspaces).
    /// 2. Compute per-preset deltas (`desired - actual`).
    /// 3. Apply the global `hard_limit`: suppress creates that would push
    ///    total prebuilds past the limit.
    /// 4. Execute actions via [`PrebuildActions`] when wired, otherwise
    ///    log + emit metrics only.
    /// 5. Emit metrics.
    pub async fn tick(&self) -> Result<ReconcileStats, ReconcileError> {
        let start = std::time::Instant::now();

        let presets = self.store.list_presets_with_prebuilds().await?;
        let running = self.store.list_prebuilt_workspaces().await?;

        let mut stats = ReconcileStats {
            presets_evaluated: presets.len(),
            total_actual: u64::try_from(running.len()).unwrap_or(u64::MAX),
            ..ReconcileStats::default()
        };

        let deltas = compute_deltas(&presets, &running);
        stats.total_desired = presets.iter().map(|p| u64::from(p.desired_instances)).sum();

        let total_actual_usize = running.len();
        let hard_limit = self.options.hard_limit;
        let mut running_total = total_actual_usize;

        // Iterate over (preset, delta) pairs so the build executor has
        // the template / organization / version context it needs.
        for (preset, delta) in presets.iter().zip(deltas.into_iter()) {
            if !delta.to_delete.is_empty() {
                let count = u64::try_from(delta.to_delete.len()).unwrap_or(u64::MAX);
                stats.deletes_requested = stats.deletes_requested.saturating_add(count);
                for ws_id in &delta.to_delete {
                    metrics::counter!(METRIC_PREBUILDS_DELETED_TOTAL).increment(1);
                    running_total = running_total.saturating_sub(1);
                    match self.actions.as_ref() {
                        Some(actions) => match actions.delete_prebuild(*ws_id).await {
                            Ok(build) => {
                                stats.deletes_executed = stats.deletes_executed.saturating_add(1);
                                info!(
                                    preset_id = %delta.preset_id,
                                    workspace_id = %ws_id,
                                    build_id = %build.id,
                                    "prebuilds: delete-build enqueued"
                                );
                            }
                            Err(error) => {
                                metrics::counter!(METRIC_PREBUILDS_RECONCILE_ERRORS_TOTAL)
                                    .increment(1);
                                warn!(
                                    preset_id = %delta.preset_id,
                                    workspace_id = %ws_id,
                                    error = %error,
                                    "prebuilds: delete-build failed"
                                );
                            }
                        },
                        None => {
                            info!(
                                preset_id = %delta.preset_id,
                                workspace_id = %ws_id,
                                "prebuilds: would delete prebuilt workspace (no actions wired)"
                            );
                        }
                    }
                }
            }

            if delta.to_create > 0 {
                let requested = u64::from(delta.to_create);
                stats.creates_requested = stats.creates_requested.saturating_add(requested);

                for _ in 0..delta.to_create {
                    if let Some(limit) = hard_limit
                        && running_total >= limit
                    {
                        stats.creates_suppressed_by_hard_limit =
                            stats.creates_suppressed_by_hard_limit.saturating_add(1);
                        warn!(
                            preset_id = %delta.preset_id,
                            hard_limit = limit,
                            running_total = running_total,
                            "prebuilds: create suppressed by hard_limit"
                        );
                        continue;
                    }
                    metrics::counter!(METRIC_PREBUILDS_CREATED_TOTAL).increment(1);
                    running_total = running_total.saturating_add(1);
                    match self.actions.as_ref() {
                        Some(actions) => match actions
                            .create_prebuild(PrebuildStartInput {
                                organization_id: preset.organization_id,
                                template_id: preset.template_id,
                                template_version_id: preset.template_version_id,
                                preset_id: preset.preset_id,
                            })
                            .await
                        {
                            Ok(build) => {
                                stats.creates_executed = stats.creates_executed.saturating_add(1);
                                info!(
                                    preset_id = %delta.preset_id,
                                    workspace_id = %build.workspace_id,
                                    build_id = %build.id,
                                    "prebuilds: create-build enqueued"
                                );
                            }
                            Err(error) => {
                                metrics::counter!(METRIC_PREBUILDS_RECONCILE_ERRORS_TOTAL)
                                    .increment(1);
                                warn!(
                                    preset_id = %delta.preset_id,
                                    error = %error,
                                    "prebuilds: create-build failed"
                                );
                            }
                        },
                        None => {
                            info!(
                                preset_id = %delta.preset_id,
                                "prebuilds: would create prebuilt workspace (no actions wired)"
                            );
                        }
                    }
                }
            }
        }

        metrics::gauge!(METRIC_PREBUILDS_CURRENT).set(running_total as f64);
        metrics::gauge!(METRIC_PREBUILDS_DESIRED).set(stats.total_desired as f64);
        metrics::histogram!(METRIC_PREBUILDS_TICK_DURATION_SECONDS)
            .record(start.elapsed().as_secs_f64());

        debug!(?stats, "prebuilds: tick complete");

        *self.last_stats.lock().await = Some(stats.clone());
        Ok(stats)
    }

    /// Returns the most recent [`ReconcileStats`], if any. Useful for
    /// tests and debug surfaces.
    pub async fn last_stats(&self) -> Option<ReconcileStats> {
        self.last_stats.lock().await.clone()
    }
}

/// Join handle for a spawned reconciler.
pub struct PrebuildReconcilerHandle {
    join: tokio::task::JoinHandle<()>,
}

impl PrebuildReconcilerHandle {
    /// Waits for the background task to finish.
    pub async fn join(self) {
        if let Err(error) = self.join.await {
            error!(error = %error, "prebuilds: reconciler task panicked");
        }
    }
}

/// Pure function: given the snapshot inputs, compute per-preset deltas.
/// Exported for testability; has no side effects.
#[must_use]
pub fn compute_deltas(
    presets: &[PresetPrebuildInfo],
    running: &[PrebuiltWorkspace],
) -> Vec<PresetDelta> {
    use std::collections::HashMap;

    // Group running prebuilds by preset, preserving oldest-first order
    // for deletion candidates.
    let mut running_by_preset: HashMap<Uuid, Vec<&PrebuiltWorkspace>> = HashMap::new();
    for ws in running {
        running_by_preset.entry(ws.preset_id).or_default().push(ws);
    }
    for v in running_by_preset.values_mut() {
        v.sort_by_key(|ws| ws.created_at);
    }

    presets
        .iter()
        .map(|preset| {
            let actual = running_by_preset.get(&preset.preset_id).map_or(0, Vec::len);
            let desired = preset.desired_instances as usize;
            let mut delta = PresetDelta {
                preset_id: preset.preset_id,
                ..PresetDelta::default()
            };
            // Hard-limited and non-active-version presets can only shrink.
            let may_create = !preset.is_hard_limited && preset.using_active_version;

            if desired > actual && may_create {
                let diff = desired.saturating_sub(actual);
                delta.to_create = u32::try_from(diff).unwrap_or(u32::MAX);
            } else if actual > desired {
                // Delete the oldest excess prebuilds.
                let excess = actual.saturating_sub(desired);
                if let Some(ws_list) = running_by_preset.get(&preset.preset_id) {
                    delta.to_delete = ws_list.iter().take(excess).map(|ws| ws.id).collect();
                }
            }
            delta
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::{
        BUILD_REASON_PREBUILD, BuilderError, PrebuildActions, PrebuildStartInput,
    };
    use coder_core::PREBUILDS_SYSTEM_USER_ID;
    use coder_core::ports::WorkspaceBuildRecord;
    use std::sync::Mutex as StdMutex;
    use time::macros::datetime;

    struct FakePrebuildStore {
        presets: StdMutex<Vec<PresetPrebuildInfo>>,
        running: StdMutex<Vec<PrebuiltWorkspace>>,
    }

    impl FakePrebuildStore {
        fn new(presets: Vec<PresetPrebuildInfo>, running: Vec<PrebuiltWorkspace>) -> Arc<Self> {
            Arc::new(Self {
                presets: StdMutex::new(presets),
                running: StdMutex::new(running),
            })
        }
    }

    #[async_trait]
    impl PrebuildReconcilerStore for FakePrebuildStore {
        async fn list_presets_with_prebuilds(
            &self,
        ) -> Result<Vec<PresetPrebuildInfo>, StorageError> {
            Ok(self.presets.lock().map(|g| g.clone()).unwrap_or_default())
        }

        async fn list_prebuilt_workspaces(&self) -> Result<Vec<PrebuiltWorkspace>, StorageError> {
            Ok(self.running.lock().map(|g| g.clone()).unwrap_or_default())
        }
    }

    fn preset(name: &str, desired: u32, active: bool) -> PresetPrebuildInfo {
        PresetPrebuildInfo {
            template_id: Uuid::new_v4(),
            template_version_id: Uuid::new_v4(),
            organization_id: Uuid::new_v4(),
            preset_id: Uuid::new_v4(),
            preset_name: name.to_owned(),
            desired_instances: desired,
            using_active_version: active,
            is_hard_limited: false,
        }
    }

    fn ws(preset_id: Uuid, days_old: i64) -> PrebuiltWorkspace {
        PrebuiltWorkspace {
            id: Uuid::new_v4(),
            preset_id,
            created_at: datetime!(2026-01-01 00:00 UTC) + time::Duration::days(days_old),
        }
    }

    #[test]
    fn compute_deltas_creates_when_below_desired() {
        let p = preset("warm", 3, true);
        let deltas = compute_deltas(std::slice::from_ref(&p), &[]);
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].to_create, 3);
        assert!(deltas[0].to_delete.is_empty());
    }

    #[test]
    fn compute_deltas_deletes_excess_oldest_first() {
        let p = preset("warm", 1, true);
        let existing = vec![ws(p.preset_id, 10), ws(p.preset_id, 1), ws(p.preset_id, 5)];
        let oldest = existing[1].id; // day 1
        let middle = existing[2].id; // day 5
        // Two need deleting; oldest-first is day 1 then day 5.
        let deltas = compute_deltas(&[p], &existing);
        assert_eq!(deltas[0].to_delete, vec![oldest, middle]);
        assert_eq!(deltas[0].to_create, 0);
    }

    #[test]
    fn compute_deltas_skips_creates_for_hard_limited_preset() {
        let mut p = preset("warm", 5, true);
        p.is_hard_limited = true;
        let deltas = compute_deltas(&[p], &[]);
        assert_eq!(deltas[0].to_create, 0);
    }

    #[test]
    fn compute_deltas_skips_creates_for_non_active_version() {
        let p = preset("warm", 5, false);
        let deltas = compute_deltas(&[p], &[]);
        assert_eq!(deltas[0].to_create, 0);
    }

    #[test]
    fn compute_deltas_still_deletes_when_non_active_version() {
        let p = preset("warm", 0, false);
        let existing = vec![ws(p.preset_id, 1)];
        let deltas = compute_deltas(&[p], &existing);
        assert_eq!(deltas[0].to_delete.len(), 1);
    }

    #[tokio::test]
    async fn prebuild_reconciler_tick_calculates_deltas() {
        let p = preset("warm", 3, true);
        let existing = vec![ws(p.preset_id, 1)];
        let store = FakePrebuildStore::new(vec![p.clone()], existing);
        let reconciler = PrebuildReconciler::new(
            store,
            PrebuildReconcilerOptions::default(),
            CancellationToken::new(),
        );

        let stats = reconciler.tick().await.unwrap_or_default();
        assert_eq!(stats.presets_evaluated, 1);
        assert_eq!(stats.total_desired, 3);
        assert_eq!(stats.total_actual, 1);
        // Desired 3, actual 1 → want 2 creates.
        assert_eq!(stats.creates_requested, 2);
        // Stubbed execution: creates_executed remains 0 until the build
        // helper is wired. Metrics still fire.
        assert_eq!(stats.creates_executed, 0);
        assert_eq!(stats.deletes_requested, 0);
    }

    #[tokio::test]
    async fn prebuild_reconciler_respects_hard_limit() {
        // Two presets, each desiring 5 instances, but global hard_limit
        // is 3. Only 3 creates should be requested; the rest are
        // suppressed.
        let p1 = preset("a", 5, true);
        let p2 = preset("b", 5, true);
        let store = FakePrebuildStore::new(vec![p1, p2], vec![]);
        let reconciler = PrebuildReconciler::new(
            store,
            PrebuildReconcilerOptions {
                tick_interval: DEFAULT_RECONCILE_INTERVAL,
                hard_limit: Some(3),
            },
            CancellationToken::new(),
        );

        let stats = reconciler.tick().await.unwrap_or_default();
        // Each preset contributes 5 to creates_requested (10 total),
        // and 7 of those should be suppressed once the running total
        // reaches the cap.
        assert_eq!(stats.creates_requested, 10);
        assert_eq!(stats.creates_suppressed_by_hard_limit, 7);
    }

    #[tokio::test]
    async fn prebuild_reconciler_no_presets_is_noop() {
        let store = FakePrebuildStore::new(vec![], vec![]);
        let reconciler = PrebuildReconciler::new(
            store,
            PrebuildReconcilerOptions::default(),
            CancellationToken::new(),
        );
        let stats = reconciler.tick().await.unwrap_or_default();
        assert_eq!(stats.presets_evaluated, 0);
        assert_eq!(stats.creates_requested, 0);
        assert_eq!(stats.deletes_requested, 0);
    }

    /// In-memory [`PrebuildActions`] impl that records every
    /// create/delete request so the integration-ish test below can
    /// assert the reconciler drives the builder as expected.
    #[derive(Default)]
    struct RecordingActions {
        creates: StdMutex<Vec<PrebuildStartInput>>,
        deletes: StdMutex<Vec<Uuid>>,
    }

    #[async_trait]
    impl PrebuildActions for RecordingActions {
        async fn create_prebuild(
            &self,
            input: PrebuildStartInput,
        ) -> Result<WorkspaceBuildRecord, BuilderError> {
            if let Ok(mut guard) = self.creates.lock() {
                guard.push(input.clone());
            }
            Ok(WorkspaceBuildRecord {
                id: Uuid::new_v4(),
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
                workspace_id: Uuid::new_v4(),
                build_number: 1,
                transition: "start".to_owned(),
                job_id: Uuid::new_v4(),
                template_version_id: input.template_version_id,
                initiator_id: PREBUILDS_SYSTEM_USER_ID,
                provisioner_state: None,
                deadline: None,
                max_deadline: None,
                reason: BUILD_REASON_PREBUILD.to_owned(),
                daily_cost: 0,
            })
        }

        async fn delete_prebuild(
            &self,
            workspace_id: Uuid,
        ) -> Result<WorkspaceBuildRecord, BuilderError> {
            if let Ok(mut guard) = self.deletes.lock() {
                guard.push(workspace_id);
            }
            Ok(WorkspaceBuildRecord {
                id: Uuid::new_v4(),
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
                workspace_id,
                build_number: 2,
                transition: "delete".to_owned(),
                job_id: Uuid::new_v4(),
                template_version_id: Uuid::nil(),
                initiator_id: PREBUILDS_SYSTEM_USER_ID,
                provisioner_state: None,
                deadline: None,
                max_deadline: None,
                reason: BUILD_REASON_PREBUILD.to_owned(),
                daily_cost: 0,
            })
        }
    }

    #[tokio::test]
    async fn prebuild_reconciler_tick_creates_workspaces_via_builder() {
        // Seed a preset with desired=2 and no existing prebuilds.
        let p = preset("warm", 2, true);
        let store = FakePrebuildStore::new(vec![p.clone()], vec![]);
        let actions = Arc::new(RecordingActions::default());
        let reconciler = PrebuildReconciler::with_actions(
            store,
            PrebuildReconcilerOptions::default(),
            CancellationToken::new(),
            actions.clone() as Arc<dyn PrebuildActions>,
        );

        let stats = reconciler.tick().await.unwrap_or_default();
        assert_eq!(stats.creates_requested, 2, "two creates requested");
        assert_eq!(stats.creates_executed, 2, "two creates executed");

        let creates = actions
            .creates
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default();
        assert_eq!(creates.len(), 2, "two workspace rows landed via builder");
        for ci in &creates {
            assert_eq!(ci.preset_id, p.preset_id);
            assert_eq!(ci.template_id, p.template_id);
            assert_eq!(ci.template_version_id, p.template_version_id);
            assert_eq!(ci.organization_id, p.organization_id);
        }
    }

    #[tokio::test]
    async fn prebuild_reconciler_tick_deletes_oldest_prebuild_via_builder() {
        // desired=0 but 2 existing prebuilds → both should be deleted
        // oldest-first.
        let p = preset("warm", 0, true);
        let existing = vec![ws(p.preset_id, 10), ws(p.preset_id, 1)];
        let oldest_id = existing[1].id;
        let newer_id = existing[0].id;
        let store = FakePrebuildStore::new(vec![p.clone()], existing);
        let actions = Arc::new(RecordingActions::default());
        let reconciler = PrebuildReconciler::with_actions(
            store,
            PrebuildReconcilerOptions::default(),
            CancellationToken::new(),
            actions.clone() as Arc<dyn PrebuildActions>,
        );

        let stats = reconciler.tick().await.unwrap_or_default();
        assert_eq!(stats.deletes_requested, 2);
        assert_eq!(stats.deletes_executed, 2);

        let deletes = actions
            .deletes
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default();
        assert_eq!(deletes.len(), 2);
        assert_eq!(deletes[0], oldest_id, "oldest prebuild is deleted first");
        assert_eq!(
            deletes[1], newer_id,
            "next-oldest prebuild is deleted after"
        );
    }
}
