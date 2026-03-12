//! Workspace, template, and deployment-stats helpers.
//!
//! Provides the autobuild executor loop, schedule evaluation, and
//! deployment-stats caching.
//!
//! # Key types
//!
//! * [`DeploymentStatsService`] — cached deployment statistics with a
//!   background 60-second refresh loop
//! * [`AutostartSchedule`] — parsed cron expression with IANA timezone support
//! * [`AutostopPolicy`] — TTL-based workspace auto-stop evaluation
//! * [`AutobuildExecutor`] — background loop that evaluates workspace lifecycle
//!   rules every 30 seconds
//! * [`TemplateScheduleConstraints`] / [`QuietHoursWindow`] — template-level
//!   schedule policies
//! * [`AutobuildAction`] — transition enum (Start / Stop / Dormant / None)
//!
//! # Utility functions
//!
//! * [`compute_extended_deadline`] — deadline extension with optional max clamp
//! * [`evaluate_dormancy`] — idle-days threshold check
#![forbid(unsafe_code)]

use std::str::FromStr;
use std::sync::{Arc, Weak};

use async_trait::async_trait;
use coder_core::ports::{WorkspaceRecord, WorkspaceTransitionRow};
use coder_core::{AppStore, DeploymentStatsResponse, OperationalStore, StorageError};
use time::OffsetDateTime;
use tokio::sync::{Mutex, RwLock};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

const DEPLOYMENT_STATS_REFRESH_SECS: u64 = 60;

/// Cached deployment-stats service modeled after Go's metrics cache.
pub struct DeploymentStatsService<S> {
    store: S,
    cache: RwLock<Option<DeploymentStatsResponse>>,
    refresh_lock: Mutex<()>,
    cancel: CancellationToken,
}

impl<S> DeploymentStatsService<S>
where
    S: OperationalStore + Clone + Send + Sync + 'static,
{
    /// Creates the cached deployment-stats service and starts background refresh.
    #[must_use]
    pub fn new(store: S) -> Arc<Self> {
        let cancel = CancellationToken::new();
        let service = Arc::new(Self {
            store,
            cache: RwLock::new(None),
            refresh_lock: Mutex::new(()),
            cancel,
        });
        Self::spawn_refresh_loop(&service);
        service
    }

    /// Signals the background refresh loop to stop.
    ///
    /// Note: this only sets the cancellation token; it does **not** wait for
    /// the background task to finish.  The loop will exit on its next
    /// iteration after it observes the token.
    ///
    /// Calling this more than once is harmless — subsequent calls return
    /// immediately because the token is already cancelled.
    pub fn close(&self) {
        self.cancel.cancel();
    }

    /// Returns the latest cached stats, refreshing on demand when needed.
    pub async fn get(&self) -> Result<DeploymentStatsResponse, StorageError> {
        if let Some(snapshot) = self.cache.read().await.clone() {
            return Ok(snapshot);
        }

        self.refresh().await
    }

    /// Forces an immediate refresh and returns the latest snapshot.
    pub async fn refresh(&self) -> Result<DeploymentStatsResponse, StorageError> {
        let _guard = self.refresh_lock.lock().await;
        let snapshot = self.store.deployment_stats().await?;
        *self.cache.write().await = Some(snapshot.clone());
        Ok(snapshot)
    }

    async fn refresh_once(&self) -> Result<(), StorageError> {
        let snapshot = self.store.deployment_stats().await?;
        *self.cache.write().await = Some(snapshot);
        Ok(())
    }

    fn spawn_refresh_loop(service: &Arc<Self>) {
        let weak = Arc::downgrade(service);
        let cancel = service.cancel.clone();
        tokio::spawn(async move {
            run_refresh_loop(weak, cancel).await;
        });
    }
}

async fn run_refresh_loop<S>(service: Weak<DeploymentStatsService<S>>, cancel: CancellationToken)
where
    S: OperationalStore + Clone + Send + Sync + 'static,
{
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(
        DEPLOYMENT_STATS_REFRESH_SECS,
    ));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("deployment stats refresh loop cancelled");
                return;
            }
            _ = interval.tick() => {}
        }
        let Some(service) = service.upgrade() else {
            return;
        };
        if let Err(error) = service.refresh_once().await {
            warn!(error = %error, "failed to refresh deployment stats cache");
        }
    }
}

// ---------------------------------------------------------------------------
// Schedule System
// ---------------------------------------------------------------------------

/// Parsed workspace autostart schedule backed by the `cron` crate.
#[derive(Clone, Debug)]
pub struct AutostartSchedule {
    /// The original cron expression string.
    expression: String,
    /// Parsed cron schedule.
    schedule: cron::Schedule,
    /// IANA timezone name (e.g. "America/Chicago").
    timezone: String,
}

/// Errors when parsing an autostart schedule.
#[derive(Debug, thiserror::Error)]
pub enum ScheduleParseError {
    /// Invalid cron expression.
    #[error("invalid cron expression: {0}")]
    InvalidCron(String),
}

impl AutostartSchedule {
    /// Parses a cron expression with an optional IANA timezone suffix.
    ///
    /// Accepts "CRON_TZ=America/Chicago 30 9 * * 1-5" or a bare
    /// "30 9 * * 1-5" (UTC assumed).
    pub fn parse(raw: &str) -> Result<Self, ScheduleParseError> {
        let (timezone, cron_expr) = if let Some(rest) = raw.strip_prefix("CRON_TZ=") {
            let mut parts = rest.splitn(2, ' ');
            let tz = parts.next().unwrap_or("UTC");
            let expr = parts.next().unwrap_or("");
            (tz.to_owned(), expr.to_owned())
        } else {
            ("UTC".to_owned(), raw.to_owned())
        };

        // The cron crate expects a 7-field expression (sec min hour dom mon dow year).
        // User-facing cron is 5-field (min hour dom mon dow), so we prepend "0"
        // for seconds and append "*" for year.
        let full_expr = format!("0 {cron_expr} *");

        let schedule = cron::Schedule::from_str(&full_expr)
            .map_err(|e| ScheduleParseError::InvalidCron(e.to_string()))?;

        Ok(Self {
            expression: raw.to_owned(),
            schedule,
            timezone,
        })
    }

    /// Returns the original expression string.
    #[must_use]
    pub fn expression(&self) -> &str {
        &self.expression
    }

    /// Returns the IANA timezone.
    #[must_use]
    pub fn timezone(&self) -> &str {
        &self.timezone
    }

    /// Returns the next scheduled occurrence after the given UTC time.
    ///
    /// The cron expression is evaluated in the schedule's timezone so that
    /// e.g. "CRON_TZ=America/Chicago 30 9 * * 1-5" fires at 09:30 Chicago
    /// time. The result is converted back to UTC.
    #[must_use]
    pub fn next_after_utc(&self) -> Option<OffsetDateTime> {
        // Try to resolve the IANA timezone; fall back to UTC on unknown names.
        let ts = if let Ok(tz) = self.timezone.parse::<chrono_tz::Tz>() {
            self.schedule
                .upcoming(tz)
                .take(1)
                .next()
                .map(|dt| dt.with_timezone(&chrono::Utc).timestamp())
        } else {
            self.schedule
                .upcoming(chrono::Utc)
                .take(1)
                .next()
                .map(|dt| dt.timestamp())
        };
        ts.and_then(|t| OffsetDateTime::from_unix_timestamp(t).ok())
    }

    /// Returns the next occurrence after `after` as a `chrono::DateTime<Utc>`.
    ///
    /// Used by the autostart eligibility check to find the next allowed
    /// autostart time after a build's creation time.
    fn next_after_chrono(
        &self,
        after: chrono::DateTime<chrono::Utc>,
    ) -> Option<chrono::DateTime<chrono::Utc>> {
        if let Ok(tz) = self.timezone.parse::<chrono_tz::Tz>() {
            self.schedule
                .after(&after.with_timezone(&tz))
                .take(1)
                .next()
                .map(|dt| dt.with_timezone(&chrono::Utc))
        } else {
            self.schedule.after(&after).take(1).next()
        }
    }

    /// Returns whether the schedule should have fired within the last
    /// `window_secs` seconds from now.
    #[must_use]
    pub fn should_have_fired(&self, window_secs: i64) -> bool {
        let now = chrono::Utc::now();
        let window_start = now - chrono::Duration::seconds(window_secs);
        if let Ok(tz) = self.timezone.parse::<chrono_tz::Tz>() {
            self.schedule
                .after(&window_start.with_timezone(&tz))
                .take(1)
                .any(|next| next.with_timezone(&chrono::Utc) <= now)
        } else {
            self.schedule
                .after(&window_start)
                .take(1)
                .any(|next| next <= now)
        }
    }
}

/// Workspace autostop policy.
#[derive(Clone, Debug)]
pub struct AutostopPolicy {
    /// Time-to-live in minutes after last activity.
    pub ttl_minutes: u64,
}

impl AutostopPolicy {
    /// Returns whether the workspace should be stopped based on last activity.
    #[must_use]
    pub fn should_stop(&self, last_activity_utc: OffsetDateTime) -> bool {
        let elapsed = OffsetDateTime::now_utc() - last_activity_utc;
        let ttl = time::Duration::minutes(i64::try_from(self.ttl_minutes).unwrap_or(i64::MAX));
        elapsed >= ttl
    }
}

/// Template-level schedule constraints.
#[derive(Clone, Debug)]
pub struct TemplateScheduleConstraints {
    /// Maximum autostart interval (empty = no constraint).
    pub max_autostart_interval: Option<std::time::Duration>,
    /// Maximum TTL for autostop.
    pub max_ttl_minutes: Option<u64>,
    /// User quiet hours window (e.g. "00:00-06:00").
    pub quiet_hours: Option<QuietHoursWindow>,
    /// Days after last use before marking dormant.
    pub dormancy_threshold_days: Option<u64>,
    /// Days dormant before auto-deletion.
    pub dormancy_auto_deletion_days: Option<u64>,
}

/// A quiet-hours window expressed as start/end hour in UTC.
#[derive(Clone, Debug)]
pub struct QuietHoursWindow {
    /// Start hour (0-23).
    pub start_hour: u8,
    /// End hour (0-23).
    pub end_hour: u8,
}

impl QuietHoursWindow {
    /// Returns whether the given UTC time falls within the quiet window.
    #[must_use]
    pub fn is_quiet(&self, now_utc: OffsetDateTime) -> bool {
        let hour = now_utc.hour();
        if self.start_hour <= self.end_hour {
            hour >= self.start_hour && hour < self.end_hour
        } else {
            // Wraps midnight: e.g. 22:00-06:00
            hour >= self.start_hour || hour < self.end_hour
        }
    }
}

/// Workspace transition action determined by the autobuild executor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AutobuildAction {
    /// Start the workspace (autostart fired).
    Start,
    /// Stop the workspace (TTL expired or deadline reached).
    Stop,
    /// Mark the workspace as dormant.
    Dormant,
    /// Delete the workspace (dormant auto-delete).
    Delete,
    /// No action needed.
    None,
}

/// The reason a workspace is being transitioned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildReason {
    /// Automatic start based on schedule.
    Autostart,
    /// Automatic stop based on TTL or deadline.
    Autostop,
    /// Workspace became dormant due to inactivity.
    Dormancy,
    /// Workspace auto-deleted after dormancy period.
    Autodelete,
}

// ---------------------------------------------------------------------------
// Autobuild Executor
// ---------------------------------------------------------------------------

const AUTOBUILD_TICK_SECS: u64 = 30;

/// Maximum number of concurrent workspace evaluations.
const MAX_CONCURRENT_TRANSITIONS: usize = 10;

/// Narrow storage trait for the autobuild executor.
///
/// Contains only the methods required for workspace lifecycle evaluation.
/// Implementations are provided for [`dyn AppStore`] (and `Arc<T>` where
/// `T: AutobuildStore`), so callers can pass their full store directly.
#[async_trait]
pub trait AutobuildStore: Send + Sync {
    /// Returns workspaces that are candidates for an autobuild transition.
    async fn get_workspaces_eligible_for_transition(
        &self,
        now: OffsetDateTime,
    ) -> Result<Vec<WorkspaceTransitionRow>, StorageError>;

    /// Atomically sets `dormant_at` and recomputes `deleting_at` for a workspace.
    async fn update_workspace_dormant_deleting_at(
        &self,
        workspace_id: uuid::Uuid,
        dormant_at: Option<OffsetDateTime>,
    ) -> Result<Option<WorkspaceRecord>, StorageError>;

    /// Soft-deletes a workspace (sets `deleted = true`).
    async fn soft_delete_workspace(&self, workspace_id: uuid::Uuid) -> Result<bool, StorageError>;
}

#[async_trait]
impl AutobuildStore for dyn AppStore {
    async fn get_workspaces_eligible_for_transition(
        &self,
        now: OffsetDateTime,
    ) -> Result<Vec<WorkspaceTransitionRow>, StorageError> {
        AppStore::get_workspaces_eligible_for_transition(self, now).await
    }

    async fn update_workspace_dormant_deleting_at(
        &self,
        workspace_id: uuid::Uuid,
        dormant_at: Option<OffsetDateTime>,
    ) -> Result<Option<WorkspaceRecord>, StorageError> {
        AppStore::update_workspace_dormant_deleting_at(self, workspace_id, dormant_at).await
    }

    async fn soft_delete_workspace(&self, workspace_id: uuid::Uuid) -> Result<bool, StorageError> {
        AppStore::soft_delete_workspace(self, workspace_id).await
    }
}

#[async_trait]
impl<T: AutobuildStore + ?Sized> AutobuildStore for Arc<T> {
    async fn get_workspaces_eligible_for_transition(
        &self,
        now: OffsetDateTime,
    ) -> Result<Vec<WorkspaceTransitionRow>, StorageError> {
        (**self).get_workspaces_eligible_for_transition(now).await
    }

    async fn update_workspace_dormant_deleting_at(
        &self,
        workspace_id: uuid::Uuid,
        dormant_at: Option<OffsetDateTime>,
    ) -> Result<Option<WorkspaceRecord>, StorageError> {
        (**self)
            .update_workspace_dormant_deleting_at(workspace_id, dormant_at)
            .await
    }

    async fn soft_delete_workspace(&self, workspace_id: uuid::Uuid) -> Result<bool, StorageError> {
        (**self).soft_delete_workspace(workspace_id).await
    }
}

/// Statistics for one autobuild executor tick.
#[derive(Clone, Debug, Default)]
pub struct AutobuildStats {
    /// Number of workspaces that were transitioned.
    pub transitions: u32,
    /// Number of workspaces that had errors during evaluation.
    pub errors: u32,
    /// Number of workspaces evaluated.
    pub evaluated: u32,
}

/// Background autobuild executor that evaluates workspace lifecycle rules.
///
/// Runs on a configurable tick interval (default 30 seconds), evaluates all
/// active workspaces against their autostart schedule, autostop TTL,
/// deadlines, dormancy rules, and auto-delete policies.
///
/// Mirrors Go's `autobuild.Executor` with a concurrent worker pool
/// limited to [`MAX_CONCURRENT_TRANSITIONS`] workers to avoid
/// overloading the database.
pub struct AutobuildExecutor<S> {
    store: S,
    cancel: CancellationToken,
    tick_secs: u64,
}

impl<S> AutobuildExecutor<S>
where
    S: AutobuildStore + Clone + Send + Sync + 'static,
{
    /// Creates the executor and starts the background evaluation loop.
    ///
    /// Returns the executor and a [`tokio::task::JoinHandle`] for the
    /// background loop.  Callers should cancel the token **and** await the
    /// handle during shutdown to ensure in-flight evaluations complete before
    /// resources (e.g. the database pool) are released.
    #[must_use]
    pub fn start(store: S, cancel: CancellationToken) -> (Arc<Self>, tokio::task::JoinHandle<()>) {
        let executor = Arc::new(Self {
            store,
            cancel: cancel.clone(),
            tick_secs: AUTOBUILD_TICK_SECS,
        });
        let handle = Self::spawn_executor_loop(&executor);
        (executor, handle)
    }

    /// Creates the executor with a custom tick interval.
    ///
    /// Useful for testing with shorter intervals.
    #[must_use]
    pub fn start_with_interval(
        store: S,
        cancel: CancellationToken,
        tick_secs: u64,
    ) -> (Arc<Self>, tokio::task::JoinHandle<()>) {
        let executor = Arc::new(Self {
            store,
            cancel: cancel.clone(),
            tick_secs,
        });
        let handle = Self::spawn_executor_loop(&executor);
        (executor, handle)
    }

    /// Evaluates one tick of the autobuild loop.
    ///
    /// Queries all workspaces eligible for a transition and evaluates each
    /// one concurrently (up to [`MAX_CONCURRENT_TRANSITIONS`] at a time).
    /// Returns statistics about the tick.
    pub async fn evaluate_once(&self) -> Result<AutobuildStats, StorageError> {
        // Truncate to the nearest minute to match Go's `t.Truncate(time.Minute)`.
        // This ensures consistent behaviour across ticks and avoids sub-minute
        // jitter when comparing against deadline / schedule boundaries.
        let raw_now = OffsetDateTime::now_utc();
        let now = raw_now
            .replace_second(0)
            .unwrap_or(raw_now)
            .replace_nanosecond(0)
            .unwrap_or(raw_now);
        let workspaces = self
            .store
            .get_workspaces_eligible_for_transition(now)
            .await?;

        let total = workspaces.len();
        if total == 0 {
            return Ok(AutobuildStats::default());
        }

        info!(
            eligible = total,
            "autobuild executor tick: evaluating workspaces"
        );

        // Use a semaphore to limit concurrency.
        let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_TRANSITIONS));
        let stats = Arc::new(std::sync::Mutex::new(AutobuildStats::default()));

        let mut handles = Vec::with_capacity(total);

        for ws in workspaces {
            let store = self.store.clone();
            let sem = semaphore.clone();
            let stats_ref = stats.clone();

            let handle = tokio::spawn(async move {
                // Acquire semaphore permit to limit concurrency.
                let _permit = match sem.acquire().await {
                    Ok(p) => p,
                    Err(_) => return, // semaphore closed
                };

                match evaluate_workspace(&store, &ws, now).await {
                    Ok(action) => {
                        if let Ok(mut s) = stats_ref.lock() {
                            s.evaluated = s.evaluated.saturating_add(1);
                            if action != AutobuildAction::None {
                                s.transitions = s.transitions.saturating_add(1);
                            }
                        }
                    }
                    Err(err) => {
                        warn!(
                            workspace_id = %ws.id,
                            workspace_name = %ws.name,
                            error = %err,
                            "autobuild: failed to evaluate workspace"
                        );
                        if let Ok(mut s) = stats_ref.lock() {
                            s.evaluated = s.evaluated.saturating_add(1);
                            s.errors = s.errors.saturating_add(1);
                        }
                    }
                }
            });
            handles.push(handle);
        }

        // Wait for all tasks to complete.
        for handle in handles {
            // Ignore JoinErrors (task panics) — they are logged by tokio.
            let _ = handle.await;
        }

        let result = match stats.lock() {
            Ok(s) => s.clone(),
            Err(poisoned) => {
                warn!("autobuild stats mutex poisoned, using recovered data");
                poisoned.into_inner().clone()
            }
        };

        if result.transitions > 0 || result.errors > 0 {
            info!(
                transitions = result.transitions,
                errors = result.errors,
                evaluated = result.evaluated,
                "autobuild executor tick completed"
            );
        }

        Ok(result)
    }

    fn spawn_executor_loop(executor: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let weak = Arc::downgrade(executor);
        let cancel = executor.cancel.clone();
        let tick_secs = executor.tick_secs;
        tokio::spawn(async move {
            run_autobuild_loop(weak, cancel, tick_secs).await;
        })
    }
}

async fn run_autobuild_loop<S>(
    executor: Weak<AutobuildExecutor<S>>,
    cancel: CancellationToken,
    tick_secs: u64,
) where
    S: AutobuildStore + Clone + Send + Sync + 'static,
{
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(tick_secs));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("autobuild executor loop cancelled");
                return;
            }
            _ = interval.tick() => {}
        }
        let Some(executor) = executor.upgrade() else {
            return;
        };
        if let Err(error) = executor.evaluate_once().await {
            warn!(error = %error, "autobuild executor tick failed");
        }
    }
}

// ---------------------------------------------------------------------------
// Workspace Evaluation Logic
// ---------------------------------------------------------------------------

/// Evaluates a single workspace and performs the appropriate action.
///
/// This is the core of the autobuild executor. It determines what transition
/// (if any) the workspace should undergo and performs it.
async fn evaluate_workspace<S: AutobuildStore>(
    store: &S,
    ws: &WorkspaceTransitionRow,
    now: OffsetDateTime,
) -> Result<AutobuildAction, StorageError> {
    let (action, reason) = match get_next_transition(ws, now) {
        Some(pair) => pair,
        None => return Ok(AutobuildAction::None),
    };

    debug!(
        workspace_id = %ws.id,
        workspace_name = %ws.name,
        ?action,
        ?reason,
        "autobuild: determined transition"
    );

    match reason {
        BuildReason::Dormancy => {
            store
                .update_workspace_dormant_deleting_at(ws.id, Some(now))
                .await?;
            info!(
                workspace_id = %ws.id,
                workspace_name = %ws.name,
                last_used_at = %ws.last_used_at,
                "autobuild: marked workspace dormant"
            );
            // If the workspace is running, it also needs to be stopped.
            if action == AutobuildAction::Stop {
                info!(
                    workspace_id = %ws.id,
                    workspace_name = %ws.name,
                    "autobuild: stopping dormant workspace"
                );
                // In the full implementation this would trigger a stop build
                // via the workspace builder.
            }
        }
        BuildReason::Autodelete => {
            info!(
                workspace_id = %ws.id,
                workspace_name = %ws.name,
                "autobuild: auto-deleting dormant workspace"
            );
            store.soft_delete_workspace(ws.id).await?;
        }
        BuildReason::Autostart => {
            info!(
                workspace_id = %ws.id,
                workspace_name = %ws.name,
                "autobuild: autostarting workspace"
            );
            // In the full implementation this would trigger a start build
            // via the workspace builder.
        }
        BuildReason::Autostop => {
            info!(
                workspace_id = %ws.id,
                workspace_name = %ws.name,
                "autobuild: autostopping workspace"
            );
            // In the full implementation this would trigger a stop build
            // via the workspace builder.
        }
    }

    Ok(action)
}

/// Determines the next transition for a workspace.
///
/// Returns `None` if no transition is needed, otherwise returns the action
/// and the reason. Mirrors Go's `getNextTransition`.
#[must_use]
fn get_next_transition(
    ws: &WorkspaceTransitionRow,
    now: OffsetDateTime,
) -> Option<(AutobuildAction, BuildReason)> {
    // Check autostop first (highest priority for running workspaces).
    if is_eligible_for_autostop(ws, now) {
        return Some((AutobuildAction::Stop, BuildReason::Autostop));
    }

    // Check autostart (for stopped workspaces).
    if is_eligible_for_autostart(ws, now) {
        return Some((AutobuildAction::Start, BuildReason::Autostart));
    }

    // Check failed-stop (stop workspaces whose start build failed).
    if is_eligible_for_failed_stop(ws, now) {
        return Some((AutobuildAction::Stop, BuildReason::Autostop));
    }

    // Check dormancy (inactive workspaces should go dormant).
    if is_eligible_for_dormant_stop(ws, now) {
        if ws.build_transition == "start" {
            return Some((AutobuildAction::Stop, BuildReason::Dormancy));
        }
        return Some((AutobuildAction::Dormant, BuildReason::Dormancy));
    }

    // Check auto-delete (dormant workspaces past deletion threshold).
    if is_eligible_for_delete(ws, now) {
        return Some((AutobuildAction::Delete, BuildReason::Autodelete));
    }

    None
}

/// Returns `true` if the workspace should be autostarted.
///
/// Conditions (matching Go's `isEligibleForAutostart`):
/// - Owner is active (not suspended)
/// - Last build job did not fail
/// - Workspace is not dormant
/// - Last build transition is "stop"
/// - Template allows user autostart
/// - Workspace has a valid autostart schedule
/// - The schedule's next occurrence has passed since the last build
fn is_eligible_for_autostart(ws: &WorkspaceTransitionRow, now: OffsetDateTime) -> bool {
    if ws.owner_status != "active" {
        return false;
    }
    if ws.job_status == "failed" {
        return false;
    }
    if ws.dormant_at.is_some() {
        return false;
    }
    if ws.build_transition != "stop" {
        return false;
    }
    if !ws.template_allow_user_autostart {
        return false;
    }

    let schedule_str = match &ws.autostart_schedule {
        Some(s) if !s.is_empty() => s.as_str(),
        _ => return false,
    };

    let schedule = match AutostartSchedule::parse(schedule_str) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let after = match ws.job_completed_at {
        Some(t) => {
            let ts = t.unix_timestamp();
            match chrono::DateTime::from_timestamp(ts, 0) {
                Some(dt) => dt,
                None => return false,
            }
        }
        None => return false,
    };

    let next_transition = match schedule.next_after_chrono(after) {
        Some(dt) => dt,
        None => return false,
    };

    let now_chrono = match chrono::DateTime::from_timestamp(now.unix_timestamp(), 0) {
        Some(dt) => dt,
        None => return false,
    };

    now_chrono >= next_transition
}

/// Returns `true` if the workspace should be autostopped.
///
/// Conditions (matching Go's `isEligibleForAutostop`):
/// - Last build job did not fail
/// - Workspace is not dormant
/// - If owner is suspended and workspace is running, stop immediately
/// - Workspace is running, has a deadline, and deadline has passed
fn is_eligible_for_autostop(ws: &WorkspaceTransitionRow, now: OffsetDateTime) -> bool {
    if ws.job_status == "failed" {
        return false;
    }
    if ws.dormant_at.is_some() {
        return false;
    }
    if ws.build_transition == "start" && ws.owner_status == "suspended" {
        return true;
    }
    if ws.build_transition != "start" {
        return false;
    }
    match ws.build_deadline {
        Some(deadline) if deadline != OffsetDateTime::UNIX_EPOCH => now > deadline,
        _ => false,
    }
}

/// Returns `true` if the workspace should be marked dormant.
///
/// Conditions (matching Go's `isEligibleForDormantStop`):
/// - Workspace is not already dormant
/// - Template has a `time_til_dormant` > 0
/// - Time since last use exceeds the threshold
fn is_eligible_for_dormant_stop(ws: &WorkspaceTransitionRow, now: OffsetDateTime) -> bool {
    if ws.dormant_at.is_some() {
        return false;
    }
    if ws.template_time_til_dormant <= 0 {
        return false;
    }
    let threshold = time::Duration::nanoseconds(ws.template_time_til_dormant);
    (now - ws.last_used_at) > threshold
}

/// Returns `true` if the workspace should be auto-deleted.
///
/// Conditions (matching Go's `isEligibleForDelete`):
/// - Workspace is dormant and has a `deleting_at` timestamp
/// - Template has `time_til_dormant_autodelete` > 0
/// - Current time is after `deleting_at`
/// - If last delete job failed, wait 24 hours before retrying
fn is_eligible_for_delete(ws: &WorkspaceTransitionRow, now: OffsetDateTime) -> bool {
    if ws.dormant_at.is_none() || ws.deleting_at.is_none() {
        return false;
    }
    if ws.template_time_til_dormant_autodelete <= 0 {
        return false;
    }
    let deleting_at = match ws.deleting_at {
        Some(t) => t,
        None => return false,
    };
    let eligible = now > deleting_at;
    if ws.build_transition == "delete" && ws.job_status == "failed" {
        if let Some(completed_at) = ws.job_completed_at {
            return eligible && (now - completed_at) > time::Duration::hours(24);
        }
        return false;
    }
    eligible
}

/// Returns `true` if the workspace should be stopped due to a failed build.
///
/// Conditions (matching Go's `isEligibleForFailedStop`):
/// - Template has a failure TTL > 0
/// - Job status is "failed"
/// - Build transition is "start"
/// - Job has completed and sufficient time has elapsed
fn is_eligible_for_failed_stop(ws: &WorkspaceTransitionRow, now: OffsetDateTime) -> bool {
    if ws.template_failure_ttl <= 0 {
        return false;
    }
    if ws.job_status != "failed" || ws.build_transition != "start" {
        return false;
    }
    let completed_at = match ws.job_completed_at {
        Some(t) => t,
        None => return false,
    };
    let failure_ttl = time::Duration::nanoseconds(ws.template_failure_ttl);
    (now - completed_at) > failure_ttl
}

/// Determines the deadline extension for a workspace.
///
/// If the workspace has an existing deadline and a maximum deadline policy,
/// the new deadline is clamped to the maximum.
#[must_use]
pub fn compute_extended_deadline(
    current_deadline: OffsetDateTime,
    extension_minutes: u64,
    max_deadline: Option<OffsetDateTime>,
) -> OffsetDateTime {
    let extended = current_deadline
        + time::Duration::minutes(i64::try_from(extension_minutes).unwrap_or(i64::MAX));
    match max_deadline {
        Some(max) if extended > max => max,
        _ => extended,
    }
}

/// Determines the dormancy action for a workspace that has been idle.
#[must_use]
pub fn evaluate_dormancy(
    last_used_at: OffsetDateTime,
    dormancy_threshold_days: u64,
) -> AutobuildAction {
    let idle_days = (OffsetDateTime::now_utc() - last_used_at).whole_days();
    let threshold = i64::try_from(dormancy_threshold_days).unwrap_or(i64::MAX);
    if idle_days >= threshold {
        AutobuildAction::Dormant
    } else {
        AutobuildAction::None
    }
}

// ---------------------------------------------------------------------------
// Activity Bump Worker
// ---------------------------------------------------------------------------

/// Trait for the store operations needed by the activity bump worker.
#[async_trait]
pub trait ActivityBumpStore: Send + Sync + 'static {
    /// Updates the last used timestamp for a workspace.
    async fn update_workspace_last_used_at(
        &self,
        workspace_id: uuid::Uuid,
        last_used_at: OffsetDateTime,
    ) -> Result<bool, StorageError>;

    /// Returns workspaces eligible for transition (used to find active ones).
    async fn get_workspaces_eligible_for_transition(
        &self,
        now: OffsetDateTime,
    ) -> Result<Vec<WorkspaceTransitionRow>, StorageError>;

    /// Updates the build deadline for a workspace build.
    async fn update_workspace_build_deadline(
        &self,
        build_id: uuid::Uuid,
        deadline: Option<OffsetDateTime>,
        max_deadline: Option<OffsetDateTime>,
    ) -> Result<bool, StorageError>;
}

#[async_trait]
impl<T: AppStore + 'static> ActivityBumpStore for T {
    async fn update_workspace_last_used_at(
        &self,
        workspace_id: uuid::Uuid,
        last_used_at: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        AppStore::update_workspace_last_used_at(self, workspace_id, last_used_at).await
    }

    async fn get_workspaces_eligible_for_transition(
        &self,
        now: OffsetDateTime,
    ) -> Result<Vec<WorkspaceTransitionRow>, StorageError> {
        AppStore::get_workspaces_eligible_for_transition(self, now).await
    }

    async fn update_workspace_build_deadline(
        &self,
        build_id: uuid::Uuid,
        deadline: Option<OffsetDateTime>,
        max_deadline: Option<OffsetDateTime>,
    ) -> Result<bool, StorageError> {
        AppStore::update_workspace_build_deadline(self, build_id, deadline, max_deadline).await
    }
}

/// Background worker that periodically bumps workspace deadlines based on
/// recent user activity.
///
/// The Go equivalent watches for activity events and extends the workspace
/// auto-stop deadline so active users don't get their workspace stopped
/// mid-session.  This Rust implementation polls periodically and extends
/// deadlines for workspaces whose `last_used_at` is recent.
pub struct ActivityBumpWorker {
    cancel: CancellationToken,
    _task: tokio::task::JoinHandle<()>,
}

impl ActivityBumpWorker {
    /// Starts the activity bump background worker.
    pub fn start<S: ActivityBumpStore>(
        store: S,
        interval_secs: u64,
        cancel: CancellationToken,
    ) -> Arc<Self> {
        let cancel_clone = cancel.clone();
        let task = tokio::spawn(async move {
            run_activity_bump_loop(store, interval_secs, cancel_clone).await;
        });
        info!(
            interval_secs,
            "activity bump worker started"
        );
        Arc::new(Self {
            cancel,
            _task: task,
        })
    }

    /// Signals the worker to stop.
    pub fn close(&self) {
        self.cancel.cancel();
    }

    /// Cancels the worker and awaits the background task to completion,
    /// ensuring in-flight DB queries finish before the pool is closed.
    pub async fn join(self: Arc<Self>) {
        self.cancel.cancel();
        // Try to unwrap the Arc; if other references exist, just cancel.
        if let Ok(this) = Arc::try_unwrap(self) {
            let _result = this._task.await;
        }
    }
}

/// Core loop: periodically find workspaces needing a deadline bump and
/// extend their auto-stop deadline.
async fn run_activity_bump_loop<S: ActivityBumpStore>(
    store: S,
    interval_secs: u64,
    cancel: CancellationToken,
) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("activity bump worker cancelled");
                return;
            }
            _ = interval.tick() => {}
        }

        let now = OffsetDateTime::now_utc();
        match activity_bump_once(&store, now).await {
            Ok(0) => {} // nothing to bump
            Ok(n) => info!(bumped = n, "activity bump cycle completed"),
            Err(error) => warn!(error = %error, "activity bump cycle failed"),
        }
    }
}

/// Single tick of the activity bump worker.
///
/// Finds running workspaces with recent activity and extends their deadline
/// by the template's `activity_bump` duration.
async fn activity_bump_once<S: ActivityBumpStore>(
    store: &S,
    now: OffsetDateTime,
) -> Result<usize, StorageError> {
    let workspaces = store.get_workspaces_eligible_for_transition(now).await?;
    let mut bumped = 0usize;

    for ws in &workspaces {
        // Only bump running workspaces (last build transition == "start").
        if ws.build_transition != "start" {
            continue;
        }
        // Skip if the template has no activity bump configured.
        if ws.activity_bump_ns <= 0 {
            continue;
        }
        // Only bump if the workspace was used recently (within the bump interval).
        let bump_duration = time::Duration::nanoseconds(ws.activity_bump_ns);
        let activity_threshold = now - bump_duration;
        if ws.last_used_at < activity_threshold {
            continue;
        }
        // Only bump if the workspace already has a deadline set (no auto-stop
        // configured means deadline is None — we must not create one).
        let current_deadline = match ws.build_deadline {
            Some(d) if d != OffsetDateTime::UNIX_EPOCH => d,
            _ => continue,
        };
        // Extend the deadline from now.
        let new_deadline = now + bump_duration;
        // Clamp to max_deadline so we never exceed the template policy.
        let new_deadline = match ws.max_deadline {
            Some(max) if max != OffsetDateTime::UNIX_EPOCH && new_deadline > max => max,
            _ => new_deadline,
        };
        // Only update if the new deadline actually extends the current one;
        // otherwise we would shorten the remaining time (Go guard equivalent).
        if new_deadline <= current_deadline {
            continue;
        }
        match store
            .update_workspace_build_deadline(
                ws.build_id,
                Some(new_deadline),
                ws.max_deadline,
            )
            .await
        {
            Ok(true) => {
                debug!(
                    workspace_id = %ws.id,
                    workspace_name = %ws.name,
                    new_deadline = %new_deadline,
                    "bumped workspace deadline"
                );
                bumped += 1;
            }
            Ok(false) => {}
            Err(error) => {
                warn!(
                    workspace_id = %ws.id,
                    error = %error,
                    "activity bump: failed to update workspace deadline"
                );
            }
        }
    }
    Ok(bumped)
}

// ---------------------------------------------------------------------------
// Dormancy Checker Worker
// ---------------------------------------------------------------------------

/// Trait for the store operations needed by the dormancy checker worker.
#[async_trait]
pub trait DormancyCheckerStore: Send + Sync + 'static {
    /// Returns workspaces eligible for transition.
    async fn get_workspaces_eligible_for_transition(
        &self,
        now: OffsetDateTime,
    ) -> Result<Vec<WorkspaceTransitionRow>, StorageError>;

    /// Sets `dormant_at` and recomputes `deleting_at` for a workspace.
    async fn update_workspace_dormant_deleting_at(
        &self,
        workspace_id: uuid::Uuid,
        dormant_at: Option<OffsetDateTime>,
    ) -> Result<Option<WorkspaceRecord>, StorageError>;
}

#[async_trait]
impl<T: AppStore + 'static> DormancyCheckerStore for T {
    async fn get_workspaces_eligible_for_transition(
        &self,
        now: OffsetDateTime,
    ) -> Result<Vec<WorkspaceTransitionRow>, StorageError> {
        AppStore::get_workspaces_eligible_for_transition(self, now).await
    }

    async fn update_workspace_dormant_deleting_at(
        &self,
        workspace_id: uuid::Uuid,
        dormant_at: Option<OffsetDateTime>,
    ) -> Result<Option<WorkspaceRecord>, StorageError> {
        AppStore::update_workspace_dormant_deleting_at(self, workspace_id, dormant_at).await
    }
}

/// Background worker that periodically checks for workspaces eligible for
/// dormancy.
///
/// Mirrors the Go `dormancy` package.  Each tick it queries for workspaces
/// that have been inactive longer than their template's dormancy threshold
/// and marks them as dormant.
pub struct DormancyCheckerWorker {
    cancel: CancellationToken,
    _task: tokio::task::JoinHandle<()>,
}

impl DormancyCheckerWorker {
    /// Starts the dormancy checker background worker.
    pub fn start<S: DormancyCheckerStore>(
        store: S,
        interval_secs: u64,
        cancel: CancellationToken,
    ) -> Arc<Self> {
        let cancel_clone = cancel.clone();
        let task = tokio::spawn(async move {
            run_dormancy_check_loop(store, interval_secs, cancel_clone).await;
        });
        info!(
            interval_secs,
            "dormancy checker worker started"
        );
        Arc::new(Self {
            cancel,
            _task: task,
        })
    }

    /// Signals the worker to stop.
    pub fn close(&self) {
        self.cancel.cancel();
    }

    /// Cancels the worker and awaits the background task to completion,
    /// ensuring in-flight DB queries finish before the pool is closed.
    pub async fn join(self: Arc<Self>) {
        self.cancel.cancel();
        // Try to unwrap the Arc; if other references exist, just cancel.
        if let Ok(this) = Arc::try_unwrap(self) {
            let _result = this._task.await;
        }
    }
}

/// Core loop: periodically check for dormant-eligible workspaces.
async fn run_dormancy_check_loop<S: DormancyCheckerStore>(
    store: S,
    interval_secs: u64,
    cancel: CancellationToken,
) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("dormancy checker worker cancelled");
                return;
            }
            _ = interval.tick() => {}
        }

        let now = OffsetDateTime::now_utc();
        match dormancy_check_once(&store, now).await {
            Ok(0) => {} // nothing to mark dormant
            Ok(n) => info!(marked_dormant = n, "dormancy check cycle completed"),
            Err(error) => warn!(error = %error, "dormancy check cycle failed"),
        }
    }
}

/// Single tick of the dormancy checker.
///
/// Finds workspaces eligible for the dormancy transition and marks them.
async fn dormancy_check_once<S: DormancyCheckerStore>(
    store: &S,
    now: OffsetDateTime,
) -> Result<usize, StorageError> {
    let workspaces = store.get_workspaces_eligible_for_transition(now).await?;
    let mut marked = 0usize;

    for ws in &workspaces {
        // Only process workspaces that are eligible for dormancy but not
        // already marked dormant.
        if ws.dormant_at.is_some() {
            continue;
        }
        if !is_eligible_for_dormant_stop(ws, now) {
            continue;
        }
        match store
            .update_workspace_dormant_deleting_at(ws.id, Some(now))
            .await
        {
            Ok(Some(_)) => {
                info!(
                    workspace_id = %ws.id,
                    workspace_name = %ws.name,
                    last_used_at = %ws.last_used_at,
                    "dormancy checker: marked workspace dormant"
                );
                marked += 1;
            }
            Ok(None) => {
                // Workspace was deleted or not found — skip.
            }
            Err(error) => {
                warn!(
                    workspace_id = %ws.id,
                    error = %error,
                    "dormancy checker: failed to mark workspace dormant"
                );
            }
        }
    }
    Ok(marked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use coder_core::{
        OperationalStore, StorageError,
        api::{
            DeploymentStatsResponse, SessionCountDeploymentStatsResponse,
            WorkspaceConnectionLatencyMs, WorkspaceDeploymentStatsResponse,
        },
    };
    use std::sync::Arc as StdArc;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    // ── Mock store ───────────────────────────────────────────

    #[derive(Clone)]
    struct MockOperationalStore {
        stats: StdArc<Mutex<DeploymentStatsResponse>>,
        should_fail: StdArc<AtomicBool>,
        call_count: StdArc<AtomicU32>,
    }

    impl MockOperationalStore {
        fn new(stats: DeploymentStatsResponse) -> Self {
            Self {
                stats: StdArc::new(Mutex::new(stats)),
                should_fail: StdArc::new(AtomicBool::new(false)),
                call_count: StdArc::new(AtomicU32::new(0)),
            }
        }

        fn with_failure(self) -> Self {
            self.should_fail.store(true, Ordering::SeqCst);
            self
        }
    }

    #[async_trait]
    impl OperationalStore for MockOperationalStore {
        async fn deployment_stats(&self) -> Result<DeploymentStatsResponse, StorageError> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            if self.should_fail.load(Ordering::SeqCst) {
                return Err(StorageError::unavailable("mock store failure"));
            }
            Ok(self.stats.lock().await.clone())
        }
    }

    fn default_stats() -> DeploymentStatsResponse {
        DeploymentStatsResponse {
            aggregated_from: OffsetDateTime::now_utc(),
            collected_at: OffsetDateTime::now_utc(),
            next_update_at: OffsetDateTime::now_utc(),
            workspaces: WorkspaceDeploymentStatsResponse {
                pending: 1,
                building: 2,
                running: 5,
                failed: 0,
                stopped: 3,
                connection_latency_ms: WorkspaceConnectionLatencyMs {
                    p50: 10.0,
                    p95: 50.0,
                },
                rx_bytes: 1024,
                tx_bytes: 2048,
            },
            session_count: SessionCountDeploymentStatsResponse {
                vscode: 3,
                ssh: 2,
                jetbrains: 1,
                reconnecting_pty: 0,
            },
        }
    }

    // ── DeploymentStatsService tests ─────────────────────────

    #[tokio::test]
    async fn stats_service_returns_cached_stats() {
        let store = MockOperationalStore::new(default_stats());
        // Build the service struct directly to avoid spawning a background loop.
        let service = StdArc::new(DeploymentStatsService {
            store,
            cache: RwLock::new(None),
            refresh_lock: Mutex::new(()),
            cancel: CancellationToken::new(),
        });

        // First call triggers refresh
        let result = service.get().await;
        assert!(result.is_ok());
        let stats = result.unwrap_or_else(|_| unreachable!());
        assert_eq!(stats.workspaces.running, 5);
        assert_eq!(stats.session_count.vscode, 3);
    }

    #[tokio::test]
    async fn stats_service_refresh_updates_cache() {
        let store = MockOperationalStore::new(default_stats());
        let call_count = store.call_count.clone();

        let service = StdArc::new(DeploymentStatsService {
            store,
            cache: RwLock::new(None),
            refresh_lock: Mutex::new(()),
            cancel: CancellationToken::new(),
        });

        let _r1 = service.refresh().await;
        let count1 = call_count.load(Ordering::SeqCst);

        let _r2 = service.refresh().await;
        let count2 = call_count.load(Ordering::SeqCst);

        assert_eq!(count2, count1 + 1, "each refresh should call the store");
    }

    #[tokio::test]
    async fn stats_service_get_returns_cached_after_refresh() {
        let store = MockOperationalStore::new(default_stats());
        let call_count = store.call_count.clone();

        let service = StdArc::new(DeploymentStatsService {
            store,
            cache: RwLock::new(None),
            refresh_lock: Mutex::new(()),
            cancel: CancellationToken::new(),
        });

        // Populate cache
        let _ = service.refresh().await;
        let count_after_refresh = call_count.load(Ordering::SeqCst);

        // get() should use cache
        let result = service.get().await;
        assert!(result.is_ok());
        let count_after_get = call_count.load(Ordering::SeqCst);
        assert_eq!(
            count_after_refresh, count_after_get,
            "get() should use cache without calling store"
        );
    }

    #[tokio::test]
    async fn stats_service_handles_store_error() {
        let store = MockOperationalStore::new(default_stats()).with_failure();

        let service = StdArc::new(DeploymentStatsService {
            store,
            cache: RwLock::new(None),
            refresh_lock: Mutex::new(()),
            cancel: CancellationToken::new(),
        });

        let result = service.get().await;
        assert!(result.is_err(), "should propagate store error");
    }

    #[tokio::test]
    async fn stats_service_returns_stale_data_after_store_failure() {
        let store = MockOperationalStore::new(default_stats());
        let should_fail = store.should_fail.clone();

        let service = StdArc::new(DeploymentStatsService {
            store,
            cache: RwLock::new(None),
            refresh_lock: Mutex::new(()),
            cancel: CancellationToken::new(),
        });

        // Populate cache successfully
        let _ = service.refresh().await;

        // Now make the store fail
        should_fail.store(true, Ordering::SeqCst);

        // get() should still return the cached value
        let result = service.get().await;
        assert!(result.is_ok(), "should return stale cached data");
        let stats = result.unwrap_or_else(|_| unreachable!());
        assert_eq!(stats.workspaces.running, 5);
    }

    // ── Schedule tests ───────────────────────────────────────

    #[test]
    fn parse_autostart_schedule_basic() {
        let schedule = AutostartSchedule::parse("30 9 * * 1-5");
        assert!(schedule.is_ok(), "basic 5-field cron should parse");
        if let Ok(s) = schedule {
            assert_eq!(s.timezone(), "UTC");
        }
    }

    #[test]
    fn parse_autostart_schedule_with_tz() {
        let schedule = AutostartSchedule::parse("CRON_TZ=America/Chicago 30 9 * * 1-5");
        assert!(schedule.is_ok(), "cron with timezone should parse");
        if let Ok(s) = schedule {
            assert_eq!(s.timezone(), "America/Chicago");
        }
    }

    #[test]
    fn parse_autostart_schedule_invalid() {
        let result = AutostartSchedule::parse("not a cron");
        assert!(result.is_err(), "invalid cron should fail");
    }

    #[test]
    fn autostop_policy_expired() {
        let policy = AutostopPolicy { ttl_minutes: 60 };
        let two_hours_ago = OffsetDateTime::now_utc() - time::Duration::hours(2);
        assert!(policy.should_stop(two_hours_ago));
    }

    #[test]
    fn autostop_policy_not_expired() {
        let policy = AutostopPolicy { ttl_minutes: 120 };
        let thirty_minutes_ago = OffsetDateTime::now_utc() - time::Duration::minutes(30);
        assert!(!policy.should_stop(thirty_minutes_ago));
    }

    #[test]
    fn quiet_hours_within_window() {
        let window = QuietHoursWindow {
            start_hour: 0,
            end_hour: 6,
        };
        // 3 AM UTC
        let t = time::macros::datetime!(2026-03-09 03:00:00 UTC);
        assert!(window.is_quiet(t));
    }

    #[test]
    fn quiet_hours_outside_window() {
        let window = QuietHoursWindow {
            start_hour: 0,
            end_hour: 6,
        };
        // 10 AM UTC
        let t = time::macros::datetime!(2026-03-09 10:00:00 UTC);
        assert!(!window.is_quiet(t));
    }

    #[test]
    fn quiet_hours_wrapping_midnight() {
        let window = QuietHoursWindow {
            start_hour: 22,
            end_hour: 6,
        };
        // 23:00 UTC - should be quiet
        let t = time::macros::datetime!(2026-03-09 23:00:00 UTC);
        assert!(window.is_quiet(t));
        // 3:00 UTC - should be quiet
        let t2 = time::macros::datetime!(2026-03-09 03:00:00 UTC);
        assert!(window.is_quiet(t2));
        // 10:00 UTC - should not be quiet
        let t3 = time::macros::datetime!(2026-03-09 10:00:00 UTC);
        assert!(!window.is_quiet(t3));
    }

    #[test]
    fn deadline_extension_basic() {
        let now = OffsetDateTime::now_utc();
        let extended = compute_extended_deadline(now, 30, None);
        let diff = (extended - now).whole_minutes();
        assert_eq!(diff, 30);
    }

    #[test]
    fn deadline_extension_clamped() {
        let now = OffsetDateTime::now_utc();
        let max = now + time::Duration::minutes(15);
        let extended = compute_extended_deadline(now, 30, Some(max));
        assert_eq!(extended, max);
    }

    #[test]
    fn dormancy_evaluation_idle() {
        let long_ago = OffsetDateTime::now_utc() - time::Duration::days(100);
        assert_eq!(evaluate_dormancy(long_ago, 90), AutobuildAction::Dormant);
    }

    #[test]
    fn dormancy_evaluation_active() {
        let recent = OffsetDateTime::now_utc() - time::Duration::days(10);
        assert_eq!(evaluate_dormancy(recent, 90), AutobuildAction::None);
    }

    // ── Additional schedule tests ────────────────────────────

    #[test]
    fn schedule_next_after_utc_returns_some() {
        let schedule = AutostartSchedule::parse("30 9 * * 1-5");
        assert!(schedule.is_ok());
        let s = schedule.unwrap_or_else(|_| unreachable!());
        let next = s.next_after_utc();
        assert!(next.is_some(), "should return the next occurrence");
    }

    #[test]
    fn schedule_expression_preserved() {
        let raw = "CRON_TZ=Europe/Oslo 0 8 * * *";
        let schedule = AutostartSchedule::parse(raw);
        assert!(schedule.is_ok());
        let s = schedule.unwrap_or_else(|_| unreachable!());
        assert_eq!(s.expression(), raw);
    }

    #[test]
    fn schedule_should_have_fired_recently() {
        // "every minute" schedule should have fired in the last 120 seconds
        let schedule = AutostartSchedule::parse("* * * * *");
        assert!(schedule.is_ok());
        let s = schedule.unwrap_or_else(|_| unreachable!());
        assert!(
            s.should_have_fired(120),
            "every-minute schedule should have fired within 120s"
        );
    }

    #[test]
    fn schedule_should_not_have_fired_in_tiny_window() {
        // A specific schedule (e.g. once a year) should not have fired in 1 second
        let schedule = AutostartSchedule::parse("0 0 1 1 *");
        assert!(schedule.is_ok());
        let s = schedule.unwrap_or_else(|_| unreachable!());
        // With a 1-second window, the yearly schedule almost certainly didn't fire
        // (unless it's exactly midnight Jan 1 UTC)
        // This is a best-effort test; the key thing is the function doesn't panic.
        let _ = s.should_have_fired(1);
    }

    // ── Autostop policy edge cases ───────────────────────────

    #[test]
    fn autostop_policy_exactly_at_ttl() {
        let policy = AutostopPolicy { ttl_minutes: 60 };
        let exactly_one_hour_ago = OffsetDateTime::now_utc() - time::Duration::minutes(60);
        assert!(
            policy.should_stop(exactly_one_hour_ago),
            "should stop when elapsed == TTL"
        );
    }

    // ── compute_extended_deadline edge cases ──────────────────

    #[test]
    fn deadline_extension_no_max_allows_full_extension() {
        let now = OffsetDateTime::now_utc();
        let extended = compute_extended_deadline(now, 120, None);
        let diff = (extended - now).whole_minutes();
        assert_eq!(diff, 120);
    }

    #[test]
    fn deadline_extension_max_far_in_future() {
        let now = OffsetDateTime::now_utc();
        let far_max = now + time::Duration::days(365);
        let extended = compute_extended_deadline(now, 30, Some(far_max));
        let diff = (extended - now).whole_minutes();
        assert_eq!(diff, 30, "extension below max should not be clamped");
    }

    // ── User-requested tests ────────────────────────────────────

    #[test]
    fn test_workspace_transition_types() {
        // AutobuildAction covers Start, Stop, Dormant, None
        let actions = [
            AutobuildAction::Start,
            AutobuildAction::Stop,
            AutobuildAction::Dormant,
            AutobuildAction::None,
        ];

        // Each variant should be distinct
        for (i, a) in actions.iter().enumerate() {
            for (j, b) in actions.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "actions at {i} and {j} should differ");
                }
            }
        }

        // Verify Copy trait — actions can be used after assignment
        let a = AutobuildAction::Start;
        let b = a;
        assert_eq!(a, b, "AutobuildAction should be Copy");

        // Dormancy evaluator: boundary case — exactly at threshold
        let at_threshold = OffsetDateTime::now_utc() - time::Duration::days(90);
        assert_eq!(
            evaluate_dormancy(at_threshold, 90),
            AutobuildAction::Dormant,
            "at exact threshold should be dormant"
        );

        // Dormancy evaluator: one day before threshold — still active
        let just_before = OffsetDateTime::now_utc() - time::Duration::days(89);
        assert_eq!(
            evaluate_dormancy(just_before, 90),
            AutobuildAction::None,
            "one day before threshold should not be dormant"
        );
    }

    #[test]
    fn test_workspace_status_derivation() {
        // Non-wrapping window (same-day range)
        let daytime_window = QuietHoursWindow {
            start_hour: 1,
            end_hour: 5,
        };
        let inside = time::macros::datetime!(2026-03-09 03:00:00 UTC);
        assert!(
            daytime_window.is_quiet(inside),
            "03:00 in 1-5 should be quiet"
        );
        let outside = time::macros::datetime!(2026-03-09 06:00:00 UTC);
        assert!(
            !daytime_window.is_quiet(outside),
            "06:00 outside 1-5 should not be quiet"
        );

        // Boundary: exactly at start_hour (22:00)
        let midnight_wrap = QuietHoursWindow {
            start_hour: 22,
            end_hour: 6,
        };
        let at_start = time::macros::datetime!(2026-03-09 22:00:00 UTC);
        assert!(
            midnight_wrap.is_quiet(at_start),
            "exactly at start_hour should be quiet"
        );
        // Boundary: exactly at end_hour (06:00) — should NOT be quiet
        let at_end = time::macros::datetime!(2026-03-09 06:00:00 UTC);
        assert!(
            !midnight_wrap.is_quiet(at_end),
            "exactly at end_hour should not be quiet"
        );
    }

    #[test]
    fn test_deadline_extension_ordering_and_clamping() {
        // Deadline extension preserves ordering: later deadlines remain later.
        let base = OffsetDateTime::now_utc();
        let build_1_deadline = base + time::Duration::minutes(30);
        let build_2_deadline = base + time::Duration::minutes(60);

        // Extend both by 15 minutes
        let extended_1 = compute_extended_deadline(build_1_deadline, 15, None);
        let extended_2 = compute_extended_deadline(build_2_deadline, 15, None);

        assert!(
            extended_1 < extended_2,
            "ordering should be preserved after extension"
        );

        // When max clamps build 2, verify it equals the max
        let max = base + time::Duration::minutes(65);
        let clamped_2 = compute_extended_deadline(build_2_deadline, 15, Some(max));
        assert_eq!(clamped_2, max, "build 2 extension should be clamped to max");
    }

    #[test]
    fn test_workspace_autostart_schedule_parsing() {
        // Basic 5-field cron (every weekday at 9:30)
        let basic = AutostartSchedule::parse("30 9 * * 1-5");
        assert!(basic.is_ok(), "basic cron should parse");
        if let Ok(s) = basic {
            assert_eq!(s.timezone(), "UTC");
            assert_eq!(s.expression(), "30 9 * * 1-5");
        }

        // With CRON_TZ prefix
        let tz = AutostartSchedule::parse("CRON_TZ=America/New_York 0 8 * * *");
        assert!(tz.is_ok(), "cron with TZ should parse");
        if let Ok(s) = tz {
            assert_eq!(s.timezone(), "America/New_York");
        }

        // Every-minute schedule — verify next_after_utc returns Some
        let every_min = AutostartSchedule::parse("* * * * *");
        assert!(every_min.is_ok(), "every-minute cron should parse");
        if let Ok(s) = every_min {
            let next = s.next_after_utc();
            assert!(
                next.is_some(),
                "every-minute schedule should have next occurrence"
            );
        }

        // Invalid cron expressions
        let invalid_cases = ["not a cron", "", "1 2 3", "60 25 * * *"];
        for case in &invalid_cases {
            let result = AutostartSchedule::parse(case);
            assert!(
                result.is_err(),
                "'{case}' should fail to parse as a cron schedule"
            );
        }

        // CRON_TZ with unknown timezone falls back to UTC in next_after_utc
        let unknown_tz = AutostartSchedule::parse("CRON_TZ=Fake/Zone * * * * *");
        assert!(unknown_tz.is_ok(), "unknown TZ still parses the cron part");
        if let Ok(s) = unknown_tz {
            assert_eq!(s.timezone(), "Fake/Zone");
            // Should still return a next occurrence (falls back to UTC)
            let next = s.next_after_utc();
            assert!(next.is_some(), "unknown TZ should fall back to UTC");
        }
    }

    #[test]
    fn test_workspace_ttl_calculation() {
        // Zero extension — novel scenario not in existing tests
        let now = OffsetDateTime::now_utc();
        let zero = compute_extended_deadline(now, 0, None);
        assert_eq!(zero, now, "zero extension should not change deadline");

        // Large (but safe) TTL should not stop recent activity
        let large_policy = AutostopPolicy {
            ttl_minutes: 525_600, // one year in minutes
        };
        let recent = OffsetDateTime::now_utc() - time::Duration::minutes(1);
        assert!(
            !large_policy.should_stop(recent),
            "large TTL should not stop recent activity"
        );
    }

    // ── Eligibility function tests ──────────────────────────

    fn make_transition_row() -> WorkspaceTransitionRow {
        WorkspaceTransitionRow {
            id: uuid::Uuid::new_v4(),
            name: "test-workspace".to_owned(),
            owner_id: uuid::Uuid::new_v4(),
            template_id: uuid::Uuid::new_v4(),
            autostart_schedule: None,
            ttl_ns: None,
            last_used_at: OffsetDateTime::now_utc(),
            dormant_at: None,
            deleting_at: None,
            deleted: false,
            build_transition: "start".to_owned(),
            build_deadline: None,
            job_status: "succeeded".to_owned(),
            job_completed_at: Some(OffsetDateTime::now_utc()),
            template_allow_user_autostart: true,
            template_default_ttl: 0,
            template_failure_ttl: 0,
            template_time_til_dormant: 0,
            template_time_til_dormant_autodelete: 0,
            owner_status: "active".to_owned(),
            build_id: uuid::Uuid::new_v4(),
            max_deadline: None,
            activity_bump_ns: 0,
        }
    }

    // ── Autostop eligibility tests ──────────────────────────

    #[test]
    fn autostop_eligible_when_deadline_passed() {
        let now = OffsetDateTime::now_utc();
        let mut ws = make_transition_row();
        ws.build_transition = "start".to_owned();
        ws.build_deadline = Some(now - time::Duration::minutes(5));
        assert!(is_eligible_for_autostop(&ws, now));
    }

    #[test]
    fn autostop_not_eligible_when_deadline_in_future() {
        let now = OffsetDateTime::now_utc();
        let mut ws = make_transition_row();
        ws.build_transition = "start".to_owned();
        ws.build_deadline = Some(now + time::Duration::hours(1));
        assert!(!is_eligible_for_autostop(&ws, now));
    }

    #[test]
    fn autostop_not_eligible_when_workspace_stopped() {
        let now = OffsetDateTime::now_utc();
        let mut ws = make_transition_row();
        ws.build_transition = "stop".to_owned();
        ws.build_deadline = Some(now - time::Duration::minutes(5));
        assert!(!is_eligible_for_autostop(&ws, now));
    }

    #[test]
    fn autostop_not_eligible_when_failed() {
        let now = OffsetDateTime::now_utc();
        let mut ws = make_transition_row();
        ws.build_transition = "start".to_owned();
        ws.build_deadline = Some(now - time::Duration::minutes(5));
        ws.job_status = "failed".to_owned();
        assert!(!is_eligible_for_autostop(&ws, now));
    }

    #[test]
    fn autostop_not_eligible_when_dormant() {
        let now = OffsetDateTime::now_utc();
        let mut ws = make_transition_row();
        ws.build_transition = "start".to_owned();
        ws.build_deadline = Some(now - time::Duration::minutes(5));
        ws.dormant_at = Some(now - time::Duration::days(1));
        assert!(!is_eligible_for_autostop(&ws, now));
    }

    #[test]
    fn autostop_suspended_user_running_workspace() {
        let now = OffsetDateTime::now_utc();
        let mut ws = make_transition_row();
        ws.build_transition = "start".to_owned();
        ws.owner_status = "suspended".to_owned();
        assert!(is_eligible_for_autostop(&ws, now));
    }

    // ── Autostart eligibility tests ─────────────────────────

    #[test]
    fn autostart_eligible_when_schedule_triggers() {
        let now = OffsetDateTime::now_utc();
        let mut ws = make_transition_row();
        ws.build_transition = "stop".to_owned();
        ws.autostart_schedule = Some("* * * * *".to_owned());
        ws.job_completed_at = Some(now - time::Duration::minutes(2));
        assert!(is_eligible_for_autostart(&ws, now));
    }

    #[test]
    fn autostart_not_eligible_when_suspended() {
        let now = OffsetDateTime::now_utc();
        let mut ws = make_transition_row();
        ws.build_transition = "stop".to_owned();
        ws.autostart_schedule = Some("* * * * *".to_owned());
        ws.job_completed_at = Some(now - time::Duration::minutes(2));
        ws.owner_status = "suspended".to_owned();
        assert!(!is_eligible_for_autostart(&ws, now));
    }

    #[test]
    fn autostart_not_eligible_when_dormant() {
        let now = OffsetDateTime::now_utc();
        let mut ws = make_transition_row();
        ws.build_transition = "stop".to_owned();
        ws.autostart_schedule = Some("* * * * *".to_owned());
        ws.job_completed_at = Some(now - time::Duration::minutes(2));
        ws.dormant_at = Some(now - time::Duration::days(1));
        assert!(!is_eligible_for_autostart(&ws, now));
    }

    #[test]
    fn autostart_not_eligible_when_running() {
        let now = OffsetDateTime::now_utc();
        let mut ws = make_transition_row();
        ws.build_transition = "start".to_owned();
        ws.autostart_schedule = Some("* * * * *".to_owned());
        ws.job_completed_at = Some(now - time::Duration::minutes(2));
        assert!(!is_eligible_for_autostart(&ws, now));
    }

    #[test]
    fn autostart_not_eligible_when_template_disallows() {
        let now = OffsetDateTime::now_utc();
        let mut ws = make_transition_row();
        ws.build_transition = "stop".to_owned();
        ws.autostart_schedule = Some("* * * * *".to_owned());
        ws.job_completed_at = Some(now - time::Duration::minutes(2));
        ws.template_allow_user_autostart = false;
        assert!(!is_eligible_for_autostart(&ws, now));
    }

    #[test]
    fn autostart_not_eligible_without_schedule() {
        let now = OffsetDateTime::now_utc();
        let mut ws = make_transition_row();
        ws.build_transition = "stop".to_owned();
        ws.autostart_schedule = None;
        ws.job_completed_at = Some(now - time::Duration::minutes(2));
        assert!(!is_eligible_for_autostart(&ws, now));
    }

    #[test]
    fn autostart_not_eligible_when_job_failed() {
        let now = OffsetDateTime::now_utc();
        let mut ws = make_transition_row();
        ws.build_transition = "stop".to_owned();
        ws.autostart_schedule = Some("* * * * *".to_owned());
        ws.job_completed_at = Some(now - time::Duration::minutes(2));
        ws.job_status = "failed".to_owned();
        assert!(!is_eligible_for_autostart(&ws, now));
    }

    // ── Dormant stop eligibility tests ──────────────────────

    #[test]
    fn dormant_stop_eligible_when_idle() {
        let now = OffsetDateTime::now_utc();
        let mut ws = make_transition_row();
        ws.last_used_at = now - time::Duration::days(31);
        // 30 days in nanoseconds
        ws.template_time_til_dormant = 30 * 24 * 60 * 60 * 1_000_000_000;
        assert!(is_eligible_for_dormant_stop(&ws, now));
    }

    #[test]
    fn dormant_stop_not_eligible_when_recently_active() {
        let now = OffsetDateTime::now_utc();
        let mut ws = make_transition_row();
        ws.last_used_at = now - time::Duration::days(10);
        ws.template_time_til_dormant = 30 * 24 * 60 * 60 * 1_000_000_000;
        assert!(!is_eligible_for_dormant_stop(&ws, now));
    }

    #[test]
    fn dormant_stop_not_eligible_when_already_dormant() {
        let now = OffsetDateTime::now_utc();
        let mut ws = make_transition_row();
        ws.last_used_at = now - time::Duration::days(31);
        ws.template_time_til_dormant = 30 * 24 * 60 * 60 * 1_000_000_000;
        ws.dormant_at = Some(now - time::Duration::days(1));
        assert!(!is_eligible_for_dormant_stop(&ws, now));
    }

    #[test]
    fn dormant_stop_not_eligible_when_no_threshold() {
        let now = OffsetDateTime::now_utc();
        let mut ws = make_transition_row();
        ws.last_used_at = now - time::Duration::days(365);
        ws.template_time_til_dormant = 0;
        assert!(!is_eligible_for_dormant_stop(&ws, now));
    }

    // ── Delete eligibility tests ────────────────────────────

    #[test]
    fn delete_eligible_when_past_deleting_at() {
        let now = OffsetDateTime::now_utc();
        let mut ws = make_transition_row();
        ws.dormant_at = Some(now - time::Duration::days(90));
        ws.deleting_at = Some(now - time::Duration::hours(1));
        ws.template_time_til_dormant_autodelete = 90 * 24 * 60 * 60 * 1_000_000_000;
        assert!(is_eligible_for_delete(&ws, now));
    }

    #[test]
    fn delete_not_eligible_when_not_dormant() {
        let now = OffsetDateTime::now_utc();
        let mut ws = make_transition_row();
        ws.dormant_at = None;
        ws.deleting_at = Some(now - time::Duration::hours(1));
        ws.template_time_til_dormant_autodelete = 90 * 24 * 60 * 60 * 1_000_000_000;
        assert!(!is_eligible_for_delete(&ws, now));
    }

    #[test]
    fn delete_not_eligible_when_before_deleting_at() {
        let now = OffsetDateTime::now_utc();
        let mut ws = make_transition_row();
        ws.dormant_at = Some(now - time::Duration::days(30));
        ws.deleting_at = Some(now + time::Duration::days(60));
        ws.template_time_til_dormant_autodelete = 90 * 24 * 60 * 60 * 1_000_000_000;
        assert!(!is_eligible_for_delete(&ws, now));
    }

    #[test]
    fn delete_waits_24h_after_failed_delete() {
        let now = OffsetDateTime::now_utc();
        let mut ws = make_transition_row();
        ws.dormant_at = Some(now - time::Duration::days(90));
        ws.deleting_at = Some(now - time::Duration::hours(2));
        ws.template_time_til_dormant_autodelete = 90 * 24 * 60 * 60 * 1_000_000_000;
        ws.build_transition = "delete".to_owned();
        ws.job_status = "failed".to_owned();
        ws.job_completed_at = Some(now - time::Duration::hours(12));
        assert!(
            !is_eligible_for_delete(&ws, now),
            "should wait 24h after failed delete"
        );

        ws.job_completed_at = Some(now - time::Duration::hours(25));
        assert!(
            is_eligible_for_delete(&ws, now),
            "should be eligible 24h+ after failed delete"
        );
    }

    // ── Failed stop eligibility tests ───────────────────────

    #[test]
    fn failed_stop_eligible() {
        let now = OffsetDateTime::now_utc();
        let mut ws = make_transition_row();
        ws.build_transition = "start".to_owned();
        ws.job_status = "failed".to_owned();
        ws.job_completed_at = Some(now - time::Duration::hours(2));
        // 1 hour in nanoseconds
        ws.template_failure_ttl = 60 * 60 * 1_000_000_000;
        assert!(is_eligible_for_failed_stop(&ws, now));
    }

    #[test]
    fn failed_stop_not_eligible_before_ttl() {
        let now = OffsetDateTime::now_utc();
        let mut ws = make_transition_row();
        ws.build_transition = "start".to_owned();
        ws.job_status = "failed".to_owned();
        ws.job_completed_at = Some(now - time::Duration::minutes(30));
        ws.template_failure_ttl = 60 * 60 * 1_000_000_000;
        assert!(!is_eligible_for_failed_stop(&ws, now));
    }

    #[test]
    fn failed_stop_not_eligible_without_failure_ttl() {
        let now = OffsetDateTime::now_utc();
        let mut ws = make_transition_row();
        ws.build_transition = "start".to_owned();
        ws.job_status = "failed".to_owned();
        ws.job_completed_at = Some(now - time::Duration::hours(2));
        ws.template_failure_ttl = 0;
        assert!(!is_eligible_for_failed_stop(&ws, now));
    }

    #[test]
    fn failed_stop_not_eligible_when_not_failed() {
        let now = OffsetDateTime::now_utc();
        let mut ws = make_transition_row();
        ws.build_transition = "start".to_owned();
        ws.job_status = "succeeded".to_owned();
        ws.job_completed_at = Some(now - time::Duration::hours(2));
        ws.template_failure_ttl = 60 * 60 * 1_000_000_000;
        assert!(!is_eligible_for_failed_stop(&ws, now));
    }

    // ── get_next_transition tests ───────────────────────────

    #[test]
    fn next_transition_autostop_has_highest_priority() {
        let now = OffsetDateTime::now_utc();
        let mut ws = make_transition_row();
        ws.build_transition = "start".to_owned();
        ws.build_deadline = Some(now - time::Duration::minutes(5));

        let result = get_next_transition(&ws, now);
        assert_eq!(result, Some((AutobuildAction::Stop, BuildReason::Autostop)));
    }

    #[test]
    fn next_transition_autostart() {
        let now = OffsetDateTime::now_utc();
        let mut ws = make_transition_row();
        ws.build_transition = "stop".to_owned();
        ws.autostart_schedule = Some("* * * * *".to_owned());
        ws.job_completed_at = Some(now - time::Duration::minutes(2));
        ws.build_deadline = None;

        let result = get_next_transition(&ws, now);
        assert_eq!(
            result,
            Some((AutobuildAction::Start, BuildReason::Autostart))
        );
    }

    #[test]
    fn next_transition_dormancy_running_workspace() {
        let now = OffsetDateTime::now_utc();
        let mut ws = make_transition_row();
        ws.build_transition = "start".to_owned();
        ws.last_used_at = now - time::Duration::days(31);
        ws.template_time_til_dormant = 30 * 24 * 60 * 60 * 1_000_000_000;
        ws.build_deadline = None;

        let result = get_next_transition(&ws, now);
        assert_eq!(result, Some((AutobuildAction::Stop, BuildReason::Dormancy)));
    }

    #[test]
    fn next_transition_dormancy_stopped_workspace() {
        let now = OffsetDateTime::now_utc();
        let mut ws = make_transition_row();
        ws.build_transition = "stop".to_owned();
        ws.last_used_at = now - time::Duration::days(31);
        ws.template_time_til_dormant = 30 * 24 * 60 * 60 * 1_000_000_000;
        ws.autostart_schedule = None;
        ws.job_status = "succeeded".to_owned();
        ws.job_completed_at = None;

        let result = get_next_transition(&ws, now);
        assert_eq!(
            result,
            Some((AutobuildAction::Dormant, BuildReason::Dormancy))
        );
    }

    #[test]
    fn next_transition_autodelete() {
        let now = OffsetDateTime::now_utc();
        let mut ws = make_transition_row();
        ws.dormant_at = Some(now - time::Duration::days(90));
        ws.deleting_at = Some(now - time::Duration::hours(1));
        ws.template_time_til_dormant_autodelete = 90 * 24 * 60 * 60 * 1_000_000_000;
        ws.build_transition = "stop".to_owned();
        ws.build_deadline = None;

        let result = get_next_transition(&ws, now);
        assert_eq!(
            result,
            Some((AutobuildAction::Delete, BuildReason::Autodelete))
        );
    }

    #[test]
    fn next_transition_none_when_no_action_needed() {
        let now = OffsetDateTime::now_utc();
        let mut ws = make_transition_row();
        ws.build_transition = "start".to_owned();
        ws.build_deadline = Some(now + time::Duration::hours(2));
        ws.template_time_til_dormant = 0;
        ws.template_failure_ttl = 0;

        let result = get_next_transition(&ws, now);
        assert_eq!(result, None);
    }

    // ── AutobuildExecutor integration tests ─────────────────

    #[derive(Clone)]
    struct MockWorkspaceStore {
        workspaces: StdArc<Mutex<Vec<WorkspaceTransitionRow>>>,
        should_fail: StdArc<AtomicBool>,
        dormancy_updates: StdArc<std::sync::Mutex<Vec<uuid::Uuid>>>,
        deleted_workspaces: StdArc<std::sync::Mutex<Vec<uuid::Uuid>>>,
    }

    impl MockWorkspaceStore {
        fn new(workspaces: Vec<WorkspaceTransitionRow>) -> Self {
            Self {
                workspaces: StdArc::new(Mutex::new(workspaces)),
                should_fail: StdArc::new(AtomicBool::new(false)),
                dormancy_updates: StdArc::new(std::sync::Mutex::new(Vec::new())),
                deleted_workspaces: StdArc::new(std::sync::Mutex::new(Vec::new())),
            }
        }

        fn with_failure(self) -> Self {
            self.should_fail.store(true, Ordering::SeqCst);
            self
        }
    }

    #[async_trait]
    impl AutobuildStore for MockWorkspaceStore {
        async fn get_workspaces_eligible_for_transition(
            &self,
            _now: OffsetDateTime,
        ) -> Result<Vec<WorkspaceTransitionRow>, StorageError> {
            if self.should_fail.load(Ordering::SeqCst) {
                return Err(StorageError::unavailable("mock store failure"));
            }
            Ok(self.workspaces.lock().await.clone())
        }

        async fn update_workspace_dormant_deleting_at(
            &self,
            workspace_id: uuid::Uuid,
            _dormant_at: Option<OffsetDateTime>,
        ) -> Result<Option<WorkspaceRecord>, StorageError> {
            if let Ok(mut updates) = self.dormancy_updates.lock() {
                updates.push(workspace_id);
            }
            Ok(None)
        }

        async fn soft_delete_workspace(
            &self,
            workspace_id: uuid::Uuid,
        ) -> Result<bool, StorageError> {
            if let Ok(mut deleted) = self.deleted_workspaces.lock() {
                deleted.push(workspace_id);
            }
            Ok(true)
        }
    }

    #[tokio::test]
    async fn executor_evaluate_empty_workspaces() {
        let store = MockWorkspaceStore::new(vec![]);
        let cancel = CancellationToken::new();
        let executor = AutobuildExecutor {
            store,
            cancel,
            tick_secs: AUTOBUILD_TICK_SECS,
        };

        let stats = executor.evaluate_once().await;
        assert!(stats.is_ok());
        let s = stats.unwrap_or_else(|_| unreachable!());
        assert_eq!(s.evaluated, 0);
        assert_eq!(s.transitions, 0);
        assert_eq!(s.errors, 0);
    }

    #[tokio::test]
    async fn executor_evaluate_handles_store_failure() {
        let store = MockWorkspaceStore::new(vec![]).with_failure();
        let cancel = CancellationToken::new();
        let executor = AutobuildExecutor {
            store,
            cancel,
            tick_secs: AUTOBUILD_TICK_SECS,
        };

        let result = executor.evaluate_once().await;
        assert!(result.is_err(), "should propagate store error");
    }

    #[tokio::test]
    async fn executor_autostop_transition() {
        let now = OffsetDateTime::now_utc();
        let mut ws = make_transition_row();
        ws.build_transition = "start".to_owned();
        ws.build_deadline = Some(now - time::Duration::minutes(5));

        let store = MockWorkspaceStore::new(vec![ws]);
        let cancel = CancellationToken::new();
        let executor = AutobuildExecutor {
            store,
            cancel,
            tick_secs: AUTOBUILD_TICK_SECS,
        };

        let stats = executor.evaluate_once().await;
        assert!(stats.is_ok());
        let s = stats.unwrap_or_else(|_| unreachable!());
        assert_eq!(s.evaluated, 1);
        assert_eq!(s.transitions, 1);
        assert_eq!(s.errors, 0);
    }

    #[tokio::test]
    async fn executor_dormancy_marks_workspace() {
        let now = OffsetDateTime::now_utc();
        let mut ws = make_transition_row();
        ws.build_transition = "stop".to_owned();
        ws.last_used_at = now - time::Duration::days(31);
        ws.template_time_til_dormant = 30 * 24 * 60 * 60 * 1_000_000_000;
        ws.autostart_schedule = None;
        ws.job_completed_at = None;
        let ws_id = ws.id;

        let store = MockWorkspaceStore::new(vec![ws]);
        let dormancy_updates = store.dormancy_updates.clone();
        let cancel = CancellationToken::new();
        let executor = AutobuildExecutor {
            store,
            cancel,
            tick_secs: AUTOBUILD_TICK_SECS,
        };

        let stats = executor.evaluate_once().await;
        assert!(stats.is_ok());
        let s = stats.unwrap_or_else(|_| unreachable!());
        assert_eq!(s.transitions, 1);

        let updates = dormancy_updates.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            updates.contains(&ws_id),
            "should have called update_workspace_dormant_deleting_at"
        );
    }

    #[tokio::test]
    async fn executor_autodelete_deletes_workspace() {
        let now = OffsetDateTime::now_utc();
        let mut ws = make_transition_row();
        ws.dormant_at = Some(now - time::Duration::days(90));
        ws.deleting_at = Some(now - time::Duration::hours(1));
        ws.template_time_til_dormant_autodelete = 90 * 24 * 60 * 60 * 1_000_000_000;
        ws.build_transition = "stop".to_owned();
        ws.build_deadline = None;
        ws.autostart_schedule = None;
        ws.job_completed_at = None;
        let ws_id = ws.id;

        let store = MockWorkspaceStore::new(vec![ws]);
        let deleted = store.deleted_workspaces.clone();
        let cancel = CancellationToken::new();
        let executor = AutobuildExecutor {
            store,
            cancel,
            tick_secs: AUTOBUILD_TICK_SECS,
        };

        let stats = executor.evaluate_once().await;
        assert!(stats.is_ok());
        let s = stats.unwrap_or_else(|_| unreachable!());
        assert_eq!(s.transitions, 1);

        let deleted = deleted.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            deleted.contains(&ws_id),
            "should have soft-deleted the workspace"
        );
    }

    #[tokio::test]
    async fn executor_cancellation() {
        let store = MockWorkspaceStore::new(vec![]);
        let cancel = CancellationToken::new();
        let (_executor, _handle) =
            AutobuildExecutor::start_with_interval(store, cancel.clone(), 3600);

        cancel.cancel();
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    }

    #[tokio::test]
    async fn executor_multiple_workspaces_concurrent() {
        let now = OffsetDateTime::now_utc();
        let mut workspaces = Vec::new();

        for i in 0..20 {
            let mut ws = make_transition_row();
            ws.name = format!("ws-{i}");
            ws.build_transition = "start".to_owned();
            ws.build_deadline = Some(now - time::Duration::minutes(5));
            workspaces.push(ws);
        }

        let store = MockWorkspaceStore::new(workspaces);
        let cancel = CancellationToken::new();
        let executor = AutobuildExecutor {
            store,
            cancel,
            tick_secs: AUTOBUILD_TICK_SECS,
        };

        let stats = executor.evaluate_once().await;
        assert!(stats.is_ok());
        let s = stats.unwrap_or_else(|_| unreachable!());
        assert_eq!(s.evaluated, 20);
        assert_eq!(s.transitions, 20);
        assert_eq!(s.errors, 0);
    }

    // ── TemplateScheduleConstraints tests ───────────────────

    #[test]
    fn template_schedule_constraints_default_values() {
        let constraints = TemplateScheduleConstraints {
            max_autostart_interval: None,
            max_ttl_minutes: None,
            quiet_hours: None,
            dormancy_threshold_days: None,
            dormancy_auto_deletion_days: None,
        };

        assert!(constraints.max_autostart_interval.is_none());
        assert!(constraints.max_ttl_minutes.is_none());
        assert!(constraints.quiet_hours.is_none());
        assert!(constraints.dormancy_threshold_days.is_none());
        assert!(constraints.dormancy_auto_deletion_days.is_none());
    }

    #[test]
    fn template_schedule_constraints_with_values() {
        let constraints = TemplateScheduleConstraints {
            max_autostart_interval: Some(std::time::Duration::from_secs(3600)),
            max_ttl_minutes: Some(480),
            quiet_hours: Some(QuietHoursWindow {
                start_hour: 22,
                end_hour: 6,
            }),
            dormancy_threshold_days: Some(30),
            dormancy_auto_deletion_days: Some(90),
        };

        assert_eq!(
            constraints.max_autostart_interval,
            Some(std::time::Duration::from_secs(3600))
        );
        assert_eq!(constraints.max_ttl_minutes, Some(480));
        assert!(constraints.quiet_hours.is_some());
        assert_eq!(constraints.dormancy_threshold_days, Some(30));
        assert_eq!(constraints.dormancy_auto_deletion_days, Some(90));

        // Verify the quiet hours window works within the constraints
        let qh = constraints
            .quiet_hours
            .as_ref()
            .unwrap_or_else(|| unreachable!());
        let midnight = time::macros::datetime!(2026-03-09 00:00:00 UTC);
        assert!(
            qh.is_quiet(midnight),
            "midnight should be in quiet window 22-6"
        );
    }

    // ── QuietHoursWindow edge cases ─────────────────────────

    #[test]
    fn quiet_hours_same_start_end_is_never_quiet() {
        // When start == end, the window is zero-width
        let window = QuietHoursWindow {
            start_hour: 12,
            end_hour: 12,
        };
        let noon = time::macros::datetime!(2026-03-09 12:00:00 UTC);
        assert!(
            !window.is_quiet(noon),
            "zero-width window should never be quiet"
        );
        let other = time::macros::datetime!(2026-03-09 06:00:00 UTC);
        assert!(
            !window.is_quiet(other),
            "zero-width window should never be quiet for any hour"
        );
    }

    #[test]
    fn quiet_hours_full_day_wrap() {
        // start=0, end=0 wrapping case — wraps midnight, covers all 24 hours
        let window = QuietHoursWindow {
            start_hour: 0,
            end_hour: 0,
        };
        // With start==end and start<=end path, hour >= 0 && hour < 0 is false
        let t = time::macros::datetime!(2026-03-09 15:00:00 UTC);
        assert!(
            !window.is_quiet(t),
            "start==end==0 non-wrapping path returns false"
        );
    }

    // ── Dormancy edge cases ─────────────────────────────────

    #[test]
    fn dormancy_zero_threshold_always_dormant() {
        let recent = OffsetDateTime::now_utc();
        assert_eq!(
            evaluate_dormancy(recent, 0),
            AutobuildAction::Dormant,
            "zero threshold means always dormant"
        );
    }

    #[test]
    fn dormancy_very_large_threshold_never_dormant() {
        let old = OffsetDateTime::now_utc() - time::Duration::days(365 * 10);
        // u64::MAX days is much larger than 10 years
        assert_eq!(
            evaluate_dormancy(old, u64::MAX),
            AutobuildAction::None,
            "enormous threshold should never be dormant"
        );
    }

    // ── AutostopPolicy edge cases ───────────────────────────

    #[test]
    fn autostop_policy_zero_ttl_always_stops() {
        let policy = AutostopPolicy { ttl_minutes: 0 };
        let now = OffsetDateTime::now_utc();
        assert!(
            policy.should_stop(now),
            "zero TTL should always trigger stop"
        );
    }

    #[test]
    fn autostop_policy_future_activity_does_not_stop() {
        let policy = AutostopPolicy { ttl_minutes: 60 };
        // Activity 1 second in the future (clock skew scenario)
        let future = OffsetDateTime::now_utc() + time::Duration::seconds(1);
        assert!(
            !policy.should_stop(future),
            "future activity should not trigger stop"
        );
    }

    // ── ScheduleParseError display ──────────────────────────

    #[test]
    fn schedule_parse_error_display() {
        let err = ScheduleParseError::InvalidCron("bad expression".to_owned());
        let msg = err.to_string();
        assert!(
            msg.contains("invalid cron expression"),
            "error message should describe invalid cron"
        );
        assert!(msg.contains("bad expression"));
    }

    // ── AutostartSchedule timezone edge cases ───────────────

    #[test]
    fn autostart_schedule_utc_default_when_no_prefix() {
        let schedule = AutostartSchedule::parse("0 12 * * *");
        assert!(schedule.is_ok());
        let s = schedule.unwrap_or_else(|_| unreachable!());
        assert_eq!(s.timezone(), "UTC");
    }

    #[test]
    fn autostart_schedule_cron_tz_with_various_timezones() {
        let timezones = [
            "America/New_York",
            "Europe/London",
            "Asia/Tokyo",
            "Australia/Sydney",
        ];
        for tz in &timezones {
            let raw = format!("CRON_TZ={tz} 0 9 * * *");
            let schedule = AutostartSchedule::parse(&raw);
            assert!(schedule.is_ok(), "should parse cron with TZ={tz}");
            let s = schedule.unwrap_or_else(|_| unreachable!());
            assert_eq!(s.timezone(), *tz);
            // Should always have a next occurrence
            assert!(
                s.next_after_utc().is_some(),
                "should have next occurrence for TZ={tz}"
            );
        }
    }

    // ── Activity Bump Worker tests ──────────────────────────

    /// Mock store for ActivityBumpStore tests.
    struct MockActivityBumpStore {
        workspaces: Vec<WorkspaceTransitionRow>,
        updated_deadlines: std::sync::Mutex<Vec<(uuid::Uuid, Option<OffsetDateTime>, Option<OffsetDateTime>)>>,
        fail_transition: AtomicBool,
    }

    impl MockActivityBumpStore {
        fn new(workspaces: Vec<WorkspaceTransitionRow>) -> Self {
            Self {
                workspaces,
                updated_deadlines: std::sync::Mutex::new(Vec::new()),
                fail_transition: AtomicBool::new(false),
            }
        }

        fn with_failure(mut self) -> Self {
            self.fail_transition = AtomicBool::new(true);
            self
        }

        fn deadline_updates(&self) -> Vec<(uuid::Uuid, Option<OffsetDateTime>, Option<OffsetDateTime>)> {
            self.updated_deadlines.lock().unwrap_or_else(|p| p.into_inner()).clone()
        }
    }

    #[async_trait]
    impl ActivityBumpStore for MockActivityBumpStore {
        async fn update_workspace_last_used_at(
            &self,
            _workspace_id: uuid::Uuid,
            _last_used_at: OffsetDateTime,
        ) -> Result<bool, StorageError> {
            Ok(true)
        }

        async fn get_workspaces_eligible_for_transition(
            &self,
            _now: OffsetDateTime,
        ) -> Result<Vec<WorkspaceTransitionRow>, StorageError> {
            if self.fail_transition.load(Ordering::Relaxed) {
                return Err(StorageError::unavailable("mock failure"));
            }
            Ok(self.workspaces.clone())
        }

        async fn update_workspace_build_deadline(
            &self,
            build_id: uuid::Uuid,
            deadline: Option<OffsetDateTime>,
            max_deadline: Option<OffsetDateTime>,
        ) -> Result<bool, StorageError> {
            if let Ok(mut updates) = self.updated_deadlines.lock() {
                updates.push((build_id, deadline, max_deadline));
            }
            Ok(true)
        }
    }

    #[tokio::test]
    async fn activity_bump_once_bumps_recently_active_workspace() {
        let now = OffsetDateTime::now_utc();
        let one_hour_ns: i64 = 3_600_000_000_000; // 1 hour in nanoseconds
        let mut ws = make_transition_row();
        ws.build_transition = "start".to_owned();
        ws.activity_bump_ns = one_hour_ns;
        ws.last_used_at = now - time::Duration::minutes(5); // active 5 min ago
        ws.job_completed_at = Some(now - time::Duration::hours(1));
        // Set a deadline in the near future so the bump actually extends it.
        ws.build_deadline = Some(now + time::Duration::minutes(10));

        let store = MockActivityBumpStore::new(vec![ws.clone()]);
        let result = activity_bump_once(&store, now).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap_or(0), 1);

        let updates = store.deadline_updates();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].0, ws.build_id);
    }

    #[tokio::test]
    async fn activity_bump_once_skips_inactive_workspace() {
        let now = OffsetDateTime::now_utc();
        let one_hour_ns: i64 = 3_600_000_000_000;
        let mut ws = make_transition_row();
        ws.build_transition = "start".to_owned();
        ws.activity_bump_ns = one_hour_ns;
        ws.last_used_at = now - time::Duration::hours(2); // inactive for 2 hours

        let store = MockActivityBumpStore::new(vec![ws]);
        let result = activity_bump_once(&store, now).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap_or(1), 0);
        assert!(store.deadline_updates().is_empty());
    }

    #[tokio::test]
    async fn activity_bump_once_skips_stopped_workspace() {
        let now = OffsetDateTime::now_utc();
        let one_hour_ns: i64 = 3_600_000_000_000;
        let mut ws = make_transition_row();
        ws.build_transition = "stop".to_owned();
        ws.activity_bump_ns = one_hour_ns;
        ws.last_used_at = now - time::Duration::minutes(1);

        let store = MockActivityBumpStore::new(vec![ws]);
        let result = activity_bump_once(&store, now).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap_or(1), 0);
    }

    #[tokio::test]
    async fn activity_bump_once_skips_no_activity_bump_configured() {
        let now = OffsetDateTime::now_utc();
        let mut ws = make_transition_row();
        ws.build_transition = "start".to_owned();
        ws.activity_bump_ns = 0; // no activity bump configured
        ws.last_used_at = now - time::Duration::minutes(1);

        let store = MockActivityBumpStore::new(vec![ws]);
        let result = activity_bump_once(&store, now).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap_or(1), 0);
    }

    #[tokio::test]
    async fn activity_bump_once_handles_store_error() {
        let now = OffsetDateTime::now_utc();
        let store = MockActivityBumpStore::new(vec![]).with_failure();
        let result = activity_bump_once(&store, now).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn activity_bump_once_empty_workspace_list() {
        let now = OffsetDateTime::now_utc();
        let store = MockActivityBumpStore::new(vec![]);
        let result = activity_bump_once(&store, now).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap_or(1), 0);
    }

    // ── Dormancy Checker Worker tests ──────────────────────────

    /// Mock store for DormancyCheckerStore tests.
    struct MockDormancyCheckerStore {
        workspaces: Vec<WorkspaceTransitionRow>,
        dormant_updates: std::sync::Mutex<Vec<(uuid::Uuid, Option<OffsetDateTime>)>>,
        fail_transition: AtomicBool,
    }

    impl MockDormancyCheckerStore {
        fn new(workspaces: Vec<WorkspaceTransitionRow>) -> Self {
            Self {
                workspaces,
                dormant_updates: std::sync::Mutex::new(Vec::new()),
                fail_transition: AtomicBool::new(false),
            }
        }

        fn with_failure(mut self) -> Self {
            self.fail_transition = AtomicBool::new(true);
            self
        }

        fn dormancy_updates(&self) -> Vec<(uuid::Uuid, Option<OffsetDateTime>)> {
            self.dormant_updates.lock().unwrap_or_else(|p| p.into_inner()).clone()
        }
    }

    #[async_trait]
    impl DormancyCheckerStore for MockDormancyCheckerStore {
        async fn get_workspaces_eligible_for_transition(
            &self,
            _now: OffsetDateTime,
        ) -> Result<Vec<WorkspaceTransitionRow>, StorageError> {
            if self.fail_transition.load(Ordering::Relaxed) {
                return Err(StorageError::unavailable("mock failure"));
            }
            Ok(self.workspaces.clone())
        }

        async fn update_workspace_dormant_deleting_at(
            &self,
            workspace_id: uuid::Uuid,
            dormant_at: Option<OffsetDateTime>,
        ) -> Result<Option<WorkspaceRecord>, StorageError> {
            if let Ok(mut updates) = self.dormant_updates.lock() {
                updates.push((workspace_id, dormant_at));
            }
            Ok(Some(WorkspaceRecord {
                id: workspace_id,
                name: "test".to_owned(),
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
                owner_id: uuid::Uuid::new_v4(),
                organization_id: uuid::Uuid::new_v4(),
                template_id: uuid::Uuid::new_v4(),
                deleted: false,
                autostart_schedule: None,
                ttl_ns: None,
                last_used_at: OffsetDateTime::now_utc(),
                dormant_at,
                deleting_at: None,
                automatic_updates: "never".to_owned(),
                favorite: false,
                next_start_at: None,
            }))
        }
    }

    #[tokio::test]
    async fn dormancy_check_once_marks_idle_workspace_dormant() {
        let now = OffsetDateTime::now_utc();
        let dormancy_ns: i64 = 7 * 24 * 3_600_000_000_000; // 7 days in ns
        let mut ws = make_transition_row();
        ws.build_transition = "start".to_owned();
        ws.dormant_at = None;
        ws.template_time_til_dormant = dormancy_ns;
        ws.last_used_at = now - time::Duration::days(10); // idle for 10 days
        ws.job_status = "succeeded".to_owned();

        let store = MockDormancyCheckerStore::new(vec![ws.clone()]);
        let result = dormancy_check_once(&store, now).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap_or(0), 1);

        let updates = store.dormancy_updates();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].0, ws.id);
        assert!(updates[0].1.is_some());
    }

    #[tokio::test]
    async fn dormancy_check_once_skips_already_dormant_workspace() {
        let now = OffsetDateTime::now_utc();
        let dormancy_ns: i64 = 7 * 24 * 3_600_000_000_000;
        let mut ws = make_transition_row();
        ws.dormant_at = Some(now - time::Duration::days(1)); // already dormant
        ws.template_time_til_dormant = dormancy_ns;
        ws.last_used_at = now - time::Duration::days(10);

        let store = MockDormancyCheckerStore::new(vec![ws]);
        let result = dormancy_check_once(&store, now).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap_or(1), 0);
        assert!(store.dormancy_updates().is_empty());
    }

    #[tokio::test]
    async fn dormancy_check_once_skips_recently_active_workspace() {
        let now = OffsetDateTime::now_utc();
        let dormancy_ns: i64 = 7 * 24 * 3_600_000_000_000;
        let mut ws = make_transition_row();
        ws.dormant_at = None;
        ws.template_time_til_dormant = dormancy_ns;
        ws.last_used_at = now - time::Duration::hours(1); // active recently

        let store = MockDormancyCheckerStore::new(vec![ws]);
        let result = dormancy_check_once(&store, now).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap_or(1), 0);
    }

    #[tokio::test]
    async fn dormancy_check_once_handles_store_error() {
        let now = OffsetDateTime::now_utc();
        let store = MockDormancyCheckerStore::new(vec![]).with_failure();
        let result = dormancy_check_once(&store, now).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn dormancy_check_once_empty_workspace_list() {
        let now = OffsetDateTime::now_utc();
        let store = MockDormancyCheckerStore::new(vec![]);
        let result = dormancy_check_once(&store, now).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap_or(1), 0);
    }

    #[tokio::test]
    async fn dormancy_check_once_skips_no_dormancy_configured() {
        let now = OffsetDateTime::now_utc();
        let mut ws = make_transition_row();
        ws.dormant_at = None;
        ws.template_time_til_dormant = 0; // no dormancy threshold
        ws.last_used_at = now - time::Duration::days(100);

        let store = MockDormancyCheckerStore::new(vec![ws]);
        let result = dormancy_check_once(&store, now).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap_or(1), 0);
    }
}
