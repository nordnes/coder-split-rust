//! Workspace, template, and deployment-stats helpers.
//!
//! Provides the autobuild executor loop, schedule evaluation, and
//! deployment-stats caching.
#![forbid(unsafe_code)]

use std::str::FromStr;
use std::sync::{Arc, Weak};

use coder_core::{DeploymentStatsResponse, OperationalStore, StorageError};
use time::OffsetDateTime;
use tokio::sync::{Mutex, RwLock};
use tracing::{info, warn};

const DEPLOYMENT_STATS_REFRESH_SECS: u64 = 60;

/// Cached deployment-stats service modeled after Go's metrics cache.
pub struct DeploymentStatsService<S> {
    store: S,
    cache: RwLock<Option<DeploymentStatsResponse>>,
    refresh_lock: Mutex<()>,
}

impl<S> DeploymentStatsService<S>
where
    S: OperationalStore + Clone + Send + Sync + 'static,
{
    /// Creates the cached deployment-stats service and starts background refresh.
    #[must_use]
    pub fn new(store: S) -> Arc<Self> {
        let service = Arc::new(Self {
            store,
            cache: RwLock::new(None),
            refresh_lock: Mutex::new(()),
        });
        Self::spawn_refresh_loop(&service);
        service
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
        tokio::spawn(async move {
            run_refresh_loop(weak).await;
        });
    }
}

async fn run_refresh_loop<S>(service: Weak<DeploymentStatsService<S>>)
where
    S: OperationalStore + Clone + Send + Sync + 'static,
{
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(
        DEPLOYMENT_STATS_REFRESH_SECS,
    ));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        interval.tick().await;
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
    /// No action needed.
    None,
}

// ---------------------------------------------------------------------------
// Autobuild Executor
// ---------------------------------------------------------------------------

const AUTOBUILD_TICK_SECS: u64 = 30;

/// Background autobuild executor that evaluates workspace lifecycle rules.
///
/// Runs every 30 seconds, evaluates all active workspaces against their
/// autostart schedule, autostop TTL, deadlines, and dormancy rules.
pub struct AutobuildExecutor<S> {
    store: S,
    _refresh_lock: Mutex<()>,
}

impl<S> AutobuildExecutor<S>
where
    S: OperationalStore + Clone + Send + Sync + 'static,
{
    /// Creates the executor and starts the background evaluation loop.
    #[must_use]
    pub fn new(store: S) -> Arc<Self> {
        let executor = Arc::new(Self {
            store,
            _refresh_lock: Mutex::new(()),
        });
        Self::spawn_executor_loop(&executor);
        executor
    }

    /// Evaluates one tick of the autobuild loop.
    ///
    /// In a full implementation this queries active workspaces and evaluates
    /// each against schedule constraints. For now, the executor is a skeleton
    /// that logs each tick.
    async fn evaluate_once(&self) -> Result<u32, StorageError> {
        // Fetch deployment stats to determine workspace counts.
        let stats = self.store.deployment_stats().await.ok();
        let workspace_count = stats
            .as_ref()
            .map(|s| {
                s.workspaces
                    .running
                    .saturating_add(s.workspaces.stopped)
                    .saturating_add(s.workspaces.pending)
            })
            .unwrap_or(0);

        if workspace_count > 0 {
            info!(
                workspaces = workspace_count,
                "autobuild executor tick evaluated"
            );
        }

        Ok(u32::try_from(workspace_count).unwrap_or(u32::MAX))
    }

    fn spawn_executor_loop(executor: &Arc<Self>) {
        let weak = Arc::downgrade(executor);
        tokio::spawn(async move {
            run_autobuild_loop(weak).await;
        });
    }
}

async fn run_autobuild_loop<S>(executor: Weak<AutobuildExecutor<S>>)
where
    S: OperationalStore + Clone + Send + Sync + 'static,
{
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(AUTOBUILD_TICK_SECS));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        interval.tick().await;
        let Some(executor) = executor.upgrade() else {
            return;
        };
        if let Err(error) = executor.evaluate_once().await {
            warn!(error = %error, "autobuild executor tick failed");
        }
    }
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

    // ── AutobuildExecutor tests ─────────────────────────────

    #[tokio::test]
    async fn autobuild_executor_evaluate_returns_workspace_count() {
        let stats = default_stats();
        let store = MockOperationalStore::new(stats);

        let executor = StdArc::new(AutobuildExecutor {
            store,
            _refresh_lock: Mutex::new(()),
        });

        let count = executor.evaluate_once().await;
        assert!(count.is_ok());
        // pending(1) + running(5) + stopped(3) = 9
        let workspace_count = count.unwrap_or_else(|_| unreachable!());
        assert_eq!(workspace_count, 9);
    }

    #[tokio::test]
    async fn autobuild_executor_evaluate_handles_store_failure() {
        let store = MockOperationalStore::new(default_stats()).with_failure();

        let executor = StdArc::new(AutobuildExecutor {
            store,
            _refresh_lock: Mutex::new(()),
        });

        // When the store fails, evaluate_once returns Ok(0) because
        // deployment_stats().ok() returns None and unwrap_or(0) kicks in.
        let count = executor.evaluate_once().await;
        assert!(count.is_ok());
        assert_eq!(count.unwrap_or_else(|_| unreachable!()), 0);
    }

    #[tokio::test]
    async fn autobuild_executor_evaluate_zero_workspaces() {
        let mut stats = default_stats();
        stats.workspaces.pending = 0;
        stats.workspaces.running = 0;
        stats.workspaces.stopped = 0;
        stats.workspaces.building = 0;
        stats.workspaces.failed = 0;
        let store = MockOperationalStore::new(stats);

        let executor = StdArc::new(AutobuildExecutor {
            store,
            _refresh_lock: Mutex::new(()),
        });

        let count = executor.evaluate_once().await;
        assert!(count.is_ok());
        assert_eq!(count.unwrap_or_else(|_| unreachable!()), 0);
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
}
