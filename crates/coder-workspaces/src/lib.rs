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
}
