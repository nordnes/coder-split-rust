//! Telemetry reporter that accepts events and exposes status.

use serde::Serialize;
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tracing::warn;
use uuid::Uuid;

use crate::events::TelemetryEvent;

/// Current status of the telemetry subsystem.
#[derive(Clone, Debug, Serialize)]
pub struct TelemetryStatus {
    /// Whether telemetry collection is enabled.
    pub enabled: bool,
    /// Stable deployment identifier.
    pub deployment_id: String,
    /// Total events collected since startup.
    pub events_collected: u64,
    /// Total events successfully submitted.
    pub events_submitted: u64,
    /// Total submission errors since startup.
    pub submission_errors: u64,
}

/// A batch of telemetry events ready for submission.
#[derive(Clone, Debug, Serialize)]
pub struct TelemetrySnapshot {
    /// Stable deployment identifier.
    pub deployment_id: String,
    /// Server version string.
    pub version: String,
    /// Events in this batch.
    pub events: Vec<TelemetryEvent>,
    /// Timestamp when this snapshot was created.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// Handle for submitting telemetry events from application code.
///
/// Cloning this handle is cheap (it wraps an `mpsc::Sender`).
/// When telemetry is disabled the sender is `None` and events are silently
/// dropped.
#[derive(Clone, Debug)]
pub struct TelemetryReporter {
    sender: Option<mpsc::Sender<TelemetryEvent>>,
    deployment_id: Uuid,
}

impl TelemetryReporter {
    /// Creates a new reporter backed by the given channel sender.
    ///
    /// Pass `None` for `sender` when telemetry is disabled — all
    /// [`report`](Self::report) calls become no-ops.
    #[must_use]
    pub fn new(sender: Option<mpsc::Sender<TelemetryEvent>>, deployment_id: Uuid) -> Self {
        Self {
            sender,
            deployment_id,
        }
    }

    /// Creates a disabled reporter that silently drops all events.
    #[must_use]
    pub fn disabled(deployment_id: Uuid) -> Self {
        Self {
            sender: None,
            deployment_id,
        }
    }

    /// Returns whether telemetry collection is active.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.sender.is_some()
    }

    /// Returns the deployment identifier.
    #[must_use]
    pub fn deployment_id(&self) -> Uuid {
        self.deployment_id
    }

    /// Submits a telemetry event for batched delivery.
    ///
    /// This is a non-blocking best-effort operation.  If the internal
    /// channel is full or telemetry is disabled the event is silently
    /// dropped.
    pub fn report(&self, event: TelemetryEvent) {
        if let Some(ref sender) = self.sender {
            if let Err(e) = sender.try_send(event) {
                warn!(error = %e, "telemetry event dropped (channel full or closed)");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::TelemetryEventKind;

    #[test]
    fn disabled_reporter_drops_events() {
        let reporter = TelemetryReporter::disabled(Uuid::nil());
        assert!(!reporter.is_enabled());
        // Should not panic.
        reporter.report(TelemetryEvent::new(
            TelemetryEventKind::UserLogin,
            None,
            None,
        ));
    }

    #[tokio::test]
    async fn enabled_reporter_sends_events() {
        let (tx, mut rx) = mpsc::channel(16);
        let reporter = TelemetryReporter::new(Some(tx), Uuid::nil());
        assert!(reporter.is_enabled());

        reporter.report(TelemetryEvent::new(
            TelemetryEventKind::UserLogin,
            None,
            None,
        ));

        let event = rx.recv().await;
        assert!(event.is_some());
        if let Some(event) = event {
            assert_eq!(event.kind, TelemetryEventKind::UserLogin);
        }
    }

    #[tokio::test]
    async fn reporter_handles_full_channel_gracefully() {
        // Channel capacity 1, send 2 events — second should be dropped.
        let (tx, _rx) = mpsc::channel(1);
        let reporter = TelemetryReporter::new(Some(tx), Uuid::nil());

        reporter.report(TelemetryEvent::new(
            TelemetryEventKind::UserLogin,
            None,
            None,
        ));
        // Second send should not panic even if channel is full.
        reporter.report(TelemetryEvent::new(
            TelemetryEventKind::UserLogout,
            None,
            None,
        ));
    }

    #[test]
    fn deployment_id_accessor() {
        let id = Uuid::new_v4();
        let reporter = TelemetryReporter::disabled(id);
        assert_eq!(reporter.deployment_id(), id);
    }

    #[test]
    fn telemetry_status_serializes() -> Result<(), Box<dyn std::error::Error>> {
        let status = TelemetryStatus {
            enabled: true,
            deployment_id: "test".to_owned(),
            events_collected: 42,
            events_submitted: 40,
            submission_errors: 2,
        };
        let json = serde_json::to_value(&status)?;
        assert_eq!(json["enabled"], true);
        assert_eq!(json["events_collected"], 42);
        Ok(())
    }

    #[test]
    fn telemetry_snapshot_serializes() -> Result<(), Box<dyn std::error::Error>> {
        let snapshot = TelemetrySnapshot {
            deployment_id: "dep-1".to_owned(),
            version: "0.1.0".to_owned(),
            events: Vec::new(),
            created_at: OffsetDateTime::now_utc(),
        };
        let json = serde_json::to_value(&snapshot)?;
        assert_eq!(json["deployment_id"], "dep-1");
        assert!(json.get("created_at").is_some());
        Ok(())
    }
}
