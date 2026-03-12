//! Background telemetry worker.
//!
//! Drains events from the mpsc channel, batches them, and periodically
//! submits snapshots to the configured telemetry endpoint.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use url::Url;
use uuid::Uuid;

use crate::events::TelemetryEvent;
use crate::reporter::{TelemetryReporter, TelemetrySnapshot, TelemetryStatus};

/// Configuration for the telemetry background worker.
#[derive(Clone, Debug)]
pub struct TelemetryConfig {
    /// Whether telemetry is enabled.
    pub enabled: bool,
    /// Stable deployment identifier.
    pub deployment_id: Uuid,
    /// Server version string included in snapshots.
    pub version: String,
    /// Remote endpoint to submit snapshots to.
    /// When `None`, events are collected but not submitted.
    pub endpoint: Option<Url>,
    /// How often to flush accumulated events.
    pub flush_interval: Duration,
    /// Maximum number of events to buffer before forcing a flush.
    pub max_batch_size: usize,
    /// Hard cap on the in-memory event buffer.  When the buffer exceeds
    /// this size (e.g. due to repeated submission failures), the oldest
    /// events are dropped to prevent unbounded memory growth.
    pub max_buffer_size: usize,
    /// Capacity of the internal mpsc channel.
    pub channel_capacity: usize,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            deployment_id: Uuid::nil(),
            version: String::new(),
            endpoint: None,
            flush_interval: Duration::from_secs(30 * 60), // 30 minutes
            max_batch_size: 1024,
            max_buffer_size: 8192,
            channel_capacity: 4096,
        }
    }
}

/// Counters shared between the worker and status queries.
#[derive(Debug, Default)]
struct Counters {
    events_collected: AtomicU64,
    events_submitted: AtomicU64,
    submission_errors: AtomicU64,
}

/// Background telemetry worker that batches and submits events.
///
/// Created via [`TelemetryWorker::start`], which spawns the background
/// task and returns a [`TelemetryReporter`] handle for submitting events.
pub struct TelemetryWorker {
    config: TelemetryConfig,
    counters: Arc<Counters>,
    /// Handle to the background task — dropping it cancels the worker.
    _task: Option<tokio::task::JoinHandle<()>>,
    /// Shutdown signal sender.
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl TelemetryWorker {
    /// Starts the telemetry worker and returns a reporter handle.
    ///
    /// When telemetry is disabled, the worker is not spawned and the
    /// returned reporter silently drops all events.
    pub fn start(config: TelemetryConfig) -> (Self, TelemetryReporter) {
        let counters = Arc::new(Counters::default());

        if !config.enabled {
            info!("telemetry disabled, events will not be collected");
            let reporter = TelemetryReporter::disabled(config.deployment_id);
            return (
                Self {
                    config,
                    counters,
                    _task: None,
                    shutdown_tx: None,
                },
                reporter,
            );
        }

        let (event_tx, event_rx) = mpsc::channel(config.channel_capacity);
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
        let reporter = TelemetryReporter::new(Some(event_tx), config.deployment_id);

        let worker_config = config.clone();
        let worker_counters = counters.clone();

        let task = tokio::spawn(async move {
            run_worker(worker_config, worker_counters, event_rx, shutdown_rx).await;
        });

        info!(
            deployment_id = %config.deployment_id,
            flush_interval_secs = config.flush_interval.as_secs(),
            "telemetry worker started"
        );

        (
            Self {
                config,
                counters,
                _task: Some(task),
                shutdown_tx: Some(shutdown_tx),
            },
            reporter,
        )
    }

    /// Returns the current telemetry status.
    pub fn status(&self) -> TelemetryStatus {
        TelemetryStatus {
            enabled: self.config.enabled,
            deployment_id: self.config.deployment_id.to_string(),
            events_collected: self.counters.events_collected.load(Ordering::Relaxed),
            events_submitted: self.counters.events_submitted.load(Ordering::Relaxed),
            submission_errors: self.counters.submission_errors.load(Ordering::Relaxed),
        }
    }

    /// Signals the background worker to flush remaining events and stop.
    ///
    /// This should be called during the graceful shutdown sequence.
    pub async fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            // Signal shutdown — the worker will drain remaining events.
            drop(tx);
        }
        if let Some(task) = self._task.take() {
            if let Err(e) = task.await {
                warn!(error = %e, "telemetry worker task panicked during shutdown");
            }
        }
        info!("telemetry worker shut down");
    }
}

/// Core event loop: drain the channel, batch events, flush periodically.
async fn run_worker(
    config: TelemetryConfig,
    counters: Arc<Counters>,
    mut event_rx: mpsc::Receiver<TelemetryEvent>,
    mut shutdown_rx: mpsc::Receiver<()>,
) {
    let client = reqwest::Client::new();
    let mut buffer: Vec<TelemetryEvent> = Vec::with_capacity(config.max_batch_size);
    let mut flush_interval = tokio::time::interval(config.flush_interval);
    // The first tick completes immediately — skip it so we don't flush an
    // empty batch right at startup.
    flush_interval.tick().await;

    loop {
        tokio::select! {
            // Receive a new event.
            maybe_event = event_rx.recv() => {
                match maybe_event {
                    Some(event) => {
                        counters.events_collected.fetch_add(1, Ordering::Relaxed);
                        buffer.push(event);

                        // Force-flush when the buffer is full.
                        if buffer.len() >= config.max_batch_size {
                            flush_batch(&client, &config, &counters, &mut buffer).await;
                        }
                    }
                    None => {
                        // All senders dropped — drain and exit.
                        debug!("telemetry event channel closed, flushing remaining events");
                        flush_batch(&client, &config, &counters, &mut buffer).await;
                        return;
                    }
                }
            }

            // Periodic flush.
            _ = flush_interval.tick() => {
                if !buffer.is_empty() {
                    flush_batch(&client, &config, &counters, &mut buffer).await;
                }
            }

            // Shutdown signal.
            _ = shutdown_rx.recv() => {
                debug!("telemetry shutdown signal received, flushing remaining events");
                // Drain any remaining events from the channel.
                while let Ok(event) = event_rx.try_recv() {
                    counters.events_collected.fetch_add(1, Ordering::Relaxed);
                    buffer.push(event);
                }
                flush_batch(&client, &config, &counters, &mut buffer).await;
                return;
            }
        }
    }
}

/// Submits a batch of events to the telemetry endpoint.
async fn flush_batch(
    client: &reqwest::Client,
    config: &TelemetryConfig,
    counters: &Counters,
    buffer: &mut Vec<TelemetryEvent>,
) {
    if buffer.is_empty() {
        return;
    }

    let events: Vec<TelemetryEvent> = buffer.drain(..).collect();
    let count = events.len() as u64;

    let snapshot = TelemetrySnapshot {
        deployment_id: config.deployment_id.to_string(),
        version: config.version.clone(),
        events,
        created_at: time::OffsetDateTime::now_utc(),
    };

    let Some(ref endpoint) = config.endpoint else {
        // No endpoint configured — count as submitted (local-only mode).
        debug!(count, "telemetry batch flushed (no endpoint configured)");
        counters
            .events_submitted
            .fetch_add(count, Ordering::Relaxed);
        return;
    };

    match submit_snapshot(client, endpoint, &snapshot).await {
        Ok(()) => {
            debug!(count, "telemetry batch submitted successfully");
            counters
                .events_submitted
                .fetch_add(count, Ordering::Relaxed);
        }
        Err(e) => {
            warn!(error = %e, count, "failed to submit telemetry batch, re-queuing events");
            counters.submission_errors.fetch_add(1, Ordering::Relaxed);
            // Re-queue events so they are retried on the next flush cycle
            // instead of being permanently lost.  Respect the configured
            // buffer cap to prevent unbounded memory growth when the
            // endpoint is persistently unreachable.
            buffer.extend(snapshot.events);
            if buffer.len() > config.max_buffer_size {
                let excess = buffer.len() - config.max_buffer_size;
                warn!(
                    excess,
                    max_buffer_size = config.max_buffer_size,
                    "telemetry buffer exceeded cap, dropping oldest events"
                );
                buffer.drain(..excess);
            }
        }
    }
}

/// Sends a snapshot to the remote telemetry endpoint.
async fn submit_snapshot(
    client: &reqwest::Client,
    endpoint: &Url,
    snapshot: &TelemetrySnapshot,
) -> Result<(), reqwest::Error> {
    let resp = client
        .post(endpoint.as_str())
        .header("Content-Type", "application/json")
        .json(snapshot)
        .send()
        .await?;

    // Treat non-2xx as an error so that `flush_batch` increments
    // `submission_errors` and the events are correctly accounted for.
    let resp = resp.error_for_status()?;
    drop(resp);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::TelemetryEventKind;

    #[tokio::test]
    async fn disabled_worker_returns_disabled_reporter() {
        let config = TelemetryConfig {
            enabled: false,
            ..TelemetryConfig::default()
        };
        let (worker, reporter) = TelemetryWorker::start(config);
        assert!(!reporter.is_enabled());
        assert!(!worker.status().enabled);
    }

    #[tokio::test]
    async fn enabled_worker_collects_events() {
        let config = TelemetryConfig {
            enabled: true,
            deployment_id: Uuid::new_v4(),
            version: "test".to_owned(),
            endpoint: None,
            flush_interval: Duration::from_millis(50),
            max_batch_size: 10,
            channel_capacity: 64,
            max_buffer_size: 8192,
        };
        let (mut worker, reporter) = TelemetryWorker::start(config);
        assert!(reporter.is_enabled());

        // Send a few events.
        for _ in 0..3 {
            reporter.report(TelemetryEvent::new(
                TelemetryEventKind::UserLogin,
                None,
                None,
            ));
        }

        // Give the worker time to process.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let status = worker.status();
        assert!(status.enabled);
        assert!(status.events_collected >= 3);

        worker.shutdown().await;
    }

    #[tokio::test]
    async fn worker_shutdown_flushes_remaining() {
        let config = TelemetryConfig {
            enabled: true,
            deployment_id: Uuid::new_v4(),
            version: "test".to_owned(),
            endpoint: None,
            // Long interval so periodic flush doesn't trigger.
            flush_interval: Duration::from_secs(3600),
            max_batch_size: 1000,
            channel_capacity: 64,
            max_buffer_size: 8192,
        };
        let (mut worker, reporter) = TelemetryWorker::start(config);

        reporter.report(TelemetryEvent::new(
            TelemetryEventKind::WorkspaceCreated,
            None,
            None,
        ));

        // Shutdown should drain remaining events.
        worker.shutdown().await;

        let status = worker.status();
        assert!(status.events_collected >= 1);
        // Without an endpoint, events are counted as submitted.
        assert!(status.events_submitted >= 1);
    }

    #[test]
    fn default_config_is_disabled() {
        let config = TelemetryConfig::default();
        assert!(!config.enabled);
        assert!(config.endpoint.is_none());
    }

    #[tokio::test]
    async fn batch_flush_on_max_size() {
        let config = TelemetryConfig {
            enabled: true,
            deployment_id: Uuid::new_v4(),
            version: "test".to_owned(),
            endpoint: None,
            flush_interval: Duration::from_secs(3600),
            max_batch_size: 5,
            channel_capacity: 64,
            max_buffer_size: 8192,
        };
        let (mut worker, reporter) = TelemetryWorker::start(config);

        // Send exactly max_batch_size events to trigger a flush.
        for _ in 0..5 {
            reporter.report(TelemetryEvent::new(
                TelemetryEventKind::ApiKeyCreated,
                None,
                None,
            ));
        }

        // Give worker time to process.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let status = worker.status();
        assert!(status.events_collected >= 5);
        assert!(status.events_submitted >= 5);

        worker.shutdown().await;
    }
}
