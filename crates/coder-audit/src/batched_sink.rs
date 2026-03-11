//! Batched audit event sink inspired by Zed's `AdaptiveBatcher` pattern.
//!
//! Callers fire-and-forget via an unbounded channel.  A background task
//! collects events and flushes them in batches — either when the batch
//! reaches `max_batch_size` or after `flush_interval` elapses,
//! whichever comes first.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::{AuditEvent, AuditSink};

/// Fire-and-forget audit sink backed by an internal buffer and a
/// background flush task.
pub struct BatchedAuditSink {
    /// Send side of the unbounded event channel.
    tx: mpsc::UnboundedSender<AuditEvent>,
    /// Handle to the background flush task (kept alive via ownership).
    _flush_task: JoinHandle<()>,
}

impl BatchedAuditSink {
    /// Creates the batched sink wrapping an inner `AuditSink` that
    /// receives flushed batches.
    pub fn new(inner: Arc<dyn AuditSink>, flush_interval: Duration, max_batch_size: usize) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let flush_task = tokio::spawn(flush_loop(rx, inner, flush_interval, max_batch_size));

        Self {
            tx,
            _flush_task: flush_task,
        }
    }
}

#[async_trait]
impl AuditSink for BatchedAuditSink {
    async fn record(&self, event: AuditEvent) {
        // Fire-and-forget: if the channel is closed the event is dropped
        // (server is shutting down).
        if self.tx.send(event).is_err() {
            warn!("batched audit sink channel closed, event dropped");
        }
    }
}

/// Background loop that drains the channel and flushes in batches.
async fn flush_loop(
    mut rx: mpsc::UnboundedReceiver<AuditEvent>,
    inner: Arc<dyn AuditSink>,
    flush_interval: Duration,
    max_batch_size: usize,
) {
    let mut batch: Vec<AuditEvent> = Vec::with_capacity(max_batch_size);

    loop {
        // Wait for the first event or channel closure.
        tokio::select! {
            maybe_event = rx.recv() => {
                match maybe_event {
                    Some(event) => batch.push(event),
                    None => {
                        // Channel closed — flush remaining and exit.
                        flush_batch(&inner, &mut batch).await;
                        return;
                    }
                }
            }
        }

        // Drain any immediately-available events up to the batch limit.
        while batch.len() < max_batch_size {
            match rx.try_recv() {
                Ok(event) => batch.push(event),
                Err(_) => break,
            }
        }

        // If the batch is full, flush immediately.
        if batch.len() >= max_batch_size {
            flush_batch(&inner, &mut batch).await;
            continue;
        }

        // Otherwise, wait for the flush interval or more events.
        let deadline = tokio::time::sleep(flush_interval);
        tokio::pin!(deadline);

        loop {
            tokio::select! {
                _ = &mut deadline => {
                    // Timer expired — flush what we have.
                    flush_batch(&inner, &mut batch).await;
                    break;
                }
                maybe_event = rx.recv() => {
                    match maybe_event {
                        Some(event) => {
                            batch.push(event);
                            if batch.len() >= max_batch_size {
                                flush_batch(&inner, &mut batch).await;
                                break;
                            }
                        }
                        None => {
                            // Channel closed — flush and exit.
                            flush_batch(&inner, &mut batch).await;
                            return;
                        }
                    }
                }
            }
        }
    }
}

/// Flushes the current batch by forwarding all events to the inner sink's
/// [`record_batch`](AuditSink::record_batch) method so that implementors
/// with a bulk INSERT path (e.g. `batch_insert_audit_logs`) can persist
/// the entire batch in a single round-trip.
async fn flush_batch(inner: &Arc<dyn AuditSink>, batch: &mut Vec<AuditEvent>) {
    if batch.is_empty() {
        return;
    }

    let count = batch.len();
    info!(count, "flushing batched audit events");

    let events: Vec<AuditEvent> = std::mem::take(batch);
    inner.record_batch(events).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AuditAction;
    use coder_rbac::ResourceKind;
    use std::sync::Mutex;
    use uuid::Uuid;

    struct CollectingSink {
        events: Mutex<Vec<AuditEvent>>,
    }

    impl CollectingSink {
        fn new() -> Self {
            Self {
                events: Mutex::new(Vec::new()),
            }
        }

        fn collected(&self) -> Vec<AuditEvent> {
            self.events
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone()
        }
    }

    #[async_trait]
    impl AuditSink for CollectingSink {
        async fn record(&self, event: AuditEvent) {
            self.events
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(event);
        }
    }

    fn make_event(action: AuditAction) -> AuditEvent {
        AuditEvent {
            action,
            resource: ResourceKind::User,
            actor_user_id: Some(Uuid::new_v4()),
            target_id: None,
            summary: format!("test: {}", action.as_str()),
        }
    }

    #[tokio::test]
    async fn batched_sink_flushes_on_interval() {
        let inner = Arc::new(CollectingSink::new());
        let sink = BatchedAuditSink::new(
            Arc::clone(&inner) as Arc<dyn AuditSink>,
            Duration::from_millis(50),
            100,
        );

        sink.record(make_event(AuditAction::Login)).await;
        sink.record(make_event(AuditAction::Create)).await;

        // Wait for the flush interval to trigger.
        tokio::time::sleep(Duration::from_millis(200)).await;

        let collected = inner.collected();
        assert_eq!(collected.len(), 2);
    }

    #[tokio::test]
    async fn batched_sink_flushes_on_batch_size() {
        let inner = Arc::new(CollectingSink::new());
        let sink = BatchedAuditSink::new(
            Arc::clone(&inner) as Arc<dyn AuditSink>,
            Duration::from_secs(60), // very long interval
            3,                       // small batch
        );

        for _ in 0..3 {
            sink.record(make_event(AuditAction::Write)).await;
        }

        // Give the background task a moment to flush.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let collected = inner.collected();
        assert_eq!(collected.len(), 3);
    }

    #[tokio::test]
    async fn batched_sink_flushes_on_drop() {
        let inner = Arc::new(CollectingSink::new());
        let sink = BatchedAuditSink::new(
            Arc::clone(&inner) as Arc<dyn AuditSink>,
            Duration::from_secs(60),
            100,
        );

        sink.record(make_event(AuditAction::Delete)).await;

        // Drop the sender side to trigger channel closure.
        drop(sink);

        // Give the flush task time to drain.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let collected = inner.collected();
        assert_eq!(collected.len(), 1);
    }
}
