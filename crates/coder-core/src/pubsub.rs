//! Pub/Sub traits, in-memory implementation, and workspace event channel helpers.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{Mutex, broadcast};
use uuid::Uuid;

/// Buffer size for internal broadcast channels.
///
/// Matches the Go implementation's `BufferSize = 2048`.
const BROADCAST_CAPACITY: usize = 2048;

/// Errors surfaced by pub/sub operations.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PubSubError {
    /// The pub/sub backend is unavailable or encountered an error.
    #[error("pubsub unavailable: {message}")]
    Unavailable { message: String },
    /// The pub/sub system has been closed.
    #[error("pubsub closed")]
    Closed,
}

impl PubSubError {
    /// Creates an availability error.
    #[must_use]
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::Unavailable {
            message: message.into(),
        }
    }
}

/// A subscription to a pub/sub channel.
///
/// Messages are received via the [`recv`](Subscription::recv) method.
/// Dropping the subscription automatically unsubscribes.
pub struct Subscription {
    receiver: broadcast::Receiver<Vec<u8>>,
}

impl Subscription {
    /// Creates a new subscription wrapping a broadcast receiver.
    #[must_use]
    pub fn new(receiver: broadcast::Receiver<Vec<u8>>) -> Self {
        Self { receiver }
    }

    /// Waits for the next message on this subscription.
    ///
    /// If messages were dropped because the subscriber fell behind, the lagged
    /// messages are silently skipped (matching Go behaviour where
    /// `ErrDroppedMessages` is recorded but the listener continues).
    pub async fn recv(&mut self) -> Result<Vec<u8>, PubSubError> {
        loop {
            match self.receiver.recv().await {
                Ok(msg) => return Ok(msg),
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    // The receiver fell behind; skip lost messages and retry.
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => {
                    return Err(PubSubError::Closed);
                }
            }
        }
    }
}

/// Generic interface for broadcasting and receiving messages.
///
/// Implementations should assume high-availability with the backing store.
/// The PostgreSQL variant uses `LISTEN`/`NOTIFY`; the in-memory variant is
/// provided for unit tests.
#[async_trait]
pub trait PubSub: Send + Sync {
    /// Subscribes to events on the named channel.
    ///
    /// Returns a [`Subscription`] whose [`recv`](Subscription::recv) method
    /// yields each published message.  Dropping the subscription cancels it.
    async fn subscribe(&self, channel: &str) -> Result<Subscription, PubSubError>;

    /// Publishes a message to every active subscriber of the named channel.
    async fn publish(&self, channel: &str, message: &[u8]) -> Result<(), PubSubError>;

    /// Shuts down the pub/sub system, releasing all resources.
    async fn close(&self) -> Result<(), PubSubError>;
}

// ---------------------------------------------------------------------------
// In-memory implementation (for tests)
// ---------------------------------------------------------------------------

/// Internal state for [`InMemoryPubSub`], protected by a single mutex to
/// prevent TOCTOU races between the `closed` flag and `channels` map.
struct InMemoryPubSubInner {
    closed: bool,
    channels: HashMap<String, broadcast::Sender<Vec<u8>>>,
}

/// In-memory [`PubSub`] implementation backed by `tokio::sync::broadcast`
/// channels.
///
/// This is an exported type so that test code in downstream crates can
/// construct it directly.
pub struct InMemoryPubSub {
    inner: Arc<Mutex<InMemoryPubSubInner>>,
}

impl InMemoryPubSub {
    /// Creates a new in-memory pub/sub instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(InMemoryPubSubInner {
                closed: false,
                channels: HashMap::new(),
            })),
        }
    }

    /// Returns an existing sender for the channel or creates a new one.
    fn get_or_create_sender(
        channels: &mut HashMap<String, broadcast::Sender<Vec<u8>>>,
        channel: &str,
    ) -> broadcast::Sender<Vec<u8>> {
        channels
            .entry(channel.to_owned())
            .or_insert_with(|| broadcast::channel(BROADCAST_CAPACITY).0)
            .clone()
    }
}

impl Default for InMemoryPubSub {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PubSub for InMemoryPubSub {
    async fn subscribe(&self, channel: &str) -> Result<Subscription, PubSubError> {
        let mut inner = self.inner.lock().await;
        if inner.closed {
            return Err(PubSubError::Closed);
        }
        let sender = Self::get_or_create_sender(&mut inner.channels, channel);
        Ok(Subscription::new(sender.subscribe()))
    }

    async fn publish(&self, channel: &str, message: &[u8]) -> Result<(), PubSubError> {
        let mut inner = self.inner.lock().await;
        if inner.closed {
            return Err(PubSubError::Closed);
        }
        let sender = Self::get_or_create_sender(&mut inner.channels, channel);
        // It is fine if there are currently no receivers.
        let _ = sender.send(message.to_vec());
        Ok(())
    }

    async fn close(&self) -> Result<(), PubSubError> {
        let mut inner = self.inner.lock().await;
        if inner.closed {
            return Ok(());
        }
        inner.closed = true;
        inner.channels.clear();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Workspace-specific event channels
// ---------------------------------------------------------------------------

/// Returns the pub/sub channel name for workspace events owned by the given
/// user.
///
/// Mirrors the Go `wspubsub.WorkspaceEventChannel(ownerID)` function.
#[must_use]
pub fn workspace_event_channel(owner_id: Uuid) -> String {
    format!("workspace_owner:{owner_id}")
}

/// Returns the pub/sub channel name for a specific workspace agent.
#[must_use]
pub fn workspace_agent_channel(agent_id: Uuid) -> String {
    format!("workspace_agent:{agent_id}")
}

/// Returns the pub/sub channel name for build-log streaming.
#[must_use]
pub fn workspace_build_logs_channel(build_id: Uuid) -> String {
    format!("workspace_build_logs:{build_id}")
}

/// Returns the pub/sub channel name for workspace agent log streaming.
#[must_use]
pub fn workspace_agent_logs_channel(agent_id: Uuid) -> String {
    format!("workspace_agent_logs:{agent_id}")
}

/// Returns the pub/sub channel name for workspace agent reinit events.
#[must_use]
pub fn workspace_agent_reinit_channel(agent_id: Uuid) -> String {
    format!("workspace_agent_reinit:{agent_id}")
}

/// The kind of workspace event broadcast over the pub/sub channel.
///
/// String representations match the Go `wspubsub.WorkspaceEventKind` constants.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkspaceEventKind {
    /// Workspace transitioned to a new state.
    #[serde(rename = "state_change")]
    StateChange,
    /// Workspace stats were updated.
    #[serde(rename = "stats_update")]
    StatsUpdate,
    /// Workspace metadata was updated.
    #[serde(rename = "mtd_update")]
    MetadataUpdate,
    /// Application health status changed.
    #[serde(rename = "app_health")]
    AppHealthUpdate,
    /// Agent lifecycle event.
    #[serde(rename = "agt_lifecycle_update")]
    AgentLifecycleUpdate,
    /// Agent connection status changed.
    #[serde(rename = "agt_connection_update")]
    AgentConnectionUpdate,
    /// Agent produced its first logs.
    #[serde(rename = "agt_first_logs")]
    AgentFirstLogs,
    /// Agent log buffer overflowed.
    #[serde(rename = "agt_logs_overflow")]
    AgentLogsOverflow,
    /// Agent timed out.
    #[serde(rename = "agt_timeout")]
    AgentTimeout,
    /// Agent app status was updated.
    #[serde(rename = "agt_app_status_update")]
    AgentAppStatusUpdate,
}

/// A workspace pub/sub event payload.
///
/// Mirrors the Go `wspubsub.WorkspaceEvent` struct.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceEvent {
    /// The kind of event.
    pub kind: WorkspaceEventKind,
    /// Target workspace identifier.
    pub workspace_id: Uuid,
    /// Agent identifier – only set for agent-specific events (excluding
    /// [`AgentTimeout`](WorkspaceEventKind::AgentTimeout)).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<Uuid>,
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[tokio::test]
    async fn in_memory_subscribe_publish_receive() -> TestResult {
        let ps = InMemoryPubSub::new();
        let mut sub = ps.subscribe("test-channel").await?;

        let message = b"hello world";
        ps.publish("test-channel", message).await?;

        let received = sub.recv().await?;
        assert_eq!(received, message);
        Ok(())
    }

    #[tokio::test]
    async fn in_memory_multiple_subscribers() -> TestResult {
        let ps = InMemoryPubSub::new();
        let mut sub1 = ps.subscribe("chan").await?;
        let mut sub2 = ps.subscribe("chan").await?;

        ps.publish("chan", b"msg").await?;

        let r1 = sub1.recv().await?;
        let r2 = sub2.recv().await?;
        assert_eq!(r1, b"msg");
        assert_eq!(r2, b"msg");
        Ok(())
    }

    #[tokio::test]
    async fn in_memory_different_channels_isolated() -> TestResult {
        let ps = InMemoryPubSub::new();
        let mut sub_a = ps.subscribe("chan-a").await?;

        ps.publish("chan-b", b"only-b").await?;
        ps.publish("chan-a", b"only-a").await?;

        let received = sub_a.recv().await?;
        assert_eq!(received, b"only-a");
        Ok(())
    }

    #[tokio::test]
    async fn in_memory_close_prevents_further_operations() -> TestResult {
        let ps = InMemoryPubSub::new();
        ps.close().await?;

        let result = ps.subscribe("chan").await;
        assert_eq!(result.err(), Some(PubSubError::Closed));

        let result = ps.publish("chan", b"msg").await;
        assert_eq!(result.err(), Some(PubSubError::Closed));
        Ok(())
    }

    #[tokio::test]
    async fn in_memory_close_terminates_subscription() -> TestResult {
        let ps = Arc::new(InMemoryPubSub::new());
        let mut sub = ps.subscribe("chan").await?;

        ps.close().await?;

        let result = sub.recv().await;
        assert_eq!(result.err(), Some(PubSubError::Closed));
        Ok(())
    }

    #[tokio::test]
    async fn workspace_channel_names() {
        let id = Uuid::nil();
        assert_eq!(
            workspace_event_channel(id),
            "workspace_owner:00000000-0000-0000-0000-000000000000"
        );
        assert_eq!(
            workspace_agent_channel(id),
            "workspace_agent:00000000-0000-0000-0000-000000000000"
        );
        assert_eq!(
            workspace_build_logs_channel(id),
            "workspace_build_logs:00000000-0000-0000-0000-000000000000"
        );
        assert_eq!(
            workspace_agent_logs_channel(id),
            "workspace_agent_logs:00000000-0000-0000-0000-000000000000"
        );
        assert_eq!(
            workspace_agent_reinit_channel(id),
            "workspace_agent_reinit:00000000-0000-0000-0000-000000000000"
        );
    }

    #[test]
    fn workspace_event_serde_roundtrip() -> TestResult {
        let event = WorkspaceEvent {
            kind: WorkspaceEventKind::StateChange,
            workspace_id: Uuid::nil(),
            agent_id: None,
        };

        let json = serde_json::to_string(&event)?;
        let parsed: WorkspaceEvent = serde_json::from_str(&json)?;
        assert_eq!(event, parsed);

        // agent_id should be omitted when None
        assert!(!json.contains("agent_id"));
        Ok(())
    }

    #[test]
    fn workspace_event_kind_string_values() -> TestResult {
        let event = WorkspaceEvent {
            kind: WorkspaceEventKind::AgentLifecycleUpdate,
            workspace_id: Uuid::nil(),
            agent_id: Some(Uuid::from_u128(42)),
        };

        let json = serde_json::to_string(&event)?;
        assert!(json.contains("agt_lifecycle_update"));
        assert!(json.contains("agent_id"));
        Ok(())
    }
}
