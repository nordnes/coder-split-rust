//! Workspace agent connectivity layer.
//!
//! Provides the [`AgentProvider`] trait for tracking live agent connections and
//! the [`InMemoryAgentProvider`] default implementation backed by a `Mutex<HashMap>`.

use std::{collections::HashMap, fmt, sync::Arc};

use async_trait::async_trait;
use thiserror::Error;
use time::OffsetDateTime;
use tokio::sync::Mutex;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors returned when sending commands to a connected workspace agent.
#[derive(Debug, Error)]
pub enum AgentError {
    /// The agent is not currently connected.
    #[error("agent is not connected")]
    NotConnected,
    /// The command could not be delivered to the agent.
    #[error("failed to send command to agent: {0}")]
    SendFailed(String),
    /// The agent returned an error for the command.
    #[error("agent returned error: {0}")]
    AgentRejected(String),
}

// ---------------------------------------------------------------------------
// Traits
// ---------------------------------------------------------------------------

/// Debug snapshot of one connected agent.
#[derive(Clone, Debug)]
pub struct AgentConnectionInfo {
    /// Unique agent identifier.
    pub agent_id: Uuid,
    /// When the agent connected.
    pub connected_at: OffsetDateTime,
}

/// A live connection to a single workspace agent.
///
/// Implementations are responsible for delivering commands to the agent and
/// surfacing errors when delivery fails.
#[async_trait]
pub trait AgentConnection: Send + Sync + fmt::Debug {
    /// Sends a recreate-devcontainer command to the agent.
    async fn recreate_devcontainer(&self, container_id: &str) -> Result<(), AgentError>;

    /// Sends a delete-devcontainer command to the agent.
    async fn delete_devcontainer(&self, container_id: &str) -> Result<(), AgentError>;

    /// Returns the agent identifier for this connection.
    fn agent_id(&self) -> Uuid;

    /// Returns the time this connection was established.
    fn connected_at(&self) -> OffsetDateTime;
}

/// Registry of live workspace agent connections.
///
/// The server uses this to look up agent connections when handlers need to
/// send real-time commands (e.g. recreate / delete devcontainer).
#[async_trait]
pub trait AgentProvider: Send + Sync {
    /// Returns the active connection for `agent_id`, if one exists.
    async fn get_agent_connection(&self, agent_id: Uuid) -> Option<Arc<dyn AgentConnection>>;

    /// Registers a new agent connection. Replaces any previous connection for
    /// the same agent.
    async fn register_agent(&self, agent_id: Uuid, conn: Arc<dyn AgentConnection>);

    /// Removes the connection for `agent_id`, but only if `conn` is still the
    /// currently registered connection (compared by `Arc` pointer equality).
    /// This prevents a disconnecting task from removing a newer connection
    /// that was registered by a reconnecting agent.
    async fn remove_agent(&self, agent_id: Uuid, conn: &Arc<dyn AgentConnection>);

    /// Returns debug info about all currently connected agents.
    async fn debug_info(&self) -> Vec<AgentConnectionInfo>;
}

// ---------------------------------------------------------------------------
// InMemoryAgentProvider
// ---------------------------------------------------------------------------

/// In-memory [`AgentProvider`] backed by a `Mutex<HashMap>`.
///
/// This is the default implementation used by the server. It stores agent
/// connections in memory and is suitable for single-instance deployments.
#[derive(Debug, Default)]
pub struct InMemoryAgentProvider {
    agents: Mutex<HashMap<Uuid, Arc<dyn AgentConnection>>>,
}

impl InMemoryAgentProvider {
    /// Creates a new empty provider.
    #[must_use]
    pub fn new() -> Self {
        Self {
            agents: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl AgentProvider for InMemoryAgentProvider {
    async fn get_agent_connection(&self, agent_id: Uuid) -> Option<Arc<dyn AgentConnection>> {
        self.agents.lock().await.get(&agent_id).cloned()
    }

    async fn register_agent(&self, agent_id: Uuid, conn: Arc<dyn AgentConnection>) {
        self.agents.lock().await.insert(agent_id, conn);
    }

    async fn remove_agent(&self, agent_id: Uuid, conn: &Arc<dyn AgentConnection>) {
        let mut agents = self.agents.lock().await;
        if let Some(current) = agents.get(&agent_id) {
            if Arc::ptr_eq(current, conn) {
                agents.remove(&agent_id);
            }
        }
    }

    async fn debug_info(&self) -> Vec<AgentConnectionInfo> {
        self.agents
            .lock()
            .await
            .values()
            .map(|conn| AgentConnectionInfo {
                agent_id: conn.agent_id(),
                connected_at: conn.connected_at(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal agent connection for unit tests.
    #[derive(Debug)]
    struct StubConnection {
        id: Uuid,
        connected: OffsetDateTime,
    }

    #[async_trait]
    impl AgentConnection for StubConnection {
        async fn recreate_devcontainer(&self, _container_id: &str) -> Result<(), AgentError> {
            Ok(())
        }

        async fn delete_devcontainer(&self, _container_id: &str) -> Result<(), AgentError> {
            Ok(())
        }

        fn agent_id(&self) -> Uuid {
            self.id
        }

        fn connected_at(&self) -> OffsetDateTime {
            self.connected
        }
    }

    #[tokio::test]
    async fn register_and_lookup() {
        let provider = InMemoryAgentProvider::new();
        let agent_id = Uuid::new_v4();
        let conn: Arc<dyn AgentConnection> = Arc::new(StubConnection {
            id: agent_id,
            connected: OffsetDateTime::now_utc(),
        });

        assert!(provider.get_agent_connection(agent_id).await.is_none());

        provider.register_agent(agent_id, conn).await;
        let found = provider.get_agent_connection(agent_id).await;
        assert!(found.is_some());
        assert_eq!(found.as_ref().map(|c| c.agent_id()), Some(agent_id));
    }

    #[tokio::test]
    async fn remove_agent_clears_connection() {
        let provider = InMemoryAgentProvider::new();
        let agent_id = Uuid::new_v4();
        let conn: Arc<dyn AgentConnection> = Arc::new(StubConnection {
            id: agent_id,
            connected: OffsetDateTime::now_utc(),
        });

        provider.register_agent(agent_id, conn.clone()).await;
        assert!(provider.get_agent_connection(agent_id).await.is_some());

        provider.remove_agent(agent_id, &conn).await;
        assert!(provider.get_agent_connection(agent_id).await.is_none());
    }

    #[tokio::test]
    async fn remove_agent_skips_newer_connection() {
        let provider = InMemoryAgentProvider::new();
        let agent_id = Uuid::new_v4();

        // Simulate first connection.
        let conn_old: Arc<dyn AgentConnection> = Arc::new(StubConnection {
            id: agent_id,
            connected: OffsetDateTime::now_utc(),
        });
        provider.register_agent(agent_id, conn_old.clone()).await;

        // Simulate reconnection — replaces old connection.
        let conn_new: Arc<dyn AgentConnection> = Arc::new(StubConnection {
            id: agent_id,
            connected: OffsetDateTime::now_utc(),
        });
        provider.register_agent(agent_id, conn_new).await;

        // Old task tries to clean up — should NOT remove the new connection.
        provider.remove_agent(agent_id, &conn_old).await;
        assert!(
            provider.get_agent_connection(agent_id).await.is_some(),
            "new connection should survive old task cleanup"
        );
    }

    #[tokio::test]
    async fn debug_info_lists_all() {
        let provider = InMemoryAgentProvider::new();
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();

        provider
            .register_agent(
                id1,
                Arc::new(StubConnection {
                    id: id1,
                    connected: OffsetDateTime::now_utc(),
                }),
            )
            .await;
        provider
            .register_agent(
                id2,
                Arc::new(StubConnection {
                    id: id2,
                    connected: OffsetDateTime::now_utc(),
                }),
            )
            .await;

        let info = provider.debug_info().await;
        assert_eq!(info.len(), 2);
        for id in [id1, id2] {
            assert!(
                info.iter().any(|i| i.agent_id == id),
                "expected agent {id} in debug_info"
            );
        }
    }
}
