//! Workspace agent connectivity layer.
//!
//! Provides the [`AgentProvider`] trait for tracking live agent connections and
//! the [`InMemoryAgentProvider`] default implementation backed by a `Mutex<HashMap>`.

use std::{collections::HashMap, fmt, sync::Arc};

use async_trait::async_trait;
use coder_core::WorkspaceAgentListeningPort;
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

    /// Stores the latest set of listening ports reported by an agent.
    ///
    /// Replaces any previously stored ports for the given agent.
    async fn set_listening_ports(&self, agent_id: Uuid, ports: Vec<WorkspaceAgentListeningPort>);

    /// Returns the listening ports most recently reported by the given agent.
    ///
    /// Returns an empty vector if the agent has not reported any ports.
    async fn get_listening_ports(&self, agent_id: Uuid) -> Vec<WorkspaceAgentListeningPort>;
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
    listening_ports: Mutex<HashMap<Uuid, Vec<WorkspaceAgentListeningPort>>>,
}

impl InMemoryAgentProvider {
    /// Creates a new empty provider.
    #[must_use]
    pub fn new() -> Self {
        Self {
            agents: Mutex::new(HashMap::new()),
            listening_ports: Mutex::new(HashMap::new()),
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
        // Clear any stale listening-port data from a previous connection so the
        // endpoint doesn't serve outdated ports until the new agent reports.
        self.listening_ports.lock().await.remove(&agent_id);
    }

    async fn remove_agent(&self, agent_id: Uuid, conn: &Arc<dyn AgentConnection>) {
        let mut agents = self.agents.lock().await;
        if let Some(current) = agents.get(&agent_id) {
            if Arc::ptr_eq(current, conn) {
                agents.remove(&agent_id);
                // Also clear stale listening-port data for the disconnected agent.
                self.listening_ports.lock().await.remove(&agent_id);
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

    async fn set_listening_ports(&self, agent_id: Uuid, ports: Vec<WorkspaceAgentListeningPort>) {
        self.listening_ports.lock().await.insert(agent_id, ports);
    }

    async fn get_listening_ports(&self, agent_id: Uuid) -> Vec<WorkspaceAgentListeningPort> {
        self.listening_ports
            .lock()
            .await
            .get(&agent_id)
            .cloned()
            .unwrap_or_default()
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

    // ── Empty provider edge cases ───────────────────────────

    #[tokio::test]
    async fn empty_provider_returns_none() {
        let provider = InMemoryAgentProvider::new();
        assert!(
            provider
                .get_agent_connection(Uuid::new_v4())
                .await
                .is_none(),
            "empty provider should return None for any ID"
        );
    }

    #[tokio::test]
    async fn empty_provider_debug_info_is_empty() {
        let provider = InMemoryAgentProvider::new();
        let info = provider.debug_info().await;
        assert!(info.is_empty(), "empty provider should have no debug info");
    }

    // ── Nil UUID agent ──────────────────────────────────────

    #[tokio::test]
    async fn register_and_lookup_nil_uuid() {
        let provider = InMemoryAgentProvider::new();
        let nil_id = Uuid::nil();
        let conn: Arc<dyn AgentConnection> = Arc::new(StubConnection {
            id: nil_id,
            connected: OffsetDateTime::now_utc(),
        });
        provider.register_agent(nil_id, conn).await;
        let found = provider.get_agent_connection(nil_id).await;
        assert!(found.is_some(), "nil UUID should be a valid agent ID");
        assert_eq!(found.as_ref().map(|c| c.agent_id()), Some(nil_id));
    }

    // ── Replace connection for same agent ───────────────────

    #[tokio::test]
    async fn register_replaces_existing_connection() {
        let provider = InMemoryAgentProvider::new();
        let agent_id = Uuid::new_v4();
        let t1 = OffsetDateTime::now_utc() - time::Duration::seconds(10);
        let t2 = OffsetDateTime::now_utc();

        let conn1: Arc<dyn AgentConnection> = Arc::new(StubConnection {
            id: agent_id,
            connected: t1,
        });
        let conn2: Arc<dyn AgentConnection> = Arc::new(StubConnection {
            id: agent_id,
            connected: t2,
        });

        provider.register_agent(agent_id, conn1).await;
        provider.register_agent(agent_id, conn2).await;

        let found = provider.get_agent_connection(agent_id).await;
        assert!(found.is_some());
        // The connection should be the newer one.
        assert_eq!(
            found.as_ref().map(|c| c.connected_at()),
            Some(t2),
            "second registration should replace first"
        );

        // Only one entry in debug_info.
        let info = provider.debug_info().await;
        assert_eq!(info.len(), 1);
    }

    // ── Remove non-existent agent is a no-op ────────────────

    #[tokio::test]
    async fn remove_nonexistent_agent_is_noop() {
        let provider = InMemoryAgentProvider::new();
        let agent_id = Uuid::new_v4();
        let conn: Arc<dyn AgentConnection> = Arc::new(StubConnection {
            id: agent_id,
            connected: OffsetDateTime::now_utc(),
        });
        // Remove without registering should not panic.
        provider.remove_agent(agent_id, &conn).await;
        assert!(provider.get_agent_connection(agent_id).await.is_none());
    }

    // ── AgentError display messages ─────────────────────────

    #[test]
    fn agent_error_not_connected_display() {
        let err = AgentError::NotConnected;
        assert_eq!(err.to_string(), "agent is not connected");
    }

    #[test]
    fn agent_error_send_failed_display() {
        let err = AgentError::SendFailed("timeout".to_owned());
        assert!(err.to_string().contains("timeout"));
        assert!(err.to_string().contains("failed to send command"));
    }

    #[test]
    fn agent_error_rejected_display() {
        let err = AgentError::AgentRejected("not supported".to_owned());
        assert!(err.to_string().contains("not supported"));
    }

    // ── StubConnection operations ───────────────────────────

    #[tokio::test]
    async fn stub_connection_recreate_devcontainer_ok() {
        let conn = StubConnection {
            id: Uuid::new_v4(),
            connected: OffsetDateTime::now_utc(),
        };
        let result = conn.recreate_devcontainer("container-123").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn stub_connection_delete_devcontainer_ok() {
        let conn = StubConnection {
            id: Uuid::new_v4(),
            connected: OffsetDateTime::now_utc(),
        };
        let result = conn.delete_devcontainer("container-456").await;
        assert!(result.is_ok());
    }

    // ── AgentConnectionInfo preserves fields ────────────────

    #[test]
    fn agent_connection_info_clone_and_debug() {
        let info = AgentConnectionInfo {
            agent_id: Uuid::new_v4(),
            connected_at: OffsetDateTime::now_utc(),
        };
        let cloned = info.clone();
        assert_eq!(info.agent_id, cloned.agent_id);
        assert_eq!(info.connected_at, cloned.connected_at);
        let debug = format!("{info:?}");
        assert!(debug.contains("AgentConnectionInfo"));
    }

    // ── Listening port storage ─────────────────────────────

    #[tokio::test]
    async fn get_listening_ports_empty_by_default() {
        let provider = InMemoryAgentProvider::new();
        let ports = provider.get_listening_ports(Uuid::new_v4()).await;
        assert!(ports.is_empty(), "no ports should be stored initially");
    }

    #[tokio::test]
    async fn set_and_get_listening_ports() {
        let provider = InMemoryAgentProvider::new();
        let agent_id = Uuid::new_v4();

        let ports = vec![
            WorkspaceAgentListeningPort {
                port: 8080,
                network: "tcp".to_owned(),
                process_name: "node".to_owned(),
            },
            WorkspaceAgentListeningPort {
                port: 3000,
                network: "tcp".to_owned(),
                process_name: String::new(),
            },
        ];
        provider.set_listening_ports(agent_id, ports.clone()).await;

        let retrieved = provider.get_listening_ports(agent_id).await;
        assert_eq!(retrieved, ports);
    }

    #[tokio::test]
    async fn set_listening_ports_replaces_previous() {
        let provider = InMemoryAgentProvider::new();
        let agent_id = Uuid::new_v4();

        let ports_v1 = vec![WorkspaceAgentListeningPort {
            port: 8080,
            network: "tcp".to_owned(),
            process_name: "old".to_owned(),
        }];
        provider.set_listening_ports(agent_id, ports_v1).await;

        let ports_v2 = vec![WorkspaceAgentListeningPort {
            port: 9090,
            network: "udp".to_owned(),
            process_name: "new".to_owned(),
        }];
        provider
            .set_listening_ports(agent_id, ports_v2.clone())
            .await;

        let retrieved = provider.get_listening_ports(agent_id).await;
        assert_eq!(retrieved, ports_v2, "new report should replace old");
    }

    #[tokio::test]
    async fn remove_agent_clears_listening_ports() {
        let provider = InMemoryAgentProvider::new();
        let agent_id = Uuid::new_v4();
        let conn: Arc<dyn AgentConnection> = Arc::new(StubConnection {
            id: agent_id,
            connected: OffsetDateTime::now_utc(),
        });

        provider.register_agent(agent_id, conn.clone()).await;
        provider
            .set_listening_ports(
                agent_id,
                vec![WorkspaceAgentListeningPort {
                    port: 8080,
                    network: "tcp".to_owned(),
                    process_name: String::new(),
                }],
            )
            .await;

        provider.remove_agent(agent_id, &conn).await;

        let ports = provider.get_listening_ports(agent_id).await;
        assert!(
            ports.is_empty(),
            "ports should be cleared when agent is removed"
        );
    }

    #[tokio::test]
    async fn register_agent_clears_stale_listening_ports() {
        let provider = InMemoryAgentProvider::new();
        let agent_id = Uuid::new_v4();
        let conn_old: Arc<dyn AgentConnection> = Arc::new(StubConnection {
            id: agent_id,
            connected: OffsetDateTime::now_utc(),
        });

        provider.register_agent(agent_id, conn_old).await;
        provider
            .set_listening_ports(
                agent_id,
                vec![WorkspaceAgentListeningPort {
                    port: 8080,
                    network: "tcp".to_owned(),
                    process_name: String::new(),
                }],
            )
            .await;

        // Simulate reconnection: register a new connection for the same agent.
        let conn_new: Arc<dyn AgentConnection> = Arc::new(StubConnection {
            id: agent_id,
            connected: OffsetDateTime::now_utc(),
        });
        provider.register_agent(agent_id, conn_new).await;

        let ports = provider.get_listening_ports(agent_id).await;
        assert!(
            ports.is_empty(),
            "stale ports should be cleared on reconnection"
        );
    }

    #[tokio::test]
    async fn listening_ports_isolated_between_agents() {
        let provider = InMemoryAgentProvider::new();
        let agent_a = Uuid::new_v4();
        let agent_b = Uuid::new_v4();

        let ports_a = vec![WorkspaceAgentListeningPort {
            port: 8080,
            network: "tcp".to_owned(),
            process_name: "a".to_owned(),
        }];
        let ports_b = vec![WorkspaceAgentListeningPort {
            port: 9090,
            network: "tcp".to_owned(),
            process_name: "b".to_owned(),
        }];

        provider.set_listening_ports(agent_a, ports_a.clone()).await;
        provider.set_listening_ports(agent_b, ports_b.clone()).await;

        assert_eq!(provider.get_listening_ports(agent_a).await, ports_a);
        assert_eq!(provider.get_listening_ports(agent_b).await, ports_b);
    }
}
