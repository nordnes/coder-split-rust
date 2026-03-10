//! Tailnet coordination layer and DERP traffic tracking.
//!
//! Provides the [`TailnetCoordinator`] trait and an [`InMemoryCoordinator`]
//! implementation that tracks connected peers in memory.  Also provides
//! [`DerpTrafficTracker`] for per-client DERP relay traffic statistics.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use time::OffsetDateTime;
use tokio::sync::watch;
use uuid::Uuid;

/// Async mutex for types that hold locks across `.await` points.
type AsyncMutex<T> = tokio::sync::Mutex<T>;

use coder_core::api::{DERPMap, DERPMapRegion, DERPNode};

// ---------------------------------------------------------------------------
// HTML escaping helper
// ---------------------------------------------------------------------------

/// Escapes HTML special characters to prevent XSS.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

// ---------------------------------------------------------------------------
// TailnetCoordinator trait
// ---------------------------------------------------------------------------

/// Trait for tailnet coordination.
///
/// Implementations track connected agents and clients, exchange node
/// information for peer-to-peer WireGuard connections, and provide debug
/// views of the coordination state.
pub trait TailnetCoordinator: Send + Sync {
    /// Returns an HTML debug page showing coordinator state.
    fn debug_html(&self) -> String;

    /// Returns JSON debug state for the tailnet mesh.
    fn debug_json(&self) -> serde_json::Value;

    /// Returns the current DERP map.
    fn derp_map(&self) -> DERPMap;

    /// Returns a receiver that yields updates when the DERP map changes.
    fn subscribe_derp_map(&self) -> watch::Receiver<DERPMap>;

    /// Register a peer connection.  Returns when the peer disconnects.
    fn add_peer(&self, peer_id: Uuid, name: String, kind: PeerKind);

    /// Remove a peer connection.
    fn remove_peer(&self, peer_id: Uuid);
}

/// The kind of peer connected to the coordinator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerKind {
    /// A workspace agent.
    Agent,
    /// A client (e.g. VS Code, SSH, web terminal).
    Client,
}

/// Information about a connected peer.
#[derive(Clone, Debug, Serialize)]
pub struct PeerInfo {
    /// Unique peer identifier.
    pub id: Uuid,
    /// Human-readable peer name.
    pub name: String,
    /// Whether this is an agent or client.
    pub kind: PeerKind,
    /// When the peer connected.
    #[serde(with = "time::serde::rfc3339")]
    pub connected_at: OffsetDateTime,
}

// ---------------------------------------------------------------------------
// InMemoryCoordinator
// ---------------------------------------------------------------------------

/// In-memory implementation of [`TailnetCoordinator`].
///
/// Tracks connected peers and maintains a DERP map that can be updated
/// and broadcast to subscribers.  This is a functional stub that tracks
/// connections but does not perform actual WireGuard coordination.
pub struct InMemoryCoordinator {
    peers: Mutex<HashMap<Uuid, PeerInfo>>,
    derp_map_tx: watch::Sender<DERPMap>,
    derp_map_rx: watch::Receiver<DERPMap>,
}

impl InMemoryCoordinator {
    /// Creates a new in-memory coordinator with an optional initial DERP map.
    #[must_use]
    pub fn new(initial_derp_map: DERPMap) -> Arc<Self> {
        let (tx, rx) = watch::channel(initial_derp_map);
        Arc::new(Self {
            peers: Mutex::new(HashMap::new()),
            derp_map_tx: tx,
            derp_map_rx: rx,
        })
    }

    /// Updates the DERP map and notifies all subscribers.
    pub fn update_derp_map(&self, map: DERPMap) {
        // send returns an error only if there are no receivers, which we
        // always have (self.derp_map_rx), so this is safe to ignore.
        let _ = self.derp_map_tx.send(map);
    }
}

impl TailnetCoordinator for InMemoryCoordinator {
    fn debug_html(&self) -> String {
        let peers: Vec<PeerInfo> = match self.peers.lock() {
            Ok(guard) => guard.values().cloned().collect(),
            Err(_) => Vec::new(),
        };

        let agents: Vec<&PeerInfo> = peers.iter().filter(|p| p.kind == PeerKind::Agent).collect();
        let clients: Vec<&PeerInfo> = peers
            .iter()
            .filter(|p| p.kind == PeerKind::Client)
            .collect();

        let derp_map = self.derp_map();

        let mut html = String::from(
            "<!DOCTYPE html>\n<html><head><title>Tailnet Coordinator Debug</title>\n\
             <style>\n\
             body { font-family: monospace; margin: 20px; background: #fafafa; }\n\
             h1 { color: #333; }\n\
             h2 { color: #555; margin-top: 24px; }\n\
             table { border-collapse: collapse; margin: 8px 0; }\n\
             th, td { border: 1px solid #ccc; padding: 6px 12px; text-align: left; }\n\
             th { background: #eee; }\n\
             .count { color: #0066cc; font-weight: bold; }\n\
             </style>\n</head><body>\n",
        );

        html.push_str("<h1>Tailnet Coordinator Debug</h1>\n");
        html.push_str(&format!(
            "<p>Agents: <span class=\"count\">{}</span> | \
             Clients: <span class=\"count\">{}</span> | \
             Total peers: <span class=\"count\">{}</span></p>\n",
            agents.len(),
            clients.len(),
            peers.len(),
        ));

        // Agents table
        html.push_str("<h2>Connected Agents</h2>\n");
        if agents.is_empty() {
            html.push_str("<p>No agents connected.</p>\n");
        } else {
            html.push_str("<table><tr><th>ID</th><th>Name</th><th>Connected At</th></tr>\n");
            for agent in &agents {
                let connected = agent
                    .connected_at
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default();
                html.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                    html_escape(&agent.id.to_string()),
                    html_escape(&agent.name),
                    html_escape(&connected),
                ));
            }
            html.push_str("</table>\n");
        }

        // Clients table
        html.push_str("<h2>Connected Clients</h2>\n");
        if clients.is_empty() {
            html.push_str("<p>No clients connected.</p>\n");
        } else {
            html.push_str("<table><tr><th>ID</th><th>Name</th><th>Connected At</th></tr>\n");
            for client in &clients {
                let connected = client
                    .connected_at
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default();
                html.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                    html_escape(&client.id.to_string()),
                    html_escape(&client.name),
                    html_escape(&connected),
                ));
            }
            html.push_str("</table>\n");
        }

        // DERP regions
        html.push_str("<h2>DERP Regions</h2>\n");
        if derp_map.regions.is_empty() {
            html.push_str("<p>No DERP regions configured.</p>\n");
        } else {
            html.push_str(
                "<table><tr><th>Region ID</th><th>Code</th><th>Name</th><th>Nodes</th></tr>\n",
            );
            for (key, region) in &derp_map.regions {
                html.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                    html_escape(key),
                    html_escape(&region.region_code),
                    html_escape(&region.region_name),
                    region.nodes.len(),
                ));
            }
            html.push_str("</table>\n");
        }

        html.push_str("</body></html>\n");
        html
    }

    fn debug_json(&self) -> serde_json::Value {
        let peers: Vec<PeerInfo> = match self.peers.lock() {
            Ok(guard) => guard.values().cloned().collect(),
            Err(_) => Vec::new(),
        };

        let agents: Vec<&PeerInfo> = peers.iter().filter(|p| p.kind == PeerKind::Agent).collect();
        let clients: Vec<&PeerInfo> = peers
            .iter()
            .filter(|p| p.kind == PeerKind::Client)
            .collect();

        let derp_map = self.derp_map();

        serde_json::json!({
            "agents": agents,
            "clients": clients,
            "total_peers": peers.len(),
            "derp_map": derp_map,
        })
    }

    fn derp_map(&self) -> DERPMap {
        self.derp_map_rx.borrow().clone()
    }

    fn subscribe_derp_map(&self) -> watch::Receiver<DERPMap> {
        self.derp_map_rx.clone()
    }

    fn add_peer(&self, peer_id: Uuid, name: String, kind: PeerKind) {
        if let Ok(mut peers) = self.peers.lock() {
            peers.insert(
                peer_id,
                PeerInfo {
                    id: peer_id,
                    name,
                    kind,
                    connected_at: OffsetDateTime::now_utc(),
                },
            );
        }
    }

    fn remove_peer(&self, peer_id: Uuid) {
        if let Ok(mut peers) = self.peers.lock() {
            peers.remove(&peer_id);
        }
    }
}

// ---------------------------------------------------------------------------
// DerpTrafficTracker
// ---------------------------------------------------------------------------

/// Per-client DERP traffic statistics.
#[derive(Clone, Debug, Serialize)]
pub struct DerpClientStats {
    /// Unique client identifier.
    pub client_id: String,
    /// Total bytes sent through the DERP relay.
    pub bytes_sent: u64,
    /// Total bytes received through the DERP relay.
    pub bytes_received: u64,
    /// Total packets sent.
    pub packets_sent: u64,
    /// Total packets received.
    pub packets_received: u64,
    /// When the client connected.
    #[serde(with = "time::serde::rfc3339")]
    pub connected_at: OffsetDateTime,
}

/// Tracks per-client DERP relay traffic counters.
///
/// This is a simple in-memory tracker that maintains byte/packet counters
/// for each connected DERP client.  In a full implementation, these
/// counters would be updated by the actual DERP relay server.
pub struct DerpTrafficTracker {
    clients: AsyncMutex<HashMap<String, DerpClientStats>>,
}

impl DerpTrafficTracker {
    /// Creates a new empty traffic tracker.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            clients: AsyncMutex::new(HashMap::new()),
        })
    }

    /// Registers a new client connection.
    pub async fn add_client(&self, client_id: String) {
        let mut clients = self.clients.lock().await;
        clients.insert(
            client_id.clone(),
            DerpClientStats {
                client_id,
                bytes_sent: 0,
                bytes_received: 0,
                packets_sent: 0,
                packets_received: 0,
                connected_at: OffsetDateTime::now_utc(),
            },
        );
    }

    /// Removes a client connection.
    pub async fn remove_client(&self, client_id: &str) {
        let mut clients = self.clients.lock().await;
        clients.remove(client_id);
    }

    /// Records bytes/packets sent by a client.
    pub async fn record_sent(&self, client_id: &str, bytes: u64, packets: u64) {
        let mut clients = self.clients.lock().await;
        if let Some(stats) = clients.get_mut(client_id) {
            stats.bytes_sent = stats.bytes_sent.saturating_add(bytes);
            stats.packets_sent = stats.packets_sent.saturating_add(packets);
        }
    }

    /// Records bytes/packets received by a client.
    pub async fn record_received(&self, client_id: &str, bytes: u64, packets: u64) {
        let mut clients = self.clients.lock().await;
        if let Some(stats) = clients.get_mut(client_id) {
            stats.bytes_received = stats.bytes_received.saturating_add(bytes);
            stats.packets_received = stats.packets_received.saturating_add(packets);
        }
    }

    /// Returns a snapshot of all client traffic statistics as JSON.
    pub async fn debug_json(&self) -> serde_json::Value {
        let clients = self.clients.lock().await;
        let stats: Vec<&DerpClientStats> = clients.values().collect();
        let total_bytes_sent: u64 = stats.iter().map(|s| s.bytes_sent).sum();
        let total_bytes_received: u64 = stats.iter().map(|s| s.bytes_received).sum();
        let total_packets_sent: u64 = stats.iter().map(|s| s.packets_sent).sum();
        let total_packets_received: u64 = stats.iter().map(|s| s.packets_received).sum();

        serde_json::json!({
            "clients": stats,
            "total_clients": stats.len(),
            "total_bytes_sent": total_bytes_sent,
            "total_bytes_received": total_bytes_received,
            "total_packets_sent": total_packets_sent,
            "total_packets_received": total_packets_received,
        })
    }
}

// ---------------------------------------------------------------------------
// Helper: build a DERPMap from ServerConfig DERP regions
// ---------------------------------------------------------------------------

/// Builds a [`DERPMap`] from the DERP region configuration in
/// [`ServerConfig`](coder_core::ServerConfig).
pub fn build_derp_map_from_config(regions: &[coder_core::config::DerpRegionConfig]) -> DERPMap {
    let mut map_regions = HashMap::new();

    for region in regions {
        let region_id = i64::from(region.id);
        let nodes: Vec<DERPNode> = region
            .nodes
            .iter()
            .map(|node| DERPNode {
                name: node.name.clone(),
                region_id,
                host_name: node
                    .url
                    .host_str()
                    .map(ToString::to_string)
                    .unwrap_or_default(),
                ipv4: None,
                ipv6: None,
                stun_port: 3478,
                stun_only: false,
                derp_port: 443,
                force_http: node.url.scheme() == "http",
            })
            .collect();

        map_regions.insert(
            region_id.to_string(),
            DERPMapRegion {
                region_id,
                region_code: region.name.clone(),
                region_name: region.name.clone(),
                avoid: false,
                nodes,
            },
        );
    }

    DERPMap {
        regions: map_regions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_memory_coordinator_add_remove_peers() {
        let coordinator = InMemoryCoordinator::new(DERPMap::default());

        let agent_id = Uuid::new_v4();
        let client_id = Uuid::new_v4();

        coordinator.add_peer(agent_id, "agent-1".to_string(), PeerKind::Agent);
        coordinator.add_peer(client_id, "client-1".to_string(), PeerKind::Client);

        let debug = coordinator.debug_json();
        assert_eq!(debug["total_peers"], 2);

        coordinator.remove_peer(agent_id);
        let debug = coordinator.debug_json();
        assert_eq!(debug["total_peers"], 1);
    }

    #[test]
    fn test_in_memory_coordinator_debug_html() {
        let coordinator = InMemoryCoordinator::new(DERPMap::default());
        coordinator.add_peer(Uuid::new_v4(), "test-agent".to_string(), PeerKind::Agent);

        let html = coordinator.debug_html();
        assert!(html.contains("Tailnet Coordinator Debug"));
        assert!(html.contains("test-agent"));
    }

    #[test]
    fn test_in_memory_coordinator_derp_map() {
        let mut initial_map = DERPMap::default();
        initial_map.regions.insert(
            "1".to_string(),
            DERPMapRegion {
                region_id: 1,
                region_code: "us-east".to_string(),
                region_name: "US East".to_string(),
                avoid: false,
                nodes: vec![],
            },
        );

        let coordinator = InMemoryCoordinator::new(initial_map.clone());
        let map = coordinator.derp_map();
        assert_eq!(map.regions.len(), 1);
        assert!(map.regions.contains_key("1"));
    }

    #[tokio::test]
    async fn test_derp_traffic_tracker() {
        let tracker = DerpTrafficTracker::new();

        tracker.add_client("client-1".to_string()).await;
        tracker.record_sent("client-1", 1024, 10).await;
        tracker.record_received("client-1", 2048, 20).await;

        let debug = tracker.debug_json().await;
        assert_eq!(debug["total_clients"], 1);
        assert_eq!(debug["total_bytes_sent"], 1024);
        assert_eq!(debug["total_bytes_received"], 2048);
        assert_eq!(debug["total_packets_sent"], 10);
        assert_eq!(debug["total_packets_received"], 20);

        tracker.remove_client("client-1").await;
        let debug = tracker.debug_json().await;
        assert_eq!(debug["total_clients"], 0);
    }

    #[test]
    fn test_build_derp_map_from_config_empty() {
        let map = build_derp_map_from_config(&[]);
        assert!(map.regions.is_empty());
    }

    #[test]
    fn test_coordinator_register_peer() {
        let coordinator = InMemoryCoordinator::new(DERPMap::default());
        let peer_id = Uuid::new_v4();

        coordinator.add_peer(peer_id, "my-agent".to_string(), PeerKind::Agent);

        let debug = coordinator.debug_json();
        assert_eq!(debug["total_peers"], 1);
        assert_eq!(debug["agents"][0]["name"], "my-agent");
        assert_eq!(debug["agents"][0]["id"], peer_id.to_string());
    }

    #[test]
    fn test_coordinator_deregister_peer() {
        let coordinator = InMemoryCoordinator::new(DERPMap::default());
        let peer_id = Uuid::new_v4();

        coordinator.add_peer(peer_id, "temp-peer".to_string(), PeerKind::Client);
        assert_eq!(coordinator.debug_json()["total_peers"], 1);

        coordinator.remove_peer(peer_id);
        assert_eq!(coordinator.debug_json()["total_peers"], 0);
    }

    #[test]
    fn test_coordinator_update_derp_map() {
        let coordinator = InMemoryCoordinator::new(DERPMap::default());
        assert!(coordinator.derp_map().regions.is_empty());

        let mut new_map = DERPMap::default();
        new_map.regions.insert(
            "2".to_string(),
            DERPMapRegion {
                region_id: 2,
                region_code: "eu-west".to_string(),
                region_name: "EU West".to_string(),
                avoid: false,
                nodes: vec![],
            },
        );

        coordinator.update_derp_map(new_map);
        let map = coordinator.derp_map();
        assert_eq!(map.regions.len(), 1);
        assert!(map.regions.contains_key("2"));
        assert_eq!(map.regions["2"].region_code, "eu-west");
    }

    #[test]
    fn test_coordinator_multiple_peers() {
        let coordinator = InMemoryCoordinator::new(DERPMap::default());

        let ids: Vec<Uuid> = (0..5).map(|_| Uuid::new_v4()).collect();
        for (i, id) in ids.iter().enumerate() {
            coordinator.add_peer(*id, format!("peer-{i}"), PeerKind::Agent);
        }

        let debug = coordinator.debug_json();
        assert_eq!(debug["total_peers"], 5);
    }

    #[test]
    fn test_coordinator_peer_kinds() {
        let coordinator = InMemoryCoordinator::new(DERPMap::default());

        let agent_id = Uuid::new_v4();
        let client_id = Uuid::new_v4();

        coordinator.add_peer(agent_id, "agent".to_string(), PeerKind::Agent);
        coordinator.add_peer(client_id, "client".to_string(), PeerKind::Client);

        let debug = coordinator.debug_json();
        assert_eq!(debug["agents"].as_array().map(|a| a.len()), Some(1));
        assert_eq!(debug["clients"].as_array().map(|a| a.len()), Some(1));
    }

    #[test]
    fn test_peer_info_creation() {
        let id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();
        let info = PeerInfo {
            id,
            name: "test-peer".to_string(),
            kind: PeerKind::Agent,
            connected_at: now,
        };

        assert_eq!(info.id, id);
        assert_eq!(info.name, "test-peer");
        assert_eq!(info.kind, PeerKind::Agent);
        assert_eq!(info.connected_at, now);
    }
}
