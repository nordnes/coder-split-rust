//! Tailnet coordination layer and DERP traffic tracking.
//!
//! Provides the [`TailnetCoordinator`] trait and an [`InMemoryCoordinator`]
//! implementation that routes node information between connected peers,
//! manages tunnels, and broadcasts DERP map updates.  Also provides
//! [`DerpTrafficTracker`] for per-client DERP relay traffic statistics.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::sync::{mpsc, watch};
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
// Coordination protocol types
// ---------------------------------------------------------------------------

/// Information about a node in the tailnet mesh.
///
/// Mirrors the Go `tailnet.Node` struct with the fields needed for
/// WireGuard peer-to-peer connection establishment.
///
/// # Protocol compatibility
///
/// The Go reference (`tailnet/proto/tailnet.proto`) uses **protobuf** over
/// DRPC, not JSON over WebSocket.  The field names here are chosen to be
/// close to the protobuf definition for documentation purposes, but real
/// Go clients will send protobuf-encoded `proto.CoordinateRequest` messages
/// which are **not** compatible with the JSON serde used here.  A future
/// milestone must add protobuf (or at minimum proto-JSON) support to
/// achieve true wire-compatibility with Go agents/clients.
///
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NodeInfo {
    /// Unique node identifier.
    #[serde(default)]
    pub id: i64,
    /// WireGuard public key (`key.NodePublic`) for handshake.
    /// Encoded as raw bytes in protobuf; serialised as a byte array in JSON.
    #[serde(default)]
    pub key: Option<Vec<u8>>,
    /// Disco public key (`key.DiscoPublic`) used for endpoint discovery.
    #[serde(default)]
    pub disco: Option<String>,
    /// Preferred DERP region for this node.
    #[serde(default)]
    pub preferred_derp: i64,
    /// Latency to each DERP region (region name to seconds).
    #[serde(default)]
    pub derp_latency: HashMap<String, f64>,
    /// IP address ranges this node exposes.
    #[serde(default)]
    pub addresses: Vec<String>,
    /// IP ranges allowed to connect to this node.
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    /// Endpoint addresses (`ip:port`) for peer-to-peer connections.
    #[serde(default)]
    pub endpoints: Vec<String>,
}

/// A coordination protocol request from a connected peer.
///
/// Each field is optional; a request may contain one or more actions.
/// Mirrors the Go `proto.CoordinateRequest` message.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CoordinateRequest {
    /// Update this peer's own node information.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_self: Option<NodeInfo>,
    /// Request a tunnel to the specified peer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub add_tunnel: Option<Uuid>,
    /// Remove a tunnel to the specified peer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remove_tunnel: Option<Uuid>,
    /// Gracefully disconnect from coordination.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disconnect: Option<bool>,
    /// Signal readiness for handshake with the specified peers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready_for_handshake: Option<Vec<Uuid>>,
}

/// The kind of update in a coordination response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerUpdateKind {
    /// Updated node information.
    Node,
    /// Peer explicitly disconnected.
    Disconnected,
    /// Peer connection was lost.
    Lost,
    /// Peer is ready for handshake.
    ReadyForHandshake,
}

/// An individual peer update in a coordination response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerUpdateMsg {
    /// The peer this update is about.
    pub id: Uuid,
    /// The kind of update.
    pub kind: PeerUpdateKind,
    /// Node information (present for `Node` updates).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<NodeInfo>,
}

/// A coordination protocol response sent to a peer.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CoordinateResponse {
    /// List of peer updates.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peer_updates: Vec<PeerUpdateMsg>,
    /// Error message, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Handle returned by [`TailnetCoordinator::coordinate`] for receiving
/// coordination responses pushed by the coordinator.
pub struct CoordinationHandle {
    /// Receiver for coordination responses.
    pub response_rx: mpsc::UnboundedReceiver<CoordinateResponse>,
    /// Unique session identifier.  Used by [`TailnetCoordinator::close_coordination`]
    /// to avoid removing a peer entry that was already replaced by a newer session.
    pub session_id: Uuid,
}

/// Errors that can occur when processing a coordination request.
#[derive(Debug)]
pub enum CoordinationError {
    /// The specified peer is not registered with the coordinator.
    UnknownPeer,
    /// Internal coordinator error (e.g. poisoned lock).
    Internal(String),
}

impl std::fmt::Display for CoordinationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownPeer => write!(f, "unknown peer"),
            Self::Internal(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl std::error::Error for CoordinationError {}

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

    /// Register a peer connection (simple registration without coordination).
    fn add_peer(&self, peer_id: Uuid, name: String, kind: PeerKind);

    /// Remove a peer connection (simple removal without coordination).
    fn remove_peer(&self, peer_id: Uuid);

    /// Begin a coordination session for a peer.
    ///
    /// Registers the peer and returns a [`CoordinationHandle`] whose
    /// `response_rx` receives [`CoordinateResponse`] messages pushed by the
    /// coordinator (e.g. when a tunnel peer updates its node info).
    ///
    /// If a peer with the same ID is already coordinating, the old session
    /// is closed with an "overwritten" error and replaced.
    fn coordinate(&self, peer_id: Uuid, name: String, kind: PeerKind) -> CoordinationHandle;

    /// Process a single coordination request from the given peer.
    ///
    /// The coordinator applies the request (node update, tunnel add/remove,
    /// disconnect, ready-for-handshake) and pushes any resulting responses
    /// to the affected peers via their response channels.
    fn process_request(
        &self,
        peer_id: Uuid,
        request: CoordinateRequest,
    ) -> Result<(), CoordinationError>;

    /// Close a coordination session, notifying tunnel peers that this peer
    /// was lost and cleaning up all associated state.
    ///
    /// The `session_id` must match the value returned by [`TailnetCoordinator::coordinate`] so
    /// that an old (overwritten) session does not accidentally remove a
    /// newer session's state.
    fn close_coordination(&self, peer_id: Uuid, session_id: Uuid);
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
// Bidirectional tunnel tracking
// ---------------------------------------------------------------------------

/// Tracks tunnels between peers in both directions for efficient lookup.
struct TunnelStore {
    /// Source peer -> set of destination peers.
    by_src: HashMap<Uuid, HashSet<Uuid>>,
    /// Destination peer -> set of source peers.
    by_dst: HashMap<Uuid, HashSet<Uuid>>,
}

impl TunnelStore {
    fn new() -> Self {
        Self {
            by_src: HashMap::new(),
            by_dst: HashMap::new(),
        }
    }

    /// Record a tunnel from `src` to `dst`.
    fn add(&mut self, src: Uuid, dst: Uuid) {
        self.by_src.entry(src).or_default().insert(dst);
        self.by_dst.entry(dst).or_default().insert(src);
    }

    /// Remove the tunnel between `a` and `b`, regardless of which peer
    /// originally created it (i.e. handles both `a→b` and `b→a` directions).
    fn remove(&mut self, a: Uuid, b: Uuid) {
        // Try a→b direction.
        if let Some(dsts) = self.by_src.get_mut(&a) {
            dsts.remove(&b);
            if dsts.is_empty() {
                self.by_src.remove(&a);
            }
        }
        if let Some(srcs) = self.by_dst.get_mut(&b) {
            srcs.remove(&a);
            if srcs.is_empty() {
                self.by_dst.remove(&b);
            }
        }
        // Try b→a direction (reverse).
        if let Some(dsts) = self.by_src.get_mut(&b) {
            dsts.remove(&a);
            if dsts.is_empty() {
                self.by_src.remove(&b);
            }
        }
        if let Some(srcs) = self.by_dst.get_mut(&a) {
            srcs.remove(&b);
            if srcs.is_empty() {
                self.by_dst.remove(&a);
            }
        }
    }

    /// Remove all tunnels involving `id` (as source or destination).
    fn remove_all(&mut self, id: Uuid) {
        if let Some(dsts) = self.by_src.remove(&id) {
            for dst in &dsts {
                if let Some(srcs) = self.by_dst.get_mut(dst) {
                    srcs.remove(&id);
                    if srcs.is_empty() {
                        self.by_dst.remove(dst);
                    }
                }
            }
        }
        if let Some(srcs) = self.by_dst.remove(&id) {
            for src in &srcs {
                if let Some(dsts) = self.by_src.get_mut(src) {
                    dsts.remove(&id);
                    if dsts.is_empty() {
                        self.by_src.remove(src);
                    }
                }
            }
        }
    }

    /// Find all peers that share a tunnel with `id` in either direction.
    fn find_tunnel_peers(&self, id: Uuid) -> Vec<Uuid> {
        let mut peers = HashSet::new();
        if let Some(dsts) = self.by_src.get(&id) {
            peers.extend(dsts);
        }
        if let Some(srcs) = self.by_dst.get(&id) {
            peers.extend(srcs);
        }
        peers.into_iter().collect()
    }

    /// Check whether a tunnel exists between `a` and `b` in either direction.
    fn tunnel_exists(&self, a: Uuid, b: Uuid) -> bool {
        self.by_src.get(&a).is_some_and(|dsts| dsts.contains(&b))
            || self.by_dst.get(&a).is_some_and(|srcs| srcs.contains(&b))
    }
}

// ---------------------------------------------------------------------------
// Internal coordinator peer state
// ---------------------------------------------------------------------------

/// Extended peer state held by the coordinator for coordination sessions.
struct CoordinatorPeer {
    /// Public peer metadata.
    info: PeerInfo,
    /// The peer's last-known node info (set via `update_self`).
    node: Option<NodeInfo>,
    /// Channel to push coordination responses to this peer.
    /// `None` for peers registered via `add_peer` (non-coordinating).
    response_tx: Option<mpsc::UnboundedSender<CoordinateResponse>>,
    /// Unique session identifier for this coordination session.
    session_id: Uuid,
}

/// Aggregated coordinator state protected by a single mutex.
struct CoordinatorInner {
    peers: HashMap<Uuid, CoordinatorPeer>,
    tunnels: TunnelStore,
}

// ---------------------------------------------------------------------------
// InMemoryCoordinator
// ---------------------------------------------------------------------------

/// In-memory implementation of [`TailnetCoordinator`].
///
/// Routes node information between connected peers, manages tunnels for
/// peer-to-peer WireGuard connections, and maintains a DERP map that can
/// be updated and broadcast to subscribers.
pub struct InMemoryCoordinator {
    inner: Mutex<CoordinatorInner>,
    derp_map_tx: watch::Sender<DERPMap>,
    derp_map_rx: watch::Receiver<DERPMap>,
}

impl InMemoryCoordinator {
    /// Creates a new in-memory coordinator with an optional initial DERP map.
    #[must_use]
    pub fn new(initial_derp_map: DERPMap) -> Arc<Self> {
        let (tx, rx) = watch::channel(initial_derp_map);
        Arc::new(Self {
            inner: Mutex::new(CoordinatorInner {
                peers: HashMap::new(),
                tunnels: TunnelStore::new(),
            }),
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

    /// Send a response to a peer, ignoring send failures (peer may have
    /// disconnected and the receiver dropped).
    fn send_to_peer(peer: &CoordinatorPeer, response: CoordinateResponse) {
        if let Some(tx) = &peer.response_tx {
            let _ = tx.send(response);
        }
    }
}

impl TailnetCoordinator for InMemoryCoordinator {
    fn debug_html(&self) -> String {
        let peers: Vec<PeerInfo> = match self.inner.lock() {
            Ok(guard) => guard.peers.values().map(|p| p.info.clone()).collect(),
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
        let peers: Vec<PeerInfo> = match self.inner.lock() {
            Ok(guard) => guard.peers.values().map(|p| p.info.clone()).collect(),
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
        if let Ok(mut inner) = self.inner.lock() {
            inner.peers.insert(
                peer_id,
                CoordinatorPeer {
                    info: PeerInfo {
                        id: peer_id,
                        name,
                        kind,
                        connected_at: OffsetDateTime::now_utc(),
                    },
                    node: None,
                    response_tx: None,
                    session_id: Uuid::new_v4(),
                },
            );
        }
    }

    fn remove_peer(&self, peer_id: Uuid) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.peers.remove(&peer_id);
            inner.tunnels.remove_all(peer_id);
        }
    }

    fn coordinate(&self, peer_id: Uuid, name: String, kind: PeerKind) -> CoordinationHandle {
        // NOTE: We use an unbounded channel here for simplicity.  The Go
        // reference also buffers coordinator responses without backpressure.
        // Under production load a misbehaving peer that stops reading could
        // accumulate messages indefinitely.  A future optimisation could
        // switch to a bounded channel (e.g. capacity 128) and disconnect
        // slow consumers on `SendError`.
        let (tx, rx) = mpsc::unbounded_channel();
        let session_id = Uuid::new_v4();

        if let Ok(mut inner) = self.inner.lock() {
            // If there is an existing coordination session, close it.
            // NOTE: We intentionally do NOT call `inner.tunnels.remove_all`
            // here — old tunnels are preserved so the reconnecting peer
            // picks up where it left off (the initial node-info exchange
            // below delivers the current tunnel peers' nodes).
            if let Some(old) = inner.peers.get(&peer_id) {
                Self::send_to_peer(
                    old,
                    CoordinateResponse {
                        peer_updates: Vec::new(),
                        error: Some("overwritten by new connection".to_string()),
                    },
                );
            }

            inner.peers.insert(
                peer_id,
                CoordinatorPeer {
                    info: PeerInfo {
                        id: peer_id,
                        name,
                        kind,
                        connected_at: OffsetDateTime::now_utc(),
                    },
                    node: None,
                    response_tx: Some(tx),
                    session_id,
                },
            );

            // Send existing tunnel peers' node info to the new peer.
            let tunnel_peers = inner.tunnels.find_tunnel_peers(peer_id);
            let mut initial_updates = Vec::new();
            for tp_id in tunnel_peers {
                if let Some(tp) = inner.peers.get(&tp_id) {
                    if let Some(node) = &tp.node {
                        initial_updates.push(PeerUpdateMsg {
                            id: tp_id,
                            kind: PeerUpdateKind::Node,
                            node: Some(node.clone()),
                        });
                    }
                }
            }
            if !initial_updates.is_empty() {
                if let Some(peer) = inner.peers.get(&peer_id) {
                    Self::send_to_peer(
                        peer,
                        CoordinateResponse {
                            peer_updates: initial_updates,
                            error: None,
                        },
                    );
                }
            }
        }

        CoordinationHandle {
            response_rx: rx,
            session_id,
        }
    }

    fn process_request(
        &self,
        peer_id: Uuid,
        request: CoordinateRequest,
    ) -> Result<(), CoordinationError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| CoordinationError::Internal(e.to_string()))?;

        if !inner.peers.contains_key(&peer_id) {
            return Err(CoordinationError::UnknownPeer);
        }

        // ---- UpdateSelf: store node info and notify tunnel peers ----
        if let Some(node) = request.update_self {
            if let Some(peer) = inner.peers.get_mut(&peer_id) {
                peer.node = Some(node.clone());
            }
            let tunnel_peers = inner.tunnels.find_tunnel_peers(peer_id);
            for tp_id in tunnel_peers {
                if let Some(tp) = inner.peers.get(&tp_id) {
                    Self::send_to_peer(
                        tp,
                        CoordinateResponse {
                            peer_updates: vec![PeerUpdateMsg {
                                id: peer_id,
                                kind: PeerUpdateKind::Node,
                                node: Some(node.clone()),
                            }],
                            error: None,
                        },
                    );
                }
            }
        }

        // ---- AddTunnel: register tunnel and exchange node info ----
        if let Some(dst_id) = request.add_tunnel {
            // Reject self-tunnels — a peer cannot tunnel to itself.
            if dst_id == peer_id {
                if let Some(src) = inner.peers.get(&peer_id) {
                    Self::send_to_peer(
                        src,
                        CoordinateResponse {
                            peer_updates: Vec::new(),
                            error: Some("cannot add tunnel to self".to_string()),
                        },
                    );
                }
            } else if !inner.peers.contains_key(&dst_id) {
                // Reject tunnels to unknown / non-coordinating peers.
                if let Some(src) = inner.peers.get(&peer_id) {
                    Self::send_to_peer(
                        src,
                        CoordinateResponse {
                            peer_updates: Vec::new(),
                            error: Some(format!(
                                "cannot add tunnel: peer \"{dst_id}\" is not connected"
                            )),
                        },
                    );
                }
            } else {
                inner.tunnels.add(peer_id, dst_id);

                // Send dst's node to src.
                let dst_node = inner.peers.get(&dst_id).and_then(|p| p.node.clone());
                if let Some(dst_node) = dst_node {
                    if let Some(src) = inner.peers.get(&peer_id) {
                        Self::send_to_peer(
                            src,
                            CoordinateResponse {
                                peer_updates: vec![PeerUpdateMsg {
                                    id: dst_id,
                                    kind: PeerUpdateKind::Node,
                                    node: Some(dst_node),
                                }],
                                error: None,
                            },
                        );
                    }
                }

                // Send src's node to dst.
                let src_node = inner.peers.get(&peer_id).and_then(|p| p.node.clone());
                if let Some(src_node) = src_node {
                    if let Some(dst) = inner.peers.get(&dst_id) {
                        Self::send_to_peer(
                            dst,
                            CoordinateResponse {
                                peer_updates: vec![PeerUpdateMsg {
                                    id: peer_id,
                                    kind: PeerUpdateKind::Node,
                                    node: Some(src_node),
                                }],
                                error: None,
                            },
                        );
                    }
                }
            } // end else (not self-tunnel)
        }

        // ---- RemoveTunnel: notify both peers and remove tunnel ----
        if let Some(dst_id) = request.remove_tunnel {
            if inner.tunnels.tunnel_exists(peer_id, dst_id) {
                if let Some(src) = inner.peers.get(&peer_id) {
                    Self::send_to_peer(
                        src,
                        CoordinateResponse {
                            peer_updates: vec![PeerUpdateMsg {
                                id: dst_id,
                                kind: PeerUpdateKind::Disconnected,
                                node: None,
                            }],
                            error: None,
                        },
                    );
                }
                if let Some(dst) = inner.peers.get(&dst_id) {
                    Self::send_to_peer(
                        dst,
                        CoordinateResponse {
                            peer_updates: vec![PeerUpdateMsg {
                                id: peer_id,
                                kind: PeerUpdateKind::Disconnected,
                                node: None,
                            }],
                            error: None,
                        },
                    );
                }
                inner.tunnels.remove(peer_id, dst_id);
            } else if let Some(src) = inner.peers.get(&peer_id) {
                Self::send_to_peer(
                    src,
                    CoordinateResponse {
                        peer_updates: Vec::new(),
                        error: Some(format!("no tunnel exists between you and \"{dst_id}\"")),
                    },
                );
            }
        }

        // ---- Disconnect: notify tunnel peers and remove peer ----
        if request.disconnect == Some(true) {
            let tunnel_peers = inner.tunnels.find_tunnel_peers(peer_id);
            for tp_id in tunnel_peers {
                if let Some(tp) = inner.peers.get(&tp_id) {
                    Self::send_to_peer(
                        tp,
                        CoordinateResponse {
                            peer_updates: vec![PeerUpdateMsg {
                                id: peer_id,
                                kind: PeerUpdateKind::Disconnected,
                                node: None,
                            }],
                            error: None,
                        },
                    );
                }
            }
            inner.tunnels.remove_all(peer_id);
            inner.peers.remove(&peer_id);
            // Peer is gone — skip any remaining fields (e.g. ready_for_handshake).
            return Ok(());
        }

        // ---- ReadyForHandshake: forward RFH to tunnel peers ----
        if let Some(rfh_ids) = request.ready_for_handshake {
            for dst_id in rfh_ids {
                if !inner.tunnels.tunnel_exists(peer_id, dst_id) {
                    if let Some(src) = inner.peers.get(&peer_id) {
                        Self::send_to_peer(
                            src,
                            CoordinateResponse {
                                peer_updates: Vec::new(),
                                error: Some(format!(
                                    "ready for handshake error: you do not share a tunnel with \"{dst_id}\""
                                )),
                            },
                        );
                    }
                    continue;
                }

                if let Some(dst) = inner.peers.get(&dst_id) {
                    Self::send_to_peer(
                        dst,
                        CoordinateResponse {
                            peer_updates: vec![PeerUpdateMsg {
                                id: peer_id,
                                kind: PeerUpdateKind::ReadyForHandshake,
                                node: None,
                            }],
                            error: None,
                        },
                    );
                }
            }
        }

        Ok(())
    }

    fn close_coordination(&self, peer_id: Uuid, session_id: Uuid) {
        if let Ok(mut inner) = self.inner.lock() {
            // Only remove the peer if the session_id matches the current
            // session.  This prevents an old (overwritten) connection from
            // accidentally destroying a newer session's state.
            if let Some(peer) = inner.peers.get(&peer_id) {
                if peer.session_id != session_id {
                    return;
                }
            } else {
                return;
            }

            // Notify tunnel peers that this peer was lost.
            let tunnel_peers = inner.tunnels.find_tunnel_peers(peer_id);
            for tp_id in tunnel_peers {
                if let Some(tp) = inner.peers.get(&tp_id) {
                    Self::send_to_peer(
                        tp,
                        CoordinateResponse {
                            peer_updates: vec![PeerUpdateMsg {
                                id: peer_id,
                                kind: PeerUpdateKind::Lost,
                                node: None,
                            }],
                            error: None,
                        },
                    );
                }
            }
            inner.tunnels.remove_all(peer_id);
            inner.peers.remove(&peer_id);
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
        assert_eq!(debug["agents"].as_array().map(|a| a.len()), Some(1));
        assert_eq!(debug["clients"].as_array().map(|a| a.len()), Some(1));

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
    fn update_derp_map_replaces_existing() {
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
    fn peer_kinds_separated_in_debug_json() {
        let coordinator = InMemoryCoordinator::new(DERPMap::default());

        let agent_id = Uuid::new_v4();
        let client_id = Uuid::new_v4();

        coordinator.add_peer(agent_id, "agent".to_string(), PeerKind::Agent);
        coordinator.add_peer(client_id, "client".to_string(), PeerKind::Client);

        let debug = coordinator.debug_json();
        assert_eq!(debug["agents"].as_array().map(|a| a.len()), Some(1));
        assert_eq!(debug["clients"].as_array().map(|a| a.len()), Some(1));
    }

    // --- Coordination protocol tests ---

    #[test]
    fn test_tunnel_store_add_remove() {
        let mut store = TunnelStore::new();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let c = Uuid::new_v4();

        store.add(a, b);
        store.add(a, c);

        assert!(store.tunnel_exists(a, b));
        assert!(store.tunnel_exists(a, c));
        // Reverse direction also counts as sharing a tunnel.
        assert!(store.tunnel_exists(b, a));

        let peers = store.find_tunnel_peers(a);
        assert_eq!(peers.len(), 2);

        store.remove(a, b);
        assert!(!store.tunnel_exists(a, b));
        assert!(store.tunnel_exists(a, c));

        store.remove_all(a);
        assert!(store.find_tunnel_peers(a).is_empty());
    }

    #[tokio::test]
    async fn test_coordinate_node_update_routes_to_tunnel_peer() {
        let coordinator = InMemoryCoordinator::new(DERPMap::default());

        let agent_id = Uuid::new_v4();
        let client_id = Uuid::new_v4();

        // Agent starts coordinating.
        let mut agent_handle =
            coordinator.coordinate(agent_id, "agent".to_string(), PeerKind::Agent);
        // Client starts coordinating.
        let mut client_handle =
            coordinator.coordinate(client_id, "client".to_string(), PeerKind::Client);

        // Client requests a tunnel to the agent.
        coordinator
            .process_request(
                client_id,
                CoordinateRequest {
                    add_tunnel: Some(agent_id),
                    ..Default::default()
                },
            )
            .ok();

        // Agent updates its node info.
        let agent_node = NodeInfo {
            id: 1,
            preferred_derp: 1,
            endpoints: vec!["192.168.1.1:41234".to_string()],
            ..Default::default()
        };
        coordinator
            .process_request(
                agent_id,
                CoordinateRequest {
                    update_self: Some(agent_node),
                    ..Default::default()
                },
            )
            .ok();

        // Client should receive the agent's node update via its response channel.
        let response = client_handle.response_rx.recv().await;
        assert!(response.is_some());
        let response = response.unwrap_or_default();
        assert_eq!(response.peer_updates.len(), 1);
        assert_eq!(response.peer_updates[0].id, agent_id);
        assert_eq!(response.peer_updates[0].kind, PeerUpdateKind::Node);
        assert!(response.peer_updates[0].node.is_some());
        let received_node = response.peer_updates[0].node.clone().unwrap_or_default();
        assert_eq!(received_node.id, 1);
        assert_eq!(received_node.preferred_derp, 1);
        assert_eq!(received_node.endpoints, vec!["192.168.1.1:41234"]);

        // Agent should NOT receive its own update (no tunnel to self).
        let agent_resp = agent_handle.response_rx.try_recv();
        assert!(agent_resp.is_err());
    }

    #[tokio::test]
    async fn test_coordinate_add_tunnel_exchanges_existing_nodes() {
        let coordinator = InMemoryCoordinator::new(DERPMap::default());

        let agent_id = Uuid::new_v4();
        let client_id = Uuid::new_v4();

        let mut _agent_handle =
            coordinator.coordinate(agent_id, "agent".to_string(), PeerKind::Agent);
        let mut client_handle =
            coordinator.coordinate(client_id, "client".to_string(), PeerKind::Client);

        // Agent sets its node info first.
        let agent_node = NodeInfo {
            id: 42,
            preferred_derp: 2,
            ..Default::default()
        };
        coordinator
            .process_request(
                agent_id,
                CoordinateRequest {
                    update_self: Some(agent_node),
                    ..Default::default()
                },
            )
            .ok();

        // Now client adds a tunnel -- should immediately receive agent's node.
        coordinator
            .process_request(
                client_id,
                CoordinateRequest {
                    add_tunnel: Some(agent_id),
                    ..Default::default()
                },
            )
            .ok();

        let response = client_handle.response_rx.recv().await;
        assert!(response.is_some());
        let response = response.unwrap_or_default();
        assert_eq!(response.peer_updates.len(), 1);
        assert_eq!(response.peer_updates[0].id, agent_id);
        assert_eq!(response.peer_updates[0].kind, PeerUpdateKind::Node);
        let node = response.peer_updates[0].node.clone().unwrap_or_default();
        assert_eq!(node.id, 42);
    }

    #[tokio::test]
    async fn test_coordinate_remove_tunnel_sends_disconnected() {
        let coordinator = InMemoryCoordinator::new(DERPMap::default());

        let agent_id = Uuid::new_v4();
        let client_id = Uuid::new_v4();

        let mut agent_handle =
            coordinator.coordinate(agent_id, "agent".to_string(), PeerKind::Agent);
        let mut client_handle =
            coordinator.coordinate(client_id, "client".to_string(), PeerKind::Client);

        // Establish tunnel.
        coordinator
            .process_request(
                client_id,
                CoordinateRequest {
                    add_tunnel: Some(agent_id),
                    ..Default::default()
                },
            )
            .ok();

        // Remove tunnel.
        coordinator
            .process_request(
                client_id,
                CoordinateRequest {
                    remove_tunnel: Some(agent_id),
                    ..Default::default()
                },
            )
            .ok();

        // Both peers should receive Disconnected updates.
        let client_resp = client_handle.response_rx.recv().await.unwrap_or_default();
        assert_eq!(client_resp.peer_updates.len(), 1);
        assert_eq!(client_resp.peer_updates[0].id, agent_id);
        assert_eq!(
            client_resp.peer_updates[0].kind,
            PeerUpdateKind::Disconnected
        );

        let agent_resp = agent_handle.response_rx.recv().await.unwrap_or_default();
        assert_eq!(agent_resp.peer_updates.len(), 1);
        assert_eq!(agent_resp.peer_updates[0].id, client_id);
        assert_eq!(
            agent_resp.peer_updates[0].kind,
            PeerUpdateKind::Disconnected
        );
    }

    #[tokio::test]
    async fn test_coordinate_close_sends_lost() {
        let coordinator = InMemoryCoordinator::new(DERPMap::default());

        let agent_id = Uuid::new_v4();
        let client_id = Uuid::new_v4();

        let mut agent_handle =
            coordinator.coordinate(agent_id, "agent".to_string(), PeerKind::Agent);
        let _client_handle =
            coordinator.coordinate(client_id, "client".to_string(), PeerKind::Client);

        // Establish tunnel.
        coordinator
            .process_request(
                client_id,
                CoordinateRequest {
                    add_tunnel: Some(agent_id),
                    ..Default::default()
                },
            )
            .ok();

        // Client disconnects abruptly.
        coordinator.close_coordination(client_id, _client_handle.session_id);

        // Agent should receive Lost update.
        let resp = agent_handle.response_rx.recv().await.unwrap_or_default();
        assert_eq!(resp.peer_updates.len(), 1);
        assert_eq!(resp.peer_updates[0].id, client_id);
        assert_eq!(resp.peer_updates[0].kind, PeerUpdateKind::Lost);
    }

    #[tokio::test]
    async fn test_coordinate_ready_for_handshake() {
        let coordinator = InMemoryCoordinator::new(DERPMap::default());

        let agent_id = Uuid::new_v4();
        let client_id = Uuid::new_v4();

        let mut agent_handle =
            coordinator.coordinate(agent_id, "agent".to_string(), PeerKind::Agent);
        let mut client_handle =
            coordinator.coordinate(client_id, "client".to_string(), PeerKind::Client);

        // Without a tunnel, RFH should return an error.
        coordinator
            .process_request(
                client_id,
                CoordinateRequest {
                    ready_for_handshake: Some(vec![agent_id]),
                    ..Default::default()
                },
            )
            .ok();

        let resp = client_handle.response_rx.recv().await.unwrap_or_default();
        assert!(resp.error.is_some());
        assert!(
            resp.error
                .as_deref()
                .unwrap_or_default()
                .contains("do not share a tunnel")
        );

        // Add tunnel and retry.
        coordinator
            .process_request(
                client_id,
                CoordinateRequest {
                    add_tunnel: Some(agent_id),
                    ..Default::default()
                },
            )
            .ok();

        coordinator
            .process_request(
                client_id,
                CoordinateRequest {
                    ready_for_handshake: Some(vec![agent_id]),
                    ..Default::default()
                },
            )
            .ok();

        // Agent should receive the RFH.
        let resp = agent_handle.response_rx.recv().await.unwrap_or_default();
        assert_eq!(resp.peer_updates.len(), 1);
        assert_eq!(resp.peer_updates[0].id, client_id);
        assert_eq!(resp.peer_updates[0].kind, PeerUpdateKind::ReadyForHandshake);
    }

    #[tokio::test]
    async fn test_coordinate_overwrite_session() {
        let coordinator = InMemoryCoordinator::new(DERPMap::default());
        let peer_id = Uuid::new_v4();

        let mut first_handle =
            coordinator.coordinate(peer_id, "peer-v1".to_string(), PeerKind::Client);

        // Open a second session with the same ID.
        let _second_handle =
            coordinator.coordinate(peer_id, "peer-v2".to_string(), PeerKind::Client);

        // First session should receive an overwrite error.
        let resp = first_handle.response_rx.recv().await.unwrap_or_default();
        assert!(resp.error.is_some());
        assert!(
            resp.error
                .as_deref()
                .unwrap_or_default()
                .contains("overwritten")
        );
    }

    #[tokio::test]
    async fn test_close_coordination_with_stale_session_id_is_noop() {
        let coordinator = InMemoryCoordinator::new(DERPMap::default());
        let peer_id = Uuid::new_v4();
        let agent_id = Uuid::new_v4();

        // First session.
        let first_handle = coordinator.coordinate(peer_id, "peer-v1".to_string(), PeerKind::Client);
        let first_session_id = first_handle.session_id;

        // Second session overwrites the first.
        let second_handle =
            coordinator.coordinate(peer_id, "peer-v2".to_string(), PeerKind::Client);

        // Set up a tunnel on the new session.
        let mut agent_handle =
            coordinator.coordinate(agent_id, "agent".to_string(), PeerKind::Agent);
        coordinator
            .process_request(
                peer_id,
                CoordinateRequest {
                    add_tunnel: Some(agent_id),
                    ..Default::default()
                },
            )
            .ok();

        // Old session tries to close — should be a no-op because session_id
        // doesn't match.
        coordinator.close_coordination(peer_id, first_session_id);

        // The new session should still be functional.
        let node = NodeInfo {
            id: 99,
            ..Default::default()
        };
        coordinator
            .process_request(
                peer_id,
                CoordinateRequest {
                    update_self: Some(node),
                    ..Default::default()
                },
            )
            .ok();

        // Agent should still receive the update (new session is alive).
        let resp = agent_handle.response_rx.recv().await.unwrap_or_default();
        assert_eq!(resp.peer_updates.len(), 1);
        assert_eq!(resp.peer_updates[0].id, peer_id);
        assert_eq!(resp.peer_updates[0].kind, PeerUpdateKind::Node);

        // Now close with the correct session_id — should work.
        coordinator.close_coordination(peer_id, second_handle.session_id);
        let resp = agent_handle.response_rx.recv().await.unwrap_or_default();
        assert_eq!(resp.peer_updates.len(), 1);
        assert_eq!(resp.peer_updates[0].kind, PeerUpdateKind::Lost);
    }

    #[tokio::test]
    async fn test_add_tunnel_to_self_returns_error() {
        let coordinator = InMemoryCoordinator::new(DERPMap::default());
        let peer_id = Uuid::new_v4();

        let mut handle =
            coordinator.coordinate(peer_id, "self-tunnel".to_string(), PeerKind::Client);

        // Try to create a tunnel to ourselves.
        coordinator
            .process_request(
                peer_id,
                CoordinateRequest {
                    add_tunnel: Some(peer_id),
                    ..Default::default()
                },
            )
            .ok();

        // Should receive an error response.
        let resp = handle.response_rx.recv().await.unwrap_or_default();
        assert!(resp.error.is_some());
        assert!(
            resp.error
                .as_deref()
                .unwrap_or_default()
                .contains("cannot add tunnel to self")
        );
    }

    #[tokio::test]
    async fn test_add_tunnel_to_unknown_peer_returns_error() {
        let coordinator = InMemoryCoordinator::new(DERPMap::default());
        let peer_id = Uuid::new_v4();
        let unknown_id = Uuid::new_v4();

        let mut handle = coordinator.coordinate(peer_id, "client".to_string(), PeerKind::Client);

        // Try to create a tunnel to an unknown peer.
        coordinator
            .process_request(
                peer_id,
                CoordinateRequest {
                    add_tunnel: Some(unknown_id),
                    ..Default::default()
                },
            )
            .ok();

        // Should receive an error response.
        let resp = handle.response_rx.recv().await.unwrap_or_default();
        assert!(resp.error.is_some());
        assert!(
            resp.error
                .as_deref()
                .unwrap_or_default()
                .contains("not connected")
        );
    }

    #[tokio::test]
    async fn test_remove_nonexistent_tunnel_returns_error() {
        let coordinator = InMemoryCoordinator::new(DERPMap::default());
        let peer_id = Uuid::new_v4();
        let other_id = Uuid::new_v4();

        let mut handle = coordinator.coordinate(peer_id, "client".to_string(), PeerKind::Client);
        let _other_handle = coordinator.coordinate(other_id, "agent".to_string(), PeerKind::Agent);

        // Try to remove a tunnel that doesn't exist.
        coordinator
            .process_request(
                peer_id,
                CoordinateRequest {
                    remove_tunnel: Some(other_id),
                    ..Default::default()
                },
            )
            .ok();

        // Should receive an error response.
        let resp = handle.response_rx.recv().await.unwrap_or_default();
        assert!(resp.error.is_some());
        assert!(
            resp.error
                .as_deref()
                .unwrap_or_default()
                .contains("no tunnel exists")
        );
    }

    #[tokio::test]
    async fn test_remove_tunnel_by_destination_peer() {
        // Regression test: when the *destination* peer of a tunnel calls
        // remove_tunnel, the tunnel should actually be removed from the
        // store (not just the src→dst direction).
        let coordinator = InMemoryCoordinator::new(DERPMap::default());
        let client_id = Uuid::new_v4();
        let agent_id = Uuid::new_v4();

        let mut client_handle =
            coordinator.coordinate(client_id, "client".to_string(), PeerKind::Client);
        let mut agent_handle =
            coordinator.coordinate(agent_id, "agent".to_string(), PeerKind::Agent);

        // Client creates tunnel to agent (stored as client→agent).
        coordinator
            .process_request(
                client_id,
                CoordinateRequest {
                    add_tunnel: Some(agent_id),
                    ..Default::default()
                },
            )
            .ok();

        // Agent removes the tunnel (reverse direction).
        coordinator
            .process_request(
                agent_id,
                CoordinateRequest {
                    remove_tunnel: Some(client_id),
                    ..Default::default()
                },
            )
            .ok();

        // Both sides should receive Disconnected.
        let resp = agent_handle.response_rx.recv().await.unwrap_or_default();
        assert_eq!(resp.peer_updates.len(), 1);
        assert_eq!(resp.peer_updates[0].kind, PeerUpdateKind::Disconnected);

        let resp = client_handle.response_rx.recv().await.unwrap_or_default();
        assert_eq!(resp.peer_updates.len(), 1);
        assert_eq!(resp.peer_updates[0].kind, PeerUpdateKind::Disconnected);

        // Verify the tunnel is actually gone — update_self should NOT route.
        coordinator
            .process_request(
                client_id,
                CoordinateRequest {
                    update_self: Some(NodeInfo {
                        id: 42,
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .ok();

        // Agent should NOT receive a node update (tunnel was removed).
        // Use try_recv to confirm nothing is pending.
        assert!(agent_handle.response_rx.try_recv().is_err());
    }

    // NOTE: Coordinator-level unit tests exist above and cover add/remove
    // peer, tunnel routing, node updates, and session lifecycle.  WebSocket-
    // level integration tests (connecting to the `tailnet_rpc_conn` handler,
    // sending `CoordinateRequest` messages, and verifying `CoordinateResponse`
    // framing) are deferred — they require a running Axum server with an
    // upgrade-capable HTTP client, which is outside the scope of this crate.
}
