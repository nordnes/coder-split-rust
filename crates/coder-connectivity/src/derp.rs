//! Tailscale-compatible DERP relay protocol implementation.
//!
//! Implements the DERP (Designated Encrypted Relay for Packets) protocol
//! used by Tailscale for relaying encrypted WireGuard traffic between peers
//! that cannot connect directly.
//!
//! # Protocol Overview
//!
//! The DERP protocol uses binary framing over WebSocket (or raw TCP):
//! - 1 byte: frame type
//! - 4 bytes: payload length (big-endian u32)
//! - N bytes: payload
//!
//! Each client authenticates with a 32-byte node public key. The server
//! routes packets between clients based on destination node keys.
//!
//! # Reference
//!
//! Go implementation: `tailscale.com/derp` package
//! Protocol spec: <https://pkg.go.dev/tailscale.com/derp>

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::sync::{RwLock, mpsc};
use tracing::debug;

// ---------------------------------------------------------------------------
// Node Key
// ---------------------------------------------------------------------------

/// Length of a DERP node public key in bytes.
pub const NODE_KEY_LEN: usize = 32;

/// A 32-byte node public key used to identify DERP clients.
///
/// Corresponds to `key.NodePublic` in the Go implementation.
/// The key is used for routing packets between peers — the relay
/// does not decrypt traffic, it only routes by key.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeKey([u8; NODE_KEY_LEN]);

impl NodeKey {
    /// Creates a new `NodeKey` from a 32-byte array.
    #[must_use]
    pub fn new(bytes: [u8; NODE_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Creates a `NodeKey` from a byte slice.
    ///
    /// Returns `None` if the slice is not exactly 32 bytes.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != NODE_KEY_LEN {
            return None;
        }
        let mut key = [0u8; NODE_KEY_LEN];
        key.copy_from_slice(bytes);
        Some(Self(key))
    }

    /// Returns the key as a byte slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; NODE_KEY_LEN] {
        &self.0
    }

    /// Returns `true` if this is the zero key (all bytes are 0).
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}

impl fmt::Debug for NodeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Show first 4 bytes as hex for readability.
        write!(
            f,
            "NodeKey({:02x}{:02x}{:02x}{:02x}..)",
            self.0[0], self.0[1], self.0[2], self.0[3]
        )
    }
}

impl fmt::Display for NodeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for NodeKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for NodeKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = hex_decode(&s).map_err(serde::de::Error::custom)?;
        NodeKey::from_slice(&bytes)
            .ok_or_else(|| serde::de::Error::custom("node key must be 32 bytes"))
    }
}

/// Decode a hex string to bytes.
fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("hex string must have even length".to_owned());
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    let mut chars = s.chars();
    while let (Some(hi), Some(lo)) = (chars.next(), chars.next()) {
        let hi = hi
            .to_digit(16)
            .ok_or_else(|| format!("invalid hex char: {hi}"))? as u8;
        let lo = lo
            .to_digit(16)
            .ok_or_else(|| format!("invalid hex char: {lo}"))? as u8;
        bytes.push((hi << 4) | lo);
    }
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// Frame Types
// ---------------------------------------------------------------------------

/// DERP protocol frame types.
///
/// These match the Tailscale DERP wire protocol frame type bytes.
/// See `tailscale.com/derp/derp.go` for the canonical definitions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    /// Server sends its public key to the client (server → client).
    ServerKey = 0x01,
    /// Client sends its public key and client info (client → server).
    ClientInfo = 0x02,
    /// Client sends a packet to a specific peer (client → server).
    SendPacket = 0x04,
    /// Server delivers a packet from a peer (server → client).
    RecvPacket = 0x05,
    /// Keep-alive frame (bidirectional).
    KeepAlive = 0x06,
    /// Client indicates this is its preferred DERP server (client → server).
    NotePreferred = 0x07,
    /// Notification that a peer has disconnected (server → client).
    PeerGone = 0x08,
    /// Notification that a peer is present (server → client).
    PeerPresent = 0x09,
    /// Client requests connection change notifications (client → server).
    /// Used by mesh peers to watch for client connects/disconnects.
    WatchConns = 0x10,
    /// Server tells a client to close its connection to a peer (server → client).
    ClosePeer = 0x11,
    /// Server sends a health/ping message (server → client).
    Ping = 0x12,
    /// Client responds to a ping (client → server).
    Pong = 0x13,
    /// Server informs client of its public IP (server → client).
    ServerInfo = 0x14,
}

impl FrameType {
    /// Converts a byte to a `FrameType`.
    ///
    /// Returns `None` for unknown frame type bytes.
    #[must_use]
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::ServerKey),
            0x02 => Some(Self::ClientInfo),
            0x04 => Some(Self::SendPacket),
            0x05 => Some(Self::RecvPacket),
            0x06 => Some(Self::KeepAlive),
            0x07 => Some(Self::NotePreferred),
            0x08 => Some(Self::PeerGone),
            0x09 => Some(Self::PeerPresent),
            0x10 => Some(Self::WatchConns),
            0x11 => Some(Self::ClosePeer),
            0x12 => Some(Self::Ping),
            0x13 => Some(Self::Pong),
            0x14 => Some(Self::ServerInfo),
            _ => None,
        }
    }

    /// Returns the byte representation of this frame type.
    #[must_use]
    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

// ---------------------------------------------------------------------------
// Frame Parsing & Writing
// ---------------------------------------------------------------------------

/// Minimum frame header size: 1 byte type + 4 bytes length.
const FRAME_HEADER_SIZE: usize = 5;

/// Maximum allowed frame payload size (10 MiB).
/// Matches the Go implementation's limit to prevent OOM attacks.
const MAX_FRAME_SIZE: u32 = 10 << 20;

/// Error type for DERP frame parsing.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// The buffer is too small to contain a valid frame header.
    #[error("buffer too small for frame header: need {FRAME_HEADER_SIZE} bytes, got {0}")]
    BufferTooSmall(usize),
    /// Unknown frame type byte.
    #[error("unknown frame type: 0x{0:02x}")]
    UnknownFrameType(u8),
    /// Frame payload exceeds the maximum allowed size.
    #[error("frame payload too large: {0} bytes (max {MAX_FRAME_SIZE})")]
    PayloadTooLarge(u32),
    /// Frame payload is incomplete (buffer doesn't contain full payload).
    #[error("incomplete frame: expected {expected} payload bytes, got {actual}")]
    IncompletePayload { expected: u32, actual: usize },
    /// Invalid payload for the given frame type.
    #[error("invalid payload for {frame_type:?}: {reason}")]
    InvalidPayload {
        frame_type: FrameType,
        reason: String,
    },
}

/// A parsed DERP frame.
#[derive(Clone, Debug)]
pub struct Frame {
    /// The frame type.
    pub frame_type: FrameType,
    /// The frame payload.
    pub payload: Vec<u8>,
}

impl Frame {
    /// Serializes this frame to bytes (type + length + payload).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let payload_len = self.payload.len() as u32;
        let mut buf = Vec::with_capacity(FRAME_HEADER_SIZE + self.payload.len());
        buf.push(self.frame_type.as_byte());
        buf.extend_from_slice(&payload_len.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Creates a `ServerKey` frame containing the server's public key.
    #[must_use]
    pub fn server_key(key: &NodeKey) -> Self {
        Self {
            frame_type: FrameType::ServerKey,
            payload: key.as_bytes().to_vec(),
        }
    }

    /// Creates a `ClientInfo` frame containing the client's public key.
    #[must_use]
    pub fn client_info(key: &NodeKey) -> Self {
        Self {
            frame_type: FrameType::ClientInfo,
            payload: key.as_bytes().to_vec(),
        }
    }

    /// Creates a `SendPacket` frame addressed to a specific destination peer.
    #[must_use]
    pub fn send_packet(dst: &NodeKey, data: &[u8]) -> Self {
        let mut payload = Vec::with_capacity(NODE_KEY_LEN + data.len());
        payload.extend_from_slice(dst.as_bytes());
        payload.extend_from_slice(data);
        Self {
            frame_type: FrameType::SendPacket,
            payload,
        }
    }

    /// Creates a `RecvPacket` frame from a specific source peer.
    #[must_use]
    pub fn recv_packet(src: &NodeKey, data: &[u8]) -> Self {
        let mut payload = Vec::with_capacity(NODE_KEY_LEN + data.len());
        payload.extend_from_slice(src.as_bytes());
        payload.extend_from_slice(data);
        Self {
            frame_type: FrameType::RecvPacket,
            payload,
        }
    }

    /// Creates a `KeepAlive` frame (empty payload).
    #[must_use]
    pub fn keep_alive() -> Self {
        Self {
            frame_type: FrameType::KeepAlive,
            payload: Vec::new(),
        }
    }

    /// Creates a `NotePreferred` frame.
    #[must_use]
    pub fn note_preferred(preferred: bool) -> Self {
        Self {
            frame_type: FrameType::NotePreferred,
            payload: vec![u8::from(preferred)],
        }
    }

    /// Creates a `PeerGone` frame for the specified peer.
    #[must_use]
    pub fn peer_gone(key: &NodeKey) -> Self {
        Self {
            frame_type: FrameType::PeerGone,
            payload: key.as_bytes().to_vec(),
        }
    }

    /// Creates a `PeerPresent` frame for the specified peer.
    #[must_use]
    pub fn peer_present(key: &NodeKey) -> Self {
        Self {
            frame_type: FrameType::PeerPresent,
            payload: key.as_bytes().to_vec(),
        }
    }

    /// Creates a `WatchConns` frame to request connection notifications.
    #[must_use]
    pub fn watch_conns() -> Self {
        Self {
            frame_type: FrameType::WatchConns,
            payload: Vec::new(),
        }
    }

    /// Creates a `Ping` frame with the given 8-byte ping data.
    #[must_use]
    pub fn ping(data: [u8; 8]) -> Self {
        Self {
            frame_type: FrameType::Ping,
            payload: data.to_vec(),
        }
    }

    /// Creates a `Pong` frame echoing the 8-byte ping data.
    #[must_use]
    pub fn pong(data: [u8; 8]) -> Self {
        Self {
            frame_type: FrameType::Pong,
            payload: data.to_vec(),
        }
    }
}

/// Parses a single DERP frame from a byte buffer.
///
/// Returns the parsed frame and the number of bytes consumed from the buffer.
/// Returns `Err` if the buffer is too small, the frame type is unknown, or
/// the payload is too large.
pub fn parse_frame(buf: &[u8]) -> Result<(Frame, usize), FrameError> {
    if buf.len() < FRAME_HEADER_SIZE {
        return Err(FrameError::BufferTooSmall(buf.len()));
    }

    let frame_type_byte = buf[0];
    let frame_type = FrameType::from_byte(frame_type_byte)
        .ok_or(FrameError::UnknownFrameType(frame_type_byte))?;

    let payload_len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    if payload_len > MAX_FRAME_SIZE {
        return Err(FrameError::PayloadTooLarge(payload_len));
    }

    let total_len = FRAME_HEADER_SIZE + payload_len as usize;
    if buf.len() < total_len {
        return Err(FrameError::IncompletePayload {
            expected: payload_len,
            actual: buf.len() - FRAME_HEADER_SIZE,
        });
    }

    let payload = buf[FRAME_HEADER_SIZE..total_len].to_vec();
    Ok((
        Frame {
            frame_type,
            payload,
        },
        total_len,
    ))
}

/// Extracts the destination `NodeKey` and packet data from a `SendPacket` frame payload.
///
/// The payload format is: 32 bytes destination key + remaining packet data.
pub fn parse_send_packet(payload: &[u8]) -> Result<(NodeKey, &[u8]), FrameError> {
    if payload.len() < NODE_KEY_LEN {
        return Err(FrameError::InvalidPayload {
            frame_type: FrameType::SendPacket,
            reason: format!(
                "payload too short for destination key: {} bytes",
                payload.len()
            ),
        });
    }
    let dst = NodeKey::from_slice(&payload[..NODE_KEY_LEN]).ok_or(FrameError::InvalidPayload {
        frame_type: FrameType::SendPacket,
        reason: "invalid destination key length".to_owned(),
    })?;
    Ok((dst, &payload[NODE_KEY_LEN..]))
}

/// Extracts the source `NodeKey` and packet data from a `RecvPacket` frame payload.
///
/// The payload format is: 32 bytes source key + remaining packet data.
pub fn parse_recv_packet(payload: &[u8]) -> Result<(NodeKey, &[u8]), FrameError> {
    if payload.len() < NODE_KEY_LEN {
        return Err(FrameError::InvalidPayload {
            frame_type: FrameType::RecvPacket,
            reason: format!("payload too short for source key: {} bytes", payload.len()),
        });
    }
    let src = NodeKey::from_slice(&payload[..NODE_KEY_LEN]).ok_or(FrameError::InvalidPayload {
        frame_type: FrameType::RecvPacket,
        reason: "invalid source key length".to_owned(),
    })?;
    Ok((src, &payload[NODE_KEY_LEN..]))
}

/// Extracts a `NodeKey` from a `PeerGone` or `PeerPresent` frame payload.
pub fn parse_peer_key(frame_type: FrameType, payload: &[u8]) -> Result<NodeKey, FrameError> {
    NodeKey::from_slice(payload).ok_or(FrameError::InvalidPayload {
        frame_type,
        reason: format!("expected {NODE_KEY_LEN} bytes, got {}", payload.len()),
    })
}

// ---------------------------------------------------------------------------
// DERP Server
// ---------------------------------------------------------------------------

/// Size of the per-client forwarding channel.
const CLIENT_CHANNEL_CAPACITY: usize = 64;

/// Keep-alive interval in seconds.
pub const KEEP_ALIVE_INTERVAL_SECS: u64 = 60;

/// Reason for a peer disconnecting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerGoneReason {
    /// Peer disconnected normally.
    Disconnected,
    /// Peer was not found (packet could not be delivered).
    NotHere,
}

/// A connected DERP client on the server.
struct DerpClient {
    /// The client's node public key.
    key: NodeKey,
    /// Channel to send frames to this client's WebSocket writer.
    sender: mpsc::Sender<Frame>,
    /// Whether this is the client's preferred DERP server.
    preferred: bool,
    /// When the client connected.
    connected_at: OffsetDateTime,
}

/// Watcher state for mesh peers that have requested connection notifications.
struct ConnWatcher {
    /// Channel to send peer present/gone notifications.
    sender: mpsc::Sender<Frame>,
}

/// The DERP relay server that manages client connections and routes packets.
///
/// This is the core relay component. It maintains a map of connected clients
/// indexed by their node public key and routes `SendPacket` frames to the
/// appropriate destination client as `RecvPacket` frames.
///
/// # Mesh Networking
///
/// The server supports mesh networking through connection watchers. When a
/// mesh peer registers via `WatchConns`, it receives notifications whenever
/// clients connect or disconnect. This allows mesh peers to maintain a
/// forwarding table and route packets between DERP servers.
pub struct DerpServer {
    /// The server's own node key (used in the handshake).
    server_key: NodeKey,
    /// Connected clients indexed by their node key.
    clients: RwLock<HashMap<NodeKey, DerpClient>>,
    /// Mesh watchers that receive connect/disconnect notifications.
    watchers: RwLock<HashMap<NodeKey, ConnWatcher>>,
    /// Mesh packet forwarders: destination key → sender to the mesh peer
    /// that can reach that destination.
    mesh_forwarders: RwLock<HashMap<NodeKey, mpsc::Sender<Frame>>>,
}

impl DerpServer {
    /// Creates a new DERP server with the given server key.
    #[must_use]
    pub fn new(server_key: NodeKey) -> Arc<Self> {
        Arc::new(Self {
            server_key,
            clients: RwLock::new(HashMap::new()),
            watchers: RwLock::new(HashMap::new()),
            mesh_forwarders: RwLock::new(HashMap::new()),
        })
    }

    /// Returns the server's public key.
    #[must_use]
    pub fn server_key(&self) -> &NodeKey {
        &self.server_key
    }

    /// Registers a new client connection and returns a receiver for frames
    /// addressed to this client.
    ///
    /// If a client with the same key is already connected, the old connection
    /// is replaced (its sender is dropped, which will cause its writer task
    /// to terminate).
    pub async fn accept_client(&self, key: NodeKey) -> mpsc::Receiver<Frame> {
        let (tx, rx) = mpsc::channel(CLIENT_CHANNEL_CAPACITY);

        let client = DerpClient {
            key,
            sender: tx,
            preferred: false,
            connected_at: OffsetDateTime::now_utc(),
        };

        {
            let mut clients = self.clients.write().await;
            clients.insert(key, client);
        }

        // Notify watchers that this peer is now present.
        self.notify_watchers(Frame::peer_present(&key)).await;

        debug!(key = %key, "DERP client connected");
        rx
    }

    /// Removes a client connection and notifies watchers.
    pub async fn remove_client(&self, key: &NodeKey) {
        {
            let mut clients = self.clients.write().await;
            clients.remove(key);
        }
        {
            let mut watchers = self.watchers.write().await;
            watchers.remove(key);
        }

        // Notify remaining watchers that this peer is gone.
        self.notify_watchers(Frame::peer_gone(key)).await;

        debug!(key = %key, "DERP client disconnected");
    }

    /// Routes a packet from `src` to `dst`.
    ///
    /// If the destination client is connected locally, the packet is delivered
    /// directly. If not, the packet is forwarded to any mesh peer that has
    /// registered as a forwarder for the destination key.
    ///
    /// Returns `true` if the packet was queued for delivery.
    pub async fn send_packet(&self, src: &NodeKey, dst: &NodeKey, data: &[u8]) -> bool {
        // Try local delivery first.
        {
            let clients = self.clients.read().await;
            if let Some(client) = clients.get(dst) {
                let frame = Frame::recv_packet(src, data);
                return client.sender.try_send(frame).is_ok();
            }
        }

        // Try mesh forwarding.
        {
            let forwarders = self.mesh_forwarders.read().await;
            if let Some(forwarder) = forwarders.get(dst) {
                let frame = Frame::send_packet(dst, data);
                return forwarder.try_send(frame).is_ok();
            }
        }

        false
    }

    /// Sends a pre-built frame directly to a client's channel without wrapping
    /// it in a `RecvPacket`. Use this for control frames like `KeepAlive` and
    /// `Pong` that should be delivered as-is to the client.
    ///
    /// Returns `true` if the frame was queued for delivery.
    pub async fn send_raw_frame(&self, dst: &NodeKey, frame: Frame) -> bool {
        let clients = self.clients.read().await;
        if let Some(client) = clients.get(dst) {
            return client.sender.try_send(frame).is_ok();
        }
        false
    }

    /// Marks a client's preferred DERP status.
    pub async fn note_preferred(&self, key: &NodeKey, preferred: bool) {
        let mut clients = self.clients.write().await;
        if let Some(client) = clients.get_mut(key) {
            client.preferred = preferred;
        }
    }

    /// Registers a watcher for connection notifications (used by mesh peers).
    ///
    /// The watcher receives `PeerPresent` frames for all currently connected
    /// clients, then ongoing `PeerPresent`/`PeerGone` notifications.
    pub async fn watch_conns(&self, watcher_key: NodeKey) -> mpsc::Receiver<Frame> {
        let (tx, rx) = mpsc::channel(CLIENT_CHANNEL_CAPACITY);

        // Send current client list to the new watcher.
        {
            let clients = self.clients.read().await;
            for client_key in clients.keys() {
                let _ = tx.try_send(Frame::peer_present(client_key));
            }
        }

        {
            let mut watchers = self.watchers.write().await;
            watchers.insert(watcher_key, ConnWatcher { sender: tx });
        }

        debug!(watcher = %watcher_key, "DERP mesh watcher registered");
        rx
    }

    /// Adds a mesh packet forwarder for a specific destination key.
    ///
    /// When the server receives a `SendPacket` for a destination that is not
    /// connected locally, it will forward the packet to this forwarder.
    pub async fn add_packet_forwarder(&self, dst: NodeKey, sender: mpsc::Sender<Frame>) {
        let mut forwarders = self.mesh_forwarders.write().await;
        forwarders.insert(dst, sender);
    }

    /// Removes a mesh packet forwarder for a specific destination key.
    pub async fn remove_packet_forwarder(&self, dst: &NodeKey) {
        let mut forwarders = self.mesh_forwarders.write().await;
        forwarders.remove(dst);
    }

    /// Returns the number of currently connected clients.
    pub async fn client_count(&self) -> usize {
        let clients = self.clients.read().await;
        clients.len()
    }

    /// Returns whether a specific client is connected.
    pub async fn has_client(&self, key: &NodeKey) -> bool {
        let clients = self.clients.read().await;
        clients.contains_key(key)
    }

    /// Returns a snapshot of connected client keys and their connection times.
    pub async fn connected_clients(&self) -> Vec<(NodeKey, OffsetDateTime)> {
        let clients = self.clients.read().await;
        clients.values().map(|c| (c.key, c.connected_at)).collect()
    }

    /// Sends a frame to all registered connection watchers.
    async fn notify_watchers(&self, frame: Frame) {
        let watchers = self.watchers.read().await;
        for watcher in watchers.values() {
            // Best-effort delivery — drop if watcher buffer is full.
            let _ = watcher.sender.try_send(frame.clone());
        }
    }
}

// ---------------------------------------------------------------------------
// DERP Mesh
// ---------------------------------------------------------------------------

/// Manages mesh connections between multiple DERP servers.
///
/// When multiple DERP servers are deployed, they form a mesh so that a
/// client connected to one server can send packets to a client connected
/// to another server. The mesh works by:
///
/// 1. Each server connects to other servers as a DERP client
/// 2. The mesh client sends `WatchConns` to receive peer notifications
/// 3. When a peer connects to the remote server, the mesh registers a
///    packet forwarder so the local server can route to that peer
/// 4. Packets destined for remote peers are forwarded through the mesh
pub struct DerpMesh {
    /// The local DERP server to add forwarders to.
    server: Arc<DerpServer>,
    /// Active mesh peer addresses and their cancellation senders.
    active: RwLock<HashMap<String, mpsc::Sender<()>>>,
}

impl DerpMesh {
    /// Creates a new mesh manager for the given DERP server.
    #[must_use]
    pub fn new(server: Arc<DerpServer>) -> Arc<Self> {
        Arc::new(Self {
            server,
            active: RwLock::new(HashMap::new()),
        })
    }

    /// Updates the set of mesh peer addresses.
    ///
    /// Performs a diff against the current active set: new addresses are
    /// added, removed addresses are cancelled.
    pub async fn set_addresses(&self, addresses: &[String]) {
        let desired: std::collections::HashSet<&str> =
            addresses.iter().map(String::as_str).collect();

        // Remove addresses that are no longer in the set.
        {
            let mut active = self.active.write().await;
            let to_remove: Vec<String> = active
                .keys()
                .filter(|addr| !desired.contains(addr.as_str()))
                .cloned()
                .collect();
            for addr in to_remove {
                if let Some(cancel_tx) = active.remove(&addr) {
                    // Signal cancellation by dropping or sending.
                    let _ = cancel_tx.try_send(());
                    debug!(address = %addr, "removed DERP mesh peer");
                }
            }
        }

        // Add new addresses.
        for addr in addresses {
            let active = self.active.read().await;
            if active.contains_key(addr) {
                continue;
            }
            drop(active);

            let (cancel_tx, cancel_rx) = mpsc::channel(1);
            {
                let mut active = self.active.write().await;
                active.insert(addr.clone(), cancel_tx);
            }
            debug!(address = %addr, "added DERP mesh peer");

            // Spawn background task to maintain the mesh connection.
            let server = self.server.clone();
            let address = addr.clone();
            tokio::spawn(async move {
                run_mesh_connection(server, address, cancel_rx).await;
            });
        }
    }

    /// Returns the number of active mesh peer connections.
    pub async fn peer_count(&self) -> usize {
        let active = self.active.read().await;
        active.len()
    }

    /// Closes all mesh connections.
    pub async fn close(&self) {
        let mut active = self.active.write().await;
        for (addr, cancel_tx) in active.drain() {
            let _ = cancel_tx.try_send(());
            debug!(address = %addr, "closed DERP mesh connection");
        }
    }
}

/// Background task that maintains a mesh connection to a remote DERP server.
///
/// This task:
/// 1. Connects to the remote DERP server
/// 2. Sends `WatchConns` to receive peer notifications
/// 3. When a peer connects to the remote server, registers a forwarder
/// 4. When a peer disconnects, removes the forwarder
/// 5. Forwards any packets that the local server can't deliver locally
///
/// The task runs until cancelled or the connection is lost.
async fn run_mesh_connection(
    server: Arc<DerpServer>,
    address: String,
    mut cancel_rx: mpsc::Receiver<()>,
) {
    debug!(address = %address, "starting DERP mesh connection");

    // In a full implementation, this would establish a WebSocket connection
    // to the remote DERP server, send WatchConns, and process notifications.
    // For now, we track the address and handle cancellation cleanly.
    //
    // The mesh protocol flow is:
    // 1. Connect to remote /derp endpoint via WebSocket
    // 2. Exchange ServerKey/ClientInfo
    // 3. Send WatchConns frame
    // 4. For each PeerPresent received: add_packet_forwarder(key, sender)
    // 5. For each PeerGone received: remove_packet_forwarder(key)
    // 6. Forward any SendPacket frames that arrive on the forwarding channel

    // Wait for cancellation.
    let _ = cancel_rx.recv().await;
    debug!(address = %address, "DERP mesh connection cancelled");
    drop(server);
}

// ---------------------------------------------------------------------------
// Server Info / Debug
// ---------------------------------------------------------------------------

/// Snapshot of a connected DERP client for debugging/monitoring.
#[derive(Clone, Debug, Serialize)]
pub struct DerpClientInfo {
    /// The client's node key (hex-encoded).
    pub key: String,
    /// Whether this is the client's preferred DERP server.
    pub preferred: bool,
    /// When the client connected.
    #[serde(with = "time::serde::rfc3339")]
    pub connected_at: OffsetDateTime,
}

/// Snapshot of the DERP server state for debugging/monitoring.
#[derive(Clone, Debug, Serialize)]
pub struct DerpServerInfo {
    /// Server's public key (hex-encoded).
    pub server_key: String,
    /// Number of connected clients.
    pub client_count: usize,
    /// Number of active mesh watchers.
    pub watcher_count: usize,
    /// Number of mesh packet forwarders.
    pub forwarder_count: usize,
    /// Connected client details.
    pub clients: Vec<DerpClientInfo>,
}

impl DerpServer {
    /// Returns a debug snapshot of the server state.
    pub async fn info(&self) -> DerpServerInfo {
        let clients = self.clients.read().await;
        let watchers = self.watchers.read().await;
        let forwarders = self.mesh_forwarders.read().await;

        let client_infos: Vec<DerpClientInfo> = clients
            .values()
            .map(|c| DerpClientInfo {
                key: c.key.to_string(),
                preferred: c.preferred,
                connected_at: c.connected_at,
            })
            .collect();

        DerpServerInfo {
            server_key: self.server_key.to_string(),
            client_count: clients.len(),
            watcher_count: watchers.len(),
            forwarder_count: forwarders.len(),
            clients: client_infos,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // -- NodeKey tests -------------------------------------------------------

    #[test]
    fn node_key_roundtrip() {
        let bytes = [42u8; NODE_KEY_LEN];
        let key = NodeKey::new(bytes);
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn node_key_from_slice_valid() {
        let bytes = vec![1u8; NODE_KEY_LEN];
        let key = NodeKey::from_slice(&bytes);
        assert!(key.is_some());
    }

    #[test]
    fn node_key_from_slice_invalid_length() {
        let short = vec![1u8; 16];
        assert!(NodeKey::from_slice(&short).is_none());

        let long = vec![1u8; 64];
        assert!(NodeKey::from_slice(&long).is_none());
    }

    #[test]
    fn node_key_is_zero() {
        let zero = NodeKey::new([0u8; NODE_KEY_LEN]);
        assert!(zero.is_zero());

        let non_zero = NodeKey::new([1u8; NODE_KEY_LEN]);
        assert!(!non_zero.is_zero());
    }

    #[test]
    fn node_key_display_hex() {
        let mut bytes = [0u8; NODE_KEY_LEN];
        bytes[0] = 0xab;
        bytes[1] = 0xcd;
        let key = NodeKey::new(bytes);
        let display = key.to_string();
        assert!(display.starts_with("abcd"));
        assert_eq!(display.len(), 64); // 32 bytes * 2 hex chars
    }

    #[test]
    fn node_key_equality() {
        let key1 = NodeKey::new([1u8; NODE_KEY_LEN]);
        let key2 = NodeKey::new([1u8; NODE_KEY_LEN]);
        let key3 = NodeKey::new([2u8; NODE_KEY_LEN]);
        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    // -- Frame parsing/writing tests -----------------------------------------

    #[test]
    fn frame_roundtrip_keep_alive() {
        let frame = Frame::keep_alive();
        let bytes = frame.to_bytes();
        let (parsed, consumed) = parse_frame(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.frame_type, FrameType::KeepAlive);
        assert!(parsed.payload.is_empty());
    }

    #[test]
    fn frame_roundtrip_server_key() {
        let key = NodeKey::new([0xaa; NODE_KEY_LEN]);
        let frame = Frame::server_key(&key);
        let bytes = frame.to_bytes();
        let (parsed, consumed) = parse_frame(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.frame_type, FrameType::ServerKey);
        assert_eq!(parsed.payload.len(), NODE_KEY_LEN);
        assert_eq!(&parsed.payload, key.as_bytes().as_slice());
    }

    #[test]
    fn frame_roundtrip_send_packet() {
        let dst = NodeKey::new([0xbb; NODE_KEY_LEN]);
        let data = b"encrypted wireguard data";
        let frame = Frame::send_packet(&dst, data);
        let bytes = frame.to_bytes();
        let (parsed, consumed) = parse_frame(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.frame_type, FrameType::SendPacket);

        let (parsed_dst, parsed_data) = parse_send_packet(&parsed.payload).unwrap();
        assert_eq!(parsed_dst, dst);
        assert_eq!(parsed_data, data);
    }

    #[test]
    fn frame_roundtrip_recv_packet() {
        let src = NodeKey::new([0xcc; NODE_KEY_LEN]);
        let data = b"response packet";
        let frame = Frame::recv_packet(&src, data);
        let bytes = frame.to_bytes();
        let (parsed, _) = parse_frame(&bytes).unwrap();
        assert_eq!(parsed.frame_type, FrameType::RecvPacket);

        let (parsed_src, parsed_data) = parse_recv_packet(&parsed.payload).unwrap();
        assert_eq!(parsed_src, src);
        assert_eq!(parsed_data, data);
    }

    #[test]
    fn frame_roundtrip_peer_gone() {
        let key = NodeKey::new([0xdd; NODE_KEY_LEN]);
        let frame = Frame::peer_gone(&key);
        let bytes = frame.to_bytes();
        let (parsed, _) = parse_frame(&bytes).unwrap();
        assert_eq!(parsed.frame_type, FrameType::PeerGone);

        let parsed_key = parse_peer_key(FrameType::PeerGone, &parsed.payload).unwrap();
        assert_eq!(parsed_key, key);
    }

    #[test]
    fn frame_roundtrip_peer_present() {
        let key = NodeKey::new([0xee; NODE_KEY_LEN]);
        let frame = Frame::peer_present(&key);
        let bytes = frame.to_bytes();
        let (parsed, _) = parse_frame(&bytes).unwrap();
        assert_eq!(parsed.frame_type, FrameType::PeerPresent);

        let parsed_key = parse_peer_key(FrameType::PeerPresent, &parsed.payload).unwrap();
        assert_eq!(parsed_key, key);
    }

    #[test]
    fn frame_roundtrip_note_preferred() {
        let frame = Frame::note_preferred(true);
        let bytes = frame.to_bytes();
        let (parsed, _) = parse_frame(&bytes).unwrap();
        assert_eq!(parsed.frame_type, FrameType::NotePreferred);
        assert_eq!(parsed.payload, vec![1u8]);
    }

    #[test]
    fn frame_roundtrip_ping_pong() {
        let ping_data = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let ping = Frame::ping(ping_data);
        let bytes = ping.to_bytes();
        let (parsed, _) = parse_frame(&bytes).unwrap();
        assert_eq!(parsed.frame_type, FrameType::Ping);
        assert_eq!(parsed.payload, ping_data);

        let pong = Frame::pong(ping_data);
        let bytes = pong.to_bytes();
        let (parsed, _) = parse_frame(&bytes).unwrap();
        assert_eq!(parsed.frame_type, FrameType::Pong);
        assert_eq!(parsed.payload, ping_data);
    }

    #[test]
    fn parse_frame_buffer_too_small() {
        let buf = [0u8; 3]; // Need at least 5 bytes for header.
        let err = parse_frame(&buf).unwrap_err();
        assert!(matches!(err, FrameError::BufferTooSmall(3)));
    }

    #[test]
    fn parse_frame_unknown_type() {
        let buf = [0xFF, 0, 0, 0, 0]; // Unknown type 0xFF with 0-length payload.
        let err = parse_frame(&buf).unwrap_err();
        assert!(matches!(err, FrameError::UnknownFrameType(0xFF)));
    }

    #[test]
    fn parse_frame_payload_too_large() {
        // Frame type 0x06 (KeepAlive) with payload length > MAX_FRAME_SIZE.
        let mut buf = vec![0x06];
        buf.extend_from_slice(&(MAX_FRAME_SIZE + 1).to_be_bytes());
        let err = parse_frame(&buf).unwrap_err();
        assert!(matches!(err, FrameError::PayloadTooLarge(_)));
    }

    #[test]
    fn parse_frame_incomplete_payload() {
        // Frame header says 10 bytes payload but only 5 are present.
        let mut buf = vec![0x06]; // KeepAlive
        buf.extend_from_slice(&10u32.to_be_bytes());
        buf.extend_from_slice(&[0u8; 5]);
        let err = parse_frame(&buf).unwrap_err();
        assert!(matches!(
            err,
            FrameError::IncompletePayload {
                expected: 10,
                actual: 5
            }
        ));
    }

    #[test]
    fn parse_send_packet_too_short() {
        let short_payload = vec![0u8; 16]; // Need at least 32 bytes for key.
        let err = parse_send_packet(&short_payload).unwrap_err();
        assert!(matches!(err, FrameError::InvalidPayload { .. }));
    }

    #[test]
    fn frame_type_roundtrip_all() {
        let types = [
            (0x01, FrameType::ServerKey),
            (0x02, FrameType::ClientInfo),
            (0x04, FrameType::SendPacket),
            (0x05, FrameType::RecvPacket),
            (0x06, FrameType::KeepAlive),
            (0x07, FrameType::NotePreferred),
            (0x08, FrameType::PeerGone),
            (0x09, FrameType::PeerPresent),
            (0x10, FrameType::WatchConns),
            (0x11, FrameType::ClosePeer),
            (0x12, FrameType::Ping),
            (0x13, FrameType::Pong),
            (0x14, FrameType::ServerInfo),
        ];
        for (byte, expected) in types {
            let ft = FrameType::from_byte(byte).unwrap();
            assert_eq!(ft, expected);
            assert_eq!(ft.as_byte(), byte);
        }
    }

    // -- DerpServer tests ----------------------------------------------------

    #[tokio::test]
    async fn server_accept_and_remove_client() {
        let server_key = NodeKey::new([1u8; NODE_KEY_LEN]);
        let server = DerpServer::new(server_key);

        let client_key = NodeKey::new([2u8; NODE_KEY_LEN]);
        let _rx = server.accept_client(client_key).await;
        assert_eq!(server.client_count().await, 1);
        assert!(server.has_client(&client_key).await);

        server.remove_client(&client_key).await;
        assert_eq!(server.client_count().await, 0);
        assert!(!server.has_client(&client_key).await);
    }

    #[tokio::test]
    async fn server_send_packet_to_connected_peer() {
        let server_key = NodeKey::new([1u8; NODE_KEY_LEN]);
        let server = DerpServer::new(server_key);

        let alice = NodeKey::new([2u8; NODE_KEY_LEN]);
        let bob = NodeKey::new([3u8; NODE_KEY_LEN]);

        let _alice_rx = server.accept_client(alice).await;
        let mut bob_rx = server.accept_client(bob).await;

        // Alice sends to Bob.
        let delivered = server.send_packet(&alice, &bob, b"hello bob").await;
        assert!(delivered);

        // Bob should receive the packet.
        let frame = tokio::time::timeout(std::time::Duration::from_millis(100), bob_rx.recv())
            .await
            .ok()
            .flatten();
        assert!(frame.is_some());
        let frame = frame.unwrap();
        assert_eq!(frame.frame_type, FrameType::RecvPacket);

        let (src, data) = parse_recv_packet(&frame.payload).unwrap();
        assert_eq!(src, alice);
        assert_eq!(data, b"hello bob");
    }

    #[tokio::test]
    async fn server_send_packet_to_unknown_peer_returns_false() {
        let server_key = NodeKey::new([1u8; NODE_KEY_LEN]);
        let server = DerpServer::new(server_key);

        let alice = NodeKey::new([2u8; NODE_KEY_LEN]);
        let unknown = NodeKey::new([99u8; NODE_KEY_LEN]);

        let _alice_rx = server.accept_client(alice).await;

        let delivered = server.send_packet(&alice, &unknown, b"hello?").await;
        assert!(!delivered);
    }

    #[tokio::test]
    async fn server_peer_notifications_to_watchers() {
        let server_key = NodeKey::new([1u8; NODE_KEY_LEN]);
        let server = DerpServer::new(server_key);

        let watcher_key = NodeKey::new([10u8; NODE_KEY_LEN]);
        let mut watcher_rx = server.watch_conns(watcher_key).await;

        // Connect a client — watcher should be notified.
        let client_key = NodeKey::new([20u8; NODE_KEY_LEN]);
        let _client_rx = server.accept_client(client_key).await;

        let notification =
            tokio::time::timeout(std::time::Duration::from_millis(100), watcher_rx.recv())
                .await
                .ok()
                .flatten();
        assert!(notification.is_some());
        let frame = notification.unwrap();
        assert_eq!(frame.frame_type, FrameType::PeerPresent);
        let key = parse_peer_key(FrameType::PeerPresent, &frame.payload).unwrap();
        assert_eq!(key, client_key);

        // Disconnect the client — watcher should be notified.
        server.remove_client(&client_key).await;

        let notification =
            tokio::time::timeout(std::time::Duration::from_millis(100), watcher_rx.recv())
                .await
                .ok()
                .flatten();
        assert!(notification.is_some());
        let frame = notification.unwrap();
        assert_eq!(frame.frame_type, FrameType::PeerGone);
        let key = parse_peer_key(FrameType::PeerGone, &frame.payload).unwrap();
        assert_eq!(key, client_key);
    }

    #[tokio::test]
    async fn server_watch_conns_sends_existing_clients() {
        let server_key = NodeKey::new([1u8; NODE_KEY_LEN]);
        let server = DerpServer::new(server_key);

        // Connect two clients first.
        let client1 = NodeKey::new([2u8; NODE_KEY_LEN]);
        let client2 = NodeKey::new([3u8; NODE_KEY_LEN]);
        let _rx1 = server.accept_client(client1).await;
        let _rx2 = server.accept_client(client2).await;

        // Then start watching — should get PeerPresent for both.
        let watcher_key = NodeKey::new([10u8; NODE_KEY_LEN]);
        let mut watcher_rx = server.watch_conns(watcher_key).await;

        let mut received_keys = std::collections::HashSet::new();
        for _ in 0..2 {
            let notification =
                tokio::time::timeout(std::time::Duration::from_millis(100), watcher_rx.recv())
                    .await
                    .ok()
                    .flatten();
            assert!(notification.is_some());
            let frame = notification.unwrap();
            assert_eq!(frame.frame_type, FrameType::PeerPresent);
            let key = parse_peer_key(FrameType::PeerPresent, &frame.payload).unwrap();
            received_keys.insert(key);
        }
        assert!(received_keys.contains(&client1));
        assert!(received_keys.contains(&client2));
    }

    #[tokio::test]
    async fn server_note_preferred() {
        let server_key = NodeKey::new([1u8; NODE_KEY_LEN]);
        let server = DerpServer::new(server_key);

        let client_key = NodeKey::new([2u8; NODE_KEY_LEN]);
        let _rx = server.accept_client(client_key).await;

        server.note_preferred(&client_key, true).await;

        let info = server.info().await;
        assert_eq!(info.clients.len(), 1);
        assert!(info.clients[0].preferred);
    }

    #[tokio::test]
    async fn server_replace_existing_client() {
        let server_key = NodeKey::new([1u8; NODE_KEY_LEN]);
        let server = DerpServer::new(server_key);

        let client_key = NodeKey::new([2u8; NODE_KEY_LEN]);
        let _old_rx = server.accept_client(client_key).await;
        assert_eq!(server.client_count().await, 1);

        // Re-register with same key replaces old connection.
        let _new_rx = server.accept_client(client_key).await;
        assert_eq!(server.client_count().await, 1);
    }

    #[tokio::test]
    async fn server_info_snapshot() {
        let server_key = NodeKey::new([1u8; NODE_KEY_LEN]);
        let server = DerpServer::new(server_key);

        let client1 = NodeKey::new([2u8; NODE_KEY_LEN]);
        let client2 = NodeKey::new([3u8; NODE_KEY_LEN]);
        let _rx1 = server.accept_client(client1).await;
        let _rx2 = server.accept_client(client2).await;

        let info = server.info().await;
        assert_eq!(info.server_key, server_key.to_string());
        assert_eq!(info.client_count, 2);
        assert_eq!(info.clients.len(), 2);
    }

    #[tokio::test]
    async fn server_mesh_forwarder() {
        let server_key = NodeKey::new([1u8; NODE_KEY_LEN]);
        let server = DerpServer::new(server_key);

        let src = NodeKey::new([2u8; NODE_KEY_LEN]);
        let remote_dst = NodeKey::new([3u8; NODE_KEY_LEN]);

        let (tx, mut rx) = mpsc::channel(16);
        server.add_packet_forwarder(remote_dst, tx).await;

        // Sending to remote_dst should go through the forwarder.
        let delivered = server.send_packet(&src, &remote_dst, b"mesh packet").await;
        assert!(delivered);

        let frame = tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv())
            .await
            .ok()
            .flatten();
        assert!(frame.is_some());
        let frame = frame.unwrap();
        assert_eq!(frame.frame_type, FrameType::SendPacket);

        // Remove forwarder — should no longer deliver.
        server.remove_packet_forwarder(&remote_dst).await;
        let delivered = server.send_packet(&src, &remote_dst, b"lost packet").await;
        assert!(!delivered);
    }

    #[tokio::test]
    async fn server_send_raw_frame_delivers_without_wrapping() {
        let server_key = NodeKey::new([1u8; NODE_KEY_LEN]);
        let server = DerpServer::new(server_key);

        let alice = NodeKey::new([2u8; NODE_KEY_LEN]);
        let mut alice_rx = server.accept_client(alice).await;

        // send_raw_frame should deliver a KeepAlive as-is (not wrapped in RecvPacket).
        let ka = Frame::keep_alive();
        let delivered = server.send_raw_frame(&alice, ka).await;
        assert!(delivered);

        let frame = tokio::time::timeout(std::time::Duration::from_millis(100), alice_rx.recv())
            .await
            .ok()
            .flatten();
        assert!(frame.is_some());
        let frame = frame.unwrap();
        assert_eq!(frame.frame_type, FrameType::KeepAlive);
        assert!(frame.payload.is_empty());

        // send_raw_frame to unknown peer returns false.
        let unknown = NodeKey::new([99u8; NODE_KEY_LEN]);
        let delivered = server.send_raw_frame(&unknown, Frame::keep_alive()).await;
        assert!(!delivered);
    }

    // -- DerpMesh tests ------------------------------------------------------

    #[tokio::test]
    async fn mesh_set_addresses_add_and_remove() {
        let server_key = NodeKey::new([1u8; NODE_KEY_LEN]);
        let server = DerpServer::new(server_key);
        let mesh = DerpMesh::new(server);

        mesh.set_addresses(&[
            "http://derp1.example.com/derp".to_owned(),
            "http://derp2.example.com/derp".to_owned(),
        ])
        .await;
        assert_eq!(mesh.peer_count().await, 2);

        // Remove one, add another.
        mesh.set_addresses(&[
            "http://derp2.example.com/derp".to_owned(),
            "http://derp3.example.com/derp".to_owned(),
        ])
        .await;
        assert_eq!(mesh.peer_count().await, 2);

        // Remove all.
        mesh.set_addresses(&[]).await;
        assert_eq!(mesh.peer_count().await, 0);
    }

    #[tokio::test]
    async fn mesh_close_removes_all() {
        let server_key = NodeKey::new([1u8; NODE_KEY_LEN]);
        let server = DerpServer::new(server_key);
        let mesh = DerpMesh::new(server);

        mesh.set_addresses(&[
            "http://derp1.example.com/derp".to_owned(),
            "http://derp2.example.com/derp".to_owned(),
        ])
        .await;
        assert_eq!(mesh.peer_count().await, 2);

        mesh.close().await;
        assert_eq!(mesh.peer_count().await, 0);
    }

    // -- Hex decode tests ----------------------------------------------------

    #[test]
    fn hex_decode_valid() {
        let bytes = hex_decode("abcd0102").unwrap();
        assert_eq!(bytes, vec![0xab, 0xcd, 0x01, 0x02]);
    }

    #[test]
    fn hex_decode_odd_length() {
        assert!(hex_decode("abc").is_err());
    }

    #[test]
    fn hex_decode_invalid_char() {
        assert!(hex_decode("zzzz").is_err());
    }
}
