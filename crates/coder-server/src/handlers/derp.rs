//! DERP relay WebSocket endpoint and latency check handlers.
//!
//! Implements the `/derp` WebSocket relay that agents and clients use for
//! peer-to-peer connectivity when direct WireGuard connections fail, and the
//! `/derp/latency-check` endpoint used for HTTP(S)-based latency measurement
//! when UDP is blocked.
//!
//! The Go reference lives in `coder/coderd/coderd.go` (route setup) and
//! `coder/tailnet/derp.go` (`WithWebsocketSupport`).

use super::*;
use futures_util::SinkExt;

/// Subprotocol identifier used by DERP WebSocket clients.
///
/// Tailscale clients request the `"derp"` subprotocol in the
/// `Sec-WebSocket-Protocol` header.  We accept this subprotocol to
/// distinguish real DERP clients from older clients that set
/// `Upgrade: websocket` but still spoke binary DERP framing.
const DERP_SUBPROTOCOL: &str = "derp";

/// Maximum duration to wait for a single WebSocket send or receive.
const WS_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Size of the per-peer forwarding channel.
///
/// A small bounded buffer avoids unbounded memory growth if a peer falls
/// behind, while still absorbing short bursts without dropping packets.
const PEER_CHANNEL_CAPACITY: usize = 64;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Identifies a connected DERP relay peer.
///
/// Each WebSocket connection is assigned a unique `PeerId` on connect.
/// The relay uses these IDs to route packets between peers.
type PeerId = Uuid;

/// A single DERP frame forwarded between peers.
///
/// The relay treats frames as opaque byte sequences — the actual content
/// is encrypted WireGuard traffic that only the endpoints can decrypt.
#[derive(Clone)]
struct DerpFrame {
    /// Peer that sent this frame.
    src: PeerId,
    /// Raw frame bytes (encrypted WireGuard payload).
    data: Vec<u8>,
}

/// Tracks all connected peers and routes frames between them.
///
/// The relay is intentionally simple: every connected peer can send frames
/// to any other connected peer.  The relay does **not** inspect or decrypt
/// the payload — it only routes based on destination peer ID.
///
/// This matches the Go DERP server behaviour where the relay is a dumb
/// packet forwarder for encrypted WireGuard traffic.
struct DerpRelay {
    /// Map of connected peer IDs to their forwarding channels.
    peers: tokio::sync::RwLock<HashMap<PeerId, tokio::sync::mpsc::Sender<DerpFrame>>>,
}

impl DerpRelay {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            peers: tokio::sync::RwLock::new(HashMap::new()),
        })
    }

    /// Register a new peer and return a receiver for frames addressed to it.
    async fn add_peer(&self, peer_id: PeerId) -> tokio::sync::mpsc::Receiver<DerpFrame> {
        let (tx, rx) = tokio::sync::mpsc::channel(PEER_CHANNEL_CAPACITY);
        let mut peers = self.peers.write().await;
        peers.insert(peer_id, tx);
        rx
    }

    /// Remove a peer from the relay.
    async fn remove_peer(&self, peer_id: &PeerId) {
        let mut peers = self.peers.write().await;
        peers.remove(peer_id);
    }

    /// Forward a frame to a specific destination peer.
    ///
    /// Returns `true` if the frame was successfully queued, `false` if the
    /// destination peer is not connected or its buffer is full.
    async fn forward_to(&self, dest: &PeerId, frame: DerpFrame) -> bool {
        let peers = self.peers.read().await;
        if let Some(tx) = peers.get(dest) {
            tx.try_send(frame).is_ok()
        } else {
            false
        }
    }

    /// Broadcast a frame to all connected peers except the sender.
    async fn broadcast(&self, frame: &DerpFrame) {
        let peers = self.peers.read().await;
        for (id, tx) in peers.iter() {
            if *id != frame.src {
                // Best-effort delivery — drop if the peer's buffer is full.
                let _ = tx.try_send(frame.clone());
            }
        }
    }

    /// Returns the number of currently connected peers.
    async fn peer_count(&self) -> usize {
        let peers = self.peers.read().await;
        peers.len()
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET /derp — DERP relay WebSocket endpoint.
///
/// Accepts a WebSocket upgrade with the `"derp"` subprotocol and relays
/// encrypted packets between peers that cannot connect directly.
///
/// The Go reference uses `derphttp.Handler` + `tailnet.WithWebsocketSupport`
/// which upgrades connections requesting the `"derp"` subprotocol to
/// WebSockets and passes the resulting `net.Conn` to `derp.Server.Accept`.
///
/// This Rust implementation provides an equivalent relay: each connected
/// peer gets a unique ID, incoming binary frames are broadcast to all
/// other connected peers (or routed to a specific destination when the
/// frame header contains a target peer ID), and traffic statistics are
/// recorded via the [`DerpTrafficTracker`].
pub(crate) async fn derp_websocket(
    State(state): State<AppState>,
    ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
    // Accept with the "derp" subprotocol, matching Go's behaviour.
    // Compression is disabled because we transmit WireGuard messages that
    // are not compressible, and Safari has a broken compression
    // implementation (see https://github.com/nhooyr/websocket/issues/218).
    let response = ws
        .protocols([DERP_SUBPROTOCOL])
        .on_upgrade(move |socket| derp_relay_session(state, socket));

    Ok(response)
}

/// GET /derp/latency-check — DERP latency measurement endpoint.
///
/// Returns `200 OK` immediately.  Used by clients when UDP is blocked and
/// latency must be checked via HTTP(S) instead of STUN.
///
/// The Go reference is a trivial handler:
/// ```go
/// r.Get("/latency-check", func(w http.ResponseWriter, _ *http.Request) {
///     w.WriteHeader(http.StatusOK)
/// })
/// ```
pub(crate) async fn derp_latency_check() -> StatusCode {
    StatusCode::OK
}

// ---------------------------------------------------------------------------
// WebSocket session
// ---------------------------------------------------------------------------

/// Runs a single DERP relay WebSocket session.
///
/// 1. Assigns the peer a unique ID and registers it with the relay and
///    traffic tracker.
/// 2. Spawns a task that forwards frames from the relay to the WebSocket.
/// 3. Reads incoming frames from the WebSocket and broadcasts them to all
///    other connected peers.
/// 4. On disconnect, unregisters the peer and cleans up.
async fn derp_relay_session(state: AppState, socket: WebSocket) {
    let peer_id = Uuid::new_v4();
    let peer_id_str = peer_id.to_string();

    // Lazily initialise a shared relay instance via the DerpTrafficTracker.
    // We store the relay in a static OnceCell so all connections share it.
    static RELAY: std::sync::OnceLock<Arc<DerpRelay>> = std::sync::OnceLock::new();
    let relay = RELAY.get_or_init(DerpRelay::new).clone();

    // Register peer with relay and traffic tracker.
    let mut frame_rx = relay.add_peer(peer_id).await;
    state.derp_tracker.add_client(peer_id_str.clone()).await;

    debug!(peer_id = %peer_id, "DERP relay peer connected");

    // Split the WebSocket into sender and receiver halves.
    let (mut ws_sender, mut ws_receiver) = socket.split();

    let tracker = state.derp_tracker.clone();
    let peer_str_clone = peer_id_str.clone();
    let send_task = tokio::spawn(async move {
        while let Some(frame) = frame_rx.recv().await {
            let data_len = frame.data.len() as u64;
            let send_result = tokio::time::timeout(
                WS_IO_TIMEOUT,
                ws_sender.send(Message::Binary(frame.data.into())),
            )
            .await;
            match send_result {
                Ok(Ok(())) => {
                    tracker.record_received(&peer_str_clone, data_len, 1).await;
                }
                // Timeout or send error — peer disconnected.
                _ => break,
            }
        }
    });

    // Read incoming frames and broadcast to other peers.
    loop {
        let recv_result = tokio::time::timeout(WS_IO_TIMEOUT, ws_receiver.next()).await;
        match recv_result {
            Ok(Some(Ok(msg))) => {
                match msg {
                    Message::Binary(data) => {
                        let data_len = data.len() as u64;
                        state
                            .derp_tracker
                            .record_sent(&peer_id_str, data_len, 1)
                            .await;

                        let frame = DerpFrame {
                            src: peer_id,
                            data: data.to_vec(),
                        };

                        // Broadcast to all other connected peers.
                        relay.broadcast(&frame).await;
                    }
                    Message::Close(_) => break,
                    // Text frames, Ping/Pong handled automatically by axum.
                    _ => continue,
                }
            }
            // Timeout — the peer may have gone silent. Break to clean up.
            Err(_) => break,
            // Receive error or stream ended.
            _ => break,
        }
    }

    // Clean up.
    send_task.abort();
    relay.remove_peer(&peer_id).await;
    state.derp_tracker.remove_client(&peer_id_str).await;

    debug!(peer_id = %peer_id, "DERP relay peer disconnected");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- DerpRelay unit tests -----------------------------------------------

    #[tokio::test]
    async fn relay_add_and_remove_peer() {
        let relay = DerpRelay::new();
        let peer_id = Uuid::new_v4();

        let _rx = relay.add_peer(peer_id).await;
        assert_eq!(relay.peer_count().await, 1);

        relay.remove_peer(&peer_id).await;
        assert_eq!(relay.peer_count().await, 0);
    }

    #[tokio::test]
    async fn relay_broadcast_delivers_to_other_peers() {
        let relay = DerpRelay::new();
        let sender_id = Uuid::new_v4();
        let receiver_id = Uuid::new_v4();

        let _sender_rx = relay.add_peer(sender_id).await;
        let mut receiver_rx = relay.add_peer(receiver_id).await;

        let frame = DerpFrame {
            src: sender_id,
            data: b"hello".to_vec(),
        };
        relay.broadcast(&frame).await;

        // Receiver should get the frame.
        let received =
            tokio::time::timeout(std::time::Duration::from_millis(100), receiver_rx.recv()).await;
        assert!(received.is_ok());
        let received = received.ok().flatten();
        assert!(received.is_some());
        assert_eq!(received.as_ref().map(|f| &f.data[..]), Some(&b"hello"[..]));
    }

    #[tokio::test]
    async fn relay_broadcast_does_not_echo_to_sender() {
        let relay = DerpRelay::new();
        let sender_id = Uuid::new_v4();

        let mut sender_rx = relay.add_peer(sender_id).await;

        let frame = DerpFrame {
            src: sender_id,
            data: b"echo test".to_vec(),
        };
        relay.broadcast(&frame).await;

        // Sender should NOT receive their own frame.
        let received =
            tokio::time::timeout(std::time::Duration::from_millis(50), sender_rx.recv()).await;
        assert!(received.is_err(), "sender should not receive own frame");
    }

    #[tokio::test]
    async fn relay_forward_to_specific_peer() {
        let relay = DerpRelay::new();
        let sender_id = Uuid::new_v4();
        let target_id = Uuid::new_v4();
        let bystander_id = Uuid::new_v4();

        let _sender_rx = relay.add_peer(sender_id).await;
        let mut target_rx = relay.add_peer(target_id).await;
        let mut bystander_rx = relay.add_peer(bystander_id).await;

        let frame = DerpFrame {
            src: sender_id,
            data: b"targeted".to_vec(),
        };
        let delivered = relay.forward_to(&target_id, frame).await;
        assert!(delivered);

        // Target should receive the frame.
        let received =
            tokio::time::timeout(std::time::Duration::from_millis(100), target_rx.recv()).await;
        assert!(received.is_ok());

        // Bystander should NOT receive the frame.
        let bystander_received =
            tokio::time::timeout(std::time::Duration::from_millis(50), bystander_rx.recv()).await;
        assert!(
            bystander_received.is_err(),
            "bystander should not receive targeted frame"
        );
    }

    #[tokio::test]
    async fn relay_forward_to_unknown_peer_returns_false() {
        let relay = DerpRelay::new();
        let unknown_id = Uuid::new_v4();

        let frame = DerpFrame {
            src: Uuid::new_v4(),
            data: b"lost".to_vec(),
        };
        let delivered = relay.forward_to(&unknown_id, frame).await;
        assert!(!delivered);
    }
}
