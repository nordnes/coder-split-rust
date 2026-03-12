//! DERP relay WebSocket endpoint and latency check handlers.
//!
//! Implements the `/derp` WebSocket relay that agents and clients use for
//! peer-to-peer connectivity when direct WireGuard connections fail, and the
//! `/derp/latency-check` endpoint used for HTTP(S)-based latency measurement
//! when UDP is blocked.
//!
//! The Go reference lives in `coder/coderd/coderd.go` (route setup) and
//! `coder/tailnet/derp.go` (`WithWebsocketSupport`).
//!
//! # Protocol
//!
//! The DERP relay uses Tailscale's binary framing protocol over WebSocket:
//!
//! 1. Server sends `ServerKey` frame with its public key
//! 2. Client sends `ClientInfo` frame with its node key
//! 3. Server sends `PeerPresent` for each already-connected peer
//! 4. Client sends `SendPacket` frames addressed to specific peers by key
//! 5. Server delivers `RecvPacket` frames from other peers
//! 6. Server sends `KeepAlive` frames every 60 seconds
//! 7. On disconnect, server sends `PeerGone` to watchers

use super::*;
use coder_connectivity::derp::{self, Frame, FrameType, NodeKey};
use futures_util::SinkExt;

/// Subprotocol identifier used by DERP WebSocket clients.
///
/// Tailscale clients request the `"derp"` subprotocol in the
/// `Sec-WebSocket-Protocol` header.  We accept this subprotocol to
/// distinguish real DERP clients from older clients that set
/// `Upgrade: websocket` but still spoke binary DERP framing.
const DERP_SUBPROTOCOL: &str = "derp";

/// Maximum duration to wait for a single WebSocket send or receive.
///
/// This MUST be longer than `KEEP_ALIVE_INTERVAL` so that idle but
/// legitimate clients are not disconnected before a keep-alive arrives.
/// The Go reference uses 120 s for the read deadline.
const WS_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Keep-alive interval for DERP relay connections.
const KEEP_ALIVE_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(derp::KEEP_ALIVE_INTERVAL_SECS);

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET /derp — DERP relay WebSocket endpoint.
///
/// Accepts a WebSocket upgrade with the `"derp"` subprotocol and relays
/// encrypted packets between peers based on their node public keys.
///
/// The protocol flow is:
/// 1. Server sends `ServerKey` frame
/// 2. Client sends `ClientInfo` frame with its node key
/// 3. Bidirectional packet relay via `SendPacket`/`RecvPacket` frames
/// 4. Server sends periodic `KeepAlive` frames
/// 5. On disconnect, server notifies watchers via `PeerGone`
///
/// The Go reference uses `derphttp.Handler` + `tailnet.WithWebsocketSupport`
/// which upgrades connections requesting the `"derp"` subprotocol to
/// WebSockets and passes the resulting `net.Conn` to `derp.Server.Accept`.
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

/// GET /api/v2/derp/latency-check — API-scoped DERP latency check.
///
/// Identical to `/derp/latency-check` but under the API prefix for
/// consistency with the Go reference which exposes it at both paths.
pub(crate) async fn api_derp_latency_check() -> StatusCode {
    StatusCode::OK
}

// ---------------------------------------------------------------------------
// WebSocket session
// ---------------------------------------------------------------------------

/// Runs a single DERP relay WebSocket session using the Tailscale DERP protocol.
///
/// 1. Sends the server key to the client.
/// 2. Waits for the client's node key (ClientInfo frame).
/// 3. Registers the client with the DERP server.
/// 4. Spawns a writer task that forwards frames from the server to the WebSocket.
/// 5. Spawns a keep-alive task that sends periodic KeepAlive frames.
/// 6. Reads incoming frames from the WebSocket and processes them:
///    - `SendPacket`: routes to destination peer by node key
///    - `NotePreferred`: marks this as the client's preferred server
///    - `WatchConns`: registers for connection notifications (mesh)
///    - `Ping`/`Pong`: responds to/acknowledges pings
/// 7. On disconnect, unregisters the peer and cleans up.
async fn derp_relay_session(state: AppState, socket: WebSocket) {
    let (mut ws_sender, mut ws_receiver) = socket.split();

    // Step 1: Send server key.
    let server_key_frame = Frame::server_key(state.derp_server.server_key());
    let server_key_bytes = server_key_frame.to_bytes();
    let send_result = tokio::time::timeout(
        WS_IO_TIMEOUT,
        ws_sender.send(Message::Binary(server_key_bytes.into())),
    )
    .await;
    if send_result.is_err() || send_result.is_ok_and(|r| r.is_err()) {
        debug!("DERP: failed to send server key");
        return;
    }

    // Step 2: Wait for client info (node key).
    let client_key = match receive_client_info(&mut ws_receiver).await {
        Some(key) => key,
        None => {
            debug!("DERP: failed to receive client info");
            return;
        }
    };

    let client_key_str = client_key.to_string();

    // Step 3: Register client with the DERP server and traffic tracker.
    let mut frame_rx = state.derp_server.accept_client(client_key).await;
    state.derp_tracker.add_client(client_key_str.clone()).await;

    debug!(key = %client_key, "DERP relay peer connected via protocol handshake");

    // Step 4: Spawn writer task — forwards frames from server to WebSocket.
    let tracker = state.derp_tracker.clone();
    let peer_str_clone = client_key_str.clone();
    let send_task = tokio::spawn(async move {
        while let Some(frame) = frame_rx.recv().await {
            let frame_bytes = frame.to_bytes();
            let data_len = frame_bytes.len() as u64;
            let send_result = tokio::time::timeout(
                WS_IO_TIMEOUT,
                ws_sender.send(Message::Binary(frame_bytes.into())),
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

    // Step 5: Spawn keep-alive task — sends periodic KeepAlive frames.
    let keep_alive_server = state.derp_server.clone();
    let keep_alive_key = client_key;
    let keep_alive_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(KEEP_ALIVE_INTERVAL);
        // Skip the first tick which fires immediately.
        interval.tick().await;
        loop {
            interval.tick().await;
            if !keep_alive_server.has_client(&keep_alive_key).await {
                break;
            }
            // Send a bare KeepAlive frame directly to the client's channel
            // (not via send_packet, which would wrap it in a RecvPacket).
            let ka_frame = Frame::keep_alive();
            if !keep_alive_server
                .send_raw_frame(&keep_alive_key, ka_frame)
                .await
            {
                // Client may have disconnected.
                break;
            }
        }
    });

    // Step 6: Read incoming frames and process them.
    loop {
        let recv_result = tokio::time::timeout(WS_IO_TIMEOUT, ws_receiver.next()).await;
        match recv_result {
            Ok(Some(Ok(msg))) => {
                match msg {
                    Message::Binary(data) => {
                        let data_len = data.len() as u64;
                        state
                            .derp_tracker
                            .record_sent(&client_key_str, data_len, 1)
                            .await;

                        // Parse DERP frame and handle accordingly.
                        if let Ok((frame, _)) = derp::parse_frame(&data) {
                            handle_client_frame(&state, &client_key, frame).await;
                        }
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

    // Step 7: Clean up.
    send_task.abort();
    keep_alive_task.abort();
    state.derp_server.remove_client(&client_key).await;
    state.derp_tracker.remove_client(&client_key_str).await;

    debug!(key = %client_key, "DERP relay peer disconnected");
}

/// Receives and parses the `ClientInfo` frame from a newly connected peer.
///
/// Returns the client's `NodeKey` if successful, or `None` if the client
/// does not send a valid `ClientInfo` frame within the timeout.
async fn receive_client_info(
    ws_receiver: &mut futures_util::stream::SplitStream<WebSocket>,
) -> Option<NodeKey> {
    let recv_result = tokio::time::timeout(WS_IO_TIMEOUT, ws_receiver.next()).await;
    match recv_result {
        Ok(Some(Ok(Message::Binary(data)))) => {
            if let Ok((frame, _)) = derp::parse_frame(&data) {
                if frame.frame_type == FrameType::ClientInfo
                    && frame.payload.len() >= derp::NODE_KEY_LEN
                {
                    return NodeKey::from_slice(&frame.payload[..derp::NODE_KEY_LEN]);
                }
            }
            None
        }
        _ => None,
    }
}

/// Processes a single DERP frame received from a connected client.
async fn handle_client_frame(state: &AppState, src_key: &NodeKey, frame: Frame) {
    match frame.frame_type {
        FrameType::SendPacket => {
            if let Ok((dst_key, packet_data)) = derp::parse_send_packet(&frame.payload) {
                let _ = state
                    .derp_server
                    .send_packet(src_key, &dst_key, packet_data)
                    .await;
            }
        }
        FrameType::NotePreferred => {
            let preferred = frame.payload.first().copied().unwrap_or(0) != 0;
            state.derp_server.note_preferred(src_key, preferred).await;
        }
        FrameType::WatchConns => {
            // Register as a watcher and forward notifications through the
            // client's existing frame channel so the writer task delivers them.
            let mut watcher_rx = state.derp_server.watch_conns(*src_key).await;
            let server = state.derp_server.clone();
            let watcher_dst = *src_key;
            tokio::spawn(async move {
                while let Some(notification) = watcher_rx.recv().await {
                    if !server.send_raw_frame(&watcher_dst, notification).await {
                        break;
                    }
                }
            });
        }
        FrameType::Ping => {
            if frame.payload.len() == 8 {
                let mut data = [0u8; 8];
                data.copy_from_slice(&frame.payload);
                let pong = Frame::pong(data);
                // Send the Pong frame directly (not via send_packet which
                // would wrap it in a RecvPacket, causing double-framing).
                let _ = state.derp_server.send_raw_frame(src_key, pong).await;
            }
        }
        // Other frame types are server-to-client or unexpected. Ignore gracefully.
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use coder_connectivity::derp::{DerpServer, Frame, FrameType, NODE_KEY_LEN, NodeKey};

    #[tokio::test]
    async fn server_basic_accept_and_packet_relay() {
        let server_key = NodeKey::new([1u8; NODE_KEY_LEN]);
        let server = DerpServer::new(server_key);

        let alice = NodeKey::new([2u8; NODE_KEY_LEN]);
        let bob = NodeKey::new([3u8; NODE_KEY_LEN]);

        let _alice_rx = server.accept_client(alice).await;
        let mut bob_rx = server.accept_client(bob).await;

        let delivered = server.send_packet(&alice, &bob, b"hello").await;
        assert!(delivered);

        let frame = tokio::time::timeout(std::time::Duration::from_millis(100), bob_rx.recv())
            .await
            .ok()
            .flatten();
        assert!(frame.is_some());
        let frame = frame.unwrap();
        assert_eq!(frame.frame_type, FrameType::RecvPacket);
    }

    #[tokio::test]
    async fn server_disconnect_removes_peer() {
        let server_key = NodeKey::new([1u8; NODE_KEY_LEN]);
        let server = DerpServer::new(server_key);

        let alice = NodeKey::new([2u8; NODE_KEY_LEN]);
        let _rx = server.accept_client(alice).await;
        assert_eq!(server.client_count().await, 1);

        server.remove_client(&alice).await;
        assert_eq!(server.client_count().await, 0);
    }

    #[tokio::test]
    async fn server_send_to_disconnected_peer_returns_false() {
        let server_key = NodeKey::new([1u8; NODE_KEY_LEN]);
        let server = DerpServer::new(server_key);

        let alice = NodeKey::new([2u8; NODE_KEY_LEN]);
        let bob = NodeKey::new([3u8; NODE_KEY_LEN]);

        let _alice_rx = server.accept_client(alice).await;
        let delivered = server.send_packet(&alice, &bob, b"hello").await;
        assert!(!delivered);
    }

    #[tokio::test]
    async fn frame_parse_and_route() {
        let dst = NodeKey::new([3u8; NODE_KEY_LEN]);
        let data = b"test payload";
        let frame = Frame::send_packet(&dst, data);
        let bytes = frame.to_bytes();

        let (parsed, _) = derp::parse_frame(&bytes).unwrap();
        assert_eq!(parsed.frame_type, FrameType::SendPacket);

        let (parsed_dst, parsed_data) = derp::parse_send_packet(&parsed.payload).unwrap();
        assert_eq!(parsed_dst, dst);
        assert_eq!(parsed_data, data);
    }

    #[tokio::test]
    async fn keep_alive_frame_creation() {
        let frame = Frame::keep_alive();
        let bytes = frame.to_bytes();
        let (parsed, _) = derp::parse_frame(&bytes).unwrap();
        assert_eq!(parsed.frame_type, FrameType::KeepAlive);
        assert!(parsed.payload.is_empty());
    }

    #[tokio::test]
    async fn peer_notification_on_connect_disconnect() {
        let server_key = NodeKey::new([1u8; NODE_KEY_LEN]);
        let server = DerpServer::new(server_key);

        let watcher_key = NodeKey::new([10u8; NODE_KEY_LEN]);
        let mut watcher_rx = server.watch_conns(watcher_key).await;

        let client_key = NodeKey::new([20u8; NODE_KEY_LEN]);
        let _client_rx = server.accept_client(client_key).await;

        let notification =
            tokio::time::timeout(std::time::Duration::from_millis(100), watcher_rx.recv())
                .await
                .ok()
                .flatten();
        assert!(notification.is_some());
        assert_eq!(
            notification.as_ref().map(|f| f.frame_type),
            Some(FrameType::PeerPresent)
        );

        server.remove_client(&client_key).await;

        let notification =
            tokio::time::timeout(std::time::Duration::from_millis(100), watcher_rx.recv())
                .await
                .ok()
                .flatten();
        assert!(notification.is_some());
        assert_eq!(
            notification.as_ref().map(|f| f.frame_type),
            Some(FrameType::PeerGone)
        );
    }

    #[tokio::test]
    async fn region_discovery_latency_check() {
        let status = derp_latency_check().await;
        assert_eq!(status, StatusCode::OK);

        let status = api_derp_latency_check().await;
        assert_eq!(status, StatusCode::OK);
    }
}
