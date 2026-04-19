//! Tailnet DRPC service — unary RPC handlers.
//!
//! Ports the two **unary** RPCs from the Go `coder.tailnet.v2.Tailnet`
//! service defined in `coder/tailnet/proto/tailnet.proto`:
//!
//! * [`TailnetRpcService::post_telemetry`] — receive a batch of
//!   `TelemetryEvent` messages and enqueue them on an mpsc sink for the
//!   coder-server to drain.
//! * [`TailnetRpcService::refresh_resume_token`] — produce a fresh signed
//!   resume token that identifies a peer across reconnects.
//!
//! The three streaming RPCs on the same service — `StreamDERPMaps`,
//! `WorkspaceUpdates`, `Coordinate` — are **deferred** to a follow-up
//! batch so this change stays small.
//!
//! This module depends on [`coder_agent_rpc::proto::tailnet_v2`] for the
//! protobuf message types. It does **not** modify `coder-agent-rpc`; the
//! transport-level DRPC dispatcher there is agent-specific, and wiring
//! the tailnet service onto the same yamux-over-WebSocket pipeline is a
//! later integration step.

use std::sync::Arc;

use base64::Engine as _;
use coder_agent_rpc::handlers::RpcError;
use coder_agent_rpc::proto::tailnet_v2 as tailnet;
use futures_util::Stream;
use prost_types::{Duration as PbDuration, Timestamp as PbTimestamp};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::tailnet::{InMemoryCoordinator, PeerKind, TailnetCoordinator};

/// Resume-token TTL chosen to match Go's `DefaultResumeTokenExpiry`
/// (`coder/tailnet/resume.go`).
const DEFAULT_RESUME_TOKEN_EXPIRY_SECS: i64 = 24 * 60 * 60;

/// Errors surfaced by the tailnet RPC service.
#[derive(Debug, Error)]
pub enum TailnetRpcError {
    /// Telemetry sink rejected a batch (channel closed / receiver dropped).
    #[error("telemetry sink closed")]
    TelemetrySinkClosed,
    /// Signing-key material was malformed.
    #[error("resume token signing: {0}")]
    Signing(String),
}

/// Sink for incoming telemetry batches. The receiver half is typically
/// drained by a background worker that logs, forwards, or persists the
/// events. In this batch the drain is stubbed with an `info!` log.
pub type TelemetrySender = mpsc::UnboundedSender<Vec<tailnet::TelemetryEvent>>;

/// Companion receiver half of a [`TelemetrySender`]. Returned by
/// [`telemetry_channel`] so callers can either drain events themselves
/// or hand off to the default logging drainer via [`log_drain_loop`].
pub type TelemetryReceiver = mpsc::UnboundedReceiver<Vec<tailnet::TelemetryEvent>>;

/// Creates a new unbounded telemetry channel sized for the network
/// telemetry batcher pattern from the Go reference.
#[must_use]
pub fn telemetry_channel() -> (TelemetrySender, TelemetryReceiver) {
    mpsc::unbounded_channel()
}

/// Simple drain task that logs each received batch at `info!`. Matches
/// the stub behaviour specified for this batch — a real Phase-2 drain
/// will forward to the telemetry worker.
pub async fn log_drain_loop(mut rx: TelemetryReceiver) {
    while let Some(batch) = rx.recv().await {
        tracing::info!(
            event_count = batch.len(),
            "tailnet: received telemetry batch (stubbed drain)"
        );
    }
}

/// Minimal HMAC-SHA256 implementation used to sign resume tokens. Keeps
/// this crate free of an extra `hmac` dep while matching the
/// symmetric-signing scheme used by Go's `jwtutils.StaticKey`.
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let digest = Sha256::digest(key);
        key_block[..32].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    outer.finalize().into()
}

/// Constant-time byte comparison to avoid signature-verification timing
/// leaks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

/// Resume-token format: `<peer_id_urn>.<expires_at_unix>.<b64url_sig>`
/// signed with HMAC-SHA256 over `"<peer_id_urn>.<expires_at_unix>"`.
/// This is intentionally simpler than the Go JWT scheme while preserving
/// the same security properties (symmetric MAC, explicit expiry).
fn sign_resume_token(key: &[u8], peer_id: Uuid, expires_at: i64) -> String {
    let payload = format!("{peer_id}.{expires_at}");
    let sig = hmac_sha256(key, payload.as_bytes());
    let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig);
    format!("{payload}.{sig_b64}")
}

/// Verifies a resume token produced by [`sign_resume_token`] and returns
/// the embedded peer id when the signature is valid and the token is
/// unexpired.
pub fn verify_resume_token(
    key: &[u8],
    token: &str,
    now_unix: i64,
) -> Result<Uuid, TailnetRpcError> {
    let parts: Vec<&str> = token.rsplitn(2, '.').collect();
    // rsplitn returns parts in reverse order.
    let (sig_b64, payload) = match parts.as_slice() {
        [sig, payload] => (*sig, *payload),
        _ => return Err(TailnetRpcError::Signing("malformed token".into())),
    };
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|e| TailnetRpcError::Signing(format!("signature base64: {e}")))?;
    let expected = hmac_sha256(key, payload.as_bytes());
    if !constant_time_eq(&sig, &expected) {
        return Err(TailnetRpcError::Signing("bad signature".into()));
    }
    let mut payload_parts = payload.splitn(2, '.');
    let peer_str = payload_parts
        .next()
        .ok_or_else(|| TailnetRpcError::Signing("missing peer id".into()))?;
    let exp_str = payload_parts
        .next()
        .ok_or_else(|| TailnetRpcError::Signing("missing expiry".into()))?;
    let peer_id = Uuid::parse_str(peer_str)
        .map_err(|e| TailnetRpcError::Signing(format!("parse peer id: {e}")))?;
    let expires_at: i64 = exp_str
        .parse()
        .map_err(|e| TailnetRpcError::Signing(format!("parse expiry: {e}")))?;
    if now_unix >= expires_at {
        return Err(TailnetRpcError::Signing("token expired".into()));
    }
    Ok(peer_id)
}

/// Service that implements the two unary tailnet RPCs. Streaming
/// methods are intentionally not part of this type — they go in a
/// follow-up batch.
///
/// Construct via [`TailnetRpcService::new`] or [`TailnetRpcService::with_stub_key`].
pub struct TailnetRpcService {
    telemetry_tx: TelemetrySender,
    signing_key: Arc<[u8]>,
    /// Default resume-token lifetime; clients should refresh at half of
    /// this.
    token_ttl_secs: i64,
    /// Optional coordinator used by streaming RPCs (e.g. `Coordinate`).
    /// `None` for the unary-only construction paths.
    coordinator: Option<Arc<InMemoryCoordinator>>,
}

impl TailnetRpcService {
    /// Creates the service with an explicit signing key (e.g. the
    /// `app_signing_key` already held by `AppState`) and a telemetry
    /// sink.
    #[must_use]
    pub fn new(telemetry_tx: TelemetrySender, signing_key: &[u8]) -> Self {
        Self {
            telemetry_tx,
            signing_key: Arc::from(signing_key),
            token_ttl_secs: DEFAULT_RESUME_TOKEN_EXPIRY_SECS,
            coordinator: None,
        }
    }

    /// Attaches the in-memory tailnet coordinator used by streaming RPCs
    /// such as `Coordinate`. Without a coordinator, the `coordinate` method
    /// returns an error on the first frame.
    #[must_use]
    pub fn with_coordinator(mut self, coordinator: Arc<InMemoryCoordinator>) -> Self {
        self.coordinator = Some(coordinator);
        self
    }

    /// Creates the service with a hardcoded placeholder key. Intended
    /// for tests and early integration work where `AppState` is not yet
    /// wired in.
    #[must_use]
    pub fn with_stub_key(telemetry_tx: TelemetrySender) -> Self {
        Self::new(telemetry_tx, b"coder-tailnet-resume-token-stub-key")
    }

    /// Overrides the resume-token TTL. Primarily useful in tests.
    #[must_use]
    pub fn with_token_ttl_secs(mut self, ttl_secs: i64) -> Self {
        self.token_ttl_secs = ttl_secs;
        self
    }

    /// Implements `PostTelemetry`. Drops each incoming batch on the
    /// configured mpsc sink and always replies with an empty
    /// [`tailnet::TelemetryResponse`], mirroring the Go behaviour in
    /// `coder/tailnet/service.go`.
    pub fn post_telemetry(
        &self,
        req: tailnet::TelemetryRequest,
    ) -> Result<tailnet::TelemetryResponse, TailnetRpcError> {
        if req.events.is_empty() {
            return Ok(tailnet::TelemetryResponse {});
        }
        self.telemetry_tx
            .send(req.events)
            .map_err(|_| TailnetRpcError::TelemetrySinkClosed)?;
        Ok(tailnet::TelemetryResponse {})
    }

    /// Implements `RefreshResumeToken`. Signs a new token bound to
    /// `peer_id` with an expiry of [`TailnetRpcService::token_ttl_secs`].
    /// Returns `refresh_in = ttl / 2` to match Go's behaviour.
    pub fn refresh_resume_token(
        &self,
        peer_id: Uuid,
    ) -> Result<tailnet::RefreshResumeTokenResponse, TailnetRpcError> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let expires_at = now.saturating_add(self.token_ttl_secs);
        let token = sign_resume_token(&self.signing_key, peer_id, expires_at);
        let refresh_in = self.token_ttl_secs / 2;
        Ok(tailnet::RefreshResumeTokenResponse {
            token,
            refresh_in: Some(PbDuration {
                seconds: refresh_in,
                nanos: 0,
            }),
            expires_at: Some(PbTimestamp {
                seconds: expires_at,
                nanos: 0,
            }),
        })
    }

    /// Exposes the signing key to verification paths that must accept
    /// tokens issued by this service (e.g. resume on reconnect).
    #[must_use]
    pub fn signing_key(&self) -> &[u8] {
        &self.signing_key
    }

    /// Implements the bidi-stream `Coordinate` RPC — **handshake + peer
    /// registration only**.
    ///
    /// Pulls the first `CoordinateRequest` off `incoming`, treats it as a
    /// handshake frame, derives a stable peer id from the Wireguard public
    /// key carried in `update_self.node.key`, registers the peer in the
    /// attached [`InMemoryCoordinator`], and emits a single empty
    /// `CoordinateResponse` as the handshake acknowledgement. Subsequent
    /// frames are logged at `debug` and dropped; the stream then parks
    /// until the incoming side closes.
    ///
    /// `TODO-tailnet-coordinate-node-updates`: route subsequent
    /// `update_self` / `add_tunnel` / `remove_tunnel` / `disconnect` /
    /// `ready_for_handshake` frames through
    /// `InMemoryCoordinator::process_request` (converting proto `Node` →
    /// `NodeInfo`), and fan coordinator response messages back onto the
    /// outbound stream as per-peer `PeerUpdate` entries. Multi-peer routing
    /// is also deferred.
    pub fn coordinate(
        &self,
        incoming: impl Stream<Item = tailnet::CoordinateRequest> + Send + Unpin + 'static,
    ) -> impl Stream<Item = Result<tailnet::CoordinateResponse, RpcError>> + Send + 'static {
        let coordinator = self.coordinator.clone();
        async_stream::stream! {
            use futures_util::StreamExt as _;

            let mut incoming = incoming;
            // 1. Pull the handshake frame (must carry update_self.node.key).
            let Some(first) = incoming.next().await else {
                yield Err(RpcError::InvalidArgument(
                    "coordinate: no handshake frame received".into(),
                ));
                return;
            };

            let Some(node) = first.update_self.as_ref().and_then(|u| u.node.as_ref()) else {
                yield Err(RpcError::InvalidArgument(
                    "coordinate: handshake frame must contain update_self.node".into(),
                ));
                return;
            };
            if node.key.is_empty() {
                yield Err(RpcError::InvalidArgument(
                    "coordinate: handshake node.key must be non-empty".into(),
                ));
                return;
            }

            let Some(coord) = coordinator else {
                yield Err(RpcError::Internal(
                    "coordinate: no coordinator attached to service".into(),
                ));
                return;
            };

            // Derive a stable peer id from the Wireguard public key bytes so
            // reconnecting peers land on the same coordinator entry. We take
            // the first 16 bytes of SHA-256(key) to avoid pulling a uuid v5
            // feature dependency.
            let digest = Sha256::digest(&node.key);
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&digest[..16]);
            let peer_id = Uuid::from_bytes(bytes);
            let name = format!("peer-{}", &peer_id.as_simple().to_string()[..8]);

            // 2. Register in the coordinator. We intentionally register as
            // `Client`; distinguishing Agent vs Client requires auth context
            // that is not wired through the DRPC transport yet (deferred).
            let handle = coord.coordinate(peer_id, name, PeerKind::Client);
            tracing::info!(
                peer_id = %peer_id,
                key_len = node.key.len(),
                "tailnet: coordinate handshake accepted",
            );

            // 3. Emit the handshake acknowledgement: an empty peer_updates /
            // no-error response signals successful registration.
            yield Ok(tailnet::CoordinateResponse::default());

            // Park on the incoming stream; log and drop subsequent frames.
            // TODO-tailnet-coordinate-node-updates.
            loop {
                tokio::select! {
                    msg = incoming.next() => {
                        match msg {
                            Some(_req) => {
                                tracing::debug!(
                                    peer_id = %peer_id,
                                    "tailnet: coordinate frame received (node-update fan-out TODO)",
                                );
                            }
                            None => break,
                        }
                    }
                }
            }

            // Ensure the peer is deregistered when the stream ends.
            coord.close_coordination(peer_id, handle.session_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tailnet::InMemoryCoordinator;
    use coder_core::api::DERPMap;
    use futures_util::StreamExt as _;

    #[tokio::test]
    async fn coordinate_handshake_registers_peer() {
        let (tx, _rx) = telemetry_channel();
        let coord = InMemoryCoordinator::new(DERPMap::default());
        let svc = TailnetRpcService::with_stub_key(tx).with_coordinator(coord.clone());

        let handshake = tailnet::CoordinateRequest {
            update_self: Some(tailnet::coordinate_request::UpdateSelf {
                node: Some(tailnet::Node {
                    key: b"wg-public-key-bytes".to_vec(),
                    ..Default::default()
                }),
            }),
            ..Default::default()
        };
        let incoming = futures_util::stream::iter(vec![handshake]);

        let mut out = Box::pin(svc.coordinate(incoming));
        let Some(Ok(ack)) = out.next().await else {
            unreachable!("expected coordinate ack frame");
        };
        assert!(ack.peer_updates.is_empty());
        assert!(ack.error.is_empty());

        // The coordinator must now have exactly one registered peer.
        let debug = coord.debug_json();
        assert_eq!(debug["total_peers"], 1);
    }

    #[test]
    fn post_telemetry_drops_events_on_sink() {
        let (tx, mut rx) = telemetry_channel();
        let svc = TailnetRpcService::with_stub_key(tx);

        let event = tailnet::TelemetryEvent {
            id: b"id".to_vec(),
            ..Default::default()
        };
        let resp = svc.post_telemetry(tailnet::TelemetryRequest {
            events: vec![event.clone()],
        });
        assert!(resp.is_ok(), "post_telemetry must succeed");
        let Ok(batch) = rx.try_recv() else {
            unreachable!("telemetry sink must receive batch");
        };
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].id, event.id);
    }

    #[test]
    fn refresh_resume_token_roundtrip_verifies() {
        let (tx, _rx) = telemetry_channel();
        let svc = TailnetRpcService::with_stub_key(tx).with_token_ttl_secs(60);
        let peer_id = Uuid::new_v4();
        let Ok(resp) = svc.refresh_resume_token(peer_id) else {
            unreachable!("generation must succeed");
        };
        assert!(!resp.token.is_empty());
        let Some(exp_pb) = resp.expires_at else {
            unreachable!("expires_at required");
        };
        let exp = exp_pb.seconds;
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let Ok(verified) = verify_resume_token(svc.signing_key(), &resp.token, now) else {
            unreachable!("verify must succeed");
        };
        assert_eq!(verified, peer_id);
        // Expired token must be rejected.
        assert!(verify_resume_token(svc.signing_key(), &resp.token, exp + 1).is_err());
    }
}
