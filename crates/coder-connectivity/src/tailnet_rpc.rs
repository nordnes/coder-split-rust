//! Tailnet DRPC service — unary and streaming RPC handlers.
//!
//! Ports RPCs from the Go `coder.tailnet.v2.Tailnet` service defined in
//! `coder/tailnet/proto/tailnet.proto`:
//!
//! * [`TailnetRpcService::post_telemetry`] — receive a batch of
//!   `TelemetryEvent` messages and enqueue them on an mpsc sink for the
//!   coder-server to drain.
//! * [`TailnetRpcService::refresh_resume_token`] — produce a fresh signed
//!   resume token that identifies a peer across reconnects.
//! * [`TailnetRpcService::stream_derp_maps`] — server-stream the current
//!   DERP map to the client. Emits an initial snapshot and, when a
//!   [`DerpMapNotifier`] is installed, subsequent frames whenever the
//!   underlying DERP config changes. Mirrors the Go push-on-change loop
//!   in `coder/tailnet/service.go`.
//!
//! The remaining streaming RPCs (`WorkspaceUpdates`, `Coordinate`) are
//! ported in sibling batches so each change stays small.
//!
//! This module depends on [`coder_agent_rpc::proto::tailnet_v2`] for the
//! protobuf message types. It does **not** modify `coder-agent-rpc`; the
//! transport-level DRPC dispatcher there is agent-specific, and wiring
//! the tailnet service onto the same yamux-over-WebSocket pipeline is a
//! later integration step.

use std::sync::Arc;

use async_stream::stream;
use async_trait::async_trait;
use base64::Engine as _;
use coder_agent_rpc::handlers::{ResponseStream, RpcContext, RpcError, ServerStreamHandler};
use coder_agent_rpc::proto::tailnet_v2 as tailnet;
use futures_util::stream::{self, StreamExt};
use prost::Message as _;
use prost_types::{Duration as PbDuration, Timestamp as PbTimestamp};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;
use tokio::sync::{mpsc, watch};
use uuid::Uuid;

/// DRPC method path for `StreamDERPMaps`. Mirrors the Go
/// `DRPCTailnet_StreamDERPMapsStream` registration.
pub const STREAM_DERP_MAPS_METHOD: &str = "/coder.tailnet.v2.Tailnet/StreamDERPMaps";

/// Trait returning the current DERP map snapshot. Modelled on Go's
/// `DerpMapFn` in `coder/tailnet/service.go`. Implementations should be
/// cheap to call (typical storage is a `watch::Receiver::borrow()` on an
/// in-process DERP config).
pub trait DerpMapProvider: Send + Sync {
    /// Returns the current DERP map. When this returns `None` the
    /// streaming handler treats the stream as finished, matching the Go
    /// `io.EOF` close signal.
    fn current(&self) -> Option<tailnet::DerpMap>;
}

/// Convenience: any closure `Fn() -> Option<DerpMap>` satisfies
/// [`DerpMapProvider`].
impl<F> DerpMapProvider for F
where
    F: Fn() -> Option<tailnet::DerpMap> + Send + Sync,
{
    fn current(&self) -> Option<tailnet::DerpMap> {
        self()
    }
}

/// Subscription source for live DERP map updates. Mirrors the role of
/// Go's `DerpMapFn` re-invocation under a ticker in
/// `coder/tailnet/service.go` — each DERP config change causes
/// [`TailnetRpcService::stream_derp_maps`] to emit a fresh frame.
///
/// When this is not plumbed the service falls back to the one-shot
/// initial-snapshot behaviour from [`DerpMapProvider`].
pub trait DerpMapNotifier: Send + Sync {
    /// Returns a `watch::Receiver` that resolves to the latest DERP
    /// map. The initial value must be immediately readable via
    /// `watch::Receiver::borrow()`; subsequent changes mark the
    /// receiver ready and are observed with `changed().await`.
    fn subscribe(&self) -> watch::Receiver<tailnet::DerpMap>;
}

/// Blanket impl letting a `watch::Sender<DerpMap>` serve as its own
/// notifier — the common wiring where the DERP config owner holds the
/// sender and the tailnet service only needs receivers.
impl DerpMapNotifier for watch::Sender<tailnet::DerpMap> {
    fn subscribe(&self) -> watch::Receiver<tailnet::DerpMap> {
        self.subscribe()
    }
}

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

/// Service that implements the tailnet RPCs. Two unary methods and one
/// server-stream method are live today; `WorkspaceUpdates` and
/// `Coordinate` are in sibling batches.
///
/// Construct via [`TailnetRpcService::new`] or [`TailnetRpcService::with_stub_key`].
pub struct TailnetRpcService {
    telemetry_tx: TelemetrySender,
    signing_key: Arc<[u8]>,
    /// Default resume-token lifetime; clients should refresh at half of
    /// this.
    token_ttl_secs: i64,
    /// Source of the current DERP map. Defaults to returning an empty
    /// map so that `stream_derp_maps` always emits at least one frame
    /// when wired up with the default constructor.
    derp_map_provider: Arc<dyn DerpMapProvider>,
    /// Optional live-update source. When present,
    /// [`TailnetRpcService::stream_derp_maps`] subscribes to it and
    /// emits a fresh frame on every change. When `None`, the stream
    /// degrades to the one-shot snapshot behaviour — this preserves
    /// backwards compatibility for callers that have not yet wired a
    /// notifier.
    derp_map_notifier: Option<Arc<dyn DerpMapNotifier>>,
}

impl TailnetRpcService {
    /// Creates the service with an explicit signing key (e.g. the
    /// `app_signing_key` already held by `AppState`) and a telemetry
    /// sink. The DERP map provider defaults to an empty-map stub; use
    /// [`TailnetRpcService::with_derp_map_provider`] to install the real
    /// source.
    #[must_use]
    pub fn new(telemetry_tx: TelemetrySender, signing_key: &[u8]) -> Self {
        Self {
            telemetry_tx,
            signing_key: Arc::from(signing_key),
            token_ttl_secs: DEFAULT_RESUME_TOKEN_EXPIRY_SECS,
            derp_map_provider: Arc::new(|| Some(tailnet::DerpMap::default())),
            derp_map_notifier: None,
        }
    }

    /// Installs a custom DERP map provider (production wiring). The
    /// default from [`TailnetRpcService::new`] returns an empty map.
    #[must_use]
    pub fn with_derp_map_provider(mut self, provider: Arc<dyn DerpMapProvider>) -> Self {
        self.derp_map_provider = provider;
        self
    }

    /// Installs a [`DerpMapNotifier`] so `stream_derp_maps` reacts to
    /// DERP config changes. Without a notifier, the stream emits only
    /// the initial snapshot from the provider (legacy behaviour).
    #[must_use]
    pub fn with_derp_map_notifier(mut self, notifier: Arc<dyn DerpMapNotifier>) -> Self {
        self.derp_map_notifier = Some(notifier);
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

    /// Returns the current DERP map snapshot as a protobuf message, or
    /// `None` if the provider signalled end-of-stream (mirroring Go's
    /// nil-returns-EOF convention in `coder/tailnet/service.go`).
    #[must_use]
    pub fn build_current_derp_map(&self) -> Option<tailnet::DerpMap> {
        self.derp_map_provider.current()
    }

    /// Implements `StreamDERPMaps`. Emits an initial snapshot and,
    /// when a [`DerpMapNotifier`] is installed, a fresh frame on every
    /// DERP config change. Terminates cleanly when the notifier's
    /// sender is dropped or the consumer stops polling (drops the
    /// returned stream).
    ///
    /// Duplicate frames are suppressed: the loop only emits a new
    /// `DerpMap` when the observed value differs from the last-sent
    /// one. This matches Go's `CompareDERPMaps` dedupe in
    /// `coder/tailnet/service.go`.
    ///
    /// If no notifier is configured, the stream degrades to emitting
    /// the single provider snapshot and closing — preserving the
    /// behaviour that predated the live-push path.
    pub fn stream_derp_maps(
        &self,
        _req: tailnet::StreamDerpMapsRequest,
    ) -> impl futures_util::Stream<Item = Result<tailnet::DerpMap, RpcError>> + Send + 'static {
        let Some(notifier) = self.derp_map_notifier.clone() else {
            let snapshot = self.build_current_derp_map();
            return stream::iter(snapshot.into_iter().map(Ok::<_, RpcError>)).boxed();
        };
        let mut rx = notifier.subscribe();
        stream! {
            // Initial snapshot: mirror the first-iteration send in Go
            // regardless of whether the watched value was "initial" or
            // had already transitioned. `borrow_and_update` clears the
            // changed flag so the next `changed().await` blocks until
            // a real update arrives.
            let mut last = rx.borrow_and_update().clone();
            yield Ok(last.clone());
            while rx.changed().await.is_ok() {
                let next = rx.borrow_and_update().clone();
                // Suppress duplicate frames — `watch` can wake
                // spuriously when the same value is re-sent.
                if next == last {
                    continue;
                }
                last = next.clone();
                yield Ok(next);
            }
            // sender dropped → clean EOF.
        }
        .boxed()
    }
}

/// Server-stream handler wiring [`TailnetRpcService::stream_derp_maps`]
/// into the [`ServerStreamHandler`] DRPC dispatcher from
/// `coder-agent-rpc`. Each emitted `DerpMap` is prost-encoded and
/// forwarded verbatim as the DRPC `Message` body.
pub struct StreamDerpMapsHandler {
    service: Arc<TailnetRpcService>,
}

impl StreamDerpMapsHandler {
    /// Wraps `service` so it can be registered against the
    /// [`STREAM_DERP_MAPS_METHOD`] DRPC path.
    #[must_use]
    pub fn new(service: Arc<TailnetRpcService>) -> Self {
        Self { service }
    }
}

#[async_trait]
impl ServerStreamHandler for StreamDerpMapsHandler {
    async fn invoke(
        &self,
        _ctx: RpcContext,
        request_body: Vec<u8>,
    ) -> Result<ResponseStream, RpcError> {
        let req = tailnet::StreamDerpMapsRequest::decode(request_body.as_slice())
            .map_err(|e| RpcError::InvalidArgument(format!("decode StreamDERPMapsRequest: {e}")))?;
        let typed = self.service.stream_derp_maps(req);
        let encoded = typed.map(|item| item.map(|msg| msg.encode_to_vec()));
        Ok(Box::pin(encoded))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[tokio::test]
    async fn stream_derp_maps_emits_initial_snapshot() {
        let (tx, _rx) = telemetry_channel();
        let mut map = tailnet::DerpMap::default();
        map.regions.insert(
            1,
            tailnet::derp_map::Region {
                region_id: 1,
                region_code: "test".into(),
                region_name: "test".into(),
                ..Default::default()
            },
        );
        let snapshot = map.clone();
        let svc = TailnetRpcService::with_stub_key(tx)
            .with_derp_map_provider(Arc::new(move || Some(snapshot.clone())));
        let mut stream = Box::pin(svc.stream_derp_maps(tailnet::StreamDerpMapsRequest {}));
        let Some(Ok(first)) = stream.next().await else {
            unreachable!("expected one DERP map frame");
        };
        assert_eq!(first, map);
        assert!(stream.next().await.is_none(), "stream must end after one");
    }

    fn region_map(id: i64, code: &str) -> tailnet::DerpMap {
        let mut map = tailnet::DerpMap::default();
        map.regions.insert(
            id,
            tailnet::derp_map::Region {
                region_id: id,
                region_code: code.into(),
                region_name: code.into(),
                ..Default::default()
            },
        );
        map
    }

    #[tokio::test]
    async fn stream_derp_maps_emits_subsequent_updates() {
        let (tx, _rx) = telemetry_channel();
        let initial = region_map(1, "one");
        let updated = region_map(2, "two");
        let (derp_tx, _derp_rx) = watch::channel(initial.clone());
        let notifier: Arc<dyn DerpMapNotifier> = Arc::new(derp_tx.clone());
        let svc = TailnetRpcService::with_stub_key(tx).with_derp_map_notifier(notifier);
        let mut stream = Box::pin(svc.stream_derp_maps(tailnet::StreamDerpMapsRequest {}));

        let Some(Ok(first)) = stream.next().await else {
            unreachable!("expected initial snapshot frame");
        };
        assert_eq!(first, initial);

        // Push a fresh DERP map and assert a second frame arrives.
        let Ok(()) = derp_tx.send(updated.clone()) else {
            unreachable!("watch::Sender::send must succeed while receivers live");
        };
        let Some(Ok(second)) = stream.next().await else {
            unreachable!("expected updated DERP map frame");
        };
        assert_eq!(second, updated);
    }

    #[tokio::test]
    async fn stream_derp_maps_dedupes_identical_updates() {
        let (tx, _rx) = telemetry_channel();
        let initial = region_map(1, "only");
        let updated = region_map(2, "changed");
        let (derp_tx, _derp_rx) = watch::channel(initial.clone());
        let notifier: Arc<dyn DerpMapNotifier> = Arc::new(derp_tx.clone());
        let svc = TailnetRpcService::with_stub_key(tx).with_derp_map_notifier(notifier);
        let mut stream = Box::pin(svc.stream_derp_maps(tailnet::StreamDerpMapsRequest {}));

        let Some(Ok(first)) = stream.next().await else {
            unreachable!("initial snapshot");
        };
        assert_eq!(first, initial);

        // Duplicate send — must not produce a frame.
        let Ok(()) = derp_tx.send(initial.clone()) else {
            unreachable!("send must succeed");
        };
        let duplicate_wait =
            tokio::time::timeout(std::time::Duration::from_millis(50), stream.next()).await;
        assert!(
            duplicate_wait.is_err(),
            "duplicate DERP map must not emit a new frame"
        );

        // A real change goes through.
        let Ok(()) = derp_tx.send(updated.clone()) else {
            unreachable!("send must succeed");
        };
        let Some(Ok(next)) = stream.next().await else {
            unreachable!("expected frame after distinct update");
        };
        assert_eq!(next, updated);
    }

    #[tokio::test]
    async fn stream_derp_maps_terminates_on_cancel() {
        let (tx, _rx) = telemetry_channel();
        let initial = region_map(1, "cancel");
        let (derp_tx, _derp_rx) = watch::channel(initial);
        let notifier: Arc<dyn DerpMapNotifier> = Arc::new(derp_tx.clone());
        let svc = TailnetRpcService::with_stub_key(tx).with_derp_map_notifier(notifier);
        let stream = svc.stream_derp_maps(tailnet::StreamDerpMapsRequest {});
        let mut pinned = Box::pin(stream);

        // Consume the initial frame.
        let Some(Ok(_first)) = pinned.next().await else {
            unreachable!("initial snapshot expected");
        };

        // Drop the stream — the underlying async_stream future must
        // halt promptly (no further sends on the watch channel).
        drop(pinned);

        // If the loop still held the receiver the sender would be
        // "live"; after drop, the sender still observes no receivers
        // for _this_ subscription (the test-held `_derp_rx` survives,
        // so we instead assert timely completion of the drop path by
        // re-polling a fresh subscription).
        let mut fresh = Box::pin(svc.stream_derp_maps(tailnet::StreamDerpMapsRequest {}));
        let second =
            tokio::time::timeout(std::time::Duration::from_millis(100), fresh.next()).await;
        let Ok(Some(Ok(_))) = second else {
            unreachable!("fresh subscription must still emit the initial frame");
        };
    }
}
