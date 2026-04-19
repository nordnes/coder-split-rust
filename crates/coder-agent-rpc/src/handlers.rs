//! Handler traits for the agent RPC service.
//!
//! The server reads `INVOKE` + `MESSAGE` pairs off the wire and dispatches
//! them to an implementation of [`AgentRpcHandler`]. The trait is
//! intentionally narrow in Phase 1: each method takes an already-decoded
//! request protobuf and returns an already-encoded response protobuf.
//!
//! Implementations should keep business logic out of the framing layer and
//! return a typed [`RpcError`] for anything that cannot be served.

use std::pin::Pin;

use async_trait::async_trait;
use futures_util::Stream;
use thiserror::Error;

use crate::proto::agent_v2 as agent;

/// Errors returned by handler methods. These are mapped onto DRPC error
/// frames by the stream server.
#[derive(Debug, Error)]
pub enum RpcError {
    /// The handler does not know how to serve this method.
    #[error("unimplemented: {0}")]
    Unimplemented(String),
    /// The request was rejected because it was malformed.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    /// The handler encountered an internal error.
    #[error("internal: {0}")]
    Internal(String),
}

/// Trait describing the subset of the agent DRPC service that the Rust
/// server currently implements. Methods default to `Unimplemented`, matching
/// the Go server's behaviour when an RPC path is unregistered.
#[async_trait]
pub trait AgentRpcHandler: Send + Sync {
    async fn get_manifest(
        &self,
        _req: agent::GetManifestRequest,
    ) -> Result<agent::Manifest, RpcError> {
        Err(RpcError::Unimplemented("GetManifest".into()))
    }

    async fn get_announcement_banners(
        &self,
        _req: agent::GetAnnouncementBannersRequest,
    ) -> Result<agent::GetAnnouncementBannersResponse, RpcError> {
        Err(RpcError::Unimplemented("GetAnnouncementBanners".into()))
    }

    async fn update_startup(
        &self,
        _req: agent::UpdateStartupRequest,
    ) -> Result<agent::Startup, RpcError> {
        Err(RpcError::Unimplemented("UpdateStartup".into()))
    }

    async fn batch_update_app_health(
        &self,
        _req: agent::BatchUpdateAppHealthRequest,
    ) -> Result<agent::BatchUpdateAppHealthResponse, RpcError> {
        Err(RpcError::Unimplemented("BatchUpdateAppHealths".into()))
    }
}

/// Opaque per-invocation metadata lifted off any `InvokeMetadata` frames
/// that preceded the `Invoke`. The wire-level representation is an opaque
/// byte string; callers may parse it later (e.g. to extract OpenTelemetry
/// span context) but the DRPC transport is neutral to its contents.
#[derive(Debug, Clone, Default)]
pub struct InvokeMetadata {
    /// Raw payloads of every `InvokeMetadata` frame received, in order.
    pub raw: Vec<Vec<u8>>,
}

impl InvokeMetadata {
    /// Returns `true` if no metadata frames were observed.
    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }
}

/// Context passed to streaming handlers. Currently carries the method path
/// (a handler may support multiple methods through a single trait object) and
/// the raw invoke metadata; future extensions will add cancellation tokens
/// and trace context without breaking callers.
#[derive(Debug, Clone, Default)]
pub struct RpcContext {
    /// The DRPC method path, e.g. `/coder.tailnet.v2.Tailnet/StreamDERPMaps`.
    pub method: String,
    /// Any raw `InvokeMetadata` frames observed before the `Invoke`.
    pub metadata: InvokeMetadata,
}

/// Boxed stream of protobuf-encoded server-stream responses. Each item is
/// the raw body bytes of one DRPC `Message` frame; the framing layer is
/// responsible for wrapping them in `done=false` frames and appending the
/// terminating `Close`.
pub type ResponseStream = Pin<Box<dyn Stream<Item = Result<Vec<u8>, RpcError>> + Send + 'static>>;

/// A server-stream handler: one request → many responses. The handler owns
/// the decoding of `request_body` (so it can return `InvalidArgument` for
/// malformed protobuf) and returns a stream of already-encoded response
/// payloads that the transport forwards verbatim.
#[async_trait]
pub trait ServerStreamHandler: Send + Sync {
    /// Dispatches a server-stream invocation, returning a stream of response
    /// payloads. Returning an error from this method aborts before any
    /// response frames are sent.
    async fn invoke(
        &self,
        ctx: RpcContext,
        request_body: Vec<u8>,
    ) -> Result<ResponseStream, RpcError>;
}

/// Sink accepted by bidi-stream handlers to emit responses. Each call to
/// [`BidiResponseSink::send`] produces a `done=true` `Message` frame on the
/// wire; when the sink is dropped the transport writes a closing `Close`.
pub struct BidiResponseSink {
    /// Channel of raw (already-encoded) response bodies.
    pub(crate) tx: tokio::sync::mpsc::Sender<Result<Vec<u8>, RpcError>>,
}

impl BidiResponseSink {
    /// Queues a raw protobuf-encoded response payload for the client.
    ///
    /// Returns an error only if the transport has dropped — i.e. the client
    /// closed its side of the stream before the handler finished. Handlers
    /// should treat that as a signal to terminate.
    pub async fn send(&self, payload: Vec<u8>) -> Result<(), RpcError> {
        self.tx
            .send(Ok(payload))
            .await
            .map_err(|_| RpcError::Internal("bidi response sink closed".into()))
    }
}

/// A bidirectional-stream handler: many requests ↔ many responses sharing a
/// single stream id. The handler consumes `requests` and emits responses via
/// `sink`.
///
/// NOTE: this crate currently delivers requests in arrival order and does
/// not guarantee strong ordering against sink sends — callers that need a
/// strict interleaving semantic (e.g. tailnet `Coordinate`) should carry
/// their own sequence numbers in the protobuf. Tracked by
/// `TODO-bidi-ordering`.
#[async_trait]
pub trait BidiStreamHandler: Send + Sync {
    /// Runs a bidi-stream invocation to completion. `requests` yields one
    /// item per fully-assembled inbound `Message` packet. The handler should
    /// return when `requests.recv().await` produces `None` (client sent
    /// `CloseSend`) or when it chooses to end the stream early.
    async fn invoke(
        &self,
        ctx: RpcContext,
        requests: tokio::sync::mpsc::Receiver<Vec<u8>>,
        sink: BidiResponseSink,
    ) -> Result<(), RpcError>;
}

/// A do-nothing implementation used in tests and as a default integration
/// point while Phase-2 handlers are in flight. Each method returns an empty
/// but well-formed response so that the transport can be exercised without
/// pulling in database or pubsub dependencies.
#[derive(Debug, Default, Clone, Copy)]
pub struct StubHandler;

#[async_trait]
impl AgentRpcHandler for StubHandler {
    async fn get_manifest(
        &self,
        _req: agent::GetManifestRequest,
    ) -> Result<agent::Manifest, RpcError> {
        Ok(agent::Manifest::default())
    }

    async fn get_announcement_banners(
        &self,
        _req: agent::GetAnnouncementBannersRequest,
    ) -> Result<agent::GetAnnouncementBannersResponse, RpcError> {
        Ok(agent::GetAnnouncementBannersResponse::default())
    }

    async fn update_startup(
        &self,
        req: agent::UpdateStartupRequest,
    ) -> Result<agent::Startup, RpcError> {
        Ok(req.startup.unwrap_or_default())
    }

    async fn batch_update_app_health(
        &self,
        _req: agent::BatchUpdateAppHealthRequest,
    ) -> Result<agent::BatchUpdateAppHealthResponse, RpcError> {
        Ok(agent::BatchUpdateAppHealthResponse::default())
    }
}
