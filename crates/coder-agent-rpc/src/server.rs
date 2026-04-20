//! Per-stream DRPC server.
//!
//! Each yamux-accepted stream carries a single DRPC RPC invocation. Three
//! invocation shapes are supported:
//!
//! * **Unary** (request → response)
//!   1. client sends `Invoke` with the method path in the body
//!   2. client sends `Message` with the request protobuf
//!   3. client may send `CloseSend` (optional)
//!   4. server replies with `Message` carrying the response protobuf
//!   5. server sends `Close` to complete the RPC
//!
//! * **Server-stream** (request → many responses): same prelude as unary,
//!   but step 4 repeats — the server writes one `Message` per item the
//!   handler stream yields, each with a fresh server-side message id, and
//!   terminates with a `Close`. Handlers are registered via
//!   [`StreamRegistry::register_server_stream`].
//!
//! * **Bidi-stream** (many requests ↔ many responses): after `Invoke`, each
//!   side sends `Message` frames with `done=true` (or multi-frame when
//!   individual messages exceed the transport cap — see
//!   [`crate::wire::PacketReassembler`]). The client eventually sends
//!   `CloseSend` to signal it will not send further; the server closes the
//!   stream with `Close` once its handler returns. Handlers are registered
//!   via [`StreamRegistry::register_bidi`].
//!
//! Errors are surfaced as DRPC `Error` packets and map onto handler
//! [`RpcError`] variants.

use std::collections::HashMap;
use std::sync::Arc;

use futures_util::StreamExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use crate::error::{DrpcError, DrpcResult};
use crate::handlers::{
    AgentRpcHandler, BidiResponseSink, BidiStreamHandler, InvokeMetadata, RpcContext, RpcError,
    ServerStreamHandler,
};
use crate::proto::agent_v2 as agent;
use crate::wire::{self, Kind, Packet, PacketId};

/// DRPC error code used for unimplemented methods. Matches
/// `drpcerr.Unimplemented` from the Go library (a sentinel value used by
/// the official client to detect missing handlers).
const DRPC_ERR_UNIMPLEMENTED: u64 = 12;
/// DRPC error code used for malformed request messages.
const DRPC_ERR_INVALID_ARGUMENT: u64 = 3;
/// Generic internal-server-error DRPC code.
const DRPC_ERR_INTERNAL: u64 = 13;

/// Maximum number of `InvokeMetadata` packets we will accept before the
/// `Invoke`. This is a defensive cap against a peer spamming metadata frames.
const MAX_INVOKE_METADATA_PACKETS: usize = 16;

/// A registry of streaming handlers keyed by DRPC method path.
///
/// The unary dispatcher in [`AgentRpcHandler`] always serves a known set of
/// agent methods and cannot express server-stream or bidi-stream semantics
/// (both of which require the handler to drive I/O on the same stream id
/// beyond a single request/response pair). Callers that want to serve
/// streaming RPCs — notably the tailnet service — populate a
/// [`StreamRegistry`] with their handler impls and pass it alongside the
/// unary handler to [`serve_drpc_stream_with_streams`] /
/// [`serve_yamux_with_streams`].
///
/// If a method path is registered here, the transport routes the invocation
/// to the streaming handler and never invokes the unary handler for that
/// call. Methods not registered here fall through to the unary handler, so
/// you can mix both kinds of RPC on the same transport.
#[derive(Default, Clone)]
pub struct StreamRegistry {
    server_streams: HashMap<String, Arc<dyn ServerStreamHandler>>,
    bidi_streams: HashMap<String, Arc<dyn BidiStreamHandler>>,
}

impl std::fmt::Debug for StreamRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamRegistry")
            .field("server_streams", &self.server_streams.keys())
            .field("bidi_streams", &self.bidi_streams.keys())
            .finish()
    }
}

impl StreamRegistry {
    /// Creates an empty registry. Equivalent to `Default::default()`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a server-stream handler under `method`. Overwrites any
    /// prior registration for the same path.
    pub fn register_server_stream(
        &mut self,
        method: impl Into<String>,
        handler: Arc<dyn ServerStreamHandler>,
    ) {
        self.server_streams.insert(method.into(), handler);
    }

    /// Registers a bidi-stream handler under `method`. Overwrites any
    /// prior registration for the same path.
    pub fn register_bidi(
        &mut self,
        method: impl Into<String>,
        handler: Arc<dyn BidiStreamHandler>,
    ) {
        self.bidi_streams.insert(method.into(), handler);
    }

    /// Returns `true` if either a server-stream or bidi handler is
    /// registered for `method`.
    #[must_use]
    pub fn has(&self, method: &str) -> bool {
        self.server_streams.contains_key(method) || self.bidi_streams.contains_key(method)
    }

    fn lookup_server_stream(&self, method: &str) -> Option<Arc<dyn ServerStreamHandler>> {
        self.server_streams.get(method).cloned()
    }

    fn lookup_bidi(&self, method: &str) -> Option<Arc<dyn BidiStreamHandler>> {
        self.bidi_streams.get(method).cloned()
    }
}

/// Drives a single DRPC stream to completion using unary dispatch only.
/// Preserved for callers that do not need streaming; internally delegates
/// to [`serve_drpc_stream_with_streams`] with an empty
/// [`StreamRegistry`].
pub async fn serve_drpc_stream<S, H>(stream: S, handler: Arc<H>) -> DrpcResult<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    H: AgentRpcHandler + ?Sized + 'static,
{
    serve_drpc_stream_with_streams(stream, handler, Arc::new(StreamRegistry::new())).await
}

/// Drives a single DRPC stream to completion. Routes the invocation to:
///
/// * the bidi-stream handler registered in `streams` if the client's method
///   path matches;
/// * otherwise the server-stream handler registered in `streams`;
/// * otherwise falls through to the unary `handler`.
///
/// See the module docs for the frame-level choreography of each case.
pub async fn serve_drpc_stream_with_streams<S, H>(
    mut stream: S,
    handler: Arc<H>,
    streams: Arc<StreamRegistry>,
) -> DrpcResult<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    H: AgentRpcHandler + ?Sized + 'static,
{
    // -- 1. Invoke --------------------------------------------------------
    // Skip any leading `InvokeMetadata` packets; they carry context the
    // Phase-1 handlers do not consume, but Go clients may still emit them.
    let mut metadata_seen = 0usize;
    let mut metadata = InvokeMetadata::default();
    let invoke = loop {
        let p = wire::read_packet(&mut stream).await?;
        match p.kind {
            Kind::InvokeMetadata => {
                metadata_seen += 1;
                if metadata_seen > MAX_INVOKE_METADATA_PACKETS {
                    return Err(DrpcError::Protocol(format!(
                        "too many InvokeMetadata packets (>{MAX_INVOKE_METADATA_PACKETS}) before Invoke"
                    )));
                }
                metadata.raw.push(p.data);
                continue;
            }
            Kind::Invoke => break p,
            other => {
                return Err(DrpcError::Protocol(format!(
                    "expected Invoke, got {other:?}"
                )));
            }
        }
    };
    let method = std::str::from_utf8(&invoke.data)
        .map_err(|e| DrpcError::Protocol(format!("invalid method utf-8: {e}")))?
        .to_owned();

    // -- 2. Route --------------------------------------------------------
    if let Some(bidi) = streams.lookup_bidi(&method) {
        return drive_bidi(
            stream,
            bidi,
            RpcContext { method, metadata },
            invoke.id.stream,
        )
        .await;
    }
    if let Some(server_stream) = streams.lookup_server_stream(&method) {
        return drive_server_stream(
            stream,
            server_stream,
            RpcContext { method, metadata },
            invoke.id.stream,
        )
        .await;
    }

    drive_unary(stream, handler, &method, invoke.id.stream).await
}

/// Unary request/response flow: read one `Message`, dispatch, write one
/// `Message` + `Close` (or an `Error` packet).
async fn drive_unary<S, H>(
    mut stream: S,
    handler: Arc<H>,
    method: &str,
    invoke_stream_id: u64,
) -> DrpcResult<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    H: AgentRpcHandler + ?Sized,
{
    // Response frames carry the same `stream` ID as the client's request, but
    // their `message` component is a server-side counter that increments per
    // outgoing frame — matching Go's `drpcstream` (which does
    // `s.write.ID.Message++` before every `MsgSend` / `SendError` / `Close`).
    let p = wire::read_packet(&mut stream).await?;
    let (body, stream_id) = match p.kind {
        Kind::Message => (p.data, p.id.stream),
        Kind::CloseSend => {
            return Err(DrpcError::Protocol(
                "client CloseSend before sending request body".into(),
            ));
        }
        Kind::Cancel | Kind::Close => {
            return Ok(());
        }
        other => {
            return Err(DrpcError::Protocol(format!(
                "unexpected packet {other:?} while reading request"
            )));
        }
    };
    let _ = invoke_stream_id; // retained for potential tracing; response uses stream_id.

    let result = dispatch(handler.as_ref(), method, &body).await;

    let mut out_message = 0u64;
    let mut next_id = || {
        out_message += 1;
        PacketId {
            stream: stream_id,
            message: out_message,
        }
    };
    match result {
        Ok(response_bytes) => {
            wire::write_packet(
                &mut stream,
                &Packet {
                    kind: Kind::Message,
                    id: next_id(),
                    data: response_bytes,
                },
            )
            .await?;
            wire::write_packet(
                &mut stream,
                &Packet {
                    kind: Kind::Close,
                    id: next_id(),
                    data: Vec::new(),
                },
            )
            .await?;
        }
        Err(err) => {
            let (code, msg) = rpc_error_to_drpc(&err);
            wire::write_error(&mut stream, next_id(), code, msg.as_str()).await?;
        }
    }
    Ok(())
}

/// Server-stream flow: read one `Message`, invoke the handler to obtain a
/// stream of encoded responses, write each as a `done=true` `Message` frame
/// with a fresh server-side message id, then terminate with `Close`. If the
/// handler returns an error before producing any responses, an `Error`
/// packet is written instead of the stream of messages.
async fn drive_server_stream<S>(
    mut stream: S,
    handler: Arc<dyn ServerStreamHandler>,
    ctx: RpcContext,
    invoke_stream_id: u64,
) -> DrpcResult<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let p = wire::read_packet(&mut stream).await?;
    let (body, stream_id) = match p.kind {
        Kind::Message => (p.data, p.id.stream),
        Kind::CloseSend => {
            return Err(DrpcError::Protocol(
                "client CloseSend before sending request body".into(),
            ));
        }
        Kind::Cancel | Kind::Close => {
            return Ok(());
        }
        other => {
            return Err(DrpcError::Protocol(format!(
                "unexpected packet {other:?} while reading request"
            )));
        }
    };
    let _ = invoke_stream_id;

    let mut out_message = 0u64;
    let mut next_id = || {
        out_message += 1;
        PacketId {
            stream: stream_id,
            message: out_message,
        }
    };

    let stream_result = handler.invoke(ctx, body).await;
    let mut response_stream = match stream_result {
        Ok(s) => s,
        Err(err) => {
            let (code, msg) = rpc_error_to_drpc(&err);
            wire::write_error(&mut stream, next_id(), code, msg.as_str()).await?;
            return Ok(());
        }
    };

    loop {
        match response_stream.next().await {
            Some(Ok(payload)) => {
                wire::write_packet(
                    &mut stream,
                    &Packet {
                        kind: Kind::Message,
                        id: next_id(),
                        data: payload,
                    },
                )
                .await?;
            }
            Some(Err(err)) => {
                let (code, msg) = rpc_error_to_drpc(&err);
                wire::write_error(&mut stream, next_id(), code, msg.as_str()).await?;
                return Ok(());
            }
            None => break,
        }
    }

    wire::write_packet(
        &mut stream,
        &Packet {
            kind: Kind::Close,
            id: next_id(),
            data: Vec::new(),
        },
    )
    .await?;
    Ok(())
}

/// Bidi-stream flow: split the byte stream so that inbound packets are fed
/// to the handler via a request channel and outbound responses are drained
/// from a response channel onto the wire. Completes when:
/// * the handler returns (server finished emitting), or
/// * the client sends `CloseSend`/`Cancel`/`Close`, or
/// * the underlying transport EOFs.
async fn drive_bidi<S>(
    stream: S,
    handler: Arc<dyn BidiStreamHandler>,
    ctx: RpcContext,
    invoke_stream_id: u64,
) -> DrpcResult<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // We need independent reader + writer halves so the inbound pump and
    // outbound pump can run concurrently. `tokio::io::split` gives us
    // those without requiring the caller to provide a `Split` type.
    let (mut reader, mut writer) = tokio::io::split(stream);

    let (req_tx, req_rx) = mpsc::channel::<Vec<u8>>(32);
    let (resp_tx, mut resp_rx) = mpsc::channel::<Result<Vec<u8>, RpcError>>(32);
    let sink = BidiResponseSink { tx: resp_tx };

    // Spawn the handler. It owns `req_rx` and `sink`. Dropping `sink` when
    // the handler returns closes resp_rx on the writer side, which is how
    // the writer task knows to send the terminal `Close`.
    let handler_task = tokio::spawn({
        let handler = handler.clone();
        async move { handler.invoke(ctx, req_rx, sink).await }
    });

    // Inbound pump: read frames, feed them to the handler via `req_tx`,
    // stop on CloseSend/Cancel/Close.
    let reader_task = tokio::spawn(async move {
        loop {
            let packet = match wire::read_packet(&mut reader).await {
                Ok(p) => p,
                Err(DrpcError::Closed) => break,
                Err(e) => {
                    tracing::debug!(error = %e, "bidi: read error");
                    break;
                }
            };
            match packet.kind {
                Kind::Message => {
                    if req_tx.send(packet.data).await.is_err() {
                        break;
                    }
                }
                Kind::CloseSend => {
                    // Client will not send more. Drop req_tx so the
                    // handler's receiver yields None on next recv.
                    break;
                }
                Kind::Cancel | Kind::Close => {
                    break;
                }
                other => {
                    tracing::debug!(?other, "bidi: ignoring unexpected packet kind");
                }
            }
        }
        // Dropping `req_tx` when this task exits signals EOF to the handler.
        drop(req_tx);
        let _ = &mut reader;
    });

    // Outbound pump: drain responses onto the wire until the handler's sink
    // is dropped, then write the closing `Close` packet.
    let mut out_message = 0u64;
    let mut next_id = || {
        out_message += 1;
        PacketId {
            stream: invoke_stream_id,
            message: out_message,
        }
    };
    while let Some(item) = resp_rx.recv().await {
        match item {
            Ok(payload) => {
                wire::write_packet(
                    &mut writer,
                    &Packet {
                        kind: Kind::Message,
                        id: next_id(),
                        data: payload,
                    },
                )
                .await?;
            }
            Err(err) => {
                let (code, msg) = rpc_error_to_drpc(&err);
                wire::write_error(&mut writer, next_id(), code, msg.as_str()).await?;
                // After an error frame we do not also write Close: the
                // Error packet is terminal per DRPC semantics.
                // Reap the handler and reader before returning.
                let _ = handler_task.await;
                reader_task.abort();
                return Ok(());
            }
        }
    }
    // Sink closed → handler finished cleanly. Emit Close.
    wire::write_packet(
        &mut writer,
        &Packet {
            kind: Kind::Close,
            id: next_id(),
            data: Vec::new(),
        },
    )
    .await?;
    // Ensure the reader task is stopped before we exit.
    reader_task.abort();
    // Wait for the handler future to settle so we surface its error if any.
    match handler_task.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => {
            tracing::debug!(error = %err, "bidi: handler returned error after close");
            Ok(())
        }
        Err(e) if e.is_cancelled() => Ok(()),
        Err(e) => Err(DrpcError::Protocol(format!("bidi handler join: {e}"))),
    }
}

fn rpc_error_to_drpc(err: &RpcError) -> (u64, String) {
    match err {
        RpcError::Unimplemented(m) => (DRPC_ERR_UNIMPLEMENTED, format!("unimplemented: {m}")),
        RpcError::InvalidArgument(m) => {
            (DRPC_ERR_INVALID_ARGUMENT, format!("invalid argument: {m}"))
        }
        RpcError::Internal(m) => (DRPC_ERR_INTERNAL, format!("internal: {m}")),
    }
}

/// Decodes the request, routes to the appropriate handler method, and
/// encodes the response. Framing-layer packet construction happens in
/// [`serve_drpc_stream`]; this function handles only protobuf<->method
/// translation.
async fn dispatch<H: AgentRpcHandler + ?Sized>(
    handler: &H,
    method: &str,
    body: &[u8],
) -> Result<Vec<u8>, RpcError> {
    fn decode<T: prost::Message + Default>(body: &[u8]) -> Result<T, RpcError> {
        T::decode(body).map_err(|e| RpcError::InvalidArgument(format!("decode: {e}")))
    }
    fn encode<T: prost::Message>(msg: &T) -> Result<Vec<u8>, RpcError> {
        let mut buf = Vec::with_capacity(msg.encoded_len());
        msg.encode(&mut buf)
            .map_err(|e| RpcError::Internal(format!("encode: {e}")))?;
        Ok(buf)
    }

    match method {
        "/coder.agent.v2.Agent/GetManifest" => {
            let req = decode::<agent::GetManifestRequest>(body)?;
            let resp = handler.get_manifest(req).await?;
            encode(&resp)
        }
        "/coder.agent.v2.Agent/GetAnnouncementBanners" => {
            let req = decode::<agent::GetAnnouncementBannersRequest>(body)?;
            let resp = handler.get_announcement_banners(req).await?;
            encode(&resp)
        }
        "/coder.agent.v2.Agent/UpdateStartup" => {
            let req = decode::<agent::UpdateStartupRequest>(body)?;
            let resp = handler.update_startup(req).await?;
            encode(&resp)
        }
        "/coder.agent.v2.Agent/BatchUpdateAppHealths" => {
            let req = decode::<agent::BatchUpdateAppHealthRequest>(body)?;
            let resp = handler.batch_update_app_health(req).await?;
            encode(&resp)
        }
        "/coder.agent.v2.Agent/UpdateStats" => {
            let req = decode::<agent::UpdateStatsRequest>(body)?;
            let resp = handler.update_stats(req).await?;
            encode(&resp)
        }
        "/coder.agent.v2.Agent/UpdateLifecycle" => {
            let req = decode::<agent::UpdateLifecycleRequest>(body)?;
            let resp = handler.update_lifecycle(req).await?;
            encode(&resp)
        }
        "/coder.agent.v2.Agent/BatchCreateLogs" => {
            let req = decode::<agent::BatchCreateLogsRequest>(body)?;
            let resp = handler.batch_create_logs(req).await?;
            encode(&resp)
        }
        "/coder.agent.v2.Agent/BatchUpdateMetadata" => {
            let req = decode::<agent::BatchUpdateMetadataRequest>(body)?;
            let resp = handler.batch_update_metadata(req).await?;
            encode(&resp)
        }
        "/coder.agent.v2.Agent/ScriptCompleted" => {
            let req = decode::<agent::WorkspaceAgentScriptCompletedRequest>(body)?;
            let resp = handler.script_completed(req).await?;
            encode(&resp)
        }
        "/coder.agent.v2.Agent/GetServiceBanner" => {
            let req = decode::<agent::GetServiceBannerRequest>(body)?;
            let resp = handler.get_service_banner(req).await?;
            encode(&resp)
        }
        // Returns `google.protobuf.Empty` — encoded as zero bytes on the wire.
        "/coder.agent.v2.Agent/ReportConnection" => {
            let req = decode::<agent::ReportConnectionRequest>(body)?;
            handler.report_connection(req).await?;
            Ok(Vec::new())
        }
        "/coder.agent.v2.Agent/GetResourcesMonitoringConfiguration" => {
            let req = decode::<agent::GetResourcesMonitoringConfigurationRequest>(body)?;
            let resp = handler.get_resources_monitoring_configuration(req).await?;
            encode(&resp)
        }
        "/coder.agent.v2.Agent/PushResourcesMonitoringUsage" => {
            let req = decode::<agent::PushResourcesMonitoringUsageRequest>(body)?;
            let resp = handler.push_resources_monitoring_usage(req).await?;
            encode(&resp)
        }
        "/coder.agent.v2.Agent/CreateSubAgent" => {
            let req = decode::<agent::CreateSubAgentRequest>(body)?;
            let resp = handler.create_sub_agent(req).await?;
            encode(&resp)
        }
        "/coder.agent.v2.Agent/DeleteSubAgent" => {
            let req = decode::<agent::DeleteSubAgentRequest>(body)?;
            let resp = handler.delete_sub_agent(req).await?;
            encode(&resp)
        }
        "/coder.agent.v2.Agent/ListSubAgents" => {
            let req = decode::<agent::ListSubAgentsRequest>(body)?;
            let resp = handler.list_sub_agents(req).await?;
            encode(&resp)
        }
        "/coder.agent.v2.Agent/ReportBoundaryLogs" => {
            let req = decode::<agent::ReportBoundaryLogsRequest>(body)?;
            let resp = handler.report_boundary_logs(req).await?;
            encode(&resp)
        }
        "/coder.agent.v2.Agent/UpdateAppStatus" => {
            let req = decode::<agent::UpdateAppStatusRequest>(body)?;
            let resp = handler.update_app_status(req).await?;
            encode(&resp)
        }
        other => Err(RpcError::Unimplemented(other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handlers::StubHandler;
    use crate::wire::PacketId;
    use prost::Message as _;
    use tokio::io::duplex;

    /// Drive one RPC end-to-end over a duplex stream: client writes
    /// Invoke + Message, reads Message + Close.
    async fn roundtrip(method: &str, request: &[u8]) -> DrpcResult<Vec<u8>> {
        let (mut client, server) = duplex(64 * 1024);
        let server_task =
            tokio::spawn(async move { serve_drpc_stream(server, Arc::new(StubHandler)).await });

        let id = PacketId {
            stream: 1,
            message: 1,
        };
        wire::write_packet(
            &mut client,
            &Packet {
                kind: Kind::Invoke,
                id,
                data: method.as_bytes().to_vec(),
            },
        )
        .await?;
        wire::write_packet(
            &mut client,
            &Packet {
                kind: Kind::Message,
                id: PacketId {
                    stream: 1,
                    message: 2,
                },
                data: request.to_vec(),
            },
        )
        .await?;

        let resp = wire::read_packet(&mut client).await?;
        assert_eq!(resp.kind, Kind::Message);
        let close = wire::read_packet(&mut client).await?;
        assert_eq!(close.kind, Kind::Close);
        // The server must use its own outbound message counter, not reuse the
        // client's request IDs. Matches Go drpc's per-stream write counter:
        // response Message=1, Close=2. Stream ID is inherited from the client.
        assert_eq!(resp.id.stream, 1);
        assert_eq!(resp.id.message, 1);
        assert_eq!(close.id.stream, 1);
        assert_eq!(close.id.message, 2);

        drop(client);
        let _ = server_task.await;
        Ok(resp.data)
    }

    #[tokio::test]
    async fn roundtrip_get_manifest() -> DrpcResult<()> {
        let body = roundtrip(
            "/coder.agent.v2.Agent/GetManifest",
            &agent::GetManifestRequest {}.encode_to_vec(),
        )
        .await?;
        // The stub returns a default Manifest; decoding just validates framing.
        let _manifest = agent::Manifest::decode(&body[..])?;
        Ok(())
    }

    #[tokio::test]
    async fn roundtrip_get_announcement_banners() -> DrpcResult<()> {
        let body = roundtrip(
            "/coder.agent.v2.Agent/GetAnnouncementBanners",
            &agent::GetAnnouncementBannersRequest {}.encode_to_vec(),
        )
        .await?;
        let resp = agent::GetAnnouncementBannersResponse::decode(&body[..])?;
        assert!(resp.announcement_banners.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn roundtrip_update_startup_echoes_payload() -> DrpcResult<()> {
        let req = agent::UpdateStartupRequest {
            startup: Some(agent::Startup {
                version: "v1.2.3".into(),
                expanded_directory: "/home/coder".into(),
                subsystems: vec![],
            }),
        };
        let body = roundtrip("/coder.agent.v2.Agent/UpdateStartup", &req.encode_to_vec()).await?;
        let resp = agent::Startup::decode(&body[..])?;
        assert_eq!(resp.version, "v1.2.3");
        assert_eq!(resp.expanded_directory, "/home/coder");
        Ok(())
    }

    #[tokio::test]
    async fn roundtrip_batch_update_app_health() -> DrpcResult<()> {
        let body = roundtrip(
            "/coder.agent.v2.Agent/BatchUpdateAppHealths",
            &agent::BatchUpdateAppHealthRequest { updates: vec![] }.encode_to_vec(),
        )
        .await?;
        let _ = agent::BatchUpdateAppHealthResponse::decode(&body[..])?;
        Ok(())
    }

    #[tokio::test]
    async fn roundtrip_update_stats() -> DrpcResult<()> {
        let body = roundtrip(
            "/coder.agent.v2.Agent/UpdateStats",
            &agent::UpdateStatsRequest { stats: None }.encode_to_vec(),
        )
        .await?;
        let _ = agent::UpdateStatsResponse::decode(&body[..])?;
        Ok(())
    }

    #[tokio::test]
    async fn roundtrip_update_lifecycle_echoes_payload() -> DrpcResult<()> {
        let req = agent::UpdateLifecycleRequest {
            lifecycle: Some(agent::Lifecycle {
                state: agent::lifecycle::State::Ready as i32,
                changed_at: None,
            }),
        };
        let body = roundtrip(
            "/coder.agent.v2.Agent/UpdateLifecycle",
            &req.encode_to_vec(),
        )
        .await?;
        let resp = agent::Lifecycle::decode(&body[..])?;
        assert_eq!(resp.state, agent::lifecycle::State::Ready as i32);
        Ok(())
    }

    #[tokio::test]
    async fn roundtrip_batch_create_logs() -> DrpcResult<()> {
        let body = roundtrip(
            "/coder.agent.v2.Agent/BatchCreateLogs",
            &agent::BatchCreateLogsRequest {
                log_source_id: vec![],
                logs: vec![],
            }
            .encode_to_vec(),
        )
        .await?;
        let _ = agent::BatchCreateLogsResponse::decode(&body[..])?;
        Ok(())
    }

    #[tokio::test]
    async fn roundtrip_batch_update_metadata() -> DrpcResult<()> {
        let body = roundtrip(
            "/coder.agent.v2.Agent/BatchUpdateMetadata",
            &agent::BatchUpdateMetadataRequest { metadata: vec![] }.encode_to_vec(),
        )
        .await?;
        let _ = agent::BatchUpdateMetadataResponse::decode(&body[..])?;
        Ok(())
    }

    #[tokio::test]
    async fn roundtrip_script_completed() -> DrpcResult<()> {
        let body = roundtrip(
            "/coder.agent.v2.Agent/ScriptCompleted",
            &agent::WorkspaceAgentScriptCompletedRequest { timing: None }.encode_to_vec(),
        )
        .await?;
        let _ = agent::WorkspaceAgentScriptCompletedResponse::decode(&body[..])?;
        Ok(())
    }

    #[tokio::test]
    async fn roundtrip_get_service_banner() -> DrpcResult<()> {
        let body = roundtrip(
            "/coder.agent.v2.Agent/GetServiceBanner",
            &agent::GetServiceBannerRequest {}.encode_to_vec(),
        )
        .await?;
        let resp = agent::ServiceBanner::decode(&body[..])?;
        assert!(!resp.enabled);
        Ok(())
    }

    #[tokio::test]
    async fn roundtrip_report_connection_returns_empty_body() -> DrpcResult<()> {
        // ReportConnection returns `google.protobuf.Empty`, which on the wire
        // is a zero-length message body — not a "missing" frame.
        let body = roundtrip(
            "/coder.agent.v2.Agent/ReportConnection",
            &agent::ReportConnectionRequest { connection: None }.encode_to_vec(),
        )
        .await?;
        assert!(body.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn roundtrip_get_resources_monitoring_configuration() -> DrpcResult<()> {
        let body = roundtrip(
            "/coder.agent.v2.Agent/GetResourcesMonitoringConfiguration",
            &agent::GetResourcesMonitoringConfigurationRequest {}.encode_to_vec(),
        )
        .await?;
        let _ = agent::GetResourcesMonitoringConfigurationResponse::decode(&body[..])?;
        Ok(())
    }

    #[tokio::test]
    async fn roundtrip_push_resources_monitoring_usage() -> DrpcResult<()> {
        let body = roundtrip(
            "/coder.agent.v2.Agent/PushResourcesMonitoringUsage",
            &agent::PushResourcesMonitoringUsageRequest { datapoints: vec![] }.encode_to_vec(),
        )
        .await?;
        let _ = agent::PushResourcesMonitoringUsageResponse::decode(&body[..])?;
        Ok(())
    }

    #[tokio::test]
    async fn roundtrip_create_sub_agent() -> DrpcResult<()> {
        let body = roundtrip(
            "/coder.agent.v2.Agent/CreateSubAgent",
            &agent::CreateSubAgentRequest::default().encode_to_vec(),
        )
        .await?;
        let _ = agent::CreateSubAgentResponse::decode(&body[..])?;
        Ok(())
    }

    #[tokio::test]
    async fn roundtrip_delete_sub_agent() -> DrpcResult<()> {
        let body = roundtrip(
            "/coder.agent.v2.Agent/DeleteSubAgent",
            &agent::DeleteSubAgentRequest { id: vec![] }.encode_to_vec(),
        )
        .await?;
        let _ = agent::DeleteSubAgentResponse::decode(&body[..])?;
        Ok(())
    }

    #[tokio::test]
    async fn roundtrip_list_sub_agents() -> DrpcResult<()> {
        let body = roundtrip(
            "/coder.agent.v2.Agent/ListSubAgents",
            &agent::ListSubAgentsRequest {}.encode_to_vec(),
        )
        .await?;
        let resp = agent::ListSubAgentsResponse::decode(&body[..])?;
        assert!(resp.agents.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn roundtrip_report_boundary_logs() -> DrpcResult<()> {
        let body = roundtrip(
            "/coder.agent.v2.Agent/ReportBoundaryLogs",
            &agent::ReportBoundaryLogsRequest { logs: vec![] }.encode_to_vec(),
        )
        .await?;
        let _ = agent::ReportBoundaryLogsResponse::decode(&body[..])?;
        Ok(())
    }

    #[tokio::test]
    async fn roundtrip_update_app_status() -> DrpcResult<()> {
        let body = roundtrip(
            "/coder.agent.v2.Agent/UpdateAppStatus",
            &agent::UpdateAppStatusRequest::default().encode_to_vec(),
        )
        .await?;
        let _ = agent::UpdateAppStatusResponse::decode(&body[..])?;
        Ok(())
    }

    #[tokio::test]
    async fn leading_invoke_metadata_is_tolerated() -> DrpcResult<()> {
        // Go clients may send one or more `InvokeMetadata` packets before the
        // `Invoke` packet. The server must skip them and still complete the
        // RPC successfully.
        let (mut client, server) = duplex(64 * 1024);
        let server_task =
            tokio::spawn(async move { serve_drpc_stream(server, Arc::new(StubHandler)).await });

        // Two leading metadata packets on the same stream id.
        for i in 1..=2u64 {
            wire::write_packet(
                &mut client,
                &Packet {
                    kind: Kind::InvokeMetadata,
                    id: PacketId {
                        stream: 1,
                        message: i,
                    },
                    data: b"ignored-metadata".to_vec(),
                },
            )
            .await?;
        }
        wire::write_packet(
            &mut client,
            &Packet {
                kind: Kind::Invoke,
                id: PacketId {
                    stream: 1,
                    message: 3,
                },
                data: b"/coder.agent.v2.Agent/GetManifest".to_vec(),
            },
        )
        .await?;
        wire::write_packet(
            &mut client,
            &Packet {
                kind: Kind::Message,
                id: PacketId {
                    stream: 1,
                    message: 4,
                },
                data: agent::GetManifestRequest {}.encode_to_vec(),
            },
        )
        .await?;

        let resp = wire::read_packet(&mut client).await?;
        assert_eq!(resp.kind, Kind::Message);
        let close = wire::read_packet(&mut client).await?;
        assert_eq!(close.kind, Kind::Close);
        drop(client);
        let _ = server_task.await;
        Ok(())
    }

    #[tokio::test]
    async fn unknown_method_returns_error_packet() -> DrpcResult<()> {
        let (mut client, server) = duplex(64 * 1024);
        let server_task =
            tokio::spawn(async move { serve_drpc_stream(server, Arc::new(StubHandler)).await });

        let id = PacketId {
            stream: 1,
            message: 1,
        };
        wire::write_packet(
            &mut client,
            &Packet {
                kind: Kind::Invoke,
                id,
                data: b"/coder.agent.v2.Agent/DoesNotExist".to_vec(),
            },
        )
        .await?;
        wire::write_packet(
            &mut client,
            &Packet {
                kind: Kind::Message,
                id: PacketId {
                    stream: 1,
                    message: 2,
                },
                data: vec![],
            },
        )
        .await?;

        let resp = wire::read_packet(&mut client).await?;
        assert_eq!(resp.kind, Kind::Error);
        // Error packet uses the server-side counter: first outbound frame on
        // this stream → message=1, inheriting the client's stream id.
        assert_eq!(resp.id.stream, 1);
        assert_eq!(resp.id.message, 1);
        assert!(resp.data.len() >= 8, "error body too short");
        let code_bytes: [u8; 8] = resp.data[..8].try_into().unwrap_or([0; 8]);
        let code = u64::from_be_bytes(code_bytes);
        assert_eq!(code, DRPC_ERR_UNIMPLEMENTED);
        drop(client);
        let _ = server_task.await;
        Ok(())
    }

    #[tokio::test]
    async fn response_uses_server_side_message_counter() -> DrpcResult<()> {
        // Regression test: even when the client's request packets have large,
        // non-contiguous message IDs, the server's response must restart its
        // own counter at 1 on the same stream (Go drpc behaviour).
        let (mut client, server) = duplex(64 * 1024);
        let server_task =
            tokio::spawn(async move { serve_drpc_stream(server, Arc::new(StubHandler)).await });

        wire::write_packet(
            &mut client,
            &Packet {
                kind: Kind::Invoke,
                id: PacketId {
                    stream: 7,
                    message: 42,
                },
                data: b"/coder.agent.v2.Agent/GetManifest".to_vec(),
            },
        )
        .await?;
        wire::write_packet(
            &mut client,
            &Packet {
                kind: Kind::Message,
                id: PacketId {
                    stream: 7,
                    message: 99,
                },
                data: agent::GetManifestRequest {}.encode_to_vec(),
            },
        )
        .await?;

        let resp = wire::read_packet(&mut client).await?;
        assert_eq!(resp.kind, Kind::Message);
        assert_eq!(resp.id.stream, 7, "response must inherit client stream id");
        assert_eq!(
            resp.id.message, 1,
            "response must use server-side counter starting at 1"
        );

        let close = wire::read_packet(&mut client).await?;
        assert_eq!(close.kind, Kind::Close);
        assert_eq!(close.id.stream, 7);
        assert_eq!(
            close.id.message, 2,
            "Close must use the next server-side message id"
        );

        drop(client);
        let _ = server_task.await;
        Ok(())
    }

    // ---------- Server-stream dispatcher tests ----------

    use crate::handlers::{
        BidiResponseSink, BidiStreamHandler, ResponseStream, RpcContext, ServerStreamHandler,
    };
    use async_trait::async_trait;
    use futures_util::stream;
    use tokio::sync::mpsc;

    /// Test server-stream handler that yields the configured list of
    /// Ok payloads and then ends the stream.
    struct ScriptedServerStream {
        items: Vec<Vec<u8>>,
    }

    #[async_trait]
    impl ServerStreamHandler for ScriptedServerStream {
        async fn invoke(
            &self,
            _ctx: RpcContext,
            _request_body: Vec<u8>,
        ) -> Result<ResponseStream, RpcError> {
            let items = self.items.clone();
            let s = stream::iter(items.into_iter().map(Ok::<_, RpcError>));
            Ok(Box::pin(s))
        }
    }

    #[tokio::test]
    async fn server_stream_emits_three_messages_then_close() -> DrpcResult<()> {
        // Server-stream shape: client sends Invoke + Message, server emits
        // three Message frames, then a Close. All share the client's stream id.
        let (mut client, server) = duplex(64 * 1024);

        let method = "/test.v1/Echo";
        let mut registry = StreamRegistry::new();
        registry.register_server_stream(
            method,
            Arc::new(ScriptedServerStream {
                items: vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()],
            }),
        );
        let registry = Arc::new(registry);

        let server_task = tokio::spawn(async move {
            serve_drpc_stream_with_streams(server, Arc::new(StubHandler), registry).await
        });

        let id = PacketId {
            stream: 42,
            message: 1,
        };
        wire::write_packet(
            &mut client,
            &Packet {
                kind: Kind::Invoke,
                id,
                data: method.as_bytes().to_vec(),
            },
        )
        .await?;
        wire::write_packet(
            &mut client,
            &Packet {
                kind: Kind::Message,
                id: PacketId {
                    stream: 42,
                    message: 2,
                },
                data: vec![],
            },
        )
        .await?;

        // Read three Message packets and one Close. Server message ids run
        // 1..=4 on the client's stream id.
        let mut received = Vec::new();
        for expected_msg_id in 1u64..=3 {
            let p = wire::read_packet(&mut client).await?;
            assert_eq!(p.kind, Kind::Message);
            assert_eq!(p.id.stream, 42);
            assert_eq!(p.id.message, expected_msg_id);
            received.push(p.data);
        }
        let close = wire::read_packet(&mut client).await?;
        assert_eq!(close.kind, Kind::Close);
        assert_eq!(close.id.stream, 42);
        assert_eq!(close.id.message, 4);

        assert_eq!(
            received,
            vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()]
        );

        drop(client);
        let _ = server_task.await;
        Ok(())
    }

    #[tokio::test]
    async fn server_stream_empty_stream_just_writes_close() -> DrpcResult<()> {
        // Handler yields nothing; server must still send a Close so the
        // client doesn't hang.
        let (mut client, server) = duplex(64 * 1024);
        let method = "/test.v1/Empty";
        let mut registry = StreamRegistry::new();
        registry.register_server_stream(method, Arc::new(ScriptedServerStream { items: vec![] }));
        let registry = Arc::new(registry);

        let server_task = tokio::spawn(async move {
            serve_drpc_stream_with_streams(server, Arc::new(StubHandler), registry).await
        });
        let id = PacketId {
            stream: 1,
            message: 1,
        };
        wire::write_packet(
            &mut client,
            &Packet {
                kind: Kind::Invoke,
                id,
                data: method.as_bytes().to_vec(),
            },
        )
        .await?;
        wire::write_packet(
            &mut client,
            &Packet {
                kind: Kind::Message,
                id: PacketId {
                    stream: 1,
                    message: 2,
                },
                data: vec![],
            },
        )
        .await?;
        let close = wire::read_packet(&mut client).await?;
        assert_eq!(close.kind, Kind::Close);
        assert_eq!(close.id.stream, 1);
        assert_eq!(close.id.message, 1);
        drop(client);
        let _ = server_task.await;
        Ok(())
    }

    // ---------- Bidi-stream dispatcher tests ----------

    /// Echo-style bidi handler: reads each inbound payload and sends it back
    /// prefixed with `"echo:"`. Exits when the request channel closes.
    struct EchoBidi;

    #[async_trait]
    impl BidiStreamHandler for EchoBidi {
        async fn invoke(
            &self,
            _ctx: RpcContext,
            mut requests: mpsc::Receiver<Vec<u8>>,
            sink: BidiResponseSink,
        ) -> Result<(), RpcError> {
            while let Some(req) = requests.recv().await {
                let mut resp = b"echo:".to_vec();
                resp.extend_from_slice(&req);
                if sink.send(resp).await.is_err() {
                    break;
                }
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn bidi_stream_client_two_server_two() -> DrpcResult<()> {
        // Client sends two Messages; server replies "echo:<msg>" for each;
        // after CloseSend, server sends Close. All shared stream id.
        let (mut client, server) = duplex(64 * 1024);
        let method = "/test.v1/Echo";
        let mut registry = StreamRegistry::new();
        registry.register_bidi(method, Arc::new(EchoBidi));
        let registry = Arc::new(registry);

        let server_task = tokio::spawn(async move {
            serve_drpc_stream_with_streams(server, Arc::new(StubHandler), registry).await
        });

        let stream_id = 9u64;
        wire::write_packet(
            &mut client,
            &Packet {
                kind: Kind::Invoke,
                id: PacketId {
                    stream: stream_id,
                    message: 1,
                },
                data: method.as_bytes().to_vec(),
            },
        )
        .await?;

        // First request + read first response.
        wire::write_packet(
            &mut client,
            &Packet {
                kind: Kind::Message,
                id: PacketId {
                    stream: stream_id,
                    message: 2,
                },
                data: b"hello".to_vec(),
            },
        )
        .await?;
        let resp1 = wire::read_packet(&mut client).await?;
        assert_eq!(resp1.kind, Kind::Message);
        assert_eq!(resp1.id.stream, stream_id);
        assert_eq!(resp1.data, b"echo:hello");

        // Second request + read second response.
        wire::write_packet(
            &mut client,
            &Packet {
                kind: Kind::Message,
                id: PacketId {
                    stream: stream_id,
                    message: 3,
                },
                data: b"world".to_vec(),
            },
        )
        .await?;
        let resp2 = wire::read_packet(&mut client).await?;
        assert_eq!(resp2.kind, Kind::Message);
        assert_eq!(resp2.id.stream, stream_id);
        assert_eq!(resp2.data, b"echo:world");

        // Half-close so the server handler yields None and the dispatcher
        // emits Close.
        wire::write_packet(
            &mut client,
            &Packet {
                kind: Kind::CloseSend,
                id: PacketId {
                    stream: stream_id,
                    message: 4,
                },
                data: vec![],
            },
        )
        .await?;
        let close = wire::read_packet(&mut client).await?;
        assert_eq!(close.kind, Kind::Close);
        assert_eq!(close.id.stream, stream_id);

        // Server-side outbound counter: resp1=1, resp2=2, close=3.
        assert_eq!(resp1.id.message, 1);
        assert_eq!(resp2.id.message, 2);
        assert_eq!(close.id.message, 3);

        drop(client);
        let _ = server_task.await;
        Ok(())
    }

    #[tokio::test]
    async fn streaming_falls_through_to_unary_when_method_unregistered() -> DrpcResult<()> {
        // A method not listed in the registry must go through the unary
        // handler — proving the registry is additive and not exclusive.
        let (mut client, server) = duplex(64 * 1024);
        let registry = Arc::new(StreamRegistry::new()); // empty
        let server_task = tokio::spawn(async move {
            serve_drpc_stream_with_streams(server, Arc::new(StubHandler), registry).await
        });
        wire::write_packet(
            &mut client,
            &Packet {
                kind: Kind::Invoke,
                id: PacketId {
                    stream: 1,
                    message: 1,
                },
                data: b"/coder.agent.v2.Agent/GetManifest".to_vec(),
            },
        )
        .await?;
        wire::write_packet(
            &mut client,
            &Packet {
                kind: Kind::Message,
                id: PacketId {
                    stream: 1,
                    message: 2,
                },
                data: agent::GetManifestRequest {}.encode_to_vec(),
            },
        )
        .await?;
        let resp = wire::read_packet(&mut client).await?;
        assert_eq!(resp.kind, Kind::Message);
        let close = wire::read_packet(&mut client).await?;
        assert_eq!(close.kind, Kind::Close);
        drop(client);
        let _ = server_task.await;
        Ok(())
    }
}
