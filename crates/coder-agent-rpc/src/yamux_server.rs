//! Serves the agent DRPC protocol over a yamux session.
//!
//! The agent opens a WebSocket to `/api/v2/workspaceagents/me/rpc` and then
//! establishes a yamux **client** session on top of the binary stream. The
//! Rust `coderd` plays the yamux **server** role: it accepts incoming
//! streams and hands each one to [`crate::server::serve_drpc_stream`] for
//! dispatch.
//!
//! We depend on the `yamux` crate which exposes futures-io (`AsyncRead` /
//! `AsyncWrite` from the `futures` crate). The caller supplies a tokio I/O
//! stream; we bridge with `tokio_util::compat`.

use std::future::poll_fn;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::{debug, warn};
use yamux::{Config, Connection, Mode};

use crate::error::{DrpcError, DrpcResult};
use crate::handlers::AgentRpcHandler;
use crate::server::serve_drpc_stream;

/// Runs a yamux server over `transport`, accepting DRPC streams and
/// dispatching each to `handler`. Completes when the session closes.
///
/// `transport` must be a tokio-compatible bidirectional byte stream —
/// typically the adapter that wraps the accepted WebSocket.
pub async fn serve_yamux<T, H>(transport: T, handler: Arc<H>) -> DrpcResult<()>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    H: AgentRpcHandler + 'static,
{
    let compat: Compat<T> = transport.compat();
    let mut connection: Connection<Compat<T>> =
        Connection::new(compat, Config::default(), Mode::Server);

    loop {
        let next = poll_fn(|cx| connection.poll_next_inbound(cx)).await;
        match next {
            Some(Ok(stream)) => {
                let handler = handler.clone();
                tokio::spawn(async move {
                    // yamux::Stream is futures-io; bridge it back to tokio-io
                    // so we can reuse the tokio-based DRPC framing code.
                    let compat = FuturesAsyncReadCompatExt::compat(stream);
                    if let Err(err) = serve_drpc_stream(compat, handler).await {
                        match err {
                            DrpcError::Closed => {}
                            other => warn!(error = %other, "agent drpc stream ended with error"),
                        }
                    }
                });
            }
            Some(Err(err)) => {
                debug!(error = %err, "yamux session error");
                return Err(DrpcError::Protocol(format!("yamux: {err}")));
            }
            None => {
                debug!("yamux session closed");
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handlers::StubHandler;
    use crate::proto::agent_v2 as agent;
    use crate::wire::{self, Kind, Packet, PacketId};
    use prost::Message as _;
    use tokio::io::duplex;

    /// End-to-end: two tokio duplex streams — one side runs the server's
    /// yamux listener + DRPC dispatch, the other side opens a yamux client
    /// stream and performs a `GetManifest` RPC.
    #[tokio::test]
    async fn yamux_end_to_end_get_manifest() -> DrpcResult<()> {
        let (server_side, client_side) = duplex(256 * 1024);

        let server_task =
            tokio::spawn(async move { serve_yamux(server_side, Arc::new(StubHandler)).await });

        // Client side: spin up a yamux Client connection, open a stream,
        // then drive the connection forward in the background.
        let client_compat = client_side.compat();
        let mut client_conn = Connection::new(client_compat, Config::default(), Mode::Client);

        let stream = poll_fn(|cx| client_conn.poll_new_outbound(cx))
            .await
            .map_err(|e| DrpcError::Protocol(format!("yamux open: {e}")))?;

        // Drive the connection so frames flow in/out.
        tokio::spawn(async move {
            while poll_fn(|cx| client_conn.poll_next_inbound(cx))
                .await
                .is_some()
            {}
        });

        let mut stream = FuturesAsyncReadCompatExt::compat(stream);

        // Invoke GetManifest on the freshly-opened yamux stream.
        let id = PacketId {
            stream: 1,
            message: 1,
        };
        wire::write_packet(
            &mut stream,
            &Packet {
                kind: Kind::Invoke,
                id,
                data: b"/coder.agent.v2.Agent/GetManifest".to_vec(),
            },
        )
        .await?;
        wire::write_packet(
            &mut stream,
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

        let resp = wire::read_packet(&mut stream).await?;
        assert_eq!(resp.kind, Kind::Message);
        let close = wire::read_packet(&mut stream).await?;
        assert_eq!(close.kind, Kind::Close);

        let _m = agent::Manifest::decode(&resp.data[..])?;

        drop(stream);
        // Best-effort: let the server task wind down.
        let _ = tokio::time::timeout(std::time::Duration::from_millis(200), server_task).await;
        Ok(())
    }
}
