//! Per-stream DRPC server.
//!
//! Each yamux-accepted stream carries a single DRPC RPC invocation:
//!
//! 1. client sends `Invoke` with the method path in the body
//! 2. client sends `Message` with the request protobuf
//! 3. client sends `CloseSend` (optional)
//! 4. server replies with `Message` carrying the response protobuf
//! 5. server sends `Close` to complete the RPC
//!
//! Errors are surfaced as DRPC `Error` packets and map onto handler
//! [`RpcError`] variants.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::{DrpcError, DrpcResult};
use crate::handlers::{AgentRpcHandler, RpcError};
use crate::proto::agent_v2 as agent;
use crate::wire::{self, Kind, Packet};

/// DRPC error code used for unimplemented methods. Matches
/// `drpcerr.Unimplemented` from the Go library (a sentinel value used by
/// the official client to detect missing handlers).
const DRPC_ERR_UNIMPLEMENTED: u32 = 12;
/// DRPC error code used for malformed request messages.
const DRPC_ERR_INVALID_ARGUMENT: u32 = 3;
/// Generic internal-server-error DRPC code.
const DRPC_ERR_INTERNAL: u32 = 13;

/// Drives a single DRPC stream to completion against `handler`.
///
/// Reads the required `Invoke` + `Message` packets, dispatches, and writes
/// the response followed by a `Close`. Control packets like `CloseSend` and
/// `Cancel` are tolerated; unknown packet kinds trigger a protocol error.
pub async fn serve_drpc_stream<S, H>(mut stream: S, handler: Arc<H>) -> DrpcResult<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    H: AgentRpcHandler + ?Sized,
{
    // -- 1. Invoke --------------------------------------------------------
    let invoke = wire::read_packet(&mut stream).await?;
    if invoke.kind != Kind::Invoke {
        return Err(DrpcError::Protocol(format!(
            "expected Invoke, got {:?}",
            invoke.kind
        )));
    }
    let method = std::str::from_utf8(&invoke.data)
        .map_err(|e| DrpcError::Protocol(format!("invalid method utf-8: {e}")))?
        .to_owned();

    // -- 2. Request message ----------------------------------------------
    // The response frames reuse the stream/message ID carried on the most
    // recently received frame from the peer.
    let p = wire::read_packet(&mut stream).await?;
    let (body, id) = match p.kind {
        Kind::Message => (p.data, p.id),
        Kind::CloseSend => {
            // Our RPCs are unary request/response; a CloseSend before any
            // body is a protocol error.
            return Err(DrpcError::Protocol(
                "client CloseSend before sending request body".into(),
            ));
        }
        Kind::Cancel | Kind::Close => {
            // Remote cancelled before we could respond.
            return Ok(());
        }
        other => {
            return Err(DrpcError::Protocol(format!(
                "unexpected packet {other:?} while reading request"
            )));
        }
    };

    // -- 3. Dispatch ------------------------------------------------------
    let result = dispatch(handler.as_ref(), &method, &body).await;

    // -- 4. Reply ---------------------------------------------------------
    match result {
        Ok(response_bytes) => {
            wire::write_packet(
                &mut stream,
                &Packet {
                    kind: Kind::Message,
                    id,
                    data: response_bytes,
                },
            )
            .await?;
            wire::write_packet(
                &mut stream,
                &Packet {
                    kind: Kind::Close,
                    id,
                    data: Vec::new(),
                },
            )
            .await?;
        }
        Err(err) => {
            let (code, msg) = rpc_error_to_drpc(&err);
            wire::write_error(&mut stream, id, code, msg.as_str()).await?;
        }
    }
    Ok(())
}

fn rpc_error_to_drpc(err: &RpcError) -> (u32, String) {
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
        let code = u32::from_be_bytes([resp.data[0], resp.data[1], resp.data[2], resp.data[3]]);
        assert_eq!(code, DRPC_ERR_UNIMPLEMENTED);
        drop(client);
        let _ = server_task.await;
        Ok(())
    }
}
