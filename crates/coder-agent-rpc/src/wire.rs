//! DRPC wire protocol framing.
//!
//! Ported from [`storj.io/drpc/drpcwire`](https://github.com/storj/drpc/wiki/Docs:-Wire-protocol).
//!
//! Every DRPC packet is serialised as one or more **frames** with layout:
//!
//! ```text
//! +-------+------------+-------------+--------+----------+
//! | hdr:1 | stream:var | message:var | len:var| data:len |
//! +-------+------------+-------------+--------+----------+
//! ```
//!
//! The header byte packs three fields:
//!
//! * bit 7 — control flag (unused by us).
//! * bits 6..=1 — packet [`Kind`].
//! * bit 0 — `done` bit; set on the last frame of a packet.
//!
//! For method dispatch we only need single-frame packets, which is the only
//! shape the Go client and server produce in practice for the agent service.

use std::io;

// `AsyncReadExt`/`AsyncWriteExt` are brought in explicitly so their
// provided methods (`read_u8`, `read_exact`, `flush`) are usable with our
// generic `AsyncRead`/`AsyncWrite` parameters.
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::error::{DrpcError, DrpcResult};

/// The size of the fixed portion of a packet kind on the wire.
pub const MAX_VARINT_LEN: usize = 10;

/// A DRPC packet kind. Mirrors `drpcwire.Kind` in the Go implementation.
///
/// We only implement the kinds used for a straightforward request/response
/// dispatch loop. Streaming and metadata extensions are not required for the
/// Phase-1 agent RPC handlers and are rejected at the server layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Start an RPC. Body is the method path, e.g. `/coder.agent.v2.Agent/GetManifest`.
    Invoke,
    /// An encoded request or response protobuf message.
    Message,
    /// An error with an attached DRPC error code.
    Error,
    /// The remote soft-cancelled this stream.
    Cancel,
    /// The peer is closing the RPC. Body is empty.
    Close,
    /// The peer will not send any further messages. Body is empty.
    CloseSend,
    /// Metadata to be attached to the next `Invoke`.
    InvokeMetadata,
}

impl Kind {
    fn from_u8(v: u8) -> DrpcResult<Self> {
        match v {
            1 => Ok(Kind::Invoke),
            2 => Ok(Kind::Message),
            3 => Ok(Kind::Error),
            4 => Ok(Kind::Cancel),
            5 => Ok(Kind::Close),
            6 => Ok(Kind::CloseSend),
            7 => Ok(Kind::InvokeMetadata),
            other => Err(DrpcError::Protocol(format!(
                "unknown drpc packet kind {other}"
            ))),
        }
    }

    fn to_u8(self) -> u8 {
        match self {
            Kind::Invoke => 1,
            Kind::Message => 2,
            Kind::Error => 3,
            Kind::Cancel => 4,
            Kind::Close => 5,
            Kind::CloseSend => 6,
            Kind::InvokeMetadata => 7,
        }
    }
}

/// A packet identifier, scoped to the DRPC stream.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PacketId {
    /// The DRPC stream identifier. Incremented per `Invoke`.
    pub stream: u64,
    /// The message identifier, incremented per frame within a stream.
    pub message: u64,
}

/// A single packet: kind + identifier + payload, fully buffered.
#[derive(Debug, Clone)]
pub struct Packet {
    pub kind: Kind,
    pub id: PacketId,
    pub data: Vec<u8>,
}

/// Reads a single DRPC packet from `r`. Only single-frame packets are
/// accepted; multi-frame packets would require buffering up to
/// `MAX_PACKET_SIZE` which Phase-1 handlers do not need.
///
/// Returns [`DrpcError::Closed`] on clean EOF before a new frame starts.
pub async fn read_packet<R: AsyncRead + Unpin>(r: &mut R) -> DrpcResult<Packet> {
    let header = match r.read_u8().await {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Err(DrpcError::Closed),
        Err(e) => return Err(e.into()),
    };

    let kind_bits = (header & 0b0111_1110) >> 1;
    let done = (header & 0b0000_0001) != 0;
    let kind = Kind::from_u8(kind_bits)?;

    let stream = read_varint(r).await?;
    let message = read_varint(r).await?;
    let length = read_varint(r).await?;

    // Be conservative about oversized frames to avoid unbounded allocation
    // from a hostile or malformed client.
    const MAX_FRAME_LEN: u64 = 32 * 1024 * 1024;
    if length > MAX_FRAME_LEN {
        return Err(DrpcError::Protocol(format!(
            "drpc frame length {length} exceeds {MAX_FRAME_LEN}"
        )));
    }
    let mut data = vec![0u8; length as usize];
    r.read_exact(&mut data).await?;

    if !done {
        return Err(DrpcError::Protocol(
            "multi-frame drpc packets are not supported".into(),
        ));
    }

    Ok(Packet {
        kind,
        id: PacketId { stream, message },
        data,
    })
}

/// Writes a single DRPC packet as one framed frame with `done = true`.
pub async fn write_packet<W: AsyncWrite + Unpin>(w: &mut W, packet: &Packet) -> DrpcResult<()> {
    let mut buf = Vec::with_capacity(1 + 3 * MAX_VARINT_LEN + packet.data.len());
    let header = (packet.kind.to_u8() << 1) | 0b0000_0001; // done
    buf.push(header);
    encode_varint(&mut buf, packet.id.stream);
    encode_varint(&mut buf, packet.id.message);
    encode_varint(&mut buf, packet.data.len() as u64);
    buf.extend_from_slice(&packet.data);
    w.write_all(&buf).await?;
    w.flush().await?;
    Ok(())
}

/// Writes a DRPC error packet. The Go wire format prefixes the error body
/// with a 4-byte big-endian error code; a code of zero means "unknown".
pub async fn write_error<W: AsyncWrite + Unpin>(
    w: &mut W,
    id: PacketId,
    code: u32,
    message: &str,
) -> DrpcResult<()> {
    let mut data = Vec::with_capacity(4 + message.len());
    data.extend_from_slice(&code.to_be_bytes());
    data.extend_from_slice(message.as_bytes());
    write_packet(
        w,
        &Packet {
            kind: Kind::Error,
            id,
            data,
        },
    )
    .await
}

async fn read_varint<R: AsyncRead + Unpin>(r: &mut R) -> DrpcResult<u64> {
    let mut value = 0u64;
    let mut shift = 0u32;
    for _ in 0..MAX_VARINT_LEN {
        let byte = r.read_u8().await?;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
    Err(DrpcError::Protocol("varint too long".into()))
}

fn encode_varint(buf: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        buf.push(((value as u8) & 0x7f) | 0x80);
        value >>= 7;
    }
    buf.push(value as u8);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn varint_roundtrip() -> DrpcResult<()> {
        for value in [0u64, 1, 127, 128, 16_384, u32::MAX as u64, u64::MAX] {
            let mut buf = Vec::new();
            encode_varint(&mut buf, value);
            let mut cursor = &buf[..];
            let got = read_varint(&mut cursor).await?;
            assert_eq!(value, got, "varint roundtrip failed for {value}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn packet_roundtrip() -> DrpcResult<()> {
        let (mut a, mut b) = duplex(1024);
        let out = Packet {
            kind: Kind::Invoke,
            id: PacketId {
                stream: 7,
                message: 3,
            },
            data: b"/coder.agent.v2.Agent/GetManifest".to_vec(),
        };
        write_packet(&mut a, &out).await?;
        let got = read_packet(&mut b).await?;
        assert_eq!(got.kind, out.kind);
        assert_eq!(got.id, out.id);
        assert_eq!(got.data, out.data);
        Ok(())
    }

    #[tokio::test]
    async fn closed_on_eof() {
        let (a, mut b) = duplex(64);
        drop(a);
        let result = read_packet(&mut b).await;
        assert!(matches!(result, Err(DrpcError::Closed)));
    }

    #[tokio::test]
    async fn rejects_multi_frame_packet() -> DrpcResult<()> {
        // Build a frame with done=false manually.
        let (mut a, mut b) = duplex(64);
        let header = (Kind::Message.to_u8() << 1) & !0b0000_0001;
        let bytes = [header, 0x00, 0x00, 0x00];
        a.write_all(&bytes).await?;
        let result = read_packet(&mut b).await;
        assert!(matches!(result, Err(DrpcError::Protocol(_))));
        Ok(())
    }
}
