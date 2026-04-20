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
//! A logical `Packet` may be split across any number of frames all sharing
//! the same `(kind, stream, message)` identifier — frames with `done=false`
//! carry partial payload bytes and frames with `done=true` close the packet.
//! See [`PacketReassembler`] for the receive side of this behaviour.

use std::collections::HashMap;
use std::io;

// `AsyncReadExt`/`AsyncWriteExt` are brought in explicitly so their
// provided methods (`read_u8`, `read_exact`, `flush`) are usable with our
// generic `AsyncRead`/`AsyncWrite` parameters.
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::error::{DrpcError, DrpcResult};

/// The size of the fixed portion of a packet kind on the wire.
pub const MAX_VARINT_LEN: usize = 10;

/// Upper bound on the total bytes a single reassembled packet may hold.
/// Mirrors Go's `drpcsdk.MaxMessageSize` (`4 << 20`) from
/// `coder/codersdk/drpcsdk/transport.go`: every DRPC message — whether
/// delivered as one frame or several — must fit inside this cap. Exceeding
/// it is a protocol error on both sides.
pub const MAX_PACKET_SIZE: usize = 4 * 1024 * 1024;

/// A DRPC packet kind. Mirrors `drpcwire.Kind` in the Go implementation.
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
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

/// A single DRPC frame — one logical unit on the wire. A `Packet` may span
/// multiple frames (all sharing the same `(kind, id)`) joined by
/// [`PacketReassembler`]. Frames with `done=false` are partial; the receiver
/// concatenates their payloads until a `done=true` frame arrives.
#[derive(Debug, Clone)]
pub struct Frame {
    pub kind: Kind,
    pub id: PacketId,
    pub data: Vec<u8>,
    /// True on the last frame of a packet.
    pub done: bool,
}

/// Buffers partial-frame payloads keyed by stream id and yields a full
/// [`Packet`] once a terminating (`done=true`) frame arrives.
///
/// A reassembler retains state across many calls: multiple independent
/// streams may interleave their frames on the underlying connection (yamux
/// multiplexing already separates streams at its layer, but at the DRPC
/// wire level multi-frame packets within a single stream must still be
/// concatenated). Only one partial packet per stream id is permitted at a
/// time; encountering a frame whose `kind` disagrees with the buffered
/// partial is rejected as a protocol error.
#[derive(Debug, Default)]
pub struct PacketReassembler {
    pending: HashMap<u64, PartialPacket>,
}

#[derive(Debug)]
struct PartialPacket {
    kind: Kind,
    id: PacketId,
    data: Vec<u8>,
}

impl PacketReassembler {
    /// Creates an empty reassembler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds a frame into the reassembler.
    ///
    /// * On a `done=true` frame with no prior partial: returns the single-
    ///   frame packet directly.
    /// * On a `done=false` frame: buffers the payload, returns `None`.
    /// * On a `done=true` frame that completes a buffered partial: returns
    ///   the concatenated packet.
    ///
    /// Cancellation: a [`Kind::Cancel`] frame on a stream with a buffered
    /// partial drops that partial before yielding the cancel packet itself,
    /// matching the Go reference where a cancel aborts any in-progress
    /// receive.
    ///
    /// Errors if a subsequent frame's `kind` disagrees with the buffered
    /// partial, or if the reassembled total would exceed [`MAX_PACKET_SIZE`].
    pub fn push(&mut self, frame: Frame) -> DrpcResult<Option<Packet>> {
        let Frame {
            kind,
            id,
            data,
            done,
        } = frame;

        // A Cancel/Close/Error frame aborts any in-progress reassembly on
        // the same stream — the partial payload becomes meaningless once
        // the peer declares the stream over. This matches Go's
        // `drpcstream.Stream.terminate` path which clears its receive
        // buffer before surfacing the control packet upstream.
        if matches!(kind, Kind::Cancel | Kind::Close | Kind::Error) {
            self.pending.remove(&id.stream);
            return Ok(Some(Packet { kind, id, data }));
        }

        if let Some(mut partial) = self.pending.remove(&id.stream) {
            if partial.kind != kind {
                return Err(DrpcError::Protocol(format!(
                    "multi-frame packet kind mismatch: expected {:?}, got {kind:?}",
                    partial.kind,
                )));
            }
            if partial.data.len().saturating_add(data.len()) > MAX_PACKET_SIZE {
                return Err(DrpcError::Protocol(format!(
                    "reassembled drpc packet exceeds {MAX_PACKET_SIZE} bytes"
                )));
            }
            partial.data.extend_from_slice(&data);
            if done {
                Ok(Some(Packet {
                    kind: partial.kind,
                    id: partial.id,
                    data: partial.data,
                }))
            } else {
                // Update the packet id's message field so the caller can see
                // the latest frame id, though typically callers only inspect
                // it on the completed packet.
                partial.id = id;
                self.pending.insert(id.stream, partial);
                Ok(None)
            }
        } else if done {
            if data.len() > MAX_PACKET_SIZE {
                return Err(DrpcError::Protocol(format!(
                    "single-frame drpc packet exceeds {MAX_PACKET_SIZE} bytes"
                )));
            }
            Ok(Some(Packet { kind, id, data }))
        } else {
            if data.len() > MAX_PACKET_SIZE {
                return Err(DrpcError::Protocol(format!(
                    "first drpc frame already exceeds {MAX_PACKET_SIZE} bytes"
                )));
            }
            self.pending
                .insert(id.stream, PartialPacket { kind, id, data });
            Ok(None)
        }
    }

    /// Returns true if this reassembler has a partial buffered for
    /// `stream_id`. Exposed for observability and tests.
    #[must_use]
    pub fn has_partial(&self, stream_id: u64) -> bool {
        self.pending.contains_key(&stream_id)
    }

    /// Drops any partial frames associated with `stream_id`, for when a
    /// stream is closing and its partial packet (if any) should be abandoned.
    pub fn clear_stream(&mut self, stream_id: u64) {
        self.pending.remove(&stream_id);
    }
}

/// Reads a single DRPC frame from `r` (may be partial — see [`Frame::done`]).
///
/// Returns [`DrpcError::Closed`] on clean EOF before a new frame starts.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> DrpcResult<Frame> {
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

    // A single frame carries at most one packet's worth of payload. The
    // reassembler enforces the same cap across the joined payload, so a
    // peer cannot dodge it by splitting into many frames.
    if length > MAX_PACKET_SIZE as u64 {
        return Err(DrpcError::Protocol(format!(
            "drpc frame length {length} exceeds {MAX_PACKET_SIZE}"
        )));
    }
    let mut data = vec![0u8; length as usize];
    r.read_exact(&mut data).await?;

    Ok(Frame {
        kind,
        id: PacketId { stream, message },
        data,
        done,
    })
}

/// Reads DRPC frames from `r` and returns once a full packet is assembled.
///
/// Unlike [`read_frame`], this tolerates multi-frame packets — it runs a
/// private [`PacketReassembler`] until it sees a terminating frame. Returns
/// [`DrpcError::Closed`] on clean EOF between packets.
pub async fn read_packet<R: AsyncRead + Unpin>(r: &mut R) -> DrpcResult<Packet> {
    let mut reassembler = PacketReassembler::new();
    loop {
        let frame = read_frame(r).await?;
        if let Some(packet) = reassembler.push(frame)? {
            return Ok(packet);
        }
    }
}

/// Writes a single DRPC packet as one frame with `done = true`.
pub async fn write_packet<W: AsyncWrite + Unpin>(w: &mut W, packet: &Packet) -> DrpcResult<()> {
    write_frame(
        w,
        &Frame {
            kind: packet.kind,
            id: packet.id,
            data: packet.data.clone(),
            done: true,
        },
    )
    .await
}

/// Writes a single DRPC frame. The caller controls the `done` bit — for
/// server-stream emission of a non-terminal message, set `done=false` and
/// follow up with additional frames (same `id`, final `done=true`).
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, frame: &Frame) -> DrpcResult<()> {
    let mut buf = Vec::with_capacity(1 + 3 * MAX_VARINT_LEN + frame.data.len());
    let done_bit = if frame.done { 0b0000_0001 } else { 0 };
    let header = (frame.kind.to_u8() << 1) | done_bit;
    buf.push(header);
    encode_varint(&mut buf, frame.id.stream);
    encode_varint(&mut buf, frame.id.message);
    encode_varint(&mut buf, frame.data.len() as u64);
    buf.extend_from_slice(&frame.data);
    w.write_all(&buf).await?;
    w.flush().await?;
    Ok(())
}

/// Writes a DRPC error packet. The Go wire format prefixes the error body
/// with an 8-byte big-endian error code (see `drpcwire.MarshalError` in the
/// upstream `storj.io/drpc` library); a code of zero means "unknown".
pub async fn write_error<W: AsyncWrite + Unpin>(
    w: &mut W,
    id: PacketId,
    code: u64,
    message: &str,
) -> DrpcResult<()> {
    let mut data = Vec::with_capacity(8 + message.len());
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
    async fn multi_frame_reassembly_concatenates() -> DrpcResult<()> {
        let mut reasm = PacketReassembler::new();
        let id = PacketId {
            stream: 1,
            message: 1,
        };
        // Three partial frames plus a terminator.
        assert!(
            reasm
                .push(Frame {
                    kind: Kind::Message,
                    id,
                    data: b"hello ".to_vec(),
                    done: false,
                })?
                .is_none()
        );
        assert!(
            reasm
                .push(Frame {
                    kind: Kind::Message,
                    id,
                    data: b"there ".to_vec(),
                    done: false,
                })?
                .is_none()
        );
        assert!(
            reasm
                .push(Frame {
                    kind: Kind::Message,
                    id,
                    data: b"multi".to_vec(),
                    done: false,
                })?
                .is_none()
        );
        let packet = reasm
            .push(Frame {
                kind: Kind::Message,
                id,
                data: b"-frame".to_vec(),
                done: true,
            })?
            .ok_or_else(|| DrpcError::Protocol("expected completed packet".into()))?;

        assert_eq!(packet.kind, Kind::Message);
        assert_eq!(packet.data, b"hello there multi-frame");
        Ok(())
    }

    #[tokio::test]
    async fn reassembler_keeps_streams_independent() -> DrpcResult<()> {
        // Frames from stream 1 and stream 2 interleaved must not pollute
        // each other's pending buffers.
        let mut reasm = PacketReassembler::new();
        let id1 = PacketId {
            stream: 1,
            message: 1,
        };
        let id2 = PacketId {
            stream: 2,
            message: 1,
        };
        assert!(
            reasm
                .push(Frame {
                    kind: Kind::Message,
                    id: id1,
                    data: b"A1".to_vec(),
                    done: false,
                })?
                .is_none()
        );
        assert!(
            reasm
                .push(Frame {
                    kind: Kind::Message,
                    id: id2,
                    data: b"B1".to_vec(),
                    done: false,
                })?
                .is_none()
        );
        assert!(
            reasm
                .push(Frame {
                    kind: Kind::Message,
                    id: id1,
                    data: b"A2".to_vec(),
                    done: false,
                })?
                .is_none()
        );
        let pkt2 = reasm
            .push(Frame {
                kind: Kind::Message,
                id: id2,
                data: b"B2".to_vec(),
                done: true,
            })?
            .ok_or_else(|| DrpcError::Protocol("stream 2 should be complete".into()))?;
        assert_eq!(pkt2.id.stream, 2);
        assert_eq!(pkt2.data, b"B1B2");

        let pkt1 = reasm
            .push(Frame {
                kind: Kind::Message,
                id: id1,
                data: b"A3".to_vec(),
                done: true,
            })?
            .ok_or_else(|| DrpcError::Protocol("stream 1 should be complete".into()))?;
        assert_eq!(pkt1.id.stream, 1);
        assert_eq!(pkt1.data, b"A1A2A3");
        Ok(())
    }

    #[tokio::test]
    async fn reassembler_rejects_mixed_kinds() {
        // Message-kind partial cannot be continued by a different non-terminal
        // kind (e.g. an InvokeMetadata frame on the same stream).
        let mut reasm = PacketReassembler::new();
        let id = PacketId {
            stream: 1,
            message: 1,
        };
        let _ = reasm.push(Frame {
            kind: Kind::Message,
            id,
            data: b"partial".to_vec(),
            done: false,
        });
        let result = reasm.push(Frame {
            kind: Kind::InvokeMetadata,
            id,
            data: b"bad".to_vec(),
            done: true,
        });
        assert!(matches!(result, Err(DrpcError::Protocol(_))));
    }

    #[tokio::test]
    async fn reassembler_drops_partial_on_cancel() -> DrpcResult<()> {
        // A Cancel frame on an in-progress stream must drop the buffered
        // partial and surface the cancel packet itself — any further
        // pretense that the partial was recoverable would leak memory and
        // confuse handlers. Matches Go drpcstream.terminate().
        let mut reasm = PacketReassembler::new();
        let id = PacketId {
            stream: 7,
            message: 1,
        };
        // Buffer 1 MiB of a future message.
        let big = vec![0xAA; 1024 * 1024];
        assert!(
            reasm
                .push(Frame {
                    kind: Kind::Message,
                    id,
                    data: big,
                    done: false,
                })?
                .is_none()
        );
        assert!(reasm.has_partial(id.stream));

        let cancel = reasm
            .push(Frame {
                kind: Kind::Cancel,
                id,
                data: Vec::new(),
                done: true,
            })?
            .ok_or_else(|| DrpcError::Protocol("cancel must yield a packet".into()))?;
        assert_eq!(cancel.kind, Kind::Cancel);
        assert!(!reasm.has_partial(id.stream), "partial must be dropped");

        // Re-starting a fresh packet on the same stream after cancel must
        // work without carrying bytes over from the abandoned partial.
        let fresh = reasm
            .push(Frame {
                kind: Kind::Message,
                id,
                data: b"fresh".to_vec(),
                done: true,
            })?
            .ok_or_else(|| DrpcError::Protocol("expected fresh packet".into()))?;
        assert_eq!(fresh.data, b"fresh");
        Ok(())
    }

    #[tokio::test]
    async fn reassembler_joins_1_mib_split_across_four_frames() -> DrpcResult<()> {
        // One 1 MiB payload split into four 256 KiB chunks must
        // reassemble bit-for-bit identical to the original.
        let mut reasm = PacketReassembler::new();
        let id = PacketId {
            stream: 11,
            message: 1,
        };
        let total: Vec<u8> = (0..(1024 * 1024)).map(|i| (i & 0xff) as u8).collect();
        let chunks: Vec<&[u8]> = total.chunks(256 * 1024).collect();
        for (i, chunk) in chunks.iter().enumerate() {
            let done = i == chunks.len() - 1;
            let result = reasm.push(Frame {
                kind: Kind::Message,
                id,
                data: chunk.to_vec(),
                done,
            })?;
            if done {
                let packet = result
                    .ok_or_else(|| DrpcError::Protocol("final frame yields packet".into()))?;
                assert_eq!(packet.data.len(), total.len());
                assert_eq!(packet.data, total);
            } else {
                assert!(result.is_none(), "partial frames must not yield");
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn reassembler_rejects_payload_beyond_4_mib() {
        // Exactly MAX_PACKET_SIZE is allowed; one byte more is a protocol
        // error. We prove this by pushing two frames whose combined size is
        // MAX_PACKET_SIZE + 1.
        let mut reasm = PacketReassembler::new();
        let id = PacketId {
            stream: 3,
            message: 1,
        };
        // First frame: exactly MAX_PACKET_SIZE bytes (the largest partial
        // that the reassembler will buffer without rejecting up front).
        let first = vec![0u8; MAX_PACKET_SIZE];
        let Ok(None) = reasm.push(Frame {
            kind: Kind::Message,
            id,
            data: first,
            done: false,
        }) else {
            unreachable!("initial MAX_PACKET_SIZE frame must be buffered");
        };
        // Second frame: a single extra byte, which would push the
        // reassembled total to MAX_PACKET_SIZE + 1 and must be rejected.
        let extra = reasm.push(Frame {
            kind: Kind::Message,
            id,
            data: vec![0u8; 1],
            done: true,
        });
        assert!(
            matches!(extra, Err(DrpcError::Protocol(_))),
            "overflow by 1 byte must be a protocol error, got {extra:?}"
        );
    }

    #[tokio::test]
    async fn reassembler_rejects_single_frame_beyond_4_mib() {
        // A solo `done=true` frame whose payload exceeds the cap is also
        // rejected — an attacker can't dodge the cap by skipping the
        // multi-frame path.
        let mut reasm = PacketReassembler::new();
        let id = PacketId {
            stream: 4,
            message: 1,
        };
        let too_big = vec![0u8; MAX_PACKET_SIZE + 1];
        let result = reasm.push(Frame {
            kind: Kind::Message,
            id,
            data: too_big,
            done: true,
        });
        assert!(matches!(result, Err(DrpcError::Protocol(_))));
    }

    #[tokio::test]
    async fn read_packet_joins_multi_frame_wire() -> DrpcResult<()> {
        // Write two `done=false` frames and one terminator on the same stream
        // id; verify `read_packet` hands back the joined payload.
        let (mut a, mut b) = duplex(4096);
        let id = PacketId {
            stream: 5,
            message: 10,
        };
        for (data, done) in [
            (&b"first-"[..], false),
            (&b"second-"[..], false),
            (&b"third"[..], true),
        ] {
            write_frame(
                &mut a,
                &Frame {
                    kind: Kind::Message,
                    id,
                    data: data.to_vec(),
                    done,
                },
            )
            .await?;
        }
        let packet = read_packet(&mut b).await?;
        assert_eq!(packet.kind, Kind::Message);
        assert_eq!(packet.data, b"first-second-third");
        Ok(())
    }
}
