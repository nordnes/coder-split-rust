//! Error types used across DRPC framing and dispatch.

use thiserror::Error;

/// Errors raised by the DRPC wire layer, stream server, or yamux wrapper.
#[derive(Debug, Error)]
pub enum DrpcError {
    /// Low-level transport failure (read/write on the byte stream).
    #[error("transport io: {0}")]
    Io(#[from] std::io::Error),
    /// The peer sent a frame whose kind/state/body we cannot process.
    #[error("drpc protocol error: {0}")]
    Protocol(String),
    /// Protobuf decode or encode failure.
    #[error("protobuf decode: {0}")]
    ProtoDecode(#[from] prost::DecodeError),
    /// Protobuf encode failure. `prost::EncodeError` is only produced when
    /// the caller provides an undersized buffer, which we never do, but we
    /// keep it in the error type so callers don't have to handle two sinks.
    #[error("protobuf encode: {0}")]
    ProtoEncode(#[from] prost::EncodeError),
    /// The peer requested an RPC method that this server does not implement.
    #[error("unknown rpc method: {0}")]
    UnknownMethod(String),
    /// The remote side closed the underlying stream cleanly.
    #[error("connection closed")]
    Closed,
}

/// Convenience alias for this crate.
pub type DrpcResult<T> = Result<T, DrpcError>;
