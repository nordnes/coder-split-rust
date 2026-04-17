//! Coder agent DRPC protocol — minimal server-side implementation.
//!
//! The Go agent speaks to `coderd` over a WebSocket that carries a **yamux**
//! session. Each accepted yamux stream then runs the [DRPC] wire protocol,
//! carrying length-prefixed protobuf messages annotated with an RPC method
//! path such as `/coder.agent.v2.Agent/GetManifest`.
//!
//! This crate ports the minimum needed for the Rust `coderd` to serve that
//! protocol:
//!
//! * [`wire`] — DRPC packet framing (headers, stream IDs, varints, kinds).
//! * [`server`] — per-stream DRPC server that reads `INVOKE` + `MESSAGE`,
//!   dispatches to a handler, and writes `MESSAGE` + `CLOSE` or `ERROR`.
//! * [`yamux_server`] — bridges a single byte-oriented transport into many
//!   DRPC streams through a yamux server session.
//! * [`handlers`] — the [`AgentRpcHandler`] trait and a [`StubHandler`] used
//!   by tests and as the Phase-1 integration point in `coder-server`.
//! * [`proto`] — `prost`-generated protobuf types for `coder.agent.v2`.
//!
//! The proto definitions are vendored from the upstream Go repo under
//! `crates/coder-agent-rpc/proto/`.
//!
//! [DRPC]: https://github.com/storj/drpc/wiki/Docs:-Wire-protocol

pub mod error;
pub mod handlers;
pub mod proto;
pub mod server;
pub mod wire;
pub mod yamux_server;

pub use error::{DrpcError, DrpcResult};
pub use handlers::{AgentRpcHandler, RpcError, StubHandler};
pub use server::serve_drpc_stream;
pub use yamux_server::serve_yamux;
