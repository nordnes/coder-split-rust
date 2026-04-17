//! Prost-generated protobuf types for the agent DRPC protocol.
//!
//! Prost resolves cross-package references using Rust module paths that
//! mirror the protobuf package names. To make that work we expose the
//! generated modules under a `coder::<pkg>::<version>` tree and then
//! re-export the ones we care about at well-known names.

#![allow(clippy::all, clippy::pedantic, unreachable_pub, missing_docs)]

/// Raw protobuf module tree. The layout matches the protobuf package names
/// (`coder.agent.v2`, `coder.tailnet.v2`) so that prost's cross-package
/// references (`super::super::tailnet::v2::DerpMap`) resolve correctly.
pub mod coder {
    pub mod agent {
        pub mod v2 {
            include!(concat!(env!("OUT_DIR"), "/coder.agent.v2.rs"));
        }
    }
    pub mod tailnet {
        pub mod v2 {
            include!(concat!(env!("OUT_DIR"), "/coder.tailnet.v2.rs"));
        }
    }
}

/// Re-export of `coder.agent.v2` at the shorter, commonly used name used by
/// the rest of the crate.
pub use coder::agent::v2 as agent_v2;

/// Re-export of `coder.tailnet.v2` at a short, stable name.
pub use coder::tailnet::v2 as tailnet_v2;
