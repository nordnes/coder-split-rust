//! Generates Rust types for the agent DRPC protocol.
//!
//! The `.proto` sources are vendored from the upstream Go project
//! (`coder/agent/proto` and `coder/tailnet/proto`) so the crate builds
//! without relying on the `coder/` submodule being present at build time.
//! When the upstream protocol changes the vendored files must be refreshed.

use std::io;

fn main() -> io::Result<()> {
    println!("cargo:rerun-if-changed=proto/agent/proto/agent.proto");
    println!("cargo:rerun-if-changed=proto/tailnet/proto/tailnet.proto");

    let mut config = prost_build::Config::new();
    config.protoc_arg("--experimental_allow_proto3_optional");
    config.compile_protos(
        &[
            "proto/agent/proto/agent.proto",
            "proto/tailnet/proto/tailnet.proto",
        ],
        &["proto"],
    )?;
    Ok(())
}
