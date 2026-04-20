//! Generates Rust types for the provisionerd DRPC protocol.
//!
//! The `.proto` source is a stripped vendoring of
//! `coder/provisionerd/proto/provisionerd.proto` that contains only the
//! messages required for the currently-ported RPCs (`CommitQuota`,
//! `AcquireJob`, `UpdateJob`, `FailJob`). Additional RPCs will extend
//! this file and the vendored proto as they are ported; see
//! `docs/backend-gap-analysis-2026-04.md` §B.6.
//!
//! The vendored copy keeps the crate buildable without relying on the
//! `coder/` submodule being present at compile time.

use std::io;

fn main() -> io::Result<()> {
    println!("cargo:rerun-if-changed=proto/provisionerd/proto/provisionerd.proto");

    // Point prost-build at a vendored `protoc` binary so the build does not
    // require a system-wide `protoc` install (important in CI where protoc
    // is not preinstalled). Caller-provided `PROTOC` env overrides still
    // win via prost-build's own resolution.
    let mut config = prost_build::Config::new();
    let protoc = protoc_bin_vendored::protoc_bin_path()
        .map_err(|e| io::Error::new(io::ErrorKind::NotFound, e))?;
    config.protoc_executable(protoc);
    config.protoc_arg("--experimental_allow_proto3_optional");
    config.compile_protos(&["proto/provisionerd/proto/provisionerd.proto"], &["proto"])?;
    Ok(())
}
