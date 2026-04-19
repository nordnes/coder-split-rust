//! Generated protobuf types for the `provisionerd` DRPC service.
//!
//! Only the types required for currently-ported RPCs are included. As
//! additional RPCs from the upstream `provisionerd/proto/provisionerd.proto`
//! are ported (§B.6 follow-ups) the vendored proto file will grow and these
//! generated types will track it.

/// Types generated from the `provisionerd` protobuf package.
#[allow(missing_docs)]
pub mod provisionerd {
    include!(concat!(env!("OUT_DIR"), "/provisionerd.rs"));
}
