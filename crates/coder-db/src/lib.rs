//! Postgres-backed persistence for the Rust backend rewrite.
#![forbid(unsafe_code)]

mod store;

pub use store::{DatabaseInitError, PostgresStore};
