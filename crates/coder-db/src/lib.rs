//! Postgres-backed persistence for the Rust backend rewrite.
//!
//! `coder-db` is the only crate that talks directly to PostgreSQL.  It
//! provides [`PostgresStore`], the production implementation of
//! [`coder_core::AppStore`], plus schema migrations and a Postgres-backed
//! pub/sub layer.
//!
//! # Modules
//!
//! | Module | Purpose |
//! |--------|---------|
//! | `migrations` | Embedded SQLx migrations and schema-version helpers |
//! | [`pubsub`] | [`PostgresPubSub`] — `LISTEN`/`NOTIFY`-backed pub/sub |
//! | `store` (private) | [`PostgresStore`] implementation with `sqlx` queries |
//!
//! # Re-exports
//!
//! The crate re-exports the key types so consumers only need
//! `use coder_db::{PostgresStore, run_migrations, …};`.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod dbauthz;
pub(crate) mod migrations;
pub mod pubsub;
mod store;

pub use dbauthz::{Authorized, DbAuthzError};
pub use migrations::{
    MigrationError, MigrationReport, MigrationStatus, migration_status, run_migrations,
};
pub use pubsub::PostgresPubSub;
pub use store::{DatabaseInitError, PostgresStore};
