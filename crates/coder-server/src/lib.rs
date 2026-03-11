//! HTTP router and middleware for the Rust backend rewrite.
#![forbid(unsafe_code)]

mod app;
pub mod connection_guard;
mod error;
mod extractors;
mod handlers;
pub(crate) mod helpers;
pub mod metrics;
pub(crate) mod middleware;

pub use app::{AppState, build_router};
