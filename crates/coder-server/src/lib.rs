//! HTTP router and middleware for the Rust backend rewrite.
#![forbid(unsafe_code)]

mod app;
mod error;
mod extractors;
pub mod metrics;

pub use app::{AppState, build_router};
