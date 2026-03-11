//! HTTP router and middleware for the Rust backend rewrite.
#![forbid(unsafe_code)]

mod app;
pub(crate) mod auth_middleware;
pub mod connection_guard;
mod error;
mod extractors;
mod handlers;
pub(crate) mod helpers;
pub mod metrics;
pub(crate) mod middleware;
pub mod rate_limit;

pub use app::{AppState, build_router};
pub use rate_limit::RateLimitState;
