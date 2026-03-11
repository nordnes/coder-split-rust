//! HTTP router and middleware for the Rust backend rewrite.
#![forbid(unsafe_code)]

mod app;
mod error;
pub mod rate_limit;

pub use app::{AppState, build_router};
pub use rate_limit::RateLimitState;
