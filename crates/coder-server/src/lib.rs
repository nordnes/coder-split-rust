//! HTTP router and middleware for the Rust backend rewrite.
#![forbid(unsafe_code)]

mod app;
mod error;
mod handlers;
pub(crate) mod helpers;
pub(crate) mod middleware;

pub use app::{AppState, build_router};
