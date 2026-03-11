//! HTTP router and middleware for the Rust backend rewrite.
#![forbid(unsafe_code)]

mod app;
mod error;
pub(crate) mod handlers;
pub(crate) mod helpers;
pub(crate) mod mw;

pub use app::{AppState, build_router};
