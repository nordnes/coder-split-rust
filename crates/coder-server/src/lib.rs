//! HTTP router and middleware for the Rust backend rewrite.
//!
//! `coder-server` owns the Axum-based HTTP layer: route definitions, request
//! extractors, security middleware, and domain-specific handler functions.
//! It is the primary consumer of [`coder_core::AppStore`] and the various
//! service traits (`AuthService`, `IdentityService`, etc.).
//!
//! # Modules
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`app`](app) | [`AppState`] construction and [`build_router`] entry point |
//! | [`auth_middleware`] | Session-cookie authentication middleware layer |
//! | [`connection_guard`] | Concurrency limiter returning 503 under overload |
//! | [`error`](error) | [`AppError`](error::AppError) enum and `IntoResponse` mapping |
//! | [`extractors`] | Axum `FromRequestParts` helpers (`Auth`, `OptionalAuth`, `AgentAuth`) |
//! | [`handlers`] | Per-domain handler modules (users, templates, workspaces, …) |
//! | [`helpers`] | Shared response builders and request helpers |
//! | [`metrics`] | Prometheus metric recording helpers |
//! | [`middleware`] | CORS, CSP, HSTS, CSRF, real-IP, and OTel middleware |
//! | [`rate_limit`] | Governor-based keyed rate limiters |
//!
//! # Quick Start
//!
//! ```ignore
//! let state = AppState::new(/* … */);
//! let router = build_router(state);
//! axum::serve(listener, router).await?;
//! ```
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
