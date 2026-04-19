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
//! | `app` | [`AppState`] construction and [`build_router`] entry point |
//! | `auth_middleware` | Session-cookie authentication middleware layer |
//! | [`connection_guard`] | Concurrency limiter returning 503 under overload |
//! | `error` | `AppError` enum and `IntoResponse` mapping |
//! | `extractors` | Axum `FromRequestParts` helpers (`Auth`, `OptionalAuth`, `AgentAuth`) |
//! | `handlers` | Per-domain handler modules (users, templates, workspaces, …) |
//! | `helpers` | Shared response builders and request helpers |
//! | [`metrics`] | Prometheus metric recording helpers |
//! | `middleware` | CORS, CSP, HSTS, CSRF, real-IP, and OTel middleware |
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
#![warn(missing_docs)]

mod app;
pub mod app_healthcheck;
pub(crate) mod auth_middleware;
pub mod connection_guard;
pub mod connection_log_pruner;
pub mod crypto_key_rotator;
pub mod db_rollup;
mod error;
mod extractors;
pub(crate) mod frontend;
mod handlers;
pub(crate) mod helpers;
pub(crate) mod instance_identity;
pub mod metrics;
pub(crate) mod middleware;
pub mod rate_limit;
pub mod reconnecting_pty;
pub mod replica_manager;
pub mod update_check;
pub mod usage_tracker;

pub use app::{AppState, build_router};
pub use rate_limit::RateLimitState;
pub use replica_manager::{
    AppStoreReplicaAdapter, ReplicaManager, ReplicaManagerOptions, ReplicaManagerStore,
};
pub use update_check::{UpdateChecker, UpdateCheckerOptions, UpdateCheckerResult};
