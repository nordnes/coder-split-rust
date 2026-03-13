//! Telemetry collection and reporting for the Coder backend.
//!
//! Provides event-driven telemetry with privacy controls, batched reporting,
//! and graceful shutdown support.  Events are collected via an mpsc channel
//! and periodically flushed to a configurable HTTP endpoint.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod events;
mod reporter;
mod worker;

pub use events::{TelemetryEvent, TelemetryEventKind};
pub use reporter::{TelemetryReporter, TelemetrySnapshot, TelemetryStatus};
pub use worker::{TelemetryConfig, TelemetryWorker};
