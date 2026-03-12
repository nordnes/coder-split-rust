//! Integration test crate — no library code.
//!
//! All tests live under `tests/` and exercise the full
//! request → handler → store → database → response pipeline
//! using a real PostgreSQL database.
#![forbid(unsafe_code)]
