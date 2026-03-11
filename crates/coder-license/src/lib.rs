//! License management and entitlements for enterprise feature gating.
//!
//! This crate provides JWT-based license validation, feature entitlement
//! checking, and grace period handling for enterprise deployments.
#![forbid(unsafe_code)]

mod entitlements;
mod features;
mod license;
mod service;

pub use coder_core::LicenseRecord;
pub use entitlements::{Entitlement, EntitlementSet, Entitlements, Feature};
pub use features::FeatureName;
pub use license::{LicenseClaims, LicenseError, LicenseValidator};
pub use service::{LicenseService, LicenseServiceError, LicenseStore};
