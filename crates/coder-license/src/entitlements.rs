//! Entitlement tracking and feature gating.
//!
//! Mirrors Go's `codersdk.Entitlements` / `codersdk.Feature` /
//! `codersdk.Entitlement` types and the `entitlements.Set` wrapper that
//! serialises concurrent reads and writes.

use std::collections::HashMap;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::features::{ALL_FEATURE_NAMES, FeatureName};

// ---------------------------------------------------------------------------
// Entitlement enum
// ---------------------------------------------------------------------------

/// Whether a single feature is entitled under the current license(s).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Entitlement {
    /// Fully entitled — the license covers this feature.
    Entitled,
    /// The license has expired but is still within its grace period.
    GracePeriod,
    /// Not entitled — no license covers this feature.
    #[default]
    NotEntitled,
}

impl Entitlement {
    /// Returns `true` if the feature can still be used (entitled **or**
    /// within grace period).
    #[must_use]
    pub fn is_entitled(self) -> bool {
        matches!(self, Self::Entitled | Self::GracePeriod)
    }

    /// Numeric weight for comparison — higher means "more entitled".
    /// Matches Go's `Entitlement.Weight()`.
    #[must_use]
    pub fn weight(self) -> i32 {
        match self {
            Self::Entitled => 2,
            Self::GracePeriod => 1,
            Self::NotEntitled => -1,
        }
    }
}

// ---------------------------------------------------------------------------
// Feature
// ---------------------------------------------------------------------------

/// The entitlement state for a single enterprise feature.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Feature {
    /// Current entitlement level.
    pub entitlement: Entitlement,
    /// Whether the feature is enabled by the deployment.
    pub enabled: bool,
    /// Optional numeric limit (e.g. user seat count).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
    /// Optional current usage value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual: Option<i64>,
}

impl Feature {
    /// Returns `true` if the feature has a limit and the current usage
    /// is within that limit (or no limit/actual is set).
    #[must_use]
    pub fn capable(&self) -> bool {
        match (self.limit, self.actual) {
            (Some(l), Some(a)) => l >= a,
            _ => true,
        }
    }
}

// ---------------------------------------------------------------------------
// Entitlements (the full snapshot)
// ---------------------------------------------------------------------------

/// Complete entitlement snapshot matching Go's `codersdk.Entitlements`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entitlements {
    /// Per-feature entitlement details.
    pub features: HashMap<String, Feature>,
    /// Active warning messages.
    pub warnings: Vec<String>,
    /// Active error messages.
    pub errors: Vec<String>,
    /// Whether any valid license is loaded.
    pub has_license: bool,
    /// Whether the current license is a trial.
    pub trial: bool,
    /// Whether telemetry is required by the license.
    pub require_telemetry: bool,
    /// Timestamp of the last refresh.
    #[serde(with = "time::serde::rfc3339")]
    pub refreshed_at: OffsetDateTime,
}

impl Entitlements {
    /// Creates a new entitlements snapshot with all features set to
    /// not-entitled and disabled, matching Go's `entitlements.New()`.
    #[must_use]
    pub fn new_unlicensed() -> Self {
        let mut features = HashMap::new();
        for &name in ALL_FEATURE_NAMES {
            features.insert(
                name.as_str().to_owned(),
                Feature {
                    entitlement: Entitlement::NotEntitled,
                    enabled: false,
                    limit: None,
                    actual: None,
                },
            );
        }
        Self {
            features,
            warnings: Vec::new(),
            errors: Vec::new(),
            has_license: false,
            trial: false,
            require_telemetry: false,
            refreshed_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    /// Merges a feature into the entitlement set. The feature is only
    /// updated when the new value expands the current entitlement (higher
    /// entitlement weight, higher limit, etc.), matching Go's
    /// `Entitlements.AddFeature`.
    pub fn add_feature(&mut self, name: FeatureName, new: Feature) {
        let key = name.as_str().to_owned();
        let existing = self.features.get(&key);
        let dominated = match existing {
            None => true,
            Some(old) => {
                let ew = old.entitlement.weight();
                let nw = new.entitlement.weight();
                if nw != ew {
                    nw > ew
                } else if old.limit != new.limit {
                    match (old.limit, new.limit) {
                        (None, Some(_)) => true,
                        (Some(_), None) => false,
                        (Some(o), Some(n)) => n > o,
                        _ => false,
                    }
                } else {
                    !old.enabled && new.enabled
                }
            }
        };
        if dominated {
            self.features.insert(key, new);
        }
    }
}

// ---------------------------------------------------------------------------
// EntitlementSet (thread-safe wrapper)
// ---------------------------------------------------------------------------

/// Thread-safe wrapper around [`Entitlements`] for concurrent access,
/// matching Go's `entitlements.Set`.
pub struct EntitlementSet {
    inner: RwLock<Entitlements>,
}

impl EntitlementSet {
    /// Creates a new set with default unlicensed entitlements.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(Entitlements::new_unlicensed()),
        }
    }

    /// Returns `true` if the named feature is currently enabled.
    #[must_use]
    pub fn enabled(&self, feature: FeatureName) -> bool {
        let guard = match self.inner.read() {
            Ok(g) => g,
            Err(_) => return false,
        };
        guard
            .features
            .get(feature.as_str())
            .is_some_and(|f| f.enabled)
    }

    /// Returns `true` if the named feature is entitled (including
    /// grace-period entitlement).
    #[must_use]
    pub fn is_entitled(&self, feature: FeatureName) -> bool {
        let guard = match self.inner.read() {
            Ok(g) => g,
            Err(_) => return false,
        };
        guard
            .features
            .get(feature.as_str())
            .is_some_and(|f| f.entitlement.is_entitled())
    }

    /// Returns `true` if any valid license is loaded.
    #[must_use]
    pub fn has_license(&self) -> bool {
        match self.inner.read() {
            Ok(g) => g.has_license,
            Err(_) => false,
        }
    }

    /// Returns a clone of the current entitlements for serialisation.
    #[must_use]
    pub fn snapshot(&self) -> Entitlements {
        match self.inner.read() {
            Ok(g) => g.clone(),
            Err(_) => Entitlements::new_unlicensed(),
        }
    }

    /// Returns cloned warning messages.
    #[must_use]
    pub fn warnings(&self) -> Vec<String> {
        match self.inner.read() {
            Ok(g) => g.warnings.clone(),
            Err(_) => Vec::new(),
        }
    }

    /// Returns cloned error messages.
    #[must_use]
    pub fn errors(&self) -> Vec<String> {
        match self.inner.read() {
            Ok(g) => g.errors.clone(),
            Err(_) => Vec::new(),
        }
    }

    /// Replaces the current entitlements with the supplied snapshot.
    pub fn update(&self, entitlements: Entitlements) {
        if let Ok(mut guard) = self.inner.write() {
            *guard = entitlements;
        }
    }
}

impl Default for EntitlementSet {
    fn default() -> Self {
        Self::new()
    }
}
