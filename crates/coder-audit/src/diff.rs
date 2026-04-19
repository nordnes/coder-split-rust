//! Structured audit diffs.
//!
//! Mirrors Go's `coderd/audit/diff.go` (`Diff[T]` + `Map[field → OldNew]`).
//! A diff is a map of field-name → `{old, new, secret}`. Fields annotated
//! with `#[audit(ignore)]` never appear; fields annotated with
//! `#[audit(secret)]` carry `secret: true` so downstream viewers can redact
//! the values.
//!
//! The [`Auditable`] trait is implemented via the companion
//! `#[derive(Auditable)]` macro (re-exported from `coder-audit`).

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

/// Trait implemented by auditable structs. Normally derived via
/// `#[derive(Auditable)]`.
pub trait Auditable {
    /// Compare `self` (the "old" value) with `other` (the "new" value) and
    /// return a structured diff.
    fn audit_diff(&self, other: &Self) -> AuditDiff;
}

/// Map of changed fields for an auditable value.
///
/// Serializes as a JSON object of `{ field_name: AuditFieldDiff }`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuditDiff {
    /// Per-field change records keyed by field name.
    pub changes: BTreeMap<String, AuditFieldDiff>,
}

/// One field's before/after values plus a `secret` flag.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuditFieldDiff {
    /// Value before the change.
    pub old: serde_json::Value,
    /// Value after the change.
    pub new: serde_json::Value,
    /// Whether the value should be redacted when rendered to users.
    pub secret: bool,
}

impl AuditDiff {
    /// Returns an empty diff.
    #[must_use]
    pub fn new() -> Self {
        Self {
            changes: BTreeMap::new(),
        }
    }

    /// Returns `true` when the diff contains no field changes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// Returns the number of changed fields.
    #[must_use]
    pub fn len(&self) -> usize {
        self.changes.len()
    }

    /// Serializes the diff to a JSON `Value`.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }

    /// Appends a short, human-readable description of the diff to the given
    /// summary string. Useful as a fallback when structured storage of
    /// diffs is not yet in place.
    ///
    /// Secret values are redacted as `"***"` in the merged description.
    pub fn merge_into(&self, summary: &mut String) {
        if self.changes.is_empty() {
            return;
        }
        if !summary.is_empty() {
            summary.push_str(" — ");
        }
        summary.push_str("changes: ");
        let mut first = true;
        for (field, change) in &self.changes {
            if !first {
                summary.push_str(", ");
            }
            first = false;
            if change.secret {
                // Intentionally no values — viewer-side would redact anyway.
                let _ = write!(summary, "{field}=(secret)");
            } else {
                let _ = write!(summary, "{field}: {} -> {}", change.old, change.new);
            }
        }
    }
}

/// Hidden helpers used exclusively by the `#[derive(Auditable)]` macro.
/// Not part of the public API.
#[doc(hidden)]
pub mod _macro_support {
    use serde::Serialize;

    /// Best-effort conversion of any serializable value to a
    /// `serde_json::Value`. Falls back to a string debug of the error on
    /// failure (the proc macro never panics on non-serializable types).
    pub fn to_json_value<T: Serialize>(value: &T) -> serde_json::Value {
        match serde_json::to_value(value) {
            Ok(v) => v,
            Err(error) => serde_json::Value::String(error.to_string()),
        }
    }
}
