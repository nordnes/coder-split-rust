//! Telemetry event definitions.
//!
//! Each event captures a single user or system action.  Sensitive fields
//! (user IDs, emails) are hashed before being included in a snapshot so
//! that no PII leaves the deployment.

use serde::Serialize;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

/// The category of a telemetry event.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryEventKind {
    /// A user authenticated (password, API key, OAuth, etc.).
    UserLogin,
    /// A user logged out.
    UserLogout,
    /// A new user was created.
    UserCreated,
    /// A workspace was created.
    WorkspaceCreated,
    /// A workspace was started.
    WorkspaceStarted,
    /// A workspace was stopped.
    WorkspaceStopped,
    /// A workspace was deleted.
    WorkspaceDeleted,
    /// A template was created.
    TemplateCreated,
    /// A template was updated.
    TemplateUpdated,
    /// A template version was created.
    TemplateVersionCreated,
    /// An API key was created.
    ApiKeyCreated,
    /// An organization was created.
    OrganizationCreated,
}

/// A single telemetry event ready for batching and submission.
#[derive(Clone, Debug, Serialize)]
pub struct TelemetryEvent {
    /// Unique event identifier.
    pub id: Uuid,
    /// Event category.
    pub kind: TelemetryEventKind,
    /// SHA-256 hash of the acting user's UUID (anonymized).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashed_user_id: Option<String>,
    /// SHA-256 hash of the target resource's UUID (anonymized).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashed_resource_id: Option<String>,
    /// Timestamp when the event occurred.
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
}

impl TelemetryEvent {
    /// Creates a new telemetry event, anonymizing optional user and resource IDs.
    #[must_use]
    pub fn new(kind: TelemetryEventKind, user_id: Option<Uuid>, resource_id: Option<Uuid>) -> Self {
        Self {
            id: Uuid::new_v4(),
            kind,
            hashed_user_id: user_id.map(|id| hash_uuid(&id)),
            hashed_resource_id: resource_id.map(|id| hash_uuid(&id)),
            timestamp: OffsetDateTime::now_utc(),
        }
    }
}

/// Produces a hex-encoded SHA-256 hash of a UUID.
///
/// Used to anonymize user and resource identifiers before they leave the
/// deployment boundary.
pub(crate) fn hash_uuid(id: &Uuid) -> String {
    let mut hasher = Sha256::new();
    hasher.update(id.as_bytes());
    let result = hasher.finalize();
    hex_encode(&result)
}

/// Hex-encodes a byte slice to a lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_uuid_is_deterministic() {
        let id = Uuid::nil();
        let h1 = hash_uuid(&id);
        let h2 = hash_uuid(&id);
        assert_eq!(h1, h2);
        // SHA-256 hex output is 64 characters.
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn hash_uuid_differs_for_different_ids() {
        let a = Uuid::from_u128(1);
        let b = Uuid::from_u128(2);
        assert_ne!(hash_uuid(&a), hash_uuid(&b));
    }

    #[test]
    fn event_new_anonymizes_ids() {
        let user = Uuid::new_v4();
        let resource = Uuid::new_v4();
        let event = TelemetryEvent::new(TelemetryEventKind::UserLogin, Some(user), Some(resource));

        assert_eq!(event.kind, TelemetryEventKind::UserLogin);
        // The hashed values should NOT be the raw UUID string.
        assert!(event.hashed_user_id.is_some());
        if let Some(ref hashed_user) = event.hashed_user_id {
            assert_ne!(hashed_user, &user.to_string());
            assert_eq!(hashed_user.len(), 64);
        }
    }

    #[test]
    fn event_new_without_ids() {
        let event = TelemetryEvent::new(TelemetryEventKind::WorkspaceCreated, None, None);
        assert!(event.hashed_user_id.is_none());
        assert!(event.hashed_resource_id.is_none());
    }

    #[test]
    fn event_serializes_to_json() -> Result<(), Box<dyn std::error::Error>> {
        let event = TelemetryEvent::new(TelemetryEventKind::TemplateCreated, None, None);
        let json = serde_json::to_value(&event)?;
        assert_eq!(json["kind"], "template_created");
        assert!(json.get("id").is_some());
        assert!(json.get("timestamp").is_some());
        Ok(())
    }

    #[test]
    fn event_kind_serializes_snake_case() -> Result<(), Box<dyn std::error::Error>> {
        let kind = TelemetryEventKind::TemplateVersionCreated;
        let json = serde_json::to_value(&kind)?;
        assert_eq!(json, "template_version_created");
        Ok(())
    }
}
