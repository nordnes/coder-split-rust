//! Audit boundary for the Rust `coderd` rewrite.
#![forbid(unsafe_code)]

pub mod batched_sink;

use async_trait::async_trait;
use coder_rbac::ResourceKind;
use tracing::info;
use uuid::Uuid;

/// Audit actions emitted by the current Rust slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "audit_action", rename_all = "snake_case")]
pub enum AuditAction {
    /// A resource was created.
    Create,
    /// A resource was updated.
    Write,
    /// A resource was deleted.
    Delete,
    /// A workspace or service was started.
    Start,
    /// A workspace or service was stopped.
    Stop,
    /// A user authenticated successfully.
    Login,
    /// A user terminated a session.
    Logout,
    /// A new user registered.
    Register,
    /// A password reset was requested.
    RequestPasswordReset,
    /// A connection was established (deprecated).
    Connect,
    /// A connection was terminated (deprecated).
    Disconnect,
    /// A resource was opened (deprecated).
    Open,
    /// A resource was closed (deprecated).
    Close,
}

impl AuditAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Write => "write",
            Self::Delete => "delete",
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Login => "login",
            Self::Logout => "logout",
            Self::Register => "register",
            Self::RequestPasswordReset => "request_password_reset",
            Self::Connect => "connect",
            Self::Disconnect => "disconnect",
            Self::Open => "open",
            Self::Close => "close",
        }
    }
}

/// Structured audit event emitted by mutating or authentication handlers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEvent {
    /// Normalized audit action.
    pub action: AuditAction,
    /// Target resource kind.
    pub resource: ResourceKind,
    /// Authenticated actor when one exists.
    pub actor_user_id: Option<Uuid>,
    /// Target object identifier when one exists.
    pub target_id: Option<String>,
    /// Human-readable summary for operational inspection.
    pub summary: String,
}

/// Sink abstraction for backend audit events.
#[async_trait]
pub trait AuditSink: Send + Sync {
    /// Records a structured audit event.
    async fn record(&self, event: AuditEvent);
}

/// Tracing-backed audit sink used by the current binary.
#[derive(Debug, Default)]
pub struct TracingAuditSink;

#[async_trait]
impl AuditSink for TracingAuditSink {
    async fn record(&self, event: AuditEvent) {
        info!(
            action = event.action.as_str(),
            resource = ?event.resource,
            actor_user_id = event.actor_user_id.map(|value| value.to_string()),
            target_id = event.target_id,
            summary = event.summary,
            "audit event"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // ── AuditAction string representations ───────────────────

    #[test]
    fn audit_action_as_str_covers_all_variants() {
        let cases: &[(AuditAction, &str)] = &[
            (AuditAction::Create, "create"),
            (AuditAction::Write, "write"),
            (AuditAction::Delete, "delete"),
            (AuditAction::Start, "start"),
            (AuditAction::Stop, "stop"),
            (AuditAction::Login, "login"),
            (AuditAction::Logout, "logout"),
            (AuditAction::Register, "register"),
            (AuditAction::RequestPasswordReset, "request_password_reset"),
            (AuditAction::Connect, "connect"),
            (AuditAction::Disconnect, "disconnect"),
            (AuditAction::Open, "open"),
            (AuditAction::Close, "close"),
        ];

        for (action, expected) in cases {
            assert_eq!(
                action.as_str(),
                *expected,
                "AuditAction::{action:?} should map to \"{expected}\""
            );
        }

        // Ensure we tested every variant (compile-time exhaustiveness via match).
        let count = cases.len();
        assert_eq!(count, 13, "expected 13 AuditAction variants, got {count}");
    }

    // ── AuditAction equality and clone ───────────────────────

    #[test]
    fn audit_action_clone_and_equality() {
        let original = AuditAction::Login;
        let cloned = original;
        assert_eq!(original, cloned);
        assert_ne!(AuditAction::Login, AuditAction::Logout);
    }

    // ── AuditEvent construction ──────────────────────────────

    #[test]
    fn audit_event_construction_with_all_fields() {
        let user_id = Uuid::new_v4();
        let event = AuditEvent {
            action: AuditAction::Create,
            resource: ResourceKind::User,
            actor_user_id: Some(user_id),
            target_id: Some("target-123".to_owned()),
            summary: "Created user".to_owned(),
        };

        assert_eq!(event.action, AuditAction::Create);
        assert_eq!(event.actor_user_id, Some(user_id));
        assert_eq!(event.target_id.as_deref(), Some("target-123"));
        assert_eq!(event.summary, "Created user");
    }

    #[test]
    fn audit_event_with_none_optional_fields() {
        let event = AuditEvent {
            action: AuditAction::Logout,
            resource: ResourceKind::ApiKey,
            actor_user_id: None,
            target_id: None,
            summary: String::new(),
        };

        assert!(event.actor_user_id.is_none());
        assert!(event.target_id.is_none());
        assert!(event.summary.is_empty());
    }

    #[test]
    fn audit_event_with_nil_uuid() {
        let nil = Uuid::nil();
        let event = AuditEvent {
            action: AuditAction::Login,
            resource: ResourceKind::Authentication,
            actor_user_id: Some(nil),
            target_id: Some(nil.to_string()),
            summary: "nil uuid login".to_owned(),
        };

        assert_eq!(event.actor_user_id, Some(Uuid::nil()));
        assert_eq!(
            event.target_id.as_deref(),
            Some("00000000-0000-0000-0000-000000000000")
        );
    }

    // ── AuditEvent clone and equality ────────────────────────

    #[test]
    fn audit_event_clone_preserves_equality() {
        let event = AuditEvent {
            action: AuditAction::Write,
            resource: ResourceKind::Organization,
            actor_user_id: Some(Uuid::new_v4()),
            target_id: Some("org-1".to_owned()),
            summary: "Updated org settings".to_owned(),
        };

        let cloned = event.clone();
        assert_eq!(event, cloned);
    }

    // ── Mock AuditSink ───────────────────────────────────────

    /// In-memory audit sink that captures recorded events for test assertions.
    struct MockAuditSink {
        events: Mutex<Vec<AuditEvent>>,
    }

    impl MockAuditSink {
        fn new() -> Self {
            Self {
                events: Mutex::new(Vec::new()),
            }
        }

        fn recorded_events(&self) -> Vec<AuditEvent> {
            self.events
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }
    }

    #[async_trait]
    impl AuditSink for MockAuditSink {
        async fn record(&self, event: AuditEvent) {
            self.events
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(event);
        }
    }

    #[tokio::test]
    async fn mock_sink_records_single_event() {
        let sink = MockAuditSink::new();
        let event = AuditEvent {
            action: AuditAction::Delete,
            resource: ResourceKind::Workspace,
            actor_user_id: Some(Uuid::new_v4()),
            target_id: Some("ws-42".to_owned()),
            summary: "Deleted workspace".to_owned(),
        };

        sink.record(event.clone()).await;

        let recorded = sink.recorded_events();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0], event);
    }

    #[tokio::test]
    async fn mock_sink_records_multiple_events_in_order() {
        let sink = MockAuditSink::new();

        let actions = [
            AuditAction::Login,
            AuditAction::Create,
            AuditAction::Write,
            AuditAction::Logout,
        ];

        for action in &actions {
            sink.record(AuditEvent {
                action: *action,
                resource: ResourceKind::User,
                actor_user_id: None,
                target_id: None,
                summary: format!("action: {}", action.as_str()),
            })
            .await;
        }

        let recorded = sink.recorded_events();
        assert_eq!(recorded.len(), actions.len());
        for (i, action) in actions.iter().enumerate() {
            assert_eq!(
                recorded[i].action, *action,
                "event at index {i} should have action {:?}",
                action
            );
        }
    }

    // ── TracingAuditSink does not panic ──────────────────────

    #[tokio::test]
    async fn tracing_sink_does_not_panic() {
        let sink = TracingAuditSink;

        // Exercise with fully populated event.
        sink.record(AuditEvent {
            action: AuditAction::Register,
            resource: ResourceKind::User,
            actor_user_id: Some(Uuid::new_v4()),
            target_id: Some("new-user".to_owned()),
            summary: "User registered".to_owned(),
        })
        .await;

        // Exercise with minimal/empty event.
        sink.record(AuditEvent {
            action: AuditAction::Close,
            resource: ResourceKind::Template,
            actor_user_id: None,
            target_id: None,
            summary: String::new(),
        })
        .await;
    }
}
