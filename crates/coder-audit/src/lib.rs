//! Audit boundary for the Rust `coderd` rewrite.
#![forbid(unsafe_code)]

use async_trait::async_trait;
use coder_rbac::ResourceKind;
use tracing::info;
use uuid::Uuid;

/// Audit actions emitted by the current Rust slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditAction {
    /// A resource was created.
    Create,
    /// A resource was updated.
    Write,
    /// A resource was deleted.
    Delete,
    /// A user authenticated successfully.
    Login,
    /// A user terminated a session.
    Logout,
}

impl AuditAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Write => "write",
            Self::Delete => "delete",
            Self::Login => "login",
            Self::Logout => "logout",
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
