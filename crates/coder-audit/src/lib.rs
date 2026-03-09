//! Audit boundary for the Rust `coderd` rewrite.
#![forbid(unsafe_code)]

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
