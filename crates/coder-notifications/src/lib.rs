//! Notification, inbox, and webpush boundary for the Rust `coderd` rewrite.
//!
//! Provides a background dispatch loop that polls pending notification messages
//! and delivers them via SMTP email, HTTP webhook, or in-app inbox.
#![forbid(unsafe_code)]

use std::sync::{Arc, Weak};

use coder_core::IdentityStore;
use coder_core::identity::{NotificationMessageStatus, NotificationMethod};
use tracing::{info, warn};

/// Current milestone for the notifications crate.
pub const STATUS: &str = "active";

const DISPATCH_POLL_SECS: u64 = 10;
const DISPATCH_BATCH_SIZE: u32 = 50;
const MAX_DISPATCH_ATTEMPTS: u32 = 3;

/// Configuration for the notification dispatch pipeline.
#[derive(Clone, Debug)]
pub struct NotificationConfig {
    /// SMTP relay host for email dispatch (empty = disabled).
    pub smtp_host: String,
    /// SMTP relay port.
    pub smtp_port: u16,
    /// Sender email address for outgoing notifications.
    pub smtp_from: String,
    /// Webhook timeout in seconds.
    pub webhook_timeout_secs: u64,
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            smtp_host: String::new(),
            smtp_port: 587,
            smtp_from: String::new(),
            webhook_timeout_secs: 30,
        }
    }
}

/// Background notification dispatch service.
///
/// Polls the database for pending notification messages and delivers them
/// using the configured dispatch methods (email, webhook, or inbox).
pub struct NotificationDispatchService<S> {
    store: S,
    config: NotificationConfig,
    http_client: reqwest::Client,
}

impl<S> NotificationDispatchService<S>
where
    S: IdentityStore + Clone + Send + Sync + 'static,
{
    /// Creates the dispatch service and starts the background poll loop.
    pub fn new(store: S, config: NotificationConfig) -> Result<Arc<Self>, reqwest::Error> {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.webhook_timeout_secs))
            .build()?;

        let service = Arc::new(Self {
            store,
            config,
            http_client,
        });
        Self::spawn_dispatch_loop(&service);
        Ok(service)
    }

    /// Returns the current configuration.
    #[must_use]
    pub fn config(&self) -> &NotificationConfig {
        &self.config
    }

    async fn dispatch_once(&self) -> Result<u32, coder_core::StorageError> {
        // Messages that have already reached MAX_DISPATCH_ATTEMPTS are
        // excluded by the query itself via the max_attempt_count parameter.
        let messages = self
            .store
            .acquire_pending_notification_messages(DISPATCH_BATCH_SIZE, MAX_DISPATCH_ATTEMPTS)
            .await?;

        let count = u32::try_from(messages.len()).unwrap_or(u32::MAX);

        for message in messages {
            let result = match message.method {
                NotificationMethod::Email => self.dispatch_email(&message).await,
                NotificationMethod::Webhook => self.dispatch_webhook(&message).await,
                NotificationMethod::Inbox => self.dispatch_inbox(&message).await,
            };

            let new_status = if result.is_ok() {
                NotificationMessageStatus::Sent
            } else {
                if let Err(ref err) = result {
                    warn!(
                        message_id = %message.id,
                        method = ?message.method,
                        error = %err,
                        "notification dispatch failed"
                    );
                }
                // Increment the attempt count so exhausted messages can be
                // identified and marked as permanently failed below.
                let _ = self
                    .store
                    .increment_notification_message_attempt_count(message.id)
                    .await;
                // If this was the last allowed attempt, mark as permanent
                // failure so the message is no longer eligible for retry.
                if message.attempt_count + 1 >= MAX_DISPATCH_ATTEMPTS as i32 {
                    NotificationMessageStatus::Failed
                } else {
                    NotificationMessageStatus::TemporaryFailure
                }
            };

            let _ = self
                .store
                .update_notification_message_status(message.id, new_status)
                .await;
        }

        Ok(count)
    }

    async fn dispatch_email(
        &self,
        message: &coder_core::identity::NotificationMessageRecord,
    ) -> Result<(), NotificationDispatchError> {
        if self.config.smtp_host.is_empty() {
            return Err(NotificationDispatchError::ConfigMissing(
                "SMTP host is not configured".to_owned(),
            ));
        }

        // A full SMTP implementation using `lettre` will be wired in when
        // SMTP credentials are provisioned. Until then, return an error so the
        // message is not incorrectly marked as Sent.
        warn!(
            message_id = %message.id,
            user_id = %message.user_id,
            smtp_host = %self.config.smtp_host,
            "email dispatch not yet implemented"
        );
        Err(NotificationDispatchError::Transport(
            "SMTP email dispatch is not yet implemented".to_owned(),
        ))
    }

    async fn dispatch_webhook(
        &self,
        message: &coder_core::identity::NotificationMessageRecord,
    ) -> Result<(), NotificationDispatchError> {
        // The targets_json field contains the webhook endpoint URL.
        let endpoint: String = serde_json::from_str(&message.targets_json)
            .ok()
            .and_then(|v: serde_json::Value| {
                v.get("url").and_then(|u| u.as_str()).map(String::from)
            })
            .unwrap_or_default();

        if endpoint.is_empty() {
            return Err(NotificationDispatchError::ConfigMissing(
                "webhook endpoint URL not found in targets".to_owned(),
            ));
        }

        let response = self
            .http_client
            .post(&endpoint)
            .header("Content-Type", "application/json")
            .body(message.input_json.clone())
            .send()
            .await
            .map_err(|e| NotificationDispatchError::Transport(e.to_string()))?;

        if !response.status().is_success() {
            return Err(NotificationDispatchError::Transport(format!(
                "webhook returned HTTP {}",
                response.status().as_u16()
            )));
        }

        info!(
            message_id = %message.id,
            endpoint = %endpoint,
            "webhook notification dispatched"
        );
        Ok(())
    }

    async fn dispatch_inbox(
        &self,
        message: &coder_core::identity::NotificationMessageRecord,
    ) -> Result<(), NotificationDispatchError> {
        // Inbox notifications are stored in the database and served via the
        // inbox API. The fetch marks them as sent automatically.
        info!(
            message_id = %message.id,
            user_id = %message.user_id,
            "inbox notification delivered"
        );
        Ok(())
    }

    fn spawn_dispatch_loop(service: &Arc<Self>) {
        let weak = Arc::downgrade(service);
        tokio::spawn(async move {
            run_dispatch_loop(weak).await;
        });
    }
}

/// Errors from the notification dispatch pipeline.
#[derive(Debug, thiserror::Error)]
pub enum NotificationDispatchError {
    /// Required configuration is missing.
    #[error("config missing: {0}")]
    ConfigMissing(String),
    /// Transport-level delivery failure.
    #[error("transport error: {0}")]
    Transport(String),
}

async fn run_dispatch_loop<S>(service: Weak<NotificationDispatchService<S>>)
where
    S: IdentityStore + Clone + Send + Sync + 'static,
{
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(DISPATCH_POLL_SECS));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        interval.tick().await;
        let Some(service) = service.upgrade() else {
            return;
        };
        match service.dispatch_once().await {
            Ok(0) => {} // nothing to dispatch
            Ok(n) => info!(dispatched = n, "notification dispatch cycle completed"),
            Err(error) => warn!(error = %error, "notification dispatch cycle failed"),
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use coder_core::identity::{
        CreateUserStoreError, InsertOrganizationMemberError, NotificationMessageRecord,
        NotificationMessageStatus, NotificationMethod, OrganizationMemberListFilter,
        OrganizationMemberRecord, OrganizationRecord, UserAppearanceRecord, UserListFilter,
        UserPreferenceRecord, UserRecord, UserStatus,
    };
    use coder_core::{CreateUserInput, IdentityStore, StorageError};
    use std::sync::Mutex;
    use time::OffsetDateTime;
    use uuid::Uuid;

    // ── Mock store ───────────────────────────────────────────

    /// Configurable mock that controls what `acquire_pending_notification_messages`
    /// returns and records calls to `update_notification_message_status` and
    /// `increment_notification_message_attempt_count`.
    #[derive(Clone)]
    struct MockStore {
        pending_messages: Vec<NotificationMessageRecord>,
        status_updates: Arc<Mutex<Vec<(Uuid, NotificationMessageStatus)>>>,
        attempt_increments: Arc<Mutex<Vec<Uuid>>>,
        force_error: Option<String>,
    }

    impl MockStore {
        fn new() -> Self {
            Self {
                pending_messages: Vec::new(),
                status_updates: Arc::new(Mutex::new(Vec::new())),
                attempt_increments: Arc::new(Mutex::new(Vec::new())),
                force_error: None,
            }
        }

        fn with_pending(mut self, messages: Vec<NotificationMessageRecord>) -> Self {
            self.pending_messages = messages;
            self
        }

        fn with_error(mut self, msg: &str) -> Self {
            self.force_error = Some(msg.to_owned());
            self
        }

        fn maybe_err(&self) -> Result<(), StorageError> {
            if let Some(msg) = &self.force_error {
                Err(StorageError::unavailable(msg))
            } else {
                Ok(())
            }
        }
    }

    #[async_trait]
    impl IdentityStore for MockStore {
        async fn list_users(
            &self,
            _filter: UserListFilter,
        ) -> Result<(Vec<UserRecord>, usize), StorageError> {
            self.maybe_err()?;
            Ok((Vec::new(), 0))
        }

        async fn create_user(
            &self,
            _input: CreateUserInput,
        ) -> Result<UserRecord, CreateUserStoreError> {
            Err(CreateUserStoreError::Storage(StorageError::unavailable(
                "not implemented in MockStore",
            )))
        }

        async fn find_user_by_id(
            &self,
            _user_id: Uuid,
        ) -> Result<Option<UserRecord>, StorageError> {
            self.maybe_err()?;
            Ok(None)
        }

        async fn find_user_by_username(
            &self,
            _username: &str,
        ) -> Result<Option<UserRecord>, StorageError> {
            self.maybe_err()?;
            Ok(None)
        }

        async fn soft_delete_user(&self, _user_id: Uuid) -> Result<bool, StorageError> {
            self.maybe_err()?;
            Ok(false)
        }

        async fn list_user_memberships(
            &self,
            _user_id: Uuid,
        ) -> Result<Vec<OrganizationMemberRecord>, StorageError> {
            self.maybe_err()?;
            Ok(Vec::new())
        }

        async fn update_user_roles(
            &self,
            _user_id: Uuid,
            _roles: Vec<String>,
        ) -> Result<Option<UserRecord>, StorageError> {
            self.maybe_err()?;
            Ok(None)
        }

        async fn update_user_profile(
            &self,
            _user_id: Uuid,
            _username: &str,
            _name: &str,
        ) -> Result<Option<UserRecord>, StorageError> {
            self.maybe_err()?;
            Ok(None)
        }

        async fn update_user_status(
            &self,
            _user_id: Uuid,
            _status: UserStatus,
        ) -> Result<Option<UserRecord>, StorageError> {
            self.maybe_err()?;
            Ok(None)
        }

        async fn user_appearance(
            &self,
            _user_id: Uuid,
        ) -> Result<UserAppearanceRecord, StorageError> {
            Err(StorageError::unavailable("not implemented in MockStore"))
        }

        async fn update_user_appearance(
            &self,
            _user_id: Uuid,
            _theme_preference: &str,
            _terminal_font: &str,
        ) -> Result<Option<UserAppearanceRecord>, StorageError> {
            self.maybe_err()?;
            Ok(None)
        }

        async fn user_preferences(
            &self,
            _user_id: Uuid,
        ) -> Result<UserPreferenceRecord, StorageError> {
            Err(StorageError::unavailable("not implemented in MockStore"))
        }

        async fn update_user_preferences(
            &self,
            _user_id: Uuid,
            _task_notification_alert_dismissed: bool,
        ) -> Result<Option<UserPreferenceRecord>, StorageError> {
            self.maybe_err()?;
            Ok(None)
        }

        async fn list_organizations(
            &self,
            _organization_ids: Vec<Uuid>,
        ) -> Result<Vec<OrganizationRecord>, StorageError> {
            self.maybe_err()?;
            Ok(Vec::new())
        }

        async fn find_organization_by_id(
            &self,
            _organization_id: Uuid,
        ) -> Result<Option<OrganizationRecord>, StorageError> {
            self.maybe_err()?;
            Ok(None)
        }

        async fn find_organization_by_name(
            &self,
            _name: &str,
        ) -> Result<Option<OrganizationRecord>, StorageError> {
            self.maybe_err()?;
            Ok(None)
        }

        async fn list_organization_members(
            &self,
            _filter: OrganizationMemberListFilter,
        ) -> Result<Vec<OrganizationMemberRecord>, StorageError> {
            self.maybe_err()?;
            Ok(Vec::new())
        }

        async fn list_organization_members_page(
            &self,
            _filter: OrganizationMemberListFilter,
        ) -> Result<(Vec<OrganizationMemberRecord>, usize), StorageError> {
            self.maybe_err()?;
            Ok((Vec::new(), 0))
        }

        async fn find_organization_member(
            &self,
            _organization_id: Uuid,
            _user_id: Uuid,
        ) -> Result<Option<OrganizationMemberRecord>, StorageError> {
            self.maybe_err()?;
            Ok(None)
        }

        async fn insert_organization_member(
            &self,
            _organization_id: Uuid,
            _user_id: Uuid,
        ) -> Result<OrganizationMemberRecord, InsertOrganizationMemberError> {
            Err(InsertOrganizationMemberError::Storage(
                StorageError::unavailable("not implemented in MockStore"),
            ))
        }

        async fn delete_organization_member(
            &self,
            _organization_id: Uuid,
            _user_id: Uuid,
        ) -> Result<bool, StorageError> {
            self.maybe_err()?;
            Ok(false)
        }

        async fn update_organization_member_roles(
            &self,
            _organization_id: Uuid,
            _user_id: Uuid,
            _roles: Vec<String>,
        ) -> Result<Option<OrganizationMemberRecord>, StorageError> {
            self.maybe_err()?;
            Ok(None)
        }

        // ----- Notification overrides -----

        async fn acquire_pending_notification_messages(
            &self,
            _limit: u32,
            _max_attempt_count: u32,
        ) -> Result<Vec<NotificationMessageRecord>, StorageError> {
            self.maybe_err()?;
            Ok(self.pending_messages.clone())
        }

        async fn update_notification_message_status(
            &self,
            message_id: Uuid,
            status: NotificationMessageStatus,
        ) -> Result<bool, StorageError> {
            self.maybe_err()?;
            self.status_updates
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((message_id, status));
            Ok(true)
        }

        async fn increment_notification_message_attempt_count(
            &self,
            message_id: Uuid,
        ) -> Result<bool, StorageError> {
            self.maybe_err()?;
            self.attempt_increments
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(message_id);
            Ok(true)
        }
    }

    // ── Helpers ──────────────────────────────────────────────

    fn make_message(method: NotificationMethod, targets_json: &str) -> NotificationMessageRecord {
        let now = OffsetDateTime::now_utc();
        NotificationMessageRecord {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            notification_template_id: Uuid::new_v4(),
            method,
            status: NotificationMessageStatus::Pending,
            attempt_count: 0,
            input_json: r#"{"key":"value"}"#.to_owned(),
            targets_json: targets_json.to_owned(),
            created_at: now,
            updated_at: now,
        }
    }

    // ── 1. NotificationMethod round-trip serialization ──────

    #[test]
    fn notification_method_round_trip_serialization() {
        let variants = [
            (NotificationMethod::Email, r#""smtp""#),
            (NotificationMethod::Webhook, r#""webhook""#),
            (NotificationMethod::Inbox, r#""inbox""#),
        ];
        for (variant, expected_json) in &variants {
            let serialized = serde_json::to_string(variant)
                .unwrap_or_else(|e| panic!("failed to serialize {variant:?}: {e}"));
            assert_eq!(&serialized, expected_json);
            let deserialized: NotificationMethod = serde_json::from_str(&serialized)
                .unwrap_or_else(|e| panic!("failed to deserialize {serialized}: {e}"));
            assert_eq!(&deserialized, variant);
        }
    }

    // ── 2. NotificationMessageStatus round-trip serialization ─

    #[test]
    fn notification_message_status_round_trip_serialization() {
        let variants = [
            (NotificationMessageStatus::Pending, r#""pending""#),
            (NotificationMessageStatus::Leased, r#""leased""#),
            (NotificationMessageStatus::Sent, r#""sent""#),
            (
                NotificationMessageStatus::TemporaryFailure,
                r#""temporary_failure""#,
            ),
            (NotificationMessageStatus::Failed, r#""permanent_failure""#),
        ];
        for (variant, expected_json) in &variants {
            let serialized = serde_json::to_string(variant)
                .unwrap_or_else(|e| panic!("failed to serialize {variant:?}: {e}"));
            assert_eq!(&serialized, expected_json);
            let deserialized: NotificationMessageStatus = serde_json::from_str(&serialized)
                .unwrap_or_else(|e| panic!("failed to deserialize {serialized}: {e}"));
            assert_eq!(&deserialized, variant);
        }
    }

    // ── 3. NotificationConfig default values ────────────────

    #[test]
    fn notification_config_default_values() {
        let config = NotificationConfig::default();
        assert!(config.smtp_host.is_empty());
        assert_eq!(config.smtp_port, 587);
        assert!(config.smtp_from.is_empty());
        assert_eq!(config.webhook_timeout_secs, 30);
    }

    // ── 4. NotificationMessageRecord construction ───────────

    #[test]
    fn notification_message_record_construction() {
        let msg = make_message(
            NotificationMethod::Email,
            r#"{"url":"https://example.com"}"#,
        );
        assert_eq!(msg.method, NotificationMethod::Email);
        assert_eq!(msg.status, NotificationMessageStatus::Pending);
        assert_eq!(msg.attempt_count, 0);
        assert!(!msg.input_json.is_empty());
    }

    // ── 5. NotificationDispatchError display messages ───────

    #[test]
    fn dispatch_error_display_messages() {
        let config_err =
            NotificationDispatchError::ConfigMissing("SMTP host is not configured".to_owned());
        assert!(config_err.to_string().contains("config missing"));
        assert!(
            config_err
                .to_string()
                .contains("SMTP host is not configured")
        );

        let transport_err = NotificationDispatchError::Transport("connection refused".to_owned());
        assert!(transport_err.to_string().contains("transport error"));
        assert!(transport_err.to_string().contains("connection refused"));
    }

    // ── 6. Service creation and config accessor ─────────────

    #[tokio::test]
    async fn service_new_returns_arc_with_config() {
        let store = MockStore::new();
        let config = NotificationConfig {
            smtp_host: "mail.example.com".to_owned(),
            smtp_port: 465,
            smtp_from: "noreply@example.com".to_owned(),
            webhook_timeout_secs: 15,
        };
        let service = NotificationDispatchService::new(store, config.clone())
            .unwrap_or_else(|e| panic!("failed to create service: {e}"));
        assert_eq!(service.config().smtp_host, "mail.example.com");
        assert_eq!(service.config().smtp_port, 465);
        assert_eq!(service.config().smtp_from, "noreply@example.com");
        assert_eq!(service.config().webhook_timeout_secs, 15);
    }

    // ── 7. Dispatch with no pending messages ────────────────

    #[tokio::test]
    async fn dispatch_once_with_no_pending_messages() {
        let store = MockStore::new();
        let config = NotificationConfig::default();
        let service = NotificationDispatchService::new(store, config)
            .unwrap_or_else(|e| panic!("failed to create service: {e}"));
        let count = service
            .dispatch_once()
            .await
            .unwrap_or_else(|e| panic!("dispatch_once failed: {e}"));
        assert_eq!(count, 0);
    }

    // ── 8. Dispatch propagates storage error ────────────────

    #[tokio::test]
    async fn dispatch_once_propagates_storage_error() {
        let store = MockStore::new().with_error("database is down");
        let config = NotificationConfig::default();
        let service = NotificationDispatchService::new(store, config)
            .unwrap_or_else(|e| panic!("failed to create service: {e}"));
        let result = service.dispatch_once().await;
        assert!(result.is_err());
        assert!(
            result
                .err()
                .is_some_and(|e| e.to_string().contains("database is down"))
        );
    }

    // ── 9. Inbox dispatch marks message as Sent ─────────────

    #[tokio::test]
    async fn dispatch_inbox_message_marks_sent() {
        let msg = make_message(NotificationMethod::Inbox, "{}");
        let msg_id = msg.id;
        let store = MockStore::new().with_pending(vec![msg]);
        let config = NotificationConfig::default();
        let service = NotificationDispatchService::new(store.clone(), config)
            .unwrap_or_else(|e| panic!("failed to create service: {e}"));

        let count = service
            .dispatch_once()
            .await
            .unwrap_or_else(|e| panic!("dispatch_once failed: {e}"));
        assert_eq!(count, 1);

        let updates = store
            .status_updates
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].0, msg_id);
        assert_eq!(updates[0].1, NotificationMessageStatus::Sent);
    }

    // ── 10. Email dispatch without SMTP config records failure ─

    #[tokio::test]
    async fn dispatch_email_without_smtp_records_temporary_failure() {
        let msg = make_message(NotificationMethod::Email, "{}");
        let msg_id = msg.id;
        let store = MockStore::new().with_pending(vec![msg]);
        // Default config has empty smtp_host → email dispatch fails.
        let config = NotificationConfig::default();
        let service = NotificationDispatchService::new(store.clone(), config)
            .unwrap_or_else(|e| panic!("failed to create service: {e}"));

        let count = service
            .dispatch_once()
            .await
            .unwrap_or_else(|e| panic!("dispatch_once failed: {e}"));
        assert_eq!(count, 1);

        // The attempt counter should have been incremented.
        let increments = store
            .attempt_increments
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        assert_eq!(increments.len(), 1);
        assert_eq!(increments[0], msg_id);

        // With attempt_count 0 + 1 < MAX_DISPATCH_ATTEMPTS (3), status is TemporaryFailure.
        let updates = store
            .status_updates
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].1, NotificationMessageStatus::TemporaryFailure);
    }

    // ── 11. Exhausted attempts mark message as Failed ───────

    #[tokio::test]
    async fn dispatch_exhausted_attempts_marks_permanent_failure() {
        let mut msg = make_message(NotificationMethod::Email, "{}");
        msg.attempt_count = 2; // MAX_DISPATCH_ATTEMPTS - 1 → next failure is permanent.
        let msg_id = msg.id;
        let store = MockStore::new().with_pending(vec![msg]);
        let config = NotificationConfig::default();
        let service = NotificationDispatchService::new(store.clone(), config)
            .unwrap_or_else(|e| panic!("failed to create service: {e}"));

        let count = service
            .dispatch_once()
            .await
            .unwrap_or_else(|e| panic!("dispatch_once failed: {e}"));
        assert_eq!(count, 1);

        let updates = store
            .status_updates
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].0, msg_id);
        assert_eq!(updates[0].1, NotificationMessageStatus::Failed);
    }

    // ── 12. Webhook without endpoint URL records failure ────

    #[tokio::test]
    async fn dispatch_webhook_without_url_records_temporary_failure() {
        // targets_json with no "url" field → webhook dispatch fails.
        let msg = make_message(NotificationMethod::Webhook, r#"{"other":"value"}"#);
        let msg_id = msg.id;
        let store = MockStore::new().with_pending(vec![msg]);
        let config = NotificationConfig::default();
        let service = NotificationDispatchService::new(store.clone(), config)
            .unwrap_or_else(|e| panic!("failed to create service: {e}"));

        let count = service
            .dispatch_once()
            .await
            .unwrap_or_else(|e| panic!("dispatch_once failed: {e}"));
        assert_eq!(count, 1);

        let increments = store
            .attempt_increments
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        assert_eq!(increments.len(), 1);
        assert_eq!(increments[0], msg_id);

        let updates = store
            .status_updates
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].1, NotificationMessageStatus::TemporaryFailure);
    }
}
