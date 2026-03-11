//! Notification, inbox, and webpush boundary for the Rust `coderd` rewrite.
//!
//! Provides a background dispatch loop that polls pending notification messages
//! and delivers them via SMTP email, HTTP webhook, or in-app inbox.
//!
//! Also provides the [`Webpusher`] dispatcher for sending Web Push notifications
//! to browser subscriptions using VAPID authentication.
#![forbid(unsafe_code)]

use std::sync::{Arc, Weak};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use coder_core::AppStore;
use coder_core::IdentityStore;
use coder_core::api::{WebpushMessage, WebpushSubscription};
use coder_core::identity::{NotificationMessageStatus, NotificationMethod};
use tracing::{error, info, warn};
use uuid::Uuid;
use web_push::{
    ContentEncoding, IsahcWebPushClient, SubscriptionInfo, VapidSignatureBuilder, WebPushClient,
    WebPushMessageBuilder,
};

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

// ---------------------------------------------------------------------------
// Web Push dispatcher
// ---------------------------------------------------------------------------

/// Errors from the web push dispatcher.
#[derive(Debug, thiserror::Error)]
pub enum WebpushError {
    /// Storage-level error.
    #[error("storage error: {0}")]
    Storage(#[from] coder_core::StorageError),
    /// Web push protocol or encoding error.
    #[error("web push error: {0}")]
    WebPush(String),
    /// JSON serialization failure.
    #[error("serialization error: {0}")]
    Serialization(String),
}

/// Web Push notification dispatcher using VAPID authentication.
///
/// Manages VAPID key pairs and sends push notifications to browser
/// subscriptions. Keys are loaded from the database on construction,
/// and regenerated if missing.
pub struct Webpusher<S> {
    store: S,
    /// VAPID subscriber contact (mailto: or https:// URL).
    vapid_sub: String,
    /// Base64url-encoded VAPID public key (for clients).
    vapid_public_key: String,
    /// PEM-encoded VAPID private key.
    vapid_private_pem: String,
    /// Reusable web push HTTP client.
    client: IsahcWebPushClient,
}

impl<S> Webpusher<S>
where
    S: AppStore + Clone + Send + Sync + 'static,
{
    /// Creates a new web push dispatcher.
    ///
    /// Loads VAPID keys from the database. If no keys exist, generates a new
    /// key pair and stores it, deleting any existing subscriptions that would
    /// be invalid with the new keys.
    pub async fn new(store: S, vapid_sub: String) -> Result<Self, WebpushError> {
        let keys = store.get_webpush_vapid_keys().await?;

        let (public_key, private_pem) = match keys {
            Some(kp) if !kp.public_key.is_empty() && !kp.private_key.is_empty() => {
                (kp.public_key, kp.private_key)
            }
            _ => {
                // Generate new VAPID keys and delete stale subscriptions.
                regenerate_vapid_keys(&store).await?
            }
        };

        // Validate that the private key can be parsed before accepting it.
        let _partial = VapidSignatureBuilder::from_pem_no_sub(private_pem.as_bytes())
            .map_err(|e| WebpushError::WebPush(format!("invalid stored VAPID key: {e}")))?;

        let client = IsahcWebPushClient::new().map_err(|e| WebpushError::WebPush(e.to_string()))?;

        Ok(Self {
            store,
            vapid_sub,
            vapid_public_key: public_key,
            vapid_private_pem: private_pem,
            client,
        })
    }

    /// Returns the VAPID public key for client-side subscription setup.
    #[must_use]
    pub fn public_key(&self) -> &str {
        &self.vapid_public_key
    }

    /// Dispatches a web push notification to all subscriptions for a user.
    ///
    /// Subscriptions that return HTTP 410 (Gone) are automatically cleaned up.
    /// Errors for individual subscriptions are logged but do not prevent
    /// delivery to other subscriptions.
    pub async fn dispatch(
        &self,
        user_id: Uuid,
        message: &WebpushMessage,
    ) -> Result<(), WebpushError> {
        let subscriptions = self
            .store
            .get_webpush_subscriptions_by_user_id(user_id)
            .await?;

        if subscriptions.is_empty() {
            return Ok(());
        }

        let msg_json =
            serde_json::to_vec(message).map_err(|e| WebpushError::Serialization(e.to_string()))?;

        let mut stale_ids: Vec<Uuid> = Vec::new();

        for sub in &subscriptions {
            match self
                .send_single(
                    &msg_json,
                    &sub.endpoint,
                    &sub.endpoint_auth_key,
                    &sub.endpoint_p256dh_key,
                )
                .await
            {
                Ok(()) => {}
                Err(WebpushSendOutcome::Gone) => {
                    stale_ids.push(sub.id);
                }
                Err(WebpushSendOutcome::Failed(err)) => {
                    warn!(
                        endpoint = %sub.endpoint,
                        error = %err,
                        "web push send failed"
                    );
                }
            }
        }

        if !stale_ids.is_empty() {
            if let Err(err) = self.store.delete_webpush_subscriptions(&stale_ids).await {
                error!(error = %err, "failed to delete stale webpush subscriptions");
            }
        }

        Ok(())
    }

    /// Sends a test push notification to verify a subscription is valid.
    pub async fn test(&self, subscription: &WebpushSubscription) -> Result<(), WebpushError> {
        let test_msg = WebpushMessage {
            icon: String::new(),
            title: "Test".to_owned(),
            body: "This is a test Web Push notification".to_owned(),
            tag: String::new(),
            actions: Vec::new(),
            data: std::collections::HashMap::new(),
        };

        let msg_json = serde_json::to_vec(&test_msg)
            .map_err(|e| WebpushError::Serialization(e.to_string()))?;

        match self
            .send_single(
                &msg_json,
                &subscription.endpoint,
                &subscription.auth_key,
                &subscription.p256dh_key,
            )
            .await
        {
            Ok(()) => Ok(()),
            Err(WebpushSendOutcome::Gone) => Err(WebpushError::WebPush(
                "subscription is no longer valid (410 Gone)".to_owned(),
            )),
            Err(WebpushSendOutcome::Failed(err)) => Err(WebpushError::WebPush(err)),
        }
    }

    /// Sends a single web push message to one subscription endpoint.
    async fn send_single(
        &self,
        payload: &[u8],
        endpoint: &str,
        auth_key: &str,
        p256dh_key: &str,
    ) -> Result<(), WebpushSendOutcome> {
        let subscription_info = SubscriptionInfo::new(endpoint, p256dh_key, auth_key);

        // Build VAPID signature: load private key from PEM, attach subscription
        // info, add the subscriber contact ("sub" claim), then build.
        let partial = VapidSignatureBuilder::from_pem_no_sub(self.vapid_private_pem.as_bytes())
            .map_err(|e| WebpushSendOutcome::Failed(format!("VAPID key load: {e}")))?;
        let mut sig_builder = partial.add_sub_info(&subscription_info);
        sig_builder.add_claim("sub", self.vapid_sub.as_str());
        let sig = sig_builder
            .build()
            .map_err(|e| WebpushSendOutcome::Failed(format!("VAPID signature build: {e}")))?;

        let mut builder = WebPushMessageBuilder::new(&subscription_info);
        builder.set_vapid_signature(sig);
        builder.set_payload(ContentEncoding::Aes128Gcm, payload);

        let web_push_msg = builder
            .build()
            .map_err(|e| WebpushSendOutcome::Failed(format!("message build: {e}")))?;

        match self.client.send(web_push_msg).await {
            Ok(()) => Ok(()),
            Err(err) => {
                // Check if the subscription is gone (HTTP 410).
                let err_str = err.to_string();
                if err_str.contains("410") || err_str.to_lowercase().contains("gone") {
                    Err(WebpushSendOutcome::Gone)
                } else {
                    Err(WebpushSendOutcome::Failed(err_str))
                }
            }
        }
    }
}

/// Internal outcome for a single web push send attempt.
enum WebpushSendOutcome {
    /// The subscription has been removed by the push service (HTTP 410).
    Gone,
    /// A transport or protocol error occurred.
    Failed(String),
}

/// Generates a new VAPID key pair, stores it, and deletes all existing
/// subscriptions (which are invalid with the new keys).
///
/// Returns `(public_key_b64, private_key_pem)` where the public key is
/// base64url-no-pad encoded and the private key is PEM-encoded.
async fn regenerate_vapid_keys<S>(store: &S) -> Result<(String, String), WebpushError>
where
    S: AppStore + Send + Sync,
{
    // Generate a fresh EC P-256 private key in PEM format.
    let private_pem = generate_ec_p256_pem()
        .map_err(|e| WebpushError::WebPush(format!("key generation: {e}")))?;

    // Parse the PEM to extract the uncompressed public key bytes.
    let partial = VapidSignatureBuilder::from_pem_no_sub(private_pem.as_bytes())
        .map_err(|e| WebpushError::WebPush(format!("PEM parse: {e}")))?;

    let public_key_bytes = partial.get_public_key();
    let public_key_b64 = URL_SAFE_NO_PAD.encode(&public_key_bytes);

    // Delete all existing subscriptions (they're invalid with new keys)
    // then store the new keys.
    store.delete_all_webpush_subscriptions().await?;
    store
        .upsert_webpush_vapid_keys(&public_key_b64, &private_pem)
        .await?;

    info!("regenerated VAPID key pair for web push");
    Ok((public_key_b64, private_pem))
}

/// Generates a PEM-encoded EC P-256 private key using the openssl command.
fn generate_ec_p256_pem() -> Result<String, String> {
    let output = std::process::Command::new("openssl")
        .args(["ecparam", "-name", "prime256v1", "-genkey", "-noout"])
        .output()
        .map_err(|e| format!("failed to run openssl: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("openssl failed: {stderr}"));
    }

    String::from_utf8(output.stdout).map_err(|e| format!("invalid UTF-8 from openssl: {e}"))
}

/// A no-op web push dispatcher that always returns an error.
///
/// Used when web push is disabled or VAPID key generation failed.
pub struct NoopWebpusher {
    /// Reason why web push is disabled.
    msg: String,
}

impl NoopWebpusher {
    /// Creates a no-op dispatcher with the given reason message.
    pub fn new(msg: impl Into<String>) -> Self {
        Self { msg: msg.into() }
    }

    /// Returns the reason why web push is disabled.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.msg
    }

    /// Always returns the empty string (no VAPID key available).
    #[must_use]
    pub fn public_key(&self) -> &str {
        ""
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

    // ── 13. Multiple pending messages dispatched in order ────

    #[tokio::test]
    async fn dispatch_multiple_inbox_messages() {
        let msg1 = make_message(NotificationMethod::Inbox, "{}");
        let msg2 = make_message(NotificationMethod::Inbox, "{}");
        let id1 = msg1.id;
        let id2 = msg2.id;
        let store = MockStore::new().with_pending(vec![msg1, msg2]);
        let config = NotificationConfig::default();
        let service = NotificationDispatchService::new(store.clone(), config)
            .unwrap_or_else(|e| panic!("failed to create service: {e}"));

        let count = service
            .dispatch_once()
            .await
            .unwrap_or_else(|e| panic!("dispatch_once failed: {e}"));
        assert_eq!(count, 2);

        let updates = store
            .status_updates
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        assert_eq!(updates.len(), 2);
        // Both should be marked as Sent
        assert!(
            updates
                .iter()
                .all(|(_, s)| *s == NotificationMessageStatus::Sent)
        );
        // Both IDs should be present
        let ids: Vec<Uuid> = updates.iter().map(|(id, _)| *id).collect();
        assert!(ids.contains(&id1));
        assert!(ids.contains(&id2));
    }

    // ── 14. Dispatch config accessor reflects construction ───

    #[tokio::test]
    async fn service_config_reflects_custom_values() {
        let store = MockStore::new();
        let config = NotificationConfig {
            smtp_host: "custom.smtp.example.com".to_owned(),
            smtp_port: 2525,
            smtp_from: "sender@custom.com".to_owned(),
            webhook_timeout_secs: 5,
        };
        let service = NotificationDispatchService::new(store, config)
            .unwrap_or_else(|e| panic!("failed to create service: {e}"));
        assert_eq!(service.config().smtp_host, "custom.smtp.example.com");
        assert_eq!(service.config().smtp_port, 2525);
        assert_eq!(service.config().smtp_from, "sender@custom.com");
        assert_eq!(service.config().webhook_timeout_secs, 5);
    }

    // ── 15. NotificationDispatchError variants ──────────────

    #[test]
    fn dispatch_error_transport_variant() {
        let err = NotificationDispatchError::Transport("connection refused".to_owned());
        let msg = err.to_string();
        assert!(
            msg.contains("transport error"),
            "should contain error prefix"
        );
        assert!(msg.contains("connection refused"));
    }

    #[test]
    fn dispatch_error_config_missing_variant() {
        let err = NotificationDispatchError::ConfigMissing("smtp_host".to_owned());
        let msg = err.to_string();
        assert!(
            msg.contains("config missing"),
            "should contain error prefix"
        );
        assert!(msg.contains("smtp_host"));
    }

    // ── 16. Message status transitions ──────────────────────

    #[test]
    fn notification_message_status_equality() {
        assert_eq!(
            NotificationMessageStatus::Pending,
            NotificationMessageStatus::Pending
        );
        assert_ne!(
            NotificationMessageStatus::Pending,
            NotificationMessageStatus::Sent
        );
        assert_ne!(
            NotificationMessageStatus::Leased,
            NotificationMessageStatus::Failed
        );
    }

    // ── 17. Webhook with valid URL but still fails (no server) ─

    #[tokio::test]
    async fn dispatch_webhook_with_unreachable_url() {
        // targets_json has a URL but no server is listening.
        let msg = make_message(
            NotificationMethod::Webhook,
            r#"{"url":"http://127.0.0.1:1/nonexistent"}"#,
        );
        let msg_id = msg.id;
        let store = MockStore::new().with_pending(vec![msg]);
        let config = NotificationConfig {
            webhook_timeout_secs: 1,
            ..NotificationConfig::default()
        };
        let service = NotificationDispatchService::new(store.clone(), config)
            .unwrap_or_else(|e| panic!("failed to create service: {e}"));

        let count = service
            .dispatch_once()
            .await
            .unwrap_or_else(|e| panic!("dispatch_once failed: {e}"));
        assert_eq!(count, 1);

        // Should fail with temporary failure (connection refused).
        let updates = store
            .status_updates
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].0, msg_id);
        assert_eq!(updates[0].1, NotificationMessageStatus::TemporaryFailure);
    }

    // ── 18. Method clone and debug ──────────────────────────

    #[test]
    fn notification_method_clone_and_debug() {
        let method = NotificationMethod::Inbox;
        let cloned = method;
        assert_eq!(method, cloned);
        let debug = format!("{method:?}");
        assert!(debug.contains("Inbox"));
    }

    // ── 19. Config default values are sensible ──────────────

    #[test]
    fn notification_config_default_smtp_port_is_587() {
        let config = NotificationConfig::default();
        assert_eq!(config.smtp_port, 587, "default SMTP port should be 587");
    }

    #[test]
    fn notification_config_default_webhook_timeout_is_30() {
        let config = NotificationConfig::default();
        assert_eq!(
            config.webhook_timeout_secs, 30,
            "default webhook timeout should be 30s"
        );
    }

    // ── 20. WebpushError display messages ─────────────────────

    #[test]
    fn webpush_error_storage_variant() {
        let err = WebpushError::Storage(StorageError::unavailable("db down"));
        let msg = err.to_string();
        assert!(msg.contains("storage error"), "should contain prefix");
        assert!(msg.contains("db down"));
    }

    #[test]
    fn webpush_error_webpush_variant() {
        let err = WebpushError::WebPush("bad key".to_owned());
        let msg = err.to_string();
        assert!(msg.contains("web push error"), "should contain prefix");
        assert!(msg.contains("bad key"));
    }

    #[test]
    fn webpush_error_serialization_variant() {
        let err = WebpushError::Serialization("invalid json".to_owned());
        let msg = err.to_string();
        assert!(msg.contains("serialization error"), "should contain prefix");
        assert!(msg.contains("invalid json"));
    }

    // ── 21. NoopWebpusher behavior ────────────────────────────

    #[test]
    fn noop_webpusher_stores_message() {
        let noop = NoopWebpusher::new("web push disabled");
        assert_eq!(noop.message(), "web push disabled");
    }

    #[test]
    fn noop_webpusher_public_key_is_empty() {
        let noop = NoopWebpusher::new("no VAPID keys");
        assert!(
            noop.public_key().is_empty(),
            "noop should return empty public key"
        );
    }

    // ── 22. EC P-256 key generation ───────────────────────────

    #[test]
    fn generate_ec_p256_pem_produces_valid_key() {
        let pem = generate_ec_p256_pem();
        assert!(pem.is_ok(), "openssl should produce a PEM key");
        let pem_str = pem.unwrap_or_else(|e| panic!("unexpected error: {e}"));
        assert!(
            pem_str.contains("BEGIN EC PRIVATE KEY"),
            "PEM should contain EC header"
        );
        assert!(
            pem_str.contains("END EC PRIVATE KEY"),
            "PEM should contain EC footer"
        );
    }

    #[test]
    fn generate_ec_p256_pem_is_parseable_by_vapid_builder() {
        let pem = generate_ec_p256_pem().unwrap_or_else(|e| panic!("keygen: {e}"));
        let result = VapidSignatureBuilder::from_pem_no_sub(pem.as_bytes());
        assert!(
            result.is_ok(),
            "generated PEM should be parseable by web-push crate"
        );
    }

    #[test]
    fn generate_ec_p256_pem_produces_65_byte_public_key() {
        let pem = generate_ec_p256_pem().unwrap_or_else(|e| panic!("keygen: {e}"));
        let partial = VapidSignatureBuilder::from_pem_no_sub(pem.as_bytes())
            .unwrap_or_else(|e| panic!("PEM parse: {e}"));
        let pub_key = partial.get_public_key();
        // Uncompressed EC P-256 public key = 65 bytes (0x04 prefix + 32x + 32y)
        assert_eq!(
            pub_key.len(),
            65,
            "EC P-256 uncompressed public key should be 65 bytes"
        );
        assert_eq!(pub_key[0], 0x04, "uncompressed key should start with 0x04");
    }

    // ── 23. WebpushMessage serialization ──────────────────────

    #[test]
    fn webpush_message_serializes_to_json() {
        let msg = WebpushMessage {
            icon: "/icon.png".to_owned(),
            title: "Test Title".to_owned(),
            body: "Test Body".to_owned(),
            tag: "test-tag".to_owned(),
            actions: Vec::new(),
            data: std::collections::HashMap::new(),
        };
        let json = serde_json::to_string(&msg);
        assert!(json.is_ok(), "WebpushMessage should serialize");
        let json_str = json.unwrap_or_else(|e| panic!("serialize: {e}"));
        assert!(json_str.contains("Test Title"));
        assert!(json_str.contains("Test Body"));
        assert!(json_str.contains("/icon.png"));
    }

    #[test]
    fn webpush_message_round_trip() {
        let msg = WebpushMessage {
            icon: String::new(),
            title: "Hello".to_owned(),
            body: "World".to_owned(),
            tag: String::new(),
            actions: Vec::new(),
            data: std::collections::HashMap::new(),
        };
        let json = serde_json::to_vec(&msg).unwrap_or_else(|e| panic!("serialize: {e}"));
        let decoded: WebpushMessage =
            serde_json::from_slice(&json).unwrap_or_else(|e| panic!("deserialize: {e}"));
        assert_eq!(decoded.title, "Hello");
        assert_eq!(decoded.body, "World");
    }

    // ── 24. WebpushSendOutcome variants ───────────────────────

    #[test]
    fn webpush_send_outcome_gone_variant() {
        let outcome = WebpushSendOutcome::Gone;
        assert!(matches!(outcome, WebpushSendOutcome::Gone));
    }

    #[test]
    fn webpush_send_outcome_failed_variant() {
        let outcome = WebpushSendOutcome::Failed("timeout".to_owned());
        match outcome {
            WebpushSendOutcome::Failed(msg) => assert_eq!(msg, "timeout"),
            WebpushSendOutcome::Gone => panic!("expected Failed variant"),
        }
    }

    // ── 25. VAPID public key base64url encoding ───────────────

    #[test]
    fn vapid_public_key_base64url_encoding() {
        let pem = generate_ec_p256_pem().unwrap_or_else(|e| panic!("keygen: {e}"));
        let partial = VapidSignatureBuilder::from_pem_no_sub(pem.as_bytes())
            .unwrap_or_else(|e| panic!("PEM parse: {e}"));
        let pub_key = partial.get_public_key();
        let encoded = URL_SAFE_NO_PAD.encode(&pub_key);
        // Base64url encoding of 65 bytes = 87 chars (no padding)
        assert_eq!(
            encoded.len(),
            87,
            "base64url of 65 bytes should be 87 chars"
        );
        // Should not contain '+', '/', or '=' (standard base64 chars)
        assert!(!encoded.contains('+'), "should use URL-safe encoding");
        assert!(!encoded.contains('/'), "should use URL-safe encoding");
        assert!(!encoded.contains('='), "should have no padding");
    }
}
