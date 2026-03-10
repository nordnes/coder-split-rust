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
            .fetch_pending_notification_messages(DISPATCH_BATCH_SIZE, MAX_DISPATCH_ATTEMPTS)
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
                // Increment the attempt count so the MAX_DISPATCH_ATTEMPTS
                // check above will eventually move the message to Failed.
                let _ = self
                    .store
                    .increment_notification_message_attempt_count(message.id)
                    .await;
                NotificationMessageStatus::Pending
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
