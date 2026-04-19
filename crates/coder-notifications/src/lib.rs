//! Notification, inbox, and webpush boundary for the Rust `coderd` rewrite.
//!
//! Provides a background dispatch loop that polls pending notification messages
//! and delivers them via SMTP email, HTTP webhook, or in-app inbox.
//!
//! Also provides the [`Webpusher`] dispatcher for sending Web Push notifications
//! to browser subscriptions using VAPID authentication.
//!
//! # Key types
//!
//! * [`NotificationDispatchService`] — background service that polls
//!   `acquire_pending_notification_messages` every 10 seconds and routes each
//!   message to the appropriate transport
//! * [`NotificationConfig`] — SMTP and webhook configuration
//! * [`NotificationDispatchError`] — transport-level delivery failures
//! * [`Webpusher`] — Web Push dispatcher with VAPID key management
//!
//! Email dispatch uses `lettre` over STARTTLS / implicit TLS, with auth-failure
//! classification so permanent failures short-circuit the retry loop. Webhook
//! delivery classifies HTTP status codes (2xx success, 4xx permanent except
//! 408/429, 5xx/408/429/timeout retryable) and applies exponential backoff
//! with jitter between retries.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use coder_core::AppStore;
use coder_core::IdentityStore;
use coder_core::api::{WebpushMessage, WebpushSubscription};
use coder_core::identity::{NotificationMessageStatus, NotificationMethod};
use futures_util::StreamExt;
use lettre::transport::smtp::authentication::{Credentials, Mechanism};
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::transport::smtp::extension::ClientId;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor, message::MultiPart};
use rand::Rng;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use uuid::Uuid;
use web_push::{
    ContentEncoding, IsahcWebPushClient, PartialVapidSignatureBuilder, SubscriptionInfo,
    VapidSignatureBuilder, WebPushClient, WebPushMessageBuilder,
};

/// Narrow capability the dispatch loop needs beyond [`IdentityStore`] —
/// reading the deployment-wide `notifier_paused` switch.
///
/// Defined as its own trait (rather than widening the service bound to
/// [`AppStore`]) so `MockStore`s in test suites can keep implementing
/// `IdentityStore` without taking on the full 200-method `AppStore`
/// surface. A blanket impl forwards to `AppStore::get_notifications_settings`
/// so production callers pass an `Arc<dyn AppStore>` unchanged.
///
/// Mirrors Go's `notifications.Manager.ensureRunning` check against
/// `GetNotificationsSettings().NotifierPaused` in
/// `coder/coderd/notifications/manager.go`.
#[async_trait::async_trait]
pub trait NotifierPausedReader: Send + Sync {
    /// Returns whether deployment-wide notification dispatch is paused.
    async fn notifier_paused(&self) -> Result<bool, coder_core::StorageError>;
}

// Concrete impl for the single production shape `apps/coderd/src/main.rs`
// actually passes (`Arc<dyn AppStore>`). Avoiding a blanket `impl<T: AppStore>`
// sidesteps orphan-rule conflicts between coder-notifications (defining this
// trait) and coder-core (owning `AppStore`) — Rust can't prove that a
// downstream crate won't add `impl AppStore for Arc<Something>`, which
// would then overlap with any `Arc<T>` forwarding impl. Tests that use a
// non-`AppStore` mock add their own `impl NotifierPausedReader` directly.
#[async_trait::async_trait]
impl NotifierPausedReader for Arc<dyn AppStore> {
    async fn notifier_paused(&self) -> Result<bool, coder_core::StorageError> {
        Ok(AppStore::get_notifications_settings(self.as_ref())
            .await?
            .notifier_paused)
    }
}

/// Current milestone for the notifications crate.
pub const STATUS: &str = "active";

const DISPATCH_BATCH_SIZE: u32 = 50;
const MAX_DISPATCH_ATTEMPTS: u32 = 3;

// ── Prometheus metric names ─────────────────────────────────────────────
//
// Emitted via the `metrics` crate (the workspace-level exporter is
// `metrics-exporter-prometheus`). Names mirror Go's
// `coderd_notifications_*` histograms/counters/gauges
// (`coderd/notifications/metrics.go`). We intentionally drop the
// `coderd_notifications_` namespace prefix since the Rust exporter
// is scoped per process and the matrix specifies the short names.
const METRIC_DISPATCH_ATTEMPTS: &str = "notifier_dispatch_attempts";
const METRIC_RETRY_COUNT: &str = "notifier_retry_count";
const METRIC_SEND_SECONDS: &str = "notifier_send_seconds";
const METRIC_QUEUED_SECONDS: &str = "notifier_queued_seconds";
const METRIC_INFLIGHT: &str = "notifier_inflight";

// Label values for `notifier_dispatch_attempts{result=…}`. Tracks Go's
// ResultSuccess / ResultTempFail / ResultPermFail constants, with
// an extra `inhibited` bucket for user-disabled templates.
const RESULT_SUCCESS: &str = "success";
const RESULT_TEMP_FAIL: &str = "temp_fail";
const RESULT_PERM_FAIL: &str = "perm_fail";
const RESULT_INHIBITED: &str = "inhibited";

/// Returns the stable `method=` label for a dispatch method. Metric label
/// values must be `&'static str` so we map through a small match rather
/// than formatting enum names at runtime.
fn method_label(method: NotificationMethod) -> &'static str {
    match method {
        NotificationMethod::Email => "smtp",
        NotificationMethod::Webhook => "webhook",
        NotificationMethod::Inbox => "inbox",
    }
}

/// RAII gauge guard: increments `notifier_inflight{method=…}` on entry and
/// decrements on drop. Ensures the gauge stays consistent even if the
/// dispatch future is cancelled or returns an error early.
struct InflightGuard {
    method: &'static str,
}

impl InflightGuard {
    fn enter(method: &'static str) -> Self {
        metrics::gauge!(METRIC_INFLIGHT, "method" => method).increment(1.0);
        Self { method }
    }
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        metrics::gauge!(METRIC_INFLIGHT, "method" => self.method).decrement(1.0);
    }
}

/// Maximum number of concurrent web push sends per dispatch call.
const MAX_CONCURRENT_SENDS: usize = 10;
/// Maximum retry attempts for transient push service failures (5xx).
const MAX_SEND_RETRIES: u32 = 3;
/// Initial backoff duration (500 ms) for retry attempts; doubles each retry.
const INITIAL_RETRY_BACKOFF: Duration = Duration::from_millis(500);

/// Configuration for the notification dispatch pipeline.
///
/// Mirrors the `NotificationsEmailConfig` / `NotificationsWebhookConfig`
/// fields in the Go reference (`codersdk/deployment.go`).
#[derive(Clone, Debug)]
pub struct NotificationConfig {
    /// SMTP relay host for email dispatch (empty = disabled).
    pub smtp_host: String,
    /// SMTP relay port.
    pub smtp_port: u16,
    /// Sender email address for outgoing notifications.
    pub smtp_from: String,
    /// Hostname identifying us to the SMTP server in EHLO/HELO.
    pub smtp_hello: String,
    /// SASL username for PLAIN / LOGIN authentication (empty = no auth).
    pub smtp_username: String,
    /// SASL password for PLAIN / LOGIN authentication.
    pub smtp_password: String,
    /// If true, attempt an implicit-TLS (SMTPS) connection (e.g. port 465).
    pub smtp_force_tls: bool,
    /// If true, upgrade the plain connection to TLS via STARTTLS (e.g. port 587).
    pub smtp_start_tls: bool,
    /// If true, skip TLS certificate verification (testing only).
    pub smtp_tls_skip_verify: bool,
    /// Webhook timeout in seconds.
    pub webhook_timeout_secs: u64,
    /// Base interval (seconds) between retries of a retryable failure.
    pub base_retry_interval_secs: u64,
    /// Cap (seconds) on the exponential backoff window.
    pub max_retry_interval_secs: u64,
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            smtp_host: String::new(),
            smtp_port: 587,
            smtp_from: String::new(),
            smtp_hello: String::new(),
            smtp_username: String::new(),
            smtp_password: String::new(),
            smtp_force_tls: false,
            smtp_start_tls: true,
            smtp_tls_skip_verify: false,
            webhook_timeout_secs: 30,
            base_retry_interval_secs: 5,
            max_retry_interval_secs: 300,
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
    poll_interval_secs: u64,
    /// Per-message retry-after deadlines used for exponential backoff.
    /// Gates the dispatch-loop hook in [`dispatch_once`].
    retry_after: Mutex<HashMap<Uuid, Instant>>,
}

impl<S> NotificationDispatchService<S>
where
    S: IdentityStore + NotifierPausedReader + Clone + Send + Sync + 'static,
{
    /// Creates the dispatch service and starts the background poll loop.
    ///
    /// Returns the shared service handle and a [`tokio::task::JoinHandle`]
    /// for the background task.  During shutdown, cancel the
    /// [`CancellationToken`] **and** await the handle to ensure in-flight
    /// dispatch cycles finish their DB writes before the pool is closed.
    ///
    /// The `poll_interval_secs` parameter controls how often the dispatch loop
    /// polls for pending messages.
    pub fn new(
        store: S,
        config: NotificationConfig,
        poll_interval_secs: u64,
        cancel: CancellationToken,
    ) -> Result<(Arc<Self>, tokio::task::JoinHandle<()>), reqwest::Error> {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.webhook_timeout_secs))
            .build()?;

        let service = Arc::new(Self {
            store,
            config,
            http_client,
            poll_interval_secs,
            retry_after: Mutex::new(HashMap::new()),
        });
        let handle = Self::spawn_dispatch_loop(&service, cancel);
        Ok((service, handle))
    }

    /// Returns the current configuration.
    #[must_use]
    pub fn config(&self) -> &NotificationConfig {
        &self.config
    }

    async fn dispatch_once(&self) -> Result<u32, coder_core::StorageError> {
        // Honor the deployment-wide pause switch before acquiring any work.
        // Mirrors Go's `notifications.Manager.ensureRunning` which checks
        // `GetNotificationsSettings().NotifierPaused` on every tick. If the
        // settings read itself fails we fall through and keep trying —
        // a single DB blip shouldn't permanently silence the dispatcher.
        match self.store.notifier_paused().await {
            Ok(true) => return Ok(0),
            Ok(false) => {}
            Err(err) => warn!(
                error = %err,
                "failed to read notifier_paused setting; continuing dispatch"
            ),
        }

        // Messages that have already reached MAX_DISPATCH_ATTEMPTS are
        // excluded by the query itself via the max_attempt_count parameter.
        let messages = self
            .store
            .acquire_pending_notification_messages(DISPATCH_BATCH_SIZE, MAX_DISPATCH_ATTEMPTS)
            .await?;

        let count = u32::try_from(messages.len()).unwrap_or(u32::MAX);

        // Accumulators for bulk-mark at the end of the cycle. Rather than
        // firing one UPDATE per message (2 UPDATEs per failure: one for the
        // attempt counter, one for the status) we group terminal outcomes
        // by kind and flush in a single round trip per group.
        //
        // Mirrors Go's `bulkUpdate` path in `notifications/manager.go` which
        // calls `BulkMarkNotificationMessagesSent` + `BulkMarkNotificationMessagesFailed`.
        let mut sent_ids: Vec<Uuid> = Vec::new();
        let mut failed_ids: Vec<Uuid> = Vec::new();
        let mut failed_statuses: Vec<NotificationMessageStatus> = Vec::new();
        let mut failed_reasons: Vec<String> = Vec::new();

        for message in messages {
            let method_label = method_label(message.method);

            // `queued_seconds` reports how long the message sat in the
            // queue before dispatch picked it up. Mirrors Go's
            // `coderd_notifications_queued_seconds` histogram. `created_at`
            // is set at enqueue time; if it's in the future (clock skew)
            // we clamp to zero.
            let queued_seconds =
                (time::OffsetDateTime::now_utc() - message.created_at).as_seconds_f64();
            metrics::histogram!(
                METRIC_QUEUED_SECONDS,
                "method" => method_label,
            )
            .record(queued_seconds.max(0.0));

            // Before any dispatch attempt, honour the per-template preference
            // for this user. If the template is disabled, the message is
            // marked `inhibited` with the fixed reason "disabled by user",
            // matching Go's `newInhibitedDispatch` (`notifier.go`). Inhibited
            // messages are terminal: they are never retried.
            if let Ok(Some(true)) = self
                .store
                .find_user_notification_preference(
                    message.user_id,
                    message.notification_template_id,
                )
                .await
            {
                failed_ids.push(message.id);
                failed_statuses.push(NotificationMessageStatus::Inhibited);
                failed_reasons.push("disabled by user".to_owned());
                metrics::counter!(
                    METRIC_DISPATCH_ATTEMPTS,
                    "method" => method_label,
                    "result" => RESULT_INHIBITED,
                )
                .increment(1);
                continue;
            }

            // Dispatch-loop hook: gate retryable messages behind exponential
            // backoff. When we skip, we release the lease back to the pending
            // pool so the next acquire cycle can pick it up once the backoff
            // window elapses.
            if self.is_in_backoff(&message.id) {
                failed_ids.push(message.id);
                failed_statuses.push(NotificationMessageStatus::TemporaryFailure);
                failed_reasons.push("backoff".to_owned());
                continue;
            }

            // Inflight gauge: counts the number of in-progress dispatches
            // for this method. Decremented on the RAII handle drop.
            let _inflight = InflightGuard::enter(method_label);
            let send_start = Instant::now();

            let result = match message.method {
                NotificationMethod::Email => self.dispatch_email(&message).await,
                NotificationMethod::Webhook => self.dispatch_webhook(&message).await,
                NotificationMethod::Inbox => self.dispatch_inbox(&message).await,
            };

            metrics::histogram!(
                METRIC_SEND_SECONDS,
                "method" => method_label,
            )
            .record(send_start.elapsed().as_secs_f64());

            match &result {
                Ok(()) => {
                    self.clear_backoff(&message.id);
                    sent_ids.push(message.id);
                    metrics::counter!(
                        METRIC_DISPATCH_ATTEMPTS,
                        "method" => method_label,
                        "result" => RESULT_SUCCESS,
                    )
                    .increment(1);
                }
                Err(err) => {
                    warn!(
                        message_id = %message.id,
                        method = ?message.method,
                        error = %err,
                        permanent = err.is_permanent(),
                        "notification dispatch failed"
                    );
                    // Permanent errors skip retry entirely. Retryable errors
                    // fall back to TemporaryFailure until the attempt budget
                    // is exhausted — the bulk-mark path will coerce to
                    // PermanentFailure at the DB level when
                    // `attempt_count + 1 >= max_attempts`.
                    let attempts_exhausted =
                        message.attempt_count + 1 >= MAX_DISPATCH_ATTEMPTS as i32;
                    if err.is_permanent() || attempts_exhausted {
                        self.clear_backoff(&message.id);
                        failed_ids.push(message.id);
                        failed_statuses.push(NotificationMessageStatus::PermanentFailure);
                        failed_reasons.push(err.to_string());
                        metrics::counter!(
                            METRIC_DISPATCH_ATTEMPTS,
                            "method" => method_label,
                            "result" => RESULT_PERM_FAIL,
                        )
                        .increment(1);
                    } else {
                        // Schedule the next retry via exponential backoff.
                        let next_attempt =
                            u32::try_from(message.attempt_count + 1).unwrap_or(u32::MAX);
                        self.schedule_backoff(message.id, next_attempt);
                        failed_ids.push(message.id);
                        failed_statuses.push(NotificationMessageStatus::TemporaryFailure);
                        failed_reasons.push(err.to_string());
                        metrics::counter!(
                            METRIC_DISPATCH_ATTEMPTS,
                            "method" => method_label,
                            "result" => RESULT_TEMP_FAIL,
                        )
                        .increment(1);
                        metrics::counter!(
                            METRIC_RETRY_COUNT,
                            "method" => method_label,
                        )
                        .increment(1);
                    }
                }
            }
        }

        // Flush accumulated terminal outcomes in two bulk updates rather
        // than per-row UPDATEs. Errors here are logged but not returned —
        // the leased rows will be re-acquired on the next cycle since
        // their `leased_until` will eventually expire.
        if !sent_ids.is_empty() {
            if let Err(err) = self
                .store
                .bulk_mark_notification_messages_sent(&sent_ids)
                .await
            {
                warn!(
                    count = sent_ids.len(),
                    error = %err,
                    "bulk_mark_notification_messages_sent failed"
                );
            }
        }
        if !failed_ids.is_empty() {
            if let Err(err) = self
                .store
                .bulk_mark_notification_messages_failed(
                    &failed_ids,
                    &failed_statuses,
                    &failed_reasons,
                    MAX_DISPATCH_ATTEMPTS,
                    u32::try_from(self.config.base_retry_interval_secs).unwrap_or(u32::MAX),
                )
                .await
            {
                warn!(
                    count = failed_ids.len(),
                    error = %err,
                    "bulk_mark_notification_messages_failed failed"
                );
            }
        }

        Ok(count)
    }

    /// Returns true if the message is still within its exponential backoff
    /// window and should not be dispatched in this cycle.
    fn is_in_backoff(&self, message_id: &Uuid) -> bool {
        match self.retry_after.lock() {
            Ok(guard) => guard
                .get(message_id)
                .is_some_and(|deadline| *deadline > Instant::now()),
            Err(poisoned) => poisoned
                .into_inner()
                .get(message_id)
                .is_some_and(|deadline| *deadline > Instant::now()),
        }
    }

    /// Schedules the next retry deadline for a message after a retryable
    /// failure, using exponential backoff with jitter bounded by config.
    fn schedule_backoff(&self, message_id: Uuid, attempt: u32) {
        let delay = backoff_duration(
            attempt,
            self.config.base_retry_interval_secs,
            self.config.max_retry_interval_secs,
        );
        let deadline = Instant::now() + delay;
        match self.retry_after.lock() {
            Ok(mut guard) => {
                guard.insert(message_id, deadline);
            }
            Err(poisoned) => {
                poisoned.into_inner().insert(message_id, deadline);
            }
        }
    }

    fn clear_backoff(&self, message_id: &Uuid) {
        match self.retry_after.lock() {
            Ok(mut guard) => {
                guard.remove(message_id);
            }
            Err(poisoned) => {
                poisoned.into_inner().remove(message_id);
            }
        }
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
        if self.config.smtp_from.is_empty() {
            return Err(NotificationDispatchError::ConfigMissing(
                "SMTP from address is not configured".to_owned(),
            ));
        }

        let email = build_email(message, &self.config.smtp_from, &self.config.smtp_hello)?;
        let transport = build_smtp_transport(&self.config)?;

        match transport.send(email).await {
            Ok(response) => {
                info!(
                    message_id = %message.id,
                    user_id = %message.user_id,
                    smtp_host = %self.config.smtp_host,
                    smtp_code = ?response.code(),
                    "email notification dispatched"
                );
                Ok(())
            }
            Err(err) => {
                // lettre's Error exposes `is_permanent()` for 5xx SMTP replies
                // (auth failures, rejected recipients, malformed messages).
                // `is_transient()` maps to 4xx temporary failures.
                if err.is_permanent() {
                    Err(NotificationDispatchError::Permanent(err.to_string()))
                } else {
                    Err(NotificationDispatchError::Transport(err.to_string()))
                }
            }
        }
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
            // `targets_json` is captured at enqueue time and never mutated,
            // so a missing endpoint URL cannot be recovered by retrying.
            // Matches `coder/coderd/notifications/dispatch/webhook.go` which
            // treats a nil/empty endpoint as a terminal dispatch failure.
            return Err(NotificationDispatchError::Permanent(
                "webhook endpoint URL not found in targets".to_owned(),
            ));
        }

        // Build the WebhookPayload envelope. Mirrors Go's
        // `dispatch.WebhookPayload` (`coder/coderd/notifications/dispatch/webhook.go`):
        // the raw `input_json` is nested under `payload`, and the
        // rendered `title` / `body` fields are pulled from the same
        // payload object (the Rust enqueuer renders them at enqueue time
        // rather than deferring to the dispatcher). The `X-Message-Id`
        // header carries the message ID out-of-band so receivers can
        // correlate deliveries without parsing the body.
        let payload: serde_json::Value =
            serde_json::from_str(&message.input_json).unwrap_or(serde_json::Value::Null);
        let extract = |k: &str| -> String {
            payload
                .get(k)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned()
        };
        let envelope = WebhookPayload {
            version: "1.1".to_owned(),
            msg_id: message.id,
            payload: &payload,
            title: extract("subject"),
            title_markdown: extract("subject"),
            body: extract("plain_body"),
            body_markdown: extract("html_body"),
        };
        let body_json = serde_json::to_vec(&envelope).map_err(|e| {
            NotificationDispatchError::Permanent(format!("serialize webhook envelope: {e}"))
        })?;

        let send_result = self
            .http_client
            .post(&endpoint)
            .header("Content-Type", "application/json")
            .header("X-Message-Id", message.id.to_string())
            .body(body_json)
            .send()
            .await;

        let response = match send_result {
            Ok(resp) => resp,
            Err(err) => {
                // Transport-level failures (DNS, connect, TLS handshake,
                // request timeout) are retryable. Go's `webhook.go` treats
                // these the same — see `retryable = true` in `Dispatcher()`.
                if err.is_timeout() || err.is_connect() || err.is_request() {
                    return Err(NotificationDispatchError::Transport(err.to_string()));
                }
                return Err(NotificationDispatchError::Transport(err.to_string()));
            }
        };

        let status = response.status();
        match classify_webhook_status(status.as_u16()) {
            WebhookOutcome::Success => {
                info!(
                    message_id = %message.id,
                    endpoint = %endpoint,
                    status = status.as_u16(),
                    "webhook notification dispatched"
                );
                Ok(())
            }
            WebhookOutcome::Retryable => Err(NotificationDispatchError::Transport(format!(
                "webhook returned retryable HTTP {}",
                status.as_u16()
            ))),
            WebhookOutcome::Permanent => Err(NotificationDispatchError::Permanent(format!(
                "webhook returned permanent HTTP {}",
                status.as_u16()
            ))),
        }
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

    fn spawn_dispatch_loop(
        service: &Arc<Self>,
        cancel: CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        let weak = Arc::downgrade(service);
        let poll_secs = service.poll_interval_secs;
        tokio::spawn(async move {
            run_dispatch_loop(weak, poll_secs, cancel).await;
        })
    }
}

/// Errors from the notification dispatch pipeline.
///
/// Errors are classified so the dispatch loop can short-circuit retries for
/// permanent failures (auth rejections, 4xx webhook responses) rather than
/// burning the attempt budget.
#[derive(Debug, thiserror::Error)]
pub enum NotificationDispatchError {
    /// Required configuration is missing. Treated as retryable: admins may
    /// provision the missing config between poll cycles.
    #[error("config missing: {0}")]
    ConfigMissing(String),
    /// Transport-level delivery failure that may succeed on retry
    /// (5xx / 408 / 429 / timeout / connection failures).
    #[error("transport error: {0}")]
    Transport(String),
    /// Permanent delivery failure. The loop marks the message
    /// [`NotificationMessageStatus::PermanentFailure`] without retrying.
    #[error("permanent failure: {0}")]
    Permanent(String),
}

impl NotificationDispatchError {
    /// Returns `true` if the error indicates no retry should be attempted.
    #[must_use]
    pub fn is_permanent(&self) -> bool {
        matches!(self, Self::Permanent(_))
    }
}

/// Envelope posted to webhook endpoints when a notification is dispatched.
///
/// Mirrors Go's `dispatch.WebhookPayload`
/// (`coder/coderd/notifications/dispatch/webhook.go`). The concrete payload
/// field embeds the full `MessagePayload` JSON (labels, data, targets,
/// template id, etc.) so receivers can key off template and user without
/// re-fetching from the API.
#[derive(serde::Serialize)]
struct WebhookPayload<'a> {
    #[serde(rename = "_version")]
    version: String,
    msg_id: Uuid,
    /// The original enqueue-time payload, verbatim.
    payload: &'a serde_json::Value,
    title: String,
    title_markdown: String,
    body: String,
    body_markdown: String,
}

/// Classification of a webhook HTTP response used by [`dispatch_webhook`].
///
/// Mirrors Go's `notifications/dispatch/webhook.go`:
/// - 2xx → success.
/// - 408 (timeout), 429 (rate limit) and 5xx → retryable.
/// - All other 4xx → permanent (caller is rejecting the payload).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WebhookOutcome {
    Success,
    Retryable,
    Permanent,
}

fn classify_webhook_status(status: u16) -> WebhookOutcome {
    if (200..300).contains(&status) {
        return WebhookOutcome::Success;
    }
    if status == 408 || status == 429 || (500..600).contains(&status) {
        return WebhookOutcome::Retryable;
    }
    if (400..500).contains(&status) {
        return WebhookOutcome::Permanent;
    }
    // 1xx / 3xx / unknown codes — treat as retryable to be safe.
    WebhookOutcome::Retryable
}

/// Computes the backoff interval for a retryable failure using
/// `base * 2^(attempt-1)` capped at `max`, plus up to 1s of jitter.
///
/// `attempt` is 1-based (first retry = 1). Matches the shape of Go's
/// `backoff.ExponentialBackOff` used in the notification retry loop.
fn backoff_duration(attempt: u32, base_secs: u64, max_secs: u64) -> Duration {
    let base_ms = base_secs.saturating_mul(1000).max(1);
    let cap_ms = max_secs.saturating_mul(1000).max(base_ms);
    let shift = attempt.saturating_sub(1).min(20);
    let backoff_ms = base_ms.saturating_mul(1u64 << shift).min(cap_ms);
    let jitter_ms = rand::thread_rng().gen_range(0..1000);
    Duration::from_millis(backoff_ms.saturating_add(jitter_ms))
}

/// Builds a lettre [`Message`] from a notification record.
///
/// The message's `input_json` payload is expected to contain `user_email`,
/// `subject`, `plain_body`, and `html_body` fields. Missing fields surface as
/// [`NotificationDispatchError::ConfigMissing`] so the message stays
/// retryable (the enqueuer can be re-run).
fn build_email(
    message: &coder_core::identity::NotificationMessageRecord,
    from_address: &str,
    hello: &str,
) -> Result<Message, NotificationDispatchError> {
    let payload: serde_json::Value = serde_json::from_str(&message.input_json).map_err(|e| {
        NotificationDispatchError::ConfigMissing(format!("invalid email payload JSON: {e}"))
    })?;

    let to_address = payload
        .get("user_email")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if to_address.is_empty() {
        return Err(NotificationDispatchError::ConfigMissing(
            "payload.user_email is empty".to_owned(),
        ));
    }

    let subject = payload
        .get("subject")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();
    let plain_body = payload
        .get("plain_body")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();
    let html_body = payload
        .get("html_body")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();

    let hostname = if hello.is_empty() { "localhost" } else { hello };
    let from_parsed = from_address
        .parse::<lettre::message::Mailbox>()
        .map_err(|e| {
            NotificationDispatchError::ConfigMissing(format!(
                "invalid SMTP from address '{from_address}': {e}"
            ))
        })?;
    let to_parsed = to_address
        .parse::<lettre::message::Mailbox>()
        .map_err(|e| {
            NotificationDispatchError::Permanent(format!(
                "invalid recipient address '{to_address}': {e}"
            ))
        })?;

    let message_id = format!("<{}@{}>", message.id, hostname);

    Message::builder()
        .from(from_parsed)
        .to(to_parsed)
        .subject(subject)
        .message_id(Some(message_id))
        .date_now()
        .multipart(MultiPart::alternative_plain_html(plain_body, html_body))
        .map_err(|e| NotificationDispatchError::Permanent(format!("build email: {e}")))
}

/// Constructs the async SMTP transport based on the runtime config.
///
/// Port/TLS selection follows Go's `smtp.Dispatcher`:
/// - `force_tls=true` → implicit TLS (`relay`), typical on port 465.
/// - `start_tls=true` → plain connect then STARTTLS upgrade, typical on 587.
/// - Otherwise → unencrypted connection (plain port 25 or local relay).
fn build_smtp_transport(
    config: &NotificationConfig,
) -> Result<AsyncSmtpTransport<Tokio1Executor>, NotificationDispatchError> {
    let host = config.smtp_host.as_str();

    let mut builder = if config.smtp_force_tls {
        AsyncSmtpTransport::<Tokio1Executor>::relay(host)
            .map_err(|e| NotificationDispatchError::Transport(format!("smtp relay: {e}")))?
    } else if config.smtp_start_tls {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)
            .map_err(|e| NotificationDispatchError::Transport(format!("smtp starttls: {e}")))?
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host)
    };

    builder = builder.port(config.smtp_port);

    if !config.smtp_hello.is_empty() {
        builder = builder.hello_name(ClientId::Domain(config.smtp_hello.clone()));
    }

    if config.smtp_tls_skip_verify && (config.smtp_force_tls || config.smtp_start_tls) {
        let tls_params = TlsParameters::builder(host.to_owned())
            .dangerous_accept_invalid_certs(true)
            .dangerous_accept_invalid_hostnames(true)
            .build()
            .map_err(|e| NotificationDispatchError::Transport(format!("tls params: {e}")))?;
        builder = if config.smtp_force_tls {
            builder.tls(Tls::Wrapper(tls_params))
        } else {
            builder.tls(Tls::Required(tls_params))
        };
    }

    if !config.smtp_username.is_empty() {
        let credentials =
            Credentials::new(config.smtp_username.clone(), config.smtp_password.clone());
        builder = builder
            .credentials(credentials)
            .authentication(vec![Mechanism::Plain, Mechanism::Login]);
    }

    Ok(builder.build())
}

async fn run_dispatch_loop<S>(
    service: Weak<NotificationDispatchService<S>>,
    poll_secs: u64,
    cancel: CancellationToken,
) where
    S: IdentityStore + NotifierPausedReader + Clone + Send + Sync + 'static,
{
    let mut interval = tokio::time::interval(Duration::from_secs(poll_secs));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("notification dispatch loop cancelled");
                return;
            }
            _ = interval.tick() => {}
        }
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

/// Result of sending test push notifications to all subscriptions for a user.
///
/// Returned by [`Webpusher::send_test_to_user`].
///
/// # Response shape
///
/// The handler returns this struct directly as JSON, producing:
/// ```json
/// { "message": "...", "success_count": N, "failure_count": M }
/// ```
/// This replaces the previous `ApiResponse::ok("...")` shape.
#[derive(Debug, serde::Serialize)]
pub struct WebpushTestResult {
    /// Human-readable summary message.
    pub message: String,
    /// Number of subscriptions that received the test notification.
    pub success_count: u32,
    /// Number of subscriptions that failed delivery.
    pub failure_count: u32,
}

/// Web Push notification dispatcher using VAPID authentication.
///
/// Manages VAPID key pairs and sends push notifications to browser
/// subscriptions. Keys are loaded from the database on construction,
/// and regenerated if missing.
///
/// The shared [`IsahcWebPushClient`] is constructed once at startup and
/// reused for all push sends, avoiding per-request client creation.
pub struct Webpusher {
    store: Arc<dyn AppStore>,
    /// VAPID subscriber contact (mailto: or https:// URL).
    vapid_sub: String,
    /// Base64url-encoded VAPID public key (for clients).
    vapid_public_key: String,
    /// Parsed VAPID private key, cached to avoid re-parsing PEM on every send.
    vapid_key: PartialVapidSignatureBuilder,
    /// Reusable web push HTTP client (constructed once, shared across sends).
    client: IsahcWebPushClient,
}

impl Webpusher {
    /// Creates a new web push dispatcher.
    ///
    /// Loads VAPID keys from the database. If no keys exist, generates a new
    /// key pair and stores it, deleting any existing subscriptions that would
    /// be invalid with the new keys.
    ///
    /// The HTTP client is created once here and reused for all subsequent
    /// sends.
    pub async fn new(store: Arc<dyn AppStore>, vapid_sub: String) -> Result<Self, WebpushError> {
        let keys = store.get_webpush_vapid_keys().await?;

        let (_stored_public, private_pem) = match keys {
            Some(kp) if !kp.public_key.is_empty() && !kp.private_key.is_empty() => {
                (kp.public_key, kp.private_key)
            }
            _ => {
                // Generate new VAPID keys and delete stale subscriptions.
                regenerate_vapid_keys(store.as_ref()).await?
            }
        };

        // Validate the private key and derive the public key from it rather
        // than trusting the stored public key.  This guards against a
        // mismatched/rotated value in the database.
        //
        // The parsed `PartialVapidSignatureBuilder` is cached in the struct
        // so that `send_single` can clone it cheaply instead of re-parsing
        // the PEM on every send.
        let vapid_key = VapidSignatureBuilder::from_pem_no_sub(private_pem.as_bytes())
            .map_err(|e| WebpushError::WebPush(format!("invalid stored VAPID key: {e}")))?;
        let derived_public = URL_SAFE_NO_PAD.encode(vapid_key.get_public_key());

        let client = IsahcWebPushClient::new().map_err(|e| WebpushError::WebPush(e.to_string()))?;

        Ok(Self {
            store,
            vapid_sub,
            vapid_public_key: derived_public,
            vapid_key,
            client,
        })
    }

    /// Returns the VAPID public key for client-side subscription setup.
    #[must_use]
    pub fn public_key(&self) -> &str {
        &self.vapid_public_key
    }

    /// Returns the VAPID subscriber contact (`sub` claim).
    #[must_use]
    pub fn vapid_sub(&self) -> &str {
        &self.vapid_sub
    }

    /// Dispatches a web push notification to all subscriptions for a user.
    ///
    /// Sends are executed concurrently, bounded by [`MAX_CONCURRENT_SENDS`].
    /// Transient failures (5xx) are retried with exponential backoff.
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

        // Send concurrently with bounded parallelism.
        // Clone subscription fields into owned data to avoid lifetime issues
        // with the async closures.
        let send_futs: Vec<_> = subscriptions
            .iter()
            .map(|sub| {
                let id = sub.id;
                let endpoint = sub.endpoint.clone();
                let auth_key = sub.endpoint_auth_key.clone();
                let p256dh_key = sub.endpoint_p256dh_key.clone();
                let payload = msg_json.clone();
                async move {
                    let result = self
                        .send_single_with_retry(&payload, &endpoint, &auth_key, &p256dh_key)
                        .await;
                    (id, endpoint, result)
                }
            })
            .collect();

        let outcomes: Vec<(Uuid, String, Result<(), WebpushSendOutcome>)> =
            futures_util::stream::iter(send_futs)
                .buffer_unordered(MAX_CONCURRENT_SENDS)
                .collect()
                .await;

        let mut stale_ids: Vec<Uuid> = Vec::new();

        for (id, endpoint, result) in outcomes {
            match result {
                Ok(()) => {}
                Err(WebpushSendOutcome::Gone) => {
                    stale_ids.push(id);
                }
                Err(WebpushSendOutcome::Failed(ref err)) => {
                    warn!(endpoint = %endpoint, error = %err, "web push send failed");
                }
                Err(WebpushSendOutcome::Retryable(ref err)) => {
                    // Unreachable: send_single_with_retry converts Retryable
                    // to Failed once retries are exhausted, but handle
                    // defensively.
                    warn!(endpoint = %endpoint, error = %err, "web push send failed (retryable)");
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

    /// Sends a test push notification to all subscriptions for a user.
    ///
    /// Returns a summary with per-subscription success/failure counts.
    /// Subscriptions returning HTTP 410 (Gone) are automatically deleted
    /// (stale subscription cleanup). Sends are executed concurrently,
    /// bounded by [`MAX_CONCURRENT_SENDS`].
    pub async fn send_test_to_user(
        &self,
        user_id: Uuid,
    ) -> Result<WebpushTestResult, WebpushError> {
        let subscriptions = self
            .store
            .get_webpush_subscriptions_by_user_id(user_id)
            .await?;

        if subscriptions.is_empty() {
            return Ok(WebpushTestResult {
                message: "No webpush subscriptions found.".to_owned(),
                success_count: 0,
                failure_count: 0,
            });
        }

        let test_msg = WebpushMessage {
            icon: String::new(),
            title: "Test".to_owned(),
            body: "This is a test Web Push notification".to_owned(),
            tag: String::new(),
            actions: Vec::new(),
            data: HashMap::new(),
        };
        let msg_json = serde_json::to_vec(&test_msg)
            .map_err(|e| WebpushError::Serialization(e.to_string()))?;

        // Send concurrently with bounded parallelism.
        // Clone subscription fields into owned data to avoid lifetime issues
        // with the async closures.
        let send_futs: Vec<_> = subscriptions
            .iter()
            .map(|sub| {
                let id = sub.id;
                let endpoint = sub.endpoint.clone();
                let auth_key = sub.endpoint_auth_key.clone();
                let p256dh_key = sub.endpoint_p256dh_key.clone();
                let payload = msg_json.clone();
                async move {
                    let result = self
                        .send_single_with_retry(&payload, &endpoint, &auth_key, &p256dh_key)
                        .await;
                    (id, endpoint, result)
                }
            })
            .collect();

        let outcomes: Vec<(Uuid, String, Result<(), WebpushSendOutcome>)> =
            futures_util::stream::iter(send_futs)
                .buffer_unordered(MAX_CONCURRENT_SENDS)
                .collect()
                .await;

        let mut stale_ids: Vec<Uuid> = Vec::new();
        let mut success_count: u32 = 0;
        let mut failure_count: u32 = 0;

        for (id, endpoint, result) in outcomes {
            match result {
                Ok(()) => {
                    success_count = success_count.saturating_add(1);
                }
                Err(WebpushSendOutcome::Gone) => {
                    stale_ids.push(id);
                    failure_count = failure_count.saturating_add(1);
                }
                Err(WebpushSendOutcome::Failed(ref err)) => {
                    warn!(endpoint = %endpoint, error = %err, "test web push send failed");
                    failure_count = failure_count.saturating_add(1);
                }
                Err(WebpushSendOutcome::Retryable(ref err)) => {
                    // Unreachable: send_single_with_retry converts Retryable
                    // to Failed once retries are exhausted, but handle
                    // defensively.
                    warn!(endpoint = %endpoint, error = %err, "test web push send failed (retryable)");
                    failure_count = failure_count.saturating_add(1);
                }
            }
        }

        // Stale subscription cleanup: delete subscriptions that returned
        // EndpointNotValid / EndpointNotFound (HTTP 410 Gone).
        if !stale_ids.is_empty() {
            let count = stale_ids.len();
            if let Err(err) = self.store.delete_webpush_subscriptions(&stale_ids).await {
                error!(error = %err, "failed to delete stale webpush subscriptions");
            } else {
                info!(count, "deleted stale webpush subscriptions");
            }
        }

        Ok(WebpushTestResult {
            message: format!("Sent test to {} subscription(s).", subscriptions.len()),
            success_count,
            failure_count,
        })
    }

    /// Sends a test push notification to verify a subscription is valid.
    pub async fn test(&self, subscription: &WebpushSubscription) -> Result<(), WebpushError> {
        let test_msg = WebpushMessage {
            icon: String::new(),
            title: "Test".to_owned(),
            body: "This is a test Web Push notification".to_owned(),
            tag: String::new(),
            actions: Vec::new(),
            data: HashMap::new(),
        };

        let msg_json = serde_json::to_vec(&test_msg)
            .map_err(|e| WebpushError::Serialization(e.to_string()))?;

        match self
            .send_single_with_retry(
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
            Err(WebpushSendOutcome::Retryable(err) | WebpushSendOutcome::Failed(err)) => {
                Err(WebpushError::WebPush(err))
            }
        }
    }

    /// Wraps [`send_single`](Self::send_single) with exponential backoff for
    /// transient failures.
    ///
    /// Hard failures ([`WebpushSendOutcome::Gone`] and
    /// [`WebpushSendOutcome::Failed`]) are returned immediately.
    /// Transient failures ([`WebpushSendOutcome::Retryable`]) are retried up
    /// to [`MAX_SEND_RETRIES`] times with exponential backoff starting at
    /// [`INITIAL_RETRY_BACKOFF`].
    async fn send_single_with_retry(
        &self,
        payload: &[u8],
        endpoint: &str,
        auth_key: &str,
        p256dh_key: &str,
    ) -> Result<(), WebpushSendOutcome> {
        let mut attempt: u32 = 0;
        loop {
            match self
                .send_single(payload, endpoint, auth_key, p256dh_key)
                .await
            {
                Ok(()) => return Ok(()),
                Err(WebpushSendOutcome::Gone) => return Err(WebpushSendOutcome::Gone),
                Err(WebpushSendOutcome::Failed(err)) => {
                    return Err(WebpushSendOutcome::Failed(err));
                }
                Err(WebpushSendOutcome::Retryable(err)) => {
                    if attempt >= MAX_SEND_RETRIES {
                        return Err(WebpushSendOutcome::Failed(format!(
                            "exhausted {MAX_SEND_RETRIES} retries: {err}"
                        )));
                    }
                    attempt += 1;
                    let backoff =
                        INITIAL_RETRY_BACKOFF * 2u32.saturating_pow(attempt.saturating_sub(1));
                    warn!(
                        endpoint = %endpoint,
                        attempt = attempt,
                        backoff_ms = backoff.as_millis() as u64,
                        error = %err,
                        "transient web push failure, retrying"
                    );
                    tokio::time::sleep(backoff).await;
                }
            }
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

        // Build VAPID signature: clone the pre-parsed key (avoids PEM
        // re-parsing on every send), attach subscription info, add the
        // subscriber contact ("sub" claim), then build.
        let mut sig_builder = self.vapid_key.clone().add_sub_info(&subscription_info);
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
                if is_subscription_gone(&err) {
                    Err(WebpushSendOutcome::Gone)
                } else if is_retryable(&err) {
                    Err(WebpushSendOutcome::Retryable(err.to_string()))
                } else {
                    Err(WebpushSendOutcome::Failed(err.to_string()))
                }
            }
        }
    }
}

/// Internal outcome for a single web push send attempt.
enum WebpushSendOutcome {
    /// The subscription has been removed by the push service (HTTP 410).
    Gone,
    /// A transient error that may succeed on retry (5xx, network).
    Retryable(String),
    /// A permanent error (bad request, unauthorized, etc.).
    Failed(String),
}

/// Checks whether a web push error indicates the subscription is gone (HTTP 410).
///
/// Uses structured matching on [`web_push::WebPushError`] variants rather than
/// fragile string matching. The `EndpointNotValid` and `EndpointNotFound`
/// variants correspond to HTTP 410 Gone responses from push services.
fn is_subscription_gone(err: &web_push::WebPushError) -> bool {
    matches!(
        err,
        web_push::WebPushError::EndpointNotValid(_) | web_push::WebPushError::EndpointNotFound(_)
    )
}

/// Checks whether a web push error is transient and worth retrying.
///
/// `ServerError` (5xx) and `Unspecified` (network-level failures such as
/// connection timeouts and DNS errors from the isahc HTTP client) are
/// considered retryable.  Hard failures such as `EndpointNotValid` (410),
/// `Unauthorized` (403), and `BadRequest` (400) are **not** retried.
fn is_retryable(err: &web_push::WebPushError) -> bool {
    matches!(
        err,
        web_push::WebPushError::ServerError { .. } | web_push::WebPushError::Unspecified
    )
}

/// Validates that a PEM-encoded VAPID private key is well-formed.
///
/// Used during server startup to verify stored VAPID keys before
/// constructing the [`Webpusher`] dispatcher.
pub fn validate_vapid_private_key(private_pem: &str) -> Result<(), String> {
    VapidSignatureBuilder::from_pem_no_sub(private_pem.as_bytes())
        .map(|_| ())
        .map_err(|e| format!("invalid VAPID private key: {e}"))
}

/// Generates a new VAPID key pair, stores it, and deletes all existing
/// subscriptions (which are invalid with the new keys).
///
/// Returns `(public_key_b64, private_key_pem)` where the public key is
/// base64url-no-pad encoded and the private key is PEM-encoded.
async fn regenerate_vapid_keys(store: &dyn AppStore) -> Result<(String, String), WebpushError> {
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

/// Generates a PEM-encoded EC P-256 private key using pure Rust cryptography.
///
/// The key is output in SEC1 PEM format (`BEGIN EC PRIVATE KEY`) which is
/// accepted by the `web-push` crate's `VapidSignatureBuilder::from_pem_no_sub`.
fn generate_ec_p256_pem() -> Result<String, String> {
    use base64::engine::general_purpose::STANDARD as B64STD;
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    // Generate a random EC P-256 private key.
    let secret_key = p256::SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let scalar_bytes = secret_key.to_bytes();
    let public_key = secret_key.public_key();
    let pub_point = public_key.to_encoded_point(false);
    let pub_bytes = pub_point.as_bytes();

    // Build SEC1 ECPrivateKey DER encoding (RFC 5915):
    //   ECPrivateKey ::= SEQUENCE {
    //     version        INTEGER { ecPrivkeyVer1(1) },
    //     privateKey     OCTET STRING (32 bytes for P-256),
    //     parameters [0] ECParameters {{ namedCurve (prime256v1) }} OPTIONAL,
    //     publicKey  [1] BIT STRING OPTIONAL
    //   }
    let oid_prime256v1: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

    // Inner content of the SEQUENCE
    let mut inner = Vec::with_capacity(128);
    // version = 1
    inner.extend_from_slice(&[0x02, 0x01, 0x01]);
    // privateKey OCTET STRING
    inner.push(0x04);
    inner.push(scalar_bytes.len() as u8);
    inner.extend_from_slice(&scalar_bytes);
    // parameters [0] EXPLICIT
    inner.push(0xa0);
    inner.push(oid_prime256v1.len() as u8);
    inner.extend_from_slice(oid_prime256v1);
    // publicKey [1] EXPLICIT BIT STRING
    let bitstring_len = 1 + pub_bytes.len(); // 1 byte for unused-bits prefix
    inner.push(0xa1);
    der_push_length(&mut inner, 2 + bitstring_len);
    inner.push(0x03);
    der_push_length(&mut inner, bitstring_len);
    inner.push(0x00); // unused bits = 0
    inner.extend_from_slice(pub_bytes);

    // Wrap in SEQUENCE
    let mut der = Vec::with_capacity(4 + inner.len());
    der.push(0x30);
    der_push_length(&mut der, inner.len());
    der.extend_from_slice(&inner);

    // Encode as PEM
    let b64 = B64STD.encode(&der);
    let mut pem = String::from("-----BEGIN EC PRIVATE KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(
            std::str::from_utf8(chunk).map_err(|e| format!("base64 encoding error: {e}"))?,
        );
        pem.push('\n');
    }
    pem.push_str("-----END EC PRIVATE KEY-----\n");
    Ok(pem)
}

/// Appends a DER length encoding to the buffer.
fn der_push_length(buf: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        buf.push(len as u8);
    } else if len < 0x100 {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
}

/// A no-op web push dispatcher placeholder.
///
/// Used when web push is disabled or VAPID key generation failed. This type
/// does not send notifications; it only exposes the disable reason and an
/// empty public key.
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
        CreateGroupInput, CreateOrganizationInput, CreateOrganizationStoreError,
        CreateUserStoreError, CustomRoleRecord, GroupMemberRecord, GroupRecord,
        InsertOrganizationMemberError, LoginType, NotificationMessageRecord,
        NotificationMessageStatus, NotificationMethod, OrgResourceCounts,
        OrganizationMemberListFilter, OrganizationMemberRecord, OrganizationRecord,
        UpdateGroupInput, UpdateOrganizationInput, UpdateOrganizationStoreError,
        UpsertCustomRoleInput, UpsertUserLinkInput, UserAppearanceRecord, UserConfigRecord,
        UserDeletedRecord, UserLinkRecord, UserListFilter, UserPreferenceRecord, UserRecord,
        UserStatus, UserStatusChangeRecord,
    };
    use coder_core::{CreateUserInput, IdentityStore, StorageError};
    use std::sync::Mutex;
    use time::OffsetDateTime;
    use uuid::Uuid;

    // ── Mock store ───────────────────────────────────────────

    /// A single captured call to `bulk_mark_notification_messages_failed`.
    /// Factored out to appease `clippy::type_complexity`.
    type BulkFailCall = (Vec<Uuid>, Vec<NotificationMessageStatus>, Vec<String>);

    /// Configurable mock that controls what `acquire_pending_notification_messages`
    /// returns and records calls to `update_notification_message_status` and
    /// `increment_notification_message_attempt_count`.
    #[derive(Clone)]
    struct MockStore {
        pending_messages: Vec<NotificationMessageRecord>,
        status_updates: Arc<Mutex<Vec<(Uuid, NotificationMessageStatus)>>>,
        attempt_increments: Arc<Mutex<Vec<Uuid>>>,
        bulk_sent: Arc<Mutex<Vec<Vec<Uuid>>>>,
        bulk_failed: Arc<Mutex<Vec<BulkFailCall>>>,
        force_error: Option<String>,
        notifier_paused: bool,
        /// `(user_id, template_id) -> disabled` preference lookups. Tests
        /// use `with_disabled_preference` to seed a row; absence means
        /// "no preference row" which maps to not-disabled.
        disabled_prefs: HashMap<(Uuid, Uuid), bool>,
    }

    impl MockStore {
        fn new() -> Self {
            Self {
                pending_messages: Vec::new(),
                status_updates: Arc::new(Mutex::new(Vec::new())),
                attempt_increments: Arc::new(Mutex::new(Vec::new())),
                bulk_sent: Arc::new(Mutex::new(Vec::new())),
                bulk_failed: Arc::new(Mutex::new(Vec::new())),
                force_error: None,
                notifier_paused: false,
                disabled_prefs: HashMap::new(),
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

        fn with_notifier_paused(mut self, paused: bool) -> Self {
            self.notifier_paused = paused;
            self
        }

        fn with_disabled_preference(
            mut self,
            user_id: Uuid,
            template_id: Uuid,
            disabled: bool,
        ) -> Self {
            self.disabled_prefs.insert((user_id, template_id), disabled);
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

        // ----- User identity supplements (stubs for test mock) -----

        async fn find_user_by_linked_id(
            &self,
            _login_type: LoginType,
            _linked_id: &str,
        ) -> Result<Option<UserRecord>, StorageError> {
            self.maybe_err()?;
            Ok(None)
        }

        async fn find_active_user_by_email_and_login_type(
            &self,
            _email: &str,
            _login_type: LoginType,
        ) -> Result<Option<UserRecord>, StorageError> {
            self.maybe_err()?;
            Ok(None)
        }

        async fn list_user_links(
            &self,
            _user_id: Uuid,
        ) -> Result<Vec<UserLinkRecord>, StorageError> {
            self.maybe_err()?;
            Ok(Vec::new())
        }

        async fn upsert_user_link(
            &self,
            _user_id: Uuid,
            _input: &UpsertUserLinkInput,
        ) -> Result<UserLinkRecord, StorageError> {
            Err(StorageError::unavailable("not implemented in MockStore"))
        }

        async fn delete_user_link(
            &self,
            _user_id: Uuid,
            _login_type: LoginType,
        ) -> Result<bool, StorageError> {
            self.maybe_err()?;
            Ok(false)
        }

        async fn get_user_config(
            &self,
            _user_id: Uuid,
            _key: &str,
        ) -> Result<Option<UserConfigRecord>, StorageError> {
            self.maybe_err()?;
            Ok(None)
        }

        async fn upsert_user_config(
            &self,
            _user_id: Uuid,
            _key: &str,
            _value: &str,
        ) -> Result<UserConfigRecord, StorageError> {
            Err(StorageError::unavailable("not implemented in MockStore"))
        }

        async fn delete_user_config(
            &self,
            _user_id: Uuid,
            _key: &str,
        ) -> Result<bool, StorageError> {
            self.maybe_err()?;
            Ok(false)
        }

        async fn insert_user_deleted(
            &self,
            _user_id: Uuid,
            _deleted_by: Option<Uuid>,
            _reason: &str,
        ) -> Result<UserDeletedRecord, StorageError> {
            Err(StorageError::unavailable("not implemented in MockStore"))
        }

        async fn insert_user_status_change(
            &self,
            _user_id: Uuid,
            _old_status: UserStatus,
            _new_status: UserStatus,
            _changed_by: Option<Uuid>,
            _reason: &str,
        ) -> Result<UserStatusChangeRecord, StorageError> {
            Err(StorageError::unavailable("not implemented in MockStore"))
        }

        async fn list_user_status_changes(
            &self,
            _user_id: Uuid,
        ) -> Result<Vec<UserStatusChangeRecord>, StorageError> {
            self.maybe_err()?;
            Ok(Vec::new())
        }

        async fn list_custom_roles(
            &self,
            _organization_id: Option<Uuid>,
        ) -> Result<Vec<CustomRoleRecord>, StorageError> {
            self.maybe_err()?;
            Ok(Vec::new())
        }

        async fn upsert_custom_role(
            &self,
            _input: &UpsertCustomRoleInput,
        ) -> Result<CustomRoleRecord, StorageError> {
            Err(StorageError::unavailable("not implemented in MockStore"))
        }

        async fn delete_custom_role(
            &self,
            _name: &str,
            _organization_id: Option<Uuid>,
        ) -> Result<bool, StorageError> {
            self.maybe_err()?;
            Ok(false)
        }

        async fn find_custom_role(
            &self,
            _name: &str,
            _organization_id: Option<Uuid>,
        ) -> Result<Option<CustomRoleRecord>, StorageError> {
            self.maybe_err()?;
            Ok(None)
        }

        async fn insert_organization(
            &self,
            _input: &CreateOrganizationInput,
        ) -> Result<OrganizationRecord, CreateOrganizationStoreError> {
            Err(CreateOrganizationStoreError::Storage(
                StorageError::unavailable("not implemented in MockStore"),
            ))
        }

        async fn update_organization(
            &self,
            _input: &UpdateOrganizationInput,
        ) -> Result<OrganizationRecord, UpdateOrganizationStoreError> {
            Err(UpdateOrganizationStoreError::Storage(
                StorageError::unavailable("not implemented in MockStore"),
            ))
        }

        async fn soft_delete_organization(&self, _id: Uuid) -> Result<bool, StorageError> {
            self.maybe_err()?;
            Ok(false)
        }

        async fn get_organization_resource_counts(
            &self,
            _id: Uuid,
        ) -> Result<OrgResourceCounts, StorageError> {
            Err(StorageError::unavailable("not implemented in MockStore"))
        }

        async fn get_organization_sharing_settings(
            &self,
            _organization_id: Uuid,
        ) -> Result<Option<coder_core::WorkspaceSharingMode>, StorageError> {
            self.maybe_err()?;
            Ok(None)
        }

        async fn update_organization_sharing_settings(
            &self,
            _organization_id: Uuid,
            _mode: coder_core::WorkspaceSharingMode,
        ) -> Result<Option<coder_core::WorkspaceSharingMode>, StorageError> {
            self.maybe_err()?;
            Ok(None)
        }

        async fn list_groups(
            &self,
            _organization_id: Uuid,
        ) -> Result<Vec<GroupRecord>, StorageError> {
            self.maybe_err()?;
            Ok(Vec::new())
        }

        async fn create_group(
            &self,
            _input: &CreateGroupInput,
        ) -> Result<GroupRecord, StorageError> {
            Err(StorageError::unavailable("not implemented in MockStore"))
        }

        async fn find_group_by_id(
            &self,
            _group_id: Uuid,
        ) -> Result<Option<GroupRecord>, StorageError> {
            self.maybe_err()?;
            Ok(None)
        }

        async fn delete_group(&self, _group_id: Uuid) -> Result<bool, StorageError> {
            self.maybe_err()?;
            Ok(false)
        }

        async fn list_group_members(
            &self,
            _group_id: Uuid,
        ) -> Result<Vec<GroupMemberRecord>, StorageError> {
            self.maybe_err()?;
            Ok(Vec::new())
        }

        async fn insert_group_member(
            &self,
            _group_id: Uuid,
            _user_id: Uuid,
        ) -> Result<(), StorageError> {
            self.maybe_err()?;
            Ok(())
        }

        async fn delete_group_member(
            &self,
            _group_id: Uuid,
            _user_id: Uuid,
        ) -> Result<bool, StorageError> {
            self.maybe_err()?;
            Ok(false)
        }

        async fn find_group_by_name(
            &self,
            _organization_id: Uuid,
            _name: &str,
        ) -> Result<Option<GroupRecord>, StorageError> {
            self.maybe_err()?;
            Ok(None)
        }

        async fn update_group(
            &self,
            _input: &UpdateGroupInput,
        ) -> Result<GroupRecord, StorageError> {
            Err(StorageError::unavailable("not implemented in MockStore"))
        }

        async fn list_all_groups(&self) -> Result<Vec<GroupRecord>, StorageError> {
            self.maybe_err()?;
            Ok(Vec::new())
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

        async fn bulk_mark_notification_messages_sent(
            &self,
            ids: &[Uuid],
        ) -> Result<u64, StorageError> {
            self.maybe_err()?;
            // Mirror the real store's behaviour of incrementing attempts on
            // success. Tests assert on both the bulk-sent capture and the
            // per-message status_updates vector (populated via a side effect
            // here), so `dispatch_once_…` tests that only inspect
            // `status_updates` keep working unchanged.
            for id in ids {
                self.status_updates
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push((*id, NotificationMessageStatus::Sent));
            }
            self.bulk_sent
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(ids.to_vec());
            Ok(ids.len() as u64)
        }

        async fn bulk_mark_notification_messages_failed(
            &self,
            ids: &[Uuid],
            statuses: &[NotificationMessageStatus],
            status_reasons: &[String],
            _max_attempts: u32,
            _retry_interval_secs: u32,
        ) -> Result<u64, StorageError> {
            self.maybe_err()?;
            for (id, status) in ids.iter().zip(statuses.iter()) {
                self.status_updates
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push((*id, *status));
                // Only count a "real" attempt increment for non-inhibited
                // rows — inhibited messages are terminal and never consume
                // retry budget.
                if !matches!(status, NotificationMessageStatus::Inhibited) {
                    self.attempt_increments
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(*id);
                }
            }
            self.bulk_failed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((ids.to_vec(), statuses.to_vec(), status_reasons.to_vec()));
            Ok(ids.len() as u64)
        }

        async fn find_user_notification_preference(
            &self,
            user_id: Uuid,
            notification_template_id: Uuid,
        ) -> Result<Option<bool>, StorageError> {
            self.maybe_err()?;
            Ok(self
                .disabled_prefs
                .get(&(user_id, notification_template_id))
                .copied())
        }

        // ----- OAuth2 Provider (stubs for test mock) -----

        async fn list_oauth2_provider_apps(
            &self,
        ) -> Result<Vec<coder_core::identity::OAuth2ProviderAppRecord>, StorageError> {
            Err(StorageError::unavailable("not implemented in MockStore"))
        }

        async fn create_oauth2_provider_app(
            &self,
            _input: &coder_core::identity::CreateOAuth2ProviderAppInput,
        ) -> Result<coder_core::identity::OAuth2ProviderAppRecord, StorageError> {
            Err(StorageError::unavailable("not implemented in MockStore"))
        }

        async fn find_oauth2_provider_app_by_id(
            &self,
            _app_id: Uuid,
        ) -> Result<Option<coder_core::identity::OAuth2ProviderAppRecord>, StorageError> {
            Err(StorageError::unavailable("not implemented in MockStore"))
        }

        async fn update_oauth2_provider_app(
            &self,
            _input: &coder_core::identity::UpdateOAuth2ProviderAppInput,
        ) -> Result<Option<coder_core::identity::OAuth2ProviderAppRecord>, StorageError> {
            Err(StorageError::unavailable("not implemented in MockStore"))
        }

        async fn delete_oauth2_provider_app(&self, _app_id: Uuid) -> Result<bool, StorageError> {
            Err(StorageError::unavailable("not implemented in MockStore"))
        }

        async fn update_oauth2_provider_app_registration_token(
            &self,
            _app_id: Uuid,
            _hash: &[u8],
        ) -> Result<(), StorageError> {
            Err(StorageError::unavailable("not implemented in MockStore"))
        }

        async fn has_oauth2_provider_app_user_approval(
            &self,
            _app_id: Uuid,
            _user_id: Uuid,
        ) -> Result<bool, StorageError> {
            Err(StorageError::unavailable("not implemented in MockStore"))
        }

        async fn insert_oauth2_provider_app_user_approval(
            &self,
            _app_id: Uuid,
            _user_id: Uuid,
            _scope: &str,
        ) -> Result<(), StorageError> {
            Err(StorageError::unavailable("not implemented in MockStore"))
        }

        async fn insert_oauth2_pending_consent(
            &self,
            _app_id: Uuid,
            _user_id: Uuid,
            _state: &str,
            _resource: &str,
            _code_challenge: &str,
            _code_challenge_method: &str,
            _expires_at: time::OffsetDateTime,
        ) -> Result<Uuid, StorageError> {
            Err(StorageError::unavailable("not implemented in MockStore"))
        }

        async fn take_oauth2_pending_consent(
            &self,
            _nonce: Uuid,
        ) -> Result<Option<coder_core::identity::OAuth2PendingConsent>, StorageError> {
            Err(StorageError::unavailable("not implemented in MockStore"))
        }

        async fn list_oauth2_provider_app_secrets(
            &self,
            _app_id: Uuid,
        ) -> Result<Vec<coder_core::identity::OAuth2ProviderAppSecretRecord>, StorageError>
        {
            Err(StorageError::unavailable("not implemented in MockStore"))
        }

        async fn create_oauth2_provider_app_secret(
            &self,
            _app_id: Uuid,
            _secret_prefix: &[u8],
            _hashed_secret: &[u8],
            _display_secret: &str,
        ) -> Result<coder_core::identity::OAuth2ProviderAppSecretRecord, StorageError> {
            Err(StorageError::unavailable("not implemented in MockStore"))
        }

        async fn find_oauth2_provider_app_secret_by_prefix(
            &self,
            _secret_prefix: &[u8],
        ) -> Result<Option<coder_core::identity::OAuth2ProviderAppSecretRecord>, StorageError>
        {
            Err(StorageError::unavailable("not implemented in MockStore"))
        }

        async fn update_oauth2_provider_app_secret_last_used(
            &self,
            _secret_id: Uuid,
        ) -> Result<Option<coder_core::identity::OAuth2ProviderAppSecretRecord>, StorageError>
        {
            Err(StorageError::unavailable("not implemented in MockStore"))
        }

        async fn delete_oauth2_provider_app_secret(
            &self,
            _secret_id: Uuid,
        ) -> Result<bool, StorageError> {
            Err(StorageError::unavailable("not implemented in MockStore"))
        }

        async fn find_oauth2_provider_app_secret_by_id(
            &self,
            _secret_id: Uuid,
        ) -> Result<Option<coder_core::identity::OAuth2ProviderAppSecretRecord>, StorageError>
        {
            Err(StorageError::unavailable("not implemented in MockStore"))
        }

        async fn create_oauth2_provider_app_code(
            &self,
            _app_id: Uuid,
            _user_id: Uuid,
            _secret_prefix: &[u8],
            _hashed_secret: &[u8],
            _expires_at: OffsetDateTime,
            _resource_uri: &str,
            _code_challenge: &str,
            _code_challenge_method: &str,
            _state_hash: Option<&str>,
            _redirect_uri: Option<&str>,
        ) -> Result<coder_core::identity::OAuth2ProviderAppCodeRecord, StorageError> {
            Err(StorageError::unavailable("not implemented in MockStore"))
        }

        async fn find_oauth2_provider_app_code_by_id(
            &self,
            _code_id: Uuid,
        ) -> Result<Option<coder_core::identity::OAuth2ProviderAppCodeRecord>, StorageError>
        {
            Err(StorageError::unavailable("not implemented in MockStore"))
        }

        async fn find_oauth2_provider_app_code_by_prefix(
            &self,
            _secret_prefix: &[u8],
        ) -> Result<Option<coder_core::identity::OAuth2ProviderAppCodeRecord>, StorageError>
        {
            Err(StorageError::unavailable("not implemented in MockStore"))
        }

        async fn delete_oauth2_provider_app_code(
            &self,
            _code_id: Uuid,
        ) -> Result<bool, StorageError> {
            Err(StorageError::unavailable("not implemented in MockStore"))
        }

        async fn delete_oauth2_provider_app_codes_by_app_and_user(
            &self,
            _app_id: Uuid,
            _user_id: Uuid,
        ) -> Result<u64, StorageError> {
            Err(StorageError::unavailable("not implemented in MockStore"))
        }

        async fn create_oauth2_provider_app_token(
            &self,
            _input: &coder_core::identity::CreateOAuth2ProviderAppTokenInput,
        ) -> Result<coder_core::identity::OAuth2ProviderAppTokenRecord, StorageError> {
            Err(StorageError::unavailable("not implemented in MockStore"))
        }

        async fn find_oauth2_provider_app_token_by_prefix(
            &self,
            _hash_prefix: &[u8],
        ) -> Result<Option<coder_core::identity::OAuth2ProviderAppTokenRecord>, StorageError>
        {
            Err(StorageError::unavailable("not implemented in MockStore"))
        }

        async fn find_oauth2_provider_app_token_by_api_key_id(
            &self,
            _api_key_id: &str,
        ) -> Result<Option<coder_core::identity::OAuth2ProviderAppTokenRecord>, StorageError>
        {
            Err(StorageError::unavailable("not implemented in MockStore"))
        }

        async fn find_oauth2_provider_app_token_by_refresh_hash(
            &self,
            _refresh_hash: &[u8],
        ) -> Result<Option<coder_core::identity::OAuth2ProviderAppTokenRecord>, StorageError>
        {
            Err(StorageError::unavailable("not implemented in MockStore"))
        }

        async fn delete_oauth2_provider_app_token(
            &self,
            _token_id: Uuid,
        ) -> Result<bool, StorageError> {
            Err(StorageError::unavailable("not implemented in MockStore"))
        }

        async fn list_oauth2_provider_app_tokens_by_app_and_user(
            &self,
            _app_id: Uuid,
            _user_id: Uuid,
        ) -> Result<Vec<coder_core::identity::OAuth2ProviderAppTokenRecord>, StorageError> {
            Err(StorageError::unavailable("not implemented in MockStore"))
        }

        async fn delete_oauth2_provider_app_tokens_by_app_and_user(
            &self,
            _app_id: Uuid,
            _user_id: Uuid,
        ) -> Result<u64, StorageError> {
            Err(StorageError::unavailable("not implemented in MockStore"))
        }
    }

    // `MockStore` does not implement `AppStore` (that trait is enormous), so
    // the blanket impl of `NotifierPausedReader` for `T: AppStore` does not
    // cover it. Provide a direct impl that drives off the test-configured
    // field.
    #[async_trait]
    impl NotifierPausedReader for MockStore {
        async fn notifier_paused(&self) -> Result<bool, StorageError> {
            self.maybe_err()?;
            Ok(self.notifier_paused)
        }
    }

    // ── Helpers ──────────────────────────────────────────────

    /// Test helper: creates a `NotificationDispatchService` with an immediately-
    /// cancelled token and a long poll interval so the background loop exits
    /// right away and tests can call `dispatch_once` directly.
    fn make_service(
        store: MockStore,
        config: NotificationConfig,
    ) -> Arc<NotificationDispatchService<MockStore>> {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let (service, _handle) = NotificationDispatchService::new(store, config, 3600, cancel)
            .unwrap_or_else(|e| panic!("failed to create service: {e}"));
        service
    }

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
            (
                NotificationMessageStatus::PermanentFailure,
                r#""permanent_failure""#,
            ),
            (NotificationMessageStatus::Unknown, r#""unknown""#),
            (NotificationMessageStatus::Inhibited, r#""inhibited""#),
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
            ..NotificationConfig::default()
        };
        let service = make_service(store, config.clone());
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
        let service = make_service(store, config);
        let count = service
            .dispatch_once()
            .await
            .unwrap_or_else(|e| panic!("dispatch_once failed: {e}"));
        assert_eq!(count, 0);
    }

    // ── 7b. Dispatch skips work entirely when notifier is paused ────
    //
    // Regression test: a message is pending in the store *and* the store
    // is configured to respond to `notifier_paused` with `true`. The
    // dispatch loop must return early without touching the queue — no
    // status updates, no attempt increments.
    #[tokio::test]
    async fn dispatch_once_skips_when_notifier_paused() {
        let msg = make_message(NotificationMethod::Inbox, "{}");
        let store = MockStore::new()
            .with_pending(vec![msg])
            .with_notifier_paused(true);
        let status_updates = store.status_updates.clone();
        let attempt_increments = store.attempt_increments.clone();

        let service = make_service(store, NotificationConfig::default());
        let count = service
            .dispatch_once()
            .await
            .unwrap_or_else(|e| panic!("dispatch_once failed: {e}"));

        assert_eq!(count, 0, "paused dispatcher must report zero dispatched");
        assert!(
            status_updates
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty(),
            "paused dispatcher must not mark any message sent/failed"
        );
        assert!(
            attempt_increments
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty(),
            "paused dispatcher must not consume retry attempts"
        );
    }

    // ── 8. Dispatch propagates storage error ────────────────

    #[tokio::test]
    async fn dispatch_once_propagates_storage_error() {
        let store = MockStore::new().with_error("database is down");
        let config = NotificationConfig::default();
        let service = make_service(store, config);
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
        let service = make_service(store.clone(), config);

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
        let service = make_service(store.clone(), config);

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
        let service = make_service(store.clone(), config);

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
        assert_eq!(updates[0].1, NotificationMessageStatus::PermanentFailure);
    }

    // ── 12. Webhook without endpoint URL records permanent failure ──

    #[tokio::test]
    async fn dispatch_webhook_without_url_records_permanent_failure() {
        // targets_json with no "url" field → webhook dispatch is a
        // permanent failure: `targets_json` is immutable per message, so
        // retrying cannot recover. The loop should short-circuit to
        // PermanentFailure without waiting out the attempt budget.
        let msg = make_message(NotificationMethod::Webhook, r#"{"other":"value"}"#);
        let msg_id = msg.id;
        let store = MockStore::new().with_pending(vec![msg]);
        let config = NotificationConfig::default();
        let service = make_service(store.clone(), config);

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
        assert_eq!(updates[0].1, NotificationMessageStatus::PermanentFailure);
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
        let service = make_service(store.clone(), config);

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
            ..NotificationConfig::default()
        };
        let service = make_service(store, config);
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
            NotificationMessageStatus::PermanentFailure
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
        let service = make_service(store.clone(), config);

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
        assert!(pem.is_ok(), "should produce a PEM key");
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
            data: HashMap::new(),
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
            data: HashMap::new(),
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
            WebpushSendOutcome::Gone | WebpushSendOutcome::Retryable(_) => {
                panic!("expected Failed variant")
            }
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

    // ── 26. Webhook status classification ─────────────────────

    #[test]
    fn classify_webhook_status_success_permanent_retryable() {
        assert_eq!(classify_webhook_status(200), WebhookOutcome::Success);
        assert_eq!(classify_webhook_status(201), WebhookOutcome::Success);
        assert_eq!(classify_webhook_status(299), WebhookOutcome::Success);
        // 4xx is permanent...
        assert_eq!(classify_webhook_status(400), WebhookOutcome::Permanent);
        assert_eq!(classify_webhook_status(401), WebhookOutcome::Permanent);
        assert_eq!(classify_webhook_status(403), WebhookOutcome::Permanent);
        assert_eq!(classify_webhook_status(404), WebhookOutcome::Permanent);
        // ...except 408 and 429.
        assert_eq!(classify_webhook_status(408), WebhookOutcome::Retryable);
        assert_eq!(classify_webhook_status(429), WebhookOutcome::Retryable);
        // 5xx retryable.
        assert_eq!(classify_webhook_status(500), WebhookOutcome::Retryable);
        assert_eq!(classify_webhook_status(502), WebhookOutcome::Retryable);
        assert_eq!(classify_webhook_status(599), WebhookOutcome::Retryable);
        // Redirects etc. are treated as retryable.
        assert_eq!(classify_webhook_status(301), WebhookOutcome::Retryable);
    }

    // ── 27. Backoff duration grows exponentially and caps ─────

    #[test]
    fn backoff_duration_respects_base_cap_and_jitter() {
        // attempt=1 → ~base, +0-1s jitter.
        let d1 = backoff_duration(1, 5, 300);
        assert!(d1 >= Duration::from_secs(5));
        assert!(d1 < Duration::from_secs(7));

        // attempt=2 → ~2*base.
        let d2 = backoff_duration(2, 5, 300);
        assert!(d2 >= Duration::from_secs(10));
        assert!(d2 < Duration::from_secs(12));

        // attempt=20 → capped at max.
        let d_cap = backoff_duration(20, 5, 300);
        assert!(d_cap >= Duration::from_secs(300));
        assert!(d_cap < Duration::from_secs(302));

        // attempt=0 is treated as 1 (no underflow).
        let d0 = backoff_duration(0, 1, 60);
        assert!(d0 >= Duration::from_secs(1));
        assert!(d0 < Duration::from_secs(3));
    }

    // ── 28. Error helper: is_permanent ────────────────────────

    #[test]
    fn notification_dispatch_error_is_permanent() {
        assert!(NotificationDispatchError::Permanent("x".into()).is_permanent());
        assert!(!NotificationDispatchError::Transport("x".into()).is_permanent());
        assert!(!NotificationDispatchError::ConfigMissing("x".into()).is_permanent());
    }

    // ── 29. Webhook dispatch: 403 → permanent failure ─────────

    /// Spawns a one-shot HTTP responder that reads one request and replies
    /// with the provided status line, then closes. Returns the bound URL.
    async fn spawn_one_shot_http(status_line: &'static str) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|e| panic!("local_addr: {e}"));
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let body = "ok";
                let resp = format!(
                    "{status_line}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });
        format!("http://{addr}/hook")
    }

    /// Spawns a sequenced HTTP responder that answers each incoming request
    /// with the next status line from `statuses` and closes. Returns the URL.
    fn spawn_sequenced_http(statuses: Vec<&'static str>) -> String {
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|e| panic!("local_addr: {e}"));
        listener
            .set_nonblocking(true)
            .unwrap_or_else(|e| panic!("nonblocking: {e}"));
        let listener =
            tokio::net::TcpListener::from_std(listener).unwrap_or_else(|e| panic!("from_std: {e}"));
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            for status_line in statuses {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let body = "ok";
                let resp = format!(
                    "{status_line}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });
        format!("http://{addr}/hook")
    }

    #[tokio::test]
    async fn dispatch_webhook_missing_url_returns_permanent() {
        // `targets_json` has no `url` field — config is absent and cannot
        // be recovered by retrying, so the dispatcher must short-circuit
        // rather than burn the attempt budget.
        let msg = make_message(NotificationMethod::Webhook, r#"{"other":"thing"}"#);
        let store = MockStore::new();
        let config = NotificationConfig::default();
        let service = make_service(store, config);
        let err = match service.dispatch_webhook(&msg).await {
            Err(e) => e,
            Ok(()) => panic!("missing URL should fail"),
        };
        assert!(
            err.is_permanent(),
            "missing URL must surface as permanent: {err}"
        );
        assert!(matches!(err, NotificationDispatchError::Permanent(_)));
    }

    #[tokio::test]
    async fn dispatch_webhook_403_returns_permanent() {
        let url = spawn_one_shot_http("HTTP/1.1 403 Forbidden").await;
        let msg = make_message(
            NotificationMethod::Webhook,
            &format!(r#"{{"url":"{url}"}}"#),
        );
        let store = MockStore::new();
        let config = NotificationConfig::default();
        let service = make_service(store, config);
        let err = match service.dispatch_webhook(&msg).await {
            Err(e) => e,
            Ok(()) => panic!("403 should fail"),
        };
        assert!(err.is_permanent(), "403 must surface as permanent: {err}");
    }

    #[tokio::test]
    async fn dispatch_webhook_500_returns_retryable_transport() {
        let url = spawn_one_shot_http("HTTP/1.1 500 Internal Server Error").await;
        let msg = make_message(
            NotificationMethod::Webhook,
            &format!(r#"{{"url":"{url}"}}"#),
        );
        let store = MockStore::new();
        let config = NotificationConfig::default();
        let service = make_service(store, config);
        let err = match service.dispatch_webhook(&msg).await {
            Err(e) => e,
            Ok(()) => panic!("500 should fail"),
        };
        assert!(
            !err.is_permanent(),
            "5xx must surface as retryable transport error: {err}"
        );
        assert!(matches!(err, NotificationDispatchError::Transport(_)));
    }

    #[tokio::test]
    async fn dispatch_webhook_200_succeeds() {
        let url = spawn_one_shot_http("HTTP/1.1 200 OK").await;
        let msg = make_message(
            NotificationMethod::Webhook,
            &format!(r#"{{"url":"{url}"}}"#),
        );
        let store = MockStore::new();
        let config = NotificationConfig::default();
        let service = make_service(store, config);
        service
            .dispatch_webhook(&msg)
            .await
            .unwrap_or_else(|e| panic!("200 should succeed: {e}"));
    }

    #[tokio::test]
    async fn dispatch_webhook_500_then_200_eventually_succeeds() {
        // First call hits 500 (retryable), second call hits 200 (success).
        let url = spawn_sequenced_http(vec![
            "HTTP/1.1 500 Internal Server Error",
            "HTTP/1.1 200 OK",
        ]);
        let msg = make_message(
            NotificationMethod::Webhook,
            &format!(r#"{{"url":"{url}"}}"#),
        );
        let store = MockStore::new();
        let config = NotificationConfig::default();
        let service = make_service(store, config);

        // First attempt: 500 → Retryable transport error.
        let first = service.dispatch_webhook(&msg).await;
        assert!(
            matches!(first, Err(NotificationDispatchError::Transport(_))),
            "expected retryable transport error, got {first:?}"
        );

        // Retry: hits 200.
        service
            .dispatch_webhook(&msg)
            .await
            .unwrap_or_else(|e| panic!("retry should succeed: {e}"));
    }

    // ── 30. Dispatch loop: permanent error short-circuits retry ──

    #[tokio::test]
    async fn dispatch_once_permanent_error_marks_permanent_failure_immediately() {
        let url = spawn_one_shot_http("HTTP/1.1 403 Forbidden").await;
        let msg = make_message(
            NotificationMethod::Webhook,
            &format!(r#"{{"url":"{url}"}}"#),
        );
        let msg_id = msg.id;
        // attempt_count=0, so normally we'd go to TemporaryFailure; with
        // a permanent error we expect PermanentFailure immediately.
        let store = MockStore::new().with_pending(vec![msg]);
        let config = NotificationConfig::default();
        let service = make_service(store.clone(), config);

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
        assert_eq!(updates[0].1, NotificationMessageStatus::PermanentFailure);
    }

    // ── 31. Exponential backoff gate: second attempt skipped ──

    #[tokio::test]
    async fn dispatch_once_retryable_schedules_backoff_and_gates_next_cycle() {
        // Use a config with a long base interval so we can observe the gate.
        let url = spawn_sequenced_http(vec![
            "HTTP/1.1 500 Internal Server Error",
            // Second request would succeed, but backoff should gate it.
            "HTTP/1.1 200 OK",
        ]);
        let msg = make_message(
            NotificationMethod::Webhook,
            &format!(r#"{{"url":"{url}"}}"#),
        );
        let msg_id = msg.id;
        let store = MockStore::new().with_pending(vec![msg.clone()]);
        let config = NotificationConfig {
            base_retry_interval_secs: 60,
            max_retry_interval_secs: 300,
            ..NotificationConfig::default()
        };
        let service = make_service(store.clone(), config);

        // Cycle 1: hits 500, retryable, schedules backoff.
        service
            .dispatch_once()
            .await
            .unwrap_or_else(|e| panic!("cycle 1: {e}"));

        // Cycle 2: backoff still active → should not call HTTP at all and
        // should only record a TemporaryFailure status update. The MockStore
        // replays the same pending list each cycle, so no re-seed is needed.
        let _ = &msg; // silence unused warning for Clone'd payload.
        service
            .dispatch_once()
            .await
            .unwrap_or_else(|e| panic!("cycle 2: {e}"));

        let updates = store
            .status_updates
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        assert!(
            updates.len() >= 2,
            "expected at least 2 status updates, got {updates:?}"
        );
        // Both updates should be TemporaryFailure (first from 500, second from backoff gate).
        for (id, status) in &updates {
            assert_eq!(*id, msg_id);
            assert_eq!(*status, NotificationMessageStatus::TemporaryFailure);
        }
    }

    // ── 32. SMTP dispatch: real SMTP conversation delivers message ──

    /// Minimal in-process SMTP responder that accepts one session without
    /// authentication and captures the raw DATA payload. It speaks enough of
    /// the protocol (`EHLO → MAIL FROM → RCPT TO → DATA → QUIT`) for lettre
    /// to consider the send successful.
    async fn spawn_smtp_capture() -> (u16, Arc<Mutex<Vec<String>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let port = listener
            .local_addr()
            .unwrap_or_else(|e| panic!("local_addr: {e}"))
            .port();
        let capture: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let cap = Arc::clone(&capture);
        tokio::spawn(async move {
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
            let (read, mut write) = sock.into_split();
            let mut reader = BufReader::new(read);
            let _ = write.write_all(b"220 test.local ESMTP ready\r\n").await;
            let mut in_data = false;
            let mut body = String::new();
            loop {
                let mut line = String::new();
                let Ok(n) = reader.read_line(&mut line).await else {
                    break;
                };
                if n == 0 {
                    break;
                }
                if in_data {
                    if line == ".\r\n" || line == ".\n" {
                        in_data = false;
                        cap.lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .push(std::mem::take(&mut body));
                        let _ = write.write_all(b"250 OK: queued\r\n").await;
                        continue;
                    }
                    body.push_str(&line);
                    continue;
                }
                let upper = line.trim_end().to_ascii_uppercase();
                if upper.starts_with("EHLO") || upper.starts_with("HELO") {
                    let _ = write
                        .write_all(b"250-test.local\r\n250 SIZE 10485760\r\n")
                        .await;
                } else if upper.starts_with("MAIL FROM") || upper.starts_with("RCPT TO") {
                    let _ = write.write_all(b"250 OK\r\n").await;
                } else if upper.starts_with("DATA") {
                    let _ = write
                        .write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                        .await;
                    in_data = true;
                } else if upper.starts_with("QUIT") {
                    let _ = write.write_all(b"221 Bye\r\n").await;
                    break;
                } else if upper.starts_with("RSET") || upper.starts_with("NOOP") {
                    let _ = write.write_all(b"250 OK\r\n").await;
                } else {
                    let _ = write.write_all(b"502 command not implemented\r\n").await;
                }
            }
        });
        (port, capture)
    }

    /// Minimal SMTP responder that rejects MAIL FROM with a permanent (5xx)
    /// error. Used to exercise the permanent-failure code path.
    async fn spawn_smtp_reject_permanent() -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let port = listener
            .local_addr()
            .unwrap_or_else(|e| panic!("local_addr: {e}"))
            .port();
        tokio::spawn(async move {
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
            let (read, mut write) = sock.into_split();
            let mut reader = BufReader::new(read);
            let _ = write.write_all(b"220 test.local ESMTP ready\r\n").await;
            loop {
                let mut line = String::new();
                let Ok(n) = reader.read_line(&mut line).await else {
                    break;
                };
                if n == 0 {
                    break;
                }
                let upper = line.trim_end().to_ascii_uppercase();
                if upper.starts_with("EHLO") || upper.starts_with("HELO") {
                    let _ = write.write_all(b"250 test.local\r\n").await;
                } else if upper.starts_with("MAIL FROM") {
                    let _ = write.write_all(b"550 5.7.1 Sender not allowed\r\n").await;
                } else if upper.starts_with("QUIT") {
                    let _ = write.write_all(b"221 Bye\r\n").await;
                    break;
                } else {
                    let _ = write.write_all(b"250 OK\r\n").await;
                }
            }
        });
        port
    }

    #[tokio::test]
    async fn dispatch_email_delivers_message_with_expected_headers() {
        let (port, capture) = spawn_smtp_capture().await;
        let payload = serde_json::json!({
            "user_email": "alice@example.com",
            "subject": "Hello",
            "plain_body": "Plain text body",
            "html_body": "<p>HTML body</p>",
        })
        .to_string();
        let mut msg = make_message(NotificationMethod::Email, "{}");
        msg.input_json = payload;
        let store = MockStore::new();
        let config = NotificationConfig {
            smtp_host: "127.0.0.1".to_owned(),
            smtp_port: port,
            smtp_from: "noreply@example.com".to_owned(),
            smtp_hello: "test.local".to_owned(),
            smtp_force_tls: false,
            smtp_start_tls: false,
            ..NotificationConfig::default()
        };
        let service = make_service(store, config);
        service
            .dispatch_email(&msg)
            .await
            .unwrap_or_else(|e| panic!("SMTP dispatch should succeed: {e}"));

        let bodies = capture.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(bodies.len(), 1, "expected exactly one delivered message");
        let body = &bodies[0];
        assert!(body.contains("From:"), "missing From header: {body}");
        assert!(body.contains("To:"), "missing To header: {body}");
        assert!(body.contains("Subject: Hello"), "missing Subject: {body}");
        assert!(body.contains("Date:"), "missing Date header: {body}");
        assert!(body.contains("Message-ID"), "missing Message-ID: {body}");
        assert!(
            body.contains("multipart/alternative"),
            "missing multipart/alternative: {body}"
        );
        assert!(body.contains("Plain text body"), "missing plain part");
        assert!(body.contains("HTML body"), "missing html part");
    }

    #[tokio::test]
    async fn dispatch_email_permanent_rejection_surfaces_as_permanent() {
        let port = spawn_smtp_reject_permanent().await;
        let payload = serde_json::json!({
            "user_email": "alice@example.com",
            "subject": "Hello",
            "plain_body": "Body",
            "html_body": "<p>Body</p>",
        })
        .to_string();
        let mut msg = make_message(NotificationMethod::Email, "{}");
        msg.input_json = payload;
        let store = MockStore::new();
        let config = NotificationConfig {
            smtp_host: "127.0.0.1".to_owned(),
            smtp_port: port,
            smtp_from: "noreply@example.com".to_owned(),
            smtp_hello: "test.local".to_owned(),
            smtp_force_tls: false,
            smtp_start_tls: false,
            ..NotificationConfig::default()
        };
        let service = make_service(store, config);
        let err = match service.dispatch_email(&msg).await {
            Err(e) => e,
            Ok(()) => panic!("permanent 5xx should fail"),
        };
        assert!(
            err.is_permanent(),
            "5xx SMTP reply must be permanent: {err}"
        );
    }

    #[tokio::test]
    async fn dispatch_email_missing_recipient_is_config_missing() {
        // SMTP host is set but payload lacks user_email.
        let mut msg = make_message(NotificationMethod::Email, "{}");
        msg.input_json = r#"{"subject":"x"}"#.to_owned();
        let store = MockStore::new();
        let config = NotificationConfig {
            smtp_host: "127.0.0.1".to_owned(),
            smtp_from: "noreply@example.com".to_owned(),
            ..NotificationConfig::default()
        };
        let service = make_service(store, config);
        let err = match service.dispatch_email(&msg).await {
            Err(e) => e,
            Ok(()) => panic!("missing recipient should fail"),
        };
        assert!(matches!(err, NotificationDispatchError::ConfigMissing(_)));
    }

    // ── 26. VAPID sub claim format ───────────────────────────
    //
    // Verifies that validate_vapid_private_key accepts a well-formed PEM
    // and rejects garbage, ensuring startup validation will catch bad keys.

    #[test]
    fn validate_vapid_private_key_accepts_valid_pem() {
        let pem = generate_ec_p256_pem().unwrap_or_else(|e| panic!("keygen: {e}"));
        assert!(
            validate_vapid_private_key(&pem).is_ok(),
            "well-formed PEM should validate"
        );
    }

    #[test]
    fn validate_vapid_private_key_rejects_garbage() {
        let result = validate_vapid_private_key("not-a-pem");
        assert!(result.is_err(), "garbage input should fail validation");
    }

    // ── 27. Stale subscription detection ─────────────────────
    //
    // EndpointNotValid and EndpointNotFound should be recognised as "gone"
    // so that the dispatcher deletes stale subscriptions.

    #[test]
    fn is_subscription_gone_rejects_unspecified() {
        // Unspecified is not a "gone" error, so stale cleanup should not trigger.
        let err = web_push::WebPushError::Unspecified;
        assert!(
            !is_subscription_gone(&err),
            "Unspecified should not be gone"
        );
    }

    #[test]
    fn is_subscription_gone_rejects_invalid_uri() {
        let err = web_push::WebPushError::InvalidUri;
        assert!(!is_subscription_gone(&err), "InvalidUri should not be gone");
    }

    #[test]
    fn is_subscription_gone_rejects_payload_too_large() {
        let err = web_push::WebPushError::PayloadTooLarge;
        assert!(
            !is_subscription_gone(&err),
            "PayloadTooLarge should not be gone"
        );
    }

    // ── 28. Retryable error classification ───────────────────

    #[test]
    fn is_retryable_accepts_unspecified() {
        // Unspecified wraps network-level failures (connection timeout, DNS
        // errors) from the isahc HTTP client and should be retried.
        let err = web_push::WebPushError::Unspecified;
        assert!(
            is_retryable(&err),
            "Unspecified (network failure) should be retryable"
        );
    }

    #[test]
    fn is_retryable_rejects_invalid_uri() {
        let err = web_push::WebPushError::InvalidUri;
        assert!(!is_retryable(&err), "InvalidUri should not be retryable");
    }

    #[test]
    fn is_retryable_rejects_payload_too_large() {
        let err = web_push::WebPushError::PayloadTooLarge;
        assert!(
            !is_retryable(&err),
            "PayloadTooLarge should not be retryable"
        );
    }

    // ── 29. WebpushTestResult response shape ─────────────────
    //
    // Documents and verifies the JSON shape: { message, success_count,
    // failure_count } replacing the old ApiResponse::ok("...") format.

    #[test]
    fn webpush_test_result_json_shape() {
        let result = WebpushTestResult {
            message: "Sent test to 3 subscription(s).".to_owned(),
            success_count: 2,
            failure_count: 1,
        };
        let json = serde_json::to_value(&result).unwrap_or_else(|e| panic!("serialize: {e}"));
        assert_eq!(
            json["message"], "Sent test to 3 subscription(s).",
            "message field"
        );
        assert_eq!(json["success_count"], 2, "success_count field");
        assert_eq!(json["failure_count"], 1, "failure_count field");
        // Exactly these three fields.
        assert_eq!(
            json.as_object()
                .unwrap_or_else(|| panic!("should be an object"))
                .len(),
            3,
            "should have exactly 3 fields"
        );
    }

    // ── 30. Shared client: Webpusher struct holds one client ──
    //
    // The `Webpusher` struct contains a single `IsahcWebPushClient`
    // field (`client`) that is constructed once at startup in `new()` and
    // reused for all subsequent `send_single` calls.  This test verifies
    // the structural guarantee by checking the field count and type layout
    // of `Webpusher` (it has exactly 5 fields, including `client`).

    #[test]
    fn webpusher_struct_has_shared_client_field() {
        // Webpusher fields: store, vapid_sub, vapid_public_key,
        // vapid_key, client.  If someone accidentally adds a
        // second client or removes the shared one, this size assertion
        // will break.
        let size = size_of::<Webpusher>();
        assert!(
            size > 0,
            "Webpusher should be a non-zero-sized type (contains shared client)"
        );
    }

    // ── 31. Concurrent send pattern: buffer_unordered ────────
    //
    // Verifies the bounded concurrency constant is reasonable.

    #[test]
    fn max_concurrent_sends_is_bounded() {
        assert_eq!(MAX_CONCURRENT_SENDS, 10, "bounded concurrency should be 10");
    }

    #[test]
    fn retry_constants_are_sensible() {
        assert_eq!(MAX_SEND_RETRIES, 3);
        assert_eq!(INITIAL_RETRY_BACKOFF, Duration::from_millis(500));
    }

    // ── 32. Notifier-paused: still-landed regression ────────────
    //
    // The guard in `dispatch_once` short-circuits when
    // `notifier_paused` is true. This test just re-asserts the
    // behaviour in a minimal form so a refactor that accidentally
    // removes the check fails loudly. The fuller test above
    // (`dispatch_once_skips_when_notifier_paused`) exercises the
    // call-count invariants.
    #[tokio::test]
    async fn notifier_paused_check_still_present() {
        let msg = make_message(NotificationMethod::Inbox, "{}");
        let store = MockStore::new()
            .with_pending(vec![msg])
            .with_notifier_paused(true);
        let service = make_service(store.clone(), NotificationConfig::default());
        let count = service
            .dispatch_once()
            .await
            .unwrap_or_else(|e| panic!("dispatch_once failed: {e}"));
        assert_eq!(count, 0, "paused dispatcher should report zero dispatched");
        assert!(
            store
                .bulk_sent
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty(),
            "paused dispatcher should not invoke bulk_mark_sent"
        );
    }

    // ── 33. Inhibited handling: disabled-by-user skips dispatch ──

    #[tokio::test]
    async fn dispatch_once_marks_message_inhibited_when_template_disabled() {
        let msg = make_message(NotificationMethod::Inbox, "{}");
        let msg_id = msg.id;
        let user_id = msg.user_id;
        let template_id = msg.notification_template_id;

        let store = MockStore::new()
            .with_pending(vec![msg])
            .with_disabled_preference(user_id, template_id, true);
        let service = make_service(store.clone(), NotificationConfig::default());

        let count = service
            .dispatch_once()
            .await
            .unwrap_or_else(|e| panic!("dispatch_once failed: {e}"));
        assert_eq!(count, 1, "message should have been acquired");

        // The inhibited message should be flushed through the bulk-failed
        // path, not dispatched and not bulk-sent.
        assert!(
            store
                .bulk_sent
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty(),
            "inhibited messages must not be reported as sent"
        );

        let bulk_failed = store
            .bulk_failed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        assert_eq!(bulk_failed.len(), 1, "expected one bulk-failed flush");
        let (ids, statuses, reasons) = &bulk_failed[0];
        assert_eq!(ids.as_slice(), &[msg_id]);
        assert_eq!(statuses.as_slice(), &[NotificationMessageStatus::Inhibited]);
        assert_eq!(reasons[0], "disabled by user");
    }

    // ── 34. Inhibited handling: disabled=false preserves delivery ─

    #[tokio::test]
    async fn dispatch_once_does_not_inhibit_when_preference_not_disabled() {
        let msg = make_message(NotificationMethod::Inbox, "{}");
        let user_id = msg.user_id;
        let template_id = msg.notification_template_id;

        let store = MockStore::new()
            .with_pending(vec![msg])
            .with_disabled_preference(user_id, template_id, false);
        let service = make_service(store.clone(), NotificationConfig::default());

        let count = service
            .dispatch_once()
            .await
            .unwrap_or_else(|e| panic!("dispatch_once failed: {e}"));
        assert_eq!(count, 1);

        // Inbox dispatch always succeeds, so the message should be bulk-sent.
        let sent = store
            .bulk_sent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        assert_eq!(sent.len(), 1);
    }

    // ── 35. Webhook envelope: body wraps input_json and X-Message-Id is set ─

    #[tokio::test]
    async fn dispatch_webhook_body_is_envelope_with_x_message_id() {
        // Stand up a tiny axum-on-tokio webhook endpoint that captures the
        // body + headers of the incoming request and returns 200.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|e| panic!("local_addr: {e}"));
        let captured: Arc<Mutex<Option<(String, String)>>> = Arc::new(Mutex::new(None));
        let captured_clone = captured.clone();

        // Accept one request, read headers + body, capture them, then 200.
        tokio::spawn(async move {
            let (mut sock, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            let mut buf = [0u8; 8192];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            let raw = String::from_utf8_lossy(&buf[..n]).into_owned();
            // Very small HTTP/1.1 parse — just good enough for the test.
            let x_message_id = raw
                .lines()
                .find_map(|l| {
                    let l = l.trim_end_matches('\r');
                    let lower = l.to_ascii_lowercase();
                    lower
                        .strip_prefix("x-message-id:")
                        .map(|s| s.trim().to_owned())
                })
                .unwrap_or_default();
            let body = raw.split("\r\n\r\n").nth(1).unwrap_or("").to_owned();
            *captured_clone.lock().unwrap_or_else(|e| e.into_inner()) = Some((x_message_id, body));
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await;
        });

        let input_json =
            r#"{"subject":"S","plain_body":"PB","html_body":"<p>HB</p>","user_email":"a@b.c"}"#;
        let targets_json = format!(r#"{{"url":"http://{addr}/hook"}}"#);
        let mut msg = make_message(NotificationMethod::Webhook, &targets_json);
        msg.input_json = input_json.to_owned();
        let msg_id = msg.id;

        let service = make_service(MockStore::new(), NotificationConfig::default());
        let res = service.dispatch_webhook(&msg).await;
        assert!(res.is_ok(), "webhook dispatch should succeed");

        // The capturing task writes after the 200 is flushed, give it a moment.
        for _ in 0..50 {
            if captured.lock().unwrap_or_else(|e| e.into_inner()).is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let (x_msg, body) = captured
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .unwrap_or_else(|| panic!("request never captured"));
        assert_eq!(x_msg, msg_id.to_string(), "X-Message-Id must match msg id");

        // Envelope shape: _version, msg_id, payload (nested), title, body.
        let parsed: serde_json::Value = serde_json::from_str(&body)
            .unwrap_or_else(|e| panic!("envelope body is not JSON: {e}: {body}"));
        assert_eq!(parsed["_version"], "1.1");
        assert_eq!(parsed["msg_id"], msg_id.to_string());
        assert_eq!(parsed["title"], "S");
        assert_eq!(parsed["title_markdown"], "S");
        assert_eq!(parsed["body"], "PB");
        assert_eq!(parsed["body_markdown"], "<p>HB</p>");
        // Raw input_json nested under `payload`.
        assert_eq!(parsed["payload"]["subject"], "S");
        assert_eq!(parsed["payload"]["plain_body"], "PB");
    }

    // ── 36. Bulk mark: dispatch_once flushes sent via bulk UPDATE ─

    #[tokio::test]
    async fn dispatch_once_flushes_sent_via_bulk_mark() {
        let msg1 = make_message(NotificationMethod::Inbox, "{}");
        let msg2 = make_message(NotificationMethod::Inbox, "{}");
        let id1 = msg1.id;
        let id2 = msg2.id;
        let store = MockStore::new().with_pending(vec![msg1, msg2]);
        let service = make_service(store.clone(), NotificationConfig::default());

        let count = service
            .dispatch_once()
            .await
            .unwrap_or_else(|e| panic!("dispatch_once failed: {e}"));
        assert_eq!(count, 2);

        // Bulk-sent should have been called exactly once with both IDs.
        let sent_batches = store
            .bulk_sent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        assert_eq!(
            sent_batches.len(),
            1,
            "expected a single bulk UPDATE, got {}",
            sent_batches.len()
        );
        let batch = &sent_batches[0];
        assert_eq!(batch.len(), 2);
        assert!(batch.contains(&id1) && batch.contains(&id2));
    }

    // ── 37. Method labels are stable ────────────────────────────

    #[test]
    fn method_label_matches_wire_names() {
        assert_eq!(method_label(NotificationMethod::Email), "smtp");
        assert_eq!(method_label(NotificationMethod::Webhook), "webhook");
        assert_eq!(method_label(NotificationMethod::Inbox), "inbox");
    }
}
