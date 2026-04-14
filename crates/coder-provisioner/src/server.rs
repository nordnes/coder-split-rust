//! WebSocket-based provisioner daemon server.
//!
//! Provisioner daemons connect over WebSocket and exchange JSON messages to
//! acquire jobs, report progress, and complete/fail jobs.  This module
//! implements the server-side message loop that drives the job lifecycle.
//!
//! The server is transport-agnostic: it communicates through a pair of
//! [`tokio::sync::mpsc`] channels.  The WebSocket adapter in `coder-server`
//! bridges from the underlying socket to these channels.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use coder_core::provisioner::{
    LogLevel, LogSource, ProvisionerJobStatus, ProvisionerJobTimingStage, ProvisionerType,
};
use coder_core::{
    AcquireProvisionerJobInput, CancelProvisionerJobInput, CompleteProvisionerJobInput,
    InsertProvisionerJobLogsInput, InsertProvisionerJobTimingsInput, ProvisionerJobRecord,
    ProvisionerStore, UpsertProvisionerDaemonInput,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

// ── Configuration ────────────────────────────────────────────

/// Default interval between daemon heartbeats.
const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

/// Default interval for checking job cancellation status.
const DEFAULT_CANCEL_CHECK_INTERVAL: Duration = Duration::from_secs(5);

// ── Wire protocol types ─────────────────────────────────────

/// Messages sent from the provisioner daemon to the server.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DaemonMessage {
    /// Request to acquire a pending job.
    AcquireJob,
    /// Heartbeat to keep the connection alive and update job heartbeat.
    Heartbeat,
    /// Report logs for the current job.
    JobLogs {
        /// Log entries to insert.
        logs: Vec<JobLogEntry>,
    },
    /// Report timing entries for the current job.
    JobTimings {
        /// Timing entries to insert.
        timings: Vec<JobTimingEntry>,
    },
    /// Mark the current job as completed (success or failure).
    CompleteJob {
        /// Error message; empty string means success.
        error: String,
        /// Machine-readable error code.
        #[serde(default)]
        error_code: String,
    },
    /// Acknowledge a cancellation request.
    CancelComplete,
}

/// Messages sent from the server to the provisioner daemon.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    /// A job has been acquired and assigned to this daemon.
    JobAssigned {
        /// The acquired job record.
        job: JobInfo,
    },
    /// No job is currently available.
    NoJob,
    /// Heartbeat acknowledgement.
    HeartbeatAck,
    /// The current job has been requested for cancellation.
    JobCanceled {
        /// The job that should be canceled.
        job_id: Uuid,
    },
    /// Logs were accepted.
    LogsAccepted {
        /// Number of log entries accepted.
        count: usize,
    },
    /// Timings were accepted.
    TimingsAccepted {
        /// Number of timing entries accepted.
        count: usize,
    },
    /// Job completion acknowledged.
    JobCompleteAck,
    /// An error occurred processing a daemon message.
    Error {
        /// Human-readable error message.
        message: String,
    },
}

/// Serializable job information sent to the daemon.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JobInfo {
    /// Job identifier.
    pub id: Uuid,
    /// Creation time (ISO 8601).
    pub created_at: String,
    /// Organization scope.
    pub organization_id: Option<Uuid>,
    /// Provisioner technology.
    pub provisioner: String,
    /// Kind of provisioner job.
    pub job_type: String,
    /// Structured input for the job.
    pub input: Value,
    /// Reference to the stored file.
    pub file_id: Option<Uuid>,
    /// Free-form tags for daemon matching.
    pub tags: Value,
}

impl From<&ProvisionerJobRecord> for JobInfo {
    fn from(job: &ProvisionerJobRecord) -> Self {
        Self {
            id: job.id,
            created_at: job.created_at.to_string(),
            organization_id: job.organization_id,
            provisioner: job.provisioner.to_string(),
            job_type: job.job_type.to_string(),
            input: job.input.clone(),
            file_id: job.file_id,
            tags: job.tags.clone(),
        }
    }
}

/// A single log entry from the daemon.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JobLogEntry {
    /// Source of the log entry.
    pub source: String,
    /// Severity level.
    pub level: String,
    /// Build stage label.
    pub stage: String,
    /// Log output text.
    pub output: String,
}

/// A single timing entry from the daemon.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JobTimingEntry {
    /// Timing start (ISO 8601).
    pub started_at: String,
    /// Timing end (ISO 8601).
    pub ended_at: String,
    /// Build stage.
    pub stage: String,
    /// Source identifier.
    pub source: String,
    /// Action performed.
    pub action: String,
    /// Resource acted upon.
    pub resource: String,
}

/// Registration details sent by the daemon when connecting.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DaemonRegistration {
    /// Daemon name.
    pub name: String,
    /// Running version.
    pub version: String,
    /// Provisioner API version.
    pub api_version: String,
    /// Supported provisioner types (e.g. `["terraform"]`).
    pub provisioners: Vec<String>,
    /// Free-form tags the daemon advertises.
    pub tags: HashMap<String, String>,
    /// Organization scope.
    pub organization_id: Uuid,
    /// Optional provisioner key used for authentication.
    pub key_id: Option<Uuid>,
}

// ── Server configuration ────────────────────────────────────

/// Configuration for the provisioner daemon server.
#[derive(Clone, Debug)]
pub struct DaemonServerConfig {
    /// Interval between daemon heartbeats sent to the store.
    pub heartbeat_interval: Duration,
    /// Interval for polling job cancellation status.
    pub cancel_check_interval: Duration,
}

impl Default for DaemonServerConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval: DEFAULT_HEARTBEAT_INTERVAL,
            cancel_check_interval: DEFAULT_CANCEL_CHECK_INTERVAL,
        }
    }
}

// ── Server implementation ───────────────────────────────────

/// Errors returned by the provisioner daemon server.
#[derive(Debug, thiserror::Error)]
pub enum DaemonServerError {
    /// A storage operation failed.
    #[error("storage: {0}")]
    Storage(#[from] coder_core::StorageError),
    /// Channel communication error.
    #[error("channel: {0}")]
    Channel(String),
    /// JSON serialization/deserialization error.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    /// The daemon sent an invalid message.
    #[error("protocol: {0}")]
    Protocol(String),
}

/// Result of processing a single daemon message.
pub enum MessageResult {
    /// Continue the message loop.
    Continue,
    /// The connection should be closed.
    Close,
}

/// Runs the provisioner daemon server loop for a single connected daemon.
///
/// This function handles the full lifecycle of a daemon connection:
/// 1. Registers (upserts) the daemon
/// 2. Enters a message loop processing daemon requests via `tokio::select!`
/// 3. Handles job acquisition, heartbeats, log/timing insertion, completion
///
/// Communication happens through `mpsc` channels:
/// - `incoming_rx`: receives [`DaemonMessage`]s from the transport layer
/// - `outgoing_tx`: sends [`ServerMessage`]s to the transport layer
///
/// The function returns when the connection is closed, the incoming channel
/// is dropped, or an unrecoverable error occurs.
pub async fn run_daemon_session<S: ProvisionerStore + ?Sized>(
    store: Arc<S>,
    registration: DaemonRegistration,
    config: DaemonServerConfig,
    mut incoming_rx: mpsc::Receiver<DaemonMessage>,
    outgoing_tx: mpsc::Sender<ServerMessage>,
) -> Result<(), DaemonServerError> {
    // 1. Register the daemon.
    let daemon = store
        .upsert_provisioner_daemon(UpsertProvisionerDaemonInput {
            name: registration.name.clone(),
            provisioners: registration.provisioners.clone(),
            tags: registration.tags.clone(),
            last_seen_at: OffsetDateTime::now_utc(),
            version: registration.version.clone(),
            organization_id: registration.organization_id,
            api_version: registration.api_version.clone(),
            key_id: registration.key_id,
        })
        .await?;

    info!(
        daemon_id = %daemon.id,
        daemon_name = %daemon.name,
        "provisioner daemon connected"
    );

    let mut current_job: Option<ProvisionerJobRecord> = None;

    // Parse the provisioner types for acquisition.
    let provisioner_types: Vec<ProvisionerType> = registration
        .provisioners
        .iter()
        .filter_map(|s| match s.as_str() {
            "terraform" => Some(ProvisionerType::Terraform),
            "echo" => Some(ProvisionerType::Echo),
            _ => None,
        })
        .collect();

    let tags_json = serde_json::to_value(&registration.tags)?;

    // 2. Message loop with periodic heartbeat and cancellation checks.
    let mut heartbeat_timer = tokio::time::interval(config.heartbeat_interval);
    // The first tick completes immediately; consume it.
    heartbeat_timer.tick().await;

    let mut cancel_check_timer = tokio::time::interval(config.cancel_check_interval);
    cancel_check_timer.tick().await;

    loop {
        tokio::select! {
            // --- Incoming message from the daemon ---
            msg = incoming_rx.recv() => {
                let Some(msg) = msg else {
                    info!(daemon_id = %daemon.id, "daemon disconnected (channel closed)");
                    break;
                };

                match handle_daemon_message(
                    &store,
                    &daemon.id,
                    &registration,
                    &provisioner_types,
                    &tags_json,
                    &mut current_job,
                    msg,
                    &outgoing_tx,
                )
                .await
                {
                    Ok(MessageResult::Continue) => {}
                    Ok(MessageResult::Close) => break,
                    Err(e) => {
                        error!(daemon_id = %daemon.id, error = %e, "error handling message");
                        let error_msg = ServerMessage::Error {
                            message: e.to_string(),
                        };
                        if outgoing_tx.send(error_msg).await.is_err() {
                            break;
                        }
                    }
                }
            }

            // --- Periodic heartbeat ---
            _ = heartbeat_timer.tick() => {
                if let Err(e) = store
                    .update_provisioner_daemon_last_seen_at(daemon.id, OffsetDateTime::now_utc())
                    .await
                {
                    warn!(daemon_id = %daemon.id, error = %e, "failed to update daemon heartbeat");
                }

                if let Some(ref job) = current_job {
                    if let Err(e) = store
                        .update_provisioner_job_by_id(job.id, OffsetDateTime::now_utc())
                        .await
                    {
                        warn!(
                            daemon_id = %daemon.id,
                            job_id = %job.id,
                            error = %e,
                            "failed to update job heartbeat"
                        );
                    }
                }
            }

            // --- Periodic cancellation check for active job ---
            _ = cancel_check_timer.tick(), if current_job.is_some() => {
                if let Some(ref job) = current_job {
                    match store.get_provisioner_job_by_id(job.id).await {
                        Ok(Some(refreshed)) => {
                            if refreshed.canceled_at.is_some()
                                && refreshed.job_status == ProvisionerJobStatus::Canceling
                            {
                                debug!(
                                    daemon_id = %daemon.id,
                                    job_id = %job.id,
                                    "job cancellation detected, notifying daemon"
                                );
                                if outgoing_tx.send(ServerMessage::JobCanceled { job_id: job.id }).await.is_err() {
                                    break;
                                }
                            }
                        }
                        Ok(None) => {
                            warn!(
                                daemon_id = %daemon.id,
                                job_id = %job.id,
                                "active job disappeared from store"
                            );
                            current_job = None;
                        }
                        Err(e) => {
                            warn!(
                                daemon_id = %daemon.id,
                                job_id = %job.id,
                                error = %e,
                                "failed to check job cancellation status"
                            );
                        }
                    }
                }
            }
        }
    }

    info!(daemon_id = %daemon.id, "daemon session ended");
    Ok(())
}

/// Handles a single message from the daemon.
#[allow(clippy::too_many_arguments)]
async fn handle_daemon_message<S: ProvisionerStore + ?Sized>(
    store: &Arc<S>,
    daemon_id: &Uuid,
    registration: &DaemonRegistration,
    provisioner_types: &[ProvisionerType],
    tags_json: &Value,
    current_job: &mut Option<ProvisionerJobRecord>,
    msg: DaemonMessage,
    outgoing_tx: &mpsc::Sender<ServerMessage>,
) -> Result<MessageResult, DaemonServerError> {
    match msg {
        DaemonMessage::AcquireJob => {
            if current_job.is_some() {
                send_msg(
                    outgoing_tx,
                    ServerMessage::Error {
                        message: "already have an active job".to_string(),
                    },
                )
                .await?;
                return Ok(MessageResult::Continue);
            }

            let result = store
                .acquire_provisioner_job(AcquireProvisionerJobInput {
                    worker_id: *daemon_id,
                    started_at: OffsetDateTime::now_utc(),
                    organization_id: registration.organization_id,
                    types: provisioner_types.to_vec(),
                    provisioner_tags: tags_json.clone(),
                })
                .await?;

            match result {
                Some(job) => {
                    debug!(
                        daemon_id = %daemon_id,
                        job_id = %job.id,
                        "job acquired"
                    );
                    let info = JobInfo::from(&job);
                    *current_job = Some(job);
                    send_msg(outgoing_tx, ServerMessage::JobAssigned { job: info }).await?;
                }
                None => {
                    send_msg(outgoing_tx, ServerMessage::NoJob).await?;
                }
            }
        }

        DaemonMessage::Heartbeat => {
            // Update daemon heartbeat.
            if let Err(e) = store
                .update_provisioner_daemon_last_seen_at(*daemon_id, OffsetDateTime::now_utc())
                .await
            {
                warn!(daemon_id = %daemon_id, error = %e, "failed to update daemon heartbeat");
            }

            // Update active job heartbeat.
            if let Some(job) = current_job.as_ref() {
                if let Err(e) = store
                    .update_provisioner_job_by_id(job.id, OffsetDateTime::now_utc())
                    .await
                {
                    warn!(
                        daemon_id = %daemon_id,
                        job_id = %job.id,
                        error = %e,
                        "failed to update job heartbeat"
                    );
                }
            }

            send_msg(outgoing_tx, ServerMessage::HeartbeatAck).await?;
        }

        DaemonMessage::JobLogs { logs } => {
            let Some(job) = current_job.as_ref() else {
                send_msg(
                    outgoing_tx,
                    ServerMessage::Error {
                        message: "no active job for log insertion".to_string(),
                    },
                )
                .await?;
                return Ok(MessageResult::Continue);
            };

            let count = logs.len();
            let now = OffsetDateTime::now_utc();

            let input = InsertProvisionerJobLogsInput {
                job_id: job.id,
                created_at: vec![now; count],
                source: logs.iter().map(|l| parse_log_source(&l.source)).collect(),
                level: logs.iter().map(|l| parse_log_level(&l.level)).collect(),
                stage: logs.iter().map(|l| l.stage.clone()).collect(),
                output: logs.iter().map(|l| l.output.clone()).collect(),
            };

            store.insert_provisioner_job_logs(input).await?;
            send_msg(outgoing_tx, ServerMessage::LogsAccepted { count }).await?;
        }

        DaemonMessage::JobTimings { timings } => {
            let Some(job) = current_job.as_ref() else {
                send_msg(
                    outgoing_tx,
                    ServerMessage::Error {
                        message: "no active job for timing insertion".to_string(),
                    },
                )
                .await?;
                return Ok(MessageResult::Continue);
            };

            let count = timings.len();

            let input = InsertProvisionerJobTimingsInput {
                job_id: job.id,
                started_at: timings
                    .iter()
                    .map(|t| parse_timestamp(&t.started_at))
                    .collect(),
                ended_at: timings
                    .iter()
                    .map(|t| parse_timestamp(&t.ended_at))
                    .collect(),
                stage: timings
                    .iter()
                    .map(|t| parse_timing_stage(&t.stage))
                    .collect(),
                source: timings.iter().map(|t| t.source.clone()).collect(),
                action: timings.iter().map(|t| t.action.clone()).collect(),
                resource: timings.iter().map(|t| t.resource.clone()).collect(),
            };

            store.insert_provisioner_job_timings(input).await?;
            send_msg(outgoing_tx, ServerMessage::TimingsAccepted { count }).await?;
        }

        DaemonMessage::CompleteJob { error, error_code } => {
            let Some(job) = current_job.as_ref() else {
                send_msg(
                    outgoing_tx,
                    ServerMessage::Error {
                        message: "no active job to complete".to_string(),
                    },
                )
                .await?;
                return Ok(MessageResult::Continue);
            };

            let now = OffsetDateTime::now_utc();
            store
                .update_provisioner_job_with_complete_by_id(CompleteProvisionerJobInput {
                    id: job.id,
                    updated_at: now,
                    completed_at: now,
                    error: error.clone(),
                    error_code,
                })
                .await?;

            info!(
                daemon_id = %daemon_id,
                job_id = %job.id,
                success = error.is_empty(),
                "job completed"
            );

            *current_job = None;
            send_msg(outgoing_tx, ServerMessage::JobCompleteAck).await?;
        }

        DaemonMessage::CancelComplete => {
            let Some(job) = current_job.as_ref() else {
                send_msg(
                    outgoing_tx,
                    ServerMessage::Error {
                        message: "no active job to cancel".to_string(),
                    },
                )
                .await?;
                return Ok(MessageResult::Continue);
            };

            let now = OffsetDateTime::now_utc();
            store
                .update_provisioner_job_with_cancel_by_id(CancelProvisionerJobInput {
                    id: job.id,
                    canceled_at: now,
                    completed_at: Some(now),
                })
                .await?;

            info!(
                daemon_id = %daemon_id,
                job_id = %job.id,
                "job canceled by daemon"
            );

            *current_job = None;
            send_msg(outgoing_tx, ServerMessage::JobCompleteAck).await?;
        }
    }

    Ok(MessageResult::Continue)
}

/// Sends a server message through the outgoing channel.
async fn send_msg(
    tx: &mpsc::Sender<ServerMessage>,
    msg: ServerMessage,
) -> Result<(), DaemonServerError> {
    tx.send(msg)
        .await
        .map_err(|e| DaemonServerError::Channel(e.to_string()))
}

// ── Parsing helpers ─────────────────────────────────────────

/// Parses a log source string into the enum.
fn parse_log_source(s: &str) -> LogSource {
    match s {
        "provisioner_daemon" => LogSource::ProvisionerDaemon,
        "provisioner" => LogSource::Provisioner,
        _ => LogSource::Provisioner,
    }
}

/// Parses a log level string into the enum.
fn parse_log_level(s: &str) -> LogLevel {
    match s {
        "trace" => LogLevel::Trace,
        "debug" => LogLevel::Debug,
        "info" => LogLevel::Info,
        "warn" => LogLevel::Warn,
        "error" => LogLevel::Error,
        _ => LogLevel::Info,
    }
}

/// Parses a timing stage string into the enum.
fn parse_timing_stage(s: &str) -> ProvisionerJobTimingStage {
    match s {
        "init" => ProvisionerJobTimingStage::Init,
        "plan" => ProvisionerJobTimingStage::Plan,
        "graph" => ProvisionerJobTimingStage::Graph,
        "apply" => ProvisionerJobTimingStage::Apply,
        _ => ProvisionerJobTimingStage::Init,
    }
}

/// Parses an ISO 8601 timestamp string, falling back to `now_utc()` on failure.
fn parse_timestamp(s: &str) -> OffsetDateTime {
    OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| OffsetDateTime::now_utc())
}

#[cfg(test)]
mod tests {
    use super::*;
    use coder_core::provisioner::{
        ProvisionerJobLogRecord as ProvisionerLogRecord,
        ProvisionerJobTimingRecord as ProvisionerTimingRecord,
    };
    use coder_core::{
        GetJobsToBeReapedInput, InsertProvisionerJobInput, InsertProvisionerKeyInput,
        ProvisionerDaemonRecord, ProvisionerKeyRecord, StorageError,
    };
    use std::sync::Mutex;

    // ── Test store ─────────────────────────────────────────

    /// In-memory store for testing the daemon server.
    struct TestStore {
        jobs: Mutex<HashMap<Uuid, ProvisionerJobRecord>>,
        daemons: Mutex<HashMap<Uuid, ProvisionerDaemonRecord>>,
        logs: Mutex<Vec<ProvisionerLogRecord>>,
        log_next_id: Mutex<i64>,
        timings: Mutex<Vec<ProvisionerTimingRecord>>,
        keys: Mutex<HashMap<Uuid, ProvisionerKeyRecord>>,
    }

    impl TestStore {
        fn new() -> Self {
            Self {
                jobs: Mutex::new(HashMap::new()),
                daemons: Mutex::new(HashMap::new()),
                logs: Mutex::new(Vec::new()),
                log_next_id: Mutex::new(1),
                timings: Mutex::new(Vec::new()),
                keys: Mutex::new(HashMap::new()),
            }
        }

        fn insert_test_job(&self, job: ProvisionerJobRecord) {
            let mut jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
            jobs.insert(job.id, job);
        }
    }

    fn lock_or_err<T>(guard: &Mutex<T>) -> Result<std::sync::MutexGuard<'_, T>, StorageError> {
        guard
            .lock()
            .map_err(|e| StorageError::unavailable(e.to_string()))
    }

    #[async_trait::async_trait]
    impl ProvisionerStore for TestStore {
        async fn acquire_provisioner_job(
            &self,
            input: AcquireProvisionerJobInput,
        ) -> Result<Option<ProvisionerJobRecord>, StorageError> {
            let mut jobs = lock_or_err(&self.jobs)?;

            let mut candidates: Vec<(Uuid, OffsetDateTime)> = jobs
                .values()
                .filter(|j| {
                    j.job_status == ProvisionerJobStatus::Pending
                        && j.started_at.is_none()
                        && j.completed_at.is_none()
                        && j.canceled_at.is_none()
                        && j.organization_id == Some(input.organization_id)
                        && input.types.contains(&j.provisioner)
                })
                .map(|j| (j.id, j.created_at))
                .collect();

            candidates.sort_by_key(|(_, created_at)| *created_at);

            let job_id = match candidates.first() {
                Some((id, _)) => *id,
                None => return Ok(None),
            };

            let job = jobs
                .get_mut(&job_id)
                .ok_or_else(|| StorageError::unavailable("concurrent modification"))?;
            job.job_status = ProvisionerJobStatus::Running;
            job.started_at = Some(input.started_at);
            job.updated_at = input.started_at;
            job.worker_id = Some(input.worker_id);
            Ok(Some(job.clone()))
        }

        async fn get_provisioner_job_by_id(
            &self,
            id: Uuid,
        ) -> Result<Option<ProvisionerJobRecord>, StorageError> {
            Ok(lock_or_err(&self.jobs)?.get(&id).cloned())
        }

        async fn get_provisioner_jobs_by_ids(
            &self,
            ids: &[Uuid],
        ) -> Result<Vec<ProvisionerJobRecord>, StorageError> {
            let jobs = lock_or_err(&self.jobs)?;
            Ok(ids.iter().filter_map(|id| jobs.get(id).cloned()).collect())
        }

        async fn insert_provisioner_job(
            &self,
            input: InsertProvisionerJobInput,
        ) -> Result<ProvisionerJobRecord, StorageError> {
            let record = ProvisionerJobRecord {
                id: input.id,
                created_at: input.created_at,
                updated_at: input.created_at,
                started_at: None,
                canceled_at: None,
                completed_at: None,
                error: String::new(),
                error_code: String::new(),
                organization_id: Some(input.organization_id),
                initiator_id: Some(input.initiator_id),
                provisioner: input.provisioner,
                storage_method: input.storage_method,
                file_id: Some(input.file_id),
                job_type: input.job_type,
                input: input.input,
                tags: input.tags,
                trace_metadata: input.trace_metadata,
                worker_id: None,
                job_status: ProvisionerJobStatus::Pending,
                logs_overflowed: false,
                logs_length: 0,
            };
            lock_or_err(&self.jobs)?.insert(record.id, record.clone());
            Ok(record)
        }

        async fn update_provisioner_job_by_id(
            &self,
            id: Uuid,
            updated_at: OffsetDateTime,
        ) -> Result<(), StorageError> {
            if let Some(job) = lock_or_err(&self.jobs)?.get_mut(&id) {
                job.updated_at = updated_at;
            }
            Ok(())
        }

        async fn update_provisioner_job_with_complete_by_id(
            &self,
            input: CompleteProvisionerJobInput,
        ) -> Result<(), StorageError> {
            if let Some(job) = lock_or_err(&self.jobs)?.get_mut(&input.id) {
                job.updated_at = input.updated_at;
                job.completed_at = Some(input.completed_at);
                job.error = input.error.clone();
                job.error_code = input.error_code.clone();
                job.job_status = if input.error.is_empty() {
                    ProvisionerJobStatus::Succeeded
                } else {
                    ProvisionerJobStatus::Failed
                };
            }
            Ok(())
        }

        async fn update_provisioner_job_with_cancel_by_id(
            &self,
            input: CancelProvisionerJobInput,
        ) -> Result<(), StorageError> {
            if let Some(job) = lock_or_err(&self.jobs)?.get_mut(&input.id) {
                job.canceled_at = Some(input.canceled_at);
                job.updated_at = input.canceled_at;
                if let Some(completed_at) = input.completed_at {
                    job.completed_at = Some(completed_at);
                    job.job_status = ProvisionerJobStatus::Canceled;
                } else {
                    job.job_status = ProvisionerJobStatus::Canceling;
                }
            }
            Ok(())
        }

        async fn get_provisioner_jobs_to_be_reaped(
            &self,
            _input: GetJobsToBeReapedInput,
        ) -> Result<Vec<ProvisionerJobRecord>, StorageError> {
            Ok(Vec::new())
        }

        async fn insert_provisioner_job_logs(
            &self,
            input: InsertProvisionerJobLogsInput,
        ) -> Result<Vec<ProvisionerLogRecord>, StorageError> {
            let count = input.created_at.len();
            let mut logs = lock_or_err(&self.logs)?;
            let mut next_id = lock_or_err(&self.log_next_id)?;
            let mut inserted = Vec::with_capacity(count);
            for i in 0..count {
                let record = ProvisionerLogRecord {
                    id: *next_id,
                    job_id: input.job_id,
                    created_at: input.created_at[i],
                    source: input.source[i],
                    level: input.level[i],
                    stage: input.stage[i].clone(),
                    output: input.output[i].clone(),
                };
                *next_id += 1;
                logs.push(record.clone());
                inserted.push(record);
            }
            Ok(inserted)
        }

        async fn get_provisioner_logs_after_id(
            &self,
            job_id: Uuid,
            after_id: i64,
        ) -> Result<Vec<ProvisionerLogRecord>, StorageError> {
            let logs = lock_or_err(&self.logs)?;
            Ok(logs
                .iter()
                .filter(|l| l.job_id == job_id && l.id > after_id)
                .cloned()
                .collect())
        }

        async fn insert_provisioner_job_timings(
            &self,
            input: InsertProvisionerJobTimingsInput,
        ) -> Result<Vec<ProvisionerTimingRecord>, StorageError> {
            let count = input.started_at.len();
            let mut timings = lock_or_err(&self.timings)?;
            let mut inserted = Vec::with_capacity(count);
            for i in 0..count {
                let record = ProvisionerTimingRecord {
                    job_id: input.job_id,
                    started_at: input.started_at[i],
                    ended_at: input.ended_at[i],
                    stage: input.stage[i],
                    source: input.source[i].clone(),
                    action: input.action[i].clone(),
                    resource: input.resource[i].clone(),
                };
                timings.push(record.clone());
                inserted.push(record);
            }
            Ok(inserted)
        }

        async fn get_provisioner_job_timings_by_job_id(
            &self,
            _job_id: Uuid,
        ) -> Result<Vec<ProvisionerTimingRecord>, StorageError> {
            Ok(Vec::new())
        }

        async fn upsert_provisioner_daemon(
            &self,
            input: UpsertProvisionerDaemonInput,
        ) -> Result<ProvisionerDaemonRecord, StorageError> {
            let record = ProvisionerDaemonRecord {
                id: Uuid::new_v4(),
                organization_id: input.organization_id,
                created_at: OffsetDateTime::now_utc(),
                last_seen_at: Some(input.last_seen_at),
                name: input.name,
                version: input.version,
                api_version: input.api_version,
                provisioners: input.provisioners,
                tags: input.tags,
                key_id: input.key_id,
            };
            lock_or_err(&self.daemons)?.insert(record.id, record.clone());
            Ok(record)
        }

        async fn update_provisioner_daemon_last_seen_at(
            &self,
            id: Uuid,
            last_seen_at: OffsetDateTime,
        ) -> Result<(), StorageError> {
            if let Some(daemon) = lock_or_err(&self.daemons)?.get_mut(&id) {
                daemon.last_seen_at = Some(last_seen_at);
            }
            Ok(())
        }

        async fn get_provisioner_daemons_by_organization(
            &self,
            organization_id: Uuid,
        ) -> Result<Vec<ProvisionerDaemonRecord>, StorageError> {
            let daemons = lock_or_err(&self.daemons)?;
            Ok(daemons
                .values()
                .filter(|d| d.organization_id == organization_id)
                .cloned()
                .collect())
        }

        async fn delete_old_provisioner_daemons(&self) -> Result<(), StorageError> {
            Ok(())
        }

        async fn insert_provisioner_key(
            &self,
            input: InsertProvisionerKeyInput,
        ) -> Result<ProvisionerKeyRecord, StorageError> {
            let record = ProvisionerKeyRecord {
                id: input.id,
                created_at: input.created_at,
                organization_id: input.organization_id,
                name: input.name,
                hashed_secret: input.hashed_secret,
                tags: input.tags,
            };
            lock_or_err(&self.keys)?.insert(record.id, record.clone());
            Ok(record)
        }

        async fn get_provisioner_key_by_id(
            &self,
            id: Uuid,
        ) -> Result<Option<ProvisionerKeyRecord>, StorageError> {
            Ok(lock_or_err(&self.keys)?.get(&id).cloned())
        }

        async fn get_provisioner_key_by_hashed_secret(
            &self,
            _hashed_secret: &[u8],
        ) -> Result<Option<ProvisionerKeyRecord>, StorageError> {
            Ok(None)
        }

        async fn get_provisioner_key_by_name(
            &self,
            _organization_id: Uuid,
            _name: &str,
        ) -> Result<Option<ProvisionerKeyRecord>, StorageError> {
            Ok(None)
        }

        async fn list_provisioner_keys_by_organization(
            &self,
            _organization_id: Uuid,
        ) -> Result<Vec<ProvisionerKeyRecord>, StorageError> {
            Ok(Vec::new())
        }

        async fn list_provisioner_keys_by_organization_exclude_reserved(
            &self,
            _organization_id: Uuid,
        ) -> Result<Vec<ProvisionerKeyRecord>, StorageError> {
            Ok(Vec::new())
        }

        async fn delete_provisioner_key(&self, _id: Uuid) -> Result<bool, StorageError> {
            Ok(false)
        }
    }

    // ── Test helpers ───────────────────────────────────────

    fn make_test_job(org_id: Uuid) -> ProvisionerJobRecord {
        let now = OffsetDateTime::now_utc();
        ProvisionerJobRecord {
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            started_at: None,
            canceled_at: None,
            completed_at: None,
            error: String::new(),
            error_code: String::new(),
            organization_id: Some(org_id),
            initiator_id: Some(Uuid::new_v4()),
            provisioner: ProvisionerType::Terraform,
            storage_method: coder_core::ProvisionerStorageMethod::File,
            file_id: Some(Uuid::new_v4()),
            job_type: coder_core::ProvisionerJobType::WorkspaceBuild,
            input: serde_json::json!({}),
            tags: serde_json::json!({}),
            trace_metadata: serde_json::json!({}),
            worker_id: None,
            job_status: ProvisionerJobStatus::Pending,
            logs_overflowed: false,
            logs_length: 0,
        }
    }

    fn make_registration(org_id: Uuid) -> DaemonRegistration {
        DaemonRegistration {
            name: "test-daemon".to_string(),
            version: "1.0.0".to_string(),
            api_version: "1.0".to_string(),
            provisioners: vec!["terraform".to_string()],
            tags: HashMap::new(),
            organization_id: org_id,
            key_id: None,
        }
    }

    /// Sends a single message through the handler and collects responses.
    async fn run_single_message(
        store: &Arc<TestStore>,
        registration: &DaemonRegistration,
        current_job: &mut Option<ProvisionerJobRecord>,
        msg: DaemonMessage,
    ) -> (Vec<ServerMessage>, Result<MessageResult, DaemonServerError>) {
        let daemon_id = Uuid::new_v4();
        let provisioner_types = vec![ProvisionerType::Terraform];
        let tags_json = serde_json::to_value(&registration.tags).unwrap_or_default();
        let (tx, mut rx) = mpsc::channel(16);

        let result = handle_daemon_message(
            store,
            &daemon_id,
            registration,
            &provisioner_types,
            &tags_json,
            current_job,
            msg,
            &tx,
        )
        .await;

        drop(tx);
        let mut responses = Vec::new();
        while let Some(msg) = rx.recv().await {
            responses.push(msg);
        }
        (responses, result)
    }

    // ── Tests ──────────────────────────────────────────────

    #[tokio::test]
    async fn test_acquire_job_success() {
        let org_id = Uuid::new_v4();
        let store = Arc::new(TestStore::new());
        let job = make_test_job(org_id);
        let job_id = job.id;
        store.insert_test_job(job);

        let registration = make_registration(org_id);
        let mut current_job: Option<ProvisionerJobRecord> = None;

        let (responses, result) = run_single_message(
            &store,
            &registration,
            &mut current_job,
            DaemonMessage::AcquireJob,
        )
        .await;

        assert!(result.is_ok());
        assert!(current_job.is_some());
        assert_eq!(current_job.as_ref().map(|j| j.id), Some(job_id));
        assert_eq!(responses.len(), 1);
        assert!(matches!(&responses[0], ServerMessage::JobAssigned { .. }));
    }

    #[tokio::test]
    async fn test_acquire_job_no_jobs() {
        let org_id = Uuid::new_v4();
        let store = Arc::new(TestStore::new());
        let registration = make_registration(org_id);
        let mut current_job: Option<ProvisionerJobRecord> = None;

        let (responses, result) = run_single_message(
            &store,
            &registration,
            &mut current_job,
            DaemonMessage::AcquireJob,
        )
        .await;

        assert!(result.is_ok());
        assert!(current_job.is_none());
        assert_eq!(responses.len(), 1);
        assert!(matches!(&responses[0], ServerMessage::NoJob));
    }

    #[tokio::test]
    async fn test_acquire_job_already_has_job() {
        let org_id = Uuid::new_v4();
        let store = Arc::new(TestStore::new());
        let registration = make_registration(org_id);
        let mut current_job: Option<ProvisionerJobRecord> = Some(make_test_job(org_id));

        let (responses, result) = run_single_message(
            &store,
            &registration,
            &mut current_job,
            DaemonMessage::AcquireJob,
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(responses.len(), 1);
        assert!(matches!(&responses[0], ServerMessage::Error { .. }));
    }

    #[tokio::test]
    async fn test_complete_job_success() {
        let org_id = Uuid::new_v4();
        let store = Arc::new(TestStore::new());
        let job = make_test_job(org_id);
        let job_id = job.id;
        store.insert_test_job(job.clone());

        let registration = make_registration(org_id);
        let mut current_job: Option<ProvisionerJobRecord> = Some(job);

        let (responses, result) = run_single_message(
            &store,
            &registration,
            &mut current_job,
            DaemonMessage::CompleteJob {
                error: String::new(),
                error_code: String::new(),
            },
        )
        .await;

        assert!(result.is_ok());
        assert!(current_job.is_none());
        assert_eq!(responses.len(), 1);
        assert!(matches!(&responses[0], ServerMessage::JobCompleteAck));

        // Verify the job was marked as completed in the store.
        let stored_job = store
            .get_provisioner_job_by_id(job_id)
            .await
            .unwrap_or(None);
        assert!(stored_job.is_some());
        if let Some(sj) = stored_job {
            assert_eq!(sj.job_status, ProvisionerJobStatus::Succeeded);
            assert!(sj.completed_at.is_some());
        }
    }

    #[tokio::test]
    async fn test_complete_job_with_error() {
        let org_id = Uuid::new_v4();
        let store = Arc::new(TestStore::new());
        let job = make_test_job(org_id);
        let job_id = job.id;
        store.insert_test_job(job.clone());

        let registration = make_registration(org_id);
        let mut current_job: Option<ProvisionerJobRecord> = Some(job);

        let (responses, result) = run_single_message(
            &store,
            &registration,
            &mut current_job,
            DaemonMessage::CompleteJob {
                error: "terraform apply failed".to_string(),
                error_code: "APPLY_FAILED".to_string(),
            },
        )
        .await;

        assert!(result.is_ok());
        assert!(current_job.is_none());
        assert_eq!(responses.len(), 1);

        let stored_job = store
            .get_provisioner_job_by_id(job_id)
            .await
            .unwrap_or(None);
        assert!(stored_job.is_some());
        if let Some(sj) = stored_job {
            assert_eq!(sj.job_status, ProvisionerJobStatus::Failed);
            assert_eq!(sj.error, "terraform apply failed");
        }
    }

    #[tokio::test]
    async fn test_cancel_complete() {
        let org_id = Uuid::new_v4();
        let store = Arc::new(TestStore::new());
        let job = make_test_job(org_id);
        let job_id = job.id;
        store.insert_test_job(job.clone());

        let registration = make_registration(org_id);
        let mut current_job: Option<ProvisionerJobRecord> = Some(job);

        let (responses, result) = run_single_message(
            &store,
            &registration,
            &mut current_job,
            DaemonMessage::CancelComplete,
        )
        .await;

        assert!(result.is_ok());
        assert!(current_job.is_none());
        assert_eq!(responses.len(), 1);
        assert!(matches!(&responses[0], ServerMessage::JobCompleteAck));

        let stored_job = store
            .get_provisioner_job_by_id(job_id)
            .await
            .unwrap_or(None);
        assert!(stored_job.is_some());
        if let Some(sj) = stored_job {
            assert_eq!(sj.job_status, ProvisionerJobStatus::Canceled);
        }
    }

    #[tokio::test]
    async fn test_heartbeat() {
        let org_id = Uuid::new_v4();
        let store = Arc::new(TestStore::new());
        let registration = make_registration(org_id);
        let mut current_job: Option<ProvisionerJobRecord> = None;

        let (responses, result) = run_single_message(
            &store,
            &registration,
            &mut current_job,
            DaemonMessage::Heartbeat,
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(responses.len(), 1);
        assert!(matches!(&responses[0], ServerMessage::HeartbeatAck));
    }

    #[tokio::test]
    async fn test_heartbeat_with_active_job() {
        let org_id = Uuid::new_v4();
        let store = Arc::new(TestStore::new());
        let job = make_test_job(org_id);
        let job_id = job.id;
        store.insert_test_job(job.clone());

        let registration = make_registration(org_id);
        let mut current_job: Option<ProvisionerJobRecord> = Some(job);

        let (responses, result) = run_single_message(
            &store,
            &registration,
            &mut current_job,
            DaemonMessage::Heartbeat,
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(responses.len(), 1);
        assert!(matches!(&responses[0], ServerMessage::HeartbeatAck));

        let stored_job = store
            .get_provisioner_job_by_id(job_id)
            .await
            .unwrap_or(None);
        assert!(stored_job.is_some());
    }

    #[tokio::test]
    async fn test_job_logs() {
        let org_id = Uuid::new_v4();
        let store = Arc::new(TestStore::new());
        let job = make_test_job(org_id);
        store.insert_test_job(job.clone());

        let registration = make_registration(org_id);
        let mut current_job: Option<ProvisionerJobRecord> = Some(job);

        let (responses, result) = run_single_message(
            &store,
            &registration,
            &mut current_job,
            DaemonMessage::JobLogs {
                logs: vec![
                    JobLogEntry {
                        source: "provisioner".to_string(),
                        level: "info".to_string(),
                        stage: "init".to_string(),
                        output: "Initializing...".to_string(),
                    },
                    JobLogEntry {
                        source: "provisioner".to_string(),
                        level: "info".to_string(),
                        stage: "plan".to_string(),
                        output: "Planning...".to_string(),
                    },
                ],
            },
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(responses.len(), 1);
        assert!(matches!(
            &responses[0],
            ServerMessage::LogsAccepted { count: 2 }
        ));

        // Verify logs were stored.
        if let Ok(stored_logs) = lock_or_err(&store.logs) {
            assert_eq!(stored_logs.len(), 2);
        }
    }

    #[tokio::test]
    async fn test_job_logs_without_active_job() {
        let org_id = Uuid::new_v4();
        let store = Arc::new(TestStore::new());
        let registration = make_registration(org_id);
        let mut current_job: Option<ProvisionerJobRecord> = None;

        let (responses, result) = run_single_message(
            &store,
            &registration,
            &mut current_job,
            DaemonMessage::JobLogs {
                logs: vec![JobLogEntry {
                    source: "provisioner".to_string(),
                    level: "info".to_string(),
                    stage: "init".to_string(),
                    output: "test".to_string(),
                }],
            },
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(responses.len(), 1);
        assert!(matches!(&responses[0], ServerMessage::Error { .. }));
    }

    #[tokio::test]
    async fn test_complete_job_without_active_job() {
        let org_id = Uuid::new_v4();
        let store = Arc::new(TestStore::new());
        let registration = make_registration(org_id);
        let mut current_job: Option<ProvisionerJobRecord> = None;

        let (responses, result) = run_single_message(
            &store,
            &registration,
            &mut current_job,
            DaemonMessage::CompleteJob {
                error: String::new(),
                error_code: String::new(),
            },
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(responses.len(), 1);
        assert!(matches!(&responses[0], ServerMessage::Error { .. }));
    }

    #[tokio::test]
    async fn test_cancel_without_active_job() {
        let org_id = Uuid::new_v4();
        let store = Arc::new(TestStore::new());
        let registration = make_registration(org_id);
        let mut current_job: Option<ProvisionerJobRecord> = None;

        let (responses, result) = run_single_message(
            &store,
            &registration,
            &mut current_job,
            DaemonMessage::CancelComplete,
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(responses.len(), 1);
        assert!(matches!(&responses[0], ServerMessage::Error { .. }));
    }

    #[tokio::test]
    async fn test_job_timings() {
        let org_id = Uuid::new_v4();
        let store = Arc::new(TestStore::new());
        let job = make_test_job(org_id);
        store.insert_test_job(job.clone());

        let registration = make_registration(org_id);
        let mut current_job: Option<ProvisionerJobRecord> = Some(job);

        let now = OffsetDateTime::now_utc();
        let now_str = now
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();

        let (responses, result) = run_single_message(
            &store,
            &registration,
            &mut current_job,
            DaemonMessage::JobTimings {
                timings: vec![JobTimingEntry {
                    started_at: now_str.clone(),
                    ended_at: now_str,
                    stage: "init".to_string(),
                    source: "terraform".to_string(),
                    action: "init".to_string(),
                    resource: "module.main".to_string(),
                }],
            },
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(responses.len(), 1);
        assert!(matches!(
            &responses[0],
            ServerMessage::TimingsAccepted { count: 1 }
        ));
    }

    #[tokio::test]
    async fn test_job_timings_without_active_job() {
        let org_id = Uuid::new_v4();
        let store = Arc::new(TestStore::new());
        let registration = make_registration(org_id);
        let mut current_job: Option<ProvisionerJobRecord> = None;

        let (responses, result) = run_single_message(
            &store,
            &registration,
            &mut current_job,
            DaemonMessage::JobTimings {
                timings: vec![JobTimingEntry {
                    started_at: "2024-01-01T00:00:00Z".to_string(),
                    ended_at: "2024-01-01T00:00:01Z".to_string(),
                    stage: "init".to_string(),
                    source: "terraform".to_string(),
                    action: "init".to_string(),
                    resource: "module.main".to_string(),
                }],
            },
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(responses.len(), 1);
        assert!(matches!(&responses[0], ServerMessage::Error { .. }));
    }

    #[tokio::test]
    async fn test_run_daemon_session_acquire_and_complete() {
        let org_id = Uuid::new_v4();
        let store = Arc::new(TestStore::new());
        let job = make_test_job(org_id);
        let job_id = job.id;
        store.insert_test_job(job);

        let registration = make_registration(org_id);
        let config = DaemonServerConfig {
            heartbeat_interval: Duration::from_secs(300),
            cancel_check_interval: Duration::from_secs(300),
        };

        let (daemon_tx, incoming_rx) = mpsc::channel(16);
        let (outgoing_tx, mut outgoing_rx) = mpsc::channel(16);

        let session_store = Arc::clone(&store);
        let session_handle = tokio::spawn(async move {
            run_daemon_session(
                session_store,
                registration,
                config,
                incoming_rx,
                outgoing_tx,
            )
            .await
        });

        // Send AcquireJob.
        daemon_tx
            .send(DaemonMessage::AcquireJob)
            .await
            .unwrap_or(());
        let resp = outgoing_rx.recv().await;
        assert!(matches!(
            resp.as_ref(),
            Some(ServerMessage::JobAssigned { .. })
        ));

        // Send Heartbeat.
        daemon_tx.send(DaemonMessage::Heartbeat).await.unwrap_or(());
        let resp = outgoing_rx.recv().await;
        assert!(matches!(resp.as_ref(), Some(ServerMessage::HeartbeatAck)));

        // Send CompleteJob.
        daemon_tx
            .send(DaemonMessage::CompleteJob {
                error: String::new(),
                error_code: String::new(),
            })
            .await
            .unwrap_or(());
        let resp = outgoing_rx.recv().await;
        assert!(matches!(resp.as_ref(), Some(ServerMessage::JobCompleteAck)));

        // Close the channel to end the session.
        drop(daemon_tx);
        let result = session_handle.await;
        assert!(result.is_ok());

        // Verify job status.
        let stored_job = store
            .get_provisioner_job_by_id(job_id)
            .await
            .unwrap_or(None);
        assert!(stored_job.is_some());
        if let Some(sj) = stored_job {
            assert_eq!(sj.job_status, ProvisionerJobStatus::Succeeded);
        }
    }

    #[tokio::test]
    async fn test_run_daemon_session_multiple_jobs() {
        let org_id = Uuid::new_v4();
        let store = Arc::new(TestStore::new());

        let job1 = make_test_job(org_id);
        let job1_id = job1.id;
        store.insert_test_job(job1);

        let job2 = make_test_job(org_id);
        let job2_id = job2.id;
        store.insert_test_job(job2);

        let registration = make_registration(org_id);
        let config = DaemonServerConfig {
            heartbeat_interval: Duration::from_secs(300),
            cancel_check_interval: Duration::from_secs(300),
        };

        let (daemon_tx, incoming_rx) = mpsc::channel(16);
        let (outgoing_tx, mut outgoing_rx) = mpsc::channel(16);

        let session_store = Arc::clone(&store);
        let session_handle = tokio::spawn(async move {
            run_daemon_session(
                session_store,
                registration,
                config,
                incoming_rx,
                outgoing_tx,
            )
            .await
        });

        // Acquire and complete first job.
        daemon_tx
            .send(DaemonMessage::AcquireJob)
            .await
            .unwrap_or(());
        let resp = outgoing_rx.recv().await;
        assert!(matches!(
            resp.as_ref(),
            Some(ServerMessage::JobAssigned { .. })
        ));

        daemon_tx
            .send(DaemonMessage::CompleteJob {
                error: String::new(),
                error_code: String::new(),
            })
            .await
            .unwrap_or(());
        let resp = outgoing_rx.recv().await;
        assert!(matches!(resp.as_ref(), Some(ServerMessage::JobCompleteAck)));

        // Acquire and complete second job.
        daemon_tx
            .send(DaemonMessage::AcquireJob)
            .await
            .unwrap_or(());
        let resp = outgoing_rx.recv().await;
        assert!(matches!(
            resp.as_ref(),
            Some(ServerMessage::JobAssigned { .. })
        ));

        daemon_tx
            .send(DaemonMessage::CompleteJob {
                error: String::new(),
                error_code: String::new(),
            })
            .await
            .unwrap_or(());
        let resp = outgoing_rx.recv().await;
        assert!(matches!(resp.as_ref(), Some(ServerMessage::JobCompleteAck)));

        drop(daemon_tx);
        let _ = session_handle.await;

        // Both jobs should be completed.
        let j1 = store
            .get_provisioner_job_by_id(job1_id)
            .await
            .unwrap_or(None);
        let j2 = store
            .get_provisioner_job_by_id(job2_id)
            .await
            .unwrap_or(None);
        assert!(j1.is_some());
        assert!(j2.is_some());
        if let (Some(j1), Some(j2)) = (j1, j2) {
            assert_eq!(j1.job_status, ProvisionerJobStatus::Succeeded);
            assert_eq!(j2.job_status, ProvisionerJobStatus::Succeeded);
        }
    }

    #[tokio::test]
    async fn test_run_daemon_session_concurrent_daemons() {
        let org_id = Uuid::new_v4();
        let store = Arc::new(TestStore::new());

        let job1 = make_test_job(org_id);
        let job1_id = job1.id;
        store.insert_test_job(job1);

        let job2 = make_test_job(org_id);
        let job2_id = job2.id;
        store.insert_test_job(job2);

        let config = DaemonServerConfig {
            heartbeat_interval: Duration::from_secs(300),
            cancel_check_interval: Duration::from_secs(300),
        };

        // Daemon 1
        let reg1 = DaemonRegistration {
            name: "daemon-1".to_string(),
            ..make_registration(org_id)
        };
        let (d1_tx, d1_rx) = mpsc::channel(16);
        let (o1_tx, mut o1_rx) = mpsc::channel(16);
        let s1 = Arc::clone(&store);
        let c1 = config.clone();
        let h1 = tokio::spawn(async move { run_daemon_session(s1, reg1, c1, d1_rx, o1_tx).await });

        // Daemon 2
        let reg2 = DaemonRegistration {
            name: "daemon-2".to_string(),
            ..make_registration(org_id)
        };
        let (d2_tx, d2_rx) = mpsc::channel(16);
        let (o2_tx, mut o2_rx) = mpsc::channel(16);
        let s2 = Arc::clone(&store);
        let c2 = config;
        let h2 = tokio::spawn(async move { run_daemon_session(s2, reg2, c2, d2_rx, o2_tx).await });

        // Both daemons acquire jobs.
        d1_tx.send(DaemonMessage::AcquireJob).await.unwrap_or(());
        let r1 = o1_rx.recv().await;
        assert!(matches!(
            r1.as_ref(),
            Some(ServerMessage::JobAssigned { .. })
        ));

        d2_tx.send(DaemonMessage::AcquireJob).await.unwrap_or(());
        let r2 = o2_rx.recv().await;
        assert!(matches!(
            r2.as_ref(),
            Some(ServerMessage::JobAssigned { .. })
        ));

        // Both complete their jobs.
        d1_tx
            .send(DaemonMessage::CompleteJob {
                error: String::new(),
                error_code: String::new(),
            })
            .await
            .unwrap_or(());
        let _ = o1_rx.recv().await;

        d2_tx
            .send(DaemonMessage::CompleteJob {
                error: String::new(),
                error_code: String::new(),
            })
            .await
            .unwrap_or(());
        let _ = o2_rx.recv().await;

        drop(d1_tx);
        drop(d2_tx);
        let _ = h1.await;
        let _ = h2.await;

        // Both jobs should be completed.
        let j1 = store
            .get_provisioner_job_by_id(job1_id)
            .await
            .unwrap_or(None);
        let j2 = store
            .get_provisioner_job_by_id(job2_id)
            .await
            .unwrap_or(None);
        assert!(j1.is_some());
        assert!(j2.is_some());
        if let (Some(j1), Some(j2)) = (j1, j2) {
            assert_eq!(j1.job_status, ProvisionerJobStatus::Succeeded);
            assert_eq!(j2.job_status, ProvisionerJobStatus::Succeeded);
        }
    }

    #[test]
    fn test_parse_log_source() {
        assert_eq!(
            parse_log_source("provisioner_daemon"),
            LogSource::ProvisionerDaemon
        );
        assert_eq!(parse_log_source("provisioner"), LogSource::Provisioner);
        assert_eq!(parse_log_source("unknown"), LogSource::Provisioner);
    }

    #[test]
    fn test_parse_log_level() {
        assert_eq!(parse_log_level("trace"), LogLevel::Trace);
        assert_eq!(parse_log_level("debug"), LogLevel::Debug);
        assert_eq!(parse_log_level("info"), LogLevel::Info);
        assert_eq!(parse_log_level("warn"), LogLevel::Warn);
        assert_eq!(parse_log_level("error"), LogLevel::Error);
        assert_eq!(parse_log_level("unknown"), LogLevel::Info);
    }

    #[test]
    fn test_parse_timing_stage() {
        assert_eq!(parse_timing_stage("init"), ProvisionerJobTimingStage::Init);
        assert_eq!(parse_timing_stage("plan"), ProvisionerJobTimingStage::Plan);
        assert_eq!(
            parse_timing_stage("graph"),
            ProvisionerJobTimingStage::Graph
        );
        assert_eq!(
            parse_timing_stage("apply"),
            ProvisionerJobTimingStage::Apply
        );
        assert_eq!(
            parse_timing_stage("unknown"),
            ProvisionerJobTimingStage::Init
        );
    }

    #[test]
    fn test_daemon_message_serialization() {
        let msg = DaemonMessage::AcquireJob;
        let json = serde_json::to_string(&msg).unwrap_or_default();
        assert!(json.contains("acquire_job"));

        let msg = DaemonMessage::CompleteJob {
            error: "test error".to_string(),
            error_code: "ERR_001".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap_or_default();
        assert!(json.contains("complete_job"));
        assert!(json.contains("test error"));

        // Roundtrip.
        let deserialized: Result<DaemonMessage, _> = serde_json::from_str(&json);
        assert!(deserialized.is_ok());
    }

    #[test]
    fn test_server_message_serialization() {
        let msg = ServerMessage::NoJob;
        let json = serde_json::to_string(&msg).unwrap_or_default();
        assert!(json.contains("no_job"));

        let msg = ServerMessage::HeartbeatAck;
        let json = serde_json::to_string(&msg).unwrap_or_default();
        assert!(json.contains("heartbeat_ack"));

        let msg = ServerMessage::Error {
            message: "something went wrong".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap_or_default();
        assert!(json.contains("error"));
        assert!(json.contains("something went wrong"));
    }

    #[test]
    fn test_job_info_from_record() {
        let now = OffsetDateTime::now_utc();
        let record = ProvisionerJobRecord {
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            started_at: None,
            canceled_at: None,
            completed_at: None,
            error: String::new(),
            error_code: String::new(),
            organization_id: Some(Uuid::new_v4()),
            initiator_id: Some(Uuid::new_v4()),
            provisioner: ProvisionerType::Terraform,
            storage_method: coder_core::ProvisionerStorageMethod::File,
            file_id: Some(Uuid::new_v4()),
            job_type: coder_core::ProvisionerJobType::WorkspaceBuild,
            input: serde_json::json!({"key": "value"}),
            tags: serde_json::json!({"env": "prod"}),
            trace_metadata: serde_json::json!({}),
            worker_id: None,
            job_status: ProvisionerJobStatus::Pending,
            logs_overflowed: false,
            logs_length: 0,
        };

        let info = JobInfo::from(&record);
        assert_eq!(info.id, record.id);
        assert_eq!(info.organization_id, record.organization_id);
        assert_eq!(info.provisioner, "terraform");
        assert_eq!(info.job_type, "workspace_build");
        assert_eq!(info.file_id, record.file_id);
    }

    #[test]
    fn test_daemon_server_config_default() {
        let config = DaemonServerConfig::default();
        assert_eq!(config.heartbeat_interval, Duration::from_secs(30));
        assert_eq!(config.cancel_check_interval, Duration::from_secs(5));
    }

    #[test]
    fn test_parse_timestamp_valid() {
        let ts = parse_timestamp("2024-01-15T10:30:00Z");
        assert_eq!(ts.year(), 2024);
        assert_eq!(ts.month() as u8, 1);
        assert_eq!(ts.day(), 15);
    }

    #[test]
    fn test_parse_timestamp_invalid_falls_back() {
        let before = OffsetDateTime::now_utc();
        let ts = parse_timestamp("not-a-date");
        let after = OffsetDateTime::now_utc();
        assert!(ts >= before && ts <= after);
    }
}
