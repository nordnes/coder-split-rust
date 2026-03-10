//! Provisioner domain types: jobs, daemons, keys, logs, and timings.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

// ── Enums ────────────────────────────────────────────────────

/// Status of a provisioner job.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvisionerJobStatus {
    /// Waiting to be acquired by a daemon.
    Pending,
    /// Currently being executed by a daemon.
    Running,
    /// Completed successfully.
    Succeeded,
    /// Completed with an error.
    Failed,
    /// Cancel has been requested but not yet acknowledged.
    Canceling,
    /// Job was canceled.
    Canceled,
    /// Unknown status (fallback).
    Unknown,
}

impl ProvisionerJobStatus {
    /// Returns the database string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Canceling => "canceling",
            Self::Canceled => "canceled",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for ProvisionerJobStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Provisioner technology type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvisionerType {
    /// Terraform-based provisioning.
    Terraform,
    /// Echo provisioner (for testing).
    Echo,
}

impl ProvisionerType {
    /// Returns the database string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Terraform => "terraform",
            Self::Echo => "echo",
        }
    }
}

impl fmt::Display for ProvisionerType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Storage method for provisioner job files.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvisionerStorageMethod {
    /// File-based storage.
    File,
}

impl ProvisionerStorageMethod {
    /// Returns the database string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::File => "file",
        }
    }
}

impl fmt::Display for ProvisionerStorageMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Type of provisioner job.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvisionerJobType {
    /// Import and parse a template version (Terraform plan).
    TemplateVersionImport,
    /// Dry-run a template version (plan without apply).
    TemplateVersionDryRun,
    /// Build workspace infrastructure (apply).
    WorkspaceBuild,
}

impl ProvisionerJobType {
    /// Returns the database string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TemplateVersionImport => "template_version_import",
            Self::TemplateVersionDryRun => "template_version_dry_run",
            Self::WorkspaceBuild => "workspace_build",
        }
    }
}

impl fmt::Display for ProvisionerJobType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Source of a provisioner job log entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogSource {
    /// Log emitted by the provisioner daemon itself.
    ProvisionerDaemon,
    /// Log emitted by the underlying provisioner (e.g. Terraform).
    Provisioner,
}

impl LogSource {
    /// Returns the database string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ProvisionerDaemon => "provisioner_daemon",
            Self::Provisioner => "provisioner",
        }
    }
}

impl fmt::Display for LogSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Severity level for provisioner job logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    /// Finest-grained trace output.
    Trace,
    /// Debug-level output.
    Debug,
    /// Informational messages.
    Info,
    /// Warnings.
    Warn,
    /// Error messages.
    Error,
}

impl LogLevel {
    /// Returns the database string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Stage in a provisioner job timing entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvisionerJobTimingStage {
    /// Initialization stage.
    Init,
    /// Planning stage.
    Plan,
    /// Graph-building stage.
    Graph,
    /// Apply stage.
    Apply,
}

impl ProvisionerJobTimingStage {
    /// Returns the database string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Init => "init",
            Self::Plan => "plan",
            Self::Graph => "graph",
            Self::Apply => "apply",
        }
    }
}

impl fmt::Display for ProvisionerJobTimingStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── Records ──────────────────────────────────────────────────

/// A stored provisioner job.
#[derive(Clone, Debug, PartialEq)]
pub struct ProvisionerJobRecord {
    /// Stable job identifier.
    pub id: Uuid,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Last update time (also serves as heartbeat).
    pub updated_at: OffsetDateTime,
    /// Start time when a worker began executing.
    pub started_at: Option<OffsetDateTime>,
    /// Time when cancellation was requested.
    pub canceled_at: Option<OffsetDateTime>,
    /// Completion time.
    pub completed_at: Option<OffsetDateTime>,
    /// Error message on failure.
    pub error: String,
    /// Machine-readable error code.
    pub error_code: String,
    /// Organization scope.
    pub organization_id: Option<Uuid>,
    /// User who initiated the job.
    pub initiator_id: Option<Uuid>,
    /// Provisioner technology.
    pub provisioner: ProvisionerType,
    /// How the template files are stored.
    pub storage_method: ProvisionerStorageMethod,
    /// Reference to the stored file.
    pub file_id: Option<Uuid>,
    /// Kind of provisioner job.
    pub job_type: ProvisionerJobType,
    /// Structured input for the job.
    pub input: Value,
    /// Free-form tags for daemon matching.
    pub tags: Value,
    /// Trace/observability metadata.
    pub trace_metadata: Value,
    /// Worker daemon that acquired this job.
    pub worker_id: Option<Uuid>,
    /// Computed job status.
    pub job_status: ProvisionerJobStatus,
    /// Whether log output was truncated.
    pub logs_overflowed: bool,
    /// Running total of log bytes written.
    pub logs_length: i32,
}

/// A stored provisioner job log entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvisionerJobLogRecord {
    /// Auto-incremented log line identifier.
    pub id: i64,
    /// Owning job.
    pub job_id: Uuid,
    /// Log creation time.
    pub created_at: OffsetDateTime,
    /// Source of the log entry.
    pub source: LogSource,
    /// Severity level.
    pub level: LogLevel,
    /// Build stage label.
    pub stage: String,
    /// Log output text.
    pub output: String,
}

/// A stored provisioner job timing entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvisionerJobTimingRecord {
    /// Owning job.
    pub job_id: Uuid,
    /// Timing start.
    pub started_at: OffsetDateTime,
    /// Timing end.
    pub ended_at: OffsetDateTime,
    /// Build stage.
    pub stage: ProvisionerJobTimingStage,
    /// Source identifier.
    pub source: String,
    /// Action performed.
    pub action: String,
    /// Resource acted upon.
    pub resource: String,
}

/// A stored provisioner key used for daemon authentication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvisionerKeyRecord {
    /// Key identifier.
    pub id: Uuid,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Organization scope.
    pub organization_id: Uuid,
    /// Human-readable key name.
    pub name: String,
    /// SHA-256 hash of the secret.
    pub hashed_secret: Vec<u8>,
    /// Free-form tags.
    pub tags: Value,
}

/// A stored provisioner daemon record (full, not just health).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvisionerDaemonRecord {
    /// Daemon identifier.
    pub id: Uuid,
    /// Organization scope.
    pub organization_id: Uuid,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Last heartbeat time.
    pub last_seen_at: Option<OffsetDateTime>,
    /// Daemon name.
    pub name: String,
    /// Running version.
    pub version: String,
    /// Provisioner API version.
    pub api_version: String,
    /// Supported provisioner types.
    pub provisioners: Vec<String>,
    /// Free-form daemon tags.
    pub tags: HashMap<String, String>,
    /// Provisioner key used for authentication.
    pub key_id: Option<Uuid>,
}

// ── Inputs ───────────────────────────────────────────────────

/// Input for inserting a new provisioner job.
#[derive(Clone, Debug, PartialEq)]
pub struct InsertProvisionerJobInput {
    /// Job identifier (caller-generated).
    pub id: Uuid,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Organization scope.
    pub organization_id: Uuid,
    /// User who initiated the job.
    pub initiator_id: Uuid,
    /// Provisioner technology.
    pub provisioner: ProvisionerType,
    /// Storage method.
    pub storage_method: ProvisionerStorageMethod,
    /// Reference to the stored file.
    pub file_id: Uuid,
    /// Kind of job.
    pub job_type: ProvisionerJobType,
    /// Structured input.
    pub input: Value,
    /// Tags for daemon matching.
    pub tags: Value,
    /// Trace metadata.
    pub trace_metadata: Value,
}

/// Input for acquiring a pending provisioner job.
#[derive(Clone, Debug, PartialEq)]
pub struct AcquireProvisionerJobInput {
    /// Worker daemon identifier.
    pub worker_id: Uuid,
    /// Acquisition time (becomes started_at).
    pub started_at: OffsetDateTime,
    /// Organization to acquire from.
    pub organization_id: Uuid,
    /// Provisioner types the daemon supports.
    pub types: Vec<ProvisionerType>,
    /// Tags the daemon advertises (must be superset of job tags).
    pub provisioner_tags: Value,
}

/// Input for completing a provisioner job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompleteProvisionerJobInput {
    /// Job identifier.
    pub id: Uuid,
    /// Update time.
    pub updated_at: OffsetDateTime,
    /// Completion time.
    pub completed_at: OffsetDateTime,
    /// Error message (empty string means success).
    pub error: String,
    /// Machine-readable error code.
    pub error_code: String,
}

/// Input for canceling a provisioner job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CancelProvisionerJobInput {
    /// Job identifier.
    pub id: Uuid,
    /// Cancellation time.
    pub canceled_at: OffsetDateTime,
    /// Optional completion time (set for immediate cancel).
    pub completed_at: Option<OffsetDateTime>,
}

/// Input for inserting provisioner job log entries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InsertProvisionerJobLogsInput {
    /// Owning job.
    pub job_id: Uuid,
    /// Timestamps for each log entry.
    pub created_at: Vec<OffsetDateTime>,
    /// Source for each log entry.
    pub source: Vec<LogSource>,
    /// Level for each log entry.
    pub level: Vec<LogLevel>,
    /// Stage for each log entry.
    pub stage: Vec<String>,
    /// Output for each log entry.
    pub output: Vec<String>,
}

/// Input for inserting provisioner job timing entries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InsertProvisionerJobTimingsInput {
    /// Owning job.
    pub job_id: Uuid,
    /// Start times.
    pub started_at: Vec<OffsetDateTime>,
    /// End times.
    pub ended_at: Vec<OffsetDateTime>,
    /// Stages.
    pub stage: Vec<ProvisionerJobTimingStage>,
    /// Sources.
    pub source: Vec<String>,
    /// Actions.
    pub action: Vec<String>,
    /// Resources.
    pub resource: Vec<String>,
}

/// Input for upserting (registering) a provisioner daemon.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpsertProvisionerDaemonInput {
    /// Daemon name.
    pub name: String,
    /// Supported provisioner types.
    pub provisioners: Vec<String>,
    /// Free-form tags.
    pub tags: HashMap<String, String>,
    /// Last-seen heartbeat time.
    pub last_seen_at: OffsetDateTime,
    /// Running version.
    pub version: String,
    /// Organization scope.
    pub organization_id: Uuid,
    /// Provisioner API version.
    pub api_version: String,
    /// Key used for authentication.
    pub key_id: Option<Uuid>,
}

/// Input for inserting a provisioner key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InsertProvisionerKeyInput {
    /// Key identifier (caller-generated).
    pub id: Uuid,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Organization scope.
    pub organization_id: Uuid,
    /// Human-readable name.
    pub name: String,
    /// SHA-256 hash of the secret.
    pub hashed_secret: Vec<u8>,
    /// Free-form tags.
    pub tags: Value,
}

/// Parameters for finding stale/hung jobs to reap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetJobsToBeReapedInput {
    /// Jobs pending since before this time should be reaped.
    pub pending_since: OffsetDateTime,
    /// Jobs running (without heartbeat) since before this time should be reaped.
    pub hung_since: OffsetDateTime,
    /// Maximum number of jobs to reap in one batch.
    pub max_jobs: i64,
}
