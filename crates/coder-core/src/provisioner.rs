//! Provisioner domain types: jobs, daemons, keys, logs, and timings.

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

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

impl FromStr for ProvisionerType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "terraform" => Ok(Self::Terraform),
            "echo" => Ok(Self::Echo),
            other => Err(format!("unknown provisioner type: {other}")),
        }
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

impl FromStr for ProvisionerJobType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "template_version_import" => Ok(Self::TemplateVersionImport),
            "template_version_dry_run" => Ok(Self::TemplateVersionDryRun),
            "workspace_build" => Ok(Self::WorkspaceBuild),
            other => Err(format!("unknown provisioner job type: {other}")),
        }
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

// ── Provisioner tag set ─────────────────────────────────────
//
// Mirrors Go's `provisionersdk` tag helpers and the SQL matching function
// `provisioner_tagset_contains` (see
// `coder/coderd/database/migrations/000275_check_tags.up.sql`).
//
// Semantics:
//   * Every provisioner job has a `scope` (either `organization` or `user`)
//     and an `owner` tag. An untagged organization job has exactly
//     `{"scope": "organization", "owner": ""}`.
//   * A daemon matches a job when either:
//     - the job is strictly untagged and the daemon's tags are equal to the
//       job's tags (untagged daemon), OR
//     - the job's tags are a subset of the daemon's tags.

/// Tag key identifying the scope of a provisioner job or daemon.
pub const TAG_SCOPE: &str = "scope";

/// Tag key identifying the owner of a user-scoped provisioner job or daemon.
pub const TAG_OWNER: &str = "owner";

/// Value of [`TAG_SCOPE`] for user-scoped jobs and daemons.
pub const SCOPE_USER: &str = "user";

/// Value of [`TAG_SCOPE`] for organization-scoped jobs and daemons.
pub const SCOPE_ORGANIZATION: &str = "organization";

/// Normalize a set of provisioner tags, enforcing the scope/owner invariants
/// documented on [`TAG_SCOPE`]/[`TAG_OWNER`].
///
/// Ports `MutateTags` from `coder/provisionersdk/provisionertags.go`:
/// - Merges all `provided` maps left-to-right, ignoring empty values in later
///   maps so callers can layer optional overrides.
/// - Injects a default `scope=organization, owner=""` when `scope` is missing.
/// - Forces `owner` to match `scope`: empty for `organization`, the stringified
///   `user_id` for `user`.
/// - Any unrecognized `scope` falls back to `organization`.
#[must_use]
pub fn mutate_tags(
    user_id: Uuid,
    provided: &[&HashMap<String, String>],
) -> HashMap<String, String> {
    let mut tags: HashMap<String, String> = HashMap::new();
    for extra in provided {
        merge_tags(&mut tags, extra);
    }
    if !tags.contains_key(TAG_SCOPE) {
        tags.insert(TAG_SCOPE.to_owned(), SCOPE_ORGANIZATION.to_owned());
        tags.insert(TAG_OWNER.to_owned(), String::new());
    }
    match tags.get(TAG_SCOPE).map(String::as_str) {
        Some(SCOPE_USER) => {
            tags.insert(TAG_OWNER.to_owned(), user_id.to_string());
        }
        Some(SCOPE_ORGANIZATION) => {
            tags.insert(TAG_OWNER.to_owned(), String::new());
        }
        _ => {
            tags.insert(TAG_SCOPE.to_owned(), SCOPE_ORGANIZATION.to_owned());
            tags.insert(TAG_OWNER.to_owned(), String::new());
        }
    }
    tags
}

/// Merge `extra` into `target`. Empty values in `extra` are ignored so
/// later maps don't overwrite earlier non-empty values with blanks.
fn merge_tags(target: &mut HashMap<String, String>, extra: &HashMap<String, String>) {
    for (k, v) in extra {
        if v.is_empty() {
            continue;
        }
        target.insert(k.clone(), v.clone());
    }
}

/// Wildcard sentinel for daemon tag values. A daemon tag with this
/// value matches any non-empty value on the corresponding job tag.
///
/// This is a Rust-side extension over Go's strict-subset matcher
/// (`provisioner_tagset_contains`, see migration `000275_check_tags.up.sql`).
/// The SQL matcher used during Postgres `AcquireProvisionerJob` does not
/// yet honor wildcards; they are observed only in the in-memory matcher
/// used by unit tests and by helpers that rank candidate daemons.
pub const TAG_WILDCARD: &str = "*";

/// Returns `true` when a daemon advertising `daemon_tags` is allowed to
/// acquire a job tagged with `job_tags`.
///
/// Ports the SQL function `provisioner_tagset_contains`:
/// - If `job_tags` is exactly `{"scope":"organization","owner":""}` (an
///   "untagged" org-scoped job) the match requires daemon and job tag sets
///   to be equal — i.e. only untagged daemons accept untagged jobs.
/// - Otherwise `job_tags` must be a subset of `daemon_tags` (every job tag
///   key/value is present in the daemon's tag set).
///
/// Additionally, a daemon tag with the value [`TAG_WILDCARD`] (`"*"`)
/// matches any value on the same key in `job_tags`. This extension is
/// additive: when the daemon does not use wildcards the behavior remains
/// identical to Go's strict-subset matcher.
#[must_use]
pub fn provisioner_tagset_matches(
    daemon_tags: &HashMap<String, String>,
    job_tags: &HashMap<String, String>,
) -> bool {
    if is_untagged_org_scope(job_tags) {
        // For an untagged org job only an exactly-equal (untagged) daemon
        // qualifies. Wildcards do not relax this; it mirrors the Go
        // SQL short-circuit in `provisioner_tagset_contains`.
        return daemon_tags == job_tags;
    }
    job_tags.iter().all(|(k, v)| match daemon_tags.get(k) {
        Some(dv) if dv == TAG_WILDCARD => true,
        Some(dv) => dv == v,
        None => false,
    })
}

/// Preference ordering for two daemons that both match a job. Lower is
/// more preferred (i.e. an acquirer should try `Organization` before
/// `User`).
///
/// Mirrors the Go acquirer semantics where an organization-scoped daemon
/// is considered first when multiple daemons share the job's provisioner
/// types and tag set. Ports the precedence implied by
/// `coder/coderd/provisionerdserver/acquirer.go` and the SQL query that
/// orders candidate jobs by prebuild/initiator preference.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DaemonScopePreference {
    /// Organization-scoped daemon — considered first.
    Organization,
    /// User-scoped daemon — considered second.
    User,
    /// Daemon whose `scope` tag is missing or unknown.
    Unknown,
}

/// Classifies a daemon's scope for preference ordering.
#[must_use]
pub fn daemon_scope_preference(daemon_tags: &HashMap<String, String>) -> DaemonScopePreference {
    match daemon_tags.get(TAG_SCOPE).map(String::as_str) {
        Some(SCOPE_ORGANIZATION) => DaemonScopePreference::Organization,
        Some(SCOPE_USER) => DaemonScopePreference::User,
        _ => DaemonScopePreference::Unknown,
    }
}

/// True when `tags` is exactly the "untagged" org-scoped set
/// `{"scope":"organization","owner":""}`.
fn is_untagged_org_scope(tags: &HashMap<String, String>) -> bool {
    tags.len() == 2
        && tags.get(TAG_SCOPE).map(String::as_str) == Some(SCOPE_ORGANIZATION)
        && tags.get(TAG_OWNER).map(String::as_str) == Some("")
}

/// Convenience: convert a JSON tag object (as stored in the database) into a
/// `HashMap<String, String>`. Non-string values are dropped, mirroring the
/// constraint that provisioner tags are always string/string.
#[must_use]
pub fn tags_from_json(value: &Value) -> HashMap<String, String> {
    let mut out = HashMap::new();
    if let Some(obj) = value.as_object() {
        for (k, v) in obj {
            if let Some(s) = v.as_str() {
                out.insert(k.clone(), s.to_owned());
            }
        }
    }
    out
}

#[cfg(test)]
mod tag_tests {
    use super::*;

    fn map<const N: usize>(pairs: [(&str, &str); N]) -> HashMap<String, String> {
        pairs
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect()
    }

    #[test]
    fn mutate_tags_defaults_to_org_scope() {
        let tags = mutate_tags(Uuid::nil(), &[]);
        assert_eq!(
            tags.get(TAG_SCOPE).map(String::as_str),
            Some(SCOPE_ORGANIZATION)
        );
        assert_eq!(tags.get(TAG_OWNER).map(String::as_str), Some(""));
    }

    #[test]
    fn mutate_tags_user_scope_sets_owner_id() {
        let user = Uuid::new_v4();
        let scope = map([("scope", "user")]);
        let tags = mutate_tags(user, &[&scope]);
        assert_eq!(tags.get(TAG_SCOPE).map(String::as_str), Some(SCOPE_USER));
        assert_eq!(
            tags.get(TAG_OWNER).map(String::as_str),
            Some(user.to_string().as_str())
        );
    }

    #[test]
    fn mutate_tags_org_scope_clears_owner() {
        let scope = map([("scope", "organization"), ("owner", "garbage")]);
        let tags = mutate_tags(Uuid::new_v4(), &[&scope]);
        assert_eq!(tags.get(TAG_OWNER).map(String::as_str), Some(""));
    }

    #[test]
    fn mutate_tags_unknown_scope_falls_back_to_org() {
        let scope = map([("scope", "weird")]);
        let tags = mutate_tags(Uuid::new_v4(), &[&scope]);
        assert_eq!(
            tags.get(TAG_SCOPE).map(String::as_str),
            Some(SCOPE_ORGANIZATION)
        );
        assert_eq!(tags.get(TAG_OWNER).map(String::as_str), Some(""));
    }

    #[test]
    fn mutate_tags_merges_and_skips_empty_overrides() {
        let a = map([("foo", "bar")]);
        let b = map([("foo", ""), ("baz", "qux")]);
        let tags = mutate_tags(Uuid::new_v4(), &[&a, &b]);
        assert_eq!(tags.get("foo").map(String::as_str), Some("bar"));
        assert_eq!(tags.get("baz").map(String::as_str), Some("qux"));
    }

    #[test]
    fn untagged_daemon_matches_untagged_job() {
        let daemon = map([("scope", "organization"), ("owner", "")]);
        let job = map([("scope", "organization"), ("owner", "")]);
        assert!(provisioner_tagset_matches(&daemon, &job));
    }

    #[test]
    fn untagged_job_requires_untagged_daemon() {
        let daemon = map([("scope", "organization"), ("owner", ""), ("env", "prod")]);
        let job = map([("scope", "organization"), ("owner", "")]);
        assert!(!provisioner_tagset_matches(&daemon, &job));
    }

    #[test]
    fn tagged_job_matches_superset_daemon() {
        let daemon = map([
            ("scope", "organization"),
            ("owner", ""),
            ("env", "prod"),
            ("dc", "chi"),
        ]);
        let job = map([("scope", "organization"), ("owner", ""), ("env", "prod")]);
        assert!(provisioner_tagset_matches(&daemon, &job));
    }

    #[test]
    fn tagged_job_rejects_missing_daemon_tag() {
        let daemon = map([("scope", "organization"), ("owner", "")]);
        let job = map([("scope", "organization"), ("owner", ""), ("env", "prod")]);
        assert!(!provisioner_tagset_matches(&daemon, &job));
    }

    #[test]
    fn user_scoped_job_rejects_org_scoped_daemon() {
        let daemon = map([("scope", "organization"), ("owner", "")]);
        let job = map([("scope", "user"), ("owner", "aaa")]);
        assert!(!provisioner_tagset_matches(&daemon, &job));
    }

    #[test]
    fn org_scoped_daemon_rejects_user_scoped_job_with_shared_extra_tag() {
        let daemon = map([("scope", "organization"), ("owner", ""), ("env", "prod")]);
        let job = map([("scope", "user"), ("owner", "aaa"), ("env", "prod")]);
        assert!(!provisioner_tagset_matches(&daemon, &job));
    }

    #[test]
    fn provisioner_tagset_matches_wildcard_any_value() {
        let daemon = map([("scope", "organization"), ("owner", ""), ("env", "*")]);
        let job = map([("scope", "organization"), ("owner", ""), ("env", "prod")]);
        assert!(provisioner_tagset_matches(&daemon, &job));

        let job_alt = map([("scope", "organization"), ("owner", ""), ("env", "stage")]);
        assert!(provisioner_tagset_matches(&daemon, &job_alt));
    }

    #[test]
    fn provisioner_tagset_matches_wildcard_miss_on_missing_key() {
        let daemon = map([("scope", "organization"), ("owner", ""), ("env", "*")]);
        let job = map([
            ("scope", "organization"),
            ("owner", ""),
            ("env", "prod"),
            ("dc", "chi"),
        ]);
        assert!(!provisioner_tagset_matches(&daemon, &job));
    }

    #[test]
    fn provisioner_tagset_wildcard_does_not_match_untagged_job() {
        // Even a "match-everything" daemon cannot match an untagged
        // org-scoped job because untagged jobs require exact equality.
        let daemon = map([("scope", "organization"), ("owner", ""), ("env", "*")]);
        let job = map([("scope", "organization"), ("owner", "")]);
        assert!(!provisioner_tagset_matches(&daemon, &job));
    }

    #[test]
    fn daemon_scope_preference_orders_org_before_user() {
        let org = map([("scope", "organization"), ("owner", "")]);
        let user = map([("scope", "user"), ("owner", "aaa")]);
        let unknown = map([("scope", "weird"), ("owner", "")]);
        assert!(daemon_scope_preference(&org) < daemon_scope_preference(&user));
        assert!(daemon_scope_preference(&user) < daemon_scope_preference(&unknown));
        assert_eq!(
            daemon_scope_preference(&org),
            DaemonScopePreference::Organization
        );
        assert_eq!(daemon_scope_preference(&user), DaemonScopePreference::User);
    }
}
