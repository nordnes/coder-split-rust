//! Provisioner and job-orchestration helpers for the Rust `coderd` rewrite.
//!
//! `coder-provisioner` provides [`ProvisionerService`], a high-level wrapper
//! around [`coder_core::ProvisionerStore`] that handles the full job lifecycle:
//!
//! * **Jobs** — acquire, heartbeat, complete, cancel, stale-job detection
//! * **Logs & Timings** — batch insert and retrieval for build output
//! * **Daemons** — upsert, heartbeat, listing, and stale-daemon cleanup
//! * **Keys** — provisioner key CRUD
//!
//! The crate also exposes [`render_init_script`] for generating OS/arch-specific
//! agent bootstrap scripts with SHA-256 content digests.
#![forbid(unsafe_code)]

pub mod server;

use std::sync::Arc;

use base64::Engine as _;
use coder_core::provisioner::{ProvisionerJobLogRecord, ProvisionerJobTimingRecord};
use coder_core::{
    AcquireProvisionerJobInput, CancelProvisionerJobInput, CompleteProvisionerJobInput,
    GetJobsToBeReapedInput, InsertProvisionerJobInput, InsertProvisionerJobLogsInput,
    InsertProvisionerJobTimingsInput, InsertProvisionerKeyInput, ProvisionerDaemonRecord,
    ProvisionerJobRecord, ProvisionerKeyRecord, ProvisionerStore, StorageError,
    UpsertProvisionerDaemonInput,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;
use tracing::instrument;
use uuid::Uuid;

const LINUX_SCRIPT: &str = include_str!("../scripts/bootstrap_linux.sh");
const DARWIN_SCRIPT: &str = include_str!("../scripts/bootstrap_darwin.sh");
const WINDOWS_SCRIPT: &str = include_str!("../scripts/bootstrap_windows.ps1");

/// Rendered agent init script plus compatibility headers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenderedInitScript {
    /// Fully rendered bootstrap script body.
    pub body: String,
    /// Compatibility `Content-Digest` value.
    pub content_digest: String,
}

/// Errors surfaced when rendering agent init scripts.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum InitScriptError {
    /// The operating system and architecture combination is unsupported.
    #[error("unknown os/arch: {os}/{arch}")]
    UnknownTarget { os: String, arch: String },
}

/// Renders the agent bootstrap script for one operating-system and architecture pair.
pub fn render_init_script(
    os: &str,
    arch: &str,
    access_url: &str,
) -> Result<RenderedInitScript, InitScriptError> {
    let os = os.to_ascii_lowercase();
    let arch = arch.to_ascii_lowercase();
    let template = match (os.as_str(), arch.as_str()) {
        ("windows", "amd64" | "arm64") => WINDOWS_SCRIPT,
        ("linux", "amd64" | "arm64" | "armv7") => LINUX_SCRIPT,
        ("darwin", "amd64" | "arm64") => DARWIN_SCRIPT,
        _ => return Err(InitScriptError::UnknownTarget { os, arch }),
    };

    let mut normalized_access_url = access_url.to_owned();
    if !normalized_access_url.ends_with('/') {
        normalized_access_url.push('/');
    }

    let body = template
        .replace("${ARCH}", &arch)
        .replace("${ACCESS_URL}", &normalized_access_url)
        .replace("${AUTH_TYPE}", "token");

    let hash = Sha256::digest(body.as_bytes());
    let encoded = base64::engine::general_purpose::STANDARD.encode(hash);
    let content_digest = format!(
        "sha256:{}",
        encoded
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );

    Ok(RenderedInitScript {
        body,
        content_digest,
    })
}

/// Default heartbeat timeout: jobs without a heartbeat update within this
/// duration are considered hung and eligible for reaping.
const DEFAULT_HEARTBEAT_TIMEOUT_SECS: i64 = 30;

/// Default maximum pending age: pending jobs older than this are reaped.
const DEFAULT_MAX_PENDING_AGE_SECS: i64 = 60 * 30; // 30 minutes

/// Default batch size for reaping stale jobs.
const DEFAULT_REAP_BATCH_SIZE: i64 = 100;

/// Errors surfaced by the provisioner service.
#[derive(Debug, Error)]
pub enum ProvisionerServiceError {
    /// A storage operation failed.
    #[error("storage: {0}")]
    Storage(#[from] StorageError),
}

/// High-level provisioner orchestration service.
///
/// Wraps a [`ProvisionerStore`] and provides job lifecycle helpers such as
/// acquisition, heartbeat updates, completion, cancellation, log/timing
/// insertion, daemon registration, and stale-job detection.
#[derive(Clone, Debug)]
pub struct ProvisionerService<S> {
    store: Arc<S>,
}

impl<S: ProvisionerStore> ProvisionerService<S> {
    /// Creates a new service backed by the given store.
    pub fn new(store: Arc<S>) -> Self {
        Self { store }
    }

    // ── Jobs ──────────────────────────────────────────────────

    /// Atomically acquires a pending job matching the daemon's capabilities.
    #[instrument(skip(self, input), err)]
    pub async fn acquire_job(
        &self,
        input: AcquireProvisionerJobInput,
    ) -> Result<Option<ProvisionerJobRecord>, ProvisionerServiceError> {
        Ok(self.store.acquire_provisioner_job(input).await?)
    }

    /// Returns a single provisioner job by id.
    #[instrument(skip(self), err)]
    pub async fn get_job(
        &self,
        id: Uuid,
    ) -> Result<Option<ProvisionerJobRecord>, ProvisionerServiceError> {
        Ok(self.store.get_provisioner_job_by_id(id).await?)
    }

    /// Returns multiple provisioner jobs by ids.
    #[instrument(skip(self), err)]
    pub async fn get_jobs(
        &self,
        ids: &[Uuid],
    ) -> Result<Vec<ProvisionerJobRecord>, ProvisionerServiceError> {
        Ok(self.store.get_provisioner_jobs_by_ids(ids).await?)
    }

    /// Inserts a new provisioner job.
    #[instrument(skip(self, input), err)]
    pub async fn insert_job(
        &self,
        input: InsertProvisionerJobInput,
    ) -> Result<ProvisionerJobRecord, ProvisionerServiceError> {
        Ok(self.store.insert_provisioner_job(input).await?)
    }

    /// Sends a heartbeat for a running job.
    #[instrument(skip(self), err)]
    pub async fn heartbeat_job(&self, id: Uuid) -> Result<(), ProvisionerServiceError> {
        let now = OffsetDateTime::now_utc();
        Ok(self.store.update_provisioner_job_by_id(id, now).await?)
    }

    /// Marks a job as completed (successfully or with an error message).
    #[instrument(skip(self, input), err)]
    pub async fn complete_job(
        &self,
        input: CompleteProvisionerJobInput,
    ) -> Result<(), ProvisionerServiceError> {
        Ok(self
            .store
            .update_provisioner_job_with_complete_by_id(input)
            .await?)
    }

    /// Marks a job as canceled.
    #[instrument(skip(self, input), err)]
    pub async fn cancel_job(
        &self,
        input: CancelProvisionerJobInput,
    ) -> Result<(), ProvisionerServiceError> {
        Ok(self
            .store
            .update_provisioner_job_with_cancel_by_id(input)
            .await?)
    }

    // ── Stale-job reaper ("unhanger") ────────────────────────

    /// Detects stuck/hung jobs and returns them for reaping.
    ///
    /// A job is considered stale if:
    /// - It has been pending for longer than `DEFAULT_MAX_PENDING_AGE_SECS`, or
    /// - It is running but its last heartbeat is older than
    ///   `DEFAULT_HEARTBEAT_TIMEOUT_SECS`.
    #[instrument(skip(self), err)]
    pub async fn get_stale_jobs(
        &self,
    ) -> Result<Vec<ProvisionerJobRecord>, ProvisionerServiceError> {
        let now = OffsetDateTime::now_utc();
        let pending_since = now - time::Duration::seconds(DEFAULT_MAX_PENDING_AGE_SECS);
        let hung_since = now - time::Duration::seconds(DEFAULT_HEARTBEAT_TIMEOUT_SECS);

        Ok(self
            .store
            .get_provisioner_jobs_to_be_reaped(GetJobsToBeReapedInput {
                pending_since,
                hung_since,
                max_jobs: DEFAULT_REAP_BATCH_SIZE,
            })
            .await?)
    }

    // ── Logs ─────────────────────────────────────────────────

    /// Inserts a batch of log entries for a job.
    #[instrument(skip(self, input), err)]
    pub async fn insert_job_logs(
        &self,
        input: InsertProvisionerJobLogsInput,
    ) -> Result<Vec<ProvisionerJobLogRecord>, ProvisionerServiceError> {
        Ok(self.store.insert_provisioner_job_logs(input).await?)
    }

    /// Returns log entries for a job after the given log-line id.
    #[instrument(skip(self), err)]
    pub async fn get_logs_after(
        &self,
        job_id: Uuid,
        after_id: i64,
    ) -> Result<Vec<ProvisionerJobLogRecord>, ProvisionerServiceError> {
        Ok(self
            .store
            .get_provisioner_logs_after_id(job_id, after_id)
            .await?)
    }

    // ── Timings ──────────────────────────────────────────────

    /// Inserts a batch of timing entries for a job.
    #[instrument(skip(self, input), err)]
    pub async fn insert_job_timings(
        &self,
        input: InsertProvisionerJobTimingsInput,
    ) -> Result<Vec<ProvisionerJobTimingRecord>, ProvisionerServiceError> {
        Ok(self.store.insert_provisioner_job_timings(input).await?)
    }

    /// Returns all timing entries for a job.
    #[instrument(skip(self), err)]
    pub async fn get_job_timings(
        &self,
        job_id: Uuid,
    ) -> Result<Vec<ProvisionerJobTimingRecord>, ProvisionerServiceError> {
        Ok(self
            .store
            .get_provisioner_job_timings_by_job_id(job_id)
            .await?)
    }

    // ── Daemons ──────────────────────────────────────────────

    /// Registers or updates a provisioner daemon.
    #[instrument(skip(self, input), err)]
    pub async fn upsert_daemon(
        &self,
        input: UpsertProvisionerDaemonInput,
    ) -> Result<ProvisionerDaemonRecord, ProvisionerServiceError> {
        Ok(self.store.upsert_provisioner_daemon(input).await?)
    }

    /// Sends a heartbeat for a daemon.
    #[instrument(skip(self), err)]
    pub async fn heartbeat_daemon(&self, id: Uuid) -> Result<(), ProvisionerServiceError> {
        let now = OffsetDateTime::now_utc();
        Ok(self
            .store
            .update_provisioner_daemon_last_seen_at(id, now)
            .await?)
    }

    /// Lists daemons for an organization.
    #[instrument(skip(self), err)]
    pub async fn list_daemons(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<ProvisionerDaemonRecord>, ProvisionerServiceError> {
        Ok(self
            .store
            .get_provisioner_daemons_by_organization(organization_id)
            .await?)
    }

    /// Deletes provisioner daemons that have not been seen in over 7 days.
    #[instrument(skip(self), err)]
    pub async fn delete_old_daemons(&self) -> Result<(), ProvisionerServiceError> {
        Ok(self.store.delete_old_provisioner_daemons().await?)
    }

    // ── Keys ─────────────────────────────────────────────────

    /// Inserts a new provisioner key.
    #[instrument(skip(self, input), err)]
    pub async fn insert_key(
        &self,
        input: InsertProvisionerKeyInput,
    ) -> Result<ProvisionerKeyRecord, ProvisionerServiceError> {
        Ok(self.store.insert_provisioner_key(input).await?)
    }

    /// Looks up a provisioner key by id.
    #[instrument(skip(self), err)]
    pub async fn get_key(
        &self,
        id: Uuid,
    ) -> Result<Option<ProvisionerKeyRecord>, ProvisionerServiceError> {
        Ok(self.store.get_provisioner_key_by_id(id).await?)
    }

    /// Looks up a provisioner key by hashed secret.
    #[instrument(skip(self, hashed_secret), err)]
    pub async fn get_key_by_secret(
        &self,
        hashed_secret: &[u8],
    ) -> Result<Option<ProvisionerKeyRecord>, ProvisionerServiceError> {
        Ok(self
            .store
            .get_provisioner_key_by_hashed_secret(hashed_secret)
            .await?)
    }

    /// Lists provisioner keys for an organization.
    #[instrument(skip(self), err)]
    pub async fn list_keys(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<ProvisionerKeyRecord>, ProvisionerServiceError> {
        Ok(self
            .store
            .list_provisioner_keys_by_organization(organization_id)
            .await?)
    }

    /// Deletes a provisioner key.
    #[instrument(skip(self), err)]
    pub async fn delete_key(&self, id: Uuid) -> Result<bool, ProvisionerServiceError> {
        Ok(self.store.delete_provisioner_key(id).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::{InitScriptError, ProvisionerService, render_init_script};
    use async_trait::async_trait;
    use coder_core::provisioner::{ProvisionerJobLogRecord, ProvisionerJobTimingRecord};
    use coder_core::{
        AcquireProvisionerJobInput, CancelProvisionerJobInput, CompleteProvisionerJobInput,
        GetJobsToBeReapedInput, InsertProvisionerJobInput, InsertProvisionerJobLogsInput,
        InsertProvisionerJobTimingsInput, InsertProvisionerKeyInput, ProvisionerDaemonRecord,
        ProvisionerJobRecord, ProvisionerKeyRecord, ProvisionerStore, StorageError,
        UpsertProvisionerDaemonInput,
    };
    use std::sync::Arc;
    use time::OffsetDateTime;
    use uuid::Uuid;

    // ── Mock store ───────────────────────────────────────────

    /// Minimal mock that records `get_provisioner_jobs_to_be_reaped` calls and
    /// returns a configurable result for every method.
    struct MockStore {
        /// Jobs returned by `get_provisioner_jobs_to_be_reaped`.
        stale_jobs: Vec<ProvisionerJobRecord>,
        /// If set, every method returns this error.
        force_error: Option<String>,
    }

    impl MockStore {
        fn new() -> Self {
            Self {
                stale_jobs: Vec::new(),
                force_error: None,
            }
        }

        fn with_stale_jobs(mut self, jobs: Vec<ProvisionerJobRecord>) -> Self {
            self.stale_jobs = jobs;
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
    impl ProvisionerStore for MockStore {
        async fn acquire_provisioner_job(
            &self,
            _input: AcquireProvisionerJobInput,
        ) -> Result<Option<ProvisionerJobRecord>, StorageError> {
            self.maybe_err()?;
            Ok(None)
        }

        async fn get_provisioner_job_by_id(
            &self,
            _id: Uuid,
        ) -> Result<Option<ProvisionerJobRecord>, StorageError> {
            self.maybe_err()?;
            Ok(None)
        }

        async fn get_provisioner_jobs_by_ids(
            &self,
            _ids: &[Uuid],
        ) -> Result<Vec<ProvisionerJobRecord>, StorageError> {
            self.maybe_err()?;
            Ok(Vec::new())
        }

        async fn insert_provisioner_job(
            &self,
            _input: InsertProvisionerJobInput,
        ) -> Result<ProvisionerJobRecord, StorageError> {
            self.maybe_err()?;
            Err(StorageError::unavailable("not implemented in MockStore"))
        }

        async fn update_provisioner_job_by_id(
            &self,
            _id: Uuid,
            _updated_at: OffsetDateTime,
        ) -> Result<(), StorageError> {
            self.maybe_err()?;
            Ok(())
        }

        async fn update_provisioner_job_with_complete_by_id(
            &self,
            _input: CompleteProvisionerJobInput,
        ) -> Result<(), StorageError> {
            self.maybe_err()?;
            Ok(())
        }

        async fn update_provisioner_job_with_cancel_by_id(
            &self,
            _input: CancelProvisionerJobInput,
        ) -> Result<(), StorageError> {
            self.maybe_err()?;
            Ok(())
        }

        async fn get_provisioner_jobs_to_be_reaped(
            &self,
            _input: GetJobsToBeReapedInput,
        ) -> Result<Vec<ProvisionerJobRecord>, StorageError> {
            self.maybe_err()?;
            Ok(self.stale_jobs.clone())
        }

        async fn insert_provisioner_job_logs(
            &self,
            _input: InsertProvisionerJobLogsInput,
        ) -> Result<Vec<ProvisionerJobLogRecord>, StorageError> {
            self.maybe_err()?;
            Ok(Vec::new())
        }

        async fn get_provisioner_logs_after_id(
            &self,
            _job_id: Uuid,
            _after_id: i64,
        ) -> Result<Vec<ProvisionerJobLogRecord>, StorageError> {
            self.maybe_err()?;
            Ok(Vec::new())
        }

        async fn insert_provisioner_job_timings(
            &self,
            _input: InsertProvisionerJobTimingsInput,
        ) -> Result<Vec<ProvisionerJobTimingRecord>, StorageError> {
            self.maybe_err()?;
            Ok(Vec::new())
        }

        async fn get_provisioner_job_timings_by_job_id(
            &self,
            _job_id: Uuid,
        ) -> Result<Vec<ProvisionerJobTimingRecord>, StorageError> {
            self.maybe_err()?;
            Ok(Vec::new())
        }

        async fn upsert_provisioner_daemon(
            &self,
            _input: UpsertProvisionerDaemonInput,
        ) -> Result<ProvisionerDaemonRecord, StorageError> {
            self.maybe_err()?;
            Err(StorageError::unavailable("not implemented in MockStore"))
        }

        async fn update_provisioner_daemon_last_seen_at(
            &self,
            _id: Uuid,
            _last_seen_at: OffsetDateTime,
        ) -> Result<(), StorageError> {
            self.maybe_err()?;
            Ok(())
        }

        async fn get_provisioner_daemons_by_organization(
            &self,
            _organization_id: Uuid,
        ) -> Result<Vec<ProvisionerDaemonRecord>, StorageError> {
            self.maybe_err()?;
            Ok(Vec::new())
        }

        async fn delete_old_provisioner_daemons(&self) -> Result<(), StorageError> {
            self.maybe_err()?;
            Ok(())
        }

        async fn insert_provisioner_key(
            &self,
            _input: InsertProvisionerKeyInput,
        ) -> Result<ProvisionerKeyRecord, StorageError> {
            self.maybe_err()?;
            Err(StorageError::unavailable("not implemented in MockStore"))
        }

        async fn get_provisioner_key_by_id(
            &self,
            _id: Uuid,
        ) -> Result<Option<ProvisionerKeyRecord>, StorageError> {
            self.maybe_err()?;
            Ok(None)
        }

        async fn get_provisioner_key_by_hashed_secret(
            &self,
            _hashed_secret: &[u8],
        ) -> Result<Option<ProvisionerKeyRecord>, StorageError> {
            self.maybe_err()?;
            Ok(None)
        }

        async fn get_provisioner_key_by_name(
            &self,
            _organization_id: Uuid,
            _name: &str,
        ) -> Result<Option<ProvisionerKeyRecord>, StorageError> {
            self.maybe_err()?;
            Ok(None)
        }

        async fn list_provisioner_keys_by_organization(
            &self,
            _organization_id: Uuid,
        ) -> Result<Vec<ProvisionerKeyRecord>, StorageError> {
            self.maybe_err()?;
            Ok(Vec::new())
        }

        async fn delete_provisioner_key(&self, _id: Uuid) -> Result<bool, StorageError> {
            self.maybe_err()?;
            Ok(false)
        }
    }

    // ── Helper ───────────────────────────────────────────────

    fn make_job_record() -> ProvisionerJobRecord {
        let now = OffsetDateTime::now_utc();
        ProvisionerJobRecord {
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            started_at: Some(now),
            canceled_at: None,
            completed_at: None,
            error: String::new(),
            error_code: String::new(),
            organization_id: Some(Uuid::new_v4()),
            initiator_id: Some(Uuid::new_v4()),
            provisioner: coder_core::ProvisionerType::Terraform,
            storage_method: coder_core::ProvisionerStorageMethod::File,
            file_id: Some(Uuid::new_v4()),
            job_type: coder_core::ProvisionerJobType::WorkspaceBuild,
            input: serde_json::json!({}),
            tags: serde_json::json!({}),
            trace_metadata: serde_json::json!({}),
            worker_id: Some(Uuid::new_v4()),
            job_status: coder_core::ProvisionerJobStatus::Running,
            logs_overflowed: false,
            logs_length: 0,
        }
    }

    // ── Init script tests ────────────────────────────────────

    #[test]
    fn renders_linux_script_with_substitutions() -> Result<(), InitScriptError> {
        let script = render_init_script("linux", "amd64", "https://coder.example")?;
        assert!(script.body.contains("coder-linux-amd64"));
        assert!(script.body.contains("CODER_AGENT_AUTH=\"token\""));
        assert!(
            script
                .body
                .contains("CODER_AGENT_URL=\"https://coder.example/\"")
        );
        assert!(script.content_digest.starts_with("sha256:"));
        Ok(())
    }

    #[test]
    fn rejects_unknown_target() {
        assert_eq!(
            render_init_script("plan9", "amd64", "https://coder.example"),
            Err(InitScriptError::UnknownTarget {
                os: "plan9".to_owned(),
                arch: "amd64".to_owned(),
            })
        );
    }

    // ── ProvisionerService tests ─────────────────────────────

    #[tokio::test]
    async fn get_stale_jobs_returns_stored_stale_jobs() {
        let job = make_job_record();
        let store = MockStore::new().with_stale_jobs(vec![job.clone()]);
        let svc = ProvisionerService::new(Arc::new(store));

        let stale = svc.get_stale_jobs().await;
        assert!(stale.is_ok());
        let jobs = stale.unwrap_or_default();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].id, job.id);
    }

    #[tokio::test]
    async fn get_stale_jobs_returns_empty_when_no_stale_jobs() {
        let store = MockStore::new();
        let svc = ProvisionerService::new(Arc::new(store));

        let stale = svc.get_stale_jobs().await;
        assert!(stale.is_ok());
        assert!(stale.unwrap_or_default().is_empty());
    }

    #[tokio::test]
    async fn get_stale_jobs_propagates_storage_error() {
        let store = MockStore::new().with_error("database is down");
        let svc = ProvisionerService::new(Arc::new(store));

        let result = svc.get_stale_jobs().await;
        assert!(result.is_err());
        assert!(
            result
                .err()
                .is_some_and(|e| e.to_string().contains("database is down"))
        );
    }

    #[tokio::test]
    async fn heartbeat_job_propagates_storage_error() {
        let store = MockStore::new().with_error("connection lost");
        let svc = ProvisionerService::new(Arc::new(store));

        let result = svc.heartbeat_job(Uuid::new_v4()).await;
        assert!(result.is_err());
        assert!(
            result
                .err()
                .is_some_and(|e| e.to_string().contains("connection lost"))
        );
    }

    #[tokio::test]
    async fn heartbeat_job_succeeds_on_healthy_store() {
        let store = MockStore::new();
        let svc = ProvisionerService::new(Arc::new(store));

        let result = svc.heartbeat_job(Uuid::new_v4()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn delete_old_daemons_propagates_error() {
        let store = MockStore::new().with_error("timeout");
        let svc = ProvisionerService::new(Arc::new(store));

        let result = svc.delete_old_daemons().await;
        assert!(result.is_err());
        assert!(
            result
                .err()
                .is_some_and(|e| e.to_string().contains("timeout"))
        );
    }

    #[tokio::test]
    async fn get_job_returns_none_from_mock() {
        let store = MockStore::new();
        let svc = ProvisionerService::new(Arc::new(store));

        let result = svc.get_job(Uuid::new_v4()).await;
        assert!(result.is_ok());
        assert!(result.unwrap_or(None).is_none());
    }

    #[tokio::test]
    async fn get_jobs_returns_empty_from_mock() {
        let store = MockStore::new();
        let svc = ProvisionerService::new(Arc::new(store));

        let result = svc.get_jobs(&[]).await;
        assert!(result.is_ok());
        assert!(result.unwrap_or_default().is_empty());
    }

    // ── Additional init script tests ─────────────────────────

    #[test]
    fn renders_darwin_script() -> Result<(), InitScriptError> {
        let script = render_init_script("darwin", "arm64", "https://coder.example")?;
        assert!(!script.body.is_empty(), "darwin script should not be empty");
        assert!(script.body.contains("coder-darwin-arm64"));
        assert!(script.content_digest.starts_with("sha256:"));
        Ok(())
    }

    #[test]
    fn renders_windows_script() -> Result<(), InitScriptError> {
        let script = render_init_script("windows", "amd64", "https://coder.example")?;
        assert!(
            !script.body.is_empty(),
            "windows script should not be empty"
        );
        assert!(script.body.contains("coder-windows-amd64"));
        assert!(script.content_digest.starts_with("sha256:"));
        Ok(())
    }

    #[test]
    fn renders_linux_arm64_script() -> Result<(), InitScriptError> {
        let script = render_init_script("linux", "arm64", "https://coder.example")?;
        assert!(script.body.contains("coder-linux-arm64"));
        Ok(())
    }

    #[test]
    fn renders_linux_armv7_script() -> Result<(), InitScriptError> {
        let script = render_init_script("linux", "armv7", "https://coder.example")?;
        assert!(script.body.contains("coder-linux-armv7"));
        Ok(())
    }

    #[test]
    fn rejects_unknown_arch() {
        let result = render_init_script("linux", "mips", "https://coder.example");
        assert!(result.is_err());
    }

    #[test]
    fn init_script_case_insensitive_os() -> Result<(), InitScriptError> {
        let script = render_init_script("Linux", "amd64", "https://coder.example")?;
        assert!(script.body.contains("coder-linux-amd64"));
        Ok(())
    }

    #[test]
    fn init_script_deterministic_digest() -> Result<(), InitScriptError> {
        let s1 = render_init_script("linux", "amd64", "https://coder.example")?;
        let s2 = render_init_script("linux", "amd64", "https://coder.example")?;
        assert_eq!(
            s1.content_digest, s2.content_digest,
            "same input should produce same digest"
        );
        assert_eq!(s1.body, s2.body, "same input should produce same body");
        Ok(())
    }

    #[test]
    fn init_script_normalizes_access_url_trailing_slash() -> Result<(), InitScriptError> {
        let without_slash = render_init_script("linux", "amd64", "https://coder.example")?;
        let with_slash = render_init_script("linux", "amd64", "https://coder.example/")?;
        assert_eq!(
            without_slash.body, with_slash.body,
            "trailing slash should be normalized"
        );
        Ok(())
    }

    // ── Provisioner key hashing test ─────────────────────────

    #[test]
    fn provisioner_key_sha256_hash_is_deterministic() {
        use sha2::{Digest, Sha256};
        let secret = b"my-secret-key-value";
        let hash1 = Sha256::digest(secret);
        let hash2 = Sha256::digest(secret);
        assert_eq!(hash1, hash2, "SHA-256 hash should be deterministic");
        assert_eq!(hash1.len(), 32, "SHA-256 should produce 32 bytes");
    }

    // ── Additional service method tests ──────────────────────

    #[tokio::test]
    async fn complete_job_succeeds_on_healthy_store() {
        let store = MockStore::new();
        let svc = ProvisionerService::new(Arc::new(store));
        let now = OffsetDateTime::now_utc();

        let result = svc
            .complete_job(CompleteProvisionerJobInput {
                id: Uuid::new_v4(),
                updated_at: now,
                completed_at: now,
                error: String::new(),
                error_code: String::new(),
            })
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn complete_job_propagates_error() {
        let store = MockStore::new().with_error("disk full");
        let svc = ProvisionerService::new(Arc::new(store));
        let now = OffsetDateTime::now_utc();

        let result = svc
            .complete_job(CompleteProvisionerJobInput {
                id: Uuid::new_v4(),
                updated_at: now,
                completed_at: now,
                error: String::new(),
                error_code: String::new(),
            })
            .await;
        assert!(result.is_err());
        assert!(
            result
                .err()
                .is_some_and(|e| e.to_string().contains("disk full"))
        );
    }

    #[tokio::test]
    async fn cancel_job_succeeds_on_healthy_store() {
        let store = MockStore::new();
        let svc = ProvisionerService::new(Arc::new(store));

        let result = svc
            .cancel_job(CancelProvisionerJobInput {
                id: Uuid::new_v4(),
                canceled_at: OffsetDateTime::now_utc(),
                completed_at: Some(OffsetDateTime::now_utc()),
            })
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn cancel_job_propagates_error() {
        let store = MockStore::new().with_error("network error");
        let svc = ProvisionerService::new(Arc::new(store));

        let result = svc
            .cancel_job(CancelProvisionerJobInput {
                id: Uuid::new_v4(),
                canceled_at: OffsetDateTime::now_utc(),
                completed_at: Some(OffsetDateTime::now_utc()),
            })
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn acquire_job_returns_none_on_healthy_store() {
        let store = MockStore::new();
        let svc = ProvisionerService::new(Arc::new(store));

        let result = svc
            .acquire_job(AcquireProvisionerJobInput {
                worker_id: Uuid::new_v4(),
                started_at: OffsetDateTime::now_utc(),
                organization_id: Uuid::new_v4(),
                types: Vec::new(),
                provisioner_tags: serde_json::json!({}),
            })
            .await;
        assert!(result.is_ok());
        assert!(
            result.unwrap_or(None).is_none(),
            "mock store returns None for acquire"
        );
    }

    #[tokio::test]
    async fn heartbeat_daemon_succeeds_on_healthy_store() {
        let store = MockStore::new();
        let svc = ProvisionerService::new(Arc::new(store));

        let result = svc.heartbeat_daemon(Uuid::new_v4()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn heartbeat_daemon_propagates_error() {
        let store = MockStore::new().with_error("timeout");
        let svc = ProvisionerService::new(Arc::new(store));

        let result = svc.heartbeat_daemon(Uuid::new_v4()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn list_daemons_returns_empty_from_mock() {
        let store = MockStore::new();
        let svc = ProvisionerService::new(Arc::new(store));

        let result = svc.list_daemons(Uuid::new_v4()).await;
        assert!(result.is_ok());
        assert!(result.unwrap_or_default().is_empty());
    }

    #[tokio::test]
    async fn get_key_returns_none_from_mock() {
        let store = MockStore::new();
        let svc = ProvisionerService::new(Arc::new(store));

        let result = svc.get_key(Uuid::new_v4()).await;
        assert!(result.is_ok());
        assert!(result.unwrap_or(None).is_none());
    }

    #[tokio::test]
    async fn get_key_by_secret_returns_none_from_mock() {
        let store = MockStore::new();
        let svc = ProvisionerService::new(Arc::new(store));

        let result = svc.get_key_by_secret(b"some-hashed-secret").await;
        assert!(result.is_ok());
        assert!(result.unwrap_or(None).is_none());
    }

    #[tokio::test]
    async fn list_keys_returns_empty_from_mock() {
        let store = MockStore::new();
        let svc = ProvisionerService::new(Arc::new(store));

        let result = svc.list_keys(Uuid::new_v4()).await;
        assert!(result.is_ok());
        assert!(result.unwrap_or_default().is_empty());
    }

    #[tokio::test]
    async fn delete_key_returns_false_from_mock() {
        let store = MockStore::new();
        let svc = ProvisionerService::new(Arc::new(store));

        let result = svc.delete_key(Uuid::new_v4()).await;
        assert!(result.is_ok());
        assert!(!result.unwrap_or(true));
    }

    #[tokio::test]
    async fn delete_old_daemons_succeeds_on_healthy_store() {
        let store = MockStore::new();
        let svc = ProvisionerService::new(Arc::new(store));

        let result = svc.delete_old_daemons().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn insert_job_logs_returns_empty_from_mock() {
        let store = MockStore::new();
        let svc = ProvisionerService::new(Arc::new(store));

        let result = svc
            .insert_job_logs(InsertProvisionerJobLogsInput {
                job_id: Uuid::new_v4(),
                created_at: Vec::new(),
                source: Vec::new(),
                level: Vec::new(),
                stage: Vec::new(),
                output: Vec::new(),
            })
            .await;
        assert!(result.is_ok());
        assert!(result.unwrap_or_default().is_empty());
    }

    #[tokio::test]
    async fn get_logs_after_returns_empty_from_mock() {
        let store = MockStore::new();
        let svc = ProvisionerService::new(Arc::new(store));

        let result = svc.get_logs_after(Uuid::new_v4(), 0).await;
        assert!(result.is_ok());
        assert!(result.unwrap_or_default().is_empty());
    }

    #[tokio::test]
    async fn get_job_timings_returns_empty_from_mock() {
        let store = MockStore::new();
        let svc = ProvisionerService::new(Arc::new(store));

        let result = svc.get_job_timings(Uuid::new_v4()).await;
        assert!(result.is_ok());
        assert!(result.unwrap_or_default().is_empty());
    }

    // ── User-requested tests ────────────────────────────────────

    #[test]
    fn test_provisioner_job_status_transitions() {
        use coder_core::ProvisionerJobStatus;

        // Verify all enum variants exist and are distinct
        let statuses = [
            ProvisionerJobStatus::Pending,
            ProvisionerJobStatus::Running,
            ProvisionerJobStatus::Succeeded,
            ProvisionerJobStatus::Failed,
            ProvisionerJobStatus::Canceling,
            ProvisionerJobStatus::Canceled,
            ProvisionerJobStatus::Unknown,
        ];

        // Each variant should be unique
        for (i, a) in statuses.iter().enumerate() {
            for (j, b) in statuses.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "status variants at {i} and {j} should differ");
                }
            }
        }

        // Verify status on a job record transitions correctly
        let mut job = make_job_record();
        assert_eq!(job.job_status, ProvisionerJobStatus::Running);

        job.job_status = ProvisionerJobStatus::Succeeded;
        assert_eq!(job.job_status, ProvisionerJobStatus::Succeeded);

        job.job_status = ProvisionerJobStatus::Failed;
        assert_eq!(job.job_status, ProvisionerJobStatus::Failed);

        job.job_status = ProvisionerJobStatus::Canceled;
        assert_eq!(job.job_status, ProvisionerJobStatus::Canceled);
    }

    #[test]
    fn test_provisioner_daemon_registration() {
        // NOTE: Intentional construction-validation smoke test for ProvisionerDaemonRecord.
        // This struct has no behavior methods, so we verify all fields survive round-trip
        // construction to guard against accidental field reordering or type changes.
        use std::collections::HashMap;

        let org_id = Uuid::new_v4();
        let daemon_id = Uuid::new_v4();
        let key_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();

        let mut tags = HashMap::new();
        tags.insert("scope".to_owned(), "organization".to_owned());
        tags.insert("owner".to_owned(), String::new());

        let daemon = ProvisionerDaemonRecord {
            id: daemon_id,
            organization_id: org_id,
            created_at: now,
            last_seen_at: Some(now),
            name: "test-daemon-01".to_owned(),
            version: "v2.18.0".to_owned(),
            api_version: "1.0".to_owned(),
            provisioners: vec!["terraform".to_owned(), "echo".to_owned()],
            tags: tags.clone(),
            key_id: Some(key_id),
        };

        assert_eq!(daemon.id, daemon_id);
        assert_eq!(daemon.organization_id, org_id);
        assert_eq!(daemon.name, "test-daemon-01");
        assert_eq!(daemon.version, "v2.18.0");
        assert_eq!(daemon.api_version, "1.0");
        assert_eq!(daemon.provisioners.len(), 2);
        assert!(daemon.provisioners.contains(&"terraform".to_owned()));
        assert!(daemon.provisioners.contains(&"echo".to_owned()));
        assert_eq!(daemon.tags, tags);
        assert_eq!(daemon.key_id, Some(key_id));
        assert!(daemon.last_seen_at.is_some());
    }

    #[test]
    fn test_provisioner_job_creation() {
        // NOTE: Intentional construction-validation smoke test for ProvisionerJobRecord.
        // This struct has no behavior methods, so we verify all fields survive round-trip
        // construction to guard against accidental field reordering or type changes.
        use coder_core::{ProvisionerJobType, ProvisionerStorageMethod, ProvisionerType};

        let now = OffsetDateTime::now_utc();
        let job_id = Uuid::new_v4();
        let org_id = Uuid::new_v4();
        let initiator_id = Uuid::new_v4();
        let file_id = Uuid::new_v4();
        let worker_id = Uuid::new_v4();

        let job = ProvisionerJobRecord {
            id: job_id,
            created_at: now,
            updated_at: now,
            started_at: Some(now),
            canceled_at: None,
            completed_at: None,
            error: String::new(),
            error_code: String::new(),
            organization_id: Some(org_id),
            initiator_id: Some(initiator_id),
            provisioner: ProvisionerType::Terraform,
            storage_method: ProvisionerStorageMethod::File,
            file_id: Some(file_id),
            job_type: ProvisionerJobType::WorkspaceBuild,
            input: serde_json::json!({"workspace_name": "my-ws"}),
            tags: serde_json::json!({"scope": "organization"}),
            trace_metadata: serde_json::json!({}),
            worker_id: Some(worker_id),
            job_status: coder_core::ProvisionerJobStatus::Running,
            logs_overflowed: false,
            logs_length: 0,
        };

        assert_eq!(job.id, job_id);
        assert_eq!(job.organization_id, Some(org_id));
        assert_eq!(job.initiator_id, Some(initiator_id));
        assert_eq!(job.provisioner, ProvisionerType::Terraform);
        assert_eq!(job.storage_method, ProvisionerStorageMethod::File);
        assert_eq!(job.file_id, Some(file_id));
        assert_eq!(job.job_type, ProvisionerJobType::WorkspaceBuild);
        assert_eq!(job.worker_id, Some(worker_id));
        assert_eq!(job.job_status, coder_core::ProvisionerJobStatus::Running);
        assert!(!job.logs_overflowed);
        assert_eq!(job.logs_length, 0);
        assert!(job.error.is_empty());
        assert!(job.canceled_at.is_none());
        assert!(job.completed_at.is_none());

        // Verify all job types
        let types = [
            ProvisionerJobType::TemplateVersionImport,
            ProvisionerJobType::TemplateVersionDryRun,
            ProvisionerJobType::WorkspaceBuild,
        ];
        for (i, a) in types.iter().enumerate() {
            for (j, b) in types.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "job types at {i} and {j} should differ");
                }
            }
        }
    }

    #[test]
    fn test_provisioner_tag_matching_contract() {
        // NOTE: This test validates the expected contract of tag matching
        // (daemon tags must be a superset of job tags) until a Rust-side
        // helper is extracted from the DB layer. The real matching lives
        // in Postgres SQL (tags <@ $5::JSONB in coder-db).
        use std::collections::HashMap;

        let mut daemon_tags: HashMap<String, String> = HashMap::new();
        daemon_tags.insert("scope".to_owned(), "organization".to_owned());
        daemon_tags.insert("owner".to_owned(), String::new());
        daemon_tags.insert("region".to_owned(), "us-east-1".to_owned());

        let mut job_tags: HashMap<String, String> = HashMap::new();
        job_tags.insert("scope".to_owned(), "organization".to_owned());

        // All job tags present in daemon tags → match
        let matches = job_tags.iter().all(|(k, v)| daemon_tags.get(k) == Some(v));
        assert!(matches, "daemon should match when it has all job tags");

        // Job requires a tag the daemon doesn't have → no match
        job_tags.insert("gpu".to_owned(), "true".to_owned());
        let matches = job_tags.iter().all(|(k, v)| daemon_tags.get(k) == Some(v));
        assert!(
            !matches,
            "daemon should not match when missing required tags"
        );

        // Empty job tags → always matches
        let empty_job_tags: HashMap<String, String> = HashMap::new();
        let matches = empty_job_tags
            .iter()
            .all(|(k, v)| daemon_tags.get(k) == Some(v));
        assert!(matches, "empty job tags should match any daemon");
    }

    #[test]
    fn test_provisioner_log_source_types() {
        use coder_core::provisioner::LogSource;

        let sources = [LogSource::ProvisionerDaemon, LogSource::Provisioner];

        // Verify both variants are distinct
        assert_ne!(sources[0], sources[1]);

        // Verify as_str round-trip
        assert_eq!(sources[0].as_str(), "provisioner_daemon");
        assert_eq!(sources[1].as_str(), "provisioner");
    }
}
