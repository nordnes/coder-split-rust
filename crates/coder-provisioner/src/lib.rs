//! Provisioner and job-orchestration helpers for the Rust `coderd` rewrite.
#![forbid(unsafe_code)]

use std::sync::Arc;

use base64::Engine as _;
use coder_core::{
    AcquireProvisionerJobInput, CancelProvisionerJobInput, CompleteProvisionerJobInput,
    GetJobsToBeReapedInput, InsertProvisionerJobInput, InsertProvisionerJobLogsInput,
    InsertProvisionerJobTimingsInput, InsertProvisionerKeyInput, ProvisionerDaemonRecord,
    ProvisionerJobLogRecord, ProvisionerJobRecord, ProvisionerJobTimingRecord,
    ProvisionerKeyRecord, ProvisionerStore, StorageError, UpsertProvisionerDaemonInput,
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
    use coder_core::{
        AcquireProvisionerJobInput, CancelProvisionerJobInput, CompleteProvisionerJobInput,
        GetJobsToBeReapedInput, InsertProvisionerJobInput, InsertProvisionerJobLogsInput,
        InsertProvisionerJobTimingsInput, InsertProvisionerKeyInput, ProvisionerDaemonRecord,
        ProvisionerJobLogRecord, ProvisionerJobRecord, ProvisionerJobTimingRecord,
        ProvisionerKeyRecord, ProvisionerStore, StorageError, UpsertProvisionerDaemonInput,
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
}
