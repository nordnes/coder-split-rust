//! Provisionerd DRPC service — infrastructure slice.
//!
//! Ports the minimal machinery needed to dispatch provisionerd DRPC RPCs
//! (currently `CommitQuota`, `AcquireJob`, `UpdateJob`, `FailJob`, and
//! `CompleteJob`) over the wire framing already implemented in
//! [`coder_agent_rpc`]. Follow-up batches will extend
//! [`ProvisionerdDrpcService`] with the remaining RPCs declared in
//! `provisionerd/proto/provisionerd.proto`:
//!
//! * `AcquireJobWithCancel` (bidi-streaming cousin of `AcquireJob`)
//! * `UploadFile`, `DownloadFile`
//!
//! Until those land, [`ProvisionerdDrpcService::dispatch`] returns
//! [`RpcError::Unimplemented`] for any method path other than the ones
//! ported here, matching the DRPC `Unimplemented` sentinel (code 12).

use std::sync::Arc;

use coder_agent_rpc::RpcError;
use coder_core::provisioner::{LogLevel, LogSource};
use coder_core::{
    AcquireProvisionerJobInput, CompleteProvisionerJobInput, InsertProvisionerJobLogsInput,
    ProvisionerStore, ProvisionerType,
};
use prost::Message as _;
use time::OffsetDateTime;
use tracing::instrument;
use uuid::Uuid;

use crate::proto::provisionerd as pd;

/// DRPC method path for the `CommitQuota` RPC.
///
/// Kept as a `pub const` so handlers, tests, and the HTTP hook that
/// registers the service on `/organizations/{org}/provisionerdaemons/
/// drpc-serve` can all reference the same string and stay in sync with
/// the upstream `.proto` declaration.
pub const COMMIT_QUOTA_METHOD: &str = "/provisionerd.ProvisionerDaemon/CommitQuota";

/// DRPC method path for the (deprecated) `AcquireJob` RPC.
///
/// Upstream Go clients still use this RPC for back-compatibility; the
/// streaming `AcquireJobWithCancel` flavour will arrive in a separate
/// batch once the DRPC stream plumbing is in place.
pub const ACQUIRE_JOB_METHOD: &str = "/provisionerd.ProvisionerDaemon/AcquireJob";

/// DRPC method path for the `UpdateJob` RPC.
pub const UPDATE_JOB_METHOD: &str = "/provisionerd.ProvisionerDaemon/UpdateJob";

/// DRPC method path for the `FailJob` RPC.
pub const FAIL_JOB_METHOD: &str = "/provisionerd.ProvisionerDaemon/FailJob";

/// DRPC method path for the `CompleteJob` RPC.
pub const COMPLETE_JOB_METHOD: &str = "/provisionerd.ProvisionerDaemon/CompleteJob";

/// DRPC service wrapping a [`ProvisionerStore`] to serve provisionerd RPCs.
///
/// Clonable and cheap to share across per-stream dispatch tasks. Only
/// depends on the [`ProvisionerStore`] sub-trait of `AppStore`; this
/// keeps the service independently testable with the existing
/// `ProvisionerStore` mocks rather than requiring a full `AppStore`
/// stand-in.
#[derive(Clone)]
pub struct ProvisionerdDrpcService {
    store: Arc<dyn ProvisionerStore>,
}

impl ProvisionerdDrpcService {
    /// Constructs a new service backed by `store`.
    pub fn new(store: Arc<dyn ProvisionerStore>) -> Self {
        Self { store }
    }

    /// Serves the `CommitQuota` RPC.
    ///
    /// Mirrors the Go OSS behaviour in
    /// `coderd/provisionerdserver/provisionerdserver.go::CommitQuota`:
    ///
    /// 1. Parse the job id from the request.
    /// 2. Look up the provisioner job; reject if missing or not yet
    ///    running (no `worker_id`).
    /// 3. Since the Rust port does not yet plug in the enterprise
    ///    `QuotaCommitter`, fall through to the community-edition
    ///    branch and return `{ok: true, budget: -1, credits_consumed: 0}`.
    ///    Wiring the enterprise committer (which calls
    ///    `GetWorkspaceBuildByJobID`, `UpdateWorkspaceBuildCostByID`,
    ///    and the quota-allowance SQL) is tracked as a follow-up.
    #[instrument(skip(self), err)]
    pub async fn commit_quota(
        &self,
        req: pd::CommitQuotaRequest,
    ) -> Result<pd::CommitQuotaResponse, RpcError> {
        let job_id = Uuid::parse_str(&req.job_id)
            .map_err(|e| RpcError::InvalidArgument(format!("parse job id: {e}")))?;

        let job = self
            .store
            .get_provisioner_job_by_id(job_id)
            .await
            .map_err(|e| RpcError::Internal(format!("get job: {e}")))?
            .ok_or_else(|| RpcError::InvalidArgument(format!("job {job_id} not found")))?;

        // Upstream requires the job to have been acquired (worker_id
        // populated) and the caller to own it; we enforce only the
        // "job is running" check here. Full worker-ownership
        // authentication will arrive with the acquire/update flow.
        if job.worker_id.is_none() {
            return Err(RpcError::InvalidArgument(
                "job isn't running yet".to_owned(),
            ));
        }

        // Community-edition fallback: no quota committer is wired, so
        // report unlimited budget and allow the build.
        Ok(pd::CommitQuotaResponse {
            ok: true,
            credits_consumed: 0,
            budget: -1,
        })
    }

    /// Serves the (deprecated) unary `AcquireJob` RPC.
    ///
    /// Mirrors the Go OSS behaviour in
    /// `coderd/provisionerdserver/provisionerdserver.go::AcquireJob`:
    /// block briefly on the acquirer until a pending job matching the
    /// daemon's capabilities is lockable, then return the acquired job.
    /// If no job is available, return an empty [`pd::AcquiredJob`] —
    /// upstream Go daemons interpret that as "poll again".
    ///
    /// This port keeps the minimum viable slice: it invokes the existing
    /// [`ProvisionerStore::acquire_provisioner_job`] with an empty tag
    /// set and echoes the raw job-row fields back on the wire. The
    /// richer payload (WorkspaceBuild / TemplateImport / TemplateDryRun
    /// oneof, template source archive, rich parameter resolution,
    /// external-auth providers, etc.) is tracked as
    /// `TODO-provisionerd-acquirejob-full-payload` and will land once
    /// the per-job-type expansion is ported. Until then, daemons
    /// receiving the empty envelope will re-poll, which is safe — the
    /// row stays locked by the database's `FOR UPDATE SKIP LOCKED`
    /// semantics and the daemon will retry with the same worker id.
    #[instrument(skip(self, _req), err)]
    pub async fn acquire_job(&self, _req: pd::Empty) -> Result<pd::AcquiredJob, RpcError> {
        // In the Go port these come from the authenticated daemon
        // handle; the DRPC transport wiring still needs to thread those
        // through. For this first slice we ask the store for any job
        // matching an empty tagset — the Postgres `tags <@ $5::JSONB`
        // check requires job tags ⊆ daemon tags, so empty-on-both-sides
        // only matches untagged jobs. Richer tag propagation is
        // tracked with the same TODO marker as the full payload.
        let input = AcquireProvisionerJobInput {
            worker_id: Uuid::nil(),
            started_at: OffsetDateTime::now_utc(),
            organization_id: Uuid::nil(),
            types: vec![ProvisionerType::Terraform, ProvisionerType::Echo],
            provisioner_tags: serde_json::json!({}),
        };

        let job_opt = self
            .store
            .acquire_provisioner_job(input)
            .await
            .map_err(|e| RpcError::Internal(format!("acquire job: {e}")))?;

        let Some(job) = job_opt else {
            // No eligible job — upstream contract is to return an
            // empty AcquiredJob so the daemon re-polls.
            return Ok(pd::AcquiredJob::default());
        };

        // Minimal payload. `TODO-provisionerd-acquirejob-full-payload`:
        // populate the `oneof type` (WorkspaceBuild/TemplateImport/
        // TemplateDryRun), `template_source_archive`, and initiator
        // user metadata.
        Ok(pd::AcquiredJob {
            job_id: job.id.to_string(),
            created_at: job.created_at.unix_timestamp(),
            provisioner: job.provisioner.as_str().to_owned(),
            user_name: String::new(),
            trace_metadata: std::collections::HashMap::new(),
        })
    }

    /// Serves the `UpdateJob` RPC.
    ///
    /// Mirrors the Go OSS behaviour in
    /// `coderd/provisionerdserver/provisionerdserver.go::UpdateJob`,
    /// reduced to the store methods already exposed by
    /// [`ProvisionerStore`]:
    ///
    /// 1. Parse the job id and look up the job.
    /// 2. Reject if the job has not been acquired (`worker_id` unset).
    ///    Full worker-ownership authentication (matching `WorkerID ==
    ///    s.ID` in Go) will arrive with the acquire flow that plumbs
    ///    the daemon identity into the service.
    /// 3. Bump `updated_at` so the stale-job reaper treats this job as
    ///    live.
    /// 4. If the request carries logs, batch-insert them via
    ///    `insert_provisioner_job_logs`. The upstream 1 MB size cap and
    ///    `logs_overflowed` flag are not enforced yet — this port only
    ///    persists what the daemon sends.
    /// 5. Return the job's cancellation state. Template variables,
    ///    workspace tags, and README persistence require additional
    ///    `ProvisionerStore` methods (`GetTemplateVersionByJobID`,
    ///    `InsertTemplateVersionVariable`, etc.) not yet ported; they
    ///    are tracked as §B.6 follow-ups.
    #[instrument(skip(self, req), err)]
    pub async fn update_job(
        &self,
        req: pd::UpdateJobRequest,
    ) -> Result<pd::UpdateJobResponse, RpcError> {
        let job_id = Uuid::parse_str(&req.job_id)
            .map_err(|e| RpcError::InvalidArgument(format!("parse job id: {e}")))?;

        let job = self
            .store
            .get_provisioner_job_by_id(job_id)
            .await
            .map_err(|e| RpcError::Internal(format!("get job: {e}")))?
            .ok_or_else(|| RpcError::InvalidArgument(format!("job {job_id} not found")))?;

        if job.worker_id.is_none() {
            return Err(RpcError::InvalidArgument(
                "job isn't running yet".to_owned(),
            ));
        }

        // Heartbeat: bump updated_at so the reaper considers the job live.
        let now = OffsetDateTime::now_utc();
        self.store
            .update_provisioner_job_by_id(job_id, now)
            .await
            .map_err(|e| RpcError::Internal(format!("update job: {e}")))?;

        // Batch-insert logs, if any. Upstream's 1 MB overflow guard is a
        // follow-up; this port just persists the wire-received batch.
        if !req.logs.is_empty() {
            let mut input = InsertProvisionerJobLogsInput {
                job_id,
                created_at: Vec::with_capacity(req.logs.len()),
                source: Vec::with_capacity(req.logs.len()),
                level: Vec::with_capacity(req.logs.len()),
                stage: Vec::with_capacity(req.logs.len()),
                output: Vec::with_capacity(req.logs.len()),
            };
            for log in req.logs {
                input.created_at.push(log_created_at(log.created_at)?);
                input.source.push(convert_log_source(log.source));
                input.level.push(convert_log_level(log.level));
                input.stage.push(log.stage);
                input.output.push(log.output);
            }
            self.store
                .insert_provisioner_job_logs(input)
                .await
                .map_err(|e| RpcError::Internal(format!("insert logs: {e}")))?;
        }

        Ok(pd::UpdateJobResponse {
            canceled: job.canceled_at.is_some(),
            variable_values: Vec::new(),
        })
    }

    /// Serves the `FailJob` RPC.
    ///
    /// Mirrors the Go OSS behaviour in
    /// `coderd/provisionerdserver/provisionerdserver.go::FailJob`,
    /// reduced to the store methods already exposed by
    /// [`ProvisionerStore`]:
    ///
    /// 1. Parse the job id and look up the job.
    /// 2. Reject if the job has not been acquired (`worker_id` unset).
    ///    Full worker-ownership authentication (matching `WorkerID ==
    ///    s.ID` in Go) will arrive with the acquire flow that plumbs
    ///    the daemon identity into the service.
    /// 3. Reject if the job is already completed — the daemon must not
    ///    fail a job that has already been marked `CompletedAt`.
    /// 4. Mark the job completed with the supplied `error` /
    ///    `error_code` via `update_provisioner_job_with_complete_by_id`,
    ///    the same store hook Go uses for both `FailJob` and
    ///    `CompleteJob`.
    /// 5. Return an empty [`pd::Empty`] — the upstream RPC signature
    ///    is `FailJob(FailedJob) returns (Empty)`.
    ///
    /// Per-type follow-ups (WorkspaceBuild state / deadline reset,
    /// telemetry report, audit log, workspace-event pubsub, end-of-logs
    /// pubsub, notification enqueue) require additional store/pubsub
    /// surfaces that are tracked as §B.6 follow-ups and land with the
    /// remaining DRPC RPCs (`CompleteJob`, `UploadFile`, `DownloadFile`,
    /// `AcquireJobWithCancel`).
    #[instrument(skip(self, req), err)]
    pub async fn fail_job(&self, req: pd::FailedJob) -> Result<pd::Empty, RpcError> {
        let job_id = Uuid::parse_str(&req.job_id)
            .map_err(|e| RpcError::InvalidArgument(format!("parse job id: {e}")))?;

        let job = self
            .store
            .get_provisioner_job_by_id(job_id)
            .await
            .map_err(|e| RpcError::Internal(format!("get job: {e}")))?
            .ok_or_else(|| RpcError::InvalidArgument(format!("job {job_id} not found")))?;

        if job.worker_id.is_none() {
            return Err(RpcError::InvalidArgument(
                "job isn't running yet".to_owned(),
            ));
        }
        if job.completed_at.is_some() {
            return Err(RpcError::InvalidArgument(
                "job already completed".to_owned(),
            ));
        }

        let now = OffsetDateTime::now_utc();
        self.store
            .update_provisioner_job_with_complete_by_id(CompleteProvisionerJobInput {
                id: job_id,
                updated_at: now,
                completed_at: now,
                error: req.error,
                error_code: req.error_code,
            })
            .await
            .map_err(|e| RpcError::Internal(format!("complete job: {e}")))?;

        Ok(pd::Empty::default())
    }

    /// Serves the `CompleteJob` RPC.
    ///
    /// Mirrors the Go OSS behaviour in
    /// `coderd/provisionerdserver/provisionerdserver.go::CompleteJob`,
    /// reduced to the store methods already exposed by
    /// [`ProvisionerStore`]:
    ///
    /// 1. Parse the job id and look up the job.
    /// 2. Reject if the job has not been acquired (`worker_id` unset).
    ///    Full worker-ownership authentication (matching `WorkerID ==
    ///    s.ID` in Go) will arrive with the acquire flow that plumbs
    ///    the daemon identity into the service.
    /// 3. Reject if the job is already completed — the daemon must not
    ///    complete a job that has already been marked `CompletedAt`.
    /// 4. Mark the job completed (no `error` / `error_code`, matching
    ///    a successful completion) via
    ///    `update_provisioner_job_with_complete_by_id` — the same
    ///    store hook Go uses for both `FailJob` and `CompleteJob`.
    /// 5. Return an empty [`pd::Empty`] — the upstream RPC signature
    ///    is `CompleteJob(CompletedJob) returns (Empty)`.
    ///
    /// Per-type follow-ups mirror the matching `FailJob` list and
    /// require additional store/pubsub surfaces that are tracked as
    /// §B.6 follow-ups: WorkspaceBuild resource / module / timing /
    /// resource-replacement / AI-task insertion, TemplateImport rich
    /// parameters / external-auth / presets / module-files /
    /// has-ai-tasks / has-external-agents persistence, TemplateDryRun
    /// resource / module insertion, telemetry report, audit log,
    /// workspace-event pubsub, end-of-logs pubsub, and notification
    /// enqueue. They land with the remaining DRPC RPCs
    /// (`UploadFile`, `DownloadFile`, `AcquireJobWithCancel`).
    #[instrument(skip(self, req), err)]
    pub async fn complete_job(&self, req: pd::CompletedJob) -> Result<pd::Empty, RpcError> {
        let job_id = Uuid::parse_str(&req.job_id)
            .map_err(|e| RpcError::InvalidArgument(format!("parse job id: {e}")))?;

        let job = self
            .store
            .get_provisioner_job_by_id(job_id)
            .await
            .map_err(|e| RpcError::Internal(format!("get job: {e}")))?
            .ok_or_else(|| RpcError::InvalidArgument(format!("job {job_id} not found")))?;

        if job.worker_id.is_none() {
            return Err(RpcError::InvalidArgument(
                "job isn't running yet".to_owned(),
            ));
        }
        if job.completed_at.is_some() {
            return Err(RpcError::InvalidArgument(
                "job already completed".to_owned(),
            ));
        }

        let now = OffsetDateTime::now_utc();
        self.store
            .update_provisioner_job_with_complete_by_id(CompleteProvisionerJobInput {
                id: job_id,
                updated_at: now,
                completed_at: now,
                error: String::new(),
                error_code: String::new(),
            })
            .await
            .map_err(|e| RpcError::Internal(format!("complete job: {e}")))?;

        Ok(pd::Empty::default())
    }

    /// Routes an incoming DRPC method + encoded request body to the
    /// appropriate handler, returning the encoded response.
    ///
    /// Unknown methods return [`RpcError::Unimplemented`] so the DRPC
    /// transport can map them onto the Go-client-recognised
    /// `drpcerr.Unimplemented` (code 12).
    pub async fn dispatch(&self, method: &str, body: &[u8]) -> Result<Vec<u8>, RpcError> {
        match method {
            COMMIT_QUOTA_METHOD => {
                let req = pd::CommitQuotaRequest::decode(body)
                    .map_err(|e| RpcError::InvalidArgument(format!("decode: {e}")))?;
                let resp = self.commit_quota(req).await?;
                let mut buf = Vec::with_capacity(resp.encoded_len());
                resp.encode(&mut buf)
                    .map_err(|e| RpcError::Internal(format!("encode: {e}")))?;
                Ok(buf)
            }
            ACQUIRE_JOB_METHOD => {
                let req = pd::Empty::decode(body)
                    .map_err(|e| RpcError::InvalidArgument(format!("decode: {e}")))?;
                let resp = self.acquire_job(req).await?;
                let mut buf = Vec::with_capacity(resp.encoded_len());
                resp.encode(&mut buf)
                    .map_err(|e| RpcError::Internal(format!("encode: {e}")))?;
                Ok(buf)
            }
            UPDATE_JOB_METHOD => {
                let req = pd::UpdateJobRequest::decode(body)
                    .map_err(|e| RpcError::InvalidArgument(format!("decode: {e}")))?;
                let resp = self.update_job(req).await?;
                let mut buf = Vec::with_capacity(resp.encoded_len());
                resp.encode(&mut buf)
                    .map_err(|e| RpcError::Internal(format!("encode: {e}")))?;
                Ok(buf)
            }
            FAIL_JOB_METHOD => {
                let req = pd::FailedJob::decode(body)
                    .map_err(|e| RpcError::InvalidArgument(format!("decode: {e}")))?;
                let resp = self.fail_job(req).await?;
                let mut buf = Vec::with_capacity(resp.encoded_len());
                resp.encode(&mut buf)
                    .map_err(|e| RpcError::Internal(format!("encode: {e}")))?;
                Ok(buf)
            }
            COMPLETE_JOB_METHOD => {
                let req = pd::CompletedJob::decode(body)
                    .map_err(|e| RpcError::InvalidArgument(format!("decode: {e}")))?;
                let resp = self.complete_job(req).await?;
                let mut buf = Vec::with_capacity(resp.encoded_len());
                resp.encode(&mut buf)
                    .map_err(|e| RpcError::Internal(format!("encode: {e}")))?;
                Ok(buf)
            }
            other => Err(RpcError::Unimplemented(other.to_owned())),
        }
    }
}

/// Converts the wire-level millisecond timestamp into an
/// [`OffsetDateTime`], rejecting values that do not fit in the
/// supported range.
fn log_created_at(millis: i64) -> Result<OffsetDateTime, RpcError> {
    // The Go proto uses `int64` millis-since-epoch. `time::OffsetDateTime`
    // supports the full nanosecond range, so converting from millis is
    // safe as long as the multiplication does not overflow.
    let nanos = i128::from(millis).saturating_mul(1_000_000);
    OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .map_err(|e| RpcError::InvalidArgument(format!("log created_at: {e}")))
}

/// Maps the protobuf `LogSource` enum onto the domain enum.
///
/// Unknown values fall back to `ProvisionerDaemon` to match the Go
/// server's default when the wire value is 0 (the proto3 default).
fn convert_log_source(source: i32) -> LogSource {
    match pd::LogSource::try_from(source) {
        Ok(pd::LogSource::Provisioner) => LogSource::Provisioner,
        _ => LogSource::ProvisionerDaemon,
    }
}

/// Maps the protobuf `LogLevel` enum onto the domain enum.
///
/// Unknown values fall back to `Info` to match Go's `convertLogLevel`
/// behaviour when the daemon sends a value the server doesn't
/// recognise.
fn convert_log_level(level: i32) -> LogLevel {
    match pd::LogLevel::try_from(level) {
        Ok(pd::LogLevel::Trace) => LogLevel::Trace,
        Ok(pd::LogLevel::Debug) => LogLevel::Debug,
        Ok(pd::LogLevel::Info) => LogLevel::Info,
        Ok(pd::LogLevel::Warn) => LogLevel::Warn,
        Ok(pd::LogLevel::Error) => LogLevel::Error,
        Err(_) => LogLevel::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use coder_core::provisioner::{ProvisionerJobLogRecord, ProvisionerJobTimingRecord};
    use coder_core::{
        AcquireProvisionerJobInput, CancelProvisionerJobInput, CompleteProvisionerJobInput,
        GetJobsToBeReapedInput, InsertProvisionerJobInput, InsertProvisionerJobLogsInput,
        InsertProvisionerJobTimingsInput, InsertProvisionerKeyInput, ProvisionerDaemonRecord,
        ProvisionerJobRecord, ProvisionerKeyRecord, ProvisionerStore, StorageError,
        UpsertProvisionerDaemonInput,
    };
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use time::OffsetDateTime;

    /// Minimal `ProvisionerStore` that returns a single preconfigured job
    /// and counts how many times `get_provisioner_job_by_id`,
    /// `update_provisioner_job_by_id`, `insert_provisioner_job_logs`,
    /// and `update_provisioner_job_with_complete_by_id` were called —
    /// the store hooks touched by `CommitQuota`, `UpdateJob`, `FailJob`,
    /// and `CompleteJob`.
    struct CountingStore {
        job: Option<ProvisionerJobRecord>,
        calls: AtomicUsize,
        log_inserts: AtomicUsize,
        heartbeats: AtomicUsize,
        completions: AtomicUsize,
    }

    impl CountingStore {
        fn new(job: Option<ProvisionerJobRecord>) -> Self {
            Self {
                job,
                calls: AtomicUsize::new(0),
                log_inserts: AtomicUsize::new(0),
                heartbeats: AtomicUsize::new(0),
                completions: AtomicUsize::new(0),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }

        fn log_insert_count(&self) -> usize {
            self.log_inserts.load(Ordering::SeqCst)
        }

        fn heartbeat_count(&self) -> usize {
            self.heartbeats.load(Ordering::SeqCst)
        }

        fn completion_count(&self) -> usize {
            self.completions.load(Ordering::SeqCst)
        }
    }

    fn running_job() -> ProvisionerJobRecord {
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
            provisioner: ProvisionerType::Terraform,
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

    #[async_trait]
    impl ProvisionerStore for CountingStore {
        async fn acquire_provisioner_job(
            &self,
            _input: AcquireProvisionerJobInput,
        ) -> Result<Option<ProvisionerJobRecord>, StorageError> {
            Ok(None)
        }

        async fn get_provisioner_job_by_id(
            &self,
            _id: Uuid,
        ) -> Result<Option<ProvisionerJobRecord>, StorageError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.job.clone())
        }

        async fn get_provisioner_jobs_by_ids(
            &self,
            _ids: &[Uuid],
        ) -> Result<Vec<ProvisionerJobRecord>, StorageError> {
            Ok(Vec::new())
        }

        async fn insert_provisioner_job(
            &self,
            _input: InsertProvisionerJobInput,
        ) -> Result<ProvisionerJobRecord, StorageError> {
            Err(StorageError::unavailable("not implemented"))
        }

        async fn update_provisioner_job_by_id(
            &self,
            _id: Uuid,
            _updated_at: OffsetDateTime,
        ) -> Result<(), StorageError> {
            self.heartbeats.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn update_provisioner_job_with_complete_by_id(
            &self,
            _input: CompleteProvisionerJobInput,
        ) -> Result<(), StorageError> {
            self.completions.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn update_provisioner_job_with_cancel_by_id(
            &self,
            _input: CancelProvisionerJobInput,
        ) -> Result<(), StorageError> {
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
            _input: InsertProvisionerJobLogsInput,
        ) -> Result<Vec<ProvisionerJobLogRecord>, StorageError> {
            self.log_inserts.fetch_add(1, Ordering::SeqCst);
            Ok(Vec::new())
        }

        async fn get_provisioner_logs_after_id(
            &self,
            _job_id: Uuid,
            _after_id: i64,
        ) -> Result<Vec<ProvisionerJobLogRecord>, StorageError> {
            Ok(Vec::new())
        }

        async fn insert_provisioner_job_timings(
            &self,
            _input: InsertProvisionerJobTimingsInput,
        ) -> Result<Vec<ProvisionerJobTimingRecord>, StorageError> {
            Ok(Vec::new())
        }

        async fn get_provisioner_job_timings_by_job_id(
            &self,
            _job_id: Uuid,
        ) -> Result<Vec<ProvisionerJobTimingRecord>, StorageError> {
            Ok(Vec::new())
        }

        async fn upsert_provisioner_daemon(
            &self,
            _input: UpsertProvisionerDaemonInput,
        ) -> Result<ProvisionerDaemonRecord, StorageError> {
            Err(StorageError::unavailable("not implemented"))
        }

        async fn update_provisioner_daemon_last_seen_at(
            &self,
            _id: Uuid,
            _last_seen_at: OffsetDateTime,
        ) -> Result<(), StorageError> {
            Ok(())
        }

        async fn get_provisioner_daemons_by_organization(
            &self,
            _organization_id: Uuid,
        ) -> Result<Vec<ProvisionerDaemonRecord>, StorageError> {
            Ok(Vec::new())
        }

        async fn delete_old_provisioner_daemons(&self) -> Result<(), StorageError> {
            Ok(())
        }

        async fn insert_provisioner_key(
            &self,
            _input: InsertProvisionerKeyInput,
        ) -> Result<ProvisionerKeyRecord, StorageError> {
            Err(StorageError::unavailable("not implemented"))
        }

        async fn get_provisioner_key_by_id(
            &self,
            _id: Uuid,
        ) -> Result<Option<ProvisionerKeyRecord>, StorageError> {
            Ok(None)
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

    /// Unary round-trip test: the dispatcher decodes a protobuf-encoded
    /// request, invokes `commit_quota` (which queries the store), and
    /// returns a properly-encoded response reflecting the community-edition
    /// fallback branch.
    #[tokio::test]
    async fn drpc_service_commit_quota_round_trip() {
        // Build a store that knows about one running job. The handler's
        // `dispatch` path must decode the wire bytes, call into the store
        // (asserted via the atomic counter), and re-encode the response
        // for the wire.
        let job = running_job();
        let job_id = job.id;
        let counting = Arc::new(CountingStore::new(Some(job)));
        let store: Arc<dyn ProvisionerStore> = counting.clone();
        let service = ProvisionerdDrpcService::new(store);

        // Encode a CommitQuotaRequest on the wire as a real client would.
        let req = pd::CommitQuotaRequest {
            job_id: job_id.to_string(),
            daily_cost: 100,
        };
        let body = req.encode_to_vec();

        // Dispatch through the method-router.
        let bytes = match service.dispatch(COMMIT_QUOTA_METHOD, &body).await {
            Ok(bytes) => bytes,
            Err(err) => unreachable!("dispatch failed: {err}"),
        };

        // Decode the response and verify the community-edition fallback
        // values: unlimited budget, zero consumed, ok=true.
        let resp = match pd::CommitQuotaResponse::decode(&bytes[..]) {
            Ok(resp) => resp,
            Err(err) => unreachable!("response decode failed: {err}"),
        };
        assert!(resp.ok, "community-edition fallback must approve");
        assert_eq!(resp.budget, -1, "community-edition budget is unlimited");
        assert_eq!(resp.credits_consumed, 0);

        // The store must have been consulted exactly once for the job
        // lookup — this is the integration assertion the task requires.
        assert_eq!(
            counting.call_count(),
            1,
            "commit_quota must call get_provisioner_job_by_id"
        );
    }

    /// Unknown methods must surface as DRPC `Unimplemented` so Go clients
    /// can transparently recognise missing RPCs via `drpcerr.Unimplemented`.
    #[tokio::test]
    async fn drpc_service_unknown_method_unimplemented() {
        let counting = Arc::new(CountingStore::new(None));
        let store: Arc<dyn ProvisionerStore> = counting;
        let service = ProvisionerdDrpcService::new(store);

        // `UploadFile` is intentionally a not-yet-ported method path
        // (it is blocked on DRPC client-streaming landing first); it
        // stands in for any unrecognised DRPC method and must bubble
        // up as `Unimplemented` (code 12) so Go clients can `drpcerr.Is`
        // the sentinel and back off.
        let err = match service
            .dispatch("/provisionerd.ProvisionerDaemon/UploadFile", &[])
            .await
        {
            Err(err) => err,
            Ok(_) => unreachable!("unknown method must error"),
        };
        match err {
            RpcError::Unimplemented(m) => {
                assert!(m.contains("UploadFile"));
            }
            other => unreachable!("expected Unimplemented, got {other:?}"),
        }
    }

    /// Unary round-trip test for `UpdateJob`: encode the request, dispatch
    /// through the method-router, decode the response, and assert the
    /// heartbeat + logs store paths were invoked exactly once.
    #[tokio::test]
    async fn drpc_service_update_job_round_trip() {
        let job = running_job();
        let job_id = job.id;
        let counting = Arc::new(CountingStore::new(Some(job)));
        let store: Arc<dyn ProvisionerStore> = counting.clone();
        let service = ProvisionerdDrpcService::new(store);

        let req = pd::UpdateJobRequest {
            job_id: job_id.to_string(),
            logs: vec![pd::Log {
                source: pd::LogSource::Provisioner as i32,
                level: pd::LogLevel::Info as i32,
                created_at: 1_700_000_000_000,
                stage: "apply".to_owned(),
                output: "hello".to_owned(),
            }],
            ..Default::default()
        };
        let bytes = match service
            .dispatch(UPDATE_JOB_METHOD, &req.encode_to_vec())
            .await
        {
            Ok(b) => b,
            Err(err) => unreachable!("dispatch failed: {err}"),
        };
        let resp = match pd::UpdateJobResponse::decode(&bytes[..]) {
            Ok(r) => r,
            Err(err) => unreachable!("response decode failed: {err}"),
        };

        assert!(!resp.canceled, "running job is not canceled");
        assert!(resp.variable_values.is_empty());
        assert_eq!(counting.heartbeat_count(), 1, "updated_at heartbeat bumped");
        assert_eq!(counting.log_insert_count(), 1, "log batch inserted once");
    }

    /// Unary round-trip test for `FailJob`: encode a `FailedJob` with
    /// error + error_code, dispatch through the method-router, decode
    /// the `Empty` response, and assert the completion store hook was
    /// invoked exactly once — matching Go's
    /// `update_provisioner_job_with_complete_by_id` call in
    /// `provisionerdserver.go::FailJob`.
    #[tokio::test]
    async fn drpc_service_fail_job_round_trip() {
        let job = running_job();
        let job_id = job.id;
        let counting = Arc::new(CountingStore::new(Some(job)));
        let store: Arc<dyn ProvisionerStore> = counting.clone();
        let service = ProvisionerdDrpcService::new(store);

        let req = pd::FailedJob {
            job_id: job_id.to_string(),
            error: "terraform apply failed".to_owned(),
            error_code: "APPLY_ERROR".to_owned(),
            r#type: None,
        };
        let bytes = match service
            .dispatch(FAIL_JOB_METHOD, &req.encode_to_vec())
            .await
        {
            Ok(b) => b,
            Err(err) => unreachable!("dispatch failed: {err}"),
        };
        // FailJob returns Empty; decoding must succeed on an empty body.
        match pd::Empty::decode(&bytes[..]) {
            Ok(_) => {}
            Err(err) => unreachable!("response decode failed: {err}"),
        }

        // The completion store hook must fire exactly once — the core
        // behaviour asserted by this test.
        assert_eq!(
            counting.completion_count(),
            1,
            "fail_job must call update_provisioner_job_with_complete_by_id exactly once"
        );
        // And the job-lookup path was consulted exactly once; the
        // heartbeat / logs paths that UpdateJob touches must NOT fire.
        assert_eq!(counting.call_count(), 1, "job lookup hit exactly once");
        assert_eq!(counting.heartbeat_count(), 0, "FailJob does not heartbeat");
        assert_eq!(
            counting.log_insert_count(),
            0,
            "FailJob does not insert logs"
        );
    }

    /// Unary round-trip test for `CompleteJob`: encode a `CompletedJob`
    /// with no per-type payload (the first-slice port does not yet
    /// decode the WorkspaceBuild / TemplateImport / TemplateDryRun
    /// oneof), dispatch through the method-router, decode the `Empty`
    /// response, and assert the completion store hook was invoked
    /// exactly once — matching Go's
    /// `update_provisioner_job_with_complete_by_id` call in
    /// `provisionerdserver.go::CompleteJob`.
    #[tokio::test]
    async fn drpc_service_complete_job_round_trip() {
        let job = running_job();
        let job_id = job.id;
        let counting = Arc::new(CountingStore::new(Some(job)));
        let store: Arc<dyn ProvisionerStore> = counting.clone();
        let service = ProvisionerdDrpcService::new(store);

        let req = pd::CompletedJob {
            job_id: job_id.to_string(),
            r#type: None,
        };
        let bytes = match service
            .dispatch(COMPLETE_JOB_METHOD, &req.encode_to_vec())
            .await
        {
            Ok(b) => b,
            Err(err) => unreachable!("dispatch failed: {err}"),
        };
        // CompleteJob returns Empty; decoding must succeed on an
        // empty body.
        match pd::Empty::decode(&bytes[..]) {
            Ok(_) => {}
            Err(err) => unreachable!("response decode failed: {err}"),
        }

        // The completion store hook must fire exactly once — the core
        // behaviour asserted by this test.
        assert_eq!(
            counting.completion_count(),
            1,
            "complete_job must call update_provisioner_job_with_complete_by_id exactly once"
        );
        // And the job-lookup path was consulted exactly once; the
        // heartbeat / logs paths that UpdateJob touches must NOT fire.
        assert_eq!(counting.call_count(), 1, "job lookup hit exactly once");
        assert_eq!(
            counting.heartbeat_count(),
            0,
            "CompleteJob does not heartbeat"
        );
        assert_eq!(
            counting.log_insert_count(),
            0,
            "CompleteJob does not insert logs"
        );
    }

    /// AcquireJob counting store: records how many times
    /// `acquire_provisioner_job` was invoked and returns a preconfigured
    /// optional job. Separate from [`CountingStore`] so the two RPCs
    /// can be asserted independently without coupling their mocks.
    struct AcquireCountingStore {
        job: Option<ProvisionerJobRecord>,
        calls: AtomicUsize,
    }

    impl AcquireCountingStore {
        fn new(job: Option<ProvisionerJobRecord>) -> Self {
            Self {
                job,
                calls: AtomicUsize::new(0),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl ProvisionerStore for AcquireCountingStore {
        async fn acquire_provisioner_job(
            &self,
            _input: AcquireProvisionerJobInput,
        ) -> Result<Option<ProvisionerJobRecord>, StorageError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.job.clone())
        }

        async fn get_provisioner_job_by_id(
            &self,
            _id: Uuid,
        ) -> Result<Option<ProvisionerJobRecord>, StorageError> {
            Ok(None)
        }

        async fn get_provisioner_jobs_by_ids(
            &self,
            _ids: &[Uuid],
        ) -> Result<Vec<ProvisionerJobRecord>, StorageError> {
            Ok(Vec::new())
        }

        async fn insert_provisioner_job(
            &self,
            _input: InsertProvisionerJobInput,
        ) -> Result<ProvisionerJobRecord, StorageError> {
            Err(StorageError::unavailable("not implemented"))
        }

        async fn update_provisioner_job_by_id(
            &self,
            _id: Uuid,
            _updated_at: OffsetDateTime,
        ) -> Result<(), StorageError> {
            Ok(())
        }

        async fn update_provisioner_job_with_complete_by_id(
            &self,
            _input: CompleteProvisionerJobInput,
        ) -> Result<(), StorageError> {
            Ok(())
        }

        async fn update_provisioner_job_with_cancel_by_id(
            &self,
            _input: CancelProvisionerJobInput,
        ) -> Result<(), StorageError> {
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
            _input: InsertProvisionerJobLogsInput,
        ) -> Result<Vec<ProvisionerJobLogRecord>, StorageError> {
            Ok(Vec::new())
        }

        async fn get_provisioner_logs_after_id(
            &self,
            _job_id: Uuid,
            _after_id: i64,
        ) -> Result<Vec<ProvisionerJobLogRecord>, StorageError> {
            Ok(Vec::new())
        }

        async fn insert_provisioner_job_timings(
            &self,
            _input: InsertProvisionerJobTimingsInput,
        ) -> Result<Vec<ProvisionerJobTimingRecord>, StorageError> {
            Ok(Vec::new())
        }

        async fn get_provisioner_job_timings_by_job_id(
            &self,
            _job_id: Uuid,
        ) -> Result<Vec<ProvisionerJobTimingRecord>, StorageError> {
            Ok(Vec::new())
        }

        async fn upsert_provisioner_daemon(
            &self,
            _input: UpsertProvisionerDaemonInput,
        ) -> Result<ProvisionerDaemonRecord, StorageError> {
            Err(StorageError::unavailable("not implemented"))
        }

        async fn update_provisioner_daemon_last_seen_at(
            &self,
            _id: Uuid,
            _last_seen_at: OffsetDateTime,
        ) -> Result<(), StorageError> {
            Ok(())
        }

        async fn get_provisioner_daemons_by_organization(
            &self,
            _organization_id: Uuid,
        ) -> Result<Vec<ProvisionerDaemonRecord>, StorageError> {
            Ok(Vec::new())
        }

        async fn delete_old_provisioner_daemons(&self) -> Result<(), StorageError> {
            Ok(())
        }

        async fn insert_provisioner_key(
            &self,
            _input: InsertProvisionerKeyInput,
        ) -> Result<ProvisionerKeyRecord, StorageError> {
            Err(StorageError::unavailable("not implemented"))
        }

        async fn get_provisioner_key_by_id(
            &self,
            _id: Uuid,
        ) -> Result<Option<ProvisionerKeyRecord>, StorageError> {
            Ok(None)
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

    /// Unary round-trip test for the `AcquireJob` RPC: the dispatcher
    /// decodes a protobuf-encoded `Empty`, invokes `acquire_job` (which
    /// calls the store exactly once), and returns a wire-encoded
    /// `AcquiredJob` carrying the queued job's id.
    #[tokio::test]
    async fn drpc_service_acquire_job_round_trip() {
        let job = running_job();
        let job_id = job.id;
        let counting = Arc::new(AcquireCountingStore::new(Some(job)));
        let store: Arc<dyn ProvisionerStore> = counting.clone();
        let service = ProvisionerdDrpcService::new(store);

        let body = pd::Empty::default().encode_to_vec();
        let bytes = match service.dispatch(ACQUIRE_JOB_METHOD, &body).await {
            Ok(bytes) => bytes,
            Err(err) => unreachable!("dispatch failed: {err}"),
        };
        let resp = match pd::AcquiredJob::decode(&bytes[..]) {
            Ok(resp) => resp,
            Err(err) => unreachable!("decode failed: {err}"),
        };

        assert_eq!(resp.job_id, job_id.to_string());
        assert_eq!(resp.provisioner, "terraform");
        assert_eq!(
            counting.call_count(),
            1,
            "acquire_job must call acquire_provisioner_job exactly once"
        );
    }
}
