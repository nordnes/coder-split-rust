//! Provisionerd DRPC service — infrastructure slice.
//!
//! Ports the minimal machinery needed to dispatch one DRPC RPC
//! (`CommitQuota`) over the wire framing already implemented in
//! [`coder_agent_rpc`]. Follow-up batches will extend
//! [`ProvisionerdDrpcService`] with the remaining RPCs declared in
//! `provisionerd/proto/provisionerd.proto`:
//!
//! * `AcquireJob` (deprecated) / `AcquireJobWithCancel`
//! * `UpdateJob`, `FailJob`, `CompleteJob`
//! * `UploadFile`, `DownloadFile`
//!
//! Until those land, [`ProvisionerdDrpcService::dispatch`] returns
//! [`RpcError::Unimplemented`] for any method path other than
//! `/provisionerd.ProvisionerDaemon/CommitQuota`, matching the DRPC
//! `Unimplemented` sentinel (code 12).

use std::sync::Arc;

use coder_agent_rpc::RpcError;
use coder_core::ProvisionerStore;
use prost::Message as _;
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
            other => Err(RpcError::Unimplemented(other.to_owned())),
        }
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
    /// and counts how many times `get_provisioner_job_by_id` was called.
    struct CountingStore {
        job: Option<ProvisionerJobRecord>,
        calls: AtomicUsize,
    }

    impl CountingStore {
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

        let err = match service
            .dispatch("/provisionerd.ProvisionerDaemon/AcquireJob", &[])
            .await
        {
            Err(err) => err,
            Ok(_) => unreachable!("unknown method must error"),
        };
        match err {
            RpcError::Unimplemented(m) => {
                assert!(m.contains("AcquireJob"));
            }
            other => unreachable!("expected Unimplemented, got {other:?}"),
        }
    }
}
