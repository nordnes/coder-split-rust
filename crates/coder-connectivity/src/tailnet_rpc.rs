//! Tailnet DRPC service — server-side RPC methods exposed over yamux.
//!
//! This module houses the Rust port of the Go `DRPCService` in
//! `coder/tailnet/service.go`. Each method corresponds to one RPC in the
//! `coder.tailnet.v2.Tailnet` service; methods are ported incrementally.
//!
//! The current slice ships only the initial-snapshot emission path for
//! `WorkspaceUpdates`. Reactive push-on-change is tracked as
//! `TODO-tailnet-workspace-updates-live` and will be added in a follow-up.

use std::sync::Arc;

use async_trait::async_trait;
use coder_agent_rpc::RpcError;
use coder_agent_rpc::proto::tailnet_v2;
use coder_core::{StorageError, WorkspaceListFilter, WorkspaceRecord};
use futures_util::{Stream, stream};
use uuid::Uuid;

/// Narrow workspace-lookup contract used by the tailnet service.
///
/// Kept separate from `coder_core::WorkspaceStore` so the tailnet RPC layer
/// depends only on the exact surface it needs — this simplifies test fakes
/// and keeps the DRPC wiring decoupled from the larger workspace domain
/// trait. Production wires this through a thin adapter over the real store.
#[async_trait]
pub trait TailnetWorkspaceLookup: Send + Sync + 'static {
    /// Lists workspaces matching the filter (same semantics as the store
    /// method of the same name).
    async fn list_workspaces(
        &self,
        filter: WorkspaceListFilter,
    ) -> Result<(Vec<WorkspaceRecord>, i64), StorageError>;
}

/// Tailnet DRPC service binding a workspace lookup for snapshot building.
///
/// Concrete RPC methods lean on [`TailnetWorkspaceLookup`] so unit tests can
/// supply a fake implementation without spinning up Postgres.
#[derive(Clone)]
pub struct TailnetRpcService {
    lookup: Arc<dyn TailnetWorkspaceLookup>,
}

impl TailnetRpcService {
    /// Builds a new service wrapping the given workspace lookup.
    pub fn new(lookup: Arc<dyn TailnetWorkspaceLookup>) -> Self {
        Self { lookup }
    }

    /// Server-stream handler for `coder.tailnet.v2.Tailnet/WorkspaceUpdates`.
    ///
    /// Emits a single initial snapshot frame containing the caller's owned
    /// workspaces. Live push-on-change is deferred — see
    /// `TODO-tailnet-workspace-updates-live`.
    pub async fn workspace_updates(
        &self,
        req: tailnet_v2::WorkspaceUpdatesRequest,
    ) -> Result<
        impl Stream<Item = Result<tailnet_v2::WorkspaceUpdate, RpcError>> + Send + 'static,
        RpcError,
    > {
        let owner_id = parse_owner_id(&req.workspace_owner_id)?;
        let snapshot = self.build_workspace_snapshot(owner_id).await?;
        // TODO-tailnet-workspace-updates-live: subscribe to workspace
        // pubsub channels (workspace build, agent lifecycle) and emit deltas
        // after this initial snapshot. Deferred to a follow-up PR.
        Ok(stream::once(async move { Ok(snapshot) }))
    }

    /// Builds the initial `WorkspaceUpdate` frame for a given owner.
    ///
    /// The Go reference returns *upserted* workspaces + agents on first
    /// emission; deleted sets remain empty. The MVP here emits the
    /// workspaces only — agent enumeration requires joining builds and
    /// resources and is deferred alongside the live path. Agent endpoints
    /// will be filled in under `TODO-tailnet-workspace-updates-live`.
    async fn build_workspace_snapshot(
        &self,
        owner_id: Uuid,
    ) -> Result<tailnet_v2::WorkspaceUpdate, RpcError> {
        let filter = WorkspaceListFilter {
            owner_id: Some(owner_id),
            viewer_id: Some(owner_id),
            limit: 0,
            offset: 0,
            ..Default::default()
        };
        let (rows, _) = self
            .lookup
            .list_workspaces(filter)
            .await
            .map_err(|err| RpcError::Internal(format!("list workspaces: {err}")))?;

        let upserted_workspaces = rows
            .into_iter()
            .map(|rec| tailnet_v2::Workspace {
                id: rec.id.as_bytes().to_vec(),
                name: rec.name,
                // Status is derived from the latest build transition in Go.
                // We default to Unknown until the live path lands — agent
                // enumeration and build-status join come together.
                status: tailnet_v2::workspace::Status::Unknown as i32,
            })
            .collect();

        Ok(tailnet_v2::WorkspaceUpdate {
            upserted_workspaces,
            upserted_agents: Vec::new(),
            deleted_workspaces: Vec::new(),
            deleted_agents: Vec::new(),
        })
    }
}

fn parse_owner_id(raw: &[u8]) -> Result<Uuid, RpcError> {
    Uuid::from_slice(raw)
        .map_err(|err| RpcError::InvalidArgument(format!("parse workspace owner id: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;
    use time::OffsetDateTime;

    #[derive(Clone, Default)]
    struct FakeLookup {
        workspaces: Vec<WorkspaceRecord>,
    }

    fn fake_workspace(owner_id: Uuid, name: &str) -> WorkspaceRecord {
        WorkspaceRecord {
            id: Uuid::new_v4(),
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            deleted: false,
            owner_id,
            organization_id: Uuid::new_v4(),
            template_id: Uuid::new_v4(),
            name: name.to_owned(),
            autostart_schedule: None,
            ttl_ns: None,
            last_used_at: OffsetDateTime::now_utc(),
            dormant_at: None,
            deleting_at: None,
            automatic_updates: "never".to_owned(),
            favorite: false,
            next_start_at: None,
        }
    }

    #[async_trait]
    impl TailnetWorkspaceLookup for FakeLookup {
        async fn list_workspaces(
            &self,
            filter: WorkspaceListFilter,
        ) -> Result<(Vec<WorkspaceRecord>, i64), StorageError> {
            let rows: Vec<WorkspaceRecord> = self
                .workspaces
                .iter()
                .filter(|w| filter.owner_id == Some(w.owner_id))
                .cloned()
                .collect();
            let count = i64::try_from(rows.len()).unwrap_or(0);
            Ok((rows, count))
        }
    }

    #[tokio::test]
    async fn workspace_updates_emits_initial_snapshot() {
        let owner = Uuid::new_v4();
        let lookup = FakeLookup {
            workspaces: vec![
                fake_workspace(owner, "alpha"),
                fake_workspace(owner, "beta"),
            ],
        };
        let svc = TailnetRpcService::new(Arc::new(lookup));
        let req = tailnet_v2::WorkspaceUpdatesRequest {
            workspace_owner_id: owner.as_bytes().to_vec(),
        };
        let stream = match svc.workspace_updates(req).await {
            Ok(s) => s,
            Err(err) => unreachable!("workspace_updates returns Ok: {err}"),
        };
        let frames: Vec<_> = stream.collect().await;
        assert_eq!(frames.len(), 1, "exactly one initial snapshot frame");
        let frame = match frames.into_iter().next() {
            Some(Ok(f)) => f,
            other => unreachable!("first frame must be Ok, got {other:?}"),
        };
        assert_eq!(frame.upserted_workspaces.len(), 2);
        let names: Vec<&str> = frame
            .upserted_workspaces
            .iter()
            .map(|w| w.name.as_str())
            .collect();
        assert!(names.contains(&"alpha"));
        assert!(names.contains(&"beta"));
    }
}
