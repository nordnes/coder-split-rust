//! `dbauthz`-style authorization wrapper (partial, W0.S3 slice).
//!
//! Mirrors Go's `coderd/database/dbauthz/dbauthz.go` newtype approach: a
//! wrapper that carries an [`Actor`] and an [`Authorizer`] alongside an
//! inner store, checking authorization *before* delegating each query.
//!
//! # Scope of this slice
//!
//! The Go `dbauthz.querier` implements hundreds of database methods. We
//! don't port the full 6,838-LOC file here. Instead, this slice wraps:
//!
//! List-side (W0.S3):
//! * `list_workspaces`  — via [`WorkspaceLister`]
//! * `list_templates`   — via [`TemplateLister`]
//! * `list_users`       — via [`UserLister`]
//! * `list_audit_logs`  — via [`AuditLogLister`]
//!
//! Workspace mutations (Round 4e):
//! * `insert_workspace`, `update_workspace_last_used_at`,
//!   `update_workspace_dormant_deleting_at`, `soft_delete_workspace`
//!   — via [`WorkspaceMutator`]
//! * `insert_workspace_build`, `update_workspace_build_deadline`
//!   — via [`WorkspaceBuildMutator`]
//!
//! Each lister trait is a narrow subset of the corresponding `coder-core`
//! super-trait, so real stores (e.g. `PostgresStore`) satisfy them via
//! the blanket `impl<T: WorkspaceStore + ?Sized> WorkspaceLister for T`
//! impls below. Test fakes only need to implement the narrow lister
//! trait, not the full 40+ method store trait.
//!
//! Each is surfaced on [`Authorized`] as a method that:
//! 1. runs `authorizer.authorize(actor, Action::Read, <resource>)`, and
//! 2. delegates to the inner store on Allow, returning
//!    [`DbAuthzError::Forbidden`] otherwise.
//!
//! Other methods must still be reached via [`Authorized::inner_unauthorized`]
//! for now — a documented bypass, NOT a silent passthrough.  Callers must
//! comment why the bypass is needed at each call-site. This matches Go's
//! `AsSystemRestricted`/similar patterns and will shrink as more methods
//! gain an authorized wrapper in follow-up work.
//!
//! # TODO-dbauthz
//!
//! * Wrap the remaining `AppStore` methods (per-resource authorize). This
//!   is ~600 methods; do it incrementally, per subsystem.
//! * Add a clippy lint (or xtask) that warns when handler code imports
//!   the raw `AppStore` trait directly instead of going through
//!   `Authorized`. Out of scope for W0.S3 — left as a follow-up.

use std::sync::Arc;

use async_trait::async_trait;
use coder_core::{
    AuditLogListFilter, AuditLogResponse, CreateWorkspaceBuildInput, CreateWorkspaceInput,
    IdentityStore, OperationalStore, StorageError, TemplateListFilter, TemplateRecord,
    TemplateStore, UserListFilter, UserRecord, WorkspaceBuildRecord, WorkspaceListFilter,
    WorkspaceRecord, WorkspaceStore,
};
use coder_rbac::{Action, Actor, Authorizer, Object, ResourceType};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

/// Error returned by [`Authorized`] methods.
#[derive(Debug, Error)]
pub enum DbAuthzError {
    /// Authorization denied the operation.
    #[error("forbidden: {0}")]
    Forbidden(String),
    /// The underlying storage call failed.
    #[error(transparent)]
    Storage(#[from] StorageError),
}

/// Narrow subset of [`WorkspaceStore`] exposing just the workspace-list
/// method. This keeps tests lightweight — fakes only need to implement
/// the narrow trait.
#[async_trait]
pub trait WorkspaceLister: Send + Sync {
    /// Lists workspaces matching the supplied filter.
    async fn list_workspaces(
        &self,
        filter: WorkspaceListFilter,
    ) -> Result<(Vec<WorkspaceRecord>, i64), StorageError>;
}

#[async_trait]
impl<T> WorkspaceLister for T
where
    T: WorkspaceStore + ?Sized,
{
    async fn list_workspaces(
        &self,
        filter: WorkspaceListFilter,
    ) -> Result<(Vec<WorkspaceRecord>, i64), StorageError> {
        WorkspaceStore::list_workspaces(self, filter).await
    }
}

/// Narrow subset of [`TemplateStore`] exposing just `list_templates`.
#[async_trait]
pub trait TemplateLister: Send + Sync {
    /// Lists templates matching the supplied filter.
    async fn list_templates(
        &self,
        filter: TemplateListFilter,
    ) -> Result<Vec<TemplateRecord>, StorageError>;
}

#[async_trait]
impl<T> TemplateLister for T
where
    T: TemplateStore + ?Sized,
{
    async fn list_templates(
        &self,
        filter: TemplateListFilter,
    ) -> Result<Vec<TemplateRecord>, StorageError> {
        TemplateStore::list_templates(self, filter).await
    }
}

/// Narrow subset of [`IdentityStore`] exposing just `list_users`.
#[async_trait]
pub trait UserLister: Send + Sync {
    /// Lists users matching the supplied filter.
    async fn list_users(
        &self,
        filter: UserListFilter,
    ) -> Result<(Vec<UserRecord>, usize), StorageError>;
}

#[async_trait]
impl<T> UserLister for T
where
    T: IdentityStore + ?Sized,
{
    async fn list_users(
        &self,
        filter: UserListFilter,
    ) -> Result<(Vec<UserRecord>, usize), StorageError> {
        IdentityStore::list_users(self, filter).await
    }
}

/// Narrow subset of [`OperationalStore`] exposing just `list_audit_logs`.
#[async_trait]
pub trait AuditLogLister: Send + Sync {
    /// Lists audit logs matching the supplied filter.
    async fn list_audit_logs(
        &self,
        filter: AuditLogListFilter,
    ) -> Result<AuditLogResponse, StorageError>;
}

#[async_trait]
impl<T> AuditLogLister for T
where
    T: OperationalStore + ?Sized,
{
    async fn list_audit_logs(
        &self,
        filter: AuditLogListFilter,
    ) -> Result<AuditLogResponse, StorageError> {
        OperationalStore::list_audit_logs(self, filter).await
    }
}

/// Narrow subset of [`WorkspaceStore`] exposing the write-side workspace
/// methods the Round 4e slice wraps. Keeping this trait small lets test
/// fakes implement just the mutators they need, without a full
/// [`WorkspaceStore`] impl.
#[async_trait]
pub trait WorkspaceMutator: Send + Sync {
    /// Inserts a new workspace row.
    async fn insert_workspace(
        &self,
        input: CreateWorkspaceInput,
    ) -> Result<WorkspaceRecord, StorageError>;

    /// Bumps `last_used_at` for the workspace (activity heartbeat path).
    async fn update_workspace_last_used_at(
        &self,
        workspace_id: Uuid,
        last_used_at: OffsetDateTime,
    ) -> Result<bool, StorageError>;

    /// Sets `dormant_at` (and derives `deleting_at`) for the workspace.
    async fn update_workspace_dormant_deleting_at(
        &self,
        workspace_id: Uuid,
        dormant_at: Option<OffsetDateTime>,
    ) -> Result<Option<WorkspaceRecord>, StorageError>;

    /// Soft-deletes the workspace.
    async fn soft_delete_workspace(&self, workspace_id: Uuid) -> Result<bool, StorageError>;
}

#[async_trait]
impl<T> WorkspaceMutator for T
where
    T: WorkspaceStore + ?Sized,
{
    async fn insert_workspace(
        &self,
        input: CreateWorkspaceInput,
    ) -> Result<WorkspaceRecord, StorageError> {
        WorkspaceStore::insert_workspace(self, input).await
    }

    async fn update_workspace_last_used_at(
        &self,
        workspace_id: Uuid,
        last_used_at: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        WorkspaceStore::update_workspace_last_used_at(self, workspace_id, last_used_at).await
    }

    async fn update_workspace_dormant_deleting_at(
        &self,
        workspace_id: Uuid,
        dormant_at: Option<OffsetDateTime>,
    ) -> Result<Option<WorkspaceRecord>, StorageError> {
        WorkspaceStore::update_workspace_dormant_deleting_at(self, workspace_id, dormant_at).await
    }

    async fn soft_delete_workspace(&self, workspace_id: Uuid) -> Result<bool, StorageError> {
        WorkspaceStore::soft_delete_workspace(self, workspace_id).await
    }
}

/// Narrow subset of [`WorkspaceStore`] exposing the write-side workspace
/// build methods this slice wraps.
#[async_trait]
pub trait WorkspaceBuildMutator: Send + Sync {
    /// Creates a new workspace build row.
    async fn insert_workspace_build(
        &self,
        input: CreateWorkspaceBuildInput,
    ) -> Result<WorkspaceBuildRecord, StorageError>;

    /// Updates the deadline / max-deadline on an in-flight build.
    async fn update_workspace_build_deadline(
        &self,
        build_id: Uuid,
        deadline: Option<OffsetDateTime>,
        max_deadline: Option<OffsetDateTime>,
    ) -> Result<bool, StorageError>;
}

#[async_trait]
impl<T> WorkspaceBuildMutator for T
where
    T: WorkspaceStore + ?Sized,
{
    async fn insert_workspace_build(
        &self,
        input: CreateWorkspaceBuildInput,
    ) -> Result<WorkspaceBuildRecord, StorageError> {
        WorkspaceStore::insert_workspace_build(self, input).await
    }

    async fn update_workspace_build_deadline(
        &self,
        build_id: Uuid,
        deadline: Option<OffsetDateTime>,
        max_deadline: Option<OffsetDateTime>,
    ) -> Result<bool, StorageError> {
        WorkspaceStore::update_workspace_build_deadline(self, build_id, deadline, max_deadline)
            .await
    }
}

/// A newtype wrapper that authorizes list operations before delegating to
/// the inner store. Mirrors Go's `dbauthz.querier` pattern. See the
/// module-level docs for the (partial) wrap surface.
///
/// `S` is the inner store type. The wrapper holds an `Arc<S>` to match
/// the production wiring, where the underlying store is shared across
/// subsystems.
#[derive(Debug)]
pub struct Authorized<S: ?Sized> {
    inner: Arc<S>,
    actor: Actor,
    authorizer: Authorizer,
}

impl<S: ?Sized> Authorized<S> {
    /// Creates a new authorized wrapper. The `actor` is threaded through
    /// every authorize check.
    #[must_use]
    pub fn new(inner: Arc<S>, actor: Actor) -> Self {
        Self {
            inner,
            actor,
            authorizer: Authorizer::new(),
        }
    }

    /// Returns the raw inner store, bypassing authorization checks.
    ///
    /// **Use sparingly**, and document at every call-site *why* the
    /// bypass is required (e.g. public endpoints that do their own
    /// access control, or system-level code running as an elevated
    /// actor that has already been authorized).
    #[must_use]
    pub fn inner_unauthorized(&self) -> &Arc<S> {
        &self.inner
    }

    /// Returns the actor this wrapper authorizes against.
    #[must_use]
    pub fn actor(&self) -> &Actor {
        &self.actor
    }

    /// Runs the authorize-then-delegate dance for `Action::Read` against a
    /// bare resource-type object (i.e. a "may this actor list this
    /// resource type at all?" check).
    fn authorize_read_resource(&self, rt: ResourceType) -> Result<(), DbAuthzError> {
        let object = Object::new(rt);
        self.authorizer
            .authorize(&self.actor, Action::Read, &object)
            .map_err(|e| DbAuthzError::Forbidden(e.message))
    }

    /// Runs an authorize check for an arbitrary action against a resource
    /// object, without delegating. Used by the mutator methods to express
    /// the usual "authorize then call the inner store" dance.
    fn authorize_action(&self, action: Action, object: &Object) -> Result<(), DbAuthzError> {
        self.authorizer
            .authorize(&self.actor, action, object)
            .map_err(|e| DbAuthzError::Forbidden(e.message))
    }
}

// ---------------------------------------------------------------------------
// The 4 list methods. Each method authorizes for `Action::Read` on the
// corresponding resource type, then invokes the inner store's matching
// trait method. For methods not in this list, callers must use
// `inner_unauthorized()` for now (see module docs / TODO-dbauthz).
// ---------------------------------------------------------------------------

impl<S> Authorized<S>
where
    S: WorkspaceLister + ?Sized,
{
    /// Authorized version of `WorkspaceStore::list_workspaces`. Mirrors
    /// the list surface of Go's `GetWorkspaces` in `dbauthz.go`.
    ///
    /// # Errors
    /// Returns [`DbAuthzError::Forbidden`] if the actor may not read
    /// workspaces, or propagates storage errors from the inner store.
    pub async fn list_workspaces(
        &self,
        filter: WorkspaceListFilter,
    ) -> Result<(Vec<WorkspaceRecord>, i64), DbAuthzError> {
        self.authorize_read_resource(ResourceType::Workspace)?;
        Ok(self.inner.list_workspaces(filter).await?)
    }
}

impl<S> Authorized<S>
where
    S: TemplateLister + ?Sized,
{
    /// Authorized version of `TemplateStore::list_templates`. Mirrors the
    /// list surface of Go's `GetTemplatesWithFilter` in `dbauthz.go`.
    ///
    /// # Errors
    /// Returns [`DbAuthzError::Forbidden`] if the actor may not read
    /// templates, or propagates storage errors from the inner store.
    pub async fn list_templates(
        &self,
        filter: TemplateListFilter,
    ) -> Result<Vec<TemplateRecord>, DbAuthzError> {
        self.authorize_read_resource(ResourceType::Template)?;
        Ok(self.inner.list_templates(filter).await?)
    }
}

impl<S> Authorized<S>
where
    S: UserLister + ?Sized,
{
    /// Authorized version of `IdentityStore::list_users`. Mirrors the
    /// list surface of Go's `GetUsers` in `dbauthz.go`.
    ///
    /// # Errors
    /// Returns [`DbAuthzError::Forbidden`] if the actor may not read
    /// users, or propagates storage errors from the inner store.
    pub async fn list_users(
        &self,
        filter: UserListFilter,
    ) -> Result<(Vec<UserRecord>, usize), DbAuthzError> {
        self.authorize_read_resource(ResourceType::User)?;
        Ok(self.inner.list_users(filter).await?)
    }
}

impl<S> Authorized<S>
where
    S: AuditLogLister + ?Sized,
{
    /// Authorized version of `OperationalStore::list_audit_logs`. Mirrors
    /// Go's `GetAuditLogsOffset` in `dbauthz.go`.
    ///
    /// # Errors
    /// Returns [`DbAuthzError::Forbidden`] if the actor may not read
    /// audit logs, or propagates storage errors from the inner store.
    pub async fn list_audit_logs(
        &self,
        filter: AuditLogListFilter,
    ) -> Result<AuditLogResponse, DbAuthzError> {
        self.authorize_read_resource(ResourceType::AuditLog)?;
        Ok(self.inner.list_audit_logs(filter).await?)
    }
}

// ---------------------------------------------------------------------------
// Workspace mutator wraps. Each authorizes the matching CRUD action against
// `ResourceType::Workspace` before delegating. For `insert_workspace` we
// include the org/owner coordinates from the input, matching Go's
// `dbauthz.InsertWorkspace` precheck; the id-only methods use a bare
// resource-type check since the caller does not pass org/owner through.
// ---------------------------------------------------------------------------

impl<S> Authorized<S>
where
    S: WorkspaceMutator + ?Sized,
{
    /// Authorized version of `WorkspaceStore::insert_workspace`. Mirrors
    /// Go's `InsertWorkspace` in `dbauthz.go`.
    ///
    /// # Errors
    /// Returns [`DbAuthzError::Forbidden`] if the actor may not create a
    /// workspace in this org for this owner, or propagates storage errors.
    pub async fn insert_workspace(
        &self,
        input: CreateWorkspaceInput,
    ) -> Result<WorkspaceRecord, DbAuthzError> {
        let object = Object::new(ResourceType::Workspace)
            .with_owner(input.owner_id)
            .in_org(input.organization_id);
        self.authorize_action(Action::Create, &object)?;
        Ok(self.inner.insert_workspace(input).await?)
    }

    /// Authorized version of `WorkspaceStore::update_workspace_last_used_at`.
    /// Used by the activity-bump / heartbeat path.
    ///
    /// # Errors
    /// Returns [`DbAuthzError::Forbidden`] if the actor may not update
    /// workspaces, or propagates storage errors from the inner store.
    pub async fn update_workspace_last_used_at(
        &self,
        workspace_id: Uuid,
        last_used_at: OffsetDateTime,
    ) -> Result<bool, DbAuthzError> {
        let object = Object::new(ResourceType::Workspace).with_id(workspace_id);
        self.authorize_action(Action::Update, &object)?;
        Ok(self
            .inner
            .update_workspace_last_used_at(workspace_id, last_used_at)
            .await?)
    }

    /// Authorized version of
    /// `WorkspaceStore::update_workspace_dormant_deleting_at`. Used by the
    /// dormancy scheduler.
    ///
    /// # Errors
    /// Returns [`DbAuthzError::Forbidden`] if the actor may not update
    /// workspaces, or propagates storage errors from the inner store.
    pub async fn update_workspace_dormant_deleting_at(
        &self,
        workspace_id: Uuid,
        dormant_at: Option<OffsetDateTime>,
    ) -> Result<Option<WorkspaceRecord>, DbAuthzError> {
        let object = Object::new(ResourceType::Workspace).with_id(workspace_id);
        self.authorize_action(Action::Update, &object)?;
        Ok(self
            .inner
            .update_workspace_dormant_deleting_at(workspace_id, dormant_at)
            .await?)
    }

    /// Authorized version of `WorkspaceStore::soft_delete_workspace`.
    /// Mirrors Go's `UpdateWorkspaceDeletedByID` dbauthz wrap.
    ///
    /// # Errors
    /// Returns [`DbAuthzError::Forbidden`] if the actor may not delete
    /// workspaces, or propagates storage errors from the inner store.
    pub async fn soft_delete_workspace(&self, workspace_id: Uuid) -> Result<bool, DbAuthzError> {
        let object = Object::new(ResourceType::Workspace).with_id(workspace_id);
        self.authorize_action(Action::Delete, &object)?;
        Ok(self.inner.soft_delete_workspace(workspace_id).await?)
    }
}

// ---------------------------------------------------------------------------
// Workspace build mutator wraps. `coder_rbac::ResourceType` has no distinct
// `WorkspaceBuild` variant; both the Go dbauthz layer and our RBAC model
// treat build create/update as an authorize check against the parent
// workspace resource type (`ResourceType::Workspace`).
// ---------------------------------------------------------------------------

impl<S> Authorized<S>
where
    S: WorkspaceBuildMutator + ?Sized,
{
    /// Authorized version of `WorkspaceStore::insert_workspace_build`.
    /// Mirrors Go's `InsertWorkspaceBuild` in `dbauthz.go`.
    ///
    /// # Errors
    /// Returns [`DbAuthzError::Forbidden`] if the actor may not create a
    /// workspace build, or propagates storage errors from the inner store.
    pub async fn insert_workspace_build(
        &self,
        input: CreateWorkspaceBuildInput,
    ) -> Result<WorkspaceBuildRecord, DbAuthzError> {
        let object = Object::new(ResourceType::Workspace).with_id(input.workspace_id);
        self.authorize_action(Action::Create, &object)?;
        Ok(self.inner.insert_workspace_build(input).await?)
    }

    /// Authorized version of `WorkspaceStore::update_workspace_build_deadline`.
    ///
    /// # Errors
    /// Returns [`DbAuthzError::Forbidden`] if the actor may not update
    /// workspace builds, or propagates storage errors from the inner store.
    pub async fn update_workspace_build_deadline(
        &self,
        build_id: Uuid,
        deadline: Option<OffsetDateTime>,
        max_deadline: Option<OffsetDateTime>,
    ) -> Result<bool, DbAuthzError> {
        let object = Object::new(ResourceType::Workspace);
        self.authorize_action(Action::Update, &object)?;
        Ok(self
            .inner
            .update_workspace_build_deadline(build_id, deadline, max_deadline)
            .await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal fake implementing only [`WorkspaceLister`]. This is the
    /// whole reason for the narrow `*Lister` traits above — a full
    /// [`WorkspaceStore`] impl would require ~40 unrelated methods.
    struct FakeWorkspaceLister;

    #[async_trait]
    impl WorkspaceLister for FakeWorkspaceLister {
        async fn list_workspaces(
            &self,
            _filter: WorkspaceListFilter,
        ) -> Result<(Vec<WorkspaceRecord>, i64), StorageError> {
            Ok((Vec::new(), 0))
        }
    }

    /// Actor with no site roles, no scope — the default restrictive
    /// actor used by the negative test.
    fn restricted_actor() -> Actor {
        Actor {
            user_id: Uuid::nil(),
            username: "nobody".to_owned(),
            organization_ids: Vec::new(),
            site_roles: Vec::new(),
            org_roles: Vec::new(),
            groups: Vec::new(),
            scope: None,
            scope_override: None,
        }
    }

    /// Owner actor — wildcard on every resource/action.
    fn owner_actor() -> Actor {
        Actor {
            user_id: Uuid::nil(),
            username: "admin".to_owned(),
            organization_ids: Vec::new(),
            site_roles: vec![coder_rbac::ROLE_OWNER.to_owned()],
            org_roles: Vec::new(),
            groups: Vec::new(),
            scope: None,
            scope_override: None,
        }
    }

    #[tokio::test]
    async fn list_workspaces_denied_without_permission() {
        let store = Arc::new(FakeWorkspaceLister);
        let authz = Authorized::new(store, restricted_actor());
        let result = authz.list_workspaces(WorkspaceListFilter::default()).await;
        assert!(
            matches!(result, Err(DbAuthzError::Forbidden(_))),
            "expected Forbidden, got: {result:?}",
        );
    }

    #[tokio::test]
    async fn list_workspaces_allowed_for_owner() {
        let store = Arc::new(FakeWorkspaceLister);
        let authz = Authorized::new(store, owner_actor());
        let result = authz.list_workspaces(WorkspaceListFilter::default()).await;
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
    }

    // -----------------------------------------------------------------------
    // WorkspaceMutator / WorkspaceBuildMutator wrap tests (Round 4e).
    // -----------------------------------------------------------------------

    /// Fake that records the last mutator call and returns canned success
    /// results. Lets us assert the authorize-then-delegate ordering.
    #[derive(Default)]
    struct FakeWorkspaceMutator;

    fn sample_workspace_record() -> WorkspaceRecord {
        WorkspaceRecord {
            id: Uuid::nil(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
            deleted: false,
            owner_id: Uuid::nil(),
            organization_id: Uuid::nil(),
            template_id: Uuid::nil(),
            name: "ws".to_owned(),
            autostart_schedule: None,
            ttl_ns: None,
            last_used_at: OffsetDateTime::UNIX_EPOCH,
            dormant_at: None,
            deleting_at: None,
            automatic_updates: "never".to_owned(),
            favorite: false,
            next_start_at: None,
        }
    }

    fn sample_build_record() -> WorkspaceBuildRecord {
        WorkspaceBuildRecord {
            id: Uuid::nil(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
            workspace_id: Uuid::nil(),
            build_number: 1,
            transition: "start".to_owned(),
            job_id: Uuid::nil(),
            template_version_id: Uuid::nil(),
            initiator_id: Uuid::nil(),
            provisioner_state: None,
            deadline: None,
            max_deadline: None,
            reason: "initiator".to_owned(),
            daily_cost: 0,
        }
    }

    fn sample_create_input() -> CreateWorkspaceInput {
        CreateWorkspaceInput {
            id: Uuid::nil(),
            owner_id: Uuid::nil(),
            organization_id: Uuid::nil(),
            template_id: Uuid::nil(),
            name: "ws".to_owned(),
            autostart_schedule: None,
            ttl_ns: None,
            automatic_updates: "never".to_owned(),
        }
    }

    fn sample_build_input() -> CreateWorkspaceBuildInput {
        CreateWorkspaceBuildInput {
            id: Uuid::nil(),
            workspace_id: Uuid::nil(),
            template_version_id: Uuid::nil(),
            build_number: 1,
            transition: "start".to_owned(),
            initiator_id: Uuid::nil(),
            job_id: Uuid::nil(),
            reason: "initiator".to_owned(),
            deadline: None,
            max_deadline: None,
        }
    }

    #[async_trait]
    impl WorkspaceMutator for FakeWorkspaceMutator {
        async fn insert_workspace(
            &self,
            _input: CreateWorkspaceInput,
        ) -> Result<WorkspaceRecord, StorageError> {
            Ok(sample_workspace_record())
        }

        async fn update_workspace_last_used_at(
            &self,
            _workspace_id: Uuid,
            _last_used_at: OffsetDateTime,
        ) -> Result<bool, StorageError> {
            Ok(true)
        }

        async fn update_workspace_dormant_deleting_at(
            &self,
            _workspace_id: Uuid,
            _dormant_at: Option<OffsetDateTime>,
        ) -> Result<Option<WorkspaceRecord>, StorageError> {
            Ok(Some(sample_workspace_record()))
        }

        async fn soft_delete_workspace(&self, _workspace_id: Uuid) -> Result<bool, StorageError> {
            Ok(true)
        }
    }

    #[derive(Default)]
    struct FakeWorkspaceBuildMutator;

    #[async_trait]
    impl WorkspaceBuildMutator for FakeWorkspaceBuildMutator {
        async fn insert_workspace_build(
            &self,
            _input: CreateWorkspaceBuildInput,
        ) -> Result<WorkspaceBuildRecord, StorageError> {
            Ok(sample_build_record())
        }

        async fn update_workspace_build_deadline(
            &self,
            _build_id: Uuid,
            _deadline: Option<OffsetDateTime>,
            _max_deadline: Option<OffsetDateTime>,
        ) -> Result<bool, StorageError> {
            Ok(true)
        }
    }

    #[tokio::test]
    async fn insert_workspace_authorizes_then_delegates() {
        let store = Arc::new(FakeWorkspaceMutator);
        let denied = Authorized::new(Arc::clone(&store), restricted_actor())
            .insert_workspace(sample_create_input())
            .await;
        assert!(
            matches!(denied, Err(DbAuthzError::Forbidden(_))),
            "expected Forbidden, got: {denied:?}",
        );

        let allowed = Authorized::new(store, owner_actor())
            .insert_workspace(sample_create_input())
            .await;
        assert!(allowed.is_ok(), "expected Ok, got: {allowed:?}");
    }

    #[tokio::test]
    async fn update_workspace_last_used_at_authorizes_then_delegates() {
        let store = Arc::new(FakeWorkspaceMutator);
        let denied = Authorized::new(Arc::clone(&store), restricted_actor())
            .update_workspace_last_used_at(Uuid::nil(), OffsetDateTime::UNIX_EPOCH)
            .await;
        assert!(
            matches!(denied, Err(DbAuthzError::Forbidden(_))),
            "expected Forbidden, got: {denied:?}",
        );

        let allowed = Authorized::new(store, owner_actor())
            .update_workspace_last_used_at(Uuid::nil(), OffsetDateTime::UNIX_EPOCH)
            .await;
        assert!(allowed.is_ok(), "expected Ok, got: {allowed:?}");
    }

    #[tokio::test]
    async fn update_workspace_dormant_deleting_at_authorizes_then_delegates() {
        let store = Arc::new(FakeWorkspaceMutator);
        let denied = Authorized::new(Arc::clone(&store), restricted_actor())
            .update_workspace_dormant_deleting_at(Uuid::nil(), None)
            .await;
        assert!(
            matches!(denied, Err(DbAuthzError::Forbidden(_))),
            "expected Forbidden, got: {denied:?}",
        );

        let allowed = Authorized::new(store, owner_actor())
            .update_workspace_dormant_deleting_at(Uuid::nil(), None)
            .await;
        assert!(allowed.is_ok(), "expected Ok, got: {allowed:?}");
    }

    #[tokio::test]
    async fn soft_delete_workspace_authorizes_then_delegates() {
        let store = Arc::new(FakeWorkspaceMutator);
        let denied = Authorized::new(Arc::clone(&store), restricted_actor())
            .soft_delete_workspace(Uuid::nil())
            .await;
        assert!(
            matches!(denied, Err(DbAuthzError::Forbidden(_))),
            "expected Forbidden, got: {denied:?}",
        );

        let allowed = Authorized::new(store, owner_actor())
            .soft_delete_workspace(Uuid::nil())
            .await;
        assert!(allowed.is_ok(), "expected Ok, got: {allowed:?}");
    }

    #[tokio::test]
    async fn insert_workspace_build_authorizes_then_delegates() {
        let store = Arc::new(FakeWorkspaceBuildMutator);
        let denied = Authorized::new(Arc::clone(&store), restricted_actor())
            .insert_workspace_build(sample_build_input())
            .await;
        assert!(
            matches!(denied, Err(DbAuthzError::Forbidden(_))),
            "expected Forbidden, got: {denied:?}",
        );

        let allowed = Authorized::new(store, owner_actor())
            .insert_workspace_build(sample_build_input())
            .await;
        assert!(allowed.is_ok(), "expected Ok, got: {allowed:?}");
    }

    #[tokio::test]
    async fn update_workspace_build_deadline_authorizes_then_delegates() {
        let store = Arc::new(FakeWorkspaceBuildMutator);
        let denied = Authorized::new(Arc::clone(&store), restricted_actor())
            .update_workspace_build_deadline(Uuid::nil(), None, None)
            .await;
        assert!(
            matches!(denied, Err(DbAuthzError::Forbidden(_))),
            "expected Forbidden, got: {denied:?}",
        );

        let allowed = Authorized::new(store, owner_actor())
            .update_workspace_build_deadline(Uuid::nil(), None, None)
            .await;
        assert!(allowed.is_ok(), "expected Ok, got: {allowed:?}");
    }
}
