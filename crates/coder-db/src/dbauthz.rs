//! `dbauthz`-style authorization wrapper (partial, W0.S3 slice).
//!
//! Mirrors Go's `coderd/database/dbauthz/dbauthz.go` newtype approach: a
//! wrapper that carries an [`Actor`] and an [`Authorizer`] alongside an
//! inner store, checking authorization *before* delegating each query.
//!
//! # Scope of this slice
//!
//! The Go `dbauthz.querier` implements hundreds of database methods. We
//! don't port the full 6,838-LOC file here. Instead, this slice wraps
//! only the list-style methods the task spec calls out as "most abused":
//!
//! * `list_workspaces`  — via [`WorkspaceLister`]
//! * `list_templates`   — via [`TemplateLister`]
//! * `list_users`       — via [`UserLister`]
//! * `list_audit_logs`  — via [`AuditLogLister`]
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
    AuditLogListFilter, AuditLogResponse, IdentityStore, OperationalStore, StorageError,
    TemplateListFilter, TemplateRecord, TemplateStore, UserListFilter, UserRecord,
    WorkspaceListFilter, WorkspaceRecord, WorkspaceStore,
};
use coder_rbac::{Action, Actor, Authorizer, Object, ResourceType};
use thiserror::Error;

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

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

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
        // Owner role grants wildcard access including Workspace:Read.
        let actor = Actor {
            user_id: Uuid::nil(),
            username: "admin".to_owned(),
            organization_ids: Vec::new(),
            site_roles: vec![coder_rbac::ROLE_OWNER.to_owned()],
            org_roles: Vec::new(),
            groups: Vec::new(),
            scope: None,
            scope_override: None,
        };
        let authz = Authorized::new(store, actor);
        let result = authz.list_workspaces(WorkspaceListFilter::default()).await;
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
    }
}
