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
//! Template mutations (Round 4f):
//! * `insert_template`, `update_template_meta`,
//!   `update_template_active_version`, `soft_delete_template`,
//!   `update_template_acl`, `insert_template_version`
//!   — via [`TemplateMutator`]
//!
//! User mutations (Wave 3):
//! * `create_user`, `update_user_profile`, `update_user_status`,
//!   `update_user_roles`, `soft_delete_user` — via [`UserMutator`]
//! * `replace_user_password` — via [`UserPasswordMutator`] (lives on
//!   [`AuthStore`] in `coder-core`, not [`IdentityStore`])
//!
//! API key mutations (Wave 0 S3 tail):
//! * `create_api_key`, `update_api_key_last_used`, `delete_api_key`
//!   — via [`ApiKeyMutator`] (lives on [`AuthStore`] in `coder-core`)
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
    ApiKeyRecord, AuditLogListFilter, AuditLogResponse, AuthStore, CreateApiKeyInput,
    CreateApiKeyStoreError, CreateTemplateInput, CreateTemplateStoreError,
    CreateTemplateVersionInput, CreateUserInput, CreateUserStoreError, CreateWorkspaceBuildInput,
    CreateWorkspaceInput, IdentityStore, OperationalStore, StorageError, TemplateListFilter,
    TemplateRecord, TemplateStore, TemplateVersionRecord, UpdateTemplateACLInput,
    UpdateTemplateMetaInput, UserListFilter, UserRecord, UserStatus, WorkspaceBuildRecord,
    WorkspaceListFilter, WorkspaceRecord, WorkspaceStore,
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
    /// Template creation failed for a non-storage reason (e.g. duplicate
    /// name). Maps from `CreateTemplateStoreError`'s domain-specific
    /// variants; the `Storage` variant flattens into [`Self::Storage`].
    #[error(transparent)]
    TemplateCreate(CreateTemplateStoreError),
    /// User creation failed for a non-storage reason (e.g. duplicate
    /// email/username). Maps from `CreateUserStoreError`'s domain-specific
    /// variants; the `Storage` variant flattens into [`Self::Storage`].
    #[error(transparent)]
    UserCreate(CreateUserStoreError),
    /// API key creation failed for a non-storage reason. Maps from
    /// `CreateApiKeyStoreError`'s domain-specific variants; the
    /// `Storage` variant flattens into [`Self::Storage`].
    #[error(transparent)]
    ApiKeyCreate(CreateApiKeyStoreError),
}

impl From<CreateTemplateStoreError> for DbAuthzError {
    fn from(err: CreateTemplateStoreError) -> Self {
        match err {
            CreateTemplateStoreError::Storage(e) => Self::Storage(e),
            other => Self::TemplateCreate(other),
        }
    }
}

impl From<CreateUserStoreError> for DbAuthzError {
    fn from(err: CreateUserStoreError) -> Self {
        match err {
            CreateUserStoreError::Storage(e) => Self::Storage(e),
            other => Self::UserCreate(other),
        }
    }
}

impl From<CreateApiKeyStoreError> for DbAuthzError {
    fn from(err: CreateApiKeyStoreError) -> Self {
        match err {
            CreateApiKeyStoreError::Storage(e) => Self::Storage(e),
            other => Self::ApiKeyCreate(other),
        }
    }
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

/// Narrow subset of [`TemplateStore`] exposing the write-side template
/// methods the Round 4f slice wraps. Keeping this trait small lets test
/// fakes implement just the mutators they need, without a full
/// [`TemplateStore`] impl.
#[async_trait]
pub trait TemplateMutator: Send + Sync {
    /// Inserts a new template row.
    async fn insert_template(
        &self,
        input: CreateTemplateInput,
    ) -> Result<TemplateRecord, CreateTemplateStoreError>;

    /// Updates template metadata fields.
    async fn update_template_meta(
        &self,
        input: UpdateTemplateMetaInput,
    ) -> Result<Option<TemplateRecord>, StorageError>;

    /// Updates the active template version pointer on a template.
    async fn update_template_active_version(
        &self,
        template_id: Uuid,
        active_version_id: Uuid,
    ) -> Result<bool, StorageError>;

    /// Soft-deletes a template.
    async fn soft_delete_template(&self, template_id: Uuid) -> Result<bool, StorageError>;

    /// Replaces the ACL entries (user_acl and group_acl) on a template.
    async fn update_template_acl(
        &self,
        template_id: Uuid,
        input: &UpdateTemplateACLInput,
    ) -> Result<(), StorageError>;

    /// Inserts a new template version row.
    async fn insert_template_version(
        &self,
        input: CreateTemplateVersionInput,
    ) -> Result<TemplateVersionRecord, StorageError>;
}

#[async_trait]
impl<T> TemplateMutator for T
where
    T: TemplateStore + ?Sized,
{
    async fn insert_template(
        &self,
        input: CreateTemplateInput,
    ) -> Result<TemplateRecord, CreateTemplateStoreError> {
        TemplateStore::insert_template(self, input).await
    }

    async fn update_template_meta(
        &self,
        input: UpdateTemplateMetaInput,
    ) -> Result<Option<TemplateRecord>, StorageError> {
        TemplateStore::update_template_meta(self, input).await
    }

    async fn update_template_active_version(
        &self,
        template_id: Uuid,
        active_version_id: Uuid,
    ) -> Result<bool, StorageError> {
        TemplateStore::update_template_active_version(self, template_id, active_version_id).await
    }

    async fn soft_delete_template(&self, template_id: Uuid) -> Result<bool, StorageError> {
        TemplateStore::soft_delete_template(self, template_id).await
    }

    async fn update_template_acl(
        &self,
        template_id: Uuid,
        input: &UpdateTemplateACLInput,
    ) -> Result<(), StorageError> {
        TemplateStore::update_template_acl(self, template_id, input).await
    }

    async fn insert_template_version(
        &self,
        input: CreateTemplateVersionInput,
    ) -> Result<TemplateVersionRecord, StorageError> {
        TemplateStore::insert_template_version(self, input).await
    }
}

/// Narrow subset of [`IdentityStore`] exposing the write-side user
/// methods the Wave 3 slice wraps. Keeping this trait small lets test
/// fakes implement just the mutators they need, without a full
/// [`IdentityStore`] impl.
#[async_trait]
pub trait UserMutator: Send + Sync {
    /// Inserts a new user row (and initial org memberships).
    async fn create_user(&self, input: CreateUserInput)
    -> Result<UserRecord, CreateUserStoreError>;

    /// Updates a user's basic profile fields (username, name).
    async fn update_user_profile(
        &self,
        user_id: Uuid,
        username: &str,
        name: &str,
    ) -> Result<Option<UserRecord>, StorageError>;

    /// Updates a user's status (active, suspended, dormant).
    async fn update_user_status(
        &self,
        user_id: Uuid,
        status: UserStatus,
    ) -> Result<Option<UserRecord>, StorageError>;

    /// Replaces the site-wide roles for a user.
    async fn update_user_roles(
        &self,
        user_id: Uuid,
        roles: Vec<String>,
    ) -> Result<Option<UserRecord>, StorageError>;

    /// Soft-deletes the user (revokes sessions + API keys).
    async fn soft_delete_user(&self, user_id: Uuid) -> Result<bool, StorageError>;
}

#[async_trait]
impl<T> UserMutator for T
where
    T: IdentityStore + ?Sized,
{
    async fn create_user(
        &self,
        input: CreateUserInput,
    ) -> Result<UserRecord, CreateUserStoreError> {
        IdentityStore::create_user(self, input).await
    }

    async fn update_user_profile(
        &self,
        user_id: Uuid,
        username: &str,
        name: &str,
    ) -> Result<Option<UserRecord>, StorageError> {
        IdentityStore::update_user_profile(self, user_id, username, name).await
    }

    async fn update_user_status(
        &self,
        user_id: Uuid,
        status: UserStatus,
    ) -> Result<Option<UserRecord>, StorageError> {
        IdentityStore::update_user_status(self, user_id, status).await
    }

    async fn update_user_roles(
        &self,
        user_id: Uuid,
        roles: Vec<String>,
    ) -> Result<Option<UserRecord>, StorageError> {
        IdentityStore::update_user_roles(self, user_id, roles).await
    }

    async fn soft_delete_user(&self, user_id: Uuid) -> Result<bool, StorageError> {
        IdentityStore::soft_delete_user(self, user_id).await
    }
}

/// Narrow subset of [`AuthStore`] exposing just the password-replacement
/// call. Password replacement is modelled on `AuthStore` in `coder-core`
/// (it revokes sessions + API keys), but conceptually it is a user
/// mutation, so the wrap still authorizes against `ResourceType::User`.
#[async_trait]
pub trait UserPasswordMutator: Send + Sync {
    /// Replaces a user's password hash and revokes active sessions/keys.
    async fn replace_user_password(
        &self,
        user_id: Uuid,
        password_hash: &str,
        clear_one_time_passcode: bool,
    ) -> Result<bool, StorageError>;
}

#[async_trait]
impl<T> UserPasswordMutator for T
where
    T: AuthStore + ?Sized,
{
    async fn replace_user_password(
        &self,
        user_id: Uuid,
        password_hash: &str,
        clear_one_time_passcode: bool,
    ) -> Result<bool, StorageError> {
        AuthStore::replace_user_password(self, user_id, password_hash, clear_one_time_passcode)
            .await
    }
}

/// Narrow subset of [`AuthStore`] exposing the write-side API key
/// methods the W0.S3 tail slice wraps. Keeping this trait small lets
/// test fakes implement just the mutators they need, without a full
/// [`AuthStore`] impl.
#[async_trait]
pub trait ApiKeyMutator: Send + Sync {
    /// Inserts a new API key row.
    async fn create_api_key(
        &self,
        input: CreateApiKeyInput,
    ) -> Result<ApiKeyRecord, CreateApiKeyStoreError>;

    /// Updates an API key's `last_used` and `expires_at` timestamps.
    /// Mirrors Go's `UpdateAPIKeyByID` in `dbauthz.go`.
    async fn update_api_key_last_used(
        &self,
        id: &str,
        last_used: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<(), StorageError>;

    /// Deletes an API key by stable identifier.
    async fn delete_api_key(&self, id: &str) -> Result<bool, StorageError>;
}

#[async_trait]
impl<T> ApiKeyMutator for T
where
    T: AuthStore + ?Sized,
{
    async fn create_api_key(
        &self,
        input: CreateApiKeyInput,
    ) -> Result<ApiKeyRecord, CreateApiKeyStoreError> {
        AuthStore::create_api_key(self, input).await
    }

    async fn update_api_key_last_used(
        &self,
        id: &str,
        last_used: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        AuthStore::update_api_key_last_used(self, id, last_used, expires_at).await
    }

    async fn delete_api_key(&self, id: &str) -> Result<bool, StorageError> {
        AuthStore::delete_api_key(self, id).await
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

// ---------------------------------------------------------------------------
// Template mutator wraps. Each authorizes the matching CRUD action against
// `ResourceType::Template` before delegating. For `insert_template` /
// `insert_template_version` we include the `organization_id` coordinate
// from the input to match Go's `dbauthz.InsertTemplate` / `InsertTemplateVersion`
// preflight (`ResourceTemplate.InOrg(arg.OrganizationID)`). The id-only
// methods pin `with_id` on a bare resource-type object.
// ---------------------------------------------------------------------------

impl<S> Authorized<S>
where
    S: TemplateMutator + ?Sized,
{
    /// Authorized version of `TemplateStore::insert_template`. Mirrors
    /// Go's `InsertTemplate` in `dbauthz.go`
    /// (`ActionCreate` on `ResourceTemplate.InOrg(arg.OrganizationID)`).
    ///
    /// # Errors
    /// Returns [`DbAuthzError::Forbidden`] if the actor may not create a
    /// template in this org, or propagates storage / domain errors from
    /// the inner store.
    pub async fn insert_template(
        &self,
        input: CreateTemplateInput,
    ) -> Result<TemplateRecord, DbAuthzError> {
        let object = Object::new(ResourceType::Template).in_org(input.organization_id);
        self.authorize_action(Action::Create, &object)?;
        Ok(self.inner.insert_template(input).await?)
    }

    /// Authorized version of `TemplateStore::update_template_meta`.
    /// Mirrors Go's `UpdateTemplateMetaByID` in `dbauthz.go`.
    ///
    /// # Errors
    /// Returns [`DbAuthzError::Forbidden`] if the actor may not update
    /// templates, or propagates storage errors from the inner store.
    pub async fn update_template_meta(
        &self,
        input: UpdateTemplateMetaInput,
    ) -> Result<Option<TemplateRecord>, DbAuthzError> {
        let object = Object::new(ResourceType::Template).with_id(input.template_id);
        self.authorize_action(Action::Update, &object)?;
        Ok(self.inner.update_template_meta(input).await?)
    }

    /// Authorized version of `TemplateStore::update_template_active_version`.
    /// Mirrors Go's `UpdateTemplateActiveVersionByID` in `dbauthz.go`.
    ///
    /// # Errors
    /// Returns [`DbAuthzError::Forbidden`] if the actor may not update
    /// templates, or propagates storage errors from the inner store.
    pub async fn update_template_active_version(
        &self,
        template_id: Uuid,
        active_version_id: Uuid,
    ) -> Result<bool, DbAuthzError> {
        let object = Object::new(ResourceType::Template).with_id(template_id);
        self.authorize_action(Action::Update, &object)?;
        Ok(self
            .inner
            .update_template_active_version(template_id, active_version_id)
            .await?)
    }

    /// Authorized version of `TemplateStore::soft_delete_template`.
    /// Mirrors Go's `SoftDeleteTemplateByID` in `dbauthz.go`.
    ///
    /// # Errors
    /// Returns [`DbAuthzError::Forbidden`] if the actor may not delete
    /// templates, or propagates storage errors from the inner store.
    pub async fn soft_delete_template(&self, template_id: Uuid) -> Result<bool, DbAuthzError> {
        let object = Object::new(ResourceType::Template).with_id(template_id);
        self.authorize_action(Action::Delete, &object)?;
        Ok(self.inner.soft_delete_template(template_id).await?)
    }

    /// Authorized version of `TemplateStore::update_template_acl`.
    /// Mirrors Go's `UpdateTemplateACLByID` in `dbauthz.go` (per the
    /// task spec, we authorize with `Action::Update`; Go uses
    /// `ActionCreate` on the same resource — both require full
    /// template-admin privileges in practice).
    ///
    /// # Errors
    /// Returns [`DbAuthzError::Forbidden`] if the actor may not update
    /// template ACLs, or propagates storage errors from the inner store.
    pub async fn update_template_acl(
        &self,
        template_id: Uuid,
        input: &UpdateTemplateACLInput,
    ) -> Result<(), DbAuthzError> {
        let object = Object::new(ResourceType::Template).with_id(template_id);
        self.authorize_action(Action::Update, &object)?;
        Ok(self.inner.update_template_acl(template_id, input).await?)
    }

    /// Authorized version of `TemplateStore::insert_template_version`.
    /// Mirrors Go's `InsertTemplateVersion` in `dbauthz.go`, which
    /// authorizes `ActionCreate` against the owning template's
    /// organization when the parent `template_id` is unset (new
    /// template) or against the existing template otherwise.
    ///
    /// # Errors
    /// Returns [`DbAuthzError::Forbidden`] if the actor may not create a
    /// template version in this org / template, or propagates storage
    /// errors from the inner store.
    pub async fn insert_template_version(
        &self,
        input: CreateTemplateVersionInput,
    ) -> Result<TemplateVersionRecord, DbAuthzError> {
        let mut object = Object::new(ResourceType::Template).in_org(input.organization_id);
        if let Some(template_id) = input.template_id {
            object = object.with_id(template_id);
        }
        self.authorize_action(Action::Create, &object)?;
        Ok(self.inner.insert_template_version(input).await?)
    }
}

// ---------------------------------------------------------------------------
// User mutator wraps (Wave 3). Each authorizes the matching CRUD action
// against `ResourceType::User` before delegating. `create_user` uses a
// bare resource-type `Create` check (no existing target id); the rest
// scope the object by user id so per-object permissions apply. Mirrors
// Go's `dbauthz.InsertUser` / `UpdateUserProfile` / `UpdateUserStatus` /
// `UpdateUserRoles` / `UpdateUserDeletedByID` /
// `UpdateUserHashedPassword` precheck behaviour.
// ---------------------------------------------------------------------------

impl<S> Authorized<S>
where
    S: UserMutator + ?Sized,
{
    /// Authorized version of `IdentityStore::create_user`. Mirrors Go's
    /// `InsertUser` in `dbauthz.go`.
    ///
    /// # Errors
    /// Returns [`DbAuthzError::Forbidden`] if the actor may not create
    /// users, [`DbAuthzError::UserCreate`] for domain-specific create
    /// failures (e.g. duplicate email), or [`DbAuthzError::Storage`]
    /// for storage failures.
    pub async fn create_user(&self, input: CreateUserInput) -> Result<UserRecord, DbAuthzError> {
        let object = Object::new(ResourceType::User);
        self.authorize_action(Action::Create, &object)?;
        Ok(self.inner.create_user(input).await?)
    }

    /// Authorized version of `IdentityStore::update_user_profile`.
    /// Mirrors Go's `UpdateUserProfile` in `dbauthz.go`.
    ///
    /// # Errors
    /// Returns [`DbAuthzError::Forbidden`] if the actor may not update
    /// this user, or propagates storage errors from the inner store.
    pub async fn update_user_profile(
        &self,
        user_id: Uuid,
        username: &str,
        name: &str,
    ) -> Result<Option<UserRecord>, DbAuthzError> {
        let object = Object::new(ResourceType::User).with_id(user_id);
        self.authorize_action(Action::Update, &object)?;
        Ok(self
            .inner
            .update_user_profile(user_id, username, name)
            .await?)
    }

    /// Authorized version of `IdentityStore::update_user_status`.
    /// Mirrors Go's `UpdateUserStatus` in `dbauthz.go`.
    ///
    /// # Errors
    /// Returns [`DbAuthzError::Forbidden`] if the actor may not update
    /// this user, or propagates storage errors from the inner store.
    pub async fn update_user_status(
        &self,
        user_id: Uuid,
        status: UserStatus,
    ) -> Result<Option<UserRecord>, DbAuthzError> {
        let object = Object::new(ResourceType::User).with_id(user_id);
        self.authorize_action(Action::Update, &object)?;
        Ok(self.inner.update_user_status(user_id, status).await?)
    }

    /// Authorized version of `IdentityStore::update_user_roles`.
    /// Mirrors Go's `UpdateUserRoles` in `dbauthz.go`.
    ///
    /// # Errors
    /// Returns [`DbAuthzError::Forbidden`] if the actor may not update
    /// this user, or propagates storage errors from the inner store.
    pub async fn update_user_roles(
        &self,
        user_id: Uuid,
        roles: Vec<String>,
    ) -> Result<Option<UserRecord>, DbAuthzError> {
        let object = Object::new(ResourceType::User).with_id(user_id);
        self.authorize_action(Action::Update, &object)?;
        Ok(self.inner.update_user_roles(user_id, roles).await?)
    }

    /// Authorized version of `IdentityStore::soft_delete_user`. Mirrors
    /// Go's `UpdateUserDeletedByID` in `dbauthz.go`.
    ///
    /// # Errors
    /// Returns [`DbAuthzError::Forbidden`] if the actor may not delete
    /// this user, or propagates storage errors from the inner store.
    pub async fn soft_delete_user(&self, user_id: Uuid) -> Result<bool, DbAuthzError> {
        let object = Object::new(ResourceType::User).with_id(user_id);
        self.authorize_action(Action::Delete, &object)?;
        Ok(self.inner.soft_delete_user(user_id).await?)
    }
}

impl<S> Authorized<S>
where
    S: UserPasswordMutator + ?Sized,
{
    /// Authorized version of `AuthStore::replace_user_password`. Mirrors
    /// Go's `UpdateUserHashedPassword` in `dbauthz.go`.
    ///
    /// # Errors
    /// Returns [`DbAuthzError::Forbidden`] if the actor may not update
    /// this user, or propagates storage errors from the inner store.
    pub async fn replace_user_password(
        &self,
        user_id: Uuid,
        password_hash: &str,
        clear_one_time_passcode: bool,
    ) -> Result<bool, DbAuthzError> {
        let object = Object::new(ResourceType::User).with_id(user_id);
        self.authorize_action(Action::Update, &object)?;
        Ok(self
            .inner
            .replace_user_password(user_id, password_hash, clear_one_time_passcode)
            .await?)
    }
}

// ---------------------------------------------------------------------------
// API key mutator wraps (W0.S3 tail). Each authorizes the matching CRUD
// action against `ResourceType::ApiKey` before delegating.
//
// `create_api_key` pins `.with_owner(input.user_id)` to match Go's
// `dbauthz.InsertAPIKey` precheck (`rbac.ResourceApiKey.WithOwner(arg.UserID)`).
//
// The id-only methods (`update_api_key_last_used`, `delete_api_key`)
// authorize against the bare `ResourceType::ApiKey` resource because
// our `Object.id` field is `Option<Uuid>` and API key IDs are opaque
// strings — we cannot express `.with_id(id_str)` here. Go's dbauthz
// fetches the row and authorizes against its owner; we defer that
// owner-scoped tightening to a follow-up (tracked in TODO-dbauthz).
// ---------------------------------------------------------------------------

impl<S> Authorized<S>
where
    S: ApiKeyMutator + ?Sized,
{
    /// Authorized version of `AuthStore::create_api_key`. Mirrors Go's
    /// `InsertAPIKey` in `dbauthz.go`
    /// (`ActionCreate` on `ResourceApiKey.WithOwner(arg.UserID)`).
    ///
    /// # Errors
    /// Returns [`DbAuthzError::Forbidden`] if the actor may not create
    /// an API key for this owner, [`DbAuthzError::ApiKeyCreate`] for
    /// domain-specific create failures (e.g. duplicate token name), or
    /// [`DbAuthzError::Storage`] for storage failures.
    pub async fn create_api_key(
        &self,
        input: CreateApiKeyInput,
    ) -> Result<ApiKeyRecord, DbAuthzError> {
        let object = Object::new(ResourceType::ApiKey).with_owner(input.user_id);
        self.authorize_action(Action::Create, &object)?;
        Ok(self.inner.create_api_key(input).await?)
    }

    /// Authorized version of `AuthStore::update_api_key_last_used`.
    /// Mirrors Go's `UpdateAPIKeyByID` in `dbauthz.go`.
    ///
    /// # Errors
    /// Returns [`DbAuthzError::Forbidden`] if the actor may not update
    /// API keys, or propagates storage errors from the inner store.
    pub async fn update_api_key_last_used(
        &self,
        id: &str,
        last_used: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<(), DbAuthzError> {
        let object = Object::new(ResourceType::ApiKey);
        self.authorize_action(Action::Update, &object)?;
        Ok(self
            .inner
            .update_api_key_last_used(id, last_used, expires_at)
            .await?)
    }

    /// Authorized version of `AuthStore::delete_api_key`. Mirrors Go's
    /// `DeleteAPIKeyByID` in `dbauthz.go`.
    ///
    /// # Errors
    /// Returns [`DbAuthzError::Forbidden`] if the actor may not delete
    /// API keys, or propagates storage errors from the inner store.
    pub async fn delete_api_key(&self, id: &str) -> Result<bool, DbAuthzError> {
        let object = Object::new(ResourceType::ApiKey);
        self.authorize_action(Action::Delete, &object)?;
        Ok(self.inner.delete_api_key(id).await?)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use coder_core::LoginType;

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

    // -----------------------------------------------------------------------
    // TemplateMutator wrap tests (Round 4f). One test per wrapped method,
    // each asserting restricted_actor -> Forbidden and owner_actor -> Ok.
    // -----------------------------------------------------------------------

    fn sample_template_record() -> TemplateRecord {
        TemplateRecord {
            id: Uuid::nil(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
            organization_id: Uuid::nil(),
            organization_name: String::new(),
            organization_display_name: String::new(),
            organization_icon: String::new(),
            deleted: false,
            name: "tpl".to_owned(),
            provisioner: "echo".to_owned(),
            active_version_id: Uuid::nil(),
            description: String::new(),
            default_ttl: 0,
            created_by: Uuid::nil(),
            icon: String::new(),
            user_acl: HashMap::new(),
            group_acl: HashMap::new(),
            display_name: String::new(),
            allow_user_cancel_workspace_jobs: false,
            allow_user_autostart: false,
            allow_user_autostop: false,
            failure_ttl: 0,
            time_til_dormant: 0,
            time_til_dormant_autodelete: 0,
            autostop_requirement_days_of_week: 0,
            autostop_requirement_weeks: 0,
            autostart_block_days_of_week: 0,
            require_active_version: false,
            deprecated: String::new(),
            activity_bump: 0,
            max_port_sharing_level: "owner".to_owned(),
            use_classic_parameter_flow: false,
            cors_behavior: String::new(),
            disable_module_cache: false,
            created_by_username: String::new(),
            created_by_avatar_url: String::new(),
            created_by_name: String::new(),
        }
    }

    fn sample_version_record() -> TemplateVersionRecord {
        TemplateVersionRecord {
            id: Uuid::nil(),
            template_id: None,
            organization_id: Uuid::nil(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
            name: "v1".to_owned(),
            readme: String::new(),
            job_id: Uuid::nil(),
            created_by: Uuid::nil(),
            external_auth_providers: serde_json::Value::Null,
            message: String::new(),
            archived: false,
            source_example_id: None,
            has_ai_task: None,
            has_external_agent: None,
            created_by_avatar_url: String::new(),
            created_by_username: String::new(),
            created_by_name: String::new(),
        }
    }

    fn sample_create_template_input() -> CreateTemplateInput {
        CreateTemplateInput {
            id: Uuid::nil(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
            organization_id: Uuid::nil(),
            name: "tpl".to_owned(),
            display_name: String::new(),
            provisioner: "echo".to_owned(),
            active_version_id: Uuid::nil(),
            description: String::new(),
            default_ttl: 0,
            created_by: Uuid::nil(),
            icon: String::new(),
            allow_user_cancel_workspace_jobs: false,
            allow_user_autostart: false,
            allow_user_autostop: false,
            failure_ttl: 0,
            time_til_dormant: 0,
            time_til_dormant_autodelete: 0,
            require_active_version: false,
            activity_bump: 0,
            max_port_share_level: "owner".to_owned(),
        }
    }

    fn sample_update_meta_input() -> UpdateTemplateMetaInput {
        UpdateTemplateMetaInput {
            template_id: Uuid::nil(),
            name: "tpl".to_owned(),
            display_name: String::new(),
            description: String::new(),
            icon: String::new(),
            default_ttl: 0,
            activity_bump: 0,
            allow_user_autostart: false,
            allow_user_autostop: false,
            allow_user_cancel_workspace_jobs: false,
            failure_ttl: 0,
            time_til_dormant: 0,
            time_til_dormant_autodelete: 0,
            require_active_version: false,
            deprecation_message: String::new(),
            max_port_share_level: "owner".to_owned(),
            cors_behavior: String::new(),
            use_classic_parameter_flow: false,
            disable_module_cache: false,
        }
    }

    fn sample_create_version_input() -> CreateTemplateVersionInput {
        CreateTemplateVersionInput {
            id: Uuid::nil(),
            template_id: None,
            organization_id: Uuid::nil(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
            name: "v1".to_owned(),
            message: String::new(),
            readme: String::new(),
            job_id: Uuid::nil(),
            created_by: Uuid::nil(),
            source_example_id: None,
        }
    }

    /// Fake [`TemplateMutator`] that returns canned success values for
    /// every wrapped method so we can assert authorize-then-delegate
    /// ordering without an in-memory store.
    #[derive(Default)]
    struct FakeTemplateMutator;

    #[async_trait]
    impl TemplateMutator for FakeTemplateMutator {
        async fn insert_template(
            &self,
            _input: CreateTemplateInput,
        ) -> Result<TemplateRecord, CreateTemplateStoreError> {
            Ok(sample_template_record())
        }

        async fn update_template_meta(
            &self,
            _input: UpdateTemplateMetaInput,
        ) -> Result<Option<TemplateRecord>, StorageError> {
            Ok(Some(sample_template_record()))
        }

        async fn update_template_active_version(
            &self,
            _template_id: Uuid,
            _active_version_id: Uuid,
        ) -> Result<bool, StorageError> {
            Ok(true)
        }

        async fn soft_delete_template(&self, _template_id: Uuid) -> Result<bool, StorageError> {
            Ok(true)
        }

        async fn update_template_acl(
            &self,
            _template_id: Uuid,
            _input: &UpdateTemplateACLInput,
        ) -> Result<(), StorageError> {
            Ok(())
        }

        async fn insert_template_version(
            &self,
            _input: CreateTemplateVersionInput,
        ) -> Result<TemplateVersionRecord, StorageError> {
            Ok(sample_version_record())
        }
    }

    #[tokio::test]
    async fn insert_template_authorizes_then_delegates() {
        let store = Arc::new(FakeTemplateMutator);
        let denied = Authorized::new(Arc::clone(&store), restricted_actor())
            .insert_template(sample_create_template_input())
            .await;
        assert!(
            matches!(denied, Err(DbAuthzError::Forbidden(_))),
            "expected Forbidden, got: {denied:?}",
        );

        let allowed = Authorized::new(store, owner_actor())
            .insert_template(sample_create_template_input())
            .await;
        assert!(allowed.is_ok(), "expected Ok, got: {allowed:?}");
    }

    #[tokio::test]
    async fn update_template_meta_authorizes_then_delegates() {
        let store = Arc::new(FakeTemplateMutator);
        let denied = Authorized::new(Arc::clone(&store), restricted_actor())
            .update_template_meta(sample_update_meta_input())
            .await;
        assert!(
            matches!(denied, Err(DbAuthzError::Forbidden(_))),
            "expected Forbidden, got: {denied:?}",
        );

        let allowed = Authorized::new(store, owner_actor())
            .update_template_meta(sample_update_meta_input())
            .await;
        assert!(allowed.is_ok(), "expected Ok, got: {allowed:?}");
    }

    #[tokio::test]
    async fn update_template_active_version_authorizes_then_delegates() {
        let store = Arc::new(FakeTemplateMutator);
        let denied = Authorized::new(Arc::clone(&store), restricted_actor())
            .update_template_active_version(Uuid::nil(), Uuid::nil())
            .await;
        assert!(
            matches!(denied, Err(DbAuthzError::Forbidden(_))),
            "expected Forbidden, got: {denied:?}",
        );

        let allowed = Authorized::new(store, owner_actor())
            .update_template_active_version(Uuid::nil(), Uuid::nil())
            .await;
        assert!(allowed.is_ok(), "expected Ok, got: {allowed:?}");
    }

    #[tokio::test]
    async fn soft_delete_template_authorizes_then_delegates() {
        let store = Arc::new(FakeTemplateMutator);
        let denied = Authorized::new(Arc::clone(&store), restricted_actor())
            .soft_delete_template(Uuid::nil())
            .await;
        assert!(
            matches!(denied, Err(DbAuthzError::Forbidden(_))),
            "expected Forbidden, got: {denied:?}",
        );

        let allowed = Authorized::new(store, owner_actor())
            .soft_delete_template(Uuid::nil())
            .await;
        assert!(allowed.is_ok(), "expected Ok, got: {allowed:?}");
    }

    #[tokio::test]
    async fn update_template_acl_authorizes_then_delegates() {
        let store = Arc::new(FakeTemplateMutator);
        let input = UpdateTemplateACLInput::default();
        let denied = Authorized::new(Arc::clone(&store), restricted_actor())
            .update_template_acl(Uuid::nil(), &input)
            .await;
        assert!(
            matches!(denied, Err(DbAuthzError::Forbidden(_))),
            "expected Forbidden, got: {denied:?}",
        );

        let allowed = Authorized::new(store, owner_actor())
            .update_template_acl(Uuid::nil(), &input)
            .await;
        assert!(allowed.is_ok(), "expected Ok, got: {allowed:?}");
    }

    #[tokio::test]
    async fn insert_template_version_authorizes_then_delegates() {
        let store = Arc::new(FakeTemplateMutator);
        let denied = Authorized::new(Arc::clone(&store), restricted_actor())
            .insert_template_version(sample_create_version_input())
            .await;
        assert!(
            matches!(denied, Err(DbAuthzError::Forbidden(_))),
            "expected Forbidden, got: {denied:?}",
        );

        let allowed = Authorized::new(store, owner_actor())
            .insert_template_version(sample_create_version_input())
            .await;
        assert!(allowed.is_ok(), "expected Ok, got: {allowed:?}");
    }

    // -----------------------------------------------------------------------
    // UserMutator / UserPasswordMutator wrap tests (Wave 3).
    // -----------------------------------------------------------------------

    fn sample_user_record() -> UserRecord {
        UserRecord {
            id: Uuid::nil(),
            email: "user@example.com".to_owned(),
            username: "user".to_owned(),
            name: "User".to_owned(),
            avatar_url: String::new(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
            last_seen_at: None,
            organization_ids: Vec::new(),
            roles: Vec::new(),
            login_type: LoginType::Password,
            status: UserStatus::Active,
            deleted: false,
            is_system: false,
        }
    }

    fn sample_create_user_input() -> CreateUserInput {
        CreateUserInput {
            email: "user@example.com".to_owned(),
            username: "user".to_owned(),
            name: "User".to_owned(),
            password_hash: None,
            login_type: LoginType::Password,
            status: UserStatus::Active,
            organization_ids: Vec::new(),
        }
    }

    #[derive(Default)]
    struct FakeUserMutator;

    #[async_trait]
    impl UserMutator for FakeUserMutator {
        async fn create_user(
            &self,
            _input: CreateUserInput,
        ) -> Result<UserRecord, CreateUserStoreError> {
            Ok(sample_user_record())
        }

        async fn update_user_profile(
            &self,
            _user_id: Uuid,
            _username: &str,
            _name: &str,
        ) -> Result<Option<UserRecord>, StorageError> {
            Ok(Some(sample_user_record()))
        }

        async fn update_user_status(
            &self,
            _user_id: Uuid,
            _status: UserStatus,
        ) -> Result<Option<UserRecord>, StorageError> {
            Ok(Some(sample_user_record()))
        }

        async fn update_user_roles(
            &self,
            _user_id: Uuid,
            _roles: Vec<String>,
        ) -> Result<Option<UserRecord>, StorageError> {
            Ok(Some(sample_user_record()))
        }

        async fn soft_delete_user(&self, _user_id: Uuid) -> Result<bool, StorageError> {
            Ok(true)
        }
    }

    #[derive(Default)]
    struct FakeUserPasswordMutator;

    #[async_trait]
    impl UserPasswordMutator for FakeUserPasswordMutator {
        async fn replace_user_password(
            &self,
            _user_id: Uuid,
            _password_hash: &str,
            _clear_one_time_passcode: bool,
        ) -> Result<bool, StorageError> {
            Ok(true)
        }
    }

    #[tokio::test]
    async fn create_user_authorizes_then_delegates() {
        let store = Arc::new(FakeUserMutator);
        let denied = Authorized::new(Arc::clone(&store), restricted_actor())
            .create_user(sample_create_user_input())
            .await;
        assert!(
            matches!(denied, Err(DbAuthzError::Forbidden(_))),
            "expected Forbidden, got: {denied:?}",
        );

        let allowed = Authorized::new(store, owner_actor())
            .create_user(sample_create_user_input())
            .await;
        assert!(allowed.is_ok(), "expected Ok, got: {allowed:?}");
    }

    #[tokio::test]
    async fn update_user_profile_authorizes_then_delegates() {
        let store = Arc::new(FakeUserMutator);
        let denied = Authorized::new(Arc::clone(&store), restricted_actor())
            .update_user_profile(Uuid::nil(), "new-username", "New Name")
            .await;
        assert!(
            matches!(denied, Err(DbAuthzError::Forbidden(_))),
            "expected Forbidden, got: {denied:?}",
        );

        let allowed = Authorized::new(store, owner_actor())
            .update_user_profile(Uuid::nil(), "new-username", "New Name")
            .await;
        assert!(allowed.is_ok(), "expected Ok, got: {allowed:?}");
    }

    #[tokio::test]
    async fn update_user_status_authorizes_then_delegates() {
        let store = Arc::new(FakeUserMutator);
        let denied = Authorized::new(Arc::clone(&store), restricted_actor())
            .update_user_status(Uuid::nil(), UserStatus::Suspended)
            .await;
        assert!(
            matches!(denied, Err(DbAuthzError::Forbidden(_))),
            "expected Forbidden, got: {denied:?}",
        );

        let allowed = Authorized::new(store, owner_actor())
            .update_user_status(Uuid::nil(), UserStatus::Suspended)
            .await;
        assert!(allowed.is_ok(), "expected Ok, got: {allowed:?}");
    }

    #[tokio::test]
    async fn update_user_roles_authorizes_then_delegates() {
        let store = Arc::new(FakeUserMutator);
        let denied = Authorized::new(Arc::clone(&store), restricted_actor())
            .update_user_roles(Uuid::nil(), vec!["owner".to_owned()])
            .await;
        assert!(
            matches!(denied, Err(DbAuthzError::Forbidden(_))),
            "expected Forbidden, got: {denied:?}",
        );

        let allowed = Authorized::new(store, owner_actor())
            .update_user_roles(Uuid::nil(), vec!["owner".to_owned()])
            .await;
        assert!(allowed.is_ok(), "expected Ok, got: {allowed:?}");
    }

    #[tokio::test]
    async fn soft_delete_user_authorizes_then_delegates() {
        let store = Arc::new(FakeUserMutator);
        let denied = Authorized::new(Arc::clone(&store), restricted_actor())
            .soft_delete_user(Uuid::nil())
            .await;
        assert!(
            matches!(denied, Err(DbAuthzError::Forbidden(_))),
            "expected Forbidden, got: {denied:?}",
        );

        let allowed = Authorized::new(store, owner_actor())
            .soft_delete_user(Uuid::nil())
            .await;
        assert!(allowed.is_ok(), "expected Ok, got: {allowed:?}");
    }

    #[tokio::test]
    async fn replace_user_password_authorizes_then_delegates() {
        let store = Arc::new(FakeUserPasswordMutator);
        let denied = Authorized::new(Arc::clone(&store), restricted_actor())
            .replace_user_password(Uuid::nil(), "hash", false)
            .await;
        assert!(
            matches!(denied, Err(DbAuthzError::Forbidden(_))),
            "expected Forbidden, got: {denied:?}",
        );

        let allowed = Authorized::new(store, owner_actor())
            .replace_user_password(Uuid::nil(), "hash", false)
            .await;
        assert!(allowed.is_ok(), "expected Ok, got: {allowed:?}");
    }

    // -----------------------------------------------------------------------
    // ApiKeyMutator wrap tests (Wave 0 S3 tail). One test per wrapped method,
    // each asserting restricted_actor -> Forbidden and owner_actor -> Ok.
    // -----------------------------------------------------------------------

    fn sample_api_key_record() -> ApiKeyRecord {
        ApiKeyRecord {
            id: "key-id".to_owned(),
            hashed_secret: Vec::new(),
            user_id: Uuid::nil(),
            last_used: OffsetDateTime::UNIX_EPOCH,
            expires_at: OffsetDateTime::UNIX_EPOCH,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
            login_type: LoginType::Password,
            scopes: Vec::new(),
            token_name: String::new(),
            lifetime_seconds: 0,
            allow_list: Vec::new(),
        }
    }

    fn sample_create_api_key_input() -> CreateApiKeyInput {
        CreateApiKeyInput {
            id: "key-id".to_owned(),
            hashed_secret: Vec::new(),
            user_id: Uuid::nil(),
            last_used: OffsetDateTime::UNIX_EPOCH,
            expires_at: OffsetDateTime::UNIX_EPOCH,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
            login_type: LoginType::Password,
            scopes: Vec::new(),
            token_name: String::new(),
            lifetime_seconds: 0,
            allow_list: Vec::new(),
        }
    }

    #[derive(Default)]
    struct FakeApiKeyMutator;

    #[async_trait]
    impl ApiKeyMutator for FakeApiKeyMutator {
        async fn create_api_key(
            &self,
            _input: CreateApiKeyInput,
        ) -> Result<ApiKeyRecord, CreateApiKeyStoreError> {
            Ok(sample_api_key_record())
        }

        async fn update_api_key_last_used(
            &self,
            _id: &str,
            _last_used: OffsetDateTime,
            _expires_at: OffsetDateTime,
        ) -> Result<(), StorageError> {
            Ok(())
        }

        async fn delete_api_key(&self, _id: &str) -> Result<bool, StorageError> {
            Ok(true)
        }
    }

    #[tokio::test]
    async fn create_api_key_authorizes_then_delegates() {
        let store = Arc::new(FakeApiKeyMutator);
        let denied = Authorized::new(Arc::clone(&store), restricted_actor())
            .create_api_key(sample_create_api_key_input())
            .await;
        assert!(
            matches!(denied, Err(DbAuthzError::Forbidden(_))),
            "expected Forbidden, got: {denied:?}",
        );

        let allowed = Authorized::new(store, owner_actor())
            .create_api_key(sample_create_api_key_input())
            .await;
        assert!(allowed.is_ok(), "expected Ok, got: {allowed:?}");
    }

    #[tokio::test]
    async fn update_api_key_last_used_authorizes_then_delegates() {
        let store = Arc::new(FakeApiKeyMutator);
        let denied = Authorized::new(Arc::clone(&store), restricted_actor())
            .update_api_key_last_used(
                "key-id",
                OffsetDateTime::UNIX_EPOCH,
                OffsetDateTime::UNIX_EPOCH,
            )
            .await;
        assert!(
            matches!(denied, Err(DbAuthzError::Forbidden(_))),
            "expected Forbidden, got: {denied:?}",
        );

        let allowed = Authorized::new(store, owner_actor())
            .update_api_key_last_used(
                "key-id",
                OffsetDateTime::UNIX_EPOCH,
                OffsetDateTime::UNIX_EPOCH,
            )
            .await;
        assert!(allowed.is_ok(), "expected Ok, got: {allowed:?}");
    }

    #[tokio::test]
    async fn delete_api_key_authorizes_then_delegates() {
        let store = Arc::new(FakeApiKeyMutator);
        let denied = Authorized::new(Arc::clone(&store), restricted_actor())
            .delete_api_key("key-id")
            .await;
        assert!(
            matches!(denied, Err(DbAuthzError::Forbidden(_))),
            "expected Forbidden, got: {denied:?}",
        );

        let allowed = Authorized::new(store, owner_actor())
            .delete_api_key("key-id")
            .await;
        assert!(allowed.is_ok(), "expected Ok, got: {allowed:?}");
    }
}
