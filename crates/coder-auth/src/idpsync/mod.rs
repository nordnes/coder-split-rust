//! IDP (Identity Provider) sync runtime.
//!
//! Ports Go's `coderd/idpsync/` package: parsing OIDC claims and
//! reconciling the authenticated user's group memberships, organization
//! memberships, and RBAC roles against the configured sync settings.
//!
//! # Scope
//!
//! * [`claims::parse_group_claims`] — extract the raw list of group
//!   names from `merged_claims[groups_field]`, enforcing the deployment
//!   `group_allow_list` when configured.
//! * [`claims::parse_org_claims`] — extract the raw list of org names
//!   from `merged_claims[<org_field>]`.
//! * [`claims::parse_role_claims`] — extract the raw list of role names
//!   from `merged_claims[<role_field>]`.
//! * [`group_sync::sync_groups`] — apply regex filter + mapping,
//!   auto-create missing groups (if enabled), and reconcile
//!   `group_members` memberships.
//! * [`organization::sync_organizations`] — apply regex filter +
//!   mapping + assign-default, and reconcile `organization_members`.
//! * [`role::sync_roles`] — reconcile site-wide roles and per-org
//!   member roles (the latter reads per-org `RoleSyncSettings`).
//! * The OIDC callback in `coder-server::handlers::auth` calls
//!   `sync_organizations` + `sync_roles` + `sync_groups` (in that
//!   order) between token verification and session issue.
//!
//! # Failure semantics
//!
//! Matching Go, a sync error is logged at WARN level but does **not**
//! fail the login. Identity must work even when sync is misconfigured.

pub mod claims;
pub mod group_sync;
pub mod organization;
pub mod role;

use thiserror::Error;

/// Errors raised by the IDP sync runtime.
#[derive(Debug, Error)]
pub enum IdpSyncError {
    /// A storage operation failed.
    #[error("storage error: {0}")]
    Storage(#[from] coder_core::StorageError),

    /// The configured regex filter failed to compile.
    #[error("invalid regex filter: {0}")]
    InvalidRegex(#[from] regex::Error),
}

/// Summary of an applied group sync, for logs and metrics.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GroupSyncResult {
    /// Number of group memberships inserted for the user.
    pub added: usize,
    /// Number of IDP-controlled group memberships removed from the user.
    pub removed: usize,
    /// Number of brand-new groups created in the organization because
    /// `auto_create_missing_groups` was enabled.
    pub created: usize,
}
