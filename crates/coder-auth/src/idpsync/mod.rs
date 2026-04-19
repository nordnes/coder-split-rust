//! IDP (Identity Provider) sync runtime.
//!
//! Ports the first slice of Go's `coderd/idpsync/` package: parsing group
//! claims out of OIDC userinfo + id_token, then reconciling the user's group
//! memberships against the per-organization sync settings.
//!
//! Higher-level concerns (organization sync, role sync) are intentionally
//! deferred to follow-up batches. See Go `idpsync/organization.go` and
//! `idpsync/role.go` for the remaining work.
//!
//! # Scope of this batch
//!
//! * [`claims::parse_group_claims`] — extract the raw list of group names
//!   from `merged_claims[groups_field]`.
//! * [`group_sync::sync_groups`] — apply regex filter + mapping, auto-create
//!   missing groups (if enabled), and reconcile `group_members` memberships.
//! * The OIDC callback hook in `coder-server::handlers::auth` calls
//!   `parse_group_claims` and `sync_groups` between token verification and
//!   session issue.
//!
//! # Failure semantics
//!
//! Matching Go, a sync error is logged at WARN level but does **not** fail
//! the login. Identity must work even when sync is misconfigured.

pub mod claims;
pub mod group_sync;

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

/// Summary of an applied sync, for logs and metrics.
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
