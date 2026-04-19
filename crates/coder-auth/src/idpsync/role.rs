//! Role reconciliation for IDP-synced users.
//!
//! Ports Go's `AGPLIDPSync.SyncRoles` + `syncSiteWideRoles` from
//! `coderd/idpsync/role.go`.
//!
//! ### Reconciliation rules
//!
//! **Site-wide roles** (optional; only if `sync_site_wide` is true):
//! 1. `raw_site_claims` are deduplicated and sorted.
//! 2. If the final set differs from the user's current site roles,
//!    `update_user_roles` is called to replace them.
//!
//! **Per-organization roles**:
//! 1. For each organization the user is a member of, load the org's
//!    [`coder_core::api::RoleSyncSettings`].
//! 2. If `settings.field` is empty for that org, skip — role sync is
//!    disabled for that org.
//! 3. Parse the org's role claim from `merged_claims`, applying
//!    `settings.mapping` to expand claim values.
//! 4. Drop the implicit organization-member role if present (Go:
//!    `rbac.RoleOrgMember`).
//! 5. If the dedup-sorted expected set differs from the member's
//!    current roles, call `update_organization_member_roles`.
//!
//! Returns a [`RoleSyncResult`] describing what changed.

use std::collections::HashSet;
use std::sync::Arc;

use coder_core::{api::RoleSyncSettings, ports::AppStore};
use serde_json::Value;
use uuid::Uuid;

use super::{IdpSyncError, claims::parse_role_claims};

/// Name of the implicit per-organization "member" role that Coder
/// always grants and that should never be part of a sync-driven
/// replacement set. Mirrors Go's `rbac.RoleOrgMember`.
const ORG_MEMBER_ROLE: &str = "organization-member";

/// Summary of an applied role sync.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RoleSyncResult {
    /// Number of site-wide roles newly added to the user.
    pub site_added: usize,
    /// Number of site-wide roles removed from the user.
    pub site_removed: usize,
    /// Number of per-organization role grants added (summed across orgs).
    pub org_added: usize,
    /// Number of per-organization role grants removed (summed across orgs).
    pub org_removed: usize,
}

/// Reconciles `user_id`'s roles.
///
/// `merged_claims` are the full claim set; per-org role fields are
/// resolved against this map. `raw_site_claims` are the site-wide roles
/// parsed from the deployment's site-role claim field (empty if
/// site-role sync is disabled).
pub async fn sync_roles(
    store: &Arc<dyn AppStore>,
    user_id: Uuid,
    merged_claims: &Value,
    raw_site_claims: &[String],
    sync_site_wide: bool,
) -> Result<RoleSyncResult, IdpSyncError> {
    let mut result = RoleSyncResult::default();

    // Site-wide sync.
    if sync_site_wide {
        let (site_added, site_removed) =
            sync_site_wide_roles(store, user_id, raw_site_claims).await?;
        result.site_added = site_added;
        result.site_removed = site_removed;
    }

    // Per-organization sync.
    let memberships = store.list_user_memberships(user_id).await?;
    for membership in memberships {
        let org_id = membership.organization_id;
        let settings = match store.role_sync_settings(org_id).await {
            Ok(s) => s,
            Err(err) => {
                tracing::warn!(
                    %user_id,
                    organization_id = %org_id,
                    error = %err,
                    "failed to load role sync settings; skipping org",
                );
                continue;
            }
        };
        if settings.field.is_empty() {
            continue;
        }

        match sync_org_roles(
            store,
            user_id,
            org_id,
            merged_claims,
            &settings,
            &membership.roles,
        )
        .await
        {
            Ok((added, removed)) => {
                result.org_added += added;
                result.org_removed += removed;
            }
            Err(err) => {
                tracing::warn!(
                    %user_id,
                    organization_id = %org_id,
                    error = %err,
                    "IDP role sync failed for organization",
                );
            }
        }
    }

    Ok(result)
}

/// Compute, diff, and (if needed) apply site-wide roles.
///
/// Returns `(added, removed)`.
async fn sync_site_wide_roles(
    store: &Arc<dyn AppStore>,
    user_id: Uuid,
    raw_site_claims: &[String],
) -> Result<(usize, usize), IdpSyncError> {
    let user = match store.find_user_by_id(user_id).await? {
        Some(u) => u,
        None => {
            // User vanished mid-flow: bail cleanly. Login will retry.
            tracing::debug!(%user_id, "user not found during site-role sync");
            return Ok((0, 0));
        }
    };
    let existing: Vec<String> = unique_sorted(user.roles.iter().map(|r| r.name.clone()));
    let expected: Vec<String> = unique_sorted(raw_site_claims.iter().cloned());

    if existing == expected {
        return Ok((0, 0));
    }

    let existing_set: HashSet<&String> = existing.iter().collect();
    let expected_set: HashSet<&String> = expected.iter().collect();
    let added = expected_set.difference(&existing_set).count();
    let removed = existing_set.difference(&expected_set).count();

    if let Err(err) = store.update_user_roles(user_id, expected).await {
        tracing::warn!(%user_id, error = %err, "failed to update site-wide roles");
        return Ok((0, 0));
    }
    Ok((added, removed))
}

/// Compute, diff, and (if needed) apply per-organization roles.
///
/// Returns `(added, removed)`.
async fn sync_org_roles(
    store: &Arc<dyn AppStore>,
    user_id: Uuid,
    org_id: Uuid,
    merged_claims: &Value,
    settings: &RoleSyncSettings,
    existing_roles: &[coder_core::identity::SlimRoleRecord],
) -> Result<(usize, usize), IdpSyncError> {
    let claim_roles = parse_role_claims(&settings.field, merged_claims);

    // Expand mapping: every role that has a mapping entry is replaced by
    // the mapped names; unmapped roles pass through. Mirrors Go exactly.
    let mut expected_raw: Vec<String> = Vec::with_capacity(claim_roles.len());
    for role in &claim_roles {
        if let Some(mapped) = settings.mapping.get(role) {
            expected_raw.extend(mapped.iter().cloned());
        } else {
            expected_raw.push(role.clone());
        }
    }

    // Drop the implicit member role and deduplicate/sort.
    let expected: Vec<String> =
        unique_sorted(expected_raw.into_iter().filter(|r| r != ORG_MEMBER_ROLE));
    let existing: Vec<String> = unique_sorted(
        existing_roles
            .iter()
            .map(|r| r.name.clone())
            .filter(|r| r != ORG_MEMBER_ROLE),
    );

    if existing == expected {
        return Ok((0, 0));
    }

    let existing_set: HashSet<&String> = existing.iter().collect();
    let expected_set: HashSet<&String> = expected.iter().collect();
    let added = expected_set.difference(&existing_set).count();
    let removed = existing_set.difference(&expected_set).count();

    if let Err(err) = store
        .update_organization_member_roles(org_id, user_id, expected)
        .await
    {
        tracing::warn!(
            %user_id,
            organization_id = %org_id,
            error = %err,
            "failed to update organization-member roles",
        );
        return Ok((0, 0));
    }
    Ok((added, removed))
}

fn unique_sorted<I: IntoIterator<Item = String>>(items: I) -> Vec<String> {
    let mut out: Vec<String> = items.into_iter().collect();
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // End-to-end reconciliation coverage against a live Postgres lives
    // in `coder-integration-tests`. These tests cover pure helpers that
    // don't need a store.

    #[test]
    fn unique_sorted_deduplicates_and_sorts() {
        let out = unique_sorted(["c", "a", "b", "a"].into_iter().map(str::to_owned));
        assert_eq!(out, vec!["a".to_owned(), "b".to_owned(), "c".to_owned()]);
    }

    #[test]
    fn member_role_is_filtered() {
        let out = unique_sorted(
            [ORG_MEMBER_ROLE, "admin", ORG_MEMBER_ROLE]
                .into_iter()
                .map(str::to_owned)
                .filter(|r| r != ORG_MEMBER_ROLE),
        );
        assert_eq!(out, vec!["admin".to_owned()]);
    }

    #[test]
    fn equal_sets_produce_no_diff() {
        let existing = vec!["a".to_owned(), "b".to_owned()];
        let expected = vec!["b".to_owned(), "a".to_owned()];
        let eu = unique_sorted(existing);
        let xu = unique_sorted(expected);
        assert_eq!(eu, xu);
    }

    #[test]
    fn mapping_expansion_replaces_claim() {
        let settings = RoleSyncSettings {
            field: "roles".to_owned(),
            mapping: [(
                "lead".to_owned(),
                vec!["admin".to_owned(), "auditor".to_owned()],
            )]
            .into_iter()
            .collect(),
        };

        // Simulate the expansion step.
        let claim_roles = vec!["lead".to_owned(), "unmapped".to_owned()];
        let mut expected: Vec<String> = Vec::new();
        for role in &claim_roles {
            if let Some(mapped) = settings.mapping.get(role) {
                expected.extend(mapped.iter().cloned());
            } else {
                expected.push(role.clone());
            }
        }
        expected = unique_sorted(expected.into_iter().filter(|r| r != ORG_MEMBER_ROLE));
        assert_eq!(
            expected,
            vec![
                "admin".to_owned(),
                "auditor".to_owned(),
                "unmapped".to_owned(),
            ]
        );
    }
}
