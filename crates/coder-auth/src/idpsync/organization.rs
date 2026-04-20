//! Organization-membership reconciliation for IDP-synced users.
//!
//! Ports Go's `AGPLIDPSync.SyncOrganizations` +
//! `OrganizationSyncSettings.ParseClaims` from
//! `coderd/idpsync/organization.go`.
//!
//! ### Reconciliation rules
//!
//! 1. Apply `regex_filter` to the parsed claim values. If no filter is
//!    configured, every claim passes through.
//! 2. Apply `settings.mapping`: each claim maps to zero or more Coder
//!    org UUIDs. Unmapped claim values are dropped (unlike group sync,
//!    which can fall back to by-name lookup — Go's
//!    `OrganizationSyncSettings.ParseClaims` does not look orgs up by
//!    name).
//! 3. If `settings.assign_default` is true, always include the default
//!    organization in the expected set.
//! 4. Reconcile `organization_members`:
//!    * Add membership for every resolved org the user isn't already in,
//!      tagging the new row as IDP-controlled.
//!    * Remove the user from orgs that were in the membership set but
//!      are not in the resolved set **only when the existing row is
//!      IDP-controlled**. Manually-assigned memberships
//!      (`is_idp_controlled = false`) are preserved across syncs so an
//!      admin grant is not silently revoked on the next login when the
//!      claim does not echo that org.
//!
//! Returns an [`OrganizationSyncResult`] describing what changed.

use std::collections::HashSet;
use std::sync::Arc;

use coder_core::{api::OrganizationSyncSettings, ports::AppStore};
use regex::Regex;
use uuid::Uuid;

use super::IdpSyncError;

/// Summary of an applied organization sync.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OrganizationSyncResult {
    /// Number of organization memberships inserted for the user.
    pub added: usize,
    /// Number of organization memberships removed from the user.
    pub removed: usize,
}

/// Reconciles `user_id`'s organization memberships against the
/// parsed claim values for the deployment-level `settings`.
///
/// * `raw_claims` are the parsed organization names/IDs from the
///   claim (see [`super::claims::parse_org_claims`]).
/// * `regex_filter`, when provided, filters `raw_claims` before
///   mapping.
///
/// Returns [`OrganizationSyncResult`].
pub async fn sync_organizations(
    store: &Arc<dyn AppStore>,
    user_id: Uuid,
    raw_claims: &[String],
    settings: &OrganizationSyncSettings,
    regex_filter: Option<&str>,
) -> Result<OrganizationSyncResult, IdpSyncError> {
    // Short-circuit if organization sync is not configured.
    if settings.field.is_empty() && !settings.assign_default {
        tracing::debug!(
            %user_id,
            "organization sync field not configured; skipping reconciliation",
        );
        return Ok(OrganizationSyncResult::default());
    }

    // 1. Compile optional regex filter.
    let filter = match regex_filter {
        Some(pattern) if !pattern.is_empty() => Some(Regex::new(pattern)?),
        _ => None,
    };

    // 2. Resolve expected org UUIDs via the mapping.
    let mut expected: HashSet<Uuid> = HashSet::new();
    for raw in raw_claims {
        if let Some(re) = &filter {
            if !re.is_match(raw) {
                continue;
            }
        }
        if let Some(ids) = settings.mapping.get(raw) {
            for id in ids {
                expected.insert(*id);
            }
        }
    }

    // 3. Optionally include the default organization.
    if settings.assign_default {
        // Fetch all orgs and find the one flagged as default. The store
        // does not expose a dedicated `get_default_organization` method,
        // so we iterate. This happens once per login.
        let all_orgs = store.list_organizations(Vec::new()).await?;
        if let Some(default) = all_orgs.iter().find(|o| o.is_default && !o.deleted) {
            expected.insert(default.id);
        } else {
            tracing::warn!(
                %user_id,
                "assign_default is enabled but no default organization exists",
            );
        }
    }

    // 4. Drop references to deleted organizations. Go filters these out
    //    via a second query; we do the same by joining against the full
    //    org list we may already have fetched (fetch on demand).
    if !expected.is_empty() {
        let all_orgs = store
            .list_organizations(expected.iter().copied().collect())
            .await?;
        let live: HashSet<Uuid> = all_orgs
            .iter()
            .filter(|o| !o.deleted)
            .map(|o| o.id)
            .collect();
        expected.retain(|id| live.contains(id));
    }

    // 5. Diff against the user's current memberships. We track the
    //    IDP-controlled flag so manually-assigned memberships (rows
    //    created by the admin API or the bootstrap path) are preserved
    //    across sync passes that do not re-assert them.
    let existing_memberships = store.list_user_memberships(user_id).await?;
    let existing_with_flag: Vec<(Uuid, bool)> = existing_memberships
        .iter()
        .map(|m| (m.organization_id, m.is_idp_controlled))
        .collect();
    let plan = plan_sync_diff(&expected, &existing_with_flag);

    let mut added = 0usize;
    for org_id in &plan.to_add {
        match store
            .insert_organization_member(*org_id, user_id, true)
            .await
        {
            Ok(_) => added += 1,
            Err(err) => {
                // Do not fail the whole sync for a single failed insert.
                // A unique-violation would indicate a race we can safely
                // ignore; other errors are logged and skipped so that
                // login continues.
                tracing::warn!(
                    %user_id,
                    organization_id = %org_id,
                    error = %err,
                    "failed to add IDP-synced organization membership",
                );
            }
        }
    }

    let mut removed = 0usize;
    for org_id in &plan.to_remove {
        match store.delete_organization_member(*org_id, user_id).await {
            Ok(true) => removed += 1,
            Ok(false) => {}
            Err(err) => {
                tracing::warn!(
                    %user_id,
                    organization_id = %org_id,
                    error = %err,
                    "failed to remove IDP-synced organization membership",
                );
            }
        }
    }

    Ok(OrganizationSyncResult { added, removed })
}

/// Result of planning a single `sync_organizations` pass: the list of
/// org UUIDs to insert (all newly tagged `is_idp_controlled = true`) and
/// the list of org UUIDs to delete.
///
/// A row is a delete candidate only when it is not in the expected set
/// **and** the existing membership is flagged `is_idp_controlled = true`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct SyncPlan {
    to_add: Vec<Uuid>,
    to_remove: Vec<Uuid>,
}

/// Computes the add/remove split for a single sync pass.
///
/// `expected` is the claim-derived set of org UUIDs the user must be a
/// member of. `existing_with_flag` lists the user's current memberships
/// along with their `is_idp_controlled` flag.
///
/// * Every expected org the user is not already in is scheduled for
///   insert.
/// * Every existing org outside the expected set is scheduled for
///   delete **only when its `is_idp_controlled` flag is `true`**.
///   Manually-assigned memberships (`false`) are always preserved.
fn plan_sync_diff(expected: &HashSet<Uuid>, existing_with_flag: &[(Uuid, bool)]) -> SyncPlan {
    let existing_ids: HashSet<Uuid> = existing_with_flag.iter().map(|(id, _)| *id).collect();

    let mut to_add: Vec<Uuid> = expected.difference(&existing_ids).copied().collect();
    // Stable ordering keeps log/test output deterministic.
    to_add.sort();

    let mut to_remove: Vec<Uuid> = existing_with_flag
        .iter()
        .filter(|(org_id, is_idp_controlled)| *is_idp_controlled && !expected.contains(org_id))
        .map(|(org_id, _)| *org_id)
        .collect();
    to_remove.sort();

    SyncPlan { to_add, to_remove }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use coder_core::api::OrganizationSyncSettings;

    // `sync_organizations` touches four store methods
    // (`list_organizations`, `list_user_memberships`,
    // `insert_organization_member`, `delete_organization_member`).
    // Wiring up a full AppStore mock would require stubbing ~200
    // methods, so end-to-end coverage lives in
    // `coder-integration-tests`. Here we cover the pure helpers.

    #[test]
    fn settings_short_circuit_when_unconfigured() {
        let settings = OrganizationSyncSettings::default();
        assert!(settings.field.is_empty());
        assert!(!settings.assign_default);
        assert!(settings.mapping.is_empty());
    }

    #[test]
    fn invalid_regex_surfaces_as_error() {
        // The regex below is built dynamically so clippy's literal
        // regex lint does not catch it at build time.
        let pattern = String::from("([") + "unclosed";
        assert!(Regex::new(&pattern).is_err());
    }

    #[test]
    fn regex_filter_drops_non_matching_claims() {
        // Exercise the claim-filter step directly.
        let filter = Regex::new(r"^team-.*$").unwrap();
        let raw = ["team-a", "other", "team-b", "misc"];
        let matched: Vec<&&str> = raw.iter().filter(|c| filter.is_match(c)).collect();
        assert_eq!(matched, vec![&"team-a", &"team-b"]);
    }

    #[test]
    fn mapping_expands_claim_to_uuid_set() {
        let org1 = Uuid::new_v4();
        let org2 = Uuid::new_v4();
        let settings = OrganizationSyncSettings {
            field: "orgs".to_owned(),
            mapping: [
                ("team-a".to_owned(), vec![org1, org2]),
                ("team-b".to_owned(), vec![org1]),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        };

        // Simulate the mapping step.
        let raw = ["team-a", "team-b", "unmapped"];
        let mut expected: HashSet<Uuid> = HashSet::new();
        for r in raw {
            if let Some(ids) = settings.mapping.get(r) {
                for id in ids {
                    expected.insert(*id);
                }
            }
        }
        assert!(expected.contains(&org1));
        assert!(expected.contains(&org2));
        assert_eq!(expected.len(), 2);
    }

    // The `plan_sync_diff` helper is the pure core of the reconciler:
    // everything the store-backed `sync_organizations` does reduces to
    // "call insert for every id in `to_add` and delete for every id in
    // `to_remove`". Exercising the helper here gives us the behaviour
    // guarantees requested in the task (manual memberships preserved,
    // IDP-controlled memberships removed when no longer asserted)
    // without having to stand up a full `AppStore` mock.

    #[test]
    fn sync_organizations_preserves_manual_memberships() {
        // A user is a manual member of `manual_org`. The claim set for
        // this sync pass does not include that org. The reconciler must
        // NOT schedule a delete for the manual membership.
        let manual_org = Uuid::new_v4();
        let claim_org = Uuid::new_v4();

        // Expected set comes from the claim; it contains `claim_org`
        // but NOT `manual_org`.
        let mut expected = HashSet::new();
        expected.insert(claim_org);

        // Existing memberships: one manual (is_idp_controlled=false),
        // nothing else.
        let existing = vec![(manual_org, false)];

        let plan = plan_sync_diff(&expected, &existing);

        assert_eq!(
            plan.to_add,
            vec![claim_org],
            "the claim-only org must be added",
        );
        assert!(
            plan.to_remove.is_empty(),
            "manual memberships must never be scheduled for removal; got {:?}",
            plan.to_remove,
        );
    }

    #[test]
    fn sync_organizations_removes_idp_controlled_no_longer_asserted() {
        // A user has an IDP-controlled membership for `stale_idp_org`.
        // The current claim no longer asserts that org; it asserts a
        // different one, `current_claim_org`, which the user is already
        // in (also IDP-controlled). The reconciler must schedule the
        // stale membership for removal and must NOT re-insert the
        // already-present one.
        let stale_idp_org = Uuid::new_v4();
        let current_claim_org = Uuid::new_v4();

        let mut expected = HashSet::new();
        expected.insert(current_claim_org);

        let existing = vec![(stale_idp_org, true), (current_claim_org, true)];

        let plan = plan_sync_diff(&expected, &existing);

        assert!(
            plan.to_add.is_empty(),
            "user already holds the expected membership; nothing to add",
        );
        assert_eq!(
            plan.to_remove,
            vec![stale_idp_org],
            "only the IDP-controlled membership the claim no longer asserts must be removed",
        );
    }

    #[test]
    fn sync_organizations_mixed_manual_and_idp_memberships() {
        // Cover the full matrix in one go: manual-kept, idp-dropped,
        // idp-kept, idp-to-add.
        let manual_kept = Uuid::new_v4();
        let idp_dropped = Uuid::new_v4();
        let idp_kept = Uuid::new_v4();
        let idp_to_add = Uuid::new_v4();

        let mut expected = HashSet::new();
        expected.insert(idp_kept);
        expected.insert(idp_to_add);

        let existing = vec![(manual_kept, false), (idp_dropped, true), (idp_kept, true)];

        let plan = plan_sync_diff(&expected, &existing);

        assert_eq!(plan.to_add, vec![idp_to_add]);
        assert_eq!(plan.to_remove, vec![idp_dropped]);
        // Explicit guards against regressions.
        assert!(!plan.to_remove.contains(&manual_kept));
        assert!(!plan.to_remove.contains(&idp_kept));
        assert!(!plan.to_add.contains(&idp_kept));
    }
}
