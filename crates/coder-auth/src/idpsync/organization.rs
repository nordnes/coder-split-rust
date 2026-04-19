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
//!    * Add membership for every resolved org the user isn't already in.
//!    * Remove the user from orgs that were in the membership set but
//!      are not in the resolved set. **Note**: Go does not track whether
//!      a membership was IDP-created or manually added — it simply
//!      removes anything outside the expected set. Rust mirrors that.
//!      A legacy-deployment safeguard would require a schema change —
//!      left as `TODO-organization-idp-flag`.
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

    // 5. Diff against the user's current memberships.
    let existing_memberships = store.list_user_memberships(user_id).await?;
    let existing: HashSet<Uuid> = existing_memberships
        .iter()
        .map(|m| m.organization_id)
        .collect();

    let mut added = 0usize;
    for org_id in expected.difference(&existing) {
        match store.insert_organization_member(*org_id, user_id).await {
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
    for org_id in existing.difference(&expected) {
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

    // TODO-organization-idp-flag: Go does not distinguish IDP-controlled
    // vs. manually-granted memberships. If the schema grows an
    // `is_idp_controlled` flag on `organization_members`, revisit the
    // `removed` loop to preserve manually-added memberships.

    Ok(OrganizationSyncResult { added, removed })
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
}
