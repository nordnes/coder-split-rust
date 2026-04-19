//! RBAC → SQL `WHERE`-clause generator ("partial evaluation" pushdown).
//!
//! Mirrors the intent of Go's `coderd/rbac/regosql` package, which translates
//! the OPA policy into a `WHERE`-clause fragment so list endpoints can
//! prefilter at the database instead of scanning every row. Rust has no
//! first-class OPA engine, so this module is a **narrower, Rust-native
//! equivalent** that covers the common cases hit by list endpoints:
//!
//! * Site-level owner (wildcard on the resource) → `TRUE` (no filter).
//! * Org-admin with N admin orgs → `{org_column} = ANY($N)`.
//! * Regular user with a workspace scope and an owner column → `{owner_column} = $N`.
//! * [`Scope::scope_workspace_agent`]-style scope → `{id_column} = $N`.
//! * Deny → `FALSE` (empty result).
//!
//! The generator produces a [`SqlFilter`] whose `clause` is safe to append to
//! an existing `WHERE` clause via `AND (<clause>)`. Parameters are returned
//! separately so callers bind them through `sqlx::QueryBuilder`.
//!
//! # What is deferred
//!
//! * Full policy-graph eval (multi-resource joins, custom roles with complex
//!   condition sets) — see `TODO-regosql-custom-roles`.
//! * Cedar or OPA integration — skipped entirely; this is Rust-native.
//! * All resource types beyond `Workspace`, `Template`, `AuditLog` — see
//!   `TODO-regosql-expand`.
//!
//! Feature-flagged via `CODER_RBAC_SQL_FILTER` (default on). When disabled,
//! call-sites fall back to the pre-existing post-filter behaviour.

use coder_core::RbacAuthzFilter;
use uuid::Uuid;

use crate::{Action, Actor, ROLE_ORGANIZATION_ADMIN, ROLE_OWNER, ResourceType};

/// A SQL `WHERE`-clause fragment plus its bind parameters.
///
/// This is a type alias for [`coder_core::RbacAuthzFilter`]; the shared
/// type lives in `coder-core` so filter structs there can carry it.
///
/// `clause` is a sub-expression intended to be appended to the caller's
/// existing `WHERE` via `AND (<clause>)`. It contains *placeholder tokens*
/// of the form `{uuid$N}` (where `N` is the 1-based parameter index) for
/// single-UUID binds, and `{uuid_array$N}` for `UUID[]` binds. Callers rewrite
/// these tokens into the correct `$k` placeholders for their actual bind
/// slots via [`rebind`].
///
/// Two sentinel clauses are emitted verbatim:
/// * `"TRUE"` — no filter needed (site owner); caller may skip altogether.
/// * `"FALSE"` — deny; caller should short-circuit to an empty result.
pub type SqlFilter = RbacAuthzFilter;

/// Constructs the permissive (no filter) clause.
#[must_use]
pub fn allow_all() -> SqlFilter {
    SqlFilter {
        clause: "TRUE".to_owned(),
        uuid_params: Vec::new(),
        uuid_array_params: Vec::new(),
    }
}

/// Constructs the deny (empty result) clause.
#[must_use]
pub fn deny_all() -> SqlFilter {
    SqlFilter {
        clause: "FALSE".to_owned(),
        uuid_params: Vec::new(),
        uuid_array_params: Vec::new(),
    }
}

/// Rewrites the `{uuid$N}` / `{uuid_array$N}` placeholders in `filter.clause`
/// into concrete `$k` placeholders, starting at `start_index` (1-based).
/// Returns the rewritten clause and the number of extra bind slots consumed.
///
/// Bind order: all `uuid_params` first (in index order), then all
/// `uuid_array_params` (in index order). The caller must bind them to
/// the `sqlx::QueryBuilder` in that same order.
#[must_use]
pub fn rebind(filter: &SqlFilter, start_index: usize) -> (String, usize) {
    let mut clause = filter.clause.clone();
    // uuid$N → $(start_index + N - 1)
    for (i, _) in filter.uuid_params.iter().enumerate() {
        let token = format!("{{uuid${}}}", i + 1);
        let slot = format!("${}", start_index + i);
        clause = clause.replace(&token, &slot);
    }
    let uuid_offset = filter.uuid_params.len();
    for (i, _) in filter.uuid_array_params.iter().enumerate() {
        let token = format!("{{uuid_array${}}}", i + 1);
        let slot = format!("${}", start_index + uuid_offset + i);
        clause = clause.replace(&token, &slot);
    }
    let total = uuid_offset + filter.uuid_array_params.len();
    (clause, total)
}

/// Builder for SQL filter fragments. See the [module-level docs](self) for
/// the covered policy surface.
pub struct SqlFilterBuilder<'a> {
    actor: &'a Actor,
    resource_type: ResourceType,
    action: Action,
    org_column: &'a str,
    owner_column: Option<&'a str>,
    id_column: &'a str,
}

impl<'a> SqlFilterBuilder<'a> {
    /// Creates a new builder with default column names. Override via
    /// [`Self::with_org_column`] / [`Self::with_owner_column`] /
    /// [`Self::with_id_column`].
    #[must_use]
    pub fn new(actor: &'a Actor, resource_type: ResourceType, action: Action) -> Self {
        Self {
            actor,
            resource_type,
            action,
            org_column: "organization_id",
            owner_column: None,
            id_column: "id",
        }
    }

    /// Sets the SQL column holding the resource's organization id.
    #[must_use]
    pub const fn with_org_column(mut self, col: &'a str) -> Self {
        self.org_column = col;
        self
    }

    /// Sets the SQL column holding the resource's owner user id. Only
    /// user-scoped filters (e.g. `list_workspaces` for a regular user)
    /// require this; leave unset for resource types without an owner
    /// (e.g. `Template`, `AuditLog`).
    #[must_use]
    pub const fn with_owner_column(mut self, col: &'a str) -> Self {
        self.owner_column = Some(col);
        self
    }

    /// Sets the SQL column holding the resource's primary id. Used only when
    /// a [`Scope::scope_workspace_agent`]-style scope is present, which
    /// constrains access to a single resource id.
    #[must_use]
    pub const fn with_id_column(mut self, col: &'a str) -> Self {
        self.id_column = col;
        self
    }

    /// Emits a SQL `WHERE`-clause fragment enforcing the actor's access to
    /// rows of this resource + action. See [`SqlFilter`] for the placeholder
    /// token format.
    ///
    /// The implementation covers the common cases; anything outside those
    /// cases falls back to the conservative `FALSE` deny. This is safe (the
    /// legacy in-memory post-filter path will still run upstream); see the
    /// feature flag in [`module docs`](self).
    #[must_use]
    pub fn build(self) -> SqlFilter {
        let actor = self.actor;

        // 1. Site-level owner: wildcard on everything → no filter.
        if actor.has_site_role(ROLE_OWNER) {
            return allow_all();
        }

        // 2. Workspace-agent-style scope: the scope's allow_list pins a single
        //    resource id. Emit an `id = $?` filter.
        if let Some(scope) = &actor.scope_override {
            for (rt_str, id_str) in &scope.allow_list {
                if *rt_str == self.resource_type.as_str() {
                    if let Ok(id) = id_str.parse::<Uuid>() {
                        return SqlFilter {
                            clause: format!("{} = {{uuid$1}}", self.id_column),
                            uuid_params: vec![id],
                            uuid_array_params: Vec::new(),
                        };
                    }
                }
            }
            // If scope_override exists but the resource isn't in allow_list,
            // it's a deny unless the allow_list has a wildcard entry.
            let has_wildcard = scope
                .allow_list
                .iter()
                .any(|(rt, id)| rt == crate::WILDCARD && id == crate::WILDCARD);
            if !has_wildcard {
                return deny_all();
            }
        }

        // 3. Organization admin: scan org_roles for `organization-admin` and
        //    collect the org ids. If any, allow `{org} = ANY(...)`.
        let admin_orgs = collect_admin_orgs(actor);
        let is_admin_anywhere = !admin_orgs.is_empty();

        // 4. Special actions: for `Workspace:Read`, regular members can read
        //    their own workspaces (per role_member's `user` block — wildcard
        //    on most resources, including Workspace:Read).
        let member_self_allowed = matches!(
            (self.resource_type, self.action),
            (
                ResourceType::Workspace,
                Action::Read | Action::Start | Action::Stop | Action::Update
            )
        );

        // Auditors can read AuditLog / Template site-wide.
        let auditor_site_allowed = matches!(
            (self.resource_type, self.action),
            (ResourceType::AuditLog, Action::Read) | (ResourceType::Template, Action::Read)
        ) && (actor.has_site_role(crate::ROLE_AUDITOR)
            || actor.has_site_role(crate::ROLE_TEMPLATE_ADMIN));

        if auditor_site_allowed {
            return allow_all();
        }

        // Build up OR-ed sub-clauses.
        let mut ors: Vec<String> = Vec::new();
        let mut uuid_params: Vec<Uuid> = Vec::new();
        let mut uuid_array_params: Vec<Vec<Uuid>> = Vec::new();

        if is_admin_anywhere {
            uuid_array_params.push(admin_orgs);
            let slot = format!("{{uuid_array${}}}", uuid_array_params.len());
            ors.push(format!("{} = ANY({slot})", self.org_column));
        }

        // Regular member reading their own workspaces.
        if member_self_allowed {
            if let Some(owner_col) = self.owner_column {
                uuid_params.push(actor.user_id);
                let slot = format!("{{uuid${}}}", uuid_params.len());
                ors.push(format!("{owner_col} = {slot}"));
            }
        }

        // For Template:Read, members of any org can read templates in those orgs.
        if matches!(
            (self.resource_type, self.action),
            (ResourceType::Template, Action::Read)
        ) && !actor.organization_ids.is_empty()
            && !is_admin_anywhere
        {
            uuid_array_params.push(actor.organization_ids.clone());
            let slot = format!("{{uuid_array${}}}", uuid_array_params.len());
            ors.push(format!("{} = ANY({slot})", self.org_column));
        }

        if ors.is_empty() {
            // TODO-regosql-custom-roles: fall back to deny for anything we
            // don't explicitly cover. The legacy in-memory post-filter path
            // still runs, so this is only a pushdown optimisation — real
            // denies will be enforced there.
            return deny_all();
        }

        let clause = if ors.len() == 1 {
            ors.into_iter().next().unwrap_or_default()
        } else {
            format!("({})", ors.join(" OR "))
        };
        SqlFilter {
            clause,
            uuid_params,
            uuid_array_params,
        }
    }
}

/// Scans the actor's `org_roles` for the `organization-admin` role and
/// returns the set of org ids the actor is an admin of.
fn collect_admin_orgs(actor: &Actor) -> Vec<Uuid> {
    let mut out = Vec::new();
    for entry in &actor.org_roles {
        // org_roles is a list of "role:org_id" strings.
        if let Some((role, org_id_str)) = entry.split_once(':') {
            if role == ROLE_ORGANIZATION_ADMIN {
                if let Ok(id) = org_id_str.parse::<Uuid>() {
                    out.push(id);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ROLE_MEMBER, Scope};

    fn base_actor() -> Actor {
        Actor {
            user_id: Uuid::nil(),
            username: "alice".to_owned(),
            organization_ids: Vec::new(),
            site_roles: Vec::new(),
            org_roles: Vec::new(),
            groups: Vec::new(),
            scope: None,
            scope_override: None,
        }
    }

    #[test]
    fn site_owner_produces_true() {
        let mut actor = base_actor();
        actor.site_roles.push(ROLE_OWNER.to_owned());
        let filter = SqlFilterBuilder::new(&actor, ResourceType::Workspace, Action::Read)
            .with_org_column("organization_id")
            .with_owner_column("owner_id")
            .build();
        assert!(filter.is_allow_all());
        assert_eq!(filter.clause, "TRUE");
    }

    #[test]
    fn deny_all_helper_returns_false() {
        let f = deny_all();
        assert!(f.is_deny_all());
    }

    #[test]
    fn org_admin_for_two_orgs_produces_any_clause() {
        let org1 = Uuid::from_u128(1);
        let org2 = Uuid::from_u128(2);
        let mut actor = base_actor();
        actor
            .org_roles
            .push(format!("{ROLE_ORGANIZATION_ADMIN}:{org1}"));
        actor
            .org_roles
            .push(format!("{ROLE_ORGANIZATION_ADMIN}:{org2}"));
        let filter = SqlFilterBuilder::new(&actor, ResourceType::Template, Action::Read)
            .with_org_column("organization_id")
            .build();
        assert_eq!(filter.clause, "organization_id = ANY({uuid_array$1})");
        assert_eq!(filter.uuid_array_params, vec![vec![org1, org2]]);
        // Rebind check.
        let (rewritten, consumed) = rebind(&filter, 5);
        assert_eq!(rewritten, "organization_id = ANY($5)");
        assert_eq!(consumed, 1);
    }

    #[test]
    fn regular_user_workspace_read_produces_owner_filter() {
        let user_id = Uuid::from_u128(42);
        let mut actor = base_actor();
        actor.user_id = user_id;
        actor.site_roles.push(ROLE_MEMBER.to_owned());
        let filter = SqlFilterBuilder::new(&actor, ResourceType::Workspace, Action::Read)
            .with_org_column("organization_id")
            .with_owner_column("owner_id")
            .build();
        assert_eq!(filter.clause, "owner_id = {uuid$1}");
        assert_eq!(filter.uuid_params, vec![user_id]);
    }

    #[test]
    fn workspace_agent_scope_pins_id() {
        let workspace_id = Uuid::from_u128(7);
        let template_id = Uuid::from_u128(8);
        let owner_id = Uuid::from_u128(9);
        let mut actor = base_actor();
        actor.scope_override = Some(Scope::scope_workspace_agent(
            workspace_id,
            template_id,
            owner_id,
            false,
        ));
        let filter = SqlFilterBuilder::new(&actor, ResourceType::Workspace, Action::Read)
            .with_id_column("id")
            .build();
        assert_eq!(filter.clause, "id = {uuid$1}");
        assert_eq!(filter.uuid_params, vec![workspace_id]);
    }

    #[test]
    fn deny_produces_false() {
        // No site roles, no org roles, no scope → nothing covers it.
        let actor = base_actor();
        let filter = SqlFilterBuilder::new(&actor, ResourceType::AuditLog, Action::Read)
            .with_org_column("organization_id")
            .build();
        assert!(filter.is_deny_all());
        assert_eq!(filter.clause, "FALSE");
    }

    #[test]
    fn template_member_sees_org_templates() {
        let org1 = Uuid::from_u128(1);
        let org2 = Uuid::from_u128(2);
        let mut actor = base_actor();
        actor.site_roles.push(ROLE_MEMBER.to_owned());
        actor.organization_ids = vec![org1, org2];
        let filter = SqlFilterBuilder::new(&actor, ResourceType::Template, Action::Read)
            .with_org_column("organization_id")
            .build();
        assert_eq!(filter.clause, "organization_id = ANY({uuid_array$1})");
        assert_eq!(filter.uuid_array_params, vec![vec![org1, org2]]);
    }

    #[test]
    fn auditor_sees_all_audit_logs() {
        let mut actor = base_actor();
        actor.site_roles.push(crate::ROLE_AUDITOR.to_owned());
        let filter = SqlFilterBuilder::new(&actor, ResourceType::AuditLog, Action::Read)
            .with_org_column("organization_id")
            .build();
        assert!(filter.is_allow_all());
    }

    #[test]
    fn rebind_with_uuid_and_uuid_array_params() {
        // Build a synthetic filter with both param kinds to exercise rebinding.
        let f = SqlFilter {
            clause: "(owner_id = {uuid$1} OR organization_id = ANY({uuid_array$1}))".to_owned(),
            uuid_params: vec![Uuid::nil()],
            uuid_array_params: vec![vec![Uuid::nil()]],
        };
        let (rewritten, consumed) = rebind(&f, 10);
        assert_eq!(rewritten, "(owner_id = $10 OR organization_id = ANY($11))");
        assert_eq!(consumed, 2);
    }
}
