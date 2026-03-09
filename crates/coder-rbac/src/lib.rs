//! RBAC boundary for the Rust `coderd` rewrite.
#![forbid(unsafe_code)]

use serde::Serialize;
use uuid::Uuid;

/// Site-wide owner role.
pub const ROLE_OWNER: &str = "owner";
/// Site-wide template admin role.
pub const ROLE_TEMPLATE_ADMIN: &str = "template-admin";
/// Site-wide user admin role.
pub const ROLE_USER_ADMIN: &str = "user-admin";
/// Site-wide auditor role.
pub const ROLE_AUDITOR: &str = "auditor";
/// Organization admin role.
pub const ROLE_ORGANIZATION_ADMIN: &str = "organization-admin";
/// Organization auditor role.
pub const ROLE_ORGANIZATION_AUDITOR: &str = "organization-auditor";
/// Organization user admin role.
pub const ROLE_ORGANIZATION_USER_ADMIN: &str = "organization-user-admin";
/// Organization template admin role.
pub const ROLE_ORGANIZATION_TEMPLATE_ADMIN: &str = "organization-template-admin";

/// Request actor used by the current HTTP layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Actor {
    /// Stable user identifier.
    pub user_id: Uuid,
    /// Login username for diagnostics and audit logs.
    pub username: String,
    /// Organization memberships visible to the actor.
    pub organization_ids: Vec<Uuid>,
    /// Site-wide RBAC roles for the actor.
    pub site_roles: Vec<String>,
}

impl Actor {
    /// Returns whether the actor has the given site-wide role.
    #[must_use]
    pub fn has_site_role(&self, role_name: &str) -> bool {
        self.site_roles
            .iter()
            .any(|role| role.eq_ignore_ascii_case(role_name))
    }

    /// Returns whether the actor has the site owner role.
    #[must_use]
    pub fn is_owner(&self) -> bool {
        self.has_site_role(ROLE_OWNER)
    }

    /// Returns whether the actor can read or modify the target user directly.
    #[must_use]
    pub fn can_access_user(&self, target_user_id: Uuid) -> bool {
        self.is_owner() || self.user_id == target_user_id
    }

    /// Returns whether the actor can view the global user listing.
    #[must_use]
    pub fn can_list_users(&self) -> bool {
        self.is_owner()
    }

    /// Returns whether the actor can access the organization.
    #[must_use]
    pub fn can_access_organization(&self, organization_id: Uuid) -> bool {
        self.is_owner() || self.organization_ids.contains(&organization_id)
    }

    /// Returns whether the actor can manage organization membership.
    #[must_use]
    pub fn can_manage_organization(&self, organization_id: Uuid) -> bool {
        let _ = organization_id;
        self.is_owner()
    }
}

/// Built-in role metadata used by the current role-listing routes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuiltinRole {
    /// Canonical role name.
    pub name: &'static str,
    /// Human-readable label.
    pub display_name: &'static str,
}

/// Returns built-in site roles surfaced by the current Rust slice.
#[must_use]
pub fn site_builtin_roles() -> &'static [BuiltinRole] {
    &[
        BuiltinRole {
            name: ROLE_OWNER,
            display_name: "Owner",
        },
        BuiltinRole {
            name: ROLE_TEMPLATE_ADMIN,
            display_name: "Template Admin",
        },
        BuiltinRole {
            name: ROLE_USER_ADMIN,
            display_name: "User Admin",
        },
        BuiltinRole {
            name: ROLE_AUDITOR,
            display_name: "Auditor",
        },
    ]
}

/// Returns built-in organization roles surfaced by the current Rust slice.
#[must_use]
pub fn organization_builtin_roles() -> &'static [BuiltinRole] {
    &[
        BuiltinRole {
            name: ROLE_ORGANIZATION_ADMIN,
            display_name: "Organization Admin",
        },
        BuiltinRole {
            name: ROLE_ORGANIZATION_AUDITOR,
            display_name: "Organization Auditor",
        },
        BuiltinRole {
            name: ROLE_ORGANIZATION_USER_ADMIN,
            display_name: "Organization User Admin",
        },
        BuiltinRole {
            name: ROLE_ORGANIZATION_TEMPLATE_ADMIN,
            display_name: "Organization Template Admin",
        },
    ]
}

/// Normalized resource kinds used by the first Rust authorization layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    /// A deployment-scoped authentication surface.
    Authentication,
    /// A site user.
    User,
    /// A site organization.
    Organization,
    /// An organization member.
    OrganizationMember,
    /// A session or token API key.
    ApiKey,
    /// A Git SSH keypair.
    GitSshKey,
    /// Deployment health settings.
    HealthSettings,
    /// An external-auth link.
    ExternalAuth,
    /// An OAuth2 provider application.
    OAuth2ProviderApp,
    /// An OAuth2 provider application secret.
    OAuth2ProviderAppSecret,
    /// A user group.
    Group,
    /// A custom role.
    CustomRole,
}
