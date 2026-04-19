//! System actor contexts used by background workers.
//!
//! Mirrors Go's `AsSystemRestricted` / `AsKeyRotator` / `AsProvisionerd` /
//! `AsNotifier` / `AsResourceMonitor` / `AsOwner` helpers in
//! `coder/coderd/database/dbauthz/dbauthz.go` (see `subjectSystemRestricted`,
//! `subjectCryptoKeyRotator`, `subjectProvisionerd`, `subjectNotifier`,
//! `subjectResourceMonitor`).
//!
//! Each public helper returns an [`Actor`] whose `site_roles` contains a
//! single synthetic role (e.g. `"system"`, `"keyrotator"`). Those role
//! names are recognised by [`crate::expand_role`] and resolve to a
//! `Role` with the minimum site-level permission set the worker needs.
//! The same permission set is also duplicated in the actor's
//! `scope_override`, so that both the scope check *and* the role check
//! in [`crate::Authorizer::authorize`] succeed for the same action set.

use uuid::Uuid;

use crate::{Action, Actor, Permission, ResourceType, Role, Scope, WILDCARD};
use std::collections::HashMap;

/// Role name constant for the system-restricted subject, mirroring Go's
/// `RoleIdentifier{Name: "system"}`.
pub const ROLE_SYSTEM_RESTRICTED: &str = "system";
/// Role name constant for the crypto-key rotator subject, mirroring Go's
/// `RoleIdentifier{Name: "keyrotator"}`.
pub const ROLE_KEY_ROTATOR: &str = "keyrotator";
/// Role name constant for the provisioner daemon subject, mirroring Go's
/// `RoleIdentifier{Name: "provisionerd"}`.
pub const ROLE_PROVISIONERD: &str = "provisionerd";
/// Role name constant for the notifier subject, mirroring Go's
/// `RoleIdentifier{Name: "notifier"}`.
pub const ROLE_NOTIFIER: &str = "notifier";
/// Role name constant for the resource monitor subject, mirroring Go's
/// `RoleIdentifier{Name: "resourcemonitor"}`.
pub const ROLE_RESOURCE_MONITOR: &str = "resourcemonitor";

/// Build a [`Role`] with the given site permissions and no user/org-scoped
/// permissions. Used by the system-actor builders below and by
/// `expand_role` in `lib.rs`.
fn make_role(name: &str, display: &str, site: Vec<Permission>) -> Role {
    Role {
        name: name.to_owned(),
        org_id: None,
        display_name: display.to_owned(),
        site,
        user: Vec::new(),
        by_org_id: HashMap::new(),
    }
}

// ---------------------------------------------------------------------------
// Permission builders. Each returns the site-level permission set for one
// system subject, mirroring the corresponding Go `subjectX.Roles[0].Site`
// map. Keeping these in private helpers lets the role-builder and the
// actor-builder share the same source of truth.
// ---------------------------------------------------------------------------

fn system_restricted_permissions() -> Vec<Permission> {
    let mut p: Vec<Permission> = vec![
        // Wildcard resource -> Read.
        Permission::allow(ResourceType::Wildcard, Action::Read),
        // System resource -> wildcard (all actions).
        Permission::allow_all(ResourceType::System),
        // ApiKey -> all actions.
        Permission::allow_all(ResourceType::ApiKey),
        // Group -> create, update.
        Permission::allow(ResourceType::Group, Action::Create),
        Permission::allow(ResourceType::Group, Action::Update),
        // AssignRole / AssignOrgRole -> all actions.
        Permission::allow_all(ResourceType::AssignRole),
        Permission::allow_all(ResourceType::AssignOrgRole),
        // Organization -> create, read.
        Permission::allow(ResourceType::Organization, Action::Create),
        Permission::allow(ResourceType::Organization, Action::Read),
        // OrganizationMember -> create, delete, read.
        Permission::allow(ResourceType::OrganizationMember, Action::Create),
        Permission::allow(ResourceType::OrganizationMember, Action::Delete),
        Permission::allow(ResourceType::OrganizationMember, Action::Read),
        // ProvisionerDaemon -> create, read, update.
        Permission::allow(ResourceType::ProvisionerDaemon, Action::Create),
        Permission::allow(ResourceType::ProvisionerDaemon, Action::Read),
        Permission::allow(ResourceType::ProvisionerDaemon, Action::Update),
        // User -> all actions.
        Permission::allow_all(ResourceType::User),
    ];
    // Workspace -> update, delete, start, stop, ssh, create_agent, delete_agent, update_agent.
    for action in [
        Action::Update,
        Action::Delete,
        Action::Start,
        Action::Stop,
        Action::Ssh,
        Action::CreateAgent,
        Action::DeleteAgent,
        Action::UpdateAgent,
    ] {
        p.push(Permission::allow(ResourceType::Workspace, action));
    }
    // DeploymentConfig -> create, update, delete.
    p.push(Permission::allow(
        ResourceType::DeploymentConfig,
        Action::Create,
    ));
    p.push(Permission::allow(
        ResourceType::DeploymentConfig,
        Action::Update,
    ));
    p.push(Permission::allow(
        ResourceType::DeploymentConfig,
        Action::Delete,
    ));
    // NotificationMessage -> all actions.
    p.push(Permission::allow_all(ResourceType::NotificationMessage));
    // NotificationPreference -> create, update, delete.
    for action in [Action::Create, Action::Update, Action::Delete] {
        p.push(Permission::allow(
            ResourceType::NotificationPreference,
            action,
        ));
    }
    // NotificationTemplate -> create, update, delete.
    for action in [Action::Create, Action::Update, Action::Delete] {
        p.push(Permission::allow(
            ResourceType::NotificationTemplate,
            action,
        ));
    }
    // CryptoKey -> create, update, delete (plus read via wildcard).
    for action in [Action::Create, Action::Update, Action::Delete] {
        p.push(Permission::allow(ResourceType::CryptoKey, action));
    }
    // File -> create, read.
    p.push(Permission::allow(ResourceType::File, Action::Create));
    p.push(Permission::allow(ResourceType::File, Action::Read));
    // ProvisionerJobs -> read, update, create.
    p.push(Permission::allow(
        ResourceType::ProvisionerJobs,
        Action::Read,
    ));
    p.push(Permission::allow(
        ResourceType::ProvisionerJobs,
        Action::Update,
    ));
    p.push(Permission::allow(
        ResourceType::ProvisionerJobs,
        Action::Create,
    ));
    // ConnectionLog -> update, read (used by connection-log pruner).
    p.push(Permission::allow(
        ResourceType::ConnectionLog,
        Action::Update,
    ));
    p.push(Permission::allow(ResourceType::ConnectionLog, Action::Read));
    p
}

fn key_rotator_permissions() -> Vec<Permission> {
    vec![Permission::allow_all(ResourceType::CryptoKey)]
}

fn provisionerd_permissions() -> Vec<Permission> {
    let mut p: Vec<Permission> = Vec::new();
    for action in [Action::Read, Action::Update, Action::Create] {
        p.push(Permission::allow(ResourceType::ProvisionerJobs, action));
    }
    p.push(Permission::allow(ResourceType::File, Action::Create));
    p.push(Permission::allow(ResourceType::File, Action::Read));
    p.push(Permission::allow_all(ResourceType::System));
    p.push(Permission::allow(ResourceType::Template, Action::Read));
    p.push(Permission::allow(ResourceType::Template, Action::Update));
    p.push(Permission::allow(ResourceType::User, Action::Read));
    p.push(Permission::allow(ResourceType::User, Action::ReadPersonal));
    p.push(Permission::allow(
        ResourceType::User,
        Action::UpdatePersonal,
    ));
    for action in [
        Action::Delete,
        Action::Read,
        Action::Update,
        Action::Start,
        Action::Stop,
        Action::CreateAgent,
    ] {
        p.push(Permission::allow(ResourceType::Workspace, action));
    }
    for action in [Action::Read, Action::Update, Action::Delete] {
        p.push(Permission::allow(ResourceType::Task, action));
    }
    p.push(Permission::allow_all(ResourceType::ApiKey));
    p.push(Permission::allow(ResourceType::Organization, Action::Read));
    p.push(Permission::allow(ResourceType::Group, Action::Read));
    p.push(Permission::allow(
        ResourceType::NotificationMessage,
        Action::Create,
    ));
    p.push(Permission::allow(
        ResourceType::NotificationMessage,
        Action::Read,
    ));
    p.push(Permission::allow(ResourceType::UsageEvent, Action::Create));
    p
}

fn notifier_permissions() -> Vec<Permission> {
    vec![
        Permission::allow_all(ResourceType::NotificationMessage),
        Permission::allow(ResourceType::InboxNotification, Action::Create),
        Permission::allow_all(ResourceType::WebpushSubscription),
        Permission::allow(ResourceType::DeploymentConfig, Action::Read),
        Permission::allow(ResourceType::DeploymentConfig, Action::Update),
    ]
}

fn resource_monitor_permissions() -> Vec<Permission> {
    vec![Permission::allow(
        ResourceType::WorkspaceAgentResourceMonitor,
        Action::Update,
    )]
}

// ---------------------------------------------------------------------------
// Role constructors. Called by `expand_role` in lib.rs when it sees one of
// the synthetic role names below in an actor's `site_roles`.
// ---------------------------------------------------------------------------

/// System-restricted `Role`. See [`system_restricted`].
#[must_use]
pub fn role_system_restricted() -> Role {
    make_role(
        ROLE_SYSTEM_RESTRICTED,
        "Coder",
        system_restricted_permissions(),
    )
}

/// Crypto-key rotator `Role`. See [`key_rotator`].
#[must_use]
pub fn role_key_rotator() -> Role {
    make_role(
        ROLE_KEY_ROTATOR,
        "Crypto Key Rotator",
        key_rotator_permissions(),
    )
}

/// Provisioner daemon `Role`. See [`provisionerd`].
#[must_use]
pub fn role_provisionerd() -> Role {
    make_role(
        ROLE_PROVISIONERD,
        "Provisioner Daemon",
        provisionerd_permissions(),
    )
}

/// Notifier `Role`. See [`notifier`].
#[must_use]
pub fn role_notifier() -> Role {
    make_role(ROLE_NOTIFIER, "Notifier", notifier_permissions())
}

/// Resource-monitor `Role`. See [`resource_monitor`].
#[must_use]
pub fn role_resource_monitor() -> Role {
    make_role(
        ROLE_RESOURCE_MONITOR,
        "Resource Monitor",
        resource_monitor_permissions(),
    )
}

// ---------------------------------------------------------------------------
// Actor constructors. Each returns a ready-to-authorise `Actor` carrying
// the corresponding synthetic role and a matching `scope_override`.
// ---------------------------------------------------------------------------

fn system_actor(
    username: &'static str,
    role_name: &'static str,
    display_name: &'static str,
    permissions: Vec<Permission>,
) -> Actor {
    // Duplicate the permissions into a Scope so that the
    // scope-check in `authorize()` mirrors the role-check. Without this,
    // the default `ScopeAll` scope would be applied and silently widen
    // the actor's permissions.
    let scope = Scope {
        role: make_role(role_name, display_name, permissions),
        allow_list: vec![(WILDCARD.to_owned(), WILDCARD.to_owned())],
    };
    Actor {
        user_id: Uuid::nil(),
        username: username.to_owned(),
        organization_ids: Vec::new(),
        site_roles: vec![role_name.to_owned()],
        org_roles: Vec::new(),
        groups: Vec::new(),
        scope: None,
        scope_override: Some(scope),
    }
}

/// Actor for the system-restricted subject. Mirrors Go's
/// `subjectSystemRestricted` in `dbauthz/dbauthz.go`.
///
/// Grants a broad-but-not-unlimited permission set used by background
/// workers (replica manager, auto-build, dormancy, connection log pruner,
/// db-rollup, usage tracker, etc.). The permission set is a best-effort
/// translation of the Go subject's site map.
#[must_use]
pub fn system_restricted() -> Actor {
    system_actor(
        "system",
        ROLE_SYSTEM_RESTRICTED,
        "Coder",
        system_restricted_permissions(),
    )
}

/// Actor for the crypto-key rotator. Mirrors Go's
/// `subjectCryptoKeyRotator` in `dbauthz/dbauthz.go`.
///
/// Only authorises wildcard actions on [`ResourceType::CryptoKey`].
#[must_use]
pub fn key_rotator() -> Actor {
    system_actor(
        "keyrotator",
        ROLE_KEY_ROTATOR,
        "Crypto Key Rotator",
        key_rotator_permissions(),
    )
}

/// Actor for the provisioner daemon. Mirrors Go's `subjectProvisionerd`
/// in `dbauthz/dbauthz.go`.
#[must_use]
pub fn provisionerd() -> Actor {
    system_actor(
        "provisionerd",
        ROLE_PROVISIONERD,
        "Provisioner Daemon",
        provisionerd_permissions(),
    )
}

/// Actor for the notifier. Mirrors Go's `subjectNotifier` in
/// `dbauthz/dbauthz.go`.
#[must_use]
pub fn notifier() -> Actor {
    system_actor(
        "notifier",
        ROLE_NOTIFIER,
        "Notifier",
        notifier_permissions(),
    )
}

/// Actor for the resource monitor. Mirrors Go's `subjectResourceMonitor`
/// in `dbauthz/dbauthz.go`.
///
/// Only authorises `Update` on workspace-agent resource monitors.
#[must_use]
pub fn resource_monitor() -> Actor {
    system_actor(
        "resourcemonitor",
        ROLE_RESOURCE_MONITOR,
        "Resource Monitor",
        resource_monitor_permissions(),
    )
}

/// Actor for a specific resource owner. Mirrors Go's `AsOwner` helper.
///
/// This returns an actor carrying the supplied `user_id` and site
/// `owner` role. Unlike the machine actors above, this uses the real
/// role-expansion path (via `ROLE_OWNER`) because the intent is "act
/// as the owner" rather than "a machine with fixed permissions".
#[must_use]
pub fn owner_of(user_id: Uuid) -> Actor {
    Actor {
        user_id,
        username: format!("owner_{user_id}"),
        organization_ids: Vec::new(),
        site_roles: vec![crate::ROLE_OWNER.to_owned()],
        org_roles: Vec::new(),
        groups: Vec::new(),
        scope: None,
        scope_override: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Authorizer, Object};

    #[test]
    fn key_rotator_can_manipulate_crypto_keys() {
        let authorizer = Authorizer::new();
        let actor = key_rotator();
        let key = Object::new(ResourceType::CryptoKey);
        for action in [Action::Read, Action::Update, Action::Create, Action::Delete] {
            assert!(
                authorizer.authorize(&actor, action, &key).is_ok(),
                "key rotator must be allowed to {action:?} crypto keys",
            );
        }
    }

    #[test]
    fn key_rotator_denied_other_resources() {
        let authorizer = Authorizer::new();
        let actor = key_rotator();
        // key rotator must NOT be able to read users or templates.
        let user = Object::new(ResourceType::User);
        let template = Object::new(ResourceType::Template);
        assert!(authorizer.authorize(&actor, Action::Read, &user).is_err());
        assert!(
            authorizer
                .authorize(&actor, Action::Read, &template)
                .is_err(),
        );
    }

    #[test]
    fn resource_monitor_can_update_monitor_only() {
        let authorizer = Authorizer::new();
        let actor = resource_monitor();
        let monitor = Object::new(ResourceType::WorkspaceAgentResourceMonitor);
        assert!(
            authorizer
                .authorize(&actor, Action::Update, &monitor)
                .is_ok(),
        );
        // Other actions on monitor denied.
        assert!(
            authorizer
                .authorize(&actor, Action::Delete, &monitor)
                .is_err(),
        );
        // Other resources denied.
        let workspace = Object::new(ResourceType::Workspace);
        assert!(
            authorizer
                .authorize(&actor, Action::Read, &workspace)
                .is_err(),
        );
    }

    #[test]
    fn notifier_can_crud_notification_messages() {
        let authorizer = Authorizer::new();
        let actor = notifier();
        let msg = Object::new(ResourceType::NotificationMessage);
        for action in [Action::Create, Action::Read, Action::Update, Action::Delete] {
            assert!(
                authorizer.authorize(&actor, action, &msg).is_ok(),
                "notifier must be allowed to {action:?} notification messages",
            );
        }
        // Notifier cannot read users.
        let user = Object::new(ResourceType::User);
        assert!(authorizer.authorize(&actor, Action::Read, &user).is_err());
    }

    #[test]
    fn provisionerd_can_read_and_update_workspaces() {
        let authorizer = Authorizer::new();
        let actor = provisionerd();
        let ws = Object::new(ResourceType::Workspace);
        assert!(authorizer.authorize(&actor, Action::Read, &ws).is_ok());
        assert!(authorizer.authorize(&actor, Action::Update, &ws).is_ok());
        assert!(authorizer.authorize(&actor, Action::Start, &ws).is_ok());
        // Provisionerd cannot create users.
        let user = Object::new(ResourceType::User);
        assert!(authorizer.authorize(&actor, Action::Create, &user).is_err(),);
    }

    #[test]
    fn system_restricted_can_manage_crypto_keys() {
        let authorizer = Authorizer::new();
        let actor = system_restricted();
        let key = Object::new(ResourceType::CryptoKey);
        // system-restricted has CryptoKey create/update/delete and
        // wildcard resource:read, so it can CRUD crypto keys.
        for action in [Action::Read, Action::Create, Action::Update, Action::Delete] {
            assert!(
                authorizer.authorize(&actor, action, &key).is_ok(),
                "system_restricted must be allowed to {action:?} crypto keys",
            );
        }
    }

    #[test]
    fn system_restricted_denied_unlisted_workspace_actions() {
        let authorizer = Authorizer::new();
        let actor = system_restricted();
        // system-restricted does NOT list Workspace:create in its Go site
        // map, so creating a workspace must be denied.
        let ws = Object::new(ResourceType::Workspace);
        assert!(authorizer.authorize(&actor, Action::Create, &ws).is_err());
    }

    #[test]
    fn owner_of_accesses_own_user_resource() {
        let authorizer = Authorizer::new();
        let user_id = Uuid::nil();
        let actor = owner_of(user_id);
        // The actor holds ROLE_OWNER, which grants read on User.
        let user = Object::new(ResourceType::User).with_id(user_id);
        assert!(authorizer.authorize(&actor, Action::Read, &user).is_ok());
    }
}
