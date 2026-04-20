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
/// Role name constant for the autostart daemon subject, mirroring Go's
/// `RoleIdentifier{Name: "autostart"}`.
pub const ROLE_AUTOSTART: &str = "autostart";
/// Role name constant for the connection logger subject, mirroring Go's
/// `RoleIdentifier{Name: "connectionlogger"}`.
pub const ROLE_CONNECTION_LOGGER: &str = "connectionlogger";
/// Role name constant for the job reaper subject, mirroring Go's
/// `RoleIdentifier{Name: "jobreaper"}`.
pub const ROLE_JOB_REAPER: &str = "jobreaper";

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

fn autostart_permissions() -> Vec<Permission> {
    let mut p: Vec<Permission> = vec![
        Permission::allow(ResourceType::OrganizationMember, Action::Read),
        // Required to read terraform files during transitions.
        Permission::allow(ResourceType::File, Action::Read),
        Permission::allow(ResourceType::NotificationMessage, Action::Create),
        Permission::allow(ResourceType::NotificationMessage, Action::Read),
        Permission::allow_all(ResourceType::System),
        Permission::allow(ResourceType::User, Action::Read),
    ];
    for action in [Action::Read, Action::Update] {
        p.push(Permission::allow(ResourceType::Task, action));
    }
    for action in [Action::Read, Action::Update] {
        p.push(Permission::allow(ResourceType::Template, action));
    }
    for action in [
        Action::Delete,
        Action::Read,
        Action::Update,
        Action::Start,
        Action::Stop,
    ] {
        p.push(Permission::allow(ResourceType::Workspace, action));
    }
    p
}

fn connection_logger_permissions() -> Vec<Permission> {
    vec![
        Permission::allow(ResourceType::ConnectionLog, Action::Update),
        Permission::allow(ResourceType::ConnectionLog, Action::Read),
    ]
}

fn job_reaper_permissions() -> Vec<Permission> {
    vec![
        Permission::allow_all(ResourceType::System),
        Permission::allow(ResourceType::Template, Action::Read),
        Permission::allow(ResourceType::Template, Action::Update),
        Permission::allow(ResourceType::Workspace, Action::Read),
        Permission::allow(ResourceType::Workspace, Action::Update),
        Permission::allow(ResourceType::ProvisionerJobs, Action::Read),
        Permission::allow(ResourceType::ProvisionerJobs, Action::Update),
    ]
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

/// Autostart daemon `Role`. See [`autostart`].
#[must_use]
pub fn role_autostart() -> Role {
    make_role(ROLE_AUTOSTART, "Autostart Daemon", autostart_permissions())
}

/// Connection logger `Role`. See [`connection_logger`].
#[must_use]
pub fn role_connection_logger() -> Role {
    make_role(
        ROLE_CONNECTION_LOGGER,
        "Connection Logger",
        connection_logger_permissions(),
    )
}

/// Job-reaper daemon `Role`. See [`job_reaper`].
#[must_use]
pub fn role_job_reaper() -> Role {
    make_role(
        ROLE_JOB_REAPER,
        "Job Reaper Daemon",
        job_reaper_permissions(),
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

/// Actor for the autostart daemon. Mirrors Go's `AsAutostart` helper and
/// `subjectAutostart` subject in `dbauthz/dbauthz.go`.
///
/// Used by the autobuild executor to transition workspaces on a schedule
/// (autostart / autostop / deadline / dormancy).
#[must_use]
pub fn autostart() -> Actor {
    system_actor(
        "autostart",
        ROLE_AUTOSTART,
        "Autostart Daemon",
        autostart_permissions(),
    )
}

/// Actor for the connection logger. Mirrors Go's `AsConnectionLogger`
/// helper and `subjectConnectionLogger` subject in `dbauthz/dbauthz.go`.
///
/// Used by the connection-log pruner to read and delete stale rows in
/// the `connection_logs` table. Task-level description calls this the
/// "auditor" actor because it is the audit-adjacent subject that owns
/// connection log retention.
#[must_use]
pub fn connection_logger() -> Actor {
    system_actor(
        "connectionlogger",
        ROLE_CONNECTION_LOGGER,
        "Connection Logger",
        connection_logger_permissions(),
    )
}

/// Actor for the job reaper. Mirrors Go's `AsJobReaper` helper and
/// `subjectJobReaper` subject in `dbauthz/dbauthz.go`.
///
/// Used by the background process that reaps stuck provisioner jobs
/// and workspace builds.
#[must_use]
pub fn job_reaper() -> Actor {
    system_actor(
        "jobreaper",
        ROLE_JOB_REAPER,
        "Job Reaper Daemon",
        job_reaper_permissions(),
    )
}

/// Returns whether the supplied actor carries one of the synthetic
/// system-subject roles defined in this module (`system`, `keyrotator`,
/// `provisionerd`, `notifier`, `resourcemonitor`, `autostart`,
/// `connectionlogger`, `jobreaper`).
///
/// Used by background-worker unit tests to assert their construction
/// path wired the correct system actor in place of the default actor.
#[must_use]
pub fn is_system(actor: &Actor) -> bool {
    actor.site_roles.iter().any(|role| {
        matches!(
            role.as_str(),
            ROLE_SYSTEM_RESTRICTED
                | ROLE_KEY_ROTATOR
                | ROLE_PROVISIONERD
                | ROLE_NOTIFIER
                | ROLE_RESOURCE_MONITOR
                | ROLE_AUTOSTART
                | ROLE_CONNECTION_LOGGER
                | ROLE_JOB_REAPER
        )
    })
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

/// Actor for the nil-UUID owner, used by bootstrap and migration code
/// that must elevate to the full owner role without a specific user
/// context. Prefer [`owner_of`] when a user id is known.
#[must_use]
pub fn owner() -> Actor {
    owner_of(Uuid::nil())
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
    fn is_system_matches_all_synthetic_actors() {
        assert!(is_system(&system_restricted()));
        assert!(is_system(&key_rotator()));
        assert!(is_system(&provisionerd()));
        assert!(is_system(&notifier()));
        assert!(is_system(&resource_monitor()));
        assert!(is_system(&autostart()));
        assert!(is_system(&connection_logger()));
        assert!(is_system(&job_reaper()));
        // owner_of uses ROLE_OWNER, not a synthetic system role.
        assert!(!is_system(&owner_of(Uuid::nil())));
        assert!(!is_system(&owner()));
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

    #[test]
    fn owner_uses_nil_user_id() {
        let actor = owner();
        assert_eq!(actor.user_id, Uuid::nil());
        assert!(actor.site_roles.iter().any(|r| r == crate::ROLE_OWNER));
    }

    #[test]
    fn autostart_can_read_and_update_workspaces() {
        let authorizer = Authorizer::new();
        let actor = autostart();
        let ws = Object::new(ResourceType::Workspace);
        for action in [
            Action::Read,
            Action::Update,
            Action::Start,
            Action::Stop,
            Action::Delete,
        ] {
            assert!(
                authorizer.authorize(&actor, action, &ws).is_ok(),
                "autostart must be allowed to {action:?} workspaces",
            );
        }
        // Autostart cannot create workspaces — that is a user action.
        assert!(authorizer.authorize(&actor, Action::Create, &ws).is_err());
        // Autostart cannot CRUD users.
        let user = Object::new(ResourceType::User);
        assert!(authorizer.authorize(&actor, Action::Create, &user).is_err());
    }

    #[test]
    fn autostart_can_read_templates_and_files() {
        let authorizer = Authorizer::new();
        let actor = autostart();
        let template = Object::new(ResourceType::Template);
        assert!(
            authorizer
                .authorize(&actor, Action::Read, &template)
                .is_ok()
        );
        assert!(
            authorizer
                .authorize(&actor, Action::Update, &template)
                .is_ok()
        );
        let file = Object::new(ResourceType::File);
        assert!(authorizer.authorize(&actor, Action::Read, &file).is_ok());
        assert!(authorizer.authorize(&actor, Action::Create, &file).is_err());
    }

    #[test]
    fn connection_logger_can_only_manage_connection_logs() {
        let authorizer = Authorizer::new();
        let actor = connection_logger();
        let log = Object::new(ResourceType::ConnectionLog);
        for action in [Action::Read, Action::Update] {
            assert!(
                authorizer.authorize(&actor, action, &log).is_ok(),
                "connection_logger must be allowed to {action:?} connection logs",
            );
        }
        // Connection-logger cannot create/delete connection log rows through
        // this scope — only update/read. The pruner deletes via the
        // `Action::Update`-gated `delete_old_connection_logs` path in the
        // dbauthz wrap (mirrors Go's connection_logger subject).
        assert!(authorizer.authorize(&actor, Action::Create, &log).is_err());
        // And it cannot read users or workspaces.
        let user = Object::new(ResourceType::User);
        assert!(authorizer.authorize(&actor, Action::Read, &user).is_err());
    }

    #[test]
    fn job_reaper_can_update_jobs_and_workspaces() {
        let authorizer = Authorizer::new();
        let actor = job_reaper();
        let job = Object::new(ResourceType::ProvisionerJobs);
        assert!(authorizer.authorize(&actor, Action::Read, &job).is_ok());
        assert!(authorizer.authorize(&actor, Action::Update, &job).is_ok());
        let ws = Object::new(ResourceType::Workspace);
        assert!(authorizer.authorize(&actor, Action::Update, &ws).is_ok());
        // Job reaper cannot start or stop workspaces — it only marks
        // stuck jobs failed. Mirrors Go's `subjectJobReaper` site map.
        assert!(authorizer.authorize(&actor, Action::Start, &ws).is_err());
        // Job reaper cannot read users.
        let user = Object::new(ResourceType::User);
        assert!(authorizer.authorize(&actor, Action::Read, &user).is_err());
    }
}
