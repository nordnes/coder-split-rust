//! RBAC boundary for the Rust `coderd` rewrite.
//!
//! This crate implements a full policy evaluation engine that supports
//! per-resource permissions, scopes, and organization-scoped roles.
//! It mirrors the Go implementation in `coderd/rbac/`.
//!
//! # Key types
//!
//! * [`Actor`] — represents an authenticated principal with site roles,
//!   org memberships, and an optional [`Scope`]
//! * [`Authorizer`] — stateless evaluator: `authorize(actor, action, object)`
//! * [`Object`] — the resource (or resource pattern) being checked
//! * [`Permission`] — a single allow / deny rule in a [`Role`]
//! * [`Role`] — named bundle of site, user, and org-scoped permissions
//! * [`Scope`] — API-key restriction layer on top of the user's roles
//!
//! Built-in roles ([`ROLE_OWNER`], [`ROLE_MEMBER`], [`ROLE_AUDITOR`], …) are
//! constructed by the `role_*` helper functions and registered in
//! [`site_builtin_roles`] / [`organization_builtin_roles`].
#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Action enum
// ---------------------------------------------------------------------------

/// All RBAC actions that can be performed on a resource.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Create a new resource.
    Create,
    /// Read resource data.
    Read,
    /// Update an existing resource.
    Update,
    /// Delete a resource.
    Delete,
    /// Use a resource (e.g. use a template to create a workspace).
    Use,
    /// SSH into a workspace.
    #[serde(rename = "ssh")]
    Ssh,
    /// Connect to workspace apps via browser.
    ApplicationConnect,
    /// View insights for a resource.
    ViewInsights,
    /// Start a workspace.
    Start,
    /// Stop a workspace.
    Stop,
    /// Assign a role.
    Assign,
    /// Unassign a role.
    Unassign,
    /// Read personal user data (settings, auth links).
    ReadPersonal,
    /// Update personal data.
    UpdatePersonal,
    /// Create a workspace agent.
    CreateAgent,
    /// Delete a workspace agent.
    DeleteAgent,
    /// Update a workspace agent.
    UpdateAgent,
    /// Share a workspace with other users or groups.
    Share,
}

/// The wildcard action string used in permission definitions.
pub const WILDCARD: &str = "*";

impl Action {
    /// Returns the canonical wire-format string for this action.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Read => "read",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::Use => "use",
            Self::Ssh => "ssh",
            Self::ApplicationConnect => "application_connect",
            Self::ViewInsights => "view_insights",
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Assign => "assign",
            Self::Unassign => "unassign",
            Self::ReadPersonal => "read_personal",
            Self::UpdatePersonal => "update_personal",
            Self::CreateAgent => "create_agent",
            Self::DeleteAgent => "delete_agent",
            Self::UpdateAgent => "update_agent",
            Self::Share => "share",
        }
    }
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ResourceType (string-based, matching Go)
// ---------------------------------------------------------------------------

/// Normalized resource types used by the RBAC system.
/// These match the Go `object_gen.go` type strings exactly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceType {
    /// Wildcard matches any resource type.
    #[serde(rename = "*")]
    Wildcard,
    /// AI bridge interception records.
    AibridgeInterception,
    /// API key or session token.
    ApiKey,
    /// Organization role assignment.
    AssignOrgRole,
    /// Site role assignment.
    AssignRole,
    /// Audit log entries.
    AuditLog,
    /// Boundary usage statistics.
    BoundaryUsage,
    /// Chat messages and metadata.
    Chat,
    /// Connection log entries.
    ConnectionLog,
    /// Crypto keys.
    CryptoKey,
    /// Debug info routes.
    DebugInfo,
    /// Deployment configuration.
    DeploymentConfig,
    /// Deployment statistics.
    DeploymentStats,
    /// File resources.
    File,
    /// Groups.
    Group,
    /// Group members.
    GroupMember,
    /// `IdP` sync settings.
    IdpsyncSettings,
    /// Inbox notifications.
    InboxNotification,
    /// Licenses.
    License,
    /// Notification messages.
    NotificationMessage,
    /// Notification preferences.
    NotificationPreference,
    /// Notification templates.
    NotificationTemplate,
    /// `OAuth2` applications.
    Oauth2App,
    /// `OAuth2` app code tokens.
    Oauth2AppCodeToken,
    /// `OAuth2` app secrets.
    Oauth2AppSecret,
    /// Organizations.
    Organization,
    /// Organization members.
    OrganizationMember,
    /// Prebuilt workspaces.
    PrebuiltWorkspace,
    /// Provisioner daemons.
    ProvisionerDaemon,
    /// Provisioner jobs.
    ProvisionerJobs,
    /// Replicas.
    Replicas,
    /// System resources (deprecated).
    System,
    /// Tailnet coordinator.
    TailnetCoordinator,
    /// Tasks.
    Task,
    /// Templates.
    Template,
    /// Usage events.
    UsageEvent,
    /// Users.
    User,
    /// User secrets.
    UserSecret,
    /// Web push subscriptions.
    WebpushSubscription,
    /// Workspaces.
    Workspace,
    /// Workspace agent devcontainers.
    WorkspaceAgentDevcontainers,
    /// Workspace agent resource monitors.
    WorkspaceAgentResourceMonitor,
    /// Dormant workspaces.
    WorkspaceDormant,
    /// Workspace proxies.
    WorkspaceProxy,
}

impl ResourceType {
    /// Returns the canonical wire-format string for this resource type.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Wildcard => "*",
            Self::AibridgeInterception => "aibridge_interception",
            Self::ApiKey => "api_key",
            Self::AssignOrgRole => "assign_org_role",
            Self::AssignRole => "assign_role",
            Self::AuditLog => "audit_log",
            Self::BoundaryUsage => "boundary_usage",
            Self::Chat => "chat",
            Self::ConnectionLog => "connection_log",
            Self::CryptoKey => "crypto_key",
            Self::DebugInfo => "debug_info",
            Self::DeploymentConfig => "deployment_config",
            Self::DeploymentStats => "deployment_stats",
            Self::File => "file",
            Self::Group => "group",
            Self::GroupMember => "group_member",
            Self::IdpsyncSettings => "idpsync_settings",
            Self::InboxNotification => "inbox_notification",
            Self::License => "license",
            Self::NotificationMessage => "notification_message",
            Self::NotificationPreference => "notification_preference",
            Self::NotificationTemplate => "notification_template",
            Self::Oauth2App => "oauth2_app",
            Self::Oauth2AppCodeToken => "oauth2_app_code_token",
            Self::Oauth2AppSecret => "oauth2_app_secret",
            Self::Organization => "organization",
            Self::OrganizationMember => "organization_member",
            Self::PrebuiltWorkspace => "prebuilt_workspace",
            Self::ProvisionerDaemon => "provisioner_daemon",
            Self::ProvisionerJobs => "provisioner_jobs",
            Self::Replicas => "replicas",
            Self::System => "system",
            Self::TailnetCoordinator => "tailnet_coordinator",
            Self::Task => "task",
            Self::Template => "template",
            Self::UsageEvent => "usage_event",
            Self::User => "user",
            Self::UserSecret => "user_secret",
            Self::WebpushSubscription => "webpush_subscription",
            Self::Workspace => "workspace",
            Self::WorkspaceAgentDevcontainers => "workspace_agent_devcontainers",
            Self::WorkspaceAgentResourceMonitor => "workspace_agent_resource_monitor",
            Self::WorkspaceDormant => "workspace_dormant",
            Self::WorkspaceProxy => "workspace_proxy",
        }
    }

    /// Parse a resource type string into a `ResourceType`.
    #[must_use]
    pub fn from_str_opt(s: &str) -> Option<Self> {
        if s == "*" {
            return Some(Self::Wildcard);
        }
        ALL_RESOURCE_TYPES
            .iter()
            .find(|rt| rt.as_str() == s)
            .copied()
    }
}

impl std::fmt::Display for ResourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// All resource types (excluding Wildcard).
pub const ALL_RESOURCE_TYPES: &[ResourceType] = &[
    ResourceType::AibridgeInterception,
    ResourceType::ApiKey,
    ResourceType::AssignOrgRole,
    ResourceType::AssignRole,
    ResourceType::AuditLog,
    ResourceType::BoundaryUsage,
    ResourceType::Chat,
    ResourceType::ConnectionLog,
    ResourceType::CryptoKey,
    ResourceType::DebugInfo,
    ResourceType::DeploymentConfig,
    ResourceType::DeploymentStats,
    ResourceType::File,
    ResourceType::Group,
    ResourceType::GroupMember,
    ResourceType::IdpsyncSettings,
    ResourceType::InboxNotification,
    ResourceType::License,
    ResourceType::NotificationMessage,
    ResourceType::NotificationPreference,
    ResourceType::NotificationTemplate,
    ResourceType::Oauth2App,
    ResourceType::Oauth2AppCodeToken,
    ResourceType::Oauth2AppSecret,
    ResourceType::Organization,
    ResourceType::OrganizationMember,
    ResourceType::PrebuiltWorkspace,
    ResourceType::ProvisionerDaemon,
    ResourceType::ProvisionerJobs,
    ResourceType::Replicas,
    ResourceType::System,
    ResourceType::TailnetCoordinator,
    ResourceType::Task,
    ResourceType::Template,
    ResourceType::UsageEvent,
    ResourceType::User,
    ResourceType::UserSecret,
    ResourceType::WebpushSubscription,
    ResourceType::Workspace,
    ResourceType::WorkspaceAgentDevcontainers,
    ResourceType::WorkspaceAgentResourceMonitor,
    ResourceType::WorkspaceDormant,
    ResourceType::WorkspaceProxy,
];

// ---------------------------------------------------------------------------
// ResourceKind – used by audit / handler code
// ---------------------------------------------------------------------------

/// Normalized resource kinds used by the Rust authorization and audit layers.
///
/// Covers all variants from the `PostgreSQL` `resource_type` enum plus
/// Rust-only variants (`Authentication`, `ExternalAuth`) that are used in
/// the authorization layer but do not appear in the database enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    /// A deployment-scoped authentication surface (Rust-only).
    Authentication,
    /// An external-auth link (Rust-only).
    ExternalAuth,
    /// A site organization.
    Organization,
    /// A template.
    Template,
    /// A template version.
    TemplateVersion,
    /// A site user.
    User,
    /// A workspace.
    Workspace,
    /// A Git SSH keypair.
    GitSshKey,
    /// A session or token API key.
    ApiKey,
    /// A group.
    Group,
    /// A workspace build.
    WorkspaceBuild,
    /// A license.
    License,
    /// A workspace proxy.
    WorkspaceProxy,
    /// A login conversion event.
    ConvertLogin,
    /// Deployment health settings.
    HealthSettings,
    /// An `OAuth2` provider application.
    Oauth2ProviderApp,
    /// An `OAuth2` provider application secret.
    Oauth2ProviderAppSecret,
    /// An `OAuth2` provider application token.
    Oauth2ProviderAppToken,
    /// A custom role.
    CustomRole,
    /// An organization member.
    OrganizationMember,
    /// Notifications settings.
    NotificationsSettings,
    /// A notification template.
    NotificationTemplate,
    /// IDP sync settings for an organization.
    IdpSyncSettingsOrganization,
    /// IDP sync settings for a group.
    IdpSyncSettingsGroup,
    /// IDP sync settings for a role.
    IdpSyncSettingsRole,
    /// A workspace agent.
    WorkspaceAgent,
    /// A workspace application.
    WorkspaceApp,
    /// Appearance configuration.
    AppearanceConfig,
    /// Prebuilds settings.
    PrebuildsSettings,
    /// A task.
    Task,
}

// ---------------------------------------------------------------------------
// Object
// ---------------------------------------------------------------------------

/// An RBAC object represents a resource (or set of resources) being checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Object {
    /// The resource type of this object.
    pub resource_type: ResourceType,
    /// Optional owner user ID.
    pub owner_id: Option<Uuid>,
    /// Optional organization ID.
    pub org_id: Option<Uuid>,
    /// Optional resource ID.
    pub id: Option<Uuid>,
    /// Whether this matches any org (disregards `org_id`).
    pub any_org: bool,
    /// Per-user ACL: `user_id` -> list of allowed actions.
    pub acl_user_list: HashMap<String, Vec<Action>>,
    /// Per-group ACL: `group_id` -> list of allowed actions.
    pub acl_group_list: HashMap<String, Vec<Action>>,
}

impl Object {
    /// Creates a new object for the given resource type.
    #[must_use]
    pub fn new(resource_type: ResourceType) -> Self {
        Self {
            resource_type,
            owner_id: None,
            org_id: None,
            id: None,
            any_org: false,
            acl_user_list: HashMap::new(),
            acl_group_list: HashMap::new(),
        }
    }

    /// Sets the owner ID.
    #[must_use]
    pub fn with_owner(mut self, owner_id: Uuid) -> Self {
        self.owner_id = Some(owner_id);
        self
    }

    /// Sets the organization ID.
    #[must_use]
    pub fn in_org(mut self, org_id: Uuid) -> Self {
        self.org_id = Some(org_id);
        self.any_org = false;
        self
    }

    /// Sets `any_org` to true.
    #[must_use]
    pub fn any_organization(mut self) -> Self {
        self.org_id = None;
        self.any_org = true;
        self
    }

    /// Sets the resource ID.
    #[must_use]
    pub fn with_id(mut self, id: Uuid) -> Self {
        self.id = Some(id);
        self
    }

    /// Sets the user ACL list.
    #[must_use]
    pub fn with_acl_user_list(mut self, acl: HashMap<String, Vec<Action>>) -> Self {
        self.acl_user_list = acl;
        self
    }

    /// Sets the group ACL list.
    #[must_use]
    pub fn with_acl_group_list(mut self, acl: HashMap<String, Vec<Action>>) -> Self {
        self.acl_group_list = acl;
        self
    }
}

// ---------------------------------------------------------------------------
// Permission
// ---------------------------------------------------------------------------

/// A single permission entry in a role.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Permission {
    /// If true, this is a negative (deny) permission.
    pub negate: bool,
    /// The resource type this permission applies to.
    pub resource_type: ResourceType,
    /// The action. `None` means wildcard action (all actions).
    pub action: Option<Action>,
}

impl Permission {
    /// Creates a positive permission for the given resource type and action.
    #[must_use]
    pub fn allow(resource_type: ResourceType, action: Action) -> Self {
        Self {
            negate: false,
            resource_type,
            action: Some(action),
        }
    }

    /// Creates a positive wildcard-action permission for the given resource type.
    #[must_use]
    pub fn allow_all(resource_type: ResourceType) -> Self {
        Self {
            negate: false,
            resource_type,
            action: None,
        }
    }

    /// Creates a negative (deny) permission for the given resource type and action.
    #[must_use]
    pub fn deny(resource_type: ResourceType, action: Action) -> Self {
        Self {
            negate: true,
            resource_type,
            action: Some(action),
        }
    }

    /// Returns true if this permission matches the given resource type and action.
    #[must_use]
    pub fn matches(&self, resource_type: ResourceType, action: Action) -> bool {
        let type_match =
            self.resource_type == ResourceType::Wildcard || self.resource_type == resource_type;
        let action_match = self.action.is_none() || self.action == Some(action);
        type_match && action_match
    }
}

// ---------------------------------------------------------------------------
// OrgPermissions
// ---------------------------------------------------------------------------

/// Organization-scoped permissions within a role.
#[derive(Clone, Debug, Default)]
pub struct OrgPermissions {
    /// Permissions that apply to all resources in the org.
    pub org: Vec<Permission>,
    /// Permissions that apply to resources owned by the member.
    pub member: Vec<Permission>,
}

// ---------------------------------------------------------------------------
// Role
// ---------------------------------------------------------------------------

/// A role contains permissions at multiple levels.
#[derive(Clone, Debug)]
pub struct Role {
    /// Role name.
    pub name: String,
    /// Optional organization ID for org-scoped roles.
    pub org_id: Option<Uuid>,
    /// Human-readable display name.
    pub display_name: String,
    /// Site-wide permissions.
    pub site: Vec<Permission>,
    /// User-scoped permissions (applies to resources the user owns).
    pub user: Vec<Permission>,
    /// Organization-scoped permissions, keyed by org ID string.
    pub by_org_id: HashMap<String, OrgPermissions>,
}

// ---------------------------------------------------------------------------
// Role name constants
// ---------------------------------------------------------------------------

/// Site-wide owner role.
pub const ROLE_OWNER: &str = "owner";
/// Site-wide member role.
pub const ROLE_MEMBER: &str = "member";
/// Site-wide template admin role.
pub const ROLE_TEMPLATE_ADMIN: &str = "template-admin";
/// Site-wide user admin role.
pub const ROLE_USER_ADMIN: &str = "user-admin";
/// Site-wide auditor role.
pub const ROLE_AUDITOR: &str = "auditor";

/// Organization admin role.
pub const ROLE_ORGANIZATION_ADMIN: &str = "organization-admin";
/// Organization member role.
pub const ROLE_ORGANIZATION_MEMBER: &str = "organization-member";
/// Organization auditor role.
pub const ROLE_ORGANIZATION_AUDITOR: &str = "organization-auditor";
/// Organization user admin role.
pub const ROLE_ORGANIZATION_USER_ADMIN: &str = "organization-user-admin";
/// Organization template admin role.
pub const ROLE_ORGANIZATION_TEMPLATE_ADMIN: &str = "organization-template-admin";
/// Organization workspace creation ban role.
pub const ROLE_ORGANIZATION_WORKSPACE_CREATION_BAN: &str = "organization-workspace-creation-ban";

// ---------------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------------

/// A scope restricts what an API key can do, on top of the user's roles.
#[derive(Clone, Debug)]
pub struct Scope {
    /// The scope's role-like permission set.
    pub role: Role,
    /// If non-empty, only resources whose IDs are in this list are allowed.
    /// A single entry with `("*", "*")` means allow all.
    pub allow_list: Vec<(String, String)>,
}

impl Scope {
    /// Returns the built-in "all" scope that allows everything.
    #[must_use]
    pub fn scope_all() -> Self {
        Self {
            role: Role {
                name: "Scope_coder:all".to_owned(),
                org_id: None,
                display_name: "All operations".to_owned(),
                site: vec![Permission {
                    negate: false,
                    resource_type: ResourceType::Wildcard,
                    action: None,
                }],
                user: Vec::new(),
                by_org_id: HashMap::new(),
            },
            allow_list: vec![(WILDCARD.to_owned(), WILDCARD.to_owned())],
        }
    }

    /// Returns the built-in `application_connect` scope.
    #[must_use]
    pub fn scope_application_connect() -> Self {
        Self {
            role: Role {
                name: "Scope_coder:application_connect".to_owned(),
                org_id: None,
                display_name: "Ability to connect to applications".to_owned(),
                site: vec![Permission::allow(
                    ResourceType::Workspace,
                    Action::ApplicationConnect,
                )],
                user: Vec::new(),
                by_org_id: HashMap::new(),
            },
            allow_list: vec![(WILDCARD.to_owned(), WILDCARD.to_owned())],
        }
    }

    /// Returns true if the allow list permits the given object.
    #[must_use]
    pub fn allows_object(&self, object: &Object) -> bool {
        if self.allow_list.is_empty() {
            return true;
        }
        for (allow_type, allow_id) in &self.allow_list {
            if allow_type == WILDCARD && allow_id == WILDCARD {
                return true;
            }
            if allow_type.as_str() == object.resource_type.as_str() {
                if allow_id == WILDCARD {
                    return true;
                }
                if let Some(obj_id) = &object.id {
                    if allow_id == &obj_id.to_string() {
                        return true;
                    }
                }
            }
        }
        false
    }
}

// ---------------------------------------------------------------------------
// Actor (expanded)
// ---------------------------------------------------------------------------

/// Request actor used by the HTTP layer for authorization.
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
    /// Organization-scoped roles: `"role_name:org_id"` format.
    pub org_roles: Vec<String>,
    /// Groups the actor belongs to.
    pub groups: Vec<String>,
    /// API key scope. If `None`, defaults to `ScopeAll`.
    pub scope: Option<String>,
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

// ---------------------------------------------------------------------------
// Built-in role metadata
// ---------------------------------------------------------------------------

/// Built-in role metadata used by the role-listing routes.
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
            name: ROLE_MEMBER,
            display_name: "Member",
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
            name: ROLE_ORGANIZATION_MEMBER,
            display_name: "Organization Member",
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

// ---------------------------------------------------------------------------
// Built-in role definitions
// ---------------------------------------------------------------------------

/// Helper: creates permissions for every resource type except the specified ones.
fn all_perms_except(except: &[ResourceType]) -> Vec<Permission> {
    ALL_RESOURCE_TYPES
        .iter()
        .filter(|rt| !except.contains(rt))
        .map(|rt| Permission::allow_all(*rt))
        .collect()
}

/// Helper: creates permissions from a map of resource type to actions.
fn permissions_from_map(map: &[(ResourceType, &[Action])]) -> Vec<Permission> {
    let mut perms = Vec::new();
    for (rt, actions) in map {
        for action in *actions {
            perms.push(Permission::allow(*rt, *action));
        }
    }
    perms
}

/// Returns the built-in owner role.
#[must_use]
pub fn role_owner() -> Role {
    let mut site = all_perms_except(&[
        ResourceType::WorkspaceDormant,
        ResourceType::PrebuiltWorkspace,
        ResourceType::Workspace,
        ResourceType::UserSecret,
        ResourceType::UsageEvent,
        ResourceType::BoundaryUsage,
    ]);
    // Add workspace with all actions.
    site.push(Permission::allow_all(ResourceType::Workspace));
    // Add dormant workspace with specific actions.
    for action in &[
        Action::Read,
        Action::Delete,
        Action::Create,
        Action::Update,
        Action::Stop,
        Action::CreateAgent,
        Action::DeleteAgent,
        Action::UpdateAgent,
    ] {
        site.push(Permission::allow(ResourceType::WorkspaceDormant, *action));
    }
    // Add prebuilt workspace actions.
    site.push(Permission::allow(
        ResourceType::PrebuiltWorkspace,
        Action::Update,
    ));
    site.push(Permission::allow(
        ResourceType::PrebuiltWorkspace,
        Action::Delete,
    ));

    Role {
        name: ROLE_OWNER.to_owned(),
        org_id: None,
        display_name: "Owner".to_owned(),
        site,
        user: Vec::new(),
        by_org_id: HashMap::new(),
    }
}

/// Returns the built-in member role.
#[must_use]
pub fn role_member() -> Role {
    let site = permissions_from_map(&[
        (ResourceType::AssignRole, &[Action::Read]),
        (ResourceType::Oauth2App, &[Action::Read]),
        (ResourceType::WorkspaceProxy, &[Action::Read]),
    ]);

    let mut user = all_perms_except(&[
        ResourceType::WorkspaceDormant,
        ResourceType::PrebuiltWorkspace,
        ResourceType::Workspace,
        ResourceType::User,
        ResourceType::OrganizationMember,
        ResourceType::BoundaryUsage,
    ]);
    // Users can read their own details and update personal data.
    user.extend(permissions_from_map(&[
        (
            ResourceType::User,
            &[Action::Read, Action::ReadPersonal, Action::UpdatePersonal],
        ),
        (
            ResourceType::ProvisionerDaemon,
            &[Action::Read, Action::Create, Action::Update],
        ),
    ]));

    Role {
        name: ROLE_MEMBER.to_owned(),
        org_id: None,
        display_name: "Member".to_owned(),
        site,
        user,
        by_org_id: HashMap::new(),
    }
}

/// Returns the built-in auditor role.
#[must_use]
pub fn role_auditor() -> Role {
    let site = permissions_from_map(&[
        (ResourceType::AssignOrgRole, &[Action::Read]),
        (ResourceType::AuditLog, &[Action::Read]),
        (ResourceType::ConnectionLog, &[Action::Read]),
        (
            ResourceType::Template,
            &[Action::Read, Action::ViewInsights],
        ),
        (ResourceType::User, &[Action::Read]),
        (ResourceType::Group, &[Action::Read]),
        (ResourceType::GroupMember, &[Action::Read]),
        (ResourceType::Organization, &[Action::Read]),
        (ResourceType::OrganizationMember, &[Action::Read]),
        (ResourceType::DeploymentStats, &[Action::Read]),
        (ResourceType::DeploymentConfig, &[Action::Read]),
        (ResourceType::AibridgeInterception, &[Action::Read]),
    ]);

    Role {
        name: ROLE_AUDITOR.to_owned(),
        org_id: None,
        display_name: "Auditor".to_owned(),
        site,
        user: Vec::new(),
        by_org_id: HashMap::new(),
    }
}

/// Returns the built-in template admin role.
#[must_use]
pub fn role_template_admin() -> Role {
    let site = permissions_from_map(&[
        (ResourceType::AssignOrgRole, &[Action::Read]),
        (
            ResourceType::Template,
            &[
                Action::Create,
                Action::Use,
                Action::Read,
                Action::Update,
                Action::Delete,
                Action::ViewInsights,
            ],
        ),
        (ResourceType::File, &[Action::Create, Action::Read]),
        (ResourceType::Workspace, &[Action::Read]),
        (
            ResourceType::PrebuiltWorkspace,
            &[Action::Update, Action::Delete],
        ),
        (
            ResourceType::ProvisionerDaemon,
            &[Action::Create, Action::Read, Action::Update, Action::Delete],
        ),
        (ResourceType::User, &[Action::Read]),
        (ResourceType::Group, &[Action::Read]),
        (ResourceType::GroupMember, &[Action::Read]),
        (ResourceType::Organization, &[Action::Read]),
        (ResourceType::OrganizationMember, &[Action::Read]),
    ]);

    Role {
        name: ROLE_TEMPLATE_ADMIN.to_owned(),
        org_id: None,
        display_name: "Template Admin".to_owned(),
        site,
        user: Vec::new(),
        by_org_id: HashMap::new(),
    }
}

/// Returns the built-in user admin role.
#[must_use]
pub fn role_user_admin() -> Role {
    let site = permissions_from_map(&[
        (
            ResourceType::AssignRole,
            &[Action::Assign, Action::Unassign, Action::Read],
        ),
        (
            ResourceType::AssignOrgRole,
            &[Action::Assign, Action::Unassign, Action::Read],
        ),
        (
            ResourceType::User,
            &[
                Action::Create,
                Action::Read,
                Action::Update,
                Action::Delete,
                Action::UpdatePersonal,
                Action::ReadPersonal,
            ],
        ),
        (
            ResourceType::Group,
            &[Action::Create, Action::Read, Action::Update, Action::Delete],
        ),
        (ResourceType::GroupMember, &[Action::Read]),
        (ResourceType::Organization, &[Action::Read]),
        (
            ResourceType::OrganizationMember,
            &[Action::Create, Action::Read, Action::Update, Action::Delete],
        ),
        (
            ResourceType::IdpsyncSettings,
            &[Action::Read, Action::Update],
        ),
    ]);

    Role {
        name: ROLE_USER_ADMIN.to_owned(),
        org_id: None,
        display_name: "User Admin".to_owned(),
        site,
        user: Vec::new(),
        by_org_id: HashMap::new(),
    }
}

/// Returns the built-in organization admin role for the given org.
#[must_use]
pub fn role_org_admin(org_id: Uuid) -> Role {
    let site = permissions_from_map(&[(ResourceType::User, &[Action::Read])]);

    let mut org_perms = all_perms_except(&[
        ResourceType::Workspace,
        ResourceType::WorkspaceDormant,
        ResourceType::PrebuiltWorkspace,
        ResourceType::AssignRole,
        ResourceType::UserSecret,
        ResourceType::BoundaryUsage,
    ]);
    // Workspace without SSH/AppConnect.
    for action in &[
        Action::Create,
        Action::Read,
        Action::Update,
        Action::Delete,
        Action::Start,
        Action::Stop,
        Action::Use,
        Action::ViewInsights,
        Action::Share,
        Action::CreateAgent,
        Action::DeleteAgent,
        Action::UpdateAgent,
    ] {
        org_perms.push(Permission::allow(ResourceType::Workspace, *action));
    }
    // Dormant workspace.
    for action in &[
        Action::Read,
        Action::Delete,
        Action::Create,
        Action::Update,
        Action::Stop,
        Action::CreateAgent,
        Action::DeleteAgent,
        Action::UpdateAgent,
    ] {
        org_perms.push(Permission::allow(ResourceType::WorkspaceDormant, *action));
    }
    org_perms.push(Permission::allow(
        ResourceType::PrebuiltWorkspace,
        Action::Update,
    ));
    org_perms.push(Permission::allow(
        ResourceType::PrebuiltWorkspace,
        Action::Delete,
    ));

    let mut by_org_id = HashMap::new();
    by_org_id.insert(
        org_id.to_string(),
        OrgPermissions {
            org: org_perms,
            member: Vec::new(),
        },
    );

    Role {
        name: ROLE_ORGANIZATION_ADMIN.to_owned(),
        org_id: Some(org_id),
        display_name: "Organization Admin".to_owned(),
        site,
        user: Vec::new(),
        by_org_id,
    }
}

/// Returns the built-in organization member role for the given org.
#[must_use]
pub fn role_org_member(org_id: Uuid) -> Role {
    let org_perms = permissions_from_map(&[
        (ResourceType::ProvisionerDaemon, &[Action::Read]),
        (ResourceType::Organization, &[Action::Read]),
        (ResourceType::AssignOrgRole, &[Action::Read]),
        (ResourceType::OrganizationMember, &[Action::Read]),
        (ResourceType::Group, &[Action::Read]),
    ]);

    let mut member_perms = all_perms_except(&[
        ResourceType::WorkspaceDormant,
        ResourceType::PrebuiltWorkspace,
        ResourceType::User,
        ResourceType::OrganizationMember,
    ]);
    member_perms.extend(permissions_from_map(&[
        (
            ResourceType::WorkspaceDormant,
            &[
                Action::Read,
                Action::Delete,
                Action::Create,
                Action::Update,
                Action::Stop,
                Action::CreateAgent,
                Action::DeleteAgent,
                Action::UpdateAgent,
            ],
        ),
        (ResourceType::OrganizationMember, &[Action::Read]),
        (
            ResourceType::ProvisionerDaemon,
            &[Action::Read, Action::Create, Action::Update],
        ),
    ]));

    let mut by_org_id = HashMap::new();
    by_org_id.insert(
        org_id.to_string(),
        OrgPermissions {
            org: org_perms,
            member: member_perms,
        },
    );

    Role {
        name: ROLE_ORGANIZATION_MEMBER.to_owned(),
        org_id: Some(org_id),
        display_name: "Organization Member".to_owned(),
        site: Vec::new(),
        user: Vec::new(),
        by_org_id,
    }
}

/// Returns the built-in organization auditor role for the given org.
#[must_use]
pub fn role_org_auditor(org_id: Uuid) -> Role {
    let org_perms = permissions_from_map(&[
        (ResourceType::AuditLog, &[Action::Read]),
        (ResourceType::ConnectionLog, &[Action::Read]),
        (
            ResourceType::Template,
            &[Action::Read, Action::ViewInsights],
        ),
        (ResourceType::Group, &[Action::Read]),
        (ResourceType::GroupMember, &[Action::Read]),
        (ResourceType::Organization, &[Action::Read]),
        (ResourceType::OrganizationMember, &[Action::Read]),
    ]);

    let mut by_org_id = HashMap::new();
    by_org_id.insert(
        org_id.to_string(),
        OrgPermissions {
            org: org_perms,
            member: Vec::new(),
        },
    );

    Role {
        name: ROLE_ORGANIZATION_AUDITOR.to_owned(),
        org_id: Some(org_id),
        display_name: "Organization Auditor".to_owned(),
        site: Vec::new(),
        user: Vec::new(),
        by_org_id,
    }
}

/// Returns the built-in organization user admin role for the given org.
#[must_use]
pub fn role_org_user_admin(org_id: Uuid) -> Role {
    let site = permissions_from_map(&[(ResourceType::User, &[Action::Read])]);

    let org_perms = permissions_from_map(&[
        (
            ResourceType::AssignOrgRole,
            &[Action::Assign, Action::Unassign, Action::Read],
        ),
        (ResourceType::Organization, &[Action::Read]),
        (
            ResourceType::OrganizationMember,
            &[Action::Create, Action::Read, Action::Update, Action::Delete],
        ),
        (
            ResourceType::Group,
            &[Action::Create, Action::Read, Action::Update, Action::Delete],
        ),
        (ResourceType::GroupMember, &[Action::Read]),
        (
            ResourceType::IdpsyncSettings,
            &[Action::Read, Action::Update],
        ),
    ]);

    let mut by_org_id = HashMap::new();
    by_org_id.insert(
        org_id.to_string(),
        OrgPermissions {
            org: org_perms,
            member: Vec::new(),
        },
    );

    Role {
        name: ROLE_ORGANIZATION_USER_ADMIN.to_owned(),
        org_id: Some(org_id),
        display_name: "Organization User Admin".to_owned(),
        site,
        user: Vec::new(),
        by_org_id,
    }
}

/// Returns the built-in organization template admin role for the given org.
#[must_use]
pub fn role_org_template_admin(org_id: Uuid) -> Role {
    let org_perms = permissions_from_map(&[
        (
            ResourceType::Template,
            &[
                Action::Create,
                Action::Use,
                Action::Read,
                Action::Update,
                Action::Delete,
                Action::ViewInsights,
            ],
        ),
        (ResourceType::File, &[Action::Create, Action::Read]),
        (ResourceType::Workspace, &[Action::Read]),
        (
            ResourceType::PrebuiltWorkspace,
            &[Action::Update, Action::Delete],
        ),
        (ResourceType::Organization, &[Action::Read]),
        (ResourceType::OrganizationMember, &[Action::Read]),
        (ResourceType::Group, &[Action::Read]),
        (ResourceType::GroupMember, &[Action::Read]),
        (
            ResourceType::ProvisionerDaemon,
            &[Action::Create, Action::Read, Action::Update, Action::Delete],
        ),
        (
            ResourceType::ProvisionerJobs,
            &[Action::Read, Action::Update, Action::Create],
        ),
    ]);

    let mut by_org_id = HashMap::new();
    by_org_id.insert(
        org_id.to_string(),
        OrgPermissions {
            org: org_perms,
            member: Vec::new(),
        },
    );

    Role {
        name: ROLE_ORGANIZATION_TEMPLATE_ADMIN.to_owned(),
        org_id: Some(org_id),
        display_name: "Organization Template Admin".to_owned(),
        site: Vec::new(),
        user: Vec::new(),
        by_org_id,
    }
}

/// Returns the workspace creation ban role for the given org.
#[must_use]
pub fn role_org_workspace_creation_ban(org_id: Uuid) -> Role {
    let org_perms = vec![
        Permission::deny(ResourceType::Workspace, Action::Create),
        Permission::deny(ResourceType::Workspace, Action::Delete),
        Permission::deny(ResourceType::Workspace, Action::CreateAgent),
        Permission::deny(ResourceType::Workspace, Action::DeleteAgent),
    ];

    let mut by_org_id = HashMap::new();
    by_org_id.insert(
        org_id.to_string(),
        OrgPermissions {
            org: org_perms,
            member: Vec::new(),
        },
    );

    Role {
        name: ROLE_ORGANIZATION_WORKSPACE_CREATION_BAN.to_owned(),
        org_id: Some(org_id),
        display_name: "Organization Workspace Creation Ban".to_owned(),
        site: Vec::new(),
        user: Vec::new(),
        by_org_id,
    }
}

/// Expands a role name (possibly with `":org_id"` suffix) into a `Role`.
/// Returns `None` if the role name is unknown.
#[must_use]
pub fn expand_role(name: &str) -> Option<Role> {
    // Check for org-scoped roles: "role_name:org_id"
    if let Some((role_name, org_id_str)) = name.split_once(':') {
        let org_id = Uuid::parse_str(org_id_str).ok()?;
        return match role_name {
            ROLE_ORGANIZATION_ADMIN => Some(role_org_admin(org_id)),
            ROLE_ORGANIZATION_MEMBER => Some(role_org_member(org_id)),
            ROLE_ORGANIZATION_AUDITOR => Some(role_org_auditor(org_id)),
            ROLE_ORGANIZATION_USER_ADMIN => Some(role_org_user_admin(org_id)),
            ROLE_ORGANIZATION_TEMPLATE_ADMIN => Some(role_org_template_admin(org_id)),
            ROLE_ORGANIZATION_WORKSPACE_CREATION_BAN => {
                Some(role_org_workspace_creation_ban(org_id))
            }
            _ => None,
        };
    }

    match name {
        ROLE_OWNER => Some(role_owner()),
        ROLE_MEMBER => Some(role_member()),
        ROLE_AUDITOR => Some(role_auditor()),
        ROLE_TEMPLATE_ADMIN => Some(role_template_admin()),
        ROLE_USER_ADMIN => Some(role_user_admin()),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Authorizer
// ---------------------------------------------------------------------------

/// Error returned when authorization fails.
#[derive(Clone, Debug)]
pub struct Forbidden {
    /// Human-readable explanation of why authorization failed.
    pub message: String,
}

impl std::fmt::Display for Forbidden {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "forbidden: {}", self.message)
    }
}

impl std::error::Error for Forbidden {}

/// The RBAC authorizer evaluates whether a subject can perform an action on an object.
///
/// # Examples
///
/// ```
/// use coder_rbac::{Action, Actor, Authorizer, Object, ResourceType};
/// use uuid::Uuid;
///
/// let authorizer = Authorizer::new();
///
/// // Build an actor with the "owner" site role.
/// let actor = Actor {
///     user_id: Uuid::new_v4(),
///     username: "admin".to_owned(),
///     site_roles: vec!["owner".to_owned()],
///     org_roles: Vec::new(),
///     organization_ids: Vec::new(),
///     groups: Vec::new(),
///     scope: None,
/// };
///
/// // Check whether the actor can read a user resource.
/// let object = Object::new(ResourceType::User);
/// assert!(authorizer.authorize(&actor, Action::Read, &object).is_ok());
/// ```
#[derive(Clone, Debug, Default)]
pub struct Authorizer;

impl Authorizer {
    /// Creates a new authorizer.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Authorize checks whether the actor is allowed to perform the given action
    /// on the given object. Returns `Ok(())` if allowed, `Err(Forbidden)` otherwise.
    ///
    /// The evaluation logic:
    /// 1. Collect all permissions from the subject's site roles + org roles
    /// 2. Apply scope restrictions from the API key
    /// 3. Check deny (negative) overrides first
    /// 4. Check positive permissions from roles
    /// 5. Check ACL lists
    ///
    /// # Errors
    ///
    /// Returns [`Forbidden`] if the actor lacks the required permission.
    pub fn authorize(
        &self,
        actor: &Actor,
        action: Action,
        object: &Object,
    ) -> Result<(), Forbidden> {
        // Step 1: Expand all roles for the actor.
        let mut roles = Vec::new();
        for role_name in &actor.site_roles {
            if let Some(role) = expand_role(role_name) {
                roles.push(role);
            }
        }
        for role_name in &actor.org_roles {
            if let Some(role) = expand_role(role_name) {
                roles.push(role);
            }
        }

        // Step 2: Apply scope restrictions.
        let scope = match &actor.scope {
            Some(s) if s == "application_connect" => Scope::scope_application_connect(),
            _ => Scope::scope_all(),
        };
        if !scope.allows_object(object) {
            return Err(Forbidden {
                message: format!(
                    "scope does not allow access to {} resource",
                    object.resource_type
                ),
            });
        }

        // Check scope role permissions.
        if !Self::check_permissions_in_role(&scope.role, actor, action, object) {
            return Err(Forbidden {
                message: format!(
                    "scope does not allow action '{}' on resource '{}'",
                    action, object.resource_type
                ),
            });
        }

        // Step 3: Check if any deny permission from any role blocks this.
        for role in &roles {
            if Self::has_deny_permission(role, actor, action, object) {
                return Err(Forbidden {
                    message: format!(
                        "role '{}' explicitly denies action '{}' on resource '{}'",
                        role.name, action, object.resource_type
                    ),
                });
            }
        }

        // Step 4: Check if any positive permission grants access.
        for role in &roles {
            if Self::check_permissions_in_role(role, actor, action, object) {
                return Ok(());
            }
        }

        // Step 5: Check ACL lists.
        let actor_id_str = actor.user_id.to_string();
        if let Some(allowed_actions) = object.acl_user_list.get(&actor_id_str) {
            if allowed_actions.contains(&action) {
                return Ok(());
            }
        }
        for group_id in &actor.groups {
            if let Some(allowed_actions) = object.acl_group_list.get(group_id) {
                if allowed_actions.contains(&action) {
                    return Ok(());
                }
            }
        }

        Err(Forbidden {
            message: format!(
                "no role grants action '{}' on resource '{}' for user '{}'",
                action, object.resource_type, actor.username
            ),
        })
    }

    /// Check if a role has a deny permission that blocks this action on this object.
    fn has_deny_permission(role: &Role, actor: &Actor, action: Action, object: &Object) -> bool {
        // Check site-level deny.
        for perm in &role.site {
            if perm.negate && perm.matches(object.resource_type, action) {
                return true;
            }
        }

        // Check org-level deny.
        if let Some(org_id) = &object.org_id {
            if let Some(org_perms) = role.by_org_id.get(&org_id.to_string()) {
                for perm in &org_perms.org {
                    if perm.negate && perm.matches(object.resource_type, action) {
                        return true;
                    }
                }
                // Check member-level deny (only if the actor owns the resource).
                if object.owner_id == Some(actor.user_id) {
                    for perm in &org_perms.member {
                        if perm.negate && perm.matches(object.resource_type, action) {
                            return true;
                        }
                    }
                }
            }
        } else if object.any_org {
            // If any_org is set, check if any org's deny permissions match.
            for org_perms in role.by_org_id.values() {
                for perm in &org_perms.org {
                    if perm.negate && perm.matches(object.resource_type, action) {
                        return true;
                    }
                }
                if object.owner_id == Some(actor.user_id) {
                    for perm in &org_perms.member {
                        if perm.negate && perm.matches(object.resource_type, action) {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    /// Check if a role's positive permissions grant the given action on the object.
    fn check_permissions_in_role(
        role: &Role,
        actor: &Actor,
        action: Action,
        object: &Object,
    ) -> bool {
        // Site-level permissions apply everywhere.
        for perm in &role.site {
            if !perm.negate && perm.matches(object.resource_type, action) {
                return true;
            }
        }

        // Org-level permissions apply within the matching org.
        if let Some(org_id) = &object.org_id {
            if let Some(org_perms) = role.by_org_id.get(&org_id.to_string()) {
                for perm in &org_perms.org {
                    if !perm.negate && perm.matches(object.resource_type, action) {
                        return true;
                    }
                }
                // Member-level permissions only apply if the actor owns the resource.
                if object.owner_id == Some(actor.user_id) {
                    for perm in &org_perms.member {
                        if !perm.negate && perm.matches(object.resource_type, action) {
                            return true;
                        }
                    }
                }
            }
        } else if object.any_org {
            // If any_org is set, check if any org's permissions match.
            for org_perms in role.by_org_id.values() {
                for perm in &org_perms.org {
                    if !perm.negate && perm.matches(object.resource_type, action) {
                        return true;
                    }
                }
                if object.owner_id == Some(actor.user_id) {
                    for perm in &org_perms.member {
                        if !perm.negate && perm.matches(object.resource_type, action) {
                            return true;
                        }
                    }
                }
            }
        }

        // User-level permissions apply to resources owned by the actor.
        if object.owner_id == Some(actor.user_id) {
            for perm in &role.user {
                if !perm.negate && perm.matches(object.resource_type, action) {
                    return true;
                }
            }
        }

        false
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_actor(roles: &[&str]) -> Actor {
        Actor {
            user_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap_or_default(),
            username: "testuser".to_owned(),
            organization_ids: vec![],
            site_roles: roles.iter().map(|r| (*r).to_owned()).collect(),
            org_roles: vec![],
            groups: vec![],
            scope: None,
        }
    }

    fn test_actor_with_orgs(roles: &[&str], org_roles: &[&str], org_ids: &[Uuid]) -> Actor {
        Actor {
            user_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap_or_default(),
            username: "testuser".to_owned(),
            organization_ids: org_ids.to_vec(),
            site_roles: roles.iter().map(|r| (*r).to_owned()).collect(),
            org_roles: org_roles.iter().map(|r| (*r).to_owned()).collect(),
            groups: vec![],
            scope: None,
        }
    }

    #[test]
    fn owner_can_do_anything_on_site_resources() {
        let authorizer = Authorizer::new();
        let actor = test_actor(&[ROLE_OWNER]);
        let object = Object::new(ResourceType::User);

        assert!(authorizer.authorize(&actor, Action::Read, &object).is_ok());
        assert!(
            authorizer
                .authorize(&actor, Action::Create, &object)
                .is_ok()
        );
        assert!(
            authorizer
                .authorize(&actor, Action::Update, &object)
                .is_ok()
        );
        assert!(
            authorizer
                .authorize(&actor, Action::Delete, &object)
                .is_ok()
        );
    }

    #[test]
    fn owner_can_read_templates() {
        let authorizer = Authorizer::new();
        let actor = test_actor(&[ROLE_OWNER]);
        let object = Object::new(ResourceType::Template);

        assert!(authorizer.authorize(&actor, Action::Read, &object).is_ok());
        assert!(
            authorizer
                .authorize(&actor, Action::Create, &object)
                .is_ok()
        );
    }

    #[test]
    fn member_cannot_create_users() {
        let authorizer = Authorizer::new();
        let actor = test_actor(&[ROLE_MEMBER]);
        let object = Object::new(ResourceType::User);

        assert!(
            authorizer
                .authorize(&actor, Action::Create, &object)
                .is_err()
        );
    }

    #[test]
    fn member_can_read_own_user() {
        let authorizer = Authorizer::new();
        let user_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap_or_default();
        let actor = test_actor(&[ROLE_MEMBER]);
        let object = Object::new(ResourceType::User).with_owner(user_id);

        assert!(authorizer.authorize(&actor, Action::Read, &object).is_ok());
        assert!(
            authorizer
                .authorize(&actor, Action::ReadPersonal, &object)
                .is_ok()
        );
        assert!(
            authorizer
                .authorize(&actor, Action::UpdatePersonal, &object)
                .is_ok()
        );
    }

    #[test]
    fn member_can_read_assign_role() {
        let authorizer = Authorizer::new();
        let actor = test_actor(&[ROLE_MEMBER]);
        let object = Object::new(ResourceType::AssignRole);

        assert!(authorizer.authorize(&actor, Action::Read, &object).is_ok());
        assert!(
            authorizer
                .authorize(&actor, Action::Assign, &object)
                .is_err()
        );
    }

    #[test]
    fn auditor_can_read_audit_logs() {
        let authorizer = Authorizer::new();
        let actor = test_actor(&[ROLE_AUDITOR]);
        let object = Object::new(ResourceType::AuditLog);

        assert!(authorizer.authorize(&actor, Action::Read, &object).is_ok());
        assert!(
            authorizer
                .authorize(&actor, Action::Create, &object)
                .is_err()
        );
    }

    #[test]
    fn auditor_can_read_templates() {
        let authorizer = Authorizer::new();
        let actor = test_actor(&[ROLE_AUDITOR]);
        let object = Object::new(ResourceType::Template);

        assert!(authorizer.authorize(&actor, Action::Read, &object).is_ok());
        assert!(
            authorizer
                .authorize(&actor, Action::ViewInsights, &object)
                .is_ok()
        );
        assert!(
            authorizer
                .authorize(&actor, Action::Create, &object)
                .is_err()
        );
    }

    #[test]
    fn template_admin_can_crud_templates() {
        let authorizer = Authorizer::new();
        let actor = test_actor(&[ROLE_TEMPLATE_ADMIN]);
        let object = Object::new(ResourceType::Template);

        assert!(authorizer.authorize(&actor, Action::Read, &object).is_ok());
        assert!(
            authorizer
                .authorize(&actor, Action::Create, &object)
                .is_ok()
        );
        assert!(
            authorizer
                .authorize(&actor, Action::Update, &object)
                .is_ok()
        );
        assert!(
            authorizer
                .authorize(&actor, Action::Delete, &object)
                .is_ok()
        );
    }

    #[test]
    fn user_admin_can_crud_users() {
        let authorizer = Authorizer::new();
        let actor = test_actor(&[ROLE_USER_ADMIN]);
        let object = Object::new(ResourceType::User);

        assert!(authorizer.authorize(&actor, Action::Read, &object).is_ok());
        assert!(
            authorizer
                .authorize(&actor, Action::Create, &object)
                .is_ok()
        );
        assert!(
            authorizer
                .authorize(&actor, Action::Update, &object)
                .is_ok()
        );
        assert!(
            authorizer
                .authorize(&actor, Action::Delete, &object)
                .is_ok()
        );
    }

    #[test]
    fn user_admin_can_assign_roles() {
        let authorizer = Authorizer::new();
        let actor = test_actor(&[ROLE_USER_ADMIN]);
        let object = Object::new(ResourceType::AssignRole);

        assert!(
            authorizer
                .authorize(&actor, Action::Assign, &object)
                .is_ok()
        );
        assert!(
            authorizer
                .authorize(&actor, Action::Unassign, &object)
                .is_ok()
        );
    }

    #[test]
    fn org_admin_has_perms_in_org() {
        let authorizer = Authorizer::new();
        let org_id = Uuid::parse_str("00000000-0000-0000-0000-000000000099").unwrap_or_default();
        let org_role = format!("{ROLE_ORGANIZATION_ADMIN}:{org_id}");
        let actor = test_actor_with_orgs(&[], &[&org_role], &[org_id]);

        let object = Object::new(ResourceType::Template).in_org(org_id);
        assert!(authorizer.authorize(&actor, Action::Read, &object).is_ok());
        assert!(
            authorizer
                .authorize(&actor, Action::Create, &object)
                .is_ok()
        );

        // Org admin should not have SSH into workspaces.
        let ws_object = Object::new(ResourceType::Workspace).in_org(org_id);
        assert!(
            authorizer
                .authorize(&actor, Action::Ssh, &ws_object)
                .is_err()
        );
    }

    #[test]
    fn org_member_can_read_in_org() {
        let authorizer = Authorizer::new();
        let org_id = Uuid::parse_str("00000000-0000-0000-0000-000000000099").unwrap_or_default();
        let org_role = format!("{ROLE_ORGANIZATION_MEMBER}:{org_id}");
        let actor = test_actor_with_orgs(&[], &[&org_role], &[org_id]);

        let object = Object::new(ResourceType::Organization).in_org(org_id);
        assert!(authorizer.authorize(&actor, Action::Read, &object).is_ok());

        // Org member cannot create templates at org level.
        let tmpl = Object::new(ResourceType::Template).in_org(org_id);
        assert!(authorizer.authorize(&actor, Action::Create, &tmpl).is_err());
    }

    #[test]
    fn org_member_can_create_own_workspaces() {
        let authorizer = Authorizer::new();
        let org_id = Uuid::parse_str("00000000-0000-0000-0000-000000000099").unwrap_or_default();
        let user_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap_or_default();
        let org_role = format!("{ROLE_ORGANIZATION_MEMBER}:{org_id}");
        let actor = test_actor_with_orgs(&[], &[&org_role], &[org_id]);

        let ws = Object::new(ResourceType::Workspace)
            .in_org(org_id)
            .with_owner(user_id);
        assert!(authorizer.authorize(&actor, Action::Create, &ws).is_ok());
        assert!(authorizer.authorize(&actor, Action::Read, &ws).is_ok());
    }

    #[test]
    fn workspace_creation_ban_denies_create() {
        let authorizer = Authorizer::new();
        let org_id = Uuid::parse_str("00000000-0000-0000-0000-000000000099").unwrap_or_default();
        let user_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap_or_default();
        let member_role = format!("{ROLE_ORGANIZATION_MEMBER}:{org_id}");
        let ban_role = format!("{ROLE_ORGANIZATION_WORKSPACE_CREATION_BAN}:{org_id}");
        let actor = test_actor_with_orgs(&[], &[&member_role, &ban_role], &[org_id]);

        let ws = Object::new(ResourceType::Workspace)
            .in_org(org_id)
            .with_owner(user_id);
        // Ban should deny create even though member role would allow it.
        assert!(authorizer.authorize(&actor, Action::Create, &ws).is_err());
        // But reading should still work.
        assert!(authorizer.authorize(&actor, Action::Read, &ws).is_ok());
    }

    #[test]
    fn no_roles_denies_everything() {
        let authorizer = Authorizer::new();
        let actor = test_actor(&[]);
        let object = Object::new(ResourceType::User);

        assert!(authorizer.authorize(&actor, Action::Read, &object).is_err());
    }

    #[test]
    fn combined_site_and_org_roles() {
        let authorizer = Authorizer::new();
        let org_id = Uuid::parse_str("00000000-0000-0000-0000-000000000099").unwrap_or_default();
        let org_role = format!("{ROLE_ORGANIZATION_MEMBER}:{org_id}");
        let actor = test_actor_with_orgs(&[ROLE_MEMBER], &[&org_role], &[org_id]);

        // Member site role lets them read assign_role.
        let ar = Object::new(ResourceType::AssignRole);
        assert!(authorizer.authorize(&actor, Action::Read, &ar).is_ok());

        // Org member role lets them read org.
        let org_obj = Object::new(ResourceType::Organization).in_org(org_id);
        assert!(authorizer.authorize(&actor, Action::Read, &org_obj).is_ok());
    }

    #[test]
    fn acl_user_list_grants_access() {
        let authorizer = Authorizer::new();
        let actor = test_actor(&[]);
        let mut acl = HashMap::new();
        acl.insert(actor.user_id.to_string(), vec![Action::Read]);
        let object = Object::new(ResourceType::Workspace).with_acl_user_list(acl);

        assert!(authorizer.authorize(&actor, Action::Read, &object).is_ok());
        assert!(
            authorizer
                .authorize(&actor, Action::Update, &object)
                .is_err()
        );
    }

    #[test]
    fn acl_group_list_grants_access() {
        let authorizer = Authorizer::new();
        let group_id = "group-1".to_owned();
        let actor = Actor {
            user_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap_or_default(),
            username: "testuser".to_owned(),
            organization_ids: vec![],
            site_roles: vec![],
            org_roles: vec![],
            groups: vec![group_id.clone()],
            scope: None,
        };
        let mut acl = HashMap::new();
        acl.insert(group_id, vec![Action::Read, Action::Update]);
        let object = Object::new(ResourceType::Workspace).with_acl_group_list(acl);

        assert!(authorizer.authorize(&actor, Action::Read, &object).is_ok());
        assert!(
            authorizer
                .authorize(&actor, Action::Update, &object)
                .is_ok()
        );
        assert!(
            authorizer
                .authorize(&actor, Action::Delete, &object)
                .is_err()
        );
    }

    #[test]
    fn expand_role_parses_org_roles() {
        let org_id = Uuid::parse_str("00000000-0000-0000-0000-000000000099").unwrap_or_default();
        let role_str = format!("{ROLE_ORGANIZATION_ADMIN}:{org_id}");
        let role = expand_role(&role_str);
        assert!(role.is_some());
    }

    #[test]
    fn expand_role_handles_unknown() {
        assert!(expand_role("nonexistent-role").is_none());
    }

    #[test]
    fn resource_type_round_trips() {
        for rt in ALL_RESOURCE_TYPES {
            let s = rt.as_str();
            let parsed = ResourceType::from_str_opt(s);
            assert_eq!(parsed, Some(*rt), "Failed round-trip for {s}");
        }
    }

    #[test]
    fn permission_matching() {
        let perm = Permission::allow(ResourceType::Template, Action::Read);
        assert!(perm.matches(ResourceType::Template, Action::Read));
        assert!(!perm.matches(ResourceType::Template, Action::Create));
        assert!(!perm.matches(ResourceType::User, Action::Read));

        let wildcard_action = Permission::allow_all(ResourceType::Template);
        assert!(wildcard_action.matches(ResourceType::Template, Action::Read));
        assert!(wildcard_action.matches(ResourceType::Template, Action::Create));
        assert!(!wildcard_action.matches(ResourceType::User, Action::Read));

        let wildcard_resource = Permission {
            negate: false,
            resource_type: ResourceType::Wildcard,
            action: None,
        };
        assert!(wildcard_resource.matches(ResourceType::Template, Action::Read));
        assert!(wildcard_resource.matches(ResourceType::User, Action::Create));
    }

    #[test]
    fn org_template_admin_can_manage_templates_in_org() {
        let authorizer = Authorizer::new();
        let org_id = Uuid::parse_str("00000000-0000-0000-0000-000000000099").unwrap_or_default();
        let org_role = format!("{ROLE_ORGANIZATION_TEMPLATE_ADMIN}:{org_id}");
        let actor = test_actor_with_orgs(&[], &[&org_role], &[org_id]);

        let object = Object::new(ResourceType::Template).in_org(org_id);
        assert!(authorizer.authorize(&actor, Action::Read, &object).is_ok());
        assert!(
            authorizer
                .authorize(&actor, Action::Create, &object)
                .is_ok()
        );
        assert!(
            authorizer
                .authorize(&actor, Action::Update, &object)
                .is_ok()
        );
        assert!(
            authorizer
                .authorize(&actor, Action::Delete, &object)
                .is_ok()
        );

        // But not in another org.
        let other_org = Uuid::parse_str("00000000-0000-0000-0000-000000000098").unwrap_or_default();
        let other_object = Object::new(ResourceType::Template).in_org(other_org);
        assert!(
            authorizer
                .authorize(&actor, Action::Read, &other_object)
                .is_err()
        );
    }

    #[test]
    fn owner_cannot_access_user_secrets() {
        let authorizer = Authorizer::new();
        let actor = test_actor(&[ROLE_OWNER]);
        let object = Object::new(ResourceType::UserSecret);

        // Owner role explicitly excludes UserSecret.
        assert!(authorizer.authorize(&actor, Action::Read, &object).is_err());
    }

    #[test]
    fn scope_application_connect_restricts() {
        let scope = Scope::scope_application_connect();
        // The scope role only allows application_connect on workspace.
        let ws = Object::new(ResourceType::Workspace);
        assert!(Authorizer::check_permissions_in_role(
            &scope.role,
            &test_actor(&[]),
            Action::ApplicationConnect,
            &ws
        ));
        assert!(!Authorizer::check_permissions_in_role(
            &scope.role,
            &test_actor(&[]),
            Action::Read,
            &ws
        ));
    }

    #[test]
    fn workspace_creation_ban_denies_with_any_org() {
        let authorizer = Authorizer::new();
        let org_id = Uuid::parse_str("00000000-0000-0000-0000-000000000099").unwrap_or_default();
        let user_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap_or_default();
        let member_role = format!("{ROLE_ORGANIZATION_MEMBER}:{org_id}");
        let ban_role = format!("{ROLE_ORGANIZATION_WORKSPACE_CREATION_BAN}:{org_id}");
        let actor = test_actor_with_orgs(&[], &[&member_role, &ban_role], &[org_id]);

        // With any_org = true, the deny from workspace-creation-ban must still apply.
        let ws = Object::new(ResourceType::Workspace)
            .any_organization()
            .with_owner(user_id);
        assert!(authorizer.authorize(&actor, Action::Create, &ws).is_err());
        // Reading should still work via the member role.
        assert!(authorizer.authorize(&actor, Action::Read, &ws).is_ok());
    }

    #[test]
    fn authorizer_respects_actor_scope() {
        let authorizer = Authorizer::new();
        // Owner with application_connect scope should only be able to
        // ApplicationConnect on workspaces, not Read templates.
        let mut actor = test_actor(&[ROLE_OWNER]);
        actor.scope = Some("application_connect".to_owned());

        let ws = Object::new(ResourceType::Workspace);
        assert!(
            authorizer
                .authorize(&actor, Action::ApplicationConnect, &ws)
                .is_ok()
        );

        // Read on template should be denied by the scope restriction.
        let tpl = Object::new(ResourceType::Template);
        assert!(authorizer.authorize(&actor, Action::Read, &tpl).is_err());

        // Without scope restriction (None), owner can read templates.
        actor.scope = None;
        assert!(authorizer.authorize(&actor, Action::Read, &tpl).is_ok());
    }

    #[test]
    fn test_action_as_str_roundtrip() {
        let actions = [
            (Action::Create, "create"),
            (Action::Read, "read"),
            (Action::Update, "update"),
            (Action::Delete, "delete"),
            (Action::Use, "use"),
            (Action::Ssh, "ssh"),
            (Action::ApplicationConnect, "application_connect"),
            (Action::ViewInsights, "view_insights"),
            (Action::Start, "start"),
            (Action::Stop, "stop"),
            (Action::Assign, "assign"),
            (Action::Unassign, "unassign"),
            (Action::ReadPersonal, "read_personal"),
            (Action::UpdatePersonal, "update_personal"),
            (Action::CreateAgent, "create_agent"),
            (Action::DeleteAgent, "delete_agent"),
            (Action::UpdateAgent, "update_agent"),
            (Action::Share, "share"),
        ];
        for (action, expected) in &actions {
            assert_eq!(action.as_str(), *expected, "Action::{action:?} as_str");
            assert_eq!(action.to_string(), *expected, "Action::{action:?} Display");
        }
    }

    #[test]
    fn test_resource_type_as_str_roundtrip() {
        // Wildcard has a special string.
        assert_eq!(ResourceType::Wildcard.as_str(), "*");
        // Spot-check a few representative variants.
        assert_eq!(ResourceType::ApiKey.as_str(), "api_key");
        assert_eq!(ResourceType::AuditLog.as_str(), "audit_log");
        assert_eq!(ResourceType::Workspace.as_str(), "workspace");
        assert_eq!(ResourceType::Template.as_str(), "template");
        assert_eq!(ResourceType::User.as_str(), "user");
        assert_eq!(
            ResourceType::WorkspaceAgentDevcontainers.as_str(),
            "workspace_agent_devcontainers"
        );
    }

    #[test]
    fn test_resource_type_from_str_opt() {
        // Valid inputs.
        assert_eq!(
            ResourceType::from_str_opt("api_key"),
            Some(ResourceType::ApiKey)
        );
        assert_eq!(
            ResourceType::from_str_opt("workspace"),
            Some(ResourceType::Workspace)
        );
        assert_eq!(
            ResourceType::from_str_opt("*"),
            Some(ResourceType::Wildcard)
        );
        // Invalid inputs return None.
        assert_eq!(ResourceType::from_str_opt("nonexistent"), None);
        assert_eq!(ResourceType::from_str_opt(""), None);
        assert_eq!(ResourceType::from_str_opt("WORKSPACE"), None);
    }

    #[test]
    fn test_object_builder_pattern() {
        let owner_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap_or_default();
        let org_id = Uuid::parse_str("00000000-0000-0000-0000-000000000099").unwrap_or_default();
        let resource_id =
            Uuid::parse_str("00000000-0000-0000-0000-000000000042").unwrap_or_default();
        // Guard against silent nil fallback from malformed UUID literals.
        assert_ne!(owner_id, Uuid::nil());
        assert_ne!(org_id, Uuid::nil());
        assert_ne!(resource_id, Uuid::nil());

        let object = Object::new(ResourceType::Workspace)
            .with_owner(owner_id)
            .in_org(org_id)
            .with_id(resource_id);

        assert_eq!(object.resource_type, ResourceType::Workspace);
        assert_eq!(object.owner_id, Some(owner_id));
        assert_eq!(object.org_id, Some(org_id));
        assert_eq!(object.id, Some(resource_id));
        assert!(!object.any_org);

        // any_organization clears org_id.
        let object2 = Object::new(ResourceType::Template).any_organization();
        assert!(object2.any_org);
        assert_eq!(object2.org_id, None);
    }

    #[test]
    fn test_permission_allow_deny() {
        let allow = Permission::allow(ResourceType::User, Action::Read);
        assert!(!allow.negate);
        assert_eq!(allow.resource_type, ResourceType::User);
        assert_eq!(allow.action, Some(Action::Read));
        assert!(allow.matches(ResourceType::User, Action::Read));
        assert!(!allow.matches(ResourceType::User, Action::Create));

        let deny = Permission::deny(ResourceType::Workspace, Action::Create);
        assert!(deny.negate);
        assert_eq!(deny.resource_type, ResourceType::Workspace);
        assert_eq!(deny.action, Some(Action::Create));
        assert!(deny.matches(ResourceType::Workspace, Action::Create));

        let allow_all = Permission::allow_all(ResourceType::Template);
        assert!(!allow_all.negate);
        assert_eq!(allow_all.action, None);
        assert!(allow_all.matches(ResourceType::Template, Action::Read));
        assert!(allow_all.matches(ResourceType::Template, Action::Delete));
    }

    /// Extends `owner_can_do_anything_on_site_resources` by testing with an
    /// *owned* workspace (`with_owner`) and verifying the actor helper methods
    /// (`is_owner`, `can_access_user`).
    #[test]
    fn test_authorizer_owner_can_access_own_resource() {
        let authorizer = Authorizer::new();
        let user_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap_or_default();
        let actor = test_actor(&[ROLE_OWNER]);
        let object = Object::new(ResourceType::Workspace).with_owner(user_id);

        assert!(authorizer.authorize(&actor, Action::Read, &object).is_ok());
        assert!(
            authorizer
                .authorize(&actor, Action::Update, &object)
                .is_ok()
        );
        assert!(
            authorizer
                .authorize(&actor, Action::Delete, &object)
                .is_ok()
        );

        // Also verify actor helper.
        assert!(actor.is_owner());
        assert!(actor.can_access_user(user_id));
    }

    /// Complements `member_cannot_create_users` and `member_can_read_assign_role`
    /// by combining both positive and negative assertions in one test, plus
    /// checking Oauth2App and the `is_owner()` helper.
    #[test]
    fn test_authorizer_member_basic_permissions() {
        let authorizer = Authorizer::new();
        let actor = test_actor(&[ROLE_MEMBER]);

        // Member can read AssignRole at site level.
        let assign_role = Object::new(ResourceType::AssignRole);
        assert!(
            authorizer
                .authorize(&actor, Action::Read, &assign_role)
                .is_ok()
        );

        // Member can read Oauth2App at site level.
        let oauth = Object::new(ResourceType::Oauth2App);
        assert!(authorizer.authorize(&actor, Action::Read, &oauth).is_ok());

        // Member cannot create users at site level.
        let user = Object::new(ResourceType::User);
        assert!(authorizer.authorize(&actor, Action::Create, &user).is_err());

        // Member is not owner.
        assert!(!actor.is_owner());
    }

    /// Extends existing owner tests by iterating over multiple resource types
    /// and verifying `can_list_users()` helper.
    #[test]
    fn test_authorizer_admin_has_broad_access() {
        let authorizer = Authorizer::new();
        let actor = test_actor(&[ROLE_OWNER]);

        // Owner has broad access to many resource types.
        for rt in &[
            ResourceType::User,
            ResourceType::Template,
            ResourceType::Organization,
            ResourceType::AuditLog,
            ResourceType::ApiKey,
        ] {
            assert!(
                authorizer
                    .authorize(&actor, Action::Read, &Object::new(*rt))
                    .is_ok(),
                "Owner should be able to read {rt:?}"
            );
        }

        // Verify actor helpers.
        assert!(actor.is_owner());
        assert!(actor.can_list_users());
    }

    #[test]
    fn test_authorizer_denies_cross_org_access() {
        let authorizer = Authorizer::new();
        let org_a = Uuid::parse_str("00000000-0000-0000-0000-00000000000a").unwrap_or_default();
        let org_b = Uuid::parse_str("00000000-0000-0000-0000-00000000000b").unwrap_or_default();
        let org_role_a = format!("{ROLE_ORGANIZATION_ADMIN}:{org_a}");
        let actor = test_actor_with_orgs(&[], &[&org_role_a], &[org_a]);

        // Can access resources in org A.
        let obj_a = Object::new(ResourceType::Template).in_org(org_a);
        assert!(authorizer.authorize(&actor, Action::Read, &obj_a).is_ok());

        // Cannot access resources in org B.
        let obj_b = Object::new(ResourceType::Template).in_org(org_b);
        assert!(authorizer.authorize(&actor, Action::Read, &obj_b).is_err());

        // Actor helpers confirm.
        assert!(actor.can_access_organization(org_a));
        assert!(!actor.can_access_organization(org_b));
    }

    /// Extends `acl_user_list_grants_access` by testing both allowed and
    /// disallowed actions in the ACL, and verifying a *different* user is denied.
    #[test]
    fn test_authorizer_acl_user_list_grants_access() {
        let authorizer = Authorizer::new();
        let user_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap_or_default();
        // Actor with no roles.
        let actor = test_actor(&[]);
        let mut acl = HashMap::new();
        acl.insert(user_id.to_string(), vec![Action::Read, Action::Update]);
        let object = Object::new(ResourceType::Workspace).with_acl_user_list(acl);

        // ACL grants read and update.
        assert!(authorizer.authorize(&actor, Action::Read, &object).is_ok());
        assert!(
            authorizer
                .authorize(&actor, Action::Update, &object)
                .is_ok()
        );
        // But not delete.
        assert!(
            authorizer
                .authorize(&actor, Action::Delete, &object)
                .is_err()
        );

        // Different user should not have access.
        let other_user =
            Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap_or_default();
        let other_actor = Actor {
            user_id: other_user,
            username: "other".to_owned(),
            organization_ids: vec![],
            site_roles: vec![],
            org_roles: vec![],
            groups: vec![],
            scope: None,
        };
        assert!(
            authorizer
                .authorize(&other_actor, Action::Read, &object)
                .is_err()
        );
    }
}
