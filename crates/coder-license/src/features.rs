//! Enterprise feature names and metadata.
//!
//! Maps the Go `codersdk.FeatureName` constants to a Rust enum with the same
//! wire-format strings and helper predicates.

use serde::{Deserialize, Serialize};

/// Enterprise feature names matching the Go `codersdk.FeatureName` constants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeatureName {
    /// User seat limit.
    UserLimit,
    /// Audit log access.
    AuditLog,
    /// Connection logging.
    ConnectionLog,
    /// Browser-only workspace access.
    BrowserOnly,
    /// SCIM user provisioning.
    #[serde(rename = "scim")]
    Scim,
    /// Template-level RBAC.
    TemplateRbac,
    /// User role management.
    UserRoleManagement,
    /// High availability / multi-replica support.
    HighAvailability,
    /// Multiple external auth providers.
    MultipleExternalAuth,
    /// External provisioner daemons.
    ExternalProvisionerDaemons,
    /// UI appearance customisation.
    Appearance,
    /// Advanced template scheduling.
    AdvancedTemplateScheduling,
    /// Workspace proxy support.
    WorkspaceProxy,
    /// External token encryption.
    ExternalTokenEncryption,
    /// Batch workspace actions.
    WorkspaceBatchActions,
    /// Batch task actions.
    TaskBatchActions,
    /// Fine-grained access control.
    AccessControl,
    /// Shared port control.
    ControlSharedPorts,
    /// Custom role definitions.
    CustomRoles,
    /// Multiple organization support.
    MultipleOrganizations,
    /// Workspace prebuilds.
    WorkspacePrebuilds,
    /// Managed agent limit (usage-period feature).
    ManagedAgentLimit,
    /// External agent workspaces.
    WorkspaceExternalAgent,
    /// AI Bridge integration.
    #[serde(rename = "aibridge")]
    AiBridge,
    /// Boundary integration.
    Boundary,
    /// AI governance user limit.
    AiGovernanceUserLimit,
}

/// All known feature names, matching Go's `FeatureNames` slice ordering.
pub(crate) const ALL_FEATURE_NAMES: &[FeatureName] = &[
    FeatureName::UserLimit,
    FeatureName::AuditLog,
    FeatureName::ConnectionLog,
    FeatureName::BrowserOnly,
    FeatureName::Scim,
    FeatureName::TemplateRbac,
    FeatureName::HighAvailability,
    FeatureName::MultipleExternalAuth,
    FeatureName::ExternalProvisionerDaemons,
    FeatureName::Appearance,
    FeatureName::AdvancedTemplateScheduling,
    FeatureName::WorkspaceProxy,
    FeatureName::UserRoleManagement,
    FeatureName::ExternalTokenEncryption,
    FeatureName::WorkspaceBatchActions,
    FeatureName::TaskBatchActions,
    FeatureName::AccessControl,
    FeatureName::ControlSharedPorts,
    FeatureName::CustomRoles,
    FeatureName::MultipleOrganizations,
    FeatureName::WorkspacePrebuilds,
    FeatureName::ManagedAgentLimit,
    FeatureName::WorkspaceExternalAgent,
    FeatureName::AiBridge,
    FeatureName::Boundary,
    FeatureName::AiGovernanceUserLimit,
];

impl FeatureName {
    /// Returns the canonical wire-format string for this feature.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserLimit => "user_limit",
            Self::AuditLog => "audit_log",
            Self::ConnectionLog => "connection_log",
            Self::BrowserOnly => "browser_only",
            Self::Scim => "scim",
            Self::TemplateRbac => "template_rbac",
            Self::UserRoleManagement => "user_role_management",
            Self::HighAvailability => "high_availability",
            Self::MultipleExternalAuth => "multiple_external_auth",
            Self::ExternalProvisionerDaemons => "external_provisioner_daemons",
            Self::Appearance => "appearance",
            Self::AdvancedTemplateScheduling => "advanced_template_scheduling",
            Self::WorkspaceProxy => "workspace_proxy",
            Self::ExternalTokenEncryption => "external_token_encryption",
            Self::WorkspaceBatchActions => "workspace_batch_actions",
            Self::TaskBatchActions => "task_batch_actions",
            Self::AccessControl => "access_control",
            Self::ControlSharedPorts => "control_shared_ports",
            Self::CustomRoles => "custom_roles",
            Self::MultipleOrganizations => "multiple_organizations",
            Self::WorkspacePrebuilds => "workspace_prebuilds",
            Self::ManagedAgentLimit => "managed_agent_limit",
            Self::WorkspaceExternalAgent => "workspace_external_agent",
            Self::AiBridge => "aibridge",
            Self::Boundary => "boundary",
            Self::AiGovernanceUserLimit => "ai_governance_user_limit",
        }
    }

    /// Returns a human-readable name for this feature.
    #[must_use]
    pub fn humanize(self) -> &'static str {
        match self {
            Self::UserLimit => "User Limit",
            Self::AuditLog => "Audit Log",
            Self::ConnectionLog => "Connection Log",
            Self::BrowserOnly => "Browser Only",
            Self::Scim => "SCIM",
            Self::TemplateRbac => "Template RBAC",
            Self::UserRoleManagement => "User Role Management",
            Self::HighAvailability => "High Availability",
            Self::MultipleExternalAuth => "Multiple External Auth",
            Self::ExternalProvisionerDaemons => "External Provisioner Daemons",
            Self::Appearance => "Appearance",
            Self::AdvancedTemplateScheduling => "Advanced Template Scheduling",
            Self::WorkspaceProxy => "Workspace Proxy",
            Self::ExternalTokenEncryption => "External Token Encryption",
            Self::WorkspaceBatchActions => "Workspace Batch Actions",
            Self::TaskBatchActions => "Task Batch Actions",
            Self::AccessControl => "Access Control",
            Self::ControlSharedPorts => "Control Shared Ports",
            Self::CustomRoles => "Custom Roles",
            Self::MultipleOrganizations => "Multiple Organizations",
            Self::WorkspacePrebuilds => "Workspace Prebuilds",
            Self::ManagedAgentLimit => "Managed Agent Limit",
            Self::WorkspaceExternalAgent => "Workspace External Agent",
            Self::AiBridge => "AI Bridge",
            Self::Boundary => "Boundary",
            Self::AiGovernanceUserLimit => "AI Governance User Limit",
        }
    }

    /// Returns `true` if this feature is always enabled when entitled,
    /// matching Go's `FeatureName.AlwaysEnable()`.
    #[must_use]
    pub fn always_enable(self) -> bool {
        matches!(
            self,
            Self::MultipleExternalAuth
                | Self::ExternalProvisionerDaemons
                | Self::Appearance
                | Self::WorkspaceBatchActions
                | Self::TaskBatchActions
                | Self::HighAvailability
                | Self::CustomRoles
                | Self::MultipleOrganizations
                | Self::WorkspacePrebuilds
                | Self::WorkspaceExternalAgent
                | Self::Boundary
        )
    }

    /// Returns `true` if this feature uses a numeric limit rather than
    /// a boolean entitlement.
    #[must_use]
    pub fn uses_limit(self) -> bool {
        matches!(
            self,
            Self::UserLimit | Self::ManagedAgentLimit | Self::AiGovernanceUserLimit
        )
    }

    /// Returns `true` if this feature is part of the Enterprise feature set
    /// (as opposed to Premium-only features).
    #[must_use]
    pub fn is_enterprise(self) -> bool {
        !matches!(self, Self::MultipleOrganizations | Self::CustomRoles)
    }
}

impl std::fmt::Display for FeatureName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
