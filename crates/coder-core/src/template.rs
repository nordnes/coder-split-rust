//! Template domain types used by the template and template version slices.

use std::collections::HashMap;

use time::OffsetDateTime;
use uuid::Uuid;

use crate::ports::StorageError;

/// A persisted template record.
#[derive(Clone, Debug, PartialEq)]
pub struct TemplateRecord {
    /// Stable template identifier.
    pub id: Uuid,
    /// Template creation time.
    pub created_at: OffsetDateTime,
    /// Last update time.
    pub updated_at: OffsetDateTime,
    /// Owning organization identifier.
    pub organization_id: Uuid,
    /// Organization name.
    pub organization_name: String,
    /// Organization display name.
    pub organization_display_name: String,
    /// Organization icon.
    pub organization_icon: String,
    /// Whether the template is soft-deleted.
    pub deleted: bool,
    /// Template slug name.
    pub name: String,
    /// Provisioner type.
    pub provisioner: String,
    /// Active template version identifier.
    pub active_version_id: Uuid,
    /// Template description.
    pub description: String,
    /// Default TTL in nanoseconds.
    pub default_ttl: i64,
    /// Creator user identifier.
    pub created_by: Uuid,
    /// Icon URL or path.
    pub icon: String,
    /// User ACL as JSON.
    pub user_acl: HashMap<String, serde_json::Value>,
    /// Group ACL as JSON.
    pub group_acl: HashMap<String, serde_json::Value>,
    /// Human-friendly display name.
    pub display_name: String,
    /// Whether users can cancel workspace jobs.
    pub allow_user_cancel_workspace_jobs: bool,
    /// Whether users can autostart.
    pub allow_user_autostart: bool,
    /// Whether users can autostop.
    pub allow_user_autostop: bool,
    /// Failure TTL in nanoseconds.
    pub failure_ttl: i64,
    /// Time til dormant in nanoseconds.
    pub time_til_dormant: i64,
    /// Time til dormant auto-delete in nanoseconds.
    pub time_til_dormant_autodelete: i64,
    /// Autostop requirement days of week bitmask.
    pub autostop_requirement_days_of_week: i16,
    /// Autostop requirement weeks.
    pub autostop_requirement_weeks: i64,
    /// Autostart block days of week bitmask.
    pub autostart_block_days_of_week: i16,
    /// Whether active version is required.
    pub require_active_version: bool,
    /// Deprecation message (empty if not deprecated).
    pub deprecated: String,
    /// Activity bump duration in nanoseconds.
    pub activity_bump: i64,
    /// Max port sharing level.
    pub max_port_sharing_level: String,
    /// Whether to use classic parameter flow.
    pub use_classic_parameter_flow: bool,
    /// CORS behavior.
    pub cors_behavior: String,
    /// Whether module cache is disabled.
    pub disable_module_cache: bool,
    /// Creator username.
    pub created_by_username: String,
    /// Creator avatar URL.
    pub created_by_avatar_url: String,
    /// Creator display name.
    pub created_by_name: String,
}

/// A persisted provisioner job record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvisionerJobRecord {
    /// Job identifier.
    pub id: Uuid,
    /// Job creation time.
    pub created_at: OffsetDateTime,
    /// Job update time.
    pub updated_at: OffsetDateTime,
    /// Job start time.
    pub started_at: Option<OffsetDateTime>,
    /// Job cancel time.
    pub canceled_at: Option<OffsetDateTime>,
    /// Job completion time.
    pub completed_at: Option<OffsetDateTime>,
    /// Error text.
    pub error: String,
    /// Organization identifier.
    pub organization_id: Uuid,
    /// Initiator user identifier.
    pub initiator_id: Uuid,
    /// Provisioner type.
    pub provisioner: String,
    /// Job status.
    pub job_status: String,
    /// File identifier.
    pub file_id: Option<Uuid>,
    /// Job type.
    pub job_type: String,
    /// Input JSON.
    pub input: serde_json::Value,
    /// Worker identifier.
    pub worker_id: Option<Uuid>,
    /// Tags JSON.
    pub tags: HashMap<String, String>,
}

/// A persisted template version record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplateVersionRecord {
    /// Version identifier.
    pub id: Uuid,
    /// Owning template identifier.
    pub template_id: Option<Uuid>,
    /// Organization identifier.
    pub organization_id: Uuid,
    /// Version creation time.
    pub created_at: OffsetDateTime,
    /// Version update time.
    pub updated_at: OffsetDateTime,
    /// Version name.
    pub name: String,
    /// README content.
    pub readme: String,
    /// Provisioner job identifier.
    pub job_id: Uuid,
    /// Creator user identifier.
    pub created_by: Uuid,
    /// External auth providers JSON.
    pub external_auth_providers: serde_json::Value,
    /// Commit-style message.
    pub message: String,
    /// Whether the version is archived.
    pub archived: bool,
    /// Source example identifier.
    pub source_example_id: Option<String>,
    /// Whether the version has an AI task.
    pub has_ai_task: Option<bool>,
    /// Whether the version has an external agent.
    pub has_external_agent: Option<bool>,
    /// Creator avatar URL.
    pub created_by_avatar_url: String,
    /// Creator username.
    pub created_by_username: String,
    /// Creator display name.
    pub created_by_name: String,
}

/// A persisted template version parameter record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplateVersionParameterRecord {
    /// Owning template version identifier.
    pub template_version_id: Uuid,
    /// Parameter name.
    pub name: String,
    /// Parameter description.
    pub description: String,
    /// Parameter type.
    pub param_type: String,
    /// Whether the parameter is mutable.
    pub mutable: bool,
    /// Default value.
    pub default_value: String,
    /// Icon.
    pub icon: String,
    /// Selectable options as JSON.
    pub options: serde_json::Value,
    /// Validation regex.
    pub validation_regex: String,
    /// Minimum validation value.
    pub validation_min: Option<i32>,
    /// Maximum validation value.
    pub validation_max: Option<i32>,
    /// Validation error message.
    pub validation_error: String,
    /// Monotonic order validation.
    pub validation_monotonic: String,
    /// Whether the parameter is required.
    pub required: bool,
    /// Display name.
    pub display_name: String,
    /// Display order.
    pub display_order: i32,
    /// Whether the parameter is ephemeral.
    pub ephemeral: bool,
    /// Form type.
    pub form_type: String,
}

/// A persisted template version variable record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplateVersionVariableRecord {
    /// Owning template version identifier.
    pub template_version_id: Uuid,
    /// Variable name.
    pub name: String,
    /// Variable description.
    pub description: String,
    /// Variable type.
    pub var_type: String,
    /// Current value.
    pub value: String,
    /// Default value.
    pub default_value: String,
    /// Whether the variable is required.
    pub required: bool,
    /// Whether the variable is sensitive.
    pub sensitive: bool,
}

/// A persisted template version preset record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplateVersionPresetRecord {
    /// Preset identifier.
    pub id: Uuid,
    /// Owning template version identifier.
    pub template_version_id: Uuid,
    /// Preset name.
    pub name: String,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Whether this is the default preset.
    pub is_default: bool,
    /// Description.
    pub description: String,
    /// Icon.
    pub icon: String,
}

/// A persisted template version preset parameter record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplateVersionPresetParameterRecord {
    /// Preset parameter identifier.
    pub id: Uuid,
    /// Owning preset identifier.
    pub template_version_preset_id: Uuid,
    /// Parameter name.
    pub name: String,
    /// Parameter value.
    pub value: String,
}

/// Input for creating a template.
#[derive(Clone, Debug)]
pub struct CreateTemplateInput {
    /// Template identifier.
    pub id: Uuid,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Update time.
    pub updated_at: OffsetDateTime,
    /// Organization identifier.
    pub organization_id: Uuid,
    /// Template name.
    pub name: String,
    /// Display name.
    pub display_name: String,
    /// Provisioner type.
    pub provisioner: String,
    /// Active version identifier.
    pub active_version_id: Uuid,
    /// Description.
    pub description: String,
    /// Default TTL in nanoseconds.
    pub default_ttl: i64,
    /// Creator user identifier.
    pub created_by: Uuid,
    /// Icon path or URL.
    pub icon: String,
    /// Allow user cancel workspace jobs.
    pub allow_user_cancel_workspace_jobs: bool,
    /// Allow user autostart.
    pub allow_user_autostart: bool,
    /// Allow user autostop.
    pub allow_user_autostop: bool,
    /// Failure TTL in nanoseconds.
    pub failure_ttl: i64,
    /// Time til dormant in nanoseconds.
    pub time_til_dormant: i64,
    /// Time til dormant auto-delete in nanoseconds.
    pub time_til_dormant_autodelete: i64,
    /// Require active version.
    pub require_active_version: bool,
    /// Activity bump duration in nanoseconds.
    pub activity_bump: i64,
    /// Max port share level.
    pub max_port_share_level: String,
}

/// Input for creating a template version.
#[derive(Clone, Debug)]
pub struct CreateTemplateVersionInput {
    /// Version identifier.
    pub id: Uuid,
    /// Template identifier (optional for unattached versions).
    pub template_id: Option<Uuid>,
    /// Organization identifier.
    pub organization_id: Uuid,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Update time.
    pub updated_at: OffsetDateTime,
    /// Version name.
    pub name: String,
    /// Commit-style message.
    pub message: String,
    /// README content.
    pub readme: String,
    /// Provisioner job identifier.
    pub job_id: Uuid,
    /// Creator user identifier.
    pub created_by: Uuid,
    /// Source example identifier.
    pub source_example_id: Option<String>,
}

/// Input for creating a provisioner job.
#[derive(Clone, Debug)]
pub struct CreateProvisionerJobInput {
    /// Job identifier.
    pub id: Uuid,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Update time.
    pub updated_at: OffsetDateTime,
    /// Organization identifier.
    pub organization_id: Uuid,
    /// Initiator user identifier.
    pub initiator_id: Uuid,
    /// Provisioner type.
    pub provisioner: String,
    /// File identifier.
    pub file_id: Option<Uuid>,
    /// Job type.
    pub job_type: String,
    /// Input JSON.
    pub input: serde_json::Value,
    /// Tags.
    pub tags: HashMap<String, String>,
}

/// Template list filter for store queries.
#[derive(Clone, Debug, Default)]
pub struct TemplateListFilter {
    /// Organization identifier.
    pub organization_id: Option<Uuid>,
    /// Exact name match.
    pub exact_name: Option<String>,
    /// Fuzzy search.
    pub search: Option<String>,
    /// Include deleted templates.
    pub deleted: bool,
}

/// Template version list filter.
#[derive(Clone, Debug, Default)]
pub struct TemplateVersionListFilter {
    /// Template identifier.
    pub template_id: Uuid,
    /// Include archived versions.
    pub include_archived: bool,
    /// Limit.
    pub limit: u32,
    /// Offset.
    pub offset: u32,
}

/// DAU entry for template usage stats.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplateDAURow {
    /// Date of the entry.
    pub date: String,
    /// Number of active users.
    pub amount: i32,
}

/// Template creation error.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum CreateTemplateStoreError {
    /// A template with the same name already exists in the organization.
    #[error("template already exists")]
    AlreadyExists,
    /// A storage failure occurred.
    #[error("{0}")]
    Storage(#[from] StorageError),
}
