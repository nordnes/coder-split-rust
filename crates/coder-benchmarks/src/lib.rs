//! Shared benchmark utilities: mock store and helpers.
//!
//! This crate provides a lightweight `BenchStore` that implements
//! `AppStore` with stub methods, plus a few real in-memory
//! implementations for the methods exercised by store benchmarks.

#![allow(clippy::too_many_arguments)]

use std::collections::HashMap;

use async_trait::async_trait;
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use coder_core::ports::{
    AppStore, DeploymentMetadata, DeploymentStore, ProvisionerStore, StorageError,
    UpdateWorkspaceACLInput, WorkspaceACLRecord, WorkspaceTransitionRow,
};

use coder_core::template::ProvisionerJobRecord as TemplateProvisionerJobRecord;
use coder_core::*;

/// A lightweight in-memory store for benchmarking.
///
/// Most methods return `StorageError::unavailable` since benchmarks
/// only exercise a handful of store paths.
#[derive(Debug)]
pub struct BenchStore {
    /// In-memory user storage keyed by user ID.
    pub users: std::sync::Mutex<HashMap<Uuid, UserRecord>>,
    /// In-memory organization storage keyed by org ID.
    pub organizations: std::sync::Mutex<HashMap<Uuid, OrganizationRecord>>,
    /// In-memory template storage keyed by template ID.
    pub templates: std::sync::Mutex<HashMap<Uuid, coder_core::template::TemplateRecord>>,
}

impl BenchStore {
    /// Creates a new empty bench store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            users: std::sync::Mutex::new(HashMap::new()),
            organizations: std::sync::Mutex::new(HashMap::new()),
            templates: std::sync::Mutex::new(HashMap::new()),
        }
    }
}

impl Default for BenchStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DeploymentStore for BenchStore {
    async fn ping(&self) -> Result<(), StorageError> {
        Ok(())
    }

    async fn ensure_deployment_metadata(&self) -> Result<DeploymentMetadata, StorageError> {
        Ok(DeploymentMetadata {
            deployment_id: Uuid::nil(),
        })
    }
}

#[async_trait]
impl ProvisionerStore for BenchStore {
    async fn acquire_provisioner_job(
        &self,
        _input: AcquireProvisionerJobInput,
    ) -> Result<Option<ProvisionerJobRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn get_provisioner_job_by_id(
        &self,
        _id: Uuid,
    ) -> Result<Option<ProvisionerJobRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn get_provisioner_jobs_by_ids(
        &self,
        _ids: &[Uuid],
    ) -> Result<Vec<ProvisionerJobRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn insert_provisioner_job(
        &self,
        _input: InsertProvisionerJobInput,
    ) -> Result<ProvisionerJobRecord, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_provisioner_job_by_id(
        &self,
        _id: Uuid,
        _updated_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_provisioner_job_with_complete_by_id(
        &self,
        _input: CompleteProvisionerJobInput,
    ) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_provisioner_job_with_cancel_by_id(
        &self,
        _input: CancelProvisionerJobInput,
    ) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn get_provisioner_jobs_to_be_reaped(
        &self,
        _input: GetJobsToBeReapedInput,
    ) -> Result<Vec<ProvisionerJobRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn insert_provisioner_job_logs(
        &self,
        _input: InsertProvisionerJobLogsInput,
    ) -> Result<Vec<coder_core::provisioner::ProvisionerJobLogRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn get_provisioner_logs_after_id(
        &self,
        _job_id: Uuid,
        _after_id: i64,
    ) -> Result<Vec<coder_core::provisioner::ProvisionerJobLogRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn insert_provisioner_job_timings(
        &self,
        _input: InsertProvisionerJobTimingsInput,
    ) -> Result<Vec<coder_core::provisioner::ProvisionerJobTimingRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn get_provisioner_job_timings_by_job_id(
        &self,
        _job_id: Uuid,
    ) -> Result<Vec<coder_core::provisioner::ProvisionerJobTimingRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn upsert_provisioner_daemon(
        &self,
        _input: UpsertProvisionerDaemonInput,
    ) -> Result<ProvisionerDaemonRecord, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_provisioner_daemon_last_seen_at(
        &self,
        _id: Uuid,
        _last_seen_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn get_provisioner_daemons_by_organization(
        &self,
        _organization_id: Uuid,
    ) -> Result<Vec<ProvisionerDaemonRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn delete_old_provisioner_daemons(&self) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn insert_provisioner_key(
        &self,
        _input: InsertProvisionerKeyInput,
    ) -> Result<ProvisionerKeyRecord, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn get_provisioner_key_by_id(
        &self,
        _id: Uuid,
    ) -> Result<Option<ProvisionerKeyRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn get_provisioner_key_by_hashed_secret(
        &self,
        _hashed_secret: &[u8],
    ) -> Result<Option<ProvisionerKeyRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn get_provisioner_key_by_name(
        &self,
        _organization_id: Uuid,
        _name: &str,
    ) -> Result<Option<ProvisionerKeyRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_provisioner_keys_by_organization(
        &self,
        _organization_id: Uuid,
    ) -> Result<Vec<ProvisionerKeyRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_provisioner_keys_by_organization_exclude_reserved(
        &self,
        _organization_id: Uuid,
    ) -> Result<Vec<ProvisionerKeyRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn delete_provisioner_key(&self, _id: Uuid) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }
}

#[async_trait]
impl AppStore for BenchStore {
    async fn first_user_exists(&self) -> Result<bool, StorageError> {
        let guard = self
            .users
            .lock()
            .map_err(|_| StorageError::unavailable("lock poisoned"))?;
        Ok(!guard.is_empty())
    }

    async fn create_first_user(
        &self,
        _user: CreateFirstUserInput,
    ) -> Result<coder_core::FirstUserRecord, CreateFirstUserStoreError> {
        Err(CreateFirstUserStoreError::Storage(
            StorageError::unavailable("bench stub"),
        ))
    }

    async fn find_password_user_by_email(
        &self,
        _email: &str,
    ) -> Result<Option<PasswordUserRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_password_user_by_id(
        &self,
        _user_id: Uuid,
    ) -> Result<Option<PasswordUserRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn insert_auth_session(
        &self,
        _token_hash: &[u8],
        _user_id: Uuid,
    ) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_user_by_session_token_hash(
        &self,
        _token_hash: &[u8],
    ) -> Result<Option<AuthenticatedUser>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn delete_auth_session(&self, _token_hash: &[u8]) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_users(
        &self,
        _filter: UserListFilter,
    ) -> Result<(Vec<UserRecord>, usize), StorageError> {
        let guard = self
            .users
            .lock()
            .map_err(|_| StorageError::unavailable("lock poisoned"))?;
        let users: Vec<UserRecord> = guard.values().cloned().collect();
        let count = users.len();
        Ok((users, count))
    }

    async fn create_user(
        &self,
        _input: CreateUserInput,
    ) -> Result<UserRecord, CreateUserStoreError> {
        Err(CreateUserStoreError::Storage(StorageError::unavailable(
            "bench stub",
        )))
    }

    async fn find_user_by_id(&self, user_id: Uuid) -> Result<Option<UserRecord>, StorageError> {
        let guard = self
            .users
            .lock()
            .map_err(|_| StorageError::unavailable("lock poisoned"))?;
        Ok(guard.get(&user_id).cloned())
    }

    async fn find_user_by_username(
        &self,
        username: &str,
    ) -> Result<Option<UserRecord>, StorageError> {
        let guard = self
            .users
            .lock()
            .map_err(|_| StorageError::unavailable("lock poisoned"))?;
        Ok(guard.values().find(|u| u.username == username).cloned())
    }

    async fn soft_delete_user(&self, _user_id: Uuid) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_user_memberships(
        &self,
        _user_id: Uuid,
    ) -> Result<Vec<OrganizationMemberRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_user_roles(
        &self,
        _user_id: Uuid,
        _roles: Vec<String>,
    ) -> Result<Option<UserRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_user_profile(
        &self,
        _user_id: Uuid,
        _username: &str,
        _name: &str,
    ) -> Result<Option<UserRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_user_status(
        &self,
        _user_id: Uuid,
        _status: UserStatus,
    ) -> Result<Option<UserRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn user_appearance(&self, _user_id: Uuid) -> Result<UserAppearanceRecord, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_user_appearance(
        &self,
        _user_id: Uuid,
        _theme_preference: &str,
        _terminal_font: &str,
    ) -> Result<Option<UserAppearanceRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn user_preferences(&self, _user_id: Uuid) -> Result<UserPreferenceRecord, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_user_preferences(
        &self,
        _user_id: Uuid,
        _task_notification_alert_dismissed: bool,
    ) -> Result<Option<UserPreferenceRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_organizations(
        &self,
        organization_ids: Vec<Uuid>,
    ) -> Result<Vec<OrganizationRecord>, StorageError> {
        let guard = self
            .organizations
            .lock()
            .map_err(|_| StorageError::unavailable("lock poisoned"))?;
        Ok(guard
            .values()
            .filter(|org| organization_ids.is_empty() || organization_ids.contains(&org.id))
            .cloned()
            .collect())
    }

    async fn find_organization_by_id(
        &self,
        _organization_id: Uuid,
    ) -> Result<Option<OrganizationRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_organization_by_name(
        &self,
        _name: &str,
    ) -> Result<Option<OrganizationRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_organization_members(
        &self,
        _filter: OrganizationMemberListFilter,
    ) -> Result<Vec<OrganizationMemberRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_organization_members_page(
        &self,
        _filter: OrganizationMemberListFilter,
    ) -> Result<(Vec<OrganizationMemberRecord>, usize), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_organization_member(
        &self,
        _organization_id: Uuid,
        _user_id: Uuid,
    ) -> Result<Option<OrganizationMemberRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn insert_organization_member(
        &self,
        _organization_id: Uuid,
        _user_id: Uuid,
    ) -> Result<OrganizationMemberRecord, InsertOrganizationMemberError> {
        Err(InsertOrganizationMemberError::Storage(
            StorageError::unavailable("bench stub"),
        ))
    }

    async fn delete_organization_member(
        &self,
        _organization_id: Uuid,
        _user_id: Uuid,
    ) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_organization_member_roles(
        &self,
        _organization_id: Uuid,
        _user_id: Uuid,
        _roles: Vec<String>,
    ) -> Result<Option<OrganizationMemberRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn store_one_time_passcode_by_email(
        &self,
        _email: &str,
        _passcode_hash: &str,
        _expires_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn replace_user_password(
        &self,
        _user_id: Uuid,
        _password_hash: &str,
        _clear_one_time_passcode: bool,
    ) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn create_api_key(
        &self,
        _input: CreateApiKeyInput,
    ) -> Result<ApiKeyRecord, CreateApiKeyStoreError> {
        Err(CreateApiKeyStoreError::Storage(StorageError::unavailable(
            "bench stub",
        )))
    }

    async fn find_api_key_by_id(&self, _id: &str) -> Result<Option<ApiKeyRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_api_key_by_name(
        &self,
        _user_id: Uuid,
        _token_name: &str,
    ) -> Result<Option<ApiKeyRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_api_keys(
        &self,
        _filter: ApiKeyListFilter,
    ) -> Result<Vec<ApiKeyWithOwnerRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn delete_api_key(&self, _id: &str) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn expire_api_key(&self, _id: &str, _now: OffsetDateTime) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_api_key_last_used(
        &self,
        _id: &str,
        _last_used: OffsetDateTime,
        _expires_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_user_last_seen_at(
        &self,
        _user_id: Uuid,
        _last_seen_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn token_config(&self, _user_id: Uuid) -> Result<TokenConfigRecord, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_audit_logs(
        &self,
        _filter: AuditLogListFilter,
    ) -> Result<AuditLogResponse, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn insert_audit_log(&self, _input: PersistAuditLogInput) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn batch_insert_audit_logs(
        &self,
        _logs: Vec<PersistAuditLogInput>,
    ) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_connection_logs(
        &self,
        _filter: coder_core::ports::ConnectionLogListFilter,
    ) -> Result<coder_core::ConnectionLogResponse, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn delete_old_connection_logs(
        &self,
        _older_than: time::OffsetDateTime,
        _limit: i64,
    ) -> Result<u64, StorageError> {
        Ok(0)
    }

    async fn health_settings(&self) -> Result<HealthSettings, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn upsert_health_settings(
        &self,
        _settings: &HealthSettings,
    ) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn appearance_config(&self) -> Result<coder_core::api::AppearanceConfig, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn upsert_appearance_config(
        &self,
        _config: &coder_core::api::AppearanceConfig,
    ) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn prebuilds_settings(&self) -> Result<coder_core::api::PrebuildsSettings, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn upsert_prebuilds_settings(
        &self,
        _settings: &coder_core::api::PrebuildsSettings,
    ) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn deployment_stats(&self) -> Result<DeploymentStatsResponse, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn upsert_workspace_stats_workspace(
        &self,
        _input: &WorkspaceStatsWorkspaceInput,
    ) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn upsert_provisioner_job_stats(
        &self,
        _input: &ProvisionerJobStatsInput,
    ) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn upsert_workspace_build_stats(
        &self,
        _input: &WorkspaceBuildStatsInput,
    ) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn insert_workspace_agent_stat(
        &self,
        _input: &WorkspaceAgentStatInput,
    ) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_workspace_proxies_for_health(
        &self,
    ) -> Result<Vec<WorkspaceProxyHealthRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn upsert_workspace_proxy_for_health(
        &self,
        _input: &WorkspaceProxyHealthInput,
    ) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_provisioner_daemons_for_health(
        &self,
    ) -> Result<Vec<ProvisionerDaemonHealthRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn upsert_provisioner_daemon_for_health(
        &self,
        _input: &ProvisionerDaemonHealthInput,
    ) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_git_ssh_key(
        &self,
        _user_id: Uuid,
    ) -> Result<Option<GitSshKeyRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn upsert_git_ssh_key(
        &self,
        _user_id: Uuid,
        _public_key: &str,
        _private_key: &str,
    ) -> Result<GitSshKeyRecord, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_external_auth_links(
        &self,
        _user_id: Uuid,
    ) -> Result<Vec<ExternalAuthLinkRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_external_auth_link(
        &self,
        _user_id: Uuid,
        _provider_id: &str,
    ) -> Result<Option<ExternalAuthLinkRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn delete_external_auth_link(
        &self,
        _user_id: Uuid,
        _provider_id: &str,
    ) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn upsert_external_auth_link(
        &self,
        _user_id: Uuid,
        _link: &UpsertExternalAuthLinkInput,
    ) -> Result<ExternalAuthLinkRecord, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn get_deployment_daus(
        &self,
        _tz_offset: i32,
    ) -> Result<coder_core::api::DAUsResponse, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn get_template_insights(
        &self,
        _start_time: OffsetDateTime,
        _end_time: OffsetDateTime,
        _interval: coder_core::api::InsightsReportInterval,
        _template_ids: Vec<Uuid>,
    ) -> Result<coder_core::api::TemplateInsightsResponse, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn get_template_insights_by_interval(
        &self,
        _start_time: OffsetDateTime,
        _end_time: OffsetDateTime,
        _interval: coder_core::api::InsightsReportInterval,
        _template_ids: Vec<Uuid>,
    ) -> Result<Vec<coder_core::api::TemplateInsightsIntervalReport>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn get_user_activity_insights(
        &self,
        _start_time: OffsetDateTime,
        _end_time: OffsetDateTime,
        _template_ids: Vec<Uuid>,
    ) -> Result<coder_core::api::UserActivityInsightsResponse, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn get_user_latency_insights(
        &self,
        _start_time: OffsetDateTime,
        _end_time: OffsetDateTime,
        _template_ids: Vec<Uuid>,
    ) -> Result<coder_core::api::UserLatencyInsightsResponse, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn get_user_status_counts(
        &self,
        _timezone: &str,
        _start_time: OffsetDateTime,
        _end_time: OffsetDateTime,
    ) -> Result<coder_core::api::GetUserStatusCountsResponse, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn insert_task(&self, _input: InsertTaskInput) -> Result<TaskRecord, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_task_by_id(&self, _id: Uuid) -> Result<Option<TaskRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_task_by_owner_and_name(
        &self,
        _owner_id: Uuid,
        _name: &str,
    ) -> Result<Option<TaskRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_tasks(&self, _filter: TaskListFilter) -> Result<Vec<TaskRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn delete_task(
        &self,
        _id: Uuid,
        _deleted_at: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_task_prompt(
        &self,
        _id: Uuid,
        _prompt: &str,
    ) -> Result<Option<TaskRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn upsert_task_snapshot(
        &self,
        _task_id: Uuid,
        _log_snapshot: &Value,
        _log_snapshot_created_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_task_snapshot(
        &self,
        _task_id: Uuid,
    ) -> Result<Option<TaskSnapshotRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn insert_chat(&self, _input: InsertChatInput) -> Result<ChatRecord, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_chat_by_id(&self, _id: Uuid) -> Result<Option<ChatRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_chats_by_owner(
        &self,
        _owner_id: Uuid,
        _archived: Option<bool>,
    ) -> Result<Vec<ChatRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn archive_chat(&self, _id: Uuid) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_chat_messages(
        &self,
        _chat_id: Uuid,
        _after_id: i64,
    ) -> Result<Vec<ChatMessageRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn insert_chat_message(
        &self,
        _input: InsertChatMessageInput,
    ) -> Result<ChatMessageRecord, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_chat_queued_messages(
        &self,
        _chat_id: Uuid,
    ) -> Result<Vec<ChatQueuedMessageRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn unarchive_chat(&self, _id: Uuid) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_chat_status(
        &self,
        _id: Uuid,
        _status: ChatStatus,
    ) -> Result<ChatRecord, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn get_chat_diff_status(
        &self,
        _chat_id: Uuid,
    ) -> Result<Option<coder_core::api::ChatDiffStatusResponse>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn get_chat_diff_contents(
        &self,
        _chat_id: Uuid,
    ) -> Result<coder_core::api::ChatDiffContentsResponse, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn get_enabled_chat_providers(
        &self,
    ) -> Result<Vec<coder_core::api::ChatModelProvider>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn insert_chat_file(
        &self,
        _input: InsertChatFileInput,
    ) -> Result<coder_core::ChatFileRecord, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_chat_file_by_id(
        &self,
        _id: Uuid,
    ) -> Result<Option<coder_core::ChatFileRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_chat_message_content(
        &self,
        _input: coder_core::UpdateChatMessageContentInput,
    ) -> Result<ChatMessageRecord, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn delete_chat_queued_message(
        &self,
        _chat_id: Uuid,
        _queued_message_id: i64,
    ) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn promote_chat_queued_message(
        &self,
        _chat_id: Uuid,
        _queued_message_id: i64,
    ) -> Result<ChatQueuedMessageRecord, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_chat_providers(
        &self,
    ) -> Result<Vec<coder_core::ChatProviderRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn insert_chat_provider(
        &self,
        _input: coder_core::InsertChatProviderInput,
    ) -> Result<coder_core::ChatProviderRecord, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_chat_provider(
        &self,
        _input: coder_core::UpdateChatProviderInput,
    ) -> Result<coder_core::ChatProviderRecord, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn delete_chat_provider(&self, _provider_id: Uuid) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_chat_model_configs(
        &self,
        _enabled_only: bool,
    ) -> Result<Vec<coder_core::ChatModelConfigRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn insert_chat_model_config(
        &self,
        _input: coder_core::InsertChatModelConfigInput,
    ) -> Result<coder_core::ChatModelConfigRecord, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_chat_model_config(
        &self,
        _input: coder_core::UpdateChatModelConfigInput,
    ) -> Result<coder_core::ChatModelConfigRecord, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn delete_chat_model_config(&self, _config_id: Uuid) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn ensure_default_chat_model_config(&self) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn unset_default_chat_model_configs(&self) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn get_notifications_settings(
        &self,
    ) -> Result<coder_core::NotificationsSettings, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn upsert_notifications_settings(
        &self,
        _settings: &coder_core::NotificationsSettings,
    ) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn get_notification_templates_by_kind(
        &self,
        _kind: &str,
    ) -> Result<Vec<coder_core::NotificationTemplate>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_notification_template_method(
        &self,
        _template_id: Uuid,
        _method: Option<&str>,
    ) -> Result<Option<coder_core::NotificationTemplate>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn get_user_notification_preferences(
        &self,
        _user_id: Uuid,
    ) -> Result<Vec<coder_core::NotificationPreference>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_user_notification_preferences(
        &self,
        _user_id: Uuid,
        _template_ids: &[Uuid],
        _disableds: &[bool],
    ) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn insert_inbox_notification(
        &self,
        _notification: &coder_core::InboxNotification,
    ) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn get_filtered_inbox_notifications(
        &self,
        _user_id: Uuid,
        _templates: Option<&[Uuid]>,
        _targets: Option<&[Uuid]>,
        _read_status: &str,
        _created_before: Option<OffsetDateTime>,
    ) -> Result<Vec<coder_core::InboxNotification>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn count_unread_inbox_notifications(&self, _user_id: Uuid) -> Result<i64, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn get_inbox_notification_by_id(
        &self,
        _id: Uuid,
    ) -> Result<Option<coder_core::InboxNotification>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_inbox_notification_read_status(
        &self,
        _id: Uuid,
        _read_at: Option<OffsetDateTime>,
    ) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn mark_all_inbox_notifications_as_read(
        &self,
        _user_id: Uuid,
        _read_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn get_webpush_subscriptions_by_user_id(
        &self,
        _user_id: Uuid,
    ) -> Result<Vec<coder_core::WebpushSubscriptionRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn insert_webpush_subscription(
        &self,
        _user_id: Uuid,
        _endpoint: &str,
        _p256dh_key: &str,
        _auth_key: &str,
    ) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn delete_webpush_subscription_by_user_and_endpoint(
        &self,
        _user_id: Uuid,
        _endpoint: &str,
    ) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn delete_webpush_subscriptions(&self, _ids: &[Uuid]) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn delete_all_webpush_subscriptions(&self) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn get_webpush_vapid_keys(
        &self,
    ) -> Result<Option<coder_core::api::VapidKeyPair>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn upsert_webpush_vapid_keys(
        &self,
        _public_key: &str,
        _private_key: &str,
    ) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_templates(
        &self,
        _filter: TemplateListFilter,
    ) -> Result<Vec<TemplateRecord>, StorageError> {
        let guard = self
            .templates
            .lock()
            .map_err(|_| StorageError::unavailable("lock poisoned"))?;
        Ok(guard.values().cloned().collect())
    }

    async fn find_template_by_id(
        &self,
        template_id: Uuid,
    ) -> Result<Option<TemplateRecord>, StorageError> {
        let guard = self
            .templates
            .lock()
            .map_err(|_| StorageError::unavailable("lock poisoned"))?;
        Ok(guard.get(&template_id).cloned())
    }

    async fn find_template_by_org_and_name(
        &self,
        _organization_id: Uuid,
        _name: &str,
    ) -> Result<Option<TemplateRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn insert_template(
        &self,
        _input: CreateTemplateInput,
    ) -> Result<TemplateRecord, CreateTemplateStoreError> {
        Err(CreateTemplateStoreError::Storage(
            StorageError::unavailable("bench stub"),
        ))
    }

    async fn update_template_meta(
        &self,
        _input: UpdateTemplateMetaInput,
    ) -> Result<Option<TemplateRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn soft_delete_template(&self, _template_id: Uuid) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_template_active_version(
        &self,
        _template_id: Uuid,
        _active_version_id: Uuid,
    ) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn template_daus(&self, _template_id: Uuid) -> Result<Vec<TemplateDAURow>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_template_versions(
        &self,
        _filter: TemplateVersionListFilter,
    ) -> Result<Vec<TemplateVersionRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_template_version_by_id(
        &self,
        _version_id: Uuid,
    ) -> Result<Option<TemplateVersionRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_template_version_by_template_and_name(
        &self,
        _template_id: Uuid,
        _name: &str,
    ) -> Result<Option<TemplateVersionRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_template_version_by_org_and_name(
        &self,
        _organization_id: Uuid,
        _template_name: &str,
        _version_name: &str,
    ) -> Result<Option<TemplateVersionRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_previous_template_version(
        &self,
        _organization_id: Uuid,
        _template_name: &str,
        _version_name: &str,
    ) -> Result<Option<TemplateVersionRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn insert_template_version(
        &self,
        _input: CreateTemplateVersionInput,
    ) -> Result<TemplateVersionRecord, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_template_version(
        &self,
        _version_id: Uuid,
        _name: &str,
        _message: &str,
    ) -> Result<Option<TemplateVersionRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn archive_template_version(&self, _version_id: Uuid) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn unarchive_template_version(&self, _version_id: Uuid) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_template_version_parameters(
        &self,
        _version_id: Uuid,
    ) -> Result<Vec<TemplateVersionParameterRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_template_version_variables(
        &self,
        _version_id: Uuid,
    ) -> Result<Vec<TemplateVersionVariableRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_template_version_presets(
        &self,
        _version_id: Uuid,
    ) -> Result<Vec<TemplateVersionPresetRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_template_version_preset_parameters(
        &self,
        _preset_id: Uuid,
    ) -> Result<Vec<TemplateVersionPresetParameterRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn create_provisioner_job(
        &self,
        _input: CreateProvisionerJobInput,
    ) -> Result<TemplateProvisionerJobRecord, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_provisioner_job(
        &self,
        _job_id: Uuid,
    ) -> Result<Option<TemplateProvisionerJobRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_provisioner_jobs_by_organization(
        &self,
        _organization_id: Uuid,
    ) -> Result<Vec<TemplateProvisionerJobRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn cancel_template_provisioner_job(&self, _job_id: Uuid) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn insert_file(&self, _input: InsertFileInput) -> Result<InsertFileResult, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn get_file_by_id(&self, _file_id: Uuid) -> Result<Option<FileRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn get_file_by_hash_and_creator(
        &self,
        _hash: &str,
        _creator_id: Uuid,
    ) -> Result<Option<FileRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn delete_file(&self, _file_id: Uuid) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn get_organization_idp_sync_settings(
        &self,
    ) -> Result<coder_core::api::OrganizationSyncSettings, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn upsert_organization_idp_sync_settings(
        &self,
        _settings: &coder_core::api::OrganizationSyncSettings,
    ) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn archive_unused_template_versions(
        &self,
        _template_id: Uuid,
        _all: bool,
    ) -> Result<Vec<Uuid>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn get_previous_template_version(
        &self,
        _organization_id: Uuid,
        _name: &str,
        _template_id: Option<Uuid>,
    ) -> Result<Option<TemplateVersionRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn get_template_user_roles(
        &self,
        _template_id: Uuid,
    ) -> Result<Vec<coder_core::ports::TemplateUserRoleRow>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn get_template_group_roles(
        &self,
        _template_id: Uuid,
    ) -> Result<Vec<coder_core::ports::TemplateGroupRoleRow>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_template_acl(
        &self,
        _template_id: Uuid,
        _input: &coder_core::ports::UpdateTemplateACLInput,
    ) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn invalidate_template_presets(
        &self,
        _template_id: Uuid,
    ) -> Result<Vec<coder_core::ports::InvalidatedPresetRow>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_workspace_agent_by_id(
        &self,
        _agent_id: Uuid,
    ) -> Result<Option<WorkspaceAgentRow>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_workspace_agent_by_auth_token(
        &self,
        _auth_token: Uuid,
    ) -> Result<Option<WorkspaceAgentRow>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_workspace_by_agent_id(
        &self,
        _agent_id: Uuid,
    ) -> Result<Option<WorkspaceRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn insert_workspace_agent_log_source(
        &self,
        _agent_id: Uuid,
        _id: Option<Uuid>,
        _display_name: &str,
        _icon: &str,
    ) -> Result<WorkspaceAgentLogSourceRow, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_workspace_agent_log_sources(
        &self,
        _agent_id: Uuid,
    ) -> Result<Vec<WorkspaceAgentLogSourceRow>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn insert_workspace_agent_logs(
        &self,
        _agent_id: Uuid,
        _log_source_id: Uuid,
        _logs: &[InsertAgentLogInput],
    ) -> Result<Vec<WorkspaceAgentLogRow>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn insert_workspace_agent_script_timing(
        &self,
        _input: &coder_core::InsertAgentScriptTimingInput,
    ) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn insert_workspace_app_status(
        &self,
        _input: &InsertWorkspaceAppStatusInput,
    ) -> Result<WorkspaceAppStatusRow, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_workspace_app_statuses_by_agent_id(
        &self,
        _agent_id: Uuid,
    ) -> Result<Vec<WorkspaceAppStatusRow>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_workspace_app_by_agent_and_slug(
        &self,
        _agent_id: Uuid,
        _slug: &str,
    ) -> Result<Option<WorkspaceAppRow>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_workspace_agent_by_instance_id(
        &self,
        _instance_id: &str,
    ) -> Result<Option<WorkspaceAgentRow>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_workspace_apps_by_agent_id(
        &self,
        _agent_id: Uuid,
    ) -> Result<Vec<WorkspaceAppRow>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_workspace_agent_scripts(
        &self,
        _agent_id: Uuid,
    ) -> Result<Vec<WorkspaceAgentScriptRow>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_workspace_agent_logs(
        &self,
        _agent_id: Uuid,
        _after_id: i64,
        _limit: i64,
    ) -> Result<Vec<WorkspaceAgentLogRow>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_workspace_agent_metadata(
        &self,
        _agent_id: Uuid,
    ) -> Result<Vec<WorkspaceAgentMetadataRow>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_workspace_agent_lifecycle_state(
        &self,
        _agent_id: Uuid,
        _lifecycle_state: &str,
        _started_at: Option<OffsetDateTime>,
        _ready_at: Option<OffsetDateTime>,
    ) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_workspace_agent_startup(
        &self,
        _agent_id: Uuid,
        _version: &str,
        _expanded_directory: &str,
        _subsystems: &[&str],
        _api_version: &str,
    ) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_workspace_app_health(
        &self,
        _app_id: Uuid,
        _health: &str,
    ) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_workspace_apps_with_healthchecks(
        &self,
    ) -> Result<Vec<coder_core::WorkspaceAppHealthcheckTarget>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn upsert_workspace_agent_metadata(
        &self,
        _agent_id: Uuid,
        _entries: &[coder_core::UpsertAgentMetadataEntry],
    ) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_workspace_agent_devcontainers(
        &self,
        _agent_id: Uuid,
    ) -> Result<Vec<coder_core::WorkspaceAgentDevcontainerRow>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_workspace_resource_by_id(
        &self,
        _resource_id: Uuid,
    ) -> Result<Option<WorkspaceResourceRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_workspace_build_by_id(
        &self,
        _build_id: Uuid,
    ) -> Result<Option<WorkspaceBuildRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_latest_workspace_build(
        &self,
        _workspace_id: Uuid,
    ) -> Result<Option<WorkspaceBuildRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_workspace_build_parameters(
        &self,
        _build_id: Uuid,
    ) -> Result<Vec<WorkspaceBuildParameterRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_provisioner_job_logs(
        &self,
        _job_id: Uuid,
        _after: Option<i64>,
    ) -> Result<Vec<ProvisionerJobLogRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_workspace_resources_by_job(
        &self,
        _job_id: Uuid,
    ) -> Result<Vec<WorkspaceResourceRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_workspace_resource_metadata(
        &self,
        _resource_ids: &[Uuid],
    ) -> Result<Vec<WorkspaceResourceMetadataRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_provisioner_job_timings(
        &self,
        _job_id: Uuid,
    ) -> Result<Vec<ProvisionerJobTimingRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn insert_workspace(
        &self,
        _input: CreateWorkspaceInput,
    ) -> Result<WorkspaceRecord, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_workspace_by_owner_and_name(
        &self,
        _owner_id: Uuid,
        _name: &str,
        _viewer_id: Option<Uuid>,
    ) -> Result<Option<WorkspaceRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn insert_workspace_build(
        &self,
        _input: CreateWorkspaceBuildInput,
    ) -> Result<WorkspaceBuildRecord, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_workspace_build_by_number(
        &self,
        _workspace_id: Uuid,
        _build_number: i64,
    ) -> Result<Option<WorkspaceBuildRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn insert_workspace_build_parameters(
        &self,
        _build_id: Uuid,
        _params: &[(String, String)],
    ) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_oauth2_provider_apps(
        &self,
    ) -> Result<Vec<coder_core::identity::OAuth2ProviderAppRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn create_oauth2_provider_app(
        &self,
        _input: &coder_core::identity::CreateOAuth2ProviderAppInput,
    ) -> Result<coder_core::identity::OAuth2ProviderAppRecord, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_oauth2_provider_app_by_id(
        &self,
        _app_id: Uuid,
    ) -> Result<Option<coder_core::identity::OAuth2ProviderAppRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_oauth2_provider_app(
        &self,
        _input: &coder_core::identity::UpdateOAuth2ProviderAppInput,
    ) -> Result<Option<coder_core::identity::OAuth2ProviderAppRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn delete_oauth2_provider_app(&self, _app_id: Uuid) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_oauth2_provider_app_registration_token(
        &self,
        _app_id: Uuid,
        _hash: &[u8],
    ) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn has_oauth2_provider_app_user_approval(
        &self,
        _app_id: Uuid,
        _user_id: Uuid,
    ) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn insert_oauth2_provider_app_user_approval(
        &self,
        _app_id: Uuid,
        _user_id: Uuid,
        _scope: &str,
    ) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn insert_oauth2_pending_consent(
        &self,
        _app_id: Uuid,
        _user_id: Uuid,
        _state: &str,
        _resource: &str,
        _code_challenge: &str,
        _code_challenge_method: &str,
        _expires_at: time::OffsetDateTime,
    ) -> Result<Uuid, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn take_oauth2_pending_consent(
        &self,
        _nonce: Uuid,
    ) -> Result<Option<coder_core::identity::OAuth2PendingConsent>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_oauth2_provider_app_secrets(
        &self,
        _app_id: Uuid,
    ) -> Result<Vec<coder_core::identity::OAuth2ProviderAppSecretRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn create_oauth2_provider_app_secret(
        &self,
        _app_id: Uuid,
        _secret_prefix: &[u8],
        _hashed_secret: &[u8],
        _display_secret: &str,
    ) -> Result<coder_core::identity::OAuth2ProviderAppSecretRecord, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn delete_oauth2_provider_app_secret(
        &self,
        _secret_id: Uuid,
    ) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_oauth2_provider_app_secret_by_prefix(
        &self,
        _secret_prefix: &[u8],
    ) -> Result<Option<coder_core::identity::OAuth2ProviderAppSecretRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_oauth2_provider_app_secret_last_used(
        &self,
        _secret_id: Uuid,
    ) -> Result<Option<coder_core::identity::OAuth2ProviderAppSecretRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_oauth2_provider_app_secret_by_id(
        &self,
        _secret_id: Uuid,
    ) -> Result<Option<coder_core::identity::OAuth2ProviderAppSecretRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn create_oauth2_provider_app_code(
        &self,
        _app_id: Uuid,
        _user_id: Uuid,
        _secret_prefix: &[u8],
        _hashed_secret: &[u8],
        _expires_at: OffsetDateTime,
        _resource_uri: &str,
        _code_challenge: &str,
        _code_challenge_method: &str,
        _state_hash: Option<&str>,
        _redirect_uri: Option<&str>,
    ) -> Result<coder_core::identity::OAuth2ProviderAppCodeRecord, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_oauth2_provider_app_code_by_prefix(
        &self,
        _secret_prefix: &[u8],
    ) -> Result<Option<coder_core::identity::OAuth2ProviderAppCodeRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn delete_oauth2_provider_app_code(&self, _code_id: Uuid) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_oauth2_provider_app_code_by_id(
        &self,
        _code_id: Uuid,
    ) -> Result<Option<coder_core::identity::OAuth2ProviderAppCodeRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn delete_oauth2_provider_app_codes_by_app_and_user(
        &self,
        _app_id: Uuid,
        _user_id: Uuid,
    ) -> Result<u64, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn create_oauth2_provider_app_token(
        &self,
        _input: &coder_core::identity::CreateOAuth2ProviderAppTokenInput,
    ) -> Result<coder_core::identity::OAuth2ProviderAppTokenRecord, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_oauth2_provider_app_token_by_prefix(
        &self,
        _hash_prefix: &[u8],
    ) -> Result<Option<coder_core::identity::OAuth2ProviderAppTokenRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_oauth2_provider_app_token_by_api_key_id(
        &self,
        _api_key_id: &str,
    ) -> Result<Option<coder_core::identity::OAuth2ProviderAppTokenRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_oauth2_provider_app_token_by_refresh_hash(
        &self,
        _refresh_hash: &[u8],
    ) -> Result<Option<coder_core::identity::OAuth2ProviderAppTokenRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn delete_oauth2_provider_app_token(
        &self,
        _token_id: Uuid,
    ) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_oauth2_provider_app_tokens_by_app_and_user(
        &self,
        _app_id: Uuid,
        _user_id: Uuid,
    ) -> Result<Vec<coder_core::identity::OAuth2ProviderAppTokenRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn delete_oauth2_provider_app_tokens_by_app_and_user(
        &self,
        _app_id: Uuid,
        _user_id: Uuid,
    ) -> Result<u64, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_workspaces(
        &self,
        _filter: WorkspaceListFilter,
    ) -> Result<(Vec<WorkspaceRecord>, i64), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_workspace_by_id(
        &self,
        _workspace_id: Uuid,
        _viewer_id: Option<Uuid>,
    ) -> Result<Option<WorkspaceRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_workspace_name(
        &self,
        _workspace_id: Uuid,
        _name: &str,
        _viewer_id: Option<Uuid>,
    ) -> Result<Option<WorkspaceRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn soft_delete_workspace(&self, _workspace_id: Uuid) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_workspace_autostart(
        &self,
        _workspace_id: Uuid,
        _schedule: Option<&str>,
    ) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_workspace_ttl(
        &self,
        _workspace_id: Uuid,
        _ttl_ns: Option<i64>,
    ) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_workspace_dormant_at(
        &self,
        _workspace_id: Uuid,
        _dormant_at: Option<OffsetDateTime>,
        _viewer_id: Option<Uuid>,
    ) -> Result<Option<WorkspaceRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_workspace_automatic_updates(
        &self,
        _workspace_id: Uuid,
        _automatic_updates: &str,
    ) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_workspace_last_used_at(
        &self,
        _workspace_id: Uuid,
        _last_used_at: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn favorite_workspace(
        &self,
        _workspace_id: Uuid,
        _user_id: Uuid,
        _favorite: bool,
    ) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_workspace_build_deadline(
        &self,
        _build_id: Uuid,
        _deadline: Option<OffsetDateTime>,
        _max_deadline: Option<OffsetDateTime>,
    ) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_workspace_build_provisioner_state(
        &self,
        _build_id: Uuid,
        _state: &[u8],
    ) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_workspace_builds(
        &self,
        _workspace_id: Uuid,
        _limit: u32,
        _offset: u32,
    ) -> Result<Vec<WorkspaceBuildRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_workspace_port_shares(
        &self,
        _workspace_id: Uuid,
    ) -> Result<Vec<WorkspaceAgentPortShareRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn upsert_workspace_port_share(
        &self,
        _input: UpsertPortShareInput,
    ) -> Result<WorkspaceAgentPortShareRecord, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn delete_workspace_port_share(
        &self,
        _workspace_id: Uuid,
        _agent_name: &str,
        _port: i32,
    ) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn get_workspace_acl(
        &self,
        _workspace_id: Uuid,
    ) -> Result<WorkspaceACLRecord, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_workspace_acl(
        &self,
        _workspace_id: Uuid,
        _input: &UpdateWorkspaceACLInput,
    ) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn delete_workspace_acl(&self, _workspace_id: Uuid) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_custom_roles(
        &self,
        _organization_id: Option<Uuid>,
    ) -> Result<Vec<CustomRoleRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn upsert_custom_role(
        &self,
        _input: &UpsertCustomRoleInput,
    ) -> Result<CustomRoleRecord, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_user_by_linked_id(
        &self,
        _login_type: LoginType,
        _linked_id: &str,
    ) -> Result<Option<UserRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_active_user_by_email_and_login_type(
        &self,
        _email: &str,
        _login_type: LoginType,
    ) -> Result<Option<UserRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_user_links(&self, _user_id: Uuid) -> Result<Vec<UserLinkRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn delete_user_config(&self, _user_id: Uuid, _key: &str) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn acquire_pending_notification_messages(
        &self,
        _limit: u32,
        _max_attempt_count: u32,
    ) -> Result<Vec<NotificationMessageRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_notification_message_status(
        &self,
        _message_id: Uuid,
        _status: NotificationMessageStatus,
    ) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn increment_notification_message_attempt_count(
        &self,
        _message_id: Uuid,
    ) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn bulk_mark_notification_messages_sent(
        &self,
        _ids: &[Uuid],
    ) -> Result<u64, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn bulk_mark_notification_messages_failed(
        &self,
        _ids: &[Uuid],
        _statuses: &[NotificationMessageStatus],
        _status_reasons: &[String],
        _max_attempts: u32,
        _retry_interval_secs: u32,
    ) -> Result<u64, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_user_notification_preference(
        &self,
        _user_id: Uuid,
        _notification_template_id: Uuid,
    ) -> Result<Option<bool>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn get_notification_template_by_id(
        &self,
        _template_id: Uuid,
    ) -> Result<Option<coder_core::api::NotificationTemplate>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_workspace_dormant_deleting_at(
        &self,
        _workspace_id: Uuid,
        _dormant_at: Option<OffsetDateTime>,
    ) -> Result<Option<WorkspaceRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn get_workspaces_eligible_for_transition(
        &self,
        _now: OffsetDateTime,
    ) -> Result<Vec<WorkspaceTransitionRow>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn create_group(&self, _input: &CreateGroupInput) -> Result<GroupRecord, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_group_by_id(&self, _group_id: Uuid) -> Result<Option<GroupRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn delete_group(&self, _group_id: Uuid) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_groups(&self, _organization_id: Uuid) -> Result<Vec<GroupRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn insert_group_member(
        &self,
        _group_id: Uuid,
        _user_id: Uuid,
    ) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn delete_group_member(
        &self,
        _group_id: Uuid,
        _user_id: Uuid,
    ) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_group_members(
        &self,
        _group_id: Uuid,
    ) -> Result<Vec<GroupMemberRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_group_by_name(
        &self,
        _organization_id: Uuid,
        _name: &str,
    ) -> Result<Option<GroupRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_group(&self, _input: &UpdateGroupInput) -> Result<GroupRecord, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_all_groups(&self) -> Result<Vec<GroupRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn upsert_user_link(
        &self,
        _user_id: Uuid,
        _input: &UpsertUserLinkInput,
    ) -> Result<UserLinkRecord, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn delete_user_link(
        &self,
        _user_id: Uuid,
        _login_type: LoginType,
    ) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn get_user_config(
        &self,
        _user_id: Uuid,
        _key: &str,
    ) -> Result<Option<UserConfigRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn upsert_user_config(
        &self,
        _user_id: Uuid,
        _key: &str,
        _value: &str,
    ) -> Result<UserConfigRecord, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn insert_user_deleted(
        &self,
        _user_id: Uuid,
        _deleted_by: Option<Uuid>,
        _reason: &str,
    ) -> Result<UserDeletedRecord, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn insert_user_status_change(
        &self,
        _user_id: Uuid,
        _old_status: UserStatus,
        _new_status: UserStatus,
        _changed_by: Option<Uuid>,
        _reason: &str,
    ) -> Result<UserStatusChangeRecord, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_user_status_changes(
        &self,
        _user_id: Uuid,
    ) -> Result<Vec<UserStatusChangeRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn delete_custom_role(
        &self,
        _name: &str,
        _organization_id: Option<Uuid>,
    ) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_custom_role(
        &self,
        _name: &str,
        _organization_id: Option<Uuid>,
    ) -> Result<Option<CustomRoleRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn insert_organization(
        &self,
        _input: &CreateOrganizationInput,
    ) -> Result<OrganizationRecord, CreateOrganizationStoreError> {
        Err(CreateOrganizationStoreError::Storage(
            StorageError::unavailable("bench stub"),
        ))
    }

    async fn update_organization(
        &self,
        _input: &UpdateOrganizationInput,
    ) -> Result<OrganizationRecord, UpdateOrganizationStoreError> {
        Err(UpdateOrganizationStoreError::Storage(
            StorageError::unavailable("bench stub"),
        ))
    }

    async fn soft_delete_organization(&self, _id: Uuid) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn get_organization_resource_counts(
        &self,
        _id: Uuid,
    ) -> Result<OrgResourceCounts, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn get_organization_sharing_settings(
        &self,
        _organization_id: Uuid,
    ) -> Result<Option<coder_core::WorkspaceSharingMode>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_organization_sharing_settings(
        &self,
        _organization_id: Uuid,
        _mode: coder_core::WorkspaceSharingMode,
    ) -> Result<Option<coder_core::WorkspaceSharingMode>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn batch_insert_workspace_build_parameters(
        &self,
        _params: Vec<WorkspaceBuildParameterRecord>,
    ) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn batch_update_workspace_last_used_at(
        &self,
        _ids: &[Uuid],
        _last_used_at: OffsetDateTime,
    ) -> Result<u64, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_users_by_ids(&self, _ids: &[Uuid]) -> Result<Vec<UserRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn group_sync_settings(
        &self,
        _org_id: Uuid,
    ) -> Result<coder_core::api::GroupSyncSettings, StorageError> {
        Ok(coder_core::api::GroupSyncSettings::default())
    }

    async fn upsert_group_sync_settings(
        &self,
        _org_id: Uuid,
        _settings: &coder_core::api::GroupSyncSettings,
    ) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn role_sync_settings(
        &self,
        _org_id: Uuid,
    ) -> Result<coder_core::api::RoleSyncSettings, StorageError> {
        Ok(coder_core::api::RoleSyncSettings::default())
    }

    async fn upsert_role_sync_settings(
        &self,
        _org_id: Uuid,
        _settings: &coder_core::api::RoleSyncSettings,
    ) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_group_sync_config(
        &self,
        _org_id: Uuid,
        _field: String,
        _regex_filter: Option<String>,
        _auto_create_missing_groups: bool,
    ) -> Result<coder_core::api::GroupSyncSettings, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn apply_group_sync_mapping_diff(
        &self,
        _org_id: Uuid,
        _add: &[coder_core::api::IDPSyncMappingGroup],
        _remove: &[coder_core::api::IDPSyncMappingGroup],
    ) -> Result<coder_core::api::GroupSyncSettings, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_role_sync_config(
        &self,
        _org_id: Uuid,
        _field: String,
    ) -> Result<coder_core::api::RoleSyncSettings, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn apply_role_sync_mapping_diff(
        &self,
        _org_id: Uuid,
        _add: &[coder_core::api::IDPSyncMappingRole],
        _remove: &[coder_core::api::IDPSyncMappingRole],
    ) -> Result<coder_core::api::RoleSyncSettings, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn oidc_claim_fields(&self, _org_id: Uuid) -> Result<Vec<String>, StorageError> {
        Ok(Vec::new())
    }

    async fn oidc_claim_field_values(
        &self,
        _org_id: Uuid,
        _claim_field: &str,
    ) -> Result<Vec<String>, StorageError> {
        Ok(Vec::new())
    }

    async fn find_workspace_port_share(
        &self,
        _workspace_id: Uuid,
        _agent_name: &str,
        _port: i32,
    ) -> Result<Option<WorkspaceAgentPortShareRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_workspace_agents_by_resource_ids(
        &self,
        _resource_ids: &[Uuid],
    ) -> Result<Vec<WorkspaceAgentRow>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_workspace_agent_script_timings_by_build_id(
        &self,
        _build_id: Uuid,
    ) -> Result<Vec<WorkspaceAgentScriptTimingRow>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn next_workspace_build_number(&self, _workspace_id: Uuid) -> Result<i64, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_licenses(&self) -> Result<Vec<LicenseRecord>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn insert_license(
        &self,
        _jwt: &str,
        _claims: &Value,
    ) -> Result<LicenseRecord, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn delete_license(&self, _id: i32) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn create_workspace_proxy(
        &self,
        _input: CreateWorkspaceProxyInput,
    ) -> Result<WorkspaceProxyRow, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_workspace_proxies(&self) -> Result<Vec<WorkspaceProxyRow>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_workspace_proxy_by_id(
        &self,
        _id: Uuid,
    ) -> Result<Option<WorkspaceProxyRow>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn find_workspace_proxy_by_name(
        &self,
        _name: &str,
    ) -> Result<Option<WorkspaceProxyRow>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_workspace_proxy(
        &self,
        _input: UpdateWorkspaceProxyInput,
    ) -> Result<WorkspaceProxyRow, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn soft_delete_workspace_proxy(&self, _id: Uuid) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_workspace_proxy_registration(
        &self,
        _input: UpdateWorkspaceProxyRegistrationInput,
    ) -> Result<WorkspaceProxyRow, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn upsert_replica(&self, _input: UpsertReplicaInput) -> Result<ReplicaRow, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_replicas_by_proxy_excluding(
        &self,
        _proxy_id: Uuid,
        _exclude_id: Uuid,
    ) -> Result<Vec<ReplicaRow>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn delete_replica(&self, _id: Uuid) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn insert_coderd_replica(
        &self,
        _input: coder_core::InsertCoderdReplicaInput,
    ) -> Result<coder_core::CoderdReplicaRow, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn refresh_coderd_replica(
        &self,
        _id: Uuid,
        _updated_at: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn delete_coderd_replica(&self, _id: Uuid) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_coderd_replicas(
        &self,
        _updated_after: OffsetDateTime,
    ) -> Result<Vec<coder_core::CoderdReplicaRow>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn prune_stale_coderd_replicas(
        &self,
        _older_than: OffsetDateTime,
    ) -> Result<u64, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_crypto_keys_by_feature(
        &self,
        _feature: coder_core::enums::CryptoKeyFeature,
    ) -> Result<Vec<CryptoKeyRow>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn insert_crypto_key(&self, _row: CryptoKeyRow) -> Result<CryptoKeyRow, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_all_crypto_keys(&self) -> Result<Vec<CryptoKeyRow>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn update_crypto_key_deletes_at(
        &self,
        _feature: coder_core::enums::CryptoKeyFeature,
        _sequence: i32,
        _deletes_at: Option<time::OffsetDateTime>,
    ) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn delete_crypto_key(
        &self,
        _feature: coder_core::enums::CryptoKeyFeature,
        _sequence: i32,
    ) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn max_crypto_key_sequence_for_feature(
        &self,
        _feature: coder_core::enums::CryptoKeyFeature,
    ) -> Result<i32, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn rotate_crypto_key_transactional(
        &self,
        _old_feature: coder_core::enums::CryptoKeyFeature,
        _old_sequence: i32,
        _old_deletes_at: time::OffsetDateTime,
        _new_row: CryptoKeyRow,
    ) -> Result<CryptoKeyRow, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn try_acquire_advisory_lock(
        &self,
        _lock_id: i64,
    ) -> Result<Option<Box<dyn coder_core::AdvisoryLock>>, StorageError> {
        Ok(None)
    }

    async fn get_derp_mesh_key(&self) -> Result<Option<String>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn insert_derp_mesh_key(&self, _value: &str) -> Result<bool, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn insert_workspace_app_stats(&self, _stats: &[Value]) -> Result<(), StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_aibridge_interceptions(
        &self,
        _filter: coder_core::api::AIBridgeInterceptionsFilter,
    ) -> Result<coder_core::api::AIBridgeListInterceptionsResponse, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn list_aibridge_models(
        &self,
        _filter: coder_core::api::AIBridgeModelsFilter,
    ) -> Result<Vec<String>, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn get_quota_allowance_for_user(
        &self,
        _user_id: Uuid,
        _organization_id: Uuid,
    ) -> Result<i64, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }

    async fn get_quota_consumed_for_user(
        &self,
        _owner_id: Uuid,
        _organization_id: Uuid,
    ) -> Result<i64, StorageError> {
        Err(StorageError::unavailable("bench stub"))
    }
}
