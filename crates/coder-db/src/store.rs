//! Postgres-backed application store.

use std::{str::FromStr, time::Duration};

use async_trait::async_trait;
use coder_core::{
    ApiAllowListTarget, ApiKeyListFilter, ApiKeyRecord, ApiKeyWithOwnerRecord, AppStore, AuditDiff,
    AuditLog, AuditLogAction, AuditLogListFilter, AuditLogResponse, AuditResourceType,
    AuthenticatedUser, CreateApiKeyInput, CreateApiKeyStoreError, CreateFirstUserInput,
    CreateFirstUserStoreError, CreateUserInput, CreateUserStoreError, DatabaseConfig,
    DeploymentMetadata, DeploymentStatsResponse, DeploymentStore, ExternalAuthAppInstallation,
    ExternalAuthLinkRecord, ExternalAuthUser, FileRecord, FirstUserRecord, GitSshKeyRecord,
    HealthSettings, InsertFileInput, InsertFileResult, InsertOrganizationMemberError, LoginType,
    MinimalOrganization, MinimalUser, OrganizationMemberListFilter, OrganizationMemberRecord,
    OrganizationRecord, PasswordUserRecord, PersistAuditLogInput, ProvisionerDaemonHealthInput,
    ProvisionerDaemonHealthRecord, ProvisionerJobStatsInput, SessionCountDeploymentStatsResponse,
    SlimRoleRecord, StorageError, TokenConfigRecord, UpsertExternalAuthLinkInput,
    UserAppearanceRecord, UserListFilter, UserPreferenceRecord, UserRecord, UserStatus,
    WebpushSubscriptionRecord, WorkspaceAgentStatInput, WorkspaceBuildStatsInput,
    WorkspaceConnectionLatencyMs, WorkspaceDeploymentStatsResponse, WorkspaceProxyHealthInput,
    WorkspaceProxyHealthRecord, WorkspaceStatsWorkspaceInput,
};
use coder_core::{
    InboxNotification, InboxNotificationAction, NotificationPreference, NotificationTemplate,
    NotificationsSettings,
};
use serde_json::{Value, from_str};
use sqlx::{FromRow, PgPool, Postgres, Transaction, postgres::PgPoolOptions};
use thiserror::Error;
use time::OffsetDateTime;
use tracing::instrument;
use uuid::Uuid;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

const REGULAR_MAX_TOKEN_LIFETIME_SECS: u64 = 60 * 60 * 24 * 30;
const OWNER_MAX_TOKEN_LIFETIME_SECS: u64 = 60 * 60 * 24 * 365;

/// Database initialization failures.
#[derive(Debug, Error)]
pub enum DatabaseInitError {
    /// Pool creation failed.
    #[error("connect to postgres: {source}")]
    Connect {
        /// Wrapped SQLx error.
        #[source]
        source: sqlx::Error,
    },
    /// Migration execution failed.
    #[error("run database migrations: {source}")]
    Migrate {
        /// Wrapped migration error.
        #[source]
        source: sqlx::migrate::MigrateError,
    },
}

/// Postgres-backed implementation of the application store.
#[derive(Debug)]
pub struct PostgresStore {
    pool: PgPool,
}

#[derive(Debug, FromRow)]
struct StoredUserRow {
    id: Uuid,
    email: String,
    username: String,
    name: String,
    avatar_url: String,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    last_seen_at: Option<OffsetDateTime>,
    login_type: String,
    status: String,
    deleted: bool,
    is_system: bool,
    organization_ids: Vec<Uuid>,
    global_roles: Vec<String>,
}

#[derive(Debug, FromRow)]
struct StoredPasswordUserRow {
    id: Uuid,
    email: String,
    username: String,
    name: String,
    avatar_url: String,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    last_seen_at: Option<OffsetDateTime>,
    hashed_password: Vec<u8>,
    hashed_one_time_passcode: Vec<u8>,
    one_time_passcode_expires_at: Option<OffsetDateTime>,
    login_type: String,
    status: String,
    deleted: bool,
    is_system: bool,
    organization_ids: Vec<Uuid>,
    global_roles: Vec<String>,
}

#[derive(Debug, FromRow)]
struct StoredOrganizationRow {
    id: Uuid,
    name: String,
    display_name: String,
    description: String,
    icon: String,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    is_default: bool,
    deleted: bool,
}

#[derive(Debug, FromRow)]
struct StoredOrganizationMemberRow {
    user_id: Uuid,
    organization_id: Uuid,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    roles: Vec<String>,
    username: String,
    avatar_url: String,
    name: String,
    email: String,
    global_roles: Vec<String>,
}

#[derive(Debug, FromRow)]
struct StoredApiKeyRow {
    id: String,
    hashed_secret: Vec<u8>,
    user_id: Uuid,
    last_used: OffsetDateTime,
    expires_at: OffsetDateTime,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    login_type: String,
    scopes: Vec<String>,
    token_name: String,
    lifetime_seconds: i64,
    allow_list_json: String,
    username: Option<String>,
}

#[derive(Debug, FromRow)]
struct StoredAppearanceRow {
    theme_preference: String,
    terminal_font: String,
}

#[derive(Debug, FromRow)]
struct StoredPreferenceRow {
    task_notification_alert_dismissed: bool,
}

#[derive(Debug, FromRow)]
struct StoredAuditLogRow {
    id: Uuid,
    request_id: Option<Uuid>,
    time: OffsetDateTime,
    ip: String,
    user_agent: String,
    resource_type: String,
    resource_id: Option<Uuid>,
    resource_target: String,
    resource_icon: String,
    action: String,
    diff_json: String,
    status_code: i32,
    additional_fields_json: String,
    description: String,
    resource_link: String,
    is_deleted: bool,
    organization_id: Option<Uuid>,
    organization_name: Option<String>,
    organization_display_name: Option<String>,
    organization_icon: Option<String>,
    user_id: Option<Uuid>,
    username: Option<String>,
    name: Option<String>,
    avatar_url: Option<String>,
}

#[derive(Debug, FromRow)]
struct StoredGitSshKeyRow {
    user_id: Uuid,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    public_key: String,
    private_key: String,
}

#[derive(Debug, FromRow)]
struct StoredExternalAuthLinkRow {
    provider_id: String,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    access_token: String,
    refresh_token: String,
    token_type: String,
    scopes: Vec<String>,
    expires_at: OffsetDateTime,
    authenticated: bool,
    validate_error: String,
    refresh_error: String,
    last_validated_at: Option<OffsetDateTime>,
    last_refreshed_at: Option<OffsetDateTime>,
    external_user_json: String,
    installations_json: String,
    app_installable: bool,
}

#[derive(Debug, FromRow)]
struct StoredDeploymentWorkspaceStatsRow {
    pending_workspaces: i64,
    building_workspaces: i64,
    running_workspaces: i64,
    failed_workspaces: i64,
    stopped_workspaces: i64,
}

#[derive(Debug, FromRow)]
struct StoredDeploymentAgentStatsRow {
    workspace_rx_bytes: i64,
    workspace_tx_bytes: i64,
    workspace_connection_latency_50: f64,
    workspace_connection_latency_95: f64,
    session_count_vscode: i64,
    session_count_ssh: i64,
    session_count_jetbrains: i64,
    session_count_reconnecting_pty: i64,
}

#[derive(Debug, FromRow)]
struct StoredWorkspaceProxyRow {
    id: Uuid,
    name: String,
    display_name: String,
    icon_url: String,
    path_app_url: String,
    wildcard_hostname: String,
    derp_enabled: bool,
    derp_only: bool,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    deleted: bool,
    version: String,
}

#[derive(Debug, FromRow)]
struct StoredProvisionerDaemonRow {
    id: Uuid,
    organization_id: Uuid,
    created_at: OffsetDateTime,
    last_seen_at: Option<OffsetDateTime>,
    name: String,
    version: String,
    api_version: String,
    provisioners: Vec<String>,
    tags_json: String,
    status: Option<String>,
}

// ---------------------------------------------------------------------------
// Notification domain row types
// ---------------------------------------------------------------------------

#[derive(FromRow)]
struct StoredNotificationTemplateRow {
    id: Uuid,
    name: String,
    title_template: String,
    body_template: String,
    actions: Option<String>,
    #[sqlx(rename = "group")]
    group: Option<String>,
    method: Option<String>,
    kind: String,
    enabled_by_default: bool,
}

#[derive(FromRow)]
struct StoredNotificationPreferenceRow {
    id: Uuid,
    disabled: bool,
    updated_at: OffsetDateTime,
}

#[derive(FromRow)]
struct StoredInboxNotificationRow {
    id: Uuid,
    user_id: Uuid,
    template_id: Uuid,
    targets: Vec<Uuid>,
    title: String,
    content: String,
    icon: String,
    actions: String,
    read_at: Option<OffsetDateTime>,
    created_at: OffsetDateTime,
}

#[derive(FromRow)]
struct StoredWebpushSubscriptionRow {
    id: Uuid,
    user_id: Uuid,
    created_at: OffsetDateTime,
    endpoint: String,
    endpoint_p256dh_key: String,
    endpoint_auth_key: String,
}

#[derive(Debug, FromRow)]
struct StoredFileRow {
    id: Uuid,
    hash: String,
    created_by: Uuid,
    created_at: OffsetDateTime,
    mimetype: String,
    data: Vec<u8>,
}

impl PostgresStore {
    /// Connects to Postgres using the supplied configuration.
    pub async fn connect(config: &DatabaseConfig) -> Result<Self, DatabaseInitError> {
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .min_connections(config.min_connections)
            .acquire_timeout(Duration::from_secs(config.acquire_timeout_secs))
            .connect(&config.postgres_url)
            .await
            .map_err(|source| DatabaseInitError::Connect { source })?;

        Ok(Self { pool })
    }

    /// Returns a clone of the underlying connection pool.
    pub fn pool(&self) -> PgPool {
        self.pool.clone()
    }

    /// Applies the Rust rewrite migrations.
    pub async fn migrate(&self) -> Result<(), DatabaseInitError> {
        MIGRATOR
            .run(&self.pool)
            .await
            .map_err(|source| DatabaseInitError::Migrate { source })
    }
}

#[async_trait]
impl DeploymentStore for PostgresStore {
    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn ping(&self) -> Result<(), StorageError> {
        sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .map(|_| ())
            .map_err(storage_error)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn ensure_deployment_metadata(&self) -> Result<DeploymentMetadata, StorageError> {
        let candidate = Uuid::new_v4();

        sqlx::query(
            "INSERT INTO site_configs (key, value)
             VALUES ('deployment_id', $1)
             ON CONFLICT (key) DO NOTHING",
        )
        .bind(candidate.to_string())
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        let stored: String =
            sqlx::query_scalar("SELECT value FROM site_configs WHERE key = 'deployment_id'")
                .fetch_one(&self.pool)
                .await
                .map_err(storage_error)?;

        let deployment_id = Uuid::parse_str(&stored).map_err(|error| {
            StorageError::invalid_data(format!(
                "site_configs.deployment_id must be a UUID: {error}"
            ))
        })?;

        Ok(DeploymentMetadata { deployment_id })
    }
}

#[async_trait]
impl AppStore for PostgresStore {
    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn first_user_exists(&self) -> Result<bool, StorageError> {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(
                SELECT 1
                FROM users
                WHERE deleted = false AND is_system = false
            )",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)
    }

    #[instrument(skip(self, user), err(level = tracing::Level::WARN))]
    async fn create_first_user(
        &self,
        user: CreateFirstUserInput,
    ) -> Result<FirstUserRecord, CreateFirstUserStoreError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(storage_error)
            .map_err(CreateFirstUserStoreError::from)?;

        let existing_user_id: Option<Uuid> = sqlx::query_scalar(
            "SELECT id
             FROM users
             WHERE deleted = false AND is_system = false
             LIMIT 1",
        )
        .fetch_optional(&mut *transaction)
        .await
        .map_err(storage_error)
        .map_err(CreateFirstUserStoreError::from)?;

        if existing_user_id.is_some() {
            return Err(CreateFirstUserStoreError::AlreadyExists);
        }

        let organization_id = ensure_default_organization(&mut transaction)
            .await
            .map_err(CreateFirstUserStoreError::from)?;
        let user_id = Uuid::new_v4();

        sqlx::query(
            "INSERT INTO users (
                id,
                email,
                username,
                name,
                hashed_password,
                created_at,
                updated_at,
                rbac_roles,
                login_type,
                status
            )
            VALUES (
                $1,
                $2,
                $3,
                $4,
                $5,
                NOW(),
                NOW(),
                ARRAY['owner']::text[],
                'password'::login_type,
                'active'::user_status
            )",
        )
        .bind(user_id)
        .bind(&user.email)
        .bind(&user.username)
        .bind(&user.name)
        .bind(user.password_hash.as_bytes())
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)
        .map_err(CreateFirstUserStoreError::from)?;

        sqlx::query(
            "INSERT INTO organization_members (
                organization_id,
                user_id,
                created_at,
                updated_at,
                roles
            )
            VALUES ($1, $2, NOW(), NOW(), ARRAY[]::text[])",
        )
        .bind(organization_id)
        .bind(user_id)
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)
        .map_err(CreateFirstUserStoreError::from)?;

        transaction
            .commit()
            .await
            .map_err(storage_error)
            .map_err(CreateFirstUserStoreError::from)?;

        Ok(FirstUserRecord {
            user_id,
            organization_id,
        })
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_password_user_by_email(
        &self,
        email: &str,
    ) -> Result<Option<PasswordUserRecord>, StorageError> {
        sqlx::query_as::<_, StoredPasswordUserRow>(
            "SELECT
                u.id,
                u.email,
                u.username,
                u.name,
                u.avatar_url,
                u.created_at,
                u.updated_at,
                u.last_seen_at,
                u.hashed_password,
                u.hashed_one_time_passcode,
                u.one_time_passcode_expires_at,
                u.login_type::text AS login_type,
                u.status::text AS status,
                u.deleted,
                u.is_system,
                COALESCE(
                    array_agg(DISTINCT om.organization_id) FILTER (WHERE om.organization_id IS NOT NULL),
                    ARRAY[]::uuid[]
                ) AS organization_ids,
                COALESCE(u.rbac_roles, ARRAY[]::text[]) AS global_roles
             FROM users u
             LEFT JOIN organization_members om ON om.user_id = u.id
             WHERE LOWER(u.email) = LOWER($1)
               AND u.deleted = false
             GROUP BY u.id",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?
        .map(password_record_from_row)
        .transpose()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_password_user_by_id(
        &self,
        user_id: Uuid,
    ) -> Result<Option<PasswordUserRecord>, StorageError> {
        sqlx::query_as::<_, StoredPasswordUserRow>(
            "SELECT
                u.id,
                u.email,
                u.username,
                u.name,
                u.avatar_url,
                u.created_at,
                u.updated_at,
                u.last_seen_at,
                u.hashed_password,
                u.hashed_one_time_passcode,
                u.one_time_passcode_expires_at,
                u.login_type::text AS login_type,
                u.status::text AS status,
                u.deleted,
                u.is_system,
                COALESCE(
                    array_agg(DISTINCT om.organization_id) FILTER (WHERE om.organization_id IS NOT NULL),
                    ARRAY[]::uuid[]
                ) AS organization_ids,
                COALESCE(u.rbac_roles, ARRAY[]::text[]) AS global_roles
             FROM users u
             LEFT JOIN organization_members om ON om.user_id = u.id
             WHERE u.id = $1
               AND u.deleted = false
             GROUP BY u.id",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?
        .map(password_record_from_row)
        .transpose()
    }

    #[instrument(skip(self, token_hash), err(level = tracing::Level::WARN))]
    async fn insert_auth_session(
        &self,
        token_hash: &[u8],
        user_id: Uuid,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO auth_sessions (token_hash, user_id, created_at, last_used_at)
             VALUES ($1, $2, NOW(), NOW())",
        )
        .bind(token_hash)
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(storage_error)
    }

    #[instrument(skip(self, token_hash), err(level = tracing::Level::WARN))]
    async fn find_user_by_session_token_hash(
        &self,
        token_hash: &[u8],
    ) -> Result<Option<AuthenticatedUser>, StorageError> {
        let row = sqlx::query_as::<_, StoredUserRow>(
            "SELECT
                u.id,
                u.email,
                u.username,
                u.name,
                u.avatar_url,
                u.created_at,
                u.updated_at,
                u.last_seen_at,
                u.login_type::text AS login_type,
                u.status::text AS status,
                u.deleted,
                u.is_system,
                COALESCE(
                    array_agg(DISTINCT om.organization_id) FILTER (WHERE om.organization_id IS NOT NULL),
                    ARRAY[]::uuid[]
                ) AS organization_ids,
                COALESCE(u.rbac_roles, ARRAY[]::text[]) AS global_roles
             FROM auth_sessions s
             INNER JOIN users u ON u.id = s.user_id
             LEFT JOIN organization_members om ON om.user_id = u.id
             WHERE s.token_hash = $1
               AND u.deleted = false
             GROUP BY u.id",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        let Some(row) = row else {
            return Ok(None);
        };

        let user_id = row.id;
        let user_record = user_record_from_row(row)?;
        let mut auth_user = AuthenticatedUser::from(user_record);

        // Fetch organization-scoped roles in "role_name:org_id" format.
        let org_roles: Vec<String> = sqlx::query_scalar(
            "SELECT role_name || ':' || sub_om.organization_id::text
             FROM organization_members sub_om
             CROSS JOIN LATERAL unnest(sub_om.roles) AS role_name
             WHERE sub_om.user_id = $1",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        auth_user.org_roles = org_roles;
        Ok(Some(auth_user))
    }

    #[instrument(skip(self, token_hash), err(level = tracing::Level::WARN))]
    async fn delete_auth_session(&self, token_hash: &[u8]) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM auth_sessions WHERE token_hash = $1")
            .bind(token_hash)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;

        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_users(
        &self,
        filter: UserListFilter,
    ) -> Result<(Vec<UserRecord>, usize), StorageError> {
        let search = (!filter.search.trim().is_empty())
            .then(|| format!("%{}%", filter.search.trim().replace('%', "\\%")));
        let status = filter.status.map(|value| value.as_str().to_owned());

        let total = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*)
             FROM users u
             WHERE u.deleted = false
               AND (
                    $1::text IS NULL
                    OR u.username ILIKE $1
                    OR u.email ILIKE $1
                    OR u.name ILIKE $1
               )
               AND ($2::text IS NULL OR u.status::text = $2)",
        )
        .bind(search.clone())
        .bind(status.clone())
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        let rows = sqlx::query_as::<_, StoredUserRow>(
            "SELECT
                u.id,
                u.email,
                u.username,
                u.name,
                u.avatar_url,
                u.created_at,
                u.updated_at,
                u.last_seen_at,
                u.login_type::text AS login_type,
                u.status::text AS status,
                u.deleted,
                u.is_system,
                COALESCE(
                    array_agg(DISTINCT om.organization_id) FILTER (WHERE om.organization_id IS NOT NULL),
                    ARRAY[]::uuid[]
                ) AS organization_ids,
                COALESCE(u.rbac_roles, ARRAY[]::text[]) AS global_roles
             FROM users u
             LEFT JOIN organization_members om ON om.user_id = u.id
             WHERE u.deleted = false
               AND (
                    $1::text IS NULL
                    OR u.username ILIKE $1
                    OR u.email ILIKE $1
                    OR u.name ILIKE $1
               )
               AND ($2::text IS NULL OR u.status::text = $2)
             GROUP BY u.id
             ORDER BY LOWER(u.username) ASC
             OFFSET $3
             LIMIT NULLIF($4::int, 0)",
        )
        .bind(search)
        .bind(status)
        .bind(i64::from(filter.offset))
        .bind(i64::from(filter.limit))
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        let users = rows
            .into_iter()
            .map(user_record_from_row)
            .collect::<Result<Vec<_>, _>>()?;

        Ok((
            users,
            usize::try_from(total)
                .map_err(|error| StorageError::invalid_data(error.to_string()))?,
        ))
    }

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn create_user(
        &self,
        input: CreateUserInput,
    ) -> Result<UserRecord, CreateUserStoreError> {
        let CreateUserInput {
            email,
            username,
            name,
            password_hash,
            login_type,
            status,
            organization_ids,
        } = input;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(storage_error)
            .map_err(CreateUserStoreError::from)?;
        let user_id = Uuid::new_v4();

        let result = sqlx::query(
            "INSERT INTO users (
                id,
                email,
                username,
                name,
                hashed_password,
                created_at,
                updated_at,
                rbac_roles,
                login_type,
                status
             ) VALUES (
                $1,
                $2,
                $3,
                $4,
                $5,
                NOW(),
                NOW(),
                ARRAY[]::text[],
                $6::login_type,
                $7::user_status
             )",
        )
        .bind(user_id)
        .bind(&email)
        .bind(&username)
        .bind(&name)
        .bind(password_hash.unwrap_or_default().into_bytes())
        .bind(login_type.as_str())
        .bind(status.as_str())
        .execute(&mut *transaction)
        .await;

        match result {
            Ok(_) => {}
            Err(error) if is_unique_violation(&error) => {
                return Err(CreateUserStoreError::AlreadyExists);
            }
            Err(error) => return Err(CreateUserStoreError::from(storage_error(error))),
        }

        for organization_id in &organization_ids {
            sqlx::query(
                "INSERT INTO organization_members (
                    organization_id,
                    user_id,
                    created_at,
                    updated_at,
                    roles
                 ) VALUES ($1, $2, NOW(), NOW(), ARRAY[]::text[])",
            )
            .bind(*organization_id)
            .bind(user_id)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)
            .map_err(CreateUserStoreError::from)?;
        }

        transaction
            .commit()
            .await
            .map_err(storage_error)
            .map_err(CreateUserStoreError::from)?;

        self.find_user_by_id(user_id)
            .await
            .map_err(CreateUserStoreError::from)?
            .ok_or_else(|| {
                CreateUserStoreError::from(StorageError::invalid_data(
                    "inserted user could not be reloaded",
                ))
            })
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_user_by_id(&self, user_id: Uuid) -> Result<Option<UserRecord>, StorageError> {
        sqlx::query_as::<_, StoredUserRow>(
            "SELECT
                u.id,
                u.email,
                u.username,
                u.name,
                u.avatar_url,
                u.created_at,
                u.updated_at,
                u.last_seen_at,
                u.login_type::text AS login_type,
                u.status::text AS status,
                u.deleted,
                u.is_system,
                COALESCE(
                    array_agg(DISTINCT om.organization_id) FILTER (WHERE om.organization_id IS NOT NULL),
                    ARRAY[]::uuid[]
                ) AS organization_ids,
                COALESCE(u.rbac_roles, ARRAY[]::text[]) AS global_roles
             FROM users u
             LEFT JOIN organization_members om ON om.user_id = u.id
             WHERE u.id = $1 AND u.deleted = false
             GROUP BY u.id",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?
        .map(user_record_from_row)
        .transpose()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_user_by_username(
        &self,
        username: &str,
    ) -> Result<Option<UserRecord>, StorageError> {
        sqlx::query_as::<_, StoredUserRow>(
            "SELECT
                u.id,
                u.email,
                u.username,
                u.name,
                u.avatar_url,
                u.created_at,
                u.updated_at,
                u.last_seen_at,
                u.login_type::text AS login_type,
                u.status::text AS status,
                u.deleted,
                u.is_system,
                COALESCE(
                    array_agg(DISTINCT om.organization_id) FILTER (WHERE om.organization_id IS NOT NULL),
                    ARRAY[]::uuid[]
                ) AS organization_ids,
                COALESCE(u.rbac_roles, ARRAY[]::text[]) AS global_roles
             FROM users u
             LEFT JOIN organization_members om ON om.user_id = u.id
             WHERE LOWER(u.username) = LOWER($1) AND u.deleted = false
             GROUP BY u.id",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?
        .map(user_record_from_row)
        .transpose()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn soft_delete_user(&self, user_id: Uuid) -> Result<bool, StorageError> {
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        let result = sqlx::query(
            "UPDATE users
             SET deleted = true, status = 'suspended'::user_status, updated_at = NOW()
             WHERE id = $1 AND deleted = false",
        )
        .bind(user_id)
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;

        if result.rows_affected() == 0 {
            transaction.rollback().await.map_err(storage_error)?;
            return Ok(false);
        }

        sqlx::query("DELETE FROM auth_sessions WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;

        sqlx::query("DELETE FROM api_keys WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;

        transaction.commit().await.map_err(storage_error)?;
        Ok(true)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_user_memberships(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<OrganizationMemberRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredOrganizationMemberRow>(
            "SELECT
                om.user_id,
                om.organization_id,
                om.created_at,
                om.updated_at,
                om.roles,
                u.username,
                u.avatar_url,
                u.name,
                u.email,
                COALESCE(u.rbac_roles, ARRAY[]::text[]) AS global_roles
             FROM organization_members om
             INNER JOIN users u ON u.id = om.user_id
             WHERE om.user_id = $1
               AND u.deleted = false
             ORDER BY om.created_at ASC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        rows.into_iter()
            .map(organization_member_record_from_row)
            .collect()
    }

    #[instrument(skip(self, roles), err(level = tracing::Level::WARN))]
    async fn update_user_roles(
        &self,
        user_id: Uuid,
        roles: Vec<String>,
    ) -> Result<Option<UserRecord>, StorageError> {
        let result = sqlx::query(
            "UPDATE users
             SET rbac_roles = $2, updated_at = NOW()
             WHERE id = $1 AND deleted = false",
        )
        .bind(user_id)
        .bind(roles)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        if result.rows_affected() == 0 {
            return Ok(None);
        }

        self.find_user_by_id(user_id).await
    }

    #[instrument(skip(self, username, name), err(level = tracing::Level::WARN))]
    async fn update_user_profile(
        &self,
        user_id: Uuid,
        username: &str,
        name: &str,
    ) -> Result<Option<UserRecord>, StorageError> {
        let result = sqlx::query(
            "UPDATE users
             SET username = $2, name = $3, updated_at = NOW()
             WHERE id = $1 AND deleted = false",
        )
        .bind(user_id)
        .bind(username)
        .bind(name)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        if result.rows_affected() == 0 {
            return Ok(None);
        }

        self.find_user_by_id(user_id).await
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_user_status(
        &self,
        user_id: Uuid,
        status: UserStatus,
    ) -> Result<Option<UserRecord>, StorageError> {
        let result = sqlx::query(
            "UPDATE users
             SET status = $2::user_status, updated_at = NOW()
             WHERE id = $1 AND deleted = false",
        )
        .bind(user_id)
        .bind(status.as_str())
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        if result.rows_affected() == 0 {
            return Ok(None);
        }

        self.find_user_by_id(user_id).await
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn user_appearance(&self, user_id: Uuid) -> Result<UserAppearanceRecord, StorageError> {
        let row = sqlx::query_as::<_, StoredAppearanceRow>(
            "SELECT theme_preference, terminal_font
             FROM users
             WHERE id = $1 AND deleted = false",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?
        .ok_or_else(|| StorageError::invalid_data("user appearance target is missing"))?;

        Ok(UserAppearanceRecord {
            theme_preference: row.theme_preference,
            terminal_font: row.terminal_font,
        })
    }

    #[instrument(skip(self, theme_preference, terminal_font), err(level = tracing::Level::WARN))]
    async fn update_user_appearance(
        &self,
        user_id: Uuid,
        theme_preference: &str,
        terminal_font: &str,
    ) -> Result<Option<UserAppearanceRecord>, StorageError> {
        let row = sqlx::query_as::<_, StoredAppearanceRow>(
            "UPDATE users
             SET theme_preference = $2,
                 terminal_font = $3,
                 updated_at = NOW()
             WHERE id = $1
               AND deleted = false
             RETURNING theme_preference, terminal_font",
        )
        .bind(user_id)
        .bind(theme_preference)
        .bind(terminal_font)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(row.map(|row| UserAppearanceRecord {
            theme_preference: row.theme_preference,
            terminal_font: row.terminal_font,
        }))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn user_preferences(&self, user_id: Uuid) -> Result<UserPreferenceRecord, StorageError> {
        let row = sqlx::query_as::<_, StoredPreferenceRow>(
            "SELECT task_notification_alert_dismissed
             FROM users
             WHERE id = $1 AND deleted = false",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?
        .ok_or_else(|| StorageError::invalid_data("user preference target is missing"))?;

        Ok(UserPreferenceRecord {
            task_notification_alert_dismissed: row.task_notification_alert_dismissed,
        })
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_user_preferences(
        &self,
        user_id: Uuid,
        task_notification_alert_dismissed: bool,
    ) -> Result<Option<UserPreferenceRecord>, StorageError> {
        let row = sqlx::query_as::<_, StoredPreferenceRow>(
            "UPDATE users
             SET task_notification_alert_dismissed = $2,
                 updated_at = NOW()
             WHERE id = $1
               AND deleted = false
             RETURNING task_notification_alert_dismissed",
        )
        .bind(user_id)
        .bind(task_notification_alert_dismissed)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(row.map(|row| UserPreferenceRecord {
            task_notification_alert_dismissed: row.task_notification_alert_dismissed,
        }))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_organizations(
        &self,
        organization_ids: Vec<Uuid>,
    ) -> Result<Vec<OrganizationRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredOrganizationRow>(
            "SELECT
                id,
                name,
                display_name,
                description,
                icon,
                created_at,
                updated_at,
                is_default,
                deleted
             FROM organizations
             WHERE deleted = false
               AND (
                    COALESCE(array_length($1::uuid[], 1), 0) = 0
                    OR id = ANY($1)
               )
             ORDER BY LOWER(name) ASC",
        )
        .bind(organization_ids)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        rows.into_iter()
            .map(organization_record_from_row)
            .collect::<Result<Vec<_>, _>>()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_organization_by_id(
        &self,
        organization_id: Uuid,
    ) -> Result<Option<OrganizationRecord>, StorageError> {
        sqlx::query_as::<_, StoredOrganizationRow>(
            "SELECT
                id,
                name,
                display_name,
                description,
                icon,
                created_at,
                updated_at,
                is_default,
                deleted
             FROM organizations
             WHERE id = $1 AND deleted = false",
        )
        .bind(organization_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?
        .map(organization_record_from_row)
        .transpose()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_organization_by_name(
        &self,
        name: &str,
    ) -> Result<Option<OrganizationRecord>, StorageError> {
        sqlx::query_as::<_, StoredOrganizationRow>(
            "SELECT
                id,
                name,
                display_name,
                description,
                icon,
                created_at,
                updated_at,
                is_default,
                deleted
             FROM organizations
             WHERE LOWER(name) = LOWER($1) AND deleted = false",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?
        .map(organization_record_from_row)
        .transpose()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_organization_members(
        &self,
        filter: OrganizationMemberListFilter,
    ) -> Result<Vec<OrganizationMemberRecord>, StorageError> {
        let search = (!filter.search.trim().is_empty())
            .then(|| format!("%{}%", filter.search.trim().replace('%', "\\%")));

        let rows = sqlx::query_as::<_, StoredOrganizationMemberRow>(
            "SELECT
                om.user_id,
                om.organization_id,
                om.created_at,
                om.updated_at,
                om.roles,
                u.username,
                u.avatar_url,
                u.name,
                u.email,
                COALESCE(u.rbac_roles, ARRAY[]::text[]) AS global_roles
             FROM organization_members om
             INNER JOIN users u ON u.id = om.user_id
             WHERE om.organization_id = $1
               AND u.deleted = false
               AND (
                    $2::text IS NULL
                    OR u.username ILIKE $2
                    OR u.email ILIKE $2
                    OR u.name ILIKE $2
               )
             ORDER BY LOWER(u.username) ASC
             OFFSET $3
             LIMIT NULLIF($4::int, 0)",
        )
        .bind(filter.organization_id)
        .bind(search)
        .bind(i64::from(filter.offset))
        .bind(i64::from(filter.limit))
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        rows.into_iter()
            .map(organization_member_record_from_row)
            .collect()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_organization_members_page(
        &self,
        filter: OrganizationMemberListFilter,
    ) -> Result<(Vec<OrganizationMemberRecord>, usize), StorageError> {
        let search = (!filter.search.trim().is_empty())
            .then(|| format!("%{}%", filter.search.trim().replace('%', "\\%")));

        let total = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*)
             FROM organization_members om
             INNER JOIN users u ON u.id = om.user_id
             WHERE om.organization_id = $1
               AND u.deleted = false
               AND (
                    $2::text IS NULL
                    OR u.username ILIKE $2
                    OR u.email ILIKE $2
                    OR u.name ILIKE $2
               )",
        )
        .bind(filter.organization_id)
        .bind(search)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        let members = self.list_organization_members(filter).await?;
        let total = usize::try_from(total)
            .map_err(|error| StorageError::invalid_data(error.to_string()))?;

        Ok((members, total))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_organization_member(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<OrganizationMemberRecord>, StorageError> {
        sqlx::query_as::<_, StoredOrganizationMemberRow>(
            "SELECT
                om.user_id,
                om.organization_id,
                om.created_at,
                om.updated_at,
                om.roles,
                u.username,
                u.avatar_url,
                u.name,
                u.email,
                COALESCE(u.rbac_roles, ARRAY[]::text[]) AS global_roles
             FROM organization_members om
             INNER JOIN users u ON u.id = om.user_id
             WHERE om.organization_id = $1
               AND om.user_id = $2
               AND u.deleted = false",
        )
        .bind(organization_id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?
        .map(organization_member_record_from_row)
        .transpose()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn insert_organization_member(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> Result<OrganizationMemberRecord, InsertOrganizationMemberError> {
        let result = sqlx::query(
            "INSERT INTO organization_members (
                organization_id,
                user_id,
                created_at,
                updated_at,
                roles
             ) VALUES ($1, $2, NOW(), NOW(), ARRAY[]::text[])",
        )
        .bind(organization_id)
        .bind(user_id)
        .execute(&self.pool)
        .await;

        match result {
            Ok(_) => self
                .find_organization_member(organization_id, user_id)
                .await
                .map_err(InsertOrganizationMemberError::from)?
                .ok_or_else(|| {
                    InsertOrganizationMemberError::from(StorageError::invalid_data(
                        "inserted organization member could not be reloaded",
                    ))
                }),
            Err(error) if is_unique_violation(&error) => {
                Err(InsertOrganizationMemberError::AlreadyExists)
            }
            Err(error) => Err(InsertOrganizationMemberError::from(storage_error(error))),
        }
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_organization_member(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "DELETE FROM organization_members
             WHERE organization_id = $1 AND user_id = $2",
        )
        .bind(organization_id)
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self, roles), err(level = tracing::Level::WARN))]
    async fn update_organization_member_roles(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
        roles: Vec<String>,
    ) -> Result<Option<OrganizationMemberRecord>, StorageError> {
        let result = sqlx::query(
            "UPDATE organization_members
             SET roles = $3, updated_at = NOW()
             WHERE organization_id = $1 AND user_id = $2",
        )
        .bind(organization_id)
        .bind(user_id)
        .bind(roles)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        if result.rows_affected() == 0 {
            return Ok(None);
        }

        self.find_organization_member(organization_id, user_id)
            .await
    }

    #[instrument(skip(self, passcode_hash), err(level = tracing::Level::WARN))]
    async fn store_one_time_passcode_by_email(
        &self,
        email: &str,
        passcode_hash: &str,
        expires_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "UPDATE users
             SET hashed_one_time_passcode = $2,
                 one_time_passcode_expires_at = $3,
                 updated_at = NOW()
             WHERE LOWER(email) = LOWER($1)
               AND deleted = false
               AND login_type = 'password'::login_type",
        )
        .bind(email)
        .bind(passcode_hash.as_bytes())
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(storage_error)
    }

    #[instrument(skip(self, password_hash), err(level = tracing::Level::WARN))]
    async fn replace_user_password(
        &self,
        user_id: Uuid,
        password_hash: &str,
        clear_one_time_passcode: bool,
    ) -> Result<bool, StorageError> {
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        let result = sqlx::query(
            "UPDATE users
             SET hashed_password = $2,
                 hashed_one_time_passcode = CASE
                     WHEN $3 THEN ''::bytea
                     ELSE hashed_one_time_passcode
                 END,
                 one_time_passcode_expires_at = CASE
                     WHEN $3 THEN NULL
                     ELSE one_time_passcode_expires_at
                 END,
                 updated_at = NOW()
             WHERE id = $1
               AND deleted = false",
        )
        .bind(user_id)
        .bind(password_hash.as_bytes())
        .bind(clear_one_time_passcode)
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;

        if result.rows_affected() == 0 {
            transaction.rollback().await.map_err(storage_error)?;
            return Ok(false);
        }

        sqlx::query("DELETE FROM auth_sessions WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;

        sqlx::query("DELETE FROM api_keys WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;

        transaction.commit().await.map_err(storage_error)?;
        Ok(true)
    }

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn create_api_key(
        &self,
        input: CreateApiKeyInput,
    ) -> Result<ApiKeyRecord, CreateApiKeyStoreError> {
        let result = sqlx::query(
            "INSERT INTO api_keys (
                id,
                hashed_secret,
                user_id,
                last_used,
                expires_at,
                created_at,
                updated_at,
                login_type,
                scopes,
                token_name,
                lifetime_seconds,
                allow_list_json
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::login_type, $9, $10, $11, $12)",
        )
        .bind(&input.id)
        .bind(&input.hashed_secret)
        .bind(input.user_id)
        .bind(input.last_used)
        .bind(input.expires_at)
        .bind(input.created_at)
        .bind(input.updated_at)
        .bind(input.login_type.as_str())
        .bind(&input.scopes)
        .bind(&input.token_name)
        .bind(input.lifetime_seconds)
        .bind(serde_json::to_string(&input.allow_list).map_err(|error| {
            CreateApiKeyStoreError::from(StorageError::invalid_data(error.to_string()))
        })?)
        .execute(&self.pool)
        .await;

        match result {
            Ok(_) => self
                .find_api_key_by_id(&input.id)
                .await
                .map_err(CreateApiKeyStoreError::from)?
                .ok_or_else(|| {
                    CreateApiKeyStoreError::from(StorageError::invalid_data(
                        "inserted API key could not be reloaded",
                    ))
                }),
            Err(error) if is_unique_violation(&error) => {
                Err(CreateApiKeyStoreError::DuplicateTokenName)
            }
            Err(error) => Err(CreateApiKeyStoreError::from(storage_error(error))),
        }
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_api_key_by_id(&self, id: &str) -> Result<Option<ApiKeyRecord>, StorageError> {
        sqlx::query_as::<_, StoredApiKeyRow>(
            "SELECT
                id,
                hashed_secret,
                user_id,
                last_used,
                expires_at,
                created_at,
                updated_at,
                login_type::text AS login_type,
                scopes,
                token_name,
                lifetime_seconds,
                allow_list_json,
                NULL::text AS username
             FROM api_keys
             WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?
        .map(api_key_record_from_row)
        .transpose()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_api_key_by_name(
        &self,
        user_id: Uuid,
        token_name: &str,
    ) -> Result<Option<ApiKeyRecord>, StorageError> {
        sqlx::query_as::<_, StoredApiKeyRow>(
            "SELECT
                id,
                hashed_secret,
                user_id,
                last_used,
                expires_at,
                created_at,
                updated_at,
                login_type::text AS login_type,
                scopes,
                token_name,
                lifetime_seconds,
                allow_list_json,
                NULL::text AS username
             FROM api_keys
             WHERE user_id = $1
               AND token_name = $2
               AND token_name <> ''",
        )
        .bind(user_id)
        .bind(token_name)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?
        .map(api_key_record_from_row)
        .transpose()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_api_keys(
        &self,
        filter: ApiKeyListFilter,
    ) -> Result<Vec<ApiKeyWithOwnerRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredApiKeyRow>(
            "SELECT
                k.id,
                k.hashed_secret,
                k.user_id,
                k.last_used,
                k.expires_at,
                k.created_at,
                k.updated_at,
                k.login_type::text AS login_type,
                k.scopes,
                k.token_name,
                k.lifetime_seconds,
                k.allow_list_json,
                u.username
             FROM api_keys k
             INNER JOIN users u ON u.id = k.user_id
             WHERE k.login_type::text = $1
               AND ($2::uuid IS NULL OR k.user_id = $2)
               AND ($3::bool OR k.expires_at > NOW())
             ORDER BY LOWER(u.username) ASC, k.created_at DESC",
        )
        .bind(filter.login_type.as_str())
        .bind(filter.user_id)
        .bind(filter.include_expired)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        rows.into_iter()
            .map(|row| {
                let username = row.username.clone().unwrap_or_default();
                Ok(ApiKeyWithOwnerRecord {
                    key: api_key_record_from_row(row)?,
                    username,
                })
            })
            .collect()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_api_key(&self, id: &str) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM api_keys WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;

        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn expire_api_key(&self, id: &str, now: OffsetDateTime) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "UPDATE api_keys
             SET expires_at = $2, updated_at = $2
             WHERE id = $1",
        )
        .bind(id)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn token_config(&self, user_id: Uuid) -> Result<TokenConfigRecord, StorageError> {
        let is_owner = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(
                SELECT 1
                FROM users
                WHERE id = $1
                  AND 'owner' = ANY(rbac_roles)
                  AND deleted = false
            )",
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        let max_token_lifetime = if is_owner {
            Duration::from_secs(OWNER_MAX_TOKEN_LIFETIME_SECS)
        } else {
            Duration::from_secs(REGULAR_MAX_TOKEN_LIFETIME_SECS)
        };

        Ok(TokenConfigRecord { max_token_lifetime })
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_audit_logs(
        &self,
        filter: AuditLogListFilter,
    ) -> Result<AuditLogResponse, StorageError> {
        let search = filter.search.trim().to_owned();
        let search_pattern = format!("%{search}%");
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*)
             FROM audit_logs al
             LEFT JOIN users u ON u.id = al.user_id
             WHERE $1 = ''
                OR al.description ILIKE $2
                OR al.resource_target ILIKE $2
                OR COALESCE(u.username, '') ILIKE $2",
        )
        .bind(&search)
        .bind(&search_pattern)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        let rows = sqlx::query_as::<_, StoredAuditLogRow>(
            "SELECT
                al.id,
                al.request_id,
                al.time,
                al.ip,
                al.user_agent,
                al.resource_type,
                al.resource_id,
                al.resource_target,
                al.resource_icon,
                al.action,
                al.diff_json,
                al.status_code,
                al.additional_fields_json,
                al.description,
                al.resource_link,
                al.is_deleted,
                al.organization_id,
                o.name AS organization_name,
                o.display_name AS organization_display_name,
                o.icon AS organization_icon,
                al.user_id,
                u.username,
                u.name,
                u.avatar_url
             FROM audit_logs al
             LEFT JOIN organizations o ON o.id = al.organization_id
             LEFT JOIN users u ON u.id = al.user_id
             WHERE $1 = ''
                OR al.description ILIKE $2
                OR al.resource_target ILIKE $2
                OR COALESCE(u.username, '') ILIKE $2
             ORDER BY al.time DESC
             LIMIT $3
             OFFSET $4",
        )
        .bind(&search)
        .bind(&search_pattern)
        .bind(i64::from(filter.limit))
        .bind(i64::from(filter.offset))
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(AuditLogResponse {
            audit_logs: rows
                .into_iter()
                .map(audit_log_from_row)
                .collect::<Result<Vec<_>, _>>()?,
            count: usize::try_from(count)
                .map_err(|error| StorageError::invalid_data(error.to_string()))?,
        })
    }

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn insert_audit_log(&self, input: PersistAuditLogInput) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO audit_logs (
                id,
                request_id,
                time,
                ip,
                user_agent,
                resource_type,
                resource_id,
                resource_target,
                resource_icon,
                action,
                diff_json,
                status_code,
                additional_fields_json,
                description,
                resource_link,
                is_deleted,
                organization_id,
                user_id
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18
            )",
        )
        .bind(input.id)
        .bind(input.request_id)
        .bind(input.time)
        .bind(input.ip)
        .bind(input.user_agent)
        .bind(input.resource_type)
        .bind(input.resource_id)
        .bind(input.resource_target)
        .bind(input.resource_icon)
        .bind(input.action)
        .bind(input.diff.to_string())
        .bind(input.status_code)
        .bind(input.additional_fields.to_string())
        .bind(input.description)
        .bind(input.resource_link)
        .bind(input.is_deleted)
        .bind(input.organization_id)
        .bind(input.user_id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn health_settings(&self) -> Result<HealthSettings, StorageError> {
        let encoded: Option<String> = sqlx::query_scalar(
            "SELECT value
             FROM site_configs
             WHERE key = 'health_settings'",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        match encoded {
            Some(encoded) => {
                from_str(&encoded).map_err(|error| StorageError::invalid_data(error.to_string()))
            }
            None => Ok(HealthSettings::default()),
        }
    }

    #[instrument(skip(self, settings), err(level = tracing::Level::WARN))]
    async fn upsert_health_settings(
        &self,
        settings: &HealthSettings,
    ) -> Result<bool, StorageError> {
        let encoded = serde_json::to_string(settings)
            .map_err(|error| StorageError::invalid_data(error.to_string()))?;
        let current: Option<String> = sqlx::query_scalar(
            "SELECT value
             FROM site_configs
             WHERE key = 'health_settings'",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        if current.as_deref() == Some(encoded.as_str()) {
            return Ok(false);
        }

        sqlx::query(
            "INSERT INTO site_configs (key, value)
             VALUES ('health_settings', $1)
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(encoded)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(true)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn deployment_stats(&self) -> Result<DeploymentStatsResponse, StorageError> {
        let collected_at: OffsetDateTime = sqlx::query_scalar("SELECT NOW()")
            .fetch_one(&self.pool)
            .await
            .map_err(storage_error)?;
        let aggregated_from = collected_at - time::Duration::minutes(15);
        let next_update_at = collected_at + time::Duration::minutes(1);
        let workspace_stats = sqlx::query_as::<_, StoredDeploymentWorkspaceStatsRow>(
            "WITH workspaces_with_jobs AS (
                SELECT latest_build.*
                FROM workspaces
                LEFT JOIN LATERAL (
                    SELECT
                        workspace_builds.transition,
                        provisioner_jobs.id AS provisioner_job_id,
                        provisioner_jobs.started_at,
                        provisioner_jobs.updated_at,
                        provisioner_jobs.canceled_at,
                        provisioner_jobs.completed_at,
                        provisioner_jobs.error
                    FROM workspace_builds
                    LEFT JOIN provisioner_jobs
                        ON provisioner_jobs.id = workspace_builds.job_id
                    WHERE workspace_builds.workspace_id = workspaces.id
                    ORDER BY build_number DESC
                    LIMIT 1
                ) latest_build ON TRUE
                WHERE workspaces.deleted = FALSE
            ),
            pending_workspaces AS (
                SELECT COUNT(*)::bigint AS count
                FROM workspaces_with_jobs
                WHERE started_at IS NULL
            ),
            building_workspaces AS (
                SELECT COUNT(*)::bigint AS count
                FROM workspaces_with_jobs
                WHERE started_at IS NOT NULL
                    AND canceled_at IS NULL
                    AND completed_at IS NULL
                    AND updated_at - INTERVAL '30 seconds' < NOW()
            ),
            running_workspaces AS (
                SELECT COUNT(*)::bigint AS count
                FROM workspaces_with_jobs
                WHERE completed_at IS NOT NULL
                    AND canceled_at IS NULL
                    AND error = ''
                    AND transition = 'start'
            ),
            failed_workspaces AS (
                SELECT COUNT(*)::bigint AS count
                FROM workspaces_with_jobs
                WHERE (canceled_at IS NOT NULL AND error <> '')
                    OR (completed_at IS NOT NULL AND error <> '')
            ),
            stopped_workspaces AS (
                SELECT COUNT(*)::bigint AS count
                FROM workspaces_with_jobs
                WHERE completed_at IS NOT NULL
                    AND canceled_at IS NULL
                    AND error = ''
                    AND transition = 'stop'
            )
            SELECT
                pending_workspaces.count AS pending_workspaces,
                building_workspaces.count AS building_workspaces,
                running_workspaces.count AS running_workspaces,
                failed_workspaces.count AS failed_workspaces,
                stopped_workspaces.count AS stopped_workspaces
            FROM pending_workspaces,
                 building_workspaces,
                 running_workspaces,
                 failed_workspaces,
                 stopped_workspaces",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;
        let agent_stats = sqlx::query_as::<_, StoredDeploymentAgentStatsRow>(
            "WITH stats AS (
                SELECT
                    agent_id,
                    created_at,
                    rx_bytes,
                    tx_bytes,
                    connection_median_latency_ms,
                    session_count_vscode,
                    session_count_ssh,
                    session_count_jetbrains,
                    session_count_reconnecting_pty,
                    ROW_NUMBER() OVER (PARTITION BY agent_id ORDER BY created_at DESC) AS rn
                FROM workspace_agent_stats
                WHERE created_at > $1
            )
            SELECT
                COALESCE(SUM(rx_bytes), 0)::bigint AS workspace_rx_bytes,
                COALESCE(SUM(tx_bytes), 0)::bigint AS workspace_tx_bytes,
                COALESCE(
                    (
                        PERCENTILE_CONT(0.5) WITHIN GROUP (
                            ORDER BY connection_median_latency_ms
                        ) FILTER (WHERE connection_median_latency_ms > 0)
                    ),
                    -1
                )::float8 AS workspace_connection_latency_50,
                COALESCE(
                    (
                        PERCENTILE_CONT(0.95) WITHIN GROUP (
                            ORDER BY connection_median_latency_ms
                        ) FILTER (WHERE connection_median_latency_ms > 0)
                    ),
                    -1
                )::float8 AS workspace_connection_latency_95,
                COALESCE(SUM(session_count_vscode) FILTER (WHERE rn = 1), 0)::bigint
                    AS session_count_vscode,
                COALESCE(SUM(session_count_ssh) FILTER (WHERE rn = 1), 0)::bigint
                    AS session_count_ssh,
                COALESCE(SUM(session_count_jetbrains) FILTER (WHERE rn = 1), 0)::bigint
                    AS session_count_jetbrains,
                COALESCE(
                    SUM(session_count_reconnecting_pty) FILTER (WHERE rn = 1),
                    0
                )::bigint AS session_count_reconnecting_pty
            FROM stats",
        )
        .bind(aggregated_from)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(DeploymentStatsResponse {
            aggregated_from,
            collected_at,
            next_update_at,
            workspaces: WorkspaceDeploymentStatsResponse {
                pending: workspace_stats.pending_workspaces,
                building: workspace_stats.building_workspaces,
                running: workspace_stats.running_workspaces,
                failed: workspace_stats.failed_workspaces,
                stopped: workspace_stats.stopped_workspaces,
                connection_latency_ms: WorkspaceConnectionLatencyMs {
                    p50: agent_stats.workspace_connection_latency_50,
                    p95: agent_stats.workspace_connection_latency_95,
                },
                rx_bytes: agent_stats.workspace_rx_bytes,
                tx_bytes: agent_stats.workspace_tx_bytes,
            },
            session_count: SessionCountDeploymentStatsResponse {
                vscode: agent_stats.session_count_vscode,
                ssh: agent_stats.session_count_ssh,
                jetbrains: agent_stats.session_count_jetbrains,
                reconnecting_pty: agent_stats.session_count_reconnecting_pty,
            },
        })
    }

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn upsert_workspace_stats_workspace(
        &self,
        input: &WorkspaceStatsWorkspaceInput,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO workspaces (id, updated_at, deleted)
             VALUES ($1, NOW(), $2)
             ON CONFLICT (id) DO UPDATE SET
                updated_at = NOW(),
                deleted = EXCLUDED.deleted",
        )
        .bind(input.id)
        .bind(input.deleted)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn upsert_provisioner_job_stats(
        &self,
        input: &ProvisionerJobStatsInput,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO provisioner_jobs (
                id, created_at, updated_at, started_at, canceled_at, completed_at, error
             )
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (id) DO UPDATE SET
                updated_at = EXCLUDED.updated_at,
                started_at = EXCLUDED.started_at,
                canceled_at = EXCLUDED.canceled_at,
                completed_at = EXCLUDED.completed_at,
                error = EXCLUDED.error",
        )
        .bind(input.id)
        .bind(input.created_at)
        .bind(input.updated_at)
        .bind(input.started_at)
        .bind(input.canceled_at)
        .bind(input.completed_at)
        .bind(&input.error)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn upsert_workspace_build_stats(
        &self,
        input: &WorkspaceBuildStatsInput,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO workspace_builds (
                id, created_at, updated_at, workspace_id, build_number, transition, job_id
             )
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (id) DO UPDATE SET
                updated_at = EXCLUDED.updated_at,
                workspace_id = EXCLUDED.workspace_id,
                build_number = EXCLUDED.build_number,
                transition = EXCLUDED.transition,
                job_id = EXCLUDED.job_id",
        )
        .bind(input.id)
        .bind(input.created_at)
        .bind(input.updated_at)
        .bind(input.workspace_id)
        .bind(input.build_number)
        .bind(&input.transition)
        .bind(input.job_id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn insert_workspace_agent_stat(
        &self,
        input: &WorkspaceAgentStatInput,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO workspace_agent_stats (
                id,
                created_at,
                user_id,
                workspace_id,
                template_id,
                agent_id,
                connections_by_proto,
                connection_count,
                rx_packets,
                rx_bytes,
                tx_packets,
                tx_bytes,
                session_count_vscode,
                session_count_jetbrains,
                session_count_reconnecting_pty,
                session_count_ssh,
                connection_median_latency_ms,
                usage
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18
            )",
        )
        .bind(input.id)
        .bind(input.created_at)
        .bind(input.user_id)
        .bind(input.workspace_id)
        .bind(input.template_id)
        .bind(input.agent_id)
        .bind(&input.connections_by_proto)
        .bind(input.connection_count)
        .bind(input.rx_packets)
        .bind(input.rx_bytes)
        .bind(input.tx_packets)
        .bind(input.tx_bytes)
        .bind(input.session_count_vscode)
        .bind(input.session_count_jetbrains)
        .bind(input.session_count_reconnecting_pty)
        .bind(input.session_count_ssh)
        .bind(input.connection_median_latency_ms)
        .bind(input.usage)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_workspace_proxies_for_health(
        &self,
    ) -> Result<Vec<WorkspaceProxyHealthRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredWorkspaceProxyRow>(
            "SELECT
                id,
                name,
                display_name,
                icon_url,
                path_app_url,
                wildcard_hostname,
                derp_enabled,
                derp_only,
                created_at,
                updated_at,
                deleted,
                version
             FROM workspace_proxies
             ORDER BY name ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(workspace_proxy_record_from_row)
            .collect())
    }

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn upsert_workspace_proxy_for_health(
        &self,
        input: &WorkspaceProxyHealthInput,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO workspace_proxies (
                id,
                name,
                display_name,
                icon_url,
                path_app_url,
                wildcard_hostname,
                derp_enabled,
                derp_only,
                created_at,
                updated_at,
                deleted,
                version
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            ON CONFLICT (id) DO UPDATE SET
                name = EXCLUDED.name,
                display_name = EXCLUDED.display_name,
                icon_url = EXCLUDED.icon_url,
                path_app_url = EXCLUDED.path_app_url,
                wildcard_hostname = EXCLUDED.wildcard_hostname,
                derp_enabled = EXCLUDED.derp_enabled,
                derp_only = EXCLUDED.derp_only,
                updated_at = EXCLUDED.updated_at,
                deleted = EXCLUDED.deleted,
                version = EXCLUDED.version",
        )
        .bind(input.id)
        .bind(&input.name)
        .bind(&input.display_name)
        .bind(&input.icon_url)
        .bind(&input.path_app_url)
        .bind(&input.wildcard_hostname)
        .bind(input.derp_enabled)
        .bind(input.derp_only)
        .bind(input.created_at)
        .bind(input.updated_at)
        .bind(input.deleted)
        .bind(&input.version)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_provisioner_daemons_for_health(
        &self,
    ) -> Result<Vec<ProvisionerDaemonHealthRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredProvisionerDaemonRow>(
            "SELECT
                id,
                organization_id,
                created_at,
                last_seen_at,
                name,
                version,
                api_version,
                provisioners,
                tags_json,
                status
             FROM provisioner_daemons
             ORDER BY name ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        rows.into_iter()
            .map(provisioner_daemon_record_from_row)
            .collect()
    }

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn upsert_provisioner_daemon_for_health(
        &self,
        input: &ProvisionerDaemonHealthInput,
    ) -> Result<(), StorageError> {
        let tags_json = serde_json::to_string(&input.tags)
            .map_err(|error| StorageError::invalid_data(error.to_string()))?;
        sqlx::query(
            "INSERT INTO provisioner_daemons (
                id,
                organization_id,
                created_at,
                last_seen_at,
                name,
                version,
                api_version,
                provisioners,
                tags_json,
                status
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT (id) DO UPDATE SET
                organization_id = EXCLUDED.organization_id,
                last_seen_at = EXCLUDED.last_seen_at,
                name = EXCLUDED.name,
                version = EXCLUDED.version,
                api_version = EXCLUDED.api_version,
                provisioners = EXCLUDED.provisioners,
                tags_json = EXCLUDED.tags_json,
                status = EXCLUDED.status",
        )
        .bind(input.id)
        .bind(input.organization_id)
        .bind(input.created_at)
        .bind(input.last_seen_at)
        .bind(&input.name)
        .bind(&input.version)
        .bind(&input.api_version)
        .bind(&input.provisioners)
        .bind(tags_json)
        .bind(&input.status)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_git_ssh_key(
        &self,
        user_id: Uuid,
    ) -> Result<Option<GitSshKeyRecord>, StorageError> {
        sqlx::query_as::<_, StoredGitSshKeyRow>(
            "SELECT user_id, created_at, updated_at, public_key, private_key
             FROM git_ssh_keys
             WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?
        .map(git_ssh_key_record_from_row)
        .transpose()
    }

    #[instrument(skip(self, public_key, private_key), err(level = tracing::Level::WARN))]
    async fn upsert_git_ssh_key(
        &self,
        user_id: Uuid,
        public_key: &str,
        private_key: &str,
    ) -> Result<GitSshKeyRecord, StorageError> {
        let row = sqlx::query_as::<_, StoredGitSshKeyRow>(
            "INSERT INTO git_ssh_keys (user_id, created_at, updated_at, public_key, private_key)
             VALUES ($1, NOW(), NOW(), $2, $3)
             ON CONFLICT (user_id)
             DO UPDATE SET
                updated_at = NOW(),
                public_key = EXCLUDED.public_key,
                private_key = EXCLUDED.private_key
             RETURNING user_id, created_at, updated_at, public_key, private_key",
        )
        .bind(user_id)
        .bind(public_key)
        .bind(private_key)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        git_ssh_key_record_from_row(row)
    }

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn insert_file(&self, input: InsertFileInput) -> Result<InsertFileResult, StorageError> {
        // Only RETURNING id — avoids shipping the (potentially large) data
        // blob back from Postgres on every insert/duplicate.
        let (id,): (Uuid,) = sqlx::query_as(
            "INSERT INTO files (id, hash, created_by, created_at, mimetype, data)
             VALUES ($1, $2, $3, NOW(), $4, $5)
             ON CONFLICT (hash, created_by) DO UPDATE SET id = files.id
             RETURNING id",
        )
        .bind(input.id)
        .bind(&input.hash)
        .bind(input.created_by)
        .bind(&input.mimetype)
        .bind(&input.data)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(InsertFileResult { id })
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_file_by_id(&self, file_id: Uuid) -> Result<Option<FileRecord>, StorageError> {
        Ok(sqlx::query_as::<_, StoredFileRow>(
            "SELECT id, hash, created_by, created_at, mimetype, data
             FROM files
             WHERE id = $1",
        )
        .bind(file_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?
        .map(file_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_file_by_hash_and_creator(
        &self,
        hash: &str,
        creator_id: Uuid,
    ) -> Result<Option<FileRecord>, StorageError> {
        Ok(sqlx::query_as::<_, StoredFileRow>(
            "SELECT id, hash, created_by, created_at, mimetype, data
             FROM files
             WHERE hash = $1 AND created_by = $2",
        )
        .bind(hash)
        .bind(creator_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?
        .map(file_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_external_auth_links(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<ExternalAuthLinkRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredExternalAuthLinkRow>(
            "SELECT
                provider_id,
                created_at,
                updated_at,
                access_token,
                refresh_token,
                token_type,
                scopes,
                expires_at,
                authenticated,
                validate_error,
                refresh_error,
                last_validated_at,
                last_refreshed_at,
                external_user_json,
                installations_json,
                app_installable
             FROM external_auth_links
             WHERE user_id = $1
             ORDER BY provider_id ASC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        rows.into_iter()
            .map(external_auth_link_record_from_row)
            .collect()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_external_auth_link(
        &self,
        user_id: Uuid,
        provider_id: &str,
    ) -> Result<Option<ExternalAuthLinkRecord>, StorageError> {
        sqlx::query_as::<_, StoredExternalAuthLinkRow>(
            "SELECT
                provider_id,
                created_at,
                updated_at,
                access_token,
                refresh_token,
                token_type,
                scopes,
                expires_at,
                authenticated,
                validate_error,
                refresh_error,
                last_validated_at,
                last_refreshed_at,
                external_user_json,
                installations_json,
                app_installable
             FROM external_auth_links
             WHERE user_id = $1 AND provider_id = $2",
        )
        .bind(user_id)
        .bind(provider_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?
        .map(external_auth_link_record_from_row)
        .transpose()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_external_auth_link(
        &self,
        user_id: Uuid,
        provider_id: &str,
    ) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "DELETE FROM external_auth_links
             WHERE user_id = $1 AND provider_id = $2",
        )
        .bind(user_id)
        .bind(provider_id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self, link), err(level = tracing::Level::WARN))]
    async fn upsert_external_auth_link(
        &self,
        user_id: Uuid,
        link: &UpsertExternalAuthLinkInput,
    ) -> Result<ExternalAuthLinkRecord, StorageError> {
        let external_user_json = match &link.user {
            Some(user) => serde_json::to_string(user)
                .map_err(|error| StorageError::invalid_data(error.to_string()))?,
            None => "null".to_owned(),
        };
        let installations_json = serde_json::to_string(&link.installations)
            .map_err(|error| StorageError::invalid_data(error.to_string()))?;

        sqlx::query_as::<_, StoredExternalAuthLinkRow>(
            "INSERT INTO external_auth_links (
                provider_id,
                user_id,
                created_at,
                updated_at,
                access_token,
                refresh_token,
                token_type,
                scopes,
                expires_at,
                authenticated,
                validate_error,
                refresh_error,
                last_validated_at,
                last_refreshed_at,
                external_user_json,
                installations_json,
                app_installable
            )
            VALUES (
                $1, $2, NOW(), NOW(), $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
            )
            ON CONFLICT (provider_id, user_id) DO UPDATE SET
                updated_at = NOW(),
                access_token = EXCLUDED.access_token,
                refresh_token = EXCLUDED.refresh_token,
                token_type = EXCLUDED.token_type,
                scopes = EXCLUDED.scopes,
                expires_at = EXCLUDED.expires_at,
                authenticated = EXCLUDED.authenticated,
                validate_error = EXCLUDED.validate_error,
                refresh_error = EXCLUDED.refresh_error,
                last_validated_at = EXCLUDED.last_validated_at,
                last_refreshed_at = EXCLUDED.last_refreshed_at,
                external_user_json = EXCLUDED.external_user_json,
                installations_json = EXCLUDED.installations_json,
                app_installable = EXCLUDED.app_installable
            RETURNING
                provider_id,
                created_at,
                updated_at,
                access_token,
                refresh_token,
                token_type,
                scopes,
                expires_at,
                authenticated,
                validate_error,
                refresh_error,
                last_validated_at,
                last_refreshed_at,
                external_user_json,
                installations_json,
                app_installable",
        )
        .bind(&link.provider_id)
        .bind(user_id)
        .bind(&link.access_token)
        .bind(&link.refresh_token)
        .bind(&link.token_type)
        .bind(&link.scopes)
        .bind(link.expires_at)
        .bind(link.authenticated)
        .bind(&link.validate_error)
        .bind(&link.refresh_error)
        .bind(link.last_validated_at)
        .bind(link.last_refreshed_at)
        .bind(external_user_json)
        .bind(installations_json)
        .bind(link.app_installable)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)
        .and_then(external_auth_link_record_from_row)
    }

    // -----------------------------------------------------------------------
    // Notifications domain
    // -----------------------------------------------------------------------

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_notifications_settings(&self) -> Result<NotificationsSettings, StorageError> {
        let encoded: Option<String> = sqlx::query_scalar(
            "SELECT value FROM site_configs WHERE key = 'notifications_settings' LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        match encoded {
            Some(encoded) => {
                from_str(&encoded).map_err(|error| StorageError::invalid_data(error.to_string()))
            }
            None => Ok(NotificationsSettings::default()),
        }
    }

    #[instrument(skip(self, settings), err(level = tracing::Level::WARN))]
    async fn upsert_notifications_settings(
        &self,
        settings: &NotificationsSettings,
    ) -> Result<(), StorageError> {
        let json = serde_json::to_string(settings)
            .map_err(|e| StorageError::invalid_data(e.to_string()))?;

        sqlx::query(
            "INSERT INTO site_configs (key, value)
             VALUES ('notifications_settings', $1)
             ON CONFLICT (key) DO UPDATE SET value = $1",
        )
        .bind(&json)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_notification_templates_by_kind(
        &self,
        kind: &str,
    ) -> Result<Vec<NotificationTemplate>, StorageError> {
        let rows = sqlx::query_as::<_, StoredNotificationTemplateRow>(
            r#"SELECT id, name, title_template, body_template, actions::text, "group", method::text,
                      kind::text, enabled_by_default
               FROM notification_templates
               WHERE ($1 = '' OR kind::text = $1)
               ORDER BY name ASC"#,
        )
        .bind(kind)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        let mut templates = Vec::with_capacity(rows.len());
        for r in rows {
            templates.push(NotificationTemplate {
                id: r.id,
                name: r.name,
                title_template: r.title_template,
                body_template: r.body_template,
                actions: r
                    .actions
                    .map(|s| from_str(&s))
                    .transpose()
                    .map_err(|e| StorageError::invalid_data(e.to_string()))?,
                group: r.group,
                method: r.method,
                kind: r.kind,
                enabled_by_default: r.enabled_by_default,
            });
        }
        Ok(templates)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_notification_template_method(
        &self,
        template_id: Uuid,
        method: Option<&str>,
    ) -> Result<Option<NotificationTemplate>, StorageError> {
        let row = sqlx::query_as::<_, StoredNotificationTemplateRow>(
            r#"UPDATE notification_templates
               SET method = $2::notification_method
               WHERE id = $1
               RETURNING id, name, title_template, body_template, actions::text, "group", method::text,
                         kind::text, enabled_by_default"#,
        )
        .bind(template_id)
        .bind(method)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        match row {
            Some(r) => Ok(Some(NotificationTemplate {
                id: r.id,
                name: r.name,
                title_template: r.title_template,
                body_template: r.body_template,
                actions: r
                    .actions
                    .map(|s| from_str(&s))
                    .transpose()
                    .map_err(|e| StorageError::invalid_data(e.to_string()))?,
                group: r.group,
                method: r.method,
                kind: r.kind,
                enabled_by_default: r.enabled_by_default,
            })),
            None => Ok(None),
        }
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_user_notification_preferences(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<NotificationPreference>, StorageError> {
        let rows = sqlx::query_as::<_, StoredNotificationPreferenceRow>(
            "SELECT notification_template_id AS id, disabled, updated_at
             FROM notification_preferences
             WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(|r| NotificationPreference {
                id: r.id,
                disabled: r.disabled,
                updated_at: r.updated_at,
            })
            .collect())
    }

    #[instrument(skip(self, template_ids, disableds), err(level = tracing::Level::WARN))]
    async fn update_user_notification_preferences(
        &self,
        user_id: Uuid,
        template_ids: &[Uuid],
        disableds: &[bool],
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO notification_preferences (user_id, notification_template_id, disabled)
             SELECT $1, UNNEST($2::uuid[]), UNNEST($3::bool[])
             ON CONFLICT (user_id, notification_template_id) DO UPDATE SET
                disabled = EXCLUDED.disabled,
                updated_at = NOW()",
        )
        .bind(user_id)
        .bind(template_ids)
        .bind(disableds)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_filtered_inbox_notifications(
        &self,
        user_id: Uuid,
        templates: Option<&[Uuid]>,
        targets: Option<&[Uuid]>,
        read_status: &str,
        created_before: Option<OffsetDateTime>,
    ) -> Result<Vec<InboxNotification>, StorageError> {
        let rows = sqlx::query_as::<_, StoredInboxNotificationRow>(
            r#"SELECT id, user_id, template_id, targets, title, content, icon, actions::text,
                      read_at, created_at
               FROM inbox_notifications
               WHERE user_id = $1
                 AND ($2::uuid[] IS NULL OR template_id = ANY($2))
                 AND ($3::uuid[] IS NULL OR targets && $3::uuid[])
                 AND (
                    $4 = 'all'
                    OR ($4 = 'unread' AND read_at IS NULL)
                    OR ($4 = 'read' AND read_at IS NOT NULL)
                 )
                 AND ($5::timestamptz IS NULL OR created_at < $5)
               ORDER BY created_at DESC
               LIMIT 25"#,
        )
        .bind(user_id)
        .bind(templates)
        .bind(targets)
        .bind(read_status)
        .bind(created_before)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        rows.into_iter().map(inbox_notification_from_row).collect()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn count_unread_inbox_notifications(&self, user_id: Uuid) -> Result<i64, StorageError> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM inbox_notifications WHERE user_id = $1 AND read_at IS NULL",
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(row.0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_inbox_notification_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<InboxNotification>, StorageError> {
        let row = sqlx::query_as::<_, StoredInboxNotificationRow>(
            "SELECT id, user_id, template_id, targets, title, content, icon, actions::text,
                    read_at, created_at
             FROM inbox_notifications WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        row.map(inbox_notification_from_row).transpose()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_inbox_notification_read_status(
        &self,
        id: Uuid,
        read_at: Option<OffsetDateTime>,
    ) -> Result<(), StorageError> {
        sqlx::query("UPDATE inbox_notifications SET read_at = $2 WHERE id = $1")
            .bind(id)
            .bind(read_at)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn mark_all_inbox_notifications_as_read(
        &self,
        user_id: Uuid,
        read_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "UPDATE inbox_notifications SET read_at = $2 WHERE user_id = $1 AND read_at IS NULL",
        )
        .bind(user_id)
        .bind(read_at)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_webpush_subscriptions_by_user_id(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<WebpushSubscriptionRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredWebpushSubscriptionRow>(
            "SELECT id, user_id, created_at, endpoint, endpoint_p256dh_key, endpoint_auth_key
             FROM webpush_subscriptions WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(|r| WebpushSubscriptionRecord {
                id: r.id,
                user_id: r.user_id,
                created_at: r.created_at,
                endpoint: r.endpoint,
                endpoint_p256dh_key: r.endpoint_p256dh_key,
                endpoint_auth_key: r.endpoint_auth_key,
            })
            .collect())
    }

    #[instrument(skip(self, endpoint, p256dh_key, auth_key), err(level = tracing::Level::WARN))]
    async fn insert_webpush_subscription(
        &self,
        user_id: Uuid,
        endpoint: &str,
        p256dh_key: &str,
        auth_key: &str,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO webpush_subscriptions (id, user_id, created_at, endpoint, endpoint_p256dh_key, endpoint_auth_key)
             VALUES (gen_random_uuid(), $1, NOW(), $2, $3, $4)
             ON CONFLICT (user_id, endpoint) DO UPDATE
             SET endpoint_p256dh_key = $3, endpoint_auth_key = $4",
        )
        .bind(user_id)
        .bind(endpoint)
        .bind(p256dh_key)
        .bind(auth_key)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self, endpoint), err(level = tracing::Level::WARN))]
    async fn delete_webpush_subscription_by_user_and_endpoint(
        &self,
        user_id: Uuid,
        endpoint: &str,
    ) -> Result<bool, StorageError> {
        let result =
            sqlx::query("DELETE FROM webpush_subscriptions WHERE user_id = $1 AND endpoint = $2")
                .bind(user_id)
                .bind(endpoint)
                .execute(&self.pool)
                .await
                .map_err(storage_error)?;

        Ok(result.rows_affected() > 0)
    }
}

async fn ensure_default_organization(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<Uuid, StorageError> {
    let organization_id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO organizations (
            id,
            name,
            display_name,
            description,
            icon,
            created_at,
            updated_at,
            is_default,
            deleted,
            workspace_sharing_disabled
        )
        SELECT
            $1,
            'first-organization',
            'First Organization',
            'Builtin default organization.',
            '',
            NOW(),
            NOW(),
            true,
            false,
            false
        WHERE NOT EXISTS (
            SELECT 1
            FROM organizations
            WHERE is_default = true
        )",
    )
    .bind(organization_id)
    .execute(&mut **transaction)
    .await
    .map_err(storage_error)?;

    sqlx::query_scalar(
        "SELECT id
         FROM organizations
         WHERE is_default = true
         LIMIT 1",
    )
    .fetch_one(&mut **transaction)
    .await
    .map_err(storage_error)
}

fn user_record_from_row(row: StoredUserRow) -> Result<UserRecord, StorageError> {
    let login_type = LoginType::from_str(&row.login_type)
        .map_err(|error| StorageError::invalid_data(error.to_string()))?;
    let status = UserStatus::from_str(&row.status)
        .map_err(|error| StorageError::invalid_data(error.to_string()))?;

    Ok(UserRecord {
        id: row.id,
        email: row.email,
        username: row.username,
        name: row.name,
        avatar_url: row.avatar_url,
        created_at: row.created_at,
        updated_at: row.updated_at,
        last_seen_at: row.last_seen_at,
        organization_ids: row.organization_ids,
        roles: slim_roles_from_names(&row.global_roles, None),
        login_type,
        status,
        deleted: row.deleted,
        is_system: row.is_system,
    })
}

fn password_record_from_row(
    row: StoredPasswordUserRow,
) -> Result<PasswordUserRecord, StorageError> {
    let password_hash = String::from_utf8(row.hashed_password.clone()).map_err(|error| {
        StorageError::invalid_data(format!(
            "users.hashed_password must be valid UTF-8: {error}"
        ))
    })?;
    let one_time_passcode_hash = if row.hashed_one_time_passcode.is_empty() {
        None
    } else {
        Some(
            String::from_utf8(row.hashed_one_time_passcode.clone()).map_err(|error| {
                StorageError::invalid_data(format!(
                    "users.hashed_one_time_passcode must be valid UTF-8: {error}"
                ))
            })?,
        )
    };

    Ok(PasswordUserRecord {
        user: user_record_from_password_row(&row)?,
        password_hash,
        one_time_passcode_hash,
        one_time_passcode_expires_at: row.one_time_passcode_expires_at,
    })
}

fn user_record_from_password_row(row: &StoredPasswordUserRow) -> Result<UserRecord, StorageError> {
    let login_type = LoginType::from_str(&row.login_type)
        .map_err(|error| StorageError::invalid_data(error.to_string()))?;
    let status = UserStatus::from_str(&row.status)
        .map_err(|error| StorageError::invalid_data(error.to_string()))?;

    Ok(UserRecord {
        id: row.id,
        email: row.email.clone(),
        username: row.username.clone(),
        name: row.name.clone(),
        avatar_url: row.avatar_url.clone(),
        created_at: row.created_at,
        updated_at: row.updated_at,
        last_seen_at: row.last_seen_at,
        organization_ids: row.organization_ids.clone(),
        roles: slim_roles_from_names(&row.global_roles, None),
        login_type,
        status,
        deleted: row.deleted,
        is_system: row.is_system,
    })
}

fn organization_record_from_row(
    row: StoredOrganizationRow,
) -> Result<OrganizationRecord, StorageError> {
    if row.name.trim().is_empty() {
        return Err(StorageError::invalid_data(
            "organizations.name must not be empty",
        ));
    }

    Ok(OrganizationRecord {
        id: row.id,
        name: row.name,
        display_name: row.display_name,
        description: row.description,
        icon: row.icon,
        created_at: row.created_at,
        updated_at: row.updated_at,
        is_default: row.is_default,
        deleted: row.deleted,
    })
}

fn organization_member_record_from_row(
    row: StoredOrganizationMemberRow,
) -> Result<OrganizationMemberRecord, StorageError> {
    Ok(OrganizationMemberRecord {
        user_id: row.user_id,
        organization_id: row.organization_id,
        created_at: row.created_at,
        updated_at: row.updated_at,
        roles: slim_roles_from_names(&row.roles, Some(row.organization_id)),
        username: row.username,
        name: row.name,
        avatar_url: row.avatar_url,
        email: row.email,
        global_roles: slim_roles_from_names(&row.global_roles, None),
    })
}

fn api_key_record_from_row(row: StoredApiKeyRow) -> Result<ApiKeyRecord, StorageError> {
    let login_type = LoginType::from_str(&row.login_type)
        .map_err(|error| StorageError::invalid_data(error.to_string()))?;
    let allow_list = from_str::<Vec<ApiAllowListTarget>>(&row.allow_list_json)
        .map_err(|error| StorageError::invalid_data(error.to_string()))?;

    Ok(ApiKeyRecord {
        id: row.id,
        hashed_secret: row.hashed_secret,
        user_id: row.user_id,
        last_used: row.last_used,
        expires_at: row.expires_at,
        created_at: row.created_at,
        updated_at: row.updated_at,
        login_type,
        scopes: row.scopes,
        token_name: row.token_name,
        lifetime_seconds: row.lifetime_seconds,
        allow_list,
    })
}

fn audit_log_from_row(row: StoredAuditLogRow) -> Result<AuditLog, StorageError> {
    let resource_type = match row.resource_type.as_str() {
        "user" => AuditResourceType::User,
        "api_key" => AuditResourceType::ApiKey,
        "git_ssh_key" => AuditResourceType::GitSshKey,
        "health_settings" => AuditResourceType::HealthSettings,
        "organization" => AuditResourceType::Organization,
        "organization_member" => AuditResourceType::OrganizationMember,
        "convert_login" => AuditResourceType::ConvertLogin,
        other => {
            return Err(StorageError::invalid_data(format!(
                "unsupported audit resource type: {other}"
            )));
        }
    };
    let action = match row.action.as_str() {
        "create" => AuditLogAction::Create,
        "write" => AuditLogAction::Write,
        "delete" => AuditLogAction::Delete,
        "start" => AuditLogAction::Start,
        "stop" => AuditLogAction::Stop,
        "login" => AuditLogAction::Login,
        "logout" => AuditLogAction::Logout,
        "register" => AuditLogAction::Register,
        "request_password_reset" => AuditLogAction::RequestPasswordReset,
        other => {
            return Err(StorageError::invalid_data(format!(
                "unsupported audit action: {other}"
            )));
        }
    };
    let diff = from_str::<AuditDiff>(&row.diff_json)
        .map_err(|error| StorageError::invalid_data(error.to_string()))?;
    let additional_fields = from_str::<Value>(&row.additional_fields_json)
        .map_err(|error| StorageError::invalid_data(error.to_string()))?;

    Ok(AuditLog {
        id: row.id,
        request_id: row.request_id,
        time: row.time,
        ip: row.ip,
        user_agent: row.user_agent,
        resource_type,
        resource_id: row.resource_id,
        resource_target: row.resource_target,
        resource_icon: row.resource_icon,
        action,
        diff,
        status_code: row.status_code,
        additional_fields,
        description: row.description,
        resource_link: row.resource_link,
        is_deleted: row.is_deleted,
        organization_id: row.organization_id,
        organization: row.organization_id.map(|id| MinimalOrganization {
            id,
            name: row.organization_name.unwrap_or_default(),
            display_name: row.organization_display_name.unwrap_or_default(),
            icon: row.organization_icon.unwrap_or_default(),
        }),
        user: row.user_id.map(|id| MinimalUser {
            id,
            username: row.username.unwrap_or_default(),
            name: row.name.unwrap_or_default(),
            avatar_url: row.avatar_url.unwrap_or_default(),
        }),
    })
}

fn git_ssh_key_record_from_row(row: StoredGitSshKeyRow) -> Result<GitSshKeyRecord, StorageError> {
    if row.public_key.trim().is_empty() || row.private_key.trim().is_empty() {
        return Err(StorageError::invalid_data(
            "git ssh keys must contain both public and private material",
        ));
    }

    Ok(GitSshKeyRecord {
        user_id: row.user_id,
        created_at: row.created_at,
        updated_at: row.updated_at,
        public_key: row.public_key,
        private_key: row.private_key,
    })
}

fn external_auth_link_record_from_row(
    row: StoredExternalAuthLinkRow,
) -> Result<ExternalAuthLinkRecord, StorageError> {
    let user = match row.external_user_json.as_str() {
        "" | "null" => None,
        encoded => Some(
            from_str::<ExternalAuthUser>(encoded)
                .map_err(|error| StorageError::invalid_data(error.to_string()))?,
        ),
    };
    let installations = from_str::<Vec<ExternalAuthAppInstallation>>(&row.installations_json)
        .map_err(|error| StorageError::invalid_data(error.to_string()))?;

    Ok(ExternalAuthLinkRecord {
        provider_id: row.provider_id,
        created_at: row.created_at,
        updated_at: row.updated_at,
        has_refresh_token: !row.refresh_token.is_empty(),
        access_token: row.access_token,
        refresh_token: row.refresh_token,
        token_type: row.token_type,
        scopes: row.scopes,
        expires: row.expires_at,
        authenticated: row.authenticated,
        validate_error: row.validate_error,
        refresh_error: row.refresh_error,
        last_validated_at: row.last_validated_at,
        last_refreshed_at: row.last_refreshed_at,
        user,
        installations,
        app_installable: row.app_installable,
    })
}

fn workspace_proxy_record_from_row(row: StoredWorkspaceProxyRow) -> WorkspaceProxyHealthRecord {
    WorkspaceProxyHealthRecord {
        id: row.id,
        name: row.name,
        display_name: row.display_name,
        icon_url: row.icon_url,
        path_app_url: row.path_app_url,
        wildcard_hostname: row.wildcard_hostname,
        derp_enabled: row.derp_enabled,
        derp_only: row.derp_only,
        created_at: row.created_at,
        updated_at: row.updated_at,
        deleted: row.deleted,
        version: row.version,
    }
}

fn provisioner_daemon_record_from_row(
    row: StoredProvisionerDaemonRow,
) -> Result<ProvisionerDaemonHealthRecord, StorageError> {
    let tags =
        from_str(&row.tags_json).map_err(|error| StorageError::invalid_data(error.to_string()))?;

    Ok(ProvisionerDaemonHealthRecord {
        id: row.id,
        organization_id: row.organization_id,
        created_at: row.created_at,
        last_seen_at: row.last_seen_at,
        name: row.name,
        version: row.version,
        api_version: row.api_version,
        provisioners: row.provisioners,
        tags,
        status: row.status,
    })
}

fn file_record_from_row(row: StoredFileRow) -> FileRecord {
    FileRecord {
        id: row.id,
        hash: row.hash,
        created_by: row.created_by,
        created_at: row.created_at,
        mimetype: row.mimetype,
        data: row.data,
    }
}

fn slim_roles_from_names(
    role_names: &[String],
    organization_id: Option<Uuid>,
) -> Vec<SlimRoleRecord> {
    role_names
        .iter()
        .map(|role| SlimRoleRecord {
            name: role.clone(),
            display_name: role
                .split(['-', '_'])
                .filter(|part| !part.is_empty())
                .map(title_case)
                .collect::<Vec<_>>()
                .join(" "),
            organization_id,
        })
        .collect()
}

fn title_case(value: &str) -> String {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

fn inbox_notification_from_row(
    row: StoredInboxNotificationRow,
) -> Result<InboxNotification, StorageError> {
    let actions: Vec<InboxNotificationAction> =
        from_str(&row.actions).map_err(|error| StorageError::invalid_data(error.to_string()))?;

    Ok(InboxNotification {
        id: row.id,
        user_id: row.user_id,
        template_id: row.template_id,
        targets: row.targets,
        title: row.title,
        content: row.content,
        icon: row.icon,
        actions,
        read_at: row.read_at,
        created_at: row.created_at,
    })
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    matches!(
        error,
        sqlx::Error::Database(database_error) if database_error.is_unique_violation()
    )
}

fn storage_error(error: sqlx::Error) -> StorageError {
    StorageError::unavailable(error.to_string())
}
