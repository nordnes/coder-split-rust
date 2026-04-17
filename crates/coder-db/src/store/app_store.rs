use super::*;

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
        let query_start = std::time::Instant::now();
        let result: Result<Option<AuthenticatedUser>, StorageError> = async {
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
        }.await;
        let query_duration = query_start.elapsed().as_secs_f64() * 1000.0;
        record_db_query(
            "find_user_by_session_token_hash",
            query_duration,
            result.is_ok(),
        );
        result
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
        let query_start = std::time::Instant::now();
        let result = sqlx::query_as::<_, StoredUserRow>(
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
        .map_err(storage_error)
        .and_then(|opt| opt.map(user_record_from_row).transpose());
        let query_duration = query_start.elapsed().as_secs_f64() * 1000.0;
        record_db_query("find_user_by_id", query_duration, result.is_ok());
        result
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

    // ----- User identity supplements -----

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn upsert_user_link(
        &self,
        user_id: Uuid,
        input: &UpsertUserLinkInput,
    ) -> Result<UserLinkRecord, StorageError> {
        let row = sqlx::query_as::<_, StoredUserLinkRow>(
            "INSERT INTO user_links (
                user_id, login_type, linked_id,
                oauth_access_token, oauth_refresh_token, oauth_expiry, claims
             ) VALUES ($1, $2::login_type, $3, $4, $5, $6, $7)
             ON CONFLICT (user_id, login_type) DO UPDATE SET
                linked_id = EXCLUDED.linked_id,
                oauth_access_token = EXCLUDED.oauth_access_token,
                oauth_refresh_token = EXCLUDED.oauth_refresh_token,
                oauth_expiry = EXCLUDED.oauth_expiry,
                claims = EXCLUDED.claims
             RETURNING
                user_id,
                login_type::text AS login_type,
                linked_id,
                oauth_access_token,
                oauth_refresh_token,
                oauth_expiry,
                claims",
        )
        .bind(user_id)
        .bind(input.login_type.as_str())
        .bind(&input.linked_id)
        .bind(&input.oauth_access_token)
        .bind(&input.oauth_refresh_token)
        .bind(input.oauth_expiry)
        .bind(serde_json::to_value(&input.claims).unwrap_or_default())
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        user_link_record_from_row(row)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_user_link(
        &self,
        user_id: Uuid,
        login_type: LoginType,
    ) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "DELETE FROM user_links WHERE user_id = $1 AND login_type = $2::login_type",
        )
        .bind(user_id)
        .bind(login_type.as_str())
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_user_config(
        &self,
        user_id: Uuid,
        key: &str,
    ) -> Result<Option<UserConfigRecord>, StorageError> {
        let row = sqlx::query_as::<_, StoredUserConfigRow>(
            "SELECT user_id, key, value FROM user_configs WHERE user_id = $1 AND key = $2",
        )
        .bind(user_id)
        .bind(key)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(row.map(|r| UserConfigRecord {
            user_id: r.user_id,
            key: r.key,
            value: r.value,
        }))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn upsert_user_config(
        &self,
        user_id: Uuid,
        key: &str,
        value: &str,
    ) -> Result<UserConfigRecord, StorageError> {
        let row = sqlx::query_as::<_, StoredUserConfigRow>(
            "INSERT INTO user_configs (user_id, key, value)
             VALUES ($1, $2, $3)
             ON CONFLICT (user_id, key) DO UPDATE SET value = EXCLUDED.value
             RETURNING user_id, key, value",
        )
        .bind(user_id)
        .bind(key)
        .bind(value)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(UserConfigRecord {
            user_id: row.user_id,
            key: row.key,
            value: row.value,
        })
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_user_config(&self, user_id: Uuid, key: &str) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM user_configs WHERE user_id = $1 AND key = $2")
            .bind(user_id)
            .bind(key)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;

        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn insert_user_deleted(
        &self,
        user_id: Uuid,
        deleted_by: Option<Uuid>,
        reason: &str,
    ) -> Result<UserDeletedRecord, StorageError> {
        let row = sqlx::query_as::<_, StoredUserDeletedRow>(
            "INSERT INTO user_deleted (user_id, deleted_by, reason)
             VALUES ($1, $2, $3)
             RETURNING id, user_id, deleted_at, deleted_by, reason",
        )
        .bind(user_id)
        .bind(deleted_by)
        .bind(reason)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(UserDeletedRecord {
            id: row.id,
            user_id: row.user_id,
            deleted_at: row.deleted_at,
            deleted_by: row.deleted_by,
            reason: row.reason,
        })
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn insert_user_status_change(
        &self,
        user_id: Uuid,
        old_status: UserStatus,
        new_status: UserStatus,
        changed_by: Option<Uuid>,
        reason: &str,
    ) -> Result<UserStatusChangeRecord, StorageError> {
        let row = sqlx::query_as::<_, StoredUserStatusChangeRow>(
            "INSERT INTO user_status_changes (user_id, old_status, new_status, changed_by, reason)
             VALUES ($1, $2::user_status, $3::user_status, $4, $5)
             RETURNING id, user_id, new_status::text AS new_status, old_status::text AS old_status, changed_at, changed_by, reason",
        )
        .bind(user_id)
        .bind(old_status.as_str())
        .bind(new_status.as_str())
        .bind(changed_by)
        .bind(reason)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        user_status_change_record_from_row(row)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_custom_role(
        &self,
        name: &str,
        organization_id: Option<Uuid>,
    ) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "DELETE FROM custom_roles WHERE name = lower($1) AND organization_id IS NOT DISTINCT FROM $2",
        )
        .bind(name)
        .bind(organization_id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_user_by_linked_id(
        &self,
        login_type: LoginType,
        linked_id: &str,
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
             JOIN user_links ul ON ul.user_id = u.id
             LEFT JOIN organization_members om ON om.user_id = u.id
             WHERE ul.login_type = $1::login_type AND ul.linked_id = $2
             GROUP BY u.id
             LIMIT 1",
        )
        .bind(login_type.as_str())
        .bind(linked_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?
        .map(user_record_from_row)
        .transpose()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_active_user_by_email_and_login_type(
        &self,
        email: &str,
        login_type: LoginType,
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
             WHERE lower(u.email) = lower($1)
               AND u.login_type = $2::login_type
               AND u.deleted = false
               AND u.is_system = false
               AND u.status = 'active'
             GROUP BY u.id
             LIMIT 1",
        )
        .bind(email)
        .bind(login_type.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?
        .map(user_record_from_row)
        .transpose()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_user_links(&self, user_id: Uuid) -> Result<Vec<UserLinkRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredUserLinkRow>(
            "SELECT
                user_id,
                login_type::text AS login_type,
                linked_id,
                oauth_access_token,
                oauth_refresh_token,
                oauth_expiry,
                claims
             FROM user_links
             WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        rows.into_iter().map(user_link_record_from_row).collect()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_user_status_changes(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<UserStatusChangeRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredUserStatusChangeRow>(
            "SELECT
                id,
                user_id,
                new_status::text AS new_status,
                old_status::text AS old_status,
                changed_at,
                changed_by,
                reason
             FROM user_status_changes
             WHERE user_id = $1
             ORDER BY changed_at ASC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        rows.into_iter()
            .map(user_status_change_record_from_row)
            .collect()
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
                deleted,
                workspace_sharing_mode
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
                deleted,
                workspace_sharing_mode
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
                deleted,
                workspace_sharing_mode
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
    async fn insert_organization(
        &self,
        input: &CreateOrganizationInput,
    ) -> Result<OrganizationRecord, CreateOrganizationStoreError> {
        let row = sqlx::query_as::<_, StoredOrganizationRow>(
            "INSERT INTO organizations (id, name, display_name, description, icon, created_at, updated_at, is_default, deleted)
             VALUES (gen_random_uuid(), $1, $2, $3, $4, NOW(), NOW(), false, false)
             RETURNING id, name, display_name, description, icon, created_at, updated_at, is_default, deleted, workspace_sharing_mode",
        )
        .bind(&input.name)
        .bind(&input.display_name)
        .bind(&input.description)
        .bind(&input.icon)
        .fetch_one(&self.pool)
        .await
        .map_err(|error| {
            if is_unique_violation(&error) {
                CreateOrganizationStoreError::AlreadyExists
            } else {
                CreateOrganizationStoreError::Storage(storage_error(error))
            }
        })?;
        organization_record_from_row(row).map_err(|e| CreateOrganizationStoreError::Storage(e))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_organization(
        &self,
        input: &UpdateOrganizationInput,
    ) -> Result<OrganizationRecord, UpdateOrganizationStoreError> {
        let row = sqlx::query_as::<_, StoredOrganizationRow>(
            "UPDATE organizations
             SET name = $2, display_name = $3, description = $4, icon = $5, updated_at = NOW()
             WHERE id = $1 AND deleted = false
             RETURNING id, name, display_name, description, icon, created_at, updated_at, is_default, deleted, workspace_sharing_mode",
        )
        .bind(input.id)
        .bind(&input.name)
        .bind(&input.display_name)
        .bind(&input.description)
        .bind(&input.icon)
        .fetch_one(&self.pool)
        .await
        .map_err(|error| {
            if is_unique_violation(&error) {
                UpdateOrganizationStoreError::AlreadyExists
            } else {
                UpdateOrganizationStoreError::Storage(storage_error_or_not_found(error))
            }
        })?;
        organization_record_from_row(row).map_err(|e| UpdateOrganizationStoreError::Storage(e))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn soft_delete_organization(&self, id: Uuid) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "UPDATE organizations SET deleted = true, updated_at = NOW() WHERE id = $1 AND deleted = false",
        )
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_organization_sharing_settings(
        &self,
        organization_id: Uuid,
    ) -> Result<Option<WorkspaceSharingMode>, StorageError> {
        let raw = sqlx::query_scalar::<_, String>(
            "SELECT workspace_sharing_mode
             FROM organizations
             WHERE id = $1 AND deleted = false",
        )
        .bind(organization_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        raw.map(|value| {
            WorkspaceSharingMode::from_str(&value).map_err(|error| {
                StorageError::invalid_data(format!("organizations.workspace_sharing_mode: {error}"))
            })
        })
        .transpose()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_organization_sharing_settings(
        &self,
        organization_id: Uuid,
        mode: WorkspaceSharingMode,
    ) -> Result<Option<WorkspaceSharingMode>, StorageError> {
        let mut tx = self.pool.begin().await.map_err(storage_error)?;

        // Keep the legacy `workspace_sharing_disabled` boolean in lock-step
        // with the richer `workspace_sharing_mode` column so old readers
        // keep working until the boolean is dropped in a follow-up PR.
        let updated = sqlx::query_scalar::<_, String>(
            "UPDATE organizations
             SET workspace_sharing_mode = $2,
                 workspace_sharing_disabled = $3,
                 updated_at = NOW()
             WHERE id = $1 AND deleted = false
             RETURNING workspace_sharing_mode",
        )
        .bind(organization_id)
        .bind(mode.as_str())
        .bind(mode.disables_sharing())
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage_error)?;

        tx.commit().await.map_err(storage_error)?;

        updated
            .map(|value| {
                WorkspaceSharingMode::from_str(&value).map_err(|error| {
                    StorageError::invalid_data(format!(
                        "organizations.workspace_sharing_mode: {error}"
                    ))
                })
            })
            .transpose()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_organization_resource_counts(
        &self,
        id: Uuid,
    ) -> Result<OrgResourceCounts, StorageError> {
        #[derive(sqlx::FromRow)]
        struct Counts {
            workspace_count: i64,
            template_count: i64,
            member_count: i64,
            group_count: i64,
            provisioner_key_count: i64,
        }
        let counts = sqlx::query_as::<_, Counts>(
            "SELECT
                (SELECT COUNT(*) FROM workspaces WHERE organization_id = $1 AND deleted = false) AS workspace_count,
                (SELECT COUNT(*) FROM templates WHERE organization_id = $1 AND deleted = false) AS template_count,
                (SELECT COUNT(*) FROM organization_members WHERE organization_id = $1) AS member_count,
                (SELECT COUNT(*) FROM groups WHERE organization_id = $1) AS group_count,
                (SELECT COUNT(*) FROM provisioner_keys WHERE organization_id = $1) AS provisioner_key_count",
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(OrgResourceCounts {
            workspace_count: counts.workspace_count as u64,
            template_count: counts.template_count as u64,
            member_count: counts.member_count as u64,
            group_count: counts.group_count as u64,
            provisioner_key_count: counts.provisioner_key_count as u64,
        })
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_custom_role(
        &self,
        name: &str,
        organization_id: Option<Uuid>,
    ) -> Result<Option<CustomRoleRecord>, StorageError> {
        let row = sqlx::query_as::<_, StoredCustomRoleRow>(
            "SELECT name, display_name, organization_id,
                    site_permissions::text AS site_permissions,
                    org_permissions::text AS org_permissions,
                    user_permissions::text AS user_permissions,
                    created_at, updated_at
             FROM custom_roles
             WHERE LOWER(name) = LOWER($1)
               AND (($2::uuid IS NULL AND organization_id IS NULL) OR organization_id = $2)",
        )
        .bind(name)
        .bind(organization_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(row.map(|r| CustomRoleRecord {
            name: r.name,
            display_name: r.display_name,
            organization_id: r.organization_id,
            site_permissions: r.site_permissions,
            org_permissions: r.org_permissions,
            user_permissions: r.user_permissions,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }))
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
    async fn update_api_key_last_used(
        &self,
        id: &str,
        last_used: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "UPDATE api_keys
             SET last_used = $2, expires_at = $3, updated_at = NOW()
             WHERE id = $1",
        )
        .bind(id)
        .bind(last_used)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_user_last_seen_at(
        &self,
        user_id: Uuid,
        last_seen_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "UPDATE users
             SET last_seen_at = $2, updated_at = NOW()
             WHERE id = $1",
        )
        .bind(user_id)
        .bind(last_seen_at)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
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
        let query_start = std::time::Instant::now();
        let result = sqlx::query(
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
        .map(|_| ())
        .map_err(storage_error);

        let query_duration = query_start.elapsed().as_secs_f64() * 1000.0;
        record_db_query("insert_audit_log", query_duration, result.is_ok());
        result
    }

    #[instrument(skip(self, logs), err(level = tracing::Level::WARN))]
    async fn batch_insert_audit_logs(
        &self,
        logs: Vec<PersistAuditLogInput>,
    ) -> Result<(), StorageError> {
        if logs.is_empty() {
            return Ok(());
        }

        // Build a multi-row INSERT statement dynamically.
        let mut query = String::from(
            "INSERT INTO audit_logs (
                id, request_id, time, ip, user_agent, resource_type, resource_id,
                resource_target, resource_icon, action, diff_json, status_code,
                additional_fields_json, description, resource_link, is_deleted,
                organization_id, user_id
            ) VALUES ",
        );

        let mut param_idx = 1u32;
        for (i, _) in logs.iter().enumerate() {
            if i > 0 {
                query.push_str(", ");
            }
            query.push('(');
            for j in 0..18u32 {
                if j > 0 {
                    query.push_str(", ");
                }
                query.push('$');
                query.push_str(&(param_idx + j).to_string());
            }
            query.push(')');
            param_idx += 18;
        }

        let mut sqlx_query = sqlx::query(&query);
        for input in &logs {
            sqlx_query = sqlx_query
                .bind(input.id)
                .bind(input.request_id)
                .bind(input.time)
                .bind(&input.ip)
                .bind(&input.user_agent)
                .bind(&input.resource_type)
                .bind(input.resource_id)
                .bind(&input.resource_target)
                .bind(&input.resource_icon)
                .bind(&input.action)
                .bind(input.diff.to_string())
                .bind(input.status_code)
                .bind(input.additional_fields.to_string())
                .bind(&input.description)
                .bind(&input.resource_link)
                .bind(input.is_deleted)
                .bind(input.organization_id)
                .bind(input.user_id);
        }

        sqlx_query
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_connection_logs(
        &self,
        filter: ConnectionLogListFilter,
    ) -> Result<ConnectionLogResponse, StorageError> {
        // The connection_logs table may not exist yet (enterprise-only migration).
        // Return an empty response; the feature gate middleware prevents unlicensed
        // access, and the actual SQL will be wired when the migration lands.
        let _ = filter;
        Ok(ConnectionLogResponse {
            connection_logs: Vec::new(),
            count: 0,
        })
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_users_by_ids(&self, ids: &[Uuid]) -> Result<Vec<UserRecord>, StorageError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }

        let rows: Vec<StoredUserRow> = sqlx::query_as(
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
             WHERE u.id = ANY($1) AND u.deleted = false
             GROUP BY u.id",
        )
        .bind(ids)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        rows.into_iter().map(user_record_from_row).collect()
    }

    #[instrument(skip(self, params), err(level = tracing::Level::WARN))]
    async fn batch_insert_workspace_build_parameters(
        &self,
        params: Vec<WorkspaceBuildParameterRecord>,
    ) -> Result<(), StorageError> {
        if params.is_empty() {
            return Ok(());
        }

        let mut query = String::from(
            "INSERT INTO workspace_build_parameters (
                workspace_build_id, name, value
            ) VALUES ",
        );

        let mut param_idx = 1u32;
        for (i, _) in params.iter().enumerate() {
            if i > 0 {
                query.push_str(", ");
            }
            query.push('(');
            for j in 0..3u32 {
                if j > 0 {
                    query.push_str(", ");
                }
                query.push('$');
                query.push_str(&(param_idx + j).to_string());
            }
            query.push(')');
            param_idx += 3;
        }

        let mut sqlx_query = sqlx::query(&query);
        for param in &params {
            sqlx_query = sqlx_query
                .bind(param.workspace_build_id)
                .bind(&param.name)
                .bind(&param.value);
        }

        sqlx_query
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn batch_update_workspace_last_used_at(
        &self,
        ids: &[Uuid],
        last_used_at: OffsetDateTime,
    ) -> Result<u64, StorageError> {
        if ids.is_empty() {
            return Ok(0);
        }

        let result = sqlx::query("UPDATE workspaces SET last_used_at = $1 WHERE id = ANY($2)")
            .bind(last_used_at)
            .bind(ids)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;

        Ok(result.rows_affected())
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
    async fn appearance_config(&self) -> Result<coder_core::api::AppearanceConfig, StorageError> {
        let encoded: Option<String> = sqlx::query_scalar(
            "SELECT value
             FROM site_configs
             WHERE key = 'appearance_config'",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        match encoded {
            Some(encoded) => serde_json::from_str(&encoded)
                .map_err(|error| StorageError::invalid_data(error.to_string())),
            None => Ok(coder_core::api::AppearanceConfig::default()),
        }
    }

    #[instrument(skip(self, config), err(level = tracing::Level::WARN))]
    async fn upsert_appearance_config(
        &self,
        config: &coder_core::api::AppearanceConfig,
    ) -> Result<bool, StorageError> {
        let encoded = serde_json::to_string(config)
            .map_err(|error| StorageError::invalid_data(error.to_string()))?;
        let current: Option<String> = sqlx::query_scalar(
            "SELECT value
             FROM site_configs
             WHERE key = 'appearance_config'",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        if current.as_deref() == Some(encoded.as_str()) {
            return Ok(false);
        }

        sqlx::query(
            "INSERT INTO site_configs (key, value)
             VALUES ('appearance_config', $1)
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(encoded)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(true)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn prebuilds_settings(&self) -> Result<coder_core::api::PrebuildsSettings, StorageError> {
        let encoded: Option<String> = sqlx::query_scalar(
            "SELECT value
             FROM site_configs
             WHERE key = 'prebuilds_settings'",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        match encoded {
            Some(encoded) => serde_json::from_str(&encoded)
                .map_err(|error| StorageError::invalid_data(error.to_string())),
            None => Ok(coder_core::api::PrebuildsSettings::default()),
        }
    }

    #[instrument(skip(self, settings), err(level = tracing::Level::WARN))]
    async fn upsert_prebuilds_settings(
        &self,
        settings: &coder_core::api::PrebuildsSettings,
    ) -> Result<bool, StorageError> {
        let encoded = serde_json::to_string(settings)
            .map_err(|error| StorageError::invalid_data(error.to_string()))?;
        let current: Option<String> = sqlx::query_scalar(
            "SELECT value
             FROM site_configs
             WHERE key = 'prebuilds_settings'",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        if current.as_deref() == Some(encoded.as_str()) {
            return Ok(false);
        }

        sqlx::query(
            "INSERT INTO site_configs (key, value)
             VALUES ('prebuilds_settings', $1)
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(encoded)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(true)
    }

    // ── IDP Sync settings ───────────────────────────────────────────────

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn group_sync_settings(
        &self,
        org_id: Uuid,
    ) -> Result<coder_core::api::GroupSyncSettings, StorageError> {
        let key = format!("{}:group-sync-settings", org_id);
        let encoded: Option<String> =
            sqlx::query_scalar("SELECT value FROM site_configs WHERE key = $1")
                .bind(&key)
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_error)?;

        match encoded {
            Some(encoded) => serde_json::from_str(&encoded)
                .map_err(|error| StorageError::invalid_data(error.to_string())),
            None => Ok(coder_core::api::GroupSyncSettings::default()),
        }
    }

    #[instrument(skip(self, settings), err(level = tracing::Level::WARN))]
    async fn upsert_group_sync_settings(
        &self,
        org_id: Uuid,
        settings: &coder_core::api::GroupSyncSettings,
    ) -> Result<(), StorageError> {
        let key = format!("{}:group-sync-settings", org_id);
        let encoded = serde_json::to_string(settings)
            .map_err(|error| StorageError::invalid_data(error.to_string()))?;
        sqlx::query(
            "INSERT INTO site_configs (key, value)
             VALUES ($1, $2)
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(&key)
        .bind(&encoded)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn role_sync_settings(
        &self,
        org_id: Uuid,
    ) -> Result<coder_core::api::RoleSyncSettings, StorageError> {
        let key = format!("{}:role-sync-settings", org_id);
        let encoded: Option<String> =
            sqlx::query_scalar("SELECT value FROM site_configs WHERE key = $1")
                .bind(&key)
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_error)?;

        match encoded {
            Some(encoded) => serde_json::from_str(&encoded)
                .map_err(|error| StorageError::invalid_data(error.to_string())),
            None => Ok(coder_core::api::RoleSyncSettings::default()),
        }
    }

    #[instrument(skip(self, settings), err(level = tracing::Level::WARN))]
    async fn upsert_role_sync_settings(
        &self,
        org_id: Uuid,
        settings: &coder_core::api::RoleSyncSettings,
    ) -> Result<(), StorageError> {
        let key = format!("{}:role-sync-settings", org_id);
        let encoded = serde_json::to_string(settings)
            .map_err(|error| StorageError::invalid_data(error.to_string()))?;
        sqlx::query(
            "INSERT INTO site_configs (key, value)
             VALUES ($1, $2)
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(&key)
        .bind(&encoded)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_group_sync_config(
        &self,
        org_id: Uuid,
        field: String,
        regex_filter: Option<String>,
        auto_create_missing_groups: bool,
    ) -> Result<coder_core::api::GroupSyncSettings, StorageError> {
        let key = format!("{}:group-sync-settings", org_id);
        let mut tx = self.pool.begin().await.map_err(storage_error)?;

        let encoded: Option<String> =
            sqlx::query_scalar("SELECT value FROM site_configs WHERE key = $1 FOR UPDATE")
                .bind(&key)
                .fetch_optional(&mut *tx)
                .await
                .map_err(storage_error)?;

        let mut settings: coder_core::api::GroupSyncSettings = match encoded {
            Some(ref e) => serde_json::from_str(e)
                .map_err(|error| StorageError::invalid_data(error.to_string()))?,
            None => coder_core::api::GroupSyncSettings::default(),
        };

        settings.field = field;
        settings.regex_filter = regex_filter;
        settings.auto_create_missing_groups = auto_create_missing_groups;

        let new_encoded = serde_json::to_string(&settings)
            .map_err(|error| StorageError::invalid_data(error.to_string()))?;
        sqlx::query(
            "INSERT INTO site_configs (key, value)
             VALUES ($1, $2)
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(&key)
        .bind(&new_encoded)
        .execute(&mut *tx)
        .await
        .map_err(storage_error)?;

        tx.commit().await.map_err(storage_error)?;
        Ok(settings)
    }

    #[instrument(skip(self, add, remove), err(level = tracing::Level::WARN))]
    async fn apply_group_sync_mapping_diff(
        &self,
        org_id: Uuid,
        add: &[coder_core::api::IDPSyncMappingGroup],
        remove: &[coder_core::api::IDPSyncMappingGroup],
    ) -> Result<coder_core::api::GroupSyncSettings, StorageError> {
        let key = format!("{}:group-sync-settings", org_id);
        let mut tx = self.pool.begin().await.map_err(storage_error)?;

        let encoded: Option<String> =
            sqlx::query_scalar("SELECT value FROM site_configs WHERE key = $1 FOR UPDATE")
                .bind(&key)
                .fetch_optional(&mut *tx)
                .await
                .map_err(storage_error)?;

        let mut settings: coder_core::api::GroupSyncSettings = match encoded {
            Some(ref e) => serde_json::from_str(e)
                .map_err(|error| StorageError::invalid_data(error.to_string()))?,
            None => coder_core::api::GroupSyncSettings::default(),
        };

        // Apply diff
        for entry in add {
            let ids = settings.mapping.entry(entry.given.clone()).or_default();
            if !ids.contains(&entry.gets) {
                ids.push(entry.gets);
            }
        }
        for entry in remove {
            if let Some(ids) = settings.mapping.get_mut(&entry.given) {
                ids.retain(|id| *id != entry.gets);
            }
        }
        settings.mapping.retain(|_, ids| !ids.is_empty());

        let new_encoded = serde_json::to_string(&settings)
            .map_err(|error| StorageError::invalid_data(error.to_string()))?;
        sqlx::query(
            "INSERT INTO site_configs (key, value)
             VALUES ($1, $2)
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(&key)
        .bind(&new_encoded)
        .execute(&mut *tx)
        .await
        .map_err(storage_error)?;

        tx.commit().await.map_err(storage_error)?;
        Ok(settings)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_role_sync_config(
        &self,
        org_id: Uuid,
        field: String,
    ) -> Result<coder_core::api::RoleSyncSettings, StorageError> {
        let key = format!("{}:role-sync-settings", org_id);
        let mut tx = self.pool.begin().await.map_err(storage_error)?;

        let encoded: Option<String> =
            sqlx::query_scalar("SELECT value FROM site_configs WHERE key = $1 FOR UPDATE")
                .bind(&key)
                .fetch_optional(&mut *tx)
                .await
                .map_err(storage_error)?;

        let mut settings: coder_core::api::RoleSyncSettings = match encoded {
            Some(ref e) => serde_json::from_str(e)
                .map_err(|error| StorageError::invalid_data(error.to_string()))?,
            None => coder_core::api::RoleSyncSettings::default(),
        };

        settings.field = field;

        let new_encoded = serde_json::to_string(&settings)
            .map_err(|error| StorageError::invalid_data(error.to_string()))?;
        sqlx::query(
            "INSERT INTO site_configs (key, value)
             VALUES ($1, $2)
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(&key)
        .bind(&new_encoded)
        .execute(&mut *tx)
        .await
        .map_err(storage_error)?;

        tx.commit().await.map_err(storage_error)?;
        Ok(settings)
    }

    #[instrument(skip(self, add, remove), err(level = tracing::Level::WARN))]
    async fn apply_role_sync_mapping_diff(
        &self,
        org_id: Uuid,
        add: &[coder_core::api::IDPSyncMappingRole],
        remove: &[coder_core::api::IDPSyncMappingRole],
    ) -> Result<coder_core::api::RoleSyncSettings, StorageError> {
        let key = format!("{}:role-sync-settings", org_id);
        let mut tx = self.pool.begin().await.map_err(storage_error)?;

        let encoded: Option<String> =
            sqlx::query_scalar("SELECT value FROM site_configs WHERE key = $1 FOR UPDATE")
                .bind(&key)
                .fetch_optional(&mut *tx)
                .await
                .map_err(storage_error)?;

        let mut settings: coder_core::api::RoleSyncSettings = match encoded {
            Some(ref e) => serde_json::from_str(e)
                .map_err(|error| StorageError::invalid_data(error.to_string()))?,
            None => coder_core::api::RoleSyncSettings::default(),
        };

        // Apply diff
        for entry in add {
            let roles = settings.mapping.entry(entry.given.clone()).or_default();
            if !roles.contains(&entry.gets) {
                roles.push(entry.gets.clone());
            }
        }
        for entry in remove {
            if let Some(roles) = settings.mapping.get_mut(&entry.given) {
                roles.retain(|role| *role != entry.gets);
            }
        }
        settings.mapping.retain(|_, roles| !roles.is_empty());

        let new_encoded = serde_json::to_string(&settings)
            .map_err(|error| StorageError::invalid_data(error.to_string()))?;
        sqlx::query(
            "INSERT INTO site_configs (key, value)
             VALUES ($1, $2)
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(&key)
        .bind(&new_encoded)
        .execute(&mut *tx)
        .await
        .map_err(storage_error)?;

        tx.commit().await.map_err(storage_error)?;
        Ok(settings)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn oidc_claim_fields(&self, org_id: Uuid) -> Result<Vec<String>, StorageError> {
        let nil = Uuid::nil();
        let fields: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT jsonb_object_keys(claims->'merged_claims')
             FROM user_links
             WHERE claims ? 'merged_claims'
               AND jsonb_typeof(claims->'merged_claims') = 'object'
               AND login_type = 'oidc'
               AND CASE WHEN $1::uuid != $2::uuid THEN
                   user_links.user_id = ANY(
                       SELECT organization_members.user_id
                       FROM organization_members
                       WHERE organization_id = $1
                   )
                   ELSE true
               END",
        )
        .bind(org_id)
        .bind(nil)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(fields)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn oidc_claim_field_values(
        &self,
        org_id: Uuid,
        claim_field: &str,
    ) -> Result<Vec<String>, StorageError> {
        let nil = Uuid::nil();
        let values: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT jsonb_array_elements_text(CASE
                WHEN jsonb_typeof(claims->'merged_claims'->$1::text) = 'array' THEN
                    (SELECT jsonb_agg(element)
                     FROM jsonb_array_elements(claims->'merged_claims'->$1::text) AS element
                     WHERE jsonb_typeof(element) = 'string')
                WHEN jsonb_typeof(claims->'merged_claims'->$1::text) = 'string' THEN
                    jsonb_build_array(claims->'merged_claims'->$1::text)
             END)
             FROM user_links
             WHERE jsonb_typeof(claims->'merged_claims'->$1::text) = ANY(ARRAY['string', 'array'])
               AND login_type = 'oidc'
               AND CASE WHEN $2::uuid != $3::uuid THEN
                   user_links.user_id = ANY(
                       SELECT organization_members.user_id
                       FROM organization_members
                       WHERE organization_id = $2
                   )
                   ELSE true
               END",
        )
        .bind(claim_field)
        .bind(org_id)
        .bind(nil)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(values)
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
    async fn get_deployment_daus(&self, tz_offset: i32) -> Result<DAUsResponse, StorageError> {
        #[derive(sqlx::FromRow)]
        struct DauRow {
            date: time::Date,
            amount: i64,
        }

        // Build a proper Etc/GMT timezone string from the integer offset.
        // Etc/GMT sign convention is inverted: positive tz_offset → Etc/GMT-N.
        let tz_name = if tz_offset == 0 {
            "UTC".to_string()
        } else if tz_offset > 0 {
            format!("Etc/GMT-{tz_offset}")
        } else {
            format!("Etc/GMT+{}", tz_offset.abs())
        };

        let rows = sqlx::query_as::<_, DauRow>(
            "SELECT
                (created_at AT TIME ZONE $1)::date AS date,
                COUNT(DISTINCT user_id) AS amount
             FROM workspace_agent_stats
             WHERE connection_count > 0
               AND user_id IS NOT NULL
             GROUP BY date
             ORDER BY date ASC",
        )
        .bind(&tz_name)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        let entries = rows
            .into_iter()
            .map(|row| DAUEntry {
                date: row.date.to_string(),
                amount: row.amount,
            })
            .collect();

        Ok(DAUsResponse {
            tz_hour_offset: tz_offset,
            entries,
        })
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_user_status_counts(
        &self,
        timezone: &str,
        start_time: OffsetDateTime,
        end_time: OffsetDateTime,
    ) -> Result<GetUserStatusCountsResponse, StorageError> {
        #[derive(sqlx::FromRow)]
        struct StatusCountRow {
            date: OffsetDateTime,
            status: String,
            count: i64,
        }

        let rows = sqlx::query_as::<_, StatusCountRow>(
            r#"
            WITH
            system_users AS (
                SELECT id FROM users WHERE is_system = TRUE
            ),
            dates_of_interest AS (
                SELECT timezone($1::text, gs_local) AS date
                FROM generate_series(
                    timezone($1::text, $2::timestamptz),
                    timezone($1::text, $3::timestamptz),
                    interval '1 day'
                ) AS gs_local
            ),
            latest_status_before_range AS (
                SELECT
                    DISTINCT ON (usc.user_id)
                    usc.user_id,
                    usc.new_status,
                    usc.changed_at
                FROM user_status_changes usc
                LEFT JOIN LATERAL (
                    SELECT COUNT(*) > 0 AS deleted
                    FROM user_deleted ud
                    WHERE ud.user_id = usc.user_id
                      AND (ud.deleted_at < usc.changed_at OR ud.deleted_at < $2::timestamptz)
                ) AS ud ON true
                WHERE usc.user_id NOT IN (SELECT id FROM system_users)
                    AND NOT ud.deleted
                    AND usc.changed_at < $2::timestamptz
                ORDER BY usc.user_id, usc.changed_at DESC
            ),
            status_changes_during_range AS (
                SELECT
                    usc.user_id,
                    usc.new_status,
                    usc.changed_at
                FROM user_status_changes usc
                LEFT JOIN LATERAL (
                    SELECT COUNT(*) > 0 AS deleted
                    FROM user_deleted ud
                    WHERE ud.user_id = usc.user_id AND ud.deleted_at < usc.changed_at
                ) AS ud ON true
                WHERE usc.user_id NOT IN (SELECT id FROM system_users)
                    AND NOT ud.deleted
                    AND usc.changed_at >= $2::timestamptz
                    AND usc.changed_at <= $3::timestamptz
            ),
            relevant_status_changes AS (
                SELECT user_id, new_status, changed_at
                FROM latest_status_before_range
                UNION ALL
                SELECT user_id, new_status, changed_at
                FROM status_changes_during_range
            ),
            statuses AS (
                SELECT DISTINCT new_status FROM relevant_status_changes
            ),
            ranked_status_change_per_user_per_date AS (
                SELECT
                    d.date,
                    rsc1.user_id,
                    ROW_NUMBER() OVER (
                        PARTITION BY d.date, rsc1.user_id
                        ORDER BY rsc1.changed_at DESC
                    ) AS rn,
                    rsc1.new_status
                FROM dates_of_interest d
                LEFT JOIN relevant_status_changes rsc1 ON rsc1.changed_at <= d.date
            )
            SELECT
                rscpupd.date::timestamptz AS date,
                statuses.new_status::text AS status,
                COUNT(rscpupd.user_id) FILTER (
                    WHERE rscpupd.rn = 1
                    AND (
                        rscpupd.new_status = statuses.new_status
                        AND (
                            NOT EXISTS (SELECT 1 FROM user_deleted WHERE user_id = rscpupd.user_id)
                            OR
                            rscpupd.date < (SELECT MIN(deleted_at) FROM user_deleted WHERE user_id = rscpupd.user_id)
                        )
                    )
                ) AS count
            FROM ranked_status_change_per_user_per_date rscpupd
            CROSS JOIN statuses
            GROUP BY rscpupd.date, statuses.new_status
            ORDER BY rscpupd.date
            "#,
        )
        .bind(timezone)
        .bind(start_time)
        .bind(end_time)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        let mut status_counts: HashMap<String, Vec<UserStatusChangeCount>> = HashMap::new();
        for row in rows {
            status_counts
                .entry(row.status)
                .or_default()
                .push(UserStatusChangeCount {
                    date: row.date,
                    count: row.count,
                });
        }

        Ok(GetUserStatusCountsResponse { status_counts })
    }

    // ── Insights methods ──────────────────────────────────────────

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_user_latency_insights(
        &self,
        start_time: OffsetDateTime,
        end_time: OffsetDateTime,
        template_ids: Vec<Uuid>,
    ) -> Result<UserLatencyInsightsResponse, StorageError> {
        #[derive(sqlx::FromRow)]
        struct LatencyRow {
            user_id: Uuid,
            username: String,
            avatar_url: String,
            template_ids: Vec<Uuid>,
            workspace_connection_latency_50: f64,
            workspace_connection_latency_95: f64,
        }

        let rows = sqlx::query_as::<_, LatencyRow>(
            r#"
            SELECT
                tus.user_id,
                u.username,
                u.avatar_url,
                array_agg(DISTINCT tus.template_id)::uuid[] AS template_ids,
                COALESCE((PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY tus.median_latency_ms)), -1)::float8 AS workspace_connection_latency_50,
                COALESCE((PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY tus.median_latency_ms)), -1)::float8 AS workspace_connection_latency_95
            FROM template_usage_stats tus
            JOIN users u ON u.id = tus.user_id
            WHERE
                tus.start_time >= $1::timestamptz
                AND tus.end_time <= $2::timestamptz
                AND CASE WHEN COALESCE(array_length($3::uuid[], 1), 0) > 0 THEN tus.template_id = ANY($3::uuid[]) ELSE TRUE END
            GROUP BY tus.user_id, u.username, u.avatar_url
            ORDER BY tus.user_id ASC
            "#,
        )
        .bind(start_time)
        .bind(end_time)
        .bind(&template_ids)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        let mut all_template_ids: Vec<Uuid> = rows
            .iter()
            .flat_map(|r| r.template_ids.iter().copied())
            .collect();
        all_template_ids.sort();
        all_template_ids.dedup();

        let users = rows
            .into_iter()
            .map(|row| UserLatency {
                template_ids: row.template_ids,
                user_id: row.user_id,
                username: row.username,
                avatar_url: row.avatar_url,
                latency_ms: ConnectionLatency {
                    p50: row.workspace_connection_latency_50,
                    p95: row.workspace_connection_latency_95,
                },
            })
            .collect();

        Ok(UserLatencyInsightsResponse {
            report: UserLatencyInsightsReport {
                start_time,
                end_time,
                template_ids: all_template_ids,
                users,
            },
        })
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_user_activity_insights(
        &self,
        start_time: OffsetDateTime,
        end_time: OffsetDateTime,
        template_ids: Vec<Uuid>,
    ) -> Result<UserActivityInsightsResponse, StorageError> {
        #[derive(sqlx::FromRow)]
        struct ActivityRow {
            user_id: Uuid,
            username: String,
            avatar_url: String,
            template_ids: Vec<Uuid>,
            usage_seconds: i64,
        }

        let rows = sqlx::query_as::<_, ActivityRow>(
            r#"
            WITH deployment_stats AS (
                SELECT
                    start_time,
                    user_id,
                    array_agg(template_id) AS template_ids,
                    LEAST(SUM(usage_mins), 30) AS usage_mins
                FROM template_usage_stats
                WHERE
                    start_time >= $1::timestamptz
                    AND end_time <= $2::timestamptz
                    AND CASE WHEN COALESCE(array_length($3::uuid[], 1), 0) > 0 THEN template_id = ANY($3::uuid[]) ELSE TRUE END
                GROUP BY start_time, user_id
            ),
            template_ids AS (
                SELECT
                    user_id,
                    array_agg(DISTINCT template_id) AS ids
                FROM deployment_stats, unnest(template_ids) template_id
                GROUP BY user_id
            )
            SELECT
                ds.user_id,
                u.username,
                u.avatar_url,
                t.ids::uuid[] AS template_ids,
                (SUM(ds.usage_mins) * 60)::bigint AS usage_seconds
            FROM deployment_stats ds
            JOIN users u ON u.id = ds.user_id
            JOIN template_ids t ON ds.user_id = t.user_id
            GROUP BY ds.user_id, u.username, u.avatar_url, t.ids
            ORDER BY ds.user_id ASC
            "#,
        )
        .bind(start_time)
        .bind(end_time)
        .bind(&template_ids)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        let mut all_template_ids: Vec<Uuid> = rows
            .iter()
            .flat_map(|r| r.template_ids.iter().copied())
            .collect();
        all_template_ids.sort();
        all_template_ids.dedup();

        let users = rows
            .into_iter()
            .map(|row| UserActivity {
                template_ids: row.template_ids,
                user_id: row.user_id,
                username: row.username,
                avatar_url: row.avatar_url,
                seconds: row.usage_seconds,
            })
            .collect();

        Ok(UserActivityInsightsResponse {
            report: UserActivityInsightsReport {
                start_time,
                end_time,
                template_ids: all_template_ids,
                users,
            },
        })
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_template_insights_by_interval(
        &self,
        start_time: OffsetDateTime,
        end_time: OffsetDateTime,
        interval: InsightsReportInterval,
        template_ids: Vec<Uuid>,
    ) -> Result<Vec<TemplateInsightsIntervalReport>, StorageError> {
        #[derive(sqlx::FromRow)]
        struct IntervalRow {
            start_time: OffsetDateTime,
            end_time: OffsetDateTime,
            template_ids: Vec<Uuid>,
            active_users: i64,
        }

        let interval_days = interval.days();

        let rows = sqlx::query_as::<_, IntervalRow>(
            r#"
            WITH ts AS (
                SELECT
                    d::timestamptz AS from_,
                    LEAST(
                        (d::timestamptz + make_interval(days => $4))::timestamptz,
                        $2::timestamptz
                    )::timestamptz AS to_
                FROM generate_series(
                    $1::timestamptz,
                    ($2::timestamptz) - '1 microsecond'::interval,
                    make_interval(days => $4)
                ) AS d
            )
            SELECT
                ts.from_ AS start_time,
                ts.to_ AS end_time,
                array_remove(array_agg(DISTINCT tus.template_id), NULL)::uuid[] AS template_ids,
                COUNT(DISTINCT tus.user_id) AS active_users
            FROM ts
            LEFT JOIN template_usage_stats AS tus
            ON
                tus.start_time >= ts.from_
                AND tus.start_time < ts.to_
                AND tus.end_time <= ts.to_
                AND CASE WHEN COALESCE(array_length($3::uuid[], 1), 0) > 0 THEN tus.template_id = ANY($3::uuid[]) ELSE TRUE END
            GROUP BY ts.from_, ts.to_
            ORDER BY ts.from_ ASC
            "#,
        )
        .bind(start_time)
        .bind(end_time)
        .bind(&template_ids)
        .bind(interval_days)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(|row| TemplateInsightsIntervalReport {
                start_time: row.start_time,
                end_time: row.end_time,
                template_ids: row.template_ids,
                interval: interval.clone(),
                active_users: row.active_users,
            })
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_template_insights(
        &self,
        start_time: OffsetDateTime,
        end_time: OffsetDateTime,
        interval: InsightsReportInterval,
        template_ids: Vec<Uuid>,
    ) -> Result<TemplateInsightsResponse, StorageError> {
        #[derive(sqlx::FromRow)]
        struct InsightsRow {
            template_ids: Vec<Uuid>,
            ssh_template_ids: Vec<Uuid>,
            sftp_template_ids: Vec<Uuid>,
            reconnecting_pty_template_ids: Vec<Uuid>,
            vscode_template_ids: Vec<Uuid>,
            jetbrains_template_ids: Vec<Uuid>,
            active_users: i64,
            #[allow(dead_code)]
            usage_total_seconds: i64,
            usage_ssh_seconds: i64,
            usage_sftp_seconds: i64,
            usage_reconnecting_pty_seconds: i64,
            usage_vscode_seconds: i64,
            usage_jetbrains_seconds: i64,
        }

        #[derive(sqlx::FromRow)]
        struct AppInsightRow {
            template_ids: Vec<Uuid>,
            #[allow(dead_code)]
            active_users: i64,
            slug: String,
            display_name: String,
            icon: String,
            usage_seconds: i64,
            times_used: i64,
        }

        #[derive(sqlx::FromRow)]
        struct ParamRow {
            num: i64,
            template_ids: Vec<Uuid>,
            name: String,
            #[sqlx(rename = "type")]
            param_type: String,
            display_name: String,
            description: String,
            options: Value,
            value: String,
            count: i64,
        }

        // Clone template_ids for the interval query since it will be moved.
        let tids_for_interval = template_ids.clone();

        // Run all 4 queries concurrently — they share no mutable state.
        let (main_row, app_rows, param_rows, interval_reports) = tokio::try_join!(
            // ── 1. Main aggregation (matches Go GetTemplateInsights) ──────
            async {
                sqlx::query_as::<_, InsightsRow>(
                    r#"
                    WITH insights AS (
                        SELECT
                            user_id,
                            LEAST(SUM(usage_mins), 30) AS usage_mins,
                            LEAST(SUM(ssh_mins), 30) AS ssh_mins,
                            LEAST(SUM(sftp_mins), 30) AS sftp_mins,
                            LEAST(SUM(reconnecting_pty_mins), 30) AS reconnecting_pty_mins,
                            LEAST(SUM(vscode_mins), 30) AS vscode_mins,
                            LEAST(SUM(jetbrains_mins), 30) AS jetbrains_mins
                        FROM template_usage_stats
                        WHERE
                            start_time >= $1::timestamptz
                            AND end_time <= $2::timestamptz
                            AND CASE WHEN COALESCE(array_length($3::uuid[], 1), 0) > 0 THEN template_id = ANY($3::uuid[]) ELSE TRUE END
                        GROUP BY start_time, user_id
                    ),
                    templates AS (
                        SELECT
                            array_agg(DISTINCT template_id) AS template_ids,
                            array_agg(DISTINCT template_id) FILTER (WHERE ssh_mins > 0) AS ssh_template_ids,
                            array_agg(DISTINCT template_id) FILTER (WHERE sftp_mins > 0) AS sftp_template_ids,
                            array_agg(DISTINCT template_id) FILTER (WHERE reconnecting_pty_mins > 0) AS reconnecting_pty_template_ids,
                            array_agg(DISTINCT template_id) FILTER (WHERE vscode_mins > 0) AS vscode_template_ids,
                            array_agg(DISTINCT template_id) FILTER (WHERE jetbrains_mins > 0) AS jetbrains_template_ids
                        FROM template_usage_stats
                        WHERE
                            start_time >= $1::timestamptz
                            AND end_time <= $2::timestamptz
                            AND CASE WHEN COALESCE(array_length($3::uuid[], 1), 0) > 0 THEN template_id = ANY($3::uuid[]) ELSE TRUE END
                    )
                    SELECT
                        COALESCE((SELECT template_ids FROM templates), '{}')::uuid[] AS template_ids,
                        COALESCE((SELECT ssh_template_ids FROM templates), '{}')::uuid[] AS ssh_template_ids,
                        COALESCE((SELECT sftp_template_ids FROM templates), '{}')::uuid[] AS sftp_template_ids,
                        COALESCE((SELECT reconnecting_pty_template_ids FROM templates), '{}')::uuid[] AS reconnecting_pty_template_ids,
                        COALESCE((SELECT vscode_template_ids FROM templates), '{}')::uuid[] AS vscode_template_ids,
                        COALESCE((SELECT jetbrains_template_ids FROM templates), '{}')::uuid[] AS jetbrains_template_ids,
                        COALESCE(COUNT(DISTINCT user_id), 0)::bigint AS active_users,
                        COALESCE(SUM(usage_mins) * 60, 0)::bigint AS usage_total_seconds,
                        COALESCE(SUM(ssh_mins) * 60, 0)::bigint AS usage_ssh_seconds,
                        COALESCE(SUM(sftp_mins) * 60, 0)::bigint AS usage_sftp_seconds,
                        COALESCE(SUM(reconnecting_pty_mins) * 60, 0)::bigint AS usage_reconnecting_pty_seconds,
                        COALESCE(SUM(vscode_mins) * 60, 0)::bigint AS usage_vscode_seconds,
                        COALESCE(SUM(jetbrains_mins) * 60, 0)::bigint AS usage_jetbrains_seconds
                    FROM insights
                    "#,
                )
                .bind(start_time)
                .bind(end_time)
                .bind(&template_ids)
                .fetch_one(&self.pool)
                .await
                .map_err(storage_error)
            },
            // ── 2. App insights (matches Go GetTemplateAppInsights) ──────
            async {
                sqlx::query_as::<_, AppInsightRow>(
                    r#"
                    WITH apps AS (
                        SELECT DISTINCT ON (ws.template_id, app.slug)
                            ws.template_id,
                            app.slug,
                            app.display_name,
                            app.icon
                        FROM workspaces ws
                        JOIN workspace_builds AS build ON build.workspace_id = ws.id
                        JOIN workspace_resources AS resource ON resource.job_id = build.job_id
                        JOIN workspace_agents AS agent ON agent.resource_id = resource.id
                        JOIN workspace_apps AS app ON app.agent_id = agent.id
                        WHERE
                                ws.deleted = FALSE
                            AND agent.deleted = FALSE
                        AND CASE WHEN COALESCE(array_length($3::uuid[], 1), 0) > 0 THEN ws.template_id = ANY($3::uuid[]) ELSE TRUE END
                            ORDER BY ws.template_id, app.slug, app.created_at DESC
                    ),
                    template_usage_stats_with_apps AS (
                        SELECT
                            tus.start_time,
                            tus.template_id,
                            tus.user_id,
                            apps.slug,
                            apps.display_name,
                            apps.icon,
                            (tus.app_usage_mins -> apps.slug)::smallint AS usage_mins
                        FROM apps
                        JOIN template_usage_stats AS tus
                        ON
                            tus.start_time >= $1::timestamptz
                            AND tus.end_time <= $2::timestamptz
                            AND CASE WHEN COALESCE(array_length($3::uuid[], 1), 0) > 0 THEN tus.template_id = ANY($3::uuid[]) ELSE TRUE END
                            AND tus.template_id = apps.template_id
                            AND tus.app_usage_mins ? apps.slug
                    ),
                    app_insights AS (
                        SELECT
                            user_id,
                            slug,
                            display_name,
                            icon,
                            LEAST(SUM(usage_mins), 30) AS usage_mins
                        FROM template_usage_stats_with_apps
                        GROUP BY start_time, user_id, slug, display_name, icon
                    ),
                    times_used AS (
                        SELECT DISTINCT ON (user_id, slug, display_name, icon, uniq)
                            slug,
                            display_name,
                            icon,
                            start_time - (
                                dense_rank() OVER (
                                    PARTITION BY user_id, slug, display_name, icon
                                    ORDER BY start_time
                                ) * '30 minutes'::interval
                            ) AS uniq
                        FROM template_usage_stats_with_apps
                    ),
                    templates AS (
                        SELECT
                            slug,
                            display_name,
                            icon,
                            array_agg(DISTINCT template_id)::uuid[] AS template_ids
                        FROM template_usage_stats_with_apps
                        GROUP BY slug, display_name, icon
                    )
                    SELECT
                        t.template_ids,
                        COUNT(DISTINCT ai.user_id)::bigint AS active_users,
                        ai.slug,
                        ai.display_name,
                        ai.icon,
                        (SUM(ai.usage_mins) * 60)::bigint AS usage_seconds,
                        COALESCE((
                            SELECT COUNT(*)
                            FROM times_used
                            WHERE times_used.slug = ai.slug
                                AND times_used.display_name = ai.display_name
                                AND times_used.icon = ai.icon
                        ), 0)::bigint AS times_used
                    FROM app_insights AS ai
                    JOIN templates AS t
                    ON t.slug = ai.slug
                        AND t.display_name = ai.display_name
                        AND t.icon = ai.icon
                    GROUP BY t.template_ids, ai.slug, ai.display_name, ai.icon
                    "#,
                )
                .bind(start_time)
                .bind(end_time)
                .bind(&template_ids)
                .fetch_all(&self.pool)
                .await
                .map_err(storage_error)
            },
            // ── 3. Parameter insights (matches Go GetTemplateParameterInsights) ──
            async {
                sqlx::query_as::<_, ParamRow>(
                    r#"
                    WITH latest_workspace_builds AS (
                        SELECT
                            wb.id,
                            wbmax.template_id,
                            wb.template_version_id
                        FROM (
                            SELECT
                                tv.template_id,
                                wbmax.workspace_id,
                                MAX(wbmax.build_number) AS max_build_number
                            FROM workspace_builds wbmax
                            JOIN template_versions tv ON tv.id = wbmax.template_version_id
                            WHERE
                                wbmax.created_at >= $1::timestamptz
                                AND wbmax.created_at < $2::timestamptz
                                AND CASE WHEN COALESCE(array_length($3::uuid[], 1), 0) > 0 THEN tv.template_id = ANY($3::uuid[]) ELSE TRUE END
                            GROUP BY tv.template_id, wbmax.workspace_id
                        ) wbmax
                        JOIN workspace_builds wb ON (
                            wb.workspace_id = wbmax.workspace_id
                            AND wb.build_number = wbmax.max_build_number
                        )
                    ),
                    unique_template_params AS (
                        SELECT
                            ROW_NUMBER() OVER (
                        ORDER BY tvp.name, tvp.type, tvp.display_name, tvp.description, tvp.options
                    ) AS num,
                            array_agg(DISTINCT wb.template_id)::uuid[] AS template_ids,
                            array_agg(wb.id)::uuid[] AS workspace_build_ids,
                            tvp.name,
                            tvp.type,
                            tvp.display_name,
                            tvp.description,
                            tvp.options
                        FROM latest_workspace_builds wb
                        JOIN template_version_parameters tvp ON tvp.template_version_id = wb.template_version_id
                        GROUP BY tvp.name, tvp.type, tvp.display_name, tvp.description, tvp.options
                    )
                    SELECT
                        utp.num,
                        utp.template_ids,
                        utp.name,
                        utp.type,
                        utp.display_name,
                        utp.description,
                        utp.options,
                        wbp.value,
                        COUNT(wbp.value) AS count
                    FROM unique_template_params utp
                    JOIN workspace_build_parameters wbp
                        ON utp.workspace_build_ids @> ARRAY[wbp.workspace_build_id]
                        AND utp.name = wbp.name
                    GROUP BY utp.num, utp.template_ids, utp.name, utp.type, utp.display_name, utp.description, utp.options, wbp.value
                    "#,
                )
                .bind(start_time)
                .bind(end_time)
                .bind(&template_ids)
                .fetch_all(&self.pool)
                .await
                .map_err(storage_error)
            },
            // ── 4. Interval reports ───────────────────────────────────────
            self.get_template_insights_by_interval(
                start_time,
                end_time,
                interval,
                tids_for_interval,
            ),
        )?;

        // Group parameter rows by num into TemplateParameterUsage entries.
        let mut param_map: HashMap<i64, TemplateParameterUsage> = HashMap::new();
        for row in param_rows {
            let entry = param_map.entry(row.num).or_insert_with(|| {
                let options = match row.options.clone() {
                    Value::Array(arr) => arr,
                    _ => Vec::new(),
                };
                TemplateParameterUsage {
                    template_ids: row.template_ids.clone(),
                    display_name: row.display_name.clone(),
                    name: row.name.clone(),
                    param_type: row.param_type.clone(),
                    description: row.description.clone(),
                    options,
                    values: Vec::new(),
                }
            });
            entry.values.push(TemplateParameterValue {
                value: row.value,
                count: row.count,
            });
        }
        let parameters_usage: Vec<TemplateParameterUsage> = {
            let mut entries: Vec<(i64, TemplateParameterUsage)> = param_map.into_iter().collect();
            entries.sort_by_key(|(k, _)| *k);
            entries.into_iter().map(|(_, v)| v).collect()
        };

        // ── 5. Build apps_usage from built-in apps + custom apps ─────
        let mut apps_usage: Vec<TemplateAppUsage> = Vec::new();

        // Built-in apps follow Go handler convention.
        if main_row.usage_vscode_seconds > 0 {
            apps_usage.push(TemplateAppUsage {
                template_ids: main_row.vscode_template_ids,
                app_type: TemplateAppsType::Builtin,
                display_name: "Visual Studio Code".to_string(),
                slug: "vscode".to_string(),
                icon: String::new(),
                seconds: main_row.usage_vscode_seconds,
                times_used: 0,
            });
        }
        if main_row.usage_jetbrains_seconds > 0 {
            apps_usage.push(TemplateAppUsage {
                template_ids: main_row.jetbrains_template_ids,
                app_type: TemplateAppsType::Builtin,
                display_name: "JetBrains".to_string(),
                slug: "jetbrains".to_string(),
                icon: String::new(),
                seconds: main_row.usage_jetbrains_seconds,
                times_used: 0,
            });
        }
        if main_row.usage_reconnecting_pty_seconds > 0 {
            apps_usage.push(TemplateAppUsage {
                template_ids: main_row.reconnecting_pty_template_ids,
                app_type: TemplateAppsType::Builtin,
                display_name: "Web Terminal".to_string(),
                slug: "reconnecting-pty".to_string(),
                icon: String::new(),
                seconds: main_row.usage_reconnecting_pty_seconds,
                times_used: 0,
            });
        }
        if main_row.usage_ssh_seconds > 0 {
            apps_usage.push(TemplateAppUsage {
                template_ids: main_row.ssh_template_ids,
                app_type: TemplateAppsType::Builtin,
                display_name: "SSH".to_string(),
                slug: "ssh".to_string(),
                icon: String::new(),
                seconds: main_row.usage_ssh_seconds,
                times_used: 0,
            });
        }
        if main_row.usage_sftp_seconds > 0 {
            apps_usage.push(TemplateAppUsage {
                template_ids: main_row.sftp_template_ids,
                app_type: TemplateAppsType::Builtin,
                display_name: "SFTP".to_string(),
                slug: "sftp".to_string(),
                icon: String::new(),
                seconds: main_row.usage_sftp_seconds,
                times_used: 0,
            });
        }

        // Custom apps from GetTemplateAppInsights.
        for row in app_rows {
            apps_usage.push(TemplateAppUsage {
                template_ids: row.template_ids,
                app_type: TemplateAppsType::App,
                display_name: row.display_name,
                slug: row.slug,
                icon: row.icon,
                seconds: row.usage_seconds,
                times_used: row.times_used,
            });
        }

        // ── 6. Assemble response ─────────────────────────────────────
        let report = TemplateInsightsReport {
            start_time,
            end_time,
            template_ids: main_row.template_ids,
            active_users: main_row.active_users,
            apps_usage,
            parameters_usage,
        };

        Ok(TemplateInsightsResponse {
            report: Some(report),
            interval_reports,
        })
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
    async fn delete_file(&self, file_id: Uuid) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM files WHERE id = $1")
            .bind(file_id)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;

        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_organization_idp_sync_settings(
        &self,
    ) -> Result<coder_core::api::OrganizationSyncSettings, StorageError> {
        let row = sqlx::query_scalar::<_, Option<String>>(
            "SELECT value FROM site_configs WHERE key = 'organization_idp_sync_settings'",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        match row.flatten() {
            Some(json) => serde_json::from_str(&json).map_err(|e| {
                StorageError::invalid_data(format!(
                    "invalid organization_idp_sync_settings JSON: {e}"
                ))
            }),
            None => Ok(coder_core::api::OrganizationSyncSettings::default()),
        }
    }

    #[instrument(skip(self, settings), err(level = tracing::Level::WARN))]
    async fn upsert_organization_idp_sync_settings(
        &self,
        settings: &coder_core::api::OrganizationSyncSettings,
    ) -> Result<(), StorageError> {
        let json = serde_json::to_string(settings).map_err(|e| {
            StorageError::invalid_data(format!(
                "failed to serialize organization_idp_sync_settings: {e}"
            ))
        })?;

        sqlx::query(
            "INSERT INTO site_configs (key, value) VALUES ('organization_idp_sync_settings', $1)
             ON CONFLICT (key) DO UPDATE SET value = $1",
        )
        .bind(&json)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
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
    // Tasks
    // -----------------------------------------------------------------------

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn insert_task(&self, input: InsertTaskInput) -> Result<TaskRecord, StorageError> {
        let row: StoredTaskRow = sqlx::query_as(
            "INSERT INTO tasks (id, organization_id, owner_id, name, display_name, template_version_id, template_parameters, prompt, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             RETURNING id, organization_id, owner_id, name, display_name, workspace_id, template_version_id, template_parameters, prompt, created_at, deleted_at",
        )
        .bind(input.id)
        .bind(input.organization_id)
        .bind(input.owner_id)
        .bind(&input.name)
        .bind(&input.display_name)
        .bind(input.template_version_id)
        .bind(&input.template_parameters)
        .bind(&input.prompt)
        .bind(input.created_at)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(task_record_from_row(row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_task_by_id(&self, id: Uuid) -> Result<Option<TaskRecord>, StorageError> {
        let row: Option<StoredTaskRow> = sqlx::query_as(
            "SELECT id, organization_id, owner_id, name, display_name, workspace_id, template_version_id, template_parameters, prompt, created_at, deleted_at
             FROM tasks WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(row.map(task_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_task_by_owner_and_name(
        &self,
        owner_id: Uuid,
        name: &str,
    ) -> Result<Option<TaskRecord>, StorageError> {
        let row: Option<StoredTaskRow> = sqlx::query_as(
            "SELECT id, organization_id, owner_id, name, display_name, workspace_id, template_version_id, template_parameters, prompt, created_at, deleted_at
             FROM tasks WHERE owner_id = $1 AND name = $2 AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 1",
        )
        .bind(owner_id)
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(row.map(task_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_tasks(&self, filter: TaskListFilter) -> Result<Vec<TaskRecord>, StorageError> {
        let rows: Vec<StoredTaskRow> = sqlx::query_as(
            "SELECT id, organization_id, owner_id, name, display_name, workspace_id, template_version_id, template_parameters, prompt, created_at, deleted_at
             FROM tasks
             WHERE deleted_at IS NULL
               AND ($1::uuid IS NULL OR owner_id = $1)
               AND ($2::uuid IS NULL OR organization_id = $2)
             ORDER BY created_at DESC",
        )
        .bind(filter.owner_id)
        .bind(filter.organization_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows.into_iter().map(task_record_from_row).collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_task(
        &self,
        id: Uuid,
        deleted_at: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let result =
            sqlx::query("UPDATE tasks SET deleted_at = $2 WHERE id = $1 AND deleted_at IS NULL")
                .bind(id)
                .bind(deleted_at)
                .execute(&self.pool)
                .await
                .map_err(storage_error)?;

        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_task_prompt(
        &self,
        id: Uuid,
        prompt: &str,
    ) -> Result<Option<TaskRecord>, StorageError> {
        let row: Option<StoredTaskRow> = sqlx::query_as(
            "UPDATE tasks SET prompt = $2
             WHERE id = $1 AND deleted_at IS NULL
             RETURNING id, organization_id, owner_id, name, display_name, workspace_id, template_version_id, template_parameters, prompt, created_at, deleted_at",
        )
        .bind(id)
        .bind(prompt)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(row.map(task_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn upsert_task_snapshot(
        &self,
        task_id: Uuid,
        log_snapshot: &Value,
        log_snapshot_created_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO task_snapshots (task_id, log_snapshot, log_snapshot_created_at)
             VALUES ($1, $2, $3)
             ON CONFLICT (task_id)
             DO UPDATE SET log_snapshot = EXCLUDED.log_snapshot,
                           log_snapshot_created_at = EXCLUDED.log_snapshot_created_at",
        )
        .bind(task_id)
        .bind(log_snapshot)
        .bind(log_snapshot_created_at)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_task_snapshot(
        &self,
        task_id: Uuid,
    ) -> Result<Option<TaskSnapshotRecord>, StorageError> {
        let row: Option<StoredTaskSnapshotRow> = sqlx::query_as(
            "SELECT task_id, log_snapshot, log_snapshot_created_at
             FROM task_snapshots WHERE task_id = $1",
        )
        .bind(task_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(row.map(|r| TaskSnapshotRecord {
            task_id: r.task_id,
            log_snapshot: r.log_snapshot,
            log_snapshot_created_at: r.log_snapshot_created_at,
        }))
    }

    // -----------------------------------------------------------------------
    // Chats
    // -----------------------------------------------------------------------

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn insert_chat(&self, input: InsertChatInput) -> Result<ChatRecord, StorageError> {
        let row: StoredChatRow = sqlx::query_as(
            "INSERT INTO chats (owner_id, workspace_id, parent_chat_id, root_chat_id, last_model_config_id, title)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING id, owner_id, workspace_id, title, status::text, last_error, parent_chat_id, root_chat_id, last_model_config_id, archived, created_at, updated_at",
        )
        .bind(input.owner_id)
        .bind(input.workspace_id)
        .bind(input.parent_chat_id)
        .bind(input.root_chat_id)
        .bind(input.last_model_config_id)
        .bind(&input.title)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        chat_record_from_row(row)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_chat_by_id(&self, id: Uuid) -> Result<Option<ChatRecord>, StorageError> {
        let row: Option<StoredChatRow> = sqlx::query_as(
            "SELECT id, owner_id, workspace_id, title, status::text, last_error, parent_chat_id, root_chat_id, last_model_config_id, archived, created_at, updated_at
             FROM chats WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        row.map(chat_record_from_row).transpose()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_chats_by_owner(
        &self,
        owner_id: Uuid,
        archived: Option<bool>,
    ) -> Result<Vec<ChatRecord>, StorageError> {
        let rows: Vec<StoredChatRow> = sqlx::query_as(
            "SELECT id, owner_id, workspace_id, title, status::text, last_error, parent_chat_id, root_chat_id, last_model_config_id, archived, created_at, updated_at
             FROM chats
             WHERE owner_id = $1
               AND ($2::boolean IS NULL OR archived = $2)
             ORDER BY updated_at DESC",
        )
        .bind(owner_id)
        .bind(archived)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        rows.into_iter().map(chat_record_from_row).collect()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn archive_chat(&self, id: Uuid) -> Result<(), StorageError> {
        sqlx::query(
            "UPDATE chats SET archived = true, updated_at = now()
             WHERE id = $1
                OR root_chat_id = $1
                OR id = (SELECT COALESCE(root_chat_id, id) FROM chats WHERE id = $1)
                OR root_chat_id = (SELECT COALESCE(root_chat_id, id) FROM chats WHERE id = $1)",
        )
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_chat_messages(
        &self,
        chat_id: Uuid,
        after_id: i64,
    ) -> Result<Vec<ChatMessageRecord>, StorageError> {
        let rows: Vec<StoredChatMessageRow> = sqlx::query_as(
            "SELECT id, chat_id, model_config_id, created_at, role, content, visibility::text, input_tokens, output_tokens, total_tokens, reasoning_tokens, cache_creation_tokens, cache_read_tokens, context_limit, compressed
             FROM chat_messages
             WHERE chat_id = $1 AND id > $2
             ORDER BY id ASC",
        )
        .bind(chat_id)
        .bind(after_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        rows.into_iter().map(chat_message_record_from_row).collect()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn insert_chat_message(
        &self,
        input: InsertChatMessageInput,
    ) -> Result<ChatMessageRecord, StorageError> {
        let visibility_str = match input.visibility {
            ChatMessageVisibility::User => "user",
            ChatMessageVisibility::Model => "model",
            ChatMessageVisibility::Both => "both",
        };
        let row: StoredChatMessageRow = sqlx::query_as(
            "INSERT INTO chat_messages (chat_id, model_config_id, role, content, visibility)
             VALUES ($1, $2, $3, $4, $5::chat_message_visibility)
             RETURNING id, chat_id, model_config_id, created_at, role, content, visibility::text, input_tokens, output_tokens, total_tokens, reasoning_tokens, cache_creation_tokens, cache_read_tokens, context_limit, compressed",
        )
        .bind(input.chat_id)
        .bind(input.model_config_id)
        .bind(&input.role)
        .bind(&input.content)
        .bind(visibility_str)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        chat_message_record_from_row(row)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_chat_queued_messages(
        &self,
        chat_id: Uuid,
    ) -> Result<Vec<ChatQueuedMessageRecord>, StorageError> {
        let rows: Vec<StoredChatQueuedMessageRow> = sqlx::query_as(
            "SELECT id, chat_id, content, created_at
             FROM chat_queued_messages
             WHERE chat_id = $1
             ORDER BY created_at ASC",
        )
        .bind(chat_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(|r| ChatQueuedMessageRecord {
                id: r.id,
                chat_id: r.chat_id,
                content: r.content,
                created_at: r.created_at,
            })
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn unarchive_chat(&self, id: Uuid) -> Result<(), StorageError> {
        sqlx::query(
            "UPDATE chats SET archived = false, updated_at = now()
             WHERE id = $1",
        )
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Chat Files
    // -----------------------------------------------------------------------

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn insert_chat_file(
        &self,
        input: InsertChatFileInput,
    ) -> Result<ChatFileRecord, StorageError> {
        let row: StoredChatFileRow = sqlx::query_as(
            "INSERT INTO chat_files (owner_id, organization_id, name, mimetype, data)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING id, owner_id, organization_id, created_at, name, mimetype, data",
        )
        .bind(input.owner_id)
        .bind(input.organization_id)
        .bind(&input.name)
        .bind(&input.mimetype)
        .bind(&input.data)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(ChatFileRecord {
            id: row.id,
            owner_id: row.owner_id,
            organization_id: row.organization_id,
            created_at: row.created_at,
            name: row.name,
            mimetype: row.mimetype,
            data: row.data,
        })
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_chat_file_by_id(&self, id: Uuid) -> Result<Option<ChatFileRecord>, StorageError> {
        let row: Option<StoredChatFileRow> = sqlx::query_as(
            "SELECT id, owner_id, organization_id, created_at, name, mimetype, data
             FROM chat_files WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(row.map(|r| ChatFileRecord {
            id: r.id,
            owner_id: r.owner_id,
            organization_id: r.organization_id,
            created_at: r.created_at,
            name: r.name,
            mimetype: r.mimetype,
            data: r.data,
        }))
    }

    // -----------------------------------------------------------------------
    // Chat Provider & Model Config
    // -----------------------------------------------------------------------

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_chat_message_content(
        &self,
        input: UpdateChatMessageContentInput,
    ) -> Result<ChatMessageRecord, StorageError> {
        let row: StoredChatMessageRow = sqlx::query_as(
            "UPDATE chat_messages SET content = $1
             WHERE id = $2 AND chat_id = $3
             RETURNING id, chat_id, model_config_id, created_at, role, content, visibility::text, input_tokens, output_tokens, total_tokens, reasoning_tokens, cache_creation_tokens, cache_read_tokens, context_limit, compressed",
        )
        .bind(&input.content)
        .bind(input.message_id)
        .bind(input.chat_id)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error_or_not_found)?;

        chat_message_record_from_row(row)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_chat_queued_message(
        &self,
        chat_id: Uuid,
        queued_message_id: i64,
    ) -> Result<(), StorageError> {
        sqlx::query("DELETE FROM chat_queued_messages WHERE id = $1 AND chat_id = $2")
            .bind(queued_message_id)
            .bind(chat_id)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn promote_chat_queued_message(
        &self,
        chat_id: Uuid,
        queued_message_id: i64,
    ) -> Result<ChatQueuedMessageRecord, StorageError> {
        let row: StoredChatQueuedMessageRow = sqlx::query_as(
            "UPDATE chat_queued_messages
             SET created_at = (
                 SELECT COALESCE(MIN(created_at), now()) - INTERVAL '1 second'
                 FROM chat_queued_messages WHERE chat_id = $2
             )
             WHERE id = $1 AND chat_id = $2
             RETURNING id, chat_id, content, created_at",
        )
        .bind(queued_message_id)
        .bind(chat_id)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error_or_not_found)?;

        Ok(ChatQueuedMessageRecord {
            id: row.id,
            chat_id: row.chat_id,
            content: row.content,
            created_at: row.created_at,
        })
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_chat_status(
        &self,
        id: Uuid,
        status: ChatStatus,
    ) -> Result<ChatRecord, StorageError> {
        let row: StoredChatRow = sqlx::query_as(
            "UPDATE chats SET status = $2::chat_status, updated_at = now()
             WHERE id = $1
             RETURNING id, owner_id, workspace_id, title, status::text, last_error, parent_chat_id, root_chat_id, last_model_config_id, archived, created_at, updated_at",
        )
        .bind(id)
        .bind(status.as_str())
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error_or_not_found)?;

        chat_record_from_row(row)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_chat_diff_status(
        &self,
        chat_id: Uuid,
    ) -> Result<Option<coder_core::api::ChatDiffStatusResponse>, StorageError> {
        let row: Option<StoredChatDiffStatusRow> = sqlx::query_as(
            "SELECT chat_id, url, pull_request_state, changes_requested,
                    additions, deletions, changed_files, refreshed_at,
                    stale_at, git_branch, git_remote_origin
             FROM chat_diff_statuses
             WHERE chat_id = $1",
        )
        .bind(chat_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(row.map(|r| coder_core::api::ChatDiffStatusResponse {
            chat_id: r.chat_id,
            url: r.url,
            pull_request_state: r.pull_request_state,
            changes_requested: r.changes_requested,
            additions: r.additions,
            deletions: r.deletions,
            changed_files: r.changed_files,
            refreshed_at: r.refreshed_at,
            stale_at: r.stale_at,
        }))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_chat_diff_contents(
        &self,
        chat_id: Uuid,
    ) -> Result<coder_core::api::ChatDiffContentsResponse, StorageError> {
        // The actual diff text is resolved from an external git provider at
        // the handler layer. We populate branch/remote_origin from the cached
        // diff status row when available; the diff field stays empty.
        let row: Option<StoredChatDiffStatusRow> = sqlx::query_as(
            "SELECT chat_id, url, pull_request_state, changes_requested,
                    additions, deletions, changed_files, refreshed_at,
                    stale_at, git_branch, git_remote_origin
             FROM chat_diff_statuses
             WHERE chat_id = $1",
        )
        .bind(chat_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(match row {
            Some(r) => coder_core::api::ChatDiffContentsResponse {
                chat_id,
                provider: None,
                remote_origin: if r.git_remote_origin.is_empty() {
                    None
                } else {
                    Some(r.git_remote_origin)
                },
                branch: if r.git_branch.is_empty() {
                    None
                } else {
                    Some(r.git_branch)
                },
                pull_request_url: r.url,
                diff: String::new(),
            },
            None => coder_core::api::ChatDiffContentsResponse {
                chat_id,
                provider: None,
                remote_origin: None,
                branch: None,
                pull_request_url: None,
                diff: String::new(),
            },
        })
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_enabled_chat_providers(
        &self,
    ) -> Result<Vec<coder_core::api::ChatModelProvider>, StorageError> {
        // The trait returns `ChatModelProvider` which aggregates provider
        // availability and model lists from external LLM APIs. The store
        // layer cannot probe external services, so we return an empty list.
        // The handler is responsible for calling `list_chat_providers()`,
        // filtering for enabled providers, and constructing `ChatModelProvider`
        // objects by probing each provider's API.
        Ok(Vec::new())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_chat_providers(&self) -> Result<Vec<ChatProviderRecord>, StorageError> {
        let rows: Vec<StoredChatProviderRow> = sqlx::query_as(
            "SELECT id, provider, display_name, api_key, base_url, enabled, created_at, updated_at
             FROM chat_providers
             ORDER BY created_at ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(chat_provider_record_from_row)
            .collect())
    }

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn insert_chat_provider(
        &self,
        input: InsertChatProviderInput,
    ) -> Result<ChatProviderRecord, StorageError> {
        let row: StoredChatProviderRow = sqlx::query_as(
            "INSERT INTO chat_providers (provider, display_name, api_key, base_url, enabled)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING id, provider, display_name, api_key, base_url, enabled, created_at, updated_at",
        )
        .bind(&input.provider)
        .bind(&input.display_name)
        .bind(&input.api_key)
        .bind(&input.base_url)
        .bind(input.enabled)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(chat_provider_record_from_row(row))
    }

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn update_chat_provider(
        &self,
        input: UpdateChatProviderInput,
    ) -> Result<ChatProviderRecord, StorageError> {
        let row: StoredChatProviderRow = sqlx::query_as(
            "UPDATE chat_providers
             SET display_name = $2,
                 api_key = $3,
                 base_url = $4,
                 enabled = $5,
                 updated_at = now()
             WHERE id = $1
             RETURNING id, provider, display_name, api_key, base_url, enabled, created_at, updated_at",
        )
        .bind(input.id)
        .bind(&input.display_name)
        .bind(&input.api_key)
        .bind(&input.base_url)
        .bind(input.enabled)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error_or_not_found)?;

        Ok(chat_provider_record_from_row(row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_chat_provider(&self, id: Uuid) -> Result<(), StorageError> {
        sqlx::query("DELETE FROM chat_providers WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_chat_model_configs(
        &self,
        enabled_only: bool,
    ) -> Result<Vec<ChatModelConfigRecord>, StorageError> {
        let rows: Vec<StoredChatModelConfigRow> = sqlx::query_as(
            "SELECT id, provider, model, display_name, enabled, is_default, context_limit, compression_threshold, options, created_at, updated_at
             FROM chat_model_configs
             WHERE deleted_at IS NULL AND ($1 = false OR enabled = true)
             ORDER BY created_at ASC",
        )
        .bind(enabled_only)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(chat_model_config_record_from_row)
            .collect())
    }

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn insert_chat_model_config(
        &self,
        input: InsertChatModelConfigInput,
    ) -> Result<ChatModelConfigRecord, StorageError> {
        let row: StoredChatModelConfigRow = sqlx::query_as(
            "INSERT INTO chat_model_configs (provider, model, display_name, enabled, is_default, context_limit, compression_threshold, options)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             RETURNING id, provider, model, display_name, enabled, is_default, context_limit, compression_threshold, options, created_at, updated_at",
        )
        .bind(&input.provider)
        .bind(&input.model)
        .bind(&input.display_name)
        .bind(input.enabled)
        .bind(input.is_default)
        .bind(input.context_limit)
        .bind(input.compression_threshold)
        .bind(&input.options)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(chat_model_config_record_from_row(row))
    }

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn update_chat_model_config(
        &self,
        input: UpdateChatModelConfigInput,
    ) -> Result<ChatModelConfigRecord, StorageError> {
        let row: StoredChatModelConfigRow = sqlx::query_as(
            "UPDATE chat_model_configs
             SET provider = $2,
                 model = $3,
                 display_name = $4,
                 enabled = $5,
                 is_default = $6,
                 context_limit = $7,
                 compression_threshold = $8,
                 options = $9,
                 updated_at = now()
             WHERE id = $1 AND deleted_at IS NULL
             RETURNING id, provider, model, display_name, enabled, is_default, context_limit, compression_threshold, options, created_at, updated_at",
        )
        .bind(input.id)
        .bind(&input.provider)
        .bind(&input.model)
        .bind(&input.display_name)
        .bind(input.enabled)
        .bind(input.is_default)
        .bind(input.context_limit)
        .bind(input.compression_threshold)
        .bind(&input.options)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error_or_not_found)?;

        Ok(chat_model_config_record_from_row(row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_chat_model_config(&self, id: Uuid) -> Result<(), StorageError> {
        sqlx::query(
            "UPDATE chat_model_configs SET deleted_at = now() WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn ensure_default_chat_model_config(&self) -> Result<(), StorageError> {
        sqlx::query(
            "UPDATE chat_model_configs
             SET is_default = true, updated_at = now()
             WHERE id = (
                 SELECT id FROM chat_model_configs
                 WHERE deleted_at IS NULL AND enabled = true
                 ORDER BY created_at ASC
                 LIMIT 1
             )
             AND NOT EXISTS (
                 SELECT 1 FROM chat_model_configs
                 WHERE is_default = true AND deleted_at IS NULL AND enabled = true
             )",
        )
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn unset_default_chat_model_configs(&self) -> Result<(), StorageError> {
        sqlx::query(
            "UPDATE chat_model_configs SET is_default = false, updated_at = now() WHERE is_default = true AND deleted_at IS NULL",
        )
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
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

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_webpush_subscriptions(&self, ids: &[Uuid]) -> Result<(), StorageError> {
        sqlx::query("DELETE FROM webpush_subscriptions WHERE id = ANY($1)")
            .bind(ids)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_all_webpush_subscriptions(&self) -> Result<(), StorageError> {
        sqlx::query("TRUNCATE TABLE webpush_subscriptions")
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_webpush_vapid_keys(&self) -> Result<Option<VapidKeyPair>, StorageError> {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT key, value FROM site_configs WHERE key IN ('webpush_vapid_public_key', 'webpush_vapid_private_key')",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        let mut public_key = None;
        let mut private_key = None;
        for (key, value) in &rows {
            match key.as_str() {
                "webpush_vapid_public_key" => public_key = Some(value.clone()),
                "webpush_vapid_private_key" => private_key = Some(value.clone()),
                _ => {}
            }
        }

        match (public_key, private_key) {
            (Some(public_key), Some(private_key))
                if !public_key.is_empty() && !private_key.is_empty() =>
            {
                Ok(Some(VapidKeyPair {
                    public_key,
                    private_key,
                }))
            }
            _ => Ok(None),
        }
    }

    #[instrument(skip(self, public_key, private_key), err(level = tracing::Level::WARN))]
    async fn upsert_webpush_vapid_keys(
        &self,
        public_key: &str,
        private_key: &str,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO site_configs (key, value)
             VALUES
                 ('webpush_vapid_public_key', $1),
                 ('webpush_vapid_private_key', $2)
             ON CONFLICT (key)
             DO UPDATE SET value = EXCLUDED.value WHERE site_configs.key = EXCLUDED.key",
        )
        .bind(public_key)
        .bind(private_key)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Notification message dispatch
    // -----------------------------------------------------------------------

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn acquire_pending_notification_messages(
        &self,
        limit: u32,
        max_attempt_count: u32,
    ) -> Result<Vec<NotificationMessageRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredNotificationMessageRow>(
            r#"UPDATE notification_messages
               SET status = 'leased'::notification_message_status,
                   leased_until = NOW() + INTERVAL '30 seconds',
                   updated_at = NOW()
               WHERE id IN (
                   SELECT id
                   FROM notification_messages
                   WHERE (status IN ('pending', 'temporary_failure')
                          OR (status = 'leased' AND leased_until < NOW()))
                     AND (next_retry_after IS NULL OR next_retry_after < NOW())
                     AND (attempt_count IS NULL OR attempt_count < $2)
                   ORDER BY created_at ASC
                   LIMIT $1
                   FOR UPDATE SKIP LOCKED
               )
               RETURNING id, user_id, notification_template_id,
                         method::text AS method,
                         status::text AS status,
                         attempt_count,
                         payload::text AS payload,
                         COALESCE(to_json(COALESCE(targets, ARRAY[]::uuid[])), '[]'::json)::text AS targets_json,
                         created_at,
                         updated_at"#,
        )
        .bind(limit as i64)
        .bind(max_attempt_count as i32)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        rows.into_iter()
            .map(notification_message_from_row)
            .collect()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_notification_message_status(
        &self,
        message_id: Uuid,
        status: NotificationMessageStatus,
    ) -> Result<bool, StorageError> {
        let status_str = match status {
            NotificationMessageStatus::Pending => "pending",
            NotificationMessageStatus::Leased => "leased",
            NotificationMessageStatus::Sent => "sent",
            NotificationMessageStatus::TemporaryFailure => "temporary_failure",
            NotificationMessageStatus::PermanentFailure => "permanent_failure",
            NotificationMessageStatus::Unknown => "unknown",
            NotificationMessageStatus::Inhibited => "inhibited",
        };

        let result = sqlx::query(
            r#"UPDATE notification_messages
               SET status = $2::notification_message_status,
                   updated_at = NOW()
               WHERE id = $1"#,
        )
        .bind(message_id)
        .bind(status_str)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn increment_notification_message_attempt_count(
        &self,
        message_id: Uuid,
    ) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "UPDATE notification_messages
             SET attempt_count = COALESCE(attempt_count, 0) + 1,
                 updated_at = NOW()
             WHERE id = $1",
        )
        .bind(message_id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(result.rows_affected() > 0)
    }

    // -----------------------------------------------------------------------
    // Custom roles
    // -----------------------------------------------------------------------

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_custom_roles(
        &self,
        organization_id: Option<Uuid>,
    ) -> Result<Vec<CustomRoleRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredCustomRoleRow>(
            r#"SELECT name, display_name, organization_id,
                      site_permissions::text AS site_permissions,
                      org_permissions::text AS org_permissions,
                      user_permissions::text AS user_permissions,
                      created_at, updated_at
               FROM custom_roles
               WHERE ($1::uuid IS NULL OR organization_id = $1)
               ORDER BY name ASC"#,
        )
        .bind(organization_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(|r| CustomRoleRecord {
                name: r.name,
                display_name: r.display_name,
                organization_id: r.organization_id,
                site_permissions: r.site_permissions,
                org_permissions: r.org_permissions,
                user_permissions: r.user_permissions,
                created_at: r.created_at,
                updated_at: r.updated_at,
            })
            .collect())
    }

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn upsert_custom_role(
        &self,
        input: &UpsertCustomRoleInput,
    ) -> Result<CustomRoleRecord, StorageError> {
        let row = sqlx::query_as::<_, StoredCustomRoleRow>(
            r#"INSERT INTO custom_roles (name, display_name, organization_id,
                                         site_permissions, org_permissions, user_permissions,
                                         created_at, updated_at)
               VALUES (LOWER($1), $2, $3, $4::jsonb, $5::jsonb, $6::jsonb, NOW(), NOW())
               ON CONFLICT (name, organization_id) DO UPDATE
               SET display_name = EXCLUDED.display_name,
                   site_permissions = EXCLUDED.site_permissions,
                   org_permissions = EXCLUDED.org_permissions,
                   user_permissions = EXCLUDED.user_permissions,
                   updated_at = NOW()
               RETURNING name, display_name, organization_id,
                         site_permissions::text AS site_permissions,
                         org_permissions::text AS org_permissions,
                         user_permissions::text AS user_permissions,
                         created_at, updated_at"#,
        )
        .bind(&input.name)
        .bind(&input.display_name)
        .bind(input.organization_id)
        .bind(&input.site_permissions)
        .bind(&input.org_permissions)
        .bind(&input.user_permissions)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(CustomRoleRecord {
            name: row.name,
            display_name: row.display_name,
            organization_id: row.organization_id,
            site_permissions: row.site_permissions,
            org_permissions: row.org_permissions,
            user_permissions: row.user_permissions,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    // -----------------------------------------------------------------------
    // Workspace Agent storage methods
    // -----------------------------------------------------------------------

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_workspace_agent_by_id(
        &self,
        agent_id: Uuid,
    ) -> Result<Option<WorkspaceAgentRow>, StorageError> {
        sqlx::query_as::<_, StoredWorkspaceAgentRow>(
            "SELECT
                id, parent_id, created_at, updated_at, name,
                first_connected_at, last_connected_at, disconnected_at,
                resource_id, auth_token, auth_instance_id,
                architecture, environment_variables::text AS environment_variables, operating_system,
                directory, expanded_directory, version, api_version,
                connection_timeout_seconds, troubleshooting_url, motd_file,
                lifecycle_state::text AS lifecycle_state, logs_length, logs_overflowed,
                started_at, ready_at,
                subsystems::text[] AS subsystems,
                display_apps::text[] AS display_apps,
                display_order, api_key_scope::text AS api_key_scope
             FROM workspace_agents
             WHERE id = $1 AND deleted = false",
        )
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(workspace_agent_row_from_stored))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_workspace_agent_by_auth_token(
        &self,
        auth_token: Uuid,
    ) -> Result<Option<WorkspaceAgentRow>, StorageError> {
        sqlx::query_as::<_, StoredWorkspaceAgentRow>(
            "SELECT
                id, parent_id, created_at, updated_at, name,
                first_connected_at, last_connected_at, disconnected_at,
                resource_id, auth_token, auth_instance_id,
                architecture, environment_variables::text AS environment_variables, operating_system,
                directory, expanded_directory, version, api_version,
                connection_timeout_seconds, troubleshooting_url, motd_file,
                lifecycle_state::text AS lifecycle_state, logs_length, logs_overflowed,
                started_at, ready_at,
                subsystems::text[] AS subsystems,
                display_apps::text[] AS display_apps,
                display_order, api_key_scope::text AS api_key_scope
             FROM workspace_agents
             WHERE auth_token = $1 AND deleted = false",
        )
        .bind(auth_token)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(workspace_agent_row_from_stored))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_workspace_agent_by_instance_id(
        &self,
        instance_id: &str,
    ) -> Result<Option<WorkspaceAgentRow>, StorageError> {
        sqlx::query_as::<_, StoredWorkspaceAgentRow>(
            "SELECT
                id, parent_id, created_at, updated_at, name,
                first_connected_at, last_connected_at, disconnected_at,
                resource_id, auth_token, auth_instance_id,
                architecture, environment_variables::text AS environment_variables, operating_system,
                directory, expanded_directory, version, api_version,
                connection_timeout_seconds, troubleshooting_url, motd_file,
                lifecycle_state::text AS lifecycle_state, logs_length, logs_overflowed,
                started_at, ready_at,
                subsystems::text[] AS subsystems,
                display_apps::text[] AS display_apps,
                display_order, api_key_scope::text AS api_key_scope
             FROM workspace_agents
             WHERE auth_instance_id = $1 AND deleted = false
             ORDER BY created_at DESC
             LIMIT 1",
        )
        .bind(instance_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(workspace_agent_row_from_stored))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_workspace_by_agent_id(
        &self,
        agent_id: Uuid,
    ) -> Result<Option<WorkspaceRecord>, StorageError> {
        sqlx::query_as::<_, StoredWorkspaceRow>(
            "SELECT
                w.id, w.created_at, w.updated_at, w.deleted,
                w.owner_id, w.organization_id, w.template_id,
                w.name, w.autostart_schedule, w.ttl,
                w.last_used_at, w.dormant_at, w.deleting_at,
                w.automatic_updates::text AS automatic_updates,
                w.favorite, w.next_start_at
             FROM workspaces w
             JOIN workspace_builds wb ON wb.workspace_id = w.id
             JOIN workspace_resources wr ON wr.job_id = wb.job_id
             JOIN workspace_agents wa ON wa.resource_id = wr.id
             WHERE wa.id = $1 AND wa.deleted = false AND w.deleted = false
             ORDER BY wb.build_number DESC
             LIMIT 1",
        )
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(workspace_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_workspace_agents_by_resource_ids(
        &self,
        resource_ids: &[Uuid],
    ) -> Result<Vec<WorkspaceAgentRow>, StorageError> {
        let rows = sqlx::query_as::<_, StoredWorkspaceAgentRow>(
            "SELECT
                id, parent_id, created_at, updated_at, name,
                first_connected_at, last_connected_at, disconnected_at,
                resource_id, auth_token, auth_instance_id,
                architecture, environment_variables::text AS environment_variables, operating_system,
                directory, expanded_directory, version, api_version,
                connection_timeout_seconds, troubleshooting_url, motd_file,
                lifecycle_state::text AS lifecycle_state, logs_length, logs_overflowed,
                started_at, ready_at,
                subsystems::text[] AS subsystems,
                display_apps::text[] AS display_apps,
                display_order, api_key_scope::text AS api_key_scope
             FROM workspace_agents
             WHERE resource_id = ANY($1) AND deleted = false
             ORDER BY created_at ASC",
        )
        .bind(resource_ids)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(workspace_agent_row_from_stored)
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_workspace_apps_by_agent_id(
        &self,
        agent_id: Uuid,
    ) -> Result<Vec<WorkspaceAppRow>, StorageError> {
        let rows = sqlx::query_as::<_, StoredWorkspaceAppRow>(
            "SELECT
                id, created_at, agent_id, display_name, icon,
                command, url, healthcheck_url, healthcheck_interval,
                healthcheck_threshold, health::text AS health, subdomain,
                sharing_level::text AS sharing_level, slug, external,
                display_order, hidden, open_in::text AS open_in,
                display_group
             FROM workspace_apps
             WHERE agent_id = $1
             ORDER BY display_order ASC, slug ASC",
        )
        .bind(agent_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(workspace_app_row_from_stored)
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_workspace_agent_scripts(
        &self,
        agent_id: Uuid,
    ) -> Result<Vec<WorkspaceAgentScriptRow>, StorageError> {
        let rows = sqlx::query_as::<_, StoredWorkspaceAgentScriptRow>(
            "SELECT
                id, workspace_agent_id, log_source_id, log_path,
                created_at, script, cron, start_blocks_login,
                run_on_start, run_on_stop, timeout_seconds, display_name
             FROM workspace_agent_scripts
             WHERE workspace_agent_id = $1
             ORDER BY display_name ASC",
        )
        .bind(agent_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(workspace_agent_script_row_from_stored)
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_workspace_agent_log_sources(
        &self,
        agent_id: Uuid,
    ) -> Result<Vec<WorkspaceAgentLogSourceRow>, StorageError> {
        let rows = sqlx::query_as::<_, StoredWorkspaceAgentLogSourceRow>(
            "SELECT id, workspace_agent_id, created_at, display_name, icon
             FROM workspace_agent_log_sources
             WHERE workspace_agent_id = $1
             ORDER BY created_at ASC",
        )
        .bind(agent_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(workspace_agent_log_source_row_from_stored)
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_workspace_agent_logs(
        &self,
        agent_id: Uuid,
        after_id: i64,
        limit: i64,
    ) -> Result<Vec<WorkspaceAgentLogRow>, StorageError> {
        let rows = sqlx::query_as::<_, StoredWorkspaceAgentLogRow>(
            "SELECT id, agent_id, created_at, output, level::text AS level, log_source_id
             FROM workspace_agent_logs
             WHERE agent_id = $1 AND id > $2
             ORDER BY id ASC
             LIMIT $3",
        )
        .bind(agent_id)
        .bind(after_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(workspace_agent_log_row_from_stored)
            .collect())
    }

    #[instrument(skip(self, logs), err(level = tracing::Level::WARN))]
    async fn insert_workspace_agent_logs(
        &self,
        agent_id: Uuid,
        log_source_id: Uuid,
        logs: &[InsertAgentLogInput],
    ) -> Result<Vec<WorkspaceAgentLogRow>, StorageError> {
        let log_count = i32::try_from(logs.len())
            .map_err(|_| StorageError::invalid_data("too many log entries"))?;

        let mut created_ats = Vec::with_capacity(logs.len());
        let mut outputs = Vec::with_capacity(logs.len());
        let mut levels = Vec::with_capacity(logs.len());

        for log in logs {
            created_ats.push(log.created_at);
            outputs.push(log.output.as_str());
            levels.push(log.level.as_str());
        }

        let mut tx = self.pool.begin().await.map_err(storage_error)?;

        // Update logs_length and logs_overflowed on the workspace_agents row.
        // The CHECK constraint max_logs_length ensures logs_length <= 1048576.
        sqlx::query(
            "UPDATE workspace_agents
             SET logs_length = LEAST(logs_length + $2, 1048576),
                 logs_overflowed = logs_overflowed OR (logs_length + $2 > 1048576)
             WHERE id = $1",
        )
        .bind(agent_id)
        .bind(log_count)
        .execute(&mut *tx)
        .await
        .map_err(storage_error)?;

        let rows = sqlx::query_as::<_, StoredWorkspaceAgentLogRow>(
            "INSERT INTO workspace_agent_logs (agent_id, created_at, output, level, log_source_id)
             SELECT $1, unnest($2::timestamptz[]), unnest($3::text[]),
                    unnest($4::log_level[]), $5
             RETURNING id, agent_id, created_at, output, level::text AS level, log_source_id",
        )
        .bind(agent_id)
        .bind(&created_ats)
        .bind(&outputs)
        .bind(&levels)
        .bind(log_source_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(storage_error)?;

        tx.commit().await.map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(workspace_agent_log_row_from_stored)
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_workspace_agent_metadata(
        &self,
        agent_id: Uuid,
    ) -> Result<Vec<WorkspaceAgentMetadataRow>, StorageError> {
        let rows = sqlx::query_as::<_, StoredWorkspaceAgentMetadataRow>(
            "SELECT workspace_agent_id, display_name, key, script,
                    value, error, timeout, interval, collected_at, display_order
             FROM workspace_agent_metadata
             WHERE workspace_agent_id = $1
             ORDER BY display_order ASC, key ASC",
        )
        .bind(agent_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(workspace_agent_metadata_row_from_stored)
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_workspace_agent_lifecycle_state(
        &self,
        agent_id: Uuid,
        lifecycle_state: &str,
        started_at: Option<OffsetDateTime>,
        ready_at: Option<OffsetDateTime>,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "UPDATE workspace_agents
             SET lifecycle_state = $2::workspace_agent_lifecycle_state,
                 started_at = COALESCE($3, started_at),
                 ready_at = COALESCE($4, ready_at)
             WHERE id = $1",
        )
        .bind(agent_id)
        .bind(lifecycle_state)
        .bind(started_at)
        .bind(ready_at)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(())
    }

    #[instrument(skip(self, entries), err(level = tracing::Level::WARN))]
    async fn upsert_workspace_agent_metadata(
        &self,
        agent_id: Uuid,
        entries: &[UpsertAgentMetadataEntry],
    ) -> Result<(), StorageError> {
        let mut tx = self.pool.begin().await.map_err(storage_error)?;
        for entry in entries {
            sqlx::query(
                "UPDATE workspace_agent_metadata
                 SET value = $3, error = $4, collected_at = $5
                 WHERE workspace_agent_id = $1 AND key = $2",
            )
            .bind(agent_id)
            .bind(&entry.key)
            .bind(&entry.value)
            .bind(&entry.error)
            .bind(entry.collected_at)
            .execute(&mut *tx)
            .await
            .map_err(storage_error)?;
        }
        tx.commit().await.map_err(storage_error)?;
        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_workspace_agent_devcontainers(
        &self,
        agent_id: Uuid,
    ) -> Result<Vec<WorkspaceAgentDevcontainerRow>, StorageError> {
        let rows = sqlx::query_as::<_, StoredWorkspaceAgentDevcontainerRow>(
            "SELECT id, workspace_agent_id, created_at, workspace_folder,
                    config_path, name, subagent_id
             FROM workspace_agent_devcontainers
             WHERE workspace_agent_id = $1
             ORDER BY name ASC",
        )
        .bind(agent_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(workspace_agent_devcontainer_row_from_stored)
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn insert_workspace_agent_log_source(
        &self,
        agent_id: Uuid,
        id: Option<Uuid>,
        display_name: &str,
        icon: &str,
    ) -> Result<WorkspaceAgentLogSourceRow, StorageError> {
        let source_id = id.unwrap_or_else(Uuid::new_v4);
        let row = sqlx::query_as::<_, StoredWorkspaceAgentLogSourceRow>(
            "INSERT INTO workspace_agent_log_sources (id, workspace_agent_id, created_at, display_name, icon)
             VALUES ($1, $2, NOW(), $3, $4)
             RETURNING id, workspace_agent_id, created_at, display_name, icon",
        )
        .bind(source_id)
        .bind(agent_id)
        .bind(display_name)
        .bind(icon)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(workspace_agent_log_source_row_from_stored(row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_workspace_app_statuses_by_agent_id(
        &self,
        agent_id: Uuid,
    ) -> Result<Vec<WorkspaceAppStatusRow>, StorageError> {
        let rows = sqlx::query_as::<_, StoredWorkspaceAppStatusRow>(
            "SELECT id, created_at, agent_id, app_id, workspace_id,
                    state::text AS state, message, uri
             FROM workspace_app_statuses
             WHERE agent_id = $1
             ORDER BY created_at DESC",
        )
        .bind(agent_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(workspace_app_status_row_from_stored)
            .collect())
    }

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn insert_workspace_app_status(
        &self,
        input: &InsertWorkspaceAppStatusInput,
    ) -> Result<WorkspaceAppStatusRow, StorageError> {
        let row = sqlx::query_as::<_, StoredWorkspaceAppStatusRow>(
            "INSERT INTO workspace_app_statuses (id, created_at, agent_id, app_id, workspace_id, state, message, uri)
             VALUES ($1, NOW(), $2, $3, $4, $5::workspace_app_status_state, $6, $7)
             RETURNING id, created_at, agent_id, app_id, workspace_id, state::text AS state, message, uri",
        )
        .bind(Uuid::new_v4())
        .bind(input.agent_id)
        .bind(input.app_id)
        .bind(input.workspace_id)
        .bind(&input.state)
        .bind(&input.message)
        .bind(&input.uri)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(workspace_app_status_row_from_stored(row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_workspace_app_by_agent_and_slug(
        &self,
        agent_id: Uuid,
        slug: &str,
    ) -> Result<Option<WorkspaceAppRow>, StorageError> {
        sqlx::query_as::<_, StoredWorkspaceAppRow>(
            "SELECT
                id, created_at, agent_id, display_name, icon,
                command, url, healthcheck_url, healthcheck_interval,
                healthcheck_threshold, health::text AS health, subdomain,
                sharing_level::text AS sharing_level, slug, external,
                display_order, hidden, open_in::text AS open_in,
                display_group
             FROM workspace_apps
             WHERE agent_id = $1 AND slug = $2",
        )
        .bind(agent_id)
        .bind(slug)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(workspace_app_row_from_stored))
    }

    // -------------------------------------------------------------------
    // Workspace domain
    // -------------------------------------------------------------------

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_workspaces(
        &self,
        filter: WorkspaceListFilter,
    ) -> Result<(Vec<WorkspaceRecord>, i64), StorageError> {
        let query_start = std::time::Instant::now();
        let result: Result<(Vec<WorkspaceRecord>, i64), StorageError> = async {
        let search = filter
            .name
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .map(|s| format!("%{}%", s.trim().replace('%', "\\%").replace('_', "\\_")));
        let owner_username = filter.owner_username.clone();
        let template_name = filter.template_name.clone();
        let _status = filter.status.clone();
        let _has_agent = filter.has_agent.clone();
        let dormant = filter.dormant;
        let template_ids: Vec<Uuid> = filter.template_ids.clone();

        let total = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*)
             FROM workspaces w
             LEFT JOIN users u ON u.id = w.owner_id
             LEFT JOIN templates t ON t.id = w.template_id
             WHERE w.deleted = false
               AND ($1::uuid IS NULL OR w.owner_id = $1)
               AND ($2::text IS NULL OR u.username = $2)
               AND ($3::text IS NULL OR w.name ILIKE $3)
               AND ($4::text IS NULL OR t.name = $4)
               AND ($5::uuid IS NULL OR w.organization_id = $5)
               AND ($6::bool IS NULL OR ($6 = true AND w.dormant_at IS NOT NULL) OR ($6 = false AND w.dormant_at IS NULL))
               AND (cardinality($7::uuid[]) = 0 OR w.template_id = ANY($7))",
        )
        .bind(filter.owner_id)
        .bind(owner_username.as_deref())
        .bind(search.as_deref())
        .bind(template_name.as_deref())
        .bind(filter.organization_id)
        .bind(dormant)
        .bind(&template_ids)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        let viewer_id = filter.viewer_id;
        let rows = sqlx::query_as::<_, StoredWorkspaceRow>(
            "SELECT
                w.id,
                w.created_at,
                w.updated_at,
                w.deleted,
                w.owner_id,
                w.organization_id,
                w.template_id,
                w.name,
                w.autostart_schedule,
                w.ttl,
                w.last_used_at,
                w.dormant_at,
                w.deleting_at,
                w.automatic_updates,
                COALESCE((wf.workspace_id IS NOT NULL), false) AS favorite,
                w.next_start_at
             FROM workspaces w
             LEFT JOIN users u ON u.id = w.owner_id
             LEFT JOIN templates t ON t.id = w.template_id
             LEFT JOIN workspace_favorites wf ON wf.workspace_id = w.id AND wf.user_id = $10
             WHERE w.deleted = false
               AND ($1::uuid IS NULL OR w.owner_id = $1)
               AND ($2::text IS NULL OR u.username = $2)
               AND ($3::text IS NULL OR w.name ILIKE $3)
               AND ($4::text IS NULL OR t.name = $4)
               AND ($5::uuid IS NULL OR w.organization_id = $5)
               AND ($6::bool IS NULL OR ($6 = true AND w.dormant_at IS NOT NULL) OR ($6 = false AND w.dormant_at IS NULL))
               AND (cardinality($7::uuid[]) = 0 OR w.template_id = ANY($7))
             ORDER BY w.last_used_at DESC
             LIMIT $8 OFFSET $9",
        )
        .bind(filter.owner_id)
        .bind(owner_username.as_deref())
        .bind(search.as_deref())
        .bind(template_name.as_deref())
        .bind(filter.organization_id)
        .bind(dormant)
        .bind(&template_ids)
        .bind(i64::from(filter.limit.min(1000)))
        .bind(i64::from(filter.offset))
        .bind(viewer_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        let workspaces: Vec<WorkspaceRecord> =
            rows.into_iter().map(workspace_record_from_row).collect();
        Ok((workspaces, total))
        }.await;
        let query_duration = query_start.elapsed().as_secs_f64() * 1000.0;
        record_db_query("list_workspaces", query_duration, result.is_ok());
        result
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_workspace_by_id(
        &self,
        workspace_id: Uuid,
        viewer_id: Option<Uuid>,
    ) -> Result<Option<WorkspaceRecord>, StorageError> {
        let query_start = std::time::Instant::now();
        let result = sqlx::query_as::<_, StoredWorkspaceRow>(
            "SELECT w.id, w.created_at, w.updated_at, w.deleted, w.owner_id, w.organization_id,
                    w.template_id, w.name, w.autostart_schedule, w.ttl, w.last_used_at,
                    w.dormant_at, w.deleting_at, w.automatic_updates,
                    COALESCE((wf.workspace_id IS NOT NULL), false) AS favorite,
                    w.next_start_at
             FROM workspaces w
             LEFT JOIN workspace_favorites wf ON wf.workspace_id = w.id AND wf.user_id = $2
             WHERE w.id = $1 AND w.deleted = false",
        )
        .bind(workspace_id)
        .bind(viewer_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(workspace_record_from_row));
        let query_duration = query_start.elapsed().as_secs_f64() * 1000.0;
        record_db_query("find_workspace_by_id", query_duration, result.is_ok());
        result
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_workspace_by_owner_and_name(
        &self,
        owner_id: Uuid,
        name: &str,
        viewer_id: Option<Uuid>,
    ) -> Result<Option<WorkspaceRecord>, StorageError> {
        sqlx::query_as::<_, StoredWorkspaceRow>(
            "SELECT w.id, w.created_at, w.updated_at, w.deleted, w.owner_id, w.organization_id,
                    w.template_id, w.name, w.autostart_schedule, w.ttl, w.last_used_at,
                    w.dormant_at, w.deleting_at, w.automatic_updates,
                    COALESCE((wf.workspace_id IS NOT NULL), false) AS favorite,
                    w.next_start_at
             FROM workspaces w
             LEFT JOIN workspace_favorites wf ON wf.workspace_id = w.id AND wf.user_id = $3
             WHERE w.owner_id = $1 AND LOWER(w.name) = LOWER($2) AND w.deleted = false",
        )
        .bind(owner_id)
        .bind(name)
        .bind(viewer_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(workspace_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn insert_workspace(
        &self,
        input: CreateWorkspaceInput,
    ) -> Result<WorkspaceRecord, StorageError> {
        sqlx::query_as::<_, StoredWorkspaceRow>(
            "INSERT INTO workspaces (
                id, owner_id, organization_id, template_id, name,
                autostart_schedule, ttl, automatic_updates,
                created_at, updated_at, last_used_at
             )
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW(), NOW())
             RETURNING id, created_at, updated_at, deleted, owner_id, organization_id,
                       template_id, name, autostart_schedule, ttl, last_used_at,
                       dormant_at, deleting_at, automatic_updates,
                       false AS favorite, next_start_at",
        )
        .bind(input.id)
        .bind(input.owner_id)
        .bind(input.organization_id)
        .bind(input.template_id)
        .bind(&input.name)
        .bind(input.autostart_schedule.as_deref())
        .bind(input.ttl_ns)
        .bind(&input.automatic_updates)
        .fetch_one(&self.pool)
        .await
        .map(workspace_record_from_row)
        .map_err(storage_error)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_workspace_name(
        &self,
        workspace_id: Uuid,
        name: &str,
        viewer_id: Option<Uuid>,
    ) -> Result<Option<WorkspaceRecord>, StorageError> {
        sqlx::query_as::<_, StoredWorkspaceRow>(
            "WITH updated AS (
                UPDATE workspaces
                SET name = $2, updated_at = NOW()
                WHERE id = $1 AND deleted = false
                RETURNING *
             )
             SELECT u.id, u.created_at, u.updated_at, u.deleted, u.owner_id,
                    u.organization_id, u.template_id, u.name, u.autostart_schedule,
                    u.ttl, u.last_used_at, u.dormant_at, u.deleting_at,
                    u.automatic_updates,
                    COALESCE((wf.user_id IS NOT NULL), false) AS favorite,
                    u.next_start_at
             FROM updated u
             LEFT JOIN workspace_favorites wf
               ON wf.workspace_id = u.id AND wf.user_id = $3",
        )
        .bind(workspace_id)
        .bind(name)
        .bind(viewer_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(workspace_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_workspace_autostart(
        &self,
        workspace_id: Uuid,
        schedule: Option<&str>,
    ) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "UPDATE workspaces SET autostart_schedule = $2, updated_at = NOW()
             WHERE id = $1 AND deleted = false",
        )
        .bind(workspace_id)
        .bind(schedule)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_workspace_ttl(
        &self,
        workspace_id: Uuid,
        ttl_ns: Option<i64>,
    ) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "UPDATE workspaces SET ttl = $2, updated_at = NOW()
             WHERE id = $1 AND deleted = false",
        )
        .bind(workspace_id)
        .bind(ttl_ns)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_workspace_dormant_at(
        &self,
        workspace_id: Uuid,
        dormant_at: Option<OffsetDateTime>,
        viewer_id: Option<Uuid>,
    ) -> Result<Option<WorkspaceRecord>, StorageError> {
        sqlx::query_as::<_, StoredWorkspaceRow>(
            "WITH updated AS (
                UPDATE workspaces
                SET dormant_at = $2, updated_at = NOW()
                WHERE id = $1 AND deleted = false
                RETURNING *
             )
             SELECT u.id, u.created_at, u.updated_at, u.deleted, u.owner_id,
                    u.organization_id, u.template_id, u.name, u.autostart_schedule,
                    u.ttl, u.last_used_at, u.dormant_at, u.deleting_at,
                    u.automatic_updates,
                    COALESCE((wf.user_id IS NOT NULL), false) AS favorite,
                    u.next_start_at
             FROM updated u
             LEFT JOIN workspace_favorites wf
               ON wf.workspace_id = u.id AND wf.user_id = $3",
        )
        .bind(workspace_id)
        .bind(dormant_at)
        .bind(viewer_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(workspace_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_workspace_automatic_updates(
        &self,
        workspace_id: Uuid,
        automatic_updates: &str,
    ) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "UPDATE workspaces SET automatic_updates = $2, updated_at = NOW()
             WHERE id = $1 AND deleted = false",
        )
        .bind(workspace_id)
        .bind(automatic_updates)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_workspace_last_used_at(
        &self,
        workspace_id: Uuid,
        last_used_at: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "UPDATE workspaces SET last_used_at = $2, updated_at = NOW()
             WHERE id = $1 AND deleted = false",
        )
        .bind(workspace_id)
        .bind(last_used_at)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn favorite_workspace(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
        favorite: bool,
    ) -> Result<bool, StorageError> {
        if favorite {
            // Insert into junction table (ignore conflict if already favorited).
            sqlx::query(
                "INSERT INTO workspace_favorites (workspace_id, user_id)
                 VALUES ($1, $2)
                 ON CONFLICT (workspace_id, user_id) DO NOTHING",
            )
            .bind(workspace_id)
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;
        } else {
            // Remove from junction table.
            sqlx::query(
                "DELETE FROM workspace_favorites
                 WHERE workspace_id = $1 AND user_id = $2",
            )
            .bind(workspace_id)
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;
        }
        Ok(true)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn soft_delete_workspace(&self, workspace_id: Uuid) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "UPDATE workspaces SET deleted = true, updated_at = NOW()
             WHERE id = $1 AND deleted = false",
        )
        .bind(workspace_id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_workspace_dormant_deleting_at(
        &self,
        workspace_id: Uuid,
        dormant_at: Option<OffsetDateTime>,
    ) -> Result<Option<WorkspaceRecord>, StorageError> {
        sqlx::query_as::<_, StoredWorkspaceRow>(
            "WITH updated AS (
                UPDATE workspaces
                SET
                    dormant_at = $2,
                    last_used_at = CASE WHEN $2::timestamptz IS NULL THEN
                        now()
                    ELSE
                        last_used_at
                    END,
                    deleting_at = CASE WHEN $2::timestamptz IS NULL OR templates.time_til_dormant_autodelete = 0 THEN
                        NULL
                    ELSE
                        $2::timestamptz + (INTERVAL '1 millisecond' * (templates.time_til_dormant_autodelete / 1000000))
                    END,
                    updated_at = NOW()
                FROM
                    templates
                WHERE
                    workspaces.id = $1
                    AND workspaces.deleted = false
                    AND templates.id = workspaces.template_id
                    AND owner_id != 'c42fdf75-3097-471c-8c33-fb52454d81c0'::UUID
                RETURNING workspaces.*
             )
             SELECT u.id, u.created_at, u.updated_at, u.deleted, u.owner_id,
                    u.organization_id, u.template_id, u.name, u.autostart_schedule,
                    u.ttl, u.last_used_at, u.dormant_at, u.deleting_at,
                    u.automatic_updates,
                    false AS favorite,
                    u.next_start_at
             FROM updated u",
        )
        .bind(workspace_id)
        .bind(dormant_at)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(workspace_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_workspaces_eligible_for_transition(
        &self,
        now: OffsetDateTime,
    ) -> Result<Vec<WorkspaceTransitionRow>, StorageError> {
        let rows = sqlx::query_as::<_, StoredWorkspaceTransitionRow>(
            "SELECT
                workspaces.id,
                workspaces.name,
                workspaces.owner_id,
                workspaces.template_id,
                workspaces.autostart_schedule,
                workspaces.ttl,
                workspaces.last_used_at,
                workspaces.dormant_at,
                workspaces.deleting_at,
                workspaces.deleted,
                workspace_builds.transition AS build_transition,
                workspace_builds.deadline AS build_deadline,
                provisioner_jobs.job_status::text AS job_status,
                provisioner_jobs.completed_at AS job_completed_at,
                templates.allow_user_autostart AS template_allow_user_autostart,
                templates.default_ttl AS template_default_ttl,
                templates.failure_ttl AS template_failure_ttl,
                templates.time_til_dormant AS template_time_til_dormant,
                templates.time_til_dormant_autodelete AS template_time_til_dormant_autodelete,
                users.status::text AS owner_status,
                workspace_builds.id AS build_id,
                workspace_builds.max_deadline AS max_deadline,
                COALESCE(templates.activity_bump, 0) AS activity_bump_ns
             FROM workspaces
             LEFT JOIN workspace_builds
                ON workspace_builds.workspace_id = workspaces.id
             INNER JOIN provisioner_jobs
                ON workspace_builds.job_id = provisioner_jobs.id
             INNER JOIN templates
                ON workspaces.template_id = templates.id
             INNER JOIN users
                ON workspaces.owner_id = users.id
             WHERE
                workspace_builds.build_number = (
                    SELECT MAX(build_number)
                    FROM workspace_builds
                    WHERE workspace_builds.workspace_id = workspaces.id
                )
                AND (
                    -- Autostop: build started, deadline passed or owner suspended
                    (
                        provisioner_jobs.job_status != 'failed'::provisioner_job_status
                        AND workspaces.dormant_at IS NULL
                        AND workspace_builds.transition = 'start'::workspace_transition
                        AND (
                            users.status = 'suspended'::user_status
                            OR (
                                workspace_builds.deadline != '0001-01-01 00:00:00+00'::timestamptz
                                AND workspace_builds.deadline < $1::timestamptz
                            )
                        )
                    )
                    OR
                    -- Autostart: build stopped, schedule ready
                    (
                        users.status = 'active'::user_status
                        AND provisioner_jobs.job_status != 'failed'::provisioner_job_status
                        AND workspace_builds.transition = 'stop'::workspace_transition
                        AND workspaces.dormant_at IS NULL
                        AND workspaces.autostart_schedule IS NOT NULL
                        AND (
                            workspaces.next_start_at IS NULL
                            OR workspaces.next_start_at <= $1::timestamptz
                        )
                    )
                    OR
                    -- Dormant stop: unused longer than time_til_dormant
                    (
                        workspaces.dormant_at IS NULL
                        AND templates.time_til_dormant > 0
                        AND ($1::timestamptz) - workspaces.last_used_at > (INTERVAL '1 millisecond' * (templates.time_til_dormant / 1000000))
                    )
                    OR
                    -- Deletion: dormant and past deleting_at
                    (
                        workspaces.dormant_at IS NOT NULL
                        AND workspaces.deleting_at IS NOT NULL
                        AND workspaces.deleting_at < $1::timestamptz
                        AND templates.time_til_dormant_autodelete > 0
                        AND CASE
                            WHEN (
                                workspace_builds.transition = 'delete'::workspace_transition
                                AND provisioner_jobs.job_status = 'failed'::provisioner_job_status
                            ) THEN (
                                (
                                    provisioner_jobs.canceled_at IS NOT NULL
                                    OR provisioner_jobs.completed_at IS NOT NULL
                                ) AND (
                                    ($1::timestamptz) - (CASE
                                        WHEN provisioner_jobs.canceled_at IS NOT NULL THEN provisioner_jobs.canceled_at
                                        ELSE provisioner_jobs.completed_at
                                    END) > INTERVAL '24 hours'
                                )
                            )
                            ELSE true
                        END
                    )
                    OR
                    -- Failed stop: failure_ttl exceeded
                    (
                        templates.failure_ttl > 0
                        AND workspace_builds.transition = 'start'::workspace_transition
                        AND provisioner_jobs.job_status = 'failed'::provisioner_job_status
                        AND provisioner_jobs.completed_at IS NOT NULL
                        AND ($1::timestamptz) - provisioner_jobs.completed_at > (INTERVAL '1 millisecond' * (templates.failure_ttl / 1000000))
                    )
                )
                AND workspaces.deleted = false
                AND workspaces.owner_id != 'c42fdf75-3097-471c-8c33-fb52454d81c0'::UUID",
        )
        .bind(now)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(workspace_transition_row_from_stored)
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn create_group(&self, input: &CreateGroupInput) -> Result<GroupRecord, StorageError> {
        let row: (
            Uuid,
            String,
            String,
            Uuid,
            String,
            i32,
            String,
            OffsetDateTime,
        ) = sqlx::query_as(
            "INSERT INTO groups (name, display_name, organization_id, avatar_url, quota_allowance)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING id, name, display_name, organization_id, avatar_url,
                       quota_allowance, source, created_at",
        )
        .bind(&input.name)
        .bind(&input.display_name)
        .bind(input.organization_id)
        .bind(&input.avatar_url)
        .bind(input.quota_allowance)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                StorageError::invalid_data(
                    "group with this name already exists in the organization",
                )
            } else {
                storage_error(e)
            }
        })?;

        let (
            id,
            name,
            display_name,
            organization_id,
            avatar_url,
            quota_allowance,
            source,
            created_at,
        ) = row;
        Ok(GroupRecord {
            id,
            name,
            display_name,
            organization_id,
            avatar_url,
            quota_allowance,
            source,
            created_at,
        })
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_group(&self, group_id: Uuid) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM groups WHERE id = $1")
            .bind(group_id)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;
        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_groups(&self, organization_id: Uuid) -> Result<Vec<GroupRecord>, StorageError> {
        let rows: Vec<(
            Uuid,
            String,
            String,
            Uuid,
            String,
            i32,
            String,
            OffsetDateTime,
        )> = sqlx::query_as(
            "SELECT id, name, display_name, organization_id, avatar_url,
                    quota_allowance, source, created_at
             FROM groups
             WHERE organization_id = $1
             ORDER BY LOWER(name) ASC",
        )
        .bind(organization_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(
                |(
                    id,
                    name,
                    display_name,
                    organization_id,
                    avatar_url,
                    quota_allowance,
                    source,
                    created_at,
                )| {
                    GroupRecord {
                        id,
                        name,
                        display_name,
                        organization_id,
                        avatar_url,
                        quota_allowance,
                        source,
                        created_at,
                    }
                },
            )
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn insert_group_member(&self, group_id: Uuid, user_id: Uuid) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO group_members (group_id, user_id)
             VALUES ($1, $2)",
        )
        .bind(group_id)
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                StorageError::invalid_data("user is already a member of this group")
            } else {
                storage_error(e)
            }
        })?;
        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_group_members(
        &self,
        group_id: Uuid,
    ) -> Result<Vec<GroupMemberRecord>, StorageError> {
        let rows: Vec<(Uuid, Uuid)> = sqlx::query_as(
            "SELECT gm.group_id, gm.user_id
             FROM group_members gm
             JOIN users u ON u.id = gm.user_id
             WHERE gm.group_id = $1
               AND u.deleted = false
             ORDER BY LOWER(u.username) ASC",
        )
        .bind(group_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(|(group_id, user_id)| GroupMemberRecord { group_id, user_id })
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_group_member(
        &self,
        group_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM group_members WHERE group_id = $1 AND user_id = $2")
            .bind(group_id)
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;
        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_group_by_id(&self, group_id: Uuid) -> Result<Option<GroupRecord>, StorageError> {
        let row: Option<(
            Uuid,
            String,
            String,
            Uuid,
            String,
            i32,
            String,
            OffsetDateTime,
        )> = sqlx::query_as(
            "SELECT id, name, display_name, organization_id, avatar_url,
                        quota_allowance, source, created_at
                 FROM groups WHERE id = $1",
        )
        .bind(group_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(row.map(
            |(
                id,
                name,
                display_name,
                organization_id,
                avatar_url,
                quota_allowance,
                source,
                created_at,
            )| {
                GroupRecord {
                    id,
                    name,
                    display_name,
                    organization_id,
                    avatar_url,
                    quota_allowance,
                    source,
                    created_at,
                }
            },
        ))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_group_by_name(
        &self,
        organization_id: Uuid,
        name: &str,
    ) -> Result<Option<GroupRecord>, StorageError> {
        let row: Option<(
            Uuid,
            String,
            String,
            Uuid,
            String,
            i32,
            String,
            OffsetDateTime,
        )> = sqlx::query_as(
            "SELECT id, name, display_name, organization_id, avatar_url,
                    quota_allowance, source, created_at
             FROM groups
             WHERE organization_id = $1 AND LOWER(name) = LOWER($2)",
        )
        .bind(organization_id)
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(row.map(
            |(
                id,
                name,
                display_name,
                organization_id,
                avatar_url,
                quota_allowance,
                source,
                created_at,
            )| {
                GroupRecord {
                    id,
                    name,
                    display_name,
                    organization_id,
                    avatar_url,
                    quota_allowance,
                    source,
                    created_at,
                }
            },
        ))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_group(&self, input: &UpdateGroupInput) -> Result<GroupRecord, StorageError> {
        let row: (
            Uuid,
            String,
            String,
            Uuid,
            String,
            i32,
            String,
            OffsetDateTime,
        ) = sqlx::query_as(
            "UPDATE groups
             SET name = $2, display_name = $3, avatar_url = $4, quota_allowance = $5
             WHERE id = $1
             RETURNING id, name, display_name, organization_id, avatar_url,
                       quota_allowance, source, created_at",
        )
        .bind(input.id)
        .bind(&input.name)
        .bind(&input.display_name)
        .bind(&input.avatar_url)
        .bind(input.quota_allowance)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                StorageError::invalid_data(
                    "group with this name already exists in the organization",
                )
            } else {
                storage_error_or_not_found(e)
            }
        })?;

        let (
            id,
            name,
            display_name,
            organization_id,
            avatar_url,
            quota_allowance,
            source,
            created_at,
        ) = row;
        Ok(GroupRecord {
            id,
            name,
            display_name,
            organization_id,
            avatar_url,
            quota_allowance,
            source,
            created_at,
        })
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_all_groups(&self) -> Result<Vec<GroupRecord>, StorageError> {
        let rows: Vec<(
            Uuid,
            String,
            String,
            Uuid,
            String,
            i32,
            String,
            OffsetDateTime,
        )> = sqlx::query_as(
            "SELECT id, name, display_name, organization_id, avatar_url,
                    quota_allowance, source, created_at
             FROM groups
             ORDER BY LOWER(name) ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(
                |(
                    id,
                    name,
                    display_name,
                    organization_id,
                    avatar_url,
                    quota_allowance,
                    source,
                    created_at,
                )| {
                    GroupRecord {
                        id,
                        name,
                        display_name,
                        organization_id,
                        avatar_url,
                        quota_allowance,
                        source,
                        created_at,
                    }
                },
            )
            .collect())
    }

    // ----- OAuth2 Provider Apps -----

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_oauth2_provider_apps(
        &self,
    ) -> Result<Vec<OAuth2ProviderAppRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredOAuth2ProviderAppRow>(
            "SELECT id, created_at, updated_at, name, icon, callback_url, redirect_uris, created_by, registration_access_token
             FROM oauth2_provider_apps
             ORDER BY (name, id) ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows.into_iter().map(oauth2_provider_app_from_row).collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn create_oauth2_provider_app(
        &self,
        input: &CreateOAuth2ProviderAppInput,
    ) -> Result<OAuth2ProviderAppRecord, StorageError> {
        let row = sqlx::query_as::<_, StoredOAuth2ProviderAppRow>(
            "INSERT INTO oauth2_provider_apps (name, icon, callback_url, created_by)
             VALUES ($1, $2, $3, $4)
             RETURNING id, created_at, updated_at, name, icon, callback_url, redirect_uris, created_by, registration_access_token",
        )
        .bind(&input.name)
        .bind(&input.icon)
        .bind(&input.callback_url)
        .bind(input.created_by)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(oauth2_provider_app_from_row(row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_oauth2_provider_app_by_id(
        &self,
        app_id: Uuid,
    ) -> Result<Option<OAuth2ProviderAppRecord>, StorageError> {
        sqlx::query_as::<_, StoredOAuth2ProviderAppRow>(
            "SELECT id, created_at, updated_at, name, icon, callback_url, redirect_uris, created_by, registration_access_token
             FROM oauth2_provider_apps WHERE id = $1",
        )
        .bind(app_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(oauth2_provider_app_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_oauth2_provider_app(
        &self,
        input: &UpdateOAuth2ProviderAppInput,
    ) -> Result<Option<OAuth2ProviderAppRecord>, StorageError> {
        sqlx::query_as::<_, StoredOAuth2ProviderAppRow>(
            "UPDATE oauth2_provider_apps SET
                updated_at = NOW(),
                name = $2,
                icon = $3,
                callback_url = $4,
                redirect_uris = $5
             WHERE id = $1
             RETURNING id, created_at, updated_at, name, icon, callback_url, redirect_uris, created_by, registration_access_token",
        )
        .bind(input.id)
        .bind(&input.name)
        .bind(&input.icon)
        .bind(&input.callback_url)
        .bind(&input.redirect_uris)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(oauth2_provider_app_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_oauth2_provider_app(&self, app_id: Uuid) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM oauth2_provider_apps WHERE id = $1")
            .bind(app_id)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;
        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self, hash), err(level = tracing::Level::WARN))]
    async fn update_oauth2_provider_app_registration_token(
        &self,
        app_id: Uuid,
        hash: &[u8],
    ) -> Result<(), StorageError> {
        sqlx::query("UPDATE oauth2_provider_apps SET registration_access_token = $2 WHERE id = $1")
            .bind(app_id)
            .bind(hash)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;
        Ok(())
    }

    // ----- OAuth2 Provider App Secrets -----

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_oauth2_provider_app_secrets(
        &self,
        app_id: Uuid,
    ) -> Result<Vec<OAuth2ProviderAppSecretRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredOAuth2ProviderAppSecretRow>(
            "SELECT id, created_at, last_used_at, secret_prefix, hashed_secret, display_secret, app_id
             FROM oauth2_provider_app_secrets
             WHERE app_id = $1
             ORDER BY (created_at, id) ASC",
        )
        .bind(app_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(oauth2_provider_app_secret_from_row)
            .collect())
    }

    #[instrument(skip(self, secret_prefix, hashed_secret), err(level = tracing::Level::WARN))]
    async fn create_oauth2_provider_app_secret(
        &self,
        app_id: Uuid,
        secret_prefix: &[u8],
        hashed_secret: &[u8],
        display_secret: &str,
    ) -> Result<OAuth2ProviderAppSecretRecord, StorageError> {
        let row = sqlx::query_as::<_, StoredOAuth2ProviderAppSecretRow>(
            "INSERT INTO oauth2_provider_app_secrets (secret_prefix, hashed_secret, display_secret, app_id)
             VALUES ($1, $2, $3, $4)
             RETURNING id, created_at, last_used_at, secret_prefix, hashed_secret, display_secret, app_id",
        )
        .bind(secret_prefix)
        .bind(hashed_secret)
        .bind(display_secret)
        .bind(app_id)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(oauth2_provider_app_secret_from_row(row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_oauth2_provider_app_secret_by_id(
        &self,
        secret_id: Uuid,
    ) -> Result<Option<OAuth2ProviderAppSecretRecord>, StorageError> {
        sqlx::query_as::<_, StoredOAuth2ProviderAppSecretRow>(
            "SELECT id, created_at, last_used_at, secret_prefix, hashed_secret, display_secret, app_id
             FROM oauth2_provider_app_secrets WHERE id = $1",
        )
        .bind(secret_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(oauth2_provider_app_secret_from_row))
    }

    #[instrument(skip(self, secret_prefix), err(level = tracing::Level::WARN))]
    async fn find_oauth2_provider_app_secret_by_prefix(
        &self,
        secret_prefix: &[u8],
    ) -> Result<Option<OAuth2ProviderAppSecretRecord>, StorageError> {
        sqlx::query_as::<_, StoredOAuth2ProviderAppSecretRow>(
            "SELECT id, created_at, last_used_at, secret_prefix, hashed_secret, display_secret, app_id
             FROM oauth2_provider_app_secrets WHERE secret_prefix = $1",
        )
        .bind(secret_prefix)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(oauth2_provider_app_secret_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_oauth2_provider_app_secret_last_used(
        &self,
        secret_id: Uuid,
    ) -> Result<Option<OAuth2ProviderAppSecretRecord>, StorageError> {
        sqlx::query_as::<_, StoredOAuth2ProviderAppSecretRow>(
            "UPDATE oauth2_provider_app_secrets SET last_used_at = NOW()
             WHERE id = $1
             RETURNING id, created_at, last_used_at, secret_prefix, hashed_secret, display_secret, app_id",
        )
        .bind(secret_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(oauth2_provider_app_secret_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_oauth2_provider_app_secret(
        &self,
        secret_id: Uuid,
    ) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM oauth2_provider_app_secrets WHERE id = $1")
            .bind(secret_id)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;
        Ok(result.rows_affected() > 0)
    }

    // ----- OAuth2 Provider App Codes -----

    #[instrument(skip(self, secret_prefix, hashed_secret), err(level = tracing::Level::WARN))]
    async fn create_oauth2_provider_app_code(
        &self,
        app_id: Uuid,
        user_id: Uuid,
        secret_prefix: &[u8],
        hashed_secret: &[u8],
        expires_at: OffsetDateTime,
        resource_uri: &str,
        code_challenge: &str,
        code_challenge_method: &str,
        state_hash: Option<&str>,
        redirect_uri: Option<&str>,
    ) -> Result<OAuth2ProviderAppCodeRecord, StorageError> {
        let row = sqlx::query_as::<_, StoredOAuth2ProviderAppCodeRow>(
            "INSERT INTO oauth2_provider_app_codes
                (expires_at, secret_prefix, hashed_secret, app_id, user_id,
                 resource_uri, code_challenge, code_challenge_method, state_hash, redirect_uri)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             RETURNING id, created_at, expires_at, secret_prefix, hashed_secret,
                       app_id, user_id, resource_uri, code_challenge, code_challenge_method,
                       state_hash, redirect_uri",
        )
        .bind(expires_at)
        .bind(secret_prefix)
        .bind(hashed_secret)
        .bind(app_id)
        .bind(user_id)
        .bind(resource_uri)
        .bind(code_challenge)
        .bind(code_challenge_method)
        .bind(state_hash)
        .bind(redirect_uri)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(oauth2_provider_app_code_from_row(row))
    }

    #[instrument(skip(self, secret_prefix), err(level = tracing::Level::WARN))]
    async fn find_oauth2_provider_app_code_by_prefix(
        &self,
        secret_prefix: &[u8],
    ) -> Result<Option<OAuth2ProviderAppCodeRecord>, StorageError> {
        sqlx::query_as::<_, StoredOAuth2ProviderAppCodeRow>(
            "SELECT id, created_at, expires_at, secret_prefix, hashed_secret,
                    app_id, user_id, resource_uri, code_challenge, code_challenge_method,
                    state_hash, redirect_uri
             FROM oauth2_provider_app_codes WHERE secret_prefix = $1",
        )
        .bind(secret_prefix)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(oauth2_provider_app_code_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_oauth2_provider_app_code_by_id(
        &self,
        code_id: Uuid,
    ) -> Result<Option<OAuth2ProviderAppCodeRecord>, StorageError> {
        sqlx::query_as::<_, StoredOAuth2ProviderAppCodeRow>(
            "SELECT id, created_at, expires_at, secret_prefix, hashed_secret,
                    app_id, user_id, resource_uri, code_challenge, code_challenge_method,
                    state_hash, redirect_uri
             FROM oauth2_provider_app_codes WHERE id = $1",
        )
        .bind(code_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(oauth2_provider_app_code_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_oauth2_provider_app_code(&self, code_id: Uuid) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM oauth2_provider_app_codes WHERE id = $1")
            .bind(code_id)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;
        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_oauth2_provider_app_codes_by_app_and_user(
        &self,
        app_id: Uuid,
        user_id: Uuid,
    ) -> Result<u64, StorageError> {
        let result =
            sqlx::query("DELETE FROM oauth2_provider_app_codes WHERE app_id = $1 AND user_id = $2")
                .bind(app_id)
                .bind(user_id)
                .execute(&self.pool)
                .await
                .map_err(storage_error)?;
        Ok(result.rows_affected())
    }

    // ----- OAuth2 Provider App Tokens -----

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn create_oauth2_provider_app_token(
        &self,
        input: &CreateOAuth2ProviderAppTokenInput,
    ) -> Result<OAuth2ProviderAppTokenRecord, StorageError> {
        let row = sqlx::query_as::<_, StoredOAuth2ProviderAppTokenRow>(
            "INSERT INTO oauth2_provider_app_tokens
                (expires_at, hash_prefix, refresh_hash, app_secret_id, api_key_id, user_id, audience)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             RETURNING id, created_at, expires_at, hash_prefix, refresh_hash,
                       app_secret_id, api_key_id, audience, user_id",
        )
        .bind(input.expires_at)
        .bind(&input.hash_prefix)
        .bind(&input.refresh_hash)
        .bind(input.app_secret_id)
        .bind(&input.api_key_id)
        .bind(input.user_id)
        .bind(&input.audience)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(oauth2_provider_app_token_from_row(row))
    }

    #[instrument(skip(self, hash_prefix), err(level = tracing::Level::WARN))]
    async fn find_oauth2_provider_app_token_by_prefix(
        &self,
        hash_prefix: &[u8],
    ) -> Result<Option<OAuth2ProviderAppTokenRecord>, StorageError> {
        sqlx::query_as::<_, StoredOAuth2ProviderAppTokenRow>(
            "SELECT id, created_at, expires_at, hash_prefix, refresh_hash,
                    app_secret_id, api_key_id, audience, user_id
             FROM oauth2_provider_app_tokens WHERE hash_prefix = $1",
        )
        .bind(hash_prefix)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(oauth2_provider_app_token_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_oauth2_provider_app_token_by_api_key_id(
        &self,
        api_key_id: &str,
    ) -> Result<Option<OAuth2ProviderAppTokenRecord>, StorageError> {
        sqlx::query_as::<_, StoredOAuth2ProviderAppTokenRow>(
            "SELECT id, created_at, expires_at, hash_prefix, refresh_hash,
                    app_secret_id, api_key_id, audience, user_id
             FROM oauth2_provider_app_tokens WHERE api_key_id = $1",
        )
        .bind(api_key_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(oauth2_provider_app_token_from_row))
    }

    #[instrument(skip(self, refresh_hash), err(level = tracing::Level::WARN))]
    async fn find_oauth2_provider_app_token_by_refresh_hash(
        &self,
        refresh_hash: &[u8],
    ) -> Result<Option<OAuth2ProviderAppTokenRecord>, StorageError> {
        sqlx::query_as::<_, StoredOAuth2ProviderAppTokenRow>(
            "SELECT id, created_at, expires_at, hash_prefix, refresh_hash,
                    app_secret_id, api_key_id, audience, user_id
             FROM oauth2_provider_app_tokens WHERE refresh_hash = $1",
        )
        .bind(refresh_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(oauth2_provider_app_token_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_oauth2_provider_app_token(&self, token_id: Uuid) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM oauth2_provider_app_tokens WHERE id = $1")
            .bind(token_id)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;
        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_oauth2_provider_app_tokens_by_app_and_user(
        &self,
        app_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<OAuth2ProviderAppTokenRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredOAuth2ProviderAppTokenRow>(
            "SELECT t.id, t.created_at, t.expires_at, t.hash_prefix, t.refresh_hash,
                    t.app_secret_id, t.api_key_id, t.audience, t.user_id
             FROM oauth2_provider_app_tokens t
             INNER JOIN oauth2_provider_app_secrets s ON s.id = t.app_secret_id
             WHERE s.app_id = $1 AND t.user_id = $2",
        )
        .bind(app_id)
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(oauth2_provider_app_token_from_row)
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_oauth2_provider_app_tokens_by_app_and_user(
        &self,
        app_id: Uuid,
        user_id: Uuid,
    ) -> Result<u64, StorageError> {
        let result = sqlx::query(
            "DELETE FROM oauth2_provider_app_tokens
             USING oauth2_provider_app_secrets
             WHERE oauth2_provider_app_secrets.id = oauth2_provider_app_tokens.app_secret_id
               AND oauth2_provider_app_secrets.app_id = $1
               AND oauth2_provider_app_tokens.user_id = $2",
        )
        .bind(app_id)
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(result.rows_affected())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_workspace_acl(
        &self,
        workspace_id: Uuid,
    ) -> Result<WorkspaceACLRecord, StorageError> {
        let row: Option<(Value, Value)> =
            sqlx::query_as("SELECT group_acl, user_acl FROM workspaces WHERE id = $1")
                .bind(workspace_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_error)?;

        match row {
            Some((group_acl_val, user_acl_val)) => {
                let group_acl: HashMap<String, String> =
                    serde_json::from_value(group_acl_val).unwrap_or_default();
                let user_acl: HashMap<String, String> =
                    serde_json::from_value(user_acl_val).unwrap_or_default();
                Ok(WorkspaceACLRecord {
                    group_acl,
                    user_acl,
                })
            }
            None => Ok(WorkspaceACLRecord::default()),
        }
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_workspace_acl(
        &self,
        workspace_id: Uuid,
        input: &UpdateWorkspaceACLInput,
    ) -> Result<(), StorageError> {
        let user_acl_json =
            serde_json::to_value(&input.user_roles).map_err(|e| StorageError::InvalidData {
                message: format!("failed to serialize user_roles: {e}"),
            })?;
        let group_acl_json =
            serde_json::to_value(&input.group_roles).map_err(|e| StorageError::InvalidData {
                message: format!("failed to serialize group_roles: {e}"),
            })?;
        sqlx::query(
            "UPDATE workspaces SET user_acl = user_acl || $2, group_acl = group_acl || $3
             WHERE id = $1",
        )
        .bind(workspace_id)
        .bind(user_acl_json)
        .bind(group_acl_json)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_workspace_acl(&self, workspace_id: Uuid) -> Result<(), StorageError> {
        sqlx::query(
            "UPDATE workspaces SET group_acl = '{}'::jsonb, user_acl = '{}'::jsonb
             WHERE id = $1",
        )
        .bind(workspace_id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_workspace_builds(
        &self,
        workspace_id: Uuid,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<WorkspaceBuildRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredWorkspaceBuildRow>(
            "SELECT id, created_at, updated_at, workspace_id, build_number, transition,
                    job_id, template_version_id, initiator_id, provisioner_state,
                    deadline, max_deadline, reason, daily_cost
             FROM workspace_builds
             WHERE workspace_id = $1
             ORDER BY build_number DESC
             LIMIT $2 OFFSET $3",
        )
        .bind(workspace_id)
        .bind(i64::from(limit.min(1000)))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(rows
            .into_iter()
            .map(workspace_build_record_from_row)
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_latest_workspace_build(
        &self,
        workspace_id: Uuid,
    ) -> Result<Option<WorkspaceBuildRecord>, StorageError> {
        sqlx::query_as::<_, StoredWorkspaceBuildRow>(
            "SELECT id, created_at, updated_at, workspace_id, build_number, transition,
                    job_id, template_version_id, initiator_id, provisioner_state,
                    deadline, max_deadline, reason, daily_cost
             FROM workspace_builds
             WHERE workspace_id = $1
             ORDER BY build_number DESC
             LIMIT 1",
        )
        .bind(workspace_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(workspace_build_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_workspace_build_by_id(
        &self,
        build_id: Uuid,
    ) -> Result<Option<WorkspaceBuildRecord>, StorageError> {
        sqlx::query_as::<_, StoredWorkspaceBuildRow>(
            "SELECT id, created_at, updated_at, workspace_id, build_number, transition,
                    job_id, template_version_id, initiator_id, provisioner_state,
                    deadline, max_deadline, reason, daily_cost
             FROM workspace_builds
             WHERE id = $1",
        )
        .bind(build_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(workspace_build_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_workspace_build_by_number(
        &self,
        workspace_id: Uuid,
        build_number: i64,
    ) -> Result<Option<WorkspaceBuildRecord>, StorageError> {
        sqlx::query_as::<_, StoredWorkspaceBuildRow>(
            "SELECT id, created_at, updated_at, workspace_id, build_number, transition,
                    job_id, template_version_id, initiator_id, provisioner_state,
                    deadline, max_deadline, reason, daily_cost
             FROM workspace_builds
             WHERE workspace_id = $1 AND build_number = $2",
        )
        .bind(workspace_id)
        .bind(build_number)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(workspace_build_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn insert_workspace_build(
        &self,
        input: CreateWorkspaceBuildInput,
    ) -> Result<WorkspaceBuildRecord, StorageError> {
        sqlx::query_as::<_, StoredWorkspaceBuildRow>(
            "INSERT INTO workspace_builds (
                id, workspace_id, template_version_id, build_number, transition,
                initiator_id, job_id, reason, deadline, max_deadline,
                created_at, updated_at
             )
             VALUES ($1, $2, $3,
                     (SELECT COALESCE(MAX(build_number), 0) + 1 FROM workspace_builds WHERE workspace_id = $2),
                     $4, $5, $6, $7, $8, $9, NOW(), NOW())
             RETURNING id, created_at, updated_at, workspace_id, build_number, transition,
                       job_id, template_version_id, initiator_id, provisioner_state,
                       deadline, max_deadline, reason, daily_cost",
        )
        .bind(input.id)
        .bind(input.workspace_id)
        .bind(input.template_version_id)
        .bind(&input.transition)
        .bind(input.initiator_id)
        .bind(input.job_id)
        .bind(&input.reason)
        .bind(input.deadline)
        .bind(input.max_deadline)
        .fetch_one(&self.pool)
        .await
        .map(workspace_build_record_from_row)
        .map_err(storage_error)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_workspace_build_deadline(
        &self,
        build_id: Uuid,
        deadline: Option<OffsetDateTime>,
        max_deadline: Option<OffsetDateTime>,
    ) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "UPDATE workspace_builds
             SET deadline = $2, max_deadline = $3, updated_at = NOW()
             WHERE id = $1",
        )
        .bind(build_id)
        .bind(deadline)
        .bind(max_deadline)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self, state), err(level = tracing::Level::WARN))]
    async fn update_workspace_build_provisioner_state(
        &self,
        build_id: Uuid,
        state: &[u8],
    ) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "UPDATE workspace_builds
             SET provisioner_state = $2, updated_at = NOW()
             WHERE id = $1",
        )
        .bind(build_id)
        .bind(state)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn next_workspace_build_number(&self, workspace_id: Uuid) -> Result<i64, StorageError> {
        let max: Option<i64> = sqlx::query_scalar(
            "SELECT MAX(build_number) FROM workspace_builds WHERE workspace_id = $1",
        )
        .bind(workspace_id)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(max.unwrap_or(0) + 1) // sqlx query_scalar returns Option for MAX
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_workspace_build_parameters(
        &self,
        build_id: Uuid,
    ) -> Result<Vec<WorkspaceBuildParameterRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredWorkspaceBuildParameterRow>(
            "SELECT workspace_build_id, name, value
             FROM workspace_build_parameters
             WHERE workspace_build_id = $1
             ORDER BY name",
        )
        .bind(build_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(rows
            .into_iter()
            .map(|row| WorkspaceBuildParameterRecord {
                workspace_build_id: row.workspace_build_id,
                name: row.name,
                value: row.value,
            })
            .collect())
    }

    #[instrument(skip(self, params), err(level = tracing::Level::WARN))]
    async fn insert_workspace_build_parameters(
        &self,
        build_id: Uuid,
        params: &[(String, String)],
    ) -> Result<(), StorageError> {
        let mut tx = self.pool.begin().await.map_err(storage_error)?;
        for (name, value) in params {
            sqlx::query(
                "INSERT INTO workspace_build_parameters (workspace_build_id, name, value)
                 VALUES ($1, $2, $3)",
            )
            .bind(build_id)
            .bind(name)
            .bind(value)
            .execute(&mut *tx)
            .await
            .map_err(storage_error)?;
        }
        tx.commit().await.map_err(storage_error)?;
        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_provisioner_job_logs(
        &self,
        job_id: Uuid,
        after: Option<i64>,
    ) -> Result<Vec<ProvisionerJobLogRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredProvisionerJobLogRow>(
            "SELECT id, job_id, created_at, source, level, stage, output
             FROM provisioner_job_logs
             WHERE job_id = $1 AND ($2::bigint IS NULL OR id > $2)
             ORDER BY id ASC",
        )
        .bind(job_id)
        .bind(after)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(rows
            .into_iter()
            .map(provisioner_job_log_record_from_row)
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_provisioner_job_timings(
        &self,
        job_id: Uuid,
    ) -> Result<Vec<ProvisionerJobTimingRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredProvisionerJobTimingRow>(
            "SELECT job_id, started_at, ended_at, stage, source, action, resource
             FROM provisioner_job_timings
             WHERE job_id = $1
             ORDER BY started_at ASC",
        )
        .bind(job_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(rows
            .into_iter()
            .map(provisioner_job_timing_record_from_row)
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_workspace_agent_script_timings_by_build_id(
        &self,
        build_id: Uuid,
    ) -> Result<Vec<WorkspaceAgentScriptTimingRow>, StorageError> {
        #[derive(sqlx::FromRow)]
        struct Row {
            script_id: Uuid,
            started_at: OffsetDateTime,
            ended_at: OffsetDateTime,
            exit_code: i32,
            stage: String,
            status: String,
            display_name: String,
            workspace_agent_id: Uuid,
            workspace_agent_name: String,
        }

        let rows = sqlx::query_as::<_, Row>(
            "SELECT
                DISTINCT ON (wast.script_id) wast.script_id,
                wast.started_at,
                wast.ended_at,
                wast.exit_code,
                wast.stage::text AS stage,
                wast.status::text AS status,
                was2.display_name,
                wa.id AS workspace_agent_id,
                wa.name AS workspace_agent_name
             FROM workspace_agent_script_timings wast
             INNER JOIN workspace_agent_scripts was2 ON was2.id = wast.script_id
             INNER JOIN workspace_agents wa ON wa.id = was2.workspace_agent_id
             INNER JOIN workspace_resources wr ON wr.id = wa.resource_id
             INNER JOIN workspace_builds wb ON wb.job_id = wr.job_id
             WHERE wb.id = $1
             ORDER BY wast.script_id, wast.started_at",
        )
        .bind(build_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(|r| WorkspaceAgentScriptTimingRow {
                script_id: r.script_id,
                started_at: r.started_at,
                ended_at: r.ended_at,
                exit_code: r.exit_code,
                stage: r.stage,
                status: r.status,
                display_name: r.display_name,
                workspace_agent_id: r.workspace_agent_id,
                workspace_agent_name: r.workspace_agent_name,
            })
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_workspace_resource_by_id(
        &self,
        resource_id: Uuid,
    ) -> Result<Option<WorkspaceResourceRecord>, StorageError> {
        let row = sqlx::query_as::<_, StoredWorkspaceResourceRow>(
            "SELECT id, created_at, job_id, transition, type AS resource_type,
                    name, hide, icon, daily_cost
             FROM workspace_resources
             WHERE id = $1",
        )
        .bind(resource_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(row.map(workspace_resource_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_workspace_resources_by_job(
        &self,
        job_id: Uuid,
    ) -> Result<Vec<WorkspaceResourceRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredWorkspaceResourceRow>(
            "SELECT id, created_at, job_id, transition, type AS resource_type,
                    name, hide, icon, daily_cost
             FROM workspace_resources
             WHERE job_id = $1
             ORDER BY name ASC",
        )
        .bind(job_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(rows
            .into_iter()
            .map(workspace_resource_record_from_row)
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_workspace_resource_metadata(
        &self,
        resource_ids: &[Uuid],
    ) -> Result<Vec<WorkspaceResourceMetadataRecord>, StorageError> {
        if resource_ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows = sqlx::query_as::<_, StoredWorkspaceResourceMetadataRow>(
            "SELECT workspace_resource_id, key, value, sensitive
             FROM workspace_resource_metadata
             WHERE workspace_resource_id = ANY($1)
             ORDER BY workspace_resource_id, key",
        )
        .bind(resource_ids)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(rows
            .into_iter()
            .map(|row| WorkspaceResourceMetadataRecord {
                workspace_resource_id: row.workspace_resource_id,
                key: row.key,
                value: row.value,
                sensitive: row.sensitive,
            })
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_workspace_port_shares(
        &self,
        workspace_id: Uuid,
    ) -> Result<Vec<WorkspaceAgentPortShareRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredPortShareRow>(
            "SELECT workspace_id, agent_name, port, share_level, protocol
             FROM workspace_agent_port_shares
             WHERE workspace_id = $1
             ORDER BY agent_name, port",
        )
        .bind(workspace_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(rows.into_iter().map(port_share_record_from_row).collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn upsert_workspace_port_share(
        &self,
        input: UpsertPortShareInput,
    ) -> Result<WorkspaceAgentPortShareRecord, StorageError> {
        sqlx::query_as::<_, StoredPortShareRow>(
            "INSERT INTO workspace_agent_port_shares (
                workspace_id, agent_name, port, share_level, protocol
             )
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (workspace_id, agent_name, port) DO UPDATE
             SET share_level = EXCLUDED.share_level,
                 protocol = EXCLUDED.protocol
             RETURNING workspace_id, agent_name, port, share_level, protocol",
        )
        .bind(input.workspace_id)
        .bind(&input.agent_name)
        .bind(input.port)
        .bind(&input.share_level)
        .bind(&input.protocol)
        .fetch_one(&self.pool)
        .await
        .map(port_share_record_from_row)
        .map_err(storage_error)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_workspace_port_share(
        &self,
        workspace_id: Uuid,
        agent_name: &str,
        port: i32,
    ) -> Result<Option<WorkspaceAgentPortShareRecord>, StorageError> {
        sqlx::query_as::<_, StoredPortShareRow>(
            "SELECT workspace_id, agent_name, port, share_level, protocol
             FROM workspace_agent_port_shares
             WHERE workspace_id = $1 AND agent_name = $2 AND port = $3",
        )
        .bind(workspace_id)
        .bind(agent_name)
        .bind(port)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
        .map(|opt| opt.map(port_share_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_workspace_port_share(
        &self,
        workspace_id: Uuid,
        agent_name: &str,
        port: i32,
    ) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "DELETE FROM workspace_agent_port_shares
             WHERE workspace_id = $1 AND agent_name = $2 AND port = $3",
        )
        .bind(workspace_id)
        .bind(agent_name)
        .bind(port)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(result.rows_affected() > 0)
    }

    // ----- Template Store Methods -----

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_templates(
        &self,
        filter: TemplateListFilter,
    ) -> Result<Vec<TemplateRecord>, StorageError> {
        // Escape LIKE metacharacters so user input is treated literally.
        let escaped_search = filter.search.as_deref().map(escape_like);
        let rows = sqlx::query_as::<_, StoredTemplateRow>(
            r#"
            SELECT t.id, t.created_at, t.updated_at, t.organization_id, t.deleted,
                   t.name, t.provisioner::text AS provisioner, t.active_version_id,
                   t.description, t.default_ttl, t.created_by, t.icon, t.user_acl,
                   t.group_acl, t.display_name, t.allow_user_cancel_workspace_jobs,
                   t.allow_user_autostart, t.allow_user_autostop, t.failure_ttl,
                   t.time_til_dormant, t.time_til_dormant_autodelete,
                   t.autostop_requirement_days_of_week, t.autostop_requirement_weeks,
                   t.autostart_block_days_of_week, t.require_active_version,
                   t.deprecated, t.activity_bump,
                   t.max_port_sharing_level::text AS max_port_sharing_level,
                   t.use_classic_parameter_flow,
                   t.cors_behavior::text AS cors_behavior,
                   t.disable_module_cache,
                   COALESCE(o.name, '') AS organization_name,
                   COALESCE(o.display_name, '') AS organization_display_name,
                   COALESCE(o.icon, '') AS organization_icon,
                   COALESCE(u.username, '') AS created_by_username,
                   COALESCE(u.avatar_url, '') AS created_by_avatar_url,
                   COALESCE(u.name, '') AS created_by_name
            FROM templates t
            LEFT JOIN organizations o ON o.id = t.organization_id
            LEFT JOIN users u ON u.id = t.created_by
            WHERE ($1::uuid IS NULL OR t.organization_id = $1)
              AND ($2::text IS NULL OR t.name = $2)
              AND ($3::bool OR t.deleted = false)
              AND ($4::text IS NULL OR t.name ILIKE '%' || $4 || '%' OR t.display_name ILIKE '%' || $4 || '%')
            ORDER BY t.name ASC
            "#,
        )
        .bind(filter.organization_id)
        .bind(filter.exact_name.as_deref())
        .bind(filter.deleted)
        .bind(escaped_search.as_deref())
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(rows.into_iter().map(template_record_from_row).collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_template_by_id(
        &self,
        template_id: Uuid,
    ) -> Result<Option<TemplateRecord>, StorageError> {
        let row = sqlx::query_as::<_, StoredTemplateRow>(
            r#"
            SELECT t.id, t.created_at, t.updated_at, t.organization_id, t.deleted,
                   t.name, t.provisioner::text AS provisioner, t.active_version_id,
                   t.description, t.default_ttl, t.created_by, t.icon, t.user_acl,
                   t.group_acl, t.display_name, t.allow_user_cancel_workspace_jobs,
                   t.allow_user_autostart, t.allow_user_autostop, t.failure_ttl,
                   t.time_til_dormant, t.time_til_dormant_autodelete,
                   t.autostop_requirement_days_of_week, t.autostop_requirement_weeks,
                   t.autostart_block_days_of_week, t.require_active_version,
                   t.deprecated, t.activity_bump,
                   t.max_port_sharing_level::text AS max_port_sharing_level,
                   t.use_classic_parameter_flow,
                   t.cors_behavior::text AS cors_behavior,
                   t.disable_module_cache,
                   COALESCE(o.name, '') AS organization_name,
                   COALESCE(o.display_name, '') AS organization_display_name,
                   COALESCE(o.icon, '') AS organization_icon,
                   COALESCE(u.username, '') AS created_by_username,
                   COALESCE(u.avatar_url, '') AS created_by_avatar_url,
                   COALESCE(u.name, '') AS created_by_name
            FROM templates t
            LEFT JOIN organizations o ON o.id = t.organization_id
            LEFT JOIN users u ON u.id = t.created_by
            WHERE t.id = $1
            "#,
        )
        .bind(template_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(row.map(template_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_template_by_org_and_name(
        &self,
        organization_id: Uuid,
        name: &str,
    ) -> Result<Option<TemplateRecord>, StorageError> {
        let row = sqlx::query_as::<_, StoredTemplateRow>(
            r#"
            SELECT t.id, t.created_at, t.updated_at, t.organization_id, t.deleted,
                   t.name, t.provisioner::text AS provisioner, t.active_version_id,
                   t.description, t.default_ttl, t.created_by, t.icon, t.user_acl,
                   t.group_acl, t.display_name, t.allow_user_cancel_workspace_jobs,
                   t.allow_user_autostart, t.allow_user_autostop, t.failure_ttl,
                   t.time_til_dormant, t.time_til_dormant_autodelete,
                   t.autostop_requirement_days_of_week, t.autostop_requirement_weeks,
                   t.autostart_block_days_of_week, t.require_active_version,
                   t.deprecated, t.activity_bump,
                   t.max_port_sharing_level::text AS max_port_sharing_level,
                   t.use_classic_parameter_flow,
                   t.cors_behavior::text AS cors_behavior,
                   t.disable_module_cache,
                   COALESCE(o.name, '') AS organization_name,
                   COALESCE(o.display_name, '') AS organization_display_name,
                   COALESCE(o.icon, '') AS organization_icon,
                   COALESCE(u.username, '') AS created_by_username,
                   COALESCE(u.avatar_url, '') AS created_by_avatar_url,
                   COALESCE(u.name, '') AS created_by_name
            FROM templates t
            LEFT JOIN organizations o ON o.id = t.organization_id
            LEFT JOIN users u ON u.id = t.created_by
            WHERE t.organization_id = $1 AND t.name = $2 AND t.deleted = false
            "#,
        )
        .bind(organization_id)
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(row.map(template_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn insert_template(
        &self,
        input: CreateTemplateInput,
    ) -> Result<TemplateRecord, CreateTemplateStoreError> {
        let result = sqlx::query(
            r#"
            INSERT INTO templates (
                id, created_at, updated_at, organization_id, name, display_name,
                provisioner, active_version_id, description, default_ttl,
                created_by, icon, allow_user_cancel_workspace_jobs,
                allow_user_autostart, allow_user_autostop,
                failure_ttl, time_til_dormant, time_til_dormant_autodelete,
                require_active_version, activity_bump, max_port_sharing_level
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7::provisioner_type, $8, $9, $10, $11, $12, $13, $14, $15,
                $16, $17, $18, $19, $20, $21::app_sharing_level
            )
            "#,
        )
        .bind(input.id)
        .bind(input.created_at)
        .bind(input.updated_at)
        .bind(input.organization_id)
        .bind(&input.name)
        .bind(&input.display_name)
        .bind(&input.provisioner)
        .bind(input.active_version_id)
        .bind(&input.description)
        .bind(input.default_ttl)
        .bind(input.created_by)
        .bind(&input.icon)
        .bind(input.allow_user_cancel_workspace_jobs)
        .bind(input.allow_user_autostart)
        .bind(input.allow_user_autostop)
        .bind(input.failure_ttl)
        .bind(input.time_til_dormant)
        .bind(input.time_til_dormant_autodelete)
        .bind(input.require_active_version)
        .bind(input.activity_bump)
        .bind(&input.max_port_share_level)
        .execute(&self.pool)
        .await;

        match result {
            Ok(_) => {}
            Err(e) if is_unique_violation(&e) => {
                return Err(CreateTemplateStoreError::AlreadyExists);
            }
            Err(e) => return Err(CreateTemplateStoreError::Storage(storage_error(e))),
        }

        self.find_template_by_id(input.id)
            .await
            .map_err(CreateTemplateStoreError::Storage)?
            .ok_or_else(|| {
                CreateTemplateStoreError::Storage(StorageError::unavailable(
                    "template not found after insert",
                ))
            })
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_template_meta(
        &self,
        input: UpdateTemplateMetaInput,
    ) -> Result<Option<TemplateRecord>, StorageError> {
        let result = sqlx::query(
            r#"
            UPDATE templates SET
                name = $2,
                display_name = $3,
                description = $4,
                icon = $5,
                default_ttl = $6,
                activity_bump = $7,
                allow_user_autostart = $8,
                allow_user_autostop = $9,
                allow_user_cancel_workspace_jobs = $10,
                failure_ttl = $11,
                time_til_dormant = $12,
                time_til_dormant_autodelete = $13,
                require_active_version = $14,
                deprecated = $15,
                max_port_sharing_level = $16::app_sharing_level,
                cors_behavior = $17::cors_behavior,
                use_classic_parameter_flow = $18,
                disable_module_cache = $19,
                updated_at = NOW()
            WHERE id = $1 AND deleted = false
            "#,
        )
        .bind(input.template_id)
        .bind(&input.name)
        .bind(&input.display_name)
        .bind(&input.description)
        .bind(&input.icon)
        .bind(input.default_ttl)
        .bind(input.activity_bump)
        .bind(input.allow_user_autostart)
        .bind(input.allow_user_autostop)
        .bind(input.allow_user_cancel_workspace_jobs)
        .bind(input.failure_ttl)
        .bind(input.time_til_dormant)
        .bind(input.time_til_dormant_autodelete)
        .bind(input.require_active_version)
        .bind(&input.deprecation_message)
        .bind(&input.max_port_share_level)
        .bind(&input.cors_behavior)
        .bind(input.use_classic_parameter_flow)
        .bind(input.disable_module_cache)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        if result.rows_affected() == 0 {
            return Ok(None);
        }
        self.find_template_by_id(input.template_id).await
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn soft_delete_template(&self, template_id: Uuid) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "UPDATE templates SET deleted = true, updated_at = NOW() WHERE id = $1 AND deleted = false",
        )
        .bind(template_id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_template_active_version(
        &self,
        template_id: Uuid,
        active_version_id: Uuid,
    ) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "UPDATE templates SET active_version_id = $2, updated_at = NOW() WHERE id = $1",
        )
        .bind(template_id)
        .bind(active_version_id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn template_daus(&self, template_id: Uuid) -> Result<Vec<TemplateDAURow>, StorageError> {
        let rows = sqlx::query_as::<_, StoredDAURow>(
            r#"
            SELECT TO_CHAR(start_time::date, 'YYYY-MM-DD') AS date,
                   CAST(COUNT(DISTINCT user_id) AS INT) AS amount
            FROM template_usage_stats
            WHERE template_id = $1
            GROUP BY start_time::date
            ORDER BY start_time::date ASC
            "#,
        )
        .bind(template_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(rows
            .into_iter()
            .map(|r| TemplateDAURow {
                date: r.date,
                amount: r.amount,
            })
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_template_versions(
        &self,
        filter: TemplateVersionListFilter,
    ) -> Result<Vec<TemplateVersionRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredTemplateVersionRow>(
            r#"
            SELECT tv.*,
                   COALESCE(u.avatar_url, '') AS created_by_avatar_url,
                   COALESCE(u.username, '') AS created_by_username,
                   COALESCE(u.name, '') AS created_by_name
            FROM template_versions tv
            LEFT JOIN users u ON u.id = tv.created_by
            WHERE tv.template_id = $1
              AND ($2::bool OR tv.archived = false)
            ORDER BY tv.created_at DESC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(filter.template_id)
        .bind(filter.include_archived)
        .bind(if filter.limit == 0 {
            i64::MAX
        } else {
            i64::from(filter.limit)
        })
        .bind(i64::from(filter.offset))
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(rows
            .into_iter()
            .map(template_version_record_from_row)
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_template_version_by_id(
        &self,
        version_id: Uuid,
    ) -> Result<Option<TemplateVersionRecord>, StorageError> {
        let row = sqlx::query_as::<_, StoredTemplateVersionRow>(
            r#"
            SELECT tv.*,
                   COALESCE(u.avatar_url, '') AS created_by_avatar_url,
                   COALESCE(u.username, '') AS created_by_username,
                   COALESCE(u.name, '') AS created_by_name
            FROM template_versions tv
            LEFT JOIN users u ON u.id = tv.created_by
            WHERE tv.id = $1
            "#,
        )
        .bind(version_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(row.map(template_version_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_template_version_by_template_and_name(
        &self,
        template_id: Uuid,
        name: &str,
    ) -> Result<Option<TemplateVersionRecord>, StorageError> {
        let row = sqlx::query_as::<_, StoredTemplateVersionRow>(
            r#"
            SELECT tv.*,
                   COALESCE(u.avatar_url, '') AS created_by_avatar_url,
                   COALESCE(u.username, '') AS created_by_username,
                   COALESCE(u.name, '') AS created_by_name
            FROM template_versions tv
            LEFT JOIN users u ON u.id = tv.created_by
            WHERE tv.template_id = $1 AND tv.name = $2
            "#,
        )
        .bind(template_id)
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(row.map(template_version_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_template_version_by_org_and_name(
        &self,
        organization_id: Uuid,
        template_name: &str,
        version_name: &str,
    ) -> Result<Option<TemplateVersionRecord>, StorageError> {
        let row = sqlx::query_as::<_, StoredTemplateVersionRow>(
            r#"
            SELECT tv.*,
                   COALESCE(u.avatar_url, '') AS created_by_avatar_url,
                   COALESCE(u.username, '') AS created_by_username,
                   COALESCE(u.name, '') AS created_by_name
            FROM template_versions tv
            LEFT JOIN users u ON u.id = tv.created_by
            JOIN templates t ON t.id = tv.template_id
            WHERE t.organization_id = $1 AND t.name = $2 AND tv.name = $3
            "#,
        )
        .bind(organization_id)
        .bind(template_name)
        .bind(version_name)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(row.map(template_version_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_previous_template_version(
        &self,
        organization_id: Uuid,
        template_name: &str,
        version_name: &str,
    ) -> Result<Option<TemplateVersionRecord>, StorageError> {
        let row = sqlx::query_as::<_, StoredTemplateVersionRow>(
            r#"
            SELECT tv.*,
                   COALESCE(u.avatar_url, '') AS created_by_avatar_url,
                   COALESCE(u.username, '') AS created_by_username,
                   COALESCE(u.name, '') AS created_by_name
            FROM template_versions tv
            LEFT JOIN users u ON u.id = tv.created_by
            JOIN templates t ON t.id = tv.template_id
            WHERE t.organization_id = $1 AND t.name = $2
              AND tv.created_at < (
                  SELECT tv2.created_at
                  FROM template_versions tv2
                  JOIN templates t2 ON t2.id = tv2.template_id
                  WHERE t2.organization_id = $1 AND t2.name = $2 AND tv2.name = $3
                  LIMIT 1
              )
            ORDER BY tv.created_at DESC
            LIMIT 1
            "#,
        )
        .bind(organization_id)
        .bind(template_name)
        .bind(version_name)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(row.map(template_version_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn insert_template_version(
        &self,
        input: CreateTemplateVersionInput,
    ) -> Result<TemplateVersionRecord, StorageError> {
        sqlx::query(
            r#"
            INSERT INTO template_versions (
                id, template_id, organization_id, created_at, updated_at,
                name, message, readme, job_id, created_by, source_example_id
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
        )
        .bind(input.id)
        .bind(input.template_id)
        .bind(input.organization_id)
        .bind(input.created_at)
        .bind(input.updated_at)
        .bind(&input.name)
        .bind(&input.message)
        .bind(&input.readme)
        .bind(input.job_id)
        .bind(input.created_by)
        .bind(input.source_example_id.as_deref())
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        self.find_template_version_by_id(input.id)
            .await?
            .ok_or_else(|| StorageError::unavailable("template version not found after insert"))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_template_version(
        &self,
        version_id: Uuid,
        name: &str,
        message: &str,
    ) -> Result<Option<TemplateVersionRecord>, StorageError> {
        let result = sqlx::query(
            "UPDATE template_versions SET name = $2, message = $3, updated_at = NOW() WHERE id = $1",
        )
        .bind(version_id)
        .bind(name)
        .bind(message)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        if result.rows_affected() == 0 {
            return Ok(None);
        }
        self.find_template_version_by_id(version_id).await
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn archive_template_version(&self, version_id: Uuid) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "UPDATE template_versions SET archived = true, updated_at = NOW() WHERE id = $1 AND archived = false",
        )
        .bind(version_id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn unarchive_template_version(&self, version_id: Uuid) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "UPDATE template_versions SET archived = false, updated_at = NOW() WHERE id = $1 AND archived = true",
        )
        .bind(version_id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_template_version_parameters(
        &self,
        version_id: Uuid,
    ) -> Result<Vec<TemplateVersionParameterRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredTemplateVersionParameterRow>(
            "SELECT template_version_id, name, description, type, mutable, default_value, icon, options, validation_regex, validation_min, validation_max, validation_error, validation_monotonic, required, display_name, display_order, ephemeral, form_type::text AS form_type FROM template_version_parameters WHERE template_version_id = $1 ORDER BY display_order ASC",
        )
        .bind(version_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(rows
            .into_iter()
            .map(template_version_parameter_from_row)
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_template_version_variables(
        &self,
        version_id: Uuid,
    ) -> Result<Vec<TemplateVersionVariableRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredTemplateVersionVariableRow>(
            "SELECT * FROM template_version_variables WHERE template_version_id = $1 ORDER BY name ASC",
        )
        .bind(version_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(rows
            .into_iter()
            .map(template_version_variable_from_row)
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_template_version_presets(
        &self,
        version_id: Uuid,
    ) -> Result<Vec<TemplateVersionPresetRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredTemplateVersionPresetRow>(
            "SELECT * FROM template_version_presets WHERE template_version_id = $1 ORDER BY name ASC",
        )
        .bind(version_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(rows
            .into_iter()
            .map(|r| TemplateVersionPresetRecord {
                id: r.id,
                template_version_id: r.template_version_id,
                name: r.name,
                created_at: r.created_at,
                is_default: r.is_default,
                description: r.description,
                icon: r.icon,
            })
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_template_version_preset_parameters(
        &self,
        preset_id: Uuid,
    ) -> Result<Vec<TemplateVersionPresetParameterRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredTemplateVersionPresetParameterRow>(
            "SELECT * FROM template_version_preset_parameters WHERE template_version_preset_id = $1 ORDER BY name ASC",
        )
        .bind(preset_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(rows
            .into_iter()
            .map(|r| TemplateVersionPresetParameterRecord {
                id: r.id,
                template_version_preset_id: r.template_version_preset_id,
                name: r.name,
                value: r.value,
            })
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn create_provisioner_job(
        &self,
        input: CreateProvisionerJobInput,
    ) -> Result<TemplateProvisionerJobRecord, StorageError> {
        let tags_json = serde_json::to_value(&input.tags)
            .map_err(|e| StorageError::unavailable(format!("serialize tags: {e}")))?;
        sqlx::query(
            r#"
            INSERT INTO provisioner_jobs (
                id, created_at, updated_at, organization_id, initiator_id,
                provisioner, file_id, type, input, tags
            ) VALUES ($1, $2, $3, $4, $5, $6::provisioner_type, $7, $8, $9, $10)
            "#,
        )
        .bind(input.id)
        .bind(input.created_at)
        .bind(input.updated_at)
        .bind(input.organization_id)
        .bind(input.initiator_id)
        .bind(&input.provisioner)
        .bind(input.file_id)
        .bind(&input.job_type)
        .bind(&input.input)
        .bind(&tags_json)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        self.find_provisioner_job(input.id)
            .await?
            .ok_or_else(|| StorageError::unavailable("provisioner job not found after insert"))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_provisioner_job(
        &self,
        job_id: Uuid,
    ) -> Result<Option<TemplateProvisionerJobRecord>, StorageError> {
        let row = sqlx::query_as::<_, StoredTemplateProvisionerJobRow>(
            r#"
            SELECT id, created_at, updated_at, started_at, canceled_at, completed_at,
                   error, organization_id, initiator_id, provisioner::text AS provisioner,
                   CASE
                       WHEN completed_at IS NOT NULL AND canceled_at IS NOT NULL THEN 'canceled'
                       WHEN completed_at IS NOT NULL AND error != '' THEN 'failed'
                       WHEN completed_at IS NOT NULL THEN 'succeeded'
                       WHEN canceled_at IS NOT NULL THEN 'canceling'
                       WHEN started_at IS NOT NULL THEN 'running'
                       ELSE 'pending'
                   END AS job_status,
                   file_id, type, input, worker_id, tags
            FROM provisioner_jobs
            WHERE id = $1
            "#,
        )
        .bind(job_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(row.map(template_provisioner_job_record_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn cancel_template_provisioner_job(&self, job_id: Uuid) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "UPDATE provisioner_jobs SET canceled_at = NOW(), completed_at = CASE WHEN worker_id IS NULL THEN NOW() ELSE completed_at END, updated_at = NOW() WHERE id = $1 AND canceled_at IS NULL AND completed_at IS NULL",
        )
        .bind(job_id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn archive_unused_template_versions(
        &self,
        template_id: Uuid,
        all: bool,
    ) -> Result<Vec<Uuid>, StorageError> {
        // Archive template versions that are not actively used.
        // If `all` is false, only archive versions whose provisioner job failed.
        let rows: Vec<(Uuid,)> = if all {
            sqlx::query_as(
                r#"
                UPDATE template_versions
                SET archived = true, updated_at = NOW()
                WHERE template_id = $1
                  AND archived = false
                  AND id != (SELECT active_version_id FROM templates WHERE id = $1)
                RETURNING id
                "#,
            )
            .bind(template_id)
            .fetch_all(&self.pool)
            .await
            .map_err(storage_error)?
        } else {
            sqlx::query_as(
                r#"
                UPDATE template_versions
                SET archived = true, updated_at = NOW()
                WHERE template_id = $1
                  AND archived = false
                  AND id != (SELECT active_version_id FROM templates WHERE id = $1)
                  AND id IN (
                      SELECT tv.id FROM template_versions tv
                      JOIN provisioner_jobs pj ON pj.id = tv.job_id
                      WHERE tv.template_id = $1
                        AND pj.completed_at IS NOT NULL
                        AND pj.error <> ''
                        AND pj.canceled_at IS NULL
                  )
                RETURNING id
                "#,
            )
            .bind(template_id)
            .fetch_all(&self.pool)
            .await
            .map_err(storage_error)?
        };
        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_previous_template_version(
        &self,
        organization_id: Uuid,
        name: &str,
        template_id: Option<Uuid>,
    ) -> Result<Option<TemplateVersionRecord>, StorageError> {
        // Find the template version with matching name, then get the one
        // created immediately before it (by created_at).
        let row = if let Some(tid) = template_id {
            sqlx::query_as::<_, StoredTemplateVersionRow>(
                r#"
                SELECT tv.*,
                       COALESCE(u.avatar_url, '') AS created_by_avatar_url,
                       COALESCE(u.username, '') AS created_by_username,
                       COALESCE(u.name, '') AS created_by_name
                FROM template_versions tv
                LEFT JOIN users u ON u.id = tv.created_by
                WHERE tv.organization_id = $1
                  AND tv.template_id = $3
                  AND tv.created_at < (
                      SELECT created_at FROM template_versions
                      WHERE organization_id = $1 AND name = $2 AND template_id = $3
                      ORDER BY created_at DESC
                      LIMIT 1
                  )
                ORDER BY tv.created_at DESC
                LIMIT 1
                "#,
            )
            .bind(organization_id)
            .bind(name)
            .bind(tid)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_error)?
        } else {
            sqlx::query_as::<_, StoredTemplateVersionRow>(
                r#"
                SELECT tv.*,
                       COALESCE(u.avatar_url, '') AS created_by_avatar_url,
                       COALESCE(u.username, '') AS created_by_username,
                       COALESCE(u.name, '') AS created_by_name
                FROM template_versions tv
                LEFT JOIN users u ON u.id = tv.created_by
                WHERE tv.organization_id = $1
                  AND tv.created_at < (
                      SELECT created_at FROM template_versions
                      WHERE organization_id = $1 AND name = $2
                      ORDER BY created_at DESC
                      LIMIT 1
                  )
                ORDER BY tv.created_at DESC
                LIMIT 1
                "#,
            )
            .bind(organization_id)
            .bind(name)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_error)?
        };
        Ok(row.map(template_version_record_from_row))
    }

    // -----------------------------------------------------------------------
    // Template ACL
    // -----------------------------------------------------------------------

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_template_user_roles(
        &self,
        template_id: Uuid,
    ) -> Result<Vec<TemplateUserRoleRow>, StorageError> {
        // The template stores user_acl as a JSONB column mapping
        // user-UUID strings to arrays of action strings.
        // We join against the users table to get user metadata.
        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            username: String,
            avatar_url: String,
            name: String,
            email: String,
            status: String,
            login_type: String,
            created_at: OffsetDateTime,
            updated_at: OffsetDateTime,
            actions: Value,
        }

        let rows = sqlx::query_as::<_, Row>(
            r#"
            SELECT u.id,
                   u.username,
                   COALESCE(u.avatar_url, '') AS avatar_url,
                   COALESCE(u.name, '') AS name,
                   u.email,
                   u.status::text AS status,
                   u.login_type::text AS login_type,
                   u.created_at,
                   u.updated_at,
                   t.user_acl -> k.uid AS actions
            FROM templates t
            CROSS JOIN LATERAL jsonb_object_keys(t.user_acl) AS k(uid)
            JOIN users u ON u.id = k.uid::uuid
            WHERE t.id = $1
              AND t.deleted = false
              AND u.deleted = false
            "#,
        )
        .bind(template_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(|r| {
                let actions: Vec<String> =
                    serde_json::from_value(r.actions.clone()).unwrap_or_default();
                TemplateUserRoleRow {
                    id: r.id,
                    username: r.username,
                    avatar_url: r.avatar_url,
                    name: r.name,
                    email: r.email,
                    status: r.status,
                    login_type: r.login_type,
                    created_at: r.created_at,
                    updated_at: r.updated_at,
                    actions,
                }
            })
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_template_group_roles(
        &self,
        template_id: Uuid,
    ) -> Result<Vec<TemplateGroupRoleRow>, StorageError> {
        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            name: String,
            display_name: String,
            organization_id: Uuid,
            avatar_url: String,
            quota_allowance: i32,
            source: String,
            actions: Value,
        }

        let rows = sqlx::query_as::<_, Row>(
            r#"
            SELECT g.id,
                   g.name,
                   COALESCE(g.display_name, '') AS display_name,
                   g.organization_id,
                   COALESCE(g.avatar_url, '') AS avatar_url,
                   g.quota_allowance,
                   g.source::text AS source,
                   t.group_acl -> k.gid AS actions
            FROM templates t
            CROSS JOIN LATERAL jsonb_object_keys(t.group_acl) AS k(gid)
            JOIN groups g ON g.id = k.gid::uuid
            WHERE t.id = $1
              AND t.deleted = false
            "#,
        )
        .bind(template_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(|r| {
                let actions: Vec<String> =
                    serde_json::from_value(r.actions.clone()).unwrap_or_default();
                TemplateGroupRoleRow {
                    id: r.id,
                    name: r.name,
                    display_name: r.display_name,
                    organization_id: r.organization_id,
                    avatar_url: r.avatar_url,
                    quota_allowance: r.quota_allowance,
                    source: r.source,
                    actions,
                }
            })
            .collect())
    }

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn update_template_acl(
        &self,
        template_id: Uuid,
        input: &UpdateTemplateACLInput,
    ) -> Result<(), StorageError> {
        sqlx::query(
            r#"
            UPDATE templates
            SET user_acl = $2::jsonb,
                group_acl = $3::jsonb,
                updated_at = now()
            WHERE id = $1
            "#,
        )
        .bind(template_id)
        .bind(serde_json::to_value(&input.user_acl).unwrap_or_default())
        .bind(serde_json::to_value(&input.group_acl).unwrap_or_default())
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn invalidate_template_presets(
        &self,
        template_id: Uuid,
    ) -> Result<Vec<InvalidatedPresetRow>, StorageError> {
        #[derive(sqlx::FromRow)]
        struct Row {
            template_name: String,
            template_version_name: String,
            preset_name: String,
        }

        let rows = sqlx::query_as::<_, Row>(
            r#"
            UPDATE template_version_presets tvp
            SET last_invalidated_at = now()
            FROM template_versions tv
            JOIN templates t ON t.active_version_id = tv.id AND t.id = $1
            WHERE tvp.template_version_id = tv.id
            RETURNING t.name AS template_name,
                      tv.name AS template_version_name,
                      tvp.name AS preset_name
            "#,
        )
        .bind(template_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(|r| InvalidatedPresetRow {
                template_name: r.template_name,
                template_version_name: r.template_version_name,
                preset_name: r.preset_name,
            })
            .collect())
    }

    // -----------------------------------------------------------------------
    // Licenses
    // -----------------------------------------------------------------------

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_licenses(&self) -> Result<Vec<LicenseRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredLicenseRow>(
            "SELECT id, uuid, uploaded_at, jwt, exp FROM licenses ORDER BY id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(|r| {
                let claims = decode_jwt_claims(&r.jwt);
                LicenseRecord {
                    id: r.id,
                    uuid: r.uuid,
                    uploaded_at: r.uploaded_at,
                    jwt: r.jwt,
                    claims,
                }
            })
            .collect())
    }

    #[instrument(skip(self, jwt, claims), err(level = tracing::Level::WARN))]
    async fn insert_license(
        &self,
        jwt: &str,
        claims: &Value,
    ) -> Result<LicenseRecord, StorageError> {
        let exp = claims
            .get("license_expires")
            .and_then(|v| v.as_i64())
            .or_else(|| claims.get("exp").and_then(|v| v.as_i64()))
            .ok_or_else(|| {
                StorageError::invalid_data(
                    "license claims must contain 'license_expires' or 'exp' field",
                )
            })?;
        let exp_dt = OffsetDateTime::from_unix_timestamp(exp)
            .map_err(|e| StorageError::invalid_data(format!("invalid expiry timestamp: {e}")))?;

        let row = sqlx::query_as::<_, StoredLicenseRow>(
            "INSERT INTO licenses (uploaded_at, jwt, exp, uuid)
             VALUES (NOW(), $1, $2, gen_random_uuid())
             RETURNING id, uuid, uploaded_at, jwt, exp",
        )
        .bind(jwt)
        .bind(exp_dt)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(LicenseRecord {
            id: row.id,
            uuid: row.uuid,
            uploaded_at: row.uploaded_at,
            jwt: row.jwt,
            claims: claims.clone(),
        })
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_license(&self, id: i32) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM licenses WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;

        Ok(result.rows_affected() > 0)
    }

    // ----- Workspace proxy CRUD -----

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn create_workspace_proxy(
        &self,
        input: CreateWorkspaceProxyInput,
    ) -> Result<WorkspaceProxyRow, StorageError> {
        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            name: String,
            display_name: String,
            icon: String,
            url: String,
            wildcard_hostname: String,
            derp_enabled: bool,
            derp_only: bool,
            created_at: OffsetDateTime,
            updated_at: OffsetDateTime,
            deleted: bool,
            version: String,
            region_id: i32,
            token_hashed_secret: Vec<u8>,
        }

        let row = sqlx::query_as::<_, Row>(
            "INSERT INTO workspace_proxies (id, name, display_name, icon, token_hashed_secret, derp_enabled, derp_only, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, true, false, $6, $7)
             RETURNING id, name, display_name, icon,
                       COALESCE(url, '') AS url,
                       COALESCE(wildcard_hostname, '') AS wildcard_hostname,
                       derp_enabled, derp_only,
                       created_at, updated_at, deleted,
                       COALESCE(version, '') AS version,
                       region_id, token_hashed_secret",
        )
        .bind(input.id)
        .bind(&input.name)
        .bind(&input.display_name)
        .bind(&input.icon)
        .bind(&input.token_hashed)
        .bind(input.created_at)
        .bind(input.updated_at)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(WorkspaceProxyRow {
            id: row.id,
            name: row.name,
            display_name: row.display_name,
            icon: row.icon,
            url: row.url,
            wildcard_hostname: row.wildcard_hostname,
            derp_enabled: row.derp_enabled,
            derp_only: row.derp_only,
            created_at: row.created_at,
            updated_at: row.updated_at,
            deleted: row.deleted,
            version: row.version,
            region_id: row.region_id,
            token_hashed: row.token_hashed_secret,
        })
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_workspace_proxies(&self) -> Result<Vec<WorkspaceProxyRow>, StorageError> {
        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            name: String,
            display_name: String,
            icon: String,
            url: String,
            wildcard_hostname: String,
            derp_enabled: bool,
            derp_only: bool,
            created_at: OffsetDateTime,
            updated_at: OffsetDateTime,
            deleted: bool,
            version: String,
            region_id: i32,
            token_hashed_secret: Vec<u8>,
        }

        let rows = sqlx::query_as::<_, Row>(
            "SELECT id, name, display_name, icon,
                    COALESCE(url, '') AS url,
                    COALESCE(wildcard_hostname, '') AS wildcard_hostname,
                    derp_enabled, derp_only,
                    created_at, updated_at, deleted,
                    COALESCE(version, '') AS version,
                    region_id, token_hashed_secret
             FROM workspace_proxies
             WHERE deleted = false
             ORDER BY created_at ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(|r| WorkspaceProxyRow {
                id: r.id,
                name: r.name,
                display_name: r.display_name,
                icon: r.icon,
                url: r.url,
                wildcard_hostname: r.wildcard_hostname,
                derp_enabled: r.derp_enabled,
                derp_only: r.derp_only,
                created_at: r.created_at,
                updated_at: r.updated_at,
                deleted: r.deleted,
                version: r.version,
                region_id: r.region_id,
                token_hashed: r.token_hashed_secret,
            })
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_workspace_proxy_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<WorkspaceProxyRow>, StorageError> {
        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            name: String,
            display_name: String,
            icon: String,
            url: String,
            wildcard_hostname: String,
            derp_enabled: bool,
            derp_only: bool,
            created_at: OffsetDateTime,
            updated_at: OffsetDateTime,
            deleted: bool,
            version: String,
            region_id: i32,
            token_hashed_secret: Vec<u8>,
        }

        let row = sqlx::query_as::<_, Row>(
            "SELECT id, name, display_name, icon,
                    COALESCE(url, '') AS url,
                    COALESCE(wildcard_hostname, '') AS wildcard_hostname,
                    derp_enabled, derp_only,
                    created_at, updated_at, deleted,
                    COALESCE(version, '') AS version,
                    region_id, token_hashed_secret
             FROM workspace_proxies
             WHERE id = $1 AND deleted = false",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(row.map(|r| WorkspaceProxyRow {
            id: r.id,
            name: r.name,
            display_name: r.display_name,
            icon: r.icon,
            url: r.url,
            wildcard_hostname: r.wildcard_hostname,
            derp_enabled: r.derp_enabled,
            derp_only: r.derp_only,
            created_at: r.created_at,
            updated_at: r.updated_at,
            deleted: r.deleted,
            version: r.version,
            region_id: r.region_id,
            token_hashed: r.token_hashed_secret,
        }))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn find_workspace_proxy_by_name(
        &self,
        name: &str,
    ) -> Result<Option<WorkspaceProxyRow>, StorageError> {
        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            name: String,
            display_name: String,
            icon: String,
            url: String,
            wildcard_hostname: String,
            derp_enabled: bool,
            derp_only: bool,
            created_at: OffsetDateTime,
            updated_at: OffsetDateTime,
            deleted: bool,
            version: String,
            region_id: i32,
            token_hashed_secret: Vec<u8>,
        }

        let row = sqlx::query_as::<_, Row>(
            "SELECT id, name, display_name, icon,
                    COALESCE(url, '') AS url,
                    COALESCE(wildcard_hostname, '') AS wildcard_hostname,
                    derp_enabled, derp_only,
                    created_at, updated_at, deleted,
                    COALESCE(version, '') AS version,
                    region_id, token_hashed_secret
             FROM workspace_proxies
             WHERE name = $1 AND deleted = false",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(row.map(|r| WorkspaceProxyRow {
            id: r.id,
            name: r.name,
            display_name: r.display_name,
            icon: r.icon,
            url: r.url,
            wildcard_hostname: r.wildcard_hostname,
            derp_enabled: r.derp_enabled,
            derp_only: r.derp_only,
            created_at: r.created_at,
            updated_at: r.updated_at,
            deleted: r.deleted,
            version: r.version,
            region_id: r.region_id,
            token_hashed: r.token_hashed_secret,
        }))
    }

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn update_workspace_proxy(
        &self,
        input: UpdateWorkspaceProxyInput,
    ) -> Result<WorkspaceProxyRow, StorageError> {
        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            name: String,
            display_name: String,
            icon: String,
            url: String,
            wildcard_hostname: String,
            derp_enabled: bool,
            derp_only: bool,
            created_at: OffsetDateTime,
            updated_at: OffsetDateTime,
            deleted: bool,
            version: String,
            region_id: i32,
            token_hashed_secret: Vec<u8>,
        }

        let row = sqlx::query_as::<_, Row>(
            "UPDATE workspace_proxies
             SET name = $2,
                 display_name = $3,
                 icon = $4,
                 token_hashed_secret = COALESCE($5, token_hashed_secret),
                 updated_at = $6
             WHERE id = $1 AND deleted = false
             RETURNING id, name, display_name, icon,
                       COALESCE(url, '') AS url,
                       COALESCE(wildcard_hostname, '') AS wildcard_hostname,
                       derp_enabled, derp_only,
                       created_at, updated_at, deleted,
                       COALESCE(version, '') AS version,
                       region_id, token_hashed_secret",
        )
        .bind(input.id)
        .bind(&input.name)
        .bind(&input.display_name)
        .bind(&input.icon)
        .bind(input.token_hashed.as_deref())
        .bind(input.updated_at)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(WorkspaceProxyRow {
            id: row.id,
            name: row.name,
            display_name: row.display_name,
            icon: row.icon,
            url: row.url,
            wildcard_hostname: row.wildcard_hostname,
            derp_enabled: row.derp_enabled,
            derp_only: row.derp_only,
            created_at: row.created_at,
            updated_at: row.updated_at,
            deleted: row.deleted,
            version: row.version,
            region_id: row.region_id,
            token_hashed: row.token_hashed_secret,
        })
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn soft_delete_workspace_proxy(&self, id: Uuid) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "UPDATE workspace_proxies SET deleted = true, updated_at = NOW()
             WHERE id = $1 AND deleted = false",
        )
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(result.rows_affected() > 0)
    }

    // ----- Workspace proxy registration -----

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn update_workspace_proxy_registration(
        &self,
        input: UpdateWorkspaceProxyRegistrationInput,
    ) -> Result<WorkspaceProxyRow, StorageError> {
        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            name: String,
            display_name: String,
            icon: String,
            url: String,
            wildcard_hostname: String,
            derp_enabled: bool,
            derp_only: bool,
            created_at: OffsetDateTime,
            updated_at: OffsetDateTime,
            deleted: bool,
            version: String,
            region_id: i32,
            token_hashed_secret: Vec<u8>,
        }

        let row = sqlx::query_as::<_, Row>(
            "UPDATE workspace_proxies
             SET url = $2, wildcard_hostname = $3, derp_enabled = $4, derp_only = $5,
                 version = $6, updated_at = $7
             WHERE id = $1
             RETURNING id, name, display_name, icon,
                       COALESCE(url, '') AS url,
                       COALESCE(wildcard_hostname, '') AS wildcard_hostname,
                       derp_enabled, derp_only,
                       created_at, updated_at, deleted,
                       COALESCE(version, '') AS version,
                       region_id, token_hashed_secret",
        )
        .bind(input.id)
        .bind(&input.url)
        .bind(&input.wildcard_hostname)
        .bind(input.derp_enabled)
        .bind(input.derp_only)
        .bind(&input.version)
        .bind(input.updated_at)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(WorkspaceProxyRow {
            id: row.id,
            name: row.name,
            display_name: row.display_name,
            icon: row.icon,
            url: row.url,
            wildcard_hostname: row.wildcard_hostname,
            derp_enabled: row.derp_enabled,
            derp_only: row.derp_only,
            created_at: row.created_at,
            updated_at: row.updated_at,
            deleted: row.deleted,
            version: row.version,
            region_id: row.region_id,
            token_hashed: row.token_hashed_secret,
        })
    }

    // ----- Replicas -----

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn upsert_replica(&self, input: UpsertReplicaInput) -> Result<ReplicaRow, StorageError> {
        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            // `replicas.proxy_id` is nullable (primary coderd rows set it to
            // NULL).  The workspace-proxy upsert path always binds a
            // non-null value so the RETURNING clause never produces NULL,
            // but keeping this `Option` avoids sqlx decode panics if a
            // future schema change ever relaxes that invariant.
            proxy_id: Option<Uuid>,
            hostname: String,
            relay_address: String,
            region_id: i32,
            version: String,
            error: String,
            database_latency: i32,
            primary_replica: bool,
            started_at: OffsetDateTime,
            stopped_at: Option<OffsetDateTime>,
            created_at: OffsetDateTime,
            updated_at: OffsetDateTime,
        }

        let row = sqlx::query_as::<_, Row>(
            "INSERT INTO replicas (id, proxy_id, hostname, relay_address, region_id, version, error, database_latency, started_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             ON CONFLICT (id) DO UPDATE SET
                 hostname = EXCLUDED.hostname,
                 relay_address = EXCLUDED.relay_address,
                 region_id = EXCLUDED.region_id,
                 version = EXCLUDED.version,
                 error = EXCLUDED.error,
                 database_latency = EXCLUDED.database_latency,
                 updated_at = EXCLUDED.updated_at
             RETURNING id, proxy_id, hostname, relay_address, region_id, version,
                       error, database_latency, primary_replica, started_at, stopped_at,
                       created_at, updated_at",
        )
        .bind(input.id)
        .bind(input.proxy_id)
        .bind(&input.hostname)
        .bind(&input.relay_address)
        .bind(input.region_id)
        .bind(&input.version)
        .bind(&input.error)
        .bind(input.database_latency)
        .bind(input.started_at)
        .bind(input.updated_at)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(ReplicaRow {
            id: row.id,
            proxy_id: row.proxy_id.ok_or_else(|| {
                StorageError::invalid_data(
                    "upsert_replica returned a row with NULL proxy_id; expected a workspace-proxy replica",
                )
            })?,
            hostname: row.hostname,
            relay_address: row.relay_address,
            region_id: row.region_id,
            version: row.version,
            error: row.error,
            database_latency: row.database_latency,
            primary_replica: row.primary_replica,
            started_at: row.started_at,
            stopped_at: row.stopped_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_replicas_by_proxy_excluding(
        &self,
        proxy_id: Uuid,
        exclude_id: Uuid,
    ) -> Result<Vec<ReplicaRow>, StorageError> {
        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            // `proxy_id` is nullable in the schema but the `WHERE proxy_id = $1`
            // filter excludes NULL rows in Postgres, so this is defensive
            // against future schema changes rather than something that can
            // happen today.
            proxy_id: Option<Uuid>,
            hostname: String,
            relay_address: String,
            region_id: i32,
            version: String,
            error: String,
            database_latency: i32,
            primary_replica: bool,
            started_at: OffsetDateTime,
            stopped_at: Option<OffsetDateTime>,
            created_at: OffsetDateTime,
            updated_at: OffsetDateTime,
        }

        let rows = sqlx::query_as::<_, Row>(
            "SELECT id, proxy_id, hostname, relay_address, region_id, version,
                    error, database_latency, primary_replica, started_at, stopped_at,
                    created_at, updated_at
             FROM replicas
             WHERE proxy_id = $1 AND id != $2 AND stopped_at IS NULL
             ORDER BY created_at ASC",
        )
        .bind(proxy_id)
        .bind(exclude_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        rows.into_iter()
            .map(|r| {
                Ok(ReplicaRow {
                    id: r.id,
                    proxy_id: r.proxy_id.ok_or_else(|| {
                        StorageError::invalid_data(
                            "list_replicas_by_proxy_excluding returned a row with NULL proxy_id; expected a workspace-proxy replica",
                        )
                    })?,
                    hostname: r.hostname,
                    relay_address: r.relay_address,
                    region_id: r.region_id,
                    version: r.version,
                    error: r.error,
                    database_latency: r.database_latency,
                    primary_replica: r.primary_replica,
                    started_at: r.started_at,
                    stopped_at: r.stopped_at,
                    created_at: r.created_at,
                    updated_at: r.updated_at,
                })
            })
            .collect()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_replica(&self, id: Uuid) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM replicas WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;

        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn insert_coderd_replica(
        &self,
        input: coder_core::InsertCoderdReplicaInput,
    ) -> Result<coder_core::CoderdReplicaRow, StorageError> {
        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            hostname: String,
            relay_address: String,
            region_id: i32,
            version: String,
            error: String,
            database_latency: i32,
            created_at: OffsetDateTime,
            started_at: OffsetDateTime,
            stopped_at: Option<OffsetDateTime>,
            updated_at: OffsetDateTime,
        }

        let row = sqlx::query_as::<_, Row>(
            "INSERT INTO replicas (
                 id, proxy_id, hostname, relay_address, region_id, version,
                 error, database_latency, primary_replica, started_at,
                 stopped_at, created_at, updated_at
             ) VALUES ($1, NULL, $2, $3, $4, $5, '', $6, TRUE, $7, NULL, $8, $9)
             RETURNING id, hostname, relay_address, region_id, version,
                       error, database_latency, created_at, started_at,
                       stopped_at, updated_at",
        )
        .bind(input.id)
        .bind(&input.hostname)
        .bind(&input.relay_address)
        .bind(input.region_id)
        .bind(&input.version)
        .bind(input.database_latency)
        .bind(input.started_at)
        .bind(input.created_at)
        .bind(input.updated_at)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(coder_core::CoderdReplicaRow {
            id: row.id,
            hostname: row.hostname,
            relay_address: row.relay_address,
            region_id: row.region_id,
            version: row.version,
            error: row.error,
            database_latency: row.database_latency,
            created_at: row.created_at,
            started_at: row.started_at,
            stopped_at: row.stopped_at,
            updated_at: row.updated_at,
        })
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn refresh_coderd_replica(
        &self,
        id: Uuid,
        updated_at: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "UPDATE replicas SET updated_at = $2
             WHERE id = $1 AND proxy_id IS NULL AND stopped_at IS NULL",
        )
        .bind(id)
        .bind(updated_at)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_coderd_replica(&self, id: Uuid) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM replicas WHERE id = $1 AND proxy_id IS NULL")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;

        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_coderd_replicas(
        &self,
        updated_after: OffsetDateTime,
    ) -> Result<Vec<coder_core::CoderdReplicaRow>, StorageError> {
        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            hostname: String,
            relay_address: String,
            region_id: i32,
            version: String,
            error: String,
            database_latency: i32,
            created_at: OffsetDateTime,
            started_at: OffsetDateTime,
            stopped_at: Option<OffsetDateTime>,
            updated_at: OffsetDateTime,
        }

        let rows = sqlx::query_as::<_, Row>(
            "SELECT id, hostname, relay_address, region_id, version,
                    error, database_latency, created_at, started_at,
                    stopped_at, updated_at
             FROM replicas
             WHERE proxy_id IS NULL
               AND stopped_at IS NULL
               AND updated_at > $1
             ORDER BY created_at ASC",
        )
        .bind(updated_after)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(|r| coder_core::CoderdReplicaRow {
                id: r.id,
                hostname: r.hostname,
                relay_address: r.relay_address,
                region_id: r.region_id,
                version: r.version,
                error: r.error,
                database_latency: r.database_latency,
                created_at: r.created_at,
                started_at: r.started_at,
                stopped_at: r.stopped_at,
                updated_at: r.updated_at,
            })
            .collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn prune_stale_coderd_replicas(
        &self,
        older_than: OffsetDateTime,
    ) -> Result<u64, StorageError> {
        let result = sqlx::query("DELETE FROM replicas WHERE proxy_id IS NULL AND updated_at < $1")
            .bind(older_than)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;

        Ok(result.rows_affected())
    }

    // ----- Crypto keys -----

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_crypto_keys_by_feature(
        &self,
        feature: coder_core::enums::CryptoKeyFeature,
    ) -> Result<Vec<CryptoKeyRow>, StorageError> {
        #[derive(sqlx::FromRow)]
        struct Row {
            feature: coder_core::enums::CryptoKeyFeature,
            sequence: i32,
            secret: Vec<u8>,
            starts_at: OffsetDateTime,
            deletes_at: Option<OffsetDateTime>,
        }

        let rows = sqlx::query_as::<_, Row>(
            "SELECT feature, sequence, secret, starts_at, deletes_at
             FROM crypto_keys
             WHERE feature = $1::crypto_key_feature
               AND starts_at <= NOW()
               AND (deletes_at IS NULL OR deletes_at > NOW())
             ORDER BY sequence ASC",
        )
        .bind(feature)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows
            .into_iter()
            .map(|r| CryptoKeyRow {
                feature: r.feature,
                sequence: r.sequence,
                secret: r.secret,
                starts_at: r.starts_at,
                deletes_at: r.deletes_at,
            })
            .collect())
    }

    #[instrument(skip(self, row), err(level = tracing::Level::WARN))]
    async fn insert_crypto_key(&self, row: CryptoKeyRow) -> Result<CryptoKeyRow, StorageError> {
        #[derive(sqlx::FromRow)]
        struct StoredRow {
            feature: coder_core::enums::CryptoKeyFeature,
            sequence: i32,
            secret: Vec<u8>,
            starts_at: OffsetDateTime,
            deletes_at: Option<OffsetDateTime>,
        }

        let result = sqlx::query_as::<_, StoredRow>(
            "INSERT INTO crypto_keys (feature, sequence, secret, starts_at, deletes_at)
             VALUES ($1::crypto_key_feature, $2, $3, $4, $5)
             RETURNING feature, sequence, secret, starts_at, deletes_at",
        )
        .bind(row.feature)
        .bind(row.sequence)
        .bind(&row.secret)
        .bind(row.starts_at)
        .bind(row.deletes_at)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(CryptoKeyRow {
            feature: result.feature,
            sequence: result.sequence,
            secret: result.secret,
            starts_at: result.starts_at,
            deletes_at: result.deletes_at,
        })
    }

    // ----- Workspace app stats -----

    #[instrument(skip(self, stats), err(level = tracing::Level::WARN))]
    async fn insert_workspace_app_stats(&self, stats: &[Value]) -> Result<(), StorageError> {
        for stat in stats {
            let user_id: Option<Uuid> = stat
                .get("user_id")
                .and_then(|v| v.as_str())
                .and_then(|s| Uuid::parse_str(s).ok());
            let workspace_id: Option<Uuid> = stat
                .get("workspace_id")
                .and_then(|v| v.as_str())
                .and_then(|s| Uuid::parse_str(s).ok());
            let agent_id: Option<Uuid> = stat
                .get("agent_id")
                .and_then(|v| v.as_str())
                .and_then(|s| Uuid::parse_str(s).ok());
            let access_method = stat
                .get("access_method")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let slug_or_port = stat
                .get("slug_or_port")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let session_id: Option<Uuid> = stat
                .get("session_id")
                .and_then(|v| v.as_str())
                .and_then(|s| Uuid::parse_str(s).ok());
            let requests: i32 = stat
                .get("requests")
                .and_then(|v| v.as_i64())
                .map(|v| v as i32)
                .unwrap_or(0);

            // Parse timestamps or fall back to now.
            let now = OffsetDateTime::now_utc();
            let session_started_at = stat
                .get("session_started_at")
                .and_then(|v| v.as_str())
                .and_then(|s| {
                    OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()
                })
                .unwrap_or(now);
            let session_ended_at = stat
                .get("session_ended_at")
                .and_then(|v| v.as_str())
                .and_then(|s| {
                    OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()
                })
                .unwrap_or(now);

            sqlx::query(
                "INSERT INTO workspace_app_stats (user_id, workspace_id, agent_id, access_method, slug_or_port, session_id, session_started_at, session_ended_at, requests)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            )
            .bind(user_id.unwrap_or_default())
            .bind(workspace_id.unwrap_or_default())
            .bind(agent_id.unwrap_or_default())
            .bind(access_method)
            .bind(slug_or_port)
            .bind(session_id.unwrap_or_default())
            .bind(session_started_at)
            .bind(session_ended_at)
            .bind(requests)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // AI Bridge
    // -----------------------------------------------------------------------

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_aibridge_interceptions(
        &self,
        filter: coder_core::api::AIBridgeInterceptionsFilter,
    ) -> Result<coder_core::api::AIBridgeListInterceptionsResponse, StorageError> {
        // The aibridge_interceptions table is enterprise-only; the feature gate
        // middleware prevents unlicensed access.  Return an empty response until
        // the full SQL is wired.
        let _ = filter;
        Ok(coder_core::api::AIBridgeListInterceptionsResponse {
            count: 0,
            results: Vec::new(),
        })
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_aibridge_models(
        &self,
        filter: coder_core::api::AIBridgeModelsFilter,
    ) -> Result<Vec<String>, StorageError> {
        // The aibridge_interceptions table is enterprise-only; the feature gate
        // middleware prevents unlicensed access.  Return an empty list until the
        // full SQL is wired.
        let _ = filter;
        Ok(Vec::new())
    }

    // -----------------------------------------------------------------------
    // Workspace quotas (enterprise)
    //
    // Ports `GetQuotaAllowanceForUser` / `GetQuotaConsumedForUser` from
    // `coder/coderd/database/queries/quotas.sql`.  The Go implementation uses
    // the `group_members_expanded` view which unions `group_members` with
    // `organization_members` (the implicit "Everyone" group has `id ==
    // organization_id`).  We inline that union here rather than add a view.
    // -----------------------------------------------------------------------

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_quota_allowance_for_user(
        &self,
        user_id: Uuid,
        organization_id: Uuid,
    ) -> Result<i64, StorageError> {
        sqlx::query_scalar::<_, i64>(
            "SELECT COALESCE(SUM(groups.quota_allowance), 0)::BIGINT
             FROM groups
             WHERE groups.organization_id = $2
               AND (
                   groups.id IN (
                       SELECT group_id FROM group_members WHERE user_id = $1
                   )
                   OR groups.id IN (
                       SELECT organization_id FROM organization_members WHERE user_id = $1
                   )
               )",
        )
        .bind(user_id)
        .bind(organization_id)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_quota_consumed_for_user(
        &self,
        owner_id: Uuid,
        organization_id: Uuid,
    ) -> Result<i64, StorageError> {
        sqlx::query_scalar::<_, i64>(
            "WITH latest_builds AS (
                 SELECT DISTINCT ON (wb.workspace_id)
                        wb.workspace_id,
                        wb.daily_cost
                 FROM workspace_builds wb
                 INNER JOIN workspaces ON wb.workspace_id = workspaces.id
                 WHERE NOT workspaces.deleted
                   AND workspaces.owner_id = $1
                   AND workspaces.organization_id = $2
                 ORDER BY wb.workspace_id, wb.build_number DESC
             )
             SELECT COALESCE(SUM(daily_cost), 0)::BIGINT FROM latest_builds",
        )
        .bind(owner_id)
        .bind(organization_id)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)
    }
}
