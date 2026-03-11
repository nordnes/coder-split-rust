use super::*;

#[async_trait]
impl ProvisionerStore for PostgresStore {
    // ── Jobs ──────────────────────────────────────────────────

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn acquire_provisioner_job(
        &self,
        input: AcquireProvisionerJobInput,
    ) -> Result<Option<ProvisionerJobRecord>, StorageError> {
        let provisioner_types: Vec<String> = input.types.iter().map(|t| t.to_string()).collect();

        // Atomically find and lock one pending job using FOR UPDATE SKIP LOCKED.
        // Tag matching: the job's tags must be a subset of the daemon's tags.
        let row = sqlx::query_as::<_, StoredProvisionerJobRow>(
            "UPDATE provisioner_jobs
             SET started_at = $1,
                 updated_at = $1,
                 worker_id = $2
             WHERE id = (
                 SELECT id
                 FROM provisioner_jobs
                 WHERE started_at IS NULL
                   AND completed_at IS NULL
                   AND canceled_at IS NULL
                   AND organization_id = $3
                   AND provisioner::TEXT = ANY($4)
                   AND tags <@ $5::JSONB
                 ORDER BY created_at ASC
                 LIMIT 1
                 FOR UPDATE SKIP LOCKED
             )
             RETURNING id, created_at, updated_at, started_at, canceled_at,
                       completed_at, error, error_code, organization_id,
                       initiator_id, provisioner::TEXT, storage_method::TEXT,
                       file_id, \"type\"::TEXT AS job_type, input, tags,
                       trace_metadata, worker_id, job_status::TEXT,
                       logs_overflowed, logs_length",
        )
        .bind(input.started_at)
        .bind(input.worker_id)
        .bind(input.organization_id)
        .bind(&provisioner_types)
        .bind(&input.provisioner_tags)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        row.map(provisioner_job_from_row).transpose()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_provisioner_job_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<ProvisionerJobRecord>, StorageError> {
        let row = sqlx::query_as::<_, StoredProvisionerJobRow>(
            "SELECT id, created_at, updated_at, started_at, canceled_at,
                    completed_at, error, error_code, organization_id,
                    initiator_id, provisioner::TEXT, storage_method::TEXT,
                    file_id, \"type\"::TEXT AS job_type, input, tags,
                    trace_metadata, worker_id, job_status::TEXT,
                    logs_overflowed, logs_length
             FROM provisioner_jobs
             WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        row.map(provisioner_job_from_row).transpose()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_provisioner_jobs_by_ids(
        &self,
        ids: &[Uuid],
    ) -> Result<Vec<ProvisionerJobRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredProvisionerJobRow>(
            "SELECT id, created_at, updated_at, started_at, canceled_at,
                    completed_at, error, error_code, organization_id,
                    initiator_id, provisioner::TEXT, storage_method::TEXT,
                    file_id, \"type\"::TEXT AS job_type, input, tags,
                    trace_metadata, worker_id, job_status::TEXT,
                    logs_overflowed, logs_length
             FROM provisioner_jobs
             WHERE id = ANY($1)
             ORDER BY created_at ASC",
        )
        .bind(ids)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        rows.into_iter()
            .map(provisioner_job_from_row)
            .collect::<Result<Vec<_>, _>>()
    }

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn insert_provisioner_job(
        &self,
        input: InsertProvisionerJobInput,
    ) -> Result<ProvisionerJobRecord, StorageError> {
        let row = sqlx::query_as::<_, StoredProvisionerJobRow>(
            "INSERT INTO provisioner_jobs (
                 id, created_at, updated_at, organization_id, initiator_id,
                 provisioner, storage_method, file_id, \"type\", input,
                 tags, trace_metadata
             ) VALUES (
                 $1, $2, $2, $3, $4,
                 $5::provisioner_type, $6::provisioner_storage_method,
                 $7, $8::provisioner_job_type, $9, $10, $11
             )
             RETURNING id, created_at, updated_at, started_at, canceled_at,
                       completed_at, error, error_code, organization_id,
                       initiator_id, provisioner::TEXT, storage_method::TEXT,
                       file_id, \"type\"::TEXT AS job_type, input, tags,
                       trace_metadata, worker_id, job_status::TEXT,
                       logs_overflowed, logs_length",
        )
        .bind(input.id)
        .bind(input.created_at)
        .bind(input.organization_id)
        .bind(input.initiator_id)
        .bind(input.provisioner.as_str())
        .bind(input.storage_method.as_str())
        .bind(input.file_id)
        .bind(input.job_type.as_str())
        .bind(&input.input)
        .bind(&input.tags)
        .bind(&input.trace_metadata)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        provisioner_job_from_row(row)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_provisioner_job_by_id(
        &self,
        id: Uuid,
        updated_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        sqlx::query("UPDATE provisioner_jobs SET updated_at = $1 WHERE id = $2")
            .bind(updated_at)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn update_provisioner_job_with_complete_by_id(
        &self,
        input: CompleteProvisionerJobInput,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "UPDATE provisioner_jobs
             SET updated_at = $1,
                 completed_at = $2,
                 error = $3,
                 error_code = $4
             WHERE id = $5",
        )
        .bind(input.updated_at)
        .bind(input.completed_at)
        .bind(&input.error)
        .bind(&input.error_code)
        .bind(input.id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn update_provisioner_job_with_cancel_by_id(
        &self,
        input: CancelProvisionerJobInput,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "UPDATE provisioner_jobs
             SET canceled_at = $1,
                 completed_at = COALESCE($2, completed_at),
                 updated_at = $1
             WHERE id = $3",
        )
        .bind(input.canceled_at)
        .bind(input.completed_at)
        .bind(input.id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn get_provisioner_jobs_to_be_reaped(
        &self,
        input: GetJobsToBeReapedInput,
    ) -> Result<Vec<ProvisionerJobRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredProvisionerJobRow>(
            "SELECT id, created_at, updated_at, started_at, canceled_at,
                    completed_at, error, error_code, organization_id,
                    initiator_id, provisioner::TEXT, storage_method::TEXT,
                    file_id, \"type\"::TEXT AS job_type, input, tags,
                    trace_metadata, worker_id, job_status::TEXT,
                    logs_overflowed, logs_length
             FROM provisioner_jobs
             WHERE (
                 -- Pending too long
                 (started_at IS NULL AND completed_at IS NULL AND created_at < $1)
                 OR
                 -- Running but no heartbeat (hung)
                 (started_at IS NOT NULL AND completed_at IS NULL AND updated_at < $2)
             )
             ORDER BY created_at ASC
             LIMIT $3",
        )
        .bind(input.pending_since)
        .bind(input.hung_since)
        .bind(input.max_jobs)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        rows.into_iter()
            .map(provisioner_job_from_row)
            .collect::<Result<Vec<_>, _>>()
    }

    // ── Logs ─────────────────────────────────────────────────

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn insert_provisioner_job_logs(
        &self,
        input: InsertProvisionerJobLogsInput,
    ) -> Result<Vec<ProvisionerLogRecord>, StorageError> {
        let n = input.created_at.len();
        if input.source.len() != n
            || input.level.len() != n
            || input.stage.len() != n
            || input.output.len() != n
        {
            return Err(StorageError::invalid_data(
                "all log input vectors must have the same length".to_string(),
            ));
        }
        let job_ids: Vec<Uuid> = vec![input.job_id; n];
        let sources: Vec<String> = input.source.iter().map(|s| s.to_string()).collect();
        let levels: Vec<String> = input.level.iter().map(|l| l.to_string()).collect();

        let mut transaction = self.pool.begin().await.map_err(storage_error)?;

        let rows = sqlx::query_as::<_, StoredProvisionerJobLogRow>(
            "INSERT INTO provisioner_job_logs (job_id, created_at, source, level, stage, output)
             SELECT * FROM UNNEST($1::UUID[], $2::TIMESTAMPTZ[], $3::log_source[], $4::log_level[], $5::VARCHAR[], $6::VARCHAR[])
             RETURNING id, job_id, created_at, source::TEXT, level::TEXT, stage, output",
        )
        .bind(&job_ids)
        .bind(&input.created_at)
        .bind(&sources)
        .bind(&levels)
        .bind(&input.stage)
        .bind(&input.output)
        .fetch_all(&mut *transaction)
        .await
        .map_err(storage_error)?;

        // Update logs_length on the parent job (tracks total bytes, not entry count).
        let total_bytes: usize = input.output.iter().map(|o| o.len()).sum();
        let log_bytes = i32::try_from(total_bytes).unwrap_or(i32::MAX);
        sqlx::query(
            "UPDATE provisioner_jobs
             SET logs_length = logs_length + $1
             WHERE id = $2",
        )
        .bind(log_bytes)
        .bind(input.job_id)
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;

        transaction.commit().await.map_err(storage_error)?;

        rows.into_iter()
            .map(provisioner_job_log_from_row)
            .collect::<Result<Vec<_>, _>>()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_provisioner_logs_after_id(
        &self,
        job_id: Uuid,
        after_id: i64,
    ) -> Result<Vec<ProvisionerLogRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredProvisionerJobLogRow>(
            "SELECT id, job_id, created_at, source::TEXT, level::TEXT, stage, output
             FROM provisioner_job_logs
             WHERE job_id = $1 AND id > $2
             ORDER BY id ASC",
        )
        .bind(job_id)
        .bind(after_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        rows.into_iter()
            .map(provisioner_job_log_from_row)
            .collect::<Result<Vec<_>, _>>()
    }

    // ── Timings ──────────────────────────────────────────────

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn insert_provisioner_job_timings(
        &self,
        input: InsertProvisionerJobTimingsInput,
    ) -> Result<Vec<ProvisionerTimingRecord>, StorageError> {
        let n = input.started_at.len();
        if input.ended_at.len() != n
            || input.stage.len() != n
            || input.source.len() != n
            || input.action.len() != n
            || input.resource.len() != n
        {
            return Err(StorageError::invalid_data(
                "all timing input vectors must have the same length".to_string(),
            ));
        }
        let job_ids: Vec<Uuid> = vec![input.job_id; n];
        let stages: Vec<String> = input.stage.iter().map(|s| s.to_string()).collect();

        let rows = sqlx::query_as::<_, StoredProvisionerJobTimingRow>(
            "INSERT INTO provisioner_job_timings (job_id, started_at, ended_at, stage, source, action, resource)
             SELECT * FROM UNNEST($1::UUID[], $2::TIMESTAMPTZ[], $3::TIMESTAMPTZ[], $4::provisioner_job_timing_stage[], $5::TEXT[], $6::TEXT[], $7::TEXT[])
             RETURNING job_id, started_at, ended_at, stage::TEXT, source, action, resource",
        )
        .bind(&job_ids)
        .bind(&input.started_at)
        .bind(&input.ended_at)
        .bind(&stages)
        .bind(&input.source)
        .bind(&input.action)
        .bind(&input.resource)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        rows.into_iter()
            .map(provisioner_job_timing_from_row)
            .collect::<Result<Vec<_>, _>>()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_provisioner_job_timings_by_job_id(
        &self,
        job_id: Uuid,
    ) -> Result<Vec<ProvisionerTimingRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredProvisionerJobTimingRow>(
            "SELECT job_id, started_at, ended_at, stage::TEXT, source, action, resource
             FROM provisioner_job_timings
             WHERE job_id = $1
             ORDER BY started_at ASC",
        )
        .bind(job_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        rows.into_iter()
            .map(provisioner_job_timing_from_row)
            .collect::<Result<Vec<_>, _>>()
    }

    // ── Daemons ──────────────────────────────────────────────

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn upsert_provisioner_daemon(
        &self,
        input: UpsertProvisionerDaemonInput,
    ) -> Result<ProvisionerDaemonRecord, StorageError> {
        let tags_json = serde_json::to_string(&input.tags)
            .map_err(|e| StorageError::invalid_data(e.to_string()))?;

        let row = sqlx::query_as::<_, StoredFullProvisionerDaemonRow>(
            "INSERT INTO provisioner_daemons (
                 name, provisioners, tags_json, last_seen_at, version,
                 organization_id, api_version, key_id
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (organization_id, name) DO UPDATE SET
                 provisioners = EXCLUDED.provisioners,
                 tags_json = EXCLUDED.tags_json,
                 last_seen_at = EXCLUDED.last_seen_at,
                 version = EXCLUDED.version,
                 api_version = EXCLUDED.api_version,
                 key_id = EXCLUDED.key_id
             RETURNING id, organization_id, created_at, last_seen_at,
                       name, version, api_version, provisioners,
                       tags_json, key_id",
        )
        .bind(&input.name)
        .bind(&input.provisioners)
        .bind(&tags_json)
        .bind(input.last_seen_at)
        .bind(&input.version)
        .bind(input.organization_id)
        .bind(&input.api_version)
        .bind(input.key_id)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        full_provisioner_daemon_from_row(row)
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn update_provisioner_daemon_last_seen_at(
        &self,
        id: Uuid,
        last_seen_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        sqlx::query("UPDATE provisioner_daemons SET last_seen_at = $1 WHERE id = $2")
            .bind(last_seen_at)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;

        Ok(())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_provisioner_daemons_by_organization(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<ProvisionerDaemonRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredFullProvisionerDaemonRow>(
            "SELECT id, organization_id, created_at, last_seen_at,
                    name, version, api_version, provisioners,
                    tags_json, key_id
             FROM provisioner_daemons
             WHERE organization_id = $1
             ORDER BY created_at ASC",
        )
        .bind(organization_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        rows.into_iter()
            .map(full_provisioner_daemon_from_row)
            .collect::<Result<Vec<_>, _>>()
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_old_provisioner_daemons(&self) -> Result<(), StorageError> {
        sqlx::query(
            "DELETE FROM provisioner_daemons
             WHERE last_seen_at IS NOT NULL AND last_seen_at < NOW() - INTERVAL '7 days'",
        )
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    // ── Keys ─────────────────────────────────────────────────

    #[instrument(skip(self, input), err(level = tracing::Level::WARN))]
    async fn insert_provisioner_key(
        &self,
        input: InsertProvisionerKeyInput,
    ) -> Result<ProvisionerKeyRecord, StorageError> {
        let row = sqlx::query_as::<_, StoredProvisionerKeyRow>(
            "INSERT INTO provisioner_keys (id, created_at, organization_id, name, hashed_secret, tags)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING id, created_at, organization_id, name, hashed_secret, tags",
        )
        .bind(input.id)
        .bind(input.created_at)
        .bind(input.organization_id)
        .bind(&input.name)
        .bind(&input.hashed_secret)
        .bind(&input.tags)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(provisioner_key_from_row(row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_provisioner_key_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<ProvisionerKeyRecord>, StorageError> {
        let row = sqlx::query_as::<_, StoredProvisionerKeyRow>(
            "SELECT id, created_at, organization_id, name, hashed_secret, tags
             FROM provisioner_keys
             WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(row.map(provisioner_key_from_row))
    }

    #[instrument(skip(self, hashed_secret), err(level = tracing::Level::WARN))]
    async fn get_provisioner_key_by_hashed_secret(
        &self,
        hashed_secret: &[u8],
    ) -> Result<Option<ProvisionerKeyRecord>, StorageError> {
        let row = sqlx::query_as::<_, StoredProvisionerKeyRow>(
            "SELECT id, created_at, organization_id, name, hashed_secret, tags
             FROM provisioner_keys
             WHERE hashed_secret = $1",
        )
        .bind(hashed_secret)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(row.map(provisioner_key_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn get_provisioner_key_by_name(
        &self,
        organization_id: Uuid,
        name: &str,
    ) -> Result<Option<ProvisionerKeyRecord>, StorageError> {
        let row = sqlx::query_as::<_, StoredProvisionerKeyRow>(
            "SELECT id, created_at, organization_id, name, hashed_secret, tags
             FROM provisioner_keys
             WHERE organization_id = $1 AND name = $2",
        )
        .bind(organization_id)
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(row.map(provisioner_key_from_row))
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn list_provisioner_keys_by_organization(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<ProvisionerKeyRecord>, StorageError> {
        let rows = sqlx::query_as::<_, StoredProvisionerKeyRow>(
            "SELECT id, created_at, organization_id, name, hashed_secret, tags
             FROM provisioner_keys
             WHERE organization_id = $1
             ORDER BY name ASC",
        )
        .bind(organization_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(rows.into_iter().map(provisioner_key_from_row).collect())
    }

    #[instrument(skip(self), err(level = tracing::Level::WARN))]
    async fn delete_provisioner_key(&self, id: Uuid) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM provisioner_keys WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;

        Ok(result.rows_affected() > 0)
    }
}
