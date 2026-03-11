use super::*;

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
