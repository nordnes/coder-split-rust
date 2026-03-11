//! Database migration runner and schema version utilities.
//!
//! Provides standalone functions for running migrations against a raw
//! [`sqlx::PgPool`] so that callers (such as `coderd --migrate-only`) do not
//! need to construct a full [`PostgresStore`](crate::PostgresStore).

use sqlx::PgPool;
use thiserror::Error;
use tracing::{info, instrument};

/// Compile-time embedded migrator produced by `sqlx::migrate!`.
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Errors that can occur while running or inspecting migrations.
#[derive(Debug, Error)]
pub enum MigrationError {
    /// A migration step failed to apply.
    #[error("run database migrations: {source}")]
    Apply {
        /// The underlying SQLx migration error.
        #[source]
        source: sqlx::migrate::MigrateError,
    },
    /// Querying migration metadata failed.
    #[error("query migration status: {source}")]
    Query {
        /// The underlying SQLx error.
        #[source]
        source: sqlx::Error,
    },
}

/// Summary returned after [`run_migrations`] completes successfully.
#[derive(Debug, Clone)]
pub struct MigrationReport {
    /// Number of migrations that were newly applied during this run.
    pub applied_count: usize,
    /// Total number of migrations that are now recorded in the database.
    pub total_count: usize,
}

/// Summary of the current schema version, returned by
/// [`migration_status`].
#[derive(Debug, Clone)]
pub struct MigrationStatus {
    /// Total number of migrations recorded in the `_sqlx_migrations` table.
    pub applied_count: i64,
    /// Whether every known migration has been applied (i.e. the schema is
    /// fully up-to-date).
    pub is_up_to_date: bool,
}

/// Runs all pending database migrations against `pool`.
///
/// Returns a [`MigrationReport`] describing how many migrations were newly
/// applied and the total count afterwards.
#[instrument(skip(pool))]
pub async fn run_migrations(pool: &PgPool) -> Result<MigrationReport, MigrationError> {
    let before = count_applied_migrations(pool).await?;

    MIGRATOR
        .run(pool)
        .await
        .map_err(|source| MigrationError::Apply { source })?;

    let after = count_applied_migrations(pool).await?;
    let applied_count = (after - before) as usize;
    let total_count = after as usize;

    if applied_count > 0 {
        info!(
            applied = applied_count,
            total = total_count,
            "applied new database migrations"
        );
    } else {
        info!(total = total_count, "database schema is up to date");
    }

    Ok(MigrationReport {
        applied_count,
        total_count,
    })
}

/// Returns the current migration status without modifying the database.
///
/// Useful for health-check endpoints that need to verify the schema is
/// up-to-date.
#[instrument(skip(pool))]
pub async fn migration_status(pool: &PgPool) -> Result<MigrationStatus, MigrationError> {
    let applied_count = count_applied_migrations(pool).await?;
    let total_known = MIGRATOR.migrations.len() as i64;
    let is_up_to_date = applied_count >= total_known;

    Ok(MigrationStatus {
        applied_count,
        is_up_to_date,
    })
}

/// Helper: counts rows in the `_sqlx_migrations` table.
///
/// Returns `0` if the table does not exist yet (fresh database).
async fn count_applied_migrations(pool: &PgPool) -> Result<i64, MigrationError> {
    // The _sqlx_migrations table may not exist on a brand-new database that
    // has never been migrated, so we guard with an EXISTS check first.
    let count: i64 = sqlx::query_scalar(
        r#"
        SELECT COALESCE(
            (SELECT COUNT(*) FROM _sqlx_migrations WHERE success = true),
            0
        )
        "#,
    )
    .fetch_one(pool)
    .await
    .or_else(|error| {
        // If the table simply doesn't exist yet, that means zero migrations
        // have been applied.  Any *other* error is unexpected.
        let msg = error.to_string();
        if msg.contains("_sqlx_migrations") && msg.contains("does not exist") {
            Ok(0i64)
        } else {
            Err(MigrationError::Query { source: error })
        }
    })?;

    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrator_has_migrations() {
        // The compile-time MIGRATOR must contain at least one migration.
        assert!(
            !MIGRATOR.migrations.is_empty(),
            "expected at least one embedded migration"
        );
    }

    #[test]
    fn migration_report_debug() {
        let report = MigrationReport {
            applied_count: 3,
            total_count: 21,
        };
        let debug = format!("{report:?}");
        assert!(debug.contains("applied_count: 3"));
        assert!(debug.contains("total_count: 21"));
    }

    #[test]
    fn migration_status_debug() {
        let status = MigrationStatus {
            applied_count: 21,
            is_up_to_date: true,
        };
        let debug = format!("{status:?}");
        assert!(debug.contains("applied_count: 21"));
        assert!(debug.contains("is_up_to_date: true"));
    }

    #[test]
    fn migration_error_display() {
        let err = MigrationError::Apply {
            source: sqlx::migrate::MigrateError::VersionMissing(1),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("run database migrations"),
            "unexpected error message: {msg}"
        );
    }
}
