# coder-db — PostgreSQL Store

This crate implements all database access via sqlx. It contains the `PostgresStore`
struct and SQL migrations.

## Key Files

- `src/store.rs` — All SQL queries (~2,900 lines), implements `AppStore` trait
- `src/lib.rs` — Re-exports `PostgresStore` and `DatabaseInitError`
- `migrations/` — SQL migration files (naming: `YYYYMMDDHHMMSS_description.sql`)

## How to Add a Query

1. Add the trait method signature in `crates/coder-core/src/ports.rs` (both in the domain sub-trait and in `AppStore`)
2. Implement it in `src/store.rs` inside the `impl AppStore for PostgresStore` block
3. Follow this pattern exactly:

```rust
#[instrument(skip(self), err(level = tracing::Level::WARN))]
async fn my_query(&self, param: Type) -> Result<ReturnType, StorageError> {
    sqlx::query_as::<_, StoredRow>(
        "SELECT col1, col2 FROM my_table WHERE id = $1",
    )
    .bind(param)
    .fetch_one(&self.pool)
    .await
    .map_err(storage_error)
}
```

## SQL Patterns

| Use Case | sqlx Function |
|----------|--------------|
| Single value | `sqlx::query_scalar::<_, T>(SQL).fetch_one(&pool)` |
| Single row | `sqlx::query_as::<_, Row>(SQL).fetch_one(&pool)` |
| Optional row | `sqlx::query_as::<_, Row>(SQL).fetch_optional(&pool)` |
| Multiple rows | `sqlx::query_as::<_, Row>(SQL).fetch_all(&pool)` |
| INSERT/UPDATE | `sqlx::query(SQL).bind(val).execute(&pool)` |
| Transaction | `let tx = self.pool.begin().await?; ... tx.commit().await?;` |

## Row Types

SQL results are deserialized into private `Stored*Row` structs:
```rust
#[derive(sqlx::FromRow)]
struct StoredUserRow {
    id: Uuid,
    email: String,
    // ...
}
```
Then converted to domain types via `TryFrom` or manual mapping.

## Rules

- **Always** add `#[instrument(skip(self), err(level = tracing::Level::WARN))]`
- **Always** use `.map_err(storage_error)` (private helper)
- **Never** use an ORM — raw SQL only
- Use `IF NOT EXISTS` in migrations for idempotency
