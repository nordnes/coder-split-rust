# Running PostgreSQL Integration Tests

This project includes integration tests that run against a real PostgreSQL 16 database. These tests verify that all `PostgresStore` SQL queries work correctly against the actual schema and migrations.

## Quick Start

```bash
# 1. Start the test database
docker compose -f docker-compose.test.yml up -d

# 2. Wait for PostgreSQL to be ready
docker compose -f docker-compose.test.yml exec test-postgres pg_isready -U coder

# 3. Run integration tests (the #[ignore] tests that need a real DB)
DATABASE_URL="postgres://coder:coder@localhost:5433/coder_test" \
  cargo test -p coder-db -- --ignored

# 4. Run HTTP-level integration tests
TEST_DATABASE_URL="postgres://coder:coder@localhost:5433/coder_test" \
  cargo test -p coder-integration-tests

# 5. Tear down when done
docker compose -f docker-compose.test.yml down -v
```

## How It Works

### Test Isolation

Each integration test uses a shared `setup_store()` helper that:
1. Reads the `DATABASE_URL` environment variable
2. Connects to PostgreSQL and runs all migrations from `crates/coder-db/migrations/`
3. Returns a `PostgresStore` instance ready for testing

The HTTP-level integration tests (`coder-integration-tests`) go further: each test creates an **isolated database** via `CREATE DATABASE`, runs migrations on it, and drops it on cleanup. This means tests are fully parallel-safe.

### Test Conventions

- All PostgresStore integration tests are marked with `#[tokio::test]` and `#[ignore]`
- The `#[ignore]` attribute means `cargo test` skips them by default (no DB needed for CI unit tests)
- Pass `-- --ignored` to run only the integration tests
- Tests gracefully skip (return `Ok(())`) if `DATABASE_URL` is not set

### Environment Variables

| Variable | Description | Default |
|---|---|---|
| `DATABASE_URL` | Connection string for `coder-db` integration tests | _(none — tests skip if unset)_ |
| `TEST_DATABASE_URL` | Connection string for `coder-integration-tests` | _(none — tests skip if unset)_ |
| `CODER_POSTGRES_URL` | Alternative connection string (used by some code paths) | _(none)_ |
| `TEST_PG_PORT` | Host port for the Docker PostgreSQL instance | `5433` |

### Docker Compose Configuration

The `docker-compose.test.yml` file spins up a PostgreSQL 16 instance:
- **User**: `coder`
- **Password**: `coder`
- **Database**: `coder_test`
- **Host port**: `5433` (configurable via `TEST_PG_PORT`)
- Uses `tmpfs` for fast ephemeral storage (data is not persisted across restarts)

Migrations are **not** baked into the Docker image. They are applied at runtime by the test harness (via `store.migrate()` or `coder_db::run_migrations()`), which ensures the test schema always matches the current codebase.

### CI Integration

The GitHub Actions CI workflow (`.github/workflows/ci.yml`) automatically:
1. Starts a PostgreSQL 16 service container
2. Sets `DATABASE_URL`, `CODER_POSTGRES_URL`, and `TEST_DATABASE_URL`
3. Runs `cargo test --locked --workspace` (unit tests)
4. Runs `cargo test --locked --workspace -- --ignored` (integration tests)

If any integration test fails, the CI build fails.

## Troubleshooting

### Tests skip with "DATABASE_URL not set"

Make sure you have the environment variable set:
```bash
export DATABASE_URL="postgres://coder:coder@localhost:5433/coder_test"
```

### Connection refused

Ensure Docker is running and the test database is up:
```bash
docker compose -f docker-compose.test.yml ps
docker compose -f docker-compose.test.yml logs test-postgres
```

### Migration errors

If you see migration errors, the database might have stale schema. Reset it:
```bash
docker compose -f docker-compose.test.yml down -v
docker compose -f docker-compose.test.yml up -d
```

### Port conflicts

If port 5433 is in use, change it:
```bash
TEST_PG_PORT=5434 docker compose -f docker-compose.test.yml up -d
DATABASE_URL="postgres://coder:coder@localhost:5434/coder_test" cargo test -p coder-db -- --ignored
```
