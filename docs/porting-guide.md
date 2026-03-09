# Porting Guide: Go → Rust Walkthrough

This guide walks through two already-ported routes to demonstrate the
vertical-slice porting pattern. Use this as a template when porting new routes.

## The Vertical Slice

Every ported route touches these layers, bottom-up:

| Layer | File | What to Define |
|-------|------|---------------|
| Migration | `crates/coder-db/migrations/YYYYMMDDHHMMSS_*.sql` | Tables, enums, indexes |
| Domain types | `crates/coder-core/src/identity.rs` (or relevant module) | Input structs, record structs, error enums |
| API types | `crates/coder-core/src/api.rs` | Request/Response structs with serde derives |
| Port trait | `crates/coder-core/src/ports.rs` | `async fn` in the relevant store trait + `AppStore` |
| DB impl | `crates/coder-db/src/store.rs` | `impl AppStore for PostgresStore` with sqlx queries |
| Handler | `crates/coder-server/src/app.rs` | Handler function |
| Route | `crates/coder-server/src/app.rs` `build_router()` | `.route("/path", get(handler))` |
| Tests | `crates/coder-server/src/app.rs` `mod tests` | Add `FakeStore` impl + `#[tokio::test]` |

## Example 1: `GET /api/v2/buildinfo` (No Database)

This is the simplest kind of route — pure computation, no DB, no auth.

### Go Source

The Go handler lives in `coder/coderd/deployment.go`. It reads build metadata
and returns a JSON response. The SDK model is in `coder/codersdk/deployment.go`
(`BuildInfoResponse` struct).

### Rust Implementation

**API type** (`crates/coder-core/src/api.rs` line ~62):
```rust
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct BuildInfoResponse {
    pub external_url: String,
    pub version: String,
    pub dashboard_url: String,
    pub telemetry: bool,
    pub workspace_proxy: bool,
    pub agent_api_version: String,
    pub provisioner_api_version: String,
    pub upgrade_message: String,
    pub deployment_id: String,
}
```

Response-only types derive `Serialize`. Request types derive `Deserialize`.
Both derive both when they appear in tests or round-trip scenarios.

**Domain type** (`crates/coder-core/src/build_info.rs` line ~10):
```rust
pub struct BuildMetadata { ... }

impl BuildMetadata {
    pub fn to_response(&self, deployment_id: Uuid, access_url: &Url, telemetry_enabled: bool)
        -> BuildInfoResponse { ... }
}
```

Internal metadata types are separate from API response types. A `to_response()`
method converts domain → API.

**Handler** (`crates/coder-server/src/app.rs` line ~417):
```rust
async fn build_info(State(state): State<AppState>) -> Json<coder_core::BuildInfoResponse> {
    Json(state.build_metadata.to_response(
        state.deployment_id,
        &state.config.access_url,
        state.config.telemetry_enabled,
    ))
}
```

Infallible handlers return `Json<T>` directly (no `Result`).

**Route registration** (`build_router()` line ~248):
```rust
.route("/buildinfo", get(build_info))
```

### Key Takeaway

For routes that don't touch the database or require auth, you only need:
1. API response type in `coder-core/src/api.rs`
2. Handler function in `coder-server/src/app.rs`
3. Route in `build_router()`

---

## Example 2: `GET/POST /api/v2/users/first` (Full Vertical Slice)

This route checks whether the first user exists (GET) and creates it (POST).
It demonstrates the full pattern: database, auth service, audit logging, error handling.

### Go Source

- Handler: `coder/coderd/users.go` — `postFirstUser()` function
- SDK models: `coder/codersdk/users.go` — `CreateFirstUserRequest`, `CreateFirstUserResponse`
- SQL: `coder/coderd/database/queries/users.sql` — the INSERT query

### Rust Implementation — Bottom Up

**Step 1: Migration** (`crates/coder-db/migrations/20260307170000_identity_bootstrap.sql`):
```sql
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    username VARCHAR(100) NOT NULL,
    name VARCHAR(128) NOT NULL DEFAULT '',
    hashed_password BYTEA NOT NULL DEFAULT '\x',
    ...
);
```
Naming convention: `YYYYMMDDHHMMSS_description.sql`. Use `IF NOT EXISTS` for idempotency.

**Step 2: Domain types** (`crates/coder-core/src/identity.rs` line ~306):
```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateFirstUserInput {
    pub email: String,
    pub username: String,
    pub name: String,
    pub password_hash: String,  // Pre-hashed before reaching the store
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirstUserRecord {
    pub user_id: Uuid,
    pub organization_id: Uuid,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CreateFirstUserStoreError {
    #[error("the initial user has already been created")]
    AlreadyExists,
    #[error("{0}")]
    Storage(#[from] StorageError),
}
```

Input types carry pre-processed data (e.g., `password_hash`, not the raw
password). Error enums use `thiserror` with domain-specific variants.

**Step 3: API types** (`crates/coder-core/src/api.rs` line ~758):
```rust
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CreateFirstUserRequest {
    pub email: String,
    pub username: String,
    #[serde(default)]
    pub name: String,
    pub password: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct CreateFirstUserResponse {
    pub user_id: Uuid,
    pub organization_id: Uuid,
}
```

**Step 4: Port trait** (`crates/coder-core/src/ports.rs` line ~818):
```rust
pub trait AppStore: DeploymentStore + Send + Sync {
    async fn first_user_exists(&self) -> Result<bool, StorageError>;
    async fn create_first_user(
        &self, user: CreateFirstUserInput,
    ) -> Result<FirstUserRecord, CreateFirstUserStoreError>;
    // ...
}
```

Every store method goes in the `AppStore` trait (and optionally in a narrower
domain trait like `AuthStore`). All traits require `Send + Sync`.

**Step 5: DB implementation** (`crates/coder-db/src/store.rs` line ~328):
```rust
#[instrument(skip(self), err(level = tracing::Level::WARN))]
async fn first_user_exists(&self) -> Result<bool, StorageError> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM users WHERE deleted = false AND is_system = false)",
    )
    .fetch_one(&self.pool)
    .await
    .map_err(storage_error)
}
```

SQL patterns:
- `sqlx::query_scalar::<_, T>(SQL)` for single-value returns
- `sqlx::query(SQL).bind(val).execute(&pool)` for INSERT/UPDATE
- `sqlx::query_as::<_, RowType>(SQL)` for typed multi-column reads
- `.map_err(storage_error)` on every query (private helper)
- `#[instrument(skip(self), err(...))]` on every method
- Transactions via `self.pool.begin()` / `tx.commit()`

**Step 6: Handler** (`crates/coder-server/src/app.rs` line ~965):
```rust
async fn get_first_user(State(state): State<AppState>) -> Result<Response, AppError> {
    let exists = state.auth.first_user_exists().await?;
    let body = if exists {
        ApiResponse::ok("The initial user has already been created!")
    } else {
        ApiResponse::ok("The initial user has not been created!")
    };
    let status = if exists { StatusCode::OK } else { StatusCode::NOT_FOUND };
    Ok((status, build_version_headers(&state.build_metadata.version), Json(body)).into_response())
}

async fn post_first_user(
    State(state): State<AppState>,
    payload: Result<Json<CreateFirstUserRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Json(request) = match payload {
        Ok(r) => r,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    match state.auth.create_first_user(&request).await {
        Ok(created) => {
            record_audit(&state, AuditAction::Create, ResourceKind::User,
                None, Some(created.user_id.to_string()), "bootstrapped first user").await;
            Ok((StatusCode::CREATED, Json(CreateFirstUserResponse {
                user_id: created.user_id,
                organization_id: created.organization_id,
            })).into_response())
        }
        Err(error) => handle_auth_error(error),
    }
}
```

Handler patterns:
- Extract state: `State(state): State<AppState>`
- Fallible handlers return `Result<Response, AppError>`
- JSON body: `Result<Json<T>, JsonRejection>` for graceful parse errors
- Audit logging after successful mutations (fire-and-forget)
- Domain errors handled by `handle_auth_error()` / `handle_identity_error()`

**Step 7: Route** (`build_router()` line ~298):
```rust
.route("/users/first", get(get_first_user).post(post_first_user))
```

Multiple methods on one path are chained.

**Step 8: Tests** (`crates/coder-server/src/app.rs` `mod tests` line ~4780):
```rust
#[tokio::test]
async fn first_user_endpoint_returns_404_and_build_version_header_when_missing()
-> Result<(), Box<dyn Error>> {
    let app = build_router(test_state(true)?);
    let response = call(app, request(Method::GET, "/api/v2/users/first")?).await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    Ok(())
}
```

Test pattern: `build_router(test_state(true)?)` → `call(app, request(...))` →
assert status + body. Uses `FakeStore` (in-memory) and `tower::ServiceExt::oneshot`.

---

## Quick Reference: Adding a New Route

1. Check `docs/parity-matrix.md` for missing routes
2. Read the Go handler in `coder/coderd/<file>.go`
3. Read the Go SDK model in `coder/codersdk/<file>.go`
4. Read the SQL in `coder/coderd/database/queries/<file>.sql`
5. Add migration in `crates/coder-db/migrations/` (if new tables needed)
6. Add domain types in `crates/coder-core/src/identity.rs` (or relevant module)
7. Add API types in `crates/coder-core/src/api.rs`
8. Add trait method in `crates/coder-core/src/ports.rs` (`AppStore` + relevant sub-trait)
9. Implement in `crates/coder-db/src/store.rs` (with `#[instrument]`)
10. Add handler in `crates/coder-server/src/app.rs`
11. Register route in `build_router()`
12. Add `FakeStore` method impl + test
13. Run: `cargo fmt --all && cargo clippy --workspace --all-targets && cargo test`

## Conventions Cheat Sheet

| What | Convention |
|------|-----------|
| Response-only types | `#[derive(Serialize)]` |
| Request types | `#[derive(Deserialize)]` (add `Serialize` if used in tests) |
| Optional fields | `#[serde(default)]` or `Option<T>` with `skip_serializing_if` |
| Store errors | `StorageError { Unavailable, InvalidData }` for generic; domain-specific enum for business logic |
| SQL queries | Raw SQL in `sqlx::query*()`, always `.map_err(storage_error)` |
| Tracing | `#[instrument(skip(self), err(level = tracing::Level::WARN))]` on store methods |
| Auth flow | `authenticate_request(&state, &headers)` → `AuthenticatedRequest { user, actor }` |
| RBAC checks | Service methods take `&Actor`, call `actor.can_xxx()` |
| Audit logging | `record_audit(state, action, resource, actor, target_id, summary)` — fire-and-forget |
| Tests | In-file `#[cfg(test)]`, `FakeStore` + `tower::oneshot`, `Box<dyn Error>` return type |
