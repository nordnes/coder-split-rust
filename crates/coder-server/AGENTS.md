# coder-server — HTTP Route Handlers

This crate contains all Axum route handlers. It is the primary file you'll edit when porting Go routes.

## Key Files

- `src/app.rs` — All handler functions AND the `build_router()` route tree (~6,500 lines)
- `src/error.rs` — `AppError` type (wraps `StorageError` → HTTP 503/500)

## How to Add a Route

1. Write the handler function in `src/app.rs` (see existing handlers for patterns)
2. Register it in `build_router()` — top-level routes go directly on the `Router`, API routes go inside `.nest("/api/v2", ...)`
3. Add a `FakeStore` method impl and `#[tokio::test]` in the `mod tests` block at the bottom

## Handler Patterns

**Infallible (no DB):**
```rust
async fn my_handler(State(state): State<AppState>) -> Json<MyResponse> {
    Json(MyResponse { ... })
}
```

**Fallible (with DB/auth):**
```rust
async fn my_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let auth = authenticate_request(&state, &headers).await?
        .ok_or_else(|| /* 401 response */)?;
    let data = state.store.my_query().await?;
    Ok((StatusCode::OK, Json(data)).into_response())
}
```

**JSON body extraction:**
```rust
async fn my_handler(
    State(state): State<AppState>,
    payload: Result<Json<MyRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Json(request) = match payload {
        Ok(r) => r,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    // ...
}
```

## AppState

Shared state passed to all handlers via `State(state): State<AppState>`:
- `state.config` — `ServerConfig`
- `state.store` — `Arc<dyn AppStore>` (database)
- `state.audit` — `Arc<dyn AuditSink>`
- `state.auth` — `AuthService` (login, sessions, API keys)
- `state.identity` — `IdentityService` (user CRUD, org membership)

## Error Handling

- Domain service errors → matched by `handle_auth_error()` / `handle_identity_error()` helper fns
- Storage errors → `AppError::Storage` → auto-mapped to 503
- All errors return `Json(ApiResponse { message, detail, validations })`

## Testing

Tests are in the `#[cfg(test)] mod tests` block at the bottom of `app.rs`:
- `FakeStore` — in-memory mock of `AppStore` using `Mutex<HashMap<...>>`
- `MemoryAuditSink` — captures audit events
- `test_state(health_ok: bool)` — creates test `AppState`
- `call(app, request)` — drives the router via `tower::ServiceExt::oneshot`
- `create_and_login(&app)` — helper that bootstraps first user + returns session token
