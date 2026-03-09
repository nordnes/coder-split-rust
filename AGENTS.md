You are an experienced, pragmatic software engineering AI agent. Do not over-engineer a solution when a simple one is possible. Keep edits minimal. If you want an exception to ANY rule, you MUST stop and get permission first.

# Project Overview

`coder-split-rust` is the Rust rewrite of the Coder backend (originally Go). The original Go monorepo is vendored under `coder/`. The Rust workspace incrementally ports API routes, starting with identity, auth, RBAC, audit, and deployment endpoints.

## Technology

- **Language:** Rust (edition 2024, MSRV 1.85, toolchain 1.94.0)
- **Web framework:** Axum 0.8
- **Database:** PostgreSQL via sqlx 0.8 (compile-time query checking, migrations)
- **Async runtime:** Tokio
- **Serialization:** serde / serde_json
- **Auth:** Custom (API keys, sessions, PBKDF2 password hashing)
- **Observability:** tracing + tracing-subscriber
- **HTTP client:** reqwest (rustls)
- **License:** AGPL-3.0-only

# Reference

## Project Structure

```
Cargo.toml              # Workspace root — all deps centralized here
rust-toolchain.toml     # Pinned toolchain + components
apps/
  coderd/               # Main Axum HTTP server binary
  coder-parity/         # Black-box Go↔Rust route comparison tool
crates/
  coder-core/           # Shared types: config, identity, API models, ports, passwords
  coder-server/         # Axum app wiring, route handlers, error types
  coder-db/             # sqlx store (Postgres queries, migrations)
  coder-auth/           # Auth middleware and session logic
  coder-identity/       # Identity/user management
  coder-rbac/           # Role-based access control
  coder-audit/          # Audit log
  coder-workspaces/     # Workspace management (stub)
  coder-provisioner/    # Provisioner integration (stub, has bootstrap scripts)
  coder-connectivity/   # Connectivity checks (stub)
  coder-notifications/  # Notification system (stub)
docs/                   # Design docs, parity matrix, conformance harness
coder/                  # Vendored original Go monorepo (read-only reference)
```

## Key Files

- `crates/coder-server/src/app.rs` — Main route definitions and handlers
- `crates/coder-server/src/error.rs` — Error types
- `crates/coder-db/src/store.rs` — Database store implementation
- `crates/coder-core/src/config.rs` — Configuration types
- `crates/coder-core/src/api.rs` — API request/response models
- `apps/coderd/src/main.rs` — Server entry point

# Essential Commands

```bash
# Build the entire workspace
cargo build

# Build in release mode
cargo build --release

# Run the coderd server
cargo run --bin coderd

# Run all tests (unit tests are in-file with #[cfg(test)])
cargo test

# Run tests for a specific crate
cargo test -p coder-server

# Lint (clippy — strict rules enforced, see below)
cargo clippy --workspace --all-targets

# Format
cargo fmt --all

# Check formatting without modifying
cargo fmt --all -- --check

# Clean build artifacts
cargo clean
```

### Provisioner Bootstrap Scripts

```bash
crates/coder-provisioner/scripts/bootstrap_linux.sh
crates/coder-provisioner/scripts/bootstrap_darwin.sh
```

# Patterns

## Workspace Dependency Management

All dependencies are declared in the root `Cargo.toml` under `[workspace.dependencies]`. Crates reference them with `dep.workspace = true`. **Do not** add dependency versions in individual crate `Cargo.toml` files.

## Strict Clippy Lints

The workspace enforces aggressive clippy lints via `[workspace.lints.clippy]`:

- `unwrap_used = "deny"` — Use `?` or explicit error handling, never `.unwrap()`
- `expect_used = "deny"` — Same; no `.expect()` either
- `panic = "deny"` — No `panic!()`
- `todo = "deny"` — No `todo!()` macros
- `dbg_macro = "deny"` — No `dbg!()` left in code
- `unsafe_code = "forbid"` — No `unsafe` blocks at all

## Rust Lint Policy

Under `[workspace.lints.rust]`:

- `unreachable_pub = "warn"` — Minimize `pub` visibility
- `unused_qualifications = "warn"`

## Error Handling

Use `thiserror` for defining error enums. Propagate with `?`. Never use `.unwrap()` or `.expect()`.

## Testing

Tests live alongside source code in `#[cfg(test)]` modules (no separate `tests/` directories). Key test files:
- `crates/coder-server/src/app.rs`
- `crates/coder-identity/src/lib.rs`
- `crates/coder-provisioner/src/lib.rs`
- `apps/coder-parity/src/main.rs`

## Axum Handlers

Handlers are defined in `crates/coder-server/src/app.rs`. Follow existing patterns for extractors, JSON responses, and error mapping.

# Anti-Patterns

- **No `.unwrap()` / `.expect()` / `panic!()` / `todo!()` / `dbg!()`** — The workspace denies these at the lint level. CI and `cargo clippy` will reject them.
- **No `unsafe` code** — Forbidden workspace-wide.
- **No per-crate dependency versions** — Always use `workspace = true` references.
- **Do not modify files under `coder/`** — This is the vendored Go reference. Treat as read-only.

# Commit and Pull Request Guidelines

## Before Committing

1. `cargo fmt --all` — Format all code.
2. `cargo clippy --workspace --all-targets` — Must pass with zero warnings.
3. `cargo test` — All tests must pass.
4. `cargo build` — Ensure clean compilation.

## Commit Messages

Use the conventional format: `type: message`

Examples from this repo:
```
feat: Rust backend rewrite — auth, identity, RBAC, and operational surfaces
```

Common types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`.

## Pull Requests

- Describe what changed and why.
- Reference any Go routes being ported.
- Ensure the parity tool (`apps/coder-parity`) is updated if new routes are added.
