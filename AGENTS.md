You are an experienced, pragmatic software engineering AI agent. Do not over-engineer a solution when a simple one is possible. Keep edits minimal. If you want an exception to ANY rule, you MUST stop and get permission first.

# Mission

This repo is a **complete Rust rewrite of the Coder backend**. The objective is to reproduce ALL backend features from the original Go codebase (`https://github.com/coder/coder`) in Rust, achieving full route and behavior parity.

**Current progress: 72 of 229 OSS routes ported (31%).**

See [`docs/parity-matrix.md`](docs/parity-matrix.md) for full route-by-route status.

# The Go Reference (`coder/`)

`coder/` is a **git submodule** pointing to a fork of the original Go monorepo ([`nordnes/coder`](https://github.com/nordnes/coder)). It is the primary reference for understanding what each route does. After cloning, run `git submodule update --init coder` if the directory is empty.

## ⚠️ CRITICAL RULES for `coder/`

- **NEVER modify any file under `coder/`** — it is read-only reference material
- **NEVER commit changes to `coder/`**
- Files under `coder/` are Go code; your Rust work goes in `crates/` and `apps/`

## Navigating the Go Source

- Route handlers: `coder/coderd/*.go` (e.g., `users.go`, `workspaces.go`, `templates.go`)
- SDK/API models: `coder/codersdk/*.go`
- Database queries: `coder/coderd/database/queries/*.sql`
- Database models: `coder/coderd/database/*.go`
- Migrations: `coder/coderd/database/migrations/`

# How to Port a Route (Vertical Slice Method)

1. Find the missing route in `docs/parity-matrix.md`
2. Read the Go handler in `coder/coderd/<file>.go`
3. Read the SDK models in `coder/codersdk/<file>.go`
4. Read the SQL queries in `coder/coderd/database/queries/<file>.sql`
5. Define Rust domain types / API models in `coder-core` or the appropriate feature crate
6. Port storage access and migrations into `coder-db`
7. Port the HTTP handler into `coder-server` (or the appropriate feature crate)
8. Add tests in `#[cfg(test)]` modules alongside the code
9. Run validation: `cargo fmt --all && cargo clippy --workspace --all-targets && cargo test`

# What's Been Ported vs What Remains

## ✅ Ported (72 routes, 31%)

- User management — CRUD, profiles, roles, status, passwords, appearance, preferences
- Authentication — login, logout, first user bootstrap, API keys/tokens, OTP, external auth
- Organizations — list, get, members, paginated members, member roles
- Deployment ops — config, stats, SSH, health checks, health settings
- Audit logging — list, test generate
- Misc — build info, experiments, CSP reports, init scripts, update check, latency check

## ❌ Remaining (157 routes, 69%)

| Domain | Routes | Go Source Files |
|--------|--------|-----------------|
| Templates & Versions | 33 | `templates.go`, `templateversions.go` |
| Workspaces & Builds | 32 | `workspaces.go`, `workspacebuilds.go` |
| Workspace Agents | 20 | `workspaceagents.go`, `workspaceagentsrpc.go` |
| Debug & Observability | 11 | `debug.go` |
| AI Tasks | 10 | `aitasks.go` |
| Notifications & Inbox | 13 | `notifications.go`, `inboxnotifications.go`, `webpush.go` |
| Insights & Analytics | 5 | `insights.go` |
| Chats | 5 | `chats.go` |
| Files | 2 | `files.go` |
| Other (params, presets, provisioner jobs, deprecated) | 26 | various |

# Crate Architecture (Go → Rust Mapping)

| Go Area | Rust Crate | Status |
|---------|------------|--------|
| `coderd/userauth.go`, sessions, API keys, OIDC, OAuth2 | `crates/coder-auth` | Partial — password auth, sessions, external auth done |
| `coderd/users.go`, organizations, RBAC | `crates/coder-identity` | Partial — user CRUD, org membership done |
| `coderd/rbac/*` | `crates/coder-rbac` | Partial — basic actor checks |
| `coderd/audit/*` | `crates/coder-audit` | Partial — structured audit sink |
| Templates, workspaces, builds, presets | `crates/coder-workspaces` | Stub — only deployment stats cache |
| Provisioner APIs and background jobs | `crates/coder-provisioner` | Stub — only init scripts |
| Notifications, inbox, webpush | `crates/coder-notifications` | Stub — placeholder only |
| DERP, tailnet, agent RPC, workspace apps | `crates/coder-connectivity` | Partial — health checks, SSH keys |
| Shared SQL repositories and migrations | `crates/coder-db` | Active — user/org/auth/audit queries |
| HTTP composition and cross-cutting middleware | `crates/coder-server` | Active — 72 route handlers |
| Shared types: config, identity, API models, passwords | `crates/coder-core` | Active — foundational types |

# Technology

- **Language:** Rust (edition 2024, MSRV 1.85, toolchain 1.94.0)
- **Web framework:** Axum 0.8
- **Database:** PostgreSQL via sqlx 0.8 (compile-time query checking, migrations)
- **Async runtime:** Tokio
- **Serialization:** serde / serde_json
- **Auth:** Custom (API keys, sessions, PBKDF2 password hashing)
- **Observability:** tracing + tracing-subscriber
- **HTTP client:** reqwest with rustls
- **License:** AGPL-3.0-only

# Project Structure

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
coder/                  # ⛔ Original Go monorepo — READ-ONLY REFERENCE
```

# Key Files

- `crates/coder-server/src/app.rs` — All route definitions and handlers (6,566 lines)
- `crates/coder-server/src/error.rs` — Error types
- `crates/coder-db/src/store.rs` — Database store implementation (2,893 lines)
- `crates/coder-core/src/ports.rs` — Port/trait definitions (2,081 lines)
- `crates/coder-core/src/api.rs` — API request/response models (1,528 lines)
- `crates/coder-core/src/config.rs` — Configuration types
- `apps/coderd/src/main.rs` — Server entry point
- `docs/parity-matrix.md` — Generated route parity status (source of truth)
- `docs/backend-rewrite.md` — Migration map and methodology

# Essential Commands

```bash
# Build the entire workspace
cargo build

# Run the coderd server
cargo run --bin coderd

# Run all tests
cargo test

# Lint (strict rules enforced)
cargo clippy --workspace --all-targets

# Format
cargo fmt --all

# Check formatting without modifying
cargo fmt --all -- --check

# Regenerate the parity matrix (requires Go source in coder/)
cargo run -p coder-parity -- inventory --go-root coder --rust-root . --scope oss --output docs/parity-matrix.md

# Run tests for a specific crate
cargo test -p coder-server
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
- **Do not create separate `tests/` directories** — Use `#[cfg(test)]` in-file.

# Commit and PR Guidelines

## Before Committing

1. `cargo fmt --all` — Format all code.
2. `cargo clippy --workspace --all-targets` — Must pass with zero warnings.
3. `cargo test` — All tests must pass.
4. `cargo build` — Ensure clean compilation.

## Commit Messages

Use the conventional format: `type: message`

Common types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`.

## Pull Requests

- Describe what changed and why.
- Reference any Go routes being ported.
- Ensure the parity tool (`apps/coder-parity`) is updated if new routes are added.
