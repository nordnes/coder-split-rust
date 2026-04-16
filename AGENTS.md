You are an experienced, pragmatic software engineering AI agent. Do not over-engineer a solution when a simple one is possible. Keep edits minimal. If you want an exception to ANY rule, you MUST stop and get permission first.

# Mission

This repo is a **complete Rust rewrite of the Coder backend**. The objective is to reproduce ALL backend features from the original Go codebase (`https://github.com/coder/coder`) in Rust, achieving full route and behavior parity.

**Current progress: 326 of 326 routes ported (100%). OSS: 229/229. Enterprise: 87/87.**

See the generated parity matrices for full route-by-route status:
- [`docs/parity-matrix.md`](docs/parity-matrix.md) — OSS routes
- [`docs/parity-matrix-enterprise.md`](docs/parity-matrix-enterprise.md) — Enterprise routes
- [`docs/parity-matrix-all.md`](docs/parity-matrix-all.md) — Combined (OSS + Enterprise)

# The Go Reference (`coder/`)

`coder/` is a **git submodule** pointing to a fork of the original Go monorepo ([`nordnes/coder`](https://github.com/nordnes/coder)). It is the primary reference for understanding what each route does. After cloning, run `git submodule update --init coder` if the directory is empty.

## ⚠️ CRITICAL RULES for `coder/`

- **NEVER modify any file under `coder/`** — it is read-only reference material
- **NEVER commit changes to `coder/`**
- Files under `coder/` are Go code; your Rust work goes in `crates/` and `apps/`

## Navigating the Go Source

- OSS route handlers: `coder/coderd/*.go` (e.g., `users.go`, `workspaces.go`, `templates.go`)
- Enterprise route handlers: `coder/enterprise/coderd/*.go` (e.g., `appearance.go`, `licenses.go`)
- SDK/API models: `coder/codersdk/*.go`
- Enterprise SDK models: `coder/enterprise/codersdk/*.go` (if present)
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

## ✅ OSS Routes: Fully Ported (229/229, 100%)

All OSS API routes have been ported to Rust. See `docs/parity-matrix.md` for the full matrix.

## ✅ Enterprise Routes: Fully Ported (87/87, 100%)

All enterprise routes have been ported to Rust. See `docs/parity-matrix-enterprise.md` for the full matrix. Key enterprise areas include:
- Appearance, licenses, entitlements, SCIM
- Groups, template ACLs, workspace quotas, workspace proxies
- Provisioner keys, IDP sync (groups/roles/organization)
- AI bridge (interceptions, models), connection log
- OAuth2 provider, custom roles, prebuilds, replicas
- Workspace sharing, quiet hours

Some workspace proxy internal routes remain at stub depth (accept requests but return minimal responses). See `crates/coder-server/PARITY_MATRIX.md` for the implementation-depth inventory.

# Crate Architecture (Go → Rust Mapping)

| Go Area | Rust Crate | Status |
|---------|------------|--------|
| `coderd/userauth.go`, sessions, API keys, OIDC, OAuth2 | `crates/coder-auth` | Active — password auth, sessions, external auth, OAuth2/OIDC callbacks |
| `coderd/users.go`, organizations, RBAC | `crates/coder-identity` | Active — full user CRUD, org membership, roles |
| `coderd/rbac/*` | `crates/coder-rbac` | Active — actor checks, role assignment, custom roles |
| `coderd/audit/*` | `crates/coder-audit` | Active — structured audit sink with full event coverage |
| Templates, workspaces, builds, presets | `crates/coder-workspaces` | Active — full template/workspace CRUD, builds, presets, scheduling |
| Provisioner APIs and background jobs | `crates/coder-provisioner` | Active — provisioner daemon serve, jobs, keys, init scripts |
| Notifications, inbox, webpush | `crates/coder-notifications` | Active — webhook + inbox dispatch, webpush, settings |
| DERP, tailnet, agent RPC, workspace apps | `crates/coder-connectivity` | Active — health checks, SSH keys, agent endpoints, workspace apps |
| Shared SQL repositories and migrations | `crates/coder-db` | Active — full query coverage across all domains |
| HTTP composition and cross-cutting middleware | `crates/coder-server` | Active — 400+ route handlers covering all 326 Go routes |
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
- `docs/parity-matrix.md` — Generated OSS route parity status
- `docs/parity-matrix-enterprise.md` — Generated Enterprise route parity status
- `docs/parity-matrix-all.md` — Generated combined route parity status
- `docs/backend-rewrite.md` — Migration map and methodology
- `Makefile` — Convenience targets for submodule update and parity generation

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

# Regenerate all parity matrices (requires Go source in coder/)
make parity-refresh
# Or individually:
cargo run -p coder-parity -- inventory --go-root coder --rust-root . --scope oss --output docs/parity-matrix.md
cargo run -p coder-parity -- inventory --go-root coder --rust-root . --scope enterprise --output docs/parity-matrix-enterprise.md
cargo run -p coder-parity -- inventory --go-root coder --rust-root . --scope all --output docs/parity-matrix-all.md

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
