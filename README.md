# coder-split-rust

`coder-split-rust` is the Rust rewrite workspace for the backend portions of
the original Coder monorepo, which remains checked in under
[`coder/`](./coder/).

This repository now contains an executable Rust foundation for the rewrite:

- a stable Rust workspace with explicit edition, resolver, MSRV, and lint
  policy
- feature-crate seams for auth, identity, RBAC, audit, workspaces,
  provisioners, connectivity, and notifications
- a Postgres-backed store for deployment metadata, organizations, users,
  organization members, auth sessions, and API keys
- an Axum-based `coderd` service with request IDs, tracing, graceful shutdown,
  and a growing identity/admin HTTP surface
- a Rust parity tool that inventories Go routes and runs black-box response
  comparisons between Go and Rust services
- a migration note that maps the initial Rust crates back to the original Go
  packages

## Current scope

The Rust service currently ports the startup and API slice around:

- `/`
- `GET /api/v2`
- `/healthz`
- `/latency-check`
- `GET /api/v2/audit`
- `POST /api/v2/audit/testgenerate`
- `GET /api/v2/auth/scopes`
- `/api/v2/buildinfo`
- `/api/v2/deployment/config`
- `GET /api/v2/deployment/stats`
- `/api/v2/deployment/ssh`
- `GET /api/v2/debug/health`
- `GET /api/v2/debug/health/settings`
- `PUT /api/v2/debug/health/settings`
- `GET /api/v2/experiments`
- `GET /api/v2/experiments/available`
- `GET /api/v2/external-auth`
- `GET /api/v2/external-auth/{externalauth}`
- `DELETE /api/v2/external-auth/{externalauth}`
- `GET /api/v2/external-auth/{externalauth}/device`
- `POST /api/v2/external-auth/{externalauth}/device`
- `GET /external-auth/{externalauth}/callback`
- `GET /gitauth/{externalauth}/callback`
- `GET /api/v2/debug/{user}/debug-link`
- `GET /api/v2/users/first`
- `POST /api/v2/users/first`
- `GET /api/v2/users`
- `POST /api/v2/users`
- `GET /api/v2/users/authmethods`
- `POST /api/v2/users/login`
- `POST /api/v2/users/logout`
- `POST /api/v2/users/validate-password`
- `POST /api/v2/users/otp/request`
- `POST /api/v2/users/otp/change-password`
- `GET /api/v2/users/oauth2/github/device`
- `GET /api/v2/users/oauth2/github/callback`
- `GET /api/v2/users/oidc/callback`
- `GET /api/v2/users/{user}`
- `DELETE /api/v2/users/{user}`
- `GET /api/v2/users/{user}/login-type`
- `GET /api/v2/users/{user}/gitsshkey`
- `PUT /api/v2/users/{user}/gitsshkey`
- `GET /api/v2/users/{user}/autofill-parameters`
- `PUT /api/v2/users/{user}/profile`
- `PUT /api/v2/users/{user}/status/suspend`
- `PUT /api/v2/users/{user}/status/activate`
- `GET /api/v2/users/{user}/appearance`
- `PUT /api/v2/users/{user}/appearance`
- `GET /api/v2/users/{user}/preferences`
- `PUT /api/v2/users/{user}/preferences`
- `PUT /api/v2/users/{user}/password`
- `POST /api/v2/users/{user}/convert-login`
- `GET /api/v2/users/roles`
- `GET /api/v2/users/{user}/roles`
- `PUT /api/v2/users/{user}/roles`
- `GET /api/v2/users/{user}/organizations`
- `GET /api/v2/users/{user}/organizations/{organizationname}`
- `GET /api/v2/organizations`
- `GET /api/v2/organizations/{organization}`
- `GET /api/v2/organizations/{organization}/members`
- `GET /api/v2/organizations/{organization}/paginated-members`
- `GET /api/v2/organizations/{organization}/members/roles`
- `GET /api/v2/organizations/{organization}/members/{user}`
- `POST /api/v2/organizations/{organization}/members/{user}`
- `DELETE /api/v2/organizations/{organization}/members/{user}`
- `PUT /api/v2/organizations/{organization}/members/{user}/roles`
- `POST /api/v2/users/{user}/keys`
- `GET /api/v2/users/{user}/keys/{keyid}`
- `DELETE /api/v2/users/{user}/keys/{keyid}`
- `PUT /api/v2/users/{user}/keys/{keyid}/expire`
- `GET /api/v2/users/{user}/keys/tokens`
- `POST /api/v2/users/{user}/keys/tokens`
- `GET /api/v2/users/{user}/keys/tokens/tokenconfig`
- `GET /api/v2/users/{user}/keys/tokens/{keyname}`

The current auth slice includes:

- top-level server-root parity for slim builds at `/` plus API-root parity at
  `GET /api/v2`
- first-user bootstrap against Postgres-backed `users`, `organizations`,
  `organization_members`, `auth_sessions`, and `api_keys`
- PBKDF2-SHA256 password hashes compatible with the original Go format
- opaque session-token issuance and request-header authentication for the
  authenticated user lookup
- owner-only user creation, soft delete, site-role listing, and site-role
  mutation
- self and owner profile/status/settings flows for login type, profile,
  suspend/activate, appearance, preferences, and password change
- password validation plus one-time-passcode request/reset flows backed by
  persisted reset state
- owner-only organization-role listing and organization-member role mutation
- user organization lookups and soft-delete revocation of sessions and API keys
- paginated organization member listings
- deterministic disabled-route surfaces for GitHub/OIDC login conversion and
  callback entrypoints until provider configuration is ported
- default OSS operational surfaces for the public scope catalog, experiments,
  store-backed deployment stats, deployment health and persisted health
  settings, audit-log query/test generation, external-auth provider discovery
  plus link lookup/deletion, callback/device exchange flows, autofill
  parameter lookup, and OIDC debug-link fallback behavior
- cached deployment stats snapshots modeled after the Go metrics cache and fed
  by Rust-side workspace, workspace-build, provisioner-job, and
  workspace-agent-stat writers
- cached debug health reports with live access-url `/healthz`, `/latency-check`,
  configured DERP node probes, persisted workspace-proxy health, and persisted
  provisioner-daemon health
- persisted Git SSH key generation/storage with OpenSSH-compatible Ed25519
  keypairs for self and owner lookups/regeneration
- external-auth read-path refresh/validation, callback/device token
  persistence, installation metadata refresh, and revoke-on-unlink behavior
- request-actor RBAC checks for self vs owner access and owner-scoped
  organization management plus owner/auditor access to operational routes
- structured audit events for login/logout, first-user bootstrap, user/member
  changes, API-key creation/deletion/expiration, health-settings updates, and
  external-auth unlink operations

Everything else in [`coder/`](./coder/) remains the source of truth until it
is migrated into Rust crates.

## Run

```bash
cargo run -p coderd -- server \
  --postgres-url postgres://postgres:postgres@127.0.0.1:5432/coder \
  --access-url http://127.0.0.1:3000
```

## Quality gates

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

## Parity Tooling

```bash
cargo run -p coder-parity -- inventory --go-root coder --rust-root . --scope oss
cargo run -p coder-parity -- compare \
  --corpus docs/conformance-corpus/server-smoke.json \
  --go-base-url http://127.0.0.1:3001 \
  --rust-base-url http://127.0.0.1:3000
```

## Layout

- `apps/coder-parity`: route inventory and black-box conformance tooling
- `apps/coderd`: binary entry point and process bootstrap
- `crates/coder-auth`: auth/session feature boundary
- `crates/coder-identity`: user/org feature boundary
- `crates/coder-rbac`: RBAC feature boundary
- `crates/coder-audit`: audit feature boundary
- `crates/coder-workspaces`: workspace/template/build feature boundary
- `crates/coder-provisioner`: provisioner/job feature boundary
- `crates/coder-connectivity`: agents/tailnet/workspace-apps feature boundary
- `crates/coder-notifications`: notification/inbox/webpush feature boundary
- `crates/coder-core`: shared config, API models, and service contracts
- `crates/coder-db`: Postgres store and SQL migrations
- `crates/coder-server`: HTTP router, middleware, and handlers
- `docs/conformance-harness.md`: parity harness usage
- `docs/parity-matrix.md`: generated OSS route parity inventory
- `docs/backend-rewrite.md`: migration map from Go packages to Rust crates
