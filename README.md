# coder-split-rust

**Complete Rust rewrite of the [Coder](https://github.com/coder/coder) backend.**

Goal: reproduce all backend features, routes, and behavior from the original Go
monorepo in Rust, achieving full API parity. The original Go source is available
under [`coder/`](./coder/) as a read-only git submodule (fork of [`coder/coder`](https://github.com/coder/coder)).

**Status: 326 of 326 API routes ported (100%).** OSS: 229/229. Enterprise: 87/87.

See the generated parity matrices for full route-by-route status:
- [`docs/parity-matrix.md`](./docs/parity-matrix.md) — OSS routes
- [`docs/parity-matrix-enterprise.md`](./docs/parity-matrix-enterprise.md) — Enterprise routes
- [`docs/parity-matrix-all.md`](./docs/parity-matrix-all.md) — Combined (OSS + Enterprise)

This repository contains an executable Rust foundation for the rewrite:

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

All 326 Go API routes (229 OSS + 87 Enterprise) have been ported to Rust. The
Rust router registers ~400 route/method pairs (the difference accounts for
Rust-only convenience endpoints, aliases, and WebSocket variants).

For the full route-by-route breakdown, see the generated parity matrices listed
above. A handful of routes remain at stub depth (returning 501 or simplified
responses) — see [`crates/coder-server/PARITY_MATRIX.md`](./crates/coder-server/PARITY_MATRIX.md)
for the implementation-depth inventory.

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
# Regenerate all parity matrices (requires Go source in coder/)
make parity-refresh

# Or individually:
cargo run -p coder-parity -- inventory --go-root coder --rust-root . --scope oss --output docs/parity-matrix.md
cargo run -p coder-parity -- inventory --go-root coder --rust-root . --scope enterprise --output docs/parity-matrix-enterprise.md
cargo run -p coder-parity -- inventory --go-root coder --rust-root . --scope all --output docs/parity-matrix-all.md

# Black-box response comparison
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
- `docs/parity-matrix-enterprise.md`: generated Enterprise route parity inventory
- `docs/parity-matrix-all.md`: generated combined (OSS + Enterprise) route parity inventory
- `docs/backend-rewrite.md`: migration map from Go packages to Rust crates
- `Makefile`: convenience targets for submodule update and parity generation
