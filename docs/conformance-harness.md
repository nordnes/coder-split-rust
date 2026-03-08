# Conformance Harness

The Rust rewrite now includes a parity tool in `apps/coder-parity`.

## Inventory

Generate a scoped route matrix from `coder/coderd`, `coder/codersdk`, and the
current Rust crates:

```bash
cargo run -p coder-parity -- inventory \
  --go-root coder \
  --rust-root . \
  --scope oss \
  --output docs/parity-matrix.md
```

The inventory now:

- filters Go handlers by scope: `oss`, `enterprise`, or `all`
- records the documented route path and the real live path
- treats `GET /api/v2` as the API root for `@Router / [get]`
- keeps server `GET /` out of the route matrix so it can be tested separately

Each Go route/method pair is marked `ported` or `missing` by matching
normalized live-path templates and HTTP methods against the Rust router.

## Live Compare

Compare Go and Rust responses from the same request corpus:

```bash
cargo run -p coder-parity -- compare \
  --corpus docs/conformance-corpus/server-smoke.json \
  --go-base-url http://127.0.0.1:3001 \
  --rust-base-url http://127.0.0.1:3000
```

Reusable corpus suites now live under `docs/conformance-corpus/`:

- `server-smoke.json`
- `auth-admin.json`
- `workspace-core.json`
- `connectivity.json`
- `notifications.json`

`server-smoke.json` is the default empty-deployment harness and compares:

- `GET /`
- `GET /api/v2`
- `GET /healthz`
- `GET /api/v2/users/first`

Current support is intentionally narrow and foundation-oriented:

- HTTP requests
- exact status comparison
- optional header comparison with ignore lists
- optional cookie comparison
- JSON, text, empty, or ignored body comparison

The corpus format is JSON and is meant to grow with later waves to cover SSE,
websocket, and RPC parity.
