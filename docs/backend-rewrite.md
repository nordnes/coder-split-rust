# Backend Rewrite Map

This document records the first concrete Rust slice and how it lines up with
the original Go implementation in [`coder/`](../coder/).

## Ported now

| Go source | Rust target | Status |
| --- | --- | --- |
| `coderd` route inventory and `codersdk` client inventory | `apps/coder-parity` | Ported as a scoped parity inventory tool with OSS vs enterprise filtering and live-path tracking |
| Go-vs-Rust black-box response comparisons | `apps/coder-parity` | Ported as the initial conformance harness with reusable corpus suites and corrected `/` vs `/api/v2` handling |
| `cli/server.go` | `apps/coderd` | Ported for process bootstrap, config parsing, DB startup, tracing, and graceful shutdown |
| top-level slim-build server root plus `coderd/apiroot.go` | `crates/coder-server` | Ported for `GET /` and `GET /api/v2` as separate contracts |
| `coderd/latencycheck.go` | `crates/coder-server` | Ported |
| `coderd/deployment.go` build info and deployment config surface | `crates/coder-server` + `crates/coder-core` + `crates/coder-db` + `crates/coder-workspaces` | Ported for `buildinfo`, `deployment/config`, `deployment/stats` aggregated from Rust workspace/provisioner/agent tables, and `deployment/ssh` |
| `coderd/audit.go` operational audit slice | `crates/coder-server` + `crates/coder-core` + `crates/coder-db` | Ported for `GET /api/v2/audit` and `POST /api/v2/audit/testgenerate` with persisted audit rows |
| `coderd/debug.go` health slice | `crates/coder-server` + `crates/coder-core` + `crates/coder-db` + `crates/coder-connectivity` | Ported for `GET /api/v2/debug/health` and `GET/PUT /api/v2/debug/health/settings`, including cached report generation plus live access-url, DERP, workspace-proxy, and provisioner-daemon probes |
| `coderd/gitsshkey.go` user Git SSH key slice | `crates/coder-server` + `crates/coder-core` + `crates/coder-connectivity` + `crates/coder-db` | Ported for `GET/PUT /api/v2/users/{user}/gitsshkey` with persisted Ed25519 OpenSSH keypairs |
| `coderd/users.go` bootstrap and admin subset | `crates/coder-server` + `crates/coder-core` + `crates/coder-db` | Ported for `GET/POST /api/v2/users/first`, `GET/POST /api/v2/users`, `GET/DELETE /api/v2/users/{user}`, `GET/PUT /api/v2/users/{user}/roles`, `GET /api/v2/users/{user}/organizations...`, login-type lookup, autofill-parameter lookup, profile updates, suspend/activate, appearance/preferences, and password change |
| `coderd/userauth.go` password login/logout/auth subset | `crates/coder-server` + `crates/coder-core` + `crates/coder-db` | Ported for `POST /api/v2/users/login`, `POST /api/v2/users/logout`, `GET /api/v2/users/authmethods`, password validation, one-time-passcode request/reset, and disabled GitHub/OIDC callback/convert-login surfaces until provider config is ported |
| `coderd/scopes_catalog.go` | `crates/coder-server` + `crates/coder-core` | Ported for `GET /api/v2/auth/scopes` |
| `coderd/experiments.go` | `crates/coder-server` + `crates/coder-core` | Ported for `GET /api/v2/experiments` and `GET /api/v2/experiments/available` with current empty/default semantics |
| `coderd/externalauth.go` default discovery surface | `crates/coder-server` + `crates/coder-core` + `crates/coder-db` + `crates/coder-auth` | Ported for configured-provider discovery, read-path refresh/validation, revoke-on-unlink, top-level callback handling, and provider-backed device authorization/device exchange |
| `coderd/organizations.go` read surface | `crates/coder-server` + `crates/coder-core` + `crates/coder-db` | Ported for `GET /api/v2/organizations` and `GET /api/v2/organizations/{organization}` |
| `coderd/members.go` read/admin subset | `crates/coder-server` + `crates/coder-core` + `crates/coder-db` | Ported for `GET/POST/DELETE /api/v2/organizations/{organization}/members/{user}`, `GET /api/v2/organizations/{organization}/members`, `GET /api/v2/organizations/{organization}/paginated-members`, and `PUT /api/v2/organizations/{organization}/members/{user}/roles` |
| `coderd/roles.go` assignable-role listing subset | `crates/coder-server` + `crates/coder-core` + `crates/coder-rbac` | Ported for `GET /api/v2/users/roles` and `GET /api/v2/organizations/{organization}/members/roles` |
| `coderd/apikey.go` session/token subset | `crates/coder-server` + `crates/coder-core` + `crates/coder-db` | Ported for `POST /api/v2/users/{user}/keys`, `GET/DELETE/PUT /api/v2/users/{user}/keys/{keyid}`, and token listing/creation/config/name lookup routes |
| `coderd/userpassword/userpassword.go` | `crates/coder-core` | Ported for PBKDF2-SHA256 hashing, verification, and session token hashing |
| `coderd/rbac/*` initial actor checks | `crates/coder-rbac` | Ported as the first request-actor RBAC seam for self-vs-owner and org membership checks |
| `coderd/audit/*` initial event boundary | `crates/coder-audit` | Ported as a structured audit sink with tracing-backed emission |
| `codersdk/name.go` | `crates/coder-core` | Ported for username and real-name validation helpers used by bootstrap |
| `coderd/database/queries/siteconfig.sql` | `crates/coder-db` | Ported for `deployment_id` bootstrap and lookup |
| `coderd/database/queries/users.sql` bootstrap/admin subset | `crates/coder-db` | Ported for first-user existence checks, creation, password lookup, session lookup, user listing, user creation, user role updates, user soft delete, and user lookup |
| `coderd/database/queries/organizations.sql` read subset | `crates/coder-db` | Ported for default organization bootstrap plus organization listing and lookup |
| `coderd/database/queries/organizationmembers.sql` read/write subset | `crates/coder-db` | Ported for first-user organization membership plus membership listing by organization/user, member lookup, insert, delete, and role updates |
| `coderd/database/queries/apikeys.sql` subset | `crates/coder-db` | Ported for API-key create/list/get/delete/expire and token policy lookup |
| `coderd/database/migrations/000024_site_config.up.sql` | `crates/coder-db/migrations` | Ported as the bootstrap migration |
| `coderd/database/migrations/*` user/org/auth-session/API-key subset | `crates/coder-db/migrations` | Ported as the identity/admin bootstrap migrations |
| `codersdk/client.go` response model | `crates/coder-core` | Ported |
| `codersdk/deployment.go` build/config/ssh response models | `crates/coder-core` | Ported for the deployment slice |
| `codersdk/users.go` bootstrap/auth/admin subset | `crates/coder-core` | Ported for first-user, login/logout, auth methods, user listing, and user lookup models |
| `codersdk/organizations.go` subset | `crates/coder-core` | Ported for organization and organization-member models |
| `codersdk/apikey.go` subset | `crates/coder-core` | Ported for create/list/get/delete/expire/token-config models |

## Ported behavior boundaries

The Rust service now covers:

- top-level slim-build root behavior and API-root parity as separate routes
- deployment bootstrap and metadata lookup
- route-scope-aware parity inventory and corrected empty-db smoke comparisons
- first-user existence checks with the build-version header compatibility hook
- first-user creation with default-organization bootstrap and owner RBAC seed
- password login with PBKDF2-SHA256 verification and auth-session persistence
- session-backed logout and auth-method discovery
- authenticated user listing, creation, lookup, deletion, and role reads/writes
  with owner-vs-self authorization
- user login-type lookup, profile updates, suspend/activate, appearance and
  preference settings, and password change
- password validation plus one-time-passcode request/reset flows
- public API key scope catalog plus empty/default experiment and external-auth
  discovery surfaces
- Go-style cached deployment stats plus the permanent Rust-side writers for
  workspace/build/job/agent aggregation
- audit-log query/test generation and deployment health/settings routes with
  live DERP, workspace-proxy, and provisioner-daemon sections
- persisted Git SSH key generation/storage plus provider-backed external-auth
  listing, lookup, refresh/validation, revoke-on-unlink, callback, and device
  flows
- user autofill-parameter validation path and OIDC debug-link fallback behavior
- user organization lookups by user and organization name
- site-role listing and organization-role listing
- organization listing/lookup and organization-member list/get/add/remove/role
  mutation, including paginated member listings
- session and token API-key CRUD/config routes for the current OSS admin slice
- initial request-actor RBAC checks plus persisted audit emission from the
  running binary

It does not yet cover the broader user-management surface from Go, including:

- full site and organization RBAC semantics, custom roles, and broader
  operational/admin surfaces beyond the current health/audit/git/external-auth
  slice
- live GitHub/OIDC provider flows, OAuth2 provider endpoints, and full
  convert-login behavior beyond the current disabled-route parity surface
- notification delivery, inbox/webpush, and the rest of session semantics
- the rest of the `coderd` backend outside this bootstrap/auth vertical slice

## Planned crate seams

The original `coderd` package is too large to translate as one crate without
recreating the same monolith in Rust. The intended split is:

| Go area | Planned Rust crate |
| --- | --- |
| auth, sessions, API keys, OIDC, OAuth2 | `crates/coder-auth` |
| users, organizations, RBAC | `crates/coder-identity` |
| templates, workspaces, builds, presets | `crates/coder-workspaces` |
| provisioner APIs and background jobs | `crates/coder-provisioner` |
| notifications, inbox, webpush | `crates/coder-notifications` |
| DERP, tailnet, agent RPC, workspace apps | `crates/coder-connectivity` |
| shared SQL repositories and migrations | `crates/coder-db` |
| HTTP composition and cross-cutting middleware | `crates/coder-server` |

The workspace now includes these crate seams as concrete Rust crates, and the
auth/RBAC/audit/identity slices now carry live behavior.

The generated route inventory in `docs/parity-matrix.md` is now the committed
OSS source of truth for parity tracking.

## Migration rule

Each future port should move a complete vertical slice:

1. Define the Rust domain types and API models in `coder-core` or a feature
   crate.
2. Port the storage access and migrations needed for that slice into
   `coder-db`.
3. Port the HTTP handler and tests into `coder-server` or a feature crate.
4. Leave the remaining Go surface in place until the slice is complete.

That keeps behavior changes reviewable and prevents a half-ported backend from
turning into a second monolith.
