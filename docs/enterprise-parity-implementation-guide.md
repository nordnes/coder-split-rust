# Enterprise Parity Implementation Guide

> **Goal**: Reach 100% parity between the Go backend and the Rust backend.
>
> **Current state** (auto-generated — run `make parity-refresh` for live numbers):
> - OSS: see `docs/parity-matrix.md`
> - Enterprise: see `docs/parity-matrix-enterprise.md`
> - Combined: see `docs/parity-matrix-all.md`
>
> **Canonical route list**: The parity matrices above are the single source of truth for which routes are missing. This document provides implementation instructions for every route listed as `missing` in `docs/parity-matrix-all.md` at the time of writing (68 routes).

---

## Table of Contents

1. [How to Use This Guide](#how-to-use-this-guide)
2. [Common Patterns](#common-patterns)
3. [Recommended Implementation Order](#recommended-implementation-order)
4. [Phase 1 — Quick-Win Settings Endpoints](#phase-1--quick-win-settings-endpoints)
5. [Phase 2 — Organization CRUD & Custom Roles](#phase-2--organization-crud--custom-roles)
6. [Phase 3 — Groups, Templates ACL & Provisioner Keys](#phase-3--groups-templates-acl--provisioner-keys)
7. [Phase 4 — IDP Sync, Connection Log, Quotas & Misc](#phase-4--idp-sync-connection-log-quotas--misc)
8. [Phase 5 — Workspace Proxies & WebSocket Coordination](#phase-5--workspace-proxies--websocket-coordination)
9. [Phase 6 — AI Bridge & Remaining Routes](#phase-6--ai-bridge--remaining-routes)
10. [Cross-Cutting Concerns](#cross-cutting-concerns)
11. [Appendix A — Full Missing Route Inventory](#appendix-a--full-missing-route-inventory)

---

## How to Use This Guide

Each route section contains:

| Field | Description |
|-------|-------------|
| **Method + Path** | HTTP method and route pattern |
| **Go Source** | File and function name in the `coder/` submodule |
| **SDK Method** | `codersdk.Client` method name (if any) |
| **Scope** | `oss` or `enterprise` |
| **Request type** | JSON body / query params / path params |
| **Response type** | JSON response shape |
| **Auth / RBAC** | Authorization checks performed |
| **Audit** | Whether audit logging is required |
| **DB operations** | Database queries and transactions |
| **Implementation notes** | Rust-specific guidance |

**Convention**: Every handler file referenced below lives under the `coder/` submodule. When this guide says `enterprise/coderd/appearance.go`, the full path is `coder/enterprise/coderd/appearance.go`.

---

## Common Patterns

These patterns recur across nearly every enterprise handler. Understand them once, apply everywhere.

### 1. Audit Logging

Most mutating enterprise endpoints use Go's `audit.InitRequest[T]` to create an audit trail:

```go
auditor := api.AGPL.Auditor.Load()
aReq, commitAudit := audit.InitRequest[database.SomeType](rw, &audit.RequestParams{
    Audit:   *auditor,
    Log:     api.Logger,
    Request: r,
    Action:  database.AuditActionWrite, // or Create, Delete
})
aReq.Old = existingRecord
defer commitAudit()
// ... mutate ...
aReq.New = updatedRecord
```

**Rust equivalent**: Use the existing audit infrastructure in `crates/coder-server`. Create an `AuditLog` entry with `old` and `new` snapshots of the resource, the action type, and the request metadata. The audit entry should be committed after the database operation succeeds.

### 2. RBAC Authorization

```go
if !api.Authorize(r, policy.ActionRead, rbac.ResourceSomething) {
    httpapi.ResourceNotFound(rw)
    return
}
```

**Rust equivalent**: Use the RBAC middleware or call `authorize()` with the appropriate `Action` and `Resource`. Return 404 (not 403) when authorization fails on read operations (to avoid leaking resource existence).

### 3. Feature Entitlement Checks

Enterprise endpoints typically sit behind entitlement middleware:

```go
api.RequireFeatureMW(codersdk.FeatureTemplateRBAC)
```

**Rust equivalent**: Add middleware that checks the license entitlements before the handler runs. Return 403 with a message like `"{Feature} is a Premium feature. Contact sales!"`.

### 4. System Context Elevation

Some handlers need to bypass RBAC for internal operations:

```go
ctx = dbauthz.AsSystemRestricted(ctx)
```

**Rust equivalent**: Use the system-restricted context/actor for database calls that need elevated privileges (e.g., listing all users for ACL assignment).

### 5. Database Transactions

```go
err := api.Database.InTx(func(tx database.Store) error {
    // ... operations ...
    return nil
}, &database.TxOptions{Isolation: sql.LevelSerializable})
```

**Rust equivalent**: Use `sqlx` transactions with the appropriate isolation level. For serializable transactions (e.g., quota commit), set the isolation level explicitly.

### 6. Read-Modify-Update Pattern

```go
err := database.ReadModifyUpdate(api.Database, func(tx database.Store) error {
    org, err = tx.GetOrganizationByID(ctx, org.ID)
    // modify fields
    org, err = tx.UpdateOrganization(ctx, params)
    return nil
})
```

**Rust equivalent**: Wrap the read + modify + update in a single database transaction to prevent lost updates.

### 7. Middleware Parameter Extraction

Go handlers extract path parameters via middleware:

```go
org := httpmw.OrganizationParam(r)
user := httpmw.UserParam(r)
template := httpmw.TemplateParam(r)
```

**Rust equivalent**: Use Axum extractors (`Path`, `Query`, etc.) and middleware-injected state. The existing codebase already has extractors for organizations, users, and templates.

---

## Recommended Implementation Order

Routes are grouped into 6 phases based on dependency chains and complexity:

| Phase | Routes | Complexity | Rationale |
|-------|--------|------------|-----------|
| 1 | 12 | Low | Simple GET/PUT pairs, no cross-dependencies |
| 2 | 6 | Medium | Org CRUD + custom roles, needed by later phases |
| 3 | 18 | Medium | Groups, template ACL, provisioner keys |
| 4 | 22 | Medium-High | IDP sync (repetitive), connection log, quotas |
| 5 | 13 | High | Workspace proxies, crypto, WebSocket |
| 6 | 5 | Medium | AI Bridge endpoints |

---

## Phase 1 — Quick-Win Settings Endpoints

These are simple GET/PUT pairs with minimal business logic. Each one typically reads a value from the database, optionally validates it, writes it back, and returns the result.

---

### 1.1 GET `/appearance`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/appearance.go` → `appearance()` |
| **SDK Method** | `Appearance` |
| **Scope** | `enterprise` |
| **Request** | None |
| **Response** | `codersdk.AppearanceConfig` (JSON) |
| **Auth** | None (public read) |
| **Audit** | No |
| **Feature gate** | `codersdk.FeatureAppearance` |

**Go handler summary** (lines 30-42):
```go
func (api *API) appearance(rw http.ResponseWriter, r *http.Request) {
    af := *api.AGPL.AppearanceFetcher.Load()
    cfg, err := af.Fetch(r.Context())
    // error → 500, else → 200 with cfg
}
```

**Implementation notes**:
- Load the appearance config from the database (or a cached fetcher).
- The `AppearanceConfig` includes fields like `application_name`, `logo_url`, `service_banner`, `announcement_banners`.
- This is a read-only endpoint with no authorization required.
- Return 500 if the database fetch fails.

---

### 1.2 PUT `/appearance`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/appearance.go` → `putAppearance()` |
| **SDK Method** | `UpdateAppearance` |
| **Scope** | `enterprise` |
| **Request** | `codersdk.UpdateAppearanceConfig` (JSON body) |
| **Response** | `codersdk.UpdateAppearanceConfig` (JSON) |
| **Auth** | `policy.ActionUpdate` on `rbac.ResourceDeploymentConfig` |
| **Audit** | Yes — `database.AuditActionWrite` on `database.Organization` |
| **Feature gate** | `codersdk.FeatureAppearance` |

**Go handler summary**:
- Authorize the caller.
- Read and validate the request body.
- Validate `ServiceBannerEnabled` and `AnnouncementBanners` fields.
- Call `api.Database.UpsertAppearanceConfig()` to persist.
- Commit audit log with old/new values.

**Implementation notes**:
- Validate that `service_banner.message` is not empty when enabled.
- Validate that each announcement banner has a non-empty message.
- Use the audit logging infrastructure for the write.

---

### 1.3 GET `/prebuilds/settings`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/prebuilds.go` → `prebuildsSettings()` |
| **SDK Method** | `GetPrebuildsSettings` |
| **Scope** | `oss` (route defined in OSS, handler in enterprise) |
| **Request** | None |
| **Response** | `codersdk.PrebuildsSettings` (JSON) |
| **Auth** | Implicit (session required) |
| **Audit** | No |

**Go handler summary** (lines 25-47):
```go
settingsJSON, err := api.Database.GetPrebuildsSettings(r.Context())
var settings codersdk.PrebuildsSettings
if len(settingsJSON) > 0 {
    json.Unmarshal([]byte(settingsJSON), &settings)
}
httpapi.Write(r.Context(), rw, http.StatusOK, settings)
```

**Implementation notes**:
- Reads a JSON string from the database.
- If the string is empty, return a default `PrebuildsSettings` (all fields at zero/false).
- `PrebuildsSettings` has a single field: `reconciliation_paused: bool`.

---

### 1.4 PUT `/prebuilds/settings`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/prebuilds.go` → `putPrebuildsSettings()` |
| **SDK Method** | `PutPrebuildsSettings` |
| **Scope** | `oss` |
| **Request** | `codersdk.PrebuildsSettings` (JSON body) |
| **Response** | `codersdk.PrebuildsSettings` or 304 Not Modified |
| **Auth** | RBAC via `prebuilds.SetPrebuildsReconciliationPaused` |
| **Audit** | Yes — `database.AuditActionWrite` on `database.PrebuildsSettings` |

**Go handler summary** (lines 59-120):
- Parse request body.
- Marshal to JSON and compare with current settings (byte comparison).
- If identical → return **304 Not Modified**.
- Otherwise, audit log the change and update via `prebuilds.SetPrebuildsReconciliationPaused()`.
- If RBAC unauthorized → 403. If error → 500. Else → 200.

**Implementation notes**:
- The 304 Not Modified response is unusual — implement it by comparing the serialized JSON bytes.
- The audit log records a `PrebuildsSettings` object with `id` (UUID) and `reconciliation_paused` fields.

---

### 1.5 GET `/users/{user}/quiet-hours`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/users.go` → `userQuietHoursSchedule()` |
| **SDK Method** | `UserQuietHoursSchedule` |
| **Scope** | `enterprise` |
| **Request** | Path param: `{user}` (UUID or "me") |
| **Response** | `codersdk.UserQuietHoursScheduleResponse` |
| **Auth** | Implicit via `UserParam` middleware |
| **Audit** | No |
| **Feature gate** | `codersdk.FeatureAdvancedTemplateScheduling` via `autostopRequirementEnabledMW` |

**Go handler summary** (lines 47-71):
```go
user := httpmw.UserParam(r)
opts, err := (*api.UserQuietHoursScheduleStore.Load()).Get(ctx, api.Database, user.ID)
// Return schedule details: raw_schedule, user_set, user_can_set, time, timezone, next
```

**Response shape**:
```json
{
  "raw_schedule": "CRON_TZ=America/Chicago 0 0 * * *",
  "user_set": true,
  "user_can_set": true,
  "time": "00:00",
  "timezone": "America/Chicago",
  "next": "2024-01-15T06:00:00Z"
}
```

**Implementation notes**:
- Requires the `AdvancedTemplateScheduling` entitlement.
- The middleware `autostopRequirementEnabledMW` returns 403 if the feature is not entitled or not enabled.
- The schedule store calculates the `next` quiet hours window based on the user's timezone.

---

### 1.6 PUT `/users/{user}/quiet-hours`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/users.go` → `putUserQuietHoursSchedule()` |
| **SDK Method** | `UpdateUserQuietHoursSchedule` |
| **Scope** | `enterprise` |
| **Request** | `codersdk.UpdateUserQuietHoursScheduleRequest` (JSON body with `schedule` string) |
| **Response** | `codersdk.UserQuietHoursScheduleResponse` |
| **Auth** | Via `UserParam` middleware |
| **Audit** | Yes — `database.AuditActionWrite` on `database.User` |
| **Feature gate** | `codersdk.FeatureAdvancedTemplateScheduling` |

**Go handler summary** (lines 83-123):
- Parse the `schedule` field from the request body.
- Call `UserQuietHoursScheduleStore.Set()` which validates the cron expression.
- If `ErrUserCannotSetQuietHoursSchedule` → 403.
- Audit log with old/new user records.

**Implementation notes**:
- The schedule is a cron expression with timezone, e.g., `CRON_TZ=America/Chicago 0 0 * * *`.
- If the deployment is configured to not allow user-set schedules, return 403.

---

### 1.7 GET `/replicas`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/replicas.go` → `replicas()` |
| **SDK Method** | `Replicas` |
| **Scope** | `enterprise` |
| **Request** | None |
| **Response** | `[]codersdk.Replica` (JSON array) |
| **Auth** | `policy.ActionRead` on `rbac.ResourceReplicas` |
| **Audit** | No |

**Go handler summary** (lines 22-34):
```go
if !api.AGPL.Authorize(r, policy.ActionRead, rbac.ResourceReplicas) {
    httpapi.ResourceNotFound(rw)
    return
}
replicas := api.replicaManager.AllPrimary()
res := make([]codersdk.Replica, 0, len(replicas))
for _, replica := range replicas {
    res = append(res, convertReplica(replica))
}
httpapi.Write(r.Context(), rw, http.StatusOK, res)
```

**Response shape per replica**:
```json
{
  "id": "uuid",
  "hostname": "coder-1",
  "created_at": "2024-01-01T00:00:00Z",
  "relay_address": "https://coder-1.example.com",
  "region_id": 1,
  "error": "",
  "database_latency": 1000000
}
```

**Implementation notes**:
- Requires a `replicaManager` service that tracks active Coder replicas.
- If RBAC denies access, return 404 (not 403).
- The `database_latency` field is in nanoseconds.

---

### 1.8 GET `/workspace-quota/{user}` (deprecated)

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/workspacequota.go` → `workspaceQuotaByUser()` |
| **SDK Method** | — |
| **Scope** | `enterprise` |
| **Request** | Path param: `{user}` |
| **Response** | `codersdk.WorkspaceQuota` |
| **Auth** | Via `UserParam` + `OrganizationParam` middleware |
| **Audit** | No |

**Go handler summary** (lines 132-143):
- Gets the default organization.
- Injects the default org ID into the URL params.
- Delegates to `workspaceQuota()` handler.

**Implementation notes**:
- This is a deprecated endpoint. It redirects internally to the new `/organizations/{organization}/members/{user}/workspace-quota` endpoint using the default organization.
- Implement by looking up the default org and calling the same quota logic.

---

### 1.9 GET `/organizations/{organization}/members/{user}/workspace-quota`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/workspacequota.go` → `workspaceQuota()` |
| **SDK Method** | `WorkspaceQuota` |
| **Scope** | `enterprise` |
| **Request** | Path params: `{organization}`, `{user}` |
| **Response** | `codersdk.WorkspaceQuota` |
| **Auth** | Via middleware |
| **Audit** | No |

**Go handler summary** (lines 154-195):
```go
organization := httpmw.OrganizationParam(r)
user := httpmw.UserParam(r)
licensed := api.Entitlements.Enabled(codersdk.FeatureTemplateRBAC)
// If not licensed, quotaAllowance = -1 (unlimited)
// Otherwise, get allowance and consumed from DB
httpapi.Write(r.Context(), rw, http.StatusOK, codersdk.WorkspaceQuota{
    CreditsConsumed: int(quotaConsumed),
    Budget:          int(quotaAllowance),
})
```

**DB operations**:
- `GetQuotaAllowanceForUser(UserID, OrganizationID)` — sum of group quota allowances
- `GetQuotaConsumedForUser(OwnerID, OrganizationID)` — sum of daily costs for running workspaces

**Implementation notes**:
- If `FeatureTemplateRBAC` is not licensed, return `budget: -1` (unlimited).
- Both values come from aggregate queries over groups and workspace builds.

---

### 1.10 GET `/organizations/{organization}/settings/workspace-sharing`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/workspacesharing.go` → `workspaceSharingSettings()` |
| **SDK Method** | `WorkspaceSharingSettings` |
| **Scope** | `enterprise` |
| **Request** | Path param: `{organization}` |
| **Response** | `codersdk.WorkspaceSharingSettings` |
| **Auth** | `policy.ActionRead` on the organization |
| **Audit** | No |

**Go handler summary** (lines 31-51):
```go
org := httpmw.OrganizationParam(r)
if !api.Authorize(r, policy.ActionRead, org) { return 403 }
disabled := org.ShareableWorkspaceOwners == database.ShareableWorkspaceOwnersNone
globallyDisabled := bool(api.DeploymentValues.DisableWorkspaceSharing)
// Build response from org settings + global config
```

**Response shape**:
```json
{
  "sharing_globally_disabled": false,
  "sharing_disabled": false,
  "shareable_workspace_owners": "everyone"
}
```

**Implementation notes**:
- `shareable_workspace_owners` is an enum: `"none"`, `"everyone"`, `"service_accounts"`.
- Global disable flag overrides the per-org setting.

---

### 1.11 PATCH `/organizations/{organization}/settings/workspace-sharing`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/workspacesharing.go` → `patchWorkspaceSharingSettings()` |
| **SDK Method** | `PatchWorkspaceSharingSettings` |
| **Scope** | `enterprise` |
| **Request** | `codersdk.UpdateWorkspaceSharingSettingsRequest` (JSON body) |
| **Response** | `codersdk.WorkspaceSharingSettings` |
| **Auth** | `policy.ActionUpdate` on the organization |
| **Audit** | Yes — `database.AuditActionWrite` on `database.Organization` |

**Go handler summary** (lines 63-194):
The handler does significant work inside a transaction:
1. Acquire `LockIDReconcileSystemRoles` (advisory lock).
2. Update `shareable_workspace_owners` on the organization.
3. Look up `org-member` and `org-service-account` system roles.
4. Call `rolestore.ReconcileSystemRole()` for each role.
5. If sharing disabled, delete workspace ACLs for that org (preserving SA workspaces in `service_accounts` mode).

**Request shape**:
```json
{
  "sharing_disabled": false,
  "shareable_workspace_owners": "everyone"
}
```

**Implementation notes**:
- `shareable_workspace_owners` field takes precedence over deprecated `sharing_disabled` boolean.
- Validate the enum value against `database.AllShareableWorkspaceOwnersValues()`.
- The transaction must acquire an advisory lock to serialize role reconciliation.
- This is one of the more complex settings endpoints due to the role reconciliation and ACL cleanup.

---

### 1.12 POST `/licenses/refresh-entitlements`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/licenses.go` → `postRefreshEntitlements()` |
| **SDK Method** | — |
| **Scope** | `enterprise` |
| **Request** | None |
| **Response** | `codersdk.Response` with message |
| **Auth** | `policy.ActionUpdate` on `rbac.ResourceLicense` |
| **Audit** | No |

**Go handler summary**:
- Authorize the caller.
- Call `api.refreshEntitlements()` which re-evaluates all license keys and updates enabled features.
- Publish a `PubsubEventLicenses` message to notify other replicas.
- Return 200 with a success message.

**Implementation notes**:
- This triggers a full re-evaluation of license entitlements.
- Requires a pubsub mechanism to notify other Coder replicas.

---

## Phase 2 — Organization CRUD & Custom Roles

These routes are prerequisites for groups, template ACLs, and other org-scoped features.

---

### 2.1 POST `/organizations`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/organizations.go` → `postOrganizations()` |
| **SDK Method** | `CreateOrganization` |
| **Scope** | `oss` |
| **Request** | `codersdk.CreateOrganizationRequest` (JSON body) |
| **Response** | `codersdk.Organization` (201 Created) |
| **Auth** | Implicit (RBAC on organization create) |
| **Audit** | Yes — `database.AuditActionCreate` on `database.Organization` |

**Request shape**:
```json
{
  "name": "my-org",
  "display_name": "My Organization",
  "description": "Optional description",
  "icon": "/emojis/1f3e2.png"
}
```

**Go handler summary** (lines 220-343):
Inside a transaction:
1. Acquire `LockIDReconcileSystemRoles` advisory lock.
2. Validate name is not `"default"` (reserved).
3. Check for name uniqueness.
4. Insert organization with `InsertOrganization()`.
5. For each system role name, call `ReconcileSystemRole()`.
6. Insert the creating user as an organization member.
7. Insert the "Everyone" group via `InsertAllUsersGroup()`.

**Implementation notes**:
- The organization ID is pre-generated (`uuid::new()`) before the transaction so it can be used in the audit request.
- `display_name` defaults to `name` if not provided.
- The `"default"` name is reserved and must be rejected.
- The transaction must create the org, reconcile system roles, add the creator as a member, and create the "Everyone" group atomically.

---

### 2.2 PATCH `/organizations/{organization}`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/organizations.go` → `patchOrganization()` |
| **SDK Method** | `UpdateOrganization` |
| **Scope** | `oss` |
| **Request** | `codersdk.UpdateOrganizationRequest` (JSON body) |
| **Response** | `codersdk.Organization` |
| **Auth** | Implicit (RBAC on organization update) |
| **Audit** | Yes — `database.AuditActionWrite` on `database.Organization` |

**Request shape** (all fields optional):
```json
{
  "name": "new-name",
  "display_name": "New Display Name",
  "description": "Updated description",
  "icon": "/emojis/1f3e3.png"
}
```

**Go handler summary** (lines 33-123):
- Uses `database.ReadModifyUpdate()` pattern (read in tx, modify, write).
- Validates name is not `"default"`.
- Only updates fields that are provided (non-empty/non-nil).
- Handles unique violation on name → 409 Conflict.

**Implementation notes**:
- Only update fields that are explicitly set in the request.
- Handle unique constraint violation on organization name.

---

### 2.3 DELETE `/organizations/{organization}`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/organizations.go` → `deleteOrganization()` |
| **SDK Method** | `DeleteOrganization` |
| **Scope** | `oss` |
| **Request** | Path param: `{organization}` |
| **Response** | `codersdk.Response` |
| **Auth** | Implicit (RBAC on organization delete) |
| **Audit** | Yes — `database.AuditActionDelete` on `database.Organization` |

**Go handler summary** (lines 133-209):
1. Check `organization.IsDefault` → 400 if true.
2. Call `UpdateOrganizationDeletedByID()` inside a transaction (soft-delete).
3. On failure, query `GetOrganizationResourceCountByID()` and return a detailed error message listing dependent resources (workspaces, templates, members, groups, provisioner keys).

**Implementation notes**:
- The default organization cannot be deleted.
- This is a **soft delete** (sets `deleted = true`, not a hard delete).
- On failure, provide helpful error messages listing resource counts that prevent deletion.
- The resource count query returns counts for: workspaces, templates, members (-1 for the default member), groups (-1 for the default group), provisioner keys.

---

### 2.4 POST `/organizations/{organization}/members/roles`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/roles.go` → `postOrgRoles()` |
| **SDK Method** | `CreateOrganizationRole` |
| **Scope** | `oss` |
| **Request** | `codersdk.Role` (JSON body) |
| **Response** | `codersdk.Role` (201 Created) |
| **Auth** | `policy.ActionCreate` on `rbac.ResourceAssignOrgRole.InOrg(org.ID)` |
| **Audit** | Yes — `database.AuditActionCreate` on `database.CustomRole` |

**Go handler summary**:
1. Parse and validate the role definition.
2. Check that the role name doesn't conflict with reserved names.
3. Validate that all permissions reference valid resource types and actions.
4. Insert the custom role via `InsertCustomRole()`.
5. Return the created role.

**Implementation notes**:
- Reserved role names (e.g., `owner`, `member`, `auditor`, `template-admin`) must be rejected.
- Permission validation should check that each permission references a valid resource type and action.
- The role is scoped to the organization.

---

### 2.5 PUT `/organizations/{organization}/members/roles`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/roles.go` → `putOrgRoles()` |
| **SDK Method** | `UpdateOrganizationRole` |
| **Scope** | `oss` |
| **Request** | `codersdk.Role` (JSON body) |
| **Response** | `codersdk.Role` |
| **Auth** | `policy.ActionUpdate` on `rbac.ResourceAssignOrgRole.InOrg(org.ID)` |
| **Audit** | Yes — `database.AuditActionWrite` on `database.CustomRole` |

**Implementation notes**:
- Similar to POST but uses `UpdateCustomRole()`.
- The role name must already exist.
- Validate permissions the same way as create.

---

### 2.6 DELETE `/organizations/{organization}/members/roles/{roleName}`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/roles.go` → `deleteOrgRole()` |
| **SDK Method** | `DeleteOrganizationRole` |
| **Scope** | `oss` |
| **Request** | Path params: `{organization}`, `{roleName}` |
| **Response** | 204 No Content |
| **Auth** | `policy.ActionDelete` on `rbac.ResourceAssignOrgRole.InOrg(org.ID)` |
| **Audit** | Yes — `database.AuditActionDelete` on `database.CustomRole` |

**Implementation notes**:
- Look up the custom role by name and organization.
- Reserved/built-in roles cannot be deleted.
- Delete via `DeleteCustomRole()`.

---

## Phase 3 — Groups, Templates ACL & Provisioner Keys

---

### 3.1 GET `/groups`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/groups.go` → `groups()` (deployment-wide) |
| **SDK Method** | — |
| **Scope** | `enterprise` |
| **Request** | None |
| **Response** | `[]codersdk.Group` |
| **Auth** | `policy.ActionRead` on `rbac.ResourceGroup` |
| **Feature gate** | `codersdk.FeatureTemplateRBAC` |

**Implementation notes**:
- Lists all groups across all organizations.
- Uses `GetGroups()` with no organization filter.
- For each group, fetch members and member count.
- Convert using `db2sdk.Group()`.

---

### 3.2 POST `/organizations/{organization}/groups`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/groups.go` → `postGroupByOrganization()` |
| **SDK Method** | `CreateGroup` |
| **Scope** | `enterprise` |
| **Request** | `codersdk.CreateGroupRequest` (JSON body) |
| **Response** | `codersdk.Group` (201 Created) |
| **Auth** | `policy.ActionCreate` on `rbac.ResourceGroup.InOrg(org.ID)` |
| **Audit** | Yes — `database.AuditActionCreate` on `database.Group` |
| **Feature gate** | `codersdk.FeatureTemplateRBAC` |

**Request shape**:
```json
{
  "name": "backend-team",
  "display_name": "Backend Team",
  "avatar_url": "",
  "quota_allowance": 100
}
```

**Go handler summary**:
1. Insert the group via `InsertGroup()`.
2. Handle unique violation → 409 Conflict.
3. If `add_users` is provided, insert each member via `InsertGroupMember()`.
4. Handle user-not-found and already-member errors gracefully.

**Implementation notes**:
- The group can optionally include initial members via `add_users` field (list of user IDs).
- Duplicate group names within an organization return 409.
- After creation, fetch the full group with members for the response.

---

### 3.3 GET `/organizations/{organization}/groups`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/groups.go` → `groupsByOrganization()` |
| **SDK Method** | — |
| **Scope** | `enterprise` |
| **Request** | Path param: `{organization}` |
| **Response** | `[]codersdk.Group` |
| **Auth** | Via middleware |
| **Feature gate** | `codersdk.FeatureTemplateRBAC` |

**Implementation notes**:
- Lists groups filtered by organization ID.
- For each group, fetch members and count.

---

### 3.4 GET `/organizations/{organization}/groups/{groupName}`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/groups.go` → `groupByOrganizationAndName()` |
| **SDK Method** | `GroupByOrgAndName` |
| **Scope** | `enterprise` |
| **Request** | Path params: `{organization}`, `{groupName}` |
| **Response** | `codersdk.Group` |
| **Auth** | Via middleware |
| **Feature gate** | `codersdk.FeatureTemplateRBAC` |

**Implementation notes**:
- Look up group by name within the organization.
- Return 404 if not found.

---

### 3.5 GET `/groups/{group}`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/groups.go` → `group()` |
| **SDK Method** | `Group` |
| **Scope** | `enterprise` |
| **Request** | Path param: `{group}` (UUID) |
| **Response** | `codersdk.Group` |
| **Auth** | Via `GroupParam` middleware |
| **Feature gate** | `codersdk.FeatureTemplateRBAC` |

---

### 3.6 PATCH `/groups/{group}`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/groups.go` → `patchGroup()` |
| **SDK Method** | `PatchGroup` |
| **Scope** | `enterprise` |
| **Request** | `codersdk.PatchGroupRequest` (JSON body) |
| **Response** | `codersdk.Group` |
| **Auth** | `policy.ActionUpdate` on the group |
| **Audit** | Yes — `database.AuditActionWrite` on `database.Group` |
| **Feature gate** | `codersdk.FeatureTemplateRBAC` |

**Request shape**:
```json
{
  "name": "new-name",
  "display_name": "New Display Name",
  "avatar_url": "",
  "quota_allowance": 200,
  "add_users": ["user-uuid-1"],
  "remove_users": ["user-uuid-2"]
}
```

**Go handler summary**:
1. Validate that `add_users` and `remove_users` don't overlap.
2. If name changed, check for uniqueness.
3. Update group metadata.
4. Add/remove members inside a transaction.
5. Handle unique violations, not-found errors.

**Implementation notes**:
- Validate that no user appears in both `add_users` and `remove_users`.
- The "Everyone" group cannot be renamed and members cannot be manually added/removed.
- Only provided fields should be updated.

---

### 3.7 DELETE `/groups/{group}`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/groups.go` → `deleteGroup()` |
| **SDK Method** | `DeleteGroup` |
| **Scope** | `enterprise` |
| **Request** | Path param: `{group}` (UUID) |
| **Response** | `codersdk.Response` |
| **Auth** | `policy.ActionDelete` on the group |
| **Audit** | Yes — `database.AuditActionDelete` on `database.Group` |
| **Feature gate** | `codersdk.FeatureTemplateRBAC` |

**Implementation notes**:
- The "Everyone" group (`group.Name == database.EveryoneGroup`) cannot be deleted → 400.
- Soft-delete or hard-delete depending on the DB schema.

---

### 3.8 GET `/templates/{template}/acl`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/templates.go` → `templateACL()` |
| **SDK Method** | `TemplateACL` |
| **Scope** | `enterprise` |
| **Request** | Path param: `{template}` (UUID) |
| **Response** | `codersdk.TemplateACL` |
| **Auth** | Via `TemplateParam` middleware (requires read access) |
| **Feature gate** | `codersdk.FeatureTemplateRBAC` |

**Response shape**:
```json
{
  "users": [
    {"user": {...}, "role": "admin"}
  ],
  "groups": [
    {"group": {...}, "role": "use"}
  ]
}
```

**Go handler summary** (lines 105-179):
1. Fetch template user roles via `GetTemplateUserRoles()`.
2. Fetch template group roles via `GetTemplateGroupRoles()`.
3. For each group, fetch members using system context.
4. Convert roles (action sets) to template role names (`admin`, `use`).

**Implementation notes**:
- Template roles are derived from action sets, not stored as strings.
- `admin` = full actions, `use` = read + use actions.
- Uses system context to read group members (caller may not have group read permission).

---

### 3.9 PATCH `/templates/{template}/acl`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/templates.go` → `patchTemplateACL()` |
| **SDK Method** | `UpdateTemplateACL` |
| **Scope** | `enterprise` |
| **Request** | `codersdk.UpdateTemplateACL` (JSON body) |
| **Response** | `codersdk.Response` |
| **Auth** | Via middleware |
| **Audit** | Yes — `database.AuditActionWrite` on `database.Template` |
| **Feature gate** | `codersdk.FeatureTemplateRBAC` |

**Request shape**:
```json
{
  "user_perms": {
    "user-uuid": "admin"
  },
  "group_perms": {
    "group-uuid": "use"
  }
}
```

**Go handler summary** (lines 191-268):
1. Validate ACL entries (valid UUIDs, valid roles).
2. Inside a transaction:
   - Re-fetch the template (for consistency).
   - For each user perm: add/update/delete from `template.UserACL`.
   - For each group perm: add/update/delete from `template.GroupACL`.
   - Write back via `UpdateTemplateACLByID()`.

**Implementation notes**:
- Role `"deleted"` removes the ACL entry.
- Validate that all referenced user/group UUIDs exist.
- The ACL is stored as a JSON map on the template record.

---

### 3.10 GET `/templates/{template}/acl/available`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/templates.go` → `templateAvailablePermissions()` |
| **SDK Method** | `TemplateACLAvailable` |
| **Scope** | `enterprise` |
| **Request** | Path param: `{template}` (UUID) |
| **Response** | `codersdk.ACLAvailable` |
| **Auth** | `policy.ActionUpdate` on the template |
| **Feature gate** | `codersdk.FeatureTemplateRBAC` |

**Response shape**:
```json
{
  "users": [...],
  "groups": [...]
}
```

**Go handler summary** (lines 32-95):
1. Authorize caller for template update.
2. Fetch all users using system context (via `GetUsers()`).
3. Fetch all groups in the template's organization using system context.
4. For each group, fetch members and member count.
5. Return the combined list.

**Implementation notes**:
- Uses system context because the caller may not have permission to list all users.
- Returns all users and all groups in the template's organization.
- This is used by the UI to populate ACL assignment dropdowns.

---

### 3.11 POST `/templates/{template}/prebuilds/invalidate`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/templates.go` → `postInvalidateTemplatePresets()` |
| **SDK Method** | `InvalidateTemplatePresets` |
| **Scope** | `enterprise` |
| **Request** | Path param: `{template}` (UUID) |
| **Response** | `codersdk.InvalidatePresetsResponse` |
| **Auth** | `policy.ActionUpdate` on the template |

**Go handler summary** (lines 351-388):
1. Authorize caller.
2. Call `UpdatePresetsLastInvalidatedAt()` for all presets of the active template version.
3. Return the list of invalidated presets.

**Implementation notes**:
- Updates `last_invalidated_at` timestamp on presets associated with the template's active version.
- Returns an array of `{ id, name, last_invalidated_at }` objects.
- If no presets exist, return an empty array (not null).

---

### 3.12 POST `/organizations/{organization}/provisionerkeys`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/provisionerkeys.go` → `postProvisionerKey()` |
| **SDK Method** | `CreateProvisionerKey` |
| **Scope** | `enterprise` |
| **Request** | `codersdk.CreateProvisionerKeyRequest` (JSON body) |
| **Response** | `codersdk.CreateProvisionerKeyResponse` (201 Created) |
| **Auth** | Via middleware |

**Request shape**:
```json
{
  "name": "my-key",
  "tags": {"environment": "production"}
}
```

**Go handler summary** (lines 27-98):
1. Validate name is non-empty, <= 64 chars.
2. Validate name is not in `ReservedProvisionerKeyNames()` (case-insensitive).
3. Generate key token via `provisionerkey.New()`.
4. Insert into DB. Handle unique violation → 409.
5. Return the token (only returned once at creation time).

**Implementation notes**:
- Reserved names: `"built-in"`, `"user-auth"`, `"psk"`.
- The key token is a secret returned only at creation time.
- The `tags` field is a string-to-string map.

---

### 3.13 GET `/organizations/{organization}/provisionerkeys`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/provisionerkeys.go` → `provisionerKeys()` |
| **SDK Method** | `ListProvisionerKeys` |
| **Scope** | `enterprise` |
| **Request** | Path param: `{organization}` |
| **Response** | `[]codersdk.ProvisionerKey` |

**Implementation notes**:
- Lists all provisioner keys for the organization, **excluding reserved keys**.
- Uses `ListProvisionerKeysByOrganizationExcludeReserved()`.
- Sort by `created_at`.

---

### 3.14 GET `/organizations/{organization}/provisionerkeys/daemons`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/provisionerkeys.go` → `provisionerKeyDaemons()` |
| **SDK Method** | `ListProvisionerKeyDaemons` |
| **Scope** | `enterprise` |
| **Request** | Path param: `{organization}` |
| **Response** | `[]codersdk.ProvisionerKeyDaemons` |

**Go handler summary** (lines 129-185):
1. List all provisioner keys (including reserved) for the org.
2. If the `user-auth` key is missing (non-default orgs), synthesize one.
3. Fetch all provisioner daemons for the org.
4. Filter daemons to "recent" ones (within 3x heartbeat interval).
5. Match daemons to keys by `daemon.KeyID == key.ID`.

**Response shape**:
```json
[
  {
    "key": {"id": "...", "name": "my-key", ...},
    "daemons": [{"id": "...", "name": "daemon-1", ...}]
  }
]
```

**Implementation notes**:
- The `user-auth` key may need to be synthesized for non-default organizations.
- Daemons are filtered by heartbeat recency (stale daemons are excluded).

---

### 3.15 DELETE `/organizations/{organization}/provisionerkeys/{provisionerkey}`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/provisionerkeys.go` → `deleteProvisionerKey()` |
| **SDK Method** | `DeleteProvisionerKey` |
| **Scope** | `enterprise` |
| **Request** | Path params: `{organization}`, `{provisionerkey}` |
| **Response** | 204 No Content |

**Implementation notes**:
- Reserved keys (`built-in`, `user-auth`, `psk`) cannot be deleted → 400.
- Delete via `DeleteProvisionerKey(id)`.

---

### 3.16 GET `/provisionerkeys/{provisionerkey}`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/provisionerkeys.go` → `fetchProvisionerKey()` |
| **SDK Method** | `GetProvisionerKey` |
| **Scope** | `enterprise` |
| **Request** | Path param: `{provisionerkey}` |
| **Response** | `codersdk.ProvisionerKey` |
| **Auth** | `CoderProvisionerKey` header (not session token) |

**Implementation notes**:
- This endpoint uses **provisioner key authentication**, not session tokens.
- The key is extracted from the `Coder-Provisioner-Key` header.
- Returns the key details (never the hashed secret).

---

## Phase 4 — IDP Sync, Connection Log, Quotas & Misc

### IDP Sync Routes

There are **16 IDP sync routes** that follow a highly repetitive pattern across 3 sync domains: **groups**, **roles**, and **organization**. Each domain has the same structure:

| Pattern | Purpose |
|---------|---------|
| `GET .../settings/idpsync/{domain}` | Read current sync settings |
| `PATCH .../settings/idpsync/{domain}` | Update full settings |
| `PATCH .../settings/idpsync/{domain}/config` | Update only config (field, regex filter) |
| `PATCH .../settings/idpsync/{domain}/mapping` | Update only field-to-resource mapping |

Plus 4 shared utility endpoints:

| Route | Purpose |
|-------|---------|
| `GET .../settings/idpsync/available-fields` | List OIDC claim fields available for mapping |
| `GET .../settings/idpsync/field-values` | List values seen for a given claim field |

These exist at both **organization level** (`/organizations/{organization}/settings/idpsync/...`) and **deployment level** (`/settings/idpsync/...`).

**Go Source**: `enterprise/coderd/idpsync.go` (873 lines)

**Common pattern for all GET endpoints**:
```go
func (api *API) idpSyncSettings(domain) handler {
    // Use system context for DB reads
    ctx = dbauthz.AsSystemRestricted(ctx)
    settings, err := api.IDPSync.Get{Domain}SyncSettings(ctx, db, orgID)
    // Return settings
}
```

**Common pattern for all PATCH endpoints**:
```go
func (api *API) patchIdpSyncSettings(domain) handler {
    // Authorize: policy.ActionUpdate on rbac.ResourceIdpsyncSettings (in org)
    // Parse request body
    // Use system context
    // Inside transaction:
    //   1. Read current settings
    //   2. Apply diff/merge
    //   3. Write updated settings
    // Audit log with old/new
    // Return updated settings
}
```

---

### 4.1-4.6 Organization-Level IDP Sync (Groups)

**Routes**:
- `GET /organizations/{organization}/settings/idpsync/groups`
- `PATCH /organizations/{organization}/settings/idpsync/groups`
- `PATCH /organizations/{organization}/settings/idpsync/groups/config`
- `PATCH /organizations/{organization}/settings/idpsync/groups/mapping`

**Settings shape** (`codersdk.GroupSyncSettings`):
```json
{
  "field": "groups",
  "regex_filter": "^team-.*",
  "auto_create_missing_groups": true,
  "mapping": {
    "idp-group-name": ["coder-group-uuid-1", "coder-group-uuid-2"]
  }
}
```

**For the `/config` endpoint**: Only updates `field`, `regex_filter`, and `auto_create_missing_groups`.
**For the `/mapping` endpoint**: Only updates the `mapping` field using a diff of adds/removes.

**PATCH mapping request shape**:
```json
{
  "add": {"idp-value": ["group-uuid-1"]},
  "remove": {"idp-value": ["group-uuid-2"]}
}
```

**Audit**: Yes, all PATCH endpoints audit with `database.AuditActionWrite`.

---

### 4.7-4.12 Organization-Level IDP Sync (Roles)

Same pattern as groups but for role sync:
- `GET /organizations/{organization}/settings/idpsync/roles`
- `PATCH /organizations/{organization}/settings/idpsync/roles`
- `PATCH /organizations/{organization}/settings/idpsync/roles/config`
- `PATCH /organizations/{organization}/settings/idpsync/roles/mapping`

**Settings shape** (`codersdk.RoleSyncSettings`):
```json
{
  "field": "roles",
  "mapping": {
    "idp-role-name": ["coder-role-name-1"]
  }
}
```

---

### 4.13-4.14 Organization-Level IDP Sync (Available Fields & Values)

- `GET /organizations/{organization}/settings/idpsync/available-fields`
- `GET /organizations/{organization}/settings/idpsync/field-values`

**Available fields** returns a list of OIDC claim field names that can be used for sync mapping.

**Field values** returns the distinct values seen for a given claim field. Takes a `field` query parameter.

---

### 4.15-4.20 Deployment-Level IDP Sync (Organization)

- `GET /settings/idpsync/organization`
- `PATCH /settings/idpsync/organization`
- `PATCH /settings/idpsync/organization/config`
- `PATCH /settings/idpsync/organization/mapping`
- `GET /settings/idpsync/available-fields`
- `GET /settings/idpsync/field-values`

Same pattern as org-level sync but scoped to the deployment. The domain is "organization" (sync IDP claims to Coder organizations).

**Settings shape** (`codersdk.OrganizationSyncSettings`):
```json
{
  "field": "organization",
  "assign_default": true,
  "mapping": {
    "idp-org-value": ["coder-org-uuid-1"]
  }
}
```

**Implementation notes for all IDP sync routes**:
- All settings are stored as JSON in the database.
- The `IDPSync` service provides Get/Set methods for each domain.
- Config updates are partial (only modify config fields, preserve mapping).
- Mapping updates use add/remove diff semantics.
- All writes use system context and are audited.

---

### 4.21 GET `/connectionlog`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/connectionlog.go` → `connectionLogs()` |
| **SDK Method** | `ConnectionLogs` |
| **Scope** | `enterprise` |
| **Request** | Query params: `q` (search), `limit`, `offset` |
| **Response** | `codersdk.ConnectionLogResponse` |
| **Auth** | Via RBAC (returns 403 on unauthorized) |

**Go handler summary** (lines 32-90):
1. Parse pagination parameters.
2. Parse search query via `searchquery.ConnectionLogs()`.
3. Count matching logs (capped at 2000).
4. If count == 0, return empty response immediately.
5. Fetch logs with `GetConnectionLogsOffset()`.
6. Convert to SDK types.

**Response shape**:
```json
{
  "connection_logs": [...],
  "count": 150,
  "count_cap": 2000
}
```

**Connection log entry shape**:
```json
{
  "id": "uuid",
  "connect_time": "2024-01-01T00:00:00Z",
  "organization": {"id": "uuid", "name": "default", ...},
  "workspace_owner_id": "uuid",
  "workspace_owner_username": "john",
  "workspace_id": "uuid",
  "workspace_name": "my-ws",
  "agent_name": "main",
  "type": "ssh",
  "ip": "192.168.1.1",
  "web_info": null,
  "ssh_info": {"connection_id": "uuid", "disconnect_reason": "", ...}
}
```

**Implementation notes**:
- The count cap of 2000 prevents expensive count queries.
- Connection types: `workspace_app`, `port_forwarding`, `ssh`, `reconnecting_pty`, `jetbrains`, `vscode`.
- `web_info` is populated for web-based connections (apps, port forwarding).
- `ssh_info` is populated for SSH-based connections (SSH, reconnecting PTY, JetBrains, VS Code).
- Search query supports filtering by user, workspace, type, organization, etc.

---

### 4.22 GET `/scim/v2/ServiceProviderConfig`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/scim.go` → `scimServiceProviderConfig()` |
| **SDK Method** | — |
| **Scope** | `enterprise` |
| **Request** | None |
| **Response** | SCIM ServiceProviderConfig (JSON) |
| **Auth** | SCIM Bearer token |

**Implementation notes**:
- Returns a static SCIM 2.0 ServiceProviderConfig document.
- The response describes the SCIM capabilities of the server (supported operations, bulk support, filter support, etc.).
- Authentication is via the SCIM API key (Bearer token), not session cookies.

---

### 4.23 DELETE `/oauth2/tokens`

| Field | Value |
|-------|-------|
| **Go Source** | `coderd/oauth2.go` → `deleteOAuth2ProviderAppTokens()` |
| **SDK Method** | `RevokeOAuth2ProviderApp` |
| **Scope** | `enterprise` |
| **Request** | Query param: `client_id` |
| **Response** | 204 No Content |
| **Auth** | Session token |

**Go handler**: Delegates to `oauth2provider.RevokeApp(api.Database)`.

**Implementation notes**:
- Revokes all tokens for a given OAuth2 application (identified by `client_id`).
- This is the "revoke app access" endpoint, not individual token revocation.
- The `client_id` is passed as a query parameter.

---

### 4.24 GET `/workspaces/{workspace}/external-agent/{agent}/credentials`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/workspaceagents.go` → `workspaceExternalAgentCredentials()` |
| **SDK Method** | `WorkspaceExternalAgentCredentials` |
| **Scope** | `enterprise` |
| **Request** | Path params: `{workspace}` (UUID), `{agent}` (name) |
| **Response** | `codersdk.ExternalAgentCredentials` |
| **Auth** | Via `WorkspaceParam` middleware |

**Go handler summary** (lines 35-98):
1. Get the latest workspace build.
2. Check `build.HasExternalAgent` → 404 if false.
3. Get all agents for the workspace + build number.
4. Find the agent by name → 404 if not found.
5. Check `agent.AuthInstanceID` is not set (external agents don't use instance auth) → 404 if set.
6. Generate the init script URL and command.

**Response shape**:
```json
{
  "agent_token": "token-string",
  "command": "curl -fsSL \"https://coder.example.com/api/v2/init-script/linux/amd64\" | CODER_AGENT_TOKEN=\"token\" sh"
}
```

**Implementation notes**:
- The command differs for Windows vs. other OS.
- The init script URL is constructed from the access URL + agent OS + architecture.
- The agent token is the `auth_token` field on the workspace agent.

---

## Phase 5 — Workspace Proxies & WebSocket Coordination

This is the most complex feature area. Workspace proxies are satellite instances that handle workspace traffic closer to users.

### Common Dependencies

Before implementing any proxy route, ensure:
1. **Proxy health service** — tracks health of all proxies.
2. **Proxy authentication middleware** — validates proxy tokens.
3. **Token generation** — `generateWorkspaceProxyToken()` creates a `proxyID:secret` token.
4. **Conversion functions** — `convertProxy()`, `convertProxies()`, `convertRegion()`.

---

### 5.1 GET `/workspaceproxies`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/workspaceproxy.go` → `workspaceProxies()` |
| **SDK Method** | `WorkspaceProxies` |
| **Scope** | `enterprise` |
| **Request** | None |
| **Response** | `codersdk.RegionsResponse[codersdk.WorkspaceProxy]` |
| **Auth** | RBAC (returns 403 for unauthorized) |

**Go handler summary** (lines 421-435):
1. Fetch all workspace proxies from DB.
2. Prepend the primary proxy.
3. Get health status for each proxy.
4. Convert and return.

**Implementation notes**:
- Always includes the primary proxy as the first item.
- Health statuses come from the `ProxyHealth` service.
- Status values: `ok`, `unhealthy`, `unreachable`, `unregistered`, `unknown`.

---

### 5.2 POST `/workspaceproxies`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/workspaceproxy.go` → `postWorkspaceProxy()` |
| **SDK Method** | `CreateWorkspaceProxy` |
| **Scope** | `enterprise` |
| **Request** | `codersdk.CreateWorkspaceProxyRequest` (JSON body) |
| **Response** | `codersdk.UpdateWorkspaceProxyResponse` (201 Created) |
| **Auth** | Via middleware |
| **Audit** | Yes — `database.AuditActionCreate` on `database.WorkspaceProxy` |

**Request shape**:
```json
{
  "name": "eu-proxy",
  "display_name": "Europe Proxy",
  "icon": "/emojis/1f1ea-1f1fa.png"
}
```

**Go handler summary** (lines 317-397):
1. Validate name is not `"primary"` (reserved).
2. Generate proxy ID and token.
3. Insert proxy with `InsertWorkspaceProxy()`.
4. Handle unique name violation → 409.
5. Report telemetry.
6. Return proxy + token (token only returned at creation).
7. Force proxy health update in background.

**Response shape**:
```json
{
  "proxy": {...},
  "proxy_token": "proxy-id:secret-token"
}
```

---

### 5.3 GET `/workspaceproxies/{workspaceproxy}`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/workspaceproxy.go` → `workspaceProxy()` |
| **SDK Method** | `WorkspaceProxyByName` |
| **Scope** | `enterprise` |
| **Request** | Path param: `{workspaceproxy}` (UUID or name) |
| **Response** | `codersdk.WorkspaceProxy` |

**Implementation notes**:
- Simple read via `WorkspaceProxyParam` middleware.
- Return proxy with health status.

---

### 5.4 PATCH `/workspaceproxies/{workspaceproxy}`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/workspaceproxy.go` → `patchWorkspaceProxy()` |
| **SDK Method** | `PatchWorkspaceProxy` |
| **Scope** | `enterprise` |
| **Request** | `codersdk.PatchWorkspaceProxy` (JSON body) |
| **Response** | `codersdk.UpdateWorkspaceProxyResponse` |
| **Auth** | Via middleware |
| **Audit** | Yes |

**Request shape**:
```json
{
  "name": "new-name",
  "display_name": "New Display",
  "icon": "/emojis/new.png",
  "regenerate_token": false
}
```

**Go handler summary** (lines 98-175):
1. If `regenerate_token` → generate new token.
2. Check if this is the primary proxy → special handling via `patchPrimaryWorkspaceProxy()`.
   - Primary proxy: cannot change name, can only change display_name and icon.
3. Otherwise, update via `UpdateWorkspaceProxy()`.
4. Return updated proxy + new token (if regenerated).
5. Force proxy health update.

**Implementation notes**:
- The primary proxy is identified by checking if `proxy.ID == deploymentID`.
- The primary proxy has restrictions on what can be updated.

---

### 5.5 DELETE `/workspaceproxies/{workspaceproxy}`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/workspaceproxy.go` → `deleteWorkspaceProxy()` |
| **SDK Method** | `DeleteWorkspaceProxyByName` |
| **Scope** | `enterprise` |
| **Request** | Path param: `{workspaceproxy}` |
| **Response** | `codersdk.Response` |
| **Auth** | Via middleware |
| **Audit** | Yes — `database.AuditActionDelete` |

**Implementation notes**:
- The primary proxy cannot be deleted → 400.
- Soft-delete via `UpdateWorkspaceProxyDeleted()`.
- Force proxy health update after deletion.

---

### 5.6 POST `/workspaceproxies/me/register`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/workspaceproxy.go` → `workspaceProxyRegister()` |
| **SDK Method** | — |
| **Scope** | `enterprise` |
| **Request** | `wsproxysdk.RegisterWorkspaceProxyRequest` (JSON body) |
| **Response** | `wsproxysdk.RegisterWorkspaceProxyResponse` |
| **Auth** | Proxy token authentication |

**Go handler summary** (lines 558-740):
This is the most complex proxy endpoint:
1. Validate the proxy URL.
2. Check protocol version compatibility.
3. Look up or create the replica record.
4. Update the proxy record with connection info (URL, wildcard hostname, DERP settings, version).
5. Return configuration including:
   - DERP mesh key
   - DERP map
   - DERP force WebSocket flag
   - Sibling replicas list
   - App security key

**Implementation notes**:
- This is called by workspace proxy instances when they start up.
- The response includes sensitive configuration needed for the proxy to operate.
- DERP mesh coordination is critical for the tailnet to function.
- Uses `InsertReplica()` or `UpdateReplica()` depending on whether the replica exists.

---

### 5.7 POST `/workspaceproxies/me/deregister`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/workspaceproxy.go` → `workspaceProxyDeregister()` |
| **SDK Method** | — |
| **Scope** | `enterprise` |
| **Request** | `wsproxysdk.DeregisterWorkspaceProxyRequest` |
| **Response** | 204 No Content |
| **Auth** | Proxy token |

**Go handler summary** (lines 794-855):
1. Delete the replica record.
2. Force proxy health update.

---

### 5.8 GET `/workspaceproxies/me/crypto-keys`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/workspaceproxy.go` → `workspaceProxyCryptoKeys()` |
| **SDK Method** | — |
| **Scope** | `enterprise` |
| **Request** | None |
| **Response** | `wsproxysdk.CryptoKeysResponse` |
| **Auth** | Proxy token |

**Go handler summary** (lines 756-783):
- Fetches crypto keys filtered to whitelisted features: `WorkspaceAppsToken` and `WorkspaceAppsAPIKey`.
- Returns active keys with their secrets.

---

### 5.9 POST `/workspaceproxies/me/issue-signed-app-token`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/workspaceproxy.go` → `workspaceProxyIssueSignedAppToken()` |
| **SDK Method** | — |
| **Scope** | `enterprise` |
| **Request** | `workspaceapps.IssueTokenRequest` |
| **Response** | `wsproxysdk.IssueSignedAppTokenResponse` |
| **Auth** | Proxy token |

**Implementation notes**:
- Called by workspace proxies to get signed tokens for accessing workspace apps.
- The token is signed using the app security key.
- Returns HTML error pages on failure (not JSON).

---

### 5.10 POST `/workspaceproxies/me/app-stats`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/workspaceproxy.go` → `workspaceProxyReportAppStats()` |
| **SDK Method** | — |
| **Scope** | `enterprise` |
| **Request** | `wsproxysdk.ReportAppStatsRequest` |
| **Response** | `codersdk.Response` |
| **Auth** | Proxy token |

**Go handler summary** (lines 518-537):
- Receives app usage statistics from workspace proxies.
- Stores them in the stats reporter.

---

### 5.11 GET `/workspaceproxies/me/coordinate` (WebSocket)

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/workspaceproxycoordinate.go` → `workspaceProxyCoordinate()` |
| **SDK Method** | — |
| **Scope** | `enterprise` |
| **Request** | WebSocket upgrade, optional `?version=` query param |
| **Response** | WebSocket connection |
| **Auth** | Proxy token |

**Go handler summary** (lines 22-70):
1. Parse `version` query parameter (default "1.0").
2. Validate against `proto.CurrentVersion`.
3. Version >= 2 uses binary WebSocket messages (dRPC), version 1 uses text.
4. Accept WebSocket connection.
5. Create a `WebsocketNetConn`.
6. Serve multi-agent coordination via `api.tailnetService.ServeMultiAgentClient()`.

**Implementation notes**:
- This is a **long-lived WebSocket connection** for tailnet coordination.
- Workspace proxies use this to coordinate with the control plane for agent connectivity.
- The protocol switches between text (v1) and binary (v2+) based on the version.
- This requires the tailnet service infrastructure.

---

### 5.12 POST `/applications/reconnecting-pty-signed-token`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/workspaceproxy.go` → `reconnectingPTYSignedToken()` |
| **SDK Method** | `IssueReconnectingPTYSignedToken` |
| **Scope** | `enterprise` |
| **Request** | `codersdk.IssueReconnectingPTYSignedTokenRequest` (JSON body) |
| **Response** | `codersdk.IssueReconnectingPTYSignedTokenResponse` |
| **Auth** | Session token |

**Go handler summary** (lines 871-952):
1. Look up the workspace by agent ID.
2. Verify the agent belongs to the workspace.
3. Sign a reconnecting PTY token using the app signing key.
4. Return the signed token.

---

## Phase 6 — AI Bridge & Remaining Routes

### 6.1 GET `/aibridge/interceptions`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/aibridge.go` → `aiBridgeInterceptions()` |
| **SDK Method** | `AIBridgeListInterceptions` |
| **Scope** | `oss` |
| **Request** | Query params: pagination (`after_id`, `limit`), filters |
| **Response** | Paginated list of AI bridge interceptions |

**Implementation notes**:
- Uses cursor-based pagination (`after_id` parameter).
- The AI Bridge feature intercepts and logs AI model interactions.
- See `enterprise/coderd/aibridge.go` for the full handler (685 lines).
- Requires search query parsing for filtering.

---

### 6.2 GET `/aibridge/models`

| Field | Value |
|-------|-------|
| **Go Source** | `enterprise/coderd/aibridge.go` → `aiBridgeModels()` |
| **SDK Method** | — |
| **Scope** | `oss` |
| **Request** | None |
| **Response** | List of available AI models |

**Implementation notes**:
- Returns the list of AI models configured for the AI bridge.
- Relatively simple read-only endpoint.

---

## Cross-Cutting Concerns

### Feature Entitlements

Most enterprise routes require specific license entitlements. The middleware pattern is:

```rust
// In route registration:
.route("/appearance", get(appearance_handler))
    .layer(require_feature(Feature::Appearance))
```

Entitlements to implement:
- `FeatureAppearance` — appearance settings
- `FeatureTemplateRBAC` — groups, template ACL, provisioner keys
- `FeatureAdvancedTemplateScheduling` — quiet hours
- `FeatureWorkspaceProxy` — workspace proxy management
- `FeatureExternalTokenEncryption` — crypto keys
- `FeatureMultipleOrganizations` — org CRUD (beyond default)

### Database Schema

Many of the missing routes require new database tables/queries:
- `workspace_proxies` — proxy CRUD
- `replicas` — replica tracking
- `groups` / `group_members` — group management
- `provisioner_keys` — provisioner key management
- `connection_logs` — connection logging
- `custom_roles` — custom organization roles

Check the Go migration files under `coder/coderd/database/migrations/` for the exact schema.

### Audit Logging

Routes marked with "Audit: Yes" need to create audit log entries. The pattern:
1. Capture the "old" state before mutation.
2. Perform the mutation.
3. Capture the "new" state.
4. Write an audit log entry with both states, the action type, and request metadata.

### Error Response Format

All errors should follow the standard Coder response format:

```json
{
  "message": "Human-readable message",
  "detail": "Technical detail (optional)",
  "validations": [
    {"field": "name", "detail": "Name is required"}
  ]
}
```

### System Context

Some operations need to bypass RBAC:
- Listing all users for ACL assignment
- Reading group members for template ACL
- IDP sync settings (read/write)
- Role reconciliation

Use the system-restricted context for these operations.

---

## Appendix A — Full Missing Route Inventory

The canonical, always-up-to-date list of missing routes is in `docs/parity-matrix-all.md` (regenerate with `make parity-refresh`). Below is a snapshot at time of writing (68 routes), grouped by feature area.

### Appearance (2 routes)
| Method | Path | Go Source |
|--------|------|-----------|
| GET | `/appearance` | `enterprise/coderd/appearance.go` |
| PUT | `/appearance` | `enterprise/coderd/appearance.go` |

### Prebuilds Settings (2 routes)
| Method | Path | Go Source |
|--------|------|-----------|
| GET | `/prebuilds/settings` | `enterprise/coderd/prebuilds.go` |
| PUT | `/prebuilds/settings` | `enterprise/coderd/prebuilds.go` |

### User Quiet Hours (2 routes)
| Method | Path | Go Source |
|--------|------|-----------|
| GET | `/users/{user}/quiet-hours` | `enterprise/coderd/users.go` |
| PUT | `/users/{user}/quiet-hours` | `enterprise/coderd/users.go` |

### Replicas (1 route)
| Method | Path | Go Source |
|--------|------|-----------|
| GET | `/replicas` | `enterprise/coderd/replicas.go` |

### Workspace Quota (2 routes)
| Method | Path | Go Source |
|--------|------|-----------|
| GET | `/workspace-quota/{user}` | `enterprise/coderd/workspacequota.go` |
| GET | `/organizations/{organization}/members/{user}/workspace-quota` | `enterprise/coderd/workspacequota.go` |

### Workspace Sharing (2 routes)
| Method | Path | Go Source |
|--------|------|-----------|
| GET | `/organizations/{organization}/settings/workspace-sharing` | `enterprise/coderd/workspacesharing.go` |
| PATCH | `/organizations/{organization}/settings/workspace-sharing` | `enterprise/coderd/workspacesharing.go` |

### Licenses (1 route)
| Method | Path | Go Source |
|--------|------|-----------|
| POST | `/licenses/refresh-entitlements` | `enterprise/coderd/licenses.go` |

### Organization CRUD (3 routes)
| Method | Path | Go Source |
|--------|------|-----------|
| POST | `/organizations` | `enterprise/coderd/organizations.go` |
| PATCH | `/organizations/{organization}` | `enterprise/coderd/organizations.go` |
| DELETE | `/organizations/{organization}` | `enterprise/coderd/organizations.go` |

### Custom Roles (3 routes)
| Method | Path | Go Source |
|--------|------|-----------|
| POST | `/organizations/{organization}/members/roles` | `enterprise/coderd/roles.go` |
| PUT | `/organizations/{organization}/members/roles` | `enterprise/coderd/roles.go` |
| DELETE | `/organizations/{organization}/members/roles/{roleName}` | `enterprise/coderd/roles.go` |

### Groups (7 routes)
| Method | Path | Go Source |
|--------|------|-----------|
| GET | `/groups` | `enterprise/coderd/groups.go` |
| GET | `/groups/{group}` | `enterprise/coderd/groups.go` |
| PATCH | `/groups/{group}` | `enterprise/coderd/groups.go` |
| DELETE | `/groups/{group}` | `enterprise/coderd/groups.go` |
| GET | `/organizations/{organization}/groups` | `enterprise/coderd/groups.go` |
| POST | `/organizations/{organization}/groups` | `enterprise/coderd/groups.go` |
| GET | `/organizations/{organization}/groups/{groupName}` | `enterprise/coderd/groups.go` |

### Template ACL (4 routes)
| Method | Path | Go Source |
|--------|------|-----------|
| GET | `/templates/{template}/acl` | `enterprise/coderd/templates.go` |
| PATCH | `/templates/{template}/acl` | `enterprise/coderd/templates.go` |
| GET | `/templates/{template}/acl/available` | `enterprise/coderd/templates.go` |
| POST | `/templates/{template}/prebuilds/invalidate` | `enterprise/coderd/templates.go` |

### Provisioner Keys (5 routes)
| Method | Path | Go Source |
|--------|------|-----------|
| POST | `/organizations/{organization}/provisionerkeys` | `enterprise/coderd/provisionerkeys.go` |
| GET | `/organizations/{organization}/provisionerkeys` | `enterprise/coderd/provisionerkeys.go` |
| GET | `/organizations/{organization}/provisionerkeys/daemons` | `enterprise/coderd/provisionerkeys.go` |
| DELETE | `/organizations/{organization}/provisionerkeys/{provisionerkey}` | `enterprise/coderd/provisionerkeys.go` |
| GET | `/provisionerkeys/{provisionerkey}` | `enterprise/coderd/provisionerkeys.go` |

### IDP Sync (16 routes)
| Method | Path | Go Source |
|--------|------|-----------|
| GET | `/organizations/{organization}/settings/idpsync/groups` | `enterprise/coderd/idpsync.go` |
| PATCH | `/organizations/{organization}/settings/idpsync/groups` | `enterprise/coderd/idpsync.go` |
| PATCH | `/organizations/{organization}/settings/idpsync/groups/config` | `enterprise/coderd/idpsync.go` |
| PATCH | `/organizations/{organization}/settings/idpsync/groups/mapping` | `enterprise/coderd/idpsync.go` |
| GET | `/organizations/{organization}/settings/idpsync/roles` | `enterprise/coderd/idpsync.go` |
| PATCH | `/organizations/{organization}/settings/idpsync/roles` | `enterprise/coderd/idpsync.go` |
| PATCH | `/organizations/{organization}/settings/idpsync/roles/config` | `enterprise/coderd/idpsync.go` |
| PATCH | `/organizations/{organization}/settings/idpsync/roles/mapping` | `enterprise/coderd/idpsync.go` |
| GET | `/organizations/{organization}/settings/idpsync/available-fields` | `enterprise/coderd/idpsync.go` |
| GET | `/organizations/{organization}/settings/idpsync/field-values` | `enterprise/coderd/idpsync.go` |
| GET | `/settings/idpsync/organization` | `enterprise/coderd/idpsync.go` |
| PATCH | `/settings/idpsync/organization` | `enterprise/coderd/idpsync.go` |
| PATCH | `/settings/idpsync/organization/config` | `enterprise/coderd/idpsync.go` |
| PATCH | `/settings/idpsync/organization/mapping` | `enterprise/coderd/idpsync.go` |
| GET | `/settings/idpsync/available-fields` | `enterprise/coderd/idpsync.go` |
| GET | `/settings/idpsync/field-values` | `enterprise/coderd/idpsync.go` |

### Connection Log (1 route)
| Method | Path | Go Source |
|--------|------|-----------|
| GET | `/connectionlog` | `enterprise/coderd/connectionlog.go` |

### SCIM (1 route)
| Method | Path | Go Source |
|--------|------|-----------|
| GET | `/scim/v2/ServiceProviderConfig` | `enterprise/coderd/scim.go` |

### OAuth2 (1 route)
| Method | Path | Go Source |
|--------|------|-----------|
| DELETE | `/oauth2/tokens` | `coderd/oauth2.go` |

### Workspace Agents (1 route)
| Method | Path | Go Source |
|--------|------|-----------|
| GET | `/workspaces/{workspace}/external-agent/{agent}/credentials` | `enterprise/coderd/workspaceagents.go` |

### Workspace Proxies (11 routes)
| Method | Path | Go Source |
|--------|------|-----------|
| GET | `/workspaceproxies` | `enterprise/coderd/workspaceproxy.go` |
| POST | `/workspaceproxies` | `enterprise/coderd/workspaceproxy.go` |
| GET | `/workspaceproxies/{workspaceproxy}` | `enterprise/coderd/workspaceproxy.go` |
| PATCH | `/workspaceproxies/{workspaceproxy}` | `enterprise/coderd/workspaceproxy.go` |
| DELETE | `/workspaceproxies/{workspaceproxy}` | `enterprise/coderd/workspaceproxy.go` |
| POST | `/workspaceproxies/me/register` | `enterprise/coderd/workspaceproxy.go` |
| POST | `/workspaceproxies/me/deregister` | `enterprise/coderd/workspaceproxy.go` |
| GET | `/workspaceproxies/me/crypto-keys` | `enterprise/coderd/workspaceproxy.go` |
| POST | `/workspaceproxies/me/issue-signed-app-token` | `enterprise/coderd/workspaceproxy.go` |
| POST | `/workspaceproxies/me/app-stats` | `enterprise/coderd/workspaceproxy.go` |
| GET | `/workspaceproxies/me/coordinate` | `enterprise/coderd/workspaceproxycoordinate.go` |

### Reconnecting PTY (1 route)
| Method | Path | Go Source |
|--------|------|-----------|
| POST | `/applications/reconnecting-pty-signed-token` | `enterprise/coderd/workspaceproxy.go` |

### AI Bridge (2 routes)
| Method | Path | Go Source |
|--------|------|-----------|
| GET | `/aibridge/interceptions` | `enterprise/coderd/aibridge.go` |
| GET | `/aibridge/models` | `enterprise/coderd/aibridge.go` |

---

**Total: 68 missing routes**

> To verify this list is current, run:
> ```bash
> make parity-refresh
> grep "| missing |" docs/parity-matrix-all.md | wc -l
> ```
