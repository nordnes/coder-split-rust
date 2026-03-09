# Gap Analysis: Go Reference → Rust Rewrite

> **Generated**: 2026-03-09  
> **Scope**: OSS features only (enterprise-only features excluded)  
> **Baseline**: 72 of 229 OSS routes ported (31%)

---

## 1. Executive Summary

The Rust rewrite of the Coder backend has established a solid foundation covering authentication, identity management, organization membership, audit logging, deployment health, and basic operational statistics — representing 72 of 229 OSS routes (31%). The ported vertical slice is deep: it includes full database migrations, domain types, API models, storage trait contracts, service layers, and HTTP handlers for the auth/identity/operations domain. However, the remaining 157 routes span the platform's core value proposition — **workspace lifecycle management, template orchestration, provisioner job coordination, and agent connectivity** — which together represent the bulk of both code complexity and user-facing functionality.

The database layer is the widest gap: the Go schema defines **88 tables** and **48 enum types** backed by **579 named queries** across 66 query files. The Rust rewrite has **15 tables**, **2 enum types**, and **~62 store methods**. Many of the Rust tables are structural stubs (e.g., `workspaces`, `workspace_builds`, `provisioner_jobs`) that exist only to support deployment-stats aggregation queries and contain a fraction of the columns present in Go. On the SDK/API type front, Go's `codersdk` package defines **~416 structs** across 50+ files; the Rust `coder-core` crate has **~82 API structs** and **~29 domain types** — roughly 27% coverage by count, though many complex domain types (templates, workspaces, builds, agents) are entirely absent.

Beyond routes and data, the Go backend relies on **12+ background systems** (provisioner daemon orchestration, tailnet/DERP coordination, autobuild scheduling, workspace dormancy, notification dispatch, agent API server, pub/sub eventing, telemetry collection, update checking, and more). The Rust rewrite currently implements **only deployment-stats caching** as a background service; all other systems are stubs or absent. Closing this gap requires not just porting HTTP handlers but building the concurrent infrastructure that makes them meaningful.

---

## 2. Route-Level Gaps

### 2.1 Summary by Domain

| Domain | Total Routes | Ported | Missing | % Complete |
|--------|-------------|--------|---------|------------|
| Root & Build Info | 3 | 3 | 0 | 100% |
| Authentication & Login | 12 | 12 | 0 | 100% |
| Users & Identity | 28 | 24 | 4 | 86% |
| Organizations & Members | 15 | 13 | 2 | 87% |
| API Keys & Tokens | 8 | 8 | 0 | 100% |
| External Auth | 7 | 7 | 0 | 100% |
| Audit | 2 | 2 | 0 | 100% |
| Deployment Config & Health | 8 | 3 | 5 | 38% |
| Templates & Versions | 33 | 0 | 33 | 0% |
| Workspaces & Builds | 32 | 0 | 32 | 0% |
| Workspace Agents | 20 | 0 | 20 | 0% |
| Debug & Observability | 11 | 0 | 11 | 0% |
| AI Tasks | 10 | 0 | 10 | 0% |
| Notifications & Inbox | 13 | 0 | 13 | 0% |
| Insights & Analytics | 5 | 0 | 5 | 0% |
| Chats | 5 | 0 | 5 | 0% |
| Files | 2 | 0 | 2 | 0% |
| Other (params, presets, provisioner jobs, proxies, etc.) | 15 | 0 | 15 | 0% |
| **Total** | **229** | **72** | **157** | **31%** |

### 2.2 Templates & Versions (33 missing routes)

**Go source**: `coderd/templates.go` (1,151 lines), `coderd/templateversions.go` (2,022 lines)

This is the largest missing domain and a prerequisite for workspace creation. Templates define the infrastructure blueprint; template versions track iterations with parameters, variables, and provisioner job state.

**Key dependencies**: Provisioner jobs, template version parameters, template version variables, workspace tags, presets, files, RBAC (ResourceTemplate).

| Complexity | Count | Examples |
|-----------|-------|---------|
| Simple | 8 | GET template by ID/name, list templates, DELETE template |
| Medium | 15 | PATCH template metadata, GET template DAUs, list template examples, GET/POST template version parameters |
| Complex | 10 | POST create template (orchestrates provisioner job), POST create template version (file upload + provisioner import), template version dry-run, archive/unarchive |

### 2.3 Workspaces & Builds (32 missing routes)

**Go source**: `coderd/workspaces.go` (2,991 lines), `coderd/workspacebuilds.go` (1,433 lines)

Core workspace lifecycle: creation, updates, deletion, builds, autostart/TTL scheduling, dormancy, favorites, port sharing, and real-time watching (SSE/WebSocket).

**Key dependencies**: Templates, template versions, provisioner jobs, workspace agents, workspace builds, RBAC (ResourceWorkspace), pub/sub for watch endpoints.

| Complexity | Count | Examples |
|-----------|-------|---------|
| Simple | 10 | GET workspace by ID, PUT autostart, PUT TTL, PUT favorites, GET build parameters |
| Medium | 12 | PATCH workspace metadata, PUT dormancy, GET workspace list (filtered/paginated), GET build by number, PUT build state |
| Complex | 10 | POST create workspace (provisioner job orchestration), POST create build (transition start/stop/delete), PATCH cancel build, GET workspace watch (SSE), GET build logs (streaming) |

### 2.4 Workspace Agents (20 missing routes)

**Go source**: `coderd/workspaceagents.go` (2,284 lines), `coderd/workspaceagentsrpc.go` (498 lines), `coderd/workspaceresourceauth.go` (209 lines), `coderd/workspaceapps.go` (94 lines), `coderd/workspaceagentportshare.go` (204 lines)

Agent lifecycle, coordination (tailnet), log streaming, PTY terminals, container management, and metadata watching. Most complex subsystem due to WebSocket/streaming requirements.

**Key dependencies**: Tailnet coordinator, DERP, pub/sub, agent API server, workspace agent stats, instance identity verification.

| Complexity | Count | Examples |
|-----------|-------|---------|
| Simple | 4 | GET agent by ID, GET connection info, GET listening ports, PATCH app status |
| Medium | 6 | GET/POST containers, POST log source, PATCH logs, DELETE/POST/GET port-share |
| Complex | 10 | GET coordinate (WebSocket + tailnet), GET PTY (WebSocket terminal), GET agent RPC (dRPC/WebSocket), GET watch-metadata (SSE), POST instance identity auth (AWS/Azure/GCP), GET reinit |

### 2.5 Debug & Observability (11 missing routes, 3 already ported as health-adjacent)

**Go source**: `coderd/debug.go` (385 lines)

Debug endpoints for pprof, expvar, coordinator state, tailnet, and DERP diagnostics.

| Complexity | Count | Examples |
|-----------|-------|---------|
| Simple | 5 | GET debug pprof, GET debug expvar, GET coordinator debug |
| Medium | 4 | GET tailnet debug, GET DERP traffic debug |
| Complex | 2 | WebSocket-based debug endpoints |

### 2.6 AI Tasks (10 missing routes)

**Go source**: `coderd/aitasks.go` (1,439 lines)

Newer feature for AI-driven task management within workspaces. Full CRUD plus status management (pause/resume/send).

| Complexity | Count | Examples |
|-----------|-------|---------|
| Simple | 3 | GET task by ID, GET task input |
| Medium | 4 | GET tasks list, POST create task, POST log snapshot |
| Complex | 3 | PATCH task (pause/resume/send with state machine transitions) |

### 2.7 Notifications & Inbox (13 missing routes)

**Go source**: `coderd/notifications.go` (458 lines), `coderd/inboxnotifications.go` (460 lines), `coderd/webpush.go` (148 lines)

Notification settings, dispatch method configuration, inbox management with SSE watching, and web push subscriptions.

| Complexity | Count | Examples |
|-----------|-------|---------|
| Simple | 5 | GET/PUT notification preferences, DELETE/POST webpush subscription |
| Medium | 5 | GET notification settings, PUT dispatch methods, POST test notification, GET inbox list |
| Complex | 3 | GET inbox watch (SSE), POST test webpush, PUT notification template method |

### 2.8 Insights & Analytics (5 missing routes)

**Go source**: `coderd/insights.go` (824 lines)

Template usage analytics, user activity/latency insights, user status counts, and DAU metrics with complex aggregation queries.

| Complexity | Count | Examples |
|-----------|-------|---------|
| Simple | 1 | GET DAUs |
| Medium | 2 | GET user-status-counts, GET user-latency |
| Complex | 2 | GET template insights (complex time-series aggregation), GET user-activity |

### 2.9 Chats (5 missing routes)

**Go source**: `coderd/chats.go` (3,697 lines)

Experimental chat/AI feature with message management, LLM integration. Notably large handler file.

| Complexity | Count | Examples |
|-----------|-------|---------|
| Simple | 2 | GET chat, DELETE chat |
| Medium | 1 | GET chats list |
| Complex | 2 | POST create chat, POST create message (LLM streaming) |

### 2.10 Files (2 missing routes)

**Go source**: `coderd/files.go` (211 lines)

Binary file upload and retrieval, used by template versions for Terraform configs.

| Complexity | Count | Examples |
|-----------|-------|---------|
| Simple | 1 | GET file by ID |
| Medium | 1 | POST upload file (binary body, content hashing) |

### 2.11 Other Missing Routes (15 routes)

**Go sources**: `coderd/parameters.go` (205 lines), `coderd/presets.go` (74 lines), `coderd/provisionerjobs.go` (691 lines), `coderd/provisionerdaemons.go` (115 lines), `coderd/deprecated.go` (85 lines), `coderd/authorize.go` (271 lines), `coderd/workspaceproxies.go` (94 lines)

| Sub-domain | Routes | Complexity |
|-----------|--------|-----------|
| Parameters & Presets | 3 | Simple–Medium |
| Provisioner Jobs | 4 | Medium–Complex (log streaming, job state) |
| Provisioner Daemons | 2 | Medium (org-scoped listing) |
| Authorization check | 1 | Medium (bulk RBAC check) |
| Workspace Proxies | 2 | Medium |
| Deprecated endpoints | 3 | Simple (redirects/aliases) |

---

## 3. Database Schema Gaps

### 3.1 Overview

| Metric | Go | Rust | Coverage |
|--------|-----|------|----------|
| Tables | 88 | 15 | 17% |
| Enum types | 48 | 2 | 4% |
| Named queries | 579 | ~62 | 11% |
| Migration files | 865 | 7 | <1% |
| Query files | 66 | 0 (inline SQL) | 0% |

The Rust rewrite uses inline SQL in `PostgresStore` methods rather than a query generator like sqlc. This is a deliberate architectural choice but means query coverage is measured by store method count.

### 3.2 Rust Tables (15 present)

| Table | Status | Notes |
|-------|--------|-------|
| `site_configs` | Full | Key-value deployment config |
| `organizations` | Full | Org CRUD complete |
| `users` | Full | All identity columns present |
| `organization_members` | Full | Membership with roles |
| `auth_sessions` | Full | Session token auth (Rust-specific, Go uses API keys for sessions) |
| `api_keys` | Full | Token and session keys |
| `audit_logs` | Full | Comprehensive audit trail |
| `git_ssh_keys` | Full | Per-user SSH keypairs |
| `external_auth_links` | Full | OAuth2/OIDC provider links |
| `workspaces` | **Stub** | Only `id`, `owner_id`, `template_id` — used for stats joins |
| `provisioner_jobs` | **Stub** | Only `id`, `created_at`, `organization_id` — stats only |
| `workspace_builds` | **Stub** | Only `id`, `workspace_id`, `build_number`, `transition` — stats only |
| `workspace_agent_stats` | **Stub** | Stats aggregation columns only |
| `workspace_proxies` | Full | Health check support |
| `provisioner_daemons` | Full | Health check support |

### 3.3 Missing Tables (73 tables)

Organized by domain, listing tables that exist in Go's `dump.sql` but are absent or stub-only in Rust.

#### Core Workspace Domain (need full schema, currently stub)

| Table | Go Columns | Description |
|-------|-----------|-------------|
| `workspaces` | ~25 | Full workspace record (name, autostart, TTL, dormancy, last_used, favorite, etc.) |
| `workspace_builds` | ~20 | Build lifecycle (job_id, transition, reason, deadline, provisioner_state) |
| `workspace_resources` | ~12 | Provisioned resources (compute, storage) |
| `workspace_agents` | ~30 | Agent state, lifecycle, architecture, connection info |
| `workspace_apps` | ~20 | In-workspace apps (URLs, health, sharing) |
| `workspace_agent_stats` | ~15 | Full stats (connections, latency, sessions, rx/tx bytes) |
| `workspace_agent_scripts` | ~15 | Agent startup/shutdown scripts |
| `workspace_agent_log_sources` | ~5 | Log source registration |
| `workspace_agent_devcontainers` | ~10 | Dev container state |
| `workspace_agent_port_share` | ~5 | Port sharing configuration |
| `workspace_agent_memory_resource_monitors` | ~10 | Memory monitoring thresholds |
| `workspace_agent_volume_resource_monitors` | ~10 | Volume monitoring thresholds |
| `workspace_agent_script_timings` | ~6 | Script execution timing |
| `workspace_app_stats` | ~10 | App usage statistics |
| `workspace_app_statuses` | ~8 | App health status history |
| `workspace_build_parameters` | ~4 | Build-time parameter values |
| `workspace_modules` | ~6 | Terraform module metadata |
| `workspace_resource_metadata` | ~5 | Resource metadata key-value |
| `workspace_proxies` | ~15 | Full proxy config (currently partial) |

#### Template Domain (entirely missing)

| Table | Go Columns | Description |
|-------|-----------|-------------|
| `templates` | ~30 | Template definition (name, provisioner, max_ttl, policies) |
| `template_versions` | ~20 | Version lifecycle (job_id, readme, message, archive state) |
| `template_version_parameters` | ~15 | Rich parameter definitions |
| `template_version_variables` | ~8 | Template variable values |
| `template_version_presets` | ~10 | Parameter presets |
| `template_version_preset_parameters` | ~4 | Preset parameter values |
| `template_version_preset_prebuild_schedules` | ~4 | Prebuild scheduling |
| `template_version_terraform_values` | ~4 | Terraform value cache |
| `template_version_workspace_tags` | ~3 | Workspace tag definitions |
| `template_usage_stats` | ~12 | Template usage analytics |

#### Provisioner Domain (entirely missing)

| Table | Go Columns | Description |
|-------|-----------|-------------|
| `provisioner_jobs` | ~20 | Full job record (type, input, status, worker, tags, file) |
| `provisioner_job_logs` | ~6 | Job output log entries |
| `provisioner_job_timings` | ~6 | Job stage timing |
| `provisioner_keys` | ~8 | Authentication keys for provisioner daemons |

#### File Storage (entirely missing)

| Table | Go Columns | Description |
|-------|-----------|-------------|
| `files` | ~6 | Uploaded file storage (hash, mimetype, data, created_by) |

#### Notification Domain (entirely missing)

| Table | Go Columns | Description |
|-------|-----------|-------------|
| `notification_messages` | ~15 | Queued notification messages |
| `notification_preferences` | ~4 | Per-user notification preferences |
| `notification_report_generator_logs` | ~3 | Report generation tracking |
| `notification_templates` | ~12 | Notification template definitions |
| `inbox_notifications` | ~10 | In-app inbox items |
| `webpush_subscriptions` | ~6 | Web push subscription endpoints |

#### Chat/AI Domain (entirely missing)

| Table | Go Columns | Description |
|-------|-----------|-------------|
| `chats` | ~8 | Chat sessions |
| `chat_messages` | ~10 | Chat message content |
| `chat_files` | ~5 | Chat file attachments |
| `chat_model_configs` | ~10 | LLM model configurations |
| `chat_providers` | ~8 | AI provider configurations |
| `chat_queued_messages` | ~8 | Queued chat messages |
| `chat_diff_statuses` | ~8 | Chat diff tracking |
| `tasks` | ~15 | AI task records |
| `task_snapshots` | ~8 | Task log snapshots |
| `task_workspace_apps` | ~4 | Task-to-app mappings |

#### Auth & Identity Supplements (partially missing)

| Table | Go Columns | Description |
|-------|-----------|-------------|
| `user_links` | ~10 | OAuth/OIDC identity links |
| `user_configs` | ~3 | Per-user configuration KV |
| `user_deleted` | ~4 | Soft-delete tracking |
| `user_status_changes` | ~4 | Status change audit trail |
| `user_secrets` | ~8 | User-stored secrets |
| `custom_roles` | ~10 | User-defined RBAC roles |
| `groups` | ~10 | User groups |
| `group_members` | ~3 | Group membership |

#### Infrastructure & Operations (entirely missing)

| Table | Go Columns | Description |
|-------|-----------|-------------|
| `licenses` | ~8 | License key storage |
| `replicas` | ~10 | High-availability replica tracking |
| `crypto_keys` | ~8 | Cryptographic key storage |
| `dbcrypt_keys` | ~6 | Database encryption keys |
| `tailnet_*` | varies | Tailnet coordination tables |
| `connection_logs` | ~15 | Connection audit trail |
| `telemetry_items` | ~4 | Telemetry data points |
| `telemetry_locks` | ~3 | Telemetry collection locks |

#### OAuth2 Provider (entirely missing)

| Table | Go Columns | Description |
|-------|-----------|-------------|
| `oauth2_provider_apps` | ~15 | OAuth2 provider app definitions |
| `oauth2_provider_app_secrets` | ~6 | App client secrets |
| `oauth2_provider_app_codes` | ~10 | Authorization codes |
| `oauth2_provider_app_tokens` | ~10 | Access/refresh tokens |

#### Analytics & Billing (entirely missing)

| Table | Go Columns | Description |
|-------|-----------|-------------|
| `usage_events` | ~8 | Usage event tracking |
| `usage_events_daily` | ~6 | Daily aggregated usage |
| `boundary_usage_stats` | ~10 | Boundary usage statistics |

#### Other (entirely missing)

| Table | Go Columns | Description |
|-------|-----------|-------------|
| `parameter_schemas` | ~12 | Legacy parameter schemas |
| `parameter_values` | ~6 | Legacy parameter values |
| `prebuilds` | varies | Prebuild scheduling/tracking |
| `jfrog_xray_scans` | ~6 | JFrog security scan results |
| `aibridge_*` (4 tables) | varies | AI bridge interceptions, token/tool usage, prompts |

### 3.4 Missing Enum Types (46 of 48)

The Rust rewrite defines only `login_type` and `user_status`. All other Go enum types are missing:

| Category | Missing Enums |
|----------|--------------|
| Agent lifecycle | `workspace_agent_lifecycle_state`, `workspace_agent_monitor_state`, `workspace_agent_script_timing_stage`, `workspace_agent_script_timing_status`, `workspace_agent_subsystem` |
| Workspace | `workspace_transition`, `workspace_app_health`, `workspace_app_open_in`, `workspace_app_status_state`, `automatic_updates`, `app_sharing_level` |
| Provisioner | `provisioner_type`, `provisioner_storage_method`, `provisioner_job_type`, `provisioner_job_status`, `provisioner_job_timing_stage`, `provisioner_daemon_status` |
| Build | `build_reason` |
| Auth | `api_key_scope`, `agent_key_scope_enum` |
| Audit | `audit_action` (Go has 13 variants vs Rust's 5), `resource_type` (Go has 27 variants vs Rust's 8 `ResourceKind`) |
| Notifications | `notification_message_status`, `notification_method`, `notification_template_kind`, `inbox_notification_read_status` |
| Parameters | `parameter_destination_scheme`, `parameter_form_type`, `parameter_scope`, `parameter_source_scheme`, `parameter_type_system` |
| Chat/AI | `chat_message_visibility`, `chat_status`, `task_status` |
| Display | `display_app`, `log_level`, `log_source`, `startup_script_behavior` |
| Network | `connection_status`, `connection_type`, `cors_behavior`, `tailnet_status`, `port_share_protocol` |
| RBAC | `group_source`, `prebuild_status` |
| Crypto | `crypto_key_feature` |

### 3.5 Query Coverage by Domain

| Query File | Go Queries | Rust Coverage | Notes |
|-----------|-----------|---------------|-------|
| `users.sql` | 27 | ~15 methods | Partial: missing autofill params, quiet hours, login type updates |
| `apikeys.sql` | 12 | ~8 methods | Good coverage for basic CRUD |
| `auditlogs.sql` | 5 | ~3 methods | Missing count-by-resource-type |
| `organizations.sql` | 10 | ~6 methods | Missing org CRUD (create/update/delete) |
| `organizationmembers.sql` | 6 | ~5 methods | Good coverage |
| `externalauth.sql` | 6 | ~4 methods | Partial |
| `gitsshkeys.sql` | 4 | ~2 methods | Partial |
| `siteconfig.sql` | 33 | ~2 methods | Large gap — deployment config, feature flags, DERP map |
| `templates.sql` | 12 | 0 | Entirely missing |
| `templateversions.sql` | 15 | 0 | Entirely missing |
| `workspaces.sql` | 33 | 0 | Entirely missing |
| `workspacebuilds.sql` | 17 | 0 | Entirely missing |
| `workspaceagents.sql` | 29 | 0 | Entirely missing |
| `provisionerjobs.sql` | 16 | 0 | Entirely missing |
| `notifications.sql` | 19 | 0 | Entirely missing |
| `chats.sql` | 30 | 0 | Entirely missing |
| `insights.sql` | 11 | 0 | Entirely missing |
| `tasks.sql` | 12 | 0 | Entirely missing |
| `tailnet.sql` | 16 | 0 | Entirely missing |
| All other files | ~237 | 0 | Entirely missing |

---

## 4. SDK Model / API Type Gaps

### 4.1 Overview

| Metric | Go (`codersdk/`) | Rust (`coder-core/`) | Coverage |
|--------|-----------------|---------------------|----------|
| Struct count | ~416 | ~111 (82 api + 29 identity) | ~27% |
| Source files | 50+ `.go` | 3 `.rs` (api, identity, ports) | — |

### 4.2 Present Rust API Types (by domain)

**Deployment & Config** (~15 structs): `BuildInfoResponse`, `UpdateCheckResponse`, `SshConfigResponse`, `DeploymentConfigResponse`, `HealthSettings`, `ServerConfig`, `DatabaseConfig`, `BuildMetadata`, etc.

**Auth & Sessions** (~20 structs): `LoginWithPasswordRequest/Response`, `CreateFirstUserRequest/Response`, `AuthMethods`, `OidcAuthMethod`, `GithubAuthMethod`, `CreateTokenRequest`, `GenerateApiKeyResponse`, `ApiKeyResponse`, `TokenConfig`, `ValidateUserPasswordRequest/Response`, etc.

**Users & Identity** (~25 structs): `UserRecord`, `AuthenticatedUser`, `PasswordUserRecord`, `OrganizationRecord`, `OrganizationMemberRecord`, `ApiKeyRecord`, `UserResponse`, `CreateUserRequest`, `UpdateUserProfileRequest`, etc.

**Audit** (~5 structs): `AuditLog`, `AuditLogResponse`, `AuditLogListFilter`, `PersistAuditLogInput`.

**Health** (~10 structs): `HealthcheckReport`, `DatabaseHealthReport`, `AccessUrlHealthReport`, `WebsocketHealthReport`, `DerpHealthReport`, `WorkspaceProxyHealthReport`, `ProvisionerDaemonsHealthReport`.

**External Auth** (~8 structs): `ExternalAuthLink`, `ExternalAuthLinkProvider`, `ExternalAuthDevice`, `ExternalAuthResponse`, etc.

**Operational** (~10 structs): `DeploymentStatsResponse`, `WorkspaceDeploymentStatsResponse`, `SessionCountDeploymentStatsResponse`, `GitSshKeyRecord`, etc.

### 4.3 Missing API Types by Domain

#### Templates (~18 Go structs in `codersdk/templates.go`)

All missing: `Template`, `UpdateTemplateMeta`, `CreateTemplateRequest`, `TemplateExample`, `TemplateACL`, `TemplateDAUsResponse`, `TemplateInsightsResponse`, `TemplateFilter`, etc.

#### Template Versions (~7 Go structs in `codersdk/templateversions.go`)

All missing: `TemplateVersion`, `CreateTemplateVersionRequest`, `TemplateVersionDryRunRequest`, `TemplateVersionImportJobOutput`, etc.

#### Workspaces (~23 Go structs in `codersdk/workspaces.go`)

All missing: `Workspace`, `CreateWorkspaceRequest`, `WorkspaceFilter`, `UpdateWorkspaceRequest`, `UpdateWorkspaceAutostartRequest`, `UpdateWorkspaceTTLRequest`, `WorkspaceDormancy`, `WorkspaceTimings`, `ResolveAutostartResponse`, `WorkspaceQuota`, etc.

#### Workspace Builds (~10 Go structs in `codersdk/workspacebuilds.go`)

All missing: `WorkspaceBuild`, `CreateWorkspaceBuildRequest`, `WorkspaceBuildTimings`, `WorkspaceBuildParameter`, `WorkspaceResource`, `WorkspaceResourceMetadata`, etc.

#### Workspace Agents (~21 Go structs in `codersdk/workspaceagents.go`)

All missing: `WorkspaceAgent`, `WorkspaceAgentMetadata`, `WorkspaceAgentLog`, `WorkspaceAgentListeningPort`, `WorkspaceAgentConnectionInfo`, `DERPRegion`, `DERPNode`, `WorkspaceAgentContainer`, `DevcontainerAgent`, etc.

#### Parameters (~10 Go structs in `codersdk/parameters.go`)

All missing: `TemplateVersionParameter`, `ParameterResolver`, `RichParameter`, `RichParameterOption`, etc.

#### Provisioner Daemons (~12 Go structs in `codersdk/provisionerdaemons.go`)

All missing: `ProvisionerDaemon`, `ProvisionerJob`, `ProvisionerJobLog`, `ProvisionerKey`, `ServeProvisionerDaemonRequest`, etc.

#### Notifications (~12 Go structs in `codersdk/notifications.go`)

All missing: `NotificationTemplate`, `NotificationPreference`, `NotificationMethodsConfig`, `UpdateNotificationTemplateMethodRequest`, etc.

#### Insights (~19 Go structs in `codersdk/insights.go`)

All missing: `DAUsResponse`, `DAUEntry`, `TemplateInsightsResponse`, `UserActivityInsightsResponse`, `UserLatencyInsightsResponse`, `UserStatusCountsResponse`, etc.

#### Chats (~48 Go structs in `codersdk/chats.go`)

All missing: `Chat`, `ChatMessage`, `ChatModelConfig`, `ChatProvider`, `CreateChatRequest`, `CreateChatMessageRequest`, etc. This is the largest single SDK file by struct count.

#### AI Tasks (~11 Go structs in `codersdk/aitasks.go`)

All missing: `Task`, `CreateTaskRequest`, `TaskStatus`, `TaskInput`, `TaskLogSnapshot`, etc.

#### OAuth2 Provider (~17 Go structs in `codersdk/oauth2.go`)

All missing: `OAuth2ProviderApp`, `OAuth2ProviderAppSecret`, `PostOAuth2ProviderAppRequest`, `OAuth2ClientConfiguration`, etc.

#### Organizations (additional ~15 Go structs)

Partially covered. Missing: `CreateOrganizationRequest`, `UpdateOrganizationRequest`, `OrganizationSyncSettings`, `CustomOrganizationRole`, provisioner daemon/job listing for orgs.

#### Deployment (additional ~61 Go structs in `codersdk/deployment.go`)

Partially covered. Large gap in deployment configuration options: `DeploymentValues`, `SerpentOption`, `AppearanceConfig`, `Entitlements`, `Feature`, `Experiment`, and many nested config structs.

### 4.4 Incomplete Types (field differences)

Several Rust types exist but are simplified compared to Go:

| Rust Type | Rust Fields | Go Equivalent Fields | Missing Fields |
|-----------|------------|---------------------|----------------|
| `AuditAction` (enum) | 5 variants | 13 variants | `start`, `stop`, `register`, `request_password_reset`, `connect`, `disconnect`, `open`, `close` |
| `ResourceKind` (enum) | 8 variants | 44 RBAC resource objects | 36 resource types |
| `UserRecord` | ~12 fields | ~20 fields | `theme_preference`, `quiet_hours_schedule`, `is_owner` derived fields |

---

## 5. Middleware & Infrastructure Gaps

### 5.1 Go Middleware Inventory

The Go backend has **34 middleware source files** (excluding tests) in `coderd/httpmw/` with **~95 exported functions**. Key middleware categories:

| Category | Go Files | Rust Equivalent | Status |
|----------|----------|----------------|--------|
| **API Key Auth** | `apikey.go` (14 funcs) | `coder-auth::AuthService::authenticate` | **Partial** — Rust uses session tokens via header/cookie; Go also validates API keys with scope checks, rate limiting per-key |
| **RBAC Authorization** | `authz.go` (2 funcs) | `coder-rbac::Actor` methods | **Partial** — Rust has basic role checks (owner, self-access, org member); Go has full policy engine with Rego/OPA |
| **Request ID** | `requestid.go` (4 funcs) | None | **Missing** |
| **Rate Limiting** | `ratelimit.go` (3 funcs) | None | **Missing** |
| **CORS** | `cors.go` (2 funcs) | `tower_http::CorsLayer` in app.rs | **Present** (basic) |
| **CSP** | `csp.go` (1 func) | None | **Missing** |
| **CSRF** | `csrf.go` (1 func) | None | **Missing** |
| **HSTS** | `hsts.go` (2 funcs) | None | **Missing** |
| **Real IP** | `realip.go` (6 funcs) | None | **Missing** |
| **Prometheus** | `prometheus.go` (1 func) | None | **Missing** |
| **pprof** | `pprof.go` (2 funcs) | None | **Missing** |
| **Resource Param Extraction** | 12 files (template, workspace, agent, build, org, user params) | Inline in handlers | **Partial** — Rust extracts params inline; Go uses middleware chain |
| **OAuth2** | `oauth2.go` (7 funcs) | `coder-auth::ExternalAuthService` | **Partial** — service-level not middleware |
| **Experiments** | `experiments.go` (2 funcs) | None | **Missing** |
| **CLI Telemetry** | `clitelemetry.go` (1 func) | None | **Missing** |
| **Actor Context** | `actor.go` (3 funcs) | Inline in handlers | **Partial** |

### 5.2 RBAC Gap

| Aspect | Go (`coderd/rbac/`) | Rust (`coder-rbac/`) | Gap |
|--------|-------------------|---------------------|-----|
| Policy engine | Full Rego/OPA evaluator | Simple role-string checks | **Major** — Go evaluates complex policies; Rust only checks "is owner" or "is self" |
| Resource objects | 44 typed resource objects | 8 `ResourceKind` variants | **Major** — 36 resource types missing |
| Roles | Built-in + custom roles with per-resource permissions | 8 built-in role constants, no permission matrix | **Major** — no per-resource permission evaluation |
| Scopes | API key scopes with resource restrictions | Basic scope strings | **Major** — no scope-based authorization |
| Organization roles | Per-org role evaluation | Org role constants only (no evaluation) | **Major** |

The RBAC system is the single largest infrastructure gap. Go's implementation uses a policy engine that evaluates `(subject, action, object)` tuples against role permissions. The Rust implementation only checks coarse-grained conditions like "is this user an owner?" or "is this the same user?".

### 5.3 Audit Gap

| Aspect | Go (`coderd/audit/`) | Rust (`coder-audit/`) | Gap |
|--------|---------------------|----------------------|-----|
| Actions | 13 enum variants | 5 enum variants | Missing: `start`, `stop`, `register`, `request_password_reset`, `connect`, `disconnect`, `open`, `close` |
| Resource types | 27 `resource_type` enum values | 8 `ResourceKind` variants | 19 resource types missing |
| Diff generation | `audit/diff.go` — automatic struct diff computation | Manual diff in handlers | **Missing** — Go auto-generates JSON diffs between old/new state |
| Request integration | `audit/request.go` — middleware-integrated request logging with IP, user agent, request ID | `AuditEvent` struct with basic fields | **Partial** — no automatic request metadata capture |
| Additional fields | Per-resource custom audit fields | None | **Missing** |

### 5.4 Rate Limiting

Go implements per-user and per-IP rate limiting via `httpmw/ratelimit.go` with configurable limits. Rust has **no rate limiting** implementation.

### 5.5 HTTP API Utilities

Go's `coderd/httpapi/` package provides shared utilities for query parsing, pagination, search, WebSocket upgrades, and SSE streaming. Rust handles these inline in handlers where needed, but is missing:

- Standardized pagination helpers
- Search/filter query parsing
- WebSocket upgrade utilities
- SSE (Server-Sent Events) streaming framework
- Standardized error response formatting (partially present via `AppError`)

---

## 6. Background Systems

| System | Go Package | Go Size | Rust Status | Complexity | Notes |
|--------|-----------|---------|-------------|-----------|-------|
| **Provisioner Daemon Orchestration** | `provisionerd/` | 3 files, 2,151 lines | **Stub** — init script rendering only | **Critical** | Manages provisioner job lifecycle, worker assignment, heartbeats |
| **Tailnet/DERP Coordination** | `tailnet/` | 26 files, 12,607 lines | **Missing** | **Critical** | WireGuard tunneling, DERP relay servers, peer coordination |
| **Agent API Server** | `coderd/agentapi/` | 29 files, 8,994 lines | **Missing** | **Critical** | gRPC/dRPC agent ↔ server communication, metadata, logs, lifecycle |
| **Notification Dispatch** | `coderd/notifications/` | 12 files, 4,671 lines | **Stub** (STATUS = "planned") | **High** | Multi-channel dispatch (email, webhook, inbox), template rendering |
| **Telemetry Collection** | `coderd/telemetry/` | 2 files, 3,814 lines | **Missing** | **Medium** | Anonymous usage telemetry, deployment tracking |
| **Autobuild Scheduler** | `coderd/autobuild/` | 4 files, 3,070 lines | **Missing** | **High** | Workspace auto-start/stop based on schedules and TTLs |
| **Workspace Schedule** | `coderd/schedule/` | 7 files, 1,538 lines | **Missing** | **High** | Cron-based scheduling, quiet hours, timezone handling |
| **Update Checker** | `coderd/updatecheck/` | 2 files, 396 lines | **Missing** | **Low** | Periodic version check against releases API |
| **Pub/Sub Event System** | `coderd/wspubsub/`, `coderd/pubsub/` | 4 files, 204 lines | **Missing** | **High** | PostgreSQL LISTEN/NOTIFY for real-time workspace events |
| **Deployment Stats Cache** | (inline in Go) | — | **Present** (`coder-workspaces`) | — | Background refresh loop, cached stats |
| **Health Check Service** | (inline in Go) | — | **Present** (`coder-connectivity`) | — | Multi-subsystem health probes, caching |
| **Git SSH Key Generation** | (inline in Go) | — | **Present** (`coder-connectivity`) | — | Ed25519 keypair generation |

### Critical Path Dependencies

The following background systems are **prerequisites** for workspace lifecycle routes:

1. **Provisioner Daemon Orchestration** → Required for `POST /templates`, `POST /template-versions`, `POST /workspaces`, `POST /workspace-builds`
2. **Pub/Sub Event System** → Required for `GET /workspaces/{id}/watch`, `GET /workspaceagents/{id}/logs`, all SSE/WebSocket streaming endpoints
3. **Agent API Server** → Required for `GET /workspaceagents/me/rpc`, agent lifecycle, log collection, metadata reporting
4. **Tailnet/DERP** → Required for `GET /workspaceagents/{id}/coordinate`, PTY terminals, workspace connectivity

---

## 7. Porting Roadmap

### 7.1 Dependency Graph

```
Phase 0 (Foundation - DONE)
  └── Auth, Identity, Organizations, Audit, Health, Stats

Phase 1 (Infrastructure Prerequisites)
  ├── Full RBAC Policy Engine
  ├── Pub/Sub Event System (PostgreSQL LISTEN/NOTIFY)
  ├── File Upload/Storage
  └── Rate Limiting + Request ID Middleware

Phase 2 (Template Domain)
  ├── Template DB Schema (templates, template_versions, parameters, variables)
  ├── Template API Types (~25 structs)
  ├── Provisioner Job Schema + Basic Job Lifecycle
  └── Template CRUD Routes (33 routes)

Phase 3 (Workspace Domain)
  ├── Workspace DB Schema (workspaces, workspace_builds, resources, agents)
  ├── Workspace API Types (~35 structs)
  ├── Autobuild Scheduler
  ├── Workspace CRUD + Build Routes (32 routes)
  └── Workspace Watch (SSE via pub/sub)

Phase 4 (Agent Domain)
  ├── Agent API Server (dRPC/WebSocket)
  ├── Tailnet/DERP Coordination
  ├── Agent DB Schema (agent stats, logs, metadata, containers)
  ├── Agent API Types (~21 structs)
  └── Agent Routes (20 routes)

Phase 5 (Notifications & AI)
  ├── Notification Dispatch System
  ├── Notification DB Schema + Routes (13 routes)
  ├── AI Tasks Schema + Routes (10 routes)
  └── Chat Schema + Routes (5 routes)

Phase 6 (Analytics & Polish)
  ├── Insights/Analytics Queries + Routes (5 routes)
  ├── Debug/Observability Routes (11 routes)
  ├── Remaining misc routes (15 routes)
  ├── Telemetry Collection
  └── Update Checker
```

### 7.2 Recommended Porting Sequence

| Phase | Domain | Routes | Estimated Effort | Key Blockers |
|-------|--------|--------|-----------------|-------------|
| **1** | Infrastructure | 0 new routes | **4–6 weeks** | RBAC policy engine is architecturally complex; pub/sub requires PostgreSQL LISTEN/NOTIFY integration |
| **2** | Templates & Versions | 33 routes | **6–8 weeks** | Provisioner job orchestration (even basic lifecycle); file upload for template bundles |
| **3** | Workspaces & Builds | 32 routes | **6–8 weeks** | Depends on Phase 2 (templates); autobuild scheduler; workspace state machine |
| **4** | Workspace Agents | 20 routes | **8–12 weeks** | Tailnet/DERP (12,607 lines); Agent API server (8,994 lines); WebSocket/streaming infrastructure |
| **5** | Notifications & AI | 28 routes | **4–6 weeks** | Notification dispatch system; LLM integration for chats |
| **6** | Analytics & Polish | 31 routes | **3–4 weeks** | Complex aggregation queries; debug endpoints |
| | **Total** | **157 routes** | **31–44 weeks** | |

### 7.3 Effort Estimates by Route Complexity

| Complexity | Definition | Count | Effort per Route |
|-----------|-----------|-------|-----------------|
| **Simple** | GET single resource, no complex auth, no streaming | ~45 | 0.5–1 day |
| **Medium** | CRUD with validation, pagination, RBAC checks, DB transactions | ~65 | 1–3 days |
| **Complex** | Streaming (SSE/WebSocket), orchestration (provisioner jobs), state machines, real-time coordination | ~47 | 3–10 days |

### 7.4 Highest-Impact Quick Wins

These routes could be ported with minimal infrastructure investment:

1. **File upload/download** (2 routes) — Simple binary storage, prerequisite for templates
2. **Authorization check** (1 route) — `POST /authcheck` for bulk RBAC evaluation
3. **Deprecated endpoints** (3 routes) — Simple redirects to existing endpoints
4. **Debug pprof/expvar** (3 routes) — Standard Go debug equivalents via Rust tracing/metrics

---

## Appendix A: Full Missing Route Inventory

| # | Method | Path | Go Source | Complexity |
|---|--------|------|-----------|-----------|
| 1 | GET | `/applications/auth-redirect` | `workspaceapps.go` | Medium |
| 2 | GET | `/applications/host` | `workspaceapps.go` | Simple |
| 3 | POST | `/authcheck` | `authorize.go` | Medium |
| 4 | POST | `/chats` | `chats.go` | Complex |
| 5 | GET | `/chats` | `chats.go` | Medium |
| 6 | DELETE | `/chats/{chat}` | `chats.go` | Simple |
| 7 | GET | `/chats/{chat}` | `chats.go` | Simple |
| 8 | POST | `/chats/{chat}/messages` | `chats.go` | Complex |
| 9 | GET | `/debug/coordinator` | `debug.go` | Medium |
| 10 | GET | `/debug/derp/traffic` | `debug.go` | Medium |
| 11 | GET | `/debug/expvar` | `debug.go` | Simple |
| 12 | GET | `/debug/health` | `debug.go` | Medium |
| 13 | GET | `/debug/pprof/*` | `debug.go` | Simple |
| 14 | GET | `/debug/tailnet` | `debug.go` | Medium |
| 15 | GET | `/debug/websocket` | `debug.go` | Simple |
| 16 | GET | `/deployment/config` | `deployment.go` | Simple |
| 17 | PATCH | `/deployment/config` | `deployment.go` | Medium |
| 18 | GET | `/files/{fileID}` | `files.go` | Simple |
| 19 | POST | `/files` | `files.go` | Medium |
| 20 | GET | `/insights/daus` | `insights.go` | Simple |
| 21 | GET | `/insights/templates` | `insights.go` | Complex |
| 22 | GET | `/insights/user-activity` | `insights.go` | Complex |
| 23 | GET | `/insights/user-latency` | `insights.go` | Medium |
| 24 | GET | `/insights/user-status-counts` | `insights.go` | Medium |
| 25 | GET | `/notifications/settings` | `notifications.go` | Simple |
| 26 | PUT | `/notifications/settings` | `notifications.go` | Medium |
| 27 | GET | `/notifications/templates` | `notifications.go` | Simple |
| 28 | POST | `/notifications/test` | `notifications.go` | Medium |
| 29 | PUT | `/notifications/templates/{id}/method` | `notifications.go` | Medium |
| 30 | GET | `/notifications/dispatch-methods` | `notifications.go` | Simple |
| 31 | GET | `/inbox/notifications` | `inboxnotifications.go` | Medium |
| 32 | PUT | `/inbox/notifications/mark-all-read` | `inboxnotifications.go` | Simple |
| 33 | GET | `/inbox/notifications/watch` | `inboxnotifications.go` | Complex |
| 34 | PUT | `/inbox/notifications/{id}/read-status` | `inboxnotifications.go` | Simple |
| 35 | GET | `/organizations/{organization}/members/roles` | `members.go` | Simple |
| 36 | PUT | `/organizations/{organization}/members/{user}/roles` | `members.go` | Medium |
| 37 | GET | `/organizations/{organization}/templates` | `templates.go` | Medium |
| 38 | POST | `/organizations/{organization}/templates` | `templates.go` | Complex |
| 39 | GET | `/organizations/{organization}/templates/{templatename}` | `templates.go` | Simple |
| 40 | GET | `/organizations/{organization}/templates/{templatename}/versions/{templateversionname}` | `templateversions.go` | Simple |
| 41 | POST | `/organizations/{organization}/templateversions` | `templateversions.go` | Complex |
| 42 | DELETE | `/templates/{template}` | `templates.go` | Medium |
| 43 | GET | `/templates/{template}` | `templates.go` | Simple |
| 44 | PATCH | `/templates/{template}` | `templates.go` | Medium |
| 45 | GET | `/templates/{template}/daus` | `templates.go` | Medium |
| 46 | GET | `/templates/{template}/examples` | `templates.go` | Simple |
| 47 | GET | `/templates/{template}/versions` | `templateversions.go` | Medium |
| 48 | GET | `/templates/{template}/versions/{templateversionname}` | `templateversions.go` | Simple |
| 49 | PATCH | `/templateversions/{templateversion}` | `templateversions.go` | Medium |
| 50 | GET | `/templateversions/{templateversion}` | `templateversions.go` | Simple |
| 51 | POST | `/templateversions/{templateversion}/archive` | `templateversions.go` | Medium |
| 52 | PATCH | `/templateversions/{templateversion}/cancel` | `templateversions.go` | Medium |
| 53 | POST | `/templateversions/{templateversion}/dry-run` | `templateversions.go` | Complex |
| 54 | GET | `/templateversions/{templateversion}/dry-run/{jobID}` | `templateversions.go` | Medium |
| 55 | GET | `/templateversions/{templateversion}/dry-run/{jobID}/cancel` | `templateversions.go` | Medium |
| 56 | GET | `/templateversions/{templateversion}/dry-run/{jobID}/logs` | `templateversions.go` | Complex |
| 57 | GET | `/templateversions/{templateversion}/dry-run/{jobID}/resources` | `templateversions.go` | Medium |
| 58 | GET | `/templateversions/{templateversion}/external-auth` | `templateversions.go` | Simple |
| 59 | GET | `/templateversions/{templateversion}/logs` | `templateversions.go` | Complex |
| 60 | GET | `/templateversions/{templateversion}/parameters` | `templateversions.go` | Simple |
| 61 | GET | `/templateversions/{templateversion}/presets` | `presets.go` | Simple |
| 62 | GET | `/templateversions/{templateversion}/presets/{presetID}/parameters` | `presets.go` | Simple |
| 63 | GET | `/templateversions/{templateversion}/resources` | `templateversions.go` | Medium |
| 64 | GET | `/templateversions/{templateversion}/rich-parameters` | `parameters.go` | Simple |
| 65 | GET | `/templateversions/{templateversion}/schema` | `deprecated.go` | Simple |
| 66 | POST | `/templateversions/{templateversion}/unarchive` | `templateversions.go` | Medium |
| 67 | GET | `/templateversions/{templateversion}/variables` | `templateversions.go` | Simple |
| 68 | GET | `/tasks` | `aitasks.go` | Medium |
| 69 | GET | `/tasks/{task}` | `aitasks.go` | Simple |
| 70 | GET | `/tasks/{task}/input` | `aitasks.go` | Simple |
| 71 | PATCH | `/tasks/{task}` | `aitasks.go` | Complex |
| 72 | GET | `/users/{user}/notifications/preferences` | `notifications.go` | Simple |
| 73 | PUT | `/users/{user}/notifications/preferences` | `notifications.go` | Medium |
| 74 | DELETE | `/users/{user}/webpush/subscription` | `webpush.go` | Simple |
| 75 | POST | `/users/{user}/webpush/subscription` | `webpush.go` | Simple |
| 76 | POST | `/users/{user}/webpush/test` | `webpush.go` | Medium |
| 77 | GET | `/users/{user}/workspace/{workspacename}` | `workspaces.go` | Medium |
| 78 | GET | `/users/{user}/workspace/{workspacename}/builds/{buildnumber}` | `workspacebuilds.go` | Medium |
| 79 | POST | `/users/{user}/workspaces` | `workspaces.go` | Complex |
| 80 | POST | `/workspaceagents/aws-instance-identity` | `workspaceresourceauth.go` | Complex |
| 81 | POST | `/workspaceagents/azure-instance-identity` | `workspaceresourceauth.go` | Complex |
| 82 | GET | `/workspaceagents/connection` | `workspaceagents.go` | Simple |
| 83 | POST | `/workspaceagents/google-instance-identity` | `workspaceresourceauth.go` | Complex |
| 84 | PATCH | `/workspaceagents/me/app-status` | `workspaceagents.go` | Simple |
| 85 | GET | `/workspaceagents/me/external-auth` | `workspaceagents.go` | Medium |
| 86 | GET | `/workspaceagents/me/gitauth` | `deprecated.go` | Simple |
| 87 | GET | `/workspaceagents/me/gitsshkey` | `gitsshkey.go` | Simple |
| 88 | POST | `/workspaceagents/me/log-source` | `workspaceagents.go` | Simple |
| 89 | PATCH | `/workspaceagents/me/logs` | `workspaceagents.go` | Medium |
| 90 | GET | `/workspaceagents/me/reinit` | `workspaceagents.go` | Complex |
| 91 | GET | `/workspaceagents/me/rpc` | `workspaceagentsrpc.go` | Complex |
| 92 | POST | `/workspaceagents/me/tasks/{task}/log-snapshot` | `aitasks.go` | Medium |
| 93 | GET | `/workspaceagents/{workspaceagent}` | `workspaceagents.go` | Simple |
| 94 | GET | `/workspaceagents/{workspaceagent}/connection` | `workspaceagents.go` | Simple |
| 95 | GET | `/workspaceagents/{workspaceagent}/containers` | `workspaceagents.go` | Medium |
| 96 | DELETE | `/workspaceagents/{workspaceagent}/containers/devcontainers/{devcontainer}` | `workspaceagents.go` | Medium |
| 97 | POST | `/workspaceagents/{workspaceagent}/containers/devcontainers/{devcontainer}/recreate` | `workspaceagents.go` | Medium |
| 98 | GET | `/workspaceagents/{workspaceagent}/containers/watch` | `workspaceagents.go` | Complex |
| 99 | GET | `/workspaceagents/{workspaceagent}/coordinate` | `workspaceagents.go` | Complex |
| 100 | GET | `/workspaceagents/{workspaceagent}/listening-ports` | `workspaceagents.go` | Simple |
| 101 | GET | `/workspaceagents/{workspaceagent}/logs` | `workspaceagents.go` | Complex |
| 102 | GET | `/workspaceagents/{workspaceagent}/pty` | `workspaceapps/proxy.go` | Complex |
| 103 | GET | `/workspaceagents/{workspaceagent}/startup-logs` | `deprecated.go` | Simple |
| 104 | GET | `/workspaceagents/{workspaceagent}/watch-metadata` | `workspaceagents.go` | Complex |
| 105 | GET | `/workspaceagents/{workspaceagent}/watch-metadata-ws` | `workspaceagents.go` | Complex |
| 106 | GET | `/workspacebuilds/{workspacebuild}` | `workspacebuilds.go` | Simple |
| 107 | PATCH | `/workspacebuilds/{workspacebuild}/cancel` | `workspacebuilds.go` | Medium |
| 108 | GET | `/workspacebuilds/{workspacebuild}/logs` | `workspacebuilds.go` | Complex |
| 109 | GET | `/workspacebuilds/{workspacebuild}/parameters` | `workspacebuilds.go` | Simple |
| 110 | GET | `/workspacebuilds/{workspacebuild}/resources` | `deprecated.go` | Simple |
| 111 | GET | `/workspacebuilds/{workspacebuild}/state` | `workspacebuilds.go` | Simple |
| 112 | PUT | `/workspacebuilds/{workspacebuild}/state` | `workspacebuilds.go` | Medium |
| 113 | GET | `/workspacebuilds/{workspacebuild}/timings` | `workspacebuilds.go` | Simple |
| 114 | GET | `/workspaces` | `workspaces.go` | Medium |
| 115 | GET | `/workspaces/{workspace}` | `workspaces.go` | Simple |
| 116 | PATCH | `/workspaces/{workspace}` | `workspaces.go` | Medium |
| 117 | DELETE | `/workspaces/{workspace}/acl` | `workspaces.go` | Medium |
| 118 | GET | `/workspaces/{workspace}/acl` | `workspaces.go` | Simple |
| 119 | PATCH | `/workspaces/{workspace}/acl` | `workspaces.go` | Medium |
| 120 | PUT | `/workspaces/{workspace}/autostart` | `workspaces.go` | Simple |
| 121 | PUT | `/workspaces/{workspace}/autoupdates` | `workspaces.go` | Simple |
| 122 | GET | `/workspaces/{workspace}/builds` | `workspacebuilds.go` | Medium |
| 123 | POST | `/workspaces/{workspace}/builds` | `workspacebuilds.go` | Complex |
| 124 | PUT | `/workspaces/{workspace}/dormant` | `workspaces.go` | Medium |
| 125 | PUT | `/workspaces/{workspace}/extend` | `workspaces.go` | Medium |
| 126 | DELETE | `/workspaces/{workspace}/favorite` | `workspaces.go` | Simple |
| 127 | PUT | `/workspaces/{workspace}/favorite` | `workspaces.go` | Simple |
| 128 | DELETE | `/workspaces/{workspace}/port-share` | `workspaceagentportshare.go` | Simple |
| 129 | GET | `/workspaces/{workspace}/port-share` | `workspaceagentportshare.go` | Simple |
| 130 | POST | `/workspaces/{workspace}/port-share` | `workspaceagentportshare.go` | Medium |
| 131 | GET | `/workspaces/{workspace}/resolve-autostart` | `workspaces.go` | Medium |
| 132 | GET | `/workspaces/{workspace}/timings` | `workspaces.go` | Simple |
| 133 | PUT | `/workspaces/{workspace}/ttl` | `workspaces.go` | Simple |
| 134 | POST | `/workspaces/{workspace}/usage` | `workspaces.go` | Medium |
| 135 | GET | `/workspaces/{workspace}/watch` | `workspaces.go` | Complex |
| 136 | GET | `/workspaces/{workspace}/watch-ws` | `workspaces.go` | Complex |
| 137 | GET | `/organizations/{organization}/provisionerdaemons` | `provisionerdaemons.go` | Medium |
| 138 | GET | `/organizations/{organization}/provisionerjobs` | `provisionerjobs.go` | Medium |
| 139 | GET | `/organizations/{organization}/provisionerjobs/{provisionerjob}` | `provisionerjobs.go` | Simple |
| 140 | PATCH | `/organizations/{organization}/provisionerjobs/{provisionerjob}/cancel` | `provisionerjobs.go` | Medium |
| 141 | GET | `/organizations/{organization}/provisionerjobs/{provisionerjob}/logs` | `provisionerjobs.go` | Complex |
| 142–157 | Various | (remaining org, debug, task routes) | various | Various |

> **Note**: Routes 142–157 cover remaining organization member role routes, additional debug endpoints, and task-related agent endpoints not fully enumerated above. See `docs/parity-matrix.md` for the complete authoritative list.

---

## Appendix B: Full Missing Table Inventory

| # | Table Name | Go Columns (approx) | Description | Domain |
|---|-----------|---------------------|-------------|--------|
| 1 | `templates` | 30 | Template definitions with policies, TTLs, provisioner config | Templates |
| 2 | `template_versions` | 20 | Version lifecycle, job references, readme, archive state | Templates |
| 3 | `template_version_parameters` | 15 | Rich parameter definitions per version | Templates |
| 4 | `template_version_variables` | 8 | Template variable values | Templates |
| 5 | `template_version_presets` | 10 | Parameter preset bundles | Templates |
| 6 | `template_version_preset_parameters` | 4 | Preset → parameter value mapping | Templates |
| 7 | `template_version_preset_prebuild_schedules` | 4 | Prebuild timing config | Templates |
| 8 | `template_version_terraform_values` | 4 | Cached Terraform plan values | Templates |
| 9 | `template_version_workspace_tags` | 3 | Workspace provisioner tag definitions | Templates |
| 10 | `template_usage_stats` | 12 | Template usage analytics | Templates |
| 11 | `workspace_resources` | 12 | Provisioned compute/storage resources | Workspaces |
| 12 | `workspace_resource_metadata` | 5 | Resource key-value metadata | Workspaces |
| 13 | `workspace_agents` | 30 | Agent state, lifecycle, connection info | Agents |
| 14 | `workspace_apps` | 20 | In-workspace application definitions | Agents |
| 15 | `workspace_agent_scripts` | 15 | Startup/shutdown scripts | Agents |
| 16 | `workspace_agent_log_sources` | 5 | Log source registration | Agents |
| 17 | `workspace_agent_devcontainers` | 10 | Dev container state tracking | Agents |
| 18 | `workspace_agent_port_share` | 5 | Port sharing configuration | Agents |
| 19 | `workspace_agent_memory_resource_monitors` | 10 | Memory monitoring thresholds | Agents |
| 20 | `workspace_agent_volume_resource_monitors` | 10 | Volume monitoring thresholds | Agents |
| 21 | `workspace_agent_script_timings` | 6 | Script execution timing | Agents |
| 22 | `workspace_app_stats` | 10 | Application usage statistics | Agents |
| 23 | `workspace_app_statuses` | 8 | Application health history | Agents |
| 24 | `workspace_build_parameters` | 4 | Build-time parameter values | Workspaces |
| 25 | `workspace_modules` | 6 | Terraform module metadata | Workspaces |
| 26 | `provisioner_job_logs` | 6 | Job output log entries | Provisioner |
| 27 | `provisioner_job_timings` | 6 | Job stage timing | Provisioner |
| 28 | `provisioner_keys` | 8 | Provisioner daemon auth keys | Provisioner |
| 29 | `files` | 6 | Uploaded file storage (Terraform bundles) | Files |
| 30 | `notification_messages` | 15 | Queued notification messages | Notifications |
| 31 | `notification_preferences` | 4 | Per-user notification preferences | Notifications |
| 32 | `notification_report_generator_logs` | 3 | Report generation tracking | Notifications |
| 33 | `notification_templates` | 12 | Notification template definitions | Notifications |
| 34 | `inbox_notifications` | 10 | In-app inbox items | Notifications |
| 35 | `webpush_subscriptions` | 6 | Web push subscription endpoints | Notifications |
| 36 | `chats` | 8 | Chat sessions | Chat/AI |
| 37 | `chat_messages` | 10 | Chat message content | Chat/AI |
| 38 | `chat_files` | 5 | Chat file attachments | Chat/AI |
| 39 | `chat_model_configs` | 10 | LLM model configurations | Chat/AI |
| 40 | `chat_providers` | 8 | AI provider configurations | Chat/AI |
| 41 | `chat_queued_messages` | 8 | Queued chat messages | Chat/AI |
| 42 | `chat_diff_statuses` | 8 | Chat diff tracking | Chat/AI |
| 43 | `tasks` | 15 | AI task records | Chat/AI |
| 44 | `task_snapshots` | 8 | Task log snapshots | Chat/AI |
| 45 | `task_workspace_apps` | 4 | Task-to-app mappings | Chat/AI |
| 46 | `user_links` | 10 | OAuth/OIDC identity links | Identity |
| 47 | `user_configs` | 3 | Per-user configuration key-value | Identity |
| 48 | `user_deleted` | 4 | Soft-delete tracking | Identity |
| 49 | `user_status_changes` | 4 | Status change audit trail | Identity |
| 50 | `user_secrets` | 8 | User-stored secrets | Identity |
| 51 | `custom_roles` | 10 | User-defined RBAC roles | RBAC |
| 52 | `groups` | 10 | User groups | RBAC |
| 53 | `group_members` | 3 | Group membership | RBAC |
| 54 | `licenses` | 8 | License key storage | Infrastructure |
| 55 | `replicas` | 10 | HA replica tracking | Infrastructure |
| 56 | `crypto_keys` | 8 | Cryptographic key storage | Infrastructure |
| 57 | `dbcrypt_keys` | 6 | Database encryption keys | Infrastructure |
| 58 | `connection_logs` | 15 | Connection audit trail | Infrastructure |
| 59 | `telemetry_items` | 4 | Telemetry data points | Infrastructure |
| 60 | `telemetry_locks` | 3 | Telemetry collection locks | Infrastructure |
| 61 | `oauth2_provider_apps` | 15 | OAuth2 provider app definitions | OAuth2 |
| 62 | `oauth2_provider_app_secrets` | 6 | App client secrets | OAuth2 |
| 63 | `oauth2_provider_app_codes` | 10 | Authorization codes | OAuth2 |
| 64 | `oauth2_provider_app_tokens` | 10 | Access/refresh tokens | OAuth2 |
| 65 | `usage_events` | 8 | Usage event tracking | Analytics |
| 66 | `usage_events_daily` | 6 | Daily aggregated usage | Analytics |
| 67 | `boundary_usage_stats` | 10 | Boundary usage statistics | Analytics |
| 68 | `parameter_schemas` | 12 | Legacy parameter schemas | Legacy |
| 69 | `parameter_values` | 6 | Legacy parameter values | Legacy |
| 70 | `aibridge_interceptions` | varies | AI bridge interceptions | AI Bridge |
| 71 | `aibridge_token_usages` | varies | AI bridge token usage | AI Bridge |
| 72 | `aibridge_tool_usages` | varies | AI bridge tool usage | AI Bridge |
| 73 | `aibridge_user_prompts` | varies | AI bridge user prompts | AI Bridge |

> **Note**: Column counts are approximate based on the Go `dump.sql` CREATE TABLE statements. Some tables marked "varies" have structures that depend on the specific Go version. The 15 Rust tables that exist as stubs (workspaces, workspace_builds, provisioner_jobs, workspace_agent_stats) need significant column additions to match Go parity — they are not counted here but are noted in Section 3.2.
