# Backend Gap Analysis & Remediation Plan — 2026-04-18

> **Purpose.** Comprehensive, ground-truth inventory of every area where the
> Rust coderd rewrite still differs from the Go reference in `coder/`, with a
> prioritised remediation plan. Supersedes the earlier
> [`docs/remaining-behavioral-gaps.md`](remaining-behavioral-gaps.md), which
> predates the agent DRPC work (PR #215), the `coder-telemetry` /
> `coder-license` / `coder-agent-rpc` crates, the `lettre`-based SMTP
> dispatcher, and the batched audit sink. Route-level parity is still
> **326 / 326 (100 %)** across OSS + Enterprise; everything in this document
> is about *behavioral* depth.

## Method

1. `make parity-refresh` — no changes; the three generated parity matrices in
   `docs/` and the depth matrix in `crates/coder-server/PARITY_MATRIX.md` are
   current.
2. Go reference enumerated by walking `coder/coderd/coderd.go` `New()` for
   every goroutine/ticker/worker, `coder/agent/proto/agent.proto` for the
   agent DRPC surface, `coder/provisionerd/proto/provisionerd.proto` for the
   provisionerd DRPC surface, and `coder/coderd/workspaceapps/`,
   `coder/coderd/workspaceagents.go`, `coder/tailnet/`,
   `coder/coderd/notifications/`, `coder/coderd/audit/` and related packages.
3. Rust side inventoried by reading:
   - `apps/coderd/src/main.rs` bootstrap (1,613 LOC) — every
     `Worker::start` / `spawn` wired into the server process.
   - `crates/coder-agent-rpc/` (1,107 LOC) — DRPC wire + yamux server.
   - `crates/coder-server/src/handlers/agent_rpc_live.rs` (379 LOC) — the
     four live RPC implementations.
   - `crates/coder-provisioner/src/server.rs` (1,909 LOC) — custom JSON
     daemon protocol.
   - `crates/coder-connectivity/src/{tailnet,derp,agents}.rs` (5,838 LOC).
   - `crates/coder-notifications/src/lib.rs` (with `lettre` SMTP +
     webhook retry + VAPID webpush).
   - `crates/coder-workspaces/src/lib.rs` (4,393 LOC) — autobuild,
     activity-bump, dormancy, lifecycle scheduler.
   - `crates/coder-server/src/{replica_manager,crypto_key_rotator,update_check}.rs`.
4. One exploration subagent (`Agent DRPC + tailnet gaps`) completed and
   contributed the RPC-by-RPC inventory in §1; the remaining foreground
   analysis is this author's.

---

## Table of contents

- [Section A — What actually landed since the last gap doc](#section-a--what-actually-landed-since-the-last-gap-doc)
- [Section B — Remaining gaps, by subsystem](#section-b--remaining-gaps-by-subsystem)
  - [B.1 Agent DRPC surface (13 / 18 RPCs missing)](#b1-agent-drpc-surface-13--18-rpcs-missing)
  - [B.2 Tailnet coordinator & transport](#b2-tailnet-coordinator--transport)
  - [B.3 DERP relay & mesh](#b3-derp-relay--mesh)
  - [B.4 Reconnecting-PTY](#b4-reconnecting-pty)
  - [B.5 Workspace-proxy coordinate bridge](#b5-workspace-proxy-coordinate-bridge)
  - [B.6 Provisioner daemon wire protocol](#b6-provisioner-daemon-wire-protocol)
  - [B.7 Template / build orchestration](#b7-template--build-orchestration)
  - [B.8 Missing periodic background workers](#b8-missing-periodic-background-workers)
  - [B.9 OAuth2 provider](#b9-oauth2-provider)
  - [B.10 Audit log coverage](#b10-audit-log-coverage)
  - [B.11 RBAC / dbauthz layer](#b11-rbac--dbauthz-layer)
  - [B.12 IDP sync, SCIM, external auth](#b12-idp-sync-scim-external-auth)
  - [B.13 Workspace apps behavioural gaps](#b13-workspace-apps-behavioural-gaps)
  - [B.14 Non-HTTP surfaces & deployment ergonomics](#b14-non-http-surfaces--deployment-ergonomics)
- [Section C — Priority matrix & waves](#section-c--priority-matrix--waves)
- [Section D — Documentation follow-ups](#section-d--documentation-follow-ups)

---

## Section A — What actually landed since the last gap doc

The previous gap inventory (`docs/remaining-behavioral-gaps.md`) was written
before several large pieces shipped. The items below were listed as missing
there but are now wired:

| Subsystem | Where it landed | Evidence |
|-----------|-----------------|----------|
| Agent DRPC wire (protobuf + varint framing + stream/message IDs) | `crates/coder-agent-rpc/src/{wire,server,yamux_server}.rs` (1,107 LOC, PR #215 “Phase 2 — live handler + 4 RPC implementations”) | `/coder.agent.v2.Agent/GetManifest\|GetAnnouncementBanners\|UpdateStartup\|BatchUpdateAppHealths` dispatch in [crates/coder-agent-rpc/src/server.rs:176](crates/coder-agent-rpc/src/server.rs:176) |
| Live agent manifest / apps / startup / banners | [crates/coder-server/src/handlers/agent_rpc_live.rs](crates/coder-server/src/handlers/agent_rpc_live.rs) | Reads store, converts rows → protobuf |
| SMTP email dispatcher | `coder-notifications` now uses `lettre` with STARTTLS / implicit TLS, SASL PLAIN/LOGIN, failure classification | [crates/coder-notifications/src/lib.rs:37](crates/coder-notifications/src/lib.rs:37) |
| Webhook retry policy | HTTP code classification + exponential backoff with jitter | [crates/coder-notifications/src/lib.rs:18](crates/coder-notifications/src/lib.rs:18) |
| Webpush VAPID signer + startup validation | [apps/coderd/src/main.rs:971](apps/coderd/src/main.rs:971), `Webpusher::new` |
| Telemetry worker | `crates/coder-telemetry` (776 LOC) — `TelemetryWorker::start` with flush interval | [apps/coderd/src/main.rs:892](apps/coderd/src/main.rs:892) |
| Replica manager | `coder-server::ReplicaManager::start` — heartbeat + unregister on shutdown | [apps/coderd/src/main.rs:955](apps/coderd/src/main.rs:955), `crates/coder-server/src/replica_manager.rs` (614 LOC) |
| Crypto-key rotator | `CryptoKeyRotator::new(...).start(...)` — rotate + retire + hard-delete | [apps/coderd/src/main.rs:934](apps/coderd/src/main.rs:934), `crates/coder-server/src/crypto_key_rotator.rs` (913 LOC) |
| Activity-bump worker | Extends TTL on active workspaces | [crates/coder-workspaces/src/lib.rs:1078](crates/coder-workspaces/src/lib.rs:1078) |
| Dormancy checker | Marks workspaces dormant after inactivity | [crates/coder-workspaces/src/lib.rs:1281](crates/coder-workspaces/src/lib.rs:1281) |
| Autobuild executor | Autostart / autostop / failed-stop retry | [crates/coder-workspaces/src/lib.rs:521](crates/coder-workspaces/src/lib.rs:521) |
| Lifecycle scheduler with quiet hours parsing | `parse_quiet_hours_schedule` + `LifecycleScheduler::start` | [crates/coder-workspaces/src/lib.rs:1570](crates/coder-workspaces/src/lib.rs:1570), [apps/coderd/src/main.rs:940](apps/coderd/src/main.rs:940) |
| GitHub release update checker | Opt-in via `config.update_check`, background poll + handle | [apps/coderd/src/main.rs:1019](apps/coderd/src/main.rs:1019), `crates/coder-server/src/update_check.rs` (497 LOC) |
| PostgreSQL `LISTEN/NOTIFY` pubsub | Dedicated `PgListener` + broadcast fan-out, capacity 2048 | [crates/coder-db/src/pubsub.rs:1](crates/coder-db/src/pubsub.rs:1) |
| Batched audit sink | Unbounded channel + background flusher with `max_batch_size` + `flush_interval`, graceful close | [crates/coder-audit/src/batched_sink.rs:1](crates/coder-audit/src/batched_sink.rs:1) |
| Graceful shutdown coordinator | Cancels every worker; drains audit + webpush; closes DB pool | [apps/coderd/src/shutdown.rs:1](apps/coderd/src/shutdown.rs:1) |
| License / entitlements service | `coder-license` (1,586 LOC): license verify, feature resolution, entitlement set | [crates/coder-license/src/](crates/coder-license/src/) |
| AWS + GCP + Azure instance identity | AWS + GCP cryptographic verifiers (PR #206); Azure scaffolding with fail-closed verifier (PR #211) — see Appendix A of the older gap doc for the remaining PKCS7 work | `crates/coder-server/src/instance_identity/` |
| OpenTelemetry + Prometheus metrics | `metrics_exporter_prometheus`, `opentelemetry_otlp` wiring | [apps/coderd/src/main.rs:49](apps/coderd/src/main.rs:49) |
| OAuth2 PKCE + `resource` parameter | `code_challenge` + `code_challenge_method = S256` + `.well-known/oauth-protected-resource` with `resource` claim | [crates/coder-server/src/handlers/oauth2.rs:499](crates/coder-server/src/handlers/oauth2.rs:499), [crates/coder-server/src/handlers/oauth2.rs:758](crates/coder-server/src/handlers/oauth2.rs:758) |

That is a lot, and it materially changes what is "remaining." The sections
below enumerate what genuinely *is* still missing.

---

## Section B — Remaining gaps, by subsystem

### B.0 Notifications dispatch — additional gaps beyond SMTP

The previous gap doc said "SMTP email dispatch is a stub"; that is **no
longer true** (see Section A). The remaining notification-dispatch gaps
surfaced by the subagent audit are narrower but numerous:

1. **Template rendering is missing from the dispatcher.** Go's notifier
   compiles `text/template` templates at dispatch time from the message
   definition, so each sent message is personalised from the DB-stored
   template plus the per-message parameters. Rust's dispatcher reads
   pre-rendered `subject` / `plain_body` / `html_body` strings out of
   `input_json`. That pushes the rendering responsibility onto whatever
   enqueued the message — and no enqueuer today speaks the Go template
   dialect or its helpers. Severity: **P0**. Effort: **L**.
2. **Webhook payload envelope is wrong.** Go wraps the message as
   `WebhookPayload { version, msg_id, title, title_markdown, body,
   body_markdown, notification_name, user }` and includes an
   `X-Message-Id` header. Rust posts the raw `input_json` as the body
   with no envelope and no ID header. Severity: **P1**. Effort: **S**.
3. **Notifier-paused setting is ignored.** Go's dispatch loop checks
   `GetNotificationsSettings().NotifierPaused` on each iteration and
   skips when paused. Rust's loop has no such guard. Severity: **P1**.
   Effort: **S**.
4. **Multi-replica lease semantics unverified.** Go uses `AcquireNotificationMessages`
   with a lease period + notifier ID, implemented via
   `FOR UPDATE SKIP LOCKED`, so replicas coexist safely. Rust
   `acquire_pending_notification_messages(batch, max_attempts)` semantics
   aren't confirmed from the code; if the SQL does not use
   `SKIP LOCKED`, two replicas can deliver the same message twice.
   Severity: **P0** if confirmed. Effort: **S** to verify + fix.
5. **No per-template "inhibited" handling.** Go marks messages whose
   template was disabled by the user as `inhibited` (with reason
   "disabled by user"). Rust doesn't. Severity: **P1**. Effort: **S**.
6. **Per-message store updates instead of bulk.** Go batches
   `BulkMarkNotificationMessages{Sent,Failed}` on a `StoreSyncInterval`
   tick. Rust updates the message status one call at a time. Severity:
   **P1**, scale-driven. Effort: **M**.
7. **Prometheus metrics gap.** Go exports `notifier_retry_count`,
   `notifier_inflight`, `notifier_send_seconds`, `notifier_queued_seconds`,
   `notifier_dispatch_attempts`. Rust emits only `tracing::info` logs.
   Effort: **M**.

### B.1 Agent DRPC surface (13 / 18 RPCs missing)

The proto file ([coder/agent/proto/agent.proto:516](coder/agent/proto/agent.proto:516)) declares **18 RPC methods** on the
`coder.agent.v2.Agent` service. The Rust dispatcher in
[crates/coder-agent-rpc/src/server.rs:176](crates/coder-agent-rpc/src/server.rs:176) routes **4**:

| # | RPC | Go ref | Rust status | Severity | Effort |
|---|-----|--------|-------------|---------:|-------:|
| 1 | `GetManifest` | `coder/coderd/agentapi/manifest.go` | **Live** (partial payload) | — | — |
| 2 | `GetServiceBanner` (v0 legacy) | `coder/coderd/agentapi/announcement_banners.go` | Unhandled | Low | XS |
| 3 | `UpdateStats` | `coder/coderd/agentapi/stats.go` | **Missing** | High | M |
| 4 | `UpdateLifecycle` | `coder/coderd/agentapi/lifecycle.go` | **Missing** | High | S |
| 5 | `BatchUpdateAppHealths` | `coder/coderd/agentapi/apps.go` | **Live** | — | — |
| 6 | `UpdateStartup` | `coder/coderd/agentapi/lifecycle.go` | **Live** | — | — |
| 7 | `BatchUpdateMetadata` | `coder/coderd/agentapi/metadata.go` + `metadatabatcher/` | **Missing** | High | M |
| 8 | `BatchCreateLogs` | `coder/coderd/agentapi/logs.go` | **Missing** (HTTP `PATCH /workspaceagents/me/logs` exists; no DRPC) | High | M |
| 9 | `GetAnnouncementBanners` | `coder/coderd/agentapi/announcement_banners.go` | **Live** | — | — |
| 10 | `ScriptCompleted` | `coder/coderd/agentapi/scripts.go` | **Missing** | Med | S |
| 11 | `GetResourcesMonitoringConfiguration` | `coder/coderd/agentapi/resources_monitoring.go` | **Missing** | Med | S |
| 12 | `PushResourcesMonitoringUsage` | `coder/coderd/agentapi/resources_monitoring.go` | **Missing** | Med | M |
| 13 | `ReportConnection` | `coder/coderd/agentapi/connectionlog.go` | **Missing** | Med | S |
| 14 | `CreateSubAgent` | `coder/coderd/agentapi/subagent.go` | **Missing** | High | M |
| 15 | `DeleteSubAgent` | `coder/coderd/agentapi/subagent.go` | **Missing** | High | S |
| 16 | `ListSubAgents` | `coder/coderd/agentapi/subagent.go` | **Missing** | High | S |
| 17 | `ReportBoundaryLogs` | `coder/coderd/agentapi/boundary_logs.go` | **Missing** | Low | S |
| 18 | `UpdateAppStatus` | `coder/coderd/agentapi/apps.go` | **Missing** | Med | S |

`UpdateStats` / `UpdateLifecycle` / `BatchCreateLogs` are called within seconds
of a real Go agent connecting, so until they land the Rust coderd cannot
service a production agent past the initial manifest fetch. The DRPC dispatch
returns code 12 (`Unimplemented`) for each unmapped method — the Go client's
behaviour on that code is to tear the session down, so the agent will fail
with a clear error rather than hang.

**Also missing at the transport level** (surfaced by the exploration
subagent): multi-frame (`done=false`) packet reassembly, streaming RPC
support (required for `Coordinate`, `WorkspaceUpdates`, `StreamDERPMaps` on
the *tailnet* service; see §B.2), and `InvokeMetadata` propagation to
handlers for tracing. The wire code in
[crates/coder-agent-rpc/src/wire.rs](crates/coder-agent-rpc/src/wire.rs)
explicitly rejects multi-frame packets today.

**Also incomplete inside the live handlers** (found reading
`agent_rpc_live.rs`): `Manifest.git_auth_configs = 0`, `vs_code_port_proxy_uri =
""`, `derp_force_websockets = false`, `derp_map = None`. Each is a small wire
into existing state (`config.external_auth`, `access_url`, deployment config,
tailnet service) — collectively **M** effort.

### B.2 Tailnet coordinator & transport

Go has a full DRPC `Tailnet` service
([coder/tailnet/proto/tailnet.proto:239](coder/tailnet/proto/tailnet.proto:239)):
`PostTelemetry`, `StreamDERPMaps` (server-stream), `RefreshResumeToken`,
`Coordinate` (bidi-stream), `WorkspaceUpdates` (server-stream). Enterprise
adds a Postgres-backed replica-aware coordinator
([coder/enterprise/tailnet/pgcoord.go](coder/enterprise/tailnet/pgcoord.go),
1,723 LOC) that replaces the in-memory one over `LISTEN/NOTIFY`.

Rust has `InMemoryCoordinator`
([crates/coder-connectivity/src/tailnet.rs:386](crates/coder-connectivity/src/tailnet.rs:386))
that uses **JSON over WebSocket**, explicitly not DRPC/protobuf, not
multi-peer, and not replica-aware. The module docstring lists the limitation
("real Go clients are **not** compatible"). Gaps:

- **Protocol incompatibility** — Go CLI / desktop / workspace-proxy all
  speak DRPC. **Severity: critical.** **Effort: L** (shared with §B.1
  transport work).
- **No `StreamDERPMaps`** — agents learn DERP topology only at connection
  time via `Manifest`; in Go they subscribe and get pushes on config
  change.
- **No `WorkspaceUpdates`** — used by CLI / desktop to learn what
  workspaces the user owns and their tunnel endpoints. Without it, the
  CLI cannot enumerate tunnels.
- **No multi-agent bridging** — Go's `ServeMultiAgentClient` assigns each
  inbound tailnet client its own peer ID so one stream can address many
  agents. Rust's single-peer model conflates them.
- **No pg-coord** — single-process only. Hard blocker for HA.

### B.3 DERP relay & mesh

`crates/coder-connectivity/src/derp.rs` (1,413 LOC) is a real DERP server
implementation (clients, key routing, keepalives, watchers, packet
forwarders) and `crates/coder-server/src/handlers/derp.rs` (433 LOC) upgrades
`/derp` to a DERP WebSocket. Good coverage for a single node.

`DerpMesh` at [crates/coder-connectivity/src/derp.rs:710](crates/coder-connectivity/src/derp.rs:710) is **scaffolding
only** — `run_mesh_connection` awaits cancellation and never dials the other
mesh nodes. Go mesh lives in
[coder/enterprise/derpmesh/derpmesh.go](coder/enterprise/derpmesh/derpmesh.go)
(165 LOC). Without mesh dialing, multi-replica DERP traffic can't cross
nodes, so SSH sessions routed to one replica can't be relayed back through
another.

Severity: High for HA / multi-region. Effort: M.

### B.4 Reconnecting-PTY

Go keeps an in-agent, session-keyed PTY that survives client disconnects and
replays scrollback on reconnect
([coder/agent/reconnectingpty/](coder/agent/reconnectingpty/)).

Rust `get_workspace_agent_pty` at
[crates/coder-server/src/handlers/agents.rs:993](crates/coder-server/src/handlers/agents.rs:993)
is a **stateless pubsub relay**: input bytes are NOTIFYed on one channel and
output bytes on another. Any WebSocket drop ends the session — no
`reconnect_id`, no scrollback replay, no agent-side buffered PTY store.

Severity: High — every dropped connection kills the user's shell. Effort: L.

### B.5 Workspace-proxy coordinate bridge

[coder/enterprise/coderd/workspaceproxycoordinate.go](coder/enterprise/coderd/workspaceproxycoordinate.go)
accepts a proxy's WebSocket and calls `ServeMultiAgentClient`, plugging the
proxy into the coordinator as a *client* that can address many agents.

Rust `run_workspace_proxy_coordinate`
([crates/coder-server/src/handlers/workspaceproxies.rs:820](crates/coder-server/src/handlers/workspaceproxies.rs:820))
accepts the WebSocket, registers the proxy as a **single peer**, and relays
JSON `CoordinateRequest`/`CoordinateResponse`. Consequences:

- All users behind one proxy share one coordinator peer ID.
- Binary frames are decoded as JSON and fail for any real v2+ proxy.

Severity: High. Effort: L — transitively blocked by §B.1 and §B.2.

### B.6 Provisioner daemon wire protocol

Go provisionerd speaks **DRPC over yamux** with 8 RPCs
([coder/provisionerd/proto/provisionerd.proto:171](coder/provisionerd/proto/provisionerd.proto:171)):
`AcquireJob`, `AcquireJobWithCancel` (bidi stream), `CommitQuota`,
`UpdateJob`, `FailJob`, `CompleteJob`, `UploadFile` (client stream),
`DownloadFile` (server stream).

Rust [crates/coder-provisioner/src/server.rs](crates/coder-provisioner/src/server.rs)
(1,909 LOC) implements a **custom JSON WebSocket protocol** with a different
message taxonomy:

| Go RPC | Rust equivalent | Gap |
|--------|-----------------|-----|
| `AcquireJob` | `DaemonMessage::AcquireJob` + `ServerMessage::{JobAssigned,NoJob}` | Wire format incompatible |
| `AcquireJobWithCancel` | Partially — cancellation is a server push `JobCanceled`, not a bidi stream | Diverges |
| `CommitQuota` | Missing | Prevents quota enforcement before Apply |
| `UpdateJob` | Merged into `JobLogs` + `JobTimings` + ad-hoc progress | Diverges |
| `FailJob` | Collapsed into `CompleteJob { error }` | Diverges |
| `CompleteJob` | `CompleteJob` | Diverges |
| `UploadFile` / `DownloadFile` | Not implemented; daemons can't transfer template tarballs | **Blocker** |

Consequence: a stock Go `provisionerd` cannot connect to a Rust coderd, and
even if it could, it couldn't exchange tarballs. Until the DRPC wire lands,
the Rust server can only drive a yet-to-be-written Rust provisioner
daemon; there isn't one.

Severity: critical if the goal is to re-use the Go provisionerd binary.
Effort: L for DRPC wire; **XL** cumulative including file-transfer streaming.

### B.7 Template / build orchestration

This is the **largest non-security functional gap** — route parity is
green but nothing below the HTTP layer actually provisions a workspace.

1. **No Terraform runtime anywhere in Rust.** Neither coderd nor a
   provisionerd equivalent embeds Terraform. Go ships
   [coder/provisioner/terraform/](coder/provisioner/terraform/) with
   `tfexec`-driven `init/plan/apply`, HCL parsing via `hashicorp/hcl`,
   module download, log streaming, and state→resource conversion.
   Rust has **zero** of this — the string `"terraform"` appears only in
   tag sets, init scripts, and configuration. Severity: **blocks real
   workspaces**. Effort: **XL** (multi-week). Recommended path: wire the
   Go `provisionerd` binary against Rust coderd via §B.6 rather than
   re-implementing HCL in Rust.
2. **`post_workspace_build` hard-codes `provisioner: "echo"`** at
   [crates/coder-server/src/handlers/workspaces.rs:313](crates/coder-server/src/handlers/workspaces.rs:313).
   Only the echo provisioner can consume scheduled jobs today.
   Severity: confirms (1). Effort: one line once (1) lands.
3. **Dynamic parameter evaluation (`POST .../dynamic-parameters/evaluate`)**
   returns stored parameter definitions. Go's `coder/coderd/dynamicparameters/`
   (10 files — `render.go`, `resolver.go`, `static.go`, `tags.go`) re-parses
   module output via `preview.Preview`, resolves conditionals, enforces
   static validation, and reseeds tags from parameter inputs. Both
   `POST .../dynamic-parameters/evaluate` and the WebSocket re-render
   stream on `GET .../dynamic-parameters` are stubbed — the WebSocket
   path in particular is **entirely absent**.
   [crates/coder-server/src/handlers/templates.rs:1506](crates/coder-server/src/handlers/templates.rs:1506) and
   [crates/coder-server/src/handlers/templates.rs:1582](crates/coder-server/src/handlers/templates.rs:1582).
   Effort: **L** — blocks on (1).
4. **Provisioner tag matching** is largely present:
   `coder-core/src/provisioner.rs` defines `TAG_SCOPE`, `TAG_OWNER`,
   `SCOPE_USER`, `SCOPE_ORGANIZATION` and
   [crates/coder-core/src/provisioner.rs:628](crates/coder-core/src/provisioner.rs:628) has
   `provisioner_tagset_matches` with `is_untagged_org_scope` short-circuit;
   [crates/coder-workspaces/src/lib.rs:1754](crates/coder-workspaces/src/lib.rs:1754)
   ports `getClassicProvisionerTags`. Minor gap: verify the
   `acquirer.go` ordering (org-scope before user-scope) matches. Severity:
   **low**. Effort: **S** (audit + test).
5. **`wsbuilder` composition is inlined and shallow.** Go's 1,431-LOC
   [coder/coderd/wsbuilder/wsbuilder.go](coder/coderd/wsbuilder/wsbuilder.go)
   composes: active-vs-requested version resolution, preset inference
   (`FindMatchingPresetID`), rich-parameter + preset-default merge,
   autostop/quiet-hours deadline + MaxDeadline, `BuildReason` selection
   (`Autostart` / `Dormancy` / `Autodelete` / `Failure-retry`),
   classic provisioner tags, transactional job + build insert, and a
   **prebuild claim attempt** (`ClaimPrebuiltWorkspace`). Metrics too.
   Rust's `post_workspace_build` at
   [crates/coder-server/src/handlers/workspaces.rs:236](crates/coder-server/src/handlers/workspaces.rs:236):
   - No preset resolution / preset-param merge (`template_version_preset_id`
     is not plumbed through).
   - **No prebuild claim attempt at all** (grep for `claim_prebuilt_workspace`
     → 0 hits).
   - `deadline: None, max_deadline: None` hard-coded at
     [crates/coder-server/src/handlers/workspaces.rs:333](crates/coder-server/src/handlers/workspaces.rs:333) — templates with
     autostop-requirement never compute a deadline; quiet-hours never
     clamp.
   - `reason: "initiator"` hard-coded.
   - No `MatchedProvisioners` pre-flight before scheduling the job.
   Severity: **high**. Effort: **M–L** — extract a `coder-workspaces::builder`
   module modelled on `wsbuilder.go` and wire from the 3 handler call
   sites (`post_workspace_build`, lines 1919, 2101).
6. **Prebuild reconciliation is completely absent.** Go's enterprise
   [coder/enterprise/coderd/prebuilds/reconcile.go](coder/enterprise/coderd/prebuilds/reconcile.go)
   (1,321 LOC) runs a ticker that builds a `GlobalSnapshot`, calls
   `CalculateActions` per `PresetSnapshot`, creates/deletes prebuilt
   workspaces, enforces hard-limits, emits metrics. Plus
   `StoreMembershipReconciler` for `PrebuildsSystemUserID` →
   `PrebuildsGroupName`. Rust has only `/prebuilds/settings` GET/PUT
   ([crates/coder-server/src/handlers/prebuilds.rs](crates/coder-server/src/handlers/prebuilds.rs),
   81 LOC); no reconciler task in `apps/coderd/src/main.rs`, no claim
   path. **The feature is advertised complete in the enterprise parity
   matrix because the HTTP routes are stubs** — this should be called
   out in the README. Severity: **high** — an enterprise flagship feature
   is non-functional. Effort: **L** (depends on (5) for the claim path).
7. **Quiet-hours data model is wired but policy is not enforced.**
   `parse_quiet_hours_schedule`
   ([crates/coder-workspaces/src/lib.rs:328](crates/coder-workspaces/src/lib.rs:328)),
   `QuietHoursWindow` (line 294), and the `PUT/GET /users/{u}/quiet-hours`
   route (app.rs:700) exist. **But**
   `autostop_requirement_days_of_week` and `autostop_requirement_weeks`
   are hard-coded to **0** in
   [crates/coder-server/src/app.rs:6133](crates/coder-server/src/app.rs:6133)
   and [crates/coder-server/src/app.rs:26289](crates/coder-server/src/app.rs:26289) (no DB read in the
   template-schedule response), and wsbuilder-equivalent never clamps
   to quiet-hours because MaxDeadline is `None` (see 5). Severity:
   **medium-high**. Effort: **S–M** (plumb the DB fields + apply in the
   builder).
8. **Autobuild executor decide-loop is close to parity.** `AutobuildExecutor`
   in Rust handles `Autostart` / `Autostop` / `Dormancy` / `Autodelete` /
   `Failure-retry` / `Inactivity` via `decide_action` at
   [crates/coder-workspaces/src/lib.rs:790](crates/coder-workspaces/src/lib.rs:790)
   and reason types at line 411. The gap is downstream: when the
   action fires, it calls the thin build path (see 5), so deadlines /
   preset / prebuild still drop. Severity: **medium**. Effort: **S** once
   (5) lands.
9. **Template version archive / unarchive**: full Rust parity —
   `post_archive_template_version` (line 1079), `post_archive_template_versions`
   (1748), `post_unarchive_template_version` (2075); store methods have
   tests. **Version promote** is via `put_template` at
   [crates/coder-server/src/app.rs:369](crates/coder-server/src/app.rs:369) setting `active_version_id`
   — same shape as Go. No gap.
10. **Workspace-app health probe loop.** Go continuously probes
    app `healthcheck_url` from the server side and writes `workspace_apps.health`.
    Rust has agent-reported path (DRPC `batch_update_app_health` at
    [crates/coder-agent-rpc/src/handlers.rs:57](crates/coder-agent-rpc/src/handlers.rs:57),
    storage `update_workspace_app_health`, pubsub `app_health` channel) but
    **no server-side prober**. Apps stay at their last agent-reported
    status. Severity: **medium**. Effort: **S** (reqwest-based poller).

### B.8 Missing periodic background workers

Inventoried from `coder/coderd/coderd.go::New` goroutines. What Rust already
runs is covered in Section A; the remaining gaps:

| Worker | Go ref | Rust status | Severity | Effort |
|--------|--------|-------------|---------:|-------:|
| **Stuck-job reaper** | [coder/coderd/jobreaper/detector.go](coder/coderd/jobreaper/detector.go) | DB method `get_stale_jobs` + handler exist, **no ticker calling it** | degraded | S |
| **dbRollup (workspace_agent_stats aggregation)** | [coder/coderd/database/dbrollup/dbrollup.go](coder/coderd/database/dbrollup/dbrollup.go) | **Missing** — no hourly/daily rollup, so `/insights/*` reads raw rows | degraded-insights | M |
| **Workspace usage tracker flusher** | [coder/coderd/workspacestats/tracker.go](coder/coderd/workspacestats/tracker.go) `NewTracker` | `POST /workspaces/{id}/usage` handler persists synchronously; no batching | degraded-perf | S |
| **Prebuild reconciler** | [coder/enterprise/coderd/prebuilds/reconcile.go](coder/enterprise/coderd/prebuilds/reconcile.go) | Missing (see §B.7.6) | degraded | M |
| **Workspace-app healthcheck probe** | spread across `coder/coderd/workspaceapps/` | Missing (see §B.7.6) | degraded | S–M |
| **System-role reconcile at startup** | `rolestore.ReconcileSystemRoles` in [coder/coderd/coderd.go:584](coder/coderd/coderd.go:584) | No equivalent — system roles are migrations-seeded only | low | XS |
| **Entitlements refresh ticker** | Go refreshes entitlements every N minutes after a license write | `coder-license` computes on read; no periodic refresh ticker for cached entitlements across replicas | low-medium | S |
| **Connection log pruning** | [coder/coderd/connectionlog/](coder/coderd/connectionlog/) pruner | Rust has the handler; no periodic prune task | low | S |
| **Crypto-key rotator advisory lock** | Go acquires `LockIDCryptoKeyRotation` pg advisory lock before each rotation | Rust `CryptoKeyRotator::start` has no advisory-lock acquisition — multi-replica double-rotation race | **high** (HA) | S |

### B.9 OAuth2 provider

The provider is largely complete (PRs #193–#206). Remaining, in priority
order:

1. **OAuth2 error envelope is not RFC 6749 compliant.** Rust uses
   `ApiResponse::error { message, detail }` on OAuth2 failures; RFC 6749
   mandates `{ "error": "<code>", "error_description": "<free text>" }`
   with codes `invalid_client`, `invalid_grant`, `unsupported_grant_type`,
   `invalid_target`, `invalid_request`. Downstream OAuth2 client libraries
   will fail to parse. Severity: **P0** — breaks third-party integrations.
   Effort: **M** (rewrite the error mapper + grep for every call site).
2. **RFC 8707 `resource` consistency at token endpoint.** `exchange_code`
   accepts `resource` at authorize time but `OAuth2TokenRequest` doesn't
   carry it at token exchange — Go `validateResourceParameter` at
   [coder/coderd/oauth2provider/tokens.go](coder/coderd/oauth2provider/tokens.go)
   errors with `errInvalidResource` if the two don't match. Severity:
   **P0**. Effort: **S**.
3. **HTTP Basic auth for confidential clients (RFC 6749 §2.3.1).** Rust
   reads client_id/client_secret only from the request body; Go
   `extractTokenRequest` accepts Basic-auth credentials and rejects
   simultaneous body + header presentation with `errConflictingClientAuth`.
   Missing means any client that sends credentials via Basic auth today
   fails with "missing client_id". Severity: **P1**. Effort: **S**.
4. **Revocation cascade + audit.** `POST /oauth2/revoke` at
   [crates/coder-server/src/handlers/oauth2.rs:1166](crates/coder-server/src/handlers/oauth2.rs:1166)
   deletes the API key (which *does* cascade to the refresh token via FK,
   per comment), but does **not** emit an audit entry. Go does. Effort:
   **XS**.
5. **Refresh-token rotation.** Go rotates refresh tokens on every refresh
   call; Rust reuses the same refresh token. Effort: **S**.
6. **Scope narrowing on refresh.** Both Go and Rust have TODOs here; not
   a regression, but neither enforces `refresh.scope ⊆ original.scope`.
   Effort: **M**.
7. **Consent screen.** Go renders a consent page on first-time
   `authorize`; Rust auto-approves. Surfaces for any third-party RFC 7591
   client. Effort: **M**.
8. **RFC 7592 registration-access-token rotation** on PUT. Low priority.
   Effort: **S**.
9. **PKCE mandatory-S256 audit.** Rust pipes `code_verifier` through
   `exchange_code` but the handler doesn't confirm S256-only (may accept
   `plain`). Audit the provider service and reject `plain`. Effort: **S**
   audit.

### B.10 Audit log coverage

`coder-audit` has a well-formed batched sink
([crates/coder-audit/src/batched_sink.rs](crates/coder-audit/src/batched_sink.rs))
with async `AuditSink` trait. But the deeper gaps are in **what the sink
receives** and **who writes to it**.

1. **No `Diff[T]` system.** Go's
   [coder/coderd/audit/diff.go](coder/coderd/audit/diff.go) + enterprise
   `audit/table.go` provide reflection over `Auditable` structs with
   per-field `ActionTrack` / `Ignore` / `Secret` policy that emits a
   structured `Map[field → OldNew{Old, New, Secret}]` change map. Rust
   `AuditEvent` has only `summary: String` — no structured diff, no
   secret redaction, no field-level tracking. Severity: **P0** (compliance
   blocker). Effort: **XL**.
2. **Audit coverage holes (spot-check).**
   - `handlers/workspaces.rs`: **0 audit call sites**. Go has **22**
     (build, start, stop, rename, delete, convert, favorite, dormant,
     autostart, autoupdates, ACL, port-share…). Severity: **P0**.
   - `handlers/templates.rs`: 4 call sites. Go has ~14 (templates +
     template-versions). Template-version audits mostly missing.
   - `handlers/users.rs`: 10 call sites. Close to Go's 12.
   - Likely missing: `apikey` audits, `aitasks` audits, notification
     template-method audits (2 in Go), `gitsshkey` audits (2 in Go),
     organization-member audits.
3. **No `Auditable` target-ID extractor.** Go dispatches over ~30 types
   to pull `(target_id, target_name)`; Rust handlers hand-build these.
4. **No request-correlation baggage.** Go propagates OTel baggage into
   audit rows; Rust audit entries lack a request ID field.
5. **Login/logout audit without StatusCode.** `auth.rs` records login
   but the HTTP status code isn't captured.

### B.11 RBAC / dbauthz layer — **largest single security-parity gap**

`coder-rbac` implements `Actor`, `Role`, `Scope`, `Permission`, and
`Authorizer` ([crates/coder-rbac/src/lib.rs:35](crates/coder-rbac/src/lib.rs:35),
2,399 LOC). It is used by handlers directly. Go's RBAC is **9,008 LOC**
across `coderd/rbac/` and — critically — every database method is wrapped
by a `dbauthz.Querier` (6,838 LOC at
[coder/coderd/database/dbauthz/dbauthz.go](coder/coderd/database/dbauthz/dbauthz.go))
that pulls the actor from context and calls `Authorize()` before returning
any rows. Rust has **no dbauthz wrapper**; RBAC is enforced only at the
HTTP handler boundary.

1. **No dbauthz-style store wrapper.** Any internal caller — background
   job, webhook, system action, or any handler that forgets the
   authorizer call — ships as an RBAC bypass. Severity: **P0**
   (largest security-parity gap in the codebase). Effort: **XL** to
   wrap every store method, or **M** to introduce a
   `dbauthz::Authorized<Store>` newtype used by handler code paths,
   with a lint against bare-store imports in handlers.
2. **No `As*` system-actor contexts.** Go pervasively uses
   `AsSystemRestricted`, `AsKeyRotator`, `AsProvisionerd`, `AsOwner`
   to elevate/demote privileges for background tasks; Rust has no
   equivalent. Effort: **L**.
3. **Scopes catalog: 2 of 21 implemented.** Go ships 21 low-level
   scopes via generated `scopes_constants_gen.go` (`workspace:start`,
   `workspace:read`, `template:read`, `apikey:*`, `user_secret:*`,
   `task:*`, `organization:*`, `WorkspaceAgentScope`, `ScopeNoUserData`,
   …). Rust only has `ScopeAll` + `ScopeApplicationConnect`. **Critical
   missing**: `WorkspaceAgentScope` — which in Go constrains an agent's
   access to its own workspace + template + owner. Without it, agents
   are granted far more than they should be. Severity: **P0**.
   Effort: **L**.
4. **No Rego / partial evaluation for SQL pushdown.** Go uses OPA with
   `regosql` to translate policy to SQL `WHERE` clauses so list
   endpoints can prefilter at the DB. Rust enumerates permissions
   in-memory, so `(pagination, RBAC)` is `O(n)` rows scanned.
   Severity: **P1** (degraded). Effort: **XL**.
5. **Custom roles (enterprise-gated in Go).** Rust handlers accept
   custom-role writes but the runtime `Authorizer` may not expand them.
   Effort: **M** to verify and wire.

### B.12 IDP sync, SCIM, external auth

`crates/coder-server/src/handlers/idpsync.rs` (809 LOC) and `scim.rs` (1,058
LOC) are substantial at the handler level, but the **runtime** is where the
real gap lives.

1. **IDP sync runtime is entirely missing.** Go `coderd/idpsync/{idpsync,
   group_sync, organization, role}.go` (~900 LOC) exposes `SyncGroups`,
   `SyncOrganizations`, `SyncRoles`, `ParseGroupClaims`,
   `ParseRoleClaims`, `ParseOrganizationClaims`. These are called from
   the OIDC login path on **every** login to reconcile memberships.
   Rust's `oauth_login.rs` builds `merged_claims` but never calls a
   sync function — so the settings (regex filter, auto-create groups,
   default-org assignment) that `idpsync.rs` persists are a no-op.
   Severity: **P0** (OIDC-driven identity management silently doesn't
   work). Effort: **XL** — must port the three Sync modules plus claim
   parsing.
2. **SCIM**: filter is intentionally disabled in Go
   (`filter: false` → returns 0 users, forcing Okta's create path);
   Rust mirrors this. `active`-only PATCH, suspended-on-deactivate,
   activate-on-reactivate all match.
   - **Possible constant-time-comparison gap**: `scim_verify_auth`
     uses `==` on the auth header in Rust? Verify; if not constant-time
     there's a side-channel on the SCIM API token. Effort: **S** audit.
   - **PUT immutability**: Rust rejects username mutations as
     `immutability_violation`; Go has a permissive TODO. Rust is
     stricter — intentional, keep it.
3. **External auth**:
   - Device flow handlers present; underlying service at
     `state.external_auth.authorize_device`/`exchange_device` not
     inspected in this pass. Effort: **S** audit.
   - `RefreshToken` proactive refresh, `ValidateURL` upstream probe,
     and `AppInstallURL`/`AppInstallationsURL` (GitHub Apps) — not
     visible from the handler surface; likely missing. Effort: **M** to
     verify + port.
4. **Callback flow** — Rust implements `OAUTH2_STATE_COOKIE`,
   `OAUTH2_REDIRECT_COOKIE`, and `sanitize_redirect_uri`. ✓

### B.13 Workspace apps behavioural gaps

From the exploration subagent:

- **Organization sharing level** — `sharing_level_db_to_proto` at
  [crates/coder-server/src/handlers/agent_rpc_live.rs:76](crates/coder-server/src/handlers/agent_rpc_live.rs:76)
  lists `organization`, but `authenticate_app_request` at
  [crates/coder-server/src/handlers/workspace_apps.rs:1303](crates/coder-server/src/handlers/workspace_apps.rs:1303)
  does not enforce org membership. Effort: **S**.
- **Stats recording** — Go writes per-session app stats
  ([coder/coderd/workspaceapps/stats.go](coder/coderd/workspaceapps/stats.go),
  324 LOC). Rust `proxy_workspace_app` doesn't. Effort: S.
- **Error classification** — Go's `appErrNotFoundDescription` chain returns
  specific UI errors (e.g., "agent is not reporting"). Rust returns generic
  404/403 on a subset. Effort: XS.

### B.14 Non-HTTP surfaces & deployment ergonomics

| Area | Go | Rust | Scope? | Effort |
|------|----|------|--------|-------:|
| `coder` CLI | `coder/cmd/coder` | **Out of scope** for this backend rewrite | explicitly out | — |
| Workspace agent binary | `coder/agent/` | **Out of scope** — Rust coderd must speak to the Go agent via DRPC (§B.1) | explicitly out | — |
| `provisionerd` binary | `coder/cmd/coder provisionerd` | **Out of scope** — but Rust must serve it via DRPC (§B.6). A Rust provisionerd is a separate decision | decide | — |
| Embedded frontend (`site/out`) | Go `embed.FS` | **No** — Rust serves `/` with a simple handler; does not host the React SPA | gap | M |
| Support bundle generation | `coder/support/bundle.go` | **Missing** | gap | S |
| Let's Encrypt / autocert | Go supports via third-party lib | **No** — only explicit `tls_cert_files` / `tls_key_files` | gap | S |
| Access-URL auto-detection | Go detects external IP if not configured | **No** — `CODER_ACCESS_URL` required | minor gap | XS |
| HTTP/2, HTTP/3 | Go supports H2 natively; H3 optional | Axum supports H2 by default; H3 not wired | minor | S |
| OS packaging (deb/rpm/Docker/brew) | All present | Not present for Rust binary | out of scope for now | — |
| Custom branding assets stored in DB | Go serves logos/favicons | Rust stores them but doesn't serve | gap | S |
| Trial-signup redirector | Present in Go | Missing | cosmetic | S |

---

## Section C — Priority matrix & waves

Two parallel concerns drive prioritisation:

- **Structural / correctness path** — what's needed so a real Go
  `coder agent` + real Go `provisionerd` can drive workspaces through
  the Rust coderd end-to-end.
- **Security / compliance path** — what the Rust coderd would *silently*
  get wrong today for a security- or compliance-minded customer.

Both paths have P0 work. Do them in parallel where the crates don't
overlap.

### Wave 0 — Security-parity P0 (do in parallel with Wave 1)

These are *not* route-surface gaps but silent correctness/security
regressions vs. Go. They block a regulated-customer deployment
regardless of §B.1–B.7.

| # | Item | § | Effort | Rationale |
|---|------|---|-------:|-----------|
| S1 | Ship `WorkspaceAgentScope` (agent is otherwise over-privileged) | B.11.3 | M | P0 security |
| S2 | Scopes catalog expansion: port the remaining ~19 scopes | B.11.3 | L | P0 security |
| S3 | `dbauthz`-style store wrapper (newtype at minimum) + lint against bare store use in handlers | B.11.1 | M (newtype) / L (full) | P0 — any forgotten authorize is an RBAC bypass |
| S4 | `AsSystemRestricted`/`AsKeyRotator`/etc. actor contexts for background tasks | B.11.2 | L | P0 — background tasks currently run with no actor |
| S5 | IDP sync runtime: port `SyncGroups`, `SyncOrganizations`, `SyncRoles`, + claim parsers; call on every OIDC login | B.12.1 | XL | P0 — settings UI is a no-op today |
| S6 | Audit `Diff[T]` reflective system with per-field track/ignore/secret policy | B.10.1 | XL | P0 — compliance blocker |
| S7 | Workspace-handlers audit sweep (0 call sites → Go's 22) and fill template-version / apikey / org-member gaps | B.10.2 | M | P0 compliance |
| S8 | OAuth2 error envelope → RFC 6749 `{error, error_description}` | B.9.1 | M | P0 — breaks third-party clients |
| S9 | OAuth2 `resource` consistency check at token exchange (RFC 8707) | B.9.2 | S | P0 |
| S10 | Crypto-key rotator pg advisory lock | B.8 | S | P0 HA race |
| S11 | Notification dispatcher template rendering (`text/template` or equivalent) | B.0.1 | L | P0 — messages are unreadable without it |
| S12 | Notification multi-replica `SKIP LOCKED` lease audit + fix | B.0.4 | S | P0 if missing |
| S13 | OAuth2 HTTP Basic client-auth support (RFC 6749 §2.3.1) | B.9.3 | S | P1 → P0 for ecosystem clients |
| S14 | SCIM auth-header constant-time comparison audit | B.12.2 | S | P1 — side-channel |

### Wave 1 — Critical path for running real workspaces

| # | Item | § | Effort | Depends on |
|---|------|---|-------:|------------|
| 1 | Implement the 4 agent RPCs called on connect (UpdateStats, UpdateLifecycle, BatchCreateLogs, BatchUpdateMetadata) | B.1 | M | existing DRPC framing |
| 2 | Implement remaining 9 agent RPCs (ScriptCompleted, ReportConnection, resources monitoring ×2, sub-agents ×3, boundary logs, UpdateAppStatus, GetServiceBanner) | B.1 | M | #1 |
| 3 | Multi-frame + streaming RPC in the DRPC wire | B.1 transport | M | prost + varint plumbing |
| 4 | Tailnet DRPC service (`Coordinate`, `WorkspaceUpdates`, `StreamDERPMaps`, `RefreshResumeToken`, `PostTelemetry`) over DRPC on `/tailnet` | B.2 | L | #3 |
| 5 | Multi-peer / `ServeMultiAgentClient` abstraction in the coordinator | B.2 | M | #4 |
| 6 | Provisionerd DRPC service on `/organizations/{org}/provisionerdaemons/serve`, including `UploadFile` / `DownloadFile` streams | B.6 | L | #3 |
| 7 | **Decision point**: run the Go `provisionerd` binary against Rust coderd (pick #6), *or* write a Rust Terraform provisioner runtime (new L–XL item). | B.7.1 | XL if own runtime | #6 |
| 8 | Fill `Manifest` gaps (git_auth_configs, vs_code_port_proxy_uri, derp_map, derp_force_websockets) | B.1 | S | #4 enables derp_map |

Wave 1 unblocks end-to-end workspace creation and SSH/PTY against a Rust
coderd. Items #1, #2, #6, #7 are the tentpoles.

### Wave 2 — HA / multi-replica

| # | Item | § | Effort |
|---|------|---|-------:|
| 9 | Postgres-backed coordinator (pg-coord) replacement | B.2 | L |
| 10 | DERP mesh dialer (replace `run_mesh_connection` stub) | B.3 | M |
| 11 | Workspace-proxy multi-peer DRPC bridge on `/workspaceproxies/me/coordinate` | B.5 | M |
| 12 | Reconnecting-PTY session store + resume token + scrollback replay | B.4 | L |

### Wave 3 — Ops & ecosystem quality

| # | Item | § | Effort |
|---|------|---|-------:|
| 13 | Stuck-job reaper ticker (use existing `get_stale_jobs`) | B.8 | S |
| 14 | Provisioner tag matching with wildcards + scopes | B.7.3 | M |
| 15 | Prebuild reconciliation loop | B.7.5 / B.8 | M |
| 16 | Workspace-app healthcheck prober loop | B.7.6 / B.8 | S–M |
| 17 | dbRollup (workspace_agent_stats aggregation) | B.8 | M |
| 18 | Workspace usage tracker batching flusher | B.8 | S |
| 19 | Connection-log pruning job | B.8 | S |
| 20 | OAuth2 revocation audit entry | B.9.4 | XS |
| 21 | OAuth2 refresh-token rotation | B.9.5 | S |
| 22 | OAuth2 PKCE S256-only audit | B.9.9 | S |
| 23 | Workspace-apps org sharing level enforcement | B.13 | S |
| 24 | Workspace-apps session stats writer | B.13 | S |
| 25 | Workspace-apps error-classification parity | B.13 | XS |
| 26 | Dynamic parameter Plan-based evaluation | B.7.2 | M (blocked on Wave 1 #7) |
| 27 | Notification webhook payload envelope + `X-Message-Id` | B.0.2 | S |
| 28 | Notifier-paused setting respected by dispatch loop | B.0.3 | S |
| 29 | Per-template "inhibited" status | B.0.5 | S |
| 30 | Bulk `BulkMarkNotificationMessages{Sent,Failed}` batching | B.0.6 | M |
| 31 | Notification Prometheus metrics | B.0.7 | M |
| 32 | External-auth proactive refresh + ValidateURL | B.12.3 | M |

### Wave 4 — Deployment ergonomics & finish

| # | Item | § | Effort |
|---|------|---|-------:|
| 33 | Embed + serve the React frontend at `/` | B.14 | M |
| 34 | Support-bundle generator endpoint | B.14 | S |
| 35 | Let's Encrypt / autocert TLS path | B.14 | S |
| 36 | Access-URL auto-detection fallback | B.14 | XS |
| 37 | Custom branding asset serving (logos from DB) | B.14 | S |
| 38 | OAuth2 consent screen | B.9.7 | M |
| 39 | OAuth2 RFC 7592 registration-access-token rotation | B.9.8 | S |
| 40 | Trial-signup redirector | B.14 | S |
| 41 | System-role reconcile at startup | B.8 | XS |
| 42 | Azure PKCS7 attested-data verifier (Appendix A of old doc) | prior gap doc | M |
| 43 | RBAC Rego / partial eval for SQL pushdown on list endpoints | B.11.4 | XL |
| 44 | RBAC custom-role runtime expansion verification | B.11.5 | M |
| 45 | Tailnet `StreamDERPMaps` subscriber support (so agents get live DERP updates) | B.2 | S once #4 lands |

### Summary of discrete work items

- **Wave 0 (security parity):** 14 items — 3 × XL, 3 × L, 5 × M, 3 × S.
- **Wave 1 (functional path):** 8 items, dominated by 2 × L + 1 × XL.
- **Wave 2 (HA):** 4 items.
- **Wave 3 (ops/ecosystem):** 20 items, mostly S/M.
- **Wave 4 (deploy polish):** 13 items.
- **Total: ~59 discrete items.**

Effort key: XS < 1 day · S = 1–3 days · M = ~1 week · L = ~3 weeks · XL ≥ 6 weeks.

### Top-10 shortlist (if you could only do ten)

1. Port the remaining 13 agent RPCs (Wave 1 #1–#2) — unblocks live agents.
2. Provisionerd DRPC + file-transfer streams + provisioner runtime
   decision (Wave 1 #6–#7) — unblocks real workspaces.
3. DRPC multi-frame + streaming (Wave 1 #3) — foundational for #1 and #2.
4. Tailnet DRPC service + multi-peer (Wave 1 #4–#5) — unblocks
   workspace proxies + CLI tunnels.
5. Extract `coder-workspaces::builder` (wsbuilder) and wire preset
   resolution, prebuild claim, MaxDeadline, quiet-hours clamp
   (§B.7.5, §B.7.7).
6. Prebuild reconciliation loop (§B.7.6) — enterprise feature currently
   false-green.
7. Scopes catalog + `WorkspaceAgentScope` (Wave 0 S1–S2) — silent
   agent over-privilege today.
8. `dbauthz` store wrapper or newtype-with-lint (Wave 0 S3) — closes
   the "forgotten authorize = bypass" class.
9. IDP sync runtime (Wave 0 S5) — `idpsync.rs` settings are a no-op
   without it.
10. Audit `Diff[T]` system + workspaces-handler audit sweep
    (Wave 0 S6–S7) — compliance blocker.

Honorable mentions that are *small but widely visible*: OAuth2 RFC 6749
error envelope (Wave 0 S8, ~1 week), RFC 8707 resource check (S9,
a few days), crypto-key rotator pg advisory lock (S10, a few days),
notifier-paused respected by dispatch (B.0.3, a day).

---

## Section D — Documentation follow-ups

1. **Deprecate** `docs/remaining-behavioral-gaps.md` or mark it
   "superseded" with a pointer to this file; its §3 (SMTP stub), §6
   (agent DRPC absent), and §9 (webhook retry absent) are now stale.
2. Update the `CLAUDE.md` / `AGENTS.md` crate-architecture table to
   list `coder-agent-rpc`, `coder-telemetry`, `coder-license`,
   `coder-mcp`, `coder-benchmarks`, `coder-integration-tests` — all of
   which exist and are omitted.
3. Regenerate `crates/coder-server/PARITY_MATRIX.md` after Wave 1 #1–#2
   land.
4. Add a note to `README.md` clarifying that **route parity is 100 %
   but *protocol* parity is not** — the Rust coderd does not currently
   interoperate with upstream Go workspace agents or `provisionerd`
   binaries, and the enterprise prebuild reconciliation loop is not
   running. This is the single most important expectations-setting
   message for anyone evaluating the rewrite.
5. Add a note to `docs/parity-matrix-enterprise.md` noting that
   prebuilds, workspace-proxy `coordinate`, and workspace-proxy
   `crypto-keys` are green at the route level but partial/stub in
   behaviour, with a link to §B.5, §B.7.6, §B.7.7 here.

---

*End of document.*
