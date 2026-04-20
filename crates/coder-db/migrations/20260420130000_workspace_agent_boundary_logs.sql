-- Workspace agent boundary logs — per-resource access records emitted
-- by boundary on the agent. Mirrors the `ReportBoundaryLogs` RPC in
-- `coder/agent/proto/agent.proto` and the handler in
-- `coder/coderd/agentapi/boundary_logs.go`.
--
-- The Go reference keeps boundary usage tracking in `coderd/boundaryusage`
-- and logs requests via slog. The Rust rewrite persists the individual
-- log rows so the coderd API can serve historical queries in a later
-- vertical slice. Schema is intentionally lean: one row per reported
-- log with the HTTP request fields pulled out of the `resource` oneof.
-- Additional resource kinds can be added as new nullable columns.

CREATE TABLE IF NOT EXISTS workspace_agent_boundary_logs (
    id bigserial NOT NULL PRIMARY KEY,
    agent_id uuid NOT NULL REFERENCES workspace_agents(id) ON DELETE CASCADE,
    event_time timestamptz NOT NULL,
    allowed boolean NOT NULL,
    -- HTTP request fields. Populated when the reported log's resource
    -- oneof is `HttpRequest`. Null when another resource type is
    -- reported (future-proofing for non-HTTP boundary log entries).
    http_method text,
    http_url text,
    -- Only populated when `allowed = true`; boundary denies by default
    -- and only allow rules carry a matched-rule identifier.
    matched_rule text,
    created_at timestamptz DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_workspace_agent_boundary_logs_agent_id
    ON workspace_agent_boundary_logs(agent_id, event_time DESC);
