-- Connection logs table (enterprise feature).
--
-- Ports `coder/coderd/database/migrations/000349_connection_logs.up.sql`.
-- The `connection_status` and `connection_type` enums are already created
-- by `20260307230000_enum_types.sql`, so this migration only introduces
-- the table and its indexes.
--
-- See `coder/coderd/agentapi/connectionlog.go::ReportConnection` for the
-- agent RPC that upserts rows here, and `coder/coderd/database/queries/
-- connectionlogs.sql` for the list/count/prune queries.

CREATE TABLE IF NOT EXISTS connection_logs (
    id                  UUID NOT NULL,
    connect_time        TIMESTAMPTZ NOT NULL,
    organization_id     UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    workspace_owner_id  UUID NOT NULL REFERENCES users (id)          ON DELETE CASCADE,
    workspace_id        UUID NOT NULL REFERENCES workspaces (id)     ON DELETE CASCADE,
    workspace_name      TEXT NOT NULL,
    agent_name          TEXT NOT NULL,
    type                connection_type NOT NULL,
    ip                  INET NOT NULL,
    code                INTEGER,

    -- Only set for web events (workspace_app / port_forwarding).
    user_agent          TEXT,
    user_id             UUID,
    slug_or_port        TEXT,

    -- Null for web events.
    connection_id       UUID,
    -- Null until we upsert a disconnect log for the same connection_id.
    disconnect_time     TIMESTAMPTZ,
    disconnect_reason   TEXT,

    PRIMARY KEY (id)
);

-- Connection ID is NULL for web events, but present for SSH events. The
-- unique index therefore permits multiple web events for the same
-- (workspace, agent) pair, and for SSH events the UPSERT path merges the
-- disconnect fields onto the existing row keyed by this triple.
CREATE UNIQUE INDEX IF NOT EXISTS idx_connection_logs_connection_id_workspace_id_agent_name
    ON connection_logs (connection_id, workspace_id, agent_name);

CREATE INDEX IF NOT EXISTS idx_connection_logs_connect_time_desc
    ON connection_logs USING btree (connect_time DESC);
CREATE INDEX IF NOT EXISTS idx_connection_logs_organization_id
    ON connection_logs USING btree (organization_id);
CREATE INDEX IF NOT EXISTS idx_connection_logs_workspace_owner_id
    ON connection_logs USING btree (workspace_owner_id);
CREATE INDEX IF NOT EXISTS idx_connection_logs_workspace_id
    ON connection_logs USING btree (workspace_id);
