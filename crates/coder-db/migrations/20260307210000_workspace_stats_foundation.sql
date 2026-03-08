CREATE TABLE IF NOT EXISTS workspaces (
    id UUID PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS provisioner_jobs (
    id UUID PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    canceled_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    error TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS workspace_builds (
    id UUID PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    build_number BIGINT NOT NULL DEFAULT 1,
    transition TEXT NOT NULL DEFAULT 'start',
    job_id UUID REFERENCES provisioner_jobs(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_workspace_builds_workspace_id_build_number
    ON workspace_builds (workspace_id, build_number DESC);

CREATE TABLE IF NOT EXISTS workspace_agent_stats (
    agent_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rx_bytes BIGINT NOT NULL DEFAULT 0,
    tx_bytes BIGINT NOT NULL DEFAULT 0,
    connection_median_latency_ms DOUBLE PRECISION NOT NULL DEFAULT 0,
    session_count_vscode BIGINT NOT NULL DEFAULT 0,
    session_count_ssh BIGINT NOT NULL DEFAULT 0,
    session_count_jetbrains BIGINT NOT NULL DEFAULT 0,
    session_count_reconnecting_pty BIGINT NOT NULL DEFAULT 0,
    usage BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_workspace_agent_stats_created_at
    ON workspace_agent_stats (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_workspace_agent_stats_agent_id_created_at
    ON workspace_agent_stats (agent_id, created_at DESC);
