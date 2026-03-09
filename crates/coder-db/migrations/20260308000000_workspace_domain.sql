-- Expand workspaces table from stats stub to full domain schema.
-- We need a templates stub first since workspaces reference it.

CREATE TABLE IF NOT EXISTS templates (
    id UUID PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    organization_id UUID NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    display_name TEXT NOT NULL DEFAULT '',
    icon TEXT NOT NULL DEFAULT '',
    provisioner TEXT NOT NULL DEFAULT 'terraform',
    active_version_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    allow_user_cancel_workspace_jobs BOOLEAN NOT NULL DEFAULT FALSE,
    require_active_version BOOLEAN NOT NULL DEFAULT FALSE,
    use_classic_parameter_flow BOOLEAN NOT NULL DEFAULT FALSE,
    max_port_sharing_level TEXT NOT NULL DEFAULT 'owner',
    deleted BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_templates_organization_id ON templates (organization_id);

CREATE TABLE IF NOT EXISTS template_versions (
    id UUID PRIMARY KEY,
    template_id UUID REFERENCES templates(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    name TEXT NOT NULL DEFAULT '',
    organization_id UUID NOT NULL
);

-- Expand workspaces from stub to full schema.
-- The stub only had: id, created_at, updated_at, deleted.
-- We add all columns the Go schema uses.
ALTER TABLE workspaces
    ADD COLUMN IF NOT EXISTS owner_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    ADD COLUMN IF NOT EXISTS organization_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    ADD COLUMN IF NOT EXISTS template_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    ADD COLUMN IF NOT EXISTS name TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS autostart_schedule TEXT,
    ADD COLUMN IF NOT EXISTS ttl BIGINT,
    ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ADD COLUMN IF NOT EXISTS dormant_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS deleting_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS automatic_updates TEXT NOT NULL DEFAULT 'never',
    ADD COLUMN IF NOT EXISTS favorite BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS next_start_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_workspaces_owner_id ON workspaces (owner_id) WHERE deleted = false;
CREATE INDEX IF NOT EXISTS idx_workspaces_template_id ON workspaces (template_id) WHERE deleted = false;
CREATE INDEX IF NOT EXISTS idx_workspaces_organization_id ON workspaces (organization_id) WHERE deleted = false;

CREATE UNIQUE INDEX IF NOT EXISTS idx_workspaces_owner_name
    ON workspaces (owner_id, LOWER(name)) WHERE deleted = false;

-- Expand workspace_builds from stub to full schema.
-- Stub had: id, created_at, updated_at, workspace_id, build_number, transition, job_id.
ALTER TABLE workspace_builds
    ADD COLUMN IF NOT EXISTS template_version_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    ADD COLUMN IF NOT EXISTS initiator_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    ADD COLUMN IF NOT EXISTS provisioner_state BYTEA,
    ADD COLUMN IF NOT EXISTS deadline TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS max_deadline TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS reason TEXT NOT NULL DEFAULT 'initiator',
    ADD COLUMN IF NOT EXISTS daily_cost INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_workspace_builds_job_id ON workspace_builds (job_id);

-- Expand provisioner_jobs from stub.
ALTER TABLE provisioner_jobs
    ADD COLUMN IF NOT EXISTS organization_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    ADD COLUMN IF NOT EXISTS initiator_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    ADD COLUMN IF NOT EXISTS provisioner TEXT NOT NULL DEFAULT 'terraform',
    ADD COLUMN IF NOT EXISTS type TEXT NOT NULL DEFAULT 'workspace_build',
    ADD COLUMN IF NOT EXISTS input JSONB NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS worker_id UUID,
    ADD COLUMN IF NOT EXISTS tags JSONB NOT NULL DEFAULT '{}';

-- Workspace build parameters table.
CREATE TABLE IF NOT EXISTS workspace_build_parameters (
    workspace_build_id UUID NOT NULL REFERENCES workspace_builds(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (workspace_build_id, name)
);

-- Workspace agent port sharing table.
CREATE TABLE IF NOT EXISTS workspace_agent_port_shares (
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    agent_name TEXT NOT NULL,
    port INTEGER NOT NULL,
    share_level TEXT NOT NULL DEFAULT 'owner',
    protocol TEXT NOT NULL DEFAULT 'http',
    PRIMARY KEY (workspace_id, agent_name, port)
);

-- Provisioner job logs table (for streaming build logs).
CREATE TABLE IF NOT EXISTS provisioner_job_logs (
    id BIGSERIAL PRIMARY KEY,
    job_id UUID NOT NULL REFERENCES provisioner_jobs(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source TEXT NOT NULL DEFAULT '',
    level TEXT NOT NULL DEFAULT 'info',
    stage TEXT NOT NULL DEFAULT '',
    output TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_provisioner_job_logs_job_id
    ON provisioner_job_logs (job_id, id);

-- Workspace resources table.
CREATE TABLE IF NOT EXISTS workspace_resources (
    id UUID PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    job_id UUID NOT NULL REFERENCES provisioner_jobs(id) ON DELETE CASCADE,
    transition TEXT NOT NULL DEFAULT 'start',
    type TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL DEFAULT '',
    hide BOOLEAN NOT NULL DEFAULT FALSE,
    icon TEXT NOT NULL DEFAULT '',
    daily_cost INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_workspace_resources_job_id ON workspace_resources (job_id);

-- Provisioner job timings table.
CREATE TABLE IF NOT EXISTS provisioner_job_timings (
    job_id UUID NOT NULL REFERENCES provisioner_jobs(id) ON DELETE CASCADE,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    stage TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL DEFAULT '',
    resource TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_provisioner_job_timings_job_id ON provisioner_job_timings (job_id);
