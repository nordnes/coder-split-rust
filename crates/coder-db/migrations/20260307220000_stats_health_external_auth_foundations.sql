ALTER TABLE workspace_agent_stats
    ADD COLUMN IF NOT EXISTS id UUID,
    ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE,
    ADD COLUMN IF NOT EXISTS template_id UUID,
    ADD COLUMN IF NOT EXISTS connections_by_proto JSONB NOT NULL DEFAULT '{}'::JSONB,
    ADD COLUMN IF NOT EXISTS connection_count BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS rx_packets BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS tx_packets BIGINT NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_workspace_agent_stats_workspace_id_created_at
    ON workspace_agent_stats (workspace_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_workspace_agent_stats_user_id_created_at
    ON workspace_agent_stats (user_id, created_at DESC);

ALTER TABLE external_auth_links
    ADD COLUMN IF NOT EXISTS token_type TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS scopes TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    ADD COLUMN IF NOT EXISTS refresh_error TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS last_validated_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_refreshed_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS workspace_proxies (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL DEFAULT '',
    icon_url TEXT NOT NULL DEFAULT '',
    path_app_url TEXT NOT NULL DEFAULT '',
    wildcard_hostname TEXT NOT NULL DEFAULT '',
    derp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    derp_only BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted BOOLEAN NOT NULL DEFAULT FALSE,
    version TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_workspace_proxies_deleted
    ON workspace_proxies (deleted);

CREATE TABLE IF NOT EXISTS provisioner_daemons (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ,
    name TEXT NOT NULL,
    version TEXT NOT NULL DEFAULT '',
    api_version TEXT NOT NULL DEFAULT '',
    provisioners TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    tags_json TEXT NOT NULL DEFAULT '{}'::TEXT,
    status TEXT
);

CREATE INDEX IF NOT EXISTS idx_provisioner_daemons_organization_id
    ON provisioner_daemons (organization_id);
