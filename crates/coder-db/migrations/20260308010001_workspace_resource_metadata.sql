-- Workspace resource metadata table.
CREATE TABLE IF NOT EXISTS workspace_resource_metadata (
    workspace_resource_id UUID NOT NULL REFERENCES workspace_resources(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    value TEXT NOT NULL DEFAULT '',
    sensitive BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (workspace_resource_id, key)
);

CREATE INDEX IF NOT EXISTS idx_workspace_resource_metadata_resource_id
    ON workspace_resource_metadata (workspace_resource_id);
