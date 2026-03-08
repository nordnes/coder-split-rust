CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY,
    request_id UUID,
    time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    resource_type TEXT NOT NULL,
    resource_id UUID,
    resource_target TEXT NOT NULL DEFAULT '',
    resource_icon TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    diff_json TEXT NOT NULL DEFAULT '{}'::TEXT,
    status_code INTEGER NOT NULL DEFAULT 0,
    additional_fields_json TEXT NOT NULL DEFAULT '{}'::TEXT,
    description TEXT NOT NULL DEFAULT '',
    resource_link TEXT NOT NULL DEFAULT '',
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_time
    ON audit_logs (time DESC);

CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id
    ON audit_logs (user_id);

CREATE INDEX IF NOT EXISTS idx_audit_logs_organization_id
    ON audit_logs (organization_id);

CREATE TABLE IF NOT EXISTS git_ssh_keys (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    public_key TEXT NOT NULL,
    private_key TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS external_auth_links (
    provider_id TEXT NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    access_token TEXT NOT NULL DEFAULT '',
    refresh_token TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    authenticated BOOLEAN NOT NULL DEFAULT TRUE,
    validate_error TEXT NOT NULL DEFAULT '',
    external_user_json TEXT NOT NULL DEFAULT 'null',
    installations_json TEXT NOT NULL DEFAULT '[]',
    app_installable BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (provider_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_external_auth_links_user_id
    ON external_auth_links (user_id);
