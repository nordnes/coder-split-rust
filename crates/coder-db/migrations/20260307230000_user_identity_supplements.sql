-- User identity supplements: links, configs, soft-delete tracking,
-- status changes, secrets, custom roles, groups and group members.

-- user_links: OAuth/OIDC identity provider links
CREATE TABLE IF NOT EXISTS user_links (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    login_type login_type NOT NULL,
    linked_id TEXT NOT NULL DEFAULT '',
    oauth_access_token TEXT NOT NULL DEFAULT '',
    oauth_refresh_token TEXT NOT NULL DEFAULT '',
    oauth_access_token_key_id TEXT,
    oauth_refresh_token_key_id TEXT,
    oauth_expiry TIMESTAMPTZ NOT NULL DEFAULT '0001-01-01 00:00:00+00',
    debug_context JSONB NOT NULL DEFAULT '{}'::JSONB,
    claims JSONB NOT NULL DEFAULT '{}'::JSONB,
    PRIMARY KEY (user_id, login_type)
);

CREATE INDEX IF NOT EXISTS idx_user_links_linked_id
    ON user_links (linked_id)
    WHERE linked_id != '';

-- user_configs: per-user key-value configuration
CREATE TABLE IF NOT EXISTS user_configs (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    value TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (user_id, key)
);

-- user_deleted: soft-delete tracking records
CREATE TABLE IF NOT EXISTS user_deleted (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    deleted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_by UUID REFERENCES users(id) ON DELETE SET NULL,
    reason TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_user_deleted_user_id
    ON user_deleted (user_id);

-- user_status_changes: audit trail of status transitions
CREATE TABLE IF NOT EXISTS user_status_changes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    new_status user_status NOT NULL,
    old_status user_status NOT NULL,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    changed_by UUID REFERENCES users(id) ON DELETE SET NULL,
    reason TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_user_status_changes_user_id
    ON user_status_changes (user_id);

-- custom_roles: user-defined RBAC roles
-- organization_id is nullable (NULL = site-scoped role), so we use a
-- UNIQUE constraint instead of PRIMARY KEY to allow NULLs.
CREATE TABLE IF NOT EXISTS custom_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    site_permissions JSONB NOT NULL DEFAULT '[]'::JSONB,
    org_permissions JSONB NOT NULL DEFAULT '[]'::JSONB,
    user_permissions JSONB NOT NULL DEFAULT '[]'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (name, organization_id)
);

-- groups: user groups for template ACLs and RBAC
CREATE TABLE IF NOT EXISTS groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    avatar_url TEXT NOT NULL DEFAULT '',
    quota_allowance INT NOT NULL DEFAULT 0,
    source TEXT NOT NULL DEFAULT 'user',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_name_org
    ON groups (organization_id, LOWER(name));

-- group_members: group membership
CREATE TABLE IF NOT EXISTS group_members (
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_group_members_user_id
    ON group_members (user_id);
