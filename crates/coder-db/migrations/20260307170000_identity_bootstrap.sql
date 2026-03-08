DO $$
BEGIN
    CREATE TYPE login_type AS ENUM (
        'password',
        'github',
        'oidc',
        'token',
        'none',
        'oauth2_provider_app'
    );
EXCEPTION
    WHEN duplicate_object THEN NULL;
END;
$$;

DO $$
BEGIN
    CREATE TYPE user_status AS ENUM (
        'active',
        'suspended',
        'dormant'
    );
EXCEPTION
    WHEN duplicate_object THEN NULL;
END;
$$;

CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    icon TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    deleted BOOLEAN NOT NULL DEFAULT FALSE,
    workspace_sharing_disabled BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_organization_name_lower
    ON organizations (LOWER(name))
    WHERE deleted = FALSE;

CREATE UNIQUE INDEX IF NOT EXISTS organizations_single_default_org
    ON organizations (is_default)
    WHERE is_default = TRUE;

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL,
    username TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL DEFAULT '',
    hashed_password BYTEA NOT NULL DEFAULT ''::BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rbac_roles TEXT[] NOT NULL DEFAULT '{}'::TEXT[],
    login_type login_type NOT NULL DEFAULT 'password',
    status user_status NOT NULL DEFAULT 'dormant',
    avatar_url TEXT NOT NULL DEFAULT '',
    deleted BOOLEAN NOT NULL DEFAULT FALSE,
    last_seen_at TIMESTAMPTZ,
    github_com_user_id BIGINT,
    is_system BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_lower
    ON users (LOWER(email))
    WHERE deleted = FALSE;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_lower
    ON users (LOWER(username))
    WHERE deleted = FALSE;

CREATE TABLE IF NOT EXISTS organization_members (
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    roles TEXT[] NOT NULL DEFAULT '{}'::TEXT[],
    PRIMARY KEY (organization_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_organization_member_user_id_uuid
    ON organization_members (user_id);

CREATE TABLE IF NOT EXISTS auth_sessions (
    token_hash BYTEA PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_user_id
    ON auth_sessions (user_id);
