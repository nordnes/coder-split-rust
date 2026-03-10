-- OAuth2 provider tables: apps, secrets, authorization codes, tokens.

-- oauth2_provider_apps: registered OAuth2 applications
CREATE TABLE IF NOT EXISTS oauth2_provider_apps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    name TEXT NOT NULL,
    icon TEXT NOT NULL DEFAULT '',
    callback_url TEXT NOT NULL,
    redirect_uris TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    created_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_oauth2_provider_apps_name
    ON oauth2_provider_apps (LOWER(name));

-- oauth2_provider_app_secrets: client secrets for OAuth2 apps
CREATE TABLE IF NOT EXISTS oauth2_provider_app_secrets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    hashed_secret BYTEA NOT NULL,
    display_secret TEXT NOT NULL DEFAULT '',
    app_id UUID NOT NULL REFERENCES oauth2_provider_apps(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_oauth2_provider_app_secrets_app_id
    ON oauth2_provider_app_secrets (app_id);

-- oauth2_provider_app_codes: authorization codes
CREATE TABLE IF NOT EXISTS oauth2_provider_app_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    secret_prefix BYTEA NOT NULL,
    hashed_secret BYTEA NOT NULL,
    app_id UUID NOT NULL REFERENCES oauth2_provider_apps(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    resource_uri TEXT NOT NULL DEFAULT '',
    code_challenge TEXT NOT NULL DEFAULT '',
    code_challenge_method TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_oauth2_provider_app_codes_app_id
    ON oauth2_provider_app_codes (app_id);

CREATE INDEX IF NOT EXISTS idx_oauth2_provider_app_codes_secret_prefix
    ON oauth2_provider_app_codes (secret_prefix);

CREATE INDEX IF NOT EXISTS idx_oauth2_provider_app_codes_user_id
    ON oauth2_provider_app_codes (user_id);

-- oauth2_provider_app_tokens: access and refresh tokens
CREATE TABLE IF NOT EXISTS oauth2_provider_app_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    hash_prefix BYTEA NOT NULL,
    refresh_hash BYTEA NOT NULL,
    app_secret_id UUID NOT NULL REFERENCES oauth2_provider_app_secrets(id) ON DELETE CASCADE,
    api_key_id TEXT NOT NULL,
    audience TEXT NOT NULL DEFAULT '',
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_oauth2_provider_app_tokens_app_secret_id
    ON oauth2_provider_app_tokens (app_secret_id);

CREATE INDEX IF NOT EXISTS idx_oauth2_provider_app_tokens_api_key_id
    ON oauth2_provider_app_tokens (api_key_id);
