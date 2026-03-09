CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    hashed_secret BYTEA NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    last_used TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    login_type login_type NOT NULL,
    scopes TEXT[] NOT NULL DEFAULT ARRAY['all']::TEXT[],
    token_name TEXT NOT NULL DEFAULT '',
    lifetime_seconds BIGINT NOT NULL DEFAULT 86400,
    allow_list_json TEXT NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_api_keys_user_id
    ON api_keys (user_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_user_token_name_lower
    ON api_keys (user_id, LOWER(token_name))
    WHERE token_name <> '';
