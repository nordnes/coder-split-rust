-- Migration: workspace proxy internal routes support
-- Adds columns needed by the CRUD store queries, plus replicas and crypto_keys tables.

-- Add missing columns to workspace_proxies for the CRUD store and registration flow.
ALTER TABLE workspace_proxies
    ADD COLUMN IF NOT EXISTS icon TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS url TEXT,
    ADD COLUMN IF NOT EXISTS token_hashed_secret BYTEA NOT NULL DEFAULT '\x',
    ADD COLUMN IF NOT EXISTS region_id INTEGER NOT NULL DEFAULT 0;

-- Replicas table: tracks proxy replica instances for DERP meshing and health.
CREATE TABLE IF NOT EXISTS replicas (
    id UUID PRIMARY KEY,
    proxy_id UUID NOT NULL REFERENCES workspace_proxies(id) ON DELETE CASCADE,
    hostname TEXT NOT NULL DEFAULT '',
    relay_address TEXT NOT NULL DEFAULT '',
    region_id INTEGER NOT NULL DEFAULT 0,
    version TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT '',
    database_latency INTEGER NOT NULL DEFAULT 0,
    primary_replica BOOLEAN NOT NULL DEFAULT FALSE,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    stopped_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_replicas_proxy_id ON replicas (proxy_id);

-- Crypto keys table: stores signing keys for workspace apps and related features.
CREATE TABLE IF NOT EXISTS crypto_keys (
    feature crypto_key_feature NOT NULL,
    sequence INTEGER NOT NULL,
    secret BYTEA NOT NULL,
    starts_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deletes_at TIMESTAMPTZ,
    PRIMARY KEY (feature, sequence)
);
