-- Tasks & Chats domain tables and enums

-- Task status enum
DO $$ BEGIN
    CREATE TYPE task_status AS ENUM (
        'pending',
        'initializing',
        'active',
        'paused',
        'unknown',
        'error'
    );
EXCEPTION WHEN duplicate_object THEN NULL;
END; $$;

-- Tasks table
CREATE TABLE tasks (
    id              UUID        NOT NULL PRIMARY KEY,
    organization_id UUID        NOT NULL,
    owner_id        UUID        NOT NULL,
    name            TEXT        NOT NULL,
    workspace_id    UUID,
    template_version_id UUID    NOT NULL,
    template_parameters JSONB   NOT NULL DEFAULT '{}'::jsonb,
    prompt          TEXT        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL,
    deleted_at      TIMESTAMPTZ,
    display_name    VARCHAR(127) NOT NULL DEFAULT ''
);

COMMENT ON COLUMN tasks.display_name IS 'Display name is a custom, human-friendly task name.';

-- Task snapshots table
CREATE TABLE task_snapshots (
    task_id                 UUID        NOT NULL PRIMARY KEY REFERENCES tasks(id),
    log_snapshot            JSONB       NOT NULL,
    log_snapshot_created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE task_snapshots IS 'Stores snapshots of task state when paused, currently limited to conversation history.';
COMMENT ON COLUMN task_snapshots.task_id IS 'The task this snapshot belongs to.';
COMMENT ON COLUMN task_snapshots.log_snapshot IS 'Task conversation history in JSON format, allowing users to view logs when the workspace is stopped.';
COMMENT ON COLUMN task_snapshots.log_snapshot_created_at IS 'When this log snapshot was captured.';

-- Task workspace apps table
CREATE TABLE task_workspace_apps (
    task_id                 UUID    NOT NULL REFERENCES tasks(id),
    workspace_agent_id      UUID,
    workspace_app_id        UUID,
    workspace_build_number  INTEGER NOT NULL,
    PRIMARY KEY (task_id, workspace_build_number)
);

-- Chat enums
DO $$ BEGIN
    CREATE TYPE chat_message_visibility AS ENUM (
        'user',
        'model',
        'both'
    );
EXCEPTION WHEN duplicate_object THEN NULL;
END; $$;

DO $$ BEGIN
    CREATE TYPE chat_status AS ENUM (
        'waiting',
        'pending',
        'running',
        'paused',
        'completed',
        'error'
    );
EXCEPTION WHEN duplicate_object THEN NULL;
END; $$;

-- Chats table
CREATE TABLE chats (
    id                  UUID        DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    owner_id            UUID        NOT NULL,
    workspace_id        UUID,
    title               TEXT        NOT NULL DEFAULT 'New Chat',
    status              chat_status NOT NULL DEFAULT 'waiting',
    worker_id           UUID,
    started_at          TIMESTAMPTZ,
    heartbeat_at        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    parent_chat_id      UUID,
    root_chat_id        UUID,
    last_model_config_id UUID      NOT NULL,
    archived            BOOLEAN     NOT NULL DEFAULT false,
    last_error          TEXT
);

-- Chat messages table
CREATE TABLE chat_messages (
    id              BIGSERIAL   NOT NULL PRIMARY KEY,
    chat_id         UUID        NOT NULL REFERENCES chats(id),
    model_config_id UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    role            TEXT        NOT NULL,
    content         JSONB,
    visibility      chat_message_visibility NOT NULL DEFAULT 'both',
    input_tokens    BIGINT,
    output_tokens   BIGINT,
    total_tokens    BIGINT,
    reasoning_tokens BIGINT,
    cache_creation_tokens BIGINT,
    cache_read_tokens BIGINT,
    context_limit   BIGINT,
    compressed      BOOLEAN     NOT NULL DEFAULT false
);

-- Chat files table
CREATE TABLE chat_files (
    id              UUID        DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    owner_id        UUID        NOT NULL,
    organization_id UUID        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    name            TEXT        NOT NULL DEFAULT '',
    mimetype        TEXT        NOT NULL,
    data            BYTEA       NOT NULL
);

-- Chat model configs table
CREATE TABLE chat_model_configs (
    id                      UUID        DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    provider                TEXT        NOT NULL,
    model                   TEXT        NOT NULL,
    display_name            TEXT        NOT NULL DEFAULT '',
    created_by              UUID,
    updated_by              UUID,
    enabled                 BOOLEAN     NOT NULL DEFAULT true,
    is_default              BOOLEAN     NOT NULL DEFAULT false,
    deleted                 BOOLEAN     NOT NULL DEFAULT false,
    deleted_at              TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    context_limit           BIGINT      NOT NULL,
    compression_threshold   INTEGER     NOT NULL,
    options                 JSONB       NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT chat_model_configs_compression_threshold_check CHECK (compression_threshold >= 0 AND compression_threshold <= 100),
    CONSTRAINT chat_model_configs_context_limit_check CHECK (context_limit > 0)
);

-- Chat providers table
CREATE TABLE chat_providers (
    id              UUID        DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    provider        TEXT        NOT NULL,
    display_name    TEXT        NOT NULL DEFAULT '',
    api_key         TEXT        NOT NULL DEFAULT '',
    api_key_key_id  TEXT,
    created_by      UUID,
    enabled         BOOLEAN     NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    base_url        TEXT        NOT NULL DEFAULT '',
    CONSTRAINT chat_providers_provider_check CHECK (provider = ANY (ARRAY['anthropic','azure','bedrock','google','openai','openai-compat','openrouter','vercel']))
);

COMMENT ON COLUMN chat_providers.api_key_key_id IS 'The ID of the key used to encrypt the provider API key. If this is NULL, the API key is not encrypted';

-- Chat queued messages table
CREATE TABLE chat_queued_messages (
    id          BIGSERIAL   NOT NULL PRIMARY KEY,
    chat_id     UUID        NOT NULL REFERENCES chats(id),
    content     JSONB       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Chat diff statuses table
CREATE TABLE chat_diff_statuses (
    chat_id             UUID        NOT NULL PRIMARY KEY REFERENCES chats(id),
    url                 TEXT,
    pull_request_state  TEXT,
    changes_requested   BOOLEAN     NOT NULL DEFAULT false,
    additions           INTEGER     NOT NULL DEFAULT 0,
    deletions           INTEGER     NOT NULL DEFAULT 0,
    changed_files       INTEGER     NOT NULL DEFAULT 0,
    refreshed_at        TIMESTAMPTZ,
    stale_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    git_branch          TEXT        NOT NULL DEFAULT '',
    git_remote_origin   TEXT        NOT NULL DEFAULT ''
);
