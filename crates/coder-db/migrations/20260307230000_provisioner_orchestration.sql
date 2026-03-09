-- Provisioner daemon orchestration: full job lifecycle, logs, timings, keys.

-- ============================================================
-- Enums
-- ============================================================
DO $$ BEGIN
    CREATE TYPE provisioner_type AS ENUM ('terraform', 'echo');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE provisioner_storage_method AS ENUM ('file');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE provisioner_job_type AS ENUM (
        'template_version_import',
        'template_version_dry_run',
        'workspace_build'
    );
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE provisioner_job_status AS ENUM (
        'pending',
        'running',
        'succeeded',
        'failed',
        'canceling',
        'canceled',
        'unknown'
    );
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE log_source AS ENUM ('provisioner_daemon', 'provisioner');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE log_level AS ENUM ('trace', 'debug', 'info', 'warn', 'error');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE provisioner_job_timing_stage AS ENUM (
        'init',
        'plan',
        'graph',
        'apply'
    );
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- ============================================================
-- Expand provisioner_jobs from stub to full schema
-- ============================================================
ALTER TABLE provisioner_jobs
    ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    ADD COLUMN IF NOT EXISTS initiator_id UUID REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS provisioner provisioner_type NOT NULL DEFAULT 'terraform',
    ADD COLUMN IF NOT EXISTS storage_method provisioner_storage_method NOT NULL DEFAULT 'file',
    ADD COLUMN IF NOT EXISTS file_id UUID,
    ADD COLUMN IF NOT EXISTS "type" provisioner_job_type NOT NULL DEFAULT 'template_version_import',
    ADD COLUMN IF NOT EXISTS "input" JSONB NOT NULL DEFAULT '{}'::JSONB,
    ADD COLUMN IF NOT EXISTS tags JSONB NOT NULL DEFAULT '{}'::JSONB,
    ADD COLUMN IF NOT EXISTS trace_metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
    ADD COLUMN IF NOT EXISTS worker_id UUID,
    ADD COLUMN IF NOT EXISTS error_code TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS logs_overflowed BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS logs_length INTEGER NOT NULL DEFAULT 0;

-- Computed job_status column for convenient querying.
-- This mirrors the Go implementation's computed status logic.
ALTER TABLE provisioner_jobs
    ADD COLUMN IF NOT EXISTS job_status provisioner_job_status
        GENERATED ALWAYS AS (
            CASE
                WHEN completed_at IS NOT NULL AND canceled_at IS NOT NULL AND error <> '' THEN 'canceled'::provisioner_job_status
                WHEN completed_at IS NOT NULL AND canceled_at IS NOT NULL THEN 'canceled'::provisioner_job_status
                WHEN completed_at IS NOT NULL AND error <> '' THEN 'failed'::provisioner_job_status
                WHEN completed_at IS NOT NULL THEN 'succeeded'::provisioner_job_status
                WHEN canceled_at IS NOT NULL THEN 'canceling'::provisioner_job_status
                WHEN started_at IS NOT NULL THEN 'running'::provisioner_job_status
                ELSE 'pending'::provisioner_job_status
            END
        ) STORED;

CREATE INDEX IF NOT EXISTS idx_provisioner_jobs_status
    ON provisioner_jobs (job_status);

CREATE INDEX IF NOT EXISTS idx_provisioner_jobs_organization_id
    ON provisioner_jobs (organization_id);

CREATE INDEX IF NOT EXISTS idx_provisioner_jobs_started_completed
    ON provisioner_jobs (started_at, completed_at)
    WHERE started_at IS NULL AND completed_at IS NULL;

-- ============================================================
-- provisioner_job_logs
-- ============================================================
CREATE TABLE IF NOT EXISTS provisioner_job_logs (
    id BIGSERIAL PRIMARY KEY,
    job_id UUID NOT NULL REFERENCES provisioner_jobs(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source log_source NOT NULL DEFAULT 'provisioner_daemon',
    level log_level NOT NULL DEFAULT 'info',
    stage VARCHAR(128) NOT NULL DEFAULT '',
    output VARCHAR(1024) NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_provisioner_job_logs_job_id
    ON provisioner_job_logs (job_id, id ASC);

-- ============================================================
-- provisioner_job_timings
-- ============================================================
CREATE TABLE IF NOT EXISTS provisioner_job_timings (
    job_id UUID NOT NULL REFERENCES provisioner_jobs(id) ON DELETE CASCADE,
    started_at TIMESTAMPTZ NOT NULL,
    ended_at TIMESTAMPTZ NOT NULL,
    stage provisioner_job_timing_stage NOT NULL,
    source TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL DEFAULT '',
    resource TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_provisioner_job_timings_job_id
    ON provisioner_job_timings (job_id);

-- ============================================================
-- provisioner_keys
-- ============================================================
CREATE TABLE IF NOT EXISTS provisioner_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    hashed_secret BYTEA NOT NULL,
    tags JSONB NOT NULL DEFAULT '{}'::JSONB,
    UNIQUE (organization_id, name)
);

CREATE INDEX IF NOT EXISTS idx_provisioner_keys_organization_id
    ON provisioner_keys (organization_id);

-- ============================================================
-- Expand provisioner_daemons with key_id reference
-- ============================================================
ALTER TABLE provisioner_daemons
    ADD COLUMN IF NOT EXISTS key_id UUID REFERENCES provisioner_keys(id) ON DELETE SET NULL;

-- Add default for id so INSERT without explicit id works (upsert_provisioner_daemon).
ALTER TABLE provisioner_daemons ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- Required for ON CONFLICT (organization_id, name) in upsert_provisioner_daemon.
CREATE UNIQUE INDEX IF NOT EXISTS idx_provisioner_daemons_org_name
    ON provisioner_daemons (organization_id, name);
