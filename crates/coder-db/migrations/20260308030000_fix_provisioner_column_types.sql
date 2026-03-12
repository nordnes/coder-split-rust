-- Fix column type mismatches caused by migration ordering:
-- 20260308000003_workspace_domain.sql creates provisioner_job_logs and
-- provisioner_job_timings with TEXT columns, then
-- 20260308010000_provisioner_orchestration.sql tries CREATE TABLE IF NOT EXISTS
-- with enum columns, but that is a no-op since the tables already exist.
--
-- This migration ALTERs the affected columns to their correct enum types.
-- Defaults must be dropped before the ALTER TYPE (PostgreSQL cannot auto-cast
-- a text default to an enum) and re-added afterwards.

-- ============================================================
-- provisioner_job_logs: source TEXT -> log_source, level TEXT -> log_level
-- ============================================================
DO $$ BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'provisioner_job_logs' AND column_name = 'source'
          AND data_type = 'text'
    ) THEN
        ALTER TABLE provisioner_job_logs ALTER COLUMN source DROP DEFAULT;
        ALTER TABLE provisioner_job_logs ALTER COLUMN source TYPE log_source USING source::log_source;
        ALTER TABLE provisioner_job_logs ALTER COLUMN source SET DEFAULT 'provisioner'::log_source;

        ALTER TABLE provisioner_job_logs ALTER COLUMN level DROP DEFAULT;
        ALTER TABLE provisioner_job_logs ALTER COLUMN level TYPE log_level USING level::log_level;
        ALTER TABLE provisioner_job_logs ALTER COLUMN level SET DEFAULT 'info'::log_level;
    END IF;
END $$;

-- ============================================================
-- provisioner_job_timings: stage TEXT -> provisioner_job_timing_stage
-- ============================================================
DO $$ BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'provisioner_job_timings' AND column_name = 'stage'
          AND data_type = 'text'
    ) THEN
        ALTER TABLE provisioner_job_timings ALTER COLUMN stage DROP DEFAULT;
        ALTER TABLE provisioner_job_timings ALTER COLUMN stage TYPE provisioner_job_timing_stage USING stage::provisioner_job_timing_stage;
    END IF;
END $$;

-- ============================================================
-- provisioner_jobs: provisioner TEXT -> provisioner_type, type TEXT -> provisioner_job_type
-- ============================================================
DO $$ BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'provisioner_jobs' AND column_name = 'provisioner'
          AND data_type = 'text'
    ) THEN
        ALTER TABLE provisioner_jobs ALTER COLUMN provisioner DROP DEFAULT;
        ALTER TABLE provisioner_jobs ALTER COLUMN provisioner TYPE provisioner_type USING provisioner::provisioner_type;

        ALTER TABLE provisioner_jobs ALTER COLUMN "type" DROP DEFAULT;
        ALTER TABLE provisioner_jobs ALTER COLUMN "type" TYPE provisioner_job_type USING "type"::provisioner_job_type;
    END IF;
END $$;
