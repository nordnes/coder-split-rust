-- Fix column type mismatches caused by migration ordering:
-- 20260308000000_workspace_domain.sql creates provisioner_job_logs and
-- provisioner_job_timings with TEXT columns, then
-- 20260308010000_provisioner_orchestration.sql tries CREATE TABLE IF NOT EXISTS
-- with enum columns, but that is a no-op since the tables already exist.
--
-- This migration ALTERs the affected columns to their correct enum types.

-- ============================================================
-- provisioner_job_logs: source TEXT -> log_source, level TEXT -> log_level
-- ============================================================
ALTER TABLE provisioner_job_logs
    ALTER COLUMN source TYPE log_source USING source::log_source,
    ALTER COLUMN level TYPE log_level USING level::log_level;

-- ============================================================
-- provisioner_job_timings: stage TEXT -> provisioner_job_timing_stage
-- ============================================================
ALTER TABLE provisioner_job_timings
    ALTER COLUMN stage TYPE provisioner_job_timing_stage USING stage::provisioner_job_timing_stage;

-- ============================================================
-- provisioner_jobs: provisioner TEXT -> provisioner_type, type TEXT -> provisioner_job_type
-- These columns were added by workspace_domain.sql as TEXT before orchestration.sql
-- could add them with enum types (ADD COLUMN IF NOT EXISTS is a no-op for existing columns).
-- ============================================================
ALTER TABLE provisioner_jobs
    ALTER COLUMN provisioner TYPE provisioner_type USING provisioner::provisioner_type,
    ALTER COLUMN "type" TYPE provisioner_job_type USING "type"::provisioner_job_type;
