-- Adds a native JSONB `diff` column to `audit_logs` for Go parity.
--
-- The legacy `diff_json` TEXT column is left in place so existing writers
-- (which stringify the diff) keep working; new writes populate both until
-- handler call sites are migrated in a follow-up wave.
--
-- Mirrors the Go schema from
-- `coder/coderd/database/migrations/000010_audit_logs.up.sql` where the
-- column is declared as `diff jsonb NOT NULL`.
ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS diff JSONB NOT NULL DEFAULT '{}'::jsonb;
