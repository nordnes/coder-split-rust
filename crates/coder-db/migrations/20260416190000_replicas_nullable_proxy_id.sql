-- Migration: allow replicas.proxy_id to be NULL.
--
-- The `replicas` table was originally introduced to track workspace-proxy
-- sibling instances for DERP meshing.  The main `coderd` server also needs
-- to register itself in this table (matching the Go schema, which has no
-- proxy_id column at all) so that the enterprise `/replicas` route can
-- return all active primary replicas of the deployment.
--
-- Making proxy_id nullable preserves the existing workspace-proxy queries
-- (which filter by a specific proxy_id) while allowing main coderd
-- replicas to be stored as rows with proxy_id IS NULL.

ALTER TABLE replicas ALTER COLUMN proxy_id DROP NOT NULL;

-- Speeds up the enterprise /replicas handler which lists all non-proxy
-- replicas that are still alive (stopped_at IS NULL, proxy_id IS NULL).
CREATE INDEX IF NOT EXISTS idx_replicas_coderd_alive
    ON replicas (updated_at)
    WHERE proxy_id IS NULL AND stopped_at IS NULL;
