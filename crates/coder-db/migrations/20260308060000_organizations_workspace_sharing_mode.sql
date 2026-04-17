-- Add a textual workspace_sharing_mode column to organizations so we can
-- persist the full `shareable_workspace_owners` enum (`none`, `everyone`,
-- `service_accounts`) instead of collapsing it onto the existing
-- `workspace_sharing_disabled` boolean.
--
-- The boolean column is retained for now (it still drives the public
-- `sharing_disabled` field on the GET/PATCH responses and keeps existing
-- reads working); dropping it is left to a follow-up cleanup PR once all
-- readers consume the new column.

ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS workspace_sharing_mode TEXT NOT NULL DEFAULT 'everyone';

-- Backfill: any row currently marked disabled maps to `'none'`, everything
-- else becomes `'everyone'`. New rows default to `'everyone'` to match the
-- existing `workspace_sharing_disabled = FALSE` default.
UPDATE organizations
SET workspace_sharing_mode = CASE
    WHEN workspace_sharing_disabled THEN 'none'
    ELSE 'everyone'
END
WHERE workspace_sharing_mode = 'everyone'
  AND workspace_sharing_disabled = TRUE;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'organizations_workspace_sharing_mode_check'
    ) THEN
        ALTER TABLE organizations
            ADD CONSTRAINT organizations_workspace_sharing_mode_check
            CHECK (workspace_sharing_mode IN ('none', 'everyone', 'service_accounts'));
    END IF;
END$$;
