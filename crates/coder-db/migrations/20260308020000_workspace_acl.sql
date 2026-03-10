-- Add workspace ACL columns (matches Go migration 000354_workspace_acl).
ALTER TABLE workspaces
    ADD COLUMN IF NOT EXISTS group_acl jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS user_acl  jsonb NOT NULL DEFAULT '{}'::jsonb;
