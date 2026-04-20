-- Adds the `is_idp_controlled` flag to `organization_members` so that
-- `sync_organizations` (OIDC login) can safely distinguish memberships
-- created by the IDP claim from those that were assigned manually.
--
-- Existing rows default to FALSE (i.e. treated as manually-assigned),
-- which preserves today's behaviour for every member that existed
-- before this migration.

ALTER TABLE organization_members
    ADD COLUMN IF NOT EXISTS is_idp_controlled BOOLEAN NOT NULL DEFAULT FALSE;
