-- Adds the columns and view that the prebuild reconciler SQL queries
-- (`GetTemplatePresetsWithPrebuilds`, `GetRunningPrebuiltWorkspaces`)
-- require. Ported from Go:
--   coder/coderd/database/migrations/000314_prebuilds.up.sql
-- plus the preset-id column on workspace_builds from earlier Go migrations.

-- Preset linkage on workspace_builds. The reconciler needs this to
-- identify which preset spawned a given build.
ALTER TABLE workspace_builds
    ADD COLUMN IF NOT EXISTS template_version_preset_id UUID
        REFERENCES template_version_presets(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_workspace_builds_template_version_preset_id
    ON workspace_builds (template_version_preset_id)
    WHERE template_version_preset_id IS NOT NULL;

-- workspace_latest_builds view: the latest build per workspace plus the
-- computed job_status. Mirrors Go's view.
DROP VIEW IF EXISTS workspace_latest_builds;
CREATE VIEW workspace_latest_builds AS
SELECT DISTINCT ON (workspace_id)
    wb.id,
    wb.workspace_id,
    wb.template_version_id,
    wb.job_id,
    wb.template_version_preset_id,
    wb.transition,
    wb.created_at,
    pj.job_status
FROM workspace_builds wb
    INNER JOIN provisioner_jobs pj ON wb.job_id = pj.id
ORDER BY wb.workspace_id, wb.build_number DESC;
