-- Templates & Template Versions domain migration
-- Ported from Go coder/coderd/database/dump.sql

-- Required enum types (created IF NOT EXISTS for safety)
DO $$ BEGIN
    CREATE TYPE provisioner_type AS ENUM ('echo', 'terraform');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE parameter_form_type AS ENUM (
        '', 'error', 'radio', 'dropdown', 'input', 'textarea',
        'slider', 'checkbox', 'switch', 'tag-select', 'multi-select'
    );
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE app_sharing_level AS ENUM (
        'owner', 'authenticated', 'organization', 'public'
    );
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE cors_behavior AS ENUM ('simple', 'passthru');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE prebuild_status AS ENUM (
        'healthy', 'hard_limited', 'validation_failed'
    );
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE provisioner_job_status AS ENUM (
        'pending', 'running', 'succeeded', 'canceling', 'canceled', 'failed'
    );
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- provisioner_jobs table (needed for template version foreign keys)
CREATE TABLE IF NOT EXISTS provisioner_jobs (
    id              uuid PRIMARY KEY,
    created_at      timestamptz NOT NULL,
    updated_at      timestamptz NOT NULL,
    started_at      timestamptz,
    canceled_at     timestamptz,
    completed_at    timestamptz,
    error           text NOT NULL DEFAULT '',
    organization_id uuid NOT NULL,
    initiator_id    uuid NOT NULL,
    provisioner     provisioner_type NOT NULL DEFAULT 'terraform',
    job_status      provisioner_job_status NOT NULL DEFAULT 'pending',
    file_id         uuid,
    type            text NOT NULL DEFAULT 'template_version_import',
    input           jsonb NOT NULL DEFAULT '{}'::jsonb,
    worker_id       uuid,
    tags            jsonb NOT NULL DEFAULT '{}'::jsonb,
    trace_metadata  jsonb NOT NULL DEFAULT '{}'::jsonb
);

-- templates table
CREATE TABLE IF NOT EXISTS templates (
    id                              uuid PRIMARY KEY,
    created_at                      timestamptz NOT NULL,
    updated_at                      timestamptz NOT NULL,
    organization_id                 uuid NOT NULL,
    deleted                         boolean NOT NULL DEFAULT false,
    name                            varchar(64) NOT NULL,
    provisioner                     provisioner_type NOT NULL,
    active_version_id               uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    description                     varchar(128) NOT NULL DEFAULT '',
    default_ttl                     bigint NOT NULL DEFAULT 604800000000000,
    created_by                      uuid NOT NULL,
    icon                            varchar(256) NOT NULL DEFAULT '',
    user_acl                        jsonb NOT NULL DEFAULT '{}'::jsonb,
    group_acl                       jsonb NOT NULL DEFAULT '{}'::jsonb,
    display_name                    varchar(64) NOT NULL DEFAULT '',
    allow_user_cancel_workspace_jobs boolean NOT NULL DEFAULT true,
    allow_user_autostart            boolean NOT NULL DEFAULT true,
    allow_user_autostop             boolean NOT NULL DEFAULT true,
    failure_ttl                     bigint NOT NULL DEFAULT 0,
    time_til_dormant                bigint NOT NULL DEFAULT 0,
    time_til_dormant_autodelete     bigint NOT NULL DEFAULT 0,
    autostop_requirement_days_of_week smallint NOT NULL DEFAULT 0,
    autostop_requirement_weeks      bigint NOT NULL DEFAULT 0,
    autostart_block_days_of_week    smallint NOT NULL DEFAULT 0,
    require_active_version          boolean NOT NULL DEFAULT false,
    deprecated                      text NOT NULL DEFAULT '',
    activity_bump                   bigint NOT NULL DEFAULT 3600000000000,
    max_port_sharing_level          app_sharing_level NOT NULL DEFAULT 'owner',
    use_classic_parameter_flow      boolean NOT NULL DEFAULT false,
    cors_behavior                   cors_behavior NOT NULL DEFAULT 'simple',
    disable_module_cache            boolean NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS idx_templates_org_name
    ON templates (organization_id, LOWER(name))
    WHERE deleted = false;

-- template_versions table
CREATE TABLE IF NOT EXISTS template_versions (
    id                      uuid PRIMARY KEY,
    template_id             uuid,
    organization_id         uuid NOT NULL,
    created_at              timestamptz NOT NULL,
    updated_at              timestamptz NOT NULL,
    name                    varchar(64) NOT NULL,
    readme                  varchar(1048576) NOT NULL DEFAULT '',
    job_id                  uuid NOT NULL,
    created_by              uuid NOT NULL,
    external_auth_providers jsonb NOT NULL DEFAULT '[]'::jsonb,
    message                 varchar(1048576) NOT NULL DEFAULT '',
    archived                boolean NOT NULL DEFAULT false,
    source_example_id       text,
    has_ai_task             boolean,
    has_external_agent      boolean
);

CREATE INDEX IF NOT EXISTS idx_template_versions_template_id
    ON template_versions (template_id)
    WHERE template_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_template_versions_name
    ON template_versions (template_id, name);

-- template_version_parameters table
CREATE TABLE IF NOT EXISTS template_version_parameters (
    template_version_id uuid NOT NULL REFERENCES template_versions(id) ON DELETE CASCADE,
    name                text NOT NULL,
    description         text NOT NULL DEFAULT '',
    type                text NOT NULL DEFAULT 'string',
    mutable             boolean NOT NULL DEFAULT false,
    default_value       text NOT NULL DEFAULT '',
    icon                text NOT NULL DEFAULT '',
    options             jsonb NOT NULL DEFAULT '[]'::jsonb,
    validation_regex    text NOT NULL DEFAULT '',
    validation_min      integer,
    validation_max      integer,
    validation_error    text NOT NULL DEFAULT '',
    validation_monotonic text NOT NULL DEFAULT '',
    required            boolean NOT NULL DEFAULT true,
    display_name        text NOT NULL DEFAULT '',
    display_order       integer NOT NULL DEFAULT 0,
    ephemeral           boolean NOT NULL DEFAULT false,
    form_type           parameter_form_type NOT NULL DEFAULT '',
    PRIMARY KEY (template_version_id, name),
    CONSTRAINT validation_monotonic_order CHECK (
        validation_monotonic = ANY (ARRAY['increasing', 'decreasing', ''])
    )
);

-- template_version_variables table
CREATE TABLE IF NOT EXISTS template_version_variables (
    template_version_id uuid NOT NULL REFERENCES template_versions(id) ON DELETE CASCADE,
    name                text NOT NULL,
    description         text NOT NULL DEFAULT '',
    type                text NOT NULL DEFAULT 'string',
    value               text NOT NULL DEFAULT '',
    default_value       text NOT NULL DEFAULT '',
    required            boolean NOT NULL DEFAULT false,
    sensitive           boolean NOT NULL DEFAULT false,
    PRIMARY KEY (template_version_id, name)
);

-- template_version_presets table
CREATE TABLE IF NOT EXISTS template_version_presets (
    id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    template_version_id     uuid NOT NULL REFERENCES template_versions(id) ON DELETE CASCADE,
    name                    text NOT NULL,
    created_at              timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    desired_instances       integer,
    invalidate_after_secs   integer DEFAULT 0,
    prebuild_status         prebuild_status NOT NULL DEFAULT 'healthy',
    scheduling_timezone     text NOT NULL DEFAULT '',
    is_default              boolean NOT NULL DEFAULT false,
    description             varchar(128) NOT NULL DEFAULT '',
    icon                    varchar(256) NOT NULL DEFAULT '',
    last_invalidated_at     timestamptz
);

-- template_version_preset_parameters table
CREATE TABLE IF NOT EXISTS template_version_preset_parameters (
    id                          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    template_version_preset_id  uuid NOT NULL REFERENCES template_version_presets(id) ON DELETE CASCADE,
    name                        text NOT NULL,
    value                       text NOT NULL
);

-- template_version_preset_prebuild_schedules table
CREATE TABLE IF NOT EXISTS template_version_preset_prebuild_schedules (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    preset_id           uuid NOT NULL REFERENCES template_version_presets(id) ON DELETE CASCADE,
    cron_expression     text NOT NULL,
    desired_instances   integer NOT NULL
);

-- template_version_terraform_values table
CREATE TABLE IF NOT EXISTS template_version_terraform_values (
    template_version_id uuid PRIMARY KEY REFERENCES template_versions(id) ON DELETE CASCADE,
    updated_at          timestamptz NOT NULL DEFAULT now(),
    cached_plan         jsonb NOT NULL,
    cached_module_files uuid,
    provisionerd_version text NOT NULL DEFAULT ''
);

-- template_version_workspace_tags table
CREATE TABLE IF NOT EXISTS template_version_workspace_tags (
    template_version_id uuid NOT NULL REFERENCES template_versions(id) ON DELETE CASCADE,
    key                 text NOT NULL,
    value               text NOT NULL,
    PRIMARY KEY (template_version_id, key)
);

-- template_usage_stats table
CREATE TABLE IF NOT EXISTS template_usage_stats (
    start_time              timestamptz NOT NULL,
    end_time                timestamptz NOT NULL,
    template_id             uuid NOT NULL,
    user_id                 uuid NOT NULL,
    median_latency_ms       real,
    usage_mins              smallint NOT NULL,
    ssh_mins                smallint NOT NULL,
    sftp_mins               smallint NOT NULL,
    reconnecting_pty_mins   smallint NOT NULL,
    vscode_mins             smallint NOT NULL,
    jetbrains_mins          smallint NOT NULL,
    app_usage_mins          jsonb,
    PRIMARY KEY (start_time, template_id, user_id)
);

-- Helpful view matching Go's template_with_names
CREATE OR REPLACE VIEW template_with_names AS
SELECT
    t.*,
    COALESCE(o.name, '') AS organization_name,
    COALESCE(o.display_name, '') AS organization_display_name,
    COALESCE(o.icon, '') AS organization_icon,
    COALESCE(u.username, '') AS created_by_username,
    COALESCE(u.avatar_url, '') AS created_by_avatar_url,
    COALESCE(u.name, '') AS created_by_name
FROM templates t
LEFT JOIN organizations o ON t.organization_id = o.id
LEFT JOIN users u ON t.created_by = u.id;

-- Helpful view matching Go's template_version_with_user
CREATE OR REPLACE VIEW template_version_with_user AS
SELECT
    tv.*,
    COALESCE(u.avatar_url, '') AS created_by_avatar_url,
    COALESCE(u.username, '') AS created_by_username,
    COALESCE(u.name, '') AS created_by_name
FROM template_versions tv
LEFT JOIN users u ON tv.created_by = u.id;
