-- Workspace agent infrastructure tables.

-- Enum: workspace agent lifecycle state
CREATE TYPE workspace_agent_lifecycle_state AS ENUM (
    'created',
    'starting',
    'start_timeout',
    'start_error',
    'ready',
    'shutting_down',
    'shutdown_timeout',
    'shutdown_error',
    'off'
);

-- Enum: workspace agent subsystem
CREATE TYPE workspace_agent_subsystem AS ENUM (
    'envbuilder',
    'envbox',
    'none',
    'exectrace'
);

-- Enum: display app
CREATE TYPE display_app AS ENUM (
    'vscode',
    'vscode_insiders',
    'web_terminal',
    'ssh_helper',
    'port_forwarding_helper'
);

-- Enum: agent key scope
CREATE TYPE agent_key_scope_enum AS ENUM (
    'all',
    'no_user_data'
);

-- Enum: app sharing level
CREATE TYPE app_sharing_level AS ENUM (
    'owner',
    'authenticated',
    'organization',
    'public'
);

-- Enum: workspace app health
CREATE TYPE workspace_app_health AS ENUM (
    'disabled',
    'initializing',
    'healthy',
    'unhealthy'
);

-- Enum: workspace app open in
CREATE TYPE workspace_app_open_in AS ENUM (
    'tab',
    'window',
    'slim-window'
);

-- Enum: workspace app status state
CREATE TYPE workspace_app_status_state AS ENUM (
    'working',
    'complete',
    'failure',
    'idle'
);

-- Enum: workspace agent monitor state
CREATE TYPE workspace_agent_monitor_state AS ENUM (
    'OK',
    'NOK'
);

-- Enum: workspace agent script timing stage
CREATE TYPE workspace_agent_script_timing_stage AS ENUM (
    'start',
    'stop',
    'cron'
);

-- Enum: workspace agent script timing status
CREATE TYPE workspace_agent_script_timing_status AS ENUM (
    'ok',
    'exit_failure',
    'timed_out',
    'pipes_left_open'
);

-- Enum: port share protocol
CREATE TYPE port_share_protocol AS ENUM (
    'http',
    'https'
);

-- Enum: log level
CREATE TYPE log_level AS ENUM (
    'trace',
    'debug',
    'info',
    'warn',
    'error'
);

-- Table: workspace_agents
CREATE TABLE workspace_agents (
    id uuid NOT NULL PRIMARY KEY,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    name varchar(64) NOT NULL,
    first_connected_at timestamptz,
    last_connected_at timestamptz,
    disconnected_at timestamptz,
    resource_id uuid NOT NULL,
    auth_token uuid NOT NULL,
    auth_instance_id varchar,
    architecture varchar(64) NOT NULL,
    environment_variables jsonb,
    operating_system varchar(64) NOT NULL,
    instance_metadata jsonb,
    resource_metadata jsonb,
    directory varchar(4096) DEFAULT '' NOT NULL,
    version text DEFAULT '' NOT NULL,
    last_connected_replica_id uuid,
    connection_timeout_seconds integer DEFAULT 0 NOT NULL,
    troubleshooting_url text DEFAULT '' NOT NULL,
    motd_file text DEFAULT '' NOT NULL,
    lifecycle_state workspace_agent_lifecycle_state DEFAULT 'created' NOT NULL,
    expanded_directory varchar(4096) DEFAULT '' NOT NULL,
    logs_length integer DEFAULT 0 NOT NULL,
    logs_overflowed boolean DEFAULT false NOT NULL,
    started_at timestamptz,
    ready_at timestamptz,
    subsystems workspace_agent_subsystem[] DEFAULT '{}',
    display_apps display_app[] DEFAULT '{vscode,vscode_insiders,web_terminal,ssh_helper,port_forwarding_helper}',
    api_version text DEFAULT '' NOT NULL,
    display_order integer DEFAULT 0 NOT NULL,
    parent_id uuid,
    api_key_scope agent_key_scope_enum DEFAULT 'all' NOT NULL,
    deleted boolean DEFAULT false NOT NULL,
    CONSTRAINT max_logs_length CHECK (logs_length <= 1048576),
    CONSTRAINT subsystems_not_none CHECK (NOT ('none' = ANY (subsystems)))
);

-- Table: workspace_apps
CREATE TABLE workspace_apps (
    id uuid NOT NULL PRIMARY KEY,
    created_at timestamptz NOT NULL,
    agent_id uuid NOT NULL REFERENCES workspace_agents(id) ON DELETE CASCADE,
    display_name varchar(64) NOT NULL,
    icon varchar(256) NOT NULL,
    command varchar(65534),
    url varchar(65534),
    healthcheck_url text DEFAULT '' NOT NULL,
    healthcheck_interval integer DEFAULT 0 NOT NULL,
    healthcheck_threshold integer DEFAULT 0 NOT NULL,
    health workspace_app_health DEFAULT 'disabled' NOT NULL,
    subdomain boolean DEFAULT false NOT NULL,
    sharing_level app_sharing_level DEFAULT 'owner' NOT NULL,
    slug text NOT NULL,
    external boolean DEFAULT false NOT NULL,
    display_order integer DEFAULT 0 NOT NULL,
    hidden boolean DEFAULT false NOT NULL,
    open_in workspace_app_open_in DEFAULT 'slim-window' NOT NULL,
    display_group text,
    tooltip varchar(2048) DEFAULT '' NOT NULL
);

-- Table: workspace_agent_log_sources
CREATE TABLE workspace_agent_log_sources (
    workspace_agent_id uuid NOT NULL REFERENCES workspace_agents(id) ON DELETE CASCADE,
    id uuid NOT NULL PRIMARY KEY,
    created_at timestamptz NOT NULL,
    display_name varchar(127) NOT NULL,
    icon text NOT NULL
);

-- Table: workspace_agent_scripts
CREATE TABLE workspace_agent_scripts (
    workspace_agent_id uuid NOT NULL REFERENCES workspace_agents(id) ON DELETE CASCADE,
    log_source_id uuid NOT NULL,
    log_path text NOT NULL,
    created_at timestamptz NOT NULL,
    script text NOT NULL,
    cron text NOT NULL,
    start_blocks_login boolean NOT NULL,
    run_on_start boolean NOT NULL,
    run_on_stop boolean NOT NULL,
    timeout_seconds integer NOT NULL,
    display_name text NOT NULL,
    id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY
);

-- Table: workspace_agent_logs (unlogged for performance)
CREATE UNLOGGED TABLE workspace_agent_logs (
    agent_id uuid NOT NULL REFERENCES workspace_agents(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL,
    output varchar(1024) NOT NULL,
    id bigserial NOT NULL PRIMARY KEY,
    level log_level DEFAULT 'info' NOT NULL,
    log_source_id uuid DEFAULT '00000000-0000-0000-0000-000000000000' NOT NULL
);

-- Table: workspace_agent_metadata (unlogged for performance)
CREATE UNLOGGED TABLE workspace_agent_metadata (
    workspace_agent_id uuid NOT NULL REFERENCES workspace_agents(id) ON DELETE CASCADE,
    display_name varchar(127) NOT NULL,
    key varchar(127) NOT NULL,
    script varchar(65535) NOT NULL,
    value varchar(65535) DEFAULT '' NOT NULL,
    error varchar(65535) DEFAULT '' NOT NULL,
    timeout bigint NOT NULL,
    "interval" bigint NOT NULL,
    collected_at timestamptz DEFAULT '0001-01-01 00:00:00+00' NOT NULL,
    display_order integer DEFAULT 0 NOT NULL,
    PRIMARY KEY (workspace_agent_id, key)
);

-- Table: workspace_agent_devcontainers
CREATE TABLE workspace_agent_devcontainers (
    id uuid NOT NULL PRIMARY KEY,
    workspace_agent_id uuid NOT NULL REFERENCES workspace_agents(id) ON DELETE CASCADE,
    created_at timestamptz DEFAULT now() NOT NULL,
    workspace_folder text NOT NULL,
    config_path text NOT NULL,
    name text NOT NULL,
    subagent_id uuid
);

-- Table: workspace_agent_memory_resource_monitors
CREATE TABLE workspace_agent_memory_resource_monitors (
    agent_id uuid NOT NULL PRIMARY KEY REFERENCES workspace_agents(id) ON DELETE CASCADE,
    enabled boolean NOT NULL,
    threshold integer NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz DEFAULT CURRENT_TIMESTAMP NOT NULL,
    state workspace_agent_monitor_state DEFAULT 'OK' NOT NULL,
    debounced_until timestamptz DEFAULT '0001-01-01 00:00:00+00' NOT NULL
);

-- Table: workspace_agent_volume_resource_monitors
CREATE TABLE workspace_agent_volume_resource_monitors (
    agent_id uuid NOT NULL REFERENCES workspace_agents(id) ON DELETE CASCADE,
    enabled boolean NOT NULL,
    threshold integer NOT NULL,
    path text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz DEFAULT CURRENT_TIMESTAMP NOT NULL,
    state workspace_agent_monitor_state DEFAULT 'OK' NOT NULL,
    debounced_until timestamptz DEFAULT '0001-01-01 00:00:00+00' NOT NULL,
    PRIMARY KEY (agent_id, path)
);

-- Table: workspace_agent_script_timings
CREATE TABLE workspace_agent_script_timings (
    script_id uuid NOT NULL REFERENCES workspace_agent_scripts(id) ON DELETE CASCADE,
    started_at timestamptz NOT NULL,
    ended_at timestamptz NOT NULL,
    exit_code integer NOT NULL,
    stage workspace_agent_script_timing_stage NOT NULL,
    status workspace_agent_script_timing_status NOT NULL
);

-- Table: workspace_app_stats
CREATE TABLE workspace_app_stats (
    id bigserial NOT NULL PRIMARY KEY,
    user_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    agent_id uuid NOT NULL,
    access_method text NOT NULL,
    slug_or_port text NOT NULL,
    session_id uuid NOT NULL,
    session_started_at timestamptz NOT NULL,
    session_ended_at timestamptz NOT NULL,
    requests integer NOT NULL
);

-- Table: workspace_app_statuses
CREATE TABLE workspace_app_statuses (
    id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    created_at timestamptz DEFAULT CURRENT_TIMESTAMP NOT NULL,
    agent_id uuid NOT NULL REFERENCES workspace_agents(id) ON DELETE CASCADE,
    app_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    state workspace_app_status_state NOT NULL,
    message text NOT NULL,
    uri text
);

-- Table: workspace_agent_port_share
CREATE TABLE workspace_agent_port_share (
    workspace_id uuid NOT NULL,
    agent_name text NOT NULL,
    port integer NOT NULL,
    share_level app_sharing_level NOT NULL,
    protocol port_share_protocol DEFAULT 'http' NOT NULL,
    PRIMARY KEY (workspace_id, agent_name, port)
);

-- Indexes for common lookups
CREATE INDEX idx_workspace_agents_resource_id ON workspace_agents(resource_id);
CREATE INDEX idx_workspace_agents_auth_token ON workspace_agents(auth_token);
CREATE INDEX idx_workspace_apps_agent_id ON workspace_apps(agent_id);
CREATE INDEX idx_workspace_agent_logs_agent_id ON workspace_agent_logs(agent_id);
CREATE INDEX idx_workspace_agent_scripts_agent_id ON workspace_agent_scripts(workspace_agent_id);
CREATE INDEX idx_workspace_agent_log_sources_agent_id ON workspace_agent_log_sources(workspace_agent_id);
CREATE INDEX idx_workspace_app_statuses_agent_id ON workspace_app_statuses(agent_id);
CREATE INDEX idx_workspace_agent_devcontainers_agent_id ON workspace_agent_devcontainers(workspace_agent_id);
