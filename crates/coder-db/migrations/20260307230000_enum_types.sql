-- Define all PostgreSQL enum types matching the Go schema.
-- login_type and user_status already exist from prior migrations.

CREATE TYPE agent_key_scope_enum AS ENUM (
    'all',
    'no_user_data'
);

CREATE TYPE api_key_scope AS ENUM (
    'coder:all',
    'coder:application_connect',
    'aibridge_interception:create',
    'aibridge_interception:read',
    'aibridge_interception:update',
    'api_key:create',
    'api_key:delete',
    'api_key:read',
    'api_key:update',
    'assign_org_role:assign',
    'assign_org_role:create',
    'assign_org_role:delete',
    'assign_org_role:read',
    'assign_org_role:unassign',
    'assign_org_role:update',
    'assign_role:assign',
    'assign_role:read',
    'assign_role:unassign',
    'audit_log:create',
    'audit_log:read',
    'connection_log:read',
    'connection_log:update',
    'crypto_key:create',
    'crypto_key:delete',
    'crypto_key:read',
    'crypto_key:update',
    'debug_info:read',
    'deployment_config:read',
    'deployment_config:update',
    'deployment_stats:read',
    'file:create',
    'file:read',
    'group:create',
    'group:delete',
    'group:read',
    'group:update',
    'group_member:read',
    'idpsync_settings:read',
    'idpsync_settings:update',
    'inbox_notification:create',
    'inbox_notification:read',
    'inbox_notification:update',
    'license:create',
    'license:delete',
    'license:read',
    'notification_message:create',
    'notification_message:delete',
    'notification_message:read',
    'notification_message:update',
    'notification_preference:read',
    'notification_preference:update',
    'notification_template:read',
    'notification_template:update',
    'oauth2_app:create',
    'oauth2_app:delete',
    'oauth2_app:read',
    'oauth2_app:update',
    'oauth2_app_code_token:create',
    'oauth2_app_code_token:delete',
    'oauth2_app_code_token:read',
    'oauth2_app_secret:create',
    'oauth2_app_secret:delete',
    'oauth2_app_secret:read',
    'oauth2_app_secret:update',
    'organization:create',
    'organization:delete',
    'organization:read',
    'organization:update',
    'organization_member:create',
    'organization_member:delete',
    'organization_member:read',
    'organization_member:update',
    'prebuilt_workspace:delete',
    'prebuilt_workspace:update',
    'provisioner_daemon:create',
    'provisioner_daemon:delete',
    'provisioner_daemon:read',
    'provisioner_daemon:update',
    'provisioner_jobs:create',
    'provisioner_jobs:read',
    'provisioner_jobs:update',
    'replicas:read',
    'system:create',
    'system:delete',
    'system:read',
    'system:update',
    'tailnet_coordinator:create',
    'tailnet_coordinator:delete',
    'tailnet_coordinator:read',
    'tailnet_coordinator:update',
    'template:create',
    'template:delete',
    'template:read',
    'template:update',
    'template:use',
    'template:view_insights',
    'usage_event:create',
    'usage_event:read',
    'usage_event:update',
    'user:create',
    'user:delete',
    'user:read',
    'user:read_personal',
    'user:update',
    'user:update_personal',
    'user_secret:create',
    'user_secret:delete',
    'user_secret:read',
    'user_secret:update',
    'webpush_subscription:create',
    'webpush_subscription:delete',
    'webpush_subscription:read',
    'workspace:application_connect',
    'workspace:create',
    'workspace:create_agent',
    'workspace:delete',
    'workspace:delete_agent',
    'workspace:read',
    'workspace:ssh',
    'workspace:start',
    'workspace:stop',
    'workspace:update',
    'workspace_agent_devcontainers:create',
    'workspace_agent_resource_monitor:create',
    'workspace_agent_resource_monitor:read',
    'workspace_agent_resource_monitor:update',
    'workspace_dormant:application_connect',
    'workspace_dormant:create',
    'workspace_dormant:create_agent',
    'workspace_dormant:delete',
    'workspace_dormant:delete_agent',
    'workspace_dormant:read',
    'workspace_dormant:ssh',
    'workspace_dormant:start',
    'workspace_dormant:stop',
    'workspace_dormant:update',
    'workspace_proxy:create',
    'workspace_proxy:delete',
    'workspace_proxy:read',
    'workspace_proxy:update',
    'coder:workspaces.create',
    'coder:workspaces.operate',
    'coder:workspaces.delete',
    'coder:workspaces.access',
    'coder:templates.build',
    'coder:templates.author',
    'coder:apikeys.manage_self',
    'aibridge_interception:*',
    'api_key:*',
    'assign_org_role:*',
    'assign_role:*',
    'audit_log:*',
    'connection_log:*',
    'crypto_key:*',
    'debug_info:*',
    'deployment_config:*',
    'deployment_stats:*',
    'file:*',
    'group:*',
    'group_member:*',
    'idpsync_settings:*',
    'inbox_notification:*',
    'license:*',
    'notification_message:*',
    'notification_preference:*',
    'notification_template:*',
    'oauth2_app:*',
    'oauth2_app_code_token:*',
    'oauth2_app_secret:*',
    'organization:*',
    'organization_member:*',
    'prebuilt_workspace:*',
    'provisioner_daemon:*',
    'provisioner_jobs:*',
    'replicas:*',
    'system:*',
    'tailnet_coordinator:*',
    'template:*',
    'usage_event:*',
    'user:*',
    'user_secret:*',
    'webpush_subscription:*',
    'workspace:*',
    'workspace_agent_devcontainers:*',
    'workspace_agent_resource_monitor:*',
    'workspace_dormant:*',
    'workspace_proxy:*',
    'task:create',
    'task:read',
    'task:update',
    'task:delete',
    'task:*',
    'workspace:share',
    'workspace_dormant:share',
    'boundary_usage:*',
    'boundary_usage:delete',
    'boundary_usage:read',
    'boundary_usage:update',
    'workspace:update_agent',
    'workspace_dormant:update_agent',
    'chat:create',
    'chat:read',
    'chat:update',
    'chat:delete',
    'chat:*'
);

CREATE TYPE app_sharing_level AS ENUM (
    'owner',
    'authenticated',
    'organization',
    'public'
);

CREATE TYPE audit_action AS ENUM (
    'create',
    'write',
    'delete',
    'start',
    'stop',
    'login',
    'logout',
    'register',
    'request_password_reset',
    'connect',
    'disconnect',
    'open',
    'close'
);

CREATE TYPE automatic_updates AS ENUM (
    'always',
    'never'
);

CREATE TYPE build_reason AS ENUM (
    'initiator',
    'autostart',
    'autostop',
    'dormancy',
    'failedstop',
    'autodelete',
    'dashboard',
    'cli',
    'ssh_connection',
    'vscode_connection',
    'jetbrains_connection',
    'task_auto_pause',
    'task_manual_pause',
    'task_resume'
);

CREATE TYPE chat_message_visibility AS ENUM (
    'user',
    'model',
    'both'
);

CREATE TYPE chat_status AS ENUM (
    'waiting',
    'pending',
    'running',
    'paused',
    'completed',
    'error'
);

CREATE TYPE connection_status AS ENUM (
    'connected',
    'disconnected'
);

CREATE TYPE connection_type AS ENUM (
    'ssh',
    'vscode',
    'jetbrains',
    'reconnecting_pty',
    'workspace_app',
    'port_forwarding'
);

CREATE TYPE cors_behavior AS ENUM (
    'simple',
    'passthru'
);

CREATE TYPE crypto_key_feature AS ENUM (
    'workspace_apps_token',
    'workspace_apps_api_key',
    'oidc_convert',
    'tailnet_resume'
);

CREATE TYPE display_app AS ENUM (
    'vscode',
    'vscode_insiders',
    'web_terminal',
    'ssh_helper',
    'port_forwarding_helper'
);

CREATE TYPE group_source AS ENUM (
    'user',
    'oidc'
);

CREATE TYPE inbox_notification_read_status AS ENUM (
    'all',
    'unread',
    'read'
);

CREATE TYPE log_level AS ENUM (
    'trace',
    'debug',
    'info',
    'warn',
    'error'
);

CREATE TYPE log_source AS ENUM (
    'provisioner_daemon',
    'provisioner'
);

CREATE TYPE notification_message_status AS ENUM (
    'pending',
    'leased',
    'sent',
    'permanent_failure',
    'temporary_failure',
    'unknown',
    'inhibited'
);

CREATE TYPE notification_method AS ENUM (
    'smtp',
    'webhook',
    'inbox'
);

CREATE TYPE notification_template_kind AS ENUM (
    'system',
    'custom'
);

CREATE TYPE parameter_destination_scheme AS ENUM (
    'none',
    'environment_variable',
    'provisioner_variable'
);

CREATE TYPE parameter_form_type AS ENUM (
    '',
    'error',
    'radio',
    'dropdown',
    'input',
    'textarea',
    'slider',
    'checkbox',
    'switch',
    'tag-select',
    'multi-select'
);

CREATE TYPE parameter_scope AS ENUM (
    'template',
    'import_job',
    'workspace'
);

CREATE TYPE parameter_source_scheme AS ENUM (
    'none',
    'data'
);

CREATE TYPE parameter_type_system AS ENUM (
    'none',
    'hcl'
);

CREATE TYPE port_share_protocol AS ENUM (
    'http',
    'https'
);

CREATE TYPE prebuild_status AS ENUM (
    'healthy',
    'hard_limited',
    'validation_failed'
);

CREATE TYPE provisioner_daemon_status AS ENUM (
    'offline',
    'idle',
    'busy'
);

CREATE TYPE provisioner_job_status AS ENUM (
    'pending',
    'running',
    'succeeded',
    'canceling',
    'canceled',
    'failed',
    'unknown'
);

CREATE TYPE provisioner_job_timing_stage AS ENUM (
    'init',
    'plan',
    'graph',
    'apply'
);

CREATE TYPE provisioner_job_type AS ENUM (
    'template_version_import',
    'workspace_build',
    'template_version_dry_run'
);

CREATE TYPE provisioner_storage_method AS ENUM (
    'file'
);

CREATE TYPE provisioner_type AS ENUM (
    'echo',
    'terraform'
);

CREATE TYPE resource_type AS ENUM (
    'organization',
    'template',
    'template_version',
    'user',
    'workspace',
    'git_ssh_key',
    'api_key',
    'group',
    'workspace_build',
    'license',
    'workspace_proxy',
    'convert_login',
    'health_settings',
    'oauth2_provider_app',
    'oauth2_provider_app_secret',
    'custom_role',
    'organization_member',
    'notifications_settings',
    'notification_template',
    'idp_sync_settings_organization',
    'idp_sync_settings_group',
    'idp_sync_settings_role',
    'workspace_agent',
    'workspace_app',
    'prebuilds_settings',
    'task'
);

CREATE TYPE startup_script_behavior AS ENUM (
    'blocking',
    'non-blocking'
);

CREATE TYPE tailnet_status AS ENUM (
    'ok',
    'lost'
);

CREATE TYPE task_status AS ENUM (
    'pending',
    'initializing',
    'active',
    'paused',
    'unknown',
    'error'
);

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

CREATE TYPE workspace_agent_monitor_state AS ENUM (
    'OK',
    'NOK'
);

CREATE TYPE workspace_agent_script_timing_stage AS ENUM (
    'start',
    'stop',
    'cron'
);

CREATE TYPE workspace_agent_script_timing_status AS ENUM (
    'ok',
    'exit_failure',
    'timed_out',
    'pipes_left_open'
);

CREATE TYPE workspace_agent_subsystem AS ENUM (
    'envbuilder',
    'envbox',
    'none',
    'exectrace'
);

CREATE TYPE workspace_app_health AS ENUM (
    'disabled',
    'initializing',
    'healthy',
    'unhealthy'
);

CREATE TYPE workspace_app_open_in AS ENUM (
    'tab',
    'window',
    'slim-window'
);

CREATE TYPE workspace_app_status_state AS ENUM (
    'working',
    'complete',
    'failure',
    'idle'
);

CREATE TYPE workspace_transition AS ENUM (
    'start',
    'stop',
    'delete'
);
