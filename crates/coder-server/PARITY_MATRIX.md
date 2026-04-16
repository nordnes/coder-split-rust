# Parity Matrix — Rust ↔ Go API Route Implementation Depth

Hand-maintained tracking document for the Rust rewrite of the Coder backend.
Tracks implementation depth of routes registered in `crates/coder-server/src/app.rs`
(`build_router`) against the Go reference in `coder/coderd/coderd.go` and
`coder/enterprise/coderd/coderd.go`.

For the generated route-parity inventories (which Go routes are ported), see:
- [`docs/parity-matrix.md`](../../docs/parity-matrix.md) — OSS routes
- [`docs/parity-matrix-enterprise.md`](../../docs/parity-matrix-enterprise.md) — Enterprise routes
- [`docs/parity-matrix-all.md`](../../docs/parity-matrix-all.md) — Combined

## Summary

| Metric | Count |
|--------|-------|
| **Total Rust routes** | 400 |
| **Go routes covered** | 326 (229 OSS + 87 Enterprise) |
| `complete` — Full implementation | 378 |
| `stub-501` — Returns 501 / WS close | 5 |
| `stub-partial` — Simplified/echo response | 17 |
| `missing` — In Go but absent from Rust | 0 |

**Completion: 378/400 routes fully implemented (94.5%). All 326 Go routes covered.**

### Status Legend

| Status | Meaning |
|--------|---------|
| `complete` | Handler has real logic, store calls work, authorization present |
| `stub-501` | Handler returns 501 Not Implemented or upgrades WS then closes immediately |
| `stub-partial` | Handler accepts request but returns simplified/hardcoded/echo response |
| `missing` | Route exists in Go but is completely absent from the Rust router |

---

## OSS Routes

### Root / Health

3/3 complete

| Route Path | Method | Handler Function | Status | Notes |
|------------|--------|------------------|--------|-------|
| `/` | GET | `api_root` | `complete` | Simple/config-based handler |
| `/healthz` | GET | `healthz` | `complete` | Simple/config-based handler |
| `/latency-check` | GET | `latency_check` | `complete` | Simple/config-based handler |

### Audit

2/2 complete

| Route Path | Method | Handler Function | Status | Notes |
|------------|--------|------------------|--------|-------|
| `/audit` | GET | `list_audit_logs` | `complete` | Full implementation with store/service calls |
| `/audit/testgenerate` | POST | `post_generate_test_audit_log` | `complete` | Full implementation with store/service calls |

### Auth

1/2 complete

| Route Path | Method | Handler Function | Status | Notes |
|------------|--------|------------------|--------|-------|
| `/auth/scopes` | GET | `list_api_key_scopes` | `stub-partial` | Returns hardcoded/simplified response |
| `/authcheck` | POST | `post_authcheck` | `complete` | Full implementation with store/service calls |

### Deployment & Config

5/9 complete

| Route Path | Method | Handler Function | Status | Notes |
|------------|--------|------------------|--------|-------|
| `/buildinfo` | GET | `build_info` | `stub-partial` | Returns hardcoded/simplified response |
| `/csp/reports` | POST | `post_csp_report` | `complete` | Full implementation with store/service calls |
| `/deployment/config` | GET | `deployment_config` | `stub-partial` | Returns hardcoded/simplified response |
| `/deployment/ssh` | GET | `deployment_ssh` | `stub-partial` | Returns hardcoded/simplified response |
| `/deployment/stats` | GET | `deployment_stats` | `complete` | Full implementation with store/service calls |
| `/experiments` | GET | `get_enabled_experiments` | `complete` | Full implementation with store/service calls |
| `/experiments/available` | GET | `get_available_experiments` | `complete` | Full implementation with store/service calls |
| `/init-script/{os}/{arch}` | GET | `get_init_script` | `complete` | Simple/config-based handler |
| `/updatecheck` | GET | `update_check` | `stub-partial` | Returns hardcoded/simplified response |

### Debug

15/16 complete

| Route Path | Method | Handler Function | Status | Notes |
|------------|--------|------------------|--------|-------|
| `/debug/coordinator` | GET | `debug_coordinator` | `complete` | Full implementation with store/service calls |
| `/debug/derp/traffic` | GET | `debug_derp_traffic` | `complete` | Full implementation with store/service calls |
| `/debug/expvar` | GET | `debug_expvar` | `complete` | Full implementation with store/service calls |
| `/debug/health` | GET | `debug_health` | `complete` | Full implementation with store/service calls |
| `/debug/health/settings` | GET | `get_health_settings` | `complete` | Full implementation with store/service calls |
| `/debug/health/settings` | PUT | `put_health_settings` | `complete` | Full implementation with store/service calls |
| `/debug/metrics` | GET | `debug_metrics` | `complete` | Full implementation with store/service calls |
| `/debug/pprof` | GET | `debug_pprof` | `complete` | Full implementation with store/service calls |
| `/debug/pprof/cmdline` | GET | `debug_pprof` | `complete` | Full implementation with store/service calls |
| `/debug/pprof/profile` | GET | `debug_pprof` | `complete` | Full implementation with store/service calls |
| `/debug/pprof/symbol` | GET | `debug_pprof` | `complete` | Full implementation with store/service calls |
| `/debug/pprof/trace` | GET | `debug_pprof` | `complete` | Full implementation with store/service calls |
| `/debug/tailnet` | GET | `debug_tailnet` | `complete` | Full implementation with store/service calls |
| `/debug/ws` | GET | `debug_websocket` | `complete` | Full implementation with store/service calls |
| `/debug/{user}/debug-link` | GET | `get_user_debug_link` | `stub-501` | Returns 501 Not Implemented |
| `/telemetry/report` | POST | `post_telemetry_report` | `complete` | Full implementation with store/service calls |

### Connectivity (DERP / Tailnet / Regions)

3/3 complete

| Route Path | Method | Handler Function | Status | Notes |
|------------|--------|------------------|--------|-------|
| `/derp-map` | GET | `derp_map_updates` | `complete` | Simple/config-based handler |
| `/regions` | GET | `get_regions` | `complete` | Simple/config-based handler |
| `/tailnet` | GET | `tailnet_rpc_conn` | `complete` | Full implementation with store/service calls |

### External Auth (OAuth/OIDC)

7/7 complete

| Route Path | Method | Handler Function | Status | Notes |
|------------|--------|------------------|--------|-------|
| `/external-auth` | GET | `list_external_auths` | `complete` | Full implementation with store/service calls |
| `/external-auth/{externalauth}` | DELETE | `delete_external_auth_by_id` | `complete` | Full implementation with store/service calls |
| `/external-auth/{externalauth}` | GET | `get_external_auth_by_id` | `complete` | Full implementation with store/service calls |
| `/external-auth/{externalauth}/callback` | GET | `get_external_auth_callback_by_id` | `complete` | Full implementation with store/service calls |
| `/external-auth/{externalauth}/device` | GET | `get_external_auth_device_by_id` | `complete` | Full implementation with store/service calls |
| `/external-auth/{externalauth}/device` | POST | `post_external_auth_device_exchange` | `complete` | Full implementation with store/service calls |
| `/gitauth/{externalauth}/callback` | GET | `get_external_auth_callback_by_id` | `complete` | Full implementation with store/service calls |

### Files

2/2 complete

| Route Path | Method | Handler Function | Status | Notes |
|------------|--------|------------------|--------|-------|
| `/files` | POST | `post_file` | `complete` | Full implementation with store/service calls |
| `/files/{fileid}` | GET | `get_file_by_id` | `complete` | Full implementation with store/service calls |

### Insights & Analytics

5/5 complete

| Route Path | Method | Handler Function | Status | Notes |
|------------|--------|------------------|--------|-------|
| `/insights/daus` | GET | `insights_daus` | `complete` | Full implementation with store/service calls |
| `/insights/templates` | GET | `insights_templates` | `complete` | Full implementation with store/service calls |
| `/insights/user-activity` | GET | `insights_user_activity` | `complete` | Full implementation with store/service calls |
| `/insights/user-latency` | GET | `insights_user_latency` | `complete` | Full implementation with store/service calls |
| `/insights/user-status-counts` | GET | `insights_user_status_counts` | `complete` | Full implementation with store/service calls |

### Notifications & Inbox

12/12 complete

| Route Path | Method | Handler Function | Status | Notes |
|------------|--------|------------------|--------|-------|
| `/notifications/custom` | POST | `post_custom_notification` | `complete` | Full implementation with store/service calls |
| `/notifications/dispatch-methods` | GET | `get_notification_dispatch_methods` | `complete` | Full implementation with store/service calls |
| `/notifications/inbox` | GET | `list_inbox_notifications` | `complete` | Full implementation with store/service calls |
| `/notifications/inbox/mark-all-as-read` | PUT | `put_mark_all_inbox_notifications_read` | `complete` | Full implementation with store/service calls |
| `/notifications/inbox/watch` | GET | `watch_inbox_notifications` | `complete` | Full implementation with store/service calls |
| `/notifications/inbox/{id}/read-status` | PUT | `put_inbox_notification_read_status` | `complete` | Full implementation with store/service calls |
| `/notifications/settings` | GET | `get_notifications_settings` | `complete` | Full implementation with store/service calls |
| `/notifications/settings` | PUT | `put_notifications_settings` | `complete` | Full implementation with store/service calls |
| `/notifications/templates/custom` | GET | `get_custom_notification_templates` | `complete` | Full implementation with store/service calls |
| `/notifications/templates/system` | GET | `get_system_notification_templates` | `complete` | Full implementation with store/service calls |
| `/notifications/templates/{id}/method` | PUT | `put_notification_template_method` | `complete` | Full implementation with store/service calls |
| `/notifications/test` | POST | `post_test_notification` | `complete` | Full implementation with store/service calls |

### OAuth2 Provider

12/12 complete

| Route Path | Method | Handler Function | Status | Notes |
|------------|--------|------------------|--------|-------|
| `/oauth2-provider/apps` | GET | `list_oauth2_provider_apps` | `complete` | Full implementation with store/service calls |
| `/oauth2-provider/apps` | POST | `post_oauth2_provider_app` | `complete` | Full implementation with store/service calls |
| `/oauth2-provider/apps/{app_id}` | DELETE | `delete_oauth2_provider_app` | `complete` | Full implementation with store/service calls |
| `/oauth2-provider/apps/{app_id}` | GET | `get_oauth2_provider_app` | `complete` | Full implementation with store/service calls |
| `/oauth2-provider/apps/{app_id}` | PUT | `put_oauth2_provider_app` | `complete` | Full implementation with store/service calls |
| `/oauth2-provider/apps/{app_id}/secrets` | GET | `list_oauth2_provider_app_secrets` | `complete` | Full implementation with store/service calls |
| `/oauth2-provider/apps/{app_id}/secrets` | POST | `post_oauth2_provider_app_secret` | `complete` | Full implementation with store/service calls |
| `/oauth2-provider/apps/{app_id}/secrets/{secret_id}` | DELETE | `delete_oauth2_provider_app_secret` | `complete` | Full implementation with store/service calls |
| `/oauth2-provider/apps/{app_id}/tokens` | DELETE | `delete_oauth2_provider_app_tokens` | `complete` | Full implementation with store/service calls |
| `/oauth2/authorize` | GET | `get_oauth2_authorize` | `complete` | Full implementation with store/service calls |
| `/oauth2/authorize` | POST | `post_oauth2_authorize` | `complete` | Full implementation with store/service calls |
| `/oauth2/tokens` | POST | `post_oauth2_token` | `complete` | Simple/config-based handler |

### Organizations

23/23 complete

| Route Path | Method | Handler Function | Status | Notes |
|------------|--------|------------------|--------|-------|
| `/organizations` | GET | `list_organizations` | `complete` | Full implementation with store/service calls |
| `/organizations/{organization}` | GET | `get_organization` | `complete` | Full implementation with store/service calls |
| `/organizations/{organization}/members` | GET | `list_organization_members` | `complete` | Full implementation with store/service calls |
| `/organizations/{organization}/members/roles` | GET | `list_organization_roles` | `complete` | Full implementation with store/service calls |
| `/organizations/{organization}/members/{user}` | DELETE | `delete_organization_member` | `complete` | Full implementation with store/service calls |
| `/organizations/{organization}/members/{user}` | GET | `get_organization_member` | `complete` | Full implementation with store/service calls |
| `/organizations/{organization}/members/{user}` | POST | `post_organization_member` | `complete` | Full implementation with store/service calls |
| `/organizations/{organization}/members/{user}/roles` | PUT | `put_organization_member_roles` | `complete` | Full implementation with store/service calls |
| `/organizations/{organization}/members/{user}/workspaces` | POST | `post_org_member_workspace` | `complete` | Full implementation with store/service calls |
| `/organizations/{organization}/members/{user}/workspaces/available-users` | GET | `get_org_member_workspace_available_users` | `complete` | Full implementation with store/service calls |
| `/organizations/{organization}/paginated-members` | GET | `list_paginated_organization_members` | `complete` | Full implementation with store/service calls |
| `/organizations/{organization}/provisionerdaemons` | GET | `list_provisioner_daemons` | `complete` | Full implementation with store/service calls |
| `/organizations/{organization}/provisionerjobs` | GET | `list_provisioner_jobs` | `complete` | Full implementation with store/service calls |
| `/organizations/{organization}/provisionerjobs/{job}` | GET | `get_provisioner_job` | `complete` | Full implementation with store/service calls |
| `/organizations/{organization}/provisionerjobs/{job}/cancel` | PATCH | `cancel_provisioner_job` | `complete` | Full implementation with store/service calls |
| `/organizations/{organization}/provisionerjobs/{job}/logs` | GET | `get_provisioner_job_logs` | `complete` | Full implementation with store/service calls |
| `/organizations/{organization}/templates` | GET | `list_org_templates` | `complete` | Full implementation with store/service calls |
| `/organizations/{organization}/templates` | POST | `post_org_template` | `complete` | Full implementation with store/service calls |
| `/organizations/{organization}/templates/examples` | GET | `get_org_template_examples` | `complete` | Full implementation with store/service calls |
| `/organizations/{organization}/templates/{templatename}` | GET | `get_org_template_by_name` | `complete` | Full implementation with store/service calls |
| `/organizations/{organization}/templates/{templatename}/versions/{templateversionname}` | GET | `get_org_template_version_by_name` | `complete` | Full implementation with store/service calls |
| `/organizations/{organization}/templates/{templatename}/versions/{templateversionname}/previous` | GET | `get_org_previous_template_version` | `complete` | Full implementation with store/service calls |
| `/organizations/{organization}/templateversions` | POST | `post_org_template_version` | `complete` | Full implementation with store/service calls |

### Applications

2/2 complete

| Route Path | Method | Handler Function | Status | Notes |
|------------|--------|------------------|--------|-------|
| `/applications/auth-redirect` | GET | `applications_auth_redirect` | `complete` | Full implementation with store/service calls |
| `/applications/host` | GET | `applications_host` | `complete` | Full implementation with store/service calls |

### AI Tasks

9/9 complete

| Route Path | Method | Handler Function | Status | Notes |
|------------|--------|------------------|--------|-------|
| `/tasks` | GET | `list_tasks` | `complete` | Full implementation with store/service calls |
| `/tasks/{user}` | POST | `create_task` | `complete` | Full implementation with store/service calls |
| `/tasks/{user}/{task}` | DELETE | `delete_task` | `complete` | Full implementation with store/service calls |
| `/tasks/{user}/{task}` | GET | `get_task` | `complete` | Full implementation with store/service calls |
| `/tasks/{user}/{task}/input` | PATCH | `patch_task_input` | `complete` | Full implementation with store/service calls |
| `/tasks/{user}/{task}/logs` | GET | `get_task_logs` | `complete` | Full implementation with store/service calls |
| `/tasks/{user}/{task}/pause` | POST | `post_task_pause` | `complete` | Full implementation with store/service calls |
| `/tasks/{user}/{task}/resume` | POST | `post_task_resume` | `complete` | Full implementation with store/service calls |
| `/tasks/{user}/{task}/send` | POST | `post_task_send` | `complete` | Full implementation with store/service calls |

### Chats

10/10 complete

| Route Path | Method | Handler Function | Status | Notes |
|------------|--------|------------------|--------|-------|
| `/chats` | GET | `list_chats` | `complete` | Full implementation with store/service calls |
| `/chats` | POST | `create_chat` | `complete` | Full implementation with store/service calls |
| `/chats/files` | POST | `upload_chat_file` | `complete` | Full implementation with store/service calls |
| `/chats/files/{file}` | GET | `get_chat_file` | `complete` | Full implementation with store/service calls |
| `/chats/{chat}` | DELETE | `delete_chat` | `complete` | Full implementation with store/service calls |
| `/chats/{chat}` | GET | `get_chat` | `complete` | Full implementation with store/service calls |
| `/chats/{chat}/archive` | POST | `archive_chat_handler` | `complete` | Full implementation with store/service calls |
| `/chats/{chat}/git/watch` | GET | `watch_chat_git` | `complete` | Full implementation with store/service calls |
| `/chats/{chat}/messages` | POST | `post_chat_message` | `complete` | Full implementation with store/service calls |
| `/chats/{chat}/unarchive` | POST | `unarchive_chat_handler` | `complete` | Full implementation with store/service calls |

### Templates & Template Versions

33/34 complete

| Route Path | Method | Handler Function | Status | Notes |
|------------|--------|------------------|--------|-------|
| `/templates` | GET | `list_all_templates` | `complete` | Full implementation with store/service calls |
| `/templates/examples` | GET | `get_all_template_examples` | `complete` | Full implementation with store/service calls |
| `/templates/{template}` | DELETE | `delete_template` | `complete` | Full implementation with store/service calls |
| `/templates/{template}` | GET | `get_template` | `complete` | Full implementation with store/service calls |
| `/templates/{template}` | PATCH | `patch_template` | `complete` | Full implementation with store/service calls |
| `/templates/{template}/daus` | GET | `get_template_daus` | `complete` | Full implementation with store/service calls |
| `/templates/{template}/examples` | GET | `get_template_examples` | `complete` | Full implementation with store/service calls |
| `/templates/{template}/versions` | GET | `list_template_versions` | `complete` | Full implementation with store/service calls |
| `/templates/{template}/versions` | PATCH | `patch_active_template_version` | `complete` | Full implementation with store/service calls |
| `/templates/{template}/versions/archive` | POST | `post_archive_template_versions` | `complete` | Full implementation with store/service calls |
| `/templates/{template}/versions/{templateversionname}` | GET | `get_template_version_by_name` | `complete` | Full implementation with store/service calls |
| `/templateversions/{templateversion}` | GET | `get_template_version` | `complete` | Full implementation with store/service calls |
| `/templateversions/{templateversion}` | PATCH | `patch_template_version` | `complete` | Full implementation with store/service calls |
| `/templateversions/{templateversion}/archive` | POST | `post_archive_template_version` | `complete` | Full implementation with store/service calls |
| `/templateversions/{templateversion}/cancel` | PATCH | `patch_cancel_template_version` | `complete` | Full implementation with store/service calls |
| `/templateversions/{templateversion}/dry-run` | POST | `post_template_version_dry_run` | `complete` | Full implementation with store/service calls |
| `/templateversions/{templateversion}/dry-run/{jobid}` | GET | `get_template_version_dry_run` | `complete` | Full implementation with store/service calls |
| `/templateversions/{templateversion}/dry-run/{jobid}` | PATCH | `patch_template_version_dry_run` | `complete` | Full implementation with store/service calls |
| `/templateversions/{templateversion}/dry-run/{jobid}/cancel` | PATCH | `patch_cancel_template_version_dry_run` | `complete` | Full implementation with store/service calls |
| `/templateversions/{templateversion}/dry-run/{jobid}/logs` | GET | `get_template_version_dry_run_logs` | `complete` | Full implementation with store/service calls |
| `/templateversions/{templateversion}/dry-run/{jobid}/matched-provisioners` | GET | `get_template_version_dry_run_matched_provisioners` | `complete` | Full implementation with store/service calls |
| `/templateversions/{templateversion}/dry-run/{jobid}/resources` | GET | `get_template_version_dry_run_resources` | `complete` | Full implementation with store/service calls |
| `/templateversions/{templateversion}/dynamic-parameters` | GET | `get_template_version_dynamic_parameters` | `complete` | Full implementation with store/service calls |
| `/templateversions/{templateversion}/dynamic-parameters/evaluate` | POST | `post_template_version_dynamic_parameters_evaluate` | `stub-partial` | Marked as stub in code |
| `/templateversions/{templateversion}/external-auth` | GET | `get_template_version_external_auth` | `complete` | Full implementation with store/service calls |
| `/templateversions/{templateversion}/logs` | GET | `get_template_version_logs` | `complete` | Full implementation with store/service calls |
| `/templateversions/{templateversion}/parameters` | GET | `get_template_version_parameters` | `complete` | Simple/config-based handler |
| `/templateversions/{templateversion}/presets` | GET | `get_template_version_presets` | `complete` | Full implementation with store/service calls |
| `/templateversions/{templateversion}/presets/{presetid}/parameters` | GET | `get_template_version_preset_parameters` | `complete` | Full implementation with store/service calls |
| `/templateversions/{templateversion}/resources` | GET | `get_template_version_resources` | `complete` | Full implementation with store/service calls |
| `/templateversions/{templateversion}/rich-parameters` | GET | `get_template_version_rich_parameters` | `complete` | Simple/config-based handler |
| `/templateversions/{templateversion}/schema` | GET | `get_template_version_schema` | `complete` | Full implementation with store/service calls |
| `/templateversions/{templateversion}/unarchive` | POST | `post_unarchive_template_version` | `complete` | Full implementation with store/service calls |
| `/templateversions/{templateversion}/variables` | GET | `get_template_version_variables` | `complete` | Full implementation with store/service calls |

### Users & Identity

46/49 complete

| Route Path | Method | Handler Function | Status | Notes |
|------------|--------|------------------|--------|-------|
| `/users` | GET | `list_users` | `complete` | Full implementation with store/service calls |
| `/users` | POST | `post_user` | `complete` | Full implementation with store/service calls |
| `/users/authmethods` | GET | `auth_methods` | `complete` | Simple/config-based handler |
| `/users/first` | GET | `get_first_user` | `complete` | Full implementation with store/service calls |
| `/users/first` | POST | `post_first_user` | `complete` | Full implementation with store/service calls |
| `/users/login` | POST | `login_with_password` | `complete` | Full implementation with store/service calls |
| `/users/logout` | POST | `logout` | `complete` | Full implementation with store/service calls |
| `/users/oauth2/github/callback` | GET | `get_github_oauth_callback_disabled` | `stub-partial` | Returns hardcoded/simplified response |
| `/users/oauth2/github/device` | GET | `get_github_oauth_device_disabled` | `stub-partial` | Returns hardcoded/simplified response |
| `/users/oidc/callback` | GET | `get_oidc_callback_disabled` | `stub-partial` | Returns hardcoded/simplified response |
| `/users/otp/change-password` | POST | `post_change_password_with_one_time_passcode` | `complete` | Simple/config-based handler |
| `/users/otp/request` | POST | `post_request_one_time_passcode` | `complete` | Full implementation with store/service calls |
| `/users/roles` | GET | `list_site_roles` | `complete` | Full implementation with store/service calls |
| `/users/validate-password` | POST | `post_validate_user_password` | `complete` | Full implementation with store/service calls |
| `/users/{user}` | DELETE | `delete_user` | `complete` | Full implementation with store/service calls |
| `/users/{user}` | GET | `get_user` | `complete` | Full implementation with store/service calls |
| `/users/{user}/appearance` | GET | `get_user_appearance` | `complete` | Full implementation with store/service calls |
| `/users/{user}/appearance` | PUT | `put_user_appearance` | `complete` | Full implementation with store/service calls |
| `/users/{user}/autofill-parameters` | GET | `get_user_autofill_parameters` | `complete` | Full implementation with store/service calls |
| `/users/{user}/convert-login` | POST | `post_convert_login` | `complete` | Full implementation with store/service calls |
| `/users/{user}/gitsshkey` | GET | `get_user_git_ssh_key` | `complete` | Full implementation with store/service calls |
| `/users/{user}/gitsshkey` | PUT | `put_user_git_ssh_key` | `complete` | Full implementation with store/service calls |
| `/users/{user}/keys` | POST | `create_session_api_key` | `complete` | Full implementation with store/service calls |
| `/users/{user}/keys/tokens` | GET | `list_token_api_keys` | `complete` | Full implementation with store/service calls |
| `/users/{user}/keys/tokens` | POST | `create_token_api_key` | `complete` | Full implementation with store/service calls |
| `/users/{user}/keys/tokens/tokenconfig` | GET | `get_token_config` | `complete` | Full implementation with store/service calls |
| `/users/{user}/keys/tokens/{keyname}` | GET | `get_api_key_by_name` | `complete` | Full implementation with store/service calls |
| `/users/{user}/keys/{keyid}` | DELETE | `delete_api_key` | `complete` | Full implementation with store/service calls |
| `/users/{user}/keys/{keyid}` | GET | `get_api_key` | `complete` | Full implementation with store/service calls |
| `/users/{user}/keys/{keyid}/expire` | PUT | `expire_api_key` | `complete` | Full implementation with store/service calls |
| `/users/{user}/login-type` | GET | `get_user_login_type` | `complete` | Full implementation with store/service calls |
| `/users/{user}/notifications/preferences` | GET | `get_user_notification_preferences` | `complete` | Full implementation with store/service calls |
| `/users/{user}/notifications/preferences` | PUT | `put_user_notification_preferences` | `complete` | Full implementation with store/service calls |
| `/users/{user}/organizations` | GET | `list_user_organizations` | `complete` | Full implementation with store/service calls |
| `/users/{user}/organizations/{organizationname}` | GET | `get_user_organization_by_name` | `complete` | Full implementation with store/service calls |
| `/users/{user}/password` | PUT | `put_user_password` | `complete` | Full implementation with store/service calls |
| `/users/{user}/preferences` | GET | `get_user_preferences` | `complete` | Full implementation with store/service calls |
| `/users/{user}/preferences` | PUT | `put_user_preferences` | `complete` | Full implementation with store/service calls |
| `/users/{user}/profile` | PUT | `put_user_profile` | `complete` | Full implementation with store/service calls |
| `/users/{user}/roles` | GET | `get_user_roles` | `complete` | Full implementation with store/service calls |
| `/users/{user}/roles` | PUT | `put_user_roles` | `complete` | Full implementation with store/service calls |
| `/users/{user}/status/activate` | PUT | `put_activate_user_account` | `complete` | Simple/config-based handler |
| `/users/{user}/status/suspend` | PUT | `put_suspend_user_account` | `complete` | Simple/config-based handler |
| `/users/{user}/webpush/subscription` | DELETE | `delete_user_webpush_subscription` | `complete` | Full implementation with store/service calls |
| `/users/{user}/webpush/subscription` | POST | `post_user_webpush_subscription` | `complete` | Full implementation with store/service calls |
| `/users/{user}/webpush/test` | POST | `post_user_webpush_test` | `complete` | Full implementation with store/service calls |
| `/users/{user}/workspace/{name}` | GET | `get_user_workspace_by_name` | `complete` | Full implementation with store/service calls |
| `/users/{user}/workspace/{name}/builds/{number}` | GET | `get_user_workspace_build_by_number` | `complete` | Full implementation with store/service calls |
| `/users/{user}/workspaces` | POST | `post_user_workspace` | `complete` | Full implementation with store/service calls |

### Workspaces & Builds

31/31 complete

| Route Path | Method | Handler Function | Status | Notes |
|------------|--------|------------------|--------|-------|
| `/workspacebuilds/{build}` | GET | `get_workspace_build` | `complete` | Full implementation with store/service calls |
| `/workspacebuilds/{build}/cancel` | PATCH | `patch_cancel_workspace_build` | `complete` | Full implementation with store/service calls |
| `/workspacebuilds/{build}/logs` | GET | `get_workspace_build_logs` | `complete` | Full implementation with store/service calls |
| `/workspacebuilds/{build}/parameters` | GET | `get_workspace_build_parameters` | `complete` | Full implementation with store/service calls |
| `/workspacebuilds/{build}/resources` | GET | `get_workspace_build_resources` | `complete` | Full implementation with store/service calls |
| `/workspacebuilds/{build}/state` | GET | `get_workspace_build_state` | `complete` | Full implementation with store/service calls |
| `/workspacebuilds/{build}/state` | PUT | `put_workspace_build_state` | `complete` | Full implementation with store/service calls |
| `/workspacebuilds/{build}/timings` | GET | `get_workspace_build_timings` | `complete` | Full implementation with store/service calls |
| `/workspaces` | GET | `list_workspaces` | `complete` | Full implementation with store/service calls |
| `/workspaces/{workspace}` | GET | `get_workspace` | `complete` | Full implementation with store/service calls |
| `/workspaces/{workspace}` | PATCH | `patch_workspace` | `complete` | Full implementation with store/service calls |
| `/workspaces/{workspace}/acl` | DELETE | `delete_workspace_acl` | `complete` | Full implementation with store/service calls |
| `/workspaces/{workspace}/acl` | GET | `get_workspace_acl` | `complete` | Full implementation with store/service calls |
| `/workspaces/{workspace}/acl` | PATCH | `patch_workspace_acl` | `complete` | Full implementation with store/service calls |
| `/workspaces/{workspace}/autostart` | PUT | `put_workspace_autostart` | `complete` | Full implementation with store/service calls |
| `/workspaces/{workspace}/autoupdates` | PUT | `put_workspace_autoupdates` | `complete` | Full implementation with store/service calls |
| `/workspaces/{workspace}/builds` | GET | `list_workspace_builds_handler` | `complete` | Full implementation with store/service calls |
| `/workspaces/{workspace}/builds` | POST | `post_workspace_build` | `complete` | Full implementation with store/service calls |
| `/workspaces/{workspace}/dormant` | PUT | `put_workspace_dormant` | `complete` | Full implementation with store/service calls |
| `/workspaces/{workspace}/extend` | PUT | `put_workspace_extend` | `complete` | Full implementation with store/service calls |
| `/workspaces/{workspace}/favorite` | DELETE | `delete_workspace_favorite` | `complete` | Full implementation with store/service calls |
| `/workspaces/{workspace}/favorite` | PUT | `put_workspace_favorite` | `complete` | Full implementation with store/service calls |
| `/workspaces/{workspace}/port-share` | DELETE | `delete_workspace_port_share` | `complete` | Full implementation with store/service calls |
| `/workspaces/{workspace}/port-share` | GET | `list_workspace_port_shares` | `complete` | Full implementation with store/service calls |
| `/workspaces/{workspace}/port-share` | POST | `post_workspace_port_share` | `complete` | Full implementation with store/service calls |
| `/workspaces/{workspace}/resolve-autostart` | GET | `get_workspace_resolve_autostart` | `complete` | Full implementation with store/service calls |
| `/workspaces/{workspace}/timings` | GET | `get_workspace_timings` | `complete` | Full implementation with store/service calls |
| `/workspaces/{workspace}/ttl` | PUT | `put_workspace_ttl` | `complete` | Full implementation with store/service calls |
| `/workspaces/{workspace}/usage` | POST | `post_workspace_usage` | `complete` | Full implementation with store/service calls |
| `/workspaces/{workspace}/watch` | GET | `get_workspace_watch` | `complete` | Full implementation with store/service calls |
| `/workspaces/{workspace}/watch-ws` | GET | `get_workspace_watch_ws` | `complete` | Full implementation with store/service calls |

### Workspace Agents

21/26 complete

| Route Path | Method | Handler Function | Status | Notes |
|------------|--------|------------------|--------|-------|
| `/workspaceagents/aws-instance-identity` | POST | `post_workspace_agent_instance_identity_aws` | `complete` | Simple/config-based handler |
| `/workspaceagents/azure-instance-identity` | POST | `post_workspace_agent_instance_identity_azure` | `complete` | Simple/config-based handler |
| `/workspaceagents/connection` | GET | `get_workspace_agents_connection_info` | `complete` | Full implementation with store/service calls |
| `/workspaceagents/google-instance-identity` | POST | `post_workspace_agent_instance_identity_google` | `complete` | Simple/config-based handler |
| `/workspaceagents/me/app-status` | PATCH | `patch_workspace_agent_app_status` | `complete` | Full implementation with store/service calls |
| `/workspaceagents/me/external-auth` | GET | `get_workspace_agent_external_auth` | `stub-partial` | Marked as stub in code |
| `/workspaceagents/me/gitauth` | GET | `deprecated_workspace_agent_git_auth` | `complete` | Full implementation with store/service calls |
| `/workspaceagents/me/gitsshkey` | GET | `workspace_agent_git_ssh_key` | `complete` | Full implementation with store/service calls |
| `/workspaceagents/me/log-source` | POST | `post_workspace_agent_log_source` | `complete` | Simple/config-based handler |
| `/workspaceagents/me/logs` | PATCH | `patch_workspace_agent_logs` | `complete` | Simple/config-based handler |
| `/workspaceagents/me/reinit` | GET | `get_workspace_agent_reinit` | `complete` | Simple/config-based handler |
| `/workspaceagents/me/rpc` | GET | `get_workspace_agent_rpc` | `complete` | Full implementation with store/service calls |
| `/workspaceagents/me/tasks/{task}/log-snapshot` | POST | `post_task_log_snapshot` | `complete` | Full implementation with store/service calls |
| `/workspaceagents/{agent}` | GET | `get_workspace_agent` | `complete` | Full implementation with store/service calls |
| `/workspaceagents/{agent}/connection` | GET | `get_workspace_agent_connection` | `complete` | Full implementation with store/service calls |
| `/workspaceagents/{agent}/containers` | GET | `get_workspace_agent_containers` | `complete` | Full implementation with store/service calls |
| `/workspaceagents/{agent}/containers/devcontainers/{devcontainer}` | DELETE | `delete_workspace_agent_devcontainer` | `complete` | Full implementation with store/service calls |
| `/workspaceagents/{agent}/containers/devcontainers/{devcontainer}/recreate` | POST | `post_workspace_agent_recreate_devcontainer` | `complete` | Full implementation with store/service calls |
| `/workspaceagents/{agent}/containers/watch` | GET | `get_workspace_agent_containers_watch` | `stub-501` | WebSocket upgrade then immediate close (not implemented) |
| `/workspaceagents/{agent}/coordinate` | GET | `get_workspace_agent_coordinate` | `stub-501` | WebSocket upgrade then immediate close (not implemented) |
| `/workspaceagents/{agent}/listening-ports` | GET | `get_workspace_agent_listening_ports` | `complete` | Full implementation with store/service calls |
| `/workspaceagents/{agent}/logs` | GET | `get_workspace_agent_logs` | `complete` | Full implementation with store/service calls |
| `/workspaceagents/{agent}/pty` | GET | `get_workspace_agent_pty` | `stub-501` | WebSocket upgrade then immediate close (not implemented) |
| `/workspaceagents/{agent}/startup-logs` | GET | `deprecated_workspace_agent_startup_logs` | `complete` | Full implementation with store/service calls |
| `/workspaceagents/{agent}/watch-metadata` | GET | `get_workspace_agent_watch_metadata` | `complete` | Full implementation with store/service calls |
| `/workspaceagents/{agent}/watch-metadata-ws` | GET | `get_workspace_agent_watch_metadata_ws` | `stub-501` | WebSocket upgrade then immediate close (not implemented) |

---

## Enterprise Routes (added in Waves 1–3)

### Appearance

2/2 complete

| Route Path | Method | Handler Function | Status | Notes |
|------------|--------|------------------|--------|-------|
| `/appearance` | GET | `get_appearance` | `complete` | Full implementation with store/service calls |
| `/appearance` | PUT | `put_appearance` | `complete` | Full implementation with store/service calls |

### Licenses & Entitlements

5/5 complete

| Route Path | Method | Handler Function | Status | Notes |
|------------|--------|------------------|--------|-------|
| `/entitlements` | GET | `get_entitlements` | `complete` | Full implementation with store/service calls |
| `/licenses` | GET | `list_licenses` | `complete` | Full implementation with store/service calls |
| `/licenses` | POST | `post_license` | `complete` | Full implementation with store/service calls |
| `/licenses/refresh-entitlements` | POST | `post_refresh_entitlements` | `complete` | Full implementation with store/service calls |
| `/licenses/{id}` | DELETE | `delete_license` | `complete` | Full implementation with store/service calls |

### SCIM

5/5 complete

| Route Path | Method | Handler Function | Status | Notes |
|------------|--------|------------------|--------|-------|
| `/scim/v2/ServiceProviderConfig` | GET | `scim_get_service_provider_config` | `complete` | Full implementation with store/service calls |
| `/scim/v2/Users` | GET | `scim_get_users` | `complete` | Full implementation with store/service calls |
| `/scim/v2/Users` | POST | `scim_post_user` | `complete` | Full implementation with store/service calls |
| `/scim/v2/Users/{id}` | GET | `scim_get_user` | `complete` | Full implementation with store/service calls |
| `/scim/v2/Users/{id}` | PATCH | `scim_patch_user` | `complete` | Full implementation with store/service calls |

### Groups

7/7 complete

| Route Path | Method | Handler Function | Status | Notes |
|------------|--------|------------------|--------|-------|
| `/groups` | GET | `list_groups` | `complete` | Full implementation with store/service calls |
| `/groups/{group}` | DELETE | `delete_group` | `complete` | Full implementation with store/service calls |
| `/groups/{group}` | GET | `get_group` | `complete` | Full implementation with store/service calls |
| `/groups/{group}` | PATCH | `patch_group` | `complete` | Full implementation with store/service calls |
| `/organizations/{organization}/groups` | GET | `list_org_groups` | `complete` | Full implementation with store/service calls |
| `/organizations/{organization}/groups` | POST | `post_org_group` | `complete` | Full implementation with store/service calls |
| `/organizations/{organization}/groups/{groupName}` | GET | `get_org_group_by_name` | `complete` | Full implementation with store/service calls |

### Template ACLs & Prebuilds

3/3 complete

| Route Path | Method | Handler Function | Status | Notes |
|------------|--------|------------------|--------|-------|
| `/templates/{template}/acl` | GET | `get_template_acl` | `complete` | Full implementation with store/service calls |
| `/templates/{template}/acl` | PATCH | `patch_template_acl` | `complete` | Full implementation with store/service calls |
| `/templates/{template}/acl/available` | GET | `get_template_acl_available` | `complete` | Full implementation with store/service calls |
| `/templates/{template}/prebuilds/invalidate` | POST | `post_invalidate_prebuilds` | `complete` | Full implementation with store/service calls |

### Workspace Quotas

2/2 complete

| Route Path | Method | Handler Function | Status | Notes |
|------------|--------|------------------|--------|-------|
| `/organizations/{organization}/members/{user}/workspace-quota` | GET | `get_workspace_quota` | `complete` | Full implementation with store/service calls |
| `/workspace-quota/{user}` | GET | `get_workspace_quota_by_user` | `complete` | Full implementation with store/service calls |

### Provisioner Keys

5/5 complete

| Route Path | Method | Handler Function | Status | Notes |
|------------|--------|------------------|--------|-------|
| `/organizations/{organization}/provisionerkeys` | GET | `list_provisioner_keys` | `complete` | Full implementation with store/service calls |
| `/organizations/{organization}/provisionerkeys` | POST | `post_provisioner_key` | `complete` | Full implementation with store/service calls |
| `/organizations/{organization}/provisionerkeys/daemons` | GET | `list_provisioner_key_daemons` | `complete` | Full implementation with store/service calls |
| `/organizations/{organization}/provisionerkeys/{provisionerkey}` | DELETE | `delete_provisioner_key` | `complete` | Full implementation with store/service calls |
| `/provisionerkeys/{provisionerkey}` | GET | `get_provisioner_key` | `complete` | Full implementation with store/service calls |

### IDP Sync

12/12 complete

| Route Path | Method | Handler Function | Status | Notes |
|------------|--------|------------------|--------|-------|
| `/organizations/{organization}/settings/idpsync/available-fields` | GET | `get_idpsync_available_fields` | `complete` | Full implementation with store/service calls |
| `/organizations/{organization}/settings/idpsync/field-values` | GET | `get_idpsync_field_values` | `complete` | Full implementation with store/service calls |
| `/organizations/{organization}/settings/idpsync/groups` | GET | `get_group_idpsync_settings` | `complete` | Full implementation with store/service calls |
| `/organizations/{organization}/settings/idpsync/groups` | PATCH | `patch_group_idpsync_settings` | `complete` | Full implementation with store/service calls |
| `/organizations/{organization}/settings/idpsync/groups/config` | PATCH | `patch_group_idpsync_config` | `complete` | Full implementation with store/service calls |
| `/organizations/{organization}/settings/idpsync/groups/mapping` | PATCH | `patch_group_idpsync_mapping` | `complete` | Full implementation with store/service calls |
| `/organizations/{organization}/settings/idpsync/roles` | GET | `get_role_idpsync_settings` | `complete` | Full implementation with store/service calls |
| `/organizations/{organization}/settings/idpsync/roles` | PATCH | `patch_role_idpsync_settings` | `complete` | Full implementation with store/service calls |
| `/organizations/{organization}/settings/idpsync/roles/config` | PATCH | `patch_role_idpsync_config` | `complete` | Full implementation with store/service calls |
| `/organizations/{organization}/settings/idpsync/roles/mapping` | PATCH | `patch_role_idpsync_mapping` | `complete` | Full implementation with store/service calls |
| `/settings/idpsync/available-fields` | GET | `get_site_idpsync_available_fields` | `complete` | Full implementation with store/service calls |
| `/settings/idpsync/field-values` | GET | `get_site_idpsync_field_values` | `complete` | Full implementation with store/service calls |

### IDP Sync — Organization

3/3 complete

| Route Path | Method | Handler Function | Status | Notes |
|------------|--------|------------------|--------|-------|
| `/settings/idpsync/organization` | GET | `get_org_idpsync_settings` | `complete` | Full implementation with store/service calls |
| `/settings/idpsync/organization` | PATCH | `patch_org_idpsync_settings` | `complete` | Full implementation with store/service calls |
| `/settings/idpsync/organization/config` | PATCH | `patch_org_idpsync_config` | `complete` | Full implementation with store/service calls |
| `/settings/idpsync/organization/mapping` | PATCH | `patch_org_idpsync_mapping` | `complete` | Full implementation with store/service calls |

### AI Bridge

2/2 complete

| Route Path | Method | Handler Function | Status | Notes |
|------------|--------|------------------|--------|-------|
| `/aibridge/interceptions` | GET | `get_aibridge_interceptions` | `complete` | Full implementation with store/service calls |
| `/aibridge/models` | GET | `get_aibridge_models` | `complete` | Full implementation with store/service calls |

### Connection Log

1/1 complete

| Route Path | Method | Handler Function | Status | Notes |
|------------|--------|------------------|--------|-------|
| `/connectionlog` | GET | `list_connection_logs` | `complete` | Full implementation with store/service calls |

### OAuth2 Protocol (Enterprise)

7/8 complete

| Route Path | Method | Handler Function | Status | Notes |
|------------|--------|------------------|--------|-------|
| `/.well-known/oauth-authorization-server` | GET | `get_oauth_authorization_server_metadata` | `complete` | Full implementation with store/service calls |
| `/.well-known/oauth-protected-resource` | GET | `get_oauth_protected_resource_metadata` | `complete` | Full implementation with store/service calls |
| `/oauth2/clients/{client_id}` | DELETE | `delete_oauth2_client` | `complete` | Full implementation with store/service calls |
| `/oauth2/clients/{client_id}` | GET | `get_oauth2_client` | `complete` | Full implementation with store/service calls |
| `/oauth2/clients/{client_id}` | PUT | `put_oauth2_client` | `complete` | Full implementation with store/service calls |
| `/oauth2/register` | POST | `post_oauth2_register` | `complete` | Full implementation with store/service calls |
| `/oauth2/revoke` | POST | `post_oauth2_revoke` | `stub-partial` | Returns error — token revocation not yet implemented |
| `/oauth2/tokens` | DELETE | `delete_oauth2_tokens` | `complete` | Full implementation with store/service calls |

### Workspace Proxies

4/10 complete

| Route Path | Method | Handler Function | Status | Notes |
|------------|--------|------------------|--------|-------|
| `/workspaceproxies` | GET | `list_workspace_proxies` | `complete` | Full implementation with store/service calls |
| `/workspaceproxies` | POST | `create_workspace_proxy` | `complete` | Full implementation with store/service calls |
| `/workspaceproxies/{workspaceproxy}` | DELETE | `delete_workspace_proxy` | `complete` | Full implementation with store/service calls |
| `/workspaceproxies/{workspaceproxy}` | GET | `get_workspace_proxy` | `complete` | Full implementation with store/service calls |
| `/workspaceproxies/{workspaceproxy}` | PATCH | `patch_workspace_proxy` | `complete` | Full implementation with store/service calls |
| `/workspaceproxies/me/register` | POST | `workspace_proxy_register` | `stub-partial` | Validates request, returns minimal registration response |
| `/workspaceproxies/me/deregister` | POST | `workspace_proxy_deregister` | `stub-partial` | Acknowledges but does not update replica table |
| `/workspaceproxies/me/coordinate` | GET | `workspace_proxy_coordinate` | `stub-partial` | WebSocket upgrade then immediate close — tailnet coordination not implemented |
| `/workspaceproxies/me/crypto-keys` | GET | `workspace_proxy_crypto_keys` | `stub-partial` | Returns empty key set |
| `/workspaceproxies/me/issue-signed-app-token` | POST | `workspace_proxy_issue_signed_app_token` | `stub-partial` | Returns placeholder — WorkspaceAppsProvider not yet ported |
| `/workspaceproxies/me/app-stats` | POST | `workspace_proxy_app_stats` | `stub-partial` | Accepts request but does not forward stats |

### Replicas

1/1 complete

| Route Path | Method | Handler Function | Status | Notes |
|------------|--------|------------------|--------|-------|
| `/replicas` | GET | `list_replicas` | `complete` | Full implementation with store/service calls |

### Provisioner Daemon Serve

1/1 complete

| Route Path | Method | Handler Function | Status | Notes |
|------------|--------|------------------|--------|-------|
| `/organizations/{organization}/provisionerdaemons/serve` | GET | `provisioner_daemon_serve` | `complete` | Full implementation with store/service calls |

### Workspace Sharing

2/2 complete

| Route Path | Method | Handler Function | Status | Notes |
|------------|--------|------------------|--------|-------|
| `/organizations/{organization}/settings/workspace-sharing` | GET | `get_workspace_sharing_settings` | `complete` | Full implementation with store/service calls |
| `/organizations/{organization}/settings/workspace-sharing` | PATCH | `patch_workspace_sharing_settings` | `complete` | Full implementation with store/service calls |

### Quiet Hours

2/2 complete

| Route Path | Method | Handler Function | Status | Notes |
|------------|--------|------------------|--------|-------|
| `/users/{user}/quiet-hours` | GET | `get_user_quiet_hours` | `complete` | Full implementation with store/service calls |
| `/users/{user}/quiet-hours` | PUT | `put_user_quiet_hours` | `complete` | Full implementation with store/service calls |

### Reconnecting PTY Signed Token

1/1 complete

| Route Path | Method | Handler Function | Status | Notes |
|------------|--------|------------------|--------|-------|
| `/applications/reconnecting-pty-signed-token` | POST | `post_reconnecting_pty_signed_token` | `complete` | Full implementation with store/service calls |

### Prebuilds

2/2 complete

| Route Path | Method | Handler Function | Status | Notes |
|------------|--------|------------------|--------|-------|
| `/prebuilds/settings` | GET | `get_prebuilds_settings` | `complete` | Full implementation with store/service calls |
| `/prebuilds/settings` | PUT | `put_prebuilds_settings` | `complete` | Full implementation with store/service calls |

### External Agent Credentials

1/1 complete

| Route Path | Method | Handler Function | Status | Notes |
|------------|--------|------------------|--------|-------|
| `/workspaces/{workspace}/external-agent/{agent}/credentials` | GET | `get_external_agent_credentials` | `complete` | Full implementation with store/service calls |

### Custom Roles (Enterprise)

3/3 complete

| Route Path | Method | Handler Function | Status | Notes |
|------------|--------|------------------|--------|-------|
| `/organizations/{organization}/members/roles` | POST | `post_org_role` | `complete` | Full implementation with store/service calls |
| `/organizations/{organization}/members/roles` | PUT | `put_org_role` | `complete` | Full implementation with store/service calls |
| `/organizations/{organization}/members/roles/{rolename}` | DELETE | `delete_org_role` | `complete` | Full implementation with store/service calls |

---

## Stub Summary

### `stub-501` (5 routes)

These routes accept the request (including WebSocket upgrade) but immediately return 501 or close the connection. They require complex subsystems (tailnet coordination, PTY relay) that are not yet ported.

| Route Path | Method | Reason |
|------------|--------|--------|
| `/debug/{user}/debug-link` | GET | Debug link generation not implemented |
| `/workspaceagents/{agent}/containers/watch` | GET | WebSocket container watch not implemented |
| `/workspaceagents/{agent}/coordinate` | GET | WebSocket tailnet coordination not implemented |
| `/workspaceagents/{agent}/pty` | GET | WebSocket PTY relay not implemented |
| `/workspaceagents/{agent}/watch-metadata-ws` | GET | WebSocket metadata watch not implemented |

### `stub-partial` (17 routes)

These routes accept requests and return valid responses, but with simplified/hardcoded data rather than full Go-equivalent behavior.

| Route Path | Method | Reason |
|------------|--------|--------|
| `/auth/scopes` | GET | Returns hardcoded scope list |
| `/buildinfo` | GET | Returns hardcoded build info |
| `/deployment/config` | GET | Returns hardcoded deployment config |
| `/deployment/ssh` | GET | Returns hardcoded SSH config |
| `/updatecheck` | GET | Returns hardcoded update response |
| `/users/oauth2/github/callback` | GET | GitHub OAuth not configured — returns disabled response |
| `/users/oauth2/github/device` | GET | GitHub OAuth not configured — returns disabled response |
| `/users/oidc/callback` | GET | OIDC not configured — returns disabled response |
| `/workspaceagents/me/external-auth` | GET | Agent external auth lookup is stub |
| `/templateversions/{ver}/dynamic-parameters/evaluate` | POST | Dynamic parameter evaluation is stub |
| `/oauth2/revoke` | POST | Token revocation returns error — not yet implemented |
| `/workspaceproxies/me/register` | POST | Validates request, returns minimal registration response |
| `/workspaceproxies/me/deregister` | POST | Acknowledges but does not update replica table |
| `/workspaceproxies/me/coordinate` | GET | WebSocket upgrade then immediate close |
| `/workspaceproxies/me/crypto-keys` | GET | Returns empty key set |
| `/workspaceproxies/me/issue-signed-app-token` | POST | Returns placeholder token |
| `/workspaceproxies/me/app-stats` | POST | Accepts but does not forward stats |
