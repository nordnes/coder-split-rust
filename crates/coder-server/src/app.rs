//! Router construction and HTTP handlers.

use std::{collections::HashMap, str::FromStr, sync::Arc};

use axum::{
    Json, Router,
    extract::{OriginalUri, Path, Query, State, rejection::JsonRejection},
    http::{
        HeaderMap, HeaderName, HeaderValue, StatusCode,
        header::{
            ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS,
            ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_TYPE, LOCATION,
        },
    },
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use coder_audit::{AuditAction, AuditEvent, AuditSink};
use coder_auth::{
    AuthService, AuthServiceError, AuthenticatedRequest, ExternalAuthService,
    ExternalAuthServiceError, OAUTH2_REDIRECT_COOKIE, OAUTH2_STATE_COOKIE, cookie_from_headers,
    supported_auth_methods,
};
use coder_connectivity::{HealthService, generate_git_ssh_key};
use coder_core::StorageError;
use coder_core::api::{
    CreateTemplateRequest, CreateTemplateVersionDryRunRequest, CreateTemplateVersionRequest,
    DAUEntry, DAUsResponse, MinimalUser, PatchTemplateVersionRequest, ProvisionerJobLog,
    ProvisionerJobResponse, ProvisionerJobStatus, TemplateExample, TemplateFilter,
    TemplateResponse, TemplateVersionExternalAuth, TemplateVersionParameter, TemplateVersionPreset,
    TemplateVersionPresetParameter, TemplateVersionResponse, TemplateVersionVariable,
    UpdateTemplateMeta, WorkspaceResource,
};
use coder_core::template::{
    CreateProvisionerJobInput, CreateTemplateInput, CreateTemplateStoreError,
    CreateTemplateVersionInput, ProvisionerJobRecord, TemplateListFilter, TemplateRecord,
    TemplateVersionListFilter, TemplateVersionRecord,
};
use coder_core::{
    ApiResponse, AppStore, AuditLogListFilter, AuthMethods, AuthenticatedUser,
    AvailableExperiments, BuildMetadata, ChangePasswordWithOneTimePasscodeRequest,
    ConvertLoginRequest, CreateFirstUserRequest, CreateFirstUserResponse,
    CreateTestAuditLogRequest, CreateTokenRequest, CreateUserRequestWithOrgs,
    DeploymentConfigResponse, ExternalApiKeyScopes, ExternalAuthDeviceExchangeRequest,
    GetUsersResponse, HealthSettings, HealthcheckReport, LoginType, LoginWithPasswordRequest,
    OrganizationMember, OrganizationMemberWithUserData, OrganizationResponse,
    PaginatedMembersResponse, PersistAuditLogInput, RequestOneTimePasscodeRequest, ServerConfig,
    SshConfigResponse, UpdateCheckResponse, UpdateRolesRequest,
    UpdateUserAppearanceSettingsRequest, UpdateUserPasswordRequest,
    UpdateUserPreferenceSettingsRequest, UpdateUserProfileRequest, UserAppearanceSettings,
    UserListFilter, UserParameter, UserPreferenceSettings, UserRecord, UserResponse,
    UserRolesResponse, UserStatus, ValidateUserPasswordRequest, ValidationError,
};
use coder_identity::{IdentityService, IdentityServiceError};
use coder_provisioner::{InitScriptError, render_init_script};
use coder_rbac::{Actor, ROLE_AUDITOR, ResourceKind};
use coder_workspaces::DeploymentStatsService;
use serde::Deserialize;
use serde_json::{Value, json};
use time::OffsetDateTime;
use tower_http::{
    normalize_path::NormalizePathLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer},
};
use tracing::debug;
use uuid::Uuid;

use crate::error::AppError;

const TIMING_ALLOW_ORIGIN: &str = "timing-allow-origin";
const BUILD_VERSION_HEADER: &str = "x-coder-build-version";
const SLIM_BUILD_MESSAGE: &str = "Slim build of Coder, does not contain the frontend static files.";
const PUBLIC_API_KEY_SCOPES: &[&str] = &[
    "audit_log:*",
    "audit_log:create",
    "audit_log:read",
    "api_key:*",
    "api_key:create",
    "api_key:delete",
    "api_key:read",
    "api_key:update",
    "coder:all",
    "coder:apikeys.manage_self",
    "coder:application_connect",
    "deployment_stats:*",
    "deployment_stats:read",
    "coder:templates.author",
    "coder:templates.build",
    "coder:workspaces.access",
    "coder:workspaces.create",
    "coder:workspaces.delete",
    "coder:workspaces.operate",
    "file:*",
    "file:create",
    "file:read",
    "organization:*",
    "organization:delete",
    "organization:read",
    "organization:update",
    "task:*",
    "task:create",
    "task:delete",
    "task:read",
    "task:update",
    "template:*",
    "template:create",
    "template:delete",
    "template:read",
    "template:update",
    "template:use",
    "user:read_personal",
    "user:update_personal",
    "user_secret:*",
    "user_secret:create",
    "user_secret:delete",
    "user_secret:read",
    "user_secret:update",
    "workspace:*",
    "workspace:application_connect",
    "workspace:create",
    "workspace:delete",
    "workspace:read",
    "workspace:ssh",
    "workspace:start",
    "workspace:stop",
    "workspace:update",
];
const VALID_HEALTH_SECTIONS: &[&str] = &[
    "DERP",
    "AccessURL",
    "Websocket",
    "Database",
    "WorkspaceProxy",
    "ProvisionerDaemons",
];
/// Shared application state for the HTTP router.
#[derive(Clone)]
pub struct AppState {
    /// Redacted runtime configuration and immutable startup settings.
    pub config: ServerConfig,
    /// Static build metadata for the running binary.
    pub build_metadata: BuildMetadata,
    /// Stable deployment identifier loaded during startup.
    pub deployment_id: Uuid,
    /// Backing store used by the current HTTP handlers.
    pub store: Arc<dyn AppStore>,
    /// Structured audit sink for mutating and auth-related routes.
    pub audit: Arc<dyn AuditSink>,
    auth: AuthService<Arc<dyn AppStore>>,
    identity: IdentityService<Arc<dyn AppStore>>,
    deployment_stats: Arc<DeploymentStatsService<Arc<dyn AppStore>>>,
    health: HealthService<Arc<dyn AppStore>>,
    external_auth: ExternalAuthService<Arc<dyn AppStore>>,
}

impl AppState {
    /// Builds application state with default shared clients and caches.
    pub fn new(
        config: ServerConfig,
        build_metadata: BuildMetadata,
        deployment_id: Uuid,
        store: Arc<dyn AppStore>,
        audit: Arc<dyn AuditSink>,
    ) -> Result<Self, reqwest::Error> {
        let auth = AuthService::new(store.clone());
        let identity = IdentityService::new(store.clone());
        let deployment_stats = DeploymentStatsService::new(store.clone());
        let health = HealthService::new(store.clone())?;
        let external_auth = ExternalAuthService::new(store.clone())?;

        Ok(Self {
            config,
            build_metadata,
            deployment_id,
            store,
            audit,
            auth,
            identity,
            deployment_stats,
            health,
            external_auth,
        })
    }
}

#[derive(Debug, Default, Deserialize)]
struct UsersQuery {
    #[serde(default)]
    q: String,
    status: Option<String>,
    limit: Option<u32>,
    offset: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
struct MembersQuery {
    #[serde(default)]
    q: String,
    limit: Option<u32>,
    offset: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
struct TokenListQuery {
    #[serde(default)]
    include_all: bool,
    #[serde(default)]
    include_expired: bool,
}

#[derive(Debug, Default, Deserialize)]
struct AuditQuery {
    #[serde(default)]
    q: String,
    limit: Option<u32>,
    offset: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
struct DebugHealthQuery {
    format: Option<String>,
    #[serde(default)]
    force: bool,
}

#[derive(Debug, Default, Deserialize)]
struct ExternalAuthCallbackQuery {
    code: Option<String>,
    state: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CspViolationReport {
    #[serde(rename = "csp-report")]
    report: HashMap<String, Value>,
}

/// Query parameters for listing template versions.
#[derive(Clone, Debug, Default, Deserialize)]
struct TemplateVersionsQuery {
    #[serde(default)]
    include_archived: Option<bool>,
    #[serde(default)]
    limit: Option<u32>,
    #[serde(default)]
    offset: Option<u32>,
}

/// Builds the Axum router for the current Rust backend slice.
pub fn build_router(state: AppState) -> Router {
    let request_id_header = HeaderName::from_static("x-request-id");

    Router::new()
        .route("/", get(server_root))
        .route("/healthz", get(healthz))
        .route("/latency-check", get(latency_check))
        .route(
            "/external-auth/{externalauth}/callback",
            get(get_external_auth_callback_by_id),
        )
        .route(
            "/gitauth/{externalauth}/callback",
            get(get_external_auth_callback_by_id),
        )
        .nest(
            "/api/v2",
            Router::new()
                .route("/", get(api_root))
                .route("/audit", get(list_audit_logs))
                .route("/audit/testgenerate", post(post_generate_test_audit_log))
                .route("/auth/scopes", get(list_api_key_scopes))
                .route("/buildinfo", get(build_info))
                .route("/csp/reports", post(post_csp_report))
                .route("/deployment/config", get(deployment_config))
                .route("/deployment/stats", get(deployment_stats))
                .route("/deployment/ssh", get(deployment_ssh))
                .route("/debug/health", get(debug_health))
                .route(
                    "/debug/health/settings",
                    get(get_health_settings).put(put_health_settings),
                )
                .route("/experiments", get(get_enabled_experiments))
                .route("/experiments/available", get(get_available_experiments))
                .route("/external-auth", get(list_external_auths))
                .route(
                    "/external-auth/{externalauth}",
                    get(get_external_auth_by_id).delete(delete_external_auth_by_id),
                )
                .route(
                    "/external-auth/{externalauth}/device",
                    get(get_external_auth_device_by_id).post(post_external_auth_device_exchange),
                )
                .route("/debug/{user}/debug-link", get(get_user_debug_link))
                .route("/organizations", get(list_organizations))
                .route("/init-script/{os}/{arch}", get(get_init_script))
                .route("/organizations/{organization}", get(get_organization))
                .route(
                    "/organizations/{organization}/members/roles",
                    get(list_organization_roles),
                )
                .route(
                    "/organizations/{organization}/members",
                    get(list_organization_members),
                )
                .route(
                    "/organizations/{organization}/paginated-members",
                    get(list_paginated_organization_members),
                )
                .route(
                    "/organizations/{organization}/members/{user}",
                    get(get_organization_member)
                        .post(post_organization_member)
                        .delete(delete_organization_member),
                )
                .route(
                    "/organizations/{organization}/members/{user}/roles",
                    put(put_organization_member_roles),
                )
                .route("/users", get(list_users).post(post_user))
                .route("/users/authmethods", get(auth_methods))
                .route("/updatecheck", get(update_check))
                .route("/users/first", get(get_first_user).post(post_first_user))
                .route("/users/login", post(login_with_password))
                .route("/users/logout", post(logout))
                .route(
                    "/users/validate-password",
                    post(post_validate_user_password),
                )
                .route("/users/otp/request", post(post_request_one_time_passcode))
                .route(
                    "/users/otp/change-password",
                    post(post_change_password_with_one_time_passcode),
                )
                .route(
                    "/users/oauth2/github/device",
                    get(get_github_oauth_device_disabled),
                )
                .route(
                    "/users/oauth2/github/callback",
                    get(get_github_oauth_callback_disabled),
                )
                .route("/users/oidc/callback", get(get_oidc_callback_disabled))
                .route("/users/roles", get(list_site_roles))
                .route("/users/{user}/keys", post(create_session_api_key))
                .route(
                    "/users/{user}/keys/{keyid}",
                    get(get_api_key).delete(delete_api_key),
                )
                .route("/users/{user}/keys/{keyid}/expire", put(expire_api_key))
                .route(
                    "/users/{user}/keys/tokens",
                    get(list_token_api_keys).post(create_token_api_key),
                )
                .route(
                    "/users/{user}/keys/tokens/tokenconfig",
                    get(get_token_config),
                )
                .route(
                    "/users/{user}/keys/tokens/{keyname}",
                    get(get_api_key_by_name),
                )
                .route("/users/{user}/organizations", get(list_user_organizations))
                .route(
                    "/users/{user}/organizations/{organizationname}",
                    get(get_user_organization_by_name),
                )
                .route(
                    "/users/{user}/roles",
                    get(get_user_roles).put(put_user_roles),
                )
                .route("/users/{user}/login-type", get(get_user_login_type))
                .route(
                    "/users/{user}/gitsshkey",
                    get(get_user_git_ssh_key).put(put_user_git_ssh_key),
                )
                .route("/users/{user}/profile", put(put_user_profile))
                .route(
                    "/users/{user}/autofill-parameters",
                    get(get_user_autofill_parameters),
                )
                .route(
                    "/users/{user}/status/suspend",
                    put(put_suspend_user_account),
                )
                .route(
                    "/users/{user}/status/activate",
                    put(put_activate_user_account),
                )
                .route(
                    "/users/{user}/appearance",
                    get(get_user_appearance).put(put_user_appearance),
                )
                .route(
                    "/users/{user}/preferences",
                    get(get_user_preferences).put(put_user_preferences),
                )
                .route("/users/{user}/password", put(put_user_password))
                .route("/users/{user}/convert-login", post(post_convert_login))
                .route("/users/{user}", get(get_user).delete(delete_user))
                // ----- Template routes -----
                .route(
                    "/organizations/{organization}/templates",
                    get(list_org_templates).post(post_org_template),
                )
                .route(
                    "/organizations/{organization}/templates/{templatename}",
                    get(get_org_template_by_name),
                )
                .route(
                    "/organizations/{organization}/templates/{templatename}/versions/{templateversionname}",
                    get(get_org_template_version_by_name),
                )
                .route(
                    "/organizations/{organization}/templateversions",
                    post(post_org_template_version),
                )
                .route(
                    "/templates/{template}",
                    get(get_template).delete(delete_template).patch(patch_template),
                )
                .route("/templates/{template}/daus", get(get_template_daus))
                .route(
                    "/templates/{template}/examples",
                    get(get_template_examples),
                )
                .route(
                    "/templates/{template}/versions",
                    get(list_template_versions),
                )
                .route(
                    "/templates/{template}/versions/{templateversionname}",
                    get(get_template_version_by_name),
                )
                .route(
                    "/templateversions/{templateversion}",
                    get(get_template_version).patch(patch_template_version),
                )
                .route(
                    "/templateversions/{templateversion}/archive",
                    post(post_archive_template_version),
                )
                .route(
                    "/templateversions/{templateversion}/cancel",
                    post(post_cancel_template_version),
                )
                .route(
                    "/templateversions/{templateversion}/dry-run",
                    post(post_template_version_dry_run),
                )
                .route(
                    "/templateversions/{templateversion}/dry-run/{jobid}",
                    get(get_template_version_dry_run).patch(patch_template_version_dry_run),
                )
                .route(
                    "/templateversions/{templateversion}/dry-run/{jobid}/cancel",
                    get(get_cancel_template_version_dry_run),
                )
                .route(
                    "/templateversions/{templateversion}/dry-run/{jobid}/logs",
                    get(get_template_version_dry_run_logs),
                )
                .route(
                    "/templateversions/{templateversion}/dry-run/{jobid}/resources",
                    get(get_template_version_dry_run_resources),
                )
                .route(
                    "/templateversions/{templateversion}/external-auth",
                    get(get_template_version_external_auth),
                )
                .route(
                    "/templateversions/{templateversion}/logs",
                    get(get_template_version_logs),
                )
                .route(
                    "/templateversions/{templateversion}/parameters",
                    get(get_template_version_parameters),
                )
                .route(
                    "/templateversions/{templateversion}/presets",
                    get(get_template_version_presets),
                )
                .route(
                    "/templateversions/{templateversion}/presets/{presetid}/parameters",
                    get(get_template_version_preset_parameters),
                )
                .route(
                    "/templateversions/{templateversion}/resources",
                    get(get_template_version_resources),
                )
                .route(
                    "/templateversions/{templateversion}/rich-parameters",
                    get(get_template_version_rich_parameters),
                )
                .route(
                    "/templateversions/{templateversion}/schema",
                    get(get_template_version_schema),
                )
                .route(
                    "/templateversions/{templateversion}/unarchive",
                    post(post_unarchive_template_version),
                )
                .route(
                    "/templateversions/{templateversion}/variables",
                    get(get_template_version_variables),
                ),
        )
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new())
                .on_response(DefaultOnResponse::new()),
        )
        .layer(PropagateRequestIdLayer::new(request_id_header.clone()))
        .layer(SetRequestIdLayer::new(request_id_header, MakeRequestUuid))
        .layer(NormalizePathLayer::trim_trailing_slash())
        .with_state(state)
}

async fn server_root() -> impl IntoResponse {
    (StatusCode::OK, SLIM_BUILD_MESSAGE)
}

async fn api_root() -> Json<ApiResponse> {
    Json(ApiResponse::ok("\u{1f44b}"))
}

async fn healthz(State(state): State<AppState>) -> Result<impl IntoResponse, AppError> {
    state.store.ping().await?;
    Ok((StatusCode::OK, "OK"))
}

async fn latency_check() -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static(TIMING_ALLOW_ORIGIN),
        HeaderValue::from_static("*"),
    );
    headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    headers.insert(ACCESS_CONTROL_ALLOW_HEADERS, HeaderValue::from_static("*"));
    headers.insert(
        ACCESS_CONTROL_ALLOW_CREDENTIALS,
        HeaderValue::from_static("false"),
    );
    headers.insert(ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static("*"));
    (StatusCode::OK, headers, "OK")
}

async fn build_info(State(state): State<AppState>) -> Json<coder_core::BuildInfoResponse> {
    Json(state.build_metadata.to_response(
        state.deployment_id,
        &state.config.access_url,
        state.config.telemetry_enabled,
    ))
}

async fn post_csp_report(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<CspViolationReport>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Json(report) = match payload {
        Ok(payload) => payload,
        Err(error) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error(
                    "Failed to read body, invalid json.",
                    error.body_text(),
                )),
            )
                .into_response());
        }
    };

    debug!(report = ?report.report, "CSP violation reported");

    Ok((StatusCode::OK, Json("ok")).into_response())
}

async fn deployment_config(State(state): State<AppState>) -> Json<DeploymentConfigResponse> {
    Json(DeploymentConfigResponse {
        config: state.config.public(),
        options: ServerConfig::supported_options(),
    })
}

async fn update_check(State(state): State<AppState>) -> Json<UpdateCheckResponse> {
    Json(UpdateCheckResponse {
        current: true,
        version: state.build_metadata.version.clone(),
        url: state.build_metadata.external_url.clone(),
    })
}

async fn get_init_script(
    State(state): State<AppState>,
    Path((os, arch)): Path<(String, String)>,
) -> Response {
    let script = match render_init_script(&os, &arch, state.config.access_url.as_str()) {
        Ok(script) => script,
        Err(InitScriptError::UnknownTarget { os, arch }) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::ok(format!("Unknown os/arch: {os}/{arch}"))),
            )
                .into_response();
        }
    };

    let mut response = (StatusCode::OK, script.body).into_response();
    response.headers_mut().insert(
        HeaderName::from_static("content-digest"),
        HeaderValue::from_str(&script.content_digest)
            .unwrap_or_else(|_| HeaderValue::from_static("sha256:")),
    );
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

async fn list_audit_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !can_view_operational_data(&context.actor) {
        return Ok(forbidden_response(
            "You are not authorized to view audit logs.",
        ));
    }

    let response = state
        .store
        .list_audit_logs(AuditLogListFilter {
            search: query.q,
            limit: query.limit.unwrap_or(50),
            offset: query.offset.unwrap_or_default(),
        })
        .await?;

    Ok((StatusCode::OK, Json(response)).into_response())
}

async fn post_generate_test_audit_log(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<CreateTestAuditLogRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !context.actor.is_owner() {
        return Ok(forbidden_response(
            "You are not authorized to generate audit logs.",
        ));
    }

    let Json(mut request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    if request.time.is_none() {
        request.time = Some(OffsetDateTime::now_utc());
    }

    let mut additional_fields = match request.additional_fields {
        Value::Null => json!({}),
        value => value,
    };
    if let Some(build_reason) = request.build_reason {
        if !additional_fields.is_object() {
            additional_fields = json!({});
        }
        if let Some(fields) = additional_fields.as_object_mut() {
            fields.insert("build_reason".to_owned(), Value::String(build_reason));
        }
    }

    state
        .store
        .insert_audit_log(PersistAuditLogInput {
            id: Uuid::new_v4(),
            request_id: request.request_id.or_else(|| Some(Uuid::new_v4())),
            time: request.time.unwrap_or_else(OffsetDateTime::now_utc),
            ip: String::new(),
            user_agent: String::new(),
            resource_type: request.resource_type.as_str().to_owned(),
            resource_id: request.resource_id.or_else(|| Some(Uuid::new_v4())),
            resource_target: context.user.username.clone(),
            resource_icon: String::new(),
            action: request.action.as_str().to_owned(),
            diff: json!({
                "foo": {
                    "old": "bar",
                    "new": "baz",
                    "secret": false
                }
            }),
            status_code: i32::from(StatusCode::OK.as_u16()),
            additional_fields,
            description: "generated test audit log".to_owned(),
            resource_link: String::new(),
            is_deleted: false,
            organization_id: request.organization_id,
            user_id: Some(context.user.id),
        })
        .await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn deployment_stats(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !can_view_operational_data(&context.actor) {
        return Ok(forbidden_response(
            "You are not authorized to view deployment stats.",
        ));
    }

    Ok((StatusCode::OK, Json(state.deployment_stats.get().await?)).into_response())
}

async fn deployment_ssh(State(state): State<AppState>) -> Json<SshConfigResponse> {
    Json(SshConfigResponse {
        hostname_prefix: state.config.ssh.hostname_prefix.clone(),
        hostname_suffix: state.config.ssh.hostname_suffix.clone(),
        ssh_config_options: state.config.ssh.ssh_config_options.clone(),
    })
}

async fn debug_health(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<DebugHealthQuery>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !can_view_operational_data(&context.actor) {
        return Ok(forbidden_response(
            "You are not authorized to view deployment health.",
        ));
    }

    let settings = state.store.health_settings().await?;
    let report = state
        .health
        .report(&state.config, &state.build_metadata, query.force)
        .await?;
    let report = apply_dismissed_health_settings(report, &settings);

    match query.format.as_deref() {
        None | Some("json") => Ok((StatusCode::OK, Json(report)).into_response()),
        Some("text") => Ok((
            StatusCode::OK,
            format!(
                "time: {}\nhealthy: {}\nderp: {}\naccess_url: {}\nwebsocket: {}\ndatabase: {}\n",
                report
                    .time
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
                report.healthy,
                report.derp.healthy,
                report.access_url.healthy,
                report.websocket.healthy,
                report.database.healthy,
            ),
        )
            .into_response()),
        Some(other) => Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::ok(format!("Invalid format option {other:?}."))),
        )
            .into_response()),
    }
}

async fn get_health_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !can_view_operational_data(&context.actor) {
        return Ok(forbidden_response(
            "You are not authorized to view health settings.",
        ));
    }

    Ok((StatusCode::OK, Json(state.store.health_settings().await?)).into_response())
}

async fn put_health_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<HealthSettings>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !context.actor.is_owner() {
        return Ok(forbidden_response(
            "You are not authorized to update health settings.",
        ));
    }

    let Json(settings) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    let invalid = settings
        .dismissed_healthchecks
        .iter()
        .filter(|section| !VALID_HEALTH_SECTIONS.contains(&section.as_str()))
        .map(|section| ValidationError {
            field: "dismissed_healthchecks".to_owned(),
            detail: format!("unsupported health section: {section}"),
        })
        .collect::<Vec<_>>();
    if !invalid.is_empty() {
        return Ok(validation_message_response(
            "Request body has invalid fields.",
            invalid,
        ));
    }

    let changed = state.store.upsert_health_settings(&settings).await?;
    if !changed {
        return Ok(StatusCode::NO_CONTENT.into_response());
    }

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::HealthSettings,
        Some(&context.user),
        None,
        "updated health settings",
    )
    .await;

    Ok((StatusCode::OK, Json(settings)).into_response())
}

async fn list_api_key_scopes() -> Json<ExternalApiKeyScopes> {
    Json(ExternalApiKeyScopes {
        external: PUBLIC_API_KEY_SCOPES
            .iter()
            .map(|scope| (*scope).to_owned())
            .collect(),
    })
}

async fn get_enabled_experiments(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    Ok(Json(Vec::<String>::new()).into_response())
}

async fn get_available_experiments(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    Ok(Json(AvailableExperiments { safe: Vec::new() }).into_response())
}

async fn auth_methods() -> Json<AuthMethods> {
    Json(supported_auth_methods())
}

async fn list_external_auths(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    Ok(Json(
        state
            .external_auth
            .list(&state.config.external_auth_providers, context.user.id)
            .await?,
    )
    .into_response())
}

async fn get_external_auth_by_id(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(provider): Path<String>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Some(config) = find_external_auth_provider(&state, &provider) else {
        return Ok(resource_not_found_response());
    };
    let response = state
        .external_auth
        .get(
            &state.config.external_auth_providers,
            context.user.id,
            &provider,
        )
        .await?;
    let Some(response) = response else {
        debug_assert!(config.id.eq_ignore_ascii_case(&provider));
        return Ok(resource_not_found_response());
    };

    Ok(Json(response).into_response())
}

async fn delete_external_auth_by_id(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(provider): Path<String>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Some(response) = state
        .external_auth
        .delete(
            &state.config.external_auth_providers,
            context.user.id,
            &provider,
        )
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    record_audit(
        &state,
        AuditAction::Delete,
        ResourceKind::ExternalAuth,
        Some(&context.user),
        Some(provider.clone()),
        "deleted external auth link",
    )
    .await;

    Ok((StatusCode::OK, Json(response)).into_response())
}

async fn get_external_auth_device_by_id(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(provider): Path<String>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Some(config) = find_external_auth_provider(&state, &provider) else {
        return Ok(resource_not_found_response());
    };
    if !config.device {
        return Ok(external_auth_device_flow_unsupported_response());
    }

    state
        .external_auth
        .authorize_device(config)
        .await
        .map(|device| (StatusCode::OK, Json(device)).into_response())
        .or_else(|error| handle_external_auth_error("Failed to authorize device.", error))
}

async fn post_external_auth_device_exchange(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(provider): Path<String>,
    payload: Result<Json<ExternalAuthDeviceExchangeRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Some(config) = find_external_auth_provider(&state, &provider) else {
        return Ok(resource_not_found_response());
    };
    if !config.device {
        return Ok(external_auth_device_flow_unsupported_response());
    }
    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    if request.device_code.trim().is_empty() {
        return Ok(validation_message_response(
            "Request body has invalid fields.",
            vec![ValidationError {
                field: "device_code".to_owned(),
                detail: "Missing value, this cannot be empty".to_owned(),
            }],
        ));
    }

    if let Err(error) = state
        .external_auth
        .exchange_device(config, context.user.id, &request)
        .await
    {
        return handle_external_auth_error("Failed to exchange device code.", error);
    }

    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn get_external_auth_callback_by_id(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(provider): Path<String>,
    Query(query): Query<ExternalAuthCallbackQuery>,
) -> Result<Response, AppError> {
    let Some(config) = find_external_auth_provider(&state, &provider) else {
        return Ok(resource_not_found_response());
    };
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(redirect_to_login_response(
            &uri,
            "Missing or invalid session token.",
        ));
    };
    let Some(state_value) = query.state.filter(|value| !value.trim().is_empty()) else {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::ok("State must be provided.")),
        )
            .into_response());
    };
    let Some(state_cookie) = cookie_from_headers(&headers, OAUTH2_STATE_COOKIE) else {
        return Ok(unauthorized_response(format!(
            "Cookie {OAUTH2_STATE_COOKIE:?} must be provided."
        )));
    };
    if state_cookie != state_value {
        return Ok(unauthorized_response("State mismatched."));
    }
    let Some(code) = query.code.filter(|value| !value.trim().is_empty()) else {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::ok("Code must be provided.")),
        )
            .into_response());
    };

    if let Err(error) = state
        .external_auth
        .exchange_callback(config, context.user.id, &code)
        .await
    {
        return handle_external_auth_error("Failed exchanging OAuth code.", error);
    }

    let redirect = cookie_from_headers(&headers, OAUTH2_REDIRECT_COOKIE)
        .map(|value| sanitize_redirect_uri(&value))
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| format!("/external-auth/{provider}?redirected=true"));

    let mut response = StatusCode::TEMPORARY_REDIRECT.into_response();
    response.headers_mut().insert(
        LOCATION,
        HeaderValue::from_str(&redirect).unwrap_or_else(|_| HeaderValue::from_static("/")),
    );
    Ok(response)
}

async fn get_first_user(State(state): State<AppState>) -> Result<Response, AppError> {
    let exists = state.auth.first_user_exists().await?;
    let body = if exists {
        ApiResponse::ok("The initial user has already been created!")
    } else {
        ApiResponse::ok("The initial user has not been created!")
    };
    let status = if exists {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    };

    Ok((
        status,
        build_version_headers(&state.build_metadata.version),
        Json(body),
    )
        .into_response())
}

async fn post_first_user(
    State(state): State<AppState>,
    payload: Result<Json<CreateFirstUserRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    match state.auth.create_first_user(&request).await {
        Ok(created) => {
            record_audit(
                &state,
                AuditAction::Create,
                ResourceKind::User,
                None,
                Some(created.user_id.to_string()),
                "bootstrapped first user",
            )
            .await;

            Ok((
                StatusCode::CREATED,
                Json(CreateFirstUserResponse {
                    user_id: created.user_id,
                    organization_id: created.organization_id,
                }),
            )
                .into_response())
        }
        Err(error) => handle_auth_error(error),
    }
}

async fn login_with_password(
    State(state): State<AppState>,
    payload: Result<Json<LoginWithPasswordRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let outcome = match state.auth.login_with_password(&request).await {
        Ok(outcome) => outcome,
        Err(error) => return handle_auth_error(error),
    };
    record_audit(
        &state,
        AuditAction::Login,
        ResourceKind::Authentication,
        Some(&outcome.user),
        Some(outcome.user.id.to_string()),
        "authenticated with password",
    )
    .await;

    Ok((StatusCode::CREATED, Json(outcome.response)).into_response())
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    state.auth.logout(&context.session_token).await?;
    record_audit(
        &state,
        AuditAction::Logout,
        ResourceKind::Authentication,
        Some(&context.user),
        Some(context.user.id.to_string()),
        "logged out",
    )
    .await;

    Ok((StatusCode::OK, Json(ApiResponse::ok("Logged out!"))).into_response())
}

async fn post_validate_user_password(
    State(state): State<AppState>,
    payload: Result<Json<ValidateUserPasswordRequest>, JsonRejection>,
) -> Response {
    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return invalid_json_response(error),
    };

    (
        StatusCode::OK,
        Json(state.auth.validate_user_password(&request)),
    )
        .into_response()
}

async fn post_request_one_time_passcode(
    State(state): State<AppState>,
    payload: Result<Json<RequestOneTimePasscodeRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    if let Err(error) = state.auth.request_one_time_passcode(&request).await {
        return handle_auth_error(error);
    }

    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn post_change_password_with_one_time_passcode(
    State(state): State<AppState>,
    payload: Result<Json<ChangePasswordWithOneTimePasscodeRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let user_id = match state
        .auth
        .change_password_with_one_time_passcode(&request)
        .await
    {
        Ok(user_id) => user_id,
        Err(error) => return handle_auth_error(error),
    };

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::User,
        None,
        Some(user_id.to_string()),
        "changed password with one-time passcode",
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn get_github_oauth_device_disabled() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ApiResponse::ok("GitHub OAuth2 is not enabled.")),
    )
        .into_response()
}

async fn get_github_oauth_callback_disabled() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ApiResponse::ok("GitHub OAuth2 is not enabled.")),
    )
        .into_response()
}

async fn get_oidc_callback_disabled() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ApiResponse::ok("OIDC is not enabled.")),
    )
        .into_response()
}

async fn get_user_debug_link(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(requested_user): Path<String>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Some(target_user) = resolve_user(&state, &requested_user, &context.user).await? else {
        return Ok(not_found_response("User not found."));
    };
    if context.user.username != target_user.username && !context.actor.is_owner() {
        return Ok(forbidden_response(
            "You are not authorized to inspect this user.",
        ));
    }
    if target_user.login_type != LoginType::Oidc {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::ok("User is not an OIDC user.")),
        )
            .into_response());
    }

    Ok(not_implemented_response(
        "OIDC debug context is not yet available in the Rust backend.",
    ))
}

async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<UsersQuery>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !context.actor.can_list_users() {
        return Ok(forbidden_response("You are not authorized to list users."));
    }

    let status = match query.status.as_deref() {
        Some(value) => match UserStatus::from_str(value) {
            Ok(status) => Some(status),
            Err(error) => {
                return Ok(validation_response(vec![ValidationError {
                    field: "status".to_owned(),
                    detail: error.to_string(),
                }]));
            }
        },
        None => None,
    };

    let (users, count) = match state
        .identity
        .list_users(
            &context.actor,
            UserListFilter {
                search: query.q,
                status,
                limit: query.limit.unwrap_or_default(),
                offset: query.offset.unwrap_or_default(),
            },
        )
        .await
    {
        Ok(result) => result,
        Err(error) => return handle_identity_error(error),
    };

    Ok((
        StatusCode::OK,
        Json(GetUsersResponse {
            users: users.into_iter().map(UserResponse::from).collect(),
            count,
        }),
    )
        .into_response())
}

async fn post_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<CreateUserRequestWithOrgs>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    let user = match state.identity.create_user(&context.actor, &request).await {
        Ok(user) => user,
        Err(error) => return handle_identity_error(error),
    };

    record_audit(
        &state,
        AuditAction::Create,
        ResourceKind::User,
        Some(&context.user),
        Some(user.id.to_string()),
        "created user",
    )
    .await;

    Ok((StatusCode::CREATED, Json(UserResponse::from(user))).into_response())
}

async fn get_user_login_type(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let response = match state
        .auth
        .get_user_login_type(&context.actor, &context.user, &user)
        .await
    {
        Ok(response) => response,
        Err(error) => return handle_auth_error(error),
    };

    Ok((StatusCode::OK, Json(response)).into_response())
}

async fn get_user_git_ssh_key(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Some(target_user) = resolve_user(&state, &user, &context.user).await? else {
        return Ok(not_found_response("User not found."));
    };
    if !context.actor.can_access_user(target_user.id) {
        return Ok(not_found_response("User not found."));
    }

    let key = match state.store.find_git_ssh_key(target_user.id).await? {
        Some(key) => key,
        None => match store_new_git_ssh_key(&state, &target_user).await {
            Ok(key) => key,
            Err(error) => {
                return Ok((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiResponse::error(
                        "Internal error generating a new SSH keypair.",
                        error,
                    )),
                )
                    .into_response());
            }
        },
    };

    Ok((
        StatusCode::OK,
        Json(coder_core::GitSshKeyResponse {
            user_id: key.user_id,
            created_at: key.created_at,
            updated_at: key.updated_at,
            public_key: key.public_key,
        }),
    )
        .into_response())
}

async fn put_user_git_ssh_key(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Some(target_user) = resolve_user(&state, &user, &context.user).await? else {
        return Ok(not_found_response("User not found."));
    };
    if !context.actor.can_access_user(target_user.id) {
        return Ok(not_found_response("User not found."));
    }

    let key = match store_new_git_ssh_key(&state, &target_user).await {
        Ok(key) => key,
        Err(error) => {
            return Ok((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error(
                    "Internal error generating a new SSH keypair.",
                    error,
                )),
            )
                .into_response());
        }
    };

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::GitSshKey,
        Some(&context.user),
        Some(target_user.id.to_string()),
        "regenerated git ssh key",
    )
    .await;

    Ok((
        StatusCode::OK,
        Json(coder_core::GitSshKeyResponse {
            user_id: key.user_id,
            created_at: key.created_at,
            updated_at: key.updated_at,
            public_key: key.public_key,
        }),
    )
        .into_response())
}

async fn get_user_autofill_parameters(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Some(target_user) = resolve_user(&state, &user, &context.user).await? else {
        return Ok(not_found_response("User not found."));
    };
    if context.user.username != target_user.username && !context.actor.is_owner() {
        return Ok(forbidden_response(
            "You are not authorized to inspect this user.",
        ));
    }

    let mut validations = Vec::new();
    match query.get("template_id") {
        Some(template_id) if !template_id.is_empty() => {
            if let Err(error) = Uuid::parse_str(template_id) {
                validations.push(ValidationError {
                    field: "template_id".to_owned(),
                    detail: error.to_string(),
                });
            }
        }
        _ => validations.push(ValidationError {
            field: "template_id".to_owned(),
            detail: "Missing value, this cannot be empty".to_owned(),
        }),
    }

    for key in query.keys() {
        if key != "template_id" {
            validations.push(ValidationError {
                field: key.clone(),
                detail: "unknown query parameter".to_owned(),
            });
        }
    }

    if !validations.is_empty() {
        return Ok(validation_message_response(
            "Invalid query parameters.",
            validations,
        ));
    }

    Ok(Json(Vec::<UserParameter>::new()).into_response())
}

async fn put_user_profile(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<UpdateUserProfileRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    let updated_user = match state
        .identity
        .update_user_profile(&context.actor, &context.user, &user, &request)
        .await
    {
        Ok(user) => user,
        Err(error) => return handle_identity_error(error),
    };

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::User,
        Some(&context.user),
        Some(updated_user.id.to_string()),
        "updated user profile",
    )
    .await;

    Ok((StatusCode::OK, Json(UserResponse::from(updated_user))).into_response())
}

async fn put_suspend_user_account(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    put_user_status(state, user, headers, UserStatus::Suspended).await
}

async fn put_activate_user_account(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    put_user_status(state, user, headers, UserStatus::Active).await
}

async fn put_user_status(
    state: AppState,
    user: String,
    headers: HeaderMap,
    status: UserStatus,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let updated_user = match state
        .identity
        .update_user_status(&context.actor, &context.user, &user, status)
        .await
    {
        Ok(user) => user,
        Err(error) => return handle_identity_error(error),
    };

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::User,
        Some(&context.user),
        Some(updated_user.id.to_string()),
        "updated user status",
    )
    .await;

    Ok((StatusCode::OK, Json(UserResponse::from(updated_user))).into_response())
}

async fn get_user_appearance(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let settings = match state
        .identity
        .get_user_appearance(&context.actor, &context.user, &user)
        .await
    {
        Ok(settings) => settings,
        Err(error) => return handle_identity_error(error),
    };
    Ok((
        StatusCode::OK,
        Json(UserAppearanceSettings {
            theme_preference: settings.theme_preference,
            terminal_font: settings.terminal_font,
        }),
    )
        .into_response())
}

async fn put_user_appearance(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<UpdateUserAppearanceSettingsRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    let (target_user_id, settings) = match state
        .identity
        .update_user_appearance(&context.actor, &context.user, &user, &request)
        .await
    {
        Ok(settings) => settings,
        Err(error) => return handle_identity_error(error),
    };

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::User,
        Some(&context.user),
        Some(target_user_id.to_string()),
        "updated user appearance settings",
    )
    .await;

    Ok((
        StatusCode::OK,
        Json(UserAppearanceSettings {
            theme_preference: settings.theme_preference,
            terminal_font: settings.terminal_font,
        }),
    )
        .into_response())
}

async fn get_user_preferences(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let settings = match state
        .identity
        .get_user_preferences(&context.actor, &context.user, &user)
        .await
    {
        Ok(settings) => settings,
        Err(error) => return handle_identity_error(error),
    };
    Ok((
        StatusCode::OK,
        Json(UserPreferenceSettings {
            task_notification_alert_dismissed: settings.task_notification_alert_dismissed,
        }),
    )
        .into_response())
}

async fn put_user_preferences(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<UpdateUserPreferenceSettingsRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    let (target_user_id, settings) = match state
        .identity
        .update_user_preferences(&context.actor, &context.user, &user, &request)
        .await
    {
        Ok(settings) => settings,
        Err(error) => return handle_identity_error(error),
    };

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::User,
        Some(&context.user),
        Some(target_user_id.to_string()),
        "updated user preference settings",
    )
    .await;

    Ok((
        StatusCode::OK,
        Json(UserPreferenceSettings {
            task_notification_alert_dismissed: settings.task_notification_alert_dismissed,
        }),
    )
        .into_response())
}

async fn put_user_password(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<UpdateUserPasswordRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    let target_user_id = match state
        .auth
        .update_user_password(&context.actor, &context.user, &user, &request)
        .await
    {
        Ok(target_user_id) => target_user_id,
        Err(error) => return handle_auth_error(error),
    };

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::User,
        Some(&context.user),
        Some(target_user_id.to_string()),
        "updated user password",
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn post_convert_login(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<ConvertLoginRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    let message = match state
        .auth
        .convert_login(&context.user, &user, &request)
        .await
    {
        Ok(message) => message,
        Err(error) => return handle_auth_error(error),
    };
    Ok((StatusCode::BAD_REQUEST, Json(ApiResponse::ok(message))).into_response())
}

async fn get_user(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let target_user = match state
        .identity
        .get_user(&context.actor, &context.user, &user)
        .await
    {
        Ok(user) => user,
        Err(error) => return handle_identity_error(error),
    };

    Ok((StatusCode::OK, Json(UserResponse::from(target_user))).into_response())
}

async fn list_site_roles(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let roles = match state.identity.list_site_roles(&context.actor) {
        Ok(roles) => roles,
        Err(error) => return handle_identity_error(error),
    };

    Ok((StatusCode::OK, Json(roles)).into_response())
}

async fn get_user_roles(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let (target_user, organization_roles) = match state
        .identity
        .get_user_roles(&context.actor, &context.user, &user)
        .await
    {
        Ok(result) => result,
        Err(error) => return handle_identity_error(error),
    };

    Ok((
        StatusCode::OK,
        Json(UserRolesResponse {
            roles: target_user
                .roles
                .into_iter()
                .map(|role| role.name)
                .collect(),
            organization_roles,
        }),
    )
        .into_response())
}

async fn put_user_roles(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<UpdateRolesRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    let updated_user = match state
        .identity
        .update_user_roles(&context.actor, &context.user, &user, &request)
        .await
    {
        Ok(user) => user,
        Err(error) => return handle_identity_error(error),
    };

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::User,
        Some(&context.user),
        Some(updated_user.id.to_string()),
        "updated user roles",
    )
    .await;

    Ok((StatusCode::OK, Json(UserResponse::from(updated_user))).into_response())
}

async fn list_organizations(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let organizations = match state.identity.list_organizations(&context.actor).await {
        Ok(organizations) => organizations,
        Err(error) => return handle_identity_error(error),
    };

    Ok((
        StatusCode::OK,
        Json(
            organizations
                .into_iter()
                .map(OrganizationResponse::from)
                .collect::<Vec<_>>(),
        ),
    )
        .into_response())
}

async fn get_organization(
    State(state): State<AppState>,
    Path(organization): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let target_organization = match state
        .identity
        .get_organization(&context.actor, &organization)
        .await
    {
        Ok(organization) => organization,
        Err(error) => return handle_identity_error(error),
    };

    Ok((
        StatusCode::OK,
        Json(OrganizationResponse::from(target_organization)),
    )
        .into_response())
}

async fn list_organization_roles(
    State(state): State<AppState>,
    Path(organization): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let roles = match state
        .identity
        .list_organization_roles(&context.actor, &organization)
        .await
    {
        Ok(roles) => roles,
        Err(error) => return handle_identity_error(error),
    };

    Ok((StatusCode::OK, Json(roles)).into_response())
}

async fn list_organization_members(
    State(state): State<AppState>,
    Path(organization): Path<String>,
    headers: HeaderMap,
    Query(query): Query<MembersQuery>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let members = match state
        .identity
        .list_organization_members(
            &context.actor,
            &organization,
            query.q,
            query.limit.unwrap_or_default(),
            query.offset.unwrap_or_default(),
        )
        .await
    {
        Ok(members) => members,
        Err(error) => return handle_identity_error(error),
    };

    Ok((
        StatusCode::OK,
        Json(
            members
                .into_iter()
                .map(OrganizationMemberWithUserData::from)
                .collect::<Vec<_>>(),
        ),
    )
        .into_response())
}

async fn list_paginated_organization_members(
    State(state): State<AppState>,
    Path(organization): Path<String>,
    headers: HeaderMap,
    Query(query): Query<MembersQuery>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let (members, count) = match state
        .identity
        .list_organization_members_page(
            &context.actor,
            &organization,
            query.q,
            query.limit.unwrap_or_default(),
            query.offset.unwrap_or_default(),
        )
        .await
    {
        Ok(result) => result,
        Err(error) => return handle_identity_error(error),
    };

    Ok((
        StatusCode::OK,
        Json(PaginatedMembersResponse {
            members: members
                .into_iter()
                .map(OrganizationMemberWithUserData::from)
                .collect(),
            count,
        }),
    )
        .into_response())
}

async fn get_organization_member(
    State(state): State<AppState>,
    Path((organization, user)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let member = match state
        .identity
        .get_organization_member(&context.actor, &context.user, &organization, &user)
        .await
    {
        Ok(member) => member,
        Err(error) => return handle_identity_error(error),
    };

    Ok((
        StatusCode::OK,
        Json(OrganizationMemberWithUserData::from(member)),
    )
        .into_response())
}

async fn post_organization_member(
    State(state): State<AppState>,
    Path((organization, user)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let member = match state
        .identity
        .create_organization_member(&context.actor, &context.user, &organization, &user)
        .await
    {
        Ok(member) => member,
        Err(error) => return handle_identity_error(error),
    };

    record_audit(
        &state,
        AuditAction::Create,
        ResourceKind::OrganizationMember,
        Some(&context.user),
        Some(format!("{}:{}", member.organization_id, member.user_id)),
        "added organization member",
    )
    .await;

    Ok((
        StatusCode::OK,
        Json(OrganizationMemberWithUserData::from(member)),
    )
        .into_response())
}

async fn delete_organization_member(
    State(state): State<AppState>,
    Path((organization, user)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let (organization_id, user_id) = match state
        .identity
        .delete_organization_member(&context.actor, &context.user, &organization, &user)
        .await
    {
        Ok(ids) => ids,
        Err(error) => return handle_identity_error(error),
    };

    record_audit(
        &state,
        AuditAction::Delete,
        ResourceKind::OrganizationMember,
        Some(&context.user),
        Some(format!("{}:{}", organization_id, user_id)),
        "removed organization member",
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn put_organization_member_roles(
    State(state): State<AppState>,
    Path((organization, user)): Path<(String, String)>,
    headers: HeaderMap,
    payload: Result<Json<UpdateRolesRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    let updated_member = match state
        .identity
        .update_organization_member_roles(
            &context.actor,
            &context.user,
            &organization,
            &user,
            &request,
        )
        .await
    {
        Ok(member) => member,
        Err(error) => return handle_identity_error(error),
    };

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::OrganizationMember,
        Some(&context.user),
        Some(format!(
            "{}:{}",
            updated_member.organization_id, updated_member.user_id
        )),
        "updated organization member roles",
    )
    .await;

    Ok((
        StatusCode::OK,
        Json(OrganizationMember::from(updated_member)),
    )
        .into_response())
}

async fn create_session_api_key(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let result = match state
        .auth
        .create_session_api_key(&context.actor, &context.user, &user)
        .await
    {
        Ok(result) => result,
        Err(error) => return handle_auth_error(error),
    };

    record_audit(
        &state,
        AuditAction::Create,
        ResourceKind::ApiKey,
        Some(&context.user),
        Some(result.key_id),
        "created session API key",
    )
    .await;

    Ok((StatusCode::CREATED, Json(result.response)).into_response())
}

async fn create_token_api_key(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<CreateTokenRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    let result = match state
        .auth
        .create_token_api_key(&context.actor, &context.user, &user, request)
        .await
    {
        Ok(result) => result,
        Err(error) => return handle_auth_error(error),
    };

    record_audit(
        &state,
        AuditAction::Create,
        ResourceKind::ApiKey,
        Some(&context.user),
        Some(result.key_id),
        "created token API key",
    )
    .await;

    Ok((StatusCode::CREATED, Json(result.response)).into_response())
}

async fn list_token_api_keys(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
    Query(query): Query<TokenListQuery>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let keys = match state
        .auth
        .list_token_api_keys(
            &context.actor,
            &context.user,
            &user,
            query.include_all,
            query.include_expired,
        )
        .await
    {
        Ok(keys) => keys,
        Err(error) => return handle_auth_error(error),
    };

    Ok((StatusCode::OK, Json(keys)).into_response())
}

async fn get_api_key(
    State(state): State<AppState>,
    Path((user, keyid)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let key = match state
        .auth
        .get_api_key(&context.actor, &context.user, &user, &keyid)
        .await
    {
        Ok(key) => key,
        Err(error) => return handle_auth_error(error),
    };

    Ok((StatusCode::OK, Json(key)).into_response())
}

async fn get_api_key_by_name(
    State(state): State<AppState>,
    Path((user, keyname)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let key = match state
        .auth
        .get_api_key_by_name(&context.actor, &context.user, &user, &keyname)
        .await
    {
        Ok(key) => key,
        Err(error) => return handle_auth_error(error),
    };

    Ok((StatusCode::OK, Json(key)).into_response())
}

async fn delete_api_key(
    State(state): State<AppState>,
    Path((user, keyid)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let key_id = match state
        .auth
        .delete_api_key(&context.actor, &context.user, &user, &keyid)
        .await
    {
        Ok(key_id) => key_id,
        Err(error) => return handle_auth_error(error),
    };

    record_audit(
        &state,
        AuditAction::Delete,
        ResourceKind::ApiKey,
        Some(&context.user),
        Some(key_id),
        "deleted API key",
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn expire_api_key(
    State(state): State<AppState>,
    Path((user, keyid)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let key_id = match state
        .auth
        .expire_api_key(&context.actor, &context.user, &user, &keyid)
        .await
    {
        Ok(key_id) => key_id,
        Err(error) => return handle_auth_error(error),
    };

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::ApiKey,
        Some(&context.user),
        Some(key_id),
        "expired API key",
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn get_token_config(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let config = match state
        .auth
        .get_token_config(&context.actor, &context.user, &user)
        .await
    {
        Ok(config) => config,
        Err(error) => return handle_auth_error(error),
    };
    Ok((StatusCode::OK, Json(config)).into_response())
}

async fn list_user_organizations(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let organizations = match state
        .identity
        .list_user_organizations(&context.actor, &context.user, &user)
        .await
    {
        Ok(organizations) => organizations,
        Err(error) => return handle_identity_error(error),
    };

    Ok((
        StatusCode::OK,
        Json(
            organizations
                .into_iter()
                .map(OrganizationResponse::from)
                .collect::<Vec<_>>(),
        ),
    )
        .into_response())
}

async fn get_user_organization_by_name(
    State(state): State<AppState>,
    Path((user, organizationname)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let target_organization = match state
        .identity
        .get_user_organization_by_name(&context.actor, &context.user, &user, &organizationname)
        .await
    {
        Ok(organization) => organization,
        Err(error) => return handle_identity_error(error),
    };

    Ok((
        StatusCode::OK,
        Json(OrganizationResponse::from(target_organization)),
    )
        .into_response())
}

async fn delete_user(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let target_user = match state
        .identity
        .delete_user(&context.actor, &context.user, &user)
        .await
    {
        Ok(user) => user,
        Err(error) => return handle_identity_error(error),
    };

    record_audit(
        &state,
        AuditAction::Delete,
        ResourceKind::User,
        Some(&context.user),
        Some(target_user.id.to_string()),
        "deleted user",
    )
    .await;

    Ok((
        StatusCode::OK,
        Json(ApiResponse::ok("User has been deleted!")),
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// Template & Template Version Handlers (33 routes)
// ---------------------------------------------------------------------------

/// Converts a `TemplateRecord` into a `TemplateResponse`.
fn template_response(rec: &TemplateRecord) -> TemplateResponse {
    use coder_core::api::{TemplateAutostartRequirement, TemplateAutostopRequirement};
    TemplateResponse {
        id: rec.id,
        created_at: rec.created_at,
        updated_at: rec.updated_at,
        organization_id: rec.organization_id,
        organization_name: rec.organization_name.clone(),
        organization_display_name: rec.organization_display_name.clone(),
        organization_icon: rec.organization_icon.clone(),
        name: rec.name.clone(),
        display_name: rec.display_name.clone(),
        provisioner: rec.provisioner.clone(),
        active_version_id: rec.active_version_id,
        active_user_count: -1,
        build_time_stats: HashMap::new(),
        description: rec.description.clone(),
        deprecated: !rec.deprecated.is_empty(),
        deprecation_message: rec.deprecated.clone(),
        deleted: rec.deleted,
        icon: rec.icon.clone(),
        default_ttl_ms: rec.default_ttl / 1_000_000,
        activity_bump_ms: rec.activity_bump / 1_000_000,
        autostop_requirement: TemplateAutostopRequirement::default(),
        autostart_requirement: TemplateAutostartRequirement::default(),
        created_by_id: rec.created_by,
        created_by_name: rec.created_by_name.clone(),
        allow_user_autostart: rec.allow_user_autostart,
        allow_user_autostop: rec.allow_user_autostop,
        allow_user_cancel_workspace_jobs: rec.allow_user_cancel_workspace_jobs,
        failure_ttl_ms: rec.failure_ttl / 1_000_000,
        time_til_dormant_ms: rec.time_til_dormant / 1_000_000,
        time_til_dormant_autodelete_ms: rec.time_til_dormant_autodelete / 1_000_000,
        require_active_version: rec.require_active_version,
        max_port_share_level: rec.max_port_sharing_level.clone(),
        cors_behavior: rec.cors_behavior.clone(),
        use_classic_parameter_flow: rec.use_classic_parameter_flow,
        disable_module_cache: rec.disable_module_cache,
    }
}

/// Converts a `ProvisionerJobRecord` into a `ProvisionerJobResponse`.
fn provisioner_job_response(job: &ProvisionerJobRecord) -> ProvisionerJobResponse {
    ProvisionerJobResponse {
        id: job.id,
        created_at: job.created_at,
        started_at: job.started_at,
        completed_at: job.completed_at,
        canceled_at: job.canceled_at,
        error: job.error.clone(),
        status: ProvisionerJobStatus::from_str_opt(&job.job_status).unwrap_or_default(),
        worker_id: job.worker_id,
        file_id: job.file_id,
        tags: job.tags.clone(),
        queue_position: 0,
        queue_size: 0,
    }
}

/// Converts a `TemplateVersionRecord` + `ProvisionerJobRecord` into a `TemplateVersionResponse`.
fn template_version_response(
    ver: &TemplateVersionRecord,
    job: &ProvisionerJobRecord,
) -> TemplateVersionResponse {
    TemplateVersionResponse {
        id: ver.id,
        template_id: ver.template_id,
        organization_id: ver.organization_id,
        created_at: ver.created_at,
        updated_at: ver.updated_at,
        name: ver.name.clone(),
        message: ver.message.clone(),
        job: provisioner_job_response(job),
        readme: ver.readme.clone(),
        created_by: MinimalUser {
            id: ver.created_by,
            username: ver.created_by_username.clone(),
            name: String::new(),
            avatar_url: ver.created_by_avatar_url.clone(),
        },
        archived: ver.archived,
        warnings: Vec::new(),
        has_external_agent: ver.has_external_agent.unwrap_or(false),
    }
}

/// Helper to build a template version response, fetching the provisioner job.
async fn build_tv_response(
    state: &AppState,
    ver: &TemplateVersionRecord,
) -> Result<TemplateVersionResponse, AppError> {
    let job = state.store.find_provisioner_job_by_id(ver.job_id).await?;
    let job = job.ok_or_else(|| {
        AppError::from(StorageError::invalid_data(format!(
            "provisioner job {} not found for version {}",
            ver.job_id, ver.id
        )))
    })?;
    Ok(template_version_response(ver, &job))
}

/// GET /organizations/{organization}/templates
async fn list_org_templates(
    State(state): State<AppState>,
    Path(org): Path<String>,
    headers: HeaderMap,
    Query(query): Query<TemplateFilter>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let org_record = state
        .store
        .find_organization_by_name(&org)
        .await?
        .ok_or_else(|| {
            AppError::from(StorageError::invalid_data(format!(
                "organization {org} not found"
            )))
        })?;

    let templates = state
        .store
        .list_templates(TemplateListFilter {
            organization_id: Some(org_record.id),
            exact_name: query.exact_name,
            search: query.search,
            deleted: query.deleted.unwrap_or(false),
        })
        .await?;

    let body: Vec<TemplateResponse> = templates.iter().map(template_response).collect();
    Ok((StatusCode::OK, Json(body)).into_response())
}

/// POST /organizations/{organization}/templates
async fn post_org_template(
    State(state): State<AppState>,
    Path(org): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<CreateTemplateRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(body) =
        payload.map_err(|e| AppError::from(StorageError::invalid_data(e.to_string())))?;

    let org_record = state
        .store
        .find_organization_by_name(&org)
        .await?
        .ok_or_else(|| {
            AppError::from(StorageError::invalid_data(format!(
                "organization {org} not found"
            )))
        })?;

    let now = OffsetDateTime::now_utc();
    let template_id = Uuid::new_v4();
    let input = CreateTemplateInput {
        id: template_id,
        created_at: now,
        updated_at: now,
        organization_id: org_record.id,
        name: body.name.clone(),
        display_name: body.display_name.clone(),
        provisioner: String::from("terraform"),
        active_version_id: body.template_version_id,
        description: body.description.clone(),
        default_ttl: body.default_ttl_ms * 1_000_000,
        created_by: context.user.id,
        icon: body.icon.clone(),
        allow_user_cancel_workspace_jobs: body.allow_user_cancel_workspace_jobs,
        allow_user_autostart: body.allow_user_autostart,
        allow_user_autostop: body.allow_user_autostop,
        failure_ttl: body.failure_ttl_ms * 1_000_000,
        time_til_dormant: body.time_til_dormant_ms * 1_000_000,
        time_til_dormant_autodelete: body.time_til_dormant_autodelete_ms * 1_000_000,
        require_active_version: body.require_active_version,
        activity_bump: body.activity_bump_ms * 1_000_000,
        max_port_share_level: body.max_port_share_level.clone(),
    };

    let template = match state.store.insert_template(input).await {
        Ok(t) => t,
        Err(CreateTemplateStoreError::AlreadyExists) => {
            return Ok((
                StatusCode::CONFLICT,
                Json(ApiResponse::error(
                    "A template with that name already exists.",
                    "duplicate name",
                )),
            )
                .into_response());
        }
        Err(CreateTemplateStoreError::Storage(e)) => return Err(AppError::from(e)),
    };

    record_audit(
        &state,
        AuditAction::Create,
        ResourceKind::Template,
        Some(&context.user),
        Some(template.id.to_string()),
        "created template",
    )
    .await;

    Ok((StatusCode::CREATED, Json(template_response(&template))).into_response())
}

/// GET /organizations/{organization}/templates/{templatename}
async fn get_org_template_by_name(
    State(state): State<AppState>,
    Path((org, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let org_record = state
        .store
        .find_organization_by_name(&org)
        .await?
        .ok_or_else(|| {
            AppError::from(StorageError::invalid_data(format!(
                "organization {org} not found"
            )))
        })?;

    let template = state
        .store
        .find_template_by_org_and_name(org_record.id, &name)
        .await?;

    match template {
        Some(t) => Ok((StatusCode::OK, Json(template_response(&t))).into_response()),
        None => Ok(not_found_response(format!("Template '{name}' not found."))),
    }
}

/// GET /organizations/{organization}/templates/{templatename}/versions/{templateversionname}
async fn get_org_template_version_by_name(
    State(state): State<AppState>,
    Path((org, tname, vname)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let org_record = state
        .store
        .find_organization_by_name(&org)
        .await?
        .ok_or_else(|| {
            AppError::from(StorageError::invalid_data(format!(
                "organization {org} not found"
            )))
        })?;

    let ver = state
        .store
        .find_template_version_by_org_and_name(org_record.id, &tname, &vname)
        .await?;

    match ver {
        Some(v) => {
            let resp = build_tv_response(&state, &v).await?;
            Ok((StatusCode::OK, Json(resp)).into_response())
        }
        None => Ok(not_found_response(format!(
            "Template version '{vname}' not found."
        ))),
    }
}

/// POST /organizations/{organization}/templateversions
async fn post_org_template_version(
    State(state): State<AppState>,
    Path(org): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<CreateTemplateVersionRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(body) =
        payload.map_err(|e| AppError::from(StorageError::invalid_data(e.to_string())))?;

    let org_record = state
        .store
        .find_organization_by_name(&org)
        .await?
        .ok_or_else(|| {
            AppError::from(StorageError::invalid_data(format!(
                "organization {org} not found"
            )))
        })?;

    let now = OffsetDateTime::now_utc();
    let job_id = Uuid::new_v4();
    let version_id = Uuid::new_v4();

    // Create the provisioner job (stub — stays in pending state).
    let provisioner = if body.provisioner.is_empty() {
        "terraform".to_owned()
    } else {
        body.provisioner.clone()
    };
    let _job = state
        .store
        .insert_provisioner_job(CreateProvisionerJobInput {
            id: job_id,
            created_at: now,
            updated_at: now,
            organization_id: org_record.id,
            initiator_id: context.user.id,
            provisioner: provisioner.clone(),
            file_id: body.file_id,
            job_type: "template_version_import".to_owned(),
            input: serde_json::json!({}),
            tags: body.tags.clone(),
        })
        .await?;

    let version_name = if body.name.is_empty() {
        version_id.to_string()
    } else {
        body.name.clone()
    };

    let ver = state
        .store
        .insert_template_version(CreateTemplateVersionInput {
            id: version_id,
            template_id: body.template_id,
            organization_id: org_record.id,
            created_at: now,
            updated_at: now,
            name: version_name,
            message: body.message.clone(),
            readme: String::new(),
            job_id,
            created_by: context.user.id,
            source_example_id: body.example_id.clone(),
        })
        .await?;

    let resp = build_tv_response(&state, &ver).await?;
    Ok((StatusCode::CREATED, Json(resp)).into_response())
}

/// GET /templates/{template}
async fn get_template(
    State(state): State<AppState>,
    Path(template_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let template = state.store.find_template_by_id(template_id).await?;
    match template {
        Some(t) => Ok((StatusCode::OK, Json(template_response(&t))).into_response()),
        None => Ok(not_found_response("Template not found.")),
    }
}

/// DELETE /templates/{template}
async fn delete_template(
    State(state): State<AppState>,
    Path(template_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let deleted = state.store.soft_delete_template(template_id).await?;
    if !deleted {
        return Ok(not_found_response("Template not found."));
    }

    record_audit(
        &state,
        AuditAction::Delete,
        ResourceKind::Template,
        Some(&context.user),
        Some(template_id.to_string()),
        "deleted template",
    )
    .await;

    Ok((
        StatusCode::OK,
        Json(ApiResponse::ok("Template has been deleted!")),
    )
        .into_response())
}

/// PATCH /templates/{template}
async fn patch_template(
    State(state): State<AppState>,
    Path(template_id): Path<Uuid>,
    headers: HeaderMap,
    payload: Result<Json<UpdateTemplateMeta>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(body) =
        payload.map_err(|e| AppError::from(StorageError::invalid_data(e.to_string())))?;

    // Fetch existing template to use current values as defaults.
    let existing = state
        .store
        .find_template_by_id(template_id)
        .await?
        .ok_or_else(|| AppError::from(StorageError::invalid_data("template not found")))?;

    let name = if body.name.is_empty() {
        &existing.name
    } else {
        &body.name
    };
    let display_name = body
        .display_name
        .as_deref()
        .unwrap_or(&existing.display_name);
    let description = body.description.as_deref().unwrap_or(&existing.description);
    let icon = body.icon.as_deref().unwrap_or(&existing.icon);
    let deprecation_message = body
        .deprecation_message
        .as_deref()
        .unwrap_or(&existing.deprecated);
    let max_port_share_level = body
        .max_port_share_level
        .as_deref()
        .unwrap_or(&existing.max_port_sharing_level);

    let updated = state
        .store
        .update_template_meta(
            template_id,
            name,
            display_name,
            description,
            icon,
            body.default_ttl_ms * 1_000_000,
            body.activity_bump_ms * 1_000_000,
            body.allow_user_autostart,
            body.allow_user_autostop,
            body.allow_user_cancel_workspace_jobs,
            body.failure_ttl_ms * 1_000_000,
            body.time_til_dormant_ms * 1_000_000,
            body.time_til_dormant_autodelete_ms * 1_000_000,
            body.require_active_version,
            deprecation_message,
            max_port_share_level,
        )
        .await?;

    match updated {
        Some(t) => {
            record_audit(
                &state,
                AuditAction::Write,
                ResourceKind::Template,
                Some(&context.user),
                Some(template_id.to_string()),
                "updated template metadata",
            )
            .await;
            Ok((StatusCode::OK, Json(template_response(&t))).into_response())
        }
        None => Ok(not_found_response("Template not found.")),
    }
}

/// GET /templates/{template}/daus
async fn get_template_daus(
    State(state): State<AppState>,
    Path(template_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let rows = state.store.template_daus(template_id).await?;
    let entries: Vec<DAUEntry> = rows
        .iter()
        .map(|r| DAUEntry {
            date: r.date.clone(),
            amount: r.amount,
        })
        .collect();
    let resp = DAUsResponse {
        entries,
        tz_hour_offset: 0,
    };
    Ok((StatusCode::OK, Json(resp)).into_response())
}

/// GET /templates/{template}/examples
async fn get_template_examples(
    State(state): State<AppState>,
    Path(_template_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    // Template examples are static / built-in. Return empty list for now.
    let examples: Vec<TemplateExample> = Vec::new();
    Ok((StatusCode::OK, Json(examples)).into_response())
}

/// GET /templates/{template}/versions
async fn list_template_versions(
    State(state): State<AppState>,
    Path(template_id): Path<Uuid>,
    headers: HeaderMap,
    Query(query): Query<TemplateVersionsQuery>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let versions = state
        .store
        .list_template_versions(TemplateVersionListFilter {
            template_id,
            include_archived: query.include_archived.unwrap_or(false),
            limit: query.limit.unwrap_or(50),
            offset: query.offset.unwrap_or(0),
        })
        .await?;

    let mut responses = Vec::with_capacity(versions.len());
    for v in &versions {
        responses.push(build_tv_response(&state, v).await?);
    }
    Ok((StatusCode::OK, Json(responses)).into_response())
}

/// GET /templates/{template}/versions/{templateversionname}
async fn get_template_version_by_name(
    State(state): State<AppState>,
    Path((template_id, vname)): Path<(Uuid, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let ver = state
        .store
        .find_template_version_by_template_and_name(template_id, &vname)
        .await?;

    match ver {
        Some(v) => {
            let resp = build_tv_response(&state, &v).await?;
            Ok((StatusCode::OK, Json(resp)).into_response())
        }
        None => Ok(not_found_response(format!(
            "Template version '{vname}' not found."
        ))),
    }
}

/// GET /templateversions/{templateversion}
async fn get_template_version(
    State(state): State<AppState>,
    Path(version_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let ver = state.store.find_template_version_by_id(version_id).await?;
    match ver {
        Some(v) => {
            let resp = build_tv_response(&state, &v).await?;
            Ok((StatusCode::OK, Json(resp)).into_response())
        }
        None => Ok(not_found_response("Template version not found.")),
    }
}

/// PATCH /templateversions/{templateversion}
async fn patch_template_version(
    State(state): State<AppState>,
    Path(version_id): Path<Uuid>,
    headers: HeaderMap,
    payload: Result<Json<PatchTemplateVersionRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(body) =
        payload.map_err(|e| AppError::from(StorageError::invalid_data(e.to_string())))?;

    let existing = state
        .store
        .find_template_version_by_id(version_id)
        .await?
        .ok_or_else(|| AppError::from(StorageError::invalid_data("template version not found")))?;

    let name = if body.name.is_empty() {
        &existing.name
    } else {
        &body.name
    };
    let message = body.message.as_deref().unwrap_or(&existing.message);

    let updated = state
        .store
        .update_template_version(version_id, name, message)
        .await?;

    match updated {
        Some(v) => {
            record_audit(
                &state,
                AuditAction::Write,
                ResourceKind::TemplateVersion,
                Some(&context.user),
                Some(version_id.to_string()),
                "updated template version",
            )
            .await;
            let resp = build_tv_response(&state, &v).await?;
            Ok((StatusCode::OK, Json(resp)).into_response())
        }
        None => Ok(not_found_response("Template version not found.")),
    }
}

/// POST /templateversions/{templateversion}/archive
async fn post_archive_template_version(
    State(state): State<AppState>,
    Path(version_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let archived = state.store.archive_template_version(version_id).await?;
    if !archived {
        return Ok(not_found_response("Template version not found."));
    }
    Ok((
        StatusCode::OK,
        Json(ApiResponse::ok("Template version archived.")),
    )
        .into_response())
}

/// POST /templateversions/{templateversion}/cancel
async fn post_cancel_template_version(
    State(state): State<AppState>,
    Path(version_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let ver = state
        .store
        .find_template_version_by_id(version_id)
        .await?
        .ok_or_else(|| AppError::from(StorageError::invalid_data("template version not found")))?;

    let canceled = state.store.cancel_provisioner_job(ver.job_id).await?;
    if !canceled {
        return Ok((
            StatusCode::PRECONDITION_FAILED,
            Json(ApiResponse::error(
                "Job cannot be canceled.",
                "job is already completed or canceled",
            )),
        )
            .into_response());
    }
    Ok((
        StatusCode::OK,
        Json(ApiResponse::ok("Template version job canceled.")),
    )
        .into_response())
}

/// POST /templateversions/{templateversion}/dry-run
async fn post_template_version_dry_run(
    State(state): State<AppState>,
    Path(version_id): Path<Uuid>,
    headers: HeaderMap,
    payload: Result<Json<CreateTemplateVersionDryRunRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(body) =
        payload.map_err(|e| AppError::from(StorageError::invalid_data(e.to_string())))?;

    // Ensure the template version exists.
    let ver = state
        .store
        .find_template_version_by_id(version_id)
        .await?
        .ok_or_else(|| AppError::from(StorageError::invalid_data("template version not found")))?;

    let now = OffsetDateTime::now_utc();
    let job_id = Uuid::new_v4();

    let input_json = serde_json::json!({
        "template_version_id": version_id,
        "workspace_name": body.workspace_name,
        "rich_parameter_values": body.rich_parameter_values,
        "user_variable_values": body.user_variable_values,
    });

    let job = state
        .store
        .insert_provisioner_job(CreateProvisionerJobInput {
            id: job_id,
            created_at: now,
            updated_at: now,
            organization_id: ver.organization_id,
            initiator_id: context.user.id,
            provisioner: String::from("terraform"),
            file_id: None,
            job_type: "template_version_dry_run".to_owned(),
            input: input_json,
            tags: HashMap::new(),
        })
        .await?;

    Ok((StatusCode::CREATED, Json(provisioner_job_response(&job))).into_response())
}

/// GET /templateversions/{templateversion}/dry-run/{jobid}
async fn get_template_version_dry_run(
    State(state): State<AppState>,
    Path((_version_id, job_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let job = state.store.find_provisioner_job_by_id(job_id).await?;
    match job {
        Some(j) => Ok((StatusCode::OK, Json(provisioner_job_response(&j))).into_response()),
        None => Ok(not_found_response("Dry-run job not found.")),
    }
}

/// PATCH /templateversions/{templateversion}/dry-run/{jobid}
async fn patch_template_version_dry_run(
    State(state): State<AppState>,
    Path((_version_id, job_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let canceled = state.store.cancel_provisioner_job(job_id).await?;
    if !canceled {
        return Ok((
            StatusCode::PRECONDITION_FAILED,
            Json(ApiResponse::error(
                "Job cannot be canceled.",
                "job is already completed or canceled",
            )),
        )
            .into_response());
    }

    let job = state.store.find_provisioner_job_by_id(job_id).await?;
    match job {
        Some(j) => Ok((StatusCode::OK, Json(provisioner_job_response(&j))).into_response()),
        None => Ok(not_found_response("Dry-run job not found.")),
    }
}

/// GET /templateversions/{templateversion}/dry-run/{jobid}/cancel
async fn get_cancel_template_version_dry_run(
    State(state): State<AppState>,
    Path((_version_id, job_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let canceled = state.store.cancel_provisioner_job(job_id).await?;
    if !canceled {
        return Ok((
            StatusCode::PRECONDITION_FAILED,
            Json(ApiResponse::error(
                "Job cannot be canceled.",
                "job is already completed or canceled",
            )),
        )
            .into_response());
    }
    Ok((
        StatusCode::OK,
        Json(ApiResponse::ok("Dry-run job canceled.")),
    )
        .into_response())
}

/// GET /templateversions/{templateversion}/dry-run/{jobid}/logs
async fn get_template_version_dry_run_logs(
    State(state): State<AppState>,
    Path((_version_id, job_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // Verify the job exists.
    let _job = state
        .store
        .find_provisioner_job_by_id(job_id)
        .await?
        .ok_or_else(|| AppError::from(StorageError::invalid_data("dry-run job not found")))?;

    // Provisioner logs are not stored in the stub implementation.
    let logs: Vec<ProvisionerJobLog> = Vec::new();
    Ok((StatusCode::OK, Json(logs)).into_response())
}

/// GET /templateversions/{templateversion}/dry-run/{jobid}/resources
async fn get_template_version_dry_run_resources(
    State(state): State<AppState>,
    Path((_version_id, job_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let _job = state
        .store
        .find_provisioner_job_by_id(job_id)
        .await?
        .ok_or_else(|| AppError::from(StorageError::invalid_data("dry-run job not found")))?;

    // Resources are populated by the provisioner daemon. Return empty for stub.
    let resources: Vec<WorkspaceResource> = Vec::new();
    Ok((StatusCode::OK, Json(resources)).into_response())
}

/// GET /templateversions/{templateversion}/external-auth
async fn get_template_version_external_auth(
    State(state): State<AppState>,
    Path(version_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // Verify the version exists.
    let _ver = state
        .store
        .find_template_version_by_id(version_id)
        .await?
        .ok_or_else(|| AppError::from(StorageError::invalid_data("template version not found")))?;

    // External auth requirements come from provisioner output. Return empty for stub.
    let auths: Vec<TemplateVersionExternalAuth> = Vec::new();
    Ok((StatusCode::OK, Json(auths)).into_response())
}

/// GET /templateversions/{templateversion}/logs
async fn get_template_version_logs(
    State(state): State<AppState>,
    Path(version_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let _ver = state
        .store
        .find_template_version_by_id(version_id)
        .await?
        .ok_or_else(|| AppError::from(StorageError::invalid_data("template version not found")))?;

    let logs: Vec<ProvisionerJobLog> = Vec::new();
    Ok((StatusCode::OK, Json(logs)).into_response())
}

/// GET /templateversions/{templateversion}/parameters (deprecated alias for rich-parameters)
async fn get_template_version_parameters(
    State(state): State<AppState>,
    Path(version_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    get_template_version_rich_parameters_impl(&state, &headers, version_id).await
}

/// GET /templateversions/{templateversion}/rich-parameters
async fn get_template_version_rich_parameters(
    State(state): State<AppState>,
    Path(version_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    get_template_version_rich_parameters_impl(&state, &headers, version_id).await
}

/// Shared implementation for parameters / rich-parameters endpoints.
async fn get_template_version_rich_parameters_impl(
    state: &AppState,
    headers: &HeaderMap,
    version_id: Uuid,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(state, headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let params = state
        .store
        .list_template_version_parameters(version_id)
        .await?;

    let body: Vec<TemplateVersionParameter> = params
        .iter()
        .map(|p| {
            let options: Vec<coder_core::api::TemplateVersionParameterOption> =
                serde_json::from_value(p.options.clone()).unwrap_or_default();
            TemplateVersionParameter {
                name: p.name.clone(),
                display_name: p.display_name.clone(),
                description: p.description.clone(),
                description_plaintext: p.description.clone(),
                param_type: p.param_type.clone(),
                form_type: p.form_type.clone(),
                mutable: p.mutable,
                default_value: p.default_value.clone(),
                icon: p.icon.clone(),
                options,
                validation_error: p.validation_error.clone(),
                validation_regex: p.validation_regex.clone(),
                validation_min: p.validation_min,
                validation_max: p.validation_max,
                validation_monotonic: p.validation_monotonic.clone(),
                required: p.required,
                ephemeral: p.ephemeral,
            }
        })
        .collect();

    Ok((StatusCode::OK, Json(body)).into_response())
}

/// GET /templateversions/{templateversion}/presets
async fn get_template_version_presets(
    State(state): State<AppState>,
    Path(version_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let presets = state
        .store
        .list_template_version_presets(version_id)
        .await?;

    let body: Vec<TemplateVersionPreset> = presets
        .iter()
        .map(|p| TemplateVersionPreset {
            id: p.id,
            template_version_id: p.template_version_id,
            name: p.name.clone(),
            created_at: p.created_at,
            is_default: p.is_default,
            description: p.description.clone(),
            icon: p.icon.clone(),
        })
        .collect();

    Ok((StatusCode::OK, Json(body)).into_response())
}

/// GET /templateversions/{templateversion}/presets/{presetid}/parameters
async fn get_template_version_preset_parameters(
    State(state): State<AppState>,
    Path((_version_id, preset_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let params = state
        .store
        .list_template_version_preset_parameters(preset_id)
        .await?;

    let body: Vec<TemplateVersionPresetParameter> = params
        .iter()
        .map(|p| TemplateVersionPresetParameter {
            id: p.id,
            template_version_preset_id: p.template_version_preset_id,
            name: p.name.clone(),
            value: p.value.clone(),
        })
        .collect();

    Ok((StatusCode::OK, Json(body)).into_response())
}

/// GET /templateversions/{templateversion}/resources
async fn get_template_version_resources(
    State(state): State<AppState>,
    Path(version_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let _ver = state
        .store
        .find_template_version_by_id(version_id)
        .await?
        .ok_or_else(|| AppError::from(StorageError::invalid_data("template version not found")))?;

    // Resources are populated by the provisioner daemon. Return empty for stub.
    let resources: Vec<WorkspaceResource> = Vec::new();
    Ok((StatusCode::OK, Json(resources)).into_response())
}

/// GET /templateversions/{templateversion}/schema (deprecated)
async fn get_template_version_schema(
    State(state): State<AppState>,
    Path(version_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let _ver = state
        .store
        .find_template_version_by_id(version_id)
        .await?
        .ok_or_else(|| AppError::from(StorageError::invalid_data("template version not found")))?;

    // Deprecated endpoint — return empty array.
    let schema: Vec<Value> = Vec::new();
    Ok((StatusCode::OK, Json(schema)).into_response())
}

/// POST /templateversions/{templateversion}/unarchive
async fn post_unarchive_template_version(
    State(state): State<AppState>,
    Path(version_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let unarchived = state.store.unarchive_template_version(version_id).await?;
    if !unarchived {
        return Ok(not_found_response("Template version not found."));
    }
    Ok((
        StatusCode::OK,
        Json(ApiResponse::ok("Template version unarchived.")),
    )
        .into_response())
}

/// GET /templateversions/{templateversion}/variables
async fn get_template_version_variables(
    State(state): State<AppState>,
    Path(version_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let vars = state
        .store
        .list_template_version_variables(version_id)
        .await?;

    let body: Vec<TemplateVersionVariable> = vars
        .iter()
        .map(|v| TemplateVersionVariable {
            name: v.name.clone(),
            description: v.description.clone(),
            var_type: v.var_type.clone(),
            value: if v.sensitive {
                String::new()
            } else {
                v.value.clone()
            },
            default_value: if v.sensitive {
                String::new()
            } else {
                v.default_value.clone()
            },
            required: v.required,
            sensitive: v.sensitive,
        })
        .collect();

    Ok((StatusCode::OK, Json(body)).into_response())
}

// ---------------------------------------------------------------------------
// End of Template & Template Version Handlers
// ---------------------------------------------------------------------------

async fn authenticate_request(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<AuthenticatedRequest>, AppError> {
    state
        .auth
        .authenticate(headers)
        .await
        .map_err(AppError::from)
}

async fn resolve_user(
    state: &AppState,
    requested_user: &str,
    authenticated_user: &AuthenticatedUser,
) -> Result<Option<UserRecord>, AppError> {
    if requested_user == "me" {
        return state
            .store
            .find_user_by_id(authenticated_user.id)
            .await
            .map_err(AppError::from);
    }

    if let Ok(user_id) = Uuid::parse_str(requested_user) {
        return state
            .store
            .find_user_by_id(user_id)
            .await
            .map_err(AppError::from);
    }

    state
        .store
        .find_user_by_username(requested_user)
        .await
        .map_err(AppError::from)
}

fn can_view_operational_data(actor: &Actor) -> bool {
    actor.is_owner() || actor.has_site_role(ROLE_AUDITOR)
}

fn find_external_auth_provider<'a>(
    state: &'a AppState,
    provider_id: &str,
) -> Option<&'a coder_core::ExternalAuthLinkProvider> {
    state
        .config
        .external_auth_providers
        .iter()
        .find(|provider| provider.id == provider_id)
}

fn apply_dismissed_health_settings(
    mut report: HealthcheckReport,
    settings: &HealthSettings,
) -> HealthcheckReport {
    for section in &settings.dismissed_healthchecks {
        match section.as_str() {
            "AccessURL" => report.access_url.base.dismissed = true,
            "DERP" => report.derp.base.dismissed = true,
            "Database" => report.database.base.dismissed = true,
            "Websocket" => report.websocket.base.dismissed = true,
            "WorkspaceProxy" => report.workspace_proxy.base.dismissed = true,
            "ProvisionerDaemons" => report.provisioner_daemons.base.dismissed = true,
            _ => {}
        }
    }
    report
}

fn sanitize_redirect_uri(input: &str) -> String {
    if let Ok(url) = url::Url::parse(input) {
        let path = url.path();
        let query = url
            .query()
            .map(|value| format!("?{value}"))
            .unwrap_or_default();
        return if path.is_empty() {
            "/".to_owned()
        } else {
            format!("{path}{query}")
        };
    }

    if let Ok(uri) = http::Uri::from_str(input) {
        if let Some(path_and_query) = uri.path_and_query() {
            return path_and_query.as_str().to_owned();
        }
        if !uri.path().is_empty() {
            return uri.path().to_owned();
        }
    }

    "/".to_owned()
}

fn redirect_to_login_response(uri: &http::Uri, message: &str) -> Response {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("message", message);
    serializer.append_pair("redirect", &sanitize_redirect_uri(&uri.to_string()));
    let location = format!("/login?{}", serializer.finish());

    let mut response = StatusCode::SEE_OTHER.into_response();
    response.headers_mut().insert(
        LOCATION,
        HeaderValue::from_str(&location).unwrap_or_else(|_| HeaderValue::from_static("/login")),
    );
    response
}

fn external_auth_device_flow_unsupported_response() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ApiResponse::ok(
            "Git auth provider does not support device flow.",
        )),
    )
        .into_response()
}

async fn store_new_git_ssh_key(
    state: &AppState,
    user: &UserRecord,
) -> Result<coder_core::GitSshKeyRecord, String> {
    let comment = if !user.email.trim().is_empty() {
        user.email.clone()
    } else {
        user.username.clone()
    };
    let generated = generate_git_ssh_key(&comment).map_err(|error| error.to_string())?;
    state
        .store
        .upsert_git_ssh_key(user.id, &generated.public_key, &generated.private_key)
        .await
        .map_err(|error| error.to_string())
}

async fn record_audit(
    state: &AppState,
    action: AuditAction,
    resource: ResourceKind,
    actor: Option<&AuthenticatedUser>,
    target_id: Option<String>,
    summary: impl Into<String>,
) {
    state
        .audit
        .record(AuditEvent {
            action,
            resource,
            actor_user_id: actor.map(|user| user.id),
            target_id,
            summary: summary.into(),
        })
        .await;
}

fn handle_auth_error(error: AuthServiceError) -> Result<Response, AppError> {
    match error {
        AuthServiceError::Storage(error) => Err(AppError::from(error)),
        AuthServiceError::Unauthorized { message } => Ok(unauthorized_response(message)),
        AuthServiceError::Forbidden { message } => Ok(forbidden_response(message)),
        AuthServiceError::NotFound { message } => Ok(not_found_response(message)),
        AuthServiceError::BadRequest { message, detail } => Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                message,
                detail,
                validations: Vec::new(),
            }),
        )
            .into_response()),
        AuthServiceError::Validation {
            message,
            validations,
        } => Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                message,
                detail: None,
                validations,
            }),
        )
            .into_response()),
        AuthServiceError::Conflict {
            message,
            detail,
            validations,
        } => Ok((
            StatusCode::CONFLICT,
            Json(ApiResponse {
                message,
                detail,
                validations,
            }),
        )
            .into_response()),
    }
}

fn handle_external_auth_error(
    message: &'static str,
    error: ExternalAuthServiceError,
) -> Result<Response, AppError> {
    match error {
        ExternalAuthServiceError::BadRequest(detail) => Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(message, detail)),
        )
            .into_response()),
        ExternalAuthServiceError::Storage(error) => Err(AppError::from(error)),
        ExternalAuthServiceError::Internal(detail) => Ok((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::error(message, detail)),
        )
            .into_response()),
    }
}

fn handle_identity_error(error: IdentityServiceError) -> Result<Response, AppError> {
    match error {
        IdentityServiceError::Storage(error) => Err(AppError::from(error)),
        IdentityServiceError::NotFound { message } => Ok(not_found_response(message)),
        IdentityServiceError::Forbidden { message } => Ok(forbidden_response(message)),
        IdentityServiceError::BadRequest { message, detail } => Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                message,
                detail,
                validations: Vec::new(),
            }),
        )
            .into_response()),
        IdentityServiceError::Validation {
            message,
            validations,
        } => Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                message,
                detail: None,
                validations,
            }),
        )
            .into_response()),
        IdentityServiceError::Conflict {
            message,
            detail,
            validations,
        } => Ok((
            StatusCode::CONFLICT,
            Json(ApiResponse {
                message,
                detail,
                validations,
            }),
        )
            .into_response()),
    }
}

fn build_version_headers(version: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Ok(value) = HeaderValue::from_str(version) {
        headers.insert(HeaderName::from_static(BUILD_VERSION_HEADER), value);
    }
    headers
}

fn invalid_json_response(error: JsonRejection) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ApiResponse::error(
            "Request body must be valid JSON.",
            error.body_text(),
        )),
    )
        .into_response()
}

fn validation_response(validations: Vec<ValidationError>) -> Response {
    validation_message_response("Request body has invalid fields.", validations)
}

fn validation_message_response(message: &str, validations: Vec<ValidationError>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ApiResponse {
            message: message.to_owned(),
            detail: None,
            validations,
        }),
    )
        .into_response()
}

fn unauthorized_response(message: impl Into<String>) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(ApiResponse::ok(message.into())),
    )
        .into_response()
}

fn forbidden_response(message: impl Into<String>) -> Response {
    (StatusCode::FORBIDDEN, Json(ApiResponse::ok(message.into()))).into_response()
}

fn not_implemented_response(message: impl Into<String>) -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(ApiResponse::ok(message.into())),
    )
        .into_response()
}

fn not_found_response(message: impl Into<String>) -> Response {
    (StatusCode::NOT_FOUND, Json(ApiResponse::ok(message.into()))).into_response()
}

fn resource_not_found_response() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ApiResponse::ok(
            "Resource not found or you do not have access to this resource",
        )),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        error::Error,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use async_trait::async_trait;
    use axum::{
        Json, Router,
        body::{Body, to_bytes},
        http::HeaderMap,
        http::{Method, Request, Response, StatusCode, header::CONTENT_TYPE},
        response::IntoResponse,
        routing::{get, post},
    };
    use coder_audit::{AuditEvent, AuditSink};
    use coder_auth::{
        OAUTH2_REDIRECT_COOKIE, OAUTH2_STATE_COOKIE, SESSION_TOKEN_COOKIE, SESSION_TOKEN_HEADER,
        hash_password,
    };
    use coder_core::{
        ApiKeyListFilter, ApiKeyRecord, ApiKeyWithOwnerRecord, AppStore, AuditLog,
        AuditLogListFilter, AuditLogResponse, AuthenticatedUser, BuildMetadata,
        ChangePasswordWithOneTimePasscodeRequest, ConvertLoginRequest, CreateApiKeyInput,
        CreateApiKeyStoreError, CreateFirstUserInput, CreateFirstUserRequest,
        CreateFirstUserStoreError, CreateTestAuditLogRequest, CreateTokenRequest, CreateUserInput,
        CreateUserRequestWithOrgs, CreateUserStoreError, DatabaseConfig, DeploymentMetadata,
        DeploymentStatsResponse, DeploymentStore, DerpNodeConfig, DerpRegionConfig,
        ExternalAuthLinkProvider, ExternalAuthLinkRecord, ExternalAuthUser, GitSshKeyRecord,
        HealthSettings, InsertOrganizationMemberError, LogFormat, LoginType,
        LoginWithPasswordRequest, OrganizationMemberListFilter, OrganizationMemberRecord,
        OrganizationRecord, PasswordUserRecord, PersistAuditLogInput, ProvisionerDaemonHealthInput,
        ProvisionerDaemonHealthRecord, ProvisionerJobStatsInput, RequestOneTimePasscodeRequest,
        ServerConfig, SessionCountDeploymentStatsResponse, SlimRoleRecord, SshConfig, StorageError,
        TokenConfigRecord, UpdateRolesRequest, UpdateUserAppearanceSettingsRequest,
        UpdateUserPasswordRequest, UpdateUserPreferenceSettingsRequest, UpdateUserProfileRequest,
        UpsertExternalAuthLinkInput, UserAppearanceRecord, UserListFilter, UserPreferenceRecord,
        UserRecord, UserStatus, ValidateUserPasswordRequest, WorkspaceAgentStatInput,
        WorkspaceBuildStatsInput, WorkspaceConnectionLatencyMs, WorkspaceDeploymentStatsResponse,
        WorkspaceProxyHealthInput, WorkspaceProxyHealthRecord, WorkspaceStatsWorkspaceInput,
    };
    use serde::Serialize;
    use serde_json::{Value, json};
    use time::OffsetDateTime;
    use tower::ServiceExt;
    use url::Url;
    use uuid::Uuid;

    use super::{
        AppState, BUILD_VERSION_HEADER, PUBLIC_API_KEY_SCOPES, SLIM_BUILD_MESSAGE, build_router,
    };

    #[derive(Debug, Default)]
    struct MemoryAuditSink {
        events: Mutex<Vec<AuditEvent>>,
    }

    #[async_trait]
    impl AuditSink for MemoryAuditSink {
        async fn record(&self, event: AuditEvent) {
            if let Ok(mut events) = self.events.lock() {
                events.push(event);
            }
        }
    }

    #[derive(Debug)]
    struct FakeStore {
        health_ok: bool,
        users: Mutex<HashMap<Uuid, UserRecord>>,
        organizations: Mutex<HashMap<Uuid, OrganizationRecord>>,
        organization_members: Mutex<HashMap<(Uuid, Uuid), OrganizationMemberRecord>>,
        sessions: Mutex<HashMap<Vec<u8>, AuthenticatedUser>>,
        api_keys: Mutex<HashMap<String, ApiKeyRecord>>,
        audit_logs: Mutex<Vec<AuditLog>>,
        password_hashes: Mutex<HashMap<Uuid, String>>,
        one_time_passcodes: Mutex<HashMap<Uuid, (String, OffsetDateTime)>>,
        appearance: Mutex<HashMap<Uuid, UserAppearanceRecord>>,
        preferences: Mutex<HashMap<Uuid, UserPreferenceRecord>>,
        health_settings: Mutex<HealthSettings>,
        git_ssh_keys: Mutex<HashMap<Uuid, GitSshKeyRecord>>,
        external_auth_links: Mutex<HashMap<(Uuid, String), ExternalAuthLinkRecord>>,
        stats_workspaces: Mutex<HashMap<Uuid, WorkspaceStatsWorkspaceInput>>,
        stats_jobs: Mutex<HashMap<Uuid, ProvisionerJobStatsInput>>,
        stats_builds: Mutex<HashMap<Uuid, WorkspaceBuildStatsInput>>,
        stats_agents: Mutex<Vec<WorkspaceAgentStatInput>>,
        workspace_proxies: Mutex<HashMap<Uuid, WorkspaceProxyHealthRecord>>,
        provisioner_daemons: Mutex<HashMap<Uuid, ProvisionerDaemonHealthRecord>>,
    }

    impl FakeStore {
        fn new(health_ok: bool) -> Self {
            Self {
                health_ok,
                users: Mutex::new(HashMap::new()),
                organizations: Mutex::new(HashMap::new()),
                organization_members: Mutex::new(HashMap::new()),
                sessions: Mutex::new(HashMap::new()),
                api_keys: Mutex::new(HashMap::new()),
                audit_logs: Mutex::new(Vec::new()),
                password_hashes: Mutex::new(HashMap::new()),
                one_time_passcodes: Mutex::new(HashMap::new()),
                appearance: Mutex::new(HashMap::new()),
                preferences: Mutex::new(HashMap::new()),
                health_settings: Mutex::new(HealthSettings::default()),
                git_ssh_keys: Mutex::new(HashMap::new()),
                external_auth_links: Mutex::new(HashMap::new()),
                stats_workspaces: Mutex::new(HashMap::new()),
                stats_jobs: Mutex::new(HashMap::new()),
                stats_builds: Mutex::new(HashMap::new()),
                stats_agents: Mutex::new(Vec::new()),
                workspace_proxies: Mutex::new(HashMap::new()),
                provisioner_daemons: Mutex::new(HashMap::new()),
            }
        }

        fn set_one_time_passcode(
            &self,
            user_id: Uuid,
            passcode: &str,
            expires_at: OffsetDateTime,
        ) -> Result<(), StorageError> {
            let passcode_hash = hash_password(passcode)
                .map_err(|error| StorageError::invalid_data(error.to_string()))?;
            self.one_time_passcodes
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .insert(user_id, (passcode_hash, expires_at));
            Ok(())
        }
    }

    #[async_trait]
    impl DeploymentStore for FakeStore {
        async fn ping(&self) -> Result<(), StorageError> {
            if self.health_ok {
                Ok(())
            } else {
                Err(StorageError::unavailable("database is down"))
            }
        }

        async fn ensure_deployment_metadata(&self) -> Result<DeploymentMetadata, StorageError> {
            Ok(DeploymentMetadata {
                deployment_id: Uuid::nil(),
            })
        }
    }

    #[async_trait]
    impl AppStore for FakeStore {
        async fn first_user_exists(&self) -> Result<bool, StorageError> {
            let users = self
                .users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            Ok(!users.is_empty())
        }

        async fn create_first_user(
            &self,
            user: CreateFirstUserInput,
        ) -> Result<coder_core::FirstUserRecord, CreateFirstUserStoreError> {
            let mut users = self
                .users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))
                .map_err(CreateFirstUserStoreError::from)?;
            if !users.is_empty() {
                return Err(CreateFirstUserStoreError::AlreadyExists);
            }

            let mut organizations = self
                .organizations
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))
                .map_err(CreateFirstUserStoreError::from)?;
            let mut members = self
                .organization_members
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))
                .map_err(CreateFirstUserStoreError::from)?;

            let user_id = Uuid::from_u128(1);
            let organization_id = Uuid::from_u128(2);
            let now = OffsetDateTime::now_utc();
            let role = SlimRoleRecord {
                name: "owner".to_owned(),
                display_name: "Owner".to_owned(),
                organization_id: None,
            };
            let user_record = UserRecord {
                id: user_id,
                email: user.email.clone(),
                username: user.username.clone(),
                name: user.name.clone(),
                avatar_url: String::new(),
                created_at: now,
                updated_at: now,
                last_seen_at: None,
                organization_ids: vec![organization_id],
                roles: vec![role.clone()],
                login_type: LoginType::Password,
                status: UserStatus::Active,
                deleted: false,
                is_system: false,
            };
            let organization = OrganizationRecord {
                id: organization_id,
                name: "first-organization".to_owned(),
                display_name: "First Organization".to_owned(),
                description: "Builtin default organization.".to_owned(),
                icon: String::new(),
                created_at: now,
                updated_at: now,
                is_default: true,
                deleted: false,
            };
            let member = OrganizationMemberRecord {
                user_id,
                organization_id,
                created_at: now,
                updated_at: now,
                roles: Vec::new(),
                username: user.username,
                name: user.name,
                avatar_url: String::new(),
                email: user.email,
                global_roles: vec![role],
            };

            organizations.insert(organization_id, organization);
            members.insert((organization_id, user_id), member);
            users.insert(user_id, user_record.clone());
            self.password_hashes
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))
                .map_err(CreateFirstUserStoreError::from)?
                .insert(user_id, user.password_hash);
            self.appearance
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))
                .map_err(CreateFirstUserStoreError::from)?
                .insert(
                    user_id,
                    UserAppearanceRecord {
                        theme_preference: String::new(),
                        terminal_font: String::new(),
                    },
                );
            self.preferences
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))
                .map_err(CreateFirstUserStoreError::from)?
                .insert(
                    user_id,
                    UserPreferenceRecord {
                        task_notification_alert_dismissed: false,
                    },
                );

            Ok(coder_core::FirstUserRecord {
                user_id,
                organization_id,
            })
        }

        async fn find_password_user_by_email(
            &self,
            email: &str,
        ) -> Result<Option<PasswordUserRecord>, StorageError> {
            let users = self
                .users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let password_hashes = self
                .password_hashes
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let one_time_passcodes = self
                .one_time_passcodes
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            Ok(users
                .values()
                .find(|record| !record.deleted && record.email.eq_ignore_ascii_case(email))
                .cloned()
                .map(|user| PasswordUserRecord {
                    password_hash: password_hashes.get(&user.id).cloned().unwrap_or_default(),
                    one_time_passcode_hash: one_time_passcodes
                        .get(&user.id)
                        .map(|(hash, _)| hash.clone()),
                    one_time_passcode_expires_at: one_time_passcodes
                        .get(&user.id)
                        .map(|(_, expires_at)| *expires_at),
                    user,
                }))
        }

        async fn find_password_user_by_id(
            &self,
            user_id: Uuid,
        ) -> Result<Option<PasswordUserRecord>, StorageError> {
            let users = self
                .users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let Some(user) = users.get(&user_id).filter(|user| !user.deleted).cloned() else {
                return Ok(None);
            };
            let password_hashes = self
                .password_hashes
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let one_time_passcodes = self
                .one_time_passcodes
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            Ok(Some(PasswordUserRecord {
                password_hash: password_hashes.get(&user.id).cloned().unwrap_or_default(),
                one_time_passcode_hash: one_time_passcodes
                    .get(&user.id)
                    .map(|(hash, _)| hash.clone()),
                one_time_passcode_expires_at: one_time_passcodes
                    .get(&user.id)
                    .map(|(_, expires_at)| *expires_at),
                user,
            }))
        }

        async fn insert_auth_session(
            &self,
            token_hash: &[u8],
            user_id: Uuid,
        ) -> Result<(), StorageError> {
            let user = self
                .users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .get(&user_id)
                .cloned()
                .ok_or_else(|| StorageError::invalid_data("missing user for session"))?;
            self.sessions
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .insert(token_hash.to_vec(), AuthenticatedUser::from(user));
            Ok(())
        }

        async fn find_user_by_session_token_hash(
            &self,
            token_hash: &[u8],
        ) -> Result<Option<AuthenticatedUser>, StorageError> {
            let sessions = self
                .sessions
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            Ok(sessions.get(token_hash).cloned())
        }

        async fn delete_auth_session(&self, token_hash: &[u8]) -> Result<bool, StorageError> {
            Ok(self
                .sessions
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .remove(token_hash)
                .is_some())
        }

        async fn list_users(
            &self,
            filter: UserListFilter,
        ) -> Result<(Vec<UserRecord>, usize), StorageError> {
            let users = self
                .users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let mut matched = users
                .values()
                .filter(|user| {
                    if user.deleted {
                        return false;
                    }
                    let search = filter.search.to_lowercase();
                    let search_matches = search.is_empty()
                        || user.username.to_lowercase().contains(&search)
                        || user.email.to_lowercase().contains(&search)
                        || user.name.to_lowercase().contains(&search);
                    let status_matches = filter.status.is_none_or(|status| user.status == status);
                    search_matches && status_matches
                })
                .cloned()
                .collect::<Vec<_>>();
            matched.sort_by(|left, right| left.username.cmp(&right.username));
            let count = matched.len();
            let start = usize::try_from(filter.offset).unwrap_or(0);
            let end = if filter.limit == 0 {
                matched.len()
            } else {
                start.saturating_add(usize::try_from(filter.limit).unwrap_or(0))
            };
            let page = matched
                .into_iter()
                .skip(start)
                .take(end.saturating_sub(start))
                .collect();
            Ok((page, count))
        }

        async fn create_user(
            &self,
            input: CreateUserInput,
        ) -> Result<UserRecord, CreateUserStoreError> {
            let mut users = self
                .users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))
                .map_err(CreateUserStoreError::from)?;
            if users.values().any(|user| {
                !user.deleted
                    && (user.email.eq_ignore_ascii_case(&input.email)
                        || user.username.eq_ignore_ascii_case(&input.username))
            }) {
                return Err(CreateUserStoreError::AlreadyExists);
            }

            let organizations = self
                .organizations
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))
                .map_err(CreateUserStoreError::from)?;
            for organization_id in &input.organization_ids {
                if !organizations.contains_key(organization_id) {
                    return Err(CreateUserStoreError::from(StorageError::invalid_data(
                        "unknown organization",
                    )));
                }
            }
            drop(organizations);

            let next_id = Uuid::from_u128(u128::try_from(users.len()).unwrap_or(0) + 10);
            let now = OffsetDateTime::now_utc();
            let user_record = UserRecord {
                id: next_id,
                email: input.email.clone(),
                username: input.username.clone(),
                name: input.name.clone(),
                avatar_url: String::new(),
                created_at: now,
                updated_at: now,
                last_seen_at: None,
                organization_ids: input.organization_ids.clone(),
                roles: Vec::new(),
                login_type: input.login_type,
                status: input.status,
                deleted: false,
                is_system: false,
            };
            users.insert(next_id, user_record.clone());
            drop(users);

            let mut members = self
                .organization_members
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))
                .map_err(CreateUserStoreError::from)?;
            for organization_id in &input.organization_ids {
                members.insert(
                    (*organization_id, next_id),
                    OrganizationMemberRecord {
                        user_id: next_id,
                        organization_id: *organization_id,
                        created_at: now,
                        updated_at: now,
                        roles: Vec::new(),
                        username: input.username.clone(),
                        name: input.name.clone(),
                        avatar_url: String::new(),
                        email: input.email.clone(),
                        global_roles: Vec::new(),
                    },
                );
            }

            if let Some(password_hash) = input.password_hash {
                self.password_hashes
                    .lock()
                    .map_err(|error| StorageError::unavailable(error.to_string()))
                    .map_err(CreateUserStoreError::from)?
                    .insert(next_id, password_hash);
            }
            self.appearance
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))
                .map_err(CreateUserStoreError::from)?
                .insert(
                    next_id,
                    UserAppearanceRecord {
                        theme_preference: String::new(),
                        terminal_font: String::new(),
                    },
                );
            self.preferences
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))
                .map_err(CreateUserStoreError::from)?
                .insert(
                    next_id,
                    UserPreferenceRecord {
                        task_notification_alert_dismissed: false,
                    },
                );

            Ok(user_record)
        }

        async fn find_user_by_id(&self, user_id: Uuid) -> Result<Option<UserRecord>, StorageError> {
            Ok(self
                .users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .get(&user_id)
                .filter(|user| !user.deleted)
                .cloned())
        }

        async fn find_user_by_username(
            &self,
            username: &str,
        ) -> Result<Option<UserRecord>, StorageError> {
            let users = self
                .users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            Ok(users
                .values()
                .filter(|user| !user.deleted)
                .find(|user| user.username.eq_ignore_ascii_case(username))
                .cloned())
        }

        async fn soft_delete_user(&self, user_id: Uuid) -> Result<bool, StorageError> {
            let mut users = self
                .users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let Some(user) = users.get_mut(&user_id) else {
                return Ok(false);
            };
            if user.deleted {
                return Ok(false);
            }
            user.deleted = true;
            user.status = UserStatus::Suspended;
            user.updated_at = OffsetDateTime::now_utc();
            drop(users);

            self.sessions
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .retain(|_, user| user.id != user_id);
            self.api_keys
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .retain(|_, key| key.user_id != user_id);
            self.organization_members
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .retain(|(_, member_user_id), _| member_user_id != &user_id);
            self.password_hashes
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .remove(&user_id);
            self.one_time_passcodes
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .remove(&user_id);
            self.appearance
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .remove(&user_id);
            self.preferences
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .remove(&user_id);

            Ok(true)
        }

        async fn list_user_memberships(
            &self,
            user_id: Uuid,
        ) -> Result<Vec<OrganizationMemberRecord>, StorageError> {
            let members = self
                .organization_members
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let mut rows = members
                .values()
                .filter(|member| member.user_id == user_id)
                .cloned()
                .collect::<Vec<_>>();
            rows.sort_by(|left, right| left.organization_id.cmp(&right.organization_id));
            Ok(rows)
        }

        async fn update_user_roles(
            &self,
            user_id: Uuid,
            roles: Vec<String>,
        ) -> Result<Option<UserRecord>, StorageError> {
            let now = OffsetDateTime::now_utc();
            let mut users = self
                .users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let Some(user) = users.get_mut(&user_id) else {
                return Ok(None);
            };
            if user.deleted {
                return Ok(None);
            }
            let slim_roles = roles
                .iter()
                .map(|role| SlimRoleRecord {
                    name: role.clone(),
                    display_name: role
                        .split('-')
                        .map(|part| {
                            let mut chars = part.chars();
                            match chars.next() {
                                Some(first) => {
                                    first.to_uppercase().collect::<String>() + chars.as_str()
                                }
                                None => String::new(),
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(" "),
                    organization_id: None,
                })
                .collect::<Vec<_>>();
            user.roles = slim_roles.clone();
            user.updated_at = now;
            let updated_user = user.clone();
            drop(users);

            self.organization_members
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .values_mut()
                .filter(|member| member.user_id == user_id)
                .for_each(|member| {
                    member.global_roles = slim_roles.clone();
                });

            Ok(Some(updated_user))
        }

        async fn update_user_profile(
            &self,
            user_id: Uuid,
            username: &str,
            name: &str,
        ) -> Result<Option<UserRecord>, StorageError> {
            let mut users = self
                .users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let Some(user) = users.get_mut(&user_id) else {
                return Ok(None);
            };
            if user.deleted {
                return Ok(None);
            }
            user.username = username.to_owned();
            user.name = name.to_owned();
            user.updated_at = OffsetDateTime::now_utc();
            let updated_user = user.clone();
            drop(users);

            self.organization_members
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .values_mut()
                .filter(|member| member.user_id == user_id)
                .for_each(|member| {
                    member.username = username.to_owned();
                    member.name = name.to_owned();
                    member.updated_at = updated_user.updated_at;
                });

            Ok(Some(updated_user))
        }

        async fn update_user_status(
            &self,
            user_id: Uuid,
            status: UserStatus,
        ) -> Result<Option<UserRecord>, StorageError> {
            let mut users = self
                .users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let Some(user) = users.get_mut(&user_id) else {
                return Ok(None);
            };
            if user.deleted {
                return Ok(None);
            }
            user.status = status;
            user.updated_at = OffsetDateTime::now_utc();
            Ok(Some(user.clone()))
        }

        async fn user_appearance(
            &self,
            user_id: Uuid,
        ) -> Result<UserAppearanceRecord, StorageError> {
            self.appearance
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .get(&user_id)
                .cloned()
                .ok_or_else(|| StorageError::invalid_data("unknown user appearance"))
        }

        async fn update_user_appearance(
            &self,
            user_id: Uuid,
            theme_preference: &str,
            terminal_font: &str,
        ) -> Result<Option<UserAppearanceRecord>, StorageError> {
            let mut appearance = self
                .appearance
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let Some(settings) = appearance.get_mut(&user_id) else {
                return Ok(None);
            };
            settings.theme_preference = theme_preference.to_owned();
            settings.terminal_font = terminal_font.to_owned();
            Ok(Some(settings.clone()))
        }

        async fn user_preferences(
            &self,
            user_id: Uuid,
        ) -> Result<UserPreferenceRecord, StorageError> {
            self.preferences
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .get(&user_id)
                .cloned()
                .ok_or_else(|| StorageError::invalid_data("unknown user preferences"))
        }

        async fn update_user_preferences(
            &self,
            user_id: Uuid,
            task_notification_alert_dismissed: bool,
        ) -> Result<Option<UserPreferenceRecord>, StorageError> {
            let mut preferences = self
                .preferences
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let Some(settings) = preferences.get_mut(&user_id) else {
                return Ok(None);
            };
            settings.task_notification_alert_dismissed = task_notification_alert_dismissed;
            Ok(Some(settings.clone()))
        }

        async fn list_organizations(
            &self,
            organization_ids: Vec<Uuid>,
        ) -> Result<Vec<OrganizationRecord>, StorageError> {
            let organizations = self
                .organizations
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let mut rows = organizations
                .values()
                .filter(|org| organization_ids.is_empty() || organization_ids.contains(&org.id))
                .cloned()
                .collect::<Vec<_>>();
            rows.sort_by(|left, right| left.name.cmp(&right.name));
            Ok(rows)
        }

        async fn find_organization_by_id(
            &self,
            organization_id: Uuid,
        ) -> Result<Option<OrganizationRecord>, StorageError> {
            Ok(self
                .organizations
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .get(&organization_id)
                .cloned())
        }

        async fn find_organization_by_name(
            &self,
            name: &str,
        ) -> Result<Option<OrganizationRecord>, StorageError> {
            let organizations = self
                .organizations
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            Ok(organizations
                .values()
                .find(|org| org.name.eq_ignore_ascii_case(name))
                .cloned())
        }

        async fn list_organization_members(
            &self,
            filter: OrganizationMemberListFilter,
        ) -> Result<Vec<OrganizationMemberRecord>, StorageError> {
            let users = self
                .users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let members = self
                .organization_members
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let mut rows = members
                .values()
                .filter(|member| member.organization_id == filter.organization_id)
                .filter(|member| users.get(&member.user_id).is_some_and(|user| !user.deleted))
                .filter(|member| {
                    let search = filter.search.to_lowercase();
                    search.is_empty()
                        || member.username.to_lowercase().contains(&search)
                        || member.email.to_lowercase().contains(&search)
                        || member.name.to_lowercase().contains(&search)
                })
                .cloned()
                .collect::<Vec<_>>();
            rows.sort_by(|left, right| left.username.cmp(&right.username));
            let start = usize::try_from(filter.offset).unwrap_or(0);
            let end = if filter.limit == 0 {
                rows.len()
            } else {
                start.saturating_add(usize::try_from(filter.limit).unwrap_or(0))
            };
            Ok(rows
                .into_iter()
                .skip(start)
                .take(end.saturating_sub(start))
                .collect())
        }

        async fn list_organization_members_page(
            &self,
            filter: OrganizationMemberListFilter,
        ) -> Result<(Vec<OrganizationMemberRecord>, usize), StorageError> {
            let users = self
                .users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let members = self
                .organization_members
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let search = filter.search.to_lowercase();
            let mut rows = members
                .values()
                .filter(|member| member.organization_id == filter.organization_id)
                .filter(|member| users.get(&member.user_id).is_some_and(|user| !user.deleted))
                .filter(|member| {
                    search.is_empty()
                        || member.username.to_lowercase().contains(&search)
                        || member.email.to_lowercase().contains(&search)
                        || member.name.to_lowercase().contains(&search)
                })
                .cloned()
                .collect::<Vec<_>>();
            rows.sort_by(|left, right| left.username.cmp(&right.username));
            let count = rows.len();
            let start = usize::try_from(filter.offset).unwrap_or(0);
            let end = if filter.limit == 0 {
                rows.len()
            } else {
                start.saturating_add(usize::try_from(filter.limit).unwrap_or(0))
            };
            Ok((
                rows.into_iter()
                    .skip(start)
                    .take(end.saturating_sub(start))
                    .collect(),
                count,
            ))
        }

        async fn find_organization_member(
            &self,
            organization_id: Uuid,
            user_id: Uuid,
        ) -> Result<Option<OrganizationMemberRecord>, StorageError> {
            Ok(self
                .organization_members
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .get(&(organization_id, user_id))
                .cloned())
        }

        async fn insert_organization_member(
            &self,
            organization_id: Uuid,
            user_id: Uuid,
        ) -> Result<OrganizationMemberRecord, InsertOrganizationMemberError> {
            let user = self
                .users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))
                .map_err(InsertOrganizationMemberError::from)?
                .get(&user_id)
                .cloned()
                .ok_or_else(|| {
                    InsertOrganizationMemberError::from(StorageError::invalid_data("unknown user"))
                })?;
            let mut members = self
                .organization_members
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))
                .map_err(InsertOrganizationMemberError::from)?;
            if members.contains_key(&(organization_id, user_id)) {
                return Err(InsertOrganizationMemberError::AlreadyExists);
            }
            let now = OffsetDateTime::now_utc();
            let member = OrganizationMemberRecord {
                user_id,
                organization_id,
                created_at: now,
                updated_at: now,
                roles: Vec::new(),
                username: user.username.clone(),
                name: user.name.clone(),
                avatar_url: user.avatar_url.clone(),
                email: user.email.clone(),
                global_roles: user.roles.clone(),
            };
            members.insert((organization_id, user_id), member.clone());
            drop(members);
            self.users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))
                .map_err(InsertOrganizationMemberError::from)?
                .entry(user_id)
                .and_modify(|entry| {
                    if !entry.organization_ids.contains(&organization_id) {
                        entry.organization_ids.push(organization_id);
                    }
                });
            Ok(member)
        }

        async fn delete_organization_member(
            &self,
            organization_id: Uuid,
            user_id: Uuid,
        ) -> Result<bool, StorageError> {
            let deleted = self
                .organization_members
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .remove(&(organization_id, user_id))
                .is_some();
            if deleted {
                self.users
                    .lock()
                    .map_err(|error| StorageError::unavailable(error.to_string()))?
                    .entry(user_id)
                    .and_modify(|entry| entry.organization_ids.retain(|id| id != &organization_id));
            }
            Ok(deleted)
        }

        async fn update_organization_member_roles(
            &self,
            organization_id: Uuid,
            user_id: Uuid,
            roles: Vec<String>,
        ) -> Result<Option<OrganizationMemberRecord>, StorageError> {
            let mut members = self
                .organization_members
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let Some(member) = members.get_mut(&(organization_id, user_id)) else {
                return Ok(None);
            };
            member.updated_at = OffsetDateTime::now_utc();
            member.roles = roles
                .iter()
                .map(|role| SlimRoleRecord {
                    name: role.clone(),
                    display_name: role
                        .split('-')
                        .map(|part| {
                            let mut chars = part.chars();
                            match chars.next() {
                                Some(first) => {
                                    first.to_uppercase().collect::<String>() + chars.as_str()
                                }
                                None => String::new(),
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(" "),
                    organization_id: Some(organization_id),
                })
                .collect();

            Ok(Some(member.clone()))
        }

        async fn store_one_time_passcode_by_email(
            &self,
            email: &str,
            passcode_hash: &str,
            expires_at: OffsetDateTime,
        ) -> Result<(), StorageError> {
            let users = self
                .users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let user_id = users
                .values()
                .find(|user| {
                    !user.deleted
                        && user.login_type == LoginType::Password
                        && user.email.eq_ignore_ascii_case(email)
                })
                .map(|user| user.id);
            drop(users);

            if let Some(user_id) = user_id {
                self.one_time_passcodes
                    .lock()
                    .map_err(|error| StorageError::unavailable(error.to_string()))?
                    .insert(user_id, (passcode_hash.to_owned(), expires_at));
            }
            Ok(())
        }

        async fn replace_user_password(
            &self,
            user_id: Uuid,
            password_hash: &str,
            clear_one_time_passcode: bool,
        ) -> Result<bool, StorageError> {
            let users = self
                .users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            if users.get(&user_id).is_none_or(|user| user.deleted) {
                return Ok(false);
            }
            drop(users);

            self.password_hashes
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .insert(user_id, password_hash.to_owned());
            if clear_one_time_passcode {
                self.one_time_passcodes
                    .lock()
                    .map_err(|error| StorageError::unavailable(error.to_string()))?
                    .remove(&user_id);
            }
            self.sessions
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .retain(|_, user| user.id != user_id);
            self.api_keys
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .retain(|_, key| key.user_id != user_id);
            Ok(true)
        }

        async fn create_api_key(
            &self,
            input: CreateApiKeyInput,
        ) -> Result<ApiKeyRecord, CreateApiKeyStoreError> {
            let mut api_keys = self
                .api_keys
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))
                .map_err(CreateApiKeyStoreError::from)?;
            if !input.token_name.is_empty()
                && api_keys
                    .values()
                    .any(|key| key.user_id == input.user_id && key.token_name == input.token_name)
            {
                return Err(CreateApiKeyStoreError::DuplicateTokenName);
            }
            let record = ApiKeyRecord {
                id: input.id,
                hashed_secret: input.hashed_secret,
                user_id: input.user_id,
                last_used: input.last_used,
                expires_at: input.expires_at,
                created_at: input.created_at,
                updated_at: input.updated_at,
                login_type: input.login_type,
                scopes: input.scopes,
                token_name: input.token_name,
                lifetime_seconds: input.lifetime_seconds,
                allow_list: input.allow_list,
            };
            api_keys.insert(record.id.clone(), record.clone());
            Ok(record)
        }

        async fn find_api_key_by_id(&self, id: &str) -> Result<Option<ApiKeyRecord>, StorageError> {
            Ok(self
                .api_keys
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .get(id)
                .cloned())
        }

        async fn find_api_key_by_name(
            &self,
            user_id: Uuid,
            token_name: &str,
        ) -> Result<Option<ApiKeyRecord>, StorageError> {
            let api_keys = self
                .api_keys
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            Ok(api_keys
                .values()
                .find(|key| key.user_id == user_id && key.token_name == token_name)
                .cloned())
        }

        async fn list_api_keys(
            &self,
            filter: ApiKeyListFilter,
        ) -> Result<Vec<ApiKeyWithOwnerRecord>, StorageError> {
            let api_keys = self
                .api_keys
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let users = self
                .users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let now = OffsetDateTime::now_utc();
            Ok(api_keys
                .values()
                .filter(|key| key.login_type == filter.login_type)
                .filter(|key| filter.user_id.is_none_or(|user_id| key.user_id == user_id))
                .filter(|key| filter.include_expired || key.expires_at > now)
                .map(|key| ApiKeyWithOwnerRecord {
                    key: key.clone(),
                    username: users
                        .get(&key.user_id)
                        .map(|user| user.username.clone())
                        .unwrap_or_default(),
                })
                .collect())
        }

        async fn delete_api_key(&self, id: &str) -> Result<bool, StorageError> {
            Ok(self
                .api_keys
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .remove(id)
                .is_some())
        }

        async fn expire_api_key(
            &self,
            id: &str,
            now: OffsetDateTime,
        ) -> Result<bool, StorageError> {
            let mut api_keys = self
                .api_keys
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let Some(key) = api_keys.get_mut(id) else {
                return Ok(false);
            };
            key.expires_at = now;
            key.updated_at = now;
            Ok(true)
        }

        async fn token_config(&self, user_id: Uuid) -> Result<TokenConfigRecord, StorageError> {
            let users = self
                .users
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let user = users
                .get(&user_id)
                .ok_or_else(|| StorageError::invalid_data("unknown user"))?;
            let max = if user.roles.iter().any(|role| role.name == "owner") {
                Duration::from_secs(60 * 60 * 24 * 365)
            } else {
                Duration::from_secs(60 * 60 * 24 * 30)
            };
            Ok(TokenConfigRecord {
                max_token_lifetime: max,
            })
        }

        async fn list_audit_logs(
            &self,
            filter: AuditLogListFilter,
        ) -> Result<AuditLogResponse, StorageError> {
            let search = filter.search.to_lowercase();
            let mut logs = self
                .audit_logs
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .iter()
                .filter(|log| {
                    search.is_empty()
                        || log.description.to_lowercase().contains(&search)
                        || log.resource_target.to_lowercase().contains(&search)
                        || log
                            .user
                            .as_ref()
                            .is_some_and(|user| user.username.to_lowercase().contains(&search))
                })
                .cloned()
                .collect::<Vec<_>>();
            logs.sort_by(|left, right| right.time.cmp(&left.time));
            let count = logs.len();
            let start = usize::try_from(filter.offset).unwrap_or(0);
            let limit = usize::try_from(filter.limit).unwrap_or(0);
            let audit_logs = if limit == 0 {
                logs.into_iter().skip(start).collect()
            } else {
                logs.into_iter().skip(start).take(limit).collect()
            };
            Ok(AuditLogResponse { audit_logs, count })
        }

        async fn insert_audit_log(&self, input: PersistAuditLogInput) -> Result<(), StorageError> {
            let user = input.user_id.and_then(|user_id| {
                self.users
                    .lock()
                    .ok()
                    .and_then(|users| users.get(&user_id).cloned())
                    .map(|user| coder_core::MinimalUser {
                        id: user.id,
                        username: user.username,
                        name: user.name,
                        avatar_url: user.avatar_url,
                    })
            });
            self.audit_logs
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .push(AuditLog {
                    id: input.id,
                    request_id: input.request_id,
                    time: input.time,
                    ip: input.ip,
                    user_agent: input.user_agent,
                    resource_type: match input.resource_type.as_str() {
                        "api_key" => coder_core::AuditResourceType::ApiKey,
                        "git_ssh_key" => coder_core::AuditResourceType::GitSshKey,
                        "health_settings" => coder_core::AuditResourceType::HealthSettings,
                        "organization" => coder_core::AuditResourceType::Organization,
                        "organization_member" => coder_core::AuditResourceType::OrganizationMember,
                        "convert_login" => coder_core::AuditResourceType::ConvertLogin,
                        _ => coder_core::AuditResourceType::User,
                    },
                    resource_id: input.resource_id,
                    resource_target: input.resource_target,
                    resource_icon: input.resource_icon,
                    action: match input.action.as_str() {
                        "create" => coder_core::AuditLogAction::Create,
                        "delete" => coder_core::AuditLogAction::Delete,
                        "start" => coder_core::AuditLogAction::Start,
                        "stop" => coder_core::AuditLogAction::Stop,
                        "login" => coder_core::AuditLogAction::Login,
                        "logout" => coder_core::AuditLogAction::Logout,
                        "register" => coder_core::AuditLogAction::Register,
                        "request_password_reset" => {
                            coder_core::AuditLogAction::RequestPasswordReset
                        }
                        _ => coder_core::AuditLogAction::Write,
                    },
                    diff: serde_json::from_value(input.diff).unwrap_or_default(),
                    status_code: input.status_code,
                    additional_fields: input.additional_fields,
                    description: input.description,
                    resource_link: input.resource_link,
                    is_deleted: input.is_deleted,
                    organization_id: input.organization_id,
                    organization: None,
                    user,
                });
            Ok(())
        }

        async fn health_settings(&self) -> Result<HealthSettings, StorageError> {
            self.health_settings
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))
                .map(|settings| settings.clone())
        }

        async fn upsert_health_settings(
            &self,
            settings: &HealthSettings,
        ) -> Result<bool, StorageError> {
            let mut current = self
                .health_settings
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            if *current == *settings {
                return Ok(false);
            }
            *current = settings.clone();
            Ok(true)
        }

        async fn deployment_stats(&self) -> Result<DeploymentStatsResponse, StorageError> {
            let now = OffsetDateTime::now_utc();
            let workspaces = self
                .stats_workspaces
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .clone();
            let jobs = self
                .stats_jobs
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .clone();
            let builds = self
                .stats_builds
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .clone();
            let agent_stats = self
                .stats_agents
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .clone();

            let mut pending = 0;
            let mut building = 0;
            let mut running = 0;
            let mut failed = 0;
            let mut stopped = 0;

            for workspace in workspaces.values().filter(|workspace| !workspace.deleted) {
                let latest_build = builds
                    .values()
                    .filter(|build| build.workspace_id == workspace.id)
                    .max_by_key(|build| build.build_number);

                let Some(build) = latest_build else {
                    pending += 1;
                    continue;
                };

                let Some(job) = build.job_id.and_then(|job_id| jobs.get(&job_id)) else {
                    pending += 1;
                    continue;
                };

                if job.started_at.is_none() {
                    pending += 1;
                    continue;
                }
                if job.started_at.is_some()
                    && job.canceled_at.is_none()
                    && job.completed_at.is_none()
                    && job.updated_at < now - time::Duration::seconds(30)
                {
                    building += 1;
                    continue;
                }
                if job.completed_at.is_some()
                    && job.canceled_at.is_none()
                    && job.error.is_empty()
                    && build.transition == "start"
                {
                    running += 1;
                    continue;
                }
                if (job.canceled_at.is_some() && !job.error.is_empty())
                    || (job.completed_at.is_some() && !job.error.is_empty())
                {
                    failed += 1;
                    continue;
                }
                if job.completed_at.is_some()
                    && job.canceled_at.is_none()
                    && job.error.is_empty()
                    && build.transition == "stop"
                {
                    stopped += 1;
                }
            }

            let aggregated_from = now - time::Duration::minutes(15);
            let mut latest_by_agent = HashMap::<Uuid, WorkspaceAgentStatInput>::new();
            let mut latencies = Vec::new();
            let mut rx_bytes = 0;
            let mut tx_bytes = 0;

            for stat in agent_stats
                .into_iter()
                .filter(|stat| stat.created_at > aggregated_from)
            {
                rx_bytes += stat.rx_bytes;
                tx_bytes += stat.tx_bytes;
                if stat.connection_median_latency_ms > 0.0 {
                    latencies.push(stat.connection_median_latency_ms);
                }

                let existing = latest_by_agent.get(&stat.agent_id).cloned();
                if existing
                    .as_ref()
                    .is_none_or(|existing| existing.created_at < stat.created_at)
                {
                    latest_by_agent.insert(stat.agent_id, stat);
                }
            }

            latencies.sort_by(|left, right| {
                left.partial_cmp(right).unwrap_or(std::cmp::Ordering::Equal)
            });
            let percentile = |quantile: f64| -> f64 {
                if latencies.is_empty() {
                    return 0.0;
                }
                let index = ((latencies.len() - 1) as f64 * quantile).round() as usize;
                latencies.get(index).copied().unwrap_or_default()
            };

            Ok(DeploymentStatsResponse {
                aggregated_from,
                collected_at: now,
                next_update_at: now + time::Duration::minutes(1),
                workspaces: WorkspaceDeploymentStatsResponse {
                    pending,
                    building,
                    running,
                    failed,
                    stopped,
                    connection_latency_ms: WorkspaceConnectionLatencyMs {
                        p50: percentile(0.5),
                        p95: percentile(0.95),
                    },
                    rx_bytes,
                    tx_bytes,
                },
                session_count: SessionCountDeploymentStatsResponse {
                    vscode: latest_by_agent
                        .values()
                        .map(|value| value.session_count_vscode)
                        .sum(),
                    ssh: latest_by_agent
                        .values()
                        .map(|value| value.session_count_ssh)
                        .sum(),
                    jetbrains: latest_by_agent
                        .values()
                        .map(|value| value.session_count_jetbrains)
                        .sum(),
                    reconnecting_pty: latest_by_agent
                        .values()
                        .map(|value| value.session_count_reconnecting_pty)
                        .sum(),
                },
            })
        }

        async fn upsert_workspace_stats_workspace(
            &self,
            input: &WorkspaceStatsWorkspaceInput,
        ) -> Result<(), StorageError> {
            self.stats_workspaces
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .insert(input.id, input.clone());
            Ok(())
        }

        async fn upsert_provisioner_job_stats(
            &self,
            input: &ProvisionerJobStatsInput,
        ) -> Result<(), StorageError> {
            self.stats_jobs
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .insert(input.id, input.clone());
            Ok(())
        }

        async fn upsert_workspace_build_stats(
            &self,
            input: &WorkspaceBuildStatsInput,
        ) -> Result<(), StorageError> {
            self.stats_builds
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .insert(input.id, input.clone());
            Ok(())
        }

        async fn insert_workspace_agent_stat(
            &self,
            input: &WorkspaceAgentStatInput,
        ) -> Result<(), StorageError> {
            self.stats_agents
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .push(input.clone());
            Ok(())
        }

        async fn list_workspace_proxies_for_health(
            &self,
        ) -> Result<Vec<WorkspaceProxyHealthRecord>, StorageError> {
            Ok(self
                .workspace_proxies
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .values()
                .cloned()
                .collect())
        }

        async fn upsert_workspace_proxy_for_health(
            &self,
            input: &WorkspaceProxyHealthInput,
        ) -> Result<(), StorageError> {
            self.workspace_proxies
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .insert(
                    input.id,
                    WorkspaceProxyHealthRecord {
                        id: input.id,
                        name: input.name.clone(),
                        display_name: input.display_name.clone(),
                        icon_url: input.icon_url.clone(),
                        path_app_url: input.path_app_url.clone(),
                        wildcard_hostname: input.wildcard_hostname.clone(),
                        derp_enabled: input.derp_enabled,
                        derp_only: input.derp_only,
                        created_at: input.created_at,
                        updated_at: input.updated_at,
                        deleted: input.deleted,
                        version: input.version.clone(),
                    },
                );
            Ok(())
        }

        async fn list_provisioner_daemons_for_health(
            &self,
        ) -> Result<Vec<ProvisionerDaemonHealthRecord>, StorageError> {
            Ok(self
                .provisioner_daemons
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .values()
                .cloned()
                .collect())
        }

        async fn upsert_provisioner_daemon_for_health(
            &self,
            input: &ProvisionerDaemonHealthInput,
        ) -> Result<(), StorageError> {
            self.provisioner_daemons
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .insert(
                    input.id,
                    ProvisionerDaemonHealthRecord {
                        id: input.id,
                        organization_id: input.organization_id,
                        created_at: input.created_at,
                        last_seen_at: input.last_seen_at,
                        name: input.name.clone(),
                        version: input.version.clone(),
                        api_version: input.api_version.clone(),
                        provisioners: input.provisioners.clone(),
                        tags: input.tags.clone(),
                        status: input.status.clone(),
                    },
                );
            Ok(())
        }

        async fn find_git_ssh_key(
            &self,
            user_id: Uuid,
        ) -> Result<Option<GitSshKeyRecord>, StorageError> {
            self.git_ssh_keys
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))
                .map(|keys| keys.get(&user_id).cloned())
        }

        async fn upsert_git_ssh_key(
            &self,
            user_id: Uuid,
            public_key: &str,
            private_key: &str,
        ) -> Result<GitSshKeyRecord, StorageError> {
            let mut keys = self
                .git_ssh_keys
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let now = OffsetDateTime::now_utc();
            let key = keys
                .entry(user_id)
                .and_modify(|existing| {
                    existing.updated_at = now;
                    existing.public_key = public_key.to_owned();
                    existing.private_key = private_key.to_owned();
                })
                .or_insert_with(|| GitSshKeyRecord {
                    user_id,
                    created_at: now,
                    updated_at: now,
                    public_key: public_key.to_owned(),
                    private_key: private_key.to_owned(),
                })
                .clone();
            Ok(key)
        }

        async fn list_external_auth_links(
            &self,
            user_id: Uuid,
        ) -> Result<Vec<ExternalAuthLinkRecord>, StorageError> {
            Ok(self
                .external_auth_links
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .iter()
                .filter(|((stored_user_id, _), _)| *stored_user_id == user_id)
                .map(|(_, link)| link.clone())
                .collect())
        }

        async fn find_external_auth_link(
            &self,
            user_id: Uuid,
            provider_id: &str,
        ) -> Result<Option<ExternalAuthLinkRecord>, StorageError> {
            self.external_auth_links
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))
                .map(|links| links.get(&(user_id, provider_id.to_owned())).cloned())
        }

        async fn delete_external_auth_link(
            &self,
            user_id: Uuid,
            provider_id: &str,
        ) -> Result<bool, StorageError> {
            Ok(self
                .external_auth_links
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?
                .remove(&(user_id, provider_id.to_owned()))
                .is_some())
        }

        async fn upsert_external_auth_link(
            &self,
            user_id: Uuid,
            link: &UpsertExternalAuthLinkInput,
        ) -> Result<ExternalAuthLinkRecord, StorageError> {
            let mut links = self
                .external_auth_links
                .lock()
                .map_err(|error| StorageError::unavailable(error.to_string()))?;
            let now = OffsetDateTime::now_utc();
            let created_at = links
                .get(&(user_id, link.provider_id.clone()))
                .map(|existing| existing.created_at)
                .unwrap_or(now);
            let record = ExternalAuthLinkRecord {
                provider_id: link.provider_id.clone(),
                created_at,
                updated_at: now,
                has_refresh_token: !link.refresh_token.is_empty(),
                expires: link.expires_at,
                access_token: link.access_token.clone(),
                refresh_token: link.refresh_token.clone(),
                token_type: link.token_type.clone(),
                scopes: link.scopes.clone(),
                authenticated: link.authenticated,
                validate_error: link.validate_error.clone(),
                refresh_error: link.refresh_error.clone(),
                last_validated_at: link.last_validated_at,
                last_refreshed_at: link.last_refreshed_at,
                user: link.user.clone(),
                installations: link.installations.clone(),
                app_installable: link.app_installable,
            };
            links.insert((user_id, link.provider_id.clone()), record.clone());
            Ok(record)
        }
    }

    fn test_config() -> Result<ServerConfig, url::ParseError> {
        Ok(ServerConfig {
            listen_addr: std::net::SocketAddr::from(([127, 0, 0, 1], 3000)),
            access_url: Url::parse("http://127.0.0.1:3000")?,
            database: DatabaseConfig {
                postgres_url: "postgres://unused".to_owned(),
                max_connections: 20,
                min_connections: 1,
                acquire_timeout_secs: 10,
            },
            telemetry_enabled: false,
            ssh: SshConfig {
                hostname_prefix: "coder".to_owned(),
                hostname_suffix: "example.internal".to_owned(),
                ssh_config_options: vec![("StrictHostKeyChecking".to_owned(), "no".to_owned())],
            },
            external_auth_providers: Vec::new(),
            derp_regions: Vec::new(),
            shutdown_grace_period_secs: 10,
            log_format: LogFormat::Pretty,
        })
    }

    fn test_state_with_store(
        health_ok: bool,
    ) -> Result<(AppState, Arc<FakeStore>), Box<dyn Error>> {
        let store = Arc::new(FakeStore::new(health_ok));
        let store_trait: Arc<dyn AppStore> = store.clone();
        let audit: Arc<dyn AuditSink> = Arc::new(MemoryAuditSink::default());

        Ok((
            AppState::new(
                test_config()?,
                BuildMetadata::default(),
                Uuid::nil(),
                store_trait,
                audit,
            )?,
            store,
        ))
    }

    fn test_state(health_ok: bool) -> Result<AppState, Box<dyn Error>> {
        test_state_with_store(health_ok).map(|(state, _)| state)
    }

    fn request(method: Method, uri: &str) -> Result<Request<Body>, http::Error> {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
    }

    fn json_request<T: Serialize>(
        method: Method,
        uri: &str,
        payload: &T,
    ) -> Result<Request<Body>, Box<dyn Error>> {
        let body = serde_json::to_vec(payload)?;
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(body))?;
        Ok(request)
    }

    fn authenticated_request(
        method: Method,
        uri: &str,
        session_token: &str,
    ) -> Result<Request<Body>, http::Error> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(SESSION_TOKEN_HEADER, session_token)
            .body(Body::empty())
    }

    fn authenticated_json_request<T: Serialize>(
        method: Method,
        uri: &str,
        session_token: &str,
        payload: &T,
    ) -> Result<Request<Body>, Box<dyn Error>> {
        let body = serde_json::to_vec(payload)?;
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header(CONTENT_TYPE, "application/json")
            .header(SESSION_TOKEN_HEADER, session_token)
            .body(Body::from(body))?;
        Ok(request)
    }

    fn request_with_cookies(
        method: Method,
        uri: &str,
        cookies: &[(&str, &str)],
    ) -> Result<Request<Body>, http::Error> {
        let cookie_header = cookies
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ");
        Request::builder()
            .method(method)
            .uri(uri)
            .header(http::header::COOKIE, cookie_header)
            .body(Body::empty())
    }

    async fn call(app: Router, request: Request<Body>) -> Result<Response<Body>, Box<dyn Error>> {
        let response = match app.oneshot(request).await {
            Ok(response) => response,
            Err(never) => match never {},
        };

        Ok(response)
    }

    async fn response_json(response: Response<Body>) -> Result<Value, Box<dyn Error>> {
        let bytes = to_bytes(response.into_body(), usize::MAX).await?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    async fn create_and_login(app: &Router) -> Result<String, Box<dyn Error>> {
        let create_response = call(
            app.clone(),
            json_request(
                Method::POST,
                "/api/v2/users/first",
                &CreateFirstUserRequest {
                    email: "owner@example.com".to_owned(),
                    username: "owner".to_owned(),
                    name: "Owner".to_owned(),
                    password: "Password123".to_owned(),
                },
            )?,
        )
        .await?;
        assert_eq!(create_response.status(), StatusCode::CREATED);

        let login_response = call(
            app.clone(),
            json_request(
                Method::POST,
                "/api/v2/users/login",
                &LoginWithPasswordRequest {
                    email: "owner@example.com".to_owned(),
                    password: "Password123".to_owned(),
                },
            )?,
        )
        .await?;
        assert_eq!(login_response.status(), StatusCode::CREATED);
        let login_body = response_json(login_response).await?;
        Ok(login_body
            .get("session_token")
            .and_then(Value::as_str)
            .ok_or("missing session token")?
            .to_owned())
    }

    async fn spawn_test_server(
        router: Router,
    ) -> Result<(Url, tokio::task::JoinHandle<()>), Box<dyn Error>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, router.into_make_service()).await;
        });
        Ok((Url::parse(&format!("http://{address}"))?, handle))
    }

    async fn first_organization_id(
        app: &Router,
        session_token: &str,
    ) -> Result<Uuid, Box<dyn Error>> {
        let response = call(
            app.clone(),
            authenticated_request(Method::GET, "/api/v2/organizations", session_token)?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await?;
        let org_id = body
            .as_array()
            .and_then(|organizations| organizations.first())
            .and_then(|organization| organization.get("id"))
            .and_then(Value::as_str)
            .ok_or("missing organization id")?;
        Ok(Uuid::parse_str(org_id)?)
    }

    #[tokio::test]
    async fn root_endpoint_returns_slim_build_response() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let response = call(app, request(Method::GET, "/")?).await?;

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), usize::MAX).await?;
        assert_eq!(String::from_utf8(bytes.to_vec())?, SLIM_BUILD_MESSAGE);
        Ok(())
    }

    #[tokio::test]
    async fn api_root_returns_wave_message() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let response = call(app, request(Method::GET, "/api/v2")?).await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await?;
        assert_eq!(
            body.get("message").and_then(Value::as_str),
            Some("\u{1f44b}")
        );
        Ok(())
    }

    #[tokio::test]
    async fn updatecheck_returns_current_build_metadata() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let response = call(app, request(Method::GET, "/api/v2/updatecheck")?).await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await?;
        assert_eq!(body.get("current").and_then(Value::as_bool), Some(true));
        assert_eq!(
            body.get("version").and_then(Value::as_str),
            Some(env!("CARGO_PKG_VERSION"))
        );
        assert_eq!(
            body.get("url").and_then(Value::as_str),
            Some("https://github.com/coder/coder")
        );
        Ok(())
    }

    #[tokio::test]
    async fn csp_reports_require_auth_and_return_ok() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);

        let unauthorized = call(
            app.clone(),
            json_request(
                Method::POST,
                "/api/v2/csp/reports",
                &json!({ "csp-report": { "blocked-uri": "https://example.com" } }),
            )?,
        )
        .await?;
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

        let session_token = create_and_login(&app).await?;
        let response = call(
            app,
            authenticated_json_request(
                Method::POST,
                "/api/v2/csp/reports",
                &session_token,
                &json!({ "csp-report": { "blocked-uri": "https://example.com" } }),
            )?,
        )
        .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await?;
        assert_eq!(body, Value::String("ok".to_owned()));
        Ok(())
    }

    #[tokio::test]
    async fn csp_reports_reject_invalid_json() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;
        let request = Request::builder()
            .method(Method::POST)
            .uri("/api/v2/csp/reports")
            .header(CONTENT_TYPE, "application/json")
            .header(SESSION_TOKEN_HEADER, session_token)
            .body(Body::from("{"))?;

        let response = call(app, request).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response_json(response).await?;
        assert_eq!(
            body.get("message").and_then(Value::as_str),
            Some("Failed to read body, invalid json.")
        );
        Ok(())
    }

    #[tokio::test]
    async fn init_script_returns_rendered_shell_script() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let response = call(
            app,
            request(Method::GET, "/api/v2/init-script/linux/amd64")?,
        )
        .await?;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("text/plain; charset=utf-8")
        );
        assert!(
            response.headers().contains_key("content-digest"),
            "expected content-digest header"
        );
        let bytes = to_bytes(response.into_body(), usize::MAX).await?;
        let body = String::from_utf8(bytes.to_vec())?;
        assert!(body.contains("coder-linux-amd64"));
        assert!(body.contains("CODER_AGENT_AUTH=\"token\""));
        assert!(body.contains("CODER_AGENT_URL=\"http://127.0.0.1:3000/\""));
        Ok(())
    }

    #[tokio::test]
    async fn init_script_rejects_unknown_targets() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let response = call(
            app,
            request(Method::GET, "/api/v2/init-script/plan9/amd64")?,
        )
        .await?;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response_json(response).await?;
        assert_eq!(
            body.get("message").and_then(Value::as_str),
            Some("Unknown os/arch: plan9/amd64")
        );
        Ok(())
    }

    #[tokio::test]
    async fn first_user_endpoint_returns_404_and_build_version_header_when_missing()
    -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let response = call(app, request(Method::GET, "/api/v2/users/first")?).await?;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response
                .headers()
                .get(BUILD_VERSION_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some(env!("CARGO_PKG_VERSION"))
        );
        Ok(())
    }

    #[tokio::test]
    async fn create_first_user_then_login_and_fetch_me() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        let user_response = call(
            app,
            authenticated_request(Method::GET, "/api/v2/users/me", &session_token)?,
        )
        .await?;
        assert_eq!(user_response.status(), StatusCode::OK);
        let user_body = response_json(user_response).await?;
        assert_eq!(
            user_body.get("email").and_then(Value::as_str),
            Some("owner@example.com")
        );
        assert_eq!(
            user_body.get("username").and_then(Value::as_str),
            Some("owner")
        );
        Ok(())
    }

    #[tokio::test]
    async fn auth_scopes_and_experiments_routes_return_expected_defaults()
    -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        let scopes_response =
            call(app.clone(), request(Method::GET, "/api/v2/auth/scopes")?).await?;
        assert_eq!(scopes_response.status(), StatusCode::OK);
        let scopes_body = response_json(scopes_response).await?;
        assert_eq!(
            scopes_body
                .get("external")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(PUBLIC_API_KEY_SCOPES.len())
        );

        let experiments_response = call(
            app.clone(),
            authenticated_request(Method::GET, "/api/v2/experiments", &session_token)?,
        )
        .await?;
        assert_eq!(experiments_response.status(), StatusCode::OK);
        assert_eq!(
            response_json(experiments_response).await?,
            Value::Array(Vec::new())
        );

        let available_response = call(
            app,
            authenticated_request(Method::GET, "/api/v2/experiments/available", &session_token)?,
        )
        .await?;
        assert_eq!(available_response.status(), StatusCode::OK);
        let available_body = response_json(available_response).await?;
        assert_eq!(
            available_body
                .get("safe")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(0)
        );

        Ok(())
    }

    #[tokio::test]
    async fn external_auth_and_debug_routes_return_current_fallbacks() -> Result<(), Box<dyn Error>>
    {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        let list_response = call(
            app.clone(),
            authenticated_request(Method::GET, "/api/v2/external-auth", &session_token)?,
        )
        .await?;
        assert_eq!(list_response.status(), StatusCode::OK);
        let list_body = response_json(list_response).await?;
        assert_eq!(
            list_body
                .get("providers")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(0)
        );
        assert_eq!(
            list_body
                .get("links")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(0)
        );

        let provider_response = call(
            app.clone(),
            authenticated_request(Method::GET, "/api/v2/external-auth/github", &session_token)?,
        )
        .await?;
        assert_eq!(provider_response.status(), StatusCode::NOT_FOUND);

        let debug_response = call(
            app.clone(),
            authenticated_request(Method::GET, "/api/v2/debug/me/debug-link", &session_token)?,
        )
        .await?;
        assert_eq!(debug_response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response_json(debug_response)
                .await?
                .get("message")
                .and_then(Value::as_str),
            Some("User is not an OIDC user.")
        );

        let autofill_response = call(
            app,
            authenticated_request(
                Method::GET,
                &format!(
                    "/api/v2/users/me/autofill-parameters?template_id={}",
                    Uuid::nil()
                ),
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(autofill_response.status(), StatusCode::OK);
        assert_eq!(
            response_json(autofill_response).await?,
            Value::Array(Vec::new())
        );

        Ok(())
    }

    #[tokio::test]
    async fn operational_admin_routes_use_backing_store() -> Result<(), Box<dyn Error>> {
        let (mut state, store) = test_state_with_store(true)?;
        let (health_url, health_handle) = spawn_test_server(
            Router::new()
                .route("/healthz", get(|| async { (StatusCode::OK, "OK") }))
                .route("/latency-check", get(|| async { (StatusCode::OK, "OK") })),
        )
        .await?;
        state.config.access_url = health_url;
        state.config.external_auth_providers = vec![ExternalAuthLinkProvider {
            id: "github".to_owned(),
            provider_type: "github".to_owned(),
            device: false,
            display_name: "GitHub".to_owned(),
            display_icon: "github".to_owned(),
            allow_refresh: false,
            allow_validate: true,
            supports_revocation: false,
            code_challenge_methods_supported: Vec::new(),
            ..ExternalAuthLinkProvider::default()
        }];
        let app = build_router(state);
        let session_token = create_and_login(&app).await?;

        store
            .external_auth_links
            .lock()
            .map_err(|error| error.to_string())?
            .insert(
                (Uuid::from_u128(1), "github".to_owned()),
                ExternalAuthLinkRecord {
                    provider_id: "github".to_owned(),
                    created_at: OffsetDateTime::now_utc(),
                    updated_at: OffsetDateTime::now_utc(),
                    has_refresh_token: false,
                    expires: OffsetDateTime::now_utc() + time::Duration::hours(1),
                    access_token: "access-token".to_owned(),
                    refresh_token: String::new(),
                    token_type: "bearer".to_owned(),
                    scopes: Vec::new(),
                    authenticated: true,
                    validate_error: String::new(),
                    refresh_error: String::new(),
                    last_validated_at: Some(OffsetDateTime::now_utc()),
                    last_refreshed_at: None,
                    user: Some(ExternalAuthUser {
                        id: 1,
                        login: "coder".to_owned(),
                        avatar_url: String::new(),
                        profile_url: "https://github.com/coder".to_owned(),
                        name: "Coder".to_owned(),
                    }),
                    installations: Vec::new(),
                    app_installable: false,
                },
            );

        let health_response = call(
            app.clone(),
            authenticated_request(Method::GET, "/api/v2/debug/health", &session_token)?,
        )
        .await?;
        assert_eq!(health_response.status(), StatusCode::OK);
        assert_eq!(
            response_json(health_response)
                .await?
                .get("healthy")
                .and_then(Value::as_bool),
            Some(true)
        );

        let update_health_response = call(
            app.clone(),
            authenticated_json_request(
                Method::PUT,
                "/api/v2/debug/health/settings",
                &session_token,
                &HealthSettings {
                    dismissed_healthchecks: vec!["Database".to_owned()],
                },
            )?,
        )
        .await?;
        assert_eq!(update_health_response.status(), StatusCode::OK);

        let audit_generate_response = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                "/api/v2/audit/testgenerate",
                &session_token,
                &CreateTestAuditLogRequest::default(),
            )?,
        )
        .await?;
        assert_eq!(audit_generate_response.status(), StatusCode::NO_CONTENT);

        let audit_list_response = call(
            app.clone(),
            authenticated_request(Method::GET, "/api/v2/audit", &session_token)?,
        )
        .await?;
        assert_eq!(audit_list_response.status(), StatusCode::OK);
        assert_eq!(
            response_json(audit_list_response)
                .await?
                .get("count")
                .and_then(Value::as_u64),
            Some(1)
        );

        let git_ssh_key_response = call(
            app.clone(),
            authenticated_request(Method::GET, "/api/v2/users/me/gitsshkey", &session_token)?,
        )
        .await?;
        assert_eq!(git_ssh_key_response.status(), StatusCode::OK);
        assert_eq!(
            response_json(git_ssh_key_response)
                .await?
                .get("public_key")
                .and_then(Value::as_str)
                .map(|value| value.starts_with("ssh-ed25519 ")),
            Some(true)
        );

        let external_auth_response = call(
            app.clone(),
            authenticated_request(Method::GET, "/api/v2/external-auth/github", &session_token)?,
        )
        .await?;
        assert_eq!(external_auth_response.status(), StatusCode::OK);
        assert_eq!(
            response_json(external_auth_response)
                .await?
                .get("authenticated")
                .and_then(Value::as_bool),
            Some(true)
        );

        let delete_external_auth_response = call(
            app,
            authenticated_request(
                Method::DELETE,
                "/api/v2/external-auth/github",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(delete_external_auth_response.status(), StatusCode::OK);
        health_handle.abort();

        Ok(())
    }

    #[tokio::test]
    async fn deployment_stats_reflect_seeded_workspace_and_agent_data() -> Result<(), Box<dyn Error>>
    {
        let (state, store) = test_state_with_store(true)?;
        let app = build_router(state);
        let session_token = create_and_login(&app).await?;

        let now = OffsetDateTime::now_utc();
        let running_workspace = Uuid::new_v4();
        let failed_workspace = Uuid::new_v4();
        let running_job = Uuid::new_v4();
        let failed_job = Uuid::new_v4();

        store
            .upsert_workspace_stats_workspace(&WorkspaceStatsWorkspaceInput {
                id: running_workspace,
                deleted: false,
            })
            .await?;
        store
            .upsert_workspace_stats_workspace(&WorkspaceStatsWorkspaceInput {
                id: failed_workspace,
                deleted: false,
            })
            .await?;
        store
            .upsert_provisioner_job_stats(&ProvisionerJobStatsInput {
                id: running_job,
                created_at: now - time::Duration::minutes(5),
                updated_at: now - time::Duration::minutes(1),
                started_at: Some(now - time::Duration::minutes(4)),
                canceled_at: None,
                completed_at: Some(now - time::Duration::minutes(1)),
                error: String::new(),
            })
            .await?;
        store
            .upsert_provisioner_job_stats(&ProvisionerJobStatsInput {
                id: failed_job,
                created_at: now - time::Duration::minutes(5),
                updated_at: now - time::Duration::minutes(2),
                started_at: Some(now - time::Duration::minutes(4)),
                canceled_at: None,
                completed_at: Some(now - time::Duration::minutes(2)),
                error: "boom".to_owned(),
            })
            .await?;
        store
            .upsert_workspace_build_stats(&WorkspaceBuildStatsInput {
                id: Uuid::new_v4(),
                workspace_id: running_workspace,
                created_at: now - time::Duration::minutes(5),
                updated_at: now - time::Duration::minutes(1),
                build_number: 1,
                transition: "start".to_owned(),
                job_id: Some(running_job),
            })
            .await?;
        store
            .upsert_workspace_build_stats(&WorkspaceBuildStatsInput {
                id: Uuid::new_v4(),
                workspace_id: failed_workspace,
                created_at: now - time::Duration::minutes(5),
                updated_at: now - time::Duration::minutes(2),
                build_number: 1,
                transition: "start".to_owned(),
                job_id: Some(failed_job),
            })
            .await?;
        store
            .insert_workspace_agent_stat(&WorkspaceAgentStatInput {
                id: Uuid::new_v4(),
                created_at: now - time::Duration::minutes(1),
                user_id: Some(Uuid::from_u128(1)),
                workspace_id: Some(running_workspace),
                template_id: None,
                agent_id: Uuid::new_v4(),
                connections_by_proto: json!({"ssh": 2}),
                connection_count: 1,
                rx_packets: 10,
                rx_bytes: 128,
                tx_packets: 20,
                tx_bytes: 256,
                session_count_vscode: 1,
                session_count_jetbrains: 0,
                session_count_reconnecting_pty: 0,
                session_count_ssh: 2,
                connection_median_latency_ms: 42.0,
                usage: false,
            })
            .await?;

        let response = call(
            app,
            authenticated_request(Method::GET, "/api/v2/deployment/stats", &session_token)?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);

        let body = response_json(response).await?;
        assert_eq!(
            body.get("workspaces")
                .and_then(|value| value.get("running"))
                .and_then(Value::as_i64),
            Some(1)
        );
        assert_eq!(
            body.get("workspaces")
                .and_then(|value| value.get("failed"))
                .and_then(Value::as_i64),
            Some(1)
        );
        assert_eq!(
            body.get("session_count")
                .and_then(|value| value.get("ssh"))
                .and_then(Value::as_i64),
            Some(2)
        );
        assert_eq!(
            body.get("workspaces")
                .and_then(|value| value.get("rx_bytes"))
                .and_then(Value::as_i64),
            Some(128)
        );

        Ok(())
    }

    #[tokio::test]
    async fn debug_health_reports_derp_proxy_and_provisioner_sections() -> Result<(), Box<dyn Error>>
    {
        let (health_url, health_handle) = spawn_test_server(
            Router::new()
                .route("/healthz", get(|| async { (StatusCode::OK, "OK") }))
                .route("/latency-check", get(|| async { (StatusCode::OK, "OK") })),
        )
        .await?;
        let (derp_url, derp_handle) = spawn_test_server(
            Router::new().route("/probe", get(|| async { (StatusCode::OK, "DERP") })),
        )
        .await?;
        let (proxy_url, proxy_handle) = spawn_test_server(
            Router::new().route("/healthz", get(|| async { (StatusCode::OK, "OK") })),
        )
        .await?;

        let (mut state, store) = test_state_with_store(true)?;
        state.config.access_url = health_url;
        state.config.derp_regions = vec![DerpRegionConfig {
            id: 1,
            name: "local".to_owned(),
            nodes: vec![DerpNodeConfig {
                name: "node-1".to_owned(),
                url: derp_url.join("/probe")?,
            }],
        }];
        store
            .upsert_workspace_proxy_for_health(&WorkspaceProxyHealthInput {
                id: Uuid::new_v4(),
                name: "proxy-eu".to_owned(),
                display_name: "Proxy EU".to_owned(),
                icon_url: String::new(),
                path_app_url: proxy_url.to_string(),
                wildcard_hostname: String::new(),
                derp_enabled: false,
                derp_only: false,
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
                deleted: false,
                version: "0.1.0".to_owned(),
            })
            .await?;
        store
            .upsert_provisioner_daemon_for_health(&ProvisionerDaemonHealthInput {
                id: Uuid::new_v4(),
                organization_id: Uuid::from_u128(2),
                created_at: OffsetDateTime::now_utc(),
                last_seen_at: Some(OffsetDateTime::now_utc()),
                name: "daemon-eu".to_owned(),
                version: "0.1.0".to_owned(),
                api_version: "v1".to_owned(),
                provisioners: vec!["terraform".to_owned()],
                tags: HashMap::new(),
                status: Some("idle".to_owned()),
            })
            .await?;

        let app = build_router(state);
        let session_token = create_and_login(&app).await?;

        let response = call(
            app,
            authenticated_request(Method::GET, "/api/v2/debug/health", &session_token)?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);

        let body = response_json(response).await?;
        assert_eq!(
            body.get("derp")
                .and_then(|value| value.get("regions"))
                .and_then(|value| value.get("local"))
                .and_then(Value::as_str),
            Some("1/1 nodes healthy")
        );
        assert_eq!(
            body.get("workspace_proxy")
                .and_then(|value| value.get("items"))
                .and_then(Value::as_array)
                .and_then(|value| value.first())
                .and_then(Value::as_str),
            Some("proxy-eu: ok")
        );
        assert_eq!(
            body.get("provisioner_daemons")
                .and_then(|value| value.get("items"))
                .and_then(Value::as_array)
                .and_then(|value| value.first())
                .and_then(Value::as_str),
            Some("daemon-eu: idle")
        );

        health_handle.abort();
        derp_handle.abort();
        proxy_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn external_auth_get_refreshes_and_delete_revokes() -> Result<(), Box<dyn Error>> {
        let revoke_hits = Arc::new(Mutex::new(0usize));
        let provider_state = revoke_hits.clone();
        let (provider_url, provider_handle) = spawn_test_server(
            Router::new()
                .route(
                    "/token",
                    post(|| async {
                        Json(json!({
                            "access_token": "fresh-access-token",
                            "refresh_token": "fresh-refresh-token",
                            "token_type": "bearer",
                            "scope": "read_api",
                            "expires_in": 1800
                        }))
                    }),
                )
                .route(
                    "/user",
                    get(|headers: HeaderMap| async move {
                        let authenticated = headers
                            .get(http::header::AUTHORIZATION)
                            .and_then(|value| value.to_str().ok())
                            == Some("Bearer fresh-access-token");
                        if authenticated {
                            (
                                StatusCode::OK,
                                Json(json!({
                                    "id": 99,
                                    "login": "refreshed-user",
                                    "avatar_url": "",
                                    "html_url": "https://gitlab.example.com/refreshed-user",
                                    "name": "Refreshed User"
                                })),
                            )
                                .into_response()
                        } else {
                            StatusCode::UNAUTHORIZED.into_response()
                        }
                    }),
                )
                .route(
                    "/revoke",
                    post(move || {
                        let provider_state = provider_state.clone();
                        async move {
                            if let Ok(mut hits) = provider_state.lock() {
                                *hits += 1;
                            }
                            StatusCode::OK
                        }
                    }),
                ),
        )
        .await?;

        let (mut state, store) = test_state_with_store(true)?;
        state.config.external_auth_providers = vec![ExternalAuthLinkProvider {
            id: "gitlab".to_owned(),
            provider_type: "gitlab".to_owned(),
            display_name: "GitLab".to_owned(),
            display_icon: "gitlab".to_owned(),
            allow_refresh: true,
            allow_validate: true,
            supports_revocation: true,
            token_url: provider_url.join("/token")?.to_string(),
            user_url: provider_url.join("/user")?.to_string(),
            revoke_url: provider_url.join("/revoke")?.to_string(),
            client_id: "client-id".to_owned(),
            client_secret: "client-secret".to_owned(),
            ..ExternalAuthLinkProvider::default()
        }];
        let app = build_router(state);
        let session_token = create_and_login(&app).await?;

        store
            .external_auth_links
            .lock()
            .map_err(|error| error.to_string())?
            .insert(
                (Uuid::from_u128(1), "gitlab".to_owned()),
                ExternalAuthLinkRecord {
                    provider_id: "gitlab".to_owned(),
                    created_at: OffsetDateTime::now_utc() - time::Duration::minutes(30),
                    updated_at: OffsetDateTime::now_utc() - time::Duration::minutes(30),
                    has_refresh_token: true,
                    expires: OffsetDateTime::now_utc() - time::Duration::minutes(5),
                    access_token: "expired-access-token".to_owned(),
                    refresh_token: "valid-refresh-token".to_owned(),
                    token_type: "bearer".to_owned(),
                    scopes: Vec::new(),
                    authenticated: false,
                    validate_error: String::new(),
                    refresh_error: String::new(),
                    last_validated_at: None,
                    last_refreshed_at: None,
                    user: None,
                    installations: Vec::new(),
                    app_installable: false,
                },
            );

        let get_response = call(
            app.clone(),
            authenticated_request(Method::GET, "/api/v2/external-auth/gitlab", &session_token)?,
        )
        .await?;
        assert_eq!(get_response.status(), StatusCode::OK);
        let get_body = response_json(get_response).await?;
        assert_eq!(
            get_body.get("authenticated").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            get_body
                .get("user")
                .and_then(|value| value.get("login"))
                .and_then(Value::as_str),
            Some("refreshed-user")
        );

        let stored_link = store
            .external_auth_links
            .lock()
            .map_err(|error| error.to_string())?
            .get(&(Uuid::from_u128(1), "gitlab".to_owned()))
            .cloned()
            .ok_or("missing refreshed link")?;
        assert_eq!(stored_link.access_token, "fresh-access-token");
        assert_eq!(stored_link.refresh_token, "fresh-refresh-token");
        assert!(stored_link.last_refreshed_at.is_some());
        assert!(stored_link.last_validated_at.is_some());

        let delete_response = call(
            app,
            authenticated_request(
                Method::DELETE,
                "/api/v2/external-auth/gitlab",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(delete_response.status(), StatusCode::OK);
        let delete_body = response_json(delete_response).await?;
        assert_eq!(
            delete_body.get("token_revoked").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(*revoke_hits.lock().map_err(|error| error.to_string())?, 1);
        assert!(
            store
                .external_auth_links
                .lock()
                .map_err(|error| error.to_string())?
                .get(&(Uuid::from_u128(1), "gitlab".to_owned()))
                .is_none()
        );

        provider_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn external_auth_callback_persists_link_and_sanitizes_redirect()
    -> Result<(), Box<dyn Error>> {
        let (provider_url, provider_handle) = spawn_test_server(
            Router::new()
                .route(
                    "/token",
                    post(|| async {
                        Json(json!({
                            "access_token": "callback-access-token",
                            "refresh_token": "callback-refresh-token",
                            "expires_in": 1800
                        }))
                    }),
                )
                .route(
                    "/user",
                    get(|| async {
                        Json(json!({
                            "id": 1,
                            "login": "coder",
                            "avatar_url": "https://example.com/avatar.png",
                            "html_url": "https://github.com/coder",
                            "name": "Coder"
                        }))
                    }),
                ),
        )
        .await?;

        let (mut state, _store) = test_state_with_store(true)?;
        state.config.external_auth_providers = vec![ExternalAuthLinkProvider {
            id: "github".to_owned(),
            provider_type: "github".to_owned(),
            display_name: "GitHub".to_owned(),
            display_icon: "github".to_owned(),
            allow_validate: true,
            token_url: provider_url.join("/token")?.to_string(),
            user_url: provider_url.join("/user")?.to_string(),
            callback_url: "http://127.0.0.1/external-auth/github/callback".to_owned(),
            client_id: "client-id".to_owned(),
            client_secret: "client-secret".to_owned(),
            ..ExternalAuthLinkProvider::default()
        }];
        let app = build_router(state);
        let session_token = create_and_login(&app).await?;

        let callback_response = call(
            app.clone(),
            request_with_cookies(
                Method::GET,
                "/external-auth/github/callback?code=callback-code&state=known-state",
                &[
                    (SESSION_TOKEN_COOKIE, &session_token),
                    (OAUTH2_STATE_COOKIE, "known-state"),
                    (
                        OAUTH2_REDIRECT_COOKIE,
                        "https://malicious.example/internal/path?ok=1",
                    ),
                ],
            )?,
        )
        .await?;
        assert_eq!(callback_response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            callback_response
                .headers()
                .get(http::header::LOCATION)
                .and_then(|value| value.to_str().ok()),
            Some("/internal/path?ok=1")
        );

        let external_auth_response = call(
            app,
            authenticated_request(Method::GET, "/api/v2/external-auth/github", &session_token)?,
        )
        .await?;
        assert_eq!(external_auth_response.status(), StatusCode::OK);
        let body = response_json(external_auth_response).await?;
        assert_eq!(
            body.get("authenticated").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            body.get("user")
                .and_then(|value| value.get("login"))
                .and_then(Value::as_str),
            Some("coder")
        );
        provider_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn external_auth_device_flow_persists_link() -> Result<(), Box<dyn Error>> {
        let (provider_url, provider_handle) = spawn_test_server(
            Router::new()
                .route(
                    "/device",
                    post(|| async {
                        Json(json!({
                            "device_code": "device-code",
                            "user_code": "ABCD-EFGH",
                            "verification_uri": "https://example.com/device",
                            "expires_in": 900,
                            "interval": 5
                        }))
                    }),
                )
                .route(
                    "/token",
                    post(|| async {
                        Json(json!({
                            "access_token": "device-access-token",
                            "refresh_token": "device-refresh-token",
                            "expires_in": 900
                        }))
                    }),
                )
                .route(
                    "/user",
                    get(|| async {
                        Json(json!({
                            "id": 7,
                            "login": "device-user",
                            "avatar_url": "",
                            "profile_url": "https://gitlab.example.com/device-user",
                            "name": "Device User"
                        }))
                    }),
                ),
        )
        .await?;

        let (mut state, _store) = test_state_with_store(true)?;
        state.config.external_auth_providers = vec![ExternalAuthLinkProvider {
            id: "gitlab".to_owned(),
            provider_type: "gitlab".to_owned(),
            device: true,
            display_name: "GitLab".to_owned(),
            display_icon: "gitlab".to_owned(),
            device_authorization_url: provider_url.join("/device")?.to_string(),
            token_url: provider_url.join("/token")?.to_string(),
            user_url: provider_url.join("/user")?.to_string(),
            client_id: "client-id".to_owned(),
            client_secret: "client-secret".to_owned(),
            scopes: vec!["read_api".to_owned()],
            ..ExternalAuthLinkProvider::default()
        }];
        let app = build_router(state);
        let session_token = create_and_login(&app).await?;

        let device_response = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                "/api/v2/external-auth/gitlab/device",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(device_response.status(), StatusCode::OK);
        assert_eq!(
            response_json(device_response)
                .await?
                .get("device_code")
                .and_then(Value::as_str),
            Some("device-code")
        );

        let exchange_response = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                "/api/v2/external-auth/gitlab/device",
                &session_token,
                &json!({ "device_code": "device-code" }),
            )?,
        )
        .await?;
        assert_eq!(exchange_response.status(), StatusCode::NO_CONTENT);

        let external_auth_response = call(
            app,
            authenticated_request(Method::GET, "/api/v2/external-auth/gitlab", &session_token)?,
        )
        .await?;
        assert_eq!(external_auth_response.status(), StatusCode::OK);
        let body = response_json(external_auth_response).await?;
        assert_eq!(
            body.get("authenticated").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            body.get("user")
                .and_then(|value| value.get("login"))
                .and_then(Value::as_str),
            Some("device-user")
        );
        provider_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn owner_can_list_users_organizations_and_members() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        let users_response = call(
            app.clone(),
            authenticated_request(Method::GET, "/api/v2/users", &session_token)?,
        )
        .await?;
        assert_eq!(users_response.status(), StatusCode::OK);
        let users_body = response_json(users_response).await?;
        assert_eq!(users_body.get("count").and_then(Value::as_u64), Some(1));

        let orgs_response = call(
            app.clone(),
            authenticated_request(Method::GET, "/api/v2/organizations", &session_token)?,
        )
        .await?;
        assert_eq!(orgs_response.status(), StatusCode::OK);

        let members_response = call(
            app,
            authenticated_request(
                Method::GET,
                "/api/v2/organizations/first-organization/members",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(members_response.status(), StatusCode::OK);
        let members_body = response_json(members_response).await?;
        assert_eq!(members_body.as_array().map(Vec::len), Some(1));
        Ok(())
    }

    #[tokio::test]
    async fn token_api_key_lifecycle_and_logout_work() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        let create_token_response = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                "/api/v2/users/me/keys/tokens",
                &session_token,
                &CreateTokenRequest {
                    lifetime: Duration::from_secs(3600),
                    token_name: "ci-token".to_owned(),
                    ..CreateTokenRequest::default()
                },
            )?,
        )
        .await?;
        assert_eq!(create_token_response.status(), StatusCode::CREATED);
        let key_body = response_json(create_token_response).await?;
        assert!(key_body.get("key").and_then(Value::as_str).is_some());

        let list_response = call(
            app.clone(),
            authenticated_request(Method::GET, "/api/v2/users/me/keys/tokens", &session_token)?,
        )
        .await?;
        assert_eq!(list_response.status(), StatusCode::OK);
        let list_body = response_json(list_response).await?;
        assert_eq!(list_body.as_array().map(Vec::len), Some(1));

        let logout_response = call(
            app.clone(),
            authenticated_request(Method::POST, "/api/v2/users/logout", &session_token)?,
        )
        .await?;
        assert_eq!(logout_response.status(), StatusCode::OK);

        let after_logout = call(
            app,
            authenticated_request(Method::GET, "/api/v2/users/me", &session_token)?,
        )
        .await?;
        assert_eq!(after_logout.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[tokio::test]
    async fn owner_can_create_users_and_manage_site_roles() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;
        let organization_id = first_organization_id(&app, &session_token).await?;

        let create_user_response = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                "/api/v2/users",
                &session_token,
                &CreateUserRequestWithOrgs {
                    email: "member@example.com".to_owned(),
                    username: "member".to_owned(),
                    name: "Member User".to_owned(),
                    password: "Password123".to_owned(),
                    login_type: Some(LoginType::Password),
                    user_status: Some(UserStatus::Active),
                    organization_ids: vec![organization_id],
                },
            )?,
        )
        .await?;
        assert_eq!(create_user_response.status(), StatusCode::CREATED);

        let site_roles_response = call(
            app.clone(),
            authenticated_request(Method::GET, "/api/v2/users/roles", &session_token)?,
        )
        .await?;
        assert_eq!(site_roles_response.status(), StatusCode::OK);
        let site_roles_body = response_json(site_roles_response).await?;
        assert_eq!(site_roles_body.as_array().map(Vec::len), Some(4));

        let update_roles_response = call(
            app.clone(),
            authenticated_json_request(
                Method::PUT,
                "/api/v2/users/member/roles",
                &session_token,
                &UpdateRolesRequest {
                    roles: vec!["user-admin".to_owned()],
                },
            )?,
        )
        .await?;
        assert_eq!(update_roles_response.status(), StatusCode::OK);
        let update_roles_body = response_json(update_roles_response).await?;
        assert_eq!(
            update_roles_body
                .get("roles")
                .and_then(Value::as_array)
                .and_then(|roles| roles.first())
                .and_then(|role| role.get("name"))
                .and_then(Value::as_str),
            Some("user-admin")
        );

        let user_roles_response = call(
            app.clone(),
            authenticated_request(Method::GET, "/api/v2/users/member/roles", &session_token)?,
        )
        .await?;
        assert_eq!(user_roles_response.status(), StatusCode::OK);
        let user_roles_body = response_json(user_roles_response).await?;
        assert_eq!(
            user_roles_body
                .get("roles")
                .and_then(Value::as_array)
                .and_then(|roles| roles.first())
                .and_then(Value::as_str),
            Some("user-admin")
        );

        let organizations_response = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                "/api/v2/users/member/organizations",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(organizations_response.status(), StatusCode::OK);
        let organizations_body = response_json(organizations_response).await?;
        assert_eq!(organizations_body.as_array().map(Vec::len), Some(1));

        let organization_response = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                "/api/v2/users/member/organizations/first-organization",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(organization_response.status(), StatusCode::OK);

        let delete_response = call(
            app.clone(),
            authenticated_request(Method::DELETE, "/api/v2/users/member", &session_token)?,
        )
        .await?;
        assert_eq!(delete_response.status(), StatusCode::OK);

        let after_delete = call(
            app,
            authenticated_request(Method::GET, "/api/v2/users/member", &session_token)?,
        )
        .await?;
        assert_eq!(after_delete.status(), StatusCode::NOT_FOUND);
        Ok(())
    }

    #[tokio::test]
    async fn owner_can_list_and_update_organization_member_roles() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;
        let organization_id = first_organization_id(&app, &session_token).await?;

        let create_user_response = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                "/api/v2/users",
                &session_token,
                &CreateUserRequestWithOrgs {
                    email: "orgmember@example.com".to_owned(),
                    username: "orgmember".to_owned(),
                    name: "Org Member".to_owned(),
                    password: "Password123".to_owned(),
                    login_type: Some(LoginType::Password),
                    user_status: Some(UserStatus::Active),
                    organization_ids: vec![organization_id],
                },
            )?,
        )
        .await?;
        assert_eq!(create_user_response.status(), StatusCode::CREATED);

        let org_roles_response = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                "/api/v2/organizations/first-organization/members/roles",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(org_roles_response.status(), StatusCode::OK);
        let org_roles_body = response_json(org_roles_response).await?;
        assert_eq!(org_roles_body.as_array().map(Vec::len), Some(4));

        let update_member_roles_response = call(
            app.clone(),
            authenticated_json_request(
                Method::PUT,
                "/api/v2/organizations/first-organization/members/orgmember/roles",
                &session_token,
                &UpdateRolesRequest {
                    roles: vec!["organization-admin".to_owned()],
                },
            )?,
        )
        .await?;
        assert_eq!(update_member_roles_response.status(), StatusCode::OK);
        let update_member_roles_body = response_json(update_member_roles_response).await?;
        assert_eq!(
            update_member_roles_body
                .get("roles")
                .and_then(Value::as_array)
                .and_then(|roles| roles.first())
                .and_then(|role| role.get("name"))
                .and_then(Value::as_str),
            Some("organization-admin")
        );

        let member_response = call(
            app,
            authenticated_request(
                Method::GET,
                "/api/v2/organizations/first-organization/members/orgmember",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(member_response.status(), StatusCode::OK);
        let member_body = response_json(member_response).await?;
        assert_eq!(
            member_body
                .get("roles")
                .and_then(Value::as_array)
                .and_then(|roles| roles.first())
                .and_then(|role| role.get("name"))
                .and_then(Value::as_str),
            Some("organization-admin")
        );
        Ok(())
    }

    #[tokio::test]
    async fn actor_cannot_mutate_their_own_roles() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        let site_roles_response = call(
            app.clone(),
            authenticated_json_request(
                Method::PUT,
                "/api/v2/users/me/roles",
                &session_token,
                &UpdateRolesRequest {
                    roles: vec!["user-admin".to_owned()],
                },
            )?,
        )
        .await?;
        assert_eq!(site_roles_response.status(), StatusCode::BAD_REQUEST);

        let organization_roles_response = call(
            app.clone(),
            authenticated_json_request(
                Method::PUT,
                "/api/v2/organizations/first-organization/members/me/roles",
                &session_token,
                &UpdateRolesRequest {
                    roles: vec!["organization-admin".to_owned()],
                },
            )?,
        )
        .await?;
        assert_eq!(
            organization_roles_response.status(),
            StatusCode::BAD_REQUEST
        );

        let delete_self_response = call(
            app,
            authenticated_request(Method::DELETE, "/api/v2/users/me", &session_token)?,
        )
        .await?;
        assert_eq!(delete_self_response.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    #[tokio::test]
    async fn owner_can_get_paginated_members_and_self_login_type() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;
        let organization_id = first_organization_id(&app, &session_token).await?;

        let create_user_response = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                "/api/v2/users",
                &session_token,
                &CreateUserRequestWithOrgs {
                    email: "member@example.com".to_owned(),
                    username: "member".to_owned(),
                    name: "Member User".to_owned(),
                    password: "Password123".to_owned(),
                    login_type: Some(LoginType::Password),
                    user_status: Some(UserStatus::Active),
                    organization_ids: vec![organization_id],
                },
            )?,
        )
        .await?;
        assert_eq!(create_user_response.status(), StatusCode::CREATED);

        let paginated_members_response = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                "/api/v2/organizations/first-organization/paginated-members?limit=1&offset=0",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(paginated_members_response.status(), StatusCode::OK);
        let paginated_members_body = response_json(paginated_members_response).await?;
        assert_eq!(
            paginated_members_body.get("count").and_then(Value::as_u64),
            Some(2)
        );
        assert_eq!(
            paginated_members_body
                .get("members")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(1)
        );

        let login_type_response = call(
            app.clone(),
            authenticated_request(Method::GET, "/api/v2/users/me/login-type", &session_token)?,
        )
        .await?;
        assert_eq!(login_type_response.status(), StatusCode::OK);
        let login_type_body = response_json(login_type_response).await?;
        assert_eq!(
            login_type_body.get("login_type").and_then(Value::as_str),
            Some("password")
        );

        let forbidden_login_type_response = call(
            app,
            authenticated_request(
                Method::GET,
                "/api/v2/users/member/login-type",
                &session_token,
            )?,
        )
        .await?;
        assert_eq!(
            forbidden_login_type_response.status(),
            StatusCode::FORBIDDEN
        );
        Ok(())
    }

    #[tokio::test]
    async fn profile_status_and_settings_flows_work() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let owner_session_token = create_and_login(&app).await?;
        let organization_id = first_organization_id(&app, &owner_session_token).await?;

        let create_user_response = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                "/api/v2/users",
                &owner_session_token,
                &CreateUserRequestWithOrgs {
                    email: "member@example.com".to_owned(),
                    username: "member".to_owned(),
                    name: "Member User".to_owned(),
                    password: "Password123".to_owned(),
                    login_type: Some(LoginType::Password),
                    user_status: Some(UserStatus::Active),
                    organization_ids: vec![organization_id],
                },
            )?,
        )
        .await?;
        assert_eq!(create_user_response.status(), StatusCode::CREATED);

        let member_login_response = call(
            app.clone(),
            json_request(
                Method::POST,
                "/api/v2/users/login",
                &LoginWithPasswordRequest {
                    email: "member@example.com".to_owned(),
                    password: "Password123".to_owned(),
                },
            )?,
        )
        .await?;
        assert_eq!(member_login_response.status(), StatusCode::CREATED);
        let member_session_token = response_json(member_login_response)
            .await?
            .get("session_token")
            .and_then(Value::as_str)
            .ok_or("missing member session token")?
            .to_owned();

        let self_profile_response = call(
            app.clone(),
            authenticated_json_request(
                Method::PUT,
                "/api/v2/users/me/profile",
                &member_session_token,
                &UpdateUserProfileRequest {
                    username: "member".to_owned(),
                    name: "Updated Member".to_owned(),
                },
            )?,
        )
        .await?;
        assert_eq!(self_profile_response.status(), StatusCode::OK);
        let self_profile_body = response_json(self_profile_response).await?;
        assert_eq!(
            self_profile_body.get("name").and_then(Value::as_str),
            Some("Updated Member")
        );

        let forbidden_username_change = call(
            app.clone(),
            authenticated_json_request(
                Method::PUT,
                "/api/v2/users/me/profile",
                &member_session_token,
                &UpdateUserProfileRequest {
                    username: "member-renamed".to_owned(),
                    name: "Updated Member".to_owned(),
                },
            )?,
        )
        .await?;
        assert_eq!(forbidden_username_change.status(), StatusCode::NOT_FOUND);

        let owner_profile_response = call(
            app.clone(),
            authenticated_json_request(
                Method::PUT,
                "/api/v2/users/member/profile",
                &owner_session_token,
                &UpdateUserProfileRequest {
                    username: "member-renamed".to_owned(),
                    name: "Renamed Member".to_owned(),
                },
            )?,
        )
        .await?;
        assert_eq!(owner_profile_response.status(), StatusCode::OK);
        let owner_profile_body = response_json(owner_profile_response).await?;
        assert_eq!(
            owner_profile_body.get("username").and_then(Value::as_str),
            Some("member-renamed")
        );

        let suspend_response = call(
            app.clone(),
            authenticated_request(
                Method::PUT,
                "/api/v2/users/member-renamed/status/suspend",
                &owner_session_token,
            )?,
        )
        .await?;
        assert_eq!(suspend_response.status(), StatusCode::OK);
        let suspend_body = response_json(suspend_response).await?;
        assert_eq!(
            suspend_body.get("status").and_then(Value::as_str),
            Some("suspended")
        );

        let activate_response = call(
            app.clone(),
            authenticated_request(
                Method::PUT,
                "/api/v2/users/member-renamed/status/activate",
                &owner_session_token,
            )?,
        )
        .await?;
        assert_eq!(activate_response.status(), StatusCode::OK);
        let activate_body = response_json(activate_response).await?;
        assert_eq!(
            activate_body.get("status").and_then(Value::as_str),
            Some("active")
        );

        let get_appearance_response = call(
            app.clone(),
            authenticated_request(
                Method::GET,
                "/api/v2/users/me/appearance",
                &member_session_token,
            )?,
        )
        .await?;
        assert_eq!(get_appearance_response.status(), StatusCode::OK);

        let update_appearance_response = call(
            app.clone(),
            authenticated_json_request(
                Method::PUT,
                "/api/v2/users/me/appearance",
                &member_session_token,
                &UpdateUserAppearanceSettingsRequest {
                    theme_preference: "dark".to_owned(),
                    terminal_font: "jetbrains-mono".to_owned(),
                },
            )?,
        )
        .await?;
        assert_eq!(update_appearance_response.status(), StatusCode::OK);
        let update_appearance_body = response_json(update_appearance_response).await?;
        assert_eq!(
            update_appearance_body
                .get("terminal_font")
                .and_then(Value::as_str),
            Some("jetbrains-mono")
        );

        let update_preferences_response = call(
            app.clone(),
            authenticated_json_request(
                Method::PUT,
                "/api/v2/users/me/preferences",
                &member_session_token,
                &UpdateUserPreferenceSettingsRequest {
                    task_notification_alert_dismissed: true,
                },
            )?,
        )
        .await?;
        assert_eq!(update_preferences_response.status(), StatusCode::OK);
        let update_preferences_body = response_json(update_preferences_response).await?;
        assert_eq!(
            update_preferences_body
                .get("task_notification_alert_dismissed")
                .and_then(Value::as_bool),
            Some(true)
        );

        Ok(())
    }

    #[tokio::test]
    async fn validate_password_and_change_password_work() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let owner_session_token = create_and_login(&app).await?;
        let organization_id = first_organization_id(&app, &owner_session_token).await?;

        let create_user_response = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                "/api/v2/users",
                &owner_session_token,
                &CreateUserRequestWithOrgs {
                    email: "member@example.com".to_owned(),
                    username: "member".to_owned(),
                    name: "Member User".to_owned(),
                    password: "Password123".to_owned(),
                    login_type: Some(LoginType::Password),
                    user_status: Some(UserStatus::Active),
                    organization_ids: vec![organization_id],
                },
            )?,
        )
        .await?;
        assert_eq!(create_user_response.status(), StatusCode::CREATED);

        let member_login_response = call(
            app.clone(),
            json_request(
                Method::POST,
                "/api/v2/users/login",
                &LoginWithPasswordRequest {
                    email: "member@example.com".to_owned(),
                    password: "Password123".to_owned(),
                },
            )?,
        )
        .await?;
        assert_eq!(member_login_response.status(), StatusCode::CREATED);
        let member_session_token = response_json(member_login_response)
            .await?
            .get("session_token")
            .and_then(Value::as_str)
            .ok_or("missing member session token")?
            .to_owned();

        let validate_password_response = call(
            app.clone(),
            json_request(
                Method::POST,
                "/api/v2/users/validate-password",
                &ValidateUserPasswordRequest {
                    password: "short".to_owned(),
                },
            )?,
        )
        .await?;
        assert_eq!(validate_password_response.status(), StatusCode::OK);
        let validate_password_body = response_json(validate_password_response).await?;
        assert_eq!(
            validate_password_body.get("valid").and_then(Value::as_bool),
            Some(false)
        );

        let missing_old_password_response = call(
            app.clone(),
            authenticated_json_request(
                Method::PUT,
                "/api/v2/users/me/password",
                &member_session_token,
                &UpdateUserPasswordRequest {
                    old_password: String::new(),
                    password: "NewPassword123".to_owned(),
                },
            )?,
        )
        .await?;
        assert_eq!(
            missing_old_password_response.status(),
            StatusCode::BAD_REQUEST
        );

        let update_password_response = call(
            app.clone(),
            authenticated_json_request(
                Method::PUT,
                "/api/v2/users/me/password",
                &member_session_token,
                &UpdateUserPasswordRequest {
                    old_password: "Password123".to_owned(),
                    password: "NewPassword123".to_owned(),
                },
            )?,
        )
        .await?;
        assert_eq!(update_password_response.status(), StatusCode::NO_CONTENT);

        let invalidated_session_response = call(
            app.clone(),
            authenticated_request(Method::GET, "/api/v2/users/me", &member_session_token)?,
        )
        .await?;
        assert_eq!(
            invalidated_session_response.status(),
            StatusCode::UNAUTHORIZED
        );

        let old_password_login_response = call(
            app.clone(),
            json_request(
                Method::POST,
                "/api/v2/users/login",
                &LoginWithPasswordRequest {
                    email: "member@example.com".to_owned(),
                    password: "Password123".to_owned(),
                },
            )?,
        )
        .await?;
        assert_eq!(
            old_password_login_response.status(),
            StatusCode::UNAUTHORIZED
        );

        let new_password_login_response = call(
            app,
            json_request(
                Method::POST,
                "/api/v2/users/login",
                &LoginWithPasswordRequest {
                    email: "member@example.com".to_owned(),
                    password: "NewPassword123".to_owned(),
                },
            )?,
        )
        .await?;
        assert_eq!(new_password_login_response.status(), StatusCode::CREATED);
        Ok(())
    }

    #[tokio::test]
    async fn otp_request_and_reset_work() -> Result<(), Box<dyn Error>> {
        let (state, store) = test_state_with_store(true)?;
        let app = build_router(state);
        let owner_session_token = create_and_login(&app).await?;
        let organization_id = first_organization_id(&app, &owner_session_token).await?;

        let create_user_response = call(
            app.clone(),
            authenticated_json_request(
                Method::POST,
                "/api/v2/users",
                &owner_session_token,
                &CreateUserRequestWithOrgs {
                    email: "member@example.com".to_owned(),
                    username: "member".to_owned(),
                    name: "Member User".to_owned(),
                    password: "Password123".to_owned(),
                    login_type: Some(LoginType::Password),
                    user_status: Some(UserStatus::Active),
                    organization_ids: vec![organization_id],
                },
            )?,
        )
        .await?;
        assert_eq!(create_user_response.status(), StatusCode::CREATED);
        let create_user_body = response_json(create_user_response).await?;
        let member_id = Uuid::parse_str(
            create_user_body
                .get("id")
                .and_then(Value::as_str)
                .ok_or("missing member id")?,
        )?;

        let otp_request_response = call(
            app.clone(),
            json_request(
                Method::POST,
                "/api/v2/users/otp/request",
                &RequestOneTimePasscodeRequest {
                    email: "unknown@example.com".to_owned(),
                },
            )?,
        )
        .await?;
        assert_eq!(otp_request_response.status(), StatusCode::NO_CONTENT);

        store.set_one_time_passcode(
            member_id,
            "reset-passcode",
            OffsetDateTime::now_utc() + time::Duration::minutes(5),
        )?;

        let reset_response = call(
            app.clone(),
            json_request(
                Method::POST,
                "/api/v2/users/otp/change-password",
                &ChangePasswordWithOneTimePasscodeRequest {
                    email: "member@example.com".to_owned(),
                    password: "RecoveredPassword123".to_owned(),
                    one_time_passcode: "reset-passcode".to_owned(),
                },
            )?,
        )
        .await?;
        assert_eq!(reset_response.status(), StatusCode::NO_CONTENT);

        let old_password_login_response = call(
            app.clone(),
            json_request(
                Method::POST,
                "/api/v2/users/login",
                &LoginWithPasswordRequest {
                    email: "member@example.com".to_owned(),
                    password: "Password123".to_owned(),
                },
            )?,
        )
        .await?;
        assert_eq!(
            old_password_login_response.status(),
            StatusCode::UNAUTHORIZED
        );

        let new_password_login_response = call(
            app,
            json_request(
                Method::POST,
                "/api/v2/users/login",
                &LoginWithPasswordRequest {
                    email: "member@example.com".to_owned(),
                    password: "RecoveredPassword123".to_owned(),
                },
            )?,
        )
        .await?;
        assert_eq!(new_password_login_response.status(), StatusCode::CREATED);
        Ok(())
    }

    #[tokio::test]
    async fn oauth_userauth_surfaces_return_disabled() -> Result<(), Box<dyn Error>> {
        let app = build_router(test_state(true)?);
        let session_token = create_and_login(&app).await?;

        let github_device_response = call(
            app.clone(),
            request(Method::GET, "/api/v2/users/oauth2/github/device")?,
        )
        .await?;
        assert_eq!(github_device_response.status(), StatusCode::BAD_REQUEST);

        let github_callback_response = call(
            app.clone(),
            request(Method::GET, "/api/v2/users/oauth2/github/callback")?,
        )
        .await?;
        assert_eq!(github_callback_response.status(), StatusCode::BAD_REQUEST);

        let oidc_callback_response = call(
            app.clone(),
            request(Method::GET, "/api/v2/users/oidc/callback")?,
        )
        .await?;
        assert_eq!(oidc_callback_response.status(), StatusCode::BAD_REQUEST);

        let convert_login_response = call(
            app,
            authenticated_json_request(
                Method::POST,
                "/api/v2/users/me/convert-login",
                &session_token,
                &ConvertLoginRequest {
                    to_type: LoginType::Github,
                    password: "Password123".to_owned(),
                },
            )?,
        )
        .await?;
        assert_eq!(convert_login_response.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }
}
