//! Templates handlers.

use std::{collections::HashMap, str::FromStr, sync::Arc};

use async_trait::async_trait;
use axum::{
    Form, Json, Router,
    body::Bytes,
    extract::{
        DefaultBodyLimit, OriginalUri, Path, Query, State,
        rejection::JsonRejection,
        ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
    },
    http::{
        HeaderMap, HeaderName, HeaderValue, StatusCode,
        header::{
            ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS,
            ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_TYPE, LOCATION,
        },
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post, put},
};
use coder_audit::{AuditAction, AuditEvent, AuditSink};
use coder_auth::{
    AuthService, AuthServiceError, AuthenticatedRequest, ExternalAuthService,
    ExternalAuthServiceError, OAUTH2_REDIRECT_COOKIE, OAUTH2_STATE_COOKIE, OAuth2ProviderError,
    OAuth2ProviderService, cookie_from_headers, supported_auth_methods,
};
use coder_connectivity::{
    HealthService,
    agents::{AgentConnection, AgentError, AgentProvider},
    generate_git_ssh_key,
    tailnet::{DerpTrafficTracker, TailnetCoordinator},
};
use coder_core::StorageError;
use coder_core::api::{
    ArchiveTemplateVersionsRequest, ArchiveTemplateVersionsResponse, CreateTemplateRequest,
    CreateTemplateVersionDryRunRequest, CreateTemplateVersionRequest, DAUEntry, DAUsResponse,
    DynamicParametersRequest, DynamicParametersResponse, MatchedProvisioners, MinimalUser,
    PatchTemplateVersionRequest, ProvisionerJobLog, ProvisionerJobResponse, ProvisionerJobStatus,
    TemplateExample, TemplateFilter, TemplateResponse, TemplateVersionExternalAuth,
    TemplateVersionParameter, TemplateVersionPreset, TemplateVersionPresetParameter,
    TemplateVersionResponse, TemplateVersionVariable, UpdateActiveTemplateVersionRequest,
    UpdateTemplateMeta, WorkspaceBuildParameter, WorkspaceResource, WorkspaceResourceMetadata,
    WorkspaceResourceResponse,
};
use coder_core::api::{InsightsReportInterval, TemplateInsightsSection};
use coder_core::api::{
    UpdateWorkspaceACLRequest, WorkspaceACLGroup, WorkspaceACLResponse, WorkspaceACLUser,
};
use coder_core::ports::UpdateWorkspaceACLInput;
use coder_core::pubsub::PubSub;
use coder_core::template::{
    CreateProvisionerJobInput, CreateTemplateInput, CreateTemplateStoreError,
    CreateTemplateVersionInput, ProvisionerJobRecord as TemplateProvisionerJobRecord,
    TemplateListFilter, TemplateRecord, TemplateVersionListFilter, TemplateVersionRecord,
    UpdateTemplateMetaInput,
};
use coder_core::{
    AWSInstanceIdentityToken, ApiResponse, AppHostResponse, AppStore, AuditLogListFilter,
    AuthMethods, AuthenticatedUser, AuthorizationRequest, AvailableExperiments,
    AzureInstanceIdentityToken, BuildMetadata, ChangePasswordWithOneTimePasscodeRequest,
    ChatMessagePart, ChatMessageRecord, ChatMessageResponse, ChatMessageUsage,
    ChatMessageVisibility, ChatQueuedMessageRecord, ChatQueuedMessageResponse, ChatRecord,
    ChatResponse, ChatWithMessagesResponse, ConvertLoginRequest, CreateChatMessageApiResponse,
    CreateChatMessageRequest, CreateChatRequest, CreateFirstUserRequest, CreateFirstUserResponse,
    CreateLogSourceRequest, CreateTaskRequest, CreateTestAuditLogRequest, CreateTokenRequest,
    CreateUserRequestWithOrgs, CreateWorkspaceBuildInput, CreateWorkspaceInput, DERPMap,
    DERPMapRegion, DERPNode, DeploymentConfigResponse, ExternalApiKeyScopes,
    ExternalAuthDeviceExchangeRequest, GCPInstanceIdentityToken, GetUsersResponse, HealthSettings,
    HealthcheckReport, InsertChatInput, InsertChatMessageInput, InsertFileInput, InsertTaskInput,
    LoginType, LoginWithPasswordRequest, OAuth2AuthorizeRequest, OAuth2ProviderAppEndpoints,
    OAuth2ProviderAppResponse, OAuth2ProviderAppSecretFullResponse,
    OAuth2ProviderAppSecretResponse, OAuth2TokenRequest, OAuth2TokenResponse, OrganizationMember,
    OrganizationMemberWithUserData, OrganizationRecord, OrganizationResponse,
    PaginatedMembersResponse, PatchAgentLogsRequest, PatchAppStatusRequest, PersistAuditLogInput,
    PostOAuth2ProviderAppRequest, PutOAuth2ProviderAppRequest, RequestOneTimePasscodeRequest,
    ServerConfig, SshConfigResponse, TaskListFilter, TaskLogSnapshotEnvelope, TaskLogsResponse,
    TaskRecord, TaskResponse, TaskSendRequest, TasksListResponse, UpdateCheckResponse,
    UpdateInboxNotificationReadStatusRequest, UpdateNotificationTemplateMethod, UpdateRolesRequest,
    UpdateUserAppearanceSettingsRequest, UpdateUserNotificationPreferences,
    UpdateUserPasswordRequest, UpdateUserPreferenceSettingsRequest, UpdateUserProfileRequest,
    UploadFileResponse, UpsertPortShareInput, UserAppearanceSettings, UserListFilter,
    UserParameter, UserPreferenceSettings, UserRecord, UserResponse, UserRolesResponse, UserStatus,
    ValidateUserPasswordRequest, ValidationError, WebpushSubscription,
    WorkspaceAgentAuthenticateResponse, WorkspaceAgentConnectionInfo,
    WorkspaceAgentListContainersResponse, WorkspaceAgentListeningPortsResponse,
    WorkspaceListFilter,
};
use coder_identity::{IdentityService, IdentityServiceError};
use coder_provisioner::{InitScriptError, render_init_script};
use coder_rbac::{Action, Actor, Authorizer, Object, ROLE_AUDITOR, ResourceKind, ResourceType};
use coder_workspaces::DeploymentStatsService;
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use time::OffsetDateTime;
use tracing::debug;
use uuid::Uuid;

use crate::app::AppState;
use crate::error::AppError;
use crate::helpers::*;

/// Converts a `TemplateRecord` into a `TemplateResponse`.
pub(crate) fn template_response(rec: &TemplateRecord) -> TemplateResponse {
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

/// Returns the static list of built-in starter template examples.
///
/// This mirrors the Go `examples.List()` function which reads from the embedded
/// `examples.gen.json` file. The Rust implementation returns the same metadata
/// without embedding the full template archives or README markdown.
pub(crate) fn starter_template_examples() -> Vec<TemplateExample> {
    const BASE_URL: &str = "https://github.com/coder/coder/tree/main/examples/templates/";

    let entries: &[(&str, &str, &str, &str, &[&str])] = &[
        (
            "aws-devcontainer",
            "AWS EC2 (Devcontainer)",
            "Provision AWS EC2 VMs with a devcontainer as Coder workspaces",
            "/icon/aws.svg",
            &["vm", "linux", "aws", "persistent", "devcontainer"],
        ),
        (
            "aws-linux",
            "AWS EC2 (Linux)",
            "Provision AWS EC2 VMs as Coder workspaces",
            "/icon/aws.svg",
            &["vm", "linux", "aws", "persistent-vm"],
        ),
        (
            "aws-windows",
            "AWS EC2 (Windows)",
            "Provision AWS EC2 VMs as Coder workspaces",
            "/icon/aws.svg",
            &["vm", "windows", "aws"],
        ),
        (
            "azure-linux",
            "Azure VM (Linux)",
            "Provision Azure VMs as Coder workspaces",
            "/icon/azure.png",
            &["vm", "linux", "azure"],
        ),
        (
            "digitalocean-linux",
            "DigitalOcean Droplet (Linux)",
            "Provision DigitalOcean Droplets as Coder workspaces",
            "/icon/do.png",
            &["vm", "linux", "digitalocean"],
        ),
        (
            "docker",
            "Docker Containers",
            "Provision Docker containers as Coder workspaces",
            "/icon/docker.png",
            &["docker", "container"],
        ),
        (
            "docker-devcontainer",
            "Docker-in-Docker Dev Containers",
            "Provision Docker containers as Coder workspaces running Dev Containers via Docker-in-Docker.",
            "/icon/docker.png",
            &["docker", "container", "devcontainer"],
        ),
        (
            "docker-envbuilder",
            "Docker (Envbuilder)",
            "Provision envbuilder containers as Coder workspaces",
            "/icon/docker.png",
            &["container", "docker", "devcontainer", "envbuilder"],
        ),
        (
            "gcp-devcontainer",
            "Google Compute Engine (Devcontainer)",
            "Provision a Devcontainer on Google Compute Engine instances as Coder workspaces",
            "/icon/gcp.png",
            &["vm", "linux", "gcp", "devcontainer"],
        ),
        (
            "gcp-linux",
            "Google Compute Engine (Linux)",
            "Provision Google Compute Engine instances as Coder workspaces",
            "/icon/gcp.png",
            &["vm", "linux", "gcp"],
        ),
        (
            "gcp-vm-container",
            "Google Compute Engine (VM Container)",
            "Provision Google Compute Engine instances as Coder workspaces",
            "/icon/gcp.png",
            &["vm-container", "linux", "gcp"],
        ),
        (
            "gcp-windows",
            "Google Compute Engine (Windows)",
            "Provision Google Compute Engine instances as Coder workspaces",
            "/icon/gcp.png",
            &["vm", "windows", "gcp"],
        ),
        (
            "kubernetes",
            "Kubernetes (Deployment)",
            "Provision Kubernetes Deployments as Coder workspaces",
            "/icon/k8s.png",
            &["kubernetes", "container"],
        ),
        (
            "kubernetes-devcontainer",
            "Kubernetes (Devcontainer)",
            "Provision envbuilder pods as Coder workspaces",
            "/icon/k8s.png",
            &["container", "kubernetes", "devcontainer"],
        ),
        (
            "nomad-docker",
            "Nomad",
            "Provision Nomad Jobs as Coder workspaces",
            "/icon/nomad.svg",
            &["nomad", "container"],
        ),
        (
            "scratch",
            "Scratch",
            "A minimal starter template for Coder",
            "/emojis/1f4e6.png",
            &[],
        ),
        (
            "tasks-docker",
            "Tasks on Docker",
            "Run Coder Tasks on Docker with an example application",
            "/icon/tasks.svg",
            &["docker", "container", "ai", "tasks"],
        ),
    ];

    entries
        .iter()
        .map(|(id, name, description, icon, tags)| TemplateExample {
            id: (*id).to_owned(),
            url: format!("{BASE_URL}{id}"),
            name: (*name).to_owned(),
            description: (*description).to_owned(),
            icon: (*icon).to_owned(),
            tags: tags.iter().map(|t| (*t).to_owned()).collect(),
            markdown: String::new(),
        })
        .collect()
}

/// Converts a `TemplateProvisionerJobRecord` into a `ProvisionerJobResponse`.
pub(crate) fn provisioner_job_response(
    job: &TemplateProvisionerJobRecord,
) -> ProvisionerJobResponse {
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

/// Converts a `TemplateVersionRecord` + `TemplateProvisionerJobRecord` into a `TemplateVersionResponse`.
pub(crate) fn template_version_response(
    ver: &TemplateVersionRecord,
    job: &TemplateProvisionerJobRecord,
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
            name: ver.created_by_name.clone(),
            avatar_url: ver.created_by_avatar_url.clone(),
        },
        archived: ver.archived,
        warnings: Vec::new(),
        has_external_agent: ver.has_external_agent.unwrap_or(false),
    }
}

/// Helper to build a template version response, fetching the provisioner job.
pub(crate) async fn build_tv_response(
    state: &AppState,
    ver: &TemplateVersionRecord,
) -> Result<TemplateVersionResponse, AppError> {
    let job = state.store.find_provisioner_job(ver.job_id).await?;
    let job = job.ok_or_else(|| {
        AppError::from(StorageError::invalid_data(format!(
            "provisioner job {} not found for version {}",
            ver.job_id, ver.id
        )))
    })?;
    Ok(template_version_response(ver, &job))
}

/// GET /organizations/{organization}/templates
pub(crate) async fn list_org_templates(
    State(state): State<AppState>,
    Path(org): Path<String>,
    headers: HeaderMap,
    Query(query): Query<TemplateFilter>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let org_record = match resolve_organization(&state, &org).await? {
        Some(o) => o,
        None => {
            return Ok(not_found_response(format!(
                "Organization '{org}' not found."
            )));
        }
    };

    let templates = state
        .store
        .list_templates(TemplateListFilter {
            organization_id: Some(org_record.id),
            exact_name: query.exact_name,
            search: query.search,
            deleted: query.deleted.unwrap_or(false),
        })
        .await?;

    // RBAC: filter templates the actor is allowed to read.
    let authorizer = Authorizer::new();
    let body: Vec<TemplateResponse> = templates
        .iter()
        .filter(|t| {
            let obj = Object::new(ResourceType::Template).in_org(t.organization_id);
            authorizer
                .authorize(&context.actor, Action::Read, &obj)
                .is_ok()
        })
        .map(template_response)
        .collect();
    Ok((StatusCode::OK, Json(body)).into_response())
}

/// POST /organizations/{organization}/templates
pub(crate) async fn post_org_template(
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

    let org_record = match resolve_organization(&state, &org).await? {
        Some(o) => o,
        None => {
            return Ok(not_found_response(format!(
                "Organization '{org}' not found."
            )));
        }
    };

    // RBAC: verify the actor can create templates in this org.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Create,
            &Object::new(ResourceType::Template).in_org(org_record.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to create templates in this organization.",
        ));
    }

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
pub(crate) async fn get_org_template_by_name(
    State(state): State<AppState>,
    Path((org, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let org_record = match resolve_organization(&state, &org).await? {
        Some(o) => o,
        None => {
            return Ok(not_found_response(format!(
                "Organization '{org}' not found."
            )));
        }
    };

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
pub(crate) async fn get_org_template_version_by_name(
    State(state): State<AppState>,
    Path((org, tname, vname)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let org_record = match resolve_organization(&state, &org).await? {
        Some(o) => o,
        None => {
            return Ok(not_found_response(format!(
                "Organization '{org}' not found."
            )));
        }
    };

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

/// GET /organizations/{organization}/templates/examples
pub(crate) async fn get_org_template_examples(
    State(state): State<AppState>,
    Path(org): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let org_record = match resolve_organization(&state, &org).await? {
        Some(o) => o,
        None => {
            return Ok(not_found_response(format!(
                "Organization '{org}' not found."
            )));
        }
    };

    // RBAC: check that the actor can read templates in this organization.
    let authorizer = Authorizer::new();
    let obj = Object::new(ResourceType::Template).in_org(org_record.id);
    if authorizer
        .authorize(&context.actor, Action::Read, &obj)
        .is_err()
    {
        return Ok(not_found_response("Resource not found.".to_owned()));
    }

    let examples = starter_template_examples();
    Ok((StatusCode::OK, Json(examples)).into_response())
}

/// GET /organizations/{organization}/templates/{templatename}/versions/{templateversionname}/previous
pub(crate) async fn get_org_previous_template_version(
    State(state): State<AppState>,
    Path((org, tname, vname)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let org_record = match resolve_organization(&state, &org).await? {
        Some(o) => o,
        None => {
            return Ok(not_found_response(format!(
                "Organization '{org}' not found."
            )));
        }
    };

    let ver = state
        .store
        .find_previous_template_version(org_record.id, &tname, &vname)
        .await?;

    match ver {
        Some(v) => {
            let resp = build_tv_response(&state, &v).await?;
            Ok((StatusCode::OK, Json(resp)).into_response())
        }
        None => Ok(not_found_response(format!(
            "No previous version found for '{vname}'."
        ))),
    }
}

/// POST /organizations/{organization}/templateversions
pub(crate) async fn post_org_template_version(
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

    let org_record = match resolve_organization(&state, &org).await? {
        Some(o) => o,
        None => {
            return Ok(not_found_response(format!(
                "Organization '{org}' not found."
            )));
        }
    };

    // RBAC: verify the actor can create template versions in this org.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Create,
            &Object::new(ResourceType::Template).in_org(org_record.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to create template versions in this organization.",
        ));
    }

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
        .create_provisioner_job(CreateProvisionerJobInput {
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

/// GET /templates
pub(crate) async fn list_all_templates(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<TemplateFilter>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let templates = state
        .store
        .list_templates(TemplateListFilter {
            organization_id: query.organization_id,
            exact_name: query.exact_name,
            search: query.search,
            deleted: query.deleted.unwrap_or(false),
        })
        .await?;

    // RBAC: filter templates the actor is allowed to read.
    let authorizer = Authorizer::new();
    let body: Vec<TemplateResponse> = templates
        .iter()
        .filter(|t| {
            let obj = Object::new(ResourceType::Template).in_org(t.organization_id);
            authorizer
                .authorize(&context.actor, Action::Read, &obj)
                .is_ok()
        })
        .map(template_response)
        .collect();
    Ok((StatusCode::OK, Json(body)).into_response())
}

/// GET /templates/examples
pub(crate) async fn get_all_template_examples(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: check that the actor can read templates in any organization.
    let authorizer = Authorizer::new();
    let obj = Object::new(ResourceType::Template).any_organization();
    if authorizer
        .authorize(&context.actor, Action::Read, &obj)
        .is_err()
    {
        return Ok(not_found_response("Resource not found.".to_owned()));
    }

    let examples = starter_template_examples();
    Ok((StatusCode::OK, Json(examples)).into_response())
}

/// GET /templates/{template}
pub(crate) async fn get_template(
    State(state): State<AppState>,
    Path(template_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let template = state.store.find_template_by_id(template_id).await?;
    match template {
        Some(t) if !t.deleted => Ok((StatusCode::OK, Json(template_response(&t))).into_response()),
        _ => Ok(not_found_response("Template not found.")),
    }
}

/// DELETE /templates/{template}
pub(crate) async fn delete_template(
    State(state): State<AppState>,
    Path(template_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // Look up the template to get org info for RBAC.
    let Some(template) = state.store.find_template_by_id(template_id).await? else {
        return Ok(not_found_response("Template not found."));
    };

    // RBAC: verify the actor can delete this template.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Delete,
            &Object::new(ResourceType::Template)
                .with_id(template_id)
                .in_org(template.organization_id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to delete this template.",
        ));
    }

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
pub(crate) async fn patch_template(
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
    let existing = match state.store.find_template_by_id(template_id).await? {
        Some(t) if !t.deleted => t,
        _ => return Ok(not_found_response("Template not found.")),
    };

    // RBAC: verify the actor can update this template.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::Template)
                .with_id(template_id)
                .in_org(existing.organization_id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update this template.",
        ));
    }

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
        .update_template_meta(UpdateTemplateMetaInput {
            template_id,
            name: name.to_owned(),
            display_name: display_name.to_owned(),
            description: description.to_owned(),
            icon: icon.to_owned(),
            default_ttl: body
                .default_ttl_ms
                .unwrap_or(existing.default_ttl / 1_000_000)
                * 1_000_000,
            activity_bump: body
                .activity_bump_ms
                .unwrap_or(existing.activity_bump / 1_000_000)
                * 1_000_000,
            allow_user_autostart: body
                .allow_user_autostart
                .unwrap_or(existing.allow_user_autostart),
            allow_user_autostop: body
                .allow_user_autostop
                .unwrap_or(existing.allow_user_autostop),
            allow_user_cancel_workspace_jobs: body
                .allow_user_cancel_workspace_jobs
                .unwrap_or(existing.allow_user_cancel_workspace_jobs),
            failure_ttl: body
                .failure_ttl_ms
                .unwrap_or(existing.failure_ttl / 1_000_000)
                * 1_000_000,
            time_til_dormant: body
                .time_til_dormant_ms
                .unwrap_or(existing.time_til_dormant / 1_000_000)
                * 1_000_000,
            time_til_dormant_autodelete: body
                .time_til_dormant_autodelete_ms
                .unwrap_or(existing.time_til_dormant_autodelete / 1_000_000)
                * 1_000_000,
            require_active_version: body
                .require_active_version
                .unwrap_or(existing.require_active_version),
            deprecation_message: deprecation_message.to_owned(),
            max_port_share_level: max_port_share_level.to_owned(),
            cors_behavior: body
                .cors_behavior
                .as_deref()
                .unwrap_or(&existing.cors_behavior)
                .to_owned(),
            use_classic_parameter_flow: body
                .use_classic_parameter_flow
                .unwrap_or(existing.use_classic_parameter_flow),
            disable_module_cache: body
                .disable_module_cache
                .unwrap_or(existing.disable_module_cache),
        })
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
pub(crate) async fn get_template_daus(
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
            amount: r.amount as i64,
        })
        .collect();
    let resp = DAUsResponse {
        entries,
        tz_hour_offset: 0,
    };
    Ok((StatusCode::OK, Json(resp)).into_response())
}

/// GET /templates/{template}/examples
pub(crate) async fn get_template_examples(
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
pub(crate) async fn list_template_versions(
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
pub(crate) async fn get_template_version_by_name(
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
pub(crate) async fn get_template_version(
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
pub(crate) async fn patch_template_version(
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

    let existing = match state.store.find_template_version_by_id(version_id).await? {
        Some(v) => v,
        None => return Ok(not_found_response("Template version not found.")),
    };

    // RBAC: verify the actor can update this template version.
    let authorizer = Authorizer::new();
    let mut obj = Object::new(ResourceType::Template).in_org(existing.organization_id);
    if let Some(tid) = existing.template_id {
        obj = obj.with_id(tid);
    }
    if authorizer
        .authorize(&context.actor, Action::Update, &obj)
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update this template version.",
        ));
    }

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
pub(crate) async fn post_archive_template_version(
    State(state): State<AppState>,
    Path(version_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // Look up the version to get template info for RBAC.
    let ver = match state.store.find_template_version_by_id(version_id).await? {
        Some(v) => v,
        None => return Ok(not_found_response("Template version not found.")),
    };

    // RBAC: verify the actor can update this template version.
    let authorizer = Authorizer::new();
    let mut obj = Object::new(ResourceType::Template).in_org(ver.organization_id);
    if let Some(tid) = ver.template_id {
        obj = obj.with_id(tid);
    }
    if authorizer
        .authorize(&context.actor, Action::Update, &obj)
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to archive this template version.",
        ));
    }

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

/// PATCH /templateversions/{templateversion}/cancel
pub(crate) async fn patch_cancel_template_version(
    State(state): State<AppState>,
    Path(version_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let ver = match state.store.find_template_version_by_id(version_id).await? {
        Some(v) => v,
        None => return Ok(not_found_response("Template version not found.")),
    };

    // RBAC: verify the actor can update this template version.
    let authorizer = Authorizer::new();
    let mut obj = Object::new(ResourceType::Template).in_org(ver.organization_id);
    if let Some(tid) = ver.template_id {
        obj = obj.with_id(tid);
    }
    if authorizer
        .authorize(&context.actor, Action::Update, &obj)
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to cancel this template version job.",
        ));
    }

    let canceled = state
        .store
        .cancel_template_provisioner_job(ver.job_id)
        .await?;
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
pub(crate) async fn post_template_version_dry_run(
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
    let ver = match state.store.find_template_version_by_id(version_id).await? {
        Some(v) => v,
        None => return Ok(not_found_response("Template version not found.")),
    };

    // RBAC: verify the actor can create workspaces in this org (dry runs simulate workspace builds).
    // Mirrors Go: policy.ActionCreate on rbac.ResourceWorkspace.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Create,
            &Object::new(ResourceType::Workspace)
                .with_owner(context.user.id)
                .in_org(ver.organization_id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to create template version dry runs.",
        ));
    }

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
        .create_provisioner_job(CreateProvisionerJobInput {
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
pub(crate) async fn get_template_version_dry_run(
    State(state): State<AppState>,
    Path((_version_id, job_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let job = state.store.find_provisioner_job(job_id).await?;
    match job {
        Some(j) => Ok((StatusCode::OK, Json(provisioner_job_response(&j))).into_response()),
        None => Ok(not_found_response("Dry-run job not found.")),
    }
}

/// PATCH /templateversions/{templateversion}/dry-run/{jobid}
pub(crate) async fn patch_template_version_dry_run(
    State(state): State<AppState>,
    Path((version_id, job_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // Look up the template version for org-scoped RBAC.
    let Some(ver) = state.store.find_template_version_by_id(version_id).await? else {
        return Ok(not_found_response("Template version not found."));
    };

    // RBAC: verify the actor can update templates (dry-run mutation).
    let authorizer = Authorizer::new();
    let mut obj = Object::new(ResourceType::Template).in_org(ver.organization_id);
    if let Some(tid) = ver.template_id {
        obj = obj.with_id(tid);
    }
    if authorizer
        .authorize(&context.actor, Action::Update, &obj)
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update template version dry runs.",
        ));
    }

    let canceled = state.store.cancel_template_provisioner_job(job_id).await?;
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

    let job = state.store.find_provisioner_job(job_id).await?;
    match job {
        Some(j) => Ok((StatusCode::OK, Json(provisioner_job_response(&j))).into_response()),
        None => Ok(not_found_response("Dry-run job not found.")),
    }
}

/// PATCH /templateversions/{templateversion}/dry-run/{jobid}/cancel
pub(crate) async fn patch_cancel_template_version_dry_run(
    State(state): State<AppState>,
    Path((version_id, job_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // Look up the template version for org-scoped RBAC.
    let Some(ver) = state.store.find_template_version_by_id(version_id).await? else {
        return Ok(not_found_response("Template version not found."));
    };

    // RBAC: verify the actor can update templates (dry-run cancel).
    let authorizer = Authorizer::new();
    let mut obj = Object::new(ResourceType::Template).in_org(ver.organization_id);
    if let Some(tid) = ver.template_id {
        obj = obj.with_id(tid);
    }
    if authorizer
        .authorize(&context.actor, Action::Update, &obj)
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to cancel template version dry runs.",
        ));
    }

    let canceled = state.store.cancel_template_provisioner_job(job_id).await?;
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
pub(crate) async fn get_template_version_dry_run_logs(
    State(state): State<AppState>,
    Path((_version_id, job_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // Verify the job exists.
    let _job = match state.store.find_provisioner_job(job_id).await? {
        Some(j) => j,
        None => return Ok(not_found_response("Dry-run job not found.")),
    };

    // Provisioner logs are not stored in the stub implementation.
    let logs: Vec<ProvisionerJobLog> = Vec::new();
    Ok((StatusCode::OK, Json(logs)).into_response())
}

/// GET /templateversions/{templateversion}/dry-run/{jobid}/resources
pub(crate) async fn get_template_version_dry_run_resources(
    State(state): State<AppState>,
    Path((_version_id, job_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let _job = match state.store.find_provisioner_job(job_id).await? {
        Some(j) => j,
        None => return Ok(not_found_response("Dry-run job not found.")),
    };

    // Resources are populated by the provisioner daemon. Return empty for stub.
    let resources: Vec<WorkspaceResource> = Vec::new();
    Ok((StatusCode::OK, Json(resources)).into_response())
}

/// GET /templateversions/{templateversion}/dry-run/{jobid}/matched-provisioners
pub(crate) async fn get_template_version_dry_run_matched_provisioners(
    State(state): State<AppState>,
    Path((_version_id, job_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let _job = match state.store.find_provisioner_job(job_id).await? {
        Some(j) => j,
        None => return Ok(not_found_response("Dry-run job not found.")),
    };

    // Matched provisioners require daemon tag matching which is not yet implemented.
    let response = MatchedProvisioners {
        count: 0,
        available: 0,
        most_recently_seen: None,
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// GET /templateversions/{templateversion}/dynamic-parameters
pub(crate) async fn get_template_version_dynamic_parameters(
    State(state): State<AppState>,
    Path(version_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let _ver = match state.store.find_template_version_by_id(version_id).await? {
        Some(v) => v,
        None => return Ok(not_found_response("Template version not found.")),
    };

    // Dynamic parameters are evaluated via the provisioner. Return empty stub.
    let response = DynamicParametersResponse::default();
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// POST /templateversions/{templateversion}/dynamic-parameters/evaluate
pub(crate) async fn post_template_version_dynamic_parameters_evaluate(
    State(state): State<AppState>,
    Path(version_id): Path<Uuid>,
    headers: HeaderMap,
    body: Result<Json<DynamicParametersRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let ver = match state.store.find_template_version_by_id(version_id).await? {
        Some(v) => v,
        None => return Ok(not_found_response("Template version not found.")),
    };

    // RBAC: verify the actor can read this template (parameter evaluation requires template read access).
    let authorizer = Authorizer::new();
    let mut obj = Object::new(ResourceType::Template).in_org(ver.organization_id);
    if let Some(tid) = ver.template_id {
        obj = obj.with_id(tid);
    }
    if authorizer
        .authorize(&context.actor, Action::Read, &obj)
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to evaluate template version parameters.",
        ));
    }

    let req = match body {
        Ok(Json(r)) => r,
        Err(e) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error("Invalid request body.", e.to_string())),
            )
                .into_response());
        }
    };

    // Dynamic parameters are evaluated via the provisioner. Return stub response.
    let response = DynamicParametersResponse {
        id: req.id,
        diagnostics: Vec::new(),
        parameters: Vec::new(),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// PATCH /templates/{template}/versions — update active template version
pub(crate) async fn patch_active_template_version(
    State(state): State<AppState>,
    Path(template_id): Path<Uuid>,
    headers: HeaderMap,
    body: Result<Json<UpdateActiveTemplateVersionRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let template = match state.store.find_template_by_id(template_id).await? {
        Some(t) => t,
        None => return Ok(not_found_response("Template not found.")),
    };

    // RBAC: verify the actor can update this template.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::Template)
                .with_id(template.id)
                .in_org(template.organization_id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update the active template version.",
        ));
    }

    let req = match body {
        Ok(Json(r)) => r,
        Err(e) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error("Invalid request body.", e.to_string())),
            )
                .into_response());
        }
    };

    // Verify the version exists and belongs to this template.
    let ver = match state.store.find_template_version_by_id(req.id).await? {
        Some(v) => v,
        None => return Ok(not_found_response("Template version not found.")),
    };

    if ver.template_id != Some(template.id) {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "Version does not belong to this template.",
                "",
            )),
        )
            .into_response());
    }

    let updated = state
        .store
        .update_template_active_version(template.id, req.id)
        .await?;
    if !updated {
        return Ok(not_found_response("Template not found."));
    }

    Ok(StatusCode::OK.into_response())
}

/// POST /templates/{template}/versions/archive — archive unused template versions
pub(crate) async fn post_archive_template_versions(
    State(state): State<AppState>,
    Path(template_id): Path<Uuid>,
    headers: HeaderMap,
    body: Result<Json<ArchiveTemplateVersionsRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let template = match state.store.find_template_by_id(template_id).await? {
        Some(t) => t,
        None => return Ok(not_found_response("Template not found.")),
    };

    // RBAC: verify the actor can update this template (archiving versions is a template mutation).
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::Template)
                .with_id(template.id)
                .in_org(template.organization_id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to archive template versions.",
        ));
    }

    let req = match body {
        Ok(Json(r)) => r,
        Err(e) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error("Invalid request body.", e.to_string())),
            )
                .into_response());
        }
    };

    let archived_ids = state
        .store
        .archive_unused_template_versions(template_id, req.all)
        .await?;

    let response = ArchiveTemplateVersionsResponse {
        template_id,
        archived_ids,
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// GET /templateversions/{templateversion}/external-auth
pub(crate) async fn get_template_version_external_auth(
    State(state): State<AppState>,
    Path(version_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // Verify the version exists.
    let _ver = match state.store.find_template_version_by_id(version_id).await? {
        Some(v) => v,
        None => return Ok(not_found_response("Template version not found.")),
    };

    // External auth requirements come from provisioner output. Return empty for stub.
    let auths: Vec<TemplateVersionExternalAuth> = Vec::new();
    Ok((StatusCode::OK, Json(auths)).into_response())
}

/// GET /templateversions/{templateversion}/logs
pub(crate) async fn get_template_version_logs(
    State(state): State<AppState>,
    Path(version_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let _ver = match state.store.find_template_version_by_id(version_id).await? {
        Some(v) => v,
        None => return Ok(not_found_response("Template version not found.")),
    };

    let logs: Vec<ProvisionerJobLog> = Vec::new();
    Ok((StatusCode::OK, Json(logs)).into_response())
}

/// GET /templateversions/{templateversion}/parameters (deprecated alias for rich-parameters)
pub(crate) async fn get_template_version_parameters(
    State(state): State<AppState>,
    Path(version_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    get_template_version_rich_parameters_impl(&state, &headers, version_id).await
}

/// GET /templateversions/{templateversion}/rich-parameters
pub(crate) async fn get_template_version_rich_parameters(
    State(state): State<AppState>,
    Path(version_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    get_template_version_rich_parameters_impl(&state, &headers, version_id).await
}

/// Shared implementation for parameters / rich-parameters endpoints.
pub(crate) async fn get_template_version_rich_parameters_impl(
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
pub(crate) async fn get_template_version_presets(
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
pub(crate) async fn get_template_version_preset_parameters(
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
pub(crate) async fn get_template_version_resources(
    State(state): State<AppState>,
    Path(version_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let _ver = match state.store.find_template_version_by_id(version_id).await? {
        Some(v) => v,
        None => return Ok(not_found_response("Template version not found.")),
    };

    // Resources are populated by the provisioner daemon. Return empty for stub.
    let resources: Vec<WorkspaceResource> = Vec::new();
    Ok((StatusCode::OK, Json(resources)).into_response())
}

/// GET /templateversions/{templateversion}/schema (deprecated)
pub(crate) async fn get_template_version_schema(
    State(state): State<AppState>,
    Path(version_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let _ver = match state.store.find_template_version_by_id(version_id).await? {
        Some(v) => v,
        None => return Ok(not_found_response("Template version not found.")),
    };

    // Deprecated endpoint — return empty array.
    let schema: Vec<Value> = Vec::new();
    Ok((StatusCode::OK, Json(schema)).into_response())
}

/// POST /templateversions/{templateversion}/unarchive
pub(crate) async fn post_unarchive_template_version(
    State(state): State<AppState>,
    Path(version_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // Look up the template version for org-scoped RBAC.
    let Some(ver) = state.store.find_template_version_by_id(version_id).await? else {
        return Ok(not_found_response("Template version not found."));
    };

    // RBAC: verify the actor can update templates (unarchiving is a template mutation).
    let authorizer = Authorizer::new();
    let mut obj = Object::new(ResourceType::Template).in_org(ver.organization_id);
    if let Some(tid) = ver.template_id {
        obj = obj.with_id(tid);
    }
    if authorizer
        .authorize(&context.actor, Action::Update, &obj)
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to unarchive template versions.",
        ));
    }

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
pub(crate) async fn get_template_version_variables(
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

/// Query parameters for listing template versions.
#[derive(Clone, Debug, Default, Deserialize)]
pub(crate) struct TemplateVersionsQuery {
    #[serde(default)]
    include_archived: Option<bool>,
    #[serde(default)]
    limit: Option<u32>,
    #[serde(default)]
    offset: Option<u32>,
}
