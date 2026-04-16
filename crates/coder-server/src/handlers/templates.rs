//! Template and template version handlers.

use super::users::clamp_pagination_limit;
use super::workspaces::workspace_transition_from_str;
use super::*;

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

/// Resolve an organization path segment by UUID or name.
pub(crate) async fn resolve_organization(
    state: &AppState,
    org_ref: &str,
) -> Result<Option<OrganizationRecord>, AppError> {
    if let Ok(org_id) = Uuid::parse_str(org_ref) {
        return Ok(state.store.find_organization_by_id(org_id).await?);
    }
    Ok(state.store.find_organization_by_name(org_ref).await?)
}

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

    // Create the provisioner job. The store bridges this into both the
    // template-side and daemon-side storage so that provisioner daemons
    // can acquire and execute the job through the full lifecycle.
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
            input: serde_json::json!({
                "template_version_id": version_id.to_string(),
            }),
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
            limit: clamp_pagination_limit(query.limit.unwrap_or(50)),
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

    let logs = state.store.list_provisioner_job_logs(job_id, None).await?;

    let items: Vec<ProvisionerJobLog> = logs
        .into_iter()
        .map(|l| ProvisionerJobLog {
            id: l.id,
            created_at: l.created_at,
            log_source: l.source,
            log_level: l.level,
            stage: l.stage,
            output: l.output,
        })
        .collect();
    Ok((StatusCode::OK, Json(items)).into_response())
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

    // Verify the job exists.
    let _job = match state.store.find_provisioner_job(job_id).await? {
        Some(j) => j,
        None => return Ok(not_found_response("Dry-run job not found.")),
    };

    let resources = state.store.list_workspace_resources_by_job(job_id).await?;

    let resource_ids: Vec<Uuid> = resources.iter().map(|r| r.id).collect();
    let all_metadata = state
        .store
        .list_workspace_resource_metadata(&resource_ids)
        .await?;

    let mut metadata_map: HashMap<Uuid, Vec<WorkspaceResourceMetadata>> = HashMap::new();
    for m in all_metadata {
        metadata_map
            .entry(m.workspace_resource_id)
            .or_default()
            .push(WorkspaceResourceMetadata {
                key: m.key,
                value: m.value,
                sensitive: m.sensitive,
            });
    }

    let items: Vec<WorkspaceResourceResponse> = resources
        .into_iter()
        .map(|r| {
            let meta = metadata_map.remove(&r.id).unwrap_or_default();
            WorkspaceResourceResponse {
                id: r.id,
                created_at: r.created_at,
                job_id: r.job_id,
                workspace_transition: workspace_transition_from_str(&r.transition),
                resource_type: r.resource_type,
                name: r.name,
                hide: r.hide,
                icon: r.icon,
                daily_cost: r.daily_cost,
                agents: Vec::new(),
                metadata: meta,
            }
        })
        .collect();
    Ok((StatusCode::OK, Json(items)).into_response())
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

    let job = match state.store.find_provisioner_job(job_id).await? {
        Some(j) => j,
        None => return Ok(not_found_response("Dry-run job not found.")),
    };

    // Fetch all provisioner daemons in the same organization.
    let daemons = state
        .store
        .get_provisioner_daemons_by_organization(job.organization_id)
        .await?;

    // A daemon matches when the job's tags are a subset of the daemon's tags.
    let now = OffsetDateTime::now_utc();
    let stale_threshold = now - time::Duration::minutes(5);
    let mut count: i32 = 0;
    let mut available: i32 = 0;
    let mut most_recently_seen: Option<OffsetDateTime> = None;

    for daemon in &daemons {
        let tags_match = job.tags.iter().all(|(k, v)| daemon.tags.get(k) == Some(v));
        if !tags_match {
            continue;
        }
        count += 1;

        if let Some(last_seen) = daemon.last_seen_at {
            if last_seen > stale_threshold {
                available += 1;
            }
            most_recently_seen = Some(match most_recently_seen {
                Some(prev) if prev >= last_seen => prev,
                _ => last_seen,
            });
        }
    }

    let response = MatchedProvisioners {
        count,
        available,
        most_recently_seen,
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// GET /templateversions/{templateversion}/dynamic-parameters
pub(crate) async fn get_template_version_dynamic_parameters(
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

    // RBAC: verify the actor can read this template.
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
            "You are not authorized to view template version parameters.",
        ));
    }

    let params = state
        .store
        .list_template_version_parameters(version_id)
        .await?;

    let parameters: Vec<Value> = params
        .iter()
        .map(|p| -> Result<Value, AppError> {
            let options: Vec<coder_core::api::TemplateVersionParameterOption> =
                serde_json::from_value(p.options.clone()).map_err(|e| AppError::InternalError {
                    message: format!("Failed to deserialize options for parameter '{}'", p.name),
                    detail: e.to_string(),
                })?;
            Ok(serde_json::to_value(TemplateVersionParameter {
                name: p.name.clone(),
                display_name: p.display_name.clone(),
                description: p.description.clone(),
                description_plaintext: strip_markdown(&p.description),
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
            })
            .map_err(|e| AppError::InternalError {
                message: "Failed to serialize parameter".to_string(),
                detail: e.to_string(),
            })?)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let response = DynamicParametersResponse {
        parameters,
        ..DynamicParametersResponse::default()
    };
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

    // Fetch the stored template-version parameters from the database and
    // return them as the evaluated result.  Full dynamic evaluation requires
    // the provisioner, which is not yet wired; returning the persisted
    // parameter definitions is the closest correct approximation and matches
    // what the Go backend does for non-dynamic template versions.
    let params = state
        .store
        .list_template_version_parameters(version_id)
        .await?;

    let parameters: Vec<Value> = params
        .iter()
        .map(|p| {
            let options: Vec<coder_core::api::TemplateVersionParameterOption> =
                serde_json::from_value(p.options.clone()).map_err(|e| AppError::InternalError {
                    message: format!("Failed to deserialize options for parameter '{}'", p.name),
                    detail: e.to_string(),
                })?;
            serde_json::to_value(TemplateVersionParameter {
                name: p.name.clone(),
                display_name: p.display_name.clone(),
                description: p.description.clone(),
                description_plaintext: strip_markdown(&p.description),
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
            })
            .map_err(|e| AppError::InternalError {
                message: format!("Failed to serialize parameter '{}'", p.name),
                detail: e.to_string(),
            })
        })
        .collect::<Result<Vec<Value>, _>>()?;

    let response = DynamicParametersResponse {
        id: req.id,
        diagnostics: Vec::new(),
        parameters,
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
    let ver = match state.store.find_template_version_by_id(version_id).await? {
        Some(v) => v,
        None => return Ok(not_found_response("Template version not found.")),
    };

    // The external_auth_providers field on template_versions is a JSON array of
    // provider ID strings written by the provisioner daemon.  We convert each
    // entry into a minimal TemplateVersionExternalAuth response.
    let provider_ids: Vec<String> =
        serde_json::from_value(ver.external_auth_providers.clone()).unwrap_or_default();

    let auths: Vec<TemplateVersionExternalAuth> = provider_ids
        .into_iter()
        .map(|id| TemplateVersionExternalAuth {
            id,
            ..TemplateVersionExternalAuth::default()
        })
        .collect();
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

    let ver = match state.store.find_template_version_by_id(version_id).await? {
        Some(v) => v,
        None => return Ok(not_found_response("Template version not found.")),
    };

    let logs = state
        .store
        .list_provisioner_job_logs(ver.job_id, None)
        .await?;

    let items: Vec<ProvisionerJobLog> = logs
        .into_iter()
        .map(|l| ProvisionerJobLog {
            id: l.id,
            created_at: l.created_at,
            log_source: l.source,
            log_level: l.level,
            stage: l.stage,
            output: l.output,
        })
        .collect();
    Ok((StatusCode::OK, Json(items)).into_response())
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
        .map(|p| -> Result<TemplateVersionParameter, AppError> {
            let options: Vec<coder_core::api::TemplateVersionParameterOption> =
                serde_json::from_value(p.options.clone()).map_err(|e| AppError::InternalError {
                    message: format!("Failed to deserialize options for parameter '{}'", p.name),
                    detail: e.to_string(),
                })?;
            Ok(TemplateVersionParameter {
                name: p.name.clone(),
                display_name: p.display_name.clone(),
                description: p.description.clone(),
                description_plaintext: strip_markdown(&p.description),
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
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

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

    let ver = match state.store.find_template_version_by_id(version_id).await? {
        Some(v) => v,
        None => return Ok(not_found_response("Template version not found.")),
    };

    let resources = state
        .store
        .list_workspace_resources_by_job(ver.job_id)
        .await?;

    let resource_ids: Vec<Uuid> = resources.iter().map(|r| r.id).collect();
    let all_metadata = state
        .store
        .list_workspace_resource_metadata(&resource_ids)
        .await?;

    let mut metadata_map: HashMap<Uuid, Vec<WorkspaceResourceMetadata>> = HashMap::new();
    for m in all_metadata {
        metadata_map
            .entry(m.workspace_resource_id)
            .or_default()
            .push(WorkspaceResourceMetadata {
                key: m.key,
                value: m.value,
                sensitive: m.sensitive,
            });
    }

    let items: Vec<WorkspaceResourceResponse> = resources
        .into_iter()
        .map(|r| {
            let meta = metadata_map.remove(&r.id).unwrap_or_default();
            WorkspaceResourceResponse {
                id: r.id,
                created_at: r.created_at,
                job_id: r.job_id,
                workspace_transition: workspace_transition_from_str(&r.transition),
                resource_type: r.resource_type,
                name: r.name,
                hide: r.hide,
                icon: r.icon,
                daily_cost: r.daily_cost,
                agents: Vec::new(),
                metadata: meta,
            }
        })
        .collect();
    Ok((StatusCode::OK, Json(items)).into_response())
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

// ── Enterprise template ACL handlers ────────────────────────────────────

/// Converts a list of action strings into a `TemplateRole`.
///
/// Mirrors the Go helper `convertToTemplateRole` in
/// `enterprise/coderd/templates.go`.
fn actions_to_template_role(actions: &[String]) -> TemplateRole {
    let mut sorted = actions.to_vec();
    sorted.sort();

    let mut admin_actions = vec![
        "application_connect".to_string(),
        "assign".to_string(),
        "delete".to_string(),
        "read".to_string(),
        "update".to_string(),
        "view_insights".to_string(),
    ];
    admin_actions.sort();

    let mut use_actions = vec![
        "application_connect".to_string(),
        "read".to_string(),
        "view_insights".to_string(),
    ];
    use_actions.sort();

    if sorted == admin_actions {
        TemplateRole::Admin
    } else if sorted == use_actions {
        TemplateRole::Use
    } else {
        TemplateRole::Deleted
    }
}

/// Converts a `TemplateRole` into the set of policy action strings
/// that should be stored in the ACL JSON.
fn template_role_to_actions(role: &TemplateRole) -> Vec<String> {
    match role {
        TemplateRole::Admin => vec![
            "application_connect".to_string(),
            "assign".to_string(),
            "delete".to_string(),
            "read".to_string(),
            "update".to_string(),
            "view_insights".to_string(),
        ],
        TemplateRole::Use => vec![
            "application_connect".to_string(),
            "read".to_string(),
            "view_insights".to_string(),
        ],
        TemplateRole::Deleted => vec![],
    }
}

/// GET /templates/{template}/acl
pub(crate) async fn get_template_acl(
    State(state): State<AppState>,
    Path(template_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(template) = state.store.find_template_by_id(template_id).await? else {
        return Ok(not_found_response("Template not found."));
    };
    if template.deleted {
        return Ok(not_found_response("Template not found."));
    }

    let user_rows = state.store.get_template_user_roles(template_id).await?;
    let group_rows = state.store.get_template_group_roles(template_id).await?;

    // Build user entries.
    let mut users = Vec::with_capacity(user_rows.len());
    for row in &user_rows {
        let memberships = state.store.list_user_memberships(row.id).await?;
        let org_ids: Vec<Uuid> = memberships.iter().map(|m| m.organization_id).collect();
        let status = row
            .status
            .parse::<UserStatus>()
            .unwrap_or(UserStatus::Active);
        let login_type = row
            .login_type
            .parse::<LoginType>()
            .unwrap_or(LoginType::None);
        users.push(TemplateACLUser {
            user: UserResponse {
                reduced: ReducedUser {
                    minimal: MinimalUser {
                        id: row.id,
                        username: row.username.clone(),
                        name: row.name.clone(),
                        avatar_url: row.avatar_url.clone(),
                    },
                    email: row.email.clone(),
                    created_at: row.created_at,
                    updated_at: row.updated_at,
                    last_seen_at: None,
                    status,
                    login_type: login_type.as_str(),
                    theme_preference: String::new(),
                },
                organization_ids: org_ids,
                roles: Vec::new(),
            },
            role: actions_to_template_role(&row.actions),
        });
    }

    // Build group entries.
    let mut groups = Vec::with_capacity(group_rows.len());
    for row in &group_rows {
        let members = state.store.list_group_members(row.id).await?;
        let mut member_users = Vec::with_capacity(members.len());
        for member in &members {
            if let Some(user) = state.store.find_user_by_id(member.user_id).await? {
                member_users.push(ReducedUser {
                    minimal: MinimalUser {
                        id: user.id,
                        username: user.username.clone(),
                        name: user.name.clone(),
                        avatar_url: user.avatar_url.clone(),
                    },
                    email: user.email.clone(),
                    created_at: user.created_at,
                    updated_at: user.updated_at,
                    last_seen_at: user.last_seen_at,
                    status: user.status,
                    login_type: user.login_type.as_str(),
                    theme_preference: String::new(),
                });
            }
        }
        let (org_name, org_display_name) = if let Some(org) = state
            .store
            .find_organization_by_id(row.organization_id)
            .await?
        {
            (org.name, org.display_name)
        } else {
            (String::new(), String::new())
        };
        let total_member_count = member_users.len() as i32;
        groups.push(TemplateACLGroup {
            group: GroupResponse {
                id: row.id.to_string(),
                name: row.name.clone(),
                display_name: row.display_name.clone(),
                organization_id: row.organization_id.to_string(),
                avatar_url: row.avatar_url.clone(),
                quota_allowance: row.quota_allowance,
                source: row.source.clone(),
                members: member_users,
                total_member_count,
                organization_name: org_name,
                organization_display_name: org_display_name,
            },
            role: actions_to_template_role(&row.actions),
        });
    }

    Ok((StatusCode::OK, Json(TemplateACLResponse { users, groups })).into_response())
}

/// PATCH /templates/{template}/acl
pub(crate) async fn patch_template_acl(
    State(state): State<AppState>,
    Path(template_id): Path<Uuid>,
    headers: HeaderMap,
    payload: Result<Json<UpdateTemplateACLRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(template) = state.store.find_template_by_id(template_id).await? else {
        return Ok(not_found_response("Template not found."));
    };
    if template.deleted {
        return Ok(not_found_response("Template not found."));
    }

    // RBAC: verify the actor can update this template.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::Template)
                .with_id(template_id)
                .in_org(template.organization_id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update this template's ACL.",
        ));
    }

    let Json(req) = match payload {
        Ok(r) => r,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    // Validate roles.
    let mut validations = Vec::new();
    for (id, role) in &req.user_perms {
        if matches!(role, TemplateRole::Deleted) {
            continue;
        }
        let actions = template_role_to_actions(role);
        if actions.is_empty() {
            validations.push(ValidationError {
                field: "user_perms".to_string(),
                detail: format!("invalid role for user {id}"),
            });
        }
    }
    for (id, role) in &req.group_perms {
        if matches!(role, TemplateRole::Deleted) {
            continue;
        }
        let actions = template_role_to_actions(role);
        if actions.is_empty() {
            validations.push(ValidationError {
                field: "group_perms".to_string(),
                detail: format!("invalid role for group {id}"),
            });
        }
    }
    if !validations.is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                message: "Invalid request to update template ACL".to_string(),
                detail: None,
                validations,
            }),
        )
            .into_response());
    }

    // Build the updated ACL maps.
    let mut user_acl = template.user_acl.clone();
    for (id, role) in &req.user_perms {
        if matches!(role, TemplateRole::Deleted) {
            user_acl.remove(id);
        } else {
            let value = serde_json::to_value(template_role_to_actions(role)).unwrap_or_default();
            user_acl.insert(id.clone(), value);
        }
    }

    let mut group_acl = template.group_acl.clone();
    for (id, role) in &req.group_perms {
        if matches!(role, TemplateRole::Deleted) {
            group_acl.remove(id);
        } else {
            let value = serde_json::to_value(template_role_to_actions(role)).unwrap_or_default();
            group_acl.insert(id.clone(), value);
        }
    }

    let input = UpdateTemplateACLInput {
        user_acl,
        group_acl,
    };
    state.store.update_template_acl(template_id, &input).await?;

    Ok((
        StatusCode::OK,
        Json(ApiResponse::ok("Successfully updated template ACL list.")),
    )
        .into_response())
}

/// GET /templates/{template}/acl/available
pub(crate) async fn get_template_acl_available(
    State(state): State<AppState>,
    Path(template_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(template) = state.store.find_template_by_id(template_id).await? else {
        return Ok(not_found_response("Template not found."));
    };
    if template.deleted {
        return Ok(not_found_response("Template not found."));
    }

    // RBAC: requires update permission on the template.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::Template)
                .with_id(template_id)
                .in_org(template.organization_id),
        )
        .is_err()
    {
        return Ok(not_found_response("Template not found."));
    }

    // Fetch all users (system-level access to list available assignees).
    let (user_records, _total) = state.store.list_users(UserListFilter::default()).await?;

    let users: Vec<ReducedUser> = user_records
        .into_iter()
        .map(|u| ReducedUser {
            minimal: MinimalUser {
                id: u.id,
                username: u.username,
                name: u.name,
                avatar_url: u.avatar_url,
            },
            email: u.email,
            created_at: u.created_at,
            updated_at: u.updated_at,
            last_seen_at: u.last_seen_at,
            status: u.status,
            login_type: u.login_type.as_str(),
            theme_preference: String::new(),
        })
        .collect();

    // Fetch groups in the template's organization.
    let group_records = state.store.list_groups(template.organization_id).await?;

    let mut groups = Vec::with_capacity(group_records.len());
    for g in &group_records {
        let members = state.store.list_group_members(g.id).await?;
        let mut member_users = Vec::with_capacity(members.len());
        for member in &members {
            if let Some(user) = state.store.find_user_by_id(member.user_id).await? {
                member_users.push(ReducedUser {
                    minimal: MinimalUser {
                        id: user.id,
                        username: user.username.clone(),
                        name: user.name.clone(),
                        avatar_url: user.avatar_url.clone(),
                    },
                    email: user.email.clone(),
                    created_at: user.created_at,
                    updated_at: user.updated_at,
                    last_seen_at: user.last_seen_at,
                    status: user.status,
                    login_type: user.login_type.as_str(),
                    theme_preference: String::new(),
                });
            }
        }
        let (org_name, org_display_name) = if let Some(org) = state
            .store
            .find_organization_by_id(g.organization_id)
            .await?
        {
            (org.name, org.display_name)
        } else {
            (String::new(), String::new())
        };
        let total_member_count = member_users.len() as i32;
        groups.push(GroupResponse {
            id: g.id.to_string(),
            name: g.name.clone(),
            display_name: g.display_name.clone(),
            organization_id: g.organization_id.to_string(),
            avatar_url: g.avatar_url.clone(),
            quota_allowance: g.quota_allowance,
            source: g.source.clone(),
            members: member_users,
            total_member_count,
            organization_name: org_name,
            organization_display_name: org_display_name,
        });
    }

    Ok((StatusCode::OK, Json(ACLAvailableResponse { users, groups })).into_response())
}

/// POST /templates/{template}/prebuilds/invalidate
pub(crate) async fn post_invalidate_template_presets(
    State(state): State<AppState>,
    Path(template_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(template) = state.store.find_template_by_id(template_id).await? else {
        return Ok(not_found_response("Template not found."));
    };
    if template.deleted {
        return Ok(not_found_response("Template not found."));
    }

    // RBAC: user must be able to update the template.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::Template)
                .with_id(template_id)
                .in_org(template.organization_id),
        )
        .is_err()
    {
        return Ok(not_found_response("Template not found."));
    }

    let rows = state.store.invalidate_template_presets(template_id).await?;

    let invalidated: Vec<InvalidatedPreset> = rows
        .into_iter()
        .map(|r| InvalidatedPreset {
            template_name: r.template_name,
            template_version_name: r.template_version_name,
            preset_name: r.preset_name,
        })
        .collect();

    Ok((
        StatusCode::OK,
        Json(InvalidatePresetsResponse { invalidated }),
    )
        .into_response())
}
