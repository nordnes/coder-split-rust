//! Workspace CRUD, builds, ACL, port shares, and related handlers.
//!
//! TODO-audit-diff-expand: only `patch_workspace` currently emits a
//! structured per-field [`coder_audit::AuditDiff`] alongside its summary
//! string. The remaining ~15 workspace mutation sites (favorite/unfavorite,
//! autostart/TTL/schedule updates, dormant/activate, ACL changes, build
//! start/stop/delete, etc.) still pass `diff: None`. Extending them is
//! tracked as a follow-up to gap-doc §B.10.1.

use super::templates::resolve_organization;
use super::users::clamp_pagination_limit;
use super::*;
use coder_core::ports::WorkspaceRecord;

/// Minimal auditable view of a workspace, used by [`patch_workspace`] to
/// demonstrate the structured-diff path for the workspace domain. Mirrors
/// the per-field policies from Go's `audit/table.go` at a reduced-surface
/// level (full roll-out deferred). Fields that are user-visible settings
/// operators can rename/retune are marked `track`; auto-maintained
/// timestamps and internal identifiers are `ignore`.
#[derive(Debug, Clone, serde::Serialize, coder_audit::Auditable)]
struct AuditWorkspaceView {
    #[audit(ignore)]
    id: Uuid,
    #[audit(ignore)]
    created_at: OffsetDateTime,
    #[audit(ignore)]
    updated_at: OffsetDateTime,
    #[audit(ignore)]
    last_used_at: OffsetDateTime,
    #[audit(ignore)]
    deleted: bool,

    #[audit(track)]
    organization_id: Uuid,
    #[audit(track)]
    owner_id: Uuid,
    #[audit(track)]
    template_id: Uuid,
    #[audit(track)]
    name: String,
    #[audit(track)]
    autostart_schedule: Option<String>,
    #[audit(track)]
    ttl_ns: Option<i64>,
    #[audit(track)]
    dormant_at: Option<OffsetDateTime>,
    #[audit(track)]
    deleting_at: Option<OffsetDateTime>,
    #[audit(track)]
    automatic_updates: String,
    #[audit(track)]
    favorite: bool,
    #[audit(track)]
    next_start_at: Option<OffsetDateTime>,
}

impl AuditWorkspaceView {
    fn from_record(record: &WorkspaceRecord) -> Self {
        Self {
            id: record.id,
            created_at: record.created_at,
            updated_at: record.updated_at,
            last_used_at: record.last_used_at,
            deleted: record.deleted,
            organization_id: record.organization_id,
            owner_id: record.owner_id,
            template_id: record.template_id,
            name: record.name.clone(),
            autostart_schedule: record.autostart_schedule.clone(),
            ttl_ns: record.ttl_ns,
            dormant_at: record.dormant_at,
            deleting_at: record.deleting_at,
            automatic_updates: record.automatic_updates.clone(),
            favorite: record.favorite,
            next_start_at: record.next_start_at,
        }
    }
}

/// Compute provisioner tags for a workspace build by copying the template
/// version's prior job tags and then normalizing via
/// [`coder_core::mutate_tags`]. Ports the Go `wsbuilder.getClassicProvisionerTags`
/// helper (see `coder/coderd/wsbuilder/wsbuilder.go`). Falls back to an empty
/// base set when the template version or its job is not found so daemon
/// matching still works against scope/owner defaults.
async fn build_provisioner_tags(
    state: &AppState,
    owner_id: Uuid,
    template_version_id: Uuid,
) -> Result<HashMap<String, String>, AppError> {
    let mut prior_tags: HashMap<String, String> = HashMap::new();
    if let Some(ver) = state
        .store
        .find_template_version_by_id(template_version_id)
        .await?
        && let Some(job) = state.store.get_provisioner_job_by_id(ver.job_id).await?
    {
        prior_tags = coder_core::tags_from_json(&job.tags);
    }
    Ok(coder_core::mutate_tags(owner_id, &[&prior_tags]))
}

/// Computes the workspace build's `max_deadline` based on the template's
/// autostop requirement and the user's (or deployment default) quiet hours.
///
/// Mirrors Go's `schedule.CalculateAutostop` call from
/// `coder/coderd/wsbuilder/wsbuilder.go`.  Returns `None` when the template
/// has no autostop requirement configured or no quiet-hours window resolves.
pub(crate) async fn resolve_build_max_deadline(
    state: &AppState,
    template: &TemplateRecord,
    owner_id: Uuid,
    now: OffsetDateTime,
) -> Result<Option<OffsetDateTime>, AppError> {
    if template.autostop_requirement_days_of_week == 0 {
        return Ok(None);
    }

    // Prefer the user's override, fall back to the deployment default.
    // Mirrors the enterprise `UserQuietHoursScheduleStore.Get` behavior.
    let user_can_set = state.config.workspace.allow_user_custom_quiet_hours;
    let raw_schedule = if user_can_set {
        match state
            .store
            .get_user_config(owner_id, "quiet_hours_schedule")
            .await?
        {
            Some(record) if !record.value.is_empty() => record.value,
            _ => state.config.workspace.default_quiet_hours_schedule.clone(),
        }
    } else {
        state.config.workspace.default_quiet_hours_schedule.clone()
    };

    let Some(window) = coder_workspaces::parse_quiet_hours_schedule(&raw_schedule) else {
        return Ok(None);
    };

    Ok(coder_workspaces::compute_max_deadline(
        template.autostop_requirement_days_of_week,
        template.autostop_requirement_weeks,
        Some(&window),
        now,
    ))
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct WorkspacesQuery {
    owner: Option<String>,
    template: Option<String>,
    name: Option<String>,
    status: Option<String>,
    has_agent: Option<String>,
    dormant: Option<bool>,
    limit: Option<u32>,
    offset: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct WorkspaceBuildsQuery {
    limit: Option<u32>,
    offset: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct BuildLogsQuery {
    after: Option<i64>,
    follow: Option<bool>,
}

/// GET /workspaces — filtered, paginated workspace listing.
pub(crate) async fn list_workspaces(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WorkspacesQuery>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let owner_id = if let Some(ref owner) = query.owner {
        if owner == "me" {
            Some(context.user.id)
        } else {
            Uuid::parse_str(owner).ok()
        }
    } else {
        None
    };
    let owner_username = query
        .owner
        .as_deref()
        .filter(|o| *o != "me" && Uuid::parse_str(o).is_err())
        .map(String::from);

    let filter = WorkspaceListFilter {
        owner_id,
        owner_username,
        template_name: query.template,
        template_ids: Vec::new(),
        name: query.name,
        status: query.status,
        has_agent: query.has_agent,
        dormant: query.dormant,
        last_used_before: None,
        last_used_after: None,
        organization_id: None,
        limit: clamp_pagination_limit(query.limit.unwrap_or(25)),
        offset: query.offset.unwrap_or(0),
        viewer_id: Some(context.user.id),
        // RBAC partial-eval SQL filter (CODER_RBAC_SQL_FILTER). Built from
        // the actor so the store can push the row predicate into Postgres.
        // When the feature flag is off, leaves this as `None` and the store
        // keeps running the legacy query unchanged.
        authz_filter: if state.config.rbac_sql_filter_enabled {
            Some(
                coder_rbac::regosql::SqlFilterBuilder::new(
                    &context.actor,
                    coder_rbac::ResourceType::Workspace,
                    coder_rbac::Action::Read,
                )
                .with_org_column("w.organization_id")
                .with_owner_column("w.owner_id")
                .with_id_column("w.id")
                .build(),
            )
        } else {
            None
        },
    };

    let (workspaces, count) = state.store.list_workspaces(filter).await?;
    let items: Vec<Value> = workspaces
        .into_iter()
        .map(|w| {
            json!({
                "id": w.id,
                "created_at": w.created_at.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
                "updated_at": w.updated_at.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
                "owner_id": w.owner_id,
                "organization_id": w.organization_id,
                "template_id": w.template_id,
                "name": w.name,
                "autostart_schedule": w.autostart_schedule,
                "ttl_ms": w.ttl_ns.map(|ns| ns / 1_000_000),
                "last_used_at": w.last_used_at.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
                "dormant_at": w.dormant_at.map(|t| t.format(&time::format_description::well_known::Rfc3339).unwrap_or_default()),
                "deleting_at": w.deleting_at.map(|t| t.format(&time::format_description::well_known::Rfc3339).unwrap_or_default()),
                "automatic_updates": w.automatic_updates,
                "favorite": w.favorite,
                "next_start_at": w.next_start_at.map(|t| t.format(&time::format_description::well_known::Rfc3339).unwrap_or_default()),
            })
        })
        .collect();

    Ok((
        StatusCode::OK,
        Json(json!({ "workspaces": items, "count": count })),
    )
        .into_response())
}

/// GET /workspaces/{workspace}
pub(crate) async fn get_workspace(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    Ok((StatusCode::OK, Json(workspace_to_json(&workspace))).into_response())
}

/// PATCH /workspaces/{workspace}
pub(crate) async fn patch_workspace(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
    payload: Result<Json<Value>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(body) = match payload {
        Ok(p) => p,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let Some(workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    // RBAC: verify the actor can update this workspace.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::Workspace)
                .with_id(workspace_id)
                .with_owner(workspace.owner_id)
                .in_org(workspace.organization_id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update this workspace.",
        ));
    }

    if let Some(name) = body.get("name").and_then(|v| v.as_str()) {
        // Capture a best-effort "before" view for the structured diff before
        // mutating. If the view cannot be materialised for any reason the
        // summary still carries the canonical record.
        let before_view = AuditWorkspaceView::from_record(&workspace);
        let Some(updated) = state
            .store
            .update_workspace_name(workspace_id, name, Some(context.user.id))
            .await?
        else {
            return Ok(resource_not_found_response());
        };
        let after_view = AuditWorkspaceView::from_record(&updated);
        let diff = {
            use coder_audit::Auditable as _;
            before_view.audit_diff(&after_view)
        };
        let audit_diff = if diff.is_empty() { None } else { Some(diff) };
        state
            .audit
            .record(AuditEvent {
                action: AuditAction::Write,
                resource: ResourceKind::Workspace,
                actor_user_id: Some(context.user.id),
                target_id: Some(workspace_id.to_string()),
                summary: format!("renamed workspace {} to {}", workspace.name, updated.name),
                diff: audit_diff,
            })
            .await;
        return Ok((StatusCode::OK, Json(workspace_to_json(&updated))).into_response());
    }

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// GET /workspaces/{workspace}/builds
pub(crate) async fn list_workspace_builds_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
    Query(query): Query<WorkspaceBuildsQuery>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(_workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    let builds = state
        .store
        .list_workspace_builds(
            workspace_id,
            clamp_pagination_limit(query.limit.unwrap_or(25)),
            query.offset.unwrap_or(0),
        )
        .await?;

    let items: Vec<Value> = builds.into_iter().map(|b| build_to_json(&b)).collect();
    Ok((StatusCode::OK, Json(items)).into_response())
}

/// POST /workspaces/{workspace}/builds — start/stop/delete transition.
pub(crate) async fn post_workspace_build(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
    payload: Result<Json<Value>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(body) = match payload {
        Ok(p) => p,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let Some(workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    // RBAC: verify the actor can update this workspace (creating a build
    // is a mutation on an existing workspace, not creating a new one).
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::Workspace)
                .with_id(workspace_id)
                .with_owner(workspace.owner_id)
                .in_org(workspace.organization_id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to create builds for this workspace.",
        ));
    }

    let transition = body
        .get("transition")
        .and_then(|v| v.as_str())
        .unwrap_or("start")
        .to_owned();

    let template_version_id = body
        .get("template_version_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok());

    // Always resolve the template row so we can compute the quiet-hours
    // max_deadline even when the caller supplied an explicit template version.
    let Some(template) = state
        .store
        .find_template_by_id(workspace.template_id)
        .await?
    else {
        return Ok(not_found_response("Template not found."));
    };
    let tv_id = template_version_id.unwrap_or(template.active_version_id);

    let job_id = Uuid::new_v4();
    let build_id = Uuid::new_v4();

    let tags = build_provisioner_tags(&state, workspace.owner_id, tv_id).await?;
    let _job = state
        .store
        .create_provisioner_job(CreateProvisionerJobInput {
            id: job_id,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            organization_id: workspace.organization_id,
            initiator_id: context.user.id,
            provisioner: "echo".to_owned(),
            file_id: None,
            job_type: "workspace_build".to_owned(),
            input: json!({}),
            tags,
        })
        .await?;

    // Compute the max_deadline (quiet-hours clamp) for templates that declare
    // an autostop requirement.  Mirrors Go's `wsbuilder` path which invokes
    // `schedule.CalculateAutostop`.
    let now = OffsetDateTime::now_utc();
    let max_deadline =
        resolve_build_max_deadline(&state, &template, workspace.owner_id, now).await?;

    // build_number is computed atomically inside insert_workspace_build.
    let build = state
        .store
        .insert_workspace_build(CreateWorkspaceBuildInput {
            id: build_id,
            workspace_id,
            template_version_id: tv_id,
            build_number: 0,
            transition: transition.clone(),
            initiator_id: context.user.id,
            job_id,
            reason: "initiator".to_owned(),
            deadline: max_deadline,
            max_deadline,
        })
        .await?;

    // Best-effort: publish reinit events to agents of the previous build so
    // they know a new build has started and can re-initialise.
    // Fetch builds for this workspace; the second entry (index 1) is the
    // previous build since the list is ordered newest-first and we just
    // inserted a new one.
    if let Ok(builds) = state.store.list_workspace_builds(workspace_id, 2, 0).await {
        // The second build in the list (if it exists) is the previous one.
        if let Some(prev_build) = builds.get(1) {
            if let Ok(resources) = state
                .store
                .list_workspace_resources_by_job(prev_build.job_id)
                .await
            {
                let resource_ids: Vec<Uuid> = resources.iter().map(|r| r.id).collect();
                if !resource_ids.is_empty() {
                    if let Ok(agents) = state
                        .store
                        .list_workspace_agents_by_resource_ids(&resource_ids)
                        .await
                    {
                        let payload = serde_json::to_vec(&json!({
                            "workspace_id": workspace_id,
                            "build_id": build_id,
                            "transition": transition,
                        }))
                        .unwrap_or_default();
                        for agent in &agents {
                            let channel =
                                coder_core::pubsub::workspace_agent_reinit_channel(agent.id);
                            let _ = state.pubsub.publish(&channel, &payload).await;
                        }
                    }
                }
            }
        }
    }

    // Audit the build transition.  Mirrors Go `workspacebuilds.go` which
    // emits a background audit entry once the build is queued.
    let (action, verb) = match transition.as_str() {
        "start" => (AuditAction::Start, "started"),
        "stop" => (AuditAction::Stop, "stopped"),
        "delete" => (AuditAction::Delete, "deleted"),
        _ => (AuditAction::Write, "updated"),
    };
    record_audit(
        &state,
        action,
        ResourceKind::Workspace,
        Some(&context.user),
        Some(workspace_id.to_string()),
        format!("{verb} workspace {} build", workspace.name),
    )
    .await;

    Ok((StatusCode::CREATED, Json(build_to_json(&build))).into_response())
}

/// PUT /workspaces/{workspace}/autostart
pub(crate) async fn put_workspace_autostart(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
    payload: Result<Json<Value>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(body) = match payload {
        Ok(p) => p,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let Some(workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    // RBAC: verify the actor can update this workspace.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::Workspace)
                .with_id(workspace_id)
                .with_owner(workspace.owner_id)
                .in_org(workspace.organization_id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update this workspace.",
        ));
    }

    let schedule = body
        .get("schedule")
        .and_then(|v| v.as_str())
        .map(String::from);

    state
        .store
        .update_workspace_autostart(workspace_id, schedule.as_deref())
        .await?;

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::Workspace,
        Some(&context.user),
        Some(workspace_id.to_string()),
        format!("updated workspace {} autostart schedule", workspace.name),
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// PUT /workspaces/{workspace}/ttl
pub(crate) async fn put_workspace_ttl(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
    payload: Result<Json<Value>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(body) = match payload {
        Ok(p) => p,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let Some(workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    // RBAC: verify the actor can update this workspace.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::Workspace)
                .with_id(workspace_id)
                .with_owner(workspace.owner_id)
                .in_org(workspace.organization_id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update this workspace.",
        ));
    }

    let ttl_ms = body.get("ttl_ms").and_then(|v| v.as_i64());
    let ttl_ns = ttl_ms.map(|ms| ms * 1_000_000);

    state
        .store
        .update_workspace_ttl(workspace_id, ttl_ns)
        .await?;

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::Workspace,
        Some(&context.user),
        Some(workspace_id.to_string()),
        format!("updated workspace {} TTL", workspace.name),
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// PUT /workspaces/{workspace}/dormant
pub(crate) async fn put_workspace_dormant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
    payload: Result<Json<Value>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(body) = match payload {
        Ok(p) => p,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let Some(workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    // RBAC: verify the actor can update workspace dormancy.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::WorkspaceDormant)
                .with_id(workspace_id)
                .with_owner(workspace.owner_id)
                .in_org(workspace.organization_id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update workspace dormancy.",
        ));
    }

    let dormant = body
        .get("dormant")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let dormant_at = if dormant {
        Some(OffsetDateTime::now_utc())
    } else {
        None
    };

    let Some(updated) = state
        .store
        .update_workspace_dormant_at(workspace_id, dormant_at, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    let verb = if dormant {
        "marked workspace"
    } else {
        "reactivated workspace"
    };
    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::Workspace,
        Some(&context.user),
        Some(workspace_id.to_string()),
        format!("{verb} {} dormancy", updated.name),
    )
    .await;

    Ok((StatusCode::OK, Json(workspace_to_json(&updated))).into_response())
}

/// PUT /workspaces/{workspace}/extend
pub(crate) async fn put_workspace_extend(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
    payload: Result<Json<Value>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(body) = match payload {
        Ok(p) => p,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let Some(workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    // RBAC: verify the actor can update this workspace.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::Workspace)
                .with_id(workspace_id)
                .with_owner(workspace.owner_id)
                .in_org(workspace.organization_id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update this workspace.",
        ));
    }

    let deadline_str = body.get("deadline").and_then(|v| v.as_str());

    let new_deadline = match deadline_str {
        Some(s) => match OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339) {
            Ok(dt) => Some(dt),
            Err(_) => {
                return Ok(validation_response(vec![ValidationError {
                    field: "deadline".to_owned(),
                    detail: "Invalid RFC3339 timestamp.".to_owned(),
                }]));
            }
        },
        None => {
            return Ok(validation_response(vec![ValidationError {
                field: "deadline".to_owned(),
                detail: "Deadline is required.".to_owned(),
            }]));
        }
    };

    let Some(latest_build) = state
        .store
        .find_latest_workspace_build(workspace_id)
        .await?
    else {
        return Ok(not_found_response("No build found for workspace."));
    };

    // Enforce max_deadline: the new deadline cannot exceed the build's max_deadline.
    let clamped_deadline = match (new_deadline, latest_build.max_deadline) {
        (Some(nd), Some(md)) if nd > md => Some(md),
        (d, _) => d,
    };

    let _updated = state
        .store
        .update_workspace_build_deadline(
            latest_build.id,
            clamped_deadline,
            latest_build.max_deadline,
        )
        .await?;

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::Workspace,
        Some(&context.user),
        Some(workspace_id.to_string()),
        format!("extended workspace {} deadline", workspace.name),
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// PUT /workspaces/{workspace}/autoupdates
pub(crate) async fn put_workspace_autoupdates(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
    payload: Result<Json<Value>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(body) = match payload {
        Ok(p) => p,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let Some(workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    // RBAC: verify the actor can update this workspace.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::Workspace)
                .with_id(workspace_id)
                .with_owner(workspace.owner_id)
                .in_org(workspace.organization_id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update this workspace.",
        ));
    }

    let automatic_updates = body
        .get("automatic_updates")
        .and_then(|v| v.as_str())
        .unwrap_or("never");

    state
        .store
        .update_workspace_automatic_updates(workspace_id, automatic_updates)
        .await?;

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::Workspace,
        Some(&context.user),
        Some(workspace_id.to_string()),
        format!(
            "updated workspace {} auto-update policy to {}",
            workspace.name, automatic_updates
        ),
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// PUT /workspaces/{workspace}/favorite
pub(crate) async fn put_workspace_favorite(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    // RBAC: verify the actor can update this workspace.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::Workspace)
                .with_id(workspace_id)
                .with_owner(workspace.owner_id)
                .in_org(workspace.organization_id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update this workspace.",
        ));
    }

    state
        .store
        .favorite_workspace(workspace_id, context.user.id, true)
        .await?;

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::Workspace,
        Some(&context.user),
        Some(workspace_id.to_string()),
        format!("favorited workspace {}", workspace.name),
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// DELETE /workspaces/{workspace}/favorite
pub(crate) async fn delete_workspace_favorite(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    // RBAC: verify the actor can update this workspace.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::Workspace)
                .with_id(workspace_id)
                .with_owner(workspace.owner_id)
                .in_org(workspace.organization_id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update this workspace.",
        ));
    }

    state
        .store
        .favorite_workspace(workspace_id, context.user.id, false)
        .await?;

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::Workspace,
        Some(&context.user),
        Some(workspace_id.to_string()),
        format!("unfavorited workspace {}", workspace.name),
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// GET /workspaces/{workspace}/port-share
pub(crate) async fn list_workspace_port_shares(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(_workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    let shares = state.store.list_workspace_port_shares(workspace_id).await?;
    let items: Vec<Value> = shares
        .into_iter()
        .map(|s| {
            json!({
                "workspace_id": s.workspace_id,
                "agent_name": s.agent_name,
                "port": s.port,
                "share_level": s.share_level,
                "protocol": s.protocol,
            })
        })
        .collect();

    Ok((StatusCode::OK, Json(json!({ "shares": items }))).into_response())
}

/// POST /workspaces/{workspace}/port-share
pub(crate) async fn post_workspace_port_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
    payload: Result<Json<Value>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(body) = match payload {
        Ok(p) => p,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let Some(workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    // RBAC: verify the actor can update this workspace.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::Workspace)
                .with_id(workspace_id)
                .with_owner(workspace.owner_id)
                .in_org(workspace.organization_id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update this workspace.",
        ));
    }

    let agent_name = body
        .get("agent_name")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();
    let port = body.get("port").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
    let share_level = body
        .get("share_level")
        .and_then(|v| v.as_str())
        .unwrap_or("owner")
        .to_owned();
    let protocol = body
        .get("protocol")
        .and_then(|v| v.as_str())
        .unwrap_or("http")
        .to_owned();

    let share = state
        .store
        .upsert_workspace_port_share(UpsertPortShareInput {
            workspace_id,
            agent_name,
            port,
            share_level,
            protocol,
        })
        .await?;

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::Workspace,
        Some(&context.user),
        Some(workspace_id.to_string()),
        format!(
            "upserted port share for workspace {} (agent {} port {})",
            workspace.name, share.agent_name, share.port
        ),
    )
    .await;

    Ok((
        StatusCode::OK,
        Json(json!({
            "workspace_id": share.workspace_id,
            "agent_name": share.agent_name,
            "port": share.port,
            "share_level": share.share_level,
            "protocol": share.protocol,
        })),
    )
        .into_response())
}

/// DELETE /workspaces/{workspace}/port-share
pub(crate) async fn delete_workspace_port_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
    payload: Result<Json<Value>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(body) = match payload {
        Ok(p) => p,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let Some(workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    // RBAC: verify the actor can update this workspace.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::Workspace)
                .with_id(workspace_id)
                .with_owner(workspace.owner_id)
                .in_org(workspace.organization_id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update this workspace.",
        ));
    }

    let agent_name = body
        .get("agent_name")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let port = body.get("port").and_then(|v| v.as_i64()).unwrap_or(0) as i32;

    state
        .store
        .delete_workspace_port_share(workspace_id, agent_name, port)
        .await?;

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::Workspace,
        Some(&context.user),
        Some(workspace_id.to_string()),
        format!(
            "deleted port share for workspace {} (agent {} port {})",
            workspace.name, agent_name, port
        ),
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// GET /workspaces/{workspace}/acl
pub(crate) async fn get_workspace_acl(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    // RBAC: verify the actor can read this workspace.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::Workspace)
                .with_id(workspace_id)
                .with_owner(workspace.owner_id)
                .in_org(workspace.organization_id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to read this workspace's ACL.",
        ));
    }

    let acl_record = state.store.get_workspace_acl(workspace_id).await?;

    // Resolve user details for user ACL entries.
    let mut users = Vec::new();
    for (user_id_str, role) in &acl_record.user_acl {
        if let Ok(uid) = Uuid::from_str(user_id_str) {
            if let Some(user) = state.store.find_user_by_id(uid).await? {
                users.push(WorkspaceACLUser {
                    id: user.id,
                    username: user.username,
                    avatar_url: user.avatar_url,
                    role: role.clone(),
                });
            }
        }
    }

    // Resolve group details for group ACL entries.
    let mut groups = Vec::new();
    for (group_id_str, role) in &acl_record.group_acl {
        if let Ok(gid) = Uuid::from_str(group_id_str) {
            let name = if let Some(group) = state.store.find_group_by_id(gid).await? {
                group.name
            } else {
                group_id_str.clone()
            };
            groups.push(WorkspaceACLGroup {
                id: gid,
                name,
                role: role.clone(),
            });
        }
    }

    Ok((StatusCode::OK, Json(WorkspaceACLResponse { users, groups })).into_response())
}

/// PATCH /workspaces/{workspace}/acl
pub(crate) async fn patch_workspace_acl(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
    payload: Result<Json<UpdateWorkspaceACLRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(req) = match payload {
        Ok(p) => p,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let Some(workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    // RBAC: verify the actor can update this workspace.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::Workspace)
                .with_id(workspace_id)
                .with_owner(workspace.owner_id)
                .in_org(workspace.organization_id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update this workspace's ACL.",
        ));
    }

    let input = UpdateWorkspaceACLInput {
        user_roles: req.user_roles,
        group_roles: req.group_roles,
    };
    state
        .store
        .update_workspace_acl(workspace_id, &input)
        .await?;

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::Workspace,
        Some(&context.user),
        Some(workspace_id.to_string()),
        format!("updated workspace {} ACL", workspace.name),
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// DELETE /workspaces/{workspace}/acl
pub(crate) async fn delete_workspace_acl(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    // RBAC: verify the actor can delete this workspace's ACL.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Delete,
            &Object::new(ResourceType::Workspace)
                .with_id(workspace_id)
                .with_owner(workspace.owner_id)
                .in_org(workspace.organization_id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to delete this workspace's ACL.",
        ));
    }

    state.store.delete_workspace_acl(workspace_id).await?;

    record_audit(
        &state,
        AuditAction::Delete,
        ResourceKind::Workspace,
        Some(&context.user),
        Some(workspace_id.to_string()),
        format!("deleted workspace {} ACL", workspace.name),
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// GET /workspaces/{workspace}/resolve-autostart
pub(crate) async fn get_workspace_resolve_autostart(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    let parameter_mismatch = false;
    Ok((
        StatusCode::OK,
        Json(json!({ "parameter_mismatch": parameter_mismatch, "template_id": workspace.template_id })),
    )
        .into_response())
}

/// GET /workspaces/{workspace}/timings
///
/// Returns build timings for the latest workspace build, including provisioner
/// timings and agent script timings. Mirrors the Go `buildTimings` function
/// in `coderd/workspacebuilds.go`.
pub(crate) async fn get_workspace_timings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(latest_build) = state
        .store
        .find_latest_workspace_build(workspace_id)
        .await?
    else {
        return Ok((
            StatusCode::OK,
            Json(json!({
                "provisioner_timings": [],
                "agent_script_timings": [],
                "agent_connection_timings": []
            })),
        )
            .into_response());
    };

    let timings_response = build_timings_response(&state, &latest_build).await?;
    Ok((StatusCode::OK, Json(timings_response)).into_response())
}

/// POST /workspaces/{workspace}/usage — updates last_used_at.
pub(crate) async fn post_workspace_usage(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    // RBAC: verify the actor can update this workspace.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::Workspace)
                .with_id(workspace_id)
                .with_owner(workspace.owner_id)
                .in_org(workspace.organization_id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update this workspace.",
        ));
    }

    // Prefer the batched usage tracker when present — collapses a burst
    // of usage pings to one DB write per flush interval. Absent tracker
    // (e.g. in unit tests that build AppState directly) falls back to
    // the synchronous update path so behaviour stays correct.
    let now = OffsetDateTime::now_utc();
    if let Some(tracker) = state.usage_tracker.as_ref() {
        tracker.add(workspace_id, now);
    } else {
        state
            .store
            .update_workspace_last_used_at(workspace_id, now)
            .await?;
    }

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// GET /workspaces/{workspace}/watch — SSE stream of workspace updates.
///
/// Subscribes to the workspace owner's pub/sub channel and streams workspace
/// state as Server-Sent Events whenever a relevant event is received.
/// Mirrors the Go `watchWorkspace` handler in `coderd/workspaces.go`.
pub(crate) async fn get_workspace_watch(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
) -> Result<Response, AppError> {
    use axum::body::Body;
    use coder_core::pubsub::{WorkspaceEvent, workspace_event_channel};

    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    let owner_id = workspace.owner_id;
    let channel = workspace_event_channel(owner_id);

    let mut subscription = state.pubsub.subscribe(&channel).await.map_err(|e| {
        AppError::Storage(StorageError::Unavailable {
            message: e.to_string(),
        })
    })?;

    let (tx, rx) = tokio::sync::mpsc::channel::<String>(64);

    // Send initial ping to signal the connection is established.
    let _ = tx.send("event: ping\ndata: {}\n\n".to_owned()).await;

    // Send current workspace state immediately after connection.
    let initial_data = serde_json::to_string(&workspace_to_json(&workspace)).unwrap_or_default();
    let _ = tx
        .send(format!("event: data\ndata: {initial_data}\n\n"))
        .await;

    // Spawn a task that listens for pub/sub events and sends SSE data.
    let store = state.store.clone();
    let viewer_id = context.user.id;
    tokio::spawn(async move {
        loop {
            // Race pub/sub recv against client disconnect (rx dropped → tx.closed()).
            tokio::select! {
                msg = subscription.recv() => {
                    match msg {
                        Ok(bytes) => {
                            // Skip messages that fail to parse or belong to a different workspace.
                            match serde_json::from_slice::<WorkspaceEvent>(&bytes) {
                                Ok(ev) if ev.workspace_id == workspace_id => { /* proceed */ }
                                _ => continue,
                            }

                            // Fetch fresh workspace state.
                            match store
                                .find_workspace_by_id(workspace_id, Some(viewer_id))
                                .await
                            {
                                Ok(Some(w)) => {
                                    let data =
                                        serde_json::to_string(&workspace_to_json(&w)).unwrap_or_default();
                                    let sse = format!("event: data\ndata: {data}\n\n");
                                    if tx.send(sse).await.is_err() {
                                        break;
                                    }
                                }
                                Ok(None) => break,
                                Err(_) => {
                                    let err_data = serde_json::to_string(&json!({
                                        "message": "Internal error fetching workspace."
                                    }))
                                    .unwrap_or_default();
                                    let sse = format!("event: error\ndata: {err_data}\n\n");
                                    let _ = tx.send(sse).await;
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
                _ = tx.closed() => {
                    // Client disconnected (rx was dropped).
                    break;
                }
            }
        }
    });

    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    let body = Body::from_stream(tokio_stream::StreamExt::map(
        stream,
        Ok::<_, std::convert::Infallible>,
    ));

    Ok((
        StatusCode::OK,
        [
            (CONTENT_TYPE, HeaderValue::from_static("text/event-stream")),
            (
                HeaderName::from_static("cache-control"),
                HeaderValue::from_static("no-cache"),
            ),
        ],
        body,
    )
        .into_response())
}

/// GET /workspaces/{workspace}/watch-ws — WebSocket stream of workspace updates.
///
/// Upgrades the connection to a WebSocket and streams workspace JSON state
/// whenever a relevant pub/sub event is received for this workspace.
/// Mirrors the Go `watchWorkspaceWS` handler.
pub(crate) async fn get_workspace_watch_ws(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
    ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
    use axum::extract::ws::Message;
    use coder_core::pubsub::{WorkspaceEvent, workspace_event_channel};

    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    let owner_id = workspace.owner_id;
    let viewer_id = context.user.id;
    let store = state.store.clone();
    let pubsub = state.pubsub.clone();

    Ok(ws.on_upgrade(move |mut socket| async move {
        // Subscribe to pub/sub BEFORE sending initial state to avoid missing
        // events that arrive between the initial fetch and the subscription.
        let channel = workspace_event_channel(owner_id);
        let mut subscription = match pubsub.subscribe(&channel).await {
            Ok(sub) => sub,
            Err(_) => return,
        };

        // Send initial workspace state.
        let initial = serde_json::to_string(&workspace_to_json(&workspace)).unwrap_or_default();
        if socket.send(Message::Text(initial.into())).await.is_err() {
            return;
        }

        loop {
            // Race pub/sub recv against WebSocket client messages to detect disconnect.
            tokio::select! {
                msg = subscription.recv() => {
                    match msg {
                        Ok(bytes) => {
                            // Skip messages that fail to parse or belong to a different workspace.
                            match serde_json::from_slice::<WorkspaceEvent>(&bytes) {
                                Ok(ev) if ev.workspace_id == workspace_id => { /* proceed */ }
                                _ => continue,
                            }

                            match store
                                .find_workspace_by_id(workspace_id, Some(viewer_id))
                                .await
                            {
                                Ok(Some(w)) => {
                                    let data =
                                        serde_json::to_string(&workspace_to_json(&w)).unwrap_or_default();
                                    if socket.send(Message::Text(data.into())).await.is_err() {
                                        break;
                                    }
                                }
                                Ok(None) => break,
                                Err(_) => {
                                    let err = serde_json::to_string(&json!({
                                        "message": "Internal error fetching workspace."
                                    }))
                                    .unwrap_or_default();
                                    let _ = socket.send(Message::Text(err.into())).await;
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
                ws_msg = socket.recv() => {
                    // Client sent a close frame or disconnected.
                    match ws_msg {
                        Some(Ok(Message::Close(_))) | None => break,
                        _ => { /* ignore other client messages */ }
                    }
                }
            }
        }
    }))
}

/// GET /workspacebuilds/{build}
pub(crate) async fn get_workspace_build(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(build_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(build) = state.store.find_workspace_build_by_id(build_id).await? else {
        return Ok(resource_not_found_response());
    };

    Ok((StatusCode::OK, Json(build_to_json(&build))).into_response())
}

/// PATCH /workspacebuilds/{build}/cancel
pub(crate) async fn patch_cancel_workspace_build(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(build_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(build) = state.store.find_workspace_build_by_id(build_id).await? else {
        return Ok(resource_not_found_response());
    };

    // Look up the workspace to get owner/org info for RBAC.
    let Some(workspace) = state
        .store
        .find_workspace_by_id(build.workspace_id, None)
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    // RBAC: verify the actor can update this workspace build.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::Workspace)
                .with_id(build.workspace_id)
                .with_owner(workspace.owner_id)
                .in_org(workspace.organization_id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to cancel this workspace build.",
        ));
    }

    let canceled = state
        .store
        .cancel_template_provisioner_job(build.job_id)
        .await?;

    if !canceled {
        return Ok((
            StatusCode::PRECONDITION_FAILED,
            Json(ApiResponse::ok("Build is already completed or canceled.")),
        )
            .into_response());
    }

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::Workspace,
        Some(&context.user),
        Some(build.workspace_id.to_string()),
        format!("canceled workspace {} build", workspace.name),
    )
    .await;

    Ok(StatusCode::OK.into_response())
}

/// GET /workspacebuilds/{build}/logs
pub(crate) async fn get_workspace_build_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(build_id): Path<Uuid>,
    Query(query): Query<BuildLogsQuery>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(build) = state.store.find_workspace_build_by_id(build_id).await? else {
        return Ok(resource_not_found_response());
    };

    let _follow = query.follow.unwrap_or(false);
    let logs = state
        .store
        .list_provisioner_job_logs(build.job_id, query.after)
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

/// GET /workspacebuilds/{build}/parameters
pub(crate) async fn get_workspace_build_parameters(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(build_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(_build) = state.store.find_workspace_build_by_id(build_id).await? else {
        return Ok(resource_not_found_response());
    };

    let params = state
        .store
        .list_workspace_build_parameters(build_id)
        .await?;

    let items: Vec<WorkspaceBuildParameter> = params
        .into_iter()
        .map(|p| WorkspaceBuildParameter {
            name: p.name,
            value: p.value,
        })
        .collect();

    Ok((StatusCode::OK, Json(items)).into_response())
}

/// GET /workspacebuilds/{build}/resources
pub(crate) async fn get_workspace_build_resources(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(build_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(build) = state.store.find_workspace_build_by_id(build_id).await? else {
        return Ok(resource_not_found_response());
    };

    let resources = state
        .store
        .list_workspace_resources_by_job(build.job_id)
        .await?;

    // Fetch metadata for all resources in one batch.
    let resource_ids: Vec<Uuid> = resources.iter().map(|r| r.id).collect();
    let all_metadata = state
        .store
        .list_workspace_resource_metadata(&resource_ids)
        .await?;

    // Group metadata by resource id.
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

/// GET /workspacebuilds/{build}/state
pub(crate) async fn get_workspace_build_state(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(build_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(build) = state.store.find_workspace_build_by_id(build_id).await? else {
        return Ok(resource_not_found_response());
    };

    let state_bytes = build.provisioner_state.unwrap_or_default();
    Ok((
        StatusCode::OK,
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        )],
        state_bytes,
    )
        .into_response())
}

/// PUT /workspacebuilds/{build}/state
pub(crate) async fn put_workspace_build_state(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(build_id): Path<Uuid>,
    body: Bytes,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(build) = state.store.find_workspace_build_by_id(build_id).await? else {
        return Ok(resource_not_found_response());
    };

    // Look up the workspace to get owner/org info for RBAC.
    let Some(workspace) = state
        .store
        .find_workspace_by_id(build.workspace_id, None)
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    // RBAC: verify the actor can update this workspace build state.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::Workspace)
                .with_id(build.workspace_id)
                .with_owner(workspace.owner_id)
                .in_org(workspace.organization_id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update this workspace build state.",
        ));
    }

    state
        .store
        .update_workspace_build_provisioner_state(build_id, &body)
        .await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// GET /workspacebuilds/{build}/timings
pub(crate) async fn get_workspace_build_timings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(build_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(build) = state.store.find_workspace_build_by_id(build_id).await? else {
        return Ok(resource_not_found_response());
    };

    let timings_response = build_timings_response(&state, &build).await?;
    Ok((StatusCode::OK, Json(timings_response)).into_response())
}

/// GET /users/{user}/workspace/{name}
pub(crate) async fn get_user_workspace_by_name(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((user, name)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(target_user) = resolve_user(&state, &user, &context.user).await? else {
        return Ok(resource_not_found_response());
    };

    // RBAC: verify the actor can read workspaces owned by target user.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::Workspace).with_owner(target_user.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to view this user's workspaces.",
        ));
    }

    let Some(workspace) = state
        .store
        .find_workspace_by_owner_and_name(target_user.id, &name, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    Ok((StatusCode::OK, Json(workspace_to_json(&workspace))).into_response())
}

/// GET /users/{user}/workspace/{name}/builds/{number}
pub(crate) async fn get_user_workspace_build_by_number(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((user, name, number)): Path<(String, String, i64)>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(target_user) = resolve_user(&state, &user, &context.user).await? else {
        return Ok(resource_not_found_response());
    };

    let Some(workspace) = state
        .store
        .find_workspace_by_owner_and_name(target_user.id, &name, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    let Some(build) = state
        .store
        .find_workspace_build_by_number(workspace.id, number)
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    Ok((StatusCode::OK, Json(build_to_json(&build))).into_response())
}

/// POST /users/{user}/workspaces — create workspace + initial build.
pub(crate) async fn post_user_workspace(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user): Path<String>,
    payload: Result<Json<Value>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(body) = match payload {
        Ok(p) => p,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let Some(target_user) = resolve_user(&state, &user, &context.user).await? else {
        return Ok(resource_not_found_response());
    };

    // RBAC: verify the actor can create workspaces for this user.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Create,
            &Object::new(ResourceType::Workspace).with_owner(target_user.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to create workspaces for this user.",
        ));
    }

    let template_id = match body.get("template_id").and_then(|v| v.as_str()) {
        Some(id) => match Uuid::parse_str(id) {
            Ok(uuid) => uuid,
            Err(_) => {
                return Ok(validation_response(vec![ValidationError {
                    field: "template_id".to_owned(),
                    detail: "Invalid UUID.".to_owned(),
                }]));
            }
        },
        None => {
            return Ok(validation_response(vec![ValidationError {
                field: "template_id".to_owned(),
                detail: "Template ID is required.".to_owned(),
            }]));
        }
    };

    let ws_name = body
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();

    if ws_name.is_empty() {
        return Ok(validation_response(vec![ValidationError {
            field: "name".to_owned(),
            detail: "Name is required.".to_owned(),
        }]));
    }

    let Some(template) = state.store.find_template_by_id(template_id).await? else {
        return Ok(not_found_response("Template not found."));
    };

    let workspace_id = Uuid::new_v4();
    let autostart_schedule = body
        .get("autostart_schedule")
        .and_then(|v| v.as_str())
        .map(String::from);
    let ttl_ms = body.get("ttl_ms").and_then(|v| v.as_i64());
    let automatic_updates = body
        .get("automatic_updates")
        .and_then(|v| v.as_str())
        .unwrap_or("never")
        .to_owned();

    let workspace = state
        .store
        .insert_workspace(CreateWorkspaceInput {
            id: workspace_id,
            owner_id: target_user.id,
            organization_id: template.organization_id,
            template_id,
            name: ws_name,
            autostart_schedule,
            ttl_ns: ttl_ms.map(|ms| ms * 1_000_000),
            automatic_updates,
        })
        .await?;

    // Create initial build.
    let job_id = Uuid::new_v4();
    let build_id = Uuid::new_v4();

    let template_version_id = body
        .get("template_version_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or(template.active_version_id);

    let tags = build_provisioner_tags(&state, workspace.owner_id, template_version_id).await?;
    let _job = state
        .store
        .create_provisioner_job(CreateProvisionerJobInput {
            id: job_id,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            organization_id: template.organization_id,
            initiator_id: context.user.id,
            provisioner: "echo".to_owned(),
            file_id: None,
            job_type: "workspace_build".to_owned(),
            input: json!({}),
            tags,
        })
        .await?;

    // Compute the max_deadline (quiet-hours clamp) for templates that declare
    // an autostop requirement.
    let now_ts = OffsetDateTime::now_utc();
    let max_deadline =
        resolve_build_max_deadline(&state, &template, workspace.owner_id, now_ts).await?;

    // build_number is computed atomically inside insert_workspace_build.
    let _build = state
        .store
        .insert_workspace_build(CreateWorkspaceBuildInput {
            id: build_id,
            workspace_id,
            template_version_id,
            build_number: 0,
            transition: "start".to_owned(),
            initiator_id: context.user.id,
            job_id,
            reason: "initiator".to_owned(),
            deadline: max_deadline,
            max_deadline,
        })
        .await?;

    // Insert build parameters if provided.
    if let Some(params) = body.get("rich_parameter_values").and_then(|v| v.as_array()) {
        let param_pairs: Vec<(String, String)> = params
            .iter()
            .filter_map(|p| {
                let name = p.get("name")?.as_str()?.to_owned();
                let value = p.get("value")?.as_str()?.to_owned();
                Some((name, value))
            })
            .collect();
        if !param_pairs.is_empty() {
            state
                .store
                .insert_workspace_build_parameters(build_id, &param_pairs)
                .await?;
        }
    }

    record_audit(
        &state,
        AuditAction::Create,
        ResourceKind::Workspace,
        Some(&context.user),
        Some(workspace.id.to_string()),
        format!("created workspace {}", workspace.name),
    )
    .await;

    Ok((StatusCode::CREATED, Json(workspace_to_json(&workspace))).into_response())
}

/// POST /organizations/{organization}/members/{user}/workspaces — create workspace in org.
///
/// Mirrors the Go `postWorkspacesByOrganization` handler: resolves the
/// organization and member, then delegates to the same workspace-creation
/// logic used by `post_user_workspace`.
pub(crate) async fn post_org_member_workspace(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((organization, user)): Path<(String, String)>,
    payload: Result<Json<Value>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Json(body) = match payload {
        Ok(p) => p,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    // Resolve organization.
    let Some(org_record) = resolve_organization(&state, &organization).await? else {
        return Ok(not_found_response("Organization not found."));
    };

    // Resolve the target user (member) within the organization context.
    let Some(target_user) = resolve_user(&state, &user, &context.user).await? else {
        return Ok(resource_not_found_response());
    };

    // RBAC: verify the actor can create workspaces for this user in this org.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Create,
            &Object::new(ResourceType::Workspace)
                .with_owner(target_user.id)
                .in_org(org_record.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to create workspaces in this organization.",
        ));
    }

    // From here, the workspace creation logic is identical to post_user_workspace.
    let template_id = match body.get("template_id").and_then(|v| v.as_str()) {
        Some(id) => match Uuid::parse_str(id) {
            Ok(uuid) => uuid,
            Err(_) => {
                return Ok(validation_response(vec![ValidationError {
                    field: "template_id".to_owned(),
                    detail: "Invalid UUID.".to_owned(),
                }]));
            }
        },
        None => {
            return Ok(validation_response(vec![ValidationError {
                field: "template_id".to_owned(),
                detail: "Template ID is required.".to_owned(),
            }]));
        }
    };

    let ws_name = body
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();

    if ws_name.is_empty() {
        return Ok(validation_response(vec![ValidationError {
            field: "name".to_owned(),
            detail: "Name is required.".to_owned(),
        }]));
    }

    let Some(template) = state.store.find_template_by_id(template_id).await? else {
        return Ok(not_found_response("Template not found."));
    };

    // Ensure the template belongs to the resolved organization.
    if template.organization_id != org_record.id {
        return Ok(not_found_response(
            "Template not found in the specified organization.",
        ));
    }

    let workspace_id = Uuid::new_v4();
    let autostart_schedule = body
        .get("autostart_schedule")
        .and_then(|v| v.as_str())
        .map(String::from);
    let ttl_ms = body.get("ttl_ms").and_then(|v| v.as_i64());
    let automatic_updates = body
        .get("automatic_updates")
        .and_then(|v| v.as_str())
        .unwrap_or("never")
        .to_owned();

    let workspace = state
        .store
        .insert_workspace(CreateWorkspaceInput {
            id: workspace_id,
            owner_id: target_user.id,
            organization_id: org_record.id,
            template_id,
            name: ws_name,
            autostart_schedule,
            ttl_ns: ttl_ms.map(|ms| ms * 1_000_000),
            automatic_updates,
        })
        .await?;

    // Create initial build.
    let job_id = Uuid::new_v4();
    let build_id = Uuid::new_v4();

    let template_version_id = body
        .get("template_version_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or(template.active_version_id);

    let tags = build_provisioner_tags(&state, workspace.owner_id, template_version_id).await?;
    let _job = state
        .store
        .create_provisioner_job(CreateProvisionerJobInput {
            id: job_id,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            organization_id: org_record.id,
            initiator_id: context.user.id,
            provisioner: "echo".to_owned(),
            file_id: None,
            job_type: "workspace_build".to_owned(),
            input: json!({}),
            tags,
        })
        .await?;

    // Compute the max_deadline (quiet-hours clamp) for templates that declare
    // an autostop requirement.
    let now_ts = OffsetDateTime::now_utc();
    let max_deadline =
        resolve_build_max_deadline(&state, &template, workspace.owner_id, now_ts).await?;

    let _build = state
        .store
        .insert_workspace_build(CreateWorkspaceBuildInput {
            id: build_id,
            workspace_id,
            template_version_id,
            build_number: 0,
            transition: "start".to_owned(),
            initiator_id: context.user.id,
            job_id,
            reason: "initiator".to_owned(),
            deadline: max_deadline,
            max_deadline,
        })
        .await?;

    // Insert build parameters if provided.
    if let Some(params) = body.get("rich_parameter_values").and_then(|v| v.as_array()) {
        let param_pairs: Vec<(String, String)> = params
            .iter()
            .filter_map(|p| {
                let name = p.get("name")?.as_str()?.to_owned();
                let value = p.get("value")?.as_str()?.to_owned();
                Some((name, value))
            })
            .collect();
        if !param_pairs.is_empty() {
            state
                .store
                .insert_workspace_build_parameters(build_id, &param_pairs)
                .await?;
        }
    }

    record_audit(
        &state,
        AuditAction::Create,
        ResourceKind::Workspace,
        Some(&context.user),
        Some(workspace.id.to_string()),
        format!("created workspace {}", workspace.name),
    )
    .await;

    Ok((StatusCode::CREATED, Json(workspace_to_json(&workspace))).into_response())
}

/// GET /organizations/{organization}/members/{user}/workspaces/available-users
///
/// Returns a list of users that can own workspaces in the given organization.
/// Mirrors the Go `workspaceAvailableUsers` handler.
pub(crate) async fn get_org_member_workspace_available_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((organization, _user)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // Validate the organization exists.
    let Some(_org_record) = resolve_organization(&state, &organization).await? else {
        return Ok(not_found_response("Organization not found."));
    };

    // List all active users — the Go implementation lists all users using
    // system context.  We return MinimalUser representations.
    let (users, _count) = state
        .store
        .list_users(UserListFilter {
            status: Some(UserStatus::Active),
            ..UserListFilter::default()
        })
        .await?;

    let minimal_users: Vec<MinimalUser> = users
        .into_iter()
        .map(|u| MinimalUser {
            id: u.id,
            username: u.username,
            name: u.name,
            avatar_url: u.avatar_url,
        })
        .collect();

    Ok((StatusCode::OK, Json(minimal_users)).into_response())
}

/// Builds the full timings response for a workspace build, including provisioner
/// timings, agent script timings, and agent connection timings.
/// Mirrors the Go `buildTimings` function in `coderd/workspacebuilds.go`.
pub(crate) async fn build_timings_response(
    state: &AppState,
    build: &coder_core::WorkspaceBuildRecord,
) -> Result<Value, AppError> {
    // Fetch provisioner job timings.
    let provisioner_timings = state
        .store
        .list_provisioner_job_timings(build.job_id)
        .await?;

    // Go's time.Time.IsZero() checks for year 0001-01-01T00:00:00Z, not Unix epoch.
    let go_zero = time::Date::from_calendar_date(1, time::Month::January, 1)
        .unwrap_or(time::Date::MIN)
        .midnight()
        .assume_utc();

    let provisioner_items: Vec<Value> = provisioner_timings
        .into_iter()
        .filter(|t| {
            // Ref: #15432: timings must not have a zero start or end time.
            t.started_at != go_zero && t.ended_at != go_zero
        })
        .map(|t| {
            json!({
                "job_id": build.job_id,
                "started_at": t.started_at.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
                "ended_at": t.ended_at.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
                "stage": t.stage,
                "source": t.source,
                "action": t.action,
                "resource": t.resource,
            })
        })
        .collect();

    // Fetch agent script timings (best-effort; the store may not implement this yet).
    let agent_script_timings = state
        .store
        .list_workspace_agent_script_timings_by_build_id(build.id)
        .await
        .unwrap_or_default();

    let agent_script_items: Vec<Value> = agent_script_timings
        .into_iter()
        .filter(|t| t.started_at != go_zero && t.ended_at != go_zero)
        .map(|t| {
            json!({
                "started_at": t.started_at.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
                "ended_at": t.ended_at.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
                "exit_code": t.exit_code,
                "stage": t.stage,
                "status": t.status,
                "display_name": t.display_name,
                "workspace_agent_id": t.workspace_agent_id.to_string(),
                "workspace_agent_name": t.workspace_agent_name,
            })
        })
        .collect();

    Ok(json!({
        "provisioner_timings": provisioner_items,
        "agent_script_timings": agent_script_items,
        "agent_connection_timings": [],
    }))
}

/// `GET /workspaces/{workspace}/external-agent/{agent}/credentials`
///
/// Returns the auth token and bootstrap command for an external agent in a
/// workspace.  Mirrors Go `workspaceExternalAgentCredentials()`.
pub(crate) async fn get_external_agent_credentials(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((workspace_id, agent_name)): Path<(Uuid, String)>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // 1. Get workspace by ID.
    let Some(workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    // RBAC: verify the actor can read this workspace.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::Workspace)
                .with_id(workspace.id)
                .with_owner(workspace.owner_id)
                .in_org(workspace.organization_id),
        )
        .is_err()
    {
        return Ok(resource_not_found_response());
    }

    // 2. Get latest workspace build.
    let Some(build) = state
        .store
        .find_latest_workspace_build(workspace.id)
        .await?
    else {
        return Ok(not_found_response("No builds found for this workspace."));
    };

    // 3. Check build's template version has_external_agent → 404 if false.
    let tv = state
        .store
        .find_template_version_by_id(build.template_version_id)
        .await?
        .ok_or_else(|| AppError::NotFound {
            message: "Template version not found.".to_owned(),
        })?;

    if !tv.has_external_agent.unwrap_or(false) {
        return Ok(not_found_response(
            "This workspace does not have an external agent.",
        ));
    }

    // 4. Get all agents for the workspace build.
    let resources = state
        .store
        .list_workspace_resources_by_job(build.job_id)
        .await?;
    let resource_ids: Vec<Uuid> = resources.iter().map(|r| r.id).collect();
    let agents = if resource_ids.is_empty() {
        vec![]
    } else {
        state
            .store
            .list_workspace_agents_by_resource_ids(&resource_ids)
            .await?
    };

    // 5. Find agent by name → 404 if not found.
    let agent = match agents.iter().find(|a| a.name == agent_name) {
        Some(a) => a,
        None => {
            return Ok(not_found_response("Agent not found."));
        }
    };

    // 6. Check agent.auth_instance_id is empty (external agents don't use
    //    instance auth) → 404 if set.
    if agent
        .auth_instance_id
        .as_ref()
        .is_some_and(|id| !id.is_empty())
    {
        return Ok(not_found_response(
            "This agent uses instance identity authentication and is not an external agent.",
        ));
    }

    // 7–8. Construct init script URL and command string.
    // The Go source uses /api/v2/init-script/{os}/{arch} which serves a shell
    // script (not a binary).  The agent token is embedded in the command so the
    // script can authenticate on first run.
    let access_url = state.config.access_url.as_str().trim_end_matches('/');
    let os = &agent.operating_system;
    let arch = &agent.architecture;
    let token = &agent.auth_token;

    let init_script_url = format!("{access_url}/api/v2/init-script/{os}/{arch}");
    let command = if os == "windows" {
        format!("$env:CODER_AGENT_TOKEN=\"{token}\"; iwr -useb \"{init_script_url}\" | iex")
    } else {
        format!("curl -fsSL \"{init_script_url}\" | CODER_AGENT_TOKEN=\"{token}\" sh")
    };

    // 9. Return credentials.
    let body = json!({
        "agent_token": agent.auth_token.to_string(),
        "command": command,
    });
    Ok((StatusCode::OK, Json(body)).into_response())
}

pub(crate) fn workspace_transition_from_str(s: &str) -> coder_core::api::WorkspaceTransition {
    match s {
        "start" => coder_core::api::WorkspaceTransition::Start,
        "stop" => coder_core::api::WorkspaceTransition::Stop,
        "delete" => coder_core::api::WorkspaceTransition::Delete,
        other => {
            tracing::warn!(
                transition = other,
                "unknown workspace transition, defaulting to start"
            );
            coder_core::api::WorkspaceTransition::Start
        }
    }
}

pub(crate) fn workspace_to_json(w: &coder_core::WorkspaceRecord) -> Value {
    json!({
        "id": w.id,
        "created_at": w.created_at.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
        "updated_at": w.updated_at.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
        "owner_id": w.owner_id,
        "organization_id": w.organization_id,
        "template_id": w.template_id,
        "name": w.name,
        "autostart_schedule": w.autostart_schedule,
        "ttl_ms": w.ttl_ns.map(|ns| ns / 1_000_000),
        "last_used_at": w.last_used_at.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
        "dormant_at": w.dormant_at.map(|t| t.format(&time::format_description::well_known::Rfc3339).unwrap_or_default()),
        "deleting_at": w.deleting_at.map(|t| t.format(&time::format_description::well_known::Rfc3339).unwrap_or_default()),
        "automatic_updates": w.automatic_updates,
        "favorite": w.favorite,
        "next_start_at": w.next_start_at.map(|t| t.format(&time::format_description::well_known::Rfc3339).unwrap_or_default()),
    })
}

pub(crate) fn build_to_json(b: &coder_core::WorkspaceBuildRecord) -> Value {
    json!({
        "id": b.id,
        "created_at": b.created_at.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
        "updated_at": b.updated_at.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
        "workspace_id": b.workspace_id,
        "build_number": b.build_number,
        "transition": b.transition,
        "job_id": b.job_id,
        "template_version_id": b.template_version_id,
        "initiator_id": b.initiator_id,
        "deadline": b.deadline.map(|t| t.format(&time::format_description::well_known::Rfc3339).unwrap_or_default()),
        "max_deadline": b.max_deadline.map(|t| t.format(&time::format_description::well_known::Rfc3339).unwrap_or_default()),
        "reason": b.reason,
        "daily_cost": b.daily_cost,
    })
}
