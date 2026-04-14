//! Group CRUD handlers (enterprise — gated on `TemplateRbac`).

use super::*;

/// `GET /api/v2/groups` — list all groups across all organizations.
pub(crate) async fn list_all_groups(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::Group),
        )
        .is_err()
    {
        return Ok(forbidden_response("You are not authorized to read groups."));
    }

    let groups = state.store.list_all_groups().await?;
    let responses = build_group_responses(&state, &groups).await?;
    Ok((StatusCode::OK, Json(responses)).into_response())
}

/// `GET /api/v2/groups/{group}` — get a single group by UUID.
pub(crate) async fn get_group(
    State(state): State<AppState>,
    Path(group_id_str): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let group_id = match Uuid::parse_str(&group_id_str) {
        Ok(id) => id,
        Err(_) => return Ok(not_found_response("Group not found.")),
    };

    let Some(group) = state.store.find_group_by_id(group_id).await? else {
        return Ok(not_found_response("Group not found."));
    };

    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::Group).in_org(group.organization_id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to read this group.",
        ));
    }

    let response = build_group_response(&state, &group).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// `PATCH /api/v2/groups/{group}` — update a group.
pub(crate) async fn patch_group(
    State(state): State<AppState>,
    Path(group_id_str): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<coder_core::api::PatchGroupRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let group_id = match Uuid::parse_str(&group_id_str) {
        Ok(id) => id,
        Err(_) => return Ok(not_found_response("Group not found.")),
    };

    let Some(group) = state.store.find_group_by_id(group_id).await? else {
        return Ok(not_found_response("Group not found."));
    };

    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::Group).in_org(group.organization_id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update this group.",
        ));
    }

    let Json(request) = match payload {
        Ok(r) => r,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let is_everyone = group.id == group.organization_id;

    // Validate "Everyone" group restrictions.
    let req_name = request.name.as_deref().unwrap_or_default();
    if is_everyone && !req_name.is_empty() && req_name != group.name {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::ok(
                "Cannot rename the Everyone group.".to_string(),
            )),
        )
            .into_response());
    }

    if is_everyone {
        if let Some(ref display) = request.display_name {
            if !display.is_empty() {
                return Ok((
                    StatusCode::BAD_REQUEST,
                    Json(ApiResponse::ok(
                        "Cannot set a display name for the Everyone group.".to_string(),
                    )),
                )
                    .into_response());
            }
        }
    }

    // Validate name is not "Everyone".
    if !req_name.is_empty() && req_name.eq_ignore_ascii_case("everyone") && !is_everyone {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::ok(
                "Cannot use the name 'Everyone' for a group.".to_string(),
            )),
        )
            .into_response());
    }

    // Cannot add/remove members from the Everyone group.
    if is_everyone && (!request.add_users.is_empty() || !request.remove_users.is_empty()) {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::ok(
                "Cannot add or remove members from the Everyone group.".to_string(),
            )),
        )
            .into_response());
    }

    // Apply field updates.
    let new_name = if req_name.is_empty() || req_name == group.name {
        group.name.clone()
    } else {
        req_name.to_string()
    };
    let new_display_name = request
        .display_name
        .unwrap_or_else(|| group.display_name.clone());
    let new_avatar_url = request
        .avatar_url
        .unwrap_or_else(|| group.avatar_url.clone());
    let new_quota_allowance = request.quota_allowance.unwrap_or(group.quota_allowance);

    // Check name uniqueness if renaming.
    if new_name != group.name {
        if let Some(_existing) = state
            .store
            .find_group_by_name(group.organization_id, &new_name)
            .await?
        {
            return Ok((
                StatusCode::CONFLICT,
                Json(ApiResponse::ok(
                    "A group with this name already exists.".to_string(),
                )),
            )
                .into_response());
        }
    }

    let update_input = coder_core::identity::UpdateGroupInput {
        id: group.id,
        name: new_name,
        display_name: new_display_name,
        avatar_url: new_avatar_url,
        quota_allowance: new_quota_allowance,
    };
    let updated = state.store.update_group(&update_input).await?;

    // Process member additions.
    for user_id_str in &request.add_users {
        if let Ok(uid) = Uuid::parse_str(user_id_str) {
            // Verify user exists.
            if state.store.find_user_by_id(uid).await?.is_some() {
                let _ = state.store.insert_group_member(group.id, uid).await;
            }
        }
    }

    // Process member removals.
    for user_id_str in &request.remove_users {
        if let Ok(uid) = Uuid::parse_str(user_id_str) {
            state.store.delete_group_member(group.id, uid).await?;
        }
    }

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::Group,
        Some(&context.user),
        Some(group.id.to_string()),
        format!("updated group {}", updated.name),
    )
    .await;

    let response = build_group_response(&state, &updated).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// `DELETE /api/v2/groups/{group}` — delete a group.
pub(crate) async fn delete_group(
    State(state): State<AppState>,
    Path(group_id_str): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let group_id = match Uuid::parse_str(&group_id_str) {
        Ok(id) => id,
        Err(_) => return Ok(not_found_response("Group not found.")),
    };

    let Some(group) = state.store.find_group_by_id(group_id).await? else {
        return Ok(not_found_response("Group not found."));
    };

    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Delete,
            &Object::new(ResourceType::Group).in_org(group.organization_id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to delete this group.",
        ));
    }

    // Cannot delete the "Everyone" group.
    if group.id == group.organization_id {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::ok(
                "Cannot delete the Everyone group.".to_string(),
            )),
        )
            .into_response());
    }

    state.store.delete_group(group.id).await?;

    record_audit(
        &state,
        AuditAction::Delete,
        ResourceKind::Group,
        Some(&context.user),
        Some(group.id.to_string()),
        format!("deleted group {}", group.name),
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `GET /api/v2/organizations/{organization}/groups` — list groups for an org.
pub(crate) async fn list_org_groups(
    State(state): State<AppState>,
    Path(organization): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(org) = resolve_organization(&state, &organization).await? else {
        return Ok(not_found_response("Organization not found."));
    };

    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::Group).in_org(org.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to read groups in this organization.",
        ));
    }

    let groups = state.store.list_groups(org.id).await?;
    let responses = build_group_responses(&state, &groups).await?;
    Ok((StatusCode::OK, Json(responses)).into_response())
}

/// `POST /api/v2/organizations/{organization}/groups` — create a group.
pub(crate) async fn post_org_group(
    State(state): State<AppState>,
    Path(organization): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<coder_core::api::CreateGroupRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(org) = resolve_organization(&state, &organization).await? else {
        return Ok(not_found_response("Organization not found."));
    };

    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Create,
            &Object::new(ResourceType::Group).in_org(org.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to create groups in this organization.",
        ));
    }

    let Json(request) = match payload {
        Ok(r) => r,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    if request.name.is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::ok("Group name is required.".to_string())),
        )
            .into_response());
    }

    // The name "Everyone" is reserved for the org-level default group.
    if request.name.eq_ignore_ascii_case("everyone") {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::ok(
                "Cannot use the name 'Everyone' for a group.".to_string(),
            )),
        )
            .into_response());
    }

    let input = coder_core::identity::CreateGroupInput {
        name: request.name.clone(),
        display_name: request.display_name,
        organization_id: org.id,
        avatar_url: request.avatar_url,
        quota_allowance: request.quota_allowance,
    };

    let group = match state.store.create_group(&input).await {
        Ok(g) => g,
        Err(StorageError::InvalidData { message }) => {
            return Ok((StatusCode::CONFLICT, Json(ApiResponse::ok(message))).into_response());
        }
        Err(e) => return Err(AppError::from(e)),
    };

    record_audit(
        &state,
        AuditAction::Create,
        ResourceKind::Group,
        Some(&context.user),
        Some(group.id.to_string()),
        format!("created group {}", group.name),
    )
    .await;

    let response = build_group_response(&state, &group).await?;
    Ok((StatusCode::CREATED, Json(response)).into_response())
}

/// `GET /api/v2/organizations/{organization}/groups/{groupName}` — lookup by name.
pub(crate) async fn get_org_group_by_name(
    State(state): State<AppState>,
    Path((organization, group_name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(org) = resolve_organization(&state, &organization).await? else {
        return Ok(not_found_response("Organization not found."));
    };

    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::Group).in_org(org.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to read groups in this organization.",
        ));
    }

    let Some(group) = state.store.find_group_by_name(org.id, &group_name).await? else {
        return Ok(not_found_response("Group not found."));
    };

    let response = build_group_response(&state, &group).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

use crate::handlers::templates::resolve_organization;
use coder_core::api::{GroupResponse, MinimalUser, ReducedUser};
use coder_core::identity::GroupRecord;

/// Build a `ReducedUser` from a `UserRecord`.
fn reduced_user_from_record(user: &coder_core::identity::UserRecord) -> ReducedUser {
    ReducedUser {
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
    }
}

/// Build a `GroupResponse` for a single group, including members and org info.
async fn build_group_response(
    state: &AppState,
    group: &GroupRecord,
) -> Result<GroupResponse, AppError> {
    let members_records = state.store.list_group_members(group.id).await?;
    let mut members = Vec::with_capacity(members_records.len());
    for mr in &members_records {
        if let Some(user) = state.store.find_user_by_id(mr.user_id).await? {
            members.push(reduced_user_from_record(&user));
        }
    }
    let total_member_count = members.len() as i32;

    // Resolve org name/display_name.
    let (org_name, org_display_name) = if let Some(org) = state
        .store
        .find_organization_by_id(group.organization_id)
        .await?
    {
        (org.name, org.display_name)
    } else {
        (String::new(), String::new())
    };

    Ok(GroupResponse {
        id: group.id.to_string(),
        name: group.name.clone(),
        display_name: group.display_name.clone(),
        organization_id: group.organization_id.to_string(),
        avatar_url: group.avatar_url.clone(),
        quota_allowance: group.quota_allowance,
        source: group.source.clone(),
        members,
        total_member_count,
        organization_name: org_name,
        organization_display_name: org_display_name,
    })
}

/// Build `GroupResponse` for a list of groups.
async fn build_group_responses(
    state: &AppState,
    groups: &[GroupRecord],
) -> Result<Vec<GroupResponse>, AppError> {
    let mut responses = Vec::with_capacity(groups.len());
    for group in groups {
        responses.push(build_group_response(state, group).await?);
    }
    Ok(responses)
}
