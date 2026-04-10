//! Organization and membership handlers.

use super::templates::resolve_organization;
use super::users::clamp_pagination_limit;
use super::*;
use coder_core::api::CustomRoleResponse;
use coder_core::{
    CreateOrganizationInput, CreateOrganizationRequest, CustomRoleRequest, UpdateOrganizationInput,
    UpdateOrganizationRequest,
};

#[derive(Debug, Default, Deserialize)]
pub(crate) struct MembersQuery {
    #[serde(default)]
    q: String,
    limit: Option<u32>,
    offset: Option<u32>,
}

pub(crate) async fn list_organizations(
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

pub(crate) async fn get_organization(
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

pub(crate) async fn list_organization_roles(
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

pub(crate) async fn list_organization_members(
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
            clamp_pagination_limit(query.limit.unwrap_or_default()),
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

pub(crate) async fn list_paginated_organization_members(
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
            clamp_pagination_limit(query.limit.unwrap_or_default()),
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

pub(crate) async fn get_organization_member(
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

pub(crate) async fn post_organization_member(
    State(state): State<AppState>,
    Path((organization, user)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can add members to this organization.
    let Some(org) = resolve_organization(&state, &organization).await? else {
        return Ok(not_found_response("Organization not found."));
    };
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Create,
            &Object::new(ResourceType::OrganizationMember).in_org(org.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to add members to this organization.",
        ));
    }

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

pub(crate) async fn delete_organization_member(
    State(state): State<AppState>,
    Path((organization, user)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can remove members from this organization.
    let Some(org) = resolve_organization(&state, &organization).await? else {
        return Ok(not_found_response("Organization not found."));
    };
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Delete,
            &Object::new(ResourceType::OrganizationMember).in_org(org.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to remove members from this organization.",
        ));
    }

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

pub(crate) async fn put_organization_member_roles(
    State(state): State<AppState>,
    Path((organization, user)): Path<(String, String)>,
    headers: HeaderMap,
    payload: Result<Json<UpdateRolesRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can assign roles in this organization.
    let Some(org) = resolve_organization(&state, &organization).await? else {
        return Ok(not_found_response("Organization not found."));
    };
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Assign,
            &Object::new(ResourceType::AssignOrgRole).in_org(org.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to assign roles in this organization.",
        ));
    }

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

// -----------------------------------------------------------------
// Organization CRUD
// -----------------------------------------------------------------

pub(crate) async fn post_organization(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<CreateOrganizationRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Create,
            &Object::new(ResourceType::Organization),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to create organizations.",
        ));
    }

    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let input = CreateOrganizationInput {
        name: request.name,
        display_name: request.display_name,
        description: request.description,
        icon: request.icon,
        actor_user_id: context.user.id,
    };

    let org = match state
        .identity
        .create_organization(&context.actor, &input)
        .await
    {
        Ok(org) => org,
        Err(error) => return handle_identity_error(error),
    };

    record_audit(
        &state,
        AuditAction::Create,
        ResourceKind::Organization,
        Some(&context.user),
        Some(org.id.to_string()),
        "created organization",
    )
    .await;

    Ok((StatusCode::CREATED, Json(OrganizationResponse::from(org))).into_response())
}

pub(crate) async fn patch_organization(
    State(state): State<AppState>,
    Path(organization): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<UpdateOrganizationRequest>, JsonRejection>,
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
            Action::Update,
            &Object::new(ResourceType::Organization).in_org(org.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update this organization.",
        ));
    }

    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let input = UpdateOrganizationInput {
        id: org.id,
        name: request.name.unwrap_or(org.name),
        display_name: request.display_name.unwrap_or(org.display_name),
        description: request.description.unwrap_or(org.description),
        icon: request.icon.unwrap_or(org.icon),
    };

    let updated_org = match state
        .identity
        .update_organization(&context.actor, &organization, &input)
        .await
    {
        Ok(org) => org,
        Err(error) => return handle_identity_error(error),
    };

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::Organization,
        Some(&context.user),
        Some(updated_org.id.to_string()),
        "updated organization",
    )
    .await;

    Ok((
        StatusCode::OK,
        Json(OrganizationResponse::from(updated_org)),
    )
        .into_response())
}

pub(crate) async fn delete_organization(
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
            Action::Delete,
            &Object::new(ResourceType::Organization).in_org(org.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to delete organizations.",
        ));
    }

    let org_id = match state
        .identity
        .delete_organization(&context.actor, &organization)
        .await
    {
        Ok(id) => id,
        Err(error) => return handle_identity_error(error),
    };

    record_audit(
        &state,
        AuditAction::Delete,
        ResourceKind::Organization,
        Some(&context.user),
        Some(org_id.to_string()),
        "deleted organization",
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

// -----------------------------------------------------------------
// Custom Roles CRUD
// -----------------------------------------------------------------

/// Reserved role names that cannot be used for custom roles.
const RESERVED_ROLE_NAMES: &[&str] = &[
    "owner",
    "member",
    "auditor",
    "template-admin",
    "user-admin",
    "organization-admin",
    "organization-member",
    "organization-auditor",
];

pub(crate) async fn post_org_role(
    State(state): State<AppState>,
    Path(organization): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<CustomRoleRequest>, JsonRejection>,
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
            &Object::new(ResourceType::AssignOrgRole).in_org(org.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to create custom roles in this organization.",
        ));
    }

    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    if RESERVED_ROLE_NAMES.contains(&request.name.to_ascii_lowercase().as_str()) {
        return Ok(validation_message_response(
            &format!(
                "Role name '{}' is reserved and cannot be used for custom roles.",
                request.name
            ),
            vec![],
        ));
    }

    // Check if a custom role with this name already exists — POST should not overwrite.
    if let Some(_existing) = state
        .identity
        .find_custom_role(&context.actor, &request.name, Some(org.id))
        .await
        .map_err(AppError::from)?
    {
        return Ok((
            StatusCode::CONFLICT,
            Json(ApiResponse::error(
                "A custom role with this name already exists in this organization.",
                "Use PUT to update an existing role.",
            )),
        )
            .into_response());
    }

    let input = coder_core::UpsertCustomRoleInput {
        name: request.name,
        display_name: request.display_name,
        organization_id: Some(org.id),
        site_permissions: serde_json::to_value(&request.site_permissions)
            .unwrap_or_default()
            .to_string(),
        org_permissions: serde_json::to_value(&request.organization_permissions)
            .unwrap_or_default()
            .to_string(),
        user_permissions: serde_json::to_value(&request.user_permissions)
            .unwrap_or_default()
            .to_string(),
    };

    let role = match state
        .identity
        .upsert_custom_role(&context.actor, &input)
        .await
    {
        Ok(role) => role,
        Err(error) => return handle_identity_error(error),
    };

    record_audit(
        &state,
        AuditAction::Create,
        ResourceKind::CustomRole,
        Some(&context.user),
        Some(role.name.clone()),
        "created custom role",
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(CustomRoleResponse {
            name: role.name,
            display_name: role.display_name,
            organization_id: role.organization_id.map(|id| id.to_string()),
        }),
    )
        .into_response())
}

pub(crate) async fn put_org_role(
    State(state): State<AppState>,
    Path(organization): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<CustomRoleRequest>, JsonRejection>,
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
            Action::Update,
            &Object::new(ResourceType::AssignOrgRole).in_org(org.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update custom roles in this organization.",
        ));
    }

    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    if RESERVED_ROLE_NAMES.contains(&request.name.to_ascii_lowercase().as_str()) {
        return Ok(validation_message_response(
            &format!(
                "Role name '{}' is reserved and cannot be used for custom roles.",
                request.name
            ),
            vec![],
        ));
    }

    let input = coder_core::UpsertCustomRoleInput {
        name: request.name,
        display_name: request.display_name,
        organization_id: Some(org.id),
        site_permissions: serde_json::to_value(&request.site_permissions)
            .unwrap_or_default()
            .to_string(),
        org_permissions: serde_json::to_value(&request.organization_permissions)
            .unwrap_or_default()
            .to_string(),
        user_permissions: serde_json::to_value(&request.user_permissions)
            .unwrap_or_default()
            .to_string(),
    };

    let role = match state
        .identity
        .upsert_custom_role(&context.actor, &input)
        .await
    {
        Ok(role) => role,
        Err(error) => return handle_identity_error(error),
    };

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::CustomRole,
        Some(&context.user),
        Some(role.name.clone()),
        "updated custom role",
    )
    .await;

    Ok((
        StatusCode::OK,
        Json(CustomRoleResponse {
            name: role.name,
            display_name: role.display_name,
            organization_id: role.organization_id.map(|id| id.to_string()),
        }),
    )
        .into_response())
}

pub(crate) async fn delete_org_role(
    State(state): State<AppState>,
    Path((organization, role_name)): Path<(String, String)>,
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
            Action::Delete,
            &Object::new(ResourceType::AssignOrgRole).in_org(org.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to delete custom roles in this organization.",
        ));
    }

    if RESERVED_ROLE_NAMES.contains(&role_name.to_ascii_lowercase().as_str()) {
        return Ok(validation_message_response(
            &format!(
                "Role '{}' is a built-in role and cannot be deleted.",
                role_name
            ),
            vec![],
        ));
    }

    let deleted = match state
        .identity
        .delete_custom_role(&context.actor, &role_name, Some(org.id))
        .await
    {
        Ok(deleted) => deleted,
        Err(error) => return handle_identity_error(error),
    };

    if !deleted {
        return Ok(not_found_response("Custom role not found."));
    }

    record_audit(
        &state,
        AuditAction::Delete,
        ResourceKind::CustomRole,
        Some(&context.user),
        Some(role_name),
        "deleted custom role",
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}
