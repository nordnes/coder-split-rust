//! Organization and membership handlers.

use super::templates::resolve_organization;
use super::users::clamp_pagination_limit;
use super::*;

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
