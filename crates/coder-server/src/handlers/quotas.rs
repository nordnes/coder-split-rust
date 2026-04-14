//! Workspace quota handlers.

use super::templates::resolve_organization;
use super::*;
use coder_core::api::WorkspaceQuota;

/// GET /api/v2/workspace-quota/{user} — deprecated workspace quota endpoint.
///
/// Looks up the default organization and delegates to the same quota logic
/// as the organization-scoped endpoint.
pub(crate) async fn get_workspace_quota_deprecated(
    State(state): State<AppState>,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(target_user) = resolve_user(&state, &user, &context.user).await? else {
        return Ok(resource_not_found_response());
    };

    // Look up the default organization.
    let orgs = state.store.list_organizations(Vec::new()).await?;
    let default_org = orgs.iter().find(|o| o.is_default);
    let Some(org) = default_org else {
        return Ok(not_found_response("Default organization not found."));
    };

    let quota = compute_workspace_quota(&state, target_user.id, org.id).await?;
    Ok((StatusCode::OK, Json(quota)).into_response())
}

/// GET /api/v2/organizations/{organization}/members/{user}/workspace-quota
pub(crate) async fn get_workspace_quota(
    State(state): State<AppState>,
    Path((organization, user)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(org) = resolve_organization(&state, &organization).await? else {
        return Ok(not_found_response("Organization not found."));
    };

    let Some(target_user) = resolve_user(&state, &user, &context.user).await? else {
        return Ok(resource_not_found_response());
    };

    let quota = compute_workspace_quota(&state, target_user.id, org.id).await?;
    Ok((StatusCode::OK, Json(quota)).into_response())
}

/// Computes workspace quota for a user in an organization.
///
/// If the `FeatureTemplateRBAC` entitlement is not licensed, returns
/// `budget: -1` (unlimited).  Otherwise queries the store for the
/// allowance and consumed values.
async fn compute_workspace_quota(
    _state: &AppState,
    _user_id: Uuid,
    _org_id: Uuid,
) -> Result<WorkspaceQuota, AppError> {
    // TODO: Once EntitlementSet is wired into AppState, check:
    //   state.entitlements.enabled(FeatureName::TemplateRbac)
    // If not licensed, return unlimited budget.
    // If licensed, query:
    //   get_quota_allowance_for_user(user_id, org_id)
    //   get_quota_consumed_for_user(user_id, org_id)
    //
    // For now, return unlimited since the entitlement service and quota
    // tables are not yet wired into AppState.
    Ok(WorkspaceQuota {
        credits_consumed: 0,
        budget: -1,
    })
}
