//! Workspace quota handlers.

use super::templates::resolve_organization;
use super::*;
use coder_core::api::WorkspaceQuota;
use coder_license::FeatureName;

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
/// Ports `coder/enterprise/coderd/workspacequota.go` (`workspaceQuota`):
///
/// * If the `TemplateRBAC` entitlement is not enabled, the budget is
///   reported as `-1` (unlimited).  Credits consumed is still queried so
///   the UI can display usage even without the feature licensed — this
///   matches the Go behavior.
/// * When enabled, the budget is the sum of `quota_allowance` across all
///   groups the user is a member of in the organization (including the
///   implicit "Everyone" group), and credits consumed is the sum of
///   `daily_cost` of the latest build of each non-deleted workspace the
///   user owns in the organization.
async fn compute_workspace_quota(
    state: &AppState,
    user_id: Uuid,
    org_id: Uuid,
) -> Result<WorkspaceQuota, AppError> {
    let licensed = state.entitlements.enabled(FeatureName::TemplateRbac);
    let budget: i64 = if licensed {
        state
            .store
            .get_quota_allowance_for_user(user_id, org_id)
            .await?
    } else {
        -1
    };
    let consumed: i64 = state
        .store
        .get_quota_consumed_for_user(user_id, org_id)
        .await?;
    Ok(WorkspaceQuota {
        credits_consumed: saturating_i64_to_i32(consumed),
        budget: saturating_i64_to_i32(budget),
    })
}

/// Saturating conversion from `i64` (SQL `BIGINT`) to `i32` (the JSON
/// field type on `WorkspaceQuota`).  Matches Go's `int(...)` cast on
/// 64-bit platforms where the API model is also a plain `int`; clipping
/// instead of wrapping protects against overflow on 32-bit targets and
/// keeps the `-1` sentinel intact.
fn saturating_i64_to_i32(value: i64) -> i32 {
    value.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
}
