//! Workspace sharing settings handlers.
//!
//! Ported from `coder/enterprise/coderd/workspacesharing.go`.

use super::templates::resolve_organization;
use super::*;
use coder_core::api::{UpdateWorkspaceSharingSettingsRequest, WorkspaceSharingSettings};

/// Accepted values for the Rust-layer `shareable_workspace_owners` enum.
///
/// The Go upstream (`coder/enterprise/coderd/workspacesharing.go`) persists
/// only a boolean `workspace_sharing_disabled`; it has no notion of this
/// enum. We therefore accept `"none"` ↔ `disabled=true` and `"everyone"` ↔
/// `disabled=false`, and reject `"service_accounts"` at the API boundary
/// until upstream grows storage for the full enum. Silently coercing
/// `"service_accounts"` to `"everyone"` would swallow the caller's intent,
/// so it is safer to 400.
const SUPPORTED_SHAREABLE_WORKSPACE_OWNERS: &[&str] = &["none", "everyone"];

/// Translates an accepted `shareable_workspace_owners` string into the
/// persisted `workspace_sharing_disabled` boolean.
///
/// Callers must validate the input against `SUPPORTED_SHAREABLE_WORKSPACE_OWNERS`
/// first; unknown values fall through to `false` here.
fn owners_to_disabled(owners: &str) -> bool {
    owners == "none"
}

/// Renders the settings response for the given organization-level value.
///
/// Globally disabled sharing is OR-ed with the per-org flag so clients see the
/// effective state.
fn render_settings(
    globally_disabled: bool,
    organization_disabled: bool,
) -> WorkspaceSharingSettings {
    let effective_disabled = globally_disabled || organization_disabled;
    let shareable_workspace_owners = if effective_disabled {
        "none".to_owned()
    } else {
        "everyone".to_owned()
    };
    WorkspaceSharingSettings {
        sharing_globally_disabled: globally_disabled,
        sharing_disabled: effective_disabled,
        shareable_workspace_owners,
    }
}

/// GET /api/v2/organizations/{organization}/settings/workspace-sharing
pub(crate) async fn get_workspace_sharing_settings(
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

    // RBAC: ActionRead on the organization.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::Organization).in_org(org.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to view workspace sharing settings.",
        ));
    }

    let globally_disabled = state.config.disable_workspace_sharing;
    let organization_disabled = state
        .store
        .get_organization_sharing_settings(org.id)
        .await?
        .unwrap_or(false);

    Ok((
        StatusCode::OK,
        Json(render_settings(globally_disabled, organization_disabled)),
    )
        .into_response())
}

/// PATCH /api/v2/organizations/{organization}/settings/workspace-sharing
pub(crate) async fn patch_workspace_sharing_settings(
    State(state): State<AppState>,
    Path(organization): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<UpdateWorkspaceSharingSettingsRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(org) = resolve_organization(&state, &organization).await? else {
        return Ok(not_found_response("Organization not found."));
    };

    // RBAC: ActionUpdate on the organization.
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
            "You are not authorized to update workspace sharing settings.",
        ));
    }

    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    // Validate shareable_workspace_owners if provided. Go upstream only stores
    // a boolean, so we only accept the two values that map cleanly onto it.
    // `service_accounts` and any other enum values are rejected with 400 until
    // the storage column grows support for them.
    if let Some(ref owners) = request.shareable_workspace_owners
        && !SUPPORTED_SHAREABLE_WORKSPACE_OWNERS.contains(&owners.as_str())
    {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "unsupported shareable_workspace_owners value",
                format!(
                    "Must be one of: {}",
                    SUPPORTED_SHAREABLE_WORKSPACE_OWNERS.join(", ")
                ),
            )),
        )
            .into_response());
    }

    let globally_disabled = state.config.disable_workspace_sharing;

    // Determine the new value. `shareable_workspace_owners` takes precedence
    // over the deprecated `sharing_disabled` boolean. When neither is present
    // we simply return the current settings without any write.
    let new_disabled: Option<bool> = if let Some(owners) = request.shareable_workspace_owners {
        Some(owners_to_disabled(&owners))
    } else {
        request.sharing_disabled
    };

    let Some(new_disabled) = new_disabled else {
        let organization_disabled = state
            .store
            .get_organization_sharing_settings(org.id)
            .await?
            .unwrap_or(false);
        return Ok((
            StatusCode::OK,
            Json(render_settings(globally_disabled, organization_disabled)),
        )
            .into_response());
    };

    let persisted = state
        .store
        .update_organization_sharing_settings(org.id, new_disabled)
        .await?;

    let Some(organization_disabled) = persisted else {
        return Ok(not_found_response("Organization not found."));
    };

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::Organization,
        Some(&context.user),
        Some(org.id.to_string()),
        if organization_disabled {
            "disabled workspace sharing for organization"
        } else {
            "enabled workspace sharing for organization"
        },
    )
    .await;

    Ok((
        StatusCode::OK,
        Json(render_settings(globally_disabled, organization_disabled)),
    )
        .into_response())
}
