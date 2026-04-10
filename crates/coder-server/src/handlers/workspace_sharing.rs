//! Workspace sharing settings handlers.

use super::templates::resolve_organization;
use super::*;
use coder_core::api::{UpdateWorkspaceSharingSettingsRequest, WorkspaceSharingSettings};

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

    // TODO: Read `shareable_workspace_owners` from the organization record once
    // the field is added to `OrganizationRecord` and `StoredOrganizationRow`.
    // For now, default to "everyone" (sharing enabled) unless globally disabled.
    let shareable_workspace_owners = if globally_disabled {
        "none".to_owned()
    } else {
        "everyone".to_owned()
    };
    let sharing_disabled = shareable_workspace_owners == "none";

    Ok((
        StatusCode::OK,
        Json(WorkspaceSharingSettings {
            sharing_globally_disabled: globally_disabled,
            sharing_disabled: sharing_disabled || globally_disabled,
            shareable_workspace_owners,
        }),
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

    // Validate shareable_workspace_owners if provided.
    if let Some(ref owners) = request.shareable_workspace_owners {
        let valid = ["none", "everyone", "service_accounts"];
        if !valid.contains(&owners.as_str()) {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error(
                    "Invalid shareable_workspace_owners value.",
                    format!("Must be one of: {}", valid.join(", ")),
                )),
            )
                .into_response());
        }
    }

    let globally_disabled = state.config.disable_workspace_sharing;

    // Determine the new value for shareable_workspace_owners.
    // `shareable_workspace_owners` takes precedence over the deprecated
    // `sharing_disabled` boolean.
    let new_owners = if let Some(owners) = request.shareable_workspace_owners {
        owners
    } else if let Some(disabled) = request.sharing_disabled {
        if disabled {
            "none".to_owned()
        } else {
            "everyone".to_owned()
        }
    } else {
        // No changes requested — return current state.
        let current_owners = if globally_disabled {
            "none".to_owned()
        } else {
            "everyone".to_owned()
        };
        let sharing_disabled = current_owners == "none";
        return Ok((
            StatusCode::OK,
            Json(WorkspaceSharingSettings {
                sharing_globally_disabled: globally_disabled,
                sharing_disabled: sharing_disabled || globally_disabled,
                shareable_workspace_owners: current_owners,
            }),
        )
            .into_response());
    };

    // TODO: Inside a transaction:
    //   1. Acquire advisory lock LockIDReconcileSystemRoles
    //   2. Update the organization's shareable_workspace_owners column
    //   3. Reconcile system roles
    //   4. If sharing disabled, delete workspace ACLs for this org
    //
    // The actual database update requires adding the shareable_workspace_owners
    // field to OrganizationRecord and the store layer.  Until that is wired,
    // return 501 to avoid a false audit trail and misleading clients.
    let _ = new_owners; // suppress unused-variable warning
    Ok((
        StatusCode::NOT_IMPLEMENTED,
        Json(ApiResponse::error(
            "Not implemented.",
            "Updating workspace sharing settings is not yet supported. \
             The persistence layer for shareable_workspace_owners has not been wired.",
        )),
    )
        .into_response())
}
