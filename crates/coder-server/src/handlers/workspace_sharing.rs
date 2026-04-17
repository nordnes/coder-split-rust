//! Workspace sharing settings handlers.
//!
//! Ported from `coder/enterprise/coderd/workspacesharing.go`.
//!
//! Storage note: the Rust layer intentionally deviates from Go's current
//! schema here. Go upstream persists only a boolean `workspace_sharing_disabled`
//! on the organization row, which cannot round-trip the full
//! `shareable_workspace_owners` enum (`none` / `everyone` / `service_accounts`).
//! We added a dedicated `workspace_sharing_mode TEXT` column so
//! `"service_accounts"` is preserved end-to-end. The legacy boolean column is
//! kept in lock-step for backward compatibility with any reader still bound to
//! it; it will be dropped in a follow-up migration once every reader consumes
//! the new column.

use super::templates::resolve_organization;
use super::*;
use coder_core::WorkspaceSharingMode;
use coder_core::api::{UpdateWorkspaceSharingSettingsRequest, WorkspaceSharingSettings};

/// Renders the settings response for the given organization-level mode.
///
/// Globally disabled sharing is OR-ed with the per-org mode so clients see the
/// effective state: when deployment-wide sharing is off we always advertise
/// `"none"` regardless of the persisted mode.
fn render_settings(
    globally_disabled: bool,
    organization_mode: WorkspaceSharingMode,
) -> WorkspaceSharingSettings {
    let effective_mode = if globally_disabled {
        WorkspaceSharingMode::None
    } else {
        organization_mode
    };
    WorkspaceSharingSettings {
        sharing_globally_disabled: globally_disabled,
        sharing_disabled: effective_mode.disables_sharing(),
        shareable_workspace_owners: effective_mode.as_str().to_owned(),
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
    let organization_mode = state
        .store
        .get_organization_sharing_settings(org.id)
        .await?
        .unwrap_or_default();

    Ok((
        StatusCode::OK,
        Json(render_settings(globally_disabled, organization_mode)),
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

    let globally_disabled = state.config.disable_workspace_sharing;

    // Determine the new mode. `shareable_workspace_owners` takes precedence
    // over the deprecated `sharing_disabled` boolean; the boolean is accepted
    // for backward compatibility and maps `true → None`, `false → Everyone`
    // (it has no way to express `service_accounts`). When neither is present
    // we return the current settings unchanged.
    let new_mode: Option<WorkspaceSharingMode> = match request.shareable_workspace_owners {
        Some(owners) => match owners.parse::<WorkspaceSharingMode>() {
            Ok(mode) => Some(mode),
            Err(_) => {
                return Ok((
                    StatusCode::BAD_REQUEST,
                    Json(ApiResponse::error(
                        "unsupported shareable_workspace_owners value",
                        "Must be one of: none, everyone, service_accounts",
                    )),
                )
                    .into_response());
            }
        },
        None => request.sharing_disabled.map(|disabled| {
            if disabled {
                WorkspaceSharingMode::None
            } else {
                WorkspaceSharingMode::Everyone
            }
        }),
    };

    let Some(new_mode) = new_mode else {
        let organization_mode = state
            .store
            .get_organization_sharing_settings(org.id)
            .await?
            .unwrap_or_default();
        return Ok((
            StatusCode::OK,
            Json(render_settings(globally_disabled, organization_mode)),
        )
            .into_response());
    };

    let persisted = state
        .store
        .update_organization_sharing_settings(org.id, new_mode)
        .await?;

    let Some(organization_mode) = persisted else {
        return Ok(not_found_response("Organization not found."));
    };

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::Organization,
        Some(&context.user),
        Some(org.id.to_string()),
        match organization_mode {
            WorkspaceSharingMode::None => "disabled workspace sharing for organization",
            WorkspaceSharingMode::Everyone => {
                "enabled workspace sharing for organization (everyone)"
            }
            WorkspaceSharingMode::ServiceAccounts => {
                "enabled workspace sharing for organization (service accounts)"
            }
        },
    )
    .await;

    Ok((
        StatusCode::OK,
        Json(render_settings(globally_disabled, organization_mode)),
    )
        .into_response())
}
