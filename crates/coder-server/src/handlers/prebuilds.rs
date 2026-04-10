//! Workspace prebuilds settings handlers.

use super::*;
use coder_core::api::PrebuildsSettings;

/// GET /api/v2/prebuilds/settings — returns the workspace prebuilds settings.
pub(crate) async fn get_prebuilds_settings(
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
            &Object::new(ResourceType::DeploymentConfig),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to view prebuilds settings.",
        ));
    }

    let settings = state.store.prebuilds_settings().await?;
    Ok((StatusCode::OK, Json(settings)).into_response())
}

/// PUT /api/v2/prebuilds/settings — updates the workspace prebuilds settings.
///
/// Returns 304 Not Modified if the submitted settings are identical to the
/// current value.
pub(crate) async fn put_prebuilds_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<PrebuildsSettings>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::DeploymentConfig),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update prebuilds settings.",
        ));
    }

    let Json(new_settings) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let changed = state.store.upsert_prebuilds_settings(&new_settings).await?;
    if !changed {
        return Ok(StatusCode::NOT_MODIFIED.into_response());
    }

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::PrebuildsSettings,
        Some(&context.user),
        None,
        "updated prebuilds settings",
    )
    .await;

    Ok((StatusCode::OK, Json(new_settings)).into_response())
}
