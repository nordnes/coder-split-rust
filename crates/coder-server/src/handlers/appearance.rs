//! Appearance configuration handlers (enterprise feature).

use super::*;
use coder_core::api::AppearanceConfig;

/// GET /api/v2/appearance — returns the deployment appearance configuration.
///
/// This endpoint is public (no authentication required) so that the login
/// page can display custom branding.
pub(crate) async fn get_appearance(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let config = state.store.appearance_config().await?;
    Ok((StatusCode::OK, Json(config)))
}

/// PUT /api/v2/appearance — updates the deployment appearance configuration.
///
/// Requires `Action::Update` on `ResourceType::DeploymentConfig`.
pub(crate) async fn put_appearance(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<AppearanceConfig>, JsonRejection>,
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
            "You are not authorized to update deployment appearance.",
        ));
    }

    let Json(new_config) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    // Validate: service banner message must be non-empty when enabled.
    if new_config.service_banner.enabled && new_config.service_banner.message.trim().is_empty() {
        return Ok(validation_message_response(
            "Request body has invalid fields.",
            vec![ValidationError {
                field: "service_banner.message".to_owned(),
                detail: "must be non-empty when banner is enabled".to_owned(),
            }],
        ));
    }

    let changed = state.store.upsert_appearance_config(&new_config).await?;
    if !changed {
        return Ok(StatusCode::NOT_MODIFIED.into_response());
    }

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::HealthSettings,
        Some(&context.user),
        None,
        "updated appearance configuration",
    )
    .await;

    Ok((StatusCode::OK, Json(new_config)).into_response())
}
