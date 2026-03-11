//! Health check and health settings handlers.

use super::*;

#[derive(Debug, Default, Deserialize)]
pub(crate) struct DebugHealthQuery {
    format: Option<String>,
    #[serde(default)]
    force: bool,
}

pub(crate) async fn healthz(State(state): State<AppState>) -> Result<impl IntoResponse, AppError> {
    state.store.ping().await?;
    Ok((StatusCode::OK, "OK"))
}

pub(crate) async fn debug_health(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<DebugHealthQuery>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !can_view_operational_data(&context.actor) {
        return Ok(forbidden_response(
            "You are not authorized to view deployment health.",
        ));
    }

    let settings = state.store.health_settings().await?;
    let report = state
        .health
        .report(&state.config, &state.build_metadata, query.force)
        .await?;
    let report = apply_dismissed_health_settings(report, &settings);

    match query.format.as_deref() {
        None | Some("json") => Ok((StatusCode::OK, Json(report)).into_response()),
        Some("text") => Ok((
            StatusCode::OK,
            format!(
                "time: {}\nhealthy: {}\nderp: {}\naccess_url: {}\nwebsocket: {}\ndatabase: {}\n",
                report
                    .time
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
                report.healthy,
                report.derp.healthy,
                report.access_url.healthy,
                report.websocket.healthy,
                report.database.healthy,
            ),
        )
            .into_response()),
        Some(other) => Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                format!("Invalid format option {other:?}."),
                "Supported formats are: json, text.",
            )),
        )
            .into_response()),
    }
}

pub(crate) async fn get_health_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !can_view_operational_data(&context.actor) {
        return Ok(forbidden_response(
            "You are not authorized to view health settings.",
        ));
    }

    Ok((StatusCode::OK, Json(state.store.health_settings().await?)).into_response())
}

pub(crate) async fn put_health_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<HealthSettings>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can update deployment configuration.
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
            "You are not authorized to update health settings.",
        ));
    }

    let Json(settings) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    let invalid = settings
        .dismissed_healthchecks
        .iter()
        .filter(|section| !VALID_HEALTH_SECTIONS.contains(&section.as_str()))
        .map(|section| ValidationError {
            field: "dismissed_healthchecks".to_owned(),
            detail: format!("unsupported health section: {section}"),
        })
        .collect::<Vec<_>>();
    if !invalid.is_empty() {
        return Ok(validation_message_response(
            "Request body has invalid fields.",
            invalid,
        ));
    }

    let changed = state.store.upsert_health_settings(&settings).await?;
    if !changed {
        return Ok(StatusCode::NO_CONTENT.into_response());
    }

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::HealthSettings,
        Some(&context.user),
        None,
        "updated health settings",
    )
    .await;

    Ok((StatusCode::OK, Json(settings)).into_response())
}
