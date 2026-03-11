//! External auth CRUD, device flow, and callback handlers.

use super::*;

#[derive(Debug, Default, Deserialize)]
pub(crate) struct ExternalAuthCallbackQuery {
    code: Option<String>,
    state: Option<String>,
}

pub(crate) async fn list_external_auths(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    Ok(Json(
        state
            .external_auth
            .list(&state.config.external_auth_providers, context.user.id)
            .await?,
    )
    .into_response())
}

pub(crate) async fn get_external_auth_by_id(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(provider): Path<String>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Some(config) = find_external_auth_provider(&state, &provider) else {
        return Ok(resource_not_found_response());
    };
    let response = state
        .external_auth
        .get(
            &state.config.external_auth_providers,
            context.user.id,
            &provider,
        )
        .await?;
    let Some(response) = response else {
        debug_assert!(config.id.eq_ignore_ascii_case(&provider));
        return Ok(resource_not_found_response());
    };

    Ok(Json(response).into_response())
}

pub(crate) async fn delete_external_auth_by_id(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(provider): Path<String>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Some(response) = state
        .external_auth
        .delete(
            &state.config.external_auth_providers,
            context.user.id,
            &provider,
        )
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    record_audit(
        &state,
        AuditAction::Delete,
        ResourceKind::ExternalAuth,
        Some(&context.user),
        Some(provider.clone()),
        "deleted external auth link",
    )
    .await;

    Ok((StatusCode::OK, Json(response)).into_response())
}

pub(crate) async fn get_external_auth_device_by_id(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(provider): Path<String>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Some(config) = find_external_auth_provider(&state, &provider) else {
        return Ok(resource_not_found_response());
    };
    if !config.device {
        return Ok(external_auth_device_flow_unsupported_response());
    }

    state
        .external_auth
        .authorize_device(config)
        .await
        .map(|device| (StatusCode::OK, Json(device)).into_response())
        .or_else(|error| handle_external_auth_error("Failed to authorize device.", error))
}

pub(crate) async fn post_external_auth_device_exchange(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(provider): Path<String>,
    payload: Result<Json<ExternalAuthDeviceExchangeRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Some(config) = find_external_auth_provider(&state, &provider) else {
        return Ok(resource_not_found_response());
    };
    if !config.device {
        return Ok(external_auth_device_flow_unsupported_response());
    }
    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    if request.device_code.trim().is_empty() {
        return Ok(validation_message_response(
            "Request body has invalid fields.",
            vec![ValidationError {
                field: "device_code".to_owned(),
                detail: "Missing value, this cannot be empty".to_owned(),
            }],
        ));
    }

    if let Err(error) = state
        .external_auth
        .exchange_device(config, context.user.id, &request)
        .await
    {
        return handle_external_auth_error("Failed to exchange device code.", error);
    }

    Ok(StatusCode::NO_CONTENT.into_response())
}

pub(crate) async fn get_external_auth_callback_by_id(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(provider): Path<String>,
    Query(query): Query<ExternalAuthCallbackQuery>,
) -> Result<Response, AppError> {
    let Some(config) = find_external_auth_provider(&state, &provider) else {
        return Ok(resource_not_found_response());
    };
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(redirect_to_login_response(
            &uri,
            "Missing or invalid session token.",
        ));
    };
    let Some(state_value) = query.state.filter(|value| !value.trim().is_empty()) else {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::ok("State must be provided.")),
        )
            .into_response());
    };
    let Some(state_cookie) = cookie_from_headers(&headers, OAUTH2_STATE_COOKIE) else {
        return Ok(unauthorized_response(format!(
            "Cookie {OAUTH2_STATE_COOKIE:?} must be provided."
        )));
    };
    if state_cookie != state_value {
        return Ok(unauthorized_response("State mismatched."));
    }
    let Some(code) = query.code.filter(|value| !value.trim().is_empty()) else {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::ok("Code must be provided.")),
        )
            .into_response());
    };

    if let Err(error) = state
        .external_auth
        .exchange_callback(config, context.user.id, &code)
        .await
    {
        return handle_external_auth_error("Failed exchanging OAuth code.", error);
    }

    let redirect = cookie_from_headers(&headers, OAUTH2_REDIRECT_COOKIE)
        .map(|value| sanitize_redirect_uri(&value))
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| format!("/external-auth/{provider}?redirected=true"));

    let mut response = StatusCode::TEMPORARY_REDIRECT.into_response();
    response.headers_mut().insert(
        LOCATION,
        HeaderValue::from_str(&redirect).unwrap_or_else(|_| HeaderValue::from_static("/")),
    );
    Ok(response)
}
