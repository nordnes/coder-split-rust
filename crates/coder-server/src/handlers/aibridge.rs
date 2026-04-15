//! AI Bridge HTTP handlers (enterprise — gated on `AiBridge`).

use super::*;

/// Default page size for listing interceptions.
const DEFAULT_INTERCEPTIONS_LIMIT: i32 = 100;
/// Maximum page size for listing interceptions.
const MAX_INTERCEPTIONS_LIMIT: i32 = 1000;

/// Default page size for listing models.
const DEFAULT_MODELS_LIMIT: i32 = 100;
/// Maximum page size for listing models.
const MAX_MODELS_LIMIT: i32 = 1000;

/// `GET /api/v2/aibridge/interceptions` — list AI Bridge interceptions.
pub(crate) async fn list_aibridge_interceptions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(mut filter): Query<coder_core::api::AIBridgeInterceptionsFilter>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // Cursor and offset pagination are mutually exclusive (Go line 91-97).
    if filter.after_id.is_some() && filter.offset.unwrap_or(0) != 0 {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                message: "Query parameters have invalid values.".to_owned(),
                detail: Some(
                    "Cannot use both after_id and offset pagination in the same request."
                        .to_owned(),
                ),
                validations: Vec::new(),
            }),
        )
            .into_response());
    }

    // Apply pagination defaults and bounds.
    let limit = filter.limit.unwrap_or(DEFAULT_INTERCEPTIONS_LIMIT);
    if limit < 1 || limit > MAX_INTERCEPTIONS_LIMIT {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                message: "Invalid pagination limit value.".to_owned(),
                detail: Some(format!(
                    "Pagination limit must be in range (0, {MAX_INTERCEPTIONS_LIMIT}]"
                )),
                validations: Vec::new(),
            }),
        )
            .into_response());
    }
    filter.limit = Some(limit);

    let response = state.store.list_aibridge_interceptions(filter).await?;

    Ok((StatusCode::OK, Json(response)).into_response())
}

/// `GET /api/v2/aibridge/models` — list distinct AI Bridge model names.
pub(crate) async fn list_aibridge_models(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(mut filter): Query<coder_core::api::AIBridgeModelsFilter>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // Apply pagination defaults and bounds.
    let limit = filter.limit.unwrap_or(DEFAULT_MODELS_LIMIT);
    if limit < 1 || limit > MAX_MODELS_LIMIT {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                message: "Invalid pagination limit value.".to_owned(),
                detail: Some(format!(
                    "Pagination limit must be in range (0, {MAX_MODELS_LIMIT}]"
                )),
                validations: Vec::new(),
            }),
        )
            .into_response());
    }
    filter.limit = Some(limit);

    let models = state.store.list_aibridge_models(filter).await?;

    Ok((StatusCode::OK, Json(models)).into_response())
}
