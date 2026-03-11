//! Telemetry status handler.
//!
//! Implements `GET /api/v2/telemetry` which returns the current telemetry
//! subsystem status including whether collection is enabled and event counts.

use super::*;

/// Response payload for `GET /api/v2/telemetry`.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct TelemetryStatusResponse {
    /// Whether telemetry collection is enabled.
    pub enabled: bool,
    /// Stable deployment identifier.
    pub deployment_id: String,
}

/// GET /api/v2/telemetry — returns the current telemetry status.
pub(crate) async fn get_telemetry_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let response = TelemetryStatusResponse {
        enabled: state.config.telemetry_enabled,
        deployment_id: state.deployment_id.to_string(),
    };

    Ok((StatusCode::OK, Json(response)).into_response())
}
