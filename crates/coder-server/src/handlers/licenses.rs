//! License and entitlements HTTP handlers.

use base64::Engine as _;

use super::*;
use coder_core::api::{AddLicenseRequest, LicenseResponse};
use coder_license::{EntitlementSet, FeatureName};

/// Converts a [`coder_core::LicenseRecord`] into a [`LicenseResponse`],
/// stripping the raw JWT from the response for security.
fn license_to_response(record: &coder_core::LicenseRecord) -> LicenseResponse {
    LicenseResponse {
        id: record.id,
        uuid: record.uuid,
        uploaded_at: record.uploaded_at,
        claims: record.claims.clone(),
    }
}

/// GET /api/v2/licenses — list all active licenses.
pub(crate) async fn list_licenses(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let records = state.store.list_licenses().await?;
    let response: Vec<LicenseResponse> = records.iter().map(license_to_response).collect();

    Ok((StatusCode::OK, Json(response)).into_response())
}

/// POST /api/v2/licenses — upload a new license JWT.
pub(crate) async fn post_license(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<AddLicenseRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Json(request) = body.map_err(|e| AppError::BadRequest {
        message: format!("Invalid request body: {e}"),
        detail: None,
        validations: Vec::new(),
    })?;

    if request.license.is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "License JWT must not be empty.",
                "The license field is required.",
            )),
        )
            .into_response());
    }

    // Decode the JWT payload without signature verification to extract the
    // claims for storage.  Full cryptographic validation is performed by the
    // `LicenseService` when entitlements are refreshed.
    let claims_value: Value = {
        let parts: Vec<&str> = request.license.split('.').collect();
        if parts.len() != 3 {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error(
                    "Invalid license.",
                    "License JWT must have three dot-separated parts.",
                )),
            )
                .into_response());
        }
        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|_| AppError::BadRequest {
                message: "Invalid license.".to_owned(),
                detail: Some("Failed to base64-decode JWT payload.".to_owned()),
                validations: Vec::new(),
            })?;
        serde_json::from_slice(&payload_bytes).map_err(|e| AppError::BadRequest {
            message: "Invalid license.".to_owned(),
            detail: Some(format!("Failed to parse JWT claims: {e}")),
            validations: Vec::new(),
        })?
    };

    let record = state
        .store
        .insert_license(&request.license, &claims_value)
        .await?;

    Ok((StatusCode::CREATED, Json(license_to_response(&record))).into_response())
}

/// DELETE /api/v2/licenses/{id} — remove a license by ID.
pub(crate) async fn delete_license_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(license_id): Path<i32>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let deleted = state.store.delete_license(license_id).await?;
    if !deleted {
        return Ok(resource_not_found_response());
    }

    Ok(StatusCode::OK.into_response())
}

/// GET /api/v2/entitlements — return the current entitlements snapshot.
pub(crate) async fn get_entitlements(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let entitlements = state.entitlements.snapshot();

    Ok((StatusCode::OK, Json(entitlements)).into_response())
}

// ---------------------------------------------------------------------------
// Enterprise feature guard
// ---------------------------------------------------------------------------

/// Returns an error response when the requested enterprise feature is not
/// entitled.  Callers can use this in handlers that gate on a specific
/// [`FeatureName`].
///
/// # Example
///
/// ```ignore
/// if !entitlements.is_entitled(&feature_name) {
///     return Ok(require_enterprise_feature(&feature_name));
/// }
/// ```
pub(crate) fn require_enterprise_feature(feature: &FeatureName) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(ApiResponse::error(
            format!(
                "Enterprise feature \"{}\" is not entitled. Contact sales for a license.",
                feature.as_str(),
            ),
            "Your license does not include this feature.",
        )),
    )
        .into_response()
}

/// Checks whether `feature` is entitled in the given [`EntitlementSet`].
///
/// Returns `true` when the feature is available (either fully entitled or in
/// a grace period).  Returns `false` otherwise.
pub(crate) fn is_feature_entitled(entitlements: &EntitlementSet, feature: FeatureName) -> bool {
    entitlements.is_entitled(feature)
}

/// POST /api/v2/licenses/refresh-entitlements — triggers a manual refresh
/// of enterprise feature entitlements.
pub(crate) async fn post_refresh_entitlements(
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
            Action::Update,
            &Object::new(ResourceType::License),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to refresh license entitlements.",
        ));
    }

    // Publish a pubsub event so that replicas that *do* have a full
    // LicenseService can pick up the request and recompute entitlements.
    if let Err(e) = state
        .pubsub
        .publish("entitlements_refreshed", b"refresh")
        .await
    {
        tracing::warn!("failed to publish entitlements refresh event: {e}");
    }

    Ok((
        StatusCode::OK,
        Json(ApiResponse::ok("Entitlements refresh requested.")),
    )
        .into_response())
}
