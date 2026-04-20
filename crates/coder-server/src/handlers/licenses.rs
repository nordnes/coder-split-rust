//! License and entitlements HTTP handlers.

use base64::Engine as _;

use super::*;
use coder_core::LicensorTrialRequest;
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

/// Request payload for `POST /api/v2/licenses/trial`.
///
/// Mirrors Go's `codersdk.LicensorTrialRequest` (which is identical to the
/// `trial_info` block on `POST /api/v2/users/first`, plus top-level
/// `email`/`source`). The server forwards the payload to the configured
/// trial-signup licensor and returns the licensor's response body verbatim.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(crate) struct PostLicenseTrialRequest {
    #[serde(default)]
    pub(crate) email: String,
    #[serde(default)]
    pub(crate) source: String,
    #[serde(default)]
    pub(crate) first_name: String,
    #[serde(default)]
    pub(crate) last_name: String,
    #[serde(default)]
    pub(crate) phone_number: String,
    #[serde(default)]
    pub(crate) job_title: String,
    #[serde(default)]
    pub(crate) company_name: String,
    #[serde(default)]
    pub(crate) country: String,
    #[serde(default)]
    pub(crate) developers: String,
}

/// POST /api/v2/licenses/trial — forward a trial-signup request to the
/// configured trial licensor service.
///
/// Mirrors Go's `PostLicenseTrial` handler: the request body is augmented
/// with the deployment ID and POSTed to the URL in `CODER_TRIAL_SIGNUP_URL`.
/// The licensor's response body is then returned to the caller. When no
/// trial-signup URL is configured, the endpoint returns 503 so operators know
/// to configure `CODER_TRIAL_SIGNUP_URL` (or remove the UI surface pointing
/// at this endpoint).
pub(crate) async fn post_license_trial(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<PostLicenseTrialRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Json(request) = body.map_err(|e| AppError::BadRequest {
        message: format!("Invalid request body: {e}"),
        detail: None,
        validations: Vec::new(),
    })?;

    if state.config.trial_signup_url.is_empty() {
        return Ok((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiResponse::error(
                "Trial signup is not configured on this deployment.",
                "Set CODER_TRIAL_SIGNUP_URL to the URL of a trial licensor service to enable this endpoint.",
            )),
        )
            .into_response());
    }

    let payload = LicensorTrialRequest {
        deployment_id: state.deployment_id.to_string(),
        email: request.email,
        source: if request.source.is_empty() {
            "api".to_owned()
        } else {
            request.source
        },
        first_name: request.first_name,
        last_name: request.last_name,
        phone_number: request.phone_number,
        job_title: request.job_title,
        company_name: request.company_name,
        country: request.country,
        developers: request.developers,
    };

    let resp = match state
        .http_client
        .post(&state.config.trial_signup_url)
        .json(&payload)
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(error) => {
            return Ok((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error(
                    "Failed to generate trial",
                    error.to_string(),
                )),
            )
                .into_response());
        }
    };

    let status = resp.status();
    let body_text = resp.text().await.unwrap_or_default();

    if !status.is_success() {
        // Licensor typically responds with `{"error":"message"}` on failure.
        let detail = serde_json::from_str::<Value>(&body_text)
            .ok()
            .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(String::from))
            .unwrap_or(body_text);
        return Ok((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::error("Failed to generate trial", detail)),
        )
            .into_response());
    }

    // Forward the upstream success body verbatim. If it parses as JSON we
    // return it as JSON; otherwise we fall through to an empty 200.
    if let Ok(value) = serde_json::from_str::<Value>(&body_text) {
        return Ok((StatusCode::OK, Json(value)).into_response());
    }
    Ok((
        StatusCode::OK,
        Json(ApiResponse::ok("Trial request submitted.")),
    )
        .into_response())
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    /// `PostLicenseTrialRequest` must deserialize Go-style snake_case payloads
    /// sent by the dashboard, populate defaults for optional fields, and tolerate
    /// the same field ordering the Go handler accepts.
    #[test]
    fn post_license_trial_request_deserializes_snake_case() {
        let json = serde_json::json!({
            "email": "dev@example.com",
            "source": "dashboard",
            "first_name": "Dev",
            "last_name": "Example",
            "phone_number": "+1-555-0199",
            "job_title": "SRE",
            "company_name": "Example Inc.",
            "country": "US",
            "developers": "1-10"
        });
        let req: PostLicenseTrialRequest =
            serde_json::from_value(json).expect("must parse snake_case body");
        assert_eq!(req.email, "dev@example.com");
        assert_eq!(req.source, "dashboard");
        assert_eq!(req.first_name, "Dev");
        assert_eq!(req.last_name, "Example");
        assert_eq!(req.phone_number, "+1-555-0199");
        assert_eq!(req.job_title, "SRE");
        assert_eq!(req.company_name, "Example Inc.");
        assert_eq!(req.country, "US");
        assert_eq!(req.developers, "1-10");
    }

    /// All fields on `PostLicenseTrialRequest` must be optional so an empty
    /// body round-trips cleanly (Go's handler similarly applies defaults).
    #[test]
    fn post_license_trial_request_defaults_missing_fields() {
        let req: PostLicenseTrialRequest =
            serde_json::from_value(serde_json::json!({})).expect("empty body must parse");
        assert!(req.email.is_empty());
        assert!(req.source.is_empty());
        assert!(req.first_name.is_empty());
        assert!(req.developers.is_empty());
    }

    /// `LicensorTrialRequest` is the wire payload forwarded to the licensor;
    /// verify we serialize every field the Go licensor expects using the
    /// snake_case names it reads.
    #[test]
    fn licensor_trial_request_serializes_all_fields() {
        let payload = LicensorTrialRequest {
            deployment_id: "deploy-abc".to_owned(),
            email: "dev@example.com".to_owned(),
            source: "dashboard".to_owned(),
            first_name: "Dev".to_owned(),
            last_name: "Example".to_owned(),
            phone_number: "+1-555-0199".to_owned(),
            job_title: "SRE".to_owned(),
            company_name: "Example Inc.".to_owned(),
            country: "US".to_owned(),
            developers: "1-10".to_owned(),
        };
        let value = serde_json::to_value(&payload).expect("payload must serialize");
        for key in [
            "deployment_id",
            "email",
            "source",
            "first_name",
            "last_name",
            "phone_number",
            "job_title",
            "company_name",
            "country",
            "developers",
        ] {
            assert!(
                value.get(key).is_some(),
                "licensor payload must include `{key}`"
            );
        }
    }
}
