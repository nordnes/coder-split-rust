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
        ResourceKind::AppearanceConfig,
        Some(&context.user),
        None,
        "updated appearance configuration",
    )
    .await;

    Ok((StatusCode::OK, Json(new_config)).into_response())
}

/// GET /api/v2/appearance/logo — serve the configured deployment logo.
///
/// The stored `AppearanceConfig.logo_url` is the canonical branding asset
/// location. When set, this endpoint issues a 302 redirect so browsers and
/// other HTTP clients can load the asset via a stable URL under the Coder
/// API surface (e.g. for dashboards that expect a relative path). When the
/// logo URL is unset, the endpoint returns 404 so callers can distinguish
/// "no custom branding configured" from "branding is configured but the
/// target URL failed".
pub(crate) async fn get_appearance_logo(
    State(state): State<AppState>,
) -> Result<Response, AppError> {
    serve_branding_asset(&state, BrandingAsset::Logo).await
}

/// GET /api/v2/appearance/favicon — serve the configured deployment favicon.
///
/// Same semantics as [`get_appearance_logo`]. The `AppearanceConfig`
/// struct only exposes `logo_url` today, but the favicon endpoint is
/// wired so the UI can use a consistent API surface when a favicon field
/// is added in the future; until then the handler returns 404.
pub(crate) async fn get_appearance_favicon(
    State(state): State<AppState>,
) -> Result<Response, AppError> {
    serve_branding_asset(&state, BrandingAsset::Favicon).await
}

/// Which branding asset to serve.
#[derive(Debug, Clone, Copy)]
enum BrandingAsset {
    Logo,
    Favicon,
}

async fn serve_branding_asset(
    state: &AppState,
    asset: BrandingAsset,
) -> Result<Response, AppError> {
    let config = state.store.appearance_config().await?;
    let target = match asset {
        BrandingAsset::Logo => config.logo_url.as_str(),
        // `AppearanceConfig` has no favicon URL yet; 404 until it does.
        BrandingAsset::Favicon => "",
    };
    if target.is_empty() {
        return Ok(resource_not_found_response());
    }

    let header_value = match HeaderValue::from_str(target) {
        Ok(v) => v,
        Err(_) => return Ok(resource_not_found_response()),
    };
    let cache_control = HeaderValue::from_static("public, max-age=300, stale-while-revalidate=60");
    Ok((
        StatusCode::FOUND,
        [
            (LOCATION, header_value),
            (axum::http::header::CACHE_CONTROL, cache_control),
        ],
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Method, Request, Response};
    use coder_core::api::AppearanceConfig;
    use tower::ServiceExt;

    async fn call(
        app: axum::Router,
        request: Request<Body>,
    ) -> Result<Response<Body>, Box<dyn std::error::Error>> {
        let response = match app.oneshot(request).await {
            Ok(response) => response,
            Err(never) => match never {},
        };
        Ok(response)
    }

    fn branding_router(state: AppState) -> axum::Router {
        axum::Router::new()
            .route(
                "/api/v2/appearance/logo",
                axum::routing::get(get_appearance_logo),
            )
            .route(
                "/api/v2/appearance/favicon",
                axum::routing::get(get_appearance_favicon),
            )
            .with_state(state)
    }

    fn get(uri: &str) -> Result<Request<Body>, http::Error> {
        Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Body::empty())
    }

    #[tokio::test]
    async fn appearance_logo_redirects_to_configured_url() -> Result<(), Box<dyn std::error::Error>>
    {
        let (state, store) = crate::app::tests::test_state_with_store(true)?;
        // Seed a logo URL via the public upsert path (mirrors PUT /appearance).
        let cfg = AppearanceConfig {
            logo_url: "https://example.com/logo.svg".to_owned(),
            ..AppearanceConfig::default()
        };
        let _ = store.upsert_appearance_config(&cfg).await?;

        let app = branding_router(state);
        let response = call(app, get("/api/v2/appearance/logo")?).await?;
        assert_eq!(response.status(), StatusCode::FOUND);
        let location = response
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok())
            .ok_or("missing Location header")?;
        assert_eq!(location, "https://example.com/logo.svg");
        let cache_control = response
            .headers()
            .get(axum::http::header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
            .ok_or("missing Cache-Control header")?;
        assert!(cache_control.contains("public"));
        Ok(())
    }

    #[tokio::test]
    async fn appearance_logo_returns_404_when_unset() -> Result<(), Box<dyn std::error::Error>> {
        let (state, _store) = crate::app::tests::test_state_with_store(true)?;
        let app = branding_router(state);
        let response = call(app, get("/api/v2/appearance/logo")?).await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        Ok(())
    }

    #[tokio::test]
    async fn appearance_favicon_returns_404_until_config_field_exists()
    -> Result<(), Box<dyn std::error::Error>> {
        // `AppearanceConfig` does not expose a favicon URL today, so the
        // endpoint must return 404 regardless of what's in the config.
        let (state, store) = crate::app::tests::test_state_with_store(true)?;
        let cfg = AppearanceConfig {
            logo_url: "https://example.com/logo.svg".to_owned(),
            ..AppearanceConfig::default()
        };
        let _ = store.upsert_appearance_config(&cfg).await?;

        let app = branding_router(state);
        let response = call(app, get("/api/v2/appearance/favicon")?).await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        Ok(())
    }
}
