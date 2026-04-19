//! Embedded React SPA served from the catch-all fallback.
//!
//! Mirrors Go's `site.Handler` in `coder/site/site.go`: at compile time the
//! contents of the `site/out/` build output are baked into the binary via
//! [`rust_embed::RustEmbed`], then served with SPA-style routing — any
//! unknown path falls back to `index.html` so client-side routes resolve
//! correctly after a hard refresh.
//!
//! The router in [`crate::build_router`] registers the embed handler as the
//! very last fallback, so `/api/*`, `/healthz`, workspace-app paths, etc. take
//! priority over static assets. Assets whose filename contains a content hash
//! (detected via `.{hash}.`) are served with an aggressive long-lived
//! `Cache-Control`; everything else uses `max-age=0, must-revalidate` so SPA
//! updates propagate on the next reload.
//!
//! The `site/out/` directory is populated by the Coder frontend build. When
//! absent, a minimal placeholder `index.html` ships with this crate so the
//! infrastructure is exercised even without a full `pnpm build`.

use std::borrow::Cow;

use axum::body::Body;
use axum::http::{HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use rust_embed::Embed;

/// Compile-time embed of the React SPA build output.
///
/// The `folder` path is resolved relative to `Cargo.toml`, so we point up two
/// levels (`crates/coder-server` → workspace root) to the conventional
/// `site/out/` location.
#[derive(Embed)]
#[folder = "../../site/out"]
struct Asset;

/// Returns the raw bytes and inferred `Content-Type` for `path`, or `None` if
/// the path is not present in the embedded bundle.
pub(crate) fn serve_asset(path: &str) -> Option<(Cow<'static, [u8]>, &'static str)> {
    // Trim any leading `/` — `rust-embed` keys are relative to `site/out/`.
    let key = path.trim_start_matches('/');
    let asset = Asset::get(key)?;
    let content_type = content_type_for(key);
    Some((asset.data, content_type))
}

/// Returns the embedded `index.html` bytes + `Content-Type`, or `None` if
/// no SPA bundle is embedded at all (i.e. `site/out/` was empty at build
/// time). Used as the SPA fallback for unknown paths so that client-side
/// routes resolve correctly after a hard refresh.
pub(crate) fn fallback_to_index() -> Option<(Cow<'static, [u8]>, &'static str)> {
    let asset = Asset::get("index.html")?;
    Some((asset.data, "text/html; charset=utf-8"))
}

/// Maps a filename suffix to a `Content-Type`. Deliberately small — we only
/// handle the types the Coder SPA actually ships. Anything else gets
/// `application/octet-stream`, which browsers treat as a download.
fn content_type_for(path: &str) -> &'static str {
    // Case-insensitive suffix match on the final extension.
    let lower = path.to_ascii_lowercase();
    match lower.rsplit('.').next() {
        Some("html") | Some("htm") => "text/html; charset=utf-8",
        Some("js") | Some("mjs") => "application/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("map") => "application/json; charset=utf-8",
        Some("svg") => "image/svg+xml; charset=utf-8",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("ttf") => "font/ttf",
        Some("otf") => "font/otf",
        Some("txt") => "text/plain; charset=utf-8",
        Some("wasm") => "application/wasm",
        _ => "application/octet-stream",
    }
}

/// Returns `true` when `name` looks like a build-hashed asset (e.g.
/// `main.8f3a1c2b.js`, `vendor-9c2f.css`). Hashed filenames are safe to
/// cache for a year because any content change renames the file.
fn is_hashed_asset(name: &str) -> bool {
    // The Coder frontend (like most Vite / esbuild outputs) produces names of
    // the form `<stem>.<hash>.<ext>`, where the hash is a hex or base36 token
    // of 6–32 characters. We treat any path with ≥3 dot-separated segments
    // where the middle segment is that long and alphanumeric as hashed.
    let mut segments = name.rsplitn(3, '.');
    let _ext = match segments.next() {
        Some(s) if !s.is_empty() => s,
        _ => return false,
    };
    let hash = match segments.next() {
        Some(s) => s,
        None => return false,
    };
    let _stem = match segments.next() {
        Some(s) if !s.is_empty() => s,
        _ => return false,
    };
    (6..=32).contains(&hash.len()) && hash.chars().all(|c| c.is_ascii_alphanumeric())
}

/// Picks a `Cache-Control` header appropriate for the asset path.
/// Hashed filenames are immutable; `index.html` (and anything else) is
/// revalidated so SPA updates ship on the next page load.
fn cache_control_for(path: &str) -> &'static str {
    let trimmed = path.trim_start_matches('/');
    // `index.html` must never be cached — it pins the script hashes.
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("index.html") {
        return "max-age=0, must-revalidate";
    }
    let last = trimmed.rsplit('/').next().unwrap_or(trimmed);
    if is_hashed_asset(last) {
        "public, max-age=31536000, immutable"
    } else {
        "max-age=0, must-revalidate"
    }
}

/// Axum fallback handler. Tries to serve the requested path from the embed,
/// otherwise falls back to `index.html` for SPA routing. If nothing is
/// embedded, returns 404.
pub(crate) async fn spa_fallback(uri: Uri) -> Response {
    let path = uri.path();
    if let Some((bytes, content_type)) = serve_asset(path) {
        return build_response(StatusCode::OK, bytes, content_type, cache_control_for(path));
    }
    if let Some((bytes, content_type)) = fallback_to_index() {
        // Even though this is an SPA miss, `index.html` MUST revalidate so
        // a stale cached copy can't point at a deleted hashed bundle.
        return build_response(
            StatusCode::OK,
            bytes,
            content_type,
            "max-age=0, must-revalidate",
        );
    }
    (StatusCode::NOT_FOUND, "not found").into_response()
}

fn build_response(
    status: StatusCode,
    bytes: Cow<'static, [u8]>,
    content_type: &'static str,
    cache_control: &'static str,
) -> Response {
    let body = match bytes {
        Cow::Borrowed(slice) => Body::from(slice),
        Cow::Owned(vec) => Body::from(vec),
    };
    let mut response = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, HeaderValue::from_static(content_type))
        .header(
            header::CACHE_CONTROL,
            HeaderValue::from_static(cache_control),
        )
        .body(body)
        .unwrap_or_else(|_| Response::new(Body::empty()));
    // Defensive: if the builder somehow returned an empty body the headers
    // are lost above. Set the status on the fallback to match.
    *response.status_mut() = status;
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_type_detection_matches_extension() {
        assert_eq!(
            content_type_for("foo.js"),
            "application/javascript; charset=utf-8"
        );
        assert_eq!(content_type_for("foo.css"), "text/css; charset=utf-8");
        assert_eq!(content_type_for("foo.svg"), "image/svg+xml; charset=utf-8");
        assert_eq!(content_type_for("foo.html"), "text/html; charset=utf-8");
        assert_eq!(content_type_for("foo.png"), "image/png");
        assert_eq!(content_type_for("foo.woff2"), "font/woff2");
        assert_eq!(content_type_for("unknown.xyz"), "application/octet-stream");
    }

    #[test]
    fn index_html_is_not_cached_long_term() {
        assert_eq!(cache_control_for("/"), "max-age=0, must-revalidate");
        assert_eq!(
            cache_control_for("/index.html"),
            "max-age=0, must-revalidate"
        );
        assert_eq!(
            cache_control_for("index.html"),
            "max-age=0, must-revalidate"
        );
    }

    #[test]
    fn hashed_assets_are_cached_immutably() {
        assert_eq!(
            cache_control_for("/assets/main.8f3a1c2b.js"),
            "public, max-age=31536000, immutable"
        );
        assert_eq!(
            cache_control_for("/vendor.9c2f3a1c2b9c.css"),
            "public, max-age=31536000, immutable"
        );
    }

    #[test]
    fn plain_named_assets_are_revalidated() {
        // A two-segment name (no hash) should not get the immutable policy.
        assert_eq!(
            cache_control_for("/favicon.ico"),
            "max-age=0, must-revalidate"
        );
        assert_eq!(
            cache_control_for("/robots.txt"),
            "max-age=0, must-revalidate"
        );
    }

    #[test]
    fn placeholder_index_is_embedded() {
        // The placeholder `site/out/index.html` we ship ensures the fallback
        // is non-empty in CI and for fresh clones that haven't run the
        // frontend build.
        let (bytes, content_type) = fallback_to_index()
            .expect("embedded index.html should always be present — site/out/index.html ships as a placeholder");
        assert_eq!(content_type, "text/html; charset=utf-8");
        let body = std::str::from_utf8(&bytes).unwrap_or("");
        assert!(
            body.contains("Coder") || body.contains("coder"),
            "placeholder index.html should mention Coder; got: {body:.200}"
        );
    }

    #[test]
    fn serve_asset_returns_index_html_with_html_content_type() {
        let (_bytes, content_type) =
            serve_asset("/index.html").expect("index.html should be embedded");
        assert_eq!(content_type, "text/html; charset=utf-8");
    }

    #[test]
    fn serve_asset_returns_none_for_missing_path() {
        assert!(serve_asset("/definitely-not-there-xyz.js").is_none());
    }

    #[tokio::test]
    async fn unknown_path_falls_back_to_index_html() {
        let uri: Uri = "/some/spa/route"
            .parse()
            .unwrap_or_else(|_| Uri::from_static("/"));
        let response = spa_fallback(uri).await;
        assert_eq!(response.status(), StatusCode::OK);
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(content_type, "text/html; charset=utf-8");
    }

    #[test]
    fn is_hashed_asset_detects_typical_build_outputs() {
        assert!(is_hashed_asset("main.8f3a1c2b.js"));
        assert!(is_hashed_asset("vendor-9c2f.9c2f3a1c2b9c.css"));
        assert!(!is_hashed_asset("favicon.ico"));
        assert!(!is_hashed_asset("index.html"));
        assert!(!is_hashed_asset("foo.bar.baz")); // `bar` is only 3 chars
    }
}
