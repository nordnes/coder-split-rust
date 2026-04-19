//! Support bundle generator endpoint.
//!
//! Mirrors Go's `coder/support/bundle.go` — a tarball containing deployment
//! info, health checks, entitlements, and replica state, streamed as a
//! single `.tar.gz` response for remote debugging.

use std::io::Write;
use std::time::Duration;

use axum::body::Body;
use axum::http::{HeaderName, HeaderValue, StatusCode, header::CONTENT_TYPE};
use coder_core::api::ReplicaResponse;
use flate2::{Compression, write::GzEncoder};
use tar::{Builder, Header};
use time::OffsetDateTime;

use super::*;
use crate::replica_manager::{replica_from_row, stale_cutoff};

/// GET /api/v2/debug/support-bundle — stream a `.tar.gz` bundle of
/// deployment diagnostics for remote support.
///
/// The archive contains:
/// * `deployment-config.json` — redacted deployment configuration.
/// * `buildinfo.json` — build version and metadata.
/// * `health.json` — deployment health report.
/// * `entitlements.json` — feature entitlements snapshot.
/// * `replicas.json` — active replica list.
///
/// Requires owner-level RBAC (same gate as `/debug/health`).
pub(crate) async fn get_support_bundle(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !can_view_operational_data(&context.actor) {
        return Ok(forbidden_response(
            "You are not authorized to generate a support bundle.",
        ));
    }

    // Gather each artifact.  Support bundles are small (tens of KiB) so an
    // in-memory archive is appropriate.
    let deployment_config_json = serde_json::to_vec_pretty(&coder_core::DeploymentConfigResponse {
        config: state.config.public(),
        options: coder_core::ServerConfig::supported_options(),
    })
    .map_err(|error| internal_error("encode deployment config", &error))?;

    let build_info_json = serde_json::to_vec_pretty(&state.build_metadata.to_response(
        state.deployment_id,
        &state.config.access_url,
        &state.config.telemetry,
    ))
    .map_err(|error| internal_error("encode build info", &error))?;

    let health_settings = state.store.health_settings().await?;
    let health_report = state
        .health
        .report(&state.config, &state.build_metadata, false)
        .await?;
    let health_report = apply_dismissed_health_settings(health_report, &health_settings);
    let health_json = serde_json::to_vec_pretty(&health_report)
        .map_err(|error| internal_error("encode health report", &error))?;

    let entitlements_snapshot = state.entitlements.snapshot();
    let entitlements_json = serde_json::to_vec_pretty(&entitlements_snapshot)
        .map_err(|error| internal_error("encode entitlements", &error))?;

    let update_interval = Duration::from_secs(state.config.worker.replica_update_interval_secs);
    let threshold = OffsetDateTime::now_utc() - stale_cutoff(update_interval);
    let replica_rows = state.store.list_coderd_replicas(threshold).await?;
    let replicas: Vec<ReplicaResponse> = replica_rows.iter().map(replica_from_row).collect();
    let replicas_json = serde_json::to_vec_pretty(&replicas)
        .map_err(|error| internal_error("encode replicas", &error))?;

    let archive = build_tar_gz(&[
        ("deployment-config.json", &deployment_config_json),
        ("buildinfo.json", &build_info_json),
        ("health.json", &health_json),
        ("entitlements.json", &entitlements_json),
        ("replicas.json", &replicas_json),
    ])
    .map_err(|error| internal_error("build support bundle archive", &error))?;

    let filename = format!(
        "coder-support-bundle-{}.tar.gz",
        OffsetDateTime::now_utc().unix_timestamp()
    );

    let mut response = Response::new(Body::from(archive));
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/gzip"));
    if let Ok(disposition) = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
    {
        response
            .headers_mut()
            .insert(HeaderName::from_static("content-disposition"), disposition);
    }
    Ok(response)
}

/// Builds an `AppError::InternalError` from a short `message` and an error
/// detail. Used to surface encoding/archiving failures with a useful
/// debugging context instead of a bare 500.
fn internal_error(message: &str, detail: &dyn std::fmt::Display) -> AppError {
    AppError::InternalError {
        message: message.to_owned(),
        detail: detail.to_string(),
    }
}

/// Packs the supplied `(name, bytes)` entries into a gzipped tar archive.
fn build_tar_gz(entries: &[(&str, &[u8])]) -> std::io::Result<Vec<u8>> {
    let mut gz = GzEncoder::new(Vec::<u8>::new(), Compression::default());
    {
        let mut builder = Builder::new(&mut gz);
        let mtime = OffsetDateTime::now_utc().unix_timestamp() as u64;
        for (name, bytes) in entries {
            let mut header = Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_mtime(mtime);
            header.set_cksum();
            builder.append_data(&mut header, *name, *bytes)?;
        }
        builder.finish()?;
    }
    gz.flush()?;
    gz.finish()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use flate2::read::GzDecoder;
    use std::io::Read;

    #[test]
    fn build_tar_gz_round_trips() {
        let entries: &[(&str, &[u8])] = &[
            ("hello.txt", b"hello world"),
            ("info.json", b"{\"ok\":true}"),
        ];
        let archive = build_tar_gz(entries).expect("archive builds");

        // Sanity: gzip magic bytes 1f 8b.
        assert_eq!(&archive[..2], &[0x1f, 0x8b]);

        let gz = GzDecoder::new(archive.as_slice());
        let mut tar = tar::Archive::new(gz);
        let mut found = std::collections::HashMap::new();
        for entry in tar.entries().expect("read entries") {
            let mut entry = entry.expect("entry ok");
            let path = entry
                .path()
                .expect("path ok")
                .to_string_lossy()
                .into_owned();
            let mut contents = Vec::new();
            entry.read_to_end(&mut contents).expect("read ok");
            found.insert(path, contents);
        }
        assert_eq!(
            found.get("hello.txt").map(Vec::as_slice),
            Some(&b"hello world"[..])
        );
        assert_eq!(
            found.get("info.json").map(Vec::as_slice),
            Some(&b"{\"ok\":true}"[..])
        );
    }
}
