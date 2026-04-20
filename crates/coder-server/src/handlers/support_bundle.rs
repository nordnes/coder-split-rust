//! Support bundle generator endpoint.
//!
//! Mirrors Go's `coder/support/support.go` — the deployment-level handler
//! produces a tarball of config, health, entitlements, and replica state for
//! remote debugging. The workspace-level handler produces a zip with
//! workspace-specific diagnostics (workspace record, build history,
//! template info, recent agent logs) mirroring the `coder support bundle`
//! CLI workflow.

use std::io::{Cursor, Write};
use std::time::Duration;

use axum::body::Body;
use axum::http::{HeaderName, HeaderValue, StatusCode, header::CONTENT_TYPE};
use coder_core::api::ReplicaResponse;
use flate2::{Compression, write::GzEncoder};
use tar::{Builder, Header};
use time::OffsetDateTime;
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

use super::workspaces::{build_to_json, workspace_to_json};
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

/// Packs the supplied `(name, bytes)` entries into an in-memory zip archive.
///
/// Uses DEFLATE compression and the conventional 0644 file permissions.
/// Support bundles are typically tens of KiB, so an in-memory buffer is
/// appropriate.
fn build_zip(entries: &[(&str, &[u8])]) -> std::io::Result<Vec<u8>> {
    let buffer = Vec::<u8>::new();
    let mut writer = ZipWriter::new(Cursor::new(buffer));
    let options: SimpleFileOptions = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(0o644);
    for (name, bytes) in entries {
        writer.start_file(*name, options)?;
        writer.write_all(bytes)?;
    }
    let cursor = writer
        .finish()
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    Ok(cursor.into_inner())
}

/// Maximum number of recent agent log entries to include per agent. Matches
/// the Go CLI's `--log-limit` default from `cli/support.go` (~4 KB of text
/// when each log is ~40 bytes), scaled to the hottest recent activity.
const AGENT_LOG_TAIL_LIMIT: i64 = 256;

/// Maximum number of builds to include in the bundle's build history. Matches
/// the Go CLI's `coder support bundle --build-history` default.
const BUILD_HISTORY_LIMIT: u32 = 5;

/// GET /api/v2/workspaces/{workspace}/support-bundle — stream a `.zip`
/// bundle of workspace-specific diagnostics for remote support.
///
/// The archive contains:
/// * `deployment-config.json` — redacted deployment configuration (secrets
///   are stripped by [`coder_core::ServerConfig::public`]).
/// * `workspace.json` — the workspace record.
/// * `template.json` — the workspace's template, when resolvable.
/// * `builds.json` — up to the 5 most recent workspace builds.
/// * `agent-logs.json` — up to ~256 recent log entries per agent attached
///   to the workspace's latest build, collected best-effort.
///
/// Requires the caller to have access to the workspace. The endpoint mirrors
/// the bundle that the Go CLI `coder support bundle` assembles by calling
/// numerous individual APIs, collapsed into a single server-side archive.
pub(crate) async fn get_workspace_support_bundle(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(workspace) = state
        .store
        .find_workspace_by_id(workspace_id, Some(context.user.id))
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    // Redacted deployment config (mirrors what the CLI fetches via
    // `GET /api/v2/deployment/config`). The `public()` view omits secrets.
    let deployment_config_json = serde_json::to_vec_pretty(&coder_core::DeploymentConfigResponse {
        config: state.config.public(),
        options: coder_core::ServerConfig::supported_options(),
    })
    .map_err(|error| internal_error("encode deployment config", &error))?;

    // Workspace record.
    let workspace_json = serde_json::to_vec_pretty(&workspace_to_json(&workspace))
        .map_err(|error| internal_error("encode workspace", &error))?;

    // Template record (best-effort: templates may have been removed). Only
    // the operator-visible fields are copied out — `TemplateRecord` does not
    // derive `Serialize`, and the ACL sub-objects are expensive to render.
    let template_payload = state
        .store
        .find_template_by_id(workspace.template_id)
        .await?
        .map(|t| {
            serde_json::json!({
                "id": t.id,
                "created_at": t.created_at
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
                "updated_at": t.updated_at
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
                "organization_id": t.organization_id,
                "organization_name": t.organization_name,
                "name": t.name,
                "display_name": t.display_name,
                "description": t.description,
                "provisioner": t.provisioner,
                "active_version_id": t.active_version_id,
                "created_by": t.created_by,
                "default_ttl_ms": t.default_ttl / 1_000_000,
                "deprecated": t.deprecated,
                "deleted": t.deleted,
            })
        });
    let template_json = serde_json::to_vec_pretty(&template_payload)
        .map_err(|error| internal_error("encode template", &error))?;

    // Build history (latest first, capped).
    let builds = state
        .store
        .list_workspace_builds(workspace_id, BUILD_HISTORY_LIMIT, 0)
        .await?;
    let builds_payload: Vec<_> = builds.iter().map(build_to_json).collect();
    let builds_json = serde_json::to_vec_pretty(&builds_payload)
        .map_err(|error| internal_error("encode builds", &error))?;

    // Agent logs: walk the most recent build's resources → agents and
    // collect a tail of logs for each. Skips silently if no build/resources
    // are attached (e.g. workspaces that have never been started).
    let mut agent_log_payload = serde_json::Map::new();
    if let Some(latest_build) = builds.first() {
        let resources = state
            .store
            .list_workspace_resources_by_job(latest_build.job_id)
            .await?;
        let resource_ids: Vec<Uuid> = resources.iter().map(|r| r.id).collect();
        if !resource_ids.is_empty() {
            let agents = state
                .store
                .list_workspace_agents_by_resource_ids(&resource_ids)
                .await?;
            for agent in agents {
                let logs = state
                    .store
                    .list_workspace_agent_logs(agent.id, 0, AGENT_LOG_TAIL_LIMIT)
                    .await?;
                let rendered: Vec<_> = logs
                    .iter()
                    .map(|log| {
                        serde_json::json!({
                            "id": log.id,
                            "created_at": log.created_at
                                .format(&time::format_description::well_known::Rfc3339)
                                .unwrap_or_default(),
                            "output": log.output,
                            "level": log.level,
                            "source_id": log.log_source_id,
                        })
                    })
                    .collect();
                agent_log_payload.insert(agent.name.clone(), serde_json::Value::Array(rendered));
            }
        }
    }
    let agent_logs_json = serde_json::to_vec_pretty(&agent_log_payload)
        .map_err(|error| internal_error("encode agent logs", &error))?;

    let archive = build_zip(&[
        ("deployment-config.json", &deployment_config_json),
        ("workspace.json", &workspace_json),
        ("template.json", &template_json),
        ("builds.json", &builds_json),
        ("agent-logs.json", &agent_logs_json),
    ])
    .map_err(|error| internal_error("build support bundle archive", &error))?;

    // Sanitise the filename: zips are handed off to end-users, so we keep
    // only filesystem-safe characters from the workspace name.
    let safe_name: String = workspace
        .name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let filename = format!("support-bundle-{safe_name}.zip");

    let mut response = Response::new(Body::from(archive));
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/zip"));
    if let Ok(disposition) = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
    {
        response
            .headers_mut()
            .insert(HeaderName::from_static("content-disposition"), disposition);
    }
    Ok(response)
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

    #[test]
    fn build_zip_round_trips() {
        let entries: &[(&str, &[u8])] = &[
            ("hello.txt", b"hello world"),
            ("info.json", b"{\"ok\":true}"),
        ];
        let archive = build_zip(entries).expect("archive builds");

        // Sanity: PK\x03\x04 is the local-file-header signature at offset 0.
        assert_eq!(&archive[..4], b"PK\x03\x04");

        let mut zip = zip::ZipArchive::new(Cursor::new(archive)).expect("read zip");
        assert_eq!(zip.len(), 2);
        let mut hello = zip.by_name("hello.txt").expect("entry present");
        let mut hello_bytes = Vec::new();
        hello.read_to_end(&mut hello_bytes).expect("read ok");
        assert_eq!(hello_bytes, b"hello world");
    }

    #[tokio::test]
    async fn workspace_support_bundle_returns_zip() {
        use crate::app::build_router;
        use crate::app::tests::{
            authenticated_request, call, create_and_login, test_state_with_store,
        };
        use axum::body::to_bytes;
        use axum::http::Method;
        use coder_core::{WorkspaceBuildRecord, WorkspaceRecord};

        let (state, store) = test_state_with_store(true).expect("state builds");
        let now = OffsetDateTime::now_utc();
        let workspace_id = Uuid::new_v4();
        let build_id = Uuid::new_v4();
        let job_id = Uuid::new_v4();
        let owner_id = Uuid::new_v4();
        let org_id = Uuid::new_v4();

        // Minimal build so `list_workspace_builds` returns a row.
        let build = WorkspaceBuildRecord {
            id: build_id,
            created_at: now,
            updated_at: now,
            workspace_id,
            build_number: 1,
            transition: "start".to_owned(),
            job_id,
            template_version_id: Uuid::new_v4(),
            initiator_id: owner_id,
            provisioner_state: None,
            deadline: None,
            max_deadline: None,
            reason: "initiator".to_owned(),
            daily_cost: 0,
        };
        store.insert_build(build).expect("insert build");

        let workspace = WorkspaceRecord {
            id: workspace_id,
            created_at: now,
            updated_at: now,
            owner_id,
            organization_id: org_id,
            template_id: Uuid::new_v4(),
            deleted: false,
            name: "acme-dev".to_owned(),
            autostart_schedule: None,
            ttl_ns: None,
            last_used_at: now,
            dormant_at: None,
            deleting_at: None,
            automatic_updates: "never".to_owned(),
            favorite: false,
            next_start_at: None,
        };
        store.insert_workspace(workspace).expect("insert workspace");

        let app = build_router(state, None);
        let token = create_and_login(&app).await.expect("login");
        let uri = format!("/api/v2/workspaces/{workspace_id}/support-bundle");
        let request = authenticated_request(Method::GET, &uri, &token).expect("build request");
        let response = call(app, request).await.expect("handler call");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/zip"),
        );
        let disposition = response
            .headers()
            .get("content-disposition")
            .and_then(|v| v.to_str().ok())
            .expect("disposition present");
        assert!(
            disposition.contains("support-bundle-acme-dev.zip"),
            "filename: {disposition}"
        );

        let body_bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        assert!(!body_bytes.is_empty());
        let zip = zip::ZipArchive::new(Cursor::new(body_bytes.to_vec())).expect("archive parses");
        assert!(
            zip.len() >= 1,
            "expected at least one entry, got {}",
            zip.len()
        );
    }
}
