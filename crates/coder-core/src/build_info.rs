//! Build metadata helpers.

use url::Url;
use uuid::Uuid;

use crate::api::BuildInfoResponse;

/// Static metadata describing the running build.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildMetadata {
    /// Semantic version for the running build.
    pub version: String,
    /// Short git commit hash for the running build.
    pub git_commit: String,
    /// Canonical link for this build or repository.
    pub external_url: String,
    /// Current agent API version.
    pub agent_api_version: String,
    /// Current provisioner API version.
    pub provisioner_api_version: String,
    /// Upgrade guidance surfaced to clients.
    pub upgrade_message: String,
    /// Whether this process is acting as a workspace proxy.
    pub workspace_proxy: bool,
}

impl BuildMetadata {
    /// Converts static build metadata into the public API response shape.
    #[must_use]
    pub fn to_response(
        &self,
        deployment_id: Uuid,
        access_url: &Url,
        telemetry: &crate::config::TelemetryConfig,
    ) -> BuildInfoResponse {
        BuildInfoResponse {
            external_url: self.external_url.clone(),
            version: self.version.clone(),
            dashboard_url: access_url.to_string(),
            telemetry: telemetry.enabled,
            workspace_proxy: self.workspace_proxy,
            agent_api_version: self.agent_api_version.clone(),
            provisioner_api_version: self.provisioner_api_version.clone(),
            upgrade_message: self.upgrade_message.clone(),
            deployment_id: deployment_id.to_string(),
            webpush_public_key: String::new(),
        }
    }
}

impl Default for BuildMetadata {
    fn default() -> Self {
        let base_version = env!("CARGO_PKG_VERSION");
        let git_commit = env!("GIT_COMMIT_HASH");

        // Build a version string that includes the commit hash when known,
        // mirroring Go's convention (e.g. "v0.1.0+abcdef1").
        let version = if git_commit == "unknown" {
            format!("v{base_version}")
        } else {
            format!("v{base_version}+{git_commit}")
        };

        Self {
            version,
            git_commit: git_commit.to_owned(),
            external_url: option_env!("CARGO_PKG_REPOSITORY")
                .unwrap_or("https://github.com/coder/coder")
                .to_owned(),
            agent_api_version: "0.1".to_owned(),
            provisioner_api_version: "0.1".to_owned(),
            upgrade_message: String::new(),
            workspace_proxy: false,
        }
    }
}
