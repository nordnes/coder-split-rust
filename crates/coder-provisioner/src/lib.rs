//! Provisioner and job-orchestration helpers for the Rust `coderd` rewrite.
#![forbid(unsafe_code)]

use base64::Engine as _;
use sha2::{Digest, Sha256};
use thiserror::Error;

const LINUX_SCRIPT: &str = include_str!("../scripts/bootstrap_linux.sh");
const DARWIN_SCRIPT: &str = include_str!("../scripts/bootstrap_darwin.sh");
const WINDOWS_SCRIPT: &str = include_str!("../scripts/bootstrap_windows.ps1");

/// Rendered agent init script plus compatibility headers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenderedInitScript {
    /// Fully rendered bootstrap script body.
    pub body: String,
    /// Compatibility `Content-Digest` value.
    pub content_digest: String,
}

/// Errors surfaced when rendering agent init scripts.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum InitScriptError {
    /// The operating system and architecture combination is unsupported.
    #[error("unknown os/arch: {os}/{arch}")]
    UnknownTarget { os: String, arch: String },
}

/// Renders the agent bootstrap script for one operating-system and architecture pair.
pub fn render_init_script(
    os: &str,
    arch: &str,
    access_url: &str,
) -> Result<RenderedInitScript, InitScriptError> {
    let os = os.to_ascii_lowercase();
    let arch = arch.to_ascii_lowercase();
    let template = match (os.as_str(), arch.as_str()) {
        ("windows", "amd64" | "arm64") => WINDOWS_SCRIPT,
        ("linux", "amd64" | "arm64" | "armv7") => LINUX_SCRIPT,
        ("darwin", "amd64" | "arm64") => DARWIN_SCRIPT,
        _ => return Err(InitScriptError::UnknownTarget { os, arch }),
    };

    let mut normalized_access_url = access_url.to_owned();
    if !normalized_access_url.ends_with('/') {
        normalized_access_url.push('/');
    }

    let body = template
        .replace("${ARCH}", &arch)
        .replace("${ACCESS_URL}", &normalized_access_url)
        .replace("${AUTH_TYPE}", "token");

    let hash = Sha256::digest(body.as_bytes());
    let encoded = base64::engine::general_purpose::STANDARD.encode(hash);
    let content_digest = format!(
        "sha256:{}",
        encoded
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );

    Ok(RenderedInitScript {
        body,
        content_digest,
    })
}

#[cfg(test)]
mod tests {
    use super::{InitScriptError, render_init_script};

    #[test]
    fn renders_linux_script_with_substitutions() -> Result<(), InitScriptError> {
        let script = render_init_script("linux", "amd64", "https://coder.example")?;
        assert!(script.body.contains("coder-linux-amd64"));
        assert!(script.body.contains("CODER_AGENT_AUTH=\"token\""));
        assert!(
            script
                .body
                .contains("CODER_AGENT_URL=\"https://coder.example/\"")
        );
        assert!(script.content_digest.starts_with("sha256:"));
        Ok(())
    }

    #[test]
    fn rejects_unknown_target() {
        assert_eq!(
            render_init_script("plan9", "amd64", "https://coder.example"),
            Err(InitScriptError::UnknownTarget {
                os: "plan9".to_owned(),
                arch: "amd64".to_owned(),
            })
        );
    }
}
