//! Cryptographic verification of cloud-provider instance-identity tokens.
//!
//! The three workspace-agent bootstrap endpoints (`aws-instance-identity`,
//! `azure-instance-identity`, `google-instance-identity`) accept a signature
//! asserted by the cloud platform so that an agent freshly launched inside a
//! workspace can exchange its instance identity for a Coder session token
//! without any human in the loop.
//!
//! Without cryptographic validation these endpoints are a trivial forgery
//! vector: any caller who knows a valid `instance_id` can impersonate that
//! agent. This module centralises the verification logic behind the
//! [`InstanceIdentityVerifier`] trait so production deployments can plug in
//! real platform keys while local development can continue to use the
//! permissive implementation.
//!
//! Ports Go reference from
//! `coder/coderd/workspaceresourceauth.go` (handlers) and the
//! `coder/coderd/awsidentity` / `coder/coderd/azureidentity` packages.

use std::sync::Arc;

use async_trait::async_trait;

pub(crate) mod aws;
pub(crate) mod azure;
pub(crate) mod gcp;

pub(crate) use aws::AwsInstanceVerifier;
pub(crate) use azure::AzureInstanceVerifier;
pub(crate) use gcp::GcpInstanceVerifier;

/// Identity extracted from a verified cloud-provider token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedInstance {
    /// Opaque cloud-provider instance identifier used to locate the matching
    /// workspace resource inside the database.
    pub instance_id: String,
}

/// Reasons why verification can fail.
///
/// The variants deliberately carry coarse-grained information so handlers can
/// map each failure to an HTTP status without leaking sensitive internals to
/// the caller.
#[derive(Debug, thiserror::Error)]
pub(crate) enum VerifyError {
    /// The request payload is malformed — e.g. the signature is empty, the
    /// document is not valid JSON, or the JWT is missing required fields.
    /// Maps to HTTP `400 Bad Request`.
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    /// The signature did not validate against the expected platform keys, or
    /// the token has expired. Maps to HTTP `401 Unauthorized`.
    #[error("verification failed")]
    VerificationFailed,
}

/// Verifier contract implemented by the three per-cloud backends.
#[async_trait]
pub(crate) trait InstanceIdentityVerifier: Send + Sync {
    /// Verifies an AWS EC2 instance-identity document and its base64-encoded
    /// RSA PKCS1v15 signature, returning the AWS `instanceId`.
    async fn verify_aws(
        &self,
        document: &str,
        signature_b64: &str,
    ) -> Result<VerifiedInstance, VerifyError>;

    /// Verifies an Azure attested-data JWT, returning the Azure `vmId`.
    async fn verify_azure(&self, signature: &str) -> Result<VerifiedInstance, VerifyError>;

    /// Verifies a GCP instance-identity JWT, returning the GCE
    /// `compute_engine.instance_id`.
    async fn verify_gcp(&self, jwt: &str) -> Result<VerifiedInstance, VerifyError>;
}

/// Permissive verifier used by local development and the existing unit-test
/// harness. It performs structural parsing only — no cryptographic
/// verification is attempted.
///
/// This preserves the pre-existing behaviour of the bootstrap endpoints so
/// test fixtures (which cannot produce AWS/Azure/Google signatures) keep
/// working. Production deployments should construct a [`CryptoVerifier`]
/// instead by setting [`ServerConfig::verify_instance_identity`][vi] to
/// `true`.
///
/// [vi]: coder_core::ServerConfig::verify_instance_identity
#[derive(Clone, Default)]
pub(crate) struct PermissiveVerifier;

#[async_trait]
impl InstanceIdentityVerifier for PermissiveVerifier {
    async fn verify_aws(
        &self,
        document: &str,
        _signature_b64: &str,
    ) -> Result<VerifiedInstance, VerifyError> {
        let doc: serde_json::Value = serde_json::from_str(document)
            .map_err(|e| VerifyError::InvalidRequest(format!("malformed JSON: {e}")))?;
        let instance_id = doc
            .get("instanceId")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| VerifyError::InvalidRequest("missing instanceId".to_owned()))?;
        Ok(VerifiedInstance {
            instance_id: instance_id.to_owned(),
        })
    }

    async fn verify_azure(&self, signature: &str) -> Result<VerifiedInstance, VerifyError> {
        let instance_id = decode_jwt_field(signature, "vmId")?;
        Ok(VerifiedInstance { instance_id })
    }

    async fn verify_gcp(&self, jwt: &str) -> Result<VerifiedInstance, VerifyError> {
        let instance_id = decode_google_instance_id(jwt)?;
        Ok(VerifiedInstance { instance_id })
    }
}

/// Cryptographic verifier: dispatches to the three per-cloud implementations.
#[derive(Clone)]
pub(crate) struct CryptoVerifier {
    aws: Arc<AwsInstanceVerifier>,
    azure: Arc<AzureInstanceVerifier>,
    gcp: Arc<GcpInstanceVerifier>,
}

impl CryptoVerifier {
    /// Construct a verifier with the default platform key sources, plus any
    /// operator-supplied AWS certificates loaded from `extra_aws_certs_dir`.
    ///
    /// The extra-cert directory is scanned at startup only; files with a
    /// `.pem` or `.crt` extension are read and appended to the bundled
    /// AWS trust roots. I/O or parse errors are logged and skipped so a
    /// misconfigured file cannot take down the server.
    #[must_use]
    pub(crate) fn new(
        http_client: reqwest::Client,
        extra_aws_certs_dir: Option<&std::path::Path>,
    ) -> Self {
        let aws = match extra_aws_certs_dir {
            Some(dir) => {
                let extras = load_extra_aws_certs(dir);
                if extras.is_empty() {
                    AwsInstanceVerifier::with_default_certificates()
                } else {
                    let combined = aws::DEFAULT_CERTIFICATES
                        .iter()
                        .map(|s| (*s).to_owned())
                        .chain(extras)
                        .collect::<Vec<_>>();
                    AwsInstanceVerifier::with_certificates(combined.iter().map(String::as_str))
                }
            }
            None => AwsInstanceVerifier::with_default_certificates(),
        };

        Self {
            aws: Arc::new(aws),
            azure: Arc::new(AzureInstanceVerifier::new(http_client.clone())),
            gcp: Arc::new(GcpInstanceVerifier::new(http_client)),
        }
    }
}

/// Reads every `*.pem` / `*.crt` file in `dir` and returns their contents.
/// Unreadable files and non-PEM entries are logged at `WARN` and skipped;
/// successful loads are logged at `INFO` with the filename so operators
/// can verify which trust roots are live.
fn load_extra_aws_certs(dir: &std::path::Path) -> Vec<String> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) => {
            tracing::warn!(
                target: "coder_server::instance_identity::aws",
                directory = %dir.display(),
                error = %err,
                "failed to read AWS instance-identity certs directory; falling back to bundled certs only"
            );
            return Vec::new();
        }
    };

    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let ext = path
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .map(str::to_ascii_lowercase);
        if !matches!(ext.as_deref(), Some("pem") | Some("crt")) {
            continue;
        }
        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                tracing::info!(
                    target: "coder_server::instance_identity::aws",
                    path = %path.display(),
                    "loaded extra AWS instance-identity certificate"
                );
                out.push(contents);
            }
            Err(err) => {
                tracing::warn!(
                    target: "coder_server::instance_identity::aws",
                    path = %path.display(),
                    error = %err,
                    "failed to read AWS instance-identity cert; skipping"
                );
            }
        }
    }
    out
}

#[async_trait]
impl InstanceIdentityVerifier for CryptoVerifier {
    async fn verify_aws(
        &self,
        document: &str,
        signature_b64: &str,
    ) -> Result<VerifiedInstance, VerifyError> {
        self.aws.verify(document, signature_b64).await
    }

    async fn verify_azure(&self, signature: &str) -> Result<VerifiedInstance, VerifyError> {
        self.azure.verify(signature).await
    }

    async fn verify_gcp(&self, jwt: &str) -> Result<VerifiedInstance, VerifyError> {
        self.gcp.verify(jwt).await
    }
}

/// Factory used by [`AppState`][crate::app::AppState] to construct the
/// appropriate verifier based on runtime configuration.
///
/// `extra_aws_certs_dir` is only consulted when `verify_enabled` is true;
/// the permissive verifier does not consult any trust roots.
#[must_use]
pub(crate) fn build_verifier(
    verify_enabled: bool,
    http_client: reqwest::Client,
    extra_aws_certs_dir: Option<&std::path::Path>,
) -> Arc<dyn InstanceIdentityVerifier> {
    if verify_enabled {
        Arc::new(CryptoVerifier::new(http_client, extra_aws_certs_dir))
    } else {
        Arc::new(PermissiveVerifier)
    }
}

/// Decodes the body of a JWT without validating the signature and extracts
/// the named top-level string field.
///
/// Used by the permissive verifier and by the unit tests that exercise the
/// shared lookup chain.
pub(crate) fn decode_jwt_field(jwt: &str, field: &str) -> Result<String, VerifyError> {
    let payload = jwt_payload(jwt)?;
    payload
        .get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| VerifyError::InvalidRequest(format!("missing {field}")))
}

/// Extracts `google.compute_engine.instance_id` from a GCP identity JWT body.
pub(crate) fn decode_google_instance_id(jwt: &str) -> Result<String, VerifyError> {
    let payload = jwt_payload(jwt)?;
    payload
        .pointer("/google/compute_engine/instance_id")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            VerifyError::InvalidRequest("missing google.compute_engine.instance_id".to_owned())
        })
}

/// Parses a `header.payload.signature` JWT into its JSON body without
/// validating the signature.
pub(crate) fn jwt_payload(jwt: &str) -> Result<serde_json::Value, VerifyError> {
    use base64::Engine;

    let mut parts = jwt.splitn(3, '.');
    let _header = parts
        .next()
        .ok_or_else(|| VerifyError::InvalidRequest("malformed JWT".to_owned()))?;
    let payload = parts
        .next()
        .ok_or_else(|| VerifyError::InvalidRequest("malformed JWT".to_owned()))?;
    let _sig = parts
        .next()
        .ok_or_else(|| VerifyError::InvalidRequest("malformed JWT".to_owned()))?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| VerifyError::InvalidRequest("malformed JWT".to_owned()))?;
    serde_json::from_slice(&decoded)
        .map_err(|_| VerifyError::InvalidRequest("malformed JWT".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use std::error::Error;

    type TestResult = Result<(), Box<dyn Error>>;

    fn make_jwt(payload: &serde_json::Value) -> Result<String, Box<dyn Error>> {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("{}");
        let body =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload)?);
        Ok(format!("{header}.{body}.sig"))
    }

    fn assert_invalid_request<T: std::fmt::Debug>(
        result: Result<T, VerifyError>,
    ) -> Result<(), Box<dyn Error>> {
        match result {
            Err(VerifyError::InvalidRequest(_)) => Ok(()),
            other => Err(format!("expected InvalidRequest, got {other:?}").into()),
        }
    }

    #[tokio::test]
    async fn permissive_aws_valid() -> TestResult {
        let verifier = PermissiveVerifier;
        let out = verifier
            .verify_aws(r#"{"instanceId":"i-abc"}"#, "")
            .await
            .map_err(|e| -> Box<dyn Error> { e.to_string().into() })?;
        assert_eq!(out.instance_id, "i-abc");
        Ok(())
    }

    #[tokio::test]
    async fn permissive_aws_missing_id() -> TestResult {
        let verifier = PermissiveVerifier;
        assert_invalid_request(verifier.verify_aws("{}", "").await)
    }

    #[tokio::test]
    async fn permissive_aws_bad_json() -> TestResult {
        let verifier = PermissiveVerifier;
        assert_invalid_request(verifier.verify_aws("nope", "").await)
    }

    #[tokio::test]
    async fn permissive_azure_valid() -> TestResult {
        let verifier = PermissiveVerifier;
        let jwt = make_jwt(&serde_json::json!({ "vmId": "az-1" }))?;
        let out = verifier
            .verify_azure(&jwt)
            .await
            .map_err(|e| -> Box<dyn Error> { e.to_string().into() })?;
        assert_eq!(out.instance_id, "az-1");
        Ok(())
    }

    #[tokio::test]
    async fn permissive_azure_missing_vm_id() -> TestResult {
        let verifier = PermissiveVerifier;
        let jwt = make_jwt(&serde_json::json!({}))?;
        assert_invalid_request(verifier.verify_azure(&jwt).await)
    }

    #[tokio::test]
    async fn permissive_azure_malformed_jwt() -> TestResult {
        let verifier = PermissiveVerifier;
        assert_invalid_request(verifier.verify_azure("abc").await)
    }

    #[tokio::test]
    async fn permissive_gcp_valid() -> TestResult {
        let verifier = PermissiveVerifier;
        let jwt = make_jwt(&serde_json::json!({
            "google": { "compute_engine": { "instance_id": "g-42" } }
        }))?;
        let out = verifier
            .verify_gcp(&jwt)
            .await
            .map_err(|e| -> Box<dyn Error> { e.to_string().into() })?;
        assert_eq!(out.instance_id, "g-42");
        Ok(())
    }

    #[tokio::test]
    async fn permissive_gcp_missing_instance_id() -> TestResult {
        let verifier = PermissiveVerifier;
        let jwt = make_jwt(&serde_json::json!({ "google": {} }))?;
        assert_invalid_request(verifier.verify_gcp(&jwt).await)
    }

    /// The extra-cert loader skips non-PEM extensions, tolerates
    /// unreadable files, and returns the PEM body for valid entries.
    #[test]
    fn load_extra_aws_certs_filters_and_tolerates_errors() -> TestResult {
        let dir = std::env::temp_dir().join(format!(
            "coder-extra-certs-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir)?;

        let valid_pem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        std::fs::write(dir.join("good.pem"), valid_pem)?;
        std::fs::write(dir.join("also-good.crt"), valid_pem)?;
        std::fs::write(dir.join("ignored.txt"), "nope")?;
        std::fs::write(dir.join("no-extension"), "nope")?;

        let loaded = load_extra_aws_certs(&dir);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(loaded.len(), 2, "only *.pem / *.crt should be loaded");
        assert!(loaded.iter().all(|c| c == valid_pem));
        Ok(())
    }

    #[test]
    fn load_extra_aws_certs_missing_directory_returns_empty() {
        let missing = std::path::Path::new("/definitely/does/not/exist/coder-extra-certs");
        assert!(load_extra_aws_certs(missing).is_empty());
    }
}
