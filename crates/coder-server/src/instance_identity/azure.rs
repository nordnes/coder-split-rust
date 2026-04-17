//! Azure VM instance-identity verification.
//!
//! ⚠️ **STUBBED — fundamentally deviates from the Go reference.** ⚠️
//!
//! Standard Azure IMDS attested-data
//! (`http://169.254.169.254/metadata/attested/document?api-version=...`)
//! returns a **base64-encoded PKCS7/CMS envelope**, not a JWT. The Go
//! reference in `coder/coderd/azureidentity/azureidentity.go` decodes that
//! PKCS7, walks the cert chain to a bundled set of Microsoft intermediates,
//! matches the signer cert's `Subject.CommonName` against
//! `^(.*\.)?metadata\.(azure\.(com|us|cn)|microsoftazure\.de)$`, and reads
//! `vmId` from the inner JSON content.
//!
//! The earlier JWT/JWKS scaffold in this module was aimed at Entra ID /
//! Azure AD v2 managed-identity tokens, which are a different wire shape
//! from what the workspace-agent bootstrap endpoint actually receives. To
//! avoid false confidence, [`AzureInstanceVerifier::verify`] is now an
//! **explicit stub**: every call emits a `WARN` via `tracing` and returns
//! [`VerifyError::VerificationFailed`] unconditionally.
//!
//! **Consequence:** with `verify_instance_identity = true`, the Azure
//! bootstrap endpoint will reject every request. Operators who need Azure
//! parity today must either (a) stay on the permissive verifier or (b)
//! wait for the PKCS7 port (tracked in
//! `docs/remaining-behavioral-gaps.md`, section "Azure instance-identity
//! PKCS7 verification"). Failing closed is intentional — silently accepting
//! unvalidated Azure tokens would be an identity-forgery vector.
//!
//! The [`issuer_regex`] helper below is still exercised by its unit test
//! and is ready to be lifted back into [`verify`] once the PKCS7 path is
//! implemented (the Entra ID issuer allow-list will apply to any JWT-based
//! token exchange Coder chooses to add on top of PKCS7).

use std::sync::LazyLock;

use regex::Regex;

use super::{VerifiedInstance, VerifyError};

/// Azure instance-identity verifier.
///
/// Currently a stub (see module docs): every call to [`Self::verify`] logs
/// a warning and returns [`VerifyError::VerificationFailed`].
pub(crate) struct AzureInstanceVerifier {
    /// Retained so the [`super::CryptoVerifier`] wiring does not need to
    /// change when PKCS7 support lands.
    #[allow(dead_code)]
    http_client: reqwest::Client,
}

impl AzureInstanceVerifier {
    #[must_use]
    pub(crate) fn new(http_client: reqwest::Client) -> Self {
        Self { http_client }
    }

    /// Stubbed: always returns [`VerifyError::VerificationFailed`].
    ///
    /// Emits a `WARN`-level trace event so operators running with
    /// `verify_instance_identity = true` see clearly why Azure bootstrap
    /// requests are being rejected. The input token is intentionally not
    /// logged — we do not want to write potentially forgeable credentials
    /// into the trace stream.
    pub(crate) async fn verify(&self, _token: &str) -> Result<VerifiedInstance, VerifyError> {
        tracing::warn!(
            target: "coder_server::instance_identity::azure",
            "Azure instance-identity verification is stubbed: the Go reference \
             uses PKCS7/CMS envelope verification with a bundled Microsoft \
             intermediate trust store, which has not yet been ported to Rust. \
             Rejecting the request. See docs/remaining-behavioral-gaps.md."
        );
        Err(VerifyError::VerificationFailed)
    }
}

/// Compiled issuer allow-list for the future JWT path. Accepts only the
/// real Entra ID / Azure AD issuer hostnames:
///
///   * `https://sts.windows.net/{tenant}/` (Entra ID v1)
///   * `https://login.microsoftonline.com/{tenant}/...` (Entra ID v2, public)
///   * `https://login.microsoftonline.us/{tenant}/...` (Gov cloud)
///   * `https://login.microsoftonline.de/{tenant}/...` (legacy Germany)
///   * `https://login.partner.microsoftonline.cn/{tenant}/...` (China)
///
/// The old `metadata.azure.*` / `microsoftazure.de` regex was a mistake —
/// that pattern matches the PKCS7 signer cert's `Subject.CommonName`, NOT
/// a JWT `iss` claim. Real Azure AD tokens never carry a `metadata.*`
/// issuer, so applying that pattern to `iss` validation would have rejected
/// every valid Entra ID token.
#[allow(dead_code)]
static DEFAULT_ISSUER_REGEX: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(concat!(
        r"^https?://(",
        r"sts\.windows\.net",
        r"|login\.microsoftonline\.com",
        r"|login\.microsoftonline\.us",
        r"|login\.microsoftonline\.de",
        r"|login\.partner\.microsoftonline\.cn",
        r")/[^/]+(/.*)?$",
    ))
    .ok()
});

/// Returns the compiled issuer regex used by the future JWT path. Exposed
/// as a function so tests can assert its behaviour even though the stub
/// verifier does not consume it yet.
#[cfg(test)]
fn default_issuer_regex() -> Option<Regex> {
    DEFAULT_ISSUER_REGEX.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    type TestResult = Result<(), Box<dyn Error>>;

    fn assert_verification_failed<T: std::fmt::Debug>(
        result: Result<T, VerifyError>,
    ) -> Result<(), Box<dyn Error>> {
        match result {
            Err(VerifyError::VerificationFailed) => Ok(()),
            other => Err(format!("expected VerificationFailed, got {other:?}").into()),
        }
    }

    /// The stub unconditionally fails, even for inputs that look like
    /// well-formed JWTs.
    #[tokio::test]
    async fn stub_rejects_jwt_shaped_input() -> TestResult {
        let verifier = AzureInstanceVerifier::new(reqwest::Client::new());
        assert_verification_failed(verifier.verify("eyJhbGciOiJSUzI1NiJ9.e30.sig").await)
    }

    /// The stub rejects empty / malformed input too — we deliberately do
    /// not distinguish malformed from invalid, since splitting the two
    /// would suggest the verifier is doing work it is not.
    #[tokio::test]
    async fn stub_rejects_empty_input() -> TestResult {
        let verifier = AzureInstanceVerifier::new(reqwest::Client::new());
        assert_verification_failed(verifier.verify("").await)
    }

    /// The issuer allow-list regex only matches real Entra ID tenant
    /// issuers. The `metadata.azure.*` pattern (which applies to the PKCS7
    /// signer cert's CN, not a JWT `iss`) is rejected — the previous
    /// version of this regex incorrectly accepted it.
    #[test]
    fn issuer_regex_matches_real_entra_issuers() -> TestResult {
        let re = default_issuer_regex().ok_or("default issuer regex failed to compile")?;

        // Real Entra ID v1 / v2 JWT issuers across all partitions.
        assert!(re.is_match("https://sts.windows.net/72f988bf-86f1-41af-91ab-2d7cd011db47/"));
        assert!(re.is_match(
            "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/v2.0"
        ));
        assert!(re.is_match(
            "https://login.microsoftonline.us/72f988bf-86f1-41af-91ab-2d7cd011db47/v2.0"
        ));
        assert!(re.is_match(
            "https://login.microsoftonline.de/72f988bf-86f1-41af-91ab-2d7cd011db47/v2.0"
        ));
        assert!(re.is_match(
            "https://login.partner.microsoftonline.cn/72f988bf-86f1-41af-91ab-2d7cd011db47/v2.0"
        ));

        // Previously-accepted PKCS7 CN-style patterns must now be REJECTED
        // when matched against `iss`. A real Entra ID token never has a
        // `metadata.*` issuer.
        assert!(!re.is_match("https://metadata.azure.com/"));
        assert!(!re.is_match("https://something.metadata.azure.us/x"));
        assert!(!re.is_match("http://metadata.azure.cn"));
        assert!(!re.is_match("https://metadata.microsoftazure.de/"));

        // Adversarial / non-Microsoft hosts must be rejected.
        assert!(!re.is_match("https://attacker.example.com/"));
        assert!(!re.is_match("https://metadata.evil.com/"));
        assert!(!re.is_match("https://login.attacker.com/abc/v2.0"));
        assert!(!re.is_match("https://sts.windowsnet/abc/"));

        // Missing tenant segment — allow-list requires at least one
        // path segment after the host.
        assert!(!re.is_match("https://sts.windows.net/"));
        assert!(!re.is_match("https://login.microsoftonline.com"));

        Ok(())
    }
}
