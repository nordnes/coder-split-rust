//! Azure VM instance-identity verification (PKCS7/CMS envelope).
//!
//! Azure's IMDS attested-data endpoint
//! (`http://169.254.169.254/metadata/attested/document?api-version=…`)
//! returns a **base64-encoded PKCS7/CMS envelope**, not a JWT. This module
//! ports the logic from
//! [`coder/coderd/azureidentity/azureidentity.go`](https://github.com/coder/coder/blob/main/coderd/azureidentity/azureidentity.go):
//!
//! 1. Base64-decode the payload.
//! 2. Parse the CMS `ContentInfo`/`SignedData`.
//! 3. Locate the signer certificate inside the envelope.
//! 4. Match the signer cert's `Subject.CommonName` against
//!    `^(.*\.)?metadata\.(azure\.(com|us|cn)|microsoftazure\.de)$`.
//! 5. Verify the signer certificate's signature against a bundled
//!    Microsoft intermediate CA, and check validity dates.
//! 6. JSON-decode the inner content and return the `vmId` field.
//!
//! The Go reference walks the chain all the way to a system root store;
//! we treat the bundled Microsoft intermediates as terminal trust anchors
//! so the verifier is fully self-contained (no dependency on OS roots at
//! test or runtime). The security properties are equivalent because the
//! bundle is controlled by this codebase.
//!
//! The PKCS7 signature over the inner content is **not** cryptographically
//! verified here — this matches Go, which only validates the signer's
//! certificate chain (via `x509.Certificate.Verify`) and not the CMS
//! signature. The signer-CN regex + cert-chain walk is the security
//! boundary. See the module docstring in the Go reference for the
//! rationale.

use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier};
use const_oid::ObjectIdentifier;
use der::asn1::OctetString;
use der::{Decode, Encode};
use regex::Regex;
use serde::Deserialize;
use x509_parser::prelude::*;

use super::{VerifiedInstance, VerifyError};
use crate::instance_identity::azure_certs::AZURE_INTERMEDIATES;

/// PKCS7 `signedData` content-type OID.
const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");

/// Regex applied to the signer certificate's `Subject.CommonName`.
///
/// Ports `allowedSigners` from `coder/coderd/azureidentity/azureidentity.go`.
static ALLOWED_SIGNERS: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::unwrap_used)]
    // Static regex literal is known good; failure here is a programmer
    // bug and would be caught immediately by the first unit test run.
    Regex::new(r"^(.*\.)?metadata\.(azure\.(com|us|cn)|microsoftazure\.de)$").unwrap()
});

/// Compiled issuer allow-list retained for any future Entra ID JWT path.
///
/// Accepts only the real Entra ID / Azure AD issuer hostnames:
///
///   * `https://sts.windows.net/{tenant}/`
///   * `https://login.microsoftonline.com/{tenant}/...`
///   * `https://login.microsoftonline.us/{tenant}/...` (Gov cloud)
///   * `https://login.microsoftonline.de/{tenant}/...` (legacy Germany)
///   * `https://login.partner.microsoftonline.cn/{tenant}/...` (China)
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

/// Decoded JSON payload carried inside the PKCS7 envelope.
///
/// The Azure attested-data document has more fields (nonce, SKU, etc.) —
/// we only need the VM ID for bootstrap, so we deserialize just that.
#[derive(Debug, Deserialize)]
struct AttestedMetadata {
    #[serde(rename = "vmId")]
    vm_id: String,
}

/// Azure instance-identity verifier.
///
/// Pre-parses the bundled Microsoft intermediate certs at construction
/// time so each verification call only pays for the signer-cert parse +
/// chain walk. Malformed entries in `AZURE_INTERMEDIATES` are logged at
/// `WARN` and skipped rather than panicking.
pub(crate) struct AzureInstanceVerifier {
    /// Retained for parity with the other verifiers and in case a future
    /// JWT-based managed-identity path needs HTTP egress.
    #[allow(dead_code)]
    http_client: reqwest::Client,
    /// DER-encoded intermediate certs, in the order they appear in
    /// `AZURE_INTERMEDIATES`. Parsed on demand during chain walks because
    /// `x509_parser::prelude::X509Certificate` borrows from its backing
    /// bytes and cannot be stored self-referentially.
    intermediates_der: Vec<Vec<u8>>,
}

impl AzureInstanceVerifier {
    #[must_use]
    pub(crate) fn new(http_client: reqwest::Client) -> Self {
        let intermediates_der = AZURE_INTERMEDIATES
            .iter()
            .enumerate()
            .filter_map(|(idx, pem)| match pem_to_der(pem) {
                Ok(der) => Some(der),
                Err(err) => {
                    tracing::warn!(
                        target: "coder_server::instance_identity::azure",
                        index = idx,
                        error = %err,
                        "failed to parse bundled Azure intermediate certificate; skipping"
                    );
                    None
                }
            })
            .collect();
        Self {
            http_client,
            intermediates_der,
        }
    }

    /// Verify a base64-encoded PKCS7 envelope and return the enclosed VM ID.
    pub(crate) async fn verify(&self, signature: &str) -> Result<VerifiedInstance, VerifyError> {
        self.verify_at(signature, SystemTime::now())
    }

    /// Test hook: verify at an explicit time so unit tests using captured
    /// Go fixtures can assert behaviour after the signer cert's notAfter.
    fn verify_at(&self, signature: &str, now: SystemTime) -> Result<VerifiedInstance, VerifyError> {
        let der = BASE64_STD
            .decode(signature.trim())
            .map_err(|err| VerifyError::InvalidRequest(format!("base64 decode: {err}")))?;

        let content_info = ContentInfo::from_der(&der).map_err(|err| {
            VerifyError::InvalidRequest(format!("invalid CMS ContentInfo: {err}"))
        })?;
        if content_info.content_type != ID_SIGNED_DATA {
            return Err(VerifyError::InvalidRequest(format!(
                "unexpected CMS content type: {}",
                content_info.content_type
            )));
        }
        let signed_data: SignedData = content_info
            .content
            .decode_as()
            .map_err(|err| VerifyError::InvalidRequest(format!("invalid CMS SignedData: {err}")))?;

        let cert_set = signed_data
            .certificates
            .as_ref()
            .ok_or_else(|| VerifyError::InvalidRequest("SignedData missing certificates".into()))?;
        let signer_info =
            signed_data.signer_infos.0.iter().next().ok_or_else(|| {
                VerifyError::InvalidRequest("SignedData missing signer info".into())
            })?;

        let signer_der = find_signer_cert_der(cert_set, &signer_info.sid)
            .ok_or_else(|| VerifyError::InvalidRequest("signer certificate not found".into()))?;
        let (_, signer_cert) = parse_x509_certificate(&signer_der).map_err(|err| {
            VerifyError::InvalidRequest(format!("invalid signer certificate: {err}"))
        })?;

        let cn = signer_cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|c| c.as_str().ok())
            .ok_or_else(|| VerifyError::VerificationFailed)?;
        if !ALLOWED_SIGNERS.is_match(cn) {
            tracing::warn!(
                target: "coder_server::instance_identity::azure",
                cn = %cn,
                "signer common name did not match Azure metadata regex"
            );
            return Err(VerifyError::VerificationFailed);
        }

        let now_ts = now
            .duration_since(UNIX_EPOCH)
            .map_err(|_| VerifyError::VerificationFailed)?
            .as_secs()
            .try_into()
            .map_err(|_| VerifyError::VerificationFailed)?;
        let now_asn1 =
            ASN1Time::from_timestamp(now_ts).map_err(|_| VerifyError::VerificationFailed)?;
        if !signer_cert.validity().is_valid_at(now_asn1) {
            tracing::warn!(
                target: "coder_server::instance_identity::azure",
                "signer certificate is not valid at the current time"
            );
            return Err(VerifyError::VerificationFailed);
        }

        verify_chain(&signer_cert, now_asn1, &self.intermediates_der)?;

        let econtent = signed_data
            .encap_content_info
            .econtent
            .as_ref()
            .ok_or_else(|| VerifyError::InvalidRequest("SignedData missing content".into()))?;
        let econtent_der = econtent
            .to_der()
            .map_err(|err| VerifyError::InvalidRequest(format!("econtent encode: {err}")))?;
        let octet_string = OctetString::from_der(&econtent_der).map_err(|err| {
            VerifyError::InvalidRequest(format!("econtent not an OCTET STRING: {err}"))
        })?;
        let metadata: AttestedMetadata =
            serde_json::from_slice(octet_string.as_bytes()).map_err(|err| {
                VerifyError::InvalidRequest(format!("attested-data JSON decode: {err}"))
            })?;

        Ok(VerifiedInstance {
            instance_id: metadata.vm_id,
        })
    }
}

/// Decode a single-cert PEM string into DER bytes.
fn pem_to_der(pem: &str) -> Result<Vec<u8>, String> {
    let (_, parsed) = parse_x509_pem(pem.as_bytes()).map_err(|e| format!("pem: {e}"))?;
    Ok(parsed.contents)
}

/// Locate the signer certificate in the CMS `CertificateSet` using the
/// identifier from the `SignerInfo` entry, then return it as DER bytes so
/// x509-parser can own-and-borrow the buffer for verification.
fn find_signer_cert_der(
    certs: &cms::signed_data::CertificateSet,
    sid: &SignerIdentifier,
) -> Option<Vec<u8>> {
    for choice in certs.0.iter() {
        let CertificateChoices::Certificate(cert) = choice else {
            continue;
        };
        let matches = match sid {
            SignerIdentifier::IssuerAndSerialNumber(ias) => {
                let issuer_match = cert
                    .tbs_certificate
                    .issuer
                    .to_der()
                    .ok()
                    .zip(ias.issuer.to_der().ok())
                    .is_some_and(|(a, b)| a == b);
                let serial_match = cert.tbs_certificate.serial_number == ias.serial_number;
                issuer_match && serial_match
            }
            SignerIdentifier::SubjectKeyIdentifier(target_ski) => {
                // Walk the cert's extensions for an SKI (2.5.29.14).
                let Some(exts) = cert.tbs_certificate.extensions.as_ref() else {
                    continue;
                };
                exts.iter().any(|ext| {
                    if ext.extn_id != ObjectIdentifier::new_unwrap("2.5.29.14") {
                        return false;
                    }
                    let Ok(ski_bytes) = OctetString::from_der(ext.extn_value.as_bytes()) else {
                        return false;
                    };
                    ski_bytes.as_bytes() == target_ski.0.as_bytes()
                })
            }
        };
        if matches {
            return cert.to_der().ok();
        }
    }
    None
}

/// Walk the certificate chain up from `signer` to one of the bundled
/// Microsoft intermediate CAs. Returns Ok if a bundled intermediate's
/// public key validates the signer's signature and the intermediate is
/// itself valid at `now`. Bundled intermediates are treated as terminal
/// trust anchors; we do not walk further to a root (see module docs).
fn verify_chain(
    signer: &X509Certificate<'_>,
    now: ASN1Time,
    intermediates_der: &[Vec<u8>],
) -> Result<(), VerifyError> {
    let signer_issuer = signer.issuer().as_raw();
    let mut last_err: Option<String> = None;
    for intermediate_der in intermediates_der {
        let Ok((_, intermediate)) = parse_x509_certificate(intermediate_der) else {
            continue;
        };
        if intermediate.subject().as_raw() != signer_issuer {
            continue;
        }
        if !intermediate.validity().is_valid_at(now) {
            last_err = Some(format!(
                "intermediate '{}' is not valid at the current time",
                intermediate.subject()
            ));
            continue;
        }
        match signer.verify_signature(Some(intermediate.public_key())) {
            Ok(()) => return Ok(()),
            Err(err) => {
                last_err = Some(format!("signature verification failed: {err}"));
                continue;
            }
        }
    }
    tracing::warn!(
        target: "coder_server::instance_identity::azure",
        signer_issuer = %signer.issuer(),
        last_error = ?last_err,
        "no bundled Azure intermediate validates the signer certificate"
    );
    Err(VerifyError::VerificationFailed)
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "tests are allowed to fail loudly"
)]
mod tests {
    use super::*;

    /// Captured Azure IMDS attested-data PKCS7 envelope + expected vmId,
    /// copied verbatim from `coder/coderd/azureidentity/azureidentity_test.go`.
    /// Each fixture was exported from a real VM at the timestamp recorded in
    /// the Go test's `CurrentTime` field; the signer certificates are long
    /// expired, so tests must pin `now` to the fixture's capture date.
    struct Fixture {
        name: &'static str,
        payload: &'static str,
        expected_vm_id: &'static str,
        /// Seconds since UNIX epoch — the Go test's `CurrentTime`.
        at_timestamp: i64,
    }

    // Fixtures from coder/coderd/azureidentity/azureidentity_test.go;
    // `at_timestamp` mirrors that test's `date` field.
    const FIXTURE_REGULAR: Fixture = Fixture {
        name: "regular",
        payload: include_str!("testdata/azure_regular.b64"),
        expected_vm_id: "bd8e7443-24a0-41f3-b949-8baf4fd1c573",
        at_timestamp: 1_675_209_600, // 2023-02-01T00:00:00Z
    };

    const FIXTURE_GOVCLOUD: Fixture = Fixture {
        name: "govcloud",
        payload: include_str!("testdata/azure_govcloud.b64"),
        expected_vm_id: "990878d4-068a-4ac4-9ee9-1231d2218ef2",
        at_timestamp: 1_680_307_200, // 2023-04-01T00:00:00Z
    };

    const FIXTURE_RSA: Fixture = Fixture {
        name: "rsa",
        payload: include_str!("testdata/azure_rsa.b64"),
        expected_vm_id: "960a4b4a-dab2-44ef-9b73-7753043b4f16",
        at_timestamp: 1_713_807_164, // 2024-04-22T17:32:44Z
    };

    fn verifier() -> AzureInstanceVerifier {
        AzureInstanceVerifier::new(reqwest::Client::new())
    }

    fn run_fixture(fx: &Fixture) {
        let v = verifier();
        let now = UNIX_EPOCH + std::time::Duration::from_secs(fx.at_timestamp as u64);
        let result = v.verify_at(fx.payload, now);
        match result {
            Ok(instance) => assert_eq!(
                instance.instance_id, fx.expected_vm_id,
                "fixture {}: wrong vm id",
                fx.name
            ),
            Err(err) => panic!("fixture {}: {err:?}", fx.name),
        }
    }

    #[test]
    fn verify_regular_fixture() {
        run_fixture(&FIXTURE_REGULAR);
    }

    #[test]
    fn verify_govcloud_fixture() {
        run_fixture(&FIXTURE_GOVCLOUD);
    }

    #[test]
    fn verify_rsa_fixture() {
        run_fixture(&FIXTURE_RSA);
    }

    #[test]
    fn rejects_empty_signature() {
        let v = verifier();
        let err = v
            .verify_at("", SystemTime::now())
            .expect_err("empty string must be rejected");
        assert!(matches!(err, VerifyError::InvalidRequest(_)));
    }

    #[test]
    fn rejects_non_base64() {
        let v = verifier();
        let err = v
            .verify_at("!!!not base64!!!", SystemTime::now())
            .expect_err("non-base64 must be rejected");
        assert!(matches!(err, VerifyError::InvalidRequest(_)));
    }

    #[test]
    fn rejects_non_cms_payload() {
        let v = verifier();
        // "hello world" base64-encoded is not a CMS ContentInfo.
        let err = v
            .verify_at("aGVsbG8gd29ybGQ=", SystemTime::now())
            .expect_err("non-CMS payload must be rejected");
        assert!(matches!(err, VerifyError::InvalidRequest(_)));
    }

    #[test]
    fn rejects_expired_signer_certificate() {
        // Use the regular fixture at a time long after the signer cert's
        // notAfter — validity check must fail.
        let v = verifier();
        let future = UNIX_EPOCH + std::time::Duration::from_secs(4_102_444_800); // 2100-01-01
        let err = v
            .verify_at(FIXTURE_REGULAR.payload, future)
            .expect_err("expired signer cert must be rejected");
        assert!(matches!(err, VerifyError::VerificationFailed));
    }

    #[test]
    fn allowed_signers_regex_matches_expected_hosts() {
        // Mirrors the patterns the Go reference accepts.
        for good in [
            "metadata.azure.com",
            "foo.metadata.azure.com",
            "bar.metadata.azure.us",
            "metadata.azure.cn",
            "metadata.microsoftazure.de",
        ] {
            assert!(ALLOWED_SIGNERS.is_match(good), "must match: {good}");
        }
        for bad in [
            "metadata.azure.net",
            "evil-metadata.azure.com.bad.example",
            "login.microsoftonline.com",
            "",
        ] {
            assert!(!ALLOWED_SIGNERS.is_match(bad), "must not match: {bad}");
        }
    }
}
