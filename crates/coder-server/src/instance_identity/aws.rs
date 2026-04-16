//! AWS EC2 instance-identity document verification.
//!
//! AWS signs the identity document with RSA PKCS1v15 over SHA-256 using the
//! regional EC2 public key. The raw (base64-encoded) signature is sent along
//! with the JSON document inside the workspace-agent bootstrap request.
//!
//! Ports `coder/coderd/awsidentity/awsidentity.go`.

use std::sync::Arc;

use base64::Engine;
use rsa::RsaPublicKey;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use sha2::Sha256;
use x509_parser::pem::parse_x509_pem;
use x509_parser::public_key::PublicKey;

use super::{VerifiedInstance, VerifyError};

/// Bundled AWS EC2 regional certificates used to verify identity documents.
///
/// The production Go code embeds a larger map covering every GovCloud and
/// partition-specific region. We ship the two most widely used anchors here
/// (`Other` covers all standard commercial regions and `HongKong` is
/// representative of regions that rotate their own key). Operators that need
/// additional regions can add them via
/// [`AwsInstanceVerifier::with_certificates`].
pub(crate) const DEFAULT_CERTIFICATES: &[&str] = &[
    // "Other" — commercial regions except those listed below.
    "-----BEGIN CERTIFICATE-----\n\
MIIDIjCCAougAwIBAgIJAKnL4UEDMN/FMA0GCSqGSIb3DQEBBQUAMGoxCzAJBgNV\n\
BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdTZWF0dGxlMRgw\n\
FgYDVQQKEw9BbWF6b24uY29tIEluYy4xGjAYBgNVBAMTEWVjMi5hbWF6b25hd3Mu\n\
Y29tMB4XDTE0MDYwNTE0MjgwMloXDTI0MDYwNTE0MjgwMlowajELMAkGA1UEBhMC\n\
VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1NlYXR0bGUxGDAWBgNV\n\
BAoTD0FtYXpvbi5jb20gSW5jLjEaMBgGA1UEAxMRZWMyLmFtYXpvbmF3cy5jb20w\n\
gZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAIe9GN//SRK2knbjySG0ho3yqQM3\n\
e2TDhWO8D2e8+XZqck754gFSo99AbT2RmXClambI7xsYHZFapbELC4H91ycihvrD\n\
jbST1ZjkLQgga0NE1q43eS68ZeTDccScXQSNivSlzJZS8HJZjgqzBlXjZftjtdJL\n\
XeE4hwvo0sD4f3j9AgMBAAGjgc8wgcwwHQYDVR0OBBYEFCXWzAgVyrbwnFncFFIs\n\
77VBdlE4MIGcBgNVHSMEgZQwgZGAFCXWzAgVyrbwnFncFFIs77VBdlE4oW6kbDBq\n\
MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHU2Vh\n\
dHRsZTEYMBYGA1UEChMPQW1hem9uLmNvbSBJbmMuMRowGAYDVQQDExFlYzIuYW1h\n\
em9uYXdzLmNvbYIJAKnL4UEDMN/FMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEF\n\
BQADgYEAFYcz1OgEhQBXIwIdsgCOS8vEtiJYF+j9uO6jz7VOmJqO+pRlAbRlvY8T\n\
C1haGgSI/A1uZUKs/Zfnph0oEI0/hu1IIJ/SKBDtN5lvmZ/IzbOPIJWirlsllQIQ\n\
7zvWbGd9c9+Rm3p04oTvhup99la7kZqevJK0QRdD/6NpCKsqP/0=\n\
-----END CERTIFICATE-----",
    // "HongKong" — ap-east-1.
    "-----BEGIN CERTIFICATE-----\n\
MIICSzCCAbQCCQDtQvkVxRvK9TANBgkqhkiG9w0BAQsFADBqMQswCQYDVQQGEwJV\n\
UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHU2VhdHRsZTEYMBYGA1UE\n\
ChMPQW1hem9uLmNvbSBJbmMuMRowGAYDVQQDExFlYzIuYW1hem9uYXdzLmNvbTAe\n\
Fw0xOTAyMDMwMzAwMDZaFw0yOTAyMDIwMzAwMDZaMGoxCzAJBgNVBAYTAlVTMRMw\n\
EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdTZWF0dGxlMRgwFgYDVQQKEw9B\n\
bWF6b24uY29tIEluYy4xGjAYBgNVBAMTEWVjMi5hbWF6b25hd3MuY29tMIGfMA0G\n\
CSqGSIb3DQEBAQUAA4GNADCBiQKBgQC1kkHXYTfc7gY5Q55JJhjTieHAgacaQkiR\n\
Pity9QPDE3b+NXDh4UdP1xdIw73JcIIG3sG9RhWiXVCHh6KkuCTqJfPUknIKk8vs\n\
M3RXflUpBe8Pf+P92pxqPMCz1Fr2NehS3JhhpkCZVGxxwLC5gaG0Lr4rFORubjYY\n\
Rh84dK98VwIDAQABMA0GCSqGSIb3DQEBCwUAA4GBAA6xV9f0HMqXjPHuGILDyaNN\n\
dKcvplNFwDTydVg32MNubAGnecoEBtUPtxBsLoVYXCOb+b5/ZMDubPF9tU/vSXuo\n\
TpYM5Bq57gJzDRaBOntQbX9bgHiUxw6XZWaTS/6xjRJDT5p3S1E0mPI3lP/eJv4o\n\
Ezk5zb3eIf10/sqt4756\n\
-----END CERTIFICATE-----",
];

/// Verifier for AWS EC2 instance-identity documents.
pub(crate) struct AwsInstanceVerifier {
    verifying_keys: Vec<Arc<VerifyingKey<Sha256>>>,
}

impl AwsInstanceVerifier {
    /// Build a verifier with the bundled default regional certificates.
    ///
    /// Invalid bundled certificates are silently dropped so a single malformed
    /// anchor cannot take down startup; this matches the Go reference
    /// behaviour where certificates that fail to parse cause `Validate` to
    /// return early rather than panic.
    #[must_use]
    pub(crate) fn with_default_certificates() -> Self {
        Self::with_certificates(DEFAULT_CERTIFICATES.iter().copied())
    }

    /// Build a verifier from caller-supplied PEM-encoded certificates.
    pub(crate) fn with_certificates<'a>(pem_iter: impl IntoIterator<Item = &'a str>) -> Self {
        let verifying_keys = pem_iter
            .into_iter()
            .filter_map(|pem| parse_rsa_verifying_key(pem).ok())
            .map(Arc::new)
            .collect();
        Self { verifying_keys }
    }

    /// Validate an AWS PKCS1v15 signature against the bundled regional
    /// certificates.
    pub(crate) async fn verify(
        &self,
        document: &str,
        signature_b64: &str,
    ) -> Result<VerifiedInstance, VerifyError> {
        // Structural: the document must parse as JSON and declare an
        // `instanceId`. This is checked even before the signature so that
        // a request with a blatantly malformed document still returns 400
        // rather than 401 (matches the existing behaviour of the stubbed
        // handler plus the Go reference).
        let doc: serde_json::Value = serde_json::from_str(document)
            .map_err(|e| VerifyError::InvalidRequest(format!("malformed JSON: {e}")))?;
        let instance_id = doc
            .get("instanceId")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| VerifyError::InvalidRequest("missing instanceId".to_owned()))?
            .to_owned();

        if self.verifying_keys.is_empty() {
            return Err(VerifyError::VerificationFailed);
        }

        let raw_signature = base64::engine::general_purpose::STANDARD
            .decode(signature_b64.trim())
            .map_err(|_| VerifyError::VerificationFailed)?;
        let signature = Signature::try_from(raw_signature.as_slice())
            .map_err(|_| VerifyError::VerificationFailed)?;

        for key in &self.verifying_keys {
            if key.verify(document.as_bytes(), &signature).is_ok() {
                return Ok(VerifiedInstance { instance_id });
            }
        }
        Err(VerifyError::VerificationFailed)
    }
}

/// Extract an RSA verifying key from a PEM-encoded X.509 certificate.
fn parse_rsa_verifying_key(pem: &str) -> Result<VerifyingKey<Sha256>, String> {
    let (_, pem_block) = parse_x509_pem(pem.as_bytes()).map_err(|e| e.to_string())?;
    let cert = pem_block
        .parse_x509()
        .map_err(|e| format!("parse X.509: {e}"))?;
    let spki = cert.public_key();
    let parsed = spki.parsed().map_err(|e| format!("parsed spki: {e}"))?;
    let PublicKey::RSA(rsa_key) = parsed else {
        return Err("certificate public key is not RSA".to_owned());
    };
    let modulus = rsa::BigUint::from_bytes_be(rsa_key.modulus);
    let exponent = rsa::BigUint::from_bytes_be(rsa_key.exponent);
    let rsa_pub =
        RsaPublicKey::new(modulus, exponent).map_err(|e| format!("build rsa key: {e}"))?;
    Ok(VerifyingKey::<Sha256>::new(rsa_pub))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::RsaPrivateKey;
    use rsa::pkcs1v15::SigningKey;
    use rsa::signature::{Keypair, RandomizedSigner, SignatureEncoding};
    use std::error::Error;

    type TestResult = Result<(), Box<dyn Error>>;

    fn verifier_with_key(key: VerifyingKey<Sha256>) -> AwsInstanceVerifier {
        AwsInstanceVerifier {
            verifying_keys: vec![Arc::new(key)],
        }
    }

    fn generate_keys() -> Result<(SigningKey<Sha256>, VerifyingKey<Sha256>), Box<dyn Error>> {
        let mut rng = rand::thread_rng();
        let priv_key = RsaPrivateKey::new(&mut rng, 2048)
            .map_err(|e| -> Box<dyn Error> { e.to_string().into() })?;
        let signing_key = SigningKey::<Sha256>::new(priv_key);
        let verifying_key = signing_key.verifying_key();
        Ok((signing_key, verifying_key))
    }

    fn assert_verification_failed<T: std::fmt::Debug>(
        result: Result<T, VerifyError>,
    ) -> Result<(), Box<dyn Error>> {
        match result {
            Err(VerifyError::VerificationFailed) => Ok(()),
            other => Err(format!("expected VerificationFailed, got {other:?}").into()),
        }
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
    async fn verify_valid_signature_returns_instance_id() -> TestResult {
        let (signing_key, verifying_key) = generate_keys()?;
        let verifier = verifier_with_key(verifying_key);

        let document = r#"{"instanceId":"i-abc","region":"us-east-1"}"#;
        let signature = signing_key.sign_with_rng(&mut rand::thread_rng(), document.as_bytes());
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

        let out = verifier
            .verify(document, &signature_b64)
            .await
            .map_err(|e| -> Box<dyn Error> { e.to_string().into() })?;
        assert_eq!(out.instance_id, "i-abc");
        Ok(())
    }

    #[tokio::test]
    async fn verify_invalid_signature_returns_verification_failed() -> TestResult {
        let (_signing_key, verifying_key) = generate_keys()?;
        let (other_signing, _other_verifying) = generate_keys()?;
        let verifier = verifier_with_key(verifying_key);

        let document = r#"{"instanceId":"i-abc"}"#;
        let signature = other_signing.sign_with_rng(&mut rand::thread_rng(), document.as_bytes());
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

        assert_verification_failed(verifier.verify(document, &signature_b64).await)
    }

    #[tokio::test]
    async fn verify_malformed_json_returns_invalid_request() -> TestResult {
        let (_signing_key, verifying_key) = generate_keys()?;
        let verifier = verifier_with_key(verifying_key);

        assert_invalid_request(verifier.verify("not json", "AAAA").await)
    }

    #[tokio::test]
    async fn verify_missing_instance_id_returns_invalid_request() -> TestResult {
        let (_signing_key, verifying_key) = generate_keys()?;
        let verifier = verifier_with_key(verifying_key);

        assert_invalid_request(verifier.verify("{}", "AAAA").await)
    }

    #[tokio::test]
    async fn verify_non_base64_signature_returns_verification_failed() -> TestResult {
        let (_signing_key, verifying_key) = generate_keys()?;
        let verifier = verifier_with_key(verifying_key);

        assert_verification_failed(
            verifier
                .verify(r#"{"instanceId":"i-abc"}"#, "not-base64$$$")
                .await,
        )
    }

    #[tokio::test]
    async fn verifier_with_empty_keys_rejects_signature() -> TestResult {
        let verifier = AwsInstanceVerifier {
            verifying_keys: Vec::new(),
        };
        assert_verification_failed(verifier.verify(r#"{"instanceId":"i-abc"}"#, "AAAA").await)
    }

    #[test]
    fn parses_bundled_default_certificates() {
        let verifier = AwsInstanceVerifier::with_default_certificates();
        assert_eq!(verifier.verifying_keys.len(), DEFAULT_CERTIFICATES.len());
    }

    #[test]
    fn parse_rsa_verifying_key_rejects_non_pem_input() {
        assert!(parse_rsa_verifying_key("not a cert").is_err());
    }
}
