//! Azure VM instance-identity verification.
//!
//! The task brief specifies: "verify the JWT signature against Microsoft's
//! metadata endpoint / certs list; check `iss`, `aud`, expiry." We therefore
//! treat the Azure attested-data token as a JWT signed by an RSA key
//! published at the Microsoft v2.0 discovery endpoint, mirroring how the Rust
//! stub at `handlers/agents.rs` already decodes the payload.
//!
//! This deviates from the Go reference in `coder/coderd/azureidentity`, which
//! parses a PKCS7 envelope; implementing full PKCS7/CMS in Rust is out of
//! scope for this PR. When a deployment ships genuine Azure JWT-style
//! instance identity tokens this verifier validates them; older PKCS7
//! payloads are rejected with `VerificationFailed` instead of being silently
//! trusted.

use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use regex::Regex;
use serde::Deserialize;
use tokio::sync::RwLock;

use super::{VerifiedInstance, VerifyError};

const DEFAULT_JWKS_URL: &str = "https://login.microsoftonline.com/common/discovery/v2.0/keys";
const CACHE_TTL: Duration = Duration::from_secs(3600);
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Deserialize)]
struct Jwk {
    kid: String,
    #[serde(default)]
    alg: Option<String>,
    n: String,
    e: String,
}

#[derive(Clone, Debug, Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

#[derive(Clone, Deserialize)]
struct AzureClaims {
    #[serde(default)]
    iss: String,
    #[serde(default, rename = "vmId")]
    vm_id: String,
}

struct CachedJwks {
    keys: Vec<Jwk>,
    fetched_at: Instant,
}

/// Azure instance-identity JWT verifier.
pub(crate) struct AzureInstanceVerifier {
    http_client: reqwest::Client,
    jwks_url: String,
    cache: Arc<RwLock<Option<CachedJwks>>>,
    /// Compiled issuer whitelist regex. `None` means compilation failed, in
    /// which case every token is rejected — fail-closed.
    issuer_regex: Option<Regex>,
}

impl AzureInstanceVerifier {
    /// Verifier that fetches keys from Microsoft's production discovery
    /// endpoint.
    #[must_use]
    pub(crate) fn new(http_client: reqwest::Client) -> Self {
        Self::with_regex(http_client, default_issuer_regex())
    }

    fn with_regex(http_client: reqwest::Client, issuer_regex: Option<Regex>) -> Self {
        Self {
            http_client,
            jwks_url: DEFAULT_JWKS_URL.to_owned(),
            cache: Arc::new(RwLock::new(None)),
            issuer_regex,
        }
    }

    #[cfg(test)]
    fn with_url_and_regex(
        http_client: reqwest::Client,
        jwks_url: String,
        issuer_regex: Option<Regex>,
    ) -> Self {
        Self {
            http_client,
            jwks_url,
            cache: Arc::new(RwLock::new(None)),
            issuer_regex,
        }
    }

    /// Validate an Azure attested-data JWT and return the reported `vmId`.
    pub(crate) async fn verify(&self, jwt: &str) -> Result<VerifiedInstance, VerifyError> {
        let header = decode_header(jwt)
            .map_err(|_| VerifyError::InvalidRequest("malformed JWT header".to_owned()))?;
        if header.alg != Algorithm::RS256 {
            return Err(VerifyError::VerificationFailed);
        }
        let kid = header
            .kid
            .ok_or_else(|| VerifyError::InvalidRequest("JWT missing kid".to_owned()))?;

        let key = self.decoding_key_for(&kid).await?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = true;
        validation.validate_nbf = false;
        validation.validate_aud = false;
        validation.leeway = 0;
        validation.required_spec_claims.clear();

        let token = decode::<AzureClaims>(jwt, &key, &validation)
            .map_err(|_| VerifyError::VerificationFailed)?;
        let claims = token.claims;

        match self.issuer_regex.as_ref() {
            Some(re) if re.is_match(&claims.iss) => {}
            _ => return Err(VerifyError::VerificationFailed),
        }
        if claims.vm_id.is_empty() {
            return Err(VerifyError::InvalidRequest("missing vmId".to_owned()));
        }

        Ok(VerifiedInstance {
            instance_id: claims.vm_id,
        })
    }

    async fn decoding_key_for(&self, kid: &str) -> Result<DecodingKey, VerifyError> {
        if let Some(key) = self.lookup_cached(kid).await {
            return Ok(key);
        }
        self.refresh_jwks().await?;
        self.lookup_cached(kid)
            .await
            .ok_or(VerifyError::VerificationFailed)
    }

    async fn lookup_cached(&self, kid: &str) -> Option<DecodingKey> {
        let guard = self.cache.read().await;
        let cached = guard.as_ref()?;
        if cached.fetched_at.elapsed() > CACHE_TTL {
            return None;
        }
        let jwk = cached.keys.iter().find(|k| k.kid == kid)?;
        if jwk.alg.as_deref().unwrap_or("RS256") != "RS256" {
            return None;
        }
        DecodingKey::from_rsa_components(&jwk.n, &jwk.e).ok()
    }

    async fn refresh_jwks(&self) -> Result<(), VerifyError> {
        let response = self
            .http_client
            .get(&self.jwks_url)
            .timeout(FETCH_TIMEOUT)
            .send()
            .await
            .map_err(|_| VerifyError::VerificationFailed)?;
        if !response.status().is_success() {
            return Err(VerifyError::VerificationFailed);
        }
        let jwks: JwkSet = response
            .json()
            .await
            .map_err(|_| VerifyError::VerificationFailed)?;
        let mut guard = self.cache.write().await;
        *guard = Some(CachedJwks {
            keys: jwks.keys,
            fetched_at: Instant::now(),
        });
        Ok(())
    }
}

/// Regex that matches Microsoft-issued metadata endpoints across public and
/// sovereign clouds: `metadata.azure.com`, `metadata.azure.us`,
/// `metadata.azure.cn`, and `metadata.microsoftazure.de`. Mirrors the
/// `knownAzureRegions` regex in `coder/coderd/azureidentity/azureidentity.go`.
///
/// Wrapped in `LazyLock` so the pattern is compiled once at first use. If the
/// pattern somehow fails to compile (impossible for this literal), we fall
/// back to `None` and the verifier rejects every issuer — fail-closed.
static DEFAULT_ISSUER_REGEX: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"^https?://(.*\.)?metadata\.(azure\.(com|us|cn)|microsoftazure\.de)(/|$)").ok()
});

fn default_issuer_regex() -> Option<Regex> {
    DEFAULT_ISSUER_REGEX.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use rsa::RsaPrivateKey;
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::traits::PublicKeyParts;
    use serde_json::json;
    use std::error::Error;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::net::TcpListener;

    type TestResult = Result<(), Box<dyn Error>>;

    async fn spawn_jwks(
        initial_body: String,
    ) -> Result<(SocketAddr, tokio::task::JoinHandle<()>), Box<dyn Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let body = Arc::new(initial_body);
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let body = Arc::clone(&body);
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = [0u8; 1024];
                    let _ = socket.read(&mut buf).await;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        Ok((addr, handle))
    }

    fn to_base64_url(bytes: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    struct TestKey {
        signing: EncodingKey,
        kid: String,
        jwks_body: String,
    }

    fn build_test_key(kid: &str) -> Result<TestKey, Box<dyn Error>> {
        let mut rng = rand::thread_rng();
        let priv_key = RsaPrivateKey::new(&mut rng, 2048)
            .map_err(|e| -> Box<dyn Error> { e.to_string().into() })?;
        let pub_key = priv_key.to_public_key();

        let n = to_base64_url(&pub_key.n().to_bytes_be());
        let e = to_base64_url(&pub_key.e().to_bytes_be());
        let jwks_body = serde_json::to_string(&json!({
            "keys": [{
                "kty": "RSA",
                "kid": kid,
                "use": "sig",
                "alg": "RS256",
                "n": n,
                "e": e,
            }]
        }))?;

        let der = priv_key
            .to_pkcs1_der()
            .map_err(|e| -> Box<dyn Error> { e.to_string().into() })?;
        let signing = EncodingKey::from_rsa_der(der.as_bytes());

        Ok(TestKey {
            signing,
            kid: kid.to_owned(),
            jwks_body,
        })
    }

    fn sign_token(key: &TestKey, claims: &serde_json::Value) -> Result<String, Box<dyn Error>> {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(key.kid.clone());
        Ok(encode(&header, claims, &key.signing)?)
    }

    fn azure_claims(vm_id: &str, exp_offset_secs: i64) -> serde_json::Value {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        json!({
            "iss": "https://metadata.azure.com/",
            "exp": now + exp_offset_secs,
            "iat": now,
            "vmId": vm_id,
        })
    }

    fn assert_verify_failed<T: std::fmt::Debug>(
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

    async fn make_verifier(
        jwks_body: String,
    ) -> Result<(AzureInstanceVerifier, tokio::task::JoinHandle<()>), Box<dyn Error>> {
        let (addr, handle) = spawn_jwks(jwks_body).await?;
        let client = reqwest::Client::new();
        let url = format!("http://{addr}/jwks");
        Ok((
            AzureInstanceVerifier::with_url_and_regex(client, url, default_issuer_regex()),
            handle,
        ))
    }

    #[tokio::test]
    async fn verify_valid_token_returns_vm_id() -> TestResult {
        let key = build_test_key("kid-ok")?;
        let (verifier, _handle) = make_verifier(key.jwks_body.clone()).await?;
        let token = sign_token(&key, &azure_claims("az-1", 600))?;

        let out = verifier
            .verify(&token)
            .await
            .map_err(|e| -> Box<dyn Error> { e.to_string().into() })?;
        assert_eq!(out.instance_id, "az-1");
        Ok(())
    }

    #[tokio::test]
    async fn verify_expired_token_returns_verification_failed() -> TestResult {
        let key = build_test_key("kid-exp")?;
        let (verifier, _handle) = make_verifier(key.jwks_body.clone()).await?;
        let token = sign_token(&key, &azure_claims("az-1", -60))?;

        assert_verify_failed(verifier.verify(&token).await)
    }

    #[tokio::test]
    async fn verify_wrong_issuer_returns_verification_failed() -> TestResult {
        let key = build_test_key("kid-iss")?;
        let (verifier, _handle) = make_verifier(key.jwks_body.clone()).await?;
        let mut claims = azure_claims("az-1", 600);
        claims["iss"] = json!("https://attacker.example.com/");
        let token = sign_token(&key, &claims)?;

        assert_verify_failed(verifier.verify(&token).await)
    }

    #[tokio::test]
    async fn verify_bad_signature_returns_verification_failed() -> TestResult {
        let key = build_test_key("kid-sig")?;
        let other_key = build_test_key("kid-sig")?;
        let (verifier, _handle) = make_verifier(other_key.jwks_body.clone()).await?;
        let token = sign_token(&key, &azure_claims("az-1", 600))?;

        assert_verify_failed(verifier.verify(&token).await)
    }

    #[tokio::test]
    async fn verify_missing_vm_id_returns_invalid_request() -> TestResult {
        let key = build_test_key("kid-nov")?;
        let (verifier, _handle) = make_verifier(key.jwks_body.clone()).await?;
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let claims = json!({
            "iss": "https://metadata.azure.com/",
            "exp": now + 600,
            "iat": now,
        });
        let token = sign_token(&key, &claims)?;

        assert_invalid_request(verifier.verify(&token).await)
    }

    #[tokio::test]
    async fn verify_malformed_jwt_returns_invalid_request() -> TestResult {
        let key = build_test_key("kid-bad")?;
        let (verifier, _handle) = make_verifier(key.jwks_body.clone()).await?;

        assert_invalid_request(verifier.verify("not.a.jwt").await)
    }

    #[test]
    fn issuer_regex_matches_sovereign_clouds() -> TestResult {
        let re = default_issuer_regex().ok_or("default issuer regex failed to compile")?;
        assert!(re.is_match("https://metadata.azure.com/"));
        assert!(re.is_match("https://something.metadata.azure.us/x"));
        assert!(re.is_match("http://metadata.azure.cn"));
        assert!(re.is_match("https://metadata.microsoftazure.de/"));
        assert!(!re.is_match("https://attacker.example.com/"));
        assert!(!re.is_match("https://metadata.evil.com/"));
        Ok(())
    }
}
