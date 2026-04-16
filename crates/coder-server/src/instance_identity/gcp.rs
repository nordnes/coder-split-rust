//! GCP instance-identity (compute-engine signed token) verification.
//!
//! Google publishes the signing keys for Compute Engine identity tokens at
//! `https://www.googleapis.com/oauth2/v3/certs` as a JWKS document. We fetch
//! and cache the document with a short TTL so the request hot path never
//! performs a synchronous outbound HTTP call.
//!
//! The JWT is a standard RS256 token. We validate the signature, the `iss`
//! claim (`https://accounts.google.com` or `accounts.google.com`), and the
//! expiry, then extract `google.compute_engine.instance_id` from the body.
//!
//! Ports the Google identity verification in
//! `coder/coderd/workspaceresourceauth.go` which uses
//! `idtoken.NewValidator` from the `google.golang.org/api/idtoken` library.

use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use tokio::sync::RwLock;

use super::{VerifiedInstance, VerifyError};

const DEFAULT_JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";
const CACHE_TTL: Duration = Duration::from_secs(3600);
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
const ALLOWED_ISSUERS: &[&str] = &["https://accounts.google.com", "accounts.google.com"];

/// Subset of a JWK relevant to RS256 verification.
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
struct GoogleClaims {
    #[serde(default)]
    iss: String,
    #[serde(default)]
    google: Option<GoogleBlock>,
}

#[derive(Clone, Deserialize)]
struct GoogleBlock {
    #[serde(default)]
    compute_engine: Option<ComputeEngineBlock>,
}

#[derive(Clone, Deserialize)]
struct ComputeEngineBlock {
    #[serde(default)]
    instance_id: String,
}

struct CachedJwks {
    keys: Vec<Jwk>,
    fetched_at: Instant,
}

/// GCP instance-identity JWT verifier.
pub(crate) struct GcpInstanceVerifier {
    http_client: reqwest::Client,
    jwks_url: String,
    cache: Arc<RwLock<Option<CachedJwks>>>,
    audience: Option<String>,
}

impl GcpInstanceVerifier {
    /// Verifier that fetches keys from Google's production JWKS endpoint.
    #[must_use]
    pub(crate) fn new(http_client: reqwest::Client) -> Self {
        Self {
            http_client,
            jwks_url: DEFAULT_JWKS_URL.to_owned(),
            cache: Arc::new(RwLock::new(None)),
            audience: None,
        }
    }

    /// Verifier for unit tests: uses a caller-supplied URL for the key set.
    #[cfg(test)]
    fn with_url(http_client: reqwest::Client, jwks_url: String) -> Self {
        Self {
            http_client,
            jwks_url,
            cache: Arc::new(RwLock::new(None)),
            audience: None,
        }
    }

    /// Validate a GCP identity JWT and return the compute-engine `instance_id`.
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
        validation.leeway = 0;
        validation.required_spec_claims.clear();
        validation.set_issuer(ALLOWED_ISSUERS);
        if let Some(aud) = &self.audience {
            validation.set_audience(&[aud]);
        } else {
            validation.validate_aud = false;
        }

        let token = decode::<GoogleClaims>(jwt, &key, &validation)
            .map_err(|_| VerifyError::VerificationFailed)?;
        let claims = token.claims;

        if !ALLOWED_ISSUERS.contains(&claims.iss.as_str()) {
            return Err(VerifyError::VerificationFailed);
        }
        let instance_id = claims
            .google
            .and_then(|g| g.compute_engine)
            .map(|c| c.instance_id)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                VerifyError::InvalidRequest("missing google.compute_engine.instance_id".to_owned())
            })?;

        Ok(VerifiedInstance { instance_id })
    }

    /// Fetch (or return cached) RSA decoding key for the given `kid`.
    async fn decoding_key_for(&self, kid: &str) -> Result<DecodingKey, VerifyError> {
        // Fast path: return from cache if still fresh.
        if let Some(key) = self.lookup_cached(kid).await {
            return Ok(key);
        }
        // Slow path: refresh the JWKS and try again.
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
    use tokio::net::TcpListener;

    type TestResult = Result<(), Box<dyn Error>>;

    /// Spawn an HTTP server that serves the JWKS body on every request.
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

        let pem_der = priv_key
            .to_pkcs1_der()
            .map_err(|e| -> Box<dyn Error> { e.to_string().into() })?;
        let signing = EncodingKey::from_rsa_der(pem_der.as_bytes());

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

    fn gcp_claims(instance_id: &str, exp_offset_secs: i64) -> serde_json::Value {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        json!({
            "iss": "https://accounts.google.com",
            "aud": "coder",
            "exp": now + exp_offset_secs,
            "iat": now,
            "google": {
                "compute_engine": {
                    "instance_id": instance_id,
                    "instance_name": "example",
                    "project_id": "proj",
                    "zone": "us-central1-a",
                }
            }
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

    fn verifier_for(addr: SocketAddr) -> GcpInstanceVerifier {
        let client = reqwest::Client::new();
        let url = format!("http://{addr}/jwks");
        GcpInstanceVerifier::with_url(client, url)
    }

    async fn make_verifier(
        jwks_body: String,
    ) -> Result<(GcpInstanceVerifier, tokio::task::JoinHandle<()>), Box<dyn Error>> {
        let (addr, handle) = spawn_jwks(jwks_body).await?;
        Ok((verifier_for(addr), handle))
    }

    #[tokio::test]
    async fn verify_valid_token_returns_instance_id() -> TestResult {
        let key = build_test_key("kid-ok")?;
        let (verifier, _handle) = make_verifier(key.jwks_body.clone()).await?;
        let token = sign_token(&key, &gcp_claims("gce-1", 600))?;

        let out = verifier
            .verify(&token)
            .await
            .map_err(|e| -> Box<dyn Error> { e.to_string().into() })?;
        assert_eq!(out.instance_id, "gce-1");
        Ok(())
    }

    #[tokio::test]
    async fn verify_expired_token_returns_verification_failed() -> TestResult {
        let key = build_test_key("kid-exp")?;
        let (verifier, _handle) = make_verifier(key.jwks_body.clone()).await?;
        let token = sign_token(&key, &gcp_claims("gce-1", -60))?;

        assert_verify_failed(verifier.verify(&token).await)
    }

    #[tokio::test]
    async fn verify_wrong_issuer_returns_verification_failed() -> TestResult {
        let key = build_test_key("kid-iss")?;
        let (verifier, _handle) = make_verifier(key.jwks_body.clone()).await?;
        let mut claims = gcp_claims("gce-1", 600);
        claims["iss"] = json!("evil.example.com");
        let token = sign_token(&key, &claims)?;

        assert_verify_failed(verifier.verify(&token).await)
    }

    #[tokio::test]
    async fn verify_bad_signature_returns_verification_failed() -> TestResult {
        let key = build_test_key("kid-sig")?;
        let other_key = build_test_key("kid-sig")?; // reuse kid, different key
        let (verifier, _handle) = make_verifier(other_key.jwks_body.clone()).await?;
        let token = sign_token(&key, &gcp_claims("gce-1", 600))?;

        assert_verify_failed(verifier.verify(&token).await)
    }

    #[tokio::test]
    async fn verify_missing_instance_id_returns_invalid_request() -> TestResult {
        let key = build_test_key("kid-noid")?;
        let (verifier, _handle) = make_verifier(key.jwks_body.clone()).await?;
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let claims = json!({
            "iss": "https://accounts.google.com",
            "exp": now + 600,
            "iat": now,
            "google": {}
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
}
