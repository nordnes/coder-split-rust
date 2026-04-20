//! Signed-token issuance and verification for reconnecting-PTY websocket
//! upgrades.
//!
//! Workspace-app proxies that relay PTY traffic for the control plane need a
//! short-lived capability token that proves the proxy is authorized to open a
//! PTY websocket against a particular workspace agent. The control plane mints
//! a token by signing the tuple `(workspace_id, agent_id, exp_unix)` with its
//! app signing key; the relay (or a test caller) later presents that token on
//! the websocket upgrade request. The PTY handler re-derives the signature
//! and checks for equality in constant time.
//!
//! Go reference: `enterprise/wsproxy/tokenprovider.go` — specifically the
//! `ReconnectingPTY` signed-token provider wired in
//! `coder/coderd/coderd.go`. The Rust backend currently only consumes the
//! token; issuance is offered for completeness and integration tests.
//!
//! The token format is deliberately simple — it is not a JWT. The string
//!
//! ```text
//! base64url(workspace_id.agent_id.exp_unix).base64url(hmac_sha256(key, msg))
//! ```
//!
//! is compact enough to carry in a query parameter, avoids a heavy JWT
//! dependency, and keeps the failure modes (bad format, bad signature,
//! expired, mismatched binding) explicit.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// Errors returned by [`verify_signed_token`].
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum VerifyError {
    /// The token does not have the expected `payload.signature` shape.
    #[error("malformed reconnecting-PTY token")]
    Malformed,
    /// The encoded payload or signature was not valid base64url.
    #[error("invalid base64 in reconnecting-PTY token")]
    InvalidEncoding,
    /// The payload did not have three dot-separated components.
    #[error("invalid reconnecting-PTY token payload")]
    InvalidPayload,
    /// A payload component was not a valid UUID or i64 exp.
    #[error("invalid reconnecting-PTY token field: {0}")]
    InvalidField(&'static str),
    /// The token binds a different workspace or agent than the caller.
    #[error("reconnecting-PTY token binding mismatch")]
    BindingMismatch,
    /// The token's expiry is in the past.
    #[error("reconnecting-PTY token expired")]
    Expired,
    /// The HMAC signature did not validate.
    #[error("reconnecting-PTY token signature mismatch")]
    SignatureMismatch,
}

/// Issuer for reconnecting-PTY signed tokens. Carries the deployment's
/// 32-byte app signing key (shared with workspace-app JWTs).
#[derive(Clone, Debug)]
pub struct ReconnectingPtyTokenSigner {
    key: Vec<u8>,
}

impl ReconnectingPtyTokenSigner {
    /// Constructs a new signer with the given raw signing key. The key must
    /// be kept secret by the control plane and the proxy.
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }

    /// Mints a signed token binding `workspace_id`, `agent_id`, and an
    /// absolute expiry Unix timestamp.
    ///
    /// The returned string is safe to carry in a query parameter or HTTP
    /// header because it is base64url (no padding) on both halves.
    #[must_use]
    pub fn sign(&self, workspace_id: Uuid, agent_id: Uuid, exp_unix: i64) -> String {
        let payload = format!("{workspace_id}.{agent_id}.{exp_unix}");
        let mac = compute_mac(&self.key, payload.as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(mac);
        format!("{payload_b64}.{sig_b64}")
    }

    /// Returns the raw key for verification helpers that accept a key slice.
    #[must_use]
    pub fn key(&self) -> &[u8] {
        &self.key
    }
}

/// Verifies a signed reconnecting-PTY token against the caller's claimed
/// `workspace_id` and `agent_id`, and checks the expiry against `now_unix`.
///
/// Performs constant-time signature comparison via the `subtle` crate.
pub fn verify_signed_token(
    key: &[u8],
    token: &str,
    workspace_id: Uuid,
    agent_id: Uuid,
    now_unix: i64,
) -> Result<(), VerifyError> {
    // A token is `payload_b64.signature_b64`. Split on the final dot to
    // tolerate any future evolution that re-uses the inner dot structure.
    let (payload_b64, sig_b64) = token.rsplit_once('.').ok_or(VerifyError::Malformed)?;
    if payload_b64.is_empty() || sig_b64.is_empty() {
        return Err(VerifyError::Malformed);
    }
    let payload = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| VerifyError::InvalidEncoding)?;
    let provided_sig = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| VerifyError::InvalidEncoding)?;

    // Recompute the expected signature over the raw payload bytes and
    // compare in constant time.
    let expected = compute_mac(key, &payload);
    if provided_sig.ct_eq(&expected).unwrap_u8() != 1 {
        return Err(VerifyError::SignatureMismatch);
    }

    // Only after the signature check do we parse the payload contents. This
    // avoids exposing oracle-style differences between malformed and
    // tampered payloads.
    let payload_str = std::str::from_utf8(&payload).map_err(|_| VerifyError::InvalidPayload)?;
    let mut parts = payload_str.split('.');
    let workspace_part = parts.next().ok_or(VerifyError::InvalidPayload)?;
    let agent_part = parts.next().ok_or(VerifyError::InvalidPayload)?;
    let exp_part = parts.next().ok_or(VerifyError::InvalidPayload)?;
    if parts.next().is_some() {
        return Err(VerifyError::InvalidPayload);
    }

    let ws_claim =
        Uuid::parse_str(workspace_part).map_err(|_| VerifyError::InvalidField("workspace_id"))?;
    let agent_claim =
        Uuid::parse_str(agent_part).map_err(|_| VerifyError::InvalidField("agent_id"))?;
    let exp: i64 = exp_part
        .parse()
        .map_err(|_| VerifyError::InvalidField("exp"))?;

    if ws_claim != workspace_id || agent_claim != agent_id {
        return Err(VerifyError::BindingMismatch);
    }
    if exp <= now_unix {
        return Err(VerifyError::Expired);
    }
    Ok(())
}

fn compute_mac(key: &[u8], msg: &[u8]) -> Vec<u8> {
    // `Hmac::new_from_slice` only fails for zero-length keys in some
    // backends; in practice the ring/sha2-based `Hmac` accepts any key
    // length. We treat an empty key as producing an all-zero-derived MAC
    // which will still fail verification downstream, so we accept any key
    // length here without panicking.
    let mut mac = match HmacSha256::new_from_slice(key) {
        Ok(m) => m,
        Err(_) => {
            // Fall back to a single-byte key so we still produce a MAC.
            // An all-zeros key is still never valid against a real key, so
            // verification will still fail securely.
            match HmacSha256::new_from_slice(&[0u8]) {
                Ok(m) => m,
                Err(_) => return Vec::new(),
            }
        }
    };
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const KEY: &[u8; 32] = b"0123456789abcdef0123456789abcdef";

    fn now() -> i64 {
        // Fixed reference time so the test is hermetic.
        1_700_000_000
    }

    #[test]
    fn signed_token_roundtrip() {
        let signer = ReconnectingPtyTokenSigner::new(KEY);
        let ws = Uuid::new_v4();
        let agent = Uuid::new_v4();
        let exp = now() + 60;
        let token = signer.sign(ws, agent, exp);
        assert!(
            verify_signed_token(signer.key(), &token, ws, agent, now()).is_ok(),
            "valid token should verify"
        );
    }

    #[test]
    fn signed_token_rejects_wrong_workspace() {
        let signer = ReconnectingPtyTokenSigner::new(KEY);
        let ws_a = Uuid::new_v4();
        let ws_b = Uuid::new_v4();
        let agent = Uuid::new_v4();
        let token = signer.sign(ws_a, agent, now() + 60);
        let err = verify_signed_token(signer.key(), &token, ws_b, agent, now()).unwrap_err();
        assert_eq!(err, VerifyError::BindingMismatch);
    }

    #[test]
    fn signed_token_rejects_expired() {
        let signer = ReconnectingPtyTokenSigner::new(KEY);
        let ws = Uuid::new_v4();
        let agent = Uuid::new_v4();
        let token = signer.sign(ws, agent, now() - 1);
        let err = verify_signed_token(signer.key(), &token, ws, agent, now()).unwrap_err();
        assert_eq!(err, VerifyError::Expired);
    }

    #[test]
    fn signed_token_rejects_tampered() {
        let signer = ReconnectingPtyTokenSigner::new(KEY);
        let ws = Uuid::new_v4();
        let agent = Uuid::new_v4();
        let token = signer.sign(ws, agent, now() + 60);
        // Flip a single character in the signature half. `rsplit_once('.')`
        // returns (payload, sig); the signature is the second half.
        let mut tampered = token.clone();
        let last = tampered.pop().unwrap();
        // Replace with a different base64url character so the resulting
        // signature decodes but won't match.
        let replacement = if last == 'A' { 'B' } else { 'A' };
        tampered.push(replacement);
        let err = verify_signed_token(signer.key(), &tampered, ws, agent, now()).unwrap_err();
        assert_eq!(err, VerifyError::SignatureMismatch);
    }

    #[test]
    fn signed_token_rejects_malformed() {
        let err = verify_signed_token(KEY, "not-a-token", Uuid::new_v4(), Uuid::new_v4(), now())
            .unwrap_err();
        assert_eq!(err, VerifyError::Malformed);
    }

    #[test]
    fn signed_token_rejects_empty_halves() {
        let err = verify_signed_token(KEY, ".", Uuid::new_v4(), Uuid::new_v4(), now()).unwrap_err();
        assert_eq!(err, VerifyError::Malformed);
    }
}
