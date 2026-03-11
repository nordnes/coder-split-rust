//! JWT license token parsing and validation.
//!
//! Mirrors Go's `enterprise/coderd/license/license.go` — specifically the
//! `Claims`, `ParseClaims`, and `validateClaims` functions.

use std::collections::HashMap;

use jsonwebtoken::{DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;

/// Current license schema version that must be present in the claims.
pub(crate) const CURRENT_VERSION: u64 = 3;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during license parsing or validation.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum LicenseError {
    /// The JWT could not be decoded.
    #[error("invalid license token: {0}")]
    InvalidToken(String),
    /// The license version is not supported.
    #[error("license must be version {CURRENT_VERSION}")]
    InvalidVersion,
    /// A required claim is missing or malformed.
    #[error("license has invalid or missing claim: {0}")]
    MissingClaim(String),
    /// The license has expired (past the grace period).
    #[error("license has expired")]
    Expired,
    /// No signing key matched the `kid` header.
    #[error("no key with ID {0}")]
    UnknownKeyId(String),
}

// ---------------------------------------------------------------------------
// License claims
// ---------------------------------------------------------------------------

/// Feature set enum — determines which features a license grants.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeatureSet {
    /// No feature set — features must be granted individually.
    #[default]
    #[serde(rename = "")]
    None,
    /// Enterprise feature set.
    Enterprise,
    /// Premium feature set (superset of Enterprise).
    Premium,
}

/// JWT claims embedded in a Coder license token.
///
/// Matches Go's `license.Claims` struct.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LicenseClaims {
    /// Standard JWT `iss` (issuer).
    #[serde(default)]
    pub iss: String,
    /// Standard JWT `sub` (subject).
    #[serde(default)]
    pub sub: String,
    /// Standard JWT `aud` (audience).
    #[serde(default)]
    pub aud: serde_json::Value,
    /// Standard JWT `exp` (expires at) — end of grace period, as a UNIX
    /// timestamp.
    #[serde(default)]
    pub exp: i64,
    /// Standard JWT `nbf` (not before) — start of validity, as a UNIX
    /// timestamp.
    #[serde(default)]
    pub nbf: i64,
    /// Standard JWT `iat` (issued at), as a UNIX timestamp.
    #[serde(default)]
    pub iat: i64,
    /// Standard JWT `jti` (JWT ID).
    #[serde(default)]
    pub jti: String,

    /// End of the legitimate license term (start of grace period), as a
    /// UNIX timestamp.
    #[serde(default)]
    pub license_expires: i64,
    /// Account type (e.g. `"salesforce"`).
    #[serde(default)]
    pub account_type: String,
    /// Account identifier.
    #[serde(default)]
    pub account_id: String,
    /// Whether this is a trial license.
    #[serde(default)]
    pub trial: bool,
    /// Feature set granted by this license.
    #[serde(default)]
    pub feature_set: FeatureSet,
    /// Legacy "all features" flag, superseded by `feature_set`.
    #[serde(default)]
    pub all_features: bool,
    /// Schema version — must equal [`CURRENT_VERSION`].
    #[serde(default)]
    pub version: u64,
    /// Per-feature numeric values (limits / enablement).
    #[serde(default)]
    pub features: HashMap<String, i64>,
    /// Whether telemetry is required.
    #[serde(default)]
    pub require_telemetry: bool,
    /// Deployment ID restrictions (empty = any deployment).
    #[serde(default)]
    pub deployment_ids: Vec<String>,
}

impl LicenseClaims {
    /// Returns the license expiry time (start of grace period).
    #[must_use]
    pub fn license_expires_at(&self) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(self.license_expires)
            .unwrap_or(OffsetDateTime::UNIX_EPOCH)
    }

    /// Returns the full expiry time (end of grace period, i.e. `exp`).
    #[must_use]
    pub fn grace_period_end(&self) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(self.exp).unwrap_or(OffsetDateTime::UNIX_EPOCH)
    }

    /// Returns the not-before time.
    #[must_use]
    pub fn not_before(&self) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(self.nbf).unwrap_or(OffsetDateTime::UNIX_EPOCH)
    }

    /// Returns the issued-at time.
    #[must_use]
    pub fn issued_at(&self) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(self.iat).unwrap_or(OffsetDateTime::UNIX_EPOCH)
    }

    /// Returns `true` if `now` is past the license expiry but still within
    /// the grace period.
    #[must_use]
    pub fn in_grace_period(&self, now: OffsetDateTime) -> bool {
        now > self.license_expires_at() && now <= self.grace_period_end()
    }

    /// Returns `true` if `now` is past the end of the grace period.
    #[must_use]
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        now > self.grace_period_end()
    }
}

// ---------------------------------------------------------------------------
// Validator
// ---------------------------------------------------------------------------

/// Validates JWT license tokens against a set of known signing keys.
///
/// The keys map `kid` header values to Ed25519 or HMAC keys depending on
/// the deployment configuration.
pub struct LicenseValidator {
    /// Signing keys indexed by `kid`.
    keys: HashMap<String, DecodingKey>,
}

impl LicenseValidator {
    /// Creates a new validator with the supplied signing keys.
    #[must_use]
    pub fn new(keys: HashMap<String, DecodingKey>) -> Self {
        Self { keys }
    }

    /// Creates a validator that accepts tokens signed with the given HMAC
    /// secret. The key is registered under the `kid` value `"development"`.
    #[must_use]
    pub fn with_hmac_secret(secret: &[u8]) -> Self {
        let mut keys = HashMap::new();
        keys.insert("development".to_owned(), DecodingKey::from_secret(secret));
        Self { keys }
    }

    /// Parses and validates a raw JWT license string, returning the claims
    /// if valid.
    pub fn validate(&self, raw_jwt: &str) -> Result<LicenseClaims, LicenseError> {
        // Extract the `kid` from the header to select the correct key.
        let header = jsonwebtoken::decode_header(raw_jwt)
            .map_err(|e| LicenseError::InvalidToken(e.to_string()))?;

        let kid = header.kid.unwrap_or_default();
        let key = self
            .keys
            .get(&kid)
            .ok_or_else(|| LicenseError::UnknownKeyId(kid.clone()))?;

        // Build validation rules — we validate exp ourselves for grace
        // period logic, but let the library check the signature.
        let mut validation = Validation::new(header.alg);
        // We handle expiry checking ourselves for grace period support.
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.required_spec_claims.clear();
        // Only list algorithms from the same family as the token header.
        // jsonwebtoken 9.x validates that the key family matches ALL listed
        // algorithms, so mixing families (e.g. EdDSA + HMAC) would fail.
        validation.algorithms = vec![header.alg];

        let token_data = jsonwebtoken::decode::<LicenseClaims>(raw_jwt, key, &validation)
            .map_err(|e| LicenseError::InvalidToken(e.to_string()))?;

        let claims = token_data.claims;
        self.validate_claims(&claims)?;
        Ok(claims)
    }

    /// Validates the structural requirements of the parsed claims.
    pub fn validate_claims(&self, claims: &LicenseClaims) -> Result<(), LicenseError> {
        if claims.version != CURRENT_VERSION {
            return Err(LicenseError::InvalidVersion);
        }
        if claims.iat == 0 {
            return Err(LicenseError::MissingClaim("iat (issued at)".into()));
        }
        if claims.license_expires == 0 {
            return Err(LicenseError::MissingClaim("license_expires".into()));
        }
        if claims.exp == 0 {
            return Err(LicenseError::MissingClaim("exp (expires at)".into()));
        }
        if claims.account_type.is_empty() {
            return Err(LicenseError::MissingClaim("account_type".into()));
        }
        if claims.account_id.is_empty() {
            return Err(LicenseError::MissingClaim("account_id".into()));
        }
        Ok(())
    }
}
