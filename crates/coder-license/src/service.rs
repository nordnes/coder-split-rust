//! License service — orchestrates license storage, validation, and
//! entitlement computation.

use std::sync::Arc;

use thiserror::Error;
use time::OffsetDateTime;
use tracing::{info, warn};

use coder_core::LicenseRecord;

use crate::entitlements::{Entitlement, EntitlementSet, Entitlements, Feature};
use crate::features::{ALL_FEATURE_NAMES, FeatureName};
use crate::license::{FeatureSet, LicenseClaims, LicenseError, LicenseValidator};

// ---------------------------------------------------------------------------
// Store trait
// ---------------------------------------------------------------------------

/// Storage operations required by the license service.
///
/// Implementations are expected to be added to the existing `AppStore` trait
/// with default (no-op) implementations so that existing store
/// implementations continue to compile.
#[async_trait::async_trait]
pub trait LicenseStore: Send + Sync {
    /// Lists all non-expired license records.
    async fn list_licenses(&self) -> Result<Vec<LicenseRecord>, coder_core::StorageError>;

    /// Inserts a new license record and returns it with the assigned ID.
    async fn insert_license(
        &self,
        jwt: &str,
        claims: &serde_json::Value,
    ) -> Result<LicenseRecord, coder_core::StorageError>;

    /// Deletes a license by its database ID. Returns `true` if a row was
    /// removed.
    async fn delete_license(&self, id: i32) -> Result<bool, coder_core::StorageError>;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced by [`LicenseService`].
#[derive(Debug, Error)]
pub enum LicenseServiceError {
    /// A license validation error.
    #[error("{0}")]
    License(#[from] LicenseError),
    /// A backing-store error.
    #[error("{0}")]
    Storage(#[from] coder_core::StorageError),
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

/// Coordinates license management, validation, and entitlement computation.
pub struct LicenseService<S> {
    store: S,
    validator: Arc<LicenseValidator>,
    entitlements: Arc<EntitlementSet>,
}

impl<S: LicenseStore> LicenseService<S> {
    /// Creates a new license service.
    pub fn new(store: S, validator: Arc<LicenseValidator>) -> Self {
        Self {
            store,
            validator,
            entitlements: Arc::new(EntitlementSet::new()),
        }
    }

    /// Returns a shared reference to the entitlement set.
    #[must_use]
    pub fn entitlements(&self) -> &Arc<EntitlementSet> {
        &self.entitlements
    }

    /// Lists all stored licenses.
    pub async fn list_licenses(&self) -> Result<Vec<LicenseRecord>, LicenseServiceError> {
        Ok(self.store.list_licenses().await?)
    }

    /// Validates and stores a new license JWT, then refreshes entitlements.
    pub async fn add_license(&self, raw_jwt: &str) -> Result<LicenseRecord, LicenseServiceError> {
        // Validate the JWT.
        let claims = self.validator.validate(raw_jwt)?;

        // Serialise claims as a generic JSON value for storage.
        let claims_value =
            serde_json::to_value(&claims).map_err(|e| LicenseError::InvalidToken(e.to_string()))?;

        let record = self.store.insert_license(raw_jwt, &claims_value).await?;

        info!(
            license_id = record.id,
            trial = claims.trial,
            "license added"
        );

        // Refresh entitlements after adding a new license.
        self.refresh_entitlements().await?;
        Ok(record)
    }

    /// Deletes a license by database ID, then refreshes entitlements.
    pub async fn delete_license(&self, id: i32) -> Result<bool, LicenseServiceError> {
        let deleted = self.store.delete_license(id).await?;
        if deleted {
            info!(license_id = id, "license deleted");
            self.refresh_entitlements().await?;
        }
        Ok(deleted)
    }

    /// Recomputes entitlements from all stored licenses.
    ///
    /// This reads every stored license, validates each JWT, and merges
    /// the resulting feature sets into a single [`Entitlements`] snapshot.
    pub async fn refresh_entitlements(&self) -> Result<(), LicenseServiceError> {
        let licenses = self.store.list_licenses().await?;
        let now = OffsetDateTime::now_utc();

        let mut ents = Entitlements::new_unlicensed();
        ents.refreshed_at = now;

        let mut valid_claims: Vec<LicenseClaims> = Vec::new();

        for license in &licenses {
            match self.validator.validate(&license.jwt) {
                Ok(claims) => {
                    if claims.is_expired(now) {
                        warn!(license_id = license.id, "skipping fully expired license");
                        continue;
                    }
                    self.apply_claims(&mut ents, &claims, now);
                    valid_claims.push(claims);
                }
                Err(e) => {
                    ents.errors
                        .push(format!("Invalid license ({}): {}", license.uuid, e));
                }
            }
        }

        // Add expiry warnings using the already-validated claims.
        self.add_expiry_warnings(&mut ents, &valid_claims, now);

        self.entitlements.update(ents);
        Ok(())
    }

    /// Applies a single license's claims to the entitlements snapshot.
    ///
    /// # Precondition
    ///
    /// The caller should filter out fully expired licenses before invoking
    /// this method.  As a safety net an explicit expiry check is included;
    /// expired claims are silently ignored.
    fn apply_claims(&self, ents: &mut Entitlements, claims: &LicenseClaims, now: OffsetDateTime) {
        // Safety guard — skip fully expired licenses even if the caller
        // forgot to filter them.
        if claims.is_expired(now) {
            return;
        }

        // Determine the entitlement level for features from this license.
        let entitlement = if claims.in_grace_period(now) {
            Entitlement::GracePeriod
        } else {
            Entitlement::Entitled
        };

        ents.has_license = true;
        ents.require_telemetry = ents.require_telemetry || claims.require_telemetry;

        if claims.trial {
            ents.trial = true;
        }

        // Resolve the effective feature set.
        let mut effective_set = claims.feature_set.clone();
        if claims.all_features && effective_set == FeatureSet::None {
            effective_set = FeatureSet::Enterprise;
        }

        // Add features from the feature set.
        let set_features = features_for_set(&effective_set);
        for &feature_name in &set_features {
            if feature_name.uses_limit() {
                // Limit features are handled via explicit claims below.
                continue;
            }
            ents.add_feature(
                feature_name,
                Feature {
                    entitlement,
                    enabled: feature_name.always_enable(),
                    limit: None,
                    actual: None,
                },
            );
        }

        // Add per-feature claims (a la carte).
        for (name_str, &value) in &claims.features {
            let Some(feature_name) = parse_feature_name(name_str) else {
                continue;
            };
            if feature_name.uses_limit() {
                if value <= 0 {
                    continue;
                }
                ents.add_feature(
                    feature_name,
                    Feature {
                        entitlement,
                        enabled: true,
                        limit: Some(value),
                        actual: None,
                    },
                );
            } else {
                if value <= 0 {
                    continue;
                }
                ents.add_feature(
                    feature_name,
                    Feature {
                        entitlement,
                        enabled: feature_name.always_enable(),
                        limit: None,
                        actual: None,
                    },
                );
            }
        }
    }

    /// Adds license expiry warnings to the entitlements snapshot.
    ///
    /// `valid_claims` should contain the already-validated, non-expired
    /// claims produced during [`refresh_entitlements`] to avoid
    /// re-validating every license JWT a second time.
    fn add_expiry_warnings(
        &self,
        ents: &mut Entitlements,
        valid_claims: &[LicenseClaims],
        now: OffsetDateTime,
    ) {
        // Find the latest license_expires among valid licenses.
        // The latest expiry determines when actual coverage ends.
        let mut latest_expiry: Option<OffsetDateTime> = None;
        for claims in valid_claims {
            let expires = claims.license_expires_at();
            if latest_expiry.is_none_or(|e| expires > e) {
                latest_expiry = Some(expires);
            }
        }

        if let Some(expiry) = latest_expiry {
            let duration = expiry - now;
            let days_to_expire = (duration.whole_seconds() as f64 / 86400.0).ceil() as i64;

            let show_warning_days: i64 = if ents.trial { 7 } else { 30 };

            if duration.is_negative() {
                ents.warnings
                    .push("Your license has expired. You are in a grace period.".to_owned());
            } else if days_to_expire < show_warning_days {
                let day_word = if days_to_expire == 1 { "day" } else { "days" };
                ents.warnings.push(format!(
                    "Your license expires in {} {}.",
                    days_to_expire, day_word
                ));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns the features granted by a feature set.
fn features_for_set(set: &FeatureSet) -> Vec<FeatureName> {
    match set {
        FeatureSet::Enterprise => ALL_FEATURE_NAMES
            .iter()
            .copied()
            .filter(|f| f.is_enterprise() && !f.uses_limit())
            .collect(),
        FeatureSet::Premium => ALL_FEATURE_NAMES
            .iter()
            .copied()
            .filter(|f| !f.uses_limit())
            .collect(),
        FeatureSet::None => Vec::new(),
    }
}

/// Tries to parse a string into a [`FeatureName`].
fn parse_feature_name(s: &str) -> Option<FeatureName> {
    // Use serde to do the string → enum conversion.
    serde_json::from_value(serde_json::Value::String(s.to_owned())).ok()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use super::*;
    use crate::entitlements::Entitlement;
    use crate::license::CURRENT_VERSION;
    use uuid::Uuid;

    #[test]
    fn test_features_for_enterprise_set() {
        let features = features_for_set(&FeatureSet::Enterprise);
        // Enterprise set should include audit_log but not custom_roles
        assert!(features.contains(&FeatureName::AuditLog));
        assert!(!features.contains(&FeatureName::CustomRoles));
        assert!(!features.contains(&FeatureName::MultipleOrganizations));
        // Limit features should be excluded
        assert!(!features.contains(&FeatureName::UserLimit));
        assert!(!features.contains(&FeatureName::ManagedAgentLimit));
    }

    #[test]
    fn test_features_for_premium_set() {
        let features = features_for_set(&FeatureSet::Premium);
        // Premium set includes everything except limit features
        assert!(features.contains(&FeatureName::AuditLog));
        assert!(features.contains(&FeatureName::CustomRoles));
        assert!(features.contains(&FeatureName::MultipleOrganizations));
        // Limit features should still be excluded
        assert!(!features.contains(&FeatureName::UserLimit));
    }

    #[test]
    fn test_features_for_none_set() {
        let features = features_for_set(&FeatureSet::None);
        assert!(features.is_empty());
    }

    #[test]
    fn test_parse_feature_name_valid() {
        assert_eq!(parse_feature_name("audit_log"), Some(FeatureName::AuditLog));
        assert_eq!(
            parse_feature_name("high_availability"),
            Some(FeatureName::HighAvailability)
        );
        assert_eq!(parse_feature_name("scim"), Some(FeatureName::Scim));
    }

    #[test]
    fn test_parse_feature_name_unknown() {
        assert_eq!(parse_feature_name("nonexistent_feature"), None);
    }

    #[test]
    fn test_entitlements_new_unlicensed() {
        let ents = Entitlements::new_unlicensed();
        assert!(!ents.has_license);
        assert!(!ents.trial);

        // All features should be present and not entitled.
        for &name in ALL_FEATURE_NAMES {
            assert!(
                ents.features.contains_key(name.as_str()),
                "feature {} missing",
                name.as_str()
            );
            let feature = &ents.features[name.as_str()];
            assert_eq!(feature.entitlement, Entitlement::NotEntitled);
            assert!(!feature.enabled);
        }
    }

    #[test]
    fn test_add_feature_expands_entitlement() {
        let mut ents = Entitlements::new_unlicensed();

        // Add a grace-period feature.
        ents.add_feature(
            FeatureName::AuditLog,
            Feature {
                entitlement: Entitlement::GracePeriod,
                enabled: true,
                limit: None,
                actual: None,
            },
        );
        let f = &ents.features["audit_log"];
        assert_eq!(f.entitlement, Entitlement::GracePeriod);
        assert!(f.enabled);

        // Upgrading to entitled should replace it.
        ents.add_feature(
            FeatureName::AuditLog,
            Feature {
                entitlement: Entitlement::Entitled,
                enabled: true,
                limit: None,
                actual: None,
            },
        );
        let f = &ents.features["audit_log"];
        assert_eq!(f.entitlement, Entitlement::Entitled);

        // Downgrading should not replace it.
        ents.add_feature(
            FeatureName::AuditLog,
            Feature {
                entitlement: Entitlement::GracePeriod,
                enabled: true,
                limit: None,
                actual: None,
            },
        );
        let f = &ents.features["audit_log"];
        assert_eq!(f.entitlement, Entitlement::Entitled);
    }

    #[test]
    fn test_license_claims_grace_period() {
        let now = OffsetDateTime::now_utc();
        let claims = LicenseClaims {
            iss: String::new(),
            sub: String::new(),
            aud: serde_json::Value::Null,
            exp: (now + time::Duration::days(30)).unix_timestamp(),
            nbf: (now - time::Duration::days(365)).unix_timestamp(),
            iat: (now - time::Duration::days(365)).unix_timestamp(),
            jti: String::new(),
            license_expires: (now - time::Duration::days(1)).unix_timestamp(),
            account_type: "test".into(),
            account_id: "test-123".into(),
            trial: false,
            feature_set: FeatureSet::Enterprise,
            all_features: false,
            version: CURRENT_VERSION,
            features: HashMap::new(),
            require_telemetry: false,
            deployment_ids: Vec::new(),
        };

        assert!(claims.in_grace_period(now));
        assert!(!claims.is_expired(now));
    }

    #[test]
    fn test_license_claims_fully_expired() {
        let now = OffsetDateTime::now_utc();
        let claims = LicenseClaims {
            iss: String::new(),
            sub: String::new(),
            aud: serde_json::Value::Null,
            exp: (now - time::Duration::days(1)).unix_timestamp(),
            nbf: (now - time::Duration::days(400)).unix_timestamp(),
            iat: (now - time::Duration::days(400)).unix_timestamp(),
            jti: String::new(),
            license_expires: (now - time::Duration::days(31)).unix_timestamp(),
            account_type: "test".into(),
            account_id: "test-123".into(),
            trial: false,
            feature_set: FeatureSet::None,
            all_features: false,
            version: CURRENT_VERSION,
            features: HashMap::new(),
            require_telemetry: false,
            deployment_ids: Vec::new(),
        };

        assert!(!claims.in_grace_period(now));
        assert!(claims.is_expired(now));
    }

    #[test]
    fn test_entitlement_set_thread_safe() {
        let set = EntitlementSet::new();
        assert!(!set.has_license());
        assert!(!set.enabled(FeatureName::AuditLog));
        assert!(!set.is_entitled(FeatureName::AuditLog));

        let mut ents = Entitlements::new_unlicensed();
        ents.has_license = true;
        ents.add_feature(
            FeatureName::AuditLog,
            Feature {
                entitlement: Entitlement::Entitled,
                enabled: true,
                limit: None,
                actual: None,
            },
        );
        set.update(ents);

        assert!(set.has_license());
        assert!(set.enabled(FeatureName::AuditLog));
        assert!(set.is_entitled(FeatureName::AuditLog));
    }

    #[test]
    fn test_feature_capable() {
        let under_limit = Feature {
            entitlement: Entitlement::Entitled,
            enabled: true,
            limit: Some(100),
            actual: Some(50),
        };
        assert!(under_limit.capable());

        let at_limit = Feature {
            entitlement: Entitlement::Entitled,
            enabled: true,
            limit: Some(100),
            actual: Some(100),
        };
        assert!(at_limit.capable());

        let over_limit = Feature {
            entitlement: Entitlement::Entitled,
            enabled: true,
            limit: Some(100),
            actual: Some(101),
        };
        assert!(!over_limit.capable());

        let no_limit = Feature {
            entitlement: Entitlement::Entitled,
            enabled: true,
            limit: None,
            actual: Some(999),
        };
        assert!(no_limit.capable());
    }

    #[test]
    fn test_validator_rejects_missing_version() {
        let validator = LicenseValidator::with_hmac_secret(b"test-secret-key-for-validation");
        let now = OffsetDateTime::now_utc();

        // Create claims with wrong version.
        let claims = LicenseClaims {
            iss: String::new(),
            sub: String::new(),
            aud: serde_json::Value::Null,
            exp: (now + time::Duration::days(30)).unix_timestamp(),
            nbf: (now - time::Duration::days(1)).unix_timestamp(),
            iat: (now - time::Duration::days(1)).unix_timestamp(),
            jti: String::new(),
            license_expires: (now + time::Duration::days(29)).unix_timestamp(),
            account_type: "test".into(),
            account_id: "test-123".into(),
            trial: false,
            feature_set: FeatureSet::None,
            all_features: false,
            version: 2, // Wrong version
            features: HashMap::new(),
            require_telemetry: false,
            deployment_ids: Vec::new(),
        };

        let result = validator.validate_claims(&claims);
        assert_eq!(result, Err(LicenseError::InvalidVersion));
    }

    #[test]
    fn test_validator_rejects_missing_account() {
        let validator = LicenseValidator::with_hmac_secret(b"test-secret-key-for-validation");
        let now = OffsetDateTime::now_utc();

        let claims = LicenseClaims {
            iss: String::new(),
            sub: String::new(),
            aud: serde_json::Value::Null,
            exp: (now + time::Duration::days(30)).unix_timestamp(),
            nbf: (now - time::Duration::days(1)).unix_timestamp(),
            iat: (now - time::Duration::days(1)).unix_timestamp(),
            jti: String::new(),
            license_expires: (now + time::Duration::days(29)).unix_timestamp(),
            account_type: String::new(), // Missing
            account_id: "test-123".into(),
            trial: false,
            feature_set: FeatureSet::None,
            all_features: false,
            version: CURRENT_VERSION,
            features: HashMap::new(),
            require_telemetry: false,
            deployment_ids: Vec::new(),
        };

        let result = validator.validate_claims(&claims);
        assert!(matches!(result, Err(LicenseError::MissingClaim(_))));
    }

    #[test]
    fn test_license_validator_with_hmac() -> Result<(), Box<dyn std::error::Error>> {
        let secret = b"test-secret-for-hmac-license-validation";
        let validator = LicenseValidator::with_hmac_secret(secret);
        let now = OffsetDateTime::now_utc();

        let claims = LicenseClaims {
            iss: "test".into(),
            sub: "test-license".into(),
            aud: serde_json::Value::Null,
            exp: (now + time::Duration::days(60)).unix_timestamp(),
            nbf: (now - time::Duration::days(1)).unix_timestamp(),
            iat: (now - time::Duration::days(1)).unix_timestamp(),
            jti: "test-jti".into(),
            license_expires: (now + time::Duration::days(30)).unix_timestamp(),
            account_type: "salesforce".into(),
            account_id: "acct-001".into(),
            trial: false,
            feature_set: FeatureSet::Enterprise,
            all_features: false,
            version: CURRENT_VERSION,
            features: HashMap::new(),
            require_telemetry: false,
            deployment_ids: Vec::new(),
        };

        // Sign the token with HMAC.
        let encoding_key = jsonwebtoken::EncodingKey::from_secret(secret);
        let header = jsonwebtoken::Header {
            alg: jsonwebtoken::Algorithm::HS256,
            kid: Some("development".into()),
            ..Default::default()
        };
        let token = jsonwebtoken::encode(&header, &claims, &encoding_key)?;

        let parsed_claims = validator.validate(&token)?;
        assert_eq!(parsed_claims.account_type, "salesforce");
        assert_eq!(parsed_claims.account_id, "acct-001");
        assert_eq!(parsed_claims.feature_set, FeatureSet::Enterprise);
        Ok(())
    }

    #[tokio::test]
    async fn test_license_service_refresh_entitlements() -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::Mutex;

        struct FakeLicenseStore {
            licenses: Mutex<Vec<LicenseRecord>>,
        }

        #[async_trait::async_trait]
        impl LicenseStore for FakeLicenseStore {
            async fn list_licenses(&self) -> Result<Vec<LicenseRecord>, coder_core::StorageError> {
                Ok(self
                    .licenses
                    .lock()
                    .map_err(|_| coder_core::StorageError::unavailable("lock poisoned"))?
                    .clone())
            }

            async fn insert_license(
                &self,
                jwt: &str,
                claims: &serde_json::Value,
            ) -> Result<LicenseRecord, coder_core::StorageError> {
                let record = LicenseRecord {
                    id: 1,
                    uuid: Uuid::new_v4(),
                    uploaded_at: OffsetDateTime::now_utc(),
                    jwt: jwt.to_owned(),
                    claims: claims.clone(),
                };
                self.licenses
                    .lock()
                    .map_err(|_| coder_core::StorageError::unavailable("lock poisoned"))?
                    .push(record.clone());
                Ok(record)
            }

            async fn delete_license(&self, id: i32) -> Result<bool, coder_core::StorageError> {
                let mut guard = self
                    .licenses
                    .lock()
                    .map_err(|_| coder_core::StorageError::unavailable("lock poisoned"))?;
                let before = guard.len();
                guard.retain(|l| l.id != id);
                Ok(guard.len() < before)
            }
        }

        let secret = b"test-hmac-secret-for-service-test";
        let validator = Arc::new(LicenseValidator::with_hmac_secret(secret));
        let store = FakeLicenseStore {
            licenses: Mutex::new(Vec::new()),
        };
        let service = LicenseService::new(store, validator);

        // Initially no license.
        service.refresh_entitlements().await?;
        assert!(!service.entitlements().has_license());
        assert!(!service.entitlements().enabled(FeatureName::AuditLog));

        // Create and add a license token.
        let now = OffsetDateTime::now_utc();
        let claims = LicenseClaims {
            iss: "test".into(),
            sub: "svc-test".into(),
            aud: serde_json::Value::Null,
            exp: (now + time::Duration::days(60)).unix_timestamp(),
            nbf: (now - time::Duration::days(1)).unix_timestamp(),
            iat: (now - time::Duration::days(1)).unix_timestamp(),
            jti: "jti-svc".into(),
            license_expires: (now + time::Duration::days(30)).unix_timestamp(),
            account_type: "salesforce".into(),
            account_id: "acct-svc".into(),
            trial: false,
            feature_set: FeatureSet::Enterprise,
            all_features: false,
            version: CURRENT_VERSION,
            features: HashMap::new(),
            require_telemetry: false,
            deployment_ids: Vec::new(),
        };

        let encoding_key = jsonwebtoken::EncodingKey::from_secret(secret);
        let header = jsonwebtoken::Header {
            alg: jsonwebtoken::Algorithm::HS256,
            kid: Some("development".into()),
            ..Default::default()
        };
        let token = jsonwebtoken::encode(&header, &claims, &encoding_key)?;

        service.add_license(&token).await?;

        assert!(service.entitlements().has_license());
        // Enterprise set should enable audit_log (it has always_enable = false,
        // but enterprise set sets enabled via always_enable check).
        // AuditLog.always_enable() is false, so enabled should be false,
        // but the feature IS entitled.
        assert!(service.entitlements().is_entitled(FeatureName::AuditLog));
        assert!(
            service
                .entitlements()
                .is_entitled(FeatureName::HighAvailability)
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_grace_period_warning_emitted() -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::Mutex;

        struct FakeLicenseStore {
            licenses: Mutex<Vec<LicenseRecord>>,
        }

        #[async_trait::async_trait]
        impl LicenseStore for FakeLicenseStore {
            async fn list_licenses(&self) -> Result<Vec<LicenseRecord>, coder_core::StorageError> {
                Ok(self
                    .licenses
                    .lock()
                    .map_err(|_| coder_core::StorageError::unavailable("lock poisoned"))?
                    .clone())
            }

            async fn insert_license(
                &self,
                jwt: &str,
                claims: &serde_json::Value,
            ) -> Result<LicenseRecord, coder_core::StorageError> {
                let record = LicenseRecord {
                    id: 1,
                    uuid: Uuid::new_v4(),
                    uploaded_at: OffsetDateTime::now_utc(),
                    jwt: jwt.to_owned(),
                    claims: claims.clone(),
                };
                self.licenses
                    .lock()
                    .map_err(|_| coder_core::StorageError::unavailable("lock poisoned"))?
                    .push(record.clone());
                Ok(record)
            }

            async fn delete_license(&self, id: i32) -> Result<bool, coder_core::StorageError> {
                let mut guard = self
                    .licenses
                    .lock()
                    .map_err(|_| coder_core::StorageError::unavailable("lock poisoned"))?;
                let before = guard.len();
                guard.retain(|l| l.id != id);
                Ok(guard.len() < before)
            }
        }

        let secret = b"test-hmac-secret-for-grace-warning";
        let validator = Arc::new(LicenseValidator::with_hmac_secret(secret));
        let store = FakeLicenseStore {
            licenses: Mutex::new(Vec::new()),
        };
        let service = LicenseService::new(store, validator);

        // Create a license where license_expires is 5 days in the past
        // but exp (JWT expiry / grace period end) is 25 days in the future.
        let now = OffsetDateTime::now_utc();
        let claims = LicenseClaims {
            iss: "test".into(),
            sub: "svc-test".into(),
            aud: serde_json::Value::Null,
            exp: (now + time::Duration::days(25)).unix_timestamp(),
            nbf: (now - time::Duration::days(1)).unix_timestamp(),
            iat: (now - time::Duration::days(1)).unix_timestamp(),
            jti: "jti-grace-warn".into(),
            license_expires: (now - time::Duration::days(5)).unix_timestamp(),
            account_type: "salesforce".into(),
            account_id: "acct-grace".into(),
            trial: false,
            feature_set: FeatureSet::Enterprise,
            all_features: false,
            version: CURRENT_VERSION,
            features: HashMap::new(),
            require_telemetry: false,
            deployment_ids: Vec::new(),
        };

        let encoding_key = jsonwebtoken::EncodingKey::from_secret(secret);
        let header = jsonwebtoken::Header {
            alg: jsonwebtoken::Algorithm::HS256,
            kid: Some("development".into()),
            ..Default::default()
        };
        let token = jsonwebtoken::encode(&header, &claims, &encoding_key)?;

        service.add_license(&token).await?;

        // The license is in grace period — warnings should include the grace message.
        let ents = service.entitlements();
        let warnings = ents.warnings();
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("Your license has expired")),
            "Expected grace period warning, got: {:?}",
            warnings,
        );

        Ok(())
    }
}
