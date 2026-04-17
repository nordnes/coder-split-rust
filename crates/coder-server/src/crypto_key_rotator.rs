//! Background rotator for `crypto_keys` rows.
//!
//! Mirrors the Go `coderd/cryptokeys/rotate.go` rotator:
//!
//! - rotates a feature's active key once it is within one "token-duration"
//!   of its expiry (`starts_at + key_duration`),
//! - marks the old key with a `deletes_at` timestamp so dependent services
//!   have time to pick up the new key,
//! - deletes keys whose `deletes_at` has elapsed,
//! - ensures each known feature always has at least one valid key.
//!
//! This module spawns one long-running task per process; it is cancelled by
//! dropping the returned [`tokio::task::JoinHandle`].

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use coder_core::enums::CryptoKeyFeature;
use coder_core::ports::{AppStore, CryptoKeyRow, StorageError};
use time::OffsetDateTime;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, warn};

/// Default interval between rotation sweeps in production.
///
/// Go uses 10 minutes; we follow the task spec's "~5 minute cadence" guidance
/// which is still well under the `DefaultKeyDuration` of 30 days.
pub const DEFAULT_ROTATION_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// Default per-feature key duration. Mirrors Go's `DefaultKeyDuration`.
pub const DEFAULT_KEY_DURATION: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Downstream token lifetime per feature. Used to compute how long a rotated
/// key must linger with a `deletes_at` grace period. Mirrors
/// `tokenDuration` in Go's `rotate.go`.
fn token_duration(feature: CryptoKeyFeature) -> Duration {
    match feature {
        CryptoKeyFeature::WorkspaceAppsApiKey | CryptoKeyFeature::WorkspaceAppsToken => {
            Duration::from_secs(60)
        }
        CryptoKeyFeature::OidcConvert => Duration::from_secs(5 * 60),
        CryptoKeyFeature::TailnetResume => Duration::from_secs(24 * 60 * 60),
    }
}

/// Returns the number of secret bytes used for a newly-minted key. Mirrors
/// the pre-hex byte counts Go uses in `generateNewSecret` (see
/// `coder/coderd/cryptokeys/rotate.go` and `.../keys.go`).
///
/// Exposed so the lazy-creation path in the `/crypto-keys` handler can match
/// the rotator's output exactly when it has to mint a key before the
/// background rotator's initial sweep lands.
#[must_use]
pub fn secret_byte_length(feature: CryptoKeyFeature) -> usize {
    match feature {
        CryptoKeyFeature::WorkspaceAppsApiKey => 32,
        CryptoKeyFeature::WorkspaceAppsToken
        | CryptoKeyFeature::OidcConvert
        | CryptoKeyFeature::TailnetResume => 64,
    }
}

/// All features the rotator manages. Mirrors Go's
/// `database.AllCryptoKeyFeatureValues()`.
const MANAGED_FEATURES: &[CryptoKeyFeature] = &[
    CryptoKeyFeature::WorkspaceAppsApiKey,
    CryptoKeyFeature::WorkspaceAppsToken,
    CryptoKeyFeature::OidcConvert,
    CryptoKeyFeature::TailnetResume,
];

/// Narrow store surface used by the rotator. Implementing this trait on a
/// mock lets unit tests exercise the full sweep without having to stand up
/// the ~100-method `AppStore` trait.
#[async_trait]
pub trait CryptoKeyStore: Send + Sync {
    /// Lists every crypto key row currently in the database.
    async fn list_all(&self) -> Result<Vec<CryptoKeyRow>, StorageError>;
    /// Lists keys for a single feature, ordered by ascending sequence.
    async fn list_by_feature(
        &self,
        feature: CryptoKeyFeature,
    ) -> Result<Vec<CryptoKeyRow>, StorageError>;
    /// Inserts a new crypto key row.
    async fn insert(&self, row: CryptoKeyRow) -> Result<CryptoKeyRow, StorageError>;
    /// Sets `deletes_at` on an existing key.
    async fn update_deletes_at(
        &self,
        feature: CryptoKeyFeature,
        sequence: i32,
        deletes_at: Option<OffsetDateTime>,
    ) -> Result<bool, StorageError>;
    /// Removes the key permanently.
    async fn delete(&self, feature: CryptoKeyFeature, sequence: i32) -> Result<bool, StorageError>;
}

/// Adapter: any `dyn AppStore` trait object implements [`CryptoKeyStore`] by
/// dispatching to the corresponding operational-store methods. We specialise
/// on the trait object (not a blanket `impl<T: AppStore>`) so test doubles
/// can provide their own `CryptoKeyStore` implementation without running
/// into coherence errors.
#[async_trait]
impl CryptoKeyStore for dyn AppStore + '_ {
    async fn list_all(&self) -> Result<Vec<CryptoKeyRow>, StorageError> {
        AppStore::list_all_crypto_keys(self).await
    }
    async fn list_by_feature(
        &self,
        feature: CryptoKeyFeature,
    ) -> Result<Vec<CryptoKeyRow>, StorageError> {
        AppStore::list_crypto_keys_by_feature(self, feature).await
    }
    async fn insert(&self, row: CryptoKeyRow) -> Result<CryptoKeyRow, StorageError> {
        AppStore::insert_crypto_key(self, row).await
    }
    async fn update_deletes_at(
        &self,
        feature: CryptoKeyFeature,
        sequence: i32,
        deletes_at: Option<OffsetDateTime>,
    ) -> Result<bool, StorageError> {
        AppStore::update_crypto_key_deletes_at(self, feature, sequence, deletes_at).await
    }
    async fn delete(&self, feature: CryptoKeyFeature, sequence: i32) -> Result<bool, StorageError> {
        AppStore::delete_crypto_key(self, feature, sequence).await
    }
}

/// Options for constructing a rotator.
#[derive(Clone, Debug)]
pub struct RotatorOptions {
    /// How often rotation sweeps run.
    pub interval: Duration,
    /// How long a newly-minted key is valid before it should be rotated.
    pub key_duration: Duration,
}

impl Default for RotatorOptions {
    fn default() -> Self {
        Self {
            interval: DEFAULT_ROTATION_INTERVAL,
            key_duration: DEFAULT_KEY_DURATION,
        }
    }
}

/// A crypto-key rotator. Construct with [`CryptoKeyRotator::new`] and drive a
/// single sweep with [`CryptoKeyRotator::rotate_once`], or run as a background
/// task with [`CryptoKeyRotator::start`].
#[derive(Clone)]
pub struct CryptoKeyRotator {
    store: Arc<dyn AppStore>,
    options: RotatorOptions,
}

impl CryptoKeyRotator {
    /// Creates a new rotator bound to `store` with the supplied `options`.
    #[must_use]
    pub fn new(store: Arc<dyn AppStore>, options: RotatorOptions) -> Self {
        Self { store, options }
    }

    /// Spawns the rotator loop on the current Tokio runtime. Runs an initial
    /// sweep synchronously (as Go's `StartRotator` does) so newly-booted
    /// deployments always have at least one key per feature before serving
    /// traffic. The loop exits cleanly when `cancel` is triggered.
    pub async fn start(self, cancel: CancellationToken) -> JoinHandle<()> {
        if let Err(error) = rotate_once(
            self.store.as_ref(),
            &self.options,
            OffsetDateTime::now_utc(),
        )
        .await
        {
            error!(%error, "initial crypto-key rotation sweep failed");
        }
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(self.options.interval);
            // The first `tick` fires immediately — skip it because we just
            // ran a sweep above.
            ticker.tick().await;
            loop {
                tokio::select! {
                    biased;
                    () = cancel.cancelled() => {
                        debug!("crypto-key rotator shutting down");
                        break;
                    }
                    _ = ticker.tick() => {
                        if let Err(error) = rotate_once(
                            self.store.as_ref(),
                            &self.options,
                            OffsetDateTime::now_utc(),
                        )
                        .await
                        {
                            error!(%error, "crypto-key rotation sweep failed");
                        }
                    }
                }
            }
        })
    }

    /// Runs a single rotation pass. Exposed so tests and the startup path can
    /// drive the rotator deterministically.
    pub async fn rotate_once(&self, now: OffsetDateTime) -> Result<(), StorageError> {
        rotate_once(self.store.as_ref(), &self.options, now).await
    }
}

/// The inner sweep, parameterised over any [`CryptoKeyStore`]. Handles:
///
/// 1. Deleting keys whose `deletes_at` has elapsed.
/// 2. Rotating keys that are within one hour of expiry.
/// 3. Ensuring each managed feature has at least one active key.
async fn rotate_once<S: CryptoKeyStore + ?Sized>(
    store: &S,
    options: &RotatorOptions,
    now: OffsetDateTime,
) -> Result<(), StorageError> {
    let keys = store.list_all().await?;
    let mut by_feature: std::collections::HashMap<CryptoKeyFeature, Vec<CryptoKeyRow>> =
        std::collections::HashMap::new();
    for feature in MANAGED_FEATURES {
        by_feature.insert(*feature, Vec::new());
    }
    for key in keys {
        by_feature.entry(key.feature).or_default().push(key);
    }

    for feature in MANAGED_FEATURES {
        let mut valid_keys = 0usize;
        let feature_keys = by_feature.remove(feature).unwrap_or_default();
        for key in feature_keys {
            if should_delete_key(&key, now) {
                match store.delete(key.feature, key.sequence).await {
                    Ok(_) => debug!(
                        feature = key.feature.as_str(),
                        sequence = key.sequence,
                        "deleted retired crypto key"
                    ),
                    Err(error) => warn!(%error, "failed to delete retired crypto key"),
                }
                continue;
            }
            if should_rotate_key(&key, options.key_duration, now) {
                match rotate_key(store, &key, now, options).await {
                    Ok(()) => {
                        // A successor key was just minted — count it so the
                        // "ensure each feature has at least one valid key"
                        // fallback below does not double-insert.
                        valid_keys += 1;
                    }
                    Err(error) => warn!(%error, "failed to rotate crypto key"),
                }
                continue;
            }
            if key.deletes_at.is_none() {
                valid_keys += 1;
            }
        }
        if valid_keys == 0 {
            if let Err(error) = insert_new_key(store, *feature, now).await {
                warn!(%error, feature = feature.as_str(), "failed to create initial crypto key");
            }
        }
    }
    Ok(())
}

async fn rotate_key<S: CryptoKeyStore + ?Sized>(
    store: &S,
    old: &CryptoKeyRow,
    now: OffsetDateTime,
    options: &RotatorOptions,
) -> Result<(), StorageError> {
    let starts_at = min_starts_at(old, now, options.key_duration, options.interval);
    // Give downstream services time to pick up the new key before we stop
    // honoring the old one. Mirrors Go's
    // `startsAt + 1h + tokenDuration(feature)`.
    let deletes_at = starts_at
        + time::Duration::hours(1)
        + duration_to_time_duration(token_duration(old.feature));
    // Stamp the old key's `deletes_at` FIRST, then insert the successor.
    // If the insert fails, the old key is already marked and `should_rotate_key`
    // will skip it on subsequent sweeps; the "ensure at least one valid key"
    // fallback in `rotate_once` will mint a fresh successor from now. Reversing
    // the order risks leaving a successor in place with the old key still
    // rotatable (deletes_at = None), which would cause unbounded key
    // accumulation under persistent `update_deletes_at` failures.
    store
        .update_deletes_at(old.feature, old.sequence, Some(deletes_at))
        .await?;
    insert_new_key(store, old.feature, starts_at).await?;
    debug!(
        feature = old.feature.as_str(),
        sequence = old.sequence,
        "rotated crypto key"
    );
    Ok(())
}

async fn insert_new_key<S: CryptoKeyStore + ?Sized>(
    store: &S,
    feature: CryptoKeyFeature,
    starts_at: OffsetDateTime,
) -> Result<(), StorageError> {
    // Use `list_all()` (unfiltered) rather than `list_by_feature()`, which in
    // production applies a `starts_at <= NOW() AND deletes_at IS NULL OR
    // deletes_at > NOW()` filter. After `rotate_key` inserts a successor with a
    // future `starts_at`, that row must still be visible here so we do not
    // reuse its sequence and hit the `(feature, sequence)` PRIMARY KEY.
    let max_sequence = store
        .list_all()
        .await?
        .into_iter()
        .filter(|k| k.feature == feature)
        .map(|k| k.sequence)
        .max()
        .unwrap_or(0);
    let mut secret = vec![0u8; secret_byte_length(feature)];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret);
    store
        .insert(CryptoKeyRow {
            feature,
            sequence: max_sequence + 1,
            secret,
            starts_at,
            deletes_at: None,
        })
        .await?;
    Ok(())
}

fn should_delete_key(key: &CryptoKeyRow, now: OffsetDateTime) -> bool {
    key.deletes_at.is_some_and(|deletes_at| now >= deletes_at)
}

fn should_rotate_key(key: &CryptoKeyRow, key_duration: Duration, now: OffsetDateTime) -> bool {
    if key.deletes_at.is_some() {
        return false;
    }
    let expires_at = key.starts_at + duration_to_time_duration(key_duration);
    // Rotate once we're within one hour of expiry. Mirrors Go's
    // `!now.Add(time.Hour).Before(expirationTime)`.
    now + time::Duration::hours(1) >= expires_at
}

fn min_starts_at(
    key: &CryptoKeyRow,
    now: OffsetDateTime,
    key_duration: Duration,
    interval: Duration,
) -> OffsetDateTime {
    let expires_at = key.starts_at + duration_to_time_duration(key_duration);
    let floor = now + duration_to_time_duration(interval.saturating_mul(3));
    if expires_at < floor {
        floor
    } else {
        expires_at
    }
}

fn duration_to_time_duration(d: Duration) -> time::Duration {
    // `time::Duration` supports nanosecond precision and negative values, so
    // converting from a `std::time::Duration` is infallible for realistic
    // inputs. Clamp on overflow rather than panic.
    time::Duration::try_from(d).unwrap_or(time::Duration::MAX)
}

#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct RotatorStore {
        inner: Mutex<Vec<CryptoKeyRow>>,
    }

    impl RotatorStore {
        fn new(seed: Vec<CryptoKeyRow>) -> Arc<Self> {
            Arc::new(Self {
                inner: Mutex::new(seed),
            })
        }

        fn snapshot(&self) -> Vec<CryptoKeyRow> {
            self.inner.lock().expect("lock poisoned").clone()
        }
    }

    #[async_trait]
    impl CryptoKeyStore for RotatorStore {
        async fn list_all(&self) -> Result<Vec<CryptoKeyRow>, StorageError> {
            Ok(self.inner.lock().expect("lock poisoned").clone())
        }
        async fn list_by_feature(
            &self,
            feature: CryptoKeyFeature,
        ) -> Result<Vec<CryptoKeyRow>, StorageError> {
            // Mirror production SQL: filter on `starts_at <= NOW()` and
            // `deletes_at IS NULL OR deletes_at > NOW()`. Tests that need the
            // unfiltered list should call `list_all`. This prevents the mock
            // from silently masking TOCTOU bugs in rotator callers.
            let now = OffsetDateTime::now_utc();
            Ok(self
                .inner
                .lock()
                .expect("lock poisoned")
                .iter()
                .filter(|k| k.feature == feature)
                .filter(|k| k.starts_at <= now)
                .filter(|k| k.deletes_at.is_none_or(|d| d > now))
                .cloned()
                .collect())
        }
        async fn insert(&self, row: CryptoKeyRow) -> Result<CryptoKeyRow, StorageError> {
            self.inner.lock().expect("lock poisoned").push(row.clone());
            Ok(row)
        }
        async fn update_deletes_at(
            &self,
            feature: CryptoKeyFeature,
            sequence: i32,
            deletes_at: Option<OffsetDateTime>,
        ) -> Result<bool, StorageError> {
            let mut guard = self.inner.lock().expect("lock poisoned");
            for k in guard.iter_mut() {
                if k.feature == feature && k.sequence == sequence {
                    k.deletes_at = deletes_at;
                    return Ok(true);
                }
            }
            Ok(false)
        }
        async fn delete(
            &self,
            feature: CryptoKeyFeature,
            sequence: i32,
        ) -> Result<bool, StorageError> {
            let mut guard = self.inner.lock().expect("lock poisoned");
            let before = guard.len();
            guard.retain(|k| !(k.feature == feature && k.sequence == sequence));
            Ok(guard.len() != before)
        }
    }

    #[tokio::test]
    async fn inserts_new_key_when_feature_has_none() {
        let store = RotatorStore::new(Vec::new());
        let now = OffsetDateTime::now_utc();
        let options = RotatorOptions::default();

        rotate_once(store.as_ref(), &options, now).await.unwrap();

        let snapshot = store.snapshot();
        assert_eq!(snapshot.len(), MANAGED_FEATURES.len());
        for feature in MANAGED_FEATURES {
            assert!(
                snapshot
                    .iter()
                    .any(|k| &k.feature == feature && k.sequence == 1),
                "expected a sequence=1 key for {feature:?}"
            );
        }
    }

    #[tokio::test]
    async fn rotates_and_retires_expired_key() {
        let now = OffsetDateTime::now_utc();
        let options = RotatorOptions {
            interval: Duration::from_secs(60),
            key_duration: Duration::from_secs(24 * 60 * 60), // 24h
        };
        let expired = CryptoKeyRow {
            feature: CryptoKeyFeature::WorkspaceAppsToken,
            sequence: 7,
            secret: vec![0xAA; 64],
            // starts_at 25h ago → 1h past expiry → should rotate.
            starts_at: now - time::Duration::hours(25),
            deletes_at: None,
        };
        let store = RotatorStore::new(vec![expired]);

        rotate_once(store.as_ref(), &options, now).await.unwrap();

        let snapshot = store.snapshot();
        let tokens: Vec<_> = snapshot
            .iter()
            .filter(|k| k.feature == CryptoKeyFeature::WorkspaceAppsToken)
            .collect();
        assert_eq!(tokens.len(), 2, "old key retained, new key inserted");
        let old = tokens
            .iter()
            .find(|k| k.sequence == 7)
            .expect("old key persisted");
        assert!(
            old.deletes_at.is_some(),
            "old key must be marked with deletes_at after rotation"
        );
        let new = tokens
            .iter()
            .find(|k| k.sequence == 8)
            .expect("new key inserted with sequence += 1");
        assert!(
            new.deletes_at.is_none(),
            "freshly-minted key must not have deletes_at set"
        );
        assert!(
            new.starts_at >= now,
            "new key must start in the future to allow propagation"
        );
    }

    #[tokio::test]
    async fn deletes_keys_past_deletes_at() {
        let now = OffsetDateTime::now_utc();
        let options = RotatorOptions {
            interval: Duration::from_secs(60),
            key_duration: Duration::from_secs(24 * 60 * 60),
        };
        // A fresh sibling key keeps the feature's valid count above zero.
        let valid = CryptoKeyRow {
            feature: CryptoKeyFeature::TailnetResume,
            sequence: 2,
            secret: vec![0x01; 64],
            starts_at: now - time::Duration::minutes(5),
            deletes_at: None,
        };
        let retired = CryptoKeyRow {
            feature: CryptoKeyFeature::TailnetResume,
            sequence: 1,
            secret: vec![0xFF; 64],
            starts_at: now - time::Duration::hours(3),
            deletes_at: Some(now - time::Duration::minutes(1)),
        };
        let store = RotatorStore::new(vec![valid, retired]);

        rotate_once(store.as_ref(), &options, now).await.unwrap();

        let snapshot = store.snapshot();
        let remaining: Vec<_> = snapshot
            .iter()
            .filter(|k| k.feature == CryptoKeyFeature::TailnetResume)
            .collect();
        assert_eq!(remaining.len(), 1, "retired key should be deleted");
        assert_eq!(
            remaining[0].sequence, 2,
            "the surviving key should be the non-retired one"
        );
    }

    #[tokio::test]
    async fn fresh_key_is_left_alone() {
        let now = OffsetDateTime::now_utc();
        let options = RotatorOptions {
            interval: Duration::from_secs(60),
            key_duration: Duration::from_secs(24 * 60 * 60),
        };
        let fresh = CryptoKeyRow {
            feature: CryptoKeyFeature::WorkspaceAppsApiKey,
            sequence: 1,
            secret: vec![0x42; 32],
            starts_at: now - time::Duration::minutes(1),
            deletes_at: None,
        };
        let store = RotatorStore::new(vec![fresh.clone()]);

        rotate_once(store.as_ref(), &options, now).await.unwrap();

        let snapshot = store.snapshot();
        let keys: Vec<_> = snapshot
            .iter()
            .filter(|k| k.feature == CryptoKeyFeature::WorkspaceAppsApiKey)
            .collect();
        assert_eq!(keys.len(), 1, "fresh key should not be rotated or deleted");
        assert_eq!(keys[0].sequence, 1);
        assert!(keys[0].deletes_at.is_none());
    }

    #[tokio::test]
    async fn full_rotation_lifecycle_eventually_deletes_old_key() {
        // Simulates the flow a caller sees across multiple sweeps:
        // (1) expired key → gets rotated & retired, new key minted;
        // (2) time advances past the retired key's deletes_at → it is deleted.
        let t0 = OffsetDateTime::now_utc();
        let options = RotatorOptions {
            interval: Duration::from_secs(60),
            key_duration: Duration::from_secs(24 * 60 * 60),
        };
        let expired = CryptoKeyRow {
            feature: CryptoKeyFeature::WorkspaceAppsToken,
            sequence: 1,
            secret: vec![0xAA; 64],
            starts_at: t0 - time::Duration::hours(25),
            deletes_at: None,
        };
        let store = RotatorStore::new(vec![expired]);

        // Sweep 1: retires old, inserts new.
        rotate_once(store.as_ref(), &options, t0).await.unwrap();
        let after_rotate: Vec<_> = store
            .snapshot()
            .into_iter()
            .filter(|k| k.feature == CryptoKeyFeature::WorkspaceAppsToken)
            .collect();
        assert_eq!(
            after_rotate.len(),
            2,
            "rotation must produce a retired predecessor plus a successor"
        );

        // Advance time past the retired key's deletes_at (starts_at + 1h +
        // token_duration(60s) = well within 2 hours under RotatorOptions).
        let t1 = t0 + time::Duration::hours(24);
        rotate_once(store.as_ref(), &options, t1).await.unwrap();

        let after_cleanup: Vec<_> = store
            .snapshot()
            .into_iter()
            .filter(|k| k.feature == CryptoKeyFeature::WorkspaceAppsToken)
            .collect();
        let old = after_cleanup.iter().find(|k| k.sequence == 1);
        assert!(old.is_none(), "retired key should be gone after deletes_at");
        assert!(
            after_cleanup.iter().any(|k| k.sequence >= 2),
            "a replacement key must still exist"
        );
    }

    #[tokio::test]
    async fn insert_new_key_accounts_for_future_dated_rows() {
        // Regression: `insert_new_key` once computed `max_sequence` from
        // `list_by_feature`, whose production SQL filters out rows with
        // `starts_at > NOW()`. A future-dated successor (the normal output
        // of `rotate_key`) would therefore be invisible and the next insert
        // would collide on the `(feature, sequence)` PRIMARY KEY. Using
        // `list_all()` + a client-side filter avoids that.
        let now = OffsetDateTime::now_utc();
        let future = CryptoKeyRow {
            feature: CryptoKeyFeature::WorkspaceAppsApiKey,
            sequence: 42,
            secret: vec![0xCC; 32],
            // starts_at in the future → production `list_by_feature` excludes it.
            starts_at: now + time::Duration::hours(1),
            deletes_at: None,
        };
        let store = RotatorStore::new(vec![future]);

        insert_new_key(store.as_ref(), CryptoKeyFeature::WorkspaceAppsApiKey, now)
            .await
            .expect("insert_new_key should succeed");

        let snapshot = store.snapshot();
        let sequences: Vec<i32> = snapshot
            .iter()
            .filter(|k| k.feature == CryptoKeyFeature::WorkspaceAppsApiKey)
            .map(|k| k.sequence)
            .collect();
        assert_eq!(
            sequences.len(),
            2,
            "future-dated predecessor must be preserved alongside the new key"
        );
        assert!(
            sequences.contains(&43),
            "new key must increment past the future-dated sequence (42 → 43); got {sequences:?}"
        );
    }
}
