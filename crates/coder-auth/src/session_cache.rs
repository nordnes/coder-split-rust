//! In-memory session authentication cache to reduce database pressure.
//!
//! Caches the result of `find_user_by_session_token_hash` so that repeated
//! authenticated requests within the TTL window avoid a full PostgreSQL JOIN
//! query.  Inspired by Zed's snapshot-based reads — we produce a cheap clone
//! of the cached data for concurrent access.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use coder_core::AuthenticatedUser;
use metrics::counter;
use tokio::sync::RwLock;
use tracing::instrument;

/// One cached session entry with its authentication payload and insertion time.
#[derive(Clone, Debug)]
pub struct CachedSession {
    /// The authenticated user payload returned by the store.
    pub user: AuthenticatedUser,
    /// Monotonic instant when this entry was cached.
    pub cached_at: Instant,
}

/// In-memory session token cache backed by a `RwLock<HashMap>`.
///
/// Read-heavy workloads benefit from the shared read lock, while cache
/// misses and evictions take a brief exclusive write lock.
#[derive(Debug)]
pub struct SessionCache {
    entries: Arc<RwLock<HashMap<Vec<u8>, CachedSession>>>,
    ttl: Duration,
}

impl SessionCache {
    /// Creates a new cache with the given time-to-live for entries.
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            ttl,
        }
    }

    /// Looks up a cached session by its hashed token.
    ///
    /// Returns `Some(user)` on a cache hit within TTL, or `None` on miss/expiry.
    /// Expired entries are lazily evicted on the next `insert` or `evict` call.
    #[instrument(skip(self, token_hash))]
    pub async fn get(&self, token_hash: &[u8]) -> Option<AuthenticatedUser> {
        let entries = self.entries.read().await;
        if let Some(cached) = entries.get(token_hash) {
            if cached.cached_at.elapsed() < self.ttl {
                counter!("session_cache_hits").increment(1);
                return Some(cached.user.clone());
            }
            // Expired — will be lazily cleaned up.
            counter!("session_cache_misses").increment(1);
            return None;
        }
        counter!("session_cache_misses").increment(1);
        None
    }

    /// Inserts or replaces a cached session entry.
    #[instrument(skip(self, token_hash, user))]
    pub async fn insert(&self, token_hash: Vec<u8>, user: AuthenticatedUser) {
        let mut entries = self.entries.write().await;
        entries.insert(
            token_hash,
            CachedSession {
                user,
                cached_at: Instant::now(),
            },
        );
    }

    /// Evicts a single session by its hashed token (e.g. on logout).
    #[instrument(skip(self, token_hash))]
    pub async fn evict(&self, token_hash: &[u8]) {
        let mut entries = self.entries.write().await;
        if entries.remove(token_hash).is_some() {
            counter!("session_cache_evictions").increment(1);
        }
    }

    /// Evicts all sessions belonging to a specific user (e.g. on password change).
    #[instrument(skip(self))]
    pub async fn evict_user(&self, user_id: uuid::Uuid) {
        let mut entries = self.entries.write().await;
        let before = entries.len();
        entries.retain(|_, cached| cached.user.id != user_id);
        let evicted = before.saturating_sub(entries.len());
        if evicted > 0 {
            counter!("session_cache_evictions").increment(evicted as u64);
        }
    }

    /// Returns the number of entries currently in the cache (including expired).
    #[must_use]
    pub async fn len(&self) -> usize {
        self.entries.read().await.len()
    }

    /// Returns whether the cache is empty.
    #[must_use]
    pub async fn is_empty(&self) -> bool {
        self.entries.read().await.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use coder_core::{AuthenticatedUser, LoginType, UserStatus};
    use time::OffsetDateTime;
    use uuid::Uuid;

    fn make_user(id: Uuid) -> AuthenticatedUser {
        AuthenticatedUser {
            id,
            email: format!("{id}@test.com"),
            username: format!("user-{id}"),
            name: "Test User".to_owned(),
            avatar_url: String::new(),
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            last_seen_at: None,
            organization_ids: vec![],
            roles: vec![],
            org_roles: vec![],
            login_type: LoginType::Password,
            status: UserStatus::Active,
        }
    }

    #[tokio::test]
    async fn cache_hit_returns_user() {
        let cache = SessionCache::new(Duration::from_secs(30));
        let user = make_user(Uuid::new_v4());
        let token_hash = vec![1, 2, 3];

        cache.insert(token_hash.clone(), user.clone()).await;
        let result = cache.get(&token_hash).await;

        assert!(result.is_some());
        let cached_user = result.unwrap_or_else(|| unreachable!());
        assert_eq!(cached_user.id, user.id);
        assert_eq!(cached_user.email, user.email);
    }

    #[tokio::test]
    async fn cache_miss_returns_none() {
        let cache = SessionCache::new(Duration::from_secs(30));
        let result = cache.get(&[4, 5, 6]).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn cache_eviction_on_logout() {
        let cache = SessionCache::new(Duration::from_secs(30));
        let user = make_user(Uuid::new_v4());
        let token_hash = vec![7, 8, 9];

        cache.insert(token_hash.clone(), user).await;
        assert!(!cache.is_empty().await);

        cache.evict(&token_hash).await;
        let result = cache.get(&token_hash).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn cache_ttl_expiry() {
        let cache = SessionCache::new(Duration::from_millis(1));
        let user = make_user(Uuid::new_v4());
        let token_hash = vec![10, 11, 12];

        cache.insert(token_hash.clone(), user).await;
        // Wait for expiry.
        tokio::time::sleep(Duration::from_millis(10)).await;

        let result = cache.get(&token_hash).await;
        assert!(result.is_none(), "expired entry should not be returned");
    }

    #[tokio::test]
    async fn cache_evict_user_removes_all_sessions() {
        let cache = SessionCache::new(Duration::from_secs(30));
        let user_id = Uuid::new_v4();
        let user = make_user(user_id);

        // Insert multiple sessions for the same user.
        cache.insert(vec![1], user.clone()).await;
        cache.insert(vec![2], user.clone()).await;
        cache.insert(vec![3], user).await;
        assert_eq!(cache.len().await, 3);

        cache.evict_user(user_id).await;
        assert!(cache.is_empty().await);
    }

    #[tokio::test]
    async fn cache_evict_user_does_not_affect_other_users() {
        let cache = SessionCache::new(Duration::from_secs(30));
        let user_a = make_user(Uuid::new_v4());
        let user_b = make_user(Uuid::new_v4());

        cache.insert(vec![1], user_a.clone()).await;
        cache.insert(vec![2], user_b.clone()).await;

        cache.evict_user(user_a.id).await;
        assert_eq!(cache.len().await, 1);

        let result = cache.get(&[2]).await;
        assert!(result.is_some());
        let cached = result.unwrap_or_else(|| unreachable!());
        assert_eq!(cached.id, user_b.id);
    }

    #[tokio::test]
    async fn concurrent_access_safety() {
        let cache = Arc::new(SessionCache::new(Duration::from_secs(30)));
        let mut handles = Vec::new();

        for i in 0u8..50 {
            let cache = Arc::clone(&cache);
            handles.push(tokio::spawn(async move {
                let user = make_user(Uuid::new_v4());
                cache.insert(vec![i], user).await;
                cache.get(&[i]).await
            }));
        }

        for handle in handles {
            let result = handle.await;
            assert!(result.is_ok());
            assert!(result.unwrap_or_else(|_| unreachable!()).is_some());
        }

        assert_eq!(cache.len().await, 50);
    }
}
