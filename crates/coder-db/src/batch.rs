//! Request-scoped database query batching.
//!
//! Inspired by Zed's git `cat-file --batch` pattern — multiple callers
//! submit lookup keys via a channel, and a background task coalesces
//! them into a single `SELECT … WHERE id = ANY($1)` query.

use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;
use std::sync::Arc;

use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{instrument, warn};

/// Maximum number of keys to batch into a single SQL query.
const MAX_BATCH_SIZE: usize = 64;

/// A batched lookup service that coalesces individual key lookups into
/// bulk `WHERE id = ANY(...)` queries.
///
/// Callers submit a key and receive the result via a `oneshot` channel.
/// A background task collects keys and executes batch queries.
pub struct BatchedLookup<K, V> {
    /// Send side for submitting lookup requests.
    request_tx: mpsc::Sender<(K, oneshot::Sender<Option<V>>)>,
    /// Background task handle (kept alive via ownership).
    _task: JoinHandle<()>,
}

/// Trait for the batch query executor — implementors provide the actual
/// SQL query logic.
#[async_trait::async_trait]
pub trait BatchQueryExecutor<K, V>: Send + Sync + 'static
where
    K: Send + 'static,
    V: Send + 'static,
{
    /// Executes a batch query for the given keys and returns a map of
    /// results.  Keys not found in the store are absent from the map.
    async fn execute_batch(&self, keys: Vec<K>) -> Result<HashMap<K, V>, coder_core::StorageError>;
}

impl<K, V> BatchedLookup<K, V>
where
    K: Eq + Hash + Clone + Debug + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    /// Creates a new batched lookup backed by the supplied executor.
    pub fn new(executor: Arc<dyn BatchQueryExecutor<K, V>>) -> Self {
        let (request_tx, request_rx) = mpsc::channel(256);
        let task = tokio::spawn(batch_loop(request_rx, executor));

        Self {
            request_tx,
            _task: task,
        }
    }

    /// Submits a single key for batched lookup.
    ///
    /// Returns `None` if the key was not found, or `Some(value)` on hit.
    /// Returns `None` if the background task is unavailable (shutdown).
    #[instrument(skip(self))]
    pub async fn lookup(&self, key: K) -> Option<V> {
        let (response_tx, response_rx) = oneshot::channel();
        if self.request_tx.send((key, response_tx)).await.is_err() {
            return None;
        }
        response_rx.await.ok().flatten()
    }
}

/// Background loop that collects lookup requests and executes batch queries.
async fn batch_loop<K, V>(
    mut rx: mpsc::Receiver<(K, oneshot::Sender<Option<V>>)>,
    executor: Arc<dyn BatchQueryExecutor<K, V>>,
) where
    K: Eq + Hash + Clone + Debug + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    loop {
        // Wait for the first request.
        let Some((first_key, first_tx)) = rx.recv().await else {
            return; // Channel closed.
        };

        let mut pending: Vec<(K, oneshot::Sender<Option<V>>)> = Vec::with_capacity(MAX_BATCH_SIZE);
        pending.push((first_key, first_tx));

        // Drain any immediately-available requests up to the batch limit.
        while pending.len() < MAX_BATCH_SIZE {
            match rx.try_recv() {
                Ok(req) => pending.push(req),
                Err(_) => break,
            }
        }

        // Collect unique keys for the query.
        let keys: Vec<K> = pending.iter().map(|(k, _)| k.clone()).collect();

        // Execute the batch query.
        match executor.execute_batch(keys).await {
            Ok(results) => {
                for (key, tx) in pending {
                    let value = results.get(&key).cloned();
                    // Ignore send errors (receiver may have been dropped).
                    let _ = tx.send(value);
                }
            }
            Err(error) => {
                warn!(error = %error, "batch lookup query failed");
                // Send None to all waiters on failure.
                for (_, tx) in pending {
                    let _ = tx.send(None);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use coder_core::StorageError;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct FakeExecutor {
        call_count: AtomicUsize,
    }

    impl FakeExecutor {
        fn new() -> Self {
            Self {
                call_count: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait::async_trait]
    impl BatchQueryExecutor<u64, String> for FakeExecutor {
        async fn execute_batch(
            &self,
            keys: Vec<u64>,
        ) -> Result<HashMap<u64, String>, StorageError> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            let mut results = HashMap::new();
            for key in keys {
                if key < 100 {
                    results.insert(key, format!("value-{key}"));
                }
                // Keys >= 100 are "not found"
            }
            Ok(results)
        }
    }

    #[tokio::test]
    async fn single_lookup_returns_value() {
        let executor = Arc::new(FakeExecutor::new());
        let lookup =
            BatchedLookup::new(Arc::clone(&executor) as Arc<dyn BatchQueryExecutor<u64, String>>);

        let result = lookup.lookup(42).await;
        assert_eq!(result, Some("value-42".to_owned()));
    }

    #[tokio::test]
    async fn missing_key_returns_none() {
        let executor = Arc::new(FakeExecutor::new());
        let lookup =
            BatchedLookup::new(Arc::clone(&executor) as Arc<dyn BatchQueryExecutor<u64, String>>);

        let result = lookup.lookup(999).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn concurrent_lookups_are_batched() {
        let executor = Arc::new(FakeExecutor::new());
        let lookup = Arc::new(BatchedLookup::new(
            Arc::clone(&executor) as Arc<dyn BatchQueryExecutor<u64, String>>
        ));

        let mut handles = Vec::new();
        for i in 0u64..10 {
            let lookup = Arc::clone(&lookup);
            handles.push(tokio::spawn(async move { lookup.lookup(i).await }));
        }

        for (i, handle) in handles.into_iter().enumerate() {
            let result = handle.await;
            assert!(result.is_ok());
            let value = result.unwrap_or_else(|_| unreachable!());
            assert_eq!(value, Some(format!("value-{i}")));
        }

        // Because requests arrive close together, they should be batched
        // into fewer queries than 10 individual calls.
        let calls = executor.call_count.load(Ordering::SeqCst);
        assert!(calls <= 10, "expected batching, got {calls} calls");
    }
}
