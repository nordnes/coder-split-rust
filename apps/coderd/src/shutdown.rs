//! Graceful shutdown coordinator.
//!
//! Runs registered shutdown tasks sequentially in dependency order, enforcing
//! a **total** timeout budget so that the entire shutdown sequence completes
//! within the configured grace period.
#![forbid(unsafe_code)]

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use tracing::{info, warn};

/// A future that produces `()` and can be sent across threads.
type BoxFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Coordinates an ordered, timeout-enforced shutdown of application components.
///
/// Components are registered with a human-readable name and a future that
/// performs their cleanup work.  When [`run`](Self::run) is called the tasks
/// execute **sequentially** in the order they were registered.  The supplied
/// `timeout` is a **total** budget shared across all tasks — each task receives
/// whatever time remains after the previous ones complete, and if the budget is
/// exhausted the remaining tasks are skipped.
pub(crate) struct ShutdownCoordinator {
    tasks: Vec<(&'static str, BoxFuture)>,
}

impl ShutdownCoordinator {
    /// Creates an empty coordinator with no registered tasks.
    pub(crate) fn new() -> Self {
        Self { tasks: Vec::new() }
    }

    /// Registers a shutdown task that will run during the shutdown sequence.
    ///
    /// Tasks run in registration order, so callers should register them in
    /// reverse-dependency order (e.g. audit before database).
    pub(crate) fn register(
        &mut self,
        name: &'static str,
        task: impl Future<Output = ()> + Send + 'static,
    ) {
        self.tasks.push((name, Box::pin(task)));
    }

    /// Executes all registered shutdown tasks sequentially within `timeout`.
    ///
    /// The timeout is a **total** budget.  Each task receives whatever time
    /// remains after the previous tasks.  If the budget is exhausted a warning
    /// is logged and the remaining tasks are skipped.
    pub(crate) async fn run(self, timeout: Duration) {
        let deadline = tokio::time::Instant::now() + timeout;

        for (name, task) in self.tasks {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                warn!(component = name, "shutdown budget exhausted, skipping");
                continue;
            }

            info!(component = name, "shutting down");
            match tokio::time::timeout(remaining, task).await {
                Ok(()) => info!(component = name, "shutdown complete"),
                Err(_) => warn!(component = name, "shutdown timed out"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

    #[tokio::test]
    async fn runs_tasks_in_registration_order() {
        let order = Arc::new(AtomicU8::new(0));

        let mut coordinator = ShutdownCoordinator::new();

        let o1 = order.clone();
        coordinator.register("first", async move {
            assert_eq!(o1.fetch_add(1, Ordering::SeqCst), 0);
        });

        let o2 = order.clone();
        coordinator.register("second", async move {
            assert_eq!(o2.fetch_add(1, Ordering::SeqCst), 1);
        });

        coordinator.run(Duration::from_secs(5)).await;
        assert_eq!(order.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn timed_out_task_exhausts_budget_for_remaining() {
        let reached = Arc::new(AtomicBool::new(false));

        let mut coordinator = ShutdownCoordinator::new();

        // This task will hang forever.
        coordinator.register("slow", async {
            std::future::pending::<()>().await;
        });

        let r = reached.clone();
        coordinator.register("fast", async move {
            r.store(true, Ordering::SeqCst);
        });

        // Total budget is 100ms; the slow task eats it all, so "fast" gets
        // skipped because the budget is exhausted.
        coordinator.run(Duration::from_millis(100)).await;
        assert!(
            !reached.load(Ordering::SeqCst),
            "fast task should be skipped when budget is exhausted"
        );
    }

    #[tokio::test]
    async fn empty_coordinator_completes_immediately() {
        let coordinator = ShutdownCoordinator::new();
        coordinator.run(Duration::from_secs(1)).await;
    }

    #[tokio::test]
    async fn total_budget_respected() {
        let start = tokio::time::Instant::now();

        let mut coordinator = ShutdownCoordinator::new();

        // Two tasks that each try to sleep 200ms, but total budget is 150ms.
        coordinator.register("a", async {
            tokio::time::sleep(Duration::from_millis(200)).await;
        });
        coordinator.register("b", async {
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        coordinator.run(Duration::from_millis(150)).await;

        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(200),
            "total shutdown should complete within the budget, took {elapsed:?}"
        );
    }
}
