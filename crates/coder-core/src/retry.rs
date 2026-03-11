//! Reusable retry strategies with jitter for async operations.

use std::{future::Future, time::Duration};

use rand::Rng;
use tracing::warn;

/// Describes how retries are scheduled after a failed attempt.
#[derive(Clone, Debug)]
pub enum RetryStrategy {
    /// Constant delay between attempts.
    Fixed {
        /// Delay between attempts.
        delay: Duration,
        /// Total number of attempts (including the first).
        max_attempts: usize,
    },
    /// Exponentially increasing delay with a cap.
    ExponentialBackoff {
        /// Delay after the first failure.
        initial_delay: Duration,
        /// Total number of attempts (including the first).
        max_attempts: usize,
        /// Upper bound on the computed delay.
        max_delay: Duration,
    },
}

impl RetryStrategy {
    /// Returns the maximum number of attempts.
    #[must_use]
    fn max_attempts(&self) -> usize {
        match self {
            Self::Fixed { max_attempts, .. } | Self::ExponentialBackoff { max_attempts, .. } => {
                *max_attempts
            }
        }
    }

    /// Computes the delay for the given zero-based retry index.
    #[must_use]
    fn delay_for_attempt(&self, attempt: usize) -> Duration {
        match self {
            Self::Fixed { delay, .. } => *delay,
            Self::ExponentialBackoff {
                initial_delay,
                max_delay,
                ..
            } => {
                let multiplier = match 1u64.checked_shl(attempt.min(31) as u32) {
                    Some(v) => v,
                    None => u64::MAX,
                };
                let base = initial_delay
                    .as_millis()
                    .saturating_mul(u128::from(multiplier));
                let capped = base.min(max_delay.as_millis());
                // Truncation is safe: capped is at most max_delay which fits in u64.
                Duration::from_millis(capped as u64)
            }
        }
    }
}

/// Adds uniformly distributed jitter to a base delay.
///
/// The returned duration is between `base * 0.75` and `base * 1.25`.
fn with_jitter(base: Duration) -> Duration {
    let millis = base.as_millis() as u64;
    if millis == 0 {
        return base;
    }
    let jitter_range = millis / 4;
    if jitter_range == 0 {
        return base;
    }
    let offset = rand::thread_rng().gen_range(0..=jitter_range.saturating_mul(2));
    let jittered = millis.saturating_sub(jitter_range).saturating_add(offset);
    Duration::from_millis(jittered)
}

/// Executes `operation` with automatic retries according to the given strategy.
///
/// The `classify` callback decides whether a particular error is retryable.
/// When it returns `true` and attempts remain, the operation is retried after
/// a jittered delay.  All retry attempts are logged at `warn` level.
///
/// # Type Parameters
///
/// * `F`  - A closure that produces futures (called once per attempt).
/// * `Fut` - The future returned by the closure.
/// * `T`  - The success value.
/// * `E`  - The error type (must implement `Display` for logging).
pub async fn retry_with_strategy<F, Fut, T, E>(
    strategy: RetryStrategy,
    classify: impl Fn(&E) -> bool,
    mut operation: F,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let max_attempts = strategy.max_attempts().max(1);
    let mut last_error: Option<E> = None;

    for attempt in 0..max_attempts {
        match operation().await {
            Ok(value) => return Ok(value),
            Err(error) => {
                let is_last = attempt + 1 >= max_attempts;
                if is_last || !classify(&error) {
                    return Err(error);
                }

                let delay = with_jitter(strategy.delay_for_attempt(attempt));
                warn!(
                    attempt = attempt + 1,
                    max_attempts,
                    delay_ms = delay.as_millis() as u64,
                    error = %error,
                    "retrying after transient failure",
                );
                tokio::time::sleep(delay).await;
                last_error = Some(error);
            }
        }
    }

    // This branch is only reachable when max_attempts is 0, which max(1)
    // prevents.  Still, satisfy the type checker.
    Err(last_error.ok_or_else(|| {
        // SAFETY: unreachable because max_attempts >= 1.
        // But we cannot panic (clippy::panic is denied), so we loop once.
        // The for-loop above always returns.
        loop {}
    })?)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[tokio::test]
    async fn fixed_strategy_succeeds_on_first_try() {
        let result: Result<&str, &str> = retry_with_strategy(
            RetryStrategy::Fixed {
                delay: Duration::from_millis(10),
                max_attempts: 3,
            },
            |_| true,
            || async { Ok("ok") },
        )
        .await;

        assert_eq!(result, Ok("ok"));
    }

    #[tokio::test]
    async fn retries_until_success() {
        let counter = AtomicUsize::new(0);

        let result: Result<&str, String> = retry_with_strategy(
            RetryStrategy::Fixed {
                delay: Duration::from_millis(1),
                max_attempts: 3,
            },
            |_| true,
            || {
                let attempt = counter.fetch_add(1, Ordering::SeqCst);
                async move {
                    if attempt < 2 {
                        Err(format!("fail {attempt}"))
                    } else {
                        Ok("ok")
                    }
                }
            },
        )
        .await;

        assert_eq!(result, Ok("ok"));
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn gives_up_after_max_attempts() {
        let counter = AtomicUsize::new(0);

        let result: Result<&str, String> = retry_with_strategy(
            RetryStrategy::Fixed {
                delay: Duration::from_millis(1),
                max_attempts: 2,
            },
            |_| true,
            || {
                counter.fetch_add(1, Ordering::SeqCst);
                async { Err("always fail".to_owned()) }
            },
        )
        .await;

        assert!(result.is_err());
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn non_retryable_error_stops_immediately() {
        let counter = AtomicUsize::new(0);

        let result: Result<&str, String> = retry_with_strategy(
            RetryStrategy::Fixed {
                delay: Duration::from_millis(1),
                max_attempts: 5,
            },
            |error: &String| error.contains("transient"),
            || {
                counter.fetch_add(1, Ordering::SeqCst);
                async { Err("permanent failure".to_owned()) }
            },
        )
        .await;

        assert!(result.is_err());
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn exponential_backoff_respects_max_delay() {
        let strategy = RetryStrategy::ExponentialBackoff {
            initial_delay: Duration::from_millis(100),
            max_attempts: 5,
            max_delay: Duration::from_millis(500),
        };

        // Attempt 0: 100ms, 1: 200ms, 2: 400ms, 3: 500ms (capped)
        assert_eq!(strategy.delay_for_attempt(0), Duration::from_millis(100));
        assert_eq!(strategy.delay_for_attempt(1), Duration::from_millis(200));
        assert_eq!(strategy.delay_for_attempt(2), Duration::from_millis(400));
        assert_eq!(strategy.delay_for_attempt(3), Duration::from_millis(500));
        assert_eq!(strategy.delay_for_attempt(4), Duration::from_millis(500));
    }

    #[test]
    fn jitter_stays_within_bounds() {
        let base = Duration::from_millis(1000);
        for _ in 0..100 {
            let jittered = with_jitter(base);
            assert!(jittered >= Duration::from_millis(750));
            assert!(jittered <= Duration::from_millis(1250));
        }
    }
}
