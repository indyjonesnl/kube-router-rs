//! Netlink retry wrapper, mirroring `upstream/internal/nlretry`.
//!
//! The Go upstream retries netlink dump calls that fail with a transient
//! "dump interrupted" / `EINTR` condition, using a capped exponential backoff
//! (~1ms → 100ms, up to 30 attempts). This module reproduces that policy in a
//! transport-agnostic way: the caller supplies the operation and a predicate
//! that decides whether an error is retryable.

use std::time::Duration;

/// Backoff/attempt policy for netlink operations.
#[derive(Debug, Clone, Copy)]
pub struct RetryConfig {
    /// Initial backoff before the first retry.
    pub base: Duration,
    /// Maximum backoff between attempts.
    pub max: Duration,
    /// Maximum number of attempts (including the first).
    pub attempts: u32,
}

impl Default for RetryConfig {
    fn default() -> Self {
        // Matches upstream nlretry defaults.
        Self {
            base: Duration::from_millis(1),
            max: Duration::from_millis(100),
            attempts: 30,
        }
    }
}

/// Run `op` with retries, sleeping with capped exponential backoff between
/// attempts as long as `retryable` returns true for the error. Returns the last
/// error once attempts are exhausted or the error is non-retryable.
pub async fn retry<T, E, F, Fut, R>(cfg: RetryConfig, retryable: R, mut op: F) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    R: Fn(&E) -> bool,
{
    let mut delay = cfg.base;
    let mut last_err: Option<E> = None;
    for attempt in 0..cfg.attempts.max(1) {
        match op().await {
            Ok(v) => return Ok(v),
            Err(e) => {
                if !retryable(&e) {
                    return Err(e);
                }
                last_err = Some(e);
                if attempt + 1 < cfg.attempts.max(1) {
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                    delay = (delay * 2).min(cfg.max);
                }
            }
        }
    }
    Err(last_err.expect("at least one attempt ran"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    const NO_SLEEP: RetryConfig = RetryConfig {
        base: Duration::ZERO,
        max: Duration::ZERO,
        attempts: 5,
    };

    #[tokio::test]
    async fn succeeds_first_try() {
        let calls = Cell::new(0);
        let r: Result<i32, ()> = retry(
            NO_SLEEP,
            |_| true,
            || {
                calls.set(calls.get() + 1);
                async { Ok(42) }
            },
        )
        .await;
        assert_eq!(r, Ok(42));
        assert_eq!(calls.get(), 1);
    }

    #[tokio::test]
    async fn retries_until_success() {
        let calls = Cell::new(0);
        let r: Result<i32, &str> = retry(
            NO_SLEEP,
            |_| true,
            || {
                calls.set(calls.get() + 1);
                let n = calls.get();
                async move {
                    if n < 3 {
                        Err("dump interrupted")
                    } else {
                        Ok(7)
                    }
                }
            },
        )
        .await;
        assert_eq!(r, Ok(7));
        assert_eq!(calls.get(), 3);
    }

    #[tokio::test]
    async fn gives_up_after_attempts() {
        let calls = Cell::new(0);
        let r: Result<(), &str> = retry(
            NO_SLEEP,
            |_| true,
            || {
                calls.set(calls.get() + 1);
                async { Err("always") }
            },
        )
        .await;
        assert_eq!(r, Err("always"));
        assert_eq!(calls.get(), 5);
    }

    #[tokio::test]
    async fn non_retryable_returns_immediately() {
        let calls = Cell::new(0);
        let r: Result<(), &str> = retry(
            NO_SLEEP,
            |_| false,
            || {
                calls.set(calls.get() + 1);
                async { Err("fatal") }
            },
        )
        .await;
        assert_eq!(r, Err("fatal"));
        assert_eq!(calls.get(), 1);
    }
}
