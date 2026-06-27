//! Cache-sync barrier with a timeout, mirroring upstream's
//! `CacheSyncOrTimeout` (`--cache-sync-timeout`).

use std::future::Future;
use std::time::Duration;

/// Returned when a cache sync does not complete within the configured timeout.
#[derive(Debug, thiserror::Error)]
#[error("cache sync timed out after {0:?}")]
pub struct CacheSyncTimeout(pub Duration);

/// Await `fut` (a cache-readiness future) bounded by `timeout`.
pub async fn wait_with_timeout<F>(fut: F, timeout: Duration) -> Result<(), CacheSyncTimeout>
where
    F: Future<Output = ()>,
{
    tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| CacheSyncTimeout(timeout))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ready_future_succeeds() {
        let r = wait_with_timeout(async {}, Duration::from_secs(1)).await;
        assert!(r.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn never_ready_times_out() {
        let r = wait_with_timeout(std::future::pending::<()>(), Duration::from_millis(50)).await;
        assert!(matches!(r, Err(CacheSyncTimeout(_))));
    }
}
