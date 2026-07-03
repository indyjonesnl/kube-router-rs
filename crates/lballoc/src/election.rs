//! Lease-based leader election, mirroring the `leaderelection` usage in
//! `lballoc.go` (Lease `kube-router-lballoc`, 15s/10s/2s). Only the elected
//! instance allocates, so IPs are never double-assigned cluster-wide.

use async_trait::async_trait;
use std::time::Duration;

/// Lease name held by the LB allocator leader.
pub const LEASE_NAME: &str = "kube-router-lballoc";
/// How long a held lease is valid without renewal.
pub const LEASE_DURATION: Duration = Duration::from_secs(15);
/// Deadline within which the leader must renew.
pub const RENEW_DEADLINE: Duration = Duration::from_secs(10);
/// How often to attempt acquire/renew.
pub const RETRY_PERIOD: Duration = Duration::from_secs(2);

/// Lease operation error.
#[derive(Debug, thiserror::Error)]
#[error("lease error: {0}")]
pub struct LeaseError(pub String);

/// Backend that attempts to acquire or renew the leader Lease.
#[async_trait]
pub trait LeaseBackend: Send + Sync {
    /// Try to acquire (if free/expired) or renew (if held by us) the lease.
    /// Returns whether this instance currently holds leadership.
    async fn acquire_or_renew(&self) -> Result<bool, LeaseError>;
}

/// Pure decision: can `me` take the lease given the current holder and whether
/// the lease has expired? Free, self-held, or expired all permit acquisition.
pub fn can_acquire(current_holder: Option<&str>, expired: bool, me: &str) -> bool {
    match current_holder {
        None => true,
        Some(h) if h == me => true,
        Some(_) => expired,
    }
}

/// Tracks leadership, emitting a transition when it flips.
pub struct LeaderElector<B: LeaseBackend> {
    backend: B,
    is_leader: bool,
}

impl<B: LeaseBackend> LeaderElector<B> {
    /// New elector, initially not the leader.
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            is_leader: false,
        }
    }

    /// Whether this instance currently believes it is the leader.
    pub fn is_leader(&self) -> bool {
        self.is_leader
    }

    /// One acquire/renew attempt. Returns `Some(new_state)` only when leadership
    /// transitions (became or lost leader), else `None`. A backend error is
    /// treated as "not leader" (fail safe).
    pub async fn tick(&mut self) -> Option<bool> {
        let held = self.backend.acquire_or_renew().await.unwrap_or(false);
        if held != self.is_leader {
            self.is_leader = held;
            Some(held)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn can_acquire_when_free_self_or_expired() {
        assert!(can_acquire(None, false, "me"));
        assert!(can_acquire(Some("me"), false, "me"));
        assert!(can_acquire(Some("other"), true, "me")); // expired
        assert!(!can_acquire(Some("other"), false, "me")); // held & fresh
    }

    /// Fake backend replaying a scripted sequence of hold results.
    struct FakeLease {
        script: Vec<bool>,
        idx: AtomicUsize,
    }
    #[async_trait]
    impl LeaseBackend for FakeLease {
        async fn acquire_or_renew(&self) -> Result<bool, LeaseError> {
            let i = self.idx.fetch_add(1, Ordering::SeqCst);
            Ok(*self.script.get(i).unwrap_or(&false))
        }
    }

    #[tokio::test]
    async fn elector_emits_transitions_on_acquire_renew_lose() {
        let backend = FakeLease {
            // acquire, renew (no transition), renew, lose, stay-lost
            script: vec![true, true, true, false, false],
            idx: AtomicUsize::new(0),
        };
        let mut e = LeaderElector::new(backend);
        assert_eq!(e.tick().await, Some(true)); // became leader
        assert!(e.is_leader());
        assert_eq!(e.tick().await, None); // still leader (renew)
        assert_eq!(e.tick().await, None); // still leader
        assert_eq!(e.tick().await, Some(false)); // lost leadership
        assert!(!e.is_leader());
        assert_eq!(e.tick().await, None); // still not leader
    }
}
