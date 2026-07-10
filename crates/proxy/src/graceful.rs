//! Graceful destination termination, mirroring `network_service_graceful.go`.
//!
//! When `--ipvs-graceful-termination` is enabled, a removed endpoint is first
//! drained (IPVS weight set to 0) and queued; it is only deleted once it has no
//! active/inactive connections or its grace period elapses.

use std::time::Instant;

use crate::ipvs::{IpvsDestination, IpvsService};

/// A destination drained and awaiting deletion.
pub struct PendingRemoval {
    /// Owning virtual service.
    pub svc: IpvsService,
    /// Drained destination (weight 0).
    pub dst: IpvsDestination,
    /// When the grace period expires.
    pub deadline: Instant,
}

/// FIFO of destinations pending graceful deletion (dedup by service + dst).
#[derive(Default)]
pub struct GracefulQueue {
    items: Vec<PendingRemoval>,
}

fn same_dst(a: &IpvsService, ad: &IpvsDestination, b: &IpvsService, bd: &IpvsDestination) -> bool {
    a.key() == b.key() && ad.addr == bd.addr && ad.port == bd.port
}

impl GracefulQueue {
    /// New empty queue.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of pending removals.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Queue a destination for graceful removal; ignored if already queued.
    pub fn enqueue(&mut self, svc: IpvsService, dst: IpvsDestination, deadline: Instant) {
        if self
            .items
            .iter()
            .any(|p| same_dst(&p.svc, &p.dst, &svc, &dst))
        {
            return;
        }
        self.items.push(PendingRemoval { svc, dst, deadline });
    }

    /// Remove and return all queued items, leaving the queue empty. The caller
    /// re-queues whichever survivors are still draining.
    pub fn take(&mut self) -> Vec<PendingRemoval> {
        std::mem::take(&mut self.items)
    }

    /// Re-queue a survivor that is still draining.
    pub fn requeue(&mut self, p: PendingRemoval) {
        self.items.push(p);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Protocol, SchedFlags, Scheduler};
    use std::time::Duration;

    fn svc() -> IpvsService {
        IpvsService {
            addr: "10.96.0.10".parse().unwrap(),
            protocol: Protocol::Tcp,
            port: 80,
            scheduler: Scheduler::Rr,
            sched_flags: SchedFlags::default(),
            persistent: None,
        }
    }
    fn dst(ip: &str) -> IpvsDestination {
        IpvsDestination {
            addr: ip.parse().unwrap(),
            port: 8080,
            weight: 0,
            tunnel: false,
        }
    }

    #[test]
    fn enqueue_dedups_by_service_and_destination() {
        let mut q = GracefulQueue::new();
        let dl = Instant::now() + Duration::from_secs(30);
        q.enqueue(svc(), dst("10.244.0.5"), dl);
        q.enqueue(svc(), dst("10.244.0.5"), dl);
        q.enqueue(svc(), dst("10.244.1.5"), dl);
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn take_empties_and_requeue_restores() {
        let mut q = GracefulQueue::new();
        q.enqueue(svc(), dst("10.244.0.5"), Instant::now());
        let items = q.take();
        assert!(q.is_empty());
        assert_eq!(items.len(), 1);
        q.requeue(items.into_iter().next().unwrap());
        assert_eq!(q.len(), 1);
    }
}
