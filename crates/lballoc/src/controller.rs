//! LoadBalancer allocation reconcile, mirroring `getAllocatedIPs` /
//! `allocateService` / `walkServices` in `lballoc.go`.

use std::net::IpAddr;

use async_trait::async_trait;

use crate::allocate::{plan_allocation, should_allocate};
use crate::model::LbService;
use crate::pools::IpRanges;

/// Supplies the current LoadBalancer services (from the informer store).
pub trait LbServiceProvider: Send + Sync {
    /// Snapshot of all services relevant to the allocator.
    fn services(&self) -> Vec<LbService>;
}

/// Status-update error.
#[derive(Debug, thiserror::Error)]
#[error("status update error: {0}")]
pub struct StatusError(pub String);

/// Appends allocated IPs to a service's `status.loadBalancer.ingress`.
#[async_trait]
pub trait StatusUpdater: Send + Sync {
    /// Append `ips` to the service's ingress status (RetryOnConflict semantics).
    async fn append_ingress(
        &self,
        namespace: &str,
        name: &str,
        ips: &[IpAddr],
    ) -> Result<(), StatusError>;
}

/// All IPs (per family) already handed out from the pools: any service's
/// external IPs or ingress IPs that fall within a configured range. Mirrors
/// `getAllocatedIPs` + `getIPsFromService`.
pub fn allocated_ips(
    services: &[LbService],
    v4_ranges: &IpRanges,
    v6_ranges: &IpRanges,
) -> (Vec<IpAddr>, Vec<IpAddr>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for svc in services {
        for ip in svc.external_ips.iter().chain(svc.ingress_ips.iter()) {
            match ip {
                IpAddr::V4(_) if v4_ranges.contains(*ip) => v4.push(*ip),
                IpAddr::V6(_) if v6_ranges.contains(*ip) => v6.push(*ip),
                _ => {}
            }
        }
    }
    (v4, v6)
}

/// Reconciles LoadBalancer services to pool allocations.
pub struct LbAllocator<P: LbServiceProvider, U: StatusUpdater> {
    v4_ranges: IpRanges,
    v6_ranges: IpRanges,
    is_default: bool,
    provider: P,
    updater: U,
}

impl<P: LbServiceProvider, U: StatusUpdater> LbAllocator<P, U> {
    /// Construct.
    pub fn new(
        v4_ranges: IpRanges,
        v6_ranges: IpRanges,
        is_default: bool,
        provider: P,
        updater: U,
    ) -> Self {
        Self {
            v4_ranges,
            v6_ranges,
            is_default,
            provider,
            updater,
        }
    }

    /// Allocate IPs for every owned service still missing one. Newly planned IPs
    /// are tracked within the pass so two services never get the same address.
    /// Returns the number of services updated.
    pub async fn reconcile(&mut self) -> Result<usize, StatusError> {
        let services = self.provider.services();
        let (mut a4, mut a6) = allocated_ips(&services, &self.v4_ranges, &self.v6_ranges);
        let mut updated = 0;
        for svc in &services {
            if !should_allocate(svc, self.is_default) {
                continue;
            }
            let plan =
                match plan_allocation(svc, &mut self.v4_ranges, &mut self.v6_ranges, &a4, &a6) {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!(ns = %svc.namespace, name = %svc.name, error = %e,
                        "failed to allocate LoadBalancer address");
                        continue;
                    }
                };
            let ips = plan.ips();
            if ips.is_empty() {
                continue;
            }
            for ip in &ips {
                if ip.is_ipv4() {
                    a4.push(*ip);
                } else {
                    a6.push(*ip);
                }
            }
            self.updater
                .append_ingress(&svc.namespace, &svc.name, &ips)
                .await?;
            updated += 1;
        }
        Ok(updated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::IpNet;
    use std::sync::Mutex;

    fn ranges(cidrs: &[&str]) -> IpRanges {
        IpRanges::new(cidrs.iter().map(|c| c.parse::<IpNet>().unwrap()).collect())
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn lb(name: &str) -> LbService {
        LbService {
            namespace: "default".into(),
            name: name.into(),
            is_loadbalancer: true,
            loadbalancer_class: None,
            want_v4: true,
            want_v6: false,
            require_dual: false,
            external_ips: vec![],
            ingress_ips: vec![],
        }
    }

    struct StaticProvider(Vec<LbService>);
    impl LbServiceProvider for StaticProvider {
        fn services(&self) -> Vec<LbService> {
            self.0.clone()
        }
    }

    #[derive(Default)]
    struct RecordUpdater(Mutex<Vec<(String, Vec<IpAddr>)>>);
    #[async_trait]
    impl StatusUpdater for RecordUpdater {
        async fn append_ingress(
            &self,
            _ns: &str,
            name: &str,
            ips: &[IpAddr],
        ) -> Result<(), StatusError> {
            self.0.lock().unwrap().push((name.into(), ips.to_vec()));
            Ok(())
        }
    }

    #[test]
    fn allocated_ips_collects_external_and_ingress_in_range() {
        let mut svc = lb("web");
        svc.external_ips = vec![ip("203.0.113.5"), ip("10.0.0.1")]; // 10.0.0.1 out of range
        svc.ingress_ips = vec![ip("203.0.113.6")];
        let (v4, _) = allocated_ips(&[svc], &ranges(&["203.0.113.0/24"]), &ranges(&[]));
        assert!(v4.contains(&ip("203.0.113.5")) && v4.contains(&ip("203.0.113.6")));
        assert!(!v4.contains(&ip("10.0.0.1")));
    }

    #[tokio::test]
    async fn reconcile_allocates_distinct_ips_and_updates_status() {
        let prov = StaticProvider(vec![lb("a"), lb("b")]);
        let updater = RecordUpdater::default();
        let mut alloc = LbAllocator::new(
            ranges(&["203.0.113.0/24"]),
            ranges(&[]),
            true,
            prov,
            updater,
        );
        let n = alloc.reconcile().await.unwrap();
        assert_eq!(n, 2);
        let recs = alloc.updater.0.lock().unwrap();
        // Two services, two distinct IPs.
        let assigned: Vec<IpAddr> = recs.iter().flat_map(|(_, ips)| ips.clone()).collect();
        assert_eq!(assigned.len(), 2);
        assert_ne!(assigned[0], assigned[1]);
    }

    #[tokio::test]
    async fn reconcile_skips_satisfied_and_unowned_services() {
        let mut satisfied = lb("done");
        satisfied.ingress_ips = vec![ip("203.0.113.9")];
        let mut foreign = lb("foreign");
        foreign.loadbalancer_class = Some("metallb".into());
        let prov = StaticProvider(vec![satisfied, foreign]);
        let updater = RecordUpdater::default();
        let mut alloc = LbAllocator::new(
            ranges(&["203.0.113.0/24"]),
            ranges(&[]),
            true,
            prov,
            updater,
        );
        assert_eq!(alloc.reconcile().await.unwrap(), 0);
    }
}
