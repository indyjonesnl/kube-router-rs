//! Service-class filtering + allocation planning, mirroring `shouldAllocate` /
//! `canAllocate` / `allocateService` in `lballoc.go`.

use std::net::IpAddr;

use crate::model::{LbService, LOAD_BALANCER_CLASS};
use crate::pools::IpRanges;

/// Allocation error.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AllocError {
    /// No range configured for a required family.
    #[error("no ranges available: {0}")]
    NoRanges(String),
    /// A required-dual-stack service could not get both families.
    #[error("unable to allocate dual-stack addresses")]
    DualStackUnavailable,
    /// No address was free in the relevant range(s).
    #[error("no IPs left to allocate")]
    Exhausted,
}

/// Whether this allocator owns a service's class (mirrors `checkClass`):
/// explicit `kube-router`, or (when default) `default`/unset.
pub fn check_class(class: Option<&str>, is_default: bool) -> bool {
    match class {
        Some(LOAD_BALANCER_CLASS) => true,
        Some("default") | None => is_default,
        _ => false,
    }
}

/// Whether the service still needs an ingress IP for a requested family
/// (mirrors `checkIngress`): a want/have family mismatch.
pub fn needs_ingress(svc: &LbService) -> bool {
    let (have4, have6) = svc.have_families();
    svc.want_v4 != have4 || svc.want_v6 != have6
}

/// Whether the allocator should act on this service (mirrors `shouldAllocate`).
pub fn should_allocate(svc: &LbService, is_default: bool) -> bool {
    svc.is_loadbalancer
        && check_class(svc.loadbalancer_class.as_deref(), is_default)
        && needs_ingress(svc)
}

/// A planned allocation: the addresses to add to `status.loadBalancer.ingress`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct AllocationPlan {
    /// IPv4 address to assign, if one was needed and available.
    pub v4: Option<IpAddr>,
    /// IPv6 address to assign, if one was needed and available.
    pub v6: Option<IpAddr>,
}

impl AllocationPlan {
    /// The addresses to append, in order.
    pub fn ips(&self) -> Vec<IpAddr> {
        self.v4.into_iter().chain(self.v6).collect()
    }
    fn is_empty(&self) -> bool {
        self.v4.is_none() && self.v6.is_none()
    }
}

/// Plan an allocation for one service (mirrors `canAllocate` + `allocateService`).
/// `allocated4`/`allocated6` are the IPs already handed out (from the range),
/// used to avoid collisions. Returns an empty plan when nothing is needed.
pub fn plan_allocation(
    svc: &LbService,
    v4_ranges: &mut IpRanges,
    v6_ranges: &mut IpRanges,
    allocated4: &[IpAddr],
    allocated6: &[IpAddr],
) -> Result<AllocationPlan, AllocError> {
    let can_v4 = !v4_ranges.is_empty();
    let can_v6 = !v6_ranges.is_empty();

    // canAllocate gating.
    if svc.require_dual && !can_v4 {
        return Err(AllocError::NoRanges("IPv4 required".into()));
    }
    if svc.require_dual && !can_v6 {
        return Err(AllocError::NoRanges("IPv6 required".into()));
    }
    if svc.want_v4 && !can_v4 && !svc.want_v6 {
        return Err(AllocError::NoRanges("no IPv4 ranges".into()));
    }
    if svc.want_v6 && !can_v6 && !svc.want_v4 {
        return Err(AllocError::NoRanges("no IPv6 ranges".into()));
    }

    let (have4, have6) = svc.have_families();
    let mut plan = AllocationPlan::default();
    let mut err4 = None;
    let mut err6 = None;
    if svc.want_v4 && !have4 && can_v4 {
        match v4_ranges.next_free_ip(allocated4) {
            Some(ip) => plan.v4 = Some(ip),
            None => err4 = Some(AllocError::Exhausted),
        }
    }
    if svc.want_v6 && !have6 && can_v6 {
        match v6_ranges.next_free_ip(allocated6) {
            Some(ip) => plan.v6 = Some(ip),
            None => err6 = Some(AllocError::Exhausted),
        }
    }

    // Nothing needed and no errors → already satisfied.
    if plan.is_empty() && err4.is_none() && err6.is_none() {
        return Ok(plan);
    }
    if plan.is_empty() {
        return Err(err4.or(err6).unwrap_or(AllocError::Exhausted));
    }
    // A required-dual service must get both families.
    if svc.require_dual && (plan.v4.is_none() || plan.v6.is_none()) {
        return Err(AllocError::DualStackUnavailable);
    }
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::IpNet;

    fn ranges(cidrs: &[&str]) -> IpRanges {
        IpRanges::new(cidrs.iter().map(|c| c.parse::<IpNet>().unwrap()).collect())
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn v4_lb() -> LbService {
        LbService {
            namespace: "default".into(),
            name: "web".into(),
            is_loadbalancer: true,
            loadbalancer_class: None,
            want_v4: true,
            want_v6: false,
            require_dual: false,
            external_ips: vec![],
            ingress_ips: vec![],
        }
    }

    #[test]
    fn check_class_matches_kube_router_and_default_rules() {
        assert!(check_class(Some("kube-router"), false));
        assert!(check_class(None, true));
        assert!(check_class(Some("default"), true));
        assert!(!check_class(None, false)); // not default → unset ignored
        assert!(!check_class(Some("metallb"), true)); // foreign class
    }

    #[test]
    fn should_allocate_requires_type_class_and_missing_ingress() {
        let svc = v4_lb();
        assert!(should_allocate(&svc, true));
        // Already has the v4 ingress → satisfied.
        let mut done = v4_lb();
        done.ingress_ips = vec![ip("203.0.113.5")];
        assert!(!should_allocate(&done, true));
        // Not a LoadBalancer.
        let mut clip = v4_lb();
        clip.is_loadbalancer = false;
        assert!(!should_allocate(&clip, true));
    }

    #[test]
    fn plans_v4_allocation() {
        let mut v4 = ranges(&["203.0.113.0/24"]);
        let mut v6 = ranges(&[]);
        let plan = plan_allocation(&v4_lb(), &mut v4, &mut v6, &[], &[]).unwrap();
        assert_eq!(plan.v4, Some(ip("203.0.113.0")));
        assert_eq!(plan.v6, None);
        assert_eq!(plan.ips(), vec![ip("203.0.113.0")]);
    }

    #[test]
    fn no_matching_range_errors() {
        let mut v4 = ranges(&[]);
        let mut v6 = ranges(&["fd00::/120"]);
        let err = plan_allocation(&v4_lb(), &mut v4, &mut v6, &[], &[]).unwrap_err();
        assert!(matches!(err, AllocError::NoRanges(_)));
    }

    #[test]
    fn require_dual_needs_both_families() {
        let mut svc = v4_lb();
        svc.want_v6 = true;
        svc.require_dual = true;
        let mut v4 = ranges(&["203.0.113.0/24"]);
        let mut v6 = ranges(&[]); // no v6 → dual fails at gating
        let err = plan_allocation(&svc, &mut v4, &mut v6, &[], &[]).unwrap_err();
        assert!(matches!(err, AllocError::NoRanges(_)));
    }

    #[test]
    fn dual_stack_allocates_both() {
        let mut svc = v4_lb();
        svc.want_v6 = true;
        svc.require_dual = true;
        let mut v4 = ranges(&["203.0.113.0/24"]);
        let mut v6 = ranges(&["fd00::/120"]);
        let plan = plan_allocation(&svc, &mut v4, &mut v6, &[], &[]).unwrap();
        assert!(plan.v4.is_some() && plan.v6.is_some());
        assert_eq!(plan.ips().len(), 2);
    }

    #[test]
    fn already_satisfied_returns_empty_plan() {
        let mut svc = v4_lb();
        svc.ingress_ips = vec![ip("203.0.113.5")];
        let mut v4 = ranges(&["203.0.113.0/24"]);
        let mut v6 = ranges(&[]);
        let plan = plan_allocation(&svc, &mut v4, &mut v6, &[], &[]).unwrap();
        assert_eq!(plan, AllocationPlan::default());
    }
}
