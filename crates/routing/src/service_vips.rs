//! Service VIP advertisement set, mirroring `getAllVIPsForService` /
//! `shouldAdvertiseService` in `upstream/pkg/controllers/routing/ecmp_vip.go`.
//!
//! Each node advertises the ClusterIP/ExternalIP/LoadBalancer VIPs of services
//! it should announce (as host routes), gated by the `--advertise-*-ip` defaults,
//! per-service annotation overrides, and local-endpoint / traffic-policy rules.
//! Because every node with local endpoints advertises the same VIP with its own
//! next hop, peers see ECMP naturally.

use std::collections::BTreeSet;
use std::net::IpAddr;

use ipnet::IpNet;

/// Cluster-wide advertisement defaults (`--advertise-cluster-ip` etc.).
#[derive(Debug, Clone, Copy)]
pub struct AdvertiseDefaults {
    /// `--advertise-cluster-ip`.
    pub cluster: bool,
    /// `--advertise-external-ip`.
    pub external: bool,
    /// `--advertise-loadbalancer-ip`.
    pub loadbalancer: bool,
}

/// Projected service view for VIP advertisement decisions.
#[derive(Debug, Clone, Default)]
pub struct SvcVip {
    /// ClusterIPs.
    pub cluster_ips: Vec<IpAddr>,
    /// ExternalIPs.
    pub external_ips: Vec<IpAddr>,
    /// LoadBalancer ingress IPs.
    pub lb_ips: Vec<IpAddr>,
    /// `internalTrafficPolicy: Local`.
    pub internal_traffic_local: bool,
    /// `externalTrafficPolicy: Local` (or the legacy `service.local` annotation).
    pub external_traffic_local: bool,
    /// This node has a ready local endpoint for the service.
    pub has_local_endpoints: bool,
    /// Per-service `kube-router.io/service.advertise.clusterip` override.
    pub adv_cluster: Option<bool>,
    /// Per-service `kube-router.io/service.advertise.externalip` override.
    pub adv_external: Option<bool>,
    /// Per-service `kube-router.io/service.advertise.loadbalancerip` override.
    pub adv_lb: Option<bool>,
    /// Deprecated `kube-router.io/service.skiplbips` annotation.
    pub skip_lb_ips: bool,
}

fn host_route(ip: IpAddr) -> IpNet {
    match ip {
        IpAddr::V4(a) => IpNet::V4(ipnet::Ipv4Net::new(a, 32).unwrap()),
        IpAddr::V6(a) => IpNet::V6(ipnet::Ipv6Net::new(a, 128).unwrap()),
    }
}

/// Decide whether a VIP category should be advertised (mirrors
/// `shouldAdvertiseService`): default (or annotation override) must be true, and
/// a `Local` traffic policy with no local endpoints suppresses it.
fn should_advertise(
    default_on: bool,
    annotation: Option<bool>,
    is_cluster_ip: bool,
    svc: &SvcVip,
) -> bool {
    if !annotation.unwrap_or(default_on) {
        return false;
    }
    if is_cluster_ip && svc.internal_traffic_local && !svc.has_local_endpoints {
        return false;
    }
    if !is_cluster_ip && svc.external_traffic_local && !svc.has_local_endpoints {
        return false;
    }
    true
}

/// The set of VIP host routes this node should advertise for `services`.
pub fn advertised_service_vips(services: &[SvcVip], d: &AdvertiseDefaults) -> BTreeSet<IpNet> {
    let mut out = BTreeSet::new();
    for svc in services {
        if should_advertise(d.cluster, svc.adv_cluster, true, svc) {
            out.extend(svc.cluster_ips.iter().copied().map(host_route));
        }
        if should_advertise(d.external, svc.adv_external, false, svc) {
            out.extend(svc.external_ips.iter().copied().map(host_route));
        }
        if !svc.skip_lb_ips && should_advertise(d.loadbalancer, svc.adv_lb, false, svc) {
            out.extend(svc.lb_ips.iter().copied().map(host_route));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }
    fn defaults() -> AdvertiseDefaults {
        AdvertiseDefaults {
            cluster: true,
            external: true,
            loadbalancer: true,
        }
    }
    fn svc() -> SvcVip {
        SvcVip {
            cluster_ips: vec![ip("10.96.0.10")],
            external_ips: vec![ip("203.0.113.5")],
            lb_ips: vec![ip("198.51.100.5")],
            has_local_endpoints: true,
            ..Default::default()
        }
    }

    #[test]
    fn advertises_all_categories_as_host_routes_by_default() {
        let vips = advertised_service_vips(&[svc()], &defaults());
        assert!(vips.contains(&net("10.96.0.10/32")));
        assert!(vips.contains(&net("203.0.113.5/32")));
        assert!(vips.contains(&net("198.51.100.5/32")));
        assert_eq!(vips.len(), 3);
    }

    #[test]
    fn default_off_suppresses_unless_annotated_on() {
        let d = AdvertiseDefaults {
            cluster: false,
            external: false,
            loadbalancer: false,
        };
        assert!(advertised_service_vips(&[svc()], &d).is_empty());
        // Per-service annotation re-enables just the clusterIP.
        let mut s = svc();
        s.adv_cluster = Some(true);
        let vips = advertised_service_vips(&[s], &d);
        assert_eq!(vips, [net("10.96.0.10/32")].into_iter().collect());
    }

    #[test]
    fn annotation_off_overrides_default_on() {
        let mut s = svc();
        s.adv_external = Some(false);
        let vips = advertised_service_vips(&[s], &defaults());
        assert!(!vips.contains(&net("203.0.113.5/32")));
        assert!(vips.contains(&net("10.96.0.10/32")));
    }

    #[test]
    fn local_traffic_policy_without_endpoints_suppresses() {
        let mut s = svc();
        s.internal_traffic_local = true;
        s.external_traffic_local = true;
        s.has_local_endpoints = false;
        // No local endpoints → nothing advertised despite defaults on.
        assert!(advertised_service_vips(&[s], &defaults()).is_empty());
    }

    #[test]
    fn local_traffic_policy_with_endpoints_advertises() {
        let mut s = svc();
        s.external_traffic_local = true;
        s.has_local_endpoints = true;
        let vips = advertised_service_vips(&[s], &defaults());
        assert!(vips.contains(&net("203.0.113.5/32")));
    }

    #[test]
    fn skiplbips_suppresses_only_loadbalancer() {
        let mut s = svc();
        s.skip_lb_ips = true;
        let vips = advertised_service_vips(&[s], &defaults());
        assert!(!vips.contains(&net("198.51.100.5/32")));
        assert!(vips.contains(&net("10.96.0.10/32")));
    }

    #[test]
    fn ipv6_vip_is_a_128_host_route() {
        let mut s = SvcVip {
            cluster_ips: vec![ip("fd00::10")],
            has_local_endpoints: true,
            ..Default::default()
        };
        s.adv_cluster = Some(true);
        let vips = advertised_service_vips(&[s], &defaults());
        assert!(vips.contains(&net("fd00::10/128")));
    }
}
