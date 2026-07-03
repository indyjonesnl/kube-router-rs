//! Projected LoadBalancer Service view used by the allocator, decoupled from the
//! Kubernetes API types (the controller maps `Service` → [`LbService`]).

use std::net::IpAddr;

/// The class this allocator claims.
pub const LOAD_BALANCER_CLASS: &str = "kube-router";

/// A projected `type: LoadBalancer` service.
#[derive(Debug, Clone, Default)]
pub struct LbService {
    /// Namespace.
    pub namespace: String,
    /// Name.
    pub name: String,
    /// `spec.type == LoadBalancer`.
    pub is_loadbalancer: bool,
    /// `spec.loadBalancerClass`, if set.
    pub loadbalancer_class: Option<String>,
    /// `spec.ipFamilies` contains IPv4.
    pub want_v4: bool,
    /// `spec.ipFamilies` contains IPv6.
    pub want_v6: bool,
    /// `spec.ipFamilyPolicy == RequireDualStack`.
    pub require_dual: bool,
    /// `spec.externalIPs`.
    pub external_ips: Vec<IpAddr>,
    /// `status.loadBalancer.ingress[].ip`.
    pub ingress_ips: Vec<IpAddr>,
}

impl LbService {
    /// IP families currently present in `status.loadBalancer.ingress`.
    pub fn have_families(&self) -> (bool, bool) {
        let v4 = self.ingress_ips.iter().any(IpAddr::is_ipv4);
        let v6 = self.ingress_ips.iter().any(IpAddr::is_ipv6);
        (v4, v6)
    }
}
