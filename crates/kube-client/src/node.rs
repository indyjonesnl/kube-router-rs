//! Node discovery selection logic, mirroring `upstream/pkg/utils/node.go`.
//!
//! Upstream prefers a node's `InternalIP` over `ExternalIP`, splits addresses by
//! family, and reads pod CIDRs from the Node spec. These pure functions encode
//! that selection so they are unit-testable; the live client maps Kubernetes
//! `Node` objects into these inputs.

use std::net::IpAddr;

use ipnet::IpNet;
use kr_common::ipfamily::{parse_cidr, parse_ip, IpFamily};

/// Kubernetes node address type (subset relevant to address selection).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeAddressType {
    /// `InternalIP` — preferred.
    Internal,
    /// `ExternalIP` — fallback.
    External,
    /// Hostname / other (ignored for IP selection).
    Other,
}

/// A node address as reported in `node.status.addresses`.
#[derive(Debug, Clone)]
pub struct NodeAddress {
    /// Address kind.
    pub kind: NodeAddressType,
    /// The address string.
    pub address: String,
}

/// The discovered primary addresses of a node, per family.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct NodeIps {
    /// Primary IPv4 address.
    pub v4: Option<IpAddr>,
    /// Primary IPv6 address.
    pub v6: Option<IpAddr>,
}

fn rank(kind: NodeAddressType) -> u8 {
    match kind {
        NodeAddressType::Internal => 0,
        NodeAddressType::External => 1,
        NodeAddressType::Other => 2,
    }
}

/// Select the primary IPv4/IPv6 addresses, preferring `InternalIP` over
/// `ExternalIP`. The first address of the best rank wins per family.
pub fn select_node_ips(addresses: &[NodeAddress]) -> NodeIps {
    let mut out = NodeIps::default();
    let mut best_rank = NodeIps::default_ranks();

    for a in addresses {
        if matches!(a.kind, NodeAddressType::Other) {
            continue;
        }
        let Ok(ip) = parse_ip(&a.address) else {
            continue;
        };
        let r = rank(a.kind);
        match IpFamily::of_addr(&ip) {
            IpFamily::V4 => {
                if out.v4.is_none() || r < best_rank.0 {
                    out.v4 = Some(ip);
                    best_rank.0 = r;
                }
            }
            IpFamily::V6 => {
                if out.v6.is_none() || r < best_rank.1 {
                    out.v6 = Some(ip);
                    best_rank.1 = r;
                }
            }
        }
    }
    out
}

impl NodeIps {
    fn default_ranks() -> (u8, u8) {
        (u8::MAX, u8::MAX)
    }
}

/// Parse pod CIDRs (from `node.spec.podCIDRs`) into per-family networks,
/// skipping any that fail to parse.
pub fn parse_pod_cidrs(cidrs: &[String]) -> Vec<IpNet> {
    cidrs.iter().filter_map(|c| parse_cidr(c).ok()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(kind: NodeAddressType, a: &str) -> NodeAddress {
        NodeAddress {
            kind,
            address: a.to_string(),
        }
    }

    #[test]
    fn prefers_internal_over_external_ipv4() {
        let addrs = vec![
            addr(NodeAddressType::External, "1.2.3.4"),
            addr(NodeAddressType::Internal, "10.0.0.5"),
        ];
        let ips = select_node_ips(&addrs);
        assert_eq!(ips.v4, Some("10.0.0.5".parse().unwrap()));
    }

    #[test]
    fn selects_both_families() {
        let addrs = vec![
            addr(NodeAddressType::Internal, "10.0.0.5"),
            addr(NodeAddressType::Internal, "fd00::5"),
        ];
        let ips = select_node_ips(&addrs);
        assert_eq!(ips.v4, Some("10.0.0.5".parse().unwrap()));
        assert_eq!(ips.v6, Some("fd00::5".parse().unwrap()));
    }

    #[test]
    fn external_used_when_no_internal() {
        let addrs = vec![addr(NodeAddressType::External, "1.2.3.4")];
        assert_eq!(select_node_ips(&addrs).v4, Some("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn ignores_hostname_and_garbage() {
        let addrs = vec![
            addr(NodeAddressType::Other, "node-1"),
            addr(NodeAddressType::Internal, "not-an-ip"),
            addr(NodeAddressType::External, "10.0.0.9"),
        ];
        assert_eq!(
            select_node_ips(&addrs).v4,
            Some("10.0.0.9".parse().unwrap())
        );
    }

    #[test]
    fn parses_pod_cidrs_skipping_bad() {
        let cidrs = vec![
            "10.244.0.0/24".to_string(),
            "garbage".to_string(),
            "fd00:244::/64".to_string(),
        ];
        let nets = parse_pod_cidrs(&cidrs);
        assert_eq!(nets.len(), 2);
    }
}
