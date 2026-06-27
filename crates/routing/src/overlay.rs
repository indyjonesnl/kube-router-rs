//! Overlay tunnel naming and the subnet-vs-tunnel decision.
//!
//! Mirrors `upstream/pkg/tunnels/linux_tunnels.go` + the overlay decision in the
//! routes controller: a deterministic tunnel name is derived from the next hop,
//! and a tunnel is used for cross-subnet pod traffic (overlay `subnet`) or for all
//! cross-node traffic (overlay `full`).

use std::net::IpAddr;

use ipnet::IpNet;
use kr_common::naming::hash16;

/// Overlay mode from `--overlay-type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlayType {
    /// Tunnel only across subnets.
    Subnet,
    /// Tunnel for all cross-node traffic.
    Full,
}

/// Encapsulation from `--overlay-encap`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encap {
    /// IP-in-IP.
    Ipip,
    /// Foo-over-UDP.
    Fou,
}

/// Deterministic tunnel interface name for a next hop. Stable across restarts so
/// the same peer always maps to the same tunnel device.
///
/// NOTE: exact byte-for-byte parity with upstream `GenerateTunnelName` will be
/// pinned when the live tunnel setup lands; the contract here is determinism +
/// a `kube-tunnel-` prefix within the Linux IFNAMSIZ (15-char) limit.
pub fn tunnel_name(next_hop: &IpAddr) -> String {
    // 6 base32 chars after the 9-char prefix keeps the name ≤ 15 (IFNAMSIZ).
    let h = hash16(&next_hop.to_string());
    format!("kube-tun-{}", &h[..6])
}

/// Decide whether traffic to `next_hop` needs the overlay tunnel, given the
/// local node's directly-attached subnets.
pub fn needs_tunnel(next_hop: &IpAddr, local_subnets: &[IpNet], overlay: OverlayType) -> bool {
    match overlay {
        OverlayType::Full => true,
        OverlayType::Subnet => !local_subnets.iter().any(|n| n.contains(next_hop)),
    }
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

    #[test]
    fn tunnel_name_is_deterministic_and_bounded() {
        let n1 = tunnel_name(&ip("10.0.0.2"));
        assert_eq!(n1, tunnel_name(&ip("10.0.0.2")));
        assert!(n1.starts_with("kube-tun-"));
        assert!(n1.len() <= 15, "IFNAMSIZ limit: {n1}");
    }

    #[test]
    fn different_next_hops_differ() {
        assert_ne!(tunnel_name(&ip("10.0.0.2")), tunnel_name(&ip("10.0.0.3")));
    }

    #[test]
    fn full_overlay_always_tunnels() {
        let subnets = vec![net("10.0.0.0/24")];
        assert!(needs_tunnel(&ip("10.0.0.5"), &subnets, OverlayType::Full));
    }

    #[test]
    fn subnet_overlay_skips_same_subnet() {
        let subnets = vec![net("10.0.0.0/24")];
        assert!(!needs_tunnel(
            &ip("10.0.0.5"),
            &subnets,
            OverlayType::Subnet
        ));
        assert!(needs_tunnel(&ip("10.1.0.5"), &subnets, OverlayType::Subnet));
    }
}
