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

/// Custom routing table overlay tunnel routes live in (`CustomTableID`).
pub const CUSTOM_TABLE_ID: u32 = 77;
/// Name for [`CUSTOM_TABLE_ID`] in `/etc/iproute2/rt_tables`.
pub const CUSTOM_TABLE_NAME: &str = "kube-router";

/// tunnel link type for a family (`ipip` for v4, `ip6tnl` for v6).
fn link_type(ipv6: bool) -> &'static str {
    if ipv6 {
        "ip6tnl"
    } else {
        "ipip"
    }
}

/// `ip fou add` args to open the GUE decap port (FoU encapsulation).
pub fn fou_add_args(port: u16) -> Vec<String> {
    vec![
        "fou".into(),
        "add".into(),
        "port".into(),
        port.to_string(),
        "gue".into(),
    ]
}

/// `ip link add` args for the overlay tunnel to `next_hop` sourced at `local`.
/// FoU wraps IPIP in GUE on `encap_port`; plain IPIP omits the encap options.
pub fn tunnel_add_args(
    name: &str,
    next_hop: IpAddr,
    local: IpAddr,
    encap: Encap,
    encap_port: u16,
) -> Vec<String> {
    let ipv6 = next_hop.is_ipv6();
    let mut a = vec![
        "link".into(),
        "add".into(),
        "name".into(),
        name.into(),
        "type".into(),
        link_type(ipv6).into(),
        "remote".into(),
        next_hop.to_string(),
        "local".into(),
        local.to_string(),
    ];
    if encap == Encap::Fou {
        let mode = if ipv6 { "ip6ip6" } else { "ipip" };
        a.extend([
            "ttl".into(),
            "225".into(),
            "encap".into(),
            "gue".into(),
            "encap-sport".into(),
            "auto".into(),
            "encap-dport".into(),
            encap_port.to_string(),
            "mode".into(),
            mode.into(),
        ]);
    }
    a
}

/// `ip link set <name> up`.
pub fn tunnel_up_args(name: &str) -> Vec<String> {
    vec!["link".into(), "set".into(), name.into(), "up".into()]
}

/// `ip route add <next_hop>/32 dev <name> table 77` — deliver overlay traffic to
/// the peer via its tunnel device in the custom table.
pub fn tunnel_route_args(next_hop: IpAddr, name: &str) -> Vec<String> {
    let host = match next_hop {
        IpAddr::V4(a) => format!("{a}/32"),
        IpAddr::V6(a) => format!("{a}/128"),
    };
    vec![
        "route".into(),
        "replace".into(),
        host,
        "dev".into(),
        name.into(),
        "table".into(),
        CUSTOM_TABLE_ID.to_string(),
    ]
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

    #[test]
    fn ipip_tunnel_add_args_omit_encap() {
        let a = tunnel_add_args(
            "kube-tun-abc",
            ip("10.0.0.2"),
            ip("10.0.0.1"),
            Encap::Ipip,
            5555,
        );
        assert_eq!(
            &a[0..6],
            &["link", "add", "name", "kube-tun-abc", "type", "ipip"]
        );
        assert!(a.contains(&"remote".to_string()) && a.contains(&"10.0.0.2".to_string()));
        assert!(!a.contains(&"encap".to_string()));
    }

    #[test]
    fn fou_tunnel_add_args_include_gue_encap() {
        let a = tunnel_add_args("t", ip("10.0.0.2"), ip("10.0.0.1"), Encap::Fou, 5555);
        assert!(a.windows(2).any(|w| w == ["encap", "gue"]));
        assert!(a.windows(2).any(|w| w == ["encap-dport", "5555"]));
        assert!(a.windows(2).any(|w| w == ["mode", "ipip"]));
        assert_eq!(
            fou_add_args(5555),
            vec!["fou", "add", "port", "5555", "gue"]
        );
    }

    #[test]
    fn v6_tunnel_uses_ip6tnl_and_route_is_128() {
        let a = tunnel_add_args("t6", ip("fd00::2"), ip("fd00::1"), Encap::Fou, 5555);
        assert!(a.windows(2).any(|w| w == ["type", "ip6tnl"]));
        assert!(a.windows(2).any(|w| w == ["mode", "ip6ip6"]));
        let r = tunnel_route_args(ip("fd00::2"), "t6");
        assert!(r.contains(&"fd00::2/128".to_string()) && r.contains(&"77".to_string()));
    }
}
