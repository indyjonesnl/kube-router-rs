//! BGP path construction (mirrors `upstream/pkg/bgp/path.go`).

use std::net::IpAddr;

use ipnet::IpNet;
use kr_common::ipfamily::IpFamily;

/// Address Family Identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Afi {
    /// IPv4.
    Ip,
    /// IPv6.
    Ip6,
}

/// Subsequent Address Family Identifier (only unicast is used).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Safi {
    /// Unicast.
    Unicast,
}

/// BGP path attribute (the subset kube-router sets for route advertisement).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attr {
    /// ORIGIN; `0` = IGP.
    Origin(u8),
    /// NEXT_HOP for IPv4 unicast.
    NextHop(IpAddr),
    /// MP_REACH_NLRI for IPv6 unicast (next hop + reachable NLRI).
    MpReachNlri {
        /// The next hop.
        next_hop: IpAddr,
        /// The reachable prefix.
        nlri: IpNet,
    },
}

/// A BGP path (advertisement or withdrawal).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Path {
    /// Address family.
    pub afi: Afi,
    /// Sub-address family.
    pub safi: Safi,
    /// The prefix being (un)advertised.
    pub prefix: IpNet,
    /// The next hop.
    pub next_hop: IpAddr,
    /// Path attributes.
    pub attrs: Vec<Attr>,
    /// Whether this is a withdrawal.
    pub withdrawal: bool,
}

/// Builds a [`Path`], selecting the correct attributes for the prefix family.
pub struct PathBuilder {
    prefix: IpNet,
    next_hop: IpAddr,
    withdrawal: bool,
}

impl PathBuilder {
    /// Start a path for `prefix` with `next_hop`.
    pub fn new(prefix: IpNet, next_hop: IpAddr) -> Self {
        Self {
            prefix,
            next_hop,
            withdrawal: false,
        }
    }

    /// Mark this path as a withdrawal.
    pub fn withdrawal(mut self, w: bool) -> Self {
        self.withdrawal = w;
        self
    }

    /// Build the path.
    pub fn build(self) -> Path {
        let family = IpFamily::of_net(&self.prefix);
        let (afi, attrs) = match family {
            IpFamily::V4 => (Afi::Ip, vec![Attr::Origin(0), Attr::NextHop(self.next_hop)]),
            IpFamily::V6 => (
                Afi::Ip6,
                vec![
                    Attr::Origin(0),
                    Attr::MpReachNlri {
                        next_hop: self.next_hop,
                        nlri: self.prefix,
                    },
                ],
            ),
        };
        Path {
            afi,
            safi: Safi::Unicast,
            prefix: self.prefix,
            next_hop: self.next_hop,
            attrs,
            withdrawal: self.withdrawal,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn ipv4_path_uses_next_hop_attr() {
        let p = PathBuilder::new(net("10.244.1.0/24"), ip("10.0.0.2")).build();
        assert_eq!(p.afi, Afi::Ip);
        assert!(p.attrs.contains(&Attr::Origin(0)));
        assert!(p.attrs.iter().any(|a| matches!(a, Attr::NextHop(_))));
        assert!(!p
            .attrs
            .iter()
            .any(|a| matches!(a, Attr::MpReachNlri { .. })));
        assert!(!p.withdrawal);
    }

    #[test]
    fn ipv6_path_uses_mp_reach_nlri() {
        let p = PathBuilder::new(net("fd00:244:1::/64"), ip("fd00::2")).build();
        assert_eq!(p.afi, Afi::Ip6);
        assert!(p.attrs.contains(&Attr::Origin(0)));
        assert!(p
            .attrs
            .iter()
            .any(|a| matches!(a, Attr::MpReachNlri { .. })));
        assert!(!p.attrs.iter().any(|a| matches!(a, Attr::NextHop(_))));
    }

    #[test]
    fn withdrawal_flag_is_carried() {
        let p = PathBuilder::new(net("10.244.1.0/24"), ip("10.0.0.2"))
            .withdrawal(true)
            .build();
        assert!(p.withdrawal);
        assert_eq!(p.prefix, net("10.244.1.0/24"));
    }
}
