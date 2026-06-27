//! IP address family handling (IPv4 / IPv6 / dual-stack), mirroring the per-family
//! split the Go upstream applies throughout its controllers.

use std::net::IpAddr;

use ipnet::IpNet;

use crate::error::{Error, Result};

/// A single IP address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpFamily {
    /// IPv4.
    V4,
    /// IPv6.
    V6,
}

impl IpFamily {
    /// Family of a parsed address.
    pub fn of_addr(addr: &IpAddr) -> Self {
        match addr {
            IpAddr::V4(_) => IpFamily::V4,
            IpAddr::V6(_) => IpFamily::V6,
        }
    }

    /// Family of a parsed network.
    pub fn of_net(net: &IpNet) -> Self {
        match net {
            IpNet::V4(_) => IpFamily::V4,
            IpNet::V6(_) => IpFamily::V6,
        }
    }

    /// `true` for IPv6.
    pub fn is_v6(self) -> bool {
        matches!(self, IpFamily::V6)
    }
}

/// Which families are enabled for the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnabledFamilies {
    /// IPv4 enabled.
    pub v4: bool,
    /// IPv6 enabled.
    pub v6: bool,
}

impl EnabledFamilies {
    /// Construct from the `--enable-ipv4` / `--enable-ipv6` toggles.
    pub fn new(v4: bool, v6: bool) -> Self {
        Self { v4, v6 }
    }

    /// `true` when both families are enabled.
    pub fn is_dual_stack(self) -> bool {
        self.v4 && self.v6
    }

    /// `true` when only IPv6 is enabled (router-id then required for BGP).
    pub fn is_v6_only(self) -> bool {
        self.v6 && !self.v4
    }

    /// `true` when at least one family is enabled.
    pub fn any(self) -> bool {
        self.v4 || self.v6
    }

    /// `true` when `family` is enabled.
    pub fn contains(self, family: IpFamily) -> bool {
        match family {
            IpFamily::V4 => self.v4,
            IpFamily::V6 => self.v6,
        }
    }
}

/// Parse a CIDR string into an [`IpNet`], producing a precise error on failure.
pub fn parse_cidr(s: &str) -> Result<IpNet> {
    s.trim().parse::<IpNet>().map_err(|e| Error::InvalidIp {
        input: s.to_string(),
        reason: e.to_string(),
    })
}

/// Parse a bare IP address string, producing a precise error on failure.
pub fn parse_ip(s: &str) -> Result<IpAddr> {
    s.trim().parse::<IpAddr>().map_err(|e| Error::InvalidIp {
        input: s.to_string(),
        reason: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_address_family() {
        assert_eq!(
            IpFamily::of_addr(&parse_ip("10.0.0.1").unwrap()),
            IpFamily::V4
        );
        assert_eq!(
            IpFamily::of_addr(&parse_ip("fd00::1").unwrap()),
            IpFamily::V6
        );
    }

    #[test]
    fn detects_net_family() {
        assert_eq!(
            IpFamily::of_net(&parse_cidr("10.96.0.0/12").unwrap()),
            IpFamily::V4
        );
        assert_eq!(
            IpFamily::of_net(&parse_cidr("fd00::/8").unwrap()),
            IpFamily::V6
        );
    }

    #[test]
    fn enabled_families_classification() {
        assert!(EnabledFamilies::new(true, true).is_dual_stack());
        assert!(EnabledFamilies::new(false, true).is_v6_only());
        assert!(!EnabledFamilies::new(true, false).is_v6_only());
        assert!(!EnabledFamilies::new(false, false).any());
        assert!(EnabledFamilies::new(true, false).contains(IpFamily::V4));
        assert!(!EnabledFamilies::new(true, false).contains(IpFamily::V6));
    }

    #[test]
    fn rejects_bad_cidr() {
        let err = parse_cidr("not-a-cidr").unwrap_err();
        assert!(matches!(err, Error::InvalidIp { .. }));
    }

    #[test]
    fn is_v6_flag() {
        assert!(IpFamily::V6.is_v6());
        assert!(!IpFamily::V4.is_v6());
    }
}
