//! External/LoadBalancer IP validation, mirroring `upstream/pkg/svcip` and the
//! `--strict-external-ip-validation` behavior.

use std::net::IpAddr;

use ipnet::IpNet;

/// Decide whether an external/LB IP may be bound.
///
/// - Lenient (`strict == false`): always allowed.
/// - Strict: the IP must fall within a configured `allowed` range and must NOT
///   fall within a `cluster` (ClusterIP) range. With strict on and no allowed
///   range configured, all such IPs are rejected (default-deny).
pub fn validate_external_ip(
    ip: IpAddr,
    allowed: &[IpNet],
    cluster: &[IpNet],
    strict: bool,
) -> bool {
    if !strict {
        return true;
    }
    if cluster.iter().any(|n| n.contains(&ip)) {
        return false; // conflicts with the ClusterIP range
    }
    allowed.iter().any(|n| n.contains(&ip))
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
    fn lenient_allows_anything() {
        assert!(validate_external_ip(ip("1.2.3.4"), &[], &[], false));
    }

    #[test]
    fn strict_requires_membership_in_allowed() {
        let allowed = [net("203.0.113.0/24")];
        let cluster = [net("10.96.0.0/12")];
        assert!(validate_external_ip(
            ip("203.0.113.5"),
            &allowed,
            &cluster,
            true
        ));
        assert!(!validate_external_ip(
            ip("198.51.100.5"),
            &allowed,
            &cluster,
            true
        ));
    }

    #[test]
    fn strict_rejects_clusterip_conflict() {
        let allowed = [net("10.0.0.0/8")];
        let cluster = [net("10.96.0.0/12")];
        // In allowed but also in cluster range → rejected.
        assert!(!validate_external_ip(
            ip("10.96.0.5"),
            &allowed,
            &cluster,
            true
        ));
    }

    #[test]
    fn strict_with_no_allowed_range_rejects_all() {
        assert!(!validate_external_ip(ip("203.0.113.5"), &[], &[], true));
    }
}
