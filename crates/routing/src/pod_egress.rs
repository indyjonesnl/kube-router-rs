//! Pod-egress SNAT rule construction, mirroring
//! `upstream/pkg/controllers/routing/pod_egress.go`.
//!
//! When `--enable-pod-egress` is set, traffic from pods to destinations outside
//! the cluster is masqueraded to the node IP. The rule (nat POSTROUTING) matches
//! pod-subnet sources whose destination is neither a pod subnet nor a node IP.
//! IPv6 uses `inet6:`-prefixed ipset names.

use kr_common::ipfamily::IpFamily;

/// IPv4 pod-subnets ipset name.
pub const POD_SUBNETS_V4: &str = "kube-router-pod-subnets";
/// IPv4 node-IPs ipset name.
pub const NODE_IPS_V4: &str = "kube-router-node-ips";

fn set_names(family: IpFamily) -> (String, String) {
    match family {
        IpFamily::V4 => (POD_SUBNETS_V4.to_string(), NODE_IPS_V4.to_string()),
        IpFamily::V6 => (
            format!("inet6:{POD_SUBNETS_V4}"),
            format!("inet6:{NODE_IPS_V4}"),
        ),
    }
}

/// Build the SNAT rule arguments for the nat POSTROUTING chain.
/// `random_fully` appends `--random-fully` when the kernel/iptables supports it.
pub fn snat_rule(family: IpFamily, random_fully: bool) -> Vec<String> {
    let (pod_subnets, node_ips) = set_names(family);
    let mut args = vec![
        "-m".into(),
        "set".into(),
        "--match-set".into(),
        pod_subnets.clone(),
        "src".into(),
        "-m".into(),
        "set".into(),
        "!".into(),
        "--match-set".into(),
        pod_subnets,
        "dst".into(),
        "-m".into(),
        "set".into(),
        "!".into(),
        "--match-set".into(),
        node_ips,
        "dst".into(),
        "-j".into(),
        "MASQUERADE".into(),
    ];
    if random_fully {
        args.push("--random-fully".into());
    }
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_rule_uses_unprefixed_sets_and_masquerades() {
        let r = snat_rule(IpFamily::V4, false);
        assert!(r.contains(&"kube-router-pod-subnets".to_string()));
        assert!(r.contains(&"kube-router-node-ips".to_string()));
        assert!(r.contains(&"MASQUERADE".to_string()));
        // Exactly one negated dst on node-ips.
        assert_eq!(r.iter().filter(|a| *a == "!").count(), 2);
        assert!(!r.contains(&"--random-fully".to_string()));
    }

    #[test]
    fn v6_rule_uses_inet6_prefixed_sets() {
        let r = snat_rule(IpFamily::V6, false);
        assert!(r.contains(&"inet6:kube-router-pod-subnets".to_string()));
        assert!(r.contains(&"inet6:kube-router-node-ips".to_string()));
    }

    #[test]
    fn random_fully_is_appended_when_supported() {
        let r = snat_rule(IpFamily::V4, true);
        assert_eq!(r.last().unwrap(), "--random-fully");
    }

    #[test]
    fn source_match_precedes_dst_excludes() {
        let r = snat_rule(IpFamily::V4, false);
        let src_pos = r.iter().position(|a| a == "src").unwrap();
        let dst_pos = r.iter().position(|a| a == "dst").unwrap();
        assert!(src_pos < dst_pos);
    }
}
