//! Pod-egress SNAT rule construction, mirroring
//! `upstream/pkg/controllers/routing/pod_egress.go`.
//!
//! When `--enable-pod-egress` is set, traffic from pods to destinations outside
//! the cluster is masqueraded to the node IP. The rule (nat POSTROUTING) matches
//! pod-subnet sources whose destination is neither a pod subnet nor a node IP.
//! IPv6 uses `inet6:`-prefixed ipset names.

use std::net::IpAddr;

use ipnet::IpNet;
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

/// Build an `ipset restore` payload that (re)creates and populates the
/// pod-subnets (`hash:net`) and node-IPs (`hash:ip`) sets the SNAT rule matches.
pub fn ipset_restore_payload(
    pod_subnets: &[IpNet],
    node_ips: &[IpAddr],
    family: IpFamily,
) -> String {
    let (subnets_set, nodes_set) = set_names(family);
    let fam = match family {
        IpFamily::V4 => "inet",
        IpFamily::V6 => "inet6",
    };
    let want_v6 = family == IpFamily::V6;
    let mut out = String::new();
    out.push_str(&format!(
        "create {subnets_set} hash:net family {fam} -exist\nflush {subnets_set}\n"
    ));
    out.push_str(&format!(
        "create {nodes_set} hash:ip family {fam} -exist\nflush {nodes_set}\n"
    ));
    for net in pod_subnets.iter().filter(|n| n.addr().is_ipv6() == want_v6) {
        out.push_str(&format!("add {subnets_set} {net}\n"));
    }
    for ip in node_ips.iter().filter(|i| i.is_ipv6() == want_v6) {
        out.push_str(&format!("add {nodes_set} {ip}\n"));
    }
    out
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

    #[test]
    fn ipset_payload_creates_and_populates_both_sets() {
        let payload = ipset_restore_payload(
            &["10.244.0.0/24".parse().unwrap()],
            &["192.168.1.10".parse().unwrap()],
            IpFamily::V4,
        );
        assert!(payload.contains("create kube-router-pod-subnets hash:net family inet"));
        assert!(payload.contains("create kube-router-node-ips hash:ip family inet"));
        assert!(payload.contains("add kube-router-pod-subnets 10.244.0.0/24"));
        assert!(payload.contains("add kube-router-node-ips 192.168.1.10"));
    }

    #[test]
    fn ipset_payload_filters_by_family() {
        let payload = ipset_restore_payload(
            &[
                "10.244.0.0/24".parse().unwrap(),
                "fd00::/64".parse().unwrap(),
            ],
            &[],
            IpFamily::V6,
        );
        assert!(payload.contains("inet6:kube-router-pod-subnets"));
        assert!(payload.contains("add inet6:kube-router-pod-subnets fd00::/64"));
        // v4 subnet excluded from the v6 set.
        assert!(!payload.contains("10.244.0.0/24"));
    }
}
