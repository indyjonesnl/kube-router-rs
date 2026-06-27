//! NetworkPolicy chain/set names and packet marks, mirroring
//! `upstream/pkg/controllers/netpol/{network_policy_controller,policy,pod}.go`.

use kr_common::ipfamily::IpFamily;
use kr_common::naming::{hash16, DST_PREFIX, SRC_PREFIX};

/// Top-level chains kube-router inserts into the filter table.
pub const ROUTER_INPUT: &str = "KUBE-ROUTER-INPUT";
/// Top-level FORWARD chain.
pub const ROUTER_FORWARD: &str = "KUBE-ROUTER-FORWARD";
/// Top-level OUTPUT chain.
pub const ROUTER_OUTPUT: &str = "KUBE-ROUTER-OUTPUT";

/// Mark set when a packet matches any policy rule.
pub const MARK_MATCHED: &str = "0x10000/0x10000";
/// Mark set when a packet is accepted by a policy.
pub const MARK_ACCEPTED: &str = "0x20000/0x20000";

/// ipset holding local pod IPs, used to gate default-deny REJECTs.
pub const LOCAL_PODS_SET: &str = "kube-router-local-pods";

/// Per-family local-pods set name (v6 gets a distinct set — ipset names are
/// global and a set is single-family).
pub fn local_pods_set(family: IpFamily) -> String {
    match family {
        IpFamily::V4 => LOCAL_PODS_SET.to_string(),
        IpFamily::V6 => format!("{LOCAL_PODS_SET}-inet6"),
    }
}

/// Per-policy source ipset name: `KUBE-SRC-<hash16(ns+name+family)>`.
pub fn src_set(namespace: &str, policy: &str, family: IpFamily) -> String {
    format!(
        "{SRC_PREFIX}{}",
        hash16(&format!("{namespace}{policy}{}", fam(family)))
    )
}

/// Per-policy destination ipset name: `KUBE-DST-<hash16(ns+name+family)>`.
pub fn dst_set(namespace: &str, policy: &str, family: IpFamily) -> String {
    format!(
        "{DST_PREFIX}{}",
        hash16(&format!("{namespace}{policy}{}", fam(family)))
    )
}

/// Per-rule-indexed source ipset (e.g. ingress rule N peers).
pub fn indexed_src_set(namespace: &str, policy: &str, rule: usize, family: IpFamily) -> String {
    format!(
        "{SRC_PREFIX}{}",
        hash16(&format!("{namespace}{policy}ingress{rule}{}", fam(family)))
    )
}

/// Per-rule-indexed destination ipset (e.g. egress rule N peers).
pub fn indexed_dst_set(namespace: &str, policy: &str, rule: usize, family: IpFamily) -> String {
    format!(
        "{DST_PREFIX}{}",
        hash16(&format!("{namespace}{policy}egress{rule}{}", fam(family)))
    )
}

fn fam(family: IpFamily) -> &'static str {
    match family {
        IpFamily::V4 => "IPv4",
        IpFamily::V6 => "IPv6",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_names_have_prefix_and_are_family_distinct() {
        let v4 = src_set("default", "web", IpFamily::V4);
        let v6 = src_set("default", "web", IpFamily::V6);
        assert!(v4.starts_with("KUBE-SRC-"));
        assert_ne!(v4, v6);
        assert!(dst_set("default", "web", IpFamily::V4).starts_with("KUBE-DST-"));
    }

    #[test]
    fn set_names_are_deterministic() {
        assert_eq!(
            src_set("ns", "p", IpFamily::V4),
            src_set("ns", "p", IpFamily::V4)
        );
    }

    #[test]
    fn indexed_sets_differ_by_rule_index() {
        let r0 = indexed_src_set("ns", "p", 0, IpFamily::V4);
        let r1 = indexed_src_set("ns", "p", 1, IpFamily::V4);
        assert_ne!(r0, r1);
    }
}
