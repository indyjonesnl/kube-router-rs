//! Firewall synthesis: NetworkPolicies + pods/namespaces → ipset contents + an
//! iptables filter-table document. Mirrors the chain model of
//! `upstream/pkg/controllers/netpol` (ingress focus for now).
//!
//! Semantics:
//! - A pod selected by no policy is unaffected (default-allow): no per-pod chain.
//! - A pod selected by an ingress policy gets a `KUBE-POD-FW-<pod>` chain that
//!   accepts established/related, jumps to each applicable `KUBE-NWPLCY-<policy>`
//!   chain (which `ACCEPT`s matching traffic), then `REJECT`s the rest.
//! - Peer sources for a rule go in one `hash:net` ipset (pod IPs as /32 + ipBlock
//!   CIDRs with `nomatch` exceptions).
//!
//! NOTE: egress, named ports, and upstream's exact mark/COMMON/TAIL layout are
//! follow-ups; this is a correct, verifiable ingress firewall.

use ipnet::IpNet;
use kr_common::ipfamily::IpFamily;
use kr_common::naming::{network_policy_chain, pod_firewall_chain};

use crate::ipset::SetType;
use crate::model::{selector_matches, Namespace, NetworkPolicy, Pod};
use crate::naming::{indexed_src_set, local_pods_set, ROUTER_FORWARD, ROUTER_INPUT, ROUTER_OUTPUT};
use crate::translate::resolve_peers;

/// An ipset to (re)populate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpsetPlan {
    /// Set name.
    pub name: String,
    /// Set type.
    pub set_type: SetType,
    /// Address family.
    pub family: IpFamily,
    /// Entries (IPs and/or CIDRs, possibly with ` nomatch`).
    pub entries: Vec<String>,
}

/// The synthesized firewall state for one IP family.
#[derive(Debug, Default, Clone)]
pub struct FirewallPlan {
    /// ipsets to populate.
    pub ipsets: Vec<IpsetPlan>,
    /// Chain declarations (`:CHAIN - [0:0]`) for our managed chains.
    pub chain_decls: Vec<String>,
    /// Rule lines (`-A CHAIN ...`).
    pub rules: Vec<String>,
}

fn reject_target(family: IpFamily) -> &'static str {
    match family {
        IpFamily::V4 => "REJECT --reject-with icmp-port-unreachable",
        IpFamily::V6 => "REJECT --reject-with icmp6-port-unreachable",
    }
}

fn policy_selects(policy: &NetworkPolicy, pod: &Pod) -> bool {
    pod.namespace == policy.namespace && selector_matches(&policy.pod_selector, &pod.labels)
}

fn pod_family_ips(pod: &Pod, family: IpFamily) -> Vec<String> {
    pod.ips
        .iter()
        .filter(|ip| {
            matches!(
                (ip, family),
                (std::net::IpAddr::V4(_), IpFamily::V4) | (std::net::IpAddr::V6(_), IpFamily::V6)
            )
        })
        .map(|ip| ip.to_string())
        .collect()
}

/// Build the firewall plan for `family`.
///
/// When `default_deny` is set, traffic to local pod IPs not in the
/// `kube-router-local-pods` set (i.e. not yet programmed) is rejected — closing
/// the race window for freshly-created pods. `pod_cidrs` scopes those rejects to
/// the node's pod range(s).
#[allow(clippy::too_many_arguments)]
pub fn build_plan(
    policies: &[NetworkPolicy],
    pods: &[Pod],
    namespaces: &[Namespace],
    node: &str,
    family: IpFamily,
    sync_version: &str,
    default_deny: bool,
    pod_cidrs: &[IpNet],
) -> FirewallPlan {
    let mut plan = FirewallPlan {
        chain_decls: vec![
            format!(":{ROUTER_INPUT} - [0:0]"),
            format!(":{ROUTER_FORWARD} - [0:0]"),
            format!(":{ROUTER_OUTPUT} - [0:0]"),
        ],
        ..Default::default()
    };

    // Per-policy ingress chains + their source ipsets.
    for pol in policies.iter().filter(|p| p.policy_types.ingress) {
        let pchain = network_policy_chain(&pol.namespace, &pol.name, sync_version, family);
        plan.chain_decls.push(format!(":{pchain} - [0:0]"));

        for (idx, rule) in pol.ingress.iter().enumerate() {
            let resolved = resolve_peers(&rule.peers, pods, namespaces, &pol.namespace, family);
            let src_match = if resolved.match_all {
                String::new()
            } else {
                let set = indexed_src_set(&pol.namespace, &pol.name, idx, family);
                let mut entries = resolved.ip_entries.clone();
                entries.extend(resolved.net_entries.clone());
                plan.ipsets.push(IpsetPlan {
                    name: set.clone(),
                    set_type: SetType::HashNet,
                    family,
                    entries,
                });
                format!(" -m set --match-set {set} src")
            };

            if rule.ports.is_empty() {
                plan.rules.push(format!("-A {pchain}{src_match} -j ACCEPT"));
            } else {
                for port in &rule.ports {
                    let pm = match port.port {
                        Some(p) => format!(" -p {} --dport {p}", port.protocol),
                        None => format!(" -p {}", port.protocol),
                    };
                    plan.rules
                        .push(format!("-A {pchain}{src_match}{pm} -j ACCEPT"));
                }
            }
        }
    }

    // Per-pod firewall chains for local, actionable, policy-selected pods.
    let mut programmed_ips: Vec<String> = Vec::new();
    for pod in pods
        .iter()
        .filter(|p| p.node_name == node && !p.host_network && !pod_family_ips(p, family).is_empty())
    {
        let applicable: Vec<String> = policies
            .iter()
            .filter(|p| p.policy_types.ingress && policy_selects(p, pod))
            .map(|p| network_policy_chain(&p.namespace, &p.name, sync_version, family))
            .collect();
        if applicable.is_empty() {
            continue; // default-allow
        }

        let podchain = pod_firewall_chain(&pod.namespace, &pod.name, sync_version);
        plan.chain_decls.push(format!(":{podchain} - [0:0]"));
        plan.rules.push(format!(
            "-A {podchain} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
        ));
        for pc in &applicable {
            plan.rules.push(format!("-A {podchain} -j {pc}"));
        }
        plan.rules
            .push(format!("-A {podchain} -j {}", reject_target(family)));

        for ip in pod_family_ips(pod, family) {
            plan.rules
                .push(format!("-A {ROUTER_FORWARD} -d {ip} -j {podchain}"));
            plan.rules
                .push(format!("-A {ROUTER_INPUT} -d {ip} -j {podchain}"));
            programmed_ips.push(ip);
        }
    }

    // Default-deny: reject traffic to pod-range dests not yet programmed.
    if default_deny {
        let set = local_pods_set(family);
        plan.ipsets.push(IpsetPlan {
            name: set.clone(),
            set_type: SetType::HashIp,
            family,
            entries: programmed_ips,
        });
        let reject = reject_target(family);
        for cidr in pod_cidrs.iter().filter(|c| {
            matches!(
                (c, family),
                (IpNet::V4(_), IpFamily::V4) | (IpNet::V6(_), IpFamily::V6)
            )
        }) {
            plan.rules.push(format!(
                "-A {ROUTER_FORWARD} -d {cidr} -m set ! --match-set {set} dst -j {reject}"
            ));
            plan.rules.push(format!(
                "-A {ROUTER_INPUT} -d {cidr} -m set ! --match-set {set} dst -j {reject}"
            ));
        }
    }

    plan
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Peer, PolicyTypes, Rule};
    use std::collections::BTreeMap;

    fn lbl(p: &[(&str, &str)]) -> BTreeMap<String, String> {
        p.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }
    fn pod(ns: &str, name: &str, labels: &[(&str, &str)], ip: &str) -> Pod {
        Pod {
            namespace: ns.into(),
            name: name.into(),
            labels: lbl(labels),
            ips: vec![ip.parse().unwrap()],
            node_name: "node-a".into(),
            host_network: false,
        }
    }

    fn allow_from(app: &str, from: &str) -> NetworkPolicy {
        NetworkPolicy {
            namespace: "default".into(),
            name: "p".into(),
            pod_selector: lbl(&[("app", app)]),
            policy_types: PolicyTypes {
                ingress: true,
                egress: false,
            },
            ingress: vec![Rule {
                peers: vec![Peer::Selector {
                    namespace_selector: None,
                    pod_selector: Some(lbl(&[("app", from)])),
                }],
                ports: vec![],
            }],
            egress: vec![],
        }
    }

    #[test]
    fn unselected_pod_gets_no_chain_default_allow() {
        let pods = vec![pod("default", "db", &[("app", "db")], "10.244.0.9")];
        let plan = build_plan(
            &[allow_from("web", "client")],
            &pods,
            &[],
            "node-a",
            IpFamily::V4,
            "1",
            false,
            &[],
        );
        // db isn't selected → no pod-fw chain, no dispatch.
        assert!(!plan.rules.iter().any(|r| r.contains("10.244.0.9")));
    }

    #[test]
    fn selected_pod_gets_fw_chain_reject_and_dispatch() {
        let pods = vec![
            pod("default", "web", &[("app", "web")], "10.244.0.5"),
            pod("default", "client", &[("app", "client")], "10.244.0.6"),
        ];
        let plan = build_plan(
            &[allow_from("web", "client")],
            &pods,
            &[],
            "node-a",
            IpFamily::V4,
            "1",
            false,
            &[],
        );

        // dispatch to web's pod-fw chain by dest IP.
        assert!(plan
            .rules
            .iter()
            .any(|r| r.contains("-A KUBE-ROUTER-FORWARD -d 10.244.0.5 -j KUBE-POD-FW-")));
        // conntrack accept + final reject present.
        assert!(plan
            .rules
            .iter()
            .any(|r| r.contains("RELATED,ESTABLISHED -j ACCEPT")));
        assert!(plan.rules.iter().any(|r| r.contains("-j REJECT")));
        // policy chain accepts from the src set.
        assert!(plan
            .rules
            .iter()
            .any(|r| r.contains("-m set --match-set KUBE-SRC-") && r.ends_with("src -j ACCEPT")));
        // src ipset contains the client IP.
        let set = plan
            .ipsets
            .iter()
            .find(|s| s.name.starts_with("KUBE-SRC-"))
            .unwrap();
        assert!(set.entries.contains(&"10.244.0.6".to_string()));
        assert_eq!(set.set_type, SetType::HashNet);
    }

    #[test]
    fn default_deny_adds_local_pods_set_and_tail_reject() {
        let pods = vec![pod("default", "x", &[("app", "x")], "10.244.0.9")];
        let cidrs = vec!["10.244.0.0/24".parse().unwrap()];
        let plan = build_plan(&[], &pods, &[], "node-a", IpFamily::V4, "1", true, &cidrs);
        assert!(plan
            .ipsets
            .iter()
            .any(|s| s.name == "kube-router-local-pods"));
        assert!(plan.rules.iter().any(|r| r.contains("-d 10.244.0.0/24")
            && r.contains("! --match-set kube-router-local-pods dst")
            && r.contains("-j REJECT")));
    }

    #[test]
    fn no_default_deny_means_no_tail_reject() {
        let pods = vec![pod("default", "x", &[("app", "x")], "10.244.0.9")];
        let cidrs = vec!["10.244.0.0/24".parse().unwrap()];
        let plan = build_plan(&[], &pods, &[], "node-a", IpFamily::V4, "1", false, &cidrs);
        assert!(!plan
            .rules
            .iter()
            .any(|r| r.contains("kube-router-local-pods")));
    }

    #[test]
    fn deny_all_ingress_when_no_rules() {
        let mut pol = allow_from("web", "client");
        pol.ingress.clear(); // ingress type, no rules → deny all
        let pods = vec![pod("default", "web", &[("app", "web")], "10.244.0.5")];
        let plan = build_plan(&[pol], &pods, &[], "node-a", IpFamily::V4, "1", false, &[]);
        // pod-fw chain exists with reject, but no ACCEPT-from rules.
        assert!(plan.rules.iter().any(|r| r.contains("-j REJECT")));
        assert!(!plan.rules.iter().any(|r| r.contains("-m set --match-set")));
    }
}
