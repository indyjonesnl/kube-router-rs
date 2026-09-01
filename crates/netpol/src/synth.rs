//! Firewall synthesis: NetworkPolicies + pods/namespaces → ipset contents + an
//! iptables filter-table document. Mirrors the chain model of
//! `upstream/pkg/controllers/netpol`, both directions.
//!
//! Semantics:
//! - A pod selected by no policy is unaffected (default-allow): no per-pod chain.
//! - A selected pod gets a `KUBE-POD-FW-<pod>` chain that jumps to
//!   `KUBE-NWPLCY-COMMON` (stateful accept), permits node-local traffic, dispatches
//!   to each applicable `KUBE-NWPLCY-<policy>` chain, then REJECTs whatever no
//!   policy marked and finally sets the accept mark.
//! - Policy chains MARK + RETURN rather than ACCEPT, so both the sending pod's
//!   egress chain and the receiving pod's ingress chain get to run.
//! - A direction no policy covers jumps to `KUBE-NWPLCY-DEFAULT`, which marks it
//!   allowed.
//! - Each rule's peers go in two ipsets: pod IPs in `hash:ip`, ipBlock CIDRs in
//!   `hash:net` with `nomatch` exceptions.
//!
//! NOTE: named ports are the remaining follow-up.

use ipnet::IpNet;
use kr_common::ipfamily::IpFamily;
use kr_common::naming::{network_policy_chain, pod_firewall_chain};

use crate::ipset::SetType;
use crate::model::{selector_matches, Namespace, NetworkPolicy, Pod};
use crate::naming::{
    dst_set, indexed_dst_ipblock_set, indexed_dst_pod_set, indexed_src_ipblock_set,
    indexed_src_pod_set, local_pods_set, src_set, MARK_ACCEPTED, MARK_MATCHED, NWPLCY_COMMON,
    NWPLCY_DEFAULT, NWPLCY_TAIL, ROUTER_FORWARD, ROUTER_INPUT, ROUTER_OUTPUT,
};
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

/// ICMP types upstream always permits (`utils.CommonICMPRules`): echo-request,
/// destination-unreachable (which carries PMTU discovery), and time-exceeded, plus
/// neighbour discovery and echo-reply on IPv6 where they are load-bearing.
fn common_icmp_rules(family: IpFamily) -> Vec<(&'static str, &'static str, &'static str)> {
    match family {
        IpFamily::V4 => vec![
            ("icmp", "--icmp-type", "echo-request"),
            ("icmp", "--icmp-type", "destination-unreachable"),
            ("icmp", "--icmp-type", "time-exceeded"),
        ],
        IpFamily::V6 => vec![
            ("icmpv6", "--icmpv6-type", "echo-request"),
            ("icmpv6", "--icmpv6-type", "destination-unreachable"),
            ("icmpv6", "--icmpv6-type", "time-exceeded"),
            ("icmpv6", "--icmpv6-type", "neighbor-solicitation"),
            ("icmpv6", "--icmpv6-type", "neighbor-advertisement"),
            ("icmpv6", "--icmpv6-type", "echo-reply"),
        ],
    }
}

/// Which side of a rule the policy's own pods sit on.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    /// Policy pods are the destination; peers are sources (`from`).
    Ingress,
    /// Policy pods are the source; peers are destinations (`to`).
    Egress,
}

/// Emit one policy's rules for a direction. Ingress and egress are structurally
/// identical in upstream (`processIngressRules` / `processEgressRules`) with src and
/// dst swapped, so they share this: the policy's target-pod set is matched on the
/// side its own pods sit on, and each rule's peers on the other side.
#[allow(clippy::too_many_arguments)]
fn emit_policy_rules(
    plan: &mut FirewallPlan,
    pchain: &str,
    rules: &[crate::model::Rule],
    dir: Direction,
    target_set: &str,
    pol: &NetworkPolicy,
    pods: &[Pod],
    namespaces: &[Namespace],
    family: IpFamily,
) {
    // The policy's own pods: dst for ingress, src for egress. Peers take the other.
    let (target_side, peer_side) = match dir {
        Direction::Ingress => ("dst", "src"),
        Direction::Egress => ("src", "dst"),
    };
    let target_match = format!(" -m set --match-set {target_set} {target_side}");

    for (idx, rule) in rules.iter().enumerate() {
        let resolved = resolve_peers(&rule.peers, pods, namespaces, &pol.namespace, family);

        // Peers go in TWO sets, as upstream does: pod IPs in a hash:ip set and ipBlock
        // CIDRs in a hash:net set with `nomatch` exceptions. A single merged hash:net
        // set cannot express both cleanly.
        let (pod_set, ipblock_set) = match dir {
            Direction::Ingress => (
                indexed_src_pod_set(&pol.namespace, &pol.name, idx, family),
                indexed_src_ipblock_set(&pol.namespace, &pol.name, idx, family),
            ),
            Direction::Egress => (
                indexed_dst_pod_set(&pol.namespace, &pol.name, idx, family),
                indexed_dst_ipblock_set(&pol.namespace, &pol.name, idx, family),
            ),
        };

        let mut peer_matches: Vec<String> = Vec::new();
        if resolved.match_all {
            // No peer selector: match every peer, port matches still apply.
            peer_matches.push(String::new());
        } else {
            if !resolved.ip_entries.is_empty() {
                plan.ipsets.push(IpsetPlan {
                    name: pod_set.clone(),
                    set_type: SetType::HashIp,
                    family,
                    entries: resolved.ip_entries.clone(),
                });
                peer_matches.push(format!(" -m set --match-set {pod_set} {peer_side}"));
            }
            if !resolved.net_entries.is_empty() {
                plan.ipsets.push(IpsetPlan {
                    name: ipblock_set.clone(),
                    set_type: SetType::HashNet,
                    family,
                    entries: resolved.net_entries.clone(),
                });
                peer_matches.push(format!(" -m set --match-set {ipblock_set} {peer_side}"));
            }
        }

        for peer_match in &peer_matches {
            if rule.ports.is_empty() {
                push_policy_verdict(plan, pchain, peer_match, &target_match, "");
            } else {
                for port in &rule.ports {
                    // --dport is the peer's port in both directions: for ingress it is
                    // the policy pod's own port, for egress the destination's.
                    let pm = match port.port {
                        Some(p) => format!(" -p {} --dport {p}", port.protocol),
                        None => format!(" -p {}", port.protocol),
                    };
                    push_policy_verdict(plan, pchain, peer_match, &target_match, &pm);
                }
            }
        }
    }
}

/// Emit the MARK + RETURN pair upstream's `appendRuleToPolicyChain` writes for one
/// matching rule. It deliberately does NOT `-j ACCEPT`: ACCEPT would end filter-table
/// traversal, so a packet permitted by the receiving pod's ingress chain would skip
/// the sending pod's egress chain entirely. Marking and returning lets every
/// applicable chain run, and the tail chain makes the final decision.
fn push_policy_verdict(
    plan: &mut FirewallPlan,
    pchain: &str,
    src_match: &str,
    target_match: &str,
    port_match: &str,
) {
    plan.rules.push(format!(
        "-A {pchain}{src_match}{target_match}{port_match} -j MARK --set-xmark {MARK_MATCHED}"
    ));
    plan.rules.push(format!(
        "-A {pchain}{src_match}{target_match}{port_match} -m mark --mark {MARK_MATCHED} -j RETURN"
    ));
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
    service_cluster_ip_ranges: &[IpNet],
    node_port_range: Option<&str>,
) -> FirewallPlan {
    let mut plan = FirewallPlan {
        chain_decls: vec![
            format!(":{ROUTER_INPUT} - [0:0]"),
            format!(":{ROUTER_FORWARD} - [0:0]"),
            format!(":{ROUTER_OUTPUT} - [0:0]"),
            format!(":{NWPLCY_COMMON} - [0:0]"),
            format!(":{NWPLCY_DEFAULT} - [0:0]"),
            format!(":{NWPLCY_TAIL} - [0:0]"),
        ],
        ..Default::default()
    };

    // KUBE-NWPLCY-COMMON: bi-directional rules that apply regardless of policy.
    // Mirrors upstream ensureCommonPolicyChain. INVALID is dropped because the NAT
    // engine skips those packets, so leaving them would leak untranslated traffic
    // (netfilter bug 693).
    plan.rules.push(format!(
        "-A {NWPLCY_COMMON} -m conntrack --ctstate INVALID -j DROP"
    ));
    plan.rules.push(format!(
        "-A {NWPLCY_COMMON} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
    ));
    for (proto, icmp_type, kind) in common_icmp_rules(family) {
        plan.rules.push(format!(
            "-A {NWPLCY_COMMON} -p {proto} {icmp_type} {kind} -j ACCEPT"
        ));
    }

    // KUBE-NWPLCY-DEFAULT: marks traffic in a direction the pod has no policy for,
    // so the pod chain's REJECT-on-unmarked does not fire. Mirrors upstream
    // ensureDefaultNetworkPolicyChain.
    plan.rules.push(format!(
        "-A {NWPLCY_DEFAULT} -j MARK --set-xmark {MARK_MATCHED}"
    ));

    // Service traffic must NOT be judged by the pod firewall on its way IN, because
    // at that point IPVS has not yet DNAT'd the ClusterIP/NodePort to a backend pod:
    // filter INPUT runs at priority 0 and ip_vs_in later, so `dst` is still the
    // service VIP and matches no peer set holding pod IPs. Upstream inserts these
    // RETURNs at the head of KUBE-ROUTER-INPUT (allowTrafficToClusterIPRange plus the
    // per-protocol NodePort whitelists) so the packet leaves this chain untouched and
    // is evaluated after DNAT with the real pod address.
    for range in service_cluster_ip_ranges.iter().filter(|c| {
        matches!(
            (c, family),
            (IpNet::V4(_), IpFamily::V4) | (IpNet::V6(_), IpFamily::V6)
        )
    }) {
        plan.rules
            .push(format!("-A {ROUTER_INPUT} -d {range} -j RETURN"));
    }
    if let Some(ports) = node_port_range {
        for proto in ["tcp", "udp", "sctp"] {
            plan.rules.push(format!(
                "-A {ROUTER_INPUT} -p {proto} -m addrtype --dst-type LOCAL \
                 -m multiport --dports {ports} -j RETURN"
            ));
        }
    }

    // Per-policy chains. Upstream keeps ONE chain per policy for both directions and
    // disambiguates by matching the policy's target-pod ipset on the appropriate side
    // (dst for ingress, src for egress), which is what makes a shared chain safe.
    for pol in policies
        .iter()
        .filter(|p| p.policy_types.ingress || p.policy_types.egress)
    {
        let pchain = network_policy_chain(&pol.namespace, &pol.name, sync_version, family);
        plan.chain_decls.push(format!(":{pchain} - [0:0]"));
        let selected: Vec<String> = pods
            .iter()
            .filter(|p| policy_selects(pol, p))
            .flat_map(|p| pod_family_ips(p, family))
            .collect();

        if pol.policy_types.ingress {
            // Ingress: the policy's own pods are the DESTINATION, peers the source.
            let target = dst_set(&pol.namespace, &pol.name, family);
            plan.ipsets.push(IpsetPlan {
                name: target.clone(),
                set_type: SetType::HashIp,
                family,
                entries: selected.clone(),
            });
            emit_policy_rules(
                &mut plan,
                &pchain,
                &pol.ingress,
                Direction::Ingress,
                &target,
                pol,
                pods,
                namespaces,
                family,
            );
        }
        if pol.policy_types.egress {
            // Egress: the policy's own pods are the SOURCE, peers the destination.
            let target = src_set(&pol.namespace, &pol.name, family);
            plan.ipsets.push(IpsetPlan {
                name: target.clone(),
                set_type: SetType::HashIp,
                family,
                entries: selected.clone(),
            });
            emit_policy_rules(
                &mut plan,
                &pchain,
                &pol.egress,
                Direction::Egress,
                &target,
                pol,
                pods,
                namespaces,
                family,
            );
        }
    }

    // Per-pod firewall chains for local, actionable pods.
    let mut programmed_ips: Vec<String> = Vec::new();
    for pod in pods
        .iter()
        .filter(|p| p.node_name == node && !p.host_network && !pod_family_ips(p, family).is_empty())
    {
        // A policy contributes to this pod's chain in whichever direction(s) it
        // declares. A pod selected by no policy at all keeps default-allow and gets
        // no chain, exactly as before.
        let selecting: Vec<&NetworkPolicy> = policies
            .iter()
            .filter(|p| (p.policy_types.ingress || p.policy_types.egress) && policy_selects(p, pod))
            .collect();
        if selecting.is_empty() {
            continue; // default-allow: no per-pod chain at all
        }
        let has_ingress = selecting.iter().any(|p| p.policy_types.ingress);
        let has_egress = selecting.iter().any(|p| p.policy_types.egress);

        let podchain = pod_firewall_chain(&pod.namespace, &pod.name, sync_version);
        plan.chain_decls.push(format!(":{podchain} - [0:0]"));

        // Upstream inserts these at position 1 of the pod chain, so they run BEFORE
        // any policy jump and before the reject below. The COMMON jump is what makes
        // the firewall stateful: without it ahead of the unmarked-REJECT, the reply
        // leg of an allowed connection is unmarked and gets rejected.
        plan.rules.push(format!("-A {podchain} -j {NWPLCY_COMMON}"));
        for ip in pod_family_ips(pod, family) {
            // Traffic originating on the pod's own node (kubelet probes, node-local
            // clients) is permitted regardless of policy.
            plan.rules.push(format!(
                "-A {podchain} -m addrtype --src-type LOCAL -d {ip} -j ACCEPT"
            ));
        }

        for ip in pod_family_ips(pod, family) {
            // Direction-gated jumps, mirroring upstream setupPodNetpolRules. A policy
            // covering BOTH directions is entered unconditionally — its rules are
            // already disambiguated by the target-pod ipset on src vs dst. A
            // single-direction policy is entered only for traffic on that side.
            for pol in &selecting {
                let pc = network_policy_chain(&pol.namespace, &pol.name, sync_version, family);
                match (pol.policy_types.ingress, pol.policy_types.egress) {
                    (true, true) => plan.rules.push(format!("-A {podchain} -j {pc}")),
                    (true, false) => plan.rules.push(format!("-A {podchain} -d {ip} -j {pc}")),
                    (false, true) => plan.rules.push(format!("-A {podchain} -s {ip} -j {pc}")),
                    (false, false) => unreachable!("filtered above"),
                }
            }
            // A direction no policy covers stays unrestricted, which under the mark
            // scheme must be stated explicitly: without a jump to DEFAULT the traffic
            // stays unmarked and the REJECT below would fire.
            if !has_ingress {
                plan.rules
                    .push(format!("-A {podchain} -d {ip} -j {NWPLCY_DEFAULT}"));
            }
            if !has_egress {
                plan.rules
                    .push(format!("-A {podchain} -s {ip} -j {NWPLCY_DEFAULT}"));
            }
        }

        // Unmarked traffic reached no permitting policy: log, reject, then clear the
        // match mark and set the accept mark for what survived.
        plan.rules.push(format!(
            "-A {podchain} -m mark ! --mark {MARK_MATCHED} -j NFLOG \
             --nflog-group 100 -m limit --limit 10/minute --limit-burst 10"
        ));
        plan.rules.push(format!(
            "-A {podchain} -m mark ! --mark {MARK_MATCHED} -j {}",
            reject_target(family)
        ));
        plan.rules
            .push(format!("-A {podchain} -j MARK --set-mark 0/0x10000"));
        plan.rules
            .push(format!("-A {podchain} -j MARK --set-mark {MARK_ACCEPTED}"));

        for ip in pod_family_ips(pod, family) {
            // Three inbound paths (routed / service-proxy via LOCAL_OUT / bridged) and
            // the outbound path, per upstream interceptPod{Inbound,Outbound}Traffic.
            plan.rules
                .push(format!("-A {ROUTER_FORWARD} -d {ip} -j {podchain}"));
            plan.rules
                .push(format!("-A {ROUTER_OUTPUT} -d {ip} -j {podchain}"));
            plan.rules.push(format!(
                "-A {ROUTER_FORWARD} -m physdev --physdev-is-bridged -d {ip} -j {podchain}"
            ));
            // Outbound: upstream's interceptPodOutboundTraffic jumps on SOURCE from
            // all three top-level chains plus the bridged variant, so egress is
            // evaluated wherever the packet leaves from.
            for chain in [ROUTER_INPUT, ROUTER_FORWARD, ROUTER_OUTPUT] {
                plan.rules.push(format!("-A {chain} -s {ip} -j {podchain}"));
            }
            plan.rules.push(format!(
                "-A {ROUTER_FORWARD} -m physdev --physdev-is-bridged -s {ip} -j {podchain}"
            ));
            programmed_ips.push(ip);
        }
    }

    // KUBE-NWPLCY-TAIL: the ACCEPT/REJECT decision, jumped to at the end of each
    // top-level chain. Mirrors upstream populateDefaultTailChain.
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
                "-A {NWPLCY_TAIL} -s {cidr} -m set ! --match-set {set} src -j {reject}"
            ));
            plan.rules.push(format!(
                "-A {NWPLCY_TAIL} -d {cidr} -m set ! --match-set {set} dst -j {reject}"
            ));
        }
    }
    plan.rules.push(format!(
        "-A {NWPLCY_TAIL} -m mark --mark {MARK_ACCEPTED} -j ACCEPT"
    ));
    if default_deny {
        let reject = reject_target(family);
        for cidr in pod_cidrs.iter().filter(|c| {
            matches!(
                (c, family),
                (IpNet::V4(_), IpFamily::V4) | (IpNet::V6(_), IpFamily::V6)
            )
        }) {
            plan.rules
                .push(format!("-A {NWPLCY_TAIL} -s {cidr} -j {reject}"));
            plan.rules
                .push(format!("-A {NWPLCY_TAIL} -d {cidr} -j {reject}"));
        }
    }

    // Each top-level chain ends with the tail jump, after the per-pod jumps above.
    for chain in [ROUTER_INPUT, ROUTER_FORWARD, ROUTER_OUTPUT] {
        plan.rules.push(format!("-A {chain} -j {NWPLCY_TAIL}"));
    }
    plan
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{LabelSelector, Peer, PolicyTypes, Rule};
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
            pod_selector: LabelSelector::from_labels(lbl(&[("app", app)])),
            policy_types: PolicyTypes {
                ingress: true,
                egress: false,
            },
            ingress: vec![Rule {
                peers: vec![Peer::Selector {
                    namespace_selector: None,
                    pod_selector: Some(LabelSelector::from_labels(lbl(&[("app", from)]))),
                }],
                ports: vec![],
            }],
            egress: vec![],
        }
    }

    fn allow_to(app: &str, to: &str, egress_only: bool) -> NetworkPolicy {
        NetworkPolicy {
            namespace: "default".into(),
            name: "e".into(),
            pod_selector: LabelSelector::from_labels(lbl(&[("app", app)])),
            policy_types: PolicyTypes {
                ingress: !egress_only,
                egress: true,
            },
            ingress: if egress_only {
                vec![]
            } else {
                vec![Rule {
                    peers: vec![],
                    ports: vec![],
                }]
            },
            egress: vec![Rule {
                peers: vec![Peer::Selector {
                    namespace_selector: None,
                    pod_selector: Some(LabelSelector::from_labels(lbl(&[("app", to)]))),
                }],
                ports: vec![],
            }],
        }
    }

    /// Egress is the mirror of ingress: the policy's own pods are matched on SRC and
    /// the peers on DST, and the pod chain is entered on source address.
    #[test]
    fn egress_policy_matches_peers_on_dst_and_is_entered_on_source() {
        let pods = vec![
            pod("default", "web", &[("app", "web")], "10.244.0.5"),
            pod("default", "db", &[("app", "db")], "10.244.0.7"),
        ];
        let plan = build_plan(
            &[allow_to("web", "db", true)],
            &pods,
            &[],
            "node-a",
            IpFamily::V4,
            "1",
            false,
            &[],
            &[],
            None,
        );
        let has = |pat: &str| plan.rules.iter().any(|r| r.contains(pat));

        // policy pods on src, peers on dst — the opposite sides from ingress.
        assert!(
            plan.rules
                .iter()
                .any(|r| r.contains("-m set --match-set KUBE-DST-")
                    && r.contains("dst")
                    && r.contains("-m set --match-set KUBE-SRC-")
                    && r.contains("src")),
            "{:?}",
            plan.rules
        );
        // the pod chain is entered on SOURCE for an egress-only policy.
        assert!(has("-A KUBE-POD-FW-") && has("-s 10.244.0.5 -j KUBE-NWPLCY-"));
        // ingress is uncovered, so it must be explicitly marked allowed.
        assert!(has("-d 10.244.0.5 -j KUBE-NWPLCY-DEFAULT"));
        // outbound intercepts on all three top-level chains plus the bridged variant.
        for c in [
            "KUBE-ROUTER-INPUT",
            "KUBE-ROUTER-FORWARD",
            "KUBE-ROUTER-OUTPUT",
        ] {
            assert!(
                has(&format!("-A {c} -s 10.244.0.5 -j KUBE-POD-FW-")),
                "outbound intercept missing on {c}"
            );
        }
        assert!(has(
            "-A KUBE-ROUTER-FORWARD -m physdev --physdev-is-bridged -s 10.244.0.5 -j KUBE-POD-FW-"
        ));
        // peer pod IPs land in the egress hash:ip set.
        let set = plan
            .ipsets
            .iter()
            .find(|s| {
                s.name.starts_with("KUBE-DST-") && s.entries.contains(&"10.244.0.7".to_string())
            })
            .expect("egress peer set");
        assert_eq!(set.set_type, SetType::HashIp);
    }

    /// A policy declaring both directions is entered WITHOUT an address gate — its
    /// rules are already separated by which side the target set is matched on. Gating
    /// it on -d or -s would silently drop one direction.
    #[test]
    fn policy_covering_both_directions_is_entered_ungated() {
        let pods = vec![
            pod("default", "web", &[("app", "web")], "10.244.0.5"),
            pod("default", "db", &[("app", "db")], "10.244.0.7"),
        ];
        let plan = build_plan(
            &[allow_to("web", "db", false)],
            &pods,
            &[],
            "node-a",
            IpFamily::V4,
            "1",
            false,
            &[],
            &[],
            None,
        );
        let jumps: Vec<&String> = plan
            .rules
            .iter()
            .filter(|r| r.contains("KUBE-POD-FW-") && r.contains("-j KUBE-NWPLCY-"))
            .collect();
        assert!(
            jumps
                .iter()
                .any(|r| !r.contains("-d ") && !r.contains("-s ")),
            "both-direction policy must be entered ungated: {jumps:?}"
        );
        // and neither direction falls through to DEFAULT.
        assert!(!plan
            .rules
            .iter()
            .any(|r| r.contains("KUBE-POD-FW-") && r.contains("-j KUBE-NWPLCY-DEFAULT")));
    }

    /// Service traffic must leave KUBE-ROUTER-INPUT before any pod-firewall jump.
    /// Filter INPUT runs at netfilter priority 0 and ip_vs_in later, so on the way
    /// in `dst` is still the ClusterIP/NodePort — it matches no peer set holding pod
    /// IPs, and egress policies would reject traffic the policy actually permits.
    /// Mirrors upstream allowTrafficToClusterIPRange + the NodePort whitelists.
    #[test]
    fn service_vips_and_nodeports_return_before_pod_jumps() {
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
            &["10.96.0.0/12".parse().unwrap()],
            Some("30000:32767"),
        );
        let input: Vec<&String> = plan
            .rules
            .iter()
            .filter(|r| r.starts_with("-A KUBE-ROUTER-INPUT"))
            .collect();

        let vip_at = input
            .iter()
            .position(|r| r.contains("-d 10.96.0.0/12 -j RETURN"))
            .expect("ClusterIP range RETURN");
        for proto in ["tcp", "udp", "sctp"] {
            assert!(
                input.iter().any(|r| r.contains(&format!("-p {proto}"))
                    && r.contains("--dst-type LOCAL")
                    && r.contains("--dports 30000:32767")
                    && r.contains("-j RETURN")),
                "missing {proto} nodeport whitelist: {input:?}"
            );
        }
        // ordering is the whole point: a jump placed before these would judge the
        // packet pre-DNAT.
        let first_pod_jump = input
            .iter()
            .position(|r| r.contains("-j KUBE-POD-FW-"))
            .expect("a pod jump on INPUT");
        assert!(
            vip_at < first_pod_jump,
            "service VIP RETURN must precede pod jumps: {input:?}"
        );
        let last_whitelist = input
            .iter()
            .rposition(|r| r.contains("--dports 30000:32767"))
            .unwrap();
        assert!(last_whitelist < first_pod_jump, "{input:?}");
    }

    /// Only ranges of the family being built are emitted.
    #[test]
    fn service_vip_return_is_family_scoped() {
        let pods = vec![pod("default", "web", &[("app", "web")], "10.244.0.5")];
        let plan = build_plan(
            &[allow_from("web", "client")],
            &pods,
            &[],
            "node-a",
            IpFamily::V4,
            "1",
            false,
            &[],
            &["fd00::/108".parse().unwrap()],
            None,
        );
        assert!(!plan.rules.iter().any(|r| r.contains("fd00::/108")));
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
            &[],
            None,
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
            &[],
            None,
        );

        let has = |pat: &str| plan.rules.iter().any(|r| r.contains(pat));

        // dispatch to web's pod-fw chain by dest IP.
        assert!(has("-A KUBE-ROUTER-FORWARD -d 10.244.0.5 -j KUBE-POD-FW-"));
        // stateful accept lives in the shared COMMON chain, not per pod.
        assert!(has(
            "-A KUBE-NWPLCY-COMMON -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
        ));
        assert!(has(
            "-A KUBE-NWPLCY-COMMON -m conntrack --ctstate INVALID -j DROP"
        ));
        // the policy chain MARKs and RETURNs; it must never ACCEPT, or a packet
        // permitted here would skip the sending pod's egress chain.
        assert!(has("-j MARK --set-xmark 0x10000/0x10000"));
        assert!(has("-m mark --mark 0x10000/0x10000 -j RETURN"));
        assert!(
            !plan.rules.iter().any(|r| r.starts_with("-A KUBE-NWPLCY-")
                && r.ends_with("-j ACCEPT")
                && !r.contains("KUBE-NWPLCY-COMMON")
                && !r.contains("KUBE-NWPLCY-TAIL")),
            "policy chains must not ACCEPT directly"
        );
        // policy rules match the peer set on src AND the policy's own pods on dst.
        assert!(plan
            .rules
            .iter()
            .any(|r| r.contains("-m set --match-set KUBE-SRC-")
                && r.contains("src")
                && r.contains("-m set --match-set KUBE-DST-")
                && r.contains("dst")));
        // the stateful accept must be reachable BEFORE the reject, or the reply leg of
        // an allowed connection is unmarked and gets rejected.
        let rules: Vec<&String> = plan
            .rules
            .iter()
            .filter(|r| r.contains("KUBE-POD-FW-"))
            .collect();
        let common_at = rules
            .iter()
            .position(|r| r.contains("-j KUBE-NWPLCY-COMMON"))
            .expect("pod chain jumps to COMMON");
        let reject_at = rules
            .iter()
            .position(|r| r.contains("! --mark 0x10000/0x10000 -j REJECT"))
            .expect("pod chain rejects unmarked");
        assert!(
            common_at < reject_at,
            "COMMON must precede REJECT: {rules:?}"
        );
        assert!(has("-m addrtype --src-type LOCAL -d 10.244.0.5 -j ACCEPT"));

        // pod chain: reject only what no policy marked, then reset + set accept mark.
        // full text: a line-continuation slip here would make iptables-restore
        // reject the whole document, not just this rule.
        assert!(has(
            "-m mark ! --mark 0x10000/0x10000 -j NFLOG --nflog-group 100 \
             -m limit --limit 10/minute --limit-burst 10"
        ));
        assert!(has("-m mark ! --mark 0x10000/0x10000 -j REJECT"));
        assert!(has("-j MARK --set-mark 0/0x10000"));
        assert!(has("-j MARK --set-mark 0x20000/0x20000"));
        // egress is untranslated, so egress must be explicitly marked allowed.
        assert!(has("-s 10.244.0.5 -j KUBE-NWPLCY-DEFAULT"));
        assert!(has(
            "-A KUBE-NWPLCY-DEFAULT -j MARK --set-xmark 0x10000/0x10000"
        ));
        // peer pod IPs go in a hash:ip set, separate from any ipBlock hash:net set.
        let set = plan
            .ipsets
            .iter()
            .find(|s| s.name.starts_with("KUBE-SRC-"))
            .unwrap();
        assert!(set.entries.contains(&"10.244.0.6".to_string()));
        assert_eq!(set.set_type, SetType::HashIp);
    }

    /// A packet reaches a local pod by three different paths, and a jump is needed
    /// for each: routed from another node (FORWARD), emitted from LOCAL_OUT after
    /// the service proxy DNATs a ClusterIP to a same-node backend (OUTPUT), and
    /// bridged from a same-node pod (physdev). A missing jump is not a missing
    /// rule — it silently ACCEPTs that whole path, because the traffic never
    /// reaches the pod chain's trailing REJECT.
    #[test]
    fn pod_chain_is_reachable_from_all_three_inbound_paths() {
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
            &[],
            None,
        );
        let has = |pat: &str| plan.rules.iter().any(|r| r.contains(pat));

        assert!(
            has("-A KUBE-ROUTER-FORWARD -d 10.244.0.5 -j KUBE-POD-FW-"),
            "routed-from-another-node path"
        );
        assert!(
            has("-A KUBE-ROUTER-OUTPUT -d 10.244.0.5 -j KUBE-POD-FW-"),
            "service-proxy loopback to a same-node pod leaves via LOCAL_OUT; \
             without this jump every pod->ClusterIP->same-node-pod flow skips the \
             firewall and is allowed"
        );
        assert!(
            has("-A KUBE-ROUTER-FORWARD -m physdev --physdev-is-bridged -d 10.244.0.5 -j KUBE-POD-FW-"),
            "bridged same-node pod->pod path"
        );
    }

    /// The default-deny rejects live in KUBE-NWPLCY-TAIL, which every top-level
    /// chain jumps to, so one set of rules covers all paths instead of being
    /// duplicated per chain. Mirrors upstream populateDefaultTailChain.
    #[test]
    fn default_deny_rejects_live_in_the_tail_chain() {
        let pods = vec![pod("default", "web", &[("app", "web")], "10.244.0.5")];
        let plan = build_plan(
            &[allow_from("web", "client")],
            &pods,
            &[],
            "node-a",
            IpFamily::V4,
            "1",
            true,
            &["10.244.0.0/24".parse().unwrap()],
            &[],
            None,
        );
        let has = |pat: &str| plan.rules.iter().any(|r| r.contains(pat));

        // ipset-gated rejects for pods whose chain has not been programmed yet.
        assert!(has(
            "-A KUBE-NWPLCY-TAIL -s 10.244.0.0/24 -m set ! --match-set kube-router-local-pods src -j REJECT"
        ));
        assert!(has(
            "-A KUBE-NWPLCY-TAIL -d 10.244.0.0/24 -m set ! --match-set kube-router-local-pods dst -j REJECT"
        ));
        // the accept-on-mark decision, then the CIDR-scoped defence in depth.
        assert!(has(
            "-A KUBE-NWPLCY-TAIL -m mark --mark 0x20000/0x20000 -j ACCEPT"
        ));
        assert!(has("-A KUBE-NWPLCY-TAIL -s 10.244.0.0/24 -j REJECT"));
        assert!(has("-A KUBE-NWPLCY-TAIL -d 10.244.0.0/24 -j REJECT"));
        // and every top-level chain reaches it.
        for c in [
            "KUBE-ROUTER-INPUT",
            "KUBE-ROUTER-FORWARD",
            "KUBE-ROUTER-OUTPUT",
        ] {
            assert!(has(&format!("-A {c} -j KUBE-NWPLCY-TAIL")), "{c}");
        }
    }

    #[test]
    fn default_deny_adds_local_pods_set_and_tail_reject() {
        let pods = vec![pod("default", "x", &[("app", "x")], "10.244.0.9")];
        let cidrs = vec!["10.244.0.0/24".parse().unwrap()];
        let plan = build_plan(
            &[],
            &pods,
            &[],
            "node-a",
            IpFamily::V4,
            "1",
            true,
            &cidrs,
            &[],
            None,
        );
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
        let plan = build_plan(
            &[],
            &pods,
            &[],
            "node-a",
            IpFamily::V4,
            "1",
            false,
            &cidrs,
            &[],
            None,
        );
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
        let plan = build_plan(
            &[pol],
            &pods,
            &[],
            "node-a",
            IpFamily::V4,
            "1",
            false,
            &[],
            &[],
            None,
        );
        // pod-fw chain exists with reject, but no ACCEPT-from rules.
        assert!(plan.rules.iter().any(|r| r.contains("-j REJECT")));
        assert!(!plan.rules.iter().any(|r| r.contains("-m set --match-set")));
    }
}
