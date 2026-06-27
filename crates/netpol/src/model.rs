//! Projected NetworkPolicy inputs (matched from Kubernetes objects in the binary,
//! kept pure here for testability). `matchLabels`-style selectors are supported;
//! `matchExpressions` is a documented follow-up.

use std::collections::BTreeMap;
use std::net::IpAddr;

use ipnet::IpNet;

/// A label selector (subset: equality `matchLabels`). Empty selector matches all.
pub type LabelSelector = BTreeMap<String, String>;

/// Does `labels` satisfy `selector` (all selector entries present and equal)?
pub fn selector_matches(selector: &LabelSelector, labels: &BTreeMap<String, String>) -> bool {
    selector
        .iter()
        .all(|(k, v)| labels.get(k).is_some_and(|lv| lv == v))
}

/// A pod (projected).
#[derive(Debug, Clone)]
pub struct Pod {
    /// Namespace.
    pub namespace: String,
    /// Name.
    pub name: String,
    /// Labels.
    pub labels: BTreeMap<String, String>,
    /// Pod IP addresses.
    pub ips: Vec<IpAddr>,
    /// Host node name (to identify local pods).
    pub node_name: String,
    /// `hostNetwork` pods are not policy-actionable.
    pub host_network: bool,
}

/// A namespace (projected) — labels used by namespace selectors.
#[derive(Debug, Clone)]
pub struct Namespace {
    /// Name.
    pub name: String,
    /// Labels.
    pub labels: BTreeMap<String, String>,
}

/// A policy peer (from/to entry).
#[derive(Debug, Clone)]
pub enum Peer {
    /// pod/namespace selector peer.
    Selector {
        /// Optional namespace selector (None ⇒ policy's own namespace).
        namespace_selector: Option<LabelSelector>,
        /// Optional pod selector (None ⇒ all pods in the selected namespaces).
        pod_selector: Option<LabelSelector>,
    },
    /// CIDR peer with optional exceptions.
    IpBlock {
        /// The CIDR.
        cidr: IpNet,
        /// Excluded sub-CIDRs.
        except: Vec<IpNet>,
    },
}

/// A port match (numeric; named ports are a follow-up).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortSpec {
    /// Lowercase protocol ("tcp"/"udp"/"sctp").
    pub protocol: String,
    /// Port number; None ⇒ all ports.
    pub port: Option<u16>,
}

/// An ingress/egress rule. Empty `peers` ⇒ match all sources/dests; empty
/// `ports` ⇒ all ports.
#[derive(Debug, Clone, Default)]
pub struct Rule {
    /// Peers (from/to).
    pub peers: Vec<Peer>,
    /// Port matches.
    pub ports: Vec<PortSpec>,
}

/// Which directions a policy applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyTypes {
    /// Applies to ingress.
    pub ingress: bool,
    /// Applies to egress.
    pub egress: bool,
}

/// A projected NetworkPolicy.
#[derive(Debug, Clone)]
pub struct NetworkPolicy {
    /// Namespace.
    pub namespace: String,
    /// Name.
    pub name: String,
    /// Pods this policy applies to (within its namespace).
    pub pod_selector: LabelSelector,
    /// Policy types.
    pub policy_types: PolicyTypes,
    /// Ingress rules.
    pub ingress: Vec<Rule>,
    /// Egress rules.
    pub egress: Vec<Rule>,
}

impl NetworkPolicy {
    /// Local pods (on `node_name`) in this policy's namespace that it selects and
    /// that are actionable (running with an IP, not hostNetwork).
    pub fn selected_local_pods<'a>(&self, pods: &'a [Pod], node_name: &str) -> Vec<&'a Pod> {
        pods.iter()
            .filter(|p| {
                p.namespace == self.namespace
                    && p.node_name == node_name
                    && !p.host_network
                    && !p.ips.is_empty()
                    && selector_matches(&self.pod_selector, &p.labels)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lbl(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn empty_selector_matches_all() {
        assert!(selector_matches(&BTreeMap::new(), &lbl(&[("a", "b")])));
    }

    #[test]
    fn selector_requires_all_entries() {
        let sel = lbl(&[("app", "web")]);
        assert!(selector_matches(&sel, &lbl(&[("app", "web"), ("x", "y")])));
        assert!(!selector_matches(&sel, &lbl(&[("app", "db")])));
        assert!(!selector_matches(&sel, &lbl(&[("x", "y")])));
    }

    fn pod(ns: &str, name: &str, node: &str, labels: &[(&str, &str)], ip: &str) -> Pod {
        Pod {
            namespace: ns.to_string(),
            name: name.to_string(),
            labels: lbl(labels),
            ips: vec![ip.parse().unwrap()],
            node_name: node.to_string(),
            host_network: false,
        }
    }

    #[test]
    fn selects_local_actionable_pods_only() {
        let policy = NetworkPolicy {
            namespace: "default".into(),
            name: "web".into(),
            pod_selector: lbl(&[("app", "web")]),
            policy_types: PolicyTypes {
                ingress: true,
                egress: false,
            },
            ingress: vec![],
            egress: vec![],
        };
        let pods = vec![
            pod(
                "default",
                "web-1",
                "node-a",
                &[("app", "web")],
                "10.244.0.5",
            ),
            pod(
                "default",
                "web-2",
                "node-b",
                &[("app", "web")],
                "10.244.1.5",
            ), // other node
            pod("default", "db-1", "node-a", &[("app", "db")], "10.244.0.6"), // not selected
        ];
        let sel = policy.selected_local_pods(&pods, "node-a");
        assert_eq!(sel.len(), 1);
        assert_eq!(sel[0].name, "web-1");
    }
}
