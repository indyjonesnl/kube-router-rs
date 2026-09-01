//! Projected NetworkPolicy inputs (matched from Kubernetes objects in the binary,
//! kept pure here for testability). Selectors implement the full Kubernetes
//! semantics — `matchLabels` AND `matchExpressions` — which is what upstream gets
//! from `v1.LabelSelectorAsSelector`.

use std::collections::BTreeMap;
use std::net::IpAddr;

use ipnet::IpNet;

/// A `matchExpressions` operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectorOp {
    /// Key present and its value is one of `values`.
    In,
    /// Key absent, or its value is not one of `values`.
    NotIn,
    /// Key present, whatever the value.
    Exists,
    /// Key absent.
    DoesNotExist,
}

/// One `matchExpressions` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectorRequirement {
    /// Label key.
    pub key: String,
    /// Operator; an unrecognised one makes the whole selector match nothing,
    /// mirroring `LabelSelectorAsSelector` rejecting it.
    pub operator: Option<SelectorOp>,
    /// Values (used by `In` / `NotIn`).
    pub values: Vec<String>,
}

/// A label selector. An entirely empty selector matches everything, per
/// Kubernetes: `podSelector: {}` selects all pods in the namespace.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LabelSelector {
    /// Equality requirements.
    pub match_labels: BTreeMap<String, String>,
    /// Set-based requirements.
    pub match_expressions: Vec<SelectorRequirement>,
}

impl LabelSelector {
    /// Build a `matchLabels`-only selector.
    pub fn from_labels(labels: BTreeMap<String, String>) -> Self {
        Self {
            match_labels: labels,
            match_expressions: Vec::new(),
        }
    }
}

/// Does `labels` satisfy `selector`? Every `matchLabels` entry and every
/// `matchExpressions` requirement must hold (they are ANDed, as in Kubernetes).
pub fn selector_matches(selector: &LabelSelector, labels: &BTreeMap<String, String>) -> bool {
    let labels_ok = selector
        .match_labels
        .iter()
        .all(|(k, v)| labels.get(k).is_some_and(|lv| lv == v));
    if !labels_ok {
        return false;
    }
    selector.match_expressions.iter().all(|req| {
        let value = labels.get(&req.key);
        match req.operator {
            Some(SelectorOp::In) => value.is_some_and(|v| req.values.contains(v)),
            Some(SelectorOp::NotIn) => value.is_none_or(|v| !req.values.contains(v)),
            Some(SelectorOp::Exists) => value.is_some(),
            Some(SelectorOp::DoesNotExist) => value.is_none(),
            // Unparseable operator: the API server would have rejected it and
            // LabelSelectorAsSelector errors, so select nothing rather than
            // silently widening the selector to match everything.
            None => false,
        }
    })
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
        assert!(selector_matches(
            &LabelSelector::default(),
            &lbl(&[("a", "b")])
        ));
    }

    fn req(key: &str, op: SelectorOp, values: &[&str]) -> SelectorRequirement {
        SelectorRequirement {
            key: key.into(),
            operator: Some(op),
            values: values.iter().map(|v| v.to_string()).collect(),
        }
    }

    /// The four operators `LabelSelectorAsSelector` supports. Dropping these used
    /// to leave an expression-only selector EMPTY, and an empty selector matches
    /// everything — so a policy targeting two pods captured the whole namespace.
    #[test]
    fn match_expressions_implement_all_four_operators() {
        let web = lbl(&[("app", "web"), ("tier", "fe")]);
        let db = lbl(&[("app", "db")]);

        let in_ = LabelSelector {
            match_labels: BTreeMap::new(),
            match_expressions: vec![req("app", SelectorOp::In, &["web", "api"])],
        };
        assert!(selector_matches(&in_, &web));
        assert!(!selector_matches(&in_, &db));

        let not_in = LabelSelector {
            match_labels: BTreeMap::new(),
            match_expressions: vec![req("app", SelectorOp::NotIn, &["web"])],
        };
        assert!(!selector_matches(&not_in, &web));
        assert!(selector_matches(&not_in, &db));
        // NotIn also matches when the key is absent entirely.
        assert!(selector_matches(&not_in, &lbl(&[("other", "x")])));

        let exists = LabelSelector {
            match_labels: BTreeMap::new(),
            match_expressions: vec![req("tier", SelectorOp::Exists, &[])],
        };
        assert!(selector_matches(&exists, &web));
        assert!(!selector_matches(&exists, &db));

        let absent = LabelSelector {
            match_labels: BTreeMap::new(),
            match_expressions: vec![req("tier", SelectorOp::DoesNotExist, &[])],
        };
        assert!(!selector_matches(&absent, &web));
        assert!(selector_matches(&absent, &db));
    }

    /// matchLabels and matchExpressions are ANDed together.
    #[test]
    fn match_labels_and_expressions_are_anded() {
        let sel = LabelSelector {
            match_labels: lbl(&[("app", "web")]),
            match_expressions: vec![req("tier", SelectorOp::In, &["fe"])],
        };
        assert!(selector_matches(
            &sel,
            &lbl(&[("app", "web"), ("tier", "fe")])
        ));
        // right labels, wrong expression
        assert!(!selector_matches(
            &sel,
            &lbl(&[("app", "web"), ("tier", "be")])
        ));
        // right expression, wrong labels
        assert!(!selector_matches(
            &sel,
            &lbl(&[("app", "db"), ("tier", "fe")])
        ));
    }

    /// An operator we cannot parse must select NOTHING. Returning true would widen
    /// the selector to every pod, which is how the previous code over-blocked.
    #[test]
    fn unparseable_operator_matches_nothing() {
        let sel = LabelSelector {
            match_labels: BTreeMap::new(),
            match_expressions: vec![SelectorRequirement {
                key: "app".into(),
                operator: None,
                values: vec![],
            }],
        };
        assert!(!selector_matches(&sel, &lbl(&[("app", "web")])));
        assert!(!selector_matches(&sel, &BTreeMap::new()));
    }

    #[test]
    fn selector_requires_all_entries() {
        let sel = LabelSelector::from_labels(lbl(&[("app", "web")]));
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
            pod_selector: LabelSelector::from_labels(lbl(&[("app", "web")])),
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
