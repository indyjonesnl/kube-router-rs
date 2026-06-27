//! Translate policy peers to concrete ipset entries, mirroring the peer
//! resolution in `upstream/pkg/controllers/netpol/policy.go`.
//!
//! Selector peers resolve to pod IPs (`hash:ip`); ipBlock peers to CIDRs with
//! `except` as `nomatch` entries (`hash:net`), filtered to one IP family.

use std::collections::BTreeSet;

use ipnet::IpNet;
use kr_common::ipfamily::IpFamily;

use crate::model::{selector_matches, Namespace, Peer, Pod};

/// Resolved peer entries for one IP family, split by ipset type.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ResolvedPeers {
    /// Pod IPs (for a `hash:ip` set).
    pub ip_entries: Vec<String>,
    /// CIDRs / `<cidr> nomatch` exceptions (for a `hash:net` set).
    pub net_entries: Vec<String>,
    /// True when the peer list was empty (match-all sources).
    pub match_all: bool,
}

fn ip_in_family(ip: &std::net::IpAddr, family: IpFamily) -> bool {
    matches!(
        (ip, family),
        (std::net::IpAddr::V4(_), IpFamily::V4) | (std::net::IpAddr::V6(_), IpFamily::V6)
    )
}

/// Namespace names whose labels match `selector` (None ⇒ just `default_ns`).
fn matched_namespaces<'a>(
    selector: &Option<crate::model::LabelSelector>,
    namespaces: &'a [Namespace],
    default_ns: &'a str,
) -> BTreeSet<&'a str> {
    match selector {
        None => BTreeSet::from([default_ns]),
        Some(sel) => namespaces
            .iter()
            .filter(|n| selector_matches(sel, &n.labels))
            .map(|n| n.name.as_str())
            .collect(),
    }
}

/// Resolve a rule's peers into ipset entries for `family`, within `policy_ns`.
pub fn resolve_peers(
    peers: &[Peer],
    pods: &[Pod],
    namespaces: &[Namespace],
    policy_ns: &str,
    family: IpFamily,
) -> ResolvedPeers {
    if peers.is_empty() {
        return ResolvedPeers {
            match_all: true,
            ..Default::default()
        };
    }
    let mut ip_entries = BTreeSet::new();
    let mut net_entries = Vec::new();

    for peer in peers {
        match peer {
            Peer::Selector {
                namespace_selector,
                pod_selector,
            } => {
                let nss = matched_namespaces(namespace_selector, namespaces, policy_ns);
                for p in pods {
                    if !nss.contains(p.namespace.as_str()) || p.host_network {
                        continue;
                    }
                    let pod_ok = pod_selector
                        .as_ref()
                        .is_none_or(|s| selector_matches(s, &p.labels));
                    if !pod_ok {
                        continue;
                    }
                    for ip in &p.ips {
                        if ip_in_family(ip, family) {
                            ip_entries.insert(ip.to_string());
                        }
                    }
                }
            }
            Peer::IpBlock { cidr, except } => {
                let cidr_family = match cidr {
                    IpNet::V4(_) => IpFamily::V4,
                    IpNet::V6(_) => IpFamily::V6,
                };
                if cidr_family != family {
                    continue;
                }
                net_entries.push(cidr.to_string());
                // `nomatch` exceptions must be added after the covering net.
                for ex in except {
                    net_entries.push(format!("{ex} nomatch"));
                }
            }
        }
    }

    ResolvedPeers {
        ip_entries: ip_entries.into_iter().collect(),
        net_entries,
        match_all: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Pod;
    use std::collections::BTreeMap;

    fn lbl(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }
    fn pod(ns: &str, labels: &[(&str, &str)], ip: &str) -> Pod {
        Pod {
            namespace: ns.to_string(),
            name: "p".into(),
            labels: lbl(labels),
            ips: vec![ip.parse().unwrap()],
            node_name: "n".into(),
            host_network: false,
        }
    }

    #[test]
    fn empty_peers_is_match_all() {
        let r = resolve_peers(&[], &[], &[], "default", IpFamily::V4);
        assert!(r.match_all);
    }

    #[test]
    fn selector_resolves_same_namespace_pod_ips() {
        let peers = vec![Peer::Selector {
            namespace_selector: None,
            pod_selector: Some(lbl(&[("app", "client")])),
        }];
        let pods = vec![
            pod("default", &[("app", "client")], "10.244.0.5"),
            pod("default", &[("app", "other")], "10.244.0.6"),
            pod("kube-system", &[("app", "client")], "10.244.1.5"), // different ns
        ];
        let r = resolve_peers(&peers, &pods, &[], "default", IpFamily::V4);
        assert_eq!(r.ip_entries, vec!["10.244.0.5".to_string()]);
    }

    #[test]
    fn namespace_selector_widens_to_matched_namespaces() {
        let peers = vec![Peer::Selector {
            namespace_selector: Some(lbl(&[("team", "a")])),
            pod_selector: None,
        }];
        let namespaces = vec![
            Namespace {
                name: "ns-a".into(),
                labels: lbl(&[("team", "a")]),
            },
            Namespace {
                name: "ns-b".into(),
                labels: lbl(&[("team", "b")]),
            },
        ];
        let pods = vec![
            pod("ns-a", &[("x", "y")], "10.0.0.1"),
            pod("ns-b", &[], "10.0.0.2"),
        ];
        let r = resolve_peers(&peers, &pods, &namespaces, "default", IpFamily::V4);
        assert_eq!(r.ip_entries, vec!["10.0.0.1".to_string()]);
    }

    #[test]
    fn ipblock_yields_net_entries_with_nomatch_except() {
        let peers = vec![Peer::IpBlock {
            cidr: "10.0.0.0/8".parse().unwrap(),
            except: vec!["10.1.0.0/16".parse().unwrap()],
        }];
        let r = resolve_peers(&peers, &[], &[], "default", IpFamily::V4);
        assert_eq!(
            r.net_entries,
            vec!["10.0.0.0/8".to_string(), "10.1.0.0/16 nomatch".to_string()]
        );
        assert!(r.ip_entries.is_empty());
    }

    #[test]
    fn family_filtering_excludes_other_family() {
        let peers = vec![Peer::Selector {
            namespace_selector: None,
            pod_selector: None,
        }];
        let pods = vec![Pod {
            namespace: "default".into(),
            name: "p".into(),
            labels: BTreeMap::new(),
            ips: vec!["10.0.0.1".parse().unwrap(), "fd00::1".parse().unwrap()],
            node_name: "n".into(),
            host_network: false,
        }];
        let v4 = resolve_peers(&peers, &pods, &[], "default", IpFamily::V4);
        let v6 = resolve_peers(&peers, &pods, &[], "default", IpFamily::V6);
        assert_eq!(v4.ip_entries, vec!["10.0.0.1".to_string()]);
        assert_eq!(v6.ip_entries, vec!["fd00::1".to_string()]);
    }
}
