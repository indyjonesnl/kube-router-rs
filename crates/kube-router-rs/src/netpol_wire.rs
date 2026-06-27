//! Wiring that maps live Kubernetes NetworkPolicy/Pod/Namespace objects to the
//! `kr_netpol` projected model and runs the firewall controller (`--run-firewall`).

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::{Namespace as K8sNamespace, Pod as K8sPod};
use k8s_openapi::api::networking::v1::{NetworkPolicy as K8sNetworkPolicy, NetworkPolicyPeer};
use kr_netpol::model::LabelSelector;
use kr_netpol::{
    Namespace, NetworkPolicy, Peer, Pod, PolicySource, PolicyTypes, PolicyWorld, PortSpec, Rule,
};
use kube::runtime::reflector::store::Store;

fn match_labels(
    sel: &k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector,
) -> LabelSelector {
    sel.match_labels.clone().unwrap_or_default()
}

fn map_peer(p: &NetworkPolicyPeer) -> Option<Peer> {
    if let Some(block) = &p.ip_block {
        let cidr = block.cidr.parse().ok()?;
        let except = block
            .except
            .clone()
            .unwrap_or_default()
            .iter()
            .filter_map(|c| c.parse().ok())
            .collect();
        return Some(Peer::IpBlock { cidr, except });
    }
    Some(Peer::Selector {
        namespace_selector: p.namespace_selector.as_ref().map(match_labels),
        pod_selector: p.pod_selector.as_ref().map(match_labels),
    })
}

fn map_ports(
    ports: &Option<Vec<k8s_openapi::api::networking::v1::NetworkPolicyPort>>,
) -> Vec<PortSpec> {
    let Some(ports) = ports else {
        return Vec::new();
    };
    ports
        .iter()
        .map(|p| {
            let protocol = p
                .protocol
                .clone()
                .unwrap_or_else(|| "TCP".into())
                .to_lowercase();
            // Numeric ports only; named ports are a follow-up.
            let port = match &p.port {
                Some(k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(n)) => {
                    u16::try_from(*n).ok()
                }
                _ => None,
            };
            PortSpec { protocol, port }
        })
        .collect()
}

/// Map a Kubernetes NetworkPolicy to the projected model.
pub fn map_policy(np: &K8sNetworkPolicy) -> Option<NetworkPolicy> {
    let namespace = np.metadata.namespace.clone()?;
    let name = np.metadata.name.clone()?;
    let spec = np.spec.as_ref()?;

    let types: Vec<String> = spec.policy_types.clone().unwrap_or_default();
    let has_egress_rules = spec.egress.as_ref().is_some_and(|e| !e.is_empty());
    let ingress = types.iter().any(|t| t == "Ingress") || types.is_empty();
    let egress = types.iter().any(|t| t == "Egress") || (types.is_empty() && has_egress_rules);

    let ingress_rules = spec
        .ingress
        .clone()
        .unwrap_or_default()
        .iter()
        .map(|r| Rule {
            peers: r
                .from
                .clone()
                .unwrap_or_default()
                .iter()
                .filter_map(map_peer)
                .collect(),
            ports: map_ports(&r.ports),
        })
        .collect();
    let egress_rules = spec
        .egress
        .clone()
        .unwrap_or_default()
        .iter()
        .map(|r| Rule {
            peers: r
                .to
                .clone()
                .unwrap_or_default()
                .iter()
                .filter_map(map_peer)
                .collect(),
            ports: map_ports(&r.ports),
        })
        .collect();

    Some(NetworkPolicy {
        namespace,
        name,
        pod_selector: spec
            .pod_selector
            .as_ref()
            .map(match_labels)
            .unwrap_or_default(),
        policy_types: PolicyTypes { ingress, egress },
        ingress: ingress_rules,
        egress: egress_rules,
    })
}

/// Map a Kubernetes Pod to the projected model (skips pods without an IP).
pub fn map_pod(pod: &K8sPod) -> Option<Pod> {
    let namespace = pod.metadata.namespace.clone()?;
    let name = pod.metadata.name.clone()?;
    let status = pod.status.as_ref();
    let ips: Vec<std::net::IpAddr> = status
        .and_then(|s| s.pod_ips.as_ref())
        .map(|v| v.iter().filter_map(|p| p.ip.parse().ok()).collect())
        .or_else(|| {
            status
                .and_then(|s| s.pod_ip.as_ref())
                .and_then(|ip| ip.parse().ok())
                .map(|ip| vec![ip])
        })
        .unwrap_or_default();
    let spec = pod.spec.as_ref();
    Some(Pod {
        namespace,
        name,
        labels: pod.metadata.labels.clone().unwrap_or_default(),
        ips,
        node_name: spec.and_then(|s| s.node_name.clone()).unwrap_or_default(),
        host_network: spec.and_then(|s| s.host_network).unwrap_or(false),
    })
}

/// Map a Kubernetes Namespace to the projected model.
pub fn map_namespace(ns: &K8sNamespace) -> Option<Namespace> {
    Some(Namespace {
        name: ns.metadata.name.clone()?,
        labels: ns.metadata.labels.clone().unwrap_or_default(),
    })
}

/// `PolicySource` backed by the NetworkPolicy/Pod/Namespace reflector stores.
pub struct StorePolicySource {
    policies: Store<K8sNetworkPolicy>,
    pods: Store<K8sPod>,
    namespaces: Store<K8sNamespace>,
}

impl StorePolicySource {
    /// Wrap the three stores.
    pub fn new(
        policies: Store<K8sNetworkPolicy>,
        pods: Store<K8sPod>,
        namespaces: Store<K8sNamespace>,
    ) -> Self {
        Self {
            policies,
            pods,
            namespaces,
        }
    }
}

impl PolicySource for StorePolicySource {
    fn snapshot(&self) -> PolicyWorld {
        PolicyWorld {
            policies: self
                .policies
                .state()
                .iter()
                .filter_map(|p| map_policy(p))
                .collect(),
            pods: self
                .pods
                .state()
                .iter()
                .filter_map(|p| map_pod(p))
                .collect(),
            namespaces: self
                .namespaces
                .state()
                .iter()
                .filter_map(|n| map_namespace(n))
                .collect(),
        }
    }
}

/// Helper to keep `BTreeMap` import used even if mapping changes.
#[allow(dead_code)]
fn _assert_label_type(_: &BTreeMap<String, String>) {}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::networking::v1::{NetworkPolicyIngressRule, NetworkPolicySpec};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector as K8sSel;
    use kube::api::ObjectMeta;

    fn sel(pairs: &[(&str, &str)]) -> K8sSel {
        K8sSel {
            match_labels: Some(
                pairs
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            ),
            ..Default::default()
        }
    }

    #[test]
    fn maps_ingress_policy_with_pod_selector_peer() {
        let np = K8sNetworkPolicy {
            metadata: ObjectMeta {
                namespace: Some("default".into()),
                name: Some("web".into()),
                ..Default::default()
            },
            spec: Some(NetworkPolicySpec {
                pod_selector: Some(sel(&[("app", "web")])),
                policy_types: Some(vec!["Ingress".into()]),
                ingress: Some(vec![NetworkPolicyIngressRule {
                    from: Some(vec![NetworkPolicyPeer {
                        pod_selector: Some(sel(&[("app", "client")])),
                        ..Default::default()
                    }]),
                    ports: None,
                }]),
                ..Default::default()
            }),
        };
        let m = map_policy(&np).unwrap();
        assert_eq!(m.name, "web");
        assert!(m.policy_types.ingress && !m.policy_types.egress);
        assert_eq!(m.ingress.len(), 1);
        assert_eq!(m.ingress[0].peers.len(), 1);
    }

    #[test]
    fn ipblock_peer_maps_to_cidr_and_except() {
        let peer = NetworkPolicyPeer {
            ip_block: Some(k8s_openapi::api::networking::v1::IPBlock {
                cidr: "10.0.0.0/8".into(),
                except: Some(vec!["10.1.0.0/16".into()]),
            }),
            ..Default::default()
        };
        match map_peer(&peer).unwrap() {
            Peer::IpBlock { cidr, except } => {
                assert_eq!(cidr.to_string(), "10.0.0.0/8");
                assert_eq!(except.len(), 1);
            }
            _ => panic!("expected ipblock"),
        }
    }
}
