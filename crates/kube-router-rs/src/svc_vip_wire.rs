//! Maps live Services + EndpointSlices to `kr_routing::service_vips::SvcVip` for
//! BGP VIP advertisement (the routing controller's advertise path).

use k8s_openapi::api::core::v1::Service as K8sService;
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kr_routing::service_vips::SvcVip;
use kube::runtime::reflector::store::Store;

const ADV_CLUSTER_ANN: &str = "kube-router.io/service.advertise.clusterip";
const ADV_EXTERNAL_ANN: &str = "kube-router.io/service.advertise.externalip";
const ADV_LB_ANN: &str = "kube-router.io/service.advertise.loadbalancer";
const SKIP_LB_ANN: &str = "kube-router.io/service.skiplbips";
const LOCAL_ANN: &str = "kube-router.io/service.local";
const SERVICE_NAME_LABEL: &str = "kubernetes.io/service-name";

fn ann_bool(anns: &std::collections::BTreeMap<String, String>, key: &str) -> Option<bool> {
    anns.get(key).map(|v| v == "true")
}

/// Whether any EndpointSlice for `namespace/name` has a ready endpoint hosted on
/// `local_node`.
fn has_local_endpoints(
    slices: &[EndpointSlice],
    namespace: &str,
    name: &str,
    local_node: &str,
) -> bool {
    slices.iter().any(|slice| {
        slice.metadata.namespace.as_deref() == Some(namespace)
            && slice
                .metadata
                .labels
                .as_ref()
                .and_then(|l| l.get(SERVICE_NAME_LABEL))
                .map(String::as_str)
                == Some(name)
            && slice.endpoints.iter().flatten().any(|ep| {
                ep.node_name.as_deref() == Some(local_node)
                    && ep.conditions.as_ref().and_then(|c| c.ready).unwrap_or(true)
            })
    })
}

/// Project Services + EndpointSlices to the VIP-advertisement view.
pub fn map_svc_vips(
    services: &[K8sService],
    slices: &[EndpointSlice],
    local_node: &str,
) -> Vec<SvcVip> {
    let mut out = Vec::new();
    for svc in services {
        let (Some(namespace), Some(name)) = (
            svc.metadata.namespace.as_deref(),
            svc.metadata.name.as_deref(),
        ) else {
            continue;
        };
        let Some(spec) = svc.spec.as_ref() else {
            continue;
        };
        if spec.type_.as_deref() == Some("ExternalName") {
            continue;
        }

        let parse = |v: &[String]| -> Vec<std::net::IpAddr> {
            v.iter().filter_map(|s| s.parse().ok()).collect()
        };
        let mut cluster = spec
            .cluster_ips
            .clone()
            .unwrap_or_else(|| spec.cluster_ip.clone().into_iter().collect());
        cluster.retain(|ip| ip != "None" && !ip.is_empty());
        let lb_ips = svc
            .status
            .as_ref()
            .and_then(|s| s.load_balancer.as_ref())
            .and_then(|lb| lb.ingress.as_ref())
            .map(|ing| {
                ing.iter()
                    .filter_map(|i| i.ip.clone())
                    .filter_map(|ip| ip.parse().ok())
                    .collect()
            })
            .unwrap_or_default();

        let anns = svc.metadata.annotations.clone().unwrap_or_default();
        let local_ann = anns.get(LOCAL_ANN).map(String::as_str) == Some("true");

        out.push(SvcVip {
            cluster_ips: parse(&cluster),
            external_ips: parse(&spec.external_ips.clone().unwrap_or_default()),
            lb_ips,
            internal_traffic_local: spec.internal_traffic_policy.as_deref() == Some("Local"),
            external_traffic_local: local_ann
                || spec.external_traffic_policy.as_deref() == Some("Local"),
            has_local_endpoints: has_local_endpoints(slices, namespace, name, local_node),
            adv_cluster: ann_bool(&anns, ADV_CLUSTER_ANN),
            adv_external: ann_bool(&anns, ADV_EXTERNAL_ANN),
            adv_lb: ann_bool(&anns, ADV_LB_ANN),
            skip_lb_ips: anns.contains_key(SKIP_LB_ANN),
        });
    }
    out
}

/// `SvcVip` snapshots from the Service + EndpointSlice reflector stores.
pub struct StoreSvcVipProvider {
    services: Store<K8sService>,
    slices: Store<EndpointSlice>,
    local_node: String,
}

impl StoreSvcVipProvider {
    /// Wrap the stores + local node name.
    pub fn new(
        services: Store<K8sService>,
        slices: Store<EndpointSlice>,
        local_node: String,
    ) -> Self {
        Self {
            services,
            slices,
            local_node,
        }
    }

    /// Current VIP-advertisement view.
    pub fn snapshot(&self) -> Vec<SvcVip> {
        let svcs: Vec<K8sService> = self
            .services
            .state()
            .iter()
            .map(|s| (**s).clone())
            .collect();
        let slices: Vec<EndpointSlice> =
            self.slices.state().iter().map(|s| (**s).clone()).collect();
        map_svc_vips(&svcs, &slices, &self.local_node)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::ServiceSpec;
    use k8s_openapi::api::discovery::v1::{Endpoint, EndpointConditions};
    use kube::api::ObjectMeta;
    use std::collections::BTreeMap;

    fn svc(cip: &str, ext_local: bool) -> K8sService {
        K8sService {
            metadata: ObjectMeta {
                namespace: Some("default".into()),
                name: Some("web".into()),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                cluster_ips: Some(vec![cip.into()]),
                external_traffic_policy: ext_local.then(|| "Local".into()),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn slice(node: &str, ready: bool) -> EndpointSlice {
        let mut labels = BTreeMap::new();
        labels.insert(SERVICE_NAME_LABEL.to_string(), "web".to_string());
        EndpointSlice {
            metadata: ObjectMeta {
                namespace: Some("default".into()),
                labels: Some(labels),
                ..Default::default()
            },
            address_type: "IPv4".into(),
            endpoints: Some(vec![Endpoint {
                addresses: vec!["10.244.0.5".into()],
                conditions: Some(EndpointConditions {
                    ready: Some(ready),
                    ..Default::default()
                }),
                node_name: Some(node.into()),
                ..Default::default()
            }]),
            ports: None,
        }
    }

    #[test]
    fn maps_clusterip_and_local_endpoint_presence() {
        let v = map_svc_vips(
            &[svc("10.96.0.10", true)],
            &[slice("node-a", true)],
            "node-a",
        );
        assert_eq!(v.len(), 1);
        assert_eq!(
            v[0].cluster_ips,
            vec!["10.96.0.10".parse::<std::net::IpAddr>().unwrap()]
        );
        assert!(v[0].external_traffic_local);
        assert!(v[0].has_local_endpoints);
    }

    #[test]
    fn endpoint_on_other_node_is_not_local() {
        let v = map_svc_vips(
            &[svc("10.96.0.10", true)],
            &[slice("node-b", true)],
            "node-a",
        );
        assert!(!v[0].has_local_endpoints);
    }

    #[test]
    fn advertise_annotations_parsed() {
        let mut s = svc("10.96.0.10", false);
        s.metadata.annotations = Some(
            [
                (ADV_CLUSTER_ANN.to_string(), "false".to_string()),
                (SKIP_LB_ANN.to_string(), "".to_string()),
            ]
            .into_iter()
            .collect(),
        );
        let v = map_svc_vips(&[s], &[], "node-a");
        assert_eq!(v[0].adv_cluster, Some(false));
        assert!(v[0].skip_lb_ips);
        assert_eq!(v[0].adv_external, None);
    }
}
