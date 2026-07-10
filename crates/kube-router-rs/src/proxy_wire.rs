//! Wiring that maps live Kubernetes Service + EndpointSlice objects to the
//! `kr_proxy` model and runs the service-proxy controller (`--run-service-proxy`).
//!
//! MVP scope: ClusterIP services (ExternalName/headless skipped). Endpoint slices
//! are joined to a service by the `kubernetes.io/service-name` label; the service
//! port is matched to slice ports by name (or the single port when unnamed).

use std::net::IpAddr;

use k8s_openapi::api::core::v1::Service as K8sService;
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kr_proxy::model::{EndpointInfo, Protocol, SchedFlags, Scheduler, ServiceInfo};
use kr_proxy::ServiceProvider;
use kube::runtime::reflector::store::Store;

const SCHEDULER_ANNOTATION: &str = "kube-router.io/service.scheduler";
const SCHEDFLAGS_ANNOTATION: &str = "kube-router.io/service.schedflags";
const DSR_ANNOTATION: &str = "kube-router.io/service.dsr";
const LOCAL_ANNOTATION: &str = "kube-router.io/service.local";
const HAIRPIN_ANNOTATION: &str = "kube-router.io/service.hairpin";
const HAIRPIN_EXTERNALIPS_ANNOTATION: &str = "kube-router.io/service.hairpin.externalips";
const SERVICE_NAME_LABEL: &str = "kubernetes.io/service-name";

fn parse_ips(v: &[String]) -> Vec<IpAddr> {
    v.iter().filter_map(|s| s.parse().ok()).collect()
}

/// Endpoints (from slices) matching service `name` in `namespace`, for service
/// port `port_name`. `port_name` empty matches the slice's single/first port.
fn endpoints_for(
    slices: &[EndpointSlice],
    namespace: &str,
    name: &str,
    port_name: &str,
    local_node: &str,
) -> Vec<EndpointInfo> {
    let mut out = Vec::new();
    for slice in slices {
        if slice.metadata.namespace.as_deref() != Some(namespace) {
            continue;
        }
        if slice
            .metadata
            .labels
            .as_ref()
            .and_then(|l| l.get(SERVICE_NAME_LABEL))
            .map(String::as_str)
            != Some(name)
        {
            continue;
        }
        // Resolve the slice port matching the service port name.
        let ports = slice.ports.clone().unwrap_or_default();
        let port = ports
            .iter()
            .find(|p| port_name.is_empty() || p.name.as_deref() == Some(port_name))
            .or_else(|| ports.first())
            .and_then(|p| p.port);
        let Some(port) = port.and_then(|p| u16::try_from(p).ok()) else {
            continue;
        };
        for ep in slice.endpoints.clone().unwrap_or_default() {
            let ready = ep.conditions.as_ref().and_then(|c| c.ready).unwrap_or(true);
            let is_local = ep.node_name.as_deref() == Some(local_node);
            for addr in &ep.addresses {
                if let Ok(ip) = addr.parse::<IpAddr>() {
                    out.push(EndpointInfo {
                        ip,
                        port,
                        is_local,
                        ready,
                    });
                }
            }
        }
    }
    out
}

/// Map Services + EndpointSlices to `(ServiceInfo, endpoints)` (one per Service
/// port). Skips ExternalName and headless (clusterIP None) services.
pub fn map_services(
    services: &[K8sService],
    slices: &[EndpointSlice],
    local_node: &str,
) -> Vec<(ServiceInfo, Vec<EndpointInfo>)> {
    let mut out = Vec::new();
    for svc in services {
        let (Some(namespace), Some(name)) =
            (svc.metadata.namespace.clone(), svc.metadata.name.clone())
        else {
            continue;
        };
        let Some(spec) = svc.spec.as_ref() else {
            continue;
        };
        if spec.type_.as_deref() == Some("ExternalName") {
            continue;
        }
        let mut cluster_ips = spec
            .cluster_ips
            .clone()
            .unwrap_or_else(|| spec.cluster_ip.clone().into_iter().collect());
        cluster_ips.retain(|ip| ip != "None" && !ip.is_empty());
        let cluster_ips = parse_ips(&cluster_ips);
        if cluster_ips.is_empty() {
            continue; // headless / no ClusterIP
        }

        let ann = svc.metadata.annotations.clone().unwrap_or_default();
        let scheduler = ann
            .get(SCHEDULER_ANNOTATION)
            .map(|s| Scheduler::parse(s))
            .unwrap_or_default();
        // Scheduler flags are only honored for the Maglev scheduler (upstream gates
        // `parseSchedFlags` on `scheduler == IpvsMaglevHashing`).
        let sched_flags = if scheduler == Scheduler::Mh {
            ann.get(SCHEDFLAGS_ANNOTATION)
                .map(|s| SchedFlags::parse(s))
                .unwrap_or_default()
        } else {
            SchedFlags::default()
        };
        let dsr = ann.contains_key(DSR_ANNOTATION);
        let hairpin = ann.contains_key(HAIRPIN_ANNOTATION);
        let hairpin_external_ips = ann.contains_key(HAIRPIN_EXTERNALIPS_ANNOTATION);
        let health_check_node_port = spec
            .health_check_node_port
            .and_then(|n| u16::try_from(n).ok());
        // Legacy annotation forces both internal and external traffic to local
        // endpoints (upstream `kube-router.io/service.local: "true"`).
        let local_ann = ann.get(LOCAL_ANNOTATION).map(String::as_str) == Some("true");
        let internal_traffic_local =
            local_ann || spec.internal_traffic_policy.as_deref() == Some("Local");
        let external_traffic_local =
            local_ann || spec.external_traffic_policy.as_deref() == Some("Local");
        // LoadBalancer ingress IPs from status (assigned by an external LB / lballoc).
        let load_balancer_ips: Vec<IpAddr> = svc
            .status
            .as_ref()
            .and_then(|s| s.load_balancer.as_ref())
            .and_then(|lb| lb.ingress.as_ref())
            .map(|ing| {
                ing.iter()
                    .filter_map(|i| i.ip.as_ref())
                    .filter_map(|ip| ip.parse().ok())
                    .collect()
            })
            .unwrap_or_default();
        let (session_affinity, affinity_timeout) = match spec.session_affinity.as_deref() {
            Some("ClientIP") => (
                true,
                spec.session_affinity_config
                    .as_ref()
                    .and_then(|c| c.client_ip.as_ref())
                    .and_then(|c| c.timeout_seconds)
                    .and_then(|t| u32::try_from(t).ok())
                    .unwrap_or(10800),
            ),
            _ => (false, 0),
        };

        for sp in spec.ports.clone().unwrap_or_default() {
            let Ok(port) = u16::try_from(sp.port) else {
                continue;
            };
            let port_name = sp.name.clone().unwrap_or_default();
            let info = ServiceInfo {
                namespace: namespace.clone(),
                name: name.clone(),
                port_name: port_name.clone(),
                protocol: Protocol::parse(sp.protocol.as_deref().unwrap_or("TCP")),
                port,
                node_port: sp.node_port.and_then(|n| u16::try_from(n).ok()),
                cluster_ips: cluster_ips.clone(),
                external_ips: parse_ips(&spec.external_ips.clone().unwrap_or_default()),
                load_balancer_ips: load_balancer_ips.clone(),
                scheduler,
                sched_flags,
                session_affinity,
                affinity_timeout,
                dsr,
                internal_traffic_local,
                external_traffic_local,
                hairpin,
                hairpin_external_ips,
                health_check_node_port,
            };
            let eps = endpoints_for(slices, &namespace, &name, &port_name, local_node);
            out.push((info, eps));
        }
    }
    out
}

/// `ServiceProvider` backed by the Service + EndpointSlice reflector stores.
pub struct StoreServiceProvider {
    services: Store<K8sService>,
    slices: Store<EndpointSlice>,
    local_node: String,
}

impl StoreServiceProvider {
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
}

impl ServiceProvider for StoreServiceProvider {
    fn services(&self) -> Vec<(ServiceInfo, Vec<EndpointInfo>)> {
        let svcs: Vec<K8sService> = self
            .services
            .state()
            .iter()
            .map(|s| (**s).clone())
            .collect();
        let slices: Vec<EndpointSlice> =
            self.slices.state().iter().map(|s| (**s).clone()).collect();
        map_services(&svcs, &slices, &self.local_node)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{ServicePort, ServiceSpec};
    use k8s_openapi::api::discovery::v1::{Endpoint, EndpointConditions, EndpointPort};
    use kube::api::ObjectMeta;
    use std::collections::BTreeMap;

    fn slice(ns: &str, svc: &str, port: i32, addr: &str, node: &str, ready: bool) -> EndpointSlice {
        let mut labels = BTreeMap::new();
        labels.insert(SERVICE_NAME_LABEL.to_string(), svc.to_string());
        EndpointSlice {
            metadata: ObjectMeta {
                namespace: Some(ns.into()),
                labels: Some(labels),
                ..Default::default()
            },
            address_type: "IPv4".into(),
            endpoints: Some(vec![Endpoint {
                addresses: vec![addr.into()],
                conditions: Some(EndpointConditions {
                    ready: Some(ready),
                    ..Default::default()
                }),
                node_name: Some(node.into()),
                ..Default::default()
            }]),
            ports: Some(vec![EndpointPort {
                name: Some("http".into()),
                port: Some(port),
                ..Default::default()
            }]),
        }
    }

    fn clusterip_service(ns: &str, name: &str, cip: &str) -> K8sService {
        K8sService {
            metadata: ObjectMeta {
                namespace: Some(ns.into()),
                name: Some(name.into()),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                cluster_ips: Some(vec![cip.into()]),
                ports: Some(vec![ServicePort {
                    name: Some("http".into()),
                    port: 80,
                    protocol: Some("TCP".into()),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn maps_clusterip_service_with_ready_endpoints() {
        let svcs = vec![clusterip_service("default", "web", "10.96.0.10")];
        let slices = vec![
            slice("default", "web", 8080, "10.244.0.5", "node-a", true),
            slice("default", "web", 8080, "10.244.1.5", "node-b", false),
        ];
        let mapped = map_services(&svcs, &slices, "node-a");
        assert_eq!(mapped.len(), 1);
        let (info, eps) = &mapped[0];
        assert_eq!(info.port, 80);
        assert_eq!(
            info.cluster_ips,
            vec!["10.96.0.10".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(eps.len(), 2);
        assert!(eps
            .iter()
            .any(|e| e.ip.to_string() == "10.244.0.5" && e.ready && e.is_local));
        assert!(eps
            .iter()
            .any(|e| e.ip.to_string() == "10.244.1.5" && !e.ready));
    }

    #[test]
    fn headless_and_externalname_skipped() {
        let mut headless = clusterip_service("default", "h", "None");
        headless.spec.as_mut().unwrap().cluster_ips = Some(vec!["None".into()]);
        let mut extname = clusterip_service("default", "e", "10.96.0.11");
        extname.spec.as_mut().unwrap().type_ = Some("ExternalName".into());
        let mapped = map_services(&[headless, extname], &[], "node-a");
        assert!(mapped.is_empty());
    }

    #[test]
    fn traffic_policy_and_loadbalancer_ingress_mapped() {
        use k8s_openapi::api::core::v1::{LoadBalancerIngress, LoadBalancerStatus, ServiceStatus};
        let mut svc = clusterip_service("default", "web", "10.96.0.10");
        {
            let spec = svc.spec.as_mut().unwrap();
            spec.internal_traffic_policy = Some("Local".into());
            spec.external_traffic_policy = Some("Local".into());
            spec.external_ips = Some(vec!["203.0.113.7".into()]);
        }
        svc.status = Some(ServiceStatus {
            load_balancer: Some(LoadBalancerStatus {
                ingress: Some(vec![LoadBalancerIngress {
                    ip: Some("198.51.100.9".into()),
                    ..Default::default()
                }]),
            }),
            ..Default::default()
        });
        let info = &map_services(&[svc], &[], "node-a")[0].0;
        assert!(info.internal_traffic_local);
        assert!(info.external_traffic_local);
        assert_eq!(
            info.external_ips,
            vec!["203.0.113.7".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            info.load_balancer_ips,
            vec!["198.51.100.9".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn legacy_local_annotation_forces_both_local() {
        let mut svc = clusterip_service("default", "web", "10.96.0.10");
        svc.metadata.annotations = Some(
            [(LOCAL_ANNOTATION.to_string(), "true".to_string())]
                .into_iter()
                .collect(),
        );
        let info = &map_services(&[svc], &[], "node-a")[0].0;
        assert!(info.internal_traffic_local);
        assert!(info.external_traffic_local);
    }

    #[test]
    fn scheduler_annotation_parsed() {
        let mut svc = clusterip_service("default", "web", "10.96.0.10");
        svc.metadata.annotations = Some(
            [(SCHEDULER_ANNOTATION.to_string(), "lc".to_string())]
                .into_iter()
                .collect(),
        );
        let mapped = map_services(&[svc], &[], "node-a");
        assert_eq!(mapped[0].0.scheduler, Scheduler::Lc);
    }

    #[test]
    fn hairpin_externalips_annotation_parsed() {
        let mut svc = clusterip_service("default", "web", "10.96.0.10");
        svc.metadata.annotations = Some(
            [(HAIRPIN_EXTERNALIPS_ANNOTATION.to_string(), "".to_string())]
                .into_iter()
                .collect(),
        );
        assert!(
            map_services(&[svc], &[], "node-a")[0]
                .0
                .hairpin_external_ips
        );
        // Absent by default.
        let plain = clusterip_service("default", "web2", "10.96.0.11");
        assert!(
            !map_services(&[plain], &[], "node-a")[0]
                .0
                .hairpin_external_ips
        );
    }

    #[test]
    fn schedflags_parsed_only_for_maglev() {
        let ann = |sched: &str| {
            let mut svc = clusterip_service("default", "web", "10.96.0.10");
            svc.metadata.annotations = Some(
                [
                    (SCHEDULER_ANNOTATION.to_string(), sched.to_string()),
                    (
                        SCHEDFLAGS_ANNOTATION.to_string(),
                        "flag-1,flag-2".to_string(),
                    ),
                ]
                .into_iter()
                .collect(),
            );
            map_services(&[svc], &[], "node-a")[0].0.sched_flags
        };
        // Maglev: flags honored.
        assert_eq!(
            ann("mh"),
            SchedFlags {
                flag1: true,
                flag2: true,
                flag3: false
            }
        );
        // Non-Maglev scheduler: flags ignored (upstream gates on the scheduler).
        assert_eq!(ann("rr"), SchedFlags::default());
    }
}
