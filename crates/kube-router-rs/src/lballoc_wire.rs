//! Wiring that maps live Kubernetes Services to the `kr_lballoc` model and
//! provides the kube-backed Lease election + status update for the LoadBalancer
//! allocator (`--run-loadbalancer`).

use std::net::IpAddr;

use k8s_openapi::api::coordination::v1::{Lease, LeaseSpec};
use k8s_openapi::api::core::v1::{LoadBalancerIngress, Service as K8sService};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::MicroTime;
use k8s_openapi::jiff::Timestamp;
use kr_lballoc::election::{LeaseError, LEASE_DURATION, LEASE_NAME};
use kr_lballoc::model::LbService;
use kr_lballoc::{LbServiceProvider, LeaseBackend, StatusUpdater};
use kube::api::{ObjectMeta, PostParams};
use kube::runtime::reflector::store::Store;
use kube::{Api, Client};

/// Map a Kubernetes Service into the allocator's projected view.
pub fn map_lb_service(svc: &K8sService) -> Option<LbService> {
    let namespace = svc.metadata.namespace.clone()?;
    let name = svc.metadata.name.clone()?;
    let spec = svc.spec.as_ref()?;

    let want_v4 = spec
        .ip_families
        .as_ref()
        .is_some_and(|f| f.iter().any(|x| x == "IPv4"));
    let want_v6 = spec
        .ip_families
        .as_ref()
        .is_some_and(|f| f.iter().any(|x| x == "IPv6"));
    let require_dual = spec.ip_family_policy.as_deref() == Some("RequireDualStack");

    let external_ips = spec
        .external_ips
        .clone()
        .unwrap_or_default()
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();
    let ingress_ips = svc
        .status
        .as_ref()
        .and_then(|s| s.load_balancer.as_ref())
        .and_then(|lb| lb.ingress.as_ref())
        .map(|ing| {
            ing.iter()
                .filter_map(|i| i.ip.as_ref())
                .filter_map(|ip| ip.parse::<IpAddr>().ok())
                .collect()
        })
        .unwrap_or_default();

    Some(LbService {
        namespace,
        name,
        is_loadbalancer: spec.type_.as_deref() == Some("LoadBalancer"),
        loadbalancer_class: spec.load_balancer_class.clone(),
        want_v4,
        want_v6,
        require_dual,
        external_ips,
        ingress_ips,
    })
}

/// `LbServiceProvider` backed by the Service reflector store.
pub struct StoreLbServiceProvider {
    services: Store<K8sService>,
}

impl StoreLbServiceProvider {
    /// Wrap the Service store.
    pub fn new(services: Store<K8sService>) -> Self {
        Self { services }
    }
}

impl LbServiceProvider for StoreLbServiceProvider {
    fn services(&self) -> Vec<LbService> {
        self.services
            .state()
            .iter()
            .filter_map(|s| map_lb_service(s))
            .collect()
    }
}

/// `StatusUpdater` that appends ingress IPs to a Service's status subresource.
pub struct KubeStatusUpdater {
    client: Client,
}

impl KubeStatusUpdater {
    /// New updater over a client.
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl StatusUpdater for KubeStatusUpdater {
    async fn append_ingress(
        &self,
        namespace: &str,
        name: &str,
        ips: &[IpAddr],
    ) -> Result<(), kr_lballoc::controller::StatusError> {
        use kr_lballoc::controller::StatusError;
        let api: Api<K8sService> = Api::namespaced(self.client.clone(), namespace);
        // Read-modify-write the status subresource (RetryOnConflict-equivalent:
        // a single attempt; the reconcile loop retries on the next tick).
        let mut svc = api
            .get_status(name)
            .await
            .map_err(|e| StatusError(e.to_string()))?;
        let status = svc.status.get_or_insert_with(Default::default);
        let lb = status.load_balancer.get_or_insert_with(Default::default);
        let ingress = lb.ingress.get_or_insert_with(Vec::new);
        for ip in ips {
            ingress.push(LoadBalancerIngress {
                ip: Some(ip.to_string()),
                ..Default::default()
            });
        }
        api.replace_status(name, &PostParams::default(), &svc)
            .await
            .map_err(|e| StatusError(e.to_string()))?;
        Ok(())
    }
}

/// `LeaseBackend` using a coordination `Lease` for cluster-wide single-allocator
/// election (mirrors the Go `LeaseLock`).
pub struct KubeLease {
    api: Api<Lease>,
    identity: String,
}

impl KubeLease {
    /// New Lease backend in `namespace` identified by `identity` (pod name).
    pub fn new(client: Client, namespace: &str, identity: String) -> Self {
        Self {
            api: Api::namespaced(client, namespace),
            identity,
        }
    }
}

#[async_trait::async_trait]
impl LeaseBackend for KubeLease {
    async fn acquire_or_renew(&self) -> Result<bool, LeaseError> {
        let now = Timestamp::now();
        let existing = self.api.get_opt(LEASE_NAME).await.map_err(err)?;

        let held_by_other_and_fresh = existing.as_ref().is_some_and(|l| {
            let spec = l.spec.as_ref();
            let holder = spec.and_then(|s| s.holder_identity.as_deref());
            match holder {
                None => false,
                Some(h) if h == self.identity => false,
                Some(_) => {
                    // Fresh if renewTime + leaseDuration is still in the future.
                    spec.and_then(|s| s.renew_time.as_ref()).is_some_and(|rt| {
                        let dur = spec
                            .and_then(|s| s.lease_duration_seconds)
                            .unwrap_or(LEASE_DURATION.as_secs() as i32);
                        now.as_second() - rt.0.as_second() < dur as i64
                    })
                }
            }
        });
        if held_by_other_and_fresh {
            return Ok(false);
        }

        let spec = LeaseSpec {
            holder_identity: Some(self.identity.clone()),
            lease_duration_seconds: Some(LEASE_DURATION.as_secs() as i32),
            renew_time: Some(MicroTime(now)),
            acquire_time: Some(MicroTime(now)),
            ..Default::default()
        };
        if let Some(mut lease) = existing {
            // Preserve resourceVersion (via the fetched object) and update in place
            // — needs only the `update` verb, matching upstream's leaderelection.
            lease.spec = Some(spec);
            self.api
                .replace(LEASE_NAME, &PostParams::default(), &lease)
                .await
                .map_err(err)?;
        } else {
            let lease = Lease {
                metadata: ObjectMeta {
                    name: Some(LEASE_NAME.to_string()),
                    ..Default::default()
                },
                spec: Some(spec),
            };
            self.api
                .create(&PostParams::default(), &lease)
                .await
                .map_err(err)?;
        }
        Ok(true)
    }
}

fn err(e: kube::Error) -> LeaseError {
    LeaseError(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{ServiceSpec, ServiceStatus};

    fn svc(type_: &str, class: Option<&str>) -> K8sService {
        K8sService {
            metadata: ObjectMeta {
                namespace: Some("default".into()),
                name: Some("web".into()),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                type_: Some(type_.into()),
                load_balancer_class: class.map(String::from),
                ip_families: Some(vec!["IPv4".into()]),
                external_ips: Some(vec!["203.0.113.5".into()]),
                ..Default::default()
            }),
            status: Some(ServiceStatus::default()),
        }
    }

    #[test]
    fn maps_loadbalancer_fields() {
        let m = map_lb_service(&svc("LoadBalancer", Some("kube-router"))).unwrap();
        assert!(m.is_loadbalancer);
        assert_eq!(m.loadbalancer_class.as_deref(), Some("kube-router"));
        assert!(m.want_v4 && !m.want_v6);
        assert_eq!(
            m.external_ips,
            vec!["203.0.113.5".parse::<IpAddr>().unwrap()]
        );
        assert!(m.ingress_ips.is_empty());
    }

    #[test]
    fn maps_clusterip_as_non_loadbalancer() {
        let m = map_lb_service(&svc("ClusterIP", None)).unwrap();
        assert!(!m.is_loadbalancer);
    }
}
