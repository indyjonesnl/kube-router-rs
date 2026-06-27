//! Service → IPVS sync, mirroring `service_endpoints_sync.go`: each Service VIP
//! becomes an IPVS virtual service bound to `kube-dummy-if`, with one destination
//! per ready endpoint. Reconciles desired vs applied (add/remove services,
//! destinations, and VIP bindings).

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ipnet::IpNet;
use kr_netlink_sys::NetlinkOps;
use kr_observability::{Component, HealthState, ServiceMetrics, ServiceStatSample};

use crate::graceful::GracefulQueue;
use crate::hairpin::{self, NatOps};
use crate::ipvs::{IpvsDestination, IpvsOps, IpvsService};
use crate::model::{EndpointInfo, Protocol, ServiceInfo};
use crate::nodeport_hc::{active_local_counts, NodePortHealthChecks};
use crate::validation::validate_external_ip;

/// Dummy interface VIPs are bound to.
pub const DUMMY_IF: &str = "kube-dummy-if";

/// Masquerade configuration for IPVS SNAT.
#[derive(Debug, Default, Clone)]
pub struct MasqueradeCfg {
    /// `--masquerade-all`.
    pub all: bool,
    /// Append `--random-fully` (kernel supports it).
    pub random_fully: bool,
    /// Primary node IP per family, as `(ipv6, ip)`.
    pub primary: Vec<(bool, IpAddr)>,
    /// Local pod CIDRs (always masqueraded leaving the pod network).
    pub pod_cidrs: Vec<String>,
}

/// Parse a `lo-hi` port range (e.g. `30000-32767`).
pub fn parse_port_range(s: &str) -> Option<(u16, u16)> {
    let (lo, hi) = s.split_once('-')?;
    Some((lo.trim().parse().ok()?, hi.trim().parse().ok()?))
}

/// External/LoadBalancer IP validation ranges (from the service-proxy flags).
#[derive(Debug, Default, Clone)]
pub struct ValidationRanges {
    /// `--service-external-ip-range`.
    pub external: Vec<IpNet>,
    /// `--loadbalancer-ip-range`.
    pub loadbalancer: Vec<IpNet>,
    /// `--service-cluster-ip-range`.
    pub cluster: Vec<IpNet>,
    /// `--strict-external-ip-validation`.
    pub strict: bool,
}

/// Supplies the current services + their endpoints (from the informer stores).
pub trait ServiceProvider: Send + Sync {
    /// Snapshot of `(service, endpoints)`.
    fn services(&self) -> Vec<(ServiceInfo, Vec<EndpointInfo>)>;
}

/// Service-sync error.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    /// IPVS failure.
    #[error(transparent)]
    Ipvs(#[from] crate::ipvs::IpvsError),
    /// netlink failure.
    #[error(transparent)]
    Netlink(#[from] kr_netlink_sys::NetlinkError),
    /// Hairpin nat reconciliation failure.
    #[error("hairpin error: {0}")]
    Hairpin(String),
    /// NodePort health-check server failure.
    #[error("nodeport healthcheck error: {0}")]
    NodePort(String),
}

fn prefix_len(ip: IpAddr) -> u8 {
    match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

fn svc_key(s: &IpvsService) -> String {
    format!("{:?}", s.key())
}

fn proto_name(p: Protocol) -> &'static str {
    match p {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        Protocol::Sctp => "sctp",
    }
}

/// Reconciles Kubernetes Services into IPVS + VIP bindings.
pub struct ServiceSync<I: IpvsOps, N: NetlinkOps, P: ServiceProvider> {
    ipvs: I,
    nl: N,
    provider: P,
    sync_period: Duration,
    ranges: ValidationRanges,
    node_ips: Vec<IpAddr>,
    graceful: bool,
    graceful_period: Duration,
    gqueue: GracefulQueue,
    metrics: Option<ServiceMetrics>,
    hairpin_global: bool,
    /// nat handlers for hairpin/masquerade SNAT, as `(ipv6, ops)` per IP family.
    hairpin_nat: Vec<(bool, Arc<dyn NatOps>)>,
    nphc: Option<NodePortHealthChecks>,
    /// Valid NodePort range; ports outside it are skipped.
    node_port_range: Option<(u16, u16)>,
    /// Masquerade config: `(masquerade_all, random_fully, primary IP per family, pod CIDRs)`.
    masquerade: Option<MasqueradeCfg>,
    applied: BTreeMap<String, (IpvsService, Vec<IpvsDestination>)>,
    /// Maps an IPVS service key to its owning `(namespace, name)` for metrics.
    meta: BTreeMap<String, (String, String)>,
    bound_vips: BTreeSet<IpAddr>,
}

impl<I: IpvsOps, N: NetlinkOps, P: ServiceProvider> ServiceSync<I, N, P> {
    /// Construct.
    pub fn new(
        ipvs: I,
        nl: N,
        provider: P,
        sync_period: Duration,
        ranges: ValidationRanges,
    ) -> Self {
        Self {
            ipvs,
            nl,
            provider,
            sync_period,
            ranges,
            node_ips: Vec::new(),
            graceful: false,
            graceful_period: Duration::from_secs(0),
            gqueue: GracefulQueue::new(),
            metrics: None,
            hairpin_global: false,
            hairpin_nat: Vec::new(),
            nphc: None,
            node_port_range: None,
            masquerade: None,
            applied: BTreeMap::new(),
            meta: BTreeMap::new(),
            bound_vips: BTreeSet::new(),
        }
    }

    /// Publish per-service IPVS statistics to the given metric families.
    pub fn with_metrics(mut self, metrics: ServiceMetrics) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Enable hairpin SNAT reconciliation. `global` forces it for all services;
    /// `nat` supplies a nat-table handler per IP family as `(ipv6, ops)`.
    pub fn with_hairpin(mut self, global: bool, nat: Vec<(bool, Arc<dyn NatOps>)>) -> Self {
        self.hairpin_global = global;
        self.hairpin_nat = nat;
        self
    }

    /// Run NodePort health-check servers for `healthCheckNodePort` services.
    pub fn with_nodeport_healthchecks(mut self, nphc: NodePortHealthChecks) -> Self {
        self.nphc = Some(nphc);
        self
    }

    /// Restrict NodePort programming to ports within `--service-node-port-range`.
    pub fn with_node_port_range(mut self, range: Option<(u16, u16)>) -> Self {
        self.node_port_range = range;
        self
    }

    /// Enable masquerade SNAT reconciliation (uses the hairpin nat handlers).
    pub fn with_masquerade(mut self, cfg: MasqueradeCfg) -> Self {
        self.masquerade = Some(cfg);
        self
    }

    /// Set the node IP(s) NodePort services bind on (primary IP, or all local
    /// addresses under `--nodeport-bindon-all-ip`). Empty → NodePort disabled.
    pub fn with_node_ips(mut self, node_ips: Vec<IpAddr>) -> Self {
        self.node_ips = node_ips;
        self
    }

    /// Enable graceful termination: removed endpoints are drained (weight 0) and
    /// only deleted once idle or after `period` (`--ipvs-graceful-termination`).
    pub fn with_graceful(mut self, enabled: bool, period: Duration) -> Self {
        self.graceful = enabled;
        self.graceful_period = period;
        self
    }

    /// One full sync: program IPVS services/destinations for ClusterIPs and bind
    /// VIPs to the dummy interface; remove anything no longer desired.
    pub async fn reconcile(&mut self) -> Result<(), SyncError> {
        self.nl.ensure_dummy_link(DUMMY_IF).await?;

        let mut desired: BTreeMap<String, (IpvsService, Vec<IpvsDestination>)> = BTreeMap::new();
        let mut want_vips: BTreeSet<IpAddr> = BTreeSet::new();
        let mut meta: BTreeMap<String, (String, String)> = BTreeMap::new();
        for (svc, eps) in self.provider.services() {
            let dests = |local_only: bool| -> Vec<IpvsDestination> {
                eps.iter()
                    .filter(|e| e.ready && (!local_only || e.is_local))
                    .map(|e| IpvsDestination {
                        addr: e.ip,
                        port: e.port,
                        weight: 1,
                        tunnel: svc.dsr,
                    })
                    .collect()
            };
            let mut add_vip = |vip: IpAddr, local_only: bool| {
                let isvc = IpvsService {
                    addr: vip,
                    protocol: svc.protocol,
                    port: svc.port,
                    scheduler: svc.scheduler,
                    persistent: svc.session_affinity.then_some(svc.affinity_timeout),
                };
                let key = svc_key(&isvc);
                meta.insert(key.clone(), (svc.namespace.clone(), svc.name.clone()));
                desired.insert(key, (isvc, dests(local_only)));
                want_vips.insert(vip);
            };

            // ClusterIPs follow the internal traffic policy.
            for vip in &svc.cluster_ips {
                add_vip(*vip, svc.internal_traffic_local);
            }
            // External/LB IPs follow the external traffic policy, after validation.
            for vip in &svc.external_ips {
                if validate_external_ip(
                    *vip,
                    &self.ranges.external,
                    &self.ranges.cluster,
                    self.ranges.strict,
                ) {
                    add_vip(*vip, svc.external_traffic_local);
                }
            }
            for vip in &svc.load_balancer_ips {
                if validate_external_ip(
                    *vip,
                    &self.ranges.loadbalancer,
                    &self.ranges.cluster,
                    self.ranges.strict,
                ) {
                    add_vip(*vip, svc.external_traffic_local);
                }
            }

            // NodePort: an IPVS service per node IP on the node port, listening on
            // existing node addresses (no dummy-interface binding). Honors the
            // external traffic policy; Local with no local endpoints is skipped
            // (mirrors `setupNodePortServices`).
            if let Some(np) = svc.node_port {
                // Skip node ports outside the configured range.
                if let Some((lo, hi)) = self.node_port_range {
                    if np < lo || np > hi {
                        continue;
                    }
                }
                let local_only = svc.external_traffic_local;
                let nodeport_dests = dests(local_only);
                if !(local_only && nodeport_dests.is_empty()) {
                    for nip in &self.node_ips {
                        let isvc = IpvsService {
                            addr: *nip,
                            protocol: svc.protocol,
                            port: np,
                            scheduler: svc.scheduler,
                            persistent: svc.session_affinity.then_some(svc.affinity_timeout),
                        };
                        let key = svc_key(&isvc);
                        meta.insert(key.clone(), (svc.namespace.clone(), svc.name.clone()));
                        desired.insert(key, (isvc, nodeport_dests.clone()));
                    }
                }
            }
        }

        // Add/update desired services + destinations.
        for (isvc, dests) in desired.values() {
            self.ipvs.add_service(isvc).await?;
            for d in dests {
                self.ipvs.add_destination(isvc, d).await?;
            }
        }
        // Collect destinations that lost their endpoint and services no longer
        // desired (borrowing `self.applied` here, so do the removals afterward).
        let mut stale_dests: Vec<(IpvsService, IpvsDestination)> = Vec::new();
        for (k, (isvc, dests)) in &desired {
            if let Some((_, prev)) = self.applied.get(k) {
                for old in prev {
                    if !dests
                        .iter()
                        .any(|d| d.addr == old.addr && d.port == old.port)
                    {
                        stale_dests.push((isvc.clone(), old.clone()));
                    }
                }
            }
        }
        let removed_svcs: Vec<IpvsService> = self
            .applied
            .iter()
            .filter(|(k, _)| !desired.contains_key(*k))
            .map(|(_, (isvc, _))| isvc.clone())
            .collect();

        for (isvc, old) in stale_dests {
            self.remove_destination(&isvc, &old).await?;
        }
        for isvc in removed_svcs {
            self.ipvs.del_service(&isvc).await?;
            if isvc.protocol == Protocol::Udp {
                self.ipvs.flush_conntrack_udp(isvc.addr, isvc.port).await?;
            }
        }

        // VIP bindings on the dummy interface.
        for vip in &want_vips {
            if !self.bound_vips.contains(vip) {
                self.nl.addr_add(DUMMY_IF, *vip, prefix_len(*vip)).await?;
            }
        }
        let stale: Vec<IpAddr> = self
            .bound_vips
            .iter()
            .filter(|v| !want_vips.contains(v))
            .copied()
            .collect();
        for vip in stale {
            self.nl.addr_del(DUMMY_IF, vip, prefix_len(vip)).await?;
        }

        self.applied = desired;
        self.bound_vips = want_vips;
        self.meta = meta;

        self.process_graceful_queue().await?;
        self.update_metrics().await?;
        self.sync_hairpin().await?;
        self.sync_masquerade().await?;
        self.sync_nodeport_healthchecks().await?;
        Ok(())
    }

    /// Reconcile IPVS masquerade SNAT rules per family (no-op if disabled).
    async fn sync_masquerade(&self) -> Result<(), SyncError> {
        let Some(cfg) = &self.masquerade else {
            return Ok(());
        };
        for (ipv6, ops) in &self.hairpin_nat {
            let Some((_, primary)) = cfg.primary.iter().find(|(f, _)| f == ipv6) else {
                continue;
            };
            let cidrs: Vec<String> = cfg
                .pod_cidrs
                .iter()
                .filter(|c| c.contains(':') == *ipv6)
                .cloned()
                .collect();
            crate::masquerade::sync_masquerade(
                ops.as_ref(),
                *primary,
                &cidrs,
                cfg.all,
                cfg.random_fully,
            )
            .await
            .map_err(|e| SyncError::Hairpin(e.to_string()))?;
        }
        Ok(())
    }

    /// Reconcile hairpin SNAT rules per configured IP family (no-op if disabled).
    async fn sync_hairpin(&self) -> Result<(), SyncError> {
        if self.hairpin_nat.is_empty() {
            return Ok(());
        }
        let services = self.provider.services();
        for (ipv6, ops) in &self.hairpin_nat {
            let rules = hairpin::hairpin_rules_for_family(&services, self.hairpin_global, *ipv6);
            hairpin::sync_hairpin(ops.as_ref(), &rules)
                .await
                .map_err(|e| SyncError::Hairpin(e.to_string()))?;
        }
        Ok(())
    }

    /// Start/stop NodePort health-check servers from current services.
    async fn sync_nodeport_healthchecks(&mut self) -> Result<(), SyncError> {
        if let Some(nphc) = self.nphc.as_mut() {
            let desired = active_local_counts(&self.provider.services());
            nphc.sync(desired)
                .await
                .map_err(|e| SyncError::NodePort(e.to_string()))?;
        }
        Ok(())
    }

    /// Collect IPVS statistics and publish per-service metrics (no-op if metrics
    /// were not configured). Mirrors the NSC Prometheus collector.
    async fn update_metrics(&self) -> Result<(), SyncError> {
        let Some(metrics) = &self.metrics else {
            return Ok(());
        };
        let stats = self.ipvs.service_stats().await?;
        let samples: Vec<ServiceStatSample> = stats
            .iter()
            .filter_map(|(svc, st)| {
                let (namespace, service) = self.meta.get(&svc_key(svc))?;
                Some(ServiceStatSample {
                    namespace: namespace.clone(),
                    service: service.clone(),
                    vip: svc.addr.to_string(),
                    protocol: proto_name(svc.protocol).into(),
                    port: svc.port,
                    total_connections: st.connections as f64,
                    packets_in: st.packets_in as f64,
                    packets_out: st.packets_out as f64,
                    bytes_in: st.bytes_in as f64,
                    bytes_out: st.bytes_out as f64,
                    cps: st.cps as f64,
                    pps_in: st.pps_in as f64,
                    pps_out: st.pps_out as f64,
                    bps_in: st.bps_in as f64,
                    bps_out: st.bps_out as f64,
                })
            })
            .collect();
        metrics.update(&samples, self.applied.len());
        Ok(())
    }

    /// Remove a destination: under graceful termination, drain it (weight 0) and
    /// queue it; otherwise delete immediately. Flushes UDP conntrack either way.
    async fn remove_destination(
        &mut self,
        svc: &IpvsService,
        dst: &IpvsDestination,
    ) -> Result<(), SyncError> {
        if self.graceful {
            let mut draining = dst.clone();
            draining.weight = 0;
            self.ipvs.update_destination(svc, &draining).await?;
            self.gqueue
                .enqueue(svc.clone(), draining, Instant::now() + self.graceful_period);
        } else {
            self.ipvs.del_destination(svc, dst).await?;
        }
        if svc.protocol == Protocol::Udp {
            self.ipvs.flush_conntrack_udp(svc.addr, svc.port).await?;
        }
        Ok(())
    }

    /// Delete drained destinations that are idle (no connections) or whose grace
    /// period elapsed. A destination re-added in the meantime is dropped from the
    /// queue without deletion (mirrors `gracefulSync`).
    async fn process_graceful_queue(&mut self) -> Result<(), SyncError> {
        if self.gqueue.is_empty() {
            return Ok(());
        }
        let now = Instant::now();
        for p in self.gqueue.take() {
            // Cancel removal if the endpoint became ready again this sync.
            let readded = self
                .applied
                .get(&svc_key(&p.svc))
                .map(|(_, ds)| {
                    ds.iter()
                        .any(|d| d.addr == p.dst.addr && d.port == p.dst.port && d.weight != 0)
                })
                .unwrap_or(false);
            if readded {
                continue;
            }
            let idle = matches!(
                self.ipvs.dest_conn_stats(&p.svc, &p.dst).await?,
                Some((0, 0))
            );
            if idle || now >= p.deadline {
                self.ipvs.del_destination(&p.svc, &p.dst).await?;
            } else {
                self.gqueue.requeue(p);
            }
        }
        Ok(())
    }

    /// Run the sync loop until `stop`, emitting a heartbeat per tick.
    pub async fn run<F>(&mut self, health: Arc<Mutex<HealthState>>, stop: F)
    where
        F: Future<Output = ()>,
    {
        let mut ticker = tokio::time::interval(self.sync_period);
        tokio::pin!(stop);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if let Err(e) = self.reconcile().await {
                        tracing::warn!(error = %e, "service sync failed");
                    }
                    if let Ok(mut h) = health.lock() {
                        h.heartbeat(Component::NetworkServices, Instant::now());
                    }
                }
                _ = &mut stop => break,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipvs::mock::MockIpvs;
    use crate::model::{Protocol, Scheduler};
    use kr_netlink_sys::mock::MockNetlink;
    use std::sync::Mutex as StdMutex;

    fn svc(vip: &str) -> ServiceInfo {
        ServiceInfo {
            namespace: "default".into(),
            name: "web".into(),
            port_name: "http".into(),
            protocol: Protocol::Tcp,
            port: 80,
            node_port: None,
            cluster_ips: vec![vip.parse().unwrap()],
            external_ips: vec![],
            load_balancer_ips: vec![],
            scheduler: Scheduler::Rr,
            session_affinity: false,
            affinity_timeout: 0,
            dsr: false,
            internal_traffic_local: false,
            external_traffic_local: false,
            hairpin: false,
            health_check_node_port: None,
        }
    }
    fn ep(ip: &str, ready: bool) -> EndpointInfo {
        EndpointInfo {
            ip: ip.parse().unwrap(),
            port: 8080,
            is_local: true,
            ready,
        }
    }
    fn ep_remote(ip: &str) -> EndpointInfo {
        EndpointInfo {
            ip: ip.parse().unwrap(),
            port: 8080,
            is_local: false,
            ready: true,
        }
    }

    struct Static(StdMutex<Vec<(ServiceInfo, Vec<EndpointInfo>)>>);
    impl ServiceProvider for Static {
        fn services(&self) -> Vec<(ServiceInfo, Vec<EndpointInfo>)> {
            self.0.lock().unwrap().clone()
        }
    }

    fn isvc(vip: &str) -> IpvsService {
        IpvsService {
            addr: vip.parse().unwrap(),
            protocol: Protocol::Tcp,
            port: 80,
            scheduler: Scheduler::Rr,
            persistent: None,
        }
    }

    #[tokio::test]
    async fn programs_service_ready_endpoints_and_binds_vip() {
        let prov = Static(StdMutex::new(vec![(
            svc("10.96.0.10"),
            vec![
                ep("10.244.0.5", true),
                ep("10.244.1.5", true),
                ep("10.244.2.5", false),
            ],
        )]));
        let mut s = ServiceSync::new(
            MockIpvs::new(),
            MockNetlink::new(),
            prov,
            Duration::from_secs(300),
            ValidationRanges::default(),
        );
        s.reconcile().await.unwrap();

        assert_eq!(s.ipvs.service_count(), 1);
        // only the 2 ready endpoints are destinations.
        assert_eq!(s.ipvs.destinations(&isvc("10.96.0.10")).len(), 2);
        // VIP bound on the dummy interface.
        assert!(s.nl.has_addr(DUMMY_IF, "10.96.0.10".parse().unwrap(), 32));
        assert!(s.nl.has_dummy(DUMMY_IF));
    }

    #[tokio::test]
    async fn endpoint_removal_and_service_removal() {
        let prov = Static(StdMutex::new(vec![(
            svc("10.96.0.10"),
            vec![ep("10.244.0.5", true), ep("10.244.1.5", true)],
        )]));
        let mut s = ServiceSync::new(
            MockIpvs::new(),
            MockNetlink::new(),
            prov,
            Duration::from_secs(300),
            ValidationRanges::default(),
        );
        s.reconcile().await.unwrap();
        assert_eq!(s.ipvs.destinations(&isvc("10.96.0.10")).len(), 2);

        // drop one endpoint
        *s.provider.0.lock().unwrap() = vec![(svc("10.96.0.10"), vec![ep("10.244.0.5", true)])];
        s.reconcile().await.unwrap();
        assert_eq!(s.ipvs.destinations(&isvc("10.96.0.10")).len(), 1);

        // remove the service entirely → ipvs service gone + VIP unbound
        *s.provider.0.lock().unwrap() = vec![];
        s.reconcile().await.unwrap();
        assert_eq!(s.ipvs.service_count(), 0);
        assert!(!s.nl.has_addr(DUMMY_IF, "10.96.0.10".parse().unwrap(), 32));
    }

    #[tokio::test]
    async fn external_ip_programmed_in_range_rejected_out_of_range() {
        let mut svc1 = svc("10.96.0.10");
        svc1.external_ips = vec![
            "203.0.113.5".parse().unwrap(),
            "198.51.100.5".parse().unwrap(),
        ];
        let prov = Static(StdMutex::new(vec![(svc1, vec![ep("10.244.0.5", true)])]));
        let ranges = ValidationRanges {
            external: vec!["203.0.113.0/24".parse().unwrap()],
            cluster: vec!["10.96.0.0/12".parse().unwrap()],
            strict: true,
            ..Default::default()
        };
        let mut s = ServiceSync::new(
            MockIpvs::new(),
            MockNetlink::new(),
            prov,
            Duration::from_secs(300),
            ranges,
        );
        s.reconcile().await.unwrap();
        // ClusterIP + the in-range external IP = 2 services; out-of-range rejected.
        assert_eq!(s.ipvs.service_count(), 2);
        assert!(s.nl.has_addr(DUMMY_IF, "203.0.113.5".parse().unwrap(), 32));
        assert!(!s.nl.has_addr(DUMMY_IF, "198.51.100.5".parse().unwrap(), 32));
    }

    #[tokio::test]
    async fn nodeport_service_bound_on_node_ips_not_dummy() {
        let mut svc1 = svc("10.96.0.10");
        svc1.node_port = Some(30080);
        let prov = Static(StdMutex::new(vec![(svc1, vec![ep("10.244.0.5", true)])]));
        let mut s = ServiceSync::new(
            MockIpvs::new(),
            MockNetlink::new(),
            prov,
            Duration::from_secs(300),
            ValidationRanges::default(),
        )
        .with_node_ips(vec!["192.168.1.10".parse().unwrap()]);
        s.reconcile().await.unwrap();
        // ClusterIP service + NodePort service = 2.
        assert_eq!(s.ipvs.service_count(), 2);
        let np = IpvsService {
            addr: "192.168.1.10".parse().unwrap(),
            protocol: Protocol::Tcp,
            port: 30080,
            scheduler: Scheduler::Rr,
            persistent: None,
        };
        assert_eq!(s.ipvs.destinations(&np).len(), 1);
        // NodePort listens on the existing node IP, NOT the dummy interface.
        assert!(!s.nl.has_addr(DUMMY_IF, "192.168.1.10".parse().unwrap(), 32));
        assert!(s.nl.has_addr(DUMMY_IF, "10.96.0.10".parse().unwrap(), 32));
    }

    #[tokio::test]
    async fn nodeport_outside_range_is_skipped() {
        let mut svc1 = svc("10.96.0.10");
        svc1.node_port = Some(40000); // outside 30000-32767
        let prov = Static(StdMutex::new(vec![(svc1, vec![ep("10.244.0.5", true)])]));
        let mut s = ServiceSync::new(
            MockIpvs::new(),
            MockNetlink::new(),
            prov,
            Duration::from_secs(300),
            ValidationRanges::default(),
        )
        .with_node_ips(vec!["192.168.1.10".parse().unwrap()])
        .with_node_port_range(parse_port_range("30000-32767"));
        s.reconcile().await.unwrap();
        // Only the ClusterIP service; the out-of-range NodePort is skipped.
        assert_eq!(s.ipvs.service_count(), 1);
    }

    #[tokio::test]
    async fn nodeport_external_local_skipped_without_local_endpoints() {
        let mut svc1 = svc("10.96.0.10");
        svc1.node_port = Some(30080);
        svc1.external_traffic_local = true;
        let prov = Static(StdMutex::new(vec![(svc1, vec![ep_remote("10.244.1.5")])]));
        let mut s = ServiceSync::new(
            MockIpvs::new(),
            MockNetlink::new(),
            prov,
            Duration::from_secs(300),
            ValidationRanges::default(),
        )
        .with_node_ips(vec!["192.168.1.10".parse().unwrap()]);
        s.reconcile().await.unwrap();
        // ClusterIP only; NodePort skipped (externalTrafficPolicy Local, no local eps).
        assert_eq!(s.ipvs.service_count(), 1);
    }

    #[tokio::test]
    async fn graceful_drains_then_deletes_when_idle() {
        let prov = Static(StdMutex::new(vec![(
            svc("10.96.0.10"),
            vec![ep("10.244.0.5", true), ep("10.244.1.5", true)],
        )]));
        let mut s = ServiceSync::new(
            MockIpvs::new(),
            MockNetlink::new(),
            prov,
            Duration::from_secs(300),
            ValidationRanges::default(),
        )
        .with_graceful(true, Duration::from_secs(3600));
        s.reconcile().await.unwrap();
        assert_eq!(s.ipvs.destinations(&isvc("10.96.0.10")).len(), 2);

        // Drop one endpoint → it is drained (weight 0), not deleted, and queued.
        *s.provider.0.lock().unwrap() = vec![(svc("10.96.0.10"), vec![ep("10.244.0.5", true)])];
        s.reconcile().await.unwrap();
        let dests = s.ipvs.destinations(&isvc("10.96.0.10"));
        assert_eq!(dests.len(), 2);
        let drained = dests
            .iter()
            .find(|d| d.addr.to_string() == "10.244.1.5")
            .unwrap();
        assert_eq!(drained.weight, 0);
        assert_eq!(s.gqueue.len(), 1);

        // Report it idle → next sync deletes it and clears the queue.
        s.ipvs.set_conn_stats(
            &isvc("10.96.0.10"),
            &IpvsDestination {
                addr: "10.244.1.5".parse().unwrap(),
                port: 8080,
                weight: 0,
                tunnel: false,
            },
            0,
            0,
        );
        s.reconcile().await.unwrap();
        assert_eq!(s.ipvs.destinations(&isvc("10.96.0.10")).len(), 1);
        assert!(s.gqueue.is_empty());
    }

    #[tokio::test]
    async fn graceful_deletes_after_period_elapses() {
        let prov = Static(StdMutex::new(vec![(
            svc("10.96.0.10"),
            vec![ep("10.244.0.5", true), ep("10.244.1.5", true)],
        )]));
        let mut s = ServiceSync::new(
            MockIpvs::new(),
            MockNetlink::new(),
            prov,
            Duration::from_secs(300),
            ValidationRanges::default(),
        )
        .with_graceful(true, Duration::from_secs(0)); // already-expired grace period
        s.reconcile().await.unwrap();

        // Drop an endpoint: with conns unknown but the period already elapsed, the
        // destination is deleted on the next sync.
        *s.provider.0.lock().unwrap() = vec![(svc("10.96.0.10"), vec![ep("10.244.0.5", true)])];
        s.reconcile().await.unwrap();
        s.reconcile().await.unwrap();
        assert_eq!(s.ipvs.destinations(&isvc("10.96.0.10")).len(), 1);
        assert!(s.gqueue.is_empty());
    }

    #[tokio::test]
    async fn udp_destination_change_flushes_conntrack() {
        let mut svc1 = svc("10.96.0.10");
        svc1.protocol = Protocol::Udp;
        let prov = Static(StdMutex::new(vec![(
            svc1.clone(),
            vec![ep("10.244.0.5", true), ep("10.244.1.5", true)],
        )]));
        let mut s = ServiceSync::new(
            MockIpvs::new(),
            MockNetlink::new(),
            prov,
            Duration::from_secs(300),
            ValidationRanges::default(),
        );
        s.reconcile().await.unwrap();
        assert!(s.ipvs.conntrack_flushes().is_empty());

        // Remove an endpoint from the UDP service → conntrack is flushed.
        *s.provider.0.lock().unwrap() = vec![(svc1, vec![ep("10.244.0.5", true)])];
        s.reconcile().await.unwrap();
        assert_eq!(
            s.ipvs.conntrack_flushes(),
            vec![("10.96.0.10".parse().unwrap(), 80)]
        );
    }

    #[tokio::test]
    async fn publishes_per_service_metrics() {
        use crate::ipvs::ServiceStats;
        let prov = Static(StdMutex::new(vec![(
            svc("10.96.0.10"),
            vec![ep("10.244.0.5", true)],
        )]));
        let obs = kr_observability::Metrics::new("t");
        let sm = kr_observability::ServiceMetrics::register(obs.registry());
        let mut s = ServiceSync::new(
            MockIpvs::new(),
            MockNetlink::new(),
            prov,
            Duration::from_secs(300),
            ValidationRanges::default(),
        )
        .with_metrics(sm);
        s.reconcile().await.unwrap();
        // Stats are zero until reported; set them and reconcile again.
        s.ipvs.set_service_stats(
            &isvc("10.96.0.10"),
            ServiceStats {
                connections: 7,
                bytes_in: 4096,
                ..Default::default()
            },
        );
        s.reconcile().await.unwrap();
        let out = obs.gather();
        assert!(out.contains("kube_router_controller_ipvs_services 1"));
        assert!(out.contains("service_name=\"web\"") && out.contains("service_vip=\"10.96.0.10\""));
        assert!(out.contains(
            "kube_router_service_total_connections{port=\"80\",protocol=\"tcp\",service_name=\"web\",service_vip=\"10.96.0.10\",svc_namespace=\"default\"} 7"
        ));
    }

    #[tokio::test]
    async fn internal_traffic_local_limits_to_local_endpoints() {
        let mut svc1 = svc("10.96.0.10");
        svc1.internal_traffic_local = true;
        let prov = Static(StdMutex::new(vec![(
            svc1,
            vec![ep("10.244.0.5", true), ep_remote("10.244.1.5")],
        )]));
        let mut s = ServiceSync::new(
            MockIpvs::new(),
            MockNetlink::new(),
            prov,
            Duration::from_secs(300),
            ValidationRanges::default(),
        );
        s.reconcile().await.unwrap();
        // Only the local endpoint is a destination.
        let dests = s.ipvs.destinations(&isvc("10.96.0.10"));
        assert_eq!(dests.len(), 1);
        assert_eq!(dests[0].addr.to_string(), "10.244.0.5");
    }
}
