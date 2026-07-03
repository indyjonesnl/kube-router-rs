//! Wiring that connects the Kubernetes Node informer store to the routing
//! controller's [`NodeProvider`], and starts the controller behind `--run-router`.
//!
//! Mirrors how `upstream/pkg/cmd/kube-router.go` constructs the routes controller
//! from informers. The BGP engine here is the [`LoggingEngine`] placeholder; the
//! concrete gRPC engine + gobgp supervision (T034 codegen) slot in unchanged
//! behind the `BgpEngine` trait.

use std::path::Path;

use ipnet::IpNet;
use k8s_openapi::api::core::v1::Node;
use kr_kube_client::node::{select_node_ips, NodeAddress, NodeAddressType};
use kr_routing::{
    parse_node_bgp, NetworkRoutesController, NodeBgp, NodeProvider, NodeRoute, NodeRouteProvider,
    RoutesControllerConfig,
};
use kube::runtime::reflector::store::Store;

/// In-image directory where CNI plugin binaries are bundled (copied to the host
/// `/opt/cni/bin` at startup). See e2e/k0s/Dockerfile.deploy.
pub const BUNDLED_CNI_DIR: &str = "/opt/cni-bundled";

fn address_kind(type_: &str) -> NodeAddressType {
    match type_ {
        "InternalIP" => NodeAddressType::Internal,
        "ExternalIP" => NodeAddressType::External,
        _ => NodeAddressType::Other,
    }
}

/// Map a Kubernetes `Node` to the routing controller's `NodeBgp`, using
/// `cluster_asn` as the ASN when the node has no `kube-router.io/node.asn`.
/// Returns `None` if the node has no name or no usable IP.
pub fn node_to_bgp(node: &Node, cluster_asn: u32) -> Option<NodeBgp> {
    let name = node.metadata.name.clone()?;
    let addresses: Vec<NodeAddress> = node
        .status
        .as_ref()
        .and_then(|s| s.addresses.as_ref())
        .map(|addrs| {
            addrs
                .iter()
                .map(|a| NodeAddress {
                    kind: address_kind(&a.type_),
                    address: a.address.clone(),
                })
                .collect()
        })
        .unwrap_or_default();

    let ips = select_node_ips(&addresses);
    let ip = ips.v4.or(ips.v6)?;

    let empty = std::collections::BTreeMap::new();
    let annotations = node.metadata.annotations.as_ref().unwrap_or(&empty);
    let bgp = parse_node_bgp(annotations);

    Some(NodeBgp {
        name,
        ip,
        asn: bgp.asn.unwrap_or(cluster_asn),
        rr_server: bgp.rr_server.and_then(|s| s.parse::<u32>().ok()),
        rr_client: bgp.rr_client.and_then(|s| s.parse::<u32>().ok()),
    })
}

/// `NodeProvider` backed by the Node reflector store.
pub struct StoreNodeProvider {
    store: Store<Node>,
    cluster_asn: u32,
}

impl StoreNodeProvider {
    /// Wrap a Node store.
    pub fn new(store: Store<Node>, cluster_asn: u32) -> Self {
        Self { store, cluster_asn }
    }

    /// The local node's BGP attributes, by name, if present in the store.
    pub fn local_node(&self, name: &str) -> Option<NodeBgp> {
        self.store
            .state()
            .iter()
            .find(|n| n.metadata.name.as_deref() == Some(name))
            .and_then(|n| node_to_bgp(n, self.cluster_asn))
    }
}

impl NodeProvider for StoreNodeProvider {
    fn nodes(&self) -> Vec<NodeBgp> {
        self.store
            .state()
            .iter()
            .filter_map(|n| node_to_bgp(n, self.cluster_asn))
            .collect()
    }
}

/// Build the routes controller from config, a Node store, the local node
/// identity, and a BGP engine. Returns `None` (with a warning) if the local node
/// is not yet in the store.
pub fn build_controller<E: kr_bgp::BgpEngine>(
    config: &kr_config::KubeRouterConfig,
    provider: StoreNodeProvider,
    local_name: &str,
    engine: E,
) -> Option<NetworkRoutesController<StoreNodeProvider, E>> {
    let local = match provider.local_node(local_name) {
        Some(n) => n,
        None => {
            tracing::warn!(
                node = local_name,
                "local node not found in store; routing not started"
            );
            return None;
        }
    };
    let local_ip = local.ip;
    // Graceful Restart applied to all peers when --bgp-graceful-restart is set.
    let graceful_restart = config
        .bgp_graceful_restart
        .then_some(kr_bgp::GracefulRestart {
            restart_time_secs: config.bgp_graceful_restart_time.as_secs() as u32,
            deferral_time_secs: config.bgp_graceful_restart_deferral_time.as_secs() as u32,
        });
    let cfg = RoutesControllerConfig {
        local,
        full_mesh: config.nodes_full_mesh,
        enable_ibgp: config.enable_ibgp,
        sync_period: config.routes_sync_period,
        graceful_restart,
    };

    // External peers from the global --peer-router-* flags (zipped by index).
    let ports: Vec<u16> = config
        .peer_router_ports
        .iter()
        .filter_map(|p| u16::try_from(*p).ok())
        .collect();
    let ttl = (config.peer_router_multihop_ttl > 0).then_some(config.peer_router_multihop_ttl);
    let external = match kr_routing::external_peers::zip_peers(
        &config.peer_router_ips,
        &config.peer_router_asns,
        &ports,
        &config.peer_router_passwords,
        ttl,
        Some(local_ip),
        graceful_restart,
    ) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "invalid external peer config; ignoring external peers");
            Vec::new()
        }
    };

    Some(NetworkRoutesController::new(cfg, provider, engine).with_external_peers(external))
}

/// In-image path to the bundled gobgpd binary.
pub const GOBGPD_PATH: &str = "/usr/local/bin/gobgpd";

/// A BGP engine chosen at runtime: the real gobgp gRPC engine when gobgpd is
/// available, else the logging stub.
pub enum SelectedEngine {
    /// Logging placeholder.
    Logging(kr_bgp::LoggingEngine),
    /// gobgp gRPC engine.
    Gobgp(kr_bgp::GobgpGrpcEngine),
}

#[async_trait::async_trait]
impl kr_bgp::BgpEngine for SelectedEngine {
    async fn start(&self, global: &kr_bgp::GlobalConfig) -> Result<(), kr_bgp::BgpError> {
        match self {
            SelectedEngine::Logging(e) => e.start(global).await,
            SelectedEngine::Gobgp(e) => e.start(global).await,
        }
    }
    async fn stop(&self) -> Result<(), kr_bgp::BgpError> {
        match self {
            SelectedEngine::Logging(e) => e.stop().await,
            SelectedEngine::Gobgp(e) => e.stop().await,
        }
    }
    async fn add_peer(&self, peer: &kr_bgp::PeerConfig) -> Result<(), kr_bgp::BgpError> {
        match self {
            SelectedEngine::Logging(e) => e.add_peer(peer).await,
            SelectedEngine::Gobgp(e) => e.add_peer(peer).await,
        }
    }
    async fn delete_peer(&self, neighbor: std::net::IpAddr) -> Result<(), kr_bgp::BgpError> {
        match self {
            SelectedEngine::Logging(e) => e.delete_peer(neighbor).await,
            SelectedEngine::Gobgp(e) => e.delete_peer(neighbor).await,
        }
    }
    async fn add_path(&self, path: &kr_bgp::Path) -> Result<(), kr_bgp::BgpError> {
        match self {
            SelectedEngine::Logging(e) => e.add_path(path).await,
            SelectedEngine::Gobgp(e) => e.add_path(path).await,
        }
    }
    async fn delete_path(&self, path: &kr_bgp::Path) -> Result<(), kr_bgp::BgpError> {
        match self {
            SelectedEngine::Logging(e) => e.delete_path(path).await,
            SelectedEngine::Gobgp(e) => e.delete_path(path).await,
        }
    }
}

/// Choose and initialize the BGP engine. If gobgpd is present and the admin port
/// is enabled, spawn it, wait for its gRPC port, connect, and `StartBgp` with the
/// node's global config; on any failure fall back to the logging engine. Returns
/// the engine plus the gobgp supervisor (kept alive for the process lifetime).
pub async fn build_engine(
    config: &kr_config::KubeRouterConfig,
    local_ip: Option<std::net::IpAddr>,
) -> (SelectedEngine, Option<kr_bgp::GobgpSupervisor>) {
    let logging = || (SelectedEngine::Logging(kr_bgp::LoggingEngine::new()), None);

    if config.gobgp_admin_port == 0 || !Path::new(GOBGPD_PATH).exists() {
        tracing::info!("gobgpd unavailable; using logging BGP engine");
        return logging();
    }
    let admin_addr = if config.gobgp_admin_address.is_empty() {
        "127.0.0.1"
    } else {
        &config.gobgp_admin_address
    };

    let mut supervisor =
        kr_bgp::GobgpSupervisor::gobgpd(GOBGPD_PATH, admin_addr, config.gobgp_admin_port);
    if let Err(e) = supervisor.spawn().await {
        tracing::warn!(error = %e, "failed to spawn gobgpd; using logging engine");
        return logging();
    }
    let endpoint = format!("{admin_addr}:{}", config.gobgp_admin_port);
    if !kr_bgp::server::wait_port_ready(&endpoint, std::time::Duration::from_secs(10)).await {
        tracing::warn!(%endpoint, "gobgpd gRPC port not ready; using logging engine");
        return logging();
    }
    let engine = match kr_bgp::GobgpGrpcEngine::connect_lazy(admin_addr, config.gobgp_admin_port) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, "gobgp connect failed; using logging engine");
            return logging();
        }
    };
    let global = kr_bgp::GlobalConfig {
        asn: config.cluster_asn,
        router_id: local_ip.filter(|ip| ip.is_ipv4()).map(|ip| ip.to_string()),
        listen_port: config.bgp_port,
        listen_addresses: local_ip.into_iter().collect(),
    };
    if let Err(e) = kr_bgp::BgpEngine::start(&engine, &global).await {
        tracing::warn!(error = %e, "gobgp StartBgp failed; using logging engine");
        return logging();
    }
    tracing::info!(asn = config.cluster_asn, "gobgp BGP engine started");
    (SelectedEngine::Gobgp(engine), Some(supervisor))
}

fn node_addresses(node: &Node) -> Vec<NodeAddress> {
    node.status
        .as_ref()
        .and_then(|s| s.addresses.as_ref())
        .map(|addrs| {
            addrs
                .iter()
                .map(|a| NodeAddress {
                    kind: address_kind(&a.type_),
                    address: a.address.clone(),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn node_pod_cidrs(node: &Node) -> Vec<IpNet> {
    let raw = node
        .spec
        .as_ref()
        .map(|s| match &s.pod_cidrs {
            Some(cidrs) if !cidrs.is_empty() => cidrs.clone(),
            _ => s.pod_cidr.clone().into_iter().collect(),
        })
        .unwrap_or_default();
    raw.iter().filter_map(|c| c.parse::<IpNet>().ok()).collect()
}

/// Map a Kubernetes `Node` to routing info (name, IP, pod CIDRs).
pub fn node_to_route(node: &Node) -> Option<NodeRoute> {
    let name = node.metadata.name.clone()?;
    let ips = select_node_ips(&node_addresses(node));
    let ip = ips.v4.or(ips.v6)?;
    Some(NodeRoute {
        name,
        ip,
        pod_cidrs: node_pod_cidrs(node),
    })
}

/// `NodeRouteProvider` backed by the Node reflector store.
pub struct StoreNodeRouteProvider {
    store: Store<Node>,
}

impl StoreNodeRouteProvider {
    /// Wrap a Node store.
    pub fn new(store: Store<Node>) -> Self {
        Self { store }
    }

    /// The local node's pod CIDRs, by name.
    pub fn local_pod_cidrs(&self, name: &str) -> Vec<IpNet> {
        self.store
            .state()
            .iter()
            .find(|n| n.metadata.name.as_deref() == Some(name))
            .map(|n| node_pod_cidrs(n))
            .unwrap_or_default()
    }
}

impl NodeRouteProvider for StoreNodeRouteProvider {
    fn node_routes(&self) -> Vec<NodeRoute> {
        self.store
            .state()
            .iter()
            .filter_map(|n| node_to_route(n))
            .collect()
    }
}

/// Install CNI plugins + write the conflist (when `enable_cni`) and enable IP
/// forwarding. Best-effort on sysctl; CNI errors are returned.
pub fn setup_cni(
    local_pod_cidrs: &[IpNet],
    enable_cni: bool,
    enable_ipv6: bool,
) -> std::io::Result<()> {
    if enable_cni {
        let installed = kr_cni::install_plugins(
            Path::new(BUNDLED_CNI_DIR),
            Path::new(kr_cni::DEFAULT_BIN_DIR),
            kr_cni::REQUIRED_PLUGINS,
        )?;
        tracing::info!(?installed, "installed CNI plugins");
        kr_cni::write_conflist(Path::new(kr_cni::DEFAULT_CONF_PATH), local_pod_cidrs)?;
        tracing::info!(cidrs = ?local_pod_cidrs, path = kr_cni::DEFAULT_CONF_PATH, "wrote CNI conflist");
    }
    if let Err(e) = kr_common::sysctl::write("net.ipv4.ip_forward", "1") {
        tracing::warn!(error = %e, "could not set net.ipv4.ip_forward");
    }
    if enable_ipv6 {
        if let Err(e) = kr_common::sysctl::write("net.ipv6.conf.all.forwarding", "1") {
            tracing::warn!(error = %e, "could not set net.ipv6.conf.all.forwarding");
        }
    }
    Ok(())
}

/// Resolve the local node name: `--hostname-override`, else `$NODE_NAME`, else
/// `$HOSTNAME`.
pub fn resolve_node_name(hostname_override: &str) -> Option<String> {
    if !hostname_override.is_empty() {
        return Some(hostname_override.to_string());
    }
    std::env::var("NODE_NAME")
        .ok()
        .or_else(|| std::env::var("HOSTNAME").ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{NodeAddress as K8sNodeAddress, NodeStatus};
    use kube::api::ObjectMeta;
    use std::collections::BTreeMap;

    fn node(name: &str, internal_ip: &str, annotations: BTreeMap<String, String>) -> Node {
        Node {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                annotations: Some(annotations),
                ..Default::default()
            },
            status: Some(NodeStatus {
                addresses: Some(vec![K8sNodeAddress {
                    type_: "InternalIP".to_string(),
                    address: internal_ip.to_string(),
                }]),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn maps_node_ip_and_default_asn() {
        let n = node("worker-1", "10.0.0.5", BTreeMap::new());
        let b = node_to_bgp(&n, 64512).unwrap();
        assert_eq!(b.name, "worker-1");
        assert_eq!(b.ip, "10.0.0.5".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(b.asn, 64512); // no node.asn annotation → cluster asn
    }

    #[test]
    fn node_asn_annotation_overrides_cluster_asn() {
        let mut ann = BTreeMap::new();
        ann.insert("kube-router.io/node.asn".to_string(), "65001".to_string());
        let b = node_to_bgp(&node("w", "10.0.0.5", ann), 64512).unwrap();
        assert_eq!(b.asn, 65001);
    }

    #[test]
    fn rr_server_annotation_parsed() {
        let mut ann = BTreeMap::new();
        ann.insert("kube-router.io/rr.server".to_string(), "42".to_string());
        let b = node_to_bgp(&node("w", "10.0.0.5", ann), 64512).unwrap();
        assert_eq!(b.rr_server, Some(42));
    }

    #[test]
    fn node_without_ip_is_skipped() {
        let n = Node {
            metadata: ObjectMeta {
                name: Some("no-ip".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(node_to_bgp(&n, 64512).is_none());
    }

    #[test]
    fn resolve_name_prefers_override() {
        assert_eq!(resolve_node_name("explicit"), Some("explicit".to_string()));
    }
}
