//! kube-router-rs entrypoint and controller orchestration.
//!
//! Mirrors `upstream/cmd/kube-router` + `pkg/cmd/kube-router.go`: parse flags,
//! require root, handle `--cleanup-config`, start the health/metrics surfaces and
//! the enabled controllers, then wait for SIGINT/SIGTERM and tear down.
//!
//! Currently the routing controller (`--run-router`) is wired end-to-end (live
//! Kubernetes Node informer → peer reconcile → BGP engine). The BGP engine is the
//! logging placeholder until the gRPC engine lands; the firewall / service-proxy /
//! loadbalancer controllers wire in their respective user-story tasks.

mod cleanup;
mod lballoc_wire;
mod netpol_wire;
mod orchestrate;
mod proxy_wire;
mod routing_wire;
mod svc_vip_wire;

use std::sync::{Arc, Mutex};
use std::time::Instant;

use k8s_openapi::api::core::v1::{Namespace, Node, Pod, Service};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use k8s_openapi::api::networking::v1::NetworkPolicy;
use kr_config::KubeRouterConfig;
use kr_observability::http;
use kr_observability::{HealthState, Metrics};
use tokio::sync::watch;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = KubeRouterConfig::parse_args();
    config
        .validate()
        .map_err(|e| anyhow::anyhow!("configuration error: {e}"))?;

    kr_observability::logging::init(&config.v_level);

    if config.cleanup_config {
        return cleanup::run(&config).await;
    }

    orchestrate::require_root(current_euid()).map_err(|e| anyhow::anyhow!("{e}"))?;

    // Health + metrics surfaces.
    let metrics = Arc::new(Metrics::new(VERSION));
    let health = Arc::new(Mutex::new(HealthState::new()));
    {
        let now = Instant::now();
        let mut h = health.lock().unwrap();
        for (component, period) in orchestrate::components_for(&config) {
            h.register(component, period, now);
        }
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let mut servers = Vec::new();
    if config.health_port != 0 {
        let addr = orchestrate::bind_addr(&config.health_addr, config.health_port);
        let listener = http::bind(&addr).await?;
        tracing::info!(%addr, "health endpoint listening");
        servers.push(tokio::spawn(http::serve(
            listener,
            http::health_handler(health.clone()),
        )));
    }
    if config.metrics_port != 0 {
        let addr = orchestrate::bind_addr(&config.metrics_addr, config.metrics_port);
        let listener = http::bind(&addr).await?;
        tracing::info!(%addr, path = %config.metrics_path, "metrics endpoint listening");
        servers.push(tokio::spawn(http::serve(
            listener,
            http::metrics_handler(metrics.clone(), config.metrics_path.clone()),
        )));
    }

    for line in orchestrate::enabled_controllers(&config) {
        tracing::info!("controller enabled: {line}");
    }

    // Controllers.
    let mut controllers = Vec::new();
    if config.run_router {
        let cfg = config.clone();
        let health2 = health.clone();
        let rx = shutdown_rx.clone();
        controllers.push(tokio::spawn(async move {
            if let Err(e) = run_routing(cfg, health2, rx).await {
                tracing::error!(error = %e, "routing controller exited with error");
            }
        }));
    }
    if config.run_firewall {
        let cfg = config.clone();
        let health2 = health.clone();
        let rx = shutdown_rx.clone();
        controllers.push(tokio::spawn(async move {
            if let Err(e) = run_firewall(cfg, health2, rx).await {
                tracing::error!(error = %e, "firewall controller exited with error");
            }
        }));
    }
    if config.run_service_proxy {
        let cfg = config.clone();
        let health2 = health.clone();
        let metrics2 = metrics.clone();
        let rx = shutdown_rx.clone();
        controllers.push(tokio::spawn(async move {
            if let Err(e) = run_serviceproxy(cfg, health2, metrics2, rx).await {
                tracing::error!(error = %e, "service-proxy controller exited with error");
            }
        }));
    }

    if config.run_loadbalancer {
        let cfg = config.clone();
        let health2 = health.clone();
        let rx = shutdown_rx.clone();
        controllers.push(tokio::spawn(async move {
            if let Err(e) = run_loadbalancer(cfg, health2, rx).await {
                tracing::error!(error = %e, "loadbalancer controller exited with error");
            }
        }));
    }

    orchestrate::wait_for_shutdown().await;
    tracing::info!("shutdown signal received; stopping");
    let _ = shutdown_tx.send(true);
    for c in controllers {
        let _ = c.await;
    }
    for s in servers {
        s.abort();
    }
    Ok(())
}

/// A future that resolves when the shutdown signal is sent.
async fn until_shutdown(mut rx: watch::Receiver<bool>) {
    loop {
        if *rx.borrow() {
            return;
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}

/// Build the Kubernetes client + Node informer, wait for cache sync, set up CNI,
/// and run the pod-network route controller + BGP peer controller until shutdown.
async fn run_routing(
    config: KubeRouterConfig,
    health: Arc<Mutex<HealthState>>,
    shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let client =
        kr_kube_client::build_client(Some(&config.kubeconfig), Some(&config.master)).await?;
    let store = kr_kube_client::spawn_reflector::<Node>(client.clone());

    let store_for_ready = store.clone();
    kr_kube_client::wait_with_timeout(
        async move {
            let _ = store_for_ready.wait_until_ready().await;
        },
        config.cache_sync_timeout,
    )
    .await?;

    let name = routing_wire::resolve_node_name(&config.hostname_override).ok_or_else(|| {
        anyhow::anyhow!("cannot determine node name; set --hostname-override or NODE_NAME")
    })?;

    // Node BGP export policy (communities + AS-path prepend) from annotations.
    let bgp_policy = routing_wire::local_node_bgp_policy(&store, &name);

    // CNI plugins + conflist (so kubelet's CNI becomes ready) + IP forwarding.
    let route_provider = routing_wire::StoreNodeRouteProvider::new(store.clone());
    let local_cidrs = route_provider.local_pod_cidrs(&name);
    if let Err(e) = routing_wire::setup_cni(&local_cidrs, config.enable_cni, config.enable_ipv6) {
        tracing::warn!(error = %e, "CNI setup failed");
    }

    // Pod-network direct routes (real netlink via `ip`).
    let mut podnet = kr_routing::PodNetController::new(
        kr_netlink_sys::SystemNetlink::new(),
        route_provider,
        name.clone(),
        config.routes_sync_period,
    );

    // BGP engine: real gobgp gRPC when available, else logging stub.
    let bgp_provider = routing_wire::StoreNodeProvider::new(store, config.cluster_asn);
    let local_ip = bgp_provider.local_node(&name).map(|n| n.ip);
    let (engine, mut supervisor) = routing_wire::build_engine(&config, local_ip).await;

    // Advertise this node's pod CIDR(s) to BGP peers (next hop = node IP).
    if let Some(nh) = local_ip {
        let mut advertiser = kr_routing::Advertiser::new();
        if let Err(e) = advertiser
            .sync(&engine, &local_cidrs, nh, config.advertise_pod_cidr)
            .await
        {
            tracing::warn!(error = %e, "pod CIDR advertisement failed");
        }
    }

    // Clone the gobgp engine (if real) for the best-path watch before it moves
    // into the controller.
    let watch_engine = match &engine {
        routing_wire::SelectedEngine::Gobgp(e) => Some(e.clone()),
        routing_wire::SelectedEngine::Logging(_) => None,
    };
    let bgp = routing_wire::build_controller(&config, bgp_provider, &name, engine);

    let health2 = health.clone();
    match watch_engine {
        // Real BGP: install kernel routes from BGP-learned best paths (parity);
        // podnet (the flat-L2 direct-route fallback) is not used.
        Some(we) => {
            let (tx, rx) = tokio::sync::mpsc::channel(256);
            let inject = tokio::spawn(receive_side_inject(
                rx,
                local_ip,
                config.injected_routes_sync_period,
                bgp_policy.import_reject.clone(),
                until_shutdown(shutdown_rx.clone()),
            ));
            // Advertise service VIPs (ClusterIP/ExternalIP/LB) to peers when any
            // --advertise-*-ip is enabled.
            let advertise_any = config.advertise_cluster_ip
                || config.advertise_external_ip
                || config.advertise_loadbalancer_ip;
            let vip = match (advertise_any, local_ip) {
                (true, Some(nh)) => Some(tokio::spawn(advertise_service_vips_task(
                    we.clone(),
                    client,
                    name.clone(),
                    kr_routing::service_vips::AdvertiseDefaults {
                        cluster: config.advertise_cluster_ip,
                        external: config.advertise_external_ip,
                        loadbalancer: config.advertise_loadbalancer_ip,
                    },
                    nh,
                    config.routes_sync_period,
                    config.cache_sync_timeout,
                    (bgp_policy.communities.clone(), bgp_policy.path_prepend),
                    shutdown_rx.clone(),
                ))),
                _ => None,
            };
            let stop_engine = we.clone();
            let watch = tokio::spawn(watch_task(we, tx, shutdown_rx.clone()));
            if let Some(mut c) = bgp {
                c.run(health, until_shutdown(shutdown_rx)).await;
            } else {
                until_shutdown(shutdown_rx).await;
            }
            // Graceful teardown order: controllers stopped above → send BGP
            // shutdown (StopBgp) so peers get a clean notification → stop the
            // watch/advertise tasks → kill gobgpd (supervisor.terminate below).
            {
                use kr_bgp::BgpEngine;
                if let Err(e) = stop_engine.stop().await {
                    tracing::warn!(error = %e, "BGP StopBgp on shutdown failed");
                }
            }
            inject.abort();
            watch.abort();
            if let Some(v) = vip {
                v.abort();
            }
        }
        // Logging engine: flat-L2 direct routes via podnet.
        None => {
            let stop_pod = until_shutdown(shutdown_rx.clone());
            match bgp {
                Some(mut c) => {
                    tokio::join!(
                        c.run(health, until_shutdown(shutdown_rx)),
                        podnet.run(health2, stop_pod)
                    );
                }
                None => podnet.run(health2, stop_pod).await,
            }
        }
    }

    // Graceful gobgp teardown.
    if let Some(s) = supervisor.as_mut() {
        let _ = s.terminate().await;
    }
    Ok(())
}

/// Periodically compute the node's advertised service-VIP set and reconcile it
/// to the BGP engine (add new VIPs, withdraw removed ones) until shutdown.
#[allow(clippy::too_many_arguments)]
async fn advertise_service_vips_task(
    engine: kr_bgp::GobgpGrpcEngine,
    client: kube::Client,
    node_name: String,
    defaults: kr_routing::service_vips::AdvertiseDefaults,
    next_hop: std::net::IpAddr,
    sync_period: std::time::Duration,
    cache_sync_timeout: std::time::Duration,
    policy_attrs: (Vec<u32>, Option<(u32, u8)>),
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let services = kr_kube_client::spawn_reflector::<Service>(client.clone());
    let slices = kr_kube_client::spawn_reflector::<EndpointSlice>(client);
    let (sv, sl) = (services.clone(), slices.clone());
    let _ = kr_kube_client::wait_with_timeout(
        async move {
            let _ = sv.wait_until_ready().await;
            let _ = sl.wait_until_ready().await;
        },
        cache_sync_timeout,
    )
    .await;

    let provider = svc_vip_wire::StoreSvcVipProvider::new(services, slices, node_name);
    let mut advertiser =
        kr_routing::Advertiser::new().with_attributes(policy_attrs.0, policy_attrs.1);
    let mut ticker = tokio::time::interval(sync_period);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let vips: Vec<ipnet::IpNet> =
                    kr_routing::service_vips::advertised_service_vips(&provider.snapshot(), &defaults)
                        .into_iter()
                        .collect();
                if let Err(e) = advertiser.sync(&engine, &vips, next_hop, true).await {
                    tracing::warn!(error = %e, "service VIP advertisement failed");
                }
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() { break; }
            }
        }
    }
}

/// Consume BGP best-path events and install/withdraw kernel routes. Skips the
/// node's own routes (next hop == local IP). Periodically re-syncs.
async fn receive_side_inject<F>(
    mut rx: tokio::sync::mpsc::Receiver<kr_bgp::PathEvent>,
    local_ip: Option<std::net::IpAddr>,
    sync_period: std::time::Duration,
    import_reject: Vec<ipnet::IpNet>,
    stop: F,
) where
    F: std::future::Future<Output = ()>,
{
    let mut injector = kr_routing::RouteInjector::new(
        kr_netlink_sys::SystemNetlink::new(),
        Vec::new(),
        kr_routing::overlay::OverlayType::Subnet,
        254,
    )
    .with_import_reject(import_reject);
    let mut ticker = tokio::time::interval(sync_period);
    tokio::pin!(stop);
    loop {
        tokio::select! {
            maybe = rx.recv() => match maybe {
                Some(ev) => {
                    if Some(ev.next_hop) == local_ip {
                        continue; // own advertised route — handled by the local bridge
                    }
                    let bp = kr_routing::BestPath {
                        prefix: ev.prefix,
                        next_hop: ev.next_hop,
                        withdrawal: ev.withdrawal,
                    };
                    if let Err(e) = injector.on_event(&bp).await {
                        tracing::warn!(error = %e, "BGP route inject failed");
                    }
                }
                None => break,
            },
            _ = ticker.tick() => {
                let _ = injector.sync().await;
            }
            _ = &mut stop => break,
        }
    }
}

/// Run the gobgp best-path watch, reconnecting with backoff until shutdown.
async fn watch_task(
    engine: kr_bgp::GobgpGrpcEngine,
    tx: tokio::sync::mpsc::Sender<kr_bgp::PathEvent>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    while !*shutdown_rx.borrow() {
        match engine.watch_best_paths(tx.clone()).await {
            Ok(()) => tracing::warn!("BGP best-path watch ended; reconnecting"),
            Err(e) => tracing::warn!(error = %e, "BGP best-path watch error; reconnecting"),
        }
        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {}
            _ = shutdown_rx.changed() => {}
        }
    }
}

/// Build the Kubernetes client + NetworkPolicy/Pod/Namespace informers, wait for
/// cache sync, and run the firewall (NetworkPolicy) controller until shutdown.
async fn run_firewall(
    config: KubeRouterConfig,
    health: Arc<Mutex<HealthState>>,
    shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    use kr_common::ipfamily::IpFamily;
    use kr_netpol::ipset::SystemIpset;
    use kr_netpol::iptables::SystemIptables;

    let client =
        kr_kube_client::build_client(Some(&config.kubeconfig), Some(&config.master)).await?;
    let policies = kr_kube_client::spawn_reflector::<NetworkPolicy>(client.clone());
    let pods = kr_kube_client::spawn_reflector::<Pod>(client.clone());
    let namespaces = kr_kube_client::spawn_reflector::<Namespace>(client);

    let (p, po, ns) = (policies.clone(), pods.clone(), namespaces.clone());
    kr_kube_client::wait_with_timeout(
        async move {
            let _ = p.wait_until_ready().await;
            let _ = po.wait_until_ready().await;
            let _ = ns.wait_until_ready().await;
        },
        config.cache_sync_timeout,
    )
    .await?;

    let name = routing_wire::resolve_node_name(&config.hostname_override).ok_or_else(|| {
        anyhow::anyhow!("cannot determine node name; set --hostname-override or NODE_NAME")
    })?;

    let mut families = Vec::new();
    if config.enable_ipv4 {
        families.push((IpFamily::V4, SystemIptables::for_family(IpFamily::V4)));
    }
    if config.enable_ipv6 {
        families.push((IpFamily::V6, SystemIptables::for_family(IpFamily::V6)));
    }

    // Local node pod CIDRs (to scope default-deny TAIL rejects).
    let node_store = kr_kube_client::spawn_reflector::<Node>(
        kr_kube_client::build_client(Some(&config.kubeconfig), Some(&config.master)).await?,
    );
    let nr = node_store.clone();
    kr_kube_client::wait_with_timeout(
        async move {
            let _ = nr.wait_until_ready().await;
        },
        config.cache_sync_timeout,
    )
    .await?;
    let pod_cidrs = routing_wire::StoreNodeRouteProvider::new(node_store).local_pod_cidrs(&name);

    let source = netpol_wire::StorePolicySource::new(policies, pods, namespaces);
    let controller = kr_netpol::FirewallController::new(
        SystemIpset::new(),
        families,
        source,
        name,
        config.iptables_sync_period,
        config.netpol_default_deny,
        pod_cidrs,
    );
    let mut rx = shutdown_rx;
    controller
        .run(health, async move {
            loop {
                if *rx.borrow() {
                    return;
                }
                if rx.changed().await.is_err() {
                    return;
                }
            }
        })
        .await;
    Ok(())
}

/// Loosen strict reverse-path filtering (rp_filter 1 → 2) on `iface`, mirroring
/// upstream: only override when currently strict (1), leaving 0 untouched to
/// avoid breaking setups that rely on reverse routing. rp_filter=2 (loose) keeps
/// anti-spoofing while allowing the asymmetric DNAT/DSR reply paths IPVS needs.
fn ensure_rp_filter_loose(iface: &str) {
    let key = format!("net.ipv4.conf.{iface}.rp_filter");
    if kr_common::sysctl::read(&key).ok().as_deref() == Some("1") {
        if let Err(e) = kr_common::sysctl::write(&key, "2") {
            tracing::warn!(error = %e, iface, "could not set rp_filter=2");
        }
    }
}

/// Apply the IPVS + ARP sysctls the service proxy needs, plus rp_filter loosening
/// on the proxy-relevant interfaces (`all`, `kube-bridge`, `kube-dummy-if`, and
/// the node's primary link). Mirrors `network_services_controller` startup.
async fn setup_ipvs_sysctls(primary_ip: Option<std::net::IpAddr>) {
    for (key, val) in [
        ("net.ipv4.vs.conntrack", "1"), // conntrack for masquerade-mode ClusterIP
        ("net.ipv4.vs.expire_nodest_conn", "1"), // drop conns to removed real servers (UDP failover)
        ("net.ipv4.vs.expire_quiescent_template", "1"), // expire persistence to down reals
        ("net.ipv4.vs.conn_reuse_mode", "0"),    // avoid k8s IPVS conn-reuse drops/latency
        ("net.ipv4.conf.all.arp_ignore", "1"),   // don't answer ARP for VIPs on the wrong iface
        ("net.ipv4.conf.all.arp_announce", "2"),
    ] {
        if let Err(e) = kr_common::sysctl::write(key, val) {
            tracing::warn!(error = %e, key, "could not set sysctl");
        }
    }
    for iface in ["all", "kube-bridge", kr_proxy::sync::DUMMY_IF] {
        ensure_rp_filter_loose(iface);
    }
    if let Some(ip) = primary_ip {
        if ip.is_ipv4() {
            if let Some(node_iface) = kr_proxy::local_ips::iface_for_ip(ip).await {
                ensure_rp_filter_loose(&node_iface);
            }
        }
    }
}

/// Build the client + Service/EndpointSlice informers and run the IPVS
/// service-proxy controller until shutdown.
async fn run_serviceproxy(
    config: KubeRouterConfig,
    health: Arc<Mutex<HealthState>>,
    metrics: Arc<Metrics>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let client =
        kr_kube_client::build_client(Some(&config.kubeconfig), Some(&config.master)).await?;
    // Service/EndpointSlice changes ping `changed` so the proxy reconciles promptly
    // (e.g. when a backend becomes ready) instead of waiting for the periodic tick.
    let changed = std::sync::Arc::new(tokio::sync::Notify::new());
    let services =
        kr_kube_client::spawn_reflector_notify::<Service>(client.clone(), changed.clone());
    let slices =
        kr_kube_client::spawn_reflector_notify::<EndpointSlice>(client.clone(), changed.clone());
    let nodes = kr_kube_client::spawn_reflector::<Node>(client);

    let (sv, sl, nd) = (services.clone(), slices.clone(), nodes.clone());
    kr_kube_client::wait_with_timeout(
        async move {
            let _ = sv.wait_until_ready().await;
            let _ = sl.wait_until_ready().await;
            let _ = nd.wait_until_ready().await;
        },
        config.cache_sync_timeout,
    )
    .await?;

    let name = routing_wire::resolve_node_name(&config.hostname_override).ok_or_else(|| {
        anyhow::anyhow!("cannot determine node name; set --hostname-override or NODE_NAME")
    })?;

    // Local pod CIDRs (for masquerade) + the node's primary IP.
    let pod_cidrs = routing_wire::StoreNodeRouteProvider::new(nodes.clone()).local_pod_cidrs(&name);
    let primary_ip = routing_wire::StoreNodeProvider::new(nodes, config.cluster_asn)
        .local_node(&name)
        .map(|n| n.ip);

    // IPVS + ARP kernel tuning for the service-proxy datapath, mirroring the Go
    // upstream (network_services_controller). IPv4-only: the ipvs-sysctl doc notes
    // there are no IPv6 equivalents. All best-effort.
    setup_ipvs_sysctls(primary_ip).await;

    // NodePort bind addresses: all local IPs under `--nodeport-bindon-all-ip`,
    // else just the primary node IP.
    let node_ips: Vec<std::net::IpAddr> = if config.nodeport_bindon_all_ip {
        kr_proxy::local_ips::all_local_ips().await
    } else {
        primary_ip.into_iter().collect()
    };

    let provider = proxy_wire::StoreServiceProvider::new(services, slices, name);
    let parse_nets =
        |v: &[String]| -> Vec<ipnet::IpNet> { v.iter().filter_map(|s| s.parse().ok()).collect() };
    let ranges = kr_proxy::sync::ValidationRanges {
        external: parse_nets(&config.service_external_ip_range),
        loadbalancer: parse_nets(&config.loadbalancer_ip_range),
        cluster: parse_nets(&config.service_cluster_ip_range),
        strict: config.strict_external_ip_validation,
    };
    let sync = kr_proxy::ServiceSync::new(
        kr_proxy::SystemIpvs::new(),
        kr_netlink_sys::SystemNetlink::new(),
        provider,
        config.ipvs_sync_period,
        ranges,
    )
    .with_node_ips(node_ips)
    .with_graceful(
        config.ipvs_graceful_termination,
        config.ipvs_graceful_period,
    )
    .with_metrics(kr_observability::ServiceMetrics::register(
        metrics.registry(),
    ))
    .with_nodeport_healthchecks(kr_proxy::nodeport_hc::NodePortHealthChecks::new())
    .with_node_port_range(kr_proxy::sync::parse_port_range(
        &config.service_node_port_range,
    ));

    // Hairpin SNAT nat handlers per enabled IP family.
    let mut hairpin_nat: Vec<(bool, std::sync::Arc<dyn kr_proxy::hairpin::NatOps>)> = Vec::new();
    if config.enable_ipv4 {
        hairpin_nat.push((
            false,
            std::sync::Arc::new(kr_proxy::hairpin::SystemNat::for_family(
                kr_common::ipfamily::IpFamily::V4,
            )),
        ));
    }
    if config.enable_ipv6 {
        hairpin_nat.push((
            true,
            std::sync::Arc::new(kr_proxy::hairpin::SystemNat::for_family(
                kr_common::ipfamily::IpFamily::V6,
            )),
        ));
    }
    let masq = kr_proxy::sync::MasqueradeCfg {
        all: config.masquerade_all,
        random_fully: true,
        primary: primary_ip
            .map(|ip| vec![(ip.is_ipv6(), ip)])
            .unwrap_or_default(),
        pod_cidrs: pod_cidrs.iter().map(|c| c.to_string()).collect(),
    };
    // IPVS service firewall (KUBE-ROUTER-SERVICES REJECT chain when not permit-all).
    let mut firewall_ipt: Vec<(bool, std::sync::Arc<dyn kr_proxy::firewall::FwIptables>)> =
        Vec::new();
    if config.enable_ipv4 {
        firewall_ipt.push((
            false,
            std::sync::Arc::new(kr_proxy::firewall::SystemFwIptables::for_family(
                kr_common::ipfamily::IpFamily::V4,
            )),
        ));
    }
    if config.enable_ipv6 {
        firewall_ipt.push((
            true,
            std::sync::Arc::new(kr_proxy::firewall::SystemFwIptables::for_family(
                kr_common::ipfamily::IpFamily::V6,
            )),
        ));
    }
    // DSR mangle handlers (FWMARK MARK + TCPMSS) per enabled family.
    let mut dsr_mangle: Vec<(bool, std::sync::Arc<dyn kr_proxy::tcpmss::MangleOps>)> = Vec::new();
    if config.enable_ipv4 {
        dsr_mangle.push((
            false,
            std::sync::Arc::new(kr_proxy::tcpmss::SystemMangle::for_family(
                kr_common::ipfamily::IpFamily::V4,
            )),
        ));
    }
    if config.enable_ipv6 {
        dsr_mangle.push((
            true,
            std::sync::Arc::new(kr_proxy::tcpmss::SystemMangle::for_family(
                kr_common::ipfamily::IpFamily::V6,
            )),
        ));
    }
    let mut sync = sync
        .with_hairpin(config.hairpin_mode, hairpin_nat)
        .with_masquerade(masq)
        .with_dsr(dsr_mangle, 1500)
        .with_firewall(
            config.ipvs_permit_all,
            firewall_ipt,
            std::sync::Arc::new(kr_proxy::firewall::SystemFwIpset),
        );
    sync.run(health, changed, async move {
        loop {
            if *shutdown_rx.borrow() {
                return;
            }
            if shutdown_rx.changed().await.is_err() {
                return;
            }
        }
    })
    .await;
    Ok(())
}

/// Build the client + Service informer and run the LoadBalancer allocator:
/// Lease-elected, it assigns pool IPs to owned `type: LoadBalancer` services.
async fn run_loadbalancer(
    config: KubeRouterConfig,
    health: Arc<Mutex<HealthState>>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    use kr_lballoc::election::{LeaderElector, RETRY_PERIOD};
    use kr_lballoc::{IpRanges, LbAllocator};
    use kr_observability::Component;

    let client =
        kr_kube_client::build_client(Some(&config.kubeconfig), Some(&config.master)).await?;
    let services = kr_kube_client::spawn_reflector::<Service>(client.clone());
    let sv = services.clone();
    kr_kube_client::wait_with_timeout(
        async move {
            let _ = sv.wait_until_ready().await;
        },
        config.cache_sync_timeout,
    )
    .await?;

    // Split the configured LB ranges by family.
    let (mut v4, mut v6) = (Vec::new(), Vec::new());
    for cidr in &config.loadbalancer_ip_range {
        if let Ok(net) = cidr.parse::<ipnet::IpNet>() {
            match net {
                ipnet::IpNet::V4(_) => v4.push(net),
                ipnet::IpNet::V6(_) => v6.push(net),
            }
        }
    }

    let provider = lballoc_wire::StoreLbServiceProvider::new(services);
    let updater = lballoc_wire::KubeStatusUpdater::new(client.clone());
    let mut allocator = LbAllocator::new(
        IpRanges::new(v4),
        IpRanges::new(v6),
        config.loadbalancer_default_class,
        provider,
        updater,
    );

    // Lease election: single allocator cluster-wide.
    let namespace = std::env::var("POD_NAMESPACE").unwrap_or_else(|_| "kube-system".into());
    let identity = std::env::var("POD_NAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "kube-router-rs".into());
    let lease = lballoc_wire::KubeLease::new(client, &namespace, identity);
    let mut elector = LeaderElector::new(lease);

    let mut election_tick = tokio::time::interval(RETRY_PERIOD);
    let mut sync_tick = tokio::time::interval(config.loadbalancer_sync_period);
    loop {
        tokio::select! {
            _ = election_tick.tick() => {
                if let Some(became) = elector.tick().await {
                    tracing::info!(leader = became, "loadbalancer leadership changed");
                }
            }
            _ = sync_tick.tick() => {
                if elector.is_leader() {
                    if let Err(e) = allocator.reconcile().await {
                        tracing::warn!(error = %e, "loadbalancer allocation failed");
                    }
                }
                if let Ok(mut h) = health.lock() {
                    h.heartbeat(Component::LoadBalancer, Instant::now());
                }
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() { break; }
            }
        }
    }
    Ok(())
}

fn current_euid() -> u32 {
    // SAFETY: geteuid is always safe to call.
    unsafe { libc::geteuid() }
}
