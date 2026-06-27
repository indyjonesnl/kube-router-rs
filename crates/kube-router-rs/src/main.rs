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
mod netpol_wire;
mod orchestrate;
mod routing_wire;

use std::sync::{Arc, Mutex};
use std::time::Instant;

use k8s_openapi::api::core::v1::{Namespace, Node, Pod};
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
    let store = kr_kube_client::spawn_reflector::<Node>(client);

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
                until_shutdown(shutdown_rx.clone()),
            ));
            let watch = tokio::spawn(watch_task(we, tx, shutdown_rx.clone()));
            if let Some(mut c) = bgp {
                c.run(health, until_shutdown(shutdown_rx)).await;
            } else {
                until_shutdown(shutdown_rx).await;
            }
            inject.abort();
            watch.abort();
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

/// Consume BGP best-path events and install/withdraw kernel routes. Skips the
/// node's own routes (next hop == local IP). Periodically re-syncs.
async fn receive_side_inject<F>(
    mut rx: tokio::sync::mpsc::Receiver<kr_bgp::PathEvent>,
    local_ip: Option<std::net::IpAddr>,
    sync_period: std::time::Duration,
    stop: F,
) where
    F: std::future::Future<Output = ()>,
{
    let mut injector = kr_routing::RouteInjector::new(
        kr_netlink_sys::SystemNetlink::new(),
        Vec::new(),
        kr_routing::overlay::OverlayType::Subnet,
        254,
    );
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

    let source = netpol_wire::StorePolicySource::new(policies, pods, namespaces);
    let controller = kr_netpol::FirewallController::new(
        SystemIpset::new(),
        families,
        source,
        name,
        config.iptables_sync_period,
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

fn current_euid() -> u32 {
    // SAFETY: geteuid is always safe to call.
    unsafe { libc::geteuid() }
}
