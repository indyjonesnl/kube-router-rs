//! Network Routes Controller (NRC) reconcile loop.
//!
//! Mirrors the routing controller's `Run` loop in
//! `upstream/pkg/controllers/routing/network_routes_controller.go`: on each
//! sync-period tick it derives the desired iBGP peer set from the current node
//! list, diffs it against the configured peers, applies the diff to the BGP
//! engine (`AddPeer`/`DeletePeer`), and emits a health heartbeat.
//!
//! NOTE: route advertisement (`AddPath`/`DeletePath`) and the netlink route
//! injection are wired in T037/T038; the concrete gRPC `BgpEngine` (vs the mock)
//! is the deferred codegen piece. The node list is supplied via [`NodeProvider`],
//! which the Node informer store implements at binary wiring.

use std::future::Future;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kr_bgp::{BgpEngine, BgpError, PeerConfig};
use kr_observability::{Component, HealthState};

use crate::peers::{derive_ibgp_peers, peer_diff, BgpPeer, NodeBgp};

/// Supplies the current cluster nodes (from the Node informer store).
pub trait NodeProvider: Send + Sync {
    /// Snapshot of the cluster nodes' BGP attributes.
    fn nodes(&self) -> Vec<NodeBgp>;
}

/// Map a derived iBGP peer to the engine's peer config.
fn to_peer_config(p: &BgpPeer) -> PeerConfig {
    PeerConfig {
        neighbor: p.neighbor,
        peer_asn: p.peer_asn,
        is_external: p.is_external,
        rr_client: p.rr_client,
        rr_cluster_id: p.rr_cluster_id.map(|c| c.to_string()),
        local_address: None,
        password: None,
        port: None,
        multihop_ttl: None,
    }
}

/// Static configuration for the routes controller's peering.
#[derive(Debug, Clone)]
pub struct RoutesControllerConfig {
    /// This node's BGP attributes.
    pub local: NodeBgp,
    /// `--nodes-full-mesh`.
    pub full_mesh: bool,
    /// `--enable-ibgp`.
    pub enable_ibgp: bool,
    /// `--routes-sync-period`.
    pub sync_period: Duration,
}

/// The routes controller.
pub struct NetworkRoutesController<P: NodeProvider, E: BgpEngine> {
    cfg: RoutesControllerConfig,
    provider: P,
    engine: E,
    current_peers: Vec<BgpPeer>,
}

impl<P: NodeProvider, E: BgpEngine> NetworkRoutesController<P, E> {
    /// Construct with the given config, node source, and BGP engine.
    pub fn new(cfg: RoutesControllerConfig, provider: P, engine: E) -> Self {
        Self {
            cfg,
            provider,
            engine,
            current_peers: Vec::new(),
        }
    }

    /// The currently-configured peers (after the last reconcile).
    pub fn current_peers(&self) -> &[BgpPeer] {
        &self.current_peers
    }

    /// Compute the desired-vs-current peer diff and update internal state,
    /// returning `(to_add, to_remove)`. Pure; does not touch the engine.
    pub fn reconcile(&mut self) -> (Vec<BgpPeer>, Vec<IpAddr>) {
        let nodes = self.provider.nodes();
        let desired = derive_ibgp_peers(
            &self.cfg.local,
            &nodes,
            self.cfg.full_mesh,
            self.cfg.enable_ibgp,
        );
        let diff = peer_diff(&self.current_peers, &desired);
        self.current_peers = desired;
        diff
    }

    /// Reconcile and apply the diff to the BGP engine. Returns the
    /// `(added, removed)` counts applied.
    pub async fn reconcile_and_apply(&mut self) -> Result<(usize, usize), BgpError> {
        let (add, remove) = self.reconcile();
        for peer in &add {
            self.engine.add_peer(&to_peer_config(peer)).await?;
        }
        for neighbor in &remove {
            self.engine.delete_peer(*neighbor).await?;
        }
        Ok((add.len(), remove.len()))
    }

    /// Run the reconcile loop until `stop` resolves, emitting a heartbeat per tick.
    pub async fn run<F>(&mut self, health: Arc<Mutex<HealthState>>, stop: F)
    where
        F: Future<Output = ()>,
    {
        let mut ticker = tokio::time::interval(self.cfg.sync_period);
        tokio::pin!(stop);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    match self.reconcile_and_apply().await {
                        Ok((added, removed)) if added > 0 || removed > 0 => {
                            tracing::info!(added, removed, "applied iBGP peer changes");
                        }
                        Ok(_) => {}
                        Err(e) => tracing::warn!(error = %e, "failed to apply iBGP peer changes"),
                    }
                    if let Ok(mut h) = health.lock() {
                        h.heartbeat(Component::NetworkRoutes, Instant::now());
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
    use std::sync::Mutex as StdMutex;

    use kr_bgp::engine::mock::MockBgpEngine;

    fn node(name: &str, ip: &str) -> NodeBgp {
        NodeBgp {
            name: name.to_string(),
            ip: ip.parse().unwrap(),
            asn: 64512,
            rr_server: None,
            rr_client: None,
        }
    }

    struct StaticNodes(StdMutex<Vec<NodeBgp>>);
    impl NodeProvider for StaticNodes {
        fn nodes(&self) -> Vec<NodeBgp> {
            self.0.lock().unwrap().clone()
        }
    }

    fn controller(
        provider: StaticNodes,
        engine: MockBgpEngine,
    ) -> NetworkRoutesController<StaticNodes, MockBgpEngine> {
        NetworkRoutesController::new(
            RoutesControllerConfig {
                local: node("a", "10.0.0.1"),
                full_mesh: true,
                enable_ibgp: true,
                sync_period: Duration::from_secs(300),
            },
            provider,
            engine,
        )
    }

    #[test]
    fn first_reconcile_adds_all_peers() {
        let prov = StaticNodes(StdMutex::new(vec![
            node("a", "10.0.0.1"),
            node("b", "10.0.0.2"),
            node("c", "10.0.0.3"),
        ]));
        let mut c = controller(prov, MockBgpEngine::new());
        let (add, remove) = c.reconcile();
        assert_eq!(add.len(), 2); // peers b and c (not self)
        assert!(remove.is_empty());
        assert_eq!(c.current_peers().len(), 2);
    }

    #[tokio::test]
    async fn reconcile_and_apply_calls_engine() {
        let prov = StaticNodes(StdMutex::new(vec![
            node("a", "10.0.0.1"),
            node("b", "10.0.0.2"),
        ]));
        let mut c = controller(prov, MockBgpEngine::new());
        let (added, removed) = c.reconcile_and_apply().await.unwrap();
        assert_eq!((added, removed), (1, 0));
        assert_eq!(c.engine.added_peer_count(), 1);
    }

    #[tokio::test]
    async fn apply_reflects_node_churn_on_engine() {
        let prov = StaticNodes(StdMutex::new(vec![
            node("a", "10.0.0.1"),
            node("b", "10.0.0.2"),
        ]));
        let mut c = controller(prov, MockBgpEngine::new());
        c.reconcile_and_apply().await.unwrap(); // adds b

        // b leaves, c joins.
        *c.provider.0.lock().unwrap() = vec![node("a", "10.0.0.1"), node("c", "10.0.0.3")];
        let (added, removed) = c.reconcile_and_apply().await.unwrap();
        assert_eq!((added, removed), (1, 1));
        assert_eq!(
            c.engine.deleted_neighbors(),
            vec!["10.0.0.2".parse::<IpAddr>().unwrap()]
        );
    }

    #[tokio::test]
    async fn second_apply_is_noop_when_unchanged() {
        let prov = StaticNodes(StdMutex::new(vec![
            node("a", "10.0.0.1"),
            node("b", "10.0.0.2"),
        ]));
        let mut c = controller(prov, MockBgpEngine::new());
        c.reconcile_and_apply().await.unwrap();
        let (added, removed) = c.reconcile_and_apply().await.unwrap();
        assert_eq!((added, removed), (0, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn run_loop_applies_and_heartbeats_then_stops() {
        let prov = StaticNodes(StdMutex::new(vec![
            node("a", "10.0.0.1"),
            node("b", "10.0.0.2"),
        ]));
        let mut c = controller(prov, MockBgpEngine::new());
        c.cfg.sync_period = Duration::from_secs(1);

        let health = Arc::new(Mutex::new(HealthState::new()));
        health.lock().unwrap().register(
            Component::NetworkRoutes,
            Duration::from_secs(1),
            Instant::now(),
        );

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let stop = async move {
            let _ = rx.await;
        };
        let handle = tokio::spawn(async move {
            c.run(health, stop).await;
            c
        });
        tokio::time::sleep(Duration::from_secs(3)).await;
        tx.send(()).unwrap();
        let c = handle.await.unwrap();
        assert_eq!(c.current_peers().len(), 1);
        assert!(c.engine.added_peer_count() >= 1);
    }
}
