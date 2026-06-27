//! Pod-network route reconciler.
//!
//! On a flat L2 (all nodes on one subnet) pod-to-pod routing needs no BGP: each
//! node installs a direct route to every *other* node's pod CIDR via that node's
//! IP. We compute the desired routes from the Node informer and apply them via
//! [`NetlinkOps`]. The local pod CIDR is handled by the CNI bridge.
//!
//! This is the same end state BGP would converge to; it's the fast path for the
//! single-subnet case and what makes cross-node pods reachable in the e2e cluster.

use std::future::Future;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ipnet::IpNet;
use kr_netlink_sys::{NetlinkError, NetlinkOps, Route};
use kr_observability::{Component, HealthState};

const MAIN_TABLE: u32 = 254;

/// A node's routing-relevant attributes (from the Node informer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRoute {
    /// Node name.
    pub name: String,
    /// Node IP (next hop for its pods).
    pub ip: IpAddr,
    /// The node's pod CIDR(s).
    pub pod_cidrs: Vec<IpNet>,
}

/// Supplies current node routing info (from the Node store).
pub trait NodeRouteProvider: Send + Sync {
    /// Snapshot of node routing info.
    fn node_routes(&self) -> Vec<NodeRoute>;
}

/// Desired direct routes for `local`: every other node's pod CIDR(s) via its IP.
pub fn desired_pod_routes(local: &str, nodes: &[NodeRoute]) -> Vec<Route> {
    let mut routes = Vec::new();
    for n in nodes {
        if n.name == local {
            continue;
        }
        for cidr in &n.pod_cidrs {
            routes.push(Route {
                dst: *cidr,
                gateway: Some(n.ip),
                table: MAIN_TABLE,
            });
        }
    }
    routes
}

/// Reconciles pod-CIDR routes into the kernel.
pub struct PodNetController<N: NetlinkOps, R: NodeRouteProvider> {
    nl: N,
    provider: R,
    local_name: String,
    sync_period: Duration,
    applied: Vec<Route>,
}

impl<N: NetlinkOps, R: NodeRouteProvider> PodNetController<N, R> {
    /// Construct.
    pub fn new(nl: N, provider: R, local_name: String, sync_period: Duration) -> Self {
        Self {
            nl,
            provider,
            local_name,
            sync_period,
            applied: Vec::new(),
        }
    }

    /// Currently-applied routes.
    pub fn applied(&self) -> &[Route] {
        &self.applied
    }

    /// Reconcile desired vs applied routes, returning `(added, removed)`.
    pub async fn reconcile(&mut self) -> Result<(usize, usize), NetlinkError> {
        let desired = desired_pod_routes(&self.local_name, &self.provider.node_routes());
        let to_add: Vec<Route> = desired
            .iter()
            .filter(|r| !self.applied.contains(r))
            .cloned()
            .collect();
        let to_del: Vec<Route> = self
            .applied
            .iter()
            .filter(|r| !desired.contains(r))
            .cloned()
            .collect();

        for r in &to_add {
            self.nl.route_replace(r).await?;
        }
        for r in &to_del {
            self.nl.route_del(r).await?;
        }
        self.applied = desired;
        Ok((to_add.len(), to_del.len()))
    }

    /// Run the reconcile loop until `stop`, emitting a heartbeat per tick.
    pub async fn run<F>(&mut self, health: Arc<Mutex<HealthState>>, stop: F)
    where
        F: Future<Output = ()>,
    {
        let mut ticker = tokio::time::interval(self.sync_period);
        tokio::pin!(stop);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    match self.reconcile().await {
                        Ok((a, d)) if a > 0 || d > 0 => tracing::info!(added = a, removed = d, "pod-network routes updated"),
                        Ok(_) => {}
                        Err(e) => tracing::warn!(error = %e, "pod-network route reconcile failed"),
                    }
                    if let Ok(mut h) = health.lock() {
                        h.heartbeat(Component::RouteSync, Instant::now());
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
    use kr_netlink_sys::mock::MockNetlink;
    use std::sync::Mutex as StdMutex;

    fn nr(name: &str, ip: &str, cidrs: &[&str]) -> NodeRoute {
        NodeRoute {
            name: name.to_string(),
            ip: ip.parse().unwrap(),
            pod_cidrs: cidrs.iter().map(|c| c.parse().unwrap()).collect(),
        }
    }

    #[test]
    fn desired_excludes_local_and_routes_others() {
        let nodes = vec![
            nr("a", "192.168.32.3", &["10.244.0.0/24"]),
            nr("b", "192.168.32.4", &["10.244.1.0/24"]),
            nr("c", "192.168.32.5", &["10.244.2.0/24"]),
        ];
        let routes = desired_pod_routes("a", &nodes);
        assert_eq!(routes.len(), 2);
        assert!(routes
            .iter()
            .all(|r| r.gateway != Some("192.168.32.3".parse().unwrap())));
    }

    struct Static(StdMutex<Vec<NodeRoute>>);
    impl NodeRouteProvider for Static {
        fn node_routes(&self) -> Vec<NodeRoute> {
            self.0.lock().unwrap().clone()
        }
    }

    #[tokio::test]
    async fn reconcile_installs_then_churns() {
        let nodes = Static(StdMutex::new(vec![
            nr("a", "192.168.32.3", &["10.244.0.0/24"]),
            nr("b", "192.168.32.4", &["10.244.1.0/24"]),
        ]));
        let mut c = PodNetController::new(
            MockNetlink::new(),
            nodes,
            "a".to_string(),
            Duration::from_secs(300),
        );
        let (add, del) = c.reconcile().await.unwrap();
        assert_eq!((add, del), (1, 0));
        assert_eq!(c.nl.route_list(254).await.unwrap().len(), 1);

        // node b leaves, node c joins.
        *c.provider.0.lock().unwrap() = vec![
            nr("a", "192.168.32.3", &["10.244.0.0/24"]),
            nr("c", "192.168.32.5", &["10.244.2.0/24"]),
        ];
        let (add, del) = c.reconcile().await.unwrap();
        assert_eq!((add, del), (1, 1));
        assert_eq!(c.nl.route_list(254).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn reconcile_noop_when_unchanged() {
        let nodes = Static(StdMutex::new(vec![
            nr("a", "192.168.32.3", &["10.244.0.0/24"]),
            nr("b", "192.168.32.4", &["10.244.1.0/24"]),
        ]));
        let mut c = PodNetController::new(
            MockNetlink::new(),
            nodes,
            "a".to_string(),
            Duration::from_secs(300),
        );
        c.reconcile().await.unwrap();
        assert_eq!(c.reconcile().await.unwrap(), (0, 0));
    }
}
