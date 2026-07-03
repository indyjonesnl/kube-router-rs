//! Route injection from BGP best-path events (mirrors the `OnBestPath` →
//! `injectRoute` path in `upstream/pkg/controllers/routing/network_routes_controller.go`
//! and `routes/route_sync.go`).
//!
//! Best-path events from the BGP engine are turned into kernel routes: an
//! advertisement installs/updates a route; a withdrawal deletes it. A route-state
//! map holds the desired routes so the injected-routes sync tick can re-apply
//! them (`--injected-routes-sync-period`). Whether a route uses the overlay
//! tunnel vs a direct next hop is decided per `overlay::needs_tunnel`.
//!
//! NOTE: the event source is the BGP engine's best-path watch (gRPC, deferred);
//! routing of tunnel traffic onto the tunnel device is completed in T039. Here a
//! route is installed via `next_hop` and the tunnel decision is recorded.

use std::collections::BTreeMap;
use std::net::IpAddr;

use ipnet::IpNet;
use kr_netlink_sys::{NetlinkError, NetlinkOps, Route};

use crate::overlay::{needs_tunnel, OverlayType};

/// A BGP best-path event (advertisement or withdrawal).
#[derive(Debug, Clone)]
pub struct BestPath {
    /// Destination prefix.
    pub prefix: IpNet,
    /// Next hop.
    pub next_hop: IpAddr,
    /// Whether this withdraws the prefix.
    pub withdrawal: bool,
}

#[derive(Debug, Clone)]
struct InjectedRoute {
    route: Route,
    via_tunnel: bool,
}

/// Injects BGP-learned routes into the kernel and reconciles them on a tick.
pub struct RouteInjector<N: NetlinkOps> {
    nl: N,
    local_subnets: Vec<IpNet>,
    overlay: OverlayType,
    table: u32,
    import_reject: Vec<IpNet>,
    routes: BTreeMap<IpNet, InjectedRoute>,
}

impl<N: NetlinkOps> RouteInjector<N> {
    /// New injector writing into routing `table`.
    pub fn new(nl: N, local_subnets: Vec<IpNet>, overlay: OverlayType, table: u32) -> Self {
        Self {
            nl,
            local_subnets,
            overlay,
            table,
            import_reject: Vec::new(),
            routes: BTreeMap::new(),
        }
    }

    /// Reject learned prefixes contained by any of these
    /// (`kube-router.io/node.bgp.customimportreject`): they are never installed.
    pub fn with_import_reject(mut self, reject: Vec<IpNet>) -> Self {
        self.import_reject = reject;
        self
    }

    /// Whether a learned prefix should be rejected on import (contained by a
    /// reject prefix of the same family).
    fn is_rejected(&self, prefix: &IpNet) -> bool {
        self.import_reject
            .iter()
            .any(|r| r.contains(&prefix.network()) && prefix.prefix_len() >= r.prefix_len())
    }

    /// Number of routes currently in the state map.
    pub fn route_count(&self) -> usize {
        self.routes.len()
    }

    /// Whether the route for `prefix` was decided to use the overlay tunnel.
    pub fn via_tunnel(&self, prefix: &IpNet) -> Option<bool> {
        self.routes.get(prefix).map(|r| r.via_tunnel)
    }

    /// Process a single best-path event.
    pub async fn on_event(&mut self, ev: &BestPath) -> Result<(), NetlinkError> {
        if ev.withdrawal {
            if let Some(ir) = self.routes.remove(&ev.prefix) {
                self.nl.route_del(&ir.route).await?;
            }
            return Ok(());
        }
        // Custom import-reject: drop the learned route (don't install it).
        if self.is_rejected(&ev.prefix) {
            if let Some(ir) = self.routes.remove(&ev.prefix) {
                self.nl.route_del(&ir.route).await?;
            }
            return Ok(());
        }
        let via_tunnel = needs_tunnel(&ev.next_hop, &self.local_subnets, self.overlay);
        let route = Route {
            dst: ev.prefix,
            gateway: Some(ev.next_hop),
            table: self.table,
        };
        self.nl.route_replace(&route).await?;
        self.routes
            .insert(ev.prefix, InjectedRoute { route, via_tunnel });
        Ok(())
    }

    /// Re-apply every route in the state map (the injected-routes sync tick).
    pub async fn sync(&self) -> Result<(), NetlinkError> {
        for ir in self.routes.values() {
            self.nl.route_replace(&ir.route).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_netlink_sys::mock::MockNetlink;

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn injector() -> RouteInjector<MockNetlink> {
        RouteInjector::new(
            MockNetlink::new(),
            vec![net("10.0.0.0/24")],
            OverlayType::Subnet,
            254,
        )
    }

    #[tokio::test]
    async fn import_reject_drops_matching_learned_route() {
        let mut inj = injector().with_import_reject(vec![net("10.244.0.0/16")]);
        // Contained by the reject prefix → not installed.
        inj.on_event(&BestPath {
            prefix: net("10.244.1.0/24"),
            next_hop: ip("10.0.0.2"),
            withdrawal: false,
        })
        .await
        .unwrap();
        assert_eq!(inj.route_count(), 0);
        // A prefix outside the reject set is still installed.
        inj.on_event(&BestPath {
            prefix: net("10.245.1.0/24"),
            next_hop: ip("10.0.0.2"),
            withdrawal: false,
        })
        .await
        .unwrap();
        assert_eq!(inj.route_count(), 1);
    }

    #[tokio::test]
    async fn advertisement_installs_route() {
        let mut inj = injector();
        inj.on_event(&BestPath {
            prefix: net("10.244.1.0/24"),
            next_hop: ip("10.0.0.2"),
            withdrawal: false,
        })
        .await
        .unwrap();
        assert_eq!(inj.route_count(), 1);
        assert_eq!(inj.nl.route_list(254).await.unwrap().len(), 1);
        // Same subnet as local 10.0.0.0/24 → direct, no tunnel.
        assert_eq!(inj.via_tunnel(&net("10.244.1.0/24")), Some(false));
    }

    #[tokio::test]
    async fn cross_subnet_next_hop_uses_tunnel_decision() {
        let mut inj = injector();
        inj.on_event(&BestPath {
            prefix: net("10.244.2.0/24"),
            next_hop: ip("10.1.0.2"), // not in local 10.0.0.0/24
            withdrawal: false,
        })
        .await
        .unwrap();
        assert_eq!(inj.via_tunnel(&net("10.244.2.0/24")), Some(true));
    }

    #[tokio::test]
    async fn withdrawal_removes_route() {
        let mut inj = injector();
        let p = net("10.244.1.0/24");
        inj.on_event(&BestPath {
            prefix: p,
            next_hop: ip("10.0.0.2"),
            withdrawal: false,
        })
        .await
        .unwrap();
        inj.on_event(&BestPath {
            prefix: p,
            next_hop: ip("10.0.0.2"),
            withdrawal: true,
        })
        .await
        .unwrap();
        assert_eq!(inj.route_count(), 0);
        assert!(inj.nl.route_list(254).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn sync_reapplies_state_idempotently() {
        let mut inj = injector();
        inj.on_event(&BestPath {
            prefix: net("10.244.1.0/24"),
            next_hop: ip("10.0.0.2"),
            withdrawal: false,
        })
        .await
        .unwrap();
        inj.sync().await.unwrap();
        // route_replace is idempotent per dst/table → still one route.
        assert_eq!(inj.nl.route_list(254).await.unwrap().len(), 1);
    }
}
