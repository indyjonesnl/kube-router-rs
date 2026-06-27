//! Netlink operations (routes, links, addresses, tunnels) behind a mockable trait.
//!
//! The Go upstream wraps `vishvananda/netlink` and mocks it in tests. We mirror
//! that: controllers depend on the [`NetlinkOps`] trait so they can be unit-tested
//! against [`MockNetlink`], with an rtnetlink-backed implementation used at runtime.
//!
//! NOTE: the rtnetlink-backed runtime implementation is added in a later task; this
//! module currently provides the trait, the retry policy, and the test mock.

pub mod retry;
pub mod system;

pub use system::SystemNetlink;

use std::net::IpAddr;

use async_trait::async_trait;
use ipnet::IpNet;

pub use retry::{retry, RetryConfig};

/// Errors from netlink operations.
#[derive(Debug, thiserror::Error)]
pub enum NetlinkError {
    /// The operation failed.
    #[error("netlink operation failed: {0}")]
    Op(String),
}

/// A route entry the agent manages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// Destination prefix.
    pub dst: IpNet,
    /// Next-hop gateway (None for a direct/link route).
    pub gateway: Option<IpAddr>,
    /// Routing table id (e.g. main, 77 PBR, 78 DSR, 79 external-ip).
    pub table: u32,
}

/// Operations the controllers need from the kernel networking layer.
#[async_trait]
pub trait NetlinkOps: Send + Sync {
    /// Ensure a dummy link with `name` exists and is up (e.g. `kube-dummy-if`).
    async fn ensure_dummy_link(&self, name: &str) -> Result<(), NetlinkError>;
    /// Add an address to a link (idempotent — already-present is OK).
    async fn addr_add(&self, link: &str, addr: IpAddr, prefix_len: u8) -> Result<(), NetlinkError>;
    /// Remove an address from a link (idempotent — absent is OK).
    async fn addr_del(&self, link: &str, addr: IpAddr, prefix_len: u8) -> Result<(), NetlinkError>;
    /// Install or replace a route.
    async fn route_replace(&self, route: &Route) -> Result<(), NetlinkError>;
    /// Delete a route by destination + table.
    async fn route_del(&self, route: &Route) -> Result<(), NetlinkError>;
    /// List routes in a table.
    async fn route_list(&self, table: u32) -> Result<Vec<Route>, NetlinkError>;
}

#[cfg(any(test, feature = "mock"))]
pub mod mock {
    //! In-memory [`NetlinkOps`] for unit tests.
    use super::*;
    use std::collections::BTreeSet;
    use std::sync::Mutex;

    /// Records mutations so tests can assert on resulting state.
    #[derive(Default)]
    pub struct MockNetlink {
        dummy_links: Mutex<BTreeSet<String>>,
        addrs: Mutex<BTreeSet<(String, IpAddr, u8)>>,
        routes: Mutex<Vec<Route>>,
    }

    impl MockNetlink {
        /// New empty mock.
        pub fn new() -> Self {
            Self::default()
        }
        /// Snapshot of routes currently installed.
        pub fn routes(&self) -> Vec<Route> {
            self.routes.lock().unwrap().clone()
        }
        /// Whether a dummy link is present.
        pub fn has_dummy(&self, name: &str) -> bool {
            self.dummy_links.lock().unwrap().contains(name)
        }
        /// Whether an address is bound.
        pub fn has_addr(&self, link: &str, addr: IpAddr, prefix_len: u8) -> bool {
            self.addrs
                .lock()
                .unwrap()
                .contains(&(link.to_string(), addr, prefix_len))
        }
    }

    #[async_trait]
    impl NetlinkOps for MockNetlink {
        async fn ensure_dummy_link(&self, name: &str) -> Result<(), NetlinkError> {
            self.dummy_links.lock().unwrap().insert(name.to_string());
            Ok(())
        }
        async fn addr_add(
            &self,
            link: &str,
            addr: IpAddr,
            prefix_len: u8,
        ) -> Result<(), NetlinkError> {
            self.addrs
                .lock()
                .unwrap()
                .insert((link.to_string(), addr, prefix_len));
            Ok(())
        }
        async fn addr_del(
            &self,
            link: &str,
            addr: IpAddr,
            prefix_len: u8,
        ) -> Result<(), NetlinkError> {
            self.addrs
                .lock()
                .unwrap()
                .remove(&(link.to_string(), addr, prefix_len));
            Ok(())
        }
        async fn route_replace(&self, route: &Route) -> Result<(), NetlinkError> {
            let mut r = self.routes.lock().unwrap();
            r.retain(|e| !(e.dst == route.dst && e.table == route.table));
            r.push(route.clone());
            Ok(())
        }
        async fn route_del(&self, route: &Route) -> Result<(), NetlinkError> {
            self.routes
                .lock()
                .unwrap()
                .retain(|e| !(e.dst == route.dst && e.table == route.table));
            Ok(())
        }
        async fn route_list(&self, table: u32) -> Result<Vec<Route>, NetlinkError> {
            Ok(self
                .routes
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r.table == table)
                .cloned()
                .collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock::MockNetlink;
    use super::*;

    #[tokio::test]
    async fn dummy_link_and_addr_roundtrip() {
        let nl = MockNetlink::new();
        nl.ensure_dummy_link("kube-dummy-if").await.unwrap();
        assert!(nl.has_dummy("kube-dummy-if"));

        let ip: IpAddr = "10.96.0.10".parse().unwrap();
        nl.addr_add("kube-dummy-if", ip, 32).await.unwrap();
        assert!(nl.has_addr("kube-dummy-if", ip, 32));
        nl.addr_del("kube-dummy-if", ip, 32).await.unwrap();
        assert!(!nl.has_addr("kube-dummy-if", ip, 32));
    }

    #[tokio::test]
    async fn route_replace_is_idempotent_per_dst_table() {
        let nl = MockNetlink::new();
        let r = Route {
            dst: "10.244.1.0/24".parse().unwrap(),
            gateway: Some("10.0.0.2".parse().unwrap()),
            table: 254,
        };
        nl.route_replace(&r).await.unwrap();
        // Replace same dst/table with a different gateway → still one route.
        let r2 = Route {
            gateway: Some("10.0.0.3".parse().unwrap()),
            ..r.clone()
        };
        nl.route_replace(&r2).await.unwrap();
        let routes = nl.route_list(254).await.unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].gateway, Some("10.0.0.3".parse().unwrap()));

        nl.route_del(&r2).await.unwrap();
        assert!(nl.route_list(254).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn route_list_filters_by_table() {
        let nl = MockNetlink::new();
        nl.route_replace(&Route {
            dst: "10.244.1.0/24".parse().unwrap(),
            gateway: None,
            table: 254,
        })
        .await
        .unwrap();
        nl.route_replace(&Route {
            dst: "10.244.2.0/24".parse().unwrap(),
            gateway: None,
            table: 77,
        })
        .await
        .unwrap();
        assert_eq!(nl.route_list(254).await.unwrap().len(), 1);
        assert_eq!(nl.route_list(77).await.unwrap().len(), 1);
    }
}
