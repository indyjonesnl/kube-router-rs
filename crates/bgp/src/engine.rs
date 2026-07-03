//! The BGP engine boundary.
//!
//! The runtime drives GoBGP over its gRPC API (research.md D5). Controllers
//! depend on the [`BgpEngine`] trait — mirroring the GoBGP API calls upstream
//! makes (`StartBgp`/`StopBgp`/`AddPeer`/`DeletePeer`/`AddPath`/`DeletePath`) — so
//! they are testable against [`mock::MockBgpEngine`].
//!
//! NOTE: the concrete tonic gRPC implementation (`GobgpGrpcEngine`) is generated
//! from the GoBGP `.proto` and is added when those proto files are vendored; the
//! process supervision it connects to lives in [`crate::server`].

use std::net::IpAddr;

use async_trait::async_trait;

use crate::path::Path;

/// Global BGP server config (maps to GoBGP `StartBgp`'s global block).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalConfig {
    /// Local ASN.
    pub asn: u32,
    /// Router id (required for IPv6-only; `"generate"` to auto-derive).
    pub router_id: Option<String>,
    /// BGP listen port (`--bgp-port`).
    pub listen_port: u32,
    /// Local listen addresses (defaults to the node IP).
    pub listen_addresses: Vec<IpAddr>,
}

/// MP-BGP Graceful Restart parameters for a peer (`--bgp-graceful-restart`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GracefulRestart {
    /// Advertised restart time (seconds).
    pub restart_time_secs: u32,
    /// Deferral time before selecting best paths after restart (seconds).
    pub deferral_time_secs: u32,
}

/// A BGP neighbor to configure (maps to GoBGP `AddPeer`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerConfig {
    /// Neighbor address.
    pub neighbor: IpAddr,
    /// Neighbor ASN.
    pub peer_asn: u32,
    /// eBGP (external) vs iBGP.
    pub is_external: bool,
    /// Treat neighbor as a route-reflector client.
    pub rr_client: bool,
    /// RR cluster id when `rr_client`.
    pub rr_cluster_id: Option<String>,
    /// Optional local session address.
    pub local_address: Option<IpAddr>,
    /// Optional base64 MD5 password.
    pub password: Option<String>,
    /// Optional remote port.
    pub port: Option<u16>,
    /// Optional eBGP multihop TTL.
    pub multihop_ttl: Option<u8>,
    /// MP-BGP Graceful Restart, when enabled.
    pub graceful_restart: Option<GracefulRestart>,
}

/// BGP engine errors.
#[derive(Debug, thiserror::Error)]
pub enum BgpError {
    /// The engine operation failed.
    #[error("bgp engine error: {0}")]
    Engine(String),
}

/// Operations the routing controller performs against the BGP engine.
#[async_trait]
pub trait BgpEngine: Send + Sync {
    /// Start the BGP server with the given global config.
    async fn start(&self, global: &GlobalConfig) -> Result<(), BgpError>;
    /// Stop the BGP server (graceful close to peers).
    async fn stop(&self) -> Result<(), BgpError>;
    /// Add (or update) a peer.
    async fn add_peer(&self, peer: &PeerConfig) -> Result<(), BgpError>;
    /// Delete a peer by neighbor address.
    async fn delete_peer(&self, neighbor: IpAddr) -> Result<(), BgpError>;
    /// Advertise a path.
    async fn add_path(&self, path: &Path) -> Result<(), BgpError>;
    /// Withdraw a path.
    async fn delete_path(&self, path: &Path) -> Result<(), BgpError>;
}

/// A [`BgpEngine`] that logs each call and succeeds.
///
/// Placeholder used by the binary until the concrete tonic gRPC engine (codegen
/// from the GoBGP proto) lands; lets the routing controller run end-to-end and
/// report exactly what it would program.
#[derive(Debug, Default)]
pub struct LoggingEngine;

impl LoggingEngine {
    /// New logging engine.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl BgpEngine for LoggingEngine {
    async fn start(&self, global: &GlobalConfig) -> Result<(), BgpError> {
        tracing::info!(asn = global.asn, "BGP start (no-op: gRPC engine pending)");
        Ok(())
    }
    async fn stop(&self) -> Result<(), BgpError> {
        tracing::info!("BGP stop (no-op: gRPC engine pending)");
        Ok(())
    }
    async fn add_peer(&self, peer: &PeerConfig) -> Result<(), BgpError> {
        tracing::info!(neighbor = %peer.neighbor, asn = peer.peer_asn, "BGP add_peer (no-op)");
        Ok(())
    }
    async fn delete_peer(&self, neighbor: IpAddr) -> Result<(), BgpError> {
        tracing::info!(%neighbor, "BGP delete_peer (no-op)");
        Ok(())
    }
    async fn add_path(&self, path: &Path) -> Result<(), BgpError> {
        tracing::info!(prefix = %path.prefix, "BGP add_path (no-op)");
        Ok(())
    }
    async fn delete_path(&self, path: &Path) -> Result<(), BgpError> {
        tracing::info!(prefix = %path.prefix, "BGP delete_path (no-op)");
        Ok(())
    }
}

#[cfg(any(test, feature = "mock"))]
pub mod mock {
    //! Recording [`BgpEngine`] for unit tests.
    use std::sync::Mutex;

    use super::*;

    /// Records every engine call for assertions.
    #[derive(Default)]
    pub struct MockBgpEngine {
        /// Global configs passed to `start`.
        pub started: Mutex<Vec<GlobalConfig>>,
        /// Whether `stop` was called.
        pub stopped: Mutex<bool>,
        /// Peers added.
        pub added_peers: Mutex<Vec<PeerConfig>>,
        /// Neighbors deleted.
        pub deleted_peers: Mutex<Vec<IpAddr>>,
        /// Paths advertised.
        pub added_paths: Mutex<Vec<Path>>,
        /// Paths withdrawn.
        pub deleted_paths: Mutex<Vec<Path>>,
    }

    impl MockBgpEngine {
        /// New empty mock.
        pub fn new() -> Self {
            Self::default()
        }
        /// Count of peers added.
        pub fn added_peer_count(&self) -> usize {
            self.added_peers.lock().unwrap().len()
        }
        /// Snapshot of deleted neighbors.
        pub fn deleted_neighbors(&self) -> Vec<IpAddr> {
            self.deleted_peers.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl BgpEngine for MockBgpEngine {
        async fn start(&self, global: &GlobalConfig) -> Result<(), BgpError> {
            self.started.lock().unwrap().push(global.clone());
            Ok(())
        }
        async fn stop(&self) -> Result<(), BgpError> {
            *self.stopped.lock().unwrap() = true;
            Ok(())
        }
        async fn add_peer(&self, peer: &PeerConfig) -> Result<(), BgpError> {
            self.added_peers.lock().unwrap().push(peer.clone());
            Ok(())
        }
        async fn delete_peer(&self, neighbor: IpAddr) -> Result<(), BgpError> {
            self.deleted_peers.lock().unwrap().push(neighbor);
            Ok(())
        }
        async fn add_path(&self, path: &Path) -> Result<(), BgpError> {
            self.added_paths.lock().unwrap().push(path.clone());
            Ok(())
        }
        async fn delete_path(&self, path: &Path) -> Result<(), BgpError> {
            self.deleted_paths.lock().unwrap().push(path.clone());
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock::MockBgpEngine;
    use super::*;

    #[tokio::test]
    async fn mock_records_calls() {
        let e = MockBgpEngine::new();
        e.start(&GlobalConfig {
            asn: 64512,
            router_id: None,
            listen_port: 179,
            listen_addresses: vec![],
        })
        .await
        .unwrap();
        e.add_peer(&PeerConfig {
            neighbor: "10.0.0.2".parse().unwrap(),
            peer_asn: 64512,
            is_external: false,
            rr_client: false,
            rr_cluster_id: None,
            local_address: None,
            password: None,
            port: None,
            multihop_ttl: None,
            graceful_restart: None,
        })
        .await
        .unwrap();
        e.delete_peer("10.0.0.3".parse().unwrap()).await.unwrap();
        e.stop().await.unwrap();

        assert_eq!(e.started.lock().unwrap().len(), 1);
        assert_eq!(e.added_peer_count(), 1);
        assert_eq!(
            e.deleted_neighbors(),
            vec!["10.0.0.3".parse::<IpAddr>().unwrap()]
        );
        assert!(*e.stopped.lock().unwrap());
    }
}
