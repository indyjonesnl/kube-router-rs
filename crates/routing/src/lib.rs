//! Network Routes Controller (NRC): BGP peering derivation, route injection,
//! overlay tunnels, and pod-egress SNAT.
//!
//! This crate currently provides the pure decision logic (peer topology derivation,
//! overlay naming/decision, pod-egress rule construction), tested against the
//! `kr-netlink-sys` mock. The live controller loop + GoBGP gRPC client are wired in
//! later tasks (T034/T042).

pub mod advertise;
pub mod annotations;
pub mod controller;
pub mod inject;
pub mod overlay;
pub mod peers;
pub mod pod_egress;
pub mod podnet;

pub use advertise::Advertiser;
pub use annotations::{parse_node_bgp, ExternalPeer, NodeBgpConfig};
pub use controller::{NetworkRoutesController, NodeProvider, RoutesControllerConfig};
pub use inject::{BestPath, RouteInjector};
pub use peers::{derive_ibgp_peers, peer_diff, BgpPeer, NodeBgp};
pub use podnet::{desired_pod_routes, NodeRoute, NodeRouteProvider, PodNetController};
