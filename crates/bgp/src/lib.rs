//! BGP path and policy modelling for the routing controller.
//!
//! The runtime drives GoBGP over gRPC (see research.md D5); this crate builds the
//! request payloads. It mirrors `upstream/pkg/bgp/path.go`: an IPv4 prefix is
//! advertised with a `NEXT_HOP` attribute, an IPv6 prefix with an `MP_REACH_NLRI`
//! attribute, both with `ORIGIN = IGP`. A withdrawal carries the same NLRI with
//! the withdrawal flag set.

pub mod engine;
pub mod grpc;
pub mod path;
pub mod policy;
pub mod server;

/// Generated GoBGP gRPC client (proto package `api`, service `GoBgpService`).
pub mod gobgp_api {
    #![allow(warnings, clippy::all)]
    include!(concat!(env!("OUT_DIR"), "/api.rs"));
}

pub use engine::{BgpEngine, BgpError, GlobalConfig, LoggingEngine, PeerConfig};
pub use grpc::{GobgpGrpcEngine, PathEvent};
pub use path::{Afi, Attr, Path, PathBuilder, Safi};
pub use policy::{DefinedSet, DefinedSetKind};
pub use server::GobgpSupervisor;
