//! Network Services Controller (NSC): IPVS-based Kubernetes Service proxy,
//! mirroring `upstream/pkg/controllers/proxy`.
//!
//! This crate provides the projected service/endpoint `model`, `validation` of
//! external/LB IPs, and the mockable `ipvs` programming abstraction. Service →
//! IPVS sync, VIP binding, DSR, hairpin, graceful termination, and the controller
//! loop build on these in subsequent tasks.

pub mod dsr;
pub mod graceful;
pub mod hairpin;
pub mod ipvs;
pub mod local_ips;
pub mod masquerade;
pub mod model;
pub mod nodeport_hc;
pub mod sync;
pub mod tcpmss;
pub mod validation;

pub use ipvs::{IpvsDestination, IpvsOps, IpvsService, SystemIpvs};
pub use model::{EndpointInfo, Protocol, Scheduler, ServiceInfo};
pub use sync::{ServiceProvider, ServiceSync};
pub use validation::validate_external_ip;
