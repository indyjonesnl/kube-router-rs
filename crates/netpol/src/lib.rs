//! Network Policy Controller (NPC): Kubernetes NetworkPolicy enforcement via
//! iptables + ipset, mirroring `upstream/pkg/controllers/netpol`.
//!
//! Layout: OS abstractions (`ipset`, `iptables`) behind mockable traits; the
//! `naming`/marks scheme; a projected policy `model`; `translate` (policies +
//! pods/namespaces → chains/rules/sets); and the full-sync `controller`.

pub mod controller;
pub mod ipset;
pub mod iptables;
pub mod model;
pub mod naming;
pub mod synth;
pub mod translate;

pub use controller::{FirewallController, PolicySource, PolicyWorld, SyncError};
pub use ipset::{IpsetOps, SetType};
pub use iptables::IptablesOps;
pub use model::{Namespace, NetworkPolicy, Peer, Pod, PolicyTypes, PortSpec, Rule};
pub use synth::{build_plan, FirewallPlan, IpsetPlan};
pub use translate::{resolve_peers, ResolvedPeers};
