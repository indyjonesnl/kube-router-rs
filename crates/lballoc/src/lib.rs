//! LoadBalancer IP allocator (`--run-loadbalancer`), mirroring
//! `upstream/pkg/controllers/lballoc`: assign IPs from configured pools to
//! `type: LoadBalancer` services this allocator owns, elected via a Lease so a
//! single instance allocates cluster-wide.

pub mod allocate;
pub mod controller;
pub mod election;
pub mod model;
pub mod pools;

pub use allocate::{plan_allocation, should_allocate, AllocError, AllocationPlan};
pub use controller::{allocated_ips, LbAllocator, LbServiceProvider, StatusUpdater};
pub use election::{LeaderElector, LeaseBackend};
pub use model::{LbService, LOAD_BALANCER_CLASS};
pub use pools::IpRanges;
