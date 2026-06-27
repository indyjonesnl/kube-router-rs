//! Shared types and helpers for kube-router-rs: IP-family handling, error types,
//! deterministic chain/set naming, and sysctl access.

pub mod error;
pub mod ipfamily;
pub mod naming;
pub mod sysctl;

pub use error::{Error, Result};
pub use ipfamily::IpFamily;
