//! Observability: health heartbeat tracking + `/healthz`, Prometheus metrics, logging.

pub mod health;
pub mod http;
pub mod logging;
pub mod metrics;

pub use health::{Component, HealthState};
pub use metrics::Metrics;
