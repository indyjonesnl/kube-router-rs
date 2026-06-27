//! Prometheus metrics registry (namespace `kube_router_`).
//!
//! Mirrors `upstream/pkg/metrics`: a registry exposed over HTTP at the configured
//! path/port, always carrying `kube_router_build_info`. Per-controller metric
//! families are registered by their controllers in later iterations.

use prometheus::{Encoder, IntGaugeVec, Opts, Registry, TextEncoder};

/// Metric namespace prefix used by every kube-router metric.
pub const NAMESPACE: &str = "kube_router";

/// Holds the registry and always-present metrics.
pub struct Metrics {
    registry: Registry,
}

impl Metrics {
    /// Build the registry and register `build_info` with the given version.
    pub fn new(version: &str) -> Self {
        let registry = Registry::new();
        let build_info = IntGaugeVec::new(
            Opts::new("build_info", "kube-router-rs build information").namespace(NAMESPACE),
            &["version"],
        )
        .expect("valid build_info metric");
        build_info.with_label_values(&[version]).set(1);
        registry
            .register(Box::new(build_info))
            .expect("register build_info");
        Self { registry }
    }

    /// The underlying registry, for controllers to register their metrics.
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Render the metrics in Prometheus text exposition format.
    pub fn gather(&self) -> String {
        let mut buf = Vec::new();
        let encoder = TextEncoder::new();
        let families = self.registry.gather();
        encoder.encode(&families, &mut buf).expect("encode metrics");
        String::from_utf8(buf).expect("utf8 metrics")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_info_is_always_present() {
        let m = Metrics::new("0.1.0-test");
        let out = m.gather();
        assert!(out.contains("kube_router_build_info"));
        assert!(out.contains("version=\"0.1.0-test\""));
    }

    #[test]
    fn registry_accepts_additional_metrics() {
        let m = Metrics::new("x");
        let g = prometheus::IntGauge::with_opts(
            Opts::new("ipvs_services", "count").namespace(NAMESPACE),
        )
        .unwrap();
        m.registry().register(Box::new(g.clone())).unwrap();
        g.set(3);
        assert!(m.gather().contains("kube_router_ipvs_services 3"));
    }
}
