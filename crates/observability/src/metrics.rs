//! Prometheus metrics registry (namespace `kube_router_`).
//!
//! Mirrors `upstream/pkg/metrics`: a registry exposed over HTTP at the configured
//! path/port, always carrying `kube_router_build_info`. Per-controller metric
//! families are registered by their controllers in later iterations.

use prometheus::{Encoder, GaugeVec, IntGauge, IntGaugeVec, Opts, Registry, TextEncoder};

/// Metric namespace prefix used by every kube-router metric.
pub const NAMESPACE: &str = "kube_router";

/// Per-service IPVS labels (mirrors `serviceLabels` in `pkg/metrics`).
const SERVICE_LABELS: &[&str] = &[
    "svc_namespace",
    "service_name",
    "service_vip",
    "protocol",
    "port",
];

/// One IPVS virtual service's statistics, ready to publish.
#[derive(Debug, Clone, Default)]
pub struct ServiceStatSample {
    /// Service namespace.
    pub namespace: String,
    /// Service name.
    pub service: String,
    /// Virtual IP.
    pub vip: String,
    /// Protocol (`tcp`/`udp`/`sctp`).
    pub protocol: String,
    /// Virtual port.
    pub port: u16,
    /// Total incoming connections.
    pub total_connections: f64,
    /// Total incoming packets.
    pub packets_in: f64,
    /// Total outgoing packets.
    pub packets_out: f64,
    /// Total incoming bytes.
    pub bytes_in: f64,
    /// Total outgoing bytes.
    pub bytes_out: f64,
    /// Connections per second.
    pub cps: f64,
    /// Incoming packets per second.
    pub pps_in: f64,
    /// Outgoing packets per second.
    pub pps_out: f64,
    /// Incoming bytes per second.
    pub bps_in: f64,
    /// Outgoing bytes per second.
    pub bps_out: f64,
}

/// Per-service IPVS metric families (mirrors the NSC Prometheus collector). The
/// cumulative IPVS counters are exposed as gauges holding their absolute values
/// and refreshed each sync.
pub struct ServiceMetrics {
    total_connections: GaugeVec,
    packets_in: GaugeVec,
    packets_out: GaugeVec,
    bytes_in: GaugeVec,
    bytes_out: GaugeVec,
    cps: GaugeVec,
    pps_in: GaugeVec,
    pps_out: GaugeVec,
    bps_in: GaugeVec,
    bps_out: GaugeVec,
    ipvs_services: IntGauge,
}

fn service_gauge(registry: &Registry, name: &str, help: &str) -> GaugeVec {
    let g = GaugeVec::new(Opts::new(name, help).namespace(NAMESPACE), SERVICE_LABELS)
        .expect("valid service metric");
    registry
        .register(Box::new(g.clone()))
        .expect("register service metric");
    g
}

impl ServiceMetrics {
    /// Build and register every per-service family into `registry`.
    pub fn register(registry: &Registry) -> Self {
        let ipvs_services = IntGauge::with_opts(
            Opts::new(
                "controller_ipvs_services",
                "Number of ipvs services in the instance",
            )
            .namespace(NAMESPACE),
        )
        .expect("valid ipvs_services metric");
        registry
            .register(Box::new(ipvs_services.clone()))
            .expect("register ipvs_services");
        Self {
            total_connections: service_gauge(
                registry,
                "service_total_connections",
                "Total incoming connections made",
            ),
            packets_in: service_gauge(registry, "service_packets_in", "Total incoming packets"),
            packets_out: service_gauge(registry, "service_packets_out", "Total outgoing packets"),
            bytes_in: service_gauge(registry, "service_bytes_in", "Total incoming bytes"),
            bytes_out: service_gauge(registry, "service_bytes_out", "Total outgoing bytes"),
            cps: service_gauge(registry, "service_cps", "Service connections per second"),
            pps_in: service_gauge(registry, "service_pps_in", "Incoming packets per second"),
            pps_out: service_gauge(registry, "service_pps_out", "Outgoing packets per second"),
            bps_in: service_gauge(registry, "service_bps_in", "Incoming bytes per second"),
            bps_out: service_gauge(registry, "service_bps_out", "Outgoing bytes per second"),
            ipvs_services,
        }
    }

    /// Replace all published series with `samples` and set the service count.
    pub fn update(&self, samples: &[ServiceStatSample], service_count: usize) {
        for g in [
            &self.total_connections,
            &self.packets_in,
            &self.packets_out,
            &self.bytes_in,
            &self.bytes_out,
            &self.cps,
            &self.pps_in,
            &self.pps_out,
            &self.bps_in,
            &self.bps_out,
        ] {
            g.reset();
        }
        for s in samples {
            let port = s.port.to_string();
            let labels = [
                s.namespace.as_str(),
                s.service.as_str(),
                s.vip.as_str(),
                s.protocol.as_str(),
                port.as_str(),
            ];
            self.total_connections
                .with_label_values(&labels)
                .set(s.total_connections);
            self.packets_in.with_label_values(&labels).set(s.packets_in);
            self.packets_out
                .with_label_values(&labels)
                .set(s.packets_out);
            self.bytes_in.with_label_values(&labels).set(s.bytes_in);
            self.bytes_out.with_label_values(&labels).set(s.bytes_out);
            self.cps.with_label_values(&labels).set(s.cps);
            self.pps_in.with_label_values(&labels).set(s.pps_in);
            self.pps_out.with_label_values(&labels).set(s.pps_out);
            self.bps_in.with_label_values(&labels).set(s.bps_in);
            self.bps_out.with_label_values(&labels).set(s.bps_out);
        }
        self.ipvs_services.set(service_count as i64);
    }
}

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

    #[test]
    fn service_metrics_publish_and_refresh() {
        let m = Metrics::new("x");
        let sm = ServiceMetrics::register(m.registry());
        let sample = ServiceStatSample {
            namespace: "default".into(),
            service: "web".into(),
            vip: "10.96.0.10".into(),
            protocol: "tcp".into(),
            port: 80,
            total_connections: 42.0,
            bytes_in: 1000.0,
            ..Default::default()
        };
        sm.update(std::slice::from_ref(&sample), 1);
        let out = m.gather();
        assert!(out.contains("kube_router_controller_ipvs_services 1"));
        assert!(out.contains(
            "kube_router_service_total_connections{port=\"80\",protocol=\"tcp\",service_name=\"web\",service_vip=\"10.96.0.10\",svc_namespace=\"default\"} 42"
        ));

        // Refresh with no samples → stale series are dropped.
        sm.update(&[], 0);
        let out = m.gather();
        assert!(!out.contains("service_name=\"web\""));
        assert!(out.contains("kube_router_controller_ipvs_services 0"));
    }
}
