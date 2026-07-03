//! Orchestration helpers: root check, enabled-component derivation, lifecycle.

use std::time::Duration;

use kr_config::KubeRouterConfig;
use kr_observability::Component;

/// Error returned when the process is not running as root.
#[derive(Debug, thiserror::Error)]
#[error(
    "kube-router-rs must run as root (effective uid {euid}); needs iptables/ipset/ipvs/netlink"
)]
pub struct NotRoot {
    /// The observed effective uid.
    pub euid: u32,
}

/// Require root (euid 0), mirroring upstream's privilege check.
pub fn require_root(euid: u32) -> Result<(), NotRoot> {
    if euid == 0 {
        Ok(())
    } else {
        Err(NotRoot { euid })
    }
}

/// Health components (with sync windows) for the enabled controllers.
pub fn components_for(config: &KubeRouterConfig) -> Vec<(Component, Duration)> {
    let mut out = Vec::new();
    if config.run_router {
        out.push((Component::NetworkRoutes, config.routes_sync_period));
        out.push((Component::RouteSync, config.injected_routes_sync_period));
    }
    if config.run_firewall {
        out.push((Component::NetworkPolicy, config.iptables_sync_period));
    }
    if config.run_service_proxy {
        // NetworkServices only. Hairpin SNAT is performed *inside* the service-proxy
        // sync loop (the same loop that heartbeats NetworkServices) — it is not a
        // separate controller and nothing emits a Hairpin heartbeat, so registering
        // it here left /healthz permanently 500 (→ liveness SIGTERM every sync
        // window). See kr_proxy::sync::run.
        out.push((Component::NetworkServices, config.ipvs_sync_period));
    }
    if config.run_loadbalancer {
        out.push((Component::LoadBalancer, config.loadbalancer_sync_period));
    }
    // NOTE: Component::Metrics is intentionally NOT registered. The metrics HTTP
    // surface is a passive endpoint, not a controller with a heartbeating sync loop;
    // registering it (as an earlier version did when --metrics-port was set) made
    // /healthz permanently 500 for the same reason as Hairpin above.
    out
}

/// Human-readable list of enabled controllers (for startup logging).
pub fn enabled_controllers(config: &KubeRouterConfig) -> Vec<&'static str> {
    let mut v = Vec::new();
    if config.run_router {
        v.push("router (BGP + routes)");
    }
    if config.run_firewall {
        v.push("firewall (network policy)");
    }
    if config.run_service_proxy {
        v.push("service-proxy (IPVS)");
    }
    if config.run_loadbalancer {
        v.push("loadbalancer-allocator");
    }
    v
}

/// Build a `host:port` bind address; empty host means all interfaces.
pub fn bind_addr(host: &str, port: u16) -> String {
    let host = if host.is_empty() { "0.0.0.0" } else { host };
    format!("{host}:{port}")
}

/// Block until SIGINT or SIGTERM is received.
pub async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(args: &[&str]) -> KubeRouterConfig {
        let mut v = vec!["kube-router-rs"];
        v.extend_from_slice(args);
        KubeRouterConfig::try_parse_from(v).unwrap()
    }

    #[test]
    fn root_required() {
        assert!(require_root(0).is_ok());
        assert!(require_root(1000).is_err());
    }

    #[test]
    fn default_components_cover_three_controllers() {
        let c = cfg(&[]);
        let comps: Vec<_> = components_for(&c).into_iter().map(|(c, _)| c).collect();
        assert!(comps.contains(&Component::NetworkRoutes));
        assert!(comps.contains(&Component::NetworkPolicy));
        assert!(comps.contains(&Component::NetworkServices));
        assert!(!comps.contains(&Component::LoadBalancer));
    }

    #[test]
    fn loadbalancer_component_only_when_enabled() {
        let c = cfg(&["--run-loadbalancer=true"]);
        let comps: Vec<_> = components_for(&c).into_iter().map(|(c, _)| c).collect();
        assert!(comps.contains(&Component::LoadBalancer));
    }

    #[test]
    fn metrics_and_hairpin_not_registered_as_health_components() {
        // Neither has a heartbeating sync loop; registering them would leave
        // /healthz permanently 500. (Regression guard for the liveness-restart bug.)
        let c = cfg(&["--metrics-port=8080", "--run-service-proxy=true"]);
        let comps: Vec<_> = components_for(&c).into_iter().map(|(c, _)| c).collect();
        assert!(!comps.contains(&Component::Metrics));
        assert!(!comps.contains(&Component::Hairpin));
        assert!(comps.contains(&Component::NetworkServices));
    }

    #[test]
    fn subset_enable_lists_only_selected() {
        let c = cfg(&[
            "--run-router=false",
            "--run-firewall=false",
            "--run-service-proxy=true",
        ]);
        assert_eq!(enabled_controllers(&c), vec!["service-proxy (IPVS)"]);
    }

    #[test]
    fn bind_addr_defaults_to_all_interfaces() {
        assert_eq!(bind_addr("", 20244), "0.0.0.0:20244");
        assert_eq!(bind_addr("127.0.0.1", 9000), "127.0.0.1:9000");
    }
}
