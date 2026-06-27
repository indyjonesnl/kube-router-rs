//! `--cleanup-config` dispatch.
//!
//! Mirrors upstream cleanup: remove all agent-owned on-node state (iptables
//! chains, ipsets, IPVS services, injected routes, tunnels) and exit without
//! starting controllers.
//!
//! NOTE: each controller's concrete teardown is implemented alongside that
//! controller (tasks T043/T057/T077/T094) and invoked here. Until those land,
//! this dispatcher enumerates the cleanup steps it will perform.

use kr_config::KubeRouterConfig;

/// Run cleanup for whichever subsystems the configuration would have enabled,
/// then return (the caller exits).
pub async fn run(config: &KubeRouterConfig) -> anyhow::Result<()> {
    tracing::info!("cleanup-config: removing kube-router-rs owned state");
    for step in cleanup_steps(config) {
        tracing::info!("cleanup: {step}");
        // Concrete teardown wired per controller in later tasks.
    }
    Ok(())
}

/// The ordered cleanup steps for a configuration.
pub fn cleanup_steps(config: &KubeRouterConfig) -> Vec<&'static str> {
    let mut steps = Vec::new();
    if config.run_firewall {
        steps.push("remove KUBE-ROUTER-*/KUBE-POD-FW-*/KUBE-NWPLCY-* iptables chains");
        steps.push("destroy KUBE-*/kube-router-* ipsets");
    }
    if config.run_service_proxy {
        steps.push("flush IPVS services and destinations");
        steps.push("remove VIPs from kube-dummy-if");
    }
    if config.run_router {
        steps.push("delete injected routes");
        steps.push("tear down overlay tunnels");
    }
    steps
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
    fn default_cleanup_covers_all_three_default_controllers() {
        let steps = cleanup_steps(&cfg(&[]));
        assert!(steps.iter().any(|s| s.contains("iptables")));
        assert!(steps.iter().any(|s| s.contains("IPVS")));
        assert!(steps.iter().any(|s| s.contains("routes")));
    }

    #[test]
    fn firewall_only_cleanup_skips_ipvs_and_routes() {
        let steps = cleanup_steps(&cfg(&["--run-service-proxy=false", "--run-router=false"]));
        assert!(steps.iter().any(|s| s.contains("iptables")));
        assert!(!steps.iter().any(|s| s.contains("IPVS")));
        assert!(!steps.iter().any(|s| s.contains("routes")));
    }
}
