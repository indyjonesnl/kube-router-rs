//! `--cleanup-config` + graceful-shutdown teardown.
//!
//! Removes all agent-owned on-node state for the enabled controllers — iptables
//! chains (filter/nat), ipsets, IPVS services, the dummy/tunnel interfaces, and
//! the DSR policy-routing tables/rules — mirroring upstream's `CleanupConfig`.
//! The command plan is pure/tested; execution is tolerant (missing state is not
//! an error) and exercised in-cluster.

use kr_config::KubeRouterConfig;

/// A single teardown command (run tolerantly — failure is logged, not fatal).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupCmd {
    /// Human-readable description.
    pub desc: &'static str,
    /// Program to run.
    pub prog: &'static str,
    /// Arguments.
    pub args: Vec<String>,
}

fn cmd(desc: &'static str, prog: &'static str, args: &[&str]) -> CleanupCmd {
    CleanupCmd {
        desc,
        prog,
        args: args.iter().map(|s| s.to_string()).collect(),
    }
}

/// Firewall (NetworkPolicy) teardown: unhook + delete the KUBE-ROUTER-* filter
/// chains and destroy the local-pods ipset.
fn firewall_cmds() -> Vec<CleanupCmd> {
    let mut v = Vec::new();
    for chain in ["INPUT", "FORWARD", "OUTPUT"] {
        let target = format!("KUBE-ROUTER-{chain}");
        v.push(cmd(
            "unhook KUBE-ROUTER filter jump",
            "iptables",
            &["-w", "-t", "filter", "-D", chain, "-j", &target],
        ));
    }
    for chain in [
        "KUBE-ROUTER-INPUT",
        "KUBE-ROUTER-FORWARD",
        "KUBE-ROUTER-OUTPUT",
    ] {
        v.push(cmd(
            "flush filter chain",
            "iptables",
            &["-w", "-t", "filter", "-F", chain],
        ));
        v.push(cmd(
            "delete filter chain",
            "iptables",
            &["-w", "-t", "filter", "-X", chain],
        ));
    }
    for set in ["kube-router-local-pods", "inet6:kube-router-local-pods"] {
        v.push(cmd("destroy ipset", "ipset", &["destroy", set]));
    }
    v
}

/// Service-proxy teardown: clear IPVS, drop the dummy interface, and remove the
/// KUBE-ROUTER-SERVICES / KUBE-ROUTER-HAIRPIN chains + service ipsets.
fn service_proxy_cmds() -> Vec<CleanupCmd> {
    let mut v = vec![
        cmd("clear all IPVS services", "ipvsadm", &["-C"]),
        cmd(
            "delete kube-dummy-if",
            "ip",
            &["link", "del", "kube-dummy-if"],
        ),
        cmd(
            "unhook KUBE-ROUTER-SERVICES INPUT jump",
            "iptables",
            &[
                "-w",
                "-t",
                "filter",
                "-D",
                "INPUT",
                "-j",
                "KUBE-ROUTER-SERVICES",
            ],
        ),
        cmd(
            "flush KUBE-ROUTER-SERVICES",
            "iptables",
            &["-w", "-t", "filter", "-F", "KUBE-ROUTER-SERVICES"],
        ),
        cmd(
            "delete KUBE-ROUTER-SERVICES",
            "iptables",
            &["-w", "-t", "filter", "-X", "KUBE-ROUTER-SERVICES"],
        ),
        cmd(
            "flush KUBE-ROUTER-HAIRPIN",
            "iptables",
            &["-w", "-t", "nat", "-F", "KUBE-ROUTER-HAIRPIN"],
        ),
        cmd(
            "delete KUBE-ROUTER-HAIRPIN",
            "iptables",
            &["-w", "-t", "nat", "-X", "KUBE-ROUTER-HAIRPIN"],
        ),
    ];
    for set in [
        "kube-router-local-ips",
        "kube-router-svip",
        "kube-router-svip-prt",
        "inet6:kube-router-local-ips",
        "inet6:kube-router-svip",
        "inet6:kube-router-svip-prt",
    ] {
        v.push(cmd("destroy ipset", "ipset", &["destroy", set]));
    }
    v
}

/// Router teardown: DSR policy-routing tables/rules + tunnel interfaces.
fn router_cmds() -> Vec<CleanupCmd> {
    vec![
        cmd(
            "flush DSR route table",
            "ip",
            &["route", "flush", "table", "78"],
        ),
        cmd(
            "flush external-IP route table",
            "ip",
            &["route", "flush", "table", "79"],
        ),
        cmd("delete DSR ip rule", "ip", &["rule", "del", "table", "78"]),
        cmd(
            "delete external-IP ip rule",
            "ip",
            &["rule", "del", "table", "79"],
        ),
        cmd(
            "delete kube-tunnel-if",
            "ip",
            &["link", "del", "kube-tunnel-if"],
        ),
        cmd(
            "delete kube-tunnel-v6",
            "ip",
            &["link", "del", "kube-tunnel-v6"],
        ),
    ]
}

/// The full ordered teardown plan for a configuration (proxy → firewall →
/// router, so service VIPs stop before their firewall/routes).
pub fn cleanup_plan(config: &KubeRouterConfig) -> Vec<CleanupCmd> {
    let mut v = Vec::new();
    if config.run_service_proxy {
        v.extend(service_proxy_cmds());
    }
    if config.run_firewall {
        v.extend(firewall_cmds());
    }
    if config.run_router {
        v.extend(router_cmds());
    }
    v
}

/// Run cleanup for whichever subsystems the configuration enables, then return
/// (the caller exits). Each command is tolerant of already-absent state.
pub async fn run(config: &KubeRouterConfig) -> anyhow::Result<()> {
    tracing::info!("cleanup-config: removing kube-router-rs owned state");
    run_plan(&cleanup_plan(config)).await;
    // Dynamically-named netpol chains (per-pod / per-policy) are swept by prefix.
    if config.run_firewall {
        sweep_dynamic_chains().await;
    }
    Ok(())
}

/// Execute a plan, logging (not failing on) per-command errors.
pub async fn run_plan(plan: &[CleanupCmd]) {
    for c in plan {
        let out = tokio::process::Command::new(c.prog)
            .args(&c.args)
            .output()
            .await;
        match out {
            Ok(o) if o.status.success() => tracing::info!("cleanup: {}", c.desc),
            Ok(o) => tracing::debug!(
                "cleanup: {} (skipped: {})",
                c.desc,
                String::from_utf8_lossy(&o.stderr).trim()
            ),
            Err(e) => tracing::warn!("cleanup: {} spawn failed: {e}", c.desc),
        }
    }
}

/// Flush+delete dynamically-named netpol chains (`KUBE-POD-FW-*`,
/// `KUBE-NWPLCY-*`) discovered from the live filter table, for v4 and v6.
async fn sweep_dynamic_chains() {
    for bin in ["iptables", "ip6tables"] {
        let save = tokio::process::Command::new(format!("{bin}-save"))
            .args(["-t", "filter"])
            .output()
            .await;
        let Ok(out) = save else { continue };
        let doc = String::from_utf8_lossy(&out.stdout);
        let chains: Vec<String> = doc
            .lines()
            .filter_map(|l| l.strip_prefix(':'))
            .filter_map(|l| l.split_whitespace().next())
            .filter(|c| c.starts_with("KUBE-POD-FW-") || c.starts_with("KUBE-NWPLCY-"))
            .map(String::from)
            .collect();
        for chain in chains {
            let _ = tokio::process::Command::new(bin)
                .args(["-w", "-t", "filter", "-F", &chain])
                .output()
                .await;
            let _ = tokio::process::Command::new(bin)
                .args(["-w", "-t", "filter", "-X", &chain])
                .output()
                .await;
        }
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

    fn has(plan: &[CleanupCmd], prog: &str, needle: &str) -> bool {
        plan.iter()
            .any(|c| c.prog == prog && c.args.iter().any(|a| a.contains(needle)))
    }

    #[test]
    fn default_cleanup_covers_all_three_controllers() {
        let plan = cleanup_plan(&cfg(&[]));
        // firewall
        assert!(has(&plan, "iptables", "KUBE-ROUTER-INPUT"));
        assert!(has(&plan, "ipset", "kube-router-local-pods"));
        // service proxy
        assert!(has(&plan, "ipvsadm", "-C"));
        assert!(has(&plan, "ip", "kube-dummy-if"));
        assert!(has(&plan, "iptables", "KUBE-ROUTER-SERVICES"));
        assert!(has(&plan, "iptables", "KUBE-ROUTER-HAIRPIN"));
        assert!(has(&plan, "ipset", "kube-router-svip"));
        // router
        assert!(has(&plan, "ip", "kube-tunnel-if"));
        assert!(has(&plan, "ip", "78"));
    }

    #[test]
    fn firewall_only_cleanup_skips_ipvs_and_routes() {
        let plan = cleanup_plan(&cfg(&["--run-service-proxy=false", "--run-router=false"]));
        assert!(has(&plan, "iptables", "KUBE-ROUTER-INPUT"));
        assert!(!has(&plan, "ipvsadm", "-C"));
        assert!(!has(&plan, "ip", "kube-tunnel-if"));
    }

    #[test]
    fn service_proxy_only_cleanup_skips_firewall_and_router() {
        let plan = cleanup_plan(&cfg(&[
            "--run-firewall=false",
            "--run-service-proxy=true",
            "--run-router=false",
        ]));
        assert!(has(&plan, "ipvsadm", "-C"));
        assert!(!has(&plan, "ipset", "kube-router-local-pods"));
        assert!(!has(&plan, "ip", "table"));
    }

    #[test]
    fn teardown_order_proxy_before_router() {
        // VIP/IPVS state is torn down before the routes/tunnels that carry it.
        let plan = cleanup_plan(&cfg(&[]));
        let ipvs = plan.iter().position(|c| c.prog == "ipvsadm").unwrap();
        let tunnel = plan
            .iter()
            .position(|c| c.args.iter().any(|a| a == "kube-tunnel-if"))
            .unwrap();
        assert!(ipvs < tunnel);
    }

    #[test]
    fn v6_ipset_variants_included() {
        let plan = cleanup_plan(&cfg(&[]));
        assert!(has(&plan, "ipset", "inet6:kube-router-svip"));
        assert!(has(&plan, "ipset", "inet6:kube-router-local-pods"));
    }
}
