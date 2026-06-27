//! Frozen parity test: every flag from `contracts/cli-flags.md`
//! (sourced from `upstream/pkg/options/options.go`) must exist with the exact
//! name, and key defaults must match. Guards against drift (FR-003, FR-074).

use std::time::Duration;

use clap::CommandFactory;
use kr_config::KubeRouterConfig;

/// Every long flag the upstream option set defines.
const EXPECTED_FLAGS: &[&str] = &[
    "advertise-cluster-ip",
    "advertise-external-ip",
    "advertise-loadbalancer-ip",
    "advertise-pod-cidr",
    "auto-mtu",
    "bgp-graceful-restart",
    "bgp-graceful-restart-deferral-time",
    "bgp-graceful-restart-time",
    "bgp-holdtime",
    "bgp-port",
    "cache-sync-timeout",
    "cleanup-config",
    "cluster-asn",
    "disable-source-dest-check",
    "enable-cni",
    "enable-ibgp",
    "enable-ipv4",
    "enable-ipv6",
    "enable-overlay",
    "enable-pod-egress",
    "enable-pprof",
    "excluded-cidrs",
    "hairpin-mode",
    "gobgp-admin-address",
    "gobgp-admin-port",
    "health-addr",
    "health-port",
    "hostname-override",
    "injected-routes-sync-period",
    "iptables-sync-period",
    "ipvs-graceful-period",
    "ipvs-graceful-termination",
    "ipvs-permit-all",
    "ipvs-sync-period",
    "kubeconfig",
    "loadbalancer-default-class",
    "loadbalancer-ip-range",
    "loadbalancer-sync-period",
    "masquerade-all",
    "master",
    "metrics-path",
    "metrics-port",
    "metrics-addr",
    "netpol-default-deny",
    "nodeport-bindon-all-ip",
    "nodes-full-mesh",
    "overlay-encap",
    "overlay-encap-port",
    "overlay-type",
    "override-nexthop",
    "peer-router-asns",
    "peer-router-ips",
    "peer-router-multihop-ttl",
    "peer-router-passwords",
    "peer-router-passwords-file",
    "peer-router-ports",
    "router-id",
    "routes-sync-period",
    "run-firewall",
    "run-loadbalancer",
    "run-router",
    "run-service-proxy",
    "runtime-endpoint",
    "service-cluster-ip-range",
    "strict-external-ip-validation",
    "service-external-ip-range",
    "service-node-port-range",
    "service-tcp-timeout",
    "service-tcpfin-timeout",
    "service-udp-timeout",
    "v",
];

fn defaults() -> KubeRouterConfig {
    KubeRouterConfig::try_parse_from(["kube-router-rs"]).expect("defaults parse")
}

#[test]
fn all_upstream_flags_present() {
    let cmd = KubeRouterConfig::command();
    let present: Vec<String> = cmd
        .get_arguments()
        .filter_map(|a| a.get_long())
        .map(|s| s.to_string())
        .collect();

    for want in EXPECTED_FLAGS {
        assert!(
            present.iter().any(|p| p == want),
            "missing flag --{want}; present: {present:?}"
        );
    }
}

#[test]
fn version_and_help_available() {
    // clap provides --version/-V and --help/-h; parsing them is a special error kind.
    let v = KubeRouterConfig::try_parse_from(["kube-router-rs", "--version"]).unwrap_err();
    assert_eq!(v.kind(), clap::error::ErrorKind::DisplayVersion);
    let h = KubeRouterConfig::try_parse_from(["kube-router-rs", "--help"]).unwrap_err();
    assert_eq!(h.kind(), clap::error::ErrorKind::DisplayHelp);
}

#[test]
fn controller_default_toggles_match_upstream() {
    let c = defaults();
    assert!(c.run_router, "run-router defaults true");
    assert!(c.run_firewall, "run-firewall defaults true");
    assert!(c.run_service_proxy, "run-service-proxy defaults true");
    assert!(!c.run_loadbalancer, "run-loadbalancer defaults false");
}

#[test]
fn family_defaults_match_upstream() {
    let c = defaults();
    assert!(c.enable_ipv4);
    assert!(!c.enable_ipv6);
}

#[test]
fn numeric_and_string_defaults_match_upstream() {
    let c = defaults();
    assert_eq!(c.bgp_port, 179);
    assert_eq!(c.gobgp_admin_address, "127.0.0.1");
    assert_eq!(c.gobgp_admin_port, 50051);
    assert_eq!(c.health_port, 20244);
    assert_eq!(c.metrics_port, 0);
    assert_eq!(c.metrics_path, "/metrics");
    assert_eq!(c.overlay_encap, "ipip");
    assert_eq!(c.overlay_type, "subnet");
    assert_eq!(c.overlay_encap_port, 5555);
    assert_eq!(c.service_node_port_range, "30000-32767");
    assert_eq!(c.service_cluster_ip_range, vec!["10.96.0.0/12".to_string()]);
    assert_eq!(c.v_level, "0");
    assert_eq!(c.cluster_asn, 0);
    assert_eq!(c.peer_router_multihop_ttl, 0);
}

#[test]
fn duration_defaults_match_upstream() {
    let c = defaults();
    assert_eq!(c.bgp_holdtime, Duration::from_secs(90));
    assert_eq!(c.bgp_graceful_restart_time, Duration::from_secs(90));
    assert_eq!(
        c.bgp_graceful_restart_deferral_time,
        Duration::from_secs(360)
    );
    assert_eq!(c.cache_sync_timeout, Duration::from_secs(60));
    assert_eq!(c.iptables_sync_period, Duration::from_secs(300));
    assert_eq!(c.ipvs_sync_period, Duration::from_secs(300));
    assert_eq!(c.routes_sync_period, Duration::from_secs(300));
    assert_eq!(c.injected_routes_sync_period, Duration::from_secs(60));
    assert_eq!(c.ipvs_graceful_period, Duration::from_secs(30));
    assert_eq!(c.loadbalancer_sync_period, Duration::from_secs(60));
    assert_eq!(c.service_tcp_timeout, Duration::from_secs(0));
}

#[test]
fn bool_flag_accepts_explicit_false() {
    let c = KubeRouterConfig::try_parse_from(["kube-router-rs", "--run-router=false"]).unwrap();
    assert!(!c.run_router);
    let c2 = KubeRouterConfig::try_parse_from(["kube-router-rs", "--run-loadbalancer"]).unwrap();
    assert!(c2.run_loadbalancer, "bare bool flag sets true");
}
