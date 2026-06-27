//! `KubeRouterConfig`: the runtime configuration parsed from CLI flags.
//!
//! Names, types, and defaults reproduce `upstream/pkg/options/options.go`
//! verbatim (parity contract — see `contracts/cli-flags.md`). The matching
//! contract test lives in `tests/flag_parity.rs`.

use std::net::IpAddr;
use std::time::Duration;

use clap::{ArgAction, Parser};

pub mod validate;

fn parse_go_duration(s: &str) -> Result<Duration, String> {
    humantime::parse_duration(s).map_err(|e| format!("invalid duration {s:?}: {e}"))
}

/// Parsed kube-router-rs configuration.
#[derive(Debug, Clone, Parser)]
#[command(
    name = "kube-router-rs",
    version,
    about = "kube-router, reimplemented in Rust (feature parity with the Go upstream)"
)]
pub struct KubeRouterConfig {
    // ---- Route/service advertisement ----
    #[arg(long = "advertise-cluster-ip", num_args = 0..=1, default_missing_value = "true", default_value_t = false, action = ArgAction::Set)]
    pub advertise_cluster_ip: bool,
    #[arg(long = "advertise-external-ip", num_args = 0..=1, default_missing_value = "true", default_value_t = false, action = ArgAction::Set)]
    pub advertise_external_ip: bool,
    #[arg(long = "advertise-loadbalancer-ip", num_args = 0..=1, default_missing_value = "true", default_value_t = false, action = ArgAction::Set)]
    pub advertise_loadbalancer_ip: bool,
    #[arg(long = "advertise-pod-cidr", num_args = 0..=1, default_missing_value = "true", default_value_t = true, action = ArgAction::Set)]
    pub advertise_pod_cidr: bool,

    #[arg(long = "auto-mtu", num_args = 0..=1, default_missing_value = "true", default_value_t = true, action = ArgAction::Set)]
    pub auto_mtu: bool,

    // ---- BGP ----
    #[arg(long = "bgp-graceful-restart", num_args = 0..=1, default_missing_value = "true", default_value_t = false, action = ArgAction::Set)]
    pub bgp_graceful_restart: bool,
    #[arg(long = "bgp-graceful-restart-deferral-time", value_parser = parse_go_duration, default_value = "360s")]
    pub bgp_graceful_restart_deferral_time: Duration,
    #[arg(long = "bgp-graceful-restart-time", value_parser = parse_go_duration, default_value = "90s")]
    pub bgp_graceful_restart_time: Duration,
    #[arg(long = "bgp-holdtime", value_parser = parse_go_duration, default_value = "90s")]
    pub bgp_holdtime: Duration,
    #[arg(long = "bgp-port", default_value_t = 179)]
    pub bgp_port: u32,

    #[arg(long = "cache-sync-timeout", value_parser = parse_go_duration, default_value = "1m")]
    pub cache_sync_timeout: Duration,
    #[arg(long = "cleanup-config", num_args = 0..=1, default_missing_value = "true", default_value_t = false, action = ArgAction::Set)]
    pub cleanup_config: bool,
    #[arg(long = "cluster-asn", default_value_t = 0)]
    pub cluster_asn: u32,

    #[arg(long = "disable-source-dest-check", num_args = 0..=1, default_missing_value = "true", default_value_t = true, action = ArgAction::Set)]
    pub disable_source_dest_check: bool,

    // ---- Feature toggles ----
    #[arg(long = "enable-cni", num_args = 0..=1, default_missing_value = "true", default_value_t = true, action = ArgAction::Set)]
    pub enable_cni: bool,
    #[arg(long = "enable-ibgp", num_args = 0..=1, default_missing_value = "true", default_value_t = true, action = ArgAction::Set)]
    pub enable_ibgp: bool,
    #[arg(long = "enable-ipv4", num_args = 0..=1, default_missing_value = "true", default_value_t = true, action = ArgAction::Set)]
    pub enable_ipv4: bool,
    #[arg(long = "enable-ipv6", num_args = 0..=1, default_missing_value = "true", default_value_t = false, action = ArgAction::Set)]
    pub enable_ipv6: bool,
    #[arg(long = "enable-overlay", num_args = 0..=1, default_missing_value = "true", default_value_t = true, action = ArgAction::Set)]
    pub enable_overlay: bool,
    #[arg(long = "enable-pod-egress", num_args = 0..=1, default_missing_value = "true", default_value_t = true, action = ArgAction::Set)]
    pub enable_pod_egress: bool,
    #[arg(long = "enable-pprof", num_args = 0..=1, default_missing_value = "true", default_value_t = false, action = ArgAction::Set)]
    pub enable_pprof: bool,

    #[arg(long = "excluded-cidrs", value_delimiter = ',')]
    pub excluded_cidrs: Vec<String>,

    #[arg(long = "hairpin-mode", num_args = 0..=1, default_missing_value = "true", default_value_t = false, action = ArgAction::Set)]
    pub hairpin_mode: bool,

    #[arg(long = "gobgp-admin-address", default_value = "127.0.0.1")]
    pub gobgp_admin_address: String,
    #[arg(long = "gobgp-admin-port", default_value_t = 50051)]
    pub gobgp_admin_port: u16,

    #[arg(long = "health-addr", default_value = "")]
    pub health_addr: String,
    #[arg(long = "health-port", default_value_t = 20244)]
    pub health_port: u16,

    #[arg(long = "hostname-override", default_value = "")]
    pub hostname_override: String,

    // ---- Sync periods ----
    #[arg(long = "injected-routes-sync-period", value_parser = parse_go_duration, default_value = "60s")]
    pub injected_routes_sync_period: Duration,
    #[arg(long = "iptables-sync-period", value_parser = parse_go_duration, default_value = "5m")]
    pub iptables_sync_period: Duration,
    #[arg(long = "ipvs-graceful-period", value_parser = parse_go_duration, default_value = "30s")]
    pub ipvs_graceful_period: Duration,
    #[arg(long = "ipvs-graceful-termination", num_args = 0..=1, default_missing_value = "true", default_value_t = false, action = ArgAction::Set)]
    pub ipvs_graceful_termination: bool,
    #[arg(long = "ipvs-permit-all", num_args = 0..=1, default_missing_value = "true", default_value_t = true, action = ArgAction::Set)]
    pub ipvs_permit_all: bool,
    #[arg(long = "ipvs-sync-period", value_parser = parse_go_duration, default_value = "5m")]
    pub ipvs_sync_period: Duration,

    #[arg(long = "kubeconfig", default_value = "")]
    pub kubeconfig: String,

    #[arg(long = "loadbalancer-default-class", num_args = 0..=1, default_missing_value = "true", default_value_t = true, action = ArgAction::Set)]
    pub loadbalancer_default_class: bool,
    #[arg(long = "loadbalancer-ip-range", value_delimiter = ',')]
    pub loadbalancer_ip_range: Vec<String>,
    #[arg(long = "loadbalancer-sync-period", value_parser = parse_go_duration, default_value = "1m")]
    pub loadbalancer_sync_period: Duration,

    #[arg(long = "masquerade-all", num_args = 0..=1, default_missing_value = "true", default_value_t = false, action = ArgAction::Set)]
    pub masquerade_all: bool,
    #[arg(long = "master", default_value = "")]
    pub master: String,

    #[arg(long = "metrics-path", default_value = "/metrics")]
    pub metrics_path: String,
    #[arg(long = "metrics-port", default_value_t = 0)]
    pub metrics_port: u16,
    #[arg(long = "metrics-addr", default_value = "")]
    pub metrics_addr: String,

    #[arg(long = "netpol-default-deny", num_args = 0..=1, default_missing_value = "true", default_value_t = false, action = ArgAction::Set)]
    pub netpol_default_deny: bool,

    #[arg(long = "nodeport-bindon-all-ip", num_args = 0..=1, default_missing_value = "true", default_value_t = false, action = ArgAction::Set)]
    pub nodeport_bindon_all_ip: bool,
    #[arg(long = "nodes-full-mesh", num_args = 0..=1, default_missing_value = "true", default_value_t = true, action = ArgAction::Set)]
    pub nodes_full_mesh: bool,

    // ---- Overlay ----
    #[arg(long = "overlay-encap", default_value = "ipip")]
    pub overlay_encap: String,
    #[arg(long = "overlay-encap-port", default_value_t = 5555)]
    pub overlay_encap_port: u16,
    #[arg(long = "overlay-type", default_value = "subnet")]
    pub overlay_type: String,

    #[arg(long = "override-nexthop", num_args = 0..=1, default_missing_value = "true", default_value_t = false, action = ArgAction::Set)]
    pub override_nexthop: bool,

    // ---- External peers ----
    #[arg(long = "peer-router-asns", value_delimiter = ',')]
    pub peer_router_asns: Vec<u32>,
    #[arg(long = "peer-router-ips", value_delimiter = ',')]
    pub peer_router_ips: Vec<IpAddr>,
    #[arg(long = "peer-router-multihop-ttl", default_value_t = 0)]
    pub peer_router_multihop_ttl: u8,
    #[arg(long = "peer-router-passwords", value_delimiter = ',')]
    pub peer_router_passwords: Vec<String>,
    #[arg(long = "peer-router-passwords-file", default_value = "")]
    pub peer_router_passwords_file: String,
    #[arg(long = "peer-router-ports", value_delimiter = ',')]
    pub peer_router_ports: Vec<u32>,

    #[arg(long = "router-id", default_value = "")]
    pub router_id: String,
    #[arg(long = "routes-sync-period", value_parser = parse_go_duration, default_value = "5m")]
    pub routes_sync_period: Duration,

    // ---- Controller toggles ----
    #[arg(long = "run-firewall", num_args = 0..=1, default_missing_value = "true", default_value_t = true, action = ArgAction::Set)]
    pub run_firewall: bool,
    #[arg(long = "run-loadbalancer", num_args = 0..=1, default_missing_value = "true", default_value_t = false, action = ArgAction::Set)]
    pub run_loadbalancer: bool,
    #[arg(long = "run-router", num_args = 0..=1, default_missing_value = "true", default_value_t = true, action = ArgAction::Set)]
    pub run_router: bool,
    #[arg(long = "run-service-proxy", num_args = 0..=1, default_missing_value = "true", default_value_t = true, action = ArgAction::Set)]
    pub run_service_proxy: bool,

    #[arg(long = "runtime-endpoint", default_value = "")]
    pub runtime_endpoint: String,

    // ---- Service proxy ranges/timeouts ----
    #[arg(long = "service-cluster-ip-range", value_delimiter = ',', default_values_t = vec!["10.96.0.0/12".to_string()])]
    pub service_cluster_ip_range: Vec<String>,
    #[arg(long = "strict-external-ip-validation", num_args = 0..=1, default_missing_value = "true", default_value_t = true, action = ArgAction::Set)]
    pub strict_external_ip_validation: bool,
    #[arg(long = "service-external-ip-range", value_delimiter = ',')]
    pub service_external_ip_range: Vec<String>,
    #[arg(long = "service-node-port-range", default_value = "30000-32767")]
    pub service_node_port_range: String,
    #[arg(long = "service-tcp-timeout", value_parser = parse_go_duration, default_value = "0s")]
    pub service_tcp_timeout: Duration,
    #[arg(long = "service-tcpfin-timeout", value_parser = parse_go_duration, default_value = "0s")]
    pub service_tcpfin_timeout: Duration,
    #[arg(long = "service-udp-timeout", value_parser = parse_go_duration, default_value = "0s")]
    pub service_udp_timeout: Duration,

    // ---- Logging/version ----
    #[arg(long = "v", short = 'v', default_value = "0")]
    pub v_level: String,
}

impl KubeRouterConfig {
    /// Parse from the process arguments (clap handles `--help`/`--version`).
    pub fn parse_args() -> Self {
        <Self as Parser>::parse()
    }

    /// Parse from an explicit argument iterator (used by tests).
    pub fn try_parse_from<I, T>(itr: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        <Self as Parser>::try_parse_from(itr)
    }
}
