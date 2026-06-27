//! Direct Server Return (DSR), mirroring the DSR paths in
//! `network_services_controller.go` / `linux_networking.go` / `utils.go`.
//!
//! DSR lets endpoints reply directly to clients (bypassing the director) using
//! the service VIP as source. The director marks VIP traffic with a per-service
//! FWMARK (so the VIP is never bound to an interface — avoiding martians), runs a
//! FWMARK-based IPVS service forwarding via IPIP tunnel to the endpoint, and the
//! endpoint pod decapsulates on a `kube-tunnel-if` tunnel that owns the VIP.
//!
//! This module provides the FWMARK registry and the pure rule/command builders;
//! the netns tunnel execution (entering the pod via its CRI PID) is the in-cluster
//! runtime layer.

use crate::ipvs::{IpvsDestination, IpvsError, IpvsOps};
use crate::model::{EndpointInfo, Protocol, Scheduler};
use crate::tcpmss::{MangleError, MangleOps};

/// Tunnel interface owning the VIP in the endpoint pod (IPv4).
pub const KUBE_TUNNEL_IF_V4: &str = "kube-tunnel-if";
/// Tunnel interface owning the VIP in the endpoint pod (IPv6).
pub const KUBE_TUNNEL_IF_V6: &str = "kube-tunnel-v6";
/// Custom routing table delivering FWMARKed packets locally.
pub const DSR_ROUTE_TABLE_ID: u32 = 78;
/// Name for [`DSR_ROUTE_TABLE_ID`].
pub const DSR_ROUTE_TABLE_NAME: &str = "kube-router-dsr";
/// Routing table for external-IP return routes.
pub const EXTERNAL_IP_ROUTE_TABLE_ID: u32 = 79;
/// Name for [`EXTERNAL_IP_ROUTE_TABLE_ID`].
pub const EXTERNAL_IP_ROUTE_TABLE_NAME: &str = "external_ip";
/// `ip rule` priority for the FWMARK → DSR table lookup.
pub const TRAFFIC_DIRECTOR_RULE_PRIORITY: u32 = 32764;
/// `ip rule` priority for the external-IP table lookup.
pub const DSR_POLICY_RULE_PRIORITY: u32 = 32765;
/// FWMARK values are masked to 14 bits.
const MAX_FWMARK: u32 = 0x3FFF;
/// Max collision-resolution attempts when assigning a unique FWMARK.
const MAX_UNIQUE_FWMARK_INC: i32 = 16380;

/// DSR error.
#[derive(Debug, thiserror::Error)]
pub enum DsrError {
    /// No unique FWMARK could be assigned.
    #[error("could not obtain a unique FWMark for {0} after {1} tries")]
    FwMarkExhausted(String, i32),
    /// IPVS failure.
    #[error(transparent)]
    Ipvs(#[from] IpvsError),
    /// mangle-table failure.
    #[error(transparent)]
    Mangle(#[from] MangleError),
}

fn proto_name(p: Protocol) -> &'static str {
    match p {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        Protocol::Sctp => "sctp",
    }
}

/// 32-bit FNV-1a hash.
fn fnv1a_32(data: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for &b in data {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

/// FNV-1a hash of `ip-proto-port[-increment]`, masked to 14 bits (matches
/// `generateFWMark`).
pub fn generate_fwmark(service_key: &str, increment: i32) -> u32 {
    let s = if increment == 0 {
        service_key.to_string()
    } else {
        format!("{service_key}-{increment}")
    };
    fnv1a_32(s.as_bytes()) & MAX_FWMARK
}

/// Service identity key (`ip-proto-port`) used for FWMARK assignment.
pub fn service_key(ip: &str, proto: Protocol, port: u16) -> String {
    format!("{ip}-{}-{port}", proto_name(proto))
}

/// Bidirectional FWMARK ↔ service registry (mirrors `fwMarkMap`).
#[derive(Debug, Default)]
pub struct FwMarkRegistry {
    map: std::collections::BTreeMap<u32, String>,
}

impl FwMarkRegistry {
    /// New empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Assign (or return the existing) unique FWMARK for a service identity,
    /// resolving collisions by salting the hash (mirrors `generateUniqueFWMark`).
    pub fn assign(&mut self, ip: &str, proto: Protocol, port: u16) -> Result<u32, DsrError> {
        let key = service_key(ip, proto, port);
        let mut increment = 0;
        loop {
            let mark = generate_fwmark(&key, increment);
            match self.map.get(&mark) {
                Some(found) if found != &key => {
                    increment += 1;
                    if increment >= MAX_UNIQUE_FWMARK_INC {
                        return Err(DsrError::FwMarkExhausted(key, MAX_UNIQUE_FWMARK_INC));
                    }
                    continue;
                }
                _ => {
                    self.map.insert(mark, key);
                    return Ok(mark);
                }
            }
        }
    }

    /// FWMARK for a service identity, if assigned.
    pub fn lookup_by_service(&self, ip: &str, proto: Protocol, port: u16) -> Option<u32> {
        let key = service_key(ip, proto, port);
        self.map.iter().find(|(_, v)| **v == key).map(|(m, _)| *m)
    }

    /// Service `(ip, proto, port)` for a FWMARK, if known.
    pub fn lookup_by_fwmark(&self, fwmark: u32) -> Option<(String, String, u16)> {
        let key = self.map.get(&fwmark)?;
        let parts: Vec<&str> = key.split('-').collect();
        if parts.len() != 3 {
            return None;
        }
        Some((parts[0].into(), parts[1].into(), parts[2].parse().ok()?))
    }

    /// Drop a FWMARK assignment (after a DSR service is removed).
    pub fn remove(&mut self, fwmark: u32) {
        self.map.remove(&fwmark);
    }
}

/// mangle MARK rule args (the FWMARK half of `setupMangleTableRule`): mark
/// traffic destined for the VIP:port so the FWMARK IPVS service handles it.
pub fn dsr_mark_args(ip: std::net::IpAddr, proto: Protocol, port: u16, fwmark: u32) -> Vec<String> {
    let p = proto_name(proto);
    vec![
        "-d".into(),
        ip.to_string(),
        "-m".into(),
        p.into(),
        "-p".into(),
        p.into(),
        "--dport".into(),
        port.to_string(),
        "-j".into(),
        "MARK".into(),
        "--set-mark".into(),
        fwmark.to_string(),
    ]
}

/// `ip rule` args routing FWMARKed packets to the DSR table (priority 32764).
pub fn ip_rule_fwmark_args(op: &str, fwmark: u32, table: u32, priority: u32) -> Vec<String> {
    vec![
        "rule".into(),
        op.into(),
        "fwmark".into(),
        fwmark.to_string(),
        "table".into(),
        table.to_string(),
        "priority".into(),
        priority.to_string(),
    ]
}

/// `ip rule add from all lookup <table> prio <priority>` for external-IP returns.
pub fn ip_rule_from_all_args(op: &str, table: u32, priority: u32) -> Vec<String> {
    vec![
        "rule".into(),
        op.into(),
        "from".into(),
        "all".into(),
        "lookup".into(),
        table.to_string(),
        "priority".into(),
        priority.to_string(),
    ]
}

/// `/etc/iproute2/rt_tables` entry line for a custom routing table.
pub fn rt_tables_entry(id: u32, name: &str) -> String {
    format!("{id} {name}")
}

/// `sysctl` key disabling reverse-path filtering for an interface.
pub fn rp_filter_key(iface: &str) -> String {
    format!("net.ipv4.conf.{iface}.rp_filter")
}

/// Commands (each an arg vector for `ip`) to set up the decapsulating tunnel
/// inside the endpoint pod's netns: create `kube-tunnel-if`, bring it up, and
/// assign the VIP. Run via `nsenter -t <pid> -n ip ...`.
pub fn tunnel_setup_commands(vip: std::net::IpAddr) -> Vec<Vec<String>> {
    let (name, mode) = if vip.is_ipv6() {
        (KUBE_TUNNEL_IF_V6, "ip6tnl")
    } else {
        (KUBE_TUNNEL_IF_V4, "ipip")
    };
    let plen = if vip.is_ipv6() { "128" } else { "32" };
    vec![
        vec![
            "link".into(),
            "add".into(),
            name.into(),
            "type".into(),
            mode.into(),
        ],
        vec!["link".into(), "set".into(), name.into(), "up".into()],
        vec![
            "addr".into(),
            "add".into(),
            format!("{vip}/{plen}"),
            "dev".into(),
            name.into(),
        ],
    ]
}

/// Configure the host-side DSR datapath for a service's VIPs: assign a FWMARK,
/// create the FWMARK IPVS service with tunnel destinations, and mark VIP traffic
/// in `mangle` PREROUTING + OUTPUT. Returns the assigned FWMARKs.
#[allow(clippy::too_many_arguments)]
pub async fn configure_dsr_host<I, M>(
    ipvs: &I,
    mangle: &M,
    registry: &mut FwMarkRegistry,
    vips: &[std::net::IpAddr],
    proto: Protocol,
    port: u16,
    endpoints: &[EndpointInfo],
    scheduler: Scheduler,
    persistent: Option<u32>,
) -> Result<Vec<u32>, DsrError>
where
    I: IpvsOps + ?Sized,
    M: MangleOps + ?Sized,
{
    let mut marks = Vec::new();
    for vip in vips {
        let fwmark = registry.assign(&vip.to_string(), proto, port)?;
        ipvs.add_fwmark_service(fwmark, scheduler, persistent)
            .await?;
        for ep in endpoints.iter().filter(|e| e.ready) {
            ipvs.add_fwmark_destination(
                fwmark,
                &IpvsDestination {
                    addr: ep.ip,
                    port: ep.port,
                    weight: 1,
                    tunnel: true,
                },
            )
            .await?;
        }
        let mark_rule = dsr_mark_args(*vip, proto, port, fwmark);
        mangle.append_unique("PREROUTING", &mark_rule).await?;
        mangle.append_unique("OUTPUT", &mark_rule).await?;
        marks.push(fwmark);
    }
    Ok(marks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipvs::mock::MockIpvs;
    use crate::tcpmss::mock::MockMangle;

    #[test]
    fn fwmark_is_deterministic_and_14_bit() {
        let m = generate_fwmark("10.96.0.10-tcp-80", 0);
        assert_eq!(m, generate_fwmark("10.96.0.10-tcp-80", 0));
        assert!(m <= MAX_FWMARK);
        // Salting changes the value.
        assert_ne!(m, generate_fwmark("10.96.0.10-tcp-80", 1));
    }

    #[test]
    fn registry_assigns_and_looks_up_both_ways() {
        let mut reg = FwMarkRegistry::new();
        let m = reg.assign("10.96.0.10", Protocol::Tcp, 80).unwrap();
        // Re-assigning the same service returns the same mark.
        assert_eq!(reg.assign("10.96.0.10", Protocol::Tcp, 80).unwrap(), m);
        assert_eq!(
            reg.lookup_by_service("10.96.0.10", Protocol::Tcp, 80),
            Some(m)
        );
        assert_eq!(
            reg.lookup_by_fwmark(m),
            Some(("10.96.0.10".into(), "tcp".into(), 80))
        );
        reg.remove(m);
        assert_eq!(reg.lookup_by_service("10.96.0.10", Protocol::Tcp, 80), None);
    }

    #[test]
    fn registry_resolves_collisions_to_distinct_marks() {
        let mut reg = FwMarkRegistry::new();
        let a = reg.assign("10.96.0.10", Protocol::Tcp, 80).unwrap();
        let b = reg.assign("10.96.0.11", Protocol::Tcp, 80).unwrap();
        let c = reg.assign("10.96.0.10", Protocol::Udp, 80).unwrap();
        // Distinct services get distinct marks.
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn mark_and_rule_builders_match_shape() {
        let m = dsr_mark_args("203.0.113.5".parse().unwrap(), Protocol::Tcp, 80, 1234);
        assert_eq!(
            m,
            vec![
                "-d",
                "203.0.113.5",
                "-m",
                "tcp",
                "-p",
                "tcp",
                "--dport",
                "80",
                "-j",
                "MARK",
                "--set-mark",
                "1234"
            ]
        );
        let r = ip_rule_fwmark_args(
            "add",
            1234,
            DSR_ROUTE_TABLE_ID,
            TRAFFIC_DIRECTOR_RULE_PRIORITY,
        );
        assert_eq!(
            r,
            vec!["rule", "add", "fwmark", "1234", "table", "78", "priority", "32764"]
        );
        assert_eq!(rt_tables_entry(78, "kube-router-dsr"), "78 kube-router-dsr");
        assert_eq!(
            rp_filter_key("kube-tunnel-if"),
            "net.ipv4.conf.kube-tunnel-if.rp_filter"
        );
    }

    #[test]
    fn tunnel_commands_select_family() {
        let v4 = tunnel_setup_commands("203.0.113.5".parse().unwrap());
        assert!(
            v4[0].contains(&"ipip".to_string()) && v4[0].contains(&"kube-tunnel-if".to_string())
        );
        assert!(v4[2].contains(&"203.0.113.5/32".to_string()));
        let v6 = tunnel_setup_commands("fd00::5".parse().unwrap());
        assert!(
            v6[0].contains(&"ip6tnl".to_string()) && v6[0].contains(&"kube-tunnel-v6".to_string())
        );
        assert!(v6[2].contains(&"fd00::5/128".to_string()));
    }

    #[tokio::test]
    async fn configure_dsr_host_programs_fwmark_service_dests_and_marks() {
        let ipvs = MockIpvs::new();
        let mangle = MockMangle::new();
        let mut reg = FwMarkRegistry::new();
        let eps = vec![
            EndpointInfo {
                ip: "10.244.0.5".parse().unwrap(),
                port: 8080,
                is_local: false,
                ready: true,
            },
            EndpointInfo {
                ip: "10.244.1.5".parse().unwrap(),
                port: 8080,
                is_local: false,
                ready: false, // not ready → skipped
            },
        ];
        let marks = configure_dsr_host(
            &ipvs,
            &mangle,
            &mut reg,
            &["203.0.113.5".parse().unwrap()],
            Protocol::Tcp,
            80,
            &eps,
            Scheduler::Rr,
            None,
        )
        .await
        .unwrap();

        assert_eq!(marks.len(), 1);
        assert_eq!(ipvs.fwmark_services(), marks);
        // Only the ready endpoint becomes a tunnel destination.
        let dests = ipvs.fwmark_dests();
        assert_eq!(dests.len(), 1);
        assert_eq!(dests[0].0, marks[0]);
        assert!(dests[0].1.tunnel);
        // MARK rule installed in both PREROUTING and OUTPUT.
        let appended = mangle.appended.lock().unwrap();
        assert!(appended.iter().any(|(c, _)| c == "PREROUTING"));
        assert!(appended.iter().any(|(c, _)| c == "OUTPUT"));
    }
}
