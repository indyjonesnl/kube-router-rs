//! IPVS service firewall, mirroring `setupIpvsFirewall`/`syncIpvsFirewall` in
//! `network_services_controller.go`.
//!
//! With `--ipvs-permit-all=false` kube-router restricts input traffic to IPVS
//! service VIPs: a `KUBE-ROUTER-SERVICES` filter chain (jumped to from INPUT for
//! packets destined to a service IP) allows essential ICMP and exact
//! `service-ip,proto:port` matches, and REJECTs everything else not addressed to
//! a local node IP. Membership is driven by ipsets refreshed from the live IPVS
//! services + local addresses each sync.

use std::net::IpAddr;

use async_trait::async_trait;

use crate::model::Protocol;

/// Set of local node addresses (so NodePort/local traffic isn't rejected).
pub const LOCAL_IPS_SET: &str = "kube-router-local-ips";
/// Set of service VIPs (hash:ip) — used by the INPUT jump match.
pub const SERVICE_IPS_SET: &str = "kube-router-svip";
/// Set of service VIP + proto:port tuples (hash:ip,port) — the ACCEPT match.
pub const SERVICE_IP_PORTS_SET: &str = "kube-router-svip-prt";
/// Filter chain holding the IPVS service firewall rules.
pub const FIREWALL_CHAIN: &str = "KUBE-ROUTER-SERVICES";

/// ipset name for a base set in the given family (`inet6:` prefix for IPv6).
pub fn ipset_name(base: &str, ipv6: bool) -> String {
    if ipv6 {
        format!("inet6:{base}")
    } else {
        base.to_string()
    }
}

fn proto_name(p: Protocol) -> &'static str {
    match p {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        // ipset wants the numeric protocol for SCTP.
        Protocol::Sctp => "132",
    }
}

/// Essential ICMP ACCEPT rule args for the firewall chain (mirrors
/// `CommonICMPRules`): echo-request, destination-unreachable (PMTU),
/// time-exceeded, plus IPv6 neighbor discovery / echo-reply.
pub fn icmp_accept_rules(ipv6: bool) -> Vec<Vec<String>> {
    let (proto, type_flag) = if ipv6 {
        ("ipv6-icmp", "--icmpv6-type")
    } else {
        ("icmp", "--icmp-type")
    };
    let mut types = vec![
        ("echo-request", "allow icmp echo requests"),
        (
            "destination-unreachable",
            "allow icmp destination unreachable messages",
        ),
        ("time-exceeded", "allow icmp time exceeded messages"),
    ];
    if ipv6 {
        types.extend([
            (
                "neighbor-solicitation",
                "allow icmp neighbor solicitation messages",
            ),
            (
                "neighbor-advertisement",
                "allow icmp neighbor advertisement messages",
            ),
            ("echo-reply", "allow icmp echo reply messages"),
        ]);
    }
    types
        .into_iter()
        .map(|(t, comment)| {
            vec![
                "-m".into(),
                "comment".into(),
                "--comment".into(),
                comment.into(),
                "-p".into(),
                proto.into(),
                type_flag.into(),
                t.into(),
                "-j".into(),
                "ACCEPT".into(),
            ]
        })
        .collect()
}

/// ACCEPT rule matching exact service `ip,proto:port` membership.
pub fn service_accept_rule(ipv6: bool) -> Vec<String> {
    vec![
        "-m".into(),
        "comment".into(),
        "--comment".into(),
        "allow input traffic to ipvs services".into(),
        "-m".into(),
        "set".into(),
        "--match-set".into(),
        ipset_name(SERVICE_IP_PORTS_SET, ipv6),
        "dst,dst".into(),
        "-j".into(),
        "ACCEPT".into(),
    ]
}

/// REJECT rule for unexpected traffic to service IPs (excludes local addresses).
pub fn reject_rule(ipv6: bool) -> Vec<String> {
    let reject_with = if ipv6 {
        "icmp6-port-unreachable"
    } else {
        "icmp-port-unreachable"
    };
    vec![
        "-m".into(),
        "comment".into(),
        "--comment".into(),
        "reject all unexpected traffic to service IPs".into(),
        "-m".into(),
        "set".into(),
        "!".into(),
        "--match-set".into(),
        ipset_name(LOCAL_IPS_SET, ipv6),
        "dst".into(),
        "-j".into(),
        "REJECT".into(),
        "--reject-with".into(),
        reject_with.into(),
    ]
}

/// INPUT jump rule directing service-IP-destined traffic into the chain.
pub fn input_jump_rule(ipv6: bool) -> Vec<String> {
    vec![
        "-m".into(),
        "comment".into(),
        "--comment".into(),
        "handle traffic to IPVS service IPs in custom chain".into(),
        "-m".into(),
        "set".into(),
        "--match-set".into(),
        ipset_name(SERVICE_IPS_SET, ipv6),
        "dst".into(),
        "-j".into(),
        FIREWALL_CHAIN.into(),
    ]
}

/// Build an `ipset restore` payload that recreates and repopulates the three
/// firewall sets for one family (idempotent via `-exist` + `flush`).
pub fn ipset_restore_payload(
    local_ips: &[IpAddr],
    service_vips: &[(IpAddr, Protocol, u16)],
    ipv6: bool,
) -> String {
    let family = if ipv6 { "inet6" } else { "inet" };
    let mut out = String::new();
    let mut create = |name: &str, kind: &str| {
        out.push_str(&format!(
            "create {name} {kind} family {family} timeout 0 -exist\nflush {name}\n"
        ));
    };
    create(&ipset_name(LOCAL_IPS_SET, ipv6), "hash:ip");
    create(&ipset_name(SERVICE_IPS_SET, ipv6), "hash:ip");
    create(&ipset_name(SERVICE_IP_PORTS_SET, ipv6), "hash:ip,port");

    for ip in local_ips.iter().filter(|ip| ip.is_ipv6() == ipv6) {
        out.push_str(&format!("add {} {ip}\n", ipset_name(LOCAL_IPS_SET, ipv6)));
    }
    for (ip, proto, port) in service_vips
        .iter()
        .filter(|(ip, _, _)| ip.is_ipv6() == ipv6)
    {
        out.push_str(&format!("add {} {ip}\n", ipset_name(SERVICE_IPS_SET, ipv6)));
        out.push_str(&format!(
            "add {} {ip},{}:{port}\n",
            ipset_name(SERVICE_IP_PORTS_SET, ipv6),
            proto_name(*proto)
        ));
    }
    out
}

/// Firewall error.
#[derive(Debug, thiserror::Error)]
#[error("firewall error: {0}")]
pub struct FirewallError(pub String);

/// filter-table operations the firewall needs (per family).
#[async_trait]
pub trait FwIptables: Send + Sync {
    /// Clear (or create) a chain in the filter table.
    async fn clear_chain(&self, chain: &str) -> Result<(), FirewallError>;
    /// Append a rule to a filter chain if not already present.
    async fn append_unique(&self, chain: &str, args: &[String]) -> Result<(), FirewallError>;
    /// Insert a rule at the top of a builtin chain if not already present.
    async fn ensure_top(&self, chain: &str, args: &[String]) -> Result<(), FirewallError>;
    /// Delete a rule from a chain (tolerant).
    async fn delete(&self, chain: &str, args: &[String]) -> Result<(), FirewallError>;
}

/// ipset restore operation.
#[async_trait]
pub trait FwIpset: Send + Sync {
    /// Apply an `ipset restore -exist` payload.
    async fn restore(&self, payload: &str) -> Result<(), FirewallError>;
}

/// Configure the firewall chain for one family. When `permit_all` the chain is
/// just cleared (no restrictions) and the INPUT jump removed; otherwise the
/// ICMP/service-accept/reject rules are installed and INPUT jumps to the chain.
pub async fn setup_firewall<T: FwIptables + ?Sized>(
    ipt: &T,
    ipv6: bool,
    permit_all: bool,
) -> Result<(), FirewallError> {
    ipt.clear_chain(FIREWALL_CHAIN).await?;
    let jump = input_jump_rule(ipv6);
    if permit_all {
        ipt.delete("INPUT", &jump).await?;
        return Ok(());
    }
    for rule in icmp_accept_rules(ipv6) {
        ipt.append_unique(FIREWALL_CHAIN, &rule).await?;
    }
    ipt.append_unique(FIREWALL_CHAIN, &service_accept_rule(ipv6))
        .await?;
    ipt.append_unique(FIREWALL_CHAIN, &reject_rule(ipv6))
        .await?;
    ipt.ensure_top("INPUT", &jump).await?;
    Ok(())
}

/// Refresh the firewall ipsets for one family from the current local IPs +
/// active service VIPs.
pub async fn sync_firewall_sets<S: FwIpset + ?Sized>(
    ipset: &S,
    local_ips: &[IpAddr],
    service_vips: &[(IpAddr, Protocol, u16)],
    ipv6: bool,
) -> Result<(), FirewallError> {
    ipset
        .restore(&ipset_restore_payload(local_ips, service_vips, ipv6))
        .await
}

/// `FwIptables` backed by `iptables`/`ip6tables -t filter` for one family.
#[derive(Debug, Clone)]
pub struct SystemFwIptables {
    base: &'static str,
}

impl SystemFwIptables {
    /// Construct for the given family.
    pub fn for_family(family: kr_common::ipfamily::IpFamily) -> Self {
        use kr_common::ipfamily::IpFamily;
        Self {
            base: match family {
                IpFamily::V4 => "iptables",
                IpFamily::V6 => "ip6tables",
            },
        }
    }

    async fn run(&self, args: &[String]) -> Result<bool, FirewallError> {
        let mut full = vec!["-w".to_string(), "-t".into(), "filter".into()];
        full.extend_from_slice(args);
        let out = tokio::process::Command::new(self.base)
            .args(&full)
            .output()
            .await
            .map_err(|e| FirewallError(format!("spawn {} {full:?}: {e}", self.base)))?;
        Ok(out.status.success())
    }
}

#[async_trait]
impl FwIptables for SystemFwIptables {
    async fn clear_chain(&self, chain: &str) -> Result<(), FirewallError> {
        // -N creates (ignored if present), -F flushes — together "clear or create".
        let _ = self.run(&["-N".into(), chain.into()]).await?;
        if !self.run(&["-F".into(), chain.into()]).await? {
            return Err(FirewallError(format!("failed to flush {chain}")));
        }
        Ok(())
    }
    async fn append_unique(&self, chain: &str, args: &[String]) -> Result<(), FirewallError> {
        let mut check = vec!["-C".to_string(), chain.into()];
        check.extend_from_slice(args);
        if self.run(&check).await? {
            return Ok(());
        }
        let mut append = vec!["-A".to_string(), chain.into()];
        append.extend_from_slice(args);
        if !self.run(&append).await? {
            return Err(FirewallError(format!("failed to append to {chain}")));
        }
        Ok(())
    }
    async fn ensure_top(&self, chain: &str, args: &[String]) -> Result<(), FirewallError> {
        let mut check = vec!["-C".to_string(), chain.into()];
        check.extend_from_slice(args);
        if self.run(&check).await? {
            return Ok(());
        }
        let mut insert = vec!["-I".to_string(), chain.into(), "1".into()];
        insert.extend_from_slice(args);
        if !self.run(&insert).await? {
            return Err(FirewallError(format!("failed to insert into {chain}")));
        }
        Ok(())
    }
    async fn delete(&self, chain: &str, args: &[String]) -> Result<(), FirewallError> {
        let mut full = vec!["-D".to_string(), chain.into()];
        full.extend_from_slice(args);
        let _ = self.run(&full).await?; // tolerant
        Ok(())
    }
}

/// `FwIpset` backed by the `ipset` binary.
#[derive(Debug, Default, Clone)]
pub struct SystemFwIpset;

#[async_trait]
impl FwIpset for SystemFwIpset {
    async fn restore(&self, payload: &str) -> Result<(), FirewallError> {
        use tokio::io::AsyncWriteExt;
        let mut child = tokio::process::Command::new("ipset")
            .args(["restore", "-exist"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| FirewallError(format!("spawn ipset restore: {e}")))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(payload.as_bytes())
                .await
                .map_err(|e| FirewallError(format!("write ipset payload: {e}")))?;
        }
        let out = child
            .wait_with_output()
            .await
            .map_err(|e| FirewallError(format!("wait ipset: {e}")))?;
        if !out.status.success() {
            return Err(FirewallError(
                String::from_utf8_lossy(&out.stderr).trim().to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipset_names_prefix_v6() {
        assert_eq!(ipset_name(SERVICE_IPS_SET, false), "kube-router-svip");
        assert_eq!(ipset_name(SERVICE_IPS_SET, true), "inet6:kube-router-svip");
    }

    #[test]
    fn icmp_rules_include_v6_neighbor_discovery() {
        assert_eq!(icmp_accept_rules(false).len(), 3);
        let v6 = icmp_accept_rules(true);
        assert_eq!(v6.len(), 6);
        assert!(v6
            .iter()
            .any(|r| r.contains(&"neighbor-solicitation".to_string())));
        assert!(v6[0].contains(&"ipv6-icmp".to_string()));
    }

    #[test]
    fn reject_and_jump_rules_match_shape() {
        let r = reject_rule(false);
        assert!(r.windows(2).any(|w| w == ["!", "--match-set"]));
        assert!(r.ends_with(&["--reject-with".into(), "icmp-port-unreachable".into()]));
        assert!(
            reject_rule(true).ends_with(&["--reject-with".into(), "icmp6-port-unreachable".into()])
        );
        let j = input_jump_rule(false);
        assert!(j.ends_with(&["-j".to_string(), FIREWALL_CHAIN.to_string()]));
    }

    #[test]
    fn ipset_payload_creates_sets_and_adds_members() {
        let payload = ipset_restore_payload(
            &["192.168.1.10".parse().unwrap()],
            &[("10.96.0.10".parse().unwrap(), Protocol::Tcp, 80)],
            false,
        );
        assert!(payload.contains("create kube-router-local-ips hash:ip family inet"));
        assert!(payload.contains("create kube-router-svip-prt hash:ip,port family inet"));
        assert!(payload.contains("add kube-router-local-ips 192.168.1.10"));
        assert!(payload.contains("add kube-router-svip 10.96.0.10"));
        assert!(payload.contains("add kube-router-svip-prt 10.96.0.10,tcp:80"));
        // v4 payload excludes v6 members.
        assert!(!payload.contains("inet6"));
    }

    // --- mock-driven orchestration tests ---
    use std::sync::Mutex;

    #[derive(Default)]
    struct MockFw {
        cleared: Mutex<Vec<String>>,
        appended: Mutex<Vec<(String, Vec<String>)>>,
        top: Mutex<Vec<(String, Vec<String>)>>,
        deleted: Mutex<Vec<(String, Vec<String>)>>,
        restores: Mutex<Vec<String>>,
    }
    #[async_trait]
    impl FwIptables for MockFw {
        async fn clear_chain(&self, c: &str) -> Result<(), FirewallError> {
            self.cleared.lock().unwrap().push(c.into());
            Ok(())
        }
        async fn append_unique(&self, c: &str, a: &[String]) -> Result<(), FirewallError> {
            self.appended.lock().unwrap().push((c.into(), a.to_vec()));
            Ok(())
        }
        async fn ensure_top(&self, c: &str, a: &[String]) -> Result<(), FirewallError> {
            self.top.lock().unwrap().push((c.into(), a.to_vec()));
            Ok(())
        }
        async fn delete(&self, c: &str, a: &[String]) -> Result<(), FirewallError> {
            self.deleted.lock().unwrap().push((c.into(), a.to_vec()));
            Ok(())
        }
    }
    #[async_trait]
    impl FwIpset for MockFw {
        async fn restore(&self, payload: &str) -> Result<(), FirewallError> {
            self.restores.lock().unwrap().push(payload.into());
            Ok(())
        }
    }

    #[tokio::test]
    async fn setup_restricted_installs_rules_and_input_jump() {
        let fw = MockFw::default();
        setup_firewall(&fw, false, false).await.unwrap();
        assert_eq!(fw.cleared.lock().unwrap().as_slice(), &[FIREWALL_CHAIN]);
        // 3 ICMP + service-accept + reject = 5 chain rules.
        assert_eq!(fw.appended.lock().unwrap().len(), 5);
        assert_eq!(fw.top.lock().unwrap().len(), 1); // INPUT jump
        assert!(fw.deleted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn setup_permit_all_clears_chain_and_removes_jump() {
        let fw = MockFw::default();
        setup_firewall(&fw, false, true).await.unwrap();
        assert_eq!(fw.cleared.lock().unwrap().len(), 1);
        assert!(fw.appended.lock().unwrap().is_empty());
        assert_eq!(fw.deleted.lock().unwrap().len(), 1); // INPUT jump removed
    }

    #[tokio::test]
    async fn sync_sets_restores_payload() {
        let fw = MockFw::default();
        sync_firewall_sets(
            &fw,
            &["192.168.1.10".parse().unwrap()],
            &[("10.96.0.10".parse().unwrap(), Protocol::Tcp, 80)],
            false,
        )
        .await
        .unwrap();
        let restores = fw.restores.lock().unwrap();
        assert_eq!(restores.len(), 1);
        assert!(restores[0].contains("add kube-router-svip-prt 10.96.0.10,tcp:80"));
    }
}
