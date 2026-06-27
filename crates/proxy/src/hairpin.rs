//! Hairpin SNAT, mirroring `syncHairpinIptablesRules` + `hairpinRuleFrom` in
//! `network_services_controller.go`/`utils.go`.
//!
//! When a pod connects to its own service VIP and is load-balanced back to
//! itself, the reply's source is the VIP but the request's was the pod IP, so the
//! pod drops it. A `nat` SNAT rule rewrites the source to the VIP. Applied per
//! service (`kube-router.io/service.hairpin`) or globally (`--hairpin-mode`).

use std::net::IpAddr;

use async_trait::async_trait;

use crate::model::{EndpointInfo, ServiceInfo};

/// nat chain holding hairpin SNAT rules.
pub const HAIRPIN_CHAIN: &str = "KUBE-ROUTER-HAIRPIN";

fn cidr_self(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(_) => format!("{ip}/32"),
        IpAddr::V6(_) => format!("{ip}/128"),
    }
}

/// SNAT rule args for one endpoint hitting its own service VIP (matches
/// `hairpinRuleFrom`): rewrite source pod IP → service VIP on the IPVS vaddr.
pub fn hairpin_snat_args(ep_ip: IpAddr, vip: IpAddr, port: u16) -> Vec<String> {
    let self_cidr = cidr_self(ep_ip);
    vec![
        "-s".into(),
        self_cidr.clone(),
        "-d".into(),
        self_cidr,
        "-m".into(),
        "ipvs".into(),
        "--vaddr".into(),
        vip.to_string(),
        "--vport".into(),
        port.to_string(),
        "-j".into(),
        "SNAT".into(),
        "--to-source".into(),
        vip.to_string(),
    ]
}

/// POSTROUTING jump that sends original-direction IPVS traffic to the hairpin
/// chain (matches `ensureHairpinChain`).
pub fn hairpin_jump_args() -> Vec<String> {
    vec![
        "-m".into(),
        "ipvs".into(),
        "--vdir".into(),
        "ORIGINAL".into(),
        "-j".into(),
        HAIRPIN_CHAIN.into(),
    ]
}

/// Desired hairpin SNAT rules for one IP family. A service is included when
/// `global` or its hairpin annotation is set and it has a local ready endpoint;
/// each local endpoint pairs with its same-family cluster + external VIPs.
pub fn hairpin_rules_for_family(
    services: &[(ServiceInfo, Vec<EndpointInfo>)],
    global: bool,
    ipv6: bool,
) -> Vec<Vec<String>> {
    let mut rules: Vec<Vec<String>> = Vec::new();
    for (svc, eps) in services {
        if !(global || svc.hairpin) {
            continue;
        }
        let vips: Vec<IpAddr> = svc
            .cluster_ips
            .iter()
            .chain(svc.external_ips.iter())
            .copied()
            .filter(|v| v.is_ipv6() == ipv6)
            .collect();
        if vips.is_empty() {
            continue;
        }
        for ep in eps {
            if !ep.is_local || !ep.ready || ep.ip.is_ipv6() != ipv6 {
                continue;
            }
            for vip in &vips {
                let rule = hairpin_snat_args(ep.ip, *vip, svc.port);
                if !rules.contains(&rule) {
                    rules.push(rule);
                }
            }
        }
    }
    rules
}

/// nat-table chain operations for hairpin reconciliation.
#[async_trait]
pub trait NatOps: Send + Sync {
    /// Create `chain` in the nat table if missing.
    async fn ensure_chain(&self, chain: &str) -> Result<(), NatError>;
    /// Append a rule to `chain` if not already present.
    async fn append_unique(&self, chain: &str, args: &[String]) -> Result<(), NatError>;
    /// Flush all rules from `chain`.
    async fn flush_chain(&self, chain: &str) -> Result<(), NatError>;
    /// Delete a rule from `chain` (tolerate "not present").
    async fn delete(&self, chain: &str, args: &[String]) -> Result<(), NatError>;
}

/// nat operation error.
#[derive(Debug, thiserror::Error)]
#[error("nat error: {0}")]
pub struct NatError(pub String);

/// Reconcile the hairpin chain: ensure the chain + POSTROUTING jump exist, then
/// replace the chain's contents with exactly `rules`.
pub async fn sync_hairpin<N: NatOps + ?Sized>(
    ops: &N,
    rules: &[Vec<String>],
) -> Result<(), NatError> {
    ops.ensure_chain(HAIRPIN_CHAIN).await?;
    ops.append_unique("POSTROUTING", &hairpin_jump_args())
        .await?;
    ops.flush_chain(HAIRPIN_CHAIN).await?;
    for rule in rules {
        ops.append_unique(HAIRPIN_CHAIN, rule).await?;
    }
    Ok(())
}

/// `NatOps` backed by the `iptables`/`ip6tables -t nat` binaries for one family.
#[derive(Debug, Clone)]
pub struct SystemNat {
    base: &'static str,
}

impl SystemNat {
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

    async fn run(&self, args: &[String]) -> Result<bool, NatError> {
        let mut full = vec!["-w".to_string(), "-t".into(), "nat".into()];
        full.extend_from_slice(args);
        let out = tokio::process::Command::new(self.base)
            .args(&full)
            .output()
            .await
            .map_err(|e| NatError(format!("spawn {} {full:?}: {e}", self.base)))?;
        Ok(out.status.success())
    }
}

#[async_trait]
impl NatOps for SystemNat {
    async fn ensure_chain(&self, chain: &str) -> Result<(), NatError> {
        // `-N` fails if it already exists; that's the desired post-state.
        let _ = self.run(&["-N".into(), chain.into()]).await?;
        Ok(())
    }
    async fn append_unique(&self, chain: &str, args: &[String]) -> Result<(), NatError> {
        let mut check = vec!["-C".to_string(), chain.into()];
        check.extend_from_slice(args);
        if self.run(&check).await? {
            return Ok(());
        }
        let mut append = vec!["-A".to_string(), chain.into()];
        append.extend_from_slice(args);
        if !self.run(&append).await? {
            return Err(NatError(format!("failed to append nat {chain} rule")));
        }
        Ok(())
    }
    async fn flush_chain(&self, chain: &str) -> Result<(), NatError> {
        let _ = self.run(&["-F".into(), chain.into()]).await?;
        Ok(())
    }
    async fn delete(&self, chain: &str, args: &[String]) -> Result<(), NatError> {
        let mut full = vec!["-D".to_string(), chain.into()];
        full.extend_from_slice(args);
        let _ = self.run(&full).await?; // tolerate "not present"
        Ok(())
    }
}

#[cfg(any(test, feature = "mock"))]
pub mod mock {
    //! Recording [`NatOps`] for tests.
    use super::*;
    use std::sync::Mutex;

    /// Records chain creation, appended rules, and flushes.
    #[derive(Default)]
    pub struct MockNat {
        /// Chains created via `ensure_chain`.
        pub chains: Mutex<Vec<String>>,
        /// Rules appended as `(chain, args)`.
        pub appended: Mutex<Vec<(String, Vec<String>)>>,
        /// Chains flushed.
        pub flushed: Mutex<Vec<String>>,
        /// Rules deleted as `(chain, args)`.
        pub deleted: Mutex<Vec<(String, Vec<String>)>>,
    }

    impl MockNat {
        /// New empty mock.
        pub fn new() -> Self {
            Self::default()
        }
        /// Rules currently appended to `chain` (after the last flush ordering).
        pub fn rules_in(&self, chain: &str) -> Vec<Vec<String>> {
            self.appended
                .lock()
                .unwrap()
                .iter()
                .filter(|(c, _)| c == chain)
                .map(|(_, a)| a.clone())
                .collect()
        }
    }

    #[async_trait]
    impl NatOps for MockNat {
        async fn ensure_chain(&self, chain: &str) -> Result<(), NatError> {
            self.chains.lock().unwrap().push(chain.to_string());
            Ok(())
        }
        async fn append_unique(&self, chain: &str, args: &[String]) -> Result<(), NatError> {
            self.appended
                .lock()
                .unwrap()
                .push((chain.to_string(), args.to_vec()));
            Ok(())
        }
        async fn flush_chain(&self, chain: &str) -> Result<(), NatError> {
            self.flushed.lock().unwrap().push(chain.to_string());
            Ok(())
        }
        async fn delete(&self, chain: &str, args: &[String]) -> Result<(), NatError> {
            self.deleted
                .lock()
                .unwrap()
                .push((chain.to_string(), args.to_vec()));
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock::MockNat;
    use super::*;
    use crate::model::{Protocol, Scheduler};

    fn svc(vip: &str, hairpin: bool) -> ServiceInfo {
        ServiceInfo {
            namespace: "default".into(),
            name: "web".into(),
            port_name: "http".into(),
            protocol: Protocol::Tcp,
            port: 80,
            node_port: None,
            cluster_ips: vec![vip.parse().unwrap()],
            external_ips: vec![],
            load_balancer_ips: vec![],
            scheduler: Scheduler::Rr,
            session_affinity: false,
            affinity_timeout: 0,
            dsr: false,
            internal_traffic_local: false,
            external_traffic_local: false,
            hairpin,
            health_check_node_port: None,
        }
    }
    fn ep(ip: &str, local: bool, ready: bool) -> EndpointInfo {
        EndpointInfo {
            ip: ip.parse().unwrap(),
            port: 8080,
            is_local: local,
            ready,
        }
    }

    #[test]
    fn snat_args_match_upstream_shape() {
        let a = hairpin_snat_args(
            "10.244.0.5".parse().unwrap(),
            "10.96.0.10".parse().unwrap(),
            80,
        );
        assert_eq!(
            a,
            vec![
                "-s",
                "10.244.0.5/32",
                "-d",
                "10.244.0.5/32",
                "-m",
                "ipvs",
                "--vaddr",
                "10.96.0.10",
                "--vport",
                "80",
                "-j",
                "SNAT",
                "--to-source",
                "10.96.0.10"
            ]
        );
    }

    #[test]
    fn rules_only_for_hairpin_services_and_local_ready_endpoints() {
        let services = vec![
            (
                svc("10.96.0.10", true),
                vec![ep("10.244.0.5", true, true), ep("10.244.1.5", false, true)],
            ),
            // No hairpin annotation and not global → excluded.
            (svc("10.96.0.20", false), vec![ep("10.244.0.6", true, true)]),
        ];
        let rules = hairpin_rules_for_family(&services, false, false);
        assert_eq!(rules.len(), 1); // only the local ready endpoint of the hairpin svc
        assert!(rules[0].contains(&"10.244.0.5/32".to_string()));
        assert!(rules[0].contains(&"10.96.0.10".to_string()));
    }

    #[test]
    fn global_mode_includes_all_services_and_skips_other_family() {
        let services = vec![(svc("10.96.0.10", false), vec![ep("10.244.0.5", true, true)])];
        // IPv6 family pass over IPv4-only service yields nothing.
        assert!(hairpin_rules_for_family(&services, true, true).is_empty());
        assert_eq!(hairpin_rules_for_family(&services, true, false).len(), 1);
    }

    #[tokio::test]
    async fn sync_ensures_chain_jump_and_rules() {
        let ops = MockNat::new();
        let rules = vec![hairpin_snat_args(
            "10.244.0.5".parse().unwrap(),
            "10.96.0.10".parse().unwrap(),
            80,
        )];
        sync_hairpin(&ops, &rules).await.unwrap();
        assert_eq!(ops.chains.lock().unwrap().as_slice(), &[HAIRPIN_CHAIN]);
        assert_eq!(ops.flushed.lock().unwrap().as_slice(), &[HAIRPIN_CHAIN]);
        // POSTROUTING jump + one hairpin rule.
        assert_eq!(ops.rules_in("POSTROUTING").len(), 1);
        assert_eq!(ops.rules_in(HAIRPIN_CHAIN).len(), 1);
    }
}
