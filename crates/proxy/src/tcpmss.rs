//! TCPMSS clamping for DSR, mirroring the TCPMSS half of `setupMangleTableRule`
//! in `network_services_controller.go`.
//!
//! In DSR mode the load balancer rewrites only the MAC/tunnel, so reply packets
//! from pods (egress via `kube-bridge`) can exceed the path MTU. A `mangle`
//! `PREROUTING` rule clamps the MSS of SYN packets sourced from the service VIP.

use std::net::IpAddr;

use async_trait::async_trait;
use kr_common::ipfamily::IpFamily;

/// Bridge interface pod traffic egresses through.
const KUBE_BRIDGE: &str = "kube-bridge";
/// IPv4 header length (bytes).
const IPV4_HEADER_LEN: i32 = 20;
/// IPv6 header length (bytes).
const IPV6_HEADER_LEN: i32 = 40;
/// Minimum TCP header length (bytes).
const TCP_HEADER_MIN_LEN: i32 = 20;

/// MSS to clamp to for the given MTU: `mtu - (2*ip_header + tcp_header)`
/// (IPv4 → `mtu-60`, IPv6 → `mtu-100`), matching upstream.
pub fn tcp_mss(mtu: i32, ipv6: bool) -> i32 {
    let ip_header = if ipv6 {
        IPV6_HEADER_LEN
    } else {
        IPV4_HEADER_LEN
    };
    mtu - (2 * ip_header + TCP_HEADER_MIN_LEN)
}

/// `mangle` PREROUTING rule args clamping MSS on SYN replies from a service VIP.
pub fn tcpmss_mangle_args(ip: IpAddr, port: u16, mss: i32) -> Vec<String> {
    vec![
        "-s".into(),
        ip.to_string(),
        "-m".into(),
        "tcp".into(),
        "-p".into(),
        "tcp".into(),
        "--sport".into(),
        port.to_string(),
        "-i".into(),
        KUBE_BRIDGE.into(),
        "--tcp-flags".into(),
        "SYN,RST".into(),
        "SYN".into(),
        "-j".into(),
        "TCPMSS".into(),
        "--set-mss".into(),
        mss.to_string(),
    ]
}

/// `mangle`-table rule operations (idempotent append / delete).
#[async_trait]
pub trait MangleOps: Send + Sync {
    /// Append a rule to `chain` if not already present (`-C` then `-A`).
    async fn append_unique(&self, chain: &str, args: &[String]) -> Result<(), MangleError>;
    /// Delete a rule from `chain` (tolerate "not present").
    async fn delete(&self, chain: &str, args: &[String]) -> Result<(), MangleError>;
}

/// Mangle operation error.
#[derive(Debug, thiserror::Error)]
#[error("mangle error: {0}")]
pub struct MangleError(pub String);

/// Program the TCPMSS clamp rule for a TCP service VIP.
pub async fn ensure_tcpmss<M: MangleOps>(
    ops: &M,
    ip: IpAddr,
    port: u16,
    mtu: i32,
) -> Result<(), MangleError> {
    let args = tcpmss_mangle_args(ip, port, tcp_mss(mtu, ip.is_ipv6()));
    ops.append_unique("PREROUTING", &args).await
}

/// Remove the TCPMSS clamp rule for a TCP service VIP.
pub async fn remove_tcpmss<M: MangleOps>(
    ops: &M,
    ip: IpAddr,
    port: u16,
    mtu: i32,
) -> Result<(), MangleError> {
    let args = tcpmss_mangle_args(ip, port, tcp_mss(mtu, ip.is_ipv6()));
    ops.delete("PREROUTING", &args).await
}

/// `MangleOps` backed by `iptables`/`ip6tables -t mangle` for one family.
#[derive(Debug, Clone)]
pub struct SystemMangle {
    base: &'static str,
}

impl SystemMangle {
    /// Construct for the given family.
    pub fn for_family(family: IpFamily) -> Self {
        Self {
            base: match family {
                IpFamily::V4 => "iptables",
                IpFamily::V6 => "ip6tables",
            },
        }
    }

    async fn run(&self, op: &str, chain: &str, args: &[String]) -> Result<bool, MangleError> {
        let mut full = vec![
            "-w".to_string(),
            "-t".into(),
            "mangle".into(),
            op.into(),
            chain.into(),
        ];
        full.extend_from_slice(args);
        let out = tokio::process::Command::new(self.base)
            .args(&full)
            .output()
            .await
            .map_err(|e| MangleError(format!("spawn {} {full:?}: {e}", self.base)))?;
        if out.status.success() {
            return Ok(true);
        }
        Ok(false)
    }
}

#[async_trait]
impl MangleOps for SystemMangle {
    async fn append_unique(&self, chain: &str, args: &[String]) -> Result<(), MangleError> {
        if self.run("-C", chain, args).await? {
            return Ok(()); // already present
        }
        if !self.run("-A", chain, args).await? {
            return Err(MangleError(format!("failed to append mangle {chain} rule")));
        }
        Ok(())
    }
    async fn delete(&self, chain: &str, args: &[String]) -> Result<(), MangleError> {
        // Tolerate "not present" — a missing rule is the desired post-state.
        let _ = self.run("-D", chain, args).await?;
        Ok(())
    }
}

#[cfg(any(test, feature = "mock"))]
pub mod mock {
    //! Recording [`MangleOps`] for tests.
    use super::*;
    use std::sync::Mutex;

    /// Records appended/deleted mangle rules as `(chain, args)`.
    #[derive(Default)]
    pub struct MockMangle {
        /// Rules appended via `append_unique`.
        pub appended: Mutex<Vec<(String, Vec<String>)>>,
        /// Rules deleted via `delete`.
        pub deleted: Mutex<Vec<(String, Vec<String>)>>,
    }

    impl MockMangle {
        /// New empty mock.
        pub fn new() -> Self {
            Self::default()
        }
    }

    #[async_trait]
    impl MangleOps for MockMangle {
        async fn append_unique(&self, chain: &str, args: &[String]) -> Result<(), MangleError> {
            self.appended
                .lock()
                .unwrap()
                .push((chain.to_string(), args.to_vec()));
            Ok(())
        }
        async fn delete(&self, chain: &str, args: &[String]) -> Result<(), MangleError> {
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
    use super::mock::MockMangle;
    use super::*;

    #[test]
    fn mss_subtracts_v4_and_v6_overhead() {
        assert_eq!(tcp_mss(1500, false), 1440); // 1500 - 60
        assert_eq!(tcp_mss(1500, true), 1400); // 1500 - 100
    }

    #[test]
    fn mangle_args_match_upstream_shape() {
        let a = tcpmss_mangle_args("10.96.0.10".parse().unwrap(), 80, 1440);
        assert_eq!(
            a,
            vec![
                "-s",
                "10.96.0.10",
                "-m",
                "tcp",
                "-p",
                "tcp",
                "--sport",
                "80",
                "-i",
                "kube-bridge",
                "--tcp-flags",
                "SYN,RST",
                "SYN",
                "-j",
                "TCPMSS",
                "--set-mss",
                "1440"
            ]
        );
    }

    #[tokio::test]
    async fn ensure_appends_prerouting_rule_with_family_mss() {
        let ops = MockMangle::new();
        ensure_tcpmss(&ops, "fd00::10".parse().unwrap(), 443, 1500)
            .await
            .unwrap();
        let appended = ops.appended.lock().unwrap();
        assert_eq!(appended.len(), 1);
        let (chain, args) = &appended[0];
        assert_eq!(chain, "PREROUTING");
        // IPv6 → MSS 1400.
        assert!(args.ends_with(&["--set-mss".to_string(), "1400".to_string()]));
    }

    #[tokio::test]
    async fn remove_deletes_prerouting_rule() {
        let ops = MockMangle::new();
        remove_tcpmss(&ops, "10.96.0.10".parse().unwrap(), 80, 1500)
            .await
            .unwrap();
        assert_eq!(ops.deleted.lock().unwrap().len(), 1);
    }
}
