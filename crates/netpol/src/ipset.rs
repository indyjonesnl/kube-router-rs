//! ipset management via the `ipset` binary, mirroring `upstream/pkg/utils/ipset.go`.
//!
//! kube-router updates sets atomically: build a TMP set, fill it, `swap` it with
//! the live set, then destroy the TMP. We reproduce that with a `restore` payload
//! (pure builder, unit-tested) fed to `ipset restore -exist`.

use async_trait::async_trait;
use kr_common::ipfamily::IpFamily;

/// ipset storage type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetType {
    /// `hash:ip` — individual addresses (pod IPs).
    HashIp,
    /// `hash:net` — CIDR blocks (ipBlock peers).
    HashNet,
}

impl SetType {
    fn as_str(self) -> &'static str {
        match self {
            SetType::HashIp => "hash:ip",
            SetType::HashNet => "hash:net",
        }
    }
}

fn family_kw(family: IpFamily) -> &'static str {
    match family {
        IpFamily::V4 => "inet",
        IpFamily::V6 => "inet6",
    }
}

/// Build an `ipset restore` payload that atomically replaces `set`'s contents
/// with `entries` via a TMP set + `swap`.
pub fn build_restore_payload(
    set: &str,
    set_type: SetType,
    family: IpFamily,
    entries: &[String],
) -> String {
    let tmp = format!("TMP-{set}");
    let typ = set_type.as_str();
    let fam = family_kw(family);
    let mut out = String::new();
    out.push_str(&format!("create {set} {typ} family {fam} -exist\n"));
    out.push_str(&format!("create {tmp} {typ} family {fam} -exist\n"));
    out.push_str(&format!("flush {tmp}\n"));
    for e in entries {
        out.push_str(&format!("add {tmp} {e} -exist\n"));
    }
    out.push_str(&format!("swap {tmp} {set}\n"));
    out.push_str(&format!("destroy {tmp}\n"));
    out
}

/// ipset operation error.
#[derive(Debug, thiserror::Error)]
#[error("ipset error: {0}")]
pub struct IpsetError(pub String);

/// ipset operations the controller needs.
#[async_trait]
pub trait IpsetOps: Send + Sync {
    /// Apply a `restore` payload (idempotent set replacement).
    async fn restore(&self, payload: &str) -> Result<(), IpsetError>;
    /// Destroy a set (ignores absent sets).
    async fn destroy(&self, name: &str) -> Result<(), IpsetError>;
}

/// `IpsetOps` backed by the `ipset` binary.
#[derive(Debug, Default, Clone)]
pub struct SystemIpset;

impl SystemIpset {
    /// New instance.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl IpsetOps for SystemIpset {
    async fn restore(&self, payload: &str) -> Result<(), IpsetError> {
        use tokio::io::AsyncWriteExt;
        use tokio::process::Command;
        let mut child = Command::new("ipset")
            .arg("restore")
            .arg("-exist")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| IpsetError(format!("spawn ipset restore: {e}")))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(payload.as_bytes())
                .await
                .map_err(|e| IpsetError(format!("write payload: {e}")))?;
        }
        let out = child
            .wait_with_output()
            .await
            .map_err(|e| IpsetError(format!("wait ipset: {e}")))?;
        if !out.status.success() {
            return Err(IpsetError(
                String::from_utf8_lossy(&out.stderr).trim().to_string(),
            ));
        }
        Ok(())
    }

    async fn destroy(&self, name: &str) -> Result<(), IpsetError> {
        let out = tokio::process::Command::new("ipset")
            .args(["destroy", name])
            .output()
            .await
            .map_err(|e| IpsetError(format!("spawn ipset destroy: {e}")))?;
        // "set doesn't exist" is fine.
        if out.status.success() || String::from_utf8_lossy(&out.stderr).contains("does not exist") {
            Ok(())
        } else {
            Err(IpsetError(
                String::from_utf8_lossy(&out.stderr).trim().to_string(),
            ))
        }
    }
}

#[cfg(any(test, feature = "mock"))]
pub mod mock {
    //! Recording [`IpsetOps`] for tests.
    use super::*;
    use std::sync::Mutex;

    /// Records restore payloads + destroyed sets.
    #[derive(Default)]
    pub struct MockIpset {
        /// Payloads passed to `restore`.
        pub restores: Mutex<Vec<String>>,
        /// Names passed to `destroy`.
        pub destroyed: Mutex<Vec<String>>,
    }

    impl MockIpset {
        /// New empty mock.
        pub fn new() -> Self {
            Self::default()
        }
    }

    #[async_trait]
    impl IpsetOps for MockIpset {
        async fn restore(&self, payload: &str) -> Result<(), IpsetError> {
            self.restores.lock().unwrap().push(payload.to_string());
            Ok(())
        }
        async fn destroy(&self, name: &str) -> Result<(), IpsetError> {
            self.destroyed.lock().unwrap().push(name.to_string());
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restore_payload_uses_tmp_swap() {
        let p = build_restore_payload(
            "KUBE-SRC-ABC",
            SetType::HashIp,
            IpFamily::V4,
            &["10.244.0.5".to_string(), "10.244.1.6".to_string()],
        );
        assert!(p.contains("create KUBE-SRC-ABC hash:ip family inet -exist"));
        assert!(p.contains("create TMP-KUBE-SRC-ABC hash:ip family inet -exist"));
        assert!(p.contains("add TMP-KUBE-SRC-ABC 10.244.0.5 -exist"));
        assert!(p.contains("swap TMP-KUBE-SRC-ABC KUBE-SRC-ABC"));
        assert!(p.contains("destroy TMP-KUBE-SRC-ABC"));
        // swap precedes destroy.
        assert!(p.find("swap ").unwrap() < p.find("destroy ").unwrap());
    }

    #[test]
    fn v6_uses_inet6_and_hash_net() {
        let p = build_restore_payload("KUBE-DST-X", SetType::HashNet, IpFamily::V6, &[]);
        assert!(p.contains("hash:net family inet6"));
    }

    #[test]
    fn tmp_name_within_ipset_limit() {
        // KUBE-SRC-<16 hash> = 25 chars; TMP- prefix → 29 ≤ 31.
        let tmp = format!("TMP-KUBE-SRC-{}", "A".repeat(16));
        assert!(tmp.len() <= 31, "len {}", tmp.len());
    }
}
