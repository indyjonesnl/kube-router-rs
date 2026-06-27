//! iptables management via `iptables-save`/`iptables-restore`, mirroring
//! `upstream/pkg/utils/iptables.go` — kube-router does a full atomic filter-table
//! save → mutate → restore per IP family.

use async_trait::async_trait;
use kr_common::ipfamily::IpFamily;

/// iptables operation error.
#[derive(Debug, thiserror::Error)]
#[error("iptables error: {0}")]
pub struct IptablesError(pub String);

/// Per-family iptables save/restore operations.
#[async_trait]
pub trait IptablesOps: Send + Sync {
    /// `iptables-save -t filter`.
    async fn save_filter(&self) -> Result<String, IptablesError>;
    /// `iptables-restore --wait -T filter` with the given table document.
    async fn restore_filter(&self, table_doc: &str) -> Result<(), IptablesError>;
    /// Ensure `builtin` (INPUT/FORWARD/OUTPUT) jumps to `target` at position 1
    /// (idempotent: check with `-C`, insert with `-I` only if missing).
    async fn ensure_jump(&self, builtin: &str, target: &str) -> Result<(), IptablesError>;
}

/// Wrap chain declarations + rule lines into an `iptables-restore` filter doc.
pub fn filter_restore_doc(decls: &[String], rules: &[String]) -> String {
    let mut out = String::from("*filter\n");
    for d in decls {
        out.push_str(d);
        out.push('\n');
    }
    for r in rules {
        out.push_str(r);
        out.push('\n');
    }
    out.push_str("COMMIT\n");
    out
}

/// `IptablesOps` backed by the iptables binaries for one IP family.
#[derive(Debug, Clone)]
pub struct SystemIptables {
    base: &'static str,
}

impl SystemIptables {
    /// Construct for the given family (`iptables` vs `ip6tables`).
    pub fn for_family(family: IpFamily) -> Self {
        Self {
            base: match family {
                IpFamily::V4 => "iptables",
                IpFamily::V6 => "ip6tables",
            },
        }
    }
}

#[async_trait]
impl IptablesOps for SystemIptables {
    async fn save_filter(&self) -> Result<String, IptablesError> {
        let out = tokio::process::Command::new(format!("{}-save", self.base))
            .args(["-t", "filter"])
            .output()
            .await
            .map_err(|e| IptablesError(format!("spawn {}-save: {e}", self.base)))?;
        if !out.status.success() {
            return Err(IptablesError(
                String::from_utf8_lossy(&out.stderr).trim().to_string(),
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    async fn restore_filter(&self, table_doc: &str) -> Result<(), IptablesError> {
        use tokio::io::AsyncWriteExt;
        let mut child = tokio::process::Command::new(format!("{}-restore", self.base))
            .args(["--wait", "-T", "filter", "--noflush"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| IptablesError(format!("spawn {}-restore: {e}", self.base)))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(table_doc.as_bytes())
                .await
                .map_err(|e| IptablesError(format!("write restore doc: {e}")))?;
        }
        let out = child
            .wait_with_output()
            .await
            .map_err(|e| IptablesError(format!("wait restore: {e}")))?;
        if !out.status.success() {
            return Err(IptablesError(
                String::from_utf8_lossy(&out.stderr).trim().to_string(),
            ));
        }
        Ok(())
    }

    async fn ensure_jump(&self, builtin: &str, target: &str) -> Result<(), IptablesError> {
        let check = tokio::process::Command::new(self.base)
            .args(["-w", "-C", builtin, "-j", target])
            .output()
            .await
            .map_err(|e| IptablesError(format!("spawn {} -C: {e}", self.base)))?;
        if check.status.success() {
            return Ok(());
        }
        let ins = tokio::process::Command::new(self.base)
            .args(["-w", "-I", builtin, "1", "-j", target])
            .output()
            .await
            .map_err(|e| IptablesError(format!("spawn {} -I: {e}", self.base)))?;
        if !ins.status.success() {
            return Err(IptablesError(
                String::from_utf8_lossy(&ins.stderr).trim().to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(any(test, feature = "mock"))]
pub mod mock {
    //! Recording [`IptablesOps`] for tests.
    use super::*;
    use std::sync::Mutex;

    /// Returns a fixed save output and records restore docs.
    #[derive(Default)]
    pub struct MockIptables {
        /// Canned `save_filter` output.
        pub save_output: Mutex<String>,
        /// Docs passed to `restore_filter`.
        pub restores: Mutex<Vec<String>>,
        /// `(builtin, target)` jumps ensured.
        pub jumps: Mutex<Vec<(String, String)>>,
    }

    impl MockIptables {
        /// New empty mock.
        pub fn new() -> Self {
            Self::default()
        }
    }

    #[async_trait]
    impl IptablesOps for MockIptables {
        async fn save_filter(&self) -> Result<String, IptablesError> {
            Ok(self.save_output.lock().unwrap().clone())
        }
        async fn restore_filter(&self, table_doc: &str) -> Result<(), IptablesError> {
            self.restores.lock().unwrap().push(table_doc.to_string());
            Ok(())
        }
        async fn ensure_jump(&self, builtin: &str, target: &str) -> Result<(), IptablesError> {
            self.jumps
                .lock()
                .unwrap()
                .push((builtin.to_string(), target.to_string()));
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restore_doc_wraps_filter_and_commit() {
        let doc = filter_restore_doc(
            &[":KUBE-ROUTER-INPUT - [0:0]".to_string()],
            &["-A KUBE-ROUTER-INPUT -j ACCEPT".to_string()],
        );
        assert!(doc.starts_with("*filter\n"));
        assert!(doc.contains(":KUBE-ROUTER-INPUT - [0:0]"));
        assert!(doc.contains("-A KUBE-ROUTER-INPUT -j ACCEPT"));
        assert!(doc.trim_end().ends_with("COMMIT"));
    }

    #[test]
    fn for_family_selects_binary() {
        assert_eq!(SystemIptables::for_family(IpFamily::V4).base, "iptables");
        assert_eq!(SystemIptables::for_family(IpFamily::V6).base, "ip6tables");
    }
}
