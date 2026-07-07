//! GoBGP process supervision.
//!
//! The routing controller manages a `gobgpd` child process and drives it over
//! gRPC on its admin address/port (`--gobgp-admin-address`/`--gobgp-admin-port`,
//! default `127.0.0.1:50051`). This module spawns/terminates the process and
//! probes the admin port for readiness; the gRPC client that connects to it is
//! the deferred codegen piece (see [`crate::engine`]).

use std::path::PathBuf;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::process::{Child, Command};

/// Supervises a child process (the gobgpd BGP engine).
pub struct GobgpSupervisor {
    program: PathBuf,
    args: Vec<String>,
    child: Option<Child>,
}

impl GobgpSupervisor {
    /// Construct a supervisor for an arbitrary program + args (used in tests).
    pub fn new(program: impl Into<PathBuf>, args: Vec<String>) -> Self {
        Self {
            program: program.into(),
            args,
            child: None,
        }
    }

    /// Construct a supervisor that runs `gobgpd` bound to the given admin endpoint.
    pub fn gobgpd(binary: impl Into<PathBuf>, admin_addr: &str, admin_port: u16) -> Self {
        Self::new(binary, gobgpd_args(admin_addr, admin_port))
    }

    /// Whether a child is currently running.
    pub fn is_running(&self) -> bool {
        self.child.is_some()
    }

    /// Spawn the child process.
    pub async fn spawn(&mut self) -> std::io::Result<()> {
        let child = Command::new(&self.program).args(&self.args).spawn()?;
        self.child = Some(child);
        Ok(())
    }

    /// Terminate the child process and reap it.
    pub async fn terminate(&mut self) -> std::io::Result<()> {
        if let Some(mut child) = self.child.take() {
            child.start_kill()?;
            let _ = child.wait().await?;
        }
        Ok(())
    }
}

/// Build the `gobgpd` argument vector for the given admin endpoint.
pub fn gobgpd_args(admin_addr: &str, admin_port: u16) -> Vec<String> {
    vec![
        "--api-hosts".to_string(),
        format!("{admin_addr}:{admin_port}"),
    ]
}

/// True if a TCP connection to `addr` succeeds right now.
pub async fn port_ready(addr: &str) -> bool {
    TcpStream::connect(addr).await.is_ok()
}

/// Poll `addr` until it accepts a connection or `timeout` elapses.
pub async fn wait_port_ready(addr: &str, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if port_ready(addr).await {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn gobgpd_args_bind_admin_endpoint() {
        assert_eq!(
            gobgpd_args("127.0.0.1", 50051),
            vec!["--api-hosts".to_string(), "127.0.0.1:50051".to_string()]
        );
    }

    #[tokio::test]
    async fn port_ready_true_when_listening_false_when_not() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        assert!(port_ready(&addr).await);

        assert!(!port_ready("127.0.0.1:0").await);
    }

    #[tokio::test]
    async fn wait_port_ready_succeeds_when_listener_present() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        assert!(wait_port_ready(&addr, Duration::from_millis(200)).await);
    }

    #[tokio::test]
    async fn supervisor_spawns_and_terminates() {
        // Use a portable stand-in for gobgpd.
        let mut sup = GobgpSupervisor::new("sleep", vec!["30".to_string()]);
        assert!(!sup.is_running());
        sup.spawn().await.expect("spawn sleep");
        assert!(sup.is_running());
        sup.terminate().await.expect("terminate");
        assert!(!sup.is_running());
    }
}
