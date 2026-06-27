//! A [`NetlinkOps`] implementation that shells out to `ip` (iproute2).
//!
//! This is the runtime impl used in-cluster. The Go upstream programs routes via
//! netlink syscalls; shelling `ip route replace`/`del` is an equivalent, robust,
//! debuggable interim (the same way upstream shells iproute2 for FoU). The arg
//! builders are pure and unit-tested; execution is exercised in-cluster.

use async_trait::async_trait;
use tokio::process::Command;

use crate::{NetlinkError, NetlinkOps, Route};

const MAIN_TABLE: u32 = 254;

/// Build `ip route replace` args for a route.
pub fn route_replace_args(route: &Route) -> Vec<String> {
    let mut a = vec!["route".into(), "replace".into(), route.dst.to_string()];
    if let Some(gw) = route.gateway {
        a.push("via".into());
        a.push(gw.to_string());
    }
    if route.table != MAIN_TABLE {
        a.push("table".into());
        a.push(route.table.to_string());
    }
    a
}

/// Build `ip route del` args for a route.
pub fn route_del_args(route: &Route) -> Vec<String> {
    let mut a = vec!["route".into(), "del".into(), route.dst.to_string()];
    if route.table != MAIN_TABLE {
        a.push("table".into());
        a.push(route.table.to_string());
    }
    a
}

/// Build `ip addr add/del` args.
pub fn addr_args(op: &str, link: &str, addr: &str, prefix_len: u8) -> Vec<String> {
    vec![
        "addr".into(),
        op.into(),
        format!("{addr}/{prefix_len}"),
        "dev".into(),
        link.into(),
    ]
}

/// `NetlinkOps` backed by the `ip` command.
#[derive(Debug, Default, Clone)]
pub struct SystemNetlink;

impl SystemNetlink {
    /// New instance.
    pub fn new() -> Self {
        Self
    }

    async fn run_ip(&self, args: &[String]) -> Result<String, NetlinkError> {
        let out = Command::new("ip")
            .args(args)
            .output()
            .await
            .map_err(|e| NetlinkError::Op(format!("spawn ip {args:?}: {e}")))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(NetlinkError::Op(format!(
                "ip {args:?} failed: {}",
                stderr.trim()
            )));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

#[async_trait]
impl NetlinkOps for SystemNetlink {
    async fn ensure_dummy_link(&self, name: &str) -> Result<(), NetlinkError> {
        // Create if missing (ignore "exists"), then bring up.
        let add = self
            .run_ip(&[
                "link".into(),
                "add".into(),
                name.into(),
                "type".into(),
                "dummy".into(),
            ])
            .await;
        if let Err(e) = add {
            if !e.to_string().contains("File exists") {
                return Err(e);
            }
        }
        self.run_ip(&["link".into(), "set".into(), name.into(), "up".into()])
            .await?;
        Ok(())
    }

    async fn addr_add(
        &self,
        link: &str,
        addr: std::net::IpAddr,
        prefix_len: u8,
    ) -> Result<(), NetlinkError> {
        let r = self
            .run_ip(&addr_args("add", link, &addr.to_string(), prefix_len))
            .await;
        match r {
            Ok(_) => Ok(()),
            Err(e) if e.to_string().contains("File exists") => Ok(()),
            Err(e) => Err(e),
        }
    }

    async fn addr_del(
        &self,
        link: &str,
        addr: std::net::IpAddr,
        prefix_len: u8,
    ) -> Result<(), NetlinkError> {
        let r = self
            .run_ip(&addr_args("del", link, &addr.to_string(), prefix_len))
            .await;
        match r {
            Ok(_) => Ok(()),
            Err(e) if e.to_string().contains("Cannot assign") => Ok(()),
            Err(e) => Err(e),
        }
    }

    async fn route_replace(&self, route: &Route) -> Result<(), NetlinkError> {
        self.run_ip(&route_replace_args(route)).await.map(|_| ())
    }

    async fn route_del(&self, route: &Route) -> Result<(), NetlinkError> {
        let r = self.run_ip(&route_del_args(route)).await;
        match r {
            Ok(_) => Ok(()),
            Err(e) if e.to_string().contains("No such process") => Ok(()),
            Err(e) => Err(e),
        }
    }

    async fn route_list(&self, table: u32) -> Result<Vec<Route>, NetlinkError> {
        // Best-effort: controllers track desired state in memory; this is for
        // diagnostics. Returns an empty list rather than parsing `ip route`.
        let _ = table;
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::IpNet;

    fn route(dst: &str, gw: Option<&str>, table: u32) -> Route {
        Route {
            dst: dst.parse::<IpNet>().unwrap(),
            gateway: gw.map(|g| g.parse().unwrap()),
            table,
        }
    }

    #[test]
    fn replace_args_main_table_with_gateway() {
        let a = route_replace_args(&route("10.244.1.0/24", Some("192.168.32.3"), 254));
        assert_eq!(
            a,
            vec!["route", "replace", "10.244.1.0/24", "via", "192.168.32.3"]
        );
    }

    #[test]
    fn replace_args_custom_table() {
        let a = route_replace_args(&route("10.244.1.0/24", Some("192.168.32.3"), 77));
        assert!(a.ends_with(&["table".to_string(), "77".to_string()]));
    }

    #[test]
    fn del_args_omit_via() {
        let a = route_del_args(&route("10.244.1.0/24", Some("192.168.32.3"), 254));
        assert_eq!(a, vec!["route", "del", "10.244.1.0/24"]);
    }

    #[test]
    fn addr_args_format() {
        assert_eq!(
            addr_args("add", "kube-dummy-if", "10.96.0.1", 32),
            vec!["addr", "add", "10.96.0.1/32", "dev", "kube-dummy-if"]
        );
    }
}
