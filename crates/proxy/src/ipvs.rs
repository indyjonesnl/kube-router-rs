//! IPVS programming abstraction, mirroring the `ipvsCalls` interface in
//! `upstream/pkg/controllers/proxy/linux_networking.go` (mocked there for tests).
//!
//! Controllers depend on [`IpvsOps`] so service/endpoint sync is testable against
//! [`mock::MockIpvs`]; the runtime impl (genetlink, with an `ipvsadm` fallback) is
//! a follow-up.

use std::net::IpAddr;

use async_trait::async_trait;

use crate::model::{Protocol, Scheduler};

/// An IPVS virtual service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpvsService {
    /// Virtual IP.
    pub addr: IpAddr,
    /// Protocol.
    pub protocol: Protocol,
    /// Virtual port.
    pub port: u16,
    /// Scheduler.
    pub scheduler: Scheduler,
    /// Persistence timeout (seconds) when session affinity is enabled.
    pub persistent: Option<u32>,
}

impl IpvsService {
    /// Identity key for a virtual service (addr/proto/port).
    pub fn key(&self) -> (IpAddr, Protocol, u16) {
        (self.addr, self.protocol, self.port)
    }
}

/// An IPVS real server (destination).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpvsDestination {
    /// Backend IP.
    pub addr: IpAddr,
    /// Backend port.
    pub port: u16,
    /// Weight (0 drains the destination).
    pub weight: i32,
    /// Tunnel (DSR) forwarding.
    pub tunnel: bool,
}

/// Cumulative + rate statistics for one IPVS virtual service (from `ipvsadm
/// --stats`/`--rate`), mirroring `ipvsSvc.Stats`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceStats {
    /// Total incoming connections.
    pub connections: u64,
    /// Total incoming packets.
    pub packets_in: u64,
    /// Total outgoing packets.
    pub packets_out: u64,
    /// Total incoming bytes.
    pub bytes_in: u64,
    /// Total outgoing bytes.
    pub bytes_out: u64,
    /// Connections per second.
    pub cps: u64,
    /// Incoming packets per second.
    pub pps_in: u64,
    /// Outgoing packets per second.
    pub pps_out: u64,
    /// Incoming bytes per second.
    pub bps_in: u64,
    /// Outgoing bytes per second.
    pub bps_out: u64,
}

/// IPVS operation error.
#[derive(Debug, thiserror::Error)]
#[error("ipvs error: {0}")]
pub struct IpvsError(pub String);

/// IPVS service/destination operations.
#[async_trait]
pub trait IpvsOps: Send + Sync {
    /// Create or update a virtual service.
    async fn add_service(&self, svc: &IpvsService) -> Result<(), IpvsError>;
    /// Update an existing virtual service's params (scheduler/persistence) in place.
    async fn edit_service(&self, svc: &IpvsService) -> Result<(), IpvsError>;
    /// Delete a virtual service.
    async fn del_service(&self, svc: &IpvsService) -> Result<(), IpvsError>;
    /// Add or update a destination under a service.
    async fn add_destination(
        &self,
        svc: &IpvsService,
        dst: &IpvsDestination,
    ) -> Result<(), IpvsError>;
    /// Delete a destination under a service.
    async fn del_destination(
        &self,
        svc: &IpvsService,
        dst: &IpvsDestination,
    ) -> Result<(), IpvsError>;
    /// Update an existing destination (e.g. set `weight = 0` to drain it during
    /// graceful termination). Defaults to an upsert via [`Self::add_destination`].
    async fn update_destination(
        &self,
        svc: &IpvsService,
        dst: &IpvsDestination,
    ) -> Result<(), IpvsError> {
        self.add_destination(svc, dst).await
    }
    /// Active/inactive connection counts for a destination, if known. `None` means
    /// the backend can't report them, so graceful removal falls back to the timer.
    async fn dest_conn_stats(
        &self,
        _svc: &IpvsService,
        _dst: &IpvsDestination,
    ) -> Result<Option<(u32, u32)>, IpvsError> {
        Ok(None)
    }
    /// Flush UDP conntrack entries for a service VIP:port after a destination
    /// change (mirrors `flushConntrackUDP`). No-op for non-UDP backends.
    async fn flush_conntrack_udp(&self, _addr: IpAddr, _port: u16) -> Result<(), IpvsError> {
        Ok(())
    }
    /// Per-virtual-service statistics, for metrics export. Empty when unsupported.
    async fn service_stats(&self) -> Result<Vec<(IpvsService, ServiceStats)>, IpvsError> {
        Ok(Vec::new())
    }
    /// Create/update a FWMARK-based virtual service (used by DSR). Default no-op.
    async fn add_fwmark_service(
        &self,
        _fwmark: u32,
        _scheduler: Scheduler,
        _persistent: Option<u32>,
    ) -> Result<(), IpvsError> {
        Ok(())
    }
    /// Add a destination under a FWMARK service (tunnel/`-i` forwarding for DSR).
    async fn add_fwmark_destination(
        &self,
        _fwmark: u32,
        _dst: &IpvsDestination,
    ) -> Result<(), IpvsError> {
        Ok(())
    }
}

/// `ipvsadm` args to create/update a FWMARK virtual service.
pub fn add_fwmark_service_args(
    fwmark: u32,
    scheduler: Scheduler,
    persistent: Option<u32>,
) -> Vec<String> {
    let mut a = vec![
        "-A".into(),
        "-f".into(),
        fwmark.to_string(),
        "-s".into(),
        scheduler.ipvs_name().into(),
    ];
    if let Some(t) = persistent {
        a.push("-p".into());
        a.push(t.to_string());
    }
    a
}

/// `ipvsadm` args to add a destination to a FWMARK service (DSR uses `-i` tunnel).
pub fn add_fwmark_dest_args(fwmark: u32, dst: &IpvsDestination) -> Vec<String> {
    vec![
        "-a".into(),
        "-f".into(),
        fwmark.to_string(),
        "-r".into(),
        vip_port(dst.addr, dst.port),
        if dst.tunnel { "-i".into() } else { "-m".into() },
        "-w".into(),
        dst.weight.to_string(),
    ]
}

/// Parse an `ipvsadm`-style `addr:port` token (IPv4 `a.b.c.d:p` or IPv6
/// `[2001:db8::1]:p`).
fn parse_addr_port(tok: &str) -> Option<(IpAddr, u16)> {
    let (addr, port) = if let Some(rest) = tok.strip_prefix('[') {
        let (a, p) = rest.split_once("]:")?;
        (a, p)
    } else {
        tok.rsplit_once(':')?
    };
    Some((addr.parse().ok()?, port.parse().ok()?))
}

fn parse_proto(tok: &str) -> Option<Protocol> {
    match tok {
        "TCP" => Some(Protocol::Tcp),
        "UDP" => Some(Protocol::Udp),
        "SCTP" => Some(Protocol::Sctp),
        _ => None,
    }
}

/// Parse `ipvsadm -Ln --stats --exact` + `--rate --exact` output into per-service
/// statistics. Destination (`->`) and header rows are ignored.
pub fn parse_ipvsadm_stats(stats: &str, rate: &str) -> Vec<(IpvsService, ServiceStats)> {
    let mut map: BTreeMapStats = BTreeMapStats::new();
    for line in stats.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        // Prot Addr:Port Conns InPkts OutPkts InBytes OutBytes
        if f.len() < 7 {
            continue;
        }
        let (Some(proto), Some((addr, port))) = (parse_proto(f[0]), parse_addr_port(f[1])) else {
            continue;
        };
        let s = ServiceStats {
            connections: f[2].parse().unwrap_or(0),
            packets_in: f[3].parse().unwrap_or(0),
            packets_out: f[4].parse().unwrap_or(0),
            bytes_in: f[5].parse().unwrap_or(0),
            bytes_out: f[6].parse().unwrap_or(0),
            ..Default::default()
        };
        map.insert((addr, proto, port), s);
    }
    for line in rate.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        // Prot Addr:Port CPS InPPS OutPPS InBPS OutBPS
        if f.len() < 7 {
            continue;
        }
        let (Some(proto), Some((addr, port))) = (parse_proto(f[0]), parse_addr_port(f[1])) else {
            continue;
        };
        if let Some(s) = map.get_mut(&(addr, proto, port)) {
            s.cps = f[2].parse().unwrap_or(0);
            s.pps_in = f[3].parse().unwrap_or(0);
            s.pps_out = f[4].parse().unwrap_or(0);
            s.bps_in = f[5].parse().unwrap_or(0);
            s.bps_out = f[6].parse().unwrap_or(0);
        }
    }
    map.into_iter()
        .map(|((addr, protocol, port), stats)| {
            (
                IpvsService {
                    addr,
                    protocol,
                    port,
                    scheduler: Scheduler::Rr,
                    persistent: None,
                },
                stats,
            )
        })
        .collect()
}

type BTreeMapStats = std::collections::BTreeMap<(IpAddr, Protocol, u16), ServiceStats>;

fn proto_flag(p: Protocol) -> &'static str {
    match p {
        Protocol::Tcp => "-t",
        Protocol::Udp => "-u",
        Protocol::Sctp => "--sctp-service",
    }
}

fn vip_port(addr: IpAddr, port: u16) -> String {
    match addr {
        IpAddr::V4(_) => format!("{addr}:{port}"),
        IpAddr::V6(_) => format!("[{addr}]:{port}"),
    }
}

/// `ipvsadm` args to create/update a virtual service.
pub fn add_service_args(svc: &IpvsService) -> Vec<String> {
    let mut a = vec![
        "-A".into(),
        proto_flag(svc.protocol).into(),
        vip_port(svc.addr, svc.port),
        "-s".into(),
        svc.scheduler.ipvs_name().into(),
    ];
    if let Some(t) = svc.persistent {
        a.push("-p".into());
        a.push(t.to_string());
    }
    a
}

/// `ipvsadm` args to edit an existing virtual service in place (`-E`) — same
/// fields as add, used to apply scheduler/persistence changes to a live service.
pub fn edit_service_args(svc: &IpvsService) -> Vec<String> {
    let mut a = add_service_args(svc);
    a[0] = "-E".into();
    a
}

/// `ipvsadm` args to delete a virtual service.
pub fn del_service_args(svc: &IpvsService) -> Vec<String> {
    vec![
        "-D".into(),
        proto_flag(svc.protocol).into(),
        vip_port(svc.addr, svc.port),
    ]
}

/// `ipvsadm` args to add/update a destination (`-i` tunnel for DSR, else `-m` masq).
pub fn add_dest_args(svc: &IpvsService, dst: &IpvsDestination) -> Vec<String> {
    vec![
        "-a".into(),
        proto_flag(svc.protocol).into(),
        vip_port(svc.addr, svc.port),
        "-r".into(),
        vip_port(dst.addr, dst.port),
        if dst.tunnel { "-i".into() } else { "-m".into() },
        "-w".into(),
        dst.weight.to_string(),
    ]
}

/// `ipvsadm` args to edit an existing destination (`-e`, e.g. to drain weight).
pub fn edit_dest_args(svc: &IpvsService, dst: &IpvsDestination) -> Vec<String> {
    let mut a = add_dest_args(svc, dst);
    a[0] = "-e".into();
    a
}

/// `ipvsadm` args to delete a destination.
pub fn del_dest_args(svc: &IpvsService, dst: &IpvsDestination) -> Vec<String> {
    vec![
        "-d".into(),
        proto_flag(svc.protocol).into(),
        vip_port(svc.addr, svc.port),
        "-r".into(),
        vip_port(dst.addr, dst.port),
    ]
}

/// `conntrack -D` args to flush UDP entries destined for a service VIP:port.
pub fn conntrack_flush_udp_args(addr: IpAddr, port: u16) -> Vec<String> {
    vec![
        "-D".into(),
        "--orig-dst".into(),
        addr.to_string(),
        "-p".into(),
        "udp".into(),
        "--dport".into(),
        port.to_string(),
    ]
}

/// `IpvsOps` backed by the `ipvsadm` binary (runtime impl).
#[derive(Debug, Default, Clone)]
pub struct SystemIpvs;

impl SystemIpvs {
    /// New instance.
    pub fn new() -> Self {
        Self
    }

    /// Run a genetlink IPVS operation, returning whether it was handled (so the
    /// `ipvsadm` fallback can be skipped). Opening the socket is best-effort.
    fn via_genl<F>(&self, f: F) -> bool
    where
        F: FnOnce(&mut crate::genetlink::Genl) -> std::io::Result<()>,
    {
        match crate::genetlink::Genl::open() {
            Ok(mut g) => match f(&mut g) {
                Ok(()) => {
                    tracing::debug!("ipvs: programmed via genetlink");
                    true
                }
                Err(e) if matches!(e.raw_os_error(), Some(17) | Some(2)) => {
                    tracing::debug!("ipvs: genetlink idempotent ({e})");
                    true
                }
                Err(e) => {
                    tracing::debug!("ipvs: genetlink failed ({e}); falling back to ipvsadm");
                    false
                }
            },
            Err(e) => {
                tracing::debug!("ipvs: genetlink unavailable ({e}); using ipvsadm");
                false
            }
        }
    }

    async fn run(&self, args: &[String]) -> Result<(), IpvsError> {
        let out = tokio::process::Command::new("ipvsadm")
            .args(args)
            .output()
            .await
            .map_err(|e| IpvsError(format!("spawn ipvsadm {args:?}: {e}")))?;
        if out.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&out.stderr);
        // Tolerate idempotent races: already-exists on add, not-found on delete.
        if stderr.contains("already exists") || stderr.contains("No such") {
            return Ok(());
        }
        Err(IpvsError(format!("ipvsadm {args:?}: {}", stderr.trim())))
    }

    /// Run `ipvsadm` and capture stdout (for `--stats`/`--rate` queries).
    async fn run_out(&self, args: &[&str]) -> Result<String, IpvsError> {
        let out = tokio::process::Command::new("ipvsadm")
            .args(args)
            .output()
            .await
            .map_err(|e| IpvsError(format!("spawn ipvsadm {args:?}: {e}")))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(IpvsError(format!("ipvsadm {args:?}: {}", stderr.trim())));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

#[async_trait]
impl IpvsOps for SystemIpvs {
    async fn add_service(&self, svc: &IpvsService) -> Result<(), IpvsError> {
        if self.via_genl(|g| g.add_service(svc)) {
            return Ok(());
        }
        self.run(&add_service_args(svc)).await
    }
    async fn edit_service(&self, svc: &IpvsService) -> Result<(), IpvsError> {
        if self.via_genl(|g| g.set_service(svc)) {
            return Ok(());
        }
        self.run(&edit_service_args(svc)).await
    }
    async fn del_service(&self, svc: &IpvsService) -> Result<(), IpvsError> {
        if self.via_genl(|g| g.del_service(svc)) {
            return Ok(());
        }
        self.run(&del_service_args(svc)).await
    }
    async fn add_destination(
        &self,
        svc: &IpvsService,
        dst: &IpvsDestination,
    ) -> Result<(), IpvsError> {
        if self.via_genl(|g| g.add_destination(svc, dst)) {
            return Ok(());
        }
        self.run(&add_dest_args(svc, dst)).await
    }
    async fn del_destination(
        &self,
        svc: &IpvsService,
        dst: &IpvsDestination,
    ) -> Result<(), IpvsError> {
        if self.via_genl(|g| g.del_destination(svc, dst)) {
            return Ok(());
        }
        self.run(&del_dest_args(svc, dst)).await
    }
    async fn update_destination(
        &self,
        svc: &IpvsService,
        dst: &IpvsDestination,
    ) -> Result<(), IpvsError> {
        self.run(&edit_dest_args(svc, dst)).await
    }
    async fn service_stats(&self) -> Result<Vec<(IpvsService, ServiceStats)>, IpvsError> {
        let stats = self.run_out(&["-Ln", "--stats", "--exact"]).await?;
        let rate = self.run_out(&["-Ln", "--rate", "--exact"]).await?;
        Ok(parse_ipvsadm_stats(&stats, &rate))
    }
    async fn add_fwmark_service(
        &self,
        fwmark: u32,
        scheduler: Scheduler,
        persistent: Option<u32>,
    ) -> Result<(), IpvsError> {
        if self.via_genl(|g| g.add_fwmark_service(fwmark, scheduler, persistent)) {
            return Ok(());
        }
        self.run(&add_fwmark_service_args(fwmark, scheduler, persistent))
            .await
    }
    async fn add_fwmark_destination(
        &self,
        fwmark: u32,
        dst: &IpvsDestination,
    ) -> Result<(), IpvsError> {
        if self.via_genl(|g| g.add_fwmark_destination(fwmark, dst)) {
            return Ok(());
        }
        self.run(&add_fwmark_dest_args(fwmark, dst)).await
    }
    async fn flush_conntrack_udp(&self, addr: IpAddr, port: u16) -> Result<(), IpvsError> {
        let args = conntrack_flush_udp_args(addr, port);
        let out = tokio::process::Command::new("conntrack")
            .args(&args)
            .output()
            .await
            .map_err(|e| IpvsError(format!("spawn conntrack {args:?}: {e}")))?;
        if out.status.success() {
            return Ok(());
        }
        // conntrack exits non-zero when nothing matched ("0 flow entries").
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        if combined.contains("0 flow entries") {
            return Ok(());
        }
        Err(IpvsError(format!(
            "conntrack {args:?}: {}",
            combined.trim()
        )))
    }
}

#[cfg(any(test, feature = "mock"))]
pub mod mock {
    //! In-memory [`IpvsOps`] for unit tests.
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    type Key = (IpAddr, Protocol, u16);

    /// Records IPVS services + their destinations.
    #[derive(Default)]
    pub struct MockIpvs {
        services: Mutex<BTreeMap<String, IpvsService>>,
        destinations: Mutex<BTreeMap<String, Vec<IpvsDestination>>>,
        conn_stats: Mutex<BTreeMap<String, (u32, u32)>>,
        conntrack_flushes: Mutex<Vec<(IpAddr, u16)>>,
        service_stats: Mutex<BTreeMap<String, ServiceStats>>,
        fwmark_services: Mutex<Vec<u32>>,
        fwmark_dests: Mutex<Vec<(u32, IpvsDestination)>>,
        /// Count of destination programming calls (add + update), so tests can
        /// assert an event-driven reconcile only writes the diff.
        dest_writes: AtomicUsize,
    }

    fn k(key: Key) -> String {
        format!("{:?}", key)
    }

    fn dk(svc: &IpvsService, dst: &IpvsDestination) -> String {
        format!("{:?}|{}:{}", svc.key(), dst.addr, dst.port)
    }

    impl MockIpvs {
        /// New empty mock.
        pub fn new() -> Self {
            Self::default()
        }
        /// Total destination programming calls (add + update) since creation.
        pub fn dest_writes(&self) -> usize {
            self.dest_writes.load(Ordering::Relaxed)
        }
        /// Number of virtual services.
        pub fn service_count(&self) -> usize {
            self.services.lock().unwrap().len()
        }
        /// The currently-programmed virtual service matching `svc`'s identity key
        /// (reflects the latest add/edit), for asserting scheduler/persistence.
        pub fn service(&self, svc: &IpvsService) -> Option<IpvsService> {
            self.services.lock().unwrap().get(&k(svc.key())).cloned()
        }
        /// Destinations for a service.
        pub fn destinations(&self, svc: &IpvsService) -> Vec<IpvsDestination> {
            self.destinations
                .lock()
                .unwrap()
                .get(&k(svc.key()))
                .cloned()
                .unwrap_or_default()
        }
        /// Set the active/inactive connection counts reported for a destination.
        pub fn set_conn_stats(
            &self,
            svc: &IpvsService,
            dst: &IpvsDestination,
            active: u32,
            inactive: u32,
        ) {
            self.conn_stats
                .lock()
                .unwrap()
                .insert(dk(svc, dst), (active, inactive));
        }
        /// VIP:port pairs that had their UDP conntrack flushed.
        pub fn conntrack_flushes(&self) -> Vec<(IpAddr, u16)> {
            self.conntrack_flushes.lock().unwrap().clone()
        }
        /// FWMARK services created (DSR).
        pub fn fwmark_services(&self) -> Vec<u32> {
            self.fwmark_services.lock().unwrap().clone()
        }
        /// FWMARK destinations added (DSR).
        pub fn fwmark_dests(&self) -> Vec<(u32, IpvsDestination)> {
            self.fwmark_dests.lock().unwrap().clone()
        }
        /// Set the statistics reported for a service.
        pub fn set_service_stats(&self, svc: &IpvsService, stats: ServiceStats) {
            self.service_stats
                .lock()
                .unwrap()
                .insert(k(svc.key()), stats);
        }
    }

    #[async_trait]
    impl IpvsOps for MockIpvs {
        async fn edit_service(&self, svc: &IpvsService) -> Result<(), IpvsError> {
            self.services
                .lock()
                .unwrap()
                .insert(k(svc.key()), svc.clone());
            Ok(())
        }
        async fn add_service(&self, svc: &IpvsService) -> Result<(), IpvsError> {
            self.services
                .lock()
                .unwrap()
                .insert(k(svc.key()), svc.clone());
            Ok(())
        }
        async fn del_service(&self, svc: &IpvsService) -> Result<(), IpvsError> {
            self.services.lock().unwrap().remove(&k(svc.key()));
            self.destinations.lock().unwrap().remove(&k(svc.key()));
            Ok(())
        }
        async fn add_destination(
            &self,
            svc: &IpvsService,
            dst: &IpvsDestination,
        ) -> Result<(), IpvsError> {
            self.dest_writes.fetch_add(1, Ordering::Relaxed);
            let mut d = self.destinations.lock().unwrap();
            let v = d.entry(k(svc.key())).or_default();
            v.retain(|e| !(e.addr == dst.addr && e.port == dst.port));
            v.push(dst.clone());
            Ok(())
        }
        async fn del_destination(
            &self,
            svc: &IpvsService,
            dst: &IpvsDestination,
        ) -> Result<(), IpvsError> {
            if let Some(v) = self.destinations.lock().unwrap().get_mut(&k(svc.key())) {
                v.retain(|e| !(e.addr == dst.addr && e.port == dst.port));
            }
            Ok(())
        }
        async fn dest_conn_stats(
            &self,
            svc: &IpvsService,
            dst: &IpvsDestination,
        ) -> Result<Option<(u32, u32)>, IpvsError> {
            Ok(self.conn_stats.lock().unwrap().get(&dk(svc, dst)).copied())
        }
        async fn flush_conntrack_udp(&self, addr: IpAddr, port: u16) -> Result<(), IpvsError> {
            self.conntrack_flushes.lock().unwrap().push((addr, port));
            Ok(())
        }
        async fn add_fwmark_service(
            &self,
            fwmark: u32,
            _scheduler: Scheduler,
            _persistent: Option<u32>,
        ) -> Result<(), IpvsError> {
            self.fwmark_services.lock().unwrap().push(fwmark);
            Ok(())
        }
        async fn add_fwmark_destination(
            &self,
            fwmark: u32,
            dst: &IpvsDestination,
        ) -> Result<(), IpvsError> {
            self.fwmark_dests
                .lock()
                .unwrap()
                .push((fwmark, dst.clone()));
            Ok(())
        }
        async fn service_stats(&self) -> Result<Vec<(IpvsService, ServiceStats)>, IpvsError> {
            let svcs = self.services.lock().unwrap();
            let stats = self.service_stats.lock().unwrap();
            Ok(svcs
                .iter()
                .map(|(key, svc)| (svc.clone(), stats.get(key).cloned().unwrap_or_default()))
                .collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock::MockIpvs;
    use super::*;

    fn svc() -> IpvsService {
        IpvsService {
            addr: "10.96.0.10".parse().unwrap(),
            protocol: Protocol::Tcp,
            port: 80,
            scheduler: Scheduler::Rr,
            persistent: None,
        }
    }
    fn dst(ip: &str) -> IpvsDestination {
        IpvsDestination {
            addr: ip.parse().unwrap(),
            port: 8080,
            weight: 1,
            tunnel: false,
        }
    }

    #[tokio::test]
    async fn service_and_destination_lifecycle() {
        let ipvs = MockIpvs::new();
        ipvs.add_service(&svc()).await.unwrap();
        assert_eq!(ipvs.service_count(), 1);

        ipvs.add_destination(&svc(), &dst("10.244.0.5"))
            .await
            .unwrap();
        ipvs.add_destination(&svc(), &dst("10.244.1.5"))
            .await
            .unwrap();
        assert_eq!(ipvs.destinations(&svc()).len(), 2);

        ipvs.del_destination(&svc(), &dst("10.244.0.5"))
            .await
            .unwrap();
        assert_eq!(ipvs.destinations(&svc()).len(), 1);

        ipvs.del_service(&svc()).await.unwrap();
        assert_eq!(ipvs.service_count(), 0);
        assert!(ipvs.destinations(&svc()).is_empty());
    }

    #[test]
    fn proto_flag_covers_all_families() {
        // Ported: ipvsadm protocol flags for TCP/UDP/SCTP.
        let s = |p: Protocol| {
            add_service_args(&IpvsService {
                protocol: p,
                ..svc()
            })[1]
                .clone()
        };
        assert_eq!(s(Protocol::Tcp), "-t");
        assert_eq!(s(Protocol::Udp), "-u");
        assert_eq!(s(Protocol::Sctp), "--sctp-service");
    }

    #[test]
    fn ipvsadm_add_service_args_with_affinity() {
        let mut s = svc();
        s.scheduler = Scheduler::Mh;
        s.persistent = Some(10800);
        let a = add_service_args(&s);
        assert_eq!(&a[0..5], &["-A", "-t", "10.96.0.10:80", "-s", "mh"]);
        assert!(a.ends_with(&["-p".to_string(), "10800".to_string()]));
    }

    #[test]
    fn ipvsadm_dest_args_masq_vs_tunnel_and_v6_bracket() {
        let masq = add_dest_args(&svc(), &dst("10.244.0.5"));
        assert!(masq.contains(&"-m".to_string()) && masq.contains(&"10.244.0.5:8080".to_string()));
        let mut d = dst("10.244.0.5");
        d.tunnel = true;
        assert!(add_dest_args(&svc(), &d).contains(&"-i".to_string()));
        // v6 destination is bracketed.
        let v6 = IpvsDestination {
            addr: "fd00::5".parse().unwrap(),
            port: 8080,
            weight: 1,
            tunnel: false,
        };
        assert!(add_dest_args(&svc(), &v6).contains(&"[fd00::5]:8080".to_string()));
    }

    #[test]
    fn parses_ipvsadm_stats_and_rate() {
        let stats = "\
IP Virtual Server version 1.2.1 (size=4096)
Prot LocalAddress:Port               Conns   InPkts  OutPkts  InBytes OutBytes
  -> RemoteAddress:Port
TCP  10.96.0.10:80                       10      100       90    10000     9000
  -> 10.244.0.5:8080                       5       50       45     5000     4500
UDP  10.96.0.20:53                         3       30       28      900      850";
        let rate = "\
Prot LocalAddress:Port                 CPS    InPPS   OutPPS    InBPS   OutBPS
TCP  10.96.0.10:80                        1       10        9     1000      900
  -> 10.244.0.5:8080                       0        5        4      500      450";
        let mut out = parse_ipvsadm_stats(stats, rate);
        out.sort_by_key(|(s, _)| s.port);
        assert_eq!(out.len(), 2);

        let (udp, _) = &out[0]; // port 53
        assert_eq!(udp.protocol, Protocol::Udp);
        let (tcp, tcp_stats) = &out[1]; // port 80
        assert_eq!(tcp.addr.to_string(), "10.96.0.10");
        assert_eq!(tcp_stats.connections, 10);
        assert_eq!(tcp_stats.bytes_in, 10000);
        assert_eq!(tcp_stats.cps, 1);
        assert_eq!(tcp_stats.bps_in, 1000);
    }

    #[test]
    fn parses_ipv6_service_address() {
        let stats = "TCP  [fd00::1]:80   7   70   60   7000   6000";
        let out = parse_ipvsadm_stats(stats, "");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0.addr.to_string(), "fd00::1");
        assert_eq!(out[0].1.connections, 7);
    }

    #[tokio::test]
    async fn add_destination_is_idempotent_per_addr_port() {
        let ipvs = MockIpvs::new();
        ipvs.add_service(&svc()).await.unwrap();
        ipvs.add_destination(&svc(), &dst("10.244.0.5"))
            .await
            .unwrap();
        let mut updated = dst("10.244.0.5");
        updated.weight = 0; // drain
        ipvs.add_destination(&svc(), &updated).await.unwrap();
        let d = ipvs.destinations(&svc());
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].weight, 0);
    }
}
