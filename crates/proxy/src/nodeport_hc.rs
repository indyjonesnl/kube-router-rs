//! NodePort health-check HTTP servers, mirroring `nodeport_healthcheck.go`.
//!
//! For `externalTrafficPolicy: Local` LoadBalancer services Kubernetes assigns a
//! `healthCheckNodePort`; an external LB probes `/healthz` on it and only routes
//! to nodes with active local endpoints. We run one server per such port,
//! answering 200 when this node has a ready local endpoint, else 503.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use kr_observability::http::{bind, serve, Response};
use tokio::task::JoinHandle;

use crate::model::{EndpointInfo, ServiceInfo};

/// Count of ready local endpoints per `healthCheckNodePort` across the services.
pub fn active_local_counts(services: &[(ServiceInfo, Vec<EndpointInfo>)]) -> BTreeMap<u16, usize> {
    let mut out = BTreeMap::new();
    for (svc, eps) in services {
        let Some(port) = svc.health_check_node_port else {
            continue;
        };
        let active = eps.iter().filter(|e| e.is_local && e.ready).count();
        *out.entry(port).or_insert(0) += active;
    }
    out
}

/// `/healthz` response for a NodePort health check: 200 with the count when this
/// node has active local endpoints, else 503 (matches the upstream handler).
pub fn nphc_response(path: &str, port: u16, counts: &Mutex<BTreeMap<u16, usize>>) -> Response {
    if !path.starts_with("/healthz") {
        return Response {
            status: 404,
            content_type: "text/plain",
            body: "not found".into(),
        };
    }
    let active = counts.lock().unwrap().get(&port).copied().unwrap_or(0);
    if active > 0 {
        Response {
            status: 200,
            content_type: "text/plain",
            body: format!("{active} Service Endpoints found\n"),
        }
    } else {
        Response {
            status: 503,
            content_type: "text/plain",
            body: "No Service Endpoints Found\n".into(),
        }
    }
}

/// Manages one HTTP server per active `healthCheckNodePort`.
#[derive(Default)]
pub struct NodePortHealthChecks {
    counts: Arc<Mutex<BTreeMap<u16, usize>>>,
    servers: BTreeMap<u16, JoinHandle<()>>,
    bind_host: String,
}

impl NodePortHealthChecks {
    /// New manager binding servers on all interfaces (`0.0.0.0`).
    pub fn new() -> Self {
        Self {
            counts: Arc::new(Mutex::new(BTreeMap::new())),
            servers: BTreeMap::new(),
            bind_host: "0.0.0.0".into(),
        }
    }

    /// Override the bind host (tests use `127.0.0.1`).
    pub fn with_bind_host(mut self, host: &str) -> Self {
        self.bind_host = host.into();
        self
    }

    /// Number of running health-check servers.
    pub fn active_ports(&self) -> Vec<u16> {
        self.servers.keys().copied().collect()
    }

    /// Reconcile to `desired` (port → active local endpoint count): update the
    /// shared counts, start servers for new ports, stop servers for gone ports.
    pub async fn sync(&mut self, desired: BTreeMap<u16, usize>) -> std::io::Result<()> {
        *self.counts.lock().unwrap() = desired.clone();

        let removed: Vec<u16> = self
            .servers
            .keys()
            .filter(|p| !desired.contains_key(p))
            .copied()
            .collect();
        for p in removed {
            if let Some(h) = self.servers.remove(&p) {
                h.abort();
            }
        }

        for &port in desired.keys() {
            if self.servers.contains_key(&port) {
                continue;
            }
            let listener = bind(&format!("{}:{port}", self.bind_host)).await?;
            let counts = self.counts.clone();
            let handle = tokio::spawn(serve(listener, move |path: &str| {
                nphc_response(path, port, &counts)
            }));
            self.servers.insert(port, handle);
        }
        Ok(())
    }

    /// Stop all running servers.
    pub fn stop_all(&mut self) {
        for (_, h) in std::mem::take(&mut self.servers) {
            h.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Protocol, SchedFlags, Scheduler};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn svc(hcnp: Option<u16>) -> ServiceInfo {
        ServiceInfo {
            namespace: "default".into(),
            name: "web".into(),
            port_name: "http".into(),
            protocol: Protocol::Tcp,
            port: 80,
            node_port: Some(30080),
            cluster_ips: vec!["10.96.0.10".parse().unwrap()],
            external_ips: vec![],
            load_balancer_ips: vec![],
            scheduler: Scheduler::Rr,
            sched_flags: SchedFlags::default(),
            session_affinity: false,
            affinity_timeout: 0,
            dsr: false,
            internal_traffic_local: false,
            external_traffic_local: true,
            hairpin: false,
            hairpin_external_ips: false,
            health_check_node_port: hcnp,
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
    fn counts_only_local_ready_endpoints_per_hcnp() {
        let services = vec![
            (
                svc(Some(31000)),
                vec![ep("10.244.0.5", true, true), ep("10.244.1.5", false, true)],
            ),
            (svc(None), vec![ep("10.244.0.6", true, true)]), // no HCNP → ignored
        ];
        let counts = active_local_counts(&services);
        assert_eq!(counts.get(&31000), Some(&1));
        assert_eq!(counts.len(), 1);
    }

    #[test]
    fn response_200_when_active_else_503() {
        let counts = Mutex::new(BTreeMap::from([(31000u16, 2usize)]));
        let ok = nphc_response("/healthz", 31000, &counts);
        assert_eq!(ok.status, 200);
        assert!(ok.body.contains("2 Service Endpoints"));
        let down = nphc_response("/healthz", 31001, &counts);
        assert_eq!(down.status, 503);
        assert_eq!(nphc_response("/other", 31000, &counts).status, 404);
    }

    async fn get(addr: &str) -> String {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut out = Vec::new();
        s.read_to_end(&mut out).await.unwrap();
        String::from_utf8_lossy(&out).into_owned()
    }

    #[tokio::test]
    async fn server_starts_and_stops_with_sync() {
        let mut nphc = NodePortHealthChecks::new().with_bind_host("127.0.0.1");
        // Pick an ephemeral free port for the test.
        let probe = bind("127.0.0.1:0").await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);

        nphc.sync(BTreeMap::from([(port, 3usize)])).await.unwrap();
        assert_eq!(nphc.active_ports(), vec![port]);
        let resp = get(&format!("127.0.0.1:{port}")).await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp}");
        assert!(resp.contains("3 Service Endpoints"));

        // Drop to zero active → still serving but 503.
        nphc.sync(BTreeMap::from([(port, 0usize)])).await.unwrap();
        let resp = get(&format!("127.0.0.1:{port}")).await;
        assert!(resp.starts_with("HTTP/1.1 503"), "got: {resp}");

        // Remove the port entirely → server stops.
        nphc.sync(BTreeMap::new()).await.unwrap();
        assert!(nphc.active_ports().is_empty());
    }
}
