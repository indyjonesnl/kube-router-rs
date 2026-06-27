//! Projected Service/Endpoint model, mirroring `serviceInfo`/`endpointSliceInfo`
//! in `upstream/pkg/controllers/proxy/network_services_controller.go`.

use std::net::IpAddr;

/// Service L4 protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Protocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
    /// SCTP.
    Sctp,
}

impl Protocol {
    /// Parse a Kubernetes protocol string (defaults to TCP).
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_uppercase().as_str() {
            "UDP" => Protocol::Udp,
            "SCTP" => Protocol::Sctp,
            _ => Protocol::Tcp,
        }
    }
}

/// IPVS scheduler (from `kube-router.io/service.scheduler`, default round-robin).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Scheduler {
    /// Round-robin.
    #[default]
    Rr,
    /// Least-connection.
    Lc,
    /// Source hashing.
    Sh,
    /// Destination hashing.
    Dh,
    /// Maglev.
    Mh,
}

impl Scheduler {
    /// Parse the scheduler annotation value (unknown → round-robin).
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "lc" => Scheduler::Lc,
            "sh" => Scheduler::Sh,
            "dh" => Scheduler::Dh,
            "mh" => Scheduler::Mh,
            _ => Scheduler::Rr,
        }
    }

    /// IPVS scheduler name passed to the kernel.
    pub fn ipvs_name(self) -> &'static str {
        match self {
            Scheduler::Rr => "rr",
            Scheduler::Lc => "lc",
            Scheduler::Sh => "sh",
            Scheduler::Dh => "dh",
            Scheduler::Mh => "mh",
        }
    }
}

/// A projected Service port (one IPVS virtual service per VIP × port).
#[derive(Debug, Clone)]
pub struct ServiceInfo {
    /// Namespace.
    pub namespace: String,
    /// Name.
    pub name: String,
    /// Service port name (part of the identity).
    pub port_name: String,
    /// Protocol.
    pub protocol: Protocol,
    /// Service port.
    pub port: u16,
    /// NodePort, if any.
    pub node_port: Option<u16>,
    /// ClusterIPs.
    pub cluster_ips: Vec<IpAddr>,
    /// ExternalIPs.
    pub external_ips: Vec<IpAddr>,
    /// LoadBalancer ingress IPs.
    pub load_balancer_ips: Vec<IpAddr>,
    /// IPVS scheduler.
    pub scheduler: Scheduler,
    /// Session affinity (sticky by client IP).
    pub session_affinity: bool,
    /// Affinity timeout (seconds), when `session_affinity`.
    pub affinity_timeout: u32,
    /// DSR (direct server return) requested.
    pub dsr: bool,
    /// `internalTrafficPolicy: Local` — ClusterIP traffic to local endpoints only.
    pub internal_traffic_local: bool,
    /// `externalTrafficPolicy: Local` — external/LB traffic to local endpoints only.
    pub external_traffic_local: bool,
    /// Hairpin SNAT requested (`kube-router.io/service.hairpin` or global mode).
    pub hairpin: bool,
    /// `spec.healthCheckNodePort` for `externalTrafficPolicy: Local` LB services.
    pub health_check_node_port: Option<u16>,
}

impl ServiceInfo {
    /// Stable identity key (`namespace/name/port_name`).
    pub fn id(&self) -> String {
        format!("{}/{}/{}", self.namespace, self.name, self.port_name)
    }
}

/// A projected Service endpoint (becomes an IPVS destination).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointInfo {
    /// Endpoint IP.
    pub ip: IpAddr,
    /// Endpoint port.
    pub port: u16,
    /// On the local node.
    pub is_local: bool,
    /// Ready (serving, not terminating).
    pub ready: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_parses_case_insensitively_defaulting_tcp() {
        assert_eq!(Protocol::parse("udp"), Protocol::Udp);
        assert_eq!(Protocol::parse("SCTP"), Protocol::Sctp);
        assert_eq!(Protocol::parse("anything"), Protocol::Tcp);
    }

    #[test]
    fn scheduler_parses_and_maps_to_ipvs_name() {
        assert_eq!(Scheduler::parse("mh"), Scheduler::Mh);
        assert_eq!(Scheduler::parse("LC").ipvs_name(), "lc");
        assert_eq!(Scheduler::parse("bogus"), Scheduler::Rr);
        assert_eq!(Scheduler::default().ipvs_name(), "rr");
    }

    #[test]
    fn service_id_is_stable() {
        let svc = ServiceInfo {
            namespace: "default".into(),
            name: "web".into(),
            port_name: "http".into(),
            protocol: Protocol::Tcp,
            port: 80,
            node_port: None,
            cluster_ips: vec!["10.96.0.10".parse().unwrap()],
            external_ips: vec![],
            load_balancer_ips: vec![],
            scheduler: Scheduler::Rr,
            session_affinity: false,
            affinity_timeout: 0,
            dsr: false,
            internal_traffic_local: false,
            external_traffic_local: false,
            hairpin: false,
            health_check_node_port: None,
        };
        assert_eq!(svc.id(), "default/web/http");
    }
}
