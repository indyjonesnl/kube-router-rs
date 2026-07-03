//! Concrete [`BgpEngine`] that drives GoBGP over its gRPC API.
//!
//! Connects to the gobgp admin endpoint (managed by [`crate::server`]) and maps
//! our engine calls to the gobgp `GoBgpService` RPCs (codegen in
//! [`crate::gobgp_api`]). Mirrors the calls kube-router's Go routing controller
//! makes against gobgp.

use std::net::IpAddr;

use async_trait::async_trait;
use ipnet::IpNet;
use tokio::sync::mpsc;
use tonic::transport::{Channel, Endpoint};

use crate::engine::{BgpEngine, BgpError, GlobalConfig, PeerConfig};
use crate::gobgp_api as api;
use crate::gobgp_api::go_bgp_service_client::GoBgpServiceClient;
use crate::path::{Afi, Path};

// gobgp Family enum numeric values (api/common.proto).
const AFI_IP: i32 = 1;
const AFI_IP6: i32 = 2;
const SAFI_UNICAST: i32 = 1;
const DEFAULT_BGP_PORT: u32 = 179;

fn map_err<E: std::fmt::Display>(e: E) -> BgpError {
    BgpError::Engine(e.to_string())
}

fn family(afi: i32) -> api::Family {
    api::Family {
        afi,
        safi: SAFI_UNICAST,
    }
}

fn prefix_nlri(p: &Path) -> api::Nlri {
    api::Nlri {
        nlri: Some(api::nlri::Nlri::Prefix(api::IpAddressPrefix {
            prefix_len: u32::from(p.prefix.prefix_len()),
            prefix: p.prefix.addr().to_string(),
        })),
    }
}

fn origin_attr() -> api::Attribute {
    api::Attribute {
        attr: Some(api::attribute::Attr::Origin(api::OriginAttribute {
            origin: 0,
        })),
    }
}

/// Build a gobgp `Path` for advertisement/withdrawal: IPv4 carries a NEXT_HOP
/// attribute, IPv6 an MP_REACH_NLRI attribute (mirrors `crate::path::PathBuilder`).
fn build_path(p: &Path) -> api::Path {
    let nlri = prefix_nlri(p);
    let (afi, mut pattrs) = match p.afi {
        Afi::Ip => (
            AFI_IP,
            vec![
                origin_attr(),
                api::Attribute {
                    attr: Some(api::attribute::Attr::NextHop(api::NextHopAttribute {
                        next_hop: p.next_hop.to_string(),
                    })),
                },
            ],
        ),
        Afi::Ip6 => (
            AFI_IP6,
            vec![
                origin_attr(),
                api::Attribute {
                    attr: Some(api::attribute::Attr::MpReach(api::MpReachNlriAttribute {
                        family: Some(family(AFI_IP6)),
                        next_hops: vec![p.next_hop.to_string()],
                        nlris: vec![prefix_nlri(p)],
                    })),
                },
            ],
        ),
    };
    // COMMUNITIES + AS_PATH prepend attributes (from node BGP policy).
    for attr in &p.attrs {
        match attr {
            crate::path::Attr::Communities(comms) if !comms.is_empty() => {
                pattrs.push(api::Attribute {
                    attr: Some(api::attribute::Attr::Communities(
                        api::CommunitiesAttribute {
                            communities: comms.clone(),
                        },
                    )),
                });
            }
            crate::path::Attr::AsPathPrepend { asn, repeat } if *repeat > 0 => {
                pattrs.push(api::Attribute {
                    attr: Some(api::attribute::Attr::AsPath(api::AsPathAttribute {
                        segments: vec![api::AsSegment {
                            r#type: api::as_segment::Type::AsSequence as i32,
                            numbers: vec![*asn; *repeat as usize],
                        }],
                    })),
                });
            }
            _ => {}
        }
    }
    api::Path {
        nlri: Some(nlri),
        pattrs,
        is_withdraw: p.withdrawal,
        family: Some(family(afi)),
        ..Default::default()
    }
}

/// A best-path event learned from a BGP peer (for kernel route injection).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathEvent {
    /// Destination prefix.
    pub prefix: IpNet,
    /// Next hop.
    pub next_hop: IpAddr,
    /// Whether the prefix is being withdrawn.
    pub withdrawal: bool,
}

/// Parse a gobgp `Path` (from a best-path watch) into a [`PathEvent`], or `None`
/// if it isn't an IP-prefix path or carries no usable next hop.
fn parse_path_event(p: &api::Path) -> Option<PathEvent> {
    let pfx = match p.nlri.as_ref()?.nlri.as_ref()? {
        api::nlri::Nlri::Prefix(ip) => ip,
        _ => return None,
    };
    let prefix: IpNet = format!("{}/{}", pfx.prefix, pfx.prefix_len).parse().ok()?;

    let mut next_hop: Option<IpAddr> = None;
    for a in &p.pattrs {
        match &a.attr {
            Some(api::attribute::Attr::NextHop(nh)) => next_hop = nh.next_hop.parse().ok(),
            Some(api::attribute::Attr::MpReach(m)) => {
                next_hop = m.next_hops.first().and_then(|h| h.parse().ok())
            }
            _ => {}
        }
    }
    Some(PathEvent {
        prefix,
        next_hop: next_hop?,
        withdrawal: p.is_withdraw,
    })
}

/// A [`BgpEngine`] backed by a gobgp gRPC connection.
#[derive(Clone)]
pub struct GobgpGrpcEngine {
    channel: Channel,
}

impl GobgpGrpcEngine {
    /// Create a lazily-connecting engine for the gobgp admin endpoint.
    pub fn connect_lazy(admin_addr: &str, admin_port: u16) -> Result<Self, BgpError> {
        let uri = format!("http://{admin_addr}:{admin_port}");
        let channel = Endpoint::from_shared(uri).map_err(map_err)?.connect_lazy();
        Ok(Self { channel })
    }

    fn client(&self) -> GoBgpServiceClient<Channel> {
        GoBgpServiceClient::new(self.channel.clone())
    }

    /// Subscribe to best-path table events and forward each as a [`PathEvent`] on
    /// `tx`. Runs until the stream ends or the receiver is dropped.
    pub async fn watch_best_paths(&self, tx: mpsc::Sender<PathEvent>) -> Result<(), BgpError> {
        let req = api::WatchEventRequest {
            table: Some(api::watch_event_request::Table {
                filters: vec![api::watch_event_request::table::Filter {
                    r#type: api::watch_event_request::table::filter::Type::Best as i32,
                    init: true,
                    ..Default::default()
                }],
            }),
            ..Default::default()
        };
        let mut stream = self
            .client()
            .watch_event(req)
            .await
            .map_err(map_err)?
            .into_inner();
        while let Some(resp) = stream.message().await.map_err(map_err)? {
            if let Some(api::watch_event_response::Event::Table(t)) = resp.event {
                for p in &t.paths {
                    if let Some(ev) = parse_path_event(p) {
                        if tx.send(ev).await.is_err() {
                            return Ok(());
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Both IPv4 and IPv6 unicast afi-safis (gobgp negotiates what the peer
    /// supports). Enables per-AFI MP-Graceful-Restart when `gr` is set.
    fn dual_afi_safis(gr: bool) -> Vec<api::AfiSafi> {
        [AFI_IP, AFI_IP6]
            .into_iter()
            .map(|afi| api::AfiSafi {
                config: Some(api::AfiSafiConfig {
                    family: Some(api::Family {
                        afi,
                        safi: SAFI_UNICAST,
                    }),
                    enabled: true,
                }),
                mp_graceful_restart: gr.then(|| api::MpGracefulRestart {
                    config: Some(api::MpGracefulRestartConfig { enabled: true }),
                    ..Default::default()
                }),
                ..Default::default()
            })
            .collect()
    }
}

#[async_trait]
impl BgpEngine for GobgpGrpcEngine {
    async fn start(&self, global: &GlobalConfig) -> Result<(), BgpError> {
        let g = api::Global {
            asn: global.asn,
            router_id: global.router_id.clone().unwrap_or_default(),
            listen_port: global.listen_port as i32,
            listen_addresses: global
                .listen_addresses
                .iter()
                .map(|a| a.to_string())
                .collect(),
            ..Default::default()
        };
        self.client()
            .start_bgp(api::StartBgpRequest { global: Some(g) })
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn stop(&self) -> Result<(), BgpError> {
        self.client()
            .stop_bgp(api::StopBgpRequest {
                allow_graceful_restart: false,
            })
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn add_peer(&self, peer: &PeerConfig) -> Result<(), BgpError> {
        let conf = api::PeerConf {
            neighbor_address: peer.neighbor.to_string(),
            peer_asn: peer.peer_asn,
            auth_password: peer.password.clone().unwrap_or_default(),
            ..Default::default()
        };
        let transport = api::Transport {
            local_address: peer
                .local_address
                .map(|a| a.to_string())
                .unwrap_or_default(),
            remote_port: peer.port.map(u32::from).unwrap_or(DEFAULT_BGP_PORT),
            ..Default::default()
        };
        let ebgp_multihop = peer.multihop_ttl.map(|ttl| api::EbgpMultihop {
            enabled: true,
            multihop_ttl: u32::from(ttl),
        });
        let route_reflector = peer.rr_client.then(|| api::RouteReflector {
            route_reflector_client: true,
            route_reflector_cluster_id: peer.rr_cluster_id.clone().unwrap_or_default(),
        });
        let graceful_restart = peer.graceful_restart.map(|gr| api::GracefulRestart {
            enabled: true,
            restart_time: gr.restart_time_secs,
            deferral_time: gr.deferral_time_secs,
            ..Default::default()
        });
        let p = api::Peer {
            conf: Some(conf),
            transport: Some(transport),
            ebgp_multihop,
            route_reflector,
            graceful_restart,
            afi_safis: Self::dual_afi_safis(peer.graceful_restart.is_some()),
            ..Default::default()
        };
        self.client()
            .add_peer(api::AddPeerRequest { peer: Some(p) })
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn delete_peer(&self, neighbor: IpAddr) -> Result<(), BgpError> {
        self.client()
            .delete_peer(api::DeletePeerRequest {
                address: neighbor.to_string(),
                interface: String::new(),
            })
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn add_path(&self, path: &Path) -> Result<(), BgpError> {
        self.client()
            .add_path(api::AddPathRequest {
                table_type: api::TableType::Global as i32,
                vrf_id: String::new(),
                path: Some(build_path(path)),
            })
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn delete_path(&self, path: &Path) -> Result<(), BgpError> {
        let mut p = build_path(path);
        p.is_withdraw = true;
        let fam = p.family;
        self.client()
            .delete_path(api::DeletePathRequest {
                table_type: api::TableType::Global as i32,
                vrf_id: String::new(),
                family: fam,
                path: Some(p),
                uuid: Vec::new(),
            })
            .await
            .map_err(map_err)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn lazy_connect_builds_engine() {
        // connect_lazy doesn't dial, but building the channel needs a runtime handle.
        assert!(GobgpGrpcEngine::connect_lazy("127.0.0.1", 50051).is_ok());
    }

    use crate::path::PathBuilder;

    #[test]
    fn build_path_v4_has_prefix_origin_and_next_hop() {
        let p = PathBuilder::new(
            "10.244.0.0/24".parse().unwrap(),
            "192.168.32.5".parse().unwrap(),
        )
        .build();
        let gp = build_path(&p);
        assert!(!gp.is_withdraw);
        assert_eq!(gp.family.as_ref().unwrap().afi, AFI_IP);
        // NLRI prefix matches.
        match gp.nlri.unwrap().nlri.unwrap() {
            api::nlri::Nlri::Prefix(pfx) => {
                assert_eq!(pfx.prefix, "10.244.0.0");
                assert_eq!(pfx.prefix_len, 24);
            }
            _ => panic!("expected prefix nlri"),
        }
        // Origin + NextHop attributes, no MpReach.
        let has_next_hop = gp
            .pattrs
            .iter()
            .any(|a| matches!(a.attr, Some(api::attribute::Attr::NextHop(_))));
        let has_mp = gp
            .pattrs
            .iter()
            .any(|a| matches!(a.attr, Some(api::attribute::Attr::MpReach(_))));
        assert!(has_next_hop && !has_mp);
    }

    #[test]
    fn build_path_v6_uses_mp_reach() {
        let p =
            PathBuilder::new("fd00:244::/64".parse().unwrap(), "fd00::5".parse().unwrap()).build();
        let gp = build_path(&p);
        assert_eq!(gp.family.as_ref().unwrap().afi, AFI_IP6);
        let mp = gp
            .pattrs
            .iter()
            .find_map(|a| match &a.attr {
                Some(api::attribute::Attr::MpReach(m)) => Some(m),
                _ => None,
            })
            .expect("mp_reach present");
        assert_eq!(mp.next_hops, vec!["fd00::5".to_string()]);
        assert_eq!(mp.nlris.len(), 1);
    }

    #[test]
    fn path_event_roundtrips_v4() {
        let p = PathBuilder::new(
            "10.244.1.0/24".parse().unwrap(),
            "192.168.32.4".parse().unwrap(),
        )
        .build();
        let ev = parse_path_event(&build_path(&p)).expect("parses");
        assert_eq!(ev.prefix, "10.244.1.0/24".parse::<IpNet>().unwrap());
        assert_eq!(ev.next_hop, "192.168.32.4".parse::<IpAddr>().unwrap());
        assert!(!ev.withdrawal);
    }

    #[test]
    fn path_event_roundtrips_v6_via_mp_reach() {
        let p = PathBuilder::new(
            "fd00:244:1::/64".parse().unwrap(),
            "fd00::4".parse().unwrap(),
        )
        .build();
        let ev = parse_path_event(&build_path(&p)).expect("parses");
        assert_eq!(ev.prefix, "fd00:244:1::/64".parse::<IpNet>().unwrap());
        assert_eq!(ev.next_hop, "fd00::4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn build_path_withdrawal_flag() {
        let p = PathBuilder::new(
            "10.244.0.0/24".parse().unwrap(),
            "192.168.32.5".parse().unwrap(),
        )
        .withdrawal(true)
        .build();
        assert!(build_path(&p).is_withdraw);
    }

    #[test]
    fn dual_afi_safis_has_v4_and_v6_unicast() {
        let afs = GobgpGrpcEngine::dual_afi_safis(false);
        assert_eq!(afs.len(), 2);
        let fams: Vec<(i32, i32)> = afs
            .iter()
            .map(|a| {
                let f = a.config.as_ref().unwrap().family.as_ref().unwrap();
                (f.afi, f.safi)
            })
            .collect();
        assert!(fams.contains(&(AFI_IP, SAFI_UNICAST)));
        assert!(fams.contains(&(AFI_IP6, SAFI_UNICAST)));
    }
}
