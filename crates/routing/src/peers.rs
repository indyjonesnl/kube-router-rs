//! iBGP peer-topology derivation, mirroring `upstream/pkg/controllers/routing/bgp_peers.go`.
//!
//! Supported topologies:
//! - **Full mesh** (`--nodes-full-mesh`): peer with every other node.
//! - **Per-AS** (`--nodes-full-mesh=false`, `--enable-ibgp`): peer only with nodes
//!   sharing the local node's ASN (from the `kube-router.io/node.asn` annotation).
//! - **Route reflector** (RR): a server peers with all nodes and marks non-server
//!   peers as RR clients (with its cluster id); a client peers only with servers.

use std::net::IpAddr;

/// A node's BGP-relevant attributes (parsed from node annotations + config).
#[derive(Debug, Clone)]
pub struct NodeBgp {
    /// Node name.
    pub name: String,
    /// Node primary IP used as the BGP neighbor address.
    pub ip: IpAddr,
    /// Node ASN.
    pub asn: u32,
    /// RR server cluster id, if this node is a route reflector server.
    pub rr_server: Option<u32>,
    /// RR client cluster id, if this node is a route reflector client.
    pub rr_client: Option<u32>,
}

/// A derived iBGP peer relationship.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpPeer {
    /// Neighbor address.
    pub neighbor: IpAddr,
    /// Neighbor ASN.
    pub peer_asn: u32,
    /// True for eBGP (external) peers; always false here (iBGP).
    pub is_external: bool,
    /// Whether the local node treats this neighbor as a route-reflector client.
    pub rr_client: bool,
    /// RR cluster id to apply when `rr_client` is true.
    pub rr_cluster_id: Option<u32>,
}

/// Derive the iBGP peers the `local` node should configure, given the other
/// cluster nodes. Returns empty when iBGP is disabled.
pub fn derive_ibgp_peers(
    local: &NodeBgp,
    others: &[NodeBgp],
    full_mesh: bool,
    enable_ibgp: bool,
) -> Vec<BgpPeer> {
    if !enable_ibgp {
        return Vec::new();
    }

    let local_is_rr_server = local.rr_server.is_some();
    let local_is_rr_client = local.rr_client.is_some();

    let mut peers = Vec::new();
    for o in others {
        if o.name == local.name {
            continue;
        }

        let mut rr_client = false;
        let mut rr_cluster_id = None;

        let should_peer = if local_is_rr_server {
            // Server peers with everyone; non-server neighbors are RR clients.
            if o.rr_server.is_none() {
                rr_client = true;
                rr_cluster_id = local.rr_server;
            }
            true
        } else if local_is_rr_client {
            // Client peers only with servers.
            o.rr_server.is_some()
        } else if full_mesh {
            true
        } else {
            // Per-AS: peer only within the same ASN.
            o.asn == local.asn
        };

        if should_peer {
            peers.push(BgpPeer {
                neighbor: o.ip,
                peer_asn: o.asn,
                is_external: false,
                rr_client,
                rr_cluster_id,
            });
        }
    }
    peers
}

/// Reconcile currently-configured peers against the desired set.
///
/// Returns `(to_add, to_remove)`: peers present in `desired` but absent or
/// changed in `current` are added; neighbor addresses present in `current` but
/// absent from `desired` are removed. The controller feeds these to
/// `AddPeer`/`DeletePeer` (gRPC wiring lands with T034).
pub fn peer_diff(current: &[BgpPeer], desired: &[BgpPeer]) -> (Vec<BgpPeer>, Vec<IpAddr>) {
    let to_add: Vec<BgpPeer> = desired
        .iter()
        .filter(|d| !current.iter().any(|c| *c == **d))
        .cloned()
        .collect();
    let to_remove: Vec<IpAddr> = current
        .iter()
        .filter(|c| !desired.iter().any(|d| d.neighbor == c.neighbor))
        .map(|c| c.neighbor)
        .collect();
    (to_add, to_remove)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(name: &str, ip: &str, asn: u32) -> NodeBgp {
        NodeBgp {
            name: name.to_string(),
            ip: ip.parse().unwrap(),
            asn,
            rr_server: None,
            rr_client: None,
        }
    }

    #[test]
    fn full_mesh_peers_with_all_others() {
        let a = node("a", "10.0.0.1", 64512);
        let nodes = vec![
            a.clone(),
            node("b", "10.0.0.2", 64512),
            node("c", "10.0.0.3", 64512),
        ];
        let peers = derive_ibgp_peers(&a, &nodes, true, true);
        assert_eq!(peers.len(), 2);
        assert!(peers.iter().all(|p| !p.is_external && !p.rr_client));
    }

    #[test]
    fn disabled_ibgp_yields_no_peers() {
        let a = node("a", "10.0.0.1", 64512);
        let nodes = vec![a.clone(), node("b", "10.0.0.2", 64512)];
        assert!(derive_ibgp_peers(&a, &nodes, true, false).is_empty());
    }

    #[test]
    fn per_as_peers_only_within_same_asn() {
        let a = node("a", "10.0.0.1", 100);
        let nodes = vec![
            a.clone(),
            node("b", "10.0.0.2", 100),
            node("c", "10.0.0.3", 200),
        ];
        let peers = derive_ibgp_peers(&a, &nodes, false, true);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].neighbor, "10.0.0.2".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn rr_server_peers_all_and_marks_clients() {
        let mut server = node("s", "10.0.0.1", 64512);
        server.rr_server = Some(1);
        let mut client = node("c", "10.0.0.2", 64512);
        client.rr_client = Some(1);
        let plain = node("p", "10.0.0.3", 64512);
        let nodes = vec![server.clone(), client.clone(), plain.clone()];

        let peers = derive_ibgp_peers(&server, &nodes, false, true);
        assert_eq!(peers.len(), 2);
        // The non-server neighbors are treated as RR clients.
        assert!(peers
            .iter()
            .all(|p| p.rr_client && p.rr_cluster_id == Some(1)));
    }

    #[test]
    fn rr_client_peers_only_with_servers() {
        let mut server = node("s", "10.0.0.1", 64512);
        server.rr_server = Some(1);
        let mut client = node("c", "10.0.0.2", 64512);
        client.rr_client = Some(1);
        let plain = node("p", "10.0.0.3", 64512);
        let nodes = vec![server.clone(), client.clone(), plain.clone()];

        let peers = derive_ibgp_peers(&client, &nodes, false, true);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].neighbor, "10.0.0.1".parse::<IpAddr>().unwrap());
    }

    fn peer(ip: &str, asn: u32) -> BgpPeer {
        BgpPeer {
            neighbor: ip.parse().unwrap(),
            peer_asn: asn,
            is_external: false,
            rr_client: false,
            rr_cluster_id: None,
        }
    }

    #[test]
    fn diff_adds_new_and_removes_stale() {
        let current = vec![peer("10.0.0.2", 64512), peer("10.0.0.3", 64512)];
        let desired = vec![peer("10.0.0.2", 64512), peer("10.0.0.4", 64512)];
        let (add, remove) = peer_diff(&current, &desired);
        assert_eq!(add, vec![peer("10.0.0.4", 64512)]);
        assert_eq!(remove, vec!["10.0.0.3".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn diff_readds_on_attribute_change() {
        let current = vec![peer("10.0.0.2", 64512)];
        let desired = vec![peer("10.0.0.2", 65000)]; // ASN changed
        let (add, remove) = peer_diff(&current, &desired);
        assert_eq!(add, vec![peer("10.0.0.2", 65000)]);
        assert!(remove.is_empty(), "same neighbor, not removed");
    }

    #[test]
    fn diff_noop_when_equal() {
        let p = vec![peer("10.0.0.2", 64512)];
        let (add, remove) = peer_diff(&p, &p);
        assert!(add.is_empty() && remove.is_empty());
    }
}
