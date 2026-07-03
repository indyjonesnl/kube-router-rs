//! External BGP peer derivation, mirroring the global/positional peer config in
//! `upstream/pkg/controllers/routing` (global `--peer-router-*` flags and the
//! deprecated positional node annotations, both zipped by index).

use std::net::IpAddr;

use kr_bgp::PeerConfig;

/// External-peer configuration error.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PeerParseError {
    /// The IP and ASN lists have different lengths.
    #[error("peer IPs ({ips}) and ASNs ({asns}) count mismatch")]
    CountMismatch {
        /// Number of peer IPs.
        ips: usize,
        /// Number of peer ASNs.
        asns: usize,
    },
    /// Ports/passwords supplied but not one-per-peer.
    #[error("{field} count ({got}) must be 0 or match peer count ({want})")]
    OptionalCountMismatch {
        /// Which optional list.
        field: &'static str,
        /// Supplied count.
        got: usize,
        /// Peer count.
        want: usize,
    },
}

/// Build external `PeerConfig`s by zipping the peer IP/ASN lists (and optional
/// per-index ports/passwords), applying the global multihop TTL + local address.
/// Mirrors `newGlobalPeers` + the positional annotation handling.
pub fn zip_peers(
    ips: &[IpAddr],
    asns: &[u32],
    ports: &[u16],
    passwords: &[String],
    multihop_ttl: Option<u8>,
    local_address: Option<IpAddr>,
) -> Result<Vec<PeerConfig>, PeerParseError> {
    if ips.len() != asns.len() {
        return Err(PeerParseError::CountMismatch {
            ips: ips.len(),
            asns: asns.len(),
        });
    }
    if !ports.is_empty() && ports.len() != ips.len() {
        return Err(PeerParseError::OptionalCountMismatch {
            field: "ports",
            got: ports.len(),
            want: ips.len(),
        });
    }
    if !passwords.is_empty() && passwords.len() != ips.len() {
        return Err(PeerParseError::OptionalCountMismatch {
            field: "passwords",
            got: passwords.len(),
            want: ips.len(),
        });
    }

    Ok(ips
        .iter()
        .zip(asns)
        .enumerate()
        .map(|(i, (&neighbor, &peer_asn))| PeerConfig {
            neighbor,
            peer_asn,
            is_external: true,
            rr_client: false,
            rr_cluster_id: None,
            local_address,
            password: passwords.get(i).filter(|p| !p.is_empty()).cloned(),
            port: ports.get(i).copied().filter(|p| *p != 0),
            multihop_ttl,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn zips_ips_asns_ports_passwords_by_index() {
        let peers = zip_peers(
            &[ip("192.0.2.1"), ip("192.0.2.2")],
            &[65001, 65002],
            &[179, 1790],
            &["".into(), "c2VjcmV0".into()],
            Some(2),
            Some(ip("10.0.0.5")),
        )
        .unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].neighbor, ip("192.0.2.1"));
        assert_eq!(peers[0].peer_asn, 65001);
        assert!(peers[0].is_external);
        assert_eq!(peers[0].port, Some(179));
        assert_eq!(peers[0].password, None); // empty string → no password
        assert_eq!(peers[0].multihop_ttl, Some(2));
        assert_eq!(peers[0].local_address, Some(ip("10.0.0.5")));
        assert_eq!(peers[1].password.as_deref(), Some("c2VjcmV0"));
        assert_eq!(peers[1].port, Some(1790));
    }

    #[test]
    fn no_optional_lists_is_fine() {
        let peers = zip_peers(&[ip("192.0.2.1")], &[65001], &[], &[], None, None).unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].port, None);
        assert_eq!(peers[0].password, None);
        assert_eq!(peers[0].multihop_ttl, None);
    }

    #[test]
    fn ip_asn_count_mismatch_errors() {
        let err = zip_peers(&[ip("192.0.2.1")], &[65001, 65002], &[], &[], None, None).unwrap_err();
        assert_eq!(err, PeerParseError::CountMismatch { ips: 1, asns: 2 });
    }

    #[test]
    fn partial_optional_list_errors() {
        let err = zip_peers(
            &[ip("192.0.2.1"), ip("192.0.2.2")],
            &[65001, 65002],
            &[179],
            &[],
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            PeerParseError::OptionalCountMismatch { field: "ports", .. }
        ));
    }
}
