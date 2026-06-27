//! Node BGP annotation parsing, mirroring `upstream/pkg/controllers/routing/`
//! (`network_routes_controller.go`, `bgp_peers.go`) and `contracts/annotations.md`.
//!
//! Parsing is lenient where upstream is lenient: malformed values are skipped
//! (logged at the call site) rather than aborting. The consolidated
//! `kube-router.io/peers` YAML takes precedence over the deprecated positional
//! `kube-router.io/peer.*` annotations.

use std::collections::BTreeMap;
use std::net::IpAddr;

use ipnet::IpNet;
use kr_common::ipfamily::{parse_cidr, parse_ip};
use serde::Deserialize;

/// Annotation keys.
pub mod keys {
    pub const ASN: &str = "kube-router.io/node.asn";
    pub const COMMUNITIES: &str = "kube-router.io/node.bgp.communities";
    pub const CUSTOM_IMPORT_REJECT: &str = "kube-router.io/node.bgp.customimportreject";
    pub const PATH_PREPEND_AS: &str = "kube-router.io/path-prepend.as";
    pub const PATH_PREPEND_REPEAT: &str = "kube-router.io/path-prepend.repeat-n";
    pub const RR_SERVER: &str = "kube-router.io/rr.server";
    pub const RR_CLIENT: &str = "kube-router.io/rr.client";
    pub const PEERS: &str = "kube-router.io/peers";
    pub const BGP_LOCAL_ADDRESSES: &str = "kube-router.io/bgp-local-addresses";
    // Deprecated positional forms.
    pub const PEER_IPS: &str = "kube-router.io/peer.ips";
    pub const PEER_ASNS: &str = "kube-router.io/peer.asns";
    pub const PEER_LOCALIPS: &str = "kube-router.io/peer.localips";
    pub const PEER_PASSWORDS: &str = "kube-router.io/peer.passwords";
    pub const PEER_PORTS: &str = "kube-router.io/peer.ports";
}

const MAX_PATH_PREPEND_REPEAT: u8 = 8;

/// An external BGP peer parsed from annotations.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ExternalPeer {
    /// Remote peer IP.
    #[serde(rename = "remoteip")]
    pub remote_ip: IpAddr,
    /// Remote peer ASN.
    #[serde(rename = "remoteasn")]
    pub remote_asn: u32,
    /// Optional local IP for the session.
    #[serde(rename = "localip", default)]
    pub local_ip: Option<IpAddr>,
    /// Optional base64 MD5 password.
    #[serde(default)]
    pub password: Option<String>,
    /// Optional remote port.
    #[serde(default)]
    pub port: Option<u16>,
}

/// Parsed node BGP configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeBgpConfig {
    /// Node ASN (`node.asn`).
    pub asn: Option<u32>,
    /// Validated BGP community tokens.
    pub communities: Vec<String>,
    /// Custom import-reject prefixes.
    pub custom_import_reject: Vec<IpNet>,
    /// `(asn, repeat)` AS-path prepend, only when both are present and valid.
    pub path_prepend: Option<(u32, u8)>,
    /// RR server cluster id (raw — may be decimal or an IP form).
    pub rr_server: Option<String>,
    /// RR client cluster id (raw).
    pub rr_client: Option<String>,
    /// BGP listen addresses.
    pub bgp_local_addresses: Vec<IpAddr>,
    /// External peers (from `peers` YAML or deprecated positional forms).
    pub external_peers: Vec<ExternalPeer>,
}

/// Well-known community names accepted by GoBGP.
const WELL_KNOWN_COMMUNITIES: &[&str] = &[
    "no-export",
    "no-advertise",
    "no-peer",
    "internet",
    "blackhole",
    "graceful-shutdown",
];

/// Validate a single BGP community token: a 32-bit integer, `<u16>:<u16>`, or a
/// well-known name.
pub fn validate_community(token: &str) -> bool {
    let t = token.trim();
    if WELL_KNOWN_COMMUNITIES.contains(&t) {
        return true;
    }
    if t.parse::<u32>().is_ok() {
        return true;
    }
    if let Some((a, b)) = t.split_once(':') {
        return a.parse::<u16>().is_ok() && b.parse::<u16>().is_ok();
    }
    false
}

fn split_list(s: &str) -> Vec<String> {
    s.split([',', ' '])
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(str::to_string)
        .collect()
}

/// Parse all BGP-relevant node annotations.
pub fn parse_node_bgp(annotations: &BTreeMap<String, String>) -> NodeBgpConfig {
    let mut cfg = NodeBgpConfig::default();

    if let Some(v) = annotations.get(keys::ASN) {
        cfg.asn = v.trim().parse::<u32>().ok();
    }
    if let Some(v) = annotations.get(keys::COMMUNITIES) {
        cfg.communities = split_list(v)
            .into_iter()
            .filter(|c| validate_community(c))
            .collect();
    }
    if let Some(v) = annotations.get(keys::CUSTOM_IMPORT_REJECT) {
        cfg.custom_import_reject = split_list(v)
            .iter()
            .filter_map(|c| parse_cidr(c).ok())
            .collect();
    }
    // Path prepend requires both fields.
    if let (Some(asn), Some(rep)) = (
        annotations.get(keys::PATH_PREPEND_AS),
        annotations.get(keys::PATH_PREPEND_REPEAT),
    ) {
        if let (Ok(asn), Ok(rep)) = (asn.trim().parse::<u32>(), rep.trim().parse::<u8>()) {
            if rep <= MAX_PATH_PREPEND_REPEAT {
                cfg.path_prepend = Some((asn, rep));
            }
        }
    }
    cfg.rr_server = annotations
        .get(keys::RR_SERVER)
        .map(|s| s.trim().to_string());
    cfg.rr_client = annotations
        .get(keys::RR_CLIENT)
        .map(|s| s.trim().to_string());
    if let Some(v) = annotations.get(keys::BGP_LOCAL_ADDRESSES) {
        cfg.bgp_local_addresses = split_list(v)
            .iter()
            .filter_map(|a| parse_ip(a).ok())
            .collect();
    }

    cfg.external_peers = parse_external_peers(annotations);
    cfg
}

/// Parse external peers, preferring the `peers` YAML over deprecated forms.
pub fn parse_external_peers(annotations: &BTreeMap<String, String>) -> Vec<ExternalPeer> {
    if let Some(yaml) = annotations.get(keys::PEERS) {
        if let Ok(peers) = serde_yaml_ng::from_str::<Vec<ExternalPeer>>(yaml) {
            return peers;
        }
    }
    parse_deprecated_peers(annotations)
}

fn parse_deprecated_peers(annotations: &BTreeMap<String, String>) -> Vec<ExternalPeer> {
    let (Some(ips), Some(asns)) = (
        annotations.get(keys::PEER_IPS),
        annotations.get(keys::PEER_ASNS),
    ) else {
        return Vec::new();
    };
    let ips = split_list(ips);
    let asns = split_list(asns);
    // Positional arrays must be 1:1.
    if ips.is_empty() || ips.len() != asns.len() {
        return Vec::new();
    }
    let local_ips = annotations
        .get(keys::PEER_LOCALIPS)
        .map(|s| split_list(s))
        .unwrap_or_default();
    let passwords = annotations
        .get(keys::PEER_PASSWORDS)
        .map(|s| split_list(s))
        .unwrap_or_default();
    let ports = annotations
        .get(keys::PEER_PORTS)
        .map(|s| split_list(s))
        .unwrap_or_default();

    let mut peers = Vec::new();
    for (i, (ip, asn)) in ips.iter().zip(asns.iter()).enumerate() {
        let (Ok(remote_ip), Ok(remote_asn)) = (parse_ip(ip), asn.parse::<u32>()) else {
            continue;
        };
        peers.push(ExternalPeer {
            remote_ip,
            remote_asn,
            local_ip: local_ips.get(i).and_then(|s| parse_ip(s).ok()),
            password: passwords.get(i).cloned(),
            port: ports.get(i).and_then(|s| s.parse::<u16>().ok()),
        });
    }
    peers
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ann(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn parses_asn_rr_and_local_addresses() {
        let a = ann(&[
            (keys::ASN, "64512"),
            (keys::RR_SERVER, "1"),
            (keys::BGP_LOCAL_ADDRESSES, "10.0.0.1, fd00::1"),
        ]);
        let c = parse_node_bgp(&a);
        assert_eq!(c.asn, Some(64512));
        assert_eq!(c.rr_server.as_deref(), Some("1"));
        assert_eq!(c.bgp_local_addresses.len(), 2);
    }

    #[test]
    fn community_validation() {
        assert!(validate_community("65001:100"));
        assert!(validate_community("4294967295"));
        assert!(validate_community("no-export"));
        assert!(!validate_community("not-a-community"));
        assert!(!validate_community("70000:1")); // first part > u16
    }

    #[test]
    fn keeps_only_valid_communities() {
        let a = ann(&[(keys::COMMUNITIES, "65001:100,bogus,no-export")]);
        let c = parse_node_bgp(&a);
        assert_eq!(c.communities, vec!["65001:100", "no-export"]);
    }

    #[test]
    fn path_prepend_requires_both_fields() {
        let only_as = ann(&[(keys::PATH_PREPEND_AS, "65001")]);
        assert_eq!(parse_node_bgp(&only_as).path_prepend, None);
        let both = ann(&[
            (keys::PATH_PREPEND_AS, "65001"),
            (keys::PATH_PREPEND_REPEAT, "3"),
        ]);
        assert_eq!(parse_node_bgp(&both).path_prepend, Some((65001, 3)));
        let too_many = ann(&[
            (keys::PATH_PREPEND_AS, "65001"),
            (keys::PATH_PREPEND_REPEAT, "9"),
        ]);
        assert_eq!(parse_node_bgp(&too_many).path_prepend, None);
    }

    #[test]
    fn custom_import_reject_parses_cidrs() {
        let a = ann(&[(keys::CUSTOM_IMPORT_REJECT, "10.0.0.0/8, garbage, fd00::/8")]);
        assert_eq!(parse_node_bgp(&a).custom_import_reject.len(), 2);
    }

    #[test]
    fn peers_yaml_is_preferred() {
        let yaml = "- remoteip: 192.0.2.1\n  remoteasn: 65100\n  port: 1790\n";
        let a = ann(&[
            (keys::PEERS, yaml),
            (keys::PEER_IPS, "10.0.0.9"),
            (keys::PEER_ASNS, "1"),
        ]);
        let peers = parse_external_peers(&a);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].remote_asn, 65100);
        assert_eq!(peers[0].port, Some(1790));
    }

    #[test]
    fn deprecated_positional_peers_zip_by_index() {
        let a = ann(&[
            (keys::PEER_IPS, "192.0.2.1,192.0.2.2"),
            (keys::PEER_ASNS, "65100,65101"),
            (keys::PEER_PORTS, "179,1790"),
        ]);
        let peers = parse_external_peers(&a);
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[1].remote_asn, 65101);
        assert_eq!(peers[1].port, Some(1790));
    }

    #[test]
    fn mismatched_positional_lengths_rejected() {
        let a = ann(&[
            (keys::PEER_IPS, "192.0.2.1,192.0.2.2"),
            (keys::PEER_ASNS, "65100"),
        ]);
        assert!(parse_external_peers(&a).is_empty());
    }
}
