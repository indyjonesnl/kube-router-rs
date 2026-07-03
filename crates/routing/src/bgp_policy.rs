//! Node BGP policy config parsed from annotations, mirroring the
//! communities / path-prepend / custom-import-reject handling in
//! `upstream/pkg/controllers/routing/bgp_policies.go`.
//!
//! - `kube-router.io/node.bgp.communities` — communities added to advertised
//!   routes (export).
//! - `kube-router.io/path-prepend.as` + `.repeat-n` — AS-path prepend (export).
//! - `kube-router.io/node.bgp.customimportreject` — prefixes rejected on import.

use ipnet::IpNet;

/// Policy parse error.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("invalid BGP policy value: {0}")]
pub struct PolicyParseError(pub String);

/// Parse a single community: `asn:value` (each 0-65535) or a plain 32-bit value.
pub fn parse_community(s: &str) -> Result<u32, PolicyParseError> {
    let s = s.trim();
    if let Some((hi, lo)) = s.split_once(':') {
        let hi: u16 = hi
            .parse()
            .map_err(|_| PolicyParseError(format!("community high part: {hi}")))?;
        let lo: u16 = lo
            .parse()
            .map_err(|_| PolicyParseError(format!("community low part: {lo}")))?;
        Ok((u32::from(hi) << 16) | u32::from(lo))
    } else {
        s.parse::<u32>()
            .map_err(|_| PolicyParseError(format!("community: {s}")))
    }
}

/// Parse a comma-separated community list (empty entries ignored).
pub fn parse_communities(s: &str) -> Result<Vec<u32>, PolicyParseError> {
    s.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(parse_community)
        .collect()
}

/// Parse a comma-separated CIDR list (invalid/empty entries skipped).
pub fn parse_import_reject(s: &str) -> Vec<IpNet> {
    s.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .filter_map(|p| p.parse::<IpNet>().ok())
        .collect()
}

/// A node's parsed BGP export/import policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BgpPolicyConfig {
    /// COMMUNITIES to add to advertised routes.
    pub communities: Vec<u32>,
    /// AS-path prepend as `(asn, repeat)`, when configured.
    pub path_prepend: Option<(u32, u8)>,
    /// Prefixes to reject on import.
    pub import_reject: Vec<IpNet>,
}

impl BgpPolicyConfig {
    /// Build from the raw annotation values (any of which may be `None`).
    /// Prepend requires both the ASN and a non-zero repeat count.
    pub fn from_annotations(
        communities: Option<&str>,
        prepend_as: Option<&str>,
        prepend_repeat: Option<&str>,
        import_reject: Option<&str>,
    ) -> Result<Self, PolicyParseError> {
        let communities = communities
            .map(parse_communities)
            .transpose()?
            .unwrap_or_default();
        let import_reject = import_reject.map(parse_import_reject).unwrap_or_default();
        let path_prepend = match prepend_as {
            Some(asn) => {
                let asn: u32 = asn
                    .trim()
                    .parse()
                    .map_err(|_| PolicyParseError(format!("path-prepend.as: {asn}")))?;
                let repeat: u8 = prepend_repeat
                    .map(|r| r.trim().parse())
                    .transpose()
                    .map_err(|_| PolicyParseError("path-prepend.repeat-n".into()))?
                    .unwrap_or(1);
                (repeat > 0).then_some((asn, repeat))
            }
            None => None,
        };
        Ok(Self {
            communities,
            path_prepend,
            import_reject,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_community_formats() {
        assert_eq!(parse_community("65000:100").unwrap(), (65000 << 16) | 100);
        assert_eq!(parse_community("7").unwrap(), 7);
        assert!(parse_community("70000:1").is_err()); // high part > u16
        assert!(parse_community("no-neg:1").is_err());
    }

    #[test]
    fn parses_community_list_skipping_blanks() {
        assert_eq!(
            parse_communities("65000:1, 65000:2 ,").unwrap(),
            vec![(65000 << 16) | 1, (65000 << 16) | 2]
        );
    }

    #[test]
    fn import_reject_parses_valid_cidrs_only() {
        let r = parse_import_reject("10.0.0.0/8, garbage, fd00::/8");
        assert_eq!(r.len(), 2);
        assert!(r.contains(&"10.0.0.0/8".parse().unwrap()));
        assert!(r.contains(&"fd00::/8".parse().unwrap()));
    }

    #[test]
    fn from_annotations_assembles_config() {
        let c = BgpPolicyConfig::from_annotations(
            Some("65000:100"),
            Some("64512"),
            Some("3"),
            Some("192.0.2.0/24"),
        )
        .unwrap();
        assert_eq!(c.communities, vec![(65000 << 16) | 100]);
        assert_eq!(c.path_prepend, Some((64512, 3)));
        assert_eq!(c.import_reject, vec!["192.0.2.0/24".parse().unwrap()]);
    }

    #[test]
    fn prepend_defaults_repeat_to_one_and_none_when_absent() {
        let c = BgpPolicyConfig::from_annotations(None, Some("64512"), None, None).unwrap();
        assert_eq!(c.path_prepend, Some((64512, 1)));
        let empty = BgpPolicyConfig::from_annotations(None, None, None, None).unwrap();
        assert_eq!(empty, BgpPolicyConfig::default());
    }
}
