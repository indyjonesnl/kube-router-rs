//! Deterministic chain/ipset name derivation.
//!
//! Mirrors the Go upstream scheme (`pkg/controllers/netpol/policy.go`,
//! `pod.go`): base32-encode the SHA-256 of the composed key and take the first
//! 16 characters. The same inputs MUST yield the same name as upstream so that
//! on-node firewall state is identical (parity requirement).

use data_encoding::BASE32;
use sha2::{Digest, Sha256};

use crate::ipfamily::IpFamily;

/// Number of leading base32 characters used in a derived name.
pub const HASH_LEN: usize = 16;

/// Upstream chain/set name prefixes.
pub const POD_FW_PREFIX: &str = "KUBE-POD-FW-";
/// Per-policy chain prefix.
pub const NWPLCY_PREFIX: &str = "KUBE-NWPLCY-";
/// Source ipset prefix.
pub const SRC_PREFIX: &str = "KUBE-SRC-";
/// Destination ipset prefix.
pub const DST_PREFIX: &str = "KUBE-DST-";

/// Base32(SHA-256(input))[..16] — the core hashing primitive.
pub fn hash16(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    let encoded = BASE32.encode(&digest);
    encoded[..HASH_LEN].to_string()
}

fn family_tag(family: IpFamily) -> &'static str {
    // Upstream uses the v1.IPFamily string ("IPv4"/"IPv6").
    match family {
        IpFamily::V4 => "IPv4",
        IpFamily::V6 => "IPv6",
    }
}

/// Per-pod firewall chain name: `KUBE-POD-FW-<hash16(namespace+pod+syncver)>`.
pub fn pod_firewall_chain(namespace: &str, pod: &str, sync_version: &str) -> String {
    format!(
        "{POD_FW_PREFIX}{}",
        hash16(&format!("{namespace}{pod}{sync_version}"))
    )
}

/// Per-policy chain name: `KUBE-NWPLCY-<hash16(namespace+policy+syncver+family)>`.
pub fn network_policy_chain(
    namespace: &str,
    policy: &str,
    sync_version: &str,
    family: IpFamily,
) -> String {
    format!(
        "{NWPLCY_PREFIX}{}",
        hash16(&format!(
            "{namespace}{policy}{sync_version}{}",
            family_tag(family)
        ))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_16_chars_and_deterministic() {
        let a = hash16("default".to_string().as_str());
        assert_eq!(a.len(), HASH_LEN);
        assert_eq!(a, hash16("default"));
    }

    #[test]
    fn hash_is_base32_alphabet() {
        let h = hash16("some-input-value");
        assert!(h
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));
    }

    #[test]
    fn different_inputs_differ() {
        assert_ne!(hash16("a"), hash16("b"));
    }

    #[test]
    fn pod_chain_has_prefix_and_length() {
        let c = pod_firewall_chain("default", "nginx-abc", "1700000000000000000");
        assert!(c.starts_with(POD_FW_PREFIX));
        assert_eq!(c.len(), POD_FW_PREFIX.len() + HASH_LEN);
    }

    #[test]
    fn policy_chain_family_changes_name() {
        let v4 = network_policy_chain("default", "deny", "1", IpFamily::V4);
        let v6 = network_policy_chain("default", "deny", "1", IpFamily::V6);
        assert_ne!(v4, v6);
        assert!(v4.starts_with(NWPLCY_PREFIX));
    }
}
