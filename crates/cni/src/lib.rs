//! CNI configuration management.
//!
//! Mirrors `upstream/pkg/utils/cni.go`: kube-router does not vendor a CNI
//! library — it edits `/etc/cni/net.d/10-kuberouter.conflist`, locating the
//! `bridge` plugin and seeding its `host-local` IPAM with the node's pod CIDR
//! ranges, while **preserving any operator-set fields** it does not understand
//! (partial JSON model). We reproduce that with serde `flatten` into a raw map.

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// CNI conf management errors.
#[derive(Debug, thiserror::Error)]
pub enum CniError {
    /// The config JSON could not be parsed.
    #[error("invalid CNI config: {0}")]
    Parse(String),
    /// No `bridge`-type plugin was found in the conflist.
    #[error("no bridge plugin found in CNI conflist")]
    NoBridgePlugin,
}

/// A single CNI range entry (`{"subnet": "..."}`), preserving extra fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Range {
    /// The subnet CIDR.
    pub subnet: String,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

/// `host-local` IPAM config, preserving extra fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipam {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub ipam_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ranges: Option<Vec<Vec<Range>>>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

/// A CNI plugin entry, preserving extra fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plugin {
    #[serde(rename = "type")]
    pub plugin_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipam: Option<Ipam>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

/// A `.conflist`, preserving top-level extra fields and plugin order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfList {
    pub plugins: Vec<Plugin>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl ConfList {
    /// Parse a conflist from JSON.
    pub fn parse(json: &str) -> Result<Self, CniError> {
        serde_json::from_str(json).map_err(|e| CniError::Parse(e.to_string()))
    }

    /// Serialize back to pretty JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("conflist serializes")
    }

    /// Seed the bridge plugin's `host-local` IPAM with one range-set per pod CIDR.
    /// Existing IPAM `type` is preserved (defaulting to `host-local` if unset).
    pub fn seed_pod_cidrs(&mut self, pod_cidrs: &[IpNet]) -> Result<(), CniError> {
        let bridge = self
            .plugins
            .iter_mut()
            .find(|p| p.plugin_type == "bridge")
            .ok_or(CniError::NoBridgePlugin)?;

        let ipam = bridge.ipam.get_or_insert_with(|| Ipam {
            ipam_type: Some("host-local".to_string()),
            ranges: None,
            extra: Map::new(),
        });
        if ipam.ipam_type.is_none() {
            ipam.ipam_type = Some("host-local".to_string());
        }
        ipam.ranges = Some(
            pod_cidrs
                .iter()
                .map(|c| {
                    vec![Range {
                        subnet: c.to_string(),
                        extra: Map::new(),
                    }]
                })
                .collect(),
        );
        Ok(())
    }
}

/// Convenience: parse, seed pod CIDRs, and re-serialize in one step.
pub fn seed_conflist(json: &str, pod_cidrs: &[IpNet]) -> Result<String, CniError> {
    let mut cl = ConfList::parse(json)?;
    cl.seed_pod_cidrs(pod_cidrs)?;
    Ok(cl.to_json())
}

/// Default on-host CNI config path kube-router-rs writes.
pub const DEFAULT_CONF_PATH: &str = "/etc/cni/net.d/10-kuberouter.conflist";
/// Default on-host CNI plugin directory.
pub const DEFAULT_BIN_DIR: &str = "/opt/cni/bin";
/// CNI plugins kube-router-rs relies on.
pub const REQUIRED_PLUGINS: &[&str] = &["bridge", "host-local", "loopback"];

/// Build the kube-router-rs CNI conflist seeded with the node's pod CIDR(s):
/// a `bridge` (`kube-bridge`, default gateway, hairpin) over `host-local` IPAM,
/// plus `loopback`. One IPAM range-set per pod CIDR (dual-stack).
pub fn kuberouter_conflist(pod_cidrs: &[IpNet]) -> String {
    let ranges: Vec<Value> = pod_cidrs
        .iter()
        .map(|c| serde_json::json!([{ "subnet": c.to_string() }]))
        .collect();
    // No explicit IPAM `routes`: `isDefaultGateway: true` already installs the
    // pod's default route via the bridge IP. Adding 0.0.0.0/0 here too makes the
    // bridge plugin fail with "file exists".
    let doc = serde_json::json!({
        "cniVersion": "1.0.0",
        "name": "kube-router-rs",
        "plugins": [
            {
                "type": "bridge",
                "bridge": "kube-bridge",
                "isDefaultGateway": true,
                "hairpinMode": true,
                "ipam": { "type": "host-local", "ranges": ranges }
            },
            { "type": "loopback" }
        ]
    });
    serde_json::to_string_pretty(&doc).expect("conflist serializes")
}

/// Write the kube-router-rs conflist to `path` (creating parent dirs).
pub fn write_conflist(path: &std::path::Path, pod_cidrs: &[IpNet]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, kuberouter_conflist(pod_cidrs))
}

/// Copy each plugin in `names` from `src_dir` to `dst_dir` if not already present
/// (executable). Returns the names actually installed. Mirrors upstream's
/// init-container behavior of seeding `/opt/cni/bin`.
pub fn install_plugins(
    src_dir: &std::path::Path,
    dst_dir: &std::path::Path,
    names: &[&str],
) -> std::io::Result<Vec<String>> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dst_dir)?;
    let mut installed = Vec::new();
    for name in names {
        let dst = dst_dir.join(name);
        if dst.exists() {
            continue;
        }
        let src = src_dir.join(name);
        if !src.exists() {
            continue;
        }
        std::fs::copy(&src, &dst)?;
        std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o755))?;
        installed.push(name.to_string());
    }
    Ok(installed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
        "cniVersion": "0.3.0",
        "name": "mynet",
        "plugins": [
            {
                "type": "bridge",
                "bridge": "kube-bridge",
                "isDefaultGateway": true,
                "ipam": { "type": "host-local" }
            },
            { "type": "portmap", "capabilities": { "portMappings": true } }
        ]
    }"#;

    fn cidr(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    #[test]
    fn seeds_bridge_ipam_with_pod_cidr() {
        let out = seed_conflist(SAMPLE, &[cidr("10.244.0.0/24")]).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let ranges = &v["plugins"][0]["ipam"]["ranges"];
        assert_eq!(ranges[0][0]["subnet"], "10.244.0.0/24");
    }

    #[test]
    fn dual_stack_produces_two_range_sets() {
        let out = seed_conflist(SAMPLE, &[cidr("10.244.0.0/24"), cidr("fd00:244::/64")]).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let ranges = v["plugins"][0]["ipam"]["ranges"].as_array().unwrap();
        assert_eq!(ranges.len(), 2);
    }

    #[test]
    fn preserves_unknown_fields() {
        let out = seed_conflist(SAMPLE, &[cidr("10.244.0.0/24")]).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        // Top-level + plugin-level operator fields survive the round-trip.
        assert_eq!(v["cniVersion"], "0.3.0");
        assert_eq!(v["name"], "mynet");
        assert_eq!(v["plugins"][0]["bridge"], "kube-bridge");
        assert_eq!(v["plugins"][0]["isDefaultGateway"], true);
        assert_eq!(v["plugins"][1]["type"], "portmap");
        assert_eq!(v["plugins"][1]["capabilities"]["portMappings"], true);
    }

    #[test]
    fn preserves_existing_ipam_type() {
        let out = seed_conflist(SAMPLE, &[cidr("10.244.0.0/24")]).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["plugins"][0]["ipam"]["type"], "host-local");
    }

    #[test]
    fn missing_bridge_is_an_error() {
        let json = r#"{"cniVersion":"0.3.0","name":"x","plugins":[{"type":"loopback"}]}"#;
        assert!(matches!(
            seed_conflist(json, &[cidr("10.244.0.0/24")]),
            Err(CniError::NoBridgePlugin)
        ));
    }

    #[test]
    fn kuberouter_conflist_has_bridge_and_seeded_ipam() {
        let out = kuberouter_conflist(&[cidr("10.244.1.0/24")]);
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["plugins"][0]["bridge"], "kube-bridge");
        assert_eq!(v["plugins"][0]["isDefaultGateway"], true);
        assert_eq!(
            v["plugins"][0]["ipam"]["ranges"][0][0]["subnet"],
            "10.244.1.0/24"
        );
        assert_eq!(v["plugins"][1]["type"], "loopback");
    }

    #[test]
    fn dual_stack_conflist_has_two_ranges() {
        let out = kuberouter_conflist(&[cidr("10.244.1.0/24"), cidr("fd00:244:1::/64")]);
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            v["plugins"][0]["ipam"]["ranges"].as_array().unwrap().len(),
            2
        );
        // No explicit IPAM routes (isDefaultGateway provides the default route).
        assert!(v["plugins"][0]["ipam"]["routes"].is_null());
    }

    #[test]
    fn install_plugins_copies_missing_only() {
        let base = std::env::temp_dir().join(format!("krcni-{}", std::process::id()));
        let src = base.join("src");
        let dst = base.join("dst");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("bridge"), b"#!/bin/true").unwrap();
        std::fs::write(src.join("loopback"), b"#!/bin/true").unwrap();

        let installed = install_plugins(&src, &dst, &["bridge", "loopback", "host-local"]).unwrap();
        // host-local not in src → skipped; bridge+loopback copied.
        assert_eq!(installed.len(), 2);
        assert!(dst.join("bridge").exists());

        // Second run: already present → nothing installed.
        let again = install_plugins(&src, &dst, &["bridge", "loopback"]).unwrap();
        assert!(again.is_empty());

        std::fs::remove_dir_all(&base).ok();
    }
}
