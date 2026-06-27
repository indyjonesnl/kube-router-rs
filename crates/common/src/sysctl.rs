//! Minimal sysctl access via `/proc/sys`, used for the kernel toggles the Go
//! upstream sets (ip_forward, arp_announce/ignore, rp_filter).

use std::path::PathBuf;

use crate::error::{Error, Result};

/// Translate a dotted sysctl key (e.g. `net.ipv4.ip_forward`) to its
/// `/proc/sys` path (e.g. `/proc/sys/net/ipv4/ip_forward`).
pub fn key_to_path(key: &str) -> PathBuf {
    let mut p = PathBuf::from("/proc/sys");
    for seg in key.split('.') {
        p.push(seg);
    }
    p
}

/// Read a sysctl value (trimmed).
pub fn read(key: &str) -> Result<String> {
    let path = key_to_path(key);
    std::fs::read_to_string(&path)
        .map(|s| s.trim().to_string())
        .map_err(|source| Error::Sysctl {
            key: key.to_string(),
            source,
        })
}

/// Write a sysctl value.
pub fn write(key: &str, value: &str) -> Result<()> {
    let path = key_to_path(key);
    std::fs::write(&path, value).map_err(|source| Error::Sysctl {
        key: key.to_string(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_key_to_proc_path() {
        assert_eq!(
            key_to_path("net.ipv4.ip_forward"),
            PathBuf::from("/proc/sys/net/ipv4/ip_forward")
        );
        assert_eq!(
            key_to_path("net.ipv4.conf.all.rp_filter"),
            PathBuf::from("/proc/sys/net/ipv4/conf/all/rp_filter")
        );
    }

    #[test]
    fn read_missing_key_errors() {
        let err = read("net.does.not.exist.kr_test").unwrap_err();
        assert!(matches!(err, Error::Sysctl { .. }));
    }
}
