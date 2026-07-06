//! Local node address enumeration for `--nodeport-bindon-all-ip`, mirroring
//! `getAllLocalIPs` (all interface addresses except dummy/kube/docker links).

use std::net::IpAddr;

/// Interface name substrings whose addresses are excluded (virtual/overlay).
const EXCLUDED: &[&str] = &["dummy", "kube", "docker"];

/// Parse `ip -o addr show` output into `(interface, address)` pairs, skipping
/// excluded interfaces. Line shape: `<idx>: <iface>  inet <addr>/<plen> ...`.
pub fn parse_ip_addr_output(out: &str) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    for line in out.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 {
            continue;
        }
        let iface = f[1];
        if EXCLUDED.iter().any(|e| iface.contains(e)) {
            continue;
        }
        if f[2] != "inet" && f[2] != "inet6" {
            continue;
        }
        if let Some((addr, _)) = f[3].split_once('/') {
            if let Ok(ip) = addr.parse::<IpAddr>() {
                if !ip.is_loopback() && !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
        }
    }
    ips
}

/// All non-loopback local addresses, excluding dummy/kube/docker interfaces
/// (shells `ip -o addr show`). Returns an empty list on failure.
pub async fn all_local_ips() -> Vec<IpAddr> {
    let out = tokio::process::Command::new("ip")
        .args(["-o", "addr", "show"])
        .output()
        .await;
    match out {
        Ok(o) if o.status.success() => parse_ip_addr_output(&String::from_utf8_lossy(&o.stdout)),
        _ => Vec::new(),
    }
}

/// Find the interface name that owns `ip` in `ip -o addr show` output. Unlike
/// [`parse_ip_addr_output`] this does not exclude virtual interfaces, since the
/// caller is resolving a known node IP to its real link (e.g. for rp_filter).
pub fn parse_iface_for_ip(out: &str, ip: IpAddr) -> Option<String> {
    for line in out.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 || (f[2] != "inet" && f[2] != "inet6") {
            continue;
        }
        if let Some((addr, _)) = f[3].split_once('/') {
            if addr.parse::<IpAddr>() == Ok(ip) {
                return Some(f[1].to_string());
            }
        }
    }
    None
}

/// Resolve the interface name owning `ip` (shells `ip -o addr show`).
pub async fn iface_for_ip(ip: IpAddr) -> Option<String> {
    let out = tokio::process::Command::new("ip")
        .args(["-o", "addr", "show"])
        .output()
        .await
        .ok()?;
    out.status
        .success()
        .then(|| parse_iface_for_ip(&String::from_utf8_lossy(&out.stdout), ip))
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_excludes_virtual_interfaces_and_loopback() {
        let out = "\
1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever
2: eth0    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0\\       valid_lft forever
2: eth0    inet6 fd00::10/64 scope global \\       valid_lft forever
3: kube-dummy-if    inet 10.96.0.1/32 scope global kube-dummy-if\\       valid_lft forever
4: docker0    inet 172.17.0.1/16 scope global docker0\\       valid_lft forever";
        let ips = parse_ip_addr_output(out);
        assert_eq!(ips.len(), 2);
        assert!(ips.contains(&"192.168.1.10".parse().unwrap()));
        assert!(ips.contains(&"fd00::10".parse().unwrap()));
        // loopback, kube-dummy-if, docker0 all excluded.
        assert!(!ips.iter().any(|ip| ip.to_string() == "10.96.0.1"));
    }

    #[test]
    fn resolves_iface_for_ip_without_excluding_virtual() {
        let out = "\
2: eth0    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0\\       valid_lft forever
3: kube-dummy-if    inet 10.96.0.1/32 scope global kube-dummy-if\\       valid_lft forever";
        assert_eq!(
            parse_iface_for_ip(out, "192.168.1.10".parse().unwrap()).as_deref(),
            Some("eth0")
        );
        // Not excluded here (unlike all_local_ips): a known VIP resolves to its link.
        assert_eq!(
            parse_iface_for_ip(out, "10.96.0.1".parse().unwrap()).as_deref(),
            Some("kube-dummy-if")
        );
        assert_eq!(parse_iface_for_ip(out, "10.0.0.9".parse().unwrap()), None);
    }
}
