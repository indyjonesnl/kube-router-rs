//! Masquerade SNAT for IPVS, mirroring `ensureMasqueradeIptablesRule`.
//!
//! IPVS NAT requires reply traffic to return through the director, so outbound
//! IPVS-forwarded traffic is SNAT'd to the node's primary IP. With
//! `--masquerade-all` every IPVS flow is masqueraded; otherwise only flows
//! leaving the pod network (`! -s podCIDR ! -d podCIDR`) are.

use std::net::IpAddr;

use crate::hairpin::{NatError, NatOps};

/// nat POSTROUTING SNAT rule for IPVS-forwarded traffic. When `cidr` is set the
/// rule excludes intra-pod-network traffic (`! -s cidr ! -d cidr`).
pub fn masquerade_args(primary_ip: IpAddr, cidr: Option<&str>, random_fully: bool) -> Vec<String> {
    let mut a = vec![
        "-m".into(),
        "ipvs".into(),
        "--ipvs".into(),
        "--vdir".into(),
        "ORIGINAL".into(),
        "--vmethod".into(),
        "MASQ".into(),
    ];
    if let Some(cidr) = cidr {
        a.extend([
            "!".into(),
            "-s".into(),
            cidr.into(),
            "!".into(),
            "-d".into(),
            cidr.into(),
        ]);
    }
    a.extend([
        "-j".into(),
        "SNAT".into(),
        "--to-source".into(),
        primary_ip.to_string(),
    ]);
    if random_fully {
        a.push("--random-fully".into());
    }
    a
}

/// Reconcile the IPVS masquerade rules in nat POSTROUTING for one family.
///
/// The unconditional all-traffic rule is added when `masquerade_all`, else
/// removed (toggling the flag off cleans up). The per-podCIDR rules are always
/// applied so return traffic from pods on other nodes is masqueraded.
pub async fn sync_masquerade<N: NatOps + ?Sized>(
    ops: &N,
    primary_ip: IpAddr,
    pod_cidrs: &[String],
    masquerade_all: bool,
    random_fully: bool,
) -> Result<(), NatError> {
    let all_rule = masquerade_args(primary_ip, None, random_fully);
    if masquerade_all {
        ops.append_unique("POSTROUTING", &all_rule).await?;
    } else {
        ops.delete("POSTROUTING", &all_rule).await?;
    }
    for cidr in pod_cidrs {
        let rule = masquerade_args(primary_ip, Some(cidr), random_fully);
        ops.append_unique("POSTROUTING", &rule).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hairpin::mock::MockNat;

    #[test]
    fn args_unconditional_vs_cidr_scoped() {
        let ip: IpAddr = "192.168.1.10".parse().unwrap();
        let all = masquerade_args(ip, None, false);
        assert!(all.windows(4).any(|w| w
            == ["-j", "SNAT", "--to-source", "192.168.1.10"]
                .map(String::from)
                .as_slice()));
        assert!(!all.contains(&"!".to_string()));

        let scoped = masquerade_args(ip, Some("10.244.0.0/24"), true);
        // Excludes intra-pod-network traffic and requests --random-fully.
        assert!(scoped
            .windows(3)
            .any(|w| w == ["!", "-s", "10.244.0.0/24"].map(String::from).as_slice()));
        assert!(scoped.ends_with(&["--random-fully".to_string()]));
    }

    #[tokio::test]
    async fn masquerade_all_appends_unconditional_rule() {
        let ops = MockNat::new();
        sync_masquerade(
            &ops,
            "192.168.1.10".parse().unwrap(),
            &["10.244.0.0/24".to_string()],
            true,
            false,
        )
        .await
        .unwrap();
        // Unconditional + one per-CIDR rule appended; nothing deleted.
        assert_eq!(ops.rules_in("POSTROUTING").len(), 2);
        assert!(ops.deleted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn without_masquerade_all_deletes_unconditional_rule() {
        let ops = MockNat::new();
        sync_masquerade(
            &ops,
            "192.168.1.10".parse().unwrap(),
            &["10.244.0.0/24".to_string()],
            false,
            false,
        )
        .await
        .unwrap();
        // Unconditional rule deleted; only the per-CIDR rule appended.
        assert_eq!(ops.deleted.lock().unwrap().len(), 1);
        assert_eq!(ops.rules_in("POSTROUTING").len(), 1);
    }
}
