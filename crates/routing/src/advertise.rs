//! Route advertisement to BGP peers (mirrors the advertise paths in
//! `upstream/pkg/controllers/routing/network_routes_controller.go` +
//! `ecmp_vip.go`).
//!
//! Tracks the set of prefixes currently advertised and, on each sync, advertises
//! newly-added prefixes (`AddPath`) and withdraws removed ones (`DeletePath` with
//! the withdrawal flag). Used for the node pod CIDR (`--advertise-pod-cidr`) and,
//! in US4, for service VIPs.

use std::collections::BTreeSet;
use std::net::IpAddr;

use ipnet::IpNet;
use kr_bgp::{BgpEngine, BgpError, PathBuilder};

/// Tracks advertised prefixes and reconciles them to the BGP engine.
#[derive(Debug, Default)]
pub struct Advertiser {
    advertised: BTreeSet<IpNet>,
}

impl Advertiser {
    /// New advertiser with nothing advertised yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Currently-advertised prefixes.
    pub fn advertised(&self) -> &BTreeSet<IpNet> {
        &self.advertised
    }

    /// Reconcile the advertised set to `desired` (advertised via `next_hop`).
    /// When `enabled` is false, all currently-advertised prefixes are withdrawn.
    /// Returns `(added, withdrawn)` counts.
    pub async fn sync<E: BgpEngine>(
        &mut self,
        engine: &E,
        desired: &[IpNet],
        next_hop: IpAddr,
        enabled: bool,
    ) -> Result<(usize, usize), BgpError> {
        let desired_set: BTreeSet<IpNet> = if enabled {
            desired.iter().copied().collect()
        } else {
            BTreeSet::new()
        };

        let to_add: Vec<IpNet> = desired_set.difference(&self.advertised).copied().collect();
        let to_withdraw: Vec<IpNet> = self.advertised.difference(&desired_set).copied().collect();

        for prefix in &to_add {
            engine
                .add_path(&PathBuilder::new(*prefix, next_hop).build())
                .await?;
        }
        for prefix in &to_withdraw {
            let path = PathBuilder::new(*prefix, next_hop).withdrawal(true).build();
            engine.delete_path(&path).await?;
        }

        self.advertised = desired_set;
        Ok((to_add.len(), to_withdraw.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_bgp::engine::mock::MockBgpEngine;

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }
    fn nh() -> IpAddr {
        "10.0.0.1".parse().unwrap()
    }

    #[tokio::test]
    async fn advertises_new_prefixes() {
        let e = MockBgpEngine::new();
        let mut adv = Advertiser::new();
        let (added, withdrawn) = adv
            .sync(&e, &[net("10.244.0.0/24")], nh(), true)
            .await
            .unwrap();
        assert_eq!((added, withdrawn), (1, 0));
        assert_eq!(e.added_paths.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn unchanged_set_is_noop() {
        let e = MockBgpEngine::new();
        let mut adv = Advertiser::new();
        adv.sync(&e, &[net("10.244.0.0/24")], nh(), true)
            .await
            .unwrap();
        let (added, withdrawn) = adv
            .sync(&e, &[net("10.244.0.0/24")], nh(), true)
            .await
            .unwrap();
        assert_eq!((added, withdrawn), (0, 0));
    }

    #[tokio::test]
    async fn changed_set_adds_and_withdraws() {
        let e = MockBgpEngine::new();
        let mut adv = Advertiser::new();
        adv.sync(&e, &[net("10.244.0.0/24")], nh(), true)
            .await
            .unwrap();
        let (added, withdrawn) = adv
            .sync(&e, &[net("10.244.1.0/24")], nh(), true)
            .await
            .unwrap();
        assert_eq!((added, withdrawn), (1, 1));
        assert_eq!(e.deleted_paths.lock().unwrap().len(), 1);
        assert!(e.deleted_paths.lock().unwrap()[0].withdrawal);
    }

    #[tokio::test]
    async fn disabled_withdraws_all() {
        let e = MockBgpEngine::new();
        let mut adv = Advertiser::new();
        adv.sync(&e, &[net("10.244.0.0/24")], nh(), true)
            .await
            .unwrap();
        let (added, withdrawn) = adv
            .sync(&e, &[net("10.244.0.0/24")], nh(), false)
            .await
            .unwrap();
        assert_eq!((added, withdrawn), (0, 1));
        assert!(adv.advertised().is_empty());
    }
}
