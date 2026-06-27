//! Network Policy Controller full-sync loop, mirroring the sync model of
//! `upstream/pkg/controllers/netpol/network_policy_controller.go`.
//!
//! Each sync: snapshot policies/pods/namespaces, build the per-family firewall
//! plan, atomically apply ipsets (`restore`) and our managed chains
//! (`iptables-restore`), ensure the builtin INPUT/FORWARD/OUTPUT jumps, and emit
//! a heartbeat.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kr_common::ipfamily::IpFamily;
use kr_observability::{Component, HealthState};

use crate::ipset::{build_restore_payload, IpsetOps};
use crate::iptables::{filter_restore_doc, IptablesOps};
use crate::naming::{ROUTER_FORWARD, ROUTER_INPUT, ROUTER_OUTPUT};
use crate::synth::build_plan;
use crate::{Namespace, NetworkPolicy, Pod};

/// Snapshot of the objects the firewall is built from.
#[derive(Debug, Default, Clone)]
pub struct PolicyWorld {
    /// NetworkPolicies.
    pub policies: Vec<NetworkPolicy>,
    /// Pods.
    pub pods: Vec<Pod>,
    /// Namespaces.
    pub namespaces: Vec<Namespace>,
}

/// Supplies the current policy world (from the informer stores).
pub trait PolicySource: Send + Sync {
    /// Current snapshot.
    fn snapshot(&self) -> PolicyWorld;
}

/// Errors during a firewall sync.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    /// ipset failure.
    #[error(transparent)]
    Ipset(#[from] crate::ipset::IpsetError),
    /// iptables failure.
    #[error(transparent)]
    Iptables(#[from] crate::iptables::IptablesError),
}

/// The Network Policy Controller.
pub struct FirewallController<I: IpsetOps, T: IptablesOps, S: PolicySource> {
    ipset: I,
    families: Vec<(IpFamily, T)>,
    source: S,
    node: String,
    /// Stable sync version → stable chain names (re-flushed each sync).
    sync_version: String,
    sync_period: Duration,
}

impl<I: IpsetOps, T: IptablesOps, S: PolicySource> FirewallController<I, T, S> {
    /// Construct.
    pub fn new(
        ipset: I,
        families: Vec<(IpFamily, T)>,
        source: S,
        node: String,
        sync_period: Duration,
    ) -> Self {
        Self {
            ipset,
            families,
            source,
            node,
            sync_version: "kr".to_string(),
            sync_period,
        }
    }

    /// Perform one full firewall sync across all families.
    pub async fn reconcile(&self) -> Result<(), SyncError> {
        let world = self.source.snapshot();
        for (family, ipt) in &self.families {
            let plan = build_plan(
                &world.policies,
                &world.pods,
                &world.namespaces,
                &self.node,
                *family,
                &self.sync_version,
            );
            for set in &plan.ipsets {
                let payload =
                    build_restore_payload(&set.name, set.set_type, set.family, &set.entries);
                self.ipset.restore(&payload).await?;
            }
            let doc = filter_restore_doc(&plan.chain_decls, &plan.rules);
            ipt.restore_filter(&doc).await?;
            ipt.ensure_jump("INPUT", ROUTER_INPUT).await?;
            ipt.ensure_jump("FORWARD", ROUTER_FORWARD).await?;
            ipt.ensure_jump("OUTPUT", ROUTER_OUTPUT).await?;
        }
        Ok(())
    }

    /// Run the full-sync loop until `stop`, emitting a heartbeat per tick.
    pub async fn run<F>(&self, health: Arc<Mutex<HealthState>>, stop: F)
    where
        F: Future<Output = ()>,
    {
        let mut ticker = tokio::time::interval(self.sync_period);
        tokio::pin!(stop);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if let Err(e) = self.reconcile().await {
                        tracing::warn!(error = %e, "network policy sync failed");
                    }
                    if let Ok(mut h) = health.lock() {
                        h.heartbeat(Component::NetworkPolicy, Instant::now());
                    }
                }
                _ = &mut stop => break,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipset::mock::MockIpset;
    use crate::iptables::mock::MockIptables;
    use crate::model::{Peer, PolicyTypes, Rule};
    use std::collections::BTreeMap;

    fn lbl(p: &[(&str, &str)]) -> BTreeMap<String, String> {
        p.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    struct StaticSource(PolicyWorld);
    impl PolicySource for StaticSource {
        fn snapshot(&self) -> PolicyWorld {
            self.0.clone()
        }
    }

    #[tokio::test]
    async fn reconcile_applies_ipsets_chains_and_jumps() {
        let world = PolicyWorld {
            policies: vec![NetworkPolicy {
                namespace: "default".into(),
                name: "web".into(),
                pod_selector: lbl(&[("app", "web")]),
                policy_types: PolicyTypes {
                    ingress: true,
                    egress: false,
                },
                ingress: vec![Rule {
                    peers: vec![Peer::Selector {
                        namespace_selector: None,
                        pod_selector: Some(lbl(&[("app", "client")])),
                    }],
                    ports: vec![],
                }],
                egress: vec![],
            }],
            pods: vec![
                Pod {
                    namespace: "default".into(),
                    name: "web".into(),
                    labels: lbl(&[("app", "web")]),
                    ips: vec!["10.244.0.5".parse().unwrap()],
                    node_name: "node-a".into(),
                    host_network: false,
                },
                Pod {
                    namespace: "default".into(),
                    name: "client".into(),
                    labels: lbl(&[("app", "client")]),
                    ips: vec!["10.244.0.6".parse().unwrap()],
                    node_name: "node-b".into(),
                    host_network: false,
                },
            ],
            namespaces: vec![],
        };

        let ctrl = FirewallController::new(
            MockIpset::new(),
            vec![(IpFamily::V4, MockIptables::new())],
            StaticSource(world),
            "node-a".to_string(),
            Duration::from_secs(300),
        );
        ctrl.reconcile().await.unwrap();

        // ipset populated with the client source IP.
        let restores = ctrl.ipset.restores.lock().unwrap();
        assert!(restores.iter().any(|p| p.contains("10.244.0.6")));

        // iptables doc has the pod-fw chain + reject + dispatch.
        let (_f, ipt) = &ctrl.families[0];
        let docs = ipt.restores.lock().unwrap();
        assert!(docs
            .iter()
            .any(|d| d.contains("KUBE-POD-FW-") && d.contains("-j REJECT")));
        assert!(docs
            .iter()
            .any(|d| d.contains("-A KUBE-ROUTER-FORWARD -d 10.244.0.5")));

        // builtin jumps ensured.
        let jumps = ipt.jumps.lock().unwrap();
        assert!(jumps.contains(&("FORWARD".to_string(), ROUTER_FORWARD.to_string())));
        assert!(jumps.contains(&("INPUT".to_string(), ROUTER_INPUT.to_string())));
    }
}
