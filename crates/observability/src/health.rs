//! Controller heartbeat tracking and health evaluation.
//!
//! Mirrors `upstream/pkg/healthcheck`: each running controller emits a heartbeat
//! per sync loop; the agent is healthy iff every registered component reported
//! within its `sync_period + ttl + grace` window.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Grace added on top of a component's sync window (upstream ~1500ms).
pub const GRACE: Duration = Duration::from_millis(1500);

/// Controllers that report heartbeats. Discriminants match upstream component IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Component {
    /// NetworkRoutesController.
    NetworkRoutes = 0,
    /// LoadBalancerController.
    LoadBalancer = 1,
    /// NetworkPolicyController.
    NetworkPolicy = 2,
    /// NetworkServicesController.
    NetworkServices = 3,
    /// HairpinController.
    Hairpin = 4,
    /// MetricsController.
    Metrics = 5,
    /// RouteSyncController.
    RouteSync = 6,
}

struct ComponentHealth {
    /// Last heartbeat (seeded at registration).
    last: Instant,
    /// Registration time; the interval from here to the first heartbeat becomes
    /// this component's TTL.
    registered: Instant,
    /// Configured sync period for this component.
    sync_period: Duration,
    /// Observed interval from registration to the FIRST heartbeat, capturing the
    /// controller's real first-cycle duration under startup load. Added to the
    /// health window so a later cycle that runs a little long under churn does not
    /// trip the liveness probe. Set once, on the first heartbeat (upstream's
    /// `AliveTTL`). `None` until then.
    ttl: Option<Duration>,
}

impl ComponentHealth {
    /// Deadline window: `sync_period + observed_ttl + grace` (mirrors upstream
    /// `CheckHealth`). Without the TTL term a 5m-period controller only tolerates
    /// 1.5s of scheduling/sync jitter, which trips the probe under load.
    fn window(&self) -> Duration {
        self.sync_period + self.ttl.unwrap_or_default() + GRACE
    }
}

/// Tracks per-component heartbeats and computes overall health.
#[derive(Default)]
pub struct HealthState {
    components: HashMap<Component, ComponentHealth>,
}

impl HealthState {
    /// New, empty state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an enabled component with its sync period; seeds an initial heartbeat.
    pub fn register(&mut self, component: Component, sync_period: Duration, now: Instant) {
        self.components.insert(
            component,
            ComponentHealth {
                last: now,
                registered: now,
                sync_period,
                ttl: None,
            },
        );
    }

    /// Record a heartbeat for a component (ignored if not registered). The first
    /// heartbeat fixes the component's TTL to the elapsed startup interval.
    pub fn heartbeat(&mut self, component: Component, now: Instant) {
        if let Some(c) = self.components.get_mut(&component) {
            if c.ttl.is_none() {
                c.ttl = Some(now.saturating_duration_since(c.registered));
            }
            c.last = now;
        }
    }

    /// `true` iff every registered component is within its window at `now`.
    pub fn is_healthy(&self, now: Instant) -> bool {
        self.stale_components(now).is_empty()
    }

    /// Components whose last heartbeat is older than their window, with how late
    /// they are — the culprits behind a `500` from `/healthz`.
    fn stale_components(&self, now: Instant) -> Vec<(Component, Duration)> {
        self.components
            .iter()
            .filter_map(|(comp, c)| {
                let since = now.saturating_duration_since(c.last);
                (since > c.window()).then_some((*comp, since))
            })
            .collect()
    }

    /// HTTP status + body for the `/healthz` endpoint. Logs the stale component(s)
    /// on failure so a liveness `500` names its culprit instead of being opaque.
    pub fn healthz_response(&self, now: Instant) -> (u16, &'static str) {
        let stale = self.stale_components(now);
        if stale.is_empty() {
            (200, "OK")
        } else {
            tracing::warn!(?stale, "healthz: controller heartbeat(s) missed");
            (500, "Unhealthy")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_state_is_healthy() {
        assert!(HealthState::new().is_healthy(Instant::now()));
    }

    #[test]
    fn fresh_heartbeat_is_healthy() {
        let mut h = HealthState::new();
        let t0 = Instant::now();
        h.register(Component::NetworkRoutes, Duration::from_secs(5), t0);
        assert!(h.is_healthy(t0));
    }

    #[test]
    fn stale_component_is_unhealthy() {
        let mut h = HealthState::new();
        let t0 = Instant::now();
        h.register(Component::NetworkPolicy, Duration::from_secs(5), t0);
        // window = 5s + 1.5s grace; advance well past it.
        let later = t0 + Duration::from_secs(10);
        assert!(!h.is_healthy(later));
        assert_eq!(h.healthz_response(later), (500, "Unhealthy"));
    }

    #[test]
    fn heartbeat_refreshes_window() {
        let mut h = HealthState::new();
        let t0 = Instant::now();
        h.register(Component::NetworkServices, Duration::from_secs(5), t0);
        let t1 = t0 + Duration::from_secs(4);
        h.heartbeat(Component::NetworkServices, t1);
        // 4s after the refreshed heartbeat is still inside the 6.5s window.
        assert!(h.is_healthy(t1 + Duration::from_secs(4)));
    }

    #[test]
    fn one_stale_makes_all_unhealthy() {
        let mut h = HealthState::new();
        let t0 = Instant::now();
        h.register(Component::NetworkRoutes, Duration::from_secs(5), t0);
        h.register(Component::NetworkServices, Duration::from_secs(5), t0);
        h.heartbeat(Component::NetworkRoutes, t0 + Duration::from_secs(100));
        // NetworkServices never refreshed.
        assert!(!h.is_healthy(t0 + Duration::from_secs(100)));
    }

    #[test]
    fn first_cycle_ttl_widens_the_window() {
        // A 5m-period controller whose first sync took 20s must tolerate later
        // cycles running ~20s long: window = period + observed_ttl + grace.
        // Regression: without the TTL term the window was period + 1.5s, so a
        // slightly-long cycle under churn tripped the liveness probe (HTTP 500).
        let mut h = HealthState::new();
        let t0 = Instant::now();
        let period = Duration::from_secs(300);
        h.register(Component::NetworkPolicy, period, t0);
        // First heartbeat 20s after registration → TTL = 20s.
        let first = t0 + Duration::from_secs(20);
        h.heartbeat(Component::NetworkPolicy, first);
        // Next heartbeat lands 315s later (period + 15s jitter). Without the TTL
        // term (window 301.5s) this would be stale; with it (321.5s) it is healthy.
        let check = first + Duration::from_secs(315);
        assert!(h.is_healthy(check));
        // Beyond period + ttl + grace it is correctly unhealthy.
        let too_late = first + Duration::from_secs(300 + 20 + 2);
        assert!(!h.is_healthy(too_late));
    }

    #[test]
    fn component_ids_match_upstream() {
        assert_eq!(Component::NetworkRoutes as u8, 0);
        assert_eq!(Component::RouteSync as u8, 6);
    }
}
