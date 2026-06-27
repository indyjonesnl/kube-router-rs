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
    last: Instant,
    window: Duration,
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
                window: sync_period + GRACE,
            },
        );
    }

    /// Record a heartbeat for a component (ignored if not registered).
    pub fn heartbeat(&mut self, component: Component, now: Instant) {
        if let Some(c) = self.components.get_mut(&component) {
            c.last = now;
        }
    }

    /// `true` iff every registered component is within its window at `now`.
    pub fn is_healthy(&self, now: Instant) -> bool {
        self.components
            .values()
            .all(|c| now.saturating_duration_since(c.last) <= c.window)
    }

    /// HTTP status + body for the `/healthz` endpoint.
    pub fn healthz_response(&self, now: Instant) -> (u16, &'static str) {
        if self.is_healthy(now) {
            (200, "OK")
        } else {
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
    fn component_ids_match_upstream() {
        assert_eq!(Component::NetworkRoutes as u8, 0);
        assert_eq!(Component::RouteSync as u8, 6);
    }
}
