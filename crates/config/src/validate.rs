//! Configuration validation, mirroring the constraints the Go upstream enforces.

use kr_common::error::{Error, Result};
use kr_common::ipfamily::{parse_cidr, EnabledFamilies};

use crate::KubeRouterConfig;

const MAX_CLUSTER_IP_RANGES: usize = 2;

impl KubeRouterConfig {
    /// Families enabled by `--enable-ipv4` / `--enable-ipv6`.
    pub fn enabled_families(&self) -> EnabledFamilies {
        EnabledFamilies::new(self.enable_ipv4, self.enable_ipv6)
    }

    /// Validate cross-field constraints. Returns the first violation found.
    pub fn validate(&self) -> Result<()> {
        let fams = self.enabled_families();
        if !fams.any() {
            return Err(Error::Config(
                "at least one of --enable-ipv4 or --enable-ipv6 must be true".into(),
            ));
        }

        // CIDR lists must parse.
        for (flag, list) in [
            ("--service-cluster-ip-range", &self.service_cluster_ip_range),
            (
                "--service-external-ip-range",
                &self.service_external_ip_range,
            ),
            ("--loadbalancer-ip-range", &self.loadbalancer_ip_range),
            ("--excluded-cidrs", &self.excluded_cidrs),
        ] {
            for c in list {
                parse_cidr(c).map_err(|e| Error::Config(format!("{flag}: {e}")))?;
            }
        }

        // At most two cluster-ip ranges (one per family).
        if self.service_cluster_ip_range.len() > MAX_CLUSTER_IP_RANGES {
            return Err(Error::Config(format!(
                "--service-cluster-ip-range accepts at most {MAX_CLUSTER_IP_RANGES} entries"
            )));
        }

        // IPv6-only requires an explicit or generated router-id for BGP.
        if self.run_router && fams.is_v6_only() && self.router_id.is_empty() {
            return Err(Error::Config(
                "--router-id is required (or \"generate\") for an IPv6-only cluster".into(),
            ));
        }

        // overlay-encap must be a known value.
        if !matches!(self.overlay_encap.as_str(), "ipip" | "fou") {
            return Err(Error::Config(format!(
                "--overlay-encap must be \"ipip\" or \"fou\", got {:?}",
                self.overlay_encap
            )));
        }

        // overlay-type must be a known value.
        if !matches!(self.overlay_type.as_str(), "subnet" | "full") {
            return Err(Error::Config(format!(
                "--overlay-type must be \"subnet\" or \"full\", got {:?}",
                self.overlay_type
            )));
        }

        // Positive sync periods.
        for (flag, d) in [
            ("--cache-sync-timeout", self.cache_sync_timeout),
            ("--routes-sync-period", self.routes_sync_period),
            ("--iptables-sync-period", self.iptables_sync_period),
            ("--ipvs-sync-period", self.ipvs_sync_period),
            ("--ipvs-graceful-period", self.ipvs_graceful_period),
            (
                "--injected-routes-sync-period",
                self.injected_routes_sync_period,
            ),
            ("--loadbalancer-sync-period", self.loadbalancer_sync_period),
        ] {
            if d.is_zero() {
                return Err(Error::Config(format!("{flag} must be greater than 0")));
            }
        }

        // Global external peers: ASN list must match IP list length when provided.
        if !self.peer_router_ips.is_empty()
            && !self.peer_router_asns.is_empty()
            && self.peer_router_ips.len() != self.peer_router_asns.len()
        {
            return Err(Error::Config(
                "--peer-router-ips and --peer-router-asns must have equal length".into(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::KubeRouterConfig;

    fn cfg(args: &[&str]) -> KubeRouterConfig {
        let mut v = vec!["kube-router-rs"];
        v.extend_from_slice(args);
        KubeRouterConfig::try_parse_from(v).expect("parse")
    }

    #[test]
    fn defaults_validate() {
        cfg(&[]).validate().expect("defaults should be valid");
    }

    #[test]
    fn no_family_enabled_is_rejected() {
        let c = cfg(&["--enable-ipv4=false", "--enable-ipv6=false"]);
        assert!(c.validate().is_err());
    }

    #[test]
    fn ipv6_only_requires_router_id() {
        let c = cfg(&["--enable-ipv4=false", "--enable-ipv6=true"]);
        assert!(c.validate().is_err());
        let ok = cfg(&[
            "--enable-ipv4=false",
            "--enable-ipv6=true",
            "--router-id=generate",
        ]);
        ok.validate().expect("router-id satisfies v6-only");
    }

    #[test]
    fn ipv6_only_router_not_running_is_ok() {
        let c = cfg(&[
            "--enable-ipv4=false",
            "--enable-ipv6=true",
            "--run-router=false",
        ]);
        c.validate().expect("no router => no router-id needed");
    }

    #[test]
    fn bad_cidr_rejected() {
        let c = cfg(&["--service-cluster-ip-range=nonsense"]);
        assert!(c.validate().is_err());
    }

    #[test]
    fn too_many_cluster_ranges_rejected() {
        let c = cfg(&["--service-cluster-ip-range=10.0.0.0/12,fd00::/108,10.1.0.0/16"]);
        assert!(c.validate().is_err());
    }

    #[test]
    fn unknown_overlay_encap_rejected() {
        let c = cfg(&["--overlay-encap=vxlan"]);
        assert!(c.validate().is_err());
    }

    #[test]
    fn zero_sync_period_rejected() {
        let c = cfg(&["--ipvs-sync-period=0s"]);
        assert!(c.validate().is_err());
    }

    #[test]
    fn peer_ip_asn_length_mismatch_rejected() {
        let c = cfg(&[
            "--peer-router-ips=10.0.0.1,10.0.0.2",
            "--peer-router-asns=65000",
        ]);
        assert!(c.validate().is_err());
    }
}
