//! BGP defined-sets / policy modelling (mirrors `upstream/pkg/controllers/routing/bgp_policies.go`).
//!
//! kube-router builds prefix "defined sets" (pod CIDRs, service VIPs, peer sets,
//! custom-import-reject, default route) referenced by the `kube_router_import` /
//! `kube_router_export` policies. This crate models them; the gRPC wiring and the
//! full export/import policy assembly land with the routing controller (US4, T084).

use ipnet::IpNet;

/// The kinds of defined set kube-router maintains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefinedSetKind {
    /// Node pod CIDRs.
    PodCidr,
    /// Advertised service VIPs.
    ServiceVip,
    /// Per-node custom import-reject prefixes.
    CustomImportReject,
    /// Default route.
    DefaultRoute,
}

/// A named prefix set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefinedSet {
    /// Set name (e.g. `podcidrdefinedset`).
    pub name: String,
    /// Set kind.
    pub kind: DefinedSetKind,
    /// Prefixes in the set.
    pub prefixes: Vec<IpNet>,
}

impl DefinedSet {
    /// Build a defined set with the upstream-equivalent name for its kind/family.
    pub fn new(kind: DefinedSetKind, v6: bool, prefixes: Vec<IpNet>) -> Self {
        let base = match kind {
            DefinedSetKind::PodCidr => "podcidrdefinedset",
            DefinedSetKind::ServiceVip => "servicevipsdefinedset",
            DefinedSetKind::CustomImportReject => "customimportrejectdefinedset",
            DefinedSetKind::DefaultRoute => "defaultroutedefinedset",
        };
        let name = if v6 {
            format!("{base}v6")
        } else {
            base.to_string()
        };
        Self {
            name,
            kind,
            prefixes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_match_upstream_scheme() {
        let v4 = DefinedSet::new(DefinedSetKind::PodCidr, false, vec![]);
        assert_eq!(v4.name, "podcidrdefinedset");
        let v6 = DefinedSet::new(DefinedSetKind::ServiceVip, true, vec![]);
        assert_eq!(v6.name, "servicevipsdefinedsetv6");
    }
}
