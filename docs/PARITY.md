# kube-router-rs — parity scope & deviations

kube-router-rs is a Rust rewrite of [kube-router](https://github.com/cloudnativelabs/kube-router)
built for behavioural parity with the Go upstream (vendored under `upstream/`).
This document records what is implemented, the intentional deviations, and the
security posture.

## Controllers

| Controller | Flag | Status |
|---|---|---|
| Network Routes (NRC) — pod networking + BGP | `--run-router` | ✅ CNI setup, direct/BGP pod routes, gobgp gRPC engine, iBGP mesh/RR, external peers, service-VIP advertisement (ECMP), graceful restart, communities / AS-path prepend / custom-import-reject, overlay tunnels (IPIP/FoU), pod-egress SNAT |
| Network Services (NSC) — IPVS service proxy | `--run-service-proxy` | ✅ ClusterIP / ExternalIP / LoadBalancer / NodePort, traffic policies, session affinity, graceful termination + conntrack, per-service metrics, hairpin, NodePort health-checks, masquerade, TCPMSS, DSR (FWMARK), ipvs-permit-all firewall |
| Network Policy (NPC) — firewall | `--run-firewall` | ✅ ingress/egress policies, default-deny, ipset-backed pod/policy chains via iptables save/restore |
| LoadBalancer allocator (lballoc) | `--run-loadbalancer` | ✅ IP-pool allocation, service-class filter, Lease leader election, status update |

Health (`/healthz`) and Prometheus metrics (`/metrics`, `kube_router_*`) surfaces,
`--cleanup-config` teardown, and graceful shutdown are implemented.

## Architecture notes

- OS effects sit behind mockable async traits (`IpvsOps`, `NetlinkOps`,
  `NatOps`/`MangleOps`, `IptablesOps`/`IpsetOps`, `BgpEngine`, `LeaseBackend`, …);
  logic is unit-tested against mocks, runtime impls shell out to
  `ip`/`iptables`/`ipset`/`ipvsadm`/`conntrack` or call gobgp/CRI over gRPC.
- BGP is driven by a supervised `gobgpd` over its gRPC API (proto vendored from
  the upstream-pinned gobgp module), mirroring upstream's use of GoBGP.

## Intentional deviations

- **IPVS programming** shells `ipvsadm` rather than using genetlink directly. The
  arg builders are unit-tested; behaviour is equivalent. A genetlink-native
  backend is a future optimisation (upstream uses the moby/ipvs netlink library).
- **BGP export attributes** (communities, AS-path prepend) are attached directly
  to advertised paths rather than via a separate gobgp export *policy*; the routes
  peers receive are identical. Custom-import-reject is enforced at the route
  injector (learned prefixes contained by a reject CIDR are not installed).
- **Not yet implemented** (minor NSC annotations): `kube-router.io/service.hairpin.externalips`
  and `kube-router.io/service.schedflags`.

## Security posture (matches upstream)

- The gobgp **admin gRPC endpoint binds to `127.0.0.1`** by default
  (`--gobgp-admin-address`); only the local agent talks to gobgpd.
- The agent **requires root** (effective uid 0) — it programs
  iptables/ipset/IPVS/netlink, matching upstream's privilege check.
- Health/metrics bind to all interfaces by default (upstream posture; a
  Prometheus scrape target). Restrict with `--metrics-addr`/`--health-addr` if
  the node's management network is untrusted.
- BGP MD5 passwords are accepted base64-encoded via `--peer-router-passwords`
  or the per-node `kube-router.io/peer.passwords` annotation.

## Verification

Unit tests cover the pure logic in every crate (`cargo test --workspace`).
Root-only **privileged tests** (mirroring upstream's `-tags privileged`) unshare
a fresh network namespace and drive the real kernel IPVS genl family — run with
`cargo test -p kr-proxy --features privileged` as root (a dedicated CI job does
this; tests skip gracefully if the IPVS module is unavailable).
Cluster-facing scenarios live in `integration/` (run against the dockerized k0s
cluster in `e2e/k0s/`): `pod_networking.sh`, `advertisement.sh`, `dropin.sh`,
`dualstack.sh`. CI runs fmt + build + clippy + tests, and a k0s job that deploys
kube-router-rs as the CNI replacement.
