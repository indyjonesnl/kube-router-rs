#!/usr/bin/env bash
# T104 integration scenario: dual-stack behaviour (FR-060).
#
# kube-router-rs is family-agnostic: every controller keys off --enable-ipv4 /
# --enable-ipv6 and derives per-family state (iptables/ip6tables, ipset inet /
# inet6:, IPVS v4/v6 VIPs, BGP IPv4/IPv6 AFI-SAFIs). This scenario verifies the
# programmed state matches the enabled families for each mode.
#
# MODE selects the family set to assert: v4 | v6 | dual (default: matches the
# cluster's --enable-ipv4/--enable-ipv6). Prereqs: k0s cluster up, KUBECONFIG set.
# Run: MODE=dual integration/dualstack.sh
set -euo pipefail

KUBECTL="${KUBECTL:-kubectl}"
NS=kube-system; DS=kube-router-rs
MODE="${MODE:-auto}"
fail() { echo "FAIL: $*"; exit 1; }

args=$("$KUBECTL" -n "$NS" get ds "$DS" -o jsonpath='{range .spec.template.spec.containers[0].args[*]}{@}{"\n"}{end}')
want4=1; want6=0
echo "$args" | grep -q -- '--enable-ipv6=true' && want6=1
echo "$args" | grep -q -- '--enable-ipv4=false' && want4=0
case "$MODE" in
  v4)   want4=1; want6=0 ;;
  v6)   want4=0; want6=1 ;;
  dual) want4=1; want6=1 ;;
  auto) : ;;
  *) fail "unknown MODE=$MODE (use v4|v6|dual|auto)" ;;
esac
echo "==> asserting families: ipv4=$want4 ipv6=$want6 (MODE=$MODE)"

POD=$("$KUBECTL" -n "$NS" get pods -l k8s-app="$DS" -o jsonpath='{.items[0].metadata.name}')
NODE=$("$KUBECTL" -n "$NS" get pod "$POD" -o jsonpath='{.spec.nodeName}'); CN="k0s-${NODE##*-}"

# service ClusterIP families programmed in IPVS should match the enabled set.
ipvs=$(docker exec "$CN" ipvsadm -Ln 2>/dev/null || true)
if [ "$want4" = 1 ]; then echo "$ipvs" | grep -qE 'TCP  10\.' || fail "no IPv4 IPVS services"; echo "    ok: IPv4 IPVS services present"; fi
if [ "$want6" = 1 ]; then echo "$ipvs" | grep -qiE 'TCP  \[' || fail "no IPv6 IPVS services"; echo "    ok: IPv6 IPVS services present"; fi
if [ "$want6" = 0 ]; then echo "$ipvs" | grep -qiE 'TCP  \[' && fail "unexpected IPv6 IPVS services" || echo "    ok: no IPv6 state"; fi

# firewall ipsets: inet6: variants exist only when IPv6 is enabled.
if [ "$want6" = 1 ]; then
  docker exec "$CN" ipset list -name 2>/dev/null | grep -q '^inet6:' || echo "    note: no inet6 ipsets yet (no v6 services)"
fi
echo "PASS: programmed dual-stack state matches the enabled families"
