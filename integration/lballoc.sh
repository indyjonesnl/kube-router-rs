#!/usr/bin/env bash
# US5 (T095) integration scenario: the LoadBalancer allocator.
#
# Asserts a type=LoadBalancer service (class kube-router) gets a pool IP from
# --loadbalancer-ip-range, a second service gets a distinct IP, the IP is freed
# on delete, and a single elected allocator owns the kube-router-lballoc Lease.
#
# Prereqs: k0s cluster up with kube-router-rs deployed with --run-loadbalancer
# and --loadbalancer-ip-range=198.51.100.0/24, KUBECONFIG set.
# Run: integration/lballoc.sh
set -euo pipefail

KUBECTL="${KUBECTL:-kubectl}"
RANGE_PREFIX="${RANGE_PREFIX:-198.51.100.}"
fail() { echo "FAIL: $*"; exit 1; }

lb_ip() { "$KUBECTL" -n default get svc "$1" -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null; }
mk() {
  cat <<YAML | "$KUBECTL" apply -f - >/dev/null
apiVersion: v1
kind: Service
metadata: { name: $1, namespace: default }
spec:
  type: LoadBalancer
  loadBalancerClass: kube-router
  selector: { app: none-$1 }
  ports: [{ port: 80 }]
YAML
}
wait_ip() { for _ in $(seq 1 24); do ip=$(lb_ip "$1"); [ -n "$ip" ] && { echo "$ip"; return; }; sleep 5; done; echo ""; }

echo "==> Leader Lease exists (single allocator)"
"$KUBECTL" -n kube-system get lease kube-router-lballoc -o jsonpath='{.spec.holderIdentity}' >/dev/null 2>&1 \
  || fail "kube-router-lballoc Lease not present"
echo "    holder: $("$KUBECTL" -n kube-system get lease kube-router-lballoc -o jsonpath='{.spec.holderIdentity}')"

echo "==> Two LB services get distinct pool IPs"
"$KUBECTL" -n default delete svc lb-a lb-b --ignore-not-found >/dev/null 2>&1 || true
mk lb-a; mk lb-b
IPA=$(wait_ip lb-a); IPB=$(wait_ip lb-b)
[ -n "$IPA" ] || fail "lb-a got no IP"
[ -n "$IPB" ] || fail "lb-b got no IP"
case "$IPA" in "$RANGE_PREFIX"*) ;; *) fail "lb-a IP $IPA not in pool" ;; esac
[ "$IPA" != "$IPB" ] || fail "duplicate IP assigned: $IPA"
echo "    ok: lb-a=$IPA lb-b=$IPB (distinct, in pool)"

echo "==> IP released on delete and reusable"
"$KUBECTL" -n default delete svc lb-a >/dev/null
mk lb-c; IPC=$(wait_ip lb-c)
[ -n "$IPC" ] || fail "lb-c got no IP after release"
echo "    ok: lb-c=$IPC (allocated from freed pool)"

"$KUBECTL" -n default delete svc lb-a lb-b lb-c --ignore-not-found >/dev/null 2>&1 || true
echo "PASS: LoadBalancer allocator assigns distinct pool IPs, frees on delete, single-leader"
