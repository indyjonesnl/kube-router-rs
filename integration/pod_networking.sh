#!/usr/bin/env bash
# US1 (T044) integration scenario: cross-node pod networking.
#
# Asserts each node has routes to the other nodes' pod CIDRs (installed by the
# routing controller — direct on flat L2, or BGP-learned), and that a pod on one
# node can reach a pod on another.
#
# Prereqs: dockerized k0s cluster up with kube-router-rs as the CNI, KUBECONFIG set.
# Run: integration/pod_networking.sh
set -euo pipefail

KUBECTL="${KUBECTL:-kubectl}"
fail() { echo "FAIL: $*"; exit 1; }

echo "==> Node pod CIDRs"
"$KUBECTL" get nodes -o custom-columns=NODE:.metadata.name,PODCIDR:.spec.podCIDR --no-headers

echo "==> Each worker has routes to the other workers' pod CIDRs"
for node in $("$KUBECTL" get nodes -o jsonpath='{.items[*].metadata.name}'); do
  cn="k0s-${node##*-}"
  routes=$(docker exec "$cn" ip route 2>/dev/null || true)
  for cidr in $("$KUBECTL" get nodes -o jsonpath='{range .items[*]}{.spec.podCIDR}{"\n"}{end}'); do
    own=$("$KUBECTL" get node "$node" -o jsonpath='{.spec.podCIDR}')
    [ "$cidr" = "$own" ] && continue
    echo "$routes" | grep -q "${cidr%/*}" || fail "$node missing route to $cidr"
  done
  echo "    ok: $node has routes to peer pod CIDRs"
done

echo "==> Cross-node pod connectivity"
"$KUBECTL" delete ns kr-podnet --ignore-not-found >/dev/null 2>&1 || true
"$KUBECTL" create ns kr-podnet >/dev/null
tol='{"spec":{"tolerations":[{"operator":"Exists"}]}}'
"$KUBECTL" -n kr-podnet run server --image=registry.k8s.io/e2e-test-images/agnhost:2.45 \
  --overrides="$tol" -- netexec --http-port=8080 >/dev/null
"$KUBECTL" -n kr-podnet wait --for=condition=Ready pod/server --timeout=120s || fail "server not Ready"
SIP=$("$KUBECTL" -n kr-podnet get pod server -o jsonpath='{.status.podIP}')
"$KUBECTL" -n kr-podnet run client --image=registry.k8s.io/e2e-test-images/agnhost:2.45 --restart=Never \
  --overrides='{"spec":{"affinity":{"podAntiAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"labelSelector":{"matchLabels":{"run":"server"}},"topologyKey":"kubernetes.io/hostname"}]}},"tolerations":[{"operator":"Exists"}]}}' \
  --command -- sh -c "wget -qO- --timeout=5 http://${SIP}:8080/hostname && echo OK" >/dev/null
"$KUBECTL" -n kr-podnet wait --for=jsonpath='{.status.phase}'=Succeeded pod/client --timeout=60s \
  || fail "cross-node connectivity failed"
"$KUBECTL" delete ns kr-podnet --wait=false >/dev/null 2>&1 || true
echo "PASS: cross-node pod networking works and peer pod-CIDR routes are present"
