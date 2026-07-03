#!/usr/bin/env bash
# US6 (T102) integration scenario: kube-router-rs as a full drop-in replacement
# for the Go kube-router.
#
# Asserts: all nodes are Ready under kube-router-rs as the CNI, the agent's
# health + metrics endpoints scrape, cross-node pod connectivity works, and
# --cleanup-config removes the agent's on-node state.
#
# Prereqs: dockerized k0s cluster up, kube-router-rs:dev imported into workers,
# kube-router-rs DaemonSet deployed, KUBECONFIG set.
# Run: integration/dropin.sh
set -euo pipefail

KUBECTL="${KUBECTL:-kubectl}"
NS=kube-system
DS=kube-router-rs
fail() { echo "FAIL: $*"; exit 1; }

echo "==> 1. All nodes Ready under kube-router-rs"
"$KUBECTL" -n "$NS" rollout status ds/"$DS" --timeout=120s
notready=$("$KUBECTL" get nodes --no-headers | awk '$2!="Ready"{print $1}')
[ -z "$notready" ] || fail "nodes not Ready: $notready"
echo "    ok: $("$KUBECTL" get nodes --no-headers | wc -l) nodes Ready"

echo "==> 2. Health + metrics endpoints scrape"
POD=$("$KUBECTL" -n "$NS" get pods -l k8s-app="$DS" -o jsonpath='{.items[0].metadata.name}')
NODE=$("$KUBECTL" -n "$NS" get pod "$POD" -o jsonpath='{.spec.nodeName}')
CN="k0s-${NODE##*-}"   # docker container name for the worker
HP=$("$KUBECTL" -n "$NS" get ds "$DS" -o jsonpath='{range .spec.template.spec.containers[0].args[*]}{@}{"\n"}{end}' | sed -nE 's/--health-port=([0-9]+)/\1/p'); HP=${HP:-20244}
MP=$("$KUBECTL" -n "$NS" get ds "$DS" -o jsonpath='{range .spec.template.spec.containers[0].args[*]}{@}{"\n"}{end}' | sed -nE 's/--metrics-port=([0-9]+)/\1/p'); MP=${MP:-8080}
docker exec "$CN" wget -qO- "http://127.0.0.1:${HP}/healthz" | grep -qiE "ok|healthy" || fail "healthz not OK"
echo "    ok: /healthz on :$HP"
if [ -n "$MP" ] && [ "$MP" != "0" ]; then
  docker exec "$CN" wget -qO- "http://127.0.0.1:${MP}/metrics" | grep -q "kube_router_build_info" || fail "metrics missing build_info"
  echo "    ok: /metrics on :$MP (kube_router_build_info present)"
fi

echo "==> 3. Cross-node pod connectivity"
"$KUBECTL" delete ns kr-dropin --ignore-not-found >/dev/null 2>&1 || true
"$KUBECTL" create ns kr-dropin >/dev/null
"$KUBECTL" -n kr-dropin run server --image=registry.k8s.io/e2e-test-images/agnhost:2.45 \
  --overrides='{"spec":{"tolerations":[{"operator":"Exists"}]}}' \
  -- netexec --http-port=8080 >/dev/null
"$KUBECTL" -n kr-dropin wait --for=condition=Ready pod/server --timeout=120s || fail "server pod not Ready"
SIP=$("$KUBECTL" -n kr-dropin get pod server -o jsonpath='{.status.podIP}')
"$KUBECTL" -n kr-dropin run client --image=registry.k8s.io/e2e-test-images/agnhost:2.45 --restart=Never \
  --overrides='{"spec":{"affinity":{"podAntiAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"labelSelector":{"matchLabels":{"run":"server"}},"topologyKey":"kubernetes.io/hostname"}]}},"tolerations":[{"operator":"Exists"}]}}' \
  --command -- sh -c "wget -qO- --timeout=5 http://${SIP}:8080/hostname && echo OK" >/dev/null
"$KUBECTL" -n kr-dropin wait --for=jsonpath='{.status.phase}'=Succeeded pod/client --timeout=60s \
  || fail "cross-node curl failed (client did not succeed)"
echo "    ok: client reached server across nodes"
"$KUBECTL" delete ns kr-dropin --wait=false >/dev/null 2>&1 || true

echo "==> 4. --cleanup-config removes agent state"
docker exec "$CN" kube-router-rs --cleanup-config --run-router=true --run-firewall=true --run-service-proxy=true >/dev/null 2>&1 || true
docker exec "$CN" sh -c 'ip link show kube-dummy-if >/dev/null 2>&1' \
  && fail "kube-dummy-if still present after cleanup" || echo "    ok: kube-dummy-if removed"
docker exec "$CN" sh -c 'iptables -t filter -L KUBE-ROUTER-INPUT >/dev/null 2>&1' \
  && fail "KUBE-ROUTER-INPUT still present after cleanup" || echo "    ok: KUBE-ROUTER chains removed"

echo "PASS: kube-router-rs is a working drop-in replacement (Ready nodes, health/metrics, cross-node connectivity, clean teardown)"
