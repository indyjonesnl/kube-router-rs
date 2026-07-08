#!/usr/bin/env bash
# One-shot deploy of kube-router-rs into the dockerized multi-node k0s cluster.
# Assumes the compose cluster is already `up -d`. Idempotent enough to re-run.
#
# Usage: e2e/k0s/deploy.sh [KUBECONFIG_OUT]   (default: ~/.kube/k0s-docker.yaml)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
KUBECONFIG_OUT="${1:-$HOME/.kube/k0s-docker.yaml}"
IMAGE="kube-router-rs:dev"
NODES=(k0s-controller-1 k0s-worker-1 k0s-worker-2 k0s-worker-3)

echo "== build agent binary =="
( cd "$REPO" && cargo build --release )
install -m 0755 "$REPO/target/release/kube-router-rs" "$HERE/kube-router-rs"

echo "== fetch gobgp =="
"$HERE/fetch-gobgp.sh"

echo "== build deploy image =="
docker build -f "$HERE/Dockerfile.deploy" -t "$IMAGE" "$HERE"

echo "== import image into each node's containerd =="
# Stream the image to `k0s ctr images import -` over the exec's stdin rather than
# `docker cp`-ing a tar into the node: the copied file was not visible to k0s ctr
# inside the worker containers (import failed "no such file"), leaving nodes CNI-less
# and NotReady. Streaming (as integration-k0s.yml does) sidesteps the node filesystem.
tar="$(mktemp --suffix=.tar)"
docker save "$IMAGE" -o "$tar"
for n in "${NODES[@]}"; do
  echo "  -> $n"
  # k0s controller has no worker containerd unless it also runs a worker; skip import errors there.
  docker exec -i "$n" k0s ctr -a /run/k0s/containerd.sock images import - < "$tar" \
    || echo "     (skipped: $n has no worker containerd)"
done
rm -f "$tar"

echo "== kubeconfig =="
"$HERE/kubeconfig.sh" "$KUBECONFIG_OUT"
export KUBECONFIG="$KUBECONFIG_OUT"

echo "== apply daemonset =="
kubectl apply -f "$HERE/kube-router-rs-daemonset.yaml"

# Tune CoreDNS for the dockerized test cluster (two independent fixes):
#  1. forward: DROP the external `forward . /etc/resolv.conf`. Neither the node's
#     upstream (127.0.0.53/systemd-resolved, node-loopback → unreachable from a pod
#     netns) NOR public resolvers (8.8.8.8/1.1.1.1, blocked in this Azure runner)
#     are reachable, so any query CoreDNS must forward BLOCKS ~10s then errors. The
#     DNS conformance probers do `dig +search`, so every ndots search-miss (incl.
#     the node's inherited search domain appended to cluster.local names) hit that
#     stall; CoreDNS backed up on dead upstreams and the multi-record tests
#     (SRV/PTR) never finished within their poll window → timeout → the test's own
#     namespace teardown then made the result reads fail ("get pods … NotFound").
#     Conformance needs NO external DNS (ExternalName is a CNAME served by the
#     kubernetes plugin, not resolved onward), so removing forward makes non-cluster
#     names SERVFAIL instantly and the probers finish fast. Upstream kube-router
#     ships stock CoreDNS and adds no DNS handling of its own — this is purely
#     test-cluster hygiene.
#  2. cache: default `cache 30` lets a replica serve a stale A record for up to
#     30s after a Service flips ClusterIP->ExternalName, timing out the "change type
#     to ExternalName" tests. Lower to 1s so the transition propagates in time.
# Both are test-cluster DNS tuning; neither changes kube-router-rs behavior.
core="$(kubectl -n kube-system get cm coredns -o jsonpath='{.data.Corefile}' 2>/dev/null)"
if [ -n "$core" ]; then
  newcore="$(printf '%s' "$core" \
    | sed '\#forward \. /etc/resolv.conf#d' \
    | sed 's/cache 30/cache 1/')"
  kubectl -n kube-system patch cm coredns --type merge \
    -p "$(python3 -c 'import json,sys;print(json.dumps({"data":{"Corefile":sys.stdin.read()}}))' <<<"$newcore")" >/dev/null 2>&1 \
    && kubectl -n kube-system rollout restart deploy/coredns >/dev/null 2>&1 \
    && echo "tuned CoreDNS (dropped external forward, cache -> 1s)"
fi

echo "== gate: wait for nodes Ready + CoreDNS Available =="
# All schedulable nodes must reach Ready (kube-router-rs is the CNI that flips them).
deadline=$(( $(date +%s) + 600 ))
while :; do
  notready="$(kubectl get nodes --no-headers 2>/dev/null | grep -cvw Ready || true)"
  total="$(kubectl get nodes --no-headers 2>/dev/null | wc -l | tr -d ' ')"
  if [ "${total:-0}" -ge 3 ] && [ "${notready:-1}" -eq 0 ]; then break; fi
  [ "$(date +%s)" -ge "$deadline" ] && { echo "TIMEOUT: nodes not Ready"; kubectl get nodes; kubectl -n kube-system get pods -o wide; exit 1; }
  sleep 5
done
kubectl -n kube-system rollout status deploy/coredns --timeout=300s
kubectl get nodes
echo "DEPLOY OK"
