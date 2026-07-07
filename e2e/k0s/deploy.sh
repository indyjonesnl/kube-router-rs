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

# Lower CoreDNS's response cache (default 30s) for the test cluster. The
# sig-network "change type to ExternalName" conformance tests flip a Service
# ClusterIP->ExternalName and then poll DNS; with cache 30 a replica that cached
# the pre-change A record (from the test's connectivity check) serves it stale
# for up to 30s, and IPVS round-robins onto it, so the poll intermittently gets
# the old ClusterIP and times out. The transition itself is correct (verified:
# after the cache clears, resolution is consistently the ExternalName CNAME) —
# this only speeds propagation to within the test's window. Best-effort.
kubectl -n kube-system get cm coredns -o jsonpath='{.data.Corefile}' 2>/dev/null | grep -q 'cache 30' && {
  newcore="$(kubectl -n kube-system get cm coredns -o jsonpath='{.data.Corefile}' | sed 's/cache 30/cache 1/')"
  kubectl -n kube-system patch cm coredns --type merge \
    -p "$(python3 -c 'import json,sys;print(json.dumps({"data":{"Corefile":sys.stdin.read()}}))' <<<"$newcore")" >/dev/null 2>&1 \
    && kubectl -n kube-system rollout restart deploy/coredns >/dev/null 2>&1 \
    && echo "lowered CoreDNS cache 30 -> 1 (ExternalName test propagation)"
}

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
