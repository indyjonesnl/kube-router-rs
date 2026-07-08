#!/usr/bin/env bash
# One-shot deploy of kube-router-rs into a kind cluster with no default CNI and
# no kube-proxy. Idempotent enough to re-run after `kind create cluster`.
#
# Usage: e2e/kind/deploy.sh [KUBECONFIG_OUT]   (default: ~/.kube/kind-kube-router-rs.yaml)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
KUBECONFIG_OUT="${1:-$HOME/.kube/kind-kube-router-rs.yaml}"
IMAGE="${KR_IMAGE:-kube-router-rs:dev}"
CLUSTER_NAME="${KIND_CLUSTER_NAME:-kube-router-rs}"

# KR_SKIP_BUILD=1 => the image is already present in the local docker daemon
# (e.g. `docker load`ed from a shared CI artifact); skip building it here.
if [ -z "${KR_SKIP_BUILD:-}" ]; then
  echo "== build deploy image =="
  docker_arch="$(docker info --format '{{.Architecture}}')"
  case "$docker_arch" in
    aarch64|arm64) target_arch=arm64 ;;
    x86_64|amd64) target_arch=amd64 ;;
    *) echo "unsupported Docker architecture: $docker_arch" >&2; exit 1 ;;
  esac
  docker build \
    --build-arg "TARGETARCH=$target_arch" \
    -f "$HERE/Dockerfile.deploy" \
    -t "$IMAGE" \
    "$REPO"
else
  echo "== skip build; using pre-loaded image $IMAGE =="
fi

echo "== load image into kind =="
kind load docker-image "$IMAGE" --name "$CLUSTER_NAME"

echo "== kubeconfig =="
mkdir -p "$(dirname "$KUBECONFIG_OUT")"
kind export kubeconfig --name "$CLUSTER_NAME" --kubeconfig "$KUBECONFIG_OUT"
export KUBECONFIG="$KUBECONFIG_OUT"

echo "== apply daemonset =="
api_host="$(kubectl get node "${CLUSTER_NAME}-control-plane" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')"
if [ -z "$api_host" ]; then
  echo "unable to discover kind control-plane InternalIP" >&2
  exit 1
fi
sed "s#__KIND_API_HOST__#${api_host}#g" "$HERE/kube-router-rs-daemonset.yaml" | kubectl apply -f -

echo "== tune CoreDNS =="
core="$(kubectl -n kube-system get cm coredns -o jsonpath='{.data.Corefile}' 2>/dev/null || true)"
if [ -n "$core" ]; then
  newcore="$(printf '%s' "$core" | sed 's/cache 30/cache 1/')"
  kubectl -n kube-system patch cm coredns --type merge \
    -p "$(python3 -c 'import json,sys;print(json.dumps({"data":{"Corefile":sys.stdin.read()}}))' <<<"$newcore")" >/dev/null 2>&1 \
    && kubectl -n kube-system rollout restart deploy/coredns >/dev/null 2>&1 \
    && echo "tuned CoreDNS cache -> 1s"
fi

echo "== gate: wait for nodes Ready + CoreDNS Available =="
deadline=$(( $(date +%s) + 600 ))
while :; do
  notready="$(kubectl get nodes --no-headers 2>/dev/null | grep -cvw Ready || true)"
  total="$(kubectl get nodes --no-headers 2>/dev/null | wc -l | tr -d ' ')"
  if [ "${total:-0}" -ge 4 ] && [ "${notready:-1}" -eq 0 ]; then break; fi
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "TIMEOUT: nodes not Ready"
    kubectl get nodes
    kubectl -n kube-system get pods -o wide
    exit 1
  fi
  sleep 5
done
kubectl -n kube-system rollout status deploy/coredns --timeout=300s
kubectl get nodes
echo "DEPLOY OK"
