#!/usr/bin/env bash
# Extract an admin kubeconfig from the dockerized k0s controller and rewrite the
# server to the host-published API (127.0.0.1:6443). The API cert includes
# 127.0.0.1 in its SANs (see compose-cluster.yaml spec.api.sans), so TLS verifies.
set -euo pipefail

OUT="${1:-$HOME/.kube/k0s-docker.yaml}"
mkdir -p "$(dirname "$OUT")"

docker exec k0s-controller-1 k0s kubeconfig admin >"$OUT"
sed -i -E 's#server: https://[^[:space:]]+:6443#server: https://127.0.0.1:6443#' "$OUT"

echo "wrote $OUT"
KUBECONFIG="$OUT" kubectl get nodes
