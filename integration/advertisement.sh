#!/usr/bin/env bash
# US4 (T085) integration scenario: an external BGP peer learns the cluster's pod
# CIDRs and advertised service VIPs from kube-router-rs.
#
# Stands up a standalone gobgpd as an external eBGP peer on the workers' docker
# network, points kube-router-rs at it (--peer-router-*, --advertise-*), and
# asserts the peer's RIB contains pod CIDRs (10.244.x.0/24) and clusterIP /32s.
#
# Prereqs: the dockerized k0s cluster is up (see e2e/k0s/), kube-router-rs:dev is
# built + imported into the workers, KUBECONFIG points at the cluster, and
# K0S_NET names the docker network the workers share.
# Run: K0S_NET=<net> integration/advertisement.sh
set -euo pipefail

IMAGE="${KR_IMAGE:-kube-router-rs:dev}"
NET="${K0S_NET:-kube-router-rs-k0s_k0s-net}"
PEER_NAME="kr-bgp-testpeer"
PEER_IP="${PEER_IP:-192.168.32.250}"
PEER_ASN="${PEER_ASN:-65179}"
CLUSTER_ASN="${CLUSTER_ASN:-64512}"
KUBECTL="${KUBECTL:-kubectl}"
KEEP="${KEEP:-}"   # set KEEP=1 to leave the peer running for debugging

cleanup() { [ -n "$KEEP" ] || docker rm -f "$PEER_NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "==> Starting external BGP test peer ($PEER_NAME, $PEER_IP AS $PEER_ASN)"
docker rm -f "$PEER_NAME" >/dev/null 2>&1 || true
docker run -d --name "$PEER_NAME" --network "$NET" --ip "$PEER_IP" \
  --entrypoint gobgpd "$IMAGE" \
  --api-hosts=127.0.0.1:50051 -t json -l info \
  >/dev/null
# gobgpd started with no config; configure global + neighbors via the CLI.
sleep 2
if ! docker ps --filter name="$PEER_NAME" --filter status=running -q | grep -q .; then
  echo "FAIL: test peer did not start"; docker logs "$PEER_NAME" 2>&1 | tail; exit 1
fi
gp() { docker exec "$PEER_NAME" gobgp "$@"; }
gp global as "$PEER_ASN" router-id "$PEER_IP"
# Accept a session from each worker node (eBGP).
WORKER_IPS=$("$KUBECTL" get nodes -o jsonpath='{range .items[*]}{.status.addresses[?(@.type=="InternalIP")].address}{"\n"}{end}')
for wip in $WORKER_IPS; do
  echo "    adding neighbor $wip as $CLUSTER_ASN"
  gp neighbor add "$wip" as "$CLUSTER_ASN" || true
done

echo "==> Pointing kube-router-rs at the peer + enabling advertisement"
"$KUBECTL" -n kube-system patch ds kube-router-rs --type=json -p='[
  {"op":"replace","path":"/spec/template/spec/containers/0/args","value":[
    "--run-router=true","--run-service-proxy=true",
    "--cluster-asn='"$CLUSTER_ASN"'",
    "--peer-router-ips='"$PEER_IP"'","--peer-router-asns='"$PEER_ASN"'",
    "--advertise-pod-cidr=true","--advertise-cluster-ip=true",
    "--routes-sync-period=10s","-v=1"]}
]'
"$KUBECTL" -n kube-system rollout status ds/kube-router-rs --timeout=120s

echo "==> Waiting for the peer to learn routes"
learned=""
for i in $(seq 1 30); do
  learned=$(gp global rib -a ipv4 2>/dev/null || true)
  if echo "$learned" | grep -qE '10\.244\.[0-9]+\.0/24' \
     && echo "$learned" | grep -qE '10\.96\.0\.[0-9]+/32'; then
    break
  fi
  sleep 5
done

echo "---- peer RIB ----"; echo "$learned"; echo "------------------"
echo "$learned" | grep -qE '10\.244\.[0-9]+\.0/24' || { echo "FAIL: no pod CIDR learned"; exit 1; }
echo "$learned" | grep -qE '10\.96\.0\.[0-9]+/32'  || { echo "FAIL: no service VIP learned"; exit 1; }
echo "PASS: external peer learned pod CIDRs and service VIPs from kube-router-rs"
