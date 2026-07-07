# kind e2e cluster

This directory provisions a multi-node kind cluster that uses kube-router-rs as
the only CNI, NetworkPolicy controller, and service proxy.

```sh
kind create cluster --config e2e/kind/cluster.yaml
./e2e/kind/deploy.sh "$HOME/.kube/kind-kube-router-rs.yaml"
```

The cluster config disables kind's default CNI and kube-proxy. The deploy script
builds a Linux runtime image from the local source tree, loads it into kind,
applies the DaemonSet, and waits for all nodes plus CoreDNS to become ready.

Clean up with:

```sh
kind delete cluster --name kube-router-rs
```
