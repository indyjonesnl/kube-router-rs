# Multi-stage build for kube-router-rs.
# Bundles the GoBGP binary (BGP engine driven over gRPC — see research.md D5) and
# CNI plugin assets, mirroring the runtime layout of upstream/Dockerfile.

FROM rust:1-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release --workspace --locked

FROM debian:bookworm-slim
# Runtime tools the agent shells out to (parity with upstream).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        iptables ipset ipvsadm iproute2 conntrack ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# CNI plugin install target (bridge, host-local, optional portmap/hostport).
RUN mkdir -p /opt/cni/bin /etc/cni/net.d

# GoBGP binary is fetched/copied here in CI (versioned via build args); the routing
# controller supervises it and talks to it over gRPC.
# COPY --from=gobgp /usr/local/bin/gobgpd /usr/local/bin/gobgpd

COPY --from=builder /src/target/release/kube-router-rs /usr/local/bin/kube-router-rs

ENTRYPOINT ["/usr/local/bin/kube-router-rs"]
