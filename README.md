# kube-router-rs

## Overview

kube-router-rs is a project that aims to rewrite kube-router in Rust.
kube-router is a popular network plugin for Kubernetes that provides network policies, network segmentation, and more.
This rewrite aims to leverage Rust's performance and safety features to enhance the reliability and efficiency of kube-router.

## Conformance (k0s, Hydrophone)

Upstream Kubernetes conformance run against a vanilla multi-node k0s cluster
with kube-router-rs as the sole CNI + service proxy + network-policy engine.
Each area runs as an isolated pipeline (weekly + on merge to `main`).

[![Services](https://github.com/indyjonesnl/kube-router-rs/actions/workflows/conformance-services.yml/badge.svg?branch=main)](https://github.com/indyjonesnl/kube-router-rs/actions/workflows/conformance-services.yml)
[![DNS](https://github.com/indyjonesnl/kube-router-rs/actions/workflows/conformance-dns.yml/badge.svg?branch=main)](https://github.com/indyjonesnl/kube-router-rs/actions/workflows/conformance-dns.yml)
[![Networking](https://github.com/indyjonesnl/kube-router-rs/actions/workflows/conformance-network.yml/badge.svg?branch=main)](https://github.com/indyjonesnl/kube-router-rs/actions/workflows/conformance-network.yml)
[![NetworkPolicy](https://github.com/indyjonesnl/kube-router-rs/actions/workflows/conformance-netpol.yml/badge.svg?branch=main)](https://github.com/indyjonesnl/kube-router-rs/actions/workflows/conformance-netpol.yml)

## Project Structure

- src/
- tests/

## Getting Started

### Prerequisites

- Rust 1.96 or later
- Cargo (Rust's package manager and build system)

### Versioning
Creating a Github version tag triggers a new version release; this tag is reused in
- the application version
- the container image version

### Deliverables

Each Github release contains:
- (Docker) container image (1 based on Alpine, 1 based on Debian)
- binaries for Alpine Linux (musl) and Debian/Ubuntu (glibc)
- Kubernetes Manifests
  - A standard YAML file containing the DaemonSet, ServiceAccount, ClusterRole, and ClusterRoleBinding
  - A DaemonSet shell Script: Inside the container image, kube-router is wrapped in a simple entrypoint shell script. 
    This script checks for kernel modules (like ip_tables, ip_vs), mounts /lib/modules, or cleans up 
    old network interfaces before the main binary execs.

### Developing

1. Clone this repository:
   ```sh
   git clone https://github.com/your-repo/kube-router-rs.git
   cd kube-router-rs
   ```
2. Build the project:
   cargo build
3. Run the project:
   cargo run

### Contributing

Contributions are welcome! Please read the CONTRIBUTING.md (CONTRIBUTING.md) file for more information on how to contribute to this project.

### License

This project is licensed under the MIT License - see the LICENSE (LICENSE) file for details.

This README provides a basic overview of the project, its structure, and instructions for getting started. It also includes placeholders for contributing and license information, which you can fill in as needed.