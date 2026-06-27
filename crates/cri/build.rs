//! Generate the CRI `RuntimeService` gRPC client from the vendored proto
//! (`k8s.io/cri-api` v0.36.1, sourced from kube-router's pinned dependency).
//! Client only; no server.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto");
    tonic_prost_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(&["proto/runtime/v1/api.proto"], &["proto"])?;
    Ok(())
}
