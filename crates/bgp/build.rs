//! Generate the GoBGP gRPC client from the vendored proto (gobgp v4.5.0,
//! sourced from kube-router's pinned dependency). Client only; no server.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto");
    tonic_prost_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(&["proto/api/gobgp.proto"], &["proto"])?;
    Ok(())
}
