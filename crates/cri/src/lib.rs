//! CRI `RuntimeService` client (tonic over a unix socket), mirroring
//! `upstream/pkg/cri`.
//!
//! Used by the DSR path to resolve a pod container's host PID so we can enter
//! its network namespace. We call `ContainerStatus` with `verbose=true` and parse
//! the runtime's `info["info"]` JSON blob for the `pid` field.

use std::time::Duration;

use serde::Deserialize;
use tonic::transport::{Channel, Endpoint, Uri};

/// Generated CRI v1 runtime types/client.
pub mod runtime_v1 {
    #![allow(clippy::all, missing_docs)]
    include!(concat!(env!("OUT_DIR"), "/runtime.v1.rs"));
}

use runtime_v1::runtime_service_client::RuntimeServiceClient;
use runtime_v1::ContainerStatusRequest;

/// Default connection timeout (matches `DefaultConnectionTimeout`).
pub const DEFAULT_CONNECTION_TIMEOUT: Duration = Duration::from_secs(15);

/// CRI client error.
#[derive(Debug, thiserror::Error)]
pub enum CriError {
    /// Endpoint string was not `proto://path` or used an unsupported protocol.
    #[error("bad endpoint: {0}")]
    Endpoint(String),
    /// gRPC transport failure.
    #[error("transport error: {0}")]
    Transport(String),
    /// gRPC call failure.
    #[error("rpc error: {0}")]
    Rpc(String),
    /// The runtime's verbose info was missing or unparseable.
    #[error("container info error: {0}")]
    Info(String),
    /// The call exceeded the configured timeout.
    #[error("timed out after {0:?}")]
    Timeout(Duration),
}

/// Split `proto://path` into `(proto, path)` (mirrors `EndpointParser`).
pub fn endpoint_parser(endpoint: &str) -> Result<(&str, &str), CriError> {
    endpoint
        .split_once("://")
        .filter(|(p, a)| !p.is_empty() && !a.is_empty())
        .ok_or_else(|| {
            CriError::Endpoint("bad endpoint format, should be 'protocol://path'".into())
        })
}

#[derive(Debug, Deserialize)]
struct ContainerInfo {
    pid: i32,
}

/// A gRPC `RuntimeService` client bound to a CRI unix socket.
pub struct RuntimeService {
    channel: Channel,
    timeout: Duration,
}

impl RuntimeService {
    /// Connect (lazily) to a CRI endpoint such as
    /// `unix:///run/containerd/containerd.sock`. Only the `unix` protocol is
    /// supported, matching upstream.
    pub fn connect(endpoint: &str, timeout: Duration) -> Result<Self, CriError> {
        let (proto, path) = endpoint_parser(endpoint)?;
        if proto != "unix" {
            return Err(CriError::Endpoint(format!(
                "only unix socket is supported, got '{proto}'"
            )));
        }
        let path = path.to_string();
        // The URI is ignored by the custom connector but must be syntactically valid.
        let channel = Endpoint::try_from("http://[::1]:50051")
            .map_err(|e| CriError::Transport(e.to_string()))?
            .connect_with_connector_lazy(tower::service_fn(move |_: Uri| {
                let path = path.clone();
                async move {
                    let stream = tokio::net::UnixStream::connect(path).await?;
                    Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
                }
            }));
        Ok(Self { channel, timeout })
    }

    /// Host PID of the given container (from `ContainerStatus` verbose info).
    pub async fn container_pid(&self, container_id: &str) -> Result<i32, CriError> {
        let mut client = RuntimeServiceClient::new(self.channel.clone());
        let req = ContainerStatusRequest {
            container_id: container_id.to_string(),
            verbose: true,
        };
        let resp = tokio::time::timeout(self.timeout, client.container_status(req))
            .await
            .map_err(|_| CriError::Timeout(self.timeout))?
            .map_err(|e| CriError::Rpc(e.to_string()))?
            .into_inner();
        let info = resp
            .info
            .get("info")
            .ok_or_else(|| CriError::Info("missing verbose 'info' field".into()))?;
        parse_container_pid(info)
    }
}

/// Parse the runtime's verbose `info` JSON blob for the container PID.
pub fn parse_container_pid(info_json: &str) -> Result<i32, CriError> {
    let info: ContainerInfo =
        serde_json::from_str(info_json).map_err(|e| CriError::Info(e.to_string()))?;
    Ok(info.pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_parser_splits_proto_and_path() {
        assert_eq!(
            endpoint_parser("unix:///run/containerd/containerd.sock").unwrap(),
            ("unix", "/run/containerd/containerd.sock")
        );
        assert!(endpoint_parser("no-scheme").is_err());
        assert!(endpoint_parser("unix://").is_err());
    }

    #[test]
    fn connect_rejects_non_unix() {
        assert!(matches!(
            RuntimeService::connect("tcp://127.0.0.1:1234", DEFAULT_CONNECTION_TIMEOUT),
            Err(CriError::Endpoint(_))
        ));
    }

    #[test]
    fn parses_pid_from_verbose_info() {
        let json = r#"{"sandboxID":"abc","pid":12345,"removing":false}"#;
        assert_eq!(parse_container_pid(json).unwrap(), 12345);
        assert!(parse_container_pid("not json").is_err());
        assert!(parse_container_pid("{}").is_err()); // missing pid
    }
}
