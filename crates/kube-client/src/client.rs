//! Kubernetes client construction, honoring `--kubeconfig` and `--master`.

use kube::config::{Config, KubeConfigOptions, Kubeconfig};
use kube::Client;

/// Errors building the Kubernetes client.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// Inferring config (in-cluster or default kubeconfig) failed.
    #[error(transparent)]
    Infer(#[from] kube::config::InferConfigError),
    /// Reading/parsing an explicit kubeconfig failed.
    #[error(transparent)]
    Kubeconfig(#[from] kube::config::KubeconfigError),
    /// The `--master` override was not a valid URL.
    #[error("invalid --master URL: {0}")]
    Master(String),
    /// Constructing the client from config failed.
    #[error(transparent)]
    Kube(#[from] kube::Error),
}

/// Build a Kubernetes client.
///
/// Mirrors upstream's resolution order: an explicit `kubeconfig` path wins;
/// otherwise config is inferred (in-cluster service account, else the default
/// kubeconfig honoring `$KUBECONFIG`). A non-empty `master` overrides the API
/// server URL from the resolved config.
pub async fn build_client(
    kubeconfig: Option<&str>,
    master: Option<&str>,
) -> Result<Client, ClientError> {
    // kube's rustls TLS needs a process-level crypto provider installed before any
    // TLS handshake; without it the first connection panics. Idempotent.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut config = match kubeconfig {
        Some(path) if !path.is_empty() => {
            let kc = Kubeconfig::read_from(path)?;
            Config::from_custom_kubeconfig(kc, &KubeConfigOptions::default()).await?
        }
        _ => Config::infer().await?,
    };

    if let Some(m) = master {
        if !m.is_empty() {
            config.cluster_url = m.parse().map_err(|e| ClientError::Master(format!("{e}")))?;
        }
    }

    Ok(Client::try_from(config)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn explicit_missing_kubeconfig_errors() {
        let r = build_client(Some("/nonexistent/kubeconfig.yaml"), None).await;
        assert!(matches!(r, Err(ClientError::Kubeconfig(_))));
    }
}
