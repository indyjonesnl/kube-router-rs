//! Common error type shared across kube-router-rs crates.

/// Errors surfaced by shared helpers.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An IP address or CIDR string could not be parsed.
    #[error("invalid IP/CIDR {input:?}: {reason}")]
    InvalidIp {
        /// The offending input.
        input: String,
        /// Why it was rejected.
        reason: String,
    },

    /// A configuration value failed validation.
    #[error("invalid configuration: {0}")]
    Config(String),

    /// An OS/sysctl interaction failed.
    #[error("sysctl error for {key:?}: {source}")]
    Sysctl {
        /// The sysctl key involved.
        key: String,
        /// Underlying IO error.
        #[source]
        source: std::io::Error,
    },
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, Error>;
