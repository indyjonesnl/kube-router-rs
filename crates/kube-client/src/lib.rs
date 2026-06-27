//! Kubernetes client, shared reflector/informer stores, node discovery, and the
//! cache-sync barrier.
//!
//! Mirrors `upstream/pkg/cmd/kube-router.go`: build a client (in-cluster or
//! kubeconfig), start shared informers for the watched resources, and block on a
//! cache sync bounded by `--cache-sync-timeout` before controllers enforce.

pub mod cache;
pub mod client;
pub mod informers;
pub mod node;

pub use cache::{wait_with_timeout, CacheSyncTimeout};
pub use client::build_client;
pub use informers::spawn_reflector;
