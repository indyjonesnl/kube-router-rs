//! Shared reflector/informer stores.
//!
//! `spawn_reflector` builds a cluster-wide watch for a resource, drives it on a
//! background task, and returns a read-only [`Store`]. Controllers read from the
//! store and call [`crate::cache::wait_with_timeout`] on `store.wait_until_ready()`
//! to implement the cache-sync barrier. Instantiate per watched resource (Pods,
//! Services, EndpointSlices, Nodes, Namespaces, NetworkPolicies, Leases).

use std::fmt::Debug;
use std::hash::Hash;

use futures::StreamExt;
use kube::runtime::reflector::store::Store;
use kube::runtime::{reflector, watcher, WatchStreamExt};
use kube::{Api, Client, Resource};
use serde::de::DeserializeOwned;

/// Start a cluster-wide reflector for resource `K` and return its store.
/// The watch runs on a spawned task until the process exits.
pub fn spawn_reflector<K>(client: Client) -> Store<K>
where
    K: Resource + Clone + Debug + DeserializeOwned + Send + Sync + 'static,
    K::DynamicType: Default + Eq + Hash + Clone,
{
    let api: Api<K> = Api::all(client);
    let (store, writer) = reflector::store::<K>();
    let stream = reflector(writer, watcher(api, watcher::Config::default()));
    tokio::spawn(async move {
        let mut stream = std::pin::pin!(stream.default_backoff());
        while let Some(event) = stream.next().await {
            if let Err(e) = event {
                tracing::warn!(error = %e, resource = std::any::type_name::<K>(), "watch error");
            }
        }
        tracing::warn!(
            resource = std::any::type_name::<K>(),
            "reflector stream ended"
        );
    });
    store
}
