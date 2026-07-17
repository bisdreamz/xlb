mod endpoints;

use self::endpoints::{EndpointSliceState, SliceApply, replace_backends};
use crate::config::Host;
use crate::provider::BackendProvider;
use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use futures::StreamExt;
use k8s_openapi::api::core::v1::Service;
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::runtime::watcher::{self, Event};
use kube::{Api, Client};
use log::{debug, info, warn};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::task::JoinHandle;

const INITIAL_SYNC_TIMEOUT: Duration = Duration::from_secs(30);
const SERVICE_NAME_LABEL: &str = "kubernetes.io/service-name";

pub struct KubernetesProvider {
    namespace: String,
    service: String,
    /// Current backend list, updated by the EndpointSlice watcher.
    backends: Arc<RwLock<Vec<Host>>>,
    /// Handle to the watch task.
    watch_handle: Arc<RwLock<Option<JoinHandle<()>>>>,
}

impl KubernetesProvider {
    pub fn new(namespace: String, service: String) -> Self {
        Self {
            namespace,
            service,
            backends: Arc::new(RwLock::new(Vec::new())),
            watch_handle: Arc::new(RwLock::new(None)),
        }
    }

    fn publish_backends(
        next: Vec<Host>,
        backends: &RwLock<Vec<Host>>,
        namespace: &str,
        service: &str,
    ) {
        let mut current = backends.write().expect("backend lock poisoned");
        let changes = replace_backends(&mut current, next);
        let total = current.len();

        for host in changes.removed {
            info!(
                "Removed backend: {} ({}) for service {}/{} (no longer eligible, total: {})",
                host.name, host.ip, namespace, service, total
            );
        }
        for host in changes.added {
            info!(
                "Added backend: {} ({}) for service {}/{} (total: {})",
                host.name, host.ip, namespace, service, total
            );
        }
    }

    fn apply_slice(
        state: &mut EndpointSliceState,
        slice: &EndpointSlice,
        backends: &RwLock<Vec<Host>>,
        namespace: &str,
        service: &str,
    ) {
        match state.apply(slice) {
            SliceApply::Unnamed => warn!(
                "Ignoring unnamed EndpointSlice for service {}/{}",
                namespace, service
            ),
            SliceApply::Deferred => {}
            SliceApply::Publish(next) => {
                Self::publish_backends(next, backends, namespace, service);
            }
        }
    }
}

#[async_trait]
impl BackendProvider for KubernetesProvider {
    async fn start(&self) -> Result<()> {
        let client = Client::try_default().await.context(
            "Failed to create Kubernetes client - ensure running in cluster or kubeconfig is set",
        )?;

        // Validate the configured Service and make the stricter XLB policy
        // explicit when Kubernetes is configured to publish not-ready peers.
        let service_api: Api<Service> = Api::namespaced(client.clone(), &self.namespace);
        let service = service_api.get(&self.service).await.context(format!(
            "Failed to get service {}/{}",
            self.namespace, self.service
        ))?;
        let publishes_not_ready = service
            .spec
            .as_ref()
            .and_then(|spec| spec.publish_not_ready_addresses)
            .unwrap_or(false);
        if publishes_not_ready {
            info!(
                "Service {}/{} publishes not-ready addresses; XLB will still require ready, serving, non-terminating endpoints for new flows",
                self.namespace, self.service
            );
        }

        let label_selector = format!("{SERVICE_NAME_LABEL}={}", self.service);
        info!(
            "Watching EndpointSlices with selector '{}' for service {}/{}",
            label_selector, self.namespace, self.service
        );

        let slices_api: Api<EndpointSlice> = Api::namespaced(client, &self.namespace);
        let backends = self.backends.clone();
        let namespace = self.namespace.clone();
        let service = self.service.clone();
        let (initial_sync_tx, initial_sync_rx) = tokio::sync::oneshot::channel();

        let handle = tokio::spawn(async move {
            let watch = watcher::watcher(
                slices_api,
                watcher::Config::default().labels(&label_selector),
            );
            futures::pin_mut!(watch);

            let mut state = EndpointSliceState::default();
            let mut initial_sync_tx = Some(initial_sync_tx);

            while let Some(event) = watch.next().await {
                match event {
                    Ok(Event::Apply(slice)) => {
                        Self::apply_slice(&mut state, &slice, &backends, &namespace, &service)
                    }
                    Ok(Event::Init) => {
                        debug!(
                            "EndpointSlice watch sync starting for service {}/{}",
                            namespace, service
                        );
                        state.begin_sync();
                    }
                    Ok(Event::InitApply(slice)) => {
                        Self::apply_slice(&mut state, &slice, &backends, &namespace, &service);
                    }
                    Ok(Event::Delete(slice)) => {
                        if let Some(name) = slice.metadata.name.as_deref()
                            && let Some(next) = state.remove(name)
                        {
                            Self::publish_backends(next, &backends, &namespace, &service);
                        }
                    }
                    Ok(Event::InitDone) => {
                        if let Some(completion) = state.finish_sync() {
                            if completion.stale_slices > 0 {
                                debug!(
                                    "Removed {} stale EndpointSlice(s) after sync for service {}/{}",
                                    completion.stale_slices, namespace, service
                                );
                            }
                            Self::publish_backends(
                                completion.backends,
                                &backends,
                                &namespace,
                                &service,
                            );
                        }
                        debug!(
                            "EndpointSlice watch sync complete for service {}/{}",
                            namespace, service
                        );
                        if let Some(tx) = initial_sync_tx.take() {
                            let _ = tx.send(());
                        }
                    }
                    Err(error) => warn!(
                        "EndpointSlice watch error for service {}/{}: {}",
                        namespace, service, error
                    ),
                }
            }

            warn!(
                "EndpointSlice watch ended unexpectedly for service {}/{}",
                namespace, service
            );
        });

        match tokio::time::timeout(INITIAL_SYNC_TIMEOUT, initial_sync_rx).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                handle.abort();
                bail!(
                    "EndpointSlice watch ended before initial sync for service {}/{}",
                    self.namespace,
                    self.service
                );
            }
            Err(_) => {
                handle.abort();
                bail!(
                    "Timed out waiting for initial EndpointSlice sync for service {}/{}",
                    self.namespace,
                    self.service
                );
            }
        }

        *self
            .watch_handle
            .write()
            .expect("watch handle lock poisoned") = Some(handle);
        info!(
            "Started Kubernetes provider watching EndpointSlices for {}/{}",
            self.namespace, self.service
        );
        Ok(())
    }

    fn get_backends(&self) -> Vec<Host> {
        self.backends.read().expect("backend lock poisoned").clone()
    }

    async fn shutdown(&self) -> Result<()> {
        if let Some(handle) = self
            .watch_handle
            .write()
            .expect("watch handle lock poisoned")
            .take()
        {
            handle.abort();
            info!(
                "Stopped Kubernetes EndpointSlice watch for {}/{}",
                self.namespace, self.service
            );
        }
        Ok(())
    }
}
