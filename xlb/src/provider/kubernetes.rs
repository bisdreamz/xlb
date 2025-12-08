use crate::provider::{BackendProvider, Host};
use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use futures::StreamExt;
use k8s_openapi::api::core::v1::{Pod, Service};
use kube::runtime::watcher::{self, Event};
use kube::{Api, Client};
use log::{debug, info, warn};
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use tokio::task::JoinHandle;

pub struct KubernetesProvider {
    namespace: String,
    service: String,
    /// Current backend list, updated by the watcher
    backends: Arc<RwLock<Vec<Host>>>,
    /// Handle to the watch task
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

    fn is_pod_ready(pod: &Pod) -> bool {
        pod.status
            .as_ref()
            .and_then(|s| s.conditions.as_ref())
            .map(|conditions| {
                conditions
                    .iter()
                    .any(|c| c.type_ == "Ready" && c.status == "True")
            })
            .unwrap_or(false)
    }

    fn extract_pod_host(pod: &Pod) -> Option<Host> {
        let name = pod.metadata.name.clone()?;
        let pod_ip = pod.status.as_ref()?.pod_ip.as_ref()?.clone();
        let ip = pod_ip.parse::<IpAddr>().ok()?;
        Some(Host { name, ip })
    }
}

#[async_trait]
impl BackendProvider for KubernetesProvider {
    async fn start(&self) -> Result<()> {
        let client = Client::try_default().await.context(
            "Failed to create Kubernetes client - ensure running in cluster or kubeconfig is set",
        )?;

        // Fetch the Service to get its selector
        let service_api: Api<Service> = Api::namespaced(client.clone(), &self.namespace);
        let svc = service_api.get(&self.service).await.context(format!(
            "Failed to get service {}/{}",
            self.namespace, self.service
        ))?;

        let selector = svc.spec.and_then(|spec| spec.selector).context(format!(
            "Service {}/{} has no selector",
            self.namespace, self.service
        ))?;

        if selector.is_empty() {
            bail!(
                "Service {}/{} has empty selector",
                self.namespace,
                self.service
            );
        }

        // Build label selector string
        let label_selector = selector
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join(",");

        info!(
            "Watching pods with selector '{}' for service {}/{}",
            label_selector, self.namespace, self.service
        );

        let pods_api: Api<Pod> = Api::namespaced(client, &self.namespace);

        // Start watcher in background
        let backends = self.backends.clone();
        let namespace = self.namespace.clone();
        let service = self.service.clone();

        let handle = tokio::spawn(async move {
            let watch =
                watcher::watcher(pods_api, watcher::Config::default().labels(&label_selector));
            futures::pin_mut!(watch);

            while let Some(event) = watch.next().await {
                match event {
                    Ok(event) => match event {
                        Event::Apply(pod) | Event::InitApply(pod) => {
                            if let Some(host) = KubernetesProvider::extract_pod_host(&pod) {
                                let is_ready = KubernetesProvider::is_pod_ready(&pod);
                                let mut backend_list = backends.write().unwrap();

                                if is_ready {
                                    // Add if not already present
                                    if !backend_list.contains(&host) {
                                        backend_list.push(host.clone());
                                        info!(
                                            "Added backend: {} ({}) for service {}/{} (total: {})",
                                            host.name,
                                            host.ip,
                                            namespace,
                                            service,
                                            backend_list.len()
                                        );
                                    }
                                } else {
                                    // Remove if present (pod went from ready to not ready)
                                    if let Some(pos) = backend_list.iter().position(|h| h == &host)
                                    {
                                        backend_list.remove(pos);
                                        info!(
                                            "Removed backend: {} ({}) for service {}/{} (total: {})",
                                            host.name,
                                            host.ip,
                                            namespace,
                                            service,
                                            backend_list.len()
                                        );
                                    }
                                }
                            }
                        }
                        Event::Delete(pod) => {
                            if let Some(pod_name) = &pod.metadata.name {
                                let mut backend_list = backends.write().unwrap();
                                if let Some(pos) =
                                    backend_list.iter().position(|h| &h.name == pod_name)
                                {
                                    let removed = backend_list.remove(pos);
                                    info!(
                                        "Removed backend: {} ({}) for service {}/{} (total: {})",
                                        removed.name,
                                        removed.ip,
                                        namespace,
                                        service,
                                        backend_list.len()
                                    );
                                }
                            }
                        }
                        Event::Init => {}
                        Event::InitDone => {
                            debug!(
                                "Initial pod sync complete for service {}/{}",
                                namespace, service
                            );
                        }
                    },
                    Err(e) => {
                        warn!(
                            "Pod watch error for service {}/{}: {}",
                            namespace, service, e
                        );
                    }
                }
            }
        });

        *self.watch_handle.write().unwrap() = Some(handle);
        info!(
            "Started Kubernetes provider watching pods for {}/{}",
            self.namespace, self.service
        );
        Ok(())
    }

    fn get_backends(&self) -> Vec<Host> {
        self.backends.read().unwrap().clone()
    }

    async fn shutdown(&self) -> Result<()> {
        if let Some(handle) = self.watch_handle.write().unwrap().take() {
            handle.abort();
            info!(
                "Stopped Kubernetes provider watch for {}/{}",
                self.namespace, self.service
            );
        }
        Ok(())
    }
}
