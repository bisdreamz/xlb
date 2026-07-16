use crate::config::Host;
use crate::provider::BackendProvider;
use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use futures::StreamExt;
use k8s_openapi::api::core::v1::{Pod, Service};
use kube::runtime::watcher::{self, Event};
use kube::{Api, Client};
use log::{debug, info, warn};
use std::collections::HashSet;
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
        pod.metadata.deletion_timestamp.is_none()
            && pod
                .status
                .as_ref()
                .and_then(|s| s.conditions.as_ref())
                .is_some_and(|conditions| {
                    conditions
                        .iter()
                        .any(|c| c.type_ == "Ready" && c.status == "True")
                })
    }

    fn extract_pod_host(pod: &Pod) -> Option<Host> {
        let name = pod.metadata.name.clone()?;
        let pod_ip = pod.status.as_ref()?.pod_ip.as_ref()?.clone();
        let ip = pod_ip.parse::<IpAddr>().ok()?;
        Some(Host { name, ip })
    }

    fn reconcile_pod(backends: &mut Vec<Host>, pod: &Pod) -> BackendUpdate {
        let Some(name) = pod.metadata.name.as_deref() else {
            return BackendUpdate::Unchanged;
        };

        if !Self::is_pod_ready(pod) {
            return Self::remove_backend(backends, name)
                .map(BackendUpdate::Removed)
                .unwrap_or(BackendUpdate::Unchanged);
        }

        let Some(host) = Self::extract_pod_host(pod) else {
            return Self::remove_backend(backends, name)
                .map(BackendUpdate::Removed)
                .unwrap_or(BackendUpdate::Unchanged);
        };

        match backends.iter_mut().find(|backend| backend.name == name) {
            Some(existing) if *existing == host => BackendUpdate::Unchanged,
            Some(existing) => {
                let previous = existing.clone();
                *existing = host.clone();
                BackendUpdate::Updated { previous, host }
            }
            None => {
                backends.push(host.clone());
                BackendUpdate::Added(host)
            }
        }
    }

    fn remove_backend(backends: &mut Vec<Host>, name: &str) -> Option<Host> {
        let position = backends.iter().position(|backend| backend.name == name)?;
        Some(backends.remove(position))
    }

    fn remove_stale_backends(backends: &mut Vec<Host>, seen: &HashSet<String>) -> usize {
        let previous_len = backends.len();
        backends.retain(|backend| seen.contains(&backend.name));
        previous_len - backends.len()
    }

    fn log_backend_update(update: BackendUpdate, namespace: &str, service: &str, total: usize) {
        match update {
            BackendUpdate::Added(host) => info!(
                "Added backend: {} ({}) for service {}/{} (total: {})",
                host.name, host.ip, namespace, service, total
            ),
            BackendUpdate::Updated { previous, host } => info!(
                "Updated backend: {} ({} -> {}) for service {}/{} (total: {})",
                host.name, previous.ip, host.ip, namespace, service, total
            ),
            BackendUpdate::Removed(host) => info!(
                "Removed backend: {} ({}) for service {}/{} (not ready or terminating, total: {})",
                host.name, host.ip, namespace, service, total
            ),
            BackendUpdate::Unchanged => {}
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum BackendUpdate {
    Added(Host),
    Updated { previous: Host, host: Host },
    Removed(Host),
    Unchanged,
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
            let mut resync_seen: Option<HashSet<String>> = None;

            while let Some(event) = watch.next().await {
                match event {
                    Ok(event) => match event {
                        Event::Apply(pod) => {
                            let mut backend_list = backends.write().unwrap();
                            let update = KubernetesProvider::reconcile_pod(&mut backend_list, &pod);
                            KubernetesProvider::log_backend_update(
                                update,
                                &namespace,
                                &service,
                                backend_list.len(),
                            );
                        }
                        Event::Init => {
                            debug!(
                                "Pod watch sync starting for service {}/{}",
                                namespace, service
                            );
                            resync_seen = Some(HashSet::new());
                        }
                        Event::InitApply(pod) => {
                            if let (Some(seen), Some(name)) =
                                (&mut resync_seen, pod.metadata.name.as_ref())
                            {
                                seen.insert(name.clone());
                            }

                            let mut backend_list = backends.write().unwrap();
                            let update = KubernetesProvider::reconcile_pod(&mut backend_list, &pod);
                            KubernetesProvider::log_backend_update(
                                update,
                                &namespace,
                                &service,
                                backend_list.len(),
                            );
                        }
                        Event::Delete(pod) => {
                            if let Some(pod_name) = &pod.metadata.name {
                                let mut backend_list = backends.write().unwrap();
                                if let Some(removed) =
                                    KubernetesProvider::remove_backend(&mut backend_list, pod_name)
                                {
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
                        Event::InitDone => {
                            if let Some(seen) = resync_seen.take() {
                                let mut backend_list = backends.write().unwrap();
                                let removed = KubernetesProvider::remove_stale_backends(
                                    &mut backend_list,
                                    &seen,
                                );
                                if removed > 0 {
                                    info!(
                                        "Removed {} stale backend(s) after pod watch sync for service {}/{} (total: {})",
                                        removed,
                                        namespace,
                                        service,
                                        backend_list.len()
                                    );
                                }
                            }
                            debug!(
                                "Pod watch sync complete for service {}/{}",
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

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{PodCondition, PodStatus};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
    use kube::api::ObjectMeta;

    fn pod(name: &str, ip: &str, ready: bool) -> Pod {
        Pod {
            metadata: ObjectMeta {
                name: Some(name.into()),
                ..Default::default()
            },
            status: Some(PodStatus {
                pod_ip: Some(ip.into()),
                conditions: Some(vec![PodCondition {
                    type_: "Ready".into(),
                    status: if ready { "True" } else { "False" }.into(),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn host(name: &str, ip: &str) -> Host {
        Host {
            name: name.into(),
            ip: ip.parse().expect("valid test IP"),
        }
    }

    #[test]
    fn ready_pod_is_eligible() {
        assert!(KubernetesProvider::is_pod_ready(&pod(
            "backend-1",
            "10.0.0.1",
            true
        )));
    }

    #[test]
    fn terminating_ready_pod_is_ineligible() {
        let mut terminating = pod("backend-1", "10.0.0.1", true);
        terminating.metadata.deletion_timestamp = Some(Time(
            "2026-07-16T00:00:00Z"
                .parse()
                .expect("valid test timestamp"),
        ));

        assert!(!KubernetesProvider::is_pod_ready(&terminating));
    }

    #[test]
    fn reconcile_removes_terminating_backend() {
        let mut backends = vec![host("backend-1", "10.0.0.1")];
        let mut terminating = pod("backend-1", "10.0.0.1", true);
        terminating.metadata.deletion_timestamp = Some(Time(
            "2026-07-16T00:00:00Z"
                .parse()
                .expect("valid test timestamp"),
        ));

        let update = KubernetesProvider::reconcile_pod(&mut backends, &terminating);

        assert_eq!(
            update,
            BackendUpdate::Removed(host("backend-1", "10.0.0.1"))
        );
        assert!(backends.is_empty());
    }

    #[test]
    fn reconcile_updates_backend_ip_by_pod_name() {
        let mut backends = vec![host("backend-1", "10.0.0.1")];

        let update =
            KubernetesProvider::reconcile_pod(&mut backends, &pod("backend-1", "10.0.0.9", true));

        assert_eq!(
            update,
            BackendUpdate::Updated {
                previous: host("backend-1", "10.0.0.1"),
                host: host("backend-1", "10.0.0.9"),
            }
        );
        assert_eq!(backends, vec![host("backend-1", "10.0.0.9")]);
    }

    #[test]
    fn resync_removes_backends_not_seen_in_snapshot() {
        let mut backends = vec![
            host("backend-1", "10.0.0.1"),
            host("backend-2", "10.0.0.2"),
            host("backend-3", "10.0.0.3"),
        ];
        let seen = HashSet::from(["backend-1".into(), "backend-3".into()]);

        let removed = KubernetesProvider::remove_stale_backends(&mut backends, &seen);

        assert_eq!(removed, 1);
        assert_eq!(
            backends,
            vec![host("backend-1", "10.0.0.1"), host("backend-3", "10.0.0.3"),]
        );
    }
}
