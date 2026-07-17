use crate::config::Host;
use k8s_openapi::api::discovery::v1::{Endpoint, EndpointSlice};
use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};

/// EndpointSlice data retained independently from XLB's eligibility policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ServiceEndpoint {
    pub name: Option<String>,
    pub ip: Ipv4Addr,
    pub node: Option<String>,
    pub zone: Option<String>,
    pub ready: Option<bool>,
    pub serving: Option<bool>,
    pub terminating: Option<bool>,
}

impl ServiceEndpoint {
    fn from_endpoint(endpoint: &Endpoint) -> Option<Self> {
        let ip = endpoint
            .addresses
            .iter()
            .filter_map(|address| address.parse::<IpAddr>().ok())
            .find_map(|address| match address {
                IpAddr::V4(ip) => Some(ip),
                IpAddr::V6(_) => None,
            })?;
        let conditions = endpoint.conditions.as_ref();

        Some(Self {
            name: endpoint
                .target_ref
                .as_ref()
                .and_then(|reference| reference.name.clone())
                .or_else(|| endpoint.hostname.clone()),
            ip,
            node: endpoint.node_name.clone(),
            zone: endpoint.zone.clone(),
            ready: conditions.and_then(|conditions| conditions.ready),
            serving: conditions.and_then(|conditions| conditions.serving),
            terminating: conditions.and_then(|conditions| conditions.terminating),
        })
    }

    /// XLB intentionally preserves stricter Pod-readiness behavior for new
    /// flows, even when a Service publishes not-ready addresses.
    fn is_eligible(&self) -> bool {
        let ready = self.ready.unwrap_or(true);
        let serving = self.serving.unwrap_or(true);
        let terminating = self.terminating.unwrap_or(false);
        ready && serving && !terminating
    }

    fn host(&self) -> Host {
        Host {
            name: self.name.clone().unwrap_or_else(|| self.ip.to_string()),
            ip: IpAddr::V4(self.ip),
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct EndpointSliceCache {
    slices: BTreeMap<String, Vec<ServiceEndpoint>>,
}

impl EndpointSliceCache {
    pub fn apply(&mut self, slice: &EndpointSlice) -> bool {
        let Some(name) = slice.metadata.name.clone() else {
            return false;
        };

        if slice.address_type != "IPv4" {
            self.slices.remove(&name);
            return true;
        }

        let endpoints = slice
            .endpoints
            .iter()
            .filter_map(ServiceEndpoint::from_endpoint)
            .collect();
        self.slices.insert(name, endpoints);
        true
    }

    pub fn remove(&mut self, name: &str) {
        self.slices.remove(name);
    }

    pub fn retain_seen(&mut self, seen: &HashSet<String>) -> usize {
        let previous = self.slices.len();
        self.slices.retain(|name, _| seen.contains(name));
        previous - self.slices.len()
    }

    pub fn eligible_hosts(&self) -> Vec<Host> {
        // EndpointSlice updates may temporarily duplicate one endpoint across
        // slices. Deduplicate by routable address, and require every observed
        // copy to remain eligible so a stale slice cannot revive a draining
        // endpoint.
        let mut hosts: BTreeMap<Ipv4Addr, (Host, bool)> = BTreeMap::new();
        for endpoint in self.slices.values().flatten() {
            hosts
                .entry(endpoint.ip)
                .and_modify(|(_, eligible)| *eligible &= endpoint.is_eligible())
                .or_insert_with(|| (endpoint.host(), endpoint.is_eligible()));
        }

        hosts
            .into_values()
            .filter_map(|(host, eligible)| eligible.then_some(host))
            .collect()
    }

    #[cfg(test)]
    fn slice_count(&self) -> usize {
        self.slices.len()
    }
}

/// Owns the EndpointSlice cache and its relist lifecycle.
///
/// While a relist is in progress, updates are cached but not published. This
/// prevents XLB from briefly exposing a partial backend set before `InitDone`.
#[derive(Debug, Default)]
pub(super) struct EndpointSliceState {
    cache: EndpointSliceCache,
    resync_seen: Option<HashSet<String>>,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum SliceApply {
    Unnamed,
    Deferred,
    Publish(Vec<Host>),
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct SyncCompletion {
    pub stale_slices: usize,
    pub backends: Vec<Host>,
}

impl EndpointSliceState {
    pub fn begin_sync(&mut self) {
        self.resync_seen = Some(HashSet::new());
    }

    pub fn apply(&mut self, slice: &EndpointSlice) -> SliceApply {
        if !self.cache.apply(slice) {
            return SliceApply::Unnamed;
        }

        if let Some(seen) = &mut self.resync_seen {
            if let Some(name) = slice.metadata.name.as_ref() {
                seen.insert(name.clone());
            }
            SliceApply::Deferred
        } else {
            SliceApply::Publish(self.cache.eligible_hosts())
        }
    }

    pub fn remove(&mut self, name: &str) -> Option<Vec<Host>> {
        self.cache.remove(name);
        self.resync_seen
            .is_none()
            .then(|| self.cache.eligible_hosts())
    }

    pub fn finish_sync(&mut self) -> Option<SyncCompletion> {
        let seen = self.resync_seen.take()?;
        let stale_slices = self.cache.retain_seen(&seen);
        Some(SyncCompletion {
            stale_slices,
            backends: self.cache.eligible_hosts(),
        })
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct BackendChanges {
    pub added: Vec<Host>,
    pub removed: Vec<Host>,
}

pub(super) fn replace_backends(current: &mut Vec<Host>, next: Vec<Host>) -> BackendChanges {
    let current_set: HashSet<Host> = current.iter().cloned().collect();
    let next_set: HashSet<Host> = next.iter().cloned().collect();
    let removed = current
        .iter()
        .filter(|host| !next_set.contains(host))
        .cloned()
        .collect();
    let added = next
        .iter()
        .filter(|host| !current_set.contains(host))
        .cloned()
        .collect();
    *current = next;

    BackendChanges { added, removed }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::ObjectReference;
    use k8s_openapi::api::discovery::v1::EndpointConditions;
    use kube::api::ObjectMeta;

    fn endpoint(
        name: &str,
        ip: &str,
        ready: Option<bool>,
        serving: Option<bool>,
        terminating: Option<bool>,
    ) -> Endpoint {
        Endpoint {
            addresses: vec![ip.into()],
            conditions: Some(EndpointConditions {
                ready,
                serving,
                terminating,
            }),
            node_name: Some("node-a".into()),
            target_ref: Some(ObjectReference {
                name: Some(name.into()),
                ..Default::default()
            }),
            zone: Some("zone-a".into()),
            ..Default::default()
        }
    }

    fn slice(name: &str, address_type: &str, endpoints: Vec<Endpoint>) -> EndpointSlice {
        EndpointSlice {
            address_type: address_type.into(),
            endpoints,
            metadata: ObjectMeta {
                name: Some(name.into()),
                ..Default::default()
            },
            ports: None,
        }
    }

    fn host(name: &str, ip: &str) -> Host {
        Host {
            name: name.into(),
            ip: ip.parse().expect("valid IP"),
        }
    }

    fn service_endpoint(
        name: &str,
        ip: &str,
        ready: Option<bool>,
        serving: Option<bool>,
        terminating: Option<bool>,
    ) -> ServiceEndpoint {
        ServiceEndpoint::from_endpoint(&endpoint(name, ip, ready, serving, terminating))
            .expect("valid endpoint")
    }

    #[test]
    fn eligibility_preserves_nullable_conditions_and_rejects_drain_states() {
        assert!(service_endpoint("ready", "10.0.0.1", None, None, None).is_eligible());
        assert!(!service_endpoint("not-ready", "10.0.0.2", Some(false), None, None).is_eligible());
        assert!(
            !service_endpoint("not-serving", "10.0.0.3", Some(true), Some(false), None)
                .is_eligible()
        );
        assert!(
            !service_endpoint(
                "terminating",
                "10.0.0.4",
                Some(true),
                Some(true),
                Some(true),
            )
            .is_eligible()
        );
    }

    #[test]
    fn relist_defers_partial_updates_and_atomically_removes_stale_slices() {
        let mut state = EndpointSliceState::default();
        let mut published = match state.apply(&slice(
            "stale",
            "IPv4",
            vec![endpoint(
                "pod-stale",
                "10.0.0.1",
                Some(true),
                Some(true),
                None,
            )],
        )) {
            SliceApply::Publish(backends) => backends,
            update => panic!("expected an initial publication, got {update:?}"),
        };

        state.begin_sync();
        assert_eq!(
            state.apply(&slice(
                "current",
                "IPv4",
                vec![endpoint(
                    "pod-current",
                    "10.0.0.2",
                    Some(true),
                    Some(true),
                    None,
                )],
            )),
            SliceApply::Deferred
        );
        assert_eq!(published, vec![host("pod-stale", "10.0.0.1")]);

        let completion = state.finish_sync().expect("active relist");
        assert_eq!(completion.stale_slices, 1);
        published = completion.backends;
        assert_eq!(published, vec![host("pod-current", "10.0.0.2")]);
    }

    #[test]
    fn merges_multiple_slices_and_ignores_ipv6() {
        let mut cache = EndpointSliceCache::default();
        assert!(cache.apply(&slice(
            "backend-a",
            "IPv4",
            vec![endpoint("pod-b", "10.0.0.2", Some(true), Some(true), None)],
        )));
        assert!(cache.apply(&slice(
            "backend-b",
            "IPv4",
            vec![endpoint("pod-a", "10.0.0.1", Some(true), Some(true), None)],
        )));
        assert!(cache.apply(&slice(
            "backend-v6",
            "IPv6",
            vec![endpoint(
                "pod-v6",
                "2001:db8::1",
                Some(true),
                Some(true),
                None
            )],
        )));

        assert_eq!(
            cache.eligible_hosts(),
            vec![host("pod-a", "10.0.0.1"), host("pod-b", "10.0.0.2")]
        );
    }

    #[test]
    fn duplicate_endpoint_uses_conservative_eligibility() {
        let mut cache = EndpointSliceCache::default();
        cache.apply(&slice(
            "old",
            "IPv4",
            vec![endpoint("pod-a", "10.0.0.1", Some(true), Some(true), None)],
        ));
        cache.apply(&slice(
            "new",
            "IPv4",
            vec![endpoint(
                "pod-a",
                "10.0.0.1",
                Some(false),
                Some(false),
                None,
            )],
        ));

        assert!(cache.eligible_hosts().is_empty());
    }

    #[test]
    fn applying_a_slice_replaces_its_previous_endpoints() {
        let mut cache = EndpointSliceCache::default();
        cache.apply(&slice(
            "backend",
            "IPv4",
            vec![endpoint("pod-a", "10.0.0.1", Some(true), Some(true), None)],
        ));
        cache.apply(&slice(
            "backend",
            "IPv4",
            vec![endpoint("pod-b", "10.0.0.2", Some(true), Some(true), None)],
        ));

        assert_eq!(cache.eligible_hosts(), vec![host("pod-b", "10.0.0.2")]);
    }

    #[test]
    fn resync_removes_slices_absent_from_the_completed_snapshot() {
        let mut cache = EndpointSliceCache::default();
        cache.apply(&slice("keep", "IPv4", Vec::new()));
        cache.apply(&slice("stale", "IPv4", Vec::new()));

        let removed = cache.retain_seen(&HashSet::from(["keep".into()]));

        assert_eq!(removed, 1);
        assert_eq!(cache.slice_count(), 1);
    }
}
