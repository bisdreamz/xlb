# Connections, shutdown, and upgrades

XLB keeps state for each accepted TCP connection. Understanding when that state is created, retained,
and removed is essential when changing backends or upgrading an XLB instance.

## New connections

A client SYN without ACK creates a connection pair. XLB:

1. selects one currently routable backend using round robin;
2. allocates the reverse-direction source port;
3. installs both directional entries as one generation;
4. forwards the SYN using the stored NAT recipe.

A retransmitted SYN for the same live tuple reuses the existing mapping. It does not select a new
backend or allocate another reverse entry. A new SYN that encounters terminal state from a previous
connection removes that terminal pair before creating a fresh connection.

## Backend changes

Backend discovery controls eligibility for **new** connections. Existing connections remain pinned
to their original backend even after it is removed from the current provider set.

In Kubernetes, a backend stops receiving new connections when its EndpointSlice record is not
ready, not serving, or terminating. The backend can remain visible in the status API and console as
draining while flow entries still reference it.

XLB does not proactively reset established connections merely because Kubernetes removed an
endpoint. This preserves the backend's opportunity to finish its own termination behavior. If the
backend has actually failed, the client sees the resulting network/TCP behavior until the endpoint,
kernel, or application recovers or the connection times out.

Static backend configuration is loaded at process startup. Changing `xlb.yaml` requires restarting
the instance. Kubernetes EndpointSlice changes are applied dynamically.

## Orderly close and reset

XLB observes FIN and RST packets while continuing to forward them:

- A bidirectional FIN close is retained for a 60-second TCP time-wait interval before cleanup.
- A reset marks the connection terminal and is cleaned up after a subsequent maintenance cycle.
- An incoming RST never causes XLB to generate another RST in response.
- Half-closed connections remain valid while only one direction has sent FIN.

Closure metrics identify whether the client or backend initiated the FIN or reset. See the
[observability guide](observability.md) for metric names and labels.

## Inactive connection cleanup

Connections that never complete an orderly close or reset are removed after `orphan_ttl_secs`:

```yaml
orphan_ttl_secs: 300
```

The effective minimum is five minutes. A lower configured value does not fail startup; XLB emits one
warning and raises it to `300` seconds.

Any normal TCP packet activity refreshes flow state, including acknowledgements and keepalive
packets. TCP keepalive timing is controlled by the endpoints and is not negotiated in the TCP
handshake. Applications that legitimately remain silent longer than the configured timeout should:

- send TCP keepalives or application traffic more frequently than the timeout; or
- raise `orphan_ttl_secs` to cover the expected idle period.

Very short values create false inactive-flow removals and high log/maintenance volume. They are not
a substitute for endpoint-level application timeouts.

## XLB shutdown behavior

On SIGTERM or SIGINT, XLB:

1. marks its lifecycle as shutting down so `/readyz` returns `503`;
2. stops the backend provider and maintenance loop;
3. enables the eBPF shutdown flag;
4. remains attached for `shutdown_timeout`;
5. returns a TCP reset for matching non-RST traffic that reaches the instance during that window;
6. detaches and exits after the grace period.

```yaml
shutdown_timeout: 15
```

Shutdown reset behavior is reactive. XLB does not scan the map and transmit unsolicited resets to
idle connections. A connection that sends no packet during the grace window receives no packet from
XLB.

The container runtime or Kubernetes termination grace period must exceed `shutdown_timeout` with
enough margin for process and runtime cleanup.

## Upgrade a Docker deployment

XLB flow maps are process-local and are not pinned for restoration by a replacement process. A
restart therefore loses the old instance's connection state.

For a multi-instance service:

1. remove or drain one XLB instance from the upstream traffic-distribution mechanism;
2. wait for the environment's propagation interval;
3. pull and verify the support-provided image digest;
4. stop the old instance with a timeout longer than `shutdown_timeout`;
5. start the new instance with the same reviewed configuration;
6. verify native/generic attachment, health, readiness, backend count, and traffic;
7. return the instance to service before continuing with another instance.

Do not assume a process restart preserves active connections.

## Upgrade a Helm deployment

Review the supplied release notes and values diff first:

```bash
helm diff upgrade xlb ./helm/xlb -n xlb -f xlb-values.yaml
```

`helm diff` requires the optional Helm diff plugin. Apply the release with:

```bash
helm upgrade xlb ./helm/xlb -n xlb -f xlb-values.yaml
```

The chart adds a configuration checksum to the Pod template, so a ConfigMap change triggers a
replacement without a deprecated force-recreate flag.

The current chart uses the Kubernetes `Recreate` deployment strategy because XLB owns host-network
interfaces and ports. Kubernetes stops the old Deployment Pods before creating replacements; this
is **not** a zero-downtime rolling update, even when `replicaCount` is greater than one. Coordinate
the upgrade with an external traffic-distribution layer or use separately managed XLB failure
domains when uninterrupted service is required.

After an upgrade, verify:

```bash
kubectl rollout status deployment/xlb -n xlb
kubectl logs deployment/xlb -n xlb --tail=100
kubectl get pods -n xlb -l app.kubernetes.io/name=xlb -o wide
```

Confirm that the image digest, XDP attachment mode, discovered/routable backend count, and status API
match the approved release before completing the change.
