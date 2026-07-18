# Configuration Overview

XLB is configured via a YAML file (`xlb.yaml`) that defines backend providers, port mappings, and operational parameters.

## Configuration File

By default, XLB loads configuration from `xlb.yaml` in the current directory.

## Basic Structure

```yaml
# Optional service name for metrics
name: my-loadbalancer

# Listen address: auto or specific IP
listen: auto

# Protocol: tcp (udp is rejected at startup)
proto: tcp

# Port mappings (1-8 mappings)
ports:
  - local_port: 80
    remote_port: 8080

# Backend provider
provider:
  static:
    backends:
      - name: backend-1
        ip: 10.0.1.10

# Routing mode: nat (dsr is rejected at startup)
mode: nat

# Orphaned connection TTL (seconds)
orphan_ttl_secs: 300

# Graceful shutdown timeout (seconds)
shutdown_timeout: 15

# Local health and status API
admin:
  address: 127.0.0.1
  port: 9090

# Optional for virtual NICs whose driver reports an unknown link speed
resources:
  network_capacity_mbps: 2000

# Optional OpenTelemetry metrics
otel:
  enabled: true
  endpoint: "http://otel-collector:4317"
  protocol: grpc
  export_interval_secs: 10
```

## Configuration Sections

### Listen Address

Controls which IP address XLB binds to:

```yaml
# Auto-detect primary interface IP (default)
listen: auto

# Specific IPv4 address
listen:
  ip: "192.168.1.10"
```

### Protocol

```yaml
# TCP load balancing (currently only TCP is supported)
proto: tcp
```

**Note:** UDP, DSR, IPv6 listeners, and static IPv6 backends are rejected at
startup until their dataplane paths are implemented. IPv6-only Kubernetes Pod
addresses are ignored.

XLB processes standard, unfragmented IPv4/TCP packets. IPv4 options and
fragments are passed unchanged before TCP parsing; XLB does not reassemble or
load-balance those packets. Unrelated Ethernet, IPv6, and non-TCP traffic is
also passed untouched.

### Port Mappings

Define which ports XLB listens on and where traffic is forwarded:

```yaml
ports:
  # XLB listens on 80, forwards to backend 8080
  - local_port: 80
    remote_port: 8080
  # XLB listens on 443, forwards to backend 8443
  - local_port: 443
    remote_port: 8443
```

**Limits:** Minimum 1, maximum 8 port mappings.

### Backend Providers

#### Static Backends

Fixed list of backend IPs:

```yaml
provider:
  static:
    backends:
      - name: backend-1
        ip: 10.0.1.10
      - name: backend-2
        ip: 10.0.1.11
      - name: backend-3
        ip: 10.0.1.12
```

#### Kubernetes Provider

Dynamic backend discovery using EndpointSlices associated with a Kubernetes Service:

```yaml
provider:
  kubernetes:
    namespace: default
    service: my-service
```

XLB watches every IPv4 EndpointSlice labeled for the Service and merges them into one backend set.
New flows use only endpoints that are ready, serving, and not terminating. Established flows remain
pinned to their selected backend while it drains or disappears from discovery.

EndpointSlice conditions are nullable. XLB treats `ready: null` and `serving: null` as true, and
`terminating: null` as false. XLB keeps this strict readiness policy even when the Service enables
`publishNotReadyAddresses`.

### Routing Mode

```yaml
# NAT mode: packets flow through XLB bidirectionally (default)
mode: nat

# DSR mode is rejected until its dataplane and deployment automation are implemented
# mode: dsr
```

Currently only NAT mode is supported; configuring DSR fails startup.

### Health and Status API

XLB serves a small HTTP operational API on `127.0.0.1:9090` by default:

- `GET /healthz` reports whether the process and its essential maintenance/provider tasks are live.
- `GET /readyz` returns `200` only after the dataplane has a fresh sample, the backend provider is
  healthy, and at least one backend is routable for new connections. It returns `503` with a stable
  machine-readable reason otherwise.
- `GET /api/v1/status` returns the versioned JSON snapshot consumed by the administrative UI.
- `GET /admin/` serves the embedded local-instance console.

```yaml
admin:
  address: 127.0.0.1
  port: 9090
```

The loopback default does not require authentication. To protect the UI and status snapshot with
HTTP Basic auth, configure a username and supply the password through the process environment:

```yaml
admin:
  address: 0.0.0.0
  port: 9090
  auth:
    username: operator
```

```bash
export XLB_ADMIN_PASSWORD='replace-with-a-strong-password'
```

Authentication covers `/admin/`, its embedded assets and client-side routes, `/`, and
`/api/v1/status`. The `/healthz` and `/readyz` probe endpoints remain unauthenticated. XLB fails
startup when authentication is configured without a non-empty `XLB_ADMIN_PASSWORD`.

Basic auth does not encrypt HTTP. When the listener is reachable outside a trusted management
network, terminate TLS in a reverse proxy, Gateway, tunnel, or other deployment layer. XLB logs a
warning when an authenticated HTTP listener binds to a non-loopback address so this boundary is
visible during deployment.

The JSON snapshot includes lifecycle/readiness, provider and dataplane state, discovered and
routable backends, active and cumulative connection counts, traffic rates and totals, flow-map
state, per-interface native or generic XDP attachment mode, and resource utilization. A backend that
has left discovery but still owns established flows remains visible until those flows close.

For Kubernetes discovery, watch errors retain the last-known-good backend set and retry with the
kube runtime's default backoff. Provider health in this API version means the initial sync completed
and the watch task remains alive; it does not claim that the Kubernetes control plane is currently
reachable. A terminated watch task or stale maintenance sample fails health and readiness.

### Administrative UI demo mode

The UI has a separate screenshot/demo build that uses clearly labeled illustrative data and never
polls a running XLB status API:

```bash
cd admin-ui
npm run dev:demo
```

Vite prints the local URL, normally `http://127.0.0.1:4173/admin/`. Use `npm run build:demo` to
produce a static production demo bundle in `admin-ui/dist`.

### Connection Management

#### Orphan TTL

Connections without FIN/RST are cleaned up after this period:

```yaml
# Clean up orphaned connections after 5 minutes
orphan_ttl_secs: 300
```

The effective minimum is 300 seconds. If a shorter value is configured, XLB logs one startup warning
and raises it to 300 rather than failing startup. This avoids expiring otherwise healthy,
temporarily idle TCP connections. TCP keepalive packets and any other packet activity refresh the
flow, but keepalive timing itself is configured by the endpoints and is not negotiated in the TCP
handshake. Endpoints that need to retain longer-lived idle connections must send TCP keepalives or
application traffic more frequently than `orphan_ttl_secs`; deployments may set a higher timeout
when that is not possible.

**Use cases:**

- Scanner connections that never close
- Half-open connections from crashed clients
- Prevents connection table exhaustion

#### Shutdown Timeout

Reactive grace period after XLB receives a termination signal:

```yaml
# Remain attached and reset matching TCP packets for 60s during shutdown
shutdown_timeout: 60
```

**Important:** This does not proactively close idle connections. The container or Kubernetes stop
grace period must be longer than `shutdown_timeout`.

### OpenTelemetry Metrics

Export metrics to OTEL collector:

```yaml
otel:
  enabled: true
  endpoint: "http://opentelemetry-collector:4317"
  export_interval_secs: 10
  protocol: grpc # or http
  # Optional authentication headers
  headers:
    Authorization: "Bearer token"
```

XLB exports resource-utilization gauges as percentages from 0 through 100. This deliberate
operator-facing representation makes autoscaler targets readable; these are percentages, not the
0-through-1 ratios used by some OpenTelemetry semantic conventions.

- `xlb.resource.cpu.host.utilization` measures host CPU usage, including the kernel softirq work
  where XDP executes. The Helm chart's default required anti-affinity places at most one XLB Pod on
  each node; deployments that override affinity must preserve that constraint.
- `xlb.resource.cpu.process.utilization` measures XLB process CPU time against its Kubernetes CPU
  limit, effective cgroup quota, or available CPUs.
- `xlb.resource.cpu.utilization` is the greater of host and process CPU pressure.
- `xlb.resource.network.utilization` measures the busiest RX or TX direction across every
  successfully attached XDP interface against that interface's full-duplex capacity. XLB uses the
  driver-reported link speed by default, or `resources.network_capacity_mbps` when configured.
- `xlb.resource.flow_map.utilization` measures directional flow-map entries against the map's
  fixed capacity.
- `xlb.resource.utilization` is the maximum CPU, network, or flow-map component. XLB does not embed
  a scaling threshold; operators choose the target percentage in their autoscaler policy.

The combined metric is omitted when CPU or NIC capacity cannot be measured or flow-map iteration is
incomplete, rather than reporting an unsafe partial value. Component metrics that remain valid
continue to be exported. Kubernetes resource attributes include the Pod, namespace, node, and
instance identity when their Downward API environment variables are present.

Cloud VirtIO drivers often expose byte counters but report an unknown link speed. Set the provider's
documented per-interface limit in that environment:

```yaml
resources:
  network_capacity_mbps: 2000
```

The override is deliberately explicit: inferring capacity from observed traffic would understate
headroom before the interface has ever reached its limit.

Treat this as a candidate autoscaling signal until the chosen metrics adapter, per-Pod aggregation,
and upstream traffic redistribution have been validated for the deployment. Kubernetes normally
averages a Pods custom metric across replicas; a per-instance alert should separately catch a hot
XLB node that fleet averaging could hide. Adding replicas only helps when the upstream load balancer
actually sends new flows to them.

## Complete Examples

### Static Deployment

```yaml
proto: tcp
listen: auto
ports:
  - local_port: 80
    remote_port: 8080
provider:
  static:
    backends:
      - name: backend-1
        ip: 10.0.1.10
      - name: backend-2
        ip: 10.0.1.11
shutdown_timeout: 15
```

### Kubernetes Deployment

```yaml
name: production-lb
proto: tcp
listen: auto
ports:
  - local_port: 80
    remote_port: 8080
  - local_port: 443
    remote_port: 8443
provider:
  kubernetes:
    namespace: default
    service: backend-service
shutdown_timeout: 60
otel:
  enabled: true
  endpoint: "http://opentelemetry-collector:4317"
  protocol: grpc
  export_interval_secs: 10
```

## Configuration Validation

XLB validates configuration on startup:

- Port mappings: 1-8 required

Other semantic validation is still being expanded. In particular, unknown YAML fields are currently
accepted and an empty static backend list is not rejected during parsing.

Check logs for validation errors:

```bash
sudo xlb
# or
RUST_LOG=debug sudo xlb
```

## Next Steps

- [Full Configuration Reference](reference.md) - Auto-generated from schema
- [Kubernetes Deployment](../deployment/kubernetes.md) - Helm chart configuration
