# Kubernetes Deployment

> **⚠️ IN PROGRESS** - Helm chart distribution is in development. For early access, contact emaczura@neuronic.dev

Deploy XLB on Kubernetes using Helm for high-performance Layer 4 load balancing with dynamic backend discovery.

## Prerequisites

- Kubernetes 1.26+
- Nodes with XDP-capable network drivers
- Helm 3.0+
- ExternalDNS (optional, for automatic DNS management)
- OpenTelemetry Collector (optional, for metrics)

## Quick Start

```bash
# Clone repository to get Helm chart
git clone <repository-url>
cd xlb

# Install XLB in dedicated namespace
helm install xlb ./helm/xlb \
  --namespace xlb \
  --create-namespace \
  --set config.provider.kubernetes.service=my-backend-service
```

## Configuration

### Backend Discovery

XLB validates the configured Service and watches every associated EndpointSlice selected by the
standard `kubernetes.io/service-name` label:

```yaml
# values.yaml
config:
  provider:
    kubernetes:
      namespace: default
      service: backend-service
```

New flows are assigned only to IPv4 endpoints that are Ready, serving, and not terminating.
EndpointSlice relists are applied as complete snapshots so stale slices are removed without exposing
a partial backend set. Established flows remain pinned to their selected backend while it drains.

The chart grants `services:get` and `endpointslices:get,list,watch` in the configured backend
namespace. It does not require Pod watch permission.

### Health and Status

The Helm chart configures HTTP probes against XLB's loopback-only admin API:

- A startup probe allows 60 seconds for initial discovery and XDP attachment before liveness and
  readiness checks begin.
- `/healthz` is the liveness endpoint.
- `/readyz` becomes ready only with a healthy provider, a fresh dataplane sample, and at least one
  routable backend.
- `/api/v1/status` exposes the versioned operational JSON used by the embedded admin page.
- `/admin/` serves the local-instance console from the same loopback-only listener.

The admin listener defaults to `127.0.0.1:9090`. Because it is unauthenticated and includes backend
addresses, do not bind it externally without deployment-level access controls.

EndpointSlice watch errors use the kube runtime's default backoff, and XLB retains its
last-known-good backend set during a control-plane interruption. Provider health in the initial API
means the initial sync completed and the watch task remains alive; a retrying task deliberately
fails open rather than draining every XLB during a Kubernetes API outage. If the task terminates,
health and readiness fail so Kubernetes can restart XLB.

### Port Mapping

Configure which ports XLB listens on and forwards to backends:

```yaml
config:
  ports:
    - local_port: 80 # XLB listens on port 80
      remote_port: 8080 # Forwards to backend port 8080
    - local_port: 443
      remote_port: 8443
```

### ExternalDNS Integration

XLB integrates with ExternalDNS for automatic DNS record management:

```yaml
service:
  type: LoadBalancer
  annotations:
    external-dns.alpha.kubernetes.io/hostname: lb.example.com

externalDNS:
  enabled: true
  ttl: 60 # DNS record TTL in seconds
```

**How it works:**

1. XLB Service created with LoadBalancer IP
2. ExternalDNS watches Service annotations
3. DNS record created: `lb.example.com` → LoadBalancer IP

Backend Pod changes do not normally change the XLB Service's load-balancer address or DNS record.

### Graceful Shutdown

XLB implements a reactive shutdown grace period:

```yaml
config:
  # How long XLB remains attached after SIGTERM and resets matching TCP traffic
  shutdown_timeout: 60

# Kubernetes termination grace period
# Must be greater than shutdown_timeout
terminationGracePeriodSeconds: 90
```

**Shutdown flow:**

1. Kubernetes sends SIGTERM.
2. XLB immediately marks `/readyz` unavailable so endpoint removal can begin.
3. XLB sets its eBPF shutdown flag and remains attached for `shutdown_timeout`.
4. Traffic that actually reaches the XLB during that window receives a reset response.
5. XLB exits and detaches the program after the timeout.

This mechanism is reactive: XLB does not transmit anything for an idle connection that sends no
packet during the grace window. `terminationGracePeriodSeconds` must exceed `shutdown_timeout`.

### Pod Anti-Affinity

Ensure XLB pods run on different nodes for high availability:

```yaml
affinity:
  podAntiAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
      - labelSelector:
          matchExpressions:
            - key: app.kubernetes.io/name
              operator: In
              values:
                - xlb
        topologyKey: kubernetes.io/hostname
```

### Host Network Mode

XLB requires `hostNetwork: true` for XDP to access physical network interfaces:

```yaml
# Automatically configured in Helm chart
hostNetwork: true
dnsPolicy: ClusterFirstWithHostNet
```

**Note:** This means:

- XLB pods bind directly to node ports
- Only one XLB pod per node (enforced by anti-affinity)
- Service ports must not conflict with other hostNetwork pods

### Resource Requirements

```yaml
resources:
  requests:
    cpu: 2000m
    memory: 256Mi
  limits:
    cpu: 4000m
    memory: 512Mi
```

Size requests and limits from measurements on your NIC, kernel, packet sizes, connection churn, and
whether XLB attached in native-driver or generic/SKB mode. Published benchmark guidance is planned.

## OpenTelemetry Metrics

Configure OTEL metrics export to your collector:

```yaml
config:
  otel:
    enabled: true
    endpoint: "http://opentelemetry-collector:4317"
    protocol: grpc
    export_interval_secs: 10
    # Optional authentication
    headers:
      Authorization: "Bearer your-token"
```

**Note:** Deploy OpenTelemetry Collector separately. XLB only exports metrics.

The `xlb.resource.utilization` gauge reports the maximum of host/process CPU pressure,
attached-interface bandwidth, and flow-map utilization as a value from 0 through 100. It contains
no built-in scaling target. A later HPA/collector example will validate it through the Kubernetes
custom metrics API before recommending production scaling defaults. Each deployment will choose
its own target percentage, replica limits, and stabilization policy.

Physical NICs normally report their link speed directly. For cloud or virtual NICs that report an
unknown speed, set `config.resources.network_capacity_mbps` in the Helm values to the provider's
documented per-interface limit. XLB continues to read live byte counters from the attached
interfaces; the override supplies only the capacity denominator.

## Complete Example

```yaml
# xlb-values.yaml
replicaCount: 2

image:
  repository: emaczura/xlb
  digest: sha256:replace-with-the-published-image-digest

config:
  proto: tcp
  listen: auto
  ports:
    - local_port: 80
      remote_port: 8080
  provider:
    kubernetes:
      namespace: default
      service: backend-service
  shutdown_timeout: 60
  otel:
    enabled: true
    endpoint: "http://opentelemetry-collector:4317"

service:
  type: LoadBalancer
  annotations:
    external-dns.alpha.kubernetes.io/hostname: lb.example.com

externalDNS:
  enabled: true
  ttl: 60

terminationGracePeriodSeconds: 90

resources:
  requests:
    cpu: 2000m
    memory: 256Mi
  limits:
    cpu: 4000m
    memory: 512Mi
```

Deploy:

```bash
helm install xlb ./helm/xlb -f xlb-values.yaml -n xlb --create-namespace
```

## Troubleshooting

### Check XDP Attachment

```bash
# Verify XDP program attached to interface
kubectl exec -n xlb <pod-name> -- ip link show | grep xdp
```

### View Logs

```bash
# Check XLB logs
kubectl logs -n xlb -l app.kubernetes.io/name=xlb

# Increase verbosity
helm upgrade xlb ./helm/xlb -n xlb --set env.RUST_LOG=debug
```

### Verify Backend Discovery

```bash
# Check discovered backends
kubectl logs -n xlb -l app.kubernetes.io/name=xlb | grep backend
```

### Test Graceful Shutdown

```bash
# Trigger pod termination and watch logs
kubectl delete pod -n xlb <pod-name>
kubectl logs -n xlb <pod-name> -f
```

Expected behavior:

1. XLB receives SIGTERM and `/readyz` begins returning `503`.
2. The eBPF shutdown flag is set.
3. Matching packets receive RST responses during `shutdown_timeout`.
4. XLB exits and detaches the program.
