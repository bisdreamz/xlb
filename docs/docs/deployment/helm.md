# Helm chart reference

The XLB chart creates a host-networked Deployment, Service, ServiceAccount, configuration ConfigMap,
and—when Kubernetes discovery is selected—namespace-scoped RBAC for the configured backend Service
and EndpointSlices.

Your Neuronic support representative will provide the chart and matching container-image details for
the approved release.

## Install or upgrade

```bash
export XLB_CHART='<path to supplied XLB chart>'

helm upgrade --install xlb "$XLB_CHART" \
  --namespace xlb \
  --create-namespace \
  --values xlb-values.yaml
```

Validate custom values before applying them:

```bash
helm lint "$XLB_CHART" -f xlb-values.yaml
helm template xlb "$XLB_CHART" -n xlb -f xlb-values.yaml >/dev/null
```

## Image

Use the repository and immutable digest supplied for the release:

```yaml
image:
  repository: "<provided repository>"
  digest: "<provided immutable digest>"
  pullPolicy: IfNotPresent

imagePullSecrets:
  - name: xlb-registry
```

When `image.digest` is non-empty, the chart deploys `repository@digest`. Production releases should
use the provided digest. Omit `imagePullSecrets` for a public image.

Create private-registry credentials separately; never place their values directly in the Helm file:

```bash
kubectl create secret docker-registry xlb-registry \
  --namespace xlb \
  --docker-server='<registry host>' \
  --docker-username='<provided username>' \
  --docker-password='<provided pull credential>'
```

## Deployment and placement

```yaml
replicaCount: 2
terminationGracePeriodSeconds: 90

resources:
  requests:
    cpu: 2000m
    memory: 256Mi
  limits:
    cpu: 4000m
    memory: 512Mi

nodeSelector: {}
tolerations: []

affinity:
  podAntiAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
      - labelSelector:
          matchExpressions:
            - key: app.kubernetes.io/name
              operator: In
              values: [xlb]
        topologyKey: kubernetes.io/hostname
```

The required anti-affinity permits one XLB Pod from the release per node. Ensure the cluster has at
least one eligible node per replica.

The chart uses Deployment strategy `Recreate`. Kubernetes removes the old Pods before creating new
ones during an upgrade. See [Connections and upgrades](../operations/connection-lifecycle.md) before
changing a production release.

## Security context and host access

```yaml
securityContext:
  capabilities:
    add:
      - NET_ADMIN
      - SYS_ADMIN
      - BPF
  privileged: true
```

The chart also sets `hostNetwork: true`, mounts `/sys/fs/bpf` and `/sys/kernel/debug` from the host,
and runs the current container as root. These permissions are required by the current loader and XDP
deployment model. Review node isolation and admission policy accordingly.

## Service exposure

The chart defaults are:

```yaml
service:
  type: LoadBalancer
  annotations: {}

externalDNS:
  enabled: true
  ttl: 60
```

Choose the Service type deliberately:

- `ClusterIP` works with direct node DNS/routing and avoids asking Kubernetes to provision another
  managed load balancer.
- `LoadBalancer` delegates external exposure to the cloud provider and can retain a managed
  load-balancer layer in front of XLB.

Override the defaults with `service.type: ClusterIP` and normally `externalDNS.enabled: false` for a
direct node-address deployment.

When `externalDNS.enabled` is true, the chart adds the configured TTL annotation. Add the provider's
hostname annotation under `service.annotations` when using a Service-based ExternalDNS source.

## Service account and RBAC

```yaml
serviceAccount:
  create: true
  annotations: {}
  name: ""
```

With Kubernetes discovery and `create: true`, the chart grants the generated account:

- `get` on the configured backend Service;
- `get`, `list`, and `watch` on EndpointSlices in the backend namespace.

When `create: false`, set `serviceAccount.name` and create equivalent RBAC yourself. The chart does
not create its Role or RoleBinding in that mode.

## XLB configuration

Values under `config` generate `/app/xlb.yaml`:

```yaml
config:
  name: production-lb
  listen: auto
  proto: tcp
  mode: nat

  ports:
    - local_port: 80
      remote_port: 8080

  provider:
    kubernetes:
      namespace: application
      service: backend-service

  orphan_ttl_secs: 300
  shutdown_timeout: 60

  admin:
    address: 127.0.0.1
    port: 9090
    auth:
      enabled: false
      username: admin
      existingSecret: ""
      passwordKey: password

  resources:
    network_capacity_mbps: null

  otel:
    enabled: false
    endpoint: "http://opentelemetry-collector:4317"
    export_interval_secs: 10
    protocol: grpc
    headers: {}
```

`config.name` defaults to `xlb` when empty. The supported values are IPv4/TCP and NAT; UDP, DSR,
and IPv6 load balancing are rejected or ignored by the current implementation.

See the [configuration overview](../configuration/index.md) and generated
[configuration reference](../configuration/reference.md) for field semantics.

## Static backends

The chart's default values contain the Kubernetes provider. A separate override file must explicitly
clear it before selecting static discovery:

```yaml
config:
  provider:
    kubernetes: null
    static:
      backends:
        - name: backend-1
          ip: 10.0.1.10
        - name: backend-2
          ip: 10.0.1.11
```

Static backend changes restart the Deployment through the configuration checksum.

## Port mappings

```yaml
config:
  ports:
    - local_port: 80
      remote_port: 8080
    - local_port: 443
      remote_port: 8443
```

XLB requires one through eight mappings. The Service exposes each `local_port`; the backend receives
traffic at its corresponding `remote_port`.

## Admin authentication

Create a Secret first:

```bash
kubectl create secret generic xlb-admin-auth \
  --namespace xlb \
  --from-literal=password='<strong password>'
```

Then reference its name and key:

```yaml
config:
  admin:
    address: 0.0.0.0
    port: 9090
    auth:
      enabled: true
      username: operator
      existingSecret: xlb-admin-auth
      passwordKey: password
```

When auth is enabled, `existingSecret`, `passwordKey`, and a non-empty username are required. The
chart injects the Secret value as `XLB_ADMIN_PASSWORD`; it does not place the password in the
ConfigMap.

Basic auth protects the console and status API, while health/readiness probes stay open. Add TLS or
another secure transport before exposing the HTTP listener outside a trusted network.

[Admin console and status API](../operations/admin-console.md)

## Health probes

Empty probe values enable the chart defaults:

```yaml
startupProbe: {}
readinessProbe: {}
livenessProbe: {}
```

The generated probes are:

| Probe | Path | Default behavior |
| --- | --- | --- |
| Startup | `/healthz` | Every 2 seconds, 30 failures allowed |
| Readiness | `/readyz` | Every second, 3 failures allowed |
| Liveness | `/healthz` | Every 10 seconds, 3 failures allowed |

The startup probe delays liveness and readiness until initial provider discovery and process startup
complete. Supply a complete Kubernetes probe object under the corresponding value to replace a
default.

## Resource capacity

Physical NIC speed is normally discovered from the host. Configure a capacity override for a cloud
or virtual interface that reports unknown speed:

```yaml
config:
  resources:
    network_capacity_mbps: 2000
```

The value is per attached interface. It supplies only the denominator for network utilization; XLB
still measures the live interface byte counters.

## OpenTelemetry

```yaml
config:
  otel:
    enabled: true
    endpoint: "http://opentelemetry-collector.monitoring:4317"
    protocol: grpc
    export_interval_secs: 10
    headers: {}
```

The current chart writes headers to the ConfigMap. Do not store sensitive collector credentials in
ordinary values without an appropriate secret-management layer.

[OpenTelemetry metric reference](../operations/observability.md)

## Environment

```yaml
env:
  RUST_LOG: info
```

Use `debug` temporarily for diagnosis. The release eBPF object compiles packet-level debug/trace
logging out of the fast path; userspace debug summaries still add log volume.

## Uninstall

```bash
helm uninstall xlb -n xlb
```

Helm removes chart-owned resources. Registry and admin-password Secrets created separately remain
until the operator deletes them.
