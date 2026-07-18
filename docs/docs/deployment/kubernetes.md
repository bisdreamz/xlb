# Kubernetes deployment

XLB runs as a privileged, host-networked Deployment and discovers application backends from the
EndpointSlices associated with one Kubernetes Service.

For a normal Kubernetes installation, use the supplied Helm chart. The chart already configures
the two settings that must not be removed:

```yaml
hostNetwork: true

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

Host networking exposes the node's real interface to XDP. Required anti-affinity keeps at most one
XLB Pod in the release namespace on each node. Without that placement constraint, multiple XLB
instances can contend for the same host interface and ports and do not provide independent node
capacity.

XLB's XDP redirect path does not require a node IP-forwarding sysctl change.

Your Neuronic support representative will provide the matching container image repository,
immutable digest, registry credentials when required, Helm chart, and release notes. Do not combine
an image and chart from different releases.

## Requirements

- Kubernetes 1.26 or newer.
- Helm 3.
- Linux worker nodes with kernel 5.10 or newer.
- Nodes that permit privileged Pods, host networking, and the required host filesystem mounts.
- At least one eligible XLB node for each replica; required anti-affinity permits one XLB Pod from
  the release per node.
- An existing backend Service with IPv4 EndpointSlices.
- An upstream exposure/routing design for the XLB node addresses.
- An OpenTelemetry Collector when durable metrics are required.

Pod Security Admission, Gatekeeper, Kyverno, or provider-specific policy may reject the chart's
privileged settings. Resolve that policy deliberately; removing the privileges or host networking
does not produce a functional XDP deployment.

## Prepare registry access

For a private registry, create a pull Secret in the XLB release namespace using the credentials
provided for your deployment:

```bash
kubectl create namespace xlb

kubectl create secret docker-registry xlb-registry \
  --namespace xlb \
  --docker-server='<registry host>' \
  --docker-username='<provided username>' \
  --docker-password='<provided pull credential>'
```

Prefer an external secret manager or sealed-secret workflow in production so credentials do not
remain in shell history.

## Create values

Create `xlb-values.yaml`:

```yaml
replicaCount: 2

image:
  repository: "<repository provided by Neuronic>"
  digest: "<immutable digest provided by Neuronic>"
  pullPolicy: IfNotPresent

imagePullSecrets:
  - name: xlb-registry

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

terminationGracePeriodSeconds: 90

service:
  type: ClusterIP

externalDNS:
  enabled: false
```

Omit `imagePullSecrets` when the supplied image is public. Prefer the supplied immutable digest in
production.

## Validate and install

Set `XLB_CHART` to the chart path supplied with the release:

```bash
export XLB_CHART='<path to supplied XLB chart>'

helm lint "$XLB_CHART" -f xlb-values.yaml
helm template xlb "$XLB_CHART" -n xlb -f xlb-values.yaml >/dev/null

helm upgrade --install xlb "$XLB_CHART" \
  --namespace xlb \
  --create-namespace \
  --values xlb-values.yaml
```

Wait for startup and inspect the real attachment mode:

```bash
kubectl rollout status deployment/xlb -n xlb --timeout=180s
kubectl logs deployment/xlb -n xlb --tail=100
kubectl get pods -n xlb -l app.kubernetes.io/name=xlb -o wide
```

Expected logs identify every successful interface attachment as `mode=Native` or `mode=Generic`.
Treat a Pod with no expected attachment as failed even if the process remains running.

## Backend discovery

The Kubernetes provider:

1. verifies that the configured Service exists;
2. watches every EndpointSlice selected by
   `kubernetes.io/service-name=<configured-service>`;
3. merges IPv4 endpoints across all slices;
4. deduplicates an address that temporarily appears in multiple slices;
5. publishes only endpoints that are ready, serving, and not terminating;
6. applies relists as complete snapshots so a partial relist cannot temporarily replace the active
   backend set.

```yaml
config:
  provider:
    kubernetes:
      namespace: application
      service: backend-service
```

Nullable EndpointSlice conditions follow Kubernetes compatibility semantics: absent `ready` and
`serving` are treated as true, while absent `terminating` is treated as false. XLB remains stricter
than a Service configured with `publishNotReadyAddresses`; it still excludes explicitly unready,
non-serving, or terminating endpoints from new connections.

Established connections remain pinned when a backend leaves discovery. See
[Connections, shutdown, and upgrades](../operations/connection-lifecycle.md).

### RBAC

When `serviceAccount.create: true`, the chart creates a Role in the backend Service namespace with:

- `get` on the configured Service name;
- `get`, `list`, and `watch` on EndpointSlices.

The RoleBinding references the XLB ServiceAccount in the release namespace. Pod watch permission is
not required.

When `serviceAccount.create: false`, the chart does not create this RBAC. Grant the existing account
equivalent permissions yourself.

## Choose how clients reach XLB

The Helm chart creates a Kubernetes Service, but the correct Service type depends on the surrounding
network design.

### Direct node routing

Use direct DNS records, BGP/anycast, provider routes, or another environment-specific mechanism to
send traffic to the XLB node addresses. `service.type: ClusterIP` is sufficient for Kubernetes
metadata and internal access in this model; external traffic reaches the host-networked XLB
interface directly.

This is the relevant model when XLB is intended to replace a usage-priced managed network load
balancer.

### Managed Service LoadBalancer

Setting:

```yaml
service:
  type: LoadBalancer
```

asks the Kubernetes cloud integration to provision or attach its normal managed load-balancer
resource. That can be useful during evaluation or when the provider supplies required address
advertisement, but it leaves another load-balancer layer and its cost in front of XLB.

Do not assume that installing XLB with `type: LoadBalancer` eliminates the provider's managed-LB
charge. Confirm the generated infrastructure and packet path for the target platform.

### ExternalDNS

The chart can add an ExternalDNS TTL annotation and accepts any additional Service annotations:

```yaml
service:
  type: LoadBalancer
  annotations:
    external-dns.alpha.kubernetes.io/hostname: lb.example.com

externalDNS:
  enabled: true
  ttl: 60
```

ExternalDNS behavior depends on the Service type and provider integration. For direct node-address
records, manage the DNS source and record lifecycle explicitly rather than assuming the Service
status contains the desired addresses.

## Host-network behavior

The chart always configures:

```yaml
hostNetwork: true
dnsPolicy: ClusterFirstWithHostNet
```

Consequences include:

- XLB sees the host's real interfaces and routes;
- administrative and service ports occupy the node network namespace;
- only one XLB Pod from the release should run on a node;
- host/cloud firewalls must allow the configured service ports;
- another host-networked workload cannot bind a conflicting admin port.

The default required Pod anti-affinity enforces one XLB Pod per node. A replica remains Pending when
there are too few eligible nodes. Use `nodeSelector`, taints/tolerations, and dedicated node pools to
make placement intentional.

## Health probes

The chart derives probes from `config.admin`:

- startup: `/healthz` every two seconds, allowing up to 60 seconds;
- readiness: `/readyz` every second after startup;
- liveness: `/healthz` every ten seconds after startup.

The admin listener is loopback-only by default, and the kubelet probes that host-network address.
Basic authentication, when enabled, does not protect the probe paths.

Readiness fails when there is no fresh dataplane sample, the backend-provider task is unhealthy,
there are no routable backends, or shutdown has begun. See
[Admin console and status API](../operations/admin-console.md) for exact reasons.

## Resource sizing and metrics

The chart defaults to:

```yaml
resources:
  requests:
    cpu: 2000m
    memory: 256Mi
  limits:
    cpu: 4000m
    memory: 512Mi
```

These are deployment defaults, not a universal capacity claim. Size from representative packet
sizes, connection churn, backend count, NIC bandwidth, and the observed XDP mode.

For virtual interfaces that do not report link speed, configure the documented per-interface
capacity:

```yaml
config:
  resources:
    network_capacity_mbps: 2000
```

Enable OTLP export to a separately deployed collector:

```yaml
config:
  otel:
    enabled: true
    endpoint: "http://opentelemetry-collector.monitoring:4317"
    protocol: grpc
    export_interval_secs: 10
```

See [Observability](../operations/observability.md) before creating alerts or autoscaling policy.

## Administrative access

Keep `config.admin.address: 127.0.0.1` unless the deployment has an explicit management-access
design. Use port-forwarding or a host tunnel for occasional access. For a persistent remote console,
enable Basic auth from a Kubernetes Secret and add TLS, a VPN, or another secure transport outside
XLB.

[Configure the admin console](../operations/admin-console.md)

## Shutdown and upgrades

Set `terminationGracePeriodSeconds` longer than `config.shutdown_timeout`. The current chart uses
Deployment strategy `Recreate`, so an upgrade is not a zero-downtime rolling update. Coordinate
upstream traffic and independent XLB failure domains before replacing a production release.

[Plan shutdown and upgrades](../operations/connection-lifecycle.md)
