# Kubernetes Deployment

> **⚠️ IN PROGRESS** - Helm chart distribution is in development. For early access, contact emaczura@neuronic.dev

Deploy XLB on Kubernetes using Helm for high-performance Layer 4 load balancing with dynamic backend discovery.

## Prerequisites

- Kubernetes 1.20+
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

XLB watches Kubernetes Endpoints for the configured service:

```yaml
# values.yaml
config:
  provider:
    kubernetes:
      namespace: default
      service: backend-service
```

The load balancer will automatically discover and route to all healthy endpoints of `backend-service`.

### Port Mapping

Configure which ports XLB listens on and forwards to backends:

```yaml
config:
  ports:
    - local_port: 80      # XLB listens on port 80
      remote_port: 8080   # Forwards to backend port 8080
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
  ttl: 60  # DNS record TTL in seconds
```

**How it works:**
1. XLB Service created with LoadBalancer IP
2. ExternalDNS watches Service annotations
3. DNS record created: `lb.example.com` → LoadBalancer IP
4. On pod termination, endpoint removed → ExternalDNS updates DNS

### Graceful Shutdown

XLB implements graceful shutdown to handle DNS propagation delays:

```yaml
config:
  # Grace period to send RSTs to new connections during shutdown
  # Should match DNS TTL to allow DNS propagation
  shutdown_timeout: 60

# Kubernetes termination grace period
# Must be greater than shutdown_timeout
terminationGracePeriodSeconds: 90
```

**Shutdown flow:**
1. Pod receives SIGTERM
2. preStop hook creates `/tmp/shutdown` file
3. Readiness probe fails immediately
4. Pod removed from Service endpoints
5. ExternalDNS detects change and updates DNS (within 30s)
6. XLB sends RST to new connections for `shutdown_timeout` period
7. DNS propagates (based on TTL)
8. Pod exits gracefully

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
    cpu: 2000m      # 2 cores minimum
    memory: 256Mi
  limits:
    cpu: 4000m      # Scale up for >100k RPS
    memory: 512Mi
```

**Performance scaling:**
- 2 cores: ~100k RPS
- 4 cores: ~200k+ RPS

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

## Complete Example

```yaml
# xlb-values.yaml
replicaCount: 2

image:
  repository: emaczura/xlb
  tag: latest

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
1. "preStop hook" creates /tmp/shutdown
2. Readiness probe fails
3. RST packets sent for `shutdown_timeout`
4. Pod exits
