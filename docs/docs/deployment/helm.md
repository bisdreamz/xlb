# Helm Chart Reference

> **⚠️ IN PROGRESS** - Helm chart distribution is in development. For early access, contact emaczura@neuronic.dev

Complete reference for XLB Helm chart configuration.

## Installation

```bash
# Clone repository to get Helm chart
git clone <repository-url>
cd xlb

helm install xlb ./helm/xlb -n xlb --create-namespace
```

From custom values:
```bash
helm install xlb ./helm/xlb -f custom-values.yaml -n xlb --create-namespace
```

## Values Reference

### Image Configuration

```yaml
image:
  repository: emaczura/xlb
  pullPolicy: IfNotPresent
  tag: "latest"

imagePullSecrets: []
```

### Deployment Configuration

```yaml
replicaCount: 2  # Number of XLB instances

terminationGracePeriodSeconds: 90  # Must be > shutdown_timeout
```

### Service Account

```yaml
serviceAccount:
  create: true
  annotations: {}
  name: ""  # Defaults to release name
```

### Security Context

```yaml
securityContext:
  capabilities:
    add:
      - NET_ADMIN  # Required for XDP
      - SYS_ADMIN  # Required for eBPF
      - BPF        # Required for eBPF maps
  privileged: true
```

### Service Configuration

```yaml
service:
  type: LoadBalancer
  annotations:
    external-dns.alpha.kubernetes.io/hostname: lb.example.com
    external-dns.alpha.kubernetes.io/ttl: "60"
```

### Resources

```yaml
resources:
  limits:
    cpu: 4000m
    memory: 512Mi
  requests:
    cpu: 2000m
    memory: 256Mi
```

### Node Scheduling

```yaml
nodeSelector: {}

tolerations: []

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

### XLB Configuration

All values under `config` are used to generate `xlb.yaml`:

```yaml
config:
  name: ""  # Optional service name for metrics
  listen: auto
  proto: tcp

  ports:
    - local_port: 80
      remote_port: 8080

  provider:
    kubernetes:
      namespace: default
      service: backend-service

  mode: nat
  orphan_ttl_secs: 300
  shutdown_timeout: 60

  otel:
    enabled: false
    endpoint: "http://opentelemetry-collector:4317"
    export_interval_secs: 10
    protocol: grpc
    headers: {}
```

See [Configuration Reference](../configuration/reference.md) for detailed field documentation.

### Health Probes

```yaml
readinessProbe:
  exec:
    command:
      - sh
      - -c
      - "ip link show | grep -q xdp && [ ! -f /tmp/shutdown ]"
  initialDelaySeconds: 5
  periodSeconds: 1
  timeoutSeconds: 3
  failureThreshold: 3

livenessProbe:
  exec:
    command:
      - sh
      - -c
      - "ip link show | grep -q xdp"
  initialDelaySeconds: 10
  periodSeconds: 10
  timeoutSeconds: 5
  failureThreshold: 3
```

### Environment Variables

```yaml
env:
  RUST_LOG: "info"  # Set to "debug" for verbose logging
```

## Common Configurations

### Static Backends

```yaml
config:
  provider:
    static:
      backends:
        - name: backend-1
          ip: 10.0.1.10
        - name: backend-2
          ip: 10.0.1.11
```

### Multiple Port Mappings

```yaml
config:
  ports:
    - local_port: 80
      remote_port: 8080
    - local_port: 443
      remote_port: 8443
    - local_port: 8080
      remote_port: 9090
```

Maximum: 8 port mappings

### Production Metrics

```yaml
config:
  name: production-lb
  otel:
    enabled: true
    endpoint: "http://opentelemetry-collector.monitoring:4317"
    protocol: grpc
    export_interval_secs: 10
```

## Upgrade

```bash
# Upgrade with new values
helm upgrade xlb ./helm/xlb -n xlb -f updated-values.yaml

# Force pod restart
helm upgrade xlb ./helm/xlb -n xlb --recreate-pods
```

## Uninstall

```bash
helm uninstall xlb -n xlb
```
