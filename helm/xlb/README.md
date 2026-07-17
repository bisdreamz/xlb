# XLB Helm Chart

Helm chart for deploying XLB eBPF Layer 4 Load Balancer on Kubernetes.

## Installation

```bash
helm install xlb ./helm/xlb -n xlb --create-namespace
```

## Configuration

See `values.yaml` for all configuration options.

### Key Configuration

**Graceful Shutdown & DNS:**
- `config.shutdown_timeout` - Must match DNS TTL (default: 60s)
- `terminationGracePeriodSeconds` - Must be > shutdown_timeout (default: 90s)
- `externalDNS.ttl` - DNS record TTL (default: 60s)

**Backend Provider:**
```yaml
config:
  provider:
    kubernetes:
      namespace: default
      service: backend-service
```

**Health and status:**

- The chart probes `/healthz` and `/readyz` on the local admin listener.
- A default startup probe protects the initial Kubernetes sync and XDP attachment window.
- `GET /api/v1/status` provides the versioned operational JSON snapshot.
- The unauthenticated listener defaults to `127.0.0.1:9090`; keep it on loopback unless access is
  protected externally.

**ExternalDNS Integration:**
```yaml
service:
  annotations:
    external-dns.alpha.kubernetes.io/hostname: lb.example.com
```

## Requirements

- Kubernetes 1.26+
- Nodes with XDP-capable network drivers
- ExternalDNS (optional, for automatic DNS management)
- OpenTelemetry Collector (optional, for metrics)

## Contact

Support: emaczura@neuronic.dev
