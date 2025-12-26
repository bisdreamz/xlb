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

**ExternalDNS Integration:**
```yaml
service:
  annotations:
    external-dns.alpha.kubernetes.io/hostname: lb.example.com
```

## Requirements

- Kubernetes 1.20+
- Nodes with XDP-capable network drivers
- ExternalDNS (optional, for automatic DNS management)
- OpenTelemetry Collector (optional, for metrics)

## Contact

Support: emaczura@neuronic.dev
