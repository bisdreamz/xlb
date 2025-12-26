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

# Protocol: tcp (udp not yet supported)
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

# Routing mode: nat or dsr (only nat currently supported)
mode: nat

# Orphaned connection TTL (seconds)
orphan_ttl_secs: 300

# Graceful shutdown timeout (seconds)
shutdown_timeout: 15

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

**Note:** UDP support is planned but not yet implemented.

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

Dynamic backend discovery via Kubernetes Endpoints:

```yaml
provider:
  kubernetes:
    namespace: default
    service: my-service
```

XLB watches the Service endpoints and automatically updates backends as pods scale.

### Routing Mode

```yaml
# NAT mode: packets flow through XLB bidirectionally (default)
mode: nat

# DSR mode: backends respond directly to clients (not yet implemented)
# mode: dsr
```

Currently only NAT mode is supported.

### Connection Management

#### Orphan TTL

Connections without FIN/RST are cleaned up after this period:

```yaml
# Clean up orphaned connections after 5 minutes
orphan_ttl_secs: 300
```

**Use cases:**
- Scanner connections that never close
- Half-open connections from crashed clients
- Prevents connection table exhaustion

#### Shutdown Timeout

Grace period during termination to handle DNS propagation:

```yaml
# Send RSTs to new connections for 60s during shutdown
shutdown_timeout: 60
```

**Important:** Should match DNS TTL for proper graceful shutdown.

### OpenTelemetry Metrics

Export metrics to OTEL collector:

```yaml
otel:
  enabled: true
  endpoint: "http://opentelemetry-collector:4317"
  export_interval_secs: 10
  protocol: grpc  # or http
  # Optional authentication headers
  headers:
    Authorization: "Bearer token"
```

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
- Backend list: at least 1 backend required for static deployments
- Invalid fields: will error

Check logs for validation errors:

```bash
sudo xlb
# or
RUST_LOG=debug sudo xlb
```

## Next Steps

- [Full Configuration Reference](reference.md) - Auto-generated from schema
- [Kubernetes Deployment](../deployment/kubernetes.md) - Helm chart configuration
