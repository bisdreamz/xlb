# XLB - High-Performance Load Balancer

XLB is an IPv4/TCP Layer 4 load balancer that routes packets at the network layer instead of terminating and re-establishing connections like traditional reverse proxies (HAProxy, Nginx).

**How it works:**
Traditional load balancers act as reverse proxies - they accept your client's connection, then open a separate connection to your backend. This creates overhead: connection setup/teardown, data copying, context switching.

XLB forwards packets directly by rewriting IP addresses and ports in the kernel. Your client's TCP connection flows end-to-end to the backend through XLB - one connection, not two.

This architecture avoids TCP termination and userspace packet copying in the load-balancing path.
Its performance still depends on the NIC, kernel, packet mix, connection churn, and whether native
driver XDP is available.

## Performance

XLB is built for native-driver XDP packet processing, with generic/SKB XDP as a compatibility
fallback. Reproducible benchmark results and comparison methodology have not yet been published, so
capacity should be established with the intended hardware and OpenRTB traffic profile.

## Current Features

- **TCP load balancing** (IPv4 only - UDP and IPv6 coming later)
- **Packet forwarding** - Direct end-to-end connections, not reverse proxy
- **Static backends** - Configure fixed backend IPs
- **Kubernetes discovery** - Automatic backend updates from K8s services
- **Reactive shutdown** - Reset matching traffic that arrives during a termination grace window
- **OpenTelemetry metrics** - Export stats to your monitoring system

## What XLB Doesn't Do

- **No Layer 7** - No HTTP parsing, routing, or header inspection
- **No TLS termination** - Pass-through only
- **No request routing** - No path-based or host-based routing
- **No caching** - Pure packet forwarding

If you need HTTP features, use Nginx, HAProxy, or Envoy behind XLB.

## Requirements

- Linux kernel 5.10+
- XDP-capable network driver (i40e, ixgbe, mlx5, virtio_net)
- 2-4 CPU cores
- 256MB+ RAM

## Scaling

XLB scales horizontally through multiple instances with DNS round-robin:

- Deploy multiple XLB instances across different nodes
- Configure DNS A records pointing to all instance IPs
- Clients are distributed across instances via DNS
- Each instance handles independent subset of connections

Example: 3 XLB instances with multiple DNS A records:
```
lb.example.com → 10.0.1.10
lb.example.com → 10.0.1.11
lb.example.com → 10.0.1.12
```

On Kubernetes, ExternalDNS can manage a record for the XLB Service's load-balancer address.

## Use Cases

**When to use XLB:**

- Cost-effective alternative to expensive cloud provider NLBs (AWS NLB, GCP Network Load Balancer)
- Portable L4 load balancing across clouds, on-prem, and bare metal
- High packet-rate services where avoiding TCP termination and userspace packet copies is valuable
- Latency-sensitive systems that can validate XLB against their own packet and connection profile
- Simple L4 forwarding without the operational complexity of HAProxy/NGINX

**When NOT to use XLB:**

- You need L7 features (HTTP routing, TLS termination, header manipulation, caching)

## Quick Start

```yaml
# xlb.yaml - Static deployment example
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
```

```bash
docker run --privileged --network=host --stop-timeout 20 \
  --mount type=bind,source="$(pwd)/xlb.yaml",target=/app/xlb.yaml,readonly \
  emaczura/xlb:0.1.0
```

See [Installation Guide](getting-started/installation.md) for details.
