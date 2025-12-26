# XLB - High-Performance Load Balancer

XLB is a Layer 4 load balancer that routes packets directly at the network layer instead of terminating and re-establishing connections like traditional reverse proxies (HAProxy, Nginx).

**How it works:**
Traditional load balancers act as reverse proxies - they accept your client's connection, then open a separate connection to your backend. This creates overhead: connection setup/teardown, data copying, context switching.

XLB forwards packets directly by rewriting IP addresses and ports in the kernel. Your client's TCP connection flows end-to-end to the backend through XLB - one connection, not two.

**Result:** Lower latency (no proxy overhead), higher throughput (no connection duplication), lower CPU usage.

## Performance

- **>100,000 requests/second** per instance
- **Multiple Gbps throughput** per instance
- 2-4 CPU cores, 256MB RAM

Built with eBPF/XDP for kernel-level packet processing.

## Current Features

- **TCP load balancing** (IPv4 only - UDP and IPv6 coming later)
- **Packet forwarding** - Direct end-to-end connections, not reverse proxy
- **Static backends** - Configure fixed backend IPs
- **Kubernetes discovery** - Automatic backend updates from K8s services
- **Graceful shutdown** - Connection draining with RST packets during termination
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

On Kubernetes, use ExternalDNS to automatically manage A records as pods scale.

## Use Cases

**When to use XLB:**

- Cost-effective alternative to expensive cloud provider NLBs (AWS NLB, GCP Network Load Balancer)
- Portable L4 load balancing across clouds, on-prem, and bare metal
- Services processing millions of requests per second where reverse proxies become CPU bottlenecks
- Low-latency requirements where reverse proxy overhead (1-5ms) is unacceptable
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
docker run --privileged --network=host \
  -v $(pwd)/xlb.yaml:/xlb.yaml:ro \
  emaczura/xlb:latest
```

See [Installation Guide](getting-started/installation.md) for details.
