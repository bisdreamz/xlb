# XLB documentation

XLB is a commercially supported, XDP-native IPv4/TCP Layer 4 load balancer for high-volume
services. It forwards packets in the Linux kernel instead of terminating the client connection and
creating a second proxy-owned connection to the backend.

XLB is designed for workloads where packet rate, connection volume, infrastructure cost, and
operational simplicity matter more than Layer 7 features. Common deployments include OpenRTB and
other latency-sensitive APIs, game infrastructure, and high-throughput TCP services.

## Supported product scope

| Area | Current behavior |
| --- | --- |
| Network protocol | IPv4/TCP |
| Forwarding mode | Bidirectional NAT |
| Backend selection | Round robin for new connections; existing connections remain pinned |
| Backend discovery | Static IPv4 addresses or Kubernetes EndpointSlices |
| XDP attachment | Native driver mode when available; generic/SKB fallback |
| Deployment | Linux hosts, virtual machines, and Kubernetes |
| Operations | Embedded admin console, health/readiness API, and OpenTelemetry metrics |
| Application traffic | Passed through without TLS termination or HTTP inspection |

UDP, IPv6 balancing, DSR, TLS termination, and Layer 7 routing are not currently implemented.
Unrelated traffic is passed to the host network stack.

## Why the packet path is different

A traditional reverse proxy accepts the client TCP connection, opens another connection to a
backend, and copies data between the two. XLB instead creates a pair of kernel-resident rewrite
recipes for each accepted connection and forwards packets directly between the client and selected
backend.

This removes proxy-owned sockets and userspace packet copies from the load-balancing path. Actual
capacity still depends on the NIC, driver, kernel, packet sizes, connection churn, and whether the
host supports native XDP. Validate production capacity with representative traffic and hardware.

[Read the architecture guide](architecture.md)

## Choose a deployment

<div class="grid cards" markdown>

-   **Kubernetes quick start**

    ---

    Deploy the supplied Helm chart on host-networked nodes. XLB discovers ready backends from the
    configured Service's EndpointSlices.

    [Start on Kubernetes](getting-started/kubernetes.md)

-   **Bare metal quick start**

    ---

    Run the supplied container on a Linux host or virtual machine using host networking and static
    backend addresses.

    [Start on bare metal](getting-started/quickstart.md)

</div>

[Compare the deployment paths](getting-started/installation.md)

## Operate XLB

- [Admin console](operations/admin-console.md): instance health, traffic, connections, backends,
  XDP attachment mode, and resource pressure.
- [Observability](operations/observability.md): OpenTelemetry metric names, labels, resource
  attributes, and alerting guidance.
- [Connections and upgrades](operations/connection-lifecycle.md): backend selection, idle cleanup,
  graceful shutdown, and deployment changes.
- [Troubleshooting](operations/troubleshooting.md): startup, attachment, routing, discovery,
  readiness, and metric failures.

## Common requirements and boundaries

- Linux kernel 5.10 or newer.
- Administrative access sufficient to load eBPF programs, attach XDP, and use host networking.
- Routable IPv4 backend addresses. Loopback backends cannot be reached through the XDP packet path.
- At least one non-loopback interface on which XDP can attach.

Native-driver XDP provides the intended fast path. XLB falls back to generic/SKB XDP when the
driver cannot attach natively and reports the selected mode in logs, the status API, and the admin
console.

## Image and release access

Your Neuronic support representative will provide the container image reference, immutable release
identifier, registry credentials when required, and the matching Helm artifact. Production
deployments should use the supplied immutable image reference.

Visit [runxlb.com](https://runxlb.com) to request an evaluation or contact your support
representative for deployment-specific guidance.
