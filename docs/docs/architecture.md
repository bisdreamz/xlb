# Architecture

XLB is a stateful Layer 4 packet forwarder. It runs a small control and maintenance process in
userspace while the traffic path executes in an eBPF program attached at XDP.

## Packet path

XLB handles application traffic in the kernel. It chooses a backend when a TCP connection begins,
keeps that connection pinned to the same backend, and rewrites packets in both directions. Later
packets use the connection state already stored in XDP, without returning to userspace for routing
decisions or packet copies.

```text
client              XLB host                         backend
  |   VIP:443 SYN       |                               |
  |-------------------->| select backend + create pair  |
  |                     |------------------------------>|
  |                     |<------------------------------|
  |<--------------------| rewrite return packet          |
```

The client sees one TCP connection to the XLB address. XLB does not accept it in a userspace socket
or create a second proxy-owned connection to the backend.

## Flow identity and affinity

An IPv4/TCP flow is identified by the complete source address, destination address, source port,
destination port, protocol, and direction. This permits concurrent connections across clients,
service ports, and client source ports without reducing identity to an application-level hash.

Each accepted connection is pinned to its selected backend for the life of the flow. Changes to the
discovered backend set affect only new connections. A retransmitted client SYN reuses the existing
nonterminal mapping instead of selecting another backend.

## NAT behavior

XLB currently implements bidirectional NAT. It rewrites the packet addresses, ports, Ethernet
addresses, and checksums needed for both directions. The return direction must traverse the same
XLB instance that owns the connection state.

This has several deployment consequences:

- Backends must be routable from the XLB host.
- Loopback backends are not valid; XDP does not use the loopback packet path.
- Upstream traffic distribution must keep both directions of a connection on the same instance.
- DSR is not currently available.

## Control plane and maintenance

The userspace process performs work that does not belong in the per-packet path:

- loads and attaches the eBPF program;
- discovers static or Kubernetes backends;
- resolves backend routes and neighbors;
- publishes routable backends to the eBPF map;
- samples flow counters once per second;
- expires closed and inactive flow pairs;
- exports OpenTelemetry metrics;
- serves health, readiness, status, and the embedded admin console.

The control plane does not copy application packets. A failed maintenance loop, admin server, or
backend-provider task is treated as a process-level failure so the deployment supervisor can
restart XLB.

## XDP attachment modes

XLB attempts native driver-mode XDP first on eligible host interfaces. When a driver rejects native
attachment, XLB retries that interface in generic/SKB mode. Startup logs and the status API report
the actual mode for every successful attachment.

Native mode is the intended high-performance path. Generic mode preserves compatibility but moves
the hook later in the kernel receive path and should be benchmarked separately.

XLB passes unrelated Ethernet, IPv6, and non-TCP traffic to the host stack. IPv4 fragments and
packets with IPv4 options are not load balanced.

## Multiple XLB instances

Every XLB instance owns an independent backend view, flow map, metrics stream, and admin console.
Instances do not replicate connection state or aggregate their local consoles.

High availability therefore requires an upstream distribution mechanism such as direct DNS records,
provider routing, BGP/anycast, or another environment-specific ingress design. A Kubernetes
`Service` of type `LoadBalancer` can also distribute traffic, but it retains the managed
load-balancer layer and its associated behavior and cost.

OpenTelemetry is the supported path for durable, fleet-wide aggregation. The embedded console is
deliberately scoped to the XLB instance serving the page.

## Current boundaries

| Capability | Status |
| --- | --- |
| IPv4/TCP | Supported |
| UDP | Rejected at startup |
| IPv6 load balancing | Rejected or ignored during discovery |
| NAT | Supported |
| DSR | Rejected at startup |
| TLS termination | Not part of XLB |
| HTTP routing or header inspection | Not part of XLB |
| Cross-instance connection-state replication | Not implemented |
| Proactive backend health checks | Not implemented; Kubernetes readiness or operator-managed static lists supply eligibility |

For HTTP routing, authentication, TLS termination, or caching, place the appropriate application or
Layer 7 proxy behind XLB.
