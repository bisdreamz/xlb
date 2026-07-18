# Choose a deployment

XLB supports two deployment paths. Choose the guide for the environment where packets will enter
the load balancer; Kubernetes and bare-metal host preparation are intentionally documented
separately.

## Kubernetes

Use the supplied Helm chart. It configures the host networking, privileged access, BPF filesystem
mounts, health probes, and EndpointSlice RBAC that XLB needs.

The two essential placement settings are:

- `hostNetwork: true`, so XLB can attach to the node's real network interface; and
- required Pod anti-affinity, so at most one XLB Pod from the release runs on each node.

Do not remove either setting. Select enough eligible nodes for the requested replica count, then
let the chart discover ready, serving, non-terminating endpoints from the configured backend
Service.

[Start on Kubernetes](kubernetes.md)

## Bare metal, virtual machines, or Docker

Use the container with host networking and prepare the Linux host explicitly. This path requires a
non-loopback interface, routes to the backends, and sufficient privileges to load eBPF and attach
XDP.

[Start on bare metal](quickstart.md)

## Common requirements

Both deployment paths require:

- Linux kernel 5.10 or newer;
- IPv4 connectivity from the XLB node or host to every backend;
- administrative access sufficient to load eBPF and attach XDP; and
- enough CPU, memory, and NIC capacity for the intended traffic profile.

Native XDP support is recommended. XLB automatically falls back to generic/SKB XDP when native
attachment is unavailable, but the two modes have different performance characteristics.

## Obtain the release artifacts

Your Neuronic support representative will provide the image details, registry access when required,
matching Helm chart for Kubernetes, and release-specific notes. Each deployment guide explains how
to supply those artifacts without embedding registry credentials in XLB configuration.

## Next steps

- [Kubernetes quick start](kubernetes.md)
- [Bare-metal quick start](quickstart.md)
- [Configuration overview](../configuration/index.md)
- [Understand the packet path](../architecture.md)
- [Open the admin console](../operations/admin-console.md)
- [Troubleshoot startup](../operations/troubleshooting.md)
