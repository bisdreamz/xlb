# Troubleshooting

Start with the XLB logs and status API. Most failures belong to one of four boundaries: host/XDP
attachment, backend routing, provider discovery, or deployment configuration.

## Collect the current state

### Docker

```bash
docker logs --tail 200 xlb
curl --fail-with-body http://127.0.0.1:9090/healthz
curl --fail-with-body http://127.0.0.1:9090/readyz
curl --silent http://127.0.0.1:9090/api/v1/status
```

If admin authentication is enabled, pass credentials only to the status request using your normal
secret-handling procedure. Do not paste them into a support bundle.

### Kubernetes

```bash
kubectl get deployment,pods,service -n xlb -o wide
kubectl logs deployment/xlb -n xlb --tail=200
kubectl describe pod -n xlb -l app.kubernetes.io/name=xlb
kubectl get endpointslices -n <backend-namespace> \
  -l kubernetes.io/service-name=<backend-service> -o yaml
```

The chart defaults to a loopback admin listener. Use a temporary port-forward when you need the
complete snapshot:

```bash
kubectl port-forward -n xlb deployment/xlb 9090:9090
```

## XDP did not attach

Relevant messages include:

```text
Native XDP attach failed for ...; retrying in SKB mode
XDP attached successfully: interface=... mode=Generic
XDP ATTACH FAILED for ...
```

`Generic` is a working compatibility mode, not the native fast path. If no expected interface
appears in `dataplane.xdp_attachments`, treat the deployment as failed even if the process remains
running.

Check:

```bash
uname -r
ip -details link show
ip -4 route show default
ethtool -i <interface>
```

Common causes are missing privileges, an unsupported driver/kernel combination, a device already
owned by an incompatible XDP program, or running without host networking.

In Kubernetes, confirm the Pod has the chart's privileged security context and the `/sys/fs/bpf`
and `/sys/kernel/debug` host mounts. Admission policies may reject or silently mutate these settings.

## Health is up but readiness is down

Read the plain-text `/readyz` reason or the `readiness.reason` status field:

| Reason | Check |
| --- | --- |
| `starting` | Wait for initial provider sync and process startup |
| `awaiting_dataplane_sample` | Maintenance loop has not published its first sample |
| `dataplane_sample_stale` | Maintenance loop is stalled or overloaded |
| `backend_provider_unhealthy` | Kubernetes watcher ended or provider task failed |
| `no_routable_backends` | Discovery returned no eligible backend, or every route/neighbor lookup failed |
| `shutting_down` | The instance received a termination signal |

Health intentionally remains live during normal startup and orderly shutdown. Readiness is the
traffic-admission signal.

## Backends are not discovered

For static configuration:

- at least one backend is required;
- every backend must be IPv4;
- names may be descriptive, but addresses must be unique and routable;
- configuration changes require a process restart.

For Kubernetes:

- the configured Service must exist in the configured namespace;
- the XLB ServiceAccount needs `get` on that Service;
- it needs `get`, `list`, and `watch` on EndpointSlices in the backend namespace;
- EndpointSlices must carry `kubernetes.io/service-name=<service>`;
- only IPv4 addresses are considered;
- endpoints must be ready, serving, and not terminating for new connections.

XLB deliberately ignores `publishNotReadyAddresses` for eligibility. It may retain the
last-known-good set during a transient watch error while the kube runtime retries.

## A backend is discovered but not routable

XLB resolves the kernel route and next-hop neighbor for each backend. An address can be present in
discovery but unavailable for new connections when that resolution fails.

On the host, inspect:

```bash
ip route get <backend-ip>
ip neigh show to <next-hop-ip>
ping -c 1 <backend-ip>
```

Check VPC routes, security groups/firewalls, VLANs, neighbor discovery, and whether the chosen source
interface can reach the backend network. XLB logs `Skipping unreachable backend` with the route or
neighbor error.

## Clients cannot reach XLB

Confirm all of the following:

- the client uses the configured listen IPv4 address and local port;
- the packet reaches an interface with a successful XDP attachment;
- host and cloud firewalls allow the service port;
- the client is not testing through host loopback;
- the configured address is actually assigned/routed to this XLB instance;
- upstream DNS, BGP, anycast, or provider routing points at the correct node;
- return traffic for the NAT connection traverses the same XLB instance.

Unrelated destinations and ports pass to the normal host stack. A request sent to the wrong local
address can therefore appear as an ordinary host-network failure rather than an XLB connection.

## Traffic reaches only one backend

Round robin applies to new TCP connections, not individual HTTP requests. HTTP keep-alive,
connection pools, HTTP/2, and long-lived application protocols can send many requests over one
connection and therefore remain on one backend.

Test with genuinely new connections and compare per-backend opened-connection counters. Also check
that all expected backends are `available_for_new_connections` rather than merely discovered or
draining.

## Resource pressure is unavailable

The combined resource value requires valid CPU, network-capacity, and complete flow-map samples.

For a virtual NIC that does not report link speed, configure the provider's documented
per-interface capacity:

```yaml
resources:
  network_capacity_mbps: 2000
```

Do not estimate capacity from current traffic. A partial flow-map iteration suppresses the map and
combined value for that interval; logs identify this condition.

## OpenTelemetry is not exporting

Check:

- `otel.enabled` is `true`;
- the endpoint and protocol match the collector receiver;
- DNS and routing work from the XLB network namespace;
- configured headers are valid for gRPC metadata or HTTP;
- the collector accepts delta-temporality metrics;
- the export interval is appropriate.

XLB initializes the exporter during startup. Invalid exporter configuration can prevent startup
rather than silently disabling metrics.

## Admin authentication fails

When `admin.auth` is present:

- `XLB_ADMIN_PASSWORD` must exist and be non-empty;
- the username must be non-empty and cannot contain `:`;
- the Kubernetes Secret name and key must match Helm values;
- `/healthz` and `/readyz` intentionally do not request credentials;
- browsers cache Basic auth credentials for the current session, so test logout behavior in a new
  private window.

HTTP Basic auth does not provide encryption. Verify the deployment-layer TLS, VPN, or tunnel when
the listener is not loopback-only.

## Prepare a support bundle

Collect the following after removing secrets and customer data:

- XLB release and image digest;
- redacted `xlb.yaml` or Helm values;
- XLB logs covering startup and the failure;
- `/api/v1/status` output;
- `uname -a`;
- `ip -details link show`;
- IPv4 routes and relevant neighbor entries;
- Kubernetes Pod, Service, and EndpointSlice descriptions when applicable;
- the expected and actual traffic topology.

Use `RUST_LOG=debug` for a short diagnostic window when requested. Restore `info` afterward so log
processing does not become part of the dataplane performance test.
