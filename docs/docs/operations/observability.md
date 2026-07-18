# Observability

XLB samples dataplane state once per second. The embedded console consumes those local samples;
the optional OpenTelemetry exporter sends metrics to an OTLP collector at the configured export
interval.

## Configure OTLP export

```yaml
name: production-lb
otel:
  enabled: true
  endpoint: "http://opentelemetry-collector:4317"
  protocol: grpc
  export_interval_secs: 10
  headers: {}
```

Supported protocols are:

- `grpc` for OTLP/gRPC;
- `http` for OTLP over HTTP/protobuf.

XLB uses delta temporality for counters. Rate-like gauges such as Mbps and packets per second are
calculated from the one-second maintenance sample before export, so they remain directly useful when
the OTLP export interval changes. The status API separately calculates per-second connection rates
for the embedded console.

The `headers` map is part of `xlb.yaml` and, with the current Helm chart, the generated ConfigMap.
Do not place a long-lived secret there unless access to that configuration is appropriately
restricted. A nearby in-cluster collector without application-level credentials is the simplest
Kubernetes arrangement.

## Resource attributes

Every metric includes:

- `service.name`: `name` from `xlb.yaml`, or `xlb` when omitted;
- `service.version`: the XLB package version.

The Helm deployment also supplies these attributes through the Downward API:

- `service.instance.id`
- `service.namespace`
- `k8s.pod.name`
- `k8s.pod.uid`
- `k8s.namespace.name`
- `k8s.node.name`

Use `service.instance.id` or the Kubernetes Pod identity when separating individual XLB instances.

## Global metrics

| Metric | Type | Meaning |
| --- | --- | --- |
| `xlb.global.backends.available` | Gauge | Backends currently published by the provider |
| `xlb.global.connections.active` | Gauge | Active connection pairs |
| `xlb.global.connections.opened` | Counter | New connections opened |
| `xlb.global.connections.closed` | Counter | Connections closed by FIN or reset |
| `xlb.global.connections.orphaned` | Counter | Inactive connection pairs removed by timeout |
| `xlb.global.flow_pair.invariant_violations` | Counter | Missing, mismatched, or concurrently removed directional flow-pair entries observed during cleanup |

`flow_pair.invariant_violations` should normally remain zero. A nonzero delta deserves investigation,
especially when accompanied by connection failures or map pressure.

## Per-backend traffic metrics

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `xlb.ingress.mbps` | Gauge | `backend` | Client-to-backend bandwidth |
| `xlb.ingress.pps` | Gauge | `backend` | Client-to-backend packets per second |
| `xlb.ingress.flows.active` | Gauge | `backend` | Active connections for the backend |
| `xlb.ingress.flows.closed` | Counter | `backend`, `type` | Client-initiated FIN or reset closures |
| `xlb.ingress.bytes` | Counter | `backend` | Client-to-backend bytes |
| `xlb.egress.mbps` | Gauge | `backend` | Backend-to-client bandwidth |
| `xlb.egress.pps` | Gauge | `backend` | Backend-to-client packets per second |
| `xlb.egress.flows.active` | Gauge | `backend` | Active return-direction connections for the backend |
| `xlb.egress.flows.closed` | Counter | `backend`, `type` | Backend-initiated FIN or reset closures |
| `xlb.egress.bytes` | Counter | `backend` | Backend-to-client bytes |

The `type` label is `fin` for an orderly TCP close and `rst` for a reset. `ingress` and `egress`
describe traffic direction, while the closure counters identify which side initiated the close.

## Resource-pressure metrics

All utilization gauges use percentages from `0` through `100`:

| Metric | Meaning |
| --- | --- |
| `xlb.resource.cpu.host.utilization` | Host CPU pressure, including kernel and softirq work |
| `xlb.resource.cpu.process.utilization` | XLB userspace CPU against its cgroup quota or available CPU capacity |
| `xlb.resource.cpu.utilization` | Greater of host and process CPU pressure |
| `xlb.resource.network.utilization` | Busiest RX or TX direction across attached interfaces as a percentage of link capacity |
| `xlb.resource.flow_map.utilization` | Directional flow entries as a percentage of map capacity |
| `xlb.resource.utilization` | Maximum CPU, network, or flow-map pressure |

Physical NICs commonly report their speed through sysfs. Cloud and virtual interfaces often expose
byte counters but no usable link speed. Supply the documented per-interface capacity in that case:

```yaml
resources:
  network_capacity_mbps: 2000
```

This value is a denominator, not a packet-capacity estimate. XLB continues to measure live bytes
from the attached interfaces.

If a required component cannot be measured, XLB omits the combined utilization value instead of
reporting an unsafe partial percentage. The component values that remain valid are still exported.

## Recommended dashboards

At minimum, graph these groups separately:

1. **Traffic:** ingress/egress Mbps and packets per second.
2. **Connection lifecycle:** active, opened, closed, and inactive-timeout removals.
3. **Backend distribution:** active flows, traffic, and closure rates grouped by `backend`.
4. **Close quality:** client/server FIN and reset rates using direction plus `type`.
5. **Capacity:** host CPU, process CPU, network, flow map, and combined utilization.
6. **Correctness:** flow-pair invariant violations.

Rates derived by an observability backend should be applied to counters such as bytes and closure
totals. Do not apply another rate operation to XLB's `*.mbps`, `*.pps`, or console-style
`*_per_second` values.

## Alerting starting points

Tune thresholds from a representative baseline rather than treating these as universal defaults:

- sustained `xlb.resource.utilization` near the deployment's chosen capacity target;
- flow-map utilization rising without returning to baseline;
- no available backends;
- any flow-pair invariant violation;
- inactive-timeout removals increasing materially above normal;
- reset closure rate or reset share increasing for one backend;
- one backend receiving materially different connection or traffic share from its peers;
- the status endpoint reporting generic XDP when native mode is expected.

The health and readiness reasons are currently exposed through the HTTP status surface rather than
as separate OpenTelemetry metrics. Monitor `/readyz` at the orchestrator or service-discovery layer.

## Autoscaling

`xlb.resource.utilization` is designed as the simplest autoscaling input: it is the maximum of CPU,
network, and flow-map pressure for one instance. XLB does not embed a scaling target. Operators
choose the target, minimum/maximum replicas, and stabilization policy appropriate to their traffic.

Adding replicas only helps when the upstream distribution mechanism sends new flows to them. The
current flow state remains local to the instance that accepted each connection. Validate the full
metrics-adapter and traffic-redistribution path before relying on an HPA policy in production.

## Metrics not currently exported

The current release does not export backend handshake latency, application response latency,
per-core metrics, durable lifecycle events, or a fleet-aggregated console. These should remain
visibly unavailable in downstream dashboards rather than inferred from unrelated measurements.
