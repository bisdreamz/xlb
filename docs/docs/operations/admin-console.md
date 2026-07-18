# Admin console and status API

Every XLB instance embeds a small operational HTTP server. It provides health and readiness probes,
a versioned JSON status snapshot, and a browser console for that one instance.

## Endpoints

| Path | Purpose | Authentication when enabled |
| --- | --- | --- |
| `/healthz` | Process and essential-task liveness | No |
| `/readyz` | Eligibility to receive new traffic | No |
| `/api/v1/status` | Versioned operational JSON | Yes |
| `/admin/` | Embedded instance console | Yes |
| `/` | Permanent redirect to `/admin/` | Yes |

The default listener is loopback-only:

```yaml
admin:
  address: 127.0.0.1
  port: 9090
```

## Health and readiness

`/healthz` answers whether the XLB process and its essential tasks remain live. Startup and orderly
shutdown are considered live states; a stale maintenance sample or terminated backend-provider task
eventually makes health fail.

`/readyz` is stricter. It returns `200` only when:

- the lifecycle is running;
- a dataplane sample has been published within the last 30 seconds;
- the backend provider task is healthy; and
- at least one backend has a usable route and can accept a new connection.

Otherwise it returns `503` and one of these stable reasons:

- `starting`
- `shutting_down`
- `awaiting_dataplane_sample`
- `dataplane_sample_stale`
- `backend_provider_unhealthy`
- `no_routable_backends`

Use readiness—not liveness—to decide whether an upstream distributor should send new traffic to an
instance.

## What the console shows

The console polls `/api/v1/status` once per second and presents:

- process lifecycle, uptime, health, and readiness;
- listen address, service ports, attached interfaces, and native/generic XDP mode;
- discovered and routable backend counts;
- active, opened, closed, and inactive-timeout connection counts;
- ingress and egress packets, bandwidth, and bytes;
- host/process CPU, network, flow-map, and combined resource pressure;
- per-backend availability, time in pool, connections, traffic, and cumulative totals;
- flow-map completeness and directional entry count.

The overview retains up to 30 minutes of one-second samples in browser memory. Per-backend charts
retain up to 15 minutes. This history is lost when the page reloads and is not shared with another
XLB instance. Use OpenTelemetry for durable or fleet-wide history.

Close-reason history, passive handshake latency, and lifecycle event history are visibly marked
`Coming soon` in the current console. XLB does not fabricate values for those views.

## Local access

Keep the default loopback listener when possible. Common access methods include an SSH tunnel:

```bash
ssh -L 9090:127.0.0.1:9090 <xlb-host>
```

or a temporary Kubernetes port-forward:

```bash
kubectl port-forward -n xlb deployment/xlb 9090:9090
```

Then open `http://127.0.0.1:9090/admin/`.

## Enable Basic authentication

To make the listener reachable outside the host, configure a non-loopback address and a username:

```yaml
admin:
  address: 0.0.0.0
  port: 9090
  auth:
    username: operator
```

Supply the password only through the `XLB_ADMIN_PASSWORD` environment variable:

```bash
export XLB_ADMIN_PASSWORD='<strong password from your secret manager>'
```

XLB fails startup when authentication is configured and the environment variable is absent or
empty. The password is intentionally excluded from normal configuration logging.

Authentication protects the console, its assets and client-side routes, the root redirect, and the
status API. Probe endpoints remain unauthenticated so container and Kubernetes health checks do not
require credentials.

## Kubernetes Secret configuration

Create a Secret without storing its value in a Helm values file:

```bash
kubectl create secret generic xlb-admin-auth \
  --namespace xlb \
  --from-literal=password='<strong password>'
```

Reference it from values:

```yaml
config:
  admin:
    address: 0.0.0.0
    port: 9090
    auth:
      enabled: true
      username: operator
      existingSecret: xlb-admin-auth
      passwordKey: password
```

The chart injects the selected Secret key as `XLB_ADMIN_PASSWORD`; it does not copy the password
into the generated ConfigMap.

## Transport security

XLB currently serves the administrative surface over HTTP. Basic authentication controls access
but does not encrypt credentials or status data. Provide TLS, a VPN, a private management network,
or an authenticated tunnel at the deployment layer before using Basic auth across an untrusted
network.

XLB logs a warning whenever an authenticated HTTP listener binds to a non-loopback address. It logs
a stronger warning when a non-loopback listener has no authentication.

## Status API compatibility

`/api/v1/status` returns `schema_version: 1` and `Cache-Control: no-store`. Consumers should:

- check `schema_version` before assuming fields;
- tolerate additional fields in compatible releases;
- use `sampled_at_unix_ms` and `sample_age_ms` to detect stale values;
- treat missing resource percentages as unavailable rather than zero;
- distinguish discovered backends from `available_for_new_connections`;
- expect a removed backend to remain visible while it still owns active flows.

The status API is intended for local operational inspection. Use the OpenTelemetry export for
long-term storage, alerting, and cross-instance aggregation.
