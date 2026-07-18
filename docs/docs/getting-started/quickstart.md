# Bare metal and Docker

This guide runs one XLB instance with two static backend servers using the support-provided image.

This host-preparation path applies to dedicated Linux hosts and virtual machines. For Kubernetes,
use the [Kubernetes deployment guide](../deployment/kubernetes.md); the Helm chart configures the
required host access and placement.

## Obtain the image

Record the image reference supplied for your deployment:

```bash
export XLB_IMAGE='<image reference supplied by Neuronic>'
docker pull "$XLB_IMAGE"
docker image inspect "$XLB_IMAGE" --format '{{json .RepoDigests}}'
```

The resolved digest should match the release information you received. Authenticate to a private
registry with the supplied customer credential, preferably through your normal secret manager,
rather than placing credentials in configuration or shell history.

## Host requirements

Confirm the default route before starting XLB:

```bash
ip -4 route show default
```

With `listen: auto`, XLB selects the primary IPv4 address and interface associated with the default
route. Configure an explicit listen address when that is not the interface on which client traffic
arrives:

```yaml
listen:
  ip: "192.0.2.10"
```

Identify the network driver when validating native XDP support:

```bash
ethtool -i <interface>
```

The driver name alone does not guarantee native support for every kernel, NIC firmware, virtual
machine type, or offload configuration. Confirm the actual `mode=Native` startup message or inspect
the admin console after launch.

## Topology

Use three network-reachable machines or virtual machines:

```text
client          XLB host             backends
192.0.2.20  ->  192.0.2.10:80  ->   10.0.1.10:8080
                                      10.0.1.11:8080
```

The client must reach the XLB host through a real network interface. Backends must not use
`127.0.0.1`; loopback traffic does not traverse the XDP hook.

## 1. Confirm the backends

Start the same test service on both backend hosts at port `8080`. Confirm the XLB host can route to
each backend:

```bash
ip route get 10.0.1.10
ip route get 10.0.1.11
```

If neighbor discovery is required on the local network, generate traffic to each backend before
starting XLB. XLB also performs route and neighbor resolution while publishing backends and skips
an address it cannot currently reach.

## 2. Create the configuration

Create `xlb.yaml` on the XLB host:

```yaml
name: evaluation-lb
listen: auto
proto: tcp
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
mode: nat
orphan_ttl_secs: 300
shutdown_timeout: 15
admin:
  address: 127.0.0.1
  port: 9090
```

## 3. Start XLB

```bash
docker run --name xlb \
  --privileged \
  --network=host \
  --stop-timeout 30 \
  --mount type=bind,source="$(pwd)/xlb.yaml",target=/app/xlb.yaml,readonly \
  "$XLB_IMAGE"
```

Look for the actual attachment and startup messages:

```text
XDP attached successfully: interface=eth0 mode=Native
Admin HTTP server listening on http://127.0.0.1:9090 (UI: /admin/)
Started XLB service (evaluation-lb) on eth0 (...)
```

The interface name, address, and attachment mode depend on the host. `mode=Generic` means XLB used
the compatibility XDP path rather than native driver mode.

## 4. Verify health and readiness

From the XLB host:

```bash
curl --fail http://127.0.0.1:9090/healthz
curl --fail http://127.0.0.1:9090/readyz
```

The endpoints return plain-text state. Readiness becomes `200` after the maintenance loop publishes
a fresh sample and at least one backend has a usable route.

Open the instance console through a local tunnel or browser running on the host:

```text
http://127.0.0.1:9090/admin/
```

## 5. Send test traffic

From the separate client machine, send traffic to the XLB host's IPv4 address:

```bash
curl http://192.0.2.10/
```

Repeat the request with new TCP connections and confirm both backends receive traffic. Backend
selection occurs once per connection, so multiple requests on one HTTP keep-alive connection remain
on the same backend.

The console should show:

- two discovered and routable backends;
- new and active connections;
- ingress and egress packet/traffic rates;
- the XDP attachment mode;
- CPU, network, and flow-map utilization when their capacities are measurable.

## Add another service port

XLB supports between one and eight mappings. For example:

```yaml
ports:
  - local_port: 80
    remote_port: 8080
  - local_port: 443
    remote_port: 8443
```

XLB forwards TCP bytes without terminating TLS. Backends listening on `8443` remain responsible for
the TLS handshake and certificates.

## Enable diagnostic logs

Recreate the container with `RUST_LOG=debug`:

```bash
docker stop xlb
docker rm xlb

docker run --name xlb \
  --privileged \
  --network=host \
  --stop-timeout 30 \
  --env RUST_LOG=debug \
  --mount type=bind,source="$(pwd)/xlb.yaml",target=/app/xlb.yaml,readonly \
  "$XLB_IMAGE"
```

Debug mode adds once-per-second maintenance summaries and provider detail. Avoid leaving verbose
logging enabled during a production performance test unless it is needed for diagnosis.

## Stop cleanly

```bash
docker stop xlb
```

XLB marks itself unready, stops backend discovery, enables its shutdown behavior, and remains
attached for `shutdown_timeout`. Matching connection traffic that reaches XLB during that window
receives a TCP reset. Idle connections do not receive a proactive packet.

The Docker stop timeout must always be longer than the configured XLB shutdown timeout.

## Next steps

- [Configuration overview](../configuration/index.md)
- [Admin console](../operations/admin-console.md)
- [Observability](../operations/observability.md)
- [Connections and upgrades](../operations/connection-lifecycle.md)
- [Troubleshooting](../operations/troubleshooting.md)
