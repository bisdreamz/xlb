# Quick Start

Get XLB running with Docker and real backend servers.

## Important: XDP Limitations

**XLB cannot route to localhost (127.0.0.1).** XDP operates at the network driver level and cannot route packets to the loopback interface. Backends must be on different hosts accessible via your network interfaces.

## Prerequisites

- Docker installed
- Backend services running on separate hosts
- Linux kernel 5.10+ on the XLB host

## Create Configuration

Create `xlb.yaml` with your real backend IPs:

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
```

**Note:** Backend IPs must be on different hosts, not localhost.

## Run XLB

```bash
docker run --privileged --network=host --stop-timeout 20 \
  --mount type=bind,source="$(pwd)/xlb.yaml",target=/app/xlb.yaml,readonly \
  emaczura/xlb:0.1.0
```

Expected output:
```
INFO xlb: Config XlbConfig { ... }
INFO xlb: Loading eBPF program on interface eth0
INFO xlb::provider: Backend backend-1 (10.0.1.10) ready: ifindex=2
INFO xlb::provider: Backend backend-2 (10.0.1.11) ready: ifindex=2
INFO xlb: XLB started successfully
```

## Test Load Balancer

From a client machine (not the XLB host):

```bash
curl http://<xlb-host-ip>
```

Traffic will be distributed across your backends.

## Enable Debug Logging

```bash
docker run --privileged --network=host --stop-timeout 20 \
  -e RUST_LOG=debug \
  --mount type=bind,source="$(pwd)/xlb.yaml",target=/app/xlb.yaml,readonly \
  emaczura/xlb:0.1.0
```

In debug mode, XLB prints per-direction packet rate, throughput, active-flow, and closure counters
to stdout every second.

## Multiple Ports

Load balance HTTP and HTTPS:

```yaml
proto: tcp
listen: auto
ports:
  - local_port: 80
    remote_port: 8080
  - local_port: 443
    remote_port: 8443
provider:
  static:
    backends:
      - name: backend-1
        ip: 10.0.1.10
      - name: backend-2
        ip: 10.0.1.11
```

## Graceful Shutdown

Stop the container:

```bash
docker stop <container-id>
```

XLB will:
1. Set SHUTDOWN flag in eBPF
2. Reactively reset matching TCP packets that arrive during shutdown
3. Wait for `shutdown_timeout` (default 15s)
4. Exit cleanly before Docker's 20-second stop timeout

The `--stop-timeout` passed to `docker run` must always be greater than `shutdown_timeout`.
Docker otherwise sends `SIGKILL` before XLB finishes its shutdown grace period.

Idle connections that send no packet during the timeout do not receive a proactive reset.

## Next Steps

- [Kubernetes Deployment](../deployment/kubernetes.md) - Deploy with Helm for production
- [Configuration Overview](../configuration/index.md) - All config options
- [Configuration Reference](../configuration/reference.md) - Full schema

## Troubleshooting

### XDP Not Attaching

```
ERROR: Failed to attach XDP program
```

**Solutions:**
- Check kernel version: `uname -r` (need 5.10+)
- Verify driver supports XDP: `ethtool -i eth0`
- Ensure `--privileged` and `--network=host` flags are set

### No Traffic Flowing

**Common cause:** Backends on localhost won't work. Backends must be on different hosts accessible via network interfaces.

Check XDP attachment:
```bash
ip link show | grep xdp
```

Enable debug logging:
```bash
docker run --privileged --network=host --stop-timeout 20 \
  -e RUST_LOG=trace \
  --mount type=bind,source="$(pwd)/xlb.yaml",target=/app/xlb.yaml,readonly \
  emaczura/xlb:0.1.0
```
