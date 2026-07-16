# Installation

## Prerequisites

- Linux kernel 5.10+
- XDP-capable network driver (i40e, ixgbe, mlx5, virtio_net)

## Kubernetes

**Coming Soon** - Helm chart distribution in progress.

Contact emaczura@neuronic.dev for early access.

## Docker

```bash
docker run --privileged --network=host --stop-timeout 20 \
  --mount type=bind,source="$(pwd)/xlb.yaml",target=/app/xlb.yaml,readonly \
  emaczura/xlb:0.1.0
```

**Required flags:**
- `--privileged` - eBPF/XDP requires privileged access
- `--network=host` - XDP requires direct network interface access
- `--stop-timeout` - Must exceed the configured `shutdown_timeout` so XLB can drain cleanly
- `--mount` - Supplies the required deployment-specific configuration; it is not baked into the image

## Configuration

Create `xlb.yaml`:

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
```

See [Configuration Overview](../configuration/overview.md) for all options.

## Next Steps

- [Quick Start Guide](quickstart.md)
- [Kubernetes Deployment](../deployment/kubernetes.md)
