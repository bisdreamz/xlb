# Installation

## Prerequisites

- Linux kernel 5.10+
- XDP-capable network driver (i40e, ixgbe, mlx5, virtio_net)

## Kubernetes

**Coming Soon** - Helm chart distribution in progress.

Contact emaczura@neuronic.dev for early access.

## Docker

```bash
docker run --privileged --network=host \
  -v $(pwd)/xlb.yaml:/xlb.yaml:ro \
  emaczura/xlb:latest
```

**Required flags:**
- `--privileged` - eBPF/XDP requires privileged access
- `--network=host` - XDP requires direct network interface access

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
