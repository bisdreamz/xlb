# XLB Helm chart

This chart deploys the XLB XDP-native IPv4/TCP Layer 4 load balancer on Kubernetes.

Your Neuronic support representative will provide the matching image repository, immutable digest,
registry access when required, chart artifact, and release notes. Do not combine chart and image
versions from different releases.

## Install

Create a values file that supplies at least the release image, backend Service, port mapping, and
chosen exposure model:

```yaml
image:
  repository: "<provided repository>"
  digest: "<provided immutable digest>"

config:
  ports:
    - local_port: 80
      remote_port: 8080
  provider:
    kubernetes:
      namespace: application
      service: backend-service

service:
  type: ClusterIP

externalDNS:
  enabled: false
```

```bash
helm upgrade --install xlb ./helm/xlb \
  --namespace xlb \
  --create-namespace \
  --values xlb-values.yaml
```

Use `imagePullSecrets` for private-registry credentials. Never store the pull credential directly in
the values file.

## Deployment requirements

- Kubernetes 1.26 or newer.
- Linux nodes with kernel 5.10 or newer.
- Privileged Pods, host networking, and BPF/debug filesystem host mounts.
- One eligible node per replica under the default required anti-affinity.
- IPv4 EndpointSlices for the configured backend Service.

The chart uses `hostNetwork: true` and Deployment strategy `Recreate`. An upgrade is not a
zero-downtime rolling replacement. Coordinate external traffic before changing a production
release.

`service.type: LoadBalancer` can provision a cloud-managed load balancer in front of XLB. Use
`ClusterIP` plus direct node DNS/routing when the goal is to replace that managed layer.

## Health and administration

- `/healthz` reports process liveness.
- `/readyz` requires a fresh dataplane sample, healthy provider task, and routable backend.
- `/api/v1/status` provides the versioned local-instance snapshot.
- `/admin/` serves the embedded local-instance console.
- The listener defaults to `127.0.0.1:9090`.

Optional Basic auth protects the console and status API while leaving probes open. The chart reads
the password from an existing Secret and injects it as `XLB_ADMIN_PASSWORD`; it does not place the
password in the ConfigMap. Add TLS or another secure transport before exposing the HTTP listener
outside a trusted network.

## Metrics

XLB can export OTLP metrics to a separately deployed collector. Set
`config.resources.network_capacity_mbps` when a cloud or virtual NIC does not report usable link
speed and the provider documents a deterministic per-interface limit.

## Documentation

See [docs.runxlb.com](https://docs.runxlb.com) for installation, Kubernetes topology, complete Helm
values, configuration, metrics, admin access, connection lifecycle, upgrades, and troubleshooting.
