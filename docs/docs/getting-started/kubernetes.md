# Kubernetes quick start

The supported Helm chart deploys XLB with the host access and Kubernetes discovery configuration
it needs. This quick start creates two XLB replicas and discovers backends from one existing
Kubernetes Service.

## Before you start

You need:

- the image and matching Helm chart supplied by your Neuronic support representative;
- an existing Service whose EndpointSlices contain ready IPv4 backends; and
- one eligible Linux node for each XLB replica.

The chart sets `hostNetwork: true` and required Pod anti-affinity. Consequently, each XLB Pod uses
the network interface of its node and no two XLB Pods in the release namespace are scheduled on the
same node. Do not disable either setting.

## 1. Prepare registry access

Skip this step when the supplied image does not require authentication. Otherwise, create the pull
Secret in the XLB namespace using the credentials provided for your deployment:

```bash
kubectl create namespace xlb

kubectl create secret docker-registry xlb-registry \
  --namespace xlb \
  --docker-server='<registry host>' \
  --docker-username='<provided username>' \
  --docker-password='<provided pull credential>'
```

Use your normal external-secret or sealed-secret workflow instead when available.

## 2. Create the values file

Create `xlb-values.yaml`:

```yaml
replicaCount: 2

image:
  repository: "<repository provided by Neuronic>"
  digest: "<immutable digest provided by Neuronic>"

imagePullSecrets:
  - name: xlb-registry

config:
  name: production-lb
  listen: auto
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

Replace `application` and `backend-service` with the namespace and name of the Service that owns
your backend EndpointSlices. Remove `imagePullSecrets` when registry authentication is not needed.

`ClusterIP` is appropriate when traffic reaches the XLB node addresses directly through DNS,
BGP/anycast, or provider routing. Choosing `LoadBalancer` can provision another managed load
balancer in front of XLB.

## 3. Install XLB

Set the chart path supplied for the release, validate the values, and install:

```bash
export XLB_CHART='<path to supplied XLB chart>'

helm lint "$XLB_CHART" -f xlb-values.yaml

helm upgrade --install xlb "$XLB_CHART" \
  --namespace xlb \
  --create-namespace \
  --values xlb-values.yaml
```

## 4. Verify the deployment

```bash
kubectl rollout status deployment/xlb -n xlb --timeout=180s
kubectl get pods -n xlb -l app.kubernetes.io/name=xlb -o wide
kubectl logs deployment/xlb -n xlb --tail=100
```

Confirm that:

- the two Pods run on different nodes;
- each Pod reports an XDP attachment in `Native` or `Generic` mode; and
- the readiness probe succeeds after at least one backend becomes routable.

Send a test connection to an XLB node address on the configured local port. Production traffic
requires an upstream design that distributes connections across the XLB node addresses while
preserving a connection's return path through the same instance.

## Next steps

- [Kubernetes deployment guide](../deployment/kubernetes.md)
- [Helm chart reference](../deployment/helm.md)
- [Admin console](../operations/admin-console.md)
- [Observability](../operations/observability.md)
- [Troubleshooting](../operations/troubleshooting.md)
