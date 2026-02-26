# Kubernetes Deployment

In Kubernetes mode the tool splits into two components:

- **Agent** (`ebpf-server`) — runs as a DaemonSet, one pod per node. Loads eBPF programs and ships events to the aggregator.
- **Aggregator** (`ebpf-aggregator`) — runs as a Deployment. Receives events from all agents, enriches them with K8s metadata, and exposes a unified query API on port 8081.

```
Node A: [Agent] ──┐
Node B: [Agent] ──┼──► [Aggregator :8081] ──► you query here
Node C: [Agent] ──┘
```

---

## Quick start

**Build images:**

```bash
make docker-build
# Builds: ebpf-monitor:latest  and  ebpf-aggregator:latest
```

**Deploy to an existing cluster:**

```bash
make k8s-deploy
# Applies all manifests under kubernetes/
```

Or step by step:

```bash
kubectl apply -f kubernetes/namespace.yaml
kubectl apply -f kubernetes/rbac.yaml
kubectl apply -f kubernetes/configmap.yaml
kubectl apply -f kubernetes/services.yaml
kubectl apply -f kubernetes/aggregator-deployment.yaml
kubectl apply -f kubernetes/daemonset.yaml
```

**Verify:**

```bash
kubectl get pods -n ebpf-system
# NAME                              READY   STATUS    RESTARTS
# ebpf-aggregator-xxx-yyy           1/1     Running   0
# ebpf-monitor-<node1>              1/1     Running   0
# ebpf-monitor-<node2>              1/1     Running   0

kubectl logs -n ebpf-system daemonset/ebpf-monitor
```

---

## Local testing with Kind

```bash
make kind-cluster-create    # create a local Kind cluster
make kind-deploy            # build images and deploy
make kind-full-test         # run integration tests
```

---

## Querying in K8s mode

Query the aggregator (port 8081):

```bash
# Port-forward from local machine
kubectl port-forward -n ebpf-system svc/ebpf-aggregator 8081:8081

# Then query as usual
curl "http://localhost:8081/api/events?type=connection&limit=20"
```

### Kubernetes-specific filters

```bash
# Events from a specific node
curl "http://localhost:8081/api/events?k8s_node_name=worker-1"

# Events from a specific pod
curl "http://localhost:8081/api/events?k8s_pod_name=my-app-7d9f8b-xkz2p"

# Events from a namespace
curl "http://localhost:8081/api/events?k8s_namespace=production"

# Combine: connections from production namespace in last 5 min
curl "http://localhost:8081/api/events?type=connection&k8s_namespace=production&since=$(date -u -d '5 minutes ago' +%Y-%m-%dT%H:%M:%SZ)"
```

### Aggregator-only endpoints

```bash
# Cluster-wide statistics
curl http://localhost:8081/api/stats

# Ingest endpoint (used internally by agents, not for external use)
POST http://localhost:8081/api/events/ingest
```

### Swagger UI

```
http://localhost:8081/swagger/
```

---

## Configuration

**ConfigMap** (`kubernetes/configmap.yaml`):

```yaml
data:
  config.yaml: |
    server:
      port: 7070
      debug: false
    aggregator:
      url: "http://ebpf-aggregator.ebpf-system.svc.cluster.local:8081"
      timeout: "30s"
      retry_attempts: 3
    kubernetes:
      enabled: true
      metadata:
        include_node_name: true
        include_pod_name: true
        include_namespace: true
```

**Key environment variables** (set in the DaemonSet/Deployment manifests):

| Variable | Description |
|----------|-------------|
| `NODE_NAME` | Auto-injected from `spec.nodeName` |
| `POD_NAME` | Auto-injected from `metadata.name` |
| `POD_NAMESPACE` | Auto-injected from `metadata.namespace` |
| `AGGREGATOR_URL` | Override aggregator service URL |
| `EBPF_LOG_LEVEL` | `debug`, `info`, `warn`, `error` |

---

## Resource requirements

The DaemonSet agent is configured with:

| | Request | Limit |
|---|---------|-------|
| Memory | 128Mi | 512Mi |
| CPU | 100m | 500m |

Adjust in `kubernetes/daemonset.yaml` if needed.

---

## Permissions

The agent requires privileged mode to load eBPF programs:

```yaml
securityContext:
  privileged: true
```

It also mounts:
- `/proc` — for boot time and process info
- `/sys/kernel/debug` — for eBPF tracepoint access

The RBAC in `kubernetes/rbac.yaml` grants the agent service account only the permissions it needs to read pod/node metadata.

---

## Push to a private registry

```bash
make docker-push REGISTRY=registry.example.com TAG=v1.2.0
```

Then update the image references in `kubernetes/daemonset.yaml` and `kubernetes/aggregator-deployment.yaml`.

---

## Cleanup

```bash
kubectl delete namespace ebpf-system
```
