# What Can I See?

This eBPF monitoring tool attaches kernel-space programs to Linux tracepoints and exposes captured events through an HTTP API. Two main categories of network events are monitored in real-time.

---

## 1. Network Connection Events

**How it works:** The tool hooks into the `connect()` syscall via the `syscalls/sys_enter_connect` kernel tracepoint. Every time a process attempts a network connection, an event is captured with full context.

**What each event tells you:**

| Field | Description | Example |
|-------|-------------|---------|
| `pid` | Process ID that made the connection | `12345` |
| `command` | Process name (first 16 chars) | `curl`, `nginx`, `python3` |
| `wall_time` | Wall-clock timestamp (RFC3339) | `2024-01-15T10:30:00Z` |
| `dest_ip` | Destination IPv4 address | `93.184.216.34` |
| `dest_ip6` | Destination IPv6 address | `2606:2800:220:1:248:1893:25c8:1946` |
| `dest_port` | Destination port | `443`, `80`, `5432` |
| `family` | Address family | `2` (AF_INET) or `10` (AF_INET6) |
| `protocol` | IP protocol | `6` (TCP) or `17` (UDP) |
| `sock_type` | Socket type | `1` (SOCK_STREAM) or `2` (SOCK_DGRAM) |

**What you can answer with connection events:**

- Which processes are making outbound connections right now?
- Is this service talking to unexpected IPs or ports?
- How often is `postgres` being contacted by the app?
- Is anything connecting to port 22 (SSH) or 3306 (MySQL)?
- What external services does my application depend on?

**Example event (JSON):**

```json
{
  "id": "a1b2c3d4",
  "type": "connection",
  "pid": 12345,
  "command": "curl",
  "wall_time": "2024-01-15T10:30:00Z",
  "metadata": {
    "dest_ip": "93.184.216.34",
    "dest_port": 443,
    "family": 2,
    "protocol": 6,
    "sock_type": 1
  }
}
```

---

## 2. Packet Drop Events

**How it works:** The tool monitors `skb/kfree_skb` and `tcp_drop` kernel tracepoints to detect when the kernel discards packets. Every drop event includes context about why it occurred and which process (if any) was involved.

**What each event tells you:**

| Field | Description | Example |
|-------|-------------|---------|
| `pid` | Process associated with the drop (if any) | `0` (kernel), `9876` |
| `command` | Process name | `nginx`, `(kernel)` |
| `wall_time` | Wall-clock timestamp | `2024-01-15T10:30:01Z` |
| `drop_reason` | Kernel drop reason code | `2` (NO_SOCKET), `35` (CONNTRACK) |
| `skb_len` | Size of dropped packet in bytes | `1500` |

**What you can answer with packet drop events:**

- Is my server experiencing packet loss?
- Are TCP connections being dropped by the kernel?
- Is a firewall/iptables rule silently dropping traffic?
- Is the system under network stress (high drop rate)?
- Which processes are involved in packet drops?

**Common drop reason codes:**

| Code | Meaning |
|------|---------|
| 0 | Not specified |
| 2 | No socket found |
| 9 | TCP invalid sequence |
| 35 | Netfilter/iptables drop |
| 36 | Conntrack full |

**Example event (JSON):**

```json
{
  "id": "e5f6g7h8",
  "type": "packet_drop",
  "pid": 0,
  "command": "",
  "wall_time": "2024-01-15T10:30:01Z",
  "metadata": {
    "drop_reason": 2,
    "skb_len": 60
  }
}
```

---

## Kubernetes metadata (when deployed in K8s)

In Kubernetes mode, every event is enriched with:

| Field | Description | Example |
|-------|-------------|---------|
| `k8s_node_name` | Node the event came from | `worker-1` |
| `k8s_pod_name` | Pod name | `my-app-7d9f8b-xkz2p` |
| `k8s_namespace` | Kubernetes namespace | `production` |

This lets you answer:
- Which pod is making connections to the database?
- Is the `payments` namespace dropping packets?
- Which node has the highest connection rate?

---

## Limitations

The following are **not** monitored:

- **Encrypted payload content** — Connection metadata is captured, but packet contents remain private
- **Pre-startup connections** — Only connections made after the monitor starts are tracked
- **Connectionless UDP** — Only `connect()` syscalls are captured, so bare UDP sockets (without explicit `connect()`) may not appear
- **Isolated namespaces** — Network isolation (e.g., containers with separate netns) may prevent capture unless eBPF programs are attached at the root namespace

---

## Live Monitoring Tip

Poll the events API continuously to get a near-real-time stream. First, [obtain an authentication token](authentication.md):

```bash
TOKEN=$(curl -s -X POST http://localhost:7070/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}' | jq -r '.access_token')

watch -n 1 "curl -s 'http://localhost:7070/api/events?limit=20' \
  -H 'Authorization: Bearer \$TOKEN' | jq '.events[] | {cmd: .command, ip: .metadata.dest_ip, port: .metadata.dest_port}'"
```

See [Querying the API](querying-api.md) for filtering options and [Authentication](authentication.md) for token management.
