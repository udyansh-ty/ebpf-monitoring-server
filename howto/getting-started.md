# Getting Started

## Prerequisites

- Linux kernel 4.18+ with eBPF support
- Root/sudo privileges (required to load eBPF programs)
- Go 1.23+
- Clang, LLVM, libbpf-dev, kernel headers

**Install dependencies (Ubuntu/Debian):**

```bash
sudo apt update
sudo apt install -y \
    golang-go \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-$(uname -r) \
    build-essential
```

**Verify eBPF support:**

```bash
uname -r                          # should be 4.18+
ls /sys/kernel/debug/tracing/     # should exist (may need debugfs mount)
```

If `/sys/kernel/debug/tracing/` is missing:

```bash
sudo mount -t debugfs debugfs /sys/kernel/debug
```

---

## Build

```bash
# Compile eBPF C programs + build Go binaries
make build

# Outputs:
#   ./bin/ebpf-server       — the monitoring agent
#   ./bin/ebpf-aggregator   — the Kubernetes aggregator (optional)
```

For a debug build with race detection:

```bash
make build-dev
# Output: ./bin/ebpf-server-dev
```

---

## Run

```bash
sudo ./bin/ebpf-server
# Listens on :7070 by default

# Custom port
sudo ./bin/ebpf-server -addr=":7070"

# Debug logging
sudo EBPF_LOG_LEVEL=debug ./bin/ebpf-server
```

**Verify it is running:**

```bash
curl http://localhost:7070/health
# {"status":"healthy","component":"eBPF Monitor API","uptime":"active","version":"1.0.0"}
```

**Check loaded eBPF programs:**

```bash
curl http://localhost:7070/api/programs
```

---

## Quick smoke test

Open a second terminal and make a network request:

```bash
curl https://example.com
```

Then query recent connection events:

```bash
curl "http://localhost:7070/api/events?type=connection&limit=5"
```

You should see the `curl` process appear in the events list with its destination IP and port.

---

## Interactive API docs

While the server is running, open the Swagger UI in a browser:

```
http://localhost:7070/docs/
```

The OpenAPI spec is also available as JSON/YAML:

```
http://localhost:7070/docs/swagger.json
http://localhost:7070/docs/swagger.yaml
```

---

## Next steps

- [Authentication](authentication.md) — login and use JWT tokens
- [What can I see?](what-can-i-see.md) — full list of observable data
- [Querying the API](querying-api.md) — filtering and querying events
- [Kubernetes deployment](kubernetes.md) — cluster-wide monitoring
