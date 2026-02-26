# Querying the API

All API endpoints are served at `http://localhost:7070` by default. The examples below show common query patterns and filtering options.

> **Authentication Required:** All API endpoints (except `/health` and login) require a Bearer token in the `Authorization` header. See [Authentication](authentication.md) for how to login and get tokens.

---

## Health Check

Verify the server is running and healthy:

```bash
curl http://localhost:7070/health
```

**Response:**
```json
{"status":"healthy","component":"eBPF Monitor API","uptime":"active","version":"1.0.0"}
```

---

## Unified Events Endpoint

`GET /api/events` is the primary API for querying captured events. Supports filtering by type, process, timestamp, and more.

### Get All Recent Events

First, [get an authentication token](authentication.md#step-1-login-and-get-token), then:

```bash
TOKEN="your_access_token_here"

curl "http://localhost:7070/api/events" \
  -H "Authorization: Bearer $TOKEN"
```

### Filter by Event Type

```bash
# Only connection events
curl "http://localhost:7070/api/events?type=connection"

# Only packet drop events
curl "http://localhost:7070/api/events?type=packet_drop"
```

### Filter by Process

```bash
# By PID
curl "http://localhost:7070/api/events?pid=54701"

# By command name
curl "http://localhost:7070/api/events?command=curl"

# Both
curl "http://localhost:7070/api/events?command=nginx&type=connection"
```

### Filter by Time Range

Use RFC3339 timestamps for precise time-based filtering:

```bash
# Events in the last hour
curl "http://localhost:7070/api/events?since=$(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)"

# Events between two times
curl "http://localhost:7070/api/events?since=2024-01-15T10:00:00Z&until=2024-01-15T11:00:00Z"
```

### Limit Results

```bash
curl "http://localhost:7070/api/events?limit=10"
```

### Combine Multiple Filters

```bash
curl "http://localhost:7070/api/events?type=connection&command=python3&since=2024-01-15T00:00:00Z&limit=50"
```

### Response Structure

```json
{
  "events": [ ... ],
  "count": 25,
  "total_count": 150,
  "query_time": "2024-01-15T12:00:00Z",
  "filters": {
    "type": "connection",
    "command": "python3",
    "since": "2024-01-15T00:00:00Z",
    "limit": 50
  }
}
```

---

## Connection Summary Endpoint

Get event counts without full event details (lightweight queries):

```bash
# All connections in the last 60 seconds
curl "http://localhost:7070/api/connection-summary?duration_seconds=60"

# Connections by a specific process
curl "http://localhost:7070/api/connection-summary?command=nginx&duration_seconds=300"

# By PID
curl "http://localhost:7070/api/connection-summary?pid=1234&duration_seconds=60"
```

POST form is also supported:

```bash
curl -X POST http://localhost:7070/api/connection-summary \
  -H "Content-Type: application/json" \
  -d '{"command":"curl","duration_seconds":60}'
```

Response:

```json
{"count":5,"pid":0,"command":"curl","duration_seconds":60,"query_time":"2024-01-15T12:00:00Z"}
```

---

## Packet Drop Summary Endpoint

```bash
curl "http://localhost:7070/api/packet-drop-summary?duration_seconds=60"

curl "http://localhost:7070/api/packet-drop-summary?pid=0&duration_seconds=300"
```

---

## List Connections Grouped by PID

```bash
curl http://localhost:7070/api/list-connections
```

```json
{
  "total_pids": 3,
  "total_events": 42,
  "events_by_pid": {
    "1234": [ ... ],
    "5678": [ ... ]
  }
}
```

---

## List Packet Drops Grouped by PID

```bash
curl http://localhost:7070/api/list-packet-drops
```

---

## Check Loaded eBPF Programs

```bash
curl http://localhost:7070/api/programs
```

```json
{
  "programs": [
    {"name":"connection","type":"eBPF","status":"active","id":12345},
    {"name":"packet_drop","type":"eBPF","status":"active","id":67890}
  ],
  "total_count": 2
}
```

---

## Useful One-Liners

Common shell recipes for monitoring tasks (includes authentication):

**Watch live connections (refresh every second):**

```bash
#!/bin/bash
TOKEN=$(curl -s -X POST http://localhost:7070/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}' | jq -r '.access_token')

watch -n 1 "curl -s 'http://localhost:7070/api/events?type=connection&limit=20' \
  -H 'Authorization: Bearer $TOKEN' | \
  jq -r '.events[] | [.command, .metadata.dest_ip, .metadata.dest_port] | @tsv'"
```

**Count connections per command in the last 5 minutes:**

```bash
TOKEN="your_access_token"

curl -s "http://localhost:7070/api/events?type=connection&since=$(date -u -d '5 minutes ago' +%Y-%m-%dT%H:%M:%SZ)" \
  -H "Authorization: Bearer $TOKEN" | \
  jq -r '[.events[] | .command] | group_by(.) | map({cmd: .[0], count: length}) | sort_by(-.count)[]'
```

**Alert if packet drops exceed a threshold:**

```bash
TOKEN="your_access_token"

count=$(curl -s "http://localhost:7070/api/packet-drop-summary?duration_seconds=60" \
  -H "Authorization: Bearer $TOKEN" | jq .count)

[ "$count" -gt 100 ] && echo "WARNING: $count packet drops in last 60s"
```

**Find all unique destination IPs in the last hour:**

```bash
TOKEN="your_access_token"

curl -s "http://localhost:7070/api/events?type=connection&since=$(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)&limit=1000" \
  -H "Authorization: Bearer $TOKEN" | \
  jq -r '[.events[].metadata.dest_ip] | unique[]'
```

---

## Interactive API Documentation

All endpoints, parameters, and responses are fully documented in the interactive Swagger UI:

```
http://localhost:7070/docs/
```
