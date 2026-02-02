# L7 Webhook Quick Start Guide

## 30-Second Overview

The eBPF Monitor now accepts L7 (application-layer) security telemetry from external sensors via HTTP webhooks.

**Two endpoints:**
- `POST /api/l7/webhook` - Send L7 events
- `GET /api/l7/webhook/stats` - View statistics

---

## Installation

Already integrated! No additional installation needed.

```bash
# Build with L7 support
go build ./cmd/aggregator

# Run aggregator
./aggregator -addr :8081
```

---

## Quick Test

### Send a Test Webhook

```bash
curl -X POST http://localhost:8081/api/l7/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "schema_version": "1.1",
    "sent_at": "2026-01-31T17:30:00Z",
    "source": "test-sensor",
    "sequence": 1,
    "batch_id": "batch-test-001",
    "events": [
      {
        "event_type": "flow_update",
        "flow_id": "192.168.1.1:443->8.8.8.8:443",
        "flow_key": "key123",
        "observed_at": 1706708399800,
        "src_ip": "192.168.1.1",
        "dst_ip": "8.8.8.8",
        "src_port": 443,
        "dst_port": 443,
        "protocol": "tcp",
        "ip_version": 4
      }
    ]
  }'
```

### Check Statistics

```bash
curl http://localhost:8081/api/l7/webhook/stats
```

### Query L7 Events

```bash
# Get all L7 events
curl http://localhost:8081/api/events?type=l7_flow_update

# Get specific events
curl http://localhost:8081/api/events?limit=50
```

---

## Configure Sensor

Example configuration for Vaanvil sensor:

```yaml
webhooks:
  - name: ebpf-monitoring
    url: http://ebpf-aggregator:8081/api/l7/webhook
    schema_version: "1.1"
    batch_size: 100
    timeout_ms: 5000
```

---

## Response Codes

| Code | Meaning |
|------|---------|
| 200 | All events processed |
| 206 | Some events failed (check details) |
| 400 | Invalid JSON or schema |
| 409 | Duplicate batch |
| 413 | Payload too large |
| 500 | Server error |

---

## Common Tasks

### Monitor Webhook Health

```bash
# Watch statistics (every 2 seconds)
watch -n 2 'curl -s http://localhost:8081/api/l7/webhook/stats | jq .'
```

### Export Events to File

```bash
curl http://localhost:8081/api/events > events.json
```

### Count L7 Events

```bash
curl -s http://localhost:8081/api/events | jq '.count'
```

### Find Events by Type

```bash
curl "http://localhost:8081/api/events?type=l7_anomaly"
```

---

## Troubleshooting

### "Duplicate batch" Error (409)

- Check sensor is generating unique batch IDs
- Wait 1 hour for cache to expire
- Or disable dedup: disable `ValidateBatchID` in config

### "Payload too large" Error (413)

- Reduce batch size on sensor
- Or increase MaxPayloadSize in receiver config

### No Events Received

1. Verify aggregator is running: `curl http://localhost:8081/health`
2. Check sensor configuration points to correct URL
3. Look at webhook statistics: `curl http://localhost:8081/api/l7/webhook/stats`
4. Check aggregator logs for errors

---

## Full Webhook Payload Example

```json
{
  "schema_version": "1.1",
  "sent_at": "2026-01-31T17:30:00Z",
  "source": "vaanvil-sensor-01",
  "source_instance": "prod-dc1",
  "sequence": 42,
  "batch_id": "batch-2026-01-31-17-30-00-a1b2c3d4",
  "events": [
    {
      "event_type": "flow_update",
      "observed_at": 1706708399800,
      "flow_start_ts": 1706708340120,
      "direction": "outbound",
      "flow_id": "192.168.1.100:54321->8.8.8.8:443",
      "flow_key": "b3b2f4d8e9f0a1b2c3d4e5f6g7h8i9j0",
      "src_ip": "192.168.1.100",
      "src_port": 54321,
      "dst_ip": "8.8.8.8",
      "dst_port": 443,
      "protocol": "tcp",
      "ip_version": 4,
      "tls": {
        "sni": "google.com",
        "alpn": "h2",
        "version": "771",
        "quic": {
          "dcid": "0x01234567"
        }
      },
      "fingerprints": {
        "ja3": "e7d705a3286e19ea42f587b344ee6865",
        "ja3_features": {
          "cipher_count": 8,
          "extension_count": 12,
          "curve_count": 4
        },
        "ja4": "771,8,12,4,h2",
        "ja4_plus": "sha256=a1b2c3d4e5f6"
      },
      "certificate": {
        "leaf_sha256": "d8:6a:7f:e1",
        "issuer_cn": "CN=Google Internet Authority G3",
        "issuer_sha256": "aa:bb:cc:dd",
        "public_key_sha256": "12:34:56:78",
        "expiry_ts": 1743580800
      },
      "verdict": {
        "action": "allow",
        "rule_id": "allow-google",
        "priority": 100,
        "cert_validation_level": "standard"
      },
      "stats": {
        "bytes": 125000,
        "packets": 245,
        "duration_ms": 19680,
        "extraction_latency_ms": 2.5,
        "sensor_latency_ms": 2.5,
        "ingest_latency_ms": 200
      }
    }
  ]
}
```

---

## Configuration Reference

### ReceiverConfig Options

```go
type ReceiverConfig struct {
    // Max payload size (bytes)
    MaxPayloadSize int64  // Default: 10MB

    // Request timeout
    RequestTimeout time.Duration  // Default: 30s

    // Enable batch deduplication
    ValidateBatchID bool  // Default: true
}
```

### Example Configuration

```go
// In cmd/aggregator/main.go
l7Receiver := l7.NewReceiver(agg.GetStorage(), &l7.ReceiverConfig{
    MaxPayloadSize:  50 * 1024 * 1024,  // 50MB
    RequestTimeout:  60 * time.Second,   // 1 minute
    ValidateBatchID: true,               // Enable dedup
})
```

---

## Files & Directories

- `internal/l7/webhook.go` - Core types and L7Event
- `internal/l7/receiver.go` - HTTP handler
- `internal/l7/webhook_test.go` - Test suite (14 tests)
- `docs/L7_WEBHOOK_INTEGRATION.md` - Complete guide
- `L7_WEBHOOK_IMPLEMENTATION_SUMMARY.md` - Implementation details

---

## More Information

- Complete Guide: [docs/L7_WEBHOOK_INTEGRATION.md](docs/L7_WEBHOOK_INTEGRATION.md)
- Implementation Details: [L7_WEBHOOK_IMPLEMENTATION_SUMMARY.md](L7_WEBHOOK_IMPLEMENTATION_SUMMARY.md)
- Main Documentation: [CLAUDE.md](CLAUDE.md)

---

**Status:** ✅ Production Ready
**Version:** 1.0.0
**License:** MIT
