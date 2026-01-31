# NDPI Enrichment for Vaanvil Webhooks

## Goal
Add an NDPI enrichment middleware that classifies each Vaanvil webhook flow using NDPI-style heuristics, stores the protocol/category/application in the event metadata, and persists the NDPI results in your SQL/NoSQL backend for richer querying.

## Architecture

1. Incoming webhook -> `internal/l7/receiver.HandleWebhook`
2. Parse payload and create `WebhookEvent`
3. Convert to `L7Event` via `NewL7Event`
4. `NewL7Event` calls `enrichNDPI(metadata, webhookEvent)` before storing
5. `enrichNDPI` builds a `pkg/ndpi.FlowTuple` (src/dst IP, ports, TLS hints) and calls `ndpi.Detect`
6. NDPI result (`protocol`, `category`, `application`, `confidence`, `ndpi_id`) is stored in `metadata["ndpi"]`
7. Storage sink (SQL/NoSQL) writes the metadata map, including the `ndpi` block, so dashboards can query NDPI attributes alongside TLS certificates/fingerprints

## SQL Schema (Postgres example)

```sql
CREATE TABLE l7_webhook_events (
  id TEXT PRIMARY KEY,
  flow_id TEXT,
  flow_key TEXT,
  batch_id TEXT,
  source TEXT,
  schema_version TEXT,
  event_type TEXT,
  direction TEXT,
  observed_at TIMESTAMP,
  flow_start_ts TIMESTAMP,
  duration_ms DOUBLE PRECISION,
  src_ip INET,
  dst_ip INET,
  src_port INT,
  dst_port INT,
  protocol TEXT,
  ip_version INT,
  tls_sni TEXT,
  tls_alpn TEXT,
  tls_version TEXT,
  ja3 TEXT,
  ja4 TEXT,
  ja4_plus TEXT,
  ja3_cipher_count INT,
  ja3_extension_count INT,
  ja3_curve_count INT,
  cert_leaf_sha256 TEXT,
  cert_issuer_sha256 TEXT,
  cert_public_key_sha256 TEXT,
  cert_expiry_ts BIGINT,
  verdict_action TEXT,
  verdict_rule_id TEXT,
  verdict_priority INT,
  cert_validation_level TEXT,
  cert_mismatch_reason TEXT,
  cert_mismatch_action TEXT,
  ndpi_protocol TEXT,
  ndpi_category TEXT,
  ndpi_application TEXT,
  ndpi_confidence DOUBLE PRECISION,
  stats_bytes BIGINT,
  stats_packets INT,
  stats_duration_ms DOUBLE PRECISION,
  stats_extraction_latency_ms DOUBLE PRECISION,
  stats_sensor_latency_ms DOUBLE PRECISION,
  stats_ingest_latency_ms DOUBLE PRECISION,
  created_at TIMESTAMP DEFAULT now()
);

CREATE INDEX idx_l7_ndpi_protocol ON l7_webhook_events(ndpi_protocol);
CREATE INDEX idx_l7_ndpi_category ON l7_webhook_events(ndpi_category);
CREATE INDEX idx_l7_cert_hash ON l7_webhook_events(cert_leaf_sha256);
CREATE INDEX idx_l7_flow_key ON l7_webhook_events(flow_key);
```

## NoSQL Document (MongoDB)

```json
{
  "_id": "<flow_key>",
  "flow_id": "...",
  "source": "vaanvil-01",
  "schema_version": "1.1",
  "direction": "outbound",
  "observed_at": ISODate("2026-01-31T17:30:00Z"),
  "tls": {...},
  "fingerprints": {...},
  "certificate": {...},
  "verdict": {...},
  "ndpi": {
     "protocol": "YouTube",
     "category": "Video",
     "application": "YouTube",
     "confidence": 0.88,
     "ndpi_id": 219
  },
  "stats": {...}
}
```

## Querying NDPI Fields

- SQL: `SELECT * FROM l7_webhook_events WHERE ndpi_category='Video' AND cert_leaf_sha256='d8:...'`
- MongoDB: `db.l7_webhook_events.find({"ndpi.protocol": "TLS", "ndpi.category": "Encrypted"})`

## Testing Enrichment

1. `go test ./pkg/ndpi` ensures detection heuristics behave.
2. `go test ./internal/l7` ensures metadata includes the `ndpi` block.
3. Use curl to POST sample webhook JSON and verify `/api/events` responses include NDPI fields.

## Next Steps

- Replace the stub NDPI heuristics with real `libndpi` bindings when available.
- Persist NDPI metadata in whichever storage backend (SQL row, JSONB column, document database).
- Expose NDPI stats via `/api/l7/webhook/stats` (already tracks counts).
