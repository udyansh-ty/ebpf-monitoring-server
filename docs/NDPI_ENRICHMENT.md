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

## PostgreSQL Storage (Persistent)

The system supports optional PostgreSQL storage for L7 events with full NDPI enrichment. When enabled, events are automatically persisted to a relational database for long-term retention, advanced querying, and integration with dashboards and alerting systems.

### Configuration

**Enable PostgreSQL storage via environment variable:**

```bash
export DB_URL="postgres://user:password@localhost:5432/ebpf"
./aggregator
```

**Or via command-line flag:**

```bash
./aggregator -db-url "postgres://user:password@localhost:5432/ebpf"
```

**Connection string format:**

```
postgres://[user[:password]@][netloc][:port][/dbname][?param1=value1&...]
```

**Example:**

```bash
postgres://postgres:secretpassword@db.example.com:5432/ebpf?sslmode=require
```

### Database Setup

**Create database:**

```bash
createdb -U postgres ebpf
```

**Or using Docker:**

```bash
docker run -d \
  -p 5432:5432 \
  -e POSTGRES_DB=ebpf \
  -e POSTGRES_PASSWORD=secretpassword \
  -v pgdata:/var/lib/postgresql/data \
  postgres:15-alpine
```

### Schema

The PostgreSQL schema is automatically created on first connection with the following key tables and indexes:

**l7_events table:**

```sql
-- Network flow (5-tuple)
src_ip INET, dst_ip INET, src_port INT, dst_port INT, protocol TEXT

-- TLS metadata
tls_sni TEXT, tls_alpn TEXT, tls_version TEXT

-- Fingerprints
ja3 TEXT, ja4 TEXT, ja4_plus TEXT

-- Certificates
cert_leaf_sha256 TEXT, cert_issuer_cn TEXT, cert_expiry_ts BIGINT

-- Verdicts
verdict_action TEXT, verdict_rule_id TEXT, verdict_priority INT

-- NDPI enrichment (NEW!)
ndpi_protocol TEXT, ndpi_category TEXT, ndpi_application TEXT, ndpi_confidence FLOAT8

-- Statistics
stats_bytes BIGINT, stats_packets INT, stats_duration_ms FLOAT8

-- Extensibility
metadata JSONB
```

**Key Indexes:**

```sql
CREATE INDEX idx_l7_ndpi_protocol ON l7_events(ndpi_protocol);
CREATE INDEX idx_l7_ndpi_category ON l7_events(ndpi_category);
CREATE INDEX idx_l7_cert_leaf_sha256 ON l7_events(cert_leaf_sha256);
CREATE INDEX idx_l7_src_dst_ip ON l7_events(src_ip, dst_ip);
CREATE INDEX idx_l7_observed_at ON l7_events(observed_at DESC);
```

### Querying NDPI Fields

**SQL examples:**

```sql
-- All HTTPS traffic
SELECT count(*) FROM l7_events
WHERE ndpi_category = 'Encrypted' AND ndpi_application = 'HTTPS';

-- YouTube traffic
SELECT src_ip, dst_ip, stats_bytes FROM l7_events
WHERE ndpi_protocol = 'YouTube'
ORDER BY observed_at DESC
LIMIT 100;

-- Certificate tracking
SELECT DISTINCT cert_issuer_cn, count(*) as cert_count
FROM l7_events
WHERE cert_leaf_sha256 IS NOT NULL
GROUP BY cert_issuer_cn
ORDER BY cert_count DESC;

-- Combined NDPI + Certificate filtering
SELECT src_ip, tls_sni, ndpi_category, ndpi_confidence
FROM l7_events
WHERE ndpi_category = 'Encrypted'
  AND cert_leaf_sha256 = 'd8:6a:7f:e1'
  AND observed_at > now() - interval '1 hour';
```

**Grafana query (for dashboard):**

```sql
SELECT
  observed_at as time,
  ndpi_protocol as metric,
  count(*) as value
FROM l7_events
WHERE $__timeFilter(observed_at)
GROUP BY time, ndpi_protocol
ORDER BY time DESC
```

### API Integration

The aggregator's `/api/events` endpoint automatically returns L7 events from PostgreSQL when configured. Query by NDPI fields:

```bash
# Get all encrypted traffic
curl "http://localhost:8081/api/events?type=l7_flow_update&ndpi_category=Encrypted&limit=100"

# Get all YouTube traffic
curl "http://localhost:8081/api/events?type=l7_flow_update&ndpi_protocol=YouTube"

# Get events with specific certificate
curl "http://localhost:8081/api/events?cert_leaf_sha256=d8:6a:7f:e1&limit=50"
```

### Connection Pooling

The PostgreSQL storage implementation uses connection pooling for efficiency:

```
- Max connections: 20
- Min connections: 5
- Max lifetime: 15 minutes
- Idle timeout: 5 minutes
```

This ensures efficient resource usage while maintaining performance for high-volume L7 event ingestion.

### Performance Tips

1. **Index optimization:** Create additional indexes on frequently filtered columns
   ```sql
   CREATE INDEX idx_l7_src_ip_time ON l7_events(src_ip, observed_at DESC);
   CREATE INDEX idx_l7_ndpi_time ON l7_events(ndpi_protocol, observed_at DESC);
   ```

2. **Archival:** Move old events to archive table periodically
   ```sql
   INSERT INTO l7_events_archive SELECT * FROM l7_events WHERE observed_at < now() - interval '90 days';
   DELETE FROM l7_events WHERE observed_at < now() - interval '90 days';
   ```

3. **Partitioning:** For large deployments, partition table by time
   ```sql
   CREATE TABLE l7_events (... partition by range (observed_at) (...));
   ```

### Monitoring

Check PostgreSQL storage statistics:

```bash
# Connection pool health
psql $DB_URL -c "SELECT datname, count(*) FROM pg_stat_activity GROUP BY datname;"

# L7 event counts
psql $DB_URL -c "SELECT event_type, count(*) FROM l7_events GROUP BY event_type;"

# NDPI distribution
psql $DB_URL -c "SELECT ndpi_category, count(*) FROM l7_events GROUP BY ndpi_category;"

# Storage usage
psql $DB_URL -c "SELECT pg_size_pretty(pg_total_relation_size('l7_events'));"
```

## Testing Enrichment & Storage

1. **Run L7 tests with memory storage:**
   ```bash
   go test ./internal/l7/... -v
   ```

2. **Run PostgreSQL storage tests (requires PostgreSQL):**
   ```bash
   # Start test database
   docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=ebpf_test postgres:15

   # Run tests
   go test ./internal/storage/... -v
   ```

3. **Manual testing with live aggregator:**
   ```bash
   # Terminal 1: Start aggregator with PostgreSQL
   export DB_URL="postgres://postgres:postgres@localhost/ebpf_test"
   ./aggregator -addr :8081

   # Terminal 2: Send webhook
   curl -X POST http://localhost:8081/api/l7/webhook \
     -H "Content-Type: application/json" \
     -d @test-payload.json

   # Terminal 3: Query from database
   psql postgres://postgres:postgres@localhost/ebpf_test \
     -c "SELECT ndpi_protocol, ndpi_category, count(*) FROM l7_events GROUP BY 1, 2;"
   ```

## Next Steps

- Replace stub NDPI heuristics with real `libndpi` C bindings for increased accuracy
- Implement event archival and retention policies
- Add Prometheus metrics for storage performance monitoring
- Create Grafana dashboards for NDPI/certificate visualization
- Implement alerting rules for anomalous NDPI classifications
