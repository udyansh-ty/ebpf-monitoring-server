# Monitoring Application - User Guide

**Version**: 1.0
**Date**: February 2, 2026
**Audience**: Security engineers, network operators, DevOps teams
**Component**: L7 Event Aggregation & Analysis Platform

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Architecture Overview](#architecture-overview)
3. [Webhook Integration](#webhook-integration)
4. [Event Storage](#event-storage)
5. [Querying Events](#querying-events)
6. [L7 Metadata Fields](#l7-metadata-fields)
7. [NDPI Protocol Classification](#ndpi-protocol-classification)
8. [IP Blocking & Policy Verdicts](#ip-blocking--policy-verdicts)
9. [PostgreSQL Setup & Configuration](#postgresql-setup--configuration)
10. [API Endpoints](#api-endpoints)
11. [Common Use Cases](#common-use-cases)
12. [Performance & Capacity](#performance--capacity)
13. [Troubleshooting](#troubleshooting)
14. [FAQ](#faq)

---

## Quick Start

### What is the Monitoring Application?

The monitoring application is an **L7 event aggregator and analyzer** that:

- ✅ **Receives** encrypted traffic metadata from Vaanvil sensors (via webhooks)
- ✅ **Enriches** events with NDPI protocol classification
- ✅ **Stores** events persistently (PostgreSQL optional)
- ✅ **Queries** and analyzes L7 traffic patterns
- ✅ **Tracks** policy verdicts (allow/drop/redirect decisions)
- ✅ **Analyzes** IP blocking, domain blocking, and certificate validation

### Key Features

| Feature | Description | Benefit |
|---------|-------------|---------|
| **Webhook Receiver** | RESTful endpoint for Vaanvil events | Real-time traffic visibility |
| **L7 Enrichment** | NDPI heuristic classification | Application-layer insight |
| **Persistent Storage** | PostgreSQL with TimescaleDB | Historical analysis & compliance |
| **Query API** | REST endpoints for filtering/searching | Integration with dashboards |
| **Multi-tenant Ready** | Multiple sensor sources support | Enterprise deployments |
| **Certificate Tracking** | SHA256 fingerprinting | PKI visibility & alerts |
| **IP Blocking Support** | Verdict analysis for IP-based rules | Security posture analysis |

### Architecture

```
┌─────────────────────────────────────────────────┐
│          Vaanvil Sensors (Multiple)             │
│  (Send L7 events via HTTPS webhooks)            │
└────────────┬────────────────────────────────────┘
             │
             ↓
┌─────────────────────────────────────────────────┐
│      Monitoring Aggregator (HTTP/REST)          │
│  ┌──────────────────────────────────────────┐   │
│  │ Webhook Receiver (/api/l7/webhook)       │   │
│  │ - Parse WebhookPayload (batch of events) │   │
│  │ - Verify HMAC signature (optional)       │   │
│  │ - Convert to core.Event interface        │   │
│  └──────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────┐   │
│  │ NDPI Enrichment Layer                    │   │
│  │ - Heuristic protocol classification      │   │
│  │ - Port/SNI/TLS version inference         │   │
│  │ - Confidence scoring                     │   │
│  └──────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────┐   │
│  │ Storage Layer (Pluggable)                │   │
│  │ ├─ MemoryStorage (default)               │   │
│  │ └─ PostgreSQLStorage (optional)          │   │
│  └──────────────────────────────────────────┘   │
└────────────┬────────────────────────────────────┘
             │
     ┌───────┴────────┐
     ↓                ↓
┌──────────┐  ┌────────────────┐
│ Memory   │  │  PostgreSQL    │
│ Buffer   │  │  + TimescaleDB │
│ (Temp)   │  │  (Persistent)  │
└──────────┘  └────────────────┘
     │                │
     └───────┬────────┘
             ↓
┌─────────────────────────────────────────────────┐
│          Query API (/api/events)                │
│  - Filter by event type, time, IP, protocol    │
│  - Export to JSON/CSV                          │
│  - Aggregation queries via SQL                 │
└─────────────────────────────────────────────────┘
```

---

## Webhook Integration

### What is a Webhook?

A webhook is an **HTTP callback** where Vaanvil **pushes** L7 events to your monitoring application. When traffic matches a policy, Vaanvil batches events and sends them to your collector.

**Advantage**: Real-time delivery without polling

### Webhook Endpoint

```
POST /api/l7/webhook
Content-Type: application/json
X-Vaanvil-Signature: sha256=<HMAC-SHA256 hex> (optional)

{
  "schema_version": "1.1",
  "sent_at": "2026-02-02T15:30:45.123Z",
  "source": "vaanvil-sensor-01",
  "batch_id": "batch-2026-02-02-15-30-45-a1b2c3d4",
  "sequence": 42,
  "events": [
    { ... }
  ]
}
```

### Receiving Webhooks

**Step 1: Configure Vaanvil to send webhooks**

In Vaanvil's `config.json`:

```json
{
  "reporting": {
    "webhook": {
      "enabled": true,
      "endpoint": "https://monitoring.example.com/api/l7/webhook",
      "batch_size": 100,
      "batch_interval": 60,
      "timeout": 30,
      "retry_count": 3,
      "hmac_key": "your-secret-signing-key"
    }
  }
}
```

**Step 2: Start monitoring aggregator**

```bash
# In-memory storage (development)
./aggregator -addr :8081

# With PostgreSQL (production)
export DB_URL="postgres://user:password@localhost:5432/monitoring"
./aggregator -addr :8081 -db-url "$DB_URL"
```

**Step 3: Verify webhook reception**

```bash
# Check health status
curl http://localhost:8081/health/status | jq .

# Check event counts
curl http://localhost:8081/api/events?limit=1 | jq '.events | length'

# View logs
tail -f /var/log/monitoring/aggregator.log
```

### Webhook Payload Schema (v1.1)

The aggregator receives **batches** of L7 events:

```json
{
  "schema_version": "1.1",
  "sent_at": "2026-02-02T15:30:45.123Z",
  "source": "vaanvil-prod-01",
  "source_instance": "instance-1",
  "batch_id": "batch-2026-02-02-15-30-45-a1b2c3d4",
  "sequence": 42,
  "events": [
    {
      "flow_id": "192.168.1.100:54321->8.8.8.8:443",
      "flow_key": "unique-flow-hash",
      "event_type": "flow_update",
      "observed_at": 1743751845123,
      "flow_start_ts": 1743751840000,
      "direction": "outbound",
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
        "quic": null
      },
      "fingerprints": {
        "ja3": "e7d705a3286e19ea42f587b344ee6865",
        "ja3_features": {
          "cipher_count": 6,
          "extension_count": 24,
          "curve_count": 5,
          "point_formats": 1
        },
        "ja4": "771,8,12,4,h2",
        "ja4_plus": "sha256hash..."
      },
      "certificate": {
        "leaf_sha256": "d8:6a:7f:e1:...",
        "issuer_cn": "Google Internet Authority G3",
        "issuer_sha256": "aa:bb:cc:dd:...",
        "public_key_sha256": "ee:ff:00:11:...",
        "expiry_ts": 1743580800
      },
      "verdict": {
        "action": "allow",
        "rule_id": "allow-google",
        "priority": 100,
        "cert_validation_level": "standard",
        "cert_mismatch_reason": null,
        "cert_mismatch_action": null
      },
      "stats": {
        "bytes": 2048,
        "packets": 12,
        "duration_ms": 1200.5,
        "extraction_latency_ms": 2.34,
        "sensor_latency_ms": 0.5,
        "ingest_latency_ms": 1.2
      }
    }
  ]
}
```

### Event Fields Reference

| Field | Type | Description |
|-------|------|-------------|
| **flow_id** | string | Human-readable flow: `src:port->dst:port` |
| **flow_key** | string | Unique hash for deduplication |
| **event_type** | string | "flow_update", "flow_end", "anomaly" |
| **observed_at** | int64 | Unix milliseconds (UTC) |
| **flow_start_ts** | int64 | When flow began (ms) |
| **direction** | string | "inbound", "outbound", "lateral" |
| **src_ip/dst_ip** | string | IPv4 or IPv6 addresses |
| **src_port/dst_port** | uint16 | Port numbers (1-65535) |
| **protocol** | string | "tcp", "udp", or "proto-N" |
| **ip_version** | int | 4 (IPv4) or 6 (IPv6) |
| **tls.sni** | string | Server Name Indication (hostname) |
| **tls.alpn** | string | Application protocol: "h2" (HTTP/2), "h3" (HTTP/3) |
| **tls.version** | string | TLS version: "769" (1.0), "770" (1.1), "771" (1.2), "772" (1.3) |
| **fingerprints.ja3** | string | TLS fingerprint (MD5 hex, 32 chars) |
| **fingerprints.ja4** | string | Next-gen TLS fingerprint (string-based) |
| **fingerprints.ja4_plus** | string | Enhanced fingerprint (SHA256-based) |
| **certificate.leaf_sha256** | string | Leaf cert SHA256 (colon-separated) |
| **certificate.issuer_cn** | string | Issuer Common Name (human-readable) |
| **certificate.expiry_ts** | int64 | Certificate expiration (Unix seconds) |
| **verdict.action** | string | Policy decision: "allow", "drop", "redirect" |
| **verdict.rule_id** | string | Matched policy rule identifier |
| **verdict.priority** | int | Rule priority (higher = checked first) |
| **stats.bytes** | int64 | Total bytes transferred |
| **stats.packets** | int32 | Total packets |
| **stats.extraction_latency_ms** | float64 | TLS metadata extraction time |

---

## Event Storage

### Storage Options

The monitoring application supports two storage backends:

#### 1. Memory Storage (Default)

**Use case**: Development, testing, non-critical deployments

```bash
./aggregator -addr :8081
# Events kept in RAM, lost on restart
```

**Characteristics**:
- ✅ Zero configuration
- ✅ Fast in-memory access
- ❌ Events lost on restart
- ❌ Limited to available RAM
- ❌ No historical analysis

#### 2. PostgreSQL Storage (Recommended)

**Use case**: Production, compliance, long-term analysis

```bash
export DB_URL="postgres://user:password@localhost:5432/monitoring"
./aggregator -addr :8081 -db-url "$DB_URL"
```

**Characteristics**:
- ✅ Persistent storage (survives restarts)
- ✅ Historical analysis & reporting
- ✅ Compliance audit trails
- ✅ Scales to billions of events
- ✅ Optional TimescaleDB for time-series optimization
- ⚠️ Requires database setup

### PostgreSQL Setup

#### Quick Start (Docker)

```bash
# Start PostgreSQL container
docker run -d \
  --name monitoring-db \
  -p 5432:5432 \
  -e POSTGRES_PASSWORD=securepass \
  -e POSTGRES_DB=monitoring \
  -v pgdata:/var/lib/postgresql/data \
  postgres:15-alpine

# Create connection string
export DB_URL="postgres://postgres:securepass@localhost:5432/monitoring"

# Start monitoring app (schema created automatically)
./aggregator -addr :8081 -db-url "$DB_URL"
```

#### Native Installation (Linux)

**Install PostgreSQL:**

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y postgresql postgresql-contrib

# Start service
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

**Create database:**

```bash
# Connect as postgres user
sudo -u postgres psql

# Create database and user
CREATE DATABASE monitoring;
CREATE USER monitoring_user WITH PASSWORD 'securepass';
ALTER ROLE monitoring_user SET client_encoding TO 'utf8';
ALTER ROLE monitoring_user SET default_transaction_isolation TO 'read committed';
ALTER ROLE monitoring_user SET default_transaction_deferrable TO on;
GRANT ALL PRIVILEGES ON DATABASE monitoring TO monitoring_user;
\q
```

**Start monitoring app:**

```bash
export DB_URL="postgres://monitoring_user:securepass@localhost:5432/monitoring"
./aggregator -addr :8081 -db-url "$DB_URL"
```

### Database Schema

The monitoring app automatically creates the `l7_events` table on first connection:

**Columns:**

| Column | Type | Purpose |
|--------|------|---------|
| **id** | TEXT PRIMARY KEY | Unique event ID |
| **flow_id** | TEXT | Human-readable flow |
| **flow_key** | TEXT | Deduplication hash |
| **batch_id** | TEXT | Batch identifier |
| **source** | TEXT | Sensor name |
| **event_type** | TEXT | Event classification |
| **observed_at** | TIMESTAMP | When event occurred |
| **src_ip** / **dst_ip** | INET | IP addresses (indexed) |
| **src_port** / **dst_port** | INT | Port numbers |
| **protocol** | TEXT | tcp/udp/quic |
| **ip_version** | INT | 4 or 6 |
| **tls_sni** | TEXT | Hostname (indexed) |
| **tls_alpn** | TEXT | Protocol version |
| **tls_version** | TEXT | TLS version code |
| **ja3** / **ja4** / **ja4_plus** | TEXT | Fingerprints |
| **cert_leaf_sha256** | TEXT | Certificate hash (indexed) |
| **cert_issuer_cn** | TEXT | Issuer name |
| **cert_expiry_ts** | BIGINT | Expiration timestamp |
| **verdict_action** | TEXT | Policy: allow/drop/redirect |
| **verdict_rule_id** | TEXT | Matched rule |
| **verdict_priority** | INT | Rule priority |
| **ndpi_protocol** | TEXT | NDPI classification |
| **ndpi_category** | TEXT | Protocol category |
| **ndpi_application** | TEXT | Application name |
| **ndpi_confidence** | FLOAT8 | Classification confidence (0-1) |
| **stats_bytes** | BIGINT | Traffic volume |
| **stats_packets** | INT | Packet count |
| **stats_duration_ms** | FLOAT8 | Flow duration |
| **metadata** | JSONB | Extensible metadata |
| **created_at** | TIMESTAMP | When stored |

**Key Indexes:**

```sql
-- Network-based queries
idx_l7_src_dst_ip          -- src_ip, dst_ip
idx_l7_src_ip              -- src_ip only
idx_l7_tls_sni             -- hostname filtering

-- NDPI queries
idx_l7_ndpi_protocol       -- protocol classification
idx_l7_ndpi_category       -- category filtering
idx_l7_ndpi_time           -- time-based protocol trends

-- Certificate queries
idx_l7_cert_leaf_sha256    -- certificate tracking
idx_l7_cert_time           -- cert history over time

-- Time-series queries
idx_l7_observed_at         -- time range filtering
idx_l7_flow_time           -- flow history per source
```

### TimescaleDB Enhancement (Optional)

For high-volume deployments, enable TimescaleDB for automatic time-series optimization:

```bash
# Connect to PostgreSQL
psql postgresql://monitoring_user:password@localhost/monitoring

# Create TimescaleDB extension
CREATE EXTENSION timescaledb;

# Verify (monitoring app handles this automatically on connect)
SELECT * FROM timescaledb_information.hypertables;
```

**Benefits:**
- Automatic data chunking (1-day intervals)
- Compression for old data (~90% space savings)
- Faster time-range queries
- Automatic retention policies

**Example query after TimescaleDB:**

```sql
-- Bandwidth by protocol (5-min buckets, last 24 hours)
SELECT
  time_bucket('5 minutes', observed_at) AS bucket,
  ndpi_protocol,
  sum(stats_bytes) AS bytes
FROM l7_events
WHERE observed_at >= now() - interval '24 hours'
GROUP BY bucket, ndpi_protocol
ORDER BY bucket DESC;
```

---

## Querying Events

### REST API Endpoints

#### 1. List Events

```bash
GET /api/events?event_type=l7_flow_update&limit=100&since=2026-02-01T00:00:00Z
```

**Query Parameters:**

| Parameter | Type | Description | Example |
|-----------|------|-------------|---------|
| **event_type** | string | Filter by event type | `l7_flow_update` |
| **limit** | int | Max events returned | `100` |
| **since** | timestamp | Start time (RFC3339) | `2026-02-01T00:00:00Z` |
| **until** | timestamp | End time (RFC3339) | `2026-02-02T00:00:00Z` |

**Response:**

```json
{
  "events": [
    {
      "id": "a1b2c3d4e5f6...",
      "type": "l7_flow_update",
      "timestamp": 1743751845123,
      "time": "2026-02-02T15:30:45.123Z",
      "flow_id": "192.168.1.100:54321->8.8.8.8:443",
      "src_ip": "192.168.1.100",
      "dst_ip": "8.8.8.8",
      "tls_sni": "google.com",
      "verdict_action": "allow",
      "ndpi_protocol": "TLS",
      "ndpi_category": "Encrypted",
      "metadata": { ... }
    }
  ],
  "total": 42,
  "cursor": "next_page_token"
}
```

#### 2. SQL Queries (PostgreSQL Only)

For advanced analysis, query PostgreSQL directly:

```bash
psql postgresql://user:password@localhost/monitoring
```

### Query Examples

#### A. Find All IP Blocks (Last 24 Hours)

```sql
SELECT
  src_ip,
  dst_ip,
  protocol,
  verdict_action,
  verdict_rule_id,
  tls_sni,
  observed_at
FROM l7_events
WHERE verdict_action = 'drop'
  AND observed_at >= now() - interval '24 hours'
ORDER BY observed_at DESC
LIMIT 100;
```

#### B. Traffic by Protocol (NDPI)

```sql
SELECT
  ndpi_category,
  ndpi_protocol,
  COUNT(*) as flow_count,
  SUM(stats_bytes) as total_bytes,
  AVG(ndpi_confidence) as avg_confidence
FROM l7_events
WHERE observed_at >= now() - interval '1 day'
GROUP BY ndpi_category, ndpi_protocol
ORDER BY total_bytes DESC;
```

#### C. Suspicious Certificates (Mismatches)

```sql
SELECT
  src_ip,
  dst_ip,
  tls_sni,
  cert_issuer_cn,
  cert_leaf_sha256,
  verdict_cert_mismatch_reason,
  count(*) as occurrences
FROM l7_events
WHERE verdict_cert_mismatch_reason IS NOT NULL
  AND observed_at >= now() - interval '7 days'
GROUP BY src_ip, dst_ip, tls_sni, cert_issuer_cn, cert_leaf_sha256
ORDER BY occurrences DESC;
```

#### D. Certificate Expiration Risk (30 Days)

```sql
SELECT
  cert_issuer_cn,
  cert_leaf_sha256,
  cert_expiry_ts,
  to_timestamp(cert_expiry_ts) as expiry_date,
  COUNT(DISTINCT tls_sni) as unique_domains,
  COUNT(*) as total_flows
FROM l7_events
WHERE cert_expiry_ts IS NOT NULL
  AND cert_expiry_ts < (EXTRACT(EPOCH FROM now()) + 30 * 86400)
GROUP BY cert_issuer_cn, cert_leaf_sha256, cert_expiry_ts
ORDER BY cert_expiry_ts ASC;
```

#### E. Top Blocked Destinations (IP Blocking)

```sql
SELECT
  dst_ip,
  COUNT(*) as block_count,
  COUNT(DISTINCT src_ip) as source_count,
  verdict_rule_id,
  MAX(observed_at) as last_blocked
FROM l7_events
WHERE verdict_action = 'drop'
  AND observed_at >= now() - interval '7 days'
GROUP BY dst_ip, verdict_rule_id
ORDER BY block_count DESC
LIMIT 50;
```

#### F. JA3 Fingerprint Distribution (Threat Intelligence)

```sql
SELECT
  fingerprints ->> 'ja3' as ja3_hash,
  COUNT(*) as fingerprint_count,
  COUNT(DISTINCT src_ip) as source_ips,
  COUNT(DISTINCT tls_sni) as target_domains,
  AVG((metadata ->> 'ndpi'::text) ->> 'confidence'::text)::float as avg_confidence
FROM l7_events
WHERE fingerprints ->> 'ja3' IS NOT NULL
  AND observed_at >= now() - interval '24 hours'
GROUP BY ja3_hash
ORDER BY fingerprint_count DESC
LIMIT 20;
```

---

## L7 Metadata Fields

### Network Layer (5-Tuple)

```
src_ip (192.168.1.100) + src_port (54321)
  ↓
dst_ip (8.8.8.8) + dst_port (443)
  ↓
protocol (tcp)
```

Uniquely identifies a network flow for tracking and analysis.

### TLS Metadata

**SNI (Server Name Indication)**
- Domain name client requests
- Enables hostname-based blocking even on encrypted HTTPS
- Example: `google.com` for connection to 8.8.8.8:443

**ALPN (Application-Layer Protocol Negotiation)**
- Protocol version negotiated in TLS handshake
- Values: `h2` (HTTP/2), `h3` (HTTP/3), `http/1.1`
- Indicates client capabilities and server support

**TLS Version**
- Encryption protocol version
- Values: `769` (TLS 1.0), `770` (1.1), `771` (1.2), `772` (1.3)
- Newer versions (772) indicate modern clients

### Fingerprints

**JA3 (TLS Client Fingerprint)**
- MD5 hash of TLS ClientHello fields
- 32-character hex string
- Uniquely identifies browser/client type
- Example: `e7d705a3286e19ea42f587b344ee6865`
- Use case: Detect malware using known JA3 hashes

**JA4 (Improved Fingerprint)**
- String-based fingerprint (more interpretable)
- Example: `771,8,12,4,h2`
- Components: `tls_version,cipher_count,extension_count,curve_count,alpn`

**JA4+ (Enhanced with Certificate)**
- SHA256-based fingerprint
- Includes certificate details
- Better for advanced threat hunting

### Certificate Data

**Leaf SHA256**
- Hash of the end-entity certificate
- Used for certificate pinning
- Example: `d8:6a:7f:e1:...`

**Issuer CN (Common Name)**
- Certificate Authority name
- Human-readable for quick identification
- Example: `Google Internet Authority G3`

**Expiry Timestamp**
- When certificate expires (Unix seconds)
- Monitor for certificates expiring soon
- Example: `1743580800` (Feb 2, 2027)

---

## NDPI Protocol Classification

### What is NDPI?

NDPI (**Deep Packet Inspection-free Identification**) classifies encrypted traffic using heuristics:
- Port numbers (e.g., :443 → HTTPS)
- Server Name Indication (SNI domain)
- TLS version and extensions
- JA3 fingerprints

### Classification Example

```
Flow: 192.168.1.100:54321 → 8.8.8.8:443
  └─ Port 443 → Likely HTTPS
  └─ SNI: "google.com" → Likely Google
  └─ TLS 1.3 → Modern client
  └─ ALPN: h2 → HTTP/2 support

Result:
  protocol: "TLS"
  category: "Encrypted"
  application: "Google Search"
  confidence: 0.95
```

### Protocol Categories

| Category | Description | Examples |
|----------|-------------|----------|
| **Encrypted** | TLS/SSL traffic | HTTPS, SSH, VPN |
| **Video** | Streaming media | YouTube, Netflix, TikTok |
| **Social** | Social networks | Facebook, Instagram, Twitter |
| **Messaging** | Chat applications | WhatsApp, Telegram, Signal |
| **P2P** | File sharing | BitTorrent, DC++ |
| **Gaming** | Online games | Fortnite, Valorant, CS:GO |
| **Malware** | Known malicious | Botnet C2, Ransomware |
| **Unsafe** | Known dangerous | Phishing, DDoS botnets |

### Query by NDPI Category

```sql
-- Block all peer-to-peer traffic
SELECT src_ip, COUNT(*) as flow_count
FROM l7_events
WHERE ndpi_category = 'P2P'
  AND observed_at >= now() - interval '24 hours'
GROUP BY src_ip
ORDER BY flow_count DESC;

-- Detect potential streaming violations
SELECT src_ip, ndpi_protocol, SUM(stats_bytes) as bandwidth
FROM l7_events
WHERE ndpi_category = 'Video'
  AND observed_at >= now() - interval '1 day'
GROUP BY src_ip, ndpi_protocol
ORDER BY bandwidth DESC
LIMIT 20;
```

### Confidence Scoring

Each NDPI classification includes a confidence value (0.0 to 1.0):

```
confidence: 0.95   ← Very confident (port + SNI + JA3 all match)
confidence: 0.75   ← Likely (port + SNI match, JA3 is partial)
confidence: 0.50   ← Uncertain (only port matches)
```

**Use in queries:**

```sql
-- Only high-confidence NDPI classifications
SELECT *
FROM l7_events
WHERE ndpi_confidence >= 0.8
  AND ndpi_category = 'Video';
```

---

## IP Blocking & Policy Verdicts

### What Changed: IP Blocking Support

Vaanvil now supports three types of policy matching:

| Type | Matches | Example |
|------|---------|---------|
| **Domain** | SNI hostname | `match: { "sni": "example.com" }` |
| **IP (Bidirectional)** | src OR dst IP | `match: { "ip": "192.0.2.0/24" }` |
| **Source IP** | src IP only | `match: { "src_ip": "203.0.113.5" }` |
| **Destination IP** | dst IP only | `match: { "dst_ip": "198.51.100.0/24" }` |

### Verdict Actions

All verdicts include an **action** field indicating what Vaanvil did:

```json
"verdict": {
  "action": "allow",           // Policy allowed traffic
  "rule_id": "allow-google",   // Which rule matched
  "priority": 100              // Rule priority (higher = checked first)
}
```

**Possible Actions:**

| Action | Meaning | Flow Result |
|--------|---------|-------------|
| **allow** | Traffic permitted | Flow continues normally |
| **drop** | Traffic blocked | Connection terminated silently |
| **redirect** | Traffic rerouted | Sent to alternate interface |

### Analyzing IP Blocks

#### Find All IP-Based Blocks

```sql
-- Flows that were dropped by Vaanvil
SELECT
  src_ip,
  dst_ip,
  protocol,
  verdict_rule_id,
  COUNT(*) as block_count,
  SUM(stats_bytes) as blocked_bytes,
  MAX(observed_at) as last_blocked
FROM l7_events
WHERE verdict_action = 'drop'
  AND observed_at >= now() - interval '24 hours'
GROUP BY src_ip, dst_ip, protocol, verdict_rule_id
ORDER BY block_count DESC;
```

#### Track IP Blocking by Rule

```sql
-- Which IP blocking rules are most active?
SELECT
  verdict_rule_id,
  COUNT(DISTINCT src_ip) as unique_sources,
  COUNT(DISTINCT dst_ip) as unique_destinations,
  COUNT(*) as total_blocks,
  SUM(stats_bytes) as total_blocked_bytes
FROM l7_events
WHERE verdict_action = 'drop'
  AND verdict_rule_id LIKE 'block-ip%'
  AND observed_at >= now() - interval '7 days'
GROUP BY verdict_rule_id
ORDER BY total_blocks DESC;
```

#### Detect Blocked Destinations (Suspicious Servers)

```sql
-- Top IP ranges trying to connect outbound but blocked
SELECT
  substring(dst_ip, 1, 15) || '.0/24' as destination_range,
  COUNT(*) as block_count,
  COUNT(DISTINCT src_ip) as internal_sources,
  MAX(observed_at) as last_attempt
FROM l7_events
WHERE verdict_action = 'drop'
  AND direction = 'outbound'
  AND observed_at >= now() - interval '7 days'
GROUP BY destination_range
ORDER BY block_count DESC
LIMIT 20;
```

#### Compare Allow vs. Drop

```sql
-- Policy enforcement ratio
SELECT
  verdict_action,
  COUNT(*) as event_count,
  ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 2) as percentage,
  SUM(stats_bytes) as total_bytes
FROM l7_events
WHERE observed_at >= now() - interval '24 hours'
GROUP BY verdict_action
ORDER BY event_count DESC;
```

### Certificate Validation Verdicts

When Vaanvil validates certificates:

```json
"verdict": {
  "action": "allow",
  "cert_validation_level": "strict",      // "strict", "standard", "relaxed"
  "cert_mismatch_reason": "subject_cn_mismatch",
  "cert_mismatch_action": "log"           // What happened on mismatch
}
```

**Query for certificate mismatches:**

```sql
SELECT
  src_ip,
  dst_ip,
  tls_sni,
  cert_issuer_cn,
  verdict_cert_mismatch_reason,
  count(*) as mismatch_count
FROM l7_events
WHERE verdict_cert_mismatch_reason IS NOT NULL
  AND observed_at >= now() - interval '7 days'
GROUP BY src_ip, dst_ip, tls_sni, cert_issuer_cn
ORDER BY mismatch_count DESC;
```

---

## PostgreSQL Setup & Configuration

### Connection String Format

```
postgres://[user[:password]@][netloc][:port][/dbname][?param1=value1&...]
```

**Examples:**

```bash
# Local development
postgres://postgres:password@localhost:5432/monitoring

# Remote with SSL
postgres://monitoring:secret@db.example.com:5432/monitoring?sslmode=require

# Connection pooling (PgBouncer)
postgres://monitoring:secret@pgbouncer.local:6432/monitoring

# AWS RDS
postgres://monitoring:secret@monitoring-db.xxxxx.us-east-1.rds.amazonaws.com:5432/monitoring?sslmode=require
```

### Starting with PostgreSQL

**Option 1: Docker (Fastest)**

```bash
docker run -d \
  --name monitoring-db \
  -p 5432:5432 \
  -e POSTGRES_PASSWORD=secretpass \
  -e POSTGRES_DB=monitoring \
  -v pgdata:/var/lib/postgresql/data \
  postgres:15-alpine

export DB_URL="postgres://postgres:secretpass@localhost:5432/monitoring"
./aggregator -addr :8081 -db-url "$DB_URL"
```

**Option 2: Native (Production)**

```bash
# Install
sudo apt-get install -y postgresql postgresql-contrib

# Create user/database
sudo -u postgres createdb monitoring
sudo -u postgres createuser monitoring_user
sudo -u postgres psql -c "ALTER USER monitoring_user PASSWORD 'secret';"

# Start
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Run monitoring
export DB_URL="postgres://monitoring_user:secret@localhost/monitoring"
./aggregator -addr :8081 -db-url "$DB_URL"
```

**Option 3: Kubernetes (Helm)**

```bash
# Install PostgreSQL operator
helm repo add postgresql https://charts.bitnami.com/bitnami
helm install monitoring-db postgresql/postgresql \
  --set auth.password=secretpass \
  --set auth.database=monitoring

# Get connection string
kubectl get secret monitoring-db-postgresql -o jsonpath='{.data.password}' | base64 -d
kubectl port-forward svc/monitoring-db-postgresql 5432:5432

export DB_URL="postgres://postgres:secretpass@localhost:5432/monitoring"
./aggregator -addr :8081 -db-url "$DB_URL"
```

### Connection Pooling

The monitoring app uses pgx connection pooling:

```
Max Connections: 20
Min Connections: 5
Max Lifetime: 15 minutes
Idle Timeout: 5 minutes
```

**Monitor pool health:**

```sql
SELECT
  datname as database,
  usename as user,
  state as connection_state,
  count(*) as conn_count
FROM pg_stat_activity
WHERE datname = 'monitoring'
GROUP BY datname, usename, state;
```

### Retention Policies

For long-term deployments, implement data archival:

```sql
-- Archive old events (keep last 90 days)
INSERT INTO l7_events_archive
SELECT * FROM l7_events
WHERE observed_at < now() - interval '90 days';

DELETE FROM l7_events
WHERE observed_at < now() - interval '90 days';

-- With TimescaleDB compression
SELECT compress_chunk(chunk)
FROM timescaledb_information.chunks
WHERE table_name = 'l7_events'
  AND range_start < now() - interval '30 days';
```

---

## API Endpoints

### Health Check

```bash
GET /health/status

Response:
{
  "status": "healthy",
  "uptime_seconds": 3600,
  "events_received": 150000,
  "events_stored": 149950,
  "storage_backend": "postgresql",
  "db_connected": true
}
```

### List Events

```bash
GET /api/events?event_type=l7_flow_update&limit=100&since=2026-02-01T00:00:00Z

Response:
{
  "events": [...],
  "total": 1500,
  "limit": 100,
  "next_cursor": "token..."
}
```

### Webhook Receiver

```bash
POST /api/l7/webhook
Content-Type: application/json
X-Vaanvil-Signature: sha256=...

Response (Success):
{
  "status": "accepted",
  "batch_id": "batch-...",
  "events_processed": 100,
  "events_stored": 100
}
```

---

## Common Use Cases

### Use Case 1: Monitor YouTube Usage

```bash
# Find YouTube traffic (last 24 hours)
curl "http://localhost:8081/api/events" | jq '.events[] |
  select(.metadata.ndpi.application == "YouTube") |
  {src_ip, dst_ip, tls_sni, bytes: .stats.bytes}'
```

**SQL:**

```sql
SELECT src_ip, COUNT(*) as connection_count, SUM(stats_bytes) as bandwidth
FROM l7_events
WHERE ndpi_protocol = 'YouTube'
  AND observed_at >= now() - interval '24 hours'
GROUP BY src_ip
ORDER BY bandwidth DESC;
```

### Use Case 2: Track Certificate Issues

```sql
-- Certificates expiring in next 30 days
SELECT
  cert_issuer_cn,
  cert_leaf_sha256,
  to_timestamp(cert_expiry_ts) as expiry,
  COUNT(DISTINCT tls_sni) as domains_affected
FROM l7_events
WHERE cert_expiry_ts IS NOT NULL
  AND cert_expiry_ts < (EXTRACT(EPOCH FROM now()) + 30 * 86400)
GROUP BY cert_issuer_cn, cert_leaf_sha256
ORDER BY cert_expiry_ts ASC;
```

### Use Case 3: Detect Botnet C2 Activity

```sql
-- Known botnet fingerprints
SELECT src_ip, dst_ip, tls_sni, count(*) as connection_count
FROM l7_events
WHERE ja3 IN (
  'known_botnet_ja3_1',
  'known_botnet_ja3_2',
  'known_botnet_ja3_3'
)
  AND observed_at >= now() - interval '24 hours'
GROUP BY src_ip, dst_ip, tls_sni;
```

### Use Case 4: Analyze IP Blocking Effectiveness

```sql
-- What IP ranges are being blocked?
SELECT
  substring(dst_ip, 1, 15) || '.0/24' as blocked_range,
  COUNT(*) as block_count,
  verdict_rule_id,
  MAX(observed_at) as last_blocked
FROM l7_events
WHERE verdict_action = 'drop'
  AND observed_at >= now() - interval '7 days'
GROUP BY blocked_range, verdict_rule_id
ORDER BY block_count DESC;
```

---

## Performance & Capacity

### Event Volume Estimates

| Setup | Events/Day | Events/Year | Storage | Hardware |
|-------|-----------|------------|---------|----------|
| **Small** (500 users) | 100K | 36M | 10 GB | 1 core, 2 GB RAM |
| **Medium** (2K users) | 500K | 180M | 50 GB | 2 cores, 8 GB RAM |
| **Large** (10K users) | 2M | 730M | 200 GB | 4 cores, 16 GB RAM |
| **Enterprise** (50K users) | 10M | 3.6B | 1 TB | 8+ cores, 32+ GB RAM |

### Database Performance Tips

1. **Create indexes on common filters:**

```sql
CREATE INDEX idx_l7_verdict_action ON l7_events(verdict_action);
CREATE INDEX idx_l7_ndpi_category_time ON l7_events(ndpi_category, observed_at DESC);
CREATE INDEX idx_l7_src_ip_time ON l7_events(src_ip, observed_at DESC);
```

2. **Use time-range queries:**

```sql
-- ✅ Fast (uses observed_at index)
SELECT * FROM l7_events WHERE observed_at >= now() - interval '1 day';

-- ❌ Slow (full table scan)
SELECT * FROM l7_events WHERE extract(year from observed_at) = 2026;
```

3. **Archive old data:**

```sql
-- Move events older than 90 days to archive table
INSERT INTO l7_events_archive SELECT * FROM l7_events
WHERE observed_at < now() - interval '90 days';
DELETE FROM l7_events WHERE observed_at < now() - interval '90 days';
```

4. **Enable TimescaleDB for time-series:**

```bash
# Significant performance improvement for time-range queries
psql postgresql://user:pass@localhost/monitoring
CREATE EXTENSION timescaledb;
# Monitoring app handles hypertable creation automatically
```

---

## Troubleshooting

### Issue: Webhooks Not Arriving

**Symptom**: Monitoring app running but no events received

**Solution:**

```bash
# 1. Check monitoring app is listening
curl http://localhost:8081/health/status

# 2. Check Vaanvil webhook configuration
grep -A10 '"webhook"' /etc/vaanvil/config.json

# 3. Test connectivity from Vaanvil machine
curl -v https://monitoring-server:8081/api/l7/webhook \
  -H "Content-Type: application/json" \
  -d '{"events": []}'

# 4. Check logs
tail -f /var/log/monitoring/aggregator.log | grep webhook
```

### Issue: High Memory Usage

**Symptom**: Monitoring app consuming too much RAM

**Solution:**

```bash
# 1. Check if using memory storage (instead of PostgreSQL)
echo $DB_URL  # Should be set to postgres://...

# 2. If memory storage, reduce buffering
# Consider switching to PostgreSQL:
export DB_URL="postgres://user:pass@localhost/monitoring"
./aggregator -addr :8081 -db-url "$DB_URL"

# 3. Monitor per-event memory
curl http://localhost:8081/health/status | jq '.events_received'
# Estimate: events * 5KB per event
```

### Issue: PostgreSQL Connection Failures

**Symptom**: `Failed to connect to PostgreSQL: connection refused`

**Solution:**

```bash
# 1. Check PostgreSQL is running
sudo systemctl status postgresql

# 2. Verify connection string
echo $DB_URL

# 3. Test connection manually
psql "$DB_URL"

# 4. Check PostgreSQL logs
sudo tail -f /var/log/postgresql/postgresql-*.log

# 5. Verify firewall
netstat -tlnp | grep 5432
```

### Issue: Slow Queries

**Symptom**: API responses taking >5 seconds

**Solution:**

```sql
-- Check missing indexes
SELECT
  schemaname,
  tablename,
  indexname
FROM pg_indexes
WHERE tablename = 'l7_events'
ORDER BY indexname;

-- Add missing indexes
CREATE INDEX idx_l7_verdict_action ON l7_events(verdict_action);
CREATE INDEX idx_l7_observed_at_action ON l7_events(observed_at DESC, verdict_action);

-- Analyze query plan
EXPLAIN ANALYZE
SELECT * FROM l7_events
WHERE observed_at >= now() - interval '1 day'
  AND verdict_action = 'drop';
```

---

## FAQ

### Q1: What's the difference between monitoring app and Vaanvil?

**A**:
- **Vaanvil** = Enforcement engine (makes allow/drop decisions on network)
- **Monitoring** = Analysis platform (collects and analyzes decisions made)

They work together: Vaanvil enforces policies, monitoring app reports what was enforced.

### Q2: Can I run multiple monitoring instances?

**A**: Yes! Point multiple instances at the same PostgreSQL database for high availability:

```
Vaanvil → Load Balancer → Monitoring Instance 1 \
                          Monitoring Instance 2  → PostgreSQL (shared)
                          Monitoring Instance 3 /
```

### Q3: What if a webhook batch fails?

**A**: Vaanvil retries with exponential backoff. If it continues failing:

```bash
# Check monitoring app logs
tail -f /var/log/monitoring/aggregator.log

# Verify endpoint is accepting requests
curl http://localhost:8081/api/l7/webhook \
  -H "Content-Type: application/json" \
  -d '{"events": []}'

# Check database connectivity
psql "$DB_URL" -c "SELECT count(*) FROM l7_events;"
```

### Q4: How do I delete old events?

**A**: Use SQL retention policies:

```sql
-- Delete events older than 90 days
DELETE FROM l7_events
WHERE observed_at < now() - interval '90 days';

-- Archive instead (safer)
INSERT INTO l7_events_archive
SELECT * FROM l7_events
WHERE observed_at < now() - interval '90 days';

DELETE FROM l7_events
WHERE observed_at < now() - interval '90 days';
```

### Q5: Can I filter by IP address via API?

**A**: Not yet. Use PostgreSQL queries or add `QueryAdvanced` method:

```sql
SELECT * FROM l7_events
WHERE src_ip = '192.168.1.100'
  AND observed_at >= now() - interval '24 hours'
ORDER BY observed_at DESC;
```

### Q6: What metadata should I use for alerting?

**A**: Key fields for alerts:

```json
{
  "verdict_action": "drop",              // Traffic was blocked
  "tls_sni": "malicious-domain.com",     // Hostname being accessed
  "src_ip": "192.168.1.100",             // Internal source
  "ndpi_protocol": "Botnet",             // NDPI classification
  "certificate_mismatch_reason": "..."   // Certificate validation issues
}
```

### Q7: How long are events retained?

**A**:
- **Memory storage**: Until restart (no retention)
- **PostgreSQL**: Until manually deleted (set retention policy)
- **Recommended**: Keep 90 days hot, archive older to S3

---

## Summary

**Key Takeaways**:

1. ✅ Webhook receiver captures L7 events from Vaanvil sensors
2. ✅ NDPI enrichment classifies encrypted protocols
3. ✅ PostgreSQL storage enables historical analysis
4. ✅ IP blocking verdicts are first-class events (same as domain blocks)
5. ✅ Rich SQL querying for compliance and threat hunting
6. ✅ Scales from development to enterprise deployments

**Next Steps**:

1. [Deploy with Docker](#quick-start-docker)
2. [Configure Vaanvil webhooks](#webhook-integration)
3. [Query your first events](#querying-events)
4. [Set up retention policies](#retention-policies)
5. [Create alerts](#common-use-cases)

---

**Last Updated**: February 2, 2026
**Version**: 1.0
**Questions?** See [Troubleshooting](#troubleshooting) section
