// Package storage provides event storage implementations.
package storage

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v4"
)

// ANCHOR: L7 Event Schema with NDPI Enrichment - Jan 31, 2026
// WHY: Persist L7 webhook events with TLS/cert/NDPI metadata for querying and alerting
// WHAT: PostgreSQL schema with structured columns for 5-tuple, TLS, certificates, verdicts, NDPI
// HOW: Create table with proper indexes on flow_key, event_type, NDPI fields, src/dst IPs

const createL7EventsTable = `
CREATE TABLE IF NOT EXISTS l7_events (
  -- Primary key
  id TEXT PRIMARY KEY,

  -- Flow identification
  flow_id TEXT NOT NULL,
  flow_key TEXT NOT NULL,
  batch_id TEXT,
  source TEXT,
  schema_version TEXT,
  event_type TEXT NOT NULL,

  -- Timing
  observed_at TIMESTAMP NOT NULL,

  -- 5-tuple (network flow)
  src_ip INET NOT NULL,
  dst_ip INET NOT NULL,
  src_port INT,
  dst_port INT,
  protocol TEXT,
  ip_version INT,

  -- TLS metadata
  tls_sni TEXT,
  tls_alpn TEXT,
  tls_version TEXT,

  -- Fingerprints (JA3, JA4, etc.)
  ja3 TEXT,
  ja4 TEXT,
  ja4_plus TEXT,
  ja3_cipher_count INT,
  ja3_extension_count INT,
  ja3_curve_count INT,

  -- Certificate metadata
  cert_leaf_sha256 TEXT,
  cert_issuer_sha256 TEXT,
  cert_issuer_cn TEXT,
  cert_public_key_sha256 TEXT,
  cert_expiry_ts BIGINT,

  -- Verdict/verdict
  verdict_action TEXT,
  verdict_rule_id TEXT,
  verdict_priority INT,
  cert_validation_level TEXT,
  cert_mismatch_reason TEXT,
  cert_mismatch_action TEXT,

  -- NDPI enrichment (new!)
  ndpi_protocol TEXT,
  ndpi_category TEXT,
  ndpi_application TEXT,
  ndpi_confidence FLOAT8,
  ndpi_id INT,

  -- Statistics
  stats_bytes BIGINT,
  stats_packets INT,
  stats_duration_ms FLOAT8,
  stats_extraction_latency_ms FLOAT8,
  stats_sensor_latency_ms FLOAT8,
  stats_ingest_latency_ms FLOAT8,

  -- Metadata as JSONB for extensibility
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,

  -- System timestamps
  created_at TIMESTAMP DEFAULT now(),
  updated_at TIMESTAMP DEFAULT now()
);

-- Performance indexes
CREATE INDEX IF NOT EXISTS idx_l7_flow_key ON l7_events(flow_key);
CREATE INDEX IF NOT EXISTS idx_l7_event_type ON l7_events(event_type);
CREATE INDEX IF NOT EXISTS idx_l7_observed_at ON l7_events(observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_l7_created_at ON l7_events(created_at DESC);

-- NDPI enrichment indexes for filtering and alerting
CREATE INDEX IF NOT EXISTS idx_l7_ndpi_protocol ON l7_events(ndpi_protocol);
CREATE INDEX IF NOT EXISTS idx_l7_ndpi_category ON l7_events(ndpi_category);
CREATE INDEX IF NOT EXISTS idx_l7_ndpi_application ON l7_events(ndpi_application);

-- Certificate query indexes
CREATE INDEX IF NOT EXISTS idx_l7_cert_leaf_sha256 ON l7_events(cert_leaf_sha256);
CREATE INDEX IF NOT EXISTS idx_l7_cert_issuer_cn ON l7_events(cert_issuer_cn);

-- 5-tuple indexes for network queries
CREATE INDEX IF NOT EXISTS idx_l7_src_dst_ip ON l7_events(src_ip, dst_ip);
CREATE INDEX IF NOT EXISTS idx_l7_src_ip ON l7_events(src_ip);
CREATE INDEX IF NOT EXISTS idx_l7_dst_ip ON l7_events(dst_ip);
CREATE INDEX IF NOT EXISTS idx_l7_ports ON l7_events(src_port, dst_port);

-- SNI index for TLS filtering
CREATE INDEX IF NOT EXISTS idx_l7_tls_sni ON l7_events(tls_sni);

-- Batch tracking
CREATE INDEX IF NOT EXISTS idx_l7_batch_id ON l7_events(batch_id);

-- JSONB metadata index (supports flexible schema growth)
CREATE INDEX IF NOT EXISTS idx_l7_metadata ON l7_events USING gin (metadata);

-- Composite indexes for common queries
CREATE INDEX IF NOT EXISTS idx_l7_ndpi_time ON l7_events(ndpi_protocol, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_l7_cert_time ON l7_events(cert_leaf_sha256, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_l7_flow_time ON l7_events(flow_key, observed_at DESC);

-- Convert table into a TimescaleDB hypertable for time-series performance when the extension is available
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'timescaledb') THEN
        CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;
        PERFORM create_hypertable(
            'l7_events',
            'observed_at',
            if_not_exists => TRUE,
            chunk_time_interval => interval '1 day'
        );
    ELSE
        RAISE NOTICE 'TimescaleDB extension not installed; hypertable creation skipped.';
    END IF;
END;
$$;
`

// ANCHOR: eBPF Event Schema - Multi-Program & Multi-NIC Ready - Feb 2, 2026
// WHY: Persist eBPF kernel monitoring events (connections, packet drops) with multi-NIC support
// WHAT: PostgreSQL schema with interface identification fields and multi-program tagging
// HOW: Create table with nullable interface fields (ready for future kernel capture), optimized indexes

const createEBPFEventsTable = `
CREATE TABLE IF NOT EXISTS ebpf_events (
  -- Event identification
  id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,                      -- "connection", "packet_drop", etc.
  program_name TEXT NOT NULL,                    -- "connection_tracer", "packet_drop_monitor"
  created_at TIMESTAMP DEFAULT now(),
  observed_at TIMESTAMP NOT NULL,

  -- MULTI-NIC SUPPORT: Interface identification (nullable for phase 1A, populated in phase 1B)
  interface_name TEXT,                           -- "eth0", "eth1", "wlan0" (indexed, nullable for now)
  interface_index INT,                           -- Linux interface index (indexed, nullable)

  -- Process information
  pid BIGINT NOT NULL,
  command TEXT NOT NULL,

  -- Kubernetes/Container metadata (automatic enrichment)
  k8s_node_name TEXT,
  k8s_pod_name TEXT,
  k8s_namespace TEXT,

  -- Network information (5-tuple for flows)
  src_ip INET,
  dst_ip INET,
  src_port INT,
  dst_port INT,
  protocol TEXT,
  ip_version INT,
  address_family INT,                            -- AF_INET (2) or AF_INET6 (10)

  -- Connection-specific fields
  connection_state TEXT,                         -- "established", "closed", "syn_sent", etc.
  socket_type TEXT,                              -- "STREAM", "DGRAM", etc.
  bytes_sent BIGINT,
  bytes_received BIGINT,
  duration_ms FLOAT8,                            -- Connection duration in milliseconds
  return_code INT,                               -- System call return code

  -- Packet drop-specific fields
  drop_reason TEXT,
  dropped_count INT,
  drop_code INT,

  -- Flexible metadata (JSONB for extensibility and future event types)
  metadata JSONB DEFAULT '{}'::jsonb,

  -- System timestamps
  updated_at TIMESTAMP DEFAULT now()
);

-- MULTI-NIC OPTIMIZED INDEXES
-- Filter by interface (ready for phase 1B)
CREATE INDEX IF NOT EXISTS idx_ebpf_interface ON ebpf_events(interface_name, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_ebpf_interface_idx ON ebpf_events(interface_index, observed_at DESC);

-- Filter by program
CREATE INDEX IF NOT EXISTS idx_ebpf_program ON ebpf_events(program_name, observed_at DESC);

-- Filter by event type
CREATE INDEX IF NOT EXISTS idx_ebpf_event_type ON ebpf_events(event_type, observed_at DESC);

-- Network analysis
CREATE INDEX IF NOT EXISTS idx_ebpf_src_dst ON ebpf_events(src_ip, dst_ip, interface_name);
CREATE INDEX IF NOT EXISTS idx_ebpf_src_ip ON ebpf_events(src_ip, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_ebpf_dst_ip ON ebpf_events(dst_ip, observed_at DESC);

-- Process analysis
CREATE INDEX IF NOT EXISTS idx_ebpf_pid ON ebpf_events(pid, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_ebpf_command ON ebpf_events(command, observed_at DESC);

-- Time-based queries
CREATE INDEX IF NOT EXISTS idx_ebpf_time ON ebpf_events(observed_at DESC);

-- Kubernetes queries (if metadata available)
CREATE INDEX IF NOT EXISTS idx_ebpf_k8s_pod ON ebpf_events(k8s_namespace, k8s_pod_name, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_ebpf_k8s_node ON ebpf_events(k8s_node_name, observed_at DESC);

-- Protocol and flow analysis
CREATE INDEX IF NOT EXISTS idx_ebpf_protocol ON ebpf_events(protocol, observed_at DESC);

-- Flexible metadata queries
CREATE INDEX IF NOT EXISTS idx_ebpf_metadata ON ebpf_events USING gin (metadata);

-- Composite indexes for common queries
CREATE INDEX IF NOT EXISTS idx_ebpf_interface_time ON ebpf_events(interface_name, observed_at DESC, event_type);
CREATE INDEX IF NOT EXISTS idx_ebpf_interface_pid ON ebpf_events(interface_name, pid, observed_at DESC);

-- OPTIONAL: View for multi-NIC statistics
CREATE OR REPLACE VIEW ebpf_interface_stats AS
SELECT
  interface_name,
  event_type,
  COUNT(*) as event_count,
  COUNT(DISTINCT pid) as unique_processes,
  COUNT(DISTINCT dst_ip) as unique_destinations,
  SUM(COALESCE(dropped_count, 0)) as total_dropped,
  SUM(COALESCE(bytes_sent + bytes_received, 0)) as total_bytes,
  MIN(observed_at) as first_event,
  MAX(observed_at) as last_event
FROM ebpf_events
WHERE interface_name IS NOT NULL
GROUP BY interface_name, event_type;
`

// RunMigrations creates all required tables and indexes.
func RunMigrations(ctx context.Context, conn *pgx.Conn) error {
	_, err := conn.Exec(ctx, createL7EventsTable)
	if err != nil {
		return fmt.Errorf("failed to create l7_events table: %w", err)
	}

	_, err = conn.Exec(ctx, createEBPFEventsTable)
	if err != nil {
		return fmt.Errorf("failed to create ebpf_events table: %w", err)
	}

	return nil
}

// DropAllTables removes all tables and views (for testing).
// ANCHOR: Complete test cleanup for Phase 1B schema - Issue #3 Fix - Feb 6, 2026
// WHY: Tests must leave database in clean state between runs
// WHAT: Drop all tables and dependent views created by migrations
// HOW: Drop ebpf_interface_stats view first (depends on ebpf_events), then tables
func DropAllTables(ctx context.Context, conn *pgx.Conn) error {
	// Drop views first (depends on tables)
	_, err := conn.Exec(ctx, `DROP VIEW IF EXISTS ebpf_interface_stats CASCADE;`)
	if err != nil {
		return fmt.Errorf("failed to drop ebpf_interface_stats view: %w", err)
	}

	// Drop tables
	_, err = conn.Exec(ctx, `DROP TABLE IF EXISTS ebpf_events CASCADE;`)
	if err != nil {
		return fmt.Errorf("failed to drop ebpf_events table: %w", err)
	}

	_, err = conn.Exec(ctx, `DROP TABLE IF EXISTS l7_events CASCADE;`)
	if err != nil {
		return fmt.Errorf("failed to drop l7_events table: %w", err)
	}

	return nil
}
