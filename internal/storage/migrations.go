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

// RunMigrations creates all required tables and indexes.
func RunMigrations(ctx context.Context, conn *pgx.Conn) error {
	_, err := conn.Exec(ctx, createL7EventsTable)
	if err != nil {
		return fmt.Errorf("failed to create l7_events table: %w", err)
	}
	return nil
}

// DropAllTables removes all tables (for testing).
func DropAllTables(ctx context.Context, conn *pgx.Conn) error {
	_, err := conn.Exec(ctx, `DROP TABLE IF EXISTS l7_events CASCADE;`)
	if err != nil {
		return fmt.Errorf("failed to drop tables: %w", err)
	}
	return nil
}
