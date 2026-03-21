// Package storage provides event storage implementations.
package storage

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v4"
)

// ANCHOR: eBPF Metadata Window Aggregate Table - Phase 2
// WHY: Persist only short-window aggregate metadata keyed by minute bucket + flow dimensions
// WHAT: Lightweight aggregate table for bounded retention and lower write amplification
// HOW: UNLOGGED table with compact counters and minimal indexing
// Stores: bucket_epoch, src_ip, dst_ip, src_port, dst_port, interface_name, sni
const createEBPFMetaWindowTable = `
CREATE UNLOGGED TABLE IF NOT EXISTS ebpf_meta_window (
  bucket_epoch      BIGINT NOT NULL,
  src_ip            INET   NOT NULL,
  dst_ip            INET   NOT NULL,
  src_port          INT    NOT NULL,
  dst_port          INT    NOT NULL,
  interface_name    TEXT   NOT NULL,
  active_seconds    BIGINT NOT NULL DEFAULT 0,
  packets_in        BIGINT NOT NULL DEFAULT 0,
  packets_out       BIGINT NOT NULL DEFAULT 0,
  session_count     BIGINT NOT NULL DEFAULT 0,
  first_seen_epoch  BIGINT NOT NULL,
  last_seen_epoch   BIGINT NOT NULL,
  PRIMARY KEY (bucket_epoch, src_ip, dst_ip, src_port, dst_port, interface_name)
);

-- Essential index for time-based queries
CREATE INDEX IF NOT EXISTS idx_ebpf_meta_window_time
  ON ebpf_meta_window (bucket_epoch DESC);

-- Index for destination IP queries
CREATE INDEX IF NOT EXISTS idx_ebpf_meta_window_dst_ip
  ON ebpf_meta_window (dst_ip, bucket_epoch DESC);

-- Index for interface queries
CREATE INDEX IF NOT EXISTS idx_ebpf_meta_window_iface
  ON ebpf_meta_window (interface_name, bucket_epoch DESC);
`

// RunMigrations creates the metadata window table.
// ANCHOR: Only metadata window - Phase 2 aggregate storage - Mar 21, 2026
// WHY: Store only sessionized connection metadata with src/dst ports and interface
// WHAT: Create UNLOGGED table with bucket_epoch, IPs, ports, interface as composite key
// HOW: Single CREATE IF NOT EXISTS - no ALTER statements, all columns defined upfront
func RunMigrations(ctx context.Context, conn *pgx.Conn) error {
	_, err := conn.Exec(ctx, createEBPFMetaWindowTable)
	if err != nil {
		return fmt.Errorf("failed to create ebpf_meta_window table: %w", err)
	}

	return nil
}

// DropAllTables removes the metadata window table (for testing).
// ANCHOR: Clean metadata window for test isolation - Mar 21, 2026
// WHY: Tests must leave database in clean state between runs
// WHAT: Drop only ebpf_meta_window table
// HOW: Simple DROP IF EXISTS with CASCADE for indexes
func DropAllTables(ctx context.Context, conn *pgx.Conn) error {
	_, err := conn.Exec(ctx, `DROP TABLE IF EXISTS ebpf_meta_window CASCADE;`)
	if err != nil {
		return fmt.Errorf("failed to drop ebpf_meta_window table: %w", err)
	}

	return nil
}
