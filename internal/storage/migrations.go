// Package storage provides event storage implementations.
package storage

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v4"
)

// ANCHOR: eBPF Metadata Window Aggregate Table - Phase 2
// WHY: Persist aggregate metadata keyed by minute bucket + flow dimensions
// WHAT: Durable aggregate table with compact counters and minimal indexing
// HOW: Regular (logged) PostgreSQL table with composite key and supporting indexes
// Stores: bucket_epoch + aggregate counters, keyed by src/dst IP+port and interface
const createEBPFMetaWindowTable = `
CREATE TABLE IF NOT EXISTS ebpf_meta_window (
  bucket_epoch      BIGINT NOT NULL,
  src_ip            INET   NOT NULL,
  dst_ip            INET   NOT NULL,
  src_port          INT    NOT NULL DEFAULT 0,
  dst_port          INT    NOT NULL DEFAULT 0,
  interface_name    TEXT   NOT NULL DEFAULT '',
  sni               TEXT   NOT NULL DEFAULT '',
  pid               BIGINT NOT NULL DEFAULT 0,
  active_seconds    BIGINT NOT NULL DEFAULT 0,
  packets_in        BIGINT NOT NULL DEFAULT 0,
  packets_out       BIGINT NOT NULL DEFAULT 0,
  session_count     BIGINT NOT NULL DEFAULT 0,
  first_seen_epoch  BIGINT NOT NULL,
  last_seen_epoch   BIGINT NOT NULL,
  PRIMARY KEY (src_ip, dst_ip, src_port, dst_port, interface_name)
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

-- Index for SNI queries
CREATE INDEX IF NOT EXISTS idx_ebpf_meta_window_sni
  ON ebpf_meta_window (sni, bucket_epoch DESC);

-- Index for process queries
CREATE INDEX IF NOT EXISTS idx_ebpf_meta_window_pid
  ON ebpf_meta_window (pid, bucket_epoch DESC);
`

// ANCHOR: Ensure durability for existing deployments
// WHY: Older schema revisions created ebpf_meta_window as UNLOGGED, which can lose data on crash
// WHAT: Promote ebpf_meta_window to LOGGED when needed
// HOW: Check relpersistence and apply ALTER TABLE ... SET LOGGED conditionally
const ensureEBPFMetaWindowLogged = `
DO $$
DECLARE
  persistence "char";
BEGIN
  SELECT c.relpersistence INTO persistence
  FROM pg_class c
  WHERE c.oid = 'ebpf_meta_window'::regclass;

  IF persistence = 'u' THEN
    EXECUTE 'ALTER TABLE ebpf_meta_window SET LOGGED';
  END IF;
END;
$$;
`

// ANCHOR: Normalize metadata window merge key for existing deployments
// WHY: Older schemas keyed rows by bucket/sni/pid and produced duplicates for same 5-tuple flow
// WHAT: Rebuild schema so rows merge by src_ip,dst_ip,src_port,dst_port,interface_name
// HOW: Conditionally rebuild table and aggregate existing rows into the new primary key
const ensureEBPFMetaWindowMergeKeySchema = `
DO $$
DECLARE
  has_target_pk BOOLEAN;
BEGIN
  ALTER TABLE ebpf_meta_window
    ADD COLUMN IF NOT EXISTS sni TEXT NOT NULL DEFAULT '';
  ALTER TABLE ebpf_meta_window
    ADD COLUMN IF NOT EXISTS pid BIGINT NOT NULL DEFAULT 0;

  SELECT EXISTS (
    SELECT 1
    FROM pg_constraint c
    JOIN pg_class t ON c.conrelid = t.oid
    WHERE t.relname = 'ebpf_meta_window'
      AND c.contype = 'p'
      AND pg_get_constraintdef(c.oid) = 'PRIMARY KEY (src_ip, dst_ip, src_port, dst_port, interface_name)'
  ) INTO has_target_pk;

  IF NOT has_target_pk THEN
    CREATE TABLE ebpf_meta_window_rebuild (
      bucket_epoch      BIGINT NOT NULL,
      src_ip            INET   NOT NULL,
      dst_ip            INET   NOT NULL,
      src_port          INT    NOT NULL DEFAULT 0,
      dst_port          INT    NOT NULL DEFAULT 0,
      interface_name    TEXT   NOT NULL DEFAULT '',
      sni               TEXT   NOT NULL DEFAULT '',
      pid               BIGINT NOT NULL DEFAULT 0,
      active_seconds    BIGINT NOT NULL DEFAULT 0,
      packets_in        BIGINT NOT NULL DEFAULT 0,
      packets_out       BIGINT NOT NULL DEFAULT 0,
      session_count     BIGINT NOT NULL DEFAULT 0,
      first_seen_epoch  BIGINT NOT NULL,
      last_seen_epoch   BIGINT NOT NULL,
      PRIMARY KEY (src_ip, dst_ip, src_port, dst_port, interface_name)
    );

    INSERT INTO ebpf_meta_window_rebuild (
      bucket_epoch, src_ip, dst_ip, src_port, dst_port, interface_name, sni, pid,
      active_seconds, packets_in, packets_out, session_count, first_seen_epoch, last_seen_epoch
    )
    SELECT
      COALESCE(MAX(bucket_epoch), 0) AS bucket_epoch,
      src_ip,
      dst_ip,
      src_port,
      dst_port,
      interface_name,
      COALESCE(MAX(NULLIF(sni, '')), '') AS sni,
      COALESCE(MAX(pid), 0) AS pid,
      COALESCE(SUM(active_seconds), 0) AS active_seconds,
      COALESCE(SUM(packets_in), 0) AS packets_in,
      COALESCE(SUM(packets_out), 0) AS packets_out,
      COALESCE(SUM(session_count), 0) AS session_count,
      COALESCE(MIN(first_seen_epoch), 0) AS first_seen_epoch,
      COALESCE(MAX(last_seen_epoch), 0) AS last_seen_epoch
    FROM ebpf_meta_window
    GROUP BY src_ip, dst_ip, src_port, dst_port, interface_name;

    DROP TABLE ebpf_meta_window CASCADE;
    ALTER TABLE ebpf_meta_window_rebuild RENAME TO ebpf_meta_window;
  END IF;
END;
$$;
`

// ANCHOR: Hard block data deletion from ebpf_meta_window
// WHY: Enforce "retain all data" even if an external job or stale binary issues DELETE/TRUNCATE
// WHAT: Install trigger function + trigger that rejects DELETE and TRUNCATE operations
// HOW: CREATE OR REPLACE FUNCTION + conditional CREATE TRIGGER via pg_trigger catalog
const ensureEBPFMetaWindowNoDelete = `
CREATE OR REPLACE FUNCTION prevent_ebpf_meta_window_delete()
RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'deletion is disabled for table ebpf_meta_window';
END;
$$ LANGUAGE plpgsql;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_trigger
    WHERE tgname = 'trg_prevent_ebpf_meta_window_delete'
      AND tgrelid = 'ebpf_meta_window'::regclass
      AND NOT tgisinternal
  ) THEN
    CREATE TRIGGER trg_prevent_ebpf_meta_window_delete
    BEFORE DELETE OR TRUNCATE ON ebpf_meta_window
    FOR EACH STATEMENT
    EXECUTE FUNCTION prevent_ebpf_meta_window_delete();
  END IF;
END;
$$;
`

// RunMigrations creates the metadata window table.
// ANCHOR: Only metadata window - Phase 2 aggregate storage - Mar 21, 2026
// WHY: Store only sessionized connection metadata with src/dst ports and interface
// WHAT: Create durable table with bucket_epoch, IPs, ports, interface as composite key
// HOW: Create/migrate schema on startup with idempotent SQL blocks
func RunMigrations(ctx context.Context, conn *pgx.Conn) error {
	_, err := conn.Exec(ctx, createEBPFMetaWindowTable)
	if err != nil {
		return fmt.Errorf("failed to create ebpf_meta_window table: %w", err)
	}

	_, err = conn.Exec(ctx, ensureEBPFMetaWindowLogged)
	if err != nil {
		return fmt.Errorf("failed to enforce ebpf_meta_window durability: %w", err)
	}

	_, err = conn.Exec(ctx, ensureEBPFMetaWindowMergeKeySchema)
	if err != nil {
		return fmt.Errorf("failed to migrate ebpf_meta_window schema: %w", err)
	}

	// Re-run index creation after potential table rebuild in migration block.
	_, err = conn.Exec(ctx, createEBPFMetaWindowTable)
	if err != nil {
		return fmt.Errorf("failed to ensure ebpf_meta_window indexes: %w", err)
	}

	_, err = conn.Exec(ctx, ensureEBPFMetaWindowNoDelete)
	if err != nil {
		return fmt.Errorf("failed to enforce ebpf_meta_window no-delete policy: %w", err)
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
