// Package storage provides event storage implementations.
package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/srodi/ebpf-server/internal/core"
	"github.com/srodi/ebpf-server/pkg/logger"
)

// ANCHOR: PostgreSQL Storage Implementation - Jan 31, 2026
// WHY: Persist L7 events with NDPI metadata to PostgreSQL for querying and long-term retention
// WHAT: PostgreSQLStorage struct implementing core.EventSink interface
// HOW: Use pgx connection pool for efficient DB access, marshal events to structured columns + JSONB

// PostgreSQLStorage implements EventSink using PostgreSQL.
// It stores L7 and eBPF events with proper routing based on event type.
// For L7 events (webhook receivers): routes to l7_events table with NDPI enrichment
// For eBPF events (kernel monitoring): routes to ebpf_events table with multi-NIC support
type PostgreSQLStorage struct {
	pool        *pgxpool.Pool
	l7Storage   *PostgreSQLL7Storage
	ebpfStorage *EBPFEventStorage
	ebpfQueries *EBPFQueries
	mu          sync.RWMutex
}

// EBPFMetaWindowRow represents one aggregated metadata row for ebpf_meta_window.
type EBPFMetaWindowRow struct {
	BucketEpoch    int64
	SrcIP          string
	DstIP          string
	SrcPort        int64
	DstPort        int64
	InterfaceName  string
	SNI            string
	PID            int64
	ActiveSeconds  int64
	PacketsIn      int64
	PacketsOut     int64
	SessionCount   int64
	FirstSeenEpoch int64
	LastSeenEpoch  int64
}

// UpsertMetaWindowRows persists aggregated metadata rows into ebpf_meta_window.
// Rows are applied in a single transaction and queued as a pgx batch.
func (s *PostgreSQLStorage) UpsertMetaWindowRows(ctx context.Context, rows []EBPFMetaWindowRow) error {
	if len(rows) == 0 {
		return nil
	}

	// ANCHOR: Log metadata window upsert operations - March 21, 2026
	logger.Infof("[DB] Upserting %d rows into ebpf_meta_window", len(rows))

	s.mu.RLock()
	defer s.mu.RUnlock()

	sql := `
		INSERT INTO ebpf_meta_window (
			bucket_epoch, src_ip, dst_ip, src_port, dst_port, interface_name, sni, pid,
			active_seconds, packets_in, packets_out, session_count,
			first_seen_epoch, last_seen_epoch
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8,
			$9, $10, $11, $12,
			$13, $14
		)
		ON CONFLICT (src_ip, dst_ip, src_port, dst_port, interface_name) DO UPDATE SET
			bucket_epoch = GREATEST(ebpf_meta_window.bucket_epoch, EXCLUDED.bucket_epoch),
			sni = CASE
				WHEN EXCLUDED.sni <> '' THEN EXCLUDED.sni
				ELSE ebpf_meta_window.sni
			END,
			pid = CASE
				WHEN EXCLUDED.pid > 0 THEN EXCLUDED.pid
				ELSE ebpf_meta_window.pid
			END,
			active_seconds = ebpf_meta_window.active_seconds + EXCLUDED.active_seconds,
			packets_in = ebpf_meta_window.packets_in + EXCLUDED.packets_in,
			packets_out = ebpf_meta_window.packets_out + EXCLUDED.packets_out,
			session_count = ebpf_meta_window.session_count + EXCLUDED.session_count,
			first_seen_epoch = LEAST(ebpf_meta_window.first_seen_epoch, EXCLUDED.first_seen_epoch),
			last_seen_epoch = GREATEST(ebpf_meta_window.last_seen_epoch, EXCLUDED.last_seen_epoch)
	`

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("failed to begin meta window upsert tx: %w", err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	batch := &pgx.Batch{}
	for _, row := range rows {
		batch.Queue(sql,
			row.BucketEpoch, row.SrcIP, row.DstIP, row.SrcPort, row.DstPort, row.InterfaceName, row.SNI, row.PID,
			row.ActiveSeconds, row.PacketsIn, row.PacketsOut, row.SessionCount,
			row.FirstSeenEpoch, row.LastSeenEpoch,
		)
	}

	results := tx.SendBatch(ctx, batch)
	for i := 0; i < len(rows); i++ {
		if _, err := results.Exec(); err != nil {
			_ = results.Close()
			logger.Errorf("[DB] UpsertMetaWindowRows failed at row %d: %v", i, err)
			return fmt.Errorf("meta window batch upsert failed at row %d: %w", i, err)
		}
	}
	if err := results.Close(); err != nil {
		logger.Errorf("[DB] Meta window batch close failed: %v", err)
		return fmt.Errorf("meta window batch close failed: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		logger.Errorf("[DB] Failed to commit meta window upsert tx: %v", err)
		return fmt.Errorf("failed to commit meta window upsert tx: %w", err)
	}

	logger.Infof("[DB] ebpf_meta_window upsert committed (%d rows)", len(rows))
	return nil
}

// NewPostgreSQLStorage creates a new PostgreSQL-backed event storage.
// connStr should be a PostgreSQL connection string (e.g., "postgres://user:pass@localhost/dbname").
// ANCHOR: Event Storage Initialization - Feb 3, 2026
// WHY: Initialize both L7 and eBPF event storage backends with proper routing
// WHAT: Create PostgreSQLStorage with separate L7 and eBPF storage instances
// HOW: Set up connection pool, run migrations, and initialize both storage backends
func NewPostgreSQLStorage(ctx context.Context, connStr string) (*PostgreSQLStorage, error) {
	// Create connection pool
	config, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse connection string: %w", err)
	}

	// Configure pool
	config.MaxConns = 20
	config.MinConns = 5
	config.MaxConnLifetime = 15 * time.Minute
	config.MaxConnIdleTime = 5 * time.Minute

	pool, err := pgxpool.ConnectConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}

	// Test connection
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping PostgreSQL: %w", err)
	}

	// Run migrations
	conn, err := pool.Acquire(ctx)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to acquire connection for migrations: %w", err)
	}
	defer conn.Release()

	if err := RunMigrations(ctx, conn.Conn()); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	logger.Infof("✅ PostgreSQL storage initialized with connection pool (max_conns=20, min_conns=5)")

	return &PostgreSQLStorage{
		pool:        pool,
		l7Storage:   &PostgreSQLL7Storage{pool: pool},
		ebpfStorage: NewEBPFEventStorage(pool),
		ebpfQueries: NewEBPFQueries(pool),
	}, nil
}

// PostgreSQLL7Storage handles storage of L7 webhook events to PostgreSQL.
// This type encapsulates the L7-specific storage logic that was previously in PostgreSQLStorage.
type PostgreSQLL7Storage struct {
	pool *pgxpool.Pool
}

// Store saves an event to PostgreSQL by routing to appropriate backend.
// ANCHOR: Event Routing by Type - Feb 3, 2026
// WHY: Route events to correct storage table based on event type
// WHAT: Determine event type and delegate to L7 or eBPF storage
// HOW: Check event type field; route eBPF events (connection, packet_drop) to eBPF storage, others to L7
func (s *PostgreSQLStorage) Store(ctx context.Context, event core.Event) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Route event to appropriate storage backend based on type
	eventType := event.Type()

	// ANCHOR: eBPF Event Routing - Feb 3, 2026
	// WHY: Separate storage for kernel-level events to enable multi-NIC support and proper indexing
	// WHAT: Route connection, packet_drop, and other kernel events to eBPF storage
	// HOW: Check event type and delegate to EBPFEventStorage.Store()
	if eventType == "connection" || eventType == "packet_drop" || eventType == "file_operation" || eventType == "process_exec" {
		// Route to eBPF event storage (supports multi-NIC and multi-program)
		return s.ebpfStorage.Store(ctx, event)
	}

	// Default to L7 storage for webhook events
	return s.storeL7Event(ctx, event)
}

// storeL7Event stores an L7 webhook event to PostgreSQL.
// This method contains the original L7-specific storage logic.
func (s *PostgreSQLStorage) storeL7Event(ctx context.Context, event core.Event) error {
	// Marshal event metadata to JSONB
	metadata := event.Metadata()
	if metadata == nil {
		metadata = map[string]interface{}{}
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		logger.Errorf("Failed to serialize metadata: %v", err)
		return fmt.Errorf("failed to marshal event metadata: %w", err)
	}

	// Extract NDPI fields if present
	ndpiProtocol := ""
	ndpiCategory := ""
	ndpiApplication := ""
	var ndpiConfidence float64 = 0
	var ndpiID int = 0

	if ndpi, ok := metadata["ndpi"].(map[string]interface{}); ok {
		if proto, ok := ndpi["protocol"].(string); ok {
			ndpiProtocol = proto
		}
		if cat, ok := ndpi["category"].(string); ok {
			ndpiCategory = cat
		}
		if app, ok := ndpi["application"].(string); ok {
			ndpiApplication = app
		}
		if conf, ok := ndpi["confidence"].(float64); ok {
			ndpiConfidence = conf
		}
		if id, ok := ndpi["ndpi_id"].(int); ok {
			ndpiID = id
		}
	}

	// Extract other common fields
	flowID := ""
	flowKey := ""
	batchID := ""
	source := ""
	schemaVersion := ""

	if v, ok := metadata["flow_id"].(string); ok {
		flowID = v
	}
	if v, ok := metadata["flow_key"].(string); ok {
		flowKey = v
	}
	if v, ok := metadata["batch_id"].(string); ok {
		batchID = v
	}
	if v, ok := metadata["source"].(string); ok {
		source = v
	}
	if v, ok := metadata["schema_version"].(string); ok {
		schemaVersion = v
	}

	// Extract TLS fields
	var tlsSNI, tlsALPN, tlsVersion *string
	if tls, ok := metadata["tls"].(map[string]interface{}); ok {
		if sni, ok := tls["sni"].(string); ok {
			tlsSNI = &sni
		}
		if alpn, ok := tls["alpn"].(string); ok {
			tlsALPN = &alpn
		}
		if ver, ok := tls["version"].(string); ok {
			tlsVersion = &ver
		}
	}

	// Extract fingerprint fields
	var ja3, ja4, ja4Plus *string
	if fp, ok := metadata["fingerprints"].(map[string]interface{}); ok {
		if j3, ok := fp["ja3"].(string); ok {
			ja3 = &j3
		}
		if j4, ok := fp["ja4"].(string); ok {
			ja4 = &j4
		}
		if j4p, ok := fp["ja4_plus"].(string); ok {
			ja4Plus = &j4p
		}
	}

	// Extract certificate fields
	var certLeafSHA256, certIssuerCN *string
	var certExpiryTS *int64
	if cert, ok := metadata["certificate"].(map[string]interface{}); ok {
		if hash, ok := cert["leaf_sha256"].(string); ok {
			certLeafSHA256 = &hash
		}
		if cn, ok := cert["issuer_cn"].(string); ok {
			certIssuerCN = &cn
		}
		if expiry, ok := cert["expiry_ts"].(float64); ok {
			expiryInt := int64(expiry)
			certExpiryTS = &expiryInt
		}
	}

	// Extract IP and port fields
	var srcIP, dstIP *string
	var srcPort, dstPort *int
	if sip, ok := metadata["src_ip"].(string); ok {
		srcIP = &sip
	}
	if dip, ok := metadata["dst_ip"].(string); ok {
		dstIP = &dip
	}
	if sport, ok := metadata["src_port"].(float64); ok {
		p := int(sport)
		srcPort = &p
	}
	if dport, ok := metadata["dst_port"].(float64); ok {
		p := int(dport)
		dstPort = &p
	}

	// Extract protocol and IP version
	var protocol *string
	var ipVersion *int
	if proto, ok := metadata["protocol"].(string); ok {
		protocol = &proto
	}
	if ver, ok := metadata["ip_version"].(float64); ok {
		v := int(ver)
		ipVersion = &v
	}

	// Extract verdict fields
	var verdictAction, verdictRuleID *string
	var verdictPriority *int
	if verdict, ok := metadata["verdict"].(map[string]interface{}); ok {
		if action, ok := verdict["action"].(string); ok {
			verdictAction = &action
		}
		if ruleID, ok := verdict["rule_id"].(string); ok {
			verdictRuleID = &ruleID
		}
		if priority, ok := verdict["priority"].(float64); ok {
			p := int(priority)
			verdictPriority = &p
		}
	}

	// Extract stats
	var statsBytesVal *int64
	var statsPacketsVal *int
	var statsDurationVal *float64
	if stats, ok := metadata["stats"].(map[string]interface{}); ok {
		if bytes, ok := stats["bytes"].(float64); ok {
			b := int64(bytes)
			statsBytesVal = &b
		}
		if packets, ok := stats["packets"].(float64); ok {
			p := int(packets)
			statsPacketsVal = &p
		}
		if duration, ok := stats["duration_ms"].(float64); ok {
			statsDurationVal = &duration
		}
	}

	// Insert into PostgreSQL
	sql := `
		INSERT INTO l7_events (
			id, flow_id, flow_key, batch_id, source, schema_version, event_type,
			observed_at, src_ip, dst_ip, src_port, dst_port, protocol, ip_version,
			tls_sni, tls_alpn, tls_version,
			ja3, ja4, ja4_plus,
			cert_leaf_sha256, cert_issuer_cn, cert_expiry_ts,
			verdict_action, verdict_rule_id, verdict_priority,
			ndpi_protocol, ndpi_category, ndpi_application, ndpi_confidence, ndpi_id,
			stats_bytes, stats_packets, stats_duration_ms,
			metadata
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			to_timestamp($8 / 1000.0), $9, $10, $11, $12, $13, $14,
			$15, $16, $17,
			$18, $19, $20,
			$21, $22, $23,
			$24, $25, $26,
			$27, $28, $29, $30, $31,
			$32, $33, $34,
			$35
		)
		ON CONFLICT (id) DO NOTHING
	`

	// Get observed_at from metadata if available, otherwise use current time
	observedAt := time.Now().UnixMilli()
	if oa, ok := metadata["observed_at"].(float64); ok {
		observedAt = int64(oa)
	}

	logger.Debugf("[DB] Storing L7 event id=%s type=%s src=%s dst=%s", event.ID(), event.Type(), srcIP, dstIP)

	_, err = s.pool.Exec(ctx, sql,
		event.ID(), flowID, flowKey, batchID, source, schemaVersion, event.Type(),
		observedAt, srcIP, dstIP, srcPort, dstPort, protocol, ipVersion,
		tlsSNI, tlsALPN, tlsVersion,
		ja3, ja4, ja4Plus,
		certLeafSHA256, certIssuerCN, certExpiryTS,
		verdictAction, verdictRuleID, verdictPriority,
		ndpiProtocol, ndpiCategory, ndpiApplication, ndpiConfidence, ndpiID,
		statsBytesVal, statsPacketsVal, statsDurationVal,
		metadataJSON,
	)

	if err != nil {
		logger.Errorf("[DB] storeL7Event failed id=%s: %v", event.ID(), err)
		return fmt.Errorf("failed to store event: %w", err)
	}

	logger.Infof("[DB] Stored L7 event id=%s type=%s src=%s->%s ndpi=%s/%s", event.ID(), event.Type(), srcIP, dstIP, ndpiProtocol, ndpiCategory)

	return nil
}

// Query retrieves events matching the criteria from PostgreSQL.
// ANCHOR: Query Routing by Event Type - Feb 3, 2026
// WHY: Route queries to correct table based on event type for optimal performance
// WHAT: Determine query table from event type and delegate to appropriate backend
// HOW: If event type is eBPF type, use eBPFEventStorage; otherwise use L7 storage
func (s *PostgreSQLStorage) Query(ctx context.Context, query core.Query) ([]core.Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Route to appropriate backend
	if query.EventType == "connection" || query.EventType == "packet_drop" || query.EventType == "file_operation" || query.EventType == "process_exec" {
		return s.ebpfStorage.Query(ctx, query)
	}

	// Default to L7 storage
	return s.queryL7Events(ctx, query)
}

// queryL7Events queries events from the L7 events table.
func (s *PostgreSQLStorage) queryL7Events(ctx context.Context, query core.Query) ([]core.Event, error) {
	// Build WHERE clause
	var args []interface{}
	whereClause := "WHERE 1=1"
	argIndex := 1

	if query.EventType != "" {
		whereClause += fmt.Sprintf(" AND event_type = $%d", argIndex)
		args = append(args, query.EventType)
		argIndex++
	}

	if query.PID != 0 {
		// L7 events don't have PID, but filter anyway for consistency
		whereClause += fmt.Sprintf(" AND metadata->>'pid' = $%d", argIndex)
		args = append(args, fmt.Sprintf("%d", query.PID))
		argIndex++
	}

	if query.Command != "" {
		whereClause += fmt.Sprintf(" AND metadata->>'command' LIKE $%d", argIndex)
		args = append(args, query.Command+"%")
		argIndex++
	}

	if !query.Since.IsZero() {
		whereClause += fmt.Sprintf(" AND observed_at >= $%d", argIndex)
		args = append(args, query.Since)
		argIndex++
	}

	if !query.Until.IsZero() {
		whereClause += fmt.Sprintf(" AND observed_at <= $%d", argIndex)
		args = append(args, query.Until)
		argIndex++
	}

	// Build ORDER BY and LIMIT
	orderBy := "ORDER BY observed_at DESC"
	limitClause := ""
	if query.Limit > 0 {
		limitClause = fmt.Sprintf(" LIMIT %d", query.Limit)
	}

	sql := fmt.Sprintf(`
		SELECT
			id, event_type, metadata
		FROM l7_events
		%s
		%s
		%s
	`, whereClause, orderBy, limitClause)

	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		logger.Errorf("Failed to query events from PostgreSQL: %v", err)
		return nil, fmt.Errorf("failed to query events: %w", err)
	}
	defer rows.Close()

	var events []core.Event
	for rows.Next() {
		var id, eventType string
		var metadataJSON string

		if err := rows.Scan(&id, &eventType, &metadataJSON); err != nil {
			logger.Errorf("Failed to scan row: %v", err)
			continue
		}

		var metadata map[string]interface{}
		if err := json.Unmarshal([]byte(metadataJSON), &metadata); err != nil {
			logger.Errorf("Failed to unmarshal metadata: %v", err)
			continue
		}

		// Reconstruct event from stored data
		event := &postgresEvent{
			id:       id,
			typ:      eventType,
			metadata: metadata,
		}

		events = append(events, event)
	}

	if err = rows.Err(); err != nil {
		logger.Errorf("Row iteration error: %v", err)
		return nil, err
	}

	// Sort by timestamp (most recent first)
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp() > events[j].Timestamp()
	})

	return events, nil
}

// Count returns the number of events matching the criteria.
// ANCHOR: Count Routing by Event Type - Feb 3, 2026
// WHY: Route count queries to correct table for proper enumeration
// WHAT: Route count to eBPF or L7 storage based on event type
// HOW: Delegate to appropriate backend Count method
func (s *PostgreSQLStorage) Count(ctx context.Context, query core.Query) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Route to appropriate backend
	if query.EventType == "connection" || query.EventType == "packet_drop" || query.EventType == "file_operation" || query.EventType == "process_exec" {
		return s.ebpfStorage.Count(ctx, query)
	}

	// Default to L7 storage
	return s.countL7Events(ctx, query)
}

// countL7Events counts events in the L7 events table.
func (s *PostgreSQLStorage) countL7Events(ctx context.Context, query core.Query) (int, error) {
	// Build WHERE clause
	var args []interface{}
	whereClause := "WHERE 1=1"
	argIndex := 1

	if query.EventType != "" {
		whereClause += fmt.Sprintf(" AND event_type = $%d", argIndex)
		args = append(args, query.EventType)
		argIndex++
	}

	if !query.Since.IsZero() {
		whereClause += fmt.Sprintf(" AND observed_at >= $%d", argIndex)
		args = append(args, query.Since)
		argIndex++
	}

	if !query.Until.IsZero() {
		whereClause += fmt.Sprintf(" AND observed_at <= $%d", argIndex)
		args = append(args, query.Until)
		argIndex++
	}

	sql := fmt.Sprintf("SELECT COUNT(*) FROM l7_events %s", whereClause)

	var count int
	err := s.pool.QueryRow(ctx, sql, args...).Scan(&count)
	if err != nil {
		logger.Errorf("Failed to count events: %v", err)
		return 0, fmt.Errorf("failed to count events: %w", err)
	}

	return count, nil
}

// Close closes the connection pool.
func (s *PostgreSQLStorage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.pool != nil {
		s.pool.Close()
		logger.Infof("PostgreSQL connection pool closed")
	}
	return nil
}

// postgresEvent is a simple Event implementation for reconstructed events from PostgreSQL.
type postgresEvent struct {
	id       string
	typ      string
	metadata map[string]interface{}
}

func (e *postgresEvent) ID() string {
	return e.id
}

func (e *postgresEvent) Type() string {
	return e.typ
}

func (e *postgresEvent) PID() uint32 {
	if pid, ok := e.metadata["pid"].(float64); ok {
		return uint32(pid)
	}
	return 0
}

func (e *postgresEvent) Command() string {
	if cmd, ok := e.metadata["command"].(string); ok {
		return cmd
	}
	return ""
}

func (e *postgresEvent) Timestamp() uint64 {
	if ts, ok := e.metadata["timestamp"].(float64); ok {
		return uint64(ts)
	}
	return 0
}

func (e *postgresEvent) Time() time.Time {
	if timeStr, ok := e.metadata["time"].(string); ok {
		if t, err := time.Parse(time.RFC3339Nano, timeStr); err == nil {
			return t
		}
	}
	return time.Now()
}

func (e *postgresEvent) Metadata() map[string]interface{} {
	return e.metadata
}

func (e *postgresEvent) MarshalJSON() ([]byte, error) {
	m := map[string]interface{}{
		"id":        e.id,
		"type":      e.typ,
		"timestamp": e.Timestamp(),
		"time":      e.Time().Format(time.RFC3339Nano),
	}
	for k, v := range e.metadata {
		m[k] = v
	}
	return json.Marshal(m)
}
