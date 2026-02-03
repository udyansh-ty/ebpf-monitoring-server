// Package storage provides event storage implementations.
package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/srodi/ebpf-server/internal/core"
	"github.com/srodi/ebpf-server/pkg/logger"
)

// ANCHOR: PostgreSQL Storage Implementation - Jan 31, 2026
// WHY: Persist L7 events with NDPI metadata to PostgreSQL for querying and long-term retention
// WHAT: PostgreSQLStorage struct implementing core.EventSink interface
// HOW: Use pgx connection pool for efficient DB access, marshal events to structured columns + JSONB

// PostgreSQLStorage implements EventSink using PostgreSQL.
// It stores L7 events with full NDPI enrichment data for persistent storage and querying.
type PostgreSQLStorage struct {
	pool *pgxpool.Pool
	mu   sync.RWMutex
}

// NewPostgreSQLStorage creates a new PostgreSQL-backed event storage.
// connStr should be a PostgreSQL connection string (e.g., "postgres://user:pass@localhost/dbname").
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
		pool: pool,
	}, nil
}

// Store saves an event to PostgreSQL.
func (s *PostgreSQLStorage) Store(ctx context.Context, event core.Event) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

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

	_, err := s.pool.Exec(ctx, sql,
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
		logger.Errorf("Failed to store event to PostgreSQL: %v", err)
		return fmt.Errorf("failed to store event: %w", err)
	}

	logger.Debugf("💾 Stored L7 event to PostgreSQL: type=%s, ndpi=%s/%s", event.Type(), ndpiProtocol, ndpiCategory)

	return nil
}

// Query retrieves events matching the criteria from PostgreSQL.
func (s *PostgreSQLStorage) Query(ctx context.Context, query core.Query) ([]core.Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

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

	// Note: Core Query interface doesn't support NDPI/certificate filters.
	// For advanced filtering, create a new QueryAdvanced method or use direct SQL.
	// This implementation focuses on the standard core.Query fields only.

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
		// Note: This is a simplified reconstruction - full details are in metadata
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
func (s *PostgreSQLStorage) Count(ctx context.Context, query core.Query) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

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
