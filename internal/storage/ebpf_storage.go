// Package storage provides event storage implementations.
package storage

// ANCHOR: Storage Imports Cleanup - Build fix - Feb 25, 2026
// Remove unused net import to satisfy the compiler.
import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/srodi/ebpf-server/internal/core"
	"github.com/srodi/ebpf-server/pkg/logger"
)

// ANCHOR: eBPF Event Storage Implementation - Feb 3, 2026
// WHY: Persist eBPF kernel monitoring events (connections, packet drops) to PostgreSQL with multi-NIC support
// WHAT: Struct implementing core.EventSink interface specifically for eBPF events
// HOW: Use pgx connection pool to store events with interface-aware indexing and multi-program tagging

// EBPFEventStorage handles storage of eBPF events to PostgreSQL.
// It routes events to the ebpf_events table with proper field extraction.
type EBPFEventStorage struct {
	pool *pgxpool.Pool
}

// NewEBPFEventStorage creates a new eBPF event storage instance.
func NewEBPFEventStorage(pool *pgxpool.Pool) *EBPFEventStorage {
	return &EBPFEventStorage{
		pool: pool,
	}
}

// Store saves an eBPF event to the ebpf_events table.
func (s *EBPFEventStorage) Store(ctx context.Context, event core.Event) error {
	metadata := event.Metadata()
	if metadata == nil {
		metadata = make(map[string]interface{})
	}

	// Marshal metadata to JSONB
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		logger.Errorf("Failed to marshal eBPF event metadata: %v", err)
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// Route to appropriate storage method based on event type
	switch event.Type() {
	case "connection":
		return s.storeConnectionEvent(ctx, event, metadata, metadataJSON)
	case "packet_drop":
		return s.storePacketDropEvent(ctx, event, metadata, metadataJSON)
	default:
		// Handle unknown event types with generic storage
		return s.storeGenericEBPFEvent(ctx, event, metadata, metadataJSON)
	}
}

// storeConnectionEvent stores a connection tracking event.
func (s *EBPFEventStorage) storeConnectionEvent(ctx context.Context, event core.Event, metadata map[string]interface{}, metadataJSON []byte) error {
	// Extract network fields
	var srcIP, dstIP *string
	var srcPort, dstPort *int
	var protocol *string
	var ipVersion *int
	var addressFamily *int

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
	if proto, ok := metadata["protocol"].(string); ok {
		protocol = &proto
	}
	if ver, ok := metadata["ip_version"].(float64); ok {
		v := int(ver)
		ipVersion = &v
	}
	if af, ok := metadata["address_family"].(float64); ok {
		a := int(af)
		addressFamily = &a
	}

	// Extract connection-specific fields
	var connectionState, socketType *string
	var bytesSent, bytesReceived *int64
	var durationMs *float64
	var returnCode *int

	if state, ok := metadata["connection_state"].(string); ok {
		connectionState = &state
	}
	if sockType, ok := metadata["socket_type"].(string); ok {
		socketType = &sockType
	}
	if sent, ok := metadata["bytes_sent"].(float64); ok {
		s := int64(sent)
		bytesSent = &s
	}
	if recv, ok := metadata["bytes_received"].(float64); ok {
		r := int64(recv)
		bytesReceived = &r
	}
	if dur, ok := metadata["duration_ms"].(float64); ok {
		durationMs = &dur
	}
	if rc, ok := metadata["return_code"].(float64); ok {
		r := int(rc)
		returnCode = &r
	}

	// Extract Kubernetes metadata
	var k8sNodeName, k8sPodName, k8sNamespace *string
	if node, ok := metadata["k8s_node_name"].(string); ok {
		k8sNodeName = &node
	}
	if pod, ok := metadata["k8s_pod_name"].(string); ok {
		k8sPodName = &pod
	}
	if ns, ok := metadata["k8s_namespace"].(string); ok {
		k8sNamespace = &ns
	}

	// Extract interface fields (multi-NIC support)
	var interfaceName *string
	var interfaceIndex *int
	if ifname, ok := metadata["interface_name"].(string); ok {
		interfaceName = &ifname
	}
	if ifidx, ok := metadata["interface_index"].(float64); ok {
		idx := int(ifidx)
		interfaceIndex = &idx
	}

	// Extract program name
	programName := "connection_tracer"
	if pname, ok := metadata["program_name"].(string); ok {
		programName = pname
	}

	// Get observed_at timestamp
	observedAt := time.Now()
	if oa, ok := metadata["observed_at"].(float64); ok {
		observedAt = time.Unix(0, int64(oa))
	}

	sql := `
		INSERT INTO ebpf_events (
			id, event_type, program_name, created_at, observed_at,
			interface_name, interface_index,
			pid, command,
			k8s_node_name, k8s_pod_name, k8s_namespace,
			src_ip, dst_ip, src_port, dst_port, protocol, ip_version, address_family,
			connection_state, socket_type, bytes_sent, bytes_received, duration_ms, return_code,
			metadata
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7,
			$8, $9,
			$10, $11, $12,
			$13, $14, $15, $16, $17, $18, $19,
			$20, $21, $22, $23, $24, $25,
			$26
		)
		ON CONFLICT (id) DO NOTHING
	`

	_, err := s.pool.Exec(ctx, sql,
		event.ID(), event.Type(), programName, time.Now(), observedAt,
		interfaceName, interfaceIndex,
		event.PID(), event.Command(),
		k8sNodeName, k8sPodName, k8sNamespace,
		srcIP, dstIP, srcPort, dstPort, protocol, ipVersion, addressFamily,
		connectionState, socketType, bytesSent, bytesReceived, durationMs, returnCode,
		metadataJSON,
	)

	if err != nil {
		logger.Errorf("Failed to store connection event to eBPF table: %v", err)
		return fmt.Errorf("failed to store connection event: %w", err)
	}

	logger.Debugf("💾 Stored eBPF connection event: pid=%d, src=%s:%v, dst=%s:%v",
		event.PID(), srcIP, srcPort, dstIP, dstPort)

	return nil
}

// storePacketDropEvent stores a packet drop event.
func (s *EBPFEventStorage) storePacketDropEvent(ctx context.Context, event core.Event, metadata map[string]interface{}, metadataJSON []byte) error {
	// Extract network fields
	var srcIP, dstIP *string
	var protocol *string
	var ipVersion *int
	var addressFamily *int

	if sip, ok := metadata["src_ip"].(string); ok {
		srcIP = &sip
	}
	if dip, ok := metadata["dst_ip"].(string); ok {
		dstIP = &dip
	}
	if proto, ok := metadata["protocol"].(string); ok {
		protocol = &proto
	}
	if ver, ok := metadata["ip_version"].(float64); ok {
		v := int(ver)
		ipVersion = &v
	}
	if af, ok := metadata["address_family"].(float64); ok {
		a := int(af)
		addressFamily = &a
	}

	// Extract drop-specific fields
	var dropReason *string
	var droppedCount, dropCode *int

	if reason, ok := metadata["drop_reason"].(string); ok {
		dropReason = &reason
	}
	if count, ok := metadata["dropped_count"].(float64); ok {
		c := int(count)
		droppedCount = &c
	}
	if code, ok := metadata["drop_code"].(float64); ok {
		c := int(code)
		dropCode = &c
	}

	// Extract Kubernetes metadata
	var k8sNodeName, k8sPodName, k8sNamespace *string
	if node, ok := metadata["k8s_node_name"].(string); ok {
		k8sNodeName = &node
	}
	if pod, ok := metadata["k8s_pod_name"].(string); ok {
		k8sPodName = &pod
	}
	if ns, ok := metadata["k8s_namespace"].(string); ok {
		k8sNamespace = &ns
	}

	// Extract interface fields (multi-NIC support)
	var interfaceName *string
	var interfaceIndex *int
	if ifname, ok := metadata["interface_name"].(string); ok {
		interfaceName = &ifname
	}
	if ifidx, ok := metadata["interface_index"].(float64); ok {
		idx := int(ifidx)
		interfaceIndex = &idx
	}

	// Extract program name
	programName := "packet_drop_monitor"
	if pname, ok := metadata["program_name"].(string); ok {
		programName = pname
	}

	// Get observed_at timestamp
	observedAt := time.Now()
	if oa, ok := metadata["observed_at"].(float64); ok {
		observedAt = time.Unix(0, int64(oa))
	}

	sql := `
		INSERT INTO ebpf_events (
			id, event_type, program_name, created_at, observed_at,
			interface_name, interface_index,
			pid, command,
			k8s_node_name, k8s_pod_name, k8s_namespace,
			src_ip, dst_ip, protocol, ip_version, address_family,
			drop_reason, dropped_count, drop_code,
			metadata
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7,
			$8, $9,
			$10, $11, $12,
			$13, $14, $15, $16, $17,
			$18, $19, $20,
			$21
		)
		ON CONFLICT (id) DO NOTHING
	`

	_, err := s.pool.Exec(ctx, sql,
		event.ID(), event.Type(), programName, time.Now(), observedAt,
		interfaceName, interfaceIndex,
		event.PID(), event.Command(),
		k8sNodeName, k8sPodName, k8sNamespace,
		srcIP, dstIP, protocol, ipVersion, addressFamily,
		dropReason, droppedCount, dropCode,
		metadataJSON,
	)

	if err != nil {
		logger.Errorf("Failed to store packet drop event to eBPF table: %v", err)
		return fmt.Errorf("failed to store packet drop event: %w", err)
	}

	logger.Debugf("💾 Stored eBPF packet drop event: pid=%d, reason=%s, count=%v",
		event.PID(), dropReason, droppedCount)

	return nil
}

// storeGenericEBPFEvent stores any eBPF event type to support extensibility.
func (s *EBPFEventStorage) storeGenericEBPFEvent(ctx context.Context, event core.Event, metadata map[string]interface{}, metadataJSON []byte) error {
	// Extract common fields
	var srcIP, dstIP *string
	var srcPort, dstPort *int
	var protocol *string
	var ipVersion *int
	var addressFamily *int

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
	if proto, ok := metadata["protocol"].(string); ok {
		protocol = &proto
	}
	if ver, ok := metadata["ip_version"].(float64); ok {
		v := int(ver)
		ipVersion = &v
	}
	if af, ok := metadata["address_family"].(float64); ok {
		a := int(af)
		addressFamily = &a
	}

	// Extract Kubernetes metadata
	var k8sNodeName, k8sPodName, k8sNamespace *string
	if node, ok := metadata["k8s_node_name"].(string); ok {
		k8sNodeName = &node
	}
	if pod, ok := metadata["k8s_pod_name"].(string); ok {
		k8sPodName = &pod
	}
	if ns, ok := metadata["k8s_namespace"].(string); ok {
		k8sNamespace = &ns
	}

	// Extract interface fields (multi-NIC support)
	var interfaceName *string
	var interfaceIndex *int
	if ifname, ok := metadata["interface_name"].(string); ok {
		interfaceName = &ifname
	}
	if ifidx, ok := metadata["interface_index"].(float64); ok {
		idx := int(ifidx)
		interfaceIndex = &idx
	}

	// Extract program name (fallback to event type if not present)
	programName := event.Type()
	if pname, ok := metadata["program_name"].(string); ok {
		programName = pname
	}

	// Get observed_at timestamp
	observedAt := time.Now()
	if oa, ok := metadata["observed_at"].(float64); ok {
		observedAt = time.Unix(0, int64(oa))
	}

	sql := `
		INSERT INTO ebpf_events (
			id, event_type, program_name, created_at, observed_at,
			interface_name, interface_index,
			pid, command,
			k8s_node_name, k8s_pod_name, k8s_namespace,
			src_ip, dst_ip, src_port, dst_port, protocol, ip_version, address_family,
			metadata
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7,
			$8, $9,
			$10, $11, $12,
			$13, $14, $15, $16, $17, $18, $19,
			$20
		)
		ON CONFLICT (id) DO NOTHING
	`

	_, err := s.pool.Exec(ctx, sql,
		event.ID(), event.Type(), programName, time.Now(), observedAt,
		interfaceName, interfaceIndex,
		event.PID(), event.Command(),
		k8sNodeName, k8sPodName, k8sNamespace,
		srcIP, dstIP, srcPort, dstPort, protocol, ipVersion, addressFamily,
		metadataJSON,
	)

	if err != nil {
		logger.Errorf("Failed to store generic eBPF event to table: %v", err)
		return fmt.Errorf("failed to store generic event: %w", err)
	}

	logger.Debugf("💾 Stored eBPF event: type=%s, pid=%d, program=%s",
		event.Type(), event.PID(), programName)

	return nil
}

// Query retrieves eBPF events matching the criteria.
func (s *EBPFEventStorage) Query(ctx context.Context, query core.Query) ([]core.Event, error) {
	var args []interface{}
	whereClause := "WHERE 1=1"
	argIndex := 1

	// Filter by event type
	if query.EventType != "" {
		whereClause += fmt.Sprintf(" AND event_type = $%d", argIndex)
		args = append(args, query.EventType)
		argIndex++
	}

	// Filter by PID
	if query.PID != 0 {
		whereClause += fmt.Sprintf(" AND pid = $%d", argIndex)
		args = append(args, query.PID)
		argIndex++
	}

	// Filter by command
	if query.Command != "" {
		whereClause += fmt.Sprintf(" AND command LIKE $%d", argIndex)
		args = append(args, query.Command+"%")
		argIndex++
	}

	// Filter by time range
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

	limitClause := ""
	if query.Limit > 0 {
		limitClause = fmt.Sprintf(" LIMIT %d", query.Limit)
	}

	sql := fmt.Sprintf(`
		SELECT
			id, event_type, pid, command, observed_at, metadata
		FROM ebpf_events
		%s
		ORDER BY observed_at DESC
		%s
	`, whereClause, limitClause)

	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		logger.Errorf("Failed to query eBPF events: %v", err)
		return nil, fmt.Errorf("failed to query events: %w", err)
	}
	defer rows.Close()

	var events []core.Event
	for rows.Next() {
		var id, eventType, command string
		var pid uint32
		var observedAt time.Time
		var metadataJSON string

		if err := rows.Scan(&id, &eventType, &pid, &command, &observedAt, &metadataJSON); err != nil {
			logger.Errorf("Failed to scan eBPF event row: %v", err)
			continue
		}

		var metadata map[string]interface{}
		if err := json.Unmarshal([]byte(metadataJSON), &metadata); err != nil {
			logger.Errorf("Failed to unmarshal eBPF metadata: %v", err)
			continue
		}

		// Reconstruct event from stored data
		event := &ebpfEventRecord{
			id:        id,
			typ:       eventType,
			pid:       pid,
			command:   command,
			timestamp: uint64(observedAt.UnixNano()),
			time:      observedAt,
			metadata:  metadata,
		}

		events = append(events, event)
	}

	if err = rows.Err(); err != nil {
		logger.Errorf("Row iteration error: %v", err)
		return nil, err
	}

	return events, nil
}

// Count returns the number of eBPF events matching the criteria.
func (s *EBPFEventStorage) Count(ctx context.Context, query core.Query) (int, error) {
	var args []interface{}
	whereClause := "WHERE 1=1"
	argIndex := 1

	if query.EventType != "" {
		whereClause += fmt.Sprintf(" AND event_type = $%d", argIndex)
		args = append(args, query.EventType)
		argIndex++
	}

	if query.PID != 0 {
		whereClause += fmt.Sprintf(" AND pid = $%d", argIndex)
		args = append(args, query.PID)
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

	sql := fmt.Sprintf("SELECT COUNT(*) FROM ebpf_events %s", whereClause)

	var count int
	err := s.pool.QueryRow(ctx, sql, args...).Scan(&count)
	if err != nil {
		logger.Errorf("Failed to count eBPF events: %v", err)
		return 0, fmt.Errorf("failed to count events: %w", err)
	}

	return count, nil
}

// ebpfEventRecord represents a reconstructed eBPF event from PostgreSQL storage.
type ebpfEventRecord struct {
	id        string
	typ       string
	pid       uint32
	command   string
	timestamp uint64
	time      time.Time
	metadata  map[string]interface{}
}

func (e *ebpfEventRecord) ID() string {
	return e.id
}

func (e *ebpfEventRecord) Type() string {
	return e.typ
}

func (e *ebpfEventRecord) PID() uint32 {
	return e.pid
}

func (e *ebpfEventRecord) Command() string {
	return e.command
}

func (e *ebpfEventRecord) Timestamp() uint64 {
	return e.timestamp
}

func (e *ebpfEventRecord) Time() time.Time {
	return e.time
}

func (e *ebpfEventRecord) Metadata() map[string]interface{} {
	return e.metadata
}

func (e *ebpfEventRecord) MarshalJSON() ([]byte, error) {
	m := map[string]interface{}{
		"id":        e.id,
		"type":      e.typ,
		"pid":       e.pid,
		"command":   e.command,
		"timestamp": e.timestamp,
		"time":      e.time.Format(time.RFC3339Nano),
	}
	for k, v := range e.metadata {
		m[k] = v
	}
	return json.Marshal(m)
}
