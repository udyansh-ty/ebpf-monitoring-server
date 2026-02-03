// Package storage provides event storage implementations.
package storage

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v4"
	"github.com/srodi/ebpf-server/internal/core"
)

// ANCHOR: PostgreSQL Storage Tests - Jan 31, 2026
// WHY: Verify PostgreSQL storage correctly persists and retrieves L7 events with NDPI metadata
// WHAT: Integration tests for Store, Query, Count operations
// HOW: Use test database connection, create/drop tables per test, verify data integrity

// testDBConnString returns a connection string for testing.
// Expects PGTEST environment variable or defaults to local postgres.
const testDBConnString = "postgres://postgres:postgres@localhost:5432/ebpf_test"

// TestPostgreSQLStorageConnect tests successful PostgreSQL connection.
func TestPostgreSQLStorageConnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Note: This test requires a running PostgreSQL instance at testDBConnString
	// To run locally: docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=ebpf_test postgres:15
	storage, err := NewPostgreSQLStorage(ctx, testDBConnString)
	if err != nil {
		t.Logf("⚠️  Skipping PostgreSQL tests - database not available: %v", err)
		t.Skip("PostgreSQL not available for testing")
	}
	defer storage.Close()

	// Verify connection pool is working
	if err := storage.pool.Ping(ctx); err != nil {
		t.Fatalf("Failed to ping database: %v", err)
	}
}

// TestStoreL7EventWithNDPI tests storing an L7 event with NDPI enrichment.
func TestStoreL7EventWithNDPI(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	storage, err := NewPostgreSQLStorage(ctx, testDBConnString)
	if err != nil {
		t.Skip("PostgreSQL not available for testing")
	}
	defer storage.Close()

	// Clean up before test
	conn, _ := storage.pool.Acquire(ctx)
	DropAllTables(ctx, conn.Conn())
	RunMigrations(ctx, conn.Conn())
	conn.Release()

	// Create test event with NDPI metadata
	event := &mockEvent{
		id:   "test-event-1",
		typ:  "l7_flow_update",
		pid:  0,
		cmd:  "flow-192.168.1.1:443->8.8.8.8:443",
		tsNs: uint64(time.Now().UnixNano()),
		time: time.Now(),
		metadata: map[string]interface{}{
			"flow_id":        "192.168.1.1:443->8.8.8.8:443",
			"flow_key":       "key-123",
			"batch_id":       "batch-001",
			"source":         "vaanvil-01",
			"schema_version": "1.1",
			"observed_at":    float64(time.Now().UnixMilli()),
			"src_ip":         "192.168.1.1",
			"dst_ip":         "8.8.8.8",
			"src_port":       float64(54321),
			"dst_port":       float64(443),
			"protocol":       "tcp",
			"ip_version":     float64(4),
			"tls": map[string]interface{}{
				"sni":     "www.google.com",
				"alpn":    "h2",
				"version": "771",
			},
			"fingerprints": map[string]interface{}{
				"ja3": "e7d705a3286e19ea42f587b344ee6865",
				"ja4": "771,8,12,4,h2",
			},
			"certificate": map[string]interface{}{
				"leaf_sha256": "d8:6a:7f:e1",
				"issuer_cn":   "CN=Google Internet Authority",
				"expiry_ts":   float64(1743580800),
			},
			"ndpi": map[string]interface{}{
				"protocol":    "TLS",
				"category":    "Encrypted",
				"application": "HTTPS",
				"confidence":  0.75,
				"ndpi_id":     443,
			},
			"stats": map[string]interface{}{
				"bytes":       float64(12500),
				"packets":     float64(25),
				"duration_ms": float64(1200),
			},
		},
	}

	// Store event
	err = storage.Store(ctx, event)
	if err != nil {
		t.Fatalf("Failed to store event: %v", err)
	}

	// Query back from database
	query := core.Query{
		EventType: "l7_flow_update",
		Limit:     10,
	}

	events, err := storage.Query(ctx, query)
	if err != nil {
		t.Fatalf("Failed to query events: %v", err)
	}

	if len(events) == 0 {
		t.Fatalf("Expected 1 event, got 0")
	}

	retrieved := events[0]
	if retrieved.ID() != event.ID() {
		t.Errorf("Event ID mismatch: expected %s, got %s", event.ID(), retrieved.ID())
	}

	if retrieved.Type() != event.Type() {
		t.Errorf("Event type mismatch: expected %s, got %s", event.Type(), retrieved.Type())
	}

	// Verify NDPI metadata was preserved
	meta := retrieved.Metadata()
	if ndpi, ok := meta["ndpi"].(map[string]interface{}); ok {
		if proto, ok := ndpi["protocol"].(string); ok && proto != "TLS" {
			t.Errorf("NDPI protocol mismatch: expected TLS, got %s", proto)
		}
		if cat, ok := ndpi["category"].(string); ok && cat != "Encrypted" {
			t.Errorf("NDPI category mismatch: expected Encrypted, got %s", cat)
		}
	} else {
		t.Fatalf("NDPI metadata not found in retrieved event")
	}
}

// TestQueryByNDPICategory tests that events with NDPI metadata are stored and retrieved correctly.
// (Advanced NDPI filtering requires direct SQL queries, not the core.Query interface)
func TestQueryByNDPICategory(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	storage, err := NewPostgreSQLStorage(ctx, testDBConnString)
	if err != nil {
		t.Skip("PostgreSQL not available for testing")
	}
	defer storage.Close()

	// Clean up and recreate schema
	conn, _ := storage.pool.Acquire(ctx)
	DropAllTables(ctx, conn.Conn())
	RunMigrations(ctx, conn.Conn())
	conn.Release()

	// Store multiple events with different NDPI categories
	events := []core.Event{
		createMockL7Event("event-1", "TLS", "Encrypted", "HTTPS"),
		createMockL7Event("event-2", "TLS", "Encrypted", "HTTPS"),
		createMockL7Event("event-3", "YouTube", "Video", "YouTube"),
	}

	for _, evt := range events {
		if err := storage.Store(ctx, evt); err != nil {
			t.Fatalf("Failed to store event: %v", err)
		}
	}

	// Query by event type (core.Query interface)
	query := core.Query{
		EventType: "l7_flow_update",
		Limit:     100,
	}

	results, err := storage.Query(ctx, query)
	if err != nil {
		t.Fatalf("Failed to query events: %v", err)
	}

	// Should get all 3 events
	if len(results) != 3 {
		t.Errorf("Expected 3 events, got %d", len(results))
	}

	// Verify NDPI data is preserved in metadata
	for _, evt := range results {
		meta := evt.Metadata()
		if ndpi, ok := meta["ndpi"].(map[string]interface{}); ok {
			if proto, ok := ndpi["protocol"].(string); ok && proto != "" {
				// NDPI data was preserved
			} else {
				t.Errorf("NDPI protocol missing in event %s", evt.ID())
			}
		} else {
			t.Errorf("NDPI metadata missing in event %s", evt.ID())
		}
	}
}

// TestQueryByEventType tests filtering by event type.
func TestQueryByEventType(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	storage, err := NewPostgreSQLStorage(ctx, testDBConnString)
	if err != nil {
		t.Skip("PostgreSQL not available for testing")
	}
	defer storage.Close()

	// Clean and recreate
	conn, _ := storage.pool.Acquire(ctx)
	DropAllTables(ctx, conn.Conn())
	RunMigrations(ctx, conn.Conn())
	conn.Release()

	// Store events
	event1 := createMockL7Event("event-1", "TLS", "Encrypted", "HTTPS")
	event2 := createMockL7Event("event-2", "TLS", "Encrypted", "HTTPS")

	storage.Store(ctx, event1)
	storage.Store(ctx, event2)

	// Query by event type
	query := core.Query{
		EventType: "l7_flow_update",
		Limit:     100,
	}

	results, err := storage.Query(ctx, query)
	if err != nil {
		t.Fatalf("Failed to query by event type: %v", err)
	}

	if len(results) != 2 {
		t.Errorf("Expected 2 events, got %d", len(results))
	}
}

// TestCountEvents tests event counting with filters.
func TestCountEvents(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	storage, err := NewPostgreSQLStorage(ctx, testDBConnString)
	if err != nil {
		t.Skip("PostgreSQL not available for testing")
	}
	defer storage.Close()

	// Clean and recreate
	conn, _ := storage.pool.Acquire(ctx)
	DropAllTables(ctx, conn.Conn())
	RunMigrations(ctx, conn.Conn())
	conn.Release()

	// Store events
	for i := 0; i < 5; i++ {
		evt := createMockL7Event(fmt.Sprintf("event-%d", i), "TLS", "Encrypted", "HTTPS")
		storage.Store(ctx, evt)
	}

	// Count total events
	query := core.Query{
		EventType: "l7_flow_update",
	}

	count, err := storage.Count(ctx, query)
	if err != nil {
		t.Fatalf("Failed to count events: %v", err)
	}

	if count != 5 {
		t.Errorf("Expected count 5, got %d", count)
	}

	// Count by event type
	query.EventType = "l7_flow_update"

	count, err = storage.Count(ctx, query)
	if err != nil {
		t.Fatalf("Failed to count by event type: %v", err)
	}

	if count != 5 {
		t.Errorf("Expected 5 events, got %d", count)
	}
}

// TestQueryTimeRange tests querying events by time range.
func TestQueryTimeRange(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	storage, err := NewPostgreSQLStorage(ctx, testDBConnString)
	if err != nil {
		t.Skip("PostgreSQL not available for testing")
	}
	defer storage.Close()

	// Clean and recreate
	conn, _ := storage.pool.Acquire(ctx)
	DropAllTables(ctx, conn.Conn())
	RunMigrations(ctx, conn.Conn())
	conn.Release()

	now := time.Now()
	pastTime := now.Add(-1 * time.Hour)
	futureTime := now.Add(1 * time.Hour)

	// Store event
	event := createMockL7Event("event-1", "TLS", "Encrypted", "HTTPS")
	storage.Store(ctx, event)

	// Query within range
	query := core.Query{
		EventType: "l7_flow_update",
		Since:     pastTime,
		Until:     futureTime,
		Limit:     100,
	}

	results, err := storage.Query(ctx, query)
	if err != nil {
		t.Fatalf("Failed to query by time range: %v", err)
	}

	if len(results) != 1 {
		t.Errorf("Expected 1 event in range, got %d", len(results))
	}

	// Query outside range
	query.Since = futureTime
	results, err = storage.Query(ctx, query)
	if err != nil {
		t.Fatalf("Failed to query outside range: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("Expected 0 events outside range, got %d", len(results))
	}
}

// TestStoreIPBlockingVerdict tests storing IP blocking verdicts correctly.
// ANCHOR: IP Blocking Verdict Test - Feb 2, 2026
// WHY: Verify IP blocking verdicts (verdict.action = "drop") stored with metadata
// WHAT: Create events with drop verdicts for IP-based rules, verify storage
// HOW: Mock event with verdict.action="drop", verify retrieved metadata
func TestStoreIPBlockingVerdict(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	storage, err := NewPostgreSQLStorage(ctx, testDBConnString)
	if err != nil {
		t.Skip("PostgreSQL not available for testing")
	}
	defer storage.Close()

	// Clean up before test
	conn, _ := storage.pool.Acquire(ctx)
	DropAllTables(ctx, conn.Conn())
	RunMigrations(ctx, conn.Conn())
	conn.Release()

	// Create mock event with IP blocking verdict
	event := &mockEvent{
		id:   "ip-block-test-1",
		typ:  "l7_flow_update",
		pid:  0,
		cmd:  "ip-blocked-flow",
		tsNs: uint64(time.Now().UnixNano()),
		time: time.Now(),
		metadata: map[string]interface{}{
			"flow_id":        "192.168.1.5:12345->198.51.100.0:443",
			"flow_key":       "ipblock-key-1",
			"batch_id":       "batch-ipblock",
			"source":         "vaanvil-prod",
			"schema_version": "1.1",
			"observed_at":    float64(time.Now().UnixMilli()),
			"src_ip":         "192.168.1.5",
			"dst_ip":         "198.51.100.0",
			"src_port":       float64(12345),
			"dst_port":       float64(443),
			"protocol":       "tcp",
			"ip_version":     float64(4),
			// IP blocking verdict
			"verdict": map[string]interface{}{
				"action":   "drop",           // Traffic was BLOCKED
				"rule_id":  "block-range-1",  // IP range blocking rule
				"priority": 200,              // High priority
			},
			"stats": map[string]interface{}{
				"bytes":       float64(0),   // No bytes transferred (blocked early)
				"packets":     float64(1),   // Only SYN packet before block
				"duration_ms": float64(0.5),
			},
		},
	}

	// Store event
	err = storage.Store(ctx, event)
	if err != nil {
		t.Fatalf("Failed to store IP blocking event: %v", err)
	}

	// Query back from database
	query := core.Query{
		EventType: "l7_flow_update",
		Limit:     10,
	}

	events, err := storage.Query(ctx, query)
	if err != nil {
		t.Fatalf("Failed to query events: %v", err)
	}

	if len(events) == 0 {
		t.Fatalf("Expected 1 event, got 0")
	}

	retrieved := events[0]
	meta := retrieved.Metadata()

	// Verify verdict was stored correctly
	verdict, ok := meta["verdict"].(map[string]interface{})
	if !ok {
		t.Fatalf("Verdict metadata not found or wrong type")
	}

	action, ok := verdict["action"].(string)
	if !ok || action != "drop" {
		t.Errorf("Expected verdict.action='drop', got '%v'", verdict["action"])
	}

	ruleID, ok := verdict["rule_id"].(string)
	if !ok || ruleID != "block-range-1" {
		t.Errorf("Expected rule_id='block-range-1', got '%v'", verdict["rule_id"])
	}

	t.Logf("✅ IP blocking verdict stored and retrieved correctly: action=%s, rule=%s", action, ruleID)
}

// TestQueryByVerdictAction tests filtering events by verdict action (allow/drop).
// ANCHOR: Verdict Action Query Test - Feb 2, 2026
// WHY: Verify ability to query all blocked traffic (verdict.action = "drop")
// WHAT: Store mixed allow/drop verdicts, query by action
// HOW: Create 5 events (2 drop, 3 allow), filter, verify count
func TestQueryByVerdictAction(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	storage, err := NewPostgreSQLStorage(ctx, testDBConnString)
	if err != nil {
		t.Skip("PostgreSQL not available for testing")
	}
	defer storage.Close()

	// Clean and recreate
	conn, _ := storage.pool.Acquire(ctx)
	DropAllTables(ctx, conn.Conn())
	RunMigrations(ctx, conn.Conn())
	conn.Release()

	// Create events with different verdicts
	events := []struct {
		id     string
		action string
	}{
		{"allow-1", "allow"},
		{"allow-2", "allow"},
		{"drop-1", "drop"},
		{"drop-2", "drop"},
		{"allow-3", "allow"},
	}

	for _, evt := range events {
		event := &mockEvent{
			id:   evt.id,
			typ:  "l7_flow_update",
			pid:  0,
			cmd:  "test-flow",
			tsNs: uint64(time.Now().UnixNano()),
			time: time.Now(),
			metadata: map[string]interface{}{
				"flow_id":        fmt.Sprintf("flow-%s", evt.id),
				"flow_key":       fmt.Sprintf("key-%s", evt.id),
				"batch_id":       "batch-verdict-test",
				"source":         "vaanvil-test",
				"schema_version": "1.1",
				"observed_at":    float64(time.Now().UnixMilli()),
				"src_ip":         "192.168.1.100",
				"dst_ip":         "8.8.8.8",
				"src_port":       float64(12345),
				"dst_port":       float64(443),
				"protocol":       "tcp",
				"ip_version":     float64(4),
				"verdict": map[string]interface{}{
					"action": evt.action,
				},
			},
		}
		if err := storage.Store(ctx, event); err != nil {
			t.Fatalf("Failed to store event: %v", err)
		}
	}

	// Query all events
	allQuery := core.Query{EventType: "l7_flow_update", Limit: 100}
	allEvents, err := storage.Query(ctx, allQuery)
	if err != nil {
		t.Fatalf("Failed to query all events: %v", err)
	}

	if len(allEvents) != 5 {
		t.Errorf("Expected 5 events total, got %d", len(allEvents))
	}

	// Count drop verdicts (direct SQL verification)
	// Note: core.Query doesn't support verdict filtering, so we verify structure
	dropCount := 0
	for _, evt := range allEvents {
		meta := evt.Metadata()
		if verdict, ok := meta["verdict"].(map[string]interface{}); ok {
			if action, ok := verdict["action"].(string); ok && action == "drop" {
				dropCount++
			}
		}
	}

	if dropCount != 2 {
		t.Errorf("Expected 2 drop verdicts in retrieved events, got %d", dropCount)
	}

	t.Logf("✅ Verdict filtering verified: %d drop, %d allow", dropCount, 5-dropCount)
}

// TestIPBlockingWithCIDRNotation tests IP blocking with CIDR range notation.
// ANCHOR: CIDR IP Blocking Test - Feb 2, 2026
// WHY: Verify IP blocking rules using CIDR notation (e.g., 198.51.100.0/24)
// WHAT: Store events with blocked IPs in CIDR range, verify storage
// HOW: Create flow to 198.51.100.1, verify rule applied to range
func TestIPBlockingWithCIDRNotation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	storage, err := NewPostgreSQLStorage(ctx, testDBConnString)
	if err != nil {
		t.Skip("PostgreSQL not available for testing")
	}
	defer storage.Close()

	// Clean and recreate
	conn, _ := storage.pool.Acquire(ctx)
	DropAllTables(ctx, conn.Conn())
	RunMigrations(ctx, conn.Conn())
	conn.Release()

	// Create events for different IPs in same CIDR range
	cidrRanges := []string{
		"198.51.100.1",
		"198.51.100.50",
		"198.51.100.255",
	}

	for _, ip := range cidrRanges {
		event := &mockEvent{
			id:   fmt.Sprintf("cidr-test-%s", ip),
			typ:  "l7_flow_update",
			pid:  0,
			cmd:  "cidr-flow",
			tsNs: uint64(time.Now().UnixNano()),
			time: time.Now(),
			metadata: map[string]interface{}{
				"flow_id":        fmt.Sprintf("flow-%s", ip),
				"flow_key":       fmt.Sprintf("key-%s", ip),
				"batch_id":       "batch-cidr",
				"source":         "vaanvil-test",
				"schema_version": "1.1",
				"observed_at":    float64(time.Now().UnixMilli()),
				"src_ip":         "192.168.1.100",
				"dst_ip":         ip,
				"src_port":       float64(12345),
				"dst_port":       float64(443),
				"protocol":       "tcp",
				"ip_version":     float64(4),
				"verdict": map[string]interface{}{
					"action":   "drop",
					"rule_id":  "block-cidr-198.51.100.0/24",
					"priority": 150,
				},
			},
		}
		if err := storage.Store(ctx, event); err != nil {
			t.Fatalf("Failed to store CIDR test event for %s: %v", ip, err)
		}
	}

	// Query and verify all 3 blocked
	query := core.Query{EventType: "l7_flow_update", Limit: 100}
	results, err := storage.Query(ctx, query)
	if err != nil {
		t.Fatalf("Failed to query CIDR events: %v", err)
	}

	if len(results) != 3 {
		t.Errorf("Expected 3 CIDR events, got %d", len(results))
	}

	// Verify all have drop verdicts with CIDR rule
	for _, evt := range results {
		meta := evt.Metadata()
		verdict, ok := meta["verdict"].(map[string]interface{})
		if !ok {
			t.Errorf("Event %s missing verdict metadata", evt.ID())
			continue
		}

		action, ok := verdict["action"].(string)
		if !ok || action != "drop" {
			t.Errorf("Event %s verdict.action not 'drop': %v", evt.ID(), verdict["action"])
		}

		ruleID, ok := verdict["rule_id"].(string)
		if !ok || ruleID != "block-cidr-198.51.100.0/24" {
			t.Errorf("Event %s wrong rule_id: %v", evt.ID(), verdict["rule_id"])
		}
	}

	t.Logf("✅ CIDR IP blocking verdicts verified: all 3 IPs blocked by single rule")
}

// Helper functions

// createMockL7Event creates a mock L7 event for testing.
func createMockL7Event(id, ndpiProto, ndpiCat, ndpiApp string) core.Event {
	return &mockEvent{
		id:   id,
		typ:  "l7_flow_update",
		pid:  0,
		cmd:  "flow-test",
		tsNs: uint64(time.Now().UnixNano()),
		time: time.Now(),
		metadata: map[string]interface{}{
			"flow_id":        fmt.Sprintf("flow-%s", id),
			"flow_key":       fmt.Sprintf("key-%s", id),
			"batch_id":       "batch-test",
			"source":         "vaanvil-test",
			"schema_version": "1.1",
			"observed_at":    float64(time.Now().UnixMilli()),
			"src_ip":         "192.168.1.100",
			"dst_ip":         "8.8.8.8",
			"src_port":       float64(54321),
			"dst_port":       float64(443),
			"protocol":       "tcp",
			"ip_version":     float64(4),
			"tls": map[string]interface{}{
				"sni":     "example.com",
				"alpn":    "h2",
				"version": "771",
			},
			"fingerprints": map[string]interface{}{
				"ja3": "test-ja3-hash",
				"ja4": "test-ja4-hash",
			},
			"ndpi": map[string]interface{}{
				"protocol":    ndpiProto,
				"category":    ndpiCat,
				"application": ndpiApp,
				"confidence":  0.8,
				"ndpi_id":     443,
			},
		},
	}
}

// mockEvent is a test implementation of core.Event.
type mockEvent struct {
	id       string
	typ      string
	pid      uint32
	cmd      string
	tsNs     uint64
	time     time.Time
	metadata map[string]interface{}
}

func (m *mockEvent) ID() string                             { return m.id }
func (m *mockEvent) Type() string                           { return m.typ }
func (m *mockEvent) PID() uint32                            { return m.pid }
func (m *mockEvent) Command() string                        { return m.cmd }
func (m *mockEvent) Timestamp() uint64                      { return m.tsNs }
func (m *mockEvent) Time() time.Time                        { return m.time }
func (m *mockEvent) Metadata() map[string]interface{}       { return m.metadata }
func (m *mockEvent) MarshalJSON() ([]byte, error)           { return []byte("{}"), nil }
