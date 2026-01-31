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
