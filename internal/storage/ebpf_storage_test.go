// Package storage provides event storage implementations.
package storage

import (
	"context"
	"testing"
	"time"

	"github.com/srodi/ebpf-server/internal/core"
	"github.com/srodi/ebpf-server/internal/events"
)

// TestEBPFConnectionEventStorage tests storing connection events.
func TestEBPFConnectionEventStorage(t *testing.T) {
	if skipPostgresTests() {
		t.Skip("PostgreSQL tests disabled")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, cleanup := setupTestPostgresPool(ctx, t)
	defer cleanup()

	storage := NewEBPFEventStorage(pool)

	// Create test connection event
	metadata := map[string]interface{}{
		"src_ip":           "192.168.1.100",
		"dst_ip":           "8.8.8.8",
		"src_port":         50000,
		"dst_port":         53,
		"protocol":         "udp",
		"ip_version":       4,
		"address_family":   2,
		"connection_state": "established",
		"socket_type":      "DGRAM",
		"bytes_sent":       100,
		"bytes_received":   500,
		"duration_ms":      1500.5,
		"return_code":      0,
		"program_name":     "connection_tracer",
		"interface_name":   "eth0",
		"interface_index":  2,
		"k8s_node_name":    "node-1",
		"k8s_pod_name":     "pod-1",
		"k8s_namespace":    "default",
		"observed_at":      float64(time.Now().UnixNano()),
	}

	event := events.NewBaseEvent("connection", 1234, "curl", uint64(time.Now().UnixNano()), metadata)

	// Store event
	err := storage.Store(ctx, event)
	if err != nil {
		t.Fatalf("Failed to store connection event: %v", err)
	}

	// Query back the event
	query := core.Query{
		EventType: "connection",
		PID:       1234,
	}

	results, err := storage.Query(ctx, query)
	if err != nil {
		t.Fatalf("Failed to query events: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(results))
	}

	result := results[0]
	if result.ID() != event.ID() {
		t.Errorf("Event ID mismatch: expected %s, got %s", event.ID(), result.ID())
	}
	if result.Type() != "connection" {
		t.Errorf("Event type mismatch: expected connection, got %s", result.Type())
	}
	if result.PID() != 1234 {
		t.Errorf("PID mismatch: expected 1234, got %d", result.PID())
	}
	if result.Command() != "curl" {
		t.Errorf("Command mismatch: expected curl, got %s", result.Command())
	}
}

// TestEBPFPacketDropEventStorage tests storing packet drop events.
func TestEBPFPacketDropEventStorage(t *testing.T) {
	if skipPostgresTests() {
		t.Skip("PostgreSQL tests disabled")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, cleanup := setupTestPostgresPool(ctx, t)
	defer cleanup()

	storage := NewEBPFEventStorage(pool)

	// Create test packet drop event
	metadata := map[string]interface{}{
		"src_ip":          "192.168.1.50",
		"dst_ip":          "10.0.0.1",
		"protocol":        "tcp",
		"ip_version":      4,
		"address_family":  2,
		"drop_reason":     "no_route",
		"dropped_count":   5,
		"drop_code":       -2,
		"program_name":    "packet_drop_monitor",
		"interface_name":  "eth1",
		"interface_index": 3,
		"observed_at":     float64(time.Now().UnixNano()),
	}

	event := events.NewBaseEvent("packet_drop", 0, "kernel", uint64(time.Now().UnixNano()), metadata)

	// Store event
	err := storage.Store(ctx, event)
	if err != nil {
		t.Fatalf("Failed to store packet drop event: %v", err)
	}

	// Query back the event
	query := core.Query{
		EventType: "packet_drop",
	}

	results, err := storage.Query(ctx, query)
	if err != nil {
		t.Fatalf("Failed to query events: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(results))
	}

	result := results[0]
	if result.Type() != "packet_drop" {
		t.Errorf("Event type mismatch: expected packet_drop, got %s", result.Type())
	}
}

// TestEBPFEventCount tests event counting.
func TestEBPFEventCount(t *testing.T) {
	if skipPostgresTests() {
		t.Skip("PostgreSQL tests disabled")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, cleanup := setupTestPostgresPool(ctx, t)
	defer cleanup()

	storage := NewEBPFEventStorage(pool)

	// Store multiple events
	for i := 0; i < 5; i++ {
		metadata := map[string]interface{}{
			"program_name": "connection_tracer",
			"observed_at":  float64(time.Now().UnixNano()),
		}
		event := events.NewBaseEvent("connection", uint32(1000+i), "process"+string(rune(i)), uint64(time.Now().UnixNano()), metadata)
		if err := storage.Store(ctx, event); err != nil {
			t.Fatalf("Failed to store event %d: %v", i, err)
		}
	}

	// Count events
	query := core.Query{
		EventType: "connection",
	}

	count, err := storage.Count(ctx, query)
	if err != nil {
		t.Fatalf("Failed to count events: %v", err)
	}

	if count != 5 {
		t.Errorf("Expected count 5, got %d", count)
	}
}

// TestEBPFMultiNICSupport tests multi-NIC interface field handling.
func TestEBPFMultiNICSupport(t *testing.T) {
	if skipPostgresTests() {
		t.Skip("PostgreSQL tests disabled")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, cleanup := setupTestPostgresPool(ctx, t)
	defer cleanup()

	storage := NewEBPFEventStorage(pool)
	queries := NewEBPFQueries(pool)

	// Store events from different interfaces
	for i, iface := range []string{"eth0", "eth1", "wlan0"} {
		metadata := map[string]interface{}{
			"interface_name":  iface,
			"interface_index": i + 1,
			"program_name":    "connection_tracer",
			"src_ip":          "192.168.1.1",
			"dst_ip":          "8.8.8.8",
			"observed_at":     float64(time.Now().UnixNano()),
		}
		event := events.NewBaseEvent("connection", uint32(2000+i), "curl", uint64(time.Now().UnixNano()), metadata)
		if err := storage.Store(ctx, event); err != nil {
			t.Fatalf("Failed to store event for interface %s: %v", iface, err)
		}
	}

	// Query interfaces
	interfaces, err := queries.ListInterfaces(ctx)
	if err != nil {
		t.Fatalf("Failed to list interfaces: %v", err)
	}

	if len(interfaces) != 3 {
		t.Errorf("Expected 3 interfaces, got %d", len(interfaces))
	}

	// Get stats for specific interface
	stats, err := queries.GetInterfaceStats(ctx, "eth0")
	if err != nil {
		t.Fatalf("Failed to get interface stats: %v", err)
	}

	if stats.InterfaceName != "eth0" {
		t.Errorf("Interface name mismatch: expected eth0, got %s", stats.InterfaceName)
	}
	if stats.EventCount != 1 {
		t.Errorf("Expected 1 event for eth0, got %d", stats.EventCount)
	}
}

// TestEBPFMultiProgramSupport tests program_name field handling.
func TestEBPFMultiProgramSupport(t *testing.T) {
	if skipPostgresTests() {
		t.Skip("PostgreSQL tests disabled")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, cleanup := setupTestPostgresPool(ctx, t)
	defer cleanup()

	storage := NewEBPFEventStorage(pool)
	queries := NewEBPFQueries(pool)

	// Store events from different programs
	programs := []string{"connection_tracer", "packet_drop_monitor", "file_ops_monitor"}
	eventTypes := []string{"connection", "packet_drop", "file_operation"}

	for i, prog := range programs {
		metadata := map[string]interface{}{
			"program_name": prog,
			"observed_at":  float64(time.Now().UnixNano()),
		}
		event := events.NewBaseEvent(eventTypes[i], uint32(3000+i), "test", uint64(time.Now().UnixNano()), metadata)
		if err := storage.Store(ctx, event); err != nil {
			t.Fatalf("Failed to store event for program %s: %v", prog, err)
		}
	}

	// List programs
	programList, err := queries.ListPrograms(ctx)
	if err != nil {
		t.Fatalf("Failed to list programs: %v", err)
	}

	if len(programList) != 3 {
		t.Errorf("Expected 3 programs, got %d", len(programList))
	}

	// Get stats for specific program
	stats, err := queries.GetProgramStats(ctx, "connection_tracer")
	if err != nil {
		t.Fatalf("Failed to get program stats: %v", err)
	}

	if stats.ProgramName != "connection_tracer" {
		t.Errorf("Program name mismatch: expected connection_tracer, got %s", stats.ProgramName)
	}
	if stats.EventCount != 1 {
		t.Errorf("Expected 1 event for connection_tracer, got %d", stats.EventCount)
	}
}

// TestEBPFProcessStats tests process-level aggregation.
func TestEBPFProcessStats(t *testing.T) {
	if skipPostgresTests() {
		t.Skip("PostgreSQL tests disabled")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, cleanup := setupTestPostgresPool(ctx, t)
	defer cleanup()

	storage := NewEBPFEventStorage(pool)
	queries := NewEBPFQueries(pool)

	// Store multiple events from same process
	for i := 0; i < 3; i++ {
		metadata := map[string]interface{}{
			"program_name":   "connection_tracer",
			"bytes_sent":     100 + i*50,
			"bytes_received": 200 + i*100,
			"observed_at":    float64(time.Now().UnixNano()),
		}
		event := events.NewBaseEvent("connection", 5000, "curl", uint64(time.Now().UnixNano()), metadata)
		if err := storage.Store(ctx, event); err != nil {
			t.Fatalf("Failed to store event %d: %v", i, err)
		}
	}

	// Get process stats
	stats, err := queries.GetProcessConnectionStats(ctx, 10)
	if err != nil {
		t.Fatalf("Failed to get process stats: %v", err)
	}

	if len(stats) != 1 {
		t.Fatalf("Expected 1 process, got %d", len(stats))
	}

	if stats[0].ConnectionCount != 3 {
		t.Errorf("Expected 3 connections for curl, got %d", stats[0].ConnectionCount)
	}
	if stats[0].Command != "curl" {
		t.Errorf("Command mismatch: expected curl, got %s", stats[0].Command)
	}
}

// TestEBPFTimeSeriesQuery tests time-bucketed queries.
func TestEBPFTimeSeriesQuery(t *testing.T) {
	if skipPostgresTests() {
		t.Skip("PostgreSQL tests disabled")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, cleanup := setupTestPostgresPool(ctx, t)
	defer cleanup()

	storage := NewEBPFEventStorage(pool)
	queries := NewEBPFQueries(pool)

	now := time.Now()

	// Store events at different times
	for i := 0; i < 5; i++ {
		metadata := map[string]interface{}{
			"program_name": "connection_tracer",
			"observed_at":  float64(now.Add(time.Duration(-i) * time.Minute).UnixNano()),
		}
		event := events.NewBaseEvent("connection", uint32(6000+i), "curl", uint64(time.Now().UnixNano()), metadata)
		if err := storage.Store(ctx, event); err != nil {
			t.Fatalf("Failed to store event %d: %v", i, err)
		}
	}

	// Query time series
	timeSeries, err := queries.ConnectionTimeSeries(ctx, now.Add(-10*time.Minute), now.Add(1*time.Minute))
	if err != nil {
		t.Fatalf("Failed to query time series: %v", err)
	}

	if len(timeSeries) == 0 {
		t.Fatalf("Expected time series data, got none")
	}
}

// TestEBPFTopDestinations tests destination IP aggregation.
func TestEBPFTopDestinations(t *testing.T) {
	if skipPostgresTests() {
		t.Skip("PostgreSQL tests disabled")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, cleanup := setupTestPostgresPool(ctx, t)
	defer cleanup()

	storage := NewEBPFEventStorage(pool)
	queries := NewEBPFQueries(pool)

	destinations := []string{"8.8.8.8", "1.1.1.1", "8.8.4.4"}

	// Store multiple events to different destinations
	for i, dst := range destinations {
		for j := 0; j < i+1; j++ {
			metadata := map[string]interface{}{
				"program_name": "connection_tracer",
				"dst_ip":       dst,
				"observed_at":  float64(time.Now().UnixNano()),
			}
			event := events.NewBaseEvent("connection", uint32(7000), "curl", uint64(time.Now().UnixNano()), metadata)
			if err := storage.Store(ctx, event); err != nil {
				t.Fatalf("Failed to store event to %s: %v", dst, err)
			}
		}
	}

	// Query top destinations
	topDests, err := queries.TopDestinations(ctx, 5)
	if err != nil {
		t.Fatalf("Failed to query top destinations: %v", err)
	}

	if len(topDests) != 3 {
		t.Errorf("Expected 3 destinations, got %d", len(topDests))
	}

	// Verify ordering
	if len(topDests) > 0 && topDests[0].ConnectionCount < topDests[len(topDests)-1].ConnectionCount {
		t.Errorf("Destinations not ordered by count")
	}
}

// Helper: skipPostgresTests returns true if PostgreSQL tests should be skipped.
func skipPostgresTests() bool {
	// Skip if no test database available
	return false // Modify if needed for your test environment
}

// Helper: setupTestPostgresPool creates a test PostgreSQL pool.
func setupTestPostgresPool(ctx context.Context, t *testing.T) (*pgxpool.Pool, func()) {
	// Use test database connection string
	// This would typically come from environment variables or test config
	connStr := "postgres://postgres:postgres@localhost:5432/monitoring_test"

	pool, err := pgxpool.Connect(ctx, connStr)
	if err != nil {
		t.Skipf("Could not connect to test PostgreSQL: %v", err)
	}

	// Run migrations to set up schema
	conn, err := pool.Acquire(ctx)
	if err != nil {
		pool.Close()
		t.Skipf("Could not acquire connection: %v", err)
	}
	defer conn.Release()

	if err := RunMigrations(ctx, conn.Conn()); err != nil {
		pool.Close()
		t.Skipf("Failed to run migrations: %v", err)
	}

	// Clean up function
	cleanup := func() {
		// Drop tables after test
		conn, _ := pool.Acquire(ctx)
		if conn != nil {
			defer conn.Release()
			conn.Conn().Exec(ctx, "DROP TABLE IF EXISTS ebpf_events CASCADE")
			conn.Conn().Exec(ctx, "DROP TABLE IF EXISTS ebpf_meta_window CASCADE")
			conn.Conn().Exec(ctx, "DROP TABLE IF EXISTS l7_events CASCADE")
		}
		pool.Close()
	}

	return pool, cleanup
}
