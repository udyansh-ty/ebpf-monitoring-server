package events

import (
	"context"
	"testing"
	"time"

	"github.com/srodi/ebpf-server/internal/core"
	"github.com/srodi/ebpf-server/internal/programs"
	"github.com/srodi/ebpf-server/pkg/logger"
)

// TestNewEventEnricher tests enricher creation.
func TestNewEventEnricher(t *testing.T) {
	resolver := programs.NewInterfaceResolver(logger.GetDefaultLogger())
	enricher := NewEventEnricher(context.Background(), resolver, nil, logger.GetDefaultLogger(), 5*time.Minute, true)

	if enricher == nil {
		t.Fatal("expected enricher, got nil")
	}

	if enricher.resolver != resolver {
		t.Error("expected resolver to be set")
	}

	if enricher.flowCacheTTL != 5*time.Minute {
		t.Errorf("expected 5m TTL, got %v", enricher.flowCacheTTL)
	}

	if !enricher.nonBlockingMode {
		t.Error("expected non-blocking mode")
	}
}

// TestCalculateFlowKey tests flow key calculation.
func TestCalculateFlowKey(t *testing.T) {
	resolver := programs.NewInterfaceResolver(logger.GetDefaultLogger())
	enricher := NewEventEnricher(context.Background(), resolver, nil, logger.GetDefaultLogger(), 5*time.Minute, true)

	tests := []struct {
		srcIP    string
		dstIP    string
		srcPort  uint16
		dstPort  uint16
		protocol string
		desc     string
	}{
		{"192.168.1.100", "8.8.8.8", 50000, 53, "udp", "DNS query"},
		{"10.0.0.1", "10.0.0.2", 80, 12345, "tcp", "HTTP response"},
		{"192.168.1.1", "192.168.1.1", 0, 0, "icmp", "ICMP request"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			key1, err := enricher.CalculateFlowKey(tt.srcIP, tt.dstIP, tt.srcPort, tt.dstPort, tt.protocol)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			// Same inputs should produce same key
			key2, _ := enricher.CalculateFlowKey(tt.srcIP, tt.dstIP, tt.srcPort, tt.dstPort, tt.protocol)
			if key1 != key2 {
				t.Error("expected deterministic flow key")
			}

			// Different inputs should produce different keys
			key3, _ := enricher.CalculateFlowKey(tt.dstIP, tt.srcIP, tt.dstPort, tt.srcPort, tt.protocol)
			if key1 == key3 {
				t.Error("expected different keys for different 5-tuples")
			}
		})
	}
}

// TestEnrichEventWithoutMetadata tests enrichment of non-enrichable events.
func TestEnrichEventWithoutMetadata(t *testing.T) {
	resolver := programs.NewInterfaceResolver(logger.GetDefaultLogger())
	enricher := NewEventEnricher(context.Background(), resolver, nil, logger.GetDefaultLogger(), 5*time.Minute, true)

	// Event without required fields
	metadata := map[string]interface{}{
		"program_name": "test",
	}

	event := NewBaseEvent("connection", 1234, "test", uint64(time.Now().UnixNano()), metadata)

	enrichedEvent, _ := enricher.EnrichEvent(context.Background(), event)

	// Should return original event (non-blocking mode)
	if enrichedEvent.ID() != event.ID() {
		t.Error("expected same event returned")
	}

	// Should not add interface info
	if _, ok := enrichedEvent.Metadata()["interface_name"]; ok {
		t.Error("expected no interface_name added when enrichment fails")
	}

	// Stats should record fallback
	stats := enricher.GetStats()
	if stats.FallbackEnrichments != 1 {
		t.Errorf("expected 1 fallback, got %d", stats.FallbackEnrichments)
	}
}

// TestEnrichEventNonConnectionType tests that non-connection events are skipped.
func TestEnrichEventNonConnectionType(t *testing.T) {
	resolver := programs.NewInterfaceResolver(logger.GetDefaultLogger())
	enricher := NewEventEnricher(context.Background(), resolver, nil, logger.GetDefaultLogger(), 5*time.Minute, true)

	// Non-connection event
	event := NewBaseEvent("unknown_type", 1234, "test", uint64(time.Now().UnixNano()), nil)

	enrichedEvent, _ := enricher.EnrichEvent(context.Background(), event)

	// Should return unchanged
	if enrichedEvent.ID() != event.ID() {
		t.Error("expected same event returned")
	}

	// Stats should not change
	stats := enricher.GetStats()
	if stats.EventsProcessed != 1 {
		t.Errorf("expected 1 event processed, got %d", stats.EventsProcessed)
	}
	if stats.SuccessfulEnrichments != 0 {
		t.Errorf("expected 0 successful enrichments, got %d", stats.SuccessfulEnrichments)
	}
}

// TestEnrichEventWithCompleteMetadata tests enrichment with all required fields.
func TestEnrichEventWithCompleteMetadata(t *testing.T) {
	resolver := programs.NewInterfaceResolver(logger.GetDefaultLogger())
	enricher := NewEventEnricher(context.Background(), resolver, nil, logger.GetDefaultLogger(), 5*time.Minute, true)

	// Event with complete 5-tuple
	metadata := map[string]interface{}{
		"src_ip":    "192.168.1.100",
		"dst_ip":    "8.8.8.8",
		"src_port":  float64(50000), // float64 from JSON unmarshaling
		"dst_port":  float64(53),
		"protocol":  "udp",
		"program_name": "test",
	}

	event := NewBaseEvent("connection", 1234, "curl", uint64(time.Now().UnixNano()), metadata)

	enrichedEvent, _ := enricher.EnrichEvent(context.Background(), event)

	// Event should have flow key calculated (though BPF lookup returns 0)
	// Since BPF maps are not configured, this should be a fallback enrichment
	stats := enricher.GetStats()
	if stats.EventsProcessed != 1 {
		t.Errorf("expected 1 event processed, got %d", stats.EventsProcessed)
	}
}

// TestEnrichEventAlreadyEnriched tests that already-enriched events are skipped.
func TestEnrichEventAlreadyEnriched(t *testing.T) {
	resolver := programs.NewInterfaceResolver(logger.GetDefaultLogger())
	enricher := NewEventEnricher(context.Background(), resolver, nil, logger.GetDefaultLogger(), 5*time.Minute, true)

	// Event already with interface_name
	metadata := map[string]interface{}{
		"interface_name":  "eth0",
		"interface_index": 2,
		"program_name":    "test",
	}

	event := NewBaseEvent("connection", 1234, "test", uint64(time.Now().UnixNano()), metadata)

	enrichedEvent, _ := enricher.EnrichEvent(context.Background(), event)

	// Should return original event
	if enrichedEvent.ID() != event.ID() {
		t.Error("expected same event returned")
	}

	// Stats should show fallback (skipped enrichment)
	stats := enricher.GetStats()
	if stats.EventsProcessed != 1 {
		t.Errorf("expected 1 event processed, got %d", stats.EventsProcessed)
	}
}

// TestGetStats tests statistics tracking.
func TestGetStats(t *testing.T) {
	resolver := programs.NewInterfaceResolver(logger.GetDefaultLogger())
	enricher := NewEventEnricher(context.Background(), resolver, nil, logger.GetDefaultLogger(), 5*time.Minute, true)

	// Initial stats
	stats := enricher.GetStats()
	if stats.EventsProcessed != 0 {
		t.Error("expected 0 events initially")
	}

	// Process some events
	for i := 0; i < 5; i++ {
		metadata := map[string]interface{}{
			"program_name": "test",
		}
		event := NewBaseEvent("connection", uint32(1000+i), "test", uint64(time.Now().UnixNano()), metadata)
		enricher.EnrichEvent(context.Background(), event)
	}

	stats = enricher.GetStats()
	if stats.EventsProcessed != 5 {
		t.Errorf("expected 5 events processed, got %d", stats.EventsProcessed)
	}

	if stats.FallbackEnrichments != 5 {
		t.Errorf("expected 5 fallback enrichments, got %d", stats.FallbackEnrichments)
	}
}

// TestGetSuccessRate tests success rate calculation.
func TestGetSuccessRate(t *testing.T) {
	resolver := programs.NewInterfaceResolver(logger.GetDefaultLogger())
	enricher := NewEventEnricher(context.Background(), resolver, nil, logger.GetDefaultLogger(), 5*time.Minute, true)

	// No events processed
	rate := enricher.GetSuccessRate()
	if rate != 0.0 {
		t.Errorf("expected 0.0 with no events, got %v", rate)
	}

	// Process events (all will be fallback since BPF maps not configured)
	for i := 0; i < 10; i++ {
		metadata := map[string]interface{}{
			"program_name": "test",
		}
		event := NewBaseEvent("connection", uint32(1000+i), "test", uint64(time.Now().UnixNano()), metadata)
		enricher.EnrichEvent(context.Background(), event)
	}

	rate = enricher.GetSuccessRate()
	if rate != 0.0 {
		t.Errorf("expected 0.0 (no BPF data), got %v", rate)
	}
}

// TestGetAverageLatencyNs tests latency tracking.
func TestGetAverageLatencyNs(t *testing.T) {
	resolver := programs.NewInterfaceResolver(logger.GetDefaultLogger())
	enricher := NewEventEnricher(context.Background(), resolver, nil, logger.GetDefaultLogger(), 5*time.Minute, true)

	// No events
	latency := enricher.GetAverageLatencyNs()
	if latency != 0 {
		t.Errorf("expected 0 latency with no events, got %d", latency)
	}

	// Process events
	for i := 0; i < 5; i++ {
		metadata := map[string]interface{}{
			"program_name": "test",
		}
		event := NewBaseEvent("connection", uint32(1000+i), "test", uint64(time.Now().UnixNano()), metadata)
		enricher.EnrichEvent(context.Background(), event)
	}

	latency = enricher.GetAverageLatencyNs()
	if latency == 0 {
		t.Logf("info: average latency is 0 (events processed too fast for measurement)")
	}
	// Should be reasonable (< 1 second = 1e9 nanoseconds)
	if latency > 1e9 {
		t.Errorf("latency suspiciously high: %d ns", latency)
	}
}

// TestPortParsing tests port extraction from various types.
func TestPortParsing(t *testing.T) {
	resolver := programs.NewInterfaceResolver(logger.GetDefaultLogger())
	enricher := NewEventEnricher(context.Background(), resolver, nil, logger.GetDefaultLogger(), 5*time.Minute, true)

	tests := []struct {
		metadata  map[string]interface{}
		fieldName string
		expected  int64
		desc      string
	}{
		{
			map[string]interface{}{"port": uint16(80)},
			"port",
			80,
			"uint16 port",
		},
		{
			map[string]interface{}{"port": int64(443)},
			"port",
			443,
			"int64 port",
		},
		{
			map[string]interface{}{"port": float64(8080)},
			"port",
			8080,
			"float64 port (JSON unmarshaling)",
		},
		{
			map[string]interface{}{},
			"port",
			-1,
			"missing port",
		},
		{
			map[string]interface{}{"port": "invalid"},
			"port",
			-1,
			"invalid port type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			port := enricher.getPortFromMetadata(tt.metadata, tt.fieldName)
			if port != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, port)
			}
		})
	}
}

// TestNonBlockingMode tests that enrichment failures don't block event processing.
func TestNonBlockingMode(t *testing.T) {
	resolver := programs.NewInterfaceResolver(logger.GetDefaultLogger())
	enricher := NewEventEnricher(context.Background(), resolver, nil, logger.GetDefaultLogger(), 5*time.Minute, true)

	// Event with missing required fields (will fail enrichment)
	metadata := map[string]interface{}{
		"program_name": "test",
		// Missing src_ip, dst_ip, ports, protocol
	}

	event := NewBaseEvent("connection", 1234, "test", uint64(time.Now().UnixNano()), metadata)

	// Enrichment should not error in non-blocking mode
	enrichedEvent, err := enricher.EnrichEvent(context.Background(), event)
	if err != nil {
		t.Errorf("unexpected error in non-blocking mode: %v", err)
	}

	// Event should still be returned (original event)
	if enrichedEvent == nil {
		t.Fatal("expected event to be returned")
	}

	if enrichedEvent.ID() != event.ID() {
		t.Error("expected same event to be returned")
	}
}

// BenchmarkFlowKeyCalculation benchmarks flow key calculation.
func BenchmarkFlowKeyCalculation(b *testing.B) {
	resolver := programs.NewInterfaceResolver(logger.GetDefaultLogger())
	enricher := NewEventEnricher(context.Background(), resolver, nil, logger.GetDefaultLogger(), 5*time.Minute, true)

	for i := 0; i < b.N; i++ {
		enricher.CalculateFlowKey("192.168.1.100", "8.8.8.8", 50000, 53, "udp")
	}
}

// BenchmarkEnricherLatency benchmarks enrichment latency (without BPF lookups).
func BenchmarkEnricherLatency(b *testing.B) {
	resolver := programs.NewInterfaceResolver(logger.GetDefaultLogger())
	enricher := NewEventEnricher(context.Background(), resolver, nil, logger.GetDefaultLogger(), 5*time.Minute, true)

	metadata := map[string]interface{}{
		"src_ip":    "192.168.1.100",
		"dst_ip":    "8.8.8.8",
		"src_port":  float64(50000),
		"dst_port":  float64(53),
		"protocol":  "udp",
		"program_name": "test",
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		event := NewBaseEvent("connection", 1234, "test", uint64(time.Now().UnixNano()), metadata)
		enricher.EnrichEvent(context.Background(), event)
	}
}
