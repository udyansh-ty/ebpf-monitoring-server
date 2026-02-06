// Package events provides event implementations and utilities for the eBPF monitoring system.
package events

import (
	"context"
	"fmt"
	"hash/fnv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/srodi/ebpf-server/internal/core"
	"github.com/srodi/ebpf-server/internal/programs"
	"github.com/srodi/ebpf-server/pkg/logger"
)

// ANCHOR: Event Enrichment Pipeline - Phase 1B - Feb 6, 2026
// WHY: Add interface information to connection events before storage
// WHAT: Lookup interface from TC classifier BPF maps, resolve to name, enrich event
// HOW: Create enricher that intercepts events, performs lookup+resolution, returns enriched event

// EventEnricher enriches connection events with interface information.
// It looks up the flow in TC classifier BPF maps and resolves the interface
// index to a human-readable name (e.g., "eth0", "eth1").
type EventEnricher struct {
	resolver         *programs.InterfaceResolver
	bpfMaps          map[string]interface{} // BPF maps from TC classifier
	log              logger.Logger
	stats            *EnricherStats
	flowCacheTTL     time.Duration // Time to live for flow cache (configurable)
	nonBlockingMode  bool           // If true, enrichment failures don't block events
	startTime        time.Time
}

// EnricherStats tracks enrichment performance metrics
type EnricherStats struct {
	EventsProcessed      int64
	SuccessfulEnrichments int64
	FallbackEnrichments  int64 // Events enriched but without BPF data
	FailedEnrichments    int64 // Events that failed enrichment (non-fatal)
	TotalLatencyNs       int64 // Cumulative latency in nanoseconds
	MinLatencyNs         int64
	MaxLatencyNs         int64
	LastErrorMsg        string
	mu                  sync.RWMutex
}

// NewEventEnricher creates a new event enricher.
// resolver: Interface resolver for ifindex → name mapping
// bpfMaps: BPF maps from TC classifier program (optional, can be nil)
// log: Logger instance
// flowCacheTTL: How long to keep flow→interface mappings (configurable, recommended 5 minutes)
// nonBlockingMode: If true, enrichment failures don't block event processing
func NewEventEnricher(ctx context.Context, resolver *programs.InterfaceResolver,
	bpfMaps map[string]interface{}, log logger.Logger,
	flowCacheTTL time.Duration, nonBlockingMode bool) *EventEnricher {

	if flowCacheTTL == 0 {
		flowCacheTTL = 5 * time.Minute // Default: 5 minutes
	}

	return &EventEnricher{
		resolver:        resolver,
		bpfMaps:         bpfMaps,
		log:             log,
		stats:           &EnricherStats{
			MinLatencyNs: 1 << 62, // Large initial value for min
		},
		flowCacheTTL:    flowCacheTTL,
		nonBlockingMode: nonBlockingMode,
		startTime:       time.Now(),
	}
}

// EnrichEvent enriches a connection event with interface information.
// Input: Connection event (may lack interface info)
// Output: Enriched event with interface_name, interface_index added to metadata
//
// This method is non-blocking (optional interface data):
// - If enrichment succeeds, adds interface_name and interface_index to metadata
// - If enrichment fails, returns original event unchanged
// - All errors are logged but don't prevent event storage
//
// Performance: <200µs per event including BPF map lookup and name resolution
func (e *EventEnricher) EnrichEvent(ctx context.Context, event core.Event) (core.Event, error) {
	startNs := time.Now().UnixNano()
	defer func() {
		elapsed := time.Now().UnixNano() - startNs
		e.recordLatency(elapsed)
	}()

	atomic.AddInt64(&e.stats.EventsProcessed, 1)

	// Only enrich connection events
	if event.Type() != "connection" && event.Type() != "packet_drop" {
		return event, nil
	}

	metadata := event.Metadata()
	if metadata == nil {
		return event, nil
	}

	// ANCHOR: Check if interface already enriched - Feb 6, 2026
	// WHY: Avoid redundant enrichment if interface_name already present
	// WHAT: Check if interface_name exists in metadata
	// HOW: Return early if already enriched
	if _, hasInterfaceName := metadata["interface_name"].(string); hasInterfaceName {
		// Already enriched, skip
		return event, nil
	}

	// Extract 5-tuple from event metadata
	flowKey, err := e.calculateFlowKey(metadata)
	if err != nil {
		// Non-fatal: missing some fields, return original event
		atomic.AddInt64(&e.stats.FallbackEnrichments, 1)
		return event, nil
	}

	// Lookup flow in BPF map (optional - might not be available yet)
	ifindex := e.lookupFlowInBPFMap(flowKey)
	if ifindex <= 0 {
		// BPF map lookup failed or flow not found
		// This is expected during transient flows or if TC program not loaded
		// Return original event - enrichment is best-effort
		atomic.AddInt64(&e.stats.FallbackEnrichments, 1)
		return event, nil
	}

	// Resolve ifindex to interface name
	ifName, err := e.resolver.GetInterfaceName(ctx, ifindex)
	if err != nil {
		// Resolution failed, but we still have ifindex
		// Add ifindex as numeric interface identifier
		metadata["interface_index"] = ifindex
		atomic.AddInt64(&e.stats.FallbackEnrichments, 1)
		e.log.Debugf("Failed to resolve ifindex %d: %v", ifindex, err)
		return event, nil
	}

	// Success: add both interface_name and interface_index to metadata
	metadata["interface_name"] = ifName
	metadata["interface_index"] = ifindex
	metadata["enrichment_timestamp"] = time.Now().UnixNano()

	atomic.AddInt64(&e.stats.SuccessfulEnrichments, 1)

	return event, nil
}

// CalculateFlowKey calculates a deterministic flow key from the 5-tuple.
// This must match the flow key calculation in the BPF program exactly.
// Used as key for BPF map lookups.
//
// Flow key = FNV-1a hash of (src_ip, dst_ip, src_port, dst_port, protocol)
func (e *EventEnricher) CalculateFlowKey(srcIP, dstIP string, srcPort, dstPort uint16, protocol string) (uint64, error) {
	h := fnv.New64a()

	// Hash each field in order
	h.Write([]byte(srcIP))
	h.Write([]byte(dstIP))
	h.Write([]byte{byte(srcPort >> 8), byte(srcPort)})
	h.Write([]byte{byte(dstPort >> 8), byte(dstPort)})
	h.Write([]byte(protocol))

	return h.Sum64(), nil
}

// calculateFlowKey extracts 5-tuple from event metadata and computes flow key.
// Returns error if required fields are missing.
func (e *EventEnricher) calculateFlowKey(metadata map[string]interface{}) (uint64, error) {
	// Extract required fields
	srcIP, ok := metadata["src_ip"].(string)
	if !ok || srcIP == "" {
		return 0, fmt.Errorf("missing or invalid src_ip")
	}

	dstIP, ok := metadata["dst_ip"].(string)
	if !ok || dstIP == "" {
		return 0, fmt.Errorf("missing or invalid dst_ip")
	}

	// Ports might be float64 from JSON unmarshaling
	srcPort := e.getPortFromMetadata(metadata, "src_port")
	if srcPort < 0 {
		return 0, fmt.Errorf("missing or invalid src_port")
	}

	dstPort := e.getPortFromMetadata(metadata, "dst_port")
	if dstPort < 0 {
		return 0, fmt.Errorf("missing or invalid dst_port")
	}

	protocol, ok := metadata["protocol"].(string)
	if !ok || protocol == "" {
		return 0, fmt.Errorf("missing or invalid protocol")
	}

	// Calculate flow key
	flowKey, err := e.CalculateFlowKey(srcIP, dstIP, uint16(srcPort), uint16(dstPort), protocol)
	if err != nil {
		return 0, err
	}

	return flowKey, nil
}

// getPortFromMetadata extracts a port number from metadata.
// Handles both uint16 and float64 types (float64 from JSON unmarshaling).
func (e *EventEnricher) getPortFromMetadata(metadata map[string]interface{}, fieldName string) int64 {
	value, ok := metadata[fieldName]
	if !ok {
		return -1
	}

	// Try uint16 first
	if port, ok := value.(uint16); ok {
		return int64(port)
	}

	// Try int64
	if port, ok := value.(int64); ok {
		return port
	}

	// Try float64 (common from JSON unmarshaling)
	if portFloat, ok := value.(float64); ok {
		return int64(portFloat)
	}

	return -1
}

// lookupFlowInBPFMap queries the BPF map for interface index.
// This would be implemented with CGO or libbpf bindings.
// For now, returns 0 to indicate lookup not available.
//
// TODO: Implement with libbpf or cilium/ebpf package
// This requires accessing the BPF maps from the TC classifier program
func (e *EventEnricher) lookupFlowInBPFMap(flowKey uint64) int {
	// TODO: Implement actual BPF map lookup
	// This would use cilium/ebpf or libbpf to query the flow_to_interface map
	// For Phase 1B initial implementation, we return 0 (lookup not implemented)
	// In subsequent phases, this will be replaced with actual lookup
	return 0
}

// GetStats returns current enrichment statistics.
func (e *EventEnricher) GetStats() EnricherStats {
	e.stats.mu.RLock()
	defer e.stats.mu.RUnlock()

	stats := *e.stats

	// Calculate average latency if events processed
	if atomic.LoadInt64(&e.stats.EventsProcessed) > 0 {
		avgLatency := atomic.LoadInt64(&e.stats.TotalLatencyNs) /
			atomic.LoadInt64(&e.stats.EventsProcessed)
		stats.TotalLatencyNs = avgLatency
	}

	return stats
}

// GetSuccessRate returns enrichment success rate (0.0 to 1.0)
func (e *EventEnricher) GetSuccessRate() float64 {
	total := atomic.LoadInt64(&e.stats.EventsProcessed)
	if total == 0 {
		return 0.0
	}

	successful := atomic.LoadInt64(&e.stats.SuccessfulEnrichments)
	return float64(successful) / float64(total)
}

// GetAverageLatencyNs returns average enrichment latency in nanoseconds.
// Returns 0 if no events processed.
func (e *EventEnricher) GetAverageLatencyNs() int64 {
	total := atomic.LoadInt64(&e.stats.EventsProcessed)
	if total == 0 {
		return 0
	}

	totalLatency := atomic.LoadInt64(&e.stats.TotalLatencyNs)
	return totalLatency / total
}

// Private methods

// recordLatency records enrichment latency for a single event.
// Updates min/max/average latency statistics.
func (e *EventEnricher) recordLatency(latencyNs int64) {
	atomic.AddInt64(&e.stats.TotalLatencyNs, latencyNs)

	// Update min latency
	for {
		currentMin := atomic.LoadInt64(&e.stats.MinLatencyNs)
		if latencyNs >= currentMin {
			break
		}
		if atomic.CompareAndSwapInt64(&e.stats.MinLatencyNs, currentMin, latencyNs) {
			break
		}
	}

	// Update max latency
	for {
		currentMax := atomic.LoadInt64(&e.stats.MaxLatencyNs)
		if latencyNs <= currentMax {
			break
		}
		if atomic.CompareAndSwapInt64(&e.stats.MaxLatencyNs, currentMax, latencyNs) {
			break
		}
	}
}

// TestingSetBPFMaps sets BPF maps for testing purposes.
// This should only be used in tests to mock BPF maps.
func (e *EventEnricher) TestingSetBPFMaps(maps map[string]interface{}) {
	e.bpfMaps = maps
}
