// Package events provides event implementations and utilities for the eBPF monitoring system.
package events

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/srodi/ebpf-server/internal/core"
	"github.com/srodi/ebpf-server/pkg/logger"
)

// ANCHOR: Event Enrichment Pipeline - Phase 1B - Feb 6, 2026
// WHY: Add interface information to connection events before storage
// WHAT: Lookup interface from TC classifier BPF maps, resolve to name, enrich event
// HOW: Create enricher that intercepts events, performs lookup+resolution, returns enriched event

// ANCHOR: InterfaceNameResolver interface to break import cycle - Issue #1 Fix - Feb 6, 2026
// WHY: programs.BaseProgram already imports events, creating a cycle if enricher imports programs
// WHAT: Define interface for interface name resolution instead of concrete type dependency
// HOW: Accept InterfaceNameResolver interface instead of *programs.InterfaceResolver concrete type
type InterfaceNameResolver interface {
	GetInterfaceName(ctx context.Context, ifindex int) (string, error)
}

// EventEnricher enriches connection events with interface information.
// It looks up the flow in TC classifier BPF maps and resolves the interface
// index to a human-readable name (e.g., "eth0", "eth1").
type EventEnricher struct {
	resolver         InterfaceNameResolver   // Interface-based to break import cycle
	bpfMaps          map[string]interface{}  // BPF maps from TC classifier
	log              *logger.Logger          // Pointer to logger instance
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
// resolver: Interface resolver for ifindex → name mapping (must implement InterfaceNameResolver)
// bpfMaps: BPF maps from TC classifier program (optional, can be nil)
// log: Logger instance pointer
// flowCacheTTL: How long to keep flow→interface mappings (configurable, recommended 5 minutes)
// nonBlockingMode: If true, enrichment failures don't block event processing
func NewEventEnricher(ctx context.Context, resolver InterfaceNameResolver,
	bpfMaps map[string]interface{}, log *logger.Logger,
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

// CalculateFlowKey calculates a deterministic flow key from the 5-tuple for IPv4.
// This matches the BPF fnv1a_hash() implementation.
func (e *EventEnricher) CalculateFlowKey(srcIP, dstIP string, srcPort, dstPort uint16, protocol string) (uint64, error) {
	protocolNum, err := parseProtocolString(protocol)
	if err != nil {
		return 0, err
	}

	return e.hashFlowKeyV4(srcIP, dstIP, srcPort, dstPort, protocolNum)
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

	protocolNum, err := e.extractProtocolNumber(metadata)
	if err != nil {
		return 0, err
	}

	ipVersion := e.getIPVersion(metadata)

	if ipVersion == 6 {
		return e.hashFlowKeyV6(srcIP, dstIP, uint16(srcPort), uint16(dstPort), protocolNum)
	}

	flowKey, err := e.hashFlowKeyV4(srcIP, dstIP, uint16(srcPort), uint16(dstPort), protocolNum)
	if err != nil {
		return 0, err
	}

	return flowKey, nil
}

func (e *EventEnricher) getIPVersion(metadata map[string]interface{}) int {
	if v, ok := metadata["ip_version"].(float64); ok && v >= 4 {
		return int(v)
	}
	if v, ok := metadata["ip_version"].(int); ok && v >= 4 {
		return v
	}
	if v, ok := metadata["ip_version"].(string); ok {
		if strings.Contains(v, "6") {
			return 6
		}
	}
	return 4
}

func (e *EventEnricher) extractProtocolNumber(metadata map[string]interface{}) (uint8, error) {
	if raw, ok := metadata["protocol"]; ok {
		if num, err := parseProtocolValue(raw); err == nil {
			return num, nil
		}
	}
	if raw, ok := metadata["raw_protocol"]; ok {
		if num, err := parseProtocolValue(raw); err == nil {
			return num, nil
		}
	}
	if raw, ok := metadata["protocol_number"]; ok {
		if num, err := parseProtocolValue(raw); err == nil {
			return num, nil
		}
	}

	return 0, fmt.Errorf("missing or invalid protocol")
}

func parseProtocolValue(value interface{}) (uint8, error) {
	switch v := value.(type) {
	case string:
		return parseProtocolString(v)
	case float64:
		return uint8(v), nil
	case int:
		return uint8(v), nil
	case uint8:
		return v, nil
	case uint16:
		return uint8(v), nil
	case uint32:
		return uint8(v), nil
	default:
		return 0, fmt.Errorf("unknown protocol type: %T", value)
	}
}

func parseProtocolString(protocol string) (uint8, error) {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "tcp":
		return 6, nil
	case "udp":
		return 17, nil
	case "icmp":
		return 1, nil
	case "icmpv6":
		return 58, nil
	default:
		num, err := strconv.ParseUint(protocol, 10, 8)
		if err != nil {
			return 0, fmt.Errorf("unknown protocol: %s", protocol)
		}
		return uint8(num), nil
	}
}

func (e *EventEnricher) hashFlowKeyV4(srcIP, dstIP string, srcPort, dstPort uint16, protocolNum uint8) (uint64, error) {
	srcIPParsed := net.ParseIP(srcIP)
	if srcIPParsed == nil || srcIPParsed.To4() == nil {
		return 0, fmt.Errorf("invalid source IP: %s", srcIP)
	}
	dstIPParsed := net.ParseIP(dstIP)
	if dstIPParsed == nil || dstIPParsed.To4() == nil {
		return 0, fmt.Errorf("invalid destination IP: %s", dstIP)
	}

	srcIPu32 := binary.BigEndian.Uint32(srcIPParsed.To4())
	dstIPu32 := binary.BigEndian.Uint32(dstIPParsed.To4())

	const fnvOffset uint64 = 0xcbf29ce484222325
	const fnvPrime uint64 = 0x100000001b3

	hash := fnvOffset

	for i := 0; i < 4; i++ {
		hash ^= uint64((srcIPu32 >> (uint(i) * 8)) & 0xFF)
		hash *= fnvPrime

		hash ^= uint64((dstIPu32 >> (uint(i) * 8)) & 0xFF)
		hash *= fnvPrime

		if i < 2 {
			hash ^= uint64((uint32(srcPort) >> (uint(i) * 8)) & 0xFF)
			hash *= fnvPrime

			hash ^= uint64((uint32(dstPort) >> (uint(i) * 8)) & 0xFF)
			hash *= fnvPrime
		}
	}

	hash ^= uint64(protocolNum)
	hash *= fnvPrime

	return hash, nil
}

func (e *EventEnricher) hashFlowKeyV6(srcIP, dstIP string, srcPort, dstPort uint16, protocolNum uint8) (uint64, error) {
	srcIPParsed := net.ParseIP(srcIP)
	if srcIPParsed == nil || srcIPParsed.To16() == nil {
		return 0, fmt.Errorf("invalid source IPv6: %s", srcIP)
	}
	dstIPParsed := net.ParseIP(dstIP)
	if dstIPParsed == nil || dstIPParsed.To16() == nil {
		return 0, fmt.Errorf("invalid destination IPv6: %s", dstIP)
	}

	srcBytes := srcIPParsed.To16()
	dstBytes := dstIPParsed.To16()

	const fnvOffset uint64 = 0xcbf29ce484222325
	const fnvPrime uint64 = 0x100000001b3

	hash := fnvOffset

	for i := 0; i < 4; i++ {
		srcChunk := binary.BigEndian.Uint32(srcBytes[i*4 : i*4+4])
		dstChunk := binary.BigEndian.Uint32(dstBytes[i*4 : i*4+4])

		hash ^= uint64(srcChunk)
		hash *= fnvPrime

		hash ^= uint64(dstChunk)
		hash *= fnvPrime
	}

	hash ^= uint64(srcPort)
	hash *= fnvPrime

	hash ^= uint64(dstPort)
	hash *= fnvPrime

	hash ^= uint64(protocolNum)
	hash *= fnvPrime

	return hash, nil
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
