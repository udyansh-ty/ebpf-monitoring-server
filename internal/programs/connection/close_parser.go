package connection

import (
	"encoding/binary"
	"net"

	"github.com/srodi/ebpf-server/internal/core"
	"github.com/srodi/ebpf-server/internal/events"
	"github.com/srodi/ebpf-server/pkg/logger"
)

// CloseEventSize is the binary size of close_event_t from the eBPF program
// struct close_event_t {
//   u32 pid (0-3)
//   u64 start_ns (4-11)
//   u64 first_pkt_ns (12-19)
//   u64 last_pkt_ns (20-27)
//   u64 pkts_sent (28-35)
//   u64 pkts_recv (36-43)
//   u32 dest_ip (44-47)
//   u8 dest_ip6[16] (48-63)
//   u16 dest_port (64-65)
//   u16 family (66-67)
//   u8 protocol (68)
//   u8 pad[1] (69)
// }
const CloseEventSize = 70

// CloseEventParser parses binary close events from the eBPF close_events ring buffer
type CloseEventParser struct{}

// EventType returns the event type name for close events
func (p *CloseEventParser) EventType() string {
	return "connection_close"
}

// Parse decodes a binary close_event_t structure into a core.Event
func (p *CloseEventParser) Parse(data []byte) (core.Event, error) {
	if len(data) != CloseEventSize {
		logger.Debugf("[CloseParser] Unexpected event size: got %d, expected %d", len(data), CloseEventSize)
		return nil, nil
	}

	// Parse binary structure
	pid := binary.LittleEndian.Uint32(data[0:4])
	startNs := binary.LittleEndian.Uint64(data[4:12])
	firstPktNs := binary.LittleEndian.Uint64(data[12:20])
	lastPktNs := binary.LittleEndian.Uint64(data[20:28])
	pktsSent := binary.LittleEndian.Uint64(data[28:36])
	pktsRecv := binary.LittleEndian.Uint64(data[36:44])
	destIPv4 := binary.LittleEndian.Uint32(data[44:48])

	// Extract IPv6 address
	destIPv6 := [16]byte{}
	copy(destIPv6[:], data[48:64])

	destPort := binary.LittleEndian.Uint16(data[64:66])
	family := binary.LittleEndian.Uint16(data[66:68])
	protocol := data[68]

	// Format destination IP
	destIP := formatIP(family, destIPv4, destIPv6)
	destination := formatDestination(family, destIPv4, destIPv6, destPort)

	// Calculate active_seconds from first to last packet
	var activeSeconds int64
	if firstPktNs > 0 && lastPktNs >= firstPktNs {
		// Convert nanoseconds to seconds
		activeSeconds = int64((lastPktNs - firstPktNs) / 1_000_000_000)
	}

	// Build metadata
	metadata := map[string]interface{}{
		"packets_in":       pktsRecv,
		"packets_out":      pktsSent,
		"packets_incoming": pktsRecv,
		"packets_outgoing": pktsSent,
		"active_seconds":   activeSeconds,
		"session_start_ns": int64(startNs),
		"session_end_ns":   int64(lastPktNs),
		"destination_ip":   destIP,
		"dest_ip":          destIP,
		"dst_ip":           destIP,
		"destination_port": destPort,
		"dst_port":         destPort,
		"destination":      destination,
		"address_family":   family,
		"protocol":         formatProtocol(protocol),
	}

	// Get command name for the process (if available)
	// For close events, we don't have command from eBPF, so we'll use empty string
	// The aggregator will correlate with the original connect event for the command
	command := ""

	// Create event using the timestamp from the connection start
	event := events.NewBaseEvent("connection_close", pid, command, startNs, metadata)

	logger.Debugf("[CloseParser] Parsed close event: PID=%d dest=%s pkts_in=%d pkts_out=%d active=%ds",
		pid, destination, pktsRecv, pktsSent, activeSeconds)

	return event, nil
}
