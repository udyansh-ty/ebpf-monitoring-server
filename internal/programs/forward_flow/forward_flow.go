// Package forward_flow implements eBPF monitoring for forwarded IPv4/IPv6 traffic.
package forward_flow

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/srodi/ebpf-server/internal/core"
	"github.com/srodi/ebpf-server/internal/events"
	"github.com/srodi/ebpf-server/internal/programs"
	"github.com/srodi/ebpf-server/pkg/logger"
)

const (
	ProgramName        = "forward_flow"
	ProgramDescription = "Monitors forwarded traffic via TCX ingress/egress for NAT/masquerade visibility"
	ObjectPath         = "bpf/forward_flow.o"

	EventsMapName = "events"
)

const (
	hookIngress = 1
	hookEgress  = 2
)

// Program implements the forwarding-flow monitoring eBPF program.
type Program struct {
	*programs.BaseProgram
}

// NewProgram creates a new forward-flow monitoring program.
func NewProgram() *Program {
	base := programs.NewBaseProgram(ProgramName, ProgramDescription, ObjectPath)
	return &Program{
		BaseProgram: base,
	}
}

// Attach attaches all forwarding-flow kprobes and starts ring buffer reading.
func (p *Program) Attach(ctx context.Context) error {
	if !p.IsLoaded() {
		return fmt.Errorf("program not loaded")
	}
	_ = ctx

	collection := p.GetCollection()
	if collection == nil {
		return fmt.Errorf("forward_flow collection not loaded")
	}

	ingressProg := collection.Programs["tc_forward_ingress"]
	if ingressProg == nil {
		return fmt.Errorf("program tc_forward_ingress not found in collection")
	}
	egressProg := collection.Programs["tc_forward_egress"]
	if egressProg == nil {
		return fmt.Errorf("program tc_forward_egress not found in collection")
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("failed to list interfaces: %w", err)
	}

	attachedCount := 0
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		inLink, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Index,
			Program:   ingressProg,
			Attach:    ebpf.AttachTCXIngress,
		})
		if err != nil {
			logger.Warnf("forward_flow: failed ingress attach on %s(%d): %v", iface.Name, iface.Index, err)
		} else {
			p.AddLink(inLink)
			attachedCount++
		}

		egLink, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Index,
			Program:   egressProg,
			Attach:    ebpf.AttachTCXEgress,
		})
		if err != nil {
			logger.Warnf("forward_flow: failed egress attach on %s(%d): %v", iface.Name, iface.Index, err)
		} else {
			p.AddLink(egLink)
			attachedCount++
		}
	}

	if attachedCount == 0 {
		logger.Warnf("forward_flow: no tcx attachments succeeded, continuing without forwarding capture")
		return nil
	}

	parser := NewEventParser()
	if err := p.StartRingBufferReader(EventsMapName, parser); err != nil {
		return fmt.Errorf("failed to start ring buffer reader: %w", err)
	}

	logger.Info("Forward-flow monitoring program attached and active")
	return nil
}

// EventParser parses forwarded flow events from binary data.
type EventParser struct{}

// NewEventParser creates a new parser.
func NewEventParser() *EventParser {
	return &EventParser{}
}

// EventType returns parser event type.
func (p *EventParser) EventType() string {
	return "forward_flow"
}

// Parse converts raw bytes from eBPF into a forwarded-flow event.
func (p *EventParser) Parse(data []byte) (core.Event, error) {
	// Must match struct forward_event_t in bpf/forward_flow.c.
	const eventSize = 84
	if len(data) != eventSize {
		return nil, fmt.Errorf("invalid forward_flow event size: expected %d bytes, got %d", eventSize, len(data))
	}

	timestamp := binary.LittleEndian.Uint64(data[0:8])
	pid := binary.LittleEndian.Uint32(data[8:12])
	packetLen := binary.LittleEndian.Uint32(data[12:16])
	ifindex := binary.LittleEndian.Uint32(data[16:20])
	srcPort := binary.LittleEndian.Uint16(data[20:22])
	dstPort := binary.LittleEndian.Uint16(data[22:24])
	family := data[24]
	protocol := data[25]
	hook := data[26]

	srcIP := ""
	dstIP := ""
	if family == 4 {
		srcIPv4 := binary.LittleEndian.Uint32(data[28:32])
		dstIPv4 := binary.LittleEndian.Uint32(data[32:36])
		srcIP = ipv4FromUint32(srcIPv4)
		dstIP = ipv4FromUint32(dstIPv4)
	} else if family == 6 {
		srcIP = net.IP(data[36:52]).String()
		dstIP = net.IP(data[52:68]).String()
	}

	ifName := strings.TrimSpace(string(data[68:84]))
	if idx := strings.IndexByte(ifName, 0); idx >= 0 {
		ifName = ifName[:idx]
	}

	proto := protocolToString(protocol)
	hookName := hookToString(hook)
	direction := "egress"
	packetsIn := int64(0)
	packetsOut := int64(1)
	bytesIn := int64(0)
	bytesOut := int64(packetLen)
	if hook == hookIngress {
		direction = "ingress"
		packetsIn = 1
		packetsOut = 0
		bytesIn = int64(packetLen)
		bytesOut = 0
	}

	metadata := map[string]interface{}{
		"event_type":         "forward_flow",
		"type":               "forward_flow",
		"timestamp":          int64(timestamp),
		"observed_at":        int64(timestamp),
		"session_start_ns":   int64(timestamp),
		"session_end_ns":     int64(timestamp),
		"src_ip":             srcIP,
		"dst_ip":             dstIP,
		"src_port":           int64(srcPort),
		"dst_port":           int64(dstPort),
		"protocol":           proto,
		"raw_protocol":       int64(protocol),
		"interface_name":     ifName,
		"ifindex":            int64(ifindex),
		"hook":               hookName,
		"direction":          direction,
		"packet_size_bytes":  int64(packetLen),
		"bytes_in":           bytesIn,
		"bytes_out":          bytesOut,
		"packets_in":         packetsIn,
		"packets_out":        packetsOut,
		"connection_state":   "forwarded",
		"action":             "allow",
		"address_family":     int64(family),
		"forwarded_traffic":  true,
		"masquerade_related": true,
	}

	event := events.NewBaseEvent("forward_flow", pid, "kernel-forward", timestamp, metadata)
	return event, nil
}

func hookToString(hook uint8) string {
	switch hook {
	case hookIngress:
		return "ingress"
	case hookEgress:
		return "egress"
	default:
		return "unknown"
	}
}

func protocolToString(proto uint8) string {
	switch proto {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 58:
		return "icmpv6"
	default:
		return ""
	}
}

func ipv4FromUint32(raw uint32) string {
	ip := net.IPv4(byte(raw), byte(raw>>8), byte(raw>>16), byte(raw>>24))
	return ip.String()
}
