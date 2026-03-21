// Package connection implements eBPF monitoring for network connections.
package connection

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/srodi/ebpf-server/internal/core"
	"github.com/srodi/ebpf-server/internal/events"
	"github.com/srodi/ebpf-server/internal/programs"
	"github.com/srodi/ebpf-server/pkg/logger"
)

const (
	afInet  = 2
	afInet6 = 10
)

const (
	sourceIPCacheTTL   = 30 * time.Second
	rdnsLookupTimeout  = 200 * time.Millisecond
	rdnsCacheTTL       = 10 * time.Minute
	rdnsFailureCacheTT = 2 * time.Minute
	rdnsCacheMaxKeys   = 4096
)

type sourceIPCacheEntry struct {
	Value     string
	UpdatedAt time.Time
}

type rdnsCacheEntry struct {
	Value     string
	UpdatedAt time.Time
	TTL       time.Duration
}

var (
	sourceIPCacheMu sync.RWMutex
	sourceIPCache   = map[uint16]sourceIPCacheEntry{}

	rdnsCacheMu sync.RWMutex
	rdnsCache   = map[string]rdnsCacheEntry{}
)

const (
	// Program configuration
	ProgramName        = "connection"
	ProgramDescription = "Monitors network connection attempts via sys_enter_connect tracepoint"
	ObjectPath         = "bpf/connection.o"

	// eBPF program and map names
	TracepointProgram = "trace_connect"
	EventsMapName     = "events"

	// Tracepoint configuration
	TracepointGroup = "syscalls"
	TracepointName  = "sys_enter_connect"
)

// Program implements the connection monitoring eBPF program.
type Program struct {
	*programs.BaseProgram
}

// NewProgram creates a new connection monitoring program.
func NewProgram() *Program {
	base := programs.NewBaseProgram(ProgramName, ProgramDescription, ObjectPath)
	return &Program{
		BaseProgram: base,
	}
}

// Attach attaches the program to the appropriate kernel hooks.
func (p *Program) Attach(ctx context.Context) error {
	if !p.IsLoaded() {
		return fmt.Errorf("program not loaded")
	}

	logger.Debugf("Attaching connection monitoring program")

	// Attach to sys_enter_connect tracepoint
	if err := p.AttachToTracepoint(TracepointProgram, TracepointGroup, TracepointName); err != nil {
		return fmt.Errorf("failed to attach to tracepoint: %w", err)
	}

	// Start ring buffer reader
	parser := NewEventParser()
	if err := p.StartRingBufferReader(EventsMapName, parser); err != nil {
		return fmt.Errorf("failed to start ring buffer reader: %w", err)
	}

	logger.Info("Connection monitoring program attached and active")
	return nil
}

// EventParser parses connection events from binary data.
type EventParser struct{}

// NewEventParser creates a new connection event parser.
func NewEventParser() *EventParser {
	return &EventParser{}
}

// EventType returns the type of events this parser handles.
func (p *EventParser) EventType() string {
	return "connection"
}

// Parse converts raw bytes from eBPF into a connection event.
func (p *EventParser) Parse(data []byte) (core.Event, error) {
	if len(data) != 60 {
		return nil, fmt.Errorf("invalid connection event size: expected 60 bytes, got %d", len(data))
	}

	// Parse binary data based on C struct layout:
	// struct event_t {
	//     u32 pid;         // 0-3
	//     u64 ts;          // 4-11
	//     u32 ret;         // 12-15
	//     char comm[16];   // 16-31
	//     u32 dest_ip;     // 32-35
	//     u8 dest_ip6[16]; // 36-51
	//     u16 dest_port;   // 52-53
	//     u16 family;      // 54-55
	//     u8 protocol;     // 56
	//     u8 sock_type;    // 57
	//     u16 padding;     // 58-59
	// }

	pid := binary.LittleEndian.Uint32(data[0:4])
	timestamp := binary.LittleEndian.Uint64(data[4:12])
	ret := int32(binary.LittleEndian.Uint32(data[12:16]))

	// Extract command (null-terminated string)
	command := extractNullTerminatedString(data[16:32])

	destIPv4 := binary.LittleEndian.Uint32(data[32:36])
	var destIPv6 [16]byte
	copy(destIPv6[:], data[36:52])

	destPort := binary.LittleEndian.Uint16(data[52:54])
	family := binary.LittleEndian.Uint16(data[54:56])
	protocol := data[56]
	sockType := data[57]

	destinationIP := formatIP(family, destIPv4, destIPv6)
	destination := formatDestination(family, destIPv4, destIPv6, destPort)
	sourceIP := inferSourceIPForFamily(family, destinationIP)
	serverName := inferServerNameFromIP(destinationIP)

	// Build metadata with parsed fields and derived information
	metadata := map[string]interface{}{
		"return_code":      ret,
		"destination_ip":   destinationIP,
		"dest_ip":          destinationIP,
		"dst_ip":           destinationIP,
		"destination_port": destPort,
		"dst_port":         destPort,
		"destination":      destination,
		"address_family":   family,
		"protocol":         formatProtocol(protocol),
		"socket_type":      formatSocketType(sockType),
		"session_start_ns": int64(timestamp),
		"session_end_ns":   int64(timestamp),
		"packets_incoming": int64(0),
		"packets_outgoing": int64(0),

		// Raw values for further processing if needed
		"raw_ipv4":     destIPv4,
		"raw_ipv6":     destIPv6,
		"raw_protocol": protocol,
		"raw_socktype": sockType,
	}
	if sourceIP != "" {
		metadata["source_ip"] = sourceIP
		metadata["src_ip"] = sourceIP
	}
	if serverName != "" {
		metadata["server_name"] = serverName
		metadata["sni"] = serverName
	}

	event := events.NewBaseEvent("connection", pid, command, timestamp, metadata)

	// Debug log the parsed connection event
	if destination != "" {
		logger.Debugf("🔗 CONNECTION EVENT: PID=%d cmd=%s dest=%s proto=%s ret=%d",
			pid, command, destination, formatProtocol(protocol), ret)
	} else {
		logger.Debugf("🔗 CONNECTION EVENT: PID=%d cmd=%s family=%d (local socket) ret=%d",
			pid, command, family, ret)
	}

	return event, nil
}

// extractNullTerminatedString extracts a null-terminated string from a byte slice.
func extractNullTerminatedString(data []byte) string {
	for i, b := range data {
		if b == 0 {
			return string(data[:i])
		}
	}
	return string(data)
}

// formatIP converts the IP address to a string representation.
func formatIP(family uint16, ipv4 uint32, ipv6 [16]byte) string {
	switch family {
	case afInet:
		if ipv4 == 0 {
			return ""
		}
		// Convert from little-endian uint32 to IP address
		ip := net.IPv4(byte(ipv4), byte(ipv4>>8), byte(ipv4>>16), byte(ipv4>>24))
		return ip.String()

	case afInet6:
		// Check if IPv6 address is all zeros
		allZero := true
		for _, b := range ipv6 {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			return ""
		}
		ip := net.IP(ipv6[:])
		return ip.String()

	default:
		return ""
	}
}

// formatDestination formats the destination as "IP:port".
func formatDestination(family uint16, ipv4 uint32, ipv6 [16]byte, port uint16) string {
	ip := formatIP(family, ipv4, ipv6)
	if ip == "" {
		return ""
	}

	// IPv6 addresses need to be wrapped in brackets
	if family == afInet6 {
		return fmt.Sprintf("[%s]:%d", ip, port)
	}

	return fmt.Sprintf("%s:%d", ip, port)
}

// formatProtocol converts protocol number to string.
func formatProtocol(protocol uint8) string {
	switch protocol {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return fmt.Sprintf("Unknown(%d)", protocol)
	}
}

// formatSocketType converts socket type to string.
func formatSocketType(sockType uint8) string {
	switch sockType {
	case 1:
		return "STREAM"
	case 2:
		return "DGRAM"
	default:
		return fmt.Sprintf("Unknown(%d)", sockType)
	}
}

func inferSourceIPForFamily(family uint16, destinationIP string) string {
	sourceIPCacheMu.RLock()
	if cached, ok := sourceIPCache[family]; ok && time.Since(cached.UpdatedAt) <= sourceIPCacheTTL {
		sourceIPCacheMu.RUnlock()
		return cached.Value
	}
	sourceIPCacheMu.RUnlock()

	resolved := resolveSourceIP(family, destinationIP)
	if resolved == "" {
		resolved = firstNonLoopbackIP(family)
	}
	if resolved == "" {
		return ""
	}

	sourceIPCacheMu.Lock()
	sourceIPCache[family] = sourceIPCacheEntry{
		Value:     resolved,
		UpdatedAt: time.Now(),
	}
	sourceIPCacheMu.Unlock()

	return resolved
}

func resolveSourceIP(family uint16, destinationIP string) string {
	network := "udp4"
	targetHost := destinationIP

	switch family {
	case afInet6:
		network = "udp6"
		if ip := net.ParseIP(targetHost); ip == nil || ip.To16() == nil || ip.To4() != nil {
			targetHost = "2001:4860:4860::8888"
		}
	default:
		network = "udp4"
		if ip := net.ParseIP(targetHost); ip == nil || ip.To4() == nil {
			targetHost = "8.8.8.8"
		}
	}

	addr := net.JoinHostPort(targetHost, "53")
	dialer := net.Dialer{Timeout: 150 * time.Millisecond}
	conn, err := dialer.Dial(network, addr)
	if err != nil {
		return ""
	}
	defer conn.Close()

	localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || localAddr == nil || localAddr.IP == nil {
		return ""
	}

	return localAddr.IP.String()
}

func firstNonLoopbackIP(family uint16) string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	for _, iface := range interfaces {
		if (iface.Flags&net.FlagUp) == 0 || (iface.Flags&net.FlagLoopback) != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			default:
				continue
			}
			if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
				continue
			}
			switch family {
			case afInet6:
				if ip.To16() != nil && ip.To4() == nil {
					return ip.String()
				}
			default:
				if v4 := ip.To4(); v4 != nil {
					return v4.String()
				}
			}
		}
	}

	return ""
}

func inferServerNameFromIP(destinationIP string) string {
	ip := net.ParseIP(strings.TrimSpace(destinationIP))
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsPrivate() || ip.IsMulticast() {
		return ""
	}

	cacheKey := ip.String()
	now := time.Now()

	rdnsCacheMu.RLock()
	if cached, ok := rdnsCache[cacheKey]; ok && now.Sub(cached.UpdatedAt) <= cached.TTL {
		rdnsCacheMu.RUnlock()
		return cached.Value
	}
	rdnsCacheMu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), rdnsLookupTimeout)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(ctx, cacheKey)
	if err != nil || len(names) == 0 {
		cacheRDNSResult(cacheKey, "", rdnsFailureCacheTT)
		return ""
	}

	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(names[0])), ".")
	if name == "" || net.ParseIP(name) != nil {
		cacheRDNSResult(cacheKey, "", rdnsFailureCacheTT)
		return ""
	}

	cacheRDNSResult(cacheKey, name, rdnsCacheTTL)
	return name
}

func cacheRDNSResult(ip, value string, ttl time.Duration) {
	rdnsCacheMu.Lock()
	defer rdnsCacheMu.Unlock()

	if len(rdnsCache) >= rdnsCacheMaxKeys {
		for k := range rdnsCache {
			delete(rdnsCache, k)
			break
		}
	}

	rdnsCache[ip] = rdnsCacheEntry{
		Value:     value,
		UpdatedAt: time.Now(),
		TTL:       ttl,
	}
}
