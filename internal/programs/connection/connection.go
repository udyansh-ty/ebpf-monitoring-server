// Package connection implements eBPF monitoring for network connections.
package connection

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/bits"
	"net"
	"os"
	"path/filepath"
	"strconv"
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
	protoTCP = 6
	protoUDP = 17
)

const (
	sourceIPCacheTTL   = 30 * time.Second
	rdnsLookupTimeout  = 200 * time.Millisecond
	rdnsCacheTTL       = 10 * time.Minute
	rdnsFailureCacheTT = 2 * time.Minute
	rdnsCacheMaxKeys   = 4096
	sourcePortCacheTTL = 30 * time.Second
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

type sourcePortCacheKey struct {
	PID      uint32
	DestIP   string
	DestPort uint16
	Protocol uint8
}

type sourcePortCacheEntry struct {
	Port      uint16
	UpdatedAt time.Time
}

var (
	sourceIPCacheMu sync.RWMutex
	sourceIPCache   = map[uint16]sourceIPCacheEntry{}

	rdnsCacheMu sync.RWMutex
	rdnsCache   = map[string]rdnsCacheEntry{}

	sourcePortCacheMu sync.RWMutex
	sourcePortCache   = map[sourcePortCacheKey]sourcePortCacheEntry{}
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

	// Resolve source port with improved method
	sourcePort := resolveSourcePort(pid, family, destinationIP, destPort, protocol)
	if sourcePort != 0 {
		metadata["source_port"] = sourcePort
		metadata["src_port"] = sourcePort
	} else {
		// Fallback: try direct socket lookup
		sourcePort = findSourcePortDirect(pid, destinationIP, destPort, protocol)
		if sourcePort != 0 {
			metadata["source_port"] = sourcePort
			metadata["src_port"] = sourcePort
		}
	}

	if sourceIP != "" {
		metadata["source_ip"] = sourceIP
		metadata["src_ip"] = sourceIP
	}
	if serverName != "" {
		metadata["server_name"] = serverName
		metadata["sni"] = serverName
	}

	// Resolve network interface from routing table
	if destinationIP != "" {
		iface := resolveInterfaceFromRoute(destinationIP)
		if iface != "" {
			metadata["interface_name"] = iface
		}
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

func resolveSourcePort(pid uint32, family uint16, destinationIP string, destinationPort uint16, protocol uint8) uint16 {
	destIP := strings.TrimSpace(destinationIP)
	if pid == 0 || destIP == "" || destinationPort == 0 {
		return 0
	}
	if protocol != protoTCP && protocol != protoUDP {
		return 0
	}

	cacheKey := sourcePortCacheKey{
		PID:      pid,
		DestIP:   destIP,
		DestPort: destinationPort,
		Protocol: protocol,
	}

	now := time.Now()
	sourcePortCacheMu.RLock()
	if cached, ok := sourcePortCache[cacheKey]; ok && now.Sub(cached.UpdatedAt) <= sourcePortCacheTTL {
		sourcePortCacheMu.RUnlock()
		return cached.Port
	}
	sourcePortCacheMu.RUnlock()

	inodes := getProcessSocketInodes(pid)
	if len(inodes) == 0 {
		return 0
	}

	isIPv6 := family == afInet6 || strings.Contains(destIP, ":")
	port := findLocalPortByRemote(inodes, destIP, destinationPort, protocol, isIPv6)
	if port == 0 {
		return 0
	}

	sourcePortCacheMu.Lock()
	sourcePortCache[cacheKey] = sourcePortCacheEntry{
		Port:      port,
		UpdatedAt: now,
	}
	sourcePortCacheMu.Unlock()

	return port
}

func getProcessSocketInodes(pid uint32) map[uint64]struct{} {
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil
	}

	inodes := make(map[uint64]struct{})
	for _, entry := range entries {
		if len(inodes) >= 2048 {
			break
		}
		link, err := os.Readlink(filepath.Join(fdDir, entry.Name()))
		if err != nil {
			continue
		}
		if !strings.HasPrefix(link, "socket:[") {
			continue
		}
		start := strings.IndexByte(link, '[')
		end := strings.IndexByte(link, ']')
		if start == -1 || end == -1 || end <= start+1 {
			continue
		}
		inodeStr := link[start+1 : end]
		inode, err := strconv.ParseUint(inodeStr, 10, 64)
		if err != nil {
			continue
		}
		inodes[inode] = struct{}{}
	}

	return inodes
}

func findLocalPortByRemote(inodes map[uint64]struct{}, destIP string, destPort uint16, protocol uint8, isIPv6 bool) uint16 {
	remoteIP := net.ParseIP(destIP)
	if remoteIP == nil {
		return 0
	}

	procFile := "/proc/net/tcp"
	if protocol == protoUDP {
		procFile = "/proc/net/udp"
	}
	if isIPv6 {
		procFile += "6"
	}

	file, err := os.Open(procFile)
	if err != nil {
		return 0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Skip header
	if !scanner.Scan() {
		return 0
	}

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		localAddr := fields[1]
		remoteAddr := fields[2]
		inodeStr := fields[len(fields)-1]

		inode, err := strconv.ParseUint(inodeStr, 10, 64)
		if err != nil {
			continue
		}
		if _, ok := inodes[inode]; !ok {
			continue
		}

		remoteParsedIP, remoteParsedPort, ok := parseProcNetAddr(remoteAddr)
		if !ok {
			continue
		}
		if !remoteParsedIP.Equal(remoteIP) || remoteParsedPort != destPort {
			continue
		}

		_, localPort, ok := parseProcNetAddr(localAddr)
		if !ok {
			continue
		}
		return localPort
	}

	return 0
}

func parseProcNetAddr(addr string) (net.IP, uint16, bool) {
	parts := strings.Split(addr, ":")
	if len(parts) != 2 {
		return nil, 0, false
	}
	ipHex := parts[0]
	portHex := parts[1]

	portVal, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return nil, 0, false
	}

	switch len(ipHex) {
	case 8:
		val, err := strconv.ParseUint(ipHex, 16, 32)
		if err != nil {
			return nil, 0, false
		}
		ip := net.IPv4(
			byte(val&0xff),
			byte((val>>8)&0xff),
			byte((val>>16)&0xff),
			byte((val>>24)&0xff),
		)
		return ip, uint16(portVal), true
	case 32:
		raw, err := hex.DecodeString(ipHex)
		if err != nil || len(raw) != 16 {
			return nil, 0, false
		}
		// /proc/net/tcp6 stores IPv6 in little-endian 32-bit words.
		for i := 0; i < 16; i += 4 {
			raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
		}
		return net.IP(raw), uint16(portVal), true
	default:
		return nil, 0, false
	}
}

// findSourcePortDirect performs a direct lookup of source port from /proc/net/tcp[6]
// by scanning all entries for a matching destination address and port.
// First tries process-specific view (/proc/PID/net/tcp[6]) which is more reliable,
// then falls back to global view (/proc/net/tcp[6]).
func findSourcePortDirect(pid uint32, destIP string, destPort uint16, protocol uint8) uint16 {
	if pid == 0 || destIP == "" || destPort == 0 {
		return 0
	}

	remoteIP := net.ParseIP(destIP)
	if remoteIP == nil {
		logger.Debugf("Failed to parse destination IP for port lookup: %s", destIP)
		return 0
	}

	// Try process-specific view first (more reliable)
	if port := findSourcePortFromProcNet(pid, remoteIP, destPort, protocol); port != 0 {
		logger.Debugf("Found source port via /proc/%d/net: %d", pid, port)
		return port
	}

	// Fall back to global view
	if port := findSourcePortFromGlobalNet(remoteIP, destPort, protocol); port != 0 {
		logger.Debugf("Found source port via /proc/net: %d", port)
		return port
	}

	logger.Debugf("Could not resolve source port for %s:%d", destIP, destPort)
	return 0
}

// findSourcePortFromProcNet tries to find source port from process-specific net file
func findSourcePortFromProcNet(pid uint32, remoteIP net.IP, destPort uint16, protocol uint8) uint16 {
	procFile := fmt.Sprintf("/proc/%d/net/tcp", pid)
	if protocol == protoUDP {
		procFile = fmt.Sprintf("/proc/%d/net/udp", pid)
	}
	if remoteIP.To4() == nil {
		procFile += "6"
	}

	file, err := os.Open(procFile)
	if err != nil {
		logger.Debugf("Failed to open %s: %v", procFile, err)
		return 0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Skip header
	if !scanner.Scan() {
		return 0
	}

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}

		localAddr := fields[1]
		remoteAddr := fields[2]

		// Parse remote address
		remoteParsedIP, remoteParsedPort, ok := parseProcNetAddr(remoteAddr)
		if !ok {
			continue
		}

		// Check if destination matches
		if !remoteParsedIP.Equal(remoteIP) || remoteParsedPort != destPort {
			continue
		}

		// Found matching entry, extract local port
		_, localPort, ok := parseProcNetAddr(localAddr)
		if !ok {
			continue
		}

		return localPort
	}

	return 0
}

// findSourcePortFromGlobalNet tries to find source port from global net files
func findSourcePortFromGlobalNet(remoteIP net.IP, destPort uint16, protocol uint8) uint16 {
	procFile := "/proc/net/tcp"
	if protocol == protoUDP {
		procFile = "/proc/net/udp"
	}
	if remoteIP.To4() == nil {
		procFile += "6"
	}

	file, err := os.Open(procFile)
	if err != nil {
		logger.Debugf("Failed to open %s: %v", procFile, err)
		return 0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Skip header
	if !scanner.Scan() {
		return 0
	}

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}

		localAddr := fields[1]
		remoteAddr := fields[2]

		// Parse remote address
		remoteParsedIP, remoteParsedPort, ok := parseProcNetAddr(remoteAddr)
		if !ok {
			continue
		}

		// Check if destination matches
		if !remoteParsedIP.Equal(remoteIP) || remoteParsedPort != destPort {
			continue
		}

		// Found matching entry, extract local port
		_, localPort, ok := parseProcNetAddr(localAddr)
		if !ok {
			continue
		}

		return localPort
	}

	return 0
}

// resolveInterfaceFromRoute determines the network interface for a destination IP
// by querying the routing table via /proc/net/route or /proc/net/ipv6_route
func resolveInterfaceFromRoute(destIP string) string {
	if destIP == "" {
		return ""
	}

	ip := net.ParseIP(destIP)
	if ip == nil {
		logger.Debugf("Failed to parse destination IP: %s", destIP)
		return ""
	}

	// Check if IPv4 or IPv6
	if ip.To4() != nil {
		iface := resolveInterfaceIPv4(ip.String())
		if iface != "" {
			logger.Debugf("Resolved IPv4 interface for %s: %s", destIP, iface)
		} else {
			logger.Debugf("Failed to resolve IPv4 interface for %s", destIP)
		}
		return iface
	}

	iface := resolveInterfaceIPv6(ip.String())
	if iface != "" {
		logger.Debugf("Resolved IPv6 interface for %s: %s", destIP, iface)
	} else {
		logger.Debugf("Failed to resolve IPv6 interface for %s", destIP)
	}
	return iface
}

// resolveInterfaceIPv4 finds the interface for an IPv4 destination by parsing /proc/net/route
func resolveInterfaceIPv4(destIP string) string {
	if destIP == "" {
		return ""
	}

	file, err := os.Open("/proc/net/route")
	if err != nil {
		logger.Debugf("Failed to open /proc/net/route: %v", err)
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Skip header line
	if !scanner.Scan() {
		logger.Debugf("Failed to read /proc/net/route header")
		return ""
	}

	destIPBytes := net.ParseIP(destIP)
	if destIPBytes == nil {
		logger.Debugf("Invalid destination IP: %s", destIP)
		return ""
	}

	destIPv4 := destIPBytes.To4()
	if destIPv4 == nil {
		logger.Debugf("Not an IPv4 address: %s", destIP)
		return ""
	}

	// Convert to uint32 in little-endian format (as stored in /proc/net/route)
	destIPUint := uint32(destIPv4[0]) | (uint32(destIPv4[1]) << 8) | (uint32(destIPv4[2]) << 16) | (uint32(destIPv4[3]) << 24)
	logger.Debugf("[Route Debug] Searching for IP: %s (little-endian uint32: 0x%08X)", destIP, destIPUint)

	var bestMatch string
	var bestMaskLen int = -1  // Initialize to -1 so default route (0 bits) matches
	var routeCount int

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)

		// /proc/net/route format: Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
		// We need at least Iface(0), Destination(1), and Mask(7)
		if len(fields) < 8 {
			continue
		}

		routeCount++

		iface := fields[0]
		destStr := fields[1]
		maskStr := fields[7]

		// Parse destination and mask as hex strings
		// In /proc/net/route, IPs are stored in little-endian byte order
		destBytes := make([]byte, 4)
		maskBytes := make([]byte, 4)

		if _, errD := hex.Decode(destBytes, []byte(destStr)); errD != nil {
			logger.Debugf("[Route] Failed to decode dest %s: %v", destStr, errD)
			continue
		}
		if _, errM := hex.Decode(maskBytes, []byte(maskStr)); errM != nil {
			logger.Debugf("[Route] Failed to decode mask %s: %v", maskStr, errM)
			continue
		}

		// Convert little-endian bytes to uint32
		dest := uint32(destBytes[0]) | (uint32(destBytes[1]) << 8) | (uint32(destBytes[2]) << 16) | (uint32(destBytes[3]) << 24)
		mask := uint32(maskBytes[0]) | (uint32(maskBytes[1]) << 8) | (uint32(maskBytes[2]) << 16) | (uint32(maskBytes[3]) << 24)

		logger.Debugf("[Route %s] dest=0x%08X (from %s bytes %v), mask=0x%08X, destIP=0x%08X, check: (0x%08X & 0x%08X) = 0x%08X == 0x%08X?",
			iface, dest, destStr, destBytes, mask, destIPUint, destIPUint, mask, destIPUint&mask, dest)

		// Check if destination IP matches this route
		if (destIPUint & mask) == dest {
			// Count set bits in mask (highest prefix length wins - most specific route)
			maskBits := bits.OnesCount32(uint32(mask))

			if maskBits > bestMaskLen {
				bestMaskLen = maskBits
				bestMatch = iface
				logger.Debugf("✓ IPv4 route match: %s -> %s (mask bits: %d)", destIP, iface, maskBits)
			}
		}
	}

	if bestMatch == "" {
		logger.Debugf("✗ No IPv4 route found for: %s (checked %d routes)", destIP, routeCount)
		return ""
	}

	logger.Debugf("✓ Resolved IPv4 interface for %s: %s", destIP, bestMatch)
	return bestMatch
}

// resolveInterfaceIPv6 finds the interface for an IPv6 destination
func resolveInterfaceIPv6(destIP string) string {
	if destIP == "" {
		return ""
	}

	file, err := os.Open("/proc/net/ipv6_route")
	if err != nil {
		logger.Debugf("Failed to open /proc/net/ipv6_route: %v", err)
		return ""
	}
	defer file.Close()

	destIPParsed := net.ParseIP(destIP)
	if destIPParsed == nil {
		logger.Debugf("Invalid destination IP: %s", destIP)
		return ""
	}

	if destIPParsed.To4() != nil {
		logger.Debugf("Not an IPv6 address: %s", destIP)
		return ""
	}

	scanner := bufio.NewScanner(file)
	var bestMatch string
	var bestPrefixLen int

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)

		// /proc/net/ipv6_route format:
		// destination prefix_len nexthop metric use flags refcnt use metric interface
		// Index:   0           1       2        3      4   5     6      7   8      9
		if len(fields) < 10 {
			continue
		}

		destHex := fields[0]
		prefixStr := fields[1]
		iface := fields[9]

		// Parse prefix length (in hex)
		prefixLen, err := strconv.ParseInt(prefixStr, 16, 8)
		if err != nil {
			continue
		}

		// Convert hex IP to standard format
		routeIP := convertIPv6HexToString(destHex)
		if routeIP == "" {
			continue
		}

		routeIPParsed := net.ParseIP(routeIP)
		if routeIPParsed == nil {
			continue
		}

		// Check if destination matches using CIDR mask
		mask := net.CIDRMask(int(prefixLen), 128)
		if mask == nil {
			continue
		}

		if destIPParsed.Mask(mask).Equal(routeIPParsed.Mask(mask)) {
			// Keep most specific route (highest prefix length)
			if int(prefixLen) > bestPrefixLen {
				bestPrefixLen = int(prefixLen)
				bestMatch = iface
				logger.Debugf("✓ IPv6 route match: %s -> %s (prefix: %d)", destIP, iface, prefixLen)
			}
		}
	}

	if bestMatch == "" {
		logger.Debugf("✗ No IPv6 route found for: %s", destIP)
		return ""
	}

	logger.Debugf("✓ Resolved IPv6 interface for %s: %s", destIP, bestMatch)
	return bestMatch
}

// convertIPv6HexToString converts IPv6 address in hex format from /proc/net/ipv6_route
// Format: 8 groups of 4 hex digits
func convertIPv6HexToString(hexStr string) string {
	if len(hexStr) != 32 {
		return ""
	}

	var parts []string
	for i := 0; i < 8; i++ {
		group := hexStr[i*4 : (i+1)*4]
		val, err := strconv.ParseUint(group, 16, 16)
		if err != nil {
			return ""
		}
		parts = append(parts, fmt.Sprintf("%04x", val))
	}

	ipStr := strings.Join(parts, ":")
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}

	return ip.String()
}
