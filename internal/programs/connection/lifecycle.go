package connection

import (
	"bufio"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/srodi/ebpf-server/pkg/logger"
)

// ConnectionStats holds information about a socket connection
type ConnectionStats struct {
	RxQueue       uint64 // Receive queue size (bytes in kernel buffer)
	TxQueue       uint64 // Transmit queue size (bytes in kernel buffer)
	ActiveSeconds int64  // How long connection has been active
	State         string // Connection state (ESTABLISHED, TIME_WAIT, etc.)
}

// ConnectionKey uniquely identifies a connection
type ConnectionKey struct {
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16
	Family  uint16 // AF_INET or AF_INET6
}

// getConnectionStats reads current socket statistics from /proc/net/tcp[6]
// This gives us real-time packet queue information
func getConnectionStats(key ConnectionKey, connStartTime time.Time) *ConnectionStats {
	if key.SrcIP == "" || key.DstIP == "" {
		return nil
	}

	// Determine which file to read based on address family
	procFile := "/proc/net/tcp"
	if key.Family == afInet6 {
		procFile = "/proc/net/ipv6_route"
	}

	file, err := os.Open(procFile)
	if err != nil {
		logger.Debugf("[Lifecycle] Failed to open %s: %v", procFile, err)
		return nil
	}
	defer file.Close()

	stats := &ConnectionStats{
		ActiveSeconds: int64(time.Since(connStartTime).Seconds()),
	}

	scanner := bufio.NewScanner(file)

	// Skip header line
	if !scanner.Scan() {
		return stats
	}

	// Format of /proc/net/tcp:
	// sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
	// Example: 0: 0100007F:1F90 0A000001:1F90 01 00000000:00000000 00:00000000 00000000 1000 0 12345

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)

		// Need at least: local_address(1), rem_address(2), tx_queue(3), rx_queue(4)
		if len(fields) < 5 {
			continue
		}

		// fields[0] is the index (sl), fields[1] is local_address, fields[2] is rem_address
		localAddr := fields[1]
		remoteAddr := fields[2]
		txQueue := fields[3]
		rxQueue := fields[4]

		// Parse local address (source IP:port)
		localParts := strings.Split(localAddr, ":")
		if len(localParts) != 2 {
			continue
		}

		localIP := convertIPv4HexToString(localParts[0])
		localPort, err := strconv.ParseUint(localParts[1], 16, 16)
		if err != nil {
			continue
		}

		// Parse remote address (destination IP:port)
		remoteParts := strings.Split(remoteAddr, ":")
		if len(remoteParts) != 2 {
			continue
		}

		remoteIP := convertIPv4HexToString(remoteParts[0])
		remotePort, err := strconv.ParseUint(remoteParts[1], 16, 16)
		if err != nil {
			continue
		}

		// Check if this matches our connection
		if localIP == key.SrcIP && uint16(localPort) == key.SrcPort &&
			remoteIP == key.DstIP && uint16(remotePort) == key.DstPort {

			// Parse queue sizes (they're in hex)
			txVal, err1 := strconv.ParseUint(txQueue, 16, 64)
			rxVal, err2 := strconv.ParseUint(rxQueue, 16, 64)

			if err1 == nil {
				stats.TxQueue = txVal
			}
			if err2 == nil {
				stats.RxQueue = rxVal
			}

			logger.Debugf("[Lifecycle] Found connection %s:%d -> %s:%d: tx=%d rx=%d active=%ds",
				localIP, localPort, remoteIP, remotePort, txVal, rxVal, stats.ActiveSeconds)

			return stats
		}
	}

	// Connection not found in /proc (might be closed or filtered)
	logger.Debugf("[Lifecycle] Connection %s:%d -> %s:%d not found in /proc/net/tcp",
		key.SrcIP, key.SrcPort, key.DstIP, key.DstPort)

	return stats
}

// convertIPv4HexToString converts hex string from /proc/net/tcp to dotted IP
// Example: "0100007F" -> "127.0.0.1" (little-endian)
func convertIPv4HexToString(hexStr string) string {
	if len(hexStr) != 8 {
		return ""
	}

	// Parse as uint32 in hex
	val, err := strconv.ParseUint(hexStr, 16, 32)
	if err != nil {
		return ""
	}

	// Convert from little-endian hex to IP bytes
	bytes := make([]byte, 4)
	bytes[0] = byte(val)
	bytes[1] = byte(val >> 8)
	bytes[2] = byte(val >> 16)
	bytes[3] = byte(val >> 24)

	ip := net.IPv4(bytes[0], bytes[1], bytes[2], bytes[3])
	return ip.String()
}

// enrichEventWithLifecycleData adds connection statistics to event metadata
func enrichEventWithLifecycleData(
	metadata map[string]interface{},
	srcIP string,
	srcPort uint16,
	dstIP string,
	dstPort uint16,
	family uint16,
	eventTime time.Time,
) {
	if srcIP == "" || dstIP == "" {
		return
	}

	key := ConnectionKey{
		SrcIP:   srcIP,
		SrcPort: srcPort,
		DstIP:   dstIP,
		DstPort: dstPort,
		Family:  family,
	}

	stats := getConnectionStats(key, eventTime)
	if stats == nil {
		return
	}

	// Add to metadata
	metadata["packets_in"] = stats.RxQueue
	metadata["packets_out"] = stats.TxQueue
	metadata["active_seconds"] = stats.ActiveSeconds

	logger.Debugf("[Lifecycle] Added stats to event: in=%d out=%d active=%ds",
		stats.RxQueue, stats.TxQueue, stats.ActiveSeconds)
}
