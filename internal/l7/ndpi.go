package l7

import (
	"fmt"
	"net"
	"strings"
)

// ndpiFlow encapsulates the tuple used for NDPI classification.
type ndpiFlow struct {
	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	Protocol string
	SNI      string
	ALPN     string
	JA3      string
	JA4      string
}

// ndpiInfo represents the NDPI result injected into metadata.
type ndpiInfo struct {
	ProtocolName   string
	Category       string
	Application    string
	Confidence     float64
	NDPIProtocolID int
}

// classifyFlow performs a lightweight NDPI-style classification based on heuristics.
func classifyFlow(flow ndpiFlow) ndpiInfo {
	info := ndpiInfo{
		ProtocolName: "unknown",
		Category:     "unknown",
		Application:  "unknown",
		Confidence:   0.1,
	}

	switch flow.Protocol {
	case "tcp":
		switch flow.DstPort {
		case 443:
			info.ProtocolName = "TLS"
			info.Category = "Encrypted"
			info.Application = "HTTPS"
			info.Confidence = 0.6
		case 80:
			info.ProtocolName = "HTTP"
			info.Category = "Web"
			info.Application = "HTTP"
			info.Confidence = 0.5
		default:
			info.ProtocolName = fmt.Sprintf("tcp/%d", flow.DstPort)
			info.Category = "custom"
			info.Application = "custom"
		}
	case "udp":
		if flow.DstPort == 123 {
			info.ProtocolName = "NTP"
			info.Category = "time"
			info.Application = "NTP"
			info.Confidence = 0.4
		}
	}

	if strings.Contains(strings.ToLower(flow.SNI), "youtube") {
		info.ProtocolName = "YouTube"
		info.Category = "Video"
		info.Application = "YouTube"
		info.Confidence = 0.85
	}

	if strings.Contains(strings.ToLower(flow.SNI), "google") && flow.DstPort == 443 {
		info.Category = "Search"
		info.Application = "Google HTTPS"
		info.Confidence = 0.75
	}

	if flow.JA4 != "" && strings.HasPrefix(flow.JA4, "771,1,0") {
		info.ProtocolName = "TLS-Old"
		info.Category = "legacy"
		info.Confidence = 0.5
	}

	if flow.JA3 != "" && strings.Contains(flow.JA3, "e7d705a3") {
		info.Application = "Google bot"
		info.Confidence = 0.8
	}

	return info
}

func normalizeIP(ip string) string {
	if ip == "" {
		return ""
	}
	if parsed := net.ParseIP(ip); parsed != nil {
		return parsed.String()
	}
	return ip
}
