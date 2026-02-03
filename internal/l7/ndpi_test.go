package l7

import "testing"

func TestClassifyFlowHTTPS(t *testing.T) {
	flow := ndpiFlow{
		SrcIP:    "192.168.1.10",
		DstIP:    "8.8.8.8",
		SrcPort:  40000,
		DstPort:  443,
		Protocol: "tcp",
		SNI:      "www.example.com",
	}

	info := classifyFlow(flow)
	if info.ProtocolName != "TLS" {
		t.Fatalf("expected TLS protocol, got %s", info.ProtocolName)
	}
	if info.Category != "Encrypted" {
		t.Fatalf("expected Encrypted category, got %s", info.Category)
	}
	if info.Confidence < 0.5 {
		t.Fatalf("expected confidence >= 0.5, got %f", info.Confidence)
	}
}

func TestClassifyFlowYouTube(t *testing.T) {
	flow := ndpiFlow{
		Protocol: "tcp",
		DstPort:  443,
		SNI:      "youtube.com",
	}
	info := classifyFlow(flow)
	if info.Application != "YouTube" {
		t.Fatalf("expected YouTube, got %s", info.Application)
	}
	if info.Category != "Video" {
		t.Fatalf("expected Video category, got %s", info.Category)
	}
	if info.Confidence < 0.8 {
		t.Fatalf("expected confidence >=0.8, got %f", info.Confidence)
	}
}

func TestNormalizeIP(t *testing.T) {
	ip := normalizeIP("192.168.1.1")
	if ip != "192.168.1.1" {
		t.Fatalf("unexpected normalized IP: %s", ip)
	}
	ip = normalizeIP("::1")
	if ip != "::1" {
		t.Fatalf("unexpected normalized IPv6: %s", ip)
	}
}
