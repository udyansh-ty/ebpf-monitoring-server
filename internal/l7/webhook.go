// Package l7 provides L7 layer protocol monitoring and Vaanvil webhook integration.
// This package handles receiving, parsing, and storing L7 telemetry data from external
// sources like Vaanvil network security sensors via webhook endpoints.
package l7

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/srodi/ebpf-server/pkg/logger"
)

// ANCHOR: L7 Webhook Event Types - Vaanvil v1.1 Schema Support - Jan 31, 2026
// WHY: Provide structured types for receiving L7 telemetry from Vaanvil sensors
// WHAT: Define WebhookEvent, WebhookPayload, TLS, Certificate, and Fingerprint structures
// HOW: Use tagged structs with JSON marshaling for HTTP request parsing and storage

// WebhookTLS represents TLS connection metadata from the webhook.
type WebhookTLS struct {
	SNI     string         `json:"sni,omitempty"`     // Server Name Indication
	ALPN    string         `json:"alpn,omitempty"`    // Application-Layer Protocol Negotiation
	Version string         `json:"version,omitempty"` // TLS version (e.g., "771" for TLS 1.2)
	QUIC    *WebhookQUIC   `json:"quic,omitempty"`    // QUIC-specific information
}

// WebhookQUIC represents QUIC connection information.
type WebhookQUIC struct {
	DCID string `json:"dcid,omitempty"` // Destination Connection ID
}

// WebhookJA3Features represents JA3 fingerprint component counts.
type WebhookJA3Features struct {
	CipherCount    int `json:"cipher_count,omitempty"`    // Number of ciphers
	ExtensionCount int `json:"extension_count,omitempty"` // Number of extensions
	CurveCount     int `json:"curve_count,omitempty"`     // Number of curves
	PointFormats   int `json:"point_formats,omitempty"`   // EC point formats count
}

// WebhookFingerprints represents multiple TLS fingerprinting algorithms.
type WebhookFingerprints struct {
	JA3         string               `json:"ja3,omitempty"`          // MD5-based fingerprint
	JA3Features *WebhookJA3Features  `json:"ja3_features,omitempty"` // JA3 component breakdown
	JA4         string               `json:"ja4,omitempty"`          // String-based fingerprint
	JA4Plus     string               `json:"ja4_plus,omitempty"`     // SHA256-based fingerprint
}

// WebhookCertificate represents X.509 certificate metadata.
type WebhookCertificate struct {
	LeafSHA256      string `json:"leaf_sha256,omitempty"`       // Leaf certificate SHA256
	IssuerCN        string `json:"issuer_cn,omitempty"`         // Issuer Common Name
	IssuerSHA256    string `json:"issuer_sha256,omitempty"`     // Issuer certificate SHA256
	PublicKeySHA256 string `json:"public_key_sha256,omitempty"` // Public key SHA256
	ExpiryTS        int64  `json:"expiry_ts,omitempty"`         // Expiration timestamp (Unix)
}

// WebhookVerdict represents traffic policy verdict and certificate validation.
type WebhookVerdict struct {
	Action              string `json:"action,omitempty"`               // "allow", "deny", "log"
	RuleID              string `json:"rule_id,omitempty"`              // Policy rule identifier
	Priority            int    `json:"priority,omitempty"`             // Rule priority
	CertValidationLevel string `json:"cert_validation_level,omitempty"` // "standard", "strict", "none"
	CertMismatchReason  string `json:"cert_mismatch_reason,omitempty"` // Reason for mismatch
	CertMismatchAction  string `json:"cert_mismatch_action,omitempty"` // Action taken on mismatch
}

// WebhookStats represents flow statistics and metrics.
type WebhookStats struct {
	Bytes               int64   `json:"bytes,omitempty"`                  // Total bytes transferred
	Packets             int64   `json:"packets,omitempty"`                // Total packets
	DurationMS          int64   `json:"duration_ms,omitempty"`            // Flow duration in milliseconds
	ExtractionLatencyMS float64 `json:"extraction_latency_ms,omitempty"`  // Data extraction latency
	SensorLatencyMS     float64 `json:"sensor_latency_ms,omitempty"`      // Sensor processing latency
	IngestLatencyMS     float64 `json:"ingest_latency_ms,omitempty"`      // Ingestion latency
}

// WebhookEvent represents a single L7 event from Vaanvil webhook (v1.1 schema).
type WebhookEvent struct {
	// Flow identification
	EventType   string `json:"event_type,omitempty"`   // "flow_update", "anomaly", "alert"
	FlowID      string `json:"flow_id,omitempty"`      // Human-readable flow identifier
	FlowKey     string `json:"flow_key,omitempty"`     // Unique flow key for deduplication
	ObservedAt  int64  `json:"observed_at,omitempty"`  // Observation timestamp (ms)
	FlowStartTS int64  `json:"flow_start_ts,omitempty"` // Flow start timestamp (ms)
	Direction   string `json:"direction,omitempty"`    // "inbound" or "outbound"
	IPVersion   int    `json:"ip_version,omitempty"`   // 4 or 6

	// Network addresses
	SrcIP    string `json:"src_ip,omitempty"`    // Source IP address
	SrcPort  uint16 `json:"src_port,omitempty"`  // Source port
	DstIP    string `json:"dst_ip,omitempty"`    // Destination IP address
	DstPort  uint16 `json:"dst_port,omitempty"`  // Destination port
	Protocol string `json:"protocol,omitempty"`  // "tcp", "udp", "quic"

	// L7 security metadata
	TLS          *WebhookTLS         `json:"tls,omitempty"`          // TLS connection metadata
	Fingerprints *WebhookFingerprints `json:"fingerprints,omitempty"` // TLS fingerprints
	Certificate  *WebhookCertificate `json:"certificate,omitempty"`   // Certificate metadata

	// Policy and verdict
	Verdict *WebhookVerdict `json:"verdict,omitempty"` // Traffic policy verdict

	// Statistics
	Stats *WebhookStats `json:"stats,omitempty"` // Flow metrics

	// Backward compatibility (v1.0)
	Metadata map[string]interface{} `json:"metadata,omitempty"` // Legacy metadata
}

// WebhookPayload represents a batch of L7 events from Vaanvil (v1.1 schema).
type WebhookPayload struct {
	// Batch metadata
	SchemaVersion  string          `json:"schema_version,omitempty"`   // "1.1"
	SentAt         string          `json:"sent_at,omitempty"`          // RFC3339 timestamp
	Source         string          `json:"source,omitempty"`           // Sensor identifier
	SourceInstance string          `json:"source_instance,omitempty"`  // Instance identifier
	Sequence       uint64          `json:"sequence,omitempty"`         // Monotonic sequence number
	BatchID        string          `json:"batch_id,omitempty"`         // Batch deduplication ID
	Events         []WebhookEvent  `json:"events,omitempty"`           // Batch of events
}

// L7Event represents an L7 event in the monitoring system.
// It implements the core.Event interface for storage and querying.
type L7Event struct {
	id        string                 // Unique event identifier
	eventType string                 // Event type from webhook
	pid       uint32                 // Process ID (0 for network-only events)
	command   string                 // Command name (from metadata or source)
	tsNs      uint64                 // Timestamp in nanoseconds since boot
	time      time.Time              // Wall-clock time
	metadata  map[string]interface{} // All L7 specific metadata
}

// NewL7Event creates a new L7 event from webhook data.
// ANCHOR: L7Event Factory - Webhook to Core Event Conversion - Jan 31, 2026
// WHY: Convert webhook events to core.Event interface for unified storage
// WHAT: Create L7Event with unique ID, timestamp conversion, metadata enrichment
// HOW: Hash flow key + timestamp, parse webhook fields into metadata map
func NewL7Event(payload *WebhookPayload, webhookEvent *WebhookEvent) (*L7Event, error) {
	if webhookEvent == nil {
		return nil, fmt.Errorf("webhook event cannot be nil")
	}

	// Calculate unique event ID from flow key and timestamp
	idInput := fmt.Sprintf("%s:%d:%s", webhookEvent.FlowKey, webhookEvent.ObservedAt, webhookEvent.EventType)
	idHash := sha256.Sum256([]byte(idInput))
	eventID := fmt.Sprintf("%x", idHash)[:16]

	// Convert webhook timestamp (milliseconds) to wall-clock time
	wallClockTime := time.UnixMilli(webhookEvent.ObservedAt)

	// Extract metadata from webhook event
	metadata := make(map[string]interface{})

	// Flow identification
	metadata["flow_id"] = webhookEvent.FlowID
	metadata["flow_key"] = webhookEvent.FlowKey
	metadata["event_type"] = webhookEvent.EventType
	metadata["direction"] = webhookEvent.Direction

	// Network information
	metadata["src_ip"] = webhookEvent.SrcIP
	metadata["src_port"] = webhookEvent.SrcPort
	metadata["dst_ip"] = webhookEvent.DstIP
	metadata["dst_port"] = webhookEvent.DstPort
	metadata["protocol"] = webhookEvent.Protocol
	metadata["ip_version"] = webhookEvent.IPVersion

	// TLS metadata
	if webhookEvent.TLS != nil {
		tls := make(map[string]interface{})
		tls["sni"] = webhookEvent.TLS.SNI
		tls["alpn"] = webhookEvent.TLS.ALPN
		tls["version"] = webhookEvent.TLS.Version
		if webhookEvent.TLS.QUIC != nil {
			tls["quic_dcid"] = webhookEvent.TLS.QUIC.DCID
		}
		metadata["tls"] = tls
	}

	// Fingerprints
	if webhookEvent.Fingerprints != nil {
		fp := make(map[string]interface{})
		fp["ja3"] = webhookEvent.Fingerprints.JA3
		fp["ja4"] = webhookEvent.Fingerprints.JA4
		fp["ja4_plus"] = webhookEvent.Fingerprints.JA4Plus
		if webhookEvent.Fingerprints.JA3Features != nil {
			fp["ja3_cipher_count"] = webhookEvent.Fingerprints.JA3Features.CipherCount
			fp["ja3_extension_count"] = webhookEvent.Fingerprints.JA3Features.ExtensionCount
			fp["ja3_curve_count"] = webhookEvent.Fingerprints.JA3Features.CurveCount
		}
		metadata["fingerprints"] = fp
	}

	// Certificate metadata
	if webhookEvent.Certificate != nil {
		cert := make(map[string]interface{})
		cert["leaf_sha256"] = webhookEvent.Certificate.LeafSHA256
		cert["issuer_cn"] = webhookEvent.Certificate.IssuerCN
		cert["issuer_sha256"] = webhookEvent.Certificate.IssuerSHA256
		cert["public_key_sha256"] = webhookEvent.Certificate.PublicKeySHA256
		cert["expiry_ts"] = webhookEvent.Certificate.ExpiryTS
		metadata["certificate"] = cert
	}

	// Verdict
	if webhookEvent.Verdict != nil {
		verdict := make(map[string]interface{})
		verdict["action"] = webhookEvent.Verdict.Action
		verdict["rule_id"] = webhookEvent.Verdict.RuleID
		verdict["priority"] = webhookEvent.Verdict.Priority
		verdict["cert_validation_level"] = webhookEvent.Verdict.CertValidationLevel
		verdict["cert_mismatch_reason"] = webhookEvent.Verdict.CertMismatchReason
		verdict["cert_mismatch_action"] = webhookEvent.Verdict.CertMismatchAction
		metadata["verdict"] = verdict
	}

	// Statistics
	if webhookEvent.Stats != nil {
		stats := make(map[string]interface{})
		stats["bytes"] = webhookEvent.Stats.Bytes
		stats["packets"] = webhookEvent.Stats.Packets
		stats["duration_ms"] = webhookEvent.Stats.DurationMS
		stats["extraction_latency_ms"] = webhookEvent.Stats.ExtractionLatencyMS
		stats["sensor_latency_ms"] = webhookEvent.Stats.SensorLatencyMS
		stats["ingest_latency_ms"] = webhookEvent.Stats.IngestLatencyMS
		metadata["stats"] = stats
	}

	// Batch metadata
	if payload != nil {
		metadata["batch_id"] = payload.BatchID
		metadata["batch_sequence"] = payload.Sequence
		metadata["sensor_source"] = payload.Source
		metadata["schema_version"] = payload.SchemaVersion
	}

	// Merge with any legacy metadata
	if len(webhookEvent.Metadata) > 0 {
		metadata["legacy_metadata"] = webhookEvent.Metadata
	}

	event := &L7Event{
		id:        eventID,
		eventType: "l7_" + webhookEvent.EventType,
		pid:       0, // L7 events are network-level, not process-level
		command:   webhookEvent.FlowID,
		tsNs:      uint64(wallClockTime.UnixNano()),
		time:      wallClockTime,
		metadata:  metadata,
	}

	logger.Debugf("📊 Created L7Event: type=%s flow=%s ts=%d", event.eventType, webhookEvent.FlowID, event.tsNs)
	return event, nil
}

// ID implements core.Event
func (e *L7Event) ID() string {
	return e.id
}

// Type implements core.Event
func (e *L7Event) Type() string {
	return e.eventType
}

// PID implements core.Event
func (e *L7Event) PID() uint32 {
	return e.pid
}

// Command implements core.Event
func (e *L7Event) Command() string {
	return e.command
}

// Timestamp implements core.Event
func (e *L7Event) Timestamp() uint64 {
	return e.tsNs
}

// Time implements core.Event
func (e *L7Event) Time() time.Time {
	return e.time
}

// Metadata implements core.Event
func (e *L7Event) Metadata() map[string]interface{} {
	return e.metadata
}

// MarshalJSON implements json.Marshaler
func (e *L7Event) MarshalJSON() ([]byte, error) {
	m := map[string]interface{}{
		"id":        e.id,
		"type":      e.eventType,
		"pid":       e.pid,
		"command":   e.command,
		"timestamp": e.tsNs,
		"time":      e.time.Format(time.RFC3339Nano),
	}
	for k, v := range e.metadata {
		m[k] = v
	}
	return json.Marshal(m)
}
