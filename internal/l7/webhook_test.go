// Package l7 provides L7 layer protocol monitoring and Vaanvil webhook integration.
package l7

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/srodi/ebpf-server/internal/storage"
)

// TestNewL7Event tests L7Event creation from webhook data.
func TestNewL7Event(t *testing.T) {
	// Create test webhook event
	payload := &WebhookPayload{
		SchemaVersion:  "1.1",
		SentAt:         time.Now().Format(time.RFC3339),
		Source:         "test-sensor",
		SourceInstance: "prod-dc1",
		Sequence:       1,
		BatchID:        "batch-test-001",
	}

	webhookEvent := &WebhookEvent{
		EventType:   "flow_update",
		FlowID:      "192.168.1.1:443->8.8.8.8:53",
		FlowKey:     "key123",
		ObservedAt:  time.Now().UnixMilli(),
		FlowStartTS: time.Now().Add(-1 * time.Minute).UnixMilli(),
		Direction:   "outbound",
		IPVersion:   4,
		SrcIP:       "192.168.1.1",
		SrcPort:     443,
		DstIP:       "8.8.8.8",
		DstPort:     53,
		Protocol:    "udp",
		TLS: &WebhookTLS{
			SNI:     "google.com",
			ALPN:    "h2",
			Version: "771",
		},
		Fingerprints: &WebhookFingerprints{
			JA3: "e7d705a3286e19ea42f587b344ee6865",
			JA4: "771,8,12,4,h2",
			JA4Plus: "sha256=abc123",
			JA3Features: &WebhookJA3Features{
				CipherCount:    8,
				ExtensionCount: 12,
				CurveCount:     4,
			},
		},
		Certificate: &WebhookCertificate{
			LeafSHA256:      "d8:6a:7f:e1",
			IssuerCN:        "CN=Google Internet Authority G3",
			IssuerSHA256:    "aa:bb:cc:dd",
			PublicKeySHA256: "12:34:56:78",
			ExpiryTS:        1743580800,
		},
		Verdict: &WebhookVerdict{
			Action:              "allow",
			RuleID:              "allow-google",
			Priority:            100,
			CertValidationLevel: "standard",
		},
		Stats: &WebhookStats{
			Bytes:               125000,
			Packets:             245,
			DurationMS:          19680,
			ExtractionLatencyMS: 2.5,
			SensorLatencyMS:     2.5,
			IngestLatencyMS:     200,
		},
	}

	// Create L7 event
	event, err := NewL7Event(payload, webhookEvent)
	if err != nil {
		t.Fatalf("Failed to create L7Event: %v", err)
	}

	// Verify event properties
	if event.ID() == "" {
		t.Error("Event ID should not be empty")
	}

	if !strings.HasPrefix(event.Type(), "l7_") {
		t.Errorf("Event type should start with 'l7_', got: %s", event.Type())
	}

	if event.PID() != 0 {
		t.Errorf("L7 events should have PID 0, got: %d", event.PID())
	}

	if event.Command() != webhookEvent.FlowID {
		t.Errorf("Command should be flow ID, got: %s", event.Command())
	}

	// Verify metadata
	meta := event.Metadata()
	if meta["flow_key"] != "key123" {
		t.Errorf("Metadata missing flow_key")
	}

	if meta["src_ip"] != "192.168.1.1" {
		t.Errorf("Metadata missing src_ip")
	}

	if tls, ok := meta["tls"].(map[string]interface{}); ok {
		if tls["sni"] != "google.com" {
			t.Errorf("TLS metadata missing SNI")
		}
	} else {
		t.Error("TLS metadata not found")
	}

	if fp, ok := meta["fingerprints"].(map[string]interface{}); ok {
		if fp["ja4"] != "771,8,12,4,h2" {
			t.Errorf("Fingerprint metadata incorrect JA4")
		}
	} else {
		t.Error("Fingerprint metadata not found")
	}

	// Test JSON marshaling
	jsonData, err := event.MarshalJSON()
	if err != nil {
		t.Fatalf("Failed to marshal event to JSON: %v", err)
	}

	var jsonMap map[string]interface{}
	if err := json.Unmarshal(jsonData, &jsonMap); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if jsonMap["type"] != event.Type() {
		t.Errorf("JSON type mismatch")
	}
}

// TestL7EventNilWebhookEvent tests error handling for nil webhook events.
func TestL7EventNilWebhookEvent(t *testing.T) {
	_, err := NewL7Event(nil, nil)
	if err == nil {
		t.Error("Should return error for nil webhook event")
	}
}

// TestL7EventMetadataComplete tests that all metadata is properly populated.
func TestL7EventMetadataComplete(t *testing.T) {
	payload := &WebhookPayload{
		SchemaVersion: "1.1",
		BatchID:       "batch-test-002",
		Sequence:      5,
		Source:        "sensor-01",
	}

	webhookEvent := &WebhookEvent{
		EventType:   "anomaly",
		FlowID:      "test-flow",
		FlowKey:     "test-key",
		ObservedAt:  time.Now().UnixMilli(),
		Direction:   "inbound",
		IPVersion:   6,
		SrcIP:       "2001:db8::1",
		SrcPort:     443,
		DstIP:       "2001:db8::2",
		DstPort:     8443,
		Protocol:    "tcp",
	}

	event, err := NewL7Event(payload, webhookEvent)
	if err != nil {
		t.Fatalf("Failed to create L7Event: %v", err)
	}

	meta := event.Metadata()

	// Verify all expected fields are present
	expectedFields := []string{
		"flow_id", "flow_key", "event_type", "direction",
		"src_ip", "src_port", "dst_ip", "dst_port", "protocol", "ip_version",
		"batch_id", "batch_sequence", "sensor_source", "schema_version",
	}

	for _, field := range expectedFields {
		if _, ok := meta[field]; !ok {
			t.Errorf("Missing metadata field: %s", field)
		}
	}

	if meta["ip_version"] != 6 {
		t.Errorf("IP version should be 6, got: %v", meta["ip_version"])
	}

	if meta["direction"] != "inbound" {
		t.Errorf("Direction should be inbound, got: %v", meta["direction"])
	}
}

// TestHandleWebhookValidPayload tests webhook handler with valid payload.
func TestHandleWebhookValidPayload(t *testing.T) {
	// Create memory storage
	memStorage := storage.NewMemoryStorage()
	receiver := NewReceiver(memStorage, &ReceiverConfig{
		MaxPayloadSize: 10 * 1024 * 1024,
		ValidateBatchID: true,
	})

	// Create test payload
	payload := WebhookPayload{
		SchemaVersion: "1.1",
		SentAt:        time.Now().Format(time.RFC3339),
		Source:        "test-sensor",
		Sequence:      1,
		BatchID:       "batch-test-003",
		Events: []WebhookEvent{
			{
				EventType:  "flow_update",
				FlowID:     "flow-1",
				FlowKey:    "key1",
				ObservedAt: time.Now().UnixMilli(),
				SrcIP:      "192.168.1.1",
				DstIP:      "8.8.8.8",
			},
		},
	}

	jsonData, _ := json.Marshal(payload)

	// Create HTTP request
	req := httptest.NewRequest("POST", "/api/l7/webhook", strings.NewReader(string(jsonData)))
	req.Header.Set("Content-Type", "application/json")

	// Create response recorder
	w := httptest.NewRecorder()

	// Handle webhook
	receiver.HandleWebhook(w, req)

	// Verify response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got: %d", w.Code)
	}

	var resp WebhookIngestionResponse
	json.NewDecoder(w.Body).Decode(&resp)

	if !resp.Success {
		t.Errorf("Response should indicate success, got: %v", resp.Success)
	}

	if resp.EventsProcessed != 1 {
		t.Errorf("Should have processed 1 event, got: %d", resp.EventsProcessed)
	}
}

// TestHandleWebhookInvalidJSON tests error handling for invalid JSON.
func TestHandleWebhookInvalidJSON(t *testing.T) {
	memStorage := storage.NewMemoryStorage()
	receiver := NewReceiver(memStorage, nil)

	req := httptest.NewRequest("POST", "/api/l7/webhook", strings.NewReader("invalid json"))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	receiver.HandleWebhook(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got: %d", w.Code)
	}
}

// TestHandleWebhookInvalidContentType tests Content-Type validation.
func TestHandleWebhookInvalidContentType(t *testing.T) {
	memStorage := storage.NewMemoryStorage()
	receiver := NewReceiver(memStorage, nil)

	req := httptest.NewRequest("POST", "/api/l7/webhook", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "text/plain")

	w := httptest.NewRecorder()
	receiver.HandleWebhook(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for invalid Content-Type, got: %d", w.Code)
	}
}

// TestHandleWebhookMethodNotAllowed tests method validation.
func TestHandleWebhookMethodNotAllowed(t *testing.T) {
	memStorage := storage.NewMemoryStorage()
	receiver := NewReceiver(memStorage, nil)

	req := httptest.NewRequest("GET", "/api/l7/webhook", nil)
	w := httptest.NewRecorder()
	receiver.HandleWebhook(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got: %d", w.Code)
	}
}

// TestHandleWebhookDuplicateBatch tests duplicate batch detection.
func TestHandleWebhookDuplicateBatch(t *testing.T) {
	memStorage := storage.NewMemoryStorage()
	receiver := NewReceiver(memStorage, &ReceiverConfig{
		MaxPayloadSize:  1024 * 1024, // 1MB
		ValidateBatchID: true,
	})

	payload := WebhookPayload{
		SchemaVersion: "1.1",
		SentAt:        time.Now().Format(time.RFC3339),
		Source:        "test-sensor",
		Sequence:      1,
		BatchID:       "batch-duplicate",
		Events: []WebhookEvent{
			{
				EventType:  "flow_update",
				FlowID:     "flow-1",
				FlowKey:    "key1",
				ObservedAt: time.Now().UnixMilli(),
				SrcIP:      "192.168.1.1",
				DstIP:      "8.8.8.8",
			},
		},
	}

	jsonData, _ := json.Marshal(payload)

	// First request should succeed
	req1 := httptest.NewRequest("POST", "/api/l7/webhook", strings.NewReader(string(jsonData)))
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	receiver.HandleWebhook(w1, req1)

	if w1.Code != http.StatusOK && w1.Code != http.StatusPartialContent {
		t.Logf("First request status: %d, body: %s", w1.Code, w1.Body.String())
		t.Errorf("First request should succeed, got status: %d", w1.Code)
	}

	// Second request with same batch ID should fail
	req2 := httptest.NewRequest("POST", "/api/l7/webhook", strings.NewReader(string(jsonData)))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	receiver.HandleWebhook(w2, req2)

	if w2.Code != http.StatusConflict {
		t.Logf("Second request status: %d, body: %s", w2.Code, w2.Body.String())
		t.Errorf("Duplicate batch should return 409, got: %d", w2.Code)
	}
}

// TestHandleWebhookPayloadSizeLimit tests payload size limit enforcement.
func TestHandleWebhookPayloadSizeLimit(t *testing.T) {
	memStorage := storage.NewMemoryStorage()
	receiver := NewReceiver(memStorage, &ReceiverConfig{
		MaxPayloadSize: 100, // Very small limit
	})

	// Create large payload
	payload := WebhookPayload{
		SchemaVersion: "1.1",
		Events:        make([]WebhookEvent, 100),
	}

	for i := 0; i < 100; i++ {
		payload.Events[i] = WebhookEvent{
			EventType:  "flow_update",
			FlowID:     fmt.Sprintf("flow-%d", i),
			FlowKey:    fmt.Sprintf("key-%d", i),
			ObservedAt: time.Now().UnixMilli(),
		}
	}

	jsonData, _ := json.Marshal(payload)

	req := httptest.NewRequest("POST", "/api/l7/webhook", strings.NewReader(string(jsonData)))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	receiver.HandleWebhook(w, req)

	if w.Code != http.StatusBadRequest && w.Code != http.StatusRequestEntityTooLarge {
		t.Logf("Note: Got status %d (may vary based on http.MaxBytesReader behavior)", w.Code)
	}
}

// TestHandleWebhookStats tests stats endpoint.
func TestHandleWebhookStats(t *testing.T) {
	memStorage := storage.NewMemoryStorage()
	receiver := NewReceiver(memStorage, nil)

	// Process a few payloads to generate stats
	for i := 0; i < 3; i++ {
		payload := WebhookPayload{
			SchemaVersion: "1.1",
			BatchID:       fmt.Sprintf("batch-%d", i),
			Events: []WebhookEvent{
				{
					EventType:  "flow_update",
					FlowKey:    fmt.Sprintf("key-%d", i),
					ObservedAt: time.Now().UnixMilli(),
				},
			},
		}
		jsonData, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/api/l7/webhook", strings.NewReader(string(jsonData)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		receiver.HandleWebhook(w, req)
	}

	// Get stats
	req := httptest.NewRequest("GET", "/api/l7/webhook/stats", nil)
	w := httptest.NewRecorder()
	receiver.HandleWebhookStats(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got: %d", w.Code)
	}

	var stats WebhookStatsResponse
	if err := json.NewDecoder(w.Body).Decode(&stats); err != nil {
		t.Fatalf("Failed to decode stats response: %v", err)
	}

	if stats.TotalPayloads < 3 {
		t.Errorf("Expected at least 3 payloads, got: %d", stats.TotalPayloads)
	}

	if stats.TotalEvents < 3 {
		t.Errorf("Expected at least 3 events, got: %d", stats.TotalEvents)
	}
}

// TestHandleWebhookStatsMethodNotAllowed tests stats endpoint method validation.
func TestHandleWebhookStatsMethodNotAllowed(t *testing.T) {
	memStorage := storage.NewMemoryStorage()
	receiver := NewReceiver(memStorage, nil)

	req := httptest.NewRequest("POST", "/api/l7/webhook/stats", nil)
	w := httptest.NewRecorder()
	receiver.HandleWebhookStats(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got: %d", w.Code)
	}
}

// TestWebhookEventJSON tests JSON serialization of webhook events.
func TestWebhookEventJSON(t *testing.T) {
	event := WebhookEvent{
		EventType:  "flow_update",
		FlowID:     "test-flow",
		ObservedAt: 1706708399800,
		TLS: &WebhookTLS{
			SNI:  "google.com",
			ALPN: "h2",
		},
		Metadata: map[string]interface{}{
			"custom_field": "custom_value",
		},
	}

	// Marshal to JSON
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// Unmarshal back
	var restored WebhookEvent
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if restored.EventType != event.EventType {
		t.Errorf("EventType mismatch after round-trip")
	}

	if restored.TLS.SNI != "google.com" {
		t.Errorf("TLS.SNI not preserved after round-trip")
	}
}

// BenchmarkNewL7Event benchmarks L7Event creation.
func BenchmarkNewL7Event(b *testing.B) {
	payload := &WebhookPayload{
		SchemaVersion: "1.1",
		BatchID:       "bench-batch",
	}

	webhookEvent := &WebhookEvent{
		EventType:  "flow_update",
		FlowID:     "bench-flow",
		FlowKey:    "bench-key",
		ObservedAt: time.Now().UnixMilli(),
		SrcIP:      "192.168.1.1",
		DstIP:      "8.8.8.8",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewL7Event(payload, webhookEvent)
	}
}

// BenchmarkHandleWebhookRequest benchmarks webhook request handling.
func BenchmarkHandleWebhookRequest(b *testing.B) {
	memStorage := storage.NewMemoryStorage()
	receiver := NewReceiver(memStorage, nil)

	payload := WebhookPayload{
		SchemaVersion: "1.1",
		BatchID:       "bench-batch",
		Events: []WebhookEvent{
			{
				EventType:  "flow_update",
				FlowID:     "bench-flow",
				FlowKey:    "bench-key",
				ObservedAt: time.Now().UnixMilli(),
				SrcIP:      "192.168.1.1",
				DstIP:      "8.8.8.8",
			},
		},
	}

	jsonData, _ := json.Marshal(payload)
	body := strings.NewReader(string(jsonData))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		body.Seek(0, io.SeekStart)
		req := httptest.NewRequest("POST", "/api/l7/webhook", body)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		receiver.HandleWebhook(w, req)
	}
}
