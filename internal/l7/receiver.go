// Package l7 provides L7 layer protocol monitoring and Vaanvil webhook integration.
package l7

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/srodi/ebpf-server/internal/core"
	"github.com/srodi/ebpf-server/pkg/logger"
)

// ReceiverConfig represents configuration for the L7 webhook receiver.
type ReceiverConfig struct {
	// MaxPayloadSize is the maximum accepted webhook payload size (bytes)
	MaxPayloadSize int64
	// RequestTimeout is the context timeout for webhook processing
	RequestTimeout time.Duration
	// ValidateBatchID enables deduplication via batch ID tracking
	ValidateBatchID bool
}

// ReceiverStats tracks webhook receiver statistics.
type ReceiverStats struct {
	TotalPayloads      int64
	TotalEvents        int64
	FailedPayloads     int64
	FailedEvents       int64
	DuplicateEvents    int64
	AveragePayloadSize int64
	mu                 atomic.Value // Stores stats snapshot
}

// Receiver handles incoming L7 webhook events from Vaanvil sensors.
// ANCHOR: L7 Webhook Receiver - Vaanvil Event Ingestion - Jan 31, 2026
// WHY: Accept and process L7 telemetry from external security sensors
// WHAT: HTTP handler that validates, parses, deduplicates, and stores webhook events
// HOW: Listen on endpoint, validate schema, parse events, store via EventSink
type Receiver struct {
	storage    core.EventSink
	config     *ReceiverConfig
	stats      *ReceiverStats
	seenBatch  map[string]time.Time // Batch ID → last seen time (for dedup)
	maxBatches int                   // Max batches to track in memory
}

// NewReceiver creates a new L7 webhook receiver.
func NewReceiver(storage core.EventSink, config *ReceiverConfig) *Receiver {
	if config == nil {
		config = &ReceiverConfig{
			MaxPayloadSize:  10 * 1024 * 1024, // 10MB default
			RequestTimeout:  30 * time.Second,
			ValidateBatchID: true,
		}
	}

	return &Receiver{
		storage:    storage,
		config:     config,
		stats:      &ReceiverStats{},
		seenBatch:  make(map[string]time.Time),
		maxBatches: 10000,
	}
}

// HandleWebhook handles incoming L7 webhook events from Vaanvil.
// ANCHOR: HTTP Handler - Webhook Event Processing - Jan 31, 2026
// WHY: Expose HTTP endpoint for external sensors to deliver L7 events
// WHAT: Accept POST requests with JSON webhook payloads
// HOW: Parse, validate, deduplicate by batch ID, store events
//
// @Summary		Receive L7 webhook events
// @Description	Ingests L7 telemetry (SSL/TLS, HTTP, DNS) from external sensors
// @Tags			l7
// @Accept			json
// @Produce		json
// @Param			body	body	WebhookPayload	true	"Webhook payload"
// @Success		200	{object}	WebhookIngestionResponse
// @Failure		400	{object}	ErrorResponse	"Invalid payload"
// @Failure		409	{object}	ErrorResponse	"Duplicate batch"
// @Failure		500	{object}	ErrorResponse	"Storage error"
// @Router			/api/l7/webhook [post]
func (r *Receiver) HandleWebhook(w http.ResponseWriter, req *http.Request) {
	// Create context with timeout
	ctx, cancel := context.WithTimeout(req.Context(), r.config.RequestTimeout)
	defer cancel()

	// Validate request method
	if req.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate Content-Type
	if req.Header.Get("Content-Type") != "application/json" {
		http.Error(w, `Expected Content-Type: application/json`, http.StatusBadRequest)
		return
	}

	// Limit request body size
	req.Body = http.MaxBytesReader(w, req.Body, r.config.MaxPayloadSize)
	defer req.Body.Close()

	// Read and parse payload
	body, err := io.ReadAll(req.Body)
	if err != nil {
		atomic.AddInt64(&r.stats.FailedPayloads, 1)
		r.respondError(w, http.StatusBadRequest, fmt.Sprintf("Failed to read body: %v", err))
		return
	}

	var payload WebhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		atomic.AddInt64(&r.stats.FailedPayloads, 1)
		r.respondError(w, http.StatusBadRequest, fmt.Sprintf("Invalid JSON: %v", err))
		return
	}

	atomic.AddInt64(&r.stats.TotalPayloads, 1)

	// Validate schema version
	if payload.SchemaVersion == "" {
		payload.SchemaVersion = "1.1"
	}
	if payload.SchemaVersion != "1.1" && payload.SchemaVersion != "1.0" {
		atomic.AddInt64(&r.stats.FailedPayloads, 1)
		r.respondError(w, http.StatusBadRequest, fmt.Sprintf("Unsupported schema version: %s", payload.SchemaVersion))
		return
	}

	// Check for duplicate batch (if deduplication enabled)
	if r.config.ValidateBatchID && payload.BatchID != "" {
		if lastSeen, exists := r.seenBatch[payload.BatchID]; exists {
			// Batch already processed recently
			logger.Errorf("Duplicate webhook batch: %s (last seen %v ago)", payload.BatchID, time.Since(lastSeen))
			r.respondError(w, http.StatusConflict, "Duplicate batch")
			return
		}
		// Record batch as seen
		r.seenBatch[payload.BatchID] = time.Now()
		// Cleanup old entries if map grows too large
		if len(r.seenBatch) > r.maxBatches {
			r.cleanupOldBatches()
		}
	}

	// Process events
	eventsProcessed := 0
	eventsFailed := 0

	for i, webhookEvent := range payload.Events {
		// Create L7Event from webhook data
		l7Event, err := NewL7Event(&payload, &webhookEvent)
		if err != nil {
			logger.Errorf("Failed to parse webhook event %d: %v", i, err)
			atomic.AddInt64(&r.stats.FailedEvents, 1)
			eventsFailed++
			continue
		}

		// Store event
		if err := r.storage.Store(ctx, l7Event); err != nil {
			logger.Errorf("Failed to store L7 event: %v", err)
			atomic.AddInt64(&r.stats.FailedEvents, 1)
			eventsFailed++
			continue
		}

		eventsProcessed++
	}

	atomic.AddInt64(&r.stats.TotalEvents, int64(eventsProcessed))
	atomic.AddInt64(&r.stats.FailedEvents, int64(eventsFailed))
	atomic.StoreInt64(&r.stats.AveragePayloadSize, int64(len(body)))

	// Respond with success
	resp := WebhookIngestionResponse{
		Success:          eventsFailed == 0,
		EventsProcessed:  eventsProcessed,
		EventsFailed:     eventsFailed,
		TotalEvents:      len(payload.Events),
		Message:          fmt.Sprintf("Processed %d/%d events from batch %s", eventsProcessed, len(payload.Events), payload.BatchID),
		Timestamp:        time.Now().Format(time.RFC3339),
		SchemaVersion:    payload.SchemaVersion,
	}

	w.Header().Set("Content-Type", "application/json")
	if eventsFailed > 0 {
		w.WriteHeader(http.StatusPartialContent) // 206 indicates partial success
	} else {
		w.WriteHeader(http.StatusOK)
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		logger.Errorf("Failed to encode response: %v", err)
	}
}

// HandleWebhookStats returns statistics about received webhooks.
// ANCHOR: Stats Endpoint - Webhook Metrics - Jan 31, 2026
// WHY: Monitor webhook receiver health and throughput
// WHAT: HTTP handler returning ingestion statistics
// HOW: Return aggregated counts and averages
//
// @Summary		Get webhook receiver statistics
// @Description	Returns ingestion statistics for L7 webhooks
// @Tags			l7
// @Accept			json
// @Produce		json
// @Success		200	{object}	WebhookStatsResponse
// @Router			/api/l7/webhook/stats [get]
func (r *Receiver) HandleWebhookStats(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := WebhookStatsResponse{
		TotalPayloads:      atomic.LoadInt64(&r.stats.TotalPayloads),
		TotalEvents:        atomic.LoadInt64(&r.stats.TotalEvents),
		FailedPayloads:     atomic.LoadInt64(&r.stats.FailedPayloads),
		FailedEvents:       atomic.LoadInt64(&r.stats.FailedEvents),
		DuplicateEvents:    atomic.LoadInt64(&r.stats.DuplicateEvents),
		AveragePayloadSize: atomic.LoadInt64(&r.stats.AveragePayloadSize),
		TrackedBatches:     int64(len(r.seenBatch)),
		QueryTime:          time.Now().Format(time.RFC3339),
	}

	// Calculate success rates
	if stats.TotalPayloads > 0 {
		stats.PayloadSuccessRate = float64(stats.TotalPayloads-stats.FailedPayloads) / float64(stats.TotalPayloads) * 100
	}
	if stats.TotalEvents > 0 {
		stats.EventSuccessRate = float64(stats.TotalEvents-stats.FailedEvents) / float64(stats.TotalEvents) * 100
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(stats); err != nil {
		logger.Errorf("Failed to encode stats response: %v", err)
	}
}

// respondError writes an error response in JSON format.
func (r *Receiver) respondError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	resp := ErrorResponse{
		Error:     http.StatusText(statusCode),
		Message:   message,
		Timestamp: time.Now().Format(time.RFC3339),
	}
	json.NewEncoder(w).Encode(resp)
}

// cleanupOldBatches removes batch entries older than 1 hour.
func (r *Receiver) cleanupOldBatches() {
	logger.Debugf("Cleaning up old batch entries (current: %d)", len(r.seenBatch))

	now := time.Now()
	maxAge := time.Hour

	for batchID, lastSeen := range r.seenBatch {
		if now.Sub(lastSeen) > maxAge {
			delete(r.seenBatch, batchID)
		}
	}

	logger.Debugf("Batch cleanup complete (remaining: %d)", len(r.seenBatch))
}

// Response types

// WebhookIngestionResponse represents the response to a webhook ingestion request.
type WebhookIngestionResponse struct {
	Success         bool   `json:"success" example:"true"`                                 // Success status
	EventsProcessed int    `json:"events_processed" example:"42"`                          // Events successfully processed
	EventsFailed    int    `json:"events_failed" example:"0"`                              // Events that failed
	TotalEvents     int    `json:"total_events" example:"42"`                              // Total events in payload
	Message         string `json:"message" example:"Processed 42/42 events from batch"`   // Status message
	Timestamp       string `json:"timestamp" example:"2026-01-31T17:30:00Z"`              // Response timestamp
	SchemaVersion   string `json:"schema_version" example:"1.1"`                          // Schema version received
}

// WebhookStatsResponse represents webhook receiver statistics.
type WebhookStatsResponse struct {
	TotalPayloads       int64   `json:"total_payloads" example:"1500"`        // Total payloads received
	TotalEvents         int64   `json:"total_events" example:"45000"`         // Total events processed
	FailedPayloads      int64   `json:"failed_payloads" example:"5"`          // Failed payloads
	FailedEvents        int64   `json:"failed_events" example:"150"`          // Failed events
	DuplicateEvents     int64   `json:"duplicate_events" example:"0"`         // Duplicate events filtered
	PayloadSuccessRate  float64 `json:"payload_success_rate" example:"99.67"` // Success rate (%)
	EventSuccessRate    float64 `json:"event_success_rate" example:"99.67"`   // Success rate (%)
	AveragePayloadSize  int64   `json:"average_payload_size" example:"28000"` // Average payload size (bytes)
	TrackedBatches      int64   `json:"tracked_batches" example:"500"`        // Batches in dedup cache
	QueryTime           string  `json:"query_time" example:"2026-01-31T17:30:00Z"` // Query timestamp
}

// ErrorResponse represents an error response.
type ErrorResponse struct {
	Error     string `json:"error" example:"Bad Request"`               // HTTP error name
	Message   string `json:"message" example:"Invalid JSON format"`     // Error message
	Timestamp string `json:"timestamp" example:"2026-01-31T17:30:00Z"` // Error timestamp
}
