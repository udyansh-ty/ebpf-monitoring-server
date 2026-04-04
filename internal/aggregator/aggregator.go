// Package aggregator provides event aggregation functionality for eBPF monitoring.
//
//	@title			eBPF Event Aggregator API
//	@description	HTTP API for aggregating and querying eBPF events from multiple agents
//	@version		1.0.0
//	@host			localhost:8081
//	@BasePath		/
//	@contact.name	API Support
//	@contact.url	https://github.com/srodi/ebpf-server/issues
//	@contact.email	support@example.com
//	@license.name	MIT
//	@license.url	https://github.com/srodi/ebpf-server/blob/main/LICENSE
package aggregator

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/srodi/ebpf-server/internal/core"
	"github.com/srodi/ebpf-server/internal/events"
	"github.com/srodi/ebpf-server/internal/storage"
	"github.com/srodi/ebpf-server/pkg/logger"
)

// Response types for aggregator API endpoints

// AggregatedEventsResponse represents the response for querying aggregated events
type AggregatedEventsResponse struct {
	Events     []core.Event           `json:"events"`                                    // List of aggregated events
	Count      int                    `json:"count" example:"50"`                        // Number of events returned
	TotalCount int                    `json:"total_count" example:"1250"`                // Total number of matching events
	QueryTime  string                 `json:"query_time" example:"2023-01-01T12:00:00Z"` // Query timestamp
	Filters    AggregatedEventFilters `json:"filters"`                                   // Applied filters
}

// AggregatedEventFilters represents the filters applied to aggregated event queries
type AggregatedEventFilters struct {
	Type  string `json:"type,omitempty" example:"connection"`            // Event type filter
	Node  string `json:"node,omitempty" example:"worker-1"`              // Node name filter
	Since string `json:"since,omitempty" example:"2023-01-01T12:00:00Z"` // Start time filter
	Until string `json:"until,omitempty" example:"2023-01-01T13:00:00Z"` // End time filter
	Limit int    `json:"limit,omitempty" example:"100"`                  // Limit filter
}

// IngestResponse represents the response for event ingestion
type IngestResponse struct {
	EventsProcessed int    `json:"events_processed" example:"25"`                  // Number of events processed
	Success         bool   `json:"success" example:"true"`                         // Ingestion success status
	Message         string `json:"message" example:"Events ingested successfully"` // Status message
	Timestamp       string `json:"timestamp" example:"2023-01-01T12:00:00Z"`       // Processing timestamp
}

// AggregationStatsResponse represents the response for aggregation statistics
type AggregationStatsResponse struct {
	TotalEvents      int64            `json:"total_events" example:"12500"`                     // Total events stored
	EventsByType     map[string]int64 `json:"events_by_type"`                                   // Events grouped by type
	EventsByNode     map[string]int64 `json:"events_by_node"`                                   // Events grouped by node
	ConnectedAgents  int              `json:"connected_agents" example:"5"`                     // Number of connected agents
	LastEventTime    string           `json:"last_event_time" example:"2023-01-01T12:00:00Z"`   // Timestamp of last event
	AggregationStart string           `json:"aggregation_start" example:"2023-01-01T10:00:00Z"` // When aggregation started
	QueryTime        string           `json:"query_time" example:"2023-01-01T12:00:00Z"`        // Query timestamp
}

// AggregatorProgramsResponse represents the response for aggregator programs information
type AggregatorProgramsResponse struct {
	ConnectedAgents []AgentInfo   `json:"connected_agents"`                          // List of connected agents
	AllPrograms     []ProgramInfo `json:"all_programs"`                              // All programs across agents
	TotalAgents     int           `json:"total_agents" example:"3"`                  // Total number of agents
	TotalPrograms   int           `json:"total_programs" example:"6"`                // Total number of programs
	QueryTime       string        `json:"query_time" example:"2023-01-01T12:00:00Z"` // Query timestamp
}

// AgentInfo represents information about a connected agent
type AgentInfo struct {
	NodeName   string        `json:"node_name" example:"worker-1"`             // Node name
	LastSeen   string        `json:"last_seen" example:"2023-01-01T12:00:00Z"` // Last seen timestamp
	EventCount int64         `json:"event_count" example:"2500"`               // Number of events from this agent
	Programs   []ProgramInfo `json:"programs"`                                 // Programs running on this agent
	Status     string        `json:"status" example:"active"`                  // Agent status
}

// ProgramInfo represents information about an eBPF program
type ProgramInfo struct {
	Name       string `json:"name" example:"connection_tracer"` // Program name
	Type       string `json:"type" example:"kprobe"`            // Program type
	Status     string `json:"status" example:"active"`          // Program status
	Node       string `json:"node" example:"worker-1"`          // Node where program is running
	EventCount int64  `json:"event_count" example:"1250"`       // Events generated by this program
}

// AggregatedListResponse represents the response for listing aggregated connection/packet drop events
type AggregatedListResponse struct {
	TotalPIDs    int                     `json:"total_pids" example:"8"`                    // Number of unique PIDs across all nodes
	TotalEvents  int                     `json:"total_events" example:"45"`                 // Total number of events
	TotalNodes   int                     `json:"total_nodes" example:"3"`                   // Number of nodes with events
	EventsByPID  map[uint32][]core.Event `json:"events_by_pid"`                             // Events grouped by PID
	EventsByNode map[string]int          `json:"events_by_node"`                            // Event count by node
	QueryTime    string                  `json:"query_time" example:"2023-01-01T12:00:00Z"` // Query timestamp
}

// AggregatedSummaryResponse represents the response for aggregated connection/packet drop summaries
type AggregatedSummaryResponse struct {
	Count           int            `json:"count" example:"15"`                        // Total count across all nodes
	CountByNode     map[string]int `json:"count_by_node"`                             // Count by node
	PID             uint32         `json:"pid,omitempty" example:"1234"`              // Process ID (if filtered)
	Command         string         `json:"command,omitempty" example:"curl"`          // Command name (if filtered)
	DurationSeconds int            `json:"duration_seconds" example:"60"`             // Duration in seconds
	TotalNodes      int            `json:"total_nodes" example:"3"`                   // Number of nodes with events
	QueryTime       string         `json:"query_time" example:"2023-01-01T12:00:00Z"` // Query timestamp
}

// Config represents aggregator configuration.
type Config struct {
	HTTPAddr string
	// ANCHOR: Aggregator Storage Injection - Bug: pgStorage unused - Feb 25, 2026
	// Allow callers to supply a storage backend instead of always using memory.
	Storage            core.EventSink
	Enricher           *events.EventEnricher // Optional enricher for Phase 1B multi-NIC support
	MetaFlushInterval  time.Duration         // Periodic metadata rollup flush interval
	MetaSessionTimeout time.Duration         // Session timeout for metadata rollup keying
}

// ProgramCache caches program information to avoid expensive queries
type ProgramCache struct {
	data      *AggregatorProgramsResponse
	lastCheck time.Time
	mu        sync.RWMutex
}

// Aggregator collects and aggregates events from multiple eBPF agents.
type Aggregator struct {
	config             *Config
	storage            core.EventSink
	stats              *Stats
	programCache       *ProgramCache
	enricher           *events.EventEnricher // Optional enricher for Phase 1B multi-NIC support
	metaFlushInt       time.Duration
	metaSessionTimeout time.Duration
	metaRollups        map[metaRollupKey]*metaRollupAggregate
	metaSessions       map[metaSessionKey]*metaSessionState
	metaMu             sync.RWMutex
	mu                 sync.RWMutex
	running            bool
}

type metaRollupKey struct {
	SrcIP     string
	DstIP     string
	SrcPort   int64
	DstPort   int64
	Interface string
	Protocol  string
}

type metaRollupAggregate struct {
	BucketEpoch     int64
	SNI             string
	PID             int64
	UID             int64
	GID             int64
	ConnectionState string
	Action          string
	L7Protocol      string
	Command         string
	Namespace       string
	ActiveSeconds   int64
	PacketsIn       int64
	PacketsOut      int64
	BytesIn         int64
	BytesOut        int64
	Retransmissions int64
	Drops           int64
	SessionCount    int64
	FirstSeenEpoch  int64
	LastSeenEpoch   int64
}

type metaSessionKey struct {
	SrcIP     string
	DstIP     string
	SrcPort   int64
	DstPort   int64
	Interface string
	Protocol  string
}

type metaSessionState struct {
	FirstSeenEpoch        int64
	LastSeenEpoch         int64
	ReportedActiveSeconds int64
	LastUpdatedEpoch      int64
}

const defaultMetaFlushInterval = 30 * time.Second
const defaultMetaSessionTimeout = 2 * time.Minute

type metaWindowBatchWriter interface {
	UpsertMetaWindowRows(ctx context.Context, rows []storage.EBPFMetaWindowRow) error
}

// Stats represents aggregation statistics.
type Stats struct {
	TotalEvents   int64            `json:"total_events"`
	EventsByType  map[string]int64 `json:"events_by_type"`
	EventsByNode  map[string]int64 `json:"events_by_node"`
	LastEventTime time.Time        `json:"last_event_time"`
	StartTime     time.Time        `json:"start_time"`
	mu            sync.RWMutex
}

// New creates a new aggregator instance.
func New(config *Config) (*Aggregator, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	// ANCHOR: Aggregator Storage Injection - Bug: pgStorage unused - Feb 25, 2026
	// Use configured storage when provided, default to in-memory storage otherwise.
	eventStorage := config.Storage
	if eventStorage == nil {
		eventStorage = storage.NewMemoryStorage()
	}
	metaFlushInt := config.MetaFlushInterval
	if metaFlushInt <= 0 {
		metaFlushInt = defaultMetaFlushInterval
	}
	metaSessionTimeout := config.MetaSessionTimeout
	if metaSessionTimeout <= 0 {
		metaSessionTimeout = defaultMetaSessionTimeout
	}

	return &Aggregator{
		config:  config,
		storage: eventStorage,
		stats: &Stats{
			EventsByType: make(map[string]int64),
			EventsByNode: make(map[string]int64),
			StartTime:    time.Now(),
		},
		programCache:       &ProgramCache{},
		enricher:           config.Enricher, // Use enricher from config (optional)
		metaFlushInt:       metaFlushInt,
		metaSessionTimeout: metaSessionTimeout,
		metaRollups:        make(map[metaRollupKey]*metaRollupAggregate),
		metaSessions:       make(map[metaSessionKey]*metaSessionState),
	}, nil
}

// Start starts the aggregator services.
func (a *Aggregator) Start(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.running {
		return fmt.Errorf("aggregator already running")
	}

	logger.Info("Starting event aggregator")
	a.running = true

	// Start cleanup routine for memory storage
	go a.cleanupRoutine(ctx)

	return nil
}

// Stop stops the aggregator services.
func (a *Aggregator) Stop() {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.running {
		return
	}

	logger.Info("Stopping event aggregator")
	a.running = false
}

// IsRunning returns true if the aggregator is running.
func (a *Aggregator) IsRunning() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.running
}

// GetStorage returns the aggregator's event storage interface.
// ANCHOR: Storage Access - L7 Webhook Integration - Jan 31, 2026
// WHY: Allow L7 receiver to store webhook events in aggregator storage
// WHAT: Export internal storage interface for external packages
// HOW: Return core.EventSink interface with proper synchronization
func (a *Aggregator) GetStorage() core.EventSink {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.storage
}

// HandleEvents handles HTTP requests for querying aggregated events.
//
//	@Summary		Query aggregated events
//	@Description	Retrieve aggregated events with optional filtering by type, node, and time range
//	@Tags			events
//	@Accept			json
//	@Produce		json
//	@Param			type		query		string	false	"Event type filter"
//	@Param			node		query		string	false	"Node name filter"
//	@Param			since		query		string	false	"Start time (RFC3339 format)"
//	@Param			until		query		string	false	"End time (RFC3339 format)"
//	@Param			limit		query		int		false	"Maximum number of events to return"
//	@Success		200			{object}	AggregatedEventsResponse	"Events and count"
//	@Failure		405			{string}	string					"Method not allowed"
//	@Failure		500			{string}	string					"Internal server error"
//	@Router			/api/events [get]
func (a *Aggregator) HandleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse query parameters
	query := parseEventQuery(r)

	// Query storage
	events, err := a.storage.Query(r.Context(), query)
	if err != nil {
		logger.Errorf("Failed to query events: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Return events as JSON
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"events": events,
		"count":  len(events),
	}); err != nil {
		logger.Errorf("Failed to encode events: %v", err)
	}
}

// HandleIngest handles HTTP requests for ingesting events from agents.
//
//	@Summary		Ingest events from agents
//	@Description	Accept events from eBPF agents for aggregation and storage
//	@Tags			events
//	@Accept			json
//	@Produce		json
//	@Param			events	body		object	true	"Events to ingest"
//	@Success		200		{object}	IngestResponse	"Ingestion result"
//	@Failure		400		{string}	string					"Bad request"
//	@Failure		405		{string}	string					"Method not allowed"
//	@Failure		500		{string}	string					"Internal server error"
//	@Router			/api/events/ingest [post]
func (a *Aggregator) HandleIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var requestData struct {
		Events []json.RawMessage `json:"events"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		logger.Errorf("Failed to decode ingest request: %v", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Process each event
	requestSourceIP := extractRequestSourceIP(r)
	processed := 0
	for _, eventData := range requestData.Events {
		if err := a.ingestEvent(r.Context(), eventData, requestSourceIP); err != nil {
			logger.Errorf("Failed to ingest event: %v", err)
			continue
		}
		processed++
	}

	// Update stats
	a.updateStats(int64(processed), requestData.Events)

	// Invalidate program cache if we processed events successfully
	// This ensures the cache reflects newly ingested data
	if processed > 0 {
		a.invalidateProgramCache()
	}

	// Return success response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "success",
		"processed": processed,
		"total":     len(requestData.Events),
	}); err != nil {
		logger.Errorf("Failed to encode ingest response: %v", err)
	}
}

// HandleStats handles HTTP requests for aggregation statistics.
//
//	@Summary		Get aggregation statistics
//	@Description	Retrieve statistics about event aggregation including counts by type and node
//	@Tags			stats
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	AggregationStatsResponse	"Aggregation statistics"
//	@Failure		405	{string}	string					"Method not allowed"
//	@Router			/api/stats [get]
func (a *Aggregator) HandleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	a.stats.mu.RLock()
	statsData := map[string]interface{}{
		"total_events":    a.stats.TotalEvents,
		"events_by_type":  a.stats.EventsByType,
		"events_by_node":  a.stats.EventsByNode,
		"last_event_time": a.stats.LastEventTime,
		"start_time":      a.stats.StartTime,
	}
	a.stats.mu.RUnlock()

	// Add current storage info for debugging
	if memStorage, ok := a.storage.(*storage.MemoryStorage); ok {
		// Get a rough count of current events (last hour)
		query := core.Query{
			Since: time.Now().Add(-1 * time.Hour),
		}
		currentEvents, _ := memStorage.Count(context.Background(), query)
		statsData["current_events_last_hour"] = currentEvents

		// Get total events in storage
		allEvents, _ := memStorage.Count(context.Background(), core.Query{})
		statsData["total_events_in_storage"] = allEvents
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(statsData); err != nil {
		logger.Errorf("Failed to encode stats: %v", err)
	}
}

// HandlePrograms handles HTTP requests for program information.
// Since the aggregator doesn't run eBPF programs directly, it returns program status from connected agents.
// This endpoint uses caching to avoid expensive queries on each request.
//
//	@Summary		Get program information
//	@Description	Get information about eBPF programs running on connected agents
//	@Tags			programs
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	AggregatorProgramsResponse	"Program information"
//	@Failure		405	{string}	string					"Method not allowed"
//	@Router			/api/programs [get]
func (a *Aggregator) HandlePrograms(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	const cacheDuration = 2 * time.Minute // Cache for 2 minutes

	// Check if we have cached data that's still fresh
	a.programCache.mu.RLock()
	if a.programCache.data != nil && time.Since(a.programCache.lastCheck) < cacheDuration {
		response := a.programCache.data
		a.programCache.mu.RUnlock()

		logger.Debugf("Serving cached program information (age: %v)", time.Since(a.programCache.lastCheck))
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", int(cacheDuration.Seconds())))
		if err := json.NewEncoder(w).Encode(response); err != nil {
			logger.Errorf("Failed to encode cached programs response: %v", err)
		}
		return
	}
	a.programCache.mu.RUnlock()

	// Cache is stale or empty, refresh it
	response, err := a.refreshProgramCache()
	if err != nil {
		logger.Errorf("Failed to refresh program cache: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	logger.Debugf("Serving fresh program information (%d agents, %d programs)",
		response.TotalAgents, response.TotalPrograms)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", int(cacheDuration.Seconds())))
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logger.Errorf("Failed to encode programs response: %v", err)
	}
}

// refreshProgramCache refreshes the program information cache by querying recent events
func (a *Aggregator) refreshProgramCache() (*AggregatorProgramsResponse, error) {
	// Query recent events to infer connected agents and their programs
	query := core.Query{
		Limit: 1000,                              // Get a good sample of recent events
		Since: time.Now().Add(-10 * time.Minute), // Last 10 minutes
	}

	events, err := a.storage.Query(context.Background(), query)
	if err != nil {
		return nil, fmt.Errorf("failed to query events for program info: %v", err)
	}

	// Aggregate information about connected agents and their programs
	agents := make(map[string]map[string]interface{}) // node_name -> agent info
	eventTypes := make(map[string]bool)               // unique event types (indicate programs)

	for _, event := range events {
		metadata := event.Metadata()

		// Extract agent information
		nodeName, hasNode := metadata["k8s_node_name"].(string)
		podName, _ := metadata["k8s_pod_name"].(string)
		namespace, _ := metadata["k8s_namespace"].(string)

		if hasNode && nodeName != "" {
			if agents[nodeName] == nil {
				agents[nodeName] = map[string]interface{}{
					"node_name":   nodeName,
					"pod_name":    podName,
					"namespace":   namespace,
					"event_types": make(map[string]bool),
					"last_seen":   event.Time(),
					"event_count": 0,
				}
			}

			// Update agent info
			agent := agents[nodeName]
			eventTypesMap := agent["event_types"].(map[string]bool)
			eventTypesMap[event.Type()] = true
			agent["event_types"] = eventTypesMap
			agent["event_count"] = agent["event_count"].(int) + 1

			// Update last seen if this event is more recent
			if event.Time().After(agent["last_seen"].(time.Time)) {
				agent["last_seen"] = event.Time()
			}
		}

		// Track unique event types across all agents
		eventTypes[event.Type()] = true
	}

	// Convert agents map to slice and format programs
	var connectedAgents []AgentInfo
	var allPrograms []ProgramInfo

	for nodeName, agentInfo := range agents {
		eventTypesMap := agentInfo["event_types"].(map[string]bool)
		var programs []ProgramInfo
		eventCount := int64(agentInfo["event_count"].(int))

		for eventType := range eventTypesMap {
			program := ProgramInfo{
				Name:       eventType + "_tracer",
				Type:       eventType,
				Status:     "active", // Inferred from recent events
				Node:       nodeName,
				EventCount: eventCount,
			}
			programs = append(programs, program)
			allPrograms = append(allPrograms, program)
		}

		agentData := AgentInfo{
			NodeName:   nodeName,
			LastSeen:   agentInfo["last_seen"].(time.Time).Format(time.RFC3339),
			EventCount: eventCount,
			Programs:   programs,
			Status:     "active",
		}
		connectedAgents = append(connectedAgents, agentData)
	}

	response := &AggregatorProgramsResponse{
		ConnectedAgents: connectedAgents,
		AllPrograms:     allPrograms,
		TotalAgents:     len(connectedAgents),
		TotalPrograms:   len(allPrograms),
		QueryTime:       time.Now().Format(time.RFC3339),
	}

	// Update cache
	a.programCache.mu.Lock()
	a.programCache.data = response
	a.programCache.lastCheck = time.Now()
	a.programCache.mu.Unlock()

	return response, nil
}

// invalidateProgramCache invalidates the program information cache
func (a *Aggregator) invalidateProgramCache() {
	a.programCache.mu.Lock()
	a.programCache.data = nil
	a.programCache.lastCheck = time.Time{}
	a.programCache.mu.Unlock()
}

// cleanupRoutine runs periodic cleanup of old events to prevent memory bloat
func (a *Aggregator) cleanupRoutine(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute) // Event cleanup every 5 minutes
	flushTicker := time.NewTicker(a.metaFlushInt)
	defer ticker.Stop()
	defer flushTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			nowEpoch := time.Now().UTC().Unix()
			a.flushMetaRollups(context.Background(), nowEpoch)
			logger.Debug("Cleanup routine stopping due to context cancellation")
			return
		case <-flushTicker.C:
			if !a.IsRunning() {
				continue
			}
			nowEpoch := time.Now().UTC().Unix()
			a.flushMetaRollups(ctx, nowEpoch)
		case <-ticker.C:
			if !a.IsRunning() {
				continue
			}

			// Clean up events older than 2 hours
			maxAge := 2 * time.Hour

			if memStorage, ok := a.storage.(*storage.MemoryStorage); ok {
				logger.Debugf("Running cleanup: removing events older than %v", maxAge)
				memStorage.Cleanup(maxAge)
				logger.Debugf("Cleanup completed")
			}
		}
	}
}

func (a *Aggregator) flushMetaRollups(ctx context.Context, nowEpoch int64) {
	// ANCHOR: Log flush operations to file - March 21, 2026
	writer, ok := a.storage.(metaWindowBatchWriter)
	if !ok {
		return
	}

	rows := a.drainMetaRollups()
	if len(rows) == 0 {
		return
	}

	logger.Infof("[FLUSH] Flushing %d metadata rollup entries to postgres (epoch=%d)", len(rows), nowEpoch)

	if err := writer.UpsertMetaWindowRows(ctx, rows); err != nil {
		logger.Errorf("[FLUSH] Metadata rollup flush failed: %v", err)
		a.mergeMetaRollupRows(rows)
		return
	}

	logger.Infof("[FLUSH] Metadata rollup flush complete")
}

func (a *Aggregator) drainMetaRollups() []storage.EBPFMetaWindowRow {
	a.metaMu.Lock()
	if len(a.metaRollups) == 0 {
		a.metaMu.Unlock()
		return nil
	}

	drained := a.metaRollups
	a.metaRollups = make(map[metaRollupKey]*metaRollupAggregate, len(drained))
	a.metaMu.Unlock()

	rows := make([]storage.EBPFMetaWindowRow, 0, len(drained))
	for key, entry := range drained {
		if entry == nil {
			continue
		}
		if key.SrcIP == "" || key.DstIP == "" {
			continue
		}

		rows = append(rows, storage.EBPFMetaWindowRow{
			BucketEpoch:     entry.BucketEpoch,
			SrcIP:           key.SrcIP,
			DstIP:           key.DstIP,
			SrcPort:         key.SrcPort,
			DstPort:         key.DstPort,
			InterfaceName:   key.Interface,
			Protocol:        key.Protocol,
			SNI:             entry.SNI,
			PID:             entry.PID,
			UID:             entry.UID,
			GID:             entry.GID,
			ConnectionState: entry.ConnectionState,
			Action:          entry.Action,
			L7Protocol:      entry.L7Protocol,
			Command:         entry.Command,
			Namespace:       entry.Namespace,
			ActiveSeconds:   entry.ActiveSeconds,
			PacketsIn:       entry.PacketsIn,
			PacketsOut:      entry.PacketsOut,
			BytesIn:         entry.BytesIn,
			BytesOut:        entry.BytesOut,
			Retransmissions: entry.Retransmissions,
			Drops:           entry.Drops,
			SessionCount:    entry.SessionCount,
			FirstSeenEpoch:  entry.FirstSeenEpoch,
			LastSeenEpoch:   entry.LastSeenEpoch,
		})
	}

	return rows
}

func (a *Aggregator) mergeMetaRollupRows(rows []storage.EBPFMetaWindowRow) {
	if len(rows) == 0 {
		return
	}

	a.metaMu.Lock()
	defer a.metaMu.Unlock()

	for _, row := range rows {
		key := metaRollupKey{
			SrcIP:     row.SrcIP,
			DstIP:     row.DstIP,
			SrcPort:   row.SrcPort,
			DstPort:   row.DstPort,
			Interface: strings.TrimSpace(row.InterfaceName),
			Protocol:  normalizeProtocol(row.Protocol),
		}

		if existing, ok := a.metaRollups[key]; ok {
			if row.BucketEpoch > existing.BucketEpoch {
				existing.BucketEpoch = row.BucketEpoch
			}
			if row.SNI != "" {
				existing.SNI = row.SNI
			}
			if row.PID > 0 {
				existing.PID = row.PID
			}
			if row.UID > 0 {
				existing.UID = row.UID
			}
			if row.GID > 0 {
				existing.GID = row.GID
			}
			if row.ConnectionState != "" {
				existing.ConnectionState = row.ConnectionState
			}
			if row.Action != "" {
				existing.Action = row.Action
			}
			if row.L7Protocol != "" {
				existing.L7Protocol = row.L7Protocol
			}
			if row.Command != "" {
				existing.Command = row.Command
			}
			if row.Namespace != "" {
				existing.Namespace = row.Namespace
			}
			existing.ActiveSeconds += row.ActiveSeconds
			existing.PacketsIn += row.PacketsIn
			existing.PacketsOut += row.PacketsOut
			existing.BytesIn += row.BytesIn
			existing.BytesOut += row.BytesOut
			existing.Retransmissions += row.Retransmissions
			existing.Drops += row.Drops
			existing.SessionCount += row.SessionCount
			if existing.FirstSeenEpoch == 0 || (row.FirstSeenEpoch > 0 && row.FirstSeenEpoch < existing.FirstSeenEpoch) {
				existing.FirstSeenEpoch = row.FirstSeenEpoch
			}
			if row.LastSeenEpoch > existing.LastSeenEpoch {
				existing.LastSeenEpoch = row.LastSeenEpoch
			}
			continue
		}

		a.metaRollups[key] = &metaRollupAggregate{
			BucketEpoch:     row.BucketEpoch,
			SNI:             row.SNI,
			PID:             row.PID,
			UID:             row.UID,
			GID:             row.GID,
			ConnectionState: row.ConnectionState,
			Action:          row.Action,
			L7Protocol:      row.L7Protocol,
			Command:         row.Command,
			Namespace:       row.Namespace,
			ActiveSeconds:   row.ActiveSeconds,
			PacketsIn:       row.PacketsIn,
			PacketsOut:      row.PacketsOut,
			BytesIn:         row.BytesIn,
			BytesOut:        row.BytesOut,
			Retransmissions: row.Retransmissions,
			Drops:           row.Drops,
			SessionCount:    row.SessionCount,
			FirstSeenEpoch:  row.FirstSeenEpoch,
			LastSeenEpoch:   row.LastSeenEpoch,
		}
	}
}

// ingestEvent processes a single event from an agent.
// ANCHOR: Event enrichment pipeline integration - Issue #1 Fix - Feb 6, 2026
// WHY: Enrich connection events with interface information before storage (Phase 1B)
// WHAT: Optionally apply enricher to extract interface_name/interface_index before storage
// HOW: Check if enricher available and event is connection type, apply enrichment, then store
func (a *Aggregator) ingestEvent(ctx context.Context, eventData json.RawMessage, requestSourceIP string) error {
	// Parse event data into a generic event
	var eventMap map[string]interface{}
	if err := json.Unmarshal(eventData, &eventMap); err != nil {
		return fmt.Errorf("failed to parse event: %v", err)
	}
	if requestSourceIP != "" {
		eventMap["ingest_remote_ip"] = requestSourceIP
	}

	// Create a simple event wrapper for storage
	var event core.Event = &SimpleEvent{
		data: eventMap,
	}

	// ANCHOR: Apply enricher to connection events - Issue #1 Fix - Feb 6, 2026
	// WHY: Add interface information (interface_name, interface_index) to events before storage
	// WHAT: If enricher available, attempt to enrich event with multi-NIC information
	// HOW: Call enricher.EnrichEvent() which is non-blocking (failures don't prevent storage)
	if a.enricher != nil {
		enrichedEvent, err := a.enricher.EnrichEvent(ctx, event)
		if err != nil {
			// Non-blocking: log error but continue with storage
			logger.Debugf("Event enrichment failed (non-blocking): %v", err)
		} else {
			event = enrichedEvent
		}
	}

	// Metadata-window mode: eBPF events are aggregated in-memory and flushed to ebpf_meta_window.
	// Raw eBPF per-event storage (ebpf_events) is intentionally bypassed.
	eventType := event.Type()
	if isMetaWindowOnlyEventType(eventType) {
		metadata := event.Metadata()
		if metadata != nil {
			metadata["event_type"] = eventType
			if _, ok := metadata["type"]; !ok {
				metadata["type"] = eventType
			}
			if _, ok := metadata["command"]; !ok {
				if command := strings.TrimSpace(event.Command()); command != "" {
					metadata["command"] = command
				}
			}
			if _, ok := metadata["pid"]; !ok {
				if pid := event.PID(); pid > 0 {
					metadata["pid"] = int64(pid)
				}
			}
		}
		a.trackMetaWindowRollup(metadata)
		return nil
	}

	// Non-eBPF event types (e.g. L7 webhook data) continue to use configured storage backend.
	logger.Infof("[INGEST] L7 event type=%s stored directly", eventType)
	if err := a.storage.Store(ctx, event); err != nil {
		return err
	}

	return nil
}

func isMetaWindowOnlyEventType(eventType string) bool {
	switch eventType {
	case "connection", "packet_drop", "packet", "process", "process_exec", "file_operation":
		return true
	default:
		return false
	}
}

func (a *Aggregator) trackMetaWindowRollup(metadata map[string]interface{}) {
	if metadata == nil {
		return
	}

	metadataMaps := collectMetadataMaps(metadata)
	eventType := strings.ToLower(strings.TrimSpace(findFirstStringValue(metadataMaps, "type", "event_type")))
	if eventType == "" {
		eventType = "connection"
	}

	srcIP := extractNormalizedIP(metadataMaps,
		"src_ip", "source_ip", "machine_ip", "client_ip", "local_ip",
		"ingest_remote_ip", "agent_ip", "source_addr", "src_addr", "saddr",
	)
	dstIP := extractNormalizedIP(metadataMaps,
		"dst_ip", "dest_ip", "destination_ip", "server_ip", "remote_ip",
		"destination", "remote_addr", "dst_addr", "daddr",
	)
	if srcIP == "" {
		return
	}
	if dstIP == "" {
		return
	}
	if net.ParseIP(srcIP) == nil || net.ParseIP(dstIP) == nil {
		return
	}

	startNS, hasStart := getInt64FromMaps(metadataMaps, "session_start_ns", "start_ns", "first_seen_ns")
	endNS, hasEnd := getInt64FromMaps(metadataMaps, "session_end_ns", "end_ns", "last_seen_ns")
	if !hasStart {
		startNS, hasStart = getInt64FromMaps(metadataMaps, "first_seen_epoch")
	}
	if !hasEnd {
		endNS, hasEnd = getInt64FromMaps(metadataMaps, "last_seen_epoch")
	}
	if !hasEnd {
		endNS, hasEnd = getInt64FromMaps(metadataMaps, "timestamp", "observed_at")
	}
	if !hasStart {
		startNS, hasStart = getInt64FromMaps(metadataMaps, "timestamp", "observed_at")
	}
	if !hasStart && !hasEnd {
		// Require at least one timing field to derive first/last seen.
		return
	}

	firstSeenEpoch := epochSecondsFromAuto(startNS)
	lastSeenEpoch := epochSecondsFromAuto(endNS)
	if lastSeenEpoch == 0 {
		if ts, ok := getInt64FromMaps(metadataMaps, "timestamp", "observed_at"); ok {
			lastSeenEpoch = epochSecondsFromAuto(ts)
		}
	}
	if firstSeenEpoch == 0 {
		firstSeenEpoch = lastSeenEpoch
	}
	if firstSeenEpoch == 0 {
		firstSeenEpoch = time.Now().UTC().Unix()
	}
	if lastSeenEpoch == 0 {
		lastSeenEpoch = firstSeenEpoch
	}
	if lastSeenEpoch < firstSeenEpoch {
		firstSeenEpoch, lastSeenEpoch = lastSeenEpoch, firstSeenEpoch
	}
	activeSeconds := deriveActiveSeconds(metadataMaps, firstSeenEpoch, lastSeenEpoch)
	explicitActiveMetric := hasExplicitActiveMetric(metadataMaps)
	packetsIn, packetsOut, bytesIn, bytesOut := deriveTrafficCounters(metadataMaps, eventType)
	if activeSeconds <= 0 && eventType == "connection" {
		// Connection syscall events are point-in-time by default, so preserve a minimum
		// active duration to avoid "always-zero" aggregates.
		activeSeconds = 1
	}
	if packetsIn == 0 && packetsOut == 0 && bytesIn == 0 && bytesOut == 0 && eventType == "connection" {
		// Minimum packet heuristic for connect events when packet counters are absent.
		packetsOut = 1
		bytesOut = estimateBytesFromPackets(packetsOut)
		if returnCode, ok := getInt64FromMaps(metadataMaps, "return_code"); !ok || returnCode >= 0 {
			packetsIn = 1
			bytesIn = estimateBytesFromPackets(packetsIn)
		}
	}
	protocol := normalizeProtocol(findFirstStringValue(metadataMaps, "protocol", "l4_protocol", "transport_protocol", "transport", "proto"))
	if protocol == "" {
		if rawProto, ok := getInt64FromMaps(metadataMaps, "raw_protocol", "protocol_number", "ip_proto"); ok {
			protocol = normalizeProtocolFromNumber(rawProto)
		}
	}
	sni := extractSNI(metadataMaps)
	srcPort := normalizePort(findFirstPort(metadataMaps, "src_port", "source_port", "sport"))
	dstPort := normalizePort(findFirstPort(metadataMaps, "dst_port", "dest_port", "destination_port", "dport", "port"))
	pid, _ := getInt64FromMaps(metadataMaps, "pid", "process_id", "tgid")
	pid = normalizePID(pid)
	uid := normalizeUIDGID(firstPositiveInt64FromMaps(metadataMaps, "uid", "user_id", "euid"))
	gid := normalizeUIDGID(firstPositiveInt64FromMaps(metadataMaps, "gid", "group_id", "egid"))
	connectionState := normalizeLabel(findFirstStringValue(metadataMaps, "connection_state", "conn_state", "state", "tcp_state"))
	action := normalizeLabel(findFirstStringValue(metadataMaps, "action", "verdict_action", "firewall_action", "decision_action"))
	l7Protocol := normalizeLabel(findFirstStringValue(metadataMaps, "l7_protocol", "application_protocol", "ndpi_protocol"))
	command := strings.TrimSpace(findFirstStringValue(metadataMaps, "command", "process_name", "comm"))
	namespace := strings.TrimSpace(findFirstStringValue(metadataMaps, "namespace", "k8s_namespace", "pod_namespace"))
	retransmissions := firstPositiveInt64FromMaps(metadataMaps, "retransmissions", "tcp_retransmissions", "retransmit_count")
	drops := firstPositiveInt64FromMaps(metadataMaps, "drops", "drop_count", "packet_drops")
	if eventType == "packet_drop" && drops == 0 {
		drops = 1
	}
	if connectionState == "" {
		if eventType == "packet_drop" {
			connectionState = "dropped"
		} else if returnCode, ok := getInt64FromMaps(metadataMaps, "return_code"); ok {
			if returnCode < 0 {
				connectionState = "failed"
			} else {
				connectionState = "connected"
			}
		}
	}
	if action == "" {
		switch eventType {
		case "packet_drop":
			action = "drop"
		case "connection":
			if returnCode, ok := getInt64FromMaps(metadataMaps, "return_code"); ok && returnCode < 0 {
				action = "deny"
			} else {
				action = "allow"
			}
		}
	}
	if l7Protocol == "" {
		l7Protocol = inferL7Protocol(dstPort, protocol, sni)
	}
	if pid > 0 && (uid == 0 || gid == 0 || command == "" || namespace == "") {
		procUID, procGID, procCommand, procNamespace := readProcessContext(pid)
		if uid == 0 && procUID > 0 {
			uid = procUID
		}
		if gid == 0 && procGID > 0 {
			gid = procGID
		}
		if command == "" && procCommand != "" {
			command = procCommand
		}
		if namespace == "" && procNamespace != "" {
			namespace = procNamespace
		}
	}
	if namespace == "" {
		namespace = "host"
	}
	if srcPort == 0 {
		srcPort = normalizePort(extractPortFromEndpoint(findFirstStringValue(metadataMaps, "src_ip", "source_ip", "source_addr", "src_addr")))
	}
	if dstPort == 0 {
		dstPort = normalizePort(extractPortFromEndpoint(findFirstStringValue(metadataMaps, "destination", "dst_ip", "dest_ip", "destination_ip", "remote_addr", "dst_addr")))
	}
	iface := strings.TrimSpace(findFirstStringValue(metadataMaps, "interface_name", "interface", "iface"))
	sessionKey := metaSessionKey{
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Interface: iface,
		Protocol:  protocol,
	}

	a.metaMu.Lock()
	defer a.metaMu.Unlock()

	a.pruneMetaSessionsLocked(lastSeenEpoch)

	bucketEpoch := lastSeenEpoch - (lastSeenEpoch % 60)
	if bucketEpoch < 0 {
		bucketEpoch = 0
	}

	sessionCountIncrement := int64(1)
	activeSecondsIncrement := activeSeconds

	sessionTimeoutSeconds := int64(a.metaSessionTimeout / time.Second)
	if sessionTimeoutSeconds <= 0 {
		sessionTimeoutSeconds = int64(defaultMetaSessionTimeout / time.Second)
	}

	if session, ok := a.metaSessions[sessionKey]; ok && session != nil {
		gap := lastSeenEpoch - session.LastSeenEpoch
		if gap < 0 {
			gap = 0
		}
		if gap <= sessionTimeoutSeconds {
			// Existing live session: keep session_count stable.
			sessionCountIncrement = 0

			if firstSeenEpoch < session.FirstSeenEpoch {
				session.FirstSeenEpoch = firstSeenEpoch
			}
			if lastSeenEpoch > session.LastSeenEpoch {
				session.LastSeenEpoch = lastSeenEpoch
			}
			if explicitActiveMetric {
				activeSecondsIncrement = activeSeconds
				session.ReportedActiveSeconds += activeSeconds
			} else {
				targetActive := maxInt64(activeSeconds, session.LastSeenEpoch-session.FirstSeenEpoch)
				if targetActive > session.ReportedActiveSeconds {
					activeSecondsIncrement = targetActive - session.ReportedActiveSeconds
					session.ReportedActiveSeconds = targetActive
				} else {
					activeSecondsIncrement = 0
				}
			}
			session.LastUpdatedEpoch = maxInt64(session.LastUpdatedEpoch, lastSeenEpoch)
		} else {
			a.metaSessions[sessionKey] = &metaSessionState{
				FirstSeenEpoch:        firstSeenEpoch,
				LastSeenEpoch:         lastSeenEpoch,
				ReportedActiveSeconds: activeSeconds,
				LastUpdatedEpoch:      lastSeenEpoch,
			}
		}
	} else {
		a.metaSessions[sessionKey] = &metaSessionState{
			FirstSeenEpoch:        firstSeenEpoch,
			LastSeenEpoch:         lastSeenEpoch,
			ReportedActiveSeconds: activeSeconds,
			LastUpdatedEpoch:      lastSeenEpoch,
		}
	}

	key := metaRollupKey{
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Interface: iface,
		Protocol:  protocol,
	}

	if entry, ok := a.metaRollups[key]; ok {
		if bucketEpoch > entry.BucketEpoch {
			entry.BucketEpoch = bucketEpoch
		}
		if sni != "" {
			entry.SNI = sni
		}
		if pid > 0 {
			entry.PID = pid
		}
		if uid > 0 {
			entry.UID = uid
		}
		if gid > 0 {
			entry.GID = gid
		}
		if connectionState != "" {
			entry.ConnectionState = connectionState
		}
		if action != "" {
			entry.Action = action
		}
		if l7Protocol != "" {
			entry.L7Protocol = l7Protocol
		}
		if command != "" {
			entry.Command = command
		}
		if namespace != "" {
			entry.Namespace = namespace
		}
		entry.ActiveSeconds += activeSecondsIncrement
		entry.PacketsIn += packetsIn
		entry.PacketsOut += packetsOut
		entry.BytesIn += bytesIn
		entry.BytesOut += bytesOut
		entry.Retransmissions += retransmissions
		entry.Drops += drops
		entry.SessionCount += sessionCountIncrement
		if firstSeenEpoch < entry.FirstSeenEpoch {
			entry.FirstSeenEpoch = firstSeenEpoch
		}
		if lastSeenEpoch > entry.LastSeenEpoch {
			entry.LastSeenEpoch = lastSeenEpoch
		}
		return
	}

	a.metaRollups[key] = &metaRollupAggregate{
		BucketEpoch:     bucketEpoch,
		SNI:             sni,
		PID:             pid,
		UID:             uid,
		GID:             gid,
		ConnectionState: connectionState,
		Action:          action,
		L7Protocol:      l7Protocol,
		Command:         command,
		Namespace:       namespace,
		ActiveSeconds:   activeSecondsIncrement,
		PacketsIn:       packetsIn,
		PacketsOut:      packetsOut,
		BytesIn:         bytesIn,
		BytesOut:        bytesOut,
		Retransmissions: retransmissions,
		Drops:           drops,
		SessionCount:    sessionCountIncrement,
		FirstSeenEpoch:  firstSeenEpoch,
		LastSeenEpoch:   lastSeenEpoch,
	}
}

func (a *Aggregator) pruneMetaSessionsLocked(nowEpoch int64) {
	if len(a.metaSessions) == 0 || nowEpoch <= 0 {
		return
	}
	ttlSeconds := int64((a.metaSessionTimeout * 3) / time.Second)
	if ttlSeconds <= 0 {
		ttlSeconds = int64((defaultMetaSessionTimeout * 3) / time.Second)
	}
	cutoff := nowEpoch - ttlSeconds
	for key, session := range a.metaSessions {
		if session == nil {
			delete(a.metaSessions, key)
			continue
		}
		lastUpdated := session.LastUpdatedEpoch
		if lastUpdated == 0 {
			lastUpdated = session.LastSeenEpoch
		}
		if lastUpdated > 0 && lastUpdated < cutoff {
			delete(a.metaSessions, key)
		}
	}
}

func deriveActiveSeconds(metadataMaps []map[string]interface{}, firstSeenEpoch, lastSeenEpoch int64) int64 {
	if activeSeconds, ok := getInt64FromMaps(metadataMaps, "active_seconds"); ok && activeSeconds > 0 {
		return activeSeconds
	}
	if durationMS, ok := getFloat64FromMaps(metadataMaps, "duration_ms"); ok && durationMS > 0 {
		seconds := int64(math.Ceil(durationMS / 1000.0))
		if seconds < 1 {
			return 1
		}
		return seconds
	}
	if durationSeconds, ok := getFloat64FromMaps(metadataMaps, "duration_seconds", "duration_sec"); ok && durationSeconds > 0 {
		seconds := int64(math.Ceil(durationSeconds))
		if seconds < 1 {
			return 1
		}
		return seconds
	}
	if lastSeenEpoch > firstSeenEpoch {
		return lastSeenEpoch - firstSeenEpoch
	}
	return 0
}

func hasExplicitActiveMetric(metadataMaps []map[string]interface{}) bool {
	if value, ok := getFloat64FromMaps(metadataMaps, "active_seconds"); ok && value > 0 {
		return true
	}
	if value, ok := getFloat64FromMaps(metadataMaps, "duration_ms", "duration_seconds", "duration_sec"); ok && value > 0 {
		return true
	}
	return false
}

func deriveTrafficCounters(metadataMaps []map[string]interface{}, eventType string) (int64, int64, int64, int64) {
	packetsIn := firstPositiveInt64FromMaps(metadataMaps,
		"packets_in", "packets_incoming", "incoming_packets", "in_packets", "rx_packets",
	)
	packetsOut := firstPositiveInt64FromMaps(metadataMaps,
		"packets_out", "packets_outgoing", "outgoing_packets", "out_packets", "tx_packets",
	)
	bytesIn := firstPositiveInt64FromMaps(metadataMaps,
		"bytes_received", "rx_bytes", "bytes_in", "incoming_bytes", "rx_queue_bytes",
	)
	bytesOut := firstPositiveInt64FromMaps(metadataMaps,
		"bytes_sent", "tx_bytes", "bytes_out", "outgoing_bytes", "tx_queue_bytes",
	)
	packetSizeBytes := firstPositiveInt64FromMaps(metadataMaps,
		"packet_size_bytes", "skb_length", "packet_length", "packet_bytes",
	)
	if eventType == "packet_drop" && packetSizeBytes > 0 && bytesOut == 0 {
		bytesOut = packetSizeBytes
	}
	if packetsIn == 0 && bytesIn > 0 {
		packetsIn = estimatePacketsFromBytes(bytesIn)
	}
	if packetsOut == 0 && bytesOut > 0 {
		packetsOut = estimatePacketsFromBytes(bytesOut)
	}
	if bytesIn == 0 && packetsIn > 0 {
		bytesIn = estimateBytesFromPackets(packetsIn)
	}
	if bytesOut == 0 && packetsOut > 0 {
		bytesOut = estimateBytesFromPackets(packetsOut)
	}
	if eventType == "packet_drop" && packetsIn == 0 && packetsOut == 0 {
		packetsOut = 1
		if bytesOut == 0 && packetSizeBytes > 0 {
			bytesOut = packetSizeBytes
		}
	}
	return packetsIn, packetsOut, bytesIn, bytesOut
}

func firstPositiveInt64FromMaps(metadataMaps []map[string]interface{}, keys ...string) int64 {
	if value, ok := getInt64FromMaps(metadataMaps, keys...); ok && value > 0 {
		return value
	}
	if value, ok := getFloat64FromMaps(metadataMaps, keys...); ok && value > 0 {
		return int64(math.Round(value))
	}
	return 0
}

func estimatePacketsFromBytes(bytes int64) int64 {
	if bytes <= 0 {
		return 0
	}
	packets := int64(math.Ceil(float64(bytes) / 1500.0))
	if packets < 1 {
		return 1
	}
	return packets
}

func estimateBytesFromPackets(packets int64) int64 {
	if packets <= 0 {
		return 0
	}
	return packets * 1500
}

func collectMetadataMaps(metadata map[string]interface{}) []map[string]interface{} {
	if metadata == nil {
		return nil
	}

	maps := []map[string]interface{}{metadata}
	for _, key := range []string{
		"metadata", "event", "data", "payload", "connection", "network",
		"tls", "ndpi", "verdict", "firewall", "policy", "security", "process",
	} {
		nestedRaw, ok := metadata[key]
		if !ok {
			continue
		}
		nestedMap, ok := nestedRaw.(map[string]interface{})
		if !ok {
			continue
		}
		maps = append(maps, nestedMap)
		if nestedMetaRaw, ok := nestedMap["metadata"]; ok {
			if nestedMeta, ok := nestedMetaRaw.(map[string]interface{}); ok {
				maps = append(maps, nestedMeta)
			}
		}
	}

	return maps
}

func findFirstStringValue(metadataMaps []map[string]interface{}, keys ...string) string {
	for _, metadata := range metadataMaps {
		if metadata == nil {
			continue
		}
		for _, key := range keys {
			if value := strings.TrimSpace(getStringValue(metadata, key)); value != "" {
				return value
			}
		}
	}
	return ""
}

func extractNormalizedIP(metadataMaps []map[string]interface{}, keys ...string) string {
	for _, metadata := range metadataMaps {
		if metadata == nil {
			continue
		}
		for _, key := range keys {
			raw := strings.TrimSpace(getStringValue(metadata, key))
			if raw == "" {
				continue
			}
			if normalized := normalizeIP(raw); normalized != "" {
				return normalized
			}
		}
	}
	return ""
}

func normalizeIP(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}

	if parsedURL, err := url.Parse(value); err == nil && parsedURL.Host != "" {
		value = parsedURL.Host
	}
	value = strings.TrimSpace(value)
	if idx := strings.IndexByte(value, '/'); idx >= 0 {
		value = value[:idx]
	}

	if ip := net.ParseIP(strings.Trim(value, "[]")); ip != nil {
		return ip.String()
	}

	if host, _, err := net.SplitHostPort(value); err == nil {
		host = strings.Trim(host, "[]")
		if ip := net.ParseIP(host); ip != nil {
			return ip.String()
		}
	}

	if strings.Count(value, ":") == 1 && strings.Contains(value, ".") {
		if host, _, err := net.SplitHostPort(value); err == nil {
			if ip := net.ParseIP(host); ip != nil {
				return ip.String()
			}
		}
	}

	return ""
}

func extractRequestSourceIP(r *http.Request) string {
	if r == nil {
		return ""
	}

	for _, candidate := range []string{
		r.Header.Get("X-Forwarded-For"),
		r.Header.Get("X-Real-Ip"),
		r.RemoteAddr,
	} {
		if candidate == "" {
			continue
		}
		parts := strings.Split(candidate, ",")
		value := strings.TrimSpace(parts[0])
		if value == "" {
			continue
		}

		host := value
		if parsed := net.ParseIP(strings.Trim(host, "[]")); parsed != nil {
			return parsed.String()
		}
		if h, _, err := net.SplitHostPort(value); err == nil {
			h = strings.Trim(h, "[]")
			if parsed := net.ParseIP(h); parsed != nil {
				return parsed.String()
			}
		}
	}

	return ""
}

func getInt64FromMaps(metadataMaps []map[string]interface{}, keys ...string) (int64, bool) {
	for _, metadata := range metadataMaps {
		if metadata == nil {
			continue
		}
		if value, ok := getInt64Value(metadata, keys...); ok {
			return value, true
		}
	}
	return 0, false
}

func getFloat64FromMaps(metadataMaps []map[string]interface{}, keys ...string) (float64, bool) {
	for _, metadata := range metadataMaps {
		if metadata == nil {
			continue
		}
		if value, ok := getFloat64Value(metadata, keys...); ok {
			return value, true
		}
	}
	return 0, false
}

func findFirstPort(metadataMaps []map[string]interface{}, keys ...string) int64 {
	if value, ok := getInt64FromMaps(metadataMaps, keys...); ok {
		return value
	}
	return 0
}

func normalizePort(port int64) int64 {
	if port < 0 || port > 65535 {
		return 0
	}
	return port
}

func normalizePID(pid int64) int64 {
	if pid < 0 {
		return 0
	}
	return pid
}

func normalizeUIDGID(value int64) int64 {
	if value < 0 {
		return 0
	}
	return value
}

func normalizeProtocolFromNumber(protocol int64) string {
	switch protocol {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 58:
		return "icmpv6"
	case 132:
		return "sctp"
	default:
		return ""
	}
}

func normalizeProtocol(raw string) string {
	value := normalizeLabel(raw)
	switch value {
	case "tcp", "udp", "icmp", "icmpv6", "sctp":
		return value
	case "unknown":
		return ""
	}

	if strings.HasPrefix(value, "unknown(") && strings.HasSuffix(value, ")") {
		num := strings.TrimSuffix(strings.TrimPrefix(value, "unknown("), ")")
		if parsed, err := strconv.ParseInt(num, 10, 64); err == nil {
			return normalizeProtocolFromNumber(parsed)
		}
	}
	if parsed, err := strconv.ParseInt(value, 10, 64); err == nil {
		return normalizeProtocolFromNumber(parsed)
	}
	return value
}

func normalizeLabel(raw string) string {
	value := strings.TrimSpace(strings.ToLower(raw))
	if value == "" {
		return ""
	}
	return value
}

func extractPortFromEndpoint(raw string) int64 {
	value := strings.TrimSpace(raw)
	if value == "" {
		return 0
	}
	if parsedURL, err := url.Parse(value); err == nil && parsedURL.Host != "" {
		value = parsedURL.Host
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return 0
	}
	_ = host
	parsed, err := strconv.ParseInt(strings.TrimSpace(port), 10, 64)
	if err != nil {
		return 0
	}
	return parsed
}

func getStringValue(metadata map[string]interface{}, key string) string {
	raw, ok := metadata[key]
	if !ok {
		return ""
	}
	switch v := raw.(type) {
	case string:
		return strings.TrimSpace(v)
	case json.Number:
		return strings.TrimSpace(v.String())
	case fmt.Stringer:
		return strings.TrimSpace(v.String())
	case []byte:
		return strings.TrimSpace(string(v))
	default:
		return ""
	}
}

func extractSNI(metadataMaps []map[string]interface{}) string {
	for _, metadata := range metadataMaps {
		if metadata == nil {
			continue
		}

		for _, key := range []string{"sni", "server_name", "tls_sni", "hostname", "host", "domain"} {
			if value := normalizeSNI(getStringValue(metadata, key)); value != "" {
				return value
			}
		}

		if tlsRaw, ok := metadata["tls"]; ok {
			if tlsMap, ok := tlsRaw.(map[string]interface{}); ok {
				for _, key := range []string{"sni", "server_name", "host"} {
					if value := normalizeSNI(getStringValue(tlsMap, key)); value != "" {
						return value
					}
				}
			}
		}

		for _, key := range []string{"url", "request_url", "host_url"} {
			if value := normalizeSNI(getStringValue(metadata, key)); value != "" {
				return value
			}
		}
	}

	return ""
}

func normalizeSNI(raw string) string {
	value := strings.TrimSpace(strings.ToLower(raw))
	if value == "" {
		return ""
	}

	if parsedURL, err := url.Parse(value); err == nil && parsedURL.Host != "" {
		value = parsedURL.Host
	}

	value = strings.TrimSpace(value)
	if idx := strings.IndexByte(value, '/'); idx >= 0 {
		value = value[:idx]
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}

	value = strings.Trim(value, "[]")
	value = strings.TrimSuffix(value, ".")
	if value == "" {
		return ""
	}

	if net.ParseIP(value) != nil {
		return ""
	}

	return value
}

func inferL7Protocol(dstPort int64, protocol, sni string) string {
	switch normalizeProtocol(protocol) {
	case "icmp":
		return "icmp"
	case "udp":
		if dstPort == 53 {
			return "dns"
		}
	case "tcp":
		switch dstPort {
		case 53:
			return "dns-tcp"
		case 80, 8080, 8081:
			return "http"
		case 443, 8443:
			if strings.TrimSpace(sni) != "" {
				return "https"
			}
			return "tls"
		case 22:
			return "ssh"
		case 5432:
			return "postgres"
		}
	}
	return ""
}

func readProcessContext(pid int64) (uid, gid int64, command, namespace string) {
	if pid <= 0 {
		return 0, 0, "", ""
	}
	base := filepath.Join("/proc", strconv.FormatInt(pid, 10))

	if statusBytes, err := os.ReadFile(filepath.Join(base, "status")); err == nil {
		for _, line := range strings.Split(string(statusBytes), "\n") {
			if strings.HasPrefix(line, "Uid:") {
				fields := strings.Fields(line)
				if len(fields) > 1 {
					if parsed, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
						uid = normalizeUIDGID(parsed)
					}
				}
			}
			if strings.HasPrefix(line, "Gid:") {
				fields := strings.Fields(line)
				if len(fields) > 1 {
					if parsed, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
						gid = normalizeUIDGID(parsed)
					}
				}
			}
		}
	}

	if commBytes, err := os.ReadFile(filepath.Join(base, "comm")); err == nil {
		command = strings.TrimSpace(string(commBytes))
	}

	if nsLink, err := os.Readlink(filepath.Join(base, "ns", "net")); err == nil {
		namespace = strings.TrimSpace(nsLink)
	}

	return uid, gid, command, namespace
}

func getInt64Value(metadata map[string]interface{}, keys ...string) (int64, bool) {
	for _, key := range keys {
		raw, ok := metadata[key]
		if !ok {
			continue
		}
		switch v := raw.(type) {
		case int:
			return int64(v), true
		case int8:
			return int64(v), true
		case int16:
			return int64(v), true
		case int32:
			return int64(v), true
		case int64:
			return v, true
		case uint:
			return int64(v), true
		case uint8:
			return int64(v), true
		case uint16:
			return int64(v), true
		case uint32:
			return int64(v), true
		case uint64:
			return int64(v), true
		case float32:
			return int64(v), true
		case float64:
			return int64(v), true
		case json.Number:
			if parsed, err := v.Int64(); err == nil {
				return parsed, true
			}
			if parsed, err := v.Float64(); err == nil {
				return int64(parsed), true
			}
		case string:
			if parsed, err := strconv.ParseInt(v, 10, 64); err == nil {
				return parsed, true
			}
			if parsed, err := strconv.ParseFloat(v, 64); err == nil {
				return int64(parsed), true
			}
		}
	}
	return 0, false
}

func getFloat64Value(metadata map[string]interface{}, keys ...string) (float64, bool) {
	for _, key := range keys {
		raw, ok := metadata[key]
		if !ok {
			continue
		}
		switch v := raw.(type) {
		case int:
			return float64(v), true
		case int8:
			return float64(v), true
		case int16:
			return float64(v), true
		case int32:
			return float64(v), true
		case int64:
			return float64(v), true
		case uint:
			return float64(v), true
		case uint8:
			return float64(v), true
		case uint16:
			return float64(v), true
		case uint32:
			return float64(v), true
		case uint64:
			return float64(v), true
		case float32:
			return float64(v), true
		case float64:
			return v, true
		case json.Number:
			if parsed, err := v.Float64(); err == nil {
				return parsed, true
			}
		case string:
			if parsed, err := strconv.ParseFloat(v, 64); err == nil {
				return parsed, true
			}
		}
	}
	return 0, false
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func epochSecondsFromAuto(v int64) int64 {
	if v <= 0 {
		return 0
	}
	nowEpoch := time.Now().UTC().Unix()
	const minUnixEpoch = 946684800                     // 2000-01-01
	const maxUnixEpoch = 4102444800                    // 2100-01-01
	const maxAcceptableSkew = int64(30 * 24 * 60 * 60) // 30 days

	candidates := []int64{
		v,                 // seconds
		v / 1_000,         // milliseconds
		v / 1_000_000,     // microseconds
		v / 1_000_000_000, // nanoseconds
	}

	best := int64(0)
	bestDiff := int64(^uint64(0) >> 1) // max int64
	for _, candidate := range candidates {
		if candidate < minUnixEpoch || candidate > maxUnixEpoch {
			continue
		}
		diff := absInt64(candidate - nowEpoch)
		if diff < bestDiff {
			bestDiff = diff
			best = candidate
		}
	}

	if best > 0 && bestDiff <= maxAcceptableSkew {
		return best
	}

	// Monotonic/boot-relative timestamps are mapped to wall-clock "now"
	// so repeated flow events can be bucketed into stable session windows.
	return nowEpoch
}

func absInt64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

// updateStats updates aggregation statistics.
func (a *Aggregator) updateStats(processed int64, events []json.RawMessage) {
	a.stats.mu.Lock()
	defer a.stats.mu.Unlock()

	a.stats.TotalEvents += processed
	a.stats.LastEventTime = time.Now()

	// Update per-type and per-node stats
	for _, eventData := range events {
		var eventMap map[string]interface{}
		if err := json.Unmarshal(eventData, &eventMap); err != nil {
			continue
		}

		// Update event type stats
		if eventType, ok := eventMap["type"].(string); ok {
			a.stats.EventsByType[eventType]++
		}

		// Update node stats
		if nodeName, ok := eventMap["k8s_node_name"].(string); ok {
			a.stats.EventsByNode[nodeName]++
		}
	}
}

// parseEventQuery parses HTTP query parameters into a core.Query.
func parseEventQuery(r *http.Request) core.Query {
	query := core.Query{}

	if eventType := r.URL.Query().Get("type"); eventType != "" {
		query.EventType = eventType
	}

	if pidStr := r.URL.Query().Get("pid"); pidStr != "" {
		if pid, err := strconv.ParseUint(pidStr, 10, 32); err == nil {
			query.PID = uint32(pid)
		}
	}

	if command := r.URL.Query().Get("command"); command != "" {
		query.Command = command
	}

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil {
			query.Limit = limit
		}
	}

	return query
}

// SimpleEvent is a simple implementation of core.Event for aggregated data.
type SimpleEvent struct {
	data map[string]interface{}
}

func (e *SimpleEvent) ID() string {
	if id, ok := e.data["id"].(string); ok {
		return id
	}
	return ""
}

func (e *SimpleEvent) Type() string {
	if eventType, ok := e.data["type"].(string); ok {
		return eventType
	}
	return ""
}

func (e *SimpleEvent) PID() uint32 {
	if pid, ok := e.data["pid"].(float64); ok {
		return uint32(pid)
	}
	return 0
}

func (e *SimpleEvent) Command() string {
	if command, ok := e.data["command"].(string); ok {
		return command
	}
	return ""
}

func (e *SimpleEvent) Timestamp() uint64 {
	if timestamp, ok := e.data["timestamp"].(float64); ok {
		return uint64(timestamp)
	}
	return 0
}

func (e *SimpleEvent) Time() time.Time {
	if timeStr, ok := e.data["time"].(string); ok {
		if t, err := time.Parse(time.RFC3339Nano, timeStr); err == nil {
			return t
		}
	}
	return time.Time{}
}

func (e *SimpleEvent) Metadata() map[string]interface{} {
	return e.data
}

func (e *SimpleEvent) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.data)
}

// QueryEvents retrieves events matching the criteria (for API compatibility).
func (a *Aggregator) QueryEvents(ctx context.Context, query core.Query) ([]core.Event, error) {
	return a.storage.Query(ctx, query)
}

// CountEvents returns the number of events matching the criteria (for API compatibility).
func (a *Aggregator) CountEvents(ctx context.Context, query core.Query) (int, error) {
	return a.storage.Count(ctx, query)
}

// GetPrograms returns program status (for API compatibility).
// The aggregator doesn't manage eBPF programs directly, so returns empty slice.
func (a *Aggregator) GetPrograms() []core.ProgramStatus {
	return []core.ProgramStatus{}
}

// HandleListConnections returns recent connection events from aggregated data.
//
//	@Summary		List connection events
//	@Description	Get recent connection events grouped by PID from aggregated data
//	@Tags			connections
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	AggregatedListResponse	"Connection events"
//	@Failure		500	{object}	map[string]string		"Internal server error"
//	@Failure		503	{object}	map[string]string		"Service unavailable"
//	@Router			/api/list-connections [get]
func (a *Aggregator) HandleListConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	query := core.Query{
		EventType: "connection",
		Limit:     100,
		Since:     time.Now().Add(-1 * time.Hour), // Last hour by default
	}

	events, err := a.storage.Query(r.Context(), query)
	if err != nil {
		logger.Errorf("Error querying connection events: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Group by PID for compatibility
	eventsByPID := make(map[uint32][]core.Event)
	eventsByNode := make(map[string]int)
	nodeSet := make(map[string]bool)

	for _, event := range events {
		pid := event.PID()
		eventsByPID[pid] = append(eventsByPID[pid], event)

		// Extract node information from event metadata
		if metadata := event.Metadata(); metadata != nil {
			if nodeName, ok := metadata["k8s_node_name"].(string); ok && nodeName != "" {
				eventsByNode[nodeName]++
				nodeSet[nodeName] = true
			}
		}
	}

	response := AggregatedListResponse{
		TotalPIDs:    len(eventsByPID),
		TotalEvents:  len(events),
		TotalNodes:   len(nodeSet),
		EventsByPID:  eventsByPID,
		EventsByNode: eventsByNode,
		QueryTime:    time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logger.Errorf("Error encoding list connections response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// HandleListPacketDrops returns recent packet drop events from aggregated data.
//
//	@Summary		List packet drop events
//	@Description	Get recent packet drop events grouped by PID from aggregated data
//	@Tags			packet_drops
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	AggregatedListResponse	"Packet drop events"
//	@Failure		500	{object}	map[string]string		"Internal server error"
//	@Failure		503	{object}	map[string]string		"Service unavailable"
//	@Router			/api/list-packet-drops [get]
func (a *Aggregator) HandleListPacketDrops(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	query := core.Query{
		EventType: "packet_drop",
		Limit:     100,
		Since:     time.Now().Add(-1 * time.Hour), // Last hour by default
	}

	events, err := a.storage.Query(r.Context(), query)
	if err != nil {
		logger.Errorf("Error querying packet drop events: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Group by PID for compatibility
	eventsByPID := make(map[uint32][]core.Event)
	eventsByNode := make(map[string]int)
	nodeSet := make(map[string]bool)

	for _, event := range events {
		pid := event.PID()
		eventsByPID[pid] = append(eventsByPID[pid], event)

		// Extract node information from event metadata
		if metadata := event.Metadata(); metadata != nil {
			if nodeName, ok := metadata["k8s_node_name"].(string); ok && nodeName != "" {
				eventsByNode[nodeName]++
				nodeSet[nodeName] = true
			}
		}
	}

	response := AggregatedListResponse{
		TotalPIDs:    len(eventsByPID),
		TotalEvents:  len(events),
		TotalNodes:   len(nodeSet),
		EventsByPID:  eventsByPID,
		EventsByNode: eventsByNode,
		QueryTime:    time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logger.Errorf("Error encoding list packet drops response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// HandleConnectionSummary provides connection event summaries from aggregated data.
//
//	@Summary		Get connection statistics
//	@Description	Get count of connection events filtered by PID, command, and time window from aggregated data
//	@Tags			connections
//	@Accept			json
//	@Produce		json
//	@Param			pid				query		int		false	"Process ID"
//	@Param			command			query		string	false	"Command name"
//	@Param			duration_seconds	query	int		false	"Duration in seconds (default: 60)"
//	@Param			request			body		map[string]interface{}	false	"Connection summary request (POST only)"
//	@Success		200				{object}	AggregatedSummaryResponse	"Connection statistics"
//	@Failure		400				{object}	map[string]string		"Bad request"
//	@Failure		500				{object}	map[string]string		"Internal server error"
//	@Router			/api/connection-summary [get]
//	@Router			/api/connection-summary [post]
func (a *Aggregator) HandleConnectionSummary(w http.ResponseWriter, r *http.Request) {
	// Parse request body for POST requests
	var request struct {
		PID      uint32 `json:"pid"`
		Command  string `json:"command"`
		Duration int    `json:"duration_seconds"`
	}

	if r.Method == "POST" {
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
	} else {
		// Handle GET request with query parameters
		if pidStr := r.URL.Query().Get("pid"); pidStr != "" {
			if pid, err := strconv.ParseUint(pidStr, 10, 32); err == nil {
				request.PID = uint32(pid)
			}
		}
		request.Command = r.URL.Query().Get("command")
		if durationStr := r.URL.Query().Get("duration_seconds"); durationStr != "" {
			if duration, err := strconv.Atoi(durationStr); err == nil {
				request.Duration = duration
			}
		}
	}

	// Default duration to 60 seconds
	if request.Duration == 0 {
		request.Duration = 60
	}

	// Build query
	query := core.Query{
		EventType: "connection",
		PID:       request.PID,
		Command:   request.Command,
		Since:     time.Now().Add(-time.Duration(request.Duration) * time.Second),
	}

	count, err := a.storage.Count(r.Context(), query)
	if err != nil {
		logger.Errorf("Error counting connection events: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	logger.Debugf("🔍 CONNECTION SUMMARY: query=%+v count=%d", query, count)

	// Get events to analyze by node for detailed response
	eventsQuery := query
	eventsQuery.Limit = 1000 // Reasonable limit for analysis
	events, err := a.storage.Query(r.Context(), eventsQuery)
	if err != nil {
		logger.Errorf("Error querying connection events for node analysis: %v", err)
		// Fall back to basic response without node breakdown
		events = nil
	}

	// Analyze events by node
	countByNode := make(map[string]int)
	nodeSet := make(map[string]bool)

	for _, event := range events {
		if metadata := event.Metadata(); metadata != nil {
			if nodeName, ok := metadata["k8s_node_name"].(string); ok && nodeName != "" {
				countByNode[nodeName]++
				nodeSet[nodeName] = true
			}
		}
	}

	response := AggregatedSummaryResponse{
		Count:           count,
		CountByNode:     countByNode,
		PID:             request.PID,
		Command:         request.Command,
		DurationSeconds: request.Duration,
		TotalNodes:      len(nodeSet),
		QueryTime:       time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logger.Errorf("Error encoding connection summary response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// HandlePacketDropSummary provides packet drop event summaries from aggregated data.
//
//	@Summary		Get packet drop statistics
//	@Description	Get count of packet drop events filtered by PID, command, and time window from aggregated data
//	@Tags			packet_drops
//	@Accept			json
//	@Produce		json
//	@Param			pid				query		int		false	"Process ID"
//	@Param			command			query		string	false	"Command name"
//	@Param			duration_seconds	query	int		false	"Duration in seconds (default: 60)"
//	@Param			request			body		map[string]interface{}	false	"Packet drop summary request (POST only)"
//	@Success		200				{object}	AggregatedSummaryResponse	"Packet drop statistics"
//	@Failure		400				{object}	map[string]string		"Bad request"
//	@Failure		500				{object}	map[string]string		"Internal server error"
//	@Router			/api/packet-drop-summary [get]
//	@Router			/api/packet-drop-summary [post]
func (a *Aggregator) HandlePacketDropSummary(w http.ResponseWriter, r *http.Request) {
	// Parse request body for POST requests
	var request struct {
		PID      uint32 `json:"pid"`
		Command  string `json:"command"`
		Duration int    `json:"duration_seconds"`
	}

	if r.Method == "POST" {
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
	} else {
		// Handle GET request with query parameters
		if pidStr := r.URL.Query().Get("pid"); pidStr != "" {
			if pid, err := strconv.ParseUint(pidStr, 10, 32); err == nil {
				request.PID = uint32(pid)
			}
		}
		request.Command = r.URL.Query().Get("command")
		if durationStr := r.URL.Query().Get("duration_seconds"); durationStr != "" {
			if duration, err := strconv.Atoi(durationStr); err == nil {
				request.Duration = duration
			}
		}
	}

	// Default duration to 60 seconds
	if request.Duration == 0 {
		request.Duration = 60
	}

	// Build query
	query := core.Query{
		EventType: "packet_drop",
		PID:       request.PID,
		Command:   request.Command,
		Since:     time.Now().Add(-time.Duration(request.Duration) * time.Second),
	}

	count, err := a.storage.Count(r.Context(), query)
	if err != nil {
		logger.Errorf("Error counting packet drop events: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	logger.Debugf("🔍 PACKET DROP SUMMARY: query=%+v count=%d", query, count)

	// Get events to analyze by node for detailed response
	eventsQuery := query
	eventsQuery.Limit = 1000 // Reasonable limit for analysis
	events, err := a.storage.Query(r.Context(), eventsQuery)
	if err != nil {
		logger.Errorf("Error querying packet drop events for node analysis: %v", err)
		// Fall back to basic response without node breakdown
		events = nil
	}

	// Analyze events by node
	countByNode := make(map[string]int)
	nodeSet := make(map[string]bool)

	for _, event := range events {
		if metadata := event.Metadata(); metadata != nil {
			if nodeName, ok := metadata["k8s_node_name"].(string); ok && nodeName != "" {
				countByNode[nodeName]++
				nodeSet[nodeName] = true
			}
		}
	}

	response := AggregatedSummaryResponse{
		Count:           count,
		CountByNode:     countByNode,
		PID:             request.PID,
		Command:         request.Command,
		DurationSeconds: request.Duration,
		TotalNodes:      len(nodeSet),
		QueryTime:       time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logger.Errorf("Error encoding packet drop summary response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}
