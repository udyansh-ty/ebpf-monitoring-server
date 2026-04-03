package main

import (
	"context"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/srodi/ebpf-server/internal/aggregator"
	"github.com/srodi/ebpf-server/internal/events"
	"github.com/srodi/ebpf-server/internal/l7"
	"github.com/srodi/ebpf-server/internal/programs"
	"github.com/srodi/ebpf-server/internal/storage"
	"github.com/srodi/ebpf-server/pkg/logger"

	_ "github.com/srodi/ebpf-server/docs/swagger-aggregator" // Import generated aggregator docs
	httpSwagger "github.com/swaggo/http-swagger"
)

func main() {
	// Parse command-line flags
	var (
		httpAddr        = flag.String("addr", ":8081", "HTTP server address")
		dbURL           = flag.String("db-url", os.Getenv("DB_URL"), "PostgreSQL connection string (optional)")
		flowCacheTTL    = flag.Duration("flow-cache-ttl", 5*time.Minute, "Flow cache TTL for interface mapping (Phase 1B)")
		metaFlushInt    = flag.Duration("meta-flush-interval", 30*time.Second, "Metadata rollup flush interval")
		metaSessionTO   = flag.Duration("meta-session-timeout", 2*time.Minute, "Metadata rollup session timeout")
		disableEnricher = flag.Bool("disable-enricher", false, "Disable event enricher (for testing)")
	)
	flag.Parse()

	logger.Info("Starting eBPF Event Aggregator...")

	// ANCHOR: Initialize file logging for debugging - March 21, 2026
	// WHY: All data insertions and operations should be logged to /var/log/ebpf-aggregator.log
	// WHAT: Initialize dual logging to stdout and file
	// HOW: Call InitFileLogger with graceful fallback to stdout-only if file not writable
	if err := logger.InitFileLogger("/var/log/ebpf-aggregator.log"); err != nil {
		logger.Warnf("Could not open log file /var/log/ebpf-aggregator.log: %v (logging to stdout only)", err)
	} else {
		logger.Info("Log file initialized: /var/log/ebpf-aggregator.log")
	}

	// ANCHOR: Optional PostgreSQL Storage for L7 and eBPF Events - Feb 3, 2026
	// WHY: Enable persistent storage of L7 webhook events with NDPI enrichment AND eBPF kernel events with multi-NIC support
	// WHAT: Check for DB_URL env var or -db-url flag, configure dual event storage backend
	// HOW: Create PostgreSQLStorage if URL provided (routes L7 to l7_events table, eBPF to ebpf_events table), otherwise use MemoryStorage
	// EVENT ROUTING:
	//   - L7 events (webhook): → l7_events table with NDPI enrichment
	//   - Connection events: → ebpf_events table with multi-NIC fields
	//   - Packet drop events: → ebpf_events table with multi-NIC fields
	//   - Future eBPF programs: → ebpf_events table (auto-supported via program_name field)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var pgStorage *storage.PostgreSQLStorage
	if *dbURL != "" {
		logger.Infof("Initializing PostgreSQL storage with dual L7+eBPF backends: %s", *dbURL)
		var err error
		pgStorage, err = storage.NewPostgreSQLStorage(ctx, *dbURL)
		if err != nil {
			logger.Fatalf("Failed to initialize PostgreSQL storage: %v", err)
		}
		defer pgStorage.Close()
		logger.Info("✅ PostgreSQL storage initialized: L7 events → l7_events table, eBPF events → ebpf_events table")
	} else {
		logger.Info("Using in-memory storage (set DB_URL environment variable to enable PostgreSQL)")
	}

	// ANCHOR: Phase 1B - TC Classifier + EventEnricher Integration - Feb 6, 2026
	// WHY: Enable multi-NIC interface capture for connection events
	// WHAT: Initialize InterfaceResolver and EventEnricher from TC BPF program
	// HOW: Load TC classifier (when available), setup enricher, apply to events before storage
	var enricher *events.EventEnricher

	if !*disableEnricher {
		// Create interface resolver (scans /sys/class/net/)
		resolver := programs.NewInterfaceResolver(logger.GetDefaultLogger())
		resolver.Start(ctx)
		defer resolver.Stop()

		logger.Info("✅ InterfaceResolver initialized: scanning /sys/class/net/ for interfaces")

		// Create event enricher with configurable cache TTL
		// BPF maps will be nil initially - set when TC program loads
		enricher = events.NewEventEnricher(ctx, resolver, nil, logger.GetDefaultLogger(), *flowCacheTTL, true)

		logger.Infof("✅ EventEnricher initialized: flow cache TTL = %v (configurable via -flow-cache-ttl)", *flowCacheTTL)
		logger.Info("💡 Phase 1B: Ready for TC classifier BPF program (when integrated)")

		tcProgram, err := programs.LoadTCClassifier(ctx)
		if err != nil {
			logger.Warnf("Failed to load TC classifier (optional): %v", err)
			logger.Info("Continuing without TC interface capture (Phase 1B partial)")
		} else {
			enricher.TestingSetBPFMaps(tcProgram.Maps())
			defer tcProgram.Close()
			logger.Info("✅ TC classifier loaded and enricher configured")
		}
	} else {
		logger.Info("⚠️  EventEnricher disabled (--disable-enricher flag set)")
	}

	// ANCHOR: Pass Configured Storage - Bug: storage ignored - Feb 25, 2026
	// Ensure the aggregator uses PostgreSQL storage when DB_URL is provided.
	// Create aggregator
	agg, err := aggregator.New(&aggregator.Config{
		HTTPAddr:           *httpAddr,
		Storage:            pgStorage,
		Enricher:           enricher, // Pass enricher to aggregator for event pipeline integration (Phase 1B)
		MetaFlushInterval:  *metaFlushInt,
		MetaSessionTimeout: *metaSessionTO,
	})
	if err != nil {
		logger.Fatalf("Failed to create aggregator: %v", err)
	}

	// Start aggregator
	if err := agg.Start(ctx); err != nil {
		logger.Fatalf("Failed to start aggregator: %v", err)
	}

	// Setup HTTP routes
	mux := http.NewServeMux()

	// Health endpoint
	mux.HandleFunc("/health", agg.HandleHealth)

	// Events API
	mux.HandleFunc("/api/events", agg.HandleEvents)
	mux.HandleFunc("/api/events/ingest", agg.HandleIngest)
	mux.HandleFunc("/api/stats", agg.HandleStats)
	mux.HandleFunc("/api/programs", agg.HandlePrograms)

	// Connection and packet drop API endpoints (aggregator-specific)
	mux.HandleFunc("/api/list-connections", agg.HandleListConnections)
	mux.HandleFunc("/api/list-packet-drops", agg.HandleListPacketDrops)
	mux.HandleFunc("/api/connection-summary", agg.HandleConnectionSummary)
	mux.HandleFunc("/api/packet-drop-summary", agg.HandlePacketDropSummary)

	// ANCHOR: L7 Webhook Endpoints - Vaanvil Integration - Jan 31, 2026
	// WHY: Accept L7 security telemetry from external sensors
	// WHAT: Register HTTP endpoints for webhook ingestion and monitoring
	// HOW: Create L7 receiver with aggregator storage, register handlers
	l7Receiver := l7.NewReceiver(agg.GetStorage(), &l7.ReceiverConfig{
		MaxPayloadSize:  10 * 1024 * 1024, // 10MB payload limit
		RequestTimeout:  30 * time.Second,
		ValidateBatchID: true,
	})
	mux.HandleFunc("/api/l7/webhook", l7Receiver.HandleWebhook)
	mux.HandleFunc("/api/l7/webhook/stats", l7Receiver.HandleWebhookStats)

	// Swagger documentation
	mux.HandleFunc("/swagger/", httpSwagger.WrapHandler)

	// Create HTTP server
	server := &http.Server{
		Addr:    *httpAddr,
		Handler: mux,
	}

	// Start HTTP server in a goroutine
	go func() {
		logger.Infof("Starting HTTP server on %s", *httpAddr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Errorf("HTTP server error: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	logger.Info("Shutting down aggregator...")

	// Create shutdown context with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Shutdown HTTP server
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Errorf("HTTP server shutdown error: %v", err)
	}

	// Stop aggregator
	cancel()
	agg.Stop()

	logger.Info("Aggregator stopped")
}
