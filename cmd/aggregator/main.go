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
	"github.com/srodi/ebpf-server/internal/l7"
	"github.com/srodi/ebpf-server/internal/storage"
	"github.com/srodi/ebpf-server/pkg/logger"

	_ "github.com/srodi/ebpf-server/docs/swagger-aggregator" // Import generated aggregator docs
	httpSwagger "github.com/swaggo/http-swagger"
)

func main() {
	// Parse command-line flags
	var (
		httpAddr = flag.String("addr", ":8081", "HTTP server address")
		dbURL    = flag.String("db-url", os.Getenv("DB_URL"), "PostgreSQL connection string (optional)")
	)
	flag.Parse()

	logger.Info("Starting eBPF Event Aggregator...")

	// ANCHOR: Optional PostgreSQL Storage for L7 Events - Jan 31, 2026
	// WHY: Enable persistent storage of L7 webhook events with NDPI enrichment
	// WHAT: Check for DB_URL env var or -db-url flag, configure storage backend
	// HOW: Create PostgreSQLStorage if URL provided, otherwise use MemoryStorage
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var pgStorage *storage.PostgreSQLStorage
	if *dbURL != "" {
		logger.Infof("Initializing PostgreSQL storage: %s", *dbURL)
		var err error
		pgStorage, err = storage.NewPostgreSQLStorage(ctx, *dbURL)
		if err != nil {
			logger.Fatalf("Failed to initialize PostgreSQL storage: %v", err)
		}
		defer pgStorage.Close()
		logger.Info("✅ PostgreSQL storage initialized successfully")
	} else {
		logger.Info("Using in-memory storage (set DB_URL environment variable to enable PostgreSQL)")
	}

	// Create aggregator
	agg, err := aggregator.New(&aggregator.Config{
		HTTPAddr: *httpAddr,
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
