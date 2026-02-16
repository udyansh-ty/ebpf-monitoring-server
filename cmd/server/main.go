package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/srodi/ebpf-server/internal/api"
	"github.com/srodi/ebpf-server/internal/auth"
	"github.com/srodi/ebpf-server/internal/middleware"
	"github.com/srodi/ebpf-server/internal/system"
	"github.com/srodi/ebpf-server/pkg/logger"

	_ "github.com/srodi/ebpf-server/docs/swagger" // Import generated docs
	httpSwagger "github.com/swaggo/http-swagger"
)

func main() {
	// Parse command-line flags
	var (
		httpAddr  = flag.String("addr", ":8080", "HTTP server address")
		jwtSecret = flag.String("jwt-secret", os.Getenv("JWT_SECRET"), "JWT signing secret")
	)
	flag.Parse()

	// Validate JWT secret
	if *jwtSecret == "" {
		fmt.Fprintf(os.Stderr, "WARNING: JWT_SECRET not set, generating random secret\n")
		*jwtSecret = auth.GenerateSecret()
	}

	// Check if debug logging is enabled
	logger.Info("Starting eBPF Network Monitor...")
	logger.Debug("Debug logging is enabled")
	logger.Debugf("Debug logging test - IsDebugEnabled: %v", logger.IsDebugEnabled())

	// Create a new system instance
	ctx := context.Background()
	logger.Debug("Creating system instance...")
	system := system.NewSystem()
	// Initialize API with the system
	api.Initialize(system)

	// Initialize and start eBPF programs
	if err := system.Initialize(); err != nil {
		logger.Fatalf("failed to initialize eBPF: %v", err)
	}

	if err := system.Start(ctx); err != nil {
		logger.Fatalf("failed to start eBPF: %v", err)
	}

	// Setup signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		logger.Info("Shutdown signal received...")
		logger.Debug("Starting cleanup process...")
		if err := system.Stop(ctx); err != nil {
			logger.Errorf("Error stopping eBPF system: %v", err)
		}
		logger.Debug("eBPF cleanup complete, canceling context...")
		cancel()
	}()

	// Initialize token generator
	tokenGen := auth.NewTokenGenerator(&auth.JWTConfig{
		SigningKey: *jwtSecret,
	})

	// Setup HTTP routes
	mux := http.NewServeMux()

	// Auth endpoints (no middleware)
	mux.HandleFunc("/api/auth/login", api.HandleLogin(tokenGen))
	mux.HandleFunc("/api/auth/refresh", api.HandleRefresh(tokenGen))

	// Health check (no middleware)
	mux.HandleFunc("/health", api.HandleHealth)

	// Wire auth middleware
	authMW := middleware.AuthMiddleware(tokenGen)

	// Protected API endpoints (with middleware)
	mux.Handle("/api/connection-summary", authMW(http.HandlerFunc(api.HandleConnectionSummary)))
	mux.Handle("/api/packet-drop-summary", authMW(http.HandlerFunc(api.HandlePacketDropSummary)))
	mux.Handle("/api/list-connections", authMW(http.HandlerFunc(api.HandleListConnections)))
	mux.Handle("/api/list-packet-drops", authMW(http.HandlerFunc(api.HandleListPacketDrops)))

	// New auto-generated API endpoints (with middleware)
	mux.Handle("/api/programs", authMW(http.HandlerFunc(api.HandlePrograms)))
	mux.Handle("/api/events", authMW(http.HandlerFunc(api.HandleEvents)))

	// Swagger documentation
	mux.HandleFunc("/docs/", httpSwagger.WrapHandler)

	// Root endpoint with service information
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{
			"service": "eBPF Network Monitor",
			"version": "v1.0.0",
			"description": "HTTP API for eBPF-based network connection and packet drop monitoring",
			"endpoints": {
				"POST /api/connection-summary": "Get connection summary for a process",
				"POST /api/packet-drop-summary": "Get packet drop summary for a process",
				"GET|POST /api/list-connections": "List network connections",
				"GET|POST /api/list-packet-drops": "List packet drops",
				"GET /api/programs": "List active eBPF programs",
				"GET /api/events": "Get filtered events",
				"GET /health": "Service health check"
			},
			"documentation": {
				"api": "/docs/",
				"swagger_json": "/docs/swagger.json",
				"swagger_yaml": "/docs/swagger.yaml"
			}
		}`)); err != nil {
			logger.Error("Failed to write health response", "error", err)
		}
	})

	logger.Infof("Starting eBPF Network Monitor HTTP API on %s...", *httpAddr)

	// Create middleware stack
	handler := http.Handler(mux)
	handler = middleware.ErrorHandlerMiddleware()(handler)    // innermost
	handler = middleware.ValidationMiddleware()(handler)
	handler = middleware.LoggingMiddleware()(handler)         // outermost

	// Create HTTP server
	httpServer := &http.Server{
		Addr:         *httpAddr,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start HTTP server in a goroutine
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("HTTP server failed: %v", err)
		}
	}()

	// Wait for context cancellation (shutdown signal)
	logger.Debug("Waiting for shutdown signal...")
	<-ctx.Done()
	logger.Debug("Context canceled, starting graceful shutdown...")

	// Graceful shutdown of HTTP server
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	logger.Debug("Shutting down HTTP server...")
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Fatalf("HTTP server shutdown error: %v", err)
	}

	logger.Info("Server shutdown complete")
}
