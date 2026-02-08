package service

import (
	"context"

	"github.com/srodi/ebpf-server/internal/system"
	"github.com/srodi/ebpf-server/pkg/logger"
)

// DefaultHealthService is the default implementation of HealthService
type DefaultHealthService struct {
	system *system.System
	logger *logger.Logger
}

// NewHealthService creates a new HealthService
func NewHealthService(sys *system.System, log *logger.Logger) HealthService {
	if log == nil {
		log = logger.GetDefaultLogger()
	}
	return &DefaultHealthService{
		system: sys,
		logger: log,
	}
}

// GetHealth returns health status of the system
func (hs *DefaultHealthService) GetHealth(ctx context.Context) map[string]interface{} {
	status := "healthy"
	statusCode := "ok"

	if hs.system == nil {
		status = "unhealthy"
		statusCode = "system_not_initialized"
	}

	return map[string]interface{}{
		"status":    status,
		"component": "eBPF Monitor API",
		"uptime":    "active",
		"version":   "1.0.0",
		"code":      statusCode,
	}
}
