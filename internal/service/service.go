package service

import (
	"context"

	"github.com/srodi/ebpf-server/internal/core"
	"github.com/srodi/ebpf-server/pkg/logger"
)

// ProgramService defines methods for managing eBPF programs
type ProgramService interface {
	GetPrograms(ctx context.Context) []core.ProgramInfo
	GetProgramStatus(ctx context.Context, name string) (*core.ProgramInfo, error)
}

// EventService defines methods for retrieving events
type EventService interface {
	GetEvents(ctx context.Context, filters map[string]interface{}) (interface{}, error)
	GetConnectionSummary(ctx context.Context, filters map[string]interface{}) (interface{}, error)
	GetPacketDropSummary(ctx context.Context, filters map[string]interface{}) (interface{}, error)
	ListConnections(ctx context.Context, filters map[string]interface{}) (interface{}, error)
	ListPacketDrops(ctx context.Context, filters map[string]interface{}) (interface{}, error)
}

// HealthService defines methods for system health checks
type HealthService interface {
	GetHealth(ctx context.Context) map[string]interface{}
}

// Services is a container for all service dependencies
type Services struct {
	Program ProgramService
	Event   EventService
	Health  HealthService
	Logger  *logger.Logger
}

// NewServices creates a new Services container
func NewServices(programSvc ProgramService, eventSvc EventService, healthSvc HealthService, log *logger.Logger) *Services {
	return &Services{
		Program: programSvc,
		Event:   eventSvc,
		Health:  healthSvc,
		Logger:  log,
	}
}
