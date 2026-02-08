package service

import (
	"context"
	"fmt"

	"github.com/srodi/ebpf-server/internal/system"
	"github.com/srodi/ebpf-server/pkg/logger"
)

// DefaultEventService is the default implementation of EventService
type DefaultEventService struct {
	system *system.System
	logger *logger.Logger
}

// NewEventService creates a new EventService
func NewEventService(sys *system.System, log *logger.Logger) EventService {
	if log == nil {
		log = logger.GetDefaultLogger()
	}
	return &DefaultEventService{
		system: sys,
		logger: log,
	}
}

// GetEvents retrieves events with optional filters
func (es *DefaultEventService) GetEvents(ctx context.Context, filters map[string]interface{}) (interface{}, error) {
	if es.system == nil {
		return nil, fmt.Errorf("system not initialized")
	}

	// Pass through to system query
	// In future, this would apply filters
	return es.system.QueryEvents(filters)
}

// GetConnectionSummary returns summary of network connections
func (es *DefaultEventService) GetConnectionSummary(ctx context.Context, filters map[string]interface{}) (interface{}, error) {
	if es.system == nil {
		return nil, fmt.Errorf("system not initialized")
	}

	return es.system.QueryConnectionSummary(filters)
}

// GetPacketDropSummary returns summary of packet drops
func (es *DefaultEventService) GetPacketDropSummary(ctx context.Context, filters map[string]interface{}) (interface{}, error) {
	if es.system == nil {
		return nil, fmt.Errorf("system not initialized")
	}

	return es.system.QueryPacketDropSummary(filters)
}

// ListConnections returns list of network connections
func (es *DefaultEventService) ListConnections(ctx context.Context, filters map[string]interface{}) (interface{}, error) {
	if es.system == nil {
		return nil, fmt.Errorf("system not initialized")
	}

	return es.system.ListConnections(filters)
}

// ListPacketDrops returns list of packet drops
func (es *DefaultEventService) ListPacketDrops(ctx context.Context, filters map[string]interface{}) (interface{}, error) {
	if es.system == nil {
		return nil, fmt.Errorf("system not initialized")
	}

	return es.system.ListPacketDrops(filters)
}
