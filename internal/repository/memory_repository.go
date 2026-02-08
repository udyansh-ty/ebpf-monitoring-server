package repository

import (
	"context"
	"fmt"
	"sync"
)

// MemoryEventRepository is an in-memory implementation of EventRepository
type MemoryEventRepository struct {
	events map[string]interface{}
	mu     sync.RWMutex
}

// NewMemoryEventRepository creates a new in-memory event repository
func NewMemoryEventRepository() EventRepository {
	return &MemoryEventRepository{
		events: make(map[string]interface{}),
	}
}

// GetEvents retrieves events with optional filters
func (m *MemoryEventRepository) GetEvents(ctx context.Context, filters map[string]interface{}) (interface{}, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var results []interface{}
	for _, event := range m.events {
		results = append(results, event)
	}

	return map[string]interface{}{
		"events": results,
		"count":  len(results),
	}, nil
}

// GetConnectionSummary returns summary of network connections
func (m *MemoryEventRepository) GetConnectionSummary(ctx context.Context, filters map[string]interface{}) (interface{}, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]interface{}{
		"total_connections": len(m.events),
		"active_connections": 0,
	}, nil
}

// GetPacketDropSummary returns summary of packet drops
func (m *MemoryEventRepository) GetPacketDropSummary(ctx context.Context, filters map[string]interface{}) (interface{}, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]interface{}{
		"total_drops": 0,
		"drop_rate":   0.0,
	}, nil
}

// ListConnections returns list of network connections
func (m *MemoryEventRepository) ListConnections(ctx context.Context, filters map[string]interface{}) (interface{}, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]interface{}{
		"connections": []interface{}{},
	}, nil
}

// ListPacketDrops returns list of packet drops
func (m *MemoryEventRepository) ListPacketDrops(ctx context.Context, filters map[string]interface{}) (interface{}, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]interface{}{
		"packet_drops": []interface{}{},
	}, nil
}

// SaveEvent saves an event to the repository
func (m *MemoryEventRepository) SaveEvent(ctx context.Context, event interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if event == nil {
		return fmt.Errorf("event cannot be nil")
	}

	// Generate a simple ID
	id := fmt.Sprintf("event_%d", len(m.events))
	m.events[id] = event

	return nil
}

// DeleteEvent deletes an event from the repository
func (m *MemoryEventRepository) DeleteEvent(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.events[id]; !exists {
		return fmt.Errorf("event not found: %s", id)
	}

	delete(m.events, id)
	return nil
}
