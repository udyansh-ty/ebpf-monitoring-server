package repository

import (
	"context"
)

// EventRepository defines the interface for event data access
type EventRepository interface {
	GetEvents(ctx context.Context, filters map[string]interface{}) (interface{}, error)
	GetConnectionSummary(ctx context.Context, filters map[string]interface{}) (interface{}, error)
	GetPacketDropSummary(ctx context.Context, filters map[string]interface{}) (interface{}, error)
	ListConnections(ctx context.Context, filters map[string]interface{}) (interface{}, error)
	ListPacketDrops(ctx context.Context, filters map[string]interface{}) (interface{}, error)
	SaveEvent(ctx context.Context, event interface{}) error
	DeleteEvent(ctx context.Context, id string) error
}

// Repositories is a container for all repository dependencies
type Repositories struct {
	Event EventRepository
}

// NewRepositories creates a new Repositories container
func NewRepositories(eventRepo EventRepository) *Repositories {
	return &Repositories{
		Event: eventRepo,
	}
}
