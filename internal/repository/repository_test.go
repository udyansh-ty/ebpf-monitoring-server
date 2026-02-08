package repository

import (
	"context"
	"testing"
)

func TestMemoryRepositorySaveEvent(t *testing.T) {
	repo := NewMemoryEventRepository()
	ctx := context.Background()

	event := map[string]interface{}{"id": "test", "data": "value"}
	err := repo.SaveEvent(ctx, event)
	if err != nil {
		t.Fatalf("Unexpected error saving event: %v", err)
	}
}

func TestMemoryRepositorySaveNilEvent(t *testing.T) {
	repo := NewMemoryEventRepository()
	ctx := context.Background()

	err := repo.SaveEvent(ctx, nil)
	if err == nil {
		t.Error("Expected error saving nil event")
	}
}

func TestMemoryRepositoryDeleteEvent(t *testing.T) {
	repo := NewMemoryEventRepository()
	ctx := context.Background()

	// Save an event first
	event := map[string]interface{}{"id": "test"}
	_ = repo.SaveEvent(ctx, event)

	// Delete the event
	err := repo.DeleteEvent(ctx, "event_0")
	if err != nil {
		t.Fatalf("Unexpected error deleting event: %v", err)
	}
}

func TestMemoryRepositoryDeleteNonexistentEvent(t *testing.T) {
	repo := NewMemoryEventRepository()
	ctx := context.Background()

	err := repo.DeleteEvent(ctx, "nonexistent")
	if err == nil {
		t.Error("Expected error deleting nonexistent event")
	}
}

func TestMemoryRepositoryGetEvents(t *testing.T) {
	repo := NewMemoryEventRepository()
	ctx := context.Background()

	// Save some events
	for i := 0; i < 3; i++ {
		_ = repo.SaveEvent(ctx, map[string]interface{}{"id": i})
	}

	result, err := repo.GetEvents(ctx, nil)
	if err != nil {
		t.Fatalf("Unexpected error getting events: %v", err)
	}

	if result == nil {
		t.Error("Expected result, got nil")
	}
}

func TestMemoryRepositoryGetConnectionSummary(t *testing.T) {
	repo := NewMemoryEventRepository()
	ctx := context.Background()

	result, err := repo.GetConnectionSummary(ctx, nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result == nil {
		t.Error("Expected result, got nil")
	}
}

func TestMemoryRepositoryGetPacketDropSummary(t *testing.T) {
	repo := NewMemoryEventRepository()
	ctx := context.Background()

	result, err := repo.GetPacketDropSummary(ctx, nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result == nil {
		t.Error("Expected result, got nil")
	}
}

func TestMemoryRepositoryListConnections(t *testing.T) {
	repo := NewMemoryEventRepository()
	ctx := context.Background()

	result, err := repo.ListConnections(ctx, nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result == nil {
		t.Error("Expected result, got nil")
	}
}

func TestMemoryRepositoryListPacketDrops(t *testing.T) {
	repo := NewMemoryEventRepository()
	ctx := context.Background()

	result, err := repo.ListPacketDrops(ctx, nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result == nil {
		t.Error("Expected result, got nil")
	}
}
