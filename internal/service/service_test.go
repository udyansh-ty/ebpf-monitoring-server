package service

import (
	"context"
	"testing"

	"github.com/srodi/ebpf-server/internal/core"
	"github.com/srodi/ebpf-server/pkg/logger"
)

// MockSystem is a mock implementation of system for testing
type MockSystem struct {
	programs []core.ProgramInfo
}

func (m *MockSystem) GetPrograms() []core.ProgramInfo {
	return m.programs
}

func (m *MockSystem) QueryEvents(filters map[string]interface{}) (interface{}, error) {
	return map[string]interface{}{"events": []interface{}{}}, nil
}

func (m *MockSystem) QueryConnectionSummary(filters map[string]interface{}) (interface{}, error) {
	return map[string]interface{}{"summary": "connection"}, nil
}

func (m *MockSystem) QueryPacketDropSummary(filters map[string]interface{}) (interface{}, error) {
	return map[string]interface{}{"summary": "packet_drop"}, nil
}

func (m *MockSystem) ListConnections(filters map[string]interface{}) (interface{}, error) {
	return map[string]interface{}{"connections": []interface{}{}}, nil
}

func (m *MockSystem) ListPacketDrops(filters map[string]interface{}) (interface{}, error) {
	return map[string]interface{}{"packet_drops": []interface{}{}}, nil
}

func TestProgramServiceGetPrograms(t *testing.T) {
	mockSys := &MockSystem{
		programs: []core.ProgramInfo{
			{Name: "test_program", Loaded: true, Attached: true},
		},
	}

	svc := NewProgramService(mockSys, logger.GetDefaultLogger())
	ctx := context.Background()

	programs := svc.GetPrograms(ctx)
	if len(programs) != 1 {
		t.Errorf("Expected 1 program, got %d", len(programs))
	}

	if programs[0].Name != "test_program" {
		t.Errorf("Expected program name 'test_program', got '%s'", programs[0].Name)
	}
}

func TestProgramServiceGetProgramStatus(t *testing.T) {
	mockSys := &MockSystem{
		programs: []core.ProgramInfo{
			{Name: "test_program", Loaded: true, Attached: true},
		},
	}

	svc := NewProgramService(mockSys, logger.GetDefaultLogger())
	ctx := context.Background()

	prog, err := svc.GetProgramStatus(ctx, "test_program")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if prog.Name != "test_program" {
		t.Errorf("Expected program name 'test_program', got '%s'", prog.Name)
	}
}

func TestProgramServiceGetProgramStatusNotFound(t *testing.T) {
	mockSys := &MockSystem{
		programs: []core.ProgramInfo{},
	}

	svc := NewProgramService(mockSys, logger.GetDefaultLogger())
	ctx := context.Background()

	_, err := svc.GetProgramStatus(ctx, "nonexistent")
	if err == nil {
		t.Error("Expected error for nonexistent program")
	}
}

func TestEventServiceGetEvents(t *testing.T) {
	mockSys := &MockSystem{}

	svc := NewEventService(mockSys, logger.GetDefaultLogger())
	ctx := context.Background()

	result, err := svc.GetEvents(ctx, nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result == nil {
		t.Error("Expected result, got nil")
	}
}

func TestHealthServiceGetHealth(t *testing.T) {
	mockSys := &MockSystem{}

	svc := NewHealthService(mockSys, logger.GetDefaultLogger())
	ctx := context.Background()

	health := svc.GetHealth(ctx)
	if health["status"] != "healthy" {
		t.Errorf("Expected status 'healthy', got '%v'", health["status"])
	}

	if health["component"] != "eBPF Monitor API" {
		t.Errorf("Expected component 'eBPF Monitor API', got '%v'", health["component"])
	}
}

func TestHealthServiceGetHealthWithNilSystem(t *testing.T) {
	svc := NewHealthService(nil, logger.GetDefaultLogger())
	ctx := context.Background()

	health := svc.GetHealth(ctx)
	if health["status"] != "unhealthy" {
		t.Errorf("Expected status 'unhealthy' for nil system, got '%v'", health["status"])
	}
}
