package service

import (
	"context"
	"fmt"

	"github.com/srodi/ebpf-server/internal/core"
	"github.com/srodi/ebpf-server/internal/system"
	"github.com/srodi/ebpf-server/pkg/logger"
)

// DefaultProgramService is the default implementation of ProgramService
type DefaultProgramService struct {
	system *system.System
	logger *logger.Logger
}

// NewProgramService creates a new ProgramService
func NewProgramService(sys *system.System, log *logger.Logger) ProgramService {
	if log == nil {
		log = logger.GetDefaultLogger()
	}
	return &DefaultProgramService{
		system: sys,
		logger: log,
	}
}

// GetPrograms returns all eBPF programs
func (ps *DefaultProgramService) GetPrograms(ctx context.Context) []core.ProgramInfo {
	if ps.system == nil {
		ps.logger.Warnf("system is not initialized")
		return []core.ProgramInfo{}
	}

	return ps.system.GetPrograms()
}

// GetProgramStatus returns status for a specific program
func (ps *DefaultProgramService) GetProgramStatus(ctx context.Context, name string) (*core.ProgramInfo, error) {
	if ps.system == nil {
		return nil, fmt.Errorf("system not initialized")
	}

	programs := ps.system.GetPrograms()
	for i := range programs {
		if programs[i].Name == name {
			return &programs[i], nil
		}
	}

	return nil, fmt.Errorf("program not found: %s", name)
}
