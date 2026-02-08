package service

import (
	"github.com/srodi/ebpf-server/internal/repository"
	"github.com/srodi/ebpf-server/internal/system"
	"github.com/srodi/ebpf-server/pkg/logger"
)

// Factory creates and configures all services
type Factory struct {
	system *system.System
	logger *logger.Logger
}

// NewFactory creates a new service factory
func NewFactory(sys *system.System, log *logger.Logger) *Factory {
	if log == nil {
		log = logger.GetDefaultLogger()
	}
	return &Factory{
		system: sys,
		logger: log,
	}
}

// CreateServices creates all services with default implementations
func (f *Factory) CreateServices() *Services {
	programSvc := NewProgramService(f.system, f.logger)
	eventSvc := NewEventService(f.system, f.logger)
	healthSvc := NewHealthService(f.system, f.logger)

	return NewServices(programSvc, eventSvc, healthSvc, f.logger)
}

// CreateRepositories creates all repositories with default implementations
func (f *Factory) CreateRepositories() *repository.Repositories {
	eventRepo := repository.NewMemoryEventRepository()
	return repository.NewRepositories(eventRepo)
}

// CreateServicesWithRepositories creates services that use repositories
func (f *Factory) CreateServicesWithRepositories() *Services {
	repos := f.CreateRepositories()

	// Create event service that uses repository
	eventSvc := &repositoryEventService{
		repo:   repos.Event,
		logger: f.logger,
	}

	programSvc := NewProgramService(f.system, f.logger)
	healthSvc := NewHealthService(f.system, f.logger)

	return NewServices(programSvc, eventSvc, healthSvc, f.logger)
}

// repositoryEventService wraps EventRepository as an EventService
type repositoryEventService struct {
	repo   repository.EventRepository
	logger *logger.Logger
}

func (res *repositoryEventService) GetEvents(ctx interface{}, filters map[string]interface{}) (interface{}, error) {
	return res.repo.GetEvents(ctx, filters)
}

func (res *repositoryEventService) GetConnectionSummary(ctx interface{}, filters map[string]interface{}) (interface{}, error) {
	return res.repo.GetConnectionSummary(ctx, filters)
}

func (res *repositoryEventService) GetPacketDropSummary(ctx interface{}, filters map[string]interface{}) (interface{}, error) {
	return res.repo.GetPacketDropSummary(ctx, filters)
}

func (res *repositoryEventService) ListConnections(ctx interface{}, filters map[string]interface{}) (interface{}, error) {
	return res.repo.ListConnections(ctx, filters)
}

func (res *repositoryEventService) ListPacketDrops(ctx interface{}, filters map[string]interface{}) (interface{}, error) {
	return res.repo.ListPacketDrops(ctx, filters)
}
