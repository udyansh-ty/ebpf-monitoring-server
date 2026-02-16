# Monitoring Repository - Implementation Gaps & Remediation Plan

> **Status:** Critical documentation-implementation gaps identified
> **Date:** February 7, 2026
> **Severity:** High - Documentation claims features not in code
> **Action:** Prioritized remediation plan

---

## EXECUTIVE SUMMARY

The monitoring repository has **40% architecture gap** between documentation and implementation:

| Component | Documented | Implemented | Gap |
|-----------|-----------|------------|-----|
| HTTP Handlers | Yes | ✅ 20/20 (100%) | None |
| API Endpoints | Yes | ✅ 20 wired (100%) | None |
| eBPF Programs | Yes | ✅ Complete | None |
| Kubernetes Support | Yes | ✅ Complete | None |
| Authentication/JWT | Yes | ❌ 0% | **CRITICAL** |
| Middleware Stack | Yes | ❌ 0% | **CRITICAL** |
| Service Layer | Yes | ❌ 0% | **CRITICAL** |
| Repository Pattern | Yes | ❌ 0% | **CRITICAL** |
| Redis Caching | Yes | ⚠️ 30% (in-memory only) | **HIGH** |
| Configuration Files | Yes | ❌ 0% | **HIGH** |
| API Documentation | Yes | ⚠️ Auto-generated only | **MEDIUM** |
| Test Success Paths | Yes | ⚠️ Error cases only | **MEDIUM** |

---

## CRITICAL GAPS (Must Fix)

### 1. ZERO AUTHENTICATION LAYER
**Problem:** All 20 endpoints are completely public; no JWT, no auth middleware

**Files Affected:**
- `cmd/server/main.go` (lines 68-80) - no auth middleware
- `cmd/aggregator/main.go` (lines 110-138) - no auth middleware
- `internal/api/handlers.go` (all 7 handlers) - no auth checks
- `internal/aggregator/aggregator.go` (all 13 handlers) - no auth checks

**Current Reality:**
```go
mux.HandleFunc("/api/events", api.HandleEvents)  // ← PUBLIC - anyone can call
```

**What Needs to Happen:**
1. Implement JWT authentication middleware
2. Add token generation/validation
3. Create auth context injection
4. Protect sensitive endpoints
5. Add rate limiting per user

**Implementation Tasks:**
- [ ] Create `internal/middleware/auth.go` (~150 LOC)
  - JWT middleware using golang-jwt/jwt
  - Token validation
  - User context injection
- [ ] Create `internal/auth/tokens.go` (~200 LOC)
  - Token generation (use RS256, not HS256)
  - Token validation
  - Claims definition
- [ ] Update all 20 handlers to require auth
- [ ] Create test suite for auth middleware
- [ ] Document auth in API.md

**Effort:** Medium (2-3 days) | **Priority:** CRITICAL

---

### 2. ZERO MIDDLEWARE LAYER
**Problem:** Handlers do everything; no separation of concerns

**What's Missing:**
- ❌ Logging middleware
- ❌ Request validation middleware
- ❌ Error handling middleware
- ❌ Rate limiting middleware
- ❌ CORS middleware
- ❌ Request ID tracking

**Current Handler Pattern (WRONG):**
```go
func HandleEvents(w http.ResponseWriter, r *http.Request) {
    // ← All parsing/validation/business logic in handler
    if globalSystem == nil {
        http.Error(w, "System not initialized", http.StatusServiceUnavailable)
        return
    }
    // ← Direct system call, no abstraction
    if events, err := globalSystem.QueryEvents(...); err != nil {
        ...
    }
}
```

**Needed Pattern (RIGHT):**
```go
// Middleware stack
authMiddleware(
    validationMiddleware(
        loggingMiddleware(
            handler
        )
    )
)
```

**Implementation Tasks:**
- [ ] Create `internal/middleware/` package
  - [ ] `auth.go` - JWT validation middleware
  - [ ] `logging.go` - Request/response logging
  - [ ] `validation.go` - Input validation
  - [ ] `errorhandler.go` - Centralized error handling
  - [ ] `ratelimit.go` - Rate limiting (Redis-backed or in-memory)
  - [ ] `cors.go` - CORS headers
  - [ ] `requestid.go` - Request ID tracking
- [ ] Wire middleware into server/aggregator main.go
- [ ] Update all handlers to use middleware
- [ ] Write middleware tests

**Effort:** Medium (2-3 days) | **Priority:** CRITICAL

---

### 3. ZERO SERVICE LAYER
**Problem:** Handlers call storage directly; no business logic abstraction

**Current Architecture (WRONG):**
```
Handler → Storage (Direct coupling)
```

**Needed Architecture (RIGHT):**
```
Handler → Middleware → Service → Repository → Storage
```

**What's Missing:**
- ❌ EventService interface
- ❌ QueryService interface
- ❌ ConnectionService interface
- ❌ Service implementations
- ❌ Dependency injection

**Implementation Tasks:**
- [ ] Create `internal/service/` package
  - [ ] `service.go` - Define Service interface
  - [ ] `event_service.go` - EventService implementation (~150 LOC)
  - [ ] `query_service.go` - QueryService implementation (~150 LOC)
  - [ ] `connection_service.go` - ConnectionService (~100 LOC)
- [ ] Update handlers to use services instead of globalSystem
- [ ] Implement dependency injection
- [ ] Add service tests (~500 LOC)

**Effort:** Medium (2-3 days) | **Priority:** CRITICAL

---

### 4. ZERO REPOSITORY PATTERN
**Problem:** Handlers call storage directly; no data access abstraction

**Current Implementation:**
```go
// In handlers.go
globalSystem.QueryEvents()  // ← Direct system call
```

**Needed Implementation:**
```go
// In handlers, via service
eventRepository.QueryEvents(filters)
```

**What's Missing:**
- ❌ EventRepository interface
- ❌ Memory repository implementation
- ❌ PostgreSQL repository implementation
- ❌ Repository factory pattern
- ❌ Query builder abstraction

**Implementation Tasks:**
- [ ] Create `internal/repository/` package
  - [ ] `repository.go` - Define Repository interface
  - [ ] `event_repository.go` - Interface definition
  - [ ] `memory_repository.go` - In-memory implementation (~150 LOC)
  - [ ] `postgres_repository.go` - PostgreSQL implementation (~200 LOC)
- [ ] Update services to use repositories
- [ ] Add factory pattern for repository creation
- [ ] Add repository tests (~400 LOC)

**Effort:** Medium (2-3 days) | **Priority:** CRITICAL

---

## HIGH-PRIORITY GAPS (Should Fix)

### 5. INCOMPLETE CACHING (Redis Declared, Not Used)
**Problem:** Documentation claims Redis, but code uses in-memory map

**Current Reality:**
```go
// internal/aggregator/aggregator.go line 125
programCache     *AggregatorProgramsResponse  // ← In-memory map, NOT Redis
programCacheTTL  time.Duration
programCacheMu   sync.RWMutex                 // ← Manual locking, not distributed
```

**What's Missing:**
- ❌ Redis client initialization
- ❌ Redis cache decorator pattern
- ❌ Cache TTL configuration
- ❌ Cache invalidation strategy
- ❌ Fallback to in-memory if Redis unavailable

**Implementation Tasks:**
- [ ] Create `internal/cache/` package
  - [ ] `cache.go` - Cache interface (memory + Redis)
  - [ ] `memory_cache.go` - In-memory implementation
  - [ ] `redis_cache.go` - Redis implementation (~150 LOC)
- [ ] Add Redis connection pooling in main.go
- [ ] Update aggregator to use cache interface
- [ ] Add cache configuration
- [ ] Write cache tests

**Effort:** Small (1-2 days) | **Priority:** HIGH

---

### 6. MISSING CONFIGURATION FILES
**Problem:** README references .env.example, API.md, ARCHITECTURE.md - none exist

**What's Missing:**
- ❌ `.env.example` - Configuration template
- ❌ `API.md` - Complete API endpoint documentation
- ❌ `ARCHITECTURE.md` - Component architecture overview
- ❌ `SETUP.md` - Deployment guide
- ❌ `init.sql` or database schema reference

**Current Reality:**
```
User reads README → sees "copy .env.example" → file doesn't exist → setup fails
```

**Implementation Tasks:**
- [ ] Create `.env.example` (30 lines)
  ```
  # Server Configuration
  SERVER_ADDR=:8080
  DB_URL=postgres://user:pass@localhost/monitoring
  LOG_LEVEL=info

  # Cache
  REDIS_URL=redis://localhost:6379
  CACHE_TTL=5m

  # Auth
  JWT_SECRET=your-secret-key
  JWT_EXPIRY=24h

  # K8s Aggregator (optional)
  AGGREGATOR_ADDR=:8081
  ```

- [ ] Create `docs/API.md` (~200 lines)
  - Full endpoint reference
  - Request/response examples
  - Filter syntax documentation
  - Error codes documentation

- [ ] Create `docs/ARCHITECTURE.md` (~300 lines)
  - Component diagram
  - Data flow explanation
  - Extension points
  - Security model

- [ ] Create `docs/SETUP.md` (~150 lines)
  - Installation steps
  - Configuration guide
  - Docker/K8s deployment
  - Troubleshooting

- [ ] Create `docs/DATABASE.md` (schema reference)
  - Table definitions
  - Indexes
  - Query performance tips

**Effort:** Small (1 day) | **Priority:** HIGH

---

### 7. TEST COVERAGE GAPS (Only Error Cases)
**Problem:** Tests only cover failure scenarios; no success path tests

**Current handlers_test.go (9,605 LOC):**
```go
func TestHandleHealthWithoutSystem(t *testing.T) {  // ✅ Tests null system
    globalSystem = nil
    // Only tests error case
}

// Missing:
// ❌ func TestHandleHealthWithSystem(t *testing.T) - success case
// ❌ func TestHandleEventsWithValidFilters(t *testing.T)
// ❌ func TestHandleEventsWithInvalidInput(t *testing.T)
```

**What's Missing:**
- ❌ Handler success path tests (80+ tests)
- ❌ Integration tests with real system
- ❌ Middleware tests
- ❌ Service tests
- ❌ Repository tests
- ❌ Error scenario tests

**Implementation Tasks:**
- [ ] Add success path handler tests (~500 LOC)
- [ ] Add middleware tests (~300 LOC)
- [ ] Add service tests (~400 LOC)
- [ ] Add repository tests (~400 LOC)
- [ ] Add integration tests (~300 LOC)
- [ ] Generate coverage report
- [ ] Update Makefile to report coverage percentage

**Current Coverage:** Unknown (coverage.out exists but not reported)
**Target Coverage:** 80%+

**Effort:** Medium (2-3 days) | **Priority:** HIGH

---

### 8. INCOMPLETE FLAG PARSING (server/main.go)
**Problem:** Server flag parsing incomplete; missing critical flags

**Current Implementation:**
```go
// cmd/server/main.go lines 20-25
var (
    httpAddr = flag.String("addr", ":8080", "HTTP server address")
    // ❌ Missing: dbURL
    // ❌ Missing: logLevel
    // ❌ Missing: configFile
    // ❌ Missing: jwtSecret
)
```

**Aggregator Does This Better:**
```go
// cmd/aggregator/main.go lines 24-31
var (
    httpAddr        = flag.String("addr", ":8081", "HTTP server address")
    dbURL           = flag.String("db-url", os.Getenv("DB_URL"), "PostgreSQL connection")
    flowCacheTTL    = flag.Duration("flow-cache-ttl", 5*time.Minute, "Flow cache TTL")
    disableEnricher = flag.Bool("disable-enricher", false, "Disable event enricher")
)
```

**Implementation Tasks:**
- [ ] Update server/main.go flag parsing to match aggregator pattern
- [ ] Add missing flags:
  - `--db-url` (PostgreSQL optional)
  - `--log-level` (info, debug, warn, error)
  - `--config-file` (optional config file path)
  - `--jwt-secret` (for token generation)
  - `--cache-ttl` (cache TTL)
- [ ] Read flags in proper order
- [ ] Add flag validation

**Effort:** Small (<1 day) | **Priority:** HIGH

---

## MEDIUM-PRIORITY GAPS (Nice to Have)

### 9. JWT ALGORITHM MISMATCH
**Problem:** Documentation claims RS256 (asymmetric), should verify implementation

**Current Code Status:** Unknown (no JWT code found in entire repo)

**What's Needed:**
- [ ] Choose RS256 (recommended, asymmetric) or HS256 (simpler, symmetric)
- [ ] Document choice in SETUP.md
- [ ] Implement token generation with chosen algorithm
- [ ] Document key management strategy

**Effort:** Small (<1 day) | **Priority:** MEDIUM

---

### 10. MISSING DOCKER CONFIGURATION REFERENCES
**Problem:** docker-compose.yml references init.sql and .env files that don't exist

**Current docker-compose.yml:**
```yaml
volumes:
  - ./init.sql:/docker-entrypoint-initdb.d/init.sql  # ❌ MISSING FILE
```

**What's Needed:**
- [ ] Update docker-compose.yml to not require init.sql (auto-migrations work)
- [ ] Create docker-compose.override.yml example with .env file
- [ ] Document PostgreSQL setup in SETUP.md
- [ ] Add database initialization steps

**Effort:** Small (<1 day) | **Priority:** MEDIUM

---

### 11. MAKEFILE IMPROVEMENTS
**Problem:** Makefile references missing targets and files

**Current Issues:**
```makefile
make migrate  # ❌ Target doesn't exist
make seed     # ❌ Target doesn't exist
docs:         # References missing API.md, ARCHITECTURE.md
```

**Implementation Tasks:**
- [ ] Remove non-existent targets or implement them
- [ ] Add `make test` with coverage reporting
- [ ] Add `make coverage-report` to generate HTML coverage
- [ ] Add `make lint` for code quality
- [ ] Add `make fmt` for code formatting
- [ ] Add `make docker-build` targets
- [ ] Document all targets in Makefile comments

**Effort:** Small (<1 day) | **Priority:** MEDIUM

---

### 12. INCOMPLETE DOCUMENTATION
**Problem:** README incomplete; CLAUDE.md exists but doesn't match reality

**Current Documentation:**
- ✅ README.md (basic)
- ✅ CLAUDE.md (development guidelines)
- ❌ API.md (missing)
- ❌ ARCHITECTURE.md (missing)
- ❌ SETUP.md (missing)
- ❌ DATABASE.md (missing)
- ✅ docs/swagger/ (auto-generated)

**Implementation Tasks:**
- [ ] Update README.md to match reality
- [ ] Create docs/API.md (endpoint reference)
- [ ] Create docs/ARCHITECTURE.md (component overview)
- [ ] Create docs/SETUP.md (deployment guide)
- [ ] Create docs/DATABASE.md (schema reference)
- [ ] Create docs/TROUBLESHOOTING.md (common issues)

**Effort:** Small (1 day) | **Priority:** MEDIUM

---

## REMEDIATION ROADMAP

### Phase 1: Foundation (Days 1-3)
**Goal:** Implement core missing layers

1. **Authentication Layer** (Day 1)
   - Create JWT middleware
   - Add token generation/validation
   - Wire into server/aggregator
   - Add basic auth tests

2. **Middleware Stack** (Day 1-2)
   - Implement logging middleware
   - Implement error handling middleware
   - Implement validation middleware
   - Wire all middleware into servers

3. **Configuration Files** (Day 2)
   - Create .env.example
   - Create docs/SETUP.md
   - Create docs/API.md
   - Update README.md

**Deliverables:**
- [ ] Working JWT authentication on all endpoints
- [ ] Middleware layer in place
- [ ] Configuration templates available
- [ ] Updated documentation

---

### Phase 2: Business Logic Layers (Days 3-5)
**Goal:** Implement service and repository patterns

1. **Service Layer** (Day 3-4)
   - Create EventService interface
   - Implement service methods
   - Update handlers to use services
   - Add service tests

2. **Repository Pattern** (Day 4-5)
   - Create EventRepository interface
   - Implement memory repository
   - Implement PostgreSQL repository
   - Update services to use repositories
   - Add repository tests

**Deliverables:**
- [ ] Service layer fully abstracted
- [ ] Repository pattern implemented
- [ ] Handlers simplified (just HTTP)
- [ ] Service/repository tests passing

---

### Phase 3: Enhancement (Days 5-7)
**Goal:** Complete remaining gaps

1. **Redis Caching** (Day 5-6)
   - Implement Redis cache
   - Add fallback to in-memory
   - Configure cache TTL
   - Add cache tests

2. **Enhanced Testing** (Day 6-7)
   - Add success path handler tests
   - Add integration tests
   - Generate coverage report
   - Document testing strategy

3. **Documentation** (Day 7)
   - Create ARCHITECTURE.md
   - Create DATABASE.md
   - Create TROUBLESHOOTING.md
   - Update all docs for accuracy

**Deliverables:**
- [ ] Redis caching working
- [ ] 80%+ test coverage
- [ ] Complete documentation
- [ ] All Makefile targets working

---

## VERIFICATION CHECKLIST

After implementation, verify:

### Authentication
- [ ] JWT tokens required for all protected endpoints
- [ ] Invalid tokens rejected with 401
- [ ] Expired tokens rejected with 401
- [ ] Token generation working (RS256)
- [ ] Auth middleware in place

### Middleware
- [ ] Logging middleware capturing all requests
- [ ] Error handling middleware converting panics to 500
- [ ] Validation middleware rejecting invalid input
- [ ] Rate limiting middleware enforcing limits
- [ ] Request ID tracking working

### Service Layer
- [ ] All business logic in services
- [ ] Handlers only handle HTTP
- [ ] Services testable in isolation
- [ ] No direct storage access from handlers

### Repository Pattern
- [ ] All storage access through repositories
- [ ] Memory repository working
- [ ] PostgreSQL repository working
- [ ] Repositories testable independently

### Testing
- [ ] Success path handler tests passing
- [ ] Error case tests passing
- [ ] Integration tests passing
- [ ] Coverage report showing 80%+
- [ ] `make test` runs all tests
- [ ] `make coverage-report` generates HTML

### Documentation
- [ ] .env.example exists and complete
- [ ] API.md documents all endpoints
- [ ] ARCHITECTURE.md explains components
- [ ] SETUP.md covers deployment
- [ ] DATABASE.md references schema
- [ ] All links work
- [ ] No dead documentation

### Makefile
- [ ] `make build` works
- [ ] `make test` runs all tests
- [ ] `make coverage-report` shows coverage
- [ ] `make docs` builds documentation
- [ ] `make lint` checks code quality
- [ ] `make fmt` formats code
- [ ] `make clean` removes artifacts

---

## EFFORT ESTIMATES

| Gap | Effort | Priority | Days |
|-----|--------|----------|------|
| Authentication Layer | Medium | CRITICAL | 1 |
| Middleware Stack | Medium | CRITICAL | 2 |
| Service Layer | Medium | CRITICAL | 2 |
| Repository Pattern | Medium | CRITICAL | 2 |
| Configuration Files | Small | HIGH | 1 |
| Test Enhancements | Medium | HIGH | 2 |
| Redis Caching | Small | HIGH | 1 |
| Flag Parsing | Small | HIGH | 0.5 |
| Documentation | Small | MEDIUM | 1 |
| JWT Algorithm | Small | MEDIUM | 0.5 |
| Makefile | Small | MEDIUM | 0.5 |
| Docker Fixes | Small | MEDIUM | 0.5 |

**Total Effort: 13.5 days** (2-3 weeks with testing)

---

## IMPLEMENTATION NOTES

1. **Start with Authentication**
   - Guards all other improvements
   - Enables testing of protected endpoints
   - Foundation for middleware

2. **Parallel Efforts**
   - Config files while implementing auth
   - Documentation while coding
   - Tests alongside implementation

3. **Testing Strategy**
   - Write tests as you implement
   - Test both success and error paths
   - Use table-driven tests for multiple scenarios
   - Aim for 80%+ coverage

4. **Documentation Strategy**
   - Write docs before implementing (TDD-style)
   - Keep docs in sync with code
   - Generate API docs from handlers
   - Link all docs from README

5. **Backward Compatibility**
   - All changes should be backward compatible
   - Old endpoints should still work
   - Configuration should have sensible defaults
   - Migrations should be reversible

---

## REFERENCES

- Current handlers: `internal/api/handlers.go` (607 LOC)
- Current aggregator: `internal/aggregator/aggregator.go` (1,125 LOC)
- Server main: `cmd/server/main.go` (146 LOC)
- Aggregator main: `cmd/aggregator/main.go` (177 LOC)
- Existing tests: `internal/api/handlers_test.go` (9,605 LOC)

---

**Document Version:** 1.0
**Created:** February 7, 2026
**Status:** Ready for Implementation
**Next Step:** Create implementation plan per phase
