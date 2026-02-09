# Quick Reference Guide - eBPF Network Monitor

## Version 2.0 - With Authentication & Service Layer

> **Updated**: February 2025
> **Status**: Phase 1-2 Implementation Complete
> **Features**: JWT Auth, Service Layer, Repository Pattern, Multi-NIC Ready

---

## Multi-NIC & Multi-Program Support - Quick Reference

## The Answer to Your Question

### "Can we save data from multiple network cards (multiple eBPF)?"

```
Current State                    With New Database
─────────────────               ──────────────────
eBPF: 2 programs ✅             eBPF: 2+ programs ✅
├─ connection                   ├─ connection      (stored)
└─ packet_drop                  ├─ packet_drop     (stored)
                                └─ future programs (auto-supported)

Network Interfaces              Network Interfaces
├─ eth0 (no tags)               ├─ eth0 (interface_name field)
├─ eth1 (no tags)               ├─ eth1 (interface_name field)
└─ wlan0 (no tags)              └─ wlan0 (interface_name field)

Storage: Memory ❌              Storage: PostgreSQL ✅
(lost on restart)               (persistent)
```

---

## Multi-NIC Timeline

### Phase 1A: Database (NOW - 2-3 days)
✅ **Ready to implement immediately**
- Schema includes interface fields
- Indexes optimized for multi-NIC
- Backward compatible (interface fields are NULL)

### Phase 1B: Kernel Capture (FUTURE - 2-3 weeks)
⏳ **When you're ready to enhance eBPF programs**
- Modify eBPF programs to capture interface name/index
- Populate interface_name and interface_index fields
- Query interface data immediately (indexes ready)

### Phase 1C: Analysis (FUTURE)
✨ **Analyze multi-NIC traffic patterns**
- Traffic per interface
- Interface comparison
- Per-process-per-interface analysis

---

## Multi-Program Support TODAY

### Already Working (No Changes Needed)

```go
// Programs Manager automatically handles all programs

// Program 1: Connection Tracer
manager.RegisterProgram(connection.NewProgram())
// ↓ Stores: event_type="connection", program_name="connection_tracer"

// Program 2: Packet Drop Monitor
manager.RegisterProgram(packet_drop.NewProgram())
// ↓ Stores: event_type="packet_drop", program_name="packet_drop_monitor"

// Program N: Your New Program (add anytime)
manager.RegisterProgram(your_program.NewProgram())
// ↓ Stores: event_type="...", program_name="..."
// Database automatically supports it!
```

### Adding New Programs (One Line!)

```go
// File: internal/system/system.go (around line 55)
s.manager.RegisterProgram(my_new_program.NewProgram())  // That's it!
```

---

## Database Schema - Multi-NIC Fields

### Interface Identification (Ready Now, Used Later)

```sql
CREATE TABLE ebpf_events (
    -- NEW: Multi-NIC fields
    interface_name TEXT,              -- "eth0", "eth1" (NULL now)
    interface_index INT,              -- Linux index (NULL now)
    program_name TEXT NOT NULL,       -- "connection_tracer", etc.

    -- Existing fields (unchanged)
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    pid BIGINT NOT NULL,
    command TEXT NOT NULL,
    src_ip INET, dst_ip INET,
    src_port INT, dst_port INT,
    protocol TEXT,
    -- ... more fields ...

    -- NEW: Multi-NIC Optimized Indexes
    INDEX idx_ebpf_interface (interface_name, observed_at DESC),
    INDEX idx_ebpf_interface_time (interface_name, observed_at DESC, event_type),
    INDEX idx_ebpf_interface_pid (interface_name, pid, observed_at DESC),
    -- ... more indexes ...
);
```

---

## Query Examples

### Today (Works Now)

```sql
-- All connections
SELECT * FROM ebpf_events WHERE event_type = 'connection';

-- By process
SELECT * FROM ebpf_events WHERE pid = 123;

-- By program
SELECT * FROM ebpf_events WHERE program_name = 'connection_tracer';
```

### Tomorrow (When Interface Capture Ready)

```sql
-- Traffic per interface
SELECT interface_name, COUNT(*) as events
FROM ebpf_events
WHERE observed_at >= now() - interval '24 hours'
GROUP BY interface_name;

-- Compare interfaces
SELECT interface_name, protocol, COUNT(*) as connections
FROM ebpf_events
WHERE event_type = 'connection'
GROUP BY interface_name, protocol;

-- Per-interface drops
SELECT interface_name, drop_reason, SUM(dropped_count)
FROM ebpf_events
WHERE event_type = 'packet_drop'
GROUP BY interface_name, drop_reason;
```

---

## Implementation Roadmap

### Phase 1: Database & Storage (2-3 days)
- [ ] Create `ebpf_events` table with multi-NIC fields
- [ ] Create 20+ optimized indexes
- [ ] Implement eBPF storage in PostgreSQL
- [ ] Add comprehensive tests

### Phase 2: Aggregator Integration (1-2 days)
- [ ] Route eBPF events to PostgreSQL
- [ ] Update API endpoints
- [ ] Add interface query parameters

### Phase 3: Documentation (1 day)
- [ ] Update docs with examples
- [ ] Create SQL query library
- [ ] Document interface field strategy

### Phase 4: Future - Kernel Capture (When Ready)
- [ ] Modify eBPF programs for interface capture
- [ ] Populate interface_name and interface_index
- [ ] Start analyzing multi-NIC traffic

---

## Key Features

### Multi-Program Support ✅
- Connection Tracer (running now)
- Packet Drop Monitor (running now)
- File Operations (easy to add)
- Process Exec Tracer (easy to add)
- Custom Programs (framework ready)

**Benefit**: Add new eBPF programs anytime with one line of code

### Multi-NIC Support ⏳ (Ready to Enable)
- Interface fields in database (now)
- Indexes for interface queries (now)
- Kernel capture capability (later)
- Multi-interface analysis (later)

**Benefit**: When ready, just populate interface fields and queries work

### Backward Compatibility ✅
- All existing queries still work
- Interface fields are NULL (safe)
- No schema changes when enabled
- Zero breaking changes

---

## Decision Matrix

| Question | Answer | Effort |
|----------|--------|--------|
| Can database handle multiple NICs? | YES ✅ | NOW |
| Can database handle multiple eBPF programs? | YES ✅ | NOW |
| Can we store eBPF data persistently? | YES ✅ | 2-3 days |
| Can we add new eBPF programs easily? | YES ✅ | 1 line |
| Can we query traffic per interface? | YES (later) | Phase 1B |
| Does it require breaking changes? | NO ✅ | - |

---

## Start Implementation?

### Option A: Full Implementation (Recommended)
**Effort**: 4-6 days
**Benefit**: Complete persistent eBPF storage with multi-NIC foundation

### Option B: Core Only (Skip Optional Views)
**Effort**: 2-3 days
**Benefit**: Core storage + queries, add views later

### Option C: Minimal (Storage Only)
**Effort**: 1-2 days
**Benefit**: Basic persistence, no optimization yet

---

## Documents Created

1. **`ebpf-database-storage.md`** (Main Plan - 500+ lines)
   - Complete implementation details
   - Schema design
   - Migration strategy
   - SQL query examples

2. **`MULTI_NIC_READINESS.md`** (Analysis - 600+ lines)
   - Current state assessment
   - Multi-NIC roadmap
   - Multi-program explanation
   - Phase-by-phase breakdown

3. **`QUICK_REFERENCE.md`** (This Document)
   - Quick overview
   - Key features summary
   - Decision matrix

---

---

## Phase 1-2: Authentication & Service Layer

### What's New (February 2025)

#### Authentication (Phase 1)
- **JWT Tokens**: Access token (24h) + Refresh token (7 days)
- **Authentication Endpoints**:
  - `POST /api/auth/login` - Request tokens with username/password
  - `POST /api/auth/refresh` - Refresh expired access token
- **Protected Routes**: All API endpoints except `/health` require Bearer token

#### Service Layer (Phase 2)
- **Clean Abstraction**: Business logic separated from HTTP handlers
- **Service Interfaces**: ProgramService, EventService, HealthService
- **Repository Pattern**: EventRepository for pluggable data storage
- **Dependency Injection**: ServiceFactory for service composition

### Getting Started with Authentication

#### 1. Login and Get Tokens
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"password"}'

# Response:
# {
#   "access_token": "eyJhbGc...",
#   "refresh_token": "eyJhbGc...",
#   "token_type": "Bearer",
#   "expires_at": "2025-02-10T07:47:00Z"
# }
```

#### 2. Use Access Token in Requests
```bash
curl -X GET http://localhost:8080/api/programs \
  -H "Authorization: Bearer <access_token>"
```

#### 3. Refresh Token When Expired
```bash
curl -X POST http://localhost:8080/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<refresh_token>"}'
```

### Service Architecture

```
┌─────────────────────────────────────────────┐
│  HTTP Handlers (REST API)                   │
├─────────────────────────────────────────────┤
│  Service Layer (Business Logic)             │
│  ├─ ProgramService                          │
│  ├─ EventService                            │
│  └─ HealthService                           │
├─────────────────────────────────────────────┤
│  Repository Layer (Data Access)             │
│  └─ EventRepository (interface)             │
│     └─ MemoryEventRepository (impl)         │
├─────────────────────────────────────────────┤
│  System (Core Monitoring)                   │
│  ├─ Program Manager                         │
│  ├─ Event Processing                        │
│  └─ Health Checks                           │
└─────────────────────────────────────────────┘
```

### Key Components

| Component | Type | Purpose | Status |
|-----------|------|---------|--------|
| JWT Tokens | Auth | Secure API access | ✅ Implemented |
| AuthMiddleware | Middleware | Token validation | ✅ Implemented |
| ServiceFactory | Pattern | Service composition | ✅ Implemented |
| EventRepository | Interface | Data access abstraction | ✅ Implemented |
| MemoryEventRepository | Implementation | Development storage | ✅ Implemented |

---

## Status

✅ **Analysis Complete**
✅ **Database Design Complete**
✅ **Multi-NIC Strategy Defined**
✅ **Implementation Ready**
✅ **Phase 1 Complete** - JWT Authentication + Middleware
✅ **Phase 2 Complete** - Service Layer + Repository Pattern

**Next Action**: See API_REST.md for endpoint details and usage examples
