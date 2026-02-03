# Plan: eBPF Event Storage in PostgreSQL Database

**Date**: February 2, 2026
**Status**: DRAFT
**Version**: 1.0

---

## Overview

The monitoring application currently has **two separate storage paths**:
1. **L7 Events** (from Vaanvil webhooks) → Stored in PostgreSQL via `l7_events` table
2. **eBPF Events** (from kernel monitoring) → Currently stored only in memory

**Objective**: Add persistent PostgreSQL storage for eBPF events (connections, packet drops, etc.) to enable historical analysis, compliance reporting, and forensic investigations.

---

## Current Architecture

### Storage Paths

```
┌─────────────────────────────────────┐
│  Vaanvil Sensors (Webhooks)         │
│  - L7 events (domain/IP blocking)   │
└────────────┬────────────────────────┘
             │
             ↓ PostgreSQLStorage.Store()
        l7_events table (1,714 lines SQL schema)

┌─────────────────────────────────────┐
│  eBPF Agents (from Kernel)          │
│  - Connections                      │
│  - Packet drops                     │
│  - Process execution (future)       │
└────────────┬────────────────────────┘
             │
             ↓ MemoryStorage.Store()
        In-memory buffer (lost on restart)
```

### eBPF Event Types Currently Collected

1. **Connection Events**
   - TCP/UDP connections (5-tuple: src IP, src port, dst IP, dst port, protocol)
   - Process ID, command name
   - Connection state (established, closed, etc.)

2. **Packet Drop Events**
   - Dropped packets (reason, packet count)
   - Source/destination IPs and ports
   - Protocol and related metadata

3. **Potential Future Events**
   - Process execution (fork/exec)
   - File operations (open/read/write/close)
   - Network security events
   - System calls

### Core Event Interface

All events (L7 + eBPF) implement `core.Event`:

```go
type Event interface {
    ID() string                                    // Unique identifier
    Type() string                                  // "l7_flow_update", "connection", "packet_drop"
    PID() uint32                                   // Process ID
    Command() string                               // Command name
    Timestamp() uint64                             // Kernel timestamp (ns since boot)
    Time() time.Time                               // Wall-clock time
    Metadata() map[string]interface{}              // Event-specific data (flexible)
    MarshalJSON() ([]byte, error)                  // JSON serialization
}
```

### Aggregator Architecture

```
cmd/aggregator/main.go
    ↓
internal/aggregator/aggregator.go
    ├─ HandleEvents()           ← API endpoint for querying events
    ├─ HandleIngest()           ← API endpoint for ingesting events
    ├─ HandleListConnections()  ← Specific eBPF query endpoint
    └─ HandleListPacketDrops()  ← Specific eBPF query endpoint
```

**Current Flow**:
1. eBPF agents send events via `/api/events/ingest` endpoint
2. Aggregator stores in memory (no persistence)
3. Queries retrieve from memory only

---

## Problem Statement

### Issues with Current Design

1. **Data Loss on Restart**: All eBPF events lost when aggregator restarts
2. **No Historical Analysis**: Can't analyze trends over hours/days
3. **No Compliance**: Can't maintain audit trail for security compliance
4. **Limited Scalability**: In-memory storage limited by available RAM
5. **No Forensics**: Can't investigate past security incidents
6. **Duplicate Code**: Separate storage implementation for L7 vs eBPF

---

## Proposed Solution

### High-Level Approach

**Create unified storage layer** supporting both L7 and eBPF events:

```
┌──────────────────────────┐
│  Aggregator              │
├──────────────────────────┤
│ /api/events/ingest       │
│ /api/events              │ ← Unified API
│ /api/stats               │
└────────┬─────────────────┘
         │
    ┌────┴────────────────────────────────┐
    │   Configurable Storage Selector     │
    │   (based on event type)             │
    └────┬───────────────────┬────────────┘
         │                   │
    ┌────▼─────────┐   ┌────▼──────────┐
    │ PostgreSQL   │   │ Memory        │
    │ Storage      │   │ Storage       │
    │ (L7 + eBPF)  │   │ (optional)    │
    └──────────────┘   └───────────────┘
```

### Implementation Strategy

#### Phase 1: Unified eBPF Storage Schema (This Plan)

Create `ebpf_events` table in PostgreSQL with:
- Connection events (TCP/UDP 5-tuple)
- Packet drop events
- Flexible metadata for future event types
- Proper indexing for common queries

#### Phase 2: Aggregator Integration

Modify `cmd/aggregator/main.go` to:
- Use PostgreSQLStorage for all events (when DB_URL set)
- Fall back to MemoryStorage if no DB_URL
- Route both L7 and eBPF events through same storage

#### Phase 3: Query Layer Updates

Enhance query capabilities:
- Add eBPF-specific query endpoints
- Support time-range queries (already works via L7)
- Add connection/packet drop aggregation queries

#### Phase 4: Documentation & Examples

- Add eBPF storage section to `docs/USAGE.md`
- Provide SQL query examples
- Document migration path from memory to PostgreSQL

---

## Multi-NIC Support Strategy

### Current State Analysis

**Key Findings**:
- ✅ **Multi-program support**: YES - System can run unlimited eBPF programs simultaneously
- ❌ **Multi-NIC support**: NO - Currently not implemented
- ❌ **Interface identification**: NO - Events don't include interface information

**Why Multi-NIC Matters**:
- Modern servers have multiple NICs (eth0, eth1, wlan0, etc.)
- Different interfaces may handle different traffic flows
- Security analysis requires knowing WHICH interface was used
- Compliance requires per-interface audit trails
- Different interfaces may have different policies

### Multi-NIC Phased Approach

#### Phase 1A: Database Ready (This Plan)
- ✅ Schema includes `interface_name` and `interface_index` fields
- ✅ Indexes optimized for multi-NIC queries
- ✅ NULL tolerant (works today, ready for tomorrow)
- ✅ Extensible metadata for future interface info

**Current Implementation**: Interface fields will be NULL (no capture yet)

#### Phase 1B: Kernel-Level Capture (Future)
When eBPF programs are enhanced to capture interface info:
- Switch from syscall-level hooks to network-layer hooks
- Use XDP (eXpress Data Path) or TC (Traffic Control) programs
- Capture net_device pointer from kernel structures
- Extract interface name/index at packet level

#### Phase 1C: Interface Metadata Enrichment (Future)
- Update event parsers to populate interface fields
- Map interface names to speeds, MTU, carrier status
- Store interface statistics alongside events

### How to Enable Multi-NIC in Future

When you're ready to capture interface data, you'll:

1. **Modify eBPF programs** (`bpf/connection.c`, `bpf/packet_drop.c`):
   ```c
   // Add to event struct
   struct event_t {
       // ... existing fields ...
       u8 ifname[16];          // Interface name (eth0, etc.)
       u32 ifindex;            // Interface index
       // ... rest ...
   } __attribute__((packed));
   ```

2. **Update event parsers** (`connection.go`, `packet_drop.go`):
   ```go
   // Extract interface from event
   interfaceName := strings.TrimRight(string(event.ifname[:]), "\x00")
   ```

3. **Populate database fields**:
   ```go
   // When storing event
   interfaceName: interfaceName,
   interfaceIndex: event.ifindex,
   ```

4. **Query by interface**:
   ```sql
   SELECT * FROM ebpf_events
   WHERE interface_name = 'eth0'
     AND observed_at >= now() - interval '24 hours'
   ```

---

## Detailed Design

### 1. PostgreSQL Schema for eBPF Events

**New Table: `ebpf_events`** (1,800+ lines - Multi-NIC Ready)

```sql
CREATE TABLE ebpf_events (
    -- Event identification
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,           -- "connection", "packet_drop", etc.
    program_name TEXT NOT NULL,         -- "connection_tracer", "packet_drop_monitor"
    created_at TIMESTAMP DEFAULT NOW(),
    observed_at TIMESTAMP NOT NULL,     -- When event occurred (wall-clock time)

    -- MULTI-NIC SUPPORT: Interface identification
    interface_name TEXT,                 -- "eth0", "eth1", "wlan0", etc. (indexed, nullable for now)
    interface_index INT,                 -- Linux interface index (indexed, nullable)

    -- Process information
    pid BIGINT NOT NULL,
    command TEXT NOT NULL,

    -- Kubernetes/Container metadata
    k8s_node_name TEXT,                  -- Kubernetes node (indexed if available)
    k8s_pod_name TEXT,                   -- Pod name (indexed if available)
    k8s_namespace TEXT,                  -- Namespace (indexed if available)

    -- Network information (5-tuple for flows)
    src_ip INET,                         -- Source IP (indexed)
    dst_ip INET,                         -- Destination IP (indexed)
    src_port INT,                        -- Source port
    dst_port INT,                        -- Destination port
    protocol TEXT,                       -- "tcp", "udp", "proto-N"
    ip_version INT,                      -- 4 or 6
    address_family INT,                  -- AF_INET (2) or AF_INET6 (10)

    -- Connection-specific fields
    connection_state TEXT,               -- "established", "closed", "syn_sent", etc.
    socket_type TEXT,                    -- "STREAM", "DGRAM", etc.
    bytes_sent BIGINT,                   -- Bytes sent in connection
    bytes_received BIGINT,               -- Bytes received in connection
    duration_ms FLOAT,                   -- Connection duration in milliseconds
    return_code INT,                     -- System call return code

    -- Packet drop-specific fields
    drop_reason TEXT,                    -- Why packets were dropped
    dropped_count INT,                   -- Number of packets dropped
    drop_code INT,                       -- Drop reason code

    -- Flexible metadata (JSONB for extensibility)
    -- Can store: custom fields, debugging info, future event types
    metadata JSONB DEFAULT '{}',

    -- MULTI-NIC OPTIMIZED INDEXES
    -- Filter by interface
    INDEX idx_ebpf_interface (interface_name, observed_at DESC),
    INDEX idx_ebpf_interface_idx (interface_index, observed_at DESC),

    -- Filter by program
    INDEX idx_ebpf_program (program_name, observed_at DESC),

    -- Filter by event type
    INDEX idx_ebpf_event_type (event_type, observed_at DESC),

    -- Network analysis
    INDEX idx_ebpf_src_dst (src_ip, dst_ip, interface_name),
    INDEX idx_ebpf_src_ip (src_ip, observed_at DESC),
    INDEX idx_ebpf_dst_ip (dst_ip, observed_at DESC),

    -- Process analysis
    INDEX idx_ebpf_pid (pid, observed_at DESC),
    INDEX idx_ebpf_command (command, observed_at DESC),

    -- Time-based queries
    INDEX idx_ebpf_time (observed_at DESC),

    -- Kubernetes queries (if metadata available)
    INDEX idx_ebpf_k8s_pod (k8s_namespace, k8s_pod_name, observed_at DESC),
    INDEX idx_ebpf_k8s_node (k8s_node_name, observed_at DESC),

    -- Protocol and flow analysis
    INDEX idx_ebpf_protocol (protocol, observed_at DESC),

    -- Flexible metadata queries
    INDEX idx_ebpf_metadata USING GIN (metadata),

    -- Composite indexes for common queries
    INDEX idx_ebpf_interface_time (interface_name, observed_at DESC, event_type),
    INDEX idx_ebpf_interface_pid (interface_name, pid, observed_at DESC),
);

-- OPTIONAL: View for multi-NIC statistics
CREATE VIEW ebpf_interface_stats AS
SELECT
    interface_name,
    event_type,
    COUNT(*) as event_count,
    COUNT(DISTINCT pid) as unique_processes,
    COUNT(DISTINCT dst_ip) as unique_destinations,
    SUM(COALESCE(dropped_count, 0)) as total_dropped,
    SUM(COALESCE(bytes_sent + bytes_received, 0)) as total_bytes,
    MIN(observed_at) as first_event,
    MAX(observed_at) as last_event
FROM ebpf_events
WHERE interface_name IS NOT NULL
GROUP BY interface_name, event_type;
```

### Multi-Program Support

The eBPF system already supports multiple programs running simultaneously:

**Programs Currently Implemented**:
1. **Connection Tracer** - Monitors TCP/UDP connections
2. **Packet Drop Monitor** - Tracks dropped packets

**How It Works**:
- Each program has its own eBPF code and event stream
- `ProgramManager` (internal/programs/manager.go) orchestrates all programs
- `MergedStream` combines events from all programs into single channel
- Events are tagged with `program_name` field for identification

**Database Impact**:
- New field: `program_name` - identifies which program generated event
- Index on `program_name` for filtering
- Allows mixed queries across programs

**Future Programs** (Easy to Add):
- File operations monitor
- Process execution tracer
- System call monitor
- Memory access monitor
- DNS monitor
- etc.

**Adding New Programs** (when ready):
```go
// internal/system/system.go
// Current: Lines 45-56

// Add your new program here:
fileProgram := file_ops.NewProgram()
s.manager.RegisterProgram(fileProgram)
```

The database schema automatically supports it via `program_name` field.

### 2. Storage Implementation

**File: `internal/storage/ebpf_storage.go`** (new)

Extend PostgreSQLStorage to handle both L7 and eBPF events:

```go
// ANCHOR: eBPF Event Storage - Feb 2, 2026
// WHY: Persist kernel-level monitoring data (connections, packet drops)
// WHAT: Store eBPF events in unified PostgreSQL backend
// HOW: Use existing pgx connection pool, map event types to tables

type PostgreSQLStorage struct {
    pool *pgxpool.Pool
    // ... existing L7 fields ...
}

func (s *PostgreSQLStorage) Store(ctx context.Context, event core.Event) error {
    switch event.Type() {
    case "l7_flow_update", "l7_flow_end":
        return s.storeL7Event(ctx, event)
    case "connection", "connection_closed":
        return s.storeEBPFConnection(ctx, event)
    case "packet_drop":
        return s.storeEBPFPacketDrop(ctx, event)
    default:
        return s.storeGenericEvent(ctx, event)
    }
}

func (s *PostgreSQLStorage) storeEBPFConnection(ctx context.Context, event core.Event) error {
    // Parse event metadata
    // Extract 5-tuple, process info
    // Insert into ebpf_events table
    // Handle errors appropriately
}

func (s *PostgreSQLStorage) storeEBPFPacketDrop(ctx context.Context, event core.Event) error {
    // Similar pattern for packet drops
}

func (s *PostgreSQLStorage) storeGenericEvent(ctx context.Context, event core.Event) error {
    // Future extensibility for new event types
}
```

### 3. Migration/Schema Management

**File: `internal/storage/migrations.go`** (update existing)

Add eBPF schema to migration:

```go
func RunMigrations(ctx context.Context, conn *pgconn.PgConn) error {
    // ... existing L7 migrations ...

    // Create ebpf_events table
    if err := createEBPFEventsTable(ctx, conn); err != nil {
        return err
    }

    // Create eBPF indexes
    // Create eBPF views (optional)

    return nil
}

func createEBPFEventsTable(ctx context.Context, conn *pgconn.PgConn) error {
    // SQL from schema above
}
```

### 4. Query Helpers

**File: `internal/storage/ebpf_queries.go`** (new)

Add convenience methods for eBPF-specific queries:

```go
// QueryConnections retrieves connection events
func (s *PostgreSQLStorage) QueryConnections(ctx context.Context, srcIP, dstIP string, since, until time.Time) ([]core.Event, error) {
    // WHERE event_type = 'connection' AND ...
}

// QueryPacketDrops retrieves packet drop events
func (s *PostgreSQLStorage) QueryPacketDrops(ctx context.Context, srcIP string, since, until time.Time) ([]core.Event, error) {
    // WHERE event_type = 'packet_drop' AND ...
}

// QueryByPID retrieves all events for a process
func (s *PostgreSQLStorage) QueryByPID(ctx context.Context, pid uint32, since, until time.Time) ([]core.Event, error) {
    // WHERE pid = ? AND observed_at BETWEEN ...
}

// ConnectionStats returns aggregated connection statistics
func (s *PostgreSQLStorage) ConnectionStats(ctx context.Context, since, until time.Time) (map[string]interface{}, error) {
    // Aggregation query: count by protocol, top IPs, etc.
}
```

### 5. Aggregator Integration

**File: `cmd/aggregator/main.go`** (update)

```go
func main() {
    // ... existing code ...

    // ANCHOR: Unified eBPF + L7 Storage - Feb 2, 2026
    // WHY: Enable persistent storage of all event types
    // WHAT: Initialize PostgreSQLStorage for both eBPF and L7 events
    // HOW: Create schema on first connection, use unified interface

    if *dbURL != "" {
        pgStorage, err := storage.NewPostgreSQLStorage(ctx, *dbURL)
        if err != nil {
            logger.Fatalf("Failed to initialize PostgreSQL storage: %v", err)
        }
        defer pgStorage.Close()

        // Now PostgreSQLStorage handles BOTH L7 and eBPF events
        // Previously only L7 was stored

        agg.SetStorage(pgStorage)  // NEW: Set storage for eBPF events too
    }
}
```

### 6. API Endpoint Updates

**File: `internal/aggregator/aggregator.go`** (update)

```go
func (a *Aggregator) HandleEvents(w http.ResponseWriter, r *http.Request) {
    // Retrieve from unified storage (PostgreSQL if available)
    // Support filtering by:
    // - event_type: "connection", "packet_drop", "l7_flow_update"
    // - src_ip, dst_ip, protocol
    // - pid, command
    // - time range (since, until)
}

func (a *Aggregator) HandleListConnections(w http.ResponseWriter, r *http.Request) {
    // Call QueryConnections() from storage
    // Return filtered connection events
}

func (a *Aggregator) HandleListPacketDrops(w http.ResponseWriter, r *http.Request) {
    // Call QueryPacketDrops() from storage
    // Return filtered packet drop events
}
```

---

## Implementation Phases

### Phase 1: Schema & Storage (This Plan)

**Files to Create**:
1. Update `internal/storage/migrations.go` - Add eBPF schema
2. Create `internal/storage/ebpf_storage.go` - eBPF storage methods
3. Create `internal/storage/ebpf_queries.go` - Query helpers
4. Create `internal/storage/ebpf_storage_test.go` - Test coverage

**Files to Modify**:
1. `internal/storage/postgres.go` - Add event type routing
2. `cmd/aggregator/main.go` - Set storage for eBPF events
3. `internal/aggregator/aggregator.go` - Use unified storage

**Estimated Effort**: 2-3 days
- Schema design: 2-3 hours
- Storage implementation: 6-8 hours
- Query helpers: 4-5 hours
- Testing: 4-5 hours
- Documentation: 2-3 hours

### Phase 2: Aggregator Integration

**Updates to existing files**:
1. Route eBPF events through PostgreSQL
2. Update API endpoints to use unified storage
3. Add eBPF-specific query parameters

**Estimated Effort**: 1-2 days

### Phase 3: Documentation

**Files to Create/Update**:
1. Update `docs/USAGE.md` - Add eBPF storage section
2. Create SQL query examples for eBPF analysis
3. Migration guide from memory to PostgreSQL

**Estimated Effort**: 1 day

---

## Benefits

### Immediate
- ✅ eBPF events survive application restarts
- ✅ 90-day historical retention possible
- ✅ Forensic investigation capability
- ✅ Compliance audit trails

### Long-Term
- ✅ Unified query API for all events
- ✅ Foundation for advanced analytics
- ✅ Integration with SIEM systems
- ✅ Scalability to enterprise scale
- ✅ Multi-tenant deployments

---

## Backward Compatibility

**Zero Breaking Changes**:
- Existing L7 storage unchanged
- Existing API endpoints continue working
- Memory storage still available (if no DB_URL)
- Can switch between memory/PostgreSQL at runtime

**Migration Path**:
```
Current State                  Proposed State
─────────────                  ──────────────
MemoryStorage                  PostgreSQLStorage
├─ L7 events (lost)      →     ├─ L7 events (persistent)
└─ eBPF events (lost)         ├─ eBPF events (NEW - persistent)
                               └─ Automatic schema creation
```

---

## Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|-----------|
| Database connection failures | Low | High | Connection pooling, graceful degradation to memory |
| Performance regression | Low | Medium | Index optimization, query profiling |
| Data migration issues | Low | High | Dry-run on test database first |
| Storage capacity | Low | Medium | TimescaleDB compression, retention policies |

---

## Testing Strategy

### Unit Tests
- Test event storage for all types
- Test query filtering
- Test error handling

### Integration Tests
- Docker PostgreSQL container
- Full event ingestion → storage → query cycle
- Memory vs. PostgreSQL comparison

### Performance Tests
- Ingest rate: 10k events/sec
- Query latency: < 100ms for 24-hour range
- Connection pooling under load

---

## Acceptance Criteria

- ✅ eBPF events stored in PostgreSQL when DB_URL set
- ✅ All existing tests pass
- ✅ 3 new test cases for eBPF storage
- ✅ Documentation updated with eBPF examples
- ✅ SQL queries provided for common analysis tasks
- ✅ Backward compatibility maintained
- ✅ Zero breaking changes to API

---

## Next Steps

1. **Approval**: Confirm approach with stakeholders
2. **Design Review**: Get feedback on schema design
3. **Implementation**: Start Phase 1
4. **Testing**: Comprehensive test coverage
5. **Documentation**: Update USAGE.md
6. **Deployment**: Production rollout plan

---

## Appendix: Example SQL Queries

### Query 1: Top Connection Destinations (Last 24 Hours)

```sql
SELECT
    dst_ip,
    protocol,
    COUNT(*) as connection_count,
    SUM(bytes_sent) as total_bytes_sent,
    SUM(bytes_received) as total_bytes_received
FROM ebpf_events
WHERE event_type = 'connection'
    AND observed_at >= now() - interval '24 hours'
GROUP BY dst_ip, protocol
ORDER BY total_bytes_received DESC
LIMIT 50;
```

### Query 2: Packet Drops by Reason

```sql
SELECT
    drop_reason,
    COUNT(*) as drop_count,
    SUM(dropped_count) as total_packets_dropped,
    COUNT(DISTINCT pid) as unique_processes
FROM ebpf_events
WHERE event_type = 'packet_drop'
    AND observed_at >= now() - interval '7 days'
GROUP BY drop_reason
ORDER BY total_packets_dropped DESC;
```

### Query 3: Process Network Activity

```sql
SELECT
    pid,
    command,
    COUNT(*) as connection_count,
    SUM(bytes_sent) as total_sent,
    SUM(bytes_received) as total_received,
    COUNT(DISTINCT dst_ip) as unique_destinations
FROM ebpf_events
WHERE event_type = 'connection'
    AND observed_at >= now() - interval '1 day'
GROUP BY pid, command
ORDER BY total_received DESC
LIMIT 20;
```

### Query 4: MULTI-NIC - Traffic by Interface (Ready for Future Implementation)

```sql
-- When interface_name is populated from eBPF
SELECT
    interface_name,
    protocol,
    COUNT(*) as connections,
    SUM(bytes_sent + bytes_received) as total_bytes,
    COUNT(DISTINCT pid) as unique_processes,
    COUNT(DISTINCT dst_ip) as unique_destinations
FROM ebpf_events
WHERE event_type = 'connection'
    AND observed_at >= now() - interval '24 hours'
    AND interface_name IS NOT NULL
GROUP BY interface_name, protocol
ORDER BY total_bytes DESC;
```

### Query 5: MULTI-NIC - Per-Interface Packet Drops

```sql
-- Monitor packet drops per interface
SELECT
    interface_name,
    drop_reason,
    COUNT(*) as drop_count,
    SUM(dropped_count) as total_dropped,
    COUNT(DISTINCT pid) as affected_processes
FROM ebpf_events
WHERE event_type = 'packet_drop'
    AND observed_at >= now() - interval '7 days'
    AND interface_name IS NOT NULL
GROUP BY interface_name, drop_reason
ORDER BY interface_name, total_dropped DESC;
```

### Query 6: MULTI-NIC - Interface Comparison

```sql
-- Compare traffic patterns across all interfaces
SELECT
    interface_name,
    COUNT(*) as event_count,
    COUNT(DISTINCT pid) as unique_processes,
    COUNT(DISTINCT dst_ip) as unique_destinations,
    SUM(COALESCE(bytes_sent, 0)) as total_sent,
    SUM(COALESCE(bytes_received, 0)) as total_received,
    SUM(COALESCE(dropped_count, 0)) as total_dropped_packets,
    COUNT(DISTINCT event_type) as event_types
FROM ebpf_events
WHERE observed_at >= now() - interval '24 hours'
GROUP BY interface_name
ORDER BY total_received DESC;
```

### Query 7: MULTI-NIC - Per-Process Traffic Distribution

```sql
-- Show how a process uses different network interfaces
SELECT
    pid,
    command,
    interface_name,
    COUNT(*) as connection_count,
    SUM(bytes_sent) as total_sent,
    SUM(bytes_received) as total_received,
    COUNT(DISTINCT dst_ip) as unique_destinations
FROM ebpf_events
WHERE event_type = 'connection'
    AND observed_at >= now() - interval '24 hours'
    AND interface_name IS NOT NULL
GROUP BY pid, command, interface_name
ORDER BY pid, total_received DESC;
```

---

**Status**: DRAFT - Awaiting approval
**Next Action**: User feedback and approval to proceed with implementation
