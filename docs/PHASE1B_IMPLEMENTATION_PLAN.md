# Phase 1B Implementation Plan: TC + Connection Tracer Hybrid

**Date**: February 6, 2026
**Status**: PLAN READY FOR APPROVAL
**Phase**: 1B - Multi-NIC Interface Capture
**Estimated Duration**: 14 calendar days
**Approach**: TC kernel classifier + userspace enrichment

---

## Executive Summary

Phase 1B implements multi-NIC interface capture for eBPF events using a **TC (Traffic Control) + Connection Tracer hybrid** approach. This enables the monitoring system to capture which network interface handles each connection, enabling per-interface analytics.

### Why This Approach?

**TC (Traffic Control Classifier)**:
- ✅ **Stable**: Mainstream kernel subsystem (20+ years)
- ✅ **Performance**: <200µs overhead per packet/connection
- ✅ **Development**: ~200 lines BPF C code
- ✅ **Maintenance**: Well-documented kernel interface
- ✅ **Interface Info**: Direct access to `skb->ifindex`

---

## Architecture Overview

### Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│  KERNEL SPACE                                                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Network Packet Arrives                                         │
│         ↓                                                        │
│  TC Ingress Classifier (BPF Program)  ← Attached to each NIC  │
│  ├─ Extracts: src_ip, dst_ip, src_port, dst_port, protocol   │
│  ├─ Captures: skb->ifindex (interface index)                  │
│  ├─ Maps: Flow Key (5-tuple) → Interface Index               │
│  └─ Returns: TC_ACT_OK (allows packet through)               │
│         ↓                                                        │
│  sys_enter_connect Tracer (Existing)  ← Existing sys_enter    │
│  ├─ Captures: Connection details (bytes, duration, state)    │
│  ├─ Returns: Event with 5-tuple                              │
│  └─ Limitation: No interface info                            │
│         ↓                                                        │
│  BPF Maps (Ring Buffer)                                        │
│  ├─ Flow Key → Interface Index mapping                        │
│  └─ Connection details                                         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                    ↓ Events via ring buffer
┌─────────────────────────────────────────────────────────────────┐
│  USERSPACE - AGGREGATOR                                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. InterfaceResolver                                          │
│     ├─ Reads: /sys/class/net/ directory                      │
│     ├─ Maps: ifindex → interface_name (eth0, eth1, wlan0)   │
│     ├─ Caches: ifindex → name mapping                        │
│     └─ Handles: Interface renames, dynamic interfaces       │
│                                                                 │
│  2. EventEnricher Pipeline                                    │
│     ├─ Input: Connection event + flow key                    │
│     ├─ Lookup: Flow key in TC classifier BPF map           │
│     ├─ Resolve: ifindex → interface_name via resolver      │
│     ├─ Enrich: Add interface_name to event metadata         │
│     └─ Output: Enriched event ready for storage             │
│                                                                 │
│  3. PostgreSQL Storage (Existing)                             │
│     ├─ Input: Enriched events                                │
│     ├─ Store: ebpf_events table                              │
│     └─ Index: Via pre-built multi-NIC indexes               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Implementation Components

### Component 1: TC Classifier BPF Program
**File**: `bpf/connection_interface.c`
**Lines**: ~200
**Purpose**: Capture interface information at packet level

#### Specification

```c
// ANCHOR: TC Ingress Classifier for Interface Capture - Phase 1B
// WHY: Identify which network interface handles each packet/connection
// WHAT: BPF program attached to TC ingress on all interfaces
// HOW: Extract packet headers, map flow key → ifindex, use BPF map for userspace access

Key Functions:
1. __always_inline safe_read_ipv4_header()
   - Safely read Ethernet frame and IPv4 header
   - Validate memory access bounds using asm volatile trick
   - Return: 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol)

2. __always_inline safe_read_ipv6_header()
   - Safely read Ethernet frame and IPv6 header
   - IPv6 extension header handling
   - Return: 5-tuple with IPv6 addresses

3. handle_connection_packet()
   - Main TC classifier handler
   - Called for each ingress packet on attached interface
   - Extract 5-tuple from packet headers
   - Create flow key: hash(5-tuple)
   - Store in BPF map: flow_key → {ifindex, timestamp}
   - Return TC_ACT_OK to allow packet forwarding

4. __always_inline build_flow_key()
   - Create deterministic hash from 5-tuple
   - Used as BPF map key for flow→interface lookup
   - Same hash calculation as userspace enricher

BPF Maps:
- flow_to_interface_map: <u64 flow_key> → <u32 ifindex>
  ├─ Max entries: 10,000 concurrent flows
  ├─ Update strategy: Overwrite on collision
  └─ Cleanup: Entries expire after 5 minutes (userspace cleanup)

- connection_metadata_map: <u64 flow_key> → <struct metadata>
  ├─ Stores: {ifindex, timestamp, protocol}
  └─ Replaces per-connection tracking

Performance:
- Per-packet overhead: <100ns per map lookup + store
- Memory: 10,000 flows × 16 bytes = 160KB
- No allocations in hot path
```

#### Implementation Steps

1. **Create skeleton with header guards**
   ```c
   #include <linux/bpf.h>
   #include <bpf/bpf_helpers.h>
   // ... other includes
   ```

2. **Implement safe header reading**
   - IPv4 and IPv6 parsing with bounds checking
   - Handle fragmented packets
   - Support various protocols (TCP, UDP, ICMP)

3. **Implement flow key calculation**
   - Deterministic hash of 5-tuple
   - Used for correlation in userspace

4. **Create BPF maps**
   - `flow_to_interface` - flow key → interface index
   - Connection metadata storage

5. **Implement main TC handler**
   - Extract 5-tuple from packet
   - Calculate flow key
   - Store in BPF maps
   - Return TC_ACT_OK

6. **Build and load testing**
   - Verify BPF program loads without errors
   - Test on single interface first
   - Validate map updates

---

### Component 2: InterfaceResolver
**File**: `internal/programs/interface_resolver.go`
**Lines**: ~150
**Purpose**: Resolve kernel interface indices to human-readable names

#### Specification

```go
// ANCHOR: Interface Index Resolver - Phase 1B
// WHY: Map kernel ifindex to human-readable interface names
// WHAT: Query /sys/class/net/ to build and maintain ifindex → name mapping
// HOW: Scan sysfs, cache results, handle interface hotplug

type InterfaceResolver struct {
    cache map[int]string      // ifindex → interface_name
    mu    sync.RWMutex
    log   logger.Logger
}

Key Methods:

1. NewInterfaceResolver(logger) → *InterfaceResolver
   - Create new resolver with empty cache
   - Initialize from current interfaces

2. GetInterfaceName(ctx, ifindex) → (string, error)
   - Lookup ifindex in cache
   - If not found:
     ├─ Scan /sys/class/net/ for interface with this index
     ├─ Cache result
     └─ Return name
   - Return: "eth0", "eth1", "wlan0", etc.
   - Return error: if ifindex is 0 or not found

3. RefreshCache(ctx) → error
   - Full cache refresh from /sys/class/net/
   - Called periodically (every 10 seconds)
   - Handles interface hotplug (add/remove)
   - Thread-safe with RWMutex

4. GetAllInterfaces(ctx) → map[int]string
   - Return complete ifindex → name mapping
   - Used for debugging, stats
   - Read-locked for thread safety

Implementation Details:

Cache Population:
  For each directory in /sys/class/net/:
  1. Read if_index file
  2. Parse: integer value = ifindex
  3. Directory name = interface_name
  4. Store: cache[ifindex] = interface_name

Example:
  /sys/class/net/eth0/if_index → "2"  ⟹ cache[2] = "eth0"
  /sys/class/net/eth1/if_index → "3"  ⟹ cache[3] = "eth1"
  /sys/class/net/wlan0/if_index → "4" ⟹ cache[4] = "wlan0"

Thread Safety:
  - RWMutex protects cache map
  - Read lock for lookups (fast path)
  - Write lock for cache updates (slow path)
  - No lock contention in normal operation

Performance:
  - Cache hit: O(1) map lookup (~50ns)
  - Cache miss: O(n) directory scan + cache update (~10ms)
  - Periodic refresh: O(n) background operation
```

#### Implementation Steps

1. **Create struct and constructor**
   ```go
   type InterfaceResolver struct {
       cache map[int]string
       mu    sync.RWMutex
       log   logger.Logger
   }
   ```

2. **Implement cache population from /sys/class/net/**
   - Scan directory
   - Read if_index files
   - Build ifindex → name mapping

3. **Implement GetInterfaceName()**
   - Fast path: cache lookup with read lock
   - Slow path: directory scan + cache update
   - Handle missing interfaces

4. **Implement RefreshCache()**
   - Periodic refresh for hotplug handling
   - Background goroutine in aggregator

5. **Add logging for debugging**
   - Log cache hits/misses
   - Log new interfaces discovered
   - Log interface removals

6. **Write unit tests**
   - Mock /sys/class/net/ structure
   - Test cache hits and misses
   - Test refresh scenarios

---

### Component 3: EventEnricher Pipeline
**File**: `internal/events/enricher.go`
**Lines**: ~200
**Purpose**: Enrich connection events with resolved interface names

#### Specification

```go
// ANCHOR: Event Enrichment Pipeline - Phase 1B
// WHY: Add interface information to connection events before storage
// WHAT: Lookup interface from TC classifier BPF maps, resolve to name, enrich event
// HOW: Create enricher that intercepts events, performs lookup+resolution, returns enriched event

type EventEnricher struct {
    resolver      *programs.InterfaceResolver
    bpfMaps       *BPFMaps              // Maps from TC classifier program
    log           logger.Logger
    statsEnabled  bool
    stats         *EnricherStats
}

Key Methods:

1. NewEventEnricher(ctx, resolver, bpfMaps, log) → *EventEnricher
   - Create enricher with interface resolver and BPF maps
   - Initialize stats tracking
   - Return ready-to-use enricher

2. EnrichEvent(ctx, event) → (*core.Event, error)
   - Input: Connection event (may lack interface info)
   - Process:
     ├─ Extract 5-tuple from event metadata
     ├─ Calculate flow key (same algorithm as BPF program)
     ├─ Lookup flow key in bpfMaps.flow_to_interface
     ├─ Get ifindex from BPF map
     ├─ Resolve ifindex → interface_name
     ├─ Add to event metadata:
     │  ├─ interface_name
     │  ├─ interface_index
     │  └─ enrichment_timestamp
     └─ Return enriched event
   - On error: Log and return original event (non-fatal)

3. CalculateFlowKey(src_ip, dst_ip, src_port, dst_port, protocol) → u64
   - Deterministic hash calculation (same as BPF program)
   - Maps 5-tuple → single u64 key
   - Used for BPF map lookup

4. GetStats() → *EnricherStats
   - Return enrichment statistics:
     ├─ Events processed
     ├─ Successful enrichments
     ├─ Fallback enrichments (no BPF data)
     ├─ Failed enrichments
     └─ Average latency

Enrichment Scenarios:

Scenario 1: BPF Data Available (Most Common)
  Event → Calculate flow key
       → Lookup in BPF map ✓ Found
       → Get ifindex
       → Resolve to name
       → Enrich metadata
       → Return enriched event

Scenario 2: BPF Data Not Available (Interface Transient)
  Event → Calculate flow key
       → Lookup in BPF map ✗ Not found
       → Log WARNING: "Flow not in BPF map"
       → Return original event (unenriched)
       → Monitoring system still stores event, just without interface

Scenario 3: ifindex → Name Resolution Fails
  Event → Lookup BPF map ✓ Got ifindex
       → Resolve ifindex → name ✗ Failed
       → Log WARNING: "Unable to resolve ifindex X to name"
       → Use ifindex directly: interface_index = X, interface_name = ""
       → Return partially enriched event

Performance:
  - BPF map lookup: <10µs (in-kernel structure)
  - Interface name resolution: <50µs (cached)
  - Total enrichment: <100µs per event
  - Parallelizable: Can enrich multiple events concurrently

Error Handling:
  - Non-fatal: Enrichment failures don't block event storage
  - Graceful degradation: Events stored even without interface info
  - Logging: All failures logged for debugging
  - Stats tracking: Failure rates monitored
```

#### Implementation Steps

1. **Create enricher struct and constructor**
   ```go
   type EventEnricher struct {
       resolver *programs.InterfaceResolver
       bpfMaps  *BPFMaps
       log      logger.Logger
   }
   ```

2. **Implement flow key calculation**
   - Deterministic hash function
   - Must match BPF program calculation
   - Use standard library `hash/fnv` or similar

3. **Implement EnrichEvent()**
   - Extract 5-tuple from event metadata
   - Calculate flow key
   - Lookup in BPF maps (requires CGO or syscall binding)
   - Resolve interface name
   - Add to metadata

4. **Add stats tracking**
   - Count successful enrichments
   - Count fallbacks
   - Track latency

5. **Write unit tests**
   - Mock BPF maps
   - Test successful enrichment
   - Test missing flow data
   - Test resolution failures

6. **Integration with aggregator**
   - Call enricher before storage
   - Handle enrichment errors gracefully
   - Log enrichment stats periodically

---

### Component 4: Integration with Aggregator
**File**: `cmd/aggregator/main.go` (updated)
**Lines**: ~30 changes
**Purpose**: Initialize enricher and apply to events

#### Changes Required

1. **Import new packages**
   ```go
   import (
       "github.com/srodi/ebpf-server/internal/programs"
       "github.com/srodi/ebpf-server/internal/events"
   )
   ```

2. **Initialize components in main()**
   ```go
   // ANCHOR: Phase 1B - TC Classifier Integration - Feb 6, 2026
   // WHY: Enable multi-NIC interface capture for connection events
   // WHAT: Initialize InterfaceResolver and EventEnricher from TC BPF program
   // HOW: Load TC classifier, setup enricher, apply to events before storage

   // Load TC classifier BPF program
   tcProgram, err := programs.LoadTCClassifier(ctx)
   if err != nil {
       logger.Errorf("Warning: Failed to load TC classifier: %v", err)
       logger.Info("Continuing without TC interface capture")
   }

   // Create interface resolver
   resolver := programs.NewInterfaceResolver(logger)
   resolver.Start(ctx)  // Start periodic refresh

   // Create event enricher
   var enricher *events.EventEnricher
   if tcProgram != nil {
       enricher = events.NewEventEnricher(ctx, resolver, tcProgram.Maps(), logger)
   }
   ```

3. **Apply enricher to aggregator**
   ```go
   // Pass enricher to aggregator
   agg, err := aggregator.New(&aggregator.Config{
       HTTPAddr: *httpAddr,
       Enricher: enricher,
   })
   ```

4. **Call enricher before storage**
   ```go
   // In aggregator event loop:
   if enricher != nil {
       event, _ = enricher.EnrichEvent(ctx, event)
   }
   storage.Store(ctx, event)
   ```

---

## Phase 1B Timeline (14 Days)

### Days 1-3: eBPF TC Program Development (200 lines)
- [ ] Create `bpf/connection_interface.c` skeleton
- [ ] Implement IPv4 and IPv6 header parsing
- [ ] Implement flow key calculation
- [ ] Create BPF maps for flow → interface mapping
- [ ] Implement TC handler logic
- [ ] Test program loads without errors
- [ ] Verify map operations work

**Deliverable**: Compiled BPF object file, test harness

### Days 4-6: Userspace Components (350 lines total)
- [ ] Create `internal/programs/interface_resolver.go` (150 lines)
  - [ ] Scan /sys/class/net/
  - [ ] Build and maintain cache
  - [ ] Implement GetInterfaceName()
  - [ ] Implement RefreshCache()
  - [ ] Write unit tests

- [ ] Create `internal/events/enricher.go` (200 lines)
  - [ ] Implement flow key calculation (matching BPF)
  - [ ] Implement EnrichEvent() logic
  - [ ] Add stats tracking
  - [ ] Write unit tests
  - [ ] Integration tests

**Deliverable**: Tested userspace components, passing unit tests

### Days 7-10: Integration & Testing (200+ lines tests)
- [ ] Update aggregator to initialize enricher
- [ ] Create integration tests (TC + enricher together)
- [ ] Write end-to-end tests with real connections
- [ ] Performance benchmarking (<200µs overhead)
- [ ] Multi-interface testing (eth0, eth1, wlan0)
- [ ] Test graceful degradation (enricher errors)
- [ ] Load testing with high connection rates

**Deliverable**: Passing integration tests, performance benchmarks

### Days 11-14: Documentation & Migration (100+ lines docs)
- [ ] Update README with Phase 1B capabilities
- [ ] Create multi-NIC query guide
- [ ] Document interface capture limitations
- [ ] Create troubleshooting guide
- [ ] Update PHASE1A documentation with Phase 1B status
- [ ] Create migration examples
- [ ] Performance tuning guide

**Deliverable**: Comprehensive documentation, examples, migration guides

---

## Testing Strategy

### Unit Tests

**InterfaceResolver Tests** (8 tests)
```go
TestResolverCacheMiss()           // First lookup triggers scan
TestResolverCacheHit()            // Subsequent lookups use cache
TestResolverRefreshCache()        // Periodic refresh works
TestResolverInvalidIfindex()      // Invalid ifindex returns error
TestResolverConcurrentAccess()    // Thread-safe access
TestResolverInterfaceHotplug()    // New interfaces discovered
TestResolverInterfaceRename()     // Renamed interfaces detected
TestResolverEmptyDirectory()      // Handles no interfaces gracefully
```

**EventEnricher Tests** (6 tests)
```go
TestEnrichmentWithBPFData()       // Happy path enrichment
TestEnrichmentMissingFlow()       // Graceful fallback without BPF data
TestEnrichmentResolutionFailure() // Handles resolution errors
TestFlowKeyCalculation()          // Flow key matches BPF calculation
TestEnrichmentStats()             // Stats tracking works
TestConcurrentEnrichment()        // Thread-safe operation
```

### Integration Tests (8 tests)
```go
TestTC_ProgramLoads()             // TC program loads successfully
TestTC_AttachesToInterfaces()      // Attaches to all interfaces
TestTC_CapturesTraffic()           // Captures interface information
TestEnricher_IntegratesWithTC()   // Enricher accesses BPF maps
TestStorage_ReceivesEnrichedEvents() // Events stored with interface info
TestQuery_ByInterface()            // Queries by interface work
TestMultiInterface_Tracking()      // Multiple interfaces tracked correctly
TestGracefulDegradation()          // Works if TC unavailable
```

### End-to-End Tests (3 tests)
```go
TestE2E_SingleConnection()         // Single connection enriched and stored
TestE2E_MultipleConnections()      // Multiple concurrent connections
TestE2E_HighConnectionRate()       // Performance under load
```

### Performance Tests
```go
BenchmarkFlowKeyCalculation()      // <100ns
BenchmarkEnricherLatency()         // <200µs per event
BenchmarkInterfaceResolution()     // <50µs per lookup
BenchmarkBPFMapLookup()            // <10µs
```

---

## Success Criteria

### Functional Requirements
- ✅ TC program loads on multiple interfaces
- ✅ Interface information captured in BPF maps
- ✅ InterfaceResolver resolves all interfaces
- ✅ EventEnricher enriches events successfully
- ✅ Enriched events stored in PostgreSQL with interface_name populated
- ✅ Queries by interface return correct results
- ✅ Works with IPv4 and IPv6 traffic

### Non-Functional Requirements
- ✅ Overhead: <200µs per connection event
- ✅ BPF program: <10µs per packet
- ✅ Memory: <1MB for resolver cache + BPF maps
- ✅ Test coverage: >80% for new code
- ✅ No breaking changes to existing APIs
- ✅ Graceful degradation if TC fails
- ✅ Thread-safe concurrent access

### Code Quality
- ✅ All new code has ANCHOR comments
- ✅ Comprehensive error handling
- ✅ Logging for debugging
- ✅ Performance benchmarks
- ✅ Documentation complete
- ✅ Migration guide for users

---

## Rollback Plan

If Phase 1B encounters issues:

1. **Complete Rollback**: Disable TC + enricher
   - Set `enricher = nil` in aggregator
   - eBPF events stored without interface info
   - No database schema changes needed
   - Zero impact on existing queries

2. **Partial Rollback**: Disable only TC, use alternative approach
   - Keep enricher code
   - Implement alternative interface capture method
   - No data loss, just delayed interface info

3. **No Data Loss**: All data stored with or without interface info
   - Phase 1A events continue to work unchanged
   - Phase 1B interface data optional
   - Can backfill later if needed

---

## Dependencies

### Required Linux Kernel Features
- `CONFIG_BPF=y` - BPF subsystem enabled
- `CONFIG_BPF_SYSCALL=y` - BPF syscall support
- `CONFIG_NET_CLS_BPF=y` - TC BPF classifier
- `CONFIG_HAVE_EBPF_JIT=y` - eBPF JIT compiler
- Kernel 5.0+ (recommended 5.8+)

### Required Go Packages
- `github.com/cilium/ebpf` - eBPF loading/management
- `github.com/vishvananda/netlink` - Interface management
- Existing packages: logger, storage, core

### System Requirements
- Linux system with BPF support
- Writable `/sys/class/net/` directory
- Root or CAP_NET_ADMIN capability for TC attachment
- ~200MB disk space for compiled object files

---

## Next Steps After Phase 1B

### Phase 2 - Analytics & APIs (Optional)
- REST API endpoints for per-interface queries
- Dashboard visualizations per interface
- Alert rules for interface-specific anomalies
- Traffic analysis by interface

### Phase 3 - Advanced Features (Future)
- VLAN interface tracking
- Virtual interface (veth, vxlan) support
- Interface naming via custom tags
- Flow classification per interface

---

## Plan Approval Checklist

Before proceeding, please verify:

- [ ] **Architecture**: TC + Connection tracer hybrid approach is correct
- [ ] **Components**: All 4 components needed (TC program, resolver, enricher, integration)
- [ ] **Timeline**: 14 days is realistic for your team
- [ ] **Testing**: Test strategy is comprehensive
- [ ] **Rollback**: Rollback plan is acceptable
- [ ] **Dependencies**: All Linux/Go dependencies available
- [ ] **Success Criteria**: All criteria understood and achievable

---

## Questions for Clarification

Before implementation, please answer:

1. **TC Program Kernel Version**: What's the minimum kernel version you need to support?
   - Default: 5.8+ (most flexible)
   - Alternative: 5.0+ (needs fallback for older kernels)

2. **Interface Count**: How many interfaces do you expect to monitor?
   - Default: 1-10 interfaces (BPF maps sized for 10K flows)
   - Alternative: More? Need to adjust BPF map sizes

3. **Flow Cache Duration**: How long should flow→interface mappings persist?
   - Default: 5 minutes (after which userspace cleans up)
   - Alternative: Shorter for high-churn environments

4. **Enrichment Strategy**: Should enrichment be blocking or non-blocking?
   - Default: Non-blocking (enrichment failures don't block storage)
   - Alternative: Blocking (harder, but guaranteed enrichment)

5. **Performance Priority**: What's more important?
   - Default: Correctness over throughput
   - Alternative: Maximum throughput, accept occasional missing interfaces

---

**Status**: READY FOR YOUR APPROVAL

Please review and confirm you want to proceed with this implementation plan.

