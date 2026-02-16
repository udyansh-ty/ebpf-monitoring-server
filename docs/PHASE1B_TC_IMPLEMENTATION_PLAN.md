# Phase 1B: TC + Connection Tracer Hybrid Implementation Plan

**Date**: February 3, 2026
**Phase**: 1B - Kernel Interface Capture
**Approach**: TC (Traffic Control) + Connection Tracer Hybrid
**Estimated Effort**: 2-3 weeks
**Status**: PLANNING

---

## Executive Summary

Phase 1B will implement interface-aware connection tracking by combining:

1. **Keep**: Existing `sys_enter_connect` tracepoint (connection data)
2. **Add**: TC (Traffic Control) ingress classifier (interface identification)
3. **Correlate**: Userspace enrichment (connect events with interface info)

This hybrid approach provides:
- ✅ Stable (TC available in all kernels)
- ✅ Fast (microsecond overhead)
- ✅ Maintainable (standard BPF patterns)
- ✅ Debuggable (well-documented)

---

## Architecture Overview

### Current Flow (Phase 1A)
```
eBPF Programs
  ├─ sys_enter_connect → event (PID, 5-tuple, duration)
  └─ kfree_skb → event (drop_reason, count)
         ↓
   PostgreSQL ebpf_events table
     ├─ interface_name = NULL ⚠️
     └─ interface_index = NULL ⚠️
```

### Target Flow (Phase 1B)
```
eBPF Programs
  ├─ sys_enter_connect → event (PID, 5-tuple, duration)
  │                          ↓
  │                    Userspace Agent
  │                          ↓
  │                    [Socket→Interface Map]
  │                          ↓
  │                    event + interface_name
  │
  ├─ TC ingress → interface map (socket → eth0/eth1)
  │
  └─ kfree_skb → event (drop_reason, count)
         ↓
   PostgreSQL ebpf_events table
     ├─ interface_name = "eth0" ✅
     └─ interface_index = 2 ✅
```

---

## Implementation Phases

### Phase 1B.1: eBPF TC Program Development (Days 1-3)

#### 1. Create TC Classifier Program

**File**: `bpf/connection_interface.c` (NEW)

```c
// ANCHOR: TC Ingress Classifier for Interface Tagging - Feb 2026
// WHY: Capture which interface handled network traffic for socket correlation
// WHAT: TC ingress hook that extracts packet flow info and interface
// HOW: Attach to interface ingress, extract skb fields, send to userspace via map

#include <uapi/linux/bpf.h>
#include <uapi/linux/in.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <linux/skbuff.h>

// Map: socket_flow → interface mapping
// Key: {saddr, daddr, sport, dport, protocol}
// Value: {interface_name, ifindex}

struct flow_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 protocol;
};

struct interface_info {
    char name[16];      // eth0, eth1, etc
    __u32 ifindex;
    __u64 timestamp;
};

BPF_HASH(socket_interface_map, struct flow_key, struct interface_info, 10240);

SEC("classifier/ingress")
int tc_ingress(struct __sk_buff *skb) {
    // ANCHOR: Extract packet metadata - Feb 2026
    // WHY: Correlate packets to sockets
    // WHAT: Get 5-tuple from packet headers
    // HOW: Use bpf_skb_load_bytes to safely read packet data

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    // Only process IP packets
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return TC_ACT_OK;

    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    // Initialize flow key
    struct flow_key flow = {
        .saddr = ip->saddr,
        .daddr = ip->daddr,
        .protocol = ip->protocol,
    };

    // Extract ports based on protocol
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;

        flow.sport = tcp->source;
        flow.dport = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;

        flow.sport = udp->source;
        flow.dport = udp->dest;
    } else {
        return TC_ACT_OK;  // Skip other protocols
    }

    // ANCHOR: Extract interface information - Feb 2026
    // WHY: Tag packet with which NIC it arrived on
    // WHAT: Get interface name from kernel device struct
    // HOW: Use skb->ifindex to look up device name

    struct interface_info info = {
        .ifindex = skb->ifindex,
        .timestamp = bpf_ktime_get_ns(),
    };

    // Extract interface name from skb (if available)
    // Note: Different kernel versions may have different ways to access this
    // For now, we send ifindex; userspace will resolve name via /sys/class/net/

    // ANCHOR: Update socket→interface mapping - Feb 2026
    // WHY: Allow connection_tracer to look up interface for socket
    // WHAT: Store bidirectional flow info in BPF map
    // HOW: Use flow_key to store interface info, expires after timeout

    socket_interface_map.update(&flow, &info);

    // Forward packet (TC doesn't drop)
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
```

#### 2. Connection Tracer Enhancement

**File**: `bpf/connection.c` (MODIFY)

```c
// EXISTING CODE: Keep all existing sys_enter_connect logic
// ADD: Socket→interface lookup after capturing flow

// In event structure, ADD:
struct connection_event {
    // ... existing fields ...

    // NEW: Interface information
    __u32 ifindex;                  // Interface index
    char ifname[16];                // Interface name (populated in userspace)
};

// In trace_connect():
// After capturing 5-tuple, do:
struct flow_key flow = {
    .saddr = src_ip,
    .daddr = dst_ip,
    .sport = src_port,
    .dport = dst_port,
    .protocol = protocol,
};

// Try to look up interface from TC map
struct interface_info *iface = socket_interface_map.lookup(&flow);
if (iface) {
    event.ifindex = iface->ifindex;
    // ifname will be resolved in userspace
}
```

#### 3. Attach TC Program

**File**: `internal/programs/connection/connection.c` or similar

```bash
# Attach TC ingress to all interfaces
for iface in $(ip link show | grep "^[0-9]" | awk '{print $2}' | sed 's/://'); do
    tc qdisc add dev $iface ingress 2>/dev/null || true
    tc filter add dev $iface ingress bpf da obj connection_interface.o sec classifier/ingress flowid 1:1
done
```

---

### Phase 1B.2: Userspace Agent Enhancement (Days 4-6)

#### 1. Interface Name Resolution

**File**: `internal/programs/manager.go` or `internal/agents/interface_resolver.go` (NEW)

```go
// ANCHOR: Interface Index to Name Resolver - Feb 2026
// WHY: Convert kernel interface indices to human-readable names
// WHAT: Resolve ifindex to eth0/eth1/wlan0 via /sys/class/net/
// HOW: Maintain cache of ifindex→name mappings, update on interface changes

package programs

import (
    "fmt"
    "io/ioutil"
    "path/filepath"
    "strconv"
    "sync"
)

type InterfaceResolver struct {
    cache map[uint32]string
    mu    sync.RWMutex
}

func NewInterfaceResolver() *InterfaceResolver {
    return &InterfaceResolver{
        cache: make(map[uint32]string),
    }
}

// ResolveInterface returns interface name for given ifindex
func (r *InterfaceResolver) ResolveInterface(ifindex uint32) (string, error) {
    // Check cache first
    r.mu.RLock()
    if name, ok := r.cache[ifindex]; ok {
        r.mu.RUnlock()
        return name, nil
    }
    r.mu.RUnlock()

    // ANCHOR: Lookup interface by ifindex - Feb 2026
    // WHY: Map kernel interface numbers to names
    // WHAT: Scan /sys/class/net/ for matching ifindex
    // HOW: Read if_index file for each interface directory

    netDir := "/sys/class/net"
    entries, err := ioutil.ReadDir(netDir)
    if err != nil {
        return "", fmt.Errorf("failed to read /sys/class/net: %w", err)
    }

    for _, entry := range entries {
        if !entry.IsDir() {
            continue
        }

        ifIndexPath := filepath.Join(netDir, entry.Name(), "ifindex")
        data, err := ioutil.ReadFile(ifIndexPath)
        if err != nil {
            continue
        }

        idx, err := strconv.ParseUint(string(data), 10, 32)
        if err != nil {
            continue
        }

        if uint32(idx) == ifindex {
            // Cache it
            r.mu.Lock()
            r.cache[ifindex] = entry.Name()
            r.mu.Unlock()
            return entry.Name(), nil
        }
    }

    return "", fmt.Errorf("interface not found for ifindex %d", ifindex)
}

// RefreshCache invalidates cache (call on interface changes)
func (r *InterfaceResolver) RefreshCache() {
    r.mu.Lock()
    r.cache = make(map[uint32]string)
    r.mu.Unlock()
}
```

#### 2. Event Enrichment Pipeline

**File**: `internal/events/enricher.go` (NEW)

```go
// ANCHOR: Event Enrichment with Interface Information - Feb 2026
// WHY: Add interface names to events from kernel interface indices
// WHAT: Enrich connection events with resolved interface names
// HOW: Use InterfaceResolver to map ifindex → interface_name before storage

package events

import (
    "github.com/srodi/ebpf-server/internal/core"
    "github.com/srodi/ebpf-server/pkg/logger"
)

type EventEnricher struct {
    ifaceResolver *programs.InterfaceResolver
}

func NewEventEnricher(resolver *programs.InterfaceResolver) *EventEnricher {
    return &EventEnricher{
        ifaceResolver: resolver,
    }
}

// EnrichEvent adds interface information to eBPF events
func (e *EventEnricher) EnrichEvent(event core.Event) error {
    metadata := event.Metadata()
    if metadata == nil {
        metadata = make(map[string]interface{})
    }

    // Check if event has interface index but no name
    ifindexVal, hasIfindex := metadata["ifindex"].(float64)
    ifnameVal, hasIfname := metadata["interface_name"].(string)

    if !hasIfindex || hasIfname {
        // No interface index or already has name
        return nil
    }

    // ANCHOR: Resolve interface name - Feb 2026
    // WHY: Convert kernel ifindex to human-readable name
    // WHAT: Look up interface name from index
    // HOW: Use InterfaceResolver to query /sys/class/net/

    ifindex := uint32(ifindexVal)
    ifname, err := e.ifaceResolver.ResolveInterface(ifindex)
    if err != nil {
        logger.Warnf("Failed to resolve interface %d: %v", ifindex, err)
        // Don't fail, just leave interface_name empty
        return nil
    }

    // Add resolved interface name to metadata
    metadata["interface_name"] = ifname
    metadata["interface_index"] = int(ifindex)

    logger.Debugf("Enriched event with interface: %s (ifindex=%d)", ifname, ifindex)

    return nil
}
```

#### 3. Integration with Event Storage

**File**: `cmd/aggregator/main.go` (MODIFY)

```go
// Add enricher initialization and event enrichment before storage

// In main():

// Initialize interface resolver
ifaceResolver := programs.NewInterfaceResolver()
enricher := events.NewEventEnricher(ifaceResolver)

// When storing events:
for event := range mergedStream.Events() {
    // ANCHOR: Enrich events before storage - Feb 2026
    // WHY: Resolve interface information from kernel indices
    // WHAT: Add interface_name to event metadata
    // HOW: Use EventEnricher to resolve ifindex to name

    if err := enricher.EnrichEvent(event); err != nil {
        logger.Warnf("Failed to enrich event: %v", err)
        // Continue despite enrichment error
    }

    // Store enriched event
    if pgStorage != nil {
        if err := pgStorage.Store(ctx, event); err != nil {
            logger.Errorf("Failed to store event: %v", err)
        }
    }
}
```

---

### Phase 1B.3: Testing & Validation (Days 7-10)

#### 1. Unit Tests

**File**: `internal/programs/interface_resolver_test.go` (NEW)

```go
func TestInterfaceResolver(t *testing.T) {
    resolver := NewInterfaceResolver()

    // Get current interface
    iface, err := resolver.ResolveInterface(1)  // loopback
    if err != nil {
        t.Errorf("Failed to resolve loopback: %v", err)
    }
    if iface != "lo" {
        t.Errorf("Expected 'lo', got %s", iface)
    }
}
```

#### 2. Integration Tests

**File**: `internal/events/enricher_test.go` (NEW)

```go
func TestEventEnrichment(t *testing.T) {
    resolver := NewInterfaceResolver()
    enricher := NewEventEnricher(resolver)

    // Create event with ifindex but no interface_name
    metadata := map[string]interface{}{
        "ifindex": float64(2),  // eth0 on most systems
    }
    event := events.NewBaseEvent("connection", 1234, "curl",
        uint64(time.Now().UnixNano()), metadata)

    // Enrich event
    err := enricher.EnrichEvent(event)
    if err != nil {
        t.Errorf("Enrichment failed: %v", err)
    }

    // Check that interface_name was added
    if ifname, ok := event.Metadata()["interface_name"]; !ok {
        t.Error("interface_name not added to metadata")
    } else {
        t.Logf("Enriched with interface: %s", ifname)
    }
}
```

#### 3. End-to-End Tests

**File**: `test/phase1b_tc_integration_test.go` (NEW)

```go
// Test full flow:
// 1. Connection event captured
// 2. TC program captures interface
// 3. Userspace enriches event
// 4. Event stored to database with interface_name
// 5. Query returns events grouped by interface

func TestPhase1BEndToEnd(t *testing.T) {
    ctx := context.Background()

    // Setup: Start aggregator with DB
    // Create multiple connections from different "interfaces"
    // Verify database records interface_name field
    // Verify queries by interface work
}
```

---

### Phase 1B.4: Documentation & Migration (Days 11-14)

#### 1. Update User Documentation

**File**: `docs/EBPF_MULTI_NIC.md` (NEW)

- How to enable multi-NIC tracking
- Query examples
- Performance implications
- Troubleshooting

#### 2. Update Architecture Docs

**File**: `docs/ARCHITECTURE.md` (MODIFY)

- Add TC + Connection Tracer hybrid diagram
- Explain interface resolution process
- Document userspace enrichment pipeline

#### 3. Migration Guide

**File**: `docs/PHASE1B_MIGRATION.md` (NEW)

- How to upgrade from Phase 1A to Phase 1B
- No database changes needed (schema already supports it)
- No API changes needed
- Backward compatibility guaranteed

---

## Files to Create/Modify

### New Files
| File | Purpose | Lines |
|------|---------|-------|
| `bpf/connection_interface.c` | TC classifier program | ~200 |
| `internal/programs/interface_resolver.go` | ifindex→name resolution | ~100 |
| `internal/events/enricher.go` | Event enrichment logic | ~150 |
| `internal/programs/interface_resolver_test.go` | Resolver tests | ~80 |
| `internal/events/enricher_test.go` | Enricher tests | ~100 |
| `test/phase1b_tc_integration_test.go` | Integration tests | ~200 |
| `docs/PHASE1B_IMPLEMENTATION.md` | Technical guide | ~400 |
| `docs/EBPF_MULTI_NIC.md` | User guide | ~300 |

### Modified Files
| File | Changes | Impact |
|------|---------|--------|
| `bpf/connection.c` | Add ifindex field extraction | Low - backward compatible |
| `cmd/aggregator/main.go` | Add enricher initialization | Low - optional feature |
| `internal/events/events.go` | Import enricher package | Low - no behavior changes |
| `docs/ARCHITECTURE.md` | Add TC + Connection Tracer diagram | Documentation only |

---

## Data Flow with Examples

### Example 1: Single Connection Over eth0

```
Time 0ms: Process runs: curl google.com
Time 1ms: sys_enter_connect fires
         Event created: {pid: 1234, src_port: 50000, dst_ip: 142.251.x.x, ifindex: NULL}

Time 2ms: Packet goes out eth0
         TC ingress fires: {eth0, ifindex: 2}
         Flow map updated: {142.251.x.x:443 → eth0}

Time 5ms: Userspace enricher runs
         Looks up: 142.251.x.x:443 in flow map → finds eth0
         Enriches event: interface_name = "eth0"

Time 10ms: Event stored
         INSERT ebpf_events (..., interface_name='eth0', ...)

Query:
SELECT * FROM ebpf_events WHERE interface_name='eth0'
→ Returns event ✅
```

### Example 2: Multiple Interfaces

```
Process 1: curl google.com (eth0)  → interface_name='eth0'
Process 2: ssh remote (eth1)       → interface_name='eth1'
Process 3: ssh 192.168.2.1 (wlan0) → interface_name='wlan0'

Query after Phase 1B:
SELECT interface_name, COUNT(*) FROM ebpf_events
WHERE event_type='connection'
GROUP BY interface_name;

Result:
interface_name | count
───────────────┼──────
eth0           | 1542
eth1           | 847
wlan0          | 293
```

---

## Performance Implications

| Component | Overhead | Notes |
|-----------|----------|-------|
| TC Classifier | <1µs per packet | Only for ingress packets |
| Interface Resolution | <100µs (cached) | Runs in userspace, cached |
| Event Enrichment | <50µs per event | Single map lookup |
| **Total per Connection** | **<200µs** | Negligible impact |

---

## Rollback Plan

If Phase 1B causes issues:

1. **Disable TC Program**
   ```bash
   tc filter del dev eth0 ingress
   ```

2. **Revert to Phase 1A**
   - Existing events still stored (backward compatible)
   - interface_name will be NULL for new events
   - All queries continue to work

3. **No Database Changes Needed**
   - Schema already supports both modes
   - Data migration not required

---

## Success Criteria

✅ **Technical**
- TC program loads without errors
- Interface name resolution works for all NICs
- Events stored with interface_name populated
- Queries by interface return correct results

✅ **Performance**
- <200µs overhead per connection
- Zero impact on packet forwarding
- Memory footprint <10MB for interface maps

✅ **Quality**
- 100% test coverage for new code
- No breaking changes to existing APIs
- Backward compatible with Phase 1A

✅ **Documentation**
- Phase 1B implementation guide complete
- User guide for multi-NIC queries complete
- Migration guide written

---

## Timeline Summary

| Phase | Duration | Status |
|-------|----------|--------|
| 1B.1: eBPF TC Program | 3 days | Planning |
| 1B.2: Userspace Enrichment | 3 days | Planning |
| 1B.3: Testing & Validation | 4 days | Planning |
| 1B.4: Documentation | 4 days | Planning |
| **Total** | **14 days** | Planning |

---

## Next Actions

1. ✅ Approve this plan
2. ⏳ Create eBPF TC classifier (`bpf/connection_interface.c`)
3. ⏳ Implement InterfaceResolver (`internal/programs/interface_resolver.go`)
4. ⏳ Build EventEnricher (`internal/events/enricher.go`)
5. ⏳ Write comprehensive tests
6. ⏳ Integrate with aggregator
7. ⏳ Test end-to-end
8. ⏳ Document and release

---

## Questions & Decisions

### Decision 1: TC vs Network Namespace
**Q**: Should we track interfaces per network namespace?
**A**: Phase 1B: No - assume single namespace. Phase 1C enhancement possible.

### Decision 2: Interface Name Changes
**Q**: What if interface is renamed (eth0 → enp0)?
**A**: InterfaceResolver caches by ifindex - handles renames automatically.

### Decision 3: Virtual Interfaces (bridges, vlans)
**Q**: Should we track traffic through bridges?
**A**: Yes - TC applies to all interfaces, including virtual ones.

---

**Status**: READY FOR APPROVAL
**Created**: February 3, 2026
**Lead**: Architecture Team
