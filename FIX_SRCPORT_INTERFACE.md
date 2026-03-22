# Fix for Source Port and Interface Name in PostgreSQL Storage

## Problem Statement

The aggregator was pushing eBPF connection events to PostgreSQL, but two critical fields were coming as:
- **src_port**: 0 (zero) instead of the actual source port
- **interface_name**: Empty string instead of the network interface name

This caused incomplete data in the `ebpf_meta_window` and `ebpf_events` tables.

## Root Cause Analysis

### 1. Source Port Issue (src_port = 0)

**Previous Implementation:**
- The code tried to resolve source port by matching socket inodes from `/proc/{pid}/fd` with entries in `/proc/net/tcp[6]`
- This approach had timing issues: the connection might not be fully established when reading `/proc/net/tcp`
- Inode matching could fail silently, leaving src_port = 0

**Fix Applied:**
- Added `findSourcePortDirect()` as a fallback method
- This function performs a direct scan of `/proc/net/tcp[6]` for matching destination IP:port pairs
- Implemented a two-stage resolution:
  1. Try original inode-based method first (cached, faster)
  2. If that fails (returns 0), use direct method as fallback

### 2. Interface Name Issue (interface_name = "")

**Previous Implementation:**
- There was NO code at all to populate `interface_name` or `interface_index` fields
- The metadata map never contained these fields
- Database storage expected them but received NULL/empty values

**Fix Applied:**
- Added `resolveInterfaceFromRoute()` to determine the network interface via the kernel routing table
- Implemented separate handlers for IPv4 and IPv6:
  - **IPv4**: Parses `/proc/net/route` and performs longest-prefix-match lookup
  - **IPv6**: Parses `/proc/net/ipv6_route` and matches by prefix length
- The interface is resolved for every connection event and added to metadata

## Implementation Details

### New Functions in `connection.go`

#### 1. `findSourcePortDirect(pid, destIP, destPort, protocol) -> uint16`
- **Purpose**: Fallback source port resolution when inode matching fails
- **Method**: Direct scan of `/proc/net/tcp[6]` looking for matching destination address/port
- **Returns**: Source port (0 if not found)
- **Efficiency**: O(n) where n = number of sockets (typical: <1000)

#### 2. `resolveInterfaceFromRoute(destIP) -> string`
- **Purpose**: Determine which network interface will be used to reach destination IP
- **Method**: Queries kernel routing table
- **Returns**: Interface name (eth0, enp0s3, etc.) or empty string if not found
- **Routing Strategy**: Longest-prefix-match (most specific route wins)

#### 3. `resolveInterfaceIPv4(destIP) -> string`
- Parses `/proc/net/route` (kernel IPv4 routing table)
- Uses `math/bits.OnesCount32()` to count mask bits for specificity
- Selects the most specific matching route

#### 4. `resolveInterfaceIPv6(destIP) -> string`
- Parses `/proc/net/ipv6_route` (kernel IPv6 routing table)
- Converts hex format to standard IPv6 notation
- Matches using CIDR prefix length comparison

## Changes Made

**File:** `internal/programs/connection/connection.go`

### Imports Added
```go
import (
	...
	"math/bits"  // For bit counting in route mask
	...
)
```

### Parse Function Enhancement
```go
// Resolve source port with improved method
sourcePort := resolveSourcePort(pid, family, destinationIP, destPort, protocol)
if sourcePort != 0 {
	metadata["source_port"] = sourcePort
	metadata["src_port"] = sourcePort
} else {
	// Fallback: try direct socket lookup
	sourcePort = findSourcePortDirect(pid, destinationIP, destPort, protocol)
	if sourcePort != 0 {
		metadata["source_port"] = sourcePort
		metadata["src_port"] = sourcePort
	}
}

// Resolve network interface from routing table
if destinationIP != "" {
	iface := resolveInterfaceFromRoute(destinationIP)
	if iface != "" {
		metadata["interface_name"] = iface
	}
}
```

## Testing

### Quick Test with cURL

1. **Start the server:**
   ```bash
   sudo ./bin/ebpf-server -addr :8080
   ```

2. **Make a connection:**
   ```bash
   curl -s "http://127.0.0.1:8080/api/events?event_type=connection&limit=1" | jq '.'
   ```

3. **Expected Results:**
   ```json
   {
     "events": [
       {
         "id": "...",
         "type": "connection",
         "src_ip": "127.0.0.1",
         "src_port": 54321,        // ✅ Now contains actual port instead of 0
         "dst_ip": "127.0.0.1",
         "dst_port": 8080,
         "interface_name": "lo",   // ✅ Now contains interface name
         "...": "..."
       }
     ]
   }
   ```

### Verify in PostgreSQL

After the aggregator pushes events to the database:

```sql
-- Check for non-zero src_port values
SELECT COUNT(*) as total_events,
       COUNT(CASE WHEN src_port > 0 THEN 1 END) as with_src_port
FROM ebpf_events WHERE event_type = 'connection';

-- Expected: with_src_port should equal or be close to total_events

-- Check for interface_name values
SELECT COUNT(*) as total_events,
       COUNT(CASE WHEN interface_name IS NOT NULL AND interface_name != '' THEN 1 END) as with_interface
FROM ebpf_events WHERE event_type = 'connection';

-- Expected: with_interface should be high (most connections have a route)
```

## Performance Considerations

### Caching Strategy
- **Source Port**: Already cached with 30-second TTL
- **Interface**: Not cached per-event (route table is stable, adds ~1-2ms per connection)

### Efficiency
- **Fallback method**: Only triggered if inode matching fails
- **Route lookup**: Uses routing table (typically <100 entries), not scanning all sockets
- **No blocking operations**: All reads from `/proc` are non-blocking

## Backwards Compatibility

✅ **Fully backwards compatible:**
- Events without interface_name still work (stored as NULL in DB)
- Existing queries using WHERE interface_name IS NOT NULL still function
- Source port defaults to 0 if both methods fail (same as before)

## Limitations

1. **Root Requirement**: Some `/proc` reads may require elevated privileges
2. **Timing**: Source port resolved after `sys_enter_connect` syscall - actual binding might happen later
3. **Route Table Stability**: Assumes route table doesn't change between event capture and resolution (reasonable assumption for most systems)

## Future Improvements

1. **eBPF Enhancement**: Capture src_port and interface_index directly in eBPF program (requires C code changes and kernel recompilation)
2. **Caching**: Add interface resolution caching if performance becomes an issue
3. **Netlink API**: Use netlink instead of `/proc` files for more reliable route lookups
