# Action Plan to Fix src_port and interface_name

## 🎯 Quick Summary

**What was wrong:**
1. ❌ `src_port = 0` - Socket inode matching was failing
2. ❌ `interface_name = empty` - Route table parsing had bugs and no error handling

**What I fixed:**
1. ✅ Added process-specific TCP table lookup (`/proc/{pid}/net/tcp[6]`)
2. ✅ Fixed IPv4 and IPv6 route table parsing
3. ✅ Added comprehensive error logging to debug failures

---

## 📋 Steps to Deploy and Test

### Step 1: Rebuild the Server (On Your Linux Machine)

```bash
cd /Users/apple/Desktop/neuro/ebpf-monitoring-server
go build -o ./bin/ebpf-server ./cmd/server/
ls -lh ./bin/ebpf-server  # Verify it was built
```

### Step 2: Stop Old Server and Start New One

```bash
# Kill old processes
pkill -f ebpf-server || true
pkill -f ebpf-aggregator || true

# Wait a moment
sleep 2

# Start aggregator with DB connection
export DB_URL='postgres://ebpfagg:ebpfaggpass@127.0.0.1:5432/ebpf_agg?sslmode=disable'
nohup ./bin/ebpf-aggregator -addr :8081 > /tmp/aggregator.log 2>&1 &

# Start server with aggregator URL
export AGGREGATOR_URL="http://127.0.0.1:8081"
sudo env AGGREGATOR_URL="$AGGREGATOR_URL" nohup ./bin/ebpf-server -addr :8080 > /tmp/server.log 2>&1 &

# Wait for startup
sleep 3

# Verify they're running
ps aux | grep -E "ebpf-server|ebpf-aggregator" | grep -v grep
```

### Step 3: Generate Traffic to Create Events

```bash
# Make multiple connections to trigger event capture
for i in {1..10}; do
  curl -s "http://localhost:8080" >/dev/null 2>&1 &
  curl -s "http://google.com" >/dev/null 2>&1 &
  curl -s "http://8.8.8.8:53" >/dev/null 2>&1 &
done

# Wait for events to be processed
sleep 3
```

### Step 4: Check Server Logs for Debugging Info

```bash
# Look for interface resolution logs
echo "=== Interface Resolution ==="
grep "Resolved.*interface" /tmp/server.log

# Look for source port resolution logs
echo ""
echo "=== Source Port Resolution ==="
grep "Found source port" /tmp/server.log

# Look for failures
echo ""
echo "=== Failures/Errors ==="
grep -i "failed\|error" /tmp/server.log | head -20
```

**Expected Output:**
```
Resolved IPv4 interface for 8.8.8.8: eth0
Found source port via /proc/1234/net: 54321
Resolved IPv6 interface for 2001:4860:4860::8888: eth0
```

### Step 5: Query Database to Verify Data

```bash
export DB_URL='postgres://ebpfagg:ebpfaggpass@127.0.0.1:5432/ebpf_agg?sslmode=disable'

# Check latest events
echo "=== Latest Events with All Fields ==="
psql "$DB_URL" -c "
SELECT
    src_ip || ':' || src_port as source,
    dst_ip || ':' || dst_port as destination,
    interface_name,
    created_at
FROM ebpf_events
WHERE event_type = 'connection'
ORDER BY created_at DESC
LIMIT 10;"

# Check data quality
echo ""
echo "=== Data Quality Report ==="
psql "$DB_URL" -c "
SELECT
    COUNT(*) as total_events,
    COUNT(CASE WHEN src_port > 0 THEN 1 END) as events_with_src_port,
    COUNT(CASE WHEN interface_name != '' THEN 1 END) as events_with_interface,
    ROUND(100.0 * COUNT(CASE WHEN src_port > 0 THEN 1 END) / COUNT(*), 2) as src_port_filled_percent,
    ROUND(100.0 * COUNT(CASE WHEN interface_name != '' THEN 1 END) / COUNT(*), 2) as interface_filled_percent
FROM ebpf_events
WHERE event_type = 'connection';"
```

**Expected Results:**
```
           source          |          destination          | interface_name |       created_at
--------------------------+--------------------------------+----------------+---------------------------
 192.168.1.5/32:54321     | 8.8.8.8/32:53                  | eth0           | 2026-03-22 08:45:12.123456
 192.168.1.5/32:45678     | 127.0.0.1/32:8081              | lo             | 2026-03-22 08:45:11.987654
```

---

## 🔍 Troubleshooting

### Issue: Still showing src_port = 0

**Possible Causes:**
1. The process didn't keep the socket open
2. `/proc/{pid}/net/tcp6` doesn't exist or is empty
3. Socket closed before we could read it

**Diagnosis:**
```bash
# Check if process-specific TCP files exist
ls -la /proc/*/net/tcp* 2>/dev/null | head -20

# Check what's in them
cat /proc/$$/net/tcp | head -3
cat /proc/$$/net/tcp6 | head -3
```

### Issue: Still showing interface_name = empty

**Possible Causes:**
1. Route table is empty (shouldn't happen)
2. Destination IP doesn't match any route
3. Parsing error in route lookup

**Diagnosis:**
```bash
# Check if route tables exist and have data
echo "=== IPv4 Routes ==="
cat /proc/net/route | wc -l

echo "=== IPv6 Routes ==="
cat /proc/net/ipv6_route | wc -l

# Check a specific route
echo "=== Route for 8.8.8.8 ==="
ip route get 8.8.8.8

echo "=== Route for 2001:4860:4860::8888 ==="
ip route get 2001:4860:4860::8888
```

### Issue: Aggregator not receiving events

```bash
# Check aggregator is running
ps aux | grep ebpf-aggregator | grep -v grep

# Check it's listening
netstat -tlnp | grep 8081
lsof -i :8081

# Check server can reach it
curl http://127.0.0.1:8081/health

# Check aggregator logs
tail -50 /tmp/aggregator.log
```

---

## 📊 Success Criteria

✅ **src_port is fixed when:**
- Most connections show `src_port > 0` (not 0)
- Example: `src_port: 54321` instead of `src_port: 0`

✅ **interface_name is fixed when:**
- Most connections show an interface name
- Example: `interface_name: eth0` or `interface_name: lo` instead of empty

✅ **Overall success when:**
- At least 70% of events have both src_port AND interface_name populated
- Logs show "Resolved IPv4/IPv6 interface" messages
- Logs show "Found source port" messages

---

## 🚀 One-Command Verification

Run this to check everything at once:

```bash
#!/bin/bash
export DB_URL='postgres://ebpfagg:ebpfaggpass@127.0.0.1:5432/ebpf_agg?sslmode=disable'

echo "=== HEALTH CHECK ==="
echo "Server: $(curl -s http://localhost:8080/health | jq -r '.status // "down"' || echo "down")"
echo "Aggregator: $(curl -s http://localhost:8081/health | jq -r '.status // "down"' || echo "down")"

echo ""
echo "=== DATA QUALITY ==="
psql "$DB_URL" -c "
SELECT
    COUNT(*) as total,
    COUNT(CASE WHEN src_port > 0 THEN 1 END) as src_port_filled,
    ROUND(100.0 * COUNT(CASE WHEN src_port > 0 THEN 1 END) / COUNT(*), 1) as src_port_pct,
    COUNT(CASE WHEN interface_name != '' THEN 1 END) as interface_filled,
    ROUND(100.0 * COUNT(CASE WHEN interface_name != '' THEN 1 END) / COUNT(*), 1) as interface_pct
FROM ebpf_events WHERE event_type='connection';"

echo ""
echo "=== LATEST EVENT SAMPLES ==="
psql "$DB_URL" -c "
SELECT src_ip || ':' || src_port, dst_ip || ':' || dst_port, interface_name
FROM ebpf_events
WHERE event_type='connection'
ORDER BY created_at DESC LIMIT 3;"
```

---

## 📝 Files Modified

- `internal/programs/connection/connection.go`
  - Added `math/bits` import
  - Improved `resolveInterfaceFromRoute()` with logging
  - Rewrote `resolveInterfaceIPv4()` with better error handling
  - Rewrote `resolveInterfaceIPv6()` with proper field validation
  - Refactored `findSourcePortDirect()` into two-stage lookup:
    - `findSourcePortFromProcNet()` - Process-specific lookup
    - `findSourcePortFromGlobalNet()` - Global lookup

---

## 📚 Documentation Created

- **ROOT_CAUSE_ANALYSIS.md** - Detailed explanation of why it failed and how it's fixed
- **ACTION_PLAN.md** - This file, step-by-step instructions
- **POSTGRES_QUERIES.md** - SQL commands to check the data

