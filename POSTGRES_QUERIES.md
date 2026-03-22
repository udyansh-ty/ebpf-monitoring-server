# PostgreSQL Queries for Checking IP and Interface Data

## Connection Setup
```bash
# Set your database connection string
export DB_URL='postgres://ebpfagg:ebpfaggpass@127.0.0.1:5432/ebpf_agg?sslmode=disable'

# Or connect directly
psql -h 127.0.0.1 -U ebpfagg -d ebpf_agg
```

---

## Quick Check - All Connection Data

```sql
-- View latest connection events with all details
SELECT
    id,
    src_ip,
    src_port,
    dst_ip,
    dst_port,
    interface_name,
    created_at
FROM ebpf_events
WHERE event_type = 'connection'
ORDER BY created_at DESC
LIMIT 10;
```

---

## Check Source IPs and Ports

```sql
-- Get all unique source IP:port combinations
SELECT
    src_ip,
    src_port,
    COUNT(*) as connection_count,
    MAX(created_at) as last_seen
FROM ebpf_events
WHERE event_type = 'connection' AND src_port > 0
GROUP BY src_ip, src_port
ORDER BY connection_count DESC;
```

```sql
-- Check how many events have src_port populated (non-zero)
SELECT
    COUNT(*) as total_connections,
    COUNT(CASE WHEN src_port > 0 THEN 1 END) as with_src_port,
    COUNT(CASE WHEN src_port = 0 THEN 1 END) as without_src_port,
    ROUND(100.0 * COUNT(CASE WHEN src_port > 0 THEN 1 END) / COUNT(*), 2) as percentage_with_port
FROM ebpf_events
WHERE event_type = 'connection';
```

---

## Check Network Interfaces

```sql
-- Get all unique interfaces used
SELECT
    interface_name,
    COUNT(*) as event_count,
    COUNT(DISTINCT src_ip) as unique_sources,
    COUNT(DISTINCT dst_ip) as unique_destinations,
    MAX(created_at) as last_seen
FROM ebpf_events
WHERE event_type = 'connection'
GROUP BY interface_name
ORDER BY event_count DESC;
```

```sql
-- Check how many events have interface_name populated
SELECT
    COUNT(*) as total_connections,
    COUNT(CASE WHEN interface_name IS NOT NULL AND interface_name != '' THEN 1 END) as with_interface,
    COUNT(CASE WHEN interface_name IS NULL OR interface_name = '' THEN 1 END) as without_interface,
    ROUND(100.0 * COUNT(CASE WHEN interface_name IS NOT NULL AND interface_name != '' THEN 1 END) / COUNT(*), 2) as percentage_with_interface
FROM ebpf_events
WHERE event_type = 'connection';
```

---

## Detailed Source and Destination Analysis

```sql
-- Show source and destination IPs with ports and interfaces
SELECT
    src_ip || ':' || src_port as source,
    dst_ip || ':' || dst_port as destination,
    interface_name,
    COUNT(*) as times,
    MIN(created_at) as first_seen,
    MAX(created_at) as last_seen
FROM ebpf_events
WHERE event_type = 'connection'
GROUP BY src_ip, src_port, dst_ip, dst_port, interface_name
ORDER BY times DESC
LIMIT 20;
```

---

## Check Metadata Window Table

```sql
-- View aggregated metadata in the window table
SELECT
    bucket_epoch,
    src_ip,
    dst_ip,
    src_port,
    dst_port,
    interface_name,
    packets_in,
    packets_out,
    session_count
FROM ebpf_meta_window
ORDER BY bucket_epoch DESC
LIMIT 10;
```

```sql
-- Summary of metadata window
SELECT
    COUNT(*) as total_rows,
    COUNT(DISTINCT src_ip) as unique_src_ips,
    COUNT(DISTINCT dst_ip) as unique_dst_ips,
    COUNT(DISTINCT interface_name) as unique_interfaces,
    SUM(packets_in) as total_packets_in,
    SUM(packets_out) as total_packets_out,
    SUM(session_count) as total_sessions
FROM ebpf_meta_window;
```

---

## Check Data by Interface

```sql
-- Detailed breakdown by interface
SELECT
    interface_name,
    COUNT(*) as events,
    COUNT(DISTINCT src_ip) as src_ips,
    COUNT(DISTINCT dst_ip) as dst_ips,
    MIN(created_at) as first_event,
    MAX(created_at) as last_event
FROM ebpf_events
WHERE event_type = 'connection'
GROUP BY interface_name
ORDER BY events DESC;
```

---

## Check Specific Connection Flows

```sql
-- See all connections from a specific source IP
SELECT
    src_ip,
    src_port,
    dst_ip,
    dst_port,
    interface_name,
    protocol,
    created_at
FROM ebpf_events
WHERE event_type = 'connection'
  AND src_ip = '192.168.1.100'  -- Change to your IP
ORDER BY created_at DESC
LIMIT 20;
```

```sql
-- See all connections to a specific destination IP
SELECT
    src_ip,
    src_port,
    dst_ip,
    dst_port,
    interface_name,
    protocol,
    command,
    created_at
FROM ebpf_events
WHERE event_type = 'connection'
  AND dst_ip = '8.8.8.8'  -- Change to destination IP
ORDER BY created_at DESC
LIMIT 20;
```

---

## Port Analysis

```sql
-- Most commonly used source ports
SELECT
    src_port,
    COUNT(*) as usage_count,
    COUNT(DISTINCT src_ip) as unique_sources,
    COUNT(DISTINCT dst_ip) as unique_destinations
FROM ebpf_events
WHERE event_type = 'connection' AND src_port > 0
GROUP BY src_port
ORDER BY usage_count DESC
LIMIT 20;
```

```sql
-- Most commonly targeted destination ports
SELECT
    dst_port,
    COUNT(*) as usage_count,
    COUNT(DISTINCT src_ip) as unique_sources,
    COUNT(DISTINCT dst_ip) as unique_destinations
FROM ebpf_events
WHERE event_type = 'connection' AND dst_port > 0
GROUP BY dst_port
ORDER BY usage_count DESC
LIMIT 20;
```

---

## Data Quality Report

```sql
-- Overall data quality report
SELECT
    COUNT(*) as total_events,
    COUNT(CASE WHEN src_ip IS NOT NULL THEN 1 END) as with_src_ip,
    COUNT(CASE WHEN src_port > 0 THEN 1 END) as with_src_port,
    COUNT(CASE WHEN dst_ip IS NOT NULL THEN 1 END) as with_dst_ip,
    COUNT(CASE WHEN dst_port > 0 THEN 1 END) as with_dst_port,
    COUNT(CASE WHEN interface_name IS NOT NULL AND interface_name != '' THEN 1 END) as with_interface,
    ROUND(100.0 * COUNT(CASE WHEN src_port > 0 AND interface_name != '' THEN 1 END) / NULLIF(COUNT(*), 0), 2) as complete_data_percent
FROM ebpf_events
WHERE event_type = 'connection';
```

---

## Real-time Monitoring Query

```sql
-- Top connections in the last hour
SELECT
    src_ip,
    src_port,
    dst_ip,
    dst_port,
    interface_name,
    COUNT(*) as connection_attempts,
    MAX(created_at) as last_attempt
FROM ebpf_events
WHERE event_type = 'connection'
  AND created_at > NOW() - INTERVAL '1 hour'
GROUP BY src_ip, src_port, dst_ip, dst_port, interface_name
ORDER BY connection_attempts DESC
LIMIT 20;
```

---

## Export Data to CSV

```sql
-- Export to CSV for analysis
\COPY (
    SELECT
        src_ip, src_port, dst_ip, dst_port, interface_name,
        protocol, command, created_at
    FROM ebpf_events
    WHERE event_type = 'connection'
    ORDER BY created_at DESC
) TO '/tmp/ebpf_connections.csv' WITH (FORMAT CSV, HEADER);
```

Then download the file:
```bash
cat /tmp/ebpf_connections.csv | head -20
```

---

## One-Liner Quick Checks

```bash
# Check total events
psql -h 127.0.0.1 -U ebpfagg -d ebpf_agg -c "SELECT COUNT(*) FROM ebpf_events WHERE event_type='connection'"

# Check events with src_port > 0
psql -h 127.0.0.1 -U ebpfagg -d ebpf_agg -c "SELECT COUNT(*) FROM ebpf_events WHERE event_type='connection' AND src_port > 0"

# Check unique interfaces
psql -h 127.0.0.1 -U ebpfagg -d ebpf_agg -c "SELECT DISTINCT interface_name FROM ebpf_events WHERE event_type='connection' AND interface_name != ''"

# Latest 5 events with all details
psql -h 127.0.0.1 -U ebpfagg -d ebpf_agg -c "SELECT src_ip, src_port, dst_ip, dst_port, interface_name FROM ebpf_events WHERE event_type='connection' ORDER BY created_at DESC LIMIT 5"
```

---

## Using psql with Formatting

```bash
# More readable output
psql -h 127.0.0.1 -U ebpfagg -d ebpf_agg -x -c "SELECT * FROM ebpf_events WHERE event_type='connection' LIMIT 1"

# Expanded display (one field per line)
psql -h 127.0.0.1 -U ebpfagg -d ebpf_agg -x -c "SELECT src_ip, src_port, dst_ip, dst_port, interface_name, created_at FROM ebpf_events LIMIT 5"

# Aligned columns
psql -h 127.0.0.1 -U ebpfagg -d ebpf_agg -A -c "SELECT src_ip, src_port, dst_ip, dst_port, interface_name FROM ebpf_events LIMIT 10"
```

