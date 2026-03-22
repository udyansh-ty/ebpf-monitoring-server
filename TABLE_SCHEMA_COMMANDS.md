# PostgreSQL Commands to Describe Table Schema

## Quick Commands

### **1. Show Table Structure (Most Common)**
```bash
psql -h 127.0.0.1 -U ebpfagg -d ebpf_agg -c "\d ebpf_meta_window"
```

**Output Shows:**
- Column names and data types
- Constraints (PRIMARY KEY, NOT NULL, DEFAULT)
- Indexes

---

### **2. Extended Format (More Detailed)**
```bash
psql -h 127.0.0.1 -U ebpfagg -d ebpf_agg -c "\d+ ebpf_meta_window"
```

**Shows Additional Info:**
- Storage size and access method
- Column defaults
- Whether nullable or not

---

### **3. Show Column Details Only**
```bash
psql -h 127.0.0.1 -U ebpfagg -d ebpf_agg -c "
SELECT
    column_name,
    data_type,
    is_nullable,
    column_default
FROM information_schema.columns
WHERE table_name = 'ebpf_meta_window'
ORDER BY ordinal_position;"
```

---

### **4. Show Constraints & Indexes**
```bash
psql -h 127.0.0.1 -U ebpfagg -d ebpf_agg -c "
SELECT constraint_name, constraint_type
FROM information_schema.table_constraints
WHERE table_name = 'ebpf_meta_window';"
```

---

### **5. Show All Indexes**
```bash
psql -h 127.0.0.1 -U ebpfagg -d ebpf_agg -c "\di+ ebpf_meta_window*"
```

---

### **6. Show Table Size**
```bash
psql -h 127.0.0.1 -U ebpfagg -d ebpf_agg -c "
SELECT
    pg_size_pretty(pg_total_relation_size('ebpf_meta_window')) as table_size,
    pg_size_pretty(pg_relation_size('ebpf_meta_window')) as data_size,
    pg_size_pretty(pg_indexes_size('ebpf_meta_window')) as indexes_size;"
```

---

## **Full Schema with SQL Definition**

```bash
psql -h 127.0.0.1 -U ebpfagg -d ebpf_agg -c "
SELECT pg_get_ddl('ebpf_meta_window'::regclass);"
```

Or view the actual CREATE TABLE statement:

```bash
psql -h 127.0.0.1 -U ebpfagg -d ebpf_agg -c "
SELECT
    'CREATE TABLE ebpf_meta_window (' ||
    array_to_string(
        array_agg(
            '  ' || column_name || ' ' || data_type ||
            CASE WHEN is_nullable = 'NO' THEN ' NOT NULL' ELSE '' END ||
            CASE WHEN column_default IS NOT NULL THEN ' DEFAULT ' || column_default ELSE '' END
        ),
        ',' || E'\n'
    ) || E'\n);'
FROM information_schema.columns
WHERE table_name = 'ebpf_meta_window'
ORDER BY ordinal_position;"
```

---

## **Expected Output (ebpf_meta_window structure)**

When you run `\d ebpf_meta_window`, you should see:

```
                    Table "public.ebpf_meta_window"
      Column      |  Type   | Collation | Nullable | Default
------------------+---------+-----------+----------+---------
 bucket_epoch     | bigint  |           | not null |
 src_ip           | inet    |           | not null |
 dst_ip           | inet    |           | not null |
 src_port         | integer |           | not null | 0
 dst_port         | integer |           | not null | 0
 interface_name   | text    |           | not null | ''::text
 sni              | text    |           | not null | ''::text
 active_seconds   | bigint  |           | not null | 0
 packets_in       | bigint  |           | not null | 0
 packets_out      | bigint  |           | not null | 0
 session_count    | bigint  |           | not null | 0
 first_seen_epoch | bigint  |           | not null |
 last_seen_epoch  | bigint  |           | not null |
Indexes:
    "ebpf_meta_window_pkey" PRIMARY KEY, btree (bucket_epoch, src_ip, dst_ip, src_port, dst_port, interface_name, sni)
    "idx_ebpf_meta_window_dst_ip" btree (dst_ip, bucket_epoch DESC)
    "idx_ebpf_meta_window_iface" btree (interface_name, bucket_epoch DESC)
    "idx_ebpf_meta_window_sni" btree (sni, bucket_epoch DESC)
    "idx_ebpf_meta_window_time" btree (bucket_epoch DESC)
```

---

## **Field Descriptions**

| Column | Type | Description |
|--------|------|-------------|
| `bucket_epoch` | BIGINT | Unix timestamp of the aggregation bucket (time window) |
| `src_ip` | INET | Source IP address (IPv4 or IPv6) |
| `dst_ip` | INET | Destination IP address (IPv4 or IPv6) |
| `src_port` | INT | Source port number |
| `dst_port` | INT | Destination port number |
| `interface_name` | TEXT | Network interface used (eth0, lo, enp0s3, etc.) |
| `sni` | TEXT | Server Name Indication (TLS hostname) |
| `active_seconds` | BIGINT | Total seconds connection was active |
| `packets_in` | BIGINT | Number of incoming packets |
| `packets_out` | BIGINT | Number of outgoing packets |
| `session_count` | BIGINT | Number of sessions/connections in this bucket |
| `first_seen_epoch` | BIGINT | Unix timestamp when first seen |
| `last_seen_epoch` | BIGINT | Unix timestamp when last seen |

---

## **One-Liner Commands**

```bash
# Just show columns and types
psql -h 127.0.0.1 -U ebpfagg -d ebpf_agg -c "\d ebpf_meta_window"

# Show with more details
psql -h 127.0.0.1 -U ebpfagg -d ebpf_agg -c "\d+ ebpf_meta_window"

# Export to file
psql -h 127.0.0.1 -U ebpfagg -d ebpf_agg -c "\d ebpf_meta_window" > /tmp/schema.txt

# Count rows
psql -h 127.0.0.1 -U ebpfagg -d ebpf_agg -c "SELECT COUNT(*) as row_count FROM ebpf_meta_window"

# Show sample data
psql -h 127.0.0.1 -U ebpfagg -d ebpf_agg -c "SELECT * FROM ebpf_meta_window LIMIT 5"
```

