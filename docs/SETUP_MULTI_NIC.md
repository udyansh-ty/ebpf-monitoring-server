# eBPF Network Monitor - Multi-NIC Setup Guide

**Version:** 1.0
**Date:** February 8, 2026
**Target:** Complete multi-network interface monitoring with eBPF

---

## Table of Contents

1. [Overview](#overview)
2. [System Requirements](#system-requirements)
3. [Package Dependencies](#package-dependencies)
4. [Configuration Requirements](#configuration-requirements)
5. [Resource Requirements](#resource-requirements)
6. [Installation Guide](#installation-guide)
7. [Multi-NIC Configuration](#multi-nic-configuration)
8. [Verification & Testing](#verification--testing)
9. [Troubleshooting](#troubleshooting)
10. [Performance Tuning](#performance-tuning)

---

## Overview

The eBPF Network Monitor is a modular system designed to capture and analyze network events from multiple NICs simultaneously using eBPF programs running in kernel space. It provides:

- **Multi-NIC Monitoring**: Simultaneous capture from all network interfaces
- **Real-time Data**: Live event streaming from kernel to userspace
- **eBPF Programs**: Lightweight kernel-space modules for packet/connection analysis
- **Persistent Storage**: PostgreSQL backend for event data retention
- **REST API**: HTTP interface for querying events and statistics
- **JWT Authentication**: Secured endpoints with token-based access
- **Middleware Stack**: Request validation, logging, and error handling
- **Service Layer**: Clean abstraction for business logic
- **Repository Pattern**: Flexible data access abstraction

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ REST API Server (HTTP)                                          │
│ ├─ Middleware Stack (Auth, Logging, Validation, Errors)        │
│ ├─ Service Layer (ProgramService, EventService, HealthService) │
│ ├─ Repository Layer (EventRepository)                          │
│ └─ Handler Functions (API endpoints)                           │
└────────────────────────┬────────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────────┐
│ eBPF Program Manager                                            │
│ ├─ Connection Tracer (monitors TCP/UDP connections)            │
│ ├─ Packet Drop Monitor (captures packet drop events)           │
│ └─ Traffic Control Classifier (multi-NIC flow capture)         │
└────────────────────────┬────────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────────┐
│ Linux Kernel (eBPF Subsystem)                                   │
│ ├─ eth0 (Monitored)                                            │
│ ├─ eth1 (Monitored)                                            │
│ └─ wlan0 (Monitored)                                           │
└────────────────────────┬────────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────────┐
│ Data Storage                                                    │
│ ├─ PostgreSQL (Persistent storage)                             │
│ ├─ Memory Repository (Optional, development)                   │
│ └─ Event logs (Persistent)                                     │
└─────────────────────────────────────────────────────────────────┘
```

---

## System Requirements

### Minimum Specifications

| Component | Requirement |
|-----------|------------|
| **CPU** | 2+ cores |
| **RAM** | 2GB minimum, 4GB+ recommended |
| **Disk** | 10GB+ for PostgreSQL |
| **Network** | Ethernet (monitored NICs) |
| **Architecture** | x86_64 (ARM support in future) |

### Operating System

**Supported Distributions:**
- Ubuntu 18.04+
- Ubuntu 20.04 LTS (recommended)
- Ubuntu 22.04 LTS (recommended)
- Debian 10+
- CentOS 8+
- RHEL 8+
- Fedora 30+

### Linux Kernel Requirements

**Minimum Kernel Version:** 4.18+
**Recommended:** 5.8+ (better eBPF support)

**Required Kernel Features:**

```bash
# Check kernel version
uname -r

# Verify eBPF support
zgrep CONFIG_BPF_SYSCALL /proc/config.gz         # Must be y
zgrep CONFIG_BPF_JIT /proc/config.gz             # Should be y
zgrep CONFIG_HAVE_EBPF_JIT /proc/config.gz       # Should be y
zgrep CONFIG_DEBUG_INFO_BTF /proc/config.gz      # Recommended

# Verify kprobes support (for connection tracing)
zgrep CONFIG_KPROBES /proc/config.gz             # Must be y
zgrep CONFIG_KPROBES_ON_FTRACE /proc/config.gz   # Recommended

# Verify tracepoints support
zgrep CONFIG_TRACEPOINTS /proc/config.gz         # Must be y
```

**Alternative verification (if /proc/config.gz doesn't exist):**

```bash
# Ubuntu/Debian
grep "CONFIG_BPF_SYSCALL=y" /boot/config-$(uname -r)

# RHEL/CentOS/Fedora
grep "CONFIG_BPF_SYSCALL=y" /boot/config-$(uname -r)
```

### User Privileges

- **Root or sudo access required** for:
  - eBPF program loading
  - Network interface monitoring
  - Port binding (ports < 1024)

- **Running without root** (custom ports):
  - Use port 8080+ (default is 8080)
  - Not recommended for production

---

## Package Dependencies

### Build Dependencies (Required)

#### Ubuntu/Debian

```bash
# Update package lists
sudo apt update

# Install build dependencies
sudo apt install -y \
    golang-go \
    golang-1.23-go \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-$(uname -r) \
    build-essential \
    pkg-config \
    git \
    make \
    curl \
    wget

# Verify installations
go version          # Should be >= 1.19
clang --version     # Should be >= 10
llvm-config --version

# Check libbpf
pkg-config --modversion libbpf
```

#### CentOS/RHEL 8+

```bash
# Enable PowerTools repository (RHEL 8)
sudo dnf install -y dnf-plugins-core
sudo dnf config-manager --set-enabled PowerTools

# Install build dependencies
sudo dnf install -y \
    golang \
    clang \
    llvm \
    libbpf-devel \
    kernel-headers \
    kernel-devel \
    make \
    git \
    pkg-config \
    curl

# Verify installations
go version
clang --version
```

#### Fedora

```bash
# Install build dependencies
sudo dnf install -y \
    golang \
    clang \
    llvm \
    libbpf-devel \
    kernel-headers \
    kernel-devel \
    make \
    git \
    pkg-config \
    curl

# Verify installations
go version
clang --version
```

### Runtime Dependencies

#### PostgreSQL Database

**Install PostgreSQL Server:**

```bash
# Ubuntu/Debian
sudo apt install -y postgresql postgresql-contrib

# Start and enable PostgreSQL
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Verify installation
sudo -u postgres psql --version
```

**CentOS/RHEL:**

```bash
sudo dnf install -y postgresql-server postgresql-contrib

# Initialize database
sudo /usr/pgsql-13/bin/postgresql-13-setup initdb

# Start and enable PostgreSQL
sudo systemctl start postgresql-13
sudo systemctl enable postgresql-13
```

**Verify PostgreSQL:**

```bash
# Connect to PostgreSQL
sudo -u postgres psql

# Create monitoring database
CREATE DATABASE monitoring;
CREATE USER monitor WITH PASSWORD 'change_me';
ALTER ROLE monitor WITH CREATEDB;
GRANT ALL PRIVILEGES ON DATABASE monitoring TO monitor;

# Verify (inside psql)
\l                 # List databases
\du                # List users
\q                 # Exit psql
```

#### Optional: Development Tools

```bash
# eBPF debugging tools
sudo apt install -y \
    bpftool \
    linux-tools-common \
    linux-tools-$(uname -r) \
    perf-tools-unstable

# Network analysis tools
sudo apt install -y \
    tcpdump \
    wireshark \
    netcat-openbsd \
    net-tools \
    iproute2

# System monitoring
sudo apt install -y \
    sysstat \
    htop \
    iotop \
    dstat
```

### Go Dependencies

All Go dependencies are managed via `go.mod`:

```bash
# View dependencies
go mod graph

# Key dependencies:
# - github.com/cilium/ebpf v0.19.0 (eBPF loader)
# - github.com/golang-jwt/jwt/v5 v5.2.0 (JWT auth)
# - github.com/jackc/pgx/v4 v4.18.3 (PostgreSQL driver)
# - github.com/swaggo/swag (Swagger documentation)

# Download dependencies
go mod download

# Verify dependencies
go mod verify
```

---

## Configuration Requirements

### Environment Variables

Create `.env` file from template:

```bash
cp .env.example .env
```

**Configuration Template (.env.example):**

```bash
# ========================================
# Server Configuration
# ========================================

SERVER_ADDR=:8080
LOG_LEVEL=info
LOG_FORMAT=text

# ========================================
# Database Configuration
# ========================================

# PostgreSQL connection (required for persistent storage)
DB_URL=postgres://monitor:change_me@localhost:5432/monitoring?sslmode=disable

# ========================================
# JWT Authentication Configuration
# ========================================

JWT_SECRET=your-secure-secret-key-change-this
JWT_EXPIRY=24h
JWT_REFRESH_EXPIRY=168h
JWT_ALGORITHM=HS256

# ========================================
# Cache Configuration
# ========================================

CACHE_TTL=5m
REDIS_URL=redis://localhost:6379  # Optional

# ========================================
# eBPF Configuration
# ========================================

# Flow cache TTL for multi-NIC capture
FLOW_CACHE_TTL=5m

# Disable enrichment if needed
DISABLE_ENRICHER=false

# ========================================
# K8s Aggregator (Optional)
# ========================================

AGGREGATOR_ADDR=:8081
AGGREGATOR_DB_URL=postgres://monitor:change_me@localhost:5432/monitoring
FLOW_CACHE_TTL=5m
DISABLE_ENRICHER=false

# ========================================
# HTTP Server Tuning
# ========================================

HTTP_READ_TIMEOUT=15s
HTTP_WRITE_TIMEOUT=15s
HTTP_MAX_HEADER_BYTES=1048576
```

### File System Requirements

**Project Structure:**

```
monitoring/
├── cmd/
│   ├── server/
│   │   └── main.go           # Server entry point
│   └── ebpf-server           # Compiled binary (created after build)
├── internal/
│   ├── api/                  # HTTP handlers
│   ├── auth/                 # JWT authentication
│   ├── middleware/           # HTTP middleware
│   ├── service/              # Business logic services
│   ├── repository/           # Data access layer
│   ├── events/               # Event types
│   ├── programs/             # eBPF program wrappers
│   ├── storage/              # Database operations
│   ├── system/               # Core system
│   └── core/                 # Core interfaces
├── pkg/
│   └── logger/               # Logging utilities
├── docs/
│   ├── setup.md              # Setup guide
│   ├── SETUP_MULTI_NIC.md    # This file
│   ├── UPDATE.md             # Update guide
│   ├── QUICK_REFERENCE.md    # Quick reference
│   └── API_REST.md           # REST API documentation
├── ebpf/
│   └── *.c, *.o              # eBPF source and compiled bytecode
├── Makefile                  # Build automation
├── go.mod, go.sum            # Go dependencies
└── .env.example              # Configuration template
```

**Directories to Create:**

```bash
# Data directory for BPF files
mkdir -p /var/lib/ebpf-monitor
sudo chown $(whoami): /var/lib/ebpf-monitor

# Logs directory
mkdir -p /var/log/ebpf-monitor
sudo chown $(whoami): /var/log/ebpf-monitor

# Configuration directory
mkdir -p /etc/ebpf-monitor
```

---

## Resource Requirements

### CPU Usage

| Scenario | CPU Impact | Notes |
|----------|-----------|-------|
| Idle (no traffic) | <1% (1 core) | Minimal overhead |
| Light traffic (1 Gbps) | 5-10% (1-2 cores) | Normal usage |
| Heavy traffic (10 Gbps) | 30-50% (2-4 cores) | Sustained heavy load |
| Peak traffic (20+ Gbps) | 50-80% (4-8 cores) | Burst handling |

**Recommendation:** Use systems with 4+ cores for production multi-NIC setups.

### Memory Usage

| Component | Memory |
|-----------|--------|
| eBPF programs (all) | 10-50 MB |
| Event buffer (in-memory) | 50-200 MB |
| Go runtime | 100-300 MB |
| PostgreSQL (idle) | 50-100 MB |
| PostgreSQL (indexed) | 500 MB - 5 GB |
| **Total (light load)** | **300-500 MB** |
| **Total (heavy load)** | **1-3 GB** |

**Recommendation:** 4GB RAM minimum, 8GB+ for production with high event rate.

### Disk Usage

| Component | Space |
|-----------|-------|
| Binary + code | 50-100 MB |
| eBPF bytecode | 5-10 MB |
| PostgreSQL (empty) | 50 MB |
| PostgreSQL (1M events) | 500 MB - 1 GB |
| PostgreSQL (1B events) | 500 GB - 1 TB |
| Log files (7 days) | 100-500 MB |

**Recommendation:**
- Development: 10GB minimum
- Production: 100GB+ depending on retention

### Network Requirements

**For Monitoring Itself:**

- **API Server Port:** 8080 (configurable)
- **Database Port:** 5432 (PostgreSQL, localhost)
- **Bandwidth:** Minimal for API calls (<1 Mbps)

**For Monitored Interfaces:**

- All network interfaces are monitored at kernel level
- No additional bandwidth needed for monitoring

### Concurrent Connections

| Limit | Value |
|-------|-------|
| Max API connections | 1000+ |
| Max event buffer | 100,000+ |
| Max database connections | 20 (configurable) |
| Max eBPF maps | 10+ per program |

---

## Installation Guide

### Step 1: System Preparation

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install build dependencies (see Package Dependencies section)
sudo apt install -y golang-go clang llvm libbpf-dev \
    linux-headers-$(uname -r) build-essential

# Verify versions
go version          # >= 1.19
clang --version     # >= 10
```

### Step 2: Clone Repository

```bash
# Clone the repository
git clone https://github.com/srodi/ebpf-server.git
cd ebpf-server

# Verify structure
ls -la                  # Should show Makefile, go.mod, ebpf/, internal/, etc.
```

### Step 3: Set Up PostgreSQL

```bash
# Install PostgreSQL
sudo apt install -y postgresql postgresql-contrib

# Start PostgreSQL
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Create database and user
sudo -u postgres psql << EOF
CREATE DATABASE monitoring;
CREATE USER monitor WITH PASSWORD 'secure_password';
ALTER ROLE monitor WITH CREATEDB;
GRANT ALL PRIVILEGES ON DATABASE monitoring TO monitor;
EOF

# Verify connection
psql -h localhost -U monitor -d monitoring -c "SELECT version();"
```

### Step 4: Configure Environment

```bash
# Copy configuration template
cp .env.example .env

# Edit configuration
nano .env

# Set these values:
# - DB_URL=postgres://monitor:secure_password@localhost:5432/monitoring?sslmode=disable
# - JWT_SECRET=your-secure-random-string (generate: openssl rand -base64 32)
# - SERVER_ADDR=:8080
# - LOG_LEVEL=info

# Verify configuration
cat .env | grep -v "^#" | grep -v "^$"
```

### Step 5: Build eBPF Programs

```bash
# Build eBPF bytecode
make build-bpf

# Verify eBPF files
ls -la ebpf/*.o       # Should show compiled .o files
```

### Step 6: Build Go Server

```bash
# Build the server
make build

# Verify binary
ls -la ./bin/ebpf-server
file ./bin/ebpf-server

# Or for development with debug logging:
make build-dev
```

### Step 7: Run the Server

```bash
# Run with sudo (required for eBPF)
sudo -E ./bin/ebpf-server

# Or with custom configuration:
sudo -E ./bin/ebpf-server -addr :8080

# Verify server is running:
# In another terminal:
curl http://localhost:8080/health
```

### Step 8: Verify Installation

```bash
# Check health endpoint
curl -s http://localhost:8080/health | jq .

# Expected output:
# {
#   "status": "healthy",
#   "component": "eBPF Monitor API",
#   "uptime": "active",
#   "version": "1.0.0"
# }

# Get JWT token for testing
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"password"}' | jq .

# Query events (requires valid token)
# Replace TOKEN with the access_token from login response
curl http://localhost:8080/api/events \
  -H "Authorization: Bearer TOKEN" | jq .
```

---

## Multi-NIC Configuration

### Understanding Multi-NIC Monitoring

The eBPF Network Monitor automatically detects and monitors all network interfaces on the system. Each interface is monitored independently, with events tagged with interface information.

### Listing Network Interfaces

```bash
# Show all network interfaces
ip link show

# Show interface details
ip addr show

# Filter specific interfaces
ip link show | grep "^[0-9]:" | awk '{print $2}'

# Example output:
# lo: (loopback)
# eth0: (primary interface)
# eth1: (secondary interface)
# wlan0: (wireless interface)
```

### Configuring Network Interfaces for Monitoring

**Option 1: Default (Monitor All)**

By default, all interfaces are monitored. No special configuration needed:

```bash
# Just run the server
sudo -E ./bin/ebpf-server

# It will automatically detect and monitor:
# - Wired interfaces (eth0, eth1, etc.)
# - Wireless interfaces (wlan0, wlan1, etc.)
# - Virtual interfaces (veth*, docker*, etc.)
```

**Option 2: Selective Monitoring (Future Enhancement)**

Currently, all interfaces are monitored. Per-interface configuration is planned for Phase 1C.

### Verifying Multi-NIC Capture

```bash
# Get all monitored programs
curl -s http://localhost:8080/api/programs \
  -H "Authorization: Bearer TOKEN" | jq .

# Get connection summary (multi-NIC)
curl -s "http://localhost:8080/api/connection-summary?pid=1234" \
  -H "Authorization: Bearer TOKEN" | jq .

# Get packet drop summary (multi-NIC)
curl -s "http://localhost:8080/api/packet-drop-summary?pid=1234" \
  -H "Authorization: Bearer TOKEN" | jq .

# List connections with interface information
curl -s "http://localhost:8080/api/list-connections?limit=10" \
  -H "Authorization: Bearer TOKEN" | jq '.results[] | {interface_name, src_ip, dst_ip}'
```

### Database Schema for Multi-NIC

The PostgreSQL schema includes multi-NIC fields:

```sql
CREATE TABLE ebpf_events (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    pid BIGINT NOT NULL,
    command TEXT NOT NULL,

    -- Multi-NIC Fields
    interface_name TEXT,          -- "eth0", "eth1", "wlan0", etc.
    interface_index INT,          -- Linux interface index
    program_name TEXT NOT NULL,   -- "connection_tracer", "packet_drop_monitor"

    -- Connection Information
    src_ip INET,
    dst_ip INET,
    src_port INT,
    dst_port INT,
    protocol TEXT,

    -- Other fields...
    observed_at TIMESTAMP DEFAULT NOW(),

    -- Indexes for multi-NIC queries
    INDEX idx_interface_time (interface_name, observed_at DESC),
    INDEX idx_program_time (program_name, observed_at DESC)
);
```

---

## Verification & Testing

### Health Check

```bash
# 1. Check server health
curl -s http://localhost:8080/health | jq .

# Expected status: "healthy"
```

### Authentication Testing

```bash
# 1. Login to get token
TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"password"}' | jq -r '.access_token')

echo "Token: $TOKEN"

# 2. Test token refresh
curl -s -X POST http://localhost:8080/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"'$REFRESH_TOKEN'"}' | jq .
```

### API Testing

```bash
# Set token variable
TOKEN="your-token-here"

# 1. Get programs
curl -s http://localhost:8080/api/programs \
  -H "Authorization: Bearer $TOKEN" | jq .

# 2. Get connection summary
curl -s http://localhost:8080/api/connection-summary \
  -H "Authorization: Bearer $TOKEN" | jq .

# 3. Get packet drop summary
curl -s http://localhost:8080/api/packet-drop-summary \
  -H "Authorization: Bearer $TOKEN" | jq .

# 4. List connections
curl -s "http://localhost:8080/api/list-connections?limit=5" \
  -H "Authorization: Bearer $TOKEN" | jq '.results[0]'

# 5. List packet drops
curl -s "http://localhost:8080/api/list-packet-drops?limit=5" \
  -H "Authorization: Bearer $TOKEN" | jq '.results[0]'

# 6. Get raw events
curl -s "http://localhost:8080/api/events?limit=5" \
  -H "Authorization: Bearer $TOKEN" | jq '.events[0]'
```

### Multi-NIC Verification

```bash
# Verify interfaces are being captured
curl -s "http://localhost:8080/api/list-connections?limit=20" \
  -H "Authorization: Bearer $TOKEN" | \
  jq '.results[] | select(.interface_name != null) | {interface_name, src_ip, dst_ip}'

# Count events per interface
curl -s "http://localhost:8080/api/list-connections?limit=100" \
  -H "Authorization: Bearer $TOKEN" | \
  jq '[.results[] | .interface_name] | group_by(.) | map({interface: .[0], count: length})'
```

### Database Verification

```bash
# Connect to PostgreSQL
psql -h localhost -U monitor -d monitoring

# Check events table exists
\dt ebpf_events

# Count total events
SELECT COUNT(*) as total_events FROM ebpf_events;

# Show events by interface
SELECT interface_name, COUNT(*) as count
FROM ebpf_events
WHERE interface_name IS NOT NULL
GROUP BY interface_name;

# Show events by program
SELECT program_name, COUNT(*) as count
FROM ebpf_events
GROUP BY program_name;

# Show recent events
SELECT id, event_type, interface_name, src_ip, dst_ip, observed_at
FROM ebpf_events
ORDER BY observed_at DESC
LIMIT 10;
```

---

## Troubleshooting

### Common Issues

#### 1. "Permission Denied" Running eBPF Programs

**Problem:** Server exits with permission error when loading eBPF programs

**Solution:**
```bash
# Run with sudo
sudo -E ./bin/ebpf-server

# Or add current user to required groups (not recommended for production)
sudo usermod -aG bpf,perf_users $USER
newgrp bpf
```

#### 2. "CONFIG_BPF_SYSCALL Not Enabled"

**Problem:** Kernel doesn't support eBPF

**Solution:**
```bash
# Check kernel config
zgrep CONFIG_BPF_SYSCALL /proc/config.gz

# If not enabled, need to rebuild kernel with BPF support
# Or upgrade to newer kernel version
uname -r  # Check current version
```

#### 3. PostgreSQL Connection Fails

**Problem:** "failed to connect to database"

**Solution:**
```bash
# Verify PostgreSQL is running
sudo systemctl status postgresql

# Check connection string in .env
psql -h localhost -U monitor -d monitoring

# Verify database and user exist
sudo -u postgres psql -c "\du"
sudo -u postgres psql -c "\l"

# Check PostgreSQL is listening
sudo netstat -tuln | grep 5432
```

#### 4. Port Already in Use

**Problem:** "bind: address already in use"

**Solution:**
```bash
# Find process using port 8080
lsof -i :8080

# Kill the process
kill -9 <PID>

# Or use different port
./bin/ebpf-server -addr :8081
```

#### 5. JWT Token Invalid

**Problem:** "invalid token" when making API calls

**Solution:**
```bash
# Generate new token
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"password"}'

# Use new token in requests
curl http://localhost:8080/api/events \
  -H "Authorization: Bearer NEW_TOKEN"

# Check token expiry in .env
cat .env | grep JWT_EXPIRY
```

### Debugging

#### Enable Debug Logging

```bash
# Set log level in .env
LOG_LEVEL=debug

# Restart server
sudo -E ./bin/ebpf-server

# Watch logs
tail -f /var/log/ebpf-monitor/*.log
```

#### Check eBPF Program Status

```bash
# List loaded BPF programs
sudo bpftool prog list

# List BPF maps
sudo bpftool map list

# Inspect specific program
sudo bpftool prog show id <ID>

# Dump map contents
sudo bpftool map dump id <ID>
```

#### Monitor System Resources

```bash
# CPU and memory usage
top -b -n 1 | grep ebpf-server

# Network interface stats
ip -s link show

# eBPF memory usage
sudo bpftool map show

# System calls (if available)
sudo strace -e trace=network ./bin/ebpf-server
```

---

## Performance Tuning

### Kernel Parameters

```bash
# Increase BPF memory limit (if needed)
sudo sysctl -w kernel.bpf_stats_enabled=1

# Increase max locked memory for eBPF
sudo sysctl -w net.core.rmem_max=134217728
sudo sysctl -w net.core.wmem_max=134217728

# Increase perf buffer size
sudo sysctl -w kernel.perf_event_paranoid=0

# Make changes persistent
echo "net.core.rmem_max=134217728" | sudo tee -a /etc/sysctl.conf
echo "net.core.wmem_max=134217728" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### Application Configuration

```bash
# In .env file:

# Increase flow cache TTL for better performance
FLOW_CACHE_TTL=10m

# Optimize cache TTL
CACHE_TTL=10m

# Increase HTTP timeouts for heavy loads
HTTP_READ_TIMEOUT=30s
HTTP_WRITE_TIMEOUT=30s

# Increase max header bytes if needed
HTTP_MAX_HEADER_BYTES=2097152  # 2MB
```

### Database Optimization

```sql
-- Create indexes for multi-NIC queries
CREATE INDEX idx_ebpf_events_interface
  ON ebpf_events(interface_name, observed_at DESC);

CREATE INDEX idx_ebpf_events_program
  ON ebpf_events(program_name, observed_at DESC);

CREATE INDEX idx_ebpf_events_src_ip
  ON ebpf_events(src_ip);

CREATE INDEX idx_ebpf_events_dst_ip
  ON ebpf_events(dst_ip);

-- Vacuum and analyze
VACUUM ANALYZE ebpf_events;

-- Check index usage
SELECT schemaname, tablename, indexname, idx_scan
FROM pg_stat_user_indexes
WHERE tablename = 'ebpf_events';
```

### Connection Pooling

The application uses connection pooling. Configure in code if needed:

```go
// internal/storage/storage.go
// Default: 20 connections
// Adjust based on load and system resources
```

---

## Next Steps

1. **[API Documentation](API_REST.md)** - Learn how to use the REST API
2. **[Quick Reference](QUICK_REFERENCE.md)** - Common commands and tasks
3. **[Update Guide](UPDATE.md)** - How to update the application
4. **[Kubernetes Deployment](../kubernetes/README.md)** - Deploy to Kubernetes

---

## Support

For issues and questions:
- Check [Troubleshooting](#troubleshooting) section above
- Review application logs in `/var/log/ebpf-monitor/`
- Check PostgreSQL logs: `sudo journalctl -u postgresql`
- Review eBPF status: `sudo bpftool prog list`

---

**Document Version:** 1.0
**Last Updated:** February 8, 2026
**Status:** Complete for Phase 1-2
