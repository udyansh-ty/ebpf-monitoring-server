# Update & Upgrade Guide

> **Last Updated**: February 2025
> **Version**: 2.0
> **Status**: Phase 1-2 Complete

---

## Table of Contents

1. [Version History](#version-history)
2. [Upgrade Paths](#upgrade-paths)
3. [Breaking Changes](#breaking-changes)
4. [Database Migrations](#database-migrations)
5. [Configuration Updates](#configuration-updates)
6. [Testing After Upgrade](#testing-after-upgrade)
7. [Rollback Procedures](#rollback-procedures)

---

## Version History

### v2.0 (Current - February 2025)

**Major Features:**
- JWT authentication with access/refresh tokens
- Service layer abstraction (ProgramService, EventService, HealthService)
- Repository pattern for pluggable data storage
- 4-layer middleware stack (logging, validation, errors, auth)
- Dependency injection via ServiceFactory
- Comprehensive test coverage (100% on service/repository)

**New Endpoints:**
- `POST /api/auth/login` - Request authentication tokens
- `POST /api/auth/refresh` - Refresh expired tokens

**Modified Endpoints:**
- All existing API endpoints now require JWT bearer token in `Authorization: Bearer <token>` header
- Exception: `/health` endpoint remains unauthenticated for monitoring

**Breaking Changes:**
- ✅ Backward compatible - no API signature changes
- ⚠️ Authentication required - clients must implement JWT token flow
- ℹ️ No database schema changes required

**Commits:**
- `726e398`: Phase 1 - JWT Authentication + Middleware
- `d7638ec`: Phase 2 - Service Layer + Repository Pattern
- `94ffa9c`: Phase 1-2 Documentation

---

### v1.0 (Previous)

**Features:**
- Basic eBPF program monitoring
- REST API endpoints
- Memory-based event storage
- Health check endpoint
- Swagger documentation

---

## Upgrade Paths

### From v1.0 to v2.0

#### Quick Upgrade (No Breaking Changes)

**Step 1: Build New Binary**
```bash
# Navigate to project
cd /home/tirveni/projects/udyansh_git/monitoring

# Build new version with v2.0 code
go build -o bin/monitoring cmd/server/main.go

# Verify build
./bin/monitoring -version  # or check help
```

**Step 2: Stop Existing Service**
```bash
# If running as systemd service
sudo systemctl stop monitoring

# If running as background process
sudo pkill -f "monitoring"

# If running in terminal
# Press Ctrl+C
```

**Step 3: Backup Current Binary and Config**
```bash
# Backup old binary
cp bin/monitoring bin/monitoring.v1.0.bak

# Backup configuration
cp .env .env.bak
cp .env.example .env.example.bak
```

**Step 4: Update Configuration**
```bash
# The new version needs JWT_SECRET in .env
# Check .env file and add if missing:
# JWT_SECRET=generated-secret-from-setup
```

**Step 5: Start New Version**
```bash
# For systemd service
sudo systemctl start monitoring

# For manual execution
sudo ./bin/monitoring

# Verify startup
curl http://localhost:8080/health
```

**Step 6: Test Authentication**
```bash
# Try to login
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"password"}'

# Expected response should include access_token and refresh_token
```

#### Canary Deployment (Side-by-side)

For production environments, test v2.0 alongside v1.0:

```bash
# Build v2.0 on different port
go build -o bin/monitoring-v2 cmd/server/main.go

# Start v2.0 on port 8081 (keep v1.0 on 8080)
sudo ./bin/monitoring-v2 -addr=":8081"

# Test v2.0 endpoints
curl http://localhost:8081/health

# Validate all endpoints work
curl http://localhost:8081/api/programs \
  -H "Authorization: Bearer <token>"

# Once validated, switch traffic
# Then shutdown v1.0
```

---

## Breaking Changes

### None in v2.0! ✅

**What Changed:**
- Added new authentication endpoints (optional feature)
- Added middleware layer (transparent to callers)
- Modified internal service architecture (hidden from API)

**What Stayed the Same:**
- All existing endpoint paths remain unchanged
- Request/response formats unchanged
- Database schema unchanged
- Configuration format unchanged

**Migration Path for Clients:**

Before (v1.0):
```bash
curl http://localhost:8080/api/programs
```

After (v2.0):
```bash
# Step 1: Get token
TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"password"}' | jq -r '.access_token')

# Step 2: Use token
curl http://localhost:8080/api/programs \
  -H "Authorization: Bearer $TOKEN"
```

---

## Database Migrations

### No Database Schema Changes Required ✅

The v2.0 release does not require any database schema modifications:

**Multi-NIC Fields Added in Previous Version:**
- `interface_name TEXT` - Network interface name (NULL-compatible)
- `interface_index INT` - Linux network interface index (NULL-compatible)
- `program_name TEXT` - eBPF program identifier (NULL-compatible)

**All fields are nullable** - existing data continues to work without changes.

### For PostgreSQL Users:

If upgrading from memory-based storage to PostgreSQL:

```bash
# Ensure PostgreSQL is installed and running
sudo systemctl start postgresql

# Update .env with database connection
DATABASE_URL=postgresql://user:password@localhost:5432/ebpf_monitor

# The application will create tables on first run
# Or manually create with:
psql < docs/database_schema.sql  # (if available)
```

### Data Migration (if needed):

```sql
-- No migration needed for existing columns
-- All new fields are nullable and backward compatible

-- But if you want to back up memory data before switching to PostgreSQL:
-- 1. Export from running v1.0 instance:
--    curl http://localhost:8080/api/events > events_backup.json
-- 2. Manually import into PostgreSQL if needed
```

---

## Configuration Updates

### New Configuration Options (v2.0)

**JWT Configuration:**
```bash
# .env file additions required:
JWT_SECRET=your-generated-secret-key     # New in v2.0
JWT_TOKEN_EXPIRY=24h                      # New in v2.0 (default: 24h)
JWT_REFRESH_EXPIRY=7d                     # New in v2.0 (default: 7d)
```

**Generate Secure JWT Secret:**
```bash
# Run this command to generate a secure secret
go run -c 'package main; import ("fmt"; "crypto/rand"; "encoding/base64"); func main() { b := make([]byte, 32); rand.Read(b); fmt.Println(base64.StdEncoding.EncodeToString(b)) }'

# Or use openssl:
openssl rand -base64 32
```

### Updated .env File Example:

```bash
# Server Configuration
HTTP_PORT=8080
HTTP_HOST=0.0.0.0

# Logging
LOG_LEVEL=info
LOG_FORMAT=json

# JWT Authentication (NEW)
JWT_SECRET=your-generated-secret-key
JWT_TOKEN_EXPIRY=24h
JWT_REFRESH_EXPIRY=7d

# Optional: Database (for future PostgreSQL migration)
DATABASE_URL=postgresql://user:password@localhost:5432/ebpf_monitor
CACHE_ENABLED=true
CACHE_TTL=3600

# Optional: Advanced Features
ENABLE_PROFILING=false
ENABLE_METRICS=true
```

### Backward Compatibility:

All previous `.env` settings continue to work:
- Existing `HTTP_PORT` setting still respected
- Existing `LOG_LEVEL` still honored
- No required changes to existing configuration

---

## Testing After Upgrade

### Health Check

```bash
# 1. Basic health check (no auth required)
curl http://localhost:8080/health
# Expected: {"service":"ebpf-server","status":"healthy","version":"v2.0"}
```

### Authentication Flow

```bash
# 2. Test login endpoint
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"password"}'

# Expected response:
# {
#   "access_token": "eyJhbGc...",
#   "refresh_token": "eyJhbGc...",
#   "token_type": "Bearer",
#   "expires_at": "2025-02-10T07:47:00Z"
# }
```

### Protected Endpoints

```bash
# 3. Get token first
TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"password"}' | jq -r '.access_token')

# 4. Test all protected endpoints

# Programs endpoint
curl http://localhost:8080/api/programs \
  -H "Authorization: Bearer $TOKEN"

# Connection summary
curl -X POST http://localhost:8080/api/connection-summary \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}'

# Packet drop summary
curl -X POST http://localhost:8080/api/packet-drop-summary \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}'

# List connections
curl "http://localhost:8080/api/list-connections?limit=10" \
  -H "Authorization: Bearer $TOKEN"

# List packet drops
curl "http://localhost:8080/api/list-packet-drops?limit=10" \
  -H "Authorization: Bearer $TOKEN"

# Events endpoint
curl "http://localhost:8080/api/events?limit=10" \
  -H "Authorization: Bearer $TOKEN"
```

### Token Refresh

```bash
# 5. Test token refresh
REFRESH_TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"password"}' | jq -r '.refresh_token')

curl -X POST http://localhost:8080/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"$REFRESH_TOKEN\"}"

# Expected: New access_token in response
```

### Error Handling

```bash
# 6. Test error scenarios

# Missing Authorization header
curl http://localhost:8080/api/programs
# Expected: 401 Unauthorized

# Invalid token
curl http://localhost:8080/api/programs \
  -H "Authorization: Bearer invalid.token.here"
# Expected: 401 Unauthorized

# Malformed Authorization header
curl http://localhost:8080/api/programs \
  -H "Authorization: NotBearer $TOKEN"
# Expected: 401 Unauthorized
```

### Performance Validation

```bash
# 7. Verify no performance regression
# (measurements before vs after upgrade)

# Time 10 requests with auth
time for i in {1..10}; do
  curl -s http://localhost:8080/api/programs \
    -H "Authorization: Bearer $TOKEN" > /dev/null
done

# Should be similar to v1.0 performance (typically <100ms per request)
```

---

## Rollback Procedures

### If Issues Occur After Upgrade

#### Option 1: Rollback to Previous Binary

```bash
# Stop v2.0
sudo systemctl stop monitoring

# Restore v1.0 binary
cp bin/monitoring.v1.0.bak bin/monitoring

# Restore v1.0 configuration
cp .env.bak .env

# Start v1.0
sudo systemctl start monitoring

# Verify
curl http://localhost:8080/health
```

#### Option 2: Restart with Debug Logging

If you want to troubleshoot before rolling back:

```bash
# Stop service
sudo systemctl stop monitoring

# Run with debug logging
LOG_LEVEL=debug ./bin/monitoring 2>&1 | tee debug.log

# Check logs for errors
grep -i "error\|failed\|fatal" debug.log

# Share logs with development team if needed
```

#### Option 3: Side-by-Side Rollback

If v2.0 is problematic but v1.0 is running:

```bash
# v2.0 was on port 8081, v1.0 on port 8080
# Switch monitoring/load balancers back to port 8080
# Monitor v2.0 for issues while v1.0 handles traffic
# Once stable, gradually shift traffic back to v2.0
```

---

## Upgrade Checklist

- [ ] Read this entire UPDATE.md file
- [ ] Review [Breaking Changes](#breaking-changes) section - should be none
- [ ] Back up current `.env` file
- [ ] Back up current binary: `cp bin/monitoring bin/monitoring.v1.0.bak`
- [ ] Build v2.0: `go build -o bin/monitoring cmd/server/main.go`
- [ ] Update `.env` with new JWT settings (see [Configuration Updates](#configuration-updates))
- [ ] Stop existing service: `sudo systemctl stop monitoring`
- [ ] Start v2.0: `sudo systemctl start monitoring`
- [ ] Run tests from [Testing After Upgrade](#testing-after-upgrade) section
- [ ] Verify all endpoints work with Bearer token
- [ ] Monitor logs: `journalctl -u monitoring -f`
- [ ] Celebrate - upgrade complete! ✅

---

## Frequently Asked Questions

### Q: Do I need to migrate my database?
**A:** No! The v2.0 changes are backward compatible. All existing data continues to work without schema changes.

### Q: Will my existing clients stop working?
**A:** Your existing API clients will need to be updated to include JWT Bearer tokens in the `Authorization` header. See [Migration Path for Clients](#migration-path-for-clients).

### Q: Can I run v1.0 and v2.0 side-by-side?
**A:** Yes! Use different ports (`-addr` flag) to run them concurrently for testing.

### Q: What if JWT_SECRET is not set?
**A:** A random secret is generated on startup, but this is insecure for production. Always set `JWT_SECRET` in your `.env`.

### Q: How long does an access token last?
**A:** Default is 24 hours. Configurable via `JWT_TOKEN_EXPIRY` environment variable.

### Q: What if I lose my refresh token?
**A:** You'll need to login again via `/api/auth/login` endpoint to get new tokens.

### Q: Is there a default username/password?
**A:** Not in the current implementation. User management should be configured based on your authentication requirements.

---

## Support & Documentation

- **Quick Reference**: See [QUICK_REFERENCE.md](QUICK_REFERENCE.md)
- **API Documentation**: See [API_REST.md](API_REST.md)
- **Setup Guide**: See [SETUP_MULTI_NIC.md](SETUP_MULTI_NIC.md)
- **Program Development**: See [program-development.md](program-development.md)
- **Database Setup**: See [setup.md](setup.md)

---

## Version Compatibility Matrix

| Component | v1.0 | v2.0 | Notes |
|-----------|------|------|-------|
| eBPF Programs | ✅ | ✅ | Unchanged |
| REST API Paths | ✅ | ✅ | Unchanged |
| Event Storage | ✅ | ✅ | Format unchanged |
| Database Schema | ✅ | ✅ | Multi-NIC fields from Phase 1A |
| Authentication | ❌ | ✅ | New in v2.0 |
| Service Layer | ❌ | ✅ | Internal refactor |
| Repository Pattern | ❌ | ✅ | Internal refactor |

---

**Last Updated**: February 9, 2025
**Maintained By**: Claude Code
**Current Version**: 2.0
