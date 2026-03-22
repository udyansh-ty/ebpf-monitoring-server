#!/bin/bash
# Quick test script to verify src_port and interface_name fixes

set -e

echo "=== eBPF Monitoring - Source Port & Interface Fix Test ==="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "📝 Prerequisites:"
echo "1. PostgreSQL must be running with DB_URL set"
echo "2. Aggregator should be running (bin/ebpf-aggregator)"
echo "3. Server should be running (sudo bin/ebpf-server)"
echo ""

# Test 1: Check API response
echo "🔍 Test 1: Query API for connection events..."
RESPONSE=$(curl -s "http://127.0.0.1:8080/api/events?event_type=connection&limit=1")

if [ -z "$RESPONSE" ]; then
  echo -e "${RED}❌ No response from API${NC}"
  exit 1
fi

# Extract values (using simple grep/cut for portability)
SRC_PORT=$(echo "$RESPONSE" | grep -o '"src_port":[0-9]*' | head -1 | cut -d: -f2)
INTERFACE=$(echo "$RESPONSE" | grep -o '"interface_name":"[^"]*"' | head -1 | cut -d'"' -f4)

echo "  API Response:"
echo "  - src_port: ${SRC_PORT:-not found}"
echo "  - interface_name: ${INTERFACE:-not found}"
echo ""

# Test 2: Validate src_port is non-zero
if [ ! -z "$SRC_PORT" ] && [ "$SRC_PORT" != "0" ]; then
  echo -e "${GREEN}✅ src_port is non-zero: $SRC_PORT${NC}"
else
  echo -e "${YELLOW}⚠️  src_port is zero or missing${NC}"
fi

# Test 3: Validate interface_name is not empty
if [ ! -z "$INTERFACE" ]; then
  echo -e "${GREEN}✅ interface_name is populated: $INTERFACE${NC}"
else
  echo -e "${YELLOW}⚠️  interface_name is empty${NC}"
fi

echo ""
echo "📊 Test 2: Check PostgreSQL data..."

# Build psql command
PSQL_CMD="psql -t -c"
if [ ! -z "$DB_URL" ]; then
  # Parse connection string
  HOST=$(echo "$DB_URL" | grep -o 'localhost\|127.0.0.1\|[a-z0-9.-]*' | head -1)
  DBNAME=$(echo "$DB_URL" | grep -o 'ebpf[^?]*' | cut -d? -f1)

  echo "Connecting to: $DBNAME@$HOST"

  # Query non-zero src_port count
  SRCPORT_COUNT=$($PSQL_CMD "SELECT COUNT(*) FROM ebpf_events WHERE event_type='connection' AND src_port > 0;" 2>/dev/null || echo "0")
  TOTAL_COUNT=$($PSQL_CMD "SELECT COUNT(*) FROM ebpf_events WHERE event_type='connection';" 2>/dev/null || echo "0")

  INTERFACE_COUNT=$($PSQL_CMD "SELECT COUNT(*) FROM ebpf_events WHERE event_type='connection' AND interface_name IS NOT NULL AND interface_name != '';" 2>/dev/null || echo "0")

  echo "  Connection Events:"
  echo "  - Total: $TOTAL_COUNT"
  echo "  - With src_port > 0: $SRCPORT_COUNT"
  echo "  - With interface_name: $INTERFACE_COUNT"

  if [ "$SRCPORT_COUNT" -gt 0 ]; then
    echo -e "  ${GREEN}✅ Database has events with non-zero src_port${NC}"
  else
    echo -e "  ${YELLOW}⚠️  No events with src_port > 0 in database yet${NC}"
  fi

  if [ "$INTERFACE_COUNT" -gt 0 ]; then
    echo -e "  ${GREEN}✅ Database has events with interface_name${NC}"
  else
    echo -e "  ${YELLOW}⚠️  No events with interface_name in database yet${NC}"
  fi
else
  echo "  ${YELLOW}ℹ️  DB_URL not set, skipping PostgreSQL check${NC}"
fi

echo ""
echo "=== Test Complete ==="
