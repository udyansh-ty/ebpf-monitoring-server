# Authentication

The eBPF Monitor API uses **JWT (JSON Web Token)** based Bearer token authentication for all endpoints except `/health` and the auth endpoints themselves.

---

## Authentication Flow

1. **Login** — Send credentials to get an access token
2. **Use Token** — Include the token in the `Authorization` header for API requests
3. **Refresh** — When the token expires, use the refresh token to get a new one

---

## Step 1: Login and Get Token

**Endpoint:** `POST /api/auth/login`

**Request:**
```bash
curl -X POST http://localhost:7070/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "admin123"
  }'
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_at": "2024-01-15T11:30:00Z",
  "token_type": "Bearer"
}
```

> **Note:** In development mode, any non-empty username and password are accepted. In production, integrate with a user database.

---

## Step 2: Use Token for API Requests

Include the `access_token` in the `Authorization` header:

```bash
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

curl http://localhost:7070/api/events \
  -H "Authorization: Bearer $TOKEN"
```

**Example workflow:**

```bash
# 1. Login and extract token
TOKEN=$(curl -s -X POST http://localhost:7070/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}' | jq -r '.access_token')

echo "Token: $TOKEN"

# 2. Use token to query API
curl "http://localhost:7070/api/events?limit=5" \
  -H "Authorization: Bearer $TOKEN" | jq .
```

---

## Step 3: Refresh Token (When Expired)

**Endpoint:** `POST /api/auth/refresh`

When your access token expires, use the refresh token to get a new one:

```bash
curl -X POST http://localhost:7070/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }'
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_at": "2024-01-15T11:30:00Z",
  "token_type": "Bearer"
}
```

---

## Token Expiration

Tokens include expiration information in the JWT claims:

```bash
# Decode token to see expiration (install jq)
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

echo $TOKEN | jq -R 'split(".")[1] | @base64d | fromjson'
```

**Output:**
```json
{
  "user_id": "admin",
  "username": "admin",
  "roles": ["user"],
  "token_use": "access",
  "exp": 1705320600,
  "iat": 1705317000,
  "nbf": 1705317000,
  "sub": "admin"
}
```

---

## Error Handling

**Missing Authorization Header:**
```bash
curl http://localhost:7070/api/events
# {"error":"missing authorization header"}
```

**Invalid Token:**
```bash
curl http://localhost:7070/api/events \
  -H "Authorization: Bearer invalid_token"
# {"error":"invalid token: failed to parse token: token is malformed"}
```

**Expired Token:**
```bash
# Use the refresh token endpoint to get a new access token
curl -X POST http://localhost:7070/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"..."}'
```

---

## Development vs Production

| Mode | Credentials | User Database | Token Secret |
|------|-------------|---------------|--------------|
| **Development** | Any non-empty username/password | None (all accepted) | Auto-generated from env |
| **Production** | Validated against user database | Required (SQL, LDAP, etc.) | Hardened secret key |

### Configure Token Secret

Set the `JWT_SECRET` environment variable:

```bash
export JWT_SECRET="your-very-secure-secret-key-here"
sudo ./bin/ebpf-server
```

Or use the config file. See `internal/auth/config.go` for details.

---

## Token Lifetime

Default token lifetimes (configurable):

- **Access Token:** 1 hour
- **Refresh Token:** 7 days

To extend token lifetime in production, update `internal/auth/config.go` and rebuild.

---

## Security Best Practices

1. **Keep tokens private** — Never commit tokens to version control
2. **Use HTTPS in production** — Tokens can be intercepted over HTTP
3. **Rotate secrets regularly** — Change `JWT_SECRET` periodically
4. **Validate refresh tokens** — Don't allow refresh after expiration
5. **Store securely** — Keep refresh tokens in secure storage (not cookies)
6. **Short-lived access tokens** — Access tokens should expire quickly
7. **Monitor token usage** — Log authentication events for audit trails

---

## Programmatic Access

### Using curl with environment variables:

```bash
#!/bin/bash

# Configuration
API_URL="http://localhost:7070"
USERNAME="admin"
PASSWORD="admin123"

# Login
LOGIN_RESPONSE=$(curl -s -X POST "$API_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}")

ACCESS_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.access_token')
REFRESH_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.refresh_token')

# Use token
curl "$API_URL/api/events?limit=10" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq .

# Refresh when expired
NEW_TOKENS=$(curl -s -X POST "$API_URL/api/auth/refresh" \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"$REFRESH_TOKEN\"}")

NEW_ACCESS_TOKEN=$(echo "$NEW_TOKENS" | jq -r '.access_token')
```

### Using Python:

```python
import requests
import json

API_URL = "http://localhost:7070"

# Login
login_response = requests.post(
    f"{API_URL}/api/auth/login",
    json={"username": "admin", "password": "admin123"}
)
tokens = login_response.json()
access_token = tokens['access_token']

# Query API
headers = {"Authorization": f"Bearer {access_token}"}
events_response = requests.get(
    f"{API_URL}/api/events?limit=10",
    headers=headers
)
print(json.dumps(events_response.json(), indent=2))
```

---

## Interactive Testing

Use the Swagger UI with authentication:

1. Open `http://localhost:7070/docs/`
2. Click the **"Authorize"** button (padlock icon)
3. Login at `/api/auth/login` first to get a token
4. Paste the access token in the "Authorization" field
5. Test endpoints directly in Swagger

---

## See Also

- [Getting Started](getting-started.md) — Installation and first run
- [Querying the API](querying-api.md) — API endpoint reference
- [What Can I See](what-can-i-see.md) — Data types and monitoring capabilities
