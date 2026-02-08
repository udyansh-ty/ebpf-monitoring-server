# Phase 1 Implementation Guide: Foundation Layer

> **Duration:** 3 days
> **Goal:** Implement authentication, middleware, and configuration
> **Status:** Ready to start

---

## PHASE 1 OVERVIEW

Phase 1 focuses on the critical foundation that all other improvements depend on:

```
┌─────────────────────────────────────────┐
│ Phase 1: Foundation (Days 1-3)          │
├─────────────────────────────────────────┤
│ Day 1: Authentication Layer             │
│ Day 1-2: Middleware Stack               │
│ Day 2: Configuration & Environment      │
└─────────────────────────────────────────┘
        ↓
┌─────────────────────────────────────────┐
│ Phase 2: Business Logic (Days 3-5)      │
├─────────────────────────────────────────┤
│ Service Layer                           │
│ Repository Pattern                      │
└─────────────────────────────────────────┘
        ↓
┌─────────────────────────────────────────┐
│ Phase 3: Enhancement (Days 5-7)         │
├─────────────────────────────────────────┤
│ Redis Caching                           │
│ Enhanced Testing                        │
│ Complete Documentation                  │
└─────────────────────────────────────────┘
```

---

## DAY 1: AUTHENTICATION LAYER

### Step 1.1: Create JWT Configuration

**File:** `internal/auth/config.go` (NEW - ~50 LOC)

```go
package auth

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"time"
)

// JWTConfig holds JWT configuration
type JWTConfig struct {
	// Secret for HS256 (symmetric) or private key for RS256 (asymmetric)
	SigningKey    string
	TokenExpiry   time.Duration
	RefreshExpiry time.Duration
	Algorithm     string // "HS256" or "RS256"
}

// LoadJWTConfig loads JWT configuration from environment
func LoadJWTConfig() *JWTConfig {
	return &JWTConfig{
		SigningKey:    os.Getenv("JWT_SECRET"),
		TokenExpiry:   parseEnvDuration("JWT_EXPIRY", 24*time.Hour),
		RefreshExpiry: parseEnvDuration("JWT_REFRESH_EXPIRY", 7*24*time.Hour),
		Algorithm:     os.Getenv("JWT_ALGORITHM"), // default "HS256"
	}
}

// GenerateSecret generates a random JWT secret if not provided
func GenerateSecret() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func parseEnvDuration(key string, defaultVal time.Duration) time.Duration {
	if val := os.Getenv(key); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			return d
		}
	}
	return defaultVal
}
```

### Step 1.2: Create JWT Token Generation

**File:** `internal/auth/tokens.go` (NEW - ~150 LOC)

```go
package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims represents JWT claims
type Claims struct {
	UserID   string   `json:"user_id"`
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
	jwt.RegisteredClaims
}

// TokenPair contains access and refresh tokens
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	TokenType    string    `json:"token_type"`
}

// TokenGenerator generates JWT tokens
type TokenGenerator struct {
	config *JWTConfig
}

// NewTokenGenerator creates a new token generator
func NewTokenGenerator(config *JWTConfig) *TokenGenerator {
	if config == nil {
		config = LoadJWTConfig()
	}
	return &TokenGenerator{config: config}
}

// GenerateTokens generates access and refresh tokens
func (tg *TokenGenerator) GenerateTokens(userID, username string, roles []string) (*TokenPair, error) {
	if tg.config.SigningKey == "" {
		return nil, fmt.Errorf("JWT secret not configured")
	}

	now := time.Now()
	expiresAt := now.Add(tg.config.TokenExpiry)
	refreshExpiresAt := now.Add(tg.config.RefreshExpiry)

	// Access token
	accessClaims := Claims{
		UserID:   userID,
		Username: username,
		Roles:    roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Subject:   userID,
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString([]byte(tg.config.SigningKey))
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	// Refresh token
	refreshClaims := Claims{
		UserID:   userID,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(refreshExpiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Subject:   userID,
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString([]byte(tg.config.SigningKey))
	if err != nil {
		return nil, fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessTokenString,
		RefreshToken: refreshTokenString,
		ExpiresAt:    expiresAt,
		TokenType:    "Bearer",
	}, nil
}

// ValidateToken validates a JWT token
func (tg *TokenGenerator) ValidateToken(tokenString string) (*Claims, error) {
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(tg.config.SigningKey), nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}
```

### Step 1.3: Create Authentication Middleware

**File:** `internal/middleware/auth.go` (NEW - ~120 LOC)

```go
package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"monitoring/internal/auth"
)

// ContextKey type for context values
type ContextKey string

const (
	UserContextKey ContextKey = "user"
)

// AuthMiddleware creates authentication middleware
func AuthMiddleware(tokenGenerator *auth.TokenGenerator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip auth for health check
			if r.URL.Path == "/health" {
				next.ServeHTTP(w, r)
				return
			}

			// Extract token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
				return
			}

			// Parse Bearer token
			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				http.Error(w, `{"error":"invalid authorization header"}`, http.StatusUnauthorized)
				return
			}

			tokenString := parts[1]

			// Validate token
			claims, err := tokenGenerator.ValidateToken(tokenString)
			if err != nil {
				http.Error(w, fmt.Sprintf(`{"error":"invalid token: %s"}`, err.Error()), http.StatusUnauthorized)
				return
			}

			// Add claims to context
			ctx := context.WithValue(r.Context(), UserContextKey, claims)
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
		})
	}
}

// GetUserFromContext extracts user claims from context
func GetUserFromContext(r *http.Request) *auth.Claims {
	claims, ok := r.Context().Value(UserContextKey).(*auth.Claims)
	if !ok {
		return nil
	}
	return claims
}
```

### Step 1.4: Update Server to Wire Authentication

**File:** `cmd/server/main.go` (MODIFY - lines 20-80)

**Changes:**
1. Add JWT flag
2. Create token generator
3. Wire auth middleware
4. Add auth endpoints (/api/auth/login, /api/auth/refresh)

```go
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"monitoring/internal/api"
	"monitoring/internal/auth"
	"monitoring/internal/middleware"
	"monitoring/internal/system"
)

func main() {
	var (
		httpAddr  = flag.String("addr", ":8080", "HTTP server address")
		dbURL     = flag.String("db-url", os.Getenv("DB_URL"), "PostgreSQL connection URL")
		jwtSecret = flag.String("jwt-secret", os.Getenv("JWT_SECRET"), "JWT signing secret")
	)
	flag.Parse()

	// Validate JWT secret
	if *jwtSecret == "" {
		fmt.Fprintf(os.Stderr, "WARNING: JWT_SECRET not set, generating random secret\n")
		*jwtSecret = auth.GenerateSecret()
	}

	// Initialize system
	sys, err := system.New(*dbURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize system: %v\n", err)
		os.Exit(1)
	}

	// Initialize token generator
	tokenGen := auth.NewTokenGenerator(&auth.JWTConfig{
		SigningKey: *jwtSecret,
	})

	// Setup API
	api.SetupGlobalSystem(sys)

	// Create HTTP server
	mux := http.NewServeMux()

	// Wire auth middleware
	authMW := middleware.AuthMiddleware(tokenGen)

	// Auth endpoints (no middleware)
	mux.HandleFunc("/api/auth/login", api.HandleLogin(tokenGen))
	mux.HandleFunc("/api/auth/refresh", api.HandleRefresh(tokenGen))

	// Health check (no middleware)
	mux.HandleFunc("/health", api.HandleHealth)

	// Protected endpoints (with middleware)
	mux.Handle("/api/events", authMW(http.HandlerFunc(api.HandleEvents)))
	mux.Handle("/api/programs", authMW(http.HandlerFunc(api.HandlePrograms)))
	mux.Handle("/api/connection-summary", authMW(http.HandlerFunc(api.HandleConnectionSummary)))
	mux.Handle("/api/packet-drop-summary", authMW(http.HandlerFunc(api.HandlePacketDropSummary)))
	mux.Handle("/api/list-connections", authMW(http.HandlerFunc(api.HandleListConnections)))
	mux.Handle("/api/list-packet-drops", authMW(http.HandlerFunc(api.HandleListPacketDrops)))

	// ... rest of main.go remains same
}
```

### Step 1.5: Add Login and Refresh Handlers

**File:** `internal/api/auth_handlers.go` (NEW - ~80 LOC)

```go
package api

import (
	"encoding/json"
	"net/http"

	"monitoring/internal/auth"
)

// LoginRequest represents login request
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// HandleLogin handles login requests
func HandleLogin(tokenGen *auth.TokenGenerator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		// TODO: Validate credentials against user store
		// For now, accept any non-empty username/password
		if req.Username == "" || req.Password == "" {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}

		tokens, err := tokenGen.GenerateTokens(req.Username, req.Username, []string{"user"})
		if err != nil {
			http.Error(w, "failed to generate tokens", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tokens)
	}
}

// RefreshRequest represents refresh token request
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// HandleRefresh handles token refresh requests
func HandleRefresh(tokenGen *auth.TokenGenerator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req RefreshRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		claims, err := tokenGen.ValidateToken(req.RefreshToken)
		if err != nil {
			http.Error(w, "invalid refresh token", http.StatusUnauthorized)
			return
		}

		tokens, err := tokenGen.GenerateTokens(claims.UserID, claims.Username, claims.Roles)
		if err != nil {
			http.Error(w, "failed to generate tokens", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tokens)
	}
}
```

### Step 1.6: Add Authentication Tests

**File:** `internal/auth/tokens_test.go` (NEW - ~150 LOC)

```go
package auth

import (
	"testing"
	"time"
)

func TestGenerateTokens(t *testing.T) {
	config := &JWTConfig{
		SigningKey:    "test-secret-key",
		TokenExpiry:   1 * time.Hour,
		RefreshExpiry: 24 * time.Hour,
	}

	tg := NewTokenGenerator(config)

	tokens, err := tg.GenerateTokens("user123", "testuser", []string{"user", "admin"})
	if err != nil {
		t.Fatalf("GenerateTokens failed: %v", err)
	}

	if tokens.AccessToken == "" {
		t.Error("AccessToken is empty")
	}

	if tokens.RefreshToken == "" {
		t.Error("RefreshToken is empty")
	}

	if tokens.TokenType != "Bearer" {
		t.Errorf("TokenType should be 'Bearer', got '%s'", tokens.TokenType)
	}
}

func TestValidateToken(t *testing.T) {
	config := &JWTConfig{
		SigningKey:    "test-secret-key",
		TokenExpiry:   1 * time.Hour,
		RefreshExpiry: 24 * time.Hour,
	}

	tg := NewTokenGenerator(config)

	tokens, _ := tg.GenerateTokens("user123", "testuser", []string{"user"})

	claims, err := tg.ValidateToken(tokens.AccessToken)
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}

	if claims.UserID != "user123" {
		t.Errorf("UserID mismatch: expected 'user123', got '%s'", claims.UserID)
	}

	if claims.Username != "testuser" {
		t.Errorf("Username mismatch: expected 'testuser', got '%s'", claims.Username)
	}
}

func TestValidateInvalidToken(t *testing.T) {
	config := &JWTConfig{
		SigningKey: "test-secret-key",
	}

	tg := NewTokenGenerator(config)

	_, err := tg.ValidateToken("invalid.token.string")
	if err == nil {
		t.Error("ValidateToken should fail for invalid token")
	}
}
```

### Step 1.7: Add Middleware Tests

**File:** `internal/middleware/auth_test.go` (NEW - ~100 LOC)

```go
package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"monitoring/internal/auth"
)

func TestAuthMiddlewareSkipsHealth(t *testing.T) {
	config := &auth.JWTConfig{SigningKey: "test-secret"}
	tokenGen := auth.NewTokenGenerator(config)
	authMW := AuthMiddleware(tokenGen)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	authMW(next).ServeHTTP(w, req)

	if !nextCalled {
		t.Error("next handler should be called for /health")
	}
}

func TestAuthMiddlewareValidToken(t *testing.T) {
	config := &auth.JWTConfig{SigningKey: "test-secret"}
	tokenGen := auth.NewTokenGenerator(config)
	authMW := AuthMiddleware(tokenGen)

	tokens, _ := tokenGen.GenerateTokens("user123", "testuser", []string{"user"})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := GetUserFromContext(r)
		if claims == nil {
			http.Error(w, "claims not found", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/api/events", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokens.AccessToken))

	w := httptest.NewRecorder()
	authMW(next).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestAuthMiddlewareMissingToken(t *testing.T) {
	config := &auth.JWTConfig{SigningKey: "test-secret"}
	tokenGen := auth.NewTokenGenerator(config)
	authMW := AuthMiddleware(tokenGen)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/api/events", nil)
	w := httptest.NewRecorder()

	authMW(next).ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}
```

### Step 1.8: Verification Checklist (Day 1)

- [ ] `internal/auth/config.go` created and compiles
- [ ] `internal/auth/tokens.go` created with token generation
- [ ] `internal/middleware/auth.go` created with auth middleware
- [ ] `cmd/server/main.go` updated to wire auth middleware
- [ ] `internal/api/auth_handlers.go` created with login/refresh
- [ ] `internal/auth/tokens_test.go` tests passing
- [ ] `internal/middleware/auth_test.go` tests passing
- [ ] All protected endpoints return 401 without token
- [ ] All protected endpoints return 200 with valid token
- [ ] `/health` endpoint accessible without auth
- [ ] `/api/auth/login` and `/api/auth/refresh` working

---

## DAY 1-2: MIDDLEWARE STACK

### Step 2.1: Create Logging Middleware

**File:** `internal/middleware/logging.go` (NEW - ~60 LOC)

```go
package middleware

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

// LoggingMiddleware creates request logging middleware
func LoggingMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Wrap response writer to capture status code
			wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			log.Printf("[%s] %s %s", r.Method, r.URL.Path, r.RemoteAddr)

			next.ServeHTTP(wrapped, r)

			duration := time.Since(start)
			log.Printf("[%d] %s %s completed in %v", wrapped.statusCode, r.Method, r.URL.Path, duration)
		})
	}
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
```

### Step 2.2: Create Error Handling Middleware

**File:** `internal/middleware/errors.go` (NEW - ~70 LOC)

```go
package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime/debug"
)

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    int    `json:"code"`
	Message string `json:"message,omitempty"`
}

// ErrorHandlerMiddleware creates error handling middleware
func ErrorHandlerMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					fmt.Printf("panic: %v\n%s\n", err, debug.Stack())

					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)

					json.NewEncoder(w).Encode(ErrorResponse{
						Error: "Internal Server Error",
						Code:  http.StatusInternalServerError,
					})
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}
```

### Step 2.3: Create Request Validation Middleware

**File:** `internal/middleware/validation.go` (NEW - ~80 LOC)

```go
package middleware

import (
	"encoding/json"
	"net/http"
)

// ValidationMiddleware creates request validation middleware
func ValidationMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Validate Content-Type for POST/PUT requests
			if r.Method == http.MethodPost || r.Method == http.MethodPut {
				contentType := r.Header.Get("Content-Type")
				if contentType != "" && contentType != "application/json" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnsupportedMediaType)
					json.NewEncoder(w).Encode(ErrorResponse{
						Error:   "Unsupported Media Type",
						Code:    http.StatusUnsupportedMediaType,
						Message: "Content-Type must be application/json",
					})
					return
				}
			}

			// Validate request body size (max 10MB)
			r.Body = http.MaxBytesReader(w, r.Body, 10*1024*1024)

			next.ServeHTTP(w, r)
		})
	}
}
```

### Step 2.4: Update Server to Wire Middleware

**File:** `cmd/server/main.go` (MODIFY - wire middleware stack)

```go
// After creating mux, wrap with middleware:

// Create middleware stack
handler := http.Handler(mux)
handler = middleware.ErrorHandlerMiddleware()(handler)    // innermost
handler = middleware.ValidationMiddleware()(handler)
handler = middleware.LoggingMiddleware()(handler)         // outermost

// Start server with middleware stack
server := &http.Server{
	Addr:    *httpAddr,
	Handler: handler,
}
```

### Step 2.5: Write Middleware Tests

**Files:**
- `internal/middleware/logging_test.go` (~60 LOC)
- `internal/middleware/validation_test.go` (~80 LOC)
- `internal/middleware/errors_test.go` (~70 LOC)

---

## DAY 2: CONFIGURATION AND ENVIRONMENT

### Step 3.1: Create .env.example

**File:** `.env.example` (NEW)

```bash
# ========================================
# Monitoring Service Configuration
# ========================================

# Server Configuration
SERVER_ADDR=:8080
LOG_LEVEL=info

# Database Configuration (Optional - only if using PostgreSQL backend)
DB_URL=postgres://user:password@localhost:5432/monitoring?sslmode=disable

# JWT Configuration
JWT_SECRET=your-secure-secret-key-change-this
JWT_EXPIRY=24h
JWT_REFRESH_EXPIRY=7d24h
JWT_ALGORITHM=HS256

# Cache Configuration
CACHE_TTL=5m
REDIS_URL=redis://localhost:6379

# K8s Aggregator (Optional)
AGGREGATOR_ADDR=:8081
AGGREGATOR_DB_URL=postgres://user:password@localhost:5432/monitoring
FLOW_CACHE_TTL=5m
DISABLE_ENRICHER=false

# Logging
LOG_LEVEL=info
LOG_FORMAT=json

# HTTP Server
HTTP_READ_TIMEOUT=15s
HTTP_WRITE_TIMEOUT=15s
HTTP_MAX_HEADER_BYTES=1048576
```

### Step 3.2: Create Configuration Package

**File:** `internal/config/config.go` (NEW - ~120 LOC)

```go
package config

import (
	"fmt"
	"os"
	"time"
)

// Config holds all configuration
type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	JWT      JWTConfig
	Cache    CacheConfig
	HTTP     HTTPConfig
	Logging  LoggingConfig
}

type ServerConfig struct {
	Addr string
}

type DatabaseConfig struct {
	URL string // PostgreSQL connection string
}

type JWTConfig struct {
	Secret        string
	Expiry        time.Duration
	RefreshExpiry time.Duration
	Algorithm     string
}

type CacheConfig struct {
	TTL      time.Duration
	RedisURL string
}

type HTTPConfig struct {
	ReadTimeout      time.Duration
	WriteTimeout     time.Duration
	MaxHeaderBytes   int
}

type LoggingConfig struct {
	Level  string
	Format string
}

// Load loads configuration from environment
func Load() *Config {
	return &Config{
		Server: ServerConfig{
			Addr: getEnv("SERVER_ADDR", ":8080"),
		},
		Database: DatabaseConfig{
			URL: getEnv("DB_URL", ""),
		},
		JWT: JWTConfig{
			Secret:        getEnv("JWT_SECRET", ""),
			Expiry:        parseDuration("JWT_EXPIRY", 24*time.Hour),
			RefreshExpiry: parseDuration("JWT_REFRESH_EXPIRY", 7*24*time.Hour),
			Algorithm:     getEnv("JWT_ALGORITHM", "HS256"),
		},
		Cache: CacheConfig{
			TTL:      parseDuration("CACHE_TTL", 5*time.Minute),
			RedisURL: getEnv("REDIS_URL", ""),
		},
		HTTP: HTTPConfig{
			ReadTimeout:    parseDuration("HTTP_READ_TIMEOUT", 15*time.Second),
			WriteTimeout:   parseDuration("HTTP_WRITE_TIMEOUT", 15*time.Second),
			MaxHeaderBytes: 1 << 20, // 1MB
		},
		Logging: LoggingConfig{
			Level:  getEnv("LOG_LEVEL", "info"),
			Format: getEnv("LOG_FORMAT", "text"),
		},
	}
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func parseDuration(key string, defaultVal time.Duration) time.Duration {
	if val := os.Getenv(key); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			return d
		}
	}
	return defaultVal
}

// Validate validates required configuration
func (c *Config) Validate() error {
	if c.JWT.Secret == "" {
		return fmt.Errorf("JWT_SECRET not set")
	}
	return nil
}
```

### Step 3.3: Update main.go to Use Configuration

**File:** `cmd/server/main.go` (MODIFY)

```go
func main() {
	// Load configuration from environment
	cfg := config.Load()

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		os.Exit(1)
	}

	// Rest of initialization uses cfg instead of individual flags
	...
}
```

---

## VERIFICATION CHECKLIST (Phase 1)

### Authentication
- [ ] JWT token generation working
- [ ] Token validation working
- [ ] Auth middleware rejects requests without token
- [ ] Auth middleware accepts requests with valid token
- [ ] Login endpoint returns tokens
- [ ] Refresh endpoint returns new tokens
- [ ] Auth tests passing (100% coverage)

### Middleware
- [ ] Logging middleware capturing requests
- [ ] Error handler converting panics to 500 responses
- [ ] Validation middleware enforcing Content-Type
- [ ] Middleware stack properly wired
- [ ] Middleware tests passing

### Configuration
- [ ] `.env.example` exists and complete
- [ ] Configuration loads from environment
- [ ] Required values validated
- [ ] Defaults provided for optional values
- [ ] Tests passing

### Endpoints Status
- [ ] `/health` - 200 (no auth required)
- [ ] `/api/auth/login` - 200 POST with credentials (no auth required)
- [ ] `/api/auth/refresh` - 200 POST with refresh token (no auth required)
- [ ] `/api/events` - 401 without token, 200 with token
- [ ] `/api/programs` - 401 without token, 200 with token
- [ ] All other endpoints - 401 without token, 200 with token

---

## NEXT STEPS (Day 3+)

After Phase 1 completion:

1. **Document Phase 1 in README.md:**
   - Authentication setup
   - Configuration guide
   - API usage with tokens

2. **Create API.md** with:
   - Login endpoint documentation
   - Refresh endpoint documentation
   - Updated endpoint documentation with auth

3. **Continue to Phase 2:**
   - Implement Service layer
   - Implement Repository pattern
   - Refactor handlers

---

**Phase 1 Version:** 1.0
**Status:** Ready to implement
**Estimated Duration:** 3 days
**Next Review:** After Day 2
