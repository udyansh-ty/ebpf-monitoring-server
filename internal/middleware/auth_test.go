package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/srodi/ebpf-server/internal/auth"
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
