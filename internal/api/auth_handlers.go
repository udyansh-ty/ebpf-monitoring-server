package api

import (
	"encoding/json"
	"net/http"

	"github.com/srodi/ebpf-server/internal/auth"
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
