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
