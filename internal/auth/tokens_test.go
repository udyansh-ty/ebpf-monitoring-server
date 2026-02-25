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

	// ANCHOR: Token Use Tests - Feb 25, 2026
	// Ensure access tokens are tagged for validation.
	if claims.TokenUse != TokenUseAccess {
		t.Errorf("TokenUse mismatch: expected '%s', got '%s'", TokenUseAccess, claims.TokenUse)
	}
}

// ANCHOR: Refresh Token Use Test - Feb 25, 2026
// Validate refresh tokens include the correct token_use claim.
func TestValidateRefreshToken(t *testing.T) {
	config := &JWTConfig{
		SigningKey:    "test-secret-key",
		TokenExpiry:   1 * time.Hour,
		RefreshExpiry: 24 * time.Hour,
	}

	tg := NewTokenGenerator(config)

	tokens, _ := tg.GenerateTokens("user123", "testuser", []string{"user"})

	claims, err := tg.ValidateToken(tokens.RefreshToken)
	if err != nil {
		t.Fatalf("ValidateToken failed for refresh: %v", err)
	}

	if claims.TokenUse != TokenUseRefresh {
		t.Errorf("TokenUse mismatch: expected '%s', got '%s'", TokenUseRefresh, claims.TokenUse)
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

func TestGenerateSecret(t *testing.T) {
	secret := GenerateSecret()
	if secret == "" {
		t.Error("GenerateSecret returned empty string")
	}
	if len(secret) < 20 {
		t.Errorf("GenerateSecret returned too short secret: %d bytes", len(secret))
	}
}
