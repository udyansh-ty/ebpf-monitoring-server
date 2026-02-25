package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ANCHOR: Token Use Claim - Bug: refresh accepted as access - Feb 25, 2026
// Add token_use to distinguish access vs refresh for validation.
const (
	TokenUseAccess  = "access"
	TokenUseRefresh = "refresh"
)

// Claims represents JWT claims
type Claims struct {
	UserID   string   `json:"user_id"`
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
	TokenUse string   `json:"token_use"`
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

	// ANCHOR: Token Use Assignment - Bug: refresh accepted as access - Feb 25, 2026
	// Tag access vs refresh tokens so handlers can enforce correct usage.
	// Access token
	accessClaims := Claims{
		UserID:   userID,
		Username: username,
		Roles:    roles,
		TokenUse: TokenUseAccess,
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
		TokenUse: TokenUseRefresh,
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
