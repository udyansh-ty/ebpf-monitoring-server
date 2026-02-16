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
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	MaxHeaderBytes int
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
