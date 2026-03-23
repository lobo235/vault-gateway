package config

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

// Config holds all runtime configuration loaded from environment variables.
type Config struct {
	VaultAddr     string
	VaultRoleID   string
	VaultSecretID string
	GatewayAPIKey string
	Port          string
	LogLevel      string
}

// Load reads configuration from environment variables, applying defaults and validating required fields.
func Load() (*Config, error) {
	// Load .env if present — ignore error if file doesn't exist
	_ = godotenv.Load()

	cfg := &Config{
		VaultAddr:     os.Getenv("VAULT_ADDR"),
		VaultRoleID:   os.Getenv("VAULT_ROLE_ID"),
		VaultSecretID: os.Getenv("VAULT_SECRET_ID"),
		GatewayAPIKey: os.Getenv("GATEWAY_API_KEY"),
		Port:          os.Getenv("PORT"),
		LogLevel:      os.Getenv("LOG_LEVEL"),
	}

	if cfg.VaultAddr == "" {
		return nil, fmt.Errorf("VAULT_ADDR is required")
	}
	if cfg.VaultRoleID == "" {
		return nil, fmt.Errorf("VAULT_ROLE_ID is required")
	}
	if cfg.VaultSecretID == "" {
		return nil, fmt.Errorf("VAULT_SECRET_ID is required")
	}
	if cfg.GatewayAPIKey == "" {
		return nil, fmt.Errorf("GATEWAY_API_KEY is required")
	}
	if cfg.Port == "" {
		cfg.Port = "8080"
	}
	switch cfg.LogLevel {
	case "debug", "info", "warn", "error":
		// valid
	case "":
		cfg.LogLevel = "info"
	default:
		return nil, fmt.Errorf("LOG_LEVEL must be one of: debug, info, warn, error")
	}

	return cfg, nil
}
