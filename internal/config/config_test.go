package config_test

import (
	"testing"

	"github.com/lobo235/vault-gateway/internal/config"
)

// setRequired sets all required env vars so individual tests can blank one out.
func setRequired(t *testing.T) {
	t.Helper()
	t.Setenv("VAULT_ADDR", "https://vault.example.com:8200")
	t.Setenv("VAULT_ROLE_ID", "test-role-id")
	t.Setenv("VAULT_SECRET_ID", "test-secret-id")
	t.Setenv("GATEWAY_API_KEY", "key123")
	t.Setenv("PORT", "")
	t.Setenv("LOG_LEVEL", "")
}

func TestLoad_AllRequired(t *testing.T) {
	setRequired(t)
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.VaultAddr != "https://vault.example.com:8200" {
		t.Errorf("VaultAddr = %q", cfg.VaultAddr)
	}
	if cfg.VaultRoleID != "test-role-id" {
		t.Errorf("VaultRoleID = %q", cfg.VaultRoleID)
	}
	if cfg.VaultSecretID != "test-secret-id" {
		t.Errorf("VaultSecretID = %q", cfg.VaultSecretID)
	}
	if cfg.GatewayAPIKey != "key123" {
		t.Errorf("GatewayAPIKey = %q", cfg.GatewayAPIKey)
	}
}

func TestLoad_PortDefaultsTo8080(t *testing.T) {
	setRequired(t)
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Port != "8080" {
		t.Errorf("Port = %q, want 8080", cfg.Port)
	}
}

func TestLoad_PortOverride(t *testing.T) {
	setRequired(t)
	t.Setenv("PORT", "9090")
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Port != "9090" {
		t.Errorf("Port = %q, want 9090", cfg.Port)
	}
}

func TestLoad_MissingVaultAddr(t *testing.T) {
	setRequired(t)
	t.Setenv("VAULT_ADDR", "")
	if _, err := config.Load(); err == nil {
		t.Fatal("expected error for missing VAULT_ADDR")
	}
}

func TestLoad_MissingVaultRoleID(t *testing.T) {
	setRequired(t)
	t.Setenv("VAULT_ROLE_ID", "")
	if _, err := config.Load(); err == nil {
		t.Fatal("expected error for missing VAULT_ROLE_ID")
	}
}

func TestLoad_MissingVaultSecretID(t *testing.T) {
	setRequired(t)
	t.Setenv("VAULT_SECRET_ID", "")
	if _, err := config.Load(); err == nil {
		t.Fatal("expected error for missing VAULT_SECRET_ID")
	}
}

func TestLoad_MissingGatewayAPIKey(t *testing.T) {
	setRequired(t)
	t.Setenv("GATEWAY_API_KEY", "")
	if _, err := config.Load(); err == nil {
		t.Fatal("expected error for missing GATEWAY_API_KEY")
	}
}

func TestLoad_LogLevelDefaultsToInfo(t *testing.T) {
	setRequired(t)
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want info", cfg.LogLevel)
	}
}

func TestLoad_LogLevelValidValues(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "error"} {
		t.Run(level, func(t *testing.T) {
			setRequired(t)
			t.Setenv("LOG_LEVEL", level)
			cfg, err := config.Load()
			if err != nil {
				t.Fatalf("unexpected error for LOG_LEVEL=%q: %v", level, err)
			}
			if cfg.LogLevel != level {
				t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, level)
			}
		})
	}
}

func TestLoad_LogLevelInvalidValue(t *testing.T) {
	setRequired(t)
	t.Setenv("LOG_LEVEL", "trace")
	if _, err := config.Load(); err == nil {
		t.Fatal("expected error for invalid LOG_LEVEL")
	}
}
