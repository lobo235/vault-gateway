package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/lobo235/vault-gateway/internal/api"
	"github.com/lobo235/vault-gateway/internal/config"
	"github.com/lobo235/vault-gateway/internal/vault"
)

// version is set at build time via -ldflags "-X main.version=<value>".
var version = "dev"

func main() {
	// Bootstrap logger at INFO so we can log config errors before cfg is loaded.
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load()
	if err != nil {
		log.Error("config error", "error", err)
		os.Exit(1)
	}

	// Re-create logger at the configured level.
	var logLevel slog.Level
	switch cfg.LogLevel {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}
	log = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))

	log.Info("starting vault-gateway", "version", version, "log_level", cfg.LogLevel)

	vaultClient, err := vault.NewClient(cfg.VaultAddr, cfg.VaultRoleID, cfg.VaultSecretID, log)
	if err != nil {
		log.Error("failed to create vault client", "error", err)
		os.Exit(1)
	}
	defer vaultClient.Close()

	srv := api.NewServer(vaultClient, cfg.GatewayAPIKey, version, log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	addr := ":" + cfg.Port
	if err := srv.Run(ctx, addr); err != nil {
		log.Error("server exited with error", "error", err)
		os.Exit(1)
	}
}
