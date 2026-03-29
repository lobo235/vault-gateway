package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// vaultClient is the interface the Server uses to communicate with Vault.
type vaultClient interface {
	Ping() error
	ReadSecret(name string) (map[string]interface{}, error)
	WriteSecret(name string, data map[string]interface{}) error
	DeleteSecret(name string) error
}

// Server holds the dependencies for the HTTP server.
type Server struct {
	vault   vaultClient
	apiKey  string
	log     *slog.Logger
	version string
}

// NewServer creates a Server wired with the given Vault client, API key, version string, and logger.
func NewServer(client vaultClient, apiKey, version string, log *slog.Logger) *Server {
	return &Server{
		vault:   client,
		apiKey:  apiKey,
		log:     log,
		version: version,
	}
}

// Handler builds and returns the root http.Handler with all routes registered.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	auth := bearerAuth(s.apiKey)

	// /health is unauthenticated — used by Nomad container health checks
	mux.HandleFunc("GET /health", s.healthHandler())

	// Authenticated routes
	mux.Handle("POST /secrets/minecraft/{serverName}", auth(http.HandlerFunc(s.createSecretsHandler())))
	mux.Handle("GET /secrets/minecraft/{serverName}", auth(http.HandlerFunc(s.readSecretsHandler())))
	mux.Handle("PUT /secrets/minecraft/{serverName}", auth(http.HandlerFunc(s.updateSecretsHandler())))
	mux.Handle("DELETE /secrets/minecraft/{serverName}", auth(http.HandlerFunc(s.deleteSecretsHandler())))

	// Generic secret routes (category/name based)
	mux.Handle("POST /secrets/{category}/{name}", auth(http.HandlerFunc(s.createGenericSecretHandler())))
	mux.Handle("GET /secrets/{category}/{name}", auth(http.HandlerFunc(s.readGenericSecretHandler())))
	mux.Handle("PUT /secrets/{category}/{name}", auth(http.HandlerFunc(s.updateGenericSecretHandler())))
	mux.Handle("DELETE /secrets/{category}/{name}", auth(http.HandlerFunc(s.deleteGenericSecretHandler())))

	return requestLogger(s.log)(mux)
}

// Run starts the HTTP server and blocks until ctx is cancelled, then shuts down gracefully.
func (s *Server) Run(ctx context.Context, addr string) error {
	srv := &http.Server{
		Addr:         addr,
		Handler:      s.Handler(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		s.log.Info("server listening", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("server error: %w", err)
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		s.log.Info("shutting down server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
