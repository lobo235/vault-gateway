package api

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/lobo235/vault-gateway/internal/vault"
)

// serverNamePattern validates Minecraft server names.
var serverNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,47}$`)

// createSecretsResponse is the response for POST /secrets/minecraft/{serverName}.
type createSecretsResponse struct {
	ServerName string `json:"server_name"`
	Created    bool   `json:"created"`
}

// readSecretsResponse is the response for GET /secrets/minecraft/{serverName}.
type readSecretsResponse struct {
	ServerName   string `json:"server_name"`
	RCONPassword string `json:"rcon_password"`
}

// updateSecretsResponse is the response for PUT /secrets/minecraft/{serverName}.
type updateSecretsResponse struct {
	ServerName string `json:"server_name"`
	Updated    bool   `json:"updated"`
}

// deleteSecretsResponse is the response for DELETE /secrets/minecraft/{serverName}.
type deleteSecretsResponse struct {
	ServerName string `json:"server_name"`
	Deleted    bool   `json:"deleted"`
}

// validateServerName checks that a server name matches the allowed pattern.
func validateServerName(name string) bool {
	return serverNamePattern.MatchString(name)
}

// createSecretsHandler handles POST /secrets/minecraft/{serverName}.
// Auto-generates an RCON password and stores it in Vault.
// The password is NOT returned in the response — it lives in Vault only.
func (s *Server) createSecretsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		serverName := r.PathValue("serverName")
		traceID := traceIDFromContext(r.Context())

		if !validateServerName(serverName) {
			writeError(w, http.StatusBadRequest, "invalid_body", "server name must match pattern: ^[a-z0-9][a-z0-9-]{0,47}$")
			return
		}

		// Check if secret already exists
		existing, err := s.vault.ReadSecret(serverName)
		if err != nil {
			s.log.Error("failed to check existing secret", "server_name", serverName, "error", err, "trace_id", traceID)
			if isUnauthorizedErr(err) {
				writeError(w, http.StatusUnauthorized, "unauthorized", "vault path access denied")
				return
			}
			writeError(w, http.StatusBadGateway, "upstream_error", "failed to check existing secrets")
			return
		}
		if existing != nil {
			writeError(w, http.StatusConflict, "already_exists", "secrets already exist for this server")
			return
		}

		password, err := vault.GeneratePassword()
		if err != nil {
			s.log.Error("failed to generate password", "error", err, "trace_id", traceID)
			writeError(w, http.StatusInternalServerError, "internal_error", "failed to generate password")
			return
		}

		data := map[string]interface{}{
			"rcon_password": password,
		}
		if err := s.vault.WriteSecret(serverName, data); err != nil {
			s.log.Error("failed to write secret", "server_name", serverName, "error", err, "trace_id", traceID)
			if isUnauthorizedErr(err) {
				writeError(w, http.StatusUnauthorized, "unauthorized", "vault path access denied")
				return
			}
			writeError(w, http.StatusBadGateway, "upstream_error", "failed to store secrets in vault")
			return
		}

		s.log.Info("created secrets", "server_name", serverName, "trace_id", traceID)
		writeJSON(w, http.StatusCreated, createSecretsResponse{
			ServerName: serverName,
			Created:    true,
		})
	}
}

// readSecretsHandler handles GET /secrets/minecraft/{serverName}.
func (s *Server) readSecretsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		serverName := r.PathValue("serverName")
		traceID := traceIDFromContext(r.Context())

		if !validateServerName(serverName) {
			writeError(w, http.StatusBadRequest, "invalid_body", "server name must match pattern: ^[a-z0-9][a-z0-9-]{0,47}$")
			return
		}

		data, err := s.vault.ReadSecret(serverName)
		if err != nil {
			s.log.Error("failed to read secret", "server_name", serverName, "error", err, "trace_id", traceID)
			if isUnauthorizedErr(err) {
				writeError(w, http.StatusUnauthorized, "unauthorized", "vault path access denied")
				return
			}
			writeError(w, http.StatusBadGateway, "upstream_error", "failed to read secrets from vault")
			return
		}
		if data == nil {
			writeError(w, http.StatusNotFound, "not_found", "no secrets found for this server")
			return
		}

		rconPassword, _ := data["rcon_password"].(string)
		writeJSON(w, http.StatusOK, readSecretsResponse{
			ServerName:   serverName,
			RCONPassword: rconPassword,
		})
	}
}

// updateSecretsHandler handles PUT /secrets/minecraft/{serverName}.
// Generates a new RCON password and overwrites the existing secret.
func (s *Server) updateSecretsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		serverName := r.PathValue("serverName")
		traceID := traceIDFromContext(r.Context())

		if !validateServerName(serverName) {
			writeError(w, http.StatusBadRequest, "invalid_body", "server name must match pattern: ^[a-z0-9][a-z0-9-]{0,47}$")
			return
		}

		// Verify the secret exists before updating
		existing, err := s.vault.ReadSecret(serverName)
		if err != nil {
			s.log.Error("failed to check existing secret", "server_name", serverName, "error", err, "trace_id", traceID)
			if isUnauthorizedErr(err) {
				writeError(w, http.StatusUnauthorized, "unauthorized", "vault path access denied")
				return
			}
			writeError(w, http.StatusBadGateway, "upstream_error", "failed to check existing secrets")
			return
		}
		if existing == nil {
			writeError(w, http.StatusNotFound, "not_found", "no secrets found for this server")
			return
		}

		password, err := vault.GeneratePassword()
		if err != nil {
			s.log.Error("failed to generate password", "error", err, "trace_id", traceID)
			writeError(w, http.StatusInternalServerError, "internal_error", "failed to generate password")
			return
		}

		data := map[string]interface{}{
			"rcon_password": password,
		}
		if err := s.vault.WriteSecret(serverName, data); err != nil {
			s.log.Error("failed to write secret", "server_name", serverName, "error", err, "trace_id", traceID)
			if isUnauthorizedErr(err) {
				writeError(w, http.StatusUnauthorized, "unauthorized", "vault path access denied")
				return
			}
			writeError(w, http.StatusBadGateway, "upstream_error", "failed to update secrets in vault")
			return
		}

		s.log.Info("updated secrets", "server_name", serverName, "trace_id", traceID)
		writeJSON(w, http.StatusOK, updateSecretsResponse{
			ServerName: serverName,
			Updated:    true,
		})
	}
}

// deleteSecretsHandler handles DELETE /secrets/minecraft/{serverName}.
// Deletes all versions of the secret using the metadata path.
func (s *Server) deleteSecretsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		serverName := r.PathValue("serverName")
		traceID := traceIDFromContext(r.Context())

		if !validateServerName(serverName) {
			writeError(w, http.StatusBadRequest, "invalid_body", "server name must match pattern: ^[a-z0-9][a-z0-9-]{0,47}$")
			return
		}

		if err := s.vault.DeleteSecret(serverName); err != nil {
			s.log.Error("failed to delete secret", "server_name", serverName, "error", err, "trace_id", traceID)
			if isUnauthorizedErr(err) {
				writeError(w, http.StatusUnauthorized, "unauthorized", "vault path access denied")
				return
			}
			writeError(w, http.StatusBadGateway, "upstream_error", "failed to delete secrets from vault")
			return
		}

		s.log.Info("deleted secrets", "server_name", serverName, "trace_id", traceID)
		writeJSON(w, http.StatusOK, deleteSecretsResponse{
			ServerName: serverName,
			Deleted:    true,
		})
	}
}

// isUnauthorizedErr checks if an error message indicates a path validation failure.
func isUnauthorizedErr(err error) bool {
	return strings.Contains(err.Error(), "unauthorized:")
}
