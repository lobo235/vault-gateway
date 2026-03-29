package api

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"github.com/lobo235/vault-gateway/internal/vault"
)

// maxRequestBodySize is the maximum allowed request body size (1 MiB).
const maxRequestBodySize = 1 << 20

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

// --- Generic secret types ---

// genericSecretRequest is the request body for POST/PUT /secrets/{category}/{name}.
type genericSecretRequest struct {
	Data map[string]interface{} `json:"data"`
}

// createGenericSecretResponse is the response for POST /secrets/{category}/{name}.
type createGenericSecretResponse struct {
	Category string `json:"category"`
	Name     string `json:"name"`
	Created  bool   `json:"created"`
}

// readGenericSecretResponse is the response for GET /secrets/{category}/{name}.
type readGenericSecretResponse struct {
	Category string                 `json:"category"`
	Name     string                 `json:"name"`
	Data     map[string]interface{} `json:"data"`
}

// updateGenericSecretResponse is the response for PUT /secrets/{category}/{name}.
type updateGenericSecretResponse struct {
	Category string `json:"category"`
	Name     string `json:"name"`
	Updated  bool   `json:"updated"`
}

// deleteGenericSecretResponse is the response for DELETE /secrets/{category}/{name}.
type deleteGenericSecretResponse struct {
	Category string `json:"category"`
	Name     string `json:"name"`
	Deleted  bool   `json:"deleted"`
}

// createGenericSecretHandler handles POST /secrets/{category}/{name}.
// Reads arbitrary key-value data from the request body and stores it in Vault.
func (s *Server) createGenericSecretHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		category := r.PathValue("category")
		name := r.PathValue("name")
		traceID := traceIDFromContext(r.Context())

		if !validateServerName(category) {
			writeError(w, http.StatusBadRequest, "invalid_body", "category must match pattern: ^[a-z0-9][a-z0-9-]{0,47}$")
			return
		}
		if !validateServerName(name) {
			writeError(w, http.StatusBadRequest, "invalid_body", "name must match pattern: ^[a-z0-9][a-z0-9-]{0,47}$")
			return
		}

		var reqBody genericSecretRequest
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_body", "request body must be valid JSON with a 'data' object")
			return
		}
		if len(reqBody.Data) == 0 {
			writeError(w, http.StatusBadRequest, "invalid_body", "data must not be empty")
			return
		}

		secretPath := category + "/" + name

		// Check if secret already exists
		existing, err := s.vault.ReadSecret(secretPath)
		if err != nil {
			s.log.Error("failed to check existing secret", "category", category, "name", name, "error", err, "trace_id", traceID)
			if isUnauthorizedErr(err) {
				writeError(w, http.StatusUnauthorized, "unauthorized", "vault path access denied")
				return
			}
			writeError(w, http.StatusBadGateway, "upstream_error", "failed to check existing secrets")
			return
		}
		if existing != nil {
			writeError(w, http.StatusConflict, "already_exists", "secret already exists at this path")
			return
		}

		if err := s.vault.WriteSecret(secretPath, reqBody.Data); err != nil {
			s.log.Error("failed to write secret", "category", category, "name", name, "error", err, "trace_id", traceID)
			if isUnauthorizedErr(err) {
				writeError(w, http.StatusUnauthorized, "unauthorized", "vault path access denied")
				return
			}
			writeError(w, http.StatusBadGateway, "upstream_error", "failed to store secret in vault")
			return
		}

		s.log.Info("created generic secret", "category", category, "name", name, "trace_id", traceID)
		writeJSON(w, http.StatusCreated, createGenericSecretResponse{
			Category: category,
			Name:     name,
			Created:  true,
		})
	}
}

// readGenericSecretHandler handles GET /secrets/{category}/{name}.
func (s *Server) readGenericSecretHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		category := r.PathValue("category")
		name := r.PathValue("name")
		traceID := traceIDFromContext(r.Context())

		if !validateServerName(category) {
			writeError(w, http.StatusBadRequest, "invalid_body", "category must match pattern: ^[a-z0-9][a-z0-9-]{0,47}$")
			return
		}
		if !validateServerName(name) {
			writeError(w, http.StatusBadRequest, "invalid_body", "name must match pattern: ^[a-z0-9][a-z0-9-]{0,47}$")
			return
		}

		secretPath := category + "/" + name

		data, err := s.vault.ReadSecret(secretPath)
		if err != nil {
			s.log.Error("failed to read secret", "category", category, "name", name, "error", err, "trace_id", traceID)
			if isUnauthorizedErr(err) {
				writeError(w, http.StatusUnauthorized, "unauthorized", "vault path access denied")
				return
			}
			writeError(w, http.StatusBadGateway, "upstream_error", "failed to read secret from vault")
			return
		}
		if data == nil {
			writeError(w, http.StatusNotFound, "not_found", "no secret found at this path")
			return
		}

		writeJSON(w, http.StatusOK, readGenericSecretResponse{
			Category: category,
			Name:     name,
			Data:     data,
		})
	}
}

// updateGenericSecretHandler handles PUT /secrets/{category}/{name}.
// Reads arbitrary key-value data from the request body and overwrites the existing secret.
func (s *Server) updateGenericSecretHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		category := r.PathValue("category")
		name := r.PathValue("name")
		traceID := traceIDFromContext(r.Context())

		if !validateServerName(category) {
			writeError(w, http.StatusBadRequest, "invalid_body", "category must match pattern: ^[a-z0-9][a-z0-9-]{0,47}$")
			return
		}
		if !validateServerName(name) {
			writeError(w, http.StatusBadRequest, "invalid_body", "name must match pattern: ^[a-z0-9][a-z0-9-]{0,47}$")
			return
		}

		var reqBody genericSecretRequest
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_body", "request body must be valid JSON with a 'data' object")
			return
		}
		if len(reqBody.Data) == 0 {
			writeError(w, http.StatusBadRequest, "invalid_body", "data must not be empty")
			return
		}

		secretPath := category + "/" + name

		// Verify the secret exists before updating
		existing, err := s.vault.ReadSecret(secretPath)
		if err != nil {
			s.log.Error("failed to check existing secret", "category", category, "name", name, "error", err, "trace_id", traceID)
			if isUnauthorizedErr(err) {
				writeError(w, http.StatusUnauthorized, "unauthorized", "vault path access denied")
				return
			}
			writeError(w, http.StatusBadGateway, "upstream_error", "failed to check existing secrets")
			return
		}
		if existing == nil {
			writeError(w, http.StatusNotFound, "not_found", "no secret found at this path")
			return
		}

		if err := s.vault.WriteSecret(secretPath, reqBody.Data); err != nil {
			s.log.Error("failed to write secret", "category", category, "name", name, "error", err, "trace_id", traceID)
			if isUnauthorizedErr(err) {
				writeError(w, http.StatusUnauthorized, "unauthorized", "vault path access denied")
				return
			}
			writeError(w, http.StatusBadGateway, "upstream_error", "failed to update secret in vault")
			return
		}

		s.log.Info("updated generic secret", "category", category, "name", name, "trace_id", traceID)
		writeJSON(w, http.StatusOK, updateGenericSecretResponse{
			Category: category,
			Name:     name,
			Updated:  true,
		})
	}
}

// deleteGenericSecretHandler handles DELETE /secrets/{category}/{name}.
// Deletes all versions of the secret using the metadata path.
func (s *Server) deleteGenericSecretHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		category := r.PathValue("category")
		name := r.PathValue("name")
		traceID := traceIDFromContext(r.Context())

		if !validateServerName(category) {
			writeError(w, http.StatusBadRequest, "invalid_body", "category must match pattern: ^[a-z0-9][a-z0-9-]{0,47}$")
			return
		}
		if !validateServerName(name) {
			writeError(w, http.StatusBadRequest, "invalid_body", "name must match pattern: ^[a-z0-9][a-z0-9-]{0,47}$")
			return
		}

		secretPath := category + "/" + name

		if err := s.vault.DeleteSecret(secretPath); err != nil {
			s.log.Error("failed to delete secret", "category", category, "name", name, "error", err, "trace_id", traceID)
			if isUnauthorizedErr(err) {
				writeError(w, http.StatusUnauthorized, "unauthorized", "vault path access denied")
				return
			}
			writeError(w, http.StatusBadGateway, "upstream_error", "failed to delete secret from vault")
			return
		}

		s.log.Info("deleted generic secret", "category", category, "name", name, "trace_id", traceID)
		writeJSON(w, http.StatusOK, deleteGenericSecretResponse{
			Category: category,
			Name:     name,
			Deleted:  true,
		})
	}
}

// isUnauthorizedErr checks if an error message indicates a path validation failure.
func isUnauthorizedErr(err error) bool {
	return strings.Contains(err.Error(), "unauthorized:")
}
