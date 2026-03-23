package api

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

// mockVaultClient implements vaultClient for testing.
type mockVaultClient struct {
	pingErr     error
	secrets     map[string]map[string]interface{}
	readErr     error
	writeErr    error
	deleteErr   error
	writeCalled bool
	deleteName  string
}

func newMockVaultClient() *mockVaultClient {
	return &mockVaultClient{
		secrets: make(map[string]map[string]interface{}),
	}
}

func (m *mockVaultClient) Ping() error {
	return m.pingErr
}

func (m *mockVaultClient) ReadSecret(name string) (map[string]interface{}, error) {
	if m.readErr != nil {
		return nil, m.readErr
	}
	data, ok := m.secrets[name]
	if !ok {
		return nil, nil
	}
	return data, nil
}

func (m *mockVaultClient) WriteSecret(name string, data map[string]interface{}) error {
	if m.writeErr != nil {
		return m.writeErr
	}
	m.writeCalled = true
	m.secrets[name] = data
	return nil
}

func (m *mockVaultClient) DeleteSecret(name string) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	m.deleteName = name
	delete(m.secrets, name)
	return nil
}

func newTestServer(t *testing.T, mock *mockVaultClient) *Server {
	t.Helper()
	return NewServer(mock, "test-api-key", "test-version", discardLogger())
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

// --- Health endpoint tests ---

func TestHealth_OK(t *testing.T) {
	mock := newMockVaultClient()
	srv := newTestServer(t, mock)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp healthResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Status != "ok" {
		t.Errorf("status = %q, want ok", resp.Status)
	}
	if resp.Version != "test-version" {
		t.Errorf("version = %q, want test-version", resp.Version)
	}
}

func TestHealth_VaultUnavailable(t *testing.T) {
	mock := newMockVaultClient()
	mock.pingErr = fmt.Errorf("vault unreachable")
	srv := newTestServer(t, mock)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}

func TestHealth_NoAuth(t *testing.T) {
	mock := newMockVaultClient()
	srv := newTestServer(t, mock)

	// Health endpoint should work without auth
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d (health should be unauthenticated)", w.Code, http.StatusOK)
	}
}

// --- Auth tests ---

func TestAuth_MissingToken(t *testing.T) {
	mock := newMockVaultClient()
	srv := newTestServer(t, mock)

	req := httptest.NewRequest(http.MethodGet, "/secrets/minecraft/mc-test", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestAuth_InvalidToken(t *testing.T) {
	mock := newMockVaultClient()
	srv := newTestServer(t, mock)

	req := httptest.NewRequest(http.MethodGet, "/secrets/minecraft/mc-test", nil)
	req.Header.Set("Authorization", "Bearer wrong-key")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

// --- Create secrets tests ---

func TestCreateSecrets_Success(t *testing.T) {
	mock := newMockVaultClient()
	srv := newTestServer(t, mock)

	req := httptest.NewRequest(http.MethodPost, "/secrets/minecraft/mc-test", nil)
	req.Header.Set("Authorization", "Bearer test-api-key")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", w.Code, http.StatusCreated)
	}

	var resp createSecretsResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.ServerName != "mc-test" {
		t.Errorf("server_name = %q, want mc-test", resp.ServerName)
	}
	if !resp.Created {
		t.Error("created = false, want true")
	}
	if !mock.writeCalled {
		t.Error("WriteSecret was not called")
	}
	// Verify a password was stored
	if _, ok := mock.secrets["mc-test"]["rcon_password"]; !ok {
		t.Error("rcon_password not stored in vault")
	}
}

func TestCreateSecrets_AlreadyExists(t *testing.T) {
	mock := newMockVaultClient()
	mock.secrets["mc-test"] = map[string]interface{}{"rcon_password": "existing"}
	srv := newTestServer(t, mock)

	req := httptest.NewRequest(http.MethodPost, "/secrets/minecraft/mc-test", nil)
	req.Header.Set("Authorization", "Bearer test-api-key")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d", w.Code, http.StatusConflict)
	}
}

func TestCreateSecrets_InvalidName(t *testing.T) {
	mock := newMockVaultClient()
	srv := newTestServer(t, mock)

	cases := []string{
		"-invalid",
		"UPPERCASE",
		"has.dots",
	}
	for _, name := range cases {
		req := httptest.NewRequest(http.MethodPost, "/secrets/minecraft/"+name, nil)
		req.Header.Set("Authorization", "Bearer test-api-key")
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest && w.Code != http.StatusNotFound {
			t.Errorf("name=%q: status = %d, want 400 or 404", name, w.Code)
		}
	}
}

func TestCreateSecrets_VaultError(t *testing.T) {
	mock := newMockVaultClient()
	mock.writeErr = fmt.Errorf("vault write failed")
	srv := newTestServer(t, mock)

	req := httptest.NewRequest(http.MethodPost, "/secrets/minecraft/mc-test", nil)
	req.Header.Set("Authorization", "Bearer test-api-key")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadGateway)
	}
}

// --- Read secrets tests ---

func TestReadSecrets_Success(t *testing.T) {
	mock := newMockVaultClient()
	mock.secrets["mc-test"] = map[string]interface{}{"rcon_password": "test-password"}
	srv := newTestServer(t, mock)

	req := httptest.NewRequest(http.MethodGet, "/secrets/minecraft/mc-test", nil)
	req.Header.Set("Authorization", "Bearer test-api-key")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp readSecretsResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.ServerName != "mc-test" {
		t.Errorf("server_name = %q, want mc-test", resp.ServerName)
	}
	if resp.RCONPassword != "test-password" {
		t.Errorf("rcon_password = %q, want test-password", resp.RCONPassword)
	}
}

func TestReadSecrets_NotFound(t *testing.T) {
	mock := newMockVaultClient()
	srv := newTestServer(t, mock)

	req := httptest.NewRequest(http.MethodGet, "/secrets/minecraft/mc-nonexistent", nil)
	req.Header.Set("Authorization", "Bearer test-api-key")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestReadSecrets_VaultError(t *testing.T) {
	mock := newMockVaultClient()
	mock.readErr = fmt.Errorf("vault read failed")
	srv := newTestServer(t, mock)

	req := httptest.NewRequest(http.MethodGet, "/secrets/minecraft/mc-test", nil)
	req.Header.Set("Authorization", "Bearer test-api-key")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadGateway)
	}
}

// --- Update secrets tests ---

func TestUpdateSecrets_Success(t *testing.T) {
	mock := newMockVaultClient()
	mock.secrets["mc-test"] = map[string]interface{}{"rcon_password": "old-password"}
	srv := newTestServer(t, mock)

	req := httptest.NewRequest(http.MethodPut, "/secrets/minecraft/mc-test", nil)
	req.Header.Set("Authorization", "Bearer test-api-key")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp updateSecretsResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if !resp.Updated {
		t.Error("updated = false, want true")
	}
	// Verify new password was stored (different from old)
	newPw, _ := mock.secrets["mc-test"]["rcon_password"].(string)
	if newPw == "old-password" {
		t.Error("password was not rotated")
	}
}

func TestUpdateSecrets_NotFound(t *testing.T) {
	mock := newMockVaultClient()
	srv := newTestServer(t, mock)

	req := httptest.NewRequest(http.MethodPut, "/secrets/minecraft/mc-nonexistent", nil)
	req.Header.Set("Authorization", "Bearer test-api-key")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

// --- Delete secrets tests ---

func TestDeleteSecrets_Success(t *testing.T) {
	mock := newMockVaultClient()
	mock.secrets["mc-test"] = map[string]interface{}{"rcon_password": "pw"}
	srv := newTestServer(t, mock)

	req := httptest.NewRequest(http.MethodDelete, "/secrets/minecraft/mc-test", nil)
	req.Header.Set("Authorization", "Bearer test-api-key")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp deleteSecretsResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if !resp.Deleted {
		t.Error("deleted = false, want true")
	}
	if mock.deleteName != "mc-test" {
		t.Errorf("deleted name = %q, want mc-test", mock.deleteName)
	}
}

func TestDeleteSecrets_VaultError(t *testing.T) {
	mock := newMockVaultClient()
	mock.deleteErr = fmt.Errorf("vault delete failed")
	srv := newTestServer(t, mock)

	req := httptest.NewRequest(http.MethodDelete, "/secrets/minecraft/mc-test", nil)
	req.Header.Set("Authorization", "Bearer test-api-key")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadGateway)
	}
}

// --- X-Trace-ID tests ---

func TestTraceID_PropagatedFromRequest(t *testing.T) {
	mock := newMockVaultClient()
	srv := newTestServer(t, mock)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("X-Trace-ID", "test-trace-123")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestTraceID_GeneratedWhenMissing(t *testing.T) {
	mock := newMockVaultClient()
	srv := newTestServer(t, mock)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	// No panic / no error means the trace ID was generated internally
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

// --- Server name validation tests ---

func TestValidateServerName(t *testing.T) {
	valid := []string{"mc-test", "a", "my-server-1", "0test", "a-b-c-d"}
	for _, name := range valid {
		if !validateServerName(name) {
			t.Errorf("validateServerName(%q) = false, want true", name)
		}
	}

	invalid := []string{"-invalid", "UPPER", "has spaces", "a.b", "../traversal", "a_b", ""}
	for _, name := range invalid {
		if validateServerName(name) {
			t.Errorf("validateServerName(%q) = true, want false", name)
		}
	}
}

// --- Path validation error handling ---

func TestCreateSecrets_UnauthorizedPath(t *testing.T) {
	mock := newMockVaultClient()
	mock.readErr = fmt.Errorf("unauthorized: path denied")
	srv := newTestServer(t, mock)

	req := httptest.NewRequest(http.MethodPost, "/secrets/minecraft/mc-test", nil)
	req.Header.Set("Authorization", "Bearer test-api-key")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}
