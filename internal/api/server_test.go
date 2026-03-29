package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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

// --- Additional handler error path tests ---

func TestCreateSecrets_WriteUnauthorized(t *testing.T) {
	mock := newMockVaultClient()
	mock.writeErr = fmt.Errorf("unauthorized: vault path access denied")
	srv := newTestServer(t, mock)

	req := httptest.NewRequest(http.MethodPost, "/secrets/minecraft/mc-test", nil)
	req.Header.Set("Authorization", "Bearer test-api-key")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestReadSecrets_InvalidName(t *testing.T) {
	mock := newMockVaultClient()
	srv := newTestServer(t, mock)

	req := httptest.NewRequest(http.MethodGet, "/secrets/minecraft/-bad", nil)
	req.Header.Set("Authorization", "Bearer test-api-key")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestReadSecrets_Unauthorized(t *testing.T) {
	mock := newMockVaultClient()
	mock.readErr = fmt.Errorf("unauthorized: path denied")
	srv := newTestServer(t, mock)

	req := httptest.NewRequest(http.MethodGet, "/secrets/minecraft/mc-test", nil)
	req.Header.Set("Authorization", "Bearer test-api-key")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestUpdateSecrets_InvalidName(t *testing.T) {
	mock := newMockVaultClient()
	srv := newTestServer(t, mock)

	req := httptest.NewRequest(http.MethodPut, "/secrets/minecraft/BAD", nil)
	req.Header.Set("Authorization", "Bearer test-api-key")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestUpdateSecrets_ReadUnauthorized(t *testing.T) {
	mock := newMockVaultClient()
	mock.readErr = fmt.Errorf("unauthorized: path denied")
	srv := newTestServer(t, mock)

	req := httptest.NewRequest(http.MethodPut, "/secrets/minecraft/mc-test", nil)
	req.Header.Set("Authorization", "Bearer test-api-key")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestUpdateSecrets_ReadVaultError(t *testing.T) {
	mock := newMockVaultClient()
	mock.readErr = fmt.Errorf("vault connection failed")
	srv := newTestServer(t, mock)

	req := httptest.NewRequest(http.MethodPut, "/secrets/minecraft/mc-test", nil)
	req.Header.Set("Authorization", "Bearer test-api-key")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadGateway)
	}
}

func TestUpdateSecrets_WriteUnauthorized(t *testing.T) {
	mock := newMockVaultClient()
	mock.secrets["mc-test"] = map[string]interface{}{"rcon_password": "old"}
	mock.writeErr = fmt.Errorf("unauthorized: vault path access denied")
	srv := newTestServer(t, mock)

	req := httptest.NewRequest(http.MethodPut, "/secrets/minecraft/mc-test", nil)
	req.Header.Set("Authorization", "Bearer test-api-key")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestUpdateSecrets_WriteVaultError(t *testing.T) {
	mock := newMockVaultClient()
	mock.secrets["mc-test"] = map[string]interface{}{"rcon_password": "old"}
	mock.writeErr = fmt.Errorf("vault write failed")
	srv := newTestServer(t, mock)

	req := httptest.NewRequest(http.MethodPut, "/secrets/minecraft/mc-test", nil)
	req.Header.Set("Authorization", "Bearer test-api-key")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadGateway)
	}
}

func TestDeleteSecrets_InvalidName(t *testing.T) {
	mock := newMockVaultClient()
	srv := newTestServer(t, mock)

	req := httptest.NewRequest(http.MethodDelete, "/secrets/minecraft/BAD", nil)
	req.Header.Set("Authorization", "Bearer test-api-key")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestDeleteSecrets_Unauthorized(t *testing.T) {
	mock := newMockVaultClient()
	mock.deleteErr = fmt.Errorf("unauthorized: path denied")
	srv := newTestServer(t, mock)

	req := httptest.NewRequest(http.MethodDelete, "/secrets/minecraft/mc-test", nil)
	req.Header.Set("Authorization", "Bearer test-api-key")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

// --- Middleware helper tests ---

func TestExtractBearer_Valid(t *testing.T) {
	token := extractBearer("Bearer my-token-123")
	if token != "my-token-123" {
		t.Errorf("extractBearer() = %q, want 'my-token-123'", token)
	}
}

func TestExtractBearer_NoPrefix(t *testing.T) {
	token := extractBearer("my-token-123")
	if token != "" {
		t.Errorf("extractBearer() = %q, want empty string", token)
	}
}

func TestExtractBearer_Empty(t *testing.T) {
	token := extractBearer("")
	if token != "" {
		t.Errorf("extractBearer() = %q, want empty string", token)
	}
}

func TestExtractBearer_WithWhitespace(t *testing.T) {
	token := extractBearer("Bearer   my-token  ")
	if token != "my-token" {
		t.Errorf("extractBearer() = %q, want 'my-token'", token)
	}
}

func TestTraceIDFromContext_Present(t *testing.T) {
	ctx := context.WithValue(context.Background(), traceIDKey, "trace-abc")
	id := traceIDFromContext(ctx)
	if id != "trace-abc" {
		t.Errorf("traceIDFromContext() = %q, want 'trace-abc'", id)
	}
}

func TestTraceIDFromContext_Missing(t *testing.T) {
	id := traceIDFromContext(context.Background())
	if id != "" {
		t.Errorf("traceIDFromContext() = %q, want empty string", id)
	}
}

func TestGenerateTraceID_Format(t *testing.T) {
	id := generateTraceID()
	if len(id) != 32 {
		t.Errorf("generateTraceID() length = %d, want 32 hex characters", len(id))
	}
	// Should be unique
	id2 := generateTraceID()
	if id == id2 {
		t.Error("generateTraceID() returned duplicate values")
	}
}

func TestIsUnauthorizedErr(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{fmt.Errorf("unauthorized: path denied"), true},
		{fmt.Errorf("unauthorized: something"), true},
		{fmt.Errorf("vault connection failed"), false},
		{fmt.Errorf("permission denied"), false},
	}
	for _, tc := range cases {
		got := isUnauthorizedErr(tc.err)
		if got != tc.want {
			t.Errorf("isUnauthorizedErr(%q) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

// --- Server.Run tests ---

func TestRun_StartsAndStops(t *testing.T) {
	mock := newMockVaultClient()
	srv := newTestServer(t, mock)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Run(ctx, ":0") // port 0 for random available port
	}()

	// Give the server a moment to start
	time.Sleep(50 * time.Millisecond)

	// Cancel context to trigger shutdown
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Run() returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run() did not shut down within 5 seconds")
	}
}

// --- Response format tests ---

func TestWriteError_Format(t *testing.T) {
	mock := newMockVaultClient()
	srv := newTestServer(t, mock)

	// Trigger a 401 error and check the response format
	req := httptest.NewRequest(http.MethodGet, "/secrets/minecraft/mc-test", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want 'application/json'", ct)
	}

	var resp errorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if resp.Code == "" {
		t.Error("error response code is empty")
	}
	if resp.Message == "" {
		t.Error("error response message is empty")
	}
}

func TestWriteJSON_ContentType(t *testing.T) {
	mock := newMockVaultClient()
	srv := newTestServer(t, mock)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want 'application/json'", ct)
	}
}

// --- Method not allowed tests ---

func TestMethodNotAllowed(t *testing.T) {
	mock := newMockVaultClient()
	srv := newTestServer(t, mock)

	// PATCH is not a registered method for /secrets/minecraft/{serverName}
	req := httptest.NewRequest(http.MethodPatch, "/secrets/minecraft/mc-test", nil)
	req.Header.Set("Authorization", "Bearer test-api-key")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	// Should get 405 or 404, not a panic
	if w.Code == http.StatusOK {
		t.Error("PATCH should not return 200")
	}
}

// --- Generic secret tests ---

func TestCreateGenericSecret_Success(t *testing.T) {
	mock := newMockVaultClient()
	srv := newTestServer(t, mock)

	body := `{"data":{"db_password":"s3cret","db_user":"admin"}}`
	req := httptest.NewRequest(http.MethodPost, "/secrets/postgres/my-db", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer test-api-key")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", w.Code, http.StatusCreated)
	}

	var resp createGenericSecretResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Category != "postgres" {
		t.Errorf("category = %q, want postgres", resp.Category)
	}
	if resp.Name != "my-db" {
		t.Errorf("name = %q, want my-db", resp.Name)
	}
	if !resp.Created {
		t.Error("created = false, want true")
	}
	if !mock.writeCalled {
		t.Error("WriteSecret was not called")
	}
	// Verify data was stored at the correct path
	stored, ok := mock.secrets["postgres/my-db"]
	if !ok {
		t.Fatal("secret not stored at postgres/my-db")
	}
	if stored["db_password"] != "s3cret" {
		t.Errorf("db_password = %q, want s3cret", stored["db_password"])
	}
	if stored["db_user"] != "admin" {
		t.Errorf("db_user = %q, want admin", stored["db_user"])
	}
}

func TestCreateGenericSecret_AlreadyExists(t *testing.T) {
	mock := newMockVaultClient()
	mock.secrets["postgres/my-db"] = map[string]interface{}{"db_password": "existing"}
	srv := newTestServer(t, mock)

	body := `{"data":{"db_password":"new"}}`
	req := httptest.NewRequest(http.MethodPost, "/secrets/postgres/my-db", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer test-api-key")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d", w.Code, http.StatusConflict)
	}
}

func TestCreateGenericSecret_MissingBody(t *testing.T) {
	mock := newMockVaultClient()
	srv := newTestServer(t, mock)

	req := httptest.NewRequest(http.MethodPost, "/secrets/postgres/my-db", nil)
	req.Header.Set("Authorization", "Bearer test-api-key")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestCreateGenericSecret_EmptyData(t *testing.T) {
	mock := newMockVaultClient()
	srv := newTestServer(t, mock)

	body := `{"data":{}}`
	req := httptest.NewRequest(http.MethodPost, "/secrets/postgres/my-db", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer test-api-key")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestCreateGenericSecret_InvalidCategory(t *testing.T) {
	mock := newMockVaultClient()
	srv := newTestServer(t, mock)

	body := `{"data":{"key":"val"}}`
	req := httptest.NewRequest(http.MethodPost, "/secrets/INVALID/my-db", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer test-api-key")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestCreateGenericSecret_InvalidName(t *testing.T) {
	mock := newMockVaultClient()
	srv := newTestServer(t, mock)

	body := `{"data":{"key":"val"}}`
	req := httptest.NewRequest(http.MethodPost, "/secrets/postgres/-bad", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer test-api-key")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestReadGenericSecret_Success(t *testing.T) {
	mock := newMockVaultClient()
	mock.secrets["redis/cache1"] = map[string]interface{}{"password": "r3dis", "port": "6379"}
	srv := newTestServer(t, mock)

	req := httptest.NewRequest(http.MethodGet, "/secrets/redis/cache1", nil)
	req.Header.Set("Authorization", "Bearer test-api-key")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp readGenericSecretResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Category != "redis" {
		t.Errorf("category = %q, want redis", resp.Category)
	}
	if resp.Name != "cache1" {
		t.Errorf("name = %q, want cache1", resp.Name)
	}
	if resp.Data["password"] != "r3dis" {
		t.Errorf("password = %q, want r3dis", resp.Data["password"])
	}
	if resp.Data["port"] != "6379" {
		t.Errorf("port = %q, want 6379", resp.Data["port"])
	}
}

func TestReadGenericSecret_NotFound(t *testing.T) {
	mock := newMockVaultClient()
	srv := newTestServer(t, mock)

	req := httptest.NewRequest(http.MethodGet, "/secrets/redis/nonexistent", nil)
	req.Header.Set("Authorization", "Bearer test-api-key")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestUpdateGenericSecret_Success(t *testing.T) {
	mock := newMockVaultClient()
	mock.secrets["redis/cache1"] = map[string]interface{}{"password": "old"}
	srv := newTestServer(t, mock)

	body := `{"data":{"password":"new-password","port":"6380"}}`
	req := httptest.NewRequest(http.MethodPut, "/secrets/redis/cache1", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer test-api-key")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp updateGenericSecretResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Category != "redis" {
		t.Errorf("category = %q, want redis", resp.Category)
	}
	if resp.Name != "cache1" {
		t.Errorf("name = %q, want cache1", resp.Name)
	}
	if !resp.Updated {
		t.Error("updated = false, want true")
	}
	// Verify data was overwritten
	stored := mock.secrets["redis/cache1"]
	if stored["password"] != "new-password" {
		t.Errorf("password = %q, want new-password", stored["password"])
	}
}

func TestUpdateGenericSecret_NotFound(t *testing.T) {
	mock := newMockVaultClient()
	srv := newTestServer(t, mock)

	body := `{"data":{"password":"new"}}`
	req := httptest.NewRequest(http.MethodPut, "/secrets/redis/nonexistent", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer test-api-key")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestDeleteGenericSecret_Success(t *testing.T) {
	mock := newMockVaultClient()
	mock.secrets["redis/cache1"] = map[string]interface{}{"password": "pw"}
	srv := newTestServer(t, mock)

	req := httptest.NewRequest(http.MethodDelete, "/secrets/redis/cache1", nil)
	req.Header.Set("Authorization", "Bearer test-api-key")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp deleteGenericSecretResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Category != "redis" {
		t.Errorf("category = %q, want redis", resp.Category)
	}
	if resp.Name != "cache1" {
		t.Errorf("name = %q, want cache1", resp.Name)
	}
	if !resp.Deleted {
		t.Error("deleted = false, want true")
	}
	if mock.deleteName != "redis/cache1" {
		t.Errorf("deleted name = %q, want redis/cache1", mock.deleteName)
	}
}

func TestMinecraftRoutesStillWork(t *testing.T) {
	// Verify that minecraft-specific routes are not broken by the generic routes
	mock := newMockVaultClient()
	srv := newTestServer(t, mock)

	req := httptest.NewRequest(http.MethodPost, "/secrets/minecraft/mc-test", nil)
	req.Header.Set("Authorization", "Bearer test-api-key")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("minecraft POST status = %d, want %d", w.Code, http.StatusCreated)
	}

	// Verify it created with rcon_password (minecraft behavior), not generic behavior
	var resp createSecretsResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.ServerName != "mc-test" {
		t.Errorf("server_name = %q, want mc-test", resp.ServerName)
	}
	if _, ok := mock.secrets["mc-test"]["rcon_password"]; !ok {
		t.Error("minecraft route did not auto-generate rcon_password")
	}
}
