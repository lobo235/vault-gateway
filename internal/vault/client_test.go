package vault

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// --- helpers ---

func discardLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

// newTestVaultClient creates a Client backed by the given httptest.Server.
func newTestVaultClient(t *testing.T, ts *httptest.Server) *Client {
	t.Helper()
	cfg := vaultapi.DefaultConfig()
	cfg.Address = ts.URL
	raw, err := vaultapi.NewClient(cfg)
	if err != nil {
		t.Fatalf("failed to create vault client: %v", err)
	}
	raw.SetToken("test-token")
	return &Client{
		client: raw,
		log:    discardLogger(),
		stopCh: make(chan struct{}),
	}
}

// --- GeneratePassword tests ---

func TestGeneratePassword_Length(t *testing.T) {
	pw, err := GeneratePassword()
	if err != nil {
		t.Fatalf("GeneratePassword() error: %v", err)
	}
	if len(pw) != passwordLength {
		t.Errorf("password length = %d, want %d", len(pw), passwordLength)
	}
}

func TestGeneratePassword_Alphabet(t *testing.T) {
	for i := 0; i < 100; i++ {
		pw, err := GeneratePassword()
		if err != nil {
			t.Fatalf("GeneratePassword() error: %v", err)
		}
		for _, c := range pw {
			if !strings.ContainsRune(passwordAlphabet, c) {
				t.Errorf("password contains invalid character %q", c)
			}
		}
	}
}

func TestGeneratePassword_Uniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		pw, err := GeneratePassword()
		if err != nil {
			t.Fatalf("GeneratePassword() error: %v", err)
		}
		if seen[pw] {
			t.Errorf("duplicate password generated: %q", pw)
		}
		seen[pw] = true
	}
}

// --- validatePath tests ---

func TestValidatePath_Valid(t *testing.T) {
	if err := validatePath("kv/data/nomad/default/mc-test"); err != nil {
		t.Errorf("validatePath() unexpected error: %v", err)
	}
}

func TestValidatePath_Invalid(t *testing.T) {
	cases := []string{
		"kv/data/other/mc-test",
		"kv/metadata/nomad/default/mc-test",
		"secret/data/mc-test",
		"",
		"../kv/data/nomad/default/mc-test",
	}
	for _, path := range cases {
		if err := validatePath(path); err == nil {
			t.Errorf("validatePath(%q) expected error, got nil", path)
		}
	}
}

func TestValidateMetadataPath_Valid(t *testing.T) {
	if err := validateMetadataPath("kv/metadata/nomad/default/mc-test"); err != nil {
		t.Errorf("validateMetadataPath() unexpected error: %v", err)
	}
}

func TestValidateMetadataPath_Invalid(t *testing.T) {
	cases := []string{
		"kv/data/nomad/default/mc-test",
		"kv/metadata/other/mc-test",
		"",
	}
	for _, path := range cases {
		if err := validateMetadataPath(path); err == nil {
			t.Errorf("validateMetadataPath(%q) expected error, got nil", path)
		}
	}
}

// --- NewClient tests ---

func TestNewClient_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/approle/login" {
			w.Header().Set("Content-Type", "application/json")
			resp := map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   "s.test-token",
					"lease_duration": 3600,
					"renewable":      true,
					"policies":       []string{"default"},
				},
			}
			json.NewEncoder(w).Encode(resp)
			return
		}
		// token lookup for renewLoop's tokenTTL call
		if r.URL.Path == "/v1/auth/token/lookup-self" {
			w.Header().Set("Content-Type", "application/json")
			resp := map[string]interface{}{
				"data": map[string]interface{}{
					"ttl": 3600.0,
				},
			}
			json.NewEncoder(w).Encode(resp)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	c, err := NewClient(ts.URL, "test-role-id", "test-secret-id", discardLogger())
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	defer c.Close()
}

func TestNewClient_LoginFailure(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"errors": ["permission denied"]}`))
	}))
	defer ts.Close()

	_, err := NewClient(ts.URL, "bad-role", "bad-secret", discardLogger())
	if err == nil {
		t.Fatal("NewClient() expected error for login failure, got nil")
	}
	if !strings.Contains(err.Error(), "vault approle login") {
		t.Errorf("error = %q, want it to contain 'vault approle login'", err.Error())
	}
}

func TestNewClient_InvalidAddress(t *testing.T) {
	// Use an address that will fail to connect
	_, err := NewClient("http://127.0.0.1:1", "role", "secret", discardLogger())
	if err == nil {
		t.Fatal("NewClient() expected error for unreachable server, got nil")
	}
}

// --- login tests ---

func TestLogin_NoAuthData(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Return response with no auth block
		json.NewEncoder(w).Encode(map[string]interface{}{})
	}))
	defer ts.Close()

	c := newTestVaultClient(t, ts)
	defer c.Close()

	err := c.login("role", "secret")
	if err == nil {
		t.Fatal("login() expected error when no auth data, got nil")
	}
	if !strings.Contains(err.Error(), "no auth data") {
		t.Errorf("error = %q, want it to contain 'no auth data'", err.Error())
	}
}

func TestLogin_VaultError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"errors": ["internal error"]}`))
	}))
	defer ts.Close()

	c := newTestVaultClient(t, ts)
	defer c.Close()

	err := c.login("role", "secret")
	if err == nil {
		t.Fatal("login() expected error, got nil")
	}
}

// --- Ping tests ---

func TestPing_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"initialized": true,
				"sealed":      false,
				"standby":     false,
				"version":     "1.15.0",
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	c := newTestVaultClient(t, ts)
	defer c.Close()

	if err := c.Ping(); err != nil {
		t.Errorf("Ping() error: %v", err)
	}
}

func TestPing_Failure(t *testing.T) {
	// Server that immediately closes connections
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Close the connection abruptly by hijacking
		hj, ok := w.(http.Hijacker)
		if ok {
			conn, _, _ := hj.Hijack()
			conn.Close()
		}
	}))
	defer ts.Close()

	c := newTestVaultClient(t, ts)
	defer c.Close()

	err := c.Ping()
	if err == nil {
		t.Fatal("Ping() expected error for broken server, got nil")
	}
	if !strings.Contains(err.Error(), "vault health check") {
		t.Errorf("error = %q, want it to contain 'vault health check'", err.Error())
	}
}

// --- ReadSecret tests ---

func TestReadSecret_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/kv/data/nomad/default/mc-test" {
			w.Header().Set("Content-Type", "application/json")
			resp := map[string]interface{}{
				"data": map[string]interface{}{
					"data": map[string]interface{}{
						"rcon_password": "super-secret",
					},
					"metadata": map[string]interface{}{
						"version": 1,
					},
				},
			}
			json.NewEncoder(w).Encode(resp)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	c := newTestVaultClient(t, ts)
	defer c.Close()

	data, err := c.ReadSecret("mc-test")
	if err != nil {
		t.Fatalf("ReadSecret() error: %v", err)
	}
	if data == nil {
		t.Fatal("ReadSecret() returned nil data")
	}
	pw, ok := data["rcon_password"].(string)
	if !ok || pw != "super-secret" {
		t.Errorf("rcon_password = %q, want 'super-secret'", pw)
	}
}

func TestReadSecret_NotFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Vault returns 404 for missing secrets
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	c := newTestVaultClient(t, ts)
	defer c.Close()

	data, err := c.ReadSecret("nonexistent")
	if err != nil {
		t.Fatalf("ReadSecret() error: %v (expected nil error for not found)", err)
	}
	if data != nil {
		t.Errorf("ReadSecret() = %v, want nil for missing secret", data)
	}
}

func TestReadSecret_VaultError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if ok {
			conn, _, _ := hj.Hijack()
			conn.Close()
		}
	}))
	defer ts.Close()

	c := newTestVaultClient(t, ts)
	defer c.Close()

	_, err := c.ReadSecret("mc-test")
	if err == nil {
		t.Fatal("ReadSecret() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "read secret") {
		t.Errorf("error = %q, want it to contain 'read secret'", err.Error())
	}
}

func TestReadSecret_UnexpectedDataFormat(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Return data where the inner "data" key is not a map
		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"data": "not-a-map",
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	c := newTestVaultClient(t, ts)
	defer c.Close()

	_, err := c.ReadSecret("mc-test")
	if err == nil {
		t.Fatal("ReadSecret() expected error for unexpected data format, got nil")
	}
	if !strings.Contains(err.Error(), "unexpected data format") {
		t.Errorf("error = %q, want it to contain 'unexpected data format'", err.Error())
	}
}

func TestReadSecret_NilData(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Return a valid response with no data
		resp := map[string]interface{}{}
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	c := newTestVaultClient(t, ts)
	defer c.Close()

	data, err := c.ReadSecret("mc-test")
	if err != nil {
		t.Fatalf("ReadSecret() error: %v", err)
	}
	if data != nil {
		t.Errorf("ReadSecret() = %v, want nil for empty response", data)
	}
}

// --- WriteSecret tests ---

func TestWriteSecret_Success(t *testing.T) {
	var receivedPath string
	var receivedBody map[string]interface{}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/v1/kv/data/nomad/default/") {
			receivedPath = r.URL.Path
			body, _ := io.ReadAll(r.Body)
			json.Unmarshal(body, &receivedBody)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"version": 1,
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	c := newTestVaultClient(t, ts)
	defer c.Close()

	data := map[string]interface{}{"rcon_password": "test-pw"}
	err := c.WriteSecret("mc-test", data)
	if err != nil {
		t.Fatalf("WriteSecret() error: %v", err)
	}

	if receivedPath != "/v1/kv/data/nomad/default/mc-test" {
		t.Errorf("wrote to path %q, want /v1/kv/data/nomad/default/mc-test", receivedPath)
	}

	// Verify the payload was wrapped in the KV v2 "data" envelope
	innerData, ok := receivedBody["data"].(map[string]interface{})
	if !ok {
		t.Fatal("request body missing 'data' wrapper")
	}
	if innerData["rcon_password"] != "test-pw" {
		t.Errorf("rcon_password = %v, want 'test-pw'", innerData["rcon_password"])
	}
}

func TestWriteSecret_VaultError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if ok {
			conn, _, _ := hj.Hijack()
			conn.Close()
		}
	}))
	defer ts.Close()

	c := newTestVaultClient(t, ts)
	defer c.Close()

	err := c.WriteSecret("mc-test", map[string]interface{}{"key": "val"})
	if err == nil {
		t.Fatal("WriteSecret() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "write secret") {
		t.Errorf("error = %q, want it to contain 'write secret'", err.Error())
	}
}

// --- DeleteSecret tests ---

func TestDeleteSecret_Success(t *testing.T) {
	var receivedPath string
	var receivedMethod string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/kv/metadata/nomad/default/") {
			receivedPath = r.URL.Path
			receivedMethod = r.Method
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	c := newTestVaultClient(t, ts)
	defer c.Close()

	err := c.DeleteSecret("mc-test")
	if err != nil {
		t.Fatalf("DeleteSecret() error: %v", err)
	}

	if receivedPath != "/v1/kv/metadata/nomad/default/mc-test" {
		t.Errorf("deleted path %q, want /v1/kv/metadata/nomad/default/mc-test", receivedPath)
	}
	if receivedMethod != http.MethodDelete {
		t.Errorf("method = %q, want DELETE", receivedMethod)
	}
}

func TestDeleteSecret_VaultError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if ok {
			conn, _, _ := hj.Hijack()
			conn.Close()
		}
	}))
	defer ts.Close()

	c := newTestVaultClient(t, ts)
	defer c.Close()

	err := c.DeleteSecret("mc-test")
	if err == nil {
		t.Fatal("DeleteSecret() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "delete secret") {
		t.Errorf("error = %q, want it to contain 'delete secret'", err.Error())
	}
}

// --- Close tests ---

func TestClose_Idempotent(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer ts.Close()

	c := newTestVaultClient(t, ts)

	// Calling Close multiple times should not panic
	c.Close()
	c.Close()
	c.Close()
}

// --- tokenTTL tests ---

func TestTokenTTL_JsonNumber(t *testing.T) {
	// The Vault API client uses json.NewDecoder with UseNumber(), so numeric
	// values come through as json.Number. tokenTTL handles this correctly.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/token/lookup-self" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"request_id":"abc","data":{"ttl":3600}}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	c := newTestVaultClient(t, ts)
	defer c.Close()

	ttl := c.tokenTTL()
	if ttl != 3600*time.Second {
		t.Errorf("tokenTTL() = %v, want %v", ttl, 3600*time.Second)
	}
}

func TestTokenTTL_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if ok {
			conn, _, _ := hj.Hijack()
			conn.Close()
		}
	}))
	defer ts.Close()

	c := newTestVaultClient(t, ts)
	defer c.Close()

	ttl := c.tokenTTL()
	if ttl != 0 {
		t.Errorf("tokenTTL() = %v, want 0 on error", ttl)
	}
}

func TestTokenTTL_NilData(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/token/lookup-self" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{})
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	c := newTestVaultClient(t, ts)
	defer c.Close()

	ttl := c.tokenTTL()
	if ttl != 0 {
		t.Errorf("tokenTTL() = %v, want 0 for nil data", ttl)
	}
}

func TestTokenTTL_MissingTTLKey(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/token/lookup-self" {
			w.Header().Set("Content-Type", "application/json")
			resp := map[string]interface{}{
				"data": map[string]interface{}{
					"other_field": "value",
				},
			}
			json.NewEncoder(w).Encode(resp)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	c := newTestVaultClient(t, ts)
	defer c.Close()

	ttl := c.tokenTTL()
	if ttl != 0 {
		t.Errorf("tokenTTL() = %v, want 0 for missing ttl key", ttl)
	}
}

func TestTokenTTL_UnsupportedType(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/token/lookup-self" {
			w.Header().Set("Content-Type", "application/json")
			resp := map[string]interface{}{
				"data": map[string]interface{}{
					"ttl": "not-a-number",
				},
			}
			json.NewEncoder(w).Encode(resp)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	c := newTestVaultClient(t, ts)
	defer c.Close()

	ttl := c.tokenTTL()
	if ttl != 0 {
		t.Errorf("tokenTTL() = %v, want 0 for unsupported type", ttl)
	}
}

// --- renewToken tests ---

func TestRenewToken_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/token/renew-self" {
			w.Header().Set("Content-Type", "application/json")
			resp := map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   "s.renewed-token",
					"lease_duration": 7200,
					"renewable":      true,
					"policies":       []string{"default"},
				},
			}
			json.NewEncoder(w).Encode(resp)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	c := newTestVaultClient(t, ts)
	defer c.Close()

	if err := c.renewToken(); err != nil {
		t.Errorf("renewToken() error: %v", err)
	}
}

func TestRenewToken_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if ok {
			conn, _, _ := hj.Hijack()
			conn.Close()
		}
	}))
	defer ts.Close()

	c := newTestVaultClient(t, ts)
	defer c.Close()

	err := c.renewToken()
	if err == nil {
		t.Fatal("renewToken() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "renew token") {
		t.Errorf("error = %q, want it to contain 'renew token'", err.Error())
	}
}

func TestRenewToken_NoAuthData(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/token/renew-self" {
			w.Header().Set("Content-Type", "application/json")
			// Return response with no auth block
			json.NewEncoder(w).Encode(map[string]interface{}{})
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	c := newTestVaultClient(t, ts)
	defer c.Close()

	err := c.renewToken()
	if err == nil {
		t.Fatal("renewToken() expected error for no auth data, got nil")
	}
	if !strings.Contains(err.Error(), "no auth data") {
		t.Errorf("error = %q, want it to contain 'no auth data'", err.Error())
	}
}

// --- renewLoop tests ---

func TestRenewLoop_StopsOnClose(t *testing.T) {
	var lookupCount atomic.Int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/token/lookup-self" {
			lookupCount.Add(1)
			w.Header().Set("Content-Type", "application/json")
			// Return very short TTL to trigger quick renewal
			resp := map[string]interface{}{
				"data": map[string]interface{}{
					"ttl": 1.0,
				},
			}
			json.NewEncoder(w).Encode(resp)
			return
		}
		if r.URL.Path == "/v1/auth/token/renew-self" {
			w.Header().Set("Content-Type", "application/json")
			resp := map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   "s.renewed",
					"lease_duration": 1,
					"renewable":      true,
				},
			}
			json.NewEncoder(w).Encode(resp)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	c := newTestVaultClient(t, ts)

	go c.renewLoop("role", "secret")

	// Give it a moment to start the loop
	time.Sleep(100 * time.Millisecond)

	// Close should stop the loop
	c.Close()

	// Give it time to exit
	time.Sleep(100 * time.Millisecond)

	// The loop should have called tokenTTL at least once
	if lookupCount.Load() < 1 {
		t.Error("renewLoop did not call tokenTTL")
	}
}

func TestLogin_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/approle/login" {
			w.Header().Set("Content-Type", "application/json")
			resp := map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   "s.new-token",
					"lease_duration": 3600,
					"renewable":      true,
					"policies":       []string{"default"},
				},
			}
			json.NewEncoder(w).Encode(resp)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	c := newTestVaultClient(t, ts)
	defer c.Close()

	err := c.login("test-role", "test-secret")
	if err != nil {
		t.Fatalf("login() error: %v", err)
	}
}
