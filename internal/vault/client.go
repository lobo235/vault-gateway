package vault

import (
	"crypto/rand"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"sync"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// passwordAlphabet is the set of characters used to generate RCON passwords.
// Strictly [a-zA-Z0-9_.-] — no shell metacharacters.
const passwordAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"

// passwordLength is the length of generated RCON passwords.
const passwordLength = 32

// kvDataPrefix is the required prefix for KV v2 data operations.
const kvDataPrefix = "kv/data/nomad/default/"

// kvMetadataPrefix is the required prefix for KV v2 metadata operations.
const kvMetadataPrefix = "kv/metadata/nomad/default/"

// Client wraps the Vault API for KV v2 secret operations with AppRole auth.
type Client struct {
	client *vaultapi.Client
	log    *slog.Logger

	stopOnce sync.Once
	stopCh   chan struct{}
}

// NewClient creates a Vault client, authenticates via AppRole, and starts token renewal.
func NewClient(addr, roleID, secretID string, log *slog.Logger) (*Client, error) {
	cfg := vaultapi.DefaultConfig()
	cfg.Address = addr

	raw, err := vaultapi.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("create vault client: %w", err)
	}

	c := &Client{
		client: raw,
		log:    log,
		stopCh: make(chan struct{}),
	}

	if err := c.login(roleID, secretID); err != nil {
		return nil, fmt.Errorf("vault approle login: %w", err)
	}

	go c.renewLoop(roleID, secretID)

	return c, nil
}

// login exchanges AppRole credentials for a Vault token.
func (c *Client) login(roleID, secretID string) error {
	payload := map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	}

	secret, err := c.client.Logical().Write("auth/approle/login", payload)
	if err != nil {
		return fmt.Errorf("approle login: %w", err)
	}
	if secret == nil || secret.Auth == nil {
		return fmt.Errorf("approle login returned no auth data")
	}

	c.client.SetToken(secret.Auth.ClientToken)
	c.log.Info("vault approle login successful", "lease_duration_s", secret.Auth.LeaseDuration)
	return nil
}

// renewLoop renews the Vault token at 2/3 of its TTL. If renewal fails, it re-authenticates.
func (c *Client) renewLoop(roleID, secretID string) {
	for {
		ttl := c.tokenTTL()
		if ttl <= 0 {
			ttl = 60 * time.Second
		}
		renewAt := ttl * 2 / 3
		if renewAt < 5*time.Second {
			renewAt = 5 * time.Second
		}

		c.log.Debug("vault token renewal scheduled", "ttl_s", int(ttl.Seconds()), "renew_in_s", int(renewAt.Seconds()))

		select {
		case <-time.After(renewAt):
			// Try renewal first
			if err := c.renewToken(); err != nil {
				c.log.Warn("vault token renewal failed, re-authenticating", "error", err)
				if err := c.login(roleID, secretID); err != nil {
					c.log.Error("vault re-authentication failed", "error", err)
				}
			}
		case <-c.stopCh:
			return
		}
	}
}

// tokenTTL returns the remaining TTL of the current token.
func (c *Client) tokenTTL() time.Duration {
	secret, err := c.client.Auth().Token().LookupSelf()
	if err != nil {
		return 0
	}
	if secret == nil || secret.Data == nil {
		return 0
	}
	ttlRaw, ok := secret.Data["ttl"]
	if !ok {
		return 0
	}
	// Vault returns ttl as a json.Number
	switch v := ttlRaw.(type) {
	case float64:
		return time.Duration(v) * time.Second
	case int:
		return time.Duration(v) * time.Second
	default:
		return 0
	}
}

// renewToken attempts to renew the current Vault token.
func (c *Client) renewToken() error {
	secret, err := c.client.Auth().Token().RenewSelf(0)
	if err != nil {
		return fmt.Errorf("renew token: %w", err)
	}
	if secret == nil || secret.Auth == nil {
		return fmt.Errorf("renew returned no auth data")
	}
	c.log.Info("vault token renewed", "lease_duration_s", secret.Auth.LeaseDuration)
	return nil
}

// Close stops the token renewal loop.
func (c *Client) Close() {
	c.stopOnce.Do(func() { close(c.stopCh) })
}

// Ping checks Vault reachability by calling sys/health.
func (c *Client) Ping() error {
	_, err := c.client.Sys().Health()
	if err != nil {
		return fmt.Errorf("vault health check: %w", err)
	}
	return nil
}

// ReadSecret reads a KV v2 secret at kv/data/nomad/default/<name>.
func (c *Client) ReadSecret(name string) (map[string]interface{}, error) {
	path := kvDataPrefix + name
	if err := validatePath(path); err != nil {
		return nil, err
	}

	secret, err := c.client.Logical().Read(path)
	if err != nil {
		return nil, fmt.Errorf("read secret %q: %w", name, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, nil
	}

	// KV v2 wraps data under a "data" key
	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("read secret %q: unexpected data format", name)
	}
	return data, nil
}

// WriteSecret writes a KV v2 secret at kv/data/nomad/default/<name>.
func (c *Client) WriteSecret(name string, data map[string]interface{}) error {
	path := kvDataPrefix + name
	if err := validatePath(path); err != nil {
		return err
	}

	// KV v2 expects data nested under a "data" key
	payload := map[string]interface{}{
		"data": data,
	}

	_, err := c.client.Logical().Write(path, payload)
	if err != nil {
		return fmt.Errorf("write secret %q: %w", name, err)
	}
	return nil
}

// DeleteSecret deletes all versions of a KV v2 secret using the metadata path.
func (c *Client) DeleteSecret(name string) error {
	path := kvMetadataPrefix + name
	if err := validateMetadataPath(path); err != nil {
		return err
	}

	_, err := c.client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("delete secret %q: %w", name, err)
	}
	return nil
}

// GeneratePassword creates a cryptographically random password of the configured length
// using characters from [a-zA-Z0-9_.-].
func GeneratePassword() (string, error) {
	alphabetLen := big.NewInt(int64(len(passwordAlphabet)))
	buf := make([]byte, passwordLength)
	for i := range buf {
		idx, err := rand.Int(rand.Reader, alphabetLen)
		if err != nil {
			return "", fmt.Errorf("generate password: %w", err)
		}
		buf[i] = passwordAlphabet[idx.Int64()]
	}
	return string(buf), nil
}

// validatePath ensures the path starts with the required KV v2 data prefix.
func validatePath(path string) error {
	if !strings.HasPrefix(path, kvDataPrefix) {
		return fmt.Errorf("unauthorized: path %q does not start with %q", path, kvDataPrefix)
	}
	return nil
}

// validateMetadataPath ensures the path starts with the required KV v2 metadata prefix.
func validateMetadataPath(path string) error {
	if !strings.HasPrefix(path, kvMetadataPrefix) {
		return fmt.Errorf("unauthorized: path %q does not start with %q", path, kvMetadataPrefix)
	}
	return nil
}
