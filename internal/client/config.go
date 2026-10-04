package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"time"
)

const ConfigDirName = "uvpn"

// Config is the on-disk state for the CLI. It is written with mode 0600 because
// it holds a live proxy credential.
type Config struct {
	// Location is the location ID the user last connected to.
	Location string `json:"location,omitempty"`
	// Country is a human-readable label for Location.
	Country string `json:"country,omitempty"`
	// Proxy is the proxy endpoint (host:port) currently in effect.
	Proxy string `json:"proxy,omitempty"`
	// Scheme is the proxy scheme (http, https, socks5, ...).
	Scheme string `json:"scheme,omitempty"`
	// Username/Password are the time-limited proxy credentials.
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	// ExpiresAt is the proxy credential expiry, already clock-shifted.
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	// AuthToken is the cached anonymous auth token (type "anonm").
	AuthToken *Token `json:"auth_token,omitempty"`
	// SecurityToken is the cached HS256 security token (type "accs").
	SecurityToken *Token `json:"security_token,omitempty"`
	// WGCountry is the country of the registered WireGuard peer, empty when no
	// tunnel is configured.
	WGCountry string `json:"wg_country,omitempty"`
	// WGEndpoint is the peer's host:port.
	WGEndpoint string `json:"wg_endpoint,omitempty"`
	// WGPublicKey is our X25519 public key, as registered with the server.
	WGPublicKey string `json:"wg_public_key,omitempty"`
	// WGPrivateKey is our X25519 private key. It never leaves this machine, but
	// it is written here, so the file is 0600 for that reason alone.
	WGPrivateKey string `json:"wg_private_key,omitempty"`
}

// configPath returns ~/.config/uvpn/config.json.
func configPath() (string, error) {
	if os.Geteuid() == 0 {
		if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
			if u, err := user.Lookup(sudoUser); err == nil && u.HomeDir != "" {
				return filepath.Join(u.HomeDir, ".config", ConfigDirName, "config.json"), nil
			}
		}
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, ConfigDirName, "config.json"), nil
}

// LoadConfig reads the config, returning a zero Config if none exists yet.
func LoadConfig() (*Config, error) {
	p, err := configPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return &Config{}, nil
	}
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", p, err)
	}
	return &c, nil
}

// SaveConfig writes the config atomically with 0600 permissions.
func SaveConfig(c *Config) error {
	p, err := configPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// ClearConfig removes the active proxy credential on disconnect, but keeps the
// cached auth tokens so the next connect does not re-register.
func ClearConfig() error {
	c, err := LoadConfig()
	if err != nil {
		return err
	}
	auth, sec := c.AuthToken, c.SecurityToken
	*c = Config{}
	c.AuthToken, c.SecurityToken = auth, sec
	return SaveConfig(c)
}

// CredentialValid reports whether the stored credential is still usable,
// allowing a refresh margin so we never hand out a token about to expire.
func (c *Config) CredentialValid(now time.Time, margin time.Duration) bool {
	if c.Username == "" || c.Password == "" || c.Proxy == "" {
		return false
	}
	if c.ExpiresAt.IsZero() {
		// No expiry recorded: treat as valid so we can still try it once.
		return true
	}
	return c.ExpiresAt.After(now.Add(margin))
}
