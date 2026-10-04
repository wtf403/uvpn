package wg

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"

	"uvpn/internal/client"
)

// ConfigPath is where the generated wg-quick config lives. It holds the
// private key, so it is written 0600 inside the 0700 config directory.
func ConfigPath() (string, error) {
	if os.Geteuid() == 0 {
		if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
			if u, err := user.Lookup(sudoUser); err == nil && u.HomeDir != "" {
				return filepath.Join(u.HomeDir, ".config", client.ConfigDirName, "wg0.conf"), nil
			}
		}
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, client.ConfigDirName, "wg0.conf"), nil
}

// Render produces a wg-quick config. wg-quick and `wg syncconf` both accept this
// format, and the field names are WireGuard's, not ours.
func (c *Config) Render() string {
	out := "# written by uvpn - WireGuard tunnel\n"
	out += "# source https://config-toolbar.urban-vpn.com/rest/v1/configs/vpn\n\n"
	out += "[Interface]\n"
	out += fmt.Sprintf("PrivateKey = %s\n", c.PrivateKey)
	if c.Address != "" {
		out += fmt.Sprintf("Address = %s\n", c.Address)
	}
	out += fmt.Sprintf("MTU = %d\n", c.MTU)
	out += fmt.Sprintf("DNS = %s\n\n", c.DNS)
	out += "[Peer]\n"
	out += fmt.Sprintf("PublicKey = %s\n", c.PeerKey)
	if c.Preshared != "" {
		out += fmt.Sprintf("PresharedKey = %s\n", c.Preshared)
	}
	out += fmt.Sprintf("Endpoint = %s\n", c.Endpoint)
	out += fmt.Sprintf("AllowedIPs = %s\n", c.AllowedIPs)
	// Keeps NAT bindings alive through short idle periods; the endpoint is
	// almost always a hostname, so this is what makes roaming work.
	out += "PersistentKeepalive = 25\n"
	return out
}

// Write persists the config for wg-quick to consume.
func (c *Config) Write() (string, error) {
	p, err := ConfigPath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(p, []byte(c.Render()), 0o600); err != nil {
		return "", err
	}
	return p, nil
}

// RemoveConfig deletes the generated config. The private key is the reason this
// matters: it should not outlive the tunnel.
func RemoveConfig() error {
	p, err := ConfigPath()
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Tooling reports what is present for actually bringing the tunnel up.
// uvpn generates the config but does not raise an interface itself: that needs
// root, and a VPN client quietly taking root is not something to do by default.
func Tooling() (hasQuick, hasWG bool) {
	if _, err := exec.LookPath("wg-quick"); err == nil {
		hasQuick = true
	}
	if _, err := exec.LookPath("wg"); err == nil {
		hasWG = true
	}
	return
}
