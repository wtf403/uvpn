package client

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

// EnvFile is written on connect so a new shell can `source` the proxy vars.
// This is the path that covers GUI apps and login sessions, which ignore the
// environment of the invoking terminal.
func EnvFile() (string, error) {
	if os.Geteuid() == 0 {
		if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
			if u, err := user.Lookup(sudoUser); err == nil && u.HomeDir != "" {
				return filepath.Join(u.HomeDir, ".config", ConfigDirName, "env.sh"), nil
			}
		}
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, ConfigDirName, "env.sh"), nil
}

// WriteEnvFile persists the proxy environment for later sourcing.
func WriteEnvFile(c *Config) error {
	p, err := EnvFile()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	proxy := ProxyURL(c.Scheme, c.Proxy, c.Username, c.Password)
	body := fmt.Sprintf(`# written by uvpn; source this to route a shell through the VPN
export http_proxy=%q
export https_proxy=%q
export HTTP_PROXY=%q
export HTTPS_PROXY=%q
export all_proxy=%q
export ALL_PROXY=%q
export no_proxy=%q
export NO_PROXY=%q
`, proxy, proxy, proxy, proxy, proxy, proxy,
		"localhost,127.0.0.1,::1", "localhost,127.0.0.1,::1")
	return os.WriteFile(p, []byte(body), 0o600)
}

// RemoveEnvFile clears the sourced proxy environment.
func RemoveEnvFile() error {
	p, err := EnvFile()
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// ApplyToCurrentProcess sets the proxy env vars for this process and any
// children. This makes `uvpn connect ... && somecommand` work in one shell.
func ApplyToCurrentProcess(c *Config) {
	proxy := ProxyURL(c.Scheme, c.Proxy, c.Username, c.Password)
	for _, k := range []string{"http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"} {
		_ = os.Setenv(k, proxy)
	}
	np := "localhost,127.0.0.1,::1"
	for _, k := range []string{"no_proxy", "NO_PROXY"} {
		_ = os.Setenv(k, np)
	}
}

// PrintConnectHint tells the user how to make the change stick for their shell
// and for GUI applications.
func PrintConnectHint(c *Config) {
	p, err := EnvFile()
	if err != nil {
		return
	}
	fmt.Printf("\nTo use this proxy in your current shell:\n")
	fmt.Printf("  source %s\n", p)
	fmt.Printf("  eval \"$(%s env)\"\n\n", os.Args[0])
	fmt.Printf("To cover GUI apps and new terminals, add this to your shell profile (~/.bashrc):\n")
	fmt.Printf("  [ -f %s ] && . %s\n", p, p)
}

// formatServer normalises a server entry into host:port and a scheme.
func formatServer(scheme, host, port string) string {
	host = strings.TrimSpace(host)
	port = strings.TrimSpace(port)
	if scheme == "" {
		scheme = "http"
	}
	if port == "" {
		return fmt.Sprintf("%s://%s", scheme, host)
	}
	return fmt.Sprintf("%s://%s:%s", scheme, host, port)
}

// ProxyURL builds the http://user:pass@host:port URL for a proxy server.
func ProxyURL(scheme, hostport, user, pass string) string {
	if scheme == "" {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s:%s@%s", scheme, user, pass, hostport)
}
