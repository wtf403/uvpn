package wg

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"uvpn/internal/client"
)

func CmdWireGuard(args []string) error {
	if len(args) == 0 {
		fmt.Print(usage)
		return nil
	}
	switch args[0] {
	case "proto":
		return cmdProto(args[1:])
	case "config":
		return cmdConfig(args[1:])
	case "up":
		return cmdUp(args[1:])
	case "down":
		return cmdDown(args[1:])
	case "-h", "--help", "help":
		fmt.Print(usage)
		return nil
	default:
		return fmt.Errorf("unknown subcommand %q\n\n%s", args[0], usage)
	}
}

const usage = `WireGuard tunnel: covers apps that ignore proxy settings

  uvpn wg proto <CODE>    Report which tunnel backend a country uses
  uvpn wg config <CODE>   Register a WireGuard peer and write the wg-quick config
  uvpn wg up [CODE]       Bring the tunnel up (needs root; falls back to config)
  uvpn wg down            Tear the tunnel down

Examples:
  uvpn wg config DE       # writes ~/.config/uvpn/wg0.conf
  sudo uvpn wg up DE      # brings the interface up and registers if needed
  sudo uvpn wg down
`

// cmdProto answers the question the Android app asks itself: is this country
// served over WireGuard? Useful on its own, and it is the one call here that
// works even while the peer backend is down.
func cmdProto(args []string) error {
	fs := flag.NewFlagSet("wg proto", flag.ExitOnError)
	fs.Parse(args)
	if fs.NArg() == 0 {
		return errors.New("wg proto requires a country code, e.g. `uvpn wg proto DE`")
	}
	code := fs.Arg(0)
	proto, err := Protocol(code)
	if err != nil {
		return err
	}
	if proto == "" {
		fmt.Printf("%s: no tunnel protocol advertised\n", code)
		return nil
	}
	fmt.Printf("%s: %s\n", code, proto)
	if proto != "wg" {
		fmt.Println("note: this region is not served over WireGuard")
	}
	return nil
}

// cmdConfig registers a peer and writes the config. This is the part that
// needs no privileges, so it is the default entry point.
func cmdConfig(args []string) error {
	fs := flag.NewFlagSet("wg config", flag.ExitOnError)
	force := fs.Bool("force", false, "generate a fresh keypair instead of reusing the stored one")
	fs.Parse(args)
	if fs.NArg() == 0 {
		return errors.New("wg config requires a country code, e.g. `uvpn wg config DE`")
	}
	code := fs.Arg(0)

	cfg, err := BuildConfig(code, *force)
	if err != nil {
		return describeFailure(err, code)
	}
	path, err := cfg.Write()
	if err != nil {
		return err
	}
	c, err := client.LoadConfig()
	if err != nil {
		return err
	}
	c.WGCountry = cfg.Country
	c.WGEndpoint = cfg.Endpoint
	c.WGPublicKey = cfg.PublicKey
	c.WGPrivateKey = cfg.PrivateKey
	if err := client.SaveConfig(c); err != nil {
		return err
	}

	fmt.Printf("wireguard config for %s written to %s\n", cfg.Country, path)
	fmt.Printf("  endpoint:   %s\n", cfg.Endpoint)
	fmt.Printf("  allowedIPs: %s\n", cfg.AllowedIPs)
	fmt.Printf("  local key:  %s...\n", truncateKey(cfg.PublicKey))
	if cfg.Preshared != "" {
		fmt.Printf("  preshared:  set\n")
	}
	printUpHint()
	return nil
}

// cmdUp brings the tunnel up. It registers a peer first if none is stored, so
// `sudo uvpn wg up DE` works as a single step.
func cmdUp(args []string) error {
	fs := flag.NewFlagSet("wg up", flag.ExitOnError)
	fs.Parse(args)

	quick, wg := Tooling()
	if !quick {
		if !wg {
			return errors.New("wireguard-tools is not installed; install it with:\n" +
				"  sudo pacman -S wireguard-tools     # Arch\n" +
				"  sudo apt install wireguard-tools   # Debian/Ubuntu")
		}
		return errors.New("wg-quick not found, only wg; use `uvpn wg config` and set the tunnel up manually")
	}

	code := fs.Arg(0)
	path, err := ConfigPath()
	if err != nil {
		return err
	}
	if code != "" || fileMissing(path) {
		if code == "" {
			return fmt.Errorf("no stored config at %s; pass a country code, e.g. `uvpn wg up DE`", path)
		}
		// Root is expected here anyway, so failing on a permissions error
		// while writing the config is unhelpful.
		if _, err := BuildConfig(code, false); err != nil {
			return describeFailure(err, code)
		}
		path, err = ConfigPath()
		if err != nil {
			return err
		}
	}

	// wg-quick wants the config named after the interface it will create.
	link, err := QuickStaging(path)
	if err != nil {
		return err
	}
	out, err := runTool("wg-quick", "up", link)
	if err != nil {
		return fmt.Errorf("wg-quick up: %w\n%s", err, out)
	}
	// Leave the interface up and drop our copy of the private key.
	_ = os.Remove(link)

	fmt.Println("tunnel is up; all traffic goes through it, including apps that ignore proxy settings")
	if ip, err := client.EgressIP(); err == nil {
		fmt.Printf("egress IP: %s\n", ip)
	}
	return nil
}

// cmdDown tears the tunnel down and removes the stored credentials.
func cmdDown(args []string) error {
	fs := flag.NewFlagSet("wg down", flag.ExitOnError)
	fs.Parse(args)
	_ = fs.Parse(args)

	if quick, _ := Tooling(); quick {
		if link, err := QuickStaging(""); err == nil && link != "" {
			if out, err := runTool("wg-quick", "down", link); err != nil {
				fmt.Fprintf(os.Stderr, "warning: wg-quick down: %v\n%s\n", err, out)
			}
		}
	}
	if err := RemoveConfig(); err != nil {
		return err
	}
	c, err := client.LoadConfig()
	if err != nil {
		return err
	}
	c.WGCountry, c.WGEndpoint, c.WGPublicKey, c.WGPrivateKey = "", "", "", ""
	if err := client.SaveConfig(c); err != nil {
		return err
	}
	fmt.Println("tunnel down; config and private key removed")
	return nil
}

// BuildConfig registers a peer for a country, reusing the stored keypair so a
// reconnect does not need a new registration.
func BuildConfig(country string, force bool) (*Config, error) {
	proto, err := Protocol(country)
	if err != nil {
		return nil, fmt.Errorf("check tunnel protocol: %w", err)
	}
	if proto != "" && proto != "wg" {
		return nil, fmt.Errorf("%s is served over %q, not WireGuard", country, proto)
	}

	sess, err := client.Bootstrap()
	if err != nil {
		return nil, err
	}
	c, err := client.LoadConfig()
	if err != nil {
		return nil, err
	}

	kp, err := existingOrNewKeypair(c, force)
	if err != nil {
		return nil, err
	}

	cfg, err := RegisterPeer(sess.Security.Value, country, kp.Public)
	if err != nil && strings.Contains(err.Error(), "401") {
		sess, bErr := client.BootstrapForce()
		if bErr == nil {
			cfg, err = RegisterPeer(sess.Security.Value, country, kp.Public)
		}
	}
	if err != nil {
		return nil, err
	}
	cfg.PrivateKey = kp.Private
	// The reply names the country it actually issued, which may differ if the
	// request was for a region with no servers of its own.
	if cfg.Country == "" {
		cfg.Country = country
	}
	return cfg, nil
}

// describeFailure turns the backend's outage into something actionable, and
// is explicit that it is a server-side condition rather than a bad request.
func describeFailure(err error, country string) error {
	if Unavailable(err) {
		return fmt.Errorf("%w\n\nUrban VPN's WireGuard backend is down on their side. "+
			"This is a service outage, not a problem with the request; the HTTP proxy "+
			"is unaffected, so `uvpn connect %s` still works.", err, country)
	}
	return err
}

// existingOrNewKeypair reuses the stored keypair unless asked for a fresh one,
// because the server keys the peer off the public key we registered.
func existingOrNewKeypair(c *client.Config, force bool) (*KeyPair, error) {
	if !force && c.WGPrivateKey != "" {
		priv, err := ParseKey(c.WGPrivateKey)
		if err == nil {
			return KeyPairFromPrivate(priv), nil
		}
	}
	return NewKeyPair()
}

func printUpHint() {
	quick, wg := Tooling()
	switch {
	case quick:
		fmt.Println("\nTo bring it up (needs root):")
		fmt.Println("  sudo uvpn wg up")
	case wg:
		fmt.Println("\nwg-quick is not installed; install wireguard-tools, or apply the config with wg manually.")
	default:
		fmt.Println("\nwireguard-tools is not installed. Install it, then run:")
		fmt.Println("  sudo uvpn wg up")
	}
}

func truncateKey(k string) string {
	if len(k) <= 12 {
		return k
	}
	return k[:12]
}

func fileMissing(p string) bool {
	_, err := os.Stat(p)
	return err != nil
}

// QuickStaging copies the config to /etc/wireguard/<name>.conf, which is
// where wg-quick looks, and returns that path. wg-quick derives the interface
// name from the file name, so the name is the interface.
func QuickStaging(src string) (string, error) {
	if src == "" {
		p, err := ConfigPath()
		if err != nil {
			return "", err
		}
		src = p
	}
	body, err := os.ReadFile(src)
	if err != nil {
		return "", err
	}
	const dir = "/etc/wireguard"
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create %s: %w", dir, err)
	}
	dst := filepath.Join(dir, "uvpn0.conf")
	if err := os.WriteFile(dst, body, 0o600); err != nil {
		return "", fmt.Errorf("write %s: %w", dst, err)
	}
	return dst, nil
}

// runTool executes a helper binary and returns its combined output, so a
// wg-quick failure comes back with the reason attached rather than just an
// exit status.
func runTool(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
