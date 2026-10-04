package tunnel

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"uvpn/internal/client"
)

func CmdTunnel(args []string) error {
	if len(args) == 0 {
		fmt.Print(Usage)
		return nil
	}
	switch args[0] {
	case "up":
		return CmdTunnelUp(args[1:])
	case "down":
		return CmdTunnelDown(args[1:])
	case "status":
		return CmdTunnelStatus(args[1:])
	case "-h", "--help", "help":
		fmt.Print(Usage)
		return nil
	default:
		return fmt.Errorf("unknown subcommand %q\n\n%s", args[0], Usage)
	}
}

const Usage = `Full-tunnel: route all traffic through the proxy, including apps
that ignore http_proxy (Chromium, Electron, Steam, Java, games)

  uvpn tunnel up <CODE>    Start the tunnel (needs root)
  uvpn tunnel down         Stop it and remove all firewall rules
  uvpn tunnel status       Show whether it is running and where traffic exits

This redirects TCP via nftables to a local relay that forwards through the
proxy with CONNECT, and answers DNS locally. UDP is dropped rather than leaked.
`

// CmdTunnelUp is the foreground tunnel process. It stays in the foreground
// because its lifetime is the tunnel's: interrupting it tears the rules back
// down, so there is never a moment where the rules exist and nothing is
// listening for them.
func CmdTunnelUp(args []string) error {
	fs := flag.NewFlagSet("tunnel up", flag.ExitOnError)
	fs.Parse(args)
	if fs.NArg() == 0 {
		return errors.New("tunnel up requires a country code, e.g. `sudo uvpn tunnel up DE`")
	}
	code := fs.Arg(0)

	if err := requireRoot("tunnel up"); err != nil {
		return err
	}
	if nftActive() {
		return errors.New("a tunnel is already running; run `uvpn tunnel down` first")
	}
	if isPortOpen(tunnelPort) {
		return fmt.Errorf("port %d is in use by another process", tunnelPort)
	}

	c, err := client.LoadConfig()
	if err != nil {
		return err
	}
	if !c.CredentialValid(time.Now(), client.RefreshMargin) {
		return fmt.Errorf("no valid proxy credential; connect first: sudo uvpn connect %s", code)
	}
	if c.Location != strings.ToUpper(code) {
		return fmt.Errorf("stored credential is for %s, not %s; run `uvpn connect %s` first",
			c.Location, strings.ToUpper(code), code)
	}

	dialer := &proxyDialer{
		addr:    c.Proxy,
		user:    c.Username,
		pass:    c.Password,
		timeout: 30 * time.Second,
	}

	// DNS first: if it cannot bind, we abort before touching any firewall
	// state, so a failure leaves the machine exactly as it was.
	dns, err := startDNS(dialer.connect)
	if err != nil {
		return fmt.Errorf("start DNS forwarder: %w", err)
	}
	defer dns.close()

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", tunnelPort))
	if err != nil {
		return fmt.Errorf("listen on relay port: %w", err)
	}
	r := &Relay{proxy: dialer, ln: ln, logf: func(m string) { fmt.Fprintln(os.Stderr, "relay:", m) }}
	go r.serve()
	defer r.close()

	if uplinkIface() == "" {
		return errors.New("could not determine the default-route interface; refusing to install rules " +
			"that would match nothing while you believe you are tunnelled")
	}

	// Rules last, once both listeners are up.
	if err := nftApply(); err != nil {
		return err
	}
	defer nftRemove()

	iface := uplinkIface()
	fmt.Printf("tunnel up: %s via %s\n", c.Location, c.Proxy)
	fmt.Printf("  TCP relay  127.0.0.1:%d (redirect on %s)\n", tunnelPort, iface)
	fmt.Printf("  DNS        127.0.0.1:%d via TCP through the proxy\n", dnsPort)
	fmt.Printf("  resolvers  %s\n", strings.Join(dnsTargets, ", "))
	fmt.Printf("  traffic:   all TCP through the proxy; UDP dropped\n")
	if len(dnsTargets) == 0 {
		fmt.Println("  note: no non-loopback IPv4 resolver in /etc/resolv.conf; DNS is not being intercepted")
	}
	fmt.Println("\nCtrl-C to bring it down.")

	// Confirm the tunnel actually changed the egress. A silent failure here
	// (rules installed, traffic still leaving directly) is the worst outcome
	// this command can produce, so it is checked rather than printed and ignored.
	direct, _ := client.EgressIPDirect()
	via, verr := client.EgressIP()
	switch {
	case verr != nil:
		fmt.Printf("  warning: could not verify egress (%v);\n", verr)
		fmt.Println("           the rules are installed but a working egress is unconfirmed")
	case direct == "":
		fmt.Printf("  egress IP: %s (direct baseline unknown)\n", via)
	case direct == via:
		fmt.Printf("  warning: egress is %s, unchanged; traffic may not be tunnelled\n", via)
	default:
		fmt.Printf("  egress IP: %s (was %s)\n", via, direct)
	}

	// Wait for a signal, then unwind through the defers.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	fmt.Println("\nbringing tunnel down...")
	return nil
}

// CmdTunnelDown removes the ruleset. Safe to run when nothing is up; the common
// case is cleaning up after a crash.
func CmdTunnelDown(args []string) error {
	fs := flag.NewFlagSet("tunnel down", flag.ExitOnError)
	fs.Parse(args)
	if !nftActive() {
		fmt.Println("no tunnel rules present; nothing to do")
		return nil
	}
	if err := nftRemove(); err != nil {
		return err
	}
	fmt.Println("tunnel down; nftables rules removed")
	return nil
}

func validWord(v bool) string {
	if v {
		return "valid"
	}
	return "expired, reconnect"
}

// CmdTunnelStatus reports what is in effect, so it is obvious whether the
// machine is currently tunnelled.
func CmdTunnelStatus(args []string) error {
	fs := flag.NewFlagSet("tunnel status", flag.ExitOnError)
	fs.Parse(args)

	active := nftActive()
	if active {
		fmt.Println("tunnel: active (all TCP redirected to the local relay)")
	} else {
		fmt.Println("tunnel: inactive")
	}
	c, err := client.LoadConfig()
	if err != nil {
		return err
	}
	if c.Proxy != "" {
		fmt.Printf("stored proxy: %s://%s (credential %s)\n", c.Scheme, c.Proxy,
			validWord(c.CredentialValid(time.Now(), client.RefreshMargin)))
	}
	if ip, err := client.EgressIP(); err == nil {
		fmt.Printf("egress IP: %s\n", ip)
	}
	return nil
}
