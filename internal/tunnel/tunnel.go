package tunnel

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// nftTable is the table we own. Everything lives under one name so `nft
// delete table` is a complete, atomic teardown; there is no way to leave
// half the rules behind and black-hole the machine.
const nftTable = "uvpn"

const (
	tunnelPort = 18081 // local TCP relay, loopback only
	dnsPort    = 15353 // local UDP DNS forwarder, loopback only
)

// uplinkIface is the interface carrying the default route. nftRules takes it as
// an argument rather than hardcoding a name, because a wireless interface can be
// renamed or re-enumerated and a ruleset that names it would then silently match
// nothing, leaving the user believing they are tunnelled while they are not.
func uplinkIface() string {
	// Deliberately not runCapture: `ip route show` needs no privilege, and
	// routing it through sudo would make an unprivileged call block on a
	// password prompt it has no business asking for.
	out, err := exec.Command("ip", "-o", "route", "show", "default").Output()
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

// bypassDest marks destinations exempt from the tunnel. Anything listed here
// still leaves directly, on purpose: a proxy cannot carry WireGuard, and
// routing the tunnel's own transport through the tunnel is a chicken-and-egg
// the CONNECT relay has no way out of.
var bypassDest = []string{
	"100.64.0.0/10",  // Tailscale / CGNAT range
	"192.168.0.0/16", // home LAN
	"172.16.0.0/12",  // Docker bridges
	"127.0.0.0/8",    // loopback
	"224.0.0.0/4",    // multicast
}

// dnsTargets are the resolvers whose traffic is pulled onto the local forwarder.
// The list is read from /etc/resolv.conf at startup rather than hardcoded, so it
// follows whichever resolver the host is actually configured to use. It also
// includes Tailscale's MagicDNS at 100.100.100.100, which is outside
// 127.0.0.0/8 and would otherwise keep resolving names locally and leak every
// lookup to the ISP.
var dnsTargets []string

// dnsRules emits the DNS interception, one rule per protocol. An empty list
// means every resolver is a loopback stub or IPv6, which resolvConfTargets
// skips on purpose: a reply from 127.0.0.1:15353 arrives from the wrong
// address and gets dropped. Loopback DNS hits the stub via the bypass list
// anyway, and the tunnel status says so.
//
// Two syntax rules matter; both come from nft rejecting this file:
//
//   - A parenthesised or-list of ip matches is not valid. Multiple resolvers
//     are written as a set literal: ip daddr { 1.1.1.1, 100.100.100.100 }.
//   - Once ip daddr is matched the payload context is already known, so a
//     trailing `udp` is a syntax error; the protocol is selected with
//     meta l4proto and the port with dport.
//
// A rule nft cannot parse does not warn; it fails the whole `nft -f` load and
// the tunnel stays down. `ip daddr { any }` used to do exactly that, with nft
// trying to resolve "any" as a hostname.
func dnsRules(b *strings.Builder, w func(string, ...any)) {
	if len(dnsTargets) == 0 {
		return
	}
	quoted := make([]string, 0, len(dnsTargets))
	for _, t := range dnsTargets {
		quoted = append(quoted, t)
	}
	dsts := "{ " + strings.Join(quoted, ", ") + " }"
	w("    ip daddr %s udp dport 53 redirect to :%d\n", dsts, dnsPort)
	w("    ip daddr %s tcp dport 53 redirect to :%d\n", dsts, dnsPort)
}

// resolvConfTargets returns the resolver addresses from /etc/resolv.conf,
// skipping link-local IPv6, which is only meaningful while the tunnel that
// provides it is up.
func resolvConfTargets() []string {
	b, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "nameserver" {
			continue
		}
		ip := net.ParseIP(f[1])
		if ip == nil {
			continue
		}
		if ip.IsLoopback() {
			continue // a local stub; not something to intercept
		}
		if ip.To4() == nil {
			continue // IPv6 resolvers need a v6 table we do not install
		}
		out = append(out, f[1])
	}
	return out
}

// exemptOutbound is the narrower, rule-level exemption list used by the UDP
// kill switch. Dropping every UDP would take out the lease itself: DHCP is UDP
// 67/68 and NetworkManager is running, so losing it costs the interface its
// address and takes the whole machine offline. Tailscale carries WireGuard over
// UDP too, and it must keep working while the tunnel is up.
//
// These are matched on interface as well as port where the rule supports it, so
// a DHCP server on the LAN cannot use them to open a general UDP path.
var exemptOutbound = []string{
	`iifname "lo"`,
	`oifname "lo"`,
	`meta mark 0x4000`, // NetworkManager marks its own DHCP packets
	`ip daddr 255.255.255.255 udp dport 67`,
	`meta l4proto udp ip daddr 100.64.0.0/10`,
	`ip daddr 192.168.0.0/16 udp dport 67`,
	`meta l4proto udp ip daddr 224.0.0.0/4`,
}

// nftRules builds the ruleset for the given uplink interface.
//
// The rule is simple: the tunnel is the *default route*, and anything exempt
// from it is exempt by address, not by exceptions scattered through the list.
// That is what stops the relay carrying its own connection to the proxy.
//
//	nat/prerouting + nat/output   TCP -> redirect to the local relay
//	filter/output + filter/forward UDP that is not exempt -> drop
//
// Two rules matter most:
//
//   - The relay's outbound sockets carry SO_MARK. The nat chains return early
//     for marked packets, so the relay's connection to the proxy is never
//     redirected back into the relay, which would loop forever.
//   - UDP is dropped rather than leaked. A QUIC client that cannot use UDP will
//     retry over TCP and get tunnelled; a QUIC client that is merely ignored
//     reconnects directly, which leaks.
//
// REDIRECT is a terminating NAT verdict, so redirected packets come back with
// their MSS option untouched. The postrouting clamp re-injects them; without it
// the client and the origin disagree on segment size and big transfers stall.
func nftRules(iface string) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }

	w("table ip %s {\n", nftTable)

	// --- prerouting: forwarded traffic ---
	b.WriteString("  chain prerouting {\n")
	b.WriteString("    type nat hook prerouting priority dstnat; policy accept;\n")
	w("    meta mark %d return\n", bypassMark)
	dnsRules(&b, w)
	for _, c := range bypassDest {
		w("    ip daddr %s return\n", c)
	}
	w("    meta l4proto tcp redirect to :%d\n", tunnelPort)
	b.WriteString("  }\n")

	// --- output: locally generated traffic ---
	b.WriteString("  chain output {\n")
	b.WriteString("    type nat hook output priority -100; policy accept;\n")
	w("    meta mark %d return\n", bypassMark)
	dnsRules(&b, w)
	for _, c := range bypassDest {
		w("    ip daddr %s return\n", c)
	}
	w("    meta l4proto tcp redirect to :%d\n", tunnelPort)
	b.WriteString("  }\n")

	// --- the UDP kill switch, for local traffic ---
	// A nat chain may only terminate with a NAT verdict, so the drop that keeps
	// UDP inside the tunnel has to live in a filter chain.
	b.WriteString("  chain outblock {\n")
	b.WriteString("    type filter hook output priority 0; policy accept;\n")
	for _, c := range exemptOutbound {
		w("    %s accept\n", c)
	}
	b.WriteString("    meta l4proto udp drop\n")
	b.WriteString("  }\n")

	// --- the same, for anything arriving from the LAN or a container ---
	b.WriteString("  chain fwblock {\n")
	b.WriteString("    type filter hook forward priority 0; policy accept;\n")
	w("    meta mark %d accept\n", bypassMark)
	for _, c := range exemptOutbound {
		w("    %s accept\n", c)
	}
	b.WriteString("    meta l4proto udp drop\n")
	b.WriteString("  }\n")

	// --- MSS repair for redirected packets ---
	b.WriteString("  chain postrouting {\n")
	b.WriteString("    type filter hook postrouting priority filter; policy accept;\n")
	b.WriteString("    oifname \"lo\" accept\n")
	if iface != "" {
		w("    oifname \"%s\" meta l4proto tcp tcp flags syn tcp option maxseg size set rt mtu\n", iface)
	} else {
		b.WriteString("    meta l4proto tcp tcp flags syn tcp option maxseg size set rt mtu\n")
	}
	b.WriteString("  }\n")
	b.WriteString("}\n")
	return b.String()
}

// nftApply installs the ruleset.
func nftApply() error {
	dnsTargets = resolvConfTargets()
	out, err := runCaptureStdin(nftRules(uplinkIface()), "nft", "-f", "-")
	if err != nil {
		return fmt.Errorf("install nftables rules: %v\n%s", err, out)
	}
	return nil
}

// nftRemove tears the tunnel down. Deleting the table removes every rule at
// once, which is why it is one operation and not a sequence.
func nftRemove() error {
	// Missing table is the desired end state, not a failure.
	_ = runPrivileged("nft", "delete", "table", "ip", nftTable)
	return nil
}

// nftActive reports whether our ruleset is currently installed.
func nftActive() bool {
	out, err := runCapture("nft", "list", "table", "ip", nftTable)
	return err == nil && strings.Contains(out, nftTable)
}

// runPrivileged executes a command, using sudo only if we are not already root.
// The password prompt is left to the terminal: a VPN should not be caching sudo
// credentials on your behalf without you asking.
func runPrivileged(name string, args ...string) error {
	out, err := runCapture(name, args...)
	if err != nil {
		return fmt.Errorf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return nil
}

func runCapture(name string, args ...string) (string, error) {
	if os.Geteuid() == 0 {
		out, err := exec.Command(name, args...).CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	full := append([]string{name}, args...)
	out, err := exec.Command("sudo", full...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// runCaptureStdin is the stdin variant, for feeding nft a ruleset.
func runCaptureStdin(stdin string, name string, args ...string) (string, error) {
	cmd := func() *exec.Cmd {
		if os.Geteuid() == 0 {
			return exec.Command(name, args...)
		}
		return exec.Command("sudo", append([]string{name}, args...)...)
	}()
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// isPortOpen reports whether something is already listening on a loopback port,
// so we fail with a clear message instead of an opaque "address in use".
func isPortOpen(port int) bool {
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		return true
	}
	_ = ln.Close()
	return false
}

func requireRoot(what string) error {
	if os.Geteuid() == 0 {
		return nil
	}
	// The hint names the subcommand, not the whole invocation: `what` is
	// already "tunnel up", so appending it again produced "tunnel tunnel up".
	return fmt.Errorf("%s needs root; re-run with sudo:\n  sudo uvpn %s", what, what)
}
