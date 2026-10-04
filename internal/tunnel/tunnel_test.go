package tunnel

import (
	"net"
	"strconv"
	"strings"
	"testing"
)

// The redirect rules are the entire point of the tunnel. A ruleset that
// installs cleanly but redirects nothing leaves the user believing they are
// tunnelled while every byte goes direct, so their presence is asserted
// explicitly rather than trusted.
// TestRulesRedirectTCP guards the single most consequential line in the
// ruleset. The first version of this rule read
//
//	meta l4proto tcp tcp dport 18081 redirect to :18081
//
// which looks right at a glance but is not: the middle `tcp dport 18081` is a
// *match*, so the rule only fires for connections already bound for port 18081.
// All other traffic, port 443 included, fell straight through, the
// relay accepted nothing, and the tunnel reported itself up while every byte
// went out direct. The bug shipped partly because a test asserted the exact
// wrong string, so this asserts the *absence* of a port match instead of the
// presence of a literal.
func TestRulesRedirectTCP(t *testing.T) {
	r := nftRules("wan0")
	want := "meta l4proto tcp redirect to :" + strconv.Itoa(tunnelPort)
	if !strings.Contains(r, want) {
		t.Fatalf("ruleset has no catch-all TCP redirect to the relay; want %q in:\n%s", want, r)
	}
	// A dport match on the catch-all rule silently re-broadens it into a no-op
	// for every port but one, so reject any redirect that is gated on dport.
	for _, line := range strings.Split(r, "\n") {
		if strings.Contains(line, "redirect to :"+strconv.Itoa(tunnelPort)) && strings.Contains(line, "dport") {
			t.Errorf("catch-all TCP redirect is gated on a port, so it only matches that port:\n%s", line)
		}
	}
}

func TestRulesRedirectDNS(t *testing.T) {
	dnsTargets = []string{"100.100.100.100"}
	r := nftRules("wan0")
	for _, want := range []string{
		"ip daddr { 100.100.100.100 } udp dport 53 redirect to :" + strconv.Itoa(dnsPort),
		"ip daddr { 100.100.100.100 } tcp dport 53 redirect to :" + strconv.Itoa(dnsPort),
	} {
		if !strings.Contains(r, want) {
			t.Errorf("missing DNS rule %q in:\n%s", want, r)
		}
	}
}

// Tailscale MagicDNS lives inside 100.64.0.0/10. If the bypass list is consulted
// first, its return wins and every lookup leaks to the local network.
func TestRulesDNSBeforeBypass(t *testing.T) {
	dnsTargets = []string{"100.100.100.100"}
	r := nftRules("wan0")
	body := r[strings.Index(r, "chain output"):]
	dns := strings.Index(body, "100.100.100.100")
	bypass := strings.Index(body, "ip daddr 100.64.0.0/10 return")
	if dns < 0 || bypass < 0 {
		t.Fatalf("expected both rules; dns=%d bypass=%d in:\n%s", dns, bypass, body)
	}
	if dns > bypass {
		t.Errorf("DNS redirect appears after the 100.64.0.0/10 bypass; MagicDNS would leak")
	}
}

// QUIC is UDP. Without an explicit drop, a browser negotiates HTTP/3 straight
// past a TCP-only tunnel.
func TestRulesDropUDP(t *testing.T) {
	r := nftRules("wan0")
	if !strings.Contains(r, "meta l4proto udp drop") {
		t.Errorf("no UDP drop; QUIC would bypass the tunnel:\n%s", r)
	}
}

// Dropping UDP unconditionally would cost the interface its DHCP lease and take
// the machine offline.
func TestRulesExemptDHCP(t *testing.T) {
	r := nftRules("wan0")
	for _, want := range []string{"udp dport 67", "255.255.255.255"} {
		if !strings.Contains(r, want) {
			t.Errorf("no DHCP exemption (%q); the lease would be lost:\n%s", want, r)
		}
	}
}

// The relay's own proxy connection must not be redirected back into the relay.
func TestRulesMarkBypassPrecedesRedirect(t *testing.T) {
	r := nftRules("wan0")
	body := r[strings.Index(r, "chain output"):strings.Index(r, "chain outblock")]
	mark := strings.Index(body, "meta mark 1 return")
	redir := strings.Index(body, "redirect to :")
	if mark < 0 || redir < 0 || mark > redir {
		t.Errorf("SO_MARK bypass must precede the redirect (mark=%d redirect=%d)", mark, redir)
	}
}

func TestResolvConfSkipsLoopbackAndV6(t *testing.T) {
	got := resolvConfTargets()
	for _, g := range got {
		ip := net.ParseIP(g)
		if ip == nil {
			t.Fatalf("unparseable resolver %q", g)
		}
		if ip.IsLoopback() {
			t.Errorf("loopback resolver %q should be skipped", g)
		}
		if ip.To4() == nil {
			t.Errorf("IPv6 resolver %q has no v4 table to land in", g)
		}
	}
}
