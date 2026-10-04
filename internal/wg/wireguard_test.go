package wg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The registration service is returning 503, so the exact success shape is not
// yet confirmed. These tests pin the parser against the field spellings
// WireGuard configs conventionally use, so a schema change shows up as a test
// failure rather than a silently broken tunnel.

func TestParseWGResponseCanonical(t *testing.T) {
	raw := json.RawMessage(`{
	  "publicKey": "PEERKEY", "endpoint": "de1.example.com:51820",
	  "presharedKey": "PSK", "allowedIPs": "0.0.0.0/0",
	  "address": "10.10.0.2/32", "dns": "1.1.1.1", "country": "DE"
	}`)
	cfg, err := ParseResponse(raw, "DE", "CLIENTKEY")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PeerKey != "PEERKEY" || cfg.Endpoint != "de1.example.com:51820" {
		t.Errorf("peer/endpoint wrong: %+v", cfg)
	}
	if cfg.Preshared != "PSK" || cfg.Address != "10.10.0.2/32" {
		t.Errorf("psk/address wrong: %+v", cfg)
	}
	if cfg.PublicKey != "CLIENTKEY" {
		t.Errorf("client key not carried through: %q", cfg.PublicKey)
	}
	if cfg.Country != "DE" {
		t.Errorf("country = %q", cfg.Country)
	}
}

// Field names differ between server builds, and the response may nest them.
func TestParseWGResponseAlternateNames(t *testing.T) {
	raw := json.RawMessage(`{
	  "wg": {
	    "peer": {
	      "serverPublicKey": "PEERKEY",
	      "serverEndpoint": "de2.example.com:51820",
	      "allowedIps": "0.0.0.0/0"
	    }
	  }
	}`)
	cfg, err := ParseResponse(raw, "DE", "CLIENTKEY")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PeerKey != "PEERKEY" || cfg.Endpoint != "de2.example.com:51820" {
		t.Errorf("nested/alternate names not resolved: %+v", cfg)
	}
}

// Endpoint may arrive split into host and port.
func TestParseWGResponseSplitEndpoint(t *testing.T) {
	raw := json.RawMessage(`{
	  "publicKey": "PEERKEY", "host": "de3.example.com", "port": "51820"
	}`)
	cfg, err := ParseResponse(raw, "DE", "CLIENTKEY")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Endpoint != "de3.example.com:51820" {
		t.Errorf("endpoint = %q, want de3.example.com:51820", cfg.Endpoint)
	}
}

// A 200 with an error envelope must not be treated as a working config.
func TestParseWGResponseErrorEnvelope(t *testing.T) {
	raw := json.RawMessage(`{"status":503,"error":"Service Unavailable","message":"WireGuard Unavailable"}`)
	_, err := ParseResponse(raw, "DE", "K")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "WireGuard Unavailable") {
		t.Errorf("error lost the message: %v", err)
	}
}

// A response with no peer fields must fail loudly, not produce a half-config.
func TestParseWGResponseMissingPeer(t *testing.T) {
	raw := json.RawMessage(`{"unexpected":"shape"}`)
	_, err := ParseResponse(raw, "DE", "K")
	if err == nil {
		t.Fatal("expected an error for a response with no peer fields")
	}
	if !strings.Contains(err.Error(), "schema") {
		t.Errorf("error should mention a schema change: %v", err)
	}
}

// The rendered config must be valid wg-quick syntax and must never omit the
// fields wg needs to bring the interface up.
func TestWGRender(t *testing.T) {
	cfg := &Config{
		PrivateKey: "PRIV", PublicKey: "PUB", PeerKey: "PEER",
		Preshared: "PSK", Endpoint: "de1.example.com:51820",
		AllowedIPs: "0.0.0.0/0", Address: "10.10.0.2/32", DNS: "1.1.1.1", MTU: 1420,
	}
	out := cfg.Render()
	for _, want := range []string{
		"[Interface]", "PrivateKey = PRIV", "Address = 10.10.0.2/32", "MTU = 1420",
		"[Peer]", "PublicKey = PEER", "PresharedKey = PSK",
		"Endpoint = de1.example.com:51820", "AllowedIPs = 0.0.0.0/0",
		"PersistentKeepalive = 25",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered config missing %q\n---\n%s", want, out)
		}
	}
}

// The private key must be written 0600 and land under the 0700 config dir.
func TestWGConfigFilePermissions(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	cfg := &Config{PrivateKey: "PRIV", PeerKey: "PEER", Endpoint: "e:1", AllowedIPs: "0.0.0.0/0", MTU: 1420}
	p, err := cfg.Write()
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("config mode = %o, want 600", perm)
	}
	if filepath.Base(p) != "wg0.conf" {
		t.Errorf("config name = %s", filepath.Base(p))
	}
	if err := RemoveConfig(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Errorf("config not removed")
	}
}

// Unavailable must distinguish a backend outage from a bad request, since
// the two call for different responses from the user.
func TestWGUnavailable(t *testing.T) {
	if !Unavailable(errString("http 503 ... WireGuard Unavailable")) {
		t.Error("503 with WireGuard Unavailable should be an outage")
	}
	if Unavailable(errString("http 400 ... invalid-request")) {
		t.Error("a 400 must not be reported as an outage")
	}
	if Unavailable(nil) {
		t.Error("nil must not be an outage")
	}
}

type errString string

func (e errString) Error() string { return string(e) }
