package wg

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"uvpn/internal/client"
)

// stubPeer mimics the registration service so the full success path can be
// exercised while the real backend is returning 503.
type stubPeer struct {
	gotKey     string
	gotWGCtry  string
	gotAuth    string
	gotRelease string
}

func (s *stubPeer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/rest/v1/api/wg/peers/register", func(w http.ResponseWriter, r *http.Request) {
		var body ProtoRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		s.gotKey = body.ClientPublicKey
		if c, ok := body.WG["country"].(string); ok {
			s.gotWGCtry = c
		}
		s.gotAuth = r.Header.Get("Authorization")
		if body.ClientPublicKey == "" {
			w.WriteHeader(400)
			_ = json.NewEncoder(w).Encode(ProtoEnvelope{Status: 400,
				Message: "peerRegistrationRequest.clientPublicKey must not be blank."})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"publicKey":    "PEERPUB=",
			"presharedKey": "PSK=",
			"endpoint":     "de-1.urban-vpn.com:51820",
			"allowedIPs":   "0.0.0.0/0",
			"address":      "10.14.0.2/32",
			"dns":          "1.1.1.1",
			"country":      "DE",
		})
	})
	mux.HandleFunc("/rest/v1/api/wg/peers/disconnect", func(w http.ResponseWriter, r *http.Request) {
		var body ProtoRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		s.gotRelease = body.ClientPublicKey
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})
	mux.HandleFunc("/rest/v1/configs/vpn", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(Features{Features: []struct {
			Name    string `json:"name"`
			Value   string `json:"value"`
			Enabled bool   `json:"enabled"`
		}{{Name: "auto_vpn_protocol", Value: "wg", Enabled: true}}})
	})
	return mux
}

// A full connect against the stub: register a peer, write the config, and check
// the stored state. This covers the path the live service is currently refusing.
func TestWGConfigEndToEndAgainstStub(t *testing.T) {
	stub := &stubPeer{}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	oldAuth, oldCfg := client.AuthBase, ConfigBase
	client.AuthBase, ConfigBase = srv.URL+"/rest/v1", srv.URL+"/rest/v1"
	defer func() { client.AuthBase, ConfigBase = oldAuth, oldCfg }()

	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	// Seed a session so client.Bootstrap() does not have to reach the real auth host.
	c, err := client.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	c.AuthToken = &client.Token{Value: "anonm-test"}
	c.SecurityToken = &client.Token{Value: "sec-test"}
	if err := client.SaveConfig(c); err != nil {
		t.Fatal(err)
	}

	kp, err := NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := RegisterPeer("sec-test", "DE", kp.Public)
	if err != nil {
		t.Fatal(err)
	}
	cfg.PrivateKey = kp.Private

	if stub.gotKey != kp.Public {
		t.Errorf("server got public key %q, want %q", stub.gotKey, kp.Public)
	}
	if stub.gotWGCtry != "DE" {
		t.Errorf("server got country %q, want DE", stub.gotWGCtry)
	}
	if stub.gotAuth != "Bearer sec-test" {
		t.Errorf("Authorization = %q", stub.gotAuth)
	}
	if cfg.Endpoint != "de-1.urban-vpn.com:51820" || cfg.PeerKey != "PEERPUB=" {
		t.Errorf("config not resolved from reply: %+v", cfg)
	}

	p, err := cfg.Write()
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	rendered := string(body)
	if !strings.Contains(rendered, "PrivateKey = "+kp.Private) {
		t.Error("rendered config is missing our private key")
	}
	if !strings.Contains(rendered, "Endpoint = de-1.urban-vpn.com:51820") {
		t.Error("rendered config is missing the endpoint")
	}

	// The config holds the private key, so its permissions matter.
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("config mode = %o, want 600", fi.Mode().Perm())
	}
	if got := filepath.Base(p); got != "wg0.conf" {
		t.Errorf("config written to %s", got)
	}
}

// Disconnect must reach the service and must not fail the teardown.
func TestWGReleaseAgainstStub(t *testing.T) {
	stub := &stubPeer{}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()
	old := client.AuthBase
	client.AuthBase = srv.URL + "/rest/v1"
	defer func() { client.AuthBase = old }()

	ReleasePeer("sec-test", "somekey")
	if stub.gotRelease != "somekey" {
		t.Errorf("disconnect sent key %q, want somekey", stub.gotRelease)
	}
}
