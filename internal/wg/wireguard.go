package wg

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"uvpn/internal/client"
)

// The Android client (com.urbanvpn.android) does not tunnel with the HTTP proxy
// the browser extension uses. It registers a WireGuard peer and brings up a real
// tunnel, which is why the app does not need proxy support from each app it
// proxies. The engine is stock golang.zx2c4.com/wireguard, so the server side is
// an ordinary WireGuard peer and a wg-quick config is all this client needs.
//
// Endpoints, both on the api-pro host that already issues the security token:
//
//	POST /rest/v1/api/wg/peers/register    claim a peer for our public key
//	POST /rest/v1/api/wg/peers/disconnect  release it
//
// A feature-flag call first confirms the region is served over WireGuard:
//
//	GET  config-toolbar.urban-vpn.com/rest/v1/configs/vpn?app=...&country=XX
//
// The registration backend is a separate service and is not always up. It
// answers 503 "WireGuard Unavailable" independently of the request, so that is
// reported as a plain service outage rather than a bad request.

const wgClientApp = "URBAN_VPN_UNBLOCKER_ANDROID_APPLICATION"

const (
	ConfigBaseDefault = "https://config-toolbar.urban-vpn.com/rest/v1"
	wgRegister        = "/api/wg/peers/register"
	wgRelease         = "/api/wg/peers/disconnect"
)

// See the note on client.AuthBase: var only so tests can redirect to a stub.
var ConfigBase = ConfigBaseDefault

// wgOutageMessage is the service-side failure body, which arrives as a plain
// 503 from the WireGuard backend rather than the vendor's usual error envelope.
const wgOutageMessage = "WireGuard Unavailable"

// Unavailable reports whether an error is the backend being down, as opposed
// to our request being wrong. The retry needs that split: a 503 means wait, a
// 400 means the payload needs fixing.
func Unavailable(err error) bool {
	return err != nil && strings.Contains(err.Error(), wgOutageMessage)
}

// ProtoRequest is the JSON body of a peer register/disconnect call. Field
// names are fixed by the server's validation messages, which name them back
// when a field is missing.
type ProtoRequest struct {
	ClientPublicKey string         `json:"clientPublicKey"`
	WG              map[string]any `json:"wg"`
}

// Config is a fully resolved tunnel: our keypair plus everything the server
// hands back for the peer.
type Config struct {
	PrivateKey  string
	PublicKey   string
	PeerKey     string
	Preshared   string
	Endpoint    string
	AllowedIPs  string
	Address     string
	Country     string
	DNS         string
	MTU         int
	ExpiresAt   string
	ServerLabel string
}

// ProtoEnvelope covers the vendor's standard error body, used to detect the
// service outage without string-matching the whole response.
type ProtoEnvelope struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
	Error   string `json:"error"`
}

// Features is the feature-flag response.
type Features struct {
	Features []struct {
		Name    string `json:"name"`
		Value   string `json:"value"`
		Enabled bool   `json:"enabled"`
	} `json:"features"`
}

// Protocol reports which tunnel backend a country is served over. The app
// reads the same flag to pick its transport; "wg" means a real tunnel, anything
// else means there is nothing to register for.
func Protocol(country string) (string, error) {
	q := fmt.Sprintf("%s/configs/vpn?app=%s&country=%s",
		ConfigBase, wgClientApp, strings.ToUpper(country))
	var f Features
	if err := client.DoJSON(http.MethodGet, q, nil, nil, &f); err != nil {
		return "", err
	}
	for _, feat := range f.Features {
		if feat.Name == "auto_vpn_protocol" {
			return feat.Value, nil
		}
	}
	return "", nil
}

// firstString walks a decoded JSON value and returns the first non-empty string
// found under any of the given key names, searching nested objects and arrays.
//
// The peer response is a protobuf-backed JSON blob whose exact field names are
// not pinned down: the registration service is currently returning 503, so we
// have not been able to observe a successful reply. Rather than guess one exact
// shape and break on the first naming difference, we accept the common spellings
// WireGuard configs use. A response that carries no recognisable peer fields is
// reported as such instead of silently producing a broken tunnel.
func firstString(v any, keys ...string) string {
	switch t := v.(type) {
	case map[string]any:
		for _, k := range keys {
			if s, ok := t[k].(string); ok && s != "" {
				return s
			}
		}
		for _, sub := range t {
			if s := firstString(sub, keys...); s != "" {
				return s
			}
		}
	case []any:
		for _, sub := range t {
			if s := firstString(sub, keys...); s != "" {
				return s
			}
		}
	}
	return ""
}

// RegisterPeer claims a WireGuard peer for our public key in a country and
// returns the resolved tunnel configuration.
func RegisterPeer(securityToken, country, clientPub string) (*Config, error) {
	body := ProtoRequest{
		ClientPublicKey: clientPub,
		WG:              map[string]any{"country": strings.ToUpper(country)},
	}
	var raw json.RawMessage
	err := client.DoJSON(http.MethodPost, client.AuthBase+wgRegister, body,
		map[string]string{"Authorization": "Bearer " + securityToken}, &raw)
	if err != nil {
		return nil, err
	}
	return ParseResponse(raw, country, clientPub)
}

// ReleasePeer tells the server the peer is no longer in use. Failures are
// non-fatal: the peer expires on its own, and refusing to tear down a working
// tunnel because a bookkeeping call failed would be worse than a leaked entry.
func ReleasePeer(securityToken, clientPub string) {
	body := ProtoRequest{
		ClientPublicKey: clientPub,
		WG:              map[string]any{},
	}
	_ = client.DoJSON(http.MethodPost, client.AuthBase+wgRelease, body,
		map[string]string{"Authorization": "Bearer " + securityToken}, nil)
}

// ParseResponse turns a peer-registration reply into a Config. privateKey
// is passed in because the reply only ever carries the server's view of the
// peer; the private half never leaves this machine.
func ParseResponse(raw json.RawMessage, country, clientPub string) (*Config, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("wireguard: empty response from peer registration")
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("wireguard: decode peer response: %w", err)
	}

	// A 200 can still carry an error envelope, so check the shape before
	// trusting it.
	var env ProtoEnvelope
	if json.Unmarshal(raw, &env) == nil && env.Status >= 400 {
		if env.Message != "" {
			return nil, fmt.Errorf("wireguard: %s", env.Message)
		}
		if env.Error != "" {
			return nil, fmt.Errorf("wireguard: %s", env.Error)
		}
	}

	peerKey := firstString(v,
		"publicKey", "peerPublicKey", "serverPublicKey", "remotePublicKey")
	endpoint := firstString(v, "endpoint", "serverEndpoint", "serverAddress", "host")
	preshared := firstString(v, "presharedKey", "preSharedKey", "preshared")
	allowed := firstString(v, "allowedIPs", "allowedIps", "allowed")
	address := firstString(v, "address", "clientAddress", "internalAddress", "ipv4", "ipAddress")
	dns := firstString(v, "dns", "dnsServers", "nameservers")
	country = firstString(v, "country", "countryCode")
	if country == "" {
		country = strings.ToUpper(country)
	}

	// The endpoint may arrive split into host and port rather than as one
	// "host:port" string; fill it in before giving up on it.
	if endpoint != "" && !strings.Contains(endpoint, ":") {
		if p := firstString(v, "port", "serverPort"); p != "" {
			endpoint = endpoint + ":" + p
		}
	}

	if peerKey == "" || endpoint == "" {
		return nil, fmt.Errorf("wireguard: peer response has no usable endpoint "+
			"(publicKey=%q endpoint=%q); the service may have changed its schema",
			peerKey, endpoint)
	}

	// WireGuard's convention is to route everything, but some deployments hand
	// back a narrower set; keep whatever the server chose.
	if allowed == "" {
		allowed = "0.0.0.0/0"
	}
	if dns == "" {
		dns = "1.1.1.1"
	}

	cfg := &Config{
		PublicKey:  clientPub,
		PeerKey:    peerKey,
		Preshared:  preshared,
		Endpoint:   endpoint,
		AllowedIPs: allowed,
		Address:    address,
		Country:    country,
		DNS:        dns,
		// 1420 is WireGuard's own default and leaves room for the UDP and
		// outer-IP headers.
		MTU: 1420,
	}
	if mtu := firstString(v, "mtu"); mtu != "" {
		var n int
		if _, err := fmt.Sscanf(mtu, "%d", &n); err == nil && n > 0 {
			cfg.MTU = n
		}
	}
	return cfg, nil
}
