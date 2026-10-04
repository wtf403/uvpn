package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Endpoints. Only these are ever contacted. The extension's analytics,
// Bugsnag, ecommerce, ad-blocker, and affiliate hosts are not in the list on
// purpose; this client has no telemetry path.
const (
	// AuthBaseDefault is the auth host: it issues the anonymous security token
	// and the per-server proxy token.
	AuthBaseDefault = "https://api-pro.urban-vpn.com/rest/v1"
	// StatsBaseDefault serves the location/server list. Note the /api/rest/v2
	// prefix; it is not the /rest/v1 used by AuthBase.
	StatsBaseDefault = "https://stats.urban-vpn.com/api/rest/v2"

	clientApp = "URBAN_VPN_BROWSER_EXTENSION"
)

// These are vars rather than consts only so tests can point them at a local
// stub; production always uses the defaults. AuthBase/StatsBase are exported
// so tests in other packages can repoint them.
var (
	AuthBase  = AuthBaseDefault
	StatsBase = StatsBaseDefault
)

// clockSkew is the measured difference between the local clock and the server's
// Date header. Urban VPN mints token expiry against server time, so a skewed
// local clock makes a valid token look expired. We correct for it, mirroring
// the extension's shiftTime/DATE_SHIFT_MS handling.
var (
	clockMu   sync.Mutex
	clockSkew time.Duration
)

// observeClock records the server/local time difference from a Date header.
func observeClock(h http.Header) {
	d := h.Get("Date")
	if d == "" {
		return
	}
	t, err := http.ParseTime(d)
	if err != nil {
		return
	}
	// Date has 1s resolution; ignore sub-second noise.
	skew := t.Sub(time.Now().UTC()).Truncate(time.Second)
	clockMu.Lock()
	clockSkew = skew
	clockMu.Unlock()
}

func skew() time.Duration {
	clockMu.Lock()
	defer clockMu.Unlock()
	return clockSkew
}

var httpClient = &http.Client{Timeout: 25 * time.Second}

// DoJSON performs a request and decodes JSON into out. On a non-2xx it returns
// the raw body (truncated) so the caller can see the API's own error text.
func DoJSON(method, endpoint string, body any, headers map[string]string, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, endpoint, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("app", clientApp)
	req.Header.Set("X-Client-App", clientApp)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	observeClock(resp.Header)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		return fmt.Errorf("http %d from %s: %s", resp.StatusCode, endpoint, strings.TrimSpace(string(raw)))
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("decode %s: %w", endpoint, err)
		}
	}
	return nil
}

// ProxyTransport dials through the given proxy, used to verify egress.
// Credentials are embedded in the proxy URL so Go sends Proxy-Authorization.
func ProxyTransport(scheme, hostport, user, pass string) (*http.Transport, error) {
	if scheme == "" {
		scheme = "http"
	}
	pu := &url.URL{Scheme: scheme, Host: hostport}
	if user != "" {
		pu.User = url.UserPassword(user, pass)
	}
	return &http.Transport{Proxy: http.ProxyURL(pu)}, nil
}

// EgressIP reports the IP the world sees for this request.
func EgressIP() (string, error) {
	resp, err := httpClient.Get("https://api.ipify.org")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 128))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// EgressIPVia reports the egress IP as seen through a proxy.
func EgressIPVia(tr *http.Transport) (string, error) {
	c := &http.Client{Transport: tr, Timeout: 25 * time.Second}
	resp, err := c.Get("https://api.ipify.org")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 128))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// EgressIPDirect reports the egress IP with proxy env vars ignored. The tunnel
// has to be judged against the real direct route, not whatever http_proxy the
// calling shell happens to have exported.
func EgressIPDirect() (string, error) {
	cl := &http.Client{
		Timeout: 25 * time.Second,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: (&net.Dialer{
				Timeout: 10 * time.Second,
			}).DialContext,
		},
	}
	resp, err := cl.Get("https://api.ipify.org")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 128))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
