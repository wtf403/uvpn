package client

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// RefreshMargin is how long before expiry we proactively re-mint credentials.
const RefreshMargin = 5 * time.Minute

// ProxyPassword is the literal password the extension supplies alongside the
// proxy token used as the username. Confirmed from CredentialProvider.provide:
// it returns { username: token.value, password: "1" }.
const ProxyPassword = "1"

// browserName is sent in the anonymous-registration payload.
const browserName = "CHROME"

// Token is a server-issued token with a clock-corrected local expiry.
type Token struct {
	Value          string    `json:"value,omitempty"`
	ExpirationTime time.Time `json:"expires_at,omitempty"`
}

// tokenResponse covers all three token endpoints. Each stores a token object
// whose "value" and "expirationTime" the client reads; other fields vary.
type tokenResponse struct {
	Type           string   `json:"type"`
	Value          string   `json:"value"`
	CreationTime   int64    `json:"creationTime"`
	ExpirationTime int64    `json:"expirationTime"`
	Expired        bool     `json:"expired"`
	Owner          struct { // present on the anonymous/security tokens
		ID   string `json:"id"`
		Type string `json:"type"`
	} `json:"owner"`
}

func (t tokenResponse) resolve() *Token {
	tok := &Token{Value: t.Value}
	// expirationTime is epoch millis in server time; re-base onto the local clock
	// so the deadline is meaningful even if the local clock has drifted.
	if t.ExpirationTime != 0 {
		tok.ExpirationTime = time.UnixMilli(t.ExpirationTime).UTC().Add(-skew())
	}
	return tok
}

func (t *Token) Valid(now time.Time, margin time.Duration) bool {
	if t == nil || t.Value == "" {
		return false
	}
	if t.ExpirationTime.IsZero() {
		return true
	}
	return t.ExpirationTime.After(now.Add(margin))
}

// registerAnonymous performs the mandatory first call: it mints the anonymous
// auth token (type "anonm") that unlocks the security token. It is sent with
// no Authorization header and explicitly bypasses the token interceptor.
func registerAnonymous() (*Token, error) {
	endpoint := fmt.Sprintf("%s/registrations/clientApps/%s/users/anonymous", AuthBase, clientApp)
	body := map[string]any{
		"clientApp": map[string]any{
			"name":    clientApp,
			"browser": browserName,
		},
	}
	var out tokenResponse
	if err := DoJSON(http.MethodPost, endpoint, body, nil, &out); err != nil {
		return nil, fmt.Errorf("anonymous registration: %w", err)
	}
	tok := out.resolve()
	if tok.Value == "" {
		return nil, fmt.Errorf("anonymous registration: empty token value")
	}
	return tok, nil
}

// getSecurityToken exchanges the anonymous token for the HS256 security token
// (type "accs") that authorises the server-list and proxy-token calls.
func getSecurityToken(authToken string) (*Token, error) {
	body := map[string]any{
		"type":      "accs",
		"clientApp": map[string]any{"name": clientApp},
	}
	headers := map[string]string{"Authorization": "Bearer " + authToken}
	var out tokenResponse
	if err := DoJSON(http.MethodPost, AuthBase+"/security/tokens/accs", body, headers, &out); err != nil {
		return nil, fmt.Errorf("security token: %w", err)
	}
	tok := out.resolve()
	if tok.Value == "" {
		return nil, fmt.Errorf("security token: empty token value")
	}
	return tok, nil
}

// GetProxyToken exchanges a per-server signature for a short-lived proxy
// username. Authorised by the security token.
func GetProxyToken(securityToken, signature string) (*Token, error) {
	body := map[string]any{
		"type":      "accs-proxy",
		"clientApp": map[string]any{"name": clientApp},
		"signature": signature,
	}
	headers := map[string]string{"Authorization": "Bearer " + securityToken}
	var out tokenResponse
	if err := DoJSON(http.MethodPost, AuthBase+"/security/tokens/accs-proxy", body, headers, &out); err != nil {
		return nil, fmt.Errorf("proxy token: %w", err)
	}
	tok := out.resolve()
	if tok.Value == "" {
		return nil, fmt.Errorf("proxy token: empty token value")
	}
	return tok, nil
}

// Session holds the tokens for one CLI invocation.
type Session struct {
	Auth     *Token
	Security *Token
}

// BootstrapForce clears any cached security token and re-authenticates.
func BootstrapForce() (*Session, error) {
	c, err := LoadConfig()
	if err != nil {
		return nil, err
	}
	c.SecurityToken = nil
	if err := SaveConfig(c); err != nil {
		return nil, err
	}
	return Bootstrap()
}

// Bootstrap runs the two-step anonymous auth, reusing cached tokens when they
// are still valid. Only the minimum calls are made; there is no telemetry.
func Bootstrap() (*Session, error) {
	s := &Session{}
	c, err := LoadConfig()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if c.AuthToken.Valid(now, RefreshMargin) {
		s.Auth = c.AuthToken
	}
	// SecurityToken must have an expiration time and not be expired.
	// A token with zero expiration time is un-timestamped/stale.
	if c.SecurityToken.Valid(now, RefreshMargin) && !c.SecurityToken.ExpirationTime.IsZero() {
		s.Security = c.SecurityToken
	}

	if s.Auth == nil {
		tok, err := registerAnonymous()
		if err != nil {
			return nil, err
		}
		s.Auth = tok
		c.AuthToken = tok
	}
	if s.Security == nil {
		tok, err := getSecurityToken(s.Auth.Value)
		if err != nil {
			// Cached auth token may be stale or revoked; try re-registering once.
			tokAnon, errAnon := registerAnonymous()
			if errAnon != nil {
				return nil, fmt.Errorf("security token: %w", err)
			}
			s.Auth = tokAnon
			c.AuthToken = tokAnon
			tok, err = getSecurityToken(s.Auth.Value)
			if err != nil {
				return nil, fmt.Errorf("security token: %w", err)
			}
		}
		s.Security = tok
		c.SecurityToken = tok
	}
	if err := SaveConfig(c); err != nil {
		return nil, err
	}
	return s, nil
}

// redact keeps tokens out of logs and error strings.
func redact(s string) string {
	if s == "" {
		return ""
	}
	if len(s) <= 6 {
		return strings.Repeat("*", len(s))
	}
	return s[:3] + strings.Repeat("*", len(s)-6) + s[len(s)-3:]
}
