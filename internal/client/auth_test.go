package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestTokenValid(t *testing.T) {
	now := time.Now()

	// Nil or empty token is never valid
	var nilTok *Token
	if nilTok.Valid(now, RefreshMargin) {
		t.Error("nil token should not be valid")
	}
	emptyTok := &Token{Value: ""}
	if emptyTok.Valid(now, RefreshMargin) {
		t.Error("empty value token should not be valid")
	}

	// Token with zero ExpirationTime (e.g. anonymous token) is considered valid
	zeroExp := &Token{Value: "anon"}
	if !zeroExp.Valid(now, RefreshMargin) {
		t.Error("token with zero expiration should be valid")
	}

	// Future token well past margin
	futureTok := &Token{Value: "valid", ExpirationTime: now.Add(1 * time.Hour)}
	if !futureTok.Valid(now, RefreshMargin) {
		t.Error("future token should be valid")
	}

	// Token within refresh margin should be considered invalid (time to refresh)
	nearExpiry := &Token{Value: "expiring", ExpirationTime: now.Add(2 * time.Minute)}
	if nearExpiry.Valid(now, RefreshMargin) {
		t.Error("token within refresh margin should not be valid")
	}

	// Expired token
	pastTok := &Token{Value: "expired", ExpirationTime: now.Add(-10 * time.Minute)}
	if pastTok.Valid(now, RefreshMargin) {
		t.Error("expired token should not be valid")
	}
}

func TestBootstrapRefreshesExpiredSecurityToken(t *testing.T) {
	var anonCalls, secCalls int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rest/v1/registrations/clientApps/" + clientApp + "/users/anonymous":
			atomic.AddInt32(&anonCalls, 1)
			_ = json.NewEncoder(w).Encode(tokenResponse{
				Type:  "anonm",
				Value: "new-anon-tok",
			})
		case "/rest/v1/security/tokens/accs":
			atomic.AddInt32(&secCalls, 1)
			_ = json.NewEncoder(w).Encode(tokenResponse{
				Type:           "accs",
				Value:          "new-sec-tok",
				ExpirationTime: time.Now().Add(1 * time.Hour).UnixMilli(),
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	oldAuth := AuthBase
	AuthBase = srv.URL + "/rest/v1"
	defer func() { AuthBase = oldAuth }()

	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	// Seed config with a valid auth token and an expired security token
	c, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	c.AuthToken = &Token{Value: "valid-anon"}
	c.SecurityToken = &Token{
		Value:          "old-expired-sec",
		ExpirationTime: time.Now().Add(-1 * time.Hour),
	}
	if err := SaveConfig(c); err != nil {
		t.Fatal(err)
	}

	sess, err := Bootstrap()
	if err != nil {
		t.Fatalf("Bootstrap failed: %v", err)
	}

	// Should have reused existing auth token, so 0 calls to registerAnonymous
	if got := atomic.LoadInt32(&anonCalls); got != 0 {
		t.Errorf("anonCalls = %d, want 0", got)
	}
	// Should have requested a new security token
	if got := atomic.LoadInt32(&secCalls); got != 1 {
		t.Errorf("secCalls = %d, want 1", got)
	}
	if sess.Security.Value != "new-sec-tok" {
		t.Errorf("Security token = %q, want new-sec-tok", sess.Security.Value)
	}
}

func TestBootstrapForceClearsAndRenews(t *testing.T) {
	var secCalls int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/rest/v1/security/tokens/accs" {
			n := atomic.AddInt32(&secCalls, 1)
			_ = json.NewEncoder(w).Encode(tokenResponse{
				Type:           "accs",
				Value:          "sec-tok-" + string(rune('0'+n)),
				ExpirationTime: time.Now().Add(1 * time.Hour).UnixMilli(),
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	oldAuth := AuthBase
	AuthBase = srv.URL + "/rest/v1"
	defer func() { AuthBase = oldAuth }()

	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	c, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	c.AuthToken = &Token{Value: "anon-tok"}
	c.SecurityToken = &Token{
		Value:          "current-sec-tok",
		ExpirationTime: time.Now().Add(30 * time.Minute),
	}
	if err := SaveConfig(c); err != nil {
		t.Fatal(err)
	}

	// Bootstrap should reuse valid token
	sess, err := Bootstrap()
	if err != nil {
		t.Fatal(err)
	}
	if sess.Security.Value != "current-sec-tok" {
		t.Errorf("Bootstrap did not reuse valid token: got %q", sess.Security.Value)
	}

	// BootstrapForce must renew
	forcedSess, err := BootstrapForce()
	if err != nil {
		t.Fatal(err)
	}
	if forcedSess.Security.Value != "sec-tok-1" {
		t.Errorf("BootstrapForce did not renew: got %q", forcedSess.Security.Value)
	}
}
