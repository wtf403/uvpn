// Package sub renders Urban VPN locations as a Happ/Xray subscription.
//
// Happ (Xray core) has no native plain-HTTP-proxy share link; its supported
// share schemes are VLESS, VMess, Trojan, Shadowsocks, Socks5 and Hysteria2.
// However, Happ accepts a *subscription* whose body is a JSON array of full
// Xray configs, passed through 1:1 ("Direct Passthrough"). Urban VPN exposes
// only an HTTP CONNECT proxy, and Xray has an "http" outbound, so each server
// is emitted as a minimal Xray config with a single protocol:"http" outbound
// carrying the per-server proxy credentials.
//
// Urban VPN proxy tokens are short-lived (~30 min), so this subscription must
// be regenerated on every fetch; `uvpn serve` does that.
package sub

import (
	"encoding/json"
	"sort"
	"strings"
	"sync"

	"uvpn/internal/client"
)

// XrayConfig is a minimal Xray config; Happ passes it straight to the core.
type XrayConfig struct {
	Remarks   string     `json:"remarks"`
	Log       logCfg     `json:"log"`
	Inbounds  []inbound  `json:"inbounds"`
	Outbounds []outbound `json:"outbounds"`
}

type logCfg struct {
	Loglevel string `json:"loglevel"`
}

type inbound struct {
	Listen   string         `json:"listen"`
	Port     int            `json:"port"`
	Protocol string         `json:"protocol"`
	Settings map[string]any `json:"settings"`
	Tag      string         `json:"tag"`
}

type outbound struct {
	Protocol string      `json:"protocol"`
	Tag      string      `json:"tag"`
	Settings httpSetting `json:"settings"`
}

type httpSetting struct {
	Servers []httpServer `json:"servers"`
}

type httpServer struct {
	Address string     `json:"address"`
	Port    int        `json:"port"`
	Users   []httpUser `json:"users,omitempty"`
}

type httpUser struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

// Build fetches every location, mints a fresh proxy token per server, and
// returns a Happ-compatible subscription body (JSON array). Servers that
// fail to mint a token are skipped; nothing is emitted for them.
func Build() ([]byte, error) {
	locs, err := client.ListLocations()
	if err != nil {
		return nil, err
	}
	sess, err := client.Bootstrap()
	if err != nil {
		return nil, err
	}

	cfgs := make([]XrayConfig, 0, len(locs))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 12)
	for _, l := range locs {
		wg.Add(1)
		go func(l client.Location) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			pt, err := client.GetProxyToken(sess.Security.Value, l.Signature)
			if err != nil || pt == nil || pt.Value == "" {
				return
			}
			host := l.Host
			if l.IP != "" {
				host = l.IP
			}
			port := 8081
			if l.Port != "" {
				// parse int port
				var p int
				for _, ch := range l.Port {
					if ch < '0' || ch > '9' {
						p = 0
						break
					}
					p = p*10 + int(ch-'0')
				}
				if p > 0 {
					port = p
				}
			}
			name := strings.TrimSpace(l.Country)
			if name == "" {
				name = l.Code
			}
			name = l.Code + " " + name
			if host != "" {
				name += " · " + host
			}
			cfg := XrayConfig{
				Remarks: name,
				Log:     logCfg{Loglevel: "warning"},
				Inbounds: []inbound{{
					Listen:   "127.0.0.1",
					Port:     10808,
					Protocol: "socks",
					Settings: map[string]any{"udp": true},
					Tag:      "socks-in",
				}},
				Outbounds: []outbound{{
					Protocol: "http",
					Tag:      "proxy",
					Settings: httpSetting{Servers: []httpServer{{
						Address: host,
						Port:    port,
						Users:   []httpUser{{User: pt.Value, Pass: client.ProxyPassword}},
					}}},
				}},
			}
			mu.Lock()
			cfgs = append(cfgs, cfg)
			mu.Unlock()
		}(l)
	}
	wg.Wait()

	sort.Slice(cfgs, func(i, j int) bool { return cfgs[i].Remarks < cfgs[j].Remarks })
	body, err := json.MarshalIndent(cfgs, "", "  ")
	if err != nil {
		return nil, err
	}
	return body, nil
}
