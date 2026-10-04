package client

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// The countries endpoint shape, mirroring what the extension consumes:
//
//	{ "countries": { "elements": [ {
//	    "code": {"iso2": "US"}, "title": "United States", "accessType": "ACCESSIBLE",
//	    "servers": { "elements": [ {
//	        "signature": "...",
//	        "address": { "primary": {"host": "...", "port": 8080, "ip": "..."} }
//	    } ] }
//	} ] } }
//
// Location identifier is the ISO-3166 alpha-2 code. The proxy scheme is always
// "http" (CONNECT); the extension hardcodes it, so there is no SOCKS.

type address struct {
	Host string      `json:"host"`
	Port json.Number `json:"port"`
	IP   string      `json:"ip"`
}

type serverAddress struct {
	Primary address `json:"primary"`
}

type server struct {
	Signature string        `json:"signature"`
	Address   serverAddress `json:"address"`
}

type elems[T any] struct {
	Elements []T `json:"elements"`
}

type country struct {
	Code struct {
		ISO2 string `json:"iso2"`
	} `json:"code"`
	Title      string        `json:"title"`
	Name       string        `json:"name"`
	AccessType string        `json:"accessType"`
	Servers    elems[server] `json:"servers"`
}

type countriesResponse struct {
	Countries elems[country] `json:"countries"`
}

// Location is one connectable server, flattened for CLI use.
type Location struct {
	Code      string
	Country   string
	Host      string
	Port      string
	IP        string
	Signature string
}

// ListLocations fetches the server list. The endpoint requires an
// Authorization header, so the session is Bootstrapped first.
func ListLocations() ([]Location, error) {
	sess, err := Bootstrap()
	if err != nil {
		return nil, err
	}
	headers := map[string]string{"Authorization": "Bearer " + sess.Security.Value}
	var resp countriesResponse
	err = DoJSON(http.MethodGet, StatsBase+"/entrypoints/countries", nil, headers, &resp)
	if err != nil && strings.Contains(err.Error(), "401") {
		sess, bErr := BootstrapForce()
		if bErr == nil {
			headers["Authorization"] = "Bearer " + sess.Security.Value
			err = DoJSON(http.MethodGet, StatsBase+"/entrypoints/countries", nil, headers, &resp)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("server list: %w", err)
	}

	var out []Location
	for _, c := range resp.Countries.Elements {
		name := c.Title
		if name == "" {
			name = c.Name
		}
		for _, s := range c.Servers.Elements {
			if s.Address.Primary.Host == "" {
				continue
			}
			out = append(out, Location{
				Code:      strings.ToUpper(c.Code.ISO2),
				Country:   name,
				Host:      s.Address.Primary.Host,
				Port:      s.Address.Primary.Port.String(),
				IP:        s.Address.Primary.IP,
				Signature: s.Signature,
			})
		}
	}
	// Stable, useful ordering: by code then host.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Code != out[j].Code {
			return out[i].Code < out[j].Code
		}
		return out[i].Host < out[j].Host
	})
	return out, nil
}

// PickLocation finds the best server for a country code, preferring the
// hostname over the raw IP (matching the extension's default behaviour).
func PickLocation(locs []Location, code string) (*Location, error) {
	code = strings.ToUpper(code)
	var exact, inPrefix []Location
	for _, l := range locs {
		if l.Code == code {
			exact = append(exact, l)
		} else if strings.HasPrefix(l.Code, code) {
			inPrefix = append(inPrefix, l)
		}
	}
	pool := exact
	if len(pool) == 0 {
		pool = inPrefix
	}
	if len(pool) == 0 {
		return nil, fmt.Errorf("no server found for %q; run `uvpn list`", code)
	}
	return &pool[0], nil
}

// PickServer finds a specific server within a country by its IP address or
// hostname. Returns nil if no match is found.
func PickServer(locs []Location, code, server string) (*Location, error) {
	code = strings.ToUpper(code)
	server = strings.ToLower(strings.TrimSpace(server))
	for _, l := range locs {
		if l.Code != code {
			continue
		}
		if strings.ToLower(l.IP) == server || strings.ToLower(l.Host) == server {
			lc := l
			return &lc, nil
		}
	}
	return nil, fmt.Errorf("no server matching %q found in %s; run `uvpn list %s`",
		server, code, code)
}
