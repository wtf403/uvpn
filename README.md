# uvpn

A no-telemetry VPN CLI for Linux that talks to Urban VPN's own APIs. Single
static binary, no accounts, no telemetry.

**This project is 100% reverse-engineered.** Urban VPN publishes no API docs,
no SDK and no protocol specification. Every endpoint, header, token flow,
WireGuard peer exchange and tunnel behaviour in this repo was recovered by
observing the vendor's browser extension and apps on the wire. Nothing here
comes from official documentation, and nothing here is officially sanctioned.

Unofficial: not affiliated with, endorsed by, or supported by Urban VPN.
Using a third-party client may break without notice when the vendor changes
their private API.

## Modes

- `uvpn connect <CODE>`: HTTP proxy for proxy-aware tools (curl, browsers).
- `uvpn tunnel up <CODE>`: full tunnel for *all* TCP traffic via nftables and a
  local CONNECT relay. Needs root.
- `uvpn wg up <CODE>`: WireGuard tunnel (UDP-capable). Needs root and
  `wg-quick`.

## Build

    go build -o uvpn .
    go vet ./...
    go test ./...

## Quick start

    ./uvpn list               # available countries
    ./uvpn list AU            # servers in one country
    ./uvpn connect --ip 139.99.148.8 AU   # pick a specific server
    eval "$(./uvpn env)"      # export proxy vars into your shell
    ./uvpn test               # verify egress IP changed
    ./uvpn disconnect

Full tunnel:

    sudo ./uvpn tunnel up AU
    curl https://ifconfig.me
    sudo ./uvpn tunnel down

## State

Config lives in `~/.config/uvpn/` (`config.json` 0600, `env.sh`, `wg0.conf`).
`sudo` commands resolve the invoking user's home via `SUDO_USER`, so connect as
yourself and only the tunnel commands need root.

## Reverse engineering notes

- All three API hosts and their path prefixes were discovered by intercepting
  the vendor's own client traffic; they are not interchangeable.
- Token expiry is signed against the *server's* clock, so the client tracks
  clock skew rather than trusting the local one.
- Anything we guessed is marked with a `why` comment. Read it before you change
  the code.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
