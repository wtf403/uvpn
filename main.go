package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"uvpn/internal/client"
	"uvpn/internal/tunnel"
	"uvpn/internal/wg"
)

const usage = `uvpn - Urban VPN CLI for Linux (no telemetry)

Usage:
  uvpn list                 List available VPN locations
  uvpn connect <CODE>       Connect through a country code (e.g. US, DE, JP)
  uvpn status               Show the current connection
  uvpn disconnect           Remove the proxy configuration
  uvpn env                  Print shell export statements for the active proxy
  uvpn ip                   Show the current egress IP
  uvpn test                 Verify the active proxy changes your egress IP

  uvpn wg <subcommand>      WireGuard tunnel: covers apps that ignore proxy settings
  uvpn tunnel <subcommand>  Full-tunnel: route all traffic through the proxy
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "list":
		err = cmdList(os.Args[2:])
	case "connect":
		err = cmdConnect(os.Args[2:])
	case "status":
		err = cmdStatus(os.Args[2:])
	case "disconnect":
		err = cmdDisconnect(os.Args[2:])
	case "env":
		err = cmdEnv(os.Args[2:])
	case "ip":
		err = cmdIP(os.Args[2:])
	case "test":
		err = cmdTest(os.Args[2:])
	case "wg":
		err = wg.CmdWireGuard(os.Args[2:])
	case "tunnel":
		err = tunnel.CmdTunnel(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func cmdList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	fs.Parse(args)
	locs, err := client.ListLocations()
	if err != nil {
		return err
	}
	if len(locs) == 0 {
		fmt.Println("no locations available")
		return nil
	}

	// If a country code is given as an argument, list every server in it.
	if fs.NArg() >= 1 {
		code := strings.ToUpper(fs.Arg(0))
		fmt.Printf("Servers in %s:\n\n", code)
		fmt.Printf("%-42s  %-15s  %s\n", "HOST", "IP", "PORT")
		for _, l := range locs {
			if l.Code != code {
				continue
			}
			fmt.Printf("%-42s  %-15s  %s\n", l.Host, l.IP, l.Port)
		}
		return nil
	}

	// Collapse to one row per country for readability, with server count.
	byCode := map[string][]client.Location{}
	var order []string
	for _, l := range locs {
		if _, ok := byCode[l.Code]; !ok {
			order = append(order, l.Code)
		}
		byCode[l.Code] = append(byCode[l.Code], l)
	}
	sort.Strings(order)
	fmt.Printf("%-5s  %-30s  %s\n", "CODE", "COUNTRY", "SERVERS")
	for _, code := range order {
		rows := byCode[code]
		fmt.Printf("%-5s  %-30s  %d\n", code, rows[0].Country, len(rows))
	}
	fmt.Println("\nUse `uvpn list <CODE>` to see all servers in a country,")
	fmt.Println("then `uvpn connect <CODE> --ip <IP>` or `--host <HOST>` to pick one.")
	return nil
}

func cmdConnect(args []string) error {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	serverIP := fs.String("ip", "", "specific server IP to connect through")
	serverHost := fs.String("host", "", "specific server hostname to connect through")
	fs.Parse(args)
	if fs.NArg() == 0 {
		return errors.New("connect requires a country code, e.g. `uvpn connect US`")
	}
	code := strings.ToUpper(fs.Arg(0))

	locs, err := client.ListLocations()
	if err != nil {
		return err
	}

	var loc *client.Location
	switch {
	case *serverIP != "":
		loc, err = client.PickServer(locs, code, *serverIP)
		if err != nil {
			return err
		}
		// Use the raw IP for the connection.
		if loc.IP != "" {
			loc.Host = loc.IP
		}
	case *serverHost != "":
		loc, err = client.PickServer(locs, code, *serverHost)
		if err != nil {
			return err
		}
	default:
		loc, err = client.PickLocation(locs, code)
		if err != nil {
			return err
		}
	}
	hostport := loc.Host + ":" + loc.Port

	// Per-server proxy token: username = token value, password = "1".
	sess, err := client.Bootstrap()
	if err != nil {
		return err
	}
	pt, err := client.GetProxyToken(sess.Security.Value, loc.Signature)
	if err != nil && strings.Contains(err.Error(), "401") {
		sess, bErr := client.BootstrapForce()
		if bErr == nil {
			pt, err = client.GetProxyToken(sess.Security.Value, loc.Signature)
		}
	}
	if err != nil {
		return err
	}

	c, err := client.LoadConfig()
	if err != nil {
		return err
	}
	c.Location = loc.Code
	c.Country = loc.Country
	c.Scheme = "http"
	c.Proxy = hostport
	c.Username = pt.Value
	c.Password = client.ProxyPassword
	c.ExpiresAt = pt.ExpirationTime
	if err := client.SaveConfig(c); err != nil {
		return err
	}
	if err := client.WriteEnvFile(c); err != nil {
		return err
	}
	client.ApplyToCurrentProcess(c)

	fmt.Printf("connected: %s (%s) via %s\n", loc.Code, loc.Country, hostport)
	if !pt.ExpirationTime.IsZero() {
		fmt.Printf("credential expires: %s\n", pt.ExpirationTime.Format(time.RFC3339))
	}
	client.PrintConnectHint(c)
	return nil
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	fs.Parse(args)
	c, err := client.LoadConfig()
	if err != nil {
		return err
	}
	if c.Proxy == "" {
		fmt.Println("not connected")
		return nil
	}
	fmt.Printf("location: %s (%s)\n", c.Location, c.Country)
	fmt.Printf("proxy:    %s://%s\n", c.Scheme, c.Proxy)
	if !c.ExpiresAt.IsZero() {
		fmt.Printf("expires:  %s (%s)\n", c.ExpiresAt.Format(time.RFC3339),
			validWord(c.CredentialValid(time.Now(), client.RefreshMargin)))
	}
	return nil
}

func cmdDisconnect(args []string) error {
	fs := flag.NewFlagSet("disconnect", flag.ExitOnError)
	fs.Parse(args)
	if err := client.ClearConfig(); err != nil {
		return err
	}
	if err := client.RemoveEnvFile(); err != nil {
		return err
	}
	fmt.Println("disconnected; proxy configuration removed")
	fmt.Println("note: unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY in existing shells")
	return nil
}

func cmdEnv(args []string) error {
	fs := flag.NewFlagSet("env", flag.ExitOnError)
	fs.Parse(args)
	c, err := client.LoadConfig()
	if err != nil {
		return err
	}
	if c.Proxy == "" {
		return errors.New("not connected")
	}
	p, err := client.EnvFile()
	if err != nil {
		return err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	fmt.Print(string(b))
	return nil
}

func cmdIP(args []string) error {
	fs := flag.NewFlagSet("ip", flag.ExitOnError)
	fs.Parse(args)
	ip, err := client.EgressIP()
	if err != nil {
		return err
	}
	fmt.Println(ip)
	return nil
}

func cmdTest(args []string) error {
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	fs.Parse(args)
	c, err := client.LoadConfig()
	if err != nil {
		return err
	}
	if c.Proxy == "" {
		return errors.New("not connected; run `uvpn connect <CODE>` first")
	}
	direct, _ := client.EgressIP()
	tr, err := client.ProxyTransport(c.Scheme, c.Proxy, c.Username, c.Password)
	if err != nil {
		return err
	}
	via, verr := client.EgressIPVia(tr)
	if verr != nil {
		return fmt.Errorf("proxy request failed: %w", verr)
	}
	fmt.Printf("direct egress: %s\n", direct)
	fmt.Printf("proxy  egress: %s\n", via)
	if direct != via {
		fmt.Println("OK: traffic is routing through the proxy")
		return nil
	}
	fmt.Println("WARN: egress IP unchanged; the proxy may not be in effect")
	return nil
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func validWord(v bool) string {
	if v {
		return "valid"
	}
	return "expired, reconnect"
}
