package tunnel

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// A minimal forward proxy, standing in for Urban VPN's, so the relay's CONNECT
// handling can be tested without depending on the vendor being up.
type stubProxy struct {
	ln     net.Listener
	auth   string
	mu     sync.Mutex
	seen   []string
	closed bool
}

func newStubProxy(t *testing.T, user, pass string) *stubProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &stubProxy{ln: ln, auth: basicAuth(user, pass)}
	go p.serve()
	t.Cleanup(func() { p.close() })
	return p
}

func (p *stubProxy) seenTargets() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.seen...)
}

func (p *stubProxy) close() {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	_ = p.ln.Close()
}

func (p *stubProxy) serve() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.handle(c)
	}
}

func (p *stubProxy) handle(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	// ReadRequest canonicalises header names, so compare against the
	// canonical form rather than the one we send on the wire.
	if p.auth != "" && req.Header.Get("Proxy-Authorization") != "Basic "+p.auth {
		fmt.Fprintf(c, "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
		return
	}
	if req.Method != http.MethodConnect {
		fmt.Fprintf(c, "HTTP/1.1 405 Method Not Allowed\r\n\r\n")
		return
	}
	target := req.Host
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(target, "443")
	}
	p.mu.Lock()
	p.seen = append(p.seen, target)
	p.mu.Unlock()

	up, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		fmt.Fprintf(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer up.Close()
	fmt.Fprintf(c, "HTTP/1.1 200 Connection established\r\n\r\n")
	splice(up, c)
}

// An end-to-end echo server the relay should reach through the proxy.
func startEcho(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				close(done)
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close(); <-done }
}

// The relay must send CONNECT with credentials and splice bytes both ways.
func TestRelayConnectThroughProxy(t *testing.T) {
	echoAddr, stopEcho := startEcho(t)
	defer stopEcho()
	proxy := newStubProxy(t, "tok", "1")

	dialer := &proxyDialer{addr: proxy.ln.Addr().String(), user: "tok", pass: "1", timeout: 5 * time.Second}
	conn, err := dialer.connect("tcp", echoAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Errorf("echo = %q, want ping", buf)
	}
	if seen := proxy.seenTargets(); len(seen) != 1 || seen[0] != echoAddr {
		t.Errorf("proxy saw %v, want [%s]", seen, echoAddr)
	}
}

// Without credentials the proxy refuses, and the relay must surface that
// rather than hanging or returning a half-open connection.
func TestRelayProxyAuthRequired(t *testing.T) {
	proxy := newStubProxy(t, "tok", "1")
	dialer := &proxyDialer{addr: proxy.ln.Addr().String(), user: "", pass: "", timeout: 5 * time.Second}
	_, err := dialer.connect("tcp", "127.0.0.1:9")
	if err == nil {
		t.Fatal("expected an error when the proxy rejects us")
	}
	if !strings.Contains(err.Error(), "407") {
		t.Errorf("error should mention the refusal: %v", err)
	}
}

// SO_ORIGINAL_DST only yields a destination on a redirected socket. On a
// directly accepted one it must fail cleanly rather than return something
// bogus that would send traffic to the wrong place.
func TestOriginalDstOnDirectConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			defer c.Close()
			time.Sleep(100 * time.Millisecond)
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	tc := c.(*net.TCPConn)
	// A correct implementation must either error or report a loopback
	// destination; it must never invent a routable address.
	dst, err := originalDst(tc)
	if err == nil && dst != nil && !dst.IP.IsLoopback() && !dst.IP.IsUnspecified() {
		t.Errorf("invented a non-loopback destination %v on a direct connection", dst)
	}
}

// RawSockaddrInet4's Port field holds the port in network byte order (big endian).
// parseRawSockaddr must decode it correctly on all architectures without byte-swapping.
func TestParseRawSockaddrPortEndianness(t *testing.T) {
	testCases := []struct {
		desc     string
		highByte byte
		lowByte  byte
		wantPort int
	}{
		{"HTTP port 80", 0x00, 0x50, 80},
		{"HTTPS port 443", 0x01, 0xbb, 443},
		{"DNS port 53", 0x00, 0x35, 53},
		{"High port 8080", 0x1f, 0x90, 8080},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			var sa syscall.RawSockaddrInet4
			sa.Addr = [4]byte{1, 2, 3, 4}
			// In memory, network byte order places high byte at offset 0, low byte at offset 1
			pBytes := (*[2]byte)(unsafe.Pointer(&sa.Port))
			pBytes[0] = tc.highByte
			pBytes[1] = tc.lowByte

			addr := parseRawSockaddr(&sa)
			if addr.Port != tc.wantPort {
				t.Errorf("parseRawSockaddr port = %d, want %d", addr.Port, tc.wantPort)
			}
			if !addr.IP.Equal(net.IPv4(1, 2, 3, 4)) {
				t.Errorf("parseRawSockaddr IP = %v, want 1.2.3.4", addr.IP)
			}
		})
	}
}

// The full data path as nftables would drive it: a client connects to the relay
// port, the relay recovers the original destination, CONNECTs through the proxy,
// and splices. The only thing stubbed is the redirect itself, which needs root.
func TestRelayEndToEndThroughProxy(t *testing.T) {
	lanIP := nonLoopbackIP(t)
	echoAddr, stopEcho := startEchoOn(t, lanIP)
	defer stopEcho()
	proxy := newStubProxy(t, "tok", "1")
	defer proxy.close()

	dialer := &proxyDialer{
		addr:    proxy.ln.Addr().String(),
		user:    "tok",
		pass:    "1",
		timeout: 5 * time.Second,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// Inject the destination: a real SO_ORIGINAL_DST needs a real REDIRECT, which
	// needs root. Everything downstream of it is exercised for real.
	r := &Relay{
		proxy: dialer,
		ln:    ln,
		logf:  func(s string) { t.Log(s) },
		dst: func(*net.TCPConn) (*net.TCPAddr, error) {
			return net.ResolveTCPAddr("tcp", echoAddr)
		},
	}
	go r.serve()
	defer r.close()

	// This is the connection a redirected client would make.
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if _, err := client.Write([]byte("round-trip")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("round-trip"))
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("spliced read: %v", err)
	}
	if string(buf) != "round-trip" {
		t.Errorf("echo = %q", buf)
	}
	if seen := proxy.seenTargets(); len(seen) != 1 || seen[0] != echoAddr {
		t.Errorf("proxy saw %v, want [%s]", seen, echoAddr)
	}
}

// nonLoopbackIP finds an address on this host that is not loopback, so a test
// can exercise a destination the relay will actually accept.
func nonLoopbackIP(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("cannot enumerate interfaces: %v", err)
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP.IsLoopback() || n.IP.To4() == nil {
			continue
		}
		return n.IP.String()
	}
	t.Skip("no non-loopback IPv4 address on this host")
	return ""
}

// startEchoOn is startEcho bound to a specific address.
func startEchoOn(t *testing.T, host string) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Skipf("cannot listen on %s: %v", host, err)
	}
	done := make(chan struct{})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				close(done)
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close(); <-done }
}
