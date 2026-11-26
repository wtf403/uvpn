package tunnel

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// A transparent full-tunnel.
//
// The goal is that *everything* on the host egresses through the Urban VPN
// proxy, including applications that ignore http_proxy entirely: Chromium,
// Electron, Steam, Java, games.
//
// Rather than implement a userspace TCP/IP stack to read from a TUN device,
// this uses the kernel's own stack and intercepts at the connection level:
//
//	nftables: all TCP  -> redirect to 127.0.0.1:<relay>
//	the kernel still performs routing, the TCP handshake and retransmits
//	the relay accepts the connection, recovers the real destination with
//	  SO_ORIGINAL_DST, dials it through the proxy using CONNECT, and splices
//	  the two byte streams together
//
// So the only hand-written protocol code is a TCP relay; the failure-prone
// part stays in the kernel.
//
// Our own outbound sockets are marked (SO_MARK) so nftables lets them bypass
// the redirect; without that the relay would try to route its own connection
// to the proxy through the proxy and deadlock.

// soOriginalDst is SO_ORIGINAL_DST from linux/netfilter_ipv4.h: after a
// REDIRECT, the kernel keeps the pre-redirect destination here.
const soOriginalDst = 80

// bypassMark is the nfmark applied to sockets the relay creates. nftables
// accepts any packet carrying it, so the relay's own traffic to the proxy
// never re-enters the relay.
const bypassMark = 0x1

// originalDst recovers the pre-redirect destination of an accepted connection.
func originalDst(conn *net.TCPConn) (*net.TCPAddr, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	var (
		addr  syscall.RawSockaddrInet4
		size  = uint32(syscall.SizeofSockaddrInet4)
		inner error
	)
	err = raw.Control(func(fd uintptr) {
		_, _, e := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			uintptr(syscall.IPPROTO_IP),
			uintptr(soOriginalDst),
			uintptr(unsafe.Pointer(&addr)),
			uintptr(unsafe.Pointer(&size)),
			0,
		)
		if e != 0 {
			inner = e
		}
	})
	if err != nil {
		return nil, err
	}
	if inner != nil {
		return nil, inner
	}
	return parseRawSockaddr(&addr), nil
}

// parseRawSockaddr converts the kernel sockaddr_in to a net.TCPAddr.
// Note: sin_port in sockaddr_in is in network byte order (big endian), so
// it must be decoded with BigEndian rather than converted directly as uint16,
// which would byte-swap the port on little-endian architectures (e.g. 80 -> 20480).
func parseRawSockaddr(addr *syscall.RawSockaddrInet4) *net.TCPAddr {
	ip := net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
	port := int(binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&addr.Port))[:]))
	return &net.TCPAddr{IP: ip, Port: port}
}

// markOutbound sets SO_MARK so nftables can exempt our own sockets from the
// redirect. SO_MARK needs CAP_NET_ADMIN, which the tunnel has because it runs
// as root, but not every context allows it, so a failure here is reported and
// the ruleset falls back to exempting by uid rather than being fatal.
// markingWorks reports whether SO_MARK actually took effect, so callers can
// choose between the mark-based and uid-based exemption.
func markingWorks() bool {
	c, err := net.Dial("tcp", "127.0.0.1:9")
	if err != nil {
		return false
	}
	defer c.Close()
	rc, err := c.(*net.TCPConn).SyscallConn()
	if err != nil {
		return false
	}
	return markOutbound(rc) == nil
}

// proxyDialer dials arbitrary destinations through the authenticated HTTP
// proxy. The proxy only speaks HTTP, so HTTPS and any TCP service are reached
// with CONNECT, which is a raw byte pipe and protocol-agnostic.
type proxyDialer struct {
	// addr is the proxy's host:port, as stored in the config.
	addr    string
	user    string
	pass    string
	timeout time.Duration
}

func (p *proxyDialer) connect(network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("bad destination %q: %w", addr, err)
	}
	target := net.JoinHostPort(host, port)

	// Mark the socket so the proxy connection itself bypasses the redirect;
	// otherwise the relay would send its own proxy connection back into itself.
	base := &net.Dialer{
		Timeout: p.timeout,
		Control: func(network, _ string, c syscall.RawConn) error {
			// Best effort: the nftables ruleset also exempts our uid, so a
			// context without CAP_NET_ADMIN still works.
			_ = markOutbound(c)
			return nil
		},
	}

	conn, err := base.Dial("tcp", p.addr)
	if err != nil {
		return nil, fmt.Errorf("dial proxy: %w", err)
	}

	// CONNECT establishes a raw tunnel; the proxy cannot see inside it.
	req := &strings.Builder{}
	fmt.Fprintf(req, "CONNECT %s HTTP/1.1\r\n", target)
	fmt.Fprintf(req, "Host: %s\r\n", target)
	if p.user != "" {
		req.WriteString("Proxy-Authorization: Basic " + basicAuth(p.user, p.pass) + "\r\n")
	}
	req.WriteString("Proxy-Connection: keep-alive\r\n\r\n")

	_ = conn.SetDeadline(time.Now().Add(p.timeout))
	if _, err := conn.Write([]byte(req.String())); err != nil {
		conn.Close()
		return nil, fmt.Errorf("send CONNECT: %w", err)
	}
	resp, err := http.ReadResponse(newBufioReader(conn), nil)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read CONNECT reply: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("proxy refused CONNECT to %s: %s", target, resp.Status)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// splice copies in both directions until either side closes, then closes both.
// This is the whole data path.
func splice(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	copyOne := func(dst, src net.Conn) {
		defer wg.Done()
		// A short deadline catches a peer that goes silent without closing,
		// so a dead connection does not pin the goroutine forever.
		_ = dst.SetWriteDeadline(time.Now().Add(5 * time.Minute))
		_, _ = io.Copy(dst, src)
		if c, ok := dst.(*net.TCPConn); ok {
			_ = c.CloseWrite()
		}
	}
	go copyOne(a, b)
	go copyOne(b, a)
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}

// Relay accepts redirected connections and forwards them through the proxy.
type Relay struct {
	proxy *proxyDialer
	ln    net.Listener
	wg    sync.WaitGroup
	// logf, when set, receives one line per connection.
	logf func(string)
	// dst recovers the pre-redirect destination. It is a field so tests can
	// supply one: SO_ORIGINAL_DST only carries meaning on a socket the kernel
	// actually redirected, so without root there is no way to produce a genuine
	// one, and a test that pretended otherwise would be testing the stub.
	dst func(*net.TCPConn) (*net.TCPAddr, error)
}

func (r *Relay) serve() error {
	for {
		c, err := r.ln.Accept()
		if err != nil {
			return err
		}
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.handle(c)
		}()
	}
}

func (r *Relay) handle(c net.Conn) {
	defer c.Close()
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	resolve := r.dst
	if resolve == nil {
		resolve = originalDst
	}
	dst, err := resolve(tc)
	if err != nil {
		// A loopback or already-connected socket has no original destination;
		// nothing sensible to forward to.
		if r.logf != nil {
			r.logf(fmt.Sprintf("no original dst: %v", err))
		}
		return
	}
	if r.logf != nil {
		r.logf(fmt.Sprintf("ACCEPTED raw dst=%v loopback=%v unspec=%v", dst,
			dst.IP.IsLoopback(), dst.IP.IsUnspecified()))
	}
	if dst.IP.IsLoopback() || dst.IP.IsUnspecified() {
		return // never tunnel our own listeners or the DNS forwarder
	}
	if r.logf != nil {
		r.logf(fmt.Sprintf("%s -> %s", c.LocalAddr(), dst))
	}
	out, err := r.proxy.connect("tcp", dst.String())
	if err != nil {
		if r.logf != nil {
			r.logf(fmt.Sprintf("  failed: %v", err))
		}
		return
	}
	splice(out, tc)
}

func (r *Relay) close() {
	_ = r.ln.Close()
}

// basicAuth builds the Proxy-Authorization value. The proxy takes the proxy
// token as the username and the literal "1" as the password.
func basicAuth(user, pass string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
}

func newBufioReader(c net.Conn) *bufio.Reader {
	return bufio.NewReader(c)
}
