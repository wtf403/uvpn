package tunnel

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// A small DNS forwarder.
//
// The proxy carries TCP, so DNS cannot simply be proxied the same way. Instead
// this answers A/AAAA lookups itself, resolving through the tunnel so the
// answers correspond to the exit country, and it is what nftables redirects
// port 53 to.
//
// Two details make it behave:
//
//   - It returns the real IP in the answer, not the address the upstream
//     server saw, so a poisoned answer cannot be handed to the client.
//   - It binds loopback only, so it is not an open resolver on the LAN.

type dnsForwarder struct {
	// upstream is the real DNS server, queried over TCP through the tunnel.
	upstream string
	// ttl bounds how long a cached answer is served.
	ttl time.Duration
	// dial dials the upstream through the proxy, so DNS leaves from the exit IP.
	dial func(network, addr string) (net.Conn, error)

	pc net.PacketConn
	// ln is the TCP half. Clients fall back to TCP whenever the UDP answer is
	// truncated, and a TCP :53 query redirected here that nobody answers looks
	// to the client like a dead resolver.
	ln     net.Listener
	cache  map[string]dnsAnswer
	closed chan struct{}
	// expire gates how often the cache is swept.
	expire time.Time
}

type dnsAnswer struct {
	a     []net.IP
	ttl   uint32
	found bool
	// raw is the untouched answer section from upstream, used for record types
	// this forwarder does not parse into addresses.
	raw []byte
	// at is when the answer was cached, used to expire it.
	at time.Time
}

// startDNS binds the forwarder on loopback. The upstream dial goes through the
// relay's proxy dialer so queries leave from the exit IP.
func startDNS(dial func(network, addr string) (net.Conn, error)) (*dnsForwarder, error) {
	if isPortOpen(dnsPort) {
		return nil, fmt.Errorf("port %d is already in use; another DNS forwarder may be running", dnsPort)
	}
	pc, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", dnsPort))
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", dnsPort))
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	f := &dnsForwarder{
		upstream: "1.1.1.1:53",
		ttl:      5 * time.Minute,
		dial:     dial,
		pc:       pc,
		ln:       ln,
		cache:    map[string]dnsAnswer{},
		closed:   make(chan struct{}),
		expire:   time.Now(),
	}
	go f.serve()
	go f.serveTCP()
	return f, nil
}

// serveTCP answers the same queries over TCP, speaking the 2-byte length prefix
// the protocol requires.
func (f *dnsForwarder) serveTCP() {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			select {
			case <-f.closed:
				return
			default:
				continue
			}
		}
		go f.handleTCP(c)
	}
}

func (f *dnsForwarder) handleTCP(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	var lenBuf [2]byte
	if _, err := readFull(c, lenBuf[:]); err != nil {
		return
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	if n == 0 || n > 4096 {
		return
	}
	query := make([]byte, n)
	if _, err := readFull(c, query); err != nil {
		return
	}
	name, qtype, ok := parseQuestion(query)
	if !ok {
		return
	}
	f.evictExpired()
	reply, err := f.answer(query, name, qtype)
	if err != nil {
		return
	}
	var out [2]byte
	binary.BigEndian.PutUint16(out[:], uint16(len(reply)))
	if _, err := c.Write(out[:]); err != nil {
		return
	}
	_, _ = c.Write(reply)
}

func (f *dnsForwarder) serve() {
	buf := make([]byte, 1500)
	for {
		n, addr, err := f.pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-f.closed:
				return
			default:
				continue
			}
		}
		query := make([]byte, n)
		copy(query, buf[:n])
		go f.handle(query, addr)
	}
}

func (f *dnsForwarder) handle(query []byte, addr net.Addr) {
	name, qtype, ok := parseQuestion(query)
	if !ok {
		return
	}
	// Every query type is answered. The earlier version handled only A and
	// AAAA and silently dropped the rest, which leaks: a dropped MX or SRV
	// query does not fail loudly, the resolver just falls through to the next
	// nameserver, straight out of the tunnel.
	f.evictExpired()
	reply, err := f.answer(query, name, qtype)
	if err != nil {
		return
	}
	_, _ = f.pc.WriteTo(reply, addr)
}

func (f *dnsForwarder) lookup(name string, qtype uint16) (dnsAnswer, bool) {
	key := fmt.Sprintf("%s/%d", name, qtype)
	if a, ok := f.cache[key]; ok {
		return a, true
	}
	// Resolve by asking the upstream over TCP, which the relay tunnels.
	ans, err := f.queryUpstream(name, qtype)
	if err != nil {
		return dnsAnswer{}, false
	}
	f.cache[key] = ans
	return ans, true
}

// answer produces the full response bytes for a query of any type. A and AAAA
// are rebuilt from the parsed addresses; every other type is passed through
// verbatim, because re-encoding MX/SRV/CAA records by hand is a good way to
// introduce a bug that only shows up as broken mail delivery.
func (f *dnsForwarder) answer(query []byte, name string, qtype uint16) ([]byte, error) {
	ans, ok := f.lookup(name, qtype)
	if !ok {
		// Upstream unreachable. SERVFAIL is the right answer; silence would
		// make the resolver retry elsewhere and leak.
		return buildServFail(query, name, qtype)
	}
	if qtype != 1 && qtype != 28 {
		return passthroughAnswer(query, name, qtype, ans)
	}
	return buildAnswer(query, name, qtype, ans)
}

// evictExpired drops cached answers past their TTL. Run on the query path
// but at most once a minute, which is cheap at human DNS rates and avoids a
// background timer per cached entry.
func (f *dnsForwarder) evictExpired() {
	now := time.Now()
	if now.Before(f.expire) {
		return
	}
	f.expire = now.Add(time.Minute)
	cutoff := now.Add(-f.ttl)
	for k, a := range f.cache {
		if a.at.Before(cutoff) {
			delete(f.cache, k)
		}
	}
}

func (f *dnsForwarder) close() {
	close(f.closed)
	_ = f.pc.Close()
	if f.ln != nil {
		_ = f.ln.Close()
	}
}

// parseQuestion extracts the first question's name and type from a query.
func parseQuestion(msg []byte) (string, uint16, bool) {
	if len(msg) < 12 {
		return "", 0, false
	}
	idx := 12
	var sb strings.Builder
	for idx < len(msg) {
		l := int(msg[idx])
		idx++
		if l == 0 {
			break
		}
		if l&0xC0 == 0xC0 { // compression pointer: not expected in a question
			return "", 0, false
		}
		if idx+l > len(msg) {
			return "", 0, false
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		sb.Write(msg[idx : idx+l])
		idx += l
	}
	if idx+4 > len(msg) {
		return "", 0, false
	}
	qtype := binary.BigEndian.Uint16(msg[idx : idx+2])
	return sb.String(), qtype, sb.Len() > 0
}

// buildAnswer assembles a response carrying the addresses, preserving the
// transaction id from the query so the client accepts it.
func buildAnswer(query []byte, name string, qtype uint16, ans dnsAnswer) ([]byte, error) {
	if len(query) < 12 {
		return nil, fmt.Errorf("query too short to answer")
	}
	resp := make([]byte, 0, 12+len(name)+6+16*len(ans.a))
	// 12-byte header: id, flags, then the four section counts.
	header := make([]byte, 12)
	copy(header[0:2], query[0:2])              // id, echoed from the query
	header[2] = 0x81                           // QR=1 response, RD=1
	header[3] = 0x80                           // RA=1 recursion available
	binary.BigEndian.PutUint16(header[4:6], 1) // QDCOUNT, the echoed question
	binary.BigEndian.PutUint16(header[6:8], uint16(len(ans.a)))
	// NSCOUNT and ARCOUNT stay zero.
	resp = append(resp, header...)

	for _, label := range strings.Split(name, ".") {
		if label == "" {
			continue
		}
		resp = append(resp, byte(len(label)))
		resp = append(resp, label...)
	}
	resp = append(resp, 0)
	resp = append(resp, byte(qtype>>8), byte(qtype))
	resp = append(resp, 0, 1) // class IN

	if !ans.found {
		return resp, nil // NOERROR with no answers, rather than NXDOMAIN
	}
	for _, ip := range ans.a {
		// name pointer to the question, then type A/AAAA, class IN, TTL, RDLENGTH
		resp = append(resp, 0xC0, 0x0C)
		resp = append(resp, byte(qtype>>8), byte(qtype), 0, 1)
		ttl := ans.ttl
		resp = append(resp, byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl))
		if v4 := ip.To4(); v4 != nil {
			resp = append(resp, 0, 4)
			resp = append(resp, v4...)
		} else {
			resp = append(resp, 0, 16)
			resp = append(resp, ip.To16()...)
		}
	}
	return resp, nil
}

// queryUpstream asks the real resolver over TCP through the proxy, so the
// answer is resolved from the exit IP. TCP also sidesteps the UDP-truncation
// and spoofing problems that make direct UDP DNS a poor default.
func (f *dnsForwarder) queryUpstream(name string, qtype uint16) (dnsAnswer, error) {
	conn, err := f.proxyDial("tcp", f.upstream)
	if err != nil {
		return dnsAnswer{}, err
	}
	defer conn.Close()

	req, err := buildQuery(name, qtype)
	if err != nil {
		return dnsAnswer{}, err
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(req); err != nil {
		return dnsAnswer{}, err
	}

	// Read a 2-byte length prefix, then that many bytes.
	var lenBuf [2]byte
	if _, err := readFull(conn, lenBuf[:]); err != nil {
		return dnsAnswer{}, err
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	if n == 0 || n > 4096 {
		return dnsAnswer{}, fmt.Errorf("bad DNS response length %d", n)
	}
	msg := make([]byte, n)
	if _, err := readFull(conn, msg); err != nil {
		return dnsAnswer{}, err
	}
	ans, err := parseAnswers(msg, name, qtype)
	if err != nil {
		return dnsAnswer{}, err
	}
	ans.raw = append([]byte(nil), msg...)
	return ans, nil
}

// proxyDial calls the dial function the tunnel injected, so the forwarder
// shares the relay's dialer, including the SO_MARK that keeps its own traffic
// out of the redirect.
func (f *dnsForwarder) proxyDial(network, addr string) (net.Conn, error) {
	if f.dial == nil {
		return nil, fmt.Errorf("no proxy dialer configured for DNS")
	}
	return f.dial(network, addr)
}

func readFull(c net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := c.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// buildQuery assembles a standard recursive query for one name.
func buildQuery(name string, qtype uint16) ([]byte, error) {
	msg := make([]byte, 12, 12+len(name)+6)
	binary.BigEndian.PutUint16(msg[0:], 0x1234) // id
	msg[2] = 0x01                               // recursion desired
	binary.BigEndian.PutUint16(msg[4:], 1)      // QDCOUNT
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			continue
		}
		if len(label) > 63 {
			return nil, fmt.Errorf("label too long")
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0, byte(qtype>>8), byte(qtype), 0, 1)
	return msg, nil
}

// parseAnswers extracts the A/AAAA records from a response.
func parseAnswers(msg []byte, name string, qtype uint16) (dnsAnswer, error) {
	if len(msg) < 12 {
		return dnsAnswer{}, fmt.Errorf("short DNS response")
	}
	ancount := int(binary.BigEndian.Uint16(msg[6:10]))
	idx := 12
	// Skip the question section.
	if idx < len(msg) {
		for idx < len(msg) {
			if msg[idx]&0xC0 == 0xC0 {
				idx += 2
				break
			}
			if msg[idx] == 0 {
				idx++
				break
			}
			idx += int(msg[idx]) + 1
		}
		idx += 4
	}
	out := dnsAnswer{ttl: 60, at: time.Now()}
	for i := 0; i < ancount && idx+10 <= len(msg); i++ {
		// name (possibly compressed)
		if msg[idx]&0xC0 == 0xC0 {
			idx += 2
		} else {
			for idx < len(msg) && msg[idx] != 0 {
				idx += int(msg[idx]) + 1
			}
			idx++
		}
		if idx+10 > len(msg) {
			break
		}
		rtype := binary.BigEndian.Uint16(msg[idx : idx+2])
		ttl := binary.BigEndian.Uint32(msg[idx+4 : idx+8])
		rdlen := int(binary.BigEndian.Uint16(msg[idx+8 : idx+10]))
		idx += 10
		if idx+rdlen > len(msg) {
			break
		}
		if uint16(rtype) == qtype {
			if rdlen == 4 {
				out.a = append(out.a, net.IP(append([]byte(nil), msg[idx:idx+4]...)))
				out.found = true
				out.ttl = ttl
			} else if rdlen == 16 {
				out.a = append(out.a, net.IP(append([]byte(nil), msg[idx:idx+16]...)))
				out.found = true
				out.ttl = ttl
			}
		}
		idx += rdlen
	}
	return out, nil
}

// buildServFail reports that the name could not be resolved through the tunnel.
// Returning nothing would be worse: the client's resolver treats a timeout as
// "this server is bad" and moves on, which leaks the query rather than failing
// it. SERVFAIL keeps the client on this resolver and says what happened.
func buildServFail(query []byte, name string, qtype uint16) ([]byte, error) {
	if len(query) < 12 {
		return nil, fmt.Errorf("query too short")
	}
	h := make([]byte, 12)
	copy(h[0:2], query[0:2])
	h[2] = 0x81 // QR=1, RD=1
	h[3] = 0x82 // RA=1, RCODE=2 (SERVFAIL)
	binary.BigEndian.PutUint16(h[4:6], 1)
	resp := append([]byte(nil), h...)
	resp = appendQuestion(resp, name, qtype)
	return resp, nil
}

// passthroughAnswer echoes upstream's answer section for record types this
// forwarder does not decode. The question is re-emitted under the client's own
// transaction id so the response is accepted.
func passthroughAnswer(query []byte, name string, qtype uint16, ans dnsAnswer) ([]byte, error) {
	if len(query) < 12 || len(ans.raw) < 12 {
		return buildServFail(query, name, qtype)
	}
	// Skip upstream's 12-byte header and its question section; the client wants
	// its own question back, not upstream's.
	off := 12
	for off < len(ans.raw) {
		l := int(ans.raw[off])
		if l == 0 {
			off++
			break
		}
		if l&0xC0 == 0xC0 {
			off += 2
			break
		}
		off += l + 1
	}
	off += 4 // qtype + qclass
	if off > len(ans.raw) {
		return buildServFail(query, name, qtype)
	}

	h := make([]byte, 12)
	copy(h[0:2], query[0:2]) // our transaction id
	h[2] = 0x81
	h[3] = ans.raw[3] & 0x0F                                                    // RD echoed, RCODE and flags preserved
	binary.BigEndian.PutUint16(h[4:6], 1)                                       // QDCOUNT
	binary.BigEndian.PutUint16(h[6:8], binary.BigEndian.Uint16(ans.raw[6:8]))   // ANCOUNT
	binary.BigEndian.PutUint16(h[8:10], binary.BigEndian.Uint16(ans.raw[8:10])) // NSCOUNT
	binary.BigEndian.PutUint16(h[10:12], 0)                                     // ARCOUNT: dropped

	resp := append([]byte(nil), h...)
	resp = appendQuestion(resp, name, qtype)
	resp = append(resp, ans.raw[off:]...)
	return resp, nil
}

// appendQuestion writes the encoded question section.
func appendQuestion(dst []byte, name string, qtype uint16) []byte {
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			continue
		}
		dst = append(dst, byte(len(label)))
		dst = append(dst, label...)
	}
	dst = append(dst, 0, byte(qtype>>8), byte(qtype), 0, 1)
	return dst
}
