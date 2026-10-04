package tunnel

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestParseQuestion(t *testing.T) {
	msg, err := buildQuery("api.ipify.org", 1)
	if err != nil {
		t.Fatal(err)
	}
	name, qtype, ok := parseQuestion(msg)
	if !ok {
		t.Fatal("failed to parse our own query")
	}
	if name != "api.ipify.org" || qtype != 1 {
		t.Errorf("got %q/%d", name, qtype)
	}
}

func TestBuildAnswerRoundTrip(t *testing.T) {
	query, _ := buildQuery("example.com", 1)
	ans := dnsAnswer{a: []net.IP{net.IPv4(1, 2, 3, 4)}, ttl: 300, found: true, at: time.Now()}
	reply, err := buildAnswer(query, "example.com", 1, ans)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(reply[0:2]) != binary.BigEndian.Uint16(query[0:2]) {
		t.Error("transaction id not preserved")
	}
	if reply[2]&0x80 == 0 {
		t.Error("QR bit not set; this is not a response")
	}
	if cnt := binary.BigEndian.Uint16(reply[6:8]); cnt != 1 {
		t.Errorf("ANCOUNT = %d, want 1", cnt)
	}
	// Wire format length-prefixes each label, so the name is not contiguous
	// text; parse it back instead of searching the bytes.
	qname, qt, ok := parseQuestion(reply)
	if !ok || qname != "example.com" || qt != 1 {
		t.Errorf("question section = %q/%d (ok=%v), want example.com/1", qname, qt, ok)
	}
}

func TestBuildAnswerNoRecords(t *testing.T) {
	query, _ := buildQuery("nx.example", 1)
	reply, err := buildAnswer(query, "nx.example", 1, dnsAnswer{at: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	// Should be a well-formed NOERROR with zero answers, not a malformed
	// reply that makes the resolver retry forever.
	if cnt := binary.BigEndian.Uint16(reply[6:8]); cnt != 0 {
		t.Errorf("ANCOUNT = %d, want 0", cnt)
	}
	if binary.BigEndian.Uint32(reply[2:6])&0xF == 0xF {
		t.Error("rcode should be NOERROR")
	}
}

// parseAnswers must skip the question and read only the requested type.
func TestParseAnswers(t *testing.T) {
	q, _ := buildQuery("example.com", 1)
	resp := make([]byte, 0, len(q)+16)
	resp = append(resp, q...)
	resp[2] = 0x81
	binary.BigEndian.PutUint16(resp[6:], 1)     // one answer
	resp = append(resp, 0xC0, 0x0C)             // pointer to question name
	resp = append(resp, 0x00, 0x01, 0x00, 0x01) // type A, class IN
	resp = append(resp, 0, 0, 1, 0x2C)          // TTL 300
	resp = append(resp, 0, 4)
	resp = append(resp, 93, 184, 216, 34)

	ans, err := parseAnswers(resp, "example.com", 1)
	if err != nil {
		t.Fatal(err)
	}
	if !ans.found || len(ans.a) != 1 {
		t.Fatalf("answers = %+v", ans)
	}
	if !ans.a[0].Equal(net.IPv4(93, 184, 216, 34)) {
		t.Errorf("address = %v, want 93.184.216.34", ans.a[0])
	}
	if ans.ttl != 300 {
		t.Errorf("ttl = %d, want 300", ans.ttl)
	}
}

// A record of a different type must be ignored, not misread as an address.
func TestParseAnswersIgnoresOtherTypes(t *testing.T) {
	q, _ := buildQuery("example.com", 1)
	resp := append([]byte(nil), q...)
	resp[2] = 0x81
	binary.BigEndian.PutUint16(resp[6:], 1)
	resp = append(resp, 0xC0, 0x0C, 0x00, 0x05, 0x00, 0x01) // type CNAME
	resp = append(resp, 0, 0, 1, 0x2C)
	resp = append(resp, 0, 0)

	ans, err := parseAnswers(resp, "example.com", 1)
	if err != nil {
		t.Fatal(err)
	}
	if ans.found {
		t.Errorf("a CNAME should not be read as an A record: %+v", ans)
	}
}

func TestCacheEviction(t *testing.T) {
	f := &dnsForwarder{
		cache:  map[string]dnsAnswer{},
		ttl:    time.Minute,
		expire: time.Now(),
	}
	f.cache["old"] = dnsAnswer{at: time.Now().Add(-2 * time.Minute), found: true}
	f.cache["new"] = dnsAnswer{at: time.Now(), found: true}

	f.expire = time.Time{} // force the sweep
	f.evictExpired()
	if _, ok := f.cache["old"]; ok {
		t.Error("expired entry was not evicted")
	}
	if _, ok := f.cache["new"]; !ok {
		t.Error("fresh entry was evicted")
	}
}

// A query the forwarder cannot parse a name out of must be answered with
// SERVFAIL, not silence. Silence makes the client's resolver treat this server
// as dead and try the next one, which is a leak.
func TestServFailIsAnswered(t *testing.T) {
	q, err := buildQuery("example.com", 1)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := buildServFail(q, "example.com", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(reply) < 12 {
		t.Fatalf("reply too short: %d bytes", len(reply))
	}
	if reply[2]&0x80 == 0 {
		t.Error("QR bit not set")
	}
	if rcode := reply[3] & 0x0F; rcode != 2 {
		t.Errorf("RCODE = %d, want 2 (SERVFAIL)", rcode)
	}
	if id := binary.BigEndian.Uint16(reply[0:2]); id != 0x1234 {
		t.Errorf("transaction id = %x, want 1234", id)
	}
}

// Record types other than A/AAAA must be forwarded, not dropped. A dropped MX
// query does not announce itself; the resolver just quietly tries the next
// nameserver, out of the tunnel.
func TestNonAddressTypesPassThrough(t *testing.T) {
	q, err := buildQuery("example.com", 15) // MX
	if err != nil {
		t.Fatal(err)
	}
	upstream := make([]byte, 0, 64)
	h := make([]byte, 12)
	binary.BigEndian.PutUint16(h[0:2], 0x1234) // buildQuery's id
	h[2] = 0x81
	h[3] = 0x80
	binary.BigEndian.PutUint16(h[4:6], 1)
	binary.BigEndian.PutUint16(h[6:8], 1) // one answer
	upstream = append(upstream, h...)
	upstream = appendQuestion(upstream, "example.com", 15)
	// Answer: pointer to question, type MX, class IN, TTL, then a short RDATA.
	upstream = append(upstream, 0xC0, 0x0C, 0, 15, 0, 1, 0, 0, 0, 60, 0, 6)
	upstream = append(upstream, []byte("mx.example")...)
	upstream = append(upstream, 0)

	ans := dnsAnswer{raw: upstream, found: true}
	reply, err := passthroughAnswer(q, "example.com", 15, ans)
	if err != nil {
		t.Fatal(err)
	}
	if n := binary.BigEndian.Uint16(reply[6:8]); n != 1 {
		t.Errorf("ANCOUNT = %d, want 1", n)
	}
	if reply[3]&0x0F != 0 {
		t.Errorf("RCODE = %d, want 0", reply[3]&0x0F)
	}
	if !bytes.Contains(reply, []byte("mx.example")) {
		t.Error("RDATA lost in passthrough")
	}
	// The question must come back under the client's id, or the reply is
	// discarded as a spoof.
	if id := binary.BigEndian.Uint16(reply[0:2]); id != 0x1234 {
		t.Errorf("id = %x, want 1234", id)
	}
}
