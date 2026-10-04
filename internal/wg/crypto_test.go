package wg

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// RFC 7748 section 5.2 test vectors.
func TestX25519RFC7748(t *testing.T) {
	cases := []struct{ scalar, point, want string }{
		{
			"a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
			"e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
			"c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
		},
		{
			"4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
			"e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
			"95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
		},
	}
	for i, c := range cases {
		var s, p [32]byte
		sb, _ := hex.DecodeString(c.scalar)
		pb, _ := hex.DecodeString(c.point)
		copy(s[:], sb)
		copy(p[:], pb)
		got := x25519(s, p)
		if hex.EncodeToString(got[:]) != c.want {
			t.Errorf("case %d: got %s want %s", i, hex.EncodeToString(got[:]), c.want)
		}
	}
}

// The iterated form from RFC 7748 section 5.2. Per iteration: k becomes
// X25519(k, u) and u becomes the old k; the final answer is the last k.
func TestX25519RFC7748Iterated(t *testing.T) {
	kb, _ := hex.DecodeString("0900000000000000000000000000000000000000000000000000000000000000")
	ub, _ := hex.DecodeString("0900000000000000000000000000000000000000000000000000000000000000")
	var k, u [32]byte
	copy(k[:], kb)
	copy(u[:], ub)
	for i := 0; i < 1000; i++ {
		oldK := k
		k = x25519(k, u)
		u = oldK
	}
	want := "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"
	if hex.EncodeToString(k[:]) != want {
		t.Errorf("iterated: got %s want %s", hex.EncodeToString(k[:]), want)
	}
}

// A generated key must be 32 bytes and the public key must be the base point
// scalar multiplication of the private key.
func TestKeyPairRoundTrip(t *testing.T) {
	kp, err := NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := ParseKey(kp.Private)
	if err != nil {
		t.Fatal(err)
	}
	derived := x25519(priv, basePoint)
	pub, err := base64.StdEncoding.DecodeString(kp.Public)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub, derived[:]) {
		t.Errorf("public key does not match re-derivation")
	}
	if len(pub) != 32 {
		t.Errorf("public key is %d bytes", len(pub))
	}
}

// Re-deriving from a stored private key must be deterministic, so reconnecting
// reuses the key the server already knows.
func TestKeyPairDeterministic(t *testing.T) {
	kp, err := NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := ParseKey(kp.Private)
	again := KeyPairFromPrivate(priv)
	if again.Public != kp.Public || again.Private != kp.Private {
		t.Errorf("key derivation is not deterministic")
	}
}
