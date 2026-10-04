package wg

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
)

// Curve25519 (X25519) scalar multiplication, per RFC 7748. This is the key
// exchange WireGuard uses: a peer's public key is the scalar multiplication of
// the base point by its private key. We need it because the server issues the
// peer half of the tunnel in response to the public key we register.
//
// Uses math/big rather than a hand-rolled field so the ladder stays auditable
// against the RFC's reference pseudocode; it runs a handful of times per
// connect, so the constant-factor cost is irrelevant.

var curveP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))

// curveA24 is (A-2)/4 for Curve25519, constant 121665.
const curveA24 = 121665

// basePoint is the u-coordinate 9, the generator of the Montgomery curve.
var basePoint = [32]byte{9}

func fieldAdd(a, b *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Add(a, b), curveP)
}

func fieldSub(a, b *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Sub(a, b), curveP)
}

func fieldMul(a, b *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Mul(a, b), curveP)
}

func fieldInv(a *big.Int) *big.Int {
	// Fermat's little theorem: a^(p-2) mod p.
	e := new(big.Int).Sub(curveP, big.NewInt(2))
	return new(big.Int).Exp(a, e, curveP)
}

// cswap exchanges the two field elements when swap is 1, so the ladder can be
// written without a data-dependent branch.
func cswap(swap uint, x2, x3 *big.Int) (*big.Int, *big.Int) {
	if swap == 1 {
		return new(big.Int).Set(x3), new(big.Int).Set(x2)
	}
	return x2, x3
}

// decodeScalar clamps the scalar per RFC 7748 section 5: clear the low three
// bits, clear the top bit, set the second-highest.
func decodeScalar(k *[32]byte) *big.Int {
	s := *k
	s[0] &= 248
	s[31] &= 127
	s[31] |= 64
	return leInt(&s)
}

// leInt reads a 32-byte little-endian integer, masking the unused top bit.
func leInt(b *[32]byte) *big.Int {
	t := *b
	t[31] &= 127
	return new(big.Int).SetBytes(reverse32(&t))
}

func reverse32(b *[32]byte) []byte {
	out := make([]byte, 32)
	for i := 0; i < 32; i++ {
		out[i] = b[31-i]
	}
	return out
}

func intLE32(x *big.Int) [32]byte {
	var out [32]byte
	b := x.Bytes()
	for i, c := range b {
		out[len(b)-1-i] = c
	}
	return out
}

// x25519 computes the scalar multiplication scalar*point on Curve25519.
func x25519(scalar, point [32]byte) [32]byte {
	k := decodeScalar(&scalar)
	u := leInt(&point)

	x1 := new(big.Int).Set(u)
	x2 := big.NewInt(1)
	z2 := big.NewInt(0)
	x3 := new(big.Int).Set(u)
	z3 := big.NewInt(1)
	swap := uint(0)

	for t := 254; t >= 0; t-- {
		kt := uint(k.Bit(t))
		swap ^= kt
		x2, x3 = cswap(swap, x2, x3)
		z2, z3 = cswap(swap, z2, z3)
		swap = kt

		a := fieldAdd(x2, z2)
		aa := fieldMul(a, a)
		b := fieldSub(x2, z2)
		bb := fieldMul(b, b)
		e := fieldSub(aa, bb)
		c := fieldAdd(x3, z3)
		d := fieldSub(x3, z3)
		da := fieldMul(d, a)
		cb := fieldMul(c, b)

		sum := fieldAdd(da, cb)
		x3 = fieldMul(sum, sum)
		diff := fieldSub(da, cb)
		z3 = fieldMul(x1, fieldMul(diff, diff))

		x2 = fieldMul(aa, bb)
		z2 = fieldMul(e, fieldAdd(aa, fieldMul(big.NewInt(curveA24), e)))
	}
	x2, x3 = cswap(swap, x2, x3)
	z2, z3 = cswap(swap, z2, z3)

	res := fieldMul(x2, fieldInv(z2))

	return intLE32(res)
}

// KeyPair holds a WireGuard keypair. WireGuard encodes keys as 32 raw bytes
// in standard (not URL-safe) base64.
type KeyPair struct {
	Private string
	Public  string
}

// NewKeyPair draws 32 fresh random bytes and derives the matching public key.
func NewKeyPair() (*KeyPair, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return nil, fmt.Errorf("read random: %w", err)
	}
	return KeyPairFromPrivate(priv), nil
}

// KeyPairFromPrivate re-derives the public key for a stored private key, so a
// re-connect does not need a new key registered.
func KeyPairFromPrivate(priv [32]byte) *KeyPair {
	pub := x25519(priv, basePoint)
	return &KeyPair{
		Private: base64.StdEncoding.EncodeToString(priv[:]),
		Public:  base64.StdEncoding.EncodeToString(pub[:]),
	}
}

// ParseKey decodes a base64 WireGuard key back to raw bytes.
func ParseKey(s string) ([32]byte, error) {
	var out [32]byte
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("decode key: %w", err)
	}
	if len(b) != 32 {
		return out, fmt.Errorf("key is %d bytes, want 32", len(b))
	}
	copy(out[:], b)
	return out, nil
}
