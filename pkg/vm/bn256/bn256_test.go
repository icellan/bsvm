package bn256

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"
)

func TestG1ScalarBaseMult(t *testing.T) {
	// g1 * 1 should produce the generator point.
	g := new(G1).ScalarBaseMult(big.NewInt(1))
	data := g.Marshal()
	if len(data) != 64 {
		t.Fatalf("expected 64-byte marshal, got %d", len(data))
	}

	// The result should not be the point at infinity (all zeros).
	zero := make([]byte, 64)
	if bytes.Equal(data, zero) {
		t.Error("g1 * 1 should not be the point at infinity")
	}
}

func TestG1Add(t *testing.T) {
	// g + g == g * 2
	g1a := new(G1).ScalarBaseMult(big.NewInt(1))
	g1b := new(G1).ScalarBaseMult(big.NewInt(1))
	sum := new(G1).Add(g1a, g1b)

	doubled := new(G1).ScalarBaseMult(big.NewInt(2))

	if !bytes.Equal(sum.Marshal(), doubled.Marshal()) {
		t.Error("g + g should equal g * 2")
	}
}

func TestG1ScalarMult(t *testing.T) {
	// g * a * b == g * (a*b)
	a := big.NewInt(123456789)
	b := big.NewInt(987654321)
	ab := new(big.Int).Mul(a, b)
	ab.Mod(ab, Order)

	ga := new(G1).ScalarBaseMult(a)
	gab := new(G1).ScalarMult(ga, b)

	direct := new(G1).ScalarBaseMult(ab)

	if !bytes.Equal(gab.Marshal(), direct.Marshal()) {
		t.Error("g*a*b should equal g*(a*b)")
	}
}

func TestG1MarshalUnmarshal(t *testing.T) {
	k, g, err := RandomG1(rand.Reader)
	if err != nil {
		t.Fatalf("RandomG1 failed: %v", err)
	}
	if k.Sign() == 0 {
		t.Fatal("random scalar should be non-zero")
	}

	data := g.Marshal()
	g2 := new(G1)
	rest, err := g2.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if len(rest) != 0 {
		t.Errorf("expected no remaining bytes, got %d", len(rest))
	}

	if !bytes.Equal(g.Marshal(), g2.Marshal()) {
		t.Error("marshal-unmarshal roundtrip failed")
	}
}

func TestG2ScalarBaseMult(t *testing.T) {
	g := new(G2).ScalarBaseMult(big.NewInt(1))
	data := g.Marshal()
	if len(data) != 128 {
		t.Fatalf("expected 128-byte marshal for G2, got %d", len(data))
	}

	zero := make([]byte, 128)
	if bytes.Equal(data, zero) {
		t.Error("g2 * 1 should not be the point at infinity")
	}
}

func TestG2MarshalUnmarshal(t *testing.T) {
	_, g, err := RandomG2(rand.Reader)
	if err != nil {
		t.Fatalf("RandomG2 failed: %v", err)
	}

	data := g.Marshal()
	g2 := new(G2)
	rest, err := g2.Unmarshal(data)
	if err != nil {
		t.Fatalf("G2 Unmarshal failed: %v", err)
	}
	if len(rest) != 0 {
		t.Errorf("expected no remaining bytes, got %d", len(rest))
	}

	if !bytes.Equal(g.Marshal(), g2.Marshal()) {
		t.Error("G2 marshal-unmarshal roundtrip failed")
	}
}

func TestPairBilinearity(t *testing.T) {
	// Bilinearity check: e(g1*a, g2*b) == e(g1, g2)^(a*b)
	a := big.NewInt(42)
	b := big.NewInt(73)

	g1a := new(G1).ScalarBaseMult(a)
	g2b := new(G2).ScalarBaseMult(b)

	lhs := Pair(g1a, g2b)

	g1 := new(G1).ScalarBaseMult(big.NewInt(1))
	g2 := new(G2).ScalarBaseMult(big.NewInt(1))
	base := Pair(g1, g2)

	ab := new(big.Int).Mul(a, b)
	rhs := new(GT).ScalarMult(base, ab)

	if !bytes.Equal(lhs.Marshal(), rhs.Marshal()) {
		t.Error("pairing bilinearity check failed: e(g1*a, g2*b) != e(g1,g2)^(a*b)")
	}
}

func TestPairingCheck(t *testing.T) {
	// PairingCheck verifies: product of e(a[i], b[i]) == 1
	// Use the identity: e(g1*k, g2) * e(g1*(-k), g2) == 1
	k := big.NewInt(99)
	negK := new(big.Int).Neg(k)
	negK.Mod(negK, Order)

	g1k := new(G1).ScalarBaseMult(k)
	g1negK := new(G1).ScalarBaseMult(negK)
	g2 := new(G2).ScalarBaseMult(big.NewInt(1))

	ok := PairingCheck([]*G1{g1k, g1negK}, []*G2{g2, g2})
	if !ok {
		t.Error("PairingCheck should return true for e(g1*k, g2) * e(g1*(-k), g2)")
	}

	// Negative test: non-trivial pairing should not check.
	g1one := new(G1).ScalarBaseMult(big.NewInt(1))
	g1two := new(G1).ScalarBaseMult(big.NewInt(2))
	bad := PairingCheck([]*G1{g1one, g1two}, []*G2{g2, g2})
	if bad {
		t.Error("PairingCheck should return false for non-cancelling pairs")
	}
}

func TestG1Neg(t *testing.T) {
	g := new(G1).ScalarBaseMult(big.NewInt(7))
	neg := new(G1).Neg(g)
	sum := new(G1).Add(g, neg)

	// g + (-g) should be the point at infinity.
	data := sum.Marshal()
	zero := make([]byte, 64)
	if !bytes.Equal(data, zero) {
		t.Error("g + (-g) should be the point at infinity")
	}
}
