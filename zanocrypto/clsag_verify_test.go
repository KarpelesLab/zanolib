package zanocrypto

import (
	"crypto/rand"
	"testing"

	"filippo.io/edwards25519"
	"github.com/KarpelesLab/zanolib/zanobase"
)

// buildConsistentRing constructs a ring + pseudo-outs consistent with the given
// real secrets at secretIndex (mirrors the relations GenerateCLSAG_GGX checks).
func buildConsistentRing(t *testing.T, ringSize int, secretIndex uint64, s0, s1, s2 *edwards25519.Scalar) ([]CLSAG_GGXInputRef, *edwards25519.Point, *edwards25519.Point, *edwards25519.Point) {
	t.Helper()
	pseudoAC := new(edwards25519.Point).ScalarBaseMult(RandomScalar(rand.Reader))
	pseudoBAID := new(edwards25519.Point).ScalarBaseMult(RandomScalar(rand.Reader))

	ring := make([]CLSAG_GGXInputRef, ringSize)
	for i := range ring {
		ring[i] = CLSAG_GGXInputRef{
			StealthAddress:   new(edwards25519.Point).ScalarBaseMult(RandomScalar(rand.Reader)),
			AmountCommitment: new(edwards25519.Point).ScalarBaseMult(RandomScalar(rand.Reader)),
			BlindedAssetID:   new(edwards25519.Point).ScalarBaseMult(RandomScalar(rand.Reader)),
		}
	}
	// real member: stealth = s0*G; ac = 1/8*(s1*G + pseudoAC); baid = 1/8*(s2*X + pseudoBAID)
	ring[secretIndex].StealthAddress = new(edwards25519.Point).ScalarBaseMult(s0)
	acFull := new(edwards25519.Point).Add(new(edwards25519.Point).ScalarBaseMult(s1), pseudoAC)
	ring[secretIndex].AmountCommitment = new(edwards25519.Point).ScalarMult(Sc1div8, acFull)
	baidFull := new(edwards25519.Point).Add(new(edwards25519.Point).ScalarMult(s2, C_point_X), pseudoBAID)
	ring[secretIndex].BlindedAssetID = new(edwards25519.Point).ScalarMult(Sc1div8, baidFull)

	ki := new(edwards25519.Point).ScalarMult(s0, Hp(ring[secretIndex].StealthAddress.Bytes()))
	return ring, ki, pseudoAC, pseudoBAID
}

func TestVerifyCLSAG_GGX(t *testing.T) {
	const ringSize = 8
	const secretIndex = 3
	s0 := RandomScalar(rand.Reader)
	s1 := RandomScalar(rand.Reader)
	s2 := RandomScalar(rand.Reader)
	ring, ki, pAC, pBAID := buildConsistentRing(t, ringSize, secretIndex, s0, s1, s2)

	m := make([]byte, 32)
	for i := range m {
		m[i] = byte(i + 1)
	}
	other := make([]byte, 32)
	for i := range other {
		other[i] = byte(0xff - i)
	}
	sig, err := GenerateCLSAG_GGX(rand.Reader, m, ring, ki, pAC, pBAID, s0, s1, s2, secretIndex)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	ok, err := VerifyCLSAG_GGX(m, ring, ki, pAC, pBAID, sig)
	if err != nil || !ok {
		t.Fatalf("valid signature failed to verify: ok=%v err=%v", ok, err)
	}

	// tamper a response -> must fail
	bad := *sig
	bad.Rg = append([]*zanobase.Scalar(nil), sig.Rg...)
	bad.Rg[0] = &zanobase.Scalar{Scalar: RandomScalar(rand.Reader)}
	if ok, _ := VerifyCLSAG_GGX(m, ring, ki, pAC, pBAID, &bad); ok {
		t.Fatal("tampered signature verified")
	}
	// wrong message -> must fail
	if ok, _ := VerifyCLSAG_GGX(other, ring, ki, pAC, pBAID, sig); ok {
		t.Fatal("signature verified under wrong message")
	}
}
