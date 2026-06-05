package zanompc_test

import (
	"crypto/rand"
	"testing"

	"filippo.io/edwards25519"
	"github.com/KarpelesLab/tss-lib/v2/frosttss"
	"github.com/KarpelesLab/zanolib/zanobase"
	"github.com/KarpelesLab/zanolib/zanocrypto"
	"github.com/KarpelesLab/zanolib/zanompc"
)

// thresholdSign drives the full two-round threshold CLSAG protocol across the
// committee and returns the signature + key image.
func thresholdSign(t *testing.T, committee []*frosttss.Key, coord *zanompc.ClsagCoordinator) (*zanobase.CLSAG_Sig, *edwards25519.Point) {
	t.Helper()
	ks := zanompc.CommitteeShareIDs(committee)
	parties := make([]*zanompc.ClsagParty, len(committee))
	for i, k := range committee {
		p, err := zanompc.NewClsagParty(k, ks, i, nil, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		parties[i] = p
	}

	kiBase := coord.KiBase()
	pkis := make([]*edwards25519.Point, len(parties))
	cgs := make([]*edwards25519.Point, len(parties))
	cks := make([]*edwards25519.Point, len(parties))
	for i, p := range parties {
		pkis[i], cgs[i], cks[i] = p.Round1(kiBase)
	}
	cPrev, aggCoeff0, err := coord.Phase1(pkis, cgs, cks)
	if err != nil {
		t.Fatalf("Phase1: %v", err)
	}
	resps := make([]*edwards25519.Scalar, len(parties))
	for i, p := range parties {
		resps[i] = p.Round2(cPrev, aggCoeff0)
	}
	sig, ki, err := coord.Phase2(resps)
	if err != nil {
		t.Fatalf("Phase2: %v", err)
	}
	return sig, ki
}

// TestThresholdCLSAG verifies a threshold-produced CLSAG-GGX signature with the
// independent verifier, for the full committee and a t+1 subset, and checks the
// key image is committee-independent.
func TestThresholdCLSAG(t *testing.T) {
	const n, threshold = 3, 1
	keys := runDKG(t, n, threshold)
	spendPub, err := zanompc.SpendPublicKey(keys[0].GroupPublicKey)
	if err != nil {
		t.Fatal(err)
	}

	const ringSize = 8
	const secretIndex = 5

	// hi is the public per-output scalar; secret0Xp = hi + x.
	hi := zanocrypto.RandomScalar(rand.Reader)
	secret1F := zanocrypto.RandomScalar(rand.Reader)
	secret2T := zanocrypto.RandomScalar(rand.Reader)

	// Build a ring consistent with the real secrets (real stealth = hi*G + spendPub).
	pAC := new(edwards25519.Point).ScalarBaseMult(zanocrypto.RandomScalar(rand.Reader))
	pBAID := new(edwards25519.Point).ScalarBaseMult(zanocrypto.RandomScalar(rand.Reader))
	ring := make([]zanocrypto.CLSAG_GGXInputRef, ringSize)
	for i := range ring {
		ring[i] = zanocrypto.CLSAG_GGXInputRef{
			StealthAddress:   new(edwards25519.Point).ScalarBaseMult(zanocrypto.RandomScalar(rand.Reader)),
			AmountCommitment: new(edwards25519.Point).ScalarBaseMult(zanocrypto.RandomScalar(rand.Reader)),
			BlindedAssetID:   new(edwards25519.Point).ScalarBaseMult(zanocrypto.RandomScalar(rand.Reader)),
		}
	}
	ring[secretIndex].StealthAddress = new(edwards25519.Point).Add(new(edwards25519.Point).ScalarBaseMult(hi), spendPub)
	acFull := new(edwards25519.Point).Add(new(edwards25519.Point).ScalarBaseMult(secret1F), pAC)
	ring[secretIndex].AmountCommitment = new(edwards25519.Point).ScalarMult(zanocrypto.Sc1div8, acFull)
	baidFull := new(edwards25519.Point).Add(new(edwards25519.Point).ScalarMult(secret2T, zanocrypto.C_point_X), pBAID)
	ring[secretIndex].BlindedAssetID = new(edwards25519.Point).ScalarMult(zanocrypto.Sc1div8, baidFull)

	m := make([]byte, 32)
	for i := range m {
		m[i] = byte(7*i + 1)
	}

	var firstKI *edwards25519.Point
	for _, committee := range [][]*frosttss.Key{keys, {keys[0], keys[1]}} {
		coord := zanompc.NewClsagCoordinator(rand.Reader, m, ring, pAC, pBAID, secret1F, secret2T, hi, spendPub, secretIndex)
		sig, ki := thresholdSign(t, committee, coord)

		ok, err := zanocrypto.VerifyCLSAG_GGX(m, ring, ki, pAC, pBAID, sig)
		if err != nil || !ok {
			t.Fatalf("committee %d: threshold signature failed to verify: ok=%v err=%v", len(committee), ok, err)
		}
		if firstKI == nil {
			firstKI = ki
			t.Logf("threshold CLSAG verified; key image %x", ki.Bytes()[:8])
		} else if firstKI.Equal(ki) != 1 {
			t.Fatalf("committee %d: key image differs from full committee", len(committee))
		}
	}
}
