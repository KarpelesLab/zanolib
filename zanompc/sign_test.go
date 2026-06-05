package zanompc_test

import (
	"testing"

	"filippo.io/edwards25519"
	"github.com/KarpelesLab/tss-lib/v2/frosttss"
	"github.com/KarpelesLab/zanolib/zanocrypto"
	"github.com/KarpelesLab/zanolib/zanompc"
)

// reconstructSecret sums the committee additive shares — TEST ONLY, to obtain a
// reference value. The real protocol never forms this scalar.
func reconstructSecret(t *testing.T, committee []*frosttss.Key) *edwards25519.Scalar {
	t.Helper()
	ks := zanompc.CommitteeShareIDs(committee)
	sum := new(edwards25519.Scalar)
	for i, k := range committee {
		w, err := zanompc.AdditiveShare(k, ks, i)
		if err != nil {
			t.Fatal(err)
		}
		sum.Add(sum, w)
	}
	return sum
}

// TestThresholdKeyImage verifies that partial key images from a signing
// committee combine to x*base, where x is the group spend secret — for both the
// full set and a t+1 subset, and that the implied secret matches the group key.
func TestThresholdKeyImage(t *testing.T) {
	const n, threshold = 3, 1 // 2-of-3
	keys := runDKG(t, n, threshold)

	spendPub, err := zanompc.SpendPublicKey(keys[0].GroupPublicKey)
	if err != nil {
		t.Fatal(err)
	}

	// base = Hp(some bytes), like a real key-image base Hp(stealth_address).
	base, err := zanocrypto.HashToEC([]byte("threshold key image base"))
	if err != nil {
		t.Fatal(err)
	}

	for _, committee := range [][]*frosttss.Key{
		keys,               // full 3-of-3
		{keys[0], keys[2]}, // 2-of-3 subset
	} {
		ks := zanompc.CommitteeShareIDs(committee)

		// Each party independently produces its partial (from its own share only).
		partG := make([]*edwards25519.Point, len(committee)) // base = G
		partB := make([]*edwards25519.Point, len(committee)) // base = Hp(...)
		for i, k := range committee {
			pg, err := zanompc.PartialKeyImage(k, ks, i, edwards25519.NewGeneratorPoint())
			if err != nil {
				t.Fatal(err)
			}
			pb, err := zanompc.PartialKeyImage(k, ks, i, base)
			if err != nil {
				t.Fatal(err)
			}
			partG[i], partB[i] = pg, pb
		}

		// Sum of w_i*G must equal the group (spend) public key.
		gotPub := zanompc.CombinePoints(partG)
		if gotPub.Equal(spendPub) != 1 {
			t.Fatalf("committee size %d: reconstructed spend pub mismatch", len(committee))
		}

		// Threshold key image must equal x*base (x reconstructed for reference).
		x := reconstructSecret(t, committee)
		wantKI := new(edwards25519.Point).ScalarMult(x, base)
		gotKI := zanompc.CombinePoints(partB)
		if gotKI.Equal(wantKI) != 1 {
			t.Fatalf("committee size %d: threshold key image mismatch", len(committee))
		}
		t.Logf("committee size %d: key image OK (%x)", len(committee), gotKI.Bytes()[:8])
	}
}
