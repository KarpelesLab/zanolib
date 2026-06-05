package zanompc

import (
	"math/big"

	"filippo.io/edwards25519"
	"github.com/KarpelesLab/tss-lib/v2/frosttss"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// scalarFromBigInt converts a scalar in [0, L) (as used by tss-lib) into the
// filippo.io/edwards25519 scalar type used throughout zanolib.
func scalarFromBigInt(v *big.Int) (*edwards25519.Scalar, error) {
	var b [32]byte
	v.FillBytes(b[:]) // big-endian; v < L < 2^253 so it fits
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i] // -> little-endian
	}
	return new(edwards25519.Scalar).SetCanonicalBytes(b[:])
}

// CommitteeShareIDs returns the share identifiers of a signing committee in the
// given order; this is the basis for Lagrange interpolation across the subset.
func CommitteeShareIDs(committee []*frosttss.Key) []*big.Int {
	ks := make([]*big.Int, len(committee))
	for i, k := range committee {
		ks[i] = k.ShareID
	}
	return ks
}

// AdditiveShare returns this party's Lagrange-weighted additive share w_i for
// the committee identified by shareIDs (with this party at index i). Summed over
// the committee, the w_i reconstruct the group (spend) secret x — but the sum is
// only ever formed implicitly, in the exponent, never as a plaintext scalar.
func AdditiveShare(key *frosttss.Key, shareIDs []*big.Int, i int) (*edwards25519.Scalar, error) {
	wi := frosttss.PrepareForSigning(tss.Edwards(), i, len(shareIDs), key.Xi, shareIDs)
	return scalarFromBigInt(wi)
}

// PartialKeyImage returns this party's contribution w_i*base to a threshold key
// image. Summing every committee member's contribution (see CombinePoints)
// yields x*base, where x is the group spend secret and base is typically
// Hp(stealth_address). No party learns x or another party's share.
func PartialKeyImage(key *frosttss.Key, shareIDs []*big.Int, i int, base *edwards25519.Point) (*edwards25519.Point, error) {
	w, err := AdditiveShare(key, shareIDs, i)
	if err != nil {
		return nil, err
	}
	return new(edwards25519.Point).ScalarMult(w, base), nil
}

// CombinePoints sums partial points (partial key images, nonce commitments, …).
func CombinePoints(parts []*edwards25519.Point) *edwards25519.Point {
	sum := edwards25519.NewIdentityPoint()
	for _, p := range parts {
		sum.Add(sum, p)
	}
	return sum
}
