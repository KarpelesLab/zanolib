package zanompc

import (
	"fmt"

	"filippo.io/edwards25519"
	"github.com/KarpelesLab/zanolib/zanocrypto"
)

// Domain-separation tags for the deterministic threshold view key. The base
// point is bound to the wallet's spend public key, and both the point and the
// final scalar are tagged so the derived value can never collide with — or be
// linked to — a real on-chain key image (whose base is Hp(stealth_address),
// with no prefix).
var (
	viewKeyBaseDomain   = []byte("ZANO_THRESHOLD_VIEWKEY\x00")
	viewKeySecretDomain = []byte("ZANO_THRESHOLD_VIEWKEY_SECRET\x00")
)

// viewKeyMsg carries one party's contribution w_i*P to the deterministic view
// key derivation.
type viewKeyMsg struct {
	Partial []byte `json:"partial"` // w_i * P
}

// ViewKeyBase returns the fixed base point P = Hp("ZANO_THRESHOLD_VIEWKEY\0" ||
// spendPub) used to derive the deterministic threshold view secret. It is a
// pure function of the group spend public key, so every committee member
// computes the same P.
func ViewKeyBase(spendPub *edwards25519.Point) *edwards25519.Point {
	return zanocrypto.Hp(append(append([]byte{}, viewKeyBaseDomain...), spendPub.Bytes()...))
}

// DeriveViewSecret derives the wallet's view secret key deterministically from
// the shared spend secret x, without anyone reconstructing x. It computes the
// "key image" V = x*P of the fixed base point P = ViewKeyBase(spendPub) — a
// deterministic PRF on x — by summing every party's partial w_i*P over the
// broker, then hashes V to a scalar (the same unclamped Keccak-to-scalar
// convention Zano uses for view keys):
//
//	view_secret = HashToScalar("ZANO_THRESHOLD_VIEWKEY_SECRET\0" || V)
//
// The result is identical on every committee member and reproducible from the
// same key shares, so a threshold wallet has a stable view key (and thus a
// stable address) without a random value or out-of-band agreement. The
// corresponding view public key is view_secret*G.
//
// Call this once per signer; it uses its own broker topic and does not touch
// the KeyImage/SignCLSAG input pairing.
func (s *ThresholdInputSigner) DeriveViewSecret() (*edwards25519.Scalar, error) {
	P := ViewKeyBase(s.spendPub)

	myPartial, err := PartialKeyImage(s.subset, s.subset.Ks, s.params.PartyID().Index, P)
	if err != nil {
		return nil, err
	}

	collected, err := exchange(s.ctx, s.params, "zano:viewkey", &viewKeyMsg{Partial: myPartial.Bytes()})
	if err != nil {
		return nil, err
	}

	partials := make([]*edwards25519.Point, len(collected))
	for i, m := range collected {
		if partials[i], err = pt(m.Partial); err != nil {
			return nil, fmt.Errorf("zanompc: bad view-key partial from party %d: %w", i, err)
		}
	}

	// V = sum_j(w_j*P) = x*P
	V := CombinePoints(partials)

	return zanocrypto.HashToScalar(append(append([]byte{}, viewKeySecretDomain...), V.Bytes()...)), nil
}
