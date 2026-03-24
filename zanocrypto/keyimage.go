package zanocrypto

import (
	"filippo.io/edwards25519"
)

// ComputeKeyImage computes the key image I = spendPriv * HashToEC(spendPub)
// for the given spend key pair. Key images are used for double-spend prevention.
func ComputeKeyImage(spendPriv *edwards25519.Scalar, spendPub *edwards25519.Point) (*edwards25519.Point, error) {
	// hash_to_ec(pub, point);
	point, err := HashToEC(spendPub.Bytes())
	if err != nil {
		return nil, err
	}

	// ge_scalarmult(&point2, &sec, &point);
	return new(edwards25519.Point).ScalarMult(spendPriv, point), nil
}
