package zanocrypto

import (
	"slices"

	"filippo.io/edwards25519"
	"github.com/KarpelesLab/zanolib/zanobase"
)

// DerivePublicKey derives a per-output public key from a key derivation,
// output index, and the recipient's base public spend key.
func DerivePublicKey(derivation []byte, outputIndex uint64, basePublic *edwards25519.Point) (*edwards25519.Point, error) {
	// derivation_to_scalar basically concats derivation and varint(outputIndex)
	scalar := HashToScalar(slices.Concat(derivation, zanobase.Varint(outputIndex).Bytes()))

	// Convert spend_public_key to an ExtendedGroupElement

	// point2 = scalar * G  (GeScalarMultBase)
	point2 := new(edwards25519.Point).ScalarBaseMult(scalar)

	// ephemeralPubPoint = spendPubPoint + point2
	ephemeralPubPoint := new(edwards25519.Point).Add(basePublic, point2)

	return ephemeralPubPoint, nil
}

// DeriveSecretKey derives a per-output secret key from a key derivation,
// output index, and the sender's base secret spend key.
func DeriveSecretKey(derivation []byte, outputIndex uint64, baseSecret *edwards25519.Scalar) (*edwards25519.Scalar, error) {
	// derivation_to_scalar basically concats derivation and varint(outputIndex)
	scalar := HashToScalar(slices.Concat(derivation, zanobase.Varint(outputIndex).Bytes()))

	// scalar + baseSecret
	return new(edwards25519.Scalar).Add(scalar, baseSecret), nil
}
