package zanocrypto

import (
	"crypto/rand"
	"crypto/sha512"
	"io"

	"filippo.io/edwards25519"
)

// GenerateKeyScalar generates a random Ed25519 private key scalar using
// crypto/rand as the entropy source.
func GenerateKeyScalar() *edwards25519.Scalar {
	seed := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		panic(err)
	}

	h := sha512.New()
	h.Write(seed)
	digest := h.Sum(nil)

	res, err := new(edwards25519.Scalar).SetBytesWithClamping(digest[:32])
	if err != nil {
		panic(err)
	}
	return res
}

// PubFromPriv derives the public key point from a private scalar: pub = priv * G.
func PubFromPriv(priv *edwards25519.Scalar) *edwards25519.Point {
	return new(edwards25519.Point).ScalarBaseMult(priv)
}
