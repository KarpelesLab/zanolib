package zanocrypto

import (
	"fmt"
	"io"

	"filippo.io/edwards25519"
)

// RandomScalar generates a random scalar by reading 64 bytes from the
// provided random source and reducing them modulo the group order L.
func RandomScalar(rand io.Reader) *edwards25519.Scalar {
	var buf [64]byte
	_, err := io.ReadFull(rand, buf[:])
	if err != nil {
		panic(fmt.Errorf("failed to read from random source: %w", err))
	}

	return must(new(edwards25519.Scalar).SetUniformBytes(buf[:]))
}
