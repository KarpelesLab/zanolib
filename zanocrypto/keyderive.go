package zanocrypto

import (
	"encoding/binary"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/blake2b"
)

// GenerateKeyDerivation computes an ECDH key derivation: 8 * secKey * pubKey.
// The multiplication by 8 ensures the result is in the prime-order subgroup.
func GenerateKeyDerivation(pubKey *edwards25519.Point, secKey *edwards25519.Scalar) (*edwards25519.Point, error) {
	p := new(edwards25519.Point).ScalarMult(secKey, pubKey)

	// Multiply the result by 8 (ge_mul8). The usual approach is to double 3x.
	p = p.Add(p, p)
	p = p.Add(p, p)
	p = p.Add(p, p)

	return p, nil
}

// DerivationHint computes a 16-bit hint from a key derivation by hashing it
// with BLAKE2b-256 and XOR-folding the result.
func DerivationHint(derivation *edwards25519.Point) uint16 {
	// Compute 32-byte blake2b hash
	hash := blake2b.Sum256(derivation.Bytes())

	// Interpret the hash as an array of 16 uint16 values in little-endian order,
	// XOR them all together, and return the result.
	var result uint16 = binary.LittleEndian.Uint16(hash[0:2])
	for i := 1; i < 16; i++ {
		result ^= binary.LittleEndian.Uint16(hash[i*2 : (i+1)*2])
	}

	return result
}
