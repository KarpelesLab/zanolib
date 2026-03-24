package zanocrypto

import (
	"hash"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/sha3"
)

// HashHelper accumulates data into a Keccak-256 hash, providing methods
// to add points, scalars, and raw bytes, and to extract the result as a
// scalar or raw hash.
type HashHelper struct {
	h hash.Hash
}

type byter interface {
	Bytes() []byte
}

// NewHashHelper creates a new [HashHelper] backed by Keccak-256.
func NewHashHelper() *HashHelper {
	return &HashHelper{h: sha3.NewLegacyKeccak256()}
}

// AddBytes writes exactly 32 bytes to the hash. Panics if len(b) != 32.
func (c *HashHelper) AddBytes(b []byte) {
	if len(b) != 32 {
		panic("addbytes expect 32 bytes")
	}
	c.h.Write(b)
}

// AddBytesModL interprets b as a 32-byte value, reduces it modulo L
// (the group order), and adds the resulting scalar to the hash.
func (c *HashHelper) AddBytesModL(b []byte) {
	if len(b) != 32 {
		panic("addbytes expect 32 bytes")
	}
	var wide [64]byte
	copy(wide[:], b)
	sc, _ := new(edwards25519.Scalar).SetUniformBytes(wide[:])
	c.Add(sc)
}

// Add writes the byte representation of each value to the hash.
func (c *HashHelper) Add(v ...byter) {
	for _, s := range v {
		c.h.Write(s.Bytes())
	}
}

// CalcHash finalizes the hash, resets the state, and returns the result
// as a scalar (reduced modulo L).
func (c *HashHelper) CalcHash() *edwards25519.Scalar {
	res := c.h.Sum(nil)
	c.h.Reset()
	var buf64 [64]byte
	copy(buf64[:], res)
	pt, _ := new(edwards25519.Scalar).SetUniformBytes(buf64[:])
	return pt
}

// CalcHashKeep is like [HashHelper.CalcHash] but does not reset the state,
// allowing further data to be added.
func (c *HashHelper) CalcHashKeep() *edwards25519.Scalar {
	res := c.h.Sum(nil)
	var buf64 [64]byte
	copy(buf64[:], res)
	pt, _ := new(edwards25519.Scalar).SetUniformBytes(buf64[:])
	return pt
}

// CalcRawHash finalizes the hash, resets the state, and returns the raw
// 32-byte hash (without scalar reduction).
func (c *HashHelper) CalcRawHash() []byte {
	res := c.h.Sum(nil)
	c.h.Reset()
	return res
}

func bter[T []S, S byter](v T) []byter {
	res := make([]byter, len(v))
	for n, a := range v {
		res[n] = a
	}
	return res
}
