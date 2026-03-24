package zanobase

import (
	"encoding/hex"
	"encoding/json"
	"io"

	"filippo.io/edwards25519"
)

// Value256 is a fixed 32-byte value used for hashes, keys, and other
// 256-bit identifiers throughout the Zano protocol.
type Value256 [32]byte

// ReadFrom reads exactly 32 bytes from r into v.
func (v *Value256) ReadFrom(r io.Reader) (int64, error) {
	n, err := io.ReadFull(r, v[:])
	return int64(n), err
}

// Bytes returns the value as a byte slice.
func (v Value256) Bytes() []byte {
	return v[:]
}

// String returns the hex-encoded representation of the value.
func (v Value256) String() string {
	return hex.EncodeToString(v[:])
}

// MarshalJSON encodes the value as a hex-encoded JSON string.
func (v Value256) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.String())
}

// IsZero returns true if all 32 bytes are zero.
func (v Value256) IsZero() bool {
	var t byte
	for _, b := range v {
		t |= b
	}
	return t == 0
}

// B32 returns the value as a [32]byte array.
func (v Value256) B32() [32]byte {
	return [32]byte(v)
}

// PB32 returns a pointer to the value as a *[32]byte.
func (v *Value256) PB32() *[32]byte {
	return (*[32]byte)(v)
}

// ToPoint attempts to decode the value as a compressed Edwards25519 point.
// Returns nil if the bytes do not represent a valid point.
func (v *Value256) ToPoint() *edwards25519.Point {
	p, err := new(edwards25519.Point).SetBytes(v[:])
	if err != nil {
		return nil
	}
	return p
}
