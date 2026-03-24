package zanocrypto

import (
	"encoding/binary"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
)

// FeToBytes marshals a field element h (in radix-2^25.5 representation) to 32 bytes s.
// Preconditions:
//
//	|h| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
//
// Write p=2^255-19; q=floor(h/p).
// Basic claim: q = floor(2^(-255)(h + 19 2^(-25)h9 + 2^(-1))).
//
// Proof:
//
//	Have |h|<=p so |q|<=1 so |19^2 2^(-255) q|<1/4.
//	Also have |h-2^230 h9|<2^230 so |19 2^(-255)(h-2^230 h9)|<1/4.
//
//	Write y=2^(-1)-19^2 2^(-255)q-19 2^(-255)(h-2^230 h9).
//	Then 0<y<1.
//
//	Write r=h-pq.
//	Have 0<=r<=p-1=2^255-20.
//	Thus 0<=r+19(2^-255)r<r+19(2^-255)2^255<=2^255-1.
//
//	Write x=r+19(2^-255)r+y.
//	Then 0<x<2^255 so floor(2^(-255)x) = 0 so floor(q+2^(-255)x) = q.
//
//	Have q+2^(-255)x = 2^(-255)(h + 19 2^(-25) h9 + 2^(-1))
//	so floor(2^(-255)(h + 19 2^(-25) h9 + 2^(-1))) = q.
func FeToBytes[T ~int32 | ~int64](s *[32]byte, h *[10]T) {
	var carry [10]T

	q := (19*h[9] + (1 << 24)) >> 25
	q = (h[0] + q) >> 26
	q = (h[1] + q) >> 25
	q = (h[2] + q) >> 26
	q = (h[3] + q) >> 25
	q = (h[4] + q) >> 26
	q = (h[5] + q) >> 25
	q = (h[6] + q) >> 26
	q = (h[7] + q) >> 25
	q = (h[8] + q) >> 26
	q = (h[9] + q) >> 25

	// Goal: Output h-(2^255-19)q, which is between 0 and 2^255-20.
	h[0] += 19 * q
	// Goal: Output h-2^255 q, which is between 0 and 2^255-20.

	carry[0] = h[0] >> 26
	h[1] += carry[0]
	h[0] -= carry[0] << 26
	carry[1] = h[1] >> 25
	h[2] += carry[1]
	h[1] -= carry[1] << 25
	carry[2] = h[2] >> 26
	h[3] += carry[2]
	h[2] -= carry[2] << 26
	carry[3] = h[3] >> 25
	h[4] += carry[3]
	h[3] -= carry[3] << 25
	carry[4] = h[4] >> 26
	h[5] += carry[4]
	h[4] -= carry[4] << 26
	carry[5] = h[5] >> 25
	h[6] += carry[5]
	h[5] -= carry[5] << 25
	carry[6] = h[6] >> 26
	h[7] += carry[6]
	h[6] -= carry[6] << 26
	carry[7] = h[7] >> 25
	h[8] += carry[7]
	h[7] -= carry[7] << 25
	carry[8] = h[8] >> 26
	h[9] += carry[8]
	h[8] -= carry[8] << 26
	carry[9] = h[9] >> 25
	h[9] -= carry[9] << 25
	// h10 = carry9

	// Goal: Output h[0]+...+2^255 h10-2^255 q, which is between 0 and 2^255-20.
	// Have h[0]+...+2^230 h[9] between 0 and 2^255-1;
	// evidently 2^255 h10-2^255 q = 0.
	// Goal: Output h[0]+...+2^230 h[9].

	s[0] = byte(h[0] >> 0)
	s[1] = byte(h[0] >> 8)
	s[2] = byte(h[0] >> 16)
	s[3] = byte((h[0] >> 24) | (h[1] << 2))
	s[4] = byte(h[1] >> 6)
	s[5] = byte(h[1] >> 14)
	s[6] = byte((h[1] >> 22) | (h[2] << 3))
	s[7] = byte(h[2] >> 5)
	s[8] = byte(h[2] >> 13)
	s[9] = byte((h[2] >> 21) | (h[3] << 5))
	s[10] = byte(h[3] >> 3)
	s[11] = byte(h[3] >> 11)
	s[12] = byte((h[3] >> 19) | (h[4] << 6))
	s[13] = byte(h[4] >> 2)
	s[14] = byte(h[4] >> 10)
	s[15] = byte(h[4] >> 18)
	s[16] = byte(h[5] >> 0)
	s[17] = byte(h[5] >> 8)
	s[18] = byte(h[5] >> 16)
	s[19] = byte((h[5] >> 24) | (h[6] << 1))
	s[20] = byte(h[6] >> 7)
	s[21] = byte(h[6] >> 15)
	s[22] = byte((h[6] >> 23) | (h[7] << 3))
	s[23] = byte(h[7] >> 5)
	s[24] = byte(h[7] >> 13)
	s[25] = byte((h[7] >> 21) | (h[8] << 4))
	s[26] = byte(h[8] >> 4)
	s[27] = byte(h[8] >> 12)
	s[28] = byte((h[8] >> 20) | (h[9] << 6))
	s[29] = byte(h[9] >> 2)
	s[30] = byte(h[9] >> 10)
	s[31] = byte(h[9] >> 18)
}

// FieldFromInt10 creates a field.Element from a 10-limb radix-2^25.5 representation.
func FieldFromInt10[T ~int32 | ~int64](f [10]T) (*field.Element, error) {
	fe := new(field.Element)
	var b [32]byte
	FeToBytes(&b, &f)
	return fe.SetBytes(b[:])
}

// ScalarInt converts a uint64 value to an Edwards25519 scalar.
func ScalarInt(v uint64) *edwards25519.Scalar {
	var b [32]byte
	binary.LittleEndian.PutUint64(b[:8], v)
	r, _ := new(edwards25519.Scalar).SetCanonicalBytes(b[:]) // because b < 2^64 this should never return an error
	return r
}

// FeDivPowM1 computes u = z / y * (z / y)^((p-5)/8) in the field GF(2^255 - 19),
// following the "ref10" formula:
//
//	t1 = 1 / y
//	t0 = z * t1                 // t0 = z / y
//	t0 = t0^((2^255) - 21)      // Pow22523(t0)
//	t0 = t0 * z                 // multiply by z
//	u = t0 * t1                 // multiply by (1 / y)
//
// Note: Pow22523 implements raising the argument to the power (2^255 - 21),
// which is used in various places (e.g. sqrt checks, ratio calculations)
// in the Ed25519/Curve25519 reference code.
func FeDivPowM1(u, z, y *field.Element) *field.Element {
	var t0, t1 field.Element

	// t1 = 1 / y
	t1.Invert(y)

	// t0 = z / y
	t0.Multiply(z, &t1)

	// t0 = (z / y) ^ (2^255 - 21)
	t0.Pow22523(&t0)

	// t0 = t0 * z
	t0.Multiply(&t0, z)

	// u = t0 * (1 / y) = z / y * (z / y)^((p-5)/8)
	u.Multiply(&t0, &t1)

	return u
}
