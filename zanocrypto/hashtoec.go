package zanocrypto

import (
	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
	"golang.org/x/crypto/sha3"
)

// HashToEC hashes the input bytes to an Edwards25519 curve point using
// Keccak-256 followed by the Monero/Zano ge_fromfe_frombytes_vartime mapping,
// then multiplies by 8 to ensure the result is in the prime-order subgroup.
func HashToEC(pubBytes []byte) (*edwards25519.Point, error) {
	hash := sha3.NewLegacyKeccak256()
	hash.Write(pubBytes)
	hashed := hash.Sum(nil)

	// 2) Map those 32 bytes to a curve point: ge_fromfe_frombytes_vartime
	point, err := geFromFeFromBytesVartime(hashed)
	if err != nil {
		return nil, err
	}

	// 3) Multiply by 8 => three doublings
	return point.ScalarMult(ScalarInt(8), point), nil
}

func geFromFeFromBytesVartime(s []byte) (*edwards25519.Point, error) {
	h0 := load4(s[0:4])
	h1 := load3(s[4:7]) << 6
	h2 := load3(s[7:10]) << 5
	h3 := load3(s[10:13]) << 3
	h4 := load3(s[13:16]) << 2
	h5 := load4(s[16:20])
	h6 := load3(s[20:23]) << 7
	h7 := load3(s[23:26]) << 5
	h8 := load3(s[26:29]) << 4
	h9 := load3(s[29:32]) << 2

	var carry0, carry1, carry2, carry3, carry4 int64
	var carry5, carry6, carry7, carry8, carry9 int64

	// Do the carry chain
	carry9 = (h9 + (1 << 24)) >> 25
	h0 += carry9 * 19
	h9 -= carry9 << 25

	carry1 = (h1 + (1 << 24)) >> 25
	h2 += carry1
	h1 -= carry1 << 25

	carry3 = (h3 + (1 << 24)) >> 25
	h4 += carry3
	h3 -= carry3 << 25

	carry5 = (h5 + (1 << 24)) >> 25
	h6 += carry5
	h5 -= carry5 << 25

	carry7 = (h7 + (1 << 24)) >> 25
	h8 += carry7
	h7 -= carry7 << 25

	carry0 = (h0 + (1 << 25)) >> 26
	h1 += carry0
	h0 -= carry0 << 26

	carry2 = (h2 + (1 << 25)) >> 26
	h3 += carry2
	h2 -= carry2 << 26

	carry4 = (h4 + (1 << 25)) >> 26
	h5 += carry4
	h4 -= carry4 << 26

	carry6 = (h6 + (1 << 25)) >> 26
	h7 += carry6
	h6 -= carry6 << 26

	carry8 = (h8 + (1 << 25)) >> 26
	h9 += carry8
	h8 -= carry8 << 26

	u, err := FieldFromInt10([10]int64{h0, h1, h2, h3, h4, h5, h6, h7, h8, h9})
	if err != nil {
		panic(err)
	}

	// End fe_frombytes.c
	var v, w, x, y, z *field.Element
	var sign int

	// v = 2 * u^2
	v = new(field.Element).Square(u)
	v = v.Mult32(v, 2)

	// w = 1
	w = new(field.Element).One()

	// w = 2*u^2 + 1
	w = new(field.Element).Add(v, w)

	// x = w^2
	x = new(field.Element).Square(w)

	// y = fe_ma2 * v = (-A^2)*v  (Monero code comment says "y = -2 * A^2 * u^2"?)
	y = new(field.Element).Multiply(FeMa2, v)

	// x = w^2 + y = w^2 - 2*A^2*u^2
	x = new(field.Element).Add(x, y)

	// r->X = (w / x)^(m+1)
	rX := FeDivPowM1(new(field.Element), w, x)

	// y = (r->X)^2
	y = new(field.Element).Square(rX)

	// x = y * x
	x = new(field.Element).Multiply(y, x)

	// y = w - x
	y = new(field.Element).Subtract(w, x)

	// z = fe_ma = -A
	z = new(field.Element).Set(FeMa)

	// if (fe_isnonzero(y)) => the "if" that goes to "negative" in C code
	if y.Equal(new(field.Element).Zero()) == 0 {
		// y = w + x
		y = new(field.Element).Add(w, x)
		if y.Equal(new(field.Element).Zero()) == 0 {
			// goto negative
			goto NEGATIVE
		} else {
			// fe_mul(r->X, r->X, fe_fffb1)
			rX = rX.Multiply(rX, FeFffb1)
		}
	} else {
		// else => fe_mul(r->X, r->X, fe_fffb2)
		rX = rX.Multiply(rX, FeFffb2)
	}

	// r->X = r->X * u
	rX = rX.Multiply(rX, u)

	// z = z * v = -A * (2*u^2)
	z = z.Multiply(z, v)

	sign = 0
	goto SETSIGN

NEGATIVE:
	// x = x * fe_sqrtm1
	x = x.Multiply(x, SqrtM1)
	// y = w - x
	y = new(field.Element).Subtract(w, x)
	if y.Equal(new(field.Element).Zero()) == 0 {
		// The C code has an assert that the next line is nonzero check
		// fe_add(y, w, x); !fe_isnonzero(y)
		y = new(field.Element).Add(w, x)
		// if still nonzero => something's wrong
		if y.Equal(new(field.Element).Zero()) == 0 {
			panic("assertion failed in ge_fromfe_frombytes_vartime")
		}
		// fe_mul(r->X, r->X, fe_fffb3)
		rX = rX.Multiply(rX, FeFffb3)
	} else {
		rX = rX.Multiply(rX, FeFffb4)
	}
	// sign = 1
	sign = 1

SETSIGN:
	// if (fe_isnegative(r->X) != sign) => fe_neg(r->X, r->X)
	if rX.IsNegative() != sign {
		// ensure r->X != 0
		if rX.Equal(new(field.Element).Zero()) == 1 {
			panic("Unexpected zero field element in setsign")
		}
		rX = rX.Negate(rX)
	}
	// r->Z = z + w
	rZ := new(field.Element).Add(z, w)
	// r->Y = z - w
	rY := new(field.Element).Subtract(z, w)
	// r->X = r->X * r->Z
	rX = rX.Multiply(rX, rZ)

	// compute T

	rT := new(field.Element).Multiply(rX, rY)
	rZInv := new(field.Element).Invert(rZ) // 1/Z in the field
	rT = rT.Multiply(rT, rZInv)            // T = (X*Y) / Z

	point := edwards25519.NewIdentityPoint()
	return point.SetExtendedCoordinates(rX, rY, rZ, rT) //affineToExtended(toAffine(rX, rY, rZ)))
}

func toAffine(ix, iy, iz *field.Element) (*field.Element, *field.Element) {
	zInv := new(field.Element).Invert(iz) // zInv = 1/Z

	x := new(field.Element).Multiply(ix, zInv) // x = x/z
	y := new(field.Element).Multiply(iy, zInv) // y = y/z
	return x, y
}

func affineToExtended(x, y *field.Element) (X, Y, Z, T *field.Element) {
	X = new(field.Element)
	Y = new(field.Element)
	Z = new(field.Element)
	T = new(field.Element)

	X = X.Set(x)
	Y = Y.Set(y)
	Z = Z.One()
	T = T.Multiply(x, y)

	return X, Y, Z, T
}
