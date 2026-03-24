package zanocrypto

import (
	"encoding/binary"
	"fmt"

	"filippo.io/edwards25519"
)

// Trait defines the cryptographic parameters for Bulletproof+ generation,
// including the generators and dimension constraints.
type Trait struct {
	Type      string // UGX or HGX
	N         int
	ValuesMax int
	Log2N     int
	MNMax     int

	// NOTE! This notation follows the original BP+ whitepaper, see mapping to Zano's generators in range_proofs.cpp
	G  *edwards25519.Point
	H  *edwards25519.Point
	H2 *edwards25519.Point
}

var (
	TraitZCout    = makeTrait("UGX", 64, 32)
	TraitZarcanum = makeTrait("HGX", 128, 16)
)

// typedef bpp_crypto_trait_zano<bpp_ct_generators_UGX, 64,  32> bpp_crypto_trait_ZC_out
// template<typename gen_trait_t, size_t N = 64, size_t values_max = 32>
func makeTrait(typ string, N, valuesMax int) *Trait {
	res := &Trait{
		Type:      typ,
		N:         N,
		ValuesMax: valuesMax,
		Log2N:     ceilLog2(N),
		MNMax:     N * valuesMax,
	}

	switch typ {
	case "HGX":
		res.G = C_point_H
		res.H = C_point_G
		res.H2 = C_point_X
	case "UGX":
		res.G = C_point_U
		res.H = C_point_G
		res.H2 = C_point_X
	default:
		panic(fmt.Errorf("unsupported trait %s", typ))
	}

	return res
}

// CalcPedersenCommitment computes a Pedersen commitment: value * G + mask * H,
// using this trait's generators.
func (t *Trait) CalcPedersenCommitment(value, mask *edwards25519.Scalar) *edwards25519.Point {
	// commitment = value * bpp_G + mask * bpp_H
	a := new(edwards25519.Point).ScalarMult(value, t.G)
	b := new(edwards25519.Point).ScalarMult(mask, t.H)
	return new(edwards25519.Point).Add(a, b)
}

func (t *Trait) at(row, col int) int {
	// scalar_mat_t in src/crypto/crypto-sugar.h
	return row*t.N + col
}

// TraitInitialTranscript returns the initial Fiat-Shamir transcript scalar
// for Bulletproof+ generation.
func TraitInitialTranscript() *edwards25519.Scalar {
	return HashToScalar([]byte("Zano BP+ initial transcript"))
}

// TraitUpdateTranscript updates the Fiat-Shamir transcript by hashing the
// current transcript value and public keys.
func TraitUpdateTranscript(hsc *HashHelper, e *edwards25519.Scalar, pubKeys []*edwards25519.Point) *edwards25519.Scalar {
	hsc.Add(e)
	hsc.Add(bter(pubKeys)...)
	return hsc.CalcHash()
}

// TraitGetGenerator returns the Bulletproof+ generator point at the given
// index. If select_H is true, returns the H-generator; otherwise the G-generator.
func TraitGetGenerator(select_H bool, index int) *edwards25519.Point {
	// simple method
	// TODO pre-generate?
	pos := 2 * uint64(index)
	if select_H {
		pos += 1
	}
	var buf [64]byte
	copy(buf[:], HashToScalar([]byte("Zano BP+ generator")).Bytes())
	// hash_buf[1].m_u64[0] = i
	binary.LittleEndian.PutUint64(buf[32:40], pos)
	return Hp(buf[:])
}
