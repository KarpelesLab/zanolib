package zanocrypto

import (
	"bytes"
	"errors"
	"io"

	"filippo.io/edwards25519"
	"github.com/KarpelesLab/zanolib/zanobase"
)

var (
	CRYPTO_HDS_CLSAG_GGX_LAYER_0   = []byte("ZANO_HDS_CLSAG_GGX_LAYER_ZERO__\x00")
	CRYPTO_HDS_CLSAG_GGX_LAYER_1   = []byte("ZANO_HDS_CLSAG_GGX_LAYER_ONE___\x00")
	CRYPTO_HDS_CLSAG_GGX_LAYER_2   = []byte("ZANO_HDS_CLSAG_GGX_LAYER_TWO___\x00")
	CRYPTO_HDS_CLSAG_GGX_CHALLENGE = []byte("ZANO_HDS_CLSAG_GGX_CHALLENGE___\x00")
)

// CLSAG_GGXInputRef holds the ring member data for a CLSAG-GGX ring signature:
// stealth address, amount commitment, and blinded asset ID.
type CLSAG_GGXInputRef struct {
	StealthAddress   *edwards25519.Point
	AmountCommitment *edwards25519.Point
	BlindedAssetID   *edwards25519.Point
}

// GenerateCLSAG_GGX generates a three-layer CLSAG-GGX ring signature proving
// knowledge of the secret keys corresponding to the real input in the ring.
// The three layers authenticate the stealth address, amount blinding mask,
// and asset ID blinding mask respectively.
func GenerateCLSAG_GGX(
	rnd io.Reader,
	m []byte,
	ring []CLSAG_GGXInputRef,
	ki *edwards25519.Point,
	pseudoOutAmountCommitment, pseudoOutBlindedAssetID *edwards25519.Point,
	secret0Xp, secret1F, secret2T *edwards25519.Scalar,
	secretIndex uint64,
) (*zanobase.CLSAG_Sig, error) {
	sig := new(zanobase.CLSAG_Sig)

	ringSize := len(ring)
	if ringSize == 0 {
		return nil, errors.New("ring size is zero")
	}
	if secretIndex >= uint64(ringSize) {
		return nil, errors.New("secretIndex out of range")
	}

	// 1) Calculate ki_base = hash_helper_t::hp(ring[secretIndex].stealth_address).
	stealthBytes := ring[secretIndex].StealthAddress.Bytes()
	kiBase := Hp(stealthBytes)

	// 2) key_image = secret_0_xp * ki_base
	keyImage := new(edwards25519.Point).ScalarMult(secret0Xp, kiBase)

	// sanity check, mostly useful for debugging
	if !bytes.Equal(keyImage.Bytes(), ki.Bytes()) {
		return nil, errors.New("CLSAG_GGX keyImage mismatch")
	}
	if !bytes.Equal(new(edwards25519.Point).ScalarMult(secret0Xp, C_point_G).Bytes(), ring[secretIndex].StealthAddress.Bytes()) {
		return nil, errors.New("CLSAG_GGX secret_0_xp mismatch")
	}
	if !bytes.Equal(new(edwards25519.Point).ScalarMult(secret1F, C_point_G).Bytes(), new(edwards25519.Point).Subtract(new(edwards25519.Point).ScalarMult(ScalarInt(8), ring[secretIndex].AmountCommitment), pseudoOutAmountCommitment).Bytes()) {
		return nil, errors.New("CLSAG_GGX secret_1_f mismatch")
	}
	if !bytes.Equal(new(edwards25519.Point).ScalarMult(secret2T, C_point_X).Bytes(), new(edwards25519.Point).Subtract(new(edwards25519.Point).ScalarMult(ScalarInt(8), ring[secretIndex].BlindedAssetID), pseudoOutBlindedAssetID).Bytes()) {
		return nil, errors.New("CLSAG_GGX secret_2_t mismatch")
	}

	// 3) K1_div8 = (1/8 * secret_1_f) * ki_base
	tmp1 := new(edwards25519.Scalar).Multiply(Sc1div8, secret1F) // sc = c_scalar_1div8 * secret_1_f
	K1_div8 := new(edwards25519.Point).ScalarMult(tmp1, kiBase)

	// Save as sig.K1 (the "public key" portion) => i.e. K1_div8 as a "public key"
	sig.K1 = &zanobase.Point{new(edwards25519.Point).Set(K1_div8)}

	// Then K1 = K1_div8; K1.modify_mul8() => multiply by 8
	K1 := new(edwards25519.Point).ScalarMult(ScalarInt(8), K1_div8)

	// 4) K2_div8 = (1/8 * secret_2_t) * ki_base
	tmp2 := new(edwards25519.Scalar).Multiply(Sc1div8, secret2T) // sc = c_scalar_1div8 * secret_2_t
	K2_div8 := new(edwards25519.Point).ScalarMult(tmp2, kiBase)

	// Save as sig.K2
	sig.K2 = &zanobase.Point{new(edwards25519.Point).Set(K2_div8)}

	// Then K2 = K2_div8; K2.modify_mul8()
	K2 := new(edwards25519.Point).ScalarMult(ScalarInt(8), K2_div8)

	// hash_helper_t::hs_t hsc(4 + 3  * ring_size);
	hsc := NewHashHelper()

	// since this was hsc.add_scalar(m), the value of m is converted to a scalar and has "mod l" applied to it
	hsc.AddBytesModL(m)

	// for each ring item, add stealth_address, amount_commitment, blinded_asset_id
	for i := 0; i < ringSize; i++ {
		hsc.Add(ring[i].StealthAddress)
		hsc.Add(ring[i].AmountCommitment)
		hsc.Add(ring[i].BlindedAssetID)
		//log.Printf("ring[%d]: sa:%x ac:%x baid:%x", i, ring[i].StealthAddress.Bytes(), ring[i].AmountCommitment.Bytes(), ring[i].BlindedAssetID.Bytes())
	}
	// also add c_scalar_1div8 * pseudoOutAmountCommitment
	tmpPoint := new(edwards25519.Point).ScalarMult(Sc1div8, pseudoOutAmountCommitment)
	hsc.Add(tmpPoint)

	tmpPoint = new(edwards25519.Point).ScalarMult(Sc1div8, pseudoOutBlindedAssetID)
	hsc.Add(tmpPoint)

	// add key_image
	hsc.Add(ki)
	// add K1, K2 (already stored in sig.*)
	hsc.Add(sig.K1.Point)
	hsc.Add(sig.K2.Point)

	// input_hash = hsc.calc_hash_no_reduce() in your code
	// We'll assume a single CalcHash() usage
	inputHash := hsc.CalcRawHash()

	//   hsc.add_32_chars(CRYPTO_HDS_CLSAG_GGX_LAYER_0)
	//   hsc.add_hash(input_hash)
	//   agg_coeff_0 = hsc.calc_hash()
	hsc.AddBytes(CRYPTO_HDS_CLSAG_GGX_LAYER_0)
	hsc.AddBytes(inputHash)
	aggCoeff0 := hsc.CalcHash()

	hsc.AddBytes(CRYPTO_HDS_CLSAG_GGX_LAYER_1)
	hsc.AddBytes(inputHash)
	aggCoeff1 := hsc.CalcHash()

	hsc.AddBytes(CRYPTO_HDS_CLSAG_GGX_LAYER_2)
	hsc.AddBytes(inputHash)
	aggCoeff2 := hsc.CalcHash()

	// Prepare A_i, Q_i by copying ring[i].amount_commitment and .blinded_asset_id,
	// then multiply each by 8
	Ai := make([]*edwards25519.Point, ringSize)
	Qi := make([]*edwards25519.Point, ringSize)
	for i := 0; i < ringSize; i++ {
		Ai[i] = new(edwards25519.Point).ScalarMult(ScalarInt(8), ring[i].AmountCommitment)
		Qi[i] = new(edwards25519.Point).ScalarMult(ScalarInt(8), ring[i].BlindedAssetID)

		//log.Printf("A_i[%d] = %x  Q_i[%d] = %x", i, Ai[i].Bytes(), i, Qi[i].Bytes())
	}

	// Calculate aggregated pubkeys for layer 0 & 1 => W_pub_keys_g,
	// and for layer 2 => W_pub_keys_x
	WpubG := make([]*edwards25519.Point, ringSize)
	WpubX := make([]*edwards25519.Point, ringSize)

	for i := 0; i < ringSize; i++ {
		// W_pub_keys_g[i] = agg_coeff_0*stealth + agg_coeff_1*(Ai[i] - pseudoOutAmountCommitment)
		term1 := new(edwards25519.Point).ScalarMult(aggCoeff0, ring[i].StealthAddress)
		diff := new(edwards25519.Point).Subtract(Ai[i], pseudoOutAmountCommitment)
		term2 := new(edwards25519.Point).ScalarMult(aggCoeff1, diff)
		WpubG[i] = new(edwards25519.Point).Add(term1, term2)
		//log.Printf("WpubG[%d] = %x", i, WpubG[i].Bytes())

		// W_pub_keys_x[i] = agg_coeff_2*(Qi[i] - pseudoOutBlindedAssetID)
		diff2 := new(edwards25519.Point).Subtract(Qi[i], pseudoOutBlindedAssetID)
		WpubX[i] = new(edwards25519.Point).ScalarMult(aggCoeff2, diff2)
		//log.Printf("WpubX[%d] = %x", i, WpubX[i].Bytes())
	}

	// Aggregate secret keys
	//
	// w_sec_key_g = agg_coeff_0*secret_0_xp + agg_coeff_1*secret_1_f
	wSecKeyG := new(edwards25519.Scalar).Multiply(aggCoeff0, secret0Xp)
	wSecKeyG = new(edwards25519.Scalar).Add(wSecKeyG, new(edwards25519.Scalar).Multiply(aggCoeff1, secret1F))

	// w_sec_key_x = agg_coeff_2*secret_2_t
	wSecKeyX := new(edwards25519.Scalar).Multiply(aggCoeff2, secret2T)

	wSecKeyGmul := new(edwards25519.Point).ScalarMult(wSecKeyG, C_point_G)
	wSecKeyXmul := new(edwards25519.Point).ScalarMult(wSecKeyX, C_point_X)

	//log.Printf("w_sec_key_g * c_point_G: %x", wSecKeyGmul.Bytes())
	//log.Printf("w_sec_key_x * c_point_X: %x", wSecKeyXmul.Bytes())

	if !bytes.Equal(wSecKeyGmul.Bytes(), WpubG[secretIndex].Bytes()) {
		return nil, errors.New("CLSAG_GGX w_sec_key_g mismatch")
	}
	if !bytes.Equal(wSecKeyXmul.Bytes(), WpubX[secretIndex].Bytes()) {
		return nil, errors.New("CLSAG_GGX w_sec_key_x mismatch")
	}

	// Aggregate key images
	//
	// W_key_image_g = agg_coeff_0*key_image + agg_coeff_1*K1
	WkeyImageGPart1 := new(edwards25519.Point).ScalarMult(aggCoeff0, keyImage)
	WkeyImageGPart2 := new(edwards25519.Point).ScalarMult(aggCoeff1, K1)
	WkeyImageG := new(edwards25519.Point).Add(WkeyImageGPart1, WkeyImageGPart2)

	//log.Printf("W_key_image_g: %x", WkeyImageG.Bytes())

	// W_key_image_x = agg_coeff_2*K2
	WkeyImageX := new(edwards25519.Point).ScalarMult(aggCoeff2, K2)

	//log.Printf("W_key_image_x: %x", WkeyImageX.Bytes())

	// Initial commitment: alpha_g, alpha_x are random scalars
	alphaG := RandomScalar(rnd)
	alphaX := RandomScalar(rnd)

	// c_prev = Hs(input_hash, alpha_g*G, alpha_g*ki_base, alpha_x*X, alpha_x*ki_base)
	hsc.AddBytes(CRYPTO_HDS_CLSAG_GGX_CHALLENGE)
	hsc.AddBytes(inputHash)

	hsc.Add(new(edwards25519.Point).ScalarMult(alphaG, C_point_G))
	hsc.Add(new(edwards25519.Point).ScalarMult(alphaG, kiBase))
	hsc.Add(new(edwards25519.Point).ScalarMult(alphaX, C_point_X))
	hsc.Add(new(edwards25519.Point).ScalarMult(alphaX, kiBase))
	//log.Printf("c[%d] = Hs(ih, %x, )", secretIndex, new(edwards25519.Point).ScalarMult(alphaG, C_point_G), )
	cPrev := hsc.CalcHash()
	//log.Printf("cPrev = %x", cPrev.Bytes())

	// Initialize sig.Rg and sig.Rx with random scalars
	sig.Rg = make([]*zanobase.Scalar, ringSize)
	sig.Rx = make([]*zanobase.Scalar, ringSize)
	for i := 0; i < ringSize; i++ {
		sig.Rg[i] = &zanobase.Scalar{RandomScalar(rnd)}
		sig.Rx[i] = &zanobase.Scalar{RandomScalar(rnd)}
	}

	// The main ring loop
	i := (int(secretIndex) + 1) % ringSize
	for j := 0; j < ringSize-1; j++ {
		//log.Printf("c[%d] = %x", i, cPrev.Bytes())
		// if i == 0 => sig.c = cPrev
		if i == 0 {
			sig.C = &zanobase.Scalar{new(edwards25519.Scalar).Set(cPrev)}
		}

		// c_{i+1} = Hs(input_hash, r_g[i]*G + c_prev*W_pub_keys_g[i],
		//                        r_g[i]*hp(ring[i].stealth_address) + c_prev*W_key_image_g,
		//                        r_x[i]*X + c_prev*W_pub_keys_x[i],
		//                        r_x[i]*hp(ring[i].stealth_address) + c_prev*W_key_image_x )
		hsc = NewHashHelper()
		hsc.AddBytes(CRYPTO_HDS_CLSAG_GGX_CHALLENGE)
		hsc.AddBytes(inputHash)

		// 1) r_g[i]*G + c_prev*W_pub_keys_g[i]
		rgG := new(edwards25519.Point).ScalarMult(sig.Rg[i].Scalar, C_point_G)
		cwpg := new(edwards25519.Point).ScalarMult(cPrev, WpubG[i])
		hsc.Add(new(edwards25519.Point).Add(rgG, cwpg))

		// 2) r_g[i]*hp(stealth) + c_prev*W_key_image_g
		stealthBytes2 := ring[i].StealthAddress.Bytes()
		hpI := Hp(stealthBytes2)

		rgHp := new(edwards25519.Point).ScalarMult(sig.Rg[i].Scalar, hpI)
		cwikg := new(edwards25519.Point).ScalarMult(cPrev, WkeyImageG)
		hsc.Add(new(edwards25519.Point).Add(rgHp, cwikg))

		// 3) r_x[i]*X + c_prev*W_pub_keys_x[i]
		rxX := new(edwards25519.Point).ScalarMult(sig.Rx[i].Scalar, C_point_X)
		cwpx := new(edwards25519.Point).ScalarMult(cPrev, WpubX[i])
		hsc.Add(new(edwards25519.Point).Add(rxX, cwpx))

		// 4) r_x[i]*hp(stealth) + c_prev*W_key_image_x
		rxHp := new(edwards25519.Point).ScalarMult(sig.Rx[i].Scalar, hpI)
		cwikx := new(edwards25519.Point).ScalarMult(cPrev, WkeyImageX)
		hsc.Add(new(edwards25519.Point).Add(rxHp, cwikx))

		cPrev = hsc.CalcHash()

		i = (i + 1) % ringSize
	}

	// Finally, for c[secretIndex] = c_prev
	if secretIndex == 0 {
		sig.C = &zanobase.Scalar{new(edwards25519.Scalar).Set(cPrev)}
	}

	// sig.r_g[secretIndex] = alpha_g - c_prev * w_sec_key_g
	rgSecretIndex := new(edwards25519.Scalar).Subtract(alphaG, new(edwards25519.Scalar).Multiply(cPrev, wSecKeyG))
	sig.Rg[secretIndex] = &zanobase.Scalar{rgSecretIndex}

	// sig.r_x[secretIndex] = alpha_x - c_prev * w_sec_key_x
	rxSecretIndex := new(edwards25519.Scalar).Subtract(alphaX, new(edwards25519.Scalar).Multiply(cPrev, wSecKeyX))
	sig.Rx[secretIndex] = &zanobase.Scalar{rxSecretIndex}

	return sig, nil
}
