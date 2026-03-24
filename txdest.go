package zanolib

import (
	"slices"

	"filippo.io/edwards25519"
	"github.com/KarpelesLab/zanolib/zanobase"
	"github.com/KarpelesLab/zanolib/zanocrypto"
)

type TxDestHtlcOut struct {
	Expiration uint64
	HtlcHash   zanobase.Value256 // crypto::hash
}

type TxDest struct {
	Amount          uint64
	Addr            []*zanobase.AccountPublicAddr // account_public_address; destination address, in case of 1 address - txout_to_key, in case of more - txout_multisig
	MinimumSigs     uint64                        // if txout_multisig: minimum signatures that are required to spend this output (minimum_sigs <= addr.size())  IF txout_to_key - not used
	AmountToProvide uint64                        // amount money that provided by initial creator of tx, used with partially created transactions
	UnlockTime      uint64                        //
	HtlcOptions     *TxDestHtlcOut                // destination_option_htlc_out
	AssetId         *zanobase.Point               // not blinded, not premultiplied
	Flags           uint64                        // set of flags (see tx_destination_entry_flags)
}

func (dst *TxDest) StealthAddress(scalar *edwards25519.Scalar, ogc *zanobase.GenContext, i int) *edwards25519.Point {
	// 1. Compute H = h * G
	H := new(edwards25519.Point).ScalarBaseMult(scalar)

	P := must(new(edwards25519.Point).SetBytes(dst.Addr[0].SpendKey[:]))

	// 3. Add the two points: R = H + P
	return new(edwards25519.Point).Add(H, P)
}

func (dst *TxDest) ConcealingPoint(scalar *edwards25519.Scalar, ogc *zanobase.GenContext, i int) *edwards25519.Point {
	// ConcealingPoint
	h := zanocrypto.HashToScalar(slices.Concat([]byte("ZANO_HDS_OUT_CONCEALING_POINT__\x00"), scalar.Bytes()))

	v := must(new(edwards25519.Point).SetBytes(dst.Addr[0].ViewKey[:]))

	return new(edwards25519.Point).ScalarMult(h, v)
}

func (dst *TxDest) BlindedAssetId(scalar *edwards25519.Scalar, ogc *zanobase.GenContext, i int) *edwards25519.Point {
	// zanocrypto.HashToScalar will also reduce
	assetBlindingMask := zanocrypto.HashToScalar(slices.Concat([]byte("ZANO_HDS_OUT_ASSET_BLIND_MASK__\x00"), scalar.Bytes()))
	ogc.AssetIdBlindingMasks[i] = &zanobase.Scalar{new(edwards25519.Scalar).Set(assetBlindingMask)}

	// 1) Decompress dst.AssetId (Q) to a Point
	Q := new(edwards25519.Point).Set(dst.AssetId.Point)

	// 3) Multiply R = assetBlindingMask * X
	R := new(edwards25519.Point).ScalarMult(assetBlindingMask, zanocrypto.C_point_X)

	// 4) S = Q + R
	S := new(edwards25519.Point).Add(Q, R)

	ogc.BlindedAssetIds[i] = &zanobase.Point{S}

	// 2) Multiply by (1/8) & return
	return new(edwards25519.Point).ScalarMult(zanocrypto.Sc1div8, S)
}

func (dst *TxDest) AmountCommitment(scalar *edwards25519.Scalar, ogc *zanobase.GenContext, i int) *edwards25519.Point {
	// amount_blinding_mask = crypto::hash_helper_t::hs(CRYPTO_HDS_OUT_AMOUNT_BLINDING_MASK, h)
	amountBlindingMask := zanocrypto.HashToScalar(slices.Concat([]byte("ZANO_HDS_OUT_AMOUNT_BLIND_MASK_\x00"), scalar.Bytes()))

	// 2) Convert dst.Amount (uint64) to a 32-byte scalar
	amount := zanocrypto.ScalarInt(dst.Amount)

	// 3) Let T = dst.BlindedAssetId(scalar).ToExtended()
	T := ogc.BlindedAssetIds[i].Point

	// 4) We want R = (amount)*T + (mask)*c_point_G
	//    But GeDoubleScalarMultVartime(&RProj, a, A, b) => a*A + b*B always uses B=basepoint.
	//    So instead do:
	//        P = (amount)*T
	//        Q = (mask)*c_point_G
	//        R = P + Q

	// --- P = amount*T ---
	P := new(edwards25519.Point).ScalarMult(amount, T)

	// --- Q = mask*c_point_G ---
	//     c_point_G is presumably an *ExtendedGroupElement*
	Q := new(edwards25519.Point).ScalarMult(amountBlindingMask, zanocrypto.C_point_G)

	// --- R = P + Q ---
	R := new(edwards25519.Point).Add(P, Q)

	// store before multiplication by 1/8 into gencontext
	ogc.AmountCommitments[i] = &zanobase.Point{new(edwards25519.Point).Set(R)}

	// 5) Multiply R by (1/8):
	//    R2 = (1/8)*R = GeDoubleScalarMultVartime(r2, cScalar1div8, R, zero)
	return new(edwards25519.Point).ScalarMult(zanocrypto.Sc1div8, R)
}
