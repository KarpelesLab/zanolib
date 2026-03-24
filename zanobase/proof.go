package zanobase

// ZCOutsRangeProof contains the range proof and aggregation proof for
// zero-confidential transaction outputs.
type ZCOutsRangeProof struct {
	// zc_outs_range_proof
	BPP *BPPSignature // for commitments in form: amount * U + mask * G
	// crypto::vector_UG_aggregation_proof_serialized
	AggregationProof *UGAggProof // E'_j = e_j * U + y'_j * G    +   vector Shnorr
}

// UGAggProof is a vector UG aggregation proof that links amount commitments
// to their Bulletproof+ range proof aggregation commitments.
type UGAggProof struct {
	AmountCommitmentsForRPAgg []*Point  `json:"amount_commitments_for_rp_aggregation"` // std::vector<public_key> E' = e * U + y' * G, premultiplied by 1/8
	Y0s                       []*Scalar `json:"y0s"`                                   // scalar_vec_t
	Y1s                       []*Scalar `json:"y1s"`                                   // scalar_vec_t
	C                         *Scalar   `json:"c"`                                     // common challenge
}

// First part of a double Schnorr proof:
//  1. for txs without ZC inputs: proves that balance point = lin(G) (cancels out G component of outputs' amount commitments, asset tags assumed to be H (native coin) and non-blinded)
//  2. for txs with    ZC inputs: proves that balance point = lin(X) (cancels out X component of blinded asset tags within amount commitments for both outputs and inputs (pseudo outs))
//
// Second part:
//
//	proof of knowing transaction secret key (with respect to G)
// ZCBalanceProof proves that the transaction inputs and outputs are balanced
// (sum of inputs equals sum of outputs plus fee).
type ZCBalanceProof struct {
	// zc_balance_proof
	DSS *GenericDoubleSchnorrSig // crypto::generic_double_schnorr_sig_s
}

// GenericDoubleSchnorrSig is a double Schnorr signature proving knowledge
// of two discrete logarithms with respect to two (possibly different) generators.
type GenericDoubleSchnorrSig struct {
	C  *Scalar
	Y0 *Scalar
	Y1 *Scalar
}
