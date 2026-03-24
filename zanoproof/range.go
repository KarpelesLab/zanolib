package zanoproof

import (
	"errors"
	"io"

	"filippo.io/edwards25519"
	"github.com/KarpelesLab/zanolib/zanobase"
	"github.com/KarpelesLab/zanolib/zanocrypto"
)

// GenerateZcOutsRangeProof generates a range proof for all zero-confidential
// outputs, proving that each output amount is in [0, 2^64). The proof
// (including UG aggregation and BPP signature) is appended to tx.Proofs.
func GenerateZcOutsRangeProof(rnd io.Reader, tx *zanobase.Transaction, contextHash []byte, ogc *zanobase.GenContext) error {
	// bool generate_zc_outs_range_proof(const crypto::hash& context_hash, const tx_generation_context& outs_gen_context, const std::vector<tx_out_v>& vouts, zc_outs_range_proof& result)
	res := new(zanobase.ZCOutsRangeProof)

	outsCount := len(ogc.Amounts)
	if outsCount != len(tx.Vout) {
		return errors.New("generate_zc_outs_range_proof: vout count not matching")
	}

	// prepare data for aggregation proof
	//std::vector<crypto::point_t> amount_commitments_for_rp_aggregation; // E' = amount * U + y' * G
	var amountCommitmentsForRpAggregation []*edwards25519.Point
	var y_primes []*edwards25519.Scalar

	for i := 0; i < outsCount; i += 1 {
		y_prime := zanocrypto.RandomScalar(rnd)
		// E'_j = e_j * U + y'_j * G
		// outs_gen_context.amounts[i] * crypto::c_point_U + y_prime * crypto::c_point_G
		tmp := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(ogc.Amounts[i].Scalar, zanocrypto.C_point_U, y_prime)
		amountCommitmentsForRpAggregation = append(amountCommitmentsForRpAggregation, tmp)
		y_primes = append(y_primes, y_prime)
	}

	// aggregation proof
	// bool r = crypto::generate_vector_UG_aggregation_proof(context_hash, outs_gen_context.amounts, outs_gen_context.amount_blinding_masks, y_primes,
	// outs_gen_context.amount_commitments, amount_commitments_for_rp_aggregation,
	// outs_gen_context.blinded_asset_ids, result.aggregation_proof, &err);
	var err error
	res.AggregationProof, err = zanocrypto.GenerateVectorUgAggregationProof(rnd, contextHash, xScs(ogc.Amounts), xScs(ogc.AmountBlindingMasks), y_primes, xPts(ogc.AmountCommitments), amountCommitmentsForRpAggregation, xPts(ogc.BlindedAssetIds))
	if err != nil {
		return err
	}

	// aggregated range proof
	// commitments_1div8[i] = &result.aggregation_proof.amount_commitments_for_rp_aggregation[i];
	// this actually does nothing more than xPts

	res.BPP, err = zanocrypto.TraitZCout.BPPGen(rnd, xScs(ogc.Amounts), y_primes, xPts(res.AggregationProof.AmountCommitmentsForRPAgg))
	if err != nil {
		return err
	}

	tx.Proofs = append(tx.Proofs, &zanobase.Variant{Tag: zanobase.TagZcOutsRangeProof, Value: res})

	return nil
}

func xPts(v []*zanobase.Point) []*edwards25519.Point {
	res := make([]*edwards25519.Point, len(v))
	for n, p := range v {
		res[n] = p.Point
	}
	return res
}

func xScs(v []*zanobase.Scalar) []*edwards25519.Scalar {
	res := make([]*edwards25519.Scalar, len(v))
	for n, s := range v {
		res[n] = s.Scalar
	}
	return res
}
