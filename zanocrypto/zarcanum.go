package zanocrypto

import (
	"errors"
	"io"

	"filippo.io/edwards25519"
	"github.com/KarpelesLab/zanolib/zanobase"
)

func GenerateVectorUgAggregationProof(rnd io.Reader, contextHash []byte, uSecrets, gSecrets0, gSecrets1 []*edwards25519.Scalar, amountCommitments, amountCommitmentsForRpAggregation, blindedAssetIds []*edwards25519.Point) (*zanobase.UGAggProof, error) {
	// bool generate_vector_UG_aggregation_proof(const hash& m, const scalar_vec_t& u_secrets, const scalar_vec_t& g_secrets0, const scalar_vec_t& g_secrets1,
	// const std::vector<point_t>& amount_commitments,
	// const std::vector<point_t>& amount_commitments_for_rp_aggregation,
	// const std::vector<point_t>& blinded_asset_ids,
	// vector_UG_aggregation_proof& result, uint8_t* p_err

	// w - public random weighting factor
	// proof of knowing e_j and y'' in zero knowledge in the following eq:
	//   E_j + w * E'_j = e_j * (T'_j + w * U) + (y_j + w * y'_j) * G
	// where:
	//   e_j   -- output's amount
	//   T'_j  -- output's blinded asset tag
	//   E_j   == e_j * T'_j + y_j  * G -- output's amount commitments
	//   E'_j  == e_j * U    + y'_j * G -- additional commitment to the same amount for range proof aggregation

	// amount_commitments[j] + w * amount_commitments_for_rp_aggregation[j]
	//   ==
	// u_secrets[j] * (blinded_asset_ids[j] + w * U) + (g_secrets0[j] + w * g_secrets1[j]) * G
	n := len(uSecrets)
	if n == 0 {
		return nil, errors.New("GenerateVectorUgAggregationProof: empty secrets")
	}
	if len(gSecrets0) != n {
		return nil, errors.New("GenerateVectorUgAggregationProof: invalid length for gSecrets0")
	}
	if len(gSecrets1) != n {
		return nil, errors.New("GenerateVectorUgAggregationProof: invalid length for gSecrets1")
	}
	if len(amountCommitments) != n {
		return nil, errors.New("GenerateVectorUgAggregationProof: invalid length for amountCommitments")
	}
	if len(amountCommitmentsForRpAggregation) != n {
		return nil, errors.New("GenerateVectorUgAggregationProof: invalid length for amountCommitmentsForRpAggregation")
	}
	if len(blindedAssetIds) != n {
		return nil, errors.New("GenerateVectorUgAggregationProof: invalid length for blindedAssetIds")
	}

	hash_calculator := NewHashHelper()
	hash_calculator.AddBytes(contextHash)
	// hash_calculator.add_points_array(amount_commitments);
	hash_calculator.Add(bter(amountCommitments)...)
	hash_calculator.Add(bter(amountCommitmentsForRpAggregation)...)
	w := hash_calculator.CalcHashKeep() // don't clean the buffer
	//log.Printf("w = %x", w.Bytes())

	// for(size_t j = 0; j < n; ++j)
	// CHECK_AND_FAIL_WITH_ERROR_IF_FALSE(amount_commitments[j] + w * amount_commitments_for_rp_aggregation[j] == u_secrets[j] * (blinded_asset_ids[j] + w * c_point_U) + (g_secrets0[j] + w * g_secrets1[j]) * c_point_G, 20)

	res := new(zanobase.UGAggProof)
	var r0, r1 []*edwards25519.Scalar
	for i := 0; i < n; i++ {
		r0 = append(r0, RandomScalar(rnd))
		r1 = append(r1, RandomScalar(rnd))
	}

	assetTagPlusUvec := make([]*edwards25519.Point, n)
	for j := range assetTagPlusUvec {
		assetTagPlusUvec[j] = new(edwards25519.Point).Add(blindedAssetIds[j], new(edwards25519.Point).ScalarMult(w, C_point_U))
	}

	R := make([]*edwards25519.Point, n)
	for j := range R {
		// R[j].assign_mul_plus_G(r0[j], asset_tag_plus_U_vec[j], r1[j]); // R[j] = r0[j] * asset_tag_plus_U_vec[j] + r1[j] * G
		R[j] = new(edwards25519.Point).VarTimeDoubleScalarBaseMult(r0[j], assetTagPlusUvec[j], r1[j])
	}

	hash_calculator.Add(bter(R)...)

	rC := hash_calculator.CalcHash()
	res.C = &zanobase.Scalar{rC}

	// DBG_VAL_PRINT(asset_tag_plus_U_vec); DBG_VAL_PRINT(m); DBG_VAL_PRINT(amount_commitments); DBG_VAL_PRINT(amount_commitments_for_rp_aggregation); DBG_VAL_PRINT(R);
	// DBG_VAL_PRINT(result.c);

	for j := 0; j < n; j += 1 {
		// result.y0s.emplace_back(r0[j] - result.c * u_secrets[j]);
		tmp := new(edwards25519.Scalar).Multiply(rC, uSecrets[j])
		res.Y0s = append(res.Y0s, &zanobase.Scalar{new(edwards25519.Scalar).Subtract(r0[j], tmp)})
		// result.y1s.emplace_back(r1[j] - result.c * (g_secrets0[j] + w * g_secrets1[j]));
		tmp = new(edwards25519.Scalar).Multiply(w, gSecrets1[j])
		tmp = tmp.Add(tmp, gSecrets0[j])
		tmp = tmp.Multiply(rC, tmp)
		res.Y1s = append(res.Y1s, &zanobase.Scalar{new(edwards25519.Scalar).Subtract(r1[j], tmp)})
		// result.amount_commitments_for_rp_aggregation.emplace_back((c_scalar_1div8 * amount_commitments_for_rp_aggregation[j]).to_public_key());
		res.AmountCommitmentsForRPAgg = append(res.AmountCommitmentsForRPAgg, &zanobase.Point{new(edwards25519.Point).ScalarMult(Sc1div8, amountCommitmentsForRpAggregation[j])})
	}

	return res, nil
}

func GenerateDoubleSchnorrSig(rnd io.Reader, gen0, gen1 *edwards25519.Point, m []byte, A *edwards25519.Point, secret_a *edwards25519.Scalar, B *edwards25519.Point, secret_b *edwards25519.Scalar) (*zanobase.GenericDoubleSchnorrSig, error) {
	r0 := RandomScalar(rnd)
	r1 := RandomScalar(rnd)
	R0 := new(edwards25519.Point).ScalarMult(r0, gen0)
	R1 := new(edwards25519.Point).ScalarMult(r1, gen1)
	hsc := NewHashHelper()
	hsc.AddBytes(m)
	hsc.Add(A, B, R0, R1)
	C := hsc.CalcHash()
	// y0 = r0 - c * secret_a
	Y0 := new(edwards25519.Scalar).Subtract(r0, new(edwards25519.Scalar).Multiply(C, secret_a))
	// y1 = r1 - c * secret_b
	Y1 := new(edwards25519.Scalar).Subtract(r1, new(edwards25519.Scalar).Multiply(C, secret_b))
	res := &zanobase.GenericDoubleSchnorrSig{
		C:  &zanobase.Scalar{C},
		Y0: &zanobase.Scalar{Y0},
		Y1: &zanobase.Scalar{Y1},
	}
	return res, nil
}
