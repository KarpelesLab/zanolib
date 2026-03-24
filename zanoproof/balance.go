package zanoproof

import (
	"bytes"
	"errors"
	"io"

	"filippo.io/edwards25519"
	"github.com/KarpelesLab/zanolib/zanobase"
	"github.com/KarpelesLab/zanolib/zanocrypto"
)

func GenerateTxBalanceProof(rnd io.Reader, tx *zanobase.Transaction, contextHash []byte, ogc *zanobase.GenContext, block_reward_for_miner_tx uint64) error {
	// generate_tx_balance_proof(const transaction &tx, const crypto::hash& tx_id, const tx_generation_context& ogc,
	res := new(zanobase.ZCBalanceProof)

	bare_inputs_sum := block_reward_for_miner_tx
	zcInputsCount := 0

	for _, vin := range tx.Vin {
		switch vin.Tag {
		// TODO handle other cases?
		case zanobase.TagTxinZcInput:
			zcInputsCount += 1
		}
	}

	fee, ok := tx.GetFee()
	if !ok {
		return errors.New("unable to get tx fee")
	}

	if zcInputsCount == 0 {
		// no ZC inputs => all inputs are bare inputs; all outputs have explicit asset_id = native_coin_asset_id; in main balance equation we only need to cancel out G-component
		// crypto::point_t commitment_to_zero = (crypto::scalar_t(bare_inputs_sum) - crypto::scalar_t(fee)) * currency::native_coin_asset_id_pt - ogc.amount_commitments_sum
		tot := new(edwards25519.Scalar).Subtract(zanocrypto.ScalarInt(bare_inputs_sum), zanocrypto.ScalarInt(fee))
		commitment_to_zero := new(edwards25519.Point).Subtract(new(edwards25519.Point).ScalarMult(tot, zanocrypto.NativeCoinAssetIdPt), ogc.AmountCommitmentsSum.Point)
		secret_x := new(edwards25519.Scalar).Negate(ogc.AmountBlindingMasksSum.Scalar)
		// Check: commitment_to_zero == secret_x * crypto::c_point_G, false, "internal error: commitment_to_zero is malformed (G)"
		//crypto::generate_double_schnorr_sig<crypto::gt_G, crypto::gt_G>(tx_id, commitment_to_zero, secret_x, ogc.tx_pub_key_p, ogc.tx_key.sec, proof.dss);
		var err error
		res.DSS, err = zanocrypto.GenerateDoubleSchnorrSig(rnd, zanocrypto.C_point_G, zanocrypto.C_point_G, contextHash, commitment_to_zero, secret_x, ogc.TxPubKeyP.Point, ogc.TxKey.Sec.Scalar)
		if err != nil {
			return err
		}
	} else {
		// there're ZC inputs => in main balance equation we only need to cancel out X-component, because G-component cancelled out by choosing blinding mask for the last pseudo out amount commitment
		// (sum(bare inputs' amounts) - fee) * H + sum(pseudo out amount commitments) + asset_op_commitment - sum(outputs' commitments) = lin(X)

		// crypto::point_t commitment_to_zero = (crypto::scalar_t(bare_inputs_sum) - crypto::scalar_t(fee)) * currency::native_coin_asset_id_pt + ogc.pseudo_out_amount_commitments_sum + (ogc.ao_commitment_in_outputs ? -ogc.ao_amount_commitment : ogc.ao_amount_commitment) - ogc.amount_commitments_sum
		tot := new(edwards25519.Scalar).Subtract(zanocrypto.ScalarInt(bare_inputs_sum), zanocrypto.ScalarInt(fee))
		tmp1 := new(edwards25519.Point).ScalarMult(tot, zanocrypto.NativeCoinAssetIdPt)
		tmp1 = tmp1.Add(tmp1, ogc.PseudoOutAmountCommitmentsSum.Point)
		if ogc.AoCommitmentInOutputs {
			tmp1 = tmp1.Subtract(tmp1, ogc.AoAmountCommitment.Point)
		} else if ogc.AoAmountCommitment != nil {
			tmp1 = tmp1.Add(tmp1, ogc.AoAmountCommitment.Point)
		}
		tmp1 = tmp1.Subtract(tmp1, ogc.AmountCommitmentsSum.Point)
		commitment_to_zero := tmp1
		// crypto::scalar_t secret_x = ogc.real_in_asset_id_blinding_mask_x_amount_sum - ogc.asset_id_blinding_mask_x_amount_sum
		secret_x := new(edwards25519.Scalar).Subtract(ogc.RealInAssetIdBlindingMaskXAmountSum.Scalar, ogc.AssetIdBlindingMaskXAmountSum.Scalar)
		// bool commitment_to_zero_is_sane = commitment_to_zero == secret_x * crypto::c_point_X
		commitment_to_zero_is_sane := bytes.Equal(commitment_to_zero.Bytes(), new(edwards25519.Point).ScalarMult(secret_x, zanocrypto.C_point_X).Bytes())
		if !commitment_to_zero_is_sane {
			return errors.New("internal error: commitment_to_zero is malformed (X)")
		}
		// crypto::generate_double_schnorr_sig<crypto::gt_X, crypto::gt_G>(tx_id, commitment_to_zero, secret_x, ogc.tx_pub_key_p, ogc.tx_key.sec,
		var err error
		res.DSS, err = zanocrypto.GenerateDoubleSchnorrSig(rnd, zanocrypto.C_point_X, zanocrypto.C_point_G, contextHash, commitment_to_zero, secret_x, ogc.TxPubKeyP.Point, ogc.TxKey.Sec.Scalar)
		if err != nil {
			return err
		}
	}

	tx.Proofs = append(tx.Proofs, &zanobase.Variant{Tag: zanobase.TagZcBalanceProof, Value: res})
	return nil
}
