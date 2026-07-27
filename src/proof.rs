//! Transaction-wide proofs: balance, output range, and asset surjection.

use crate::base::gencontext::GenContext;
use crate::base::sig::{ZcAssetSurjectionProof, ZcBalanceProof, ZcOutsRangeProof};
use crate::base::tx::Transaction;
use crate::base::variant::Variant;
use crate::crypto::bpp::TRAIT_ZC_OUT;
use crate::crypto::consts::{C_POINT_G, C_POINT_U, C_POINT_X, NATIVE_COIN_ASSET_ID_PT};
use crate::crypto::{
    Point, Scalar, double_scalar_base_mult, generate_bge_proof, generate_double_schnorr_sig,
    generate_vector_ug_aggregation_proof, random_scalar, scalar_int,
};
use crate::error::{Error, Result};
use crate::rng::RngCore;

/// Proves that inputs equal outputs plus fee, appending the proof to `tx`.
pub fn generate_tx_balance_proof(
    rnd: &mut dyn RngCore,
    tx: &mut Transaction,
    context_hash: &[u8],
    ogc: &GenContext,
    block_reward_for_miner_tx: u64,
) -> Result<()> {
    let bare_inputs_sum = block_reward_for_miner_tx;
    let zc_inputs_count = tx.zc_inputs_count();
    let fee = tx.fee().ok_or_else(|| Error::msg("unable to get tx fee"))?;

    let tx_pub_key = ogc
        .tx_pub_key_p
        .ok_or_else(|| Error::msg("gen context has no tx public key"))?;
    let tx_sec_key = ogc
        .tx_key
        .as_ref()
        .ok_or_else(|| Error::msg("gen context has no tx key pair"))?
        .sec
        .clone();

    let total = scalar_int(bare_inputs_sum).sub(&scalar_int(fee));
    let amount_commitments_sum = GenContext::point_or_identity(&ogc.amount_commitments_sum);

    let dss = if zc_inputs_count == 0 {
        // No ZC inputs: every output has an explicit native asset id, so only
        // the G-component needs to cancel.
        let commitment_to_zero = NATIVE_COIN_ASSET_ID_PT
            .mul(&total)
            .sub(&amount_commitments_sum);
        let secret_x = GenContext::scalar_or_zero(&ogc.amount_blinding_masks_sum).negate();
        if commitment_to_zero != C_POINT_G.mul(&secret_x) {
            return Err(Error::msg(
                "internal error: commitment_to_zero is malformed (G)",
            ));
        }
        generate_double_schnorr_sig(
            rnd,
            &C_POINT_G,
            &C_POINT_G,
            context_hash,
            &commitment_to_zero,
            &secret_x,
            &tx_pub_key,
            &tx_sec_key,
        )?
    } else {
        // With ZC inputs only the X-component needs to cancel: the G-component
        // is handled by the last pseudo-output's blinding mask.
        let mut c = NATIVE_COIN_ASSET_ID_PT.mul(&total);
        c = c.add(&GenContext::point_or_identity(
            &ogc.pseudo_out_amount_commitments_sum,
        ));
        if let Some(ao) = &ogc.ao_amount_commitment {
            c = if ogc.ao_commitment_in_outputs {
                c.sub(ao)
            } else {
                c.add(ao)
            };
        }
        let commitment_to_zero = c.sub(&amount_commitments_sum);
        let secret_x = GenContext::scalar_or_zero(&ogc.real_in_asset_id_blinding_mask_x_amount_sum)
            .sub(&GenContext::scalar_or_zero(
                &ogc.asset_id_blinding_mask_x_amount_sum,
            ));
        if commitment_to_zero != C_POINT_X.mul(&secret_x) {
            return Err(Error::msg(
                "internal error: commitment_to_zero is malformed (X)",
            ));
        }
        generate_double_schnorr_sig(
            rnd,
            &C_POINT_X,
            &C_POINT_G,
            context_hash,
            &commitment_to_zero,
            &secret_x,
            &tx_pub_key,
            &tx_sec_key,
        )?
    };

    tx.proofs
        .push(Variant::ZcBalanceProof(ZcBalanceProof { dss }));
    Ok(())
}

/// Proves every output amount is in `[0, 2^64)`, appending the proof to `tx`.
pub fn generate_zc_outs_range_proof(
    rnd: &mut dyn RngCore,
    tx: &mut Transaction,
    context_hash: &[u8],
    ogc: &GenContext,
) -> Result<()> {
    let outs_count = ogc.amounts.len();
    if outs_count != tx.vout.len() {
        return Err(Error::msg(
            "generate_zc_outs_range_proof: vout count not matching",
        ));
    }

    // E'_j = e_j * U + y'_j * G
    let mut amount_commitments_for_rp_aggregation = Vec::with_capacity(outs_count);
    let mut y_primes: Vec<Scalar> = Vec::with_capacity(outs_count);
    for i in 0..outs_count {
        let y_prime = random_scalar(rnd);
        amount_commitments_for_rp_aggregation.push(double_scalar_base_mult(
            &ogc.amounts[i],
            &C_POINT_U,
            &y_prime,
        ));
        y_primes.push(y_prime);
    }

    let aggregation_proof = generate_vector_ug_aggregation_proof(
        rnd,
        context_hash,
        &ogc.amounts,
        &ogc.amount_blinding_masks,
        &y_primes,
        &ogc.amount_commitments,
        &amount_commitments_for_rp_aggregation,
        &ogc.blinded_asset_ids,
    )?;

    let bpp = TRAIT_ZC_OUT.bpp_gen(
        rnd,
        &ogc.amounts,
        &y_primes,
        &aggregation_proof.amount_commitments_for_rp_agg,
    )?;

    tx.proofs.push(Variant::ZcOutsRangeProof(ZcOutsRangeProof {
        bpp,
        aggregation_proof,
    }));
    Ok(())
}

/// Proves each output's asset type matches one of the inputs', appending the
/// proof to `tx`.
pub fn generate_asset_surjection_proof(
    rnd: &mut dyn RngCore,
    tx: &mut Transaction,
    context_hash: &[u8],
    ogc: &GenContext,
) -> Result<()> {
    let outs_count = ogc.blinded_asset_ids.len();
    if outs_count == 0 {
        return Err(Error::msg("blinded_asset_ids shouldn't be empty"));
    }
    let zc_ins_count = ogc.pseudo_outs_blinded_asset_ids.len();

    let mut bge_proofs = Vec::with_capacity(outs_count);
    for j in 0..outs_count {
        let h = ogc.asset_ids[j];
        let t = ogc.blinded_asset_ids[j];

        let mut ring: Vec<Point> = Vec::with_capacity(zc_ins_count);
        let mut secret = ogc.asset_id_blinding_masks[j].negate();
        let mut secret_index: Option<usize> = None;

        for i in 0..zc_ins_count {
            ring.push(ogc.pseudo_outs_blinded_asset_ids[i].sub(&t));
            if secret_index.is_none() && ogc.real_zc_ins_asset_ids[i] == h {
                secret_index = Some(i);
                secret = secret.add(&ogc.pseudo_outs_plus_real_out_blinding_masks[i]);
            }
        }

        // TODO: extra ring members for native coins in txs with non-ZC inputs,
        // and for asset-emitting operations.

        let secret_index = secret_index.ok_or_else(|| {
            crate::err!(
                "out #{j}: cannot find a corresponding asset id in inputs or asset operations; asset id: {}",
                hex::encode(h.compress())
            )
        })?;

        bge_proofs.push(generate_bge_proof(
            rnd,
            context_hash,
            &ring,
            &secret,
            secret_index,
        )?);
    }

    tx.proofs
        .push(Variant::ZcAssetSurjectionProof(ZcAssetSurjectionProof {
            bge_proofs,
        }));
    Ok(())
}
