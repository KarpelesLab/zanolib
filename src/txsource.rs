//! Transaction sources (outputs to spend) and their per-input signature.

use crate::base::gencontext::GenContext;
use crate::base::ser::{EpeeRead, EpeeWrite, Reader, write_vec};
use crate::base::sig::ZcSig;
use crate::base::tx::Transaction;
use crate::base::types::Value256;
use crate::base::variant::Variant;
use crate::crypto::clsag::ClsagGgxInputRef;
use crate::crypto::consts::{C_POINT_X, SC_1DIV8};
use crate::crypto::{Point, Scalar, double_scalar_base_mult, random_scalar, scalar_int};
use crate::error::{Error, Result};
use crate::inputsigner::{ClsagRequest, InputSigner};
use crate::rng::RngCore;

/// One ring member of a source: the referenced output and its public data.
#[derive(Clone, Debug)]
pub struct TxSourceOutputEntry {
    /// Either a global output index or a `ref_by_id`.
    pub out_reference: Variant,
    /// The output's one-time public key.
    pub stealth_address: Point,
    /// Concealing point (confidential outputs only).
    pub concealing_point: Point,
    /// Amount commitment (confidential outputs only).
    pub amount_commitment: Point,
    /// Blinded asset id (confidential outputs only).
    pub blinded_asset_id: Point,
}

impl EpeeWrite for TxSourceOutputEntry {
    fn write_epee(&self, out: &mut Vec<u8>) {
        self.out_reference.write_epee(out);
        self.stealth_address.write_epee(out);
        self.concealing_point.write_epee(out);
        self.amount_commitment.write_epee(out);
        self.blinded_asset_id.write_epee(out);
    }
}
impl EpeeRead for TxSourceOutputEntry {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        Ok(TxSourceOutputEntry {
            out_reference: Variant::read_epee(r)?,
            stealth_address: Point::read_epee(r)?,
            concealing_point: Point::read_epee(r)?,
            amount_commitment: Point::read_epee(r)?,
            blinded_asset_id: Point::read_epee(r)?,
        })
    }
}

/// An input to spend: its ring, which member is real, and the blinding masks
/// recovered when the output was received.
#[derive(Clone, Debug)]
pub struct TxSource {
    /// The ring (decoys plus the real output), in global-index order.
    pub outputs: Vec<TxSourceOutputEntry>,
    /// Index of the real output within `outputs`.
    pub real_output: u64,
    /// Transaction public key of the depositing transaction.
    pub real_out_tx_key: Point,
    /// Amount blinding mask of the real output.
    pub real_out_amount_blinding_mask: Scalar,
    /// Asset id blinding mask of the real output.
    pub real_out_asset_id_blinding_mask: Scalar,
    /// Index of the real output within the depositing transaction.
    pub real_out_in_tx_index: u64,
    /// Amount held by the real output.
    pub amount: u64,
    /// Index into the wallet's transfer list.
    pub transfer_index: u64,
    /// Multisig output id, if this is a multisig input.
    pub multisig_id: Value256,
    /// Required multisig signature count.
    pub ms_sigs_count: u64,
    /// Multisig key count.
    pub ms_keys_count: u64,
    /// Whether this input completes a separately-signed transaction.
    pub separately_signed_tx_complete: bool,
    /// HTLC origin, for HTLC inputs.
    pub htlc_origin: String,

    // The fields below are set by the in-package transfer builder and are not
    // part of the serialized blob.
    /// Unblinded source asset id (native coin for plain transfers).
    pub asset_id: Option<Point>,
    /// Set when the source is a Zarcanum output, regardless of mask values.
    pub is_zc_input: bool,
    /// Public per-output scalar `Hs(8*v*R, idx)`; `secret0Xp = hi + x`.
    pub hi: Option<Scalar>,
}

impl EpeeWrite for TxSource {
    fn write_epee(&self, out: &mut Vec<u8>) {
        write_vec(&self.outputs, out);
        self.real_output.write_epee(out);
        self.real_out_tx_key.write_epee(out);
        self.real_out_amount_blinding_mask.write_epee(out);
        self.real_out_asset_id_blinding_mask.write_epee(out);
        self.real_out_in_tx_index.write_epee(out);
        self.amount.write_epee(out);
        self.transfer_index.write_epee(out);
        self.multisig_id.write_epee(out);
        self.ms_sigs_count.write_epee(out);
        self.ms_keys_count.write_epee(out);
        self.separately_signed_tx_complete.write_epee(out);
        self.htlc_origin.write_epee(out);
    }
}
impl EpeeRead for TxSource {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        Ok(TxSource {
            outputs: r.read_vec()?,
            real_output: u64::read_epee(r)?,
            real_out_tx_key: Point::read_epee(r)?,
            real_out_amount_blinding_mask: Scalar::read_epee(r)?,
            real_out_asset_id_blinding_mask: Scalar::read_epee(r)?,
            real_out_in_tx_index: u64::read_epee(r)?,
            amount: u64::read_epee(r)?,
            transfer_index: u64::read_epee(r)?,
            multisig_id: Value256::read_epee(r)?,
            ms_sigs_count: u64::read_epee(r)?,
            ms_keys_count: u64::read_epee(r)?,
            separately_signed_tx_complete: bool::read_epee(r)?,
            htlc_origin: String::read_epee(r)?,
            asset_id: None,
            is_zc_input: false,
            hi: None,
        })
    }
}

impl TxSource {
    /// Whether this is a confidential (Zarcanum) input.
    ///
    /// True when explicitly flagged (set when built from a Zarcanum output) or,
    /// for sources parsed from an unsigned-tx blob, when the asset id blinding
    /// mask is non-zero.
    pub fn is_zc(&self) -> bool {
        self.is_zc_input || self.real_out_asset_id_blinding_mask != Scalar::ZERO
    }

    /// Builds the confidential signature for this input, filling in the
    /// pseudo-output commitments and accumulating into `ogc`.
    ///
    /// `last_output` must be true for the final input of a transaction: its
    /// pseudo-output blinding mask is chosen (rather than random) so the
    /// G-components of the balance equation cancel.
    #[allow(clippy::too_many_arguments)]
    pub fn generate_zc_sig(
        &self,
        rnd: &mut dyn RngCore,
        tx: &Transaction,
        input_index: usize,
        tx_hash_for_sig: &[u8],
        ogc: &mut GenContext,
        last_output: bool,
        signer: &mut dyn InputSigner,
    ) -> Result<ZcSig> {
        let vin = tx.vin[input_index]
            .as_txin_zc_input()
            .ok_or_else(|| Error::msg("input is not a txin_zc_input"))?;

        // Each source carries its own unblinded asset id; fall back to the first
        // destination's asset for single-asset sources parsed from a blob.
        let asset_id = match self.asset_id {
            Some(p) => p,
            None => *ogc
                .asset_ids
                .first()
                .ok_or_else(|| Error::msg("no asset id available for input"))?,
        };

        // T_i = H_i + r_i * X
        let source_blinded_asset_id =
            asset_id.add(&C_POINT_X.mul(&self.real_out_asset_id_blinding_mask));
        ogc.real_zc_ins_asset_ids.push(asset_id);

        let pseudo_out_amount_blinding_mask = if last_output {
            // Either a normal tx or the last signature of a consolidated one:
            // pick the mask so the G-components cancel out.
            //   f'_{i-1} = sum{y_j} - sum{f'_i} (+/- the asset-operation mask)
            let mut ao_term = GenContext::scalar_or_zero(&ogc.ao_amount_blinding_mask);
            if !ogc.ao_commitment_in_outputs {
                ao_term = ao_term.negate();
            }
            let mut m = GenContext::scalar_or_zero(&ogc.amount_blinding_masks_sum);
            if let Some(sum) = &ogc.pseudo_out_amount_blinding_masks_sum {
                m = m.sub(sum);
            }
            m.add(&ao_term)
        } else {
            let m = random_scalar(rnd);
            GenContext::add_scalar(&mut ogc.pseudo_out_amount_blinding_masks_sum, &m);
            m
        };

        let pseudo_out_asset_id_blinding_mask = random_scalar(rnd);

        // T^p_i = T_i + r'_i * X
        let pseudo_out_blinded_asset_id =
            source_blinded_asset_id.add(&C_POINT_X.mul(&pseudo_out_asset_id_blinding_mask));

        // += r_i * a_i
        GenContext::add_scalar(
            &mut ogc.real_in_asset_id_blinding_mask_x_amount_sum,
            &self
                .real_out_asset_id_blinding_mask
                .mul(&scalar_int(self.amount)),
        );

        ogc.pseudo_outs_blinded_asset_ids
            .push(pseudo_out_blinded_asset_id);
        ogc.pseudo_outs_plus_real_out_blinding_masks
            .push(pseudo_out_asset_id_blinding_mask.add(&self.real_out_asset_id_blinding_mask));

        // A^p_i = a_i * T_i + f'_i * G
        let pseudo_out_amount_commitment = double_scalar_base_mult(
            &scalar_int(self.amount),
            &source_blinded_asset_id,
            &pseudo_out_amount_blinding_mask,
        );
        GenContext::add_point(
            &mut ogc.pseudo_out_amount_commitments_sum,
            &pseudo_out_amount_commitment,
        );

        // Three-layer ring signature:
        //   layer 0: stealth addresses,  secret = in_ephemeral.sec (via signer)
        //   layer 1: amount commitments, secret = real mask - pseudo-out mask
        //   layer 2: blinded asset ids,  secret = -pseudo-out asset mask
        let ring: Vec<ClsagGgxInputRef> = self
            .outputs
            .iter()
            .map(|o| ClsagGgxInputRef {
                stealth_address: o.stealth_address,
                amount_commitment: o.amount_commitment,
                blinded_asset_id: o.blinded_asset_id,
            })
            .collect();

        let secret1_f = self
            .real_out_amount_blinding_mask
            .sub(&pseudo_out_amount_blinding_mask);
        let secret2_t = pseudo_out_asset_id_blinding_mask.negate();
        let hi = self
            .hi
            .as_ref()
            .ok_or_else(|| Error::msg("source is missing its per-output scalar"))?;

        let ggx = signer.sign_clsag(
            rnd,
            &ClsagRequest {
                hi,
                msg: tx_hash_for_sig,
                ring: &ring,
                key_image: &vin.key_image,
                pseudo_out_amount_commitment: &pseudo_out_amount_commitment,
                pseudo_out_blinded_asset_id: &pseudo_out_blinded_asset_id,
                secret1_f: &secret1_f,
                secret2_t: &secret2_t,
                secret_index: self.real_output,
            },
        )?;

        Ok(ZcSig {
            pseudo_out_amount_commitment: pseudo_out_amount_commitment.mul(&SC_1DIV8),
            pseudo_out_blinded_asset_id: pseudo_out_blinded_asset_id.mul(&SC_1DIV8),
            ggx,
        })
    }
}
