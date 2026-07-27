//! The generation context threaded through transaction construction.

use super::types::KeyPair;
use crate::crypto::{Point, Scalar};

/// Accumulates the per-output commitments, blinding masks and running sums that
/// the signatures and proofs are built from.
///
/// Fields that the Go original left as nil pointers until first use are
/// [`Option`]s here; [`GenContext::add_scalar`] / [`GenContext::add_point`]
/// reproduce its accumulate-or-initialize behaviour.
#[derive(Clone, Debug, Default)]
pub struct GenContext {
    /// Unblinded asset id per output.
    pub asset_ids: Vec<Point>,
    /// Blinded asset id `T'_j` per output.
    pub blinded_asset_ids: Vec<Point>,
    /// Amount commitment per output.
    pub amount_commitments: Vec<Point>,
    /// Asset id blinding mask `s_j` per output.
    pub asset_id_blinding_masks: Vec<Scalar>,
    /// Amount per output, as a scalar.
    pub amounts: Vec<Scalar>,
    /// Amount blinding mask `y_j` per output.
    pub amount_blinding_masks: Vec<Scalar>,
    /// Blinded asset id of each pseudo output.
    pub pseudo_outs_blinded_asset_ids: Vec<Point>,
    /// `r_i + r'_i` per input.
    pub pseudo_outs_plus_real_out_blinding_masks: Vec<Scalar>,
    /// Unblinded asset id of each real (spent) confidential input.
    pub real_zc_ins_asset_ids: Vec<Point>,
    /// Amount of each confidential input.
    pub zc_input_amounts: Vec<u64>,
    /// Sum of the pseudo-output amount commitments.
    pub pseudo_out_amount_commitments_sum: Option<Point>,
    /// Sum of the pseudo-output amount blinding masks.
    pub pseudo_out_amount_blinding_masks_sum: Option<Scalar>,
    /// `sum(r_i * a_i)` over real inputs.
    pub real_in_asset_id_blinding_mask_x_amount_sum: Option<Scalar>,
    /// Sum of the outputs' amount commitments.
    pub amount_commitments_sum: Option<Point>,
    /// Sum of the outputs' amount blinding masks.
    pub amount_blinding_masks_sum: Option<Scalar>,
    /// `sum(s_j * e_j)` over outputs.
    pub asset_id_blinding_mask_x_amount_sum: Option<Scalar>,
    /// Asset-operation asset id.
    pub ao_asset_id: Option<Point>,
    /// Asset-operation asset id, as a point.
    pub ao_asset_id_pt: Option<Point>,
    /// Asset-operation amount commitment.
    pub ao_amount_commitment: Option<Point>,
    /// Asset-operation amount blinding mask.
    pub ao_amount_blinding_mask: Option<Scalar>,
    /// Whether the asset-operation commitment sits in the outputs.
    pub ao_commitment_in_outputs: bool,
    /// The transaction key pair.
    pub tx_key: Option<KeyPair>,
    /// The transaction public key.
    pub tx_pub_key_p: Option<Point>,
}

impl GenContext {
    /// Grows (or truncates) the per-input and per-output vectors.
    pub fn resize(&mut self, in_cnt: usize, out_cnt: usize) {
        self.asset_ids.resize_with(out_cnt, Point::identity);
        self.blinded_asset_ids.resize_with(out_cnt, Point::identity);
        self.amount_commitments
            .resize_with(out_cnt, Point::identity);
        self.asset_id_blinding_masks
            .resize_with(out_cnt, || Scalar::ZERO);
        self.amounts.resize_with(out_cnt, || Scalar::ZERO);
        self.amount_blinding_masks
            .resize_with(out_cnt, || Scalar::ZERO);
        self.zc_input_amounts.resize(in_cnt, 0);
    }

    /// `*slot += v`, initializing the slot on first use.
    pub fn add_scalar(slot: &mut Option<Scalar>, v: &Scalar) {
        *slot = Some(match slot {
            Some(cur) => cur.add(v),
            None => v.clone(),
        });
    }

    /// `*slot += v`, initializing the slot on first use.
    pub fn add_point(slot: &mut Option<Point>, v: &Point) {
        *slot = Some(match slot {
            Some(cur) => cur.add(v),
            None => *v,
        });
    }

    /// The accumulated value, or zero if nothing was ever added.
    pub fn scalar_or_zero(slot: &Option<Scalar>) -> Scalar {
        slot.clone().unwrap_or(Scalar::ZERO)
    }

    /// The accumulated value, or the identity if nothing was ever added.
    pub fn point_or_identity(slot: &Option<Point>) -> Point {
        slot.unwrap_or_else(Point::identity)
    }
}
