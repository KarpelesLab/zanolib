//! Zarcanum-specific proofs: the vector UG aggregation proof and the generic
//! double Schnorr signature.

use super::consts::{C_POINT_U, SC_1DIV8};
use super::hash::HashHelper;
use super::{Point, Scalar, double_scalar_base_mult, random_scalar};
use crate::base::sig::{GenericDoubleSchnorrSig, UgAggProof};
use crate::error::{Error, Result};
use crate::rng::RngCore;

/// Proves, for every output `j`, knowledge of `e_j` and `y''_j` in
/// `E_j + w*E'_j = e_j*(T'_j + w*U) + (y_j + w*y'_j)*G`, linking each amount
/// commitment to the commitment the range proof aggregates over.
#[allow(clippy::too_many_arguments)]
pub fn generate_vector_ug_aggregation_proof(
    rnd: &mut dyn RngCore,
    context_hash: &[u8],
    u_secrets: &[Scalar],
    g_secrets0: &[Scalar],
    g_secrets1: &[Scalar],
    amount_commitments: &[Point],
    amount_commitments_for_rp_aggregation: &[Point],
    blinded_asset_ids: &[Point],
) -> Result<UgAggProof> {
    let n = u_secrets.len();
    if n == 0 {
        return Err(Error::msg(
            "generate_vector_ug_aggregation_proof: empty secrets",
        ));
    }
    for (name, len) in [
        ("gSecrets0", g_secrets0.len()),
        ("gSecrets1", g_secrets1.len()),
        ("amountCommitments", amount_commitments.len()),
        (
            "amountCommitmentsForRpAggregation",
            amount_commitments_for_rp_aggregation.len(),
        ),
        ("blindedAssetIds", blinded_asset_ids.len()),
    ] {
        if len != n {
            return Err(crate::err!(
                "generate_vector_ug_aggregation_proof: invalid length for {name}"
            ));
        }
    }

    let mut hsc = HashHelper::new();
    hsc.add_bytes(context_hash);
    hsc.add_points(amount_commitments);
    hsc.add_points(amount_commitments_for_rp_aggregation);
    let w = hsc.calc_hash_keep(); // deliberately keeps the buffer

    let r0: Vec<Scalar> = (0..n).map(|_| random_scalar(rnd)).collect();
    let r1: Vec<Scalar> = (0..n).map(|_| random_scalar(rnd)).collect();

    let asset_tag_plus_u: Vec<Point> = blinded_asset_ids
        .iter()
        .map(|t| t.add(&C_POINT_U.mul(&w)))
        .collect();

    let big_r: Vec<Point> = (0..n)
        .map(|j| double_scalar_base_mult(&r0[j], &asset_tag_plus_u[j], &r1[j]))
        .collect();
    hsc.add_points(&big_r);

    let c = hsc.calc_hash();

    let mut y0s = Vec::with_capacity(n);
    let mut y1s = Vec::with_capacity(n);
    let mut agg = Vec::with_capacity(n);
    for j in 0..n {
        y0s.push(r0[j].sub(&c.mul(&u_secrets[j])));
        let combined = g_secrets0[j].add(&w.mul(&g_secrets1[j]));
        y1s.push(r1[j].sub(&c.mul(&combined)));
        agg.push(amount_commitments_for_rp_aggregation[j].mul(&SC_1DIV8));
    }

    Ok(UgAggProof {
        amount_commitments_for_rp_agg: agg,
        y0s,
        y1s,
        c,
    })
}

/// Proves knowledge of `secret_a` with `A = secret_a * gen0` and `secret_b`
/// with `B = secret_b * gen1`, in one signature.
#[allow(clippy::too_many_arguments)]
pub fn generate_double_schnorr_sig(
    rnd: &mut dyn RngCore,
    gen0: &Point,
    gen1: &Point,
    m: &[u8],
    big_a: &Point,
    secret_a: &Scalar,
    big_b: &Point,
    secret_b: &Scalar,
) -> Result<GenericDoubleSchnorrSig> {
    let r0 = random_scalar(rnd);
    let r1 = random_scalar(rnd);
    let big_r0 = gen0.mul(&r0);
    let big_r1 = gen1.mul(&r1);

    let mut hsc = HashHelper::new();
    hsc.add_bytes(m);
    hsc.add_point(big_a);
    hsc.add_point(big_b);
    hsc.add_point(&big_r0);
    hsc.add_point(&big_r1);
    let c = hsc.calc_hash();

    Ok(GenericDoubleSchnorrSig {
        y0: r0.sub(&c.mul(secret_a)),
        y1: r1.sub(&c.mul(secret_b)),
        c,
    })
}
