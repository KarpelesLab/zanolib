//! CLSAG-GGX: the three-layer ring signature Zano uses for confidential inputs.

use super::consts::{C_POINT_G, C_POINT_X, SC_1DIV8};
use super::hash::HashHelper;
use super::hashtoec::hp;
use super::{Point, Scalar, mul8, random_scalar};
use crate::base::sig::ClsagSig;
use crate::error::{Error, Result};
use crate::rng::RngCore;

/// Domain separator for the layer-0 aggregation coefficient.
pub const CRYPTO_HDS_CLSAG_GGX_LAYER_0: &[u8; 32] = b"ZANO_HDS_CLSAG_GGX_LAYER_ZERO__\x00";
/// Domain separator for the layer-1 aggregation coefficient.
pub const CRYPTO_HDS_CLSAG_GGX_LAYER_1: &[u8; 32] = b"ZANO_HDS_CLSAG_GGX_LAYER_ONE___\x00";
/// Domain separator for the layer-2 aggregation coefficient.
pub const CRYPTO_HDS_CLSAG_GGX_LAYER_2: &[u8; 32] = b"ZANO_HDS_CLSAG_GGX_LAYER_TWO___\x00";
/// Domain separator for the ring challenges.
pub const CRYPTO_HDS_CLSAG_GGX_CHALLENGE: &[u8; 32] = b"ZANO_HDS_CLSAG_GGX_CHALLENGE___\x00";

/// One ring member: its stealth address, amount commitment and blinded asset id.
#[derive(Clone, Copy, Debug)]
pub struct ClsagGgxInputRef {
    /// The output's one-time public key.
    pub stealth_address: Point,
    /// The output's amount commitment (as stored on-chain, i.e. times 1/8).
    pub amount_commitment: Point,
    /// The output's blinded asset id (as stored on-chain, i.e. times 1/8).
    pub blinded_asset_id: Point,
}

/// The public values every challenge in the ring is bound to.
struct RingContext {
    input_hash: [u8; 32],
    agg_coeff0: Scalar,
    agg_coeff1: Scalar,
    agg_coeff2: Scalar,
    w_pub_g: Vec<Point>,
    w_pub_x: Vec<Point>,
    w_key_image_g: Point,
    w_key_image_x: Point,
}

/// Computes the input hash, aggregation coefficients and aggregated public keys
/// shared by the signer and the verifier.
fn ring_context(
    m: &[u8],
    ring: &[ClsagGgxInputRef],
    ki: &Point,
    pseudo_out_amount_commitment: &Point,
    pseudo_out_blinded_asset_id: &Point,
    k1_div8: &Point,
    k2_div8: &Point,
) -> RingContext {
    let mut hsc = HashHelper::new();
    hsc.add_bytes_mod_l(m);
    for r in ring {
        hsc.add_point(&r.stealth_address);
        hsc.add_point(&r.amount_commitment);
        hsc.add_point(&r.blinded_asset_id);
    }
    hsc.add_point(&pseudo_out_amount_commitment.mul(&SC_1DIV8));
    hsc.add_point(&pseudo_out_blinded_asset_id.mul(&SC_1DIV8));
    hsc.add_point(ki);
    hsc.add_point(k1_div8);
    hsc.add_point(k2_div8);
    let input_hash = hsc.calc_raw_hash();

    hsc.add_bytes(CRYPTO_HDS_CLSAG_GGX_LAYER_0);
    hsc.add_bytes(&input_hash);
    let agg_coeff0 = hsc.calc_hash();
    hsc.add_bytes(CRYPTO_HDS_CLSAG_GGX_LAYER_1);
    hsc.add_bytes(&input_hash);
    let agg_coeff1 = hsc.calc_hash();
    hsc.add_bytes(CRYPTO_HDS_CLSAG_GGX_LAYER_2);
    hsc.add_bytes(&input_hash);
    let agg_coeff2 = hsc.calc_hash();

    let mut w_pub_g = Vec::with_capacity(ring.len());
    let mut w_pub_x = Vec::with_capacity(ring.len());
    for r in ring {
        let a_i = mul8(&r.amount_commitment);
        let q_i = mul8(&r.blinded_asset_id);
        let term1 = r.stealth_address.mul(&agg_coeff0);
        let term2 = a_i.sub(pseudo_out_amount_commitment).mul(&agg_coeff1);
        w_pub_g.push(term1.add(&term2));
        w_pub_x.push(q_i.sub(pseudo_out_blinded_asset_id).mul(&agg_coeff2));
    }

    let k1 = mul8(k1_div8);
    let k2 = mul8(k2_div8);
    let w_key_image_g = ki.mul(&agg_coeff0).add(&k1.mul(&agg_coeff1));
    let w_key_image_x = k2.mul(&agg_coeff2);

    RingContext {
        input_hash,
        agg_coeff0,
        agg_coeff1,
        agg_coeff2,
        w_pub_g,
        w_pub_x,
        w_key_image_g,
        w_key_image_x,
    }
}

/// One step of the ring: `c_{i+1} = Hs(input_hash, ...)` from the responses at
/// index `i` and the current challenge.
fn ring_step(
    ctx: &RingContext,
    ring: &[ClsagGgxInputRef],
    sig_rg: &Scalar,
    sig_rx: &Scalar,
    i: usize,
    c: &Scalar,
) -> Scalar {
    let hp_i = hp(&ring[i].stealth_address.compress());
    let mut h = HashHelper::new();
    h.add_bytes(CRYPTO_HDS_CLSAG_GGX_CHALLENGE);
    h.add_bytes(&ctx.input_hash);
    h.add_point(&C_POINT_G.mul(sig_rg).add(&ctx.w_pub_g[i].mul(c)));
    h.add_point(&hp_i.mul(sig_rg).add(&ctx.w_key_image_g.mul(c)));
    h.add_point(&C_POINT_X.mul(sig_rx).add(&ctx.w_pub_x[i].mul(c)));
    h.add_point(&hp_i.mul(sig_rx).add(&ctx.w_key_image_x.mul(c)));
    h.calc_hash()
}

/// Generates a CLSAG-GGX ring signature.
///
/// The three layers authenticate, in order: the stealth address (secret
/// `secret_0_xp`), the amount blinding mask difference (`secret_1_f`) and the
/// asset id blinding mask (`secret_2_t`).
#[allow(clippy::too_many_arguments)]
pub fn generate_clsag_ggx(
    rnd: &mut dyn RngCore,
    m: &[u8],
    ring: &[ClsagGgxInputRef],
    ki: &Point,
    pseudo_out_amount_commitment: &Point,
    pseudo_out_blinded_asset_id: &Point,
    secret_0_xp: &Scalar,
    secret_1_f: &Scalar,
    secret_2_t: &Scalar,
    secret_index: u64,
) -> Result<ClsagSig> {
    let ring_size = ring.len();
    if ring_size == 0 {
        return Err(Error::msg("ring size is zero"));
    }
    if secret_index >= ring_size as u64 {
        return Err(Error::msg("secretIndex out of range"));
    }
    let real = secret_index as usize;

    // ki_base = Hp(real stealth address); key_image = secret_0_xp * ki_base
    let ki_base = hp(&ring[real].stealth_address.compress());
    let key_image = ki_base.mul(secret_0_xp);

    // Sanity checks, mostly useful while debugging a caller.
    if key_image != *ki {
        return Err(Error::msg("CLSAG_GGX keyImage mismatch"));
    }
    if C_POINT_G.mul(secret_0_xp) != ring[real].stealth_address {
        return Err(Error::msg("CLSAG_GGX secret_0_xp mismatch"));
    }
    if C_POINT_G.mul(secret_1_f)
        != mul8(&ring[real].amount_commitment).sub(pseudo_out_amount_commitment)
    {
        return Err(Error::msg("CLSAG_GGX secret_1_f mismatch"));
    }
    if C_POINT_X.mul(secret_2_t)
        != mul8(&ring[real].blinded_asset_id).sub(pseudo_out_blinded_asset_id)
    {
        return Err(Error::msg("CLSAG_GGX secret_2_t mismatch"));
    }

    // Auxiliary key images for layers 1 and 2, stored premultiplied by 1/8.
    let k1_div8 = ki_base.mul(&SC_1DIV8.mul(secret_1_f));
    let k2_div8 = ki_base.mul(&SC_1DIV8.mul(secret_2_t));

    let ctx = ring_context(
        m,
        ring,
        ki,
        pseudo_out_amount_commitment,
        pseudo_out_blinded_asset_id,
        &k1_div8,
        &k2_div8,
    );

    // Aggregated secrets, checked against the aggregated public keys.
    let w_sec_key_g = ctx
        .agg_coeff0
        .mul(secret_0_xp)
        .add(&ctx.agg_coeff1.mul(secret_1_f));
    let w_sec_key_x = ctx.agg_coeff2.mul(secret_2_t);
    if C_POINT_G.mul(&w_sec_key_g) != ctx.w_pub_g[real] {
        return Err(Error::msg("CLSAG_GGX w_sec_key_g mismatch"));
    }
    if C_POINT_X.mul(&w_sec_key_x) != ctx.w_pub_x[real] {
        return Err(Error::msg("CLSAG_GGX w_sec_key_x mismatch"));
    }

    // Initial commitment.
    let alpha_g = random_scalar(rnd);
    let alpha_x = random_scalar(rnd);

    let mut hsc = HashHelper::new();
    hsc.add_bytes(CRYPTO_HDS_CLSAG_GGX_CHALLENGE);
    hsc.add_bytes(&ctx.input_hash);
    hsc.add_point(&C_POINT_G.mul(&alpha_g));
    hsc.add_point(&ki_base.mul(&alpha_g));
    hsc.add_point(&C_POINT_X.mul(&alpha_x));
    hsc.add_point(&ki_base.mul(&alpha_x));
    let mut c_prev = hsc.calc_hash();

    // Decoy responses.
    let mut rg: Vec<Scalar> = (0..ring_size).map(|_| random_scalar(rnd)).collect();
    let mut rx: Vec<Scalar> = (0..ring_size).map(|_| random_scalar(rnd)).collect();
    let mut sig_c: Option<Scalar> = None;

    let mut i = (real + 1) % ring_size;
    for _ in 0..ring_size - 1 {
        if i == 0 {
            sig_c = Some(c_prev.clone());
        }
        c_prev = ring_step(&ctx, ring, &rg[i], &rx[i], i, &c_prev);
        i = (i + 1) % ring_size;
    }
    if real == 0 {
        sig_c = Some(c_prev.clone());
    }

    rg[real] = alpha_g.sub(&c_prev.mul(&w_sec_key_g));
    rx[real] = alpha_x.sub(&c_prev.mul(&w_sec_key_x));

    Ok(ClsagSig {
        c: sig_c.expect("the ring always sets c"),
        rg,
        rx,
        k1: k1_div8,
        k2: k2_div8,
    })
}

/// Verifies a CLSAG-GGX ring signature: walks the ring of challenges from
/// `sig.c` and checks that it closes back on itself.
pub fn verify_clsag_ggx(
    m: &[u8],
    ring: &[ClsagGgxInputRef],
    ki: &Point,
    pseudo_out_amount_commitment: &Point,
    pseudo_out_blinded_asset_id: &Point,
    sig: &ClsagSig,
) -> Result<bool> {
    let ring_size = ring.len();
    if ring_size == 0 {
        return Err(Error::msg("ring size is zero"));
    }
    if sig.rg.len() != ring_size || sig.rx.len() != ring_size {
        return Err(Error::msg("malformed signature"));
    }

    let ctx = ring_context(
        m,
        ring,
        ki,
        pseudo_out_amount_commitment,
        pseudo_out_blinded_asset_id,
        &sig.k1,
        &sig.k2,
    );

    let mut c = sig.c.clone();
    for i in 0..ring_size {
        c = ring_step(&ctx, ring, &sig.rg[i], &sig.rx[i], i, &c);
    }
    Ok(c == sig.c)
}
