//! Threshold CLSAG-GGX: the per-party and coordinator halves.
//!
//! Layer 0 (the spend key) is the only part that touches the threshold secret;
//! layers 1 and 2 use per-transaction blinding masks that every party knows, so
//! they are computed publicly.

use super::sign::{additive_share, combine_points};
use crate::base::sig::ClsagSig;
use crate::crypto::clsag::{
    CRYPTO_HDS_CLSAG_GGX_CHALLENGE, CRYPTO_HDS_CLSAG_GGX_LAYER_0, CRYPTO_HDS_CLSAG_GGX_LAYER_1,
    CRYPTO_HDS_CLSAG_GGX_LAYER_2, ClsagGgxInputRef,
};
use crate::crypto::consts::{C_POINT_G, C_POINT_X, SC_1DIV8};
use crate::crypto::{HashHelper, Point, Scalar, hp, mul8, random_scalar};
use crate::error::{Error, Result};
use crate::rng::RngCore;
use tsslib::frosttss::Key;

/// One signer in a threshold CLSAG-GGX signature.
///
/// It holds only the Lagrange-weighted additive share `w` (the sum over the
/// committee is the group spend secret `x`) and a fresh per-signature nonce.
/// No party ever sees `x` or another party's share.
pub struct ClsagParty {
    w: Scalar,
    alpha_g: Scalar,
}

impl ClsagParty {
    /// Builds a signer from a key share already reindexed to the signing
    /// committee. If `alpha_g` is `None` a fresh nonce is sampled from `rnd`;
    /// tests may inject one.
    pub fn new(key: &Key, alpha_g: Option<Scalar>, rnd: &mut dyn RngCore) -> Result<ClsagParty> {
        Ok(ClsagParty {
            w: additive_share(key)?,
            alpha_g: alpha_g.unwrap_or_else(|| random_scalar(rnd)),
        })
    }

    /// Round 1: this party's partial key image `w*kiBase` and its nonce
    /// commitments `alphaG*G` and `alphaG*kiBase`.
    pub fn round1(&self, ki_base: &Point) -> (Point, Point, Point) {
        (
            ki_base.mul(&self.w),
            Point::mul_base(&self.alpha_g),
            ki_base.mul(&self.alpha_g),
        )
    }

    /// Round 2: this party's partial layer-0 response
    /// `alphaG - cPrev*aggCoeff0*w`.
    pub fn round2(&self, c_prev: &Scalar, agg_coeff0: &Scalar) -> Scalar {
        self.alpha_g.sub(&c_prev.mul(agg_coeff0).mul(&self.w))
    }
}

/// The public signing context for one Zano confidential input, identical across
/// every signer.
///
/// `secret0Xp = hi + x`, where `hi` is the public per-output scalar
/// (`Hs(8*v*R, output_index)`) and `x` is the threshold spend secret.
pub struct ClsagContext<'a> {
    /// The 32-byte transaction hash being signed.
    pub message: &'a [u8],
    /// The ring, in on-chain order.
    pub ring: &'a [ClsagGgxInputRef],
    /// The pseudo-output amount commitment.
    pub pseudo_out_amount_commitment: &'a Point,
    /// The pseudo-output blinded asset id.
    pub pseudo_out_blinded_asset_id: &'a Point,
    /// Layer-1 secret (a per-tx blinding mask, not the spend key).
    pub secret1_f: &'a Scalar,
    /// Layer-2 secret (a per-tx blinding mask, not the spend key).
    pub secret2_t: &'a Scalar,
    /// The public per-output scalar.
    pub hi: &'a Scalar,
    /// The group spend public key `x*G`.
    pub spend_pub: &'a Point,
    /// Index of the real output within the ring.
    pub secret_index: u64,
}

/// Drives the threshold CLSAG-GGX signature for one input.
///
/// It knows everything public — the ring, the key-image base, the per-tx
/// blinding masks and `hi` — and never learns `x`.
pub struct ClsagCoordinator {
    ki_base: Point,
    ki: Option<Point>,
    input_hash: [u8; 32],
    agg_coeff0: Scalar,
    agg_coeff1: Scalar,
    c_prev: Scalar,
    sig: Option<ClsagSig>,
}

impl ClsagCoordinator {
    /// `Hp(real stealth address)`; parties need it for round 1.
    pub fn ki_base(ctx: &ClsagContext<'_>) -> Point {
        hp(&ctx.ring[ctx.secret_index as usize]
            .stealth_address
            .compress())
    }

    /// Consumes the parties' round-1 outputs, assembles the key image, runs the
    /// public ring of challenges, and returns `(cPrev, aggCoeff0)` for round 2.
    pub fn phase1(
        rnd: &mut dyn RngCore,
        ctx: &ClsagContext<'_>,
        partial_kis: &[Point],
        commit_gs: &[Point],
        commit_ks: &[Point],
    ) -> Result<(ClsagCoordinator, Scalar, Scalar)> {
        let rs = ctx.ring.len();
        let real = ctx.secret_index as usize;
        if real >= rs {
            return Err(Error::msg("secretIndex out of range"));
        }
        let ki_base = ClsagCoordinator::ki_base(ctx);

        // key image: ki = hi*kiBase + sum(w_j*kiBase) = (hi+x)*kiBase
        let ki = ki_base.mul(ctx.hi).add(&combine_points(partial_kis));

        // The real stealth address must equal (hi+x)*G = hi*G + spendPub.
        let exp_stealth = Point::mul_base(ctx.hi).add(ctx.spend_pub);
        if exp_stealth != ctx.ring[real].stealth_address {
            return Err(Error::msg(
                "real stealth address does not match hi*G + spendPub",
            ));
        }

        // Combined nonce commitments.
        let ag = combine_points(commit_gs);
        let ak = combine_points(commit_ks);

        // K1, K2 come from the per-tx masks — no spend key involved.
        let k1_div8 = ki_base.mul(&SC_1DIV8.mul(ctx.secret1_f));
        let k2_div8 = ki_base.mul(&SC_1DIV8.mul(ctx.secret2_t));
        let k1 = mul8(&k1_div8);
        let k2 = mul8(&k2_div8);

        // input_hash and the aggregation coefficients.
        let mut hsc = HashHelper::new();
        hsc.add_bytes_mod_l(ctx.message);
        for r in ctx.ring {
            hsc.add_point(&r.stealth_address);
            hsc.add_point(&r.amount_commitment);
            hsc.add_point(&r.blinded_asset_id);
        }
        hsc.add_point(&ctx.pseudo_out_amount_commitment.mul(&SC_1DIV8));
        hsc.add_point(&ctx.pseudo_out_blinded_asset_id.mul(&SC_1DIV8));
        hsc.add_point(&ki);
        hsc.add_point(&k1_div8);
        hsc.add_point(&k2_div8);
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

        let mut w_pub_g = Vec::with_capacity(rs);
        let mut w_pub_x = Vec::with_capacity(rs);
        for r in ctx.ring {
            let a_i = mul8(&r.amount_commitment);
            let q_i = mul8(&r.blinded_asset_id);
            w_pub_g.push(
                r.stealth_address
                    .mul(&agg_coeff0)
                    .add(&a_i.sub(ctx.pseudo_out_amount_commitment).mul(&agg_coeff1)),
            );
            w_pub_x.push(q_i.sub(ctx.pseudo_out_blinded_asset_id).mul(&agg_coeff2));
        }
        let w_key_image_g = ki.mul(&agg_coeff0).add(&k1.mul(&agg_coeff1));
        let w_key_image_x = k2.mul(&agg_coeff2);

        // X-layer nonce (unrelated to the spend key) and the first challenge.
        let alpha_x = random_scalar(rnd);
        hsc.add_bytes(CRYPTO_HDS_CLSAG_GGX_CHALLENGE);
        hsc.add_bytes(&input_hash);
        hsc.add_point(&ag);
        hsc.add_point(&ak);
        hsc.add_point(&C_POINT_X.mul(&alpha_x));
        hsc.add_point(&ki_base.mul(&alpha_x));
        let mut c_prev = hsc.calc_hash();

        // Decoy responses.
        let rg: Vec<Scalar> = (0..rs).map(|_| random_scalar(rnd)).collect();
        let mut rx: Vec<Scalar> = (0..rs).map(|_| random_scalar(rnd)).collect();
        let mut sig_c: Option<Scalar> = None;

        // The public ring loop, exactly as the single-key signer runs it.
        let mut i = (real + 1) % rs;
        for _ in 0..rs - 1 {
            if i == 0 {
                sig_c = Some(c_prev.clone());
            }
            let hp_i = hp(&ctx.ring[i].stealth_address.compress());
            let mut h = HashHelper::new();
            h.add_bytes(CRYPTO_HDS_CLSAG_GGX_CHALLENGE);
            h.add_bytes(&input_hash);
            h.add_point(&C_POINT_G.mul(&rg[i]).add(&w_pub_g[i].mul(&c_prev)));
            h.add_point(&hp_i.mul(&rg[i]).add(&w_key_image_g.mul(&c_prev)));
            h.add_point(&C_POINT_X.mul(&rx[i]).add(&w_pub_x[i].mul(&c_prev)));
            h.add_point(&hp_i.mul(&rx[i]).add(&w_key_image_x.mul(&c_prev)));
            c_prev = h.calc_hash();
            i = (i + 1) % rs;
        }
        if real == 0 {
            sig_c = Some(c_prev.clone());
        }

        // The X-layer real response needs no spend key.
        let w_sec_key_x = agg_coeff2.mul(ctx.secret2_t);
        rx[real] = alpha_x.sub(&c_prev.mul(&w_sec_key_x));
        // rg[real] is filled in by phase2, once the parties have responded.

        let sig = ClsagSig {
            c: sig_c.expect("the ring always sets c"),
            rg,
            rx,
            k1: k1_div8,
            k2: k2_div8,
        };

        Ok((
            ClsagCoordinator {
                ki_base,
                ki: Some(ki),
                input_hash,
                agg_coeff0: agg_coeff0.clone(),
                agg_coeff1,
                c_prev: c_prev.clone(),
                sig: Some(sig),
            },
            c_prev,
            agg_coeff0,
        ))
    }

    /// Consumes the parties' round-2 partial responses and finalizes the
    /// signature. Returns the signature and the assembled key image.
    pub fn phase2(
        &mut self,
        ctx: &ClsagContext<'_>,
        partial_responses: &[Scalar],
    ) -> Result<(ClsagSig, Point)> {
        let mut sig = self
            .sig
            .take()
            .ok_or_else(|| Error::msg("phase1 must run before phase2"))?;

        // sum(partials) = alphaG - cPrev*aggCoeff0*x
        let sum = partial_responses
            .iter()
            .fold(Scalar::ZERO, |acc, r| acc.add(r));
        // Subtract the public part: cPrev*(aggCoeff0*hi + aggCoeff1*secret1F).
        let public = self
            .agg_coeff0
            .mul(ctx.hi)
            .add(&self.agg_coeff1.mul(ctx.secret1_f))
            .mul(&self.c_prev);
        sig.rg[ctx.secret_index as usize] = sum.sub(&public);

        let ki = self.ki.ok_or_else(|| Error::msg("no key image"))?;
        Ok((sig, ki))
    }

    /// The key-image base this coordinator used.
    pub fn ki_base_point(&self) -> Point {
        self.ki_base
    }

    /// The input hash bound into every challenge.
    pub fn input_hash(&self) -> [u8; 32] {
        self.input_hash
    }
}
