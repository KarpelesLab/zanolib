//! The spend-key-dependent half of signing one confidential input.

use crate::base::sig::ClsagSig;
use crate::crypto::{
    Point, Scalar, clsag::ClsagGgxInputRef, compute_key_image, generate_clsag_ggx,
};
use crate::error::Result;
use crate::rng::RngCore;

/// Everything a signature needs from an input, minus the spend key.
pub struct ClsagRequest<'a> {
    /// The public per-output scalar `hi = Hs(8*v*R, output_index)`.
    pub hi: &'a Scalar,
    /// The message being signed (the tx prefix hash).
    pub msg: &'a [u8],
    /// The ring, in on-chain order.
    pub ring: &'a [ClsagGgxInputRef],
    /// The key image previously returned by [`InputSigner::key_image`].
    pub key_image: &'a Point,
    /// The pseudo-output amount commitment.
    pub pseudo_out_amount_commitment: &'a Point,
    /// The pseudo-output blinded asset id.
    pub pseudo_out_blinded_asset_id: &'a Point,
    /// Layer-1 secret: the amount blinding mask difference.
    pub secret1_f: &'a Scalar,
    /// Layer-2 secret: the negated asset id blinding mask.
    pub secret2_t: &'a Scalar,
    /// Index of the real output within the ring.
    pub secret_index: u64,
}

/// Produces the two spend-key-dependent values for one confidential input: the
/// key image and the CLSAG-GGX ring signature.
///
/// The effective per-input secret is `secret0Xp = hi + x`, where `hi` is public
/// and `x` is the wallet spend secret. A local signer holds `x` directly; a
/// threshold signer (see the [`mpc`](crate::mpc) module) holds it as shares and
/// never reconstructs it.
///
/// Signing calls [`InputSigner::key_image`] for every input first (key images
/// are part of the tx prefix), then — once the prefix hash is known —
/// [`InputSigner::sign_clsag`] for each input, in the same order.
pub trait InputSigner {
    /// The key image for an input whose real output has stealth address
    /// `in_e_pub` and public per-output scalar `hi`.
    fn key_image(&mut self, hi: &Scalar, in_e_pub: &Point) -> Result<Point>;

    /// The CLSAG-GGX signature for one input.
    fn sign_clsag(&mut self, rnd: &mut dyn RngCore, req: &ClsagRequest<'_>) -> Result<ClsagSig>;
}

/// Signs with a spend secret held in this process — the default, non-MPC path.
pub struct LocalInputSigner {
    spend_secret: Scalar,
}

impl LocalInputSigner {
    /// Wraps an in-process spend secret.
    pub fn new(spend_secret: Scalar) -> LocalInputSigner {
        LocalInputSigner { spend_secret }
    }

    /// `in_e_sec = hi + x`.
    fn in_e_sec(&self, hi: &Scalar) -> Scalar {
        hi.add(&self.spend_secret)
    }
}

impl InputSigner for LocalInputSigner {
    fn key_image(&mut self, hi: &Scalar, in_e_pub: &Point) -> Result<Point> {
        Ok(compute_key_image(&self.in_e_sec(hi), in_e_pub))
    }

    fn sign_clsag(&mut self, rnd: &mut dyn RngCore, req: &ClsagRequest<'_>) -> Result<ClsagSig> {
        generate_clsag_ggx(
            rnd,
            req.msg,
            req.ring,
            req.key_image,
            req.pseudo_out_amount_commitment,
            req.pseudo_out_blinded_asset_id,
            &self.in_e_sec(req.hi),
            req.secret1_f,
            req.secret2_t,
            req.secret_index,
        )
    }
}
