//! Zano's cryptographic primitives: the curve helpers, hash-to-point/scalar
//! functions, key derivation, ChaCha8, and the CLSAG-GGX / Bulletproof+ / BGE
//! proof systems.
//!
//! Port of the Go `zanocrypto` package. Group and scalar arithmetic come from
//! purecrypto's edwards25519 hazmat API; only the coordinate-field arithmetic
//! needed by `ge_fromfe_frombytes_vartime` lives here (see [`field`]).

pub mod bge;
pub mod bpp;
pub mod chacha8;
pub mod clsag;
pub mod consts;
pub mod derive;
pub mod field;
pub mod hash;
pub mod hashtoec;
pub mod maths;
pub mod zarcanum;

use crate::error::{Error, Result};
use crate::rng::RngCore;

pub use purecrypto::ec::edwards25519::hazmat::{EdwardsPoint as Point, Scalar};

pub use bge::generate_bge_proof;
pub use bpp::{TRAIT_ZARCANUM, TRAIT_ZC_OUT, Trait};
pub use chacha8::{chacha8, chacha8_generate_key};
pub use clsag::{ClsagGgxInputRef, generate_clsag_ggx, verify_clsag_ggx};
pub use consts::*;
pub use derive::{
    compute_key_image, derivation_hint, derive_public_key, derive_secret_key,
    generate_key_derivation,
};
pub use hash::{HashHelper, hash_to_scalar, hs_bytes};
pub use hashtoec::{hash_to_ec, hash_to_point, hp};
pub use zarcanum::{generate_double_schnorr_sig, generate_vector_ug_aggregation_proof};

/// Decodes a compressed point, rejecting anything that is not on the curve.
pub fn point_from_bytes(b: &[u8]) -> Result<Point> {
    let arr: [u8; 32] = b.try_into().map_err(|_| Error::InvalidPoint)?;
    Point::decompress(&arr).ok_or(Error::InvalidPoint)
}

/// Decodes a canonical (reduced) scalar.
pub fn scalar_from_canonical(b: &[u8]) -> Result<Scalar> {
    let arr: [u8; 32] = b.try_into().map_err(|_| Error::InvalidScalar)?;
    Scalar::from_bytes_canonical(&arr).ok_or(Error::InvalidScalar)
}

/// Reduces a little-endian byte string (at most 64 bytes) modulo the group order.
pub fn scalar_from_wide(b: &[u8]) -> Scalar {
    let mut wide = [0u8; 64];
    let n = b.len().min(64);
    wide[..n].copy_from_slice(&b[..n]);
    Scalar::from_bytes_mod_order(&wide)
}

/// Converts a u64 into a scalar.
pub fn scalar_int(v: u64) -> Scalar {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&v.to_le_bytes());
    // v < 2^64 < L, so this is always canonical.
    Scalar::from_bytes_canonical(&b).expect("u64 is always a canonical scalar")
}

/// `8*p`, three doublings — Zano's `point_t::modify_mul8()`.
///
/// On-chain Zarcanum outputs store the concealing point, amount commitment and
/// blinded asset id pre-multiplied by 1/8; multiplying by 8 recovers the value
/// used in the receiver-side equations.
pub fn mul8(p: &Point) -> Point {
    p.mul_by_cofactor()
}

/// Reads 64 bytes from `rnd` and reduces them modulo the group order.
pub fn random_scalar(rnd: &mut dyn RngCore) -> Scalar {
    let mut buf = [0u8; 64];
    rnd.fill_bytes(&mut buf);
    Scalar::from_bytes_mod_order(&buf)
}

/// `priv * G`.
pub fn pub_from_priv(s: &Scalar) -> Point {
    Point::mul_base(s)
}

/// Generates a random private scalar from the OS entropy source, clamped the
/// way ed25519 key generation clamps (matching the Go `GenerateKeyScalar`).
pub fn generate_key_scalar(rnd: &mut dyn RngCore) -> Scalar {
    use purecrypto::hash::{Digest, Sha512};
    let mut seed = [0u8; 32];
    rnd.fill_bytes(&mut seed);
    let digest = Sha512::digest(&seed);
    let mut lower = [0u8; 32];
    lower.copy_from_slice(&digest[..32]);
    // Clamping, then reduction: identical to SetBytesWithClamping.
    lower[0] &= 248;
    lower[31] &= 63;
    lower[31] |= 64;
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&lower);
    Scalar::from_bytes_mod_order(&wide)
}

/// `a*A + b*B`, where `B` is the ed25519 base point.
pub fn double_scalar_base_mult(a: &Scalar, big_a: &Point, b: &Scalar) -> Point {
    big_a.mul(a).add(&Point::mul_base(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_int_round_trips() {
        let s = scalar_int(0x0102030405060708);
        assert_eq!(&s.to_bytes()[..8], &0x0102030405060708u64.to_le_bytes());
    }

    #[test]
    fn mul8_matches_three_doublings() {
        let p = Point::mul_base(&scalar_int(1234567));
        let manual = p.add(&p);
        let manual = manual.add(&manual);
        let manual = manual.add(&manual);
        assert_eq!(mul8(&p), manual);
    }
}
