//! Key derivation: ECDH derivations, per-output ephemeral keys, key images.

use super::hash::hash_to_scalar;
use super::{Point, Scalar};
use crate::base::varint::varint_bytes;
use crate::error::Result;

/// `8 * secret * public` — the ECDH key derivation. The cofactor multiplication
/// puts the result in the prime-order subgroup.
pub fn generate_key_derivation(pub_key: &Point, sec_key: &Scalar) -> Point {
    pub_key.mul(sec_key).mul_by_cofactor()
}

/// `derivation_to_scalar`: `Hs(derivation || varint(output_index))`.
pub fn derivation_to_scalar(derivation: &[u8], output_index: u64) -> Scalar {
    let mut buf = derivation.to_vec();
    buf.extend_from_slice(&varint_bytes(output_index));
    hash_to_scalar(&buf)
}

/// Derives a per-output public key: `Hs(derivation, i)*G + base_public`.
pub fn derive_public_key(
    derivation: &[u8],
    output_index: u64,
    base_public: &Point,
) -> Result<Point> {
    let scalar = derivation_to_scalar(derivation, output_index);
    Ok(Point::mul_base(&scalar).add(base_public))
}

/// Derives a per-output secret key: `Hs(derivation, i) + base_secret`.
pub fn derive_secret_key(derivation: &[u8], output_index: u64, base_secret: &Scalar) -> Scalar {
    derivation_to_scalar(derivation, output_index).add(base_secret)
}

/// A 16-bit hint stored in tx extra so a wallet can skip derivations that cannot
/// belong to it: BLAKE2b-256 of the derivation, XOR-folded to 16 bits.
pub fn derivation_hint(derivation: &Point) -> u16 {
    let hash = purecrypto::hash::blake2b256(&derivation.compress());
    let mut result = u16::from_le_bytes([hash[0], hash[1]]);
    for i in 1..16 {
        result ^= u16::from_le_bytes([hash[i * 2], hash[i * 2 + 1]]);
    }
    result
}

/// The key image `I = secret * Hp(public)`, used for double-spend prevention.
pub fn compute_key_image(spend_priv: &Scalar, spend_pub: &Point) -> Point {
    super::hashtoec::hash_to_ec(&spend_pub.compress()).mul(spend_priv)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::scalar_int;

    #[test]
    fn derivation_is_symmetric() {
        // 8*a*(b*G) == 8*b*(a*G): sender and receiver derive the same secret.
        let a = scalar_int(0x1234_5678_9abc_def0);
        let b = scalar_int(0x0fed_cba9_8765_4321);
        let big_a = Point::mul_base(&a);
        let big_b = Point::mul_base(&b);
        assert_eq!(
            generate_key_derivation(&big_b, &a),
            generate_key_derivation(&big_a, &b)
        );
    }

    #[test]
    fn public_and_secret_derivations_agree() {
        let base = scalar_int(9876543210);
        let base_pub = Point::mul_base(&base);
        let derivation = [3u8; 32];
        let pub_key = derive_public_key(&derivation, 7, &base_pub).unwrap();
        let sec_key = derive_secret_key(&derivation, 7, &base);
        assert_eq!(pub_key, Point::mul_base(&sec_key));
    }

    #[test]
    fn key_image_is_stable() {
        let s = scalar_int(42);
        let p = Point::mul_base(&s);
        assert_eq!(compute_key_image(&s, &p), compute_key_image(&s, &p));
    }
}
