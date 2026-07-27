//! Monero/Zano `ge_fromfe_frombytes_vartime` and the hash-to-point functions
//! built on it.

use super::Point;
use super::consts::*;
use super::field::{Fe, fe_div_pow_m1, fe_to_bytes_25_5};
use purecrypto::hash::{Digest, Keccak256};

fn load3(b: &[u8]) -> i64 {
    (b[0] as i64) | ((b[1] as i64) << 8) | ((b[2] as i64) << 16)
}

fn load4(b: &[u8]) -> i64 {
    (b[0] as i64) | ((b[1] as i64) << 8) | ((b[2] as i64) << 16) | ((b[3] as i64) << 24)
}

/// Maps 32 bytes to a curve point, exactly as `ge_fromfe_frombytes_vartime`
/// does. The result is *not* in the prime-order subgroup; callers multiply by
/// the cofactor (see [`hp`]).
pub fn ge_from_fe_from_bytes_vartime(s: &[u8]) -> Point {
    assert_eq!(s.len(), 32, "ge_fromfe_frombytes_vartime expects 32 bytes");

    let mut h0 = load4(&s[0..4]);
    let mut h1 = load3(&s[4..7]) << 6;
    let mut h2 = load3(&s[7..10]) << 5;
    let mut h3 = load3(&s[10..13]) << 3;
    let mut h4 = load3(&s[13..16]) << 2;
    let mut h5 = load4(&s[16..20]);
    let mut h6 = load3(&s[20..23]) << 7;
    let mut h7 = load3(&s[23..26]) << 5;
    let mut h8 = load3(&s[26..29]) << 4;
    let mut h9 = load3(&s[29..32]) << 2;

    let carry9 = (h9 + (1 << 24)) >> 25;
    h0 += carry9 * 19;
    h9 -= carry9 << 25;

    let carry1 = (h1 + (1 << 24)) >> 25;
    h2 += carry1;
    h1 -= carry1 << 25;

    let carry3 = (h3 + (1 << 24)) >> 25;
    h4 += carry3;
    h3 -= carry3 << 25;

    let carry5 = (h5 + (1 << 24)) >> 25;
    h6 += carry5;
    h5 -= carry5 << 25;

    let carry7 = (h7 + (1 << 24)) >> 25;
    h8 += carry7;
    h7 -= carry7 << 25;

    let carry0 = (h0 + (1 << 25)) >> 26;
    h1 += carry0;
    h0 -= carry0 << 26;

    let carry2 = (h2 + (1 << 25)) >> 26;
    h3 += carry2;
    h2 -= carry2 << 26;

    let carry4 = (h4 + (1 << 25)) >> 26;
    h5 += carry4;
    h4 -= carry4 << 26;

    let carry6 = (h6 + (1 << 25)) >> 26;
    h7 += carry6;
    h6 -= carry6 << 26;

    let carry8 = (h8 + (1 << 25)) >> 26;
    h9 += carry8;
    h8 -= carry8 << 26;

    let u = Fe::from_bytes(&fe_to_bytes_25_5([h0, h1, h2, h3, h4, h5, h6, h7, h8, h9]));

    // v = 2 * u^2
    let v = u.square().mul_small(2);
    // w = 2*u^2 + 1
    let w = v.add(&Fe::ONE);
    // x = w^2 - 2*A^2*u^2
    let mut x = w.square().add(&FE_MA2.mul(&v));

    // r->X = (w / x)^(m+1)
    let mut r_x = fe_div_pow_m1(&w, &x);

    // y = (r->X)^2 ; x = y * x ; y = w - x
    let y = r_x.square();
    x = y.mul(&x);
    let y = w.sub(&x);

    let mut z = *FE_MA;
    let sign;

    if !y.is_zero() {
        let y = w.add(&x);
        if !y.is_zero() {
            // "negative" branch
            x = x.mul(&FE_SQRT_M1);
            let y = w.sub(&x);
            if !y.is_zero() {
                let y = w.add(&x);
                assert!(
                    y.is_zero(),
                    "assertion failed in ge_fromfe_frombytes_vartime"
                );
                r_x = r_x.mul(&FE_FFFB3);
            } else {
                r_x = r_x.mul(&FE_FFFB4);
            }
            sign = 1;
            return finish(r_x, z, w, sign);
        }
        r_x = r_x.mul(&FE_FFFB1);
    } else {
        r_x = r_x.mul(&FE_FFFB2);
    }

    // r->X = r->X * u ; z = z * v
    r_x = r_x.mul(&u);
    z = z.mul(&v);
    sign = 0;
    finish(r_x, z, w, sign)
}

/// Applies the sign fix-up and converts `(X : Y : Z)` to a compressed point.
fn finish(mut r_x: Fe, z: Fe, w: Fe, sign: u8) -> Point {
    if r_x.is_negative() != (sign == 1) {
        assert!(!r_x.is_zero(), "unexpected zero field element in setsign");
        r_x = r_x.neg();
    }
    let r_z = z.add(&w);
    let r_y = z.sub(&w);
    let r_x = r_x.mul(&r_z);

    let zinv = r_z.invert();
    let ax = r_x.mul(&zinv);
    let ay = r_y.mul(&zinv);
    let mut enc = ay.to_bytes();
    enc[31] |= (ax.to_bytes()[0] & 1) << 7;
    Point::decompress(&enc).expect("ge_fromfe_frombytes_vartime produced an off-curve point")
}

/// `hash_to_point`: maps an already-hashed 32-byte value to a curve point.
pub fn hash_to_point(h: &[u8]) -> Point {
    ge_from_fe_from_bytes_vartime(h)
}

/// Hashes with Keccak-256, maps to a curve point and multiplies by the cofactor,
/// putting the result in the prime-order subgroup.
pub fn hash_to_ec(data: &[u8]) -> Point {
    let h = Keccak256::digest(data);
    ge_from_fe_from_bytes_vartime(&h).mul_by_cofactor()
}

/// `Hp(data) = 8 * ge_fromfe_frombytes_vartime(keccak256(data))`.
///
/// Identical to [`hash_to_ec`]; both names exist in the C++ original.
pub fn hp(data: &[u8]) -> Point {
    hash_to_ec(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hp_is_in_the_prime_order_subgroup() {
        for i in 0u8..8 {
            let p = hp(&[i; 32]);
            assert!(bool::from(p.is_torsion_free()));
            assert_ne!(p, Point::identity());
        }
    }

    #[test]
    fn hp_is_deterministic() {
        assert_eq!(hp(b"zano"), hp(b"zano"));
        assert_ne!(hp(b"zano"), hp(b"zanp"));
    }
}
