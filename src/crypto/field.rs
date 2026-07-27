//! Arithmetic in the base field GF(2^255 - 19).
//!
//! purecrypto exposes the edwards25519 *group* and its scalar field, but not the
//! underlying coordinate field. The Monero/Zano `ge_fromfe_frombytes_vartime`
//! map (see [`super::hashtoec`]) and the precomputed generator table both need
//! raw field arithmetic, so this module provides it: five 51-bit limbs, little
//! endian, the same representation used by every modern ed25519 implementation.
//!
//! Values are kept only weakly reduced (each limb < 2^52) between operations;
//! [`Fe::to_bytes`] performs the final canonical reduction.

const MASK: u64 = (1u64 << 51) - 1;

/// An element of GF(2^255 - 19), as five 51-bit limbs.
#[derive(Clone, Copy, Debug)]
pub struct Fe(pub [u64; 5]);

impl Fe {
    /// The additive identity.
    pub const ZERO: Fe = Fe([0, 0, 0, 0, 0]);
    /// The multiplicative identity.
    pub const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    /// Weak reduction: propagates carries so every limb is < 2^51 (plus a small
    /// slack in limb 0).
    fn reduce(mut l: [u64; 5]) -> Fe {
        let c0 = l[0] >> 51;
        let c1 = l[1] >> 51;
        let c2 = l[2] >> 51;
        let c3 = l[3] >> 51;
        let c4 = l[4] >> 51;
        l[0] &= MASK;
        l[1] &= MASK;
        l[2] &= MASK;
        l[3] &= MASK;
        l[4] &= MASK;
        l[0] += c4 * 19;
        l[1] += c0;
        l[2] += c1;
        l[3] += c2;
        l[4] += c3;
        Fe(l)
    }

    /// Decodes 32 little-endian bytes, ignoring the top bit (as ed25519 does).
    pub fn from_bytes(s: &[u8; 32]) -> Fe {
        let load8 = |i: usize| -> u64 {
            u64::from_le_bytes([
                s[i],
                s[i + 1],
                s[i + 2],
                s[i + 3],
                s[i + 4],
                s[i + 5],
                s[i + 6],
                s[i + 7],
            ])
        };
        Fe([
            load8(0) & MASK,
            (load8(6) >> 3) & MASK,
            (load8(12) >> 6) & MASK,
            (load8(19) >> 1) & MASK,
            (load8(24) >> 12) & MASK,
        ])
    }

    /// Encodes as 32 little-endian bytes, fully reduced modulo p.
    pub fn to_bytes(&self) -> [u8; 32] {
        // Fully carry, then conditionally subtract p by adding 19 and checking
        // for an overflow past 2^255.
        let mut l = Fe::reduce(self.0).0;
        let mut q = (l[0] + 19) >> 51;
        q = (l[1] + q) >> 51;
        q = (l[2] + q) >> 51;
        q = (l[3] + q) >> 51;
        q = (l[4] + q) >> 51;
        l[0] += 19 * q;
        l[1] += l[0] >> 51;
        l[0] &= MASK;
        l[2] += l[1] >> 51;
        l[1] &= MASK;
        l[3] += l[2] >> 51;
        l[2] &= MASK;
        l[4] += l[3] >> 51;
        l[3] &= MASK;
        l[4] &= MASK;

        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&(l[0] | (l[1] << 51)).to_le_bytes());
        out[8..16].copy_from_slice(&((l[1] >> 13) | (l[2] << 38)).to_le_bytes());
        out[16..24].copy_from_slice(&((l[2] >> 26) | (l[3] << 25)).to_le_bytes());
        out[24..32].copy_from_slice(&((l[3] >> 39) | (l[4] << 12)).to_le_bytes());
        out
    }

    /// `self + rhs`.
    pub fn add(&self, rhs: &Fe) -> Fe {
        Fe::reduce([
            self.0[0] + rhs.0[0],
            self.0[1] + rhs.0[1],
            self.0[2] + rhs.0[2],
            self.0[3] + rhs.0[3],
            self.0[4] + rhs.0[4],
        ])
    }

    /// `self - rhs`.
    pub fn sub(&self, rhs: &Fe) -> Fe {
        // Add 16*p first so the subtraction cannot underflow.
        Fe::reduce([
            (self.0[0] + 36028797018963664u64) - rhs.0[0],
            (self.0[1] + 36028797018963952u64) - rhs.0[1],
            (self.0[2] + 36028797018963952u64) - rhs.0[2],
            (self.0[3] + 36028797018963952u64) - rhs.0[3],
            (self.0[4] + 36028797018963952u64) - rhs.0[4],
        ])
    }

    /// `-self`.
    pub fn neg(&self) -> Fe {
        Fe::ZERO.sub(self)
    }

    /// `self * rhs`.
    pub fn mul(&self, rhs: &Fe) -> Fe {
        let a = &self.0;
        let b = &rhs.0;
        let m = |x: u64, y: u64| -> u128 { (x as u128) * (y as u128) };

        let b1_19 = b[1] * 19;
        let b2_19 = b[2] * 19;
        let b3_19 = b[3] * 19;
        let b4_19 = b[4] * 19;

        let c0 = m(a[0], b[0]) + m(a[4], b1_19) + m(a[3], b2_19) + m(a[2], b3_19) + m(a[1], b4_19);
        let mut c1 =
            m(a[1], b[0]) + m(a[0], b[1]) + m(a[4], b2_19) + m(a[3], b3_19) + m(a[2], b4_19);
        let mut c2 =
            m(a[2], b[0]) + m(a[1], b[1]) + m(a[0], b[2]) + m(a[4], b3_19) + m(a[3], b4_19);
        let mut c3 = m(a[3], b[0]) + m(a[2], b[1]) + m(a[1], b[2]) + m(a[0], b[3]) + m(a[4], b4_19);
        let mut c4 = m(a[4], b[0]) + m(a[3], b[1]) + m(a[2], b[2]) + m(a[1], b[3]) + m(a[0], b[4]);

        let mut out = [0u64; 5];
        c1 += c0 >> 51;
        out[0] = (c0 as u64) & MASK;
        c2 += c1 >> 51;
        out[1] = (c1 as u64) & MASK;
        c3 += c2 >> 51;
        out[2] = (c2 as u64) & MASK;
        c4 += c3 >> 51;
        out[3] = (c3 as u64) & MASK;
        let carry = (c4 >> 51) as u64;
        out[4] = (c4 as u64) & MASK;

        out[0] += carry * 19;
        out[1] += out[0] >> 51;
        out[0] &= MASK;
        Fe(out)
    }

    /// `self * self`.
    pub fn square(&self) -> Fe {
        self.mul(self)
    }

    /// `self` squared `k` times.
    pub fn pow2k(&self, k: u32) -> Fe {
        let mut r = *self;
        for _ in 0..k {
            r = r.square();
        }
        r
    }

    /// Multiplies by a small constant.
    pub fn mul_small(&self, n: u64) -> Fe {
        self.mul(&Fe([n, 0, 0, 0, 0]))
    }

    /// Shared addition chain: returns `(self^(2^250-1), self^11)`.
    fn pow22501(&self) -> (Fe, Fe) {
        let t0 = self.square();
        let t1 = t0.pow2k(2);
        let t2 = self.mul(&t1);
        let t3 = t0.mul(&t2);
        let t4 = t3.square();
        let t5 = t2.mul(&t4);
        let t6 = t5.pow2k(5);
        let t7 = t6.mul(&t5);
        let t8 = t7.pow2k(10);
        let t9 = t8.mul(&t7);
        let t10 = t9.pow2k(20);
        let t11 = t10.mul(&t9);
        let t12 = t11.pow2k(10);
        let t13 = t12.mul(&t7);
        let t14 = t13.pow2k(50);
        let t15 = t14.mul(&t13);
        let t16 = t15.pow2k(100);
        let t17 = t16.mul(&t15);
        let t18 = t17.pow2k(50);
        let t19 = t18.mul(&t13);
        (t19, t3)
    }

    /// Multiplicative inverse (`self^(p-2)`); the inverse of zero is zero.
    pub fn invert(&self) -> Fe {
        let (t19, t3) = self.pow22501();
        t19.pow2k(5).mul(&t3)
    }

    /// `self^((p-5)/8)`, the "Pow22523" of the ed25519 reference code.
    pub fn pow_p58(&self) -> Fe {
        let (t19, _) = self.pow22501();
        self.mul(&t19.pow2k(2))
    }

    /// Whether the canonical encoding has its least significant bit set.
    pub fn is_negative(&self) -> bool {
        self.to_bytes()[0] & 1 == 1
    }

    /// Whether this element is zero.
    pub fn is_zero(&self) -> bool {
        self.to_bytes() == [0u8; 32]
    }

    /// Builds a field element from the 10-limb radix-2^25.5 representation used
    /// by the ed25519 reference code (and by Zano's hard-coded constants).
    pub fn from_int10(f: [i64; 10]) -> Fe {
        Fe::from_bytes(&fe_to_bytes_25_5(f))
    }
}

impl PartialEq for Fe {
    fn eq(&self, other: &Fe) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}
impl Eq for Fe {}

/// Serializes a radix-2^25.5 (10 limb) field element to 32 bytes, the `fe_tobytes`
/// of the ed25519 reference code. Used only to import the hard-coded constants
/// and the `ge_fromfe_frombytes_vartime` intermediate value.
pub fn fe_to_bytes_25_5(mut h: [i64; 10]) -> [u8; 32] {
    let mut carry = [0i64; 10];

    let mut q = (19 * h[9] + (1 << 24)) >> 25;
    q = (h[0] + q) >> 26;
    q = (h[1] + q) >> 25;
    q = (h[2] + q) >> 26;
    q = (h[3] + q) >> 25;
    q = (h[4] + q) >> 26;
    q = (h[5] + q) >> 25;
    q = (h[6] + q) >> 26;
    q = (h[7] + q) >> 25;
    q = (h[8] + q) >> 26;
    q = (h[9] + q) >> 25;

    // Output h - (2^255-19)q, which is between 0 and 2^255-20.
    h[0] += 19 * q;

    carry[0] = h[0] >> 26;
    h[1] += carry[0];
    h[0] -= carry[0] << 26;
    carry[1] = h[1] >> 25;
    h[2] += carry[1];
    h[1] -= carry[1] << 25;
    carry[2] = h[2] >> 26;
    h[3] += carry[2];
    h[2] -= carry[2] << 26;
    carry[3] = h[3] >> 25;
    h[4] += carry[3];
    h[3] -= carry[3] << 25;
    carry[4] = h[4] >> 26;
    h[5] += carry[4];
    h[4] -= carry[4] << 26;
    carry[5] = h[5] >> 25;
    h[6] += carry[5];
    h[5] -= carry[5] << 25;
    carry[6] = h[6] >> 26;
    h[7] += carry[6];
    h[6] -= carry[6] << 26;
    carry[7] = h[7] >> 25;
    h[8] += carry[7];
    h[7] -= carry[7] << 25;
    carry[8] = h[8] >> 26;
    h[9] += carry[8];
    h[8] -= carry[8] << 26;
    carry[9] = h[9] >> 25;
    h[9] -= carry[9] << 25;

    let b = |v: i64| -> u8 { (v & 0xff) as u8 };
    let mut s = [0u8; 32];
    s[0] = b(h[0]);
    s[1] = b(h[0] >> 8);
    s[2] = b(h[0] >> 16);
    s[3] = b((h[0] >> 24) | (h[1] << 2));
    s[4] = b(h[1] >> 6);
    s[5] = b(h[1] >> 14);
    s[6] = b((h[1] >> 22) | (h[2] << 3));
    s[7] = b(h[2] >> 5);
    s[8] = b(h[2] >> 13);
    s[9] = b((h[2] >> 21) | (h[3] << 5));
    s[10] = b(h[3] >> 3);
    s[11] = b(h[3] >> 11);
    s[12] = b((h[3] >> 19) | (h[4] << 6));
    s[13] = b(h[4] >> 2);
    s[14] = b(h[4] >> 10);
    s[15] = b(h[4] >> 18);
    s[16] = b(h[5]);
    s[17] = b(h[5] >> 8);
    s[18] = b(h[5] >> 16);
    s[19] = b((h[5] >> 24) | (h[6] << 1));
    s[20] = b(h[6] >> 7);
    s[21] = b(h[6] >> 15);
    s[22] = b((h[6] >> 23) | (h[7] << 3));
    s[23] = b(h[7] >> 5);
    s[24] = b(h[7] >> 13);
    s[25] = b((h[7] >> 21) | (h[8] << 4));
    s[26] = b(h[8] >> 4);
    s[27] = b(h[8] >> 12);
    s[28] = b((h[8] >> 20) | (h[9] << 6));
    s[29] = b(h[9] >> 2);
    s[30] = b(h[9] >> 10);
    s[31] = b(h[9] >> 18);
    s
}

/// `u = z / y * (z / y)^((p-5)/8)`, the ref10 `fe_divpowm1`.
pub fn fe_div_pow_m1(z: &Fe, y: &Fe) -> Fe {
    let t1 = y.invert();
    let t0 = z.mul(&t1);
    let t0 = t0.pow_p58();
    let t0 = t0.mul(z);
    t0.mul(&t1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_round_trip() {
        let mut b = [0u8; 32];
        for (i, v) in b.iter_mut().enumerate() {
            *v = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        b[31] &= 0x7f;
        assert_eq!(Fe::from_bytes(&b).to_bytes(), b);
    }

    #[test]
    fn field_axioms() {
        let a = Fe::from_int10([
            -10913610, 13857413, -15372611, 6949391, 114729, -8787816, -6275908, -3247719,
            -18696448, -12055116,
        ]);
        let one = Fe::ONE;
        assert_eq!(a.mul(&one), a);
        assert_eq!(a.add(&a.neg()), Fe::ZERO);
        assert_eq!(a.sub(&a), Fe::ZERO);
        assert_eq!(a.mul(&a), a.square());
        assert_eq!(a.mul(&a.invert()), one);
        assert!(!a.is_zero());
        assert!(Fe::ZERO.is_zero());
    }

    #[test]
    fn sqrt_m1_squares_to_minus_one() {
        // sqrt(-1) is one of the hard-coded constants; check the 10-limb import.
        let sqrt_m1 = Fe::from_int10([
            -32595792, -7943725, 9377950, 3500415, 12389472, -272473, -25146209, -2005654, 326686,
            11406482,
        ]);
        assert_eq!(sqrt_m1.square(), Fe::ONE.neg());
    }

    #[test]
    fn p_minus_one_is_canonical() {
        // p-1 encodes as 0xec,0xff..0x7f; adding one wraps to zero.
        let mut b = [0xffu8; 32];
        b[0] = 0xec;
        b[31] = 0x7f;
        let pm1 = Fe::from_bytes(&b);
        assert_eq!(pm1.to_bytes(), b);
        assert_eq!(pm1.add(&Fe::ONE), Fe::ZERO);
    }
}
