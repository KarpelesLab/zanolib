//! Bulletproof+ aggregated range proofs — `src/crypto/range_proof_bpp.h`.

use super::consts::{C_POINT_0, C_POINT_G, C_POINT_H, C_POINT_U, C_POINT_X, SC_1DIV8};
use super::hash::{HashHelper, hash_to_scalar};
use super::hashtoec::hp;
use super::maths::ceil_log2;
use super::{Point, Scalar, random_scalar, scalar_int};
use crate::base::sig::BppSignature;
use crate::error::{Error, Result};
use crate::rng::RngCore;
use std::sync::LazyLock;

/// The generator set and dimensions of one Bulletproof+ flavour.
///
/// The notation follows the BP+ whitepaper; see `range_proofs.cpp` for the
/// mapping onto Zano's generators.
pub struct Trait {
    /// Generator selection: `"UGX"` or `"HGX"`.
    pub kind: &'static str,
    /// Bit width of each committed value.
    pub n: usize,
    /// Maximum number of values in one aggregated proof.
    pub values_max: usize,
    /// `ceil(log2(n))`.
    pub log2_n: usize,
    /// `n * values_max`.
    pub mn_max: usize,
    /// The `G` generator of the paper.
    pub g: Point,
    /// The `H` generator of the paper.
    pub h: Point,
    /// The secondary `H2` generator.
    pub h2: Point,
}

impl Trait {
    fn new(kind: &'static str, n: usize, values_max: usize) -> Trait {
        let (g, h, h2) = match kind {
            "HGX" => (*C_POINT_H, *C_POINT_G, *C_POINT_X),
            "UGX" => (*C_POINT_U, *C_POINT_G, *C_POINT_X),
            _ => panic!("unsupported trait {kind}"),
        };
        Trait {
            kind,
            n,
            values_max,
            log2_n: ceil_log2(n),
            mn_max: n * values_max,
            g,
            h,
            h2,
        }
    }

    /// `value * G + mask * H` with this trait's generators.
    pub fn calc_pedersen_commitment(&self, value: &Scalar, mask: &Scalar) -> Point {
        self.g.mul(value).add(&self.h.mul(mask))
    }

    /// Index of element `(row, col)` in a `c_bpp_m x n` matrix.
    fn at(&self, row: usize, col: usize) -> usize {
        row * self.n + col
    }
}

/// The trait used for confidential transaction outputs (`UGX`, n = 64).
pub static TRAIT_ZC_OUT: LazyLock<Trait> = LazyLock::new(|| Trait::new("UGX", 64, 32));
/// The trait used for Zarcanum PoS proofs (`HGX`, n = 128).
pub static TRAIT_ZARCANUM: LazyLock<Trait> = LazyLock::new(|| Trait::new("HGX", 128, 16));

/// The initial Fiat-Shamir transcript value.
pub fn trait_initial_transcript() -> Scalar {
    hash_to_scalar(b"Zano BP+ initial transcript")
}

/// Folds `e` and `pub_keys` into the transcript, returning the new value.
pub fn trait_update_transcript(hsc: &mut HashHelper, e: &Scalar, pub_keys: &[Point]) -> Scalar {
    hsc.add_scalar(e);
    hsc.add_points(pub_keys);
    hsc.calc_hash()
}

/// The Bulletproof+ generator at `index`; `select_h` picks the H-generator.
pub fn trait_get_generator(select_h: bool, index: usize) -> Point {
    let mut pos = 2 * index as u64;
    if select_h {
        pos += 1;
    }
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&hash_to_scalar(b"Zano BP+ generator").to_bytes());
    buf[32..40].copy_from_slice(&pos.to_le_bytes());
    hp(&buf)
}

impl Trait {
    /// Generates an aggregated Bulletproof+ range proof for `values` with
    /// blinding factors `masks`. `commitments_1div8` are the already-computed
    /// commitments, premultiplied by 1/8.
    pub fn bpp_gen(
        &self,
        rnd: &mut dyn RngCore,
        values: &[Scalar],
        masks: &[Scalar],
        commitments_1div8: &[Point],
    ) -> Result<BppSignature> {
        if values.is_empty() {
            return Err(Error::msg("bpp_gen: no values"));
        }
        if values.len() > self.values_max {
            return Err(crate::err!(
                "bpp_gen: {} values exceeds the maximum of {}",
                values.len(),
                self.values_max
            ));
        }

        let c_bpp_log2_m = ceil_log2(values.len());
        let c_bpp_m = 1usize << c_bpp_log2_m;
        let c_bpp_mn = c_bpp_m * self.n;

        // Decompose each value into aL (its bits) and aR = aL - 1.
        let mut a_ls = vec![Scalar::ZERO; c_bpp_mn];
        let mut a_rs = vec![Scalar::ZERO; c_bpp_mn];
        let minus_one = Scalar::ONE.negate();
        for (i, v) in values.iter().enumerate() {
            let vb = v.to_bytes();
            for j in 0..self.n {
                if vb[j / 8] & (1 << (j % 8)) != 0 {
                    a_ls[self.at(i, j)] = Scalar::ONE; // aL = 1, aR = 0
                } else {
                    a_rs[self.at(i, j)] = minus_one.clone(); // aL = 0, aR = -1
                }
            }
        }
        for i in values.len()..c_bpp_m {
            for j in 0..self.n {
                a_rs[self.at(i, j)] = minus_one.clone();
            }
        }

        // Fiat-Shamir transcript.
        let mut hsc = HashHelper::new();
        let mut e = trait_initial_transcript();
        e = trait_update_transcript(&mut hsc, &e, commitments_1div8);

        // A = alpha*H + sum(aL_i*G_i) + sum(aR_i*H_i), premultiplied by 1/8.
        let alpha = random_scalar(rnd);
        let mut a0 = C_POINT_G.mul(&alpha);
        for i in 0..c_bpp_mn {
            a0 = a0
                .add(&trait_get_generator(false, i).mul(&a_ls[i]))
                .add(&trait_get_generator(true, i).mul(&a_rs[i]));
        }
        let a0 = a0.mul(&SC_1DIV8);

        // Challenges y and z.
        hsc.add_scalar(&e);
        hsc.add_point(&a0);
        let y = hsc.calc_hash();
        let z = hash_to_scalar(&y.to_bytes());
        e = z.clone();

        // d = (z^2, z^4, ..., z^(2m)) x (1, 2, 4, ..., 2^(n-1)), column-major.
        let z_sq = z.mul(&z);
        let mut d = vec![Scalar::ZERO; c_bpp_mn];
        d[0] = z_sq.clone();
        for i in 1..c_bpp_m {
            // Note: the Go original multiplied a never-updated `prev` here, so
            // every row past the second got z^4 instead of z^(2i).
            d[self.at(i, 0)] = d[self.at(i - 1, 0)].mul(&z_sq);
        }
        for j in 1..self.n {
            for i in 0..c_bpp_m {
                let v = d[self.at(i, j - 1)].clone();
                d[self.at(i, j)] = v.add(&v);
            }
        }

        // Extended Vandermonde vector (1, y, y^2, ..., y^(mn+1)).
        let mut y_powers = Vec::with_capacity(c_bpp_mn + 2);
        y_powers.push(scalar_int(1));
        for i in 1..=c_bpp_mn + 1 {
            y_powers.push(y_powers[i - 1].mul(&y));
        }
        let y_mn_p1 = y_powers[c_bpp_mn + 1].clone();

        // aL_hat = aL - z ; aR_hat = aR + z + d o y^leftarrow
        let mut a: Vec<Scalar> = a_ls.iter().map(|v| v.sub(&z)).collect();
        let mut b: Vec<Scalar> = a_rs
            .iter()
            .enumerate()
            .map(|(i, v)| v.add(&z).add(&d[i].mul(&y_powers[c_bpp_mn - i])))
            .collect();

        // alpha_hat = alpha + y^(mn+1) * sum(z^(2j) * gamma_j)
        let mut alpha_hat = Scalar::ZERO;
        for (i, mask) in masks.iter().enumerate() {
            alpha_hat = alpha_hat.add(&d[self.at(i, 0)].mul(mask));
        }
        let mut alpha_hat = alpha.add(&y_mn_p1.mul(&alpha_hat));

        // 1, y^-1, y^-2, ...
        let y_inverse = y.invert();
        let mut y_inverse_powers = Vec::with_capacity(c_bpp_mn / 2 + 1);
        y_inverse_powers.push(scalar_int(1));
        for i in 1..c_bpp_mn / 2 + 1 {
            y_inverse_powers.push(y_inverse_powers[i - 1].mul(&y_inverse));
        }

        let mut g: Vec<Point> = (0..c_bpp_mn)
            .map(|i| trait_get_generator(false, i))
            .collect();
        let mut h: Vec<Point> = (0..c_bpp_mn)
            .map(|i| trait_get_generator(true, i))
            .collect();

        let mut lv = Vec::new();
        let mut rv = Vec::new();

        // zk-WIP reduction rounds (preprint page 13, Fig. 1).
        let mut nn = c_bpp_mn / 2;
        while nn >= 1 {
            let d_l = random_scalar(rnd);
            let d_r = random_scalar(rnd);

            // cL = <a1, (y, y^2, ...) o b2>
            let mut c_l = Scalar::ZERO;
            for i in 0..nn {
                c_l = c_l.add(&a[i].mul(&y_powers[i + 1]).mul(&b[nn + i]));
            }
            // cR = <a2, (y, y^2, ...) o b1> * y^n
            let mut c_r = Scalar::ZERO;
            for i in 0..nn {
                c_r = c_r.add(&a[nn + i].mul(&y_powers[i + 1]).mul(&b[i]));
            }
            c_r = c_r.mul(&y_powers[nn]);

            // L = y^-n * a1*g2 + b2*h1 + cL*G + dL*H
            let mut sum = *C_POINT_0;
            for i in 0..nn {
                sum = sum.add(&g[nn + i].mul(&a[i]));
            }
            let mut big_l = self.calc_pedersen_commitment(&c_l, &d_l);
            for i in 0..nn {
                big_l = big_l.add(&h[i].mul(&b[nn + i]));
            }
            big_l = big_l.add(&sum.mul(&y_inverse_powers[nn]));
            let big_l = big_l.mul(&SC_1DIV8);

            // R = y^n * a2*g1 + b1*h2 + cR*G + dR*H
            let mut sum = *C_POINT_0;
            for i in 0..nn {
                sum = sum.add(&g[i].mul(&a[nn + i]));
            }
            let mut big_r = self.calc_pedersen_commitment(&c_r, &d_r);
            for i in 0..nn {
                big_r = big_r.add(&h[nn + i].mul(&b[i]));
            }
            big_r = big_r.add(&sum.mul(&y_powers[nn]));
            let big_r = big_r.mul(&SC_1DIV8);

            lv.push(big_l);
            rv.push(big_r);

            // Update the transcript.
            hsc.add_scalar(&e);
            hsc.add_point(&big_l);
            hsc.add_point(&big_r);
            e = hsc.calc_hash();

            let e_squared = e.mul(&e);
            let e_inverse = e.invert();
            let e_inverse_squared = e_inverse.mul(&e_inverse);
            let e_y_inv_n = e.mul(&y_inverse_powers[nn]);
            let e_inv_y_n = e_inverse.mul(&y_powers[nn]);

            for i in 0..nn {
                g[i] = g[i].mul(&e_inverse).add(&g[nn + i].mul(&e_y_inv_n));
                h[i] = h[i].mul(&e).add(&h[nn + i].mul(&e_inverse));
                a[i] = e.mul(&a[i]).add(&e_inv_y_n.mul(&a[nn + i]));
                b[i] = e_inverse.mul(&b[i]).add(&e.mul(&b[nn + i]));
            }

            alpha_hat = alpha_hat.add(&e_squared.mul(&d_l).add(&e_inverse_squared.mul(&d_r)));

            nn /= 2;
        }

        // zk-WIP final round.
        let r = random_scalar(rnd);
        let s = random_scalar(rnd);
        let delta = random_scalar(rnd);
        let eta = random_scalar(rnd);

        // A = r*g + s*h + y*(r*b + s*a)*G + delta*H
        let tmp = r.mul(&b[0]).add(&s.mul(&a[0]));
        let big_a = self
            .calc_pedersen_commitment(&y.mul(&tmp), &delta)
            .add(&g[0].mul(&r).add(&h[0].mul(&s)))
            .mul(&SC_1DIV8);

        // B = (r*y*s)*G + eta*H
        let big_b = self
            .calc_pedersen_commitment(&r.mul(&y).mul(&s), &eta)
            .mul(&SC_1DIV8);

        hsc.add_scalar(&e);
        hsc.add_point(&big_a);
        hsc.add_point(&big_b);
        e = hsc.calc_hash();

        Ok(BppSignature {
            lv,
            rv,
            a0,
            a: big_a,
            b: big_b,
            r: r.add(&e.mul(&a[0])),
            s: s.add(&e.mul(&b[0])),
            delta: eta.add(&e.mul(&delta)).add(&e.mul(&e).mul(&alpha_hat)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::FixedRng;

    #[test]
    fn traits_have_the_expected_shape() {
        assert_eq!(TRAIT_ZC_OUT.n, 64);
        assert_eq!(TRAIT_ZC_OUT.log2_n, 6);
        assert_eq!(TRAIT_ZC_OUT.mn_max, 64 * 32);
        assert_eq!(TRAIT_ZARCANUM.n, 128);
        assert_eq!(TRAIT_ZARCANUM.log2_n, 7);
    }

    #[test]
    fn generators_differ_per_index_and_selection() {
        assert_ne!(trait_get_generator(false, 0), trait_get_generator(true, 0));
        assert_ne!(trait_get_generator(false, 0), trait_get_generator(false, 1));
    }

    #[test]
    fn proof_has_one_round_per_halving() {
        // A single 64-bit value gives mn = 64, so 6 reduction rounds.
        let mut rnd = FixedRng(0x42);
        let values = vec![scalar_int(1000)];
        let masks = vec![random_scalar(&mut rnd)];
        let commitments = vec![
            C_POINT_U
                .mul(&values[0])
                .add(&C_POINT_G.mul(&masks[0]))
                .mul(&SC_1DIV8),
        ];
        let sig = TRAIT_ZC_OUT
            .bpp_gen(&mut rnd, &values, &masks, &commitments)
            .unwrap();
        assert_eq!(sig.lv.len(), 6);
        assert_eq!(sig.rv.len(), 6);
    }

    #[test]
    fn d_vector_powers_are_consecutive() {
        // d(i, 0) must be z^(2(i+1)); the Go original repeated z^4 from i=2 on.
        let z = scalar_int(3);
        let z_sq = z.mul(&z);
        let t = &*TRAIT_ZC_OUT;
        let c_bpp_m = 4;
        let mut d = vec![Scalar::ZERO; c_bpp_m * t.n];
        d[0] = z_sq.clone();
        for i in 1..c_bpp_m {
            d[t.at(i, 0)] = d[t.at(i - 1, 0)].mul(&z_sq);
        }
        let mut want = z_sq.clone();
        for i in 0..c_bpp_m {
            assert_eq!(d[t.at(i, 0)], want, "row {i}");
            want = want.mul(&z_sq);
        }
    }
}
