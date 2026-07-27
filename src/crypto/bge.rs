//! One-out-of-many (BGE) proofs — `src/crypto/one_out_of_many_proofs.cpp`.

use super::consts::{C_POINT_0, C_POINT_X, SC_1DIV8};
use super::hash::{HashHelper, hash_to_scalar};
use super::hashtoec::hp;
use super::maths::{ceil_log_n, int_pow};
use super::{Point, Scalar, random_scalar, scalar_int};
use crate::base::sig::BgeProof;
use crate::error::{Error, Result};
use crate::rng::RngCore;
use std::sync::LazyLock;

/// Number of digits per position; `n` in the paper.
const BGE_N: usize = 4;

/// The 32 precomputed BGE generators (`mn_max * 2`).
static BGE_GENERATORS: LazyLock<Vec<Point>> = LazyLock::new(|| {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&hash_to_scalar(b"Zano BGE generator").to_bytes());
    (0..32u8)
        .map(|i| {
            let mut b = buf;
            b[32] = i;
            hp(&b)
        })
        .collect()
});

/// Returns the BGE generator at `index`, or `None` if it is out of range.
pub fn bge_generator(index: usize) -> Option<Point> {
    BGE_GENERATORS.get(index).copied()
}

/// Generates a one-out-of-many proof: the prover knows the discrete log of one
/// ring element (at `secret_index`) with respect to `X`, without revealing which.
pub fn generate_bge_proof(
    rnd: &mut dyn RngCore,
    context_hash: &[u8],
    ring: &[Point],
    secret: &Scalar,
    secret_index: usize,
) -> Result<BgeProof> {
    let n = BGE_N;
    let ring_size = ring.len();
    if ring_size == 0 {
        return Err(Error::msg("generate_bge_proof: empty ring"));
    }
    if secret_index >= ring_size {
        return Err(Error::msg("generate_bge_proof: invalid secretIndex"));
    }

    let m = ceil_log_n(ring_size, n).max(1);
    let big_n = int_pow(n, m);
    let mn = m * n;

    // a_mat is an m x n matrix of scalars, row-major: index (j, i) = j*n + i.
    let idx = |j: usize, i: usize| j * n + i;
    let mut a_mat: Vec<Scalar> = vec![Scalar::ZERO; mn];
    let mut l_digits = vec![0usize; m];
    let mut l = secret_index;
    for j in 0..m {
        let mut row0 = Scalar::ZERO;
        for i in (1..n).rev() {
            let a = random_scalar(rnd);
            row0 = row0.sub(&a);
            a_mat[idx(j, i)] = a;
        }
        a_mat[idx(j, 0)] = row0;
        l_digits[j] = l % n; // j-th digit of secret_index
        l /= n;
    }

    // coeffs is an m x N matrix (naive construction, as in the C++ original).
    let mut coeffs: Vec<Scalar> = vec![Scalar::ZERO; big_n * m];
    for i in 0..big_n {
        coeffs[i] = Scalar::ONE; // first row is (1, ..., 1)
        let mut i_tmp = i;
        let mut m_bound = 1usize;
        for j in 0..m {
            let i_j = i_tmp % n; // j-th digit of i
            i_tmp /= n;

            if i_j == l_digits[j] {
                let mut carry = Scalar::ZERO;
                for k in 0..m_bound {
                    let old = coeffs[k * big_n + i].clone();
                    coeffs[k * big_n + i] =
                        coeffs[k * big_n + i].mul(&a_mat[idx(j, i_j)]).add(&carry);
                    carry = old;
                }
                if m_bound < m {
                    coeffs[m_bound * big_n + i] = coeffs[m_bound * big_n + i].add(&carry);
                }
                m_bound += 1;
            } else {
                for k in 0..m_bound {
                    coeffs[k * big_n + i] = coeffs[k * big_n + i].mul(&a_mat[idx(j, i_j)]);
                }
            }
        }
    }

    let r_a = random_scalar(rnd);
    let r_b = random_scalar(rnd);
    let ro: Vec<Scalar> = (0..m).map(|_| random_scalar(rnd)).collect();

    let mut big_a = *C_POINT_0;
    let mut big_b = *C_POINT_0;
    let mut pk = Vec::with_capacity(m);

    for j in 0..m {
        for i in 0..n {
            let gen_1 = bge_generator((j * n + i) * 2)
                .ok_or_else(|| Error::msg("failed to run get_BGE_generator"))?;
            let gen_2 = bge_generator((j * n + i) * 2 + 1)
                .ok_or_else(|| Error::msg("failed to run get_BGE_generator"))?;
            let a = &a_mat[idx(j, i)];
            // A += a*gen_1 - a^2*gen_2
            big_a = big_a.add(&gen_1.mul(a).sub(&gen_2.mul(&a.mul(a))));
            if l_digits[j] == i {
                // B += gen_1 - a*gen_2
                big_b = big_b.add(&gen_1.sub(&gen_2.mul(a)));
            } else {
                // B += a*gen_2
                big_b = big_b.add(&gen_2.mul(a));
            }
        }

        let mut p_k = *C_POINT_0;
        for i in 0..ring_size {
            p_k = p_k.add(&ring[i].mul(&coeffs[j * big_n + i]));
        }
        for i in ring_size..big_n {
            p_k = p_k.add(&ring[ring_size - 1].mul(&coeffs[j * big_n + i]));
        }
        p_k = p_k.add(&C_POINT_X.mul(&ro[j]));
        pk.push(p_k.mul(&SC_1DIV8));
    }

    big_a = big_a.add(&C_POINT_X.mul(&r_a));
    let out_a = big_a.mul(&SC_1DIV8);
    big_b = big_b.add(&C_POINT_X.mul(&r_b));
    let out_b = big_b.mul(&SC_1DIV8);

    let mut hsc = HashHelper::new();
    hsc.add_bytes(context_hash);
    for el in ring {
        hsc.add_point(&el.mul(&SC_1DIV8));
    }
    hsc.add_point(&out_a);
    hsc.add_point(&out_b);
    for el in &pk {
        hsc.add_point(el);
    }
    let x = hsc.calc_hash();

    let mut f = vec![Scalar::ZERO; m * (n - 1)];
    for j in 0..m {
        for i in 1..n {
            let mut v = a_mat[idx(j, i)].clone();
            if l_digits[j] == i {
                v = v.add(&x);
            }
            f[j * (n - 1) + i - 1] = v;
        }
    }

    let y = r_a.add(&x.mul(&r_b));

    let mut z = Scalar::ZERO;
    let mut x_power = scalar_int(1);
    for r in ro.iter().take(m) {
        z = z.sub(&x_power.mul(r));
        x_power = x_power.mul(&x);
    }
    let z = z.add(&secret.mul(&x_power));

    Ok(BgeProof {
        a: out_a,
        b: out_b,
        pk,
        f,
        y,
        z,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::FixedRng;

    #[test]
    fn generators_are_distinct_and_prime_order() {
        for i in 0..32 {
            let g = bge_generator(i).unwrap();
            assert!(bool::from(g.is_torsion_free()));
            for j in 0..i {
                assert_ne!(g, bge_generator(j).unwrap());
            }
        }
        assert!(bge_generator(32).is_none());
    }

    #[test]
    fn proof_shape_matches_ring_size() {
        // m = ceil_log_4(ring), f has m*(n-1) entries and pk has m entries.
        for (ring_size, want_m) in [(1usize, 1usize), (3, 1), (4, 1), (5, 2), (16, 2)] {
            let ring: Vec<Point> = (0..ring_size)
                .map(|i| Point::mul_base(&scalar_int(i as u64 + 1)))
                .collect();
            let secret = scalar_int(7);
            let mut rnd = FixedRng(0x42);
            let p = generate_bge_proof(&mut rnd, &[9u8; 32], &ring, &secret, 0).unwrap();
            assert_eq!(p.pk.len(), want_m, "ring size {ring_size}");
            assert_eq!(p.f.len(), want_m * 3, "ring size {ring_size}");
        }
    }

    #[test]
    fn a_matrix_rows_sum_to_zero() {
        // The proof's soundness relies on each row of a_mat summing to zero;
        // this is what the row-major (j*n + i) indexing guarantees.
        let n = BGE_N;
        let m = 2;
        let idx = |j: usize, i: usize| j * n + i;
        let mut rnd = FixedRng(0x11);
        let mut a_mat = vec![Scalar::ZERO; m * n];
        for j in 0..m {
            let mut row0 = Scalar::ZERO;
            for i in (1..n).rev() {
                let a = random_scalar(&mut rnd);
                row0 = row0.sub(&a);
                a_mat[idx(j, i)] = a;
            }
            a_mat[idx(j, 0)] = row0;
        }
        for j in 0..m {
            let mut sum = Scalar::ZERO;
            for i in 0..n {
                sum = sum.add(&a_mat[idx(j, i)]);
            }
            assert_eq!(sum, Scalar::ZERO, "row {j}");
        }
    }
}
