//! Keccak-256 based hashing helpers (Zano's `hash_helper_t`).

use super::{Point, Scalar};
use purecrypto::hash::{Digest, Keccak256};

/// Accumulates data into a Keccak-256 hash, with helpers for points, scalars
/// and raw 32-byte values, and extraction as either a scalar (reduced mod L) or
/// the raw digest.
#[derive(Clone)]
pub struct HashHelper {
    h: Keccak256,
}

impl Default for HashHelper {
    fn default() -> Self {
        Self::new()
    }
}

impl HashHelper {
    /// Creates an empty hasher.
    pub fn new() -> HashHelper {
        HashHelper {
            h: Keccak256::new(),
        }
    }

    /// Writes exactly 32 bytes.
    ///
    /// # Panics
    /// If `b` is not 32 bytes long (mirroring the Go helper's contract, which
    /// only ever receives hashes and domain separators).
    pub fn add_bytes(&mut self, b: &[u8]) {
        assert_eq!(b.len(), 32, "add_bytes expects 32 bytes");
        self.h.update(b);
    }

    /// Interprets `b` as a 32-byte little-endian value, reduces it modulo L and
    /// writes the resulting scalar.
    pub fn add_bytes_mod_l(&mut self, b: &[u8]) {
        assert_eq!(b.len(), 32, "add_bytes_mod_l expects 32 bytes");
        let s = super::scalar_from_wide(b);
        self.add_scalar(&s);
    }

    /// Writes a compressed point.
    pub fn add_point(&mut self, p: &Point) {
        self.h.update(&p.compress());
    }

    /// Writes several compressed points, in order.
    pub fn add_points(&mut self, ps: &[Point]) {
        for p in ps {
            self.add_point(p);
        }
    }

    /// Writes a canonical scalar.
    pub fn add_scalar(&mut self, s: &Scalar) {
        self.h.update(&s.to_bytes());
    }

    /// Writes several scalars, in order.
    pub fn add_scalars(&mut self, ss: &[Scalar]) {
        for s in ss {
            self.add_scalar(s);
        }
    }

    /// Writes arbitrary bytes (no length restriction).
    pub fn add_raw(&mut self, b: &[u8]) {
        self.h.update(b);
    }

    /// Finalizes, resets the state, and returns the digest reduced modulo L.
    pub fn calc_hash(&mut self) -> Scalar {
        let s = self.calc_hash_keep();
        self.h = Keccak256::new();
        s
    }

    /// Like [`HashHelper::calc_hash`] but keeps the state, so more data can be added.
    pub fn calc_hash_keep(&mut self) -> Scalar {
        let sum = self.h.clone().finalize();
        super::scalar_from_wide(&sum)
    }

    /// Finalizes, resets the state, and returns the raw 32-byte digest.
    pub fn calc_raw_hash(&mut self) -> [u8; 32] {
        let sum = self.h.clone().finalize();
        self.h = Keccak256::new();
        sum
    }
}

/// `keccak256(data) mod L`.
pub fn hash_to_scalar(data: &[u8]) -> Scalar {
    super::scalar_from_wide(&Keccak256::digest(data))
}

/// `keccak256(a || b || ...) mod L` over a list of byte chunks.
pub fn hs_bytes(chunks: &[&[u8]]) -> Scalar {
    let mut h = Keccak256::new();
    for c in chunks {
        h.update(c);
    }
    super::scalar_from_wide(&h.finalize())
}

/// Keccak-256 of the concatenation of `chunks`.
pub fn keccak_concat(chunks: &[&[u8]]) -> [u8; 32] {
    let mut h = Keccak256::new();
    for c in chunks {
        h.update(c);
    }
    h.finalize()
}

const KECCAK_ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];
const KECCAK_ROTATIONS: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];
const KECCAK_PI_LANES: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

/// The Keccak-f[1600] permutation.
fn keccak_f1600(st: &mut [u64; 25]) {
    for rc in KECCAK_ROUND_CONSTANTS {
        // θ
        let mut bc = [0u64; 5];
        for (i, b) in bc.iter_mut().enumerate() {
            *b = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        }
        for i in 0..5 {
            let t = bc[(i + 4) % 5] ^ bc[(i + 1) % 5].rotate_left(1);
            for j in (0..25).step_by(5) {
                st[j + i] ^= t;
            }
        }
        // ρ and π
        let mut t = st[1];
        for (rot, lane) in KECCAK_ROTATIONS.iter().zip(KECCAK_PI_LANES) {
            let next = st[lane];
            st[lane] = t.rotate_left(*rot);
            t = next;
        }
        // χ
        for j in (0..25).step_by(5) {
            let row = [st[j], st[j + 1], st[j + 2], st[j + 3], st[j + 4]];
            for i in 0..5 {
                st[j + i] = row[i] ^ (!row[(i + 1) % 5] & row[(i + 2) % 5]);
            }
        }
        // ι
        st[0] ^= rc;
    }
}

/// Zano's `keccak(in, inlen, md, mdlen)`: original (pre-SHA-3) Keccak padding
/// with a rate of `200 - 2*mdlen` bytes, returning the first `mdlen` bytes of
/// the state. `mdlen` = 32 is plain Keccak-256; zano also uses other lengths,
/// e.g. 40 bytes to derive a ChaCha key and IV in one go.
///
/// # Panics
/// If `mdlen` is 0 or larger than 99 (no room left for the rate).
pub fn keccak_variable(input: &[u8], mdlen: usize) -> Vec<u8> {
    assert!(
        (1..100).contains(&mdlen),
        "keccak_variable: unsupported output length {mdlen}"
    );
    let rate = 200 - 2 * mdlen;
    let mut st = [0u64; 25];
    let absorb = |st: &mut [u64; 25], block: &[u8]| {
        for (i, lane) in block.chunks(8).enumerate() {
            let mut b = [0u8; 8];
            b[..lane.len()].copy_from_slice(lane);
            st[i] ^= u64::from_le_bytes(b);
        }
        keccak_f1600(st);
    };
    let mut blocks = input.chunks_exact(rate);
    for block in blocks.by_ref() {
        absorb(&mut st, block);
    }
    let rest = blocks.remainder();
    let mut last = vec![0u8; rate];
    last[..rest.len()].copy_from_slice(rest);
    last[rest.len()] = 1;
    last[rate - 1] |= 0x80;
    absorb(&mut st, &last);

    st.iter()
        .flat_map(|lane| lane.to_le_bytes())
        .take(mdlen)
        .collect()
}

#[cfg(test)]
mod keccak_tests {
    use super::*;

    #[test]
    fn keccak_variable_matches_keccak256_at_32_bytes() {
        for len in [0usize, 1, 31, 32, 135, 136, 137, 300] {
            let input: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            assert_eq!(
                keccak_variable(&input, 32),
                purecrypto::hash::keccak256(&input).to_vec(),
                "len {len}"
            );
        }
    }
}
