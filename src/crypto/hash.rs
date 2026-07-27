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
