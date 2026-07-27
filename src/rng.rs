//! Randomness sources.
//!
//! The Go original threads an `io.Reader` through every routine that needs
//! randomness, so callers can inject a deterministic stream in tests. The Rust
//! port threads `&mut dyn RngCore` (purecrypto's trait) for the same reason.

pub use purecrypto::rng::{OsRng, RngCore};

use purecrypto::hash::{ExtendableOutput, KeccakReader, Shake256, XofReader};

/// A deterministic byte stream, for tests and for the non-secret per-signature
/// randomness that every MPC party must derive identically.
///
/// Backed by SHAKE256 over a caller-supplied seed.
pub struct ShakeRng {
    reader: KeccakReader,
}

impl ShakeRng {
    /// Creates a stream seeded with `seed`.
    pub fn new(seed: &[u8]) -> ShakeRng {
        let mut xof = Shake256::new();
        xof.update(seed);
        ShakeRng {
            reader: xof.finalize_xof(),
        }
    }
}

impl RngCore for ShakeRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.reader.read(dest);
    }
}

/// A stream of one repeated byte. Mirrors the Go tests' `fakeRnd` (all `0x42`),
/// which keeps generated signatures reproducible.
#[derive(Clone, Copy, Debug)]
pub struct FixedRng(pub u8);

impl RngCore for FixedRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(self.0);
    }
}
