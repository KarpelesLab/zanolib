//! A deterministic view key for a threshold wallet.

use super::signer::ThresholdInputSigner;
use crate::crypto::{Point, Scalar};
use crate::error::Result;
use purecrypto::hash::HashAlgorithm;

/// The key-image identifier the view secret is derived under.
///
/// Distinct identifiers give unlinkable secrets from the same shares, so this
/// label is what separates the view key from any other value a committee might
/// derive with the same ceremony.
pub const VIEW_KEY_IDENTIFIER: &[u8] = b"ZANO_THRESHOLD_VIEWKEY";

/// Keccak-256, matching the hash Zano uses everywhere else.
const VIEW_KEY_HASH: HashAlgorithm = HashAlgorithm::Keccak256;

impl ThresholdInputSigner {
    /// Derives the wallet's view secret key deterministically from the shared
    /// spend secret `x`, without anyone reconstructing `x`.
    ///
    /// Zano's usual `view = keccak(spend_secret)` cannot run under MPC, so the
    /// committee instead runs tsslib's threshold key-image ceremony — a
    /// distributed PRF — over [`VIEW_KEY_IDENTIFIER`]: each party contributes
    /// `W_i = λ_i·s_i·P` for a point `P` bound to the identifier and the group
    /// public key, the partials sum to `V = x·P`, and the secret is
    /// `HashToScalar(identifier, V)`. The shared secret never assembles, every
    /// party learns the identical value, and each partial carries a DLEQ proof
    /// so a wrong contribution is caught and its sender named.
    ///
    /// Partials travel point-to-point, never broadcast: `t+1` of them
    /// reconstruct `V`, so the ceremony depends on the per-recipient
    /// confidentiality the broker contract requires.
    ///
    /// The result is stable across runs and across any qualifying committee, so
    /// a threshold wallet has a fixed view key — and therefore a fixed address —
    /// with no random value and no out-of-band agreement. The matching view
    /// public key is `view_secret*G`; see [`ThresholdInputSigner::derive_view_keys`].
    ///
    /// Every committee member must call this, and it must not run concurrently
    /// with a signing session on the same broker.
    pub fn derive_view_secret(&self) -> Result<Scalar> {
        let party = self
            .subset()
            .new_key_image(
                VIEW_KEY_IDENTIFIER.to_vec(),
                self.params().clone(),
                VIEW_KEY_HASH,
            )
            .map_err(|e| crate::err!("zanompc: view key ceremony: {e}"))?;
        let res = party
            .wait()
            .map_err(|e| crate::err!("zanompc: view key ceremony: {e}"))?;
        // Note: `res.public_key` is the *child spend* key (group_pub + secret*G)
        // the ceremony defines for tweaked signing — not the Zano view key.
        Ok(res.secret)
    }

    /// [`ThresholdInputSigner::derive_view_secret`] plus the matching view
    /// public key `view_secret*G`, which is what goes into the address.
    pub fn derive_view_keys(&self) -> Result<(Scalar, Point)> {
        let secret = self.derive_view_secret()?;
        let public = Point::mul_base(&secret);
        Ok((secret, public))
    }
}
