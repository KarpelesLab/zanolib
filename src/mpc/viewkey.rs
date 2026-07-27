//! A deterministic view key for a threshold wallet.

use super::sign::{combine_points, partial_key_image};
use super::signer::ThresholdInputSigner;
use super::transport::exchange;
use crate::crypto::{Point, Scalar, hash_to_scalar, hp};
use crate::error::Result;
use serde::{Deserialize, Serialize};

/// Domain separator for the view-key base point.
const VIEW_KEY_BASE_DOMAIN: &[u8] = b"ZANO_THRESHOLD_VIEWKEY\x00";
/// Domain separator for the final view secret.
const VIEW_KEY_SECRET_DOMAIN: &[u8] = b"ZANO_THRESHOLD_VIEWKEY_SECRET\x00";

/// One party's contribution `w_i*P` to the deterministic view key derivation.
#[derive(Clone, Serialize, Deserialize)]
struct ViewKeyMsg {
    /// `w_i * P`, hex.
    partial: String,
}

/// The fixed base point `P = Hp("ZANO_THRESHOLD_VIEWKEY\0" || spendPub)` used to
/// derive the deterministic threshold view secret.
///
/// It is a pure function of the group spend public key, so every committee
/// member computes the same `P`. Both the base point and the final scalar are
/// domain-separated, so the derived value can never collide with — or be linked
/// to — a real on-chain key image (whose base is `Hp(stealth_address)`, with no
/// prefix).
pub fn view_key_base(spend_pub: &Point) -> Point {
    let mut buf = VIEW_KEY_BASE_DOMAIN.to_vec();
    buf.extend_from_slice(&spend_pub.compress());
    hp(&buf)
}

impl ThresholdInputSigner {
    /// Derives the wallet's view secret key deterministically from the shared
    /// spend secret `x`, without anyone reconstructing `x`.
    ///
    /// It computes the "key image" `V = x*P` of the fixed base point
    /// `P = view_key_base(spendPub)` — a deterministic PRF on `x` — by summing
    /// every party's partial `w_i*P` over the broker, then hashes `V` to a
    /// scalar (the same unclamped Keccak-to-scalar convention Zano uses for
    /// view keys):
    ///
    /// ```text
    /// view_secret = HashToScalar("ZANO_THRESHOLD_VIEWKEY_SECRET\0" || V)
    /// ```
    ///
    /// The result is identical on every committee member and reproducible from
    /// the same key shares, so a threshold wallet has a stable view key (and
    /// therefore a stable address) with no random value and no out-of-band
    /// agreement. The matching view public key is `view_secret*G`.
    ///
    /// Call this once per signer; it uses its own broker topic and does not
    /// disturb the key-image / signature pairing.
    pub fn derive_view_secret(&self) -> Result<Scalar> {
        let p = view_key_base(&self.spend_pub_key());

        let my_partial = partial_key_image(self.subset(), &p)?;
        let collected: Vec<ViewKeyMsg> = exchange(
            self.params(),
            "zano:viewkey",
            &ViewKeyMsg {
                partial: hex::encode(my_partial.compress()),
            },
        )?;

        let mut partials = Vec::with_capacity(collected.len());
        for (i, m) in collected.iter().enumerate() {
            let raw = hex::decode(&m.partial)
                .map_err(|e| crate::err!("zanompc: bad view-key partial from party {i}: {e}"))?;
            partials.push(
                crate::crypto::point_from_bytes(&raw).map_err(|e| {
                    crate::err!("zanompc: bad view-key partial from party {i}: {e}")
                })?,
            );
        }

        // V = sum_j(w_j*P) = x*P
        let v = combine_points(&partials);

        let mut buf = VIEW_KEY_SECRET_DOMAIN.to_vec();
        buf.extend_from_slice(&v.compress());
        Ok(hash_to_scalar(&buf))
    }
}
