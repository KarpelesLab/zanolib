//! Turning FROST key shares into the additive shares a Zano key image needs.

use crate::crypto::{Point, Scalar};
use crate::error::{Error, Result};
use tsslib::frost::Ed25519;
use tsslib::frost::binding::lagrange_coefficient;
use tsslib::frosttss::Key;

/// The share identifiers of a signing committee, in committee order — the basis
/// for Lagrange interpolation across the subset.
pub fn committee_share_ids(key: &Key) -> Vec<Vec<u8>> {
    key.ks.iter().map(|k| k.as_be_bytes().to_vec()).collect()
}

/// This party's Lagrange-weighted additive share `w_i` for the committee named
/// by `key.ks` (the key must already be reindexed with
/// [`Key::subset_for_parties`](tsslib::frosttss::Key::subset_for_parties)).
///
/// Summed over the committee the `w_i` reconstruct the group (spend) secret `x`
/// — but the sum is only ever formed implicitly, in the exponent, never as a
/// plaintext scalar.
pub fn additive_share(key: &Key) -> Result<Scalar> {
    let ids = committee_share_ids(key);
    let lambda = lagrange_coefficient::<Ed25519>(key.share_id.as_be_bytes(), &ids)
        .ok_or_else(|| Error::msg("zanompc: duplicate share id in the signing committee"))?;
    Ok(lambda.mul(&key.xi))
}

/// This party's contribution `w_i * base` to a threshold key image.
///
/// Summing every committee member's contribution (see [`combine_points`])
/// yields `x * base`, where `x` is the group spend secret and `base` is
/// typically `Hp(stealth_address)`. No party learns `x` or another party's
/// share.
pub fn partial_key_image(key: &Key, base: &Point) -> Result<Point> {
    Ok(base.mul(&additive_share(key)?))
}

/// Sums partial points (partial key images, nonce commitments, …).
pub fn combine_points(parts: &[Point]) -> Point {
    parts.iter().fold(Point::identity(), |acc, p| acc.add(p))
}
