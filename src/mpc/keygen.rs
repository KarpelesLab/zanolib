//! Turning a FROST group public key into a Zano spend key and address.

use crate::address::{Address, AddressType};
use crate::base::Value256;
use crate::crypto::Point;
use crate::error::{Error, Result};

/// The 32-byte Zano spend public key encoding of a FROST group public key.
///
/// FROST encodes points in canonical RFC 8032 form, identical to Zano's
/// ed25519 point encoding.
pub fn spend_public_key_bytes(group_pub: &Point) -> Result<Value256> {
    let enc = group_pub.compress();
    // Validate that it decodes as a canonical ed25519 point.
    Point::decompress(&enc)
        .ok_or_else(|| Error::msg("group public key is not a valid ed25519 point"))?;
    Ok(Value256(enc))
}

/// The threshold spend public key as a curve point.
pub fn spend_public_key(group_pub: &Point) -> Result<Point> {
    let b = spend_public_key_bytes(group_pub)?;
    Point::decompress(&b.0).ok_or(Error::InvalidPoint)
}

/// Builds the Zano address for a threshold wallet from its FROST group (spend)
/// public key and a view public key.
///
/// `flags` is 0 for a standard wallet or 1 for auditable.
pub fn address(group_pub: &Point, view_pub: &[u8], flags: u8) -> Result<Address> {
    let spend = spend_public_key_bytes(group_pub)?;
    if view_pub.len() != 32 {
        return Err(crate::err!(
            "view public key must be 32 bytes, got {}",
            view_pub.len()
        ));
    }
    let typ = if flags & 1 == 1 {
        AddressType::Audit
    } else {
        AddressType::Public
    };
    Ok(Address {
        typ,
        flags,
        spend_key: spend.0.to_vec(),
        view_key: view_pub.to_vec(),
        payment_id: Vec::new(),
    })
}
