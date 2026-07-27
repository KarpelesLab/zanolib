//! Small shared value types.

use super::ser::{EpeeRead, EpeeWrite, Reader};
use crate::crypto::{Point, Scalar};
use crate::error::Result;
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize, Serializer};

/// A fixed 32-byte value: hashes, keys and other 256-bit identifiers.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Value256(pub [u8; 32]);

impl Value256 {
    /// The all-zero value.
    pub const ZERO: Value256 = Value256([0u8; 32]);

    /// Borrows the bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Whether every byte is zero.
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }

    /// Decodes as a compressed curve point, or `None` if the bytes are not a
    /// valid point.
    pub fn to_point(&self) -> Option<Point> {
        Point::decompress(&self.0)
    }

    /// Builds a value from a point's compressed encoding.
    pub fn from_point(p: &Point) -> Value256 {
        Value256(p.compress())
    }

    /// Builds a value from a scalar's canonical encoding.
    pub fn from_scalar(s: &Scalar) -> Value256 {
        Value256(s.to_bytes())
    }

    /// Parses a 64-character hex string.
    pub fn from_hex(s: &str) -> Result<Value256> {
        let v = hex::decode(s)?;
        let arr: [u8; 32] = v
            .as_slice()
            .try_into()
            .map_err(|_| crate::err!("expected 32 bytes, got {}", v.len()))?;
        Ok(Value256(arr))
    }
}

impl From<[u8; 32]> for Value256 {
    fn from(v: [u8; 32]) -> Value256 {
        Value256(v)
    }
}

impl std::fmt::Display for Value256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl std::fmt::Debug for Value256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Value256({})", hex::encode(self.0))
    }
}

impl Serialize for Value256 {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for Value256 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Value256, D::Error> {
        let s = String::deserialize(d)?;
        Value256::from_hex(&s).map_err(de::Error::custom)
    }
}

impl EpeeWrite for Value256 {
    fn write_epee(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }
}
impl EpeeRead for Value256 {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Value256(r.read_32()?))
    }
}

/// A Zano account's public keys.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountPublicAddr {
    /// Public spend key.
    pub spend_key: Value256,
    /// Public view key.
    pub view_key: Value256,
    /// Address flags (bit 0 = auditable).
    pub flags: u8,
}

impl EpeeWrite for AccountPublicAddr {
    fn write_epee(&self, out: &mut Vec<u8>) {
        self.spend_key.write_epee(out);
        self.view_key.write_epee(out);
        out.push(self.flags);
    }
}
impl EpeeRead for AccountPublicAddr {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        Ok(AccountPublicAddr {
            spend_key: Value256::read_epee(r)?,
            view_key: Value256::read_epee(r)?,
            flags: r.read_byte()?,
        })
    }
}

/// References an output by its source transaction hash and output index.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefById {
    /// Source transaction hash.
    pub hash: Value256,
    /// Output index within that transaction.
    pub n: u32,
}

impl EpeeWrite for RefById {
    fn write_epee(&self, out: &mut Vec<u8>) {
        self.hash.write_epee(out);
        self.n.write_epee(out);
    }
}
impl EpeeRead for RefById {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        Ok(RefById {
            hash: Value256::read_epee(r)?,
            n: u32::read_epee(r)?,
        })
    }
}

/// Pairs an output index with its key image.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct KeyImageIndex {
    /// Index of the output within the transaction.
    pub out_index: u64,
    /// The output's key image.
    pub image: Value256,
}

impl EpeeWrite for KeyImageIndex {
    fn write_epee(&self, out: &mut Vec<u8>) {
        self.out_index.write_epee(out);
        self.image.write_epee(out);
    }
}
impl EpeeRead for KeyImageIndex {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        Ok(KeyImageIndex {
            out_index: u64::read_epee(r)?,
            image: Value256::read_epee(r)?,
        })
    }
}

/// A public/secret key pair.
#[derive(Clone, Debug)]
pub struct KeyPair {
    /// Public key.
    pub pub_key: Point,
    /// Secret key.
    pub sec: Scalar,
}
