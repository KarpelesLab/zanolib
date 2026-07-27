//! Zano addresses: the base58-chunked encoding and the address types.

use crate::base::varint::{append_varint, take_varint};
use crate::error::{Error, Result};
use purecrypto::hash::keccak256;

/// The Bitcoin base58 alphabet, as used by Zano.
const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Encoded length of a chunk of `i` raw bytes.
const ENCODED_BLOCK_SIZES: [usize; 9] = [0, 2, 3, 5, 6, 7, 9, 10, 11];
/// Raw length of a chunk of `i` encoded characters, or `None` if impossible.
const DECODED_BLOCK_SIZES: [i8; 12] = [0, -1, 1, 2, -1, 3, 4, 5, -1, 6, 7, 8];
const FULL_BLOCK_SIZE: usize = 8;
const FULL_ENCODED_SIZE: usize = 11;

fn encode_block(block: &[u8], out: &mut String) {
    let size = block.len();
    assert!(
        (1..=FULL_BLOCK_SIZE).contains(&size),
        "invalid block length"
    );
    let mut num: u64 = 0;
    for b in block {
        num = (num << 8) | *b as u64;
    }
    let encoded_len = ENCODED_BLOCK_SIZES[size];
    let mut res = vec![ALPHABET[0]; encoded_len];
    let mut i = encoded_len;
    while num > 0 && i > 0 {
        i -= 1;
        res[i] = ALPHABET[(num % 58) as usize];
        num /= 58;
    }
    out.push_str(std::str::from_utf8(&res).expect("alphabet is ASCII"));
}

fn decode_digit(c: u8) -> Option<u64> {
    ALPHABET.iter().position(|a| *a == c).map(|v| v as u64)
}

fn decode_block(block: &str, out: &mut Vec<u8>) -> Result<()> {
    let size = block.len();
    if !(1..=FULL_ENCODED_SIZE).contains(&size) {
        return Err(Error::msg("base58: invalid block length"));
    }
    let raw_size = DECODED_BLOCK_SIZES[size];
    if raw_size < 0 {
        return Err(Error::msg("base58: invalid block length"));
    }
    let raw_size = raw_size as usize;

    let mut res_num: u64 = 0;
    for c in block.bytes() {
        if c > 127 {
            return Err(Error::msg("base58: non-ascii character"));
        }
        let idx =
            decode_digit(c).ok_or_else(|| crate::err!("base58: bad digit {:?}", c as char))?;
        if res_num > (u64::MAX - idx) / 58 {
            return Err(Error::msg("base58: overflow"));
        }
        res_num = res_num * 58 + idx;
    }
    if raw_size < 8 && res_num >= (1u64 << (raw_size * 8)) {
        return Err(Error::msg("base58: overflow"));
    }
    for n in (0..raw_size).rev() {
        out.push(((res_num >> (n * 8)) & 0xff) as u8);
    }
    Ok(())
}

/// Encodes bytes with Zano's chunked base58 (8-byte blocks -> 11 characters).
pub fn base58_encode_chunked(data: &[u8]) -> String {
    let mut out = String::new();
    for block in data.chunks(FULL_BLOCK_SIZE) {
        encode_block(block, &mut out);
    }
    out
}

/// Decodes Zano's chunked base58.
pub fn base58_decode_chunked(encoded: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    if encoded.is_empty() {
        return Ok(out);
    }
    let bytes = encoded.as_bytes();
    let full_blocks = bytes.len() / FULL_ENCODED_SIZE;
    for i in 0..full_blocks {
        let block = &encoded[i * FULL_ENCODED_SIZE..(i + 1) * FULL_ENCODED_SIZE];
        decode_block(block, &mut out)?;
    }
    if !bytes.len().is_multiple_of(FULL_ENCODED_SIZE) {
        decode_block(&encoded[full_blocks * FULL_ENCODED_SIZE..], &mut out)?;
    }
    Ok(out)
}

/// The kind of a Zano address, encoded as a varint prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressType {
    /// `Zx` — standard public address.
    Public,
    /// `iZ` — integrated address with a payment id.
    IntegratedV1,
    /// `iZ` — integrated address, v2 (carries flags).
    IntegratedV2,
    /// `aZx` — auditable public address.
    Audit,
    /// `aiZX` — auditable integrated address.
    AuditIntegrated,
    /// Any other prefix, preserved verbatim.
    Unknown(u64),
}

impl AddressType {
    /// The numeric prefix.
    pub fn prefix(&self) -> u64 {
        match self {
            AddressType::Public => 0xc5,
            AddressType::IntegratedV1 => 0x3678,
            AddressType::IntegratedV2 => 0x36f8,
            AddressType::Audit => 0x98c8,
            AddressType::AuditIntegrated => 0x8a49,
            AddressType::Unknown(v) => *v,
        }
    }

    /// Builds a type from its numeric prefix.
    pub fn from_prefix(v: u64) -> AddressType {
        match v {
            0xc5 => AddressType::Public,
            0x3678 => AddressType::IntegratedV1,
            0x36f8 => AddressType::IntegratedV2,
            0x98c8 => AddressType::Audit,
            0x8a49 => AddressType::AuditIntegrated,
            other => AddressType::Unknown(other),
        }
    }

    /// Whether this is an auditable address.
    pub fn auditable(&self) -> bool {
        matches!(self, AddressType::Audit | AddressType::AuditIntegrated)
    }

    /// Whether the encoding carries a flags byte.
    pub fn has_flags(&self) -> bool {
        matches!(
            self,
            AddressType::IntegratedV2 | AddressType::Audit | AddressType::AuditIntegrated
        )
    }
}

impl std::fmt::Display for AddressType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddressType::Public => f.write_str("Public Address (Zx)"),
            AddressType::IntegratedV1 => f.write_str("Integrated Address (iZ)"),
            AddressType::IntegratedV2 => f.write_str("Integrated Address V2 (iZ)"),
            AddressType::Audit => f.write_str("Audit Address (aZx)"),
            AddressType::AuditIntegrated => f.write_str("Audit Integrated Address (aiZX)"),
            AddressType::Unknown(v) => write!(f, "Unknown Address type ({v:x})"),
        }
    }
}

/// A parsed Zano address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address {
    /// The address type.
    pub typ: AddressType,
    /// Address flags (bit 0 = auditable).
    pub flags: u8,
    /// Public spend key (32 bytes).
    pub spend_key: Vec<u8>,
    /// Public view key (32 bytes).
    pub view_key: Vec<u8>,
    /// Integrated payment id, if any.
    pub payment_id: Vec<u8>,
}

impl Address {
    /// Parses a base58 Zano address, verifying its checksum.
    pub fn parse(addr: &str) -> Result<Address> {
        let payload = base58_decode_chunked(addr)?;
        if payload.len() < 64 + 4 {
            return Err(Error::msg("address is too short"));
        }
        let (body, cksum) = payload.split_at(payload.len() - 4);
        if keccak256(body)[..4] != *cksum {
            return Err(Error::msg("invalid checksum in address"));
        }

        let (typ_prefix, rest) = take_varint(body)?;
        if rest.len() < 64 {
            return Err(Error::msg("address is too short"));
        }
        let typ = AddressType::from_prefix(typ_prefix);
        let mut res = Address {
            typ,
            flags: 0,
            spend_key: rest[..32].to_vec(),
            view_key: rest[32..64].to_vec(),
            payment_id: rest[64..].to_vec(),
        };
        if typ.has_flags() {
            if res.payment_id.is_empty() {
                return Err(Error::msg("address is too short while reading flags"));
            }
            res.flags = res.payment_id.remove(0);
        } else if typ == AddressType::Public && !res.payment_id.is_empty() {
            // A public address carries no payment id, so trailing data is flags.
            res.flags = res.payment_id.remove(0);
        }
        Ok(res)
    }

    /// Sets (or clears, when empty) the integrated payment id, adjusting the
    /// address type accordingly.
    pub fn set_payment_id(&mut self, payment_id: &[u8]) -> Result<()> {
        if payment_id.len() > 128 {
            return Err(Error::msg("payment id is too long"));
        }
        if payment_id.is_empty() {
            self.payment_id.clear();
            self.typ = match self.typ {
                AddressType::IntegratedV1 | AddressType::IntegratedV2 => AddressType::Public,
                AddressType::AuditIntegrated => AddressType::Audit,
                other => other,
            };
            return Ok(());
        }
        self.payment_id = payment_id.to_vec();
        self.typ = match self.typ {
            AddressType::Public if self.flags != 0 => AddressType::IntegratedV2,
            AddressType::Public => AddressType::IntegratedV1,
            AddressType::Audit => AddressType::AuditIntegrated,
            other => other,
        };
        Ok(())
    }

    /// A compact debug rendering of the address' fields.
    pub fn debug_string(&self) -> String {
        format!(
            "type={} spendKey={} viewKey={} flags={:x} paymentId={}",
            self.typ,
            hex::encode(&self.spend_key),
            hex::encode(&self.view_key),
            self.flags,
            hex::encode(&self.payment_id)
        )
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut buf = Vec::new();
        append_varint(&mut buf, self.typ.prefix());
        buf.extend_from_slice(&self.spend_key);
        buf.extend_from_slice(&self.view_key);
        match self.typ {
            AddressType::Public => {
                // No payment id here, so any extra data means flags.
                if self.flags != 0 {
                    buf.push(self.flags);
                }
            }
            _ => {
                if self.typ.has_flags() {
                    buf.push(self.flags);
                }
                buf.extend_from_slice(&self.payment_id);
            }
        }
        let cksum = keccak256(&buf);
        buf.extend_from_slice(&cksum[..4]);
        f.write_str(&base58_encode_chunked(&buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base58_block_sizes() {
        // 8 raw bytes always encode to 11 characters.
        assert_eq!(base58_encode_chunked(&[0u8; 8]).len(), 11);
        assert_eq!(base58_encode_chunked(&[0xff; 8]).len(), 11);
        // Partial blocks use the size table.
        for (raw, enc) in [
            (1usize, 2usize),
            (2, 3),
            (3, 5),
            (4, 6),
            (5, 7),
            (6, 9),
            (7, 10),
        ] {
            assert_eq!(base58_encode_chunked(&vec![0xab; raw]).len(), enc);
        }
    }

    #[test]
    fn base58_round_trip() {
        for len in 1..40usize {
            let data: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(37)).collect();
            let enc = base58_encode_chunked(&data);
            assert_eq!(base58_decode_chunked(&enc).unwrap(), data, "len {len}");
        }
    }

    /// The vectors from the Go `TestAddressParse`, covering every address type.
    const VECTORS: &[(&str, &str, &str, &str, u8)] = &[
        (
            "ZxD5aoLDPTdcaRx4uCpyW4XiLfEXejepAVz8cSY2fwHNEiJNu6NmpBBDLGTJzCsUvn3acCVDVDPMV8yQXdPooAp338Se7AxeH",
            "9f5e1fa93630d4b281b18bb67a3db79e9622fc703cc3ad4a453a82e0a36d51fa",
            "a3f208c8f9ba49bab28eed62b35b0f6be0a297bcd85c2faa1eb1820527bcf7e3",
            "",
            0,
        ),
        (
            "iZ2Zi6RmTWwcaRx4uCpyW4XiLfEXejepAVz8cSY2fwHNEiJNu6NmpBBDLGTJzCsUvn3acCVDVDPMV8yQXdPooAp3iTqEsjvJoco1aLSZXS6T",
            "9f5e1fa93630d4b281b18bb67a3db79e9622fc703cc3ad4a453a82e0a36d51fa",
            "a3f208c8f9ba49bab28eed62b35b0f6be0a297bcd85c2faa1eb1820527bcf7e3",
            "87440d0b9acc42f1",
            0,
        ),
        (
            "ZxD5aoLDPTdcaRx4uCpyW4XiLfEXejepAVz8cSY2fwHNEiJNu6NmpBBDLGTJzCsUvn3acCVDVDPMV8yQXdPooAp3APrDvRoL5C",
            "9f5e1fa93630d4b281b18bb67a3db79e9622fc703cc3ad4a453a82e0a36d51fa",
            "a3f208c8f9ba49bab28eed62b35b0f6be0a297bcd85c2faa1eb1820527bcf7e3",
            "",
            0xfe,
        ),
        (
            "iZ4mBxubNfqcaRx4uCpyW4XiLfEXejepAVz8cSY2fwHNEiJNu6NmpBBDLGTJzCsUvn3acCVDVDPMV8yQXdPooAp3iTrG7nU5rRCWmcozLaMoY95sAbo6",
            "9f5e1fa93630d4b281b18bb67a3db79e9622fc703cc3ad4a453a82e0a36d51fa",
            "a3f208c8f9ba49bab28eed62b35b0f6be0a297bcd85c2faa1eb1820527bcf7e3",
            "3ba0527bcfb1fa93630d28eed6",
            0xfe,
        ),
        (
            "aZxb9Et6FhP9AinRwcPqSqBKjckre7PgoZjK3q5YG2fUKHYWFZMWjB6YAEAdw4yDDUGEQ7CGEgbqhGRKeadGV1jLYcEJMEmqQFn",
            "9f5e1fa93630d4b281b18bb67a3db79e9622fc703cc3ad4a453a82e0a36d51fa",
            "a3f208c8f9ba49bab28eed62b35b0f6be0a297bcd85c2faa1eb1820527bcf7e3",
            "",
            0x01,
        ),
        (
            "aiZXDondHWu9AinRwcPqSqBKjckre7PgoZjK3q5YG2fUKHYWFZMWjB6YAEAdw4yDDUGEQ7CGEgbqhGRKeadGV1jLYcEJM9xJH8EbjuRiMJgFmPRATsEV9",
            "9f5e1fa93630d4b281b18bb67a3db79e9622fc703cc3ad4a453a82e0a36d51fa",
            "a3f208c8f9ba49bab28eed62b35b0f6be0a297bcd85c2faa1eb1820527bcf7e3",
            "3ba0527bcfb1fa93630d28eed6",
            0x01,
        ),
    ];

    #[test]
    fn known_addresses_parse_and_reencode() {
        for (addr_str, spend, view, pid, flags) in VECTORS {
            // The base58 layer must round-trip on its own.
            let raw = base58_decode_chunked(addr_str).unwrap();
            assert_eq!(&base58_encode_chunked(&raw), addr_str);

            let addr = Address::parse(addr_str).unwrap_or_else(|e| panic!("{addr_str}: {e}"));
            assert_eq!(hex::encode(&addr.spend_key), *spend);
            assert_eq!(hex::encode(&addr.view_key), *view);
            assert_eq!(hex::encode(&addr.payment_id), *pid);
            assert_eq!(addr.flags, *flags);
            assert_eq!(&addr.to_string(), addr_str);
        }
    }

    #[test]
    fn address_types_are_recognized() {
        assert_eq!(
            Address::parse(VECTORS[0].0).unwrap().typ,
            AddressType::Public
        );
        assert_eq!(
            Address::parse(VECTORS[1].0).unwrap().typ,
            AddressType::IntegratedV1
        );
        assert_eq!(
            Address::parse(VECTORS[3].0).unwrap().typ,
            AddressType::IntegratedV2
        );
        assert_eq!(
            Address::parse(VECTORS[4].0).unwrap().typ,
            AddressType::Audit
        );
        assert_eq!(
            Address::parse(VECTORS[5].0).unwrap().typ,
            AddressType::AuditIntegrated
        );
    }

    #[test]
    fn set_payment_id_switches_type() {
        let mut addr = Address::parse(VECTORS[0].0).unwrap();
        assert_eq!(addr.typ, AddressType::Public);
        addr.set_payment_id(&[1, 2, 3, 4]).unwrap();
        assert_eq!(addr.typ, AddressType::IntegratedV1);
        let parsed = Address::parse(&addr.to_string()).unwrap();
        assert_eq!(parsed.payment_id, vec![1, 2, 3, 4]);
        addr.set_payment_id(&[]).unwrap();
        assert_eq!(addr.typ, AddressType::Public);
        assert!(addr.set_payment_id(&[0u8; 129]).is_err());
    }

    #[test]
    fn invalid_address_is_rejected() {
        assert!(Address::parse("invalid").is_err());
        assert!(Address::parse("").is_err());
    }

    #[test]
    fn address_round_trip() {
        let addr = Address {
            typ: AddressType::Public,
            flags: 0,
            spend_key: vec![1u8; 32],
            view_key: vec![2u8; 32],
            payment_id: Vec::new(),
        };
        let s = addr.to_string();
        assert!(s.starts_with("Zx"), "unexpected prefix in {s}");
        assert_eq!(Address::parse(&s).unwrap(), addr);
    }

    #[test]
    fn integrated_address_round_trip() {
        let mut addr = Address {
            typ: AddressType::Public,
            flags: 0,
            spend_key: vec![3u8; 32],
            view_key: vec![4u8; 32],
            payment_id: Vec::new(),
        };
        addr.set_payment_id(b"payment-id-1").unwrap();
        assert_eq!(addr.typ, AddressType::IntegratedV1);
        let parsed = Address::parse(&addr.to_string()).unwrap();
        assert_eq!(parsed.payment_id, b"payment-id-1");
        assert_eq!(parsed.spend_key, vec![3u8; 32]);
    }

    #[test]
    fn auditable_address_keeps_flags() {
        let addr = Address {
            typ: AddressType::Audit,
            flags: 1,
            spend_key: vec![5u8; 32],
            view_key: vec![6u8; 32],
            payment_id: Vec::new(),
        };
        let parsed = Address::parse(&addr.to_string()).unwrap();
        assert_eq!(parsed.flags, 1);
        assert_eq!(parsed.typ, AddressType::Audit);
        assert!(parsed.typ.auditable());
    }

    #[test]
    fn corrupt_checksum_is_rejected() {
        let addr = Address {
            typ: AddressType::Public,
            flags: 0,
            spend_key: vec![1u8; 32],
            view_key: vec![2u8; 32],
            payment_id: Vec::new(),
        };
        let s = addr.to_string();
        let mut chars: Vec<char> = s.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == 'A' { 'B' } else { 'A' };
        let broken: String = chars.into_iter().collect();
        assert!(Address::parse(&broken).is_err());
    }
}
