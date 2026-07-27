//! CryptoNote-style base-128 varints.

use crate::error::{Error, Result};

/// Encodes `v` as a varint.
pub fn varint_bytes(v: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(varint_packed_size(v));
    append_varint(&mut out, v);
    out
}

/// Appends the varint encoding of `v` to `out`.
pub fn append_varint(out: &mut Vec<u8>, mut v: u64) {
    // Note: the Go original used `v > 0x80` here, which emitted a bare 0x80 —
    // a truncated varint — for exactly 128. This uses `>= 0x80`, matching
    // zano's C++ `tools::write_varint`.
    while v >= 0x80 {
        out.push((v as u8 & 0x7f) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// The number of bytes [`append_varint`] will emit for `v`: one per 7 bits,
/// so up to 10 for a full 64-bit value.
///
/// (The Go original's table stopped at 8, under-reporting everything above
/// 2^49.)
pub fn varint_packed_size(v: u64) -> usize {
    let bits = 64 - v.leading_zeros() as usize;
    bits.div_ceil(7).max(1)
}

/// Decodes a varint from the front of `buf`, returning the value and the rest.
pub fn take_varint(buf: &[u8]) -> Result<(u64, &[u8])> {
    let mut v: u64 = 0;
    let mut shift = 0u32;
    for (i, b) in buf.iter().enumerate() {
        v |= ((*b as u64) & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Ok((v, &buf[i + 1..]));
        }
        shift += 7;
        if shift >= 70 {
            return Err(Error::msg("varint is too long"));
        }
    }
    Err(Error::UnexpectedEof)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        for v in [
            0u64,
            42,
            127,
            128,
            129,
            1337,
            0x3fff,
            0x4000,
            0x123456789,
            0xabcdef123456789,
            u64::MAX,
        ] {
            let buf = varint_bytes(v);
            assert_eq!(buf.len(), varint_packed_size(v), "size of {v:#x}");
            let (dec, rest) = take_varint(&buf).unwrap();
            assert_eq!(dec, v, "decoding {v:#x}");
            assert!(rest.is_empty(), "trailing data decoding {v:#x}");
        }
    }

    #[test]
    fn one_twenty_eight_is_two_bytes() {
        // The Go implementation emitted a single 0x80 here, which is a
        // truncated varint: decoding it consumes the following field.
        assert_eq!(varint_bytes(128), vec![0x80, 0x01]);
    }

    #[test]
    fn known_encodings() {
        assert_eq!(varint_bytes(0), vec![0x00]);
        assert_eq!(varint_bytes(127), vec![0x7f]);
        assert_eq!(varint_bytes(300), vec![0xac, 0x02]);
    }

    #[test]
    fn truncated_input_errors() {
        assert!(take_varint(&[]).is_err());
        assert!(take_varint(&[0x80]).is_err());
    }
}
