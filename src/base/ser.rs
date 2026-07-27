//! The binary (de)serialization used by Zano's `BEGIN_SERIALIZE_OBJECT` blobs.
//!
//! Layout rules, mirroring the Go reflection-based codec this replaces:
//!   * integers are fixed-width little endian unless a field is explicitly a
//!     varint (each struct writes its own varint fields),
//!   * `Vec<T>` and byte strings are prefixed with a varint count,
//!   * points and scalars are their bare 32-byte encodings.

use crate::crypto::{Point, Scalar};
use crate::error::{Error, Result};

use super::varint::append_varint;

/// Maximum element count accepted for a length-prefixed vector.
pub const MAX_VEC_LEN: u64 = 128;
/// Maximum byte length accepted for a length-prefixed byte string.
pub const MAX_BYTES_LEN: u64 = 4096;

/// A cursor over an in-memory blob.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Wraps a byte slice.
    pub fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf, pos: 0 }
    }

    /// The bytes not yet consumed.
    pub fn remaining(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    /// Whether every byte has been consumed.
    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// How many bytes have been consumed so far.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Reads one byte.
    pub fn read_byte(&mut self) -> Result<u8> {
        if self.pos >= self.buf.len() {
            return Err(Error::UnexpectedEof);
        }
        let b = self.buf[self.pos];
        self.pos += 1;
        Ok(b)
    }

    /// Reads exactly `n` bytes.
    pub fn read_exact(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.buf.len() - self.pos < n {
            return Err(Error::UnexpectedEof);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// Reads a fixed 32-byte value.
    pub fn read_32(&mut self) -> Result<[u8; 32]> {
        let mut out = [0u8; 32];
        out.copy_from_slice(self.read_exact(32)?);
        Ok(out)
    }

    /// Reads a varint.
    pub fn read_varint(&mut self) -> Result<u64> {
        let mut v: u64 = 0;
        let mut shift = 0u32;
        loop {
            let b = self.read_byte()?;
            v |= ((b as u64) & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Ok(v);
            }
            shift += 7;
            if shift >= 70 {
                return Err(Error::msg("varint is too long"));
            }
        }
    }

    /// Reads a varint-prefixed byte string.
    pub fn read_var_bytes(&mut self) -> Result<Vec<u8>> {
        let n = self.read_varint()?;
        if n > MAX_BYTES_LEN {
            return Err(crate::err!("byte string too long: {n}"));
        }
        Ok(self.read_exact(n as usize)?.to_vec())
    }

    /// Reads a varint-prefixed UTF-8 string (invalid bytes are replaced).
    pub fn read_var_string(&mut self) -> Result<String> {
        Ok(String::from_utf8_lossy(&self.read_var_bytes()?).into_owned())
    }

    /// Reads a varint-counted vector.
    pub fn read_vec<T: EpeeRead>(&mut self) -> Result<Vec<T>> {
        let n = self.read_varint()?;
        if n > MAX_VEC_LEN {
            return Err(crate::err!("slice too large: {n} > {MAX_VEC_LEN}"));
        }
        let mut out = Vec::with_capacity(n as usize);
        for _ in 0..n {
            out.push(T::read_epee(self)?);
        }
        Ok(out)
    }
}

/// Types that can be written in Zano's binary format.
pub trait EpeeWrite {
    /// Appends the encoding of `self` to `out`.
    fn write_epee(&self, out: &mut Vec<u8>);

    /// Convenience: encodes `self` into a fresh buffer.
    fn to_epee_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write_epee(&mut out);
        out
    }
}

/// Types that can be read from Zano's binary format.
pub trait EpeeRead: Sized {
    /// Reads one value from `r`.
    fn read_epee(r: &mut Reader<'_>) -> Result<Self>;

    /// Convenience: decodes a value from a complete blob, requiring that every
    /// byte be consumed.
    fn from_epee_bytes(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf);
        let v = Self::read_epee(&mut r)?;
        if !r.is_empty() {
            return Err(Error::msg("trailing data"));
        }
        Ok(v)
    }
}

/// Writes a varint-counted vector.
pub fn write_vec<T: EpeeWrite>(v: &[T], out: &mut Vec<u8>) {
    append_varint(out, v.len() as u64);
    for e in v {
        e.write_epee(out);
    }
}

/// Writes a varint-prefixed byte string.
pub fn write_var_bytes(b: &[u8], out: &mut Vec<u8>) {
    append_varint(out, b.len() as u64);
    out.extend_from_slice(b);
}

macro_rules! int_codec {
    ($t:ty) => {
        impl EpeeWrite for $t {
            fn write_epee(&self, out: &mut Vec<u8>) {
                out.extend_from_slice(&self.to_le_bytes());
            }
        }
        impl EpeeRead for $t {
            fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
                let n = std::mem::size_of::<$t>();
                let b = r.read_exact(n)?;
                let mut a = [0u8; std::mem::size_of::<$t>()];
                a.copy_from_slice(b);
                Ok(<$t>::from_le_bytes(a))
            }
        }
    };
}

int_codec!(u8);
int_codec!(u16);
int_codec!(u32);
int_codec!(u64);

impl EpeeWrite for bool {
    fn write_epee(&self, out: &mut Vec<u8>) {
        out.push(*self as u8);
    }
}
impl EpeeRead for bool {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        Ok(r.read_byte()? != 0)
    }
}

impl EpeeWrite for [u8; 32] {
    fn write_epee(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
}
impl EpeeRead for [u8; 32] {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        r.read_32()
    }
}

impl EpeeWrite for Vec<u8> {
    fn write_epee(&self, out: &mut Vec<u8>) {
        write_var_bytes(self, out);
    }
}
impl EpeeRead for Vec<u8> {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        r.read_var_bytes()
    }
}

impl EpeeWrite for String {
    fn write_epee(&self, out: &mut Vec<u8>) {
        write_var_bytes(self.as_bytes(), out);
    }
}
impl EpeeRead for String {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        r.read_var_string()
    }
}

impl EpeeWrite for Point {
    fn write_epee(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.compress());
    }
}
impl EpeeRead for Point {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        let b = r.read_32()?;
        Point::decompress(&b).ok_or(Error::InvalidPoint)
    }
}

impl EpeeWrite for Scalar {
    fn write_epee(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_bytes());
    }
}
impl EpeeRead for Scalar {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        let b = r.read_32()?;
        Scalar::from_bytes_canonical(&b).ok_or(Error::InvalidScalar)
    }
}

// Note: there is deliberately no blanket `impl EpeeWrite for Vec<T>`. It would
// collide with the `Vec<u8>` byte-string impl above (Rust has no
// specialization), so typed vectors go through [`write_vec`] and
// [`Reader::read_vec`] at each call site.
