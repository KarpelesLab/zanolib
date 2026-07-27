//! A minimal encoder/decoder for epee's "portable storage" binary format — the
//! serialization used by Zano's daemon `.bin` RPC endpoints.
//!
//! Only the subset this library needs is implemented: ordered sections,
//! unsigned integers, booleans, strings/blobs, nested objects, and arrays of
//! integers or objects.
//!
//! Reference: `zano/contrib/epee/include/storages/portable_storage*.h`.

use crate::error::{Error, Result};

const SIGNATURE_A: u32 = 0x0101_1101;
const SIGNATURE_B: u32 = 0x0102_0101;
const FORMAT_VER: u8 = 1;

const TYPE_INT64: u8 = 1;
const TYPE_INT32: u8 = 2;
const TYPE_INT16: u8 = 3;
const TYPE_INT8: u8 = 4;
const TYPE_UINT64: u8 = 5;
const TYPE_UINT32: u8 = 6;
const TYPE_UINT16: u8 = 7;
const TYPE_UINT8: u8 = 8;
const TYPE_DOUBLE: u8 = 9;
const TYPE_STRING: u8 = 10;
const TYPE_BOOL: u8 = 11;
const TYPE_OBJECT: u8 = 12;

const FLAG_ARRAY: u8 = 0x80;

/// A value in an epee section.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// An unsigned integer (every integer width decodes into this).
    Uint(u64),
    /// A boolean.
    Bool(bool),
    /// A string or binary blob.
    Bytes(Vec<u8>),
    /// A nested section.
    Section(Section),
    /// An array of integers.
    UintArray(Vec<u64>),
    /// An array of sections.
    SectionArray(Vec<Section>),
    /// An array of any other value type.
    Array(Vec<Value>),
}

/// An ordered set of named entries (an epee "section"/object).
///
/// Insertion order is preserved so encoding is deterministic; lookup is by name.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Section {
    entries: Vec<(String, Value)>,
}

impl Section {
    /// An empty section.
    pub fn new() -> Section {
        Section::default()
    }

    /// Adds or replaces an entry, returning `self` for chaining.
    pub fn set(&mut self, name: &str, v: impl Into<Value>) -> &mut Section {
        let v = v.into();
        match self.entries.iter_mut().find(|(k, _)| k == name) {
            Some(slot) => slot.1 = v,
            None => self.entries.push((name.to_string(), v)),
        }
        self
    }

    /// The raw value for `name`.
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.entries.iter().find(|(k, _)| k == name).map(|(_, v)| v)
    }

    /// A `uint`-typed entry.
    pub fn uint(&self, name: &str) -> Option<u64> {
        match self.get(name)? {
            Value::Uint(v) => Some(*v),
            _ => None,
        }
    }

    /// A string/blob entry, as bytes.
    pub fn bytes(&self, name: &str) -> Option<&[u8]> {
        match self.get(name)? {
            Value::Bytes(v) => Some(v),
            _ => None,
        }
    }

    /// An array-of-object entry.
    pub fn sections(&self, name: &str) -> Option<&[Section]> {
        match self.get(name)? {
            Value::SectionArray(v) => Some(v),
            _ => None,
        }
    }

    /// The entries, in insertion order.
    pub fn entries(&self) -> &[(String, Value)] {
        &self.entries
    }
}

impl From<u64> for Value {
    fn from(v: u64) -> Value {
        Value::Uint(v)
    }
}
impl From<bool> for Value {
    fn from(v: bool) -> Value {
        Value::Bool(v)
    }
}
impl From<&str> for Value {
    fn from(v: &str) -> Value {
        Value::Bytes(v.as_bytes().to_vec())
    }
}
impl From<Vec<u8>> for Value {
    fn from(v: Vec<u8>) -> Value {
        Value::Bytes(v)
    }
}
impl From<Section> for Value {
    fn from(v: Section) -> Value {
        Value::Section(v)
    }
}
impl From<Vec<u64>> for Value {
    fn from(v: Vec<u64>) -> Value {
        Value::UintArray(v)
    }
}
impl From<Vec<Section>> for Value {
    fn from(v: Vec<Section>) -> Value {
        Value::SectionArray(v)
    }
}

fn append_varint(b: &mut Vec<u8>, v: u64) {
    match v {
        0..=63 => b.push((v << 2) as u8),
        64..=16383 => b.extend_from_slice(&(((v << 2) | 1) as u16).to_le_bytes()),
        16384..=1073741823 => b.extend_from_slice(&(((v << 2) | 2) as u32).to_le_bytes()),
        _ => b.extend_from_slice(&((v << 2) | 3).to_le_bytes()),
    }
}

fn append_string(b: &mut Vec<u8>, s: &[u8]) {
    append_varint(b, s.len() as u64);
    b.extend_from_slice(s);
}

fn append_section(b: &mut Vec<u8>, s: &Section) {
    append_varint(b, s.entries.len() as u64);
    for (k, v) in &s.entries {
        b.push(k.len() as u8);
        b.extend_from_slice(k.as_bytes());
        append_entry(b, v);
    }
}

fn append_entry(b: &mut Vec<u8>, v: &Value) {
    match v {
        Value::Uint(x) => {
            b.push(TYPE_UINT64);
            b.extend_from_slice(&x.to_le_bytes());
        }
        Value::Bool(x) => {
            b.push(TYPE_BOOL);
            b.push(*x as u8);
        }
        Value::Bytes(x) => {
            b.push(TYPE_STRING);
            append_string(b, x);
        }
        Value::Section(x) => {
            b.push(TYPE_OBJECT);
            append_section(b, x);
        }
        Value::UintArray(x) => {
            b.push(TYPE_UINT64 | FLAG_ARRAY);
            append_varint(b, x.len() as u64);
            for e in x {
                b.extend_from_slice(&e.to_le_bytes());
            }
        }
        Value::SectionArray(x) => {
            b.push(TYPE_OBJECT | FLAG_ARRAY);
            append_varint(b, x.len() as u64);
            for e in x {
                append_section(b, e);
            }
        }
        Value::Array(_) => panic!("epee: cannot encode a heterogeneous array"),
    }
}

/// Encodes a root section to the portable-storage binary format.
pub fn marshal(root: &Section) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&SIGNATURE_A.to_le_bytes());
    b.extend_from_slice(&SIGNATURE_B.to_le_bytes());
    b.push(FORMAT_VER);
    append_section(&mut b, root);
    b
}

struct EpeeReader<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> EpeeReader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.p + n > self.b.len() {
            return Err(crate::err!(
                "epee: unexpected end of buffer (need {n} at {} of {})",
                self.p,
                self.b.len()
            ));
        }
        let v = &self.b[self.p..self.p + n];
        self.p += n;
        Ok(v)
    }

    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn varint(&mut self) -> Result<u64> {
        let first = *self.b.get(self.p).ok_or(Error::UnexpectedEof)?;
        Ok(match first & 0x03 {
            0 => self.take(1)?[0] as u64 >> 2,
            1 => u16::from_le_bytes(self.take(2)?.try_into().unwrap()) as u64 >> 2,
            2 => u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as u64 >> 2,
            _ => u64::from_le_bytes(self.take(8)?.try_into().unwrap()) >> 2,
        })
    }

    fn read_section(&mut self) -> Result<Section> {
        let count = self.varint()?;
        let mut s = Section::new();
        for _ in 0..count {
            let nl = self.byte()? as usize;
            let name = String::from_utf8_lossy(self.take(nl)?).into_owned();
            let v = self.read_entry()?;
            s.set(&name, v);
        }
        Ok(s)
    }

    fn read_entry(&mut self) -> Result<Value> {
        let t = self.byte()?;
        if t & FLAG_ARRAY != 0 {
            return self.read_array(t & !FLAG_ARRAY);
        }
        self.read_value(t)
    }

    fn read_array(&mut self, base: u8) -> Result<Value> {
        let count = self.varint()?;
        if base == TYPE_OBJECT {
            let mut out = Vec::new();
            for _ in 0..count {
                out.push(self.read_section()?);
            }
            return Ok(Value::SectionArray(out));
        }
        let mut out = Vec::new();
        for _ in 0..count {
            out.push(self.read_value(base)?);
        }
        if out.iter().all(|v| matches!(v, Value::Uint(_))) {
            return Ok(Value::UintArray(
                out.into_iter()
                    .map(|v| match v {
                        Value::Uint(x) => x,
                        _ => unreachable!(),
                    })
                    .collect(),
            ));
        }
        Ok(Value::Array(out))
    }

    fn read_value(&mut self, t: u8) -> Result<Value> {
        Ok(match t {
            TYPE_UINT64 | TYPE_INT64 => {
                Value::Uint(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
            }
            TYPE_UINT32 | TYPE_INT32 => {
                Value::Uint(u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as u64)
            }
            TYPE_UINT16 | TYPE_INT16 => {
                Value::Uint(u16::from_le_bytes(self.take(2)?.try_into().unwrap()) as u64)
            }
            TYPE_UINT8 | TYPE_INT8 => Value::Uint(self.byte()? as u64),
            TYPE_BOOL => Value::Bool(self.byte()? != 0),
            // Raw bits; doubles are not used by anything we call.
            TYPE_DOUBLE => Value::Uint(u64::from_le_bytes(self.take(8)?.try_into().unwrap())),
            TYPE_STRING => {
                let n = self.varint()? as usize;
                Value::Bytes(self.take(n)?.to_vec())
            }
            TYPE_OBJECT => Value::Section(self.read_section()?),
            other => return Err(crate::err!("epee: unsupported value type {other}")),
        })
    }
}

/// Decodes a portable-storage binary buffer into its root section.
pub fn unmarshal(data: &[u8]) -> Result<Section> {
    if data.len() < 9 {
        return Err(crate::err!("epee: too short ({} < 9)", data.len()));
    }
    if u32::from_le_bytes(data[0..4].try_into().unwrap()) != SIGNATURE_A
        || u32::from_le_bytes(data[4..8].try_into().unwrap()) != SIGNATURE_B
    {
        return Err(Error::msg("epee: bad signature"));
    }
    if data[8] != FORMAT_VER {
        return Err(crate::err!("epee: unknown format version {}", data[8]));
    }
    let mut r = EpeeReader {
        b: &data[9..],
        p: 0,
    };
    r.read_section()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let mut dist = Section::new();
        dist.set("amount", 0u64)
            .set("global_offsets", vec![1u64, 2, 3]);
        let mut req = Section::new();
        req.set("amounts", vec![dist.clone()])
            .set("height_upper_limit", 0u64)
            .set("use_forced_mix_outs", false)
            .set("coinbase_percents", 0u64)
            .set("blob", vec![0xdeu8, 0xad, 0xbe, 0xef])
            .set("name", "zano");

        let enc = marshal(&req);
        let dec = unmarshal(&enc).unwrap();
        assert_eq!(dec.uint("height_upper_limit"), Some(0));
        assert_eq!(dec.bytes("blob"), Some(&[0xde, 0xad, 0xbe, 0xef][..]));
        assert_eq!(dec.bytes("name"), Some(&b"zano"[..]));
        assert_eq!(dec.get("use_forced_mix_outs"), Some(&Value::Bool(false)));
        let subs = dec.sections("amounts").unwrap();
        assert_eq!(subs.len(), 1);
        assert_eq!(
            subs[0].get("global_offsets"),
            Some(&Value::UintArray(vec![1, 2, 3]))
        );
    }

    #[test]
    fn header_is_validated() {
        assert!(unmarshal(&[]).is_err());
        let mut enc = marshal(&Section::new());
        enc[0] ^= 0xff;
        assert!(unmarshal(&enc).is_err());
        let mut enc = marshal(&Section::new());
        enc[8] = 9;
        assert!(unmarshal(&enc).is_err());
    }

    #[test]
    fn varint_widths() {
        for v in [
            0u64,
            63,
            64,
            16383,
            16384,
            1073741823,
            1073741824,
            u64::MAX >> 2,
        ] {
            let mut b = Vec::new();
            append_varint(&mut b, v);
            let mut r = EpeeReader { b: &b, p: 0 };
            assert_eq!(r.varint().unwrap(), v);
        }
    }

    #[test]
    fn set_replaces_in_place() {
        let mut s = Section::new();
        s.set("a", 1u64).set("b", 2u64).set("a", 3u64);
        assert_eq!(s.entries().len(), 3 - 1);
        assert_eq!(s.uint("a"), Some(3));
    }
}
