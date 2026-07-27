//! Transaction structures and their binary layout.

use super::ser::{EpeeRead, EpeeWrite, Reader, write_vec};
use super::types::Value256;
use super::variant::{Variant, tag};
use super::varint::append_varint;
use crate::crypto::Point;
use crate::error::Result;

/// `TRANSACTION_VERSION_INITAL`.
pub const TRANSACTION_VERSION_INITIAL: u64 = 0;
/// `TRANSACTION_VERSION_PRE_HF4`.
pub const TRANSACTION_VERSION_PRE_HF4: u64 = 1;
/// `TRANSACTION_VERSION_POST_HF4`.
pub const TRANSACTION_VERSION_POST_HF4: u64 = 2;
/// `TRANSACTION_VERSION_POST_HF5` — adds `hardfork_id` to the prefix.
pub const TRANSACTION_VERSION_POST_HF5: u64 = 3;

/// A coinbase (generation) input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxInGen {
    /// Block height.
    pub height: u64,
}

impl EpeeWrite for TxInGen {
    fn write_epee(&self, out: &mut Vec<u8>) {
        append_varint(out, self.height);
    }
}
impl EpeeRead for TxInGen {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        Ok(TxInGen {
            height: r.read_varint()?,
        })
    }
}

/// A legacy (pre-HF4) transparent input.
#[derive(Clone, Debug)]
pub struct TxInToKey {
    /// Input amount.
    pub amount: u64,
    /// Ring member references (`uint64` offsets or `ref_by_id`).
    pub key_offsets: Vec<Variant>,
    /// Key image.
    pub k_image: Point,
    /// Additional input details.
    pub etc_details: Vec<Variant>,
}

impl EpeeWrite for TxInToKey {
    fn write_epee(&self, out: &mut Vec<u8>) {
        append_varint(out, self.amount);
        write_vec(&self.key_offsets, out);
        self.k_image.write_epee(out);
        write_vec(&self.etc_details, out);
    }
}
impl EpeeRead for TxInToKey {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        Ok(TxInToKey {
            amount: r.read_varint()?,
            key_offsets: r.read_vec()?,
            k_image: Point::read_epee(r)?,
            etc_details: r.read_vec()?,
        })
    }
}

/// A Zarcanum (confidential) input.
#[derive(Clone, Debug)]
pub struct TxInZcInput {
    /// Ring member references, as deltas of global output indices.
    pub key_offsets: Vec<Variant>,
    /// Key image, for double-spend prevention.
    pub key_image: Point,
    /// Additional input details.
    pub etc_details: Vec<Variant>,
}

impl EpeeWrite for TxInZcInput {
    fn write_epee(&self, out: &mut Vec<u8>) {
        write_vec(&self.key_offsets, out);
        self.key_image.write_epee(out);
        write_vec(&self.etc_details, out);
    }
}
impl EpeeRead for TxInZcInput {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        Ok(TxInZcInput {
            key_offsets: r.read_vec()?,
            key_image: Point::read_epee(r)?,
            etc_details: r.read_vec()?,
        })
    }
}

/// A Zarcanum (confidential) output.
#[derive(Clone, Copy, Debug, Default)]
pub struct TxOutZarcanum {
    /// One-time stealth address.
    pub stealth_address: Value256,
    /// Concealing point `Q`, premultiplied by 1/8.
    pub concealing_point: Value256,
    /// Amount commitment, premultiplied by 1/8.
    pub amount_commitment: Value256,
    /// Blinded asset id `T`, premultiplied by 1/8.
    pub blinded_asset_id: Value256,
    /// Amount, XOR-masked with a per-output key.
    pub encrypted_amount: u64,
    /// Mixin attribute (1 = no mixing, for auditable addresses).
    pub mix_attr: u8,
}

impl EpeeWrite for TxOutZarcanum {
    fn write_epee(&self, out: &mut Vec<u8>) {
        self.stealth_address.write_epee(out);
        self.concealing_point.write_epee(out);
        self.amount_commitment.write_epee(out);
        self.blinded_asset_id.write_epee(out);
        self.encrypted_amount.write_epee(out);
        out.push(self.mix_attr);
    }
}
impl EpeeRead for TxOutZarcanum {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        Ok(TxOutZarcanum {
            stealth_address: Value256::read_epee(r)?,
            concealing_point: Value256::read_epee(r)?,
            amount_commitment: Value256::read_epee(r)?,
            blinded_asset_id: Value256::read_epee(r)?,
            encrypted_amount: u64::read_epee(r)?,
            mix_attr: r.read_byte()?,
        })
    }
}

/// The hashable prefix of a transaction.
#[derive(Clone, Debug, Default)]
pub struct TransactionPrefix {
    /// Transaction version.
    pub version: u64,
    /// Inputs.
    pub vin: Vec<Variant>,
    /// Extra fields.
    pub extra: Vec<Variant>,
    /// Outputs.
    pub vout: Vec<Variant>,
    /// Hardfork id; only serialized for version >= 3.
    pub hardfork_id: u8,
}

impl EpeeWrite for TransactionPrefix {
    fn write_epee(&self, out: &mut Vec<u8>) {
        append_varint(out, self.version);
        write_vec(&self.vin, out);
        write_vec(&self.extra, out);
        write_vec(&self.vout, out);
        if self.version >= TRANSACTION_VERSION_POST_HF5 {
            out.push(self.hardfork_id);
        }
    }
}
impl EpeeRead for TransactionPrefix {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        let version = r.read_varint()?;
        let vin = r.read_vec()?;
        let extra = r.read_vec()?;
        let vout = r.read_vec()?;
        let hardfork_id = if version >= TRANSACTION_VERSION_POST_HF5 {
            r.read_byte()?
        } else {
            0
        };
        Ok(TransactionPrefix {
            version,
            vin,
            extra,
            vout,
            hardfork_id,
        })
    }
}

impl TransactionPrefix {
    /// Keccak-256 over the serialized prefix — the transaction id.
    pub fn hash(&self) -> Value256 {
        Value256(purecrypto::hash::keccak256(&self.to_epee_bytes()))
    }
}

/// A complete transaction: prefix, attachments, signatures and proofs.
#[derive(Clone, Debug, Default)]
pub struct Transaction {
    /// Transaction version.
    pub version: u64,
    /// Inputs.
    pub vin: Vec<Variant>,
    /// Extra fields.
    pub extra: Vec<Variant>,
    /// Outputs.
    pub vout: Vec<Variant>,
    /// Hardfork id; part of the prefix, only present for version >= 3.
    pub hardfork_id: u8,
    /// Attachments.
    pub attachment: Vec<Variant>,
    /// Per-input signatures.
    pub signatures: Vec<Variant>,
    /// Transaction-wide proofs.
    pub proofs: Vec<Variant>,
}

impl Transaction {
    /// The hashable prefix of this transaction.
    pub fn prefix(&self) -> TransactionPrefix {
        TransactionPrefix {
            version: self.version,
            vin: self.vin.clone(),
            extra: self.extra.clone(),
            vout: self.vout.clone(),
            hardfork_id: self.hardfork_id,
        }
    }

    /// The transaction id (hash of the prefix).
    pub fn id(&self) -> Value256 {
        self.prefix().hash()
    }

    /// The fee recorded in tx extra, if any.
    pub fn fee(&self) -> Option<u64> {
        self.extra.iter().find_map(|e| match e {
            Variant::ZarcanumTxDataV1 { fee } => Some(*fee),
            _ => None,
        })
    }

    /// The transaction public key from tx extra, if present.
    pub fn tx_pub_key(&self) -> Option<Value256> {
        self.extra.iter().find_map(|e| match e {
            Variant::PubKey(v) => Some(*v),
            _ => None,
        })
    }

    /// Reads only the parts needed to detect received outputs and recover
    /// payment ids: the prefix and the attachment section, which precede
    /// signatures and proofs on the wire.
    ///
    /// This lets a scanner process every on-chain transaction without
    /// implementing every signature/proof variant (notably the large PoS
    /// `zarcanum_sig`). Remaining bytes are left unread.
    pub fn deserialize_for_scan(buf: &[u8]) -> Result<Transaction> {
        let mut r = Reader::new(buf);
        let version = r.read_varint()?;
        let vin = r.read_vec()?;
        let extra = r.read_vec()?;
        let vout = r.read_vec()?;
        let hardfork_id = if version >= TRANSACTION_VERSION_POST_HF5 {
            r.read_byte()?
        } else {
            0
        };
        let attachment = r.read_vec()?;
        Ok(Transaction {
            version,
            vin,
            extra,
            vout,
            hardfork_id,
            attachment,
            signatures: Vec::new(),
            proofs: Vec::new(),
        })
    }

    /// Counts the confidential (Zarcanum) inputs.
    pub fn zc_inputs_count(&self) -> usize {
        self.vin
            .iter()
            .filter(|v| v.tag() == tag::TXIN_ZC_INPUT)
            .count()
    }
}

impl EpeeWrite for Transaction {
    fn write_epee(&self, out: &mut Vec<u8>) {
        append_varint(out, self.version);
        write_vec(&self.vin, out);
        write_vec(&self.extra, out);
        write_vec(&self.vout, out);
        if self.version >= TRANSACTION_VERSION_POST_HF5 {
            out.push(self.hardfork_id);
        }
        write_vec(&self.attachment, out);
        write_vec(&self.signatures, out);
        write_vec(&self.proofs, out);
    }
}
impl EpeeRead for Transaction {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        let version = r.read_varint()?;
        let vin = r.read_vec()?;
        let extra = r.read_vec()?;
        let vout = r.read_vec()?;
        let hardfork_id = if version >= TRANSACTION_VERSION_POST_HF5 {
            r.read_byte()?
        } else {
            0
        };
        Ok(Transaction {
            version,
            vin,
            extra,
            vout,
            hardfork_id,
            attachment: r.read_vec()?,
            signatures: r.read_vec()?,
            proofs: r.read_vec()?,
        })
    }
}
