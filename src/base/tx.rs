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
/// `TRANSACTION_VERSION_POST_HF6` — outputs carry a version and an encrypted
/// payment id, and use their own variant tags.
pub const TRANSACTION_VERSION_POST_HF6: u64 = 4;

/// `ZANO_HARDFORK_04_AFTER_HEIGHT` on mainnet: Zarcanum is active for blocks
/// above this height.
pub const ZANO_HARDFORK_04_AFTER_HEIGHT: u64 = 2_555_000;
/// `ZANO_HARDFORK_05_AFTER_HEIGHT` on mainnet.
pub const ZANO_HARDFORK_05_AFTER_HEIGHT: u64 = 3_076_400;
/// `ZANO_HARDFORK_06_AFTER_HEIGHT` on mainnet.
pub const ZANO_HARDFORK_06_AFTER_HEIGHT: u64 = 3_833_000;

/// The transaction version and hardfork id a mainnet transaction must carry
/// to be included in the block at `height` (zano's
/// `get_tx_version_and_hardfork_id`). For a transaction built now, `height` is
/// the daemon's block count, i.e. the height of the next block.
///
/// Only post-Zarcanum (HF4+) heights are meaningful here: this crate cannot
/// build earlier transactions.
pub fn tx_version_and_hardfork_id(height: u64) -> (u64, u64) {
    if height > ZANO_HARDFORK_06_AFTER_HEIGHT {
        (TRANSACTION_VERSION_POST_HF6, 6)
    } else if height > ZANO_HARDFORK_05_AFTER_HEIGHT {
        (TRANSACTION_VERSION_POST_HF5, 5)
    } else if height > ZANO_HARDFORK_04_AFTER_HEIGHT {
        (TRANSACTION_VERSION_POST_HF4, 4)
    } else {
        (TRANSACTION_VERSION_PRE_HF4, 3)
    }
}

/// `CURRENCY_HF4_MANDATORY_MIN_COINAGE`: every output a transaction references
/// (real or decoy) must be at least this many blocks deep when the
/// transaction is mined.
pub const CURRENCY_HF4_MANDATORY_MIN_COINAGE: u64 = 10;

/// `CURRENCY_TX_MIN_ALLOWED_OUTS`: every non-coinbase transaction needs at
/// least this many outputs (since HF4).
pub const CURRENCY_TX_MIN_ALLOWED_OUTS: usize = 2;
/// `CURRENCY_TX_MAX_ALLOWED_OUTS`: a consensus rule since HF6.
pub const CURRENCY_TX_MAX_ALLOWED_OUTS: usize = 32;
/// `CURRENCY_TX_MAX_ALLOWED_INPUTS`: a consensus rule since HF6.
pub const CURRENCY_TX_MAX_ALLOWED_INPUTS: usize = 256;
/// `CURRENCY_TX_PRACTICAL_MAX_INPUTS`: the input count zano's wallet stays
/// under so a transaction fits the size limit.
pub const CURRENCY_TX_PRACTICAL_MAX_INPUTS: usize = 80;

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
///
/// Two wire layouts exist, told apart by their variant tag. Transactions below
/// [`TRANSACTION_VERSION_POST_HF6`] use `tx_out_zarcanum_v1`
/// ([`tag::TX_OUT_ZARCANUM_V1`]), which has neither `version` nor
/// `encrypted_payment_id`; from v4 on they use `tx_out_zarcanum`
/// ([`tag::TX_OUT_ZARCANUM`]), which has both.
///
/// [`tag::TX_OUT_ZARCANUM_V1`]: super::variant::tag::TX_OUT_ZARCANUM_V1
/// [`tag::TX_OUT_ZARCANUM`]: super::variant::tag::TX_OUT_ZARCANUM
#[derive(Clone, Copy, Debug, Default)]
pub struct TxOutZarcanum {
    /// Output format version (`TX_OUT_ZARCANUM_CURRENT_VERSION` = 0); absent
    /// from the pre-HF6 layout.
    pub version: u64,
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
    /// Payment id, XOR-masked with the same per-output key (bytes 8..16);
    /// absent from the pre-HF6 layout. Since HF6 this is where the payment id
    /// of an integrated address travels.
    pub encrypted_payment_id: u64,
    /// Mixin attribute (1 = no mixing, for auditable addresses).
    pub mix_attr: u8,
}

impl TxOutZarcanum {
    /// Writes the post-HF6 layout (`tx_out_zarcanum`).
    pub fn write_epee_v2(&self, out: &mut Vec<u8>) {
        append_varint(out, self.version);
        self.stealth_address.write_epee(out);
        self.concealing_point.write_epee(out);
        self.amount_commitment.write_epee(out);
        self.blinded_asset_id.write_epee(out);
        self.encrypted_amount.write_epee(out);
        self.encrypted_payment_id.write_epee(out);
        out.push(self.mix_attr);
    }

    /// Reads the post-HF6 layout (`tx_out_zarcanum`).
    pub fn read_epee_v2(r: &mut Reader<'_>) -> Result<Self> {
        let version = r.read_varint()?;
        if version > 0 {
            return Err(crate::err!("unsupported tx_out_zarcanum version {version}"));
        }
        Ok(TxOutZarcanum {
            version,
            stealth_address: Value256::read_epee(r)?,
            concealing_point: Value256::read_epee(r)?,
            amount_commitment: Value256::read_epee(r)?,
            blinded_asset_id: Value256::read_epee(r)?,
            encrypted_amount: u64::read_epee(r)?,
            encrypted_payment_id: u64::read_epee(r)?,
            mix_attr: r.read_byte()?,
        })
    }
}

impl EpeeWrite for TxOutZarcanum {
    /// Writes the pre-HF6 layout (`tx_out_zarcanum_v1`), which has no place for
    /// `version` or `encrypted_payment_id`.
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
    /// Reads the pre-HF6 layout (`tx_out_zarcanum_v1`).
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        Ok(TxOutZarcanum {
            version: 0,
            stealth_address: Value256::read_epee(r)?,
            concealing_point: Value256::read_epee(r)?,
            amount_commitment: Value256::read_epee(r)?,
            blinded_asset_id: Value256::read_epee(r)?,
            encrypted_amount: u64::read_epee(r)?,
            encrypted_payment_id: 0,
            mix_attr: r.read_byte()?,
        })
    }
}

/// A gateway input (HF6): funds moved out of a gateway address.
#[derive(Clone, Copy, Debug, Default)]
pub struct TxInGateway {
    /// Structure version.
    pub version: u64,
    /// Gateway address id.
    pub gateway_addr: Value256,
    /// Asset id, premultiplied by 1/8.
    pub asset_id: Value256,
    /// Explicit (non-confidential) amount.
    pub amount: u64,
}

impl EpeeWrite for TxInGateway {
    fn write_epee(&self, out: &mut Vec<u8>) {
        append_varint(out, self.version);
        self.gateway_addr.write_epee(out);
        self.asset_id.write_epee(out);
        append_varint(out, self.amount);
        // zano serializes the version a second time here.
        append_varint(out, self.version);
    }
}
impl EpeeRead for TxInGateway {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        let version = r.read_varint()?;
        if version > 0 {
            return Err(crate::err!("unsupported txin_gateway version {version}"));
        }
        let v = TxInGateway {
            version,
            gateway_addr: Value256::read_epee(r)?,
            asset_id: Value256::read_epee(r)?,
            amount: r.read_varint()?,
        };
        let _version_again = r.read_varint()?;
        Ok(v)
    }
}

/// A gateway output (HF6): an explicit-amount payment to a gateway address.
#[derive(Clone, Copy, Debug, Default)]
pub struct TxOutGateway {
    /// Structure version.
    pub version: u64,
    /// Gateway address id.
    pub gateway_addr: Value256,
    /// Asset id, premultiplied by 1/8.
    pub asset_id: Value256,
    /// Explicit (non-confidential) amount.
    pub amount: u64,
    /// Payment id, in the clear.
    pub payment_id: u64,
}

impl EpeeWrite for TxOutGateway {
    fn write_epee(&self, out: &mut Vec<u8>) {
        append_varint(out, self.version);
        self.gateway_addr.write_epee(out);
        self.asset_id.write_epee(out);
        append_varint(out, self.amount);
        self.payment_id.write_epee(out);
    }
}
impl EpeeRead for TxOutGateway {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        let version = r.read_varint()?;
        if version > 0 {
            return Err(crate::err!("unsupported tx_out_gateway version {version}"));
        }
        Ok(TxOutGateway {
            version,
            gateway_addr: Value256::read_epee(r)?,
            asset_id: Value256::read_epee(r)?,
            amount: r.read_varint()?,
            payment_id: u64::read_epee(r)?,
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
