//! The tagged union (`boost::variant`) used throughout Zano's serialization,
//! plus the tx-extra / attachment payload types it can hold.
//!
//! Tag values match the `SET_VARIANT_TAGS` table in zano's
//! `src/currency_core/currency_basic.h`.

use super::gateway::{GatewayAddressDescriptorOperation, GatewaySig, ZcGwBalanceProof};
use super::ser::{EpeeRead, EpeeWrite, Reader, write_var_bytes, write_vec};
use super::sig::{ZcAssetSurjectionProof, ZcBalanceProof, ZcOutsRangeProof, ZcSig};
use super::tx::{
    TRANSACTION_VERSION_POST_HF6, TxInGateway, TxInGen, TxInToKey, TxInZcInput, TxOutGateway,
    TxOutZarcanum,
};
use super::types::{AccountPublicAddr, RefById, Value256};
use super::varint::append_varint;
use crate::error::Result;

/// Variant discriminators.
pub mod tag {
    /// `txin_gen`
    pub const GEN: u8 = 0;
    /// `txin_to_key`
    pub const TO_KEY: u8 = 1;
    /// `tx_comment`
    pub const COMMENT: u8 = 7;
    /// `tx_crypto_checksum`
    pub const CRYPTO_CHECKSUM: u8 = 10;
    /// derivation hint (2 raw bytes)
    pub const DERIVATION_HINT: u8 = 11;
    /// `tx_service_attachment`
    pub const SERVICE_ATTACHMENT: u8 = 12;
    /// `etc_tx_details_unlock_time`
    pub const UNLOCK_TIME: u8 = 14;
    /// `etc_tx_details_expiration_time`
    pub const EXPIRATION_TIME: u8 = 15;
    /// `etc_tx_details_flags`
    pub const TX_FLAGS: u8 = 16;
    /// `signed_parts`
    pub const SIGNED_PARTS: u8 = 17;
    /// `extra_attachment_info`
    pub const EXTRA_ATTACHMENT_INFO: u8 = 18;
    /// `extra_user_data`
    pub const USER_DATA: u8 = 19;
    /// `extra_padding`
    pub const EXTRA_PADDING: u8 = 21;
    /// transaction public key
    pub const PUB_KEY: u8 = 22;
    /// `etc_tx_flags16`
    pub const ETC_TX_FLAGS16: u8 = 23;
    /// `derive_xor`
    pub const DERIVE_XOR: u8 = 24;
    /// `ref_by_id`
    pub const REF_BY_ID: u8 = 25;
    /// bare `uint64_t`
    pub const UINT64: u8 = 26;
    /// `etc_tx_time`
    pub const ETC_TX_TIME: u8 = 27;
    /// bare `uint32_t`
    pub const UINT32: u8 = 28;
    /// `tx_payer`
    pub const PAYER: u8 = 31;
    /// `tx_receiver`
    pub const RECEIVER: u8 = 32;
    /// `txin_zc_input`
    pub const TXIN_ZC_INPUT: u8 = 37;
    /// `tx_out_zarcanum_v1` — the pre-HF6 output layout.
    pub const TX_OUT_ZARCANUM_V1: u8 = 38;
    /// `zarcanum_tx_data_v1`
    pub const ZARCANUM_TX_DATA_V1: u8 = 39;
    /// `ZC_sig`
    pub const ZC_SIG: u8 = 43;
    /// `zc_asset_surjection_proof`
    pub const ZC_ASSET_SURJECTION_PROOF: u8 = 46;
    /// `zc_outs_range_proof`
    pub const ZC_OUTS_RANGE_PROOF: u8 = 47;
    /// `zc_balance_proof`
    pub const ZC_BALANCE_PROOF: u8 = 48;
    /// `eth_public_key` (33 bytes)
    pub const ETH_PUBLIC_KEY: u8 = 60;
    /// `dummy` — a tag with no payload
    pub const DUMMY: u8 = 62;
    /// `tx_out_zarcanum` — the output layout used from HF6 on.
    pub const TX_OUT_ZARCANUM: u8 = 63;
    /// `txin_gateway`
    pub const TXIN_GATEWAY: u8 = 65;
    /// `tx_out_gateway`
    pub const TX_OUT_GATEWAY: u8 = 66;
    /// `gateway_signature`
    pub const GATEWAY_SIG: u8 = 67;
    /// `eddsa_signature` (64 bytes)
    pub const EDDSA_SIGNATURE: u8 = 68;
    /// `eddsa_public_key` (32 bytes)
    pub const EDDSA_PUBLIC_KEY: u8 = 69;
    /// `generic_schnorr_sig_s` (two scalars)
    pub const GENERIC_SCHNORR_SIG_S: u8 = 70;
    /// `eth_signature` (64 bytes)
    pub const ETH_SIGNATURE: u8 = 71;
    /// `account_public_address`, as used inside `address_v`
    pub const ACCOUNT_PUBLIC_ADDRESS: u8 = 72;
    /// `gateway_address_descriptor_operation`
    pub const GATEWAY_ADDRESS_DESCRIPTOR_OPERATION: u8 = 73;
    /// `gateway_address_descriptor_operation_register`
    pub const GATEWAY_ADDRESS_DESCRIPTOR_OPERATION_REGISTER: u8 = 74;
    /// `gateway_address_descriptor_operation_update`
    pub const GATEWAY_ADDRESS_DESCRIPTOR_OPERATION_UPDATE: u8 = 75;
    /// `gateway_address_ownership_proof`
    pub const GATEWAY_ADDRESS_OWNERSHIP_PROOF: u8 = 76;
    /// `zc_gw_balance_proof`
    pub const ZC_GW_BALANCE_PROOF: u8 = 77;
    /// `etc_coinbase_block_cumulative_size` — mandatory in every coinbase
    /// since HF6.
    pub const ETC_COINBASE_BLOCK_CUMULATIVE_SIZE: u8 = 78;
}

/// Arbitrary user data placed in tx extra (e.g. a mining pool signature).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtraUserData {
    /// Opaque payload.
    pub buff: Vec<u8>,
}

/// Zero/stub padding in tx extra.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtraPadding {
    /// Padding bytes.
    pub buff: Vec<u8>,
}

/// Describes an attached payload: size, hash and count.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtraAttachmentInfo {
    /// Total attachment size.
    pub sz: u64,
    /// Hash over the attachment blob.
    pub hsh: Value256,
    /// Number of attachments.
    pub cnt: u64,
}

/// How many outputs/extras a given input signs over, for separately-signed
/// (consolidated) transactions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignedParts {
    /// Number of outputs covered.
    pub n_outs: u64,
    /// Number of extra entries covered.
    pub n_extras: u64,
}

/// An (optionally encrypted) free-form comment attachment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxComment {
    /// Comment bytes.
    pub comment: Vec<u8>,
}

/// Carries the tx key derivation encrypted to the sender's secret send key,
/// plus a 32-bit validation hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxCryptoChecksum {
    /// Encrypted key derivation.
    pub encrypted_key_derivation: Value256,
    /// Validation hash.
    pub derivation_hash: u32,
}

/// A generic service payload. Integrated-address payment IDs travel as a
/// service attachment with `service_id == "P"`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxServiceAttachment {
    /// Service identifier.
    pub service_id: String,
    /// Service-specific instruction.
    pub instruction: String,
    /// Payload, possibly encrypted or deflated (see [`TxServiceAttachment::flags`]).
    pub body: Vec<u8>,
    /// Optional public keys the payload is addressed to.
    pub security: Vec<Value256>,
    /// Flags; see the `TX_SERVICE_ATTACHMENT_*` constants.
    pub flags: u8,
}

/// `tx_service_attachment` flag: the body is chacha-encrypted.
pub const TX_SERVICE_ATTACHMENT_ENCRYPT_BODY: u8 = 1 << 0;
/// `tx_service_attachment` flag: the body is zlib-deflated.
pub const TX_SERVICE_ATTACHMENT_DEFLATE_BODY: u8 = 1 << 1;
/// `tx_service_attachment` flag: isolate auditable addresses.
pub const TX_SERVICE_ATTACHMENT_ENCRYPT_BODY_ISOLATE_AUDITABLE: u8 = 1 << 2;
/// `tx_service_attachment` flag: add a proof.
pub const TX_SERVICE_ATTACHMENT_ENCRYPT_ADD_PROOF: u8 = 1 << 3;

/// The `service_id` used to carry integrated-address payment IDs.
pub const PAYMENT_ID_SERVICE_ID: &str = "P";

/// One entry of a `boost::variant` container (tx inputs, outputs, extra,
/// attachments, signatures and proofs).
#[derive(Clone, Debug)]
pub enum Variant {
    /// Coinbase input.
    Gen(TxInGen),
    /// Legacy transparent input.
    ToKey(TxInToKey),
    /// Free-form comment.
    Comment(TxComment),
    /// Encrypted key derivation + hash.
    CryptoChecksum(TxCryptoChecksum),
    /// Derivation hint (2 bytes, varint-length-prefixed on the wire).
    DerivationHint(Vec<u8>),
    /// Service attachment.
    ServiceAttachment(TxServiceAttachment),
    /// Global unlock time.
    UnlockTime(u64),
    /// Transaction expiration time.
    ExpirationTime(u64),
    /// Transaction flags.
    TxFlags(u64),
    /// Signed-parts descriptor.
    SignedParts(SignedParts),
    /// Attachment descriptor.
    ExtraAttachmentInfo(ExtraAttachmentInfo),
    /// Arbitrary user data.
    UserData(ExtraUserData),
    /// Padding.
    ExtraPadding(ExtraPadding),
    /// Transaction public key.
    PubKey(Value256),
    /// 16-bit tx flags.
    EtcTxFlags16(u16),
    /// Derive-xor value.
    DeriveXor(u16),
    /// Output reference by transaction id.
    RefById(RefById),
    /// Bare `uint64` (used for output global-index offsets).
    Uint64(u64),
    /// Transaction timestamp.
    EtcTxTime(u64),
    /// Bare `uint32`.
    Uint32(u32),
    /// Encrypted payer address.
    Payer(AccountPublicAddr),
    /// Encrypted receiver address.
    Receiver(AccountPublicAddr),
    /// Zarcanum (confidential) input.
    TxInZcInput(TxInZcInput),
    /// Zarcanum (confidential) output, pre-HF6 layout (tx version < 4).
    TxOutZarcanumV1(TxOutZarcanum),
    /// Zarcanum (confidential) output, HF6 layout (tx version >= 4).
    TxOutZarcanum(TxOutZarcanum),
    /// Gateway input.
    TxInGateway(TxInGateway),
    /// Gateway output.
    TxOutGateway(TxOutGateway),
    /// Gateway input signature.
    GatewaySig(GatewaySig),
    /// Gateway address ownership proof.
    GatewayAddressOwnershipProof(GatewaySig),
    /// Balance proof for transactions with no confidential input.
    ZcGwBalanceProof(ZcGwBalanceProof),
    /// Gateway address registration/update, carried in tx extra.
    GatewayAddressDescriptorOperation(GatewayAddressDescriptorOperation),
    /// Cumulative block size, mandatory in every coinbase since HF6.
    EtcCoinbaseBlockCumulativeSize(u64),
    /// Fee record.
    ZarcanumTxDataV1 {
        /// Transaction fee, in native atomic units.
        fee: u64,
    },
    /// Confidential input signature.
    ZcSig(ZcSig),
    /// Asset surjection proof.
    ZcAssetSurjectionProof(ZcAssetSurjectionProof),
    /// Outputs range proof.
    ZcOutsRangeProof(ZcOutsRangeProof),
    /// Balance proof.
    ZcBalanceProof(ZcBalanceProof),
}

impl Variant {
    /// The wire discriminator for this value.
    pub fn tag(&self) -> u8 {
        match self {
            Variant::Gen(_) => tag::GEN,
            Variant::ToKey(_) => tag::TO_KEY,
            Variant::Comment(_) => tag::COMMENT,
            Variant::CryptoChecksum(_) => tag::CRYPTO_CHECKSUM,
            Variant::DerivationHint(_) => tag::DERIVATION_HINT,
            Variant::ServiceAttachment(_) => tag::SERVICE_ATTACHMENT,
            Variant::UnlockTime(_) => tag::UNLOCK_TIME,
            Variant::ExpirationTime(_) => tag::EXPIRATION_TIME,
            Variant::TxFlags(_) => tag::TX_FLAGS,
            Variant::SignedParts(_) => tag::SIGNED_PARTS,
            Variant::ExtraAttachmentInfo(_) => tag::EXTRA_ATTACHMENT_INFO,
            Variant::UserData(_) => tag::USER_DATA,
            Variant::ExtraPadding(_) => tag::EXTRA_PADDING,
            Variant::PubKey(_) => tag::PUB_KEY,
            Variant::EtcTxFlags16(_) => tag::ETC_TX_FLAGS16,
            Variant::DeriveXor(_) => tag::DERIVE_XOR,
            Variant::RefById(_) => tag::REF_BY_ID,
            Variant::Uint64(_) => tag::UINT64,
            Variant::EtcTxTime(_) => tag::ETC_TX_TIME,
            Variant::Uint32(_) => tag::UINT32,
            Variant::Payer(_) => tag::PAYER,
            Variant::Receiver(_) => tag::RECEIVER,
            Variant::TxInZcInput(_) => tag::TXIN_ZC_INPUT,
            Variant::TxOutZarcanumV1(_) => tag::TX_OUT_ZARCANUM_V1,
            Variant::TxOutZarcanum(_) => tag::TX_OUT_ZARCANUM,
            Variant::TxInGateway(_) => tag::TXIN_GATEWAY,
            Variant::TxOutGateway(_) => tag::TX_OUT_GATEWAY,
            Variant::GatewaySig(_) => tag::GATEWAY_SIG,
            Variant::GatewayAddressOwnershipProof(_) => tag::GATEWAY_ADDRESS_OWNERSHIP_PROOF,
            Variant::ZcGwBalanceProof(_) => tag::ZC_GW_BALANCE_PROOF,
            Variant::GatewayAddressDescriptorOperation(_) => {
                tag::GATEWAY_ADDRESS_DESCRIPTOR_OPERATION
            }
            Variant::EtcCoinbaseBlockCumulativeSize(_) => tag::ETC_COINBASE_BLOCK_CUMULATIVE_SIZE,
            Variant::ZarcanumTxDataV1 { .. } => tag::ZARCANUM_TX_DATA_V1,
            Variant::ZcSig(_) => tag::ZC_SIG,
            Variant::ZcAssetSurjectionProof(_) => tag::ZC_ASSET_SURJECTION_PROOF,
            Variant::ZcOutsRangeProof(_) => tag::ZC_OUTS_RANGE_PROOF,
            Variant::ZcBalanceProof(_) => tag::ZC_BALANCE_PROOF,
        }
    }

    /// The variant's name, as used by zano's `SET_VARIANT_TAGS`.
    pub fn type_name(&self) -> &'static str {
        match self {
            Variant::Gen(_) => "gen",
            Variant::ToKey(_) => "key",
            Variant::Comment(_) => "comment",
            Variant::CryptoChecksum(_) => "checksum",
            Variant::DerivationHint(_) => "derivation_hint",
            Variant::ServiceAttachment(_) => "attachment",
            Variant::UnlockTime(_) => "unlock_time",
            Variant::ExpirationTime(_) => "expiration_time",
            Variant::TxFlags(_) => "flags",
            Variant::SignedParts(_) => "signed_outs",
            Variant::ExtraAttachmentInfo(_) => "extra_attach_info",
            Variant::UserData(_) => "user_data",
            Variant::ExtraPadding(_) => "extra_padding",
            Variant::PubKey(_) => "pub_key",
            Variant::EtcTxFlags16(_) => "etc_tx_flags16",
            Variant::DeriveXor(_) => "derive_xor",
            Variant::RefById(_) => "ref_by_id",
            Variant::Uint64(_) => "uint64_t",
            Variant::EtcTxTime(_) => "etc_tx_time",
            Variant::Uint32(_) => "uint32_t",
            Variant::Payer(_) => "payer2",
            Variant::Receiver(_) => "receiver2",
            Variant::TxInZcInput(_) => "txin_zc_input",
            Variant::TxOutZarcanumV1(_) => "tx_out_zarcanum_v1",
            Variant::TxOutZarcanum(_) => "tx_out_zarcanum",
            Variant::TxInGateway(_) => "txin_gateway",
            Variant::TxOutGateway(_) => "tx_out_gateway",
            Variant::GatewaySig(_) => "gateway_signature",
            Variant::GatewayAddressOwnershipProof(_) => "gateway_address_ownership_proof",
            Variant::ZcGwBalanceProof(_) => "zc_gw_balance_proof",
            Variant::GatewayAddressDescriptorOperation(_) => "gateway_address_descriptor_operation",
            Variant::EtcCoinbaseBlockCumulativeSize(_) => "etc_coinbase_block_cumulative_size",
            Variant::ZarcanumTxDataV1 { .. } => "zarcanum_tx_data_v1",
            Variant::ZcSig(_) => "ZC_sig",
            Variant::ZcAssetSurjectionProof(_) => "zc_asset_surjection_proof",
            Variant::ZcOutsRangeProof(_) => "zc_outs_range_proof",
            Variant::ZcBalanceProof(_) => "zc_balance_proof",
        }
    }

    /// Borrows the value as a Zarcanum output, in either layout.
    pub fn as_tx_out_zarcanum(&self) -> Option<&TxOutZarcanum> {
        match self {
            Variant::TxOutZarcanum(v) | Variant::TxOutZarcanumV1(v) => Some(v),
            _ => None,
        }
    }

    /// Wraps a Zarcanum output in the layout a transaction of `tx_version`
    /// uses.
    pub fn tx_out_zarcanum(out: TxOutZarcanum, tx_version: u64) -> Variant {
        if tx_version >= TRANSACTION_VERSION_POST_HF6 {
            Variant::TxOutZarcanum(out)
        } else {
            Variant::TxOutZarcanumV1(out)
        }
    }

    /// Borrows the value as a Zarcanum input, if it is one.
    pub fn as_txin_zc_input(&self) -> Option<&TxInZcInput> {
        match self {
            Variant::TxInZcInput(v) => Some(v),
            _ => None,
        }
    }

    /// Borrows the value as a service attachment, if it is one.
    pub fn as_service_attachment(&self) -> Option<&TxServiceAttachment> {
        match self {
            Variant::ServiceAttachment(v) => Some(v),
            _ => None,
        }
    }

    /// Returns the `uint64` payload, if this is a bare integer reference.
    pub fn as_uint64(&self) -> Option<u64> {
        match self {
            Variant::Uint64(v) => Some(*v),
            _ => None,
        }
    }
}

impl EpeeWrite for Variant {
    fn write_epee(&self, out: &mut Vec<u8>) {
        out.push(self.tag());
        match self {
            Variant::Gen(v) => v.write_epee(out),
            Variant::ToKey(v) => v.write_epee(out),
            Variant::Comment(v) => write_var_bytes(&v.comment, out),
            Variant::CryptoChecksum(v) => {
                v.encrypted_key_derivation.write_epee(out);
                v.derivation_hash.write_epee(out);
            }
            Variant::DerivationHint(v) => write_var_bytes(v, out),
            Variant::ServiceAttachment(v) => {
                write_var_bytes(v.service_id.as_bytes(), out);
                write_var_bytes(v.instruction.as_bytes(), out);
                write_var_bytes(&v.body, out);
                write_vec(&v.security, out);
                out.push(v.flags);
            }
            Variant::UnlockTime(v)
            | Variant::ExpirationTime(v)
            | Variant::TxFlags(v)
            | Variant::EtcTxTime(v) => append_varint(out, *v),
            Variant::SignedParts(v) => {
                append_varint(out, v.n_outs);
                append_varint(out, v.n_extras);
            }
            Variant::ExtraAttachmentInfo(v) => {
                append_varint(out, v.sz);
                v.hsh.write_epee(out);
                append_varint(out, v.cnt);
            }
            Variant::UserData(v) => write_var_bytes(&v.buff, out),
            Variant::ExtraPadding(v) => write_var_bytes(&v.buff, out),
            Variant::PubKey(v) => v.write_epee(out),
            Variant::EtcTxFlags16(v) | Variant::DeriveXor(v) => v.write_epee(out),
            Variant::RefById(v) => v.write_epee(out),
            Variant::Uint64(v) => v.write_epee(out),
            Variant::Uint32(v) => v.write_epee(out),
            Variant::Payer(v) | Variant::Receiver(v) => v.write_epee(out),
            Variant::TxInZcInput(v) => v.write_epee(out),
            Variant::TxOutZarcanumV1(v) => v.write_epee(out),
            Variant::TxOutZarcanum(v) => v.write_epee_v2(out),
            Variant::TxInGateway(v) => v.write_epee(out),
            Variant::TxOutGateway(v) => v.write_epee(out),
            Variant::GatewaySig(v) | Variant::GatewayAddressOwnershipProof(v) => v.write_epee(out),
            Variant::ZcGwBalanceProof(v) => v.write_epee(out),
            Variant::GatewayAddressDescriptorOperation(v) => v.write_epee(out),
            Variant::EtcCoinbaseBlockCumulativeSize(v) => append_varint(out, *v),
            Variant::ZarcanumTxDataV1 { fee } => fee.write_epee(out),
            Variant::ZcSig(v) => v.write_epee(out),
            Variant::ZcAssetSurjectionProof(v) => v.write_epee(out),
            Variant::ZcOutsRangeProof(v) => v.write_epee(out),
            Variant::ZcBalanceProof(v) => v.write_epee(out),
        }
    }
}

impl EpeeRead for Variant {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        let t = r.read_byte()?;
        Ok(match t {
            tag::GEN => Variant::Gen(TxInGen::read_epee(r)?),
            tag::TO_KEY => Variant::ToKey(TxInToKey::read_epee(r)?),
            tag::COMMENT => Variant::Comment(TxComment {
                comment: r.read_var_bytes()?,
            }),
            tag::CRYPTO_CHECKSUM => Variant::CryptoChecksum(TxCryptoChecksum {
                encrypted_key_derivation: Value256::read_epee(r)?,
                derivation_hash: u32::read_epee(r)?,
            }),
            tag::DERIVATION_HINT => Variant::DerivationHint(r.read_var_bytes()?),
            tag::SERVICE_ATTACHMENT => Variant::ServiceAttachment(TxServiceAttachment {
                service_id: r.read_var_string()?,
                instruction: r.read_var_string()?,
                body: r.read_var_bytes()?,
                security: r.read_vec()?,
                flags: r.read_byte()?,
            }),
            tag::UNLOCK_TIME => Variant::UnlockTime(r.read_varint()?),
            tag::EXPIRATION_TIME => Variant::ExpirationTime(r.read_varint()?),
            tag::TX_FLAGS => Variant::TxFlags(r.read_varint()?),
            tag::SIGNED_PARTS => Variant::SignedParts(SignedParts {
                n_outs: r.read_varint()?,
                n_extras: r.read_varint()?,
            }),
            tag::EXTRA_ATTACHMENT_INFO => Variant::ExtraAttachmentInfo(ExtraAttachmentInfo {
                sz: r.read_varint()?,
                hsh: Value256::read_epee(r)?,
                cnt: r.read_varint()?,
            }),
            tag::USER_DATA => Variant::UserData(ExtraUserData {
                buff: r.read_var_bytes()?,
            }),
            tag::EXTRA_PADDING => Variant::ExtraPadding(ExtraPadding {
                buff: r.read_var_bytes()?,
            }),
            tag::PUB_KEY => Variant::PubKey(Value256::read_epee(r)?),
            tag::ETC_TX_FLAGS16 => Variant::EtcTxFlags16(u16::read_epee(r)?),
            tag::DERIVE_XOR => Variant::DeriveXor(u16::read_epee(r)?),
            tag::REF_BY_ID => Variant::RefById(RefById::read_epee(r)?),
            tag::UINT64 => Variant::Uint64(u64::read_epee(r)?),
            tag::ETC_TX_TIME => Variant::EtcTxTime(r.read_varint()?),
            tag::UINT32 => Variant::Uint32(u32::read_epee(r)?),
            tag::PAYER => Variant::Payer(AccountPublicAddr::read_epee(r)?),
            tag::RECEIVER => Variant::Receiver(AccountPublicAddr::read_epee(r)?),
            tag::TXIN_ZC_INPUT => Variant::TxInZcInput(TxInZcInput::read_epee(r)?),
            tag::TX_OUT_ZARCANUM_V1 => Variant::TxOutZarcanumV1(TxOutZarcanum::read_epee(r)?),
            tag::TX_OUT_ZARCANUM => Variant::TxOutZarcanum(TxOutZarcanum::read_epee_v2(r)?),
            tag::TXIN_GATEWAY => Variant::TxInGateway(TxInGateway::read_epee(r)?),
            tag::TX_OUT_GATEWAY => Variant::TxOutGateway(TxOutGateway::read_epee(r)?),
            tag::GATEWAY_SIG => Variant::GatewaySig(GatewaySig::read_epee(r)?),
            tag::GATEWAY_ADDRESS_OWNERSHIP_PROOF => {
                Variant::GatewayAddressOwnershipProof(GatewaySig::read_epee(r)?)
            }
            tag::ZC_GW_BALANCE_PROOF => Variant::ZcGwBalanceProof(ZcGwBalanceProof::read_epee(r)?),
            tag::GATEWAY_ADDRESS_DESCRIPTOR_OPERATION => {
                Variant::GatewayAddressDescriptorOperation(
                    GatewayAddressDescriptorOperation::read_epee(r)?,
                )
            }
            tag::ETC_COINBASE_BLOCK_CUMULATIVE_SIZE => {
                Variant::EtcCoinbaseBlockCumulativeSize(r.read_varint()?)
            }
            tag::ZARCANUM_TX_DATA_V1 => Variant::ZarcanumTxDataV1 {
                fee: u64::read_epee(r)?,
            },
            tag::ZC_SIG => Variant::ZcSig(ZcSig::read_epee(r)?),
            tag::ZC_ASSET_SURJECTION_PROOF => {
                Variant::ZcAssetSurjectionProof(ZcAssetSurjectionProof::read_epee(r)?)
            }
            tag::ZC_OUTS_RANGE_PROOF => Variant::ZcOutsRangeProof(ZcOutsRangeProof::read_epee(r)?),
            tag::ZC_BALANCE_PROOF => Variant::ZcBalanceProof(ZcBalanceProof::read_epee(r)?),
            // A binary variant carries no length prefix, so an unknown tag
            // cannot be skipped: surface a clean error instead.
            other => return Err(crate::err!("unsupported variant tag {other}")),
        })
    }
}
